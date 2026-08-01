//
// ChatClient.swift  (gaapchat)
//
// Decentralized multicast group chat over the LISP overlay — the Swift port of the Python
// gaapchat send/listen/command logic. Wire format is IDENTICAL for interop:
//   data%%<myid>%%<text>              a chat message
//   ping%%<myid>%%<seq>               ping the group (members auto-pong)
//   pong%%<myid>%%<pinger>%%<seq>     pong response
// All sent to the hashed group on UDP 0xfafa. Own multicast loopbacks are filtered by myid.
//

import Foundation
import Combine
import Darwin
import UIKit

// A styled span for rich rendering: only the ping/pong sequence and the group address
// (an EID) get color, everything else is plain — matching the Python app.
enum ChatSpan: Codable {
    case plain(String)      // default text color
    case seq(String)        // ping/pong sequence number — colored by colorIndex
    case eid(String)        // group address — green (it's an EID)
    case name(String)       // sender/member name — bold
}

struct ChatMessage: Identifiable, Codable {
    var id = UUID()                // var (not let) so Codable actually restores it on reload
    enum Kind: String, Codable { case data, mine, ping, pong, info }
    let kind: Kind
    let sender: String
    let text: String
    let colorIndex: Int?        // 0..3 for ping/pong seq coloring (blue,green,red,purple)
    var spans: [ChatSpan]? = nil   // rich rendering (seq + EID coloring); nil = plain `text`
    var detail: String? = nil      // compact content for :history (nil = use `text`)
    var pongs: [String] = []       // for a ping bubble: responder hosts collected for this seq
    var at = Date()                // var so Codable restores the real timestamp on reload
}

@MainActor
final class ChatClient: ObservableObject {
    @Published var messages: [ChatMessage] = []
    @Published var groupName = ""
    @Published var groupAddress = ""            // 224.b2.b3.b4
    @Published var joined = false
    @Published var lispReady = false
    @Published var members: [String] = []       // senders seen (":show"), insertion order
    @Published var lastSent: [String: Date] = [:]   // member -> last time they sent to the group
    @Published var firstSeen: [String: Date] = [:]  // member -> first-message time (first msg we saw)
    @Published var dataSent: [String: Int] = [:]    // member -> data messages sent
    @Published var pingsSent: [String: Int] = [:]   // member -> pings sent
    @Published var pongsSent: [String: Int] = [:]   // member -> pongs sent
    @Published var sentCount = 0                 // messages we sent this session (data/ping/pong)
    @Published var recvCount = 0                 // messages we received this session
    @Published var showHistory = false           // drives the History sheet (set by :history)
    @Published var showMembers = false           // drives the Members sheet (set by :show)
    @Published var missedCount = 0               // messages that arrived while we were away (badge)
    let nickname = "ios"                          // fixed identity prefix (not user-configurable)

    var device: String { GaapWire.localHostname }
    var myid: String { "\(nickname)@\(device)" }

    let helpText = """
    Commands [shortcut]:
      :help    [:?]  this display
      :history [:h]  show text history
      :ping    [:p]  ping the group (members pong)
      :quit    [:q]  leave the group + clear
      :show    [:s]  show members
    """

    private var group: UInt32 = 0
    private var inboxTimer: Timer?              // polls the shared inbox (replaces the loopback listener)
    private var reportTimer: Timer?             // periodic IGMP Report (soft-state refresh)
    private var readyTimer: Timer?
    // Ping/pong color cycling (Python: blue→green→red→purple).
    private var colorCounter = -1
    private var pingColorForSeq: [String: Int] = [:]
    // Which pong-collector bubble (message id) gathers the responders for a given ping seq — the
    // pongs fold into ONE pill (colored by the seq) that's separate from the ping's own bubble.
    private var pongBubbleIdForSeq: [String: UUID] = [:]
    // Group name of the session we loaded from disk on launch (so restore knows the loaded
    // messages belong to the sticky group and can be kept rather than wiped).
    private var loadedGroupName = ""

    init() {
        startInboxPolling()
        refreshReady()
        readyTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshReady() }
        }
        loadSession()               // restore prior messages/members/history (survives a kill)
        restoreStickyGroupIfAny()   // re-enter + replay the sticky group if iOS killed us
    }

    // The user has seen the missed messages — clear the badge.
    func clearMissed() { missedCount = 0 }

    private func refreshReady() {
        let age = GaapWire.lispHeartbeatAge
        lispReady = (age != nil && age! < 5)
    }

    // MARK: join / leave

    // Timestamp for the "Joined group at …" line.
    private static let joinStamp: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "MM/dd/yy HH:mm:ss"; return f
    }()

    // A fresh, user-initiated join: skip whatever backlog is sitting in the inbox and clear
    // any prior session state.
    func join(_ name: String) { enter(name, replay: false, wipe: true) }

    // Re-enter the sticky group on launch (iOS killed us while suspended). We do NOT seekToEnd,
    // so the poll replays every message that arrived while gaapchat wasn't running. We also KEEP
    // the session we just loaded (messages/members/history) as long as it's for this same group —
    // that's what "state survives leaving the app" means from the user's side. From init().
    private func restoreStickyGroupIfAny() {
        guard !joined, let name = GaapInbox.savedGroupName,
              !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        enter(name, replay: true, wipe: (name != loadedGroupName))
    }

    private func enter(_ name: String, replay: Bool, wipe: Bool) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        if joined { leave() }
        groupName = trimmed
        groupAddress = GaapHash.groupAddress(trimmed)
        group = GaapWire.parseIPv4(groupAddress) ?? 0
        GaapInbox.setSticky(group)         // keep this group joined at the xTR while we're suspended
        GaapInbox.saveGroupName(trimmed)   // remember it so a relaunch can rejoin the same group
        if replay {
            missedCount = GaapInbox.pendingCount(group: group)   // badge: messages we missed
        } else {
            GaapInbox.seekToEnd()          // fresh session — don't replay stale backlog
            missedCount = 0
        }
        joined = true
        if wipe {
            messages.removeAll()
            members.removeAll(); lastSent.removeAll(); firstSeen.removeAll()   // fresh session state
            dataSent.removeAll(); pingsSent.removeAll(); pongsSent.removeAll()
            pongBubbleIdForSeq.removeAll()
            sentCount = 0; recvCount = 0
        }
        // Name + address are already shown in the header, so just stamp when we joined.
        info("\(replay ? "Rejoined" : "Joined") group at \(Self.joinStamp.string(from: Date()))")
        sendReport(announce: true)                      // IGMP Report → LISP registers (*,G)
        reportTimer?.invalidate()
        reportTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.sendReport() }   // periodic refresh (silent)
        }
        if replay { drainInbox() }                      // replay the missed backlog now
    }

    func leave() {
        guard joined else { return }
        reportTimer?.invalidate(); reportTimer = nil
        GaapInbox.clearSticky()        // stop keeping the group sticky-joined; let it age out
        GaapInbox.clearGroupName()     // explicit leave — don't auto-rejoin on next launch
        clearSession()                 // drop the persisted session — nothing to restore
        if group != 0 {
            GaapWire.sendIGMP(type: GaapWire.igmpLeave, group: group)
        }
        joined = false
        missedCount = 0
    }

    // MARK: session persistence (survives an iOS kill)

    // A snapshot of everything the UI shows, saved on background and reloaded on launch so
    // messages, members (:show) and history survive gaapchat being jettisoned while suspended.
    private struct GaapSession: Codable {
        var groupName: String
        var messages: [ChatMessage]
        var members: [String]
        var firstSeen: [String: Date]
        var lastSent: [String: Date]
        var dataSent: [String: Int]
        var pingsSent: [String: Int]
        var pongsSent: [String: Int]
        var sentCount: Int
        var recvCount: Int
    }

    private static var sessionURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.net.lispers.xtr")?
            .appendingPathComponent("gaap-session.json")
    }

    private func saveSession() {
        guard joined, let url = Self.sessionURL else { return }
        let s = GaapSession(groupName: groupName, messages: messages, members: members,
                            firstSeen: firstSeen, lastSent: lastSent,
                            dataSent: dataSent, pingsSent: pingsSent, pongsSent: pongsSent,
                            sentCount: sentCount, recvCount: recvCount)
        if let data = try? JSONEncoder().encode(s) { try? data.write(to: url) }
    }

    private func loadSession() {
        guard let url = Self.sessionURL, let data = try? Data(contentsOf: url),
              let s = try? JSONDecoder().decode(GaapSession.self, from: data) else { return }
        loadedGroupName = s.groupName
        messages = s.messages
        members = s.members; firstSeen = s.firstSeen; lastSent = s.lastSent
        dataSent = s.dataSent; pingsSent = s.pingsSent; pongsSent = s.pongsSent
        sentCount = s.sentCount; recvCount = s.recvCount
        // Rebuild the pong-collector map so replayed pongs fold into their existing pills.
        for m in messages where m.kind == .pong { if let seq = m.detail { pongBubbleIdForSeq[seq] = m.id } }
    }

    private func clearSession() {
        if let url = Self.sessionURL { try? FileManager.default.removeItem(at: url) }
        loadedGroupName = ""
    }

    private func sendReport(announce: Bool = false) {
        guard joined, group != 0 else { return }
        GaapWire.sendIGMP(type: GaapWire.igmpReport, group: group)
        _ = announce
    }

    // MARK: send

    // A line the user typed. ":" prefix = command; otherwise a chat message.
    func submit(_ raw: String) {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        if text.hasPrefix(":") { runCommand(text); return }
        guard joined, group != 0 else { info("Join a group first."); return }
        GaapWire.sendChat(group: group, ascii: Data("data%%\(myid)%%\(text)".utf8))
        append(.init(kind: .mine, sender: myid, text: text, colorIndex: nil))   // show my own
        note(member: myid); sentCount += 1; dataSent[myid, default: 0] += 1
    }

    private func runCommand(_ cmd: String) {
        switch cmd {
        case ":q", ":quit":
            let name = groupName
            let ts = Self.joinStamp.string(from: Date())
            leave(); messages.removeAll()
            // Group name in blue (like the header), with a timestamp.
            append(.init(kind: .info, sender: "", text: "Left group \(name) at \(ts)",
                         colorIndex: nil,
                         spans: [.plain("Left group "), .name(name), .plain(" at \(ts)")]))
        case ":?", ":help":
            info(helpText)
        case ":s", ":show":
            showMembers = true
        case ":p", ":ping":
            sendPing()
        case ":h", ":history":
            showHistory = true
        default:
            info("Unknown command \(cmd). Try :help")
        }
    }

    private func sendPing() {
        guard joined, group != 0 else { info("Join a group first."); return }
        let seq = String(Int(Date().timeIntervalSince1970 * 1000) % 100000)
        let ci = nextColor(for: seq)
        GaapWire.sendChat(group: group, ascii: Data("ping%%\(myid)%%\(seq)".utf8))
        append(.init(kind: .ping, sender: myid, text: "Send ping-\(seq) to \(groupAddress)",
                     colorIndex: ci,
                     spans: [.plain("Send ping-"), .seq(seq), .plain(" to "), .eid(groupAddress)],
                     detail: seq))
        note(member: myid); sentCount += 1; pingsSent[myid, default: 0] += 1
    }

    private func sendPong(to pinger: String, seq: String) {
        guard group != 0 else { return }
        GaapWire.sendChat(group: group, ascii: Data("pong%%\(myid)%%\(pinger)%%\(seq)".utf8))
        note(member: myid); sentCount += 1; pongsSent[myid, default: 0] += 1
    }

    // A pong arrived for `seq` — add the responder to that ping's bubble (deduped) so all pongs
    // for one ping collect in a single pill. If we never saw the ping (e.g. it predated our
    // join), start a small collector bubble keyed by the seq.
    private func collectPong(seq: String, from sender: String) {
        let host = hostOnly(sender)
        if let id = pongBubbleIdForSeq[seq], let i = messages.firstIndex(where: { $0.id == id }) {
            if !messages[i].pongs.contains(host) { messages[i].pongs.append(host) }
        } else {
            // One pill per ping seq; colorIndex carries the seq color used to render the lines.
            let ci = pingColorForSeq[seq] ?? nextColor(for: seq)
            var m = ChatMessage(kind: .pong, sender: "", text: "pong for ping-\(seq)",
                                colorIndex: ci, detail: seq)
            m.pongs = [host]
            pongBubbleIdForSeq[seq] = m.id
            append(m)
        }
    }

    // MARK: receive

    // Receive is now driven by the SHARED INBOX (see GaapInbox), not a loopback socket: the
    // always-on xTR buffers every group message to a file, so messages that arrive while
    // gaapchat is suspended are replayed on return. Polling covers both the live foreground
    // case and the catch-up on foreground — no dedup needed, since each record is consumed once.
    private func startInboxPolling() {
        inboxTimer?.invalidate()
        inboxTimer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.drainInbox() }
        }
    }

    private func drainInbox() {
        guard joined, group != 0 else { return }
        for inner in GaapInbox.drain(group: group) { handleInner(inner) }
    }

    // A raw inner IP/UDP packet the LISP app forwarded. Parse chat + dispatch.
    private func handleInner(_ data: Data) {
        guard joined, let (_, text) = GaapWire.parseChatPacket(data) else { return }
        let parms = text.components(separatedBy: "%%")
        guard parms.count >= 3 else { return }
        let op = parms[0], sender = parms[1]
        if sender == myid { return }                    // our own multicast loopback
        note(member: sender); recvCount += 1
        switch op {
        case "data":
            dataSent[sender, default: 0] += 1
            append(.init(kind: .data, sender: sender, text: parms[2], colorIndex: nil))
        case "ping":
            let seq = parms[2]
            let ci = nextColor(for: seq)
            pingsSent[sender, default: 0] += 1
            append(.init(kind: .ping, sender: sender,
                         text: "ping-\(seq) from \(sender), pong sent to \(groupAddress)",
                         colorIndex: ci,
                         spans: [.plain("ping-"), .seq(seq), .plain(" from "), .name(sender),
                                 .plain(", pong sent to "), .eid(groupAddress)],
                         detail: seq))
            sendPong(to: sender, seq: seq)
        case "pong" where parms.count >= 4:
            pongsSent[sender, default: 0] += 1
            collectPong(seq: parms[3], from: sender)   // fold into the ping's bubble
        default:
            break
        }
    }

    // MARK: helpers

    private func nextColor(for seq: String) -> Int {
        if let c = pingColorForSeq[seq] { return c }
        colorCounter += 1
        let c = colorCounter % 4
        pingColorForSeq[seq] = c
        return c
    }
    private func note(member: String) {
        let now = Date()
        if firstSeen[member] == nil { firstSeen[member] = now }   // join time = first message seen
        lastSent[member] = now                                    // last time they sent to the group
        if !members.contains(member) { members.append(member) }
    }

    // Short "time since" label for the Members window, e.g. "just now"/"12s"/"3m"/"1h".
    func agoString(_ s: TimeInterval) -> String {
        let sec = Int(s.rounded())
        if sec < 1    { return "just now" }
        if sec < 60   { return "\(sec)s" }
        if sec < 3600 { return "\(sec / 60)m" }
        return "\(sec / 3600)h"
    }
    private func info(_ text: String) {
        append(.init(kind: .info, sender: "", text: text, colorIndex: nil))
    }
    private func append(_ m: ChatMessage) {
        messages.append(m)
        if messages.count > 1000 { messages.removeFirst(messages.count - 1000) }
    }

    func onBackground() { sendReport(); saveSession() } // refresh + persist the session before suspend
    func onForeground() {
        startInboxPolling()                             // the poll timer was suspended while backgrounded
        if joined, group != 0 {                         // badge the messages that arrived while away
            missedCount += GaapInbox.pendingCount(group: group)
        }
        drainInbox()                                    // replay messages that arrived while we were away
        refreshReady(); if joined { sendReport() }
    }
    func onTerminate()  { leave() }                     // best-effort IGMP Leave on close
}
