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
enum ChatSpan {
    case plain(String)      // default text color
    case seq(String)        // ping/pong sequence number — colored by colorIndex
    case eid(String)        // group address — green (it's an EID)
    case name(String)       // sender/member name — bold
}

struct ChatMessage: Identifiable {
    let id = UUID()
    enum Kind { case data, mine, ping, pong, info }
    let kind: Kind
    let sender: String
    let text: String
    let colorIndex: Int?        // 0..3 for ping/pong seq coloring (blue,green,red,purple)
    var spans: [ChatSpan]? = nil   // rich rendering (seq + EID coloring); nil = plain `text`
    var detail: String? = nil      // compact content for :history (nil = use `text`)
    let at = Date()
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
    @Published var firstSeen: [String: Date] = [:]  // member -> join time (first message we saw from them)
    @Published var sentCount = 0                 // messages we sent this session (data/ping/pong)
    @Published var recvCount = 0                 // messages we received this session
    @Published var showHistory = false           // drives the History sheet (set by :history)
    @Published var showMembers = false           // drives the Members sheet (set by :show)
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
    private var listenFD: Int32 = -1
    private var listenSource: DispatchSourceRead?
    private var reportTimer: Timer?             // periodic IGMP Report (soft-state refresh)
    private var readyTimer: Timer?
    // Ping/pong color cycling (Python: blue→green→red→purple).
    private var colorCounter = -1
    private var pingColorForSeq: [String: Int] = [:]

    init() {
        startListener()
        refreshReady()
        readyTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshReady() }
        }
    }

    private func refreshReady() {
        let age = GaapWire.lispHeartbeatAge
        lispReady = (age != nil && age! < 5)
    }

    // MARK: join / leave

    func join(_ name: String) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        if joined { leave() }
        groupName = trimmed
        groupAddress = GaapHash.groupAddress(trimmed)
        group = GaapWire.parseIPv4(groupAddress) ?? 0
        joined = true
        messages.removeAll()
        members.removeAll(); lastSent.removeAll(); firstSeen.removeAll()   // fresh session state
        sentCount = 0; recvCount = 0
        info("Joined group \"\(trimmed)\" → \(groupAddress)")
        sendReport(announce: true)                      // IGMP Report → LISP registers (*,G)
        reportTimer?.invalidate()
        reportTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.sendReport() }   // periodic refresh (silent)
        }
    }

    func leave() {
        guard joined else { return }
        reportTimer?.invalidate(); reportTimer = nil
        if group != 0 {
            GaapWire.sendIGMP(type: GaapWire.igmpLeave, group: group)
        }
        joined = false
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
        note(member: myid); sentCount += 1
    }

    private func runCommand(_ cmd: String) {
        switch cmd {
        case ":q", ":quit":
            leave(); messages.removeAll(); info("Left the group.")
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
        note(member: myid); sentCount += 1
    }

    private func sendPong(to pinger: String, seq: String) {
        guard group != 0 else { return }
        GaapWire.sendChat(group: group, ascii: Data("pong%%\(myid)%%\(pinger)%%\(seq)".utf8))
        note(member: myid); sentCount += 1
    }

    // MARK: receive

    private func startListener() {
        // Tear down any existing listener first — iOS may invalidate the socket while the
        // app is backgrounded, so we rebuild it on every foreground (see onForeground()).
        listenSource?.cancel(); listenSource = nil
        if listenFD >= 0 { close(listenFD); listenFD = -1 }

        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = GaapWire.recvPort.bigEndian
        addr.sin_addr.s_addr = INADDR_ANY
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { close(fd); return }
        listenFD = fd
        let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: DispatchQueue.global())
        src.setEventHandler { [weak self] in
            var buf = [UInt8](repeating: 0, count: 2048)
            let n = recv(fd, &buf, buf.count, 0)
            guard n > 0 else { return }
            let data = Data(buf[0..<n])
            Task { @MainActor in self?.handleInner(data) }
        }
        src.resume()
        listenSource = src
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
            append(.init(kind: .data, sender: sender, text: parms[2], colorIndex: nil))
        case "ping":
            let seq = parms[2]
            let ci = nextColor(for: seq)
            append(.init(kind: .ping, sender: sender,
                         text: "ping-\(seq) from \(sender), pong sent to \(groupAddress)",
                         colorIndex: ci,
                         spans: [.plain("ping-"), .seq(seq), .plain(" from "), .name(sender),
                                 .plain(", pong sent to "), .eid(groupAddress)],
                         detail: seq))
            sendPong(to: sender, seq: seq)
        case "pong" where parms.count >= 4:
            let pinger = parms[2], seq = parms[3]
            let ci = pingColorForSeq[seq]
            append(.init(kind: .pong, sender: sender,
                         text: "pong from \(sender) for \(pinger)'s ping-\(seq)", colorIndex: ci,
                         spans: [.plain("pong from "), .name(sender),
                                 .plain(" for \(pinger)'s ping-"), .seq(seq)],
                         detail: "\(pinger)-\(seq)"))
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

    func onBackground() { sendReport() }                // one refresh before suspend
    func onForeground() {
        startListener()                                 // rebuild the 41345 socket (iOS may kill it while backgrounded)
        refreshReady(); if joined { sendReport() }
    }
    func onTerminate()  { leave() }                     // best-effort IGMP Leave on close
}
