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

struct ChatMessage: Identifiable {
    let id = UUID()
    enum Kind { case data, mine, ping, pong, info }
    let kind: Kind
    let sender: String
    let text: String
    let colorIndex: Int?        // 0..3 for ping/pong seq coloring (blue,green,red,purple)
    let at = Date()
}

@MainActor
final class ChatClient: ObservableObject {
    @Published var messages: [ChatMessage] = []
    @Published var groupName = ""
    @Published var groupAddress = ""            // 224.b2.b3.b4
    @Published var joined = false
    @Published var lispReady = false
    @Published var members: [String] = []       // senders seen (":show")
    @Published var nickname: String {
        didSet { UserDefaults.standard.set(nickname, forKey: "nickname") }
    }

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
        nickname = UserDefaults.standard.string(forKey: "nickname") ?? "me"
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
        info("Joined group '\(trimmed)' → \(groupAddress) as \(myid)")
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
            info("Send IGMPv2 leave for group \(groupAddress)")
        }
        joined = false
    }

    private func sendReport(announce: Bool = false) {
        guard joined, group != 0 else { return }
        GaapWire.sendIGMP(type: GaapWire.igmpReport, group: group)
        if announce { info("Send IGMPv2 report for group \(groupAddress)") }
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
        note(member: myid)
    }

    private func runCommand(_ cmd: String) {
        switch cmd {
        case ":q", ":quit":
            leave(); messages.removeAll(); info("Left the group.")
        case ":?", ":help":
            info(helpText)
        case ":s", ":show":
            info("Members:\n" + (members.isEmpty ? "  (none yet)"
                 : members.map { "  \($0)" }.joined(separator: "\n")))
        case ":p", ":ping":
            sendPing()
        case ":h", ":history":
            info("History: \(messages.count) messages this session")
        default:
            info("Unknown command \(cmd). Try :help")
        }
    }

    private func sendPing() {
        guard joined, group != 0 else { info("Join a group first."); return }
        let seq = String(Int(Date().timeIntervalSince1970 * 1000) % 100000)
        let ci = nextColor(for: seq)
        GaapWire.sendChat(group: group, ascii: Data("ping%%\(myid)%%\(seq)".utf8))
        append(.init(kind: .ping, sender: myid, text: "sent ping-\(seq) to group", colorIndex: ci))
    }

    private func sendPong(to pinger: String, seq: String) {
        guard group != 0 else { return }
        GaapWire.sendChat(group: group, ascii: Data("pong%%\(myid)%%\(pinger)%%\(seq)".utf8))
    }

    // MARK: receive

    private func startListener() {
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
        note(member: sender)
        switch op {
        case "data":
            append(.init(kind: .data, sender: sender, text: parms[2], colorIndex: nil))
        case "ping":
            let seq = parms[2]
            let ci = nextColor(for: seq)
            append(.init(kind: .ping, sender: sender,
                         text: "ping-\(seq) from \(sender) — pong sent", colorIndex: ci))
            sendPong(to: sender, seq: seq)
        case "pong" where parms.count >= 4:
            let pinger = parms[2], seq = parms[3]
            let ci = pingColorForSeq[seq]
            append(.init(kind: .pong, sender: sender,
                         text: "pong from \(sender) for \(pinger)'s ping-\(seq)", colorIndex: ci))
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
        if !members.contains(member) { members.append(member) }
    }
    private func info(_ text: String) {
        append(.init(kind: .info, sender: "", text: text, colorIndex: nil))
    }
    private func append(_ m: ChatMessage) {
        messages.append(m)
        if messages.count > 1000 { messages.removeFirst(messages.count - 1000) }
    }

    func onBackground() { sendReport() }                // one refresh before suspend
    func onForeground() { refreshReady(); if joined { sendReport() } }
    func onTerminate()  { leave() }                     // best-effort IGMP Leave on close
}
