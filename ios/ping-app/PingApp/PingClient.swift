//
// PingClient.swift  (PING app)
//
// A ping CLIENT over the overlay tunnel. Sends echoes via LispWire (into the tunnel);
// the LISP app's ITR forwards them and forwards the replies back to us over loopback
// (127.0.0.1:replyPort). We match replies by ICMP id/seq and show rtt. We never answer
// echo-requests — the LISP app is the ETR for those.
//

import Foundation
import Combine
import Darwin
import UIKit

struct PingRow: Identifiable {
    let id = UUID()
    let sequence: UInt16
    let target: String
    var responder: String
    var rttMs: Double?
    var status: Status = .pending
    let sentAt = Date()
    enum Status { case pending, reply, timeout }
}

// One completed ping run — for the History section (where/when/success rate).
struct PingSession: Identifiable, Codable {
    var id = UUID()
    var target: String
    var startedAt: Date
    var sent: Int
    var replies: Int
    // rtt stats over the run's replies (ms). Optional so history persisted before this
    // field decodes fine (nil → the row just omits the rtt line).
    var minRtt: Double? = nil
    var avgRtt: Double? = nil
    var maxRtt: Double? = nil
    var successPct: Int { sent == 0 ? 0 : Int((Double(replies) / Double(sent) * 100).rounded()) }
}

@MainActor
final class PingClient: ObservableObject {
    @Published var results: [PingRow] = []          // newest first
    @Published var running = false
    @Published var currentTarget: String?
    @Published var tunnelUp = false
    @Published var ourEID: String = "—"
    @Published var utunName: String = ""
    @Published var interval: Double = 1.0
    @Published var history: [PingSession] = []
    @Published var lispReady = false            // LISP app's readiness heartbeat is fresh

    var active: [PingRow] { results.filter { $0.status == .pending } }       // in-flight
    var completed: [PingRow] { results.filter { $0.status != .pending } }     // done

    private let identifier = UInt16.random(in: 1...0xFFFF)
    private var outstanding: [UInt16: (rowID: UUID, sentAt: Date)] = [:]
    // Per-seq set of responder EIDs already recorded. A multicast group ping yields one
    // reply per member (e.g. our own self-reply plus each other member), so we keep the
    // seq open and add a row per NEW responder instead of stopping at the first.
    private var seqResponders: [UInt16: Set<UInt32>] = [:]
    // 224.0.0.0/4 — a group ping (multiple responders expected).
    private var targetMulticast: Bool { (target & 0xF000_0000) == 0xE000_0000 }
    private let sendQueue = DispatchQueue(label: "net.lispers.ping.send")
    private var sendSource: DispatchSourceTimer?     // fires on sendQueue — survives backgrounding
    nonisolated(unsafe) private var sendSeq: UInt16 = 0     // touched only on sendQueue
    private var target: UInt32 = 0
    private var targetStr = ""

    // Current run's stats (finalized into `history` on stop / next start).
    private var sessSent = 0
    private var sessReplies = 0
    private var sessStart = Date()
    // Running rtt stats for the current run (ms).
    private var sessRttSum = 0.0
    private var sessRttMin = Double.greatestFiniteMagnitude
    private var sessRttMax = 0.0
    private var sessRttCount = 0

    private var listenFD: Int32 = -1
    private var listenSource: DispatchSourceRead?
    private let historyKey = "pingHistory.v1"

    private var pollTimer: Timer?

    init() {
        if let d = UserDefaults.standard.data(forKey: historyKey),
           let h = try? JSONDecoder().decode([PingSession].self, from: d) { history = h }
        startReplyListener()
        refreshTunnel()
        // Poll the tunnel + readiness state so up/down + EID + "LISP app ready" update
        // live (the utun can come up, or LISP get enabled, while PING is already open).
        pollTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshTunnel() }
        }
    }

    func refreshTunnel() {
        // Readiness: the LISP app stamps an App-Group heartbeat every second while its xTR
        // can forward; treat it as ready if stamped within the last 5s. Read fresh (file,
        // not cached), so this is correct the instant PING foregrounds — no round-trip lag.
        lispReady = (LispWire.lispHeartbeatAge ?? .infinity) < 5

        // Local EID comes from the LISP app via the App Group (shown even if the utun
        // isn't visible this instant). Device = real utun; simulator = loopback to the
        // LISP app (usable as long as the LISP app has published its EID).
        if let u = LispWire.findUtun() {
            tunnelUp = true; utunName = u.name
            ourEID = LispWire.configuredEID ?? LispWire.dotted(u.addr)
        } else if let eid = LispWire.configuredEID {
            tunnelUp = true; utunName = "loopback"    // sim: no NE, go straight to the LISP app
            ourEID = eid
        } else {
            tunnelUp = false; utunName = ""
            ourEID = "—"
        }
    }

    // MARK: send

    func start(_ input: String) {
        refreshTunnel()
        guard let dst = LispWire.parseIPv4(input.trimmingCharacters(in: .whitespaces)) else { return }
        stop()                                          // finalizes any prior run
        target = dst; targetStr = LispWire.dotted(dst)
        sessSent = 0; sessReplies = 0; sessStart = Date()
        sessRttSum = 0; sessRttMin = .greatestFiniteMagnitude; sessRttMax = 0; sessRttCount = 0
        running = true; currentTarget = targetStr
        acquireBgTask()                                 // hold the assertion for the whole
                                                        // session, so a later swipe-up gets the
                                                        // background window with no acquire race
        startSendLoop(resetSeq: true)                   // fires immediately + every interval
    }

    // The send loop runs on a background GCD queue (a DispatchSourceTimer), NOT a main
    // run-loop Timer — so it keeps firing while PING is backgrounded during the keep-alive
    // grace (main-thread Timers stop the moment the app leaves the foreground, which is why
    // the LISP counters froze after ~1 packet). The send itself is pure; only the UI
    // bookkeeping hops to the main actor, and if we're backgrounded it just defers — the
    // packets still go out, which is what keeps the xTR's map-cache counters incrementing.
    private func startSendLoop(resetSeq: Bool = false) {
        stopSendLoop()
        let ident = identifier
        let tgt = target
        let ivl = max(interval, 0.1)
        if resetSeq { sendQueue.async { [weak self] in self?.sendSeq = 0 } }   // new session only
        let src = DispatchSource.makeTimerSource(queue: sendQueue)
        src.schedule(deadline: .now(), repeating: ivl, leeway: .milliseconds(50))
        src.setEventHandler { [weak self] in
            guard let self = self else { return }
            self.sendSeq &+= 1
            let s = self.sendSeq
            let sentAt = Date()
            let ok = LispWire.sendEcho(to: tgt, identifier: ident, sequence: s) != nil
            Task { @MainActor in self.recordSent(seq: s, ok: ok, sentAt: sentAt) }
        }
        sendSource = src
        src.resume()
    }

    private func stopSendLoop() { sendSource?.cancel(); sendSource = nil }

    // Returning to the foreground: drop the grace and make sure the send loop is running
    // again. iOS suspends a backgrounded app (freezing the send queue) within a second or
    // two despite the keep-alive assertion, and it doesn't reliably resume itself — so we
    // restart it here (continuing the sequence) whenever PING is on screen mid-session.
    func enteredForeground() {
        cancelGrace()
        refreshTunnel()
        if running { acquireBgTask(); startSendLoop() }   // re-arm assertion + resume sending
    }

    func setInterval(_ s: Double) { interval = s; if running { startSendLoop() } }

    func stop() {
        graceSource?.cancel(); graceSource = nil
        stopSendLoop()
        if running { finalizeSession() }
        running = false; currentTarget = nil
        releaseBgTask()
    }

    // Keep pinging briefly after leaving the app, then pause. Key detail: the background
    // assertion is acquired in start() (while foreground, with plenty of time), NOT here —
    // so it's already in place BEFORE the user swipes up, and iOS grants the ~30s window
    // immediately instead of losing the acquire race to the transition (which was killing
    // the send loop the instant the swipe began). The grace-stop runs on a GCD timer, not a
    // main-run-loop Timer, so it fires reliably while backgrounded.
    private var graceSource: DispatchSourceTimer?
    private let graceQueue = DispatchQueue(label: "net.lispers.ping.grace")
    private var bgTask: UIBackgroundTaskIdentifier = .invalid

    private func acquireBgTask() {
        guard bgTask == .invalid else { return }
        bgTask = UIApplication.shared.beginBackgroundTask(withName: "ping-run") { [weak self] in
            Task { @MainActor in self?.endGrace() }     // iOS reclaimed our time
        }
    }
    private func releaseBgTask() {
        if bgTask != .invalid { UIApplication.shared.endBackgroundTask(bgTask); bgTask = .invalid }
    }

    func keepAliveBriefly(_ seconds: TimeInterval = 25) {
        guard running else { return }
        acquireBgTask()                                 // should already be held from start()
        graceSource?.cancel()
        let src = DispatchSource.makeTimerSource(queue: graceQueue)
        src.schedule(deadline: .now() + seconds)
        src.setEventHandler { [weak self] in Task { @MainActor in self?.endGrace() } }
        graceSource = src
        src.resume()
    }
    func cancelGrace() {
        graceSource?.cancel(); graceSource = nil        // keep the bgTask held for the session
    }
    private func endGrace() {
        graceSource?.cancel(); graceSource = nil
        stopSendLoop()          // grace window over: pause emitting (battery). Keep the
                                // session "running" so returning to the foreground resumes it.
        releaseBgTask()         // let iOS suspend us now
    }

    private func finalizeSession() {
        guard sessSent > 0 else { return }
        let avg = sessRttCount > 0 ? sessRttSum / Double(sessRttCount) : nil
        history.insert(PingSession(target: targetStr, startedAt: sessStart,
                                   sent: sessSent, replies: sessReplies,
                                   minRtt: sessRttCount > 0 ? sessRttMin : nil,
                                   avgRtt: avg,
                                   maxRtt: sessRttCount > 0 ? sessRttMax : nil), at: 0)
        if history.count > 100 { history.removeLast(history.count - 100) }
        if let d = try? JSONEncoder().encode(history) { UserDefaults.standard.set(d, forKey: historyKey) }
        sessSent = 0; sessReplies = 0
        sessRttSum = 0; sessRttMin = .greatestFiniteMagnitude; sessRttMax = 0; sessRttCount = 0
    }

    func clearHistory() { history.removeAll(); UserDefaults.standard.removeObject(forKey: historyKey) }

    // Bookkeeping for a packet the send loop already emitted (runs on the main actor).
    private func recordSent(seq: UInt16, ok: Bool, sentAt: Date) {
        guard running else { return }
        if !ok {                                        // no overlay path
            tunnelUp = false
            var row = PingRow(sequence: seq, target: targetStr, responder: targetStr)
            row.status = .timeout
            results.insert(row, at: 0)
            return
        }
        tunnelUp = true
        sessSent += 1
        let row = PingRow(sequence: seq, target: targetStr, responder: targetStr)
        outstanding[seq] = (row.id, sentAt)
        results.insert(row, at: 0)
        if results.count > 500 { results.removeLast() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { [weak self] in
            guard let self = self, let o = self.outstanding.removeValue(forKey: seq) else { return }
            self.seqResponders.removeValue(forKey: seq)
            if let i = self.results.firstIndex(where: { $0.id == o.rowID }), self.results[i].status == .pending {
                self.results[i].status = .timeout
            }
        }
    }

    // MARK: receive (loopback from the LISP app)

    private func startReplyListener() {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = LispWire.replyPort.bigEndian
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
            Task { @MainActor in self?.handleReply(data) }
        }
        src.resume()
        listenSource = src
    }

    // `data` is the inner reply IP packet: IP[src=responder, dst=ourEID] / ICMP echo-reply.
    private func handleReply(_ data: Data) {
        guard data.count >= 20, (data[data.startIndex] >> 4) == 4 else { return }
        let b = data.startIndex
        let ihl = Int(data[b] & 0x0F) * 4
        guard data[b + 9] == 1, data.count >= ihl + 8, data[b + ihl] == 0 else { return }   // ICMP echo-reply
        let ident = (UInt16(data[b+ihl+4]) << 8) | UInt16(data[b+ihl+5])
        let seq   = (UInt16(data[b+ihl+6]) << 8) | UInt16(data[b+ihl+7])
        guard ident == identifier, let o = outstanding[seq] else { return }
        let responderV4 = (UInt32(data[b+12]) << 24) | (UInt32(data[b+13]) << 16)
                        | (UInt32(data[b+14]) << 8) | UInt32(data[b+15])
        // One reply per member per seq — ignore a duplicate from the same responder.
        var seen = seqResponders[seq] ?? []
        guard !seen.contains(responderV4) else { return }
        let firstResponder = seen.isEmpty
        seen.insert(responderV4); seqResponders[seq] = seen
        let responder = "\(data[b+12]).\(data[b+13]).\(data[b+14]).\(data[b+15])"
        let rtt = (Date().timeIntervalSince(o.sentAt) * 1000).rounded()
        sessReplies += 1
        sessRttSum += rtt; sessRttCount += 1
        sessRttMin = min(sessRttMin, rtt); sessRttMax = max(sessRttMax, rtt)
        if firstResponder {
            // Fill in the placeholder row for this seq.
            if let i = results.firstIndex(where: { $0.id == o.rowID }) {
                results[i].rttMs = rtt
                results[i].responder = responder
                results[i].status = .reply
            }
        } else {
            // Additional multicast responder — one row per member.
            var row = PingRow(sequence: seq, target: targetStr, responder: responder)
            row.rttMs = rtt; row.status = .reply
            results.insert(row, at: 0)
            if results.count > 500 { results.removeLast() }
        }
        // Unicast: single reply, so release the seq now (the 2.5s timeout becomes a no-op).
        // Multicast: keep it open until the timeout so late members still land.
        if !targetMulticast {
            outstanding.removeValue(forKey: seq)
            seqResponders.removeValue(forKey: seq)
        }
    }

    func clearResults() { results.removeAll { $0.status != .pending } }

    // Trim the oldest N completed rows (results is newest-first). Pending kept.
    func clearOldest(_ n: Int = 100) {
        let ids = Set(results.filter { $0.status != .pending }.suffix(n).map { $0.id })
        results.removeAll { ids.contains($0.id) }
    }
}
