//
// PingService.swift
//
// EID-to-EID ping over the overlay. Builds the full inner IPv4 + ICMP echo
// packet in-app (no raw sockets needed — the outer transport is our UDP
// data socket), matches echo-replies by id/sequence, and answers inbound
// echo-requests aimed at our EID so other xTRs can ping us.
//

import Foundation
import Combine

struct PingResult: Identifiable {
    let id = UUID()
    let sequence: UInt16
    let target: String
    var address: String
    var rttMs: Double?          // set on reply
    var status: Status = .pending
    var multicast = false       // a group ping — reply rows are per group member
    let sentAt = Date()
    enum Status { case pending, reply, timeout }
}

final class PingService: ObservableObject {
    @Published var results: [PingResult] = []   // newest first; pending + done
    @Published var inFlight = false
    @Published var continuous = false           // running until the tab is left
    @Published var currentTarget: String?       // target of the active ping
    @Published var interval: Double = 1.0        // seconds between echoes

    var active: [PingResult] { results.filter { $0.status == .pending } }
    var completed: [PingResult] { results.filter { $0.status != .pending } }

    private weak var engine: LispEngine?
    private let identifier = UInt16.random(in: 1...0xFFFF)
    private var sequence: UInt16 = 0
    // Per-sequence outstanding request. A multicast echo yields MANY replies
    // (one per group member), so we keep the seq open and track which sources
    // already answered. Accessed only on the main queue.
    private struct Outstanding {
        let id: UUID                    // the placeholder result row
        let target: String
        let sentAt: Date
        let multicast: Bool
        var gotReply = false
        var sources: Set<UInt32> = []   // responder EIDs already recorded
    }
    private var outstanding: [UInt16: Outstanding] = [:]
    private var pingTimer: Timer?
    private var graceTimer: Timer?
    private var currentEID: LispAddress?

    init(engine: LispEngine) { self.engine = engine }

    // MARK: build + send

    // Continuous ping (one echo every `interval`) until stopContinuous(). The
    // Ping tab keeps it alive for 5s after the tab is left (so map-cache counters
    // can be watched), and stops it at once if the app is backgrounded. Tapping
    // another target restarts against it.
    func startContinuous(name: String, eid: LispAddress) {
        guard let engine = engine, engine.running, let source = engine.config.eid else {
            engine?.log.fprint(.core, "Cannot ping — LISP is not enabled")
            return
        }
        var eid = eid
        // A group is looked up/encapsulated in our instance-id (the default
        // (0/0, 224/4) entry lives there).
        if eid.isMulticast { eid.instanceID = UInt32(engine.config.instanceID); eid.maskLen = 32 }
        stopContinuous()
        currentEID = eid
        DispatchQueue.main.async {
            self.inFlight = true; self.continuous = true; self.currentTarget = name
        }
        sendEcho(name: name, source: source, dest: eid)
        scheduleTimer(name: name, eid: eid)
    }

    // (Re)create the repeating echo timer at the current interval.
    private func scheduleTimer(name: String, eid: LispAddress) {
        pingTimer?.invalidate()
        pingTimer = Timer.scheduledTimer(withTimeInterval: max(interval, 0.05),
                                         repeats: true) { [weak self] _ in
            guard let self = self, let engine = self.engine, engine.running,
                  let source = engine.config.eid else { self?.stopContinuous(); return }
            self.sendEcho(name: name, source: source, dest: eid)
        }
    }

    // Change the interval; if a ping is running, apply it live.
    func setInterval(_ seconds: Double) {
        interval = seconds
        if continuous, let eid = currentEID, let name = currentTarget {
            scheduleTimer(name: name, eid: eid)
        }
    }

    func stopContinuous() {
        pingTimer?.invalidate(); pingTimer = nil
        graceTimer?.invalidate(); graceTimer = nil
        currentEID = nil
        DispatchQueue.main.async {
            self.inFlight = false; self.continuous = false; self.currentTarget = nil
        }
    }

    // Switching tabs keeps the ping going for `seconds` more (map-cache counters
    // keep climbing); returning to the tab (cancelGrace) keeps it alive.
    func keepAliveBriefly(_ seconds: TimeInterval = 5) {
        guard continuous else { return }
        graceTimer?.invalidate()
        graceTimer = Timer.scheduledTimer(withTimeInterval: seconds,
                                          repeats: false) { [weak self] _ in
            self?.stopContinuous()
        }
    }

    func cancelGrace() {
        graceTimer?.invalidate(); graceTimer = nil
    }

    // Clear finished results (keeps any in-flight pings).
    func clearResults() {
        DispatchQueue.main.async { self.results.removeAll { $0.status != .pending } }
    }

    // Remove the oldest N completed results. `results` is newest-first, so the
    // oldest completed rows are at the end. Pending pings are always kept.
    func clearOldest(_ n: Int = 100) {
        DispatchQueue.main.async {
            let oldest = self.results.filter { $0.status != .pending }.suffix(n)
            let ids = Set(oldest.map { $0.id })
            self.results.removeAll { ids.contains($0.id) }
        }
    }

    private func sendEcho(name: String, source: LispAddress, dest: LispAddress) {
        guard let engine = engine else { return }
        sequence &+= 1
        let seq = sequence
        let icmp = Self.buildICMPEcho(type: 8, identifier: identifier, sequence: seq)
        let inner = Self.buildIPv4(source: source, dest: dest, protocol: 1,
                                   payload: icmp)
        // Insert a pending row immediately so the UI shows the in-flight echo.
        let multicast = dest.isMulticast
        let result = PingResult(sequence: seq, target: name,
                                address: dest.addressString, multicast: multicast)
        DispatchQueue.main.async {
            self.outstanding[seq] = Outstanding(id: result.id, target: name,
                                                sentAt: result.sentAt, multicast: multicast)
            self.results.insert(result, at: 0)
            if self.results.count > 500 { self.results.removeLast() }
        }
        engine.log.dprint(.itr, "Send ICMP echo-request to \(name) " +
                          "(\(dest.addressString)), seq \(seq)")
        engine.encapAndSend(inner: inner, destEID: dest)
        // Per-sequence timeout. For multicast the seq stays open until here so
        // every group member can answer; only mark timeout if nobody did.
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { [weak self] in
            guard let self = self, let o = self.outstanding.removeValue(forKey: seq)
            else { return }
            if !o.gotReply {
                if let idx = self.results.firstIndex(where: { $0.id == o.id }) {
                    self.results[idx].status = .timeout
                }
                self.engine?.log.dprint(.itr, "ICMP echo seq \(seq) timed out")
            }
        }
    }

    // MARK: receive

    func processInboundICMP(_ icmp: Data, from source: LispAddress) {
        guard icmp.count >= 8, let engine = engine else { return }
        let type = icmp[icmp.startIndex]
        var r = ByteReader(icmp)
        r.skip(4)
        guard let ident = r.u16(), let seq = r.u16() else { return }

        if type == 0 {                      // echo-reply
            guard ident == identifier else { return }
            engine.log.dprint(.itr, "Receive ICMP echo-reply " +
                              "from \(source.addressString), seq \(seq)")
            let srcStr = source.addressString
            let srcV4 = source.v4
            DispatchQueue.main.async {
                guard var o = self.outstanding[seq], !o.sources.contains(srcV4) else { return }
                o.sources.insert(srcV4)
                let rtt = (Date().timeIntervalSince(o.sentAt) * 1000).rounded()
                if !o.gotReply {
                    o.gotReply = true
                    if let idx = self.results.firstIndex(where: { $0.id == o.id }) {
                        self.results[idx].rttMs = rtt
                        self.results[idx].address = srcStr
                        self.results[idx].status = .reply
                    }
                } else {
                    // Additional responder (multicast group) — one row per source.
                    var r = PingResult(sequence: seq, target: o.target,
                                       address: srcStr, multicast: true)
                    r.rttMs = rtt; r.status = .reply
                    self.results.insert(r, at: 0)
                    if self.results.count > 500 { self.results.removeLast() }
                }
                // Unicast: done. Multicast: keep open for more until the timeout.
                self.outstanding[seq] = o.multicast ? o : nil
            }
        } else if type == 8 {               // echo-request (unicast EID or joined group)
            guard let myEID = engine.config.eid else { return }
            // Don't reply to our OWN echo-request looped back to us as a member of the
            // group we pinged — the RTR replicates our multicast packet back to us.
            // A self-reply goes UNICAST to our own EID and encaps via the unicast
            // map-cache entry, so a group ping would wrongly bump the unicast 0/0 (and
            // decent 240/8) counters. Only the multicast entry should count for a
            // group ping; drop the self-loop.
            if source.v4 == myEID.v4 {
                engine.log.dprint(.etr, "Ignoring our own echo-request looped back " +
                                  "from a joined group (no self-reply)")
                return
            }
            engine.log.lprint(.etr, "Receive ICMP echo-request from " +
                              "\(source.addressString), seq \(seq)")
            var reply = Data(icmp)
            reply[reply.startIndex] = 0     // type 0 echo-reply
            reply[reply.startIndex + 2] = 0
            reply[reply.startIndex + 3] = 0
            let cksum = internetChecksum(reply)
            reply[reply.startIndex + 2] = UInt8(cksum >> 8)
            reply[reply.startIndex + 3] = UInt8(cksum & 0xff)
            let inner = Self.buildIPv4(source: myEID, dest: source,
                                       protocol: 1, payload: reply)
            // Explicit ETR log confirming the echo-reply is sent — including for a
            // joined multicast group (the reply goes unicast to the pinger EID in
            // `source`). encapAndSend then logs the actual encap, or a drop if the
            // return-path RLOCs are all unreach.
            engine.log.lprint(.etr, "Send ICMP echo-reply \(myEID.addressString) -> " +
                              "\(source.addressString), seq \(seq)")
            engine.encapAndSend(inner: inner, destEID: source)
        }
    }

    // MARK: packet builders

    static func buildICMPEcho(type: UInt8, identifier: UInt16,
                              sequence: UInt16) -> Data {
        var w = ByteWriter()
        w.u8(type); w.u8(0)                 // type, code
        w.u16(0)                            // checksum placeholder
        w.u16(identifier); w.u16(sequence)
        w.bytes(Data("lispers.net iOS ping".utf8))
        var pkt = w.data
        let cksum = internetChecksum(pkt)
        pkt[2] = UInt8(cksum >> 8); pkt[3] = UInt8(cksum & 0xff)
        return pkt
    }

    static func buildIPv4(source: LispAddress, dest: LispAddress,
                          protocol proto: UInt8, payload: Data) -> Data {
        var w = ByteWriter()
        w.u8(0x45); w.u8(0)
        w.u16(UInt16(20 + payload.count))
        w.u16(UInt16.random(in: 0...0xFFFF))
        w.u16(0x4000)                       // DF
        w.u8(64)                            // TTL
        w.u8(proto)
        w.u16(0)                            // checksum below
        w.bytes(source.packAddress())
        w.bytes(dest.packAddress())
        var header = w.data
        let cksum = internetChecksum(header)
        header[10] = UInt8(cksum >> 8); header[11] = UInt8(cksum & 0xff)
        return header + payload
    }
}
