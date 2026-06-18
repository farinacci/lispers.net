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
    let sentAt = Date()
    enum Status { case pending, reply, timeout }
}

final class PingService: ObservableObject {
    @Published var results: [PingResult] = []   // newest first; pending + done
    @Published var inFlight = false
    @Published var currentTarget: String?       // target of the active ping batch

    var active: [PingResult] { results.filter { $0.status == .pending } }
    var completed: [PingResult] { results.filter { $0.status != .pending } }

    private weak var engine: LispEngine?
    private let identifier = UInt16.random(in: 1...0xFFFF)
    private var sequence: UInt16 = 0
    private var outstanding: [UInt16: UUID] = [:]   // seq -> result id

    init(engine: LispEngine) { self.engine = engine }

    // MARK: build + send

    func ping(name: String, eid: LispAddress, count: Int = 3) {
        guard let engine = engine, engine.running, let source = engine.config.eid else {
            engine?.log.fprint(.core, "Cannot ping — LISP is not enabled")
            return
        }
        DispatchQueue.main.async { self.inFlight = true; self.currentTarget = name }
        for i in 0..<count {
            DispatchQueue.main.asyncAfter(deadline: .now() + Double(i)) { [weak self] in
                self?.sendEcho(name: name, source: source, dest: eid)
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + Double(count) + 2.5) { [weak self] in
            self?.reapTimeouts()
            DispatchQueue.main.async { self?.inFlight = false; self?.currentTarget = nil }
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
        let result = PingResult(sequence: seq, target: name, address: dest.addressString)
        outstanding[seq] = result.id
        DispatchQueue.main.async {
            self.results.insert(result, at: 0)
            if self.results.count > 50 { self.results.removeLast() }
        }
        engine.log.lprint(.itr, "Send ICMP echo-request to \(name) " +
                          "(\(dest.addressString)), seq \(seq)")
        engine.encapAndSend(inner: inner, destEID: dest)
    }

    private func reapTimeouts() {
        let timedOut = outstanding
        outstanding.removeAll()
        DispatchQueue.main.async {
            for (seq, id) in timedOut {
                if let idx = self.results.firstIndex(where: { $0.id == id }) {
                    self.results[idx].status = .timeout
                }
                self.engine?.log.lprint(.itr, "ICMP echo seq \(seq) timed out")
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
            guard ident == identifier,
                  let id = outstanding.removeValue(forKey: seq) else { return }
            engine.log.fprint(.itr, "ICMP echo-reply from \(source.addressString), " +
                              "seq \(seq)")
            DispatchQueue.main.async {
                guard let idx = self.results.firstIndex(where: { $0.id == id }) else { return }
                let rtt = (Date().timeIntervalSince(self.results[idx].sentAt) * 1000)
                    .rounded(toPlaces: 2)
                self.results[idx].rttMs = rtt
                self.results[idx].address = source.addressString
                self.results[idx].status = .reply
            }
        } else if type == 8 {               // echo-request aimed at our EID
            guard let myEID = engine.config.eid else { return }
            engine.log.lprint(.etr, "ICMP echo-request from \(source.addressString), " +
                              "seq \(seq) — replying")
            var reply = Data(icmp)
            reply[reply.startIndex] = 0     // type 0 echo-reply
            reply[reply.startIndex + 2] = 0
            reply[reply.startIndex + 3] = 0
            let cksum = internetChecksum(reply)
            reply[reply.startIndex + 2] = UInt8(cksum >> 8)
            reply[reply.startIndex + 3] = UInt8(cksum & 0xff)
            let inner = Self.buildIPv4(source: myEID, dest: source,
                                       protocol: 1, payload: reply)
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
