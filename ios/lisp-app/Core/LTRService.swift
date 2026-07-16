//
// LTRService.swift
//
// LISP-Trace client (ltr.py) — traces the encap/decap path between our EID and a
// destination EID. Mirrors ltr.py's socket model so it can receive BOTH kinds of
// reply:
//   * the normal round-trip reply, which comes back over the overlay (the dest ETR
//     swaps the EIDs); our xTR decaps it and forwards it to us on loopback 41346.
//   * an ERROR return (a node that can't complete the path — map-cache miss, not an
//     EID — appends a "dr: ? (reason)" hop and returns the packet DIRECTLY to the
//     originating client's RLOC, un-encapsulated).
//
// To catch the direct error return we open a DEDICATED UDP socket, learn its NAT
// translation with an Info-Request (like the LIG tab), stamp that translated
// RLOC:port into the Type-9 header AND a pre-filled ITR path node (so return_to_
// sender has our address), send RTR NAT-primers FROM that socket (so the RTR's
// rtr_cache_nat_trace maps our header address to the socket), and listen on it.
//

import Foundation
import Combine
import Darwin

struct LTRLine: Identifiable {
    let id = UUID()
    let content: Content
    enum Content {
        case plain(String)                                  // black text
        case error(String)                                  // red text
        case learning(addr: String?)                        // "Learning ..." + red translated addr

        case sendRT(seid: String, deid: String)             // EIDs green
        case natTraversal(rtr: String)                      // "Send NAT-traversal ... RTR <x> ..."
        case received(source: String, rtt: String)          // source red, rtt orange+bold
        case pathHeader(se: String, de: String)             // "Path from <se> to <de>:" green
        // "  <n> <encap|decap>: <sr> -> <dr>, ts <ts>, node <hn>" — sr/dr red (dr bold if '?'), hn blue
        case hop(n: String, ed: String, sr: String, dr: String, drError: Bool, ts: String, hn: String)
    }
}

final class LTRService: ObservableObject {
    @Published var output: [LTRLine] = []
    @Published var inFlight = false

    private weak var engine: LispEngine?
    private var nonce = Data()
    private var sentAt = Date()
    private var done = false
    private var seid = LispAddress()
    private var deid = LispAddress()
    private var timeoutTimer: Timer?

    // Dedicated socket — sends the Info-Request + NAT-primers and receives the error return.
    private let socketQueue = DispatchQueue(label: "lisp.ltr")
    private var ltrSocket: UDPSocket?
    private var ephemRLOC = LispAddress()       // our translated RLOC (Info-Reply)
    private var ephemPort: UInt16 = 0            // our translated source port
    private var waitingForInfo = false

    // Loopback listener the extension forwards decapped (overlay) Trace replies to.
    private var replyFD: Int32 = -1
    private var replySource: DispatchSourceRead?

    init(engine: LispEngine) { self.engine = engine }

    // MARK: send

    func trace(target rawTarget: String) {
        guard let engine = engine, engine.running, let s = engine.config.eid else {
            set([LTRLine(content: .error("Enable LISP on the xTR tab first."))]); return
        }
        let input = rawTarget.trimmingCharacters(in: .whitespaces)
        guard var d = LispAddress(string: input, iid: UInt32(engine.config.instanceID)) else {
            set([LTRLine(content: .error("Invalid EID: \(input)"))]); return
        }
        d.maskLen = 32
        if d.isMulticast { set([LTRLine(content: .error("Multicast EID not supported"))]); return }

        seid = s; deid = d
        output = []; inFlight = true; done = false
        nonce = Data((0..<8).map { _ in UInt8.random(in: 0...255) })
        startReplyListener()                                // overlay replies -> 41346

        // Fallback translation if the Info-Request times out.
        ephemRLOC = engine.translatedRLOC ?? engine.rloc?.address ?? LispAddress()
        ephemPort = engine.advertisedPort

        // Open the dedicated socket and learn its translation (Info-Request), then send.
        ltrSocket?.shutdown()
        guard let sock = UDPSocket(localPort: 0, queue: socketQueue) else {
            set([LTRLine(content: .error("Could not open LTR socket."))]); return
        }
        ltrSocket = sock
        sock.startReceiving { [weak self] data, from, port, _ in
            DispatchQueue.main.async { self?.socketReceive(data, from: from, port: port) }
        }

        if let (mr, _) = engine.mapServerFor(eid: deid) {
            waitingForInfo = true
            append(.init(content: .learning(addr: nil)))
            sendInfo(mr, attempt: 1)
        } else {
            sendTrace()                                     // no MR — use the fallback translation
        }
    }

    private func sendInfo(_ mr: LispAddress, attempt: Int) {
        guard let engine = engine, let sock = ltrSocket, waitingForInfo else { return }
        var info = LispInfo(); info.nonce = lispGetControlNonce(); info.hostname = engine.xtrName
        _ = sock.send(info.encodeRequest(), to: mr, port: LISP.ctrlPort)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { [weak self] in
            guard let self = self, self.waitingForInfo else { return }
            if attempt < 3 { self.sendInfo(mr, attempt: attempt + 1) }
            else { self.waitingForInfo = false; self.sendTrace() }   // fall back
        }
    }

    private func sendTrace() {
        guard let engine = engine else { finish(); return }
        let s = "[\(seid.instanceID)]\(seid.addressString)"
        let d = "[\(deid.instanceID)]\(deid.addressString)"

        // Pre-fill our own ITR node so a node that errors can return to us — its `sr`
        // MUST equal the Type-9 header RLOC:port (the rtr_cache_nat_trace key). Include the
        // RLOC-probe telemetry for the RTR we encap to, like every other encap node.
        var itr: [String: Any] = [
            "n": "ITR", "sr": "\(ephemRLOC.addressString):\(ephemPort)",
            "ets": Date().timeIntervalSince1970, "hn": engine.xtrName]
        if let mc = engine.mapCache.lookup(deid), let r = mc.selectRLOC(hashL4: false) {
            var dr = r.rloc.addressString
            if r.encapPort != LISP.dataPort { dr += ":\(r.encapPort)" }
            itr["dr"] = dr
            itr["rtts"] = r.recentRTTs.map { $0 ?? -1 }
            itr["hops"] = r.recentHops
            itr["lats"] = r.recentLatencies
        } else {
            itr["dr"] = engine.rtrList.first?.addressString ?? "?"
        }
        let seg: [String: Any] = ["se": s, "de": d, "paths": [itr]]
        let json = (try? JSONSerialization.data(withJSONObject: [seg])) ?? Data("[]".utf8)

        let trace = Self.buildTracePacket(rloc: ephemRLOC, port: ephemPort, nonce: nonce, json: json)
        append(.init(content: .sendRT(seid: seid.addressString, deid: deid.addressString)))

        // NAT-primers: send the raw Type-9 straight to each RTR:2434 from our socket, so
        // the RTR maps our header RLOC:port -> this socket for the direct error return.
        if engine.behindNAT, !engine.rtrList.isEmpty {
            for rtr in engine.rtrList {
                append(.init(content: .natTraversal(rtr: rtr.addressString)))
                _ = ltrSocket?.send(trace, to: rtr, port: LISP.tracePort)
            }
        }

        // Round-trip: wrap the Type-9 in inner IPv4/UDP and send over the overlay.
        let udp = Self.buildUDP(sport: ephemPort, dport: LISP.tracePort, payload: trace)
        let inner = PingService.buildIPv4(source: seid, dest: deid, protocol: 17, payload: udp)
        sentAt = Date()
        engine.log.lprint(.itr, "ltr: Send LISP-Trace \(seid.addressString) -> " +
            "\(deid.addressString):\(LISP.tracePort)")
        if engine.isMirroring, let utun = OverlayTunnel.findUtun() {
            OverlayTunnel.sendRawInner(inner, toTunnelEID: utun.addr, ifIndex: utun.ifIndex)
        } else {
            engine.encapAndSend(inner: inner, destEID: deid)
        }

        timeoutTimer?.invalidate()
        timeoutTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: false) { [weak self] _ in
            guard let self = self, !self.done else { return }
            self.append(.init(content: .error("*** No LISP-Trace reply received (3s timeout) ***")))
            self.finish()
        }
    }

    // MARK: receive

    // The dedicated socket: first the Info-Reply (our translation), then possibly a
    // direct error return (a raw Type-9 packet).
    private func socketReceive(_ data: Data, from: LispAddress, port: UInt16) {
        guard let first = data.first else { return }
        switch first >> 4 {
        case LISP.typeNatInfo:
            guard waitingForInfo, let info = LispInfo.decode(data), info.isReply else { return }
            waitingForInfo = false
            if !info.globalETRRLOC.isNull { ephemRLOC = info.globalETRRLOC }
            if info.etrPort != 0 { ephemPort = info.etrPort }
            setLastLearning("\(ephemRLOC.addressString):\(ephemPort)")
            append(.init(content: .plain("")))
            sendTrace()
        case LISP.typeLispTrace:
            processTrace(data, source: from)                // direct error return (raw Type-9)
        default:
            break
        }
    }

    // The overlay reply forwarded by the extension (inner IPv4/UDP -> strip -> Type-9).
    private func handleLoopback(_ data: Data) {
        let b = data.startIndex
        guard data.count >= 28, (data[b] >> 4) == 4 else { return }
        let ihl = Int(data[b] & 0x0f) * 4
        guard data.count >= ihl + 8, data[b + 9] == 17 else { return }
        let srcV4 = (UInt32(data[b+12]) << 24) | (UInt32(data[b+13]) << 16)
                  | (UInt32(data[b+14]) << 8) | UInt32(data[b+15])
        let trace = data.subdata(in: (b + ihl + 8)..<data.endIndex)
        processTrace(trace, source: LispAddress(v4: srcV4))
    }

    // Verify a Type-9 packet's header + nonce, parse the JSON, and render it.
    private func processTrace(_ packet: Data, source: LispAddress) {
        guard !done, packet.count >= 16 else { return }
        let p = packet.startIndex
        let firstLong = (UInt32(packet[p]) << 24) | (UInt32(packet[p+1]) << 16)
                      | (UInt32(packet[p+2]) << 8) | UInt32(packet[p+3])
        guard (firstLong & 0xFF00_0000) == 0x9000_0000 else { return }   // top byte = Type-9
        guard packet.subdata(in: (p+8)..<(p+16)) == nonce else { return }
        done = true
        timeoutTimer?.invalidate(); timeoutTimer = nil

        let rtt = Date().timeIntervalSince(sentAt).rounded(toPlaces: 3)
        append(.init(content: .received(source: source.addressString, rtt: "\(rtt)")))
        append(.init(content: .plain("")))
        displayJSON(packet.subdata(in: (p+16)..<packet.endIndex))
        finish()
    }

    // ltr.py display_packet(): array of segments, each with se/de + a paths[] array.
    private func displayJSON(_ data: Data) {
        guard let obj = try? JSONSerialization.jsonObject(with: data),
              let segments = obj as? [[String: Any]] else {
            append(.init(content: .error("Invalid JSON data in LISP-Trace reply"))); return
        }
        for segment in segments {
            append(.init(content: .pathHeader(se: (segment["se"] as? String) ?? "?",
                                              de: (segment["de"] as? String) ?? "?")))
            for path in (segment["paths"] as? [[String: Any]]) ?? [] {
                let n = (path["n"] as? String) ?? "?"
                let sr = (path["sr"] as? String) ?? "?"
                let dr = (path["dr"] as? String) ?? "?"
                let hn = (path["hn"] as? String) ?? "?"
                let ed: String, ts: String
                if let t = path["ets"] { ed = "encap"; ts = Self.ts(t) }
                else if let t = path["dts"] { ed = "decap"; ts = Self.ts(t) }
                else { ed = "encap"; ts = "?" }
                append(.init(content: .hop(n: n, ed: ed, sr: sr, dr: dr,
                                           drError: dr.contains("?"), ts: ts, hn: hn)))
                if path["rtts"] != nil, path["hops"] != nil, path["lats"] != nil {
                    let r = Self.arr(path["rtts"], rtts: true)
                    let h = Self.arr(path["hops"], rtts: false)
                    let l = Self.arr(path["lats"], rtts: false)
                    append(.init(content: .plain("             recent-rtts \(r), recent-hops \(h)")))
                    append(.init(content: .plain("             recent-latencies \(l)")))
                }
            }
            append(.init(content: .plain("")))
        }
    }

    private static func ts(_ any: Any) -> String {
        if let d = any as? Double { return "\(d)" }
        if let i = any as? Int { return "\(i)" }
        return "\(any)"
    }
    private static func arr(_ any: Any?, rtts: Bool) -> String {
        guard let a = any as? [Any] else { return "[]" }
        return "[" + a.map { el -> String in
            if rtts, let d = el as? Double { return d == -1 ? "?" : "\(d)" }
            if rtts, let i = el as? Int { return i == -1 ? "?" : "\(i)" }
            if let s = el as? String { return s }
            return "\(el)"
        }.joined(separator: ", ") + "]"
    }

    // MARK: Type-9 builders

    static func buildTracePacket(rloc: LispAddress, port: UInt16, nonce: Data, json: Data) -> Data {
        var w = ByteWriter()
        w.u32(0x9000_0000 | UInt32(port))       // Type-9 + local private port
        w.u32(rloc.v4)                          // local private IPv4 RLOC
        w.bytes(nonce)                          // 8-byte nonce
        w.bytes(json)                           // pre-filled JSON (our ITR node)
        return w.data
    }
    static func buildUDP(sport: UInt16, dport: UInt16, payload: Data) -> Data {
        var w = ByteWriter()
        w.u16(sport); w.u16(dport); w.u16(UInt16(8 + payload.count)); w.u16(0)
        w.bytes(payload)
        return w.data
    }

    // MARK: loopback listener (overlay replies land here)

    private func startReplyListener() {
        guard replyFD < 0 else { return }
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = LISP.ltrReplyPort.bigEndian
        addr.sin_addr.s_addr = INADDR_ANY
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { close(fd); return }
        replyFD = fd
        let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: DispatchQueue.global())
        src.setEventHandler { [weak self] in
            var buf = [UInt8](repeating: 0, count: 9000)
            let n = recv(fd, &buf, buf.count, 0)
            guard n > 0 else { return }
            let data = Data(buf[0..<n])
            DispatchQueue.main.async { self?.handleLoopback(data) }
        }
        src.resume()
        replySource = src
    }
    private func stopReplyListener() {
        replySource?.cancel(); replySource = nil
        if replyFD >= 0 { close(replyFD); replyFD = -1 }
    }

    private func finish() {
        stopReplyListener()
        ltrSocket?.shutdown(); ltrSocket = nil
        waitingForInfo = false
        timeoutTimer?.invalidate(); timeoutTimer = nil
        DispatchQueue.main.async { self.inFlight = false }
    }
    func clear() { output = [] }
    private func append(_ l: LTRLine) { DispatchQueue.main.async { self.output.append(l) } }
    // Fill the translated address into the "Learning translation ..." line in place, so the
    // (red) address lands on the same line as the request. Falls back to a new line.
    private func setLastLearning(_ addr: String) {
        DispatchQueue.main.async {
            let line = LTRLine(content: .learning(addr: addr))
            if let i = self.output.indices.last, case .learning = self.output[i].content {
                self.output[i] = line
            } else {
                self.output.append(line)
            }
        }
    }
    private func set(_ ls: [LTRLine]) {
        DispatchQueue.main.async { self.output = ls; self.inFlight = false }
    }
}
