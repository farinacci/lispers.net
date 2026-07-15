//
// LTRService.swift
//
// LISP-Trace client (ltr.py) — traces the encap/decap path between our EID and a
// destination EID. Builds an empty Type-9 LISP-Trace packet with a nonce and sends
// it over the overlay to the destination EID on UDP 2434; the ITR/RTR/ETR chain
// appends JSON path data as it forwards, and the destination ETR returns it. The
// reply, decapped by our xTR, is forwarded to us on loopback 41346. We verify the
// nonce, parse the accumulated JSON, and render it EXACTLY like ltr.py's
// display_packet — green EIDs, red RLOCs, blue node names.
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
        case sendRT(seid: String, deid: String)             // "Send round-trip ... EIDs <s> and <d> ..." bold
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
    private var localPort: UInt16 = 0
    private var timeoutTimer: Timer?
    // Dedicated socket for the NAT-traversal RTR primers (ltr.py sends the raw Type-9
    // packet straight to each RTR:2434 so the return path can route back).
    private let socketQueue = DispatchQueue(label: "lisp.ltr")
    private var ltrSocket: UDPSocket?

    // Loopback listener the extension forwards decapped LISP-Trace replies to.
    private var replyFD: Int32 = -1
    private var replySource: DispatchSourceRead?

    init(engine: LispEngine) { self.engine = engine }

    // MARK: send

    func trace(target rawTarget: String) {
        guard let engine = engine, engine.running, let seid = engine.config.eid else {
            set([LTRLine(content: .error("Enable LISP on the xTR tab first."))])
            return
        }
        let input = rawTarget.trimmingCharacters(in: .whitespaces)
        guard var deid = LispAddress(string: input, iid: UInt32(engine.config.instanceID)) else {
            set([LTRLine(content: .error("Invalid EID: \(input)"))])
            return
        }
        deid.maskLen = 32
        if deid.isMulticast {                               // ltr.py: check_multicast()
            set([LTRLine(content: .error("Multicast EID not supported"))])
            return
        }

        // Our RLOC (translated if behind a NAT) is carried in the Type-9 header.
        let rloc = engine.translatedRLOC ?? engine.rloc?.address ?? LispAddress()

        output = []
        inFlight = true
        localPort = UInt16.random(in: 20000...60000)
        nonce = Data((0..<8).map { _ in UInt8.random(in: 0...255) })
        startReplyListener()

        let s = seid.addressString, d = deid.addressString

        // The empty Type-9 LISP-Trace packet (ltr.py build_packet).
        let trace = Self.buildTracePacket(rloc: rloc, port: localPort, nonce: nonce)

        // Behind a NAT: prime the RTRs first (ltr.py), sending the raw Type-9 packet
        // straight to each RTR:2434 so the return path can route back. The RTR list is
        // the Info-Reply cache (engine.rtrList) — no lispers.net API needed.
        if engine.behindNAT, !engine.rtrList.isEmpty {
            if ltrSocket == nil { ltrSocket = UDPSocket(localPort: 0, queue: socketQueue) }
            for rtr in engine.rtrList {
                append(.init(content: .plain("Send NAT-traversal LISP-Trace to RTR " +
                    "\(rtr.addressString) ...")))
                _ = ltrSocket?.send(trace, to: rtr, port: LISP.tracePort)
            }
        }

        append(.init(content: .sendRT(seid: s, deid: d)))

        // Wrap the Type-9 packet in inner IPv4/UDP (src=our EID -> dst=dest EID, UDP
        // sport=localPort -> dport 2434) and send it over the overlay.
        let udp = Self.buildUDP(sport: localPort, dport: LISP.tracePort, payload: trace)
        let inner = PingService.buildIPv4(source: seid, dest: deid, protocol: 17, payload: udp)
        sentAt = Date()
        engine.log.lprint(.itr, "ltr: Send LISP-Trace \(s) -> \(d):\(LISP.tracePort), " +
            "nonce 0x\(nonce.map { String(format: "%02x", $0) }.joined())")
        if engine.isMirroring, let utun = OverlayTunnel.findUtun() {
            OverlayTunnel.sendRawInner(inner, toTunnelEID: utun.addr, ifIndex: utun.ifIndex)
        } else {
            engine.encapAndSend(inner: inner, destEID: deid)
        }

        timeoutTimer?.invalidate()
        timeoutTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: false) { [weak self] _ in
            self?.finishTimeout()          // ltr.py waits 3 seconds
        }
    }

    private func finishTimeout() {
        append(.init(content: .error("*** No LISP-Trace reply received (3s timeout) ***")))
        finish()
    }

    // MARK: reply listener (the extension forwards decapped Trace replies here)

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
            DispatchQueue.main.async { self?.handleReply(data) }
        }
        src.resume()
        replySource = src
    }

    private func stopReplyListener() {
        replySource?.cancel(); replySource = nil
        if replyFD >= 0 { close(replyFD); replyFD = -1 }
    }

    // A decapped inner IP/UDP LISP-Trace reply the extension forwarded. Strip IP+UDP,
    // verify the Type-9 header + nonce, parse the JSON, and render like ltr.py.
    private func handleReply(_ data: Data) {
        let b = data.startIndex
        guard data.count >= 28, (data[b] >> 4) == 4 else { return }
        let ihl = Int(data[b] & 0x0F) * 4
        guard data.count >= ihl + 8, data[b + 9] == 17 else { return }          // proto UDP
        let srcV4 = (UInt32(data[b+12]) << 24) | (UInt32(data[b+13]) << 16)
                  | (UInt32(data[b+14]) << 8) | UInt32(data[b+15])
        let payload = data.subdata(in: (b + ihl + 8)..<data.endIndex)           // Type-9 packet
        guard payload.count >= 16 else { return }
        let p = payload.startIndex
        // parse_packet(): first long must be 0x90000000 (port field zeroed on reply).
        let first = (UInt32(payload[p]) << 24) | (UInt32(payload[p+1]) << 16)
                  | (UInt32(payload[p+2]) << 8) | UInt32(payload[p+3])
        guard first == 0x9000_0000 else { return }
        guard payload.subdata(in: (p+8)..<(p+16)) == nonce else { return }       // nonce match
        let jsonData = payload.subdata(in: (p+16)..<payload.endIndex)

        timeoutTimer?.invalidate(); timeoutTimer = nil
        let rtt = Date().timeIntervalSince(sentAt).rounded(toPlaces: 3)
        append(.init(content: .received(source: LispAddress(v4: srcV4).addressString,
                                        rtt: "\(rtt)")))
        append(.init(content: .plain("")))
        displayJSON(jsonData)
        finish()
    }

    // ltr.py display_packet(): array of segments, each with se/de + a paths[] array.
    private func displayJSON(_ data: Data) {
        guard let obj = try? JSONSerialization.jsonObject(with: data),
              let segments = obj as? [[String: Any]] else {
            append(.init(content: .error("Invalid JSON data in LISP-Trace reply")))
            return
        }
        for segment in segments {
            let se = (segment["se"] as? String) ?? "?"
            let de = (segment["de"] as? String) ?? "?"
            append(.init(content: .pathHeader(se: se, de: de)))
            for path in (segment["paths"] as? [[String: Any]]) ?? [] {
                let n = (path["n"] as? String) ?? "?"
                let sr = (path["sr"] as? String) ?? "?"
                let dr = (path["dr"] as? String) ?? "?"
                let hn = (path["hn"] as? String) ?? "?"
                let ed: String, ts: String
                if let t = path["ets"] { ed = "encap"; ts = Self.tsString(t) }
                else if let t = path["dts"] { ed = "decap"; ts = Self.tsString(t) }
                else { ed = "encap"; ts = "?" }
                append(.init(content: .hop(n: n, ed: ed, sr: sr, dr: dr,
                                           drError: dr.contains("?"), ts: ts, hn: hn)))
                if path["rtts"] != nil, path["hops"] != nil, path["lats"] != nil {
                    let r = Self.fmtArray(path["rtts"], rtts: true)
                    let h = Self.fmtArray(path["hops"], rtts: false)
                    let l = Self.fmtArray(path["lats"], rtts: false)
                    append(.init(content: .plain("             recent-rtts \(r), recent-hops \(h)")))
                    append(.init(content: .plain("             recent-latencies \(l)")))
                }
            }
            append(.init(content: .plain("")))              // blank line between segments
        }
    }

    private static func tsString(_ any: Any) -> String {
        if let d = any as? Double { return "\(d)" }
        if let i = any as? Int { return "\(i)" }
        return "\(any)"
    }

    // json.dumps(array) with ltr.py's cleanup: rtts -1 -> "?"; hops/lats echoed as-is.
    private static func fmtArray(_ any: Any?, rtts: Bool) -> String {
        guard let arr = any as? [Any] else { return "[]" }
        let items = arr.map { el -> String in
            if rtts, let d = el as? Double { return d == -1 ? "?" : "\(d)" }
            if rtts, let i = el as? Int { return i == -1 ? "?" : "\(i)" }
            if let s = el as? String { return s }
            return "\(el)"
        }
        return "[" + items.joined(separator: ", ") + "]"
    }

    // MARK: Type-9 packet builders (ltr.py build_packet)

    // first long = 0x90000000 | local-port, then our IPv4 RLOC, then an 8-byte nonce.
    static func buildTracePacket(rloc: LispAddress, port: UInt16, nonce: Data) -> Data {
        var w = ByteWriter()
        w.u32(0x9000_0000 | UInt32(port))
        w.u32(rloc.v4)
        w.bytes(nonce)
        return w.data
    }

    static func buildUDP(sport: UInt16, dport: UInt16, payload: Data) -> Data {
        var w = ByteWriter()
        w.u16(sport); w.u16(dport)
        w.u16(UInt16(8 + payload.count))
        w.u16(0)                                    // checksum optional for IPv4 UDP
        w.bytes(payload)
        return w.data
    }

    private func finish() {
        stopReplyListener()
        ltrSocket?.shutdown(); ltrSocket = nil
        timeoutTimer?.invalidate(); timeoutTimer = nil
        DispatchQueue.main.async { self.inFlight = false }
    }
    func clear() { output = [] }
    private func append(_ l: LTRLine) { DispatchQueue.main.async { self.output.append(l) } }
    private func set(_ ls: [LTRLine]) {
        DispatchQueue.main.async { self.output = ls; self.inFlight = false }
    }
}
