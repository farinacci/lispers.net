//
// LispWire.swift  (PING app)
//
// Self-contained overlay-app send path. The PING app knows NOTHING about map-caches
// or RLOCs — it builds an ICMP echo inside a raw inner IP packet and sends that (NO LISP
// header — the local hop doesn't need one) as a unicast UDP datagram to the overlay
// tunnel's own EID on 4341. The LISP app's packet-tunnel extension captures it and its
// ITR encaps + forwards. Replies come back to the LISP app, which forwards the ones that
// aren't for its own pings to us over loopback (see PingClient).
//

import Foundation
import Darwin

enum LispWire {
    static let appGroup = "group.net.lispers.xtr"
    static let injectPort: UInt16 = 4341        // the tunnel EID's LISP data port
    static let appInjectPort: UInt16 = 41342    // loopback: us -> LISP app (sim fallback, no NE)
    static let replyPort: UInt16 = 41343        // loopback: LISP app -> us (echo-replies)

    // The overlay tunnel's utun (a utun* carrying a 240.x address) + our EID (its addr).
    static func findUtun() -> (name: String, ifIndex: UInt32, addr: UInt32)? {
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0 else { return nil }
        defer { freeifaddrs(ifap) }
        var p = ifap
        while let cur = p {
            defer { p = cur.pointee.ifa_next }
            let name = String(cString: cur.pointee.ifa_name)
            guard name.hasPrefix("utun"), let sa = cur.pointee.ifa_addr,
                  sa.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            let host = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
            }
            if (host & 0xF000_0000) == 0xF000_0000 { return (name, if_nametoindex(name), host) }
        }
        return nil
    }

    static var isTunnelUp: Bool { findUtun() != nil }

    // The hostname the LISP app configured (published into the App Group). Falls back
    // to the system hostname (ProcessInfo, ".local" stripped) if the LISP app hasn't
    // written one yet.
    static var localHostname: String {
        if let shared = UserDefaults(suiteName: appGroup)?.string(forKey: "tunnelHostname"),
           !shared.trimmingCharacters(in: .whitespaces).isEmpty { return shared }
        let h = ProcessInfo.processInfo.hostName
        let sys = h.hasSuffix(".local") ? String(h.dropLast(6)) : h
        return sys == "localhost" ? "—" : sys
    }

    // The overlay instance-id, published by the LISP app into the shared App Group.
    static var instanceID: UInt32 {
        UInt32(UserDefaults(suiteName: appGroup)?.integer(forKey: "tunnelIID") ?? 0)
    }

    // The overlay EID the LISP app configured (published into the App Group).
    static var configuredEID: String? {
        let e = UserDefaults(suiteName: appGroup)?.string(forKey: "tunnelEID")
        return (e?.isEmpty == false) ? e : nil
    }

    // Age (seconds) of the LISP app's readiness heartbeat, or nil if none. The LISP app
    // stamps `xtr-heartbeat` into the App Group every second while its xTR is running
    // (foreground or the ~30s background grace) and clears it on disable/suspend. Reading
    // the file fresh each call (not cached UserDefaults) is why this reflects liveness
    // reliably — no live loopback round-trip needed, so it doesn't flap on app-switching.
    static var lispHeartbeatAge: TimeInterval? {
        guard let url = FileManager.default
                .containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
                .appendingPathComponent("xtr-heartbeat"),
              let s = try? String(contentsOf: url, encoding: .utf8),
              let t = TimeInterval(s.trimmingCharacters(in: .whitespacesAndNewlines)) else { return nil }
        return Date().timeIntervalSince1970 - t
    }

    static func dotted(_ a: UInt32) -> String {
        "\((a >> 24) & 0xff).\((a >> 16) & 0xff).\((a >> 8) & 0xff).\(a & 0xff)"
    }
    static func parseIPv4(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var v: UInt32 = 0
        for p in parts { guard let o = UInt8(p) else { return nil }; v = (v << 8) | UInt32(o) }
        return v
    }

    // MARK: builders

    static func internetChecksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        var i = data.startIndex
        while i < data.endIndex {
            let hi = UInt32(data[i]) << 8
            let lo = i + 1 < data.endIndex ? UInt32(data[i + 1]) : 0
            sum &+= hi | lo
            i += 2
        }
        while (sum >> 16) != 0 { sum = (sum & 0xFFFF) &+ (sum >> 16) }
        return UInt16(~sum & 0xFFFF)
    }

    static func buildICMPEcho(identifier: UInt16, sequence: UInt16) -> Data {
        var p = Data([8, 0, 0, 0])                          // type 8, code 0, cksum(0,0)
        p.append(UInt8(identifier >> 8)); p.append(UInt8(identifier & 0xff))
        p.append(UInt8(sequence >> 8));   p.append(UInt8(sequence & 0xff))
        p.append(Data("lispers.net PING app".utf8))
        let c = internetChecksum(p)
        p[2] = UInt8(c >> 8); p[3] = UInt8(c & 0xff)
        return p
    }

    static func buildIPv4(source: UInt32, dest: UInt32, proto: UInt8, payload: Data) -> Data {
        var h = Data()
        h.append(0x45); h.append(0)                         // ver/ihl, tos
        let total = UInt16(20 + payload.count)
        h.append(UInt8(total >> 8)); h.append(UInt8(total & 0xff))
        h.append(contentsOf: [0x00, 0x00, 0x40, 0x00])      // id, flags(DF)
        h.append(64); h.append(proto)                       // ttl, proto
        h.append(contentsOf: [0, 0])                        // checksum
        func be(_ a: UInt32) -> [UInt8] { [UInt8(a >> 24 & 0xff), UInt8(a >> 16 & 0xff), UInt8(a >> 8 & 0xff), UInt8(a & 0xff)] }
        h.append(contentsOf: be(source)); h.append(contentsOf: be(dest))
        let c = internetChecksum(h)
        h[10] = UInt8(c >> 8); h[11] = UInt8(c & 0xff)
        return h + payload
    }

    // 8-byte LISP data header: N-bit + nonce, I-bit + 24-bit instance-id.
    static func lispDataHeader(iid: UInt32) -> Data {
        let nonce = arc4random() & 0x00FF_FFFF
        let first: UInt32 = 0x8000_0000 | 0x0800_0000 | nonce
        let second: UInt32 = (iid & 0x00FF_FFFF) << 8
        return Data([UInt8(first >> 24 & 0xff), UInt8(first >> 16 & 0xff), UInt8(first >> 8 & 0xff), UInt8(first & 0xff),
                     UInt8(second >> 24 & 0xff), UInt8(second >> 16 & 0xff), UInt8(second >> 8 & 0xff), UInt8(second & 0xff)])
    }

    // MARK: send

    // Build the raw inner ICMP-echo IP packet and put it on the overlay — NO LISP header:
    // the local hop to the LISP app doesn't need one (it knows its own instance-id), so
    // it does the encap. On a DEVICE, inject it at the tunnel EID on 4341 (rides the utun;
    // the extension captures it, strips the outer wrapper, hands the app the raw inner).
    // On the SIMULATOR (no NE tunnel), send the same raw inner straight to the LISP app's
    // loopback inject port (127.0.0.1:appInjectPort). Returns (ourEID, ok).
    @discardableResult
    static func sendEcho(to dest: UInt32, identifier: UInt16, sequence: UInt16) -> (src: UInt32, ok: Bool)? {
        let icmp = buildICMPEcho(identifier: identifier, sequence: sequence)
        if let utun = findUtun() {
            let inner = buildIPv4(source: utun.addr, dest: dest, proto: 1, payload: icmp)
            let ok = sendUDP(inner, to: utun.addr, port: injectPort, boundTo: utun.ifIndex)
            return (utun.addr, ok)
        }
        // Simulator fallback: source EID is the one the LISP app published; send to loopback.
        guard let eidStr = configuredEID, let eid = parseIPv4(eidStr) else { return nil }
        let inner = buildIPv4(source: eid, dest: dest, proto: 1, payload: icmp)
        let ok = sendUDP(inner, to: 0x7f00_0001 /* 127.0.0.1 */, port: appInjectPort, boundTo: nil)
        return (eid, ok)
    }


    // MARK: native (underlay) ping — for RLOCs, NOT overlay EIDs

    // An unprivileged ICMP datagram socket (SOCK_DGRAM/IPPROTO_ICMP is allowed on iOS — no
    // entitlement, same mechanism Apple's SimplePing uses). Replies land on the SAME fd, so
    // the caller keeps it open with a read source. Returns -1 on failure.
    static func openICMPSocket() -> Int32 { socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) }

    // Ping an RLOC directly over the underlay: the kernel adds the IP header, so we send just
    // the ICMP echo. No overlay, no LISP app involved — this is a normal Internet ping.
    static func sendEchoNative(to dest: UInt32, identifier: UInt16, sequence: UInt16, fd: Int32) -> Bool {
        guard fd >= 0 else { return false }
        let icmp = buildICMPEcho(identifier: identifier, sequence: sequence)
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = dest.bigEndian
        let n = icmp.withUnsafeBytes { raw in
            withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(fd, raw.baseAddress, raw.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        return n == icmp.count
    }

    // Resolve a DNS name (or literal) to a first IPv4 address. Blocks — call off the main
    // thread. Returns host-order UInt32, or nil if it doesn't resolve.
    static func resolveDNS(_ host: String) -> UInt32? {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_DGRAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0 else { return nil }
        defer { freeaddrinfo(res) }
        var p = res
        while let cur = p {
            if cur.pointee.ai_family == AF_INET, let sa = cur.pointee.ai_addr {
                return sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
                }
            }
            p = cur.pointee.ai_next
        }
        return nil
    }

    // The device's own outgoing IPv4 for a route to `dest` — the real underlay source a
    // native ping leaves with (NOT the overlay EID). connect() on a UDP socket sends nothing;
    // it just resolves the route so getsockname() reports the chosen local address.
    static func outgoingIP(to dest: UInt32) -> UInt32? {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(9).bigEndian          // discard port; no packet is sent
        addr.sin_addr.s_addr = dest.bigEndian
        let c = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard c == 0 else { return nil }
        var local = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let g = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard g == 0 else { return nil }
        let v = UInt32(bigEndian: local.sin_addr.s_addr)
        return v == 0 ? nil : v
    }

    // Reverse-DNS (PTR) an RLOC to its hostname. Blocks — call off the main thread.
    // NI_NAMEREQD makes getnameinfo fail (return nil) instead of echoing the numeric
    // address back when there's no PTR record.
    static func reverseDNS(_ addr: String) -> String? {
        guard let v = parseIPv4(addr) else { return nil }
        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_addr.s_addr = v.bigEndian
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let r = withUnsafePointer(to: &sa) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sap in
                getnameinfo(sap, socklen_t(MemoryLayout<sockaddr_in>.size),
                            &host, socklen_t(host.count), nil, 0, NI_NAMEREQD)
            }
        }
        guard r == 0 else { return nil }
        let name = String(cString: host)
        return name.isEmpty ? nil : name
    }

    private static func sendUDP(_ data: Data, to hostBE: UInt32, port: UInt16, boundTo ifIndex: UInt32?) -> Bool {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        if var idx = ifIndex.map({ Int32($0) }) {
            setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<Int32>.size))
        }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = hostBE.bigEndian
        let n = data.withUnsafeBytes { raw in
            withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(fd, raw.baseAddress, raw.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        return n == data.count
    }
}
