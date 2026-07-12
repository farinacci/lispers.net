//
// GaapWire.swift  (gaapchat)
//
// Self-contained overlay-app wire path, like the PING app's LispWire. gaapchat knows nothing
// about map-caches/RLOCs — it builds raw inner IPv4 packets and injects them over the LISP
// tunnel (utun EID:4341 on device; loopback 41342 on the simulator). The LISP app's xTR
// encaps/forwards; received group traffic is forwarded back to us on the overlay-recv port.
//
//   • IGMPv2 Report/Leave (proto 2, inner dst = our EID) → the LISP app registers/leaves a
//     soft-state (*,G) so the phone receives the group. (Inner dst = EID per the PING/ICMP
//     convention — the LISP app parses IGMP locally, doesn't forward it.)
//   • Chat (proto 17 UDP dport 0xfafa, inner dst = group) → the LISP app encaps it as
//     multicast to the group; members receive it and their LISP apps forward it to gaapchat.
//

import Foundation
import Darwin

enum GaapWire {
    static let appGroup = "group.net.lispers.xtr"
    static let injectPort: UInt16 = 4341        // the tunnel EID's LISP data port (device utun)
    static let appInjectPort: UInt16 = 41342    // loopback: us -> LISP app (sim fallback, no NE)
    static let recvPort: UInt16 = 41345         // loopback: LISP app -> us (received group UDP)
    static let chatPort: UInt16 = 0xfafa        // Python gaapchat app_port — interop

    // IGMPv2 (RFC 2236) message types.
    static let igmpReport: UInt8 = 0x16
    static let igmpLeave: UInt8  = 0x17
    static let appName = "gaapchat"             // appended to IGMP so the xTR labels the group

    // MARK: shared overlay state (published by the LISP app into the App Group)

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

    static var configuredEID: String? {
        let e = UserDefaults(suiteName: appGroup)?.string(forKey: "tunnelEID")
        return (e?.isEmpty == false) ? e : nil
    }
    static var instanceID: UInt32 {
        UInt32(UserDefaults(suiteName: appGroup)?.integer(forKey: "tunnelIID") ?? 0)
    }
    static var localHostname: String {
        if let s = UserDefaults(suiteName: appGroup)?.string(forKey: "tunnelHostname"),
           !s.trimmingCharacters(in: .whitespaces).isEmpty { return s }
        let h = ProcessInfo.processInfo.hostName
        let sys = h.hasSuffix(".local") ? String(h.dropLast(6)) : h
        return sys == "localhost" ? "phone" : sys
    }
    // Age (s) of the LISP app's readiness heartbeat, or nil. Same file the PING app reads.
    static var lispHeartbeatAge: TimeInterval? {
        guard let url = FileManager.default
                .containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
                .appendingPathComponent("xtr-heartbeat"),
              let s = try? String(contentsOf: url, encoding: .utf8),
              let t = TimeInterval(s.trimmingCharacters(in: .whitespacesAndNewlines)) else { return nil }
        return Date().timeIntervalSince1970 - t
    }

    // MARK: helpers

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
    static func internetChecksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0; var i = data.startIndex
        while i < data.endIndex {
            let hi = UInt32(data[i]) << 8
            let lo = i + 1 < data.endIndex ? UInt32(data[i + 1]) : 0
            sum &+= hi | lo; i += 2
        }
        while (sum >> 16) != 0 { sum = (sum & 0xFFFF) &+ (sum >> 16) }
        return UInt16(~sum & 0xFFFF)
    }
    private static func be(_ a: UInt32) -> [UInt8] {
        [UInt8(a >> 24 & 0xff), UInt8(a >> 16 & 0xff), UInt8(a >> 8 & 0xff), UInt8(a & 0xff)]
    }

    // MARK: builders

    static func buildIPv4(source: UInt32, dest: UInt32, proto: UInt8, payload: Data) -> Data {
        var h = Data()
        h.append(0x45); h.append(0)
        let total = UInt16(20 + payload.count)
        h.append(UInt8(total >> 8)); h.append(UInt8(total & 0xff))
        h.append(contentsOf: [0x00, 0x00, 0x40, 0x00])          // id, flags(DF)
        h.append(64); h.append(proto)                           // ttl, proto
        h.append(contentsOf: [0, 0])                            // checksum
        h.append(contentsOf: be(source)); h.append(contentsOf: be(dest))
        let c = internetChecksum(h)
        h[10] = UInt8(c >> 8); h[11] = UInt8(c & 0xff)
        return h + payload
    }

    static func buildIGMP(type: UInt8, group: UInt32) -> Data {
        var p = Data([type, 0, 0, 0])                           // type, max-resp 0, cksum(0,0)
        p.append(contentsOf: be(group))
        let c = internetChecksum(p)
        p[2] = UInt8(c >> 8); p[3] = UInt8(c & 0xff)
        return p
    }

    // 8-byte UDP header + payload. Checksum 0 = "none" (valid for IPv4 UDP); the inner packet
    // is delivered raw to gaapchat which parses it by hand, so no checksum is needed.
    static func buildUDP(sport: UInt16, dport: UInt16, payload: Data) -> Data {
        var u = Data()
        let len = UInt16(8 + payload.count)
        u.append(UInt8(sport >> 8)); u.append(UInt8(sport & 0xff))
        u.append(UInt8(dport >> 8)); u.append(UInt8(dport & 0xff))
        u.append(UInt8(len >> 8)); u.append(UInt8(len & 0xff))
        u.append(0); u.append(0)
        return u + payload
    }

    // MARK: send

    // IGMPv2 Report/Leave to the LISP app (inner dst = our EID, proto 2).
    @discardableResult
    static func sendIGMP(type: UInt8, group: UInt32) -> Bool {
        let igmp = buildIGMP(type: type, group: group) + Data(appName.utf8)   // trailing joiner name
        if let utun = findUtun() {
            let inner = buildIPv4(source: utun.addr, dest: utun.addr, proto: 2, payload: igmp)
            return sendUDP(inner, to: utun.addr, port: injectPort, boundTo: utun.ifIndex)
        }
        guard let eidStr = configuredEID, let eid = parseIPv4(eidStr) else { return false }
        let inner = buildIPv4(source: eid, dest: eid, proto: 2, payload: igmp)
        return sendUDP(inner, to: 0x7f00_0001, port: appInjectPort, boundTo: nil)
    }

    // Chat message to a group (inner dst = group, UDP dport 0xfafa). Returns (ourEID, ok).
    @discardableResult
    static func sendChat(group: UInt32, ascii: Data) -> (src: UInt32, ok: Bool)? {
        let udp = buildUDP(sport: chatPort, dport: chatPort, payload: ascii)
        if let utun = findUtun() {
            let inner = buildIPv4(source: utun.addr, dest: group, proto: 17, payload: udp)
            return (utun.addr, sendUDP(inner, to: utun.addr, port: injectPort, boundTo: utun.ifIndex))
        }
        guard let eidStr = configuredEID, let eid = parseIPv4(eidStr) else { return nil }
        let inner = buildIPv4(source: eid, dest: group, proto: 17, payload: udp)
        return (eid, sendUDP(inner, to: 0x7f00_0001, port: appInjectPort, boundTo: nil))
    }

    // Parse a raw inner IPv4/UDP chat packet the LISP app forwarded to us. Returns the
    // sender EID + the ASCII text if it's a chat packet (UDP dport 0xfafa).
    static func parseChatPacket(_ data: Data) -> (src: UInt32, text: String)? {
        let b = data.startIndex
        guard data.count >= 28, (data[b] >> 4) == 4 else { return nil }
        let ihl = Int(data[b] & 0x0F) * 4
        guard data[b + 9] == 17, data.count >= ihl + 8 else { return nil }   // UDP
        let dport = (UInt16(data[b+ihl+2]) << 8) | UInt16(data[b+ihl+3])
        guard dport == chatPort else { return nil }
        let src = (UInt32(data[b+12]) << 24) | (UInt32(data[b+13]) << 16)
                | (UInt32(data[b+14]) << 8) | UInt32(data[b+15])
        let payload = data.subdata(in: (b + ihl + 8)..<data.endIndex)
        guard let text = String(data: payload, encoding: .utf8) else { return nil }
        return (src, text)
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
