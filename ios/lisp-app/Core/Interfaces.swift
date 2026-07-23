//
// Interfaces.swift
//
// RLOC discovery — the iOS replacement for lisp_get_local_addresses()
// (lisp.py:1743). Picks the first non-loopback, non-link-local IPv4 address,
// preferring Wi-Fi (en0) then cellular (pdp_ip0), and watches for path
// changes so the engine can re-register on Wi-Fi/cellular handoff.
//

import Foundation
import Network

struct DiscoveredRLOC: Codable {
    let address: LispAddress
    let interfaceName: String
    var ifIndex: UInt32 = 0             // if_nametoindex — for IP_BOUND_IF egress
}

enum Interfaces {
    // Does the OS have a usable route out this interface? A UDP connect() to a public host
    // SCOPED to the interface (IP_BOUND_IF) performs only a ROUTE LOOKUP — it sends nothing —
    // and fails ENETUNREACH/EHOSTUNREACH when the interface has no route out. This is the
    // signal that distinguishes a Wi-Fi that's been DISCONNECTED via Control Center (en0
    // lingers UP + IFF_RUNNING with its stale IP, but its default route is gone) from a real
    // working interface — which neither interface-presence nor IFF_RUNNING can tell apart.
    // A torn-down cellular context vanishes from getifaddrs entirely, so it never needs this.
    static func hasRoute(ifIndex: UInt32) -> Bool {
        guard ifIndex != 0 else { return true }
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return true }              // can't test → don't withdraw
        defer { close(fd) }
        var idx = Int32(ifIndex)
        setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(53).bigEndian
        addr.sin_addr.s_addr = UInt32(0x0101_0101).bigEndian   // 1.1.1.1 (no packet is sent)
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return r == 0
    }

    // All UP, non-loopback, non-link-local IPv4 interfaces, with their index.
    private static func candidates() -> [DiscoveredRLOC] {
        // strict = UP *and* RUNNING (really carrying traffic); loose = UP only. We return
        // strict, but fall back to loose if strict comes up empty, so a platform that doesn't
        // set IFF_RUNNING the way we expect can never strand the xTR with no RLOC at all.
        var strict: [DiscoveredRLOC] = []
        var loose: [DiscoveredRLOC] = []
        var out: [DiscoveredRLOC] { strict.isEmpty ? loose : strict }
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return out }
        defer { freeifaddrs(ifaddr) }
        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let p = ptr {
            defer { ptr = p.pointee.ifa_next }
            // IFF_UP alone is NOT liveness: it's the ADMINISTRATIVE flag, and iOS leaves en0
            // IFF_UP with its IPv4 address still attached after Wi-Fi is switched off — so a
            // dead Wi-Fi kept looking "live" and its RLOC stayed registered (cellular behaved
            // correctly only because turning it off tears the pdp_ip0 context down entirely).
            // IFF_RUNNING is the carrier/resources-allocated flag — ifconfig's "status: active".
            guard let sa = p.pointee.ifa_addr, sa.pointee.sa_family == AF_INET,
                  (p.pointee.ifa_flags & UInt32(IFF_UP)) != 0,
                  (p.pointee.ifa_flags & UInt32(IFF_LOOPBACK)) == 0
            else { continue }
            let isRunning = (p.pointee.ifa_flags & UInt32(IFF_RUNNING)) != 0
            let name = String(cString: p.pointee.ifa_name)
            // Skip VPN / tunnel pseudo-interfaces: Perimeter 81 / IKEv2 = ipsec*,
            // WireGuard / Tailscale / iCloud Private Relay = utun*. Their addresses
            // are NOT valid overlay RLOCs — encapsulating out a tunnel would carry
            // LISP inside the VPN and advertise an unreachable RLOC. Only real
            // physical egress (en*, pdp_ip*) qualifies. (This also stops engine.rloc
            // from flapping to ipsec0 when the VPN connects, which made the xTR tab
            // and map-cache disagree on the interface.)
            if name.hasPrefix("ipsec") || name.hasPrefix("utun") { continue }
            var addr = sockaddr_in()
            memcpy(&addr, sa, MemoryLayout<sockaddr_in>.size)
            let host = UInt32(bigEndian: addr.sin_addr.s_addr)
            if (host & 0xFFFF_0000) == 0xA9FE_0000 { continue }   // link-local
            let d = DiscoveredRLOC(address: LispAddress(v4: host),
                                   interfaceName: name,
                                   ifIndex: if_nametoindex(name))
            loose.append(d)
            // Strict = UP, RUNNING, *and* actually has a route out. The route check is what
            // catches a Control-Center-disconnected Wi-Fi that still lingers with an IP.
            if isRunning && hasRoute(ifIndex: d.ifIndex) { strict.append(d) }
        }
        return out
    }

    static func discoverRLOC() -> DiscoveredRLOC? {
        let cands = candidates()
        // Preference order mirrors "first suitable interface": Wi-Fi,
        // then cellular, then anything else (e.g. USB ethernet en2/en3).
        for prefix in ["en0", "pdp_ip", "en"] {
            if let c = cands.first(where: { $0.interfaceName.hasPrefix(prefix) }) { return c }
        }
        return cands.first
    }

    // The RLOC-bearing interfaces for multi-homing: exactly ONE Wi-Fi (en0) and
    // ONE cellular egress. iOS exposes SEVERAL cellular PDP contexts — pdp_ip0 is
    // the internet/default-APN interface, while pdp_ip1/pdp_ip2 are IMS/VoLTE/MMS/
    // tethering contexts that can't route general traffic. Picking every "pdp_ip*"
    // (the old hasPrefix bug) added those dead contexts as next-hops that never get
    // a probe reply → no active next-hop → no "*", no forwarding on that phone.
    // Take pdp_ip0 (or the lowest-numbered pdp_ip* if pdp_ip0 is absent) only.
    static func discoverAllRLOCs() -> [DiscoveredRLOC] {
        let cands = candidates()
        var picked: [DiscoveredRLOC] = []
        if let wifi = cands.first(where: { $0.interfaceName == "en0" }) {
            picked.append(wifi)
        }
        let cell = cands.first(where: { $0.interfaceName == "pdp_ip0" })
            ?? cands.filter { $0.interfaceName.hasPrefix("pdp_ip") }
                    .sorted { $0.interfaceName < $1.interfaceName }.first
        if let cell = cell { picked.append(cell) }
        if picked.isEmpty, let one = discoverRLOC() { picked = [one] }
        return picked
    }
}

final class PathWatcher {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "lisp.path")

    func start(onChange: @escaping () -> Void) {
        monitor.pathUpdateHandler = { _ in onChange() }
        monitor.start(queue: queue)
    }

    func stop() { monitor.cancel() }
}
