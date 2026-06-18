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

struct DiscoveredRLOC {
    let address: LispAddress
    let interfaceName: String
}

enum Interfaces {
    static func discoverRLOC() -> DiscoveredRLOC? {
        var candidates: [(name: String, addr: LispAddress)] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }

        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let p = ptr {
            defer { ptr = p.pointee.ifa_next }
            guard let sa = p.pointee.ifa_addr, sa.pointee.sa_family == AF_INET,
                  (p.pointee.ifa_flags & UInt32(IFF_UP)) != 0,
                  (p.pointee.ifa_flags & UInt32(IFF_LOOPBACK)) == 0
            else { continue }
            let name = String(cString: p.pointee.ifa_name)
            var addr = sockaddr_in()
            memcpy(&addr, sa, MemoryLayout<sockaddr_in>.size)
            let host = UInt32(bigEndian: addr.sin_addr.s_addr)
            // Skip link-local 169.254/16
            if (host & 0xFFFF_0000) == 0xA9FE_0000 { continue }
            candidates.append((name, LispAddress(v4: host)))
        }

        // Preference order mirrors "first suitable interface": Wi-Fi,
        // then cellular, then anything else (e.g. USB ethernet en2/en3).
        for prefix in ["en0", "pdp_ip", "en", "utun"] {
            if let c = candidates.first(where: { $0.name.hasPrefix(prefix) }) {
                return DiscoveredRLOC(address: c.addr, interfaceName: c.name)
            }
        }
        return candidates.first.map { DiscoveredRLOC(address: $0.addr, interfaceName: $0.name) }
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
