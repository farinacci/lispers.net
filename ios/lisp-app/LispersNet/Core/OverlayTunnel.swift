//
// OverlayTunnel.swift
//
// App-side helpers for the overlay tunnel. Find the utun the packet-tunnel provider
// brought up, hand raw inner packets to it (the overlay ITR ingress), publish the
// map-cache the extension's ITR looks up against, and read back the capture log.
//

import Foundation
import Darwin

enum OverlayTunnel {
    static let appGroup = "group.net.lispers.xtr"

    // The utun interface (name, ifIndex, its 240.x IPv4 address) if the tunnel is up.
    // Mirror of Interfaces.candidates() but INVERTED — that one skips utun; we want it.
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
            if (host & 0xF000_0000) == 0xF000_0000 {          // 240.0.0.0/4
                return (name, if_nametoindex(name), host)
            }
        }
        return nil
    }

    var isUp: Bool { OverlayTunnel.findUtun() != nil }

    private static func dotted(_ a: UInt32) -> String {
        "\((a >> 24) & 0xff).\((a >> 16) & 0xff).\((a >> 8) & 0xff).\(a & 0xff)"
    }

    // Overlay-app send (kept for the LISP app's own — currently DISABLED — Tunnel-mode
    // ping; the PING app is the real overlay client). Prepend a LISP data header (with
    // the instance-id) and unicast it to the tunnel EID on 4341, pinned to the utun.
    @discardableResult
    static func injectInner(_ inner: Data, iid: UInt32) -> Bool {
        guard let utun = findUtun() else { return false }
        var hdr = LispDataHeader()
        hdr.setNonce(UInt32.random(in: 0...0xFFFFFF))
        hdr.setInstanceID(iid)
        let lisp = hdr.encode() + inner
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var idx = Int32(utun.ifIndex)
        setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(4341).bigEndian
        addr.sin_addr.s_addr = utun.addr.bigEndian
        let n = lisp.withUnsafeBytes { raw in
            withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(fd, raw.baseAddress, raw.count, 0, sa,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        return n == lisp.count
    }

    // The provider's capture-log lines from the shared App-Group container.
    static var captureURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appendingPathComponent("tunnel-capture.log")
    }
    static func readCapture() -> [String] {
        guard let url = captureURL, let s = try? String(contentsOf: url, encoding: .utf8)
        else { return [] }
        return s.split(separator: "\n").map(String.init)
    }
}
