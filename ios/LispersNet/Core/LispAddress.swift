//
// LispAddress.swift
//
// IPv4/IPv6 address with instance-id and mask length. The string form of a
// prefix must match lisp_address.print_prefix() ("[<iid>]<addr>/<len>" with
// the brackets omitted only in the no-iid prints) because the lisp-decent
// hash is computed over that exact string.
//

import Foundation

struct LispAddress: Equatable, Hashable, CustomStringConvertible {
    var afi: UInt16 = 0
    var v4: UInt32 = 0
    var v6: Data = Data()       // 16 bytes when afi == IPv6
    var maskLen: Int = 0
    var instanceID: UInt32 = 0

    var isNull: Bool { afi == 0 }
    var isIPv4: Bool { afi == LISP.afiIPv4 }
    var isIPv6: Bool { afi == LISP.afiIPv6 }

    init() {}

    init(v4 address: UInt32, maskLen: Int = 32, iid: UInt32 = 0) {
        afi = LISP.afiIPv4; v4 = address; self.maskLen = maskLen; instanceID = iid
    }

    init?(string: String, iid: UInt32 = 0) {
        var s = string.trimmingCharacters(in: .whitespaces)
        instanceID = iid
        // Optional [iid] prefix
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            let inner = String(s[s.index(after: s.startIndex)..<close])
            guard let parsed = UInt32(inner) else { return nil }
            instanceID = parsed
            s = String(s[s.index(after: close)...])
        }
        var ml = -1
        if let slash = s.firstIndex(of: "/") {
            guard let parsed = Int(s[s.index(after: slash)...]) else { return nil }
            ml = parsed
            s = String(s[..<slash])
        }
        if s.contains(":") {
            var buf = [UInt8](repeating: 0, count: 16)
            guard inet_pton(AF_INET6, s, &buf) == 1 else { return nil }
            afi = LISP.afiIPv6; v6 = Data(buf); maskLen = ml < 0 ? 128 : ml
        } else {
            var addr = in_addr()
            guard inet_pton(AF_INET, s, &addr) == 1 else { return nil }
            afi = LISP.afiIPv4; v4 = UInt32(bigEndian: addr.s_addr)
            maskLen = ml < 0 ? 32 : ml
        }
        return
    }

    var addressLength: Int { isIPv4 ? 4 : (isIPv6 ? 16 : 0) }

    // print_address_no_iid()
    var addressString: String {
        if isIPv4 {
            return "\(v4 >> 24).\((v4 >> 16) & 0xff).\((v4 >> 8) & 0xff).\(v4 & 0xff)"
        }
        if isIPv6 {
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            var bytes = [UInt8](v6)
            inet_ntop(AF_INET6, &bytes, &buf, socklen_t(INET6_ADDRSTRLEN))
            return String(cString: buf)
        }
        return "none"
    }

    // print_prefix() — the lisp-decent hash input format
    var prefixString: String { "[\(instanceID)]\(addressString)/\(maskLen)" }

    var description: String { prefixString }

    func packAddress() -> Data {
        if isIPv4 {
            var w = ByteWriter(); w.u32(v4); return w.data
        }
        return v6
    }

    static func unpack(afi: UInt16, reader: inout ByteReader) -> LispAddress? {
        var a = LispAddress(); a.afi = afi
        if afi == LISP.afiIPv4 {
            guard let v = reader.u32() else { return nil }
            a.v4 = v; a.maskLen = 32
        } else if afi == LISP.afiIPv6 {
            guard let d = reader.bytes(16) else { return nil }
            a.v6 = d; a.maskLen = 128
        } else if afi == 0 {
            a.maskLen = 0
        } else {
            return nil
        }
        return a
    }

    // Does `self` (a host address) fall inside prefix `p`?
    func isMoreSpecific(than p: LispAddress) -> Bool {
        guard isIPv4, p.isIPv4, instanceID == p.instanceID else { return false }
        guard p.maskLen <= 32 else { return false }
        let mask: UInt32 = p.maskLen == 0 ? 0 : ~UInt32(0) << (32 - p.maskLen)
        return (v4 & mask) == (p.v4 & mask)
    }

    var isOverlayAddress: Bool {    // 240.0.0.0/4 — the only LISP-forwarded space
        isIPv4 && (v4 & LISP.overlayMask) == LISP.overlayPrefix
    }
}
