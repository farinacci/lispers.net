//
// ByteBuffer.swift
//
// Binary pack/unpack helpers. LISP control headers are network byte order
// EXCEPT 64-bit nonces and xTR-IDs, which lisp.py packs with native-order
// struct.pack("Q") — on every machine we care about that is little-endian.
// Keep that quirk or registrations/probes will not interop.
//

import Foundation

struct ByteWriter {
    private(set) var data = Data()

    mutating func u8(_ v: UInt8) { data.append(v) }
    mutating func u16(_ v: UInt16) {        // network order
        data.append(UInt8(v >> 8)); data.append(UInt8(v & 0xff))
    }
    mutating func u32(_ v: UInt32) {        // network order
        data.append(UInt8(v >> 24)); data.append(UInt8((v >> 16) & 0xff))
        data.append(UInt8((v >> 8) & 0xff)); data.append(UInt8(v & 0xff))
    }
    mutating func u64Native(_ v: UInt64) {  // struct.pack("Q") on LE hosts
        var le = v.littleEndian
        withUnsafeBytes(of: &le) { data.append(contentsOf: $0) }
    }
    mutating func bytes(_ d: Data) { data.append(d) }
    mutating func zeros(_ n: Int) { data.append(Data(repeating: 0, count: n)) }
}

struct ByteReader {
    let data: Data
    private(set) var offset: Int

    init(_ d: Data) { data = d; offset = 0 }

    var remaining: Int { data.count - offset }

    mutating func u8() -> UInt8? {
        guard remaining >= 1 else { return nil }
        defer { offset += 1 }
        return data[data.startIndex + offset]
    }
    mutating func u16() -> UInt16? {
        guard remaining >= 2 else { return nil }
        let b = data.startIndex + offset; offset += 2
        return UInt16(data[b]) << 8 | UInt16(data[b + 1])
    }
    mutating func u32() -> UInt32? {
        guard remaining >= 4 else { return nil }
        let b = data.startIndex + offset; offset += 4
        return UInt32(data[b]) << 24 | UInt32(data[b + 1]) << 16 |
               UInt32(data[b + 2]) << 8 | UInt32(data[b + 3])
    }
    mutating func u64Native() -> UInt64? {
        guard remaining >= 8 else { return nil }
        var v: UInt64 = 0
        for i in (0..<8).reversed() {       // little-endian assembly
            v = (v << 8) | UInt64(data[data.startIndex + offset + i])
        }
        offset += 8
        return v
    }
    mutating func bytes(_ n: Int) -> Data? {
        guard remaining >= n else { return nil }
        let b = data.startIndex + offset; offset += n
        return data.subdata(in: b..<(b + n))
    }
    // Read a null-terminated distinguished name (AFI 17), consuming the null.
    mutating func readName() -> String {
        var s = ""
        while let c = u8(), c != 0 { s.append(Character(UnicodeScalar(c))) }
        return s
    }
    mutating func skip(_ n: Int) { offset = min(offset + n, data.count) }
    // Read the next u16 WITHOUT advancing (used to tell an RLE node's optional
    // AFI-17 rloc-name from the start of the following node).
    func peekU16() -> UInt16? {
        guard remaining >= 2 else { return nil }
        let b = data.startIndex + offset
        return UInt16(data[b]) << 8 | UInt16(data[b + 1])
    }
}

// One's-complement checksum used for inner IPv4 headers and ICMP
// (lisp_ip_checksum / lisp_icmp_checksum equivalents).
func internetChecksum(_ data: Data) -> UInt16 {
    var sum: UInt32 = 0
    var i = data.startIndex
    while i + 1 < data.endIndex {
        sum &+= UInt32(data[i]) << 8 | UInt32(data[i + 1])
        i += 2
    }
    if i < data.endIndex { sum &+= UInt32(data[i]) << 8 }
    while sum > 0xffff { sum = (sum & 0xffff) &+ (sum >> 16) }
    return ~UInt16(sum & 0xffff)
}
