//
// LispDataHeader.swift
//
// 8-byte LISP data encapsulation header (lisp_data_header, lisp.py:3079).
//
//   first long:  N L E V I P KK | 24-bit nonce
//   second long: 24-bit instance-id | 8-bit LSBs
//

import Foundation

struct LispDataHeader {
    var firstLong: UInt32 = 0
    var secondLong: UInt32 = 0

    static let nBit: UInt32 = 0x8000_0000
    static let lBit: UInt32 = 0x4000_0000
    static let eBit: UInt32 = 0x2000_0000
    static let vBit: UInt32 = 0x1000_0000
    static let iBit: UInt32 = 0x0800_0000
    static let pBit: UInt32 = 0x0400_0000

    mutating func setNonce(_ nonce: UInt32) {
        firstLong |= Self.nBit
        firstLong = (firstLong & 0xFF00_0000) | (nonce & 0x00FF_FFFF)
    }

    mutating func setInstanceID(_ iid: UInt32) {
        if iid == 0 { return }              // I-bit stays clear for IID 0
        firstLong |= Self.iBit
        secondLong = (secondLong & 0xFF) | (iid << 8)
    }

    var instanceID: UInt32 { (secondLong >> 8) & 0xFF_FFFF }
    var hasInstanceID: Bool { firstLong & Self.iBit != 0 }
    var nonce: UInt32 { firstLong & 0x00FF_FFFF }

    // lisp_data_header.print_header (lisp.py:3094): "<e_or_d> LISP-header -> flags:
    // Nlevipkk, nonce: <24-bit>, iid/lsb: <8-hex>". Flag letter is upper-case when
    // its bit is set, lower-case when clear (KK = the 2-bit key-id field).
    func printHeader() -> String {
        let k = (firstLong >> 24) & 0x3
        func fl(_ bit: UInt32, _ c: String) -> String {
            firstLong & bit != 0 ? c.uppercased() : c
        }
        let flags = fl(Self.nBit, "n") + fl(Self.lBit, "l") + fl(Self.eBit, "e")
                  + fl(Self.vBit, "v") + fl(Self.iBit, "i") + fl(Self.pBit, "p")
                  + ((k == 2 || k == 3) ? "K" : "k") + ((k == 1 || k == 3) ? "K" : "k")
        let nonceHex = String(firstLong & 0x00FF_FFFF, radix: 16)
        let iidLsb = String(format: "%08x", secondLong)
        return "LISP-header -> flags: \(flags), nonce: \(nonceHex), iid/lsb: \(iidLsb)"
    }

    func encode() -> Data {
        var w = ByteWriter()
        w.u32(firstLong); w.u32(secondLong)
        return w.data
    }

    static func decode(_ data: Data) -> LispDataHeader? {
        guard data.count >= 8 else { return nil }
        var r = ByteReader(data)
        var h = LispDataHeader()
        h.firstLong = r.u32()!; h.secondLong = r.u32()!
        return h
    }
}
