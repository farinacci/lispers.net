//
// ChaCha8.swift  (gaapchat)
//
// Bernstein's original ChaCha stream cipher, 8 rounds, 8-byte IV — a bit-for-bit port of
// the Python `chacha.py` (NOT RFC-8439 ChaCha20/Poly1305, so CryptoKit's ChaChaPoly won't
// interop). Encryption and decryption are identical (XOR keystream).
//
// The GAAP wrapping (gaap.py): 32-byte key = groupName.zfill(32) (left-pad with ASCII '0'),
// 8-byte IV = "A"*8, first 4 bytes = the 0xAAAAAAAA marker left in the clear, rest ChaCha8.
//
// NOTE: gaapchat chat is PLAINTEXT (decided 2026-07-11 for immediate Python interop), so this
// is READY but not wired into the chat path. It's here to honor the "use chacha.py" design
// and for a future encrypted mode / GAAP-protocol support.
//

import Foundation

struct ChaCha8 {
    private static let TAU:   [UInt32] = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574]
    private static let SIGMA: [UInt32] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    private static let rounds = 8

    private var state = [UInt32](repeating: 0, count: 16)
    private var keyState = [UInt32](repeating: 0, count: 16)

    // key: 16 or 32 bytes. iv: 8 bytes.
    init(key: [UInt8], iv: [UInt8]) {
        keySetup(key)
        ivSetup(iv)
    }

    private static func le32(_ b: ArraySlice<UInt8>) -> UInt32 {
        let a = Array(b)
        return UInt32(a[0]) | (UInt32(a[1]) << 8) | (UInt32(a[2]) << 16) | (UInt32(a[3]) << 24)
    }

    private mutating func keySetup(_ key: [UInt8]) {
        var ks = [UInt32](repeating: 0, count: 16)
        if key.count == 16 {
            let k = (0..<4).map { Self.le32(key[($0*4)..<($0*4+4)]) }
            ks[0] = Self.TAU[0]; ks[1] = Self.TAU[1]; ks[2] = Self.TAU[2]; ks[3] = Self.TAU[3]
            ks[4] = k[0]; ks[5] = k[1]; ks[6] = k[2]; ks[7] = k[3]
            ks[8] = k[0]; ks[9] = k[1]; ks[10] = k[2]; ks[11] = k[3]
        } else {   // 32 bytes
            let k = (0..<8).map { Self.le32(key[($0*4)..<($0*4+4)]) }
            ks[0] = Self.SIGMA[0]; ks[1] = Self.SIGMA[1]; ks[2] = Self.SIGMA[2]; ks[3] = Self.SIGMA[3]
            for i in 0..<8 { ks[4+i] = k[i] }
        }
        keyState = ks
    }

    private mutating func ivSetup(_ iv: [UInt8]) {
        let v0 = Self.le32(iv[0..<4]); let v1 = Self.le32(iv[4..<8])
        var s = keyState
        s[12] = 0; s[13] = 0; s[14] = v0; s[15] = v1
        state = s
    }

    private static func rotl(_ v: UInt32, _ n: UInt32) -> UInt32 { (v << n) | (v >> (32 - n)) }

    private static func quarterround(_ x: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        x[a] = x[a] &+ x[b]; x[d] = rotl(x[d] ^ x[a], 16)
        x[c] = x[c] &+ x[d]; x[b] = rotl(x[b] ^ x[c], 12)
        x[a] = x[a] &+ x[b]; x[d] = rotl(x[d] ^ x[a], 8)
        x[c] = x[c] &+ x[d]; x[b] = rotl(x[b] ^ x[c], 7)
    }

    private func scramble() -> [UInt8] {
        var x = state
        var r = 0
        while r < Self.rounds {
            Self.quarterround(&x, 0, 4, 8, 12); Self.quarterround(&x, 1, 5, 9, 13)
            Self.quarterround(&x, 2, 6, 10, 14); Self.quarterround(&x, 3, 7, 11, 15)
            Self.quarterround(&x, 0, 5, 10, 15); Self.quarterround(&x, 1, 6, 11, 12)
            Self.quarterround(&x, 2, 7, 8, 13); Self.quarterround(&x, 3, 4, 9, 14)
            r += 2
        }
        var out = [UInt8](); out.reserveCapacity(64)
        for i in 0..<16 {
            let w = x[i] &+ state[i]
            out.append(UInt8(w & 0xff)); out.append(UInt8((w >> 8) & 0xff))
            out.append(UInt8((w >> 16) & 0xff)); out.append(UInt8((w >> 24) & 0xff))
        }
        return out
    }

    // XOR the keystream over `data` in 64-byte blocks (encrypt == decrypt).
    mutating func process(_ data: [UInt8]) -> [UInt8] {
        var out = [UInt8](); out.reserveCapacity(data.count)
        var offset = 0
        while offset < data.count {
            let stream = scramble()
            let n = min(64, data.count - offset)
            for i in 0..<n { out.append(data[offset + i] ^ stream[i]) }
            offset += 64
            state[12] = state[12] &+ 1
            if state[12] == 0 { state[13] = state[13] &+ 1 }
        }
        return out
    }

    // The GAAP wrapping: 32-byte key = groupName.zfill(32), iv "A"*8, 4-byte 0xAAAAAAAA
    // marker in the clear + ChaCha8(rest). Kept for parity with gaap.py's encrypt().
    static func gaapKey(_ groupName: String) -> [UInt8] {
        let padded = String(repeating: "0", count: max(0, 32 - groupName.count)) + groupName
        return Array(padded.utf8.prefix(32))
    }
}
