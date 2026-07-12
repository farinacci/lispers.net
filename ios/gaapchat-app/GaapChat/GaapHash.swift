//
// GaapHash.swift  (gaapchat)
//
// The GAAP group-name → group-address hash, ported bit-for-bit from the Python
// gaap.py `hash_group_name`, so an iOS group name resolves to the SAME multicast
// address as the Python app (interop). A rehash count N≠0 appends "+N" to the name
// before hashing — the fallback addresses GAAP would use on a collision.
//
//   Python:  hv = hmac.new(b"gaap", name.encode(), sha256).hexdigest()
//            group = "224.{}.{}.{}".format(hv[58:60], hv[60:62], hv[62:64])  # bytes 29,30,31
//

import Foundation
import CryptoKit

enum GaapHash {
    static let maxRehash = 4                    // Python gaap.py MAX_REHASH

    // The 224.b2.b3.b4 group address for `groupName` at a given rehash count (0 = primary).
    static func groupAddress(_ groupName: String, rehash: Int = 0) -> String {
        var name = groupName
        if rehash != 0 { name += "+\(rehash)" }
        let key = SymmetricKey(data: Data("gaap".utf8))
        let mac = HMAC<SHA256>.authenticationCode(for: Data(name.utf8), using: key)
        let d = Array(mac)                      // 32 bytes
        return "224.\(d[29]).\(d[30]).\(d[31])"
    }

    // The primary address plus every rehash fallback — what a name could hash to if the
    // primary collides (shown in the Collision tab, mirrors gaaphash.py / validate_hash).
    static func candidates(_ groupName: String) -> [(rehash: Int, name: String, address: String)] {
        (0..<maxRehash).map { n in
            let nm = n == 0 ? groupName : "\(groupName)+\(n)"
            return (n, nm, groupAddress(groupName, rehash: n))
        }
    }
}
