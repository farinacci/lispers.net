//
// Telemetry.swift
//
// RLOC-probe telemetry per the lispers.net "lisp json" mechanism
// (lisp_encode_telemetry / lisp_decode_telemetry, lisp.py:21549-21610).
// The JSON body rides in an LCAF JSON-type ITR-RLOC (Map-Request) and
// RLOC-record (Map-Reply). Timestamps are UTC seconds as decimal strings.
//

import Foundation

enum Telemetry {
    static let configTemplate =
        "{ \"type\" : \"telemetry\", \"sub-type\" : \"timestamps\", " +
        "\"itr-out\" : \"?\", \"etr-in\" : \"?\", \"etr-out\" : \"?\", " +
        "\"itr-in\" : \"?\" }"

    static func parse(_ json: String) -> [String: String]? {
        guard let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let dict = obj as? [String: String] else { return nil }
        return dict
    }

    // lisp_is_json_telemetry()
    static func isTelemetry(_ json: String) -> Bool {
        guard let d = parse(json) else { return false }
        return d["type"] == "telemetry" && d["sub-type"] == "timestamps"
    }

    // lisp_encode_telemetry(): fill in whichever timestamps are supplied.
    static func encode(_ json: String, itrIn: String? = nil, itrOut: String? = nil,
                       etrIn: String? = nil, etrOut: String? = nil) -> String {
        guard var d = parse(json) else { return json }
        if let v = itrIn { d["itr-in"] = v }
        if let v = itrOut { d["itr-out"] = v }
        if let v = etrIn { d["etr-in"] = v }
        if let v = etrOut { d["etr-out"] = v }
        let keys = ["type", "sub-type", "itr-out", "etr-in", "etr-out", "itr-in"]
        let body = keys.compactMap { k in
            d[k].map { "\"\(k)\" : \"\($0)\"" }
        }.joined(separator: ", ")
        return "{ \(body) }"
    }

    static func timestamp() -> String { String(Date().timeIntervalSince1970) }

    // One-way delays as lisp.py:13868 computes them: fwd = etr-in - itr-out,
    // rev = itr-in - etr-out, both rounded to 3 decimals.
    static func latencies(_ json: String) -> (forward: Double, reverse: Double)? {
        guard let d = parse(json),
              let io = Double(d["itr-out"] ?? "?"), let ei = Double(d["etr-in"] ?? "?"),
              let eo = Double(d["etr-out"] ?? "?"), let ii = Double(d["itr-in"] ?? "?")
        else { return nil }
        return ((ei - io).rounded(toPlaces: 3), (ii - eo).rounded(toPlaces: 3))
    }
}

extension Double {
    func rounded(toPlaces places: Int) -> Double {
        let p = pow(10.0, Double(places))
        return (self * p).rounded() / p
    }
}

// lisp_get_decent_index / lisp_get_decent_dns_name (lisp.py:20551):
// HMAC-SHA256 keyed "lisp-decent" over print_prefix() of the EID, first 12
// hex chars mod modulus, prepended to the dns suffix.
import CryptoKit

enum LispDecent {
    // lisp_get_decent_eid_string(): if the EID matches a configured decent
    // lookup-prefix (longest match), hash the EID masked to that prefix's
    // lookup-length instead of the full /32.
    static func eidString(for eid: LispAddress, prefixes: [DecentPrefix]) -> String {
        var bestLookup: Int?
        var bestPrefixLen = -1
        for p in prefixes {
            guard let pa = LispAddress(string: p.eidPrefix, iid: eid.instanceID) else { continue }
            if eid.isMoreSpecific(than: pa) && pa.maskLen > bestPrefixLen {
                bestPrefixLen = pa.maskLen
                bestLookup = p.lookupLength
            }
        }
        guard let lookup = bestLookup else { return eid.prefixString }
        var masked = eid
        masked.maskLen = lookup
        masked.zeroHostBits()
        return masked.prefixString
    }

    static func index(eid: LispAddress, modulus: Int, prefixes: [DecentPrefix] = []) -> Int {
        let key = SymmetricKey(data: Data("lisp-decent".utf8))
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(eidString(for: eid, prefixes: prefixes).utf8), using: key)
        let hex = Data(mac).map { String(format: "%02x", $0) }.joined()
        let slice = String(hex.prefix(12))
        let value = UInt64(slice, radix: 16) ?? 0
        return Int(value % UInt64(max(modulus, 1)))
    }

    static func dnsName(eid: LispAddress, modulus: Int, suffix: String,
                        prefixes: [DecentPrefix] = []) -> String {
        "\(index(eid: eid, modulus: modulus, prefixes: prefixes)).\(suffix)"
    }
}
