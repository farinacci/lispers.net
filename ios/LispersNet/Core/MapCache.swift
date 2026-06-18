//
// MapCache.swift
//
// lisp_mapping / lisp_map_cache equivalents, plus the display formatting of
// lisp-mc.py so the Map-Cache screen reads identically to the Python tool.
//

import Foundation

final class LispRLOC {
    var rloc: LispAddress
    var priority: UInt8 = 1
    var weight: UInt8 = 100
    var encapPort: UInt16 = LISP.dataPort       // ≠4341 when NAT-translated
    var state = "up-state"                      // or "unreach-state"
    var stateChange = Date()
    var rlocName: String?
    var packetCount: UInt64 = 0
    var byteCount: UInt64 = 0
    var lastPacket: Date?
    // RLOC-probe state
    var lastProbeNonce: UInt64 = 0
    var lastProbeSent: Date?
    var lastProbeReply: Date?
    var recentRTTs: [Double] = []               // last 10, seconds
    var recentHops: [String] = []
    var recentLatencies: [String] = []          // "fwd/rev"

    init(rloc: LispAddress) { self.rloc = rloc }

    var isUp: Bool { state == "up-state" }

    func storeRTT(_ rtt: Double) {
        recentRTTs = [rtt] + recentRTTs.prefix(9)
    }
    // Hops each way from the received TTLs, "to/from" (store_rloc_probe_hops,
    // lisp.py:13845): 64 - received-TTL, with "?"/"!" for unknown/too-far.
    func storeHops(toReceivedTTL: Int, fromReceivedTTL: Int) {
        func h(_ ttl: Int) -> String {
            if ttl <= 0 { return "?" }
            if ttl < LISP.rlocProbeTTL / 2 { return "!" }
            return String(LISP.rlocProbeTTL - ttl)
        }
        recentHops = ["\(h(toReceivedTTL))/\(h(fromReceivedTTL))"] + recentHops.prefix(9)
    }
    func storeLatency(_ l: String) {
        recentLatencies = [l] + recentLatencies.prefix(9)
    }
}

final class LispMapCacheEntry {
    var eid: LispAddress
    var group = LispAddress()                   // non-null = multicast (S,G)
    var rlocSet: [LispRLOC]
    var action = LISP.noAction
    var uptime = Date()
    var ttl: TimeInterval?                      // seconds; nil = forever
    var lastRefresh = Date()
    var isStatic = false                        // config/RTR-installed

    var isMulticast: Bool { !group.isNull }

    init(eid: LispAddress, rlocSet: [LispRLOC] = []) {
        self.eid = eid
        self.rlocSet = rlocSet
    }

    // lisp-mc.py ttl rendering: "<minutes>m" (or "<seconds>s"), "never" if unset.
    var ttlString: String {
        guard let ttl = ttl else { return "never" }
        let mins = Int(ttl) / 60
        return mins != 0 ? "\(mins)m" : "\(Int(ttl))s"
    }

    var hasExpired: Bool {
        guard let ttl = ttl, !isStatic else { return false }
        return Date().timeIntervalSince(lastRefresh) >= ttl
    }

    func selectRLOC() -> LispRLOC? {
        let up = rlocSet.filter { $0.isUp }
        return up.min { ($0.priority, 255 - $0.weight) < ($1.priority, 255 - $1.weight) }
    }
}

final class LispMapCache {
    private(set) var entries: [LispMapCacheEntry] = []
    private let lock = NSLock()

    func lookup(_ dest: LispAddress) -> LispMapCacheEntry? {
        lock.lock(); defer { lock.unlock() }
        // Unicast longest-prefix match (multicast (S,G) entries excluded).
        return entries
            .filter { !$0.isMulticast && dest.isMoreSpecific(than: $0.eid) && !$0.hasExpired }
            .max { $0.eid.maskLen < $1.eid.maskLen }
    }

    func add(_ entry: LispMapCacheEntry) {
        lock.lock(); defer { lock.unlock() }
        entries.removeAll { $0.eid == entry.eid && $0.group == entry.group }
        entries.append(entry)
        entries.sort { ($0.eid.maskLen, $0.eid.v4) < ($1.eid.maskLen, $1.eid.v4) }
    }

    func remove(eidPrefix: LispAddress) {
        lock.lock(); defer { lock.unlock() }
        entries.removeAll { $0.eid == eidPrefix }
    }

    func clearDynamic() {
        lock.lock(); defer { lock.unlock() }
        entries.removeAll { !$0.isStatic }
    }

    func clearAll() {
        lock.lock(); defer { lock.unlock() }
        entries.removeAll()
    }

    func snapshot() -> [LispMapCacheEntry] {
        lock.lock(); defer { lock.unlock() }
        return entries
    }
}

// MARK: - lisp-mc.py style formatting

// Compact elapsed time for the status header ("5m", "1h03m").
func formatUptime(_ since: Date) -> String {
    let s = Int(Date().timeIntervalSince(since))
    if s < 60 { return "\(s)s" }
    if s < 3600 { return "\(s / 60)m" }
    if s < 86400 { return String(format: "%dh%02dm", s / 3600, (s % 3600) / 60) }
    return "\(s / 86400)d\((s % 86400) / 3600)h"
}

// Map-cache elapsed time, lisp-mc.py style: "H:MM:SS" or "N days, H:MM:SS".
func formatHMS(_ since: Date) -> String {
    let t = Int(Date().timeIntervalSince(since))
    let days = t / 86400
    let hms = String(format: "%d:%02d:%02d", (t % 86400) / 3600, (t % 3600) / 60, t % 60)
    return days > 0 ? "\(days) days, \(hms)" : hms
}

// Trailing-zero-trimmed seconds, matching Python's float repr (0.26 not 0.260).
func fmtSecs(_ v: Double) -> String {
    if v < 0 { return "?" }
    var s = String(format: "%.3f", v)
    while s.hasSuffix("0") { s.removeLast() }
    if s.hasSuffix(".") { s.removeLast() }
    return s
}
