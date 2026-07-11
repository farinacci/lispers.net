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
    // Multi-homing next-hop: the egress interface this RLOC entry is probed/used
    // on. nil = single-homed (OS default interface). Two entries with the same
    // rloc address but different interfaceName are the Wi-Fi/cellular next-hops.
    var interfaceName: String?
    var ifIndex: UInt32 = 0
    var activeNextHop = false                   // the "*" — best-rtt among siblings
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
    // When the CURRENT run of unanswered probes began. Set on the first probe
    // after a reply (or from creation) and NOT reset by subsequent re-sends, so
    // the unreach timer measures "outstanding for > wait" instead of "since the
    // last send" — the latter never exceeds the probe interval and so could
    // never fire. Cleared on a probe-reply.
    var probeOutstandingSince: Date?
    var recentRTTs: [Double] = []               // last 3, seconds
    var recentHops: [String] = []
    var recentLatencies: [String] = []          // "fwd/rev"

    init(rloc: LispAddress) { self.rloc = rloc }

    var isUp: Bool { state == "up-state" }

    func storeRTT(_ rtt: Double) {
        recentRTTs = [rtt] + recentRTTs.prefix(2)
    }
    // Hops each way from the received TTLs, "to/from" (store_rloc_probe_hops,
    // lisp.py:13845): 64 - received-TTL, with "?"/"!" for unknown/too-far.
    func storeHops(toReceivedTTL: Int, fromReceivedTTL: Int) {
        func h(_ ttl: Int) -> String {
            if ttl <= 0 { return "?" }
            if ttl < LISP.rlocProbeTTL / 2 { return "!" }
            return String(LISP.rlocProbeTTL - ttl)
        }
        recentHops = ["\(h(toReceivedTTL))/\(h(fromReceivedTTL))"] + recentHops.prefix(2)
    }
    func storeLatency(_ l: String) {
        recentLatencies = [l] + recentLatencies.prefix(2)
    }
}

final class LispMapCacheEntry {
    var eid: LispAddress
    var group = LispAddress()                   // non-null = multicast (S,G)
    var rlocSet: [LispRLOC]
    var action = LISP.noAction
    var loadSplitIndex = 0                       // round-robin cursor (load-split)
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

    // hashL4 false → hash inner src+dst ONLY (consistent per flow). Multicast uses
    // this so a given (S,G) always picks the SAME RTR (the RTR then replicates);
    // unicast defaults to LISP_LOAD_SPLIT_PINGS (adds 4 L4 bytes so successive
    // pings spread across the best tier).
    // loadSplit == true: strict ROUND-ROBIN — this packet to one RTR, the NEXT to
    // another, cycling through the up RTRs (one copy per packet; the xTR does not
    // replicate). loadSplit == false: a single STABLE RTR (hash of src+dst, so a
    // flow always uses the same one — no spread across RTRs).
    func selectRLOC(for inner: Data? = nil, hashL4 loadSplit: Bool = LISP.loadSplitPings) -> LispRLOC? {
        var up = rlocSet.filter { $0.isUp }
        // Don't blackhole data just because RLOC-PROBES stopped being answered. Many
        // NATs drop the control-plane probe (and its reply) while still forwarding
        // data, so an RLOC can read unreach-state yet still carry traffic. When NO
        // RLOC is probe-reachable, fall back to forwarding through the whole set
        // (best next-hop below) rather than dropping — the map-cache still shows
        // unreach/? so the probe status stays honest. Matches starting RLOCs up-state
        // so they're usable under probe-filtering NATs.
        if up.isEmpty { up = rlocSet }
        // Multi-homing: forward out each RTR's ACTIVE (best-rtt) next-hop only;
        // fall back to all up if none is marked active yet. Single-homed RLOCs
        // (nil interface) always pass.
        let active = up.filter { $0.interfaceName == nil || $0.activeNextHop }
        if !active.isEmpty { up = active }
        // best_rloc_set (lisp.py): the up RLOCs at the best (lowest) priority.
        guard let bestPri = up.map({ $0.priority }).min() else { return nil }
        let best = up.filter { $0.priority == bestPri }
        if best.count == 1 { return best[0] }

        if loadSplit {
            let r = best[loadSplitIndex % best.count]
            loadSplitIndex &+= 1
            return r
        }

        // No load-split: deterministic single RTR — hash the src+dst (bytes 12..20)
        // only, so every packet of a flow lands on the same RTR.
        if let inner = inner, inner.count >= 20, inner.first.map({ $0 >> 4 }) == 4 {
            let b = inner.startIndex
            var h: UInt8 = 0
            for i in 12..<20 { h ^= inner[b + i] }
            return best[Int(h) % best.count]
        }
        return best.max { $0.weight < $1.weight }
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

    // (S,G) lookup: longest match on the GROUP (destination) first, then on the
    // SOURCE within the matched group — lisp_map_cache_lookup, lisp.py:11674.
    func lookupMulticast(source: LispAddress, group: LispAddress) -> LispMapCacheEntry? {
        lock.lock(); defer { lock.unlock() }
        return entries
            .filter { $0.isMulticast && !$0.hasExpired
                && group.isMoreSpecific(than: $0.group)
                && source.isMoreSpecific(than: $0.eid) }
            .max { a, b in
                a.group.maskLen != b.group.maskLen
                    ? a.group.maskLen < b.group.maskLen
                    : a.eid.maskLen < b.eid.maskLen
            }
    }

    func add(_ entry: LispMapCacheEntry) {
        lock.lock(); defer { lock.unlock() }
        entries.removeAll { $0.eid == entry.eid && $0.group == entry.group }
        entries.append(entry)
        entries.sort { ($0.eid.maskLen, $0.eid.v4) < ($1.eid.maskLen, $1.eid.v4) }
    }

    // Remove the entry for this (eid, group) pair. Default null group removes the
    // unicast entry without disturbing (eid, *) multicast variants.
    func remove(eidPrefix: LispAddress, group: LispAddress = LispAddress()) {
        lock.lock(); defer { lock.unlock() }
        entries.removeAll { $0.eid == eidPrefix && $0.group == group }
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

// Minute-granularity uptime for the xTR screen: "< 1m", "5m", "1h3m", "1d3h".
// asOf lets a per-minute TimelineView drive the value.
func formatUptimeMinutes(_ since: Date, asOf: Date = Date()) -> String {
    let s = Int(asOf.timeIntervalSince(since))
    if s < 60 { return "< 1m" }
    if s < 3600 { return "\(s / 60)m" }
    if s < 86400 { return "\(s / 3600)h\((s % 3600) / 60)m" }
    return "\(s / 86400)d\((s % 86400) / 3600)h"
}

// Map-cache elapsed time, lisp-mc.py style: "H:MM:SS" or "N days, H:MM:SS".
// asOf defaults to now (live, for map-cache rows); callers can pass a snapshot
// time to freeze the value (the xTR-tab uptimes update only on (re)appear).
func formatHMS(_ since: Date, asOf: Date = Date()) -> String {
    let t = Int(asOf.timeIntervalSince(since))
    let days = t / 86400
    let hms = String(format: "%d:%02d:%02d", (t % 86400) / 3600, (t % 3600) / 60, t % 60)
    return days > 0 ? "\(days) days, \(hms)" : hms
}

// Fixed 3-decimal seconds (x.yyy) — 0.710, never 0.71. Negative = unknown ("?").
func fmtSecs(_ v: Double) -> String {
    v < 0 ? "?" : String(format: "%.3f", v)
}

// Fixed 3-decimal seconds keeping the sign — for latencies, which are legitimately
// negative under clock skew (fwd/rev = etr-in − itr-out etc.).
func fmt3(_ v: Double) -> String { String(format: "%.3f", v) }
