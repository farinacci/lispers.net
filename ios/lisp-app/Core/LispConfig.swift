//
// LispConfig.swift
//
// Persisted app configuration — the UI-facing equivalent of lisp.config.
// Covers: enable, debug toggles, map-servers, lisp-decent suffix/modulus,
// decent-NAT, NAT-traversal, EID, telemetry.
//

import Foundation
import Combine

struct MapServerConfig: Identifiable, Codable, Equatable {
    var id = UUID()
    var dnsNameOrAddress: String = ""
    var authKey: String = ""
    var authAlg: String = "sha2"        // sha1 | sha2
}

// "lisp decent-prefix" — an EID-prefix and the lookup-length used to mask EIDs
// in that prefix for the decent map-resolver hash.
struct DecentPrefix: Identifiable, Codable, Equatable {
    var id = UUID()
    var eidPrefix: String = ""          // e.g. "240.11.0.0/16"
    var lookupLength: Int?              // nil = not yet entered (no default)
}

final class LispConfig: ObservableObject, Codable {
    // (1) enable/disable
    @Published var lispEnabled = false
    // (2) lisp-decent mapping system
    @Published var mapServers: [MapServerConfig] = []   // legacy non-decent path
    @Published var decentSuffix: String = ""
    @Published var decentModulus: Int = 0
    @Published var decentAuthKey: String = ""           // shared map-server key (sha2)
    @Published var decentPrefixes: [DecentPrefix] = []  // lookup-length per prefix
    // (3) logging scopes — independent switches. Control-plane logging defaults OFF on a
    // fresh install (no saved config); existing users keep their saved setting.
    @Published var controlPlaneLog = false
    @Published var dataPlaneLog = false
    @Published var rlocProbeLog = false
    // EID + NAT
    @Published var eidString: String = ""           // e.g. "240.10.0.100"
    @Published var instanceID: Int = 0
    // xTR/host name, editable on the xTR tab. Defaults to the system hostname
    // (ProcessInfo, ".local" stripped) so the user gets a name out of the box;
    // blank on devices that only report "localhost". Not persisted unless the user
    // edits it, so an un-customized name stays LIVE (re-derived each launch).
    @Published var xtrHostname: String = LispConfig.defaultHostname()

    static func defaultHostname() -> String {
        let h = ProcessInfo.processInfo.hostName
        let name = h.hasSuffix(".local") ? String(h.dropLast(6)) : h
        return name == "localhost" ? "" : name
    }
    @Published var decentNATEnabled = false
    @Published var natTraversalEnabled = true
    @Published var rlocProbingEnabled = true
    @Published var telemetryEnabled = true          // "lisp json" telemetry
    @Published var siteID: UInt64 = 0
    @Published var joinedGroups: [String] = []      // multicast groups we receive
    // Ping load-splitting across the RTR set (Ping tab toggles). For each type:
    //   on  = hash per-packet across the up RTRs (spread the load);
    //   off = a single deterministic up RTR (no spread to multiple RTRs).
    @Published var loadSplitUnicast = true
    @Published var loadSplitMulticast = false
    // Egress multi-homing: probe every usable interface (Wi-Fi + cellular) to each
    // RTR and use the best-rtt one (lisp.py rloc_next_hop). Off = use the single
    // OS-chosen interface (today's behavior).
    @Published var multihomingEnabled = false
    // Multi-homing egress-switch hysteresis (lisp.py lisp_mh_rtt_pct): only move the
    // active next-hop to a better interface when its rtt beats the current one by at
    // least this percent. Higher = stickier (fewer switches); 0 = switch on any
    // improvement. Default 10%.
    @Published var mhSwitchPct: Int = 10

    var decentConfigured: Bool { !decentSuffix.isEmpty && decentModulus > 0 }

    var eid: LispAddress? {
        guard !eidString.isEmpty else { return nil }
        var a = LispAddress(string: eidString, iid: UInt32(instanceID))
        a?.maskLen = 32
        return a
    }

    // MARK: persistence

    enum CodingKeys: String, CodingKey {
        case lispEnabled, mapServers, decentSuffix, decentModulus, decentAuthKey, decentPrefixes
        case controlPlaneLog, dataPlaneLog, rlocProbeLog, eidString, instanceID, xtrHostname
        case decentNATEnabled, natTraversalEnabled, rlocProbingEnabled
        case telemetryEnabled, siteID, joinedGroups
        case loadSplitUnicast, loadSplitMulticast, multihomingEnabled, mhSwitchPct
    }

    init() { load() }

    required init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        lispEnabled = try c.decodeIfPresent(Bool.self, forKey: .lispEnabled) ?? false
        mapServers = try c.decodeIfPresent([MapServerConfig].self, forKey: .mapServers) ?? []
        decentSuffix = try c.decodeIfPresent(String.self, forKey: .decentSuffix) ?? ""
        decentModulus = try c.decodeIfPresent(Int.self, forKey: .decentModulus) ?? 0
        decentAuthKey = try c.decodeIfPresent(String.self, forKey: .decentAuthKey) ?? ""
        decentPrefixes = try c.decodeIfPresent([DecentPrefix].self, forKey: .decentPrefixes) ?? []
        controlPlaneLog = try c.decodeIfPresent(Bool.self, forKey: .controlPlaneLog) ?? false
        dataPlaneLog = try c.decodeIfPresent(Bool.self, forKey: .dataPlaneLog) ?? false
        rlocProbeLog = try c.decodeIfPresent(Bool.self, forKey: .rlocProbeLog) ?? false
        eidString = try c.decodeIfPresent(String.self, forKey: .eidString) ?? ""
        instanceID = try c.decodeIfPresent(Int.self, forKey: .instanceID) ?? 0
        xtrHostname = try c.decodeIfPresent(String.self, forKey: .xtrHostname) ?? ""
        decentNATEnabled = try c.decodeIfPresent(Bool.self, forKey: .decentNATEnabled) ?? false
        natTraversalEnabled = try c.decodeIfPresent(Bool.self, forKey: .natTraversalEnabled) ?? true
        rlocProbingEnabled = try c.decodeIfPresent(Bool.self, forKey: .rlocProbingEnabled) ?? true
        telemetryEnabled = try c.decodeIfPresent(Bool.self, forKey: .telemetryEnabled) ?? true
        siteID = try c.decodeIfPresent(UInt64.self, forKey: .siteID) ?? 0
        joinedGroups = try c.decodeIfPresent([String].self, forKey: .joinedGroups) ?? []
        loadSplitUnicast = try c.decodeIfPresent(Bool.self, forKey: .loadSplitUnicast) ?? true
        loadSplitMulticast = try c.decodeIfPresent(Bool.self, forKey: .loadSplitMulticast) ?? false
        multihomingEnabled = try c.decodeIfPresent(Bool.self, forKey: .multihomingEnabled) ?? false
        mhSwitchPct = try c.decodeIfPresent(Int.self, forKey: .mhSwitchPct) ?? 10
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(lispEnabled, forKey: .lispEnabled)
        try c.encode(mapServers, forKey: .mapServers)
        try c.encode(decentSuffix, forKey: .decentSuffix)
        try c.encode(decentModulus, forKey: .decentModulus)
        try c.encode(decentAuthKey, forKey: .decentAuthKey)
        try c.encode(decentPrefixes, forKey: .decentPrefixes)
        try c.encode(controlPlaneLog, forKey: .controlPlaneLog)
        try c.encode(dataPlaneLog, forKey: .dataPlaneLog)
        try c.encode(rlocProbeLog, forKey: .rlocProbeLog)
        try c.encode(eidString, forKey: .eidString)
        try c.encode(instanceID, forKey: .instanceID)
        try c.encode(xtrHostname, forKey: .xtrHostname)
        try c.encode(decentNATEnabled, forKey: .decentNATEnabled)
        try c.encode(natTraversalEnabled, forKey: .natTraversalEnabled)
        try c.encode(rlocProbingEnabled, forKey: .rlocProbingEnabled)
        try c.encode(telemetryEnabled, forKey: .telemetryEnabled)
        try c.encode(siteID, forKey: .siteID)
        try c.encode(joinedGroups, forKey: .joinedGroups)
        try c.encode(loadSplitUnicast, forKey: .loadSplitUnicast)
        try c.encode(loadSplitMulticast, forKey: .loadSplitMulticast)
        try c.encode(multihomingEnabled, forKey: .multihomingEnabled)
        try c.encode(mhSwitchPct, forKey: .mhSwitchPct)
    }

    // The config lives in the shared App-Group container so the LispTunnel extension
    // (Option B) reads the exact same config the app writes. Falls back to Documents
    // if the container is somehow unavailable.
    private static var fileURL: URL {
        if let g = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: OverlayTunnel.appGroup) {
            return g.appendingPathComponent("lisp-config.json")
        }
        return legacyFileURL
    }

    // Pre-Option-B location (app's Documents). Kept only to migrate an existing config
    // into the App-Group container on first load after upgrading.
    private static var legacyFileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("lisp-config.json")
    }

    func save() {
        if let data = try? JSONEncoder().encode(self) {
            try? data.write(to: Self.fileURL)
        }
    }

    private func load() {
        // First launch after the App-Group move: if the shared file doesn't exist yet
        // but a legacy Documents config does, read that and rewrite it to the shared
        // location so both processes see it going forward.
        var url = Self.fileURL
        let fm = FileManager.default
        if !fm.fileExists(atPath: url.path),
           fm.fileExists(atPath: Self.legacyFileURL.path) {
            url = Self.legacyFileURL
        }
        guard let data = try? Data(contentsOf: url),
              let loaded = try? JSONDecoder().decode(LispConfig.self, from: data)
        else { return }
        defer { if url == Self.legacyFileURL { save() } }   // persist migration to App-Group
        lispEnabled = loaded.lispEnabled
        mapServers = loaded.mapServers
        decentSuffix = loaded.decentSuffix
        decentModulus = loaded.decentModulus
        decentAuthKey = loaded.decentAuthKey
        decentPrefixes = loaded.decentPrefixes
        controlPlaneLog = loaded.controlPlaneLog
        dataPlaneLog = loaded.dataPlaneLog
        rlocProbeLog = loaded.rlocProbeLog
        eidString = loaded.eidString
        instanceID = loaded.instanceID
        // Only a user-typed name is persisted; an empty saved value re-derives the
        // live system hostname so the field shows a default instead of going blank.
        xtrHostname = loaded.xtrHostname.isEmpty ? Self.defaultHostname() : loaded.xtrHostname
        decentNATEnabled = loaded.decentNATEnabled
        natTraversalEnabled = loaded.natTraversalEnabled
        rlocProbingEnabled = loaded.rlocProbingEnabled
        telemetryEnabled = loaded.telemetryEnabled
        siteID = loaded.siteID
        joinedGroups = loaded.joinedGroups
        loadSplitUnicast = loaded.loadSplitUnicast
        loadSplitMulticast = loaded.loadSplitMulticast
        multihomingEnabled = loaded.multihomingEnabled
        mhSwitchPct = loaded.mhSwitchPct

        // Migrate a legacy map-server auth-key into the decent key, once.
        if decentAuthKey.isEmpty, let key = mapServers.first?.authKey, !key.isEmpty {
            decentAuthKey = key
            save()
        }
    }

    // What a live reload changed, split so the engine knows how to apply it.
    struct ConfigReload {
        var dynamicChanged = false      // apply in place (logs, telemetry, load-split, mh %)
        var registerChanged = false     // just re-register (EID, IID, auth-key, MSes, hostname…)
        var bounceChanged = false       // needs sockets rebound (NAT mode, mh, RLOC-probe, enable)
        var eidChanged = false          // the tunnel IP is the EID — provider must re-address
    }

    // Reload the FULL config from the shared App-Group file. The extension reads config
    // once at startTunnel; this lets on-device edits in the app reach the running xTR with
    // no Save button and no VPN bounce. Dynamic fields apply in place; structural fields
    // trigger a soft engine re-register (see LispEngine.applyLiveReload).
    func reloadAll() -> ConfigReload {
        guard let data = try? Data(contentsOf: Self.fileURL),
              let loaded = try? JSONDecoder().decode(LispConfig.self, from: data)
        else { return ConfigReload() }
        var r = ConfigReload()
        func dyn<T: Equatable>(_ kp: ReferenceWritableKeyPath<LispConfig, T>, _ v: T) {
            if self[keyPath: kp] != v { self[keyPath: kp] = v; r.dynamicChanged = true }
        }
        // reg — just re-register (Map-Register carries EID/IID/auth/hostname/MS to the MS).
        func reg<T: Equatable>(_ kp: ReferenceWritableKeyPath<LispConfig, T>, _ v: T) {
            if self[keyPath: kp] != v { self[keyPath: kp] = v; r.registerChanged = true }
        }
        // bounce — needs sockets rebound (NAT/data-port mode, mh, RLOC-probe, LISP enable).
        func bounce<T: Equatable>(_ kp: ReferenceWritableKeyPath<LispConfig, T>, _ v: T) {
            if self[keyPath: kp] != v { self[keyPath: kp] = v; r.bounceChanged = true }
        }
        // Dynamic — read at use-sites (or a direct setter), no re-register needed.
        dyn(\.loadSplitUnicast, loaded.loadSplitUnicast)
        dyn(\.loadSplitMulticast, loaded.loadSplitMulticast)
        dyn(\.controlPlaneLog, loaded.controlPlaneLog)
        dyn(\.dataPlaneLog, loaded.dataPlaneLog)
        dyn(\.rlocProbeLog, loaded.rlocProbeLog)
        dyn(\.telemetryEnabled, loaded.telemetryEnabled)
        dyn(\.mhSwitchPct, loaded.mhSwitchPct)
        // Register-only — the Map-Register conveys these; no socket rebind.
        if eidString != loaded.eidString { r.eidChanged = true }   // + tunnel re-address
        reg(\.eidString, loaded.eidString)
        reg(\.instanceID, loaded.instanceID)
        reg(\.decentAuthKey, loaded.decentAuthKey)
        reg(\.xtrHostname, loaded.xtrHostname)
        reg(\.siteID, loaded.siteID)
        reg(\.decentSuffix, loaded.decentSuffix)
        reg(\.decentModulus, loaded.decentModulus)
        reg(\.decentPrefixes, loaded.decentPrefixes)
        reg(\.mapServers, loaded.mapServers)
        // Bounce — sockets/data-plane must be rebuilt for these to take effect.
        bounce(\.natTraversalEnabled, loaded.natTraversalEnabled)
        bounce(\.decentNATEnabled, loaded.decentNATEnabled)
        bounce(\.multihomingEnabled, loaded.multihomingEnabled)
        bounce(\.rlocProbingEnabled, loaded.rlocProbingEnabled)
        bounce(\.lispEnabled, loaded.lispEnabled)
        return r
    }
}
