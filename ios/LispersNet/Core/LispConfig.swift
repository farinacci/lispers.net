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
    // (3) logging scopes — independent switches
    @Published var controlPlaneLog = true
    @Published var dataPlaneLog = false
    @Published var rlocProbeLog = false
    // EID + NAT
    @Published var eidString: String = ""           // e.g. "240.10.0.100"
    @Published var instanceID: Int = 0
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
        case controlPlaneLog, dataPlaneLog, rlocProbeLog, eidString, instanceID
        case decentNATEnabled, natTraversalEnabled, rlocProbingEnabled
        case telemetryEnabled, siteID, joinedGroups
        case loadSplitUnicast, loadSplitMulticast, multihomingEnabled
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
        controlPlaneLog = try c.decodeIfPresent(Bool.self, forKey: .controlPlaneLog) ?? true
        dataPlaneLog = try c.decodeIfPresent(Bool.self, forKey: .dataPlaneLog) ?? false
        rlocProbeLog = try c.decodeIfPresent(Bool.self, forKey: .rlocProbeLog) ?? false
        eidString = try c.decodeIfPresent(String.self, forKey: .eidString) ?? ""
        instanceID = try c.decodeIfPresent(Int.self, forKey: .instanceID) ?? 0
        decentNATEnabled = try c.decodeIfPresent(Bool.self, forKey: .decentNATEnabled) ?? false
        natTraversalEnabled = try c.decodeIfPresent(Bool.self, forKey: .natTraversalEnabled) ?? true
        rlocProbingEnabled = try c.decodeIfPresent(Bool.self, forKey: .rlocProbingEnabled) ?? true
        telemetryEnabled = try c.decodeIfPresent(Bool.self, forKey: .telemetryEnabled) ?? true
        siteID = try c.decodeIfPresent(UInt64.self, forKey: .siteID) ?? 0
        joinedGroups = try c.decodeIfPresent([String].self, forKey: .joinedGroups) ?? []
        loadSplitUnicast = try c.decodeIfPresent(Bool.self, forKey: .loadSplitUnicast) ?? true
        loadSplitMulticast = try c.decodeIfPresent(Bool.self, forKey: .loadSplitMulticast) ?? false
        multihomingEnabled = try c.decodeIfPresent(Bool.self, forKey: .multihomingEnabled) ?? false
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
        try c.encode(decentNATEnabled, forKey: .decentNATEnabled)
        try c.encode(natTraversalEnabled, forKey: .natTraversalEnabled)
        try c.encode(rlocProbingEnabled, forKey: .rlocProbingEnabled)
        try c.encode(telemetryEnabled, forKey: .telemetryEnabled)
        try c.encode(siteID, forKey: .siteID)
        try c.encode(joinedGroups, forKey: .joinedGroups)
        try c.encode(loadSplitUnicast, forKey: .loadSplitUnicast)
        try c.encode(loadSplitMulticast, forKey: .loadSplitMulticast)
        try c.encode(multihomingEnabled, forKey: .multihomingEnabled)
    }

    private static var fileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("lisp-config.json")
    }

    func save() {
        if let data = try? JSONEncoder().encode(self) {
            try? data.write(to: Self.fileURL)
        }
    }

    private func load() {
        guard let data = try? Data(contentsOf: Self.fileURL),
              let loaded = try? JSONDecoder().decode(LispConfig.self, from: data)
        else { return }
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
        decentNATEnabled = loaded.decentNATEnabled
        natTraversalEnabled = loaded.natTraversalEnabled
        rlocProbingEnabled = loaded.rlocProbingEnabled
        telemetryEnabled = loaded.telemetryEnabled
        siteID = loaded.siteID
        joinedGroups = loaded.joinedGroups
        loadSplitUnicast = loaded.loadSplitUnicast
        loadSplitMulticast = loaded.loadSplitMulticast
        multihomingEnabled = loaded.multihomingEnabled

        // Migrate a legacy map-server auth-key into the decent key, once.
        if decentAuthKey.isEmpty, let key = mapServers.first?.authKey, !key.isEmpty {
            decentAuthKey = key
            save()
        }
    }
}
