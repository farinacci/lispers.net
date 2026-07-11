//
// EngineMirror.swift
//
// Option B state bridge. The process that actually runs the xTR — the app (VPN-off)
// OR the LispTunnel extension (VPN-on) — serialises its live display state (map-cache +
// status) to a shared App-Group file once a second. The OTHER process (the app, when the
// extension owns the xTR) polls that file and mirrors it into its own LispEngine object,
// so MapCacheView / StatusHeader / Logs render the extension's live state UNCHANGED —
// they just observe the app's engine, which is now a faithful mirror.
//
// Only the engine that owns the sockets writes (writeSnapshot runs from the 1s timer in
// startTimers(), which only the real xTR schedules), so there is never a write race.
//

import Foundation

// A flat, Codable view of everything the UI shows. Decoupled from the LispRLOC /
// LispMapCacheEntry classes so the wire format is stable and cheap to (de)serialise.
struct EngineSnapshot: Codable {
    struct RLOC: Codable {
        var rloc: LispAddress
        var priority: UInt8
        var weight: UInt8
        var encapPort: UInt16
        var interfaceName: String?
        var ifIndex: UInt32
        var activeNextHop: Bool
        var state: String
        var stateChange: Date
        var rlocName: String?
        var packetCount: UInt64
        var byteCount: UInt64
        var lastPacket: Date?
        var recentRTTs: [Double]
        var recentHops: [String]
        var recentLatencies: [String]
    }
    struct Entry: Codable {
        var eid: LispAddress
        var group: LispAddress
        var action: Int
        var uptime: Date
        var ttl: TimeInterval?
        var isStatic: Bool
        var rlocs: [RLOC]
    }
    struct MHIface: Codable {
        var iface: DiscoveredRLOC
        var translatedRLOC: LispAddress?
        var translatedPort: UInt16
    }

    // scalar status (StatusHeader)
    var running: Bool
    var xtrName: String
    var eidString: String
    var rloc: DiscoveredRLOC?
    var translatedRLOC: LispAddress?
    var translatedPort: UInt16
    var behindNAT: Bool
    var registrationsSent: Int
    var lispStart: Date?
    var joinedGroupsCount: Int
    var mh: [MHIface]
    var entries: [Entry]
    var updated: Date

    static var fileURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: OverlayTunnel.appGroup)?
            .appendingPathComponent("xtr-state.json")
    }

    static func read() -> EngineSnapshot? {
        guard let url = fileURL, let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(EngineSnapshot.self, from: data)
    }
}

extension LispEngine {
    // Serialise the current state. Reads the map-cache via its lock-guarded snapshot().
    func buildSnapshot() -> EngineSnapshot {
        let entries: [EngineSnapshot.Entry] = mapCache.snapshot().map { e in
            let rlocs = e.rlocSet.map { r in
                EngineSnapshot.RLOC(
                    rloc: r.rloc, priority: r.priority, weight: r.weight,
                    encapPort: r.encapPort, interfaceName: r.interfaceName,
                    ifIndex: r.ifIndex, activeNextHop: r.activeNextHop, state: r.state,
                    stateChange: r.stateChange, rlocName: r.rlocName,
                    packetCount: r.packetCount, byteCount: r.byteCount,
                    lastPacket: r.lastPacket, recentRTTs: r.recentRTTs,
                    recentHops: r.recentHops, recentLatencies: r.recentLatencies)
            }
            return EngineSnapshot.Entry(
                eid: e.eid, group: e.group, action: e.action, uptime: e.uptime,
                ttl: e.ttl, isStatic: e.isStatic, rlocs: rlocs)
        }
        let mh: [EngineSnapshot.MHIface] = mhInterfaces.map { iface in
            let x = ifaceTranslated[iface.interfaceName]
            return EngineSnapshot.MHIface(iface: iface, translatedRLOC: x?.rloc,
                                          translatedPort: x?.port ?? 0)
        }
        return EngineSnapshot(
            running: running, xtrName: xtrName, eidString: config.eidString,
            rloc: rloc, translatedRLOC: translatedRLOC, translatedPort: translatedPort,
            behindNAT: behindNAT, registrationsSent: registrationsSent,
            lispStart: lispStart, joinedGroupsCount: config.joinedGroups.count,
            mh: mh, entries: entries, updated: Date())
    }

    // Called from the real xTR's 1s UI timer (startTimers). Atomically publishes the
    // snapshot to the App-Group file for the mirroring process to read.
    func writeSnapshot() {
        guard let url = EngineSnapshot.fileURL,
              let data = try? JSONEncoder().encode(buildSnapshot()) else { return }
        try? data.write(to: url, options: .atomic)
    }

    // Rebuild the map-cache + scalar state from a snapshot (the mirroring app engine).
    // Runs on the main actor: it drives @Published UI state.
    func applySnapshot(_ s: EngineSnapshot) {
        mapCache.clearAll()
        for se in s.entries {
            let rlocs = se.rlocs.map { sr -> LispRLOC in
                let r = LispRLOC(rloc: sr.rloc)
                r.priority = sr.priority; r.weight = sr.weight; r.encapPort = sr.encapPort
                r.interfaceName = sr.interfaceName; r.ifIndex = sr.ifIndex
                r.activeNextHop = sr.activeNextHop; r.state = sr.state
                r.stateChange = sr.stateChange; r.rlocName = sr.rlocName
                r.packetCount = sr.packetCount; r.byteCount = sr.byteCount
                r.lastPacket = sr.lastPacket; r.recentRTTs = sr.recentRTTs
                r.recentHops = sr.recentHops; r.recentLatencies = sr.recentLatencies
                return r
            }
            let entry = LispMapCacheEntry(eid: se.eid, rlocSet: rlocs)
            entry.group = se.group; entry.action = se.action; entry.uptime = se.uptime
            entry.ttl = se.ttl; entry.isStatic = se.isStatic; entry.lastRefresh = Date()
            mapCache.add(entry)
        }
        mirrorSetRunning(s.running)
        mirrorSetRLOC(s.rloc)
        translatedRLOC = s.translatedRLOC
        translatedPort = s.translatedPort
        behindNAT = s.behindNAT
        registrationsSent = s.registrationsSent
        lispStart = s.lispStart
        mhInterfaces = s.mh.map { $0.iface }
        ifaceTranslated = Dictionary(uniqueKeysWithValues: s.mh.compactMap { m in
            m.translatedRLOC.map { (m.iface.interfaceName, (rloc: $0, port: m.translatedPort)) }
        })
        bumpMapCache()
    }

    // MARK: - app-side mirror poll (VPN-on: the extension owns the xTR)

    // Start polling the App-Group snapshot and mirroring it into this engine. Used by the
    // app when the Overlay App VPN is enabled — the extension is the real xTR, this engine
    // is a read-only mirror and MUST NOT bind sockets.
    func startStateMirror() {
        guard mirrorTimer == nil else { return }
        isMirroring = true
        // The extension owns the log files now; don't let this process write them too.
        log.setFileWrites(false)
        if let s = EngineSnapshot.read() { applySnapshot(s) }
        mirrorLogs()
        let t = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            guard let self else { return }
            if let s = EngineSnapshot.read() { self.applySnapshot(s) }
            self.mirrorLogs()
        }
        mirrorTimer = t
    }

    // Tail the extension's App-Group log files into the app's in-memory ring so the Logs
    // tab shows what the extension logged (core/itr/etr) — the app's own engine isn't
    // running in mirror mode, so nothing else populates those scopes.
    private func mirrorLogs() {
        for c in [LogComponent.core, .itr, .etr] { log.loadTail(c) }
    }

    func stopStateMirror() {
        let wasMirroring = isMirroring
        mirrorTimer?.invalidate(); mirrorTimer = nil
        isMirroring = false
        log.setFileWrites(true)   // this process may become the xTR again (VPN off)
        // While mirroring we set running=true and filled the map-cache from the extension's
        // snapshot. Reset to a clean NON-running state so a following enable() (the app
        // becoming the real xTR again) actually binds its sockets — enable() bails if
        // running is already true, which would leave a zombie engine (running, no sockets)
        // whose encapAndSend logs an encap then no-ops. Only do this if we WERE mirroring —
        // never disturb a real in-app xTR.
        if wasMirroring {
            mirrorSetRunning(false)
            mapCache.clearAll()
            bumpMapCache()
        }
    }
}
