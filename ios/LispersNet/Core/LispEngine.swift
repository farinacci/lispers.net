//
// LispEngine.swift
//
// The single-process replacement for the lisp-core/lisp-itr/lisp-etr trio.
// Owns the sockets, map-cache, timers, and NAT state; the control-plane and
// data-plane logic live in ControlPlane.swift / DataPlane.swift extensions.
//

import Foundation
import Combine

final class LispEngine: ObservableObject {
    let config: LispConfig
    let log = LispLog.shared
    let mapCache = LispMapCache()

    @Published private(set) var running = false
    @Published private(set) var rloc: DiscoveredRLOC?
    @Published var behindNAT = false
    @Published var translatedRLOC: LispAddress?
    @Published var translatedPort: UInt16 = 0
    @Published var registrationsSent = 0
    @Published var lastMapNotify: Date?
    @Published var mapCacheVersion = 0      // bumped to refresh the UI

    // Sockets — control bound to 4342, data bound to 4341.
    var ctrlSocket: UDPSocket?
    var dataSocket: UDPSocket?
    let socketQueue = DispatchQueue(label: "lisp.sockets")

    // xTR identity
    var xtrID: (UInt64, UInt64) = (UInt64.random(in: 0...UInt64.max),
                                   UInt64.random(in: 0...UInt64.max))

    // Base RLOC/host name advertised in Info-Requests and used as the prefix of
    // the translated RLOC-name ("<xtrName>@tp-<port>"). Strip the mDNS ".local".
    var xtrName: String {
        let h = ProcessInfo.processInfo.hostName
        return h.hasSuffix(".local") ? String(h.dropLast(6)) : h
    }

    // Pending state
    var pendingMapRequests: [UInt64: LispAddress] = [:]      // nonce -> EID
    var queuedPackets: [UInt32: [Data]] = [:]                // dest v4 -> inner pkts
    var lastMapRequestSent: [UInt32: Date] = [:]             // rate limiter
    var rtrList: [LispAddress] = []
    var lastInfoNonce: UInt64 = 0

    private var timers: [Timer] = []
    private let pathWatcher = PathWatcher()
    var pingService: PingService!
    var ligService: LigService!

    init(config: LispConfig) {
        self.config = config
        pingService = PingService(engine: self)
        ligService = LigService(engine: self)
        log.controlPlaneLogging = config.controlPlaneLog
        log.dataPlaneLogging = config.dataPlaneLog
        log.rlocProbeLogging = config.rlocProbeLog
    }

    // MARK: lifecycle

    func enable() {
        guard !running else { return }
        log.controlPlaneLogging = config.controlPlaneLog
        log.dataPlaneLogging = config.dataPlaneLog
        log.rlocProbeLogging = config.rlocProbeLog
        log.fprint(.core, "lispers.net LISP xTR starting up")

        guard let discovered = Interfaces.discoverRLOC() else {
            log.fprint(.core, "No usable RLOC interface found — cannot start")
            return
        }
        rloc = discovered
        log.fprint(.core, "Using RLOC \(discovered.address.addressString) on " +
                   "interface \(discovered.interfaceName)")

        // NAT-traversal uses an EPHEMERAL data source port so the NAT yields a
        // real translated port (lisp.py sends the data Info-Request from an
        // ephemeral port — using 4341 "will break the data-plane"). decent-NAT
        // instead requires the fixed data port 4341.
        let dataBind: UInt16 = config.decentNATEnabled ? LISP.dataPort : 0
        guard let ctrl = UDPSocket(localPort: LISP.ctrlPort, queue: socketQueue),
              let data = UDPSocket(localPort: dataBind, queue: socketQueue) else {
            log.fprint(.core, "Could not bind UDP control/data sockets")
            return
        }
        ctrlSocket = ctrl
        dataSocket = data
        log.fprint(.core, "Data socket bound to local port \(data.localPort)" +
                   (config.decentNATEnabled ? " (decent-NAT)" : " (ephemeral, NAT-traversal)"))
        ctrl.startReceiving { [weak self] d, from, port, ttl in
            self?.processControlPacket(d, from: from, sourcePort: port, receivedTTL: ttl)
        }
        data.startReceiving { [weak self] d, from, port, _ in
            self?.processDataPacket(d, from: from, sourcePort: port)
        }

        if config.decentNATEnabled { installDecentNATEntry() }
        running = true

        // Initial NAT discovery, then registration (mirrors the 2-second
        // lisp_etr_info_timer kick in lisp-etr.py:96).
        if config.natTraversalEnabled {
            sendInfoRequests()
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
                self?.sendMapRegisters()
            }
        } else {
            sendMapRegisters()
        }

        startTimers()
        pathWatcher.start { [weak self] in self?.pathChanged() }
        log.fprint(.core, "LISP xTR enabled, EID \(config.eidString), " +
                   "decent-NAT \(config.decentNATEnabled ? "enabled" : "disabled")")
    }

    func disable() {
        guard running else { return }
        timers.forEach { $0.invalidate() }
        timers.removeAll()
        pathWatcher.stop()
        ctrlSocket?.shutdown(); ctrlSocket = nil
        dataSocket?.shutdown(); dataSocket = nil
        mapCache.clearAll()
        pendingMapRequests.removeAll()
        queuedPackets.removeAll()
        behindNAT = false
        translatedRLOC = nil
        translatedPort = 0
        rtrList.removeAll()
        running = false
        bumpMapCache()
        log.fprint(.core, "LISP xTR disabled")
    }

    private func startTimers() {
        let register = Timer.scheduledTimer(withTimeInterval: LISP.mapRegisterInterval,
                                            repeats: true) { [weak self] _ in
            self?.sendMapRegisters()
        }
        let probe = Timer.scheduledTimer(withTimeInterval: LISP.rlocProbeInterval,
                                         repeats: true) { [weak self] _ in
            self?.sendRLOCProbes()
        }
        timers = [register, probe]
        if config.natTraversalEnabled {
            let info = Timer.scheduledTimer(withTimeInterval: LISP.infoInterval,
                                            repeats: true) { [weak self] _ in
                self?.sendInfoRequests()
            }
            timers.append(info)
        }
    }

    private func pathChanged() {
        guard running else { return }
        let newRLOC = Interfaces.discoverRLOC()
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            if newRLOC?.address != self.rloc?.address {
                self.log.fprint(.core, "RLOC change: \(self.rloc?.address.addressString ?? "none") -> " +
                                "\(newRLOC?.address.addressString ?? "none"), re-registering")
                self.rloc = newRLOC
                if self.config.natTraversalEnabled { self.sendInfoRequests() }
                self.sendMapRegisters()
            }
        }
    }

    // decent-NAT toggle: the 240.0.0.0/8 send-map-request static entry.
    func installDecentNATEntry() {
        guard var eid = LispAddress(string: LISP.decentNatEID) else { return }
        eid.maskLen = LISP.decentNatMaskLen
        eid.instanceID = UInt32(config.instanceID)
        let entry = LispMapCacheEntry(eid: eid)
        entry.action = LISP.sendMapRequestAction
        entry.isStatic = true
        entry.ttl = nil
        mapCache.add(entry)
        log.fprint(.core, "Installed static map-cache entry [\(config.instanceID)]" +
                   "\(LISP.decentNatEID)/\(LISP.decentNatMaskLen), action send-map-request")
        bumpMapCache()
    }

    func removeDecentNATEntry() {
        guard var eid = LispAddress(string: LISP.decentNatEID) else { return }
        eid.maskLen = LISP.decentNatMaskLen
        eid.instanceID = UInt32(config.instanceID)
        mapCache.remove(eidPrefix: eid)
        log.fprint(.core, "Removed static map-cache entry \(LISP.decentNatEID)/\(LISP.decentNatMaskLen)")
        bumpMapCache()
    }

    // When RTRs are learned from an Info-Reply, a NATed xTR reaches the overlay
    // by relaying through them. lispers.net installs default map-cache entries
    // 0.0.0.0/0 (unicast) and (0.0.0.0/0, 224.0.0.0/4) (multicast) whose RLOC-set
    // is the RTR list. IPv4 only for now.
    func installRTRDefaultMapCacheEntries() {
        guard !rtrList.isEmpty else { return }
        let iid = UInt32(config.instanceID)

        func rtrRLOCSet() -> [LispRLOC] {
            rtrList.map { rtr in
                let r = LispRLOC(rloc: rtr)
                r.priority = 254
                r.weight = 0
                r.rlocName = "RTR"
                r.state = "up-state"
                return r
            }
        }

        var src = LispAddress(string: "0.0.0.0")!
        src.maskLen = 0; src.instanceID = iid
        let ttl = TimeInterval(LISP.registerTTL) * 60      // 1440m, the register TTL

        // Unicast default 0.0.0.0/0
        let uni = LispMapCacheEntry(eid: src, rlocSet: rtrRLOCSet())
        uni.isStatic = true; uni.ttl = ttl
        mapCache.add(uni)

        // Multicast default (0.0.0.0/0, 224.0.0.0/4)
        var grp = LispAddress(string: "224.0.0.0")!
        grp.maskLen = 4; grp.instanceID = iid
        let mc = LispMapCacheEntry(eid: src, rlocSet: rtrRLOCSet())
        mc.group = grp; mc.isStatic = true; mc.ttl = ttl
        mapCache.add(mc)

        let rtrs = rtrList.map { $0.addressString }.joined(separator: ", ")
        log.fprint(.itr, "Installed RTR default map-cache entries 0.0.0.0/0 and " +
                   "(0.0.0.0/0, 224.0.0.0/4) -> RTRs \(rtrs)")
        bumpMapCache()
    }

    // Turning RLOC-probing off: we can no longer determine reachability, so put
    // any unreach-state RLOCs back to up-state.
    func rlocProbingDisabled() {
        for entry in mapCache.snapshot() {
            for r in entry.rlocSet where !r.isUp {
                r.state = "up-state"
                r.stateChange = Date()
            }
        }
        bumpMapCache()
    }

    func bumpMapCache() {
        DispatchQueue.main.async { self.mapCacheVersion += 1 }
    }

    // Resolve a map-server for an EID: decent hash when configured, else the
    // first configured map-server (lisp_build_map_register decent branch).
    func mapServerFor(eid: LispAddress) -> (address: LispAddress, config: MapServerConfig)? {
        if config.decentConfigured {
            let name = LispDecent.dnsName(eid: eid, modulus: config.decentModulus,
                                          suffix: config.decentSuffix,
                                          prefixes: config.decentPrefixes)
            guard let addr = DNS.resolve(name) else {
                log.lprint(.etr, "Cannot resolve decent map-server \(name)")
                return nil
            }
            log.lprint(.etr, "LISP-Decent map-server \(name) -> \(addr.addressString) " +
                       "for EID \(eid.prefixString)")
            let msConfig = MapServerConfig(dnsNameOrAddress: name,
                                           authKey: config.decentAuthKey, authAlg: "sha2")
            return (addr, msConfig)
        }
        for ms in config.mapServers where !ms.dnsNameOrAddress.isEmpty {
            if let addr = DNS.resolve(ms.dnsNameOrAddress) {
                return (addr, ms)
            }
        }
        return nil
    }
}
