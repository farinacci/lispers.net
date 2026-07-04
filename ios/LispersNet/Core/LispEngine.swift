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
    // Translated DATA port, learned from the RTRs' Info-Replies only (NOT the
    // map-server's — the map-server's path translates to a different port, e.g.
    // 41341, that the RTRs don't use for forwarding). This is the port we
    // advertise in @tp and display. Fallback to natDataPort until an RTR replies.
    @Published var translatedPort: UInt16 = 0
    var advertisedPort: UInt16 { translatedPort != 0 ? translatedPort : LISP.natDataPort }
    // Translated CONTROL port (ctrlSocket's public NAT port), learned from the
    // map-server's control-socket Info-Reply. An ECM Map-Request goes out the
    // ctrlSocket, and lisp.py's map-server proxy-replies to itr-rloc:<inner UDP
    // src port> — so that inner source port MUST be this translated control port,
    // or the reply lands on a port with no NAT mapping and is dropped. (lig does
    // the same with its own ephemeral socket's translated port.)
    @Published var translatedCtrlPort: UInt16 = 0
    @Published var registrationsSent = 0
    @Published var lastMapNotify: Date?
    @Published var mapCacheVersion = 0      // bumped to refresh the UI
    // When the app process launched (this object is created once at launch) and
    // when LISP was last enabled (reset each time the Enable LISP toggle is
    // turned on). Shown as "LISP app uptime" / "LISP uptime" in the status header.
    let appStart = Date()
    @Published var lispStart: Date?
    // group addressString -> "<decent dns> (<resolved addr>)" of its map-server,
    // shown under each joined group in the Ping tab.
    @Published var groupMapServers: [String: String] = [:]

    // Sockets — control bound to 4342, data bound to 4341.
    var ctrlSocket: UDPSocket?
    var dataSocket: UDPSocket?
    // Multi-homing: per-interface control/data sockets (IP_BOUND_IF), keyed by
    // interface name, used to RLOC-probe and encap out a specific interface.
    var ifaceCtrlSockets: [String: UDPSocket] = [:]
    var ifaceDataSockets: [String: UDPSocket] = [:]
    var mhInterfaces: [DiscoveredRLOC] = []     // the interfaces we multi-home over
    // Multi-homing: per-interface translated (public RLOC, @tp DATA port) learned
    // from each interface's own RTR Info-Reply. We register ALL of these so a
    // remote ITR can decap to us on either interface (outbound picks the active).
    @Published var ifaceTranslated: [String: (rloc: LispAddress, port: UInt16)] = [:]
    let socketQueue = DispatchQueue(label: "lisp.sockets")

    // Route control/data sends to the right socket: the per-interface one when
    // multi-homing and the RLOC names an interface, else the default socket.
    func ctrlSock(for iface: String?) -> UDPSocket? {
        if let n = iface, let s = ifaceCtrlSockets[n] { return s }
        return ctrlSocket
    }
    func dataSock(for iface: String?) -> UDPSocket? {
        if let n = iface, let s = ifaceDataSockets[n] { return s }
        return dataSocket
    }
    // Device name for the "Send on <device>" / "Receive on <device>" debug prefix;
    // falls back to the active OS RLOC interface when not interface-specific.
    func devName(_ ifn: String? = nil) -> String { ifn ?? rloc?.interfaceName ?? "?" }

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
    var lastEncapActivity: Date?            // drives the 500ms map-cache refresh

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
    }

    // MARK: lifecycle

    func enable() {
        guard !running else { return }
        lispStart = Date()          // reset LISP uptime each time we enable
        log.controlPlaneLogging = config.controlPlaneLog
        log.dataPlaneLogging = config.dataPlaneLog
        // Banner at the top of each component log, naming the build that's running
        // (mirrors lisp.py's "lispers.net LISP <proc> starting up ..., version ...").
        let banner = "version \(ContentView.version), hostname \(xtrName)"
        log.aprint(.core, "lispers.net IOS xTR starting up, \(banner)")
        log.aprint(.itr, "lispers.net IOS ITR starting up, \(banner)")
        log.aprint(.etr, "lispers.net IOS ETR starting up, \(banner)")

        guard let discovered = Interfaces.discoverRLOC() else {
            log.fprint(.core, "No usable RLOC interface found — cannot start")
            return
        }
        rloc = discovered
        log.fprint(.core, "Using RLOC \(discovered.address.addressString) on " +
                   "interface \(discovered.interfaceName)")

        // With a NAT in the path (NAT-traversal, and decent-NAT which is just
        // NAT-traversal + the full-RLOC-set request) bind the data socket to a
        // FIXED non-4341 port so the NAT-translated @tp port stays stable across
        // app restarts (an ephemeral port 0 changed every relaunch, stranding the
        // RTR on a stale @tp and flapping our RLOC to unreach). Not 4341: Mac-lisp
        // collision + "4341 breaks the data-plane". No NAT → use the real 4341.
        let behindNATConfigured = config.natTraversalEnabled || config.decentNATEnabled
        let dataBind: UInt16 = behindNATConfigured ? LISP.natDataPort : LISP.dataPort
        guard let ctrl = UDPSocket(localPort: LISP.ctrlPort, queue: socketQueue),
              let data = UDPSocket(localPort: dataBind, queue: socketQueue) else {
            log.fprint(.core, "Could not bind UDP control/data sockets")
            return
        }
        ctrlSocket = ctrl
        dataSocket = data
        log.fprint(.core, "Data socket bound to local port \(data.localPort)" +
                   (behindNATConfigured ? " (fixed, NAT-traversal)" : " (no NAT)"))
        ctrl.startReceiving { [weak self] d, from, port, ttl in
            self?.processControlPacket(d, from: from, sourcePort: port, receivedTTL: ttl)
        }
        data.startReceiving { [weak self] d, from, port, ttl in
            self?.processDataPacket(d, from: from, sourcePort: port, receivedTTL: ttl)
        }

        buildMultihomeSockets(dataBind: dataBind)

        if config.decentNATEnabled { installDecentNATEntry() }
        running = true

        // Initial NAT discovery, then registration (mirrors the 2-second
        // lisp_etr_info_timer kick in lisp-etr.py:96). decent-NAT needs NAT
        // discovery too — it learns the translated DATA port for @tp-<port>.
        if config.natTraversalEnabled || config.decentNATEnabled {
            sendInfoRequests()
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
                self?.sendMapRegisters()
                self?.sendGroupRegisters()
            }
        } else {
            sendMapRegisters()
            sendGroupRegisters()
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
        tearDownMultihomeSockets()
        mapCache.clearAll()
        pendingMapRequests.removeAll()
        queuedPackets.removeAll()
        behindNAT = false
        translatedRLOC = nil
        translatedPort = 0
        translatedCtrlPort = 0
        rtrList.removeAll()
        running = false
        bumpMapCache()
        log.fprint(.core, "LISP xTR disabled")
    }

    // MARK: app-background lifecycle
    //
    // iOS reclaims our UDP sockets while the app is suspended. If we leave the
    // DispatchSourceRead and the repeating timers live across a suspend, on resume
    // they touch a dead/reused fd and the app crashes (EXC_GUARD/EXC_BAD_ACCESS) —
    // the "screen blanks, swipe up, crash" signature. So on .background we proactively
    // tear down the network (cancel sources+timers, close sockets) BEFORE iOS suspends
    // us, and on .active we rebuild it. Learned state (map-cache, RTR list, NAT info)
    // is preserved — only the transport is recycled.
    private var networkSuspended = false

    // Multi-homing: bring up a control+data socket per interface (Wi-Fi +
    // cellular), each pinned via IP_BOUND_IF, so we can RLOC-probe and encap out
    // each one; replies/return-data come back on the socket that sent. Shared by
    // enable() and resumeNetwork() so both build them (and both must, or the
    // multihome sockets go stale/crash across a suspend).
    func buildMultihomeSockets(dataBind: UInt16) {
        mhInterfaces = config.multihomingEnabled ? Interfaces.discoverAllRLOCs() : []
        for iface in mhInterfaces {
            guard let c = UDPSocket(localPort: LISP.ctrlPort, queue: socketQueue, boundTo: iface),
                  let d = UDPSocket(localPort: dataBind, queue: socketQueue, boundTo: iface) else {
                log.fprint(.core, "Multihoming: could not bind sockets on \(iface.interfaceName)")
                continue
            }
            let ifn = iface.interfaceName
            c.startReceiving { [weak self] dt, from, port, ttl in
                self?.processControlPacket(dt, from: from, sourcePort: port,
                                           receivedTTL: ttl, onInterface: ifn)
            }
            d.startReceiving { [weak self] dt, from, port, ttl in
                self?.processDataPacket(dt, from: from, sourcePort: port,
                                        receivedTTL: ttl, onInterface: ifn)
            }
            ifaceCtrlSockets[iface.interfaceName] = c
            ifaceDataSockets[iface.interfaceName] = d
            log.fprint(.core, "Multihoming: interface \(iface.interfaceName) " +
                       "RLOC \(iface.address.addressString) bound")
        }
    }

    // Tear down the per-interface sockets (suspend/disable). MUST run before iOS
    // suspends us — a live DispatchSourceRead on a reclaimed fd crashes on resume.
    func tearDownMultihomeSockets() {
        ifaceCtrlSockets.values.forEach { $0.shutdown() }
        ifaceDataSockets.values.forEach { $0.shutdown() }
        ifaceCtrlSockets.removeAll(); ifaceDataSockets.removeAll()
        mhInterfaces.removeAll()
        ifaceTranslated.removeAll()
    }

    func suspendNetwork() {
        guard running, !networkSuspended else { return }
        networkSuspended = true
        timers.forEach { $0.invalidate() }
        timers.removeAll()
        pathWatcher.stop()
        ctrlSocket?.shutdown(); ctrlSocket = nil
        dataSocket?.shutdown(); dataSocket = nil
        tearDownMultihomeSockets()
        log.fprint(.core, "Network suspended (app backgrounded)")
    }

    func resumeNetwork() {
        guard running, networkSuspended else { return }
        networkSuspended = false
        let behindNATConfigured = config.natTraversalEnabled || config.decentNATEnabled
        let dataBind: UInt16 = behindNATConfigured ? LISP.natDataPort : LISP.dataPort
        guard let ctrl = UDPSocket(localPort: LISP.ctrlPort, queue: socketQueue),
              let data = UDPSocket(localPort: dataBind, queue: socketQueue) else {
            log.fprint(.core, "Could not re-bind UDP sockets on resume — disabling")
            disable()
            return
        }
        ctrlSocket = ctrl
        dataSocket = data
        ctrl.startReceiving { [weak self] d, from, port, ttl in
            self?.processControlPacket(d, from: from, sourcePort: port, receivedTTL: ttl)
        }
        data.startReceiving { [weak self] d, from, port, ttl in
            self?.processDataPacket(d, from: from, sourcePort: port, receivedTTL: ttl)
        }
        buildMultihomeSockets(dataBind: dataBind)      // rebuild per-interface sockets too
        startTimers()
        pathWatcher.start { [weak self] in self?.pathChanged() }
        // NAT bindings expired while suspended — refresh registration/NAT state on
        // the fresh sockets (this is what the App used to do on .active, but it was
        // sending on the DEAD sockets).
        if behindNATConfigured { sendInfoRequests() }
        sendMapRegisters()
        sendGroupRegisters()
        log.fprint(.core, "Network resumed (app foregrounded)")
    }

    private func startTimers() {
        let register = Timer.scheduledTimer(withTimeInterval: LISP.mapRegisterInterval,
                                            repeats: true) { [weak self] _ in
            self?.sendMapRegisters()
            self?.sendGroupRegisters()
        }
        let probe = Timer.scheduledTimer(withTimeInterval: LISP.rlocProbeInterval,
                                         repeats: true) { [weak self] _ in
            // Re-evaluate the best RLOC interface every cycle, not just on the
            // NWPathMonitor callback — that callback doesn't reliably fire when
            // Wi-Fi comes up while cellular stays the primary path, so without this
            // the xTR stays on 5G even though en0 (preferred) is now available.
            // discoverRLOC is cheap (getifaddrs); pathChanged only re-registers
            // when the chosen address actually changes.
            self?.pathChanged()
            self?.sendRLOCProbes()
        }
        timers = [register, probe]
        if config.natTraversalEnabled || config.decentNATEnabled {
            let info = Timer.scheduledTimer(withTimeInterval: LISP.infoInterval,
                                            repeats: true) { [weak self] _ in
                self?.sendInfoRequests()
            }
            timers.append(info)
        }
        // While data is being encapsulated, refresh the map-cache every 500ms so
        // the packet-count flashes boldface live. When idle, this stays quiet and
        // the display updates on RLOC-probe replies (processProbeReply bumps).
        let ui = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            guard let self = self, let last = self.lastEncapActivity,
                  Date().timeIntervalSince(last) < 2.0 else { return }
            self.bumpMapCache()
        }
        timers.append(ui)
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
                if self.config.natTraversalEnabled || self.config.decentNATEnabled {
                    self.sendInfoRequests()
                }
                self.sendMapRegisters()
                self.sendGroupRegisters()
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
        mapCache.remove(eidPrefix: eid)         // the 240/8 send-map-request entry
        // Disabling decent-NAT invalidates everything we learned through it — flush
        // the dynamic (learned) entries but keep the static defaults (RTR 0/0, ::/0,
        // and the (S,G) multicast defaults).
        mapCache.clearDynamic()
        log.fprint(.core, "Removed decent-NAT \(LISP.decentNatEID)/" +
                   "\(LISP.decentNatMaskLen) entry and flushed learned map-cache entries " +
                   "(kept defaults)")
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
            // Multi-homing: one RLOC per (RTR × interface) so each interface is a
            // separate next-hop probed independently. Single-homed: one per RTR.
            let ifaces: [DiscoveredRLOC?] = (config.multihomingEnabled && !mhInterfaces.isEmpty)
                ? mhInterfaces.map { $0 } : [nil]
            var out: [LispRLOC] = []
            for rtr in rtrList {
                for iface in ifaces {
                    let r = LispRLOC(rloc: rtr)
                    r.priority = 254
                    r.weight = 0
                    r.rlocName = "RTR"
                    r.interfaceName = iface?.interfaceName
                    r.ifIndex = iface?.ifIndex ?? 0
                    // With RLOC-probing on we don't yet know the RTR is reachable —
                    // start unreach so we never show reach without telemetry; a
                    // probe reply promotes it. Probing off -> assume up (forward).
                    r.state = config.rlocProbingEnabled ? "unreach-state" : "up-state"
                    out.append(r)
                }
            }
            return out
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
            // Show the decent lookup-prefix the EID matched (masked to the matching
            // decent-prefix's lookup-length) — this is what gets hashed to select
            // the map-server, so it tells you WHICH lookup-prefix is in play.
            let lookup = LispDecent.eidString(for: eid, prefixes: config.decentPrefixes)
            log.lprint(.etr, "LISP-Decent map-server \(name) -> \(addr.addressString) " +
                       "for EID \(eid.prefixString), lookup-prefix \(lookup)")
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
