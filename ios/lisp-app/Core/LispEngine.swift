//
// LispEngine.swift
//
// The single-process replacement for the lisp-core/lisp-itr/lisp-etr trio.
// Owns the sockets, map-cache, timers, and NAT state; the control-plane and
// data-plane logic live in ControlPlane.swift / DataPlane.swift extensions.
//

import Foundation
import Combine
import Darwin
#if HOST_APP
import UIKit   // UIApplication.beginBackgroundTask — host-app only; unavailable in the NE extension
#endif

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
    // Overlay-app (IGMP) joined groups — shown in the Multicast Groups list LOCKED (the user
    // can't leave these; only the app that joined them via IGMP, or the soft-state timeout).
    // Excludes the LISP app's own manually-joined groups (those show with a Leave button).
    // Mirror of igmpGroups (app-xTR) / the snapshot.
    @Published var appJoinedGroups: [AppJoinedGroup] = []

    // Sockets — control bound to 4342, data bound to 4341.
    var ctrlSocket: UDPSocket?
    var dataSocket: UDPSocket?
    var overlayInjectSocket: UDPSocket?         // loopback handoff from the tunnel extension
    private var pingReplyFD: Int32 = -1         // loopback sender to the PING client app
    // Multi-homing: per-interface control/data sockets (IP_BOUND_IF), keyed by
    // interface name, used to RLOC-probe and encap out a specific interface.
    var ifaceCtrlSockets: [String: UDPSocket] = [:]
    var ifaceDataSockets: [String: UDPSocket] = [:]
    var mhInterfaces: [DiscoveredRLOC] = []     // the interfaces we multi-home over
    // Multi-homing: per-interface translated (public RLOC, @tp DATA port) learned
    // from each interface's own RTR Info-Reply. We register ALL of these so a
    // remote ITR can decap to us on either interface (outbound picks the active).
    @Published var ifaceTranslated: [String: (rloc: LispAddress, port: UInt16)] = [:]
    // Build running the REAL xTR (from the snapshot). Differs from AppInfo.version when the
    // LispTunnel extension is still executing an older binary after an app reinstall.
    @Published var engineVersion: String?

    // Debounce for Info-Reply-triggered Map-Registers. A flurry of identical
    // Info-Replies — both RTRs, on every interface, plus retransmits — arrives within
    // a few ms; we coalesce them into ONE register fired after the burst settles,
    // instead of one per reply (the storm) or suppressing them entirely (which
    // starved the NAT keepalive and froze packet-counts).
    var pendingRegisterWork: DispatchWorkItem?
    let socketQueue = DispatchQueue(label: "lisp.sockets")
    // Overlay work (inject-encap + the readiness heartbeat) runs here, OFF socketQueue so
    // it never starves RLOC-probe-reply processing, and on GCD (not main) so it keeps
    // running while the LISP app is backgrounded for a foreground overlay app — on the sim
    // (never suspended) and during the device background grace. MapCache is NSLock-guarded.
    let overlayQueue = DispatchQueue(label: "lisp.overlay")
    private var heartbeatSource: DispatchSourceTimer?

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

    // xTR identity — STABLE across launches, and shared by the app and the LispTunnel
    // extension (either process can host the xTR, so both must present the SAME identity).
    //
    // This MUST NOT be re-randomized per launch. The map-server keys a site's registrations by
    // xtr-id, so a fresh id registers as an ADDITIONAL ETR for the same EID rather than
    // replacing the previous one — the map-server then keeps every past launch's RLOC-set for
    // the full register TTL (24h) and merges them all into the Map-Reply. That is what left
    // dead RLOCs (old NAT bindings / departed interfaces) in the mapping, so remote ITRs cached
    // them and encapped into black holes. With a stable id, each Map-Register REPLACES our
    // RLOC-set, so losing an interface actually withdraws its RLOC.
    var xtrID: (UInt64, UInt64) = LispEngine.persistentXTRID()

    private static func persistentXTRID() -> (UInt64, UInt64) {
        let key = "xtrID"
        let defaults = UserDefaults(suiteName: "group.net.lispers.xtr")
        if let s = defaults?.string(forKey: key) {
            let parts = s.split(separator: "-")
            if parts.count == 2, let hi = UInt64(parts[0], radix: 16),
               let lo = UInt64(parts[1], radix: 16) {
                return (hi, lo)
            }
        }
        let v = (UInt64.random(in: 0...UInt64.max), UInt64.random(in: 0...UInt64.max))
        defaults?.set(String(format: "%016llx-%016llx", v.0, v.1), forKey: key)
        return v
    }

    // Base RLOC/host name advertised in Info-Requests and used as the prefix of
    // the translated RLOC-name ("<xtrName>@tp-<port>"). Strip the mDNS ".local".
    var xtrName: String {
        // A hostname set on the xTR tab wins; otherwise the 0.6 default — the
        // system hostname (ProcessInfo.hostName, ".local" stripped), which is the
        // device's mDNS name where iOS exposes it, else "localhost".
        let configured = config.xtrHostname.trimmingCharacters(in: .whitespaces)
        if !configured.isEmpty { return configured }
        let h = ProcessInfo.processInfo.hostName
        return h.hasSuffix(".local") ? String(h.dropLast(6)) : h
    }

    // Pending state
    var pendingMapRequests: [UInt64: LispAddress] = [:]      // nonce -> EID
    var queuedPackets: [UInt32: [Data]] = [:]                // dest v4 -> inner pkts
    var lastMapRequestSent: [UInt32: Date] = [:]             // rate limiter
    var rtrList: [LispAddress] = []
    // Decent-NAT peer ETRs to NAT-probe (open our local NAT hole toward them so we can encap
    // directly, bypassing the RTR). Keyed by RLOC v4. Mirrors lisp_etr_nat_probe_list
    // (lisp-etr.py:77) — populated from resolved 240/x map-cache RLOCs that carry an @tp name.
    var natProbeList: [UInt32: LispAddress] = [:]
    var lastInfoNonce: UInt64 = 0
    // Per-interface data Info-Request nonce → interface name. A data Info-Reply is attributed
    // to the interface its request EGRESSED on by matching this nonce — NOT by which socket
    // caught the reply, because the wildcard default data socket (INADDR_ANY:41341) can steal
    // a per-interface reply under SO_REUSEPORT, so socket-based attribution drops (or
    // mis-assigns) an interface's translated RLOC. Rebuilt each Info-Request cycle.
    var infoNonceIface: [UInt64: String] = [:]
    var lastEncapActivity: Date?            // drives the 500ms map-cache refresh
    // IGMP soft-state (*,G) membership requested by an overlay app (gaapchat) via IGMPv2
    // Reports injected over the tunnel (inner IP proto 2, dst = our EID). group-v4 -> last
    // report time; expires after LISP.igmpGroupTimeout without a Report. Kept SEPARATE from
    // config.joinedGroups (user-joined, persisted) so the user can't leave an app-joined
    // group — only the app's IGMP Leave (or the soft-state timeout) removes it. See IGMP.swift.
    var igmpGroups: [UInt32: Date] = [:]        // group-v4 -> last report time
    var igmpGroupSource: [UInt32: String] = [:] // group-v4 -> joiner ("LISP app" or overlay app)
    var overlayRecvFD: Int32 = -1           // loopback sender to the gaapchat overlay app

    private var timers: [Timer] = []
    // Option B mirror (app side, VPN-on): polls the extension's App-Group snapshot into
    // this engine so the UI shows the extension's live state. See EngineMirror.swift.
    var mirrorTimer: Timer?
    var isMirroring = false
    // Set by the tunnel provider: the tunnel IP is the EID, so an EID edit while the VPN is
    // up must re-address the utun. applyLiveReload() calls this before the soft re-register.
    var onEIDChange: ((String) -> Void)?
    // Internal setters so the mirror (EngineMirror.swift, a separate file) can drive the
    // private(set) status props. Only for mirroring — the real xTR sets these directly.
    func mirrorSetRunning(_ v: Bool) { running = v }
    func mirrorSetRLOC(_ v: DiscoveredRLOC?) { rloc = v }
    private let pathWatcher = PathWatcher()
    var pingService: PingService!
    var ligService: LigService!
    var ltrService: LTRService!

    init(config: LispConfig) {
        self.config = config
        pingService = PingService(engine: self)
        ligService = LigService(engine: self)
        ltrService = LTRService(engine: self)
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
        let banner = "version \(AppInfo.version), hostname \(xtrName)"
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

        // Loopback socket: the tunnel extension hands us captured overlay inner packets
        // here (127.0.0.1:overlayInjectPort); we forward each via the normal data plane.
        if let inject = UDPSocket(localPort: LISP.overlayInjectPort, queue: socketQueue) {
            overlayInjectSocket = inject
            // Hand the encap off to overlayQueue, NOT socketQueue: this handler shares
            // socketQueue with the control + data receive handlers, and heavy per-packet
            // encap/logging here starves RLOC-probe-reply processing (probeOutstandingSince
            // isn't cleared before the unreach check fires → RTR flips to unreach under a
            // sustained ping load). overlayQueue is also GCD (not main), so it keeps
            // encapping while the app is backgrounded for a foreground overlay app.
            inject.startReceiving { [weak self] d, _, _, _ in
                self?.overlayQueue.async { self?.injectFromTunnel(d) }
            }
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
                self?.selfReportManualGroups()
            }
        } else {
            sendMapRegisters()
            selfReportManualGroups()
        }

        startTimers()
        pathWatcher.start { [weak self] in self?.pathChanged() }
        log.aprint(.core, "LISP xTR enabled, EID [\(config.instanceID)]\(config.eidString)")
    }

    func disable() {
        guard running else { return }
        heartbeatSource?.cancel(); heartbeatSource = nil
        clearHeartbeat()                    // overlay apps flip to "not running" at once
        timers.forEach { $0.invalidate() }
        timers.removeAll()
        pathWatcher.stop()
        ctrlSocket?.shutdown(); ctrlSocket = nil
        dataSocket?.shutdown(); dataSocket = nil
        overlayInjectSocket?.shutdown(); overlayInjectSocket = nil
        tearDownMultihomeSockets()
        mapCache.clearAll()
        igmpGroups.removeAll(); igmpGroupSource.removeAll()  // drop soft-state groups
        if overlayRecvFD >= 0 { close(overlayRecvFD); overlayRecvFD = -1 }
        pendingMapRequests.removeAll()
        queuedPackets.removeAll()
        behindNAT = false
        translatedRLOC = nil
        translatedPort = 0
        translatedCtrlPort = 0
        rtrList.removeAll()
        running = false
        bumpMapCache()
        log.aprint(.core, "LISP xTR disabled")
    }

    // Live-reconfigure (extension only, called from the 1s timer). The app writes xTR-tab
    // edits to the shared config file; pick them up and apply to the running xTR — no Save
    // button, no VPN off/on. Dynamic fields apply in place; structural fields do a soft
    // re-register (disable+enable rebinds sockets and re-registers, the tunnel stays up).
    // The bounce is deferred to the next runloop tick so it doesn't invalidate the timer
    // that's currently firing (this method runs inside that timer).
    private var registerDirty = false
    private var bounceDirty = false
    private var pendingEIDChange = false

    func applyLiveReload() {
        let r = config.reloadAll()
        if r.dynamicChanged {
            log.controlPlaneLogging = config.controlPlaneLog
            log.dataPlaneLogging = config.dataPlaneLog
        }
        if r.eidChanged { pendingEIDChange = true }
        // A structural field is mid-edit (differs from last tick). Mark it dirty and wait for
        // it to settle, so a text field like EID/auth-key applies ONCE on the committed value,
        // not on every keystroke.
        if r.bounceChanged { bounceDirty = true; return }
        if r.registerChanged { registerDirty = true; return }
        guard bounceDirty || registerDirty else { return }
        // A full tick with no further change = the edit committed. Apply once.
        let doBounce = bounceDirty
        let eidChanged = pendingEIDChange
        registerDirty = false; bounceDirty = false; pendingEIDChange = false
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            if eidChanged { self.onEIDChange?(self.config.eidString) }   // re-address the utun
            if doBounce {
                // Sockets/data-plane must be rebuilt (NAT mode, mh, RLOC-probe, enable). The
                // per-field "Config change:" lines already say what changed; enable()/disable()
                // log the re-register — so no separate "settled" line needed.
                if self.running { self.disable() }
                if self.config.lispEnabled { self.enable() }
            } else if self.running {
                // Register-only (EID, IID, auth-key, MSes, hostname): a fresh Map-Register.
                self.sendMapRegisters()
            }
        }
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
        overlayInjectSocket?.shutdown(); overlayInjectSocket = nil
        tearDownMultihomeSockets()
        heartbeatSource?.cancel(); heartbeatSource = nil
        clearHeartbeat()                    // overlay apps see "not running" once suspended
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
        // Rebuild the overlay loopback inject socket too (suspend tore it down) — else the
        // extension's handoff has nowhere to land after a background/foreground cycle.
        if let inject = UDPSocket(localPort: LISP.overlayInjectPort, queue: socketQueue) {
            overlayInjectSocket = inject
            // Hand the encap off to overlayQueue, NOT socketQueue: this handler shares
            // socketQueue with the control + data receive handlers, and heavy per-packet
            // encap/logging here starves RLOC-probe-reply processing (probeOutstandingSince
            // isn't cleared before the unreach check fires → RTR flips to unreach under a
            // sustained ping load). overlayQueue is also GCD (not main), so it keeps
            // encapping while the app is backgrounded for a foreground overlay app.
            inject.startReceiving { [weak self] d, _, _, _ in
                self?.overlayQueue.async { self?.injectFromTunnel(d) }
            }
        }
        buildMultihomeSockets(dataBind: dataBind)      // rebuild per-interface sockets too
        // The probe timer was paused while backgrounded, so probeOutstandingSince is stale
        // (it counted wall-clock we weren't actually probing). Reset it so the unreach timer
        // restarts from the fresh probes below, instead of instantly flipping RLOCs to
        // unreach the moment we foreground after a background gap.
        for entry in mapCache.snapshot() {
            for r in entry.rlocSet { r.probeOutstandingSince = nil }
        }
        startTimers()
        pathWatcher.start { [weak self] in self?.pathChanged() }
        // NAT bindings expired while suspended — refresh registration/NAT state on
        // the fresh sockets (this is what the App used to do on .active, but it was
        // sending on the DEAD sockets).
        if behindNATConfigured { sendInfoRequests() }
        sendMapRegisters()
        reregisterIGMPGroups()                       // refresh (*,G) with the resumed sockets
        log.fprint(.core, "Network resumed (app foregrounded)")
    }

    // MARK: background grace (0.8 interim; full always-on = Option B / [[always-on-xtr-idea]])
    //
    // When the app backgrounds (e.g. a foreground overlay app like PING takes over), hold
    // a UIKit background-task assertion and KEEP the sockets up instead of suspending
    // immediately — so the xTR keeps forwarding for the overlay app (encap → RTR → reply →
    // loopback to PING) for the finite window iOS grants (~30s, not tunable). When the
    // assertion expires, suspend cleanly. Returning to the foreground cancels it.
    #if HOST_APP && !targetEnvironment(simulator)
    private var graceTask: UIBackgroundTaskIdentifier = .invalid

    func beginBackgroundGrace() {
        guard running else { suspendNetwork(); return }   // nothing to keep alive
        if graceTask == .invalid {
            graceTask = UIApplication.shared.beginBackgroundTask(withName: "xtr-grace") {
                [weak self] in self?.expireBackgroundGrace()
            }
            log.fprint(.core, "Background grace started — xTR keeps forwarding (~30s)")
        }
        // Deliberately do NOT suspendNetwork here — sockets stay up for the window.
    }

    private func expireBackgroundGrace() {
        log.fprint(.core, "Background grace expired — suspending")
        suspendNetwork()
        if graceTask != .invalid { UIApplication.shared.endBackgroundTask(graceTask); graceTask = .invalid }
    }

    func endBackgroundGrace() {   // called on return to foreground
        if graceTask != .invalid { UIApplication.shared.endBackgroundTask(graceTask); graceTask = .invalid }
    }
    #endif

    private func startTimers() {
        let register = Timer.scheduledTimer(withTimeInterval: LISP.mapRegisterInterval,
                                            repeats: true) { [weak self] _ in
            self?.sendMapRegisters()                 // unicast EID (its own timer)
            self?.selfReportManualGroups()           // manual groups self-report IGMP → (*,G)
            self?.expireIGMPGroups()                 // drop overlay groups whose app went silent
                                                     //   past the grace window (igmpGroupTimeout)
            self?.reregisterIGMPGroups()             // extension-owned (*,G) refresh — keeps a
                                                     //   backgrounded app's group alive through
                                                     //   the grace window without its IGMP reports
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
            self?.withdrawDeadTranslations()   // withdraw a departed interface's RLOC promptly
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
        // Refresh the map-cache display on a steady 1s cadence while running, not
        // just on encap activity / RLOC-probe replies. Otherwise, when the probe
        // return-path is filtered (no replies -> no processProbeReply bump) and
        // pings are intermittent, the view froze at its first render — uptime stuck
        // at 0:00:00 and packet-counts/rtts never repainting even though the
        // underlying objects were updating. This drives the SAME @Published bump the
        // view already observes, so it works regardless of the view's own timers.
        let ui = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.bumpMapCache()
            // Publish live state to the App-Group so the OTHER process (the app UI when
            // this xTR runs in the extension — Option B) can mirror it. Only the real
            // xTR runs startTimers, so there's never a competing writer.
            self.writeSnapshot()
            // Extension only: pick up config the user edited in the app while the VPN is up
            // (the extension read config once at startTunnel). No Save button, no VPN bounce.
            #if !HOST_APP
            self.applyLiveReload()
            #endif
        }
        timers.append(ui)

        // Readiness heartbeat on a GCD timer (NOT the main-run-loop Timer above): the main
        // run loop stops firing timers once the app is backgrounded, but overlay apps read
        // this heartbeat precisely WHEN this app is backgrounded (they're foreground). A GCD
        // timer keeps stamping while backgrounded-not-suspended (sim; device grace window).
        heartbeatSource?.cancel()
        let hb = DispatchSource.makeTimerSource(queue: overlayQueue)
        hb.schedule(deadline: .now(), repeating: 1.0, leeway: .milliseconds(200))
        hb.setEventHandler { [weak self] in self?.writeHeartbeat() }
        heartbeatSource = hb
        hb.resume()
    }

    // Re-bind the primary control/data sockets after a path change. Keeps the SAME local ports
    // (the data port is deliberately fixed so the NAT-translated @tp stays stable), so this
    // only discards the dead socket state — it doesn't move our @tp.
    func rebuildPrimarySockets() {
        guard running, !networkSuspended else { return }
        let behindNATConfigured = config.natTraversalEnabled || config.decentNATEnabled
        let dataBind: UInt16 = behindNATConfigured ? LISP.natDataPort : LISP.dataPort
        ctrlSocket?.shutdown(); ctrlSocket = nil
        dataSocket?.shutdown(); dataSocket = nil
        guard let ctrl = UDPSocket(localPort: LISP.ctrlPort, queue: socketQueue),
              let data = UDPSocket(localPort: dataBind, queue: socketQueue) else {
            log.aprint(.core, "Path change: could not re-bind primary control/data sockets")
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
        log.aprint(.core, "Path change: re-bound primary control/data sockets " +
                   "(ctrl \(LISP.ctrlPort), data \(dataBind))")
    }

    // Trigger a Map-Register whenever a translation's interface has gone away, so its RLOC is
    // withdrawn promptly (sendMapRegisters drops dead translations and registers the live set).
    // Driven by the 10s probe timer so withdrawal lands within ~10s even if the NWPathMonitor
    // callback didn't fire and pathChanged's change-guard short-circuited.
    func withdrawDeadTranslations() {
        guard running, config.multihomingEnabled, !ifaceTranslated.isEmpty else { return }
        let live = Set(Interfaces.discoverAllRLOCs().map { $0.interfaceName })
        guard ifaceTranslated.keys.contains(where: { !live.contains($0) }) else { return }
        sendMapRegisters()
    }

    private func pathChanged() {
        guard running else { return }
        let newRLOC = Interfaces.discoverRLOC()
        let newMH = config.multihomingEnabled ? Interfaces.discoverAllRLOCs() : []
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            // Detect a change on the PRIMARY RLOC or on ANY multi-homed interface's address
            // (a Wi-Fi network switch keeps the same interface but changes its IP + NAT).
            let primaryChanged = newRLOC?.address != self.rloc?.address
            let oldMH = Dictionary(uniqueKeysWithValues:
                self.mhInterfaces.map { ($0.interfaceName, $0.address) })
            let newMHMap = Dictionary(uniqueKeysWithValues:
                newMH.map { ($0.interfaceName, $0.address) })
            guard primaryChanged || oldMH != newMHMap else { return }

            self.log.aprint(.core, "Path change: RLOC \(self.rloc?.address.addressString ?? "none") " +
                            "-> \(newRLOC?.address.addressString ?? "none") — rebuilding sockets, " +
                            "re-learning NAT translations")
            self.rloc = newRLOC

            // Drop the translated RLOC/@tp learned on the OLD network for every interface whose
            // IP changed — otherwise it lingers (copied from the other interface) until LISP is
            // disabled, and its RLOC-probes get no replies (no rtts). It re-learns via the
            // Info-Requests below.
            for (name, addr) in newMHMap where oldMH[name] != addr {
                self.ifaceTranslated[name] = nil
            }
            // A departed interface's translation is dropped in the Map-Register path
            // (sendMapRegisters registers only live interfaces), which this triggers below.
            if primaryChanged { self.translatedRLOC = nil; self.translatedPort = 0 }

            // Rebuild the PRIMARY control/data sockets too. Darwin pins a UDP socket's source
            // address once it has sent, so after the interface that address belonged to goes
            // away every sendto() on it fails (EADDRNOTAVAIL/ENETDOWN) — silently, until now.
            // That is what stopped Map-Registers from ever leaving the phone on interface loss:
            // the RLOC-set we built was correct, it just never went out, so the map-server kept
            // the old set until it timed the registration out. Only the multi-homing sockets
            // used to be rebuilt here; these two carry the Map-Registers.
            self.rebuildPrimarySockets()

            // Rebuild the per-interface (multi-homing) sockets bound to the NEW interface IPs,
            // so Info-Requests and RLOC-probes egress the right path after the switch.
            if self.config.multihomingEnabled {
                let dataBind = (self.config.natTraversalEnabled || self.config.decentNATEnabled)
                    ? LISP.natDataPort : LISP.dataPort
                self.tearDownMultihomeSockets()
                self.buildMultihomeSockets(dataBind: dataBind)
                // mhInterfaces changed (e.g. Wi-Fi came up at a hotel) — rebuild the RTR default
                // map-cache entries so the new interface is a next-hop (one RLOC per RTR×iface).
                self.installRTRDefaultMapCacheEntries()
            }

            if self.config.natTraversalEnabled || self.config.decentNATEnabled {
                self.sendInfoRequests()
            }
            self.sendMapRegisters()
            self.reregisterIGMPGroups()          // refresh (*,G) on RLOC change
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
        natProbeList.removeAll()                // stop NAT-probing peer ETRs
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
                    // Start up-state so the RLOC is usable IMMEDIATELY. A NAT may
                    // filter our RLOC-probes for the first cycle(s), and a brand-new
                    // default entry should not be unusable while we wait for the
                    // first reply. We fire a probe the instant the entry is created
                    // (installRTRDefaultMapCacheEntries below calls sendRLOCProbes),
                    // and the unreach timer still demotes it after rlocProbeReplyWait
                    // if no reply ever comes. rtts stay "?" until the first reply
                    // lands, so telemetry still tells "assumed up" from "probe-
                    // confirmed up" (? -> a number == first probe reply received).
                    r.state = "up-state"
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
        // Mark an active next-hop ("*") NOW, on the freshly-built RLOC set, instead
        // of leaving every hop inactive until the first probe reply. With no rtt
        // data yet, selectNextHop's fallback picks the cellular (pdp_ip*) hop — so
        // a "*" shows the instant pdp_ip0 comes up and the set is rebuilt, not 10-30s
        // later. Probe replies refine the choice by rtt afterward.
        recomputeActiveNextHops()
        bumpMapCache()
        // Probe the new RTRs right now instead of waiting up to a full
        // rlocProbeInterval — telemetry arrives sooner and the RLOCs get
        // probe-confirmed faster (they already start up-state, so they're usable
        // in the meantime).
        sendRLOCProbes()
    }

    // An overlay app's LISP data packet ([LISP-hdr][inner]), captured off the utun by
    // the tunnel extension and handed to us over loopback. This is the ITR: DECAP the
    // overlay app's LISP header (which carries the instance-id it sent in), then do a
    // map-cache lookup on the inner header and RE-ENCAP through the normal data plane —
    // same load-split/multihoming RLOC selection, "Encap outer RLOCs: …" log, and RLOC
    // counters as an in-app ping. Runs on socketQueue (the receive handler's queue).
    func injectFromTunnel(_ inner: Data) {
        guard running else { return }
        // A RAW inner IP packet from an overlay app — no LISP header (the local hop
        // doesn't need one; we know our own instance-id). Encap it as the ITR.
        // (Readiness is advertised via the App-Group heartbeat file, not a loopback ack.)
        guard inner.count >= 20, let v = inner.first, v >> 4 == 4 else { return }
        let iid = UInt32(config.instanceID)
        let ip = innerIPInfo(inner)
        log.dprint(.itr, "Receive utun, inner EIDs: [\(iid)]\(ip.src) -> [\(iid)]\(ip.dst), " +
                   "inner tos/ttl: \(ip.tos)/\(ip.ttl), length: \(inner.count), " +
                   "packet: \(lispFormatPacket(inner))")
        let b = inner.startIndex
        let ihl = Int(inner[b] & 0x0F) * 4
        // IGMP (proto 2) from an overlay app (gaapchat): parse it to drive soft-state
        // (*,G) group membership registration — do NOT encap it to the network.
        if inner[b + 9] == LISP.ipProtoIGMP {
            // Log a parsed summary in the ITR log: report/leave, group, and the app-name the
            // joiner appended after the 8-byte IGMP message.
            if inner.count >= b + ihl + 8 {
                let type = inner[b + ihl]
                let gv4 = (UInt32(inner[b+ihl+4]) << 24) | (UInt32(inner[b+ihl+5]) << 16)
                        | (UInt32(inner[b+ihl+6]) << 8) | UInt32(inner[b+ihl+7])
                var g = LispAddress(v4: gv4); g.instanceID = iid; g.maskLen = 32
                let kind: String
                switch type {
                case LISP.igmpV2Report, LISP.igmpV1Report: kind = "Report"
                case LISP.igmpV2Leave:                     kind = "Leave"
                default: kind = String(format: "type-0x%02x", type)
                }
                var app = "unknown"
                if inner.count > b + ihl + 8,
                   let s = String(data: inner.subdata(in: (b+ihl+8)..<inner.endIndex),
                                  encoding: .utf8), !s.isEmpty { app = s }
                // [iid]-prefix the group so the log colorizer greens it as an EID.
                log.dprint(.itr, "IGMPv2 \(kind) for group [\(iid)]\(g.addressString) from app \"\(app)\"")
            }
            handleOverlayIGMP(inner, ihl: ihl)
            return
        }
        let dstV4 = (UInt32(inner[b+16]) << 24) | (UInt32(inner[b+17]) << 16)
                  | (UInt32(inner[b+18]) << 8) | UInt32(inner[b+19])
        var dest = LispAddress(v4: dstV4)
        dest.instanceID = iid
        dest.maskLen = 32
        encapAndSend(inner: inner, destEID: dest)     // encap: logs "Encap …" + bumps counters
    }

    // Overlay-app readiness heartbeat. While the xTR is running (foreground OR the ~30s
    // background grace — i.e. whenever it can actually forward) we stamp the current time
    // into an App-Group file every second. Overlay apps (PING, gaapchat) read its age to
    // show "LISP app ready" without any live loopback round-trip (which flaps under rapid
    // app-switching). Cleared on disable/suspend so overlay apps flip to "not running"
    // promptly. App-Group FILE, not UserDefaults — the reliable cross-process channel.
    private var heartbeatURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.net.lispers.xtr")?
            .appendingPathComponent("xtr-heartbeat")
    }
    private func writeHeartbeat() {
        guard let url = heartbeatURL else { return }
        try? String(Date().timeIntervalSince1970).write(to: url, atomically: true, encoding: .utf8)
    }
    private func clearHeartbeat() {
        guard let url = heartbeatURL else { return }
        try? FileManager.default.removeItem(at: url)
    }

    // An ICMP echo-reply that isn't for one of our own (Direct-mode) pings belongs to
    // the external PING client app. Forward the inner reply IP packet to it over
    // loopback (127.0.0.1:pingReplyPort); the PING app matches it by ICMP id/seq.
    func forwardReplyToPingApp(_ innerReply: Data, from src: LispAddress, iid: UInt32 = 0) {
        if pingReplyFD < 0 { pingReplyFD = socket(AF_INET, SOCK_DGRAM, 0) }
        guard pingReplyFD >= 0 else { return }
        // Deliver to BOTH overlay ping clients: the standalone PING app (41343) and the
        // in-app Ping tab when the app is mirroring the extension (41344). Each ignores
        // replies whose ICMP identifier isn't one of its own, so the duplicate is harmless.
        for port in [LISP.pingReplyPort, LISP.pingReplyPortApp] {
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr.s_addr = UInt32(0x7f00_0001).bigEndian     // 127.0.0.1
            _ = innerReply.withUnsafeBytes { raw in
                withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        sendto(pingReplyFD, raw.baseAddress, raw.count, 0, sa,
                               socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
        }
        // Egress line for the decap'd reply, in the ETR scope so it sits right after the
        // "Decap …" line in lisp-etr.log — the symmetric counterpart of the ingress
        // "Receive utun, inner EIDs: …": confirms we handed the packet to the external app.
        let ip = innerIPInfo(innerReply)
        log.dprint(.etr, "Send utun, inner EIDs: [\(iid)]\(ip.src) -> [\(iid)]\(ip.dst), " +
                   "length: \(innerReply.count), delivered to external app")
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
