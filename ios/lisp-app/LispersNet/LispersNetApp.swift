//
// LispersNetApp.swift
//
// lispers.net iOS xTR — app entry point. The engine is created once and
// shared via the environment; re-foregrounding refreshes NAT state since
// iOS suspends our sockets in the background (see PLAN.md bottleneck #2).
//

import SwiftUI

@main
struct LispersNetApp: App {
    @StateObject private var config: LispConfig
    @StateObject private var engine: LispEngine
    @StateObject private var hosts = HostsFile()
    @StateObject private var tunnel = TunnelManager()
    @Environment(\.scenePhase) private var scenePhase

    init() {
        let cfg = LispConfig()
        _config = StateObject(wrappedValue: cfg)
        _engine = StateObject(wrappedValue: LispEngine(config: cfg))
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(config)
                .environmentObject(engine)
                .environmentObject(hosts)
                .environmentObject(engine.pingService)
                .environmentObject(engine.ligService)
                .environmentObject(tunnel)
                .onChange(of: scenePhase) { _, phase in
                    // iOS reclaims our sockets while suspended; tear the network down
                    // before that happens and rebuild it on return. Re-sending on the
                    // suspended sockets (the old behavior) crashed on foreground.
                    // Also publish the configured hostname into the App Group so the PING
                    // app can show it (written on .background too, to catch a fresh edit
                    // right before the user switches to PING).
                    // Publish the overlay identity into the App Group so overlay apps
                    // (PING, gaapchat) can read it — EID/IID here (not just in the tunnel
                    // start) so it's available on the SIMULATOR, where the tunnel can't run.
                    let group = UserDefaults(suiteName: "group.net.lispers.xtr")
                    let eid = config.eidString.isEmpty ? "240.0.0.1" : config.eidString
                    func publishIdentity() {
                        group?.set(eid, forKey: "tunnelEID")
                        group?.set(config.instanceID, forKey: "tunnelIID")
                        group?.set(engine.xtrName, forKey: "tunnelHostname")
                    }
                    switch phase {
                    case .background:
                        // On a device iOS will suspend us and reclaim our sockets. Rather
                        // than tear down immediately, hold a background-task assertion and
                        // keep forwarding for a foreground overlay app (PING/gaapchat) for
                        // the ~30s window iOS grants — the 0.8 interim before Option B. When
                        // the assertion expires, suspendNetwork runs cleanly. The SIMULATOR
                        // doesn't suspend background apps, so we just keep it up there.
                        #if !targetEnvironment(simulator)
                        engine.beginBackgroundGrace()
                        #endif
                        publishIdentity()
                    case .active:
                        #if !targetEnvironment(simulator)
                        engine.endBackgroundGrace()   // returned within the window
                        #endif
                        engine.resumeNetwork()        // no-op if the grace didn't expire
                        publishIdentity()
                        // Reconnect the overlay tunnel on foreground ONLY if the user opted
                        // in (ensureUp no-ops otherwise). We never auto-prompt here — the
                        // one-time ask is in the UI when LISP starts. The xTR runs with or
                        // without the tunnel; the tunnel is only needed for overlay apps.
                        Task { await tunnel.ensureUp(eid: eid, instanceID: config.instanceID) }
                    default:          break
                    }
                }
        }
    }
}
