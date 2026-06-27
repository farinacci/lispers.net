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
                .onChange(of: scenePhase) { _, phase in
                    // iOS reclaims our sockets while suspended; tear the network down
                    // before that happens and rebuild it on return. Re-sending on the
                    // suspended sockets (the old behavior) crashed on foreground.
                    switch phase {
                    case .background: engine.suspendNetwork()
                    case .active:     engine.resumeNetwork()
                    default:          break
                    }
                }
        }
    }
}
