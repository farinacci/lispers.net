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
                    if phase == .active && engine.running && config.natTraversalEnabled {
                        // NAT bindings likely expired while suspended.
                        engine.sendInfoRequests()
                        engine.sendMapRegisters()
                    }
                }
        }
    }
}
