//
// PingAppApp.swift  (PING app)
//
// PING — a ping client that runs ONLY over the lispers.net overlay tunnel. It relies
// on the LISP app (its packet-tunnel + xTR) being installed and enabled; PING just
// injects echoes into the tunnel and shows the replies the LISP app forwards back.
//

import SwiftUI

@main
struct PingAppApp: App {
    @StateObject private var client = PingClient()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(client)
                .onChange(of: scenePhase) { _, phase in
                    if phase == .active { client.refreshTunnel() }
                    else { client.stop() }
                }
        }
    }
}
