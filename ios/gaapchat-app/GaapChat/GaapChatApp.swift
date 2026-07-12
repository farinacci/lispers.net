//
// GaapChatApp.swift  (gaapchat)
//
// gaapchat — decentralized multicast group chat that runs over the lispers.net overlay.
// It relies on the LISP app (its always-on xTR) being installed + enabled: gaapchat joins
// a group via IGMP over the tunnel and sends/receives chat as overlay multicast.
//

import SwiftUI

@main
struct GaapChatApp: App {
    @StateObject private var client = ChatClient()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(client)
                .onChange(of: scenePhase) { _, phase in
                    switch phase {
                    case .active:     client.onForeground()
                    case .background: client.onBackground()   // one IGMP refresh before suspend
                    default:          break
                    }
                }
        }
    }
}
