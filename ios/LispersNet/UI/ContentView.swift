//
// ContentView.swift
//
// Tab shell + status header. The lispers.net palette: green for EIDs and
// good news, red for RLOCs and trouble, blue for names.
//

import SwiftUI

extension Color {
    static let lispGreen = Color(red: 0.16, green: 0.55, blue: 0.16)
    static let lispRed = Color(red: 0.78, green: 0.12, blue: 0.12)
    static let lispBlue = Color(red: 0.20, green: 0.40, blue: 0.95)
}

struct ContentView: View {
    @EnvironmentObject var engine: LispEngine
    @EnvironmentObject var config: LispConfig

    // App version string — bump on request.
    static let version = "0.0"

    var body: some View {
        VStack(spacing: 0) {
            tabs
            Text("version \(Self.version)")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .padding(.top, 2)
                .padding(.bottom, 34)
                .frame(maxWidth: .infinity)
                // Form/List screens (Ping, LIG, xTR) bleed their grouped-gray
                // background into the bottom safe area; an opaque strip keeps the
                // version line on the same clean surface as Map-Cache and Logs.
                .background(Color(.systemBackground))
        }
        .ignoresSafeArea(.container, edges: .bottom)
    }

    private var tabs: some View {
        TabView {
            MapCacheView()
                .tabItem { Label("Map-Cache", systemImage: "tablecells") }
            LogsView()
                .tabItem { Label("Logs", systemImage: "doc.plaintext") }
            PingView()
                .tabItem { Label("Ping", systemImage: "dot.radiowaves.left.and.right") }
            LigView()
                .tabItem { Label("LIG", systemImage: "magnifyingglass") }
            ConfigView()
                .tabItem { Label("xTR", systemImage: "gearshape") }
        }
        .onAppear {
            // Resume a persisted-enabled xTR on launch so the toggle state and
            // the engine never disagree.
            if config.lispEnabled && !engine.running { engine.enable() }
        }
    }
}

struct StatusHeader: View {
    @EnvironmentObject var engine: LispEngine
    @EnvironmentObject var config: LispConfig

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle()
                    .fill(engine.running ? Color.lispGreen : Color.gray)
                    .frame(width: 10, height: 10)
                Text(engine.running ? "LISP enabled" : "LISP disabled")
                    .font(.headline)
                Spacer()
                if engine.behindNAT {
                    Text("behind NAT")
                        .font(.caption.bold())
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.orange.opacity(0.25))
                        .clipShape(Capsule())
                }
            }
            if engine.running {
                Group {
                    Text("EID ").foregroundStyle(.secondary) +
                    Text(config.eidString.isEmpty ? "unconfigured" : config.eidString)
                        .foregroundStyle(Color.lispGreen).bold()
                    Text("RLOC ").foregroundStyle(.secondary) +
                    Text(engine.rloc.map {
                        "\($0.address.addressString) (\($0.interfaceName))"
                    } ?? "none").foregroundStyle(Color.lispRed)
                    if let t = engine.translatedRLOC {
                        Text("translated RLOC:port ").foregroundStyle(.secondary) +
                        Text("\(t.addressString):\(String(engine.translatedPort))")
                            .foregroundStyle(Color.lispRed)
                    }
                    Text("registers sent ").foregroundStyle(.secondary) +
                    Text(String(engine.registrationsSent))
                }
                .font(.caption.monospaced())
            }
        }
        .padding(.vertical, 4)
    }
}
