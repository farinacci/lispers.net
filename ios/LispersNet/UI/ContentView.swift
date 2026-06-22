//
// ContentView.swift
//
// Tab shell + status header. The lispers.net palette: green for EIDs and
// good news, red for RLOCs and trouble, blue for names.
//

import SwiftUI

extension Color {
    static let lispGreen = Color(red: 0.16, green: 0.55, blue: 0.16)
    static let lispDarkGreen = Color(red: 0.0, green: 0.35, blue: 0.0)
    static let lispRed = Color(red: 0.78, green: 0.12, blue: 0.12)
    static let lispBlue = Color(red: 0.20, green: 0.40, blue: 0.95)
    // Slightly darker than the default row separator (but not heavy).
    static let lispSeparator = Color.gray.opacity(0.55)
}

// Tracks whether the software keyboard is on screen so the tab bar can hide
// while typing (it otherwise overlaps the keyboard / its accessory).
final class KeyboardObserver: ObservableObject {
    @Published var isVisible = false
    init() {
        let nc = NotificationCenter.default
        nc.addObserver(forName: UIResponder.keyboardWillShowNotification, object: nil,
                       queue: .main) { [weak self] _ in self?.isVisible = true }
        nc.addObserver(forName: UIResponder.keyboardWillHideNotification, object: nil,
                       queue: .main) { [weak self] _ in self?.isVisible = false }
    }
}

struct ContentView: View {
    @EnvironmentObject var engine: LispEngine
    @EnvironmentObject var config: LispConfig
    @StateObject private var keyboard = KeyboardObserver()
    @Environment(\.verticalSizeClass) private var vSizeClass

    // App version string — bump on request.
    static let version = "0.3-12"

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

    // Hide the tab bar while the keyboard is up (so it doesn't float over the
    // input) and in landscape (compact height) to free vertical space; it
    // reappears in portrait. The modifier must sit on each tab's content.
    private var tabBarVisibility: Visibility {
        (keyboard.isVisible || vSizeClass == .compact) ? .hidden : .visible
    }

    private var tabs: some View {
        TabView {
            MapCacheView()
                .toolbar(tabBarVisibility, for: .tabBar)
                .tabItem { Label("Map-Cache", systemImage: "tablecells") }
            LogsView()
                .toolbar(tabBarVisibility, for: .tabBar)
                .tabItem { Label("Logs", systemImage: "doc.plaintext") }
            PingView()
                .toolbar(tabBarVisibility, for: .tabBar)
                .tabItem { Label("Ping", systemImage: "dot.radiowaves.left.and.right") }
            LigView()
                .toolbar(tabBarVisibility, for: .tabBar)
                .tabItem { Label("LIG", systemImage: "magnifyingglass") }
            ConfigView()
                .toolbar(tabBarVisibility, for: .tabBar)
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
    @ObservedObject var netName = NetworkName.shared

    // "<addr> (en0 -> MyWiFi)" / "<addr> (pdp_ip0 -> Carrier)" — the network name
    // is appended when iOS lets us read it (Wi-Fi needs the wifi-info entitlement +
    // location permission; cellular carrier is usually unavailable on modern iOS).
    private func rlocLabel(_ rloc: DiscoveredRLOC) -> String {
        let iface = rloc.interfaceName
        var suffix = ""
        if iface == "en0", let s = netName.wifiSSID, !s.isEmpty {
            suffix = " \u{2192} \(s)"
        } else if iface.hasPrefix("pdp_ip"), let c = netName.cellularName, !c.isEmpty {
            suffix = " \u{2192} \(c)"
        }
        return "\(rloc.address.addressString) (\(iface)\(suffix))"
    }

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
                    Text(engine.rloc.map { rlocLabel($0) } ?? "none")
                        .foregroundStyle(Color.lispRed)
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
