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
        // Derive visibility from the keyboard's END FRAME rather than pairing
        // willShow/willHide events: interactive dismissal (scrollDismissesKeyboard)
        // and rapid focus changes — as happens after a lig — can drop a "hide",
        // which left isVisible stuck true and the tab bar permanently hidden.
        nc.addObserver(forName: UIResponder.keyboardWillChangeFrameNotification,
                       object: nil, queue: .main) { [weak self] note in
            // Ignore frame changes posted while we're not the active app: iOS emits
            // spurious keyboard-frame notifications during the background/foreground
            // transition that would otherwise latch isVisible=true and leave the tab
            // bar hidden after returning from the lock screen.
            guard UIApplication.shared.applicationState == .active else { return }
            guard let end = (note.userInfo?[UIResponder.keyboardFrameEndUserInfoKey]
                                as? NSValue)?.cgRectValue else { return }
            let screenH = UIScreen.main.bounds.height
            self?.isVisible = end.minY < screenH - 1      // keyboard on screen
        }
        // Belt-and-suspenders: an explicit hide always clears the flag.
        nc.addObserver(forName: UIResponder.keyboardWillHideNotification, object: nil,
                       queue: .main) { [weak self] _ in self?.isVisible = false }
        // Returning to foreground with the keyboard down must always restore the tab
        // bar — clear any stale "visible" a dropped hide or transition artifact left.
        nc.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil,
                       queue: .main) { [weak self] _ in self?.isVisible = false }
    }
}

struct ContentView: View {
    @EnvironmentObject var engine: LispEngine
    @EnvironmentObject var config: LispConfig
    @StateObject private var keyboard = KeyboardObserver()
    @Environment(\.verticalSizeClass) private var vSizeClass

    // App version string — bump on request.
    static let version = "0.4-70"

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
    // Snapshot time the uptimes are measured against; refreshed each time this
    // view appears (tab switch) so the values update on (re)entry, not live.
    @State private var asOf = Date()

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
                Text(engine.running ? "LISP is active" : "LISP is inactive")
                    .font(.headline)
                // LISP uptime — since the Enable LISP toggle was last turned on.
                // Snapshotted on appear (asOf); it refreshes when you leave and
                // return to this tab, not every second.
                if engine.running, let s = engine.lispStart {
                    Text(formatHMS(s, asOf: asOf))
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if engine.behindNAT {
                    Text("behind NAT")
                        .font(.caption.bold())
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.orange.opacity(0.25))
                        .clipShape(Capsule())
                }
            }
            // LISP app uptime — since the app process launched. Only shown when
            // it differs from the LISP uptime (i.e. LISP was re-enabled after
            // launch); if LISP came up with the app the two are equal, so the
            // separate line would be redundant. Also snapshotted on appear.
            if engine.running, let s = engine.lispStart,
               s.timeIntervalSince(engine.appStart) >= 2 {
                (Text("LISP app uptime ").foregroundStyle(.secondary)
                 + Text(formatHMS(engine.appStart, asOf: asOf)))
                    .font(.caption.monospaced())
            }
            if engine.running {
                Group {
                    Text("Hostname ").foregroundStyle(.secondary) +
                    Text(engine.xtrName).foregroundStyle(Color.lispBlue).bold()
                    Text("EID ").foregroundStyle(.secondary) +
                    Text(config.eidString.isEmpty ? "unconfigured" : config.eidString)
                        .foregroundStyle(Color.lispGreen).bold()
                    Text("RLOC ").foregroundStyle(.secondary) +
                    Text(engine.rloc.map { rlocLabel($0) } ?? "none")
                        .foregroundStyle(Color.lispRed)
                    if let t = engine.translatedRLOC {
                        // The RTR-reported translated DATA port (engine.advertisedPort)
                        // — the same value we put in @tp and the RTRs use to forward.
                        Text("translated RLOC:port ").foregroundStyle(.secondary) +
                        Text("\(t.addressString):\(String(engine.advertisedPort))")
                            .foregroundStyle(Color.lispRed)
                    }
                    Text("registers sent ").foregroundStyle(.secondary) +
                    Text(String(engine.registrationsSent)) +
                    Text(", groups joined ").foregroundStyle(.secondary) +
                    Text(String(config.joinedGroups.count))
                }
                .font(.caption.monospaced())
            }
        }
        .padding(.vertical, 4)
        .onAppear { asOf = Date() }
    }
}
