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
    @EnvironmentObject var tunnel: TunnelManager
    @EnvironmentObject var ping: PingService
    @StateObject private var keyboard = KeyboardObserver()
    @Environment(\.verticalSizeClass) private var vSizeClass
    @State private var selectedTab = Tab.mapCache

    private enum Tab: Hashable { case mapCache, logs, ping, lig, ltr, xtr }

    // App version string — canonical value lives in Core (AppInfo.version, bump there).
    static let version = AppInfo.version

    var body: some View {
        VStack(spacing: 0) {
            tabs
            Text("LISP xTR app version \(Self.version)")
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
        // Opened via the lispxtr:// scheme (the PING / gaapchat "Open" button) — land
        // on the xTR tab so the user sees the xTR status straight away.
        .onOpenURL { url in
            if url.scheme == "lispxtr" { selectedTab = .xtr }
        }
        // The tabs are an opacity-toggled ZStack (all always in the hierarchy), so PingView's
        // onAppear/onDisappear never fire on a tab switch. Drive the ping's tab-leave grace
        // (keep pinging 10s so the map-cache/Logs counters can be watched, then stop) off the
        // actual tab selection instead.
        .onChange(of: selectedTab) { old, new in
            if new == .ping { ping.cancelGrace() }
            else if old == .ping { ping.keepAliveBriefly(10) }
        }
    }

    // Hide the tab bar while the keyboard is up (so it doesn't float over the
    // input) and in landscape (compact height) to free vertical space; it
    // reappears in portrait. The modifier must sit on each tab's content.
    private var tabBarVisibility: Visibility {
        (keyboard.isVisible || vSizeClass == .compact) ? .hidden : .visible
    }

    // The six tab views, kept alive in a ZStack (only the selected one visible) so tab
    // state survives switching — a custom bar is used instead of the system tab bar,
    // which caps at 5 items on iPhone and collapses the rest into a "More" tab.
    private var tabs: some View {
        VStack(spacing: 0) {
            ZStack {
                MapCacheView().opacity(selectedTab == .mapCache ? 1 : 0)
                    .allowsHitTesting(selectedTab == .mapCache)
                LogsView().opacity(selectedTab == .logs ? 1 : 0)
                    .allowsHitTesting(selectedTab == .logs)
                PingView().opacity(selectedTab == .ping ? 1 : 0)
                    .allowsHitTesting(selectedTab == .ping)
                LigView().opacity(selectedTab == .lig ? 1 : 0)
                    .allowsHitTesting(selectedTab == .lig)
                LTRView().opacity(selectedTab == .ltr ? 1 : 0)
                    .allowsHitTesting(selectedTab == .ltr)
                ConfigView().opacity(selectedTab == .xtr ? 1 : 0)
                    .allowsHitTesting(selectedTab == .xtr)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            if tabBarVisibility == .visible {
                HStack(spacing: 0) {
                    tabButton(.mapCache, "Map-Cache", "tablecells")
                    tabButton(.logs, "Logs", "doc.plaintext")
                    tabButton(.ping, "Ping", "dot.radiowaves.left.and.right")
                    tabButton(.lig, "LIG", "magnifyingglass")
                    tabButton(.ltr, "LTR", "point.3.filled.connected.trianglepath.dotted")
                    tabButton(.xtr, "xTR", "gearshape")
                }
                .padding(.vertical, 8).padding(.horizontal, 6)
                .background(.regularMaterial, in: Capsule())
                .overlay(Capsule().stroke(Color(.separator).opacity(0.5), lineWidth: 0.5))
                .padding(.horizontal, 10)
                .padding(.top, 6)
                .padding(.bottom, 12)              // raise the pill above the version line
            }
        }
        .onAppear {
            // Resume a persisted-enabled xTR on launch. Who runs it (app vs the
            // always-on extension) depends on the Overlay App VPN switch.
            XTRCoordinator.reconcile(engine: engine, config: config, tunnel: tunnel)
        }
    }

    // One custom tab-bar item — narrow enough that all six fit without a "More" tab.
    private func tabButton(_ tab: Tab, _ title: String, _ icon: String) -> some View {
        Button { selectedTab = tab } label: {
            VStack(spacing: 2) {
                Image(systemName: icon).font(.system(size: 17))
                Text(title).font(.system(size: 10)).lineLimit(1).minimumScaleFactor(0.7)
            }
            .frame(maxWidth: .infinity)
            .foregroundStyle(selectedTab == tab ? Color.lispGreen : Color.primary.opacity(0.7))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
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
                Text(engine.running ? "LISP is active" : "LISP is inactive")
                    .font(.headline)
                // LISP uptime — since the Enable LISP toggle was last turned on.
                // Minute-granularity, ticks once a minute ("< 1m", "5m", "1h3m",
                // "1d3h").
                if engine.running, let s = engine.lispStart {
                    TimelineView(.periodic(from: .now, by: 60)) { ctx in
                        Text(formatUptimeMinutes(s, asOf: ctx.date))
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
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
            // separate line would be redundant. Ticks once a minute.
            if engine.running, let s = engine.lispStart,
               s.timeIntervalSince(engine.appStart) >= 2 {
                TimelineView(.periodic(from: .now, by: 60)) { ctx in
                    (Text("LISP app uptime ").foregroundStyle(.secondary)
                     + Text(formatUptimeMinutes(engine.appStart, asOf: ctx.date)))
                        .font(.caption.monospaced())
                }
            }
            if engine.running {
                Group {
                    Text("Hostname ").foregroundStyle(.secondary) +
                    Text(engine.xtrName).foregroundStyle(Color.lispBlue).bold()
                    Text("EID ").foregroundStyle(.secondary) +
                    Text(config.eidString.isEmpty ? "unconfigured" : config.eidString)
                        .foregroundStyle(Color.lispGreen).bold()
                    // Keep "<addr> (iface → SSID)" on ONE line, shrinking the font if the
                    // network name makes it too long to fit.
                    (Text("RLOC ").foregroundStyle(.secondary) +
                     Text(engine.rloc.map { rlocLabel($0) } ?? "none")
                        .foregroundStyle(Color.lispRed))
                        .lineLimit(1)
                        .minimumScaleFactor(0.5)
                    if let t = engine.translatedRLOC {
                        // The RTR-reported translated DATA port (engine.advertisedPort)
                        // — the same value we put in @tp and the RTRs use to forward.
                        Text("translated RLOC:port ").foregroundStyle(.secondary) +
                        Text("\(t.addressString):\(String(engine.advertisedPort))")
                            .foregroundStyle(Color.lispRed)
                    }
                    // Multi-homing: the other interface(s)' RLOC + translated
                    // RLOC:port (each interface is registered as its own RLOC).
                    if config.multihomingEnabled {
                        ForEach(engine.mhInterfaces.filter {
                            $0.interfaceName != engine.rloc?.interfaceName
                        }, id: \.interfaceName) { iface in
                            (Text("RLOC ").foregroundStyle(.secondary) +
                             Text(rlocLabel(iface)).foregroundStyle(Color.lispRed))
                                .lineLimit(1)
                                .minimumScaleFactor(0.5)
                            if let tr = engine.ifaceTranslated[iface.interfaceName] {
                                Text("translated RLOC:port ").foregroundStyle(.secondary) +
                                Text("\(tr.rloc.addressString):\(String(tr.port))")
                                    .foregroundStyle(Color.lispRed)
                            }
                        }
                    }
                    Text("registers sent ").foregroundStyle(.secondary) +
                    Text(String(engine.registrationsSent)) +
                    Text(", groups joined ").foregroundStyle(.secondary) +
                    Text(String(config.joinedGroups.count))

                    // The LispTunnel extension is a separate process that iOS does NOT reload
                    // when the app is reinstalled — it keeps running the OLD binary until the
                    // VPN is toggled (or LISP is disabled/re-enabled). That made freshly-built
                    // fixes look like they "didn't work". Surface it instead of guessing.
                    if let ev = engine.engineVersion, ev != AppInfo.version {
                        (Text("⚠︎ xTR running ").foregroundStyle(Color.lispRed) +
                         Text(ev).foregroundStyle(Color.lispRed) +
                         Text(", app is ").foregroundStyle(.secondary) +
                         Text(AppInfo.version).foregroundStyle(.secondary) +
                         Text(" — toggle VPN to reload").foregroundStyle(Color.lispRed))
                    }
                }
                .font(.caption.monospaced())
            }
        }
        .padding(.vertical, 4)
    }
}
