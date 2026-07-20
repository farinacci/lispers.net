//
// ContentView.swift  (PING app)
//
// Mirrors the LISP app's Ping tab behavior: the live "Pinging…" section (with the
// per-seq "waiting X.Xs" rows + Stop) and the Results section float to the top while a
// ping runs and drop to the bottom when idle; scroll snaps to the active section on
// start and back to the top on stop. Adds PING's own Status + History sections.
//

import SwiftUI
import UIKit

extension Color {
    static let lispGreen = Color(red: 0.16, green: 0.55, blue: 0.16)
    static let lispRed = Color(red: 0.78, green: 0.12, blue: 0.12)
    static let lispBlue = Color(red: 0.20, green: 0.40, blue: 0.95)
    static let lispSeparator = Color.gray.opacity(0.55)
}

// Reverse-DNS cache for RLOCs: hostname(for:) returns a cached name or nil while it looks
// one up off the main thread; the async result republishes so the row redraws with the name.
// "" is stored for a no-PTR address so we don't re-query it every redraw.
@MainActor
final class RDNSCache: ObservableObject {
    @Published private(set) var names: [String: String] = [:]
    private var inflight: Set<String> = []

    func hostname(for addr: String) -> String? {
        if let n = names[addr] { return n.isEmpty ? nil : n }
        guard !inflight.contains(addr) else { return nil }
        inflight.insert(addr)
        DispatchQueue.global().async {
            let host = LispWire.reverseDNS(addr)
            DispatchQueue.main.async {
                self.inflight.remove(addr)
                self.names[addr] = host ?? ""       // cache the miss too (empty = none)
            }
        }
        return nil
    }
}

struct ContentView: View {
    @EnvironmentObject var client: PingClient
    @StateObject private var hosts = PingHosts()
    @StateObject private var rdns = RDNSCache()
    @State private var target = ""
    @State private var showAllResults = false
    @State private var showAllHosts = false
    @FocusState private var focused: Bool
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.openURL) private var openURL
    static let version = "0.3"
    private static let resultsCollapsedCount = 10
    private static let hostsCollapsedCount = 5

    private var trimmed: String { target.trimmingCharacters(in: .whitespaces) }

    // Resolve the typed target to a dotted address, delivered async (DNS can block):
    //   • a literal IPv4  → an EID (240/4, overlay) or an RLOC (native underlay ping)
    //   • a configured hostname (lisp-hosts) → its EID
    //   • otherwise a DNS name → its first A record (usually an RLOC)
    // client.start() then routes overlay-vs-native by the address prefix.
    private func resolve(_ input: String, completion: @escaping (String?) -> Void) {
        let s = input.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty else { completion(nil); return }
        if LispWire.parseIPv4(s) != nil { completion(s); return }
        if let a = hosts.entries.first(where: { $0.name.caseInsensitiveCompare(s) == .orderedSame })?.address {
            completion(a); return
        }
        DispatchQueue.global().async {
            let addr = LispWire.resolveDNS(s)
            DispatchQueue.main.async { completion(addr.map(LispWire.dotted)) }
        }
    }
    private func startPing(_ input: String) {
        focused = false
        resolve(input) { addr in
            guard let addr = addr else { return }
            target = addr
            client.start(addr)
        }
    }

    // Color an address by kind: an overlay EID (240/4 or a 224/4 group) is green, a routable
    // RLOC is red. Anything that doesn't parse as IPv4 stays neutral.
    private func addrColor(_ s: String) -> Color {
        guard let v = LispWire.parseIPv4(s) else { return .primary }
        let hi = v & 0xF000_0000
        return (hi == 0xF000_0000 || hi == 0xE000_0000) ? .lispGreen : .lispRed
    }
    private func isRLOC(_ s: String) -> Bool {
        guard let v = LispWire.parseIPv4(s) else { return false }
        let hi = v & 0xF000_0000
        return !(hi == 0xF000_0000 || hi == 0xE000_0000)   // not an overlay EID/group
    }
    // The name shown above an address: an RLOC's reverse-DNS name, or an EID's configured
    // hostname reverse-looked-up in the Hostname Configuration (lisp-hosts). nil if none
    // (or, for an RLOC, while the DNS lookup is still in flight).
    private func displayName(for addr: String) -> String? {
        if isRLOC(addr) { return rdns.hostname(for: addr) }
        guard let v = LispWire.parseIPv4(addr) else { return nil }
        return hosts.entries.first { LispWire.parseIPv4($0.address) == v }?.name
    }

    // Launch the LISP app via its custom URL scheme (registered in its Info.plist) so the
    // user can bring the xTR to the foreground straight from the "open it" hint.
    private func openLispApp() {
        // Concrete host ("open") — a bare "lispxtr://" (empty authority) doesn't reliably
        // launch on all iOS versions. The LISP app matches on the scheme, ignoring the host.
        guard let url = URL(string: "lispxtr://open") else { return }
        openURL(url) { accepted in
            // Fallback to the low-level opener if the SwiftUI action declines (rare).
            if !accepted { UIApplication.shared.open(url) }
        }
    }

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
            List {
                // Zero-height true-top anchor (scroll target on stop).
                Section {
                    Color.clear.frame(height: 0).id("list-top")
                        .listRowInsets(EdgeInsets()).listRowSeparator(.hidden)
                        .listRowBackground(Color.clear)
                }.listSectionSpacing(0)

                // While running, float the live section + Results to the very top.
                if client.running {
                    activePingSection(floated: true)
                    resultsSection
                }

                statusSection

                // Ping a target (input) — an overlay EID, an RLOC, or a DNS name.
                Section {
                    HStack {
                        TextField("EID, RLOC, or DNS name", text: $target)
                            .font(.body.monospaced())
                            .keyboardType(.asciiCapable)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .focused($focused)
                        Button("Ping") { startPing(target) }
                            .buttonStyle(.borderless)
                            .disabled(trimmed.isEmpty)
                    }
                } header: { centered("Ping an EID or RLOC") }

                // Interval — its own section.
                Section {
                    Picker("Interval", selection: Binding(get: { client.interval },
                                                          set: { client.setInterval($0) })) {
                        Text("1s").tag(1.0); Text("500ms").tag(0.5)
                        Text("250ms").tag(0.25); Text("100ms").tag(0.1)
                    }
                    .pickerStyle(.segmented)
                }

                // Hostnames — show the first few; a pull-down reveals the rest.
                Section {
                    let allHosts = hosts.entries
                    let shownHosts = showAllHosts ? allHosts : Array(allHosts.prefix(Self.hostsCollapsedCount))
                    ForEach(shownHosts) { h in
                        Button { startPing(h.address) } label: {
                            HStack {
                                Text(h.name).bold()
                                Text(h.address).font(.callout.monospaced()).foregroundStyle(Color.lispGreen)
                                Spacer()
                                let pinging = client.running && client.currentTarget == h.address
                                Image(systemName: "dot.radiowaves.left.and.right")
                                    .foregroundStyle(pinging ? Color.lispGreen : .secondary)
                                    .symbolEffect(.variableColor, isActive: pinging)
                            }
                        }
                    }
                    if allHosts.count > Self.hostsCollapsedCount {
                        Button { withAnimation { showAllHosts.toggle() } } label: {
                            HStack {
                                Spacer()
                                Text(showAllHosts ? "Show first \(Self.hostsCollapsedCount)"
                                                  : "Show all \(allHosts.count)").font(.caption)
                                Image(systemName: showAllHosts ? "chevron.up" : "chevron.down").font(.caption.bold())
                                Spacer()
                            }
                        }
                        .buttonStyle(.borderless).foregroundStyle(Color.lispBlue)
                    }
                    // Read-only here — the Hostname Configuration is owned by the LISP xTR app.
                    Button { openLispApp() } label: {
                        HStack {
                            Spacer()
                            Text("Edit hostnames in the LISP xTR app")
                                .font(.caption).foregroundStyle(.secondary)
                            Image(systemName: "arrow.up.forward.app").font(.caption)
                            Spacer()
                        }
                    }
                } header: { centered("Hostname Configuration") }

                // Idle: live section + Results rest at the end.
                if !client.running {
                    activePingSection(floated: false)
                    resultsSection
                }

                historySection
            }
            .listRowSeparatorTint(.lispSeparator)
            .contentMargins(.top, -60, for: .scrollContent)     // pull the first section up close to the title
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle("PING")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if client.running {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Stop") { client.stop() }.foregroundStyle(Color.lispRed)
                    }
                }
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active {
                    client.enteredForeground()      // resume the send loop
                    hosts.reload()                  // pick up LISP xTR Hostname Configuration edits
                }
                else { client.keepAliveBriefly(25) }     // keep pinging ~25s (within iOS's ~30s) after leaving
            }
            .onChange(of: client.currentTarget) { _, t in
                if t != nil {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                        withAnimation { proxy.scrollTo("activePing", anchor: .top) }
                    }
                } else {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
                        proxy.scrollTo("list-top", anchor: .top)
                    }
                }
            }
            .animation(nil, value: client.running)
            .safeAreaInset(edge: .bottom) {
                // Opaque strip so scrolled-up content never bleeds over the version line.
                Text("LISP PING app version \(Self.version)").font(.caption2).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity).padding(.top, 28).padding(.bottom, 6)
                    .background(Color(.systemGroupedBackground))
            }
            }
        }
    }

    // MARK: sections

    private var statusSection: some View {
        Section {
            // Both status dots on ONE line: LISP on the left, Overlay path on the right.
            HStack(spacing: 8) {
                Circle().fill(client.lispReady ? Color.lispGreen : Color.orange)
                    .frame(width: 10, height: 10)
                (Text("LISP is ") + (client.lispReady
                    ? Text("active").foregroundColor(.lispGreen)
                    : Text("not running").foregroundColor(.orange)))
                    .font(.subheadline)
                Spacer()
                Circle().fill(client.tunnelUp ? Color.lispGreen : Color.gray)
                    .frame(width: 10, height: 10)
                // Force-press "Overlay path" to reveal which interface carries the overlay:
                // a real utunNN on device, or loopback straight to the LISP app (sim / no NE).
                (Text("Overlay path ") + (client.tunnelUp
                    ? Text("active").foregroundColor(.lispGreen)
                    : Text("down").foregroundColor(.lispRed)))
                    .font(.subheadline)
                    .contextMenu {
                        if client.tunnelUp {
                            Label(client.utunName == "loopback"
                                  ? "Overlay via loopback"
                                  : "Overlay via \(client.utunName)",
                                  systemImage: "point.3.connected.trianglepath.dotted")
                        } else {
                            Label("Overlay path is down", systemImage: "xmark.circle")
                        }
                    }
            }
            // Open the LISP xTR app when it isn't running — centered, not a stray left row.
            if !client.lispReady {
                HStack {
                    Spacer()
                    Button("Open LISP xTR app") { openLispApp() }
                        .buttonStyle(.borderedProminent).tint(.lispGreen).controlSize(.small)
                    Spacer()
                }
            }
            // Hostname + Local EID on ONE line — never wrap; shrink to fit if tight.
            HStack {
                Text("Hostname").foregroundStyle(.secondary)
                Text(LispWire.localHostname).font(.callout.monospaced()).foregroundStyle(Color.lispBlue)
                    .lineLimit(1).minimumScaleFactor(0.5)
                Spacer(minLength: 8)
                Text("EID").foregroundStyle(.secondary)
                Text(client.ourEID).font(.callout.monospaced()).foregroundStyle(Color.lispGreen)
                    .lineLimit(1).minimumScaleFactor(0.5)
            }
        } header: { centered("Ping Overlay App") }
    }

    // Completed replies — same clear logic as the LISP app (collapse + Clear 100 / Clear).
    private var resultsSection: some View {
        let all = client.completed
        let limit = Self.resultsCollapsedCount
        let shown = showAllResults ? all : Array(all.prefix(limit))
        return Section {
            if all.isEmpty { Text("No results yet").foregroundStyle(.secondary) }
            ForEach(shown) { r in
                let ok = r.status == .reply
                HStack {
                    Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundStyle(ok ? Color.lispGreen : Color.lispRed)
                    // The host's name sits ABOVE its address (EID → lisp-hosts name, RLOC →
                    // reverse DNS); the two small lines keep the row roughly the same height.
                    VStack(alignment: .leading, spacing: 0) {
                        if let h = displayName(for: r.responder) {
                            Text(h).font(.caption2.monospaced()).foregroundColor(.lispBlue)
                                .lineLimit(1).minimumScaleFactor(0.5)
                        }
                        (Text(r.responder).foregroundColor(addrColor(r.responder))
                            + Text(" seq \(r.sequence)").foregroundColor(.primary))
                            .font(.caption.monospaced()).lineLimit(1).minimumScaleFactor(0.5)
                    }
                    Spacer()
                    Text(r.rttMs.map { "\(Int($0)) ms" } ?? "timeout")
                        .font(.caption.monospaced().bold())
                        .foregroundStyle(ok ? .primary : Color.lispRed)
                }
            }
            if all.count > limit {
                Button { withAnimation { showAllResults.toggle() } } label: {
                    HStack {
                        Spacer()
                        Text(showAllResults ? "Show last \(limit)" : "Show all \(all.count)").font(.caption)
                        Image(systemName: showAllResults ? "chevron.up" : "chevron.down").font(.caption.bold())
                        Spacer()
                    }
                }
                .buttonStyle(.borderless).foregroundStyle(Color.lispBlue)
            }
        } header: {
            ZStack {
                centered("Results")
                if !all.isEmpty {
                    HStack {
                        Button("Clear 100") { client.clearOldest(100) }
                            .font(.caption).textCase(nil).foregroundStyle(.primary)
                        Spacer()
                        Button("Clear") { client.clearResults() }
                            .font(.caption).textCase(nil).foregroundStyle(.primary)
                    }
                }
            }
        }
    }

    // Live "Pinging…" content: spinner + source→target, then per-seq waiting rows.
    // NOTE: no Stop button here — it lives in the nav bar. When running, this section
    // floats to the top right under where you touch to scroll, and a tiny drag registered
    // as a tap on an in-list Stop, killing the ping. The fixed toolbar Stop can't be hit
    // while scrolling the list.
    @ViewBuilder private var activePingContent: some View {
        if client.running || !client.active.isEmpty {
            HStack(spacing: 8) {
                ProgressView()
                VStack(alignment: .leading, spacing: 2) {
                    Text("Pinging ...").bold()
                    // Source and target colored by kind: green EID, red RLOC.
                    (Text(client.sourceDisplay).foregroundColor(addrColor(client.sourceDisplay))
                        + Text(" \u{2192} ").foregroundColor(.primary)
                        + Text(client.currentTarget ?? "").foregroundColor(addrColor(client.currentTarget ?? "")))
                        .font(.callout.monospaced()).lineLimit(1).minimumScaleFactor(0.5)
                }
                Spacer()
            }
            .id("activePing")
            TimelineView(.periodic(from: .now, by: 0.2)) { _ in
                ForEach(client.active) { r in
                    HStack {
                        Image(systemName: "dot.radiowaves.left.and.right").foregroundStyle(Color.lispBlue)
                        (Text("seq \(r.sequence) → ").foregroundColor(.primary)
                            + Text(r.target).foregroundColor(addrColor(r.target)))
                            .font(.caption.monospaced())
                        Spacer()
                        Text(String(format: "waiting %.1fs", Date().timeIntervalSince(r.sentAt)))
                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    @ViewBuilder private func activePingSection(floated: Bool) -> some View {
        if client.running || !client.active.isEmpty {
            if floated {
                Section { activePingContent }
            } else {
                Section { activePingContent } header: { centered("Active Ping") }
            }
        }
    }

    private var historySection: some View {
        Section {
            if client.history.isEmpty { Text("No history yet").foregroundStyle(.secondary) }
            ForEach(client.history.prefix(50)) { s in
                historyRow(s)
                    // Force-press a history line to re-ping that address.
                    .contextMenu {
                        Button { startPing(s.target) } label: {
                            Label("Ping \(s.target)", systemImage: "dot.radiowaves.left.and.right")
                        }
                    }
            }
        } header: {
            ZStack {
                centered("History")
                if !client.history.isEmpty {
                    HStack { Spacer(); Button("Clear") { client.clearHistory() }.font(.caption).textCase(nil) }
                }
            }
        }
    }

    private func historyRow(_ s: PingSession) -> some View {
        // Bottom-aligned so the middle rtt sits on the same line as the date and the
        // replies/sent count (the second line of each side).
        HStack(alignment: .bottom) {
            VStack(alignment: .leading, spacing: 1) {
                // Host name above the address (EID → lisp-hosts name, RLOC → reverse DNS);
                // date below, as before.
                if let h = displayName(for: s.target) {
                    Text(h).font(.caption2.monospaced()).foregroundColor(.lispBlue)
                        .lineLimit(1).minimumScaleFactor(0.5)
                }
                Text(s.target).font(.callout.monospaced()).foregroundStyle(addrColor(s.target))
                    .lineLimit(1).minimumScaleFactor(0.5)
                Text(s.startedAt.formatted(date: .abbreviated, time: .shortened))
                    .font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
            if let avg = s.avgRtt {
                // min/avg/max rtt (ms), centered on the replies/sent line.
                Text("\(Int(s.minRtt ?? avg))/\(Int(avg))/\(Int(s.maxRtt ?? avg)) ms")
                    .font(.caption2.monospaced()).foregroundStyle(.secondary)
                Spacer()
            }
            VStack(alignment: .trailing, spacing: 2) {
                Text("\(s.successPct)%").font(.callout.bold())
                    .foregroundStyle(s.successPct >= 100 ? Color.lispGreen
                        : s.successPct == 0 ? Color.lispRed : .primary)
                Text("\(s.replies)/\(s.sent)").font(.caption2.monospaced()).foregroundStyle(.secondary)
            }
        }
    }

    private func centered(_ s: String) -> some View {
        Text(s).frame(maxWidth: .infinity, alignment: .center)
    }
}

