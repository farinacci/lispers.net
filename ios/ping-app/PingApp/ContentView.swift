//
// ContentView.swift  (PING app)
//
// Mirrors the LISP app's Ping tab behavior: the live "Pinging…" section (with the
// per-seq "waiting X.Xs" rows + Stop) and the Results section float to the top while a
// ping runs and drop to the bottom when idle; scroll snaps to the active section on
// start and back to the top on stop. Adds PING's own Status + History sections.
//

import SwiftUI

extension Color {
    static let lispGreen = Color(red: 0.16, green: 0.55, blue: 0.16)
    static let lispRed = Color(red: 0.78, green: 0.12, blue: 0.12)
    static let lispBlue = Color(red: 0.20, green: 0.40, blue: 0.95)
    static let lispSeparator = Color.gray.opacity(0.55)
}

struct ContentView: View {
    @EnvironmentObject var client: PingClient
    @StateObject private var hosts = PingHosts()
    @State private var target = ""
    @State private var editingHosts = false
    @State private var showAllResults = false
    @FocusState private var focused: Bool
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.openURL) private var openURL
    static let version = "0.2"
    private static let resultsCollapsedCount = 10

    private var trimmed: String { target.trimmingCharacters(in: .whitespaces) }

    // Resolve an EID or a hostname (from the list) to a dotted EID; nil if neither.
    private func resolve(_ input: String) -> String? {
        let s = input.trimmingCharacters(in: .whitespaces)
        if LispWire.parseIPv4(s) != nil { return s }
        return hosts.entries.first { $0.name.caseInsensitiveCompare(s) == .orderedSame }?.address
    }
    private func startPing(_ input: String) {
        focused = false
        guard let addr = resolve(input) else { return }
        target = addr
        client.start(addr)
    }

    // Launch the LISP app via its custom URL scheme (registered in its Info.plist) so the
    // user can bring the xTR to the foreground straight from the "open it" hint.
    private func openLispApp() {
        if let url = URL(string: "lispxtr://") { openURL(url) }
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

                // Ping an EID (input) — its own section, like the LISP app.
                Section {
                    HStack {
                        TextField("EID or hostname", text: $target)
                            .font(.body.monospaced())
                            .keyboardType(.asciiCapable)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .focused($focused)
                        Button("Ping") { startPing(target) }
                            .buttonStyle(.borderless)
                            .disabled(trimmed.isEmpty)
                    }
                } header: { centered("Ping an EID") }

                // Interval — its own section.
                Section {
                    Picker("Interval", selection: Binding(get: { client.interval },
                                                          set: { client.setInterval($0) })) {
                        Text("1s").tag(1.0); Text("500ms").tag(0.5)
                        Text("250ms").tag(0.25); Text("100ms").tag(0.1)
                    }
                    .pickerStyle(.segmented)
                }

                // Hostnames
                Section {
                    ForEach(hosts.entries) { h in
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
                    Button { editingHosts = true } label: {
                        HStack { Spacer(); Text("Edit hostnames"); Spacer() }
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
            .sheet(isPresented: $editingHosts) { HostsEditor(hosts: hosts) }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { client.enteredForeground() }   // resume the send loop
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
            HStack {
                Circle().fill(client.tunnelUp ? Color.lispGreen : Color.gray)
                    .frame(width: 10, height: 10)
                Group {
                    if client.tunnelUp {
                        Text("Overlay path ") + Text("active").foregroundColor(.lispGreen)
                            + Text(" — using ")
                            + Text(client.utunName).foregroundColor(.lispBlue)
                                .font(.callout.monospaced())        // same as the Hostname (dino-iphone) row
                    } else {
                        Text("Overlay path ") + Text("down").foregroundColor(.lispRed)
                    }
                }
                .font(.subheadline)
                Spacer()
            }
            HStack {
                Circle().fill(client.lispReady ? Color.lispGreen : Color.orange)
                    .frame(width: 10, height: 10)
                if client.lispReady {
                    (Text("LISP app is ") + Text("ready to encap/decap").foregroundColor(.lispGreen))
                        .font(.subheadline)
                    Spacer()
                } else {
                    (Text("LISP app ") + Text("not running").foregroundColor(.orange))
                        .font(.subheadline)
                    Spacer()
                    Button("Open") { openLispApp() }
                        .buttonStyle(.borderedProminent)
                        .tint(.lispGreen)
                        .controlSize(.small)
                }
            }
            HStack {
                Text("Hostname").foregroundStyle(.secondary)
                Spacer()
                Text(LispWire.localHostname).font(.callout.monospaced()).foregroundStyle(Color.lispBlue)
            }
            HStack {
                Text("Local EID").foregroundStyle(.secondary)
                Spacer()
                Text(client.ourEID).font(.callout.monospaced()).foregroundStyle(Color.lispGreen)
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
                    Text("\(r.responder) seq \(r.sequence)").font(.caption.monospaced())
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
                    Text("\(client.ourEID) \u{2192} \(client.currentTarget ?? "")")
                        .font(.callout.monospaced()).lineLimit(1).minimumScaleFactor(0.5)
                }
                Spacer()
            }
            .id("activePing")
            TimelineView(.periodic(from: .now, by: 0.2)) { _ in
                ForEach(client.active) { r in
                    HStack {
                        Image(systemName: "dot.radiowaves.left.and.right").foregroundStyle(Color.lispBlue)
                        Text("seq \(r.sequence) → \(r.target)").font(.caption.monospaced())
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
            ForEach(client.history.prefix(50)) { s in historyRow(s) }
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
            VStack(alignment: .leading, spacing: 2) {
                Text(s.target).font(.callout.monospaced()).foregroundStyle(Color.lispGreen)
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

struct HostsEditor: View {
    @ObservedObject var hosts: PingHosts
    @Environment(\.dismiss) private var dismiss
    @State private var newName = ""
    @State private var newAddr = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("hosts") {
                    ForEach(hosts.entries) { h in
                        HStack {
                            Text(h.name).bold()
                            Text(h.address).font(.body.monospaced()).foregroundStyle(Color.lispGreen)
                        }
                    }
                    .onDelete { hosts.remove(at: $0) }
                }
                Section("add") {
                    HStack {
                        TextField("name", text: $newName).autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                        TextField("240.x.x.x", text: $newAddr).font(.body.monospaced())
                            .keyboardType(.numbersAndPunctuation)
                        Button("Add") {
                            hosts.add(name: newName, address: newAddr); newName = ""; newAddr = ""
                        }
                    }
                }
            }
            .navigationTitle("Hostnames")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}
