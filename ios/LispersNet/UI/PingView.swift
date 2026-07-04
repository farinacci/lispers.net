//
// PingView.swift
//
// EID-to-EID ping. Targets come from the lisp-hosts file (lhr, frt, cmh by
// default) — never hard-coded. Includes an editor for the hosts file.
//

import SwiftUI

struct PingView: View {
    @EnvironmentObject var engine: LispEngine
    @EnvironmentObject var config: LispConfig
    @EnvironmentObject var hosts: HostsFile
    @EnvironmentObject var ping: PingService
    @State private var editingHosts = false
    @State private var customEID = ""
    @FocusState private var eidFocused: Bool
    @State private var showAllResults = false
    @Environment(\.scenePhase) private var scenePhase

    private static let resultsCollapsedCount = 10

    private var customTrimmed: String { customEID.trimmingCharacters(in: .whitespaces) }

    // A capsule toggle-button for the load-split row: green filled when on, gray
    // outline when off; tapping flips it.
    private func splitButton(_ title: String, isOn: Bool,
                             _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.callout)
                .padding(.horizontal, 12).padding(.vertical, 5)
                .background(isOn ? Color.lispGreen : Color.gray.opacity(0.18))
                .foregroundColor(isOn ? .white : .primary)
                .clipShape(Capsule())
        }
        .buttonStyle(.borderless)
    }

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
            List {
                // Zero-height true-top anchor. Scrolling here on stop lands at
                // content-offset 0, where List keeps the nav-bar safe-area inset —
                // so the "Ping an EID" header rests cleanly below the bar instead of
                // tucking up under its translucent blur (the "ghosted header" bug).
                // Wrapped in a zero-spacing Section so it adds no visible gap.
                Section {
                    Color.clear
                        .frame(height: 0)
                        .id("list-top")
                        .listRowInsets(EdgeInsets())
                        .listRowSeparator(.hidden)
                        .listRowBackground(Color.clear)
                }
                .listSectionSpacing(0)

                // While a ping is running, float the live section to the very top
                // (no header, so the first row lands crisply under the nav bar and
                // is reachable regardless of how much content is below it), with the
                // Results right beneath it so replies stream in under "Pinging…".
                if ping.continuous {
                    activePingSection(floated: true)
                    resultsSection
                }
                // Ping an arbitrary EID not in the hosts list — kept at the very top,
                // right under the "Ping" title, now ABOVE the parameter section.
                Section {
                    HStack {
                        TextField("EID or hostname", text: $customEID)
                            .font(.body.monospaced())
                            .keyboardType(.asciiCapable)
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                            .focused($eidFocused)
                        Button("Ping") {
                            eidFocused = false
                            let input = customTrimmed
                            hosts.resolveTarget(input) { eid in
                                if let eid = eid {
                                    ping.startContinuous(name: eid.addressString, eid: eid)
                                } else {
                                    engine.log.fprint(.core, "Ping: cannot resolve \(input)")
                                }
                            }
                        }
                        .buttonStyle(.borderless)
                        .disabled(!engine.running || customTrimmed.isEmpty)
                    }
                } header: {
                    Text("Ping an EID (from \(engine.config.eidString.isEmpty ? "our EID" : "EID \(engine.config.eidString)"))")
                        .frame(maxWidth: .infinity, alignment: .center)
                }
                .id("ping-top")
                // Tighten the gap to the parameters below, but keep a little breathing room.
                .listSectionSpacing(12)

                // Timer + load-split toggles, now BELOW the Ping-an-EID field.
                Section {
                    Picker("Interval", selection: Binding(
                        get: { ping.interval }, set: { ping.setInterval($0) })) {
                        Text("1s").tag(1.0)
                        Text("500ms").tag(0.5)
                        Text("250ms").tag(0.25)
                        Text("100ms").tag(0.1)
                    }
                    .pickerStyle(.segmented)

                    // "load-split" with unicast/multicast as independent toggle-
                    // buttons on one line (green = on). On = spread packets across
                    // the up RTRs; off = a single RTR (no spread).
                    HStack {
                        Text("load-split")
                        Spacer()
                        splitButton("unicast", isOn: config.loadSplitUnicast) {
                            config.loadSplitUnicast.toggle(); config.save()
                        }
                        splitButton("multicast", isOn: config.loadSplitMulticast) {
                            config.loadSplitMulticast.toggle(); config.save()
                        }
                    }
                }

                Section {
                    ForEach(hosts.entries) { entry in
                        let entryEID = LispAddress(string: entry.address)
                        Button {
                            if let eid = entryEID {
                                ping.startContinuous(name: eid.addressString, eid: eid)
                            }
                        } label: {
                            HStack {
                                Text(entry.name).bold()
                                Text(entry.address)
                                    .font(.callout.monospaced())
                                    .foregroundStyle(Color.lispGreen)
                                Spacer()
                                let pinging = ping.continuous
                                    && ping.currentTarget == entryEID?.addressString
                                Image(systemName: "dot.radiowaves.left.and.right")
                                    .foregroundStyle(pinging ? Color.lispGreen : .secondary)
                                    .symbolEffect(.variableColor, isActive: pinging)
                            }
                        }
                        .disabled(!engine.running)
                    }
                    if !engine.running {
                        Text("Enable LISP on the xTR tab to ping.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Button { editingHosts = true } label: {
                        HStack { Spacer(); Text("Edit hostnames"); Spacer() }
                    }
                } header: {
                    Text("Hostname Configuration")
                        .frame(maxWidth: .infinity, alignment: .center)
                }

                // When idle (stopped, or after the tab-switch grace expires), the
                // live section + Results rest at the END in reading order.
                if !ping.continuous {
                    activePingSection(floated: false)
                    resultsSection
                }
            }
            .listRowSeparatorTint(.lispSeparator)
            // Pull the first section up tight under the nav bar (past the List's
            // default top content inset) so the timer/toggle pill sits right below
            // "Ping". Negative margin closes the remaining gap.
            .contentMargins(.top, -44, for: .scrollContent)
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle("Ping")
            .navigationBarTitleDisplayMode(.inline)
            .sheet(isPresented: $editingHosts) {
                HostsEditor()
            }
            // Switching tabs keeps the ping running 5s longer so the map-cache
            // counters can be watched climbing; returning cancels that.
            .onAppear { ping.cancelGrace() }
            .onDisappear { ping.keepAliveBriefly(5) }
            // Backgrounding the app stops the ping immediately.
            .onChange(of: scenePhase) { _, phase in
                if phase != .active { ping.stopContinuous() }
            }
            // When a ping starts, pin the (now top, header-less) live section to
            // the top of the window so it's seen without manual scrolling.
            .onChange(of: ping.currentTarget) { _, target in
                if target != nil {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                        withAnimation { proxy.scrollTo("activePing", anchor: .top) }
                    }
                } else {
                    // Stopped: the header-less floated section is removed. Snap to
                    // the true top (offset 0) so the "Ping an EID" header rests below
                    // the nav bar, not ghosted under its blur. Defer past the reflow.
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
                        proxy.scrollTo("list-top", anchor: .top)
                    }
                }
            }
            // Don't cross-fade the section reflow when the ping starts/stops.
            .animation(nil, value: ping.continuous)
            }
        }
    }

    // Completed ping replies. Floats up under the live "Pinging…" section while a
    // ping runs (easy to watch), drops to the end when idle.
    private var resultsSection: some View {
        let all = ping.completed
        let limit = Self.resultsCollapsedCount
        // completed is newest-first, so prefix() is the most-recent N.
        let shown = showAllResults ? all : Array(all.prefix(limit))
        return Section {
            if all.isEmpty {
                Text("No results yet").foregroundStyle(.secondary)
            }
            ForEach(shown) { r in
                let ok = r.status == .reply
                HStack {
                    Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundStyle(ok ? Color.lispGreen : Color.lispRed)
                    // Multicast replies come from many group members — lead with the
                    // responder's host name (blue) when lisp-hosts knows it.
                    Group {
                        if r.multicast, let hn = hosts.name(for: r.address) {
                            Text(hn + " ").foregroundColor(.lispBlue)
                                + Text("\(r.address) seq \(r.sequence)")
                        } else {
                            Text("\(r.address) seq \(r.sequence)")
                        }
                    }
                    .font(.caption.monospaced())
                    Spacer()
                    Text(r.rttMs.map { "\(Int($0)) ms" } ?? "timeout")
                        .font(.caption.monospaced().bold())
                        .foregroundStyle(ok ? .primary : Color.lispRed)
                }
            }
            // Pull-down to reveal the rest; only when more than the last N exist.
            if all.count > limit {
                Button {
                    withAnimation { showAllResults.toggle() }
                } label: {
                    HStack {
                        Spacer()
                        Text(showAllResults ? "Show last \(limit)" : "Show all \(all.count)")
                            .font(.caption)
                        Image(systemName: showAllResults ? "chevron.up" : "chevron.down")
                            .font(.caption.bold())
                        Spacer()
                    }
                }
                .buttonStyle(.borderless)
                .foregroundStyle(Color.lispBlue)
            }
        } header: {
            ZStack {
                Text("Results").frame(maxWidth: .infinity, alignment: .center)
                if !ping.completed.isEmpty {
                    HStack {
                        // Trim the oldest 100 (left), opposite the full Clear (right).
                        Button("Clear 100") { ping.clearOldest(100) }
                            .font(.caption)
                            .textCase(nil)
                            .foregroundStyle(.primary)
                        Spacer()
                        Button("Clear") { ping.clearResults() }
                            .font(.caption)
                            .textCase(nil)
                            .foregroundStyle(.primary)
                    }
                }
            }
        }
    }

    // The live-ping rows (or the idle placeholder). The "Pinging ..." row carries
    // the "activePing" scroll id.
    @ViewBuilder private var activePingContent: some View {
        if ping.inFlight || !ping.active.isEmpty {
            HStack(spacing: 8) {
                ProgressView()
                VStack(alignment: .leading, spacing: 2) {
                    Text("Pinging ...").bold()
                    Text("\(engine.config.eidString) \u{2192} \(ping.currentTarget ?? "")")
                        .font(.callout.monospaced())
                        .lineLimit(1)
                        .minimumScaleFactor(0.5)
                }
                Spacer()
                if ping.continuous {
                    Button("Stop") { ping.stopContinuous() }
                        .buttonStyle(.borderless)
                        .foregroundStyle(Color.lispRed)
                }
            }
            .id("activePing")
            TimelineView(.periodic(from: .now, by: 0.2)) { _ in
                ForEach(ping.active) { r in
                    HStack {
                        Image(systemName: "dot.radiowaves.left.and.right")
                            .foregroundStyle(Color.lispBlue)
                        Text("seq \(r.sequence) → \(r.target)")
                            .font(.caption.monospaced())
                        Spacer()
                        Text(String(format: "waiting %.1fs",
                                    Date().timeIntervalSince(r.sentAt)))
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    // Only rendered while a ping is actually in flight — no "Active Ping" section
    // (and no "No active ping" placeholder) when idle.
    // Floated == true: no header, so the first row sits crisply at the very top.
    // Floated == false: resting position in the middle, with the "Active Ping" header.
    @ViewBuilder private func activePingSection(floated: Bool) -> some View {
        if ping.inFlight || !ping.active.isEmpty {
            if floated {
                Section { activePingContent }
            } else {
                Section { activePingContent } header: {
                    Text("Active Ping").frame(maxWidth: .infinity, alignment: .center)
                }
            }
        }
    }
}

struct HostsEditor: View {
    @EnvironmentObject var hosts: HostsFile
    @Environment(\.dismiss) private var dismiss
    @State private var working: [HostEntry] = []
    @State private var newName = ""
    @State private var newAddress = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("lisp-hosts (Documents/lisp-hosts)") {
                    ForEach($working) { $e in
                        HStack {
                            TextField("name", text: $e.name)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                            TextField("eid", text: $e.address)
                                .font(.body.monospaced())
                                .keyboardType(.decimalPad)
                        }
                    }
                    .onDelete { working.remove(atOffsets: $0) }
                }
                Section("add entry") {
                    HStack {
                        TextField("name", text: $newName)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        TextField("eid address", text: $newAddress)
                            .font(.body.monospaced())
                            .keyboardType(.decimalPad)
                        Button("Add") {
                            guard !newName.isEmpty,
                                  LispAddress(string: newAddress) != nil else { return }
                            working.append(HostEntry(name: newName, address: newAddress))
                            newName = ""; newAddress = ""
                        }
                    }
                }
            }
            .listRowSeparatorTint(.lispSeparator)
            .navigationTitle("lisp-hosts")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { hosts.save(working); dismiss() }
                }
            }
            .onAppear { working = hosts.entries }
        }
    }
}
