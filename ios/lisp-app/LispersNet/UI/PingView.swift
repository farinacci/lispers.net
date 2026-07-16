//
// PingView.swift
//
// EID-to-EID ping. Targets come from the lisp-hosts file (lhr, frt, cmh by
// default) — never hard-coded. Includes an editor for the hosts file.
//

import SwiftUI
import UIKit                       // UIPasteboard — long-press to copy a hostname/EID
import UniformTypeIdentifiers      // UTType for the hosts-file importer

struct PingView: View {
    @EnvironmentObject var engine: LispEngine
    @EnvironmentObject var config: LispConfig
    @EnvironmentObject var hosts: HostsFile
    @EnvironmentObject var ping: PingService
    @State private var customEID = ""
    @FocusState private var eidFocused: Bool
    @State private var showAllResults = false
    @State private var showAllTargets = false
    @Environment(\.scenePhase) private var scenePhase
    // The Direct/Tunnel "path" pill is HIDDEN for now — the PING app is the overlay client,
    // so we test the overlay there. The code is kept below (gated on `showPathControl`),
    // so flipping this to `true` brings the pill back. Always Direct while hidden.
    @State private var tunnelMode = false
    private let showPathControl = false

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
                        .disabled(customTrimmed.isEmpty || !engine.running)
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

                    // Ping path (direct|tunnel) — HIDDEN (the PING app is the overlay
                    // client). Code kept, gated on showPathControl so it's easy to restore.
                    if showPathControl {
                        HStack {
                            Text("path").foregroundStyle(.secondary)
                            Spacer()
                            splitButton("direct", isOn: !tunnelMode) { }
                            splitButton("tunnel", isOn: tunnelMode) { }
                        }
                        .disabled(true)
                        .opacity(0.5)
                    }
                }

                Section {
                    // Seeded defaults (lhr/frt/cmh) always show; added/imported hosts
                    // stay tucked behind a pull-down so they don't eat vertical space.
                    let defaults = hosts.entries.filter { HostsFile.defaultNames.contains($0.name) }
                    let others = hosts.entries.filter { !HostsFile.defaultNames.contains($0.name) }
                    ForEach(defaults) { targetRow($0) }
                    if showAllTargets {
                        ForEach(others) { targetRow($0) }
                    }
                    if !others.isEmpty {
                        Button {
                            withAnimation { showAllTargets.toggle() }
                        } label: {
                            HStack {
                                Spacer()
                                Text(showAllTargets ? "Show fewer"
                                                    : "Show \(others.count) more")
                                    .font(.caption)
                                Image(systemName: showAllTargets ? "chevron.up" : "chevron.down")
                                    .font(.caption.bold())
                                Spacer()
                            }
                        }
                        .buttonStyle(.borderless)
                        .foregroundStyle(Color.lispBlue)
                    }
                    if !engine.running {
                        Text("Enable LISP on the xTR tab to ping.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } header: {
                    Text("Ping Targets")
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
            .contentMargins(.top, -50, for: .scrollContent)
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle("Ping")
            .navigationBarTitleDisplayMode(.inline)
            // Switching tabs keeps the ping running 10s longer so the map-cache
            // counters (and Logs) can be watched climbing; returning cancels that.
            .onAppear { ping.cancelGrace() }
            .onDisappear { ping.keepAliveBriefly(10) }
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

    // One tappable ping-target row (host name + EID + live-ping indicator).
    @ViewBuilder private func targetRow(_ entry: HostEntry) -> some View {
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
    @State private var showImport = false
    // Own the edit state locally so the parent's 1s engine-mirror re-render can't
    // retrigger the edit-mode row animation (was: list sliding left/right repeatedly).
    @State private var editMode: EditMode = .inactive

    // /etc/hosts format: a header banner, then "<address>\t<name>" per entry.
    private static let hostsHeader = """
    #
    # This hosts file was created by the lispers.net LISP xTR IOS app.
    #

    """
    private func exportText() -> String {
        Self.hostsHeader + working.map { "\($0.address)\t\($0.name)" }.joined(separator: "\n") + "\n"
    }
    // Parse /etc/hosts lines ("<address>\t<name> [aliases]"), skipping blank/comment lines.
    private func parseHosts(_ text: String) -> [HostEntry] {
        var out: [HostEntry] = []
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard parts.count >= 2, LispAddress(string: parts[0]) != nil else { continue }
            out.append(HostEntry(name: parts[1], address: parts[0]))   // /etc/hosts: address, then name
        }
        return out
    }
    private func readImported(_ url: URL) -> String? {
        let ok = url.startAccessingSecurityScopedResource()
        defer { if ok { url.stopAccessingSecurityScopedResource() } }
        return try? String(contentsOf: url, encoding: .utf8)
    }
    // Present the system share sheet from the top-most view controller — reliable even
    // from inside a sheet (SwiftUI's nested .sheet blanks the UIActivityViewController).
    static func presentShare(_ items: [Any]) {
        guard let scene = UIApplication.shared.connectedScenes
                  .compactMap({ $0 as? UIWindowScene })
                  .first(where: { $0.activationState == .foregroundActive }),
              let root = scene.keyWindow?.rootViewController else { return }
        var top = root
        while let p = top.presentedViewController { top = p }
        let av = UIActivityViewController(activityItems: items, applicationActivities: nil)
        if let pop = av.popoverPresentationController {          // iPad anchor
            pop.sourceView = top.view
            pop.sourceRect = CGRect(x: top.view.bounds.midX, y: top.view.bounds.maxY - 60,
                                    width: 0, height: 0)
        }
        top.present(av, animated: true)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ForEach($working) { $e in
                        HStack {
                            TextField("name", text: $e.name)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .foregroundStyle(Color.lispBlue)          // hostname blue
                            TextField("eid", text: $e.address)
                                .font(.body.monospaced())
                                .keyboardType(.decimalPad)
                                .foregroundStyle(Color.lispGreen)         // EID green
                        }
                        .contextMenu {                                    // long-press to copy
                            Button {
                                UIPasteboard.general.string = e.address
                            } label: { Label("Copy EID \(e.address)", systemImage: "doc.on.doc") }
                            Button {
                                UIPasteboard.general.string = e.name
                            } label: { Label("Copy name \(e.name)", systemImage: "doc.on.doc") }
                        }
                        // onDelete drives BOTH swipe-to-delete and the edit-mode red −.
                        // Disable it while not editing so only the edit-mode delete remains.
                        .deleteDisabled(!editMode.isEditing)
                    }
                    .onDelete { working.remove(atOffsets: $0) }   // Edit-mode delete (red −)
                    .onMove { working.move(fromOffsets: $0, toOffset: $1) }  // drag to reorder
                } header: {
                    Text("Hostname Configuration").frame(maxWidth: .infinity, alignment: .center)
                }
                // Edit/Done centered directly below the list (reorder + red − delete).
                Section {
                    Button(editMode.isEditing ? "Done" : "Edit") {
                        withAnimation { editMode = editMode.isEditing ? .inactive : .active }
                    }
                    .frame(maxWidth: .infinity, alignment: .center)
                    .tint(Color.lispBlue)
                }
                Section {
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
                } header: {
                    Text("Add Entry").frame(maxWidth: .infinity, alignment: .center)
                }
                Section {
                    HStack {
                        Button {
                            let url = FileManager.default.temporaryDirectory
                                .appendingPathComponent("lisp-hostnames")
                            try? exportText().data(using: .utf8)?.write(to: url)
                            Self.presentShare([url])           // share sheet from the top VC
                        } label: {
                            Label("Export", systemImage: "square.and.arrow.up")
                                .font(.subheadline)
                                .padding(.horizontal, 14).padding(.vertical, 7)
                                .background(Color.lispGreen.opacity(0.15), in: Capsule())
                                .foregroundStyle(Color.lispGreen)
                        }
                        .buttonStyle(.plain)
                        Spacer()
                        Button {
                            showImport = true
                        } label: {
                            Label("Import", systemImage: "square.and.arrow.down")
                                .font(.subheadline)
                                .padding(.horizontal, 14).padding(.vertical, 7)
                                .background(Color.lispGreen.opacity(0.15), in: Capsule())
                                .foregroundStyle(Color.lispGreen)
                        }
                        .buttonStyle(.plain)
                    }
                } header: {
                    Text("Import / Export")
                        .frame(maxWidth: .infinity, alignment: .center)
                } footer: {
                    Text("(/etc/hosts format)")
                        .frame(maxWidth: .infinity, alignment: .center)
                }
            }
            .listRowSeparatorTint(.lispSeparator)
            .environment(\.editMode, $editMode)     // local edit state (stable across re-renders)
            .navigationTitle("LISP Hosts")
            .navigationBarTitleDisplayMode(.inline)
            .fileImporter(isPresented: $showImport,
                          allowedContentTypes: [.plainText, .text, .data, .item]) { result in
                guard case .success(let url) = result,
                      let text = readImported(url) else { return }
                let imported = parseHosts(text)
                let existing = Set(working.map { $0.address })      // merge, skip dup addresses
                working += imported.filter { !existing.contains($0.address) }
            }
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
