//
// PingView.swift
//
// EID-to-EID ping. Targets come from the lisp-hosts file (lhr, frt, cmh by
// default) — never hard-coded. Includes an editor for the hosts file.
//

import SwiftUI

struct PingView: View {
    @EnvironmentObject var engine: LispEngine
    @EnvironmentObject var hosts: HostsFile
    @EnvironmentObject var ping: PingService
    @State private var editingHosts = false
    @State private var customEID = ""
    @FocusState private var eidFocused: Bool
    @Environment(\.scenePhase) private var scenePhase

    private var customTrimmed: String { customEID.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
            List {
                // While a ping is running, float the live section to the very top
                // (no header, so the first row lands crisply under the nav bar and
                // is reachable regardless of how much content is below it).
                if ping.continuous { activePingSection(floated: true) }
                Section {
                    Picker("Interval", selection: Binding(
                        get: { ping.interval }, set: { ping.setInterval($0) })) {
                        Text("1s").tag(1.0)
                        Text("500ms").tag(0.5)
                        Text("250ms").tag(0.25)
                        Text("100ms").tag(0.1)
                    }
                    .pickerStyle(.segmented)

                    // Ping an arbitrary EID not in the hosts list.
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
                        HStack { Spacer(); Text("Edit hosts"); Spacer() }
                    }
                } header: {
                    Text("Ping an EID (from \(engine.config.eidString.isEmpty ? "our EID" : "EID \(engine.config.eidString)"))")
                        .frame(maxWidth: .infinity, alignment: .center)
                }

                // In its resting position (not pinging) the live section sits here
                // in the middle, with its header. While pinging it is floated to
                // the top of the List instead (see the top of this List).
                if !ping.continuous { activePingSection(floated: false) }

                Section {
                    if ping.completed.isEmpty {
                        Text("No results yet").foregroundStyle(.secondary)
                    }
                    ForEach(ping.completed) { r in
                        let ok = r.status == .reply
                        HStack {
                            Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(ok ? Color.lispGreen : Color.lispRed)
                            Text("\(r.address) seq \(r.sequence)")
                                .font(.caption.monospaced())
                            Spacer()
                            Text(r.rttMs.map { "\(Int($0)) ms" } ?? "timeout")
                                .font(.caption.monospaced().bold())
                                .foregroundStyle(ok ? .primary : Color.lispRed)
                        }
                    }
                } header: {
                    ZStack {
                        Text("Results").frame(maxWidth: .infinity, alignment: .center)
                        if !ping.completed.isEmpty {
                            HStack {
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
            .listRowSeparatorTint(.lispSeparator)
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
        } else {
            Text("No active ping").font(.caption).foregroundStyle(.secondary)
        }
    }

    // Floated == true: no header, so the first row sits crisply at the very top.
    // Floated == false: resting position in the middle, with the "Active Ping" header.
    @ViewBuilder private func activePingSection(floated: Bool) -> some View {
        if floated {
            Section { activePingContent }
        } else {
            Section { activePingContent } header: {
                Text("Active Ping").frame(maxWidth: .infinity, alignment: .center)
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
