//
// ConfigView.swift
//
// (1) enable/disable LISP, (2) map-servers + lisp-decent suffix/modulus,
// (3) control-plane and data-plane debugging, plus EID, NAT-traversal,
// decent-NAT, and telemetry.
//

import SwiftUI

struct ConfigView: View {
    @EnvironmentObject var config: LispConfig
    @EnvironmentObject var engine: LispEngine
    @FocusState private var keyboardUp: Bool
    @State private var editingPrefixes = false
    // Share the whole xTR configuration as one image (even the off-screen part).
    @State private var shareImage: UIImage?
    @State private var showShare = false
    // Multicast group join/leave field (section sits between xTR config and Logging).
    @State private var groupField = ""

    private func centeredTitle(_ s: String) -> some View {
        Text(s).frame(maxWidth: .infinity, alignment: .center)
    }

    private var groupTrimmed: String { groupField.trimmingCharacters(in: .whitespaces) }
    private var groupIsValid: Bool { LispAddress(string: groupTrimmed)?.isMulticast == true }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    StatusHeader()
                    Toggle("Enable LISP", isOn: Binding(
                        get: { config.lispEnabled },
                        set: { on in
                            config.lispEnabled = on
                            config.save()
                            on ? engine.enable() : engine.disable()
                        }))
                    .tint(.lispGreen)
                }

                Section {
                    HStack(spacing: 8) {
                        Text("EID:")
                        TextField("240.10.0.100", text: $config.eidString)
                            .keyboardType(.numbersAndPunctuation)
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                            .font(.body.monospaced())
                            .multilineTextAlignment(.leading)
                            .frame(maxWidth: .infinity)
                            .focused($keyboardUp)
                            .onChange(of: config.eidString) { _, _ in config.save() }
                        Text("IID:")
                        TextField("0", value: $config.instanceID,
                                  format: .number.grouping(.never))
                            .keyboardType(.numberPad)
                            .font(.body.monospaced())
                            .multilineTextAlignment(.trailing)
                            .frame(width: 56)
                            .focused($keyboardUp)
                            .onChange(of: config.instanceID) { _, _ in config.save() }
                    }
                    .listRowInsets(EdgeInsets(top: 6, leading: 16, bottom: 6, trailing: 16))
                } header: {
                    centeredTitle("EID Configuration")
                }

                Section {
                    Toggle("RLOC-probing", isOn: Binding(
                        get: { config.rlocProbingEnabled },
                        set: { on in
                            config.rlocProbingEnabled = on; config.save()
                            if !on { engine.rlocProbingDisabled() }
                        }))
                    Toggle("NAT-traversal", isOn: Binding(
                        get: { config.natTraversalEnabled },
                        set: { on in
                            config.natTraversalEnabled = on
                            // decent-NAT requires a NAT in the path; turning
                            // NAT-traversal off turns decent-NAT off too.
                            if !on && config.decentNATEnabled {
                                config.decentNATEnabled = false
                                if engine.running { engine.removeDecentNATEntry() }
                            }
                            config.save()
                        }))
                    Toggle("Decentralized-NAT", isOn: Binding(
                        get: { config.decentNATEnabled },
                        set: { on in
                            config.decentNATEnabled = on
                            // decent-NAT is just NAT-traversal + asking the
                            // map-server for the full RLOC-set, so it implies
                            // NAT-traversal — flip that bar on too.
                            if on { config.natTraversalEnabled = true }
                            config.save()
                            guard engine.running else { return }
                            on ? engine.installDecentNATEntry()
                               : engine.removeDecentNATEntry()
                        }))
                } header: {
                    centeredTitle("xTR Configuration")
                }

                multicastSection

                Section {
                    Toggle("Control-plane", isOn: Binding(
                        get: { config.controlPlaneLog },
                        set: { on in
                            config.controlPlaneLog = on; config.save()
                            engine.log.controlPlaneLogging = on
                        }))
                    Toggle("Data-plane", isOn: Binding(
                        get: { config.dataPlaneLog },
                        set: { on in
                            config.dataPlaneLog = on; config.save()
                            engine.log.dataPlaneLogging = on
                        }))
                } header: {
                    centeredTitle("Logging")
                }

                Section {
                    HStack(spacing: 8) {
                        Text("Suffix:").frame(width: 72, alignment: .leading)
                        TextField("suffix, e.g. ms.example.com", text: $config.decentSuffix)
                            .font(.body.monospaced())
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                            .focused($keyboardUp)
                            .onChange(of: config.decentSuffix) { _, _ in config.save() }
                    }
                    Stepper("Modulus: \(config.decentModulus)",
                            value: $config.decentModulus, in: 0...255)
                        .onChange(of: config.decentModulus) { _, _ in config.save() }
                    HStack(spacing: 8) {
                        Text("Auth-key:")
                        SecureField("authentication-key", text: $config.decentAuthKey)
                            .font(.body.monospaced())
                            .multilineTextAlignment(.trailing)
                            .focused($keyboardUp)
                            .onChange(of: config.decentAuthKey) { _, _ in config.save() }
                    }
                    if config.decentConfigured, let eid = config.eid {
                        LabeledContent("EID registers to") {
                            Text(LispDecent.dnsName(eid: eid,
                                                    modulus: config.decentModulus,
                                                    suffix: config.decentSuffix,
                                                    prefixes: config.decentPrefixes))
                            .font(.caption.monospaced())
                            .foregroundStyle(.blue)
                        }
                    }
                } header: {
                    centeredTitle("LISP-Decent MS Configuration")
                }

                Section {
                    ForEach($config.decentPrefixes) { $p in
                        DecentPrefixRow(prefix: $p, editing: editingPrefixes,
                                        keyboardUp: $keyboardUp) {
                            config.decentPrefixes.removeAll { $0.id == p.id }
                            config.save()
                        }
                    }
                    .onChange(of: config.decentPrefixes) { _, _ in config.save() }
                    // "add prefix" stays on the left; "edit/delete prefix" on the
                    // right reveals the minus buttons and enables the fields. The
                    // list is otherwise read-only so it can't be changed by
                    // accident. Adding a prefix drops into edit mode so the new
                    // row is immediately editable.
                    HStack {
                        Button("add prefix") {
                            config.decentPrefixes.append(DecentPrefix())
                            config.save()
                            editingPrefixes = true
                        }
                        .buttonStyle(.borderless)
                        Spacer()
                        Button(editingPrefixes ? "done" : "edit/delete prefix") {
                            keyboardUp = false
                            editingPrefixes.toggle()
                        }
                        .buttonStyle(.borderless)
                    }
                } header: {
                    centeredTitle("LISP-Decent Lookup Prefix Configuration")
                }
            }
            .listRowSeparatorTint(.lispSeparator)
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle("lispers.net xTR")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    // Render the entire configuration (not just what's on screen)
                    // to one image and hand it to the share sheet.
                    Button {
                        let snap = XTRSnapshot()
                            .environmentObject(config)
                            .environmentObject(engine)
                        let r = ImageRenderer(content: snap)
                        r.scale = UIScreen.main.scale
                        if let ui = r.uiImage { shareImage = ui; showShare = true }
                    } label: {
                        Image(systemName: "square.and.arrow.up")
                    }
                }
            }
            .sheet(isPresented: $showShare) {
                if let img = shareImage { ShareSheet(items: [img]) }
            }
        }
    }

    // Join/leave multicast groups. Joining registers (0/0, G/32) so an RTR
    // replicates the group's traffic to us; pinging a 224.x address just works
    // via the default (0/0, 224/4) map-cache entry.
    private var multicastSection: some View {
        Section {
            HStack {
                TextField("Join group address", text: $groupField)
                    .font(.body.monospaced())
                    .keyboardType(.numbersAndPunctuation)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                    .focused($keyboardUp)
                Button("Join") {
                    keyboardUp = false
                    engine.joinGroup(groupTrimmed)
                    groupField = ""
                }
                .buttonStyle(.borderless)
                .disabled(!engine.running || !groupIsValid)
            }
            ForEach(config.joinedGroups, id: \.self) { g in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Image(systemName: "dot.radiowaves.up.forward")
                            .foregroundStyle(Color.lispGreen)
                        Text(g).font(.callout.monospaced()).foregroundStyle(Color.lispGreen)
                        Spacer()
                        Button("Leave") { engine.leaveGroup(g) }
                            .buttonStyle(.borderless)
                            .foregroundStyle(Color.lispRed)
                    }
                    Group {
                        if let ms = engine.groupMapServers[g] {
                            Text("registers to ").foregroundStyle(.primary)
                                + Text(ms).foregroundStyle(Color.lispBlue)
                        } else {
                            Text(engine.running ? "registering…" : "register when LISP is active")
                                .foregroundStyle(.secondary)
                        }
                    }
                    .font(.caption2.monospaced())
                    .lineLimit(1).minimumScaleFactor(0.7)
                }
            }
            if config.joinedGroups.isEmpty {
                Text("No groups joined")
                    .font(.caption).foregroundStyle(.secondary)
            }
        } header: {
            centeredTitle("Multicast Groups")
        }
    }
}

// A read-only, non-scrolling rendering of the xTR configuration, sized to a
// fixed width so ImageRenderer captures the whole thing (including the parts
// scrolled off screen) as a single shareable image.
private struct XTRSnapshot: View {
    @EnvironmentObject var config: LispConfig
    @EnvironmentObject var engine: LispEngine

    private func line(_ label: String, _ value: String, _ color: Color = .primary) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text(label).foregroundStyle(.secondary)
            Text(value).foregroundStyle(color).bold()
            Spacer(minLength: 0)
        }
        .font(.system(size: 13, design: .monospaced))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("lispers.net xTR — \(ContentView.version)")
                .font(.headline)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.bottom, 2)

            // Reuse the live status block so the snapshot always matches the
            // screen — hostname, EID, RLOC, translated RLOC, registers, NAT —
            // and automatically picks up anything added to it later.
            StatusHeader()

            Divider()
            line("IID:", "\(config.instanceID)")
            line("EID:", config.eidString.isEmpty ? "—" : config.eidString, .lispGreen)

            Divider()
            line("RLOC-probing:", config.rlocProbingEnabled ? "on" : "off")
            line("NAT-traversal:", config.natTraversalEnabled ? "on" : "off")
            line("Decentralized-NAT:", config.decentNATEnabled ? "on" : "off")

            Divider()
            line("Control-plane log:", config.controlPlaneLog ? "on" : "off")
            line("Data-plane log:", config.dataPlaneLog ? "on" : "off")

            Divider()
            line("Suffix:", config.decentSuffix.isEmpty ? "—" : config.decentSuffix, .lispBlue)
            line("Modulus:", "\(config.decentModulus)")
            line("Auth-key:", config.decentAuthKey.isEmpty ? "—"
                 : String(repeating: "*", count: config.decentAuthKey.count))
            if config.decentConfigured, let eid = config.eid {
                line("registers to:", LispDecent.dnsName(eid: eid,
                        modulus: config.decentModulus, suffix: config.decentSuffix,
                        prefixes: config.decentPrefixes), .lispBlue)
            }
            if !config.decentPrefixes.isEmpty {
                Divider()
                Text("Lookup prefixes:")
                    .font(.system(size: 13, design: .monospaced)).foregroundStyle(.secondary)
                ForEach(config.decentPrefixes) { p in
                    line("  •", "\(p.eidPrefix) lookup-len: \(p.lookupLength.map(String.init) ?? "?")", .lispGreen)
                }
            }
        }
        .padding(16)
        .frame(width: 390, alignment: .leading)
        .background(Color(.systemBackground))
    }
}

// One row of the LISP-Decent lookup-prefix list: a delete button, the
// eid-prefix field, and the lookup-length. Extracted to keep the Form body
// within the SwiftUI type-checker's reach.
private struct DecentPrefixRow: View {
    @Binding var prefix: DecentPrefix
    var editing: Bool
    var keyboardUp: FocusState<Bool>.Binding
    let onDelete: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            if editing {
                Button(action: onDelete) {
                    Image(systemName: "minus.circle.fill")
                        .foregroundStyle(Color.lispRed)
                }
                .buttonStyle(.borderless)
            }
            TextField("eid-prefix, e.g. 240.11.0.0/16", text: $prefix.eidPrefix)
                .keyboardType(.numbersAndPunctuation)
                .autocapitalization(.none)
                .disableAutocorrection(true)
                .font(.body.monospaced())
                .focused(keyboardUp)
                .disabled(!editing)
            Divider()
            Text("lookup-len:")
            // Bound as text (not a numeric format) so it can be cleared to empty
            // and must be typed in — no default value.
            TextField("?", text: Binding(
                get: { prefix.lookupLength.map(String.init) ?? "" },
                set: { prefix.lookupLength = Int($0) }))
                .keyboardType(.numberPad)
                .font(.body.monospaced())
                .frame(width: 36)
                .focused(keyboardUp)
                .disabled(!editing)
        }
    }
}
