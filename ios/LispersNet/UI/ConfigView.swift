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

    private func centeredTitle(_ s: String) -> some View {
        Text(s).frame(maxWidth: .infinity, alignment: .center)
    }

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
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 8) {
                            Text("IID:").frame(width: 40, alignment: .leading)
                            TextField("0", value: $config.instanceID,
                                      format: .number.grouping(.never))
                                .keyboardType(.numberPad)
                                .font(.body.monospaced())
                                .frame(width: 90)
                                .focused($keyboardUp)
                                .onChange(of: config.instanceID) { _, _ in config.save() }
                        }
                        HStack(spacing: 8) {
                            Text("EID:").frame(width: 40, alignment: .leading)
                            TextField("240.10.0.100", text: $config.eidString)
                                .keyboardType(.numbersAndPunctuation)
                                .autocapitalization(.none)
                                .disableAutocorrection(true)
                                .font(.body.monospaced())
                                .focused($keyboardUp)
                                .onChange(of: config.eidString) { _, _ in config.save() }
                        }
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
                    Toggle("NAT-traversal", isOn: $config.natTraversalEnabled)
                        .onChange(of: config.natTraversalEnabled) { _, _ in config.save() }
                    Toggle("Decentralized-NAT", isOn: Binding(
                        get: { config.decentNATEnabled },
                        set: { on in
                            config.decentNATEnabled = on
                            config.save()
                            guard engine.running else { return }
                            on ? engine.installDecentNATEntry()
                               : engine.removeDecentNATEntry()
                        }))
                } header: {
                    centeredTitle("xTR Configuration")
                }

                Section {
                    TextField("suffix, e.g. ms.example.com", text: $config.decentSuffix)
                        .font(.body.monospaced())
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        .focused($keyboardUp)
                        .onChange(of: config.decentSuffix) { _, _ in config.save() }
                    Stepper("Modulus: \(config.decentModulus)",
                            value: $config.decentModulus, in: 0...255)
                        .onChange(of: config.decentModulus) { _, _ in config.save() }
                    SecureField("authentication-key", text: $config.decentAuthKey)
                        .font(.body.monospaced())
                        .focused($keyboardUp)
                        .onChange(of: config.decentAuthKey) { _, _ in config.save() }
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
                    centeredTitle("LISP-Decent Configuration")
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

                Section {
                    Toggle("Control-plane (all)", isOn: Binding(
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
                    Toggle("RLOC-probe only", isOn: Binding(
                        get: { config.rlocProbeLog },
                        set: { on in
                            config.rlocProbeLog = on; config.save()
                            engine.log.rlocProbeLogging = on
                        }))
                } header: {
                    centeredTitle("Logging")
                }
            }
            .navigationTitle("lispers.net xTR")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") { keyboardUp = false }
                }
            }
        }
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
            TextField("32", value: $prefix.lookupLength,
                      format: .number.grouping(.never))
                .keyboardType(.numberPad)
                .font(.body.monospaced())
                .frame(width: 36)
                .focused(keyboardUp)
                .disabled(!editing)
        }
    }
}
