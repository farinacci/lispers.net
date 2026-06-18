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

                Section("EID Configuration") {
                    HStack(spacing: 6) {
                        Text("Instance-ID:")
                        TextField("0", value: $config.instanceID,
                                  format: .number.grouping(.never))
                            .keyboardType(.numberPad)
                            .font(.body.monospaced())
                            .frame(width: 60)
                            .focused($keyboardUp)
                            .onChange(of: config.instanceID) { _, _ in config.save() }
                        Text("EID:")
                        TextField("240.10.0.100", text: $config.eidString)
                            .keyboardType(.numbersAndPunctuation)
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                            .font(.body.monospaced())
                            .focused($keyboardUp)
                            .onChange(of: config.eidString) { _, _ in config.save() }
                    }
                }

                Section("xTR Configuration") {
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
                }

                Section("LISP-Decent Configuration") {
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
                                                    suffix: config.decentSuffix))
                            .font(.caption.monospaced())
                            .foregroundStyle(.blue)
                        }
                    }
                }

                Section("Logging") {
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
