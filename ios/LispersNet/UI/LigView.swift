//
// LigView.swift
//
// LISP Internet Groper tab — mapping-system lookups. Type a hostname (from
// lisp-hosts) or an EID and tap "lig"; output renders like lisp-lig.py with
// green EID-prefix, red RLOCs, blue rloc-names, everything else black.
//

import SwiftUI

struct LigView: View {
    @EnvironmentObject var engine: LispEngine
    @EnvironmentObject var hosts: HostsFile
    @EnvironmentObject var lig: LigService
    @State private var eid = ""
    @State private var count = 1
    @State private var pubsub = false
    @State private var noInfo = false
    @State private var debug = false
    @FocusState private var keyboardUp: Bool

    private let mono = Font.system(size: 12, design: .monospaced)

    var body: some View {
        NavigationStack {
            Form {
                lookupSection
                parametersSection
                outputSection
            }
            .navigationTitle("LIG")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    if !lig.output.isEmpty { Button("Clear") { lig.output = [] } }
                }
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") { keyboardUp = false }
                }
            }
        }
    }

    private var lookupSection: some View {
        Section("EID Mapping System Lookup") {
            HStack {
                TextField("hostname or EID, e.g. lhr or 240.10.0.1", text: $eid)
                    .keyboardType(.numbersAndPunctuation)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                    .font(.body.monospaced())
                    .focused($keyboardUp)
                Button {
                    keyboardUp = false
                    let input = eid.trimmingCharacters(in: .whitespaces)
                    let dest = hosts.lookup(input)?.addressString ?? input
                    lig.lookup(eidString: dest, count: count,
                               pubsub: pubsub, noInfo: noInfo, debug: debug)
                } label: {
                    if lig.inFlight { ProgressView() } else { Text("lig it").bold() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!engine.running || eid.isEmpty || lig.inFlight)
            }
        }
    }

    private var parametersSection: some View {
        Section("Parameters") {
            Stepper("count: \(count)", value: $count, in: 1...5)
            Toggle("pubsub (subscribe)", isOn: $pubsub)
            Toggle("no-info", isOn: $noInfo)
            Toggle("debug", isOn: $debug)
        }
    }

    private var outputSection: some View {
        Section("Output") {
            if lig.output.isEmpty {
                Text("No lookups yet").foregroundStyle(.secondary)
            } else {
                // One VStack row → no separators between output lines.
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(lig.output) { line in
                        lineView(line)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }

    private func lineView(_ line: LigLine) -> Text {
        switch line.content {
        case .plain(let s):
            return Text(s).font(mono)
        case .error(let s):
            return Text(s).font(mono).foregroundColor(.lispRed)
        case .send(let lead, let paren, let trail):
            return Text(lead).font(mono)
                 + Text(paren).font(mono).fontWeight(.heavy)
                 + Text(trail).font(mono)
        case .eidPrefix(let prefix, let rest):
            return Text("EID-prefix: ").font(mono)
                 + Text(prefix).font(mono).foregroundColor(.lispGreen)
                 + Text(rest).font(mono)
        case .rloc(let addr, let before, let name, let after):
            var t = Text("  RLOC: ").font(mono)
                  + Text(addr).font(mono).foregroundColor(.lispRed)
                  + Text(before).font(mono)
            if let n = name { t = t + Text(n).font(mono).foregroundColor(.lispBlue) }
            return t + Text(after).font(mono)
        }
    }
}
