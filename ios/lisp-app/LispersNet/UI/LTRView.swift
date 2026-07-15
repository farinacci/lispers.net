//
// LTRView.swift
//
// LISP Traceroute tab (ltr.py). Type a hostname (from lisp-hosts) or an EID and tap
// "ltr"; the accumulated encap/decap path renders EXACTLY like ltr.py — green EIDs,
// red RLOCs, blue node names, bold EIDs on the send line. The Output section is
// pinch-to-zoom, like LIG.
//

import SwiftUI

struct LTRView: View {
    @EnvironmentObject var engine: LispEngine
    @EnvironmentObject var hosts: HostsFile
    @EnvironmentObject var ltr: LTRService
    @State private var eid = ""
    @FocusState private var keyboardUp: Bool
    @State private var fontScale: CGFloat = 1.0
    @GestureState private var pinch: CGFloat = 1.0

    // Pinch-to-zoom the output by scaling its monospaced font size (same as LIG).
    private var zoom: CGFloat { min(max(fontScale * pinch, 0.6), 3.0) }
    private var mono: Font { .system(size: 12 * zoom, design: .monospaced) }
    private var magnify: some Gesture {
        MagnifyGesture()
            .updating($pinch) { v, state, _ in state = v.magnification }
            .onEnded { v in fontScale = min(max(fontScale * v.magnification, 0.6), 3.0) }
    }

    private static let outputAnchor = "ltr-output-top"

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                Form {
                    lookupSection
                    outputSection
                }
                .listRowSeparatorTint(.lispSeparator)
                .scrollDismissesKeyboard(.interactively)
                .onChange(of: ltr.output.count) { _, count in
                    guard count > 0 else { return }
                    withAnimation { proxy.scrollTo(Self.outputAnchor, anchor: .top) }
                }
                .navigationTitle("LTR")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .topBarTrailing) {
                        if !ltr.output.isEmpty { Button("Clear") { ltr.clear() } }
                    }
                }
            }
        }
    }

    private var lookupSection: some View {
        Section {
            HStack {
                TextField("EID or hostname", text: $eid)
                    .keyboardType(.asciiCapable)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                    .font(.body.monospaced())
                    .focused($keyboardUp)
                Button {
                    keyboardUp = false
                    let input = eid.trimmingCharacters(in: .whitespaces)
                    hosts.resolveTarget(input) { addr in
                        guard let addr = addr else {
                            ltr.output = [LTRLine(content: .error("Cannot resolve \(input)"))]
                            return
                        }
                        ltr.trace(target: addr.addressString)
                    }
                } label: {
                    if ltr.inFlight { ProgressView() } else { Text("Send").bold() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!engine.running || eid.isEmpty || ltr.inFlight)
            }
        } header: {
            Text("LISP Traceroute").frame(maxWidth: .infinity, alignment: .center)
        }
    }

    private var outputSection: some View {
        Section {
            if ltr.output.isEmpty {
                Text("No traces yet").foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(ltr.output) { line in
                        lineView(line)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                    }
                }
                .id(Self.outputAnchor)
                .simultaneousGesture(magnify)
            }
        } header: {
            Text("Output").frame(maxWidth: .infinity, alignment: .center)
        }
    }

    // ltr.py display_packet coloring: EID green, RLOC red (bold red if it has '?'),
    // node name blue; send-line EIDs bold.
    private func lineView(_ line: LTRLine) -> Text {
        switch line.content {
        case .plain(let s):
            return Text(s).font(mono)
        case .error(let s):
            return Text(s).font(mono).foregroundColor(.lispRed)
        case .sendRT(let seid, let deid):
            return Text("Send round-trip LISP-Trace between EIDs ").font(mono)
                 + Text(seid).font(mono).foregroundColor(.lispGreen)
                 + Text(" -> ").font(mono)
                 + Text(deid).font(mono).foregroundColor(.lispGreen)
                 + Text(" ...").font(mono)
        case .received(let source, let rtt):
            return Text("Received reply from ").font(mono)
                 + Text(source).font(mono).foregroundColor(.lispRed)
                 + Text(", rtt ").font(mono)
                 + Text(rtt).font(mono).fontWeight(.heavy).foregroundColor(.orange)
                 + Text(" secs").font(mono)
        case .pathHeader(let se, let de):
            return Text("Path from ").font(mono)
                 + Text(se).font(mono).foregroundColor(.lispGreen)
                 + Text(" to ").font(mono)
                 + Text(de).font(mono).foregroundColor(.lispGreen)
                 + Text(":").font(mono)
        case .hop(let n, let ed, let sr, let dr, let drError, let ts, let hn):
            var t = Text("  \(n) \(ed): ").font(mono)
                  + Text(sr).font(mono).foregroundColor(.lispRed)
                  + Text(" -> ").font(mono)
            t = t + (drError ? Text(dr).font(mono).bold().foregroundColor(.lispRed)
                             : Text(dr).font(mono).foregroundColor(.lispRed))
            return t + Text(", ts \(ts), node ").font(mono)
                     + Text(hn).font(mono).foregroundColor(.lispBlue)
        }
    }
}
