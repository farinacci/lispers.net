//
// LTRView.swift
//
// LISP Traceroute tab (ltr.py). Type a hostname (from lisp-hosts) or an EID and tap
// "ltr"; the accumulated encap/decap path renders EXACTLY like ltr.py — green EIDs,
// red RLOCs, blue node names, bold EIDs on the send line. The Output section is
// pinch-to-zoom, like LIG.
//

import SwiftUI
import UIKit

struct LTRView: View {
    @EnvironmentObject var engine: LispEngine
    @EnvironmentObject var hosts: HostsFile
    @EnvironmentObject var ltr: LTRService
    @State private var eid = ""
    @State private var twoTraces = false        // one trace out each interface (forwarding-chosen RTR)
    @State private var fullMatrix = false        // every RTR × every interface
    @State private var showShare = false         // Share the output as a color-coded image
    @State private var shareImage: UIImage?
    @FocusState private var keyboardUp: Bool
    @State private var fontScale: CGFloat = 1.0
    @GestureState private var pinch: CGFloat = 1.0

    // Full Matrix wins if both are on (it's the superset).
    private var traceMode: LTRService.TraceMode {
        fullMatrix ? .fullMatrix : (twoTraces ? .twoTraces : .single)
    }

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
                .sheet(isPresented: $showShare) {
                    if let img = shareImage { ShareSheet(items: [img]) }
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
                    // An explicit EID ("[iid]…" or a literal address) is traced as typed so the
                    // instance-id survives; otherwise resolve it as a hostname.
                    if input.hasPrefix("[") || LispAddress(string: input) != nil {
                        ltr.trace(target: input, mode: traceMode)
                    } else {
                        hosts.resolveTarget(input) { addr in
                            guard let addr = addr else {
                                ltr.output = [LTRLine(content: .error("Cannot resolve \(input)"))]
                                return
                            }
                            ltr.trace(target: addr.addressString, mode: traceMode)
                        }
                    }
                } label: {
                    if ltr.inFlight { ProgressView() } else { Text("Send").bold() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!engine.running || eid.isEmpty || ltr.inFlight)
            }
            .alignmentGuide(.listRowSeparatorLeading) { _ in 0 }   // full-width divider above "ltr self"
            // Trace to our own EID — the path the mapping system has for us (mirrors "lig self").
            Button {
                keyboardUp = false
                ltr.trace(target: "[\(engine.config.instanceID)]\(engine.config.eidString)", mode: traceMode)
            } label: {
                HStack {
                    Spacer()
                    Text("LTR self").bold()
                    if !engine.config.eidString.isEmpty {
                        Text("[\(engine.config.instanceID)]\(engine.config.eidString)")
                            .font(.callout.monospaced())
                            .foregroundStyle(Color.lispGreen)
                    }
                    Spacer()
                }
            }
            .disabled(!engine.running || engine.config.eidString.isEmpty || ltr.inFlight)
            // Multi-path options — off = one trace via the normal forwarding path. Mutually
            // exclusive: turning one on turns the other off.
            Toggle("Multihoming Trace", isOn: $twoTraces).disabled(ltr.inFlight)
                .onChange(of: twoTraces) { _, on in if on { fullMatrix = false } }
            Toggle("Full-Matrix Trace", isOn: $fullMatrix).disabled(ltr.inFlight)
                .onChange(of: fullMatrix) { _, on in if on { twoTraces = false } }
        } header: {
            Text("LISP Traceroute").frame(maxWidth: .infinity, alignment: .center)
        }
    }

    @ViewBuilder private func rowView(_ line: LTRLine) -> some View {
        if case .divider = line.content {
            Divider()
        } else {
            lineView(line).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
        }
    }

    private var outputSection: some View {
        Section {
            if ltr.output.isEmpty {
                Text("No traces yet").foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(ltr.output) { rowView($0) }
                }
                .id(Self.outputAnchor)
                .simultaneousGesture(magnify)
            }
        } header: {
            Text("Output")
                .frame(maxWidth: .infinity, alignment: .center)
                .overlay(alignment: .trailing) {
                    if !ltr.output.isEmpty {
                        Button { shareImage = makeShareImage(); showShare = true } label: {
                            Image(systemName: "square.and.arrow.up")
                        }
                    }
                }
        }
    }

    // Render the color-coded output to an image (wide → no wrap; light scheme so default text
    // is black on white), for the Share button.
    private var shareRenderView: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(ltr.output) { rowView($0) }
        }
        .padding(12)
        .frame(width: 1100, alignment: .leading)
        .background(Color.white)
        .environment(\.colorScheme, .light)
    }
    @MainActor private func makeShareImage() -> UIImage? {
        let r = ImageRenderer(content: shareRenderView)
        r.scale = 3
        return r.uiImage
    }

    // An overlay unicast EID literal: an IPv4 in 240/4 (first octet >= 240). A round-trip
    // reply from the target EID is green; a reply from any other (RLOC) address means an xTR
    // returned an error hop, so it stays red.
    private static func isEIDAddress(_ s: String) -> Bool {
        let host = s.split(separator: ":").first.map(String.init) ?? s
        let octets = host.split(separator: ".")
        guard octets.count == 4, let first = Int(octets[0]) else { return false }
        return first >= 240 && first <= 255
    }

    // ltr.py display_packet coloring: EID green, RLOC red (bold red if it has '?'),
    // node name blue; send-line EIDs bold.
    private func lineView(_ line: LTRLine) -> Text {
        switch line.content {
        case .plain(let s):
            return Text(s).font(mono)
        case .title(let s):
            return Text(s).font(mono).bold()
        case .matrixTitle(let rloc, let iface):
            return Text("Full-Matrix Trace - send to RLOC ").font(mono).bold()
                 + Text(rloc).font(mono).bold().foregroundColor(.lispRed)
                 + Text(" out \(iface)").font(mono).bold()
        case .divider:
            return Text("")                 // rendered as a real Divider() by rowView()
        case .error(let s):
            return Text(s).font(mono).foregroundColor(.lispRed)
        case .learning(let addr):
            var t = Text("Learning translation (Info-Request) ...").font(mono)
            if let a = addr {
                t = t + Text(" translated address ").font(mono)
                      + Text(a).font(mono).foregroundColor(.lispRed)
            }
            return t
        case .sendRT(let seid, let deid):
            return Text("Send round-trip LISP-Trace between EIDs ").font(mono)
                 + Text(seid).font(mono).foregroundColor(.lispGreen)
                 + Text(" -> ").font(mono)
                 + Text(deid).font(mono).foregroundColor(.lispGreen)
                 + Text(" ...").font(mono)
        case .natTraversal(let rtr):
            return Text("Send NAT-traversal LISP-Trace to RTR ").font(mono)
                 + Text(rtr).font(mono).foregroundColor(.lispRed)
                 + Text(" ...").font(mono)
        case .received(let source, let rtt):
            // The reply source is green when it's an overlay EID (224/4 or 240/4 — a
            // round-trip reply comes back FROM the target EID), red when it's an RLOC/RTR.
            let srcColor: Color = Self.isEIDAddress(source) ? .lispGreen : .lispRed
            return Text("Received reply from ").font(mono)
                 + Text(source).font(mono).foregroundColor(srcColor)
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
