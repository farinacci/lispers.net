//
// LigView.swift
//
// LISP Internet Groper tab — mapping-system lookups. Type a hostname (from
// lisp-hosts) or an EID and tap "lig"; output renders like lisp-lig.py with
// green EID-prefix, red RLOCs, blue rloc-names, everything else black.
//

import SwiftUI
import UIKit

struct LigView: View {
    @EnvironmentObject var engine: LispEngine
    @EnvironmentObject var hosts: HostsFile
    @EnvironmentObject var lig: LigService
    @State private var eid = ""
    @State private var count = 1
    @State private var pubsub = false
    @State private var noInfo = false
    @State private var debug = false
    @State private var showShare = false         // Share the output as a color-coded image
    @State private var shareImage: UIImage?
    @FocusState private var keyboardUp: Bool
    @State private var fontScale: CGFloat = 1.0
    @GestureState private var pinch: CGFloat = 1.0

    // Pinch-to-zoom the lig output by scaling its monospaced font size.
    private var zoom: CGFloat { min(max(fontScale * pinch, 0.6), 3.0) }
    private var mono: Font { .system(size: 12 * zoom, design: .monospaced) }
    private var magnify: some Gesture {
        MagnifyGesture()
            .updating($pinch) { v, state, _ in state = v.magnification }
            .onEnded { v in fontScale = min(max(fontScale * v.magnification, 0.6), 3.0) }
    }

    private static let outputAnchor = "lig-output-top"

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                Form {
                    lookupSection
                    outputSection
                }
                .listRowSeparatorTint(.lispSeparator)
                .scrollDismissesKeyboard(.interactively)
                // On a fresh lig, jump the screen to the output so the rloc-set is
                // visible without scrolling past the lookup/params sections.
                .onChange(of: lig.output.count) { _, count in
                    guard count > 0 else { return }
                    withAnimation { proxy.scrollTo(Self.outputAnchor, anchor: .top) }
                }
                .navigationTitle("LIG")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .topBarTrailing) {
                        if !lig.output.isEmpty { Button("Clear") { lig.output = [] } }
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
                    // An explicit EID — "[iid]…", a 'distinguished-name', or a literal address
                    // — is ligged as typed so the instance-id and name survive. Anything else
                    // is treated as a hostname and resolved via lisp-hosts / DNS.
                    if input.hasPrefix("[") || input.contains("'")
                        || LispAddress(string: input) != nil {
                        lig.lookup(eidString: input, count: count,
                                   pubsub: pubsub, noInfo: noInfo, debug: debug)
                    } else {
                        hosts.resolveTarget(input) { addr in
                            guard let addr = addr else {
                                lig.output = [LigLine(content: .error("Cannot resolve \(input)"))]
                                return
                            }
                            lig.lookup(eidString: addr.addressString, count: count,
                                       pubsub: pubsub, noInfo: noInfo, debug: debug)
                        }
                    }
                } label: {
                    if lig.inFlight { ProgressView() } else { Text("lig it").bold() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!engine.running || eid.isEmpty || lig.inFlight)
            }
            Stepper("count: \(count)", value: $count, in: 1...5)
            Toggle("no-info", isOn: $noInfo)
            Toggle("debug", isOn: $debug)
            // Map-Request for our own EID, to see what the mapping system has
            // registered for us — last line of the section.
            Button {
                keyboardUp = false
                lig.lookup(eidString: engine.config.eidString, count: count,
                           pubsub: pubsub, noInfo: noInfo, debug: debug)
            } label: {
                HStack {
                    Spacer()
                    Text("LIG self").bold()
                    if !engine.config.eidString.isEmpty {
                        Text("[\(engine.config.instanceID)]\(engine.config.eidString)")
                            .font(.callout.monospaced())
                            .foregroundStyle(Color.lispGreen)
                    }
                    Spacer()
                }
            }
            .disabled(!engine.running || engine.config.eidString.isEmpty || lig.inFlight)
        } header: {
            Text("EID Mapping System Lookup")
                .frame(maxWidth: .infinity, alignment: .center)
        }
    }

    private var outputSection: some View {
        Section {
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
                .id(Self.outputAnchor)              // scroll target for auto-jump
                .simultaneousGesture(magnify)
            }
        } header: {
            Text("Output")
                .frame(maxWidth: .infinity, alignment: .center)
                .overlay(alignment: .trailing) {
                    if !lig.output.isEmpty {
                        Button { shareImage = makeShareImage(); showShare = true } label: {
                            Image(systemName: "square.and.arrow.up")
                        }
                    }
                }
        }
    }

    // Color EID (green), rloc-name (blue), RLOC (red) tokens — same scheme as the
    // Logs / Map-Cache views — so the debug lines match lisp-lig.py's coloring.
    // Group 1 = multicast (S,G) tuple "[iid](S/ml, G/ml)" -> green (an EID).
    private static let tokenRegex = try? NSRegularExpression(
        pattern: #"((?:\[\d+\])?\(\d{1,3}(?:\.\d{1,3}){3}/\d+,\s*\d{1,3}(?:\.\d{1,3}){3}/\d+\))|(\[\d+\][\d.]+(?:/\d+)?)|([\w.-]+@tp-\d+)|(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)"#)

    private static func coloredTokens(_ s: String, font: Font) -> Text {
        guard let regex = tokenRegex else { return Text(s).font(font) }
        let ns = s as NSString
        var out = Text("")
        var last = 0
        for m in regex.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            if m.range.location > last {
                out = out + Text(ns.substring(with: NSRange(location: last,
                                  length: m.range.location - last))).font(font)
            }
            let token = ns.substring(with: m.range)
            let color: Color = (m.range(at: 1).location != NSNotFound
                                || m.range(at: 2).location != NSNotFound) ? .lispGreen
                : m.range(at: 3).location != NSNotFound ? .lispBlue : .lispRed
            out = out + Text(token).font(font).foregroundColor(color)
            last = m.range.location + m.range.length
        }
        if last < ns.length { out = out + Text(ns.substring(from: last)).font(font) }
        return out
    }

    // Render the color-coded output to an image (wide → no wrap; light scheme so default text
    // is black on white), for the Share button.
    private var shareRenderView: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(lig.output) { line in
                lineView(line).frame(maxWidth: .infinity, alignment: .leading)
            }
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

    private func lineView(_ line: LigLine) -> Text {
        switch line.content {
        case .plain(let s):
            return Self.coloredTokens(s, font: mono)
        case .error(let s):
            return Text(s).font(mono).foregroundColor(.lispRed)
        case .send(let lead, let paren, let midTrail, let eid, let endTrail):
            return Text(lead).font(mono)
                 + Text(paren).font(mono).fontWeight(.heavy)
                 + Text(midTrail).font(mono)
                 + Text(eid).font(mono).bold().foregroundColor(.lispDarkGreen)
                 + Text(endTrail).font(mono)
        case .eidPrefix(let prefix, let rest):
            return Text("EID-prefix: ").font(mono)
                 + Text(prefix).font(mono).foregroundColor(.lispGreen)
                 + Text(rest).font(mono)
        case .mapReply(let from, let rtt):
            // from-RLOC red, rtt value orange + bold (between "rtt" and "secs").
            return Text("Received map-reply from ").font(mono)
                 + Text(from).font(mono).foregroundColor(.lispRed)
                 + Text(" with rtt ").font(mono)
                 + Text(rtt).font(mono).fontWeight(.heavy).foregroundColor(.orange)
                 + Text(" secs:").font(mono)
        case .rloc(let addr, let before, let name, let after, let addrIsRLE):
            var t = Text("  RLOC: ").font(mono)
                  + Text(addr).font(mono).foregroundColor(addrIsRLE ? .primary : .lispRed)
                  + Text(before).font(mono)
            if let n = name { t = t + Text(n).font(mono).foregroundColor(.lispBlue) }
            return t + Text(after).font(mono)
        case .rle(let m):
            // one member per line: "    rle: <ip> <name>" — indented 2 from the RLOC column
            // (RLOC starts at 2 spaces, so rle sits at 4); ip red, name blue.
            var t = Text("    rle: ").font(mono)
                  + Text(m.rloc).font(mono).foregroundColor(.lispRed)
            if let n = m.name { t = t + Text(" \(n)").font(mono).foregroundColor(.lispBlue) }
            return t
        }
    }
}
