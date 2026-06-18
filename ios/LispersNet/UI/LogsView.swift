//
// LogsView.swift
//
// Live viewers for lisp-core.log, lisp-itr.log, lisp-etr.log. The files are
// also on disk under Documents/logs/ (visible in the Files app via
// UIFileSharingEnabled) in the exact lprint() format.
//

import SwiftUI

struct LogsView: View {
    @ObservedObject var log = LispLog.shared
    @State private var component: LogComponent = .core

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("log", selection: $component) {
                    Text("lisp-core.log").tag(LogComponent.core)
                    Text("lisp-itr.log").tag(LogComponent.itr)
                    Text("lisp-etr.log").tag(LogComponent.etr)
                }
                .pickerStyle(.segmented)
                .padding()

                ScrollViewReader { proxy in
                    // Vertical scroll; lines wrap to the available width (portrait
                    // as before, landscape gives wider, fuller lines).
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            let lines = log.lines[component] ?? []
                            ForEach(Array(lines.enumerated()), id: \.offset) { i, line in
                                Self.colored(line)
                                    .font(.system(size: 11, design: .monospaced))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(i)
                            }
                            if lines.isEmpty {
                                Text("(no log lines — enable logging on the xTR tab)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .padding()
                            }
                        }
                        .padding(.horizontal, 8)
                    }
                    .onChange(of: (log.lines[component] ?? []).count) { _, count in
                        if count > 0 { proxy.scrollTo(count - 1, anchor: .bottom) }
                    }
                }
            }
            .navigationTitle("Logs")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                Button("Clear") { log.clear(component) }
            }
        }
    }

    // Color EID tokens "[<iid>]<addr>[/<mask>]" green, rloc-names "<x>@tp-<port>"
    // blue, and RLOC tokens "<addr>[:<port>]" red. Alternatives are ordered so
    // an EID's address / a name's digits aren't also flagged as an RLOC.
    private static let tokenRegex = try? NSRegularExpression(
        pattern: #"(\[\d+\][\d.]+(?:/\d+)?)|([\w.-]+@tp-\d+)|(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)"#)

    static func colored(_ line: String) -> Text {
        // Bold the leading "MM/dd/yy HH:mm:ss.SSS" timestamp (heavier than the
        // body so it stands out, but not a darker color).
        var body = line
        var stamp = Text("")
        if let r = line.range(of: #"^\d\d/\d\d/\d\d \d\d:\d\d:\d\d\.\d\d\d"#,
                              options: .regularExpression) {
            stamp = Text(String(line[r])).bold()
            body = String(line[r.upperBound...])
        }
        return stamp + tokens(body)
    }

    // Color EID (green), rloc-name (blue), and RLOC (red) tokens within text.
    private static func tokens(_ s: String) -> Text {
        guard let regex = tokenRegex else { return Text(s) }
        let ns = s as NSString
        var out = Text("")
        var last = 0
        for m in regex.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            if m.range.location > last {
                out = out + Text(ns.substring(with: NSRange(location: last,
                                              length: m.range.location - last)))
            }
            let token = ns.substring(with: m.range)
            let color: Color = m.range(at: 1).location != NSNotFound ? .lispGreen
                : m.range(at: 2).location != NSNotFound ? .lispBlue : .lispRed
            out = out + Text(token).foregroundColor(color)
            last = m.range.location + m.range.length
        }
        if last < ns.length { out = out + Text(ns.substring(from: last)) }
        return out
    }
}
