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
    @State private var fontScale: CGFloat = 1.0
    // While true, the view sticks to the newest line and shows messages live as
    // they're issued; turned off by the up-arrow or any manual scroll.
    @State private var follow = true
    // Search: the magnifier toggles it; the up/down arrows become chevrons that
    // step through matches (starting at the bottom-most, moving up).
    @State private var searching = false
    @State private var searchText = ""
    @State private var matchIdx = 0
    @FocusState private var searchFocused: Bool
    @GestureState private var pinch: CGFloat = 1.0
    // Pinch-to-zoom the log font; the LazyVStack re-flows so scrolling stays good.
    private var zoom: CGFloat { min(max(fontScale * pinch, 0.6), 3.0) }
    private var magnify: some Gesture {
        MagnifyGesture()
            .updating($pinch) { v, state, _ in state = v.magnification }
            .onEnded { v in fontScale = min(max(fontScale * v.magnification, 0.6), 3.0) }
    }

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                let lines = log.lines[component] ?? []
                let hits = searching ? matchingLines(lines) : []
                let current = hits.indices.contains(matchIdx) ? hits[matchIdx] : -1
                let hitSet = Set(hits)
                VStack(spacing: 0) {
                    Picker("log", selection: $component) {
                        Text("lisp-core.log").tag(LogComponent.core)
                        Text("lisp-itr.log").tag(LogComponent.itr)
                        Text("lisp-etr.log").tag(LogComponent.etr)
                    }
                    .pickerStyle(.segmented)
                    .padding([.horizontal, .top])

                    if searching { searchBar(proxy, hitCount: hits.count) }

                    // Vertical scroll; lines wrap to the available width (portrait
                    // as before, landscape gives wider, fuller lines).
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(lines.enumerated()), id: \.offset) { i, line in
                                Self.colored(line)
                                    .font(.system(size: 11 * zoom, design: .monospaced))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(i == current ? Color.yellow.opacity(0.55)
                                        : hitSet.contains(i) ? Color.yellow.opacity(0.22)
                                        : Color.clear)
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
                    // Only auto-scroll to the newest line while "following" (the
                    // user is parked at the bottom). A manual drag turns following
                    // off so the view stays where they're reading.
                    .onChange(of: lines.count) { _, count in
                        if follow, count > 0 { proxy.scrollTo(count - 1, anchor: .bottom) }
                    }
                    .onChange(of: component) { _, _ in
                        follow = true
                        let n = (log.lines[component] ?? []).count
                        if n > 0 { proxy.scrollTo(n - 1, anchor: .bottom) }
                    }
                    .simultaneousGesture(magnify)
                    .simultaneousGesture(
                        DragGesture().onChanged { _ in if follow { follow = false } })
                }
                .navigationTitle("Logs")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    // Normal: up = top, down = bottom (bar-tipped arrows). Search:
                    // chevrons that step through matches. Magnifier toggles search.
                    ToolbarItem(placement: .topBarLeading) {
                        HStack(spacing: 8) {
                            Button {
                                if searching { gotoMatch(matchIdx - 1, proxy) }
                                else { follow = false; withAnimation { proxy.scrollTo(0, anchor: .top) } }
                            } label: {
                                Image(systemName: searching ? "chevron.up" : "arrow.up.to.line")
                                    .font(.caption2)
                            }
                            .tint(.primary)
                            Button {
                                if searching { gotoMatch(matchIdx + 1, proxy) }
                                else {
                                    follow = true
                                    if lines.count > 0 {
                                        withAnimation { proxy.scrollTo(lines.count - 1, anchor: .bottom) }
                                    }
                                }
                            } label: {
                                Image(systemName: searching ? "chevron.down" : "arrow.down.to.line")
                                    .font(.caption2)
                            }
                            .tint(.primary)
                            Button {
                                searching.toggle()
                                if searching { follow = false; searchFocused = true }
                                else { searchText = "" }
                            } label: {
                                Image(systemName: "magnifyingglass").font(.caption2)
                            }
                            .tint(searching ? .lispGreen : .primary)
                        }
                    }
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Clear") { log.clear(component) }
                    }
                }
            }
        }
    }

    // Search bar shown under the picker while searching. Typing re-anchors to the
    // bottom-most match; "n/total" shows the current position.
    private func searchBar(_ proxy: ScrollViewProxy, hitCount: Int) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").font(.footnote).foregroundStyle(.secondary)
            TextField("search", text: $searchText)
                .font(.system(.footnote, design: .monospaced))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .focused($searchFocused)
                .submitLabel(.search)
                .onChange(of: searchText) { _, _ in
                    let m = matchingLines(log.lines[component] ?? [])
                    matchIdx = max(0, m.count - 1)          // start at the bottom
                    if let line = m.last { withAnimation { proxy.scrollTo(line, anchor: .center) } }
                }
            if !searchText.isEmpty {
                Text("\(hitCount == 0 ? 0 : matchIdx + 1)/\(hitCount)")
                    .font(.caption2.monospaced()).foregroundStyle(.secondary)
                Button {
                    // Clearing exits search mode entirely: drop the search bar and
                    // the keyboard so the tab bar comes back.
                    searchText = ""
                    searching = false
                    searchFocused = false
                } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                }
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }

    // Indices of lines containing the search string (case-insensitive).
    private func matchingLines(_ lines: [String]) -> [Int] {
        guard !searchText.isEmpty else { return [] }
        let q = searchText.lowercased()
        return lines.indices.filter { lines[$0].lowercased().contains(q) }
    }

    // Move to match `idx` (clamped) and scroll it into view.
    private func gotoMatch(_ idx: Int, _ proxy: ScrollViewProxy) {
        let m = matchingLines(log.lines[component] ?? [])
        guard !m.isEmpty else { return }
        matchIdx = min(max(idx, 0), m.count - 1)
        withAnimation { proxy.scrollTo(m[matchIdx], anchor: .center) }
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
