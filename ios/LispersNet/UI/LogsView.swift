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
    // Grep/filter mode: show ONLY the lines containing the search string, instead of
    // the whole log with matches highlighted. Toggled by the funnel in the search bar.
    @State private var filterOnly = false
    @FocusState private var searchFocused: Bool
    // Colored HTML export (the share sheet for the .html version).
    @State private var htmlShareURL: URL?
    @State private var showHTMLShare = false
    // While searching, the displayed lines are FROZEN to this snapshot so live log
    // appends don't reflow the LazyVStack and jerk the view away from the match
    // you're reading. Re-taken when search is (re)entered or the component changes.
    @State private var searchSnapshot: [String] = []
    @GestureState private var pinch: CGFloat = 1.0
    // Pinch-to-zoom the log font; the LazyVStack re-flows so scrolling stays good.
    private var zoom: CGFloat { min(max(fontScale * pinch, 0.6), 3.0) }
    private var magnify: some Gesture {
        MagnifyGesture()
            .updating($pinch) { v, state, _ in state = v.magnification }
            .onEnded { v in fontScale = min(max(fontScale * v.magnification, 0.6), 3.0) }
    }

    // Lines to display: a frozen snapshot while searching (stable, so stepping
    // through matches never gets bumped by new log lines), live otherwise.
    private var displayLines: [String] {
        searching ? searchSnapshot : (log.lines[component] ?? [])
    }

    // The lines actually rendered: in grep/filter mode, only those containing the
    // search string; otherwise the full snapshot/live tail. All the hit/step/scroll
    // logic operates on THIS array so indices stay consistent.
    private var visibleLines: [String] {
        let base = displayLines
        guard searching, filterOnly, !searchText.isEmpty else { return base }
        let q = searchText.lowercased()
        return base.filter { $0.lowercased().contains(q) }
    }

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                let lines = visibleLines
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
                                    // Filter mode: every visible line matches, so only
                                    // the current-step line gets the bright highlight;
                                    // no faint wash on all of them.
                                    .background(i == current ? Color.yellow.opacity(0.55)
                                        : (!filterOnly && hitSet.contains(i)) ? Color.yellow.opacity(0.22)
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
                        // Switching logs while searching re-freezes to the new log;
                        // otherwise resume following the live tail.
                        if searching { searchSnapshot = log.lines[component] ?? [] }
                        follow = !searching
                        let n = visibleLines.count
                        if n > 0 { proxy.scrollTo(n - 1, anchor: .bottom) }
                    }
                    .onChange(of: filterOnly) { _, _ in
                        // Toggling grep changes which lines are shown; re-anchor to the
                        // bottom-most match so the count and highlight stay sensible.
                        let m = matchingLines(visibleLines)
                        matchIdx = max(0, m.count - 1)
                        if let last = m.last { withAnimation { proxy.scrollTo(last, anchor: .bottom) } }
                    }
                    .simultaneousGesture(magnify)
                    .simultaneousGesture(
                        DragGesture().onChanged { _ in
                            if follow { follow = false }
                            // Scrolling while searching hides the keyboard to give
                            // the log more screen real estate.
                            if searching { searchFocused = false }
                        })
                }
                .navigationTitle("Logs")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    // Normal: up = top, down = bottom (bar-tipped arrows). Search:
                    // chevrons that step through matches. Magnifier toggles search.
                    ToolbarItem(placement: .topBarLeading) {
                        // Small glyphs, but each gets a ~44pt thumb-sized hit area
                        // via a frame + contentShape so taps don't miss/collide.
                        HStack(spacing: 4) {
                            Button {
                                if searching { gotoMatch(matchIdx - 1, proxy) }
                                else { follow = false; withAnimation { proxy.scrollTo(0, anchor: .top) } }
                            } label: {
                                Image(systemName: searching ? "chevron.up" : "arrow.up.to.line")
                                    .font(.caption2)
                                    .frame(width: 38, height: 38)
                                    .contentShape(Rectangle())
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
                                    .frame(width: 38, height: 38)
                                    .contentShape(Rectangle())
                            }
                            .tint(.primary)
                            Button {
                                searching.toggle()
                                if searching {
                                    // Freeze the current lines so the search view
                                    // is stable while stepping through matches.
                                    searchSnapshot = log.lines[component] ?? []
                                    follow = false; searchFocused = true
                                } else { searchText = ""; filterOnly = false }
                            } label: {
                                Image(systemName: "magnifyingglass")
                                    .font(.caption2)
                                    .frame(width: 38, height: 38)
                                    .contentShape(Rectangle())
                            }
                            .tint(searching ? .lispGreen : .primary)
                        }
                    }
                    ToolbarItemGroup(placement: .topBarTrailing) {
                        // Share the current log: plain .log, or a colored .html
                        // export that preserves the on-screen syntax coloring.
                        Menu {
                            ShareLink("Plain text (.log)",
                                      item: LispLog.logsDirectory
                                        .appendingPathComponent(component.filename))
                            Button {
                                htmlShareURL = Self.htmlFile(for: component)
                                showHTMLShare = true
                            } label: { Label("Colored (.html)", systemImage: "paintpalette") }
                        } label: {
                            Image(systemName: "square.and.arrow.up")
                        }
                        Button("Clear") { log.clear(component) }
                    }
                }
                .sheet(isPresented: $showHTMLShare) {
                    if let u = htmlShareURL { ShareSheet(items: [u]) }
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
                    let m = matchingLines(visibleLines)
                    matchIdx = max(0, m.count - 1)          // start at the bottom
                    if let line = m.last { withAnimation { proxy.scrollTo(line, anchor: .center) } }
                }
            // Grep toggle: show only the matching lines (funnel fills green when on).
            Button { filterOnly.toggle() } label: {
                Image(systemName: filterOnly ? "line.3.horizontal.decrease.circle.fill"
                                             : "line.3.horizontal.decrease.circle")
                    .foregroundStyle(filterOnly ? Color.lispGreen : .secondary)
            }
            if !searchText.isEmpty {
                Text("\(hitCount == 0 ? 0 : matchIdx + 1)/\(hitCount)")
                    .font(.caption2.monospaced()).foregroundStyle(.secondary)
                Button {
                    // Clearing exits search mode entirely: drop the search bar and
                    // the keyboard so the tab bar comes back.
                    searchText = ""
                    searching = false
                    filterOnly = false
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
        let m = matchingLines(visibleLines)
        guard !m.isEmpty else { return }
        matchIdx = min(max(idx, 0), m.count - 1)
        withAnimation { proxy.scrollTo(m[matchIdx], anchor: .center) }
    }

    // Color EID tokens "[<iid>]<addr>[/<mask>]" green, rloc-names "<x>@tp-<port>"
    // blue, and RLOC tokens "<addr>[:<port>]" red. Alternatives are ordered so
    // an EID's address / a name's digits aren't also flagged as an RLOC.
    // Group 4 colors the startup banner's "hostname <name>" blue (it has no
    // @tp-port, so it wouldn't otherwise match the rloc-name rule).
    // Group 1 is the multicast (S,G) tuple "[iid](S/ml, G/ml)" — colored green
    // (it's an EID) before the RLOC rule can grab its dotted-quads as red.
    private static let tokenRegex = try? NSRegularExpression(
        pattern: #"((?:\[\d+\])?\(\d{1,3}(?:\.\d{1,3}){3}/\d+,\s*\d{1,3}(?:\.\d{1,3}){3}/\d+\))|(\[\d+\][\d.]+(?:/\d+)?)|([\w.-]+@tp-\d+)|(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)|((?<=hostname )[\w.-]+)"#)

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
        // Boldface every protocol keyword in the line (a line can have more than
        // one, e.g. "Send Map-Request (ECM) ..."); gaps keep token coloring.
        guard let bold = boldRegex else { return stamp + tokens(body) }
        let ns = body as NSString
        var out = stamp
        var last = 0
        for m in bold.matches(in: body, range: NSRange(location: 0, length: ns.length)) {
            if m.range.location > last {
                out = out + tokens(ns.substring(with: NSRange(location: last,
                                   length: m.range.location - last)))
            }
            out = out + Text(ns.substring(with: m.range)).fontWeight(.black)
            last = m.range.location + m.range.length
        }
        if last < ns.length { out = out + tokens(ns.substring(from: last)) }
        return out
    }

    // Boldface, deliberately sparingly:
    //  • the egress/ingress interface token (en*/pdp_ip*): after "Send "/"Receive "
    //    on the byte lines, and at the tail of Encap ("… to <if>") / Decap
    //    ("… from <if>"). Every OTHER message has no interface, so " to "/" from "
    //    only match those tails (elsewhere they're followed by an address);
    //  • the startup banner's version number after "version ";
    //  • the map-server DNS NAME on the "LISP-Decent map-server <n> -> <ip>" line
    //    ONLY (after "Decent map-server " — NOT the "Send Map-Register to map-server"
    //    line): a dotted token that contains a letter, so a bare IP isn't bolded;
    //  • the Encap/Decap keyword and the protocol-message keywords.
    // (No blanket "token after ->" or "(...)" rules — those wrongly bolded
    // record-ttl/flags/nonce and "(encap)".)
    private static let boldRegex = try? NSRegularExpression(pattern:
        #"(?<=Send )(?:en|pdp_ip)\w*|(?<=Receive )(?:en|pdp_ip)\w*|(?<= to )(?:en|pdp_ip)\w*|(?<= from )(?:en|pdp_ip)\w*|(?<=version )[\w.-]+|(?<=Decent map-server )(?=[\w.-]*[A-Za-z])[\w-]+(?:\.[\w-]+)+|Encap|Decap|RLOC-probe reply|RLOC-probe request|RLOC-probe|Map-Register|Map-Request|Map-Reply|Info-Request|Info-Reply|ECM"#)

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
            let color: Color = (m.range(at: 1).location != NSNotFound
                                || m.range(at: 2).location != NSNotFound) ? .lispGreen
                : m.range(at: 4).location != NSNotFound ? .lispRed : .lispBlue
            out = out + Text(token).foregroundColor(color)
            last = m.range.location + m.range.length
        }
        if last < ns.length { out = out + Text(ns.substring(from: last)) }
        return out
    }

    // MARK: colored HTML export
    // Render the on-disk log to an .html file that preserves the same coloring
    // (EID green, RLOC red, name/hostname blue, bold timestamp + keywords) so a
    // shared log keeps its syntax highlighting — plain .log/.txt cannot.

    private static func esc(_ s: String) -> String {
        var r = ""
        for c in s {
            switch c {
            case "&": r += "&amp;"
            case "<": r += "&lt;"
            case ">": r += "&gt;"
            default:  r.append(c)
            }
        }
        return r
    }

    // HTML for a gap with no keywords: color EID/rloc/name tokens (mirrors tokens()).
    private static func htmlTokens(_ s: String) -> String {
        guard let regex = tokenRegex else { return esc(s) }
        let ns = s as NSString
        var out = ""
        var last = 0
        for m in regex.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            if m.range.location > last {
                out += esc(ns.substring(with: NSRange(location: last,
                                        length: m.range.location - last)))
            }
            let cls = (m.range(at: 1).location != NSNotFound
                       || m.range(at: 2).location != NSNotFound) ? "eid"
                : m.range(at: 4).location != NSNotFound ? "rloc" : "name"
            out += "<span class=\"\(cls)\">\(esc(ns.substring(with: m.range)))</span>"
            last = m.range.location + m.range.length
        }
        if last < ns.length { out += esc(ns.substring(from: last)) }
        return out
    }

    // HTML for one log line (mirrors colored(): bold timestamp + keywords).
    private static func htmlLine(_ line: String) -> String {
        var body = line
        var out = ""
        if let r = line.range(of: #"^\d\d/\d\d/\d\d \d\d:\d\d:\d\d\.\d\d\d"#,
                              options: .regularExpression) {
            out = "<span class=\"ts\">\(esc(String(line[r])))</span>"
            body = String(line[r.upperBound...])
        }
        guard let bold = boldRegex else { return out + htmlTokens(body) }
        let ns = body as NSString
        var last = 0
        for m in bold.matches(in: body, range: NSRange(location: 0, length: ns.length)) {
            if m.range.location > last {
                out += htmlTokens(ns.substring(with: NSRange(location: last,
                                  length: m.range.location - last)))
            }
            out += "<b>\(esc(ns.substring(with: m.range)))</b>"
            last = m.range.location + m.range.length
        }
        if last < ns.length { out += htmlTokens(ns.substring(from: last)) }
        return out
    }

    static func htmlFile(for component: LogComponent) -> URL? {
        let src = LispLog.logsDirectory.appendingPathComponent(component.filename)
        let text = (try? String(contentsOf: src, encoding: .utf8)) ?? ""
        var rows = ""
        text.enumerateLines { line, _ in rows += Self.htmlLine(line) + "\n" }
        let doc = """
        <!DOCTYPE html><html><head><meta charset="utf-8">\
        <meta name="viewport" content="width=device-width, initial-scale=1">\
        <title>\(component.filename)</title>\
        <style>body{background:#fff;color:#111;\
        font:12px ui-monospace,Menlo,monospace;white-space:pre-wrap;\
        word-break:break-word;padding:10px}.ts{font-weight:700}\
        .eid{color:#298C29}.rloc{color:#C71F1F}.name{color:#3366F2}\
        b{font-weight:800}</style></head><body>\(rows)</body></html>
        """
        let out = FileManager.default.temporaryDirectory
            .appendingPathComponent(component.filename.replacingOccurrences(
                of: ".log", with: ".html"))
        try? doc.data(using: .utf8)?.write(to: out)
        return out
    }
}

// UIActivityViewController bridge for sharing the generated .html file.
struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
