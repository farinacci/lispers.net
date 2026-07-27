//
// ContentView.swift  (gaapchat)
//
// Two tabs: Chat (the group conversation, matching the Python gaapchat UX — colored
// ping/pong, control commands) and Collide (a group-name → hashed-address / rehash-
// candidate viewer, like gaaphash.py, to spot group-address collisions).
//

import SwiftUI
import UIKit   // UIPasteboard (tap-to-copy the group address)

extension Color {
    static let gcBlue   = Color(red: 0.20, green: 0.40, blue: 0.95)
    static let gcGreen  = Color(red: 0.16, green: 0.55, blue: 0.16)
    static let gcRed    = Color(red: 0.78, green: 0.12, blue: 0.12)
    static let gcPurple = Color(red: 0.60, green: 0.20, blue: 0.80)
}
// Ping/pong sequence colors — Python: blue → green → red → purple.
let pingPalette: [Color] = [.gcBlue, .gcGreen, .gcRed, .gcPurple]

// Display name: drop the "user@" prefix, show just the host. The full "user@host" id is
// still used on the wire; this only affects what's shown in messages/history.
func hostOnly(_ id: String) -> String { id.components(separatedBy: "@").last ?? id }

struct ContentView: View {
    // App/build version — bump on every build (like the LISP + PING apps).
    static let version = "0.4"
    @State private var tab = 0
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                topTab("chat", 0)
                Spacer()
                Text(tab == 0 ? "gaapchat" : "gaaphash").font(.title3.bold())
                Spacer()
                topTab("hash", 1)
            }
            .padding(.horizontal, 20).padding(.top, 10).padding(.bottom, 6)
            Divider()
            if tab == 0 { ChatView() } else { CollideView() }
            Text("LISP gaapchat app version \(Self.version)")
                .font(.caption2).foregroundStyle(.secondary)
                .padding(.top, 2).padding(.bottom, 4)
        }
    }
    private func topTab(_ title: String, _ i: Int) -> some View {
        Button { tab = i } label: {
            Text(title).font(.headline)
                .foregroundStyle(tab == i ? Color.white : Color.gcBlue)
                .padding(.horizontal, 20).padding(.vertical, 7)
                .background(tab == i ? Color.gcBlue : Color.gcBlue.opacity(0.12))
                .clipShape(Capsule())
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Chat

struct ChatView: View {
    @EnvironmentObject var client: ChatClient
    @Environment(\.openURL) private var openURL
    @State private var groupField = ""
    @State private var input = ""
    @AppStorage("gcFontSize") private var fontSize: Double = 13   // pinch the message list to zoom
    @State private var zoomBase: Double? = nil
    private var mono: Font { .system(size: fontSize, design: .monospaced) }

    // Launch the LISP app via its custom URL scheme (same as the PING app) so the user
    // can bring the xTR to the foreground straight from the "not running" hint.
    private func openLispApp() {
        if let url = URL(string: "lispxtr://") { openURL(url) }
    }

    var body: some View {
        ZStack {
            VStack(spacing: 0) {
                header
                Divider()
                messageList
                Divider()
                inputBar
                Divider()
                commandBar
            }
            if client.showHistory {
                CenteredCard(title: "History",
                             height: cardHeight(items: historyCount, base: 160, per: 26),
                             onDone: { client.showHistory = false }) {
                    HistoryView().environmentObject(client)
                }
            }
            if client.showMembers {
                CenteredCard(title: "Members",
                             height: cardHeight(items: memberCount, base: 150, per: 44),
                             onDone: { client.showMembers = false }) {
                    MembersView().environmentObject(client)
                }
            }
        }
    }

    // Centered pop-up card sizing: grows with the list, capped at ~80% of the screen.
    private var memberCount: Int { Set(client.members + [client.myid]).count }
    private var historyCount: Int { client.messages.filter { $0.kind != .info }.count }
    private func cardHeight(items: Int, base: CGFloat, per: CGFloat) -> CGFloat {
        min(UIScreen.main.bounds.height * 0.8, base + CGFloat(items) * per)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Circle().fill(client.lispReady ? Color.gcGreen : .orange)
                    .frame(width: 11, height: 11)
                Text(client.lispReady ? "LISP xTR ready" : "LISP xTR not running")
                    .font(.subheadline).foregroundStyle(client.lispReady ? .primary : .secondary)
                if !client.lispReady {
                    Button("Open") { openLispApp() }
                        .buttonStyle(.borderedProminent).tint(.gcGreen).controlSize(.mini)
                        .font(.caption2)
                }
                Spacer()
                Text("you are \(hostOnly(client.myid))").font(.caption2).foregroundStyle(.secondary)
            }
            if client.joined {
                (Text("group-name ").foregroundStyle(.secondary)
                 + Text(client.groupName).bold().foregroundColor(.gcBlue)
                 + Text("  →  ").foregroundStyle(.secondary)
                 + Text(client.groupAddress).foregroundColor(.gcGreen))
                    .font(.caption.monospaced())
            } else {
                HStack {
                    TextField("enter group-name", text: $groupField)
                        .textFieldStyle(.roundedBorder)
                        .autocapitalization(.none).disableAutocorrection(true)
                        .onSubmit { join() }
                    Button("Join") { join() }
                        .buttonStyle(.borderedProminent).tint(.gcGreen)
                        .disabled(groupField.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(client.messages) { m in row(m).id(m.id) }
                    // Blank space below the last message so it isn't flush against the input
                    // bar and read as cut off. Scroll to THIS pad (not the last message) so
                    // the newest line always has room beneath it.
                    Color.clear.frame(height: 60).id("bottom-pad")
                }
                .padding(12)
            }
            .scrollDismissesKeyboard(.interactively)    // pull the keyboard down by dragging
            .gesture(MagnificationGesture()             // pinch to zoom text smaller/larger
                .onChanged { scale in
                    let base = zoomBase ?? fontSize
                    if zoomBase == nil { zoomBase = base }
                    fontSize = min(30, max(8, base * Double(scale)))
                }
                .onEnded { _ in zoomBase = nil })
            .onChange(of: client.messages.count) { _, _ in
                withAnimation { proxy.scrollTo("bottom-pad", anchor: .bottom) }
            }
        }
    }

    @ViewBuilder private func row(_ m: ChatMessage) -> some View {
        switch m.kind {
        case .info:
            if m.spans != nil { infoSpanText(m) }          // colored info (e.g. "Left group …")
            else { Text(m.text).font(mono).foregroundStyle(.secondary) }
        case .mine:
            HStack { Spacer()
                Text(m.text).font(mono).padding(8)
                    .background(Color.gcBlue.opacity(0.15)).clipShape(RoundedRectangle(cornerRadius: 10))
            }
        case .data:
            (Text(hostOnly(m.sender) + ": ").font(mono).bold().foregroundColor(.gcBlue)
             + Text(m.text).font(mono))
        case .ping, .pong:
            spanText(m)
        }
    }

    // Ping/pong rows: color ONLY the sequence number and the group address (EID),
    // like the Python app — everything else stays default. Falls back to plain text.
    private func spanText(_ m: ChatMessage) -> Text {
        guard let spans = m.spans else {
            return Text(m.text).font(mono)
                .foregroundColor(m.colorIndex.map { pingPalette[$0] } ?? .secondary)
        }
        let seqColor = m.colorIndex.map { pingPalette[$0] } ?? .primary
        return spans.reduce(Text("")) { acc, span in
            switch span {
            case .plain(let s): return acc + Text(s)
            case .seq(let s):   return acc + Text(s).foregroundColor(seqColor).bold()
            case .eid(let s):   return acc + Text(s).foregroundColor(.gcGreen)
            case .name(let s):  return acc + Text(hostOnly(s)).bold()
            }
        }.font(mono)
    }

    // Colored info lines (e.g. "Left group <name> at <ts>"): the group name (.name span, NOT a
    // user@host id here) in blue like the header; everything else secondary.
    private func infoSpanText(_ m: ChatMessage) -> Text {
        guard let spans = m.spans else {
            return Text(m.text).font(mono).foregroundColor(.secondary)
        }
        return spans.reduce(Text("")) { acc, span in
            switch span {
            case .plain(let s): return acc + Text(s).foregroundColor(.secondary)
            case .name(let s):  return acc + Text(s).foregroundColor(.gcBlue).bold()
            case .eid(let s):   return acc + Text(s).foregroundColor(.gcGreen)
            case .seq(let s):   return acc + Text(s).foregroundColor(.secondary)
            }
        }.font(mono)
    }

    private var inputBar: some View {
        HStack(spacing: 8) {
            TextField(client.joined ? "enter message" : "join a group above", text: $input)
                .textFieldStyle(.roundedBorder).font(mono)
                .autocapitalization(.none).disableAutocorrection(true)
                .onSubmit { send() }
            Button { send() } label: {
                Image(systemName: "arrow.up.circle.fill")           // iMessage-style send
                    .font(.title)
                    .symbolRenderingMode(.palette)
                    .foregroundStyle(.white, Color.gcBlue)
            }
            .disabled(input.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(10)
    }

    // The ":" commands as a tab-bar of buttons below the input (same as :help lists).
    private var commandBar: some View {
        HStack(spacing: 0) {
            cmdButton("show",    ":show",    "person.2")
            cmdButton("history", ":history", "clock")
            cmdButton("ping",    ":ping",    "dot.radiowaves.left.and.right")
            cmdButton("quit",    ":quit",    "rectangle.portrait.and.arrow.right")
        }
        .padding(.top, 4).padding(.bottom, 16)   // lift the buttons clear of the version line
    }
    private func cmdButton(_ label: String, _ cmd: String, _ icon: String) -> some View {
        Button { client.submit(cmd) } label: {
            VStack(spacing: 2) {
                Image(systemName: icon).font(.body)
                Text(label).font(.caption2)
            }
            .frame(maxWidth: .infinity)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(.tint)
    }

    private func join() {
        client.join(groupField)
        groupField = ""
    }
    private func send() {
        let t = input; input = ""
        client.submit(t)
    }
}

// MARK: - History (a dismissible window, not inline)

struct HistoryView: View {
    @EnvironmentObject var client: ChatClient
    private let mono = Font.system(size: 13, design: .monospaced)

    private var entries: [ChatMessage] { client.messages.filter { $0.kind != .info } }

    var body: some View {
        VStack(spacing: 0) {
            Text("Total messages sent/received: \(client.sentCount)/\(client.recvCount)")
                .font(.subheadline.bold())
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(Color.gcBlue.opacity(0.10))
            Divider()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    if entries.isEmpty {
                        Text("(no history yet)").font(mono).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        ForEach(entries) { m in historyRow(m).lineLimit(1).minimumScaleFactor(0.5) }
                    }
                }
                .padding(12)
            }
        }
    }

    private func opLabel(_ m: ChatMessage) -> String {
        switch m.kind {
        case .mine, .data: return "data"
        case .ping:        return "ping"
        case .pong:        return "pong"
        case .info:        return ""
        }
    }

    private func historyRow(_ m: ChatMessage) -> Text {
        // "<bold op> <sender>: <data>".
        Text(opLabel(m)).font(mono).bold()
        + Text(" \(hostOnly(m.sender)): ").font(mono)
        + Text(m.detail ?? m.text).font(mono)
    }
}

// MARK: - Members (a dismissible window, like History)

struct MembersView: View {
    @EnvironmentObject var client: ChatClient
    private let mono = Font.system(size: 13, design: .monospaced)

    // All members including self, most-recently-active first.
    private var ordered: [String] {
        let all = client.members.contains(client.myid) ? client.members
                                                       : client.members + [client.myid]
        return all.sorted { (client.lastSent[$0] ?? .distantPast) > (client.lastSent[$1] ?? .distantPast) }
    }

    var body: some View {
        VStack(spacing: 0) {
            Text("\(ordered.count) member\(ordered.count == 1 ? "" : "s")")
                .font(.subheadline.bold())
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(Color.gcBlue.opacity(0.10))
            Divider()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(ordered, id: \.self) { m in memberRow(m).lineLimit(1).minimumScaleFactor(0.5) }
                }
                .padding(12)
            }
        }
    }

    private func memberRow(_ m: String) -> Text {
        let now = Date()
        let joined = client.firstSeen[m].map { client.agoString(now.timeIntervalSince($0)) } ?? "never"
        let last = client.lastSent[m].map { client.agoString(now.timeIntervalSince($0)) } ?? "never"
        let short = m.components(separatedBy: "@").last ?? m   // drop "user@" for horizontal room
        return Text(short).font(mono).bold().foregroundColor(.gcBlue)
             + Text(" — joined \(joined), last sent \(last)").font(mono).foregroundColor(.secondary)
    }
}

// MARK: - Centered pop-up card (dimmed backdrop + a card centered on screen)

struct CenteredCard<Content: View>: View {
    let title: String
    let height: CGFloat
    let onDone: () -> Void
    @ViewBuilder var content: () -> Content

    var body: some View {
        GeometryReader { geo in
            ZStack {
                // Tap the dimmed backdrop to dismiss (in addition to Done).
                Color.black.opacity(0.35).ignoresSafeArea().onTapGesture(perform: onDone)
                VStack(spacing: 0) {
                    HStack {
                        Text(title).font(.headline).bold()
                        Spacer()
                        Button("Done", action: onDone).font(.headline)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 12)
                    .background(Color.gcBlue.opacity(0.10))
                    Divider()
                    content()          // the content's own ScrollView scrolls when it overflows
                }
                .frame(maxWidth: 400)
                // Clamp to the ACTUAL available height (not UIScreen, which was unreliable and
                // let the card grow past the screen — pushing Done off and leaving no way to
                // dismiss). The header (with Done) stays fixed; the content scrolls inside.
                .frame(height: min(height, geo.size.height * 0.85))
                .background(Color(.systemBackground))
                .clipShape(RoundedRectangle(cornerRadius: 18))
                .shadow(radius: 24)
                .frame(maxWidth: .infinity, maxHeight: .infinity)   // center within the geometry
            }
        }
    }
}

// MARK: - Collide (group-name hash viewer)

struct CollideView: View {
    @EnvironmentObject var client: ChatClient
    @State private var name = ""
    private let mono = Font.system(.body, design: .monospaced)

    var candidates: [(rehash: Int, name: String, address: String)] {
        let n = name.trimmingCharacters(in: .whitespaces)
        return n.isEmpty ? [] : GaapHash.candidates(n)
    }

    private var footerText: String {
        var s = "A group-name hashes to multicast group address "
        s += "224.<byte-2>.<byte-3>.<byte-4>. If more than one group-name hashes to "
        s += "the same group address, the GAAP protocol fixes the collision by "
        s += "rehashing with \"<group-name>+1\", \"<group-name>+2\", and "
        s += "\"<group-name>+3\"."
        return s
    }

    var body: some View {
        Form {
            Section {
                TextField("enter group-name", text: $name)
                    .autocapitalization(.none).disableAutocorrection(true).font(mono)
            } footer: {
                Text(footerText)
            }
            if !candidates.isEmpty {
                Section("Hashes of group-name to group address") {
                    ForEach(candidates, id: \.rehash) { c in
                        HStack {
                            (Text(c.rehash == 0 ? "primary" : "rehash \(c.rehash)")
                                .foregroundStyle(.secondary)
                             + Text("  \(c.name)").foregroundColor(.gcBlue))
                                .font(.caption.monospaced())
                            Spacer()
                            Text(c.address).font(mono).bold().foregroundColor(.gcGreen)
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { UIPasteboard.general.string = c.address }
                        .contextMenu {
                            Button {
                                UIPasteboard.general.string = c.address
                            } label: {
                                Label("Copy \(c.address)", systemImage: "doc.on.doc")
                            }
                        }
                    }
                }
            }
        }
        .onAppear { if name.isEmpty { name = client.groupName } }   // default to current group
    }
}
