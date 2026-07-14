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

struct ContentView: View {
    // App/build version — bump on every build (like the LISP + PING apps).
    static let version = "0.1"
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
    private let mono = Font.system(.body, design: .monospaced)

    // Launch the LISP app via its custom URL scheme (same as the PING app) so the user
    // can bring the xTR to the foreground straight from the "not running" hint.
    private func openLispApp() {
        if let url = URL(string: "lispxtr://") { openURL(url) }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            messageList
            Divider()
            inputBar
            Divider()
            commandBar
        }
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
                Text("as \(client.myid)").font(.caption2).foregroundStyle(.secondary)
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
                }
                .padding(12)
            }
            .scrollDismissesKeyboard(.interactively)    // pull the keyboard down by dragging
            .onChange(of: client.messages.count) { _, _ in
                if let last = client.messages.last { withAnimation { proxy.scrollTo(last.id, anchor: .bottom) } }
            }
        }
    }

    @ViewBuilder private func row(_ m: ChatMessage) -> some View {
        switch m.kind {
        case .info:
            Text(m.text).font(.caption.monospaced()).foregroundStyle(.secondary)
        case .mine:
            HStack { Spacer()
                Text(m.text).font(mono).padding(8)
                    .background(Color.gcBlue.opacity(0.15)).clipShape(RoundedRectangle(cornerRadius: 10))
            }
        case .data:
            (Text(m.sender + ": ").font(mono).bold().foregroundColor(.gcBlue)
             + Text(m.text).font(mono))
        case .ping, .pong:
            Text(m.text).font(mono)
                .foregroundColor(m.colorIndex.map { pingPalette[$0] } ?? .secondary)
        }
    }

    private var inputBar: some View {
        HStack(spacing: 8) {
            TextField(client.joined ? "enter message" : "join a group above", text: $input)
                .textFieldStyle(.roundedBorder).font(mono)
                .autocapitalization(.none).disableAutocorrection(true)
                .onSubmit { send() }
            Button { send() } label: { Image(systemName: "paperplane.fill") }
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
            cmdButton("help",    ":help",    "questionmark.circle")
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
