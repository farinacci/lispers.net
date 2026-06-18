//
// PingView.swift
//
// EID-to-EID ping. Targets come from the lisp-hosts file (lhr, frt, cmh by
// default) — never hard-coded. Includes an editor for the hosts file.
//

import SwiftUI

struct PingView: View {
    @EnvironmentObject var engine: LispEngine
    @EnvironmentObject var hosts: HostsFile
    @EnvironmentObject var ping: PingService
    @State private var editingHosts = false

    var body: some View {
        NavigationStack {
            List {
                Section("Ping an EID (from \(engine.config.eidString.isEmpty ? "our EID" : engine.config.eidString))") {
                    ForEach(hosts.entries) { entry in
                        Button {
                            if let eid = LispAddress(string: entry.address) {
                                ping.ping(name: entry.name, eid: eid)
                            }
                        } label: {
                            HStack {
                                Text(entry.name).bold()
                                Text(entry.address)
                                    .font(.callout.monospaced())
                                    .foregroundStyle(Color.lispGreen)
                                Spacer()
                                Image(systemName: "dot.radiowaves.left.and.right")
                            }
                        }
                        .disabled(!engine.running || ping.inFlight)
                    }
                    if !engine.running {
                        Text("Enable LISP on the xTR tab to ping.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }

                // Middle section: live feedback while a ping is in flight.
                Section("Active Ping") {
                    if ping.inFlight || !ping.active.isEmpty {
                        HStack(spacing: 8) {
                            ProgressView()
                            Text("Pinging \(ping.currentTarget ?? "")…").bold()
                        }
                        TimelineView(.periodic(from: .now, by: 0.2)) { _ in
                            ForEach(ping.active) { r in
                                HStack {
                                    Image(systemName: "dot.radiowaves.left.and.right")
                                        .foregroundStyle(Color.lispBlue)
                                    Text("seq \(r.sequence) → \(r.target)")
                                        .font(.caption.monospaced())
                                    Spacer()
                                    Text(String(format: "waiting %.1fs",
                                                Date().timeIntervalSince(r.sentAt)))
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    } else {
                        Text("No active ping").font(.caption).foregroundStyle(.secondary)
                    }
                }

                Section("Results") {
                    if ping.completed.isEmpty {
                        Text("No results yet").foregroundStyle(.secondary)
                    }
                    ForEach(ping.completed) { r in
                        let ok = r.status == .reply
                        HStack {
                            Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(ok ? Color.lispGreen : Color.lispRed)
                            Text("\(r.target) (\(r.address)) seq \(r.sequence)")
                                .font(.caption.monospaced())
                            Spacer()
                            Text(r.rttMs.map { "\($0) ms" } ?? "timeout")
                                .font(.caption.monospaced().bold())
                                .foregroundStyle(ok ? .primary : Color.lispRed)
                        }
                    }
                }
            }
            .navigationTitle("Ping")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                Button("Edit lisp-hosts") { editingHosts = true }
            }
            .sheet(isPresented: $editingHosts) {
                HostsEditor()
            }
        }
    }
}

struct HostsEditor: View {
    @EnvironmentObject var hosts: HostsFile
    @Environment(\.dismiss) private var dismiss
    @State private var working: [HostEntry] = []
    @State private var newName = ""
    @State private var newAddress = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("lisp-hosts (Documents/lisp-hosts)") {
                    ForEach($working) { $e in
                        HStack {
                            TextField("name", text: $e.name)
                            TextField("eid", text: $e.address)
                                .font(.body.monospaced())
                                .keyboardType(.decimalPad)
                        }
                    }
                    .onDelete { working.remove(atOffsets: $0) }
                }
                Section("add entry") {
                    HStack {
                        TextField("name", text: $newName)
                        TextField("eid address", text: $newAddress)
                            .font(.body.monospaced())
                            .keyboardType(.decimalPad)
                        Button("Add") {
                            guard !newName.isEmpty,
                                  LispAddress(string: newAddress) != nil else { return }
                            working.append(HostEntry(name: newName, address: newAddress))
                            newName = ""; newAddress = ""
                        }
                    }
                }
            }
            .navigationTitle("lisp-hosts")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { hosts.save(working); dismiss() }
                }
            }
            .onAppear { working = hosts.entries }
        }
    }
}
