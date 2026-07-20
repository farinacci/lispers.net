//
// HostsFile.swift
//
// The mini /etc/hosts, local to the app: Documents/lisp-hosts. Seeded with
// the three overlay targets; editable in the UI or via the Files app. The
// ping screen never hard-codes addresses.
//

import Foundation

struct HostEntry: Identifiable, Equatable {
    // Stable identity: a computed id == name churned the row's identity on every
    // keystroke while editing the name, so the TextField lost focus after one
    // character. A fixed UUID keeps the row (and its focus) alive across edits.
    let id = UUID()
    var name: String
    var address: String
}

final class HostsFile: ObservableObject {
    @Published private(set) var entries: [HostEntry] = []

    static let defaultContents = """
    #
    # lisp-hosts: <name> <eid-address>, one per line. Edit freely.
    #
    lhr 240.10.0.1
    frt 240.10.0.2
    cmh 240.10.0.8
    """

    static let appGroup = "group.net.lispers.xtr"

    // Stored in the SHARED App-Group container so overlay apps (PING, gaapchat) use the SAME
    // Hostname Configuration. Falls back to the app's Documents only if the container is
    // somehow unavailable.
    static var fileURL: URL {
        if let g = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) {
            return g.appendingPathComponent("lisp-hosts")
        }
        return legacyFileURL
    }
    // Pre-App-Group location (app's Documents) — read once to migrate into the shared file.
    static var legacyFileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("lisp-hosts")
    }

    // The seeded targets (lhr/frt/cmh) — parsed from defaultContents, not hard-coded.
    // The Ping tab shows these by default and tucks any added/imported hosts behind a
    // pull-down so a big imported /etc/hosts doesn't eat the screen.
    static let defaultNames: Set<String> = Set(
        defaultContents.split(separator: "\n").compactMap { line in
            let t = line.trimmingCharacters(in: .whitespaces)
            guard !t.isEmpty, !t.hasPrefix("#") else { return nil }
            return t.split(separator: " ").first.map(String.init)
        })

    init() { load() }

    func load() {
        let fm = FileManager.default
        if !fm.fileExists(atPath: Self.fileURL.path) {
            // First run after the App-Group move: migrate a legacy Documents/lisp-hosts into
            // the shared file; otherwise seed the defaults.
            if let legacy = try? String(contentsOf: Self.legacyFileURL, encoding: .utf8) {
                try? legacy.write(to: Self.fileURL, atomically: true, encoding: .utf8)
            } else {
                try? Self.defaultContents.write(to: Self.fileURL, atomically: true, encoding: .utf8)
            }
        }
        let text = (try? String(contentsOf: Self.fileURL, encoding: .utf8)) ?? ""
        entries = text.split(separator: "\n").compactMap { line in
            let t = line.trimmingCharacters(in: .whitespaces)
            guard !t.isEmpty, !t.hasPrefix("#") else { return nil }
            let parts = t.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 2 else { return nil }
            return HostEntry(name: String(parts[0]), address: String(parts[1]))
        }
    }

    func save(_ newEntries: [HostEntry]) {
        var text = "#\n# lisp-hosts: <name> <eid-address>, one per line.\n#\n"
        for e in newEntries { text += "\(e.name) \(e.address)\n" }
        try? text.write(to: Self.fileURL, atomically: true, encoding: .utf8)
        load()
    }

    func lookup(_ name: String) -> LispAddress? {
        guard let e = entries.first(where: { $0.name == name }) else { return nil }
        return LispAddress(string: e.address)
    }

    // Reverse lookup: EID address -> configured host name, if any. Compares on the
    // numeric address so "240.10.0.1" matches regardless of formatting.
    func name(for address: String) -> String? {
        guard let a = LispAddress(string: address) else {
            return entries.first { $0.address == address }?.name
        }
        return entries.first { LispAddress(string: $0.address)?.v4 == a.v4 }?.name
    }

    // Resolve a typed target to an EID: this lisp-hosts file first, then a literal
    // address, then a DNS name. DNS can block, so the result is delivered async on
    // the main thread (the hosts/literal cases still return synchronously-fast).
    func resolveTarget(_ input: String, completion: @escaping (LispAddress?) -> Void) {
        let s = input.trimmingCharacters(in: .whitespaces)
        if let eid = lookup(s) { completion(eid); return }
        if let eid = LispAddress(string: s) { completion(eid); return }
        DispatchQueue.global().async {
            let eid = DNS.resolve(s)
            DispatchQueue.main.async { completion(eid) }
        }
    }
}
