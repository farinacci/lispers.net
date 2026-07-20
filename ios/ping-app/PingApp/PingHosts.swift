//
// PingHosts.swift  (PING app)
//
// Tappable host shortcuts (name -> EID). These come from the SAME shared "lisp-hosts" file
// the LISP xTR app's Hostname Configuration writes (App-Group container), so PING uses the
// LISP app's hostnames. Edits here write back to that shared file, so they also show up in
// the LISP app. Nothing is seeded here — the LISP app owns creating/migrating the file — so
// running PING first never clobbers the LISP app's Hostname Configuration.
//

import Foundation
import Combine

struct PingHost: Identifiable, Codable, Hashable {
    var id = UUID()
    var name: String
    var address: String
}

@MainActor
final class PingHosts: ObservableObject {
    // READ-ONLY in PING: the Hostname Configuration is owned by the LISP xTR app. PING only
    // reads the shared file; to add/edit/delete a host the user goes to the LISP xTR app.
    @Published private(set) var entries: [PingHost] = []

    static let appGroup = "group.net.lispers.xtr"
    private static var fileURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appendingPathComponent("lisp-hosts")
    }
    // Shown only until the LISP xTR app has created the shared file (not persisted here).
    private static let defaultEntries = [
        PingHost(name: "lhr", address: "240.10.0.1"),
        PingHost(name: "frt", address: "240.10.0.2"),
        PingHost(name: "cmh", address: "240.10.0.8"),
    ]

    init() { entries = Self.loadEntries() }

    // Re-read the shared file — called when the app returns to the foreground, since the LISP
    // xTR app may have edited the Hostname Configuration meanwhile.
    func reload() {
        let loaded = Self.loadEntries()
        let same = loaded.count == entries.count &&
            zip(loaded, entries).allSatisfy { $0.name == $1.name && $0.address == $1.address }
        if !same { entries = loaded }
    }

    private static func loadEntries() -> [PingHost] {
        guard let url = fileURL, let text = try? String(contentsOf: url, encoding: .utf8) else {
            return defaultEntries
        }
        return parse(text)
    }
    // "<name> <eid-address> [aliases]" per line; blank/comment (#) lines skipped.
    private static func parse(_ text: String) -> [PingHost] {
        text.split(separator: "\n").compactMap { line in
            let t = line.trimmingCharacters(in: .whitespaces)
            guard !t.isEmpty, !t.hasPrefix("#") else { return nil }
            let parts = t.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard parts.count >= 2 else { return nil }
            return PingHost(name: parts[0], address: parts[1])
        }
    }

}
