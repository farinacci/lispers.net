//
// HostsFile.swift
//
// The mini /etc/hosts, local to the app: Documents/lisp-hosts. Seeded with
// the three overlay targets; editable in the UI or via the Files app. The
// ping screen never hard-codes addresses.
//

import Foundation

struct HostEntry: Identifiable, Equatable {
    var id: String { name }
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

    static var fileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("lisp-hosts")
    }

    init() { load() }

    func load() {
        if !FileManager.default.fileExists(atPath: Self.fileURL.path) {
            try? Self.defaultContents.write(to: Self.fileURL, atomically: true,
                                            encoding: .utf8)
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
