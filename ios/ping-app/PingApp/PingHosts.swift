//
// PingHosts.swift  (PING app)
//
// Tappable host shortcuts (name -> EID), persisted locally. Same idea as the LISP
// app's lisp-hosts, but PING keeps its own list.
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
    @Published var entries: [PingHost] { didSet { save() } }
    private let key = "pingHosts.v1"

    init() {
        if let d = UserDefaults.standard.data(forKey: key),
           let h = try? JSONDecoder().decode([PingHost].self, from: d) {
            entries = h
        } else {
            entries = [
                PingHost(name: "lhr", address: "240.10.0.1"),
                PingHost(name: "frt", address: "240.10.0.2"),
                PingHost(name: "cmh", address: "240.10.0.8"),
            ]
        }
    }

    func add(name: String, address: String) {
        let n = name.trimmingCharacters(in: .whitespaces)
        let a = address.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty, LispWire.parseIPv4(a) != nil else { return }
        entries.append(PingHost(name: n, address: a))
    }
    func remove(at offsets: IndexSet) { entries.remove(atOffsets: offsets) }

    private func save() {
        if let d = try? JSONEncoder().encode(entries) { UserDefaults.standard.set(d, forKey: key) }
    }
}
