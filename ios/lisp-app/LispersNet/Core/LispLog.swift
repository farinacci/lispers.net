//
// LispLog.swift
//
// lprint()/dprint() equivalents. One logical process per component (core,
// itr, etr) so the log files read exactly like the Python trio:
//
//   06/10/26 14:32:45.123: itr: Send Map-Request ...
//
// Lines go to Documents/logs/lisp-<component>.log and to an in-memory ring
// observed by the UI.
//

import Foundation
import Combine

enum LogComponent: String, CaseIterable {
    case core, itr, etr

    var filename: String { "lisp-\(rawValue).log" }
}

final class LispLog: ObservableObject {
    static let shared = LispLog()

    // Independent logging scopes — each is its own UI switch. Control-plane
    // covers everything control-related, including RLOC-probing.
    var controlPlaneLogging = true      // all control-plane lines (incl. probes) + key events
    var dataPlaneLogging = false        // data-plane (encap/decap) lines + key events

    @Published private(set) var lines: [LogComponent: [String]] = [
        .core: [], .itr: [], .etr: []
    ]

    private let queue = DispatchQueue(label: "lisp.log")
    private var handles: [LogComponent: FileHandle] = [:]
    private let maxUILines = 2000

    static var logsDirectory: URL {
        let docs = FileManager.default.urls(for: .documentDirectory,
                                            in: .userDomainMask)[0]
        return docs.appendingPathComponent("logs", isDirectory: true)
    }

    private init() {
        try? FileManager.default.createDirectory(at: Self.logsDirectory,
                                                 withIntermediateDirectories: true)
    }

    private static let tsFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MM/dd/yy HH:mm:ss.SSS"   // lprint() timestamp
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()

    // lprint() — control-plane line.
    func lprint(_ component: LogComponent, _ message: String) {
        if controlPlaneLogging { emit(component, message) }
    }

    // dprint() — data-plane line.
    func dprint(_ component: LogComponent, _ message: String) {
        if dataPlaneLogging { emit(component, message) }
    }

    // pprint() — RLOC-probe line; folded into the control-plane scope.
    func pprint(_ component: LogComponent, _ message: String) {
        if controlPlaneLogging { emit(component, message) }
    }

    // fprint() — key event (registration, NAT, lifecycle).
    func fprint(_ component: LogComponent, _ message: String) {
        if controlPlaneLogging || dataPlaneLogging { emit(component, message) }
    }

    // aprint() — always logged, even when both logging scopes are off. Reserved
    // for the per-process startup banner so each log always records when the code
    // (re)started.
    func aprint(_ component: LogComponent, _ message: String) {
        emit(component, message)
    }

    private func emit(_ component: LogComponent, _ message: String) {
        let ts = Self.tsFormatter.string(from: Date())
        let line = "\(ts): \(component.rawValue): \(message)"
        queue.async {
            self.write(line: line, to: component)
            DispatchQueue.main.async {
                var l = self.lines[component] ?? []
                l.append(line)
                if l.count > self.maxUILines { l.removeFirst(l.count - self.maxUILines) }
                self.lines[component] = l
            }
        }
    }

    private func write(line: String, to component: LogComponent) {
        let url = Self.logsDirectory.appendingPathComponent(component.filename)
        if handles[component] == nil {
            if !FileManager.default.fileExists(atPath: url.path) {
                FileManager.default.createFile(atPath: url.path, contents: nil)
            }
            handles[component] = try? FileHandle(forWritingTo: url)
            _ = try? handles[component]?.seekToEnd()
        }
        if let data = (line + "\n").data(using: .utf8) {
            try? handles[component]?.write(contentsOf: data)
        }
    }

    func clear(_ component: LogComponent) {
        queue.async {
            try? self.handles[component]?.close()
            self.handles[component] = nil
            let url = Self.logsDirectory.appendingPathComponent(component.filename)
            try? FileManager.default.removeItem(at: url)
            DispatchQueue.main.async { self.lines[component] = [] }
        }
    }
}

// lisp_format_packet(): hex dump in 8-char groups.
func lispFormatPacket(_ data: Data) -> String {
    let hex = data.map { String(format: "%02x", $0) }.joined()
    var out: [String] = []
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let end = hex.index(idx, offsetBy: 8, limitedBy: hex.endIndex) ?? hex.endIndex
        out.append(String(hex[idx..<end]))
        idx = end
    }
    return out.joined(separator: " ")
}
