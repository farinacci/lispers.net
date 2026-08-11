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
    // Byte offset in each component's file recorded at Clear time: loadTail only shows bytes
    // AFTER this, so Clear takes effect immediately whether or not the extension truncates
    // (VPN-on) — and self-heals to 0 if the file is later truncated below the offset.
    private var clearedOffset: [LogComponent: Int] = [:]
    // Gate on file writes (not the in-memory ring). The app turns this OFF while mirroring
    // the extension (Option B) so it doesn't corrupt the extension's shared log files.
    private var fileWritesEnabled = true

    // Logs live in the shared App-Group container so that whichever process runs the
    // xTR — the app (VPN-off) OR the LispTunnel extension (Option B, VPN-on) — writes to
    // the SAME files, and the app's Logs tab reads them regardless of who produced them.
    // (Mode coordination guarantees only one engine runs at a time, so there are never
    // two concurrent writers.) Falls back to Documents if the container is unavailable.
    static var logsDirectory: URL {
        let base = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: OverlayTunnel.appGroup)
            ?? FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("logs", isDirectory: true)
    }

    private init() {
        try? FileManager.default.createDirectory(at: Self.logsDirectory,
                                                 withIntermediateDirectories: true)
    }

    // Debug aid: copy the App-Group log files into the app's OWN Documents/logs so they can be
    // pulled off-device with `devicectl device copy from --domain-type appDataContainer
    // --domain-identifier net.lispers.xtr --source Documents/logs`. The app-GROUP container
    // domain can't be copied (an Xcode `..`-path bug), but the app's own container copies fine.
    // Called from the app's 1 s mirror poll (EngineMirror.mirrorLogs) so the pullable copy stays
    // fresh while the Logs tab is open. No-op if the app is the writer (VPN-off) — same files.
    func copyToAppDocuments() {
        guard let docs = FileManager.default.urls(for: .documentDirectory,
                                                  in: .userDomainMask).first else { return }
        let dst = docs.appendingPathComponent("logs", isDirectory: true)
        let fm = FileManager.default
        try? fm.createDirectory(at: dst, withIntermediateDirectories: true)
        for c in LogComponent.allCases {
            let src = Self.logsDirectory.appendingPathComponent(c.filename)
            guard src != dst.appendingPathComponent(c.filename),   // group != Documents
                  fm.fileExists(atPath: src.path) else { continue }
            let out = dst.appendingPathComponent(c.filename)
            try? fm.removeItem(at: out)
            try? fm.copyItem(at: src, to: out)
        }
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

    // A shared "clear pending" marker. The mirroring app (which can't safely truncate a file
    // the extension has open) drops this; the owning writer truncates on its next write, and
    // loadTail shows empty until then. Lets the Logs-tab Clear button work in VPN-on mode.
    private func markerURL(_ c: LogComponent) -> URL {
        Self.logsDirectory.appendingPathComponent("lisp-\(c.rawValue).clear")
    }

    private func write(line: String, to component: LogComponent) {
        // In Option B mirror mode the app does NOT own the log files — the extension does,
        // and it writes them continuously. Two processes appending via cached FileHandle
        // offsets corrupt each other, so the app suppresses file writes while mirroring
        // (its in-memory ring still updates; the Logs tab shows the extension's files via
        // loadTail). Set false by startStateMirror, true by stopStateMirror.
        guard fileWritesEnabled else { return }
        // Honor a Clear the mirroring app requested: truncate this file before appending.
        if FileManager.default.fileExists(atPath: markerURL(component).path) {
            applyClear(component)
        }
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
            // Record the current file size as the display floor: loadTail hides everything up to
            // here, so the Clear sticks even if the extension never truncates. Also drop the
            // marker so the owning writer CAN truncate (keeps the file from growing forever), and
            // if WE own the files (VPN-off) truncate now. Always blank the ring for an instant UI.
            let url = Self.logsDirectory.appendingPathComponent(component.filename)
            self.clearedOffset[component] = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
            FileManager.default.createFile(atPath: self.markerURL(component).path, contents: nil)
            DispatchQueue.main.async { self.lines[component] = [] }
            if self.fileWritesEnabled { self.applyClear(component); self.clearedOffset[component] = 0 }
        }
    }

    // Truncate a component's log — owning writer only. Removes the file (a fresh empty one is
    // recreated on the next write) and clears the pending marker. Must run on `queue`.
    private func applyClear(_ component: LogComponent) {
        try? handles[component]?.close()
        handles[component] = nil
        try? FileManager.default.removeItem(
            at: Self.logsDirectory.appendingPathComponent(component.filename))
        try? FileManager.default.removeItem(at: markerURL(component))
    }

    // Option B mirror: load a component's in-memory ring from the tail of its on-disk
    // file. The app process doesn't run the engine in VPN-on mode — the LispTunnel
    // extension does, and it writes the real log FILES (shared App-Group dir). The app's
    // LogsView shows the in-memory ring, so the app tails those files into it for display.
    // Enable/disable on-disk writes (the app disables while mirroring the extension).
    // Dropping the cached handles forces the next write to re-open and seek-to-end — the
    // file may have grown while the extension owned it, so a stale offset would clobber it.
    func setFileWrites(_ enabled: Bool) {
        queue.async {
            self.fileWritesEnabled = enabled
            for (c, h) in self.handles { try? h.close(); self.handles[c] = nil }
        }
    }

    func loadTail(_ component: LogComponent, maxLines: Int = 2000) {
        let url = Self.logsDirectory.appendingPathComponent(component.filename)
        queue.async {
            guard let data = try? Data(contentsOf: url) else {
                DispatchQueue.main.async { self.lines[component] = [] }   // no file (e.g. just cleared)
                return
            }
            // Only show bytes AFTER the last Clear. Self-heal if the file was truncated below it.
            var start = self.clearedOffset[component] ?? 0
            if start > data.count { start = 0; self.clearedOffset[component] = 0 }
            let s = String(data: data.subdata(in: start..<data.count), encoding: .utf8) ?? ""
            let all = s.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            let tail = Array(all.suffix(maxLines))
            DispatchQueue.main.async { self.lines[component] = tail }
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
