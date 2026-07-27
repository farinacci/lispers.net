//
// GaapInbox.swift  (gaapchat — the READER side)
//
// Continuity: the always-on LISP xTR (the LispTunnel extension) keeps our group joined while
// we're suspended and appends every received group message to a shared App-Group file. We
// replay from that file, so messages that arrived while gaapchat was backgrounded show up on
// return. See the LISP app's GaapInbox for the file format.
//

import Foundation

enum GaapInbox {
    static let appGroup = "group.net.lispers.xtr"
    private static let defaults = UserDefaults(suiteName: appGroup)

    static var fileURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appendingPathComponent("gaap-inbox.bin")
    }

    // Ask the extension to keep this group joined (v4 host order) even while we're suspended.
    static func setSticky(_ g: UInt32) { defaults?.set(Int(g), forKey: "gaapStickyGroup") }
    static func clearSticky() { defaults?.set(0, forKey: "gaapStickyGroup") }

    // Read the records for `group` we haven't consumed yet; returns the inner packets in order.
    // Re-anchors to the file start if it was trimmed (generation bumped) or shrank.
    static func drain(group: UInt32) -> [Data] {
        guard let url = fileURL, let data = try? Data(contentsOf: url) else { return [] }
        let gen = defaults?.integer(forKey: "gaapInboxGen") ?? 0
        let readerGen = defaults?.integer(forKey: "gaapReaderGen") ?? -1
        var offset = defaults?.integer(forKey: "gaapReaderOffset") ?? 0
        if gen != readerGen || offset > data.count { offset = 0 }
        let bytes = [UInt8](data)
        var out: [Data] = []
        var i = offset
        while i + 8 <= bytes.count {
            let recGroup = u32(bytes, i)
            let len = Int(u32(bytes, i + 4))
            let end = i + 8 + len
            if end > bytes.count { break }              // partial trailing record — next time
            if recGroup == group { out.append(data.subdata(in: (i + 8)..<end)) }
            i = end
        }
        defaults?.set(i, forKey: "gaapReaderOffset")
        defaults?.set(gen, forKey: "gaapReaderGen")
        return out
    }

    // Mark the current backlog as already-seen (call on a fresh join so a new session doesn't
    // replay stale messages, e.g. from a previous group).
    static func seekToEnd() {
        var size = 0
        if let url = fileURL, let s = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize { size = s }
        defaults?.set(size, forKey: "gaapReaderOffset")
        defaults?.set(defaults?.integer(forKey: "gaapInboxGen") ?? 0, forKey: "gaapReaderGen")
    }

    private static func u32(_ b: [UInt8], _ i: Int) -> UInt32 {
        (UInt32(b[i]) << 24) | (UInt32(b[i+1]) << 16) | (UInt32(b[i+2]) << 8) | UInt32(b[i+3])
    }
}
