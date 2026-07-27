//
// GaapInbox.swift  (LISP xTR app / LispTunnel extension — the WRITER side)
//
// Continuity for gaapchat: gaapchat is an ordinary app that iOS SUSPENDS seconds after it
// is backgrounded, so it misses group messages and its (*,G) soft-state lapses. The always-
// on xTR (this process) bridges the gap:
//
//   • Sticky join — gaapchat writes the group it wants kept joined to a shared App-Group
//     marker; expireIGMPGroups() never ages that group out, so the phone keeps receiving the
//     group's traffic while gaapchat is away.
//   • Inbox — every received group chat message is appended to a shared App-Group file that
//     gaapchat replays on return, so nothing that arrived while it was suspended is lost.
//
// Wire of the file: a sequence of records, each [UInt32 group-v4 BE][UInt32 len BE][len bytes
// = the raw inner IP packet, exactly what forwardUDPToOverlayApp delivers]. The reader
// (gaapchat's own GaapInbox) tracks a byte offset + a generation counter we bump on trim.
//

import Foundation

enum GaapInbox {
    static let appGroup = "group.net.lispers.xtr"
    static let maxRecords = 500                 // ring-buffer cap (older messages age out)
    private static let defaults = UserDefaults(suiteName: appGroup)

    static var fileURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appendingPathComponent("gaap-inbox.bin")
    }

    // The group gaapchat wants kept joined (v4 host order); 0 = none. Written by gaapchat.
    static var stickyGroup: UInt32 {
        UInt32(exactly: defaults?.integer(forKey: "gaapStickyGroup") ?? 0) ?? 0
    }

    // Append one received group chat message (the raw inner IP packet) for group `g`.
    static func append(_ inner: Data, group g: UInt32) {
        guard let url = fileURL else { return }
        var rec = Data()
        putU32(&rec, g); putU32(&rec, UInt32(inner.count)); rec.append(inner)
        if let fh = try? FileHandle(forWritingTo: url) {
            defer { try? fh.close() }
            fh.seekToEndOfFile(); fh.write(rec)
        } else {
            try? rec.write(to: url)             // first write creates the file
        }
        if let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize,
           size > maxRecords * 256 { trim(url) }
    }

    // Keep only the last maxRecords whole records; bump the generation so the reader knows to
    // re-anchor its offset (a rewrite shifts every byte position).
    private static func trim(_ url: URL) {
        guard let data = try? Data(contentsOf: url) else { return }
        let bytes = [UInt8](data)
        var ranges: [Range<Int>] = []
        var i = 0
        while i + 8 <= bytes.count {
            let len = Int(getU32(bytes, i + 4))
            let end = i + 8 + len
            if end > bytes.count { break }
            ranges.append(i..<end); i = end
        }
        guard ranges.count > maxRecords else { return }
        var out = Data()
        for r in ranges.suffix(maxRecords) { out.append(data.subdata(in: r)) }
        try? out.write(to: url)
        defaults?.set((defaults?.integer(forKey: "gaapInboxGen") ?? 0) + 1, forKey: "gaapInboxGen")
    }

    private static func putU32(_ d: inout Data, _ v: UInt32) {
        var b = v.bigEndian; withUnsafeBytes(of: &b) { d.append(contentsOf: $0) }
    }
    private static func getU32(_ b: [UInt8], _ i: Int) -> UInt32 {
        (UInt32(b[i]) << 24) | (UInt32(b[i+1]) << 16) | (UInt32(b[i+2]) << 8) | UInt32(b[i+3])
    }
}
