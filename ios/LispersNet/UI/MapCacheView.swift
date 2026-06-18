//
// MapCacheView.swift
//
// The map-cache rendered in the lisp-mc.py layout and color scheme:
// green EID prefixes, red RLOC addresses, green up-state / red unreach-state,
// blue RLOC-names and the active interface.
//

import SwiftUI

struct MapCacheView: View {
    @EnvironmentObject var engine: LispEngine
    private let mono = Font.system(size: 11, design: .monospaced)

    var body: some View {
        NavigationStack {
            // Vertical scroll; text wraps to the available width (so portrait
            // looks as before and landscape just gives wider, fuller lines). The
            // TimelineView refreshes the content once a second for live uptimes
            // and the packet-count coloring.
            ScrollView {
                TimelineView(.periodic(from: .now, by: 1)) { _ in
                    VStack(alignment: .leading, spacing: 14) {
                        let entries = engine.mapCache.snapshot()
                        (Text("LISP Map-Cache for ") +
                         Text(engine.config.eidString.isEmpty ? "xTR" : engine.config.eidString).bold() +
                         Text(", entries \(entries.count)"))
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)

                        if entries.isEmpty {
                            Text("Map-cache is empty.")
                                .font(.callout).foregroundStyle(.secondary)
                        }

                        ForEach(entries, id: \.uptime) { entry in
                            entryCard(entry)
                        }
                    }
                    .padding()
                }
            }
            .navigationTitle("Map-Cache")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func entryCard(_ e: LispMapCacheEntry) -> some View {
        let iface = engine.rloc?.interfaceName ?? "???"
        return VStack(alignment: .leading, spacing: 3) {
            eidLine(e)
            ForEach(Array(e.rlocSet.enumerated()), id: \.offset) { _, r in
                rlocLine(r)
                statsLine(r, iface: iface)
                if r.lastProbeSent != nil { telemetryLine(r) }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    // EID [0]240.10.0.6/32, uptime …, ttl 1440m[, action …]   (prefix green)
    private func eidLine(_ e: LispMapCacheEntry) -> Text {
        let prefix = e.isMulticast
            ? "[\(e.eid.instanceID)](\(e.eid.addressString)/\(e.eid.maskLen), " +
              "\(e.group.addressString)/\(e.group.maskLen))"
            : "[\(e.eid.instanceID)]\(e.eid.addressString)/\(e.eid.maskLen)"
        var t = Text("EID ").font(mono)
            + Text(prefix).font(mono).foregroundColor(.lispGreen)
            + Text(", uptime \(formatHMS(e.uptime)), ttl \(e.ttlString)").font(mono)
        if e.action != LISP.noAction {
            t = t + Text(", action ").font(mono)
                  + Text(LISP.actionString(e.action)).font(mono).bold()
        }
        return t
    }

    // RLOC <addr>, state <state> since …, p/w[, name]   (addr red, state
    // green/red, name blue)
    private func rlocLine(_ r: LispRLOC) -> Text {
        var addr = r.rloc.addressString
        if r.encapPort != LISP.dataPort { addr += ":\(r.encapPort)" }
        var t = Text("  RLOC ").font(mono)
            + Text(addr).font(mono).foregroundColor(.lispRed)
            + Text(", state ").font(mono)
            + Text(r.state).font(mono).foregroundColor(r.isUp ? .lispGreen : .lispRed)
            + Text(" since \(formatHMS(r.stateChange)), p\(r.priority)/w\(r.weight)").font(mono)
        if let name = r.rlocName {
            t = t + Text(", ").font(mono) + Text(name).font(mono).foregroundColor(.lispBlue)
        }
        return t
    }

    // *<iface>: packet-count: …   ("*<iface>" blue; packet-count bold-black if a
    // packet was encapsulated in the last second, bold-green within the last
    // minute, plain otherwise — mirrors lisp-mc.py print_stats()).
    private func statsLine(_ r: LispRLOC, iface: String) -> Text {
        let active = r.isUp ? "*" : ""
        var count = Text("\(r.packetCount)").font(mono)
        if let last = r.lastPacket {
            let dt = Date().timeIntervalSince(last)
            if dt <= 1 { count = count.fontWeight(.black).foregroundColor(.primary) }
            else if dt <= 60 { count = count.fontWeight(.black).foregroundColor(.lispGreen) }
        }
        return Text("    ").font(mono)
            + Text("\(active)\(iface)").font(mono).foregroundColor(.lispBlue)
            + Text(": packet-count: ").font(mono)
            + count
            + Text(", packet-rate: 0 pps, byte-count: \(r.byteCount), " +
                   "bit-rate: 0.0 mbps").font(mono)
    }

    private func telemetryLine(_ r: LispRLOC) -> Text {
        let rtts = r.recentRTTs.isEmpty ? "?, ?, ?"
            : r.recentRTTs.map { fmtSecs($0) }.joined(separator: ", ")
        let hops = r.recentHops.isEmpty ? "?/?, ?/?, ?/?" : r.recentHops.joined(separator: ", ")
        let lats = r.recentLatencies.isEmpty ? "?/?, ?/?, ?/?"
            : r.recentLatencies.joined(separator: ", ")
        return Text("    rtts [\(rtts)], hops [\(hops)], lats [\(lats)]")
            .font(mono).foregroundStyle(.secondary)
    }
}
