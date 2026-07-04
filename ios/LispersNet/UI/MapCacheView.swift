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
    @State private var fontScale: CGFloat = 1.0
    @GestureState private var pinch: CGFloat = 1.0
    // Pinch-to-zoom by scaling the monospaced font size, so the ScrollView
    // re-flows and scrolling stays correct (unlike .scaleEffect).
    private var zoom: CGFloat { min(max(fontScale * pinch, 0.6), 3.0) }
    private var mono: Font { .system(size: 11 * zoom, design: .monospaced) }
    private var magnify: some Gesture {
        MagnifyGesture()
            .updating($pinch) { v, state, _ in state = v.magnification }
            .onEnded { v in fontScale = min(max(fontScale * v.magnification, 0.6), 3.0) }
    }

    var body: some View {
        NavigationStack {
            // Vertical scroll; text wraps to the available width. Refreshes are
            // driven by engine.mapCacheVersion: every 500ms while data is being
            // encapsulated (packet-count flashes boldface), and on each RLOC-probe
            // reply when idle.
            ScrollView {
                Group {
                    let _ = engine.mapCacheVersion
                    VStack(alignment: .leading, spacing: 14) {
                        let entries = engine.mapCache.snapshot()
                        (Text("LISP Map-Cache for ") +
                         Text(engine.config.eidString.isEmpty ? "xTR" : engine.config.eidString).bold() +
                         Text(", entries \(entries.count)"))
                            .font(.system(size: 12 * zoom, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .center)

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
            .simultaneousGesture(magnify)
            .navigationTitle("Map-Cache")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func entryCard(_ e: LispMapCacheEntry) -> some View {
        let iface = engine.rloc?.interfaceName ?? "???"
        // Group multi-homing next-hops by RLOC address:port so the RLOC prints
        // ONCE with a per-interface stats+rtt line under it (lisp.py layout),
        // instead of repeating the RLOC line per interface.
        var groups: [[LispRLOC]] = []
        for r in e.rlocSet {
            if let i = groups.firstIndex(where: {
                $0[0].rloc.v4 == r.rloc.v4 && $0[0].encapPort == r.encapPort }) {
                groups[i].append(r)
            } else { groups.append([r]) }
        }
        return VStack(alignment: .leading, spacing: 3) {
            eidLine(e)
            ForEach(groups.indices, id: \.self) { gi in
                let hops = groups[gi]
                rlocLine(hops[0], groupUp: hops.contains { $0.isUp })
                ForEach(hops.indices, id: \.self) { hi in
                    statsLine(hops[hi], iface: iface)
                    // Only show rtts/hops/lats when RLOC-probing is on — with it
                    // off there's no telemetry, so the "[?, ?, ?]" line is noise.
                    if engine.config.rlocProbingEnabled, hops[hi].lastProbeSent != nil {
                        telemetryLine(hops[hi])
                    }
                }
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
    private func rlocLine(_ r: LispRLOC, groupUp: Bool? = nil) -> Text {
        var addr = r.rloc.addressString
        if r.encapPort != LISP.dataPort { addr += ":\(r.encapPort)" }
        // Multi-homing: the RLOC is up if ANY of its next-hops is up.
        let up = groupUp ?? r.isUp
        var t = Text("  RLOC ").font(mono)
            + Text(addr).font(mono).foregroundColor(.lispRed)
            + Text(", state ").font(mono)
            + Text(up ? "up-state" : "unreach-state").font(mono)
                .foregroundColor(up ? .lispGreen : .lispRed)
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
        // Multi-homing: label with this next-hop's own interface and put "*" on
        // the active (best-rtt) one. Single-homed: the up interface gets "*".
        let ifaceName = r.interfaceName ?? iface
        let active = (r.interfaceName != nil ? r.activeNextHop : r.isUp)
        var count = Text("\(r.packetCount)").font(mono)
        if let last = r.lastPacket {
            let dt = Date().timeIntervalSince(last)
            if dt <= 1 { count = count.fontWeight(.black).foregroundColor(.primary) }
            else if dt <= 60 { count = count.fontWeight(.black).foregroundColor(.lispGreen) }
        }
        // The "*" marking the selected outgoing interface is bold black; the
        // interface name stays blue.
        let star = active ? Text("*").font(mono).fontWeight(.black).foregroundColor(.primary)
                          : Text("")
        return Text("    ").font(mono)
            + star
            + Text(ifaceName).font(mono).foregroundColor(.lispBlue)
            + Text(": packet-count: ").font(mono)
            + count
            + Text(", packet-rate: 0 pps, byte-count: \(r.byteCount), " +
                   "bit-rate: 0.0 mbps").font(mono)
    }

    // rtts / hops / lats on ONE line. Landscape has the room to show all three
    // recents inline; in portrait the line stays single and scrolls horizontally
    // rather than wrapping.
    private func telemetryLine(_ r: LispRLOC) -> some View {
        let rtts = r.recentRTTs.isEmpty ? "?, ?, ?"
            : r.recentRTTs.map { fmtSecs($0) }.joined(separator: ", ")
        let hops = r.recentHops.isEmpty ? "?/?, ?/?, ?/?" : r.recentHops.joined(separator: ", ")
        let lats = r.recentLatencies.isEmpty ? "?/?, ?/?, ?/?"
            : r.recentLatencies.joined(separator: ", ")
        return ScrollView(.horizontal, showsIndicators: false) {
            Text("    rtts [\(rtts)], hops [\(hops)], lats [\(lats)]")
                .font(mono).foregroundStyle(.secondary)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
        }
    }
}
