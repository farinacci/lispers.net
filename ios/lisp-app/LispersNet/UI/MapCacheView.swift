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
            // Vertical scroll; text wraps to the available width. The engine bumps
            // mapCacheVersion once a second while running, which re-runs this body AND
            // (via the version passed into each MapCacheEntryCard) forces the entry
            // cards to re-read their live counts/rtts/uptime — the cards can't observe
            // the in-place mutations of their class-backed entry on their own.
            ScrollView {
                Group {
                    let _ = engine.mapCacheVersion
                    VStack(alignment: .leading, spacing: 14) {
                        let entries = engine.mapCache.snapshot()
                        // Title carries the local hostname (xTR tab override, else the
                        // learned system name), in blue — the lispers.net palette for
                        // names.
                        (Text("LISP Map-Cache for ") +
                         Text(engine.xtrName).bold().foregroundColor(.lispBlue) +
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
        MapCacheEntryCard(entry: e, iface: engine.rloc?.interfaceName ?? "???",
                          font: mono, showTelemetry: engine.config.rlocProbingEnabled,
                          version: engine.mapCacheVersion)
    }
}

// One map-cache entry in the lisp-mc.py layout — SHARED by the Map-Cache tab and
// the xTR share snapshot so they render IDENTICALLY (colors, fields, per-interface
// state + rtts/hops/lats). Group multi-homing next-hops by RLOC address:port.
struct MapCacheEntryCard: View {
    let entry: LispMapCacheEntry
    let iface: String                    // single-homed active interface (for "*")
    let font: Font
    let showTelemetry: Bool
    var scrollTelemetry: Bool = true     // tab scrolls the telemetry line; share wraps
    // A changing value that forces SwiftUI to re-render this card when the parent
    // refreshes. `entry` is a CLASS whose fields (uptime, packet-count, rtts) mutate
    // in place — SwiftUI can't see those mutations through the reference, so without
    // a changing input it skips this view's body and the display freezes at first
    // render. The Map-Cache tab feeds engine.mapCacheVersion here; the share leaves
    // it 0 (one-shot render).
    var version: Int = 0

    var body: some View { card() }

    private func card() -> some View {
        let e = entry
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
                    statsLine(hops[hi])
                    if showTelemetry, hops[hi].lastProbeSent != nil {
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
        var t = Text("EID ").font(font)
            + Text(prefix).font(font).foregroundColor(.lispGreen)
            + Text(", uptime \(formatHMS(e.uptime)), ttl \(e.ttlString)").font(font)
        if e.action != LISP.noAction {
            t = t + Text(", action ").font(font)
                  + Text(LISP.actionString(e.action)).font(font).bold()
        }
        return t
    }

    // RLOC <addr>, state <state> since …, p/w[, name]
    private func rlocLine(_ r: LispRLOC, groupUp: Bool? = nil) -> Text {
        var addr = r.rloc.addressString
        if r.encapPort != LISP.dataPort { addr += ":\(r.encapPort)" }
        let up = groupUp ?? r.isUp
        var t = Text("  RLOC ").font(font)
            + Text(addr).font(font).foregroundColor(.lispRed)
            + Text(", state ").font(font)
            + Text(up ? "up-state" : "unreach-state").font(font)
                .foregroundColor(up ? .lispGreen : .lispRed)
            + Text(" since \(formatHMS(r.stateChange)), p\(r.priority)/w\(r.weight)").font(font)
        if let name = r.rlocName {
            t = t + Text(", ").font(font) + Text(name).font(font).foregroundColor(.lispBlue)
        }
        return t
    }

    // *<iface>: packet-count …   (packet-count bold-black ≤1s / green ≤1min). No
    // per-interface up/unreach tag — the rtts line below tells whether probes are
    // being received on this outgoing interface; the RLOC line above is the only
    // reachability verdict (down only when ALL interfaces are down), matching lisp.py.
    private func statsLine(_ r: LispRLOC) -> Text {
        let ifaceName = r.interfaceName ?? iface
        let active = (r.interfaceName != nil ? r.activeNextHop : r.isUp)
        var count = Text("\(r.packetCount)").font(font)
        if let last = r.lastPacket {
            let dt = Date().timeIntervalSince(last)
            if dt <= 1 { count = count.fontWeight(.black).foregroundColor(.primary) }
            else if dt <= 60 { count = count.fontWeight(.black).foregroundColor(.lispGreen) }
        }
        let star = active ? Text("*").font(font).fontWeight(.black).foregroundColor(.primary)
                          : Text("")
        return Text("    ").font(font)
            + star
            + Text(ifaceName).font(font).foregroundColor(.lispBlue)
            + Text(": packet-count: ").font(font)
            + count
            + Text(", packet-rate: 0 pps, byte-count: \(r.byteCount), " +
                   "bit-rate: 0.0 mbps").font(font)
    }

    // rtts / hops / lats on ONE line. Tab scrolls it horizontally; the share wraps
    // (an ImageRenderer can't scroll, so it must show the whole line).
    @ViewBuilder private func telemetryLine(_ r: LispRLOC) -> some View {
        let rtts = r.recentRTTs.isEmpty ? "?, ?, ?"
            : r.recentRTTs.map { fmtSecs($0) }.joined(separator: ", ")
        let hops = r.recentHops.isEmpty ? "?/?, ?/?, ?/?" : r.recentHops.joined(separator: ", ")
        let lats = r.recentLatencies.isEmpty ? "?/?, ?/?, ?/?"
            : r.recentLatencies.joined(separator: ", ")
        let t = Text("    rtts [\(rtts)], hops [\(hops)], lats [\(lats)]")
            .font(font).foregroundStyle(.secondary)
        if scrollTelemetry {
            ScrollView(.horizontal, showsIndicators: false) {
                t.lineLimit(1).fixedSize(horizontal: true, vertical: false)
            }
        } else {
            t.fixedSize(horizontal: false, vertical: true)
        }
    }
}
