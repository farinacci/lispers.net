//
// IGMP.swift
//
// Group membership for the overlay is driven ENTIRELY by IGMPv2 (soft-state). Every
// membership Report — whether from an overlay app (gaapchat, over the tunnel) or the LISP
// app self-reporting its own manually-joined groups — TRIGGERS a (*,G) Map-Register. There
// is no separate periodic multicast-register timer: the report cadence IS the register
// cadence (gaapchat + the LISP self-report timer both re-report ~every 60s). The unicast
// EID keeps its own Map-Register timer. A group with no Report within LISP.igmpGroupTimeout
// is expired + de-registered; an explicit Leave de-registers immediately.
//
// The joining app appends its name to the IGMP packet (after the 8-byte message) so the
// xTR can label each group by who joined it — the LISP app's own self-reports carry
// "LISP app"; gaapchat carries "gaapchat".
//

import Foundation
import Darwin

// One overlay-app-joined group, for the LOCKED display in the Multicast Groups list.
struct AppJoinedGroup: Identifiable, Hashable {
    var address: String
    var source: String                          // the app that joined it (e.g. "gaapchat")
    var lastReport: Date                         // when the most recent IGMP report arrived
    var id: String { address }
}

extension LispEngine {
    static let manualIGMPSource = "LISP app"

    // Parse an IGMPv2 packet injected over the tunnel (proto 2): type(1), max-resp(1),
    // checksum(2), group(4), then an optional trailing UTF-8 joiner-app name.
    func handleOverlayIGMP(_ inner: Data, ihl: Int) {
        let b = inner.startIndex
        guard inner.count >= ihl + 8 else { return }
        let type = inner[b + ihl]
        let g = (UInt32(inner[b+ihl+4]) << 24) | (UInt32(inner[b+ihl+5]) << 16)
              | (UInt32(inner[b+ihl+6]) << 8) | UInt32(inner[b+ihl+7])
        var source = "overlay app"
        if inner.count > ihl + 8,
           let s = String(data: inner.subdata(in: (b+ihl+8)..<inner.endIndex), encoding: .utf8),
           !s.isEmpty { source = s }
        applyIGMP(g, type: type, source: source)
    }

    // Core membership state machine — shared by overlay-app reports (handleOverlayIGMP) and
    // the LISP app's own manual-group self-reports (selfReportManualGroups). Each Report
    // triggers a (*,G) Map-Register; each Leave triggers a de-register.
    func applyIGMP(_ g: UInt32, type: UInt8, source: String) {
        guard (g >> 28) == 0xE else { return }              // 224.0.0.0/4 only
        var group = LispAddress(v4: g)
        group.instanceID = UInt32(config.instanceID); group.maskLen = 32

        switch type {
        case LISP.igmpV2Report, LISP.igmpV1Report:
            igmpGroups[g] = Date(); igmpGroupSource[g] = source
            log.lprint(.etr, "Receive IGMPv2 report for group \(group.addressString) " +
                       "from \(source) — triggering (*,G) Map-Register")
            sendGroupRegister(group: group, ttl: LISP.multicastRegisterTTL)
            refreshAppJoinedGroups(); bumpMapCache()
        case LISP.igmpV2Leave:
            if igmpGroups.removeValue(forKey: g) != nil {
                igmpGroupSource.removeValue(forKey: g)
                log.lprint(.etr, "Receive IGMPv2 leave for group \(group.addressString) " +
                           "from \(source) — triggering (*,G) de-register")
                sendGroupRegister(group: group, ttl: 0)
                refreshAppJoinedGroups(); bumpMapCache()
            }
        default:
            break                                           // queries etc. — ignore
        }
    }

    // The LISP app self-reports IGMPv2 for each MANUALLY-joined group (config.joinedGroups),
    // so a manual group uses the exact same IGMP → (*,G) register path as an overlay app.
    // Run from the periodic register timer (replaces the old sendGroupRegisters loop).
    func selfReportManualGroups() {
        guard running else { return }
        let iid = UInt32(config.instanceID)
        for gstr in config.joinedGroups {
            guard var group = LispAddress(string: gstr, iid: iid), group.isMulticast else { continue }
            group.maskLen = 32
            log.lprint(.etr, "Send IGMPv2 report for group \(group.addressString) " +
                       "(\(Self.manualIGMPSource))")
            applyIGMP(group.v4, type: LISP.igmpV2Report, source: Self.manualIGMPSource)
        }
    }

    // Re-register every active (*,G) with the CURRENT translated port — used after the NAT
    // port is (re)learned (Info-Reply) or on network resume, without waiting for the next
    // IGMP report. No IGMP log (this is a port-refresh, not a membership change).
    func reregisterIGMPGroups() {
        for group in igmpGroupAddresses {
            sendGroupRegister(group: group, ttl: LISP.multicastRegisterTTL)
        }
    }

    // Expire IGMP soft-state groups not refreshed within the timeout. Called from the timer.
    func expireIGMPGroups() {
        guard !igmpGroups.isEmpty else { return }
        let now = Date()
        for (g, last) in igmpGroups where now.timeIntervalSince(last) > LISP.igmpGroupTimeout {
            igmpGroups.removeValue(forKey: g)
            let src = igmpGroupSource.removeValue(forKey: g) ?? "overlay app"
            var group = LispAddress(v4: g)
            group.instanceID = UInt32(config.instanceID); group.maskLen = 32
            log.lprint(.etr, "IGMP soft-state expired for group \(group.addressString) " +
                       "(\(src) gone), de-registering")
            sendGroupRegister(group: group, ttl: 0)
            refreshAppJoinedGroups(); bumpMapCache()
        }
    }

    // Overlay-app groups (source ≠ "LISP app") for the LOCKED display. Manual groups render
    // separately from config.joinedGroups (with a Leave button).
    func refreshAppJoinedGroups() {
        let iid = UInt32(config.instanceID)
        let list: [AppJoinedGroup] = igmpGroups.keys.compactMap { v4 in
            let src = igmpGroupSource[v4] ?? "overlay app"
            guard src != Self.manualIGMPSource else { return nil }
            var a = LispAddress(v4: v4); a.instanceID = iid; a.maskLen = 32
            return AppJoinedGroup(address: a.addressString, source: src,
                                  lastReport: igmpGroups[v4] ?? Date())
        }.sorted { $0.address < $1.address }
        DispatchQueue.main.async { self.appJoinedGroups = list }
    }

    // The IGMP soft-state groups as /32 host addresses (data-plane accept check).
    var igmpGroupAddresses: [LispAddress] {
        let iid = UInt32(config.instanceID)
        return igmpGroups.keys.map { v4 in
            var a = LispAddress(v4: v4); a.instanceID = iid; a.maskLen = 32; return a
        }
    }

    // Forward a received overlay UDP packet (a joined group's chat traffic) to the gaapchat
    // app over loopback (127.0.0.1:overlayRecvPort). Raw inner IP packet; gaapchat filters
    // its own multicast loopback by sender id.
    func forwardUDPToOverlayApp(_ inner: Data, from src: LispAddress, iid: UInt32) {
        if overlayRecvFD < 0 { overlayRecvFD = socket(AF_INET, SOCK_DGRAM, 0) }
        guard overlayRecvFD >= 0 else { return }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = LISP.overlayRecvPort.bigEndian
        addr.sin_addr.s_addr = UInt32(0x7f00_0001).bigEndian        // 127.0.0.1
        _ = inner.withUnsafeBytes { raw in
            withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(overlayRecvFD, raw.baseAddress, raw.count, 0, sa,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        let ip = innerIPInfo(inner)
        log.dprint(.etr, "Send utun, inner EIDs: [\(iid)]\(ip.src) -> [\(iid)]\(ip.dst), " +
                   "length: \(inner.count), delivered to overlay app")
    }
}
