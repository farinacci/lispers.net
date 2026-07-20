//
// DataPlane.swift
//
// Encap/decap. Outbound: inner IPv4 packets (built by PingService) are
// looked up in the map-cache; 240.0.0.0/4 destinations ride the overlay,
// everything else is left to the phone's normal underlay networking.
// Inbound: strip the 8-byte data header, enforce the decent-NAT source-port
// rule, and hand inner ICMP to the ping service.
//

import Foundation

extension LispEngine {

    // MARK: - encap (lisp-itr.py:577 flow)

    func encapAndSend(inner: Data, destEID: LispAddress) {
        guard running else { return }
        let multicast = destEID.isMulticast
        // A LISP-Trace to our OWN EID must still go OUT to the RTR (which decaps + re-encaps
        // back to us) so the round-trip path is real — otherwise it short-circuits locally
        // (no RTR hops). Non-trace own-EID packets stay local (below).
        let isTrace = Self.isTracePacket(inner)
        let selfTrace = !multicast && isTrace && (config.eid.map { destEID.v4 == $0.v4 } ?? false)
        // A unicast packet destined to our OWN EID is local (e.g. our self-reply to our own
        // multicast group ping). Deliver it up the stack — do NOT encap to the network or
        // Map-Request it, which would wrongly create a map-cache entry for ourselves.
        if !multicast, !selfTrace, let myEID = config.eid, destEID.v4 == myEID.v4 {
            log.dprint(.itr, "Destination \(destEID.addressString) is our own EID — " +
                       "deliver locally, no encap")
            deliverInner(inner, iid: destEID.instanceID)
            return
        }
        guard destEID.isOverlayAddress || multicast else {
            // Requirement: only 240/4 (unicast) and 224/4 (multicast) use the overlay.
            log.dprint(.itr, "Destination \(destEID.addressString) not in " +
                       "240.0.0.0/4 or 224.0.0.0/4, native-forward (underlay)")
            return
        }
        // Multicast: (S,G) lookup (source = our EID); the default (0/0, 224/4)
        // entry's RLOC-set is the RTRs, and selectRLOC hashes (S,G) -> one RTR,
        // which then replicates to the joined receivers.
        // Self-trace: resolve via the RTR default (0/0), not the 240/8 send-map-request entry.
        // Looking up 0.0.0.0 matches ONLY the 0/0 default (the RTR set), so we encap to the RTR.
        let lookupEID = selfTrace ? LispAddress(v4: 0, maskLen: 0, iid: destEID.instanceID) : destEID
        let entry = multicast
            ? mapCache.lookupMulticast(source: config.eid ?? LispAddress(), group: destEID)
            : mapCache.lookup(lookupEID)
        // True miss — no matching entry at all. Unicast asks the mapping system and
        // queues; multicast drops (the (0/0,224/4) default should always match).
        guard let entry = entry else {
            if multicast {
                log.lprint(.itr, "No multicast map-cache entry for group " +
                           "\(destEID.addressString), dropping")
                return
            }
            log.lprint(.itr, "Map-cache lookup \(destEID.addressString) -> miss, " +
                       "send Map-Request")
            var q = queuedPackets[destEID.v4] ?? []
            if q.count < 4 { q.append(inner) }
            queuedPackets[destEID.v4] = q
            sendMapRequest(for: destEID)
            return
        }
        // A send-map-request entry (decent-NAT 240/8) resolves the specific EID.
        if entry.action == LISP.sendMapRequestAction {
            log.lprint(.itr, "Map-cache \(destEID.addressString) -> send-map-request")
            var q = queuedPackets[destEID.v4] ?? []
            if q.count < 4 { q.append(inner) }
            queuedPackets[destEID.v4] = q
            sendMapRequest(for: destEID)
            return
        }
        // Matched a forwarding entry (e.g. the 0.0.0.0/0 default -> RTRs). Pick ONE
        // up RLOC. If none are reachable, drop — do NOT encapsulate to an unreach
        // RLOC, and do NOT fall through to a Map-Request that would create a more-
        // specific entry for something the default already covers.
        //
        // The Ping-tab "load-split" toggle for this traffic type drives selection:
        //   ON  -> hash per-packet across the up RTRs (spread the load; a member
        //          reachable via only some RTRs then gets partial delivery).
        //   OFF -> a single deterministic up RTR (no spread to multiple RTRs).
        guard entry.action == LISP.noAction,
              let rlocEntry = entry.selectRLOC(for: inner,
                  hashL4: multicast ? config.loadSplitMulticast
                                    : config.loadSplitUnicast) else {
            log.lprint(.itr, "Map-cache \(destEID.addressString) matched " +
                       "\(entry.eid.prefixString) but no reachable RLOC, dropping")
            return
        }

        var header = LispDataHeader()
        let nonce = UInt32.random(in: 0...0xFFFFFF)
        header.setNonce(nonce)
        header.setInstanceID(destEID.instanceID)
        let packet = header.encode() + inner

        rlocEntry.packetCount += 1
        rlocEntry.byteCount += UInt64(inner.count)
        rlocEntry.lastPacket = Date()
        lastEncapActivity = rlocEntry.lastPacket

        // Multi-homing: encap out the active next-hop's interface socket.
        let sock = dataSock(for: rlocEntry.interfaceName)
        // lisp.py print_packet("Send") — full outer/inner detail.
        let ip = innerIPInfo(inner)
        // Data-plane encap bypasses loggedSend, so there is NO "Send <if> N bytes"
        // line for it — the egress interface is recorded here or nowhere.
        let eifn = rlocEntry.interfaceName ?? rloc?.interfaceName ?? "?"
        log.dprint(.itr, "Encap \(eifn) outer RLOCs: " +
                   "\(rloc?.address.addressString ?? "?") -> \(rlocEntry.rloc.addressString), " +
                   "outer tos/ttl: 0/64, outer UDP: \(sock?.localPort ?? 0) -> " +
                   "\(rlocEntry.encapPort), inner EIDs: [\(destEID.instanceID)]\(ip.src) -> " +
                   "[\(destEID.instanceID)]\(ip.dst), " +
                   "inner tos/ttl: \(ip.tos)/\(ip.ttl), length: \(packet.count), " +
                   "\(header.printHeader()), " +
                   "packet: \(lispFormatPacket(packet))")
        sock?.send(packet, to: rlocEntry.rloc, port: rlocEntry.encapPort)
    }

    // Parse an inner IPv4 packet's EIDs + tos/ttl for the encap/decap log lines
    // (mirrors lisp.py print_packet's inner-EID and inner-tos/ttl fields).
    func innerIPInfo(_ p: Data) -> (src: String, dst: String, tos: Int, ttl: Int) {
        guard p.count >= 20, let v = p.first, v >> 4 == 4 else { return ("?", "?", 0, 0) }
        let b = p.startIndex
        func u32(_ o: Int) -> UInt32 {
            (UInt32(p[b+o]) << 24) | (UInt32(p[b+o+1]) << 16)
                | (UInt32(p[b+o+2]) << 8) | UInt32(p[b+o+3])
        }
        return (LispAddress(v4: u32(12)).addressString,
                LispAddress(v4: u32(16)).addressString,
                Int(p[b + 1]), Int(p[b + 8]))
    }

    func flushQueuedPackets(for eid: LispAddress) {
        guard let queued = queuedPackets.removeValue(forKey: eid.v4) else { return }
        log.dprint(.itr, "Flushing \(queued.count) queued packet(s) for " +
                   eid.addressString)
        for inner in queued { encapAndSend(inner: inner, destEID: eid) }
    }

    // MARK: - decap (lisp-etr.py:1056 flow)

    func processDataPacket(_ data: Data, from: LispAddress, sourcePort: UInt16,
                           receivedTTL: Int = -1, onInterface: String? = nil) {
        guard data.count >= 4 else { return }
        // The data socket carries both real data packets AND control (Info-Replies,
        // RLOC-probe replies, 0xffffff relays). Log a real data packet under the
        // data-plane scope; log control under control-plane. (Map-Req/Reply (type
        // 1/2) are handed to processControlPacket, which logs its own receive.)
        let nibble = data[data.startIndex] >> 4
        let isRelay = data.count > 8 && LispDataHeader.decode(data)?.instanceID == LISP.infoIID
        let rifn = onInterface ?? rloc?.interfaceName ?? "?"
        let recvMsg = "Receive \(rifn) \(data.count) bytes from \(from.addressString) " +
                      "\(sourcePort), packet: \(lispFormatPacket(data))"
        if isRelay {
            log.lprint(.itr, recvMsg)         // 0xffffff relay = RLOC-probe traffic -> itr
        } else if nibble == LISP.typeNatInfo {
            log.lprint(.etr, recvMsg)         // raw Info-Reply -> etr (register/NAT)
        }
        // Real data (nibble >= 8) gets NO separate receive line — its raw hex rides the
        // Decap line's "packet:" pulldown below, so there's one line per decap (like Encap).
        // raw type 1/2 (RLOC-probe) -> processControlPacket logs its own receive

        // The reply to a data-port Info-Request comes back RAW (unwrapped) on
        // the data port — lisp_process_info_request sends it straight to our
        // translated source port (lisp.py:16448). This is how we learn the
        // translated DATA port used in the "@tp-<port>" RLOC-name.
        if data[data.startIndex] >> 4 == LISP.typeNatInfo {
            if let info = LispInfo.decode(data), info.isReply {
                processInfoReply(info, from: from, sourcePort: sourcePort,
                                 fromDataPort: true, onInterface: onInterface)
            }
            return
        }

        // RLOC-probe replies from an RTR arrive here, not on the control socket:
        // the RTR replies FROM its data port 4341 TO our translated data RLOC:port
        // so the answer traverses the firewall. They are raw control messages
        // (Map-Reply, or a probe Map-Request), so hand them to the control plane.
        // Real data packets carry a data header whose first byte has the N-bit
        // set (high nibble >= 8), so type 1/2 here is unambiguously control.
        let firstNibble = data[data.startIndex] >> 4
        if firstNibble == LISP.typeMapReply || firstNibble == LISP.typeMapRequest {
            processControlPacket(data, from: from, sourcePort: sourcePort,
                                 receivedTTL: receivedTTL, onInterface: onInterface)
            return
        }

        guard data.count > 8, let header = LispDataHeader.decode(data) else { return }

        // IID 0xffffff = a control message relayed over the data plane. The body
        // may be raw, or (when an RTR relays it) wrapped in inner IPv4+UDP.
        if header.hasInstanceID && header.instanceID == LISP.infoIID {
            var inner = Data(data.dropFirst(8))
            var innerTTL = -1
            if let v = inner.first, v >> 4 == 4 {           // strip inner IPv4+UDP
                let b = inner.startIndex
                guard inner.count >= 28 else { return }
                innerTTL = Int(inner[b + 8])                // IP TTL field
                let ihl = Int(inner[b] & 0xf) * 4
                inner = Data(inner.dropFirst(ihl + 8))      // drop IP + UDP
            }
            guard let type = inner.first.map({ $0 >> 4 }) else { return }
            switch type {
            case LISP.typeNatInfo:
                if let info = LispInfo.decode(inner), info.isReply {
                    processInfoReply(info, from: from, sourcePort: sourcePort,
                                     fromDataPort: true, onInterface: onInterface)
                }
            case LISP.typeMapRequest:
                if let req = LispMapRequest.decode(inner), req.rlocProbe {
                    answerEncapsulatedProbe(req, fromRTR: from, sourcePort: sourcePort,
                                            innerTTL: innerTTL, onInterface: onInterface)
                }
            case LISP.typeMapReply:
                if let reply = LispMapReply.decode(inner) {
                    processMapReply(reply, from: from, receivedTTL: innerTTL)
                }
            default:
                break
            }
            return
        }

        let inner = Data(data.dropFirst(8))
        // lisp.py print_packet("Receive"/decap) — full outer/inner detail, with the raw
        // received packet on the "packet:" pulldown at the end (one line per decap).
        let ip = innerIPInfo(inner)
        let outTTL = receivedTTL >= 0 ? String(receivedTTL) : "?"
        let difn = onInterface ?? rloc?.interfaceName ?? "?"     // multi-homing ingress iface
        log.dprint(.etr, "Decap \(difn) outer RLOCs: " +
                   "\(from.addressString) -> \(rloc?.address.addressString ?? "?"), " +
                   "outer tos/ttl: 0/\(outTTL), outer UDP: \(sourcePort) -> " +
                   "\(dataSocket?.localPort ?? 0), inner EIDs: [\(header.instanceID)]\(ip.src) -> " +
                   "[\(header.instanceID)]\(ip.dst), inner tos/ttl: \(ip.tos)/\(ip.ttl), " +
                   "length: \(data.count), \(header.printHeader()), " +
                   "packet: \(lispFormatPacket(data))")
        deliverInner(inner, iid: header.instanceID, onInterface: onInterface, outerSource: from)
    }

    // Append our ETR decap node to a returning LISP-Trace packet (lisp_trace_append,
    // ed="decap") so the trace ends with the phone's own hop, then return the rebuilt
    // inner IP/UDP packet. Falls back to the original on any parse failure.
    private func appendTraceDecap(_ inner: Data, outerSource: LispAddress) -> Data {
        let b = inner.startIndex
        guard inner.count >= 20 else { return inner }
        let ihl = Int(inner[b] & 0x0f) * 4
        let udpOff = b + ihl
        let payloadOff = udpOff + 8                 // start of Type-9 packet
        let jsonOff = payloadOff + 16               // header: first-long(4)+rloc(4)+nonce(8)
        guard inner.count > jsonOff else { return inner }
        func u32(_ o: Int) -> UInt32 {
            (UInt32(inner[b+o]) << 24) | (UInt32(inner[b+o+1]) << 16)
          | (UInt32(inner[b+o+2]) << 8) | UInt32(inner[b+o+3])
        }
        let deid = LispAddress(v4: u32(16)).addressString      // inner dst = our EID (return dest)

        let jsonData = inner.subdata(in: jsonOff..<inner.endIndex)
        guard var segments = (try? JSONSerialization.jsonObject(with: jsonData))
                as? [[String: Any]] else { return inner }

        let ourRLOC = (translatedRLOC ?? rloc?.address)?.addressString ?? "?"
        let sr = outerSource.isNull ? (rloc?.address.addressString ?? "?")
                                    : outerSource.addressString
        let entry: [String: Any] = ["n": "ETR", "sr": sr, "dr": ourRLOC,
                                    "hn": xtrName, "dts": Date().timeIntervalSince1970]
        // Append to the return segment (de == our EID); else the last segment.
        if let i = segments.firstIndex(where: { ($0["de"] as? String) == deid }) {
            var paths = (segments[i]["paths"] as? [[String: Any]]) ?? []
            paths.append(entry); segments[i]["paths"] = paths
        } else if !segments.isEmpty {
            var paths = (segments[segments.count-1]["paths"] as? [[String: Any]]) ?? []
            paths.append(entry); segments[segments.count-1]["paths"] = paths
        }
        guard let newJSON = try? JSONSerialization.data(withJSONObject: segments) else { return inner }

        // Rebuild IP + UDP + Type-9 header + new JSON, fixing lengths + checksums.
        let udpPayload = inner.subdata(in: payloadOff..<jsonOff) + newJSON       // Type-9 hdr + JSON
        var udp = Data(inner.subdata(in: udpOff..<payloadOff))
        let udpLen = UInt16(truncatingIfNeeded: 8 + udpPayload.count)
        udp[udp.startIndex+4] = UInt8(udpLen >> 8); udp[udp.startIndex+5] = UInt8(udpLen & 0xff)
        udp[udp.startIndex+6] = 0; udp[udp.startIndex+7] = 0                     // zero UDP checksum
        var ipHdr = Data(inner.subdata(in: b..<udpOff))
        let totalLen = UInt16(truncatingIfNeeded: ihl + 8 + udpPayload.count)
        ipHdr[ipHdr.startIndex+2] = UInt8(totalLen >> 8); ipHdr[ipHdr.startIndex+3] = UInt8(totalLen & 0xff)
        ipHdr[ipHdr.startIndex+10] = 0; ipHdr[ipHdr.startIndex+11] = 0
        let ck = internetChecksum(ipHdr)
        ipHdr[ipHdr.startIndex+10] = UInt8(ck >> 8); ipHdr[ipHdr.startIndex+11] = UInt8(ck & 0xff)
        return ipHdr + udp + udpPayload
    }

    // Parse inner IPv4 (lisp_ipv4_input equivalent) and deliver to the app.
    // A LISP-Trace inner packet: IPv4 + UDP with dst port 2434 (LISP_TRACE_PORT).
    static func isTracePacket(_ inner: Data) -> Bool {
        let b = inner.startIndex
        guard inner.count >= 20, (inner[b] >> 4) == 4 else { return false }
        let ihl = Int(inner[b] & 0x0f) * 4
        guard inner[b + 9] == 17, inner.count >= ihl + 8 else { return false }   // UDP
        let dport = (UInt16(inner[b + ihl + 2]) << 8) | UInt16(inner[b + ihl + 3])
        return dport == LISP.tracePort
    }

    private func deliverInner(_ packet: Data, iid: UInt32 = 0, onInterface: String? = nil,
                              outerSource: LispAddress = LispAddress()) {
        guard packet.count >= 20 else { return }
        var r = ByteReader(packet)
        guard let vihl = r.u8(), vihl >> 4 == 4 else { return }
        let ihl = Int(vihl & 0xf) * 4
        guard packet.count >= ihl else { return }
        _ = r.u8()                          // tos
        guard let totalLen = r.u16(), Int(totalLen) <= packet.count else { return }
        r.skip(4)                           // id + frag
        guard let ttl = r.u8(), ttl > 0 else { return }
        guard let proto = r.u8() else { return }
        r.skip(2)                           // checksum
        guard let src = r.u32(), let dst = r.u32() else { return }

        let srcAddr = LispAddress(v4: src)
        let dstAddr = LispAddress(v4: dst)

        let forUs = config.eid.map { dstAddr.v4 == $0.v4 } ?? false
        // A joined group: either a user-joined group (config) OR an overlay-app IGMP
        // soft-state group (gaapchat).
        let forGroup = dstAddr.isMulticast
            && (joinedGroupAddresses.contains { $0.v4 == dstAddr.v4 }
                || igmpGroups[dstAddr.v4] != nil)
        guard forUs || forGroup else {
            log.dprint(.etr, "Inner destination \(dstAddr.addressString) is not our EID " +
                       "or a joined group, discarding")
            return
        }
        if forGroup {
            // A multicast packet the RTR replicated to us (we joined the group).
            log.lprint(.etr, "Receive multicast EID packet, group " +
                       "\(dstAddr.addressString) from \(srcAddr.addressString)")
        }

        if proto == 1 {                     // ICMP
            let icmp = packet.subdata(in: (packet.startIndex + ihl)..<packet.endIndex)
            // An echo-REPLY that isn't for a local (this-app, Direct) ping belongs to
            // the external PING client app — forward the inner reply to it over loopback.
            // Echo-REQUESTS (and our own replies) are always handled here (we're the ETR).
            if icmp.count >= 8, icmp[icmp.startIndex] == 0, !pingService.isLocalReply(icmp) {
                forwardReplyToPingApp(packet, from: srcAddr, iid: iid)
            } else {
                pingService.processInboundICMP(icmp, from: srcAddr)
            }
        } else if proto == 17 {             // UDP — overlay-app traffic
            // A LISP-Trace (ltr) reply is UDP whose payload's first nibble is Type-9;
            // route it to the LTR tab on 41346. Everything else (gaapchat chat) goes to
            // the overlay-app port. The gaapchat app filters its own multicast loopback
            // by sender id, so delivering self-looped copies is fine.
            let ub = packet.startIndex + ihl
            let isTrace = packet.count >= ub + 9 && (packet[ub + 8] >> 4) == LISP.typeLispTrace
            if isTrace {
                // Append our own ETR decap hop (lisp_trace_append, ed="decap") so the
                // phone appears as the final line, then hand the reply to the LTR tab.
                let withHop = appendTraceDecap(packet, outerSource: outerSource)
                forwardUDPToOverlayApp(withHop, from: srcAddr, iid: iid,
                                       port: LISP.ltrReplyPort, label: "LTR app")
            } else {
                forwardUDPToOverlayApp(packet, from: srcAddr, iid: iid)
            }
        }
    }
}
