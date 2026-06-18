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
        guard destEID.isOverlayAddress else {
            // Requirement: only 240/4 uses the overlay.
            log.dprint(.itr, "Destination \(destEID.addressString) not in " +
                       "240.0.0.0/4, native-forward (underlay)")
            return
        }
        guard let entry = mapCache.lookup(destEID), entry.action == LISP.noAction,
              let rlocEntry = entry.selectRLOC() else {
            // Miss or send-map-request action: request the mapping and queue.
            log.lprint(.itr, "Map-cache lookup \(destEID.addressString) -> miss, " +
                       "send Map-Request")
            var q = queuedPackets[destEID.v4] ?? []
            if q.count < 4 { q.append(inner) }
            queuedPackets[destEID.v4] = q
            sendMapRequest(for: destEID)
            return
        }

        var header = LispDataHeader()
        header.setNonce(UInt32.random(in: 0...0xFFFFFF))
        header.setInstanceID(destEID.instanceID)
        let packet = header.encode() + inner

        rlocEntry.packetCount += 1
        rlocEntry.byteCount += UInt64(inner.count)
        rlocEntry.lastPacket = Date()
        lastEncapActivity = rlocEntry.lastPacket

        log.dprint(.itr, "Encapsulate \(inner.count) bytes EID " +
                   "\(destEID.addressString) -> RLOC \(rlocEntry.rloc.addressString):" +
                   "\(rlocEntry.encapPort)")
        dataSocket?.send(packet, to: rlocEntry.rloc, port: rlocEntry.encapPort)
    }

    func flushQueuedPackets(for eid: LispAddress) {
        guard let queued = queuedPackets.removeValue(forKey: eid.v4) else { return }
        log.dprint(.itr, "Flushing \(queued.count) queued packet(s) for " +
                   eid.addressString)
        for inner in queued { encapAndSend(inner: inner, destEID: eid) }
    }

    // MARK: - decap (lisp-etr.py:1056 flow)

    func processDataPacket(_ data: Data, from: LispAddress, sourcePort: UInt16,
                           receivedTTL: Int = -1) {
        guard data.count >= 4 else { return }
        log.dprint(.etr, "data-socket rx \(data.count) bytes from " +
                   "\(from.addressString):\(sourcePort), first=" +
                   lispFormatPacket(data.prefix(8)))

        // The reply to a data-port Info-Request comes back RAW (unwrapped) on
        // the data port — lisp_process_info_request sends it straight to our
        // translated source port (lisp.py:16448). This is how we learn the
        // translated DATA port used in the "@tp-<port>" RLOC-name.
        if data[data.startIndex] >> 4 == LISP.typeNatInfo {
            if let info = LispInfo.decode(data), info.isReply {
                processInfoReply(info, fromDataPort: true)
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
                                 receivedTTL: receivedTTL)
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
                    processInfoReply(info, fromDataPort: true)
                }
            case LISP.typeMapRequest:
                if let req = LispMapRequest.decode(inner), req.rlocProbe {
                    answerEncapsulatedProbe(req, fromRTR: from, innerTTL: innerTTL)
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

        // decent-NAT rule: encapsulated packets must come from source port
        // 4341; anything else is dropped.
        if config.decentNATEnabled && sourcePort != LISP.dataPort {
            log.dprint(.etr, "Drop packet from \(from.addressString):\(sourcePort) " +
                       "— decent-NAT requires source port \(LISP.dataPort)")
            return
        }

        let inner = Data(data.dropFirst(8))
        log.dprint(.etr, "Decapsulate \(inner.count) bytes from RLOC " +
                   "\(from.addressString):\(sourcePort), iid \(header.instanceID)")
        deliverInner(inner)
    }

    // Parse inner IPv4 (lisp_ipv4_input equivalent) and deliver to the app.
    private func deliverInner(_ packet: Data) {
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

        guard let myEID = config.eid, dstAddr.v4 == myEID.v4 else {
            log.dprint(.etr, "Inner destination \(dstAddr.addressString) is not " +
                       "our EID, discarding")
            return
        }

        if proto == 1 {                     // ICMP
            let icmp = packet.subdata(in: (packet.startIndex + ihl)..<packet.endIndex)
            pingService.processInboundICMP(icmp, from: srcAddr)
        }
    }
}
