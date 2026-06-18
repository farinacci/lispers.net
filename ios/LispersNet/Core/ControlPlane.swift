//
// ControlPlane.swift
//
// Registration, Map-Request/Map-Reply, Info-Request/Info-Reply, and
// RLOC-probing with telemetry. Logging mirrors the Python lprint() lines so
// lisp-itr.log / lisp-etr.log read like the originals.
//

import Foundation

extension LispEngine {

    // MARK: - Map-Register (lisp_build_map_register, lisp-etr.py:480)

    func sendMapRegisters() {
        guard running, let eid = config.eid, let myRLOC = rloc else { return }
        guard let (msAddr, msConf) = mapServerFor(eid: eid) else {
            log.lprint(.etr, "No map-server available, deferring Map-Register")
            return
        }

        var eidRecord = LispEIDRecord()
        eidRecord.recordTTL = LISP.registerTTL
        eidRecord.eid = eid
        eidRecord.authoritative = true

        var rlocRecord = LispRLOCRecord()
        rlocRecord.rloc = behindNAT ? (translatedRLOC ?? myRLOC.address) : myRLOC.address
        rlocRecord.priority = 1
        rlocRecord.weight = 100
        rlocRecord.localBit = true
        rlocRecord.reachBit = true
        if behindNAT {
            // Translated RLOC carries "<xtr>@tp-<translated-data-port>" so peers
            // know which NAT-translated port to send encapsulated data to
            // (store_translated_rloc, lisp.py:13765).
            let port = translatedPort != 0 ? translatedPort : LISP.dataPort
            rlocRecord.rlocName = "\(xtrName)\(LISP.tpPrefix)\(port)"
        }

        var records = [rlocRecord]
        if behindNAT {
            // RTR RLOCs at priority 254 with RLOC-name "RTR" (lisp-etr.py:452,
            // lisp.py:7373).
            for rtr in rtrList {
                var r = LispRLOCRecord()
                r.rloc = rtr
                r.priority = 254
                r.weight = 0
                r.reachBit = true
                r.rlocName = "RTR"
                records.append(r)
            }
        }
        eidRecord.rlocCount = UInt8(records.count)
        var recordData = eidRecord.encode()
        for r in records { recordData.append(r.encode()) }

        var register = LispMapRegister()
        register.nonce = lispGetControlNonce()
        register.recordCount = 1
        register.wantMapNotify = false      // don't request a Map-Notify ack
        register.xtrID = xtrID
        register.siteID = config.siteID
        register.algID = msConf.authAlg == "sha1" ? LISP.sha1AlgID : LISP.sha2AlgID
        // key-id selects WHICH configured key on the map-server — it is NOT the
        // alg-id. lispers.net's lisp_parse_auth_key() assigns key-id 0 to a plain
        // "authentication-key" (no "[key-id]" prefix), so default to 0. Sending
        // key-id 2 made the MS hash with an empty key (auth always failed).
        register.keyID = 0
        let packet = register.encode(eidRecords: recordData, password: msConf.authKey)

        let decent = config.decentConfigured
            ? ", decent-index \(LispDecent.index(eid: eid, modulus: config.decentModulus, prefixes: config.decentPrefixes))" : ""
        let rlocName = rlocRecord.rlocName.map { " (\($0))" } ?? ""
        log.lprint(.etr, "Send Map-Register to map-server \(msAddr.addressString)\(decent), " +
                   "EID-prefix \(eid.prefixString), RLOC \(rlocRecord.rloc.addressString)\(rlocName)")
        log.dprint(.etr, "Send \(packet.count) bytes to \(msAddr.addressString):" +
                   "\(LISP.ctrlPort), packet: \(lispFormatPacket(packet.prefix(64)))")
        ctrlSocket?.send(packet, to: msAddr, port: LISP.ctrlPort)
        DispatchQueue.main.async { self.registrationsSent += 1 }
    }

    // MARK: - Info-Request (lisp_send_info_request, lisp.py:16376)

    func sendInfoRequests() {
        guard running, let eid = config.eid else { return }
        guard let (msAddr, _) = mapServerFor(eid: eid) else { return }

        var info = LispInfo()
        info.nonce = lispGetControlNonce()
        info.hostname = xtrName
        lastInfoNonce = info.nonce
        let packet = info.encodeRequest()

        // Control-port Info-Request from the 4342 socket.
        log.lprint(.etr, "Send Info-Request to MS \(msAddr.addressString), " +
                   "port \(LISP.ctrlPort) (for control)")
        ctrlSocket?.send(packet, to: msAddr, port: LISP.ctrlPort)

        // Data-port Info-Request from the 4341 socket, wrapped in a LISP
        // data header with IID 0xffffff, so the NAT creates/refreshes the
        // data-port binding (lisp.py:16414).
        var header = LispDataHeader()
        header.setInstanceID(LISP.infoIID)
        let dataWrapped = header.encode() + packet
        log.lprint(.etr, "Send Info-Request to RTR \(msAddr.addressString), " +
                   "port \(LISP.dataPort) (for data)")
        dataSocket?.send(dataWrapped, to: msAddr, port: LISP.dataPort)

        // Send the data-port Info-Request to each RTR — their reply carries the
        // translated DATA port we register as "@tp-<port>".
        for rtr in rtrList {
            log.lprint(.etr, "Send Info-Request to RTR \(rtr.addressString), " +
                       "port \(LISP.dataPort) (for data)")
            dataSocket?.send(dataWrapped, to: rtr, port: LISP.dataPort)
        }

        // Also send a RAW Info-Request from the DATA socket to each responder's
        // CONTROL port (4342). This makes the responder record our ephemeral
        // data translation and reply from 4342 — and because we sent TO 4342,
        // that reply traverses a port-restricted NAT back to our data socket,
        // giving us the real translated data port in its etr-port field.
        dataSocket?.send(packet, to: msAddr, port: LISP.ctrlPort)
        for rtr in rtrList {
            dataSocket?.send(packet, to: rtr, port: LISP.ctrlPort)
        }
    }

    func processInfoReply(_ info: LispInfo, fromDataPort: Bool) {
        guard let myRLOC = rloc else { return }
        let global = info.globalETRRLOC
        log.lprint(.etr, "Info-Reply -> nonce 0x\(String(info.nonce, radix: 16)), " +
                   "global-rloc: \(global.addressString), etr-port: \(info.etrPort), " +
                   "ms-port: \(info.msPort), RTR-list: " +
                   (info.rtrList.isEmpty ? "empty"
                    : info.rtrList.map { $0.addressString }.joined(separator: ", ")))

        if !info.rtrList.isEmpty && info.rtrList != rtrList {
            rtrList = info.rtrList
            let rtrs = rtrList.map { $0.addressString }.joined(separator: ", ")
            log.fprint(.etr, "Cached \(rtrList.count) RTR(s) from Info-Reply: \(rtrs)")
            installRTRDefaultMapCacheEntries()
        }

        let natted = !global.isNull && global != myRLOC.address
        DispatchQueue.main.async {
            self.behindNAT = natted
            if natted {
                self.translatedRLOC = global
                // Only the data-port (ephemeral) Info-Reply carries the
                // translated DATA port peers encapsulate to. The control reply's
                // etr-port is the control-port translation and must not be used.
                if fromDataPort { self.translatedPort = info.etrPort }
            } else {
                self.translatedRLOC = nil
                self.translatedPort = 0
            }
        }
        if natted {
            log.fprint(.etr, "xTR is behind NAT: translated RLOC " +
                       "\(global.addressString):\(info.etrPort)")
            // Register through the NAT now that we know the translation.
            DispatchQueue.main.async { self.sendMapRegisters() }
        }
    }

    // MARK: - Map-Request, ECM lookup path (lisp_send_map_request)

    func sendMapRequest(for destEID: LispAddress) {
        guard running, let sourceEID = config.eid, let myRLOC = rloc else { return }
        // Rate limit (lisp_rate_limit_map_request)
        if let last = lastMapRequestSent[destEID.v4],
           Date().timeIntervalSince(last) < LISP.mapRequestRateLimit { return }
        lastMapRequestSent[destEID.v4] = Date()
        guard let (msAddr, _) = mapServerFor(eid: destEID) else { return }

        var req = LispMapRequest()
        req.nonce = lispGetControlNonce()
        req.sourceEID = sourceEID
        req.itrRLOCs = [myRLOC.address]
        var target = destEID
        target.maskLen = 32
        req.targetEID = target
        pendingMapRequests[req.nonce] = target

        let inner = req.encode()
        let ecm = LispECM.wrap(control: inner, innerSource: sourceEID,
                               innerDest: target, sourcePort: LISP.ctrlPort,
                               destPort: LISP.ctrlPort, toMS: true)
        log.lprint(.itr, "Send Map-Request (ECM) for EID \(target.prefixString) " +
                   "to \(msAddr.addressString), nonce 0x\(String(req.nonce, radix: 16))")
        log.dprint(.itr, "Send \(ecm.count) bytes to \(msAddr.addressString):" +
                   "\(LISP.ctrlPort), packet: \(lispFormatPacket(ecm.prefix(64)))")
        ctrlSocket?.send(ecm, to: msAddr, port: LISP.ctrlPort)
    }

    // MARK: - RLOC-probing (non-ECM Map-Request, probe bit + telemetry)

    func sendRLOCProbes() {
        guard running, config.rlocProbingEnabled,
              config.eid != nil, let myRLOC = rloc else { return }
        // Probe every entry's RLOCs, including the static RTR defaults — that's
        // how the RTRs get telemetry (rtts/hops/lats). The send-map-request
        // 240/8 entry has no RLOCs, so it contributes nothing. The same RTR
        // appears under both the unicast 0/0 and multicast (0/0,224/4) default
        // entries; probe each unique RLOC once per cycle (lisp.py suppresses
        // duplicate-RLOC probes) and share the nonce so one reply updates both.
        let snapshot = mapCache.snapshot()
        var probedKeys = Set<UInt64>()
        func probeKey(_ rl: LispRLOC) -> UInt64 {
            let p = rl.encapPort != LISP.dataPort ? rl.encapPort : LISP.ctrlPort
            return UInt64(rl.rloc.v4) << 16 | UInt64(p)
        }
        for entry in snapshot {
            for r in entry.rlocSet {
                // Mark unreachable if no reply within the wait window.
                if let sent = r.lastProbeSent,
                   Date().timeIntervalSince(sent) > LISP.rlocProbeReplyWait,
                   (r.lastProbeReply ?? .distantPast) < sent, r.isUp {
                    r.state = "unreach-state"
                    r.stateChange = Date()
                    log.pprint(.itr, "RLOC \(r.rloc.addressString) went unreachable, " +
                               "no RLOC-probe reply")
                    bumpMapCache()
                }

                // Skip if we already probed this RLOC (same address:port) this
                // cycle under another default entry.
                if probedKeys.contains(probeKey(r)) { continue }
                probedKeys.insert(probeKey(r))

                var probe = LispMapRequest()
                probe.nonce = lispGetControlNonce()
                probe.rlocProbe = true
                // RLOC-probes carry no source-EID (lisp_send_map_request uses
                // seid=None for unicast), and set the N flag when we are a NAT'd
                // xTR — matching the wire format of a working decent-NAT probe.
                probe.decentNATXtr = behindNAT
                // Advertise our PRIVATE RLOC, exactly like the working xTRs
                // (itr-rloc 10.x). lisp_rtr_process_map_request replaces a private
                // itr-rloc with the packet `source`, so the RTR replies to the
                // public address:port our probe actually came from — which routes
                // straight back to the control socket that sent it.
                probe.itrRLOCs = [myRLOC.address]
                var target = entry.eid
                target.maskLen = entry.eid.maskLen
                probe.targetEID = target
                if config.telemetryEnabled {
                    probe.telemetryJSON = Telemetry.encode(
                        Telemetry.configTemplate, itrOut: Telemetry.timestamp())
                }
                // Stamp this nonce/time on every sibling RLOC with the same
                // address:port so the single reply updates them all.
                let sentAt = Date()
                for e2 in snapshot {
                    for s in e2.rlocSet where probeKey(s) == probeKey(r) {
                        s.lastProbeNonce = probe.nonce
                        s.lastProbeSent = sentAt
                    }
                }
                let packet = probe.encode()
                let tel = config.telemetryEnabled ? ", with telemetry" : ""

                // Send the RLOC-probe from the control socket to the RTR's
                // control port 4342, exactly like the working xTRs — no data port
                // involved. The RTR replies (raw Map-Reply) to the packet source,
                // i.e. our control socket's translation, so it returns on 4342.
                let port = r.encapPort != LISP.dataPort ? r.encapPort : LISP.ctrlPort
                log.pprint(.itr, "Send RLOC-probe to \(r.rloc.addressString):\(port), " +
                           "for EID \(entry.eid.prefixString)\(tel), nonce 0x" +
                           String(probe.nonce, radix: 16))
                ctrlSocket?.send(packet, to: r.rloc, port: port)
            }
        }
    }

    func processProbeReply(_ reply: LispMapReply, from: LispAddress, replyTTL: Int) {
        let now = Date()
        // Telemetry rides back as a JSON RLOC-record — decode it once.
        var latency: String?
        for (_, rlocs) in reply.records {
            for rl in rlocs {
                guard let json = rl.jsonString, Telemetry.isTelemetry(json) else { continue }
                let stamped = Telemetry.encode(json, itrIn: Telemetry.timestamp())
                if let (fwd, rev) = Telemetry.latencies(stamped) {
                    latency = "\(fwd)/\(rev)"
                    log.lprint(.itr, "Telemetry for \(from.addressString): " +
                               "fwd \(fwd) secs, rev \(rev) secs")
                }
            }
        }
        // Update every RLOC carrying this nonce (the same RTR appears under both
        // the unicast and multicast default entries), so they stay in sync.
        var matched = false, loggedRTT = false
        for entry in mapCache.snapshot() {
            for r in entry.rlocSet where r.lastProbeNonce == reply.nonce {
                matched = true
                r.lastProbeReply = now
                if let sent = r.lastProbeSent {
                    let rtt = now.timeIntervalSince(sent).rounded(toPlaces: 3)
                    r.storeRTT(rtt)
                    if !loggedRTT {
                        log.pprint(.itr, "Received RLOC-probe reply from \(from.addressString), " +
                                   "RTT \(rtt) secs, nonce 0x\(String(reply.nonce, radix: 16))")
                        loggedRTT = true
                    }
                }
                // to-hops from the responder's echoed received-TTL (Map-Reply
                // hop-count); from-hops from the reply's own received TTL.
                r.storeHops(toReceivedTTL: Int(reply.hopCount), fromReceivedTTL: replyTTL)
                if !r.isUp {
                    r.state = "up-state"
                    r.stateChange = now
                    log.pprint(.itr, "RLOC \(from.addressString) is reachable again")
                }
                if let l = latency { r.storeLatency(l) }
            }
        }
        if matched { bumpMapCache() }
    }

    // Answer RLOC-probes aimed at us so peers' telemetry works
    // (lisp_build_map_reply with probe bit + telemetry RLOC-record).
    func processMapRequest(_ req: LispMapRequest, from: LispAddress, sourcePort: UInt16,
                           receivedTTL: Int = -1) {
        guard let eid = config.eid, let myRLOC = rloc else { return }
        guard req.rlocProbe else {
            log.lprint(.etr, "Ignoring non-probe Map-Request from \(from.addressString)")
            return
        }
        let etrIn = Telemetry.timestamp()
        log.lprint(.etr, "Receive RLOC-probe from \(from.addressString), " +
                   "nonce 0x\(String(req.nonce, radix: 16))")

        var eidRec = LispEIDRecord()
        eidRec.recordTTL = LISP.registerTTL
        eidRec.eid = eid

        var rlocRec = LispRLOCRecord()
        rlocRec.rloc = myRLOC.address
        rlocRec.priority = 1
        rlocRec.weight = 100
        rlocRec.localBit = true
        rlocRec.probeBit = true
        rlocRec.reachBit = true

        var records: [LispRLOCRecord] = [rlocRec]
        if let json = req.telemetryJSON, Telemetry.isTelemetry(json) {
            var t = rlocRec
            t.jsonString = Telemetry.encode(json, etrIn: etrIn,
                                            etrOut: Telemetry.timestamp())
            records = [t]
        }

        var reply = LispMapReply()
        reply.nonce = req.nonce
        reply.rlocProbe = true
        // Echo the TTL the probe arrived with so the requester can derive its
        // ITR->ETR hop count (lisp.py:7342).
        reply.hopCount = receivedTTL >= 0 ? UInt8(clamping: receivedTTL) : 0
        reply.records = [(eidRec, records)]
        let packet = reply.encode()
        log.lprint(.etr, "Send RLOC-probe Map-Reply to \(from.addressString):\(sourcePort)")
        ctrlSocket?.send(packet, to: from, port: sourcePort)
    }

    // Answer a data-encapsulated RLOC-probe relayed by an RTR: build the probe
    // Map-Reply (with telemetry) and data-encapsulate it back to the RTR, per
    // lisp_encap_rloc_probe (lisp.py:7555/19092). Without this the RTR marks our
    // RLOC unreach-state.
    func answerEncapsulatedProbe(_ req: LispMapRequest, fromRTR rtr: LispAddress,
                                 innerTTL: Int) {
        guard let eid = config.eid, let myRLOC = rloc else { return }
        let etrIn = Telemetry.timestamp()
        log.pprint(.etr, "Received RLOC-probe (encap) from RTR \(rtr.addressString), " +
                   "nonce 0x\(String(req.nonce, radix: 16)) — replying via RTR")

        var eidRec = LispEIDRecord()
        eidRec.recordTTL = LISP.registerTTL
        eidRec.eid = eid

        var rlocRec = LispRLOCRecord()
        rlocRec.rloc = behindNAT ? (translatedRLOC ?? myRLOC.address) : myRLOC.address
        rlocRec.priority = 1
        rlocRec.weight = 100
        rlocRec.localBit = true
        rlocRec.probeBit = true
        rlocRec.reachBit = true
        if behindNAT {
            let port = translatedPort != 0 ? translatedPort : LISP.dataPort
            rlocRec.rlocName = "\(xtrName)\(LISP.tpPrefix)\(port)"
        }

        var records: [LispRLOCRecord] = [rlocRec]
        if let json = req.telemetryJSON, Telemetry.isTelemetry(json) {
            var t = rlocRec
            t.jsonString = Telemetry.encode(json, etrIn: etrIn,
                                            etrOut: Telemetry.timestamp())
            records = [t]
        }

        var reply = LispMapReply()
        reply.nonce = req.nonce
        reply.rlocProbe = true
        reply.hopCount = innerTTL >= 0 ? UInt8(clamping: innerTTL) : 0
        reply.records = [(eidRec, records)]

        let encap = encapForRTR(control: reply.encode(), src: myRLOC.address, dst: rtr)
        dataSocket?.send(encap, to: rtr, port: LISP.dataPort)
    }

    // Data-encapsulate a control message to an RTR: data header (IID 0xffffff) +
    // inner IPv4 (src->dst) + UDP 4341->4342 + control (lisp_encap_rloc_probe).
    private func encapForRTR(control: Data, src: LispAddress, dst: LispAddress) -> Data {
        var w = ByteWriter()
        var header = LispDataHeader()
        header.setNonce(UInt32.random(in: 0...0xFFFFFF))
        header.setInstanceID(LISP.infoIID)
        w.bytes(header.encode())

        let udpLen = 8 + control.count
        var ip = ByteWriter()
        ip.u8(0x45); ip.u8(0)
        ip.u16(UInt16(20 + udpLen))
        ip.u16(0); ip.u16(0)                    // id, flags/frag
        ip.u8(64); ip.u8(17); ip.u16(0)         // ttl, UDP, checksum
        ip.bytes(src.packAddress()); ip.bytes(dst.packAddress())
        var ipH = ip.data
        let ck = internetChecksum(ipH)
        ipH[10] = UInt8(ck >> 8); ipH[11] = UInt8(ck & 0xff)
        w.bytes(ipH)

        w.u16(LISP.dataPort); w.u16(LISP.ctrlPort)   // sport 4341, dport 4342
        w.u16(UInt16(udpLen)); w.u16(0)
        w.bytes(control)
        return w.data
    }

    // MARK: - Map-Reply processing → map-cache install

    func processMapReply(_ reply: LispMapReply, from: LispAddress, receivedTTL: Int = -1) {
        if reply.rlocProbe {
            processProbeReply(reply, from: from, replyTTL: receivedTTL)
            return
        }
        // A lig (LIG tab) lookup claims its own reply for display.
        if ligService.handleReply(reply, from: from) { return }
        guard pendingMapRequests.removeValue(forKey: reply.nonce) != nil else {
            log.lprint(.itr, "Map-Reply nonce 0x\(String(reply.nonce, radix: 16)) " +
                       "has no pending Map-Request, ignoring")
            return
        }
        for (eidRec, rlocRecs) in reply.records {
            let entry = LispMapCacheEntry(eid: eidRec.eid)
            entry.action = eidRec.action
            entry.ttl = TimeInterval(eidRec.recordTTL) * 60
            for rr in rlocRecs where !rr.rloc.isNull {
                let r = LispRLOC(rloc: rr.rloc)
                r.priority = rr.priority
                r.weight = rr.weight
                r.state = rr.reachBit ? "up-state" : "unreach-state"
                entry.rlocSet.append(r)
            }
            mapCache.add(entry)
            let rlocs = entry.rlocSet.map { $0.rloc.addressString }
                .joined(separator: ", ")
            log.lprint(.itr, "Add map-cache entry EID \(eidRec.eid.prefixString), " +
                       "RLOCs [\(rlocs)], ttl \(entry.ttlString)")
            bumpMapCache()
            flushQueuedPackets(for: eidRec.eid)
        }
    }

    // MARK: - control packet dispatch

    func processControlPacket(_ data: Data, from: LispAddress, sourcePort: UInt16,
                              receivedTTL: Int = -1) {
        guard data.count >= 4 else { return }
        let type = data[data.startIndex] >> 4
        log.dprint(.core, "Receive \(data.count) bytes from \(from.addressString):" +
                   "\(sourcePort), packet: \(lispFormatPacket(data.prefix(64)))")
        switch type {
        case LISP.typeMapReply:
            if let reply = LispMapReply.decode(data) {
                processMapReply(reply, from: from, receivedTTL: receivedTTL)
            }
        case LISP.typeMapRequest:
            if let req = LispMapRequest.decode(data) {
                processMapRequest(req, from: from, sourcePort: sourcePort,
                                  receivedTTL: receivedTTL)
            }
        case LISP.typeMapNotify:
            DispatchQueue.main.async { self.lastMapNotify = Date() }
            log.lprint(.etr, "Receive Map-Notify from \(from.addressString) " +
                       "(registration acknowledged)")
        case LISP.typeNatInfo:
            log.dprint(.etr, "Info-Reply raw \(data.count) bytes: \(lispFormatPacket(data))")
            if let info = LispInfo.decode(data), info.isReply {
                processInfoReply(info, fromDataPort: false)
            }
        case LISP.typeECM:
            if let inner = LispECM.unwrap(data), inner.count >= 4 {
                processControlPacket(inner, from: from, sourcePort: sourcePort,
                                     receivedTTL: receivedTTL)
            }
        default:
            log.lprint(.core, "Unsupported LISP control type \(type) from " +
                       from.addressString)
        }
    }
}
