//
// ControlPlane.swift
//
// Registration, Map-Request/Map-Reply, Info-Request/Info-Reply, and
// RLOC-probing with telemetry. Logging mirrors the Python lprint() lines so
// lisp-itr.log / lisp-etr.log read like the originals.
//

import Foundation

// Parse a "[<key-id>]<key>" authentication-key: the bracketed integer becomes the Map-Register
// key-id and the remainder is the HMAC key. No (or malformed) prefix → key-id 0 and the whole
// string is the key. Mirrors lisp.py lisp_parse_auth_key().
func lispParseAuthKey(_ raw: String) -> (keyID: UInt8, key: String) {
    if raw.hasPrefix("["), let close = raw.firstIndex(of: "]"),
       let id = UInt8(raw[raw.index(after: raw.startIndex)..<close]) {
        return (id, String(raw[raw.index(after: close)...]))
    }
    return (0, raw)
}

extension LispEngine {

    // Send a packet and log it like lisp.py's lisp_send() dprint: "Send N bytes
    // to <addr>:<port>, packet: <full hex>". Centralizes per-packet hex logging so
    // every send matches the detail in lisp-itr.log / lisp-etr.log.
    func loggedSend(_ data: Data, to dest: LispAddress, port: UInt16,
                    on socket: UDPSocket?, _ comp: LogComponent) {
        // lisp_send() — this is CONTROL traffic (Map-Reg/Req/Reply, Info, probes,
        // ECM); data-plane encap bypasses loggedSend. lprint() => control-plane
        // scope, so it doesn't show when only data-plane logging is on.
        let ifn = socket?.interfaceName ?? rloc?.interfaceName ?? "?"
        log.lprint(comp, "Send \(ifn) \(data.count) bytes to \(dest.addressString) " +
                   "\(port), packet: \(lispFormatPacket(data))")
        socket?.send(data, to: dest, port: port)
    }

    // MARK: - lisp.py print_record() parity
    //
    // These reproduce the exact text the Python daemon writes to lisp-itr.log /
    // lisp-etr.log so the Logs tab reads the same (sans ANSI color).

    // print_ttl(): seconds if the high bit is set, else whole hours or minutes.
    func ttlString(_ ttl: UInt32) -> String {
        if ttl & 0x8000_0000 != 0 { return "\(ttl & 0x7fff_ffff) secs" }
        return ttl % 60 == 0 ? "\(ttl / 60) hours" : "\(ttl) mins"
    }

    private func rlocFlags(_ r: LispRLOCRecord) -> String {
        (r.localBit ? "L" : "l") + (r.probeBit ? "P" : "p") + (r.reachBit ? "R" : "r")
    }

    // print_record(): one EID-record line followed by its RLOC-record lines.
    func logEIDRecords(_ comp: LogComponent,
                       _ records: [(eid: LispEIDRecord, rlocs: [LispRLOCRecord])]) {
        for (eidRec, rlocs) in records {
            let eidStr = eidRec.group.isNull ? eidRec.eid.prefixString
                : "[\(eidRec.eid.instanceID)](\(eidRec.eid.addressString)/\(eidRec.eid.maskLen), " +
                  "\(eidRec.group.addressString)/\(eidRec.group.maskLen))"
            log.lprint(comp, "  EID-record -> record-ttl: \(ttlString(eidRec.recordTTL)), " +
                       "rloc-count: \(rlocs.count), action: \(LISP.actionString(eidRec.action)), " +
                       "\(eidRec.authoritative ? "auth" : "non-auth"), map-version: 0, " +
                       "afi: \(eidRec.eid.afi), [iid]eid/ml: \(eidStr)")
            for r in rlocs {
                if !r.rle.isEmpty {
                    let nm = r.rlocName.map { ", rloc-name: \($0)" } ?? ""
                    log.lprint(comp, "    RLOC-record -> flags: \(rlocFlags(r)), " +
                               "\(r.priority)/\(r.weight)/\(r.mpriority)/\(r.mweight), " +
                               "no-address\(nm)")
                    for n in r.rle {
                        let nnm = n.rlocName.map { " \($0)" } ?? ""
                        log.lprint(comp, "      rle: \(n.rloc.addressString)\(nnm)")
                    }
                    continue
                }
                var line = "    RLOC-record -> flags: \(rlocFlags(r)), " +
                           "\(r.priority)/\(r.weight)/\(r.mpriority)/\(r.mweight), " +
                           "afi: \(r.rloc.afi), rloc: \(r.rloc.addressString)"
                if let n = r.rlocName { line += ", rloc-name: \(n)" }
                if let j = r.jsonString { line += ", json: \(j)" }
                log.lprint(comp, line)
            }
        }
    }

    // print_map_reply(): header line + the EID/RLOC record breakdown.
    func logMapReply(_ comp: LogComponent, _ reply: LispMapReply) {
        let flags = (reply.rlocProbe ? "R" : "r") + "es"
        log.lprint(comp, "Map-Reply -> flags: \(flags), hop-count: \(reply.hopCount), " +
                   "record-count: \(reply.records.count), " +
                   "nonce: 0x\(String(reply.nonce, radix: 16))")
        logEIDRecords(comp, reply.records)
    }

    // print_map_request(): header + ITR-RLOC list (telemetry as the extra +1).
    func logMapRequest(_ comp: LogComponent, _ req: LispMapRequest) {
        // Flag order: A D R S P I M X N L D (only R/I/X/N are modeled here).
        let flags = "ad" + (req.rlocProbe ? "R" : "r") + "sp"
                  + (req.smrInvoked ? "I" : "i") + "m"
                  + (req.subscribe ? "X" : "x")
                  + (req.decentNATXtr ? "N" : "n") + "ld"
        let itrCount = max(req.itrRLOCs.count + (req.telemetryJSON != nil ? 1 : 0) - 1, 0)
        let src = req.sourceEID.isNull
            ? "[\(req.targetEID.instanceID)]no-address"
            : "[\(req.sourceEID.instanceID)]\(req.sourceEID.addressString)"
        log.lprint(comp, "Map-Request -> flags: \(flags), itr-rloc-count: \(itrCount) (+1), " +
                   "record-count: 1, nonce: 0x\(String(req.nonce, radix: 16)), " +
                   "source-eid: afi \(req.sourceEID.afi), \(src), target-eid: afi " +
                   "\(req.targetEID.afi), \(req.targetEID.prefixString), ITR-RLOCs:")
        for itr in req.itrRLOCs {
            log.lprint(comp, "  itr-rloc: afi \(itr.afi) \(itr.addressString)")
        }
        if let tel = req.telemetryJSON {
            log.lprint(comp, "  itr-rloc: afi \(LISP.afiLCAF) telemetry: \(tel)")
        }
    }

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

        // Local RLOC-record(s). Multi-homing registers EACH interface's public
        // RLOC + "@tp-<port>" so a remote ITR can decap to us on either interface
        // (outbound egress is chosen separately by best-rtt). Else the single
        // translated RLOC (@tp is the RTR-reported DATA port, engine.advertisedPort
        // — the port the RTRs use to forward/probe us, matching lisp.py's @tp parse).
        // Multi-homing registers EACH interface as its own RLOC-record: its own translated
        // ADDRESS + its own "@tp-<port>". No per-interface hostname is needed — the remote
        // end distinguishes interfaces by RLOC ADDRESS (lisp_get_nat_info matches on
        // nat_info.address, lisp.py:17173), so a shared "xtr" hostname is fine; the port
        // here is THIS interface's translated @tp (from ifaceTranslated), not a shared one.
        let locals: [(rloc: LispAddress, port: UInt16)]
        if behindNAT && config.multihomingEnabled && !ifaceTranslated.isEmpty {
            locals = ifaceTranslated.values
                .sorted { $0.rloc.v4 < $1.rloc.v4 }.map { ($0.rloc, $0.port) }
        } else if behindNAT {
            locals = [(translatedRLOC ?? myRLOC.address, advertisedPort)]
        } else {
            locals = [(myRLOC.address, 0)]
        }
        var records: [LispRLOCRecord] = []
        for (r, port) in locals {
            var rr = LispRLOCRecord()
            rr.rloc = r
            rr.priority = 1
            rr.weight = 100
            rr.localBit = true
            rr.reachBit = true
            if behindNAT { rr.rlocName = "\(xtrName)\(LISP.tpPrefix)\(port)" }
            records.append(rr)
        }
        let rlocRecord = records[0]                 // for the log line below
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
        // key-id selects WHICH configured key on the map-server — it is NOT the alg-id.
        // A plain "authentication-key" is key-id 0; a "[<key-id>]<key>" prefix overrides it
        // (lisp.py lisp_parse_auth_key), and the HMAC uses only the part after the bracket.
        let auth = lispParseAuthKey(msConf.authKey)
        register.keyID = auth.keyID
        let packet = register.encode(eidRecords: recordData, password: auth.key)

        let decent = config.decentConfigured
            ? ", decent-index \(LispDecent.index(eid: eid, modulus: config.decentModulus, prefixes: config.decentPrefixes))" : ""
        _ = rlocRecord
        let localList = locals.map { l in
            l.rloc.addressString + (behindNAT ? " (\(xtrName)\(LISP.tpPrefix)\(l.port))" : "")
        }.joined(separator: ", ")
        let msDisplay = msConf.dnsNameOrAddress.isEmpty ? msAddr.addressString : msConf.dnsNameOrAddress
        log.lprint(.etr, "Send Map-Register to map-server \(msDisplay)\(decent), " +
                   "EID-prefix \(eid.prefixString), RLOCs \(localList)")
        // print_map_register() breakdown — header + the EID/RLOC record list.
        let regFlags = (register.proxyReply ? "P" : "p") + "s"
                     + (register.xtrIDPresent ? "I" : "i")
                     + (register.useTTLForTimeout ? "T" : "t")
                     + (register.mergeRegister ? "R" : "r")
                     + (register.mobileNode ? "M" : "m")
                     + (register.wantMapNotify ? "N" : "n") + "fe"
        let algName = register.algID == LISP.sha1AlgID ? " (sha1)" : " (sha2)"
        let authLen = register.algID == LISP.sha1AlgID ? 20 : 32
        let xtrHex = String(format: "%016llx%016llx", register.xtrID.0, register.xtrID.1)
        log.lprint(.etr, "Map-Register -> flags: \(regFlags), record-count: 1, " +
                   "nonce: 0x\(String(register.nonce, radix: 16)), " +
                   "key/alg-id: \(register.keyID)/\(register.algID)\(algName), " +
                   "auth-len: \(authLen), xtr-id: 0x\(xtrHex), site-id: \(register.siteID)")
        logEIDRecords(.etr, [(eid: eidRecord, rlocs: records)])
        loggedSend(packet, to: msAddr, port: LISP.ctrlPort, on: ctrlSocket, .etr)
        DispatchQueue.main.async { self.registrationsSent += 1 }
    }

    // MARK: - Multicast group registration (lisp_send_multicast_map_register)

    // NOTE: (*,G) Map-Registers are now IGMP-triggered — every membership Report (from an
    // overlay app over the tunnel, or the LISP app self-reporting a manual group) drives one
    // sendGroupRegister via applyIGMP (see IGMP.swift). There is no periodic multicast-register
    // loop here; the unicast EID keeps its own timer (sendMapRegisters).

    // Build/send one group Map-Register (merge bit + an RLE locator with this xTR
    // at level 128). ttl 0 de-registers the group.
    func sendGroupRegister(group: LispAddress, ttl: UInt32) {
        guard let myRLOC = rloc else { return }
        guard let (msAddr, msConf) = mapServerFor(eid: group) else {
            log.lprint(.etr, "No map-server for group \(group.addressString), deferring")
            return
        }
        // Surface the destination map-server (DNS name) in the Ping tab's group row.
        let msName = msConf.dnsNameOrAddress.isEmpty ? msAddr.addressString
            : msConf.dnsNameOrAddress
        let gKey = group.addressString
        DispatchQueue.main.async { self.groupMapServers[gKey] = msName }
        var src = LispAddress(string: "0.0.0.0", iid: group.instanceID)!
        src.maskLen = 0                                 // source 0.0.0.0/0

        var eidRec = LispEIDRecord()
        eidRec.recordTTL = ttl
        eidRec.eid = src
        eidRec.group = group
        eidRec.authoritative = true

        // The receiver RLOC-record: an RLE node at level 128 with our (NAT-
        // translated) RLOC, main RLOC null, priorities 255/0/1/100 — unusable for
        // unicast, usable for multicast (lisp_send_multicast_map_register). The
        // receiver hostname (plain, no @tp) goes on the RLOC RECORD, and the RLE
        // node stays nameless. The map-server's RLE merge (merge_rles_in_site_eid)
        // SOURCES the per-node name from registered_rlocs[0].rloc_name — the RECORD
        // name — and promotes it onto each merged node, then clears the record name.
        // So a record-level name is what makes the merged-reply / lig show the name
        // per member (matching frt/cmh / lisp-etr.py:940). A node-level name is NOT
        // read by the merge and would come back empty.
        // The record name carries "@tp-<port>" behind a NAT — it MUST match the
        // name our RLOC-probe reply sends (answerEncapsulatedProbe), otherwise the
        // RTR can't match the probe reply to this registered RLE member and it
        // stays unreach. (Registering plain while probe-replying with @tp — 0.4-69
        // — is exactly what broke it.) Consistency wins over matching lisp.py's
        // plain RLE name. The map-server merge promotes this name onto the node.
        var node = RLENode()
        node.level = 128
        node.rloc = behindNAT ? (translatedRLOC ?? myRLOC.address) : myRLOC.address
        var rleRec = LispRLOCRecord()
        rleRec.priority = 255; rleRec.weight = 0
        rleRec.mpriority = 1; rleRec.mweight = 100
        rleRec.localBit = true; rleRec.reachBit = true
        rleRec.rloc = LispAddress()                     // no-address main RLOC
        rleRec.rlocName = behindNAT
            ? "\(xtrName)\(LISP.tpPrefix)\(advertisedPort)"
            : xtrName                                    // merge promotes to node
        rleRec.rle = [node]

        // The RTRs at priority 254 (rloc-count = 1 + rtr-count). The MS/RTR uses
        // these to replicate; without them the register's RLOC-set is incomplete.
        var rtrRecs: [LispRLOCRecord] = []
        for rtr in rtrList {
            var r = LispRLOCRecord()
            r.rloc = rtr
            r.priority = 254; r.weight = 0
            r.mpriority = 255; r.mweight = 0
            r.localBit = false; r.reachBit = true
            r.rlocName = "RTR"
            rtrRecs.append(r)
        }

        let allRecs = [rleRec] + rtrRecs
        eidRec.rlocCount = UInt8(allRecs.count)

        var recordData = eidRec.encode()
        for r in allRecs { recordData.append(r.encode()) }

        var register = LispMapRegister()
        register.nonce = lispGetControlNonce()
        register.recordCount = 1
        register.wantMapNotify = false
        register.mergeRegister = true                   // merge receivers into one RLE
        register.mobileNode = false                     // m clear (match the ETR)
        register.useTTLForTimeout = false               // t clear
        register.xtrID = xtrID
        register.siteID = config.siteID
        register.algID = msConf.authAlg == "sha1" ? LISP.sha1AlgID : LISP.sha2AlgID
        let auth = lispParseAuthKey(msConf.authKey)     // "[<key-id>]<key>" → key-id + HMAC key
        register.keyID = auth.keyID
        let packet = register.encode(eidRecords: recordData, password: auth.key)

        let act = ttl == 0 ? "de-register" : "register"
        let msDisplay = msConf.dnsNameOrAddress.isEmpty ? msAddr.addressString : msConf.dnsNameOrAddress
        log.lprint(.etr, "Send group Map-Register (\(act), merge) to map-server " +
                   "\(msDisplay), (\(src.addressString)/0, \(group.addressString)/32), " +
                   "RLE-node \(node.rloc.addressString), + \(rtrRecs.count) RTR(s)")
        logEIDRecords(.etr, [(eid: eidRec, rlocs: allRecs)])
        loggedSend(packet, to: msAddr, port: LISP.ctrlPort, on: ctrlSocket, .etr)
    }

    // The joined groups parsed as /32 host addresses (data-plane accept check).
    var joinedGroupAddresses: [LispAddress] {
        let iid = UInt32(config.instanceID)
        return config.joinedGroups.compactMap { s in
            guard var a = LispAddress(string: s, iid: iid), a.isMulticast else { return nil }
            a.maskLen = 32
            return a
        }
    }

    // Manual join from the LISP UI: persist it, then drive the (*,G) register the SAME way
    // an overlay app does — self-report an IGMPv2 membership Report (source "LISP app").
    func joinGroup(_ groupString: String) {
        guard let g = LispAddress(string: groupString), g.isMulticast else { return }
        let canon = g.addressString
        if !config.joinedGroups.contains(canon) {
            config.joinedGroups.append(canon)
            config.save()
        }
        guard running else { return }
        log.lprint(.etr, "Send IGMPv2 report for group \(canon) (\(Self.manualIGMPSource))")
        applyIGMP(g.v4, type: LISP.igmpV2Report, source: Self.manualIGMPSource)
    }

    func leaveGroup(_ groupString: String) {
        guard let g = LispAddress(string: groupString), g.isMulticast else { return }
        if running {
            log.lprint(.etr, "Send IGMPv2 leave for group \(g.addressString) (\(Self.manualIGMPSource))")
            applyIGMP(g.v4, type: LISP.igmpV2Leave, source: Self.manualIGMPSource)
        }
        config.joinedGroups.removeAll { $0 == g.addressString }
        groupMapServers[g.addressString] = nil
        config.save()
    }

    // MARK: - Info-Request (lisp_send_info_request, lisp.py:16376)

    // Pick a map-server to ask for the RTR-list this interval. In decent mode the
    // map-servers are 0.<suffix> .. (modulus-1).<suffix>; picking a RANDOM one each
    // interval rotates through them, so if they disagree on the RTR-list we notice
    // (processInfoReply flags the change). We do NOT need to ask every map-server —
    // one control Info-Reply carries the whole list. Non-decent: a random configured
    // map-server.
    private func randomInfoMapServer() -> (name: String, address: LispAddress)? {
        if config.decentConfigured {
            let idx = Int.random(in: 0..<max(config.decentModulus, 1))
            let name = "\(idx).\(config.decentSuffix)"
            guard let addr = DNS.resolve(name) else {
                log.lprint(.etr, "Cannot resolve decent map-server \(name)")
                return nil
            }
            return (name, addr)
        }
        let candidates = config.mapServers.filter { !$0.dnsNameOrAddress.isEmpty }
        guard let ms = candidates.randomElement(),
              let addr = DNS.resolve(ms.dnsNameOrAddress) else { return nil }
        return (ms.dnsNameOrAddress, addr)
    }

    // The NAT-traversed interfaces to egress Info-Requests out of (multi-homing);
    // single-homed = the default sockets. Shared by sendInfoRequests and the
    // triggered decent-NAT peer probe so both fan out identically.
    private func natTraversedIfaces() -> [(ifn: String?, ctrl: UDPSocket?, data: UDPSocket?)] {
        (config.multihomingEnabled && !ifaceDataSockets.isEmpty)
            ? ifaceDataSockets.keys.map { ($0, ifaceCtrlSockets[$0], ifaceDataSockets[$0]) }
            : [(nil, ctrlSocket, dataSocket)]
    }

    // Send a bare data-port (4341) Info-Request to one destination out EACH NAT interface —
    // the same NAT-punch as the RTR probes (section 3), aimed at a peer ETR. No reply expected.
    func sendNATProbe(to dest: LispAddress, reason: String) {
        guard running else { return }
        var header = LispDataHeader(); header.setInstanceID(LISP.infoIID)
        for (ifn, _, dataSock) in natTraversedIfaces() {
            let via = ifn.map { " via \($0)" } ?? ""
            var di = LispInfo(); di.nonce = lispGetControlNonce(); di.hostname = xtrName
            log.lprint(.etr, "Send NAT-Probe to ETR \(dest.addressString), port " +
                       "\(LISP.dataPort) (\(reason))\(via)")
            loggedSend(header.encode() + di.encodeRequest(), to: dest,
                       port: LISP.dataPort, on: dataSock, .etr)
        }
    }

    func sendInfoRequests() {
        guard running, config.eid != nil else { return }

        guard let (msName, msAddr) = randomInfoMapServer() else { return }

        let ifaces = natTraversedIfaces()

        infoNonceIface.removeAll()

        // (1) Control Info-Request (4342) to ONE map-server, out EACH interface. Each reply
        // carries THIS interface's translated RLOC (global-rloc) — which is what we register —
        // plus the RTR-list + control-port translation. Nonce → interface so each reply's
        // translated RLOC is registered for the interface it egressed on.
        for (ifn, ctrlSock, _) in ifaces {
            var ci = LispInfo(); ci.nonce = lispGetControlNonce(); ci.hostname = xtrName
            lastInfoNonce = ci.nonce
            if let ifn = ifn { infoNonceIface[ci.nonce] = ifn }
            let via = ifn.map { " via \($0)" } ?? ""
            log.lprint(.etr, "Send Info-Request to map-server \(msName) " +
                       "\(msAddr.addressString), port \(LISP.ctrlPort) (for control, RTR-list)" +
                       "\(via), nonce 0x\(String(ci.nonce, radix: 16))")
            loggedSend(ci.encodeRequest(), to: msAddr, port: LISP.ctrlPort, on: ctrlSock, .etr)
        }

        // (2) Info-Request to the MAP-SERVER on the CONTROL port (4342) but egressed the DATA
        // socket — this is the one we want a REPLY to: it teaches us our translated DATA @tp so we
        // can register @tp-<real port> (decent-NAT direct path — an ITR encaps straight to our
        // public addr:@tp). This mirrors lisp.py exactly: the ETR sends every Info-Request from ONE
        // socket (lisp_ephem_socket), the same socket that receives encapsulated data, so the
        // map-server's echoed etr_port IS that socket's NAT translation. The map-server only answers
        // on 4342 (it has no data-plane on 4341), so the DEST is 4342; the LOCAL SOURCE port is what
        // determines the @tp, and here it's the data socket's — the same local port the RTR requests
        // below and inbound data use. BARE Info-Request (control message, no data header). Nonce →
        // interface so processInfoReply(fromDataPort:) records THIS interface's @tp.
        for (ifn, _, dataSock) in ifaces {
            var di = LispInfo(); di.nonce = lispGetControlNonce(); di.hostname = xtrName
            if let ifn = ifn { infoNonceIface[di.nonce] = ifn }
            let via = ifn.map { " via \($0)" } ?? ""
            log.lprint(.etr, "Send Info-Request to map-server \(msName) " +
                       "\(msAddr.addressString), port \(LISP.ctrlPort) from data socket " +
                       "(for translated @tp)\(via), nonce 0x\(String(di.nonce, radix: 16))")
            loggedSend(di.encodeRequest(), to: msAddr, port: LISP.ctrlPort, on: dataSock, .etr)
        }
        var header = LispDataHeader(); header.setInstanceID(LISP.infoIID)

        // (3) Data Info-Request (4341) to EACH RTR, out EACH interface — ONE-WAY NAT-punch so each
        // RTR caches this interface's translated DATA port in its lisp-nat-info table (it uses that
        // for forwarding; the RTR ignores @tp in the name). No reply expected. Bare like lisp.py.
        for (ifn, _, dataSock) in ifaces {
            let via = ifn.map { " via \($0)" } ?? ""
            for rtr in rtrList {
                var di = LispInfo(); di.nonce = lispGetControlNonce(); di.hostname = xtrName
                log.lprint(.etr, "Send Info-Request to RTR \(rtr.addressString), " +
                           "port \(LISP.dataPort) (for data, NAT-punch — no reply expected)\(via)")
                loggedSend(header.encode() + di.encodeRequest(), to: rtr,
                           port: LISP.dataPort, on: dataSock, .etr)
            }
        }

        // (4) DECENT-NAT: NAT-probe each resolved peer ETR (lisp_etr_nat_probe_list) on 4341,
        // out each interface — opens our local NAT hole toward the peer so we can encap directly
        // (bypassing the RTR). Only when decent-NAT is on; the list is fed from 240/x map-cache
        // RLOCs that carry an @tp name (processMapReply). Same NAT-punch as the RTR probes above.
        if config.decentNATEnabled {
            for peer in natProbeList.values {
                sendNATProbe(to: peer, reason: "decent-NAT peer, periodic")
            }
        }
    }

    // A decent-NAT prober (an RTR or a peer ETR, per lisp_etr_nat_probe_list) NAT-probes us with
    // an Info-REQUEST to keep our NAT binding open and confirm reachability. We MUST answer with
    // an Info-Reply echoing the prober's translated addr:port — an unanswered probe flips our
    // registered RLOC to unreach-state. Mirrors lisp_process_info_request (lisp.py:16512).
    func processInfoRequest(_ info: LispInfo, from source: LispAddress,
                            sourcePort: UInt16, fromDataPort: Bool,
                            onInterface: String? = nil) {
        guard running else { return }
        // sport == 0 is a pure NAT-pierce (a remote ITR opening the hole) — no reply needed.
        guard sourcePort != 0 else {
            log.lprint(.etr, "Receive Info-Request (NAT-pierce) from " +
                       "\(source.addressString) — hole punched, no reply")
            return
        }
        var reply = LispInfo()
        reply.nonce = info.nonce
        reply.globalETRRLOC = source        // echo the prober's translated address
        reply.etrPort = sourcePort          // echo the prober's translated port
        let packet = reply.encodeReply(echoHostname: info.hostname)
        let sock = fromDataPort ? dataSock(for: onInterface) : ctrlSock(for: onInterface)
        log.lprint(.etr, "Receive Info-Request from \(source.addressString) \(sourcePort) " +
                   "(\(fromDataPort ? "data" : "control")) — sending Info-Reply (NAT-probe answer)")
        loggedSend(packet, to: source, port: sourcePort, on: sock, .etr)
    }

    func processInfoReply(_ info: LispInfo, from source: LispAddress,
                          sourcePort: UInt16, fromDataPort: Bool,
                          onInterface: String? = nil) {
        guard let myRLOC = rloc else { return }
        let global = info.globalETRRLOC
        let isRTR = rtrList.contains { $0.v4 == source.v4 }
        let nhIn = onInterface.map { " on nh \($0)" } ?? ""
        log.lprint(.etr, "Info-Reply from \(source.addressString) \(sourcePort)\(nhIn) " +
                   "(\(fromDataPort ? "data" : "control")\(isRTR ? ", RTR" : "")) -> " +
                   "nonce 0x\(String(info.nonce, radix: 16)), " +
                   "global-rloc: \(global.addressString), etr-port: \(info.etrPort), " +
                   "ms-port: \(info.msPort), RTR-list: " +
                   (info.rtrList.isEmpty ? "empty"
                    : info.rtrList.map { $0.addressString }.joined(separator: ", ")))

        // Compare as an unordered set so a mere reordering between map-servers isn't
        // treated as a change.
        let newSig = info.rtrList.map { $0.v4 }.sorted()
        let curSig = rtrList.map { $0.v4 }.sorted()
        if !info.rtrList.isEmpty && newSig != curSig {
            let wasEmpty = rtrList.isEmpty
            let old = rtrList.map { $0.addressString }.joined(separator: ", ")
            rtrList = info.rtrList
            let rtrs = rtrList.map { $0.addressString }.joined(separator: ", ")
            if wasEmpty {
                log.fprint(.etr, "Cached \(rtrList.count) RTR(s) from Info-Reply: \(rtrs)")
            } else {
                // We rotate the map-server we ask each interval, so an RTR-list that
                // CHANGES from what we already had usually means the decent
                // map-servers disagree — flag it as a likely misconfiguration.
                log.fprint(.etr, "RTR-list CHANGED [\(old)] -> [\(rtrs)] from map-server " +
                           "\(source.addressString) — map-servers may be inconsistently " +
                           "configured with the RTR-list")
            }
            installRTRDefaultMapCacheEntries()
        }

        let natted = !global.isNull && global != myRLOC.address
        DispatchQueue.main.async {
            // The interface this reply belongs to — by the NONCE of the request that egressed
            // it (infoNonceIface), NOT the socket that caught it (SO_REUSEPORT can misdeliver).
            // The globally-advertised translation reflects the PRIMARY interface (or single-
            // homed); each other interface keeps its own translation in ifaceTranslated.
            // The interface this reply is for — by the NONCE of the control Info-Request that
            // egressed it (infoNonceIface), not the socket that caught it (SO_REUSEPORT can
            // misdeliver). The globally-advertised translation reflects the PRIMARY interface
            // (single-homed uses it directly); each other interface keeps its own translated
            // RLOC in ifaceTranslated for its own registered RLOC-record.
            let replyIface = self.infoNonceIface[info.nonce] ?? onInterface
            let isPrimary = (replyIface == nil || replyIface == self.rloc?.interfaceName)
            self.behindNAT = natted
            if natted {
                if fromDataPort {
                    // DATA-port Info-Reply (map-server) → our translated DATA @tp for THIS
                    // interface. Register @tp-<this real port> so an ITR can encap directly to us
                    // (decent-NAT direct path). Keep the interface's translated ADDRESS (learned
                    // from its control reply); set the port.
                    if isPrimary { self.translatedPort = info.etrPort }
                    if let ifn = replyIface {
                        let addr = self.ifaceTranslated[ifn]?.rloc ?? global
                        if self.ifaceTranslated[ifn]?.port != info.etrPort {
                            self.log.fprint(.etr, "Interface \(ifn) translated @tp port " +
                                "\(info.etrPort) (nonce 0x\(String(info.nonce, radix: 16)))")
                        }
                        self.ifaceTranslated[ifn] = (addr, info.etrPort)
                    }
                } else {
                    // CONTROL-port Info-Reply (map-server) → this interface's translated RLOC
                    // ADDRESS (global) + control-port translation (for ECM Map-Requests). Keep any
                    // @tp port already learned from the data reply; default to natDataPort until it
                    // arrives (the RTR relay works meanwhile).
                    if isPrimary {
                        self.translatedRLOC = global
                        self.translatedCtrlPort = info.etrPort
                    }
                    if let ifn = replyIface {
                        let port = self.ifaceTranslated[ifn]?.port ?? LISP.natDataPort
                        if self.ifaceTranslated[ifn]?.rloc != global {
                            self.log.fprint(.etr, "Interface \(ifn) translated RLOC " +
                                "\(global.addressString) (nonce 0x\(String(info.nonce, radix: 16)))")
                        }
                        self.ifaceTranslated[ifn] = (global, port)
                    }
                }
            } else if isPrimary {
                self.translatedRLOC = nil
                self.translatedPort = 0
                self.translatedCtrlPort = 0
            }
        }
        // Re-register through the NAT once the Info-Reply burst settles. One
        // Info-Request cycle draws 6-8 replies (both RTRs × every interface, plus
        // retransmits) within a few ms; firing a Map-Register per reply was the storm
        // seen in lisp-etr.log. DEBOUNCE instead: (re)schedule a single register a
        // short time out, so the burst collapses to ONE register that carries the
        // fully-learned translated port. This keeps the per-cycle NAT keepalive the
        // RTRs need to keep forwarding to us (so RLOC-probe replies keep arriving and
        // RLOCs stay up) — suppressing it entirely, as the old change-detection did,
        // starved that path and froze packet-counts.
        DispatchQueue.main.async {
            self.pendingRegisterWork?.cancel()
            let work = DispatchWorkItem { [weak self] in
                guard let self = self, self.running else { return }
                if self.behindNAT, let g = self.translatedRLOC {
                    self.log.fprint(.etr, "xTR is behind NAT: translated RLOC " +
                               "\(g.addressString):\(self.advertisedPort)")
                }
                self.sendMapRegisters()
                self.reregisterIGMPGroups()          // (*,G) with the freshly-learned @tp port
            }
            self.pendingRegisterWork = work
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25, execute: work)
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
        // Advertise the TRANSLATED (public) RLOC as our ITR-RLOC when behind a
        // NAT — the map-server proxy-replies TO the itr-rloc, so a private RLOC
        // here sends the Map-Reply to an unroutable address and it never arrives.
        // (lig does the same; this is why lig got replies and ping didn't.)
        req.itrRLOCs = [behindNAT ? (translatedRLOC ?? myRLOC.address) : myRLOC.address]
        // N flag: ask the map-server to skip lisp_get_partial_rloc_set and return
        // the FULL registered RLOC-set (public ETR + RTRs), not just the RTRs.
        req.decentNATXtr = true
        var target = destEID
        target.maskLen = 32
        req.targetEID = target
        pendingMapRequests[req.nonce] = target

        let inner = req.encode()
        // Behind a NAT the map-server proxy-replies to itr-rloc:<inner UDP src
        // port>, so the ECM inner source MUST be our TRANSLATED RLOC + translated
        // CONTROL port (not the EID / 4342) — otherwise the reply lands on a port
        // with no NAT mapping and is dropped. Mirrors the working lig path.
        let ecmSrcRLOC = behindNAT ? (translatedRLOC ?? myRLOC.address) : myRLOC.address
        let ecmSrcPort = (behindNAT && translatedCtrlPort != 0) ? translatedCtrlPort : LISP.ctrlPort
        let ecm = LispECM.wrap(control: inner, innerSource: ecmSrcRLOC,
                               innerDest: target, sourcePort: ecmSrcPort,
                               destPort: LISP.ctrlPort, toMS: true)
        // Under LISP-Decent, note which lookup-prefix the dest EID matched (the
        // masked prefix that's hashed to pick this map-resolver) — matters when
        // decent-NAT is used so we know which lookup-prefix selected the resolver.
        let lp = config.decentConfigured
            ? ", lookup-prefix \(LispDecent.eidString(for: destEID, prefixes: config.decentPrefixes))" : ""
        log.lprint(.itr, "Send Map-Request (ECM) to map-resolver \(msAddr.addressString), " +
                   "for EID \(target.prefixString)\(lp)")
        logMapRequest(.itr, req)
        loggedSend(ecm, to: msAddr, port: LISP.ctrlPort, on: ctrlSocket, .itr)
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
        var probedKeys = Set<String>()
        // Include the egress interface so multi-homing probes the SAME RTR once
        // per interface (Wi-Fi + cellular) instead of deduping them into one.
        func probeKey(_ rl: LispRLOC) -> String {
            let p = rl.encapPort != LISP.dataPort ? rl.encapPort : LISP.ctrlPort
            return "\(rl.rloc.v4):\(p):\(rl.interfaceName ?? "")"
        }
        for entry in snapshot {
            for r in entry.rlocSet {
                // Mark unreachable if probes have been outstanding (no reply)
                // for longer than the wait window. We measure from when the
                // CURRENT unanswered run began (probeOutstandingSince), NOT from
                // the last send: re-sends happen every probe interval (< wait),
                // so "now - lastProbeSent" never crosses the wait and could
                // never fire while we keep probing.
                if let out = r.probeOutstandingSince,
                   Date().timeIntervalSince(out) > LISP.rlocProbeReplyWait, r.isUp {
                    r.state = "unreach-state"
                    r.stateChange = Date()
                    // Drop the now-stale telemetry: showing the last good rtts/
                    // hops/lats next to an unreachable RLOC reads as "still being
                    // answered" when it isn't. They repopulate on the next reply.
                    r.recentRTTs = []
                    r.recentHops = []
                    r.recentLatencies = []
                    log.pprint(.itr, "RLOC \(r.rloc.addressString) went unreachable, " +
                               "no RLOC-probe reply")
                    recomputeActiveNextHops()
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
                // Multi-homing: advertise the egress interface's own source
                // address as the itr-rloc (the socket is bound to it), so this
                // next-hop is probed as its own path. Single-homed: myRLOC.
                let srcAddr = r.interfaceName.flatMap { n in
                    mhInterfaces.first { $0.interfaceName == n }?.address } ?? myRLOC.address
                probe.itrRLOCs = [srcAddr]
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
                        // Reserve a "?" slot for THIS probe. A matching reply fills it
                        // (processProbeReply); if none comes it stays "?". The slot count
                        // shows how many probes have gone out — [?] after one, [?, ?] after
                        // two, [?, ?, ?] after three.
                        s.probeSent()
                        s.lastProbeNonce = probe.nonce
                        s.lastProbeSent = sentAt
                        // Begin the unanswered run on the first send after a
                        // reply (or from creation); leave it alone once set so
                        // the unreach timer keeps counting across re-sends.
                        if s.probeOutstandingSince == nil {
                            s.probeOutstandingSince = sentAt
                        }
                    }
                }
                let packet = probe.encode()
                let tel = config.telemetryEnabled ? ", with telemetry" : ""

                // Behind a NAT, probing an RTR: DATA-ENCAPSULATE the probe to the
                // RTR's data port 4341 (just like the RTR probes us, and like
                // answerEncapsulatedProbe). A raw probe to the RTR's control port
                // gets a raw reply aimed at our control-port translation, which
                // many NATs won't return (observed: 0 replies on 4342). The RTR
                // sees sport==0 on a data-encap'd probe and data-encaps the reply
                // back to our translated :<dataport> mapping — which IS kept open
                // by registers + the RTR's own probes — so the reply (with rtt/
                // hops/lats telemetry) returns on the data socket. The reply rides
                // the existing relay path in processDataPacket -> processProbeReply.
                // Multi-homing: send out this next-hop's interface socket. The
                // egress interface shows on the "Send <if> N bytes" byte line the
                // loggedSend below emits, not here. Single-homed: default socket.
                // DATA-ENCAPSULATE the probe to any NAT'd peer we reach via encap: an RTR
                // (encapPort 4341) OR a decent-NAT peer (encapPort = its translated @tp).
                // A NAT'd peer's data plane only processes LISP-encapsulated packets on its
                // data port, so a RAW control-port probe to it is dropped — it never replies
                // and the RLOC wrongly shows unreach even while our data flows to it. Send to
                // the peer's encapPort (4341 for an RTR, the @tp for a decent peer), the same
                // port our data traffic uses. The reply returns data-encap on our data socket.
                if behindNAT, rtrList.contains(where: { $0.v4 == r.rloc.v4 })
                              || r.encapPort != LISP.dataPort {
                    let encap = encapForRTR(control: packet, src: srcAddr, dst: r.rloc)
                    log.pprint(.itr, "Send RLOC-probe request to " +
                               "\(r.rloc.addressString):\(r.encapPort) (encap), for EID " +
                               "\(entry.eid.prefixString)\(tel), nonce 0x" +
                               String(probe.nonce, radix: 16))
                    logMapRequest(.itr, probe)
                    loggedSend(encap, to: r.rloc, port: r.encapPort,
                               on: dataSock(for: r.interfaceName), .itr)
                } else {
                    // Not NAT'd (or a direct xTR RLOC): raw probe to the control
                    // port; the reply returns raw on 4342.
                    let port = r.encapPort != LISP.dataPort ? r.encapPort : LISP.ctrlPort
                    log.pprint(.itr, "Send RLOC-probe request to \(r.rloc.addressString):\(port), " +
                               "for EID \(entry.eid.prefixString)\(tel), nonce 0x" +
                               String(probe.nonce, radix: 16))
                    logMapRequest(.itr, probe)
                    loggedSend(packet, to: r.rloc, port: port,
                               on: ctrlSock(for: r.interfaceName), .itr)
                }
            }
        }
    }

    // Multi-homing (lisp.py select_rloc_next_hop): within each entry, group an
    // RTR's next-hop RLOCs by address and mark the up one with the lowest recent
    // rtt as active ("*"); the rest inactive. Single-homed RLOCs are untouched.
    // Choose the egress next-hop per RTR, porting lisp.py select_rloc_next_hop
    // (lisp.py:14033). The same RTR appears under both the unicast and multicast
    // default entries, so gather its next-hops across ALL entries and decide once
    // — then apply the choice (and log) a single time per RTR address.
    func recomputeActiveNextHops() {
        var groups: [UInt32: [LispRLOC]] = [:]
        for entry in mapCache.snapshot() {
            for r in entry.rlocSet where r.interfaceName != nil {
                groups[r.rloc.v4, default: []].append(r)
            }
        }
        for (_, hops) in groups { selectNextHop(hops) }
    }

    // Port of lisp.py select_rloc_next_hop: pick the min-rtt up next-hop, but only
    // *switch* egress when it beats the currently-active next-hop by ≥ mhRTTPct
    // (10%) of that rtt — the hysteresis that stops jitter from oscillating. rtts
    // are in seconds (recentRTTs.first = newest), matching lisp.py's units.
    private func selectNextHop(_ hops: [LispRLOC]) {
        guard !hops.isEmpty else { return }
        let addr = hops[0].rloc.addressString

        // Newest ACTUAL rtt (skip "?" lost-probe slots) for the best-next-hop choice.
        func rtt(_ r: LispRLOC) -> Double? { r.isUp ? r.recentRTTs.compactMap { $0 }.first : nil }
        func isCellular(_ r: LispRLOC) -> Bool {
            r.interfaceName?.hasPrefix("pdp_ip") ?? false
        }

        // Only a next-hop with actual RLOC-probe rtt data can be judged "best".
        // When NO next-hop has proving data (Dino's rule), assume the cellular
        // (pdp_ip*) link has the better rtt and make it active — never a data-less
        // en0. (Wi-Fi behind CGNAT/VPN often gets no probe reply at all.)
        guard let best = hops.filter({ rtt($0) != nil }).min(by: { rtt($0)! < rtt($1)! }) else {
            let pick = hops.first(where: isCellular) ?? hops[0]
            for h in hops { h.activeNextHop = (h.interfaceName == pick.interfaceName) }
            return
        }
        let bestRTT = rtt(best)!
        let device = best.interfaceName ?? "?"

        // The currently-active hop is a valid rtt baseline ONLY if it has its own
        // data. A data-less active (e.g. en0 with rtts [?,?,?]) cannot be "better",
        // so adopt the data-bearing best outright — the fix for the "* on en0 with
        // no data" case.
        let active = hops.first { $0.activeNextHop }
        let oldDevice = active?.interfaceName
        guard let baselineRTT = active.flatMap(rtt) else {
            for h in hops { h.activeNextHop = (h.interfaceName == best.interfaceName) }
            if oldDevice != device {
                log.pprint(.itr, "Change egress \(oldDevice ?? "none") -> \(device) " +
                           "for RLOC \(addr), best-rtt \(fmtSecs(bestRTT)) secs")
            }
            return
        }

        // Both baseline and best have data → lisp.py select_rloc_next_hop hysteresis:
        // switch only when best is at least mhSwitchPct% better than the active
        // next-hop (configurable on the xTR tab; default 10%). Log line mirrors
        // lisp.py's format exactly.
        let pct = config.mhSwitchPct
        let diff = baselineRTT * Double(pct) / 100.0
        let better = bestRTT <= (baselineRTT - diff)
        if hops.count >= 2 {
            // lisp.py tag: ", switch" when we move to a different, better interface;
            // ", same-interface" when the active interface stays the best (no
            // data-plane change); "" when a better-rtt interface exists but hysteresis
            // holds us. lisp.py ties "same-interface" to a better next-hop ON the
            // active device — iOS has one next-hop per interface, so the equivalent is
            // simply "device unchanged".
            let tag = (oldDevice == device) ? ", same-interface" : (better ? ", switch" : "")
            log.pprint(.itr, "RLOC \(addr) (\(device)) new rtt \(fmtSecs(bestRTT)) " +
                       "\(better ? "<=" : ">") \(pct)% of last rtt \(fmtSecs(baselineRTT))\(tag)")
        }
        guard better, oldDevice != device else { return }
        for h in hops { h.activeNextHop = (h.interfaceName == best.interfaceName) }
        log.pprint(.itr, "Change egress \(oldDevice ?? "none") -> \(device) " +
                   "for RLOC \(addr), best-rtt \(fmtSecs(bestRTT)) secs")
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
                    latency = "\(fmt3(fwd))/\(fmt3(rev))"   // 3-decimal, shown in the reply line
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
                r.probeOutstandingSince = nil   // reply ends the unanswered run
                if let sent = r.lastProbeSent {
                    let rtt = now.timeIntervalSince(sent).rounded(toPlaces: 3)
                    r.storeRTT(rtt)
                    if !loggedRTT {
                        // Full lisp.py-style line: rtt, hop counts (to-ttl/from-ttl),
                        // and latency (fwd/rev) all in one message.
                        let fromTTL = replyTTL >= 0 ? "\(replyTTL)" : "?"
                        let st = r.isUp ? "up-state" : "unreach-state"
                        // Multi-homing: which interface this reply came in on.
                        log.pprint(.itr, "Receive RLOC-probe reply " +
                                   "from \(from.addressString) " +
                                   "for \(entry.eid.prefixString), \(st) -> up, rtt \(fmtSecs(rtt)) secs, " +
                                   "to-ttl/from-ttl \(reply.hopCount)/\(fromTTL), " +
                                   "latency \(latency ?? "?/?"), " +
                                   "nonce 0x\(String(reply.nonce, radix: 16))")
                        loggedRTT = true
                    }
                }
                // to-hops from the responder's echoed received-TTL (Map-Reply
                // hop-count); from-hops from the reply's own received TTL.
                r.storeHops(toReceivedTTL: Int(reply.hopCount), fromReceivedTTL: replyTTL)
                if !r.isUp {
                    r.state = "up-state"
                    r.stateChange = now
                    let nh = r.interfaceName.map { " on nh \($0)" } ?? ""
                    log.pprint(.itr, "RLOC \(from.addressString)\(nh) is reachable again")
                }
                if let l = latency { r.storeLatency(l) }
            }
        }
        if matched { recomputeActiveNextHops(); bumpMapCache() }
        else {
            // A probe reply DID arrive but no map-cache RLOC is waiting on this nonce.
            // Splits "reply never comes back" (a path/NAT problem — no log at all) from
            // "reply arrives but we can't match it" (a nonce/rebuild bug) — the two need
            // opposite fixes. Include the outstanding nonces so a mismatch is obvious.
            let outstanding = mapCache.snapshot().flatMap { $0.rlocSet }
                .compactMap { $0.lastProbeNonce }.map { "0x\(String($0, radix: 16))" }
            log.pprint(.itr, "Receive RLOC-probe reply from \(from.addressString) " +
                       "nonce 0x\(String(reply.nonce, radix: 16)) — NO MATCH (outstanding: " +
                       "\(outstanding.isEmpty ? "none" : outstanding.joined(separator: ", ")))")
        }
    }

    // Answer RLOC-probes aimed at us so peers' telemetry works
    // (lisp_build_map_reply with probe bit + telemetry RLOC-record).
    func processMapRequest(_ req: LispMapRequest, from: LispAddress, sourcePort: UInt16,
                           receivedTTL: Int = -1) {
        guard let eid = config.eid, let myRLOC = rloc else { return }
        guard req.rlocProbe else {
            log.lprint(.itr, "Ignoring non-probe Map-Request from \(from.addressString)")
            return
        }
        let etrIn = Telemetry.timestamp()
        log.lprint(.itr, "Receive RLOC-probe request from \(from.addressString), " +
                   "nonce 0x\(String(req.nonce, radix: 16))")
        logMapRequest(.itr, req)

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
        log.lprint(.itr, "Send RLOC-probe reply to \(from.addressString):\(sourcePort)")
        logMapReply(.itr, reply)
        loggedSend(packet, to: from, port: sourcePort, on: ctrlSocket, .itr)
    }

    // Answer a data-encapsulated RLOC-probe relayed by an RTR: build the probe
    // Map-Reply (with telemetry) and data-encapsulate it back to the RTR, per
    // lisp_encap_rloc_probe (lisp.py:7555/19092). Without this the RTR marks our
    // RLOC unreach-state.
    func answerEncapsulatedProbe(_ req: LispMapRequest, fromRTR rtr: LispAddress,
                                 sourcePort: UInt16, innerTTL: Int,
                                 onInterface: String? = nil) {
        guard let eid = config.eid, let myRLOC = rloc else { return }
        // Reply as the interface the probe ARRIVED on (multi-homing): the RTR probed a
        // specific translated RLOC:port, so the answer must carry that same RLOC/@tp AND
        // egress that same interface's socket — otherwise the RTR sees the reply from a
        // different translation (the default socket egresses the OS default route, e.g.
        // Wi-Fi) and leaves the probed RLOC unreach.
        let ifTrans = onInterface.flatMap { ifaceTranslated[$0] }
        let probeData = onInterface.flatMap { ifaceDataSockets[$0] } ?? dataSocket
        let probeCtrl = onInterface.flatMap { ifaceCtrlSockets[$0] } ?? ctrlSocket
        let etrIn = Telemetry.timestamp()
        log.pprint(.itr, "Receive RLOC-probe request (encap) from \(rtr.addressString):\(sourcePort), " +
                   "nonce 0x\(String(req.nonce, radix: 16)) — replying to source")

        var eidRec = LispEIDRecord()
        eidRec.recordTTL = LISP.registerTTL
        eidRec.eid = eid

        var rlocRec = LispRLOCRecord()
        rlocRec.rloc = behindNAT ? (ifTrans?.rloc ?? translatedRLOC ?? myRLOC.address) : myRLOC.address
        rlocRec.priority = 1
        rlocRec.weight = 100
        rlocRec.localBit = true
        rlocRec.probeBit = true
        rlocRec.reachBit = true
        // Same "<xtr>@tp-<port>" the register advertises (see sendMapRegister): the
        // RTR-reported translated DATA port, so lisp.py's probe-reply matching
        // (lisp.py:18367) lands on the port the RTR uses, not the map-server's.
        if behindNAT {
            let port = ifTrans?.port ?? advertisedPort
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

        // lisp_etr_process_map_request: data-encapsulate the RLOC-probe reply
        // ONLY back to an RTR. For a direct prober (a public xTR like lhr) send a
        // RAW Map-Reply out the control socket to itr_rloc:sport (the default
        // lisp_send_map_reply path) — a public ITR ignores a data-encap'd reply,
        // which is why lhr stayed unreach while the RTR went up.
        if rtrList.contains(where: { $0.v4 == rtr.v4 }) {
            let encap = encapForRTR(control: reply.encode(), src: myRLOC.address, dst: rtr)
            loggedSend(encap, to: rtr, port: sourcePort, on: probeData, .itr)
            // The RTR does NOT answer our RLOC-probes with a Map-Reply — it PROBES US
            // instead (lisp_rtr_process_map_request), and our reply here is what keeps us
            // up on ITS side. So RECEIVING the RTR's probe is our liveness signal for it:
            // mark the RTR's map-cache RLOC(s) reachable and clear the outstanding-probe
            // timer, so our own (never-answered) probes don't flip it to unreach. If the
            // RTR dies it stops probing us, probeOutstandingSince stays set, and the
            // existing unreach timer (sendRLOCProbes) demotes it after rlocProbeReplyWait.
            markRTRReachableFromInboundProbe(rtr)
        } else {
            loggedSend(reply.encode(), to: rtr, port: sourcePort, on: probeCtrl, .itr)
        }
    }

    // Mark every map-cache RLOC that IS this RTR reachable (it just probed us). Runs on
    // the socket queue like processProbeReply, which mutates RLOC state the same way.
    private func markRTRReachableFromInboundProbe(_ rtr: LispAddress) {
        let now = Date()
        var changed = false
        for entry in mapCache.snapshot() {
            for r in entry.rlocSet where r.rloc.v4 == rtr.v4 {
                r.probeOutstandingSince = nil       // its probe cancels our unreach countdown
                // NOTE: do NOT set lastProbeReply here — that field means "a reply to OUR
                // probe arrived" and gates the lost-probe "?" in sendRLOCProbes. Receiving
                // the RTR's probe proves liveness (up-state) but our own probe may still be
                // unanswered, which must still record a "?". Clearing the unreach countdown
                // above is enough to keep it up.
                if !r.isUp {
                    r.state = "up-state"; r.stateChange = now
                    log.pprint(.itr, "RLOC \(rtr.addressString) reachable (received its RLOC-probe)")
                    changed = true
                }
            }
        }
        if changed { recomputeActiveNextHops() }
        bumpMapCache()
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
        // lisp.py logs the full Map-Reply breakdown for every reply received,
        // before deciding whether it's a probe / lig / map-cache reply.
        logMapReply(.itr, reply)
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
                r.rlocName = rr.rlocName
                // Parse "<name>@tp-<port>" and encapsulate to that NAT-translated
                // data port (lisp.py store_decent_nat_port). Otherwise we'd encap
                // to 4341 and the peer's NAT would drop it.
                if let name = rr.rlocName, let tp = name.range(of: LISP.tpPrefix),
                   let port = UInt16(name[tp.upperBound...]) {
                    r.encapPort = port
                    // Decent-NAT: this peer ETR is behind a NAT (carries an @tp name). NAT-probe
                    // it so our local NAT opens a hole toward it and it caches our translated port
                    // — enabling direct ETR↔ETR encap (bypassing the RTR). Trigger an immediate
                    // probe the first time we see it (low join latency); thereafter it rides the
                    // periodic Info-Request timer (sendInfoRequests section 4). Mirrors lisp-etr.py
                    // lisp_etr_nat_probe (1885): add to list + trigger on first appearance.
                    if config.decentNATEnabled, natProbeList[rr.rloc.v4] == nil {
                        natProbeList[rr.rloc.v4] = rr.rloc
                        sendNATProbe(to: rr.rloc, reason: "decent-NAT peer, triggered")
                    }
                }
                entry.rlocSet.append(r)
            }
            mapCache.add(entry)
            log.lprint(.itr, "Replace \(eidRec.eid.prefixString) map-cache with " +
                       "\(entry.rlocSet.count) RLOCs")
            bumpMapCache()
            flushQueuedPackets(for: eidRec.eid)
        }
    }

    // MARK: - control packet dispatch

    func processControlPacket(_ data: Data, from: LispAddress, sourcePort: UInt16,
                              receivedTTL: Int = -1, onInterface: String? = nil) {
        guard data.count >= 4 else { return }
        let type = data[data.startIndex] >> 4
        // Log the raw receive under the scope that will process it, so an
        // RLOC-probe reply (Map-Reply) — or an incoming probe (Map-Request) —
        // shows a "Receive ..." line in lisp-itr.log right above its Map-Reply
        // breakdown, the way Info-Replies / data packets do in lisp-etr.log.
        let recvComp: LogComponent
        switch type {
        case LISP.typeMapReply, LISP.typeMapRequest: recvComp = .itr
        case LISP.typeMapNotify, LISP.typeNatInfo:    recvComp = .etr
        default:                                      recvComp = .core
        }
        let rifn = onInterface ?? rloc?.interfaceName ?? "?"
        log.lprint(recvComp, "Receive \(rifn) \(data.count) bytes from \(from.addressString) " +
                   "\(sourcePort), packet: \(lispFormatPacket(data))")
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
            log.lprint(.etr, "Info-Reply raw \(data.count) bytes: \(lispFormatPacket(data))")
            if let info = LispInfo.decode(data), info.isReply {
                processInfoReply(info, from: from, sourcePort: sourcePort,
                                 fromDataPort: false)
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
