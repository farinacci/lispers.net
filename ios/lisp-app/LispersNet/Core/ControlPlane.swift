//
// ControlPlane.swift
//
// Registration, Map-Request/Map-Reply, Info-Request/Info-Reply, and
// RLOC-probing with telemetry. Logging mirrors the Python lprint() lines so
// lisp-itr.log / lisp-etr.log read like the originals.
//

import Foundation

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
        // key-id selects WHICH configured key on the map-server — it is NOT the
        // alg-id. lispers.net's lisp_parse_auth_key() assigns key-id 0 to a plain
        // "authentication-key" (no "[key-id]" prefix), so default to 0. Sending
        // key-id 2 made the MS hash with an empty key (auth always failed).
        register.keyID = 0
        let packet = register.encode(eidRecords: recordData, password: msConf.authKey)

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

    // Register every joined group as (0.0.0.0/0, G/32) so ITRs/RTRs can find the
    // replication list. One Map-Register per group (each hashes to its own decent
    // map-server, on the GROUP — lisp-etr.py: "use group address and no source as
    // part of hash").
    func sendGroupRegisters() {
        guard running, rloc != nil else { return }
        let iid = UInt32(config.instanceID)
        for gstr in config.joinedGroups {
            guard var group = LispAddress(string: gstr, iid: iid), group.isMulticast
            else { continue }
            group.maskLen = 32
            sendGroupRegister(group: group, ttl: LISP.multicastRegisterTTL)
        }
    }

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
        register.keyID = 0
        let packet = register.encode(eidRecords: recordData, password: msConf.authKey)

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

    func joinGroup(_ groupString: String) {
        guard let g = LispAddress(string: groupString), g.isMulticast else { return }
        let canon = g.addressString
        if !config.joinedGroups.contains(canon) {
            config.joinedGroups.append(canon)
            config.save()
        }
        guard running else { return }
        var grp = g; grp.maskLen = 32; grp.instanceID = UInt32(config.instanceID)
        sendGroupRegister(group: grp, ttl: LISP.multicastRegisterTTL)
    }

    func leaveGroup(_ groupString: String) {
        guard let g = LispAddress(string: groupString), g.isMulticast else { return }
        if running {
            var grp = g; grp.maskLen = 32; grp.instanceID = UInt32(config.instanceID)
            sendGroupRegister(group: grp, ttl: 0)       // de-register
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

    func sendInfoRequests() {
        guard running, config.eid != nil else { return }

        var info = LispInfo()
        info.nonce = lispGetControlNonce()
        info.hostname = xtrName
        lastInfoNonce = info.nonce
        let packet = info.encodeRequest()

        // ONE control-plane Info-Request, to a randomly-chosen map-server. Its reply
        // is the only one that carries the RTR-list (RTRs answer with an empty list)
        // and it also gives our control-port NAT translation. No need to ask all of
        // them — rotating one-per-interval both cuts traffic and surfaces
        // inconsistent RTR-lists across the map-server set.
        if let (msName, msAddr) = randomInfoMapServer() {
            log.lprint(.etr, "Send Info-Request to map-server \(msName) " +
                       "\(msAddr.addressString), port \(LISP.ctrlPort) (for control, RTR-list)")
            loggedSend(packet, to: msAddr, port: LISP.ctrlPort, on: ctrlSocket, .etr)
        }

        // Data-plane Info-Request to EACH RTR, per outgoing interface — data-encapsulated
        // to the RTR's DATA port 4341 ONLY. This opens/refreshes this interface's NAT data
        // binding (so the RTR can encap to us through the NAT) AND the RTR replies with our
        // translated data RLOC:port, which we register as "@tp-<port>". We do NOT also
        // Info-Request the RTR on its control port 4342 — that exchange is unnecessary; the
        // control-port translation we need for ECM Map-Requests comes from the map-server's
        // reply above, not the RTR.
        var header = LispDataHeader()
        header.setInstanceID(LISP.infoIID)
        let dataWrapped = header.encode() + packet

        for rtr in rtrList {
            log.lprint(.etr, "Send Info-Request to RTR \(rtr.addressString), " +
                       "port \(LISP.dataPort) (for data)")
            loggedSend(dataWrapped, to: rtr, port: LISP.dataPort, on: dataSocket, .etr)
        }

        // Multi-homing: repeat the per-RTR data dance out EACH interface's own
        // socket so we learn every interface's translated RLOC:port (ifaceTranslated).
        // The per-interface byte lines carry the egress interface, so no separate
        // descriptive line here.
        if config.multihomingEnabled {
            for (_, sock) in ifaceDataSockets {
                for rtr in rtrList {
                    loggedSend(dataWrapped, to: rtr, port: LISP.dataPort, on: sock, .etr)
                }
            }
        }
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
            self.behindNAT = natted
            if natted {
                self.translatedRLOC = global
                // Learn the translated DATA port from the data-socket Info-Reply,
                // exactly like lisp_process_info_reply()'s store=True path — no
                // special-casing by responder or mode. The control-socket reply
                // (fromDataPort == false) carries the control-port translation and
                // is not used for @tp.
                // Learn the translated DATA port from an RTR's data-socket Info-Reply
                // ONLY. The map-server's reply carries its own path's translation
                // (e.g. 41341) which the RTRs don't use for forwarding/probing, so it
                // must not set the port we advertise.
                // The control-socket reply (the map-server's Info-Reply on :4342) carries
                // the ctrlSocket's public NAT port — needed as the ECM Map-Request's
                // inner UDP source port so the map-server's proxy Map-Reply routes
                // back through the NAT (see translatedCtrlPort). RTRs aren't Info-Requested
                // on 4342 anymore, so this only comes from the map-server now.
                if !fromDataPort {
                    self.translatedCtrlPort = info.etrPort
                }
                if fromDataPort && isRTR {
                    if self.translatedPort != info.etrPort {
                        self.log.fprint(.etr, "Translated DATA port \(info.etrPort) " +
                            "from RTR \(source.addressString) (was \(self.translatedPort))")
                    }
                    self.translatedPort = info.etrPort
                    // Multi-homing: remember THIS interface's public RLOC:port so
                    // we can register both interfaces (a remote ITR can decap to us
                    // on either). The reply arrived on that interface's socket.
                    if let ifn = onInterface {
                        self.ifaceTranslated[ifn] = (global, info.etrPort)
                    }
                }
            } else {
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
                if behindNAT, rtrList.contains(where: { $0.v4 == r.rloc.v4 }) {
                    let encap = encapForRTR(control: packet, src: srcAddr, dst: r.rloc)
                    log.pprint(.itr, "Send RLOC-probe request to " +
                               "\(r.rloc.addressString):\(LISP.dataPort), for EID " +
                               "\(entry.eid.prefixString)\(tel), nonce 0x" +
                               String(probe.nonce, radix: 16))
                    logMapRequest(.itr, probe)
                    loggedSend(encap, to: r.rloc, port: LISP.dataPort,
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

        func rtt(_ r: LispRLOC) -> Double? { r.isUp ? r.recentRTTs.first : nil }
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
        log.lprint(.itr, "Receive RLOC-probe from \(from.addressString), " +
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
        log.lprint(.itr, "Send RLOC-probe Map-Reply to \(from.addressString):\(sourcePort)")
        logMapReply(.itr, reply)
        loggedSend(packet, to: from, port: sourcePort, on: ctrlSocket, .itr)
    }

    // Answer a data-encapsulated RLOC-probe relayed by an RTR: build the probe
    // Map-Reply (with telemetry) and data-encapsulate it back to the RTR, per
    // lisp_encap_rloc_probe (lisp.py:7555/19092). Without this the RTR marks our
    // RLOC unreach-state.
    func answerEncapsulatedProbe(_ req: LispMapRequest, fromRTR rtr: LispAddress,
                                 sourcePort: UInt16, innerTTL: Int) {
        guard let eid = config.eid, let myRLOC = rloc else { return }
        let etrIn = Telemetry.timestamp()
        log.pprint(.itr, "Receive RLOC-probe (encap) from \(rtr.addressString):\(sourcePort), " +
                   "nonce 0x\(String(req.nonce, radix: 16)) — replying to source")

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
        // Same "<xtr>@tp-<port>" the register advertises (see sendMapRegister): the
        // RTR-reported translated DATA port, so lisp.py's probe-reply matching
        // (lisp.py:18367) lands on the port the RTR uses, not the map-server's.
        if behindNAT {
            rlocRec.rlocName = "\(xtrName)\(LISP.tpPrefix)\(advertisedPort)"
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
            loggedSend(encap, to: rtr, port: sourcePort, on: dataSocket, .itr)
        } else {
            loggedSend(reply.encode(), to: rtr, port: sourcePort, on: ctrlSocket, .itr)
        }
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
