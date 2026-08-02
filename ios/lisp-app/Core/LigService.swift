//
// LigService.swift
//
// LISP Internet Groper (lisp-lig.py) — a mapping-system lookup. Uses a DEDICATED
// ephemeral UDP socket: the Info-Request and the ECM Map-Request both go out that
// one socket to the map-resolver:4342, so the NAT keeps a single consistent
// mapping and the proxy Map-Reply comes straight back to us (the engine's shared
// 4342/4341 sockets translate inconsistently toward the MS, which dropped the
// reply). Renders the returned Map-Reply in lisp-lig.py's output format.
//

import Foundation
import Combine

struct RLEMember { let rloc: String; let name: String? }

struct LigLine: Identifiable {
    let id = UUID()
    let content: Content
    enum Content {
        case plain(String)                                  // black text
        case error(String)                                  // red text
        // paren bold; eid bold dark-green (the EID being ligged)
        case send(lead: String, paren: String, midTrail: String, eid: String, endTrail: String)
        case eidPrefix(prefix: String, rest: String)            // prefix green
        // "Received map-reply from <ip> with rtt <rtt> secs:" — ip red, rtt bold.
        case mapReply(from: String, rtt: String)
        // addrIsRLE: this RLOC-record is a replication list — render the address
        // label ("RLEs") in black instead of a red rloc address.
        case rloc(addr: String, beforeName: String, name: String?, afterName: String,
                  addrIsRLE: Bool = false)
        // one replication-list member per line: "        rle: <ip>(<name>)"
        case rle(member: RLEMember)
    }
}

extension LigLine {
    // Plain-text form of a line, for the Share button (mirrors lineView's wording).
    var asPlainText: String {
        switch content {
        case .plain(let s), .error(let s):
            return s
        case .send(let lead, let paren, let mid, let eid, let end):
            return lead + paren + mid + eid + end
        case .eidPrefix(let prefix, let rest):
            return "EID-prefix: " + prefix + rest
        case .mapReply(let from, let rtt):
            return "Received map-reply from \(from) with rtt \(rtt) secs:"
        case .rloc(let addr, let before, let name, let after, _):
            return "  RLOC: " + addr + before + (name ?? "") + after
        case .rle(let m):
            return "    rle: " + m.rloc + (m.name.map { " \($0)" } ?? "")
        }
    }
}

final class LigService: ObservableObject {
    @Published var output: [LigLine] = []
    @Published var inFlight = false

    private weak var engine: LispEngine?
    private var pending: [UInt64: Date] = [:]
    private var remaining = 0
    private var target = LispAddress()
    private var pubsub = false
    private var debug = false

    // Dedicated ephemeral socket + the translation the map-resolver sees for it.
    private let socketQueue = DispatchQueue(label: "lisp.lig")
    private var ligSocket: UDPSocket?
    private var mrAddr = LispAddress()
    private var ephemRLOC = LispAddress()    // our translated RLOC (Info-Reply)
    private var ephemPort: UInt16 = 0         // our translated source port
    private var waitingForInfo = false

    init(engine: LispEngine) { self.engine = engine }

    func lookup(eidString: String, count: Int, pubsub: Bool, noInfo: Bool, debug: Bool) {
        guard let engine = engine, engine.running, engine.config.eid != nil else {
            set([LigLine(content: .error("Enable LISP on the xTR tab first."))])
            return
        }
        // Accept an optional "[<iid>]" prefix on the EID (e.g. "[1]240.10.0.1"); the bracketed
        // instance-id overrides the configured default so you can lig into any IID.
        let raw = eidString.trimmingCharacters(in: .whitespaces)
        var iid = UInt32(engine.config.instanceID)
        var addrStr = raw
        if raw.hasPrefix("["), let close = raw.firstIndex(of: "]"),
           let parsed = UInt32(raw[raw.index(after: raw.startIndex)..<close]) {
            iid = parsed
            addrStr = String(raw[raw.index(after: close)...]).trimmingCharacters(in: .whitespaces)
        }
        guard var eid = LispAddress(string: addrStr, iid: iid) else {
            set([LigLine(content: .error("Invalid EID: \(eidString)"))])
            return
        }
        if !eid.isName { eid.maskLen = 32 }     // a distinguished name keeps its len*8 mask
        target = eid
        self.pubsub = pubsub
        self.debug = debug
        remaining = max(1, min(count, 5))
        output = []
        inFlight = true

        guard let (mr, _) = engine.mapServerFor(eid: target) else {
            set([LigLine(content: .error("No map-resolver for \(target.prefixString) " +
                                         "— configure LISP-Decent."))])
            return
        }
        mrAddr = mr

        // (Re)open the dedicated lig socket on an OS-assigned ephemeral port.
        ligSocket?.shutdown()
        guard let sock = UDPSocket(localPort: 0, queue: socketQueue) else {
            set([LigLine(content: .error("Could not open lig socket."))])
            return
        }
        ligSocket = sock
        sock.startReceiving { [weak self] data, from, port, _ in
            DispatchQueue.main.async { self?.ligReceive(data, from: from, port: port) }
        }

        // Fallback translation if we skip / time out the Info-Request.
        ephemRLOC = engine.translatedRLOC ?? (engine.rloc?.address ?? LispAddress())
        ephemPort = engine.behindNAT ? engine.translatedPort : LISP.ctrlPort

        if !noInfo {
            waitingForInfo = true
            append(.init(content: .plain("Possible NAT in path, sending Info-Request ...")))
            sendLigInfo(mr, attempt: 1)
        } else {
            sendOne()
        }
    }

    // Send the Info-Request out the dedicated socket and retry a few times — the
    // map-resolver may be far (e.g. 4.sm-ms in Singapore) and we MUST learn this
    // socket's translation before the ECM, or the reply can't route back.
    private func sendLigInfo(_ mr: LispAddress, attempt: Int) {
        guard let engine = engine, let sock = ligSocket, waitingForInfo else { return }
        var info = LispInfo()
        info.nonce = lispGetControlNonce()
        info.hostname = engine.xtrName
        if attempt == 1, debug {
            append(.init(content: .plain("")))
            append(.init(content: .plain("Info-Request -> nonce: 0x" +
                "\(String(info.nonce, radix: 16)), hostname: \(engine.xtrName)")))
            append(.init(content: .plain("Send Info-Request to MS \(mr.addressString), " +
                "port \(LISP.ctrlPort) (for control)")))
        }
        LispLog.shared.lprint(.itr, "lig: Send Info-Request to \(mr.addressString):" +
            "\(LISP.ctrlPort) (attempt \(attempt)), nonce 0x\(String(info.nonce, radix: 16))")
        _ = sock.send(info.encodeRequest(), to: mr, port: LISP.ctrlPort)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { [weak self] in
            guard let self = self, self.waitingForInfo else { return }
            if attempt < 4 {
                self.sendLigInfo(mr, attempt: attempt + 1)
            } else {
                self.waitingForInfo = false
                LispLog.shared.lprint(.itr, "lig: No Info-Reply after \(attempt) attempts " +
                    "from \(mr.addressString) — falling back to xTR translation")
                self.append(.init(content: .plain("(no Info-Reply — using xTR translation)")))
                self.append(.init(content: .plain("")))
                self.sendOne()
            }
        }
    }

    // All replies land on the dedicated socket: first the Info-Reply (which gives
    // us our translation), then the proxy Map-Reply.
    private func ligReceive(_ data: Data, from: LispAddress, port: UInt16) {
        guard let first = data.first else { return }
        LispLog.shared.lprint(.itr, "lig: Received \(data.count) bytes from " +
            "\(from.addressString):\(port), type \(first >> 4)")
        switch first >> 4 {
        case LISP.typeNatInfo:
            guard waitingForInfo, let info = LispInfo.decode(data), info.isReply else { return }
            waitingForInfo = false
            if !info.globalETRRLOC.isNull { ephemRLOC = info.globalETRRLOC }
            if info.etrPort != 0 { ephemPort = info.etrPort }
            LispLog.shared.lprint(.itr, "lig: Info-Reply from \(from.addressString) — " +
                "global \(ephemRLOC.addressString), etr-port \(ephemPort)")
            if debug {
                let rtrs = info.rtrList.isEmpty ? "empty"
                    : info.rtrList.map { $0.addressString }.joined(separator: ", ")
                append(.init(content: .plain("Info-Reply -> nonce: 0x" +
                    "\(String(info.nonce, radix: 16)), ms-port: \(info.msPort), etr-port: " +
                    "\(info.etrPort), global-rloc: \(info.globalETRRLOC.addressString), " +
                    "ms-rloc: no-address, private-rloc: '\(engine?.xtrName ?? "")', " +
                    "RTR-list: \(rtrs)")))
                append(.init(content: .plain("")))
            }
            append(.init(content: .plain("Info-Reply received, public address " +
                "\(ephemRLOC.addressString), translated port \(ephemPort)")))
            append(.init(content: .plain("")))
            sendOne()
        case LISP.typeMapReply:
            guard let reply = LispMapReply.decode(data) else {
                LispLog.shared.lprint(.itr, "lig: undecodable map-reply (\(data.count) " +
                                      "bytes): \(lispFormatPacket(data))")
                pending.removeAll()
                let hint = target.isMulticast
                    ? " — the map-server likely has no (S,G) registration for this group"
                    : ""
                append(.init(content: .error("*** Received a map-reply we can't decode " +
                    "(\(data.count) bytes)\(hint) ***")))
                next()
                return
            }
            _ = handleReply(reply, from: from)
        default:
            break
        }
    }

    private func sendOne() {
        guard let engine = engine, let sock = ligSocket else { finish(); return }
        guard let (mr, msConf) = engine.mapServerFor(eid: target) else { finish(); return }

        var req = LispMapRequest()
        req.nonce = lispGetControlNonce()
        req.sourceEID = LispAddress()           // lisp-lig.py sends no source-EID
        req.itrRLOCs = [ephemRLOC]
        if target.isMulticast {
            // Group lookup: (S=0/0, G=target). The map-resolver was already hashed
            // on the group (target), matching how receivers register.
            var src = LispAddress(string: "0.0.0.0", iid: target.instanceID)!
            src.maskLen = 0
            req.targetEID = src
            req.targetGroup = target
        } else {
            req.targetEID = target
        }
        // N flag (decent_nat_xtr) → map-server returns the FULL registered RLOC-set.
        req.decentNATXtr = true
        req.subscribe = pubsub
        req.xtrID = pubsub ? engine.xtrID : nil

        let inner = req.encode()
        // ECM inner IP src = our translated RLOC, inner UDP src = our translated
        // ephemeral port — so the proxy Map-Reply routes back to THIS socket. A distinguished
        // name can't go in the inner IPv4 dest field, so use the map-resolver's address there
        // (we send straight to the MS anyway — it reads the target from the map-request record).
        let ecmDest = target.isName ? mr : target
        let ecm = LispECM.wrap(control: inner, innerSource: ephemRLOC, innerDest: ecmDest,
                               sourcePort: ephemPort, destPort: LISP.ctrlPort, toMS: false)
        pending[req.nonce] = Date()

        let sub = pubsub ? "subscribe " : ""
        let mrName = msConf.dnsNameOrAddress.isEmpty ? mr.addressString : msConf.dnsNameOrAddress
        // A group lookup is an (S,G): source 0.0.0.0/0, group G/<ml>.
        let sgDisplay = "[\(target.instanceID)](0.0.0.0/0, \(target.addressString)/\(target.maskLen))"
        let eidNoMask = target.isMulticast ? sgDisplay
            : "[\(target.instanceID)]\(target.addressString)"
        let decentPrefix = engine.config.decentConfigured
            ? LispDecent.eidString(for: target, prefixes: engine.config.decentPrefixes)
            : target.prefixString
        append(.init(content: .send(
            lead: "Send lig \(sub)map-request to \(mr.addressString) ",
            paren: "(\(mrName) for \(decentPrefix))",
            midTrail: " for EID ",
            eid: eidNoMask,
            endTrail: " ...")))
        if debug {
            append(.init(content: .plain("")))
            let flags = "adrspim" + (pubsub ? "X" : "x") + "Nld"
            let irc = max(req.itrRLOCs.count - 1, 0)
            let srcStr = req.sourceEID.isNull ? "[\(target.instanceID)]no-address"
                                              : req.sourceEID.prefixString
            append(.init(content: .plain(
                "Map-Request -> flags: \(flags), itr-rloc-count: \(irc) (+1), " +
                "record-count: 1, nonce: 0x\(String(req.nonce, radix: 16)), " +
                "source-eid: afi \(req.sourceEID.afi), \(srcStr), target-eid: afi " +
                "\(target.afi), \(target.isMulticast ? sgDisplay : target.prefixString), " +
                "ITR-RLOCs:")))
            for itr in req.itrRLOCs {
                append(.init(content: .plain("  itr-rloc: afi \(itr.afi) \(itr.addressString)")))
            }
            append(.init(content: .plain(
                "ECM -> flags: sdem, inner IP: [\(target.instanceID)]\(ephemRLOC.addressString) -> " +
                "[\(target.instanceID)]\(target.addressString), inner UDP: " +
                "\(ephemPort) -> \(LISP.ctrlPort)")))
            append(.init(content: .plain(
                "Send Encapsulated-Control-Message to \(mr.addressString)")))
            append(.init(content: .plain(
                "Send ECM \(ecm.count) bytes: \(lispFormatPacket(ecm))")))
            append(.init(content: .plain("")))
        }
        _ = sock.send(ecm, to: mr, port: LISP.ctrlPort)

        let nonce = req.nonce
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
            guard let self = self, self.pending.removeValue(forKey: nonce) != nil else { return }
            self.append(.init(content: .error("*** No map-reply received (timeout) ***")))
            self.next()
        }
    }

    func handleReply(_ reply: LispMapReply, from: LispAddress) -> Bool {
        guard let sentAt = pending.removeValue(forKey: reply.nonce) else { return false }
        let rtt = Date().timeIntervalSince(sentAt).rounded(toPlaces: 3)
        append(.init(content: .mapReply(from: from.addressString, rtt: "\(rtt)")))
        if debug {
            append(.init(content: .plain("")))
            let flags = (reply.rlocProbe ? "R" : "r") + "es"
            append(.init(content: .plain("Map-Reply -> flags: \(flags), hop-count: " +
                "\(reply.hopCount), record-count: \(reply.records.count), " +
                "nonce: 0x\(String(reply.nonce, radix: 16))")))
        }
        for (eidRec, rlocs) in reply.records {
            let prefix = eidRec.group.isNull ? eidRec.eid.prefixString
                : "[\(eidRec.eid.instanceID)](\(eidRec.eid.addressString)/\(eidRec.eid.maskLen), " +
                  "\(eidRec.group.addressString)/\(eidRec.group.maskLen))"
            append(.init(content: .eidPrefix(prefix: prefix,
                         rest: ", ttl: \(ttlString(eidRec.recordTTL)), rloc-set:")))
            if debug {
                append(.init(content: .plain("  EID-record -> record-ttl: " +
                    "\(ttlString(eidRec.recordTTL)), rloc-count: \(rlocs.count), action: " +
                    "\(LISP.actionString(eidRec.action)), " +
                    "\(eidRec.authoritative ? "auth" : "non-auth"), map-version: 0, afi: " +
                    "\(eidRec.eid.afi), [iid]eid/ml: \(eidRec.eid.prefixString)")))
            }
            if rlocs.isEmpty {
                append(.init(content: .plain("  Empty, map-reply action: " +
                             "\(LISP.actionString(eidRec.action))")))
            }
            for rl in rlocs {
                let flags = (rl.localBit ? "L" : "l") + (rl.probeBit ? "P" : "p")
                          + (rl.reachBit ? "R" : "r")
                let rtr = rl.priority == 254 && rl.mpriority == 255
                let isRLE = !rl.rle.isEmpty
                // A replication-list record shows "RLEs" (black) in place of an
                // address; its member names ride on the "rle:" lines below. A plain
                // RLOC-record with no address still shows the usual red "no-address".
                let addr = isRLE ? "RLEs"
                    : (rl.rloc.afi == 0 ? "no-address" : rl.rloc.addressString)
                let name = isRLE ? nil : rl.rlocName
                var before = ", up/uw/mp/mw: \(rl.priority)/\(rl.weight)/" +
                             "\(rl.mpriority)/\(rl.mweight), flags: \(flags)"
                if name != nil { before += ", rloc-name: " }
                append(.init(content: .rloc(addr: addr, beforeName: before,
                             name: name, afterName: rtr ? ", RTR" : "", addrIsRLE: isRLE)))
                if isRLE {
                    for m in rl.rle {
                        append(.init(content: .rle(member: RLEMember(
                            rloc: m.rloc.addressString, name: m.rlocName))))
                    }
                }
                if debug {
                    let name = rl.rlocName.map { ", rloc-name: \($0)" } ?? ""
                    append(.init(content: .plain("    RLOC-record -> flags: \(flags), " +
                        "\(rl.priority)/\(rl.weight)/\(rl.mpriority)/\(rl.mweight), afi: " +
                        "\(rl.rloc.afi), rloc: \(rl.rloc.addressString)\(name)")))
                }
                if let json = rl.jsonString {
                    append(.init(content: .plain("        json: \(json)")))
                }
            }
            append(.init(content: .plain("")))     // blank line per record (lisp-lig.py)
        }
        next()
        return true
    }

    // print_ttl(): "<n> hours" when a whole number of hours, else "<n> mins".
    private func ttlString(_ minutes: UInt32) -> String {
        if minutes == 0 { return "0 secs" }
        return minutes % 60 == 0 ? "\(minutes / 60) hours" : "\(minutes) mins"
    }

    private func next() {
        remaining -= 1
        if remaining > 0 {
            append(.init(content: .plain("")))   // blank line between responses
            sendOne()
        } else {
            finish()
        }
    }

    private func finish() {
        ligSocket?.shutdown(); ligSocket = nil
        DispatchQueue.main.async { self.inFlight = false }
    }
    private func append(_ l: LigLine) { DispatchQueue.main.async { self.output.append(l) } }
    private func set(_ ls: [LigLine]) {
        DispatchQueue.main.async { self.output = ls; self.inFlight = false }
    }
}
