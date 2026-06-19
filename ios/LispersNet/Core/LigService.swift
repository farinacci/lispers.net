//
// LigService.swift
//
// LISP Internet Groper (lisp-lig.py) — a mapping-system lookup. Sends an
// ECM-encapsulated Map-Request to the LISP-Decent map-resolver (same hash the
// rest of the app uses) for a destination EID and renders the returned
// Map-Reply in lisp-lig.py's output format.
//

import Foundation
import Combine

struct LigLine: Identifiable {
    let id = UUID()
    let content: Content
    enum Content {
        case plain(String)                                  // black text
        case error(String)                                  // red text
        // paren bold; eid bold dark-green (the EID being ligged)
        case send(lead: String, paren: String, midTrail: String, eid: String, endTrail: String)
        case eidPrefix(prefix: String, rest: String)            // prefix green
        case rloc(addr: String, beforeName: String, name: String?, afterName: String)
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

    init(engine: LispEngine) { self.engine = engine }

    func lookup(eidString: String, count: Int, pubsub: Bool, noInfo: Bool, debug: Bool) {
        guard let engine = engine, engine.running, engine.config.eid != nil else {
            set([LigLine(content: .error("Enable LISP on the xTR tab first."))])
            return
        }
        guard var eid = LispAddress(string: eidString.trimmingCharacters(in: .whitespaces),
                                    iid: UInt32(engine.config.instanceID)) else {
            set([LigLine(content: .error("Invalid EID: \(eidString)"))])
            return
        }
        eid.maskLen = 32
        target = eid
        self.pubsub = pubsub
        self.debug = debug
        remaining = max(1, min(count, 5))
        output = []
        inFlight = true

        if !noInfo {
            append(.init(content: .plain("Possible NAT in path, sending Info-Request ...")))
            engine.sendInfoRequests()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { [weak self] in
                guard let self = self, let engine = self.engine else { return }
                if engine.behindNAT, let t = engine.translatedRLOC {
                    self.append(.init(content: .plain("Info-Reply received, public address " +
                                "\(t.addressString), translated port \(engine.translatedPort)")))
                }
                self.append(.init(content: .plain("")))
                self.sendOne()
            }
        } else {
            sendOne()
        }
    }

    private func sendOne() {
        guard let engine = engine, let source = engine.config.eid,
              let myRLOC = engine.rloc else { finish(); return }
        guard let (mr, msConf) = engine.mapServerFor(eid: target) else {
            append(.init(content: .error("No map-resolver for \(target.prefixString) " +
                                         "— configure LISP-Decent.")))
            finish(); return
        }

        var req = LispMapRequest()
        req.nonce = lispGetControlNonce()
        req.sourceEID = source
        req.itrRLOCs = [engine.behindNAT ? (engine.translatedRLOC ?? myRLOC.address)
                                         : myRLOC.address]
        req.targetEID = target
        // Set the N flag like lisp-lig.py (map_request.decent_nat_xtr = True): the
        // map-server then skips lisp_get_partial_rloc_set and returns the FULL
        // registered RLOC-set instead of just the RTRs.
        req.decentNATXtr = true
        req.subscribe = pubsub
        req.xtrID = pubsub ? engine.xtrID : nil

        let inner = req.encode()
        let ecm = LispECM.wrap(control: inner, innerSource: source, innerDest: target,
                               sourcePort: LISP.ctrlPort, destPort: LISP.ctrlPort, toMS: true)
        pending[req.nonce] = Date()

        let sub = pubsub ? "subscribe " : ""
        let mrName = msConf.dnsNameOrAddress.isEmpty ? mr.addressString : msConf.dnsNameOrAddress
        let eidNoMask = "[\(target.instanceID)]\(target.addressString)"
        // lisp-lig.py prints the decent eid-string it matched (EID masked to the
        // configured lookup-length), not the /32 — so a lookup-prefix change is
        // visible here (get_decent_info / lisp_get_decent_eid_string).
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
            // Mirror lisp-lig.py's debug (lisp_debug_logging => print_map_request()
            // breakdown + packet hex). Flags order matches lisp.py: a d r s p i m
            // x n l d; lig sets the N (decent_nat) flag and X when subscribing.
            let flags = "adrspim" + (pubsub ? "X" : "x") + "Nld"
            let irc = max(req.itrRLOCs.count - 1, 0)
            let srcStr = source.isNull ? "[\(target.instanceID)]no-address"
                                       : source.prefixString
            append(.init(content: .plain(
                "Map-Request -> flags: \(flags), itr-rloc-count: \(irc) (+1), " +
                "record-count: 1, nonce: 0x\(String(req.nonce, radix: 16)), " +
                "source-eid: afi \(source.afi), \(srcStr), target-eid: afi " +
                "\(target.afi), \(target.prefixString), ITR-RLOCs:")))
            for itr in req.itrRLOCs {
                append(.init(content: .plain("  itr-rloc: afi \(itr.afi) \(itr.addressString)")))
            }
            append(.init(content: .plain(
                "Send ECM \(ecm.count) bytes: \(lispFormatPacket(ecm))")))
        }
        engine.ctrlSocket?.send(ecm, to: mr, port: LISP.ctrlPort)

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
        append(.init(content: .plain("Received map-reply from \(from.addressString) " +
                     "with rtt \(rtt) secs:")))
        for (eidRec, rlocs) in reply.records {
            append(.init(content: .eidPrefix(prefix: eidRec.eid.prefixString,
                         rest: ", ttl: \(ttlString(eidRec.recordTTL)), rloc-set:")))
            if rlocs.isEmpty {
                append(.init(content: .plain("  Empty, map-reply action: " +
                             "\(LISP.actionString(eidRec.action))")))
            }
            for rl in rlocs {
                let flags = (rl.localBit ? "L" : "l") + (rl.probeBit ? "P" : "p")
                          + (rl.reachBit ? "R" : "r")
                let rtr = rl.priority == 254 && rl.mpriority == 255
                var before = ", up/uw/mp/mw: \(rl.priority)/\(rl.weight)/" +
                             "\(rl.mpriority)/\(rl.mweight), flags: \(flags)"
                if rl.rlocName != nil { before += ", rloc-name: " }
                append(.init(content: .rloc(addr: rl.rloc.addressString, beforeName: before,
                             name: rl.rlocName, afterName: rtr ? ", RTR" : "")))
                // Registered JSON (e.g. telemetry) on the RLOC — lisp-lig.py:235.
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

    private func finish() { DispatchQueue.main.async { self.inFlight = false } }
    private func append(_ l: LigLine) { DispatchQueue.main.async { self.output.append(l) } }
    private func set(_ ls: [LigLine]) {
        DispatchQueue.main.async { self.output = ls; self.inFlight = false }
    }
}
