//
// LispControlMessages.swift
//
// Wire-format encoders/decoders for the control messages the xTR needs:
// Map-Request (ECM lookup + non-ECM RLOC-probe), Map-Reply, Map-Register,
// Info-Request/Info-Reply, and the ECM wrapper. Byte layouts mirror the
// classes in lisp.py — see PLAN.md for the line references.
//

import Foundation
import CryptoKit

func lispGetControlNonce() -> UInt64 { UInt64.random(in: 0...UInt64.max) }

// MARK: - EID record (lisp_eid_record, lisp.py:5109)

struct LispEIDRecord {
    var recordTTL: UInt32 = 0           // minutes
    var rlocCount: UInt8 = 0
    var action: Int = LISP.noAction
    var authoritative = false
    var eid = LispAddress()

    func encode() -> Data {
        var w = ByteWriter()
        w.u32(recordTTL)
        w.u8(rlocCount)
        w.u8(UInt8(eid.maskLen))
        var af: UInt16 = UInt16(action) << 13
        if authoritative { af |= 0x1000 }
        w.u16(af)
        w.u16(0)                        // sig-count(4) | map-version(12)
        if eid.instanceID != 0 {
            // LCAF Instance-ID (lcaf_encode_iid, lisp.py:12521)
            w.u16(LISP.afiLCAF)
            w.u8(0); w.u8(0)
            w.u8(LISP.lcafInstanceID)
            w.u8(0)
            w.u16(UInt16(4 + 2 + eid.addressLength))
            w.u32(eid.instanceID)
            w.u16(eid.afi)
            w.bytes(eid.packAddress())
        } else {
            w.u16(eid.afi)
            w.bytes(eid.packAddress())
        }
        return w.data
    }

    static func decode(_ r: inout ByteReader) -> LispEIDRecord? {
        var rec = LispEIDRecord()
        guard let ttl = r.u32(), let cnt = r.u8(), let ml = r.u8(),
              let af = r.u16(), let _ = r.u16(), let afi0 = r.u16() else { return nil }
        var afi = afi0
        rec.recordTTL = ttl
        rec.rlocCount = cnt
        rec.action = Int((af >> 13) & 0x7)
        rec.authoritative = af & 0x1000 != 0
        var iid: UInt32 = 0
        if afi == LISP.afiLCAF {
            guard let _ = r.u8(), let _ = r.u8(), let type = r.u8(),
                  let _ = r.u8(), let _ = r.u16() else { return nil }
            guard type == LISP.lcafInstanceID else { return nil }
            guard let i = r.u32(), let innerAFI = r.u16() else { return nil }
            iid = i; afi = innerAFI
        }
        guard var eid = LispAddress.unpack(afi: afi, reader: &r) else { return nil }
        eid.maskLen = Int(ml)
        eid.instanceID = iid
        rec.eid = eid
        return rec
    }
}

// MARK: - RLOC record (lisp_rloc_record, lisp.py:5597)

struct LispRLOCRecord {
    var priority: UInt8 = 1
    var weight: UInt8 = 100
    var mpriority: UInt8 = 255
    var mweight: UInt8 = 0
    var localBit = false
    var probeBit = false
    var reachBit = false
    var rloc = LispAddress()
    var jsonString: String?             // telemetry rides here (LCAF JSON)
    var rlocName: String?               // e.g. "RTR" or "<xtr>@tp-<port>"

    func encode() -> Data {
        var w = ByteWriter()
        w.u8(priority); w.u8(weight); w.u8(mpriority); w.u8(mweight)
        var flags: UInt16 = 0
        if localBit { flags |= 0x0004 }
        if probeBit { flags |= 0x0002 }
        if reachBit { flags |= 0x0001 }
        w.u16(flags)
        if let json = jsonString {
            w.bytes(Self.encodeJSONLCAF(json: json, rloc: rloc))
        } else if let name = rlocName {
            w.bytes(Self.encodeNameLCAF(name: name, rloc: rloc))
        } else {
            w.u16(rloc.afi)
            w.bytes(rloc.packAddress())
        }
        return w.data
    }

    // RLOC-name carried as an LCAF AFI-List (type 1): the RLOC address followed
    // by an AFI-17 distinguished name (lisp_rloc_record.encode_lcaf, lisp.py).
    static func encodeNameLCAF(name: String, rloc: LispAddress) -> Data {
        var w = ByteWriter()
        let nameBytes = Data(name.utf8)
        let npktLen = 2 + nameBytes.count + 1               // AFI-17 + name + null
        let apktLen = 2 + rloc.addressLength + npktLen      // inner AFI + addr + name
        w.u16(LISP.afiLCAF)
        w.u8(0); w.u8(0)
        w.u8(LISP.lcafAFIList)
        w.u8(0)
        w.u16(UInt16(apktLen))
        w.u16(rloc.afi)
        w.bytes(rloc.packAddress())
        w.u16(LISP.afiName)
        w.bytes(nameBytes); w.u8(0)
        return w.data
    }

    // encode_json (lisp.py:5718): HBBBBHH then json then telemetry RLOC.
    static func encodeJSONLCAF(json: String, rloc: LispAddress) -> Data {
        var w = ByteWriter()
        let jsonBytes = Data(json.utf8)
        w.u16(LISP.afiLCAF)
        w.u8(0); w.u8(0)
        w.u8(LISP.lcafJSON)
        w.u8(0)                                     // kid (no encryption)
        w.u16(UInt16(jsonBytes.count + rloc.addressLength + 2))
        w.u16(UInt16(jsonBytes.count))
        w.bytes(jsonBytes)
        if Telemetry.isTelemetry(json) {
            w.u16(rloc.afi)
            w.bytes(rloc.packAddress())
        } else {
            w.u16(0)
        }
        return w.data
    }

    static func decode(_ r: inout ByteReader) -> LispRLOCRecord? {
        var rec = LispRLOCRecord()
        guard let p = r.u8(), let wt = r.u8(), let mp = r.u8(), let mw = r.u8(),
              let flags = r.u16(), let afi = r.u16() else { return nil }
        rec.priority = p; rec.weight = wt; rec.mpriority = mp; rec.mweight = mw
        rec.localBit = flags & 0x0004 != 0
        rec.probeBit = flags & 0x0002 != 0
        rec.reachBit = flags & 0x0001 != 0
        if afi == LISP.afiLCAF {
            guard let _ = r.u8(), let _ = r.u8(), let type = r.u8(),
                  let _ = r.u8(), let lcafLen = r.u16() else { return nil }
            if type == LISP.lcafJSON {
                guard let jsonLen = r.u16(),
                      let jsonBytes = r.bytes(Int(jsonLen)) else { return nil }
                rec.jsonString = String(data: jsonBytes, encoding: .utf8)
                if let afi2 = r.u16(), afi2 != 0,
                   let a = LispAddress.unpack(afi: afi2, reader: &r) {
                    rec.rloc = a
                }
            } else if type == LISP.lcafAFIList {
                // AFI-List: an address plus optional AFI-17 distinguished name
                // (the "<xtr>@tp-<port>" / "RTR" rloc-name).
                let end = r.offset + Int(lcafLen)
                while r.offset < end {
                    guard let innerAFI = r.u16() else { break }
                    if innerAFI == LISP.afiName {
                        rec.rlocName = r.readName()
                    } else if innerAFI != 0,
                              let a = LispAddress.unpack(afi: innerAFI, reader: &r) {
                        rec.rloc = a
                    } else if innerAFI == 0 {
                        continue
                    } else {
                        break
                    }
                }
                if r.offset < end { r.skip(end - r.offset) }
            } else {
                r.skip(Int(lcafLen))    // unhandled LCAF type
            }
        } else if afi == LISP.afiName {
            // Distinguished name: null-terminated string, then real AFI+addr
            // may not follow in this position for our use cases; consume name.
            var name = ""
            while let c = r.u8(), c != 0 { name.append(Character(UnicodeScalar(c))) }
            _ = name
        } else {
            guard let a = LispAddress.unpack(afi: afi, reader: &r) else { return nil }
            rec.rloc = a
        }
        return rec
    }
}

// MARK: - Map-Register (lisp_map_register, lisp.py:3943)

struct LispMapRegister {
    var nonce: UInt64 = 0
    var keyID: UInt8 = 0
    var algID: UInt8 = LISP.sha2AlgID
    var proxyReply = true
    var wantMapNotify = true
    var mergeRegister = false
    var useTTLForTimeout = true
    var xtrIDPresent = true
    var xtrID: (UInt64, UInt64) = (0, 0)        // 128-bit
    var siteID: UInt64 = 0
    var recordCount: UInt8 = 0

    // Returns the complete packet: header + records + xTR-ID trailer with
    // HMAC patched in (lisp_compute_auth over the whole packet, auth zeroed).
    func encode(eidRecords: Data, password: String) -> Data {
        var w = ByteWriter()
        var first: UInt32 = UInt32(LISP.typeMapRegister) << 28
        if proxyReply { first |= 0x0800_0000 }      // P
        if xtrIDPresent { first |= 0x0200_0000 }    // I
        if useTTLForTimeout { first |= 0x800 }      // T
        if mergeRegister { first |= 0x400 }         // R
        if wantMapNotify { first |= 0x100 }         // N
        first |= UInt32(recordCount)
        w.u32(first)
        w.u64Native(nonce)
        w.u8(keyID)
        let alg = password.isEmpty ? LISP.noneAlgID : algID
        w.u8(alg)
        let authLen = alg == LISP.sha1AlgID ? 20 : (alg == LISP.sha2AlgID ? 32 : 0)
        w.u16(UInt16(authLen))
        let authOffset = w.data.count
        w.zeros(authLen)
        w.bytes(eidRecords)
        if xtrIDPresent {
            // Trailer bytes end up on the wire in big-endian order (the
            // byte_swap_64 + native pack in lisp.py cancel out).
            var t = ByteWriter()
            t.u32(UInt32(xtrID.0 >> 32)); t.u32(UInt32(truncatingIfNeeded: xtrID.0))
            t.u32(UInt32(xtrID.1 >> 32)); t.u32(UInt32(truncatingIfNeeded: xtrID.1))
            t.u32(UInt32(siteID >> 32)); t.u32(UInt32(truncatingIfNeeded: siteID))
            w.bytes(t.data)
        }
        var packet = w.data
        if alg != LISP.noneAlgID {
            let key = SymmetricKey(data: Data(password.utf8))
            let digest: Data
            if alg == LISP.sha1AlgID {
                digest = Data(HMAC<Insecure.SHA1>.authenticationCode(for: packet, using: key))
            } else {
                digest = Data(HMAC<SHA256>.authenticationCode(for: packet, using: key))
            }
            packet.replaceSubrange(authOffset..<(authOffset + authLen), with: digest)
        }
        return packet
    }
}

// MARK: - Map-Request (lisp_map_request, lisp.py:4373)

struct LispMapRequest {
    var nonce: UInt64 = 0
    var rlocProbe = false
    var smrInvoked = false
    var sourceEID = LispAddress()
    var itrRLOCs: [LispAddress] = []
    var telemetryJSON: String?          // extra ITR-RLOC carrying telemetry
    var targetEID = LispAddress()
    var subscribe = false               // pubsub: subscribe bit + xTR-ID
    var xtrID: (UInt64, UInt64)?

    func encode() -> Data {
        var w = ByteWriter()
        var first: UInt32 = UInt32(LISP.typeMapRequest) << 28
        if rlocProbe { first |= 0x0200_0000 }       // R/probe
        if smrInvoked { first |= 0x0040_0000 }      // I
        if subscribe { first |= 0x0010_0000 }       // X (xTR-ID present)
        let itrCount = itrRLOCs.count + (telemetryJSON != nil ? 1 : 0)
        first |= UInt32(max(itrCount - 1, 0)) << 8  // count is N-1 on the wire
        first |= 1                                  // one EID record
        w.u32(first)
        w.u64Native(nonce)
        // Source EID
        if sourceEID.isNull {
            w.u16(0)
        } else {
            w.u16(sourceEID.afi)
            w.bytes(sourceEID.packAddress())
        }
        // ITR-RLOCs
        for rloc in itrRLOCs {
            w.u16(rloc.afi)
            w.bytes(rloc.packAddress())
        }
        if let json = telemetryJSON, let first = itrRLOCs.first {
            w.bytes(LispRLOCRecord.encodeJSONLCAF(json: json, rloc: first))
        }
        // Subscribe byte + mask-len, then EID prefix.
        w.u8(subscribe ? 0x80 : 0)
        w.u8(UInt8(targetEID.maskLen))
        w.u16(targetEID.afi)
        w.bytes(targetEID.packAddress())
        // pubsub xTR-ID trailer (lisp.py encode_xtr_id, big-endian on the wire).
        if subscribe, let xid = xtrID {
            w.u32(UInt32(xid.0 >> 32)); w.u32(UInt32(truncatingIfNeeded: xid.0))
            w.u32(UInt32(xid.1 >> 32)); w.u32(UInt32(truncatingIfNeeded: xid.1))
        }
        return w.data
    }

    static func decode(_ data: Data) -> LispMapRequest? {
        var r = ByteReader(data)
        guard let first = r.u32(), let nonce = r.u64Native() else { return nil }
        guard first >> 28 == LISP.typeMapRequest else { return nil }
        var req = LispMapRequest()
        req.nonce = nonce
        req.rlocProbe = first & 0x0200_0000 != 0
        req.smrInvoked = first & 0x0040_0000 != 0
        let itrCount = Int((first >> 8) & 0x1f) + 1
        guard let srcAFI = r.u16() else { return nil }
        if srcAFI != 0 {
            guard let s = LispAddress.unpack(afi: srcAFI, reader: &r) else { return nil }
            req.sourceEID = s
        }
        for _ in 0..<itrCount {
            guard let afi = r.u16() else { return nil }
            if afi == LISP.afiLCAF {
                guard let _ = r.u8(), let _ = r.u8(), let type = r.u8(),
                      let _ = r.u8(), let lcafLen = r.u16() else { return nil }
                if type == LISP.lcafJSON {
                    guard let jsonLen = r.u16(),
                          let jsonBytes = r.bytes(Int(jsonLen)) else { return nil }
                    req.telemetryJSON = String(data: jsonBytes, encoding: .utf8)
                    if let afi2 = r.u16(), afi2 != 0 {
                        _ = LispAddress.unpack(afi: afi2, reader: &r)
                    }
                } else {
                    r.skip(Int(lcafLen))
                }
            } else if let a = LispAddress.unpack(afi: afi, reader: &r) {
                req.itrRLOCs.append(a)
            } else {
                return nil
            }
        }
        guard let _ = r.u8(), let ml = r.u8(), let eidAFI = r.u16(),
              var eid = LispAddress.unpack(afi: eidAFI, reader: &r) else { return nil }
        eid.maskLen = Int(ml)
        req.targetEID = eid
        return req
    }
}

// MARK: - Map-Reply (lisp_map_reply, lisp.py:5015)

struct LispMapReply {
    var nonce: UInt64 = 0
    var rlocProbe = false
    var hopCount: UInt8 = 0
    var records: [(eid: LispEIDRecord, rlocs: [LispRLOCRecord])] = []

    func encode() -> Data {
        var w = ByteWriter()
        var first: UInt32 = UInt32(LISP.typeMapReply) << 28
        if rlocProbe { first |= 0x0800_0000 }
        first |= UInt32(hopCount) << 8
        first |= UInt32(records.count)
        w.u32(first)
        w.u64Native(nonce)
        for (var eidRec, rlocs) in records {
            eidRec.rlocCount = UInt8(rlocs.count)
            w.bytes(eidRec.encode())
            for rl in rlocs { w.bytes(rl.encode()) }
        }
        return w.data
    }

    static func decode(_ data: Data) -> LispMapReply? {
        var r = ByteReader(data)
        guard let first = r.u32(), let nonce = r.u64Native() else { return nil }
        guard first >> 28 == LISP.typeMapReply else { return nil }
        var reply = LispMapReply()
        reply.nonce = nonce
        reply.rlocProbe = first & 0x0800_0000 != 0
        reply.hopCount = UInt8((first >> 8) & 0xff)
        let recordCount = Int(first & 0xff)
        for _ in 0..<recordCount {
            guard let eidRec = LispEIDRecord.decode(&r) else { return nil }
            var rlocs: [LispRLOCRecord] = []
            for _ in 0..<eidRec.rlocCount {
                guard let rl = LispRLOCRecord.decode(&r) else { return nil }
                rlocs.append(rl)
            }
            reply.records.append((eidRec, rlocs))
        }
        return reply
    }
}

// MARK: - Info-Request / Info-Reply (lisp_info, lisp.py:6435)

struct LispInfo {
    var isReply = false
    var nonce: UInt64 = 0
    var hostname: String?
    // Reply fields (LCAF NAT type 7)
    var msPort: UInt16 = 0
    var etrPort: UInt16 = 0
    var globalETRRLOC = LispAddress()
    var privateETRRLOC = LispAddress()
    var rtrList: [LispAddress] = []

    func encodeRequest() -> Data {
        var w = ByteWriter()
        w.u32(UInt32(LISP.typeNatInfo) << 28)
        w.u64Native(nonce)
        w.zeros(12)                     // key-id/auth-len/ttl/masklen/afi all 0
        if let h = hostname {
            w.u16(LISP.afiName)
            w.bytes(Data(h.utf8)); w.u8(0)
        } else {
            w.u16(0)
        }
        return w.data
    }

    static func decode(_ data: Data) -> LispInfo? {
        var r = ByteReader(data)
        guard let first = r.u32(), let nonce = r.u64Native() else { return nil }
        guard first >> 28 == LISP.typeNatInfo else { return nil }
        var info = LispInfo()
        info.nonce = nonce
        info.isReply = first & 0x0800_0000 != 0
        guard let _ = r.u16(), let authLen = r.u16(), authLen == 0,
              let _ = r.u32(), let _ = r.u32() else { return nil }
        if !info.isReply {
            if let afi = r.u16(), afi == LISP.afiName {
                var name = ""
                while let c = r.u8(), c != 0 { name.append(Character(UnicodeScalar(c))) }
                info.hostname = name
            }
            return info
        }
        // Info-Reply LCAF NAT type 7: HHBBHHHH then addresses (lisp.py:6500)
        guard let afi = r.u16(), afi == LISP.afiLCAF,
              let _ = r.u16(),                              // reserved
              let lcafType = r.u8(), lcafType == LISP.lcafNAT,
              let _ = r.u8(),                               // reserved
              let _ = r.u16(),                              // lcaf length
              let msPort = r.u16(), let etrPort = r.u16(),
              let gAFI = r.u16() else { return nil }
        info.msPort = msPort
        info.etrPort = etrPort
        // Address slots come in fixed order: global ETR RLOC, global MS RLOC,
        // private ETR RLOC, then the RTR list (lisp_info.decode, lisp.py:6523).
        if gAFI != 0, let g = LispAddress.unpack(afi: gAFI, reader: &r) {
            info.globalETRRLOC = g
        }
        // Global MS RLOC (AFI 0 = absent).
        if let msAFI = r.u16(), msAFI != 0 {
            _ = LispAddress.unpack(afi: msAFI, reader: &r)
        }
        // Private ETR RLOC. The MS echoes our hostname here as a distinguished
        // name (AFI 17) — it MUST be consumed (null-terminated) or the RTR list
        // that follows is misparsed and lost.
        if let pAFI = r.u16(), pAFI != 0 {
            if pAFI == LISP.afiName {
                _ = r.readName()
            } else if let p = LispAddress.unpack(afi: pAFI, reader: &r) {
                info.privateETRRLOC = p
            }
        }
        // RTR list — zero or more AFI+address entries (AFI 0 entries skipped).
        while let rtrAFI = r.u16() {
            if rtrAFI == 0 { continue }
            guard let rtr = LispAddress.unpack(afi: rtrAFI, reader: &r) else { break }
            info.rtrList.append(rtr)
        }
        return info
    }
}

// MARK: - ECM (lisp_ecm, lisp.py:5303)

enum LispECM {
    // Wrap a control message in ECM: 4-byte ECM header + inner IPv4 + UDP.
    static func wrap(control: Data, innerSource: LispAddress,
                     innerDest: LispAddress, sourcePort: UInt16,
                     destPort: UInt16, toMS: Bool = true) -> Data {
        var w = ByteWriter()
        var first: UInt32 = UInt32(LISP.typeECM) << 28
        if toMS { first |= 0x0100_0000 }            // M-bit: to map-server
        w.u32(first)
        // Inner IPv4 header (20 bytes)
        let udpLen = 8 + control.count
        var ip = ByteWriter()
        ip.u8(0x45); ip.u8(0)
        ip.u16(UInt16(20 + udpLen))
        ip.u16(0xdfdf); ip.u16(0)
        ip.u8(128)                                  // LISP_DEFAULT_ECM_TTL
        ip.u8(17)                                   // UDP
        ip.u16(0)                                   // checksum below
        ip.bytes(innerSource.packAddress())
        ip.bytes(innerDest.packAddress())
        var ipHeader = ip.data
        let cksum = internetChecksum(ipHeader)
        ipHeader[10] = UInt8(cksum >> 8); ipHeader[11] = UInt8(cksum & 0xff)
        w.bytes(ipHeader)
        // Inner UDP header
        w.u16(sourcePort); w.u16(destPort)
        w.u16(UInt16(udpLen)); w.u16(0)
        w.bytes(control)
        return w.data
    }

    // Strip ECM + inner IP/UDP, returning the inner control message.
    static func unwrap(_ data: Data) -> Data? {
        var r = ByteReader(data)
        guard let first = r.u32(), first >> 28 == LISP.typeECM else { return nil }
        guard let vihl = r.u8() else { return nil }
        if vihl >> 4 == 4 {
            r.skip(19 - 4 + 4)                      // rest of IPv4 header
            r.skip(8)                               // UDP
        } else if vihl >> 4 == 6 {
            r.skip(39); r.skip(8)
        } else { return nil }
        guard r.remaining > 0 else { return nil }
        return r.bytes(r.remaining)
    }
}
