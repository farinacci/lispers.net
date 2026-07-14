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
    var group = LispAddress()           // non-null = multicast (S,G); eid = source

    // Multicast-Info LCAF body (lcaf_encode_sg, lisp.py:12643) — written after the
    // AFI-LCAF marker. Carries iid, source (=eid) and group with both mask lengths.
    static func encodeMcastInfoLCAF(source: LispAddress, group: LispAddress) -> Data {
        var w = ByteWriter()
        w.u8(0); w.u8(0)                            // rsvd, flags
        w.u8(LISP.lcafMcastInfo)                    // type 9
        w.u8(0)                                     // rsvd
        // len = lcaf_length(MCAST) = (addr_len+2)*2+8 = 20 for IPv4 (lisp.py).
        let len = (source.addressLength + 2) * 2 + 8
        w.u16(UInt16(len))
        w.u32(source.instanceID)
        w.u16(0); w.u16(0)                          // 4 reserved bytes after iid (the
                                                    // running map-server's mcast-info
                                                    // LCAF — NOT the 2-byte BBBBHIHBB)
        w.u8(UInt8(source.maskLen))                 // source mask-len
        w.u8(UInt8(group.maskLen))                  // group mask-len
        w.u16(source.afi); w.bytes(source.packAddress())
        w.u16(group.afi);  w.bytes(group.packAddress())
        return w.data
    }

    func encode() -> Data {
        var w = ByteWriter()
        w.u32(recordTTL)
        w.u8(rlocCount)
        w.u8(UInt8(eid.maskLen))                    // source mask for (S,G); prefix-len otherwise
        var af: UInt16 = UInt16(action) << 13
        if authoritative { af |= 0x1000 }
        w.u16(af)
        w.u16(0)                        // sig-count(4) | map-version(12)
        if !group.isNull {
            // Multicast (S,G): AFI-LCAF marker + Multicast-Info LCAF (type 9).
            w.u16(LISP.afiLCAF)
            w.bytes(Self.encodeMcastInfoLCAF(source: eid, group: group))
        } else if eid.instanceID != 0 {
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
            if type == LISP.lcafInstanceID {
                guard let i = r.u32(), let innerAFI = r.u16() else { return nil }
                iid = i; afi = innerAFI
            } else if type == LISP.lcafMcastInfo {
                // (S,G): iid, 4-byte rsvd, src-mask, grp-mask, src AFI+addr, grp AFI+addr.
                guard let i = r.u32(), let _ = r.u32(),
                      let sml = r.u8(), let gml = r.u8(), let sAfi = r.u16(),
                      var src = LispAddress.unpack(afi: sAfi, reader: &r),
                      let gAfi = r.u16(),
                      var grp = LispAddress.unpack(afi: gAfi, reader: &r) else { return nil }
                src.maskLen = Int(sml); src.instanceID = i
                grp.maskLen = Int(gml); grp.instanceID = i
                rec.eid = src; rec.group = grp
                return rec
            } else {
                return nil
            }
        }
        guard var eid = LispAddress.unpack(afi: afi, reader: &r) else { return nil }
        eid.maskLen = Int(ml)
        eid.instanceID = iid
        rec.eid = eid
        return rec
    }
}

// MARK: - RLOC record (lisp_rloc_record, lisp.py:5597)

// One replication-list entry: a receiver RLOC at a replication level
// (lisp_rle_node, lisp.py:13080). Local receiver level = 128.
struct RLENode {
    var level: UInt8 = 128
    var rloc = LispAddress()
    var rlocName: String?
}

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
    var rle: [RLENode] = []             // non-empty = locator is an RLE (type 13)

    // Replication-List-Entry LCAF (type 13, lisp.py:5777). The RLOC-record's
    // locator is the replication list: per node [rsvd:2][rsvd:1][level:1][AFI:2]
    // [rloc][optional AFI-17 name].
    static func encodeRLELCAF(_ rle: [RLENode]) -> Data {
        var body = ByteWriter()
        for n in rle {
            body.u16(0); body.u8(0)                 // rsvd
            body.u8(n.level)
            body.u16(n.rloc.afi)
            body.bytes(n.rloc.packAddress())
            if let name = n.rlocName {
                body.u16(LISP.afiName)
                body.bytes(Data(name.utf8)); body.u8(0)
            }
        }
        var w = ByteWriter()
        w.u16(LISP.afiLCAF)
        w.u8(0); w.u8(0)
        w.u8(LISP.lcafRLE)
        w.u8(0)
        w.u16(UInt16(body.data.count))
        w.bytes(body.data)
        return w.data
    }

    // A replication-list locator the way lisp_rloc_record.encode_lcaf builds it:
    // an AFI-List LCAF (type 1) wrapping the (usually null) main RLOC, an optional
    // rloc-name, then the RLE LCAF. apkt_len covers rloc-afi(2)+rloc+name+RLE.
    static func encodeRLEAFIList(rloc: LispAddress, name: String?, rle: [RLENode]) -> Data {
        var npkt = ByteWriter()
        if let name = name {
            npkt.u16(LISP.afiName)
            npkt.bytes(Data(name.utf8)); npkt.u8(0)
        }
        let rpkt = encodeRLELCAF(rle)
        let apktLen = 2 + rloc.addressLength + npkt.data.count + rpkt.count
        var w = ByteWriter()
        w.u16(LISP.afiLCAF)
        w.u8(0); w.u8(0)
        w.u8(LISP.lcafAFIList)                  // type 1
        w.u8(0)
        w.u16(UInt16(apktLen))
        w.u16(rloc.afi)                         // main rloc AFI (0 = no-address)
        w.bytes(rloc.packAddress())
        w.bytes(npkt.data)                      // rloc-name
        w.bytes(rpkt)                           // RLE LCAF
        return w.data
    }

    func encode() -> Data {
        var w = ByteWriter()
        w.u8(priority); w.u8(weight); w.u8(mpriority); w.u8(mweight)
        var flags: UInt16 = 0
        if localBit { flags |= 0x0004 }
        if probeBit { flags |= 0x0002 }
        if reachBit { flags |= 0x0001 }
        w.u16(flags)
        if !rle.isEmpty {
            w.bytes(Self.encodeRLEAFIList(rloc: rloc, name: rlocName, rle: rle))
        } else if let json = jsonString, let name = rlocName {
            // Both an rloc-name AND telemetry: one AFI-List LCAF carrying the
            // address, the name, then the JSON LCAF (lisp.py encode_lcaf order:
            // apkt + npkt + jpkt). A NAT'd RLOC-probe reply needs both — the name
            // so the RTR can resolve our per-RTR translated port from its own NAT
            // state, the JSON for latency telemetry. Emitting only one (the old
            // if/else dropped the name when json was set) made the RTR fall back
            // to our registered "@tp-<port>" name and reject the reply.
            w.bytes(Self.encodeNameJSONLCAF(name: name, json: json, rloc: rloc))
        } else if let json = jsonString {
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

    // RLOC-name + telemetry together, as one AFI-List LCAF (type 1). Mirrors
    // lisp_rloc_record.encode_lcaf: AFI-List header, then [rloc-afi + addr], then
    // the AFI-17 distinguished name, then the JSON LCAF (apkt + npkt + jpkt).
    static func encodeNameJSONLCAF(name: String, json: String, rloc: LispAddress) -> Data {
        let nameBytes = Data(name.utf8)
        let npktLen = 2 + nameBytes.count + 1               // AFI-17 + name + null
        let jpkt = encodeJSONLCAF(json: json, rloc: rloc)   // nested JSON LCAF
        let apktLen = 2 + rloc.addressLength + npktLen + jpkt.count
        var w = ByteWriter()
        w.u16(LISP.afiLCAF)
        w.u8(0); w.u8(0)
        w.u8(LISP.lcafAFIList)
        w.u8(0)
        w.u16(UInt16(apktLen))
        w.u16(rloc.afi)                                     // first sub-AFI: rloc
        w.bytes(rloc.packAddress())
        w.u16(LISP.afiName)                                 // name sub-AFI
        w.bytes(nameBytes); w.u8(0)
        w.bytes(jpkt)                                       // json sub-AFI (LCAF)
        return w.data
    }

    // Map-Request ITR-RLOC telemetry, matching lisp_map_request.encode_json()
    // exactly: lcaf-len = json-len + 4 (the 2-byte json-len field + a trailing
    // AFI 0), and NO RLOC address. The general encodeJSONLCAF() below appends the
    // RLOC address (for Map-Reply records); using it here makes lcaf-len = json
    // + 6, which fails the RTR's "lcaf_len == json_len + 4" check and yields
    // "Could not decode Map-Request packet".
    static func encodeProbeTelemetryLCAF(json: String) -> Data {
        var w = ByteWriter()
        let jsonBytes = Data(json.utf8)
        w.u16(LISP.afiLCAF)
        w.u8(0); w.u8(0)
        w.u8(LISP.lcafJSON)
        w.u8(0)
        w.u16(UInt16(jsonBytes.count + 4))      // lcaf-len = json-len + 4
        w.u16(UInt16(jsonBytes.count))          // json-len
        w.bytes(jsonBytes)
        w.u16(0)                                // trailing AFI 0
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
                    } else if innerAFI == LISP.afiLCAF {
                        // Nested LCAF inside the AFI-List: JSON telemetry (probe
                        // reply) or an RLE replication-list (group reply).
                        guard let _ = r.u8(), let _ = r.u8(), let t2 = r.u8(),
                              let _ = r.u8(), let l2 = r.u16() else { break }
                        if t2 == LISP.lcafJSON, let jsonLen = r.u16(),
                           let jb = r.bytes(Int(jsonLen)) {
                            rec.jsonString = String(data: jb, encoding: .utf8)
                        } else if t2 == LISP.lcafRLE {
                            let rend = r.offset + Int(l2)
                            while r.offset + 6 <= rend {
                                guard let _ = r.u16(), let _ = r.u8(), let level = r.u8(),
                                      let naf = r.u16(),
                                      let addr = LispAddress.unpack(afi: naf, reader: &r)
                                else { break }
                                var node = RLENode(level: level, rloc: addr, rlocName: nil)
                                if r.peekU16() == LISP.afiName {
                                    _ = r.u16(); node.rlocName = r.readName()
                                }
                                rec.rle.append(node)
                            }
                        }
                        break
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
            } else if type == LISP.lcafRLE {
                // Replication list: the joined-receiver RLOCs (lig of a group).
                let end = r.offset + Int(lcafLen)
                while r.offset + 6 <= end {
                    guard let _ = r.u16(), let _ = r.u8(), let level = r.u8(),
                          let nodeAFI = r.u16(),
                          let addr = LispAddress.unpack(afi: nodeAFI, reader: &r)
                    else { break }
                    var node = RLENode(level: level, rloc: addr, rlocName: nil)
                    if r.peekU16() == LISP.afiName {
                        _ = r.u16(); node.rlocName = r.readName()
                    }
                    rec.rle.append(node)
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
    var mobileNode = true                       // M: this xTR is a mobile node
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
        if mobileNode { first |= 0x200 }            // M (mobile-node)
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
    var decentNATXtr = false            // N: probe is from a NAT'd xTR
    var sourceEID = LispAddress()
    var itrRLOCs: [LispAddress] = []
    var telemetryJSON: String?          // extra ITR-RLOC carrying telemetry
    var targetEID = LispAddress()
    var targetGroup = LispAddress()     // non-null = (S,G) lookup; targetEID = source
    var subscribe = false               // pubsub: subscribe bit + xTR-ID
    var xtrID: (UInt64, UInt64)?

    func encode() -> Data {
        var w = ByteWriter()
        var first: UInt32 = UInt32(LISP.typeMapRequest) << 28
        if rlocProbe { first |= 0x0200_0000 }       // R/probe
        if smrInvoked { first |= 0x0040_0000 }      // I
        if subscribe { first |= 0x0010_0000 }       // X (xTR-ID present)
        if decentNATXtr { first |= 0x0000_8000 }    // N (decent-NAT xTR)
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
        if let json = telemetryJSON {
            w.bytes(LispRLOCRecord.encodeProbeTelemetryLCAF(json: json))
        }
        // Subscribe byte + mask-len, then EID prefix — or a Multicast-Info LCAF
        // when looking up a group (lig <group>), lisp.py:4627.
        w.u8(subscribe ? 0x80 : 0)
        w.u8(UInt8(targetEID.maskLen))
        if !targetGroup.isNull {
            w.u16(LISP.afiLCAF)
            w.bytes(LispEIDRecord.encodeMcastInfoLCAF(source: targetEID, group: targetGroup))
        } else {
            w.u16(targetEID.afi)
            w.bytes(targetEID.packAddress())
        }
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

    // Info-Reply — the R (info-reply) bit + a Type-7 NAT LCAF echoing the requester's
    // translated addr:port (globalETRRLOC/etrPort) so a decent-NAT prober confirms we're
    // reachable and learns its own translation. `echoHostname` rides the private-ETR-RLOC
    // slot as an AFI-17 name. Mirrors lisp_info.encode()'s reply path (lisp.py:6489-6538).
    func encodeReply(echoHostname: String?) -> Data {
        var w = ByteWriter()
        w.u32((UInt32(LISP.typeNatInfo) << 28) | (1 << 27))    // type 7, R bit set
        w.u64Native(nonce)
        w.zeros(12)                                            // key-id/auth-len/ttl/masklen/afi
        // Type-7 NAT LCAF: HHBBHH (afi, rsvd, lcaf-type, rsvd, lcaf-len) then ports + addresses.
        w.u16(LISP.afiLCAF); w.u16(0)
        w.u8(LISP.lcafNAT); w.u8(0)
        w.u16(16)                                              // lcaf-len (fixed 16, like lisp.py)
        w.u16(msPort); w.u16(etrPort)
        // Global ETR RLOC = the requester's translated address (IPv4).
        w.u16(LISP.afiIPv4); w.bytes(globalETRRLOC.packAddress())
        // Global MS RLOC absent (AFI 0), then private ETR RLOC = the echoed hostname (AFI-17).
        w.u16(0)
        if let h = echoHostname {
            w.u16(LISP.afiName); w.bytes(Data(h.utf8)); w.u8(0)
        } else {
            w.u16(0)
        }
        w.u16(0)                                               // empty RTR-list terminator
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
