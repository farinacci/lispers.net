//
// LispConstants.swift
//
// Constants carried over from lisp.py so wire behavior and timer cadence
// match the Python xTR exactly.
//

import Foundation

enum LISP {
    // UDP ports
    static let dataPort: UInt16 = 4341          // LISP_DATA_PORT
    static let ctrlPort: UInt16 = 4342          // LISP_CTRL_PORT
    // Fixed local port for the data socket in NAT-traversal mode. lisp.py uses a
    // fixed data port (4341); we can't (Mac-lisp collision + "4341 breaks the
    // data-plane"), but a FIXED non-4341 port keeps the NAT-translated @tp port
    // stable across app restarts so the RTR's registration doesn't go stale and
    // flap our RLOC to unreach-state. (Ephemeral port 0 changed every relaunch.)
    static let natDataPort: UInt16 = 41341

    // Control message types (high nibble of first long)
    static let typeMapRequest: UInt8 = 1
    static let typeMapReply: UInt8 = 2
    static let typeMapRegister: UInt8 = 3
    static let typeMapNotify: UInt8 = 4
    static let typeNatInfo: UInt8 = 7           // LISP_NAT_INFO
    static let typeECM: UInt8 = 8               // LISP_ECM

    // AFIs
    static let afiIPv4: UInt16 = 1
    static let afiIPv6: UInt16 = 2
    static let afiLCAF: UInt16 = 16387          // LISP_AFI_LCAF
    static let afiName: UInt16 = 17             // LISP_AFI_NAME (distinguished name)

    // LCAF types
    static let lcafAFIList: UInt8 = 1           // LISP_LCAF_AFI_LIST_TYPE
    static let lcafInstanceID: UInt8 = 2
    static let lcafNAT: UInt8 = 7               // LISP_LCAF_NAT_TYPE
    static let lcafJSON: UInt8 = 14             // LISP_LCAF_JSON_TYPE

    static let tpPrefix = "@tp-"                // LISP_TP (translated-port tag)

    // Map-cache actions (lisp.py:429)
    static let noAction = 0
    static let nativeForwardAction = 1
    static let sendMapRequestAction = 2
    static let dropAction = 3

    static func actionString(_ a: Int) -> String {
        switch a {
        case nativeForwardAction: return "native-forward"
        case sendMapRequestAction: return "send-map-request"
        case dropAction: return "drop-action"
        default: return "no-action"
        }
    }

    // Auth algorithm IDs
    static let noneAlgID: UInt8 = 0
    static let sha1AlgID: UInt8 = 1             // LISP_SHA_1_96_ALG_ID
    static let sha2AlgID: UInt8 = 2             // LISP_SHA_256_128_ALG_ID

    // Timers (seconds) — lisp.py values
    static let infoInterval: TimeInterval = 15          // LISP_INFO_INTERVAL
    static let mapRegisterInterval: TimeInterval = 60   // LISP_MAP_REGISTER_INTERVAL
    static let rlocProbeInterval: TimeInterval = 10     // LISP_RLOC_PROBE_INTERVAL
    static let rlocProbeReplyWait: TimeInterval = 15    // LISP_RLOC_PROBE_REPLY_WAIT
    static let rlocProbeTTL = 64                        // LISP_RLOC_PROBE_TTL
    static let registerTTL: UInt32 = 1440               // minutes (LISP_REGISTER_TTL)
    static let mapRequestRateLimit: TimeInterval = 2

    // The overlay EID space requirement: only 240.0.0.0/4 uses LISP.
    static let overlayPrefix: UInt32 = 0xF000_0000      // 240.0.0.0
    static let overlayMask: UInt32 = 0xF000_0000        // /4

    // decent-NAT static entry: 240.0.0.0/8 send-map-request
    static let decentNatEID = "240.0.0.0"
    static let decentNatMaskLen = 8

    // Data header instance-id used on data-port Info-Requests
    static let infoIID: UInt32 = 0xFFFFFF
}
