//
// LispConstants.swift
//
// Constants carried over from lisp.py so wire behavior and timer cadence
// match the Python xTR exactly.
//

import Foundation

// App/build version string. **BUMP THIS ON EVERY BUILD.** Lives in Core (not ContentView)
// so both the app and the LispTunnel extension can stamp it into their log banners;
// ContentView.version is an alias for the app UI.
enum AppInfo {
    static let version = "0.14-30"
}

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
    // Loopback port the tunnel extension hands captured overlay inner packets to, so
    // the app's data plane (encapAndSend) forwards them with the same logging + map-
    // cache counters + registered data socket as an in-app ping.
    static let overlayInjectPort: UInt16 = 41342
    // Loopback port the LISP app forwards echo-REPLIES to the external PING client app
    // on (replies not matching a local Direct ping). The PING app listens here.
    static let pingReplyPort: UInt16 = 41343
    // Second reply port: when the xTR runs in the extension (Option B), the app's OWN
    // Direct-ping tab is an overlay client too (it injects to the extension like PING),
    // so the extension forwards echo-replies to BOTH ports — 41343 for the standalone
    // PING app, 41344 for the in-app Ping tab — and each matches by its ICMP identifier.
    static let pingReplyPortApp: UInt16 = 41344
    // Loopback port the LISP app forwards received overlay UDP (a joined multicast group's
    // traffic, e.g. gaapchat chat) to. The gaapchat app listens here. Distinct from the
    // PING reply ports so nothing collides.
    static let overlayRecvPort: UInt16 = 41345
    // The gaapchat chat UDP port (Python gaapchat app_port = 0xfafa) — the inner UDP dst
    // port of chat data/ping/pong packets. Kept identical for Python interop.
    static let gaapChatPort: UInt16 = 0xfafa

    // LISP-Trace (ltr.py). Type-9 messages ride UDP on port 2434 (4342 backwards) between
    // EIDs; the accumulated path JSON is returned to the ltr client. The extension forwards
    // decapped LISP-Trace replies (inner UDP payload starting 0x9x) to the LTR tab on 41346.
    static let tracePort: UInt16 = 2434                 // LISP_TRACE_PORT
    static let typeLispTrace: UInt8 = 9                 // LISP-Trace message type (high nibble)
    static let ltrReplyPort: UInt16 = 41346

    // IGMPv2 (RFC 2236) — an overlay app (gaapchat) sends these over the tunnel (inner
    // dst = our EID, IP proto 2) to drive soft-state (*,G) group membership registration.
    static let ipProtoIGMP: UInt8 = 2
    static let igmpV1Report: UInt8 = 0x12
    static let igmpV2Report: UInt8 = 0x16
    static let igmpV2Leave: UInt8  = 0x17
    // (*,G) soft-state GRACE WINDOW: an overlay group survives this long after the joining
    // app's last IGMP Report. Long enough to tolerate app-switching / brief backgrounding
    // (the always-on xTR refreshes the (*,G) meanwhile), short enough to auto-clean a hard-
    // killed app whose Leave never sent. gaapchat reports every 60s foreground + once at
    // background, so a backgrounded group survives ~3 min then de-registers.
    static let igmpGroupTimeout: TimeInterval = 180     // 3 min

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
    static let lcafMcastInfo: UInt8 = 9         // LISP_LCAF_MCAST_INFO_TYPE (S,G)
    static let lcafRLE: UInt8 = 13              // LISP_LCAF_RLE_TYPE (replication list)
    static let lcafJSON: UInt8 = 14             // LISP_LCAF_JSON_TYPE

    static let tpPrefix = "@tp-"                // LISP_TP (translated-port tag)

    // LISP_LOAD_SPLIT_PINGS — spread per-ping traffic across the best-priority
    // RLOC tier (e.g. both RTRs) instead of pinning to one. Default on here.
    static let loadSplitPings = true

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
    // Go unreach after 3 missed probes (3 × interval). At a 10 s interval a reply
    // that's merely late won't flap the RLOC; three consecutive misses will.
    static let rlocProbeReplyWait: TimeInterval = 30    // 3 × rlocProbeInterval
    static let rlocProbeTTL = 64                        // LISP_RLOC_PROBE_TTL
    // Multi-homing egress hysteresis: a better next-hop must beat the currently
    // active one by this % of its rtt before we switch — damps oscillation from
    // ordinary jitter (lisp.py lisp_mh_rtt_pct / multi-home-rtt-percentage).
    static let mhRTTPct = 10
    static let registerTTL: UInt32 = 1440               // minutes (LISP_REGISTER_TTL)
    static let multicastRegisterTTL: UInt32 = 1440      // minutes (24h) — group membership
                                                        // (refreshed every 60s register)
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
