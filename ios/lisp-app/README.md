# lispers.net iOS xTR

A native Swift iPhone port of the lispers.net xTR (phase 1: app-internal
overlay with EID-to-EID ping). See [PLAN.md](PLAN.md) for the architecture,
the bottleneck analysis, and the list of os.system() calls that could not be
ported.

## What it does

- Registers your EID to the mapping system (Map-Register with SHA-1/SHA-256
  auth, xTR-ID/site-ID, want-map-notify) every 60 seconds and on RLOC change.
- NAT-traversal: Info-Request/Info-Reply on both the control (4342) and data
  (4341) paths, translated-RLOC detection, RTR list registration at
  priority 254, 15-second NAT keepalive.
- LISP-Decent: configure the pull suffix + modulus; the map-server name is
  `<hmac-sha256-hash mod modulus>.<suffix>` — verified byte-identical to
  `lisp_get_decent_index()` in lisp.py.
- Decentralized-NAT toggle: installs the `240.0.0.0/8` send-map-request
  static map-cache entry and enforces source-port-4341 on decap.
- Map-Requests both ECM-encapsulated (mapping-system lookup) and non-ECM
  (RLOC-probe), Map-Reply processing into the map-cache.
- RLOC-probing every 10 s with **telemetry** (the "lisp json" timestamps
  body): RTT + forward/reverse one-way latencies, shown in the map-cache.
- EID-to-EID **ping** over the overlay: inner IPv4/ICMP built in-app,
  encapsulated to port 4341. Targets come from the editable `lisp-hosts`
  file (defaults: lhr 240.10.0.1, frt 240.10.0.2, cmh 240.10.0.8). The app
  also answers pings and RLOC-probes sent to its EID.
- Logs in lprint() format: lisp-core.log, lisp-itr.log, lisp-etr.log —
  live in the Logs tab and on disk in the app's Documents/logs/ (visible in
  the Files app). Control-plane and data-plane debug toggles in the UI.
- Map-Cache tab renders entries in the lisp-mc.py layout and color scheme.

## Building

Requirements: Xcode 16 or newer (project uses folder-synchronized groups),
iOS 17+ deployment target. No external dependencies — CryptoKit, Network,
and SwiftUI only.

```
open LispersNet.xcodeproj
```

Select the LispersNet target → Signing & Capabilities → set your Team
(a free Apple ID works — the app needs no paid entitlements).

## Sideloading onto your iPhone (no TestFlight)

1. Plug the iPhone into the Mac (or use Wi-Fi debugging once paired).
2. On the phone: Settings → Privacy & Security → **Developer Mode** → on
   (iOS asks to reboot).
3. In Xcode, pick your iPhone as the run destination and press **Run**.
4. First launch only: Settings → General → VPN & Device Management → trust
   your developer certificate.

With a free Apple ID the signature lasts **7 days** — re-run from Xcode to
refresh, or use AltStore/SideStore to auto-refresh. A paid developer account
extends this to one year. (This is bottleneck #8 in PLAN.md.)

## Using the app

1. **xTR tab**: set your EID (e.g. `240.10.0.100`), add a map-server
   (dns-name/address + authentication-key) *or* set the LISP-Decent suffix
   and modulus, then flip **Enable LISP**. The app discovers the active RLOC
   interface (Wi-Fi first, then cellular) automatically.
2. Toggle **Decentralized-NAT** if your overlay runs decent-NAT — you'll see
   the 240.0.0.0/8 entry appear in the Map-Cache tab.
3. **Ping tab**: tap lhr / frt / cmh. First ping to a new EID triggers a
   Map-Request; the reply installs the map-cache entry and the queued ping
   goes out. Edit `lisp-hosts` from the toolbar to add targets.
4. **Map-Cache tab**: lisp-mc.py-style display with RLOC state, packet
   counts, and probe rtts/hops/lats.
5. **Logs tab**: pick lisp-core.log / lisp-itr.log / lisp-etr.log. Turn on
   control-plane or data-plane debugging from the xTR tab to see the
   familiar packet-level lines.

## Caveats (short version — PLAN.md has the full list)

- Foreground-only: iOS suspends the sockets in the background; the app
  re-runs Info-Request + Map-Register when it returns to the foreground.
- App-generated traffic only (ping). System-wide overlay needs a
  NEPacketTunnelProvider and a paid developer account — that's phase 2.
- decent-NAT's source-port-4341 expectation requires a port-preserving NAT,
  same as the Python xTR; cellular CGNAT often is not.
