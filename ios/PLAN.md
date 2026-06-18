# lispers.net iOS xTR — Plan & Analysis

Conversion of the lispers.net Python xTR subset to a native Swift iPhone app.
Source analyzed: `/Users/dino/l/lisp/` (lisp.py, lisp-itr.py, lisp-etr.py,
lisp-core.py, lispconfig.py, lisp-mc.py).

## Scope (phase 1)

The app is a self-contained xTR. It registers the configured EID to the
mapping system, and carries **app-generated traffic only** (the built-in
EID-to-EID ping) over the overlay. Traffic to non-240/4 addresses uses the
phone's normal underlay networking, untouched. Because the overlay traffic is
generated inside the app, **no Network Extension / packet tunnel is needed**
— everything is plain UDP sockets, which means the app sideloads with a free
Apple ID (no paid entitlements). This is the single most important
architectural decision; see Bottlenecks below.

### Implemented control messages
- **Info-Request / Info-Reply** (type 7) — NAT-traversal; periodic at
  `LISP_INFO_INTERVAL` (15 s) to keep the NAT binding alive; also sent
  LISP-data-header-wrapped (IID `0xffffff`) out the 4341 data socket so the
  data-port NAT binding exists (mirrors `lisp_send_info_request()`,
  lisp.py:16376).
- **Map-Register** (type 3) — every 60 s + triggered; HMAC-SHA1-96 /
  SHA256-128 over the zeroed-auth packet; I-bit with 128-bit xTR-ID and
  site-ID trailer; want-map-notify; merge; RTR RLOCs at priority 254 when
  behind a NAT.
- **Map-Request** (type 1) — both **ECM-encapsulated** (type 8) for mapping
  system lookups and **non-ECM RLOC-probe** (probe bit, sent straight to the
  RLOC on port 4342) — exactly the dual use the spec requires.
- **Map-Reply** (type 2) — parsed for lookups; probe replies matched by nonce
  for RLOC-probing; we also answer probes directed at us so telemetry has an
  ETR side.

### RLOC-probing + telemetry
Telemetry follows the lispers.net "lisp json" mechanism: a JSON body
`{"type":"telemetry","sub-type":"timestamps","itr-out":"?","etr-in":"?","etr-out":"?","itr-in":"?"}`
is carried as an LCAF JSON-type (14) ITR-RLOC in the probe Map-Request and as
a JSON RLOC-record in the probe Map-Reply. The app fills `itr-out` on send,
the responder fills `etr-in`/`etr-out`, and on reply receipt we stamp
`itr-in`, then compute RTT and forward/reverse one-way latencies
(rounded to 3 decimals, as `lisp.py:13868` does). Ring buffers of the last 10
RTTs / hop-counts / latencies are shown in the map-cache view, same as
`lisp-mc.py` prints `rtts [...], hops [...], lats [...]`.

### lisp-decent + decentralized-NAT
- Suffix + modulus configurable in the UI (equivalent of
  `decentralized-pull-xtr-dns-suffix` / `-modulus`).
- Map-server name for an EID = `str(index) + "." + suffix` where
  `index = int(hmac_sha256(key="lisp-decent", msg=eid_prefix_string).hex[0:12], 16) % modulus`
  — byte-for-byte the algorithm in `lisp_get_decent_index()` (lisp.py:20551),
  including the `[iid]prefix` string format from `print_prefix()`.
- The **decent-NAT toggle** installs the static map-cache entry
  `240.0.0.0/8` with action `send-map-request` (action value 2) and enforces
  the rule that received encapsulated packets must have **source port 4341**;
  packets failing the check are dropped and logged. When the toggle is off
  the entry is removed and the check is not applied.

### Data plane
- 8-byte LISP data header (N/L/E/V/I flags, 24-bit nonce, 24-bit IID) —
  encode/decode identical to `lisp_data_header` (lisp.py:3079).
- Outer is plain UDP from our socket (the OS builds the IP header), dest port
  4341. The Python source-port hash (`0xf000 | hash&0xfff`) applies to raw-
  socket encap; on iOS the data socket is **bound to local port 4341**, which
  is exactly what decent-NAT requires, and what NAT-traversal needs so the
  translated data-port binding matches Info-Request state.
- Inner packets are full IPv4 headers built in-app (checksum, TTL) — the ping
  service crafts inner IPv4+ICMP echo packets from our EID, so no raw sockets
  are needed anywhere.
- Decap: strip data header, verify the decent-NAT source-port rule, parse
  inner IPv4, deliver ICMP echo-replies to the ping service, and answer
  incoming echo-requests addressed to our EID (so other xTRs can ping us).
- Only destinations inside `240.0.0.0/4` go through the map-cache/overlay,
  per the requirement.

### Map-cache
`lisp_mapping`-equivalent entries with uptime, TTL ("forever"/mins/hours
formatting from `print_ttl()`), action, per-RLOC state (up/unreach),
priority/weight, encap-port (shown when ≠ 4341), per-RLOC stats and telemetry
lists. The map-cache screen renders the **same layout as `lisp-mc.py`**,
including its color scheme (green EIDs, red RLOCs, blue names, bold actions).

### Logging
Three in-app logs — **lisp-core.log, lisp-itr.log, lisp-etr.log** — written
to the app's Documents/logs/ directory (retrievable via Finder/Files app
since `UIFileSharingEnabled` is set) and shown live in the UI. Line format is
identical to `lprint()` (lisp.py:824):

    06/10/26 14:32:45.123: itr: Send Map-Request to 91.l8.198.am, port 4342

Control-plane debugging toggles per-component debug logging (the `lisp debug`
clause); the data-plane debugging toggle is `lisp_data_plane_logging`
(`dprint()`), off by default, printing encap/decap per-packet lines.

### Mini hosts file
`Documents/lisp-hosts` seeded on first launch with

    lhr 240.10.0.1
    frt 240.10.0.2
    cmh 240.10.0.8

The ping screen builds its target list from this file (editable in the UI
and via the Files app), so addresses are never hard-coded.

## App structure

```
ios/
  PLAN.md                     this file
  README.md                   build + sideload instructions
  LispersNet.xcodeproj/       hand-written, folder-synchronized project
  LispersNet/
    LispersNetApp.swift       @main; engine lifecycle
    Core/
      LispConstants.swift     ports, intervals, actions, AFIs, flag masks
      ByteBuffer.swift        big-endian packing/unpacking helpers
      LispAddress.swift       IPv4/IPv6 + IID + prefix; print_prefix() parity
      LispLog.swift           lprint/dprint/fprint; 3 log files + live UI feed
      LispDataHeader.swift    8-byte data header
      LispControlMessages.swift  Map-Request/Reply/Register, Info, ECM,
                                 EID-record, RLOC-record, LCAF JSON, auth
      Telemetry.swift         encode/decode/RTT+latency math
      MapCache.swift          mappings, RLOC state, lisp-mc.py formatting
      Interfaces.swift        RLOC discovery (getifaddrs) + NWPathMonitor
      Sockets.swift           UDP sockets bound to 4341/4342
      ControlPlane.swift      registration, Info-Request flow, lookups, probes
      DataPlane.swift         encap/decap, decent-NAT checks, stats
      PingService.swift       inner IPv4/ICMP build + match, RTT display
      HostsFile.swift         lisp-hosts parser/store
      LispConfig.swift        persisted settings (map-servers, EID, decent…)
      LispEngine.swift        orchestrator: enable/disable, timers
    UI/
      ContentView.swift       tab shell + status header
      ConfigView.swift        toggles, map-servers, decent, EID
      PingView.swift          ping lhr/frt/cmh + hosts editor
      MapCacheView.swift      lisp-mc.py-style rendering
      LogsView.swift          core/itr/etr log viewer
    Assets.xcassets           lispers.net-style icon
```

Single process replaces the lisp-core/lisp-itr/lisp-etr process trio; the
Unix-socket IPC layer (`lisp_ipc()`, lisp.py:6897) disappears entirely, but
the per-component log identity is preserved so the logs read the same.

## Bottlenecks (the honest list)

1. **App-only overlay vs. system tunnel.** Phase 1 deliberately avoids
   `NEPacketTunnelProvider`. The moment you want *other apps'* traffic (or
   the whole phone) on the overlay, you need the Packet Tunnel entitlement —
   that requires a **paid Apple Developer account** ($99/yr) and cannot be
   sideloaded with free provisioning. OOR's iOS port pays exactly this cost.
   This is the biggest fork in the road, and why ping-from-the-app is the
   right phase-1 deliverable.

2. **Backgrounding.** iOS suspends the app (and its sockets) shortly after it
   leaves the foreground. Consequences: periodic Map-Registers stop, the
   15-second Info-Request NAT keepalive stops, and the NAT binding will
   expire. The app re-runs the Info-Request/Map-Register sequence on
   foreground return, but a phone xTR is effectively **foreground-only**.
   True always-on operation again points at the Network Extension (which gets
   background execution).

3. **Source-port preservation through NAT.** decent-NAT requires received
   encap packets to have source port 4341. We bind the data socket to local
   port 4341, but whether the *peer sees* 4341 depends on the NAT not
   rewriting the source port (port-preserving / full-cone behavior). Cellular
   CGNATs frequently rewrite ports — same constraint the Python xTR has on
   any NATed box, but phones live behind CGNAT more often. NAT-traversal mode
   (Info-Request discovered translated port + RTR relay) is the fallback and
   is implemented.

4. **No pcap, no raw sockets, no kernel routes.** The Python ITR/ETR pcap
   the wire and write iptables/`ip route` state. None of that exists on iOS.
   It doesn't matter for phase 1 because all overlay traffic originates and
   terminates inside the app, but it permanently rules out the Python
   architecture of "capture transit packets" — transit forwarding must go
   through the OS tunnel API instead.

5. **RLOC discovery & path changes.** Wi-Fi↔cellular handoffs change the
   RLOC mid-flight. `NWPathMonitor` triggers re-discovery, a triggered
   Map-Register, and fresh Info-Requests; expect a few seconds of overlay
   outage on every handoff. Also, the cellular interface address is usually
   CGNAT'd (see #3).

6. **Wire-format quirks.** The Python encoders have endianness subtleties the
   Swift code must reproduce exactly: nonces packed in *native* (little-
   endian) order while everything else is network order; the 64-bit byte
   swap on x86/ARM in the Map-Register auth path; the IPv4-vs-IPv6 dport
   swap quirk in `lisp_packet.fix_outer_header()`. These are interop bugs
   waiting to happen and are flagged with comments in the Swift code.

7. **Local Network privacy prompt.** The first send to a private-subnet
   address pops the iOS Local Network permission dialog. Map-servers on the
   public internet don't trigger it, but lab setups with RFC1918 map-servers
   will. `NSLocalNetworkUsageDescription` is set in the project.

8. **Free-provisioning expiry.** A free Apple ID signature is valid 7 days;
   the app must be re-deployed from Xcode weekly (AltStore/SideStore can
   automate the refresh). A paid account extends this to 1 year.

## os.system()/getoutput() calls that cannot be ported

These exist in the Python xTR and have **no iOS equivalent**. None are needed
for phase 1; replacements noted.

| Call (file:line) | Purpose | iOS disposition |
|---|---|---|
| `iptables -t raw …` (lisp-itr.py:1000-1062, ×~10) | divert/drop EID traffic in kernel | not portable, not needed — app sources all overlay traffic |
| `ip route add/delete …` (lisp-etr.py:1843-1868) | install EID routes toward tun | not portable — would be `NEPacketTunnelNetworkSettings` routes in a phase-2 tunnel |
| `ip link set … up` (lisp-etr.py:1711) | bring up tun device | same as above |
| `netstat -rn \| egrep default` (lisp-itr.py:225) | find default-route interface | replaced by `NWPathMonitor`/`getifaddrs` |
| `ifconfig \| egrep …` (lisp-itr.py:238-241) | enumerate interfaces | replaced by `getifaddrs()` |
| `egrep 'lisp-nat = yes' ./lisp.config` (lisp-itr.py:1133) | read config | replaced by in-app settings store |
| `uptime`, `cp lisp.config …`, `pydoc`, log greps (lisp-core.py various) | web UI/ops conveniences | dropped — web UI is out of scope per requirements |
| `ls join-*` (lisp-etr.py:1504) | multicast group joins | dropped — multicast out of scope phase 1 |

Anything above that you want behaviorally preserved in a later phase (e.g.
real route installation) is a Network Extension conversation, not a shell
conversation.

## Phase 2 candidates (not in this build)

- `NEPacketTunnelProvider` system tunnel so *any* app's 240/4 traffic rides
  the overlay (requires paid developer account; OOR's iOS code is the
  reference for the tunnel-side plumbing).
- LISP-crypto (chacha/poly1305 are pure-python and port easily; Apple
  CryptoKit has ChaCha20-Poly1305 built in).
- Multicast EIDs, RLE, pubsub, map-notify processing beyond ack.
