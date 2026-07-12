# gaapchat (iOS) — design & plan

Port of Python `gaap`/`gaapchat` (`/Users/dino/code/gaap/src/`) to a Swift/SwiftUI app that
runs over the LISP overlay (the shipped Option-B always-on xTR). First real overlay app.
Target dir: **`/Users/dino/l/ios/gaapchat-app`** (Dino's email said `/Users/dino/ios/…` but
that doesn't exist; using the `l/ios` tree next to lisp-app + ping-app).

## Decisions
- **Chat is PLAINTEXT** (Dino, 2026-07-11) — interoperates with the current Python gaapchat as-is.
  ChaCha8 is still ported and kept ready, but chat text goes in the clear.
- **IPv4-only** — the overlay is IPv4 (240/4 EIDs, 224/4 groups). The Python `ff1e::` IPv6 path
  is out of scope on iOS.
- **Hash-only at runtime** — hash the group-name → address; do NOT run the full GAAP
  allocation/claim protocol (224.0.170.170:0xaaaa). The collision "hash tab" is diagnostic only.
- **gs / gr** — deferred to a later phase ("see if they can be enabled").
- Same **LISP app logo/icon**.

## Interop-critical facts (from the Python reference — must match bit-for-bit)
- **Group address hash** (`gaap.py hash_group_name`): `HMAC-SHA256(key=b"gaap", msg=group_name)`;
  rehash N≠0 appends `"+"+str(N)` to the name before hashing. Take the LAST 3 bytes of the
  digest → `224.b2.b3.b4` (b2=digest[29], b3=digest[30], b4=digest[31], mask 0xff = /8 = 24-bit).
  CryptoKit `HMAC<SHA256>`.
- **Chat UDP port**: `0xfafa` (64250). Chat sent to `(group_address, 0xfafa)`.
- **Chat wire format** — plaintext ASCII, `"%%"`-delimited:
  - `data%%<myid>%%<text>`
  - `ping%%<myid>%%<seq>`     (member receiving a ping auto-sends a pong)
  - `pong%%<myid>%%<pinger>%%<seq>`
  - `myid = "<user>@<hostname>"`; `seq` = the fractional digits of `time.time()`.
  - Receiver skips its own loopback (`parms[1] == myid`).
- **UI** (`gaapchat.py`): commands `:help/:?`, `:history/:h`, `:ping/:p`, `:quit/:q`, `:show/:s`.
  Ping/pong `seq` cycles colors **blue→green→red→purple**; `data` shows the sender bold.
  `:show` = union of senders seen; `:history` = full log.
- **ChaCha8** (`chacha.py`): Bernstein 8-round (NOT RFC-8439 ChaCha20 — CryptoKit won't interop),
  8-byte IV = `b"A"*8`, 32-byte key = `group_name.zfill(32)` (left-pad with ASCII '0'), first 4
  bytes = `0xAAAAAAAA` marker left in the clear, rest ChaCha8. Ported + ready; not used for chat.
- **iOS `myid`**: no Unix user/hostname → use a user-set **nickname** (default = device name).

## Architecture — over the overlay, like the PING app
- **Send**: build raw inner IPv4/UDP `[src=myEID, dst=group:0xfafa]/[ascii]`, inject to the tunnel
  (utun `EID:4341` on device / loopback 41342 on sim) → the extension encaps → multicast to group.
- **Receive**: the extension decaps the group UDP → forwards the raw inner to gaapchat's receive
  port. **NEW LISP-app work: `deliverInner` today only forwards ICMP; it must also forward group
  (and unicast-to-us) UDP to the overlay app.**
- **Group join/register**: gaapchat asks the LISP app to join+register the hashed group. **NEW
  LISP-app work: an overlay-app group-join/leave API** (App-Group command file the extension +
  app read). The group shows in the LISP "groups joined" list but is **app-joined**: the user
  cannot leave it in the LISP UI; only gaapchat leaves it (on app close / stale heartbeat).

## LISP-app changes (Phase A — modifies the shipped app; new dev cycle 0.10-2+)
1. **Overlay-UDP receive**: `DataPlane.deliverInner` forwards a decapped UDP packet destined to a
   joined group (or our EID) to the overlay app on a new loopback port (gaapchat receive port).
2. **Overlay-app group join/leave API**: gaapchat writes requested app-groups to the App-Group
   container; the engine (app or extension) joins + `sendGroupRegisters` them and tags them
   `appJoined`. Leave when the request is withdrawn / the app's heartbeat goes stale.
3. **UI**: app-joined groups render in the joined-groups list with the user's leave control
   disabled (a lock/《app》badge); user-joined groups behave as today.
4. Keep working with the existing PING paths (41342 inject, 41343/41344 replies) — gaapchat gets
   its own receive port so nothing clashes.

## gaapchat app (Phase B — new Xcode project)
- SwiftUI chat view matching the Python UX (colored message rows, input box, the `:` commands),
  a **Collision** tab (group-name → the rehash candidate addresses, like `gaaphash`/`gaapcollide`),
  and a small settings area (nickname, current group + hashed address, LISP-ready indicator like
  PING's heartbeat).
- `GaapHash` (HMAC-SHA256), `ChaCha8` (ported), overlay send/recv (reuse PING's `LispWire`
  raw-inner pattern), group join/leave requests to the LISP app.
- Lifecycle: on group-join → ask LISP to register; stays joined while backgrounded (extension
  persists); on app close → leave request. Same LISP icon assets.

## Ports
- Chat: **0xfafa** (interop). Overlay inject to extension: **41342** (utun `EID:4341` on device),
  reused from PING. gaapchat receive from extension: **NEW** loopback port (e.g. 41345) so it
  doesn't collide with PING's 41343/41344.

## IGMP-driven registration model (Dino refinements, 2026-07-11) — DONE
- **(*,G) Map-Registers are IGMP-triggered, not timer-driven.** Every IGMPv2 Report triggers
  ONE `sendGroupRegister`; the LISP register timer does **unicast EID only** (`sendMapRegisters`).
  `applyIGMP` (IGMP.swift) is the single membership state machine. `reregisterIGMPGroups()`
  re-registers all (*,G) with the current @tp port on Info-Reply / RLOC-change / resume.
- **Manual LISP groups self-report IGMP** (`selfReportManualGroups`, ~60s from the register
  timer + on manual join) → same `applyIGMP` path → same (*,G) trigger. Manual join/leave now
  call `applyIGMP` (report/leave, source "LISP app") instead of `sendGroupRegister` directly.
- **Source labeling in-band:** the joiner appends its name to the IGMP packet (gaapchat →
  "gaapchat"; LISP self-report → "LISP app"). `igmpGroupSource[g]` records it. VERIFIED on sim:
  an injected report with trailing "gaapchat" produced snapshot `igmpGroups {addr: "gaapchat"}`.
- **Logging:** joiner logs `Send IGMPv2 report/leave for group <addr>` (gaapchat in its chat log
  on join/leave; LISP for manual self-reports); the xTR logs `Receive IGMPv2 report/leave …
  from <source> — triggering (*,G) Map-Register` on receipt, followed by the register line.
- **Display (xTR tab Multicast Groups):** manual groups (config.joinedGroups) show `manual` +
  a Leave button; overlay groups (appJoinedGroups, from igmpGroups where source≠"LISP app")
  show LOCKED with `via <source>`. Snapshot field is now `igmpGroups: [address: source]`.

## BUILD STATUS (2026-07-11, overnight autonomous run)
**Phases A + B + C implemented; both apps build for sim AND device.** Not yet device-tested
(phone was locked overnight — that's the remaining step).

- **LISP app 0.10-3** (Phase A, uncommitted, modifies the shipped 0.10):
  - `Core/IGMP.swift` — parse IGMPv2 Report/Leave from the overlay-inject path → soft-state
    (*,G) `igmpGroups` (report every ~60s, expire after `igmpGroupTimeout`=300s); register via
    `sendGroupRegister`; forward received group/unicast UDP to the overlay app (`overlayRecvPort`
    41345). `injectFromTunnel` intercepts proto 2; `deliverInner` accepts IGMP groups + forwards
    proto-17. New constants in `LispConstants.swift`. App-joined groups shown LOCKED in ConfigView
    (via `engine.appJoinedGroups` + a new `igmpGroups` snapshot field).
  - **VERIFIED on sim:** injecting a crafted IGMPv2 report for `224.145.240.210` (hash of "audio")
    to the app-as-xTR engine populated the snapshot's `igmpGroups` → registration path works.
- **gaapchat 0.1** (`/Users/dino/l/ios/gaapchat-app`, new Xcode project, bundle
  `net.lispers.xtr.gaapchat`, LISP icon): `GaapHash` (HMAC-SHA256 — **verified bit-for-bit vs
  Python** for 5 names), `ChaCha8` (ported, ready, unused — chat is plaintext), `GaapWire` (IGMP
  Report/Leave send + chat UDP send to group:0xfafa + chat parser + recv on 41345), `ChatClient`
  (myid=`nick@device`, data/ping/pong, color-cycled ping/pong, `:` commands, join→IGMP/60s reports,
  leave-on-:quit, shows own messages), `ContentView` (Chat + Collide tabs). Installed + launched
  on sim (overlay round-trip can't run on sim — no NE).

### NEEDS DEVICE (morning): install LISP 0.10-3 + gaapchat 0.1 on the phone, then
- Enable Overlay App VPN, restart it so the extension loads 0.10-3.
- gaapchat: join a group → confirm it appears LOCKED in the LISP app's Multicast Groups.
- Chat between gaapchat (iphone) and Python gaapchat (same group name) → messages both ways;
  `:ping` → colored pongs from members; verify plaintext interop on port 0xfafa.
- Background gaapchat >5 min → group soft-state expires (Dino's choice); `:quit` → clean leave.

## Phasing
- **A** — LISP-app: overlay-UDP receive forward + overlay-app group-join/leave API + no-user-leave
  UI. (Foundational; unblocks the app.)
- **B** — gaapchat app: hash, overlay send/recv, chat UI + commands + colors, group lifecycle.
- **C** — collision tab; wire in ChaCha8 (ready); polish; on-device test with Python gaapchat.
- **D** (later) — gs / gr integration.
