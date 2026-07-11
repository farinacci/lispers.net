# Option B — Always-on xTR in the NE Extension (0.10 / next release)

## Goal
Relocate the xTR's data + control plane into the `LispTunnel` NEPacketTunnelProvider so the
phone stays a **registered, pingable xTR when the app is backgrounded or closed**. The app
becomes a UI / monitor / controller; the extension is the always-on xTR (alive whenever the
"Overlay App VPN" is enabled — iOS keeps a packet-tunnel provider running as long as its VPN
config is on).

## The load-bearing invariant
The **registered RLOC:port MUST be the extension's data-socket NAT mapping.** RTRs encap to
that mapping; if it's the app's socket (which iOS suspends), inbound delivery dies. So the
extension must own: the data socket (4341 / fixed NAT port), the Info-Request NAT dance that
learns the translated `@tp-<port>`, and Map-Register.

## What changes

### 1. Share `Core/` with the extension
Today `LispEngine` + all of `Core/` compile ONLY into the app target; the extension has just
`PacketTunnelProvider.swift`. The engine must run inside the extension.
- Move `Core/` into a unit both targets compile: **(a) a shared framework** (`LispCore`) or
  **(b) add the `Core/` files to the LispTunnel target's membership.** Framework = cleaner
  boundary, more pbxproj surgery (Xcode-16 synchronized-folder format). Files-in-both = less
  surgery, must `#if` app-only bits.
- **Guard app-only deps** out of the extension: `beginBackgroundGrace()` / `UIApplication`
  (already `#if canImport(UIKit)`), any SwiftUI. `LispConfig`'s on-disk file must move to the
  **App-Group container** so both processes read it.
- **Memory audit** — NE has a tight jetsam budget (~tens of MB). Trim log ring buffers,
  map-cache retention, and the heavy per-packet hex logging. Lean or iOS kills the extension.

### 2. Extension becomes the xTR
- `startTunnel`: read the **FULL config** from the App Group (map-servers, decent
  suffix/modulus/auth-key, NAT flags, telemetry, joined groups — not just EID/IID/hostname),
  bring up a **minimal utun** (just the vehicle that keeps the extension alive; overlay
  traffic does NOT route through it), then start the engine: bind data (4341/NAT) + control
  (4342) sockets, Info-Requests, Map-Register, RLOC-probing, encap/decap — all on **GCD
  timers** (no UI run loop in an extension), plus the overlay inject (41342) + reply (41343)
  sockets.
- `stopTunnel`: tear the engine down cleanly.
- Handle **iOS on-demand restarts** idempotently (re-read config, re-register).

### 3. Mode coordination — exactly one xTR
Two processes can't both bind 4341/4342/41342.
- **VPN on** → the **extension** is the xTR (always-on); the app must NOT start engine sockets.
- **VPN off** → the **app** is the xTR (today's foreground-only behavior).
- The toggle transition hands off (app engine down ⇄ extension engine up). Needs an owner flag
  in the App Group + startup checks in both to avoid split-brain / double-register.

### 4. App ⇄ extension IPC (so the UI still works)
- **Config down (app → ext):** app serializes the full `LispConfig` to an App-Group FILE on
  every change; the extension reads it and (re)starts the engine. (FILE, not UserDefaults —
  the reliable cross-process channel.)
- **State up (ext → app):** the extension periodically writes the map-cache snapshot (entries,
  RLOCs, states, counters, rtts/hops/lats) and the logs (itr/etr/core) to App-Group files; the
  app reads + renders them. (Extends today's capture-file mirroring to the full state.)
- **Commands (app → ext):** enable/disable, config edits, join/leave group, Direct ping, LIG —
  as command records (App-Group file or a loopback control port the extension listens on).

### 5. Overlay-app path — no change to overlay apps
PING/gaapchat already send the raw inner to loopback `41342` and read replies on `41343`. In
Option B those endpoints are owned by the **extension** instead of the app. The overlay apps
don't change. (utun capture path stays for the future transparent model, not the primary
transport.)

### 6. Direct ping / LIG from the app
The Ping/LIG tabs drive the app's engine today. With the engine in the extension they must
**send a command to the extension**, which executes and streams results back (an App-Group
file the tab tails). Most UI-invasive piece.

## Risks & constraints
- **NE memory / jetsam** — the #1 risk. Engine + map-cache + logs must fit the budget.
- **NAT-mapping invariant** — registered port = extension data socket, or the phone isn't
  reachable.
- **Dual-process socket coordination** — the mode handoff must be airtight (no double-bind,
  no double-register, no split-brain).
- **iOS extension restarts** — re-read config + re-register idempotently.
- **UI latency** — state via file polling updates on a cadence, not instantly.
- **Debuggability** — the extension is a separate process; harder to debug (os_log).

## Suggested phasing
- **Phase 0** — shared-Core restructure + memory audit + config→App-Group. No behavior change
  (app still the xTR). Validate the extension can compile + link the engine.
- **Phase 1** — extension runs the xTR when the VPN's on; app defers. PROVE: phone stays
  registered/pingable with the app **closed** (a remote xTR pings it; overlay round-trip works
  with the app backgrounded).
- **Phase 2** — full state/log/map-cache up to the app UI; config + enable/disable commands down.
- **Phase 3** — Direct ping / LIG via the extension; UI parity.

## Phase 0 — DONE (2026-07-09)
Core sharing implemented via **files-in-both-targets**, restructure validated:
- `LispersNet/Core/` lifted to a **top-level `Core/`** synced folder, added to BOTH targets'
  `fileSystemSynchronizedGroups` (new `PBXFileSystemSynchronizedRootGroup` AA300…B1). One
  source copy; the extension now compiles + links the whole engine.
- **`HOST_APP`** Swift compilation condition added to the app target only. The
  `UIApplication.beginBackgroundGrace` block in `LispEngine` re-guarded `#if HOST_APP`
  (`canImport(UIKit)` is TRUE in an extension but `UIApplication.shared` is unavailable there).
- App/build **version constant moved to Core** (`AppInfo.version` in LispConstants.swift);
  `ContentView.version` is now an alias so the extension can stamp log banners. **Bump
  `AppInfo.version` on every build.**
- **Config → App-Group container** (`LispConfig.fileURL` → `group.net.lispers.xtr`), with a
  one-time migration read from the legacy Documents path (`save()` rewrites to the shared
  location). Verified: sim run writes `AppGroup/.../lisp-config.json`.
- Verified: app+extension build for **simulator** AND **device** (extension entitlements
  provision), app launches on sim without crashing. No behavior change (app is still the xTR).
- Version bumped 0.9 → **0.9-1**. Not installed on dino-iphone (locked; no behavior change).

## Phase 1 — VALIDATED ON DEVICE (2026-07-09, 0.9-4)
Confirmed on dino-iphone with app + PING backgrounded: unicast PING round-trip, sim→iphone
unicast ping, AND multicast (sim → 224.2.2.2 → iphone replies) all work — both data planes
served by the always-on extension. Heartbeat green with both apps backgrounded. The extension's
`Timer`s fire fine (registration/probing/snapshot/heartbeat all work) — #1 risk CLEARED.
Logs fix (0.9-4): app tails the extension's App-Group log files (core/itr/etr) into the Logs
tab via `LispLog.loadTail` (LogsView reads a per-process in-memory ring that was empty in
mirror mode); old TunnelManager capture-mirror disabled.

The extension HOSTS the xTR. Builds clean for sim + device.
- **Extension is the xTR** (`LispTunnel/PacketTunnelProvider.swift`): `startTunnel` reads the
  App-Group `LispConfig`, creates a `LispEngine`, `enable()`s it on the main queue, keeps the
  utun (240/4) up, and forwards overlay-injected packets to its OWN in-process engine
  (127.0.0.1:41342). So the registered RLOC:port is the EXTENSION's data-socket NAT mapping —
  the phone is registered/pingable with the app closed. `stopTunnel` → `engine.disable()`.
- **Mode coordination** (`LispersNet/XTRCoordinator.swift`): Overlay App VPN ON → extension is
  the xTR, the app releases its sockets and MIRRORS; OFF → app is the xTR (original dual-mode).
  Reconcile is called from ConfigView toggles, ContentView.onAppear, and scenePhase `.active`.
  Guarantees one process binds 4342/41341 at a time. (Off→app handoff waits 1.5s for the
  extension to release sockets — a coarse guard, may need a status-driven wait.)
- **Live map-cache + status mirror** (`Core/EngineMirror.swift`): `EngineSnapshot` (Codable
  map-cache + status) is written to App-Group `xtr-state.json` every second by whoever runs
  the xTR (from the 1s timer in `startTimers`, so only the real xTR writes). In VPN-on mode the
  app polls it 1×/s and `applySnapshot()`s it into its own engine → MapCacheView/StatusHeader
  render the extension's live state UNCHANGED. `LispAddress`/`DiscoveredRLOC` made `Codable`.
- **Shared logs** (`Core/LispLog.swift`): logs now live in the App-Group `logs/` dir, so the
  app's Logs tab shows what the extension issued. Heartbeat also written by the extension →
  PING sees "LISP ready" with the app closed.

### On-device test checklist (dino-iphone)
1. Enable LISP + Overlay App VPN → accept the VPN prompt. Confirm the app shows the xTR active
   with a live map-cache (mirrored from the extension) and logs.
2. **Close the LISP app.** From a remote xTR, ping the phone's EID → replies. And run PING with
   the LISP app CLOSED → overlay round-trip works. Heartbeat stays green.

### Known follow-ups (NOT in this cut)
- **#1 risk — extension timers:** the engine uses `Timer.scheduledTimer` (needs the main run
  loop). Should fire in an NE provider, but if registration/probing never happens on device,
  convert the engine's repeating timers to GCD `DispatchSourceTimer` (as the heartbeat already
  is). First thing to check if the phone doesn't register.
- **Config live-reload:** the extension reads config once at `startTunnel`; app edits need a
  VPN restart to take effect. Add a config-changed signal later.
- **Decision #6 (Ping tab) / LIG in mirror mode:** the app's Direct ping no-ops in mirror mode
  (sockets nil) — no crash, but it doesn't yet inject to the extension over loopback like PING.
  LIG likewise. Wire these next.
- **Memory/jetsam:** engine + logs now run in the NE budget — watch for jetsam under load; trim
  log ring buffers / per-packet hex if needed.

## Decisions (Dino, 2026-07-09)
1. **Core sharing — DONE, files-in-both-targets** (see Phase 0 above).
2. **Dual-mode, confirmed.** The NE is a VPN and CANNOT run without it, so: **VPN on → NE is
   the always-on xTR; VPN off → the app is the xTR** (today's foreground-only). Keep the
   app-side engine as the VPN-off path. (Option-B-only would force the VPN always on —
   reintroducing the mandatory-VPN we just removed.)
3. **Live map-cache in the NE — MUST, Phase 1.** It's small (default entries + RTRs). The NE
   owns it and writes a snapshot to an App-Group file frequently; the app's Map-Cache tab
   renders it live. This is a hard Phase-1 requirement, not deferrable.
4. **Logs — NE issues, app stores/shows.** The NE writes log lines to shared App-Group files
   (itr/etr/core scopes); the app's Logs tab tails them. Same mechanism as today's capture
   mirroring, extended to all engine output.
5. **LIG — stays app-side, standalone** (its own ephemeral Map-Request socket, independent of
   the xTR's registered socket; works VPN on/off). NAT-reply nuance: if reply-routing behind
   a NAT needs the NE's translated control port, LIG becomes a command to the NE — start
   standalone.
6. **Ping tab — stays in the app UI, but injects to the NE over loopback (41342) and reads
   replies (41343), the SAME mechanism as the PING app** (with the VPN on; the registered data
   socket lives in the NE). So the built-in Ping tab is an overlay client — user pings from
   inside the LISP app, no need to launch PING. KEEP BOTH the built-in Ping tab and the
   standalone PING app. VPN-off: Ping tab falls back to the in-app engine. Detail to settle:
   Ping tab + PING app sharing reply port 41343 (match by ICMP id, or give the tab its own
   reply port).
