//
// XTRCoordinator.swift  (app target only)
//
// Decides WHO runs the xTR, based on the two switches:
//   • Enable LISP      (config.lispEnabled) — master on/off
//   • Overlay App VPN  (tunnel.choice == .enabled) — run the xTR in the always-on
//                        LispTunnel extension (Option B) instead of in the app
//
//   Overlay VPN ON  → the extension is the xTR; the app releases its sockets and MIRRORS
//                     the extension's live state (map-cache/status/logs) for display.
//   Overlay VPN OFF → the app is the xTR (dual-mode, the original in-app behavior).
//
// This guarantees exactly one process binds the LISP sockets (4342 / 41341) at a time.
// Call reconcile() whenever either switch changes, and on launch/foreground.
//

import Foundation

@MainActor
enum XTRCoordinator {
    static func reconcile(engine: LispEngine, config: LispConfig, tunnel: TunnelManager) {
        let eid = config.eidString.isEmpty ? "240.0.0.1" : config.eidString
        let overlayOn = tunnel.choice == .enabled

        if config.lispEnabled && overlayOn {
            // The extension owns the xTR. Release any app-held sockets first (so the
            // extension can bind them), then mirror its state and make sure the VPN is up.
            if engine.running && !engine.isMirroring { engine.disable() }
            engine.startStateMirror()
            Task { await tunnel.ensureUp(eid: eid, instanceID: config.instanceID) }
            return
        }

        // App is the xTR (or nothing is) — the extension must not be running.
        engine.stopStateMirror()
        let wasActive = tunnel.isActive
        if wasActive { tunnel.stop() }

        if config.lispEnabled {
            if wasActive {
                // The VPN was up; the extension needs a moment to release 4342/41341 before
                // the app can rebind them. enable() bails (running stays false) if the bind
                // fails, so RETRY until it takes — a fixed delay could lose the race and
                // leave the app-xTR down, which is exactly when Direct ping/LIG would fail.
                retryEnable(engine, attemptsLeft: 8, delay: 0.6)
            } else if !engine.running {
                engine.enable()
            }
        } else if engine.running && !engine.isMirroring {
            engine.disable()
        }
    }

    // Attempt engine.enable() and, if the sockets didn't bind yet (running still false),
    // try again shortly — up to attemptsLeft times.
    private static func retryEnable(_ engine: LispEngine, attemptsLeft: Int, delay: Double) {
        guard !engine.running, !engine.isMirroring, attemptsLeft > 0 else { return }
        engine.enable()
        if !engine.running {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                retryEnable(engine, attemptsLeft: attemptsLeft - 1, delay: delay)
            }
        }
    }
}
