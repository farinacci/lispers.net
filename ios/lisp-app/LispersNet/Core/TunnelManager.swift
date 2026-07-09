//
// TunnelManager.swift
//
// Installs and drives the LispTunnel packet-tunnel-provider via NETunnelProviderManager:
// create/enable the VPN profile (one-time "Allow VPN" prompt), start/stop it, and
// publish status for the UI. Writes the EID into the App Group first so the provider
// uses it as the utun address.
//

import Foundation
import NetworkExtension
import Combine

@MainActor
final class TunnelManager: ObservableObject {
    static let appGroup = "group.net.lispers.xtr"
    static let providerBundleID = "net.lispers.xtr.LispTunnel"

    @Published var status: NEVPNStatus = .invalid
    @Published var lastError: String?

    // The overlay tunnel is OPT-IN: it's required only to run overlay apps (PING,
    // gaapchat), NOT for the xTR itself. We ask ONCE (when LISP starts) and remember the
    // answer — never auto-prompt on every foreground (that looped forever on denial).
    enum OverlayChoice: String { case unset, enabled, declined }
    private let choiceKey = "overlayTunnelChoice"
    @Published var choice: OverlayChoice = .unset {
        didSet { UserDefaults.standard.set(choice.rawValue, forKey: choiceKey) }
    }

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    // Mirror the provider's capture file into lisp-itr.log while the tunnel is up.
    private var mirrorTask: Task<Void, Never>?
    private var lastMirroredSeq = 0
    private var utunName = "utun"

    var isActive: Bool { status == .connected || status == .connecting || status == .reasserting }
    var statusText: String {
        switch status {
        case .invalid:      return "not installed"
        case .disconnected: return "off"
        case .connecting:   return "connecting…"
        case .connected:    return "on"
        case .reasserting:  return "reasserting…"
        case .disconnecting:return "disconnecting…"
        @unknown default:   return "unknown"
        }
    }

    init() {
        if let raw = UserDefaults.standard.string(forKey: choiceKey),
           let c = OverlayChoice(rawValue: raw) { choice = c }
        Task { await load() }
    }

    // Load an existing profile if one is installed.
    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            if let m = managers.first { manager = m; observe(m) }
        } catch { lastError = error.localizedDescription }
    }

    // Create/enable the profile if needed, then start the tunnel. The EID goes into the
    // App Group so the provider can set the utun's address.
    func start(eid: String, instanceID: Int) async {
        let d = UserDefaults(suiteName: Self.appGroup)
        d?.set(eid, forKey: "tunnelEID")
        d?.set(instanceID, forKey: "tunnelIID")
        do {
            let m = manager ?? NETunnelProviderManager()
            let proto = (m.protocolConfiguration as? NETunnelProviderProtocol)
                ?? NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerBundleID
            proto.serverAddress = "LISP overlay"
            m.protocolConfiguration = proto
            m.localizedDescription = "LISP Overlay Tunnel"
            m.isEnabled = true
            try await m.saveToPreferences()
            try await m.loadFromPreferences()      // reload so connection is valid
            manager = m
            observe(m)
            try m.connection.startVPNTunnel()
        } catch {
            lastError = error.localizedDescription
            // iOS "Allow VPN Configurations" was denied (or a config error). Record the
            // decline so foregrounding never re-prompts in a loop — the user can turn it
            // back on from the xTR tab.
            choice = .declined
        }
    }

    func stop() { manager?.connection.stopVPNTunnel() }

    // User opted IN (via the launch prompt or the xTR-tab toggle): remember it and start.
    // This is the only path that triggers the one-time "Allow VPN" prompt.
    func enableOverlay(eid: String, instanceID: Int) async {
        choice = .enabled
        await start(eid: eid, instanceID: instanceID)
    }

    // User opted OUT: remember it and tear the tunnel down. The xTR keeps running.
    func disableOverlay() {
        choice = .declined
        stop()
    }

    // Reconnect an already-opted-in tunnel if it dropped (called on foreground ONLY when
    // choice == .enabled). Permission is already granted, so this never prompts.
    func ensureUp(eid: String, instanceID: Int) async {
        guard choice == .enabled else { return }
        if manager == nil { await load() }
        if isActive { return }
        await start(eid: eid, instanceID: instanceID)
    }

    private func observe(_ m: NETunnelProviderManager) {
        if let o = observer { NotificationCenter.default.removeObserver(o) }
        status = m.connection.status
        updateMirroring()
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: m.connection, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.status = m.connection.status
                self?.updateMirroring()
            }
        }
    }

    // MARK: - mirror the provider's captures into lisp-itr.log

    private func updateMirroring() {
        if isActive {
            if mirrorTask == nil { startMirroring() }
        } else {
            mirrorTask?.cancel(); mirrorTask = nil
        }
    }

    // Parse the "<seq>\t…" prefix the provider stamps on every capture-file line.
    private static func seq(of line: String) -> Int? {
        guard let tab = line.firstIndex(of: "\t") else { return nil }
        return Int(line[..<tab])
    }

    private func startMirroring() {
        // Baseline = the highest seq ALREADY in the capture file, read from the FILE
        // itself (cross-process UserDefaults isn't reliably visible to the app), so we
        // mirror only packets captured from here on and never skip new ones.
        // Baseline = highest seq already in the capture file (read from the FILE;
        // cross-process UserDefaults isn't reliably visible), so we mirror only NEW
        // captures from here on.
        lastMirroredSeq = OverlayTunnel.readCapture().compactMap(Self.seq).max() ?? 0
        utunName = OverlayTunnel.findUtun()?.name ?? "utun"
        LispLog.shared.fprint(.itr,
            "=== overlay tunnel up on \(utunName): capturing 240.0.0.0/4 ===")
        mirrorTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                self?.mirrorNewCaptures()
                try? await Task.sleep(nanoseconds: 700_000_000)   // poll ~1.4×/sec
            }
        }
    }

    // Read the shared capture file and echo each NEW "<seq>\t<line>" into lisp-itr.log
    // so a tunnel-interface receive shows up in the Logs tab next to the
    // RLOC-probes/registers, e.g. "Receive utun5, UDP 240.0.0.254 -> 240.10.0.1 len 60".
    private func mirrorNewCaptures() {
        for line in OverlayTunnel.readCapture() {
            guard let seq = Self.seq(of: line), seq > lastMirroredSeq,
                  let tab = line.firstIndex(of: "\t") else { continue }
            lastMirroredSeq = seq
            let body = String(line[line.index(after: tab)...])
            if body.hasPrefix("===") {
                LispLog.shared.fprint(.itr, body)          // provider up/stopped banners
            } else {
                LispLog.shared.dprint(.itr, body)          // "Received utun …" — data-plane, like the Encap lines
            }
        }
    }
}
