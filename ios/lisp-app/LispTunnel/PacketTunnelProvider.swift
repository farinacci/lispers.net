//
// PacketTunnelProvider.swift  (LispTunnel extension)
//
// Option B: the ALWAYS-ON xTR. When the Overlay App VPN is enabled, iOS keeps this
// packet-tunnel provider running as its own process — so the phone stays a registered,
// pingable xTR even when the LISP app is backgrounded or closed. This provider now HOSTS
// the full LispEngine (registration, Info-Requests/NAT, RLOC-probing, the data + control
// sockets, encap/decap) — the registered RLOC:port is THIS process's data-socket NAT
// mapping, which is what makes the phone reachable when the app isn't running.
//
// It also keeps a minimal utun up (routing 240.0.0.0/4, all overlay EIDs) purely as the
// vehicle iOS uses to keep this process alive and to capture packets a separate overlay
// app (PING, gaapchat) injects. An overlay app can't send raw multicast or IP-in-IP on
// iOS, so it sends its inner IP packet UNICAST to the tunnel EID on 4341:
//   IP[src=EID → dst=tunnelEID]/UDP 4341/[inner IP].
// We strip the outer IP+UDP and hand the raw [inner] to the in-process engine over
// loopback (127.0.0.1:overlayInjectPort) — the engine's data plane does the map-cache
// lookup + encap and egresses on its own registered data socket, so replies come back to
// THIS process and are forwarded to the overlay app (127.0.0.1:pingReplyPort).
//
// While the app is the xTR (VPN-off, dual-mode) this extension isn't running at all; mode
// coordination in the app guarantees only one engine binds the sockets at a time.
//

import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider {
    static let appGroup = "group.net.lispers.xtr"
    static let injectPort: UInt16 = 4341        // overlay apps inject LISP packets here (on the utun)
    private let log = Logger(subsystem: "net.lispers.xtr.LispTunnel", category: "tunnel")

    private var tunnelEIDBytes: [UInt8] = [240, 0, 0, 1]
    private var fwdFD: Int32 = -1               // reused loopback socket to the in-process engine

    // The hosted xTR. Held for the provider's lifetime; created on startTunnel, torn
    // down on stopTunnel. Config is read from the shared App-Group file (LispConfig).
    private var config: LispConfig?
    private var engine: LispEngine?

    private var captureURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: Self.appGroup)?
            .appendingPathComponent("tunnel-capture.log")
    }

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        // Build the engine + config on the main queue so the engine's repeating
        // Timers schedule on (and fire from) the extension's main run loop.
        let cfg = LispConfig()
        self.config = cfg
        let eid = cfg.eidString.isEmpty ? "240.0.0.1" : cfg.eidString
        tunnelEIDBytes = Self.parseOctets(eid) ?? [240, 0, 0, 1]

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "240.0.0.0")
        let ipv4 = NEIPv4Settings(addresses: [eid], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [
            NEIPv4Route(destinationAddress: "240.0.0.0", subnetMask: "240.0.0.0"),      // 240.0.0.0/4
        ]
        settings.ipv4Settings = ipv4
        settings.mtu = 1400

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.log.error("setTunnelNetworkSettings failed: \(error.localizedDescription)")
                completionHandler(error); return
            }
            self.append("=== tunnel up, EID \(eid) — hosting xTR, routing 240/4 ===")
            self.log.log("tunnel up, EID \(eid, privacy: .public) — starting hosted xTR")
            // Start the xTR engine on the main queue (run-loop timers) and begin
            // capturing overlay-injected packets off the utun.
            DispatchQueue.main.async {
                let engine = LispEngine(config: cfg)
                self.engine = engine
                if cfg.lispEnabled { engine.enable() }
                self.readLoop()
                completionHandler(nil)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        DispatchQueue.main.async { [weak self] in
            self?.engine?.disable()
            self?.engine = nil
            if let fd = self?.fwdFD, fd >= 0 { close(fd); self?.fwdFD = -1 }
            self?.append("=== tunnel stopped (reason \(reason.rawValue)) ===")
            completionHandler()
        }
    }

    private func readLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            for (i, pkt) in packets.enumerated() where protocols[i].int32Value == AF_INET {
                self.handleInjected(pkt)
            }
            self.readLoop()   // re-arm
        }
    }

    // An overlay-injected packet (UDP to our tunnel EID on 4341): strip the outer IP+UDP
    // and hand the raw [inner] to the in-process engine over loopback. The engine logs the
    // "Receive utun, inner EIDs …" line and does the map-cache lookup + encap.
    private func handleInjected(_ p: Data) {
        let b = p.startIndex
        guard p.count >= 28, (p[b] >> 4) == 4 else { return }
        let ihl = Int(p[b] & 0x0F) * 4
        guard ihl >= 20, p.count >= ihl + 8, p[b + 9] == 17 else { return }   // UDP
        guard p[b+16] == tunnelEIDBytes[0], p[b+17] == tunnelEIDBytes[1],
              p[b+18] == tunnelEIDBytes[2], p[b+19] == tunnelEIDBytes[3] else { return }
        let dport = (UInt16(p[b+ihl+2]) << 8) | UInt16(p[b+ihl+3])
        guard dport == Self.injectPort else { return }

        let payload = p.subdata(in: (b + ihl + 8)..<p.endIndex)  // raw [inner IP]
        guard payload.count >= 20 else { return }
        forwardToEngine(payload)
    }

    // Hand the raw inner packet to the in-process engine's overlay-inject socket
    // (127.0.0.1:overlayInjectPort). Same-process loopback — the engine's receive
    // handler dispatches it onto overlayQueue for encap.
    private func forwardToEngine(_ pkt: Data) {
        if fwdFD < 0 { fwdFD = socket(AF_INET, SOCK_DGRAM, 0) }
        guard fwdFD >= 0 else { return }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = LISP.overlayInjectPort.bigEndian
        addr.sin_addr.s_addr = UInt32(0x7f00_0001).bigEndian     // 127.0.0.1
        _ = pkt.withUnsafeBytes { raw in
            withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(fwdFD, raw.baseAddress, raw.count, 0, sa,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }

    private static func parseOctets(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var out: [UInt8] = []
        for p in parts { guard let v = UInt8(p) else { return nil }; out.append(v) }
        return out
    }

    // Append a "<seq>\t<line>" record to the shared capture file (bounded ~200 lines);
    // used only for the up/down banners now (the engine writes real logs to the shared
    // App-Group logs dir, which the app's Logs tab reads directly).
    private func append(_ line: String) {
        guard let url = captureURL else { return }
        let d = UserDefaults(suiteName: Self.appGroup)
        let seq = (d?.integer(forKey: "tunnelRxSeq") ?? 0) + 1
        d?.set(seq, forKey: "tunnelRxSeq")
        let entry = "\(seq)\t\(line)"
        if let existing = try? String(contentsOf: url, encoding: .utf8) {
            var lines = existing.split(separator: "\n", omittingEmptySubsequences: false)
                .map(String.init)
            lines.append(entry)
            if lines.count > 200 { lines.removeFirst(lines.count - 200) }
            try? lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        } else {
            try? (entry + "\n").write(to: url, atomically: true, encoding: .utf8)
        }
    }
}
