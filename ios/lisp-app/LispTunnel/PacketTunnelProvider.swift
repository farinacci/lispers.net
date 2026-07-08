//
// PacketTunnelProvider.swift  (LispTunnel extension)
//
// The overlay packet tunnel. Brings up a utun that routes 240.0.0.0/4 (all overlay
// EIDs) — captures the LISP packets a separate overlay app (e.g. PING) injects, and
// hands them to the LISP app. (No 224.240/12 route: overlay apps can't send raw
// multicast on iOS, so multicast rides as the INNER of a unicast-to-tunnel-EID packet —
// nothing ever routes in by a multicast group address, so the route was unused.)
//
// An overlay app can't send raw multicast on iOS (blocked) or IP-in-IP (no raw
// sockets), so it sends its inner IP packet UNICAST to the tunnel's own EID on 4341:
//   IP[src=EID → dst=tunnelEID]/UDP 4341/[inner IP].
// The local hop needs no LISP header (the LISP app knows its own instance-id), so we
// strip the outer IP+UDP and hand the raw [inner] to the app over loopback
// (127.0.0.1:overlayInjectPort). The app's data plane does the map-cache lookup + encap
// — so the "Receive utun, inner EIDs …" and "Encap outer RLOCs: …" log lines and the
// map-cache counters are the real ones, and the encap egresses on the app's registered
// data socket (so replies come back). This works while the app is foreground; PING's
// keep-alive lets it keep sending during the switch. (Full-background = future Option B.)
//

import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider {
    static let appGroup = "group.net.lispers.xtr"
    static let injectPort: UInt16 = 4341        // overlay apps inject LISP packets here (on the utun)
    static let appLoopbackPort: UInt16 = 41342  // where we hand packets to the app (LISP.overlayInjectPort)
    private let log = Logger(subsystem: "net.lispers.xtr.LispTunnel", category: "tunnel")

    private var tunnelEIDBytes: [UInt8] = [240, 0, 0, 1]
    private var fwdFD: Int32 = -1               // reused loopback socket to the app

    private var captureURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: Self.appGroup)?
            .appendingPathComponent("tunnel-capture.log")
    }

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        let d = UserDefaults(suiteName: Self.appGroup)
        let eid = d?.string(forKey: "tunnelEID") ?? "240.0.0.1"
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
            self.append("=== tunnel up, EID \(eid), routing 240/4 ===")
            self.log.log("tunnel up, EID \(eid, privacy: .public)")
            self.readLoop()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        if fwdFD >= 0 { close(fwdFD); fwdFD = -1 }
        append("=== tunnel stopped (reason \(reason.rawValue)) ===")
        completionHandler()
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

    // An overlay-injected packet (UDP to our tunnel EID on 4341): strip outer IP+UDP and
    // hand the raw [inner] to the app over loopback (silently — the app logs the
    // "Receive utun, inner EIDs …" line). The app does the map-cache lookup + encap.
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
        forwardToApp(payload)
    }

    private func forwardToApp(_ pkt: Data) {
        if fwdFD < 0 { fwdFD = socket(AF_INET, SOCK_DGRAM, 0) }
        guard fwdFD >= 0 else { return }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = Self.appLoopbackPort.bigEndian
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
    // the app mirrors new lines into lisp-itr.log. (Only used for the up/down banners.)
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
