//
// Sockets.swift
//
// BSD UDP sockets with explicit local port binding. The data socket binds
// local port 4341 (the decent-NAT requirement and the port the NAT binding
// must be created on); the control socket binds 4342. DispatchSourceRead
// delivers datagrams off the main thread.
//

import Foundation

final class UDPSocket {
    let fd: Int32
    private(set) var localPort: UInt16
    private var source: DispatchSourceRead?
    private let queue: DispatchQueue
    // The interface this socket egresses on (multi-homing); nil = OS default.
    let interfaceName: String?

    // `boundTo` (multi-homing): pin egress to that interface via IP_BOUND_IF and
    // bind to the interface's own source address, so RLOC-probes go out — and
    // replies come back on — that specific interface (Wi-Fi or cellular).
    init?(localPort: UInt16, queue: DispatchQueue, boundTo iface: DiscoveredRLOC? = nil) {
        self.localPort = localPort
        self.queue = queue
        self.interfaceName = iface?.interfaceName
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, socklen_t(MemoryLayout<Int32>.size))
        // Pin egress to a specific interface (Darwin IP_BOUND_IF = 25).
        if let iface = iface, iface.ifIndex != 0 {
            var idx = Int32(iface.ifIndex)
            setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<Int32>.size))
        }
        // Deliver the received IP TTL on each datagram (for RLOC-probe hop
        // counts) and send our control packets at the probe TTL of 64.
        var ttlOn: Int32 = 1
        setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &ttlOn, socklen_t(MemoryLayout<Int32>.size))
        var sendTTL = Int32(LISP.rlocProbeTTL)
        setsockopt(fd, IPPROTO_IP, IP_TTL, &sendTTL, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = localPort.bigEndian
        // Bind to the interface's own source address when multi-homing (lets the
        // per-interface sockets share the fixed port); INADDR_ANY otherwise.
        addr.sin_addr.s_addr = iface.map { $0.address.v4.bigEndian } ?? INADDR_ANY
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { close(fd); return nil }

        // For an ephemeral bind (port 0), read back the OS-assigned local port.
        if localPort == 0 {
            var sn = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            _ = withUnsafeMutablePointer(to: &sn) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(fd, $0, &len)
                }
            }
            self.localPort = UInt16(bigEndian: sn.sin_port)
        }
    }

    func startReceiving(_ handler: @escaping (Data, _ fromAddr: LispAddress, _ fromPort: UInt16, _ ttl: Int) -> Void) {
        let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        src.setEventHandler { [fd] in
            var buf = [UInt8](repeating: 0, count: 9216)
            var control = [UInt8](repeating: 0, count: 64)
            var from = sockaddr_in()
            var ttl = -1
            let n: Int = buf.withUnsafeMutableBytes { bufPtr in
                control.withUnsafeMutableBytes { ctrlPtr in
                    withUnsafeMutablePointer(to: &from) { fromPtr in
                        var iov = iovec(iov_base: bufPtr.baseAddress, iov_len: bufPtr.count)
                        return withUnsafeMutablePointer(to: &iov) { iovPtr in
                            var msg = msghdr()
                            msg.msg_name = UnsafeMutableRawPointer(fromPtr)
                            msg.msg_namelen = socklen_t(MemoryLayout<sockaddr_in>.size)
                            msg.msg_iov = iovPtr
                            msg.msg_iovlen = 1
                            msg.msg_control = ctrlPtr.baseAddress
                            msg.msg_controllen = socklen_t(ctrlPtr.count)
                            let r = recvmsg(fd, &msg, 0)
                            // Parse the first cmsg by hand (Darwin layout:
                            // cmsg_len u32, cmsg_level i32, cmsg_type i32, data).
                            if r > 0 && msg.msg_controllen >= 13 {
                                let level = Int32(ctrlPtr[4]) | Int32(ctrlPtr[5]) << 8 |
                                            Int32(ctrlPtr[6]) << 16 | Int32(ctrlPtr[7]) << 24
                                let type = Int32(ctrlPtr[8]) | Int32(ctrlPtr[9]) << 8 |
                                           Int32(ctrlPtr[10]) << 16 | Int32(ctrlPtr[11]) << 24
                                if level == IPPROTO_IP && (type == IP_RECVTTL || type == IP_TTL) {
                                    ttl = Int(ctrlPtr[12])
                                }
                            }
                            return r
                        }
                    }
                }
            }
            guard n > 0 else { return }
            let host = UInt32(bigEndian: from.sin_addr.s_addr)
            let port = UInt16(bigEndian: from.sin_port)
            handler(Data(buf[0..<n]), LispAddress(v4: host), port, ttl)
        }
        // Close the fd ONLY from the cancel handler, i.e. after the source is fully
        // torn down — never while an event handler may be mid-recvmsg, and exactly
        // once. (A bare close() right after cancel() can race the in-flight handler
        // or double-close an fd iOS already reclaimed → EXC_GUARD.)
        src.setCancelHandler { [fd] in close(fd) }
        src.resume()
        source = src
    }

    @discardableResult
    func send(_ data: Data, to dest: LispAddress, port: UInt16) -> Bool {
        guard dest.isIPv4 else { return false }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = dest.v4.bigEndian
        let sent = data.withUnsafeBytes { raw in
            withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(fd, raw.baseAddress, data.count, 0, sa,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        return sent == data.count
    }

    func shutdown() {
        if let s = source {
            s.cancel()          // cancel handler closes fd after teardown completes
            source = nil
        } else {
            close(fd)           // never started receiving — close directly
        }
    }
}

// Synchronous DNS resolution for map-server dns-names (decent names like
// "7.ms.example.com" change with the EID hash, so resolve at send time and
// cache briefly).
enum DNS {
    private static var cache: [String: (addr: LispAddress, at: Date)] = [:]
    private static let lock = NSLock()

    static func resolve(_ name: String) -> LispAddress? {
        if let direct = LispAddress(string: name) { return direct }
        lock.lock()
        if let hit = cache[name], Date().timeIntervalSince(hit.at) < 60 {
            lock.unlock(); return hit.addr
        }
        lock.unlock()
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(name, nil, &hints, &res) == 0, let info = res else { return nil }
        defer { freeaddrinfo(res) }
        guard let sa = info.pointee.ai_addr else { return nil }
        var sin = sockaddr_in()
        memcpy(&sin, sa, MemoryLayout<sockaddr_in>.size)
        let addr = LispAddress(v4: UInt32(bigEndian: sin.sin_addr.s_addr))
        lock.lock(); cache[name] = (addr, Date()); lock.unlock()
        return addr
    }
}
