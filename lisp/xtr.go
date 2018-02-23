//
// xtr.go
//
// This file contains LISP ITR, RTR< and ETR functions that can encapsulate and
// decapsulate packets faster than the python code lisp-itr.py, lisp-etr.py,
// and lisp-rtr.py.
//
// This is a external data-plane from the lispers.net control-plane perspective
// and must be run with "lisp xtr-parameters" sub-command "ipc-data-plane =
// yes".
//
// Todo list:
// (1) Do lisp-crytpo.
// (2) Make sure we add encap-port for both NAT-traversal and lisp-crypto.
// (3) Look at alternative to gopacket.NewPacketSource(). Gopi says use
//     static buffer. GC will kill you.
// (4) Fix decap forwarding for IPv6 EIDs. Test IPv6 RLOCs.
//
package main

import "fmt"
import "os"
import "strings"
import "strconv"
import "syscall"
import "time"
import "net"
import "math/rand"
import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"

//
// ---------- Global Variables ----------
//
var lisp_rtr = true
var lisp_rtr_only = false
var lisp_encap_socket [2]int
var lisp_decap_socket *net.UDPConn

//
// Prebuild LISP and UDP headers. And IPv4 and IPv6 outer headers.
//
var	lisp_header      []byte
var	lisp_udp_header  []byte
var	lisp_ipv4_header []byte
var	lisp_ipv6_header []byte

//
// main
//
// Main entry point for xtr.go that runs in binary file lisp-xtr.
//
func main() {
	if (!lisp_xtr_startup()) {
		return
	}

	//
	// Run thread to process IPC messages from the lispers.net control-plane.
	//
	lisp_ipc_message_processing()

	//
	// If we return, return resources.
	//
	lisp_xtr_shutdown()
}

//
// lisp_xtr_startup
//
// Initialize the process and start forwarding threads. Run thread to listen
// for IPC messages from the lispers.net python code.
//
func lisp_xtr_startup() bool {
	hostname, _ := os.Hostname()
	hostname = strings.Split(hostname, ".")[0]
	ts := lisp_command_output("date")
	version := lisp_read_file("./lisp-version.txt")
	
    lprint("lispers.net LISP xTR starting up %s, version %s, hostname %s", ts,
		version, bold(hostname))

	//
	// Initialize pre-built headers.
	//
	lisp_build_headers()

	//
	// Create named socket "lispets.net-itr" to punt packets to the lispers.net
	// python control-plane.
	//
	if (!lisp_create_punt_socket()) {
		lprint("lisp_create_punt_socket() failed")
		return(false)
	}

	//
	// Create raw socket for sending encapsulated packets.
	//
	if (!lisp_create_encap_socket()) {
		lprint("lisp_create_encap_socket() failed")
		return(false)
	}

	//
	// Create UDP socket for receiving IPv4 encapsulated LISP packets. For
	// IPv6 encapsulated packets use pcap.
	//
	if (!lisp_create_decap_socket()) {
		lprint("lisp_create_decap_socket() failed")
		return(false)
	}
	lisp_create_decap_ipv6_capture()

	//
	// Start stats thread.
	//
	go lisp_stats_thread()
	return(true)
}

//
// lisp_build_headers
//
// Initialize pre-built headers used in lisp_encapsulate().
//
func lisp_build_headers() {
	
	//
	// Prebuild LISP and UDP headers. And IPv4 and IPv6 outer headers.
	//
	lisp_header      = []byte{ 0x88, 0, 0, 0, 0, 0, 0, 0 }
	lisp_udp_header  = []byte{ 0,0, 0x10,0xf5, 0,8, 0,0 }
	lisp_ipv4_header = []byte{ 0x45, 0, 0,0, 0,0, 0x40,0, 32, 17, 0,0,
		0,0,0,0, 0,0,0,0 }

	//
	// IPv6 header will be 8 bytes plus an appended local source RLOC. And then
	// in lisp_encapsulate(), an appended destination RLOC happens.
	//
	lisp_ipv6_header = []byte{ 0x60,0,0,0, 0,0,17,32 }
	source_rloc := lisp_get_ipv6_rloc()
	if (source_rloc == nil) {
		source_rloc = []byte{ 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0 }
	}
	lprint("Using IPv6 source RLOC %s", source_rloc.String())
	lisp_ipv6_header = append(lisp_ipv6_header, source_rloc...)
}

//
// lisp_get_ipv6_rloc
//
// Get the local IPv6 address on the interface with the default route.
//
func lisp_get_ipv6_rloc() net.IP {
	interfaces, _ := net.Interfaces()

	for _, intf := range interfaces {
		if (intf.Name != "eth0") { continue }
		addrs, _ := intf.Addrs()
		for _, addr := range addrs {
			a := addr.String()
			if (!strings.Contains(a, ":")) { continue }
			if (strings.Contains(a, "fe80")) { continue }
			a = strings.Split(a, "/")[0]
			return(net.ParseIP(a))
		}
    }
	return(nil)
}

//
// lisp_xtr_shutdown
//
// Undo what was initialized in lisp_xtr_startup().
//
func lisp_xtr_shutdown() {

	//
	// Close sockets.
	//
	lisp_ipc_socket.Close()
	lisp_punt_socket.Close()

    lprint("lispers.net LISP shutting down")
}

//
// lisp_create_encap_socket
//
// Create raw sockets for IPv4 and IPv6 to be used after a LISP, UDP, and
// outer headers are prepended.
//
func lisp_create_encap_socket() bool {

	//
	// Create IPv4 raw socket.
	//
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW,
		syscall.IPPROTO_RAW)
	if (err != nil) {
		lprint("syscall.Socket() for IPv4 encap socket failed: %s", err)
		return(false)
	}
	lisp_encap_socket[0] = s

	//
	// Create IPv6 raw socket.
	//
	s, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW,
		syscall.IPPROTO_RAW)
	if (err != nil) {
		lprint("syscall.Socket() for IPv6 encap socket failed: %s", err)
		return(false)
	}
	lisp_encap_socket[1] = s
	return(true)
}

//
// lisp_create_decap_nat_capture
//
// Since the kernel will not pass UDP packets with checksum 0 through the
// raw sockets interface, we must pcap them in the ETR.
//
func lisp_create_decap_ipv6_capture() {
	pfilter := "ether proto 0x86dd and dst net 0::/0 and dst port 4341"

	lprint("Capturing LISP packets with IPv6 RLOCs for '%s'", pfilter)
	go lisp_etr_ipv6_thread(pfilter)
}

//
// lisp_create_decap_nat_capture
//
// Packet capture when an RTR encapsulates packets from port 4341 to the
// ephemeral port 'lisp-etr-nat-port' passed in from the lispers.net control-
// plane. We cannot open a socket because the control-plane needs it for
// Info-Replies.
//
func lisp_create_decap_nat_capture() {
	pfilter := fmt.Sprintf("(src port 4341 and dst port %d)",
		lisp_etr_nat_port)

	lprint("Capturing nat-traversal packets for '%s'", pfilter)
	go lisp_etr_nat_thread(pfilter)
}

//
// lisp_create_decap_socket
//
// Create UDP datagram socket and bind to well-known LISP port 4341.
//
func lisp_create_decap_socket() bool {
	udp_addr, err := net.ResolveUDPAddr("udp4", ":4341")
 	if (err != nil) {
 		lprint("net.ResolveUDPAddr() failed: %s", err)
 		return(false)
 	}

 	udp_socket, err := net.ListenUDP("udp4", udp_addr)
 	if (err != nil) {
 		lprint("net.ListenUDP() on port 4341 failed: %s\n", err)
 		return(false)
 	}
	lisp_decap_socket = udp_socket

	//
	// Start ETR thread.
	//
	go lisp_etr_thread()
	return(true)
}

//
// lisp_start_itr_data_plane
//
// Setup ITR capture filters and start thread for each interface we are
// capturing on.
//
func lisp_start_itr_data_plane() {

	//
	// Setup filters based on database-mappings provided by the lispers.net
	// control-plane.
	//
	pfilter := "(ether proto 0x0800 or 0x86dd) and (src net "
	for _, source := range lisp_database {
		pfilter = pfilter + source.eid_prefix.lisp_print_address(false) +
			" or "
	}
	pfilter = pfilter[0:len(pfilter)-4] + ")"

	//
	// Start thread for new interfaces added to lisp_interfaces.
	//
	for device, lisp_if := range lisp_interfaces {
		if (!lisp_if.thread_started) {
			lisp_if.thread_started = true
			go lisp_itr_thread(device, pfilter)
		}
	}
}

//
// lisp_itr_thread
//
// Run thread to packet capture packets and try to encapsulate them.
//
func lisp_itr_thread(device string, pfilter string) {
	handle, _ := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	handle.SetBPFFilter(pfilter)

	lprint("Capturing packets on %s for '%s'", bold(device), pfilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		lisp_itr_data_plane(packet, device)
	}
}

//
// lisp_itr_data_plane
//
// This function receives packet natively from the PF_RING, does a map-cache
// lookup on the destination address and encapsulates to RLOC.
//
// The encapsulation format after the outer header is:
//
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    / |       Source Port = xxxx      |       Dest Port = 4341        |
//  UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    \ |           UDP Length          |        UDP Checksum           |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  L   |N|L|E|V|I|P|K|K|            Nonce/Map-Version                  |
//  I \ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  S / |                 Instance ID/Locator-Status-Bits               |
//  P   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
func lisp_itr_data_plane(go_packet gopacket.Packet, input_device string) {
	var s, d   []byte
	var iid    int
	var ttl    byte
	var source Lisp_address
	var dest   Lisp_address

	//
	// Skip over MAC header and point to network layer header.
	//
	packet := go_packet.Data()[14:]

	lisp_log_packet("Received on " + bold(input_device), packet, false)

	ipv4 := (packet[0] & 0xf0 == 0x40)
	ipv6 := (packet[0] & 0xf0 == 0x60)

	if (ipv4) {
		if (len(packet) < 20) {
			dprint("IPv4 invalid packet length, discard packet")
			return
		}
		if (!lisp_ip_checksum(packet[0:20], true)) {
			dprint("IPv4 header checksum failed, discard packet")
			return
		}
		err := lisp_ttl_check(&packet[8])
		if (err) {
			return
		}
		lisp_ip_checksum(packet[0:20], false)
		s = packet[12:16]
		d = packet[16:20]
		ttl = packet[8]
	} else if (ipv6) {
		if (len(packet) < 40) {
			dprint("IPv6 invalid packet length, discard packet")
			return
		}
		err := lisp_ttl_check(&packet[7])
		if (err) {
			return
		}
		s = packet[8:24]
		d = packet[24:40]
		ttl = packet[7]
	} else {
		dprint("Received non-IP packet, discard packet")
		return
	}

	//
	// Get instance-ID to use from Lisp_interface.
	//
	lisp_int, ok := lisp_interfaces[input_device]
	if (ok) {
		iid = lisp_int.instance_id
	} else {
		iid = 0
	}
	
	//
	// Do a lisp_database lookup on the source to see if its an EID.
	//
	source.lisp_make_address(iid, s)
	err := lisp_get_database(source)
	if (err) {
		dprint("Source %s is not an EID, discard packet",
			source.lisp_print_address(true))
		return
	}
	dest.lisp_make_address(iid, d)

	dprint("Packet EIDs %s -> %s", green(source.lisp_print_address(true)),
		green(dest.lisp_print_address(true)))

	//
	// Do destination map-cache lookup.
	//
	rloc, hash, rles := lisp_map_cache_lookup(source, dest)
	if (rloc == nil && len(rles) == 0) {
		lisp_punt_packet(input_device, source, dest)
		return
	}

	//
	// Increment packet counters, prepend outer headers, and send. Check to
	// see if we are replicating to a set of RLOCs or sending to just one. For
	// multicast replication, since append()s are done in lisp_encapsulate()
	// the packet will be copied so a unique packet will be transmitted.
	//
	for _, rle := range rles {
		rle.packets += 1
		rle.bytes += uint(len(packet))
		rle.last_packet = time.Now()
		lisp_encapsulate("Replicate", packet, dest.instance_id, &rle, ttl,
			hash)
	}
	if (rloc != nil) {
		rloc.packets += 1
		rloc.bytes += uint(len(packet))
		rloc.last_packet = time.Now()
		lisp_encapsulate("Encapsulate", packet, dest.instance_id, rloc, ttl,
			hash)
	}
}

//
// lisp_encapsulate
//
// This function is called from either lisp_itr_data_plane() or lisp_etr_
// data_plane(). If the former, a packet is received natively from an EID
// source and is encapsulated to the RLOC that maps from the destination EID.
// If the later, the packet is decapsulated, and if the destination is found
// in the map-cache, it is re-encapsulated (RTR function). Otherwise, it is
// sent to the kernel to natively forward.
//
func lisp_encapsulate(log string, packet []byte, iid int, rloc *Lisp_rloc,
	ttl byte, hash int) {
	var sa4   syscall.SockaddrInet4
	var sa6   syscall.SockaddrInet6
	var outer []byte
	var err   error

	//
	// Store instance-ID and nonce in LISP header.
	//
 	nonce := rand.Uint32() & 0xffffff
	lisp := lisp_header
	lisp[1] = byte((nonce >> 16) & 0xff)
	lisp[2] = byte((nonce >> 8) & 0xff)
	lisp[3] = byte(nonce & 0xff)
	lisp[4] = byte((iid >> 16) & 0xff)
	lisp[5] = byte((iid >> 8) & 0xff)
	lisp[6] = byte(iid & 0xff)
	packet = append(lisp, packet...)

	//
	// Store values in UDP header.
	//
	udp := lisp_udp_header
	udp[0] = byte((hash >> 8) | 0xf0)
	udp[1] = byte(hash & 0xff)
	udp[2] = byte(rloc.encap_port >> 8)
    udp[3] = byte(rloc.encap_port & 0xff)	
	udp_length := len(packet) + 8
	udp[4] = byte(udp_length >> 8)
	udp[5] = byte(udp_length & 0xff)
	packet = append(udp, packet...)

	//
	// Prepend outer header. Since we are sending on a raw socket, kernel
	// fills in source RLOC address and IPv4 checksum.
	//
	if (rloc.rloc.lisp_is_ipv4()) {
		outer = lisp_ipv4_header
		ip_length := udp_length + 20
		outer[2] = byte(ip_length >> 8)
		outer[3] = byte(ip_length & 0xff)
		outer[8] = ttl
		outer = append(outer[0:16], rloc.rloc.address...)
		packet = append(outer, packet...)

		if (!lisp_ip_checksum(packet[0:20], false)) {
			dprint("Could not calculate IPv4 header checksum")
			return
		}

		dprint("%s to IPv4 RLOC %s, encap-port %d", log,
			red(rloc.rloc.lisp_print_address(false)), rloc.encap_port)

		lisp_log_packet("Encap", packet, true)

		//
		// Send on raw socket.
		//
		copy(sa4.Addr[:], rloc.rloc.address)
		sa4.Port = 0
		err = syscall.Sendto(lisp_encap_socket[0], packet, 0, &sa4)

	} else if (rloc.rloc.lisp_is_ipv6()) {
		outer = lisp_ipv6_header
		outer[4] = byte(udp_length >> 8)
		outer[5] = byte(udp_length & 0xff)
		outer[7] = ttl
		outer = append(outer, rloc.rloc.address...)
		packet = append(outer, packet...)

		dprint("%s to IPv6 RLOC %s, encap-port %d", log,
			red(rloc.rloc.lisp_print_address(false)), rloc.encap_port)

		lisp_log_packet("Encap", packet, true)

		//
		// Send on raw socket.
		//
		copy(sa6.Addr[:], rloc.rloc.address)
		sa6.Port = 0
		err = syscall.Sendto(lisp_encap_socket[1], packet, 0, &sa6)
	} else {
		return
	}

	//
	// Did we get a send error?
	//
	if (err != nil) {
		dprint("syscall.Sendto() to RLOC %s failed: %s", 
			red(rloc.rloc.lisp_print_address(false)), err)
	}
}

//
// lisp_map_cache_lookup
//
// Do a LISP map-cache lookup on the destination EID.
//
func lisp_map_cache_lookup(source Lisp_address,	dest Lisp_address) (*Lisp_rloc,
	int, []Lisp_rloc) {

	mc := lisp_lml_lookup(dest)

	//
	// Map-cache entry not found.
	//
	if (mc == nil) {
		dprint("Map-cache lookup %s for EID %s, punt packet", bold("miss"),
			dest.lisp_print_address(true))
		return nil, 0, []Lisp_rloc{}
	}

	dprint("Map-cache lookup %s %s for EID %s", bold("found"),
        green(mc.eid_prefix.lisp_print_address(true)),
		dest.lisp_print_address(true))
	
	//
	// Map-cache entry has an rle-set.
	//
	if (len(mc.rle_set) != 0) {
		return nil, 0, mc.rle_set
	}

	//
	// Map-cache entry has empty rloc-set.
	//
	rloc_set_len := len(mc.rloc_set)
	if (rloc_set_len == 0) {
		dprint("Map-cache entry has empty rloc-set, punt packet")
		return nil, 0, []Lisp_rloc{}
	}

	//
	// Get specific RLOC from rloc-set by hashing source and dest EIDs.
	//
	hash := int(source.lisp_hash_address() ^ dest.lisp_hash_address())
	index := hash % rloc_set_len
	return &mc.rloc_set[index], hash, []Lisp_rloc{}
}

//
// lisp_etr_thread
//
// Run thread to listen on port 4341 raw socket.
//
func lisp_etr_thread() {
	lprint("Listening on raw socket port 4341")

	buf := make([]byte, 8192)
	for {
 		n, source, err := lisp_decap_socket.ReadFromUDP(buf)
  		if (err != nil) {
 			lprint("RecvFromUDP() failed: %s", err)
  			time.Sleep(100 * time.Millisecond)
  			continue
  		}
 		lisp_etr_data_plane(buf[0:n], source.String())
	}
}

//
// lisp_etr_ipv6_thread
//
// Run thread to capture any LISP encapsulated packets with IPv6 RLOCs. We
// need to get packets this way since the kernel will not pass UDP packets
// with checksum 0 through a raw packet interface.
//
// Note, there is a 2-byte Linux header before the MAC header.
//
func lisp_etr_ipv6_thread(pfilter string) {
	var source net.IP
	
	handle, _ := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	handle.SetBPFFilter(pfilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for gopacket := range packetSource.Packets() {
		packet := gopacket.Data()[16:]

		source = packet[8:24]
		source_rloc := source.String() + ":"
		source_rloc += strconv.Itoa(int(packet[40]) >> 8 + int(packet[41]))
		packet = packet[48:]
		lisp_etr_data_plane(packet, source_rloc)
	}
}

//
// lisp_etr_nat_thread
//
// Run thread to packet capture packts to port lisp_nat_etr_port'. We have
// jump over headers so lisp_etr_data_plane() believes the packet starts
// at the LISP header.
//
// Note, there is a 2-byte Linux header before the MAC header.
//
func lisp_etr_nat_thread(pfilter string) {
	var source net.IP
	
	handle, _ := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	handle.SetBPFFilter(pfilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for gopacket := range packetSource.Packets() {
		packet := gopacket.Data()[16:]

		version := packet[0] & 0xf0
		if (version == 0x40) {
			source = packet[12:16]
			packet = packet[28:]
		} else if (version == 0x60) {
			source = packet[8:24]
			packet = packet[48:]
		}
		source_rloc := source.String() + ":" + "4341"
		lisp_etr_data_plane(packet, source_rloc)
	}
}

//
// lisp_etr_data_plane
//
// Process received LISP encapsulated packet.
//
func lisp_etr_data_plane(packet []byte, source_rloc string) {
	var inner, lisp  []byte
	var source, dest Lisp_address
	var sa4          syscall.SockaddrInet4
	var socket, iid  int
	var ttl          byte

	lisp_log_packet("Decap from " + red(source_rloc), packet, true)

	//
	// Get header pointers. Get instance-ID from LISP header when I-bit is set.
	//
	lisp = packet[0:8]
	inner = packet[8:]
	inner_version := (inner[0] & 0xf0)

	if ((lisp[0] & 0x08) == 0x08) {
		iid = int(lisp[4]) << 16 + int(lisp[5]) << 8 + int(lisp[6])
	} else {
		iid = 0
	}

	//
	// Check TTL before parsing addresses.
	//
	if (inner_version == 0x40) {
		if (!lisp_ip_checksum(inner[0:20], true)) {
			dprint("IPv4 header checksum failed, discard packet")
			return
		}
		err := lisp_ttl_check(&inner[8])
		if (err) {
			return
		}
		lisp_ip_checksum(inner[0:20], false)
		source.lisp_make_address(iid, inner[12:16])
		dest.lisp_make_address(iid, inner[16:20])
		ttl = inner[8]
		socket = 0
	} else if (inner_version == 0x60) {
		err := lisp_ttl_check(&inner[7])
		if (err) {
			return
		}
		source.lisp_make_address(iid, inner[8:24])
		dest.lisp_make_address(iid, inner[24:40])
		ttl = inner[7]
		socket = 1
	} else {
		dprint("Invalid inner IP header version 0x%x", inner_version)
		return
	}

	//
	// Instance-ID of -1 is an encapsulated control message, punt it.
	//
	if (iid == 0xffffff) {
		dprint("Punt data-encapsulated control message")
		lisp_punt_packet("?", source, dest)
		return
	}

	//
	// Do a lisp_database lookup on the destination to see if its an EID. Don't
	// do this for a destination multicast address.
	//
	if (!lisp_rtr_only && !dest.lisp_is_multicast()) {
		err := lisp_get_database(dest)
		if (err) {
			dprint("Destination %s is not a configured EID",
				dest.lisp_print_address(true))
		} else {
			s := green(source.lisp_print_address(true))
			d := green(dest.lisp_print_address(true))
			dprint("Forward packet %s -> %s", s, d)

			copy(sa4.Addr[:], dest.address)
			sa4.Port = 0
			err := syscall.Sendto(lisp_encap_socket[socket], inner, 0, &sa4)
			if (err != nil) {
				dprint("syscall.Sendto() to EID %s failed: %s", d, err)
			}
			return
		}
	}

	//
	// Do the following only if configured as an RTR.
	//
	if (!lisp_rtr) { return }

	dprint("Packet EIDs %s -> %s, RTR processing",
		green(source.lisp_print_address(true)),
		green(dest.lisp_print_address(true)))

	//
	// We are now acting as an RTR, do destination map-cache lookup.
	//
	rloc, hash, rles := lisp_map_cache_lookup(source, dest)
	if (rloc == nil && len(rles) == 0) {
		lisp_punt_packet("?", source, dest)
		return
	}

	//
	// Increment packet counters, prepend outer headers, and send. Check to
	// see if we are replicating to a set of RLOCs or sending to just one. For
	// multicast replication, since append()s are done in lisp_encapsulate()
	// the packet will be copied so a unique packet will be transmitted.
	//
	for _, rle := range rles {
		rle.packets += 1
		rle.bytes += uint(len(packet))
		rle.last_packet = time.Now()
		lisp_encapsulate("Replicate", inner, dest.instance_id, &rle, ttl, hash)
	}
	if (rloc != nil) {
		rloc.packets += 1
		rloc.bytes += uint(len(packet))
		rloc.last_packet = time.Now()
		lisp_encapsulate("Encapsulate", inner, dest.instance_id, rloc, ttl,
			hash)
	}
}

//
// lisp_ttl_check
//
// Check the received packet still has enough TTL to forward packet.
//
func lisp_ttl_check(ttl *byte) bool {
	if (*ttl == 0) {
		dprint("TTL arrived as 0, discard packet")
		return(true)
	}
	*ttl = *ttl - 1
	if (*ttl == 0) {
		dprint("TTL decremented to 0, discard packet")
		return(true)
	}
	return(false)
}

//
// lisp_get_database
//
// See if address matches a database-entry, if so, its an EID. If it is not
// return err true.
//
func lisp_get_database(address Lisp_address) bool {
	for _, lisp_db := range lisp_database {
		if (lisp_db.eid_prefix.lisp_more_specific(address)) {
			return(false)
		}
	}
	return(true)
}

//
// lisp_ip_checksum
//
// Input to this function is 20-bytes in packed form. Calculate IP header
// checksum and place in byte 10 and byte 11 of header when we are computing
// a checksum for an outer header being sent. For checking a received packet,
// the checksum in the header must be non-zero.
//
func lisp_ip_checksum(data []byte, checking bool) bool {
	var checksum, packet_checksum int

	length := len(data)
    if (length < 20) {
        lprint("IPv4 packet too short, length %s", length)
        return(false)
    }

	//
	// If checking the checksum, the header checksum field must be non-zero.
	// If computing the checksum the header checksum field must be zero.
	//
    packet_checksum = int(data[10]) << 8 + int(data[11])
	if (checking && packet_checksum == 0) {
		lprint("IPv4 header checksum field is 0, discard packet")
		return(false)
	}
	if (!checking && packet_checksum != 0) {
		lprint("IPv4 checksum not computed when packet checksum is non-zero")
		return(false)
	}
	checksum = 0
	data[10] = 0
	data[11] = 0

    //
    // Go 2-bytes at a time so we only have to fold carry-over once.
    //
	for i := 0; i < length; i += 2 {
		checksum += int(data[i]) << 8 + int(data[i+1])
	}

    //
    // Add in carry. And take 1's complement.
    //
	carry := checksum >> 16
	checksum = checksum & 0xffff
    checksum += carry
	checksum = ^checksum & 0xffff

    //
    // Pack in 2-byte buffer and insert at bytes 10 and 11.
    //
	if (checking) {
		return((packet_checksum == checksum))
	}
	data[10] = byte(checksum >> 8)
	data[11] = byte(checksum & 0xff)
    return(true)
}

//-----------------------------------------------------------------------------
