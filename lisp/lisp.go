//
// lisp.go
//
// This file contains function and type definitions used by xtr.go and ipc.go.
//
// This is a external data-plane from the lispers.net control-plane perspective
// and must be run with "lisp xtr-parameters" sub-command "ipc-data-plane =
// yes".
//
package main

import "fmt"
import "bufio"
import "os"
import "os/exec"
import "strings"
import "strconv"
import "time"
import "net"

//
// ---------- Variable Definitions ----------
//
var lisp_debug_logging      bool = true
var lisp_data_plane_logging bool = false

//
// ---------- Constants Definitions ----------
//
const LISP_DATA_PORT       = 4341
const LISP_CTRL_PORT       = 4342
const LISP_L2_DATA_PORT    = 8472
const LISP_VXLAN_DATA_PORT = 4789
const LISP_VXLAN_GPE_PORT  = 4790

//
// ---------- Type Definitions ----------
//
type Lisp_address struct {
	instance_id        int
	mask_len           int
	address            net.IP
	mask_address       net.IPMask
	address_string     string
}

//
// lisp_print_address
//
// Return string with address. And optionally prepend "[<iid>]"
//
func (a *Lisp_address) lisp_print_address(with_iid bool) string {
	if (with_iid) {
		iid := a.instance_id
		if (iid == 0xffffff) { iid = -1 }
		return(fmt.Sprintf("[%d]%s", iid, a.address_string))
	}
	return(a.address_string)
}

//
// lisp_store_address
//
// Store and instance-ID and string representation of an IPv4 or IPv6 address
// and store in Lisp_address format.
//
func (a *Lisp_address) lisp_store_address(iid int, addr string) bool {
	var address string

	//
	// Is this address string an address or a prefix?
	//
	if (strings.Contains(addr, "/")) {
		split := strings.Split(addr, "/")
		address = split[0]
		a.mask_len, _ = strconv.Atoi(split[1])
	} else {
		address = addr
		a.mask_len = -1
	}
	a.instance_id = iid

	//
	// Parse address string. ParseIP() will put IPv4 addresses in a 16-byte
	// array. We don't want that because address []byte length will determine
	// address family.
	//
	a.address = net.ParseIP(address)
	if (strings.Contains(addr, ".")) {
		a.address = a.address[12:16]
	}

	//
	// Set mask-length and mask address.
	//
	if (a.mask_len == -1) {
		a.mask_len = len(a.address) * 8
	}
	a.mask_address = net.CIDRMask(a.mask_len, len(a.address) * 8)

	//
	// Store string for printing.
	//
	a.address_string = addr
	return(true)
}

//
// lisp_is_ipv4
//
// Return true if Lisp_address is IPv4.
//
func (a *Lisp_address) lisp_is_ipv4() bool {
	return((len(a.address) == 4))
}

//
// lisp_is_ipv6
//
// Return true if Lisp_address is IPv6.
//
func (a *Lisp_address) lisp_is_ipv6() bool {
	return((len(a.address) == 16))
}

//
// lisp_is_multicst
//
// Return true if Lisp_address is an IPv4 or IPv6 multicast group address.
//
func (a *Lisp_address) lisp_is_multicast() bool {
	if (a.lisp_is_ipv4()) {
		return(int(a.address[0]) >= 224 && int(a.address[0]) < 240)
	}
	if (a.lisp_is_ipv6()) {
		return(a.address[0] == 0xff)
	}
	return(false)
}

//
// lisp_make_address
//
// Store and instance-ID and byte representation of an IPv4 or IPv6 address
// and store in Lisp_address format.
// 
func (a *Lisp_address) lisp_make_address(iid int, addr []byte) {
	a.instance_id = iid
	a.address = addr
	a.mask_len = len(a.address) * 8
	a.mask_address = net.CIDRMask(a.mask_len, len(a.address) * 8)
	a.address_string = a.address.String()
}

//
// lisp_exact_match
//
// Compare two addresses and return true if they match.
//
func (a *Lisp_address) lisp_exact_match(addr Lisp_address) (bool) {
	if (len(a.address) != len(addr.address)) {
		return(false)
	}
	if (a.mask_len != addr.mask_len) {
		return(false)
	}
	if (a.instance_id != addr.instance_id) {
		return(false)
	}
	if (a.address.Equal(addr.address) == false) {
		return(false)
	}
	return(true)
}

//
// lisp_more_specific
//
// Return true if the supplied address is more specific than the method
// address. If the mask-lengths are the same, a true is returned.
//
func (a *Lisp_address) lisp_more_specific(addr Lisp_address) (bool) {
	if (len(a.address) != len(addr.address)) {
		return(false)
	}
	if (a.instance_id != addr.instance_id) {
		return(false)
	}
	if (a.mask_len > addr.mask_len) {
		return(false)
	}
	for i := 0; i < len(a.address); i++ {
		if (a.mask_address[i] == 0) {
			break
		}
		if ((a.address[i] & a.mask_address[i]) !=
			(addr.address[i] & a.mask_address[i])) {
			return(false)
		}
	}
	return(true)
}

//
// lisp_hash_address
//
// Hash address to aid in selecting a source UDP port.
//
func (a *Lisp_address) lisp_hash_address() uint16 {
	var hash uint = 0

	for i := 0; i < len(a.address); i++ {
		hash = hash ^ uint(a.address[i])
	}

	//
	// Fold result into a short.
	//
	return(uint16(hash >> 16) ^ uint16(hash & 0xffff))
}

type Lisp_database struct {
	eid_prefix Lisp_address
}
type Lisp_interface struct {
	instance_id    int
}
type Lisp_map_cache struct {
	next_mc    *Lisp_map_cache
	eid_prefix Lisp_address
	rloc_set   []Lisp_rloc
	rle_set    []Lisp_rloc
}
type Lisp_rloc struct {
	rloc                  Lisp_address
	encap_port            int
	encrypt_key           string
	icv_key               string
	packets               uint
	bytes                 uint
	last_packet           time.Time
}

//
// lprint
//
// Print control-plane debug logging output when configured.
//
func lprint(format string, args ...interface{}) {
	if (!lisp_debug_logging) {
		return
	}

	ts := time.Now()
	ms := ts.Nanosecond() / 1000000
	ds := fmt.Sprintf("%02d/%02d/%02d %02d:%02d:%02d.%03d", ts.Month(),
		ts.Day(), ts.Year(), ts.Hour(), ts.Minute(), ts.Second(), ms)
	f := ds + ": xtr: " + format + "\n"
	fmt.Printf(f, args...)
}

//
// dprint
//
// Print data-plane debug logging output when configured.
//
func dprint(format string, args ...interface{}) {
	if (!lisp_data_plane_logging) {
		return
	}

	ts := time.Now()
	ms := ts.Nanosecond() / 1000000
	ds := fmt.Sprintf("%02d/%02d/%02d %02d:%02d:%02d.%03d", ts.Month(),
		ts.Day(), ts.Year(), ts.Hour(), ts.Minute(), ts.Second(), ms)
	f := ds + ": xtr: " + format + "\n"
	fmt.Printf(f, args...)
}

//
// debug
//
// For temporary debug output that highlights line in boldface red.
//
func debug(format string, args ...interface{}) {
	f := red(">>>") + format + red("<<<") + "\n"
	fmt.Printf(f, args...)
}

//
// debugv
//
// For temporary debug output that shows the contents of a data structure.
// Very useful for debugging.
//
func debugv(args interface{}) {
	debug("%#v", args)
}

//
// lisp_command_output
//
// Execute a system command and return a string with output.
//
func lisp_command_output(command string) string {
	cmd := exec.Command(command)
	out, err := cmd.CombinedOutput()
	if (err != nil) {
		return("")
	}
	output := string(out)
	return(output[0:len(output)-1])
}

//
// lisp_read_file
//
// Read entire file into a string.
//
func lisp_read_file(filename string) string {
	fd, err := os.Open(filename)
	if (err != nil) {
		return("")
	}
	scanner := bufio.NewScanner(fd)
	scanner.Scan()
	fd.Close()
	return(scanner.Text())
}

//
// lisp_write_file
//
// Write supplied string to supplied file.
//
func lisp_write_file(filename string, text string) {
	fd, err := os.Create(filename)
	if (err != nil) {
		lprint("Could not create file %s", filename)
		return
	}
	_, err = fd.WriteString(text)
	if (err != nil) {
		lprint("Could not write string to file %s", filename)
		return
	}
	fd.Close()
}

//
// bold
//
// Make input string boldface.
//
func bold(str string) string {
    return("\033[1m" + str + "\033[0m")
}

//
// green
//
// Make input string green.
//
func green(str string) string {
    return("\033[92m" + bold(str) + "\033[0m")
}

//
// red
//
// Make input string red.
//
func red(str string) string {
    return("\033[91m" + bold(str) + "\033[0m")
}

//
// lisp_log_packet
//
// Log a received data packet either native or LISP encapsulated.
//
func lisp_log_packet(prefix_string string, packet []byte, is_lisp bool) {
	var num       int
	var udp, lisp []byte

	if (!lisp_data_plane_logging) {
		return
	}

	ip := true
	if (packet[0] == 0x45) {
		num = 20
	} else if (packet[0] == 0x60) {
		num = 40
	} else {
		num = 8
		if (packet[8] == 0x45) { num += 20 }
		if (packet[8] == 0x60) { num += 40 }
		ip = false
	}
	udp = packet[num:num+8]
	lisp = packet[num+8:num+16]

	packet_string := fmt.Sprintf("%s: ", prefix_string)
	p := packet
	for i := 0; i < num; i += 4 {
		packet_string += fmt.Sprintf("%02x%02x%02x%02x ", p[i], p[i+1],
			p[i+2], p[i+3])
	}

	//
	// Return for invalid packet.
	//
	if (ip == false) {
		dprint(packet_string)
		return
	}

	if (!is_lisp) {
		dprint(packet_string)
		return
	}

	packet_string += fmt.Sprintf("UDP: ")
	for i := 0; i < 8; i += 4 {
		packet_string += fmt.Sprintf("%02x%02x%02x%02x ", udp[i], udp[i+1],
			udp[i+2], udp[i+3])
	}
	packet_string += fmt.Sprintf("LISP: ")
	for i := 0; i < 8; i += 4 {
		packet_string += fmt.Sprintf("%02x%02x%02x%02x ", lisp[i], lisp[i+1],
			lisp[i+2], lisp[i+3])
	}
	dprint(packet_string)
}

//
// lisp_get_local_address
//
// Given supplied interface, return locaal IPv4 and IPv6 addresses.
//
func lisp_get_local_address(device string) (string, string) {
	var ipv4 string = ""
	var ipv6 string = ""

	intf, _ := net.InterfaceByName(device)
	addrs, _ := intf.Addrs()

	for _, a := range addrs {
		addr := strings.Split(a.String(), "/")[0]
		if (addr == "::1") { continue }
		if (strings.Contains(addr, "fe80")) { continue }
		if (strings.Contains(addr, "127.0.0.1")) { continue }
		if (strings.Contains(addr, ":")) { ipv6 = addr }
		if (strings.Count(addr, ".") == 3) { ipv4 = addr }
	}
	return ipv4, ipv6
}

//-----------------------------------------------------------------------------
