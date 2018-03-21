//
// ipc.go
//
// The functions contain in this file are used to interface with the
// lispers.net control-plane. 
//
// This is a external data-plane from the lispers.net control-plane perspective
// and must be run with "lisp xtr-parameters" sub-command "ipc-data-plane =
// yes".
//
package main

import "fmt"
import "net"
import "time"
import "encoding/json"
import "os"
import "strconv"

const lispers_dir = "./"

//
// 200ms rate-limiter in units of nanaoseconds.
//
const lisp_rate_limiter = 200000000

//
// Sockets used for control-plane IPC.
//
var lisp_ipc_socket    *net.UnixConn
var lisp_punt_socket   *net.UnixConn
var lisp_last_punt     time.Time
var lisp_config_change int

//
// Data structures for running the data-plane.
//
var lisp_database     []Lisp_database
//  lisp_map_cache    []*Lisp_map_cache = lisp_lml_cache
var lisp_interfaces   map[string]Lisp_interface
var lisp_etr_nat_port int
var lisp_decap_keys   map[string]string

//
// lisp_ipc_message_processing
//
// Listen on socket "lisp-ipc-data-plane" for messages from the lispers.net
// python control-plane.
//
func lisp_ipc_message_processing() {
	var lisp_interface      Lisp_interface
	var lisp_database_entry Lisp_database
	var eid                 string
	var jdata               map[string]interface{}
	var sa                  net.UnixAddr

	sa.Name = lispers_dir + "lisp-ipc-data-plane"
	sa.Net = "unixgram"

	//
	// If named socket file exists, remove it.
	//
	_, err := os.Stat(sa.Name)
	if (err == nil) {
		os.Remove(sa.Name)
	}

	socket, err := net.ListenUnixgram("unixgram", &sa)
	if (err != nil) {
		lprint("net.ListenUnixgram() failed: %s", err)
		return
	}
	lisp_ipc_socket = socket

	buf := make([]byte, 8192)
	for {
		time.Sleep(100 * time.Millisecond)

		n, err := socket.Read(buf[:])
		if (err != nil) {
			lprint("socket.Read() failed: %s", err)
			continue
		}

		lprint("Received %s: '%s'", bold("IPC"), buf[0:n])

		jdata = make(map[string]interface{}, 0)
		err = json.Unmarshal(buf[0:n], &jdata)
		if (err != nil) {
			lprint("json.Unmarshall() failed: %s", err)
			continue
		}
		value, ok := jdata["type"]
		if (!ok) {
			lprint("JSON 'type' not found")
			continue
		}

		//
		// Process each JSON type.
		//
		if (value == "entire-map-cache") {
			entries := jdata["entries"].([]interface{})
			if (len(entries) == 0) {
				lml_clear_hash_table()
			}
			for _, jj := range entries {
				j := jj.(map[string]interface{})
				lisp_store_map_cache_data(j)
			}

		} else if (value == "map-cache") {
			lisp_store_map_cache_data(jdata)

		} else if (value == "database-mappings") {
			lisp_database = make([]Lisp_database, 0)
			for _, jj := range jdata["database-mappings"].([]interface{}) {
				j := jj.(map[string]interface{})
				iid, _ := strconv.Atoi(j["instance-id"].(string))
				eid = j["eid-prefix"].(string)
				lisp_database_entry.eid_prefix.lisp_store_address(iid, eid)
				lisp_database = append(lisp_database, lisp_database_entry)
			}
			if (len(lisp_database) != 0 && len(lisp_interfaces) != 0) {
				lisp_config_change++
				lisp_start_itr_data_plane()
			}

		} else if (value == "interfaces") {
 			new_interfaces := make(map[string]Lisp_interface, 0)
			for _, jj := range jdata["interfaces"].([]interface{}) {
				j := jj.(map[string]interface{})
				device := j["interface"].(string)
				iid, _ := strconv.Atoi(j["instance-id"].(string))

				entry, ok := lisp_interfaces[device]
				if (ok) {
					entry.instance_id = int(iid)
					new_interfaces[device] = entry
				} else {
					lisp_interface.instance_id = int(iid)
					new_interfaces[device] = lisp_interface
				}
			}
			lisp_interfaces = new_interfaces
			if (len(lisp_database) != 0 && len(lisp_interfaces) != 0) {
				lisp_config_change++
				lisp_start_itr_data_plane()
			}

		} else if (value == "etr-nat-port") {
			old_port := lisp_etr_nat_port
			lisp_etr_nat_port = int(jdata["port"].(float64))
			if (lisp_etr_nat_port != old_port) {
				lisp_create_decap_nat_capture()
			}

		} else if (value == "xtr-parameters") {
			lisp_debug_logging = jdata["control-plane-logging"].(bool)
			lisp_data_plane_logging = jdata["data-plane-logging"].(bool)
			lisp_rtr = jdata["rtr"].(bool)

		} else {
			lprint("JSON '%s' not supported", value)
			continue
		}

		//
		// Display entire state.
		//
		out := lisp_show_state()
		lisp_write_file("./show-xtr", out)
		if (lisp_debug_logging) {
			fmt.Printf(out)
		}
	}
}

//
// lisp_store_map_cache_data
//
// Store map-cache data from this JSON structure documented in lisp-ipc-data-
// plane.tx.
//
func lisp_store_map_cache_data(jdata map[string]interface{}) {
	var lisp_mc_entry *Lisp_map_cache
	var eid           Lisp_address
	var rloc, rle     Lisp_rloc

	iid, _ := strconv.Atoi(jdata["instance-id"].(string))
	eid.lisp_store_address(iid, jdata["eid-prefix"].(string))
	lisp_mc_entry = new(Lisp_map_cache)
	lisp_mc_entry.eid_prefix = eid

	//
	// Find entry and remove it. If opcode is add, then append to array.
	// If opcode is a delete, just return.
	//
	mc := lisp_lml_exact_lookup(eid)
	if (mc != nil) {
		lisp_lml_delete_entry(mc)
	}
	if (jdata["opcode"] == "add") {
		rloc_set := jdata["rlocs"]
		rle_set := jdata["rles"]

		if (rloc_set != nil) {
			for _, jj := range rloc_set.([]interface{}) {
				j := jj.(map[string]interface{})
				rloc.rloc.lisp_store_address(0, j["rloc"].(string))
				rloc.encap_port, _ = strconv.Atoi(j["port"].(string))
				_, ok := j["encrypt-key"].(string)
				if (ok) { rloc.encrypt_key = j["encrypt-key"].(string) }
				_, ok = j["icv-key"].(string)
				if (ok) { rloc.icv_key = j["icv-key"].(string) }
				lisp_mc_entry.rloc_set = append(lisp_mc_entry.rloc_set, rloc)
			}
		}
		if (rle_set != nil) {
			for _, jj := range rle_set.([]interface{}) {
				j := jj.(map[string]interface{})
				rle.rloc.lisp_store_address(0, j["rle"].(string))
				rle.encap_port, _ = strconv.Atoi(j["port"].(string))
				_, ok := j["encrypt-key"].(string)
				if (ok) { rle.encrypt_key = j["encrypt-key"].(string) }
				_, ok = j["icv-key"].(string)
				if (ok) { rle.icv_key = j["icv-key"].(string) }
				lisp_mc_entry.rle_set = append(lisp_mc_entry.rle_set, rle)
			}
 		}
		lisp_lml_add_entry(lisp_mc_entry)
	}
}

//
// lisp_show_state
//
// Show data structure state.
//
func lisp_show_state() string {

	//
	// Header line followed by blank line.
	//
	out := "lispers.net release " + bold(lisp_read_file("./lisp-version.txt"))
	out += " running at " + lisp_command_output("date") + "\n\n"

	//
	// xTR state section.
	//
	out += fmt.Sprintf("%s\n", bold("LISP xTR State"))
	e_or_d := "disabled/"
	if (lisp_debug_logging) { e_or_d = "enabled/" }
	if (lisp_data_plane_logging) {
		e_or_d += "enabled"
	} else {
		e_or_d += "disabled"
	}
    out += fmt.Sprintf("  LISP control/data-plane logging: %s\n", e_or_d)
	if (lisp_rtr) {
		out += fmt.Sprintf("  LISP RTR: enabled\n")
	} else {
		out += fmt.Sprintf("  LISP RTR: disabled\n")
	}
	out += fmt.Sprintf("  LISP ETR NAT Port: %d\n", lisp_etr_nat_port)

	//
	// Display "lisp interfaces".
	//
	out += fmt.Sprintf("  LISP Interfaces: ")
	if (len(lisp_interfaces) == 0) { out += fmt.Sprintf(" []") }
	for key, value := range lisp_interfaces {
		out += fmt.Sprintf("%s:[%d] ", key, value.instance_id)
	}
	out += fmt.Sprintf("\n")

	//
	// Display "lisp database-mappings".
	//
	out += fmt.Sprintf("  LISP Database Mappings: ")
	if (len(lisp_database) == 0) { out += fmt.Sprintf(" []\n") }
	for i, value := range lisp_database {
		out += fmt.Sprintf("%s", value.eid_prefix.lisp_print_address(true))
		if (i == len(lisp_database)-1) {
			out += fmt.Sprintf("\n")
		} else {
			out += fmt.Sprintf(", ")
		}
	}

	//
	// Section break. Blank line before map-cache display.
	//
	out += fmt.Sprintf("\n")

	//
	// Display map-cache.
	//
	out += fmt.Sprintf("%s\n", bold("LISP xTR Map-Cache State"))
	for mc := lisp_lml_walk(nil); mc != nil; mc = lisp_lml_walk(mc) {
		if (len(mc.rloc_set) == 0 && len(mc.rle_set) == 0) {
			out += fmt.Sprintf("  EID: %s, rloc-set: [], rle-set: []\n",
				mc.eid_prefix.lisp_print_address(true))
			continue
		}
		if (len(mc.rloc_set) != 0) {
			out += fmt.Sprintf("  EID: %s, rloc-set: ",
				mc.eid_prefix.lisp_print_address(true))
			for i, rloc := range mc.rloc_set {
				out += fmt.Sprintf("%s:%d",
					rloc.rloc.lisp_print_address(false), rloc.encap_port)
				if (i != len(mc.rloc_set)-1) {
					out += fmt.Sprintf(", ")
				}
			}
			out += fmt.Sprintf("\n")
		}
		if (len(mc.rle_set) != 0) {
			out += fmt.Sprintf("  EID: %s, rle-set: ",
				mc.eid_prefix.lisp_print_address(true))
			for i, rle := range mc.rle_set {
				out += fmt.Sprintf("%s:%d", rle.rloc.lisp_print_address(false),
					rle.encap_port)
				if (i != len(mc.rle_set)-1) {
					out += fmt.Sprintf(", ")
				}
			}
			out += fmt.Sprintf("\n")
		}
	}

	//
	// Final blank line.
	//
	out += fmt.Sprintf("\n")
	return(out)
}

//
// lisp_create_punt_socket
//
// Create named socket 'lispers.net-itr: is lispers.net directory.
//
func lisp_create_punt_socket() bool {
	var sa    net.UnixAddr
	var found error

	sa.Name = lispers_dir + "lispers.net-itr"
	sa.Net = "unixgram"

	for i := 0; i < 4; i++ {
		_, found = os.Stat(sa.Name)
		if (found == nil) {	break }
		lprint("Punt socket %s does not exist, waiting ...", sa.Name)
		time.Sleep(time.Duration(i) * (time.Second * 2))
	}
	if (found != nil) { return(false) }
 	lprint("Punt socket %s found", sa.Name)

	socket, err := net.DialUnix("unixgram", nil, &sa)
	if (err != nil) {
		lprint("net.DialUnix() failed: %s", err)
		return(false)
	}
	lisp_punt_socket = socket

	//
	// Tell control-plane we have restarted.
	//
	lisp_send_restart()
	return(true)
}

//
// lisp_punt_packet
//
// Send IPC message to punt packet.
//
func lisp_punt_packet(input_interface string, seid Lisp_address,
	deid Lisp_address) {
	var ipc = map[string]string{ "type" : "discovery", "source-eid" : "",
		"dest-eid" : "", "interface" : "", "instance-id" : "" }

	//
	// Check rate-limiter before bothering the control-plane.
	//
	elapsed := time.Since(lisp_last_punt).Nanoseconds()
	if (elapsed <= lisp_rate_limiter) {
		s := green(seid.lisp_print_address(false))
		d := green(deid.lisp_print_address(false))
		dprint("Rate-limit punt packet %s -> %s", s, d)
		return
	}

	if (input_interface == "?") {
		iid := fmt.Sprintf("%d", seid.instance_id)
		if (seid.instance_id == 0xffffff) {
			iid = "-1"
		}
		ipc["instance-id"] = iid
	} else {
		ipc["interface"] = input_interface
		iid := lisp_interfaces[input_interface].instance_id
		ipc["instance-id"] = fmt.Sprintf("%d", iid)
	}
	ipc["source-eid"] = seid.lisp_print_address(false)
	ipc["dest-eid"] = deid.lisp_print_address(false)

	//
	// Encode in JSON and send on lispers.net-itr named socket.
	//
	jdata, err := json.Marshal(ipc)
	if (err != nil) {
		lprint("json.Marshal() failed: %s", err)
		return
	}

	lprint("Send %s: '%s'", bold("IPC"), jdata)
	lisp_punt_socket.Write(jdata)
	lisp_last_punt = time.Now()
}

//
// lisp_send_restart
//
// Send IPC message to control-plane indicating that this data-plane has restarted.
//
func lisp_send_restart() {
	var ipc = map[string]string{ "type" : "restart" }

	//
	// Encode in JSON and send on lispers.net-itr named socket.
	//
	jdata, err := json.Marshal(ipc)
	if (err != nil) {
		lprint("json.Marshal() failed: %s", err)
		return
	}

	lprint("Send %s: '%s'", bold("IPC"), jdata)
	lisp_punt_socket.Write(jdata)
}

//
// lisp_stats_thread
//
// Peridoically send data-plane stats to the lispers.net control-plane.
//
func lisp_stats_thread() {
	print_idle := false
	ipc := make(map[string]interface{}, 0)

	for {
		eids := make([]interface{}, 0)
		count := 0
		for mc := lisp_lml_walk(nil); mc != nil; mc = lisp_lml_walk(mc) {
			count += 1
			rlocs := make([]interface{}, 0)
			for j, _ := range mc.rloc_set {
				rloc := &mc.rloc_set[j]
				if (rloc.packets == 0) { continue }

				ipc_rloc := make(map[string]interface{}, 0)
				ipc_rloc["rloc"] = rloc.rloc.lisp_print_address(false)
				ipc_rloc["port"] = fmt.Sprintf("%d", rloc.encap_port)
				ipc_rloc["packet-count"] = rloc.packets
				ipc_rloc["byte-count"] = rloc.bytes
				ipc_rloc["seconds-last-packet"] =
					time.Since(rloc.last_packet).Seconds()
				rloc.packets = 0
				rloc.bytes = 0
				rlocs = append(rlocs, ipc_rloc)
			}
			if (len(rlocs) == 0) {
				continue
			}

			ipc_eid := make(map[string]interface{}, 0)
			ipc_eid["instance-id"] =
				fmt.Sprintf("%d", mc.eid_prefix.instance_id)
			ipc_eid["eid-prefix"] = mc.eid_prefix.lisp_print_address(false)
			ipc_eid["rlocs"] = rlocs
			eids = append(eids, ipc_eid)
		}

		if (len(eids) != 0) {
			ipc["type"] = "statistics"
			ipc["entries"] = eids

			//
			// Encode in JSON and send on lispers.net-itr named socket.
			//
			jdata, err := json.Marshal(ipc)
			if (err == nil) {
				lprint("Send %s: '%s'", bold("IPC"), jdata)
				lisp_punt_socket.Write(jdata)
			} else {
				lprint("json.Marshal() for stats messsage failed: %s", err)
			}
		} else if (print_idle) {
			lprint("No change for %d map-cache entries, stats message " +
				"suppressed", count)
		}

		//
		// Send stats in 5 seconds if there was any change.
		//
		time.Sleep(5 * time.Second)
	}
}
