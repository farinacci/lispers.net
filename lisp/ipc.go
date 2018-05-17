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
var lisp_show_timer    time.Time

//
// Data structures for running the data-plane.
//
var lisp_database        []Lisp_database
var lisp_interfaces      map[string]Lisp_interface
var lisp_itr_crypto_port int
var lisp_etr_nat_port    int
var lisp_decap_keys      map[string]*Lisp_rloc
var lisp_decap_stats     map[string]*Lisp_stats

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

	//
	// If named socket file exists, remove it. Then open the socket.
	//
	sa.Name = lispers_dir + "lisp-ipc-data-plane"
	sa.Net = "unixgram"
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

	//
	// Allocate lisp_decap_keys map.
	//
	lisp_decap_keys = make(map[string]*Lisp_rloc)

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

		} else if (value == "itr-crypto-port") {
			lisp_itr_crypto_port = int(jdata["port"].(float64))

		} else if (value == "etr-nat-port") {
			old_port := lisp_etr_nat_port
			lisp_etr_nat_port = int(jdata["port"].(float64))
			if (lisp_etr_nat_port != old_port) {
				lisp_create_decap_nat_capture()
			}

		} else if (value == "decap-keys") {
			keys_set := jdata["keys"]
			if (keys_set == nil) { continue }
			addr := jdata["rloc"].(string)
			port := jdata["port"].(string)

			rloc := new(Lisp_rloc)
			rloc.rloc.lisp_store_address(0, addr)
			lisp_store_keys(nil, rloc, "decrypt-key", keys_set.([]interface{}))

			index := addr + ":" + port
			lisp_decap_keys[index] = rloc

		} else if (value == "xtr-parameters") {
			lisp_debug_logging = jdata["control-plane-logging"].(bool)
			lisp_data_plane_logging = jdata["data-plane-logging"].(bool)
			lisp_rtr = jdata["rtr"].(bool)

		} else {
			lprint("JSON '%s' not supported", value)
			continue
		}

		//
		// Display entire state. But don't do it more than every 2 seconds.
		//
		if (time.Since(lisp_show_timer).Seconds() >= 2) {
			lisp_show_timer = time.Now()
			go func() {
				time.Sleep(2 * time.Second)
				out := lisp_show_state()
				lisp_write_file("./show-xtr", out)
				if (lisp_debug_logging) { fmt.Printf(out) }
			}()
		}
	}
}

//
// lisp_store_keys
//
// Store keys in an Lisp_rloc in the map-cache or in the lisp_decap_keys
// array. There seems to be some strange issue in the hmac and sha256
// packages where if you call the libraries with the same icv key as before,
// it will not compute a good ICV. So this function takes care of detecting
// previous state with the same keys and uses that state. When keys change,
// from the LISP control-plane, the issue does not exist.
//
func lisp_store_keys(mc *Lisp_map_cache, rloc *Lisp_rloc, key_name string,
	key_set []interface{}) {

	var rloc_keys [4]*Lisp_keys
	var keys      *Lisp_keys

	//
	// Get RLOC keys array from possibly existing map-cache entry.
	//
	if (mc != nil) {
		rloc_entry := mc.lisp_find_rloc(rloc.rloc)
		if (rloc_entry != nil) { rloc_keys = rloc_entry.keys }
	}

	for _, jj := range key_set {
		j := jj.(map[string]interface{})
		key_id, _ := strconv.Atoi(j["key-id"].(string))
		if (key_id < 1 && key_id > 3) { continue }

		crypto_key, ok := j[key_name].(string)
		if (ok == false) { continue }
		icv_key, ok := j["icv-key"].(string)
		if (ok == false) { continue }

		//
		// Check if keys are the same and if so, use the values from the
		// existing RLOC map-cache entry.
		//
		if (rloc_keys[key_id] != nil &&
			rloc_keys[key_id].crypto_key == crypto_key &&
			rloc_keys[key_id].icv_key == icv_key) {
			keys = rloc_keys[key_id]
		} else {
			keys = new(Lisp_keys)
			keys.lisp_setup_keys(crypto_key, icv_key)
		}
		rloc.keys[key_id] = keys
		rloc.use_key_id = key_id
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

	iid, _ := strconv.Atoi(jdata["instance-id"].(string))
	eid.lisp_store_address(iid, jdata["eid-prefix"].(string))
	lisp_mc_entry = new(Lisp_map_cache)
	lisp_mc_entry.eid_prefix = eid

	//
	// Find entry and remove it. If opcode is add, then append to array.
	// If opcode is a delete, just return.
	//
	mc := lisp_lml_exact_lookup(eid)
	if (jdata["opcode"] == "delete") {
		if (mc != nil) { lisp_lml_delete_entry(mc) }
		return
	}

	if (jdata["opcode"] == "add") {
		rloc_set := jdata["rlocs"]
		rle_set := jdata["rles"]

		if (rloc_set != nil) {
			for _, jj := range rloc_set.([]interface{}) {
				j := jj.(map[string]interface{})
				rloc := new(Lisp_rloc)
				rloc.rloc.lisp_store_address(0, j["rloc"].(string))
				rloc.encap_port, _ = strconv.Atoi(j["port"].(string))
				keys_set := j["keys"]
				if (keys_set != nil) {
					lisp_store_keys(mc, rloc, "encrypt-key",
						keys_set.([]interface{}))
				}
				lisp_mc_entry.rloc_set = append(lisp_mc_entry.rloc_set, *rloc)
			}
		}
		if (rle_set != nil) {
			for _, jj := range rle_set.([]interface{}) {
				j := jj.(map[string]interface{})
				rle := new(Lisp_rloc)
				rle.rloc.lisp_store_address(0, j["rle"].(string))
				rle.encap_port, _ = strconv.Atoi(j["port"].(string))
				keys_set := j["keys"]
				if (keys_set != nil) {
					lisp_store_keys(mc, rle, "encrypt-key",
						keys_set.([]interface{}))
				}
				lisp_mc_entry.rle_set = append(lisp_mc_entry.rle_set, *rle)
			}
 		}
		if (mc != nil) { lisp_lml_delete_entry(mc) }
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
	out += fmt.Sprintf("  LISP ITR Crypto Port: %d\n", lisp_itr_crypto_port)
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
				key_id := ""
				if (rloc.use_key_id != 0) {
					key_id = fmt.Sprintf(", key-id %d", rloc.use_key_id)
				}
				out += fmt.Sprintf("%s:%d%s",
					rloc.rloc.lisp_print_address(false), rloc.encap_port,
					key_id)
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
	// Display decap keys if any.
	//
	if (len(lisp_decap_keys) != 0) {
		out += fmt.Sprintf("\n%s\n", bold("LISP xTR Decap Keys"))
		for index, rloc := range lisp_decap_keys {
			key_str := "["
			for i := 0; i < len(rloc.keys); i++ {
				if (rloc.keys[i] == nil) { continue }
				if (key_str != "[") { key_str += ", " }
				key_str += fmt.Sprintf("%d", i)
			}
			key_str += "]"
			out += fmt.Sprintf("  RLOC: %s, key-ids %s\n", index, key_str)
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

	//
	// First IPC message is "type" : "statistics" which sends stats for map-
	// cache entry.
	//
	for {
		eids := make([]interface{}, 0)
		count := 0
		for mc := lisp_lml_walk(nil); mc != nil; mc = lisp_lml_walk(mc) {
			count += 1
			rlocs := make([]interface{}, 0)
			for j, _ := range mc.rloc_set {
				rloc := &mc.rloc_set[j]
				if (rloc.stats.packets == 0) { continue }

				ipc_rloc := make(map[string]interface{}, 0)
				ipc_rloc["rloc"] = rloc.rloc.lisp_print_address(false)
				ipc_rloc["port"] = fmt.Sprintf("%d", rloc.encap_port)
				ipc_rloc["packet-count"] = rloc.stats.packets
				ipc_rloc["byte-count"] = rloc.stats.bytes
				ipc_rloc["seconds-last-packet"] =
					time.Since(rloc.stats.last_packet).Seconds()
				rloc.stats.packets = 0
				rloc.stats.bytes = 0
				rlocs = append(rlocs, ipc_rloc)
			}
			if (len(rlocs) == 0) { continue }

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
		// Second IPC message is "type" : "decap-stats" which sends global
		// stats for ETR and RTR decap processing.
		//
		dipc := make(map[string]interface{}, 0)
		changed := false
		for k, stats := range lisp_decap_stats {
			if (stats.packets == 0) { continue }

			changed = true
			dipc_stats := make(map[string]interface{}, 0)
			dipc_stats["packet-count"] = stats.packets
			dipc_stats["byte-count"] = stats.bytes
			dipc_stats["seconds-last-packet"] =
				time.Since(stats.last_packet).Seconds()
			dipc[k] = dipc_stats
			stats.packets = 0
			stats.bytes = 0
		}

		//
		// Encode in JSON and send on lispers.net-itr named socket.
		//
		if (changed) {
			dipc["type"] = "decap-statistics"
			jdata, err := json.Marshal(dipc)
			if (err == nil) {
				lprint("Send %s: '%s'", bold("IPC"), jdata)
				lisp_punt_socket.Write(jdata)
			} else {
				lprint("json.Marshal() for decap-stats messsage failed: %s",
					err)
			}
		} else if (print_idle) {
			lprint("No change to decap-stats, message suppressed")
		}

		//
		// Send stats in 5 seconds if there was any change.
		//
		time.Sleep(5 * time.Second)
	}
}
