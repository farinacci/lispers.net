#
# lisp-itr.py
#
# This file performs LISP Ingress Tunnel Router (ITR) functionality.
#

import lisp
import lispconfig
import socket
import select
import threading
import pcappy
import time
import os
import commands
import struct
import json

#------------------------------------------------------------------------------

#
# Global data structures relative to the lisp-itr process.
#
lisp_send_sockets = [None, None, None]
lisp_ipc_listen_socket = None
lisp_ipc_punt_socket = None
lisp_ephem_listen_socket = None
lisp_ephem_nat_socket = None
lisp_ephem_port = lisp.lisp_get_ephemeral_port()
lisp_ephem_nat_port = lisp.lisp_get_ephemeral_port()
lisp_raw_socket = None
lisp_raw_v6_socket = None
lisp_periodic_timer = None
lisp_itr_info_timer = None

#
# This is for testing sending from one local EID-prefix to another EID-prefix
# on the same system. Rather than natively forwarding a packet, the mapping
# system is used.
#
lisp_xtr_loopback = False

#
# Used to start pcap threads concurrently.
#
lisp_pcap_lock = threading.Lock()

#------------------------------------------------------------------------------

#
# lisp_itr_show_command
#
# Display state in an ITR.
#
def lisp_itr_show_command(parameter):
    return(lispconfig.lisp_itr_rtr_show_command(parameter, "ITR", []))
#enddef

#
# lisp_itr_show_keys_command
#
# Call lispconfig.lisp_show_crypto_list().
#
def lisp_itr_show_keys_command(parameter):
    return(lispconfig.lisp_show_crypto_list("ITR"))
#enddef


#
# lisp_itr_show_rloc_probe_command
#
# Display RLOC-probe list state in an ITR.
#
def lisp_itr_show_rloc_probe_command(parameter):
    return(lispconfig.lisp_itr_rtr_show_rloc_probe_command("ITR"))
#enddef

#
# lisp_itr_process_timer
#
# This is the ITR's 60-second periodic timer routine. We typically use it
# to time-out map-cache entries. But the one case where we are acting as
# a L2-overlay ITR, we will send Map-Requests to retrieve the broadcast
# entry so we have the latest replication-list before we need it.
#
def lisp_itr_process_timer(lisp_sockets, lisp_ephem_port):
    lisp.lisp_set_exception()

    #
    # Remove nonce entries from crypto-list.
    #
    for keys in lisp.lisp_crypto_keys_by_nonce.values():
        for key in keys: del(key)
    #endfor
    lisp.lisp_crypto_keys_by_nonce = {}

    #
    # If doing L2-overlays, get map-cache entry from (0000-0000-0000/0, 
    # ffff-ffff-ffff/48).
    #
    if (lisp.lisp_l2_overlay):
        afi = lisp.LISP_AFI_MAC
        iid = lisp.lisp_default_iid
        s = lisp.lisp_address(afi, "0000-0000-0000", 0, iid)
        s.mask_len = 0
        d = lisp.lisp_address(afi, "ffff-ffff-ffff", 48, iid)
        lisp.lisp_send_map_request(lisp_sockets, lisp_ephem_port, s, d, None)
    #endif

    #
    # Timeout Map-Cache entries.
    #
    lisp.lisp_timeout_map_cache(lisp.lisp_map_cache)

    #
    # Restart periodic timer.
    #
    lisp_periodic_timer = threading.Timer(60, lisp_itr_process_timer, 
        [lisp_sockets, lisp_ephem_port])
    lisp_periodic_timer.start()
#enddef

#
# lisp_itr_timeout_dynamic_eids
#
# Check to see if dyanmic-EIDs have stop sending data. If so, remove the 
# state and stop registering them.
#
def lisp_itr_timeout_dynamic_eids(lisp_socket):
    lisp.lisp_set_exception()

    now = lisp.lisp_get_timestamp()
    for db in lisp.lisp_db_list:
        if (db.dynamic_eid_configured() == False): continue

        delete_list = []
        for dyn_eid in db.dynamic_eids.values():
            ts = dyn_eid.last_packet
            if (ts == None): continue
            if (ts + dyn_eid.timeout > now): continue

            #
            # Check hardware if dyn-EID has had packets SENT to. We want the
            # opposite but this is all we get from Arista.
            #
            if (lisp.lisp_program_hardware):
                prefix = dyn_eid.dynamic_eid.print_prefix_no_iid()
                if (lisp.lisp_arista_is_alive(prefix)):
                    lisp.lprint(("Hardware indicates dynamic-EID {} " + \
                        "still active").format(lisp.green(prefix, False)))
                    continue
                #endif
            #endif

            #
            # Tell ETR process so it can register dynamic-EID.
            #
            eid_str = dyn_eid.dynamic_eid.print_address()
            ipc = "learn%{}%None".format(eid_str)
            ipc = lisp.lisp_command_ipc(ipc, "lisp-itr")
            lisp.lisp_ipc(ipc, lisp_socket, "lisp-etr")

            lisp.lprint("Dynamic-EID {}".format( \
                lisp.bold(lisp.green(eid_str, False) + " activity timeout", 
                False)))
            delete_list.append(eid_str)
        #endfor

        #
        # Remove the timed out entries from db.dynamic_eids{}.
        #
        for eid_str in delete_list: db.dynamic_eids.pop(eid_str)
    #endfor

    #
    # Restart periodic timer.
    #
    threading.Timer(lisp.LISP_DEFAULT_DYN_EID_TIMEOUT, 
        lisp_itr_timeout_dynamic_eids, [lisp_socket]).start()
#enddef

#
# lisp_get_active_interfaces
#
# Get interfaces that are plugged in. Including loopback interfaces.
#
# We need to test these 3 types of lines from "ifconfig" output:
#
# aten2     Link encap:Ethernet  HWaddr 00:1F:A0:07:0C:04 
# eth7: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
# en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
#
def lisp_get_active_interfaces():
    if (lisp.lisp_is_macos()): return(["en0", "en1", "lo0"])

    #
    # Linux distributions have different ifconfig output format.
    #
    gs = "Link encap"
    interfaces = commands.getoutput("ifconfig | egrep '{}'".format(gs))
    if (interfaces == ""):
        gs = ": flags="
        interfaces = commands.getoutput("ifconfig | egrep '{}'".format(gs))
    #endif
        
    interfaces = interfaces.split("\n")

    return_interfaces = []
    for interface in interfaces:
        ifname = interface.split(gs)[0].replace(" ", "")
        return_interfaces.append(ifname)
    #endfor
    return(return_interfaces)
#enddef

#
# lisp_itr_startup
#
# Intialize this LISP ITR process. This function returns no values.
#
def lisp_itr_startup():
    global lisp_send_sockets
    global lisp_ipc_listen_socket
    global lisp_ipc_punt_socket
    global lisp_ephem_listen_socket
    global lisp_ephem_nat_socket
    global lisp_raw_socket, lisp_raw_v6_socket

    lisp.lisp_i_am("itr")
    lisp.lisp_set_exception()
    lisp.lisp_print_banner("ITR starting up")

    #
    # Get local address for source RLOC for encapsulation.
    #
    lisp.lisp_get_local_interfaces()
    lisp.lisp_get_local_macs()
    if (lisp.lisp_get_local_addresses() == False): return(False)

    #
    # Open send socket.
    #
    lisp_send_sockets[0] = lisp.lisp_open_send_socket("", lisp.LISP_AFI_IPV4)
    lisp_send_sockets[1] = lisp.lisp_open_send_socket("", lisp.LISP_AFI_IPV6)
    lisp_ipc_listen_socket = lisp.lisp_open_listen_socket("", "lisp-itr")
    lisp_ipc_punt_socket = lisp.lisp_open_listen_socket("", "lispers.net-itr")
    lisp_send_sockets[2] = lisp_ipc_listen_socket
    address = "0.0.0.0" if lisp.lisp_is_raspbian() else "0::0"
    lisp_ephem_listen_socket = lisp.lisp_open_listen_socket(address,
        str(lisp_ephem_port))

    #
    # Used on for listening for Info-Replies for NAT-traversal support.
    #
    lisp_ephem_nat_socket = lisp.lisp_open_listen_socket("0.0.0.0", 
        str(lisp_ephem_nat_port))

    #
    # Open up raw socket so we can send with IP headers after decapsulation.
    #
    lisp_raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
        socket.IPPROTO_RAW)
    lisp_raw_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

    if (lisp.lisp_is_raspbian() == False):
        lisp_raw_v6_socket = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
            socket.IPPROTO_UDP)
    #endif

    #
    # Start map-cache timeout timer.
    #
    threading.Thread(target=lisp_itr_get_capture_info).start()

    #
    # Load map-cache from checkpoint file before we start writing to it.
    #
    lisp.lisp_load_checkpoint()

    #
    # Should we load-split pings?
    #
    lisp.lisp_load_split_pings = (os.getenv("LISP_LOAD_SPLIT_PINGS") != None)

    #
    # Start map-cache timeout timer.
    #
    lisp_periodic_timer = threading.Timer(60, lisp_itr_process_timer,
        [lisp_send_sockets, lisp_ephem_port])
    lisp_periodic_timer.start()

    #
    # Start dynamic-EID timeout timer.
    #
    threading.Timer(lisp.LISP_DEFAULT_DYN_EID_TIMEOUT, 
        lisp_itr_timeout_dynamic_eids, [lisp_ipc_listen_socket]).start()

    return(True)
#enddef

#
# lisp_itr_count_eid_prefixes
#
# Cound the number of "prefix" sub-commands inside of each "lisp database-
# mapping" command.
#
def lisp_itr_count_eid_prefixes():
    f = open("./lisp.config", "r")

    within = False
    count = 0
    for line in f:
        if (line == "lisp database-mapping {\n"): within = True
        if (line == "}\n"): within = False
        if (within == False): continue
        if (line[0] == " " and line.find("prefix {") != -1): count += 1
    #endif
    f.close()

    return(count)
#enddef

#
# lisp_itr_get_local_eid_prefixes
#
# Check the number of "lisp database-mapping" commands we will process. Wait
# for them to be processed and only return when all are processed.
#
# Return array of static EID-prefixes and an array of dynamic EID-prefixes.
#
def lisp_itr_get_local_eid_prefixes():

    #
    # Count the number of "prefix" sub-commands within a "lisp database-
    # mapping" command clause in the lisp.config file.
    #
    count = lisp_itr_count_eid_prefixes()

    #
    # Does user want us to wait longer than a second to check to see if
    # commands are done. If the CPU is going to be busy during startup, the
    # wait-time should be made longer..
    #
    wait_time = os.getenv("LISP_ITR_WAIT_TIME")
    wait_time = 1 if (wait_time == None) else int(wait_time)

    #
    # Wait for database-mapping commands to execute. We need to retrieve
    # EID-prefixes we need to listen on.
    #
    while (count != len(lisp.lisp_db_list)):
        lisp.lprint(("Waiting {} second(s) for {} database-mapping EID-" + \
            "prefixes, {} processed so far ...").format(wait_time, count, 
            len(lisp.lisp_db_list)))
        time.sleep(wait_time)
    #endwhile

    #
    # Return each IPv4, IPv6, or MAC EIDs. These are the ones we need to
    # pass to pcap.
    #
    sources = []
    dyn_eids = []
    for db in lisp.lisp_db_list:
        if (db.eid.is_ipv4() or db.eid.is_ipv6() or db.eid.is_mac()):
            eid_str = db.eid.print_prefix_no_iid()
            if (db.dynamic_eid_configured()): dyn_eids.append(eid_str)
            sources.append(eid_str)
        #endif
    #endfor
    return(sources, dyn_eids)
#enddef

#
# lisp_itr_get_capture_info
#
# Thead to wait for database-mapping commands to finish processing so we can
# get local EID-prefixes to be source filters for packet capture.
#
def lisp_itr_get_capture_info():
    global lisp_pcap_lock

    lisp.lisp_set_exception()

    #
    # Wait for database-mapping commands to execute. We need to retrieve
    # EID-prefixes we need to listen on.
    #
    sources, dyn_eids = lisp_itr_get_local_eid_prefixes()

    #
    # If "ipc-data-plane = yes" is configured, we do not need to do any
    # data-plane forwarding. There is another module running with the
    # lispers.net control-plane that is doing data-plane forwarding. We'll
    # get punts via the lispers.net-itr named socket. But we do have to
    # packet capture RLOC-probe replies. Also capture multicast Map-Register
    # messages for LISP-Decent.
    #
    cp_pfilter = None
    if (lisp.lisp_ipc_data_plane): 
        lisp.lprint(lisp.bold("Data-plane packet capture disabled", False))
        cp_pfilter = "(udp src port 4342 and ip[28] == 0x28)" + \
            " or (ip[16] >= 224 and ip[16] < 240 and (ip[28] & 0xf0) == 0x30)"

        lisp.lprint("Control-plane capture: '{}'".format(cp_pfilter))
    else:
        lisp.lprint("Capturing packets for source-EIDs {}".format( \
            lisp.green(str(sources), False)))
    #endif
    if (lisp.lisp_pitr): lisp.lprint("Configured for PITR functionality")

    #
    # We want the kernel to handle any packets with source AND destination
    # that matches any EID-prefixes for the site. Any other case, we want
    # the pcap filters to get the packet to this lisp-itr process.
    #
    l2_overlay = lisp.lisp_l2_overlay
    if (l2_overlay == False):
        if (lisp.lisp_is_linux()): lisp_itr_kernel_filter(sources, dyn_eids)
    #endif

    #
    # Build packet capture filter so we get packets for configured source EID-
    # prefixes.
    #
    if (cp_pfilter == None):
        if (lisp.lisp_pitr):
            pfilter = lisp_itr_build_pcap_filter(sources, [], False, True)
        else:
            pfilter = lisp_itr_build_pcap_filter(sources, dyn_eids, l2_overlay,
                False)
        #endif
    else:
        pfilter = cp_pfilter
    #endif

    #
    # User can select which interfaces to pcap on.
    #
    interfaces = lisp_get_active_interfaces()
    pcap_list = os.getenv("LISP_PCAP_LIST")
    if (pcap_list == None):
        us = ""
        rloc_interfaces = []
    else:
        eid_interfaces = list(set(pcap_list.split()) & set(interfaces))
        rloc_interfaces = list(set(pcap_list.split()) ^ set(interfaces))
        us = "user-selected "
        lisp.lprint("User pcap-list: {}, active-interfaces: {}".format( \
            pcap_list, interfaces))
        interfaces = eid_interfaces
    #endif

    #
    # Start a pcap thread so we can receive packets from applications on this
    # system. But make sure the device is up on A10 devices.
    #
    for device in interfaces:
        args = [device, pfilter, lisp_pcap_lock]
        lisp.lprint("Capturing packets on {}interface {}".format(us, device))
        threading.Thread(target=lisp_itr_pcap_thread, args=args).start() 
    #endfor
    if (cp_pfilter): return

    #
    # Start a pcap thread so we can receive RLOC-probe Map-Replies packets on 
    # RLOC interfaces. This is only called when LISP_PCAP_LIST is set.
    #
    probe_pfilter = "(udp src port 4342 and ip[28] == 0x28)"
    for device in rloc_interfaces:
        args = [device, probe_pfilter, lisp_pcap_lock]
        lisp.lprint("Capture RLOC-probe replies on RLOC interface {}".format( \
            device))
        threading.Thread(target=lisp_itr_pcap_thread, args=args).start() 
    #endfor
#enddef

#
# lisp_itr_shutdown
#
# Shut down this process.
#
def lisp_itr_shutdown():

    #
    # Cancel periodic Info timer threads.
    #
    if (lisp_itr_info_timer): lisp_itr_info_timer.cancel()

    #
    # Close sockets.
    #
    lisp.lisp_close_socket(lisp_send_sockets[0], "")
    lisp.lisp_close_socket(lisp_send_sockets[1], "")
    lisp.lisp_close_socket(lisp_ephem_listen_socket, "")
    lisp.lisp_close_socket(lisp_ephem_nat_socket, "")
    lisp.lisp_close_socket(lisp_ipc_listen_socket, "lisp-itr")
    lisp.lisp_close_socket(lisp_ipc_punt_socket, "lispers.net-itr")
#enddef

#
# lisp_itr_process_data_plane_stats
#
# { "type" : "statistics", "entries" :
#   [ { "instance-id" : "<iid>", "eid-prefix" : "<eid>", "rlocs" : [
#     { "rloc" : "<rloc-1>", "packet-count" : <count>, "byte-count" : <bcount>,
#       "seconds-last-packet" : "<timestamp>" },  ...
#     { "rloc" : "<rloc-n>", "packet-count" : <count>, "byte-count" : <bcount>,
#        "seconds-last-packet" : <system-uptime> } ], ... }
#    ]
# }
#
def lisp_itr_process_data_plane_stats(msg):
    if (msg.has_key("entries") == False):
        lisp.lprint("No 'entries' in stats IPC message")
        return
    #endif

    for msg in msg["entries"]:
        if (msg.has_key("eid-prefix") == False):
            lisp.lprint("No 'eid-prefix' in stats IPC message")
            continue
        #endif
        eid_str = msg["eid-prefix"]

        if (msg.has_key("instance-id") == False):
            lisp.lprint("No 'instance-id' in stats IPC message")
            continue
        #endif
        iid = int(msg["instance-id"])

        #
        # Lookup EID-prefix in map-cache.
        #
        eid = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, iid)
        eid.store_prefix(eid_str)
        mc = lisp.lisp_map_cache_lookup(None, eid)
        if (mc == None): 
            lisp.lprint("Map-cache entry for {} not found for stats update". \
                format(eid_str))
            continue
        #endif

        if (msg.has_key("rlocs") == False):
            lisp.lprint("No 'rlocs' in stats IPC message for {}".format( \
                eid_str))
            continue
        #endif
        ipc_rlocs = msg["rlocs"]

        #
        # Loop through RLOCs in IPC message.
        #
        for ipc_rloc in ipc_rlocs:
            if (ipc_rloc.has_key("rloc") == False): continue

            rloc_str = ipc_rloc["rloc"]
            rloc = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
            rloc.store_address(rloc_str)

            rloc_entry = mc.get_rloc(rloc)
            if (rloc_entry == None): continue

            #
            # Update stats.
            #
            pc = 0 if ipc_rloc.has_key("packet-count") == False else \
                ipc_rloc["packet-count"]
            bc = 0 if ipc_rloc.has_key("byte-count") == False else \
                ipc_rloc["byte-count"]
            ts = 0 if ipc_rloc.has_key("seconds-last-packet") == False else \
                ipc_rloc["seconds-last-packet"]
        
            rloc_entry.stats.packet_count += pc
            rloc_entry.stats.byte_count += bc
            rloc_entry.stats.last_increment = lisp.lisp_get_timestamp() - ts
        
            lisp.lprint("Update stats {}/{}/{}s for {} RLOC {}".format(pc, bc,
                ts, eid_str, rloc_str))
        #endfor
    #endfor
#enddef

#
# lisp_ipc_map_cache_entry
#
# Callback from class lisp_cache.walk_cache().
#
def lisp_ipc_map_cache_entry(mc, jdata):
    entry = lisp.lisp_write_ipc_map_cache(True, mc, dont_send=True)
    jdata.append(entry)
    return([True, jdata])
#enddef

#
# lisp_ipc_walk_map_cache
#
# Walk the entries in the lisp_map_cache(). And then subsequently walk the
# entries in lisp_mapping.source_cache().
#
def lisp_ipc_walk_map_cache(mc, jdata):
    
    #
    # There is only destination state in this map-cache entry.
    #
    if (mc.group.is_null()): return(lisp_ipc_map_cache_entry(mc, jdata))

    if (mc.source_cache == None): return([True, jdata])

    #
    # There is (source, group) state so walk all sources for this group
    # entry.
    #
    jdata = mc.source_cache.walk_cache(lisp_ipc_map_cache_entry, jdata)
    return([True, jdata])
#enddef

#
# lisp_itr_process_data_plane_restart
#
# The external data-plane has restarted. We will touch the lisp.config file so
# all configuration information is sent and then traverse the map-cache
# sending each entry to the data-plane so it can regain its state.
#
def lisp_itr_process_data_plane_restart():
    os.system("touch ./lisp.config")

    jdata = { "type" : "entire-map-cache", "entries" : [] }

    entries = jdata["entries"]
    lisp.lisp_map_cache.walk_cache(lisp_ipc_walk_map_cache, entries)
    lisp.lisp_write_to_dp_socket(jdata)
#enddef

#
# lisp_itr_process_punt
#
# Another data-plane is punting a packet to us so we can discover a source
# EID, send a map-request, or store statistics data.
# The format of the JSON message is:
#
# { "type" : "discovery", "source-eid" : <eid-source-address>, 
#   "dest-eid" : <eid-dest-address>, "interface" : "<device-name>",
#   "instance-id" : <iid> }
# 
# [ { "type" : "statistics", "eid-prefix" : "<eid-prefix>", "rlocs" : [
#     { "rloc" : <rloc-1>, "packet-count" : <count>, "byte-count" : <bcount>,
#       "last-packet" : "<timestamp>" },  ...
#     { "rloc" : <rloc-n>, "packet-count" : <count>, "byte-count" : <bcount>,
#        "last-packet" : "<timestamp>" }
# }, ... ]
#
# { "type" : "restart" }
#
def lisp_itr_process_punt(punt_socket):
    global lisp_send_sockets, lisp_ephem_port

    message, source = punt_socket.recvfrom(4000)

    msg = json.loads(message)
    if (type(msg) != dict):
        lisp.lprint("Invalid punt message from {}, not in JSON format". \
            format(source))
        return
    #endif
    punt = lisp.bold("Punt", False)
    lisp.lprint("{} message from '{}': '{}'".format(punt, source, msg))

    if (msg.has_key("type") == False):
        lisp.lprint("Punt IPC message has no 'type' key")
        return
    #endif

    #
    # Process statistics message.
    #
    if (msg["type"] == "statistics"):
        lisp_itr_process_data_plane_stats(msg)
        return
    #endif

    #
    # Process statistics message.
    #
    if (msg["type"] == "restart"):
        lisp_itr_process_data_plane_restart()
        return
    #endif

    #
    # Process possible punt packet discovery message.
    #
    if (msg["type"] != "discovery"):
        lisp.lprint("Punt IPC message has wrong format")
        return
    #endif
    if (msg.has_key("interface") == False):
        lisp.lprint("Invalid punt message from {}, required keys missing". \
            format(source))
        return
    #endif

    device = msg["interface"]
    iid = lisp.lisp_get_interface_instance_id(device, None)

    #
    # Validate EID format.
    #
    seid = None
    if (msg.has_key("source-eid")):
        source_eid = msg["source-eid"]
        seid = lisp.lisp_address(lisp.LISP_AFI_NONE, source_eid, 0, iid)
        if (seid.is_null()):
            lisp.lprint("Invalid source-EID format '{}'".format(source_eid))
            return
        #endif
    #endif
    deid = None
    if (msg.has_key("dest-eid")):
        dest_eid = msg["dest-eid"]
        deid = lisp.lisp_address(lisp.LISP_AFI_NONE, dest_eid, 0, iid)
        if (deid.is_null()):
            lisp.lprint("Invalid dest-EID format '{}'".format(dest_eid))
            return
        #endif
    #endif

    #
    # Do source-EID discovery.
    #
    # Make sure we have a configured database-mapping entry for this EID.
    #
    if (seid):
        e = lisp.green(seid.print_address(), False)
        db = lisp.lisp_db_for_lookups.lookup_cache(seid, False)
        if (db != None):

            #
            # Check accept policy and if accepted, discover EID by putting 
            # in discovery cache. ETR will register it.
            #
            if (db.dynamic_eid_configured()):
                interface = lisp.lisp_allow_dynamic_eid(device, seid)
                if (interface != None):
                    lisp_itr_discover_eid(db, seid, device, interface)
                else:
                    lisp.lprint(("Disallow dynamic source-EID {} " + \
                        "on interface {}").format(e, device))
                #endif
            #endif
        else:
            lisp.lprint("Punt from non-EID source {}".format(e))
        #endif
    #endif

    #
    # Do Map-Request processing on destination.
    #
    if (deid):
        mc = lisp.lisp_map_cache_lookup(seid, deid)
        if (mc == None or mc.action == lisp.LISP_SEND_MAP_REQUEST_ACTION):

            #
            # Check if we should rate-limit Map-Request and if not send
            # Map-Request.
            #
            if (lisp.lisp_rate_limit_map_request(seid, deid)): return
            lisp.lisp_send_map_request(lisp_send_sockets, lisp_ephem_port, 
                seid, deid, None)
        else:
            e = lisp.green(deid.print_address(), False)
            lisp.lprint("Map-cache entry for {} already exists".format(e))
        #endif
    #endif
#enddef

#
# lisp_itr_discover_eid
#
# Put dynamic-EID in db.dynamic_eids{} array.
#
def lisp_itr_discover_eid(db, eid, input_interface, routed_interface):
    eid_str = eid.print_address()
    if (db.dynamic_eids.has_key(eid_str)): 
        db.dynamic_eids[eid_str].last_packet = lisp.lisp_get_timestamp()
        return
    #endif

    #
    # Add to list.
    #
    dyn_eid = lisp.lisp_dynamic_eid()
    dyn_eid.dynamic_eid.copy_address(eid)
    dyn_eid.interface = routed_interface
    dyn_eid.last_packet = lisp.lisp_get_timestamp()
    dyn_eid.get_timeout(routed_interface)
    db.dynamic_eids[eid_str] = dyn_eid

    routed = ""
    if (input_interface != routed_interface):
        routed = ", routed-interface " + routed_interface
    #endif

    eid_string = lisp.green(eid_str, False) + lisp.bold(" discovered", False)
    lisp.lprint("Dynamic-EID {} on interface {}{}, timeout {}".format( \
        eid_string,input_interface, routed, dyn_eid.timeout))

    #
    # Tell ETR process so it can register dynamic-EID.
    #
    ipc = "learn%{}%{}".format(eid_str, routed_interface)
    ipc = lisp.lisp_command_ipc(ipc, "lisp-itr")
    lisp.lisp_ipc(ipc, lisp_ipc_listen_socket, "lisp-etr")
    return
#enddef

#
# lisp_itr_data_plane
#
# Do map-cache lookup and encapsulate packet.
#
def lisp_itr_data_plane(packet, device, input_interface, macs, my_sa):
    global lisp_send_sockets
    global lisp_ephem_port
    global lisp_raw_socket, lisp_raw_v6_socket
    global lisp_ipc_listen_socket

    #
    # Check RLOC-probe Map-Reply. We need to grab the TTL from IP header.
    #
    orig_packet = packet
    packet, source, port, ttl = lisp.lisp_is_rloc_probe(packet, 1)
    if (orig_packet != packet):
        if (source == None): return
        lisp.lisp_parse_packet(lisp_send_sockets, packet, source, port, ttl)
        return
    #endif

    packet = lisp.lisp_packet(packet)
    if (packet.decode(False, None, None) == None): return

    #
    # For locally source packets from this system, the MAC address may
    # be the default router. Check source to see if assigned to this system,
    # and if so, accept on interface "device".
    #
    if (my_sa): input_interface = device

    #
    # Get instance-ID for incoming interface.
    #
    source_eid = packet.inner_source
    iid = lisp.lisp_get_interface_instance_id(input_interface, source_eid)
    packet.inner_dest.instance_id = iid
    packet.inner_source.instance_id = iid

    #
    # Print some useful header fields and strip outer headers..
    #
    if (macs != ""): macs = ", MACs: " + macs + ","
    packet.print_packet("Receive {}{}".format(device, macs), False)

    #
    # Drop packet if input interface not found based on MAC address used.
    #
    if (device != input_interface):
        lisp.dprint("Not our MAC address on interface {}, pcap interface {}". \
            format(input_interface, device))
        return
    #endif

    lisp_decent = lisp.lisp_decent_configured
    if (lisp_decent):
        multicast = packet.inner_dest.is_multicast_address()
        local = packet.inner_source.is_local()
        lisp_decent = (local and multicast)
    #endif

    if (lisp_decent == False):

        #
        # Only forward packets from source-EIDs.
        #
        db = lisp.lisp_db_for_lookups.lookup_cache(packet.inner_source, False)
        if (db == None):
            lisp.dprint("Packet received from non-EID source")
            return
        #endif

        #
        # Check to see if we are doing dynamic-EID discovery.
        #
        if (db.dynamic_eid_configured()):
            i = lisp.lisp_allow_dynamic_eid(input_interface, 
                packet.inner_source)
            if (i):
                lisp_itr_discover_eid(db, packet.inner_source, 
                    input_interface, i)
            else:
                e = lisp.green(packet.inner_source.print_address(), False)
                lisp.dprint("Disallow dynamic-EID {} on interface {}".format(e,
                    input_interface))
                return
            #endif
        #endif

        if (packet.inner_source.is_local() and 
            packet.udp_dport == lisp.LISP_CTRL_PORT): return
    #endif

    #
    # Do input processing for currently supported packet types..
    #
    if (packet.inner_version == 4):
        packet.packet = lisp.lisp_ipv4_input(packet.packet)
        if (packet.packet == None): return
        packet.inner_ttl -= 1
    elif (packet.inner_version == 6):
        packet.packet = lisp.lisp_ipv6_input(packet)
        if (packet.packet == None): return
        packet.inner_ttl -= 1
    else:
        packet.packet = lisp.lisp_mac_input(packet.packet)
        if (packet.packet == None): return
        packet.encap_port = lisp.LISP_L2_DATA_PORT
    #endif

    #
    # First check if destination is to any local EID-prefixes from database-
    # mapping commands. In this case, we need to natively forward.
    #
    if (lisp_xtr_loopback == False):
        db = lisp.lisp_db_for_lookups.lookup_cache(packet.inner_dest, False)
        if (db and db.dynamic_eid_configured == False):
            lisp.dprint(("Packet destined to local EID-prefix {}, " + \
                "natively forwarding").format(db.print_eid_tuple()))
            packet.send_packet(lisp_raw_socket, packet.inner_dest)
            return
        #endif
    #endif

    # 
    # Do map-cache lookup.
    #
    mc = lisp.lisp_map_cache_lookup(packet.inner_source, packet.inner_dest)

    #
    # If "secondary-iid" is configured, we want to check the secondary 
    # map-cache if a lookup miss occured in the default IID for this source 
    # EID-prefix. If destination EID found in secondary map-cache, use it.
    # Otherwise, send Map-Request for EID in default IID.
    #
    secondary_iid = db.secondary_iid if (db != None) else None
    if (secondary_iid and mc and mc.action == lisp.LISP_NATIVE_FORWARD_ACTION):
        dest_eid = packet.inner_dest
        dest_eid.instance_id = secondary_iid
        mc = lisp.lisp_map_cache_lookup(packet.inner_source, dest_eid)
    #endif

    #
    # Map-cache lookup miss.
    #
    if (mc == None or mc.action == lisp.LISP_SEND_MAP_REQUEST_ACTION):
        if (lisp.lisp_rate_limit_map_request(packet.inner_source, 
            packet.inner_dest)): return
        lisp.lisp_send_map_request(lisp_send_sockets, lisp_ephem_port, 
            packet.inner_source, packet.inner_dest, None)
        return
    #endif

    #
    # Send Map-Request to see if there is a RLOC change or to refresh an
    # entry that is about to time out.
    #
    if (mc and mc.is_active and mc.has_ttl_elapsed()):
        lisp.lprint("Refresh map-cache entry {}".format( \
            lisp.green(mc.print_eid_tuple(), False)))
        lisp.lisp_send_map_request(lisp_send_sockets, lisp_ephem_port, 
            packet.inner_source, packet.inner_dest, None)
    #endif

    #
    # Update stats for entry. Stats per RLOC is done in lisp_mapping.select_
    # rloc().
    #
    mc.stats.increment(len(packet.packet))

    #
    # Encapsulate, native forward, or encapsulate-and-replciate  packet.
    #
    dest_rloc, dest_port, nonce, action, rle = \
        mc.select_rloc(packet, lisp_ipc_listen_socket)

    if (dest_rloc == None and rle == None):
        if (action == lisp.LISP_NATIVE_FORWARD_ACTION):
            lisp.dprint("Natively forwarding")
            packet.send_packet(lisp_raw_socket, packet.inner_dest)
            return
        #endif
        lisp.dprint("No reachable RLOCs found")
        return
    #endif
    if (dest_rloc and dest_rloc.is_null()): 
        lisp.dprint("Drop action RLOC found")
        return
    #endif

    #
    # Setup outer header for either unicast or multicast transmission..
    #
    packet.outer_tos = packet.inner_tos
    packet.outer_ttl = packet.inner_ttl

    #
    # Do unicast encapsulation.
    #
    if (dest_rloc):
        packet.outer_dest.copy_address(dest_rloc)
        version = packet.outer_dest.afi_to_version()
        packet.outer_version = version
        source_rloc = lisp.lisp_myrlocs[0] if (version == 4) else \
            lisp.lisp_myrlocs[1]
        packet.outer_source.copy_address(source_rloc)

        #
        # Encode new LISP, UDP, and outer header.
        #
        if (packet.encode(nonce) == None): return
        if (len(packet.packet) <= 1500): packet.print_packet("Send", True)

        #
        # Send out on raw socket.
        #
        raw_socket = lisp_raw_v6_socket if version == 6 else lisp_raw_socket
        packet.send_packet(raw_socket, packet.outer_dest)

    elif (rle):

        #
        # Do replication of RLE is returned. Since we are an ITR, replicate to
        # level-0 RTRs (or ETRs) only (or first-level boxes only)..
        #
        level = rle.rle_nodes[0].level
        orig_len = len(packet.packet)
        for node in rle.rle_nodes:
            if (node.level != level): return

            packet.outer_dest.copy_address(node.address)
            if (lisp_decent): packet.inner_dest.instance_id = 0xffffff
            version = packet.outer_dest.afi_to_version()
            packet.outer_version = version
            source_rloc = lisp.lisp_myrlocs[0] if (version == 4) else \
                lisp.lisp_myrlocs[1]
            packet.outer_source.copy_address(source_rloc)

            if (packet.encode(None) == None): return

            #
            # Replicate out on raw socket.
            #
            packet.print_packet("Replicate-to-L{}".format(node.level), True)
            packet.send_packet(lisp_raw_socket, packet.outer_dest)

            #
            # We need to strip the encapsulation header so we can add a new
            # one for the next replication.
            #
            strip_len = len(packet.packet) - orig_len
            packet.packet = packet.packet[strip_len::]
        #endfor
    #endif

    # 
    # Don't need packet structure anymore.
    #
    del(packet)
#enddef

#
# lisp_itr_pcap_process_packet
#
# Receive LISP encapsulated packet from pcap.loop().
#
def lisp_itr_pcap_process_packet(device, not_used, packet):
#   offset = 4 if device == "lo0" else (14 if lisp.lisp_is_macos() else 16)
    offset = 4 if device == "lo0" else 14

    if (lisp.lisp_frame_logging):
        title = lisp.bold("Received frame on interface '{}'".format(device), 
            False)
        frame = lisp.lisp_format_packet(packet[0:64])
        lisp.lprint("{}: {}".format(title, frame))
    #endif
 
    #
    # Get input interface based on source MAC address.
    #
    macs = ""
    my_sa = False
    interface = device
    if (offset == 14): 
        interfaces, sa, da, my_sa = lisp.lisp_get_input_interface(packet)
        interface = device if (device in interfaces) else interfaces[0]
        macs = lisp.lisp_format_macs(sa, da)
        if (interface.find("vlan") != -1): offset +=4

        #
        # If destination MAC address is multicast, set my_sa. Examine low-order
        # bit of first byte by grabbing the second nibble and testing low-order
        # bit after converting to integer.
        #
        if (int(da[1], 16) & 1): my_sa = True
    #endif

    # 
    # Check for VLAN encapsulation.
    #
    ethertype = struct.unpack("H", packet[offset-2:offset])[0]
    ethertype = socket.ntohs(ethertype)
    if (ethertype == 0x8100): 
        vlan = struct.unpack("I", packet[offset:offset+4])[0]
        vlan = socket.ntohl(vlan)
        interface = "vlan" + str(vlan >> 16)
        offset += 4
    elif (ethertype == 0x806):
        lisp.dprint("Dropping ARP packets, host should have default route")
        return
    #endif

    if (lisp.lisp_l2_overlay): offset = 0

    lisp_itr_data_plane(packet[offset::], device, interface, macs, my_sa)
#endef

#
# lisp_itr_kernel_filter
#
# Supplied 'sources' array are the EID-prefixes we want the kernel to drop
# packets for. We will use iptables for Linux and ipfw for MacOS.
#
# We need this address combination support (notation S -> D):
#
#  site-EID -> remote-EID processed by ITR
#  site-EID -> non-EID    processed by ITR
#  site-EID -> site-EID   processed by kernel
#  non-EID  -> non-EID    processed by kernel
#  non-EID  -> remote-EID processed by kernel
#  non-EID  -> site-EID   processed by kernel
#
# The pcap filters reflect the ITR processing combos and can be found in 
# lisp_itr_build_pcap_filter(). This routine programs iptables to do the 
# kernel processing combos.
#
# (1) iptables -t raw -A lisp -j ACCEPT -d <special-addresses>
# (2) iptables -t raw -A lisp -j ACCEPT -d <local-address> ...
# (3) iptables -t raw -A lisp -j ACCEPT -s <site-eid> -d <site-eid> ...
# (4) iptables -t raw -A lisp -j DROP -s <site-eid> ...
#
# (1) and (2), we want kernel to route packets. This allows loopback and 
# multicast to be processed by kernel. 
#
# For (3), we want the kernel to do local routing of packets inside of a site
# in this ITR.
#
# For (4), we want kernel to not touch any packets sourced from locally 
# configured EIDs. That is each EID-prefix from a "lisp database-mapping"
# command. Because those EID-prefixes are pcap'ed and process by the lisp-itr
# process.
#
def lisp_itr_kernel_filter(sources, dyn_eids):
    if (os.getenv("LISP_NO_IPTABLES") != None):
        lisp.lprint("User selected to suppress installing iptables rules")
        return
    #endif
    
    os.system("sudo iptables -t raw -N lisp")
    os.system("sudo iptables -t raw -A PREROUTING -j lisp")
    os.system("sudo ip6tables -t raw -N lisp")
    os.system("sudo ip6tables -t raw -A PREROUTING -j lisp")

    #
    # Have kernel process packets for local addresses when sourced from site
    # EIDs. We do not want the lisp-itr process to process such packets. 
    # We want the kernel to deliver packets to and from local applications. 
    # And we want the kernel to forward decapsulated packets out interfaces 
    # leading the EIDs.
    #
    add = "sudo ip{}tables -t raw -A lisp -j ACCEPT -d {}"
    addr_set = ["127.0.0.1", "::1", "224.0.0.0/4", "ff00::/8", "fe80::/16"]
    addr_set += sources + lisp.lisp_get_all_addresses()
    for addr in addr_set:
        six = "" if addr.find(":") == -1 else "6"
        os.system(add.format(six, addr))
    #endfor

    #
    # When source and destination addresses are EIDs for this LISP site,
    # we want the kernel to do local routing. But as a PITR, we don't want
    # the kernel to route everything (EID-prefix 0.0.0.0/0) or we can't have
    # this process encapsulate for any source address to a destination EID.
    #
    if (lisp.lisp_pitr == False):
        add = "sudo ip{}tables -t raw -A lisp -j ACCEPT -s {} -d {}"
        check = "sudo ip{}tables -t raw -C lisp -j ACCEPT -s {} -d {}"
        for source in sources:
            if (source in dyn_eids): continue
            six = "" if source.find(":") == -1 else "6"
            for s in sources:
                if (s in dyn_eids): continue
                if (s.find(".") != -1 and source.find(".") == -1): continue
                if (s.find(":") != -1 and source.find(":") == -1): continue
                if (commands.getoutput(check.format(six, source, s)) == ""):
                    continue
                #endif
                os.system(add.format(six, source, s))
            #endfor
        #endfor
    #endif

    #
    # Now put in drop rules for each "lisp database-mapping" EID-prefix.
    #
    drop = "sudo ip{}tables -t raw -A lisp -j DROP -s {}"
    for source in sources:
        six = "" if source.find(":") == -1 else "6"
        os.system(drop.format(six, source))
    #endif

    #
    # Print out rules we just configured.
    #
    rules = commands.getoutput("sudo iptables -t raw -S lisp").split("\n")
    rules += commands.getoutput("sudo ip6tables -t raw -S lisp").split("\n")
    lisp.lprint("Using kernel filters: {}".format(rules))

    #
    # Check if we need to put in a iptables rule workaround for the virtio TCP
    # checksum corruption problem for KVM guest OSes. Check environmnt 
    # variable LISP_VIRTIO_BUG.
    #
    if (os.getenv("LISP_VIRTIO_BUG") != None):
        c = ("sudo iptables -A POSTROUTING -t mangle -p tcp -j " + \
            "CHECKSUM --checksum-fill; ")
        c += ("sudo iptables -A POSTROUTING -t mangle -p udp -j " + \
            "CHECKSUM --checksum-fill; ")
        c += ("sudo ip6tables -A POSTROUTING -t mangle -p tcp -j " + \
            "CHECKSUM --checksum-fill; ")
        c += ("sudo ip6tables -A POSTROUTING -t mangle -p udp -j " + \
            "CHECKSUM --checksum-fill")
        os.system(c)
        virtio = lisp.bold("virtio", False)
        lisp.lprint("{} bug workaround, configure '{}'".format(virtio, c))
    #endif
#enddef

#
# lisp_itr_build_pcap_filter
#
# Build pcap filter and return string to caller.
#
def lisp_itr_build_pcap_filter(sources, dyn_eids, l2_overlay, pitr):
    if (l2_overlay):
        pfilter = "ether[6:4] >= 0 and ether[10:2] >= 0"
        lisp.lprint("Using pcap filter: '{}'".format(pfilter))
        return(pfilter)
    #endif

    ether_pfilter = "(not ether proto 0x806)"
    probe_pfilter = " or (udp src port 4342 and ip[28] == 0x28)"
    decent_pfilter = \
        " or (ip[16] >= 224 and ip[16] < 240 and (ip[28] & 0xf0) == 0x30)"

    src_pfilter = ""
    dst_pfilter = ""
    for source in sources:
        src_pfilter += "{}".format(source)
        if (source not in dyn_eids): dst_pfilter += "{}".format(source)
        if (sources[-1] == source): break
        src_pfilter += " or "
        if (source not in dyn_eids): dst_pfilter += " or "
    #endfor
    if (dst_pfilter[-4::] == " or "): dst_pfilter = dst_pfilter[0:-4]

    #
    # If "lisp-nat = yes" is configured, then we are a PETR and we need
    # to accept packets for local EIDs (assigned to loopback interfaces).
    # So allow the first one to be accepted.
    #
    lisp_nat = commands.getoutput("egrep 'lisp-nat = yes' ./lisp.config")
    lisp_nat = (lisp_nat != "" and lisp_nat[0] == " ")
    loopback = lisp.lisp_get_loopback_address() if (lisp_nat) else None

    addr_pfilter = ""
    addresses = lisp.lisp_get_all_addresses()
    for addr in addresses:
        if (addr == loopback): continue
        addr_pfilter += "{}".format(addr)
        if (addresses[-1] == addr): break
        addr_pfilter += " or "
    #endif

    if (src_pfilter != ""):
        src_pfilter = " and (src net {})".format(src_pfilter)
    #endif
    if (dst_pfilter != ""):
        dst_pfilter = " and not (dst net {})".format(dst_pfilter)
    #endif
    if (addr_pfilter != ""):
        addr_pfilter = " and not (dst host {})".format(addr_pfilter)
    #endif

    #
    # A PITR wants to see packets from anywhere so it can encap to possible
    # LISP sites. But we want the kernel to route and consume for RLOCs for
    # this system.
    #
    if (pitr):
        dst_pfilter = ""
        addr_pfilter = addr_pfilter.replace("dst ", "")
    #endif

    #
    # Concatenate all the filters.
    #
    pfilter = ether_pfilter + src_pfilter + dst_pfilter + addr_pfilter
    pfilter += probe_pfilter
    pfilter += decent_pfilter

    lisp.lprint("Using pcap filter: '{}'".format(pfilter))
    return(pfilter)
#enddef

#
# lisp_itr_pcap_thread
#
# Receive LISP encapsulated packet from pcap.
#
def lisp_itr_pcap_thread(device, pfilter, pcap_lock):
    lisp.lisp_set_exception()

    pcap_lock.acquire()
    pcap = pcappy.open_live(device, 9000, 0, 100)
    pcap_lock.release()

    pcap.filter = pfilter
    pcap.loop(-1, lisp_itr_pcap_process_packet, device)
#enddef

#
# lisp_itr_process_info_timer
#
# Time to send a periodic Info-Request message. This must be done less often
# then sending periodic Map-Registers as well as less the the NAT timeout
# value which is usually one minute.
#
def lisp_itr_process_info_timer():
    global lisp_itr_info_timer
    global lisp_ephem_nat_socket
    global lisp_send_sockets

    lisp.lisp_set_exception()

    #
    # Build Info-Request messages if we have any private RLOCs in database-
    # mappings.
    #
    sockets = [lisp_ephem_nat_socket, lisp_ephem_nat_socket, 
        lisp_ipc_listen_socket]
    lisp.lisp_build_info_requests(sockets, None, lisp.LISP_CTRL_PORT)

    #
    # Restart periodic timer.
    #
    lisp_itr_info_timer.cancel()
    lisp_itr_info_timer = threading.Timer(lisp.LISP_INFO_INTERVAL, 
        lisp_itr_process_info_timer, [])
    lisp_itr_info_timer.start()
#enddef

#
# lisp_itr_map_resolver_command
#
# Call lispconfig.lisp_map_resolver_command and set "test-mr" timer.
#
def lisp_itr_map_resolver_command(kv_pair):
    global lisp_send_sockets
    global lisp_ephem_port
    global lisp_itr_info_timer

    lispconfig.lisp_map_resolver_command(kv_pair)

    if (lisp.lisp_test_mr_timer == None or 
        lisp.lisp_test_mr_timer.is_alive() == False):
        lisp.lisp_test_mr_timer = threading.Timer(2, lisp.lisp_test_mr, 
            [lisp_send_sockets, lisp_ephem_port])
        lisp.lisp_test_mr_timer.start()
    #endif

    #
    # Trigger a Info-Request if we are doing NAT-traversal.
    #
    lisp_itr_info_timer = threading.Timer(0, lisp_itr_process_info_timer, [])
    lisp_itr_info_timer.start()
#enddef

#
# lisp_itr_database_mapping_command
# 
# Add database-mapping entry so ITR can packet capture on packets only from
# sources from the *first* database-mapping configured.
#
def lisp_itr_database_mapping_command(kv_pair):
    lispconfig.lisp_database_mapping_command(kv_pair)
#endef

#
# lisp_itr_xtr_command
#
# Call lispconfig.lisp_xtr_command() but pass socket parameters to starting
# the RLOC-probing timer if "rloc-probing = yes".
#
def lisp_itr_xtr_command(kv_pair):
    global lisp_ephem_listen_socket

    #
    # Cache current state for nat-traversal and rloc-probing so we know if
    # we should trigger..
    #
    nat_traversal = lisp.lisp_nat_traversal
    rloc_probing = lisp.lisp_rloc_probing

    #
    # Execute command.
    #
    lispconfig.lisp_xtr_command(kv_pair)

    #
    # Did "nat-traversal = yes" or "rloc-probing = yes" just happen?
    #
    nat_now_on = (nat_traversal == False and lisp.lisp_nat_traversal and \
        lisp.lisp_rloc_probing)
    rloc_probing_now_on = (rloc_probing == False and lisp.lisp_rloc_probing)

    interval = 0
    if (rloc_probing_now_on): interval = 1
    if (nat_now_on): interval = 5
    
    if (interval != 0):
        lisp_sockets = [lisp_ephem_listen_socket, lisp_ephem_listen_socket]
        lisp.lisp_start_rloc_probe_timer(interval, lisp_sockets)
    #endif

    #
    # If nat-traversal=yes and data-plane-security=yes on an ITR, then we
    # need to set source port in RLOC-probe requrests and encapsulated data
    # packets to be the same value.
    #
    if (lisp.lisp_crypto_ephem_port == None and lisp.lisp_nat_traversal and 
        lisp.lisp_data_plane_security):
        port = lisp_ephem_listen_socket.getsockname()[1]
        lisp.lisp_crypto_ephem_port = port
        lisp.lprint("Use port {} for NAT-based lisp-crypto".format(port))
    #endif

    #
    # Write to external data-plane if enabled.
    #
    lisp.lisp_ipc_write_xtr_parameters(lisp.lisp_debug_logging,
        lisp.lisp_data_plane_logging)
#enddef

#
# lisp_itr_process_nonce_ipc
#
# Process an nonce IPC message from the ETR. It wants to tell us that a
# request-nonce was received and we need to echo it or when this ITR requested
# a nonce to be echoed, the ETR is telling us it has been echoed.
#
def lisp_itr_process_nonce_ipc(ipc):
    x, opcode, rloc_str, nonce = ipc.split("%")
    nonce = int(nonce, 16)

    echo_nonce = lisp.lisp_get_echo_nonce(None, rloc_str)
    if (echo_nonce == None): echo_nonce = lisp.lisp_echo_nonce(rloc_str)

    #
    # If we are in request-nonce mode, exit it, so we can echo the nonce the
    # other side is requesting.
    #
    if (opcode == "R"):
        echo_nonce.request_nonce_rcvd = nonce
        echo_nonce.last_request_nonce_rcvd = lisp.lisp_get_timestamp()
        echo_nonce.echo_nonce_sent = nonce
        echo_nonce.last_new_echo_nonce_sent = lisp.lisp_get_timestamp()
        lisp.lprint("Start echo-nonce mode for {}, nonce 0x{}".format( \
            lisp.red(echo_nonce.rloc_str, False), lisp.lisp_hex_string(nonce)))
    #endif

    if (opcode == "E"):
        echo_nonce.echo_nonce_rcvd = nonce
        echo_nonce.last_echo_nonce_rcvd = lisp.lisp_get_timestamp()

        if (echo_nonce.request_nonce_sent == nonce):
            en = lisp.bold("echoed nonce", False)
            lisp.lprint("Received {} {} from {}".format(en,
                lisp.lisp_hex_string(nonce), 
                lisp.red(echo_nonce.rloc_str, False)))

            echo_nonce.request_nonce_sent = None
            lisp.lprint("Stop request-nonce mode for {}".format( \
                lisp.red(echo_nonce.rloc_str, False)))
            echo_nonce.last_good_echo_nonce_rcvd = lisp.lisp_get_timestamp()
        else:
            rns = "none"
            if (echo_nonce.request_nonce_sent):
                rns = lisp.lisp_hex_string(echo_nonce.request_nonce_sent)
            #endif
            lisp.lprint(("Received echo-nonce 0x{} from {}, but request-" + \
                "nonce is {}").format(lisp.lisp_hex_string(nonce),
                lisp.red(echo_nonce.rloc_str, False), rns))
        #endif
    #endif
#enddef

#
# ITR commands procssed by this process.
#
lisp_itr_commands = {
    "lisp xtr-parameters" : [lisp_itr_xtr_command, {
        "rloc-probing" : [True, "yes", "no"],
        "nonce-echoing" : [True, "yes", "no"],
        "data-plane-security" : [True, "yes", "no"],
        "data-plane-logging" : [True, "yes", "no"],
        "frame-logging" : [True, "yes", "no"],
        "flow-logging" : [True, "yes", "no"],
        "nat-traversal" : [True, "yes", "no"],
        "checkpoint-map-cache" : [True, "yes", "no"],
        "ipc-data-plane" : [True, "yes", "no"],
        "decentralized-xtr" : [True, "yes", "no"],
        "program-hardware" : [True, "yes", "no"] }],

    "lisp interface" : [lispconfig.lisp_interface_command, {
        "interface-name" : [True],
        "device" : [True],
        "instance-id" : [True, 0, 0xffffffff], 
        "dynamic-eid" : [True],
        "multi-tenant-eid" : [True],
        "lisp-nat" : [True, "yes", "no"],
        "dynamic-eid-device" : [True],
        "dynamic-eid-timeout" : [True, 0, 0xff] }],

    "lisp map-resolver" : [lisp_itr_map_resolver_command, {
        "mr-name" : [True],
        "ms-name" : [True],
        "dns-name" : [True],
        "address" : [True] }],

    "lisp database-mapping" : [lisp_itr_database_mapping_command, {
        "prefix" : [], 
        "mr-name" : [True],
        "ms-name" : [True],
        "instance-id" : [True, 0, 0xffffffff],  
        "secondary-instance-id" : [True, 0, 0xffffffff], 
        "eid-prefix" : [True], 
        "group-prefix" : [True], 
        "dynamic-eid" : [True, "yes", "no"],
        "signature-eid" : [True, "yes", "no"],
        "rloc" : [], 
        "rloc-record-name" : [True],
        "elp-name" : [True],
        "geo-name" : [True],
        "rle-name" : [True],
        "json-name" : [True],
        "address" : [True], 
        "interface" : [True], 
        "priority" : [True, 0, 255], 
        "weight" : [True, 0, 100] }],

    "lisp map-cache" : [lispconfig.lisp_map_cache_command, {
        "prefix" : [], 
        "instance-id" : [True, 0, 0xffffffff],  
        "eid-prefix" : [True], 
        "group-prefix" : [True], 
        "send-map-request" : [True, "yes", "no"], 
        "rloc" : [], 
        "rloc-record-name" : [True],
        "rle-name" : [True],
        "elp-name" : [True],
        "address" : [True], 
        "priority" : [True, 0, 255], 
        "weight" : [True, 0, 100] }],

    "lisp itr-map-cache" : [lispconfig.lisp_map_cache_command, {
        "prefix" : [], 
        "instance-id" : [True, 0, 0xffffffff],  
        "eid-prefix" : [True], 
        "group-prefix" : [True], 
        "rloc" : [], 
        "rloc-record-name" : [True],
        "rle-name" : [True],
        "elp-name" : [True],
        "address" : [True], 
        "priority" : [True, 0, 255], 
        "weight" : [True, 0, 100] }],

    "lisp explicit-locator-path" : [lispconfig.lisp_elp_command, {
        "elp-name" : [False], 
        "elp-node" : [], 
        "address" : [True], 
        "probe" : [True, "yes", "no"],
        "strict" : [True, "yes", "no"],
        "eid" : [True, "yes", "no"] }], 

    "lisp replication-list-entry" : [lispconfig.lisp_rle_command, {
        "rle-name" : [False], 
        "rle-node" : [], 
        "address" : [True], 
        "level" : [True, 0, 255] }], 

    "lisp geo-coordinates" : [lispconfig.lisp_geo_command, {
        "geo-name" : [False],
        "geo-tag" : [False] }],

    "show itr-map-cache" : [lisp_itr_show_command, { }],
    "show itr-rloc-probing" : [lisp_itr_show_rloc_probe_command, { }],
    "show itr-keys" : [lisp_itr_show_keys_command, {}],
    "show itr-dynamic-eid" : [lispconfig.lisp_show_dynamic_eid_command, { }]
}

#------------------------------------------------------------------------------

#
# Main entry point for process.
#
if (lisp_itr_startup() == False):
    lisp.lprint("lisp_itr_startup() failed")
    lisp.lisp_print_banner("ITR abnormal exit")
    exit(1)
#endif

socket_list = [lisp_ephem_listen_socket, lisp_ipc_listen_socket, 
    lisp_ephem_nat_socket, lisp_ipc_punt_socket]

#
# Should we listen to the map-cache/punt IPC socket if it exists.
#
listen_on_ipc_socket = True
ephem_sockets = [lisp_ephem_listen_socket] * 3
ephem_nat_sockets = [lisp_ephem_nat_socket] * 3

while (True):
    try: ready_list, w, x = select.select(socket_list, [], [])
    except: break

    #
    # Process Punt signal message from another data-plane (snabb).
    #
    if (lisp.lisp_ipc_data_plane and lisp_ipc_punt_socket in ready_list):
        lisp_itr_process_punt(lisp_ipc_punt_socket)
    #endif

    #
    # Process Map-Reply messages received on ephemeral port.
    #
    if (lisp_ephem_listen_socket in ready_list):
        opcode, source, port, packet = lisp.lisp_receive(ephem_sockets[0], 
            False)
        if (source == ""): break

        if (lisp.lisp_is_rloc_probe_reply(packet[0])): continue
        lisp.lisp_parse_packet(ephem_sockets, packet, source, port)
    #endif

    #
    # Process Info-Reply messages received on NAT ephemeral port.
    #
    if (lisp_ephem_nat_socket in ready_list):
        opcode, source, port, packet = lisp.lisp_receive(ephem_nat_sockets[0], 
            False)
        if (source == ""): break

        if (lisp.lisp_is_rloc_probe_reply(packet[0])): continue
        probe = lisp.lisp_parse_packet(ephem_nat_sockets, packet, source, port)

        #
        # Info-Reply has new RTR-list, RLOC-probe the RTR RLOCs so we can
        # lisp-crypto faster.
        #
        if (probe): 
            lisp_sockets = [lisp_ephem_listen_socket, lisp_ephem_listen_socket]
            lisp.lisp_start_rloc_probe_timer(0, lisp_sockets)
        #endif
    #endif

    #
    # Process either commands, an IPC data-packet (for testing), or any
    # protocol message on the IPC listen socket.
    #
    if (lisp_ipc_listen_socket in ready_list):
        opcode, source, port, packet = \
            lisp.lisp_receive(lisp_ipc_listen_socket, True)
        if (source == ""): break

        if (opcode == "command"): 
            if (packet == "clear"): 
                lisp.lisp_clear_map_cache()
                continue
            #endif
            if (packet.find("nonce%") != -1):
                lisp_itr_process_nonce_ipc(packet)
                continue
            #endif
            lispconfig.lisp_process_command(lisp_ipc_listen_socket, opcode, 
                packet, "lisp-itr", [lisp_itr_commands])
        elif (opcode == "api"):
            lisp.lisp_process_api("lisp-itr", lisp_ipc_listen_socket, packet)
        elif (opcode == "data-packet"):
            lisp_itr_data_plane(packet, "ipc")
        else:
            if (lisp.lisp_is_rloc_probe_reply(packet[0])): continue
            lisp.lisp_parse_packet(lisp_send_sockets, packet, source, port)
        #endif
    #endif

#endwhile

lisp_itr_shutdown()
lisp.lisp_print_banner("ITR normal exit")
exit(0)

#------------------------------------------------------------------------------