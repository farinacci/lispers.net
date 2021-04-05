# -----------------------------------------------------------------------------
#             
# Copyright 2013-2019 lispers.net - Dino Farinacci <farinacci@gmail.com>
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.    
# 
# -----------------------------------------------------------------------------
#
# lisp-itr.py
#
# This file performs LISP Ingress Tunnel Router (ITR) functionality.
#
# -----------------------------------------------------------------------------

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
    return
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
    return
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
    # This is used by the ITR to send RTR status change information to the
    # ETR. Since RLOC-probing runs inside the lisp library, when state changes
    # occur, an IPC will have to be sent from the timer thread. This is the
    # only use-case for lisp.lisp_ipc_socket.
    #
    lisp.lisp_ipc_socket = lisp_ipc_listen_socket

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
    # system. But make sure the device is up on A10 devices. If ethernet MAC
    # capturing, do not listen on non ethernet interfaces.
    #
    mac_capturing = (pfilter.find("ether host") != -1)
    for device in interfaces:
        if (device in ["lo", "lispers.net"] and mac_capturing):
            lisp.lprint(("Capturing suppressed on interface {}, " + \
                "MAC filters configured").format(device))
            continue
        #endif

        #
        # MacOS uses one interface for the RLOC interface as well as the
        # EID interface.
        #
        if (lisp.lisp_is_macos() and device != "en0"): continue

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
    return
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
    if (device != input_interface and device != "lispers.net"):
        lisp.dprint("Not our MAC address on interface {}, pcap interface {}". \
            format(input_interface, device))
        return
    #endif

    lisp_decent = lisp.lisp_decent_push_configured
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
                lisp.lisp_itr_discover_eid(db, packet.inner_source, 
                    input_interface, i, lisp_ipc_listen_socket)
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
    igmp = False
    if (packet.inner_version == 4):
        igmp, packet.packet = lisp.lisp_ipv4_input(packet.packet)
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
    if (mc): mc.add_recent_source(packet.inner_source)

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
        if (mc): mc.add_recent_source(packet.inner_source)
    #endif

    #
    # Map-cache lookup miss.
    #
    if (mc == None or lisp.lisp_mr_or_pubsub(mc.action)):
        if (lisp.lisp_rate_limit_map_request(packet.inner_dest)): return

        pubsub = (mc and mc.action == lisp.LISP_SEND_PUBSUB_ACTION)
        lisp.lisp_send_map_request(lisp_send_sockets, lisp_ephem_port, 
            packet.inner_source, packet.inner_dest, None, pubsub)

        if (packet.is_trace()):
            lisp.lisp_trace_append(packet, reason="map-cache miss")
        #endif
        return
    #endif

    #
    # Send Map-Request to see if there is a RLOC change or to refresh an
    # entry that is about to time out.
    #
    if (mc and mc.is_active() and mc.has_ttl_elapsed()):
        if (lisp.lisp_rate_limit_map_request(packet.inner_dest) == False):
            lisp.lprint("Refresh map-cache entry {}".format( \
                lisp.green(mc.print_eid_tuple(), False)))
            lisp.lisp_send_map_request(lisp_send_sockets, lisp_ephem_port, 
                packet.inner_source, packet.inner_dest, None)
        #endif
    #endif

    #
    # Update stats for entry. Stats per RLOC is done in lisp_mapping.select_
    # rloc().
    #
    mc.last_refresh_time = time.time()
    mc.stats.increment(len(packet.packet))

    #
    # Encapsulate, native forward, or encapsulate-and-replciate  packet.
    #
    dest_rloc, dest_port, nonce, action, rle, rloc_entry = \
        mc.select_rloc(packet, lisp_ipc_listen_socket)

    if (dest_rloc == None and rle == None):
        if (action == lisp.LISP_NATIVE_FORWARD_ACTION):
            lisp.dprint("Natively forwarding")
            packet.send_packet(lisp_raw_socket, packet.inner_dest)

            if (packet.is_trace()):
                lisp.lisp_trace_append(packet, reason="not an EID")
            #endif
            return
        #endif
        r = "No reachable RLOCs found"
        lisp.dprint(r)
        if (packet.is_trace()): lisp.lisp_trace_append(packet, reason=r)
        return
    #endif
    if (dest_rloc and dest_rloc.is_null()): 
        r = "Drop action RLOC found"
        lisp.dprint(r)

        if (packet.is_trace()): lisp.lisp_trace_append(packet, reason=r)
        return
    #endif

    #
    # Setup outer header for either unicast or multicast transmission..
    #
    packet.outer_tos = packet.inner_tos
    packet.outer_ttl = 32 if (igmp) else packet.inner_ttl

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

        if (packet.is_trace()):
            if (lisp.lisp_trace_append(packet, rloc_entry=rloc_entry) \
                == False): return
        #endif

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
        for node in rle.rle_forwarding_list:
            if (node.level != level): return

            packet.outer_dest.copy_address(node.address)
            if (lisp_decent): packet.inner_dest.instance_id = 0xffffff
            version = packet.outer_dest.afi_to_version()
            packet.outer_version = version
            source_rloc = lisp.lisp_myrlocs[0] if (version == 4) else \
                lisp.lisp_myrlocs[1]
            packet.outer_source.copy_address(source_rloc)

            if (packet.is_trace()):
                if (lisp.lisp_trace_append(packet) == False): return
            #endif

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
    return
#enddef

#
# lisp_itr_pcap_process_packet
#
# Receive LISP encapsulated packet from pcap.loop().
#
def lisp_itr_pcap_process_packet(device, not_used, packet):
    offset = 4 if device == "lo0" else 0 if device == "lispers.net" else 14

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
    if (offset != 0):
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
    #endif

    if (lisp.lisp_l2_overlay): offset = 0

    lisp_itr_data_plane(packet[offset::], device, interface, macs, my_sa)
    return
#enddef

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
    addr_set = ["127.0.0.1", "::1", "224.0.0.0/4 -p igmp", "ff00::/8",
        "fe80::/16"]
    addr_set += sources + lisp.lisp_get_all_addresses()
    for addr in addr_set:
        if (lisp.lisp_is_mac_string(addr)): continue
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
            if (lisp.lisp_is_mac_string(source)): continue
            if (source in dyn_eids): continue
            six = "" if source.find(":") == -1 else "6"
            for s in sources:
                if (lisp.lisp_is_mac_string(s)): continue
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
        if (lisp.lisp_is_mac_string(source)): continue
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
    # Note a debian host system that runs docker will need the following
    # command so ip6tables works inside of the docker container:
    #
    #   sudo modprobe ip6table_filter
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
    return
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
        insert_source = source
        if (lisp.lisp_is_mac_string(source)):
            insert_source = source.split("/")[0]
            insert_source = insert_source.replace("-", "")
            mac_str = []
            for i in range(0, 12, 2): mac_str.append(insert_source[i:i+2])
            insert_source = "ether host " + ":".join(mac_str)
        #endif

        src_pfilter += "{}".format(insert_source)
        if (source not in dyn_eids): dst_pfilter += "{}".format(insert_source)
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
    return
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
    return
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
    return
#enddef

#
# lisp_itr_database_mapping_command
# 
# Add database-mapping entry so ITR can packet capture on packets only from
# sources from the *first* database-mapping configured.
#
def lisp_itr_database_mapping_command(kv_pair):
    lispconfig.lisp_database_mapping_command(kv_pair)
    return
#enddef

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
    if (lisp.lisp_crypto_ephem_port == None and lisp.lisp_data_plane_security):
        port = lisp_ephem_listen_socket.getsockname()[1]
        lisp.lisp_crypto_ephem_port = port
        lisp.lprint("Use port {} for lisp-crypto packets".format(port))
        entry = { "type" : "itr-crypto-port", "port" : port }
        lisp.lisp_write_to_dp_socket(entry)
    #endif

    #
    # Write to external data-plane if enabled.
    #
    lisp.lisp_ipc_write_xtr_parameters(lisp.lisp_debug_logging,
        lisp.lisp_data_plane_logging)
    return
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
    return
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
        "decentralized-push-xtr" : [True, "yes", "no"],
        "decentralized-pull-xtr-modulus" : [True, 1, 0xff],
        "decentralized-pull-xtr-dns-suffix" : [True],
        "register-reachable-rtrs" : [True, "yes", "no"],
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

    "lisp map-server" : [lispconfig.lisp_map_server_command, {
        "ms-name" : [True],
        "address" : [True], 
        "dns-name" : [True], 
        "authentication-type" : [False, "sha1", "sha2"],
        "authentication-key" : [False], 
        "encryption-key" : [False], 
        "proxy-reply" : [False, "yes", "no"],
        "want-map-notify" : [False, "yes", "no"],
        "merge-registrations" : [False, "yes", "no"],
        "refresh-registrations" : [False, "yes", "no"],
        "site-id" : [False, 1, 0xffffffffffffffff] }],

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
        "register-ttl" : [True, 1, 0xffffffff], 
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
        "subscribe-request" : [True, "yes", "no"], 
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

    "lisp json" : [lispconfig.lisp_json_command, {
        "json-name" : [False],
        "json-string" : [False] }],

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
        lisp.lisp_process_punt(lisp_ipc_punt_socket, lisp_send_sockets,
            lisp_ephem_port)
    #endif

    #
    # Process Map-Reply messages received on ephemeral port.
    #
    if (lisp_ephem_listen_socket in ready_list):
        opcode, source, port, packet = lisp.lisp_receive(ephem_sockets[0], 
            False)
        if (source == ""): break

        if (lisp.lisp_is_rloc_probe_reply(packet[0])):
            lisp.lprint("ITR ignoring RLOC-probe reply, using pcap")
            continue
        #endif
        lisp.lisp_parse_packet(ephem_sockets, packet, source, port)
    #endif

    #
    # Process Info-Reply messages received on NAT ephemeral port.
    #
    if (lisp_ephem_nat_socket in ready_list):
        opcode, source, port, packet = lisp.lisp_receive(ephem_nat_sockets[0], 
            False)
        if (source == ""): break

        if (lisp.lisp_is_rloc_probe_reply(packet[0])):
            lisp.lprint("ITR ignoring RLOC-probe reply, using pcap")
            continue
        #endif
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
            if (lisp.lisp_is_rloc_probe_reply(packet[0])):
                lisp.lprint("ITR ignoring RLOC-probe request, using pcap")
                continue
            #endif
            lisp.lisp_parse_packet(lisp_send_sockets, packet, source, port)
        #endif
    #endif

#endwhile

lisp_itr_shutdown()
lisp.lisp_print_banner("ITR normal exit")
exit(0)

#------------------------------------------------------------------------------
