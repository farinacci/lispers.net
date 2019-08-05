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
# lisp-rtr.py
#
# This file performs LISP Reencapsualting Tunnel Router (RTR) functionality.
#
# -----------------------------------------------------------------------------

import lisp
import lispconfig
import socket
import time
import select
import threading
import pcappy
import os
import copy
import commands
import binascii

#------------------------------------------------------------------------------

#
# Global data structures relative to the lisp-itr process.
#
lisp_send_sockets = [None, None, None]
lisp_trace_listen_socket = None
lisp_ipc_listen_socket = None
lisp_ipc_punt_socket = None
lisp_ephem_listen_socket = None
lisp_ephem_port = lisp.lisp_get_ephemeral_port()
lisp_raw_socket = None
lisp_raw_v6_socket = None
lisp_periodic_timer = None

lisp_threads = []

#
# In AWS, the source RLOC must be a private address or it will not outbound
# forward encapsulated packets.
#
lisp_rtr_source_rloc = None

#
# Check if fast python data-plane should run.
#
lisp_rtr_fast_mode = (os.getenv("LISP_RTR_FAST_DATA_PLANE") != None)
lisp_rtr_latency_debug = (os.getenv("LISP_RTR_LATENCY_DEBUG") != None)

#------------------------------------------------------------------------------

#
# lisp_rtr_show_command
#
# Display state in an RTR.
#
def lisp_rtr_show_command(parameter):
    global lisp_threads

    return(lispconfig.lisp_itr_rtr_show_command(parameter, "RTR", 
        lisp_threads))
#enddef

#
# lisp_rtr_show_command_dns
#
# Display state in an RTR but pass in boolean to not do a DNS lookup.
#
def lisp_rtr_show_command_dns(parameter):
    global lisp_threads

    return(lispconfig.lisp_itr_rtr_show_command(parameter, "RTR", lisp_threads,
        True))
#enddef

#
# lisp_rtr_show_keys_command
#
# Call lispconfig.lisp_show_crypto_list().
#
def lisp_rtr_show_keys_command(parameter):
    return(lispconfig.lisp_show_crypto_list("RTR"))
#enddef

#
# lisp_rtr_database_mapping_command
# 
# Add database-mapping entry so RTR can sign Map-Requests.
#
def lisp_rtr_database_mapping_command(kv_pair):
    lispconfig.lisp_database_mapping_command(kv_pair)
#enddef

#
# lisp_rtr_glean_mapping_command
# 
# Add a configured glean_mapping to the lisp_glean_mapping array.
#
def lisp_rtr_glean_mapping_command(kv_pair):
    entry = { "rloc-probe" : False }

    for kw in kv_pair.keys():
        value = kv_pair[kw]

        if (kw == "instance-id"):
            v = value.split("-")
            entry["instance-id"] = [0, 0]
            if (len(v) == 1):
                entry["instance-id"][0] = int(v[0])
                entry["instance-id"][1] = int(v[0])
            else:
                entry["instance-id"][0] = int(v[0])
                entry["instance-id"][1] = int(v[1])
            #endif
        #endif
        if (kw == "eid-prefix"):
            eid = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
            eid.store_prefix(value)
            entry["eid-prefix"] = eid
        #endif
        if (kw == "rloc-prefix"):
            rloc = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
            rloc.store_prefix(value)
            entry["rloc-prefix"] = rloc
        #endif
        if (kw == "rloc-probe"):
            entry["rloc-probe"] = (value == "yes")
        #endif
    #endfor

    #
    # Check if entry already exists. If so, just return.
    #
    for e in lisp.lisp_glean_mappings:
        if (e.has_key("eid-prefix") ^ entry.has_key("eid-prefix")): continue
        if (e.has_key("eid-prefix") and entry.has_key("eid-prefix")):
            old = e["eid-prefix"]
            new = entry["eid-prefix"]
            if (old.is_exact_match(new) == False): continue
        #endif

        if (e.has_key("rloc-prefix") ^ entry.has_key("rloc-prefix")): continue
        if (e.has_key("rloc-prefix") and entry.has_key("rloc-prefix")):
            old = e["rloc-prefix"]
            new = entry["rloc-prefix"]
            if (old.is_exact_match(new) == False): continue
        #endif

        if (e.has_key("instance-id") ^ entry.has_key("instance-id")): continue
        if (e.has_key("instance-id") and entry.has_key("instance-id")):
            old = e["instance-id"]
            new = entry["instance-id"]
            if (old != new): continue
        #endif

        #
        # Found a match. Do not append existing entry to array.
        #
        return
    #endfor

    #
    # Add dictionary array to array.
    #
    lisp.lisp_glean_mappings.append(entry)
#enddef

#
# lisp_rtr_show_rloc_probe_command
#
# Display RLOC-probe list state in an RTR.
#
def lisp_rtr_show_rloc_probe_command(parameter):
    return(lispconfig.lisp_itr_rtr_show_rloc_probe_command("RTR"))
#enddef

#
# lisp_fix_rloc_encap_state_entry
#
# Examine one map-cache entry.
#
def lisp_fix_rloc_encap_state_entry(mc, parms):
    lisp_sockets, rloc, port, hostname = parms

    addr = "{}:{}".format(rloc.print_address_no_iid(), port)
    eid = lisp.green(mc.print_eid_tuple(), False)
    msg = "Changed '{}' translated address:port to {} for EID {}, {} {}". \
        format(hostname, lisp.red(addr, False), eid, "{}", "{}")

    for rloc_entry in mc.rloc_set:
        if (rloc_entry.rle):
            for rle_node in rloc_entry.rle.rle_nodes:
                if (rle_node.rloc_name != hostname): continue
                rle_node.store_translated_rloc(rloc, port)
                old_addr = rle_node.address.print_address_no_iid() + ":" + \
                    str(rle_node.translated_port)
                lisp.lprint(msg.format("RLE", old_addr))
            #endfor
        #endif

        if (rloc_entry.rloc_name != hostname): continue

        #
        # Update lisp-crypto encap array. Put keys in new dictionary array
        # location since translated address and port changed. We don't want
        # to rekey because of a NAT change.
        #
        old_addr = rloc_entry.rloc.print_address_no_iid() + ":" + \
            str(rloc_entry.translated_port)
        if (lisp.lisp_crypto_keys_by_rloc_encap.has_key(old_addr)):
            keys = lisp.lisp_crypto_keys_by_rloc_encap[old_addr]
            lisp.lisp_crypto_keys_by_rloc_encap[addr] = keys
        #endif

        #
        # Update translated information with new information.
        #
        rloc_entry.delete_from_rloc_probe_list(mc.eid, mc.group)
        rloc_entry.store_translated_rloc(rloc, port)
        rloc_entry.add_to_rloc_probe_list(mc.eid, mc.group)
        lisp.lprint(msg.format("RLOC", old_addr))

        #
        # Trigger RLOC-probe if enabled.
        #
        if (lisp.lisp_rloc_probing):
            seid = None if (mc.group.is_null()) else mc.eid
            deid = mc.eid if (mc.group.is_null()) else mc.group
            lisp.lisp_send_map_request(lisp_sockets, 0, seid, deid, rloc_entry)
        #endif
    #endfor

    #
    # Write change to external data-plane.
    #
    lisp.lisp_write_ipc_map_cache(True, mc)
    return(True, parms)
#enddef

#
# lisp_fix_rloc_encap_state_walk
#
# Walk main cache and source-cache for each entry to handle multicast entries.
#
def lisp_fix_rloc_encap_state_walk(mc, parms):

    #
    # There is only destination state in this map-cache entry.
    #
    if (mc.group.is_null()): return(lisp_fix_rloc_encap_state_entry(mc, parms))

    if (mc.source_cache == None): return(True, parms)

    #
    # There is (source, group) state so walk all sources for this group
    # entry.
    #
    mc.source_cache.walk_cache(lisp_fix_rloc_encap_state_entry, parms)
    return(True, parms)
#enddef

#
# lisp_fix_rloc_encap_state
#
# Walk map-cache looking for supplied RLOC and change its encap-port to
# the supplied port passed to this function.
#
def lisp_fix_rloc_encap_state(sockets, hostname, rloc, port):
    lisp.lisp_map_cache.walk_cache(lisp_fix_rloc_encap_state_walk, 
        [sockets, rloc, port, hostname])
    return
#enddef

#
# lisp_fast_debug
#
# Print out debug for lisp_rtr_fast_data_plane().
#
def lisp_fast_debug(sred, packet):
    if (lisp.lisp_data_plane_logging == False): return

    if (sred in ["Send", "Receive"]):
        p = binascii.hexlify(packet[0:20])
        lisp.lprint("Fast-{}: ip {} {} {} {} {}".format(sred, p[0:8], p[8:16],
            p[16:24], p[24:32], p[32:40]))
    elif (sred in ["Encap", "Decap"]):
        p = binascii.hexlify(packet[0:36])
        lisp.lprint("Fast-{}: ip {} {} {} {} {}, udp {} {}, lisp {} {}". \
            format(sred, p[0:8], p[8:16], p[16:24], p[24:32], p[32:40],
            p[40:48], p[48:56], p[56:64], p[64:72]))
    #endif
#enddef

#
# lisp_fast_lookup_debug
#
# Print out lisp_rtr_fast_data_plane() lookup information.
#
def lisp_fast_lookup_debug(dest, mc):
    if (lisp.lisp_data_plane_logging == False): return

    hm = "miss" if mc == None else "hit!"
    lisp.lprint("Fast-Lookup {} {}".format(dest.print_address(), hm))
#enddef

#
# lisp_latency_debug
#
# Set or print latency timing. Used by both lisp_rtr_data_plane() and lisp_
# rtr_fast_data_plane().
#
def lisp_latency_debug(ts, msg):
    global lisp_rtr_latency_debug
    
    if (lisp_rtr_latency_debug == False): return(None)

    #
    # Return the initial timestamp when requested.
    #
    if (ts == None): return(time.time())

    #
    # Compute elapsed time from initial timestamp.
    #
    ts = (time.time() - ts) * 1000000
    lisp.lprint("{}-Latency: {} usecs".format(msg, round(ts, 1)), "force")
    return(None)        
#enddef

#
# lisp_fast_address_to_binary
#
# Convert 4-byte address from packet format to binary. Used to store in
# lisp_address.address for other support functions to be used.
#
def lisp_fast_address_to_binary(a):
    binary = ord(a[0]) << 24 | ord(a[1]) << 16 | ord(a[2]) << 8 | ord(a[3])
    return(binary)
#enddef

#
# lisp_rtr_fast_data_plane
#
# This is a python fast data plane that is limited in features and process
# packets in a raw manner. That is, there are no library calls and no byte
# swaps done. It is designed to make the gleaning RTR data-plane with LISP
# to non-LISP interworking go faster.
#
# Any non-fast operations returns False to allow lisp_rtr_data_plane() to
# process the packet normally.
#
# The first byte of 'packet' is assumed to be either the first byte of the
# LISP encapsulated packet (coming from an ITR) or a regular IP packet
# (arriving from a non-LISP source). All other packets (like LISP control-plane
# packets that can come in the form of both encapsulated or non encapsulated,
# return False, for lisp_rtr_data_plane() to process.
#
lisp_seid_cached = lisp.lisp_address(lisp.LISP_AFI_IPV4, "", 32, 0)
lisp_deid_cached = lisp.lisp_address(lisp.LISP_AFI_IPV4, "", 32, 0)

def lisp_rtr_fast_data_plane(packet):
    global lisp_address_cached, lisp_map_cache, lisp_raw_socket

    ts = lisp_latency_debug(None, "Fast")

    #
    # Check if UDP ports for any type of LISP packet. Strict outer headers
    # if LISP encapsulated packet.
    #
    iid = 0
    srloc = None
    if (packet[9] == '\x11'):
        if (packet[20:22] == '\x10\xf6'): return(False)
        if (packet[22:24] == '\x10\xf6'): return(False)

        if (packet[20:22] == '\x10\xf5' or packet[22:24] == '\x10\xf5'):
            srloc = packet[12:16]
            iid = packet[32:35]
            iid = ord(iid[0]) << 16 | ord(iid[1]) << 8 | ord(iid[2])
            if (iid == 0xffffff): return(False)
            lisp_fast_debug("Decap", packet)
            packet = packet[36::]
        #endif
    #endif

    lisp_fast_debug("Receive", packet)

    #
    # Get destination in a form for map_cache lookup.
    #
    dest = lisp_fast_address_to_binary(packet[16:20])
    lisp_deid_cached.instance_id = iid
    lisp_deid_cached.address = dest

    #
    # Don't switch multicast for now.
    #
    if ((dest & 0xe0000000) == 0xe0000000): return(False)
    
    #
    # Do map-cache lookup.
    #
    dest = lisp_deid_cached
    mc = lisp.lisp_map_cache.lookup_cache(dest, False)
    lisp_fast_lookup_debug(dest, mc)
    if (mc == None): return(False)

    #
    # Check for source gleaning. If gleaned entry and RLOC changes from SRLOC
    # return to do more general processing.
    #
    if (srloc != None):
        src = lisp_fast_address_to_binary(packet[12:16])
        lisp_seid_cached.instance_id = iid
        lisp_seid_cached.address = src
        src_mc = lisp.lisp_map_cache.lookup_cache(lisp_seid_cached, False)
        if (src_mc == None):
            allow, nil = lisp.lisp_allow_gleaning(lisp_seid_cached, None)
            if (allow): return(False)
        elif (src_mc.gleaned):
            srloc = lisp_fast_address_to_binary(srloc)
            if (src_mc.rloc_set[0].rloc.address != srloc): return(False)
        #endif
    #endif

    #
    # Need this check for interworking.
    #
    if (mc.action == lisp.LISP_NATIVE_FORWARD_ACTION and
        mc.eid.instance_id == 0):
        dest.instance_id = lisp.lisp_default_secondary_iid
        mc = lisp.lisp_map_cache.lookup_cache(dest, False)
        lisp_fast_lookup_debug(dest, mc)
        if (mc == None): return(False)

        length = len(packet)
        stats = mc.stats
        lisp_fast_debug("Send", packet)
    else:

        #
        # Determine if new LISP encap is to be prepended or we are forwarding
        # a decapsulated packet.
        #
        if (mc.best_rloc_set == []): return(False)
        
        dest = mc.best_rloc_set[0]
        if (dest.state != lisp.LISP_RLOC_UP_STATE): return(False)

        iid = mc.eid.instance_id
        port = dest.translated_port
        stats = dest.stats
        dest = dest.rloc
        drloc = dest.address
        srloc = lisp.lisp_myrlocs[0].address

        #
        # Build outer IPv4 header.
        #
        outer = '\x45\x00'
        length = len(packet) + 20 + 8 + 8
        outer += chr((length >> 8) & 0xff) + chr(length & 0xff)
        outer += '\xff\xff\x40\x00\x10\x11\x00\x00'
        outer += chr((srloc >> 24) & 0xff)
        outer += chr((srloc >> 16) & 0xff)
        outer += chr((srloc >> 8) & 0xff)
        outer += chr(srloc & 0xff)
        outer += chr((drloc >> 24) & 0xff)
        outer += chr((drloc >> 16) & 0xff)
        outer += chr((drloc >> 8) & 0xff)
        outer += chr(drloc & 0xff)
        outer = lisp.lisp_ip_checksum(outer)

        #
        # Build UDP and LISP headers.
        #
        udplen = length - 20
        udplisp = '\xff\x00' if (port == 4341) else '\x10\xf5'
        udplisp += chr((port >> 8) & 0xff) + chr(port & 0xff)
        udplisp += chr((udplen >> 8) & 0xff) + chr(udplen & 0xff) + '\x00\x00'

        udplisp += '\x08\xdf\xdf\xdf'
        udplisp += chr((iid >> 16) & 0xff)
        udplisp += chr((iid >> 8) & 0xff)
        udplisp += chr(iid & 0xff)
        udplisp += '\x00'

        #
        # Append all outer headers.
        #
        packet = outer + udplisp + packet
        lisp_fast_debug("Encap", packet)
    #endif

    #
    # Increment stats.
    #
    mc.last_refresh_time = time.time()
    stats.increment(length)
    
    #
    # Send it.
    #
    dest = dest.print_address_no_iid()
    lisp_raw_socket.sendto(packet, (dest, 0))

    lisp_latency_debug(ts, "Fast")
    return(True)
#endif    

#
# lisp_rtr_data_plane
#
# Capture a LISP encapsulated packet, decap it, process inner header, and
# re-encapsulated it.
#
def lisp_rtr_data_plane(lisp_packet, thread_name):
    global lisp_send_sockets, lisp_ephem_prot, lisp_data_packet 
    global lisp_raw_socket, lisp_raw_v6_socket
    global lisp_trace_listen_socket
    global lisp_rtr_source_rloc
    global lisp_rtr_fast_mode

    ts = lisp_latency_debug(None, "RTR")

    #
    # Try switching packet fast.
    #
    if (lisp_rtr_fast_mode):
        if (lisp_rtr_fast_data_plane(lisp_packet.packet)): return
    #endif

    #
    # Feature-rich forwarding path.
    #
    packet = lisp_packet
    is_lisp_packet = packet.is_lisp_packet(packet.packet)

    #
    # Check RLOC-probe Map-Request. We need to grab the TTL from IP header.
    #
    if (is_lisp_packet == False):
        orig_packet = packet.packet
        pkt, source, port, ttl = lisp.lisp_is_rloc_probe(orig_packet, -1)
        if (orig_packet != pkt):
            if (source == None): return
            lisp.lisp_parse_packet(lisp_send_sockets, pkt, source, port, ttl)
            return
        #endif
    #endif

    #
    # First check if we are assembling IPv4 fragments.
    #
    packet.packet = lisp.lisp_reassemble(packet.packet)
    if (packet.packet == None): return

    #
    # We need to cache the input encapsualted packet as well as the output
    # encapsulated packet.
    #
    if (lisp.lisp_flow_logging): packet = copy.deepcopy(packet)

    #
    # If we are a PITR as well, we are receiving non encapsulated packets
    # via return packets from doing LISP-NAT. Print some useful header fields
    # and strip outer headers. Strip outer headers if LISP encapsulated packet
    # and start inner header forwarding logic.
    #
    if (is_lisp_packet):
        if (packet.decode(True, None, lisp.lisp_decap_stats) == None): return
        packet.print_packet("Receive-({})".format(thread_name), True)
        packet.strip_outer_headers()
    else:
        if (packet.decode(False, None, None) == None): return
        packet.print_packet("Receive-({})".format(thread_name), False)
    #endif

    #
    # If instance-id is 0xffffff, this is a Info-Request packet encapsulated
    # to port 4341. We need to store the source port and source RLOC for
    # NAT-traversal reasons.
    #
    # We don't need to send an Info-Reply from the 4341 data port. There is no
    # information the xTR needs. It has the translated address from the 
    # map-server, and the NAT is ready for packets from port 4341 since we 
    # received this Info-Request.
    #
    if (is_lisp_packet and packet.lisp_header.get_instance_id() == 0xffffff):
        header = lisp.lisp_control_header()
        header.decode(packet.packet)
        if (header.is_info_request()):
            info = lisp.lisp_info()
            info.decode(packet.packet)
            info.print_info()

            #
            # Store/refresh NAT state and Fix map-cache entries if there was
            # a change.
            #
            h = info.hostname if (info.hostname != None) else ""
            s = packet.outer_source
            p = packet.udp_sport
            if (lisp.lisp_store_nat_info(h, s, p)):
                lisp_fix_rloc_encap_state(lisp_send_sockets, h, s, p)
            #endif
        else:
            source = packet.outer_source.print_address_no_iid()
            ttl = packet.outer_ttl
            packet = packet.packet
            if (lisp.lisp_is_rloc_probe_request(packet[28]) == False and
                lisp.lisp_is_rloc_probe_reply(packet[28]) == False): ttl = -1
            packet = packet[28::]
            lisp.lisp_parse_packet(lisp_send_sockets, packet, source, 0, ttl)
        #endif
        return
    #endif

    #
    # Packets are arriving on pcap interface. Need to check if another data-
    # plane is running. If so, don't deliver duplicates.
    #
    if (lisp.lisp_ipc_data_plane): 
        lisp.dprint("Drop packet, external data-plane active")
        return
    #endif

    #
    # Increment global stats.
    #
    if (is_lisp_packet):
        lisp.lisp_decap_stats["good-packets"].increment(len(packet.packet))
    #endif

    #
    # Process inner header (checksum and decrement ttl).
    #
    igmp = None
    if (packet.inner_dest.is_mac()):
        packet.packet = lisp.lisp_mac_input(packet.packet)
        if (packet.packet == None): return
        packet.encap_port = lisp.LISP_VXLAN_DATA_PORT
    elif (packet.inner_version == 4):
        igmp, packet.packet = lisp.lisp_ipv4_input(packet.packet)
        if (packet.packet == None): return
        packet.inner_ttl = packet.outer_ttl
    elif (packet.inner_version == 6):
        packet.packet = lisp.lisp_ipv6_input(packet)
        if (packet.packet == None): return
        packet.inner_ttl = packet.outer_ttl
    else:
        lisp.dprint("Cannot parse inner packet header")
        return
    #endif

    #
    # Process decap node trace function.
    #
    if (packet.is_trace()):
        if (lisp.lisp_trace_append(packet, ed="decap") == False): return
        packet.outer_source.afi = lisp.LISP_AFI_NONE
        packet.outer_dest.afi = lisp.LISP_AFI_NONE
    #endif

    #
    # Should we glean source information from packet and add it to the
    # map-cache??
    #
    allow, nil = lisp.lisp_allow_gleaning(packet.inner_source,
        packet.outer_source)
    if (allow):
        igmp_packet = packet.packet if (igmp) else None
        lisp.lisp_glean_map_cache(packet.inner_source, packet.outer_source,
            packet.udp_sport, igmp_packet)
        if (igmp): return
    #endif
    gleaned_dest, nil = lisp.lisp_allow_gleaning(packet.inner_dest, None)
    packet.gleaned_dest = gleaned_dest

    #
    # Do map-cache lookup. If no entry found, send Map-Request.
    #
    mc = lisp.lisp_map_cache_lookup(packet.inner_source, packet.inner_dest)

    #
    # Check if we are doing secondary-instance-ids only when we have a 
    # map-cache entry in the IID that is possibly a non-LISP site.
    #
    if (mc and (mc.action == lisp.LISP_NATIVE_FORWARD_ACTION or 
        mc.eid.address == 0)):
        db = lisp.lisp_db_for_lookups.lookup_cache(packet.inner_source, False)
        if (db and db.secondary_iid):
            dest_eid = packet.inner_dest
            dest_eid.instance_id = db.secondary_iid

            mc = lisp.lisp_map_cache_lookup(packet.inner_source, dest_eid)
            if (mc):
                packet.gleaned_dest = mc.gleaned
            else:
                gleaned_dest, nil = lisp.lisp_allow_gleaning(dest_eid, None)
                packet.gleaned_dest = gleaned_dest
            #endif
        #endif
    #endif
        
    #
    # Map-cache lookup miss. Do not send Map-Request to mapping system if
    # dest-EID is configured to be gleaned. We want to give preference to
    # the gleaned mapping and not the mapping in the mapping system.
    #
    if (mc == None and gleaned_dest):
        lisp.lprint("Suppress Map-Request for gleaned EID {}".format( \
            lisp.green(packet.inner_dest.print_address(), False)))
        return
    #endif

    if (mc == None or mc.action == lisp.LISP_SEND_MAP_REQUEST_ACTION):
        if (lisp.lisp_rate_limit_map_request(packet.inner_source, 
            packet.inner_dest)): return
        lisp.lisp_send_map_request(lisp_send_sockets, lisp_ephem_port, 
            packet.inner_source, packet.inner_dest, None)

        if (packet.is_trace()):
            s = lisp_trace_listen_socket
            r = "map-cache miss"
            lisp.lisp_trace_append(packet, reason=r, lisp_socket=s)
        #endif
        return
    #endif

    #
    # Send Map-Request to see if there is a RLOC change or to refresh an
    # entry that is about to time out.
    #
    if (mc and mc.is_active() and mc.has_ttl_elapsed() and
        mc.gleaned == False):
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
    # Encapsulate or native forward packet.
    #
    dest_rloc, dest_port, nonce, action, rle, rloc_entry = \
        mc.select_rloc(packet, None)

    if (dest_rloc == None and rle == None):
        if (action == lisp.LISP_NATIVE_FORWARD_ACTION):
            lisp.dprint("Natively forwarding")
            packet.send_packet(lisp_raw_socket, packet.inner_dest)

            if (packet.is_trace()):
                s = lisp_trace_listen_socket
                r = "not an EID"
                lisp.lisp_trace_append(packet, reason=r, lisp_socket=s)
            #endif
            lisp_latency_debug(ts, "RTR")
            return
        #endif
        r = "No reachable RLOCs found"
        lisp.dprint(r)

        if (packet.is_trace()):
            s = lisp_trace_listen_socket
            lisp.lisp_trace_append(packet, reason=r, lisp_socket=s)
        #endif
        return
    #endif
    if (dest_rloc and dest_rloc.is_null()): 
        lisp.dprint("Drop action RLOC found")

        if (packet.is_trace()):
            s = lisp_trace_listen_socket
            r = "drop action"
            lisp.lisp_trace_append(packet, reason=r, lisp_socket=s)
        #endif
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
        packet.encap_port = dest_port
        if (dest_port == 0): packet.encap_port = lisp.LISP_DATA_PORT
        packet.outer_dest.copy_address(dest_rloc)
        version = packet.outer_dest.afi_to_version()
        packet.outer_version = version

        source_rloc = lisp_rtr_source_rloc if (version == 4) else \
            lisp.lisp_myrlocs[1]
        packet.outer_source.copy_address(source_rloc)

        if (packet.is_trace()):
            s = lisp_trace_listen_socket
            if (lisp.lisp_trace_append(packet, rloc_entry=rloc_entry,
                lisp_socket=s) == False): return
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
        # Do replication of RLE is returned.
        #
        orig_len = len(packet.packet)
        for node in rle.rle_forwarding_list:
            packet.outer_dest.copy_address(node.address)
            packet.encap_port = lisp.LISP_DATA_PORT if \
                node.translated_port == 0 else node.translated_port

            version = packet.outer_dest.afi_to_version()
            packet.outer_version = version
            source_rloc = lisp.lisp_myrlocs[0] if (version == 4) else \
                lisp.lisp_myrlocs[1]
            packet.outer_source.copy_address(source_rloc)

            if (packet.is_trace()):
                s = lisp_trace_listen_socket
                r = "replicate"
                if (lisp.lisp_trace_append(packet, reason=r, lisp_socket=s) \
                    == False): return
            #endif

            if (packet.encode(None) == None): return

            packet.print_packet("Replicate-to-L{}".format(node.level), True)
            packet.send_packet(lisp_raw_socket, packet.outer_dest)

            #
            # We need to strip the encapsulation header so we can add a new
            # one for the next replication.
            #
            strip_len = len(packet.packet) - orig_len
            packet.packet = packet.packet[strip_len::]

            if (lisp.lisp_flow_logging): packet = copy.deepcopy(packet)
        #endfor
    #endif

    # 
    # Don't need packet structure anymore.
    #
    del(packet)

    lisp_latency_debug(ts, "RTR")
    return
#enddef

#
# lisp_rtr_worker_thread
#
# This function runs for each thread started. 
#
def lisp_rtr_worker_thread(lisp_thread):
    lisp.lisp_set_exception()
    while (True):

        #
        # Dequeue packet from pcap's enqueue.
        #
        packet = lisp_thread.input_queue.get()

        #
        # Count input packets and bytes.
        #
        lisp_thread.input_stats.increment(len(packet))

        #
        # Use pre-defined packet data structure, store packet buffer in it.
        #
        lisp_thread.lisp_packet.packet = packet

        #
        # Decap and encap, go, go, go.
        #
        lisp_rtr_data_plane(lisp_thread.lisp_packet, lisp_thread.thread_name)
    #endwhile
    return
#enddef

#
# lisp_triage
#
# Decide which RTR thread should process packet. Do a modulus on the timestamp
# to randomly have a single thread process a received packet.
#
def lisp_triage(thread):
    seed = (time.time() % thread.number_of_pcap_threads)
    return(int(seed) == thread.thread_number)
#enddef

#
# lisp_rtr_pcap_process_packet
#
# Receive LISP encapsulated packet from pcap.loop(). IPC it to ourselves so
# main thread can get access to lisp.lisp_map_cache.
#
def lisp_rtr_pcap_process_packet(parms, not_used, packet):
    if (lisp_triage(parms[1]) == False): return

    device = parms[0]
    lisp_thread = parms[1]
    use_workers = lisp_thread.number_of_worker_threads

    lisp_thread.input_stats.increment(len(packet))

    #
    # Jump over MAC header if packet received on interface. There is a 4-byte
    # internal header in any case (loopback interfaces will have a 4 byte
    # header)..
    #
    offset = 4 if device == "lo0" else (14 if lisp.lisp_is_macos() else 16)
    packet = packet[offset::]

    #
    # If we are using worker threads, queue packet so they can process packet.
    #
    if (use_workers):
        index = lisp_thread.input_stats.packet_count % use_workers
        index = index + (len(lisp_threads) - use_workers)
        thread = lisp_threads[index]
        thread.input_queue.put(packet)
    else:
        lisp_thread.lisp_packet.packet = packet
        lisp_rtr_data_plane(lisp_thread.lisp_packet, lisp_thread.thread_name)
    #endif
    return
#enddef

#
# lisp_rtr_pcap_thread
#
# Setup pcap filters for this thread to receive packets in lisps_rtr_pcap_
# processs_packet().
#
def lisp_rtr_pcap_thread(lisp_thread):
    lisp.lisp_set_exception()
    if (lisp.lisp_myrlocs[0] == None): return

    device = "lo0" if lisp.lisp_is_macos() else "any"
    pcap = pcappy.open_live(device, 9000, 0, 100)

    #
    # If "lisp-nat = yes" is configured, then a PETR is co-located with this
    # RTR functionality. We need to pcap *all* packets (0.0.0.0/0 and 0::/0).
    #
    lisp_nat = commands.getoutput("egrep 'lisp-nat = yes' ./lisp.config")
    lisp_nat = (lisp_nat != "" and lisp_nat[0] == " ")

    pfilter = "(dst host "
    afilter = ""
    for addr in lisp.lisp_get_all_addresses():
        pfilter += "{} or ".format(addr)
        afilter += "{} or ".format(addr)
    #endif
    pfilter = pfilter[0:-4]
    pfilter += ") and ((udp dst port 4341 or 8472 or 4789) or "
    pfilter += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + \
        "(ip[6]&0xe0 == 0 and ip[7] != 0))))"

    #
    # For RLOC-probe messages that come via pcap interface so we have the
    # IP header to grab the TTL.
    #
    afilter = afilter[0:-4]
    pfilter += (" or (not (src host {}) and " + \
        "((udp src port 4342 and ip[28] == 0x28) or " + \
        "(udp dst port 4342 and ip[28] == 0x12)))").format(afilter)

    if (lisp_nat):
        pfilter += " or (dst net 0.0.0.0/0 and not (host {}))".format(afilter)
    #endif

    lisp.lprint("Capturing packets for: '{}'".format(pfilter))
    pcap.filter = pfilter

    #
    # Enter receive loop.
    #
    pcap.loop(-1, lisp_rtr_pcap_process_packet, [device, lisp_thread])
    return
#enddef

#
# lisp_rtr_process_timer
#
# Call general timeout routine to process the RTR map-cache.
#
def lisp_rtr_process_timer():
    lisp.lisp_set_exception()

    #
    # Remove nonce entries from crypto-list.
    #
    for keys in lisp.lisp_crypto_keys_by_nonce.values():
        for key in keys: del(key)
    #endfor
    lisp.lisp_crypto_keys_by_nonce.clear()
    lisp.lisp_crypto_keys_by_nonce = {}

    #
    # Walk map-cache.
    #
    lisp.lisp_timeout_map_cache(lisp.lisp_map_cache)

    #
    # Clear the LISP-Trace cache so we can optimize memory usage. There is only
    # a one-time use for the cahced entries.
    #
    lisp.lisp_rtr_nat_trace_cache.clear()
    lisp.lisp_rtr_nat_trace_cache = {}

    #
    # Restart periodic timer.
    #
    lisp_periodic_timer = threading.Timer(60, lisp_rtr_process_timer, [])
    lisp_periodic_timer.start()
    return
#enddef

#
# lisp_rtr_startup
#
# Intialize this LISP RTR process. This function returns no values.
#
def lisp_rtr_startup():
    global lisp_ipc_listen_socket, lisp_send_sockets, lisp_ephem_listen_socket
    global lisp_raw_socket, lisp_raw_v6_socket, lisp_threads
    global lisp_ipc_punt_socket, lisp_trace_listen_socket
    global lisp_rtr_source_rloc

    lisp.lisp_i_am("rtr")
    lisp.lisp_set_exception()
    lisp.lisp_print_banner("RTR starting up")

    #
    # Get local address for source RLOC for encapsulation.
    #
    if (lisp.lisp_get_local_addresses() == False): return(False)

    #
    # Get interface address for RTR source RLOC if env variable defined. It
    # should be the private translatable address from a AWS resident NAT.
    #
    lisp_rtr_source_rloc = lisp.lisp_myrlocs[0]
    if (lisp.lisp_on_aws()):
        lisp_rtr_source_rloc = lisp.lisp_get_interface_address("eth0")
    #endif

    #
    # Open network send socket and internal listen socket. For an RTR, that
    # may be behind a NAT, all Map-Requests are sent with the ephemeral port
    # so the Map-Request port and the ECM port will be the same.
    #
    address = "0.0.0.0" if lisp.lisp_is_raspbian() else "0::0"
    lisp_ephem_listen_socket = lisp.lisp_open_listen_socket(address,
        str(lisp_ephem_port))
    lisp_ipc_listen_socket = lisp.lisp_open_listen_socket("", "lisp-rtr")
    lisp_ipc_punt_socket = lisp.lisp_open_listen_socket("", "lispers.net-itr")

    lisp_send_sockets[0] = lisp_ephem_listen_socket
#   lisp_send_sockets[0] = lisp.lisp_open_send_socket("", lisp.LISP_AFI_IPV4)
    lisp_send_sockets[1] = lisp.lisp_open_send_socket("", lisp.LISP_AFI_IPV6)
    lisp_send_sockets[2] = lisp_ipc_listen_socket

    #
    # Open up raw socket so we can send with IP headers after decapsulation.
    # There is a special case where the RTR's lisp_send_sockets array is of
    # size 4 since we need to pass the raw socket through the lisp.py module
    # to send a data encapsulated RLOC-probe to an ETR that sits behind a NAT.
    # The test is in lisp_send_map_request() for this. This is the case in
    # ETRs as well. All other components use an array size of 3 modulo.
    #
    lisp_raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
        socket.IPPROTO_RAW)
    lisp_raw_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    lisp_send_sockets.append(lisp_raw_socket)

    #
    # Open up a listen socket on the LISP-Trace port so the RTR can cache
    # translated RLOC information from an ltr client program.
    #
    lisp_trace_listen_socket = lisp.lisp_open_listen_socket("0.0.0.0",
        str(lisp.LISP_TRACE_PORT))

    if (lisp.lisp_is_raspbian() == False):
        lisp_raw_v6_socket = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
           socket.IPPROTO_UDP)
    #endif

    pcap_threads = os.getenv("LISP_PCAP_THREADS")
    pcap_threads = 1 if (pcap_threads == None) else int(pcap_threads)
    worker_threads = os.getenv("LISP_WORKER_THREADS")
    worker_threads = 0 if (worker_threads == None) else int(worker_threads)

    #
    # Setup packet capture.
    #
    for i in range(pcap_threads):
        t = lisp.lisp_thread("pcap-{}".format(i))
        t.thread_number = i
        t.number_of_pcap_threads = pcap_threads
        t.number_of_worker_threads = worker_threads
        lisp_threads.append(t)
        threading.Thread(target=lisp_rtr_pcap_thread, args=[t]).start()
    #endif

    #
    # Start worker threads. If you want to change the number of them, only 
    # this constant needs changing.
    #
    for i in range(worker_threads):
        t = lisp.lisp_thread("worker-{}".format(i))
        lisp_threads.append(t)
        threading.Thread(target=lisp_rtr_worker_thread, args=[t]).start()
    #endfor

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
    lisp_periodic_timer = threading.Timer(60, lisp_rtr_process_timer, [])
    lisp_periodic_timer.start()
    return(True)
#enddef

#
# lisp_rtr_shutdown
#
# Shut down this process.
#
def lisp_rtr_shutdown():

    #
    # Close sockets.
    #
    lisp.lisp_close_socket(lisp_send_sockets[0], "")
    lisp.lisp_close_socket(lisp_send_sockets[1], "")
    lisp.lisp_close_socket(lisp_ipc_listen_socket, "lisp-rtr")
    lisp.lisp_close_socket(lisp_ephem_listen_socket, "")
    lisp.lisp_close_socket(lisp_trace_listen_socket, "")
    lisp.lisp_close_socket(lisp_ipc_punt_socket, "lispers.net-itr")
    lisp_raw_socket.close()
    return
#enddef

#
# lisp_rtr_map_resolver_command
#
# Call lispconfig.lisp_map_resolver_command and set "test-mr" timer.
#
def lisp_rtr_map_resolver_command(kv_pair):
    global lisp_send_sockets
    global lisp_ephem_port

    lispconfig.lisp_map_resolver_command(kv_pair)

    if (lisp.lisp_test_mr_timer == None or 
        lisp.lisp_test_mr_timer.is_alive() == False):
        lisp.lisp_test_mr_timer = threading.Timer(2, lisp.lisp_test_mr, 
            [lisp_send_sockets, lisp_ephem_port])
        lisp.lisp_test_mr_timer.start()
    #endif
    return
#enddef

#
# lisp_rtr_xtr_command
#
# Call lispconfig.lisp_xtr_command() but pass socket parameters to starting
# the RLOC-probing timer if "rloc-probing = yes".
#
def lisp_rtr_xtr_command(kv_pair):
    global lisp_ephem_listen_socket, lisp_raw_socket, lisp_ephem_port

    rloc_probing = lisp.lisp_rloc_probing

    #
    # Execute command.
    #
    lispconfig.lisp_xtr_command(kv_pair)

    #
    # Trigger if "rloc-probing = yes" just happened and it was previously
    # set to "no".
    #
    if (rloc_probing == False and lisp.lisp_rloc_probing):
        lisp_sockets = [lisp_ephem_listen_socket, lisp_ephem_listen_socket,
            None, lisp_raw_socket]
        lisp.lisp_start_rloc_probe_timer(1, lisp_sockets)
        entry = { "type" : "itr-crypto-port", "port" : lisp_ephem_port }
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
# RTR commands processed by this process.
#
lisp_rtr_commands = {
    "lisp xtr-parameters" : [lisp_rtr_xtr_command, {
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
        "dynamic-eid-device" : [True],
        "lisp-nat" : [True, "yes", "no"],
        "dynamic-eid-timeout" : [True, 0, 0xff] }],

    "lisp map-resolver" : [lisp_rtr_map_resolver_command, {
        "mr-name" : [True],
        "ms-name" : [True],
        "dns-name" : [True],
        "address" : [True] }],

    "lisp map-cache" : [lispconfig.lisp_map_cache_command, {
        "prefix" : [], 
        "mr-name" : [True],
        "ms-name" : [True],
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

    "lisp rtr-map-cache" : [lispconfig.lisp_map_cache_command, {
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

    "lisp json" : [lispconfig.lisp_json_command, {
        "json-name" : [False],
        "json-string" : [False] }],

    "lisp database-mapping" : [lisp_rtr_database_mapping_command, {
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

    "lisp glean-mapping" : [lisp_rtr_glean_mapping_command, {
        "instance-id" : [False], 
        "eid-prefix" : [True], 
        "rloc-prefix" : [True],
        "rloc-probe" : [True, "yes", "no"] }],

    "show rtr-rloc-probing" : [lisp_rtr_show_rloc_probe_command, { }],
    "show rtr-keys" : [lisp_rtr_show_keys_command, {}],
    "show rtr-map-cache" : [lisp_rtr_show_command, {}],
    "show rtr-map-cache-dns" : [lisp_rtr_show_command_dns, {}]
}

#
# lisp_rtr_process_trace_packet
#
# Process RLOC-based LISP-Trace message.
#
def lisp_rtr_process_trace_packet(lisp_socket):

    #
    # Read from listen socket for port 2434 and parse LISP-Trace packet.
    #
    opcode, source, port, packet = lisp.lisp_receive(lisp_socket, False)
    trace = lisp.lisp_trace()
    if (trace.decode(packet) == False): return

    #
    # Cache the translated information. Will use local addressing info to
    # find translated information in lisp_trace_append().
    #
    trace.rtr_cache_nat_trace(source, port)
#enddef

#------------------------------------------------------------------------------

#
# Main entry point for process.
#
if (lisp_rtr_startup() == False):
    lisp.lprint("lisp_rtr_startup() failed")
    lisp.lisp_print_banner("RTR abnormal exit")
    exit(1)
#endif

socket_list = [lisp_ephem_listen_socket, lisp_ipc_listen_socket,
               lisp_ipc_punt_socket, lisp_trace_listen_socket]
ephem_sockets = [lisp_ephem_listen_socket] * 3

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
    # LISP-TRACE messages coming from an ltr client program.
    #
    if (lisp_trace_listen_socket in ready_list):
        lisp_rtr_process_trace_packet(lisp_trace_listen_socket)
    #endif

    #
    # Process Map-Reply messages received on ephemeral port.
    #
    if (lisp_ephem_listen_socket in ready_list):
        opcode, source, port, packet = lisp.lisp_receive(ephem_sockets[0],
            False)
        if (source == ""): break
        if (lisp.lisp_is_rloc_probe_request(packet[0])):
            lisp.lprint("RTR ignoring RLOC-probe request, using pcap")
            continue
        #endif
        if (lisp.lisp_is_rloc_probe_reply(packet[0])):
            lisp.lprint("RTR ignoring RLOC-probe reply, using pcap")
            continue
        #endif
        lisp.lisp_parse_packet(ephem_sockets, packet, source, port)
    #endif

    #
    # Process either commands, an IPC data-packet (for testing), or any
    # protocol message on the IPC listen socket..
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
            if (packet.find("clear%") != -1):
                lispconfig.lisp_clear_decap_stats(packet)
                continue
            #endif
            lispconfig.lisp_process_command(lisp_ipc_listen_socket, opcode, 
                packet, "lisp-rtr", [lisp_rtr_commands])
        elif (opcode == "api"):
            lisp.lisp_process_api("lisp-rtr", lisp_ipc_listen_socket, packet)
        elif (opcode == "data-packet"):
            lisp_rtr_data_plane(packet, "")
        else:
            if (lisp.lisp_is_rloc_probe_request(packet[0])):
                lisp.lprint("RTR ignoring RLOC-probe request, using pcap")
                continue
            #endif
            if (lisp.lisp_is_rloc_probe_reply(packet[0])):
                lisp.lprint("RTR ignoring RLOC-probe reply, using pcap")
                continue
            #endif
            lisp.lisp_parse_packet(lisp_send_sockets, packet, source, port)
        #endif
    #endif

#endwhile

lisp_rtr_shutdown()
lisp.lisp_print_banner("RTR normal exit")
exit(0)

#------------------------------------------------------------------------------
