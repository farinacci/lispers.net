#-----------------------------------------------------------------------------
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
# lisp-etr.py
#
# This file performs LISP Egress Tunnel Router (ETR) functionality.
# 
# -----------------------------------------------------------------------------

from future import standard_library
standard_library.install_aliases()
from builtins import str
import lisp
import lispconfig
import socket
import select
import threading
import time
import struct
from subprocess import getoutput
import os
try:
    import pytun
except:
    pytun = None
#endtry
try:
    import pcappy
except:
    pass
#endtry
import pcapy

#------------------------------------------------------------------------------

#
# Global data structures relative to the lisp-etr process.
#
lisp_register_timer = None
lisp_trigger_register_timer = None
lisp_etr_info_timer = None
lisp_ephem_socket = None
lisp_ephem_port = lisp.lisp_get_ephemeral_port()
lisp_ipc_listen_socket = None
lisp_send_sockets = [None, None, None]
lisp_raw_socket = None
lisp_l2_socket = None
lisp_mac_header = None

LISP_MAP_REGISTER_INTERVAL = 60 # In units of seconds

#
# Test mode. Allows a batch of database-mapping commands to be read from
# lisp.config before any Map-Registers are sent. When an EID 'eid-done' is
# found (which is placed as the last database-mapping command in lisp.config),
# then lisp_build_map_register() is called via the 5-second delay timer.
#
lisp_etr_test_mode = (os.getenv("LISP_ETR_TEST_MODE") != None)
lisp_seen_eid_done = False

#------------------------------------------------------------------------------

#
# lisp_etr_map_server_command
#
# Configure a Map-Server and trigger ETR functionality.
#
def lisp_etr_map_server_command(kv_pair):
    global lisp_trigger_register_timer
    global lisp_etr_info_timer

    ms = lispconfig.lisp_map_server_command(kv_pair)

    #
    # Trigger a Info-Request if we are doing NAT-traversal if this is the
    # first Map-Server..
    #
    first_ms = (len(lisp.lisp_map_servers_list) == 1)
    if (first_ms):
        ms = list(lisp.lisp_map_servers_list.values())[0]
        lisp_etr_info_timer = threading.Timer(2, lisp_etr_process_info_timer, 
            [ms.map_server])
        lisp_etr_info_timer.start()
    else:

        #
        # Trigger Map-Register to newly configured Map-Server.
        #
        # Do not trigger Map-Register if NAT-traveral is configured. We may not
        # have the global RLOC yet from Info-Replies. When the Info-Reply comes
        # in we do trigger Map-Registers to all map-servers.
        #
        if (lisp.lisp_nat_traversal): return
        if (ms and len(lisp.lisp_db_list) > 0): 
            lisp_build_map_register(lisp_send_sockets, None, None, ms, False)
        #endif
    #endif

    #
    # Do not start the trigger timer if we are in test-mode. We may already
    # be sending a huge list of Map-Registers after "eid-done".
    #
    if (lisp_etr_test_mode and lisp_seen_eid_done): return

    #
    # Handle case where "lisp database-mapping" comes before "lisp map-server"
    # in configuration file. We have to start periodic timer.
    #
    if (len(lisp.lisp_db_list) > 0): 
        if (lisp_trigger_register_timer != None): return
        lisp_trigger_register_timer = threading.Timer(5, 
            lisp_process_register_timer, [lisp_send_sockets])
        lisp_trigger_register_timer.start()
    #endif
#enddef

#
# lisp_etr_database_mapping_command
# 
# This function supports adding additional RLOCs to a database-mapping entry
# that already exists.
#
def lisp_etr_database_mapping_command(kv_pair):
    global lisp_register_timer, lisp_trigger_register_timer
    global lisp_send_sockets, lisp_seen_eid_done
    global lisp_seen_eid_done_count

    #
    # This is to fix an issue with the same set of database-mappings being
    # sent a second time. Only in test-mode we don't want to dup process for
    # large numbers of entries.
    #
    if (lisp_seen_eid_done): return

    lispconfig.lisp_database_mapping_command(kv_pair, lisp_ephem_port,
        (lisp_etr_test_mode == False))

    #
    # Trigger Map-Register when all databaase-mappings are configured.
    #
    # Do not trigger Map-Register if NAT-traveral is configured. We may not
    # have the global RLOC yet from Info-Replies. When the Info-Reply comes
    # in we do trigger Map-Registers to all map-servers.
    #
    if (lisp.lisp_nat_traversal): return
    if (lisp_trigger_register_timer != None): return

    #
    # Wait until a large set of database-mapping commands are processed
    # before sending the first set of Map-Registers. Used in test mode only.
    #
    if (lisp_etr_test_mode):
        db_size = len(lisp.lisp_db_list)
        if (db_size % 1000 == 0):
            lisp.fprint("{} database-mappings processed".format(db_size))
        #endif

        db = lisp.lisp_db_list[-1]
        if (db.eid.is_dist_name() == False): return
        if (db.eid.address != "eid-done"): return
        lisp_seen_eid_done = True

        lisp.fprint("Finished batch of {} database-mappings".format(db_size))

        t = threading.Timer(0, lisp_process_register_timer,
            [lisp_send_sockets])
        lisp_register_timer = t
        lisp_register_timer.start()
        return
    #endif

    if (len(lisp.lisp_map_servers_list) > 0):
        lisp_trigger_register_timer = threading.Timer(5,
            lisp_process_register_timer, [lisp_send_sockets])
        lisp_trigger_register_timer.start()
    #endif
#enddef

#
# lisp_etr_show_command
#
# Show ETR configured map-servers and database-mappings.
#
def lisp_etr_show_command(clause):

    #
    # Show local found RLOCs.
    #
    output = lispconfig.lisp_show_myrlocs("")

    #
    # Show decapsulation stats.
    #
    output = lispconfig.lisp_show_decap_stats(output, "ETR")

    #
    # Show configured map-servers.
    #
    dns_suffix = lisp.lisp_decent_dns_suffix
    if (dns_suffix == None):
        dns_suffix = ":"
    else:
        dns_suffix = "&nbsp;(dns-suffix '{}'):".format(dns_suffix)
    #endif

    hover = "{} configured map-servers".format(len(lisp.lisp_map_servers_list))
    title = "LISP-ETR Configured Map-Servers{}".format(dns_suffix)
    title = lisp.lisp_span(title, hover)

    hover = ("P = proxy-reply requested, M = merge-registrations " + \
        "requested, N = Map-Notify requested")
    reg_title = lisp.lisp_span("Registration<br>flags", hover) 

    output += lispconfig.lisp_table_header(title, "Address", "Auth-Type", 
        "xTR-ID", "Site-ID", reg_title, "Map-Registers<br>Sent", 
        "Map-Notifies<br>Received")

    for ms in list(lisp.lisp_map_servers_list.values()):
        ms.resolve_dns_name()
        ms_name = "" if ms.ms_name == "all" else ms.ms_name + "<br>"
        addr_str = ms_name + ms.map_server.print_address_no_iid()
        if (ms.dns_name): addr_str += "<br>" + ms.dns_name

        xtr_id = "0x" + lisp.lisp_hex_string(ms.xtr_id)
        flags = "{}-{}-{}-{}".format("P" if ms.proxy_reply else "p",
            "M" if ms.merge_registrations else "m",
            "N" if ms.want_map_notify else "n",
            "R" if ms.refresh_registrations else "r")

        registers_sent = ms.map_registers_sent + \
            ms.map_registers_multicast_sent

        output += lispconfig.lisp_table_row(addr_str, 
           "sha1" if (ms.alg_id == lisp.LISP_SHA_1_96_ALG_ID) else  "sha2",
            xtr_id, ms.site_id, flags, registers_sent,
            ms.map_notifies_received)
    #endfor
    output += lispconfig.lisp_table_footer()

    #
    # Show database-mappings configured.
    #
    output = lispconfig.lisp_show_db_list("ETR", output)

    #
    # Show ELP configuration, if it exists.
    #
    if (len(lisp.lisp_elp_list) != 0):
        output = lispconfig.lisp_show_elp_list(output)
    #endif

    #
    # Show RLE configuration, if it exists.
    #
    if (len(lisp.lisp_rle_list) != 0):
        output = lispconfig.lisp_show_rle_list(output)
    #endif

    #
    # Show JSON configuration, if it exists.
    #
    if (len(lisp.lisp_json_list) != 0):
        output = lispconfig.lisp_show_json_list(output)
    #endif

    #
    # Show group-mappings, if they exist.
    #
    if (len(lisp.lisp_group_mapping_list) != 0):
        title = "Configured Group Mappings:"
        output += lispconfig.lisp_table_header(title, "Name", "Group Prefix", 
            "Sources", "Use MS")
        for gm in list(lisp.lisp_group_mapping_list.values()):
            sources = ""
            for s in gm.sources: sources += s + ", "
            if (sources == ""):
                sources = "*"
            else:
                sources = sources[0:-2]
            #endif
            output += lispconfig.lisp_table_row(gm.group_name, 
                gm.group_prefix.print_prefix(), sources, gm.use_ms_name)
        #endfor
        output += lispconfig.lisp_table_footer()
    #endif
    return(output)
#enddef

#
# lisp_etr_show_keys_command
#
# Call lispconfig.lisp_show_crypto_list().
#
def lisp_etr_show_keys_command(parameter):
    return(lispconfig.lisp_show_crypto_list("ETR"))
#enddef

#
# lisp_group_mapping_command
#
# Process the "lisp group-mapping" command clause.
#
def lisp_group_mapping_command(kv_pairs):
    sources = []
    group_prefix = None
    rle_address = None
    ms_name = "all"

    for kw in list(kv_pairs.keys()):
        value = kv_pairs[kw]
        if (kw == "group-name"): 
            group_name = value
        #endif
        if (kw == "group-prefix"): 
            if (group_prefix == None):
                group_prefix = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
            #endif
            group_prefix.store_prefix(value)
        #endif
        if (kw == "instance-id"): 
            if (group_prefix == None):
                group_prefix = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
            #endif
            group_prefix.instance_id = int(value)
        #endif
        if (kw == "ms-name"): 
            ms_name = value[0]
        #endif
        if (kw == "address"):
            for source in value:
                if (source != ""): sources.append(source)
            #endfor
        #endif
        if (kw == "rle-address"):
            if (rle_address == None):
                rle_address = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
            #endif
            rle_address.store_address(value)
        #endif
    #endfor
    gm = lisp.lisp_group_mapping(group_name, ms_name, group_prefix, sources,
        rle_address)
    gm.add_group()
    return
#enddef

#
# lisp_build_map_register_records
#
# Build EID and RLOC records to be inserted in a Map-Register message.
#
def lisp_build_map_register_records(quiet, db, eid, group, ttl):

    #
    # Don't include RTR-list if there is no NAT in the path but nat-traversal
    # is configured and NAT in path is tested. When there is a NAT, include
    # all RTRs if lisp_register_all_rtrs is configured. Otherwise, if the
    # array element is None, then the RTR is down and should be excluded in
    # the list to register.
    #
    rtr_list = {}
    for rloc_entry in db.rloc_set:
        if (rloc_entry.translated_rloc.is_null()): continue

        for rtr_str in lisp.lisp_rtr_list:
            rtr = lisp.lisp_rtr_list[rtr_str]
            if (lisp.lisp_register_all_rtrs == False and rtr == None):
                lisp.lprint("  Exclude unreachable RTR {}".format( \
                    lisp.red(rtr_str, False)))
                continue
            #endif
            if (rtr == None): continue
            rtr_list[rtr_str] = rtr
        #endif
        break
    #endfor

    count = 0
    eid_records = ""
    for iid in [eid.instance_id] + eid.iid_list:
        eid_record = lisp.lisp_eid_record()

        eid_record.rloc_count = len(db.rloc_set) + len(rtr_list)
        eid_record.authoritative = True
        eid_record.record_ttl = ttl
        eid_record.eid.copy_address(eid)
        eid_record.eid.instance_id = iid
        eid_record.eid.iid_list = []
        eid_record.group.copy_address(group)

        eid_records += eid_record.encode()
        if (not quiet): 
            prefix_str = lisp.lisp_print_eid_tuple(eid, group)
            decent_index = ""
            if (lisp.lisp_decent_pull_xtr_configured()):
                decent_index = lisp.lisp_get_decent_index(eid)
                decent_index = lisp.bold(str(decent_index), False)
                decent_index = ", decent-index {}".format(decent_index)
            #endif
            lisp.lprint("  EID-prefix {} for ms-name '{}'{}".format( \
                lisp.green(prefix_str, False), db.use_ms_name, decent_index))
            eid_record.print_record("  ", False)
        #endif

        for rloc_entry in db.rloc_set:
            rloc_record = lisp.lisp_rloc_record()
            rloc_record.store_rloc_entry(rloc_entry)
            rloc_record.local_bit = rloc_entry.rloc.is_local()
            rloc_record.reach_bit = True
            eid_records += rloc_record.encode()
            if (not quiet): rloc_record.print_record("    ")
        #endfor

        #
        # If we are doing NAT-traversal, include a set or RTR RLOCs with
        # priority 1. And set the global RLOCs to priority 254.
        #
        for rtr in list(rtr_list.values()):
            rloc_record = lisp.lisp_rloc_record()
            rloc_record.rloc.copy_address(rtr)
            rloc_record.priority = 254
            rloc_record.rloc_name = "RTR"
            rloc_record.weight = 0
            rloc_record.mpriority = 255
            rloc_record.mweight = 0
            rloc_record.local_bit = False
            rloc_record.reach_bit = True
            eid_records += rloc_record.encode()
            if (not quiet): rloc_record.print_record("    RTR ")
        #endfor

        #
        # Return to caller number of EID records written to returned buffer.
        #
        count += 1
    #endfor
    return(eid_records, count)
#enddef

#
# lisp_build_map_register
#
# From each configured "database-mapping" command, register mappings to 
# configured map-servers.
#
def lisp_build_map_register(lisp_sockets, ttl, eid_only, ms_only, refresh):

    #
    # No database-mapping entries.
    #
    if (eid_only != None): 
        db_list_len = 1
    else:
        db_list_len = lisp.lisp_db_list_length()
        if (db_list_len == 0): return
    #endif

    if (lisp_etr_test_mode):
        lisp.fprint("Build Map-Register for {} database-mapping entries". \
            format(db_list_len))
    else:
        lisp.fprint("Build Map-Register for {} database-mapping entries". \
            format(db_list_len))
    #endif

    #
    # Set boolean if "decentralized-pull-xtr-[modulus,dns-suffix]" configured.
    #
    decent = lisp.lisp_decent_pull_xtr_configured()

    #
    # Go quiet with debug output when there are a lot of EID-records.
    #
    quiet = (db_list_len > 12)

    ms_list = {}
    if (decent):

        #
        # If "decentralized-pull-xtr-[modulus,dns-suffix]" is configured,
        # decide which map-server this EID belongs too (and is registered with.
        #
        for db in lisp.lisp_db_list:
            eid = db.eid if db.group.is_null() else db.group
            dns_name = lisp.lisp_get_decent_dns_name(eid)
            ms_list[dns_name] = []
        #endfor
    else:

        #
        # Set up each map-server names so we can decide which EID-prefixes go
        # to which map-servers. [0] is eid_records and [1] is count.
        #
        for ms in list(lisp.lisp_map_servers_list.values()):
            if (ms_only != None and ms != ms_only): continue
            ms_list[ms.ms_name] = []
        #endfor
    #endif

    #
    # Create data structure instances to build Map-Regiser message.
    #
    map_register = lisp.lisp_map_register()
    map_register.nonce = 0xaabbccdddfdfdf00
    map_register.xtr_id_present = True
    map_register.use_ttl_for_timeout = True

    if (ttl == None): ttl = lisp.LISP_REGISTER_TTL

    #
    # Traverse the databas-mapping associative array.
    #
    mtu = 65000 if (lisp_etr_test_mode) else 1100
    for db in lisp.lisp_db_list:
        if (decent):
            ms_dns_name = lisp.lisp_get_decent_dns_name(db.eid)
        else:
            ms_dns_name = db.use_ms_name
        #endif

        #
        # Is db entry associated with a map-server name that is not
        # configured?
        #
        if (ms_dns_name not in ms_list): continue

        msl = ms_list[ms_dns_name]
        if (msl == []):
            msl = ["", 0]
            ms_list[ms_dns_name].append(msl)
        else:
            msl = ms_list[ms_dns_name][-1]
        #endif

        #
        # If dynamic-EIDs are discovered, add each of them to EID-records, 
        # unless, we are doing a trigger in which case a single dynamic-EID
        # is built into an EID-record.
        #
        # Otherwise, add static EID-prefixes into EID-records, unless a single
        # one is triggered.
        #
        eid_records = ""
        if (db.dynamic_eid_configured()):
            for dyn_eid in list(db.dynamic_eids.values()):
                eid = dyn_eid.dynamic_eid
                if (eid_only == None or eid_only.is_exact_match(eid)):
                    records, count = lisp_build_map_register_records(quiet, db,
                        eid, db.group, ttl)
                    eid_records += records
                    msl[1] += count
                #endif
            #endfor
        else:            
            if (eid_only == None):
                if (ttl != 0): ttl = db.register_ttl
                eid_records, count = lisp_build_map_register_records(quiet, db,
                    db.eid, db.group, ttl)
                msl[1] += count
            #endif
        #endif

        #
        # Add EID-records to correct map-server name set.
        #
        msl[0] += eid_records

        if (msl[1] == 20 or len(msl[0]) > mtu):
            msl = ["", 0]
            ms_list[ms_dns_name].append(msl)
        #endif
    #endfor

    #
    # Send Map-Register to each configured map-server.
    #
    sleep_time = .500 if (lisp_etr_test_mode) else .001
    count = 0
    for ms in list(lisp.lisp_map_servers_list.values()):
        if (ms_only != None and ms != ms_only): continue

        ms_dns_name = ms.dns_name if decent else ms.ms_name
        if (ms_dns_name not in ms_list): continue
        
        for msl in ms_list[ms_dns_name]:

            #
            # Build map-server specific fields.
            #
            map_register.record_count = msl[1]
            if (map_register.record_count == 0): continue

            map_register.nonce += 1
            map_register.alg_id = ms.alg_id
            map_register.key_id = ms.key_id
            map_register.proxy_reply_requested = ms.proxy_reply
            map_register.merge_register_requested = ms.merge_registrations
            map_register.map_notify_requested = ms.want_map_notify
            map_register.xtr_id = ms.xtr_id
            map_register.site_id = ms.site_id
            map_register.encrypt_bit = (ms.ekey != None)
            if (ms.refresh_registrations): 
                map_register.map_register_refresh = refresh
            #endif
            if (ms.ekey != None): map_register.encryption_key_id = ms.ekey_id
            packet = map_register.encode()
            map_register.print_map_register()

            #
            # Append EID-records and encode xtr-ID and site-ID at end of 
            # Map-Register.
            #
            trailer = map_register.encode_xtr_id("")
            eid_records = msl[0]
            packet = packet + eid_records + trailer

            ms.map_registers_sent += 1
            lisp.lisp_send_map_register(lisp_sockets, packet, map_register, ms)

            count += 1
            if (count % 100 == 0 and lisp_etr_test_mode):
                sleep_time += .1
                lisp.fprint("Sent {} Map-Registers, ipd {}".format(count,
                    sleep_time))
            #endif
            time.sleep(sleep_time)
        #endfor

        if (lisp_etr_test_mode):
            lisp.fprint("Sent total {} Map-Registers".format(count))
        #endif

        #
        # Do DNS lookup for Map-Server if "dns-name" configured.
        #
        ms.resolve_dns_name()

        #
        # Exit loop if we are triggering a Map-Register to a single 
        # Map-Server.
        # 
        if (ms_only != None and ms == ms_only): break
    #endfor
    return
#enddef

#
# lisp_etr_process_info_timer
#
# Time to send a periodic Info-Request message. This must be done less often
# then sending periodic Map-Registers as well as less the the NAT timeout
# value which is usually one minute.
#
def lisp_etr_process_info_timer(ms):
    global lisp_etr_info_timer
    global lisp_ephem_socket

    lisp.lisp_set_exception()

    #
    # Build Info-Request messages if we have any private RLOCs in database-
    # mappings.
    #
    sockets = [lisp_ephem_socket, lisp_ephem_socket, lisp_ipc_listen_socket]
    lisp.lisp_build_info_requests(sockets, ms, lisp.LISP_CTRL_PORT)

    #
    # Build Info-Request for RTRs so we can open up NAT state so RTRs
    # can encapsulate to us when ETR is behind NAT.
    #
    allow_private = (os.getenv("LISP_RTR_BEHIND_NAT") == None)
    for rtr in list(lisp.lisp_rtr_list.values()):
        if (rtr == None): continue
        if (rtr.is_private_address() and allow_private == False):
            r = lisp.red(rtr.print_address_no_iid(), False)
            lisp.lprint("Skip over RTR private address {}".format(r))
            continue
        #endif
        lisp.lisp_build_info_requests(sockets, rtr, lisp.LISP_DATA_PORT)
    #endfor
    
    #
    # Restart periodic timer. For some reason only this timer has to be
    # canceled. Found on while testing NAT-traversal on rasp-pi in Jul 2015.
    #
    lisp_etr_info_timer.cancel()
    lisp_etr_info_timer = threading.Timer(lisp.LISP_INFO_INTERVAL, 
        lisp_etr_process_info_timer, [None])
    lisp_etr_info_timer.start()
    return
#enddef

#
# lisp_process_register_timer
#
# Time to send a periodic Map-Register.
#
def lisp_process_register_timer(lisp_sockets):
    global lisp_register_timer, lisp_trigger_register_timer
    global lisp_ephem_socket

    lisp.lisp_set_exception()

    #
    # Build and send Map-Register.
    #
    lisp_build_map_register(lisp_sockets, None, None, None, True)

    #
    # If we are are doing L2-overlays, then register as a join of the
    # broadcast MAC address.
    #
    if (lisp.lisp_l2_overlay):
        entry = [ None, "ffff-ffff-ffff", True ]
        lisp_send_multicast_map_register(lisp_sockets, [entry])
    #endif

    #
    # If trigger timer called this function, clear it out and only use it
    # when a new map-server of database-mapping is configured.
    #
    if (lisp_trigger_register_timer != None):
        lisp_trigger_register_timer.cancel()
        lisp_trigger_register_timer = None
    #endif

    #
    # Restart periodic timer.
    #
    if (lisp_register_timer): lisp_register_timer.cancel()
    lisp_register_timer = threading.Timer(LISP_MAP_REGISTER_INTERVAL, 
        lisp_process_register_timer, [lisp_send_sockets])
    lisp_register_timer.start()
    return
#enddef

#
# lisp_send_multicast_map_register
#
# Build a Map-Register message with a Multicast Info Type LCAF as an EID-record
# for each entry in the 'entries' array. And build an RLOC-record as an RLE
# describing this ETR as the RLOC to be used for replication.
#
# The entries is an array of (source, group, joinleave) tuples.
#
def lisp_send_multicast_map_register(lisp_sockets, entries):
    length = len(entries)
    if (length == 0): return

    afi = None
    if (entries[0][1].find(":") != -1): afi = lisp.LISP_AFI_IPV6 
    if (entries[0][1].find(".") != -1): afi = lisp.LISP_AFI_IPV4
    if (entries[0][1].find("-") != -1): afi = lisp.LISP_AFI_MAC
    if (afi == None): 
        lisp.lprint("lisp_send_multicast_map_register() invalid group address")
        return
    #endif

    #
    # Find all (*,G) entries in entries array and replace with (S,G) entries
    # from lisp_group_mapping_list. The comment to avoid the source check
    # is there so we can build a g_entry that can validate against group
    # mappings. Have to fix to allow different sources for the same G when
    # (S,G) is reported.
    #
    g_entries = []
    for source, group, joinleave in entries:
#       if (source != None): continue
        g_entries.append([group, joinleave])
    #endfor

    decent = lisp.lisp_decent_pull_xtr_configured()

    ms_list = {}
    entries = []
    for group, joinleave in g_entries: 
        ms_gm = lisp.lisp_lookup_group(group)
        if (ms_gm == None):
            lisp.lprint("No group-mapping for {}, could be underlay group". \
                format(group))
            continue
        #endif

        lisp.lprint("Use group-mapping '{}' {} for group {}".format( \
            ms_gm.group_name, ms_gm.group_prefix.print_prefix(), group))

        iid = ms_gm.group_prefix.instance_id
        ms_name = ms_gm.use_ms_name
        rle = ms_gm.rle_address

        #
        # To obtain decent-index for a group address, just use group address
        # and no source as part of hash. Because an ITR does not know if (*,G)
        # or (S,G) is registered with the mapping system
        #
        key = ms_name
        if (decent):
            key = lisp.lisp_get_decent_dns_name_from_str(iid, group)
            ms_list[key] = ["", 0]
        #endif

        if (len(ms_gm.sources) == 0): 
            entries.append(["0.0.0.0", group, iid, key, rle, joinleave])
            continue
        #endif
        for s in ms_gm.sources: 
            ms_list[key] = ["", 0]
            entries.append([s, group, iid, key, rle, joinleave])
        #endfor
    #endfor

    length = len(entries)
    if (length == 0): return

    lisp.lprint("Build Map-Register for {} multicast entries".format(length))

    #
    # Build RLE node for RLOC-record encoding. If behind a NAT, we need to
    # insert a global address as the RLE node address. We will do that in
    # the entries for loop.
    #
    rle_node = lisp.lisp_rle_node()
    rle_node.level = 128
    translated_rloc = lisp.lisp_get_any_translated_rloc()
    rle = lisp.lisp_rle("")
    rle.rle_nodes.append(rle_node)

    #
    # Set up each map-server names so we can decide which EID-prefixes go
    # to which map-servers. [0] is eid_records and [1] is count. The ms_list
    # is already setup for when pull-based decent is used.
    #
    if (decent == False):
        for ms in list(lisp.lisp_map_servers_list.values()):
            ms_list[ms.ms_name] = ["", 0]
        #endfor
    #endif

    rloc_name = None
    if (lisp.lisp_nat_traversal): rloc_name = lisp.lisp_hostname

    #
    # Count number of RTRs reachable so we know allocation count.
    #
    rtr_count = 0
    for rtr in list(lisp.lisp_rtr_list.values()):
        if (rtr == None): continue
        rtr_count += 1
    #endfor

    #
    # Run through multicast entry array.
    #
    eid_records = ""
    for source, group, iid, ms_dns_name, rle_addr, joinleave in entries:

        #
        # Is db entry associated with a map-server name that is not configured?
        #
        if (ms_dns_name not in ms_list): continue

        eid_record = lisp.lisp_eid_record()
        eid_record.rloc_count = 1 + rtr_count
        eid_record.authoritative = True
        eid_record.record_ttl = lisp.LISP_REGISTER_TTL if joinleave else 0
        eid_record.eid = lisp.lisp_address(afi, source, 0, iid)
        if (eid_record.eid.address == 0): eid_record.eid.mask_len = 0
        eid_record.group = lisp.lisp_address(afi, group, 0, iid)
        if (eid_record.group.is_mac_broadcast() and \
            eid_record.eid.address == 0): eid_record.eid.mask_len = 0

        decent_index = ""
        ms_name = ""
        if (lisp.lisp_decent_pull_xtr_configured()):
            decent_index = lisp.lisp_get_decent_index(eid_record.group)
            decent_index = lisp.bold(str(decent_index), False)
            decent_index = "with decent-index {}".format(decent_index)
        else:
            decent_index = "for ms-name '{}'".format(ms_dns_name)
        #endif

        eid_str = lisp.green(eid_record.print_eid_tuple(), False)
        lisp.lprint("  EID-prefix {} {}{}".format(eid_str, ms_name,
            decent_index))

        eid_records += eid_record.encode()
        eid_record.print_record("  ", False)
        ms_list[ms_dns_name][1] += 1

        #
        # Build our RLOC entry.
        #
        rloc_record = lisp.lisp_rloc_record()
        rloc_record.rloc_name = rloc_name

        #
        # Decide on RLE address. Have NAT-traversal take precedent, otherwise
        # use configured RLE in group-mapping. If one wasn't configured use
        # lisp_myrlocs IPv4 address.
        #
        if (translated_rloc != None): 
            rle_node.address = translated_rloc
        elif (rle_addr != None):
            rle_node.address = rle_addr
        else:
            rle_node.address = rle_addr = lisp.lisp_myrlocs[0]
        #endif

        rloc_record.rle = rle
        rloc_record.local_bit = True
        rloc_record.reach_bit = True
        rloc_record.priority = 255
        rloc_record.weight = 0
        rloc_record.mpriority = 1
        rloc_record.mweight = 100
        eid_records += rloc_record.encode()
        rloc_record.print_record("    ")

        #
        # If we are doing NAT-traversal, include a set or RTR RLOCs with
        # priority 1. And set the global RLOCs to priority 254.
        #
        for rtr in list(lisp.lisp_rtr_list.values()):
            if (rtr == None): continue
            rloc_record = lisp.lisp_rloc_record()
            rloc_record.rloc.copy_address(rtr)
            rloc_record.priority = 254
            rloc_record.rloc_name = "RTR"
            rloc_record.weight = 0
            rloc_record.mpriority = 255
            rloc_record.mweight = 0
            rloc_record.local_bit = False
            rloc_record.reach_bit = True
            eid_records += rloc_record.encode()
            rloc_record.print_record("    RTR ")
        #endfor

        #
        # Add EID-records to correct map-server name set.
        #
        ms_list[ms_dns_name][0] += eid_records
    #endfor

    #
    # Build map-server independent fields.
    #
    map_register = lisp.lisp_map_register()
    map_register.nonce = 0xaabbccdddfdfdf00
    map_register.xtr_id_present = True
    map_register.proxy_reply_requested = True
    map_register.map_notify_requested = False
    map_register.merge_register_requested = True

    #
    # Send Map-Register to each configured map-server.
    #
    for ms in list(lisp.lisp_map_servers_list.values()):
        key = ms.dns_name if decent else ms.ms_name

        #
        # Get EID-records from correct map-server name set.
        #
        if (key not in ms_list): continue

        #
        # Build map-server specific fields.
        #
        map_register.record_count = ms_list[key][1]
        if (map_register.record_count == 0): continue

        map_register.nonce += 1
        map_register.alg_id = ms.alg_id
        map_register.alg_id = ms.key_id
        map_register.xtr_id = ms.xtr_id
        map_register.site_id = ms.site_id
        map_register.encrypt_bit = (ms.ekey != None)
        packet = map_register.encode()
        map_register.print_map_register()

        #
        # Append EID-records and encode xtr-ID and site-ID at end of 
        # Map-Register.
        #
        trailer = map_register.encode_xtr_id("")
        packet = packet + eid_records + trailer

        ms.map_registers_multicast_sent += 1
        lisp.lisp_send_map_register(lisp_sockets, packet, map_register, ms)

        #
        # Do DNS lookup for Map-Server if "dns-name" configured.
        #
        ms.resolve_dns_name()

        #
        # Go build more EID-records.
        #
        time.sleep(.001)
    #endfor
    return
#enddef

#
# lisp_etr_data_plane
#
# Capture a LISP encapsulated packet, decap it, process inner header, and
# re-encapsulated it.
#
def lisp_etr_data_plane(parms, not_used, packet):
    global lisp_ipc_listen_socket, lisp_send_sockets

    device = parms[0]
    lisp_raw_socket = parms[1]

    #
    # Jump over MAC header if packet received on interface. There is a 4-byte
    # internal header in any case (loopback interfaces will have a 4 byte
    # header)..
    #
    if (lisp.lisp_is_macos() == False):
        offset = 4 if device == "lo0" else 16
        packet = packet[offset::]
    #endif

    #
    # Check IGMP packet.
    #
    protocol = struct.unpack("B", packet[9])[0]
    if (protocol == 2):
        entries = lisp.lisp_process_igmp_packet(packet)
        if (type(entries) != bool):
            lisp_send_multicast_map_register(lisp_send_sockets, entries)
            return
        #endif
    #endif

    #
    # Check RLOC-probe Map-Request. We need to grab the TTL from IP header.
    #
    orig_packet = packet
    packet, source, port, ttl = lisp.lisp_is_rloc_probe(packet, 0)
    if (orig_packet != packet):
        if (source == None): return
        lisp.lisp_parse_packet(lisp_send_sockets, packet, source, port, ttl)
        return
    #endif

    #
    # First check if we are assembling IPv4 fragments. Do this only when
    # not doing NAT-traversal. Otherwise, the kernel will do it when we 
    # receive the same packet on a raw socket (in lisp_etr_nat_data_plane()).
    #
    if (struct.unpack("B", packet[0])[0] & 0xf0 == 0x40):
        sport = socket.ntohs(struct.unpack("H", packet[20:22])[0])
        if (lisp.lisp_nat_traversal and sport == lisp.LISP_DATA_PORT): return
        packet = lisp.lisp_reassemble(packet)
        if (packet == None): return
    #endif

    packet = lisp.lisp_packet(packet)
    status = packet.decode(True, lisp_ipc_listen_socket, lisp.lisp_decap_stats)
    if (status == None): return

    #
    # Print some useful header fields.
    #
    packet.print_packet("Receive", True)

    #
    # If we are looping back Map-Registers via encapsulation, overwrite
    # multicast address with source address. That means we are sending a
    # Map-Register message to the lisp-core process from our local RLOC
    # address to our local RLOC address. Also, zero out the UDP checksum
    # since the destination address changes that affects the pseudo-header.
    #
    if (lisp.lisp_decent_push_configured and
        packet.inner_dest.is_multicast_address() and \
        packet.lisp_header.get_instance_id() == 0xffffff):
        source = packet.inner_source.print_address_no_iid()
        packet.strip_outer_headers()
        packet = packet.packet[28::]
        packet = lisp.lisp_packet_ipc(packet, source, sport)
        lisp.lisp_ipc(packet, lisp_ipc_listen_socket, "lisp-ms")
        return
    #endif

    #
    # Check if inner packet is a LISP control-packet. Typically RLOC-probes
    # from RTRs can come through NATs. We want to reply to the global address
    # of the RTR which is the outer source RLOC. We don't care about the
    # inner source port since the RTR will decapsulate a data encapsulated
    # RLOC-probe Map-Reply. The inner LISP header begins at offset 20+16+28=64
    # (outer-IPv4 + UDP-outer-LISP + inner-IPv4-UDP).
    #
    if (packet.lisp_header.get_instance_id() == 0xffffff):
        inner_ip = packet.packet[36::]
        inner_lisp = inner_ip[28::]
        ttl = -1
        if (lisp.lisp_is_rloc_probe_request(inner_lisp[0])):
            ttl = struct.unpack("B", inner_ip[8])[0] - 1
        #endif
        source = packet.outer_source.print_address_no_iid()
        lisp.lisp_parse_packet(lisp_send_sockets, inner_lisp, source, 0, ttl)
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
    lisp.lisp_decap_stats["good-packets"].increment(len(packet.packet))

    #
    # Strip outer headers and start inner header forwarding logic.
    #
    packet.strip_outer_headers()
    f_or_b = lisp.bold("Forward", False)

    #
    # Process inner header (checksum and decrement ttl).
    #
    igmp = False
    L2 = packet.inner_dest.is_mac()
    if (L2):
        packet.packet = lisp.lisp_mac_input(packet.packet)
        if (packet.packet == None): return
        f_or_b = lisp.bold("Bridge", False)
    elif (packet.inner_version == 4):
        igmp, packet.packet = lisp.lisp_ipv4_input(packet.packet)
        if (packet.packet == None): return
        if (igmp):
            entries = lisp.lisp_process_igmp_packet(packet.packet)
            if (type(entries) != bool):
                lisp_send_multicast_map_register(lisp_send_sockets, entries)
                return
            #endif
        #endif
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
    # Check if database-mapping exists for our local destination. When the
    # destination is a multicast address, check if the source is our EID.
    # That means we sent to a group we are members of. If using an RTR,
    # it can't tell since the source RLOC could be rewritten by a NAT so
    # the ETR must process the packet. If it decaps, the ITR on this system
    # will pcap it and encap again. This will happen until the TTL reaches 0.
    #
    if (packet.inner_dest.is_multicast_address() == False):
        db = lisp.lisp_db_for_lookups.lookup_cache(packet.inner_dest, False)
        if (db):
            db.increment_decap_stats(packet)
        else:
            lisp.dprint("No database-mapping found for EID {}".format( \
                lisp.green(packet.inner_dest.print_address(), False)))
            return
        #endif
    else:
        if (lisp.lisp_db_for_lookups.lookup_cache(packet.inner_source, False)):
            lisp.dprint("Discard echoed multicast packet (through NAT)")
            return
        #endif
    #endif

    #
    # If this is a trace packet, lisp_trace_append() will swap addresses
    # and send packet back to source. We have no app to forward this decap'ed
    # packet to, so return.
    #
    if (packet.is_trace()):
        if (lisp.lisp_trace_append(packet, ed="decap") == False): return
    #endif

    #
    # We are going to forward or bridge the decapsulated packet.
    #
    addr_str = "{} -> {}".format(packet.inner_source.print_address(),
        packet.inner_dest.print_address())

    lisp.dprint("{} packet for EIDs {}: {} ...".format(f_or_b, \
        lisp.green(addr_str, False), 
        lisp.lisp_format_packet(packet.packet[0:60])))

    #
    # If we are decapsulating a MAC frame, then use the L2 socket where
    # the MAC header is already in packet.
    #
    if (L2):
        packet.bridge_l2_packet(packet.inner_dest, db)
        return
    #endif

    #
    # Send on L2 socket since IPv6 raw sockets do not allow us to send an
    # entire IPv6 header in payload. Prepend prebuilt MAC header.
    #
    if (packet.inner_version == 6):
        packet.send_l2_packet(lisp_l2_socket, lisp_mac_header)
        return
    #endif

    #
    # Default to global raw socket otherwise get socket baesd on instance-ID.
    #
    raw_socket = packet.get_raw_socket()
    if (raw_socket == None): raw_socket = lisp_raw_socket

    #
    # Send out.
    #
    packet.send_packet(raw_socket, packet.inner_dest)
    return
#enddef

#
# lisp_etr_nat_data_plane
#
# Packet came in on a destination ephemeral port from a source port of 4341.
# That is a RTR encapsulated this packet that is coming through a NAT device.
#
# The packet has the outer IP and UDP headers stripped so the first byte of
# this supplied data packet has the LISP data header on it.
#
def lisp_etr_nat_data_plane(lisp_raw_socket, packet, source):
    global lisp_ipc_listen_socket, lisp_send_sockets

    #
    # Decode LISP header.
    #
    lisp_header = packet
    packet = lisp.lisp_packet(packet[8::])
    if (packet.lisp_header.decode(lisp_header) == False): return

    #
    # Store outer source RLOC address so if we are doing lisp-crypto across
    # NAT-traversal, we can find the decryption key.
    #
    packet.outer_source = lisp.lisp_address(lisp.LISP_AFI_IPV4, source, 
        lisp.LISP_IPV4_HOST_MASK_LEN, 0)

    status = packet.decode(False, lisp_ipc_listen_socket, 
        lisp.lisp_decap_stats)
    if (status == None): return

    #
    # Special case to log packets with no outer header but are considered
    # decapsulated when coming through NATs. Since packets are sent from
    # source port 4341, the kernel will strip outer header, so we don't have
    # outer header context in lisp_packet().
    #
    if (lisp.lisp_flow_logging): packet.log_flow(False)

    packet.print_packet("Kernel-decap", False)
    lisp.dprint(packet.lisp_header.print_header(" "))

    #
    # If we are looping back Map-Registers via encapsulation, overwrite
    # multicast address with source address. That means we are sending a
    # Map-Register message to the lisp-core process from our local RLOC
    # address to our local RLOC address. Also, zero out the UDP checksum
    # since the destination address changes that affects the pseudo-header.
    #
    if (lisp.lisp_decent_push_configured and
        packet.inner_dest.is_multicast_address() and \
        packet.lisp_header.get_instance_id() == 0xffffff):
        sport = packet.udp_sport
        packet = packet.packet[28::]
        packet = lisp.lisp_packet_ipc(packet, source, sport)
        lisp.lisp_ipc(packet, lisp_ipc_listen_socket, "lisp-ms")
        return
    #endif

    #
    # Check if inner packet is a LISP control-packet. Typically RLOC-probes
    # from RTRs can come through NATs. We want to reply to the global address
    # of the RTR which is the outer source RLOC. We don't care about the
    # inner source port since the RTR will decapsulate a data encapsulated
    # RLOC-probe Map-Reply.
    #
    if (packet.lisp_header.get_instance_id() == 0xffffff):
        inner_ip = packet.packet
        inner_lisp = inner_ip[28::]
        ttl = -1
        if (lisp.lisp_is_rloc_probe_request(inner_lisp[0])):
            ttl = struct.unpack("B", inner_ip[8])[0] - 1
        #endif
        lisp.lisp_parse_packet(lisp_send_sockets, inner_lisp, source, 0, ttl)
        return
    #endif

    #
    # Packets are arriving on ephemeral socket. Need to check if another data-
    # plane is running. If so, don't deliver duplicates.
    #
    if (lisp.lisp_ipc_data_plane): 
        lisp.dprint("Drop packet, external data-plane active")
        return
    #endif

    #
    # Increment global stats.
    #
    lisp.lisp_decap_stats["good-packets"].increment(len(packet.packet))

    #
    # Check if database-mapping exists for our local destination. When the
    # destination is a multicast address, check if the source is our EID.
    # That means we sent to a group we are members of. If using an RTR,
    # it can't tell since the source RLOC could be rewritten by a NAT so
    # the ETR must process the packet. If it decaps, the ITR on this system
    # will pcap it and encap again. This will happen until the TTL reaches 0.
    #
    if (packet.inner_dest.is_multicast_address() == False):
        db = lisp.lisp_db_for_lookups.lookup_cache(packet.inner_dest, False)
        if (db):
            db.increment_decap_stats(packet)
        else:
            lisp.dprint("No database-mapping found for EID {}".format( \
                lisp.green(packet.inner_dest.print_address(), False)))
            #endif
        #endif
    else:
        if (lisp.lisp_db_for_lookups.lookup_cache(packet.inner_source, False)):
            lisp.dprint("Discard echoed multicast packet")
            return
        #endif
    #endif

    #
    # If this is a trace packet, lisp_trace_append() will swap addresses
    # and send packet back to source. We have no app to forward this decap'ed
    # packet to, so return.
    #
    if (packet.is_trace()):
        if (lisp.lisp_trace_append(packet, ed="decap") == False): return
    #endif

    addr_str = "{} -> {}".format(packet.inner_source.print_address(),
        packet.inner_dest.print_address())

    lisp.dprint("{} packet for EIDs {}: {} ...".format( \
        lisp.bold("NAT-Forward", False), lisp.green(addr_str, False), 
            lisp.lisp_format_packet(packet.packet[0:60])))

    #
    # Send on L2 socket since IPv6 raw sockets do not allow us to send an
    # entire IPv6 header in payload. Prepend prebuilt MAC header
    #
    if (packet.inner_version == 6):
        packet.send_l2_packet(lisp_l2_socket, lisp_mac_header)
        return
    #endif

    #
    # Default to global raw socket otherwise get socket baesd on instance-ID.
    #
    raw_socket = packet.get_raw_socket()
    if (raw_socket == None): raw_socket = lisp_raw_socket

    #
    # Send out on raw socket.
    #
    packet.send_packet(raw_socket, packet.inner_dest)
    return
#enddef

#
# lisp_register_ipv6_group_entries
#
# Find an IPv6 group-mapping and send a Map-Register for each configured IPv6
# source for the IPv6 group-prefix found.
#
def lisp_register_ipv6_group_entries(group, joinleave):
    ms_gm = lisp.lisp_lookup_group(group)
    if (ms_gm == None): return

    sg = []
    for s in ms_gm.sources: 
        sg.append([s, group, joinleave])
    #endfor

    lisp_send_multicast_map_register(lisp_send_sockets, sg)
    return
#enddef

#
# lisp_etr_join_leave_process
#
# Look at file-system to see if there is a join or leave to be done. This
# function will send joins in the form of building an IP/IGMPv2 packet to
# be passed to lisp_process_igmp_packet(). The groups that are joined are
# ones found as filenames in the current directory as "join-<group>". The
# IGMP Reports wil lbe sent to lisp_process_igmp_packet() every 30 seconds.
#
# For right now, if the group address is IPv6, send a Map-Register directly.
# We will get to MLD support later.
#
# This is used for testing and not meant for production deployment.
#
def lisp_etr_join_leave_process():
    global lisp_send_sockets

    lisp.lisp_set_exception()

    swap = socket.htonl
    ipigmp = [swap(0x46000020), swap(0x9fe60000), swap(0x0102d7cc), 
              swap(0x0acfc15a), swap(0xe00000fb), swap(0x94040000)]

    packet = ""
    for l in ipigmp: packet += struct.pack("I", l)

    #
    # Look for files in current directory for "join-<group>" and then send
    # an IGMPv2 report to ourselves.
    #
    while (True):
        groups = getoutput("ls join-*").replace("join-", "")
        groups = groups.split("\n")

        for group in groups:
            if (lisp.lisp_valid_address_format("address", group) == False):
                continue
            #endif
            
            ipv6 = (group.find(":") != -1)

            #
            # Check if we are leaving group.
            #
            leavejoin = os.path.exists("leave-{}".format(group))
            lisp.lprint("Internal {} group {}".format( \
               "leaving" if leavejoin else "joining", group))

            #
            # Set IGMP message to Report or Leave. Then add group.
            #
            if (ipv6):
                if (group.lower().find("ff02:") != -1):
                    lisp.lprint("Suppress registration for link-local groups")
                    continue
                #endif
                lisp_register_ipv6_group_entries(group, (leavejoin == False))
            else:
                send_packet = packet
                if (leavejoin):
                    send_packet += struct.pack("I", swap(0x17000000))
                else:
                    send_packet += struct.pack("I", swap(0x16000000))
                #endif

                octet = group.split(".")
                value = int(octet[0]) << 24
                value += int(octet[1]) << 16
                value += int(octet[2]) << 8
                value += int(octet[3])
                send_packet += struct.pack("I", swap(value))
                sg = lisp.lisp_process_igmp_packet(send_packet)
                if (type(sg) != bool):
                    lisp_send_multicast_map_register(lisp_send_sockets, sg)
                #endif
                time.sleep(.100)
            #endif
        #endfor
        time.sleep(10)
    #endwhile
    return
#enddef

#
# lisp_etr_process
#
# This thread is for receiving encapsulated LISP packets address to destination
# port 4341. As well as IGMP reports. The IGMP reports can be captured on
# Ubuntu and Fedora but not on MacOS. The former supports IGMPv3 and the
# latter supports IGMPv2 if we listen on "en0".
#
def lisp_etr_process():
    lisp.lisp_set_exception()
    if (lisp.lisp_myrlocs[0] == None): return

    #
    # Find all multicast RLEs so we can receive packets on underlay multicast
    # groups.
    #
    rles = lisp.lisp_get_all_multicast_rles()

    #
    # We need to listen on en0 when doing IGMP testing on MacOS.
    #
    device = "any"
#   device = "en0" if lisp.lisp_is_macos() else "any"
#   device = "lo0" if lisp.lisp_is_macos() else "any"

    pfilter = "(proto 2) or "

    pfilter += "((dst host "
    for addr in lisp.lisp_get_all_addresses() + rles:
        pfilter += "{} or ".format(addr)
    #endif
    pfilter = pfilter[0:-4]
    pfilter += ") and ((udp dst port 4341 or 8472 or 4789) or "
    pfilter += "(udp src port 4341) or "
    pfilter += "(udp dst port 4342 and ip[28] == 0x12) or "
    pfilter += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + \
        "(ip[6]&0xe0 == 0 and ip[7] != 0)))))"

    lisp.lprint("Capturing packets for: '{}' on device {}".format(pfilter,
        device))

    #
    # Enter receive loop.
    #
    if (lisp.lisp_is_python2()):
        pcap = pcappy.open_live(device, 1600, 0, 100)
        pcap.filter = pfilter
        pcap.loop(-1, lisp_etr_data_plane, [device, lisp_raw_socket])
    #endif
    if (lisp.lisp_is_python3()):
        pcap = pcapy.open_live(device, 1600, 0, 100)
        pcap.setfilter(pfilter)
        while(True):
            header, packet = pcap.next()     
            lisp_etr_data_plane([device, lisp_raw_socket], None, packet)
        #endwhile
    #endif
    return
#enddef

#
# lisp_etr_startup
#
# Intialize this LISP ETR process. This function returns no values.
#
def lisp_etr_startup():
    global lisp_ipc_listen_socket
    global lisp_ephem_socket
    global lisp_send_sockets
    global lisp_raw_socket
    global lisp_l2_socket
    global lisp_mac_header

    lisp.lisp_i_am("etr")
    lisp.lisp_set_exception()
    lisp.lisp_print_banner("ETR starting up")

    #
    # Get local address for source RLOC for encapsulation.
    #
    lisp.lisp_get_local_interfaces()
    lisp.lisp_get_local_macs()
    if (lisp.lisp_get_local_addresses() == False): return(False)

    #
    # Prebuild MAC header for lisp_l2_socket sending. Disabled code in favor
    # of using pytun. See below.
    #
#   m = list(lisp.lisp_mymacs.keys())[0]
#   mac = ""
#   for i in range(0, 12, 2): mac += chr(int(m[i:i+2], 16))
#   lisp_mac_header = mac + mac + "\x86\xdd"
#   lisp.dprint("Built MAC header for L2 socket:", 
#       lisp.lisp_format_packet(lisp_mac_header))
    
    #
    # Used on for listening for Info-Replies for NAT-traversal support.
    #
    s = lisp.lisp_open_listen_socket("0.0.0.0", str(lisp_ephem_port))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
    lisp_ephem_socket = s

    #
    # Open network send socket and internal listen socket.
    #
    lisp_ipc_listen_socket = lisp.lisp_open_listen_socket("", "lisp-etr")

    lisp_send_sockets[0] = lisp_ephem_socket
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
    # Open a L2 socket so when we decapsulate and have to route an IPv6
    # packet, we have the kernel receive a MAC frame on the loopback interface.
    # We do this because there is no IP_HDRINCL for IPv6 raw sockets.
    #
    # Disabling this code in favor of using a tuntap tun interface via the
    # pytun module. See code right below.
    #
#   if ("PF_PACKET" in dir(socket)):
#       interface = "lo" if ("lo" in lisp.lisp_myinterfaces.keys()) else \
#           "lo0" if ("lo0" in lisp.lisp_myinterfaces.keys()) else None
#       if (interface != None):
#           lisp_l2_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
#           lisp_l2_socket.bind(("lo", 0x86dd))
#       #endif
#   #endif

    # 
    # Setup tuntap tunnel interface so when we decap IPv6 packets, we can
    # send to kernel to route them.
    #
    if (pytun != None):
        lisp_mac_header = '\x00\x00\x86\xdd'
        device = "lispers.net"
        try:
            lisp_l2_socket = pytun.TunTapDevice(flags=pytun.IFF_TUN, 
                name=device)
            os.system("ip link set dev {} up".format(device))
        except:
            lisp.lprint("Cannot create tuntap interface")
        #endtry
    #endif

    #
    # Start thread to listen on data socket.
    #
    threading.Thread(target=lisp_etr_process, args=[]).start()

    #
    # Test code to force IGMPv2 joins and leaves on an airplane. ;-)
    #
    threading.Thread(target=lisp_etr_join_leave_process, args=[]).start()
    return(True)
#enddef

#
# lisp_etr_shutdown
#
# Shut down this process.
#
def lisp_etr_shutdown():
    global lisp_register_timer
    global lisp_etr_info_timer

    #
    # Cancel periodic Map-Register and Info timer threads.
    #
    if (lisp_register_timer): lisp_register_timer.cancel()
    if (lisp_etr_info_timer): lisp_etr_info_timer.cancel()

    #
    # Close sockets.
    #
    lisp.lisp_close_socket(lisp_send_sockets[0], "")
    lisp.lisp_close_socket(lisp_send_sockets[1], "")
    lisp.lisp_close_socket(lisp_ipc_listen_socket, "lisp-etr")
    return
#enddef

#
# lisp_etr_discover_eid
#
# Process IPC message from the lisp-itr process. It will be in the form of:
#
#      "learn%<eid-string>%<interface-name>"    
#
def lisp_etr_discover_eid(ipc):
    ipc = ipc.split("%")
    eid_str = ipc[1]
    interface = ipc[2]
    if (interface == "None"): interface = None

    eid = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
    eid.store_address(eid_str)

    #
    # Do database-mapping lookup.
    #
    db = lisp.lisp_db_for_lookups.lookup_cache(eid, False)
    if (db == None or db.dynamic_eid_configured() == False):
        lisp.lprint("ITR/ETR dynamic-EID configuration out of sync for {}". \
            format(lisp.green(eid_str, False)))
        return
    #endif

    #
    # Do logic checks. That is do not remove an entry if it is not there and
    # don't try to add an entry if it is already cached.
    #
    dyn_eid = None
    if (eid_str in db.dynamic_eids): dyn_eid = db.dynamic_eids[eid_str]

    if (dyn_eid == None and interface == None):
        lisp.lprint("ITR/ETR state mismatch for {}".format( \
            lisp.green(eid_str, False)))
        return
    #endif

    #
    # Check if ITR is changing the interface to the same interface, meaning
    # it is confused. Otherwise, the IPC is an interface change. Don't register
    # in this case.
    #
    if (dyn_eid and interface):
        if (dyn_eid.interface == interface):
            lisp.lprint("ITR sent redundant IPC for {}".format( \
                lisp.green(eid_str, False)))
        else:
            lisp.lprint("Dynamic-EID {} interface change, {} -> {}".format( \
                lisp.green(eid_str, False), dyn_eid.interface, interface))
            dyn_eid.interface = interface
        #endif
        return
    #endif
   
    #
    # Add new entry and register it.
    #
    if (interface):
        dyn_eid = lisp.lisp_dynamic_eid()
        dyn_eid.dynamic_eid.copy_address(eid)
        dyn_eid.interface = interface
        dyn_eid.get_timeout(interface)
        db.dynamic_eids[eid_str] = dyn_eid

        reg = lisp.bold("Registering", False)
        eid_str = lisp.bold(eid_str, False)
        lisp.lprint("{} dynamic-EID {} on interface {}, timeout {}".format(reg,
            lisp.green(eid_str, False), interface, dyn_eid.timeout))

        lisp_build_map_register(lisp_send_sockets, None, eid, None, False)

        #
        # Add /32 to routing table.
        #
        if (lisp.lisp_is_macos() == False):
            eid_str = eid.print_prefix_no_iid()
            cmd = "ip route add {} dev {}".format(eid_str, interface)
            os.system(cmd)
        #endif
        return
    #endif

    #
    # Remove existig entry and deregister it.
    #
    if (eid_str in db.dynamic_eids):
        interface = db.dynamic_eids[eid_str].interface
        dereg = lisp.bold("Deregistering", False)
        lisp.lprint("{} dynamic-EID {}".format(dereg, 
            lisp.green(eid_str, False)))

        lisp_build_map_register(lisp_send_sockets, 0, eid, None, False)
                 
        db.dynamic_eids.pop(eid_str)

        #
        # Delete /32 from routing table.
        #
        if (lisp.lisp_is_macos() == False):
            eid_str = eid.print_prefix_no_iid()
            cmd = "ip route delete {} dev {}".format(eid_str, interface)
            os.system(cmd)
        #endif
    #endif
    return
#enddef

#
# lisp_etr_process_rtr_updown
#
# Process IPC message from lisp-itr. It is telling the lisp-etr process if
# RLOC-probing has determined if the RTR has gone up or down. And therefore
# if it should be registered to the mapping system.
#
def lisp_etr_process_rtr_updown(ipc):
    if (lisp.lisp_register_all_rtrs): return

    opcode, rtr_str, status = ipc.split("%")
    if (rtr_str not in lisp.lisp_rtr_list): return

    lisp.lprint("Process ITR IPC message, RTR {} has gone {}".format(
        lisp.red(rtr_str, False), lisp.bold(status, False)))
    
    rtr = lisp.lisp_rtr_list[rtr_str]
    if (status == "down"):
        lisp.lisp_rtr_list[rtr_str] = None
        return
    #endif

    rtr = lisp.lisp_address(lisp.LISP_AFI_IPV4, rtr_str, 32, 0)
    lisp.lisp_rtr_list[rtr_str] = rtr
    return
#enddef

#
# lisp_etr_process_nonce_ipc
#
# Process an nonce IPC message from the ITR. It wants to know when a nonce
# is echoed from a remote ITR.
#
def lisp_etr_process_nonce_ipc(ipc):
    x, opcode, rloc_str, nonce = ipc.split("%")
    nonce = int(nonce, 16)

    echo_nonce = lisp.lisp_get_echo_nonce(None, rloc_str)
    if (echo_nonce == None): echo_nonce = lisp.lisp_echo_nonce(rloc_str)

    if (opcode == "R"):
        echo_nonce.request_nonce_sent = nonce
        lisp.lprint("Waiting for echo-nonce 0x{} from {}".format( \
            lisp.lisp_hex_string(nonce), lisp.red(echo_nonce.rloc_str, False)))
    elif (opcode == "E"):
        echo_nonce.echo_nonce_sent = nonce
        lisp.lprint("Sent echo-nonce 0x{} to {}".format( \
            lisp.lisp_hex_string(nonce), lisp.red(echo_nonce.rloc_str, False)))
    #endif
    return
#enddef

#
# ETR commands procssed by this process.
#
lisp_etr_commands = {
    "lisp xtr-parameters" : [lispconfig.lisp_xtr_command, {
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

    "lisp map-server" : [lisp_etr_map_server_command, {
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

    "lisp database-mapping" : [lisp_etr_database_mapping_command, {
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

    "lisp group-mapping" : [lisp_group_mapping_command, {
        "group-name" : [False],
        "ms-name" : [True],
        "group-prefix" : [False],
        "instance-id" : [True, 0, 0xffffffff],  
        "rle-address" : [False],
        "sources" : [],
        "address" : [True] }],

    "show database-mapping" : [lisp_etr_show_command, { }],
    "show etr-keys" : [lisp_etr_show_keys_command, {}],
    "show etr-dynamic-eid" : [lispconfig.lisp_show_dynamic_eid_command, { }]
}

#------------------------------------------------------------------------------

#
# Main entry point for process.
#
if (lisp_etr_startup() == False):
    lisp.lprint("lisp_etr_startup() failed")
    lisp.lisp_print_banner("ETR abnormal exit")
    exit(1)
#endif

socket_list = [lisp_ephem_socket, lisp_ipc_listen_socket]

while (True):
    try: ready_list, w, x = select.select(socket_list, [], [])
    except: break

    #
    # Process Info-Reply messages received on ephemeral port.
    #
    if (lisp_ephem_socket in ready_list):
        opcode, source, port, packet = \
            lisp.lisp_receive(lisp_ephem_socket, False)
        if (source == ""): break

        if (port == lisp.LISP_DATA_PORT):
            lisp_etr_nat_data_plane(lisp_raw_socket, packet, source)
        else:
            if (lisp.lisp_is_rloc_probe_request(packet[0])):
                lisp.lprint("ETR ignoring RLOC-probe request, using pcap")
                continue
            #endif
            send_register = lisp.lisp_parse_packet(lisp_send_sockets, packet, 
                source, port)

            #
            # Info-Reply from map-server has new RTR-list, trigger a 
            # Map-Register and a Info-Request to the RTR.
            #
            if (send_register):
                lisp_etr_info_timer = threading.Timer(0,
                    lisp_etr_process_info_timer, [None])
                lisp_etr_info_timer.start()
                lisp_register_timer = threading.Timer(0,
                    lisp_process_register_timer, [lisp_send_sockets])
                lisp_register_timer.start()
            #endif
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
            if (packet.find("learn%") != -1):
                lisp_etr_discover_eid(packet)
            elif (packet.find("nonce%") != -1):
                lisp_etr_process_nonce_ipc(packet)
            elif (packet.find("clear%") != -1):
                lispconfig.lisp_clear_decap_stats(packet)
            elif (packet.find("rtr%") != -1):
                lisp_etr_process_rtr_updown(packet)
            elif (packet.find("stats%") != -1):
                packet = packet.split("%")[-1]
                lisp.lisp_process_data_plane_decap_stats(packet, None)
            else:
                lispconfig.lisp_process_command(lisp_ipc_listen_socket, 
                    opcode, packet, "lisp-etr", [lisp_etr_commands])
            #endif
        elif (opcode == "api"):
            lisp.lisp_process_api("lisp-etr", lisp_ipc_listen_socket, packet)
        else:
            if (lisp.lisp_is_rloc_probe_request(packet[0])):
                lisp.lprint("ETR ignoring RLOC-probe request, using pcap")
                continue
            #endif
            lisp.lisp_parse_packet(lisp_send_sockets, packet, source, port)
        #endif
    #endif
#endwhile

lisp_etr_shutdown()
lisp.lisp_print_banner("ETR normal exit")
exit(0)

#------------------------------------------------------------------------------
