#
# lisp-mr.py
#
# This file performs LISP Map-Resolver functionality.
#

import lisp
import lispconfig
import threading
import select

#------------------------------------------------------------------------------

#
# Global variable definitions.
#
lisp_send_sockets = [None, None, None]
lisp_ipc_listen_socket = None
lisp_ephem_listen_socket = None
lisp_send_internal_socket = None
lisp_ddt_roots = {}
lisp_referral_timer = None
lisp_ephem_port = lisp.lisp_get_ephemeral_port()

#------------------------------------------------------------------------------

#
# lisp_clear_referral_cache
#
# Blow away cache and add back static and ddt-root entries by reading
# configuration file.
#
def lisp_clear_referral_cache():
    lisp.lisp_referral_cache = lisp.lisp_cache()
#enddef

#
# lisp_ddt_root_command
#
# Add DDT root entries.
#
def lisp_ddt_root_command(kv_pair):
    global lisp_ddt_roots

    #
    # Create instance to store in ddt-roots list.
    #
    ddt_root = lisp.lisp_ddt_root()

    #
    # Create instance to store in the referral cache.
    #
    referral = lisp.lisp_referral()

    #
    # Get command input.
    #
    for kw in kv_pair.keys():
        if (kw == "address"):
            addr_str = kv_pair[kw]
            ddt_root.root_address.store_address(addr_str)
        #endif
        if (kw == "public-key"):
            value = kv_pair[kw]
            ddt_root.public_key = value
        #endif
        if (kw == "priority"): 
            value = kv_pair[kw]
            ddt_root.priority = value
        #endif
        if (kw == "weight"):
            value = kv_pair[kw]
            ddt_root.weight = value
        #endif
    #endfor

    #
    # Add new instance to ddt-roots list.
    #
    lisp_ddt_roots[addr_str] = ddt_root

    #
    # Now take all roots configured so far and make the referral nodes for
    # EID-prefix [*]. Store new referral instance in the referral-cache.
    # Prepend (and not sort) since we want the [*] entry to be first.
    #
    for ddt_root in lisp_ddt_roots.values():
        referral_node = lisp.lisp_referral_node()
        referral_node.referral_address = ddt_root.root_address
        referral_node.priority = ddt_root.priority
        referral_node.weight = ddt_root.weight
        addr_str = referral_node.referral_address.print_address()
        referral.referral_set[addr_str] = referral_node
    #endfor
    referral.eid.afi = lisp.LISP_AFI_ULTIMATE_ROOT

    #
    # Add to referral-cache.
    #
    referral.add_cache()
    return
#enddef

#
# lisp_referral_cache_command
#
# Add static referral cache entries.
#
def lisp_referral_cache_command(kv_pair):

    prefix_set = []
    for i in range(len(kv_pair["eid-prefix"])):
        referral = lisp.lisp_referral()
        prefix_set.append(referral)
    #endfor

    referral_set = []
    if (kv_pair.has_key("address")):
        for i in range(len(kv_pair["address"])):
            ref_node = lisp.lisp_referral_node()
            referral_set.append(ref_node)
        #endfor
    #endif

    for kw in kv_pair.keys():
        value = kv_pair[kw]
        if (kw == "instance-id"):
            for i in range(len(prefix_set)):
                referral = prefix_set[i]
                v = value[i]
                if (v == ""): v = "0"
                referral.eid.instance_id = int(v)
                referral.group.instance_id = int(v)
            #endfor
        #endif
        if (kw == "eid-prefix"):
            for i in range(len(prefix_set)):
                referral = prefix_set[i]
                v = value[i]
                if (v != ""): referral.eid.store_prefix(v)
            #endfor
        #endif
        if (kw == "group-prefix"):
            for i in range(len(prefix_set)):
                referral = prefix_set[i]
                v = value[i]
                if (v != ""): referral.group.store_prefix(v)
            #endfor
        #endif

        if (kw == "priority"): 
            for i in range(len(referral_set)):
                ref_node = referral_set[i]
                v = value[i]
                if (v == ""): v = "0"
                ref_node.priority = int(v)
            #endfor
        #endif
        if (kw == "weight"):
            for i in range(len(referral_set)):
                ref_node = referral_set[i]
                v = value[i]
                if (v == ""): v = "0"
                ref_node.weight = int(v)
            #endfor
        #endif
        if (kw == "address"):
            for i in range(len(referral_set)):
                ref_node = referral_set[i]
                v = value[i]
                if (v != ""): ref_node.referral_address.store_address(v)
            #endfor
        #endif
    #endfor

    #
    # Store in map-cache data structures.
    #
    for referral in prefix_set:
        for ref_node in referral_set:
            addr_str = ref_node.referral_address.print_address()
            referral.referral_set[addr_str] = ref_node
        #endfor
        referral.add_cache()
    #endfor
#enddef

#
# lisp_display_referral_cache
#
# Display the referral cache.
#
def lisp_display_referral_cache(ref, output):

    uts = lisp.lisp_print_elapsed(ref.uptime)
    ets = lisp.lisp_print_future(ref.expires)
    prefix = ref.print_eid_tuple()

    ref_source = "configured" if (ref.referral_source.not_set()) else \
        ref.referral_source.print_address_no_iid()

    time_str = "--"
    if (ref.eid.is_ultimate_root()): 
        ref_type = "root"
    elif (ref_source == "configured"):
        ref_type = "any"
    else:
        ref_type = ref.print_referral_type()
        if (ref.is_referral_negative()): 
            ref_type = lisp.red(ref_type, True)
        #endif
        time_str = "{}<br>{}".format(ets, str(ref.referral_ttl/60))
    #endif

    if (len(ref.referral_set) == 0):
        output += lispconfig.lisp_table_row(prefix, uts, time_str, 
            ref_type, ref_source, "--", "--", "--")
    #endif

    for ref_node in ref.referral_set.values(): 
        addr = ref_node.referral_address.print_address_no_iid()
        addr += "<br>up" if ref_node.updown else "<br>down"

        output += lispconfig.lisp_table_row(prefix, uts, time_str, 
            ref_type, ref_source, addr, str(ref_node.priority) + "<br>" +
            str(ref_node.weight), str(ref_node.map_requests_sent) + "<br>" +
            str(ref_node.no_responses))

        if (prefix != ""): 
            prefix = ""
            uts = ""
            time_str = ""
            ref_source = ""
            ref_type = ""
        #endif
    #endfor

    return([True, output])
#enddef

#
# lisp_walk_referral_cache
#
# Walk the entries in the lisp_referral_cache(). And then subsequently walk the
# entries in lisp_referral.source_cache().
#
def lisp_walk_referral_cache(ref, output):
    
    #
    # There is only destination state in this map-cache entry.
    #
    if (ref.group.is_null()): return(lisp_display_referral_cache(ref, output))

    if (ref.source_cache == None): return([True, output])

    #
    # There is (source, group) state so walk all sources for this group
    # entry.
    #
    output = ref.source_cache.walk_cache(lisp_display_referral_cache, output)
    return([True, output])
#enddef

#
# lisp_mr_show_referral_cache_lookup
#
# Do a Map-Request lookup.
#
def lisp_mr_show_referral_cache_lookup(eid_str):
    eid, eid_exact, group, group_exact = \
        lispconfig.lisp_get_lookup_string(eid_str)

    output = "<br>"

    entry = lisp.lisp_referral_cache_lookup(eid, group, eid_exact)
    if (entry == None):
        output += "{} {}".format(lisp.lisp_print_sans("Lookup not found for"),
            lisp.lisp_print_cour(eid_str))
    else:
        ts = lisp.lisp_print_elapsed(entry.uptime)
        output += "{}{}{}{}{}{}".format( \
            lisp.lisp_print_sans("{} match lookup for ".format("Exact" if \
                eid_exact else "Longest")),
            lisp.lisp_print_cour(eid_str),
            lisp.lisp_print_sans(" found "),
            lisp.lisp_print_cour(entry.print_eid_tuple()),
            lisp.lisp_print_sans(", referral-type {}".format( \
                lisp.lisp_print_cour(entry.print_referral_type()))),
            lisp.lisp_print_sans(" with uptime {}".format( \
                lisp.lisp_print_cour(ts))))
    #endif
    output += "<br>"

    return(output)
#enddef

#
# lisp_mr_show_referral_cache_command
#
# Display the referral cache.
#
def lisp_mr_show_referral_cache_command(parameter):

    #
    # Do lookup if there is a parameter supplied.
    #
    if (parameter != ""): 
        return(lisp_mr_show_referral_cache_lookup(parameter))
    #endif

    #
    # Top part of display has the form for doing a specific lookup.
    #
    banner = "Enter EID for Referral-Cache lookup:"
    input_rectangle = \
        lisp.lisp_eid_help_hover('<input type="text" name="eid" />')
    output = '''
        <form action="/lisp/show/referral/lookup" method="post">
        <i><font face="Courier New" size="3">
        {} {}
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></i></form>
    '''.format(lisp.lisp_print_sans(banner), input_rectangle)

    #
    # Display the DDT Map-Request queue contents if anything is in it.
    #
    queue_size = len(lisp.lisp_ddt_map_requestQ)
    if (queue_size != 0):
        hover = "{} entries in map-request queue".format(queue_size)
        title = lisp.lisp_span("LISP-MR Map-Request Queue:", hover)

        output += lispconfig.lisp_table_header(title, 
            "EID-Prefix or (S,G)", "Nonce", "Uptime", "Map-Request Source", 
            "Retry Count", "Tried DDT-Root", "Last Request Sent To",
            "Last Map-Referral EID-Prefix")
        
        for key in lisp.lisp_ddt_map_requestQ:
            mr = lisp.lisp_ddt_map_requestQ[key]
            ut = lisp.lisp_print_elapsed(mr.uptime)
            last_sent = mr.last_request_sent_to
            last_sent = "--" if (last_sent == None) else \
                last_sent.print_address_no_iid()
            itr = mr.itr
            itr = "--" if (itr == None) else (itr.print_address_no_iid() + \
                "<br>({}ITR)".format("P" if mr.from_pitr else ""))
            
            last_eid = mr.last_cached_prefix[0]
            last_group = mr.last_cached_prefix[1]
            last_prefix = "--" if (last_eid == None) else \
                 lisp.lisp_print_eid_tuple(last_eid, last_group)

            output += lispconfig.lisp_table_row(mr.print_eid_tuple(), 
                "0x" + lisp.lisp_hex_string(mr.nonce), ut, itr, 
                mr.retry_count, "yes" if mr.tried_root else "no", last_sent, 
                last_prefix)

        #endfor
        output += lispconfig.lisp_table_footer()
    #endif

    hover = "{} entries in referral-cache".format( \
        lisp.lisp_referral_cache.cache_size())
    title = lisp.lisp_span("LISP-MR Referral-Cache:", hover)

    output += lispconfig.lisp_table_header(title, 
        "EID-Prefix or (S,G)", "Uptime", "Expires<br>TTL", 
        "Referral Type", "Map-Referral Source", 
        "Referral Address<br>Node Status", 
        "Priority<br>Weight", "Map-Requests Sent<br>No Responses")
    
    output = lisp.lisp_referral_cache.walk_cache(lisp_walk_referral_cache, 
        output)

    output += lispconfig.lisp_table_footer()
    return(output)
#enddef

#
# lisp_timeout_referral_entry
#
# Check if a specific referral entry needs to be removed due timer expiry.
#
def lisp_timeout_referral_entry(referral, delete_list):

    if (referral.expires == 0): return([True, delete_list])

    now = lisp.lisp_get_timestamp()
    if (referral.uptime + referral.referral_ttl > now): 
        return([True, delete_list])
    #endif

    #
    # Timed out.
    #
    elapsed = lisp.lisp_print_elapsed(referral.uptime)
    prefix_str = referral.print_eid_tuple()
    lisp.lprint("Referral for EID-prefix {} has timed out, had uptime of {}". \
        format(lisp.green(prefix_str, False), elapsed))

    #
    # Add to delete-list to remove after this loop.
    #
    delete_list.append(referral)
    return([True, delete_list])
#endef

#
# lisp_timeout_referral_cache_walk
#
# Walk the entries in the lisp_referral_cache(). And then subsequently walk the
# entries in lisp_referral.source_cache().
#
def lisp_timeout_referral_cache_walk(ref, delete_list):

    #
    # There is only destination state in this map-cache entry.
    #
    if (ref.group.is_null()): 
        return(lisp_timeout_referral_entry(ref, delete_list))
    #endif

    if (ref.source_cache == None): return([True, delete_list])

    #
    # There is (source, group) state so walk all sources for this group
    # entry.
    #
    delete_list = ref.source_cache.walk_cache(lisp_timeout_referral_entry, 
        delete_list)
    return([True, delete_list])
#enddef

#
# lisp_timeout_referral_cache
#
# Time out entries that have not registered within their advertised register-
# ttl.
#
def lisp_timeout_referral_cache():
    lisp.lisp_set_exception()
    delete_list = []

    c = lisp.lisp_referral_cache
    delete_list = c.walk_cache(lisp_timeout_referral_cache_walk, delete_list)

    #
    # Now remove from lisp_referral_cache all the timed out entries on the
    # delete_list[].
    #
    for referral in delete_list: referral.delete_cache()

    #
    # Restart periodic timer.
    #
    lisp_referral_timer = threading.Timer(
        lisp.LISP_REFERRAL_TIMEOUT_CHECK_INTERVAL, lisp_timeout_referral_cache,
            [])
    lisp_referral_timer.start()
#enddef

#
# lisp_mr_startup
#
# Intialize this LISP MR process. This function returns a LISP network
# listen socket.
#
def lisp_mr_startup():
    global lisp_send_sockets
    global lisp_ipc_listen_socket
    global lisp_send_internal_socket
    global lisp_ephem_listen_socket
    
    lisp.lisp_i_am("mr")
    lisp.lisp_set_exception()
    lisp.lisp_print_banner("Map-Resolver starting up")

    #
    # Get local address for source RLOC for encapsulation.
    #
    if (lisp.lisp_get_local_addresses() == False): return(False)

    #
    # Open send socket.
    #
    lisp_send_internal_socket = lisp.lisp_open_send_socket("lisp-mrms", "")
    lisp_ipc_listen_socket = lisp.lisp_open_listen_socket("", "lisp-mr")
    address = "0.0.0.0" if lisp.lisp_is_raspbian() else "0::0"
    lisp_ephem_listen_socket = lisp.lisp_open_listen_socket(address,
        str(lisp_ephem_port))
    lisp_send_sockets[0] = lisp_ephem_listen_socket
    lisp_send_sockets[1] = lisp_ephem_listen_socket
    lisp_send_sockets[2] = lisp_ipc_listen_socket

    #
    # Start site-cache timeout timer.
    #
    lisp_referral_timer = threading.Timer(
        lisp.LISP_REFERRAL_TIMEOUT_CHECK_INTERVAL, lisp_timeout_referral_cache,
            [])
    lisp_referral_timer.start()
    return(True)
#enddef

#
# lisp_mr_shutdown
#
# Shutdown process.
#
def lisp_mr_shutdown():

    #
    # Close sockets.
    #
    lisp.lisp_close_socket(lisp_ephem_listen_socket, "")
    lisp.lisp_close_socket(lisp_send_internal_socket, "lisp-mrms")
    lisp.lisp_close_socket(lisp_ipc_listen_socket, "lisp-mr")
#enddef

#
# lisp_mr_parse_packet
#
# Map-Resolver packet parsing. Decide if packet should be processed locally.
#
def lisp_mr_parse_packet(packet, source_str, sport):

    header = lisp.lisp_control_header()
    if (header.decode(packet) == None):
        lisp.lprint("Could not decode control header")
        return
    #endif
        
    #
    # Store source in internal lisp_address() format.
    #
    source = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
    source.store_address(source_str)

    #
    # If this is an ECM and since we are a Map-Resolver, check if the 
    # Map-Server is colocated on the same machine. If so, have it process 
    # the ECM when there is no DDT configured for the Map-Resolver.
    #
    if (header.type == lisp.LISP_ECM):
        ddt_roots_exist = (len(lisp_ddt_roots) > 0)
        if (lisp.lisp_is_running("lisp-ms") and ddt_roots_exist == False):
            packet = lisp.lisp_packet_ipc(packet, source_str, sport)
            lisp.lisp_ipc(packet, lisp_send_internal_socket, "lisp-ms")
            return
        #endif

        #
        # Process the Map-Request as a DDT-based Map-Resolver.
        # 
        if (ddt_roots_exist):
            lisp.lisp_process_ecm(lisp_send_sockets, packet, source, sport)
            return
        #endif
        lisp.lprint("Map-Resolver dropping ECM, DDT or Map-Server not " + \
            "configured")
        return
    #endif

    #
    # Process Map-Referral.
    #
    if (header.type == lisp.LISP_MAP_REFERRAL):
        lisp.lisp_process_map_referral(lisp_send_sockets, packet, source)
        return
    #endif            

    #
    # This process processes only ECMs and Map-Referral messages.
    #
    lisp.lprint("Map-Resolver received an unexpected LISP packet, type: {}". \
        format(header.type))
#enddef

#------------------------------------------------------------------------------

#
# Map-Resolver commands procssed by this process.
#
lisp_mr_commands = {
    "lisp ddt-root" : [lisp_ddt_root_command, {
        "address" : [False],
        "public-key" : [False],
        "priority" : [False, 0, 255], 
        "weight" : [False, 0, 100] }],

    "lisp referral-cache" : [lisp_referral_cache_command, {
        "prefix" : [], 
        "instance-id" : [True, 0, 0xffffffff],  
        "eid-prefix" : [True], 
        "group-prefix" : [True], 
        "referral" : [], 
        "address" : [True], 
        "priority" : [True, 0, 255], 
        "weight" : [True, 0, 100] }],

    "show referral-cache" : [lisp_mr_show_referral_cache_command, { }],
}

#------------------------------------------------------------------------------

#
# Main entry point for process.
#
if (lisp_mr_startup() == False):
    lisp.lprint("lisp_mr_startup() failed")
    lisp.lisp_print_banner("Map-Resolver abnormal exit")
    exit(1)
#endif

socket_list = [lisp_ephem_listen_socket, lisp_ipc_listen_socket]
ephem_sockets = [lisp_ephem_listen_socket] * 3

while (True):
    try: ready_list, w, x = select.select(socket_list, [], [])
    except: break

    if (lisp_ephem_listen_socket in ready_list):
        opcode, source, port, packet = lisp.lisp_receive(ephem_sockets[0], 
            False)
        if (source == ""): break
        lisp.lisp_parse_packet(ephem_sockets, packet, source, port)
        continue
    #endif

    opcode, source, port, packet = \
        lisp.lisp_receive(lisp_ipc_listen_socket, True)
    if (source == ""): break

    if (opcode == "command"): 
        if (packet == "clear"): 
            lisp_clear_referral_cache()
            continue
        #endif
        lispconfig.lisp_process_command(lisp_ipc_listen_socket, opcode, 
            packet, "lisp-mr", [lisp_mr_commands])
    else:
        lisp_mr_parse_packet(packet, source, port)
    #endif
#endwhile

lisp_mr_shutdown()
lisp.lisp_print_banner("Map-Resolver normal exit")
exit(0)

#------------------------------------------------------------------------------

