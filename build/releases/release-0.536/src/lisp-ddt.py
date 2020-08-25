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
# lisp-ddt.py
#
# This file performs LISP DDT node functionality.
#
# -----------------------------------------------------------------------------

import lisp
import lispconfig

#------------------------------------------------------------------------------
#
# Global variable definitions.
#
lisp_send_sockets = [None, None, None]
lisp_ipc_listen_socket = None

#------------------------------------------------------------------------------

#
# lisp_ddt_auth_prefix_command
#
# Add an authoritative-prefix to the DDT cache.
#
def lisp_ddt_auth_prefix_command(kv_pair):
    ddt_entry = lisp.lisp_ddt_entry()

    for kw in kv_pair.keys():
        value = kv_pair[kw]

        if (kw == "instance-id"):
            v = value.split("-")
            if (v[0] == ""): continue

            no_eid = (kv_pair.has_key("eid-prefix") == False or
                kv_pair["eid-prefix"] == "")
            no_group = (kv_pair.has_key("group-prefix") == False or
                kv_pair["group-prefix"] == "")

            if (no_eid and no_group):
                ddt_entry.eid.store_iid_range(int(v[0]), int(v[1]))
            else:
                ddt_entry.eid.instance_id = int(v[0])
                ddt_entry.group.instance_id = int(v[0])
            #endif
        #endif
        if (kw == "eid-prefix"):
            ddt_entry.eid.store_prefix(value)
        #endif
        if (kw == "group-prefix"):
            ddt_entry.group.store_prefix(value)
        #endif
    #endfor

    #
    # Do not configure auth-prefix if delegation already exists. Always give
    # a configured delegation priority over a configured auth-prefix.
    #
    ddt = lisp.lisp_ddt_cache_lookup(ddt_entry.eid, ddt_entry.group, True)
    if (ddt != None and ddt.is_auth_prefix() == False): return

    #
    # Store in map-cache data structures.
    #
    ddt_entry.add_cache()
    return
#enddef

#
# lisp_ddt_delegation_command
#
# Create a ddt-cache entry for a delegation to a child referral.
#
def lisp_ddt_delegation_command(kv_pair):
    prefix_set = []
    for i in range(len(kv_pair["eid-prefix"])):
        ddt_entry = lisp.lisp_ddt_entry()
        prefix_set.append(ddt_entry)
    #endwhile

    eid_prefix_list = []
    if (kv_pair.has_key("eid-prefix")):
        for i in kv_pair["eid-prefix"]: eid_prefix_list.append(i)
    #endif

    child_set = []
    if (kv_pair.has_key("address")):
        for i in range(len(kv_pair["address"])):
            child = lisp.lisp_ddt_node()
            child_set.append(child)
        #endfor
    #endif

    for kw in kv_pair.keys():
        value = kv_pair[kw]
        if (kw == "instance-id"):
            for index in range(len(prefix_set)):
                ddt_entry = prefix_set[index]
                v = value[index].split("-")
                if (v[0] == ""): continue

                no_eid = (kv_pair["eid-prefix"][index] == "" and
                    kv_pair["group-prefix"][index] == "")

                if (no_eid):
                    ddt_entry.eid.store_iid_range(int(v[0]), int(v[1]))
                else:
                    ddt_entry.eid.instance_id = int(v[0])
                    ddt_entry.group.instance_id = int(v[0])
                #endif
            #endfor
        #endif
        if (kw == "eid-prefix"):
            for index in range(len(prefix_set)):
                ddt_entry = prefix_set[index]
                prefix_str = value[index]
                if (prefix_str == ""): continue
                ddt_entry.eid.store_prefix(prefix_str)
            #endfor
        #endif
        if (kw == "group-prefix"):
            for index in range(len(prefix_set)):
                ddt_entry = prefix_set[index]
                prefix_str = value[index]
                if (prefix_str == ""): continue
                ddt_entry.group.store_prefix(prefix_str)
            #endfor
        #endif

        if (kw == "priority"): 
            for index in range(len(child_set)):
                child = child_set[index]
                v = value[index]
                if (v == ""): v = "0"
                child.priority = int(v)
            #endfor
        #endif
        if (kw == "weight"): 
            for index in range(len(child_set)):
                child = child_set[index]
                v = value[index]
                if (v == ""): v = "0"
                child.weight = int(v)
            #endfor
        #endif
        if (kw == "address"):
            for index in range(len(child_set)):
                child = child_set[index]
                v = value[index]
                if (v != ""): child.delegate_address.store_address(v)
            #endfor
        #endif
        if (kw == "public_key"):
            for index in range(len(child_set)):
                child = child_set[index]
                v = value[index]
                child.public_key = v
            #endfor
        #endif
        if (kw == "node-type"):
            for index in range(len(child_set)):
                child = child_set[index]
                v = value[index]
                if (v == "map-server-child"): child.map_server_child = True
            #endfor
        #endif
    #endfor

    #
    # All the prefixes in the prefix_set are stored and in the lisp_ddt_
    # cache. Now we have to point all of them to each child set.
    #
    for ddt_entry in prefix_set:
        ddt_entry.add_cache()
        for child in child_set:
            ddt_entry.delegation_set.append(child)
        #endfor
    #endfor
    return
#enddef

#
# lisp_ddt_show_delegations_lookup
#
# Do a Map-Request lookup. If found, return information from ddt-entry. If not
# found, return negative prefix.
#
def lisp_ddt_show_delegations_lookup(eid_str):
    eid, eid_exact, group, group_exact = \
        lispconfig.lisp_get_lookup_string(eid_str)

    output = "<br>"

    #
    # Do lookup in DDT-cache.
    #
    ddt_entry = lisp.lisp_ddt_cache_lookup(eid, group, eid_exact)
    if (ddt_entry == None):
        banner = "DDT entry not found for non-authoritative EID" 
        output += "{} {}".format(lisp.lisp_print_sans(banner), 
            lisp.lisp_print_cour(eid_str))
        return(output + "<br>")
    #endif

    if (ddt_entry.is_auth_prefix()):
        if (group.is_null()):
            neg_prefix = lisp.lisp_ddt_compute_neg_prefix(eid, ddt_entry,
                lisp.lisp_ddt_cache)
            neg_prefix = lisp.lisp_print_cour(neg_prefix.print_prefix()),
        else:
            gneg_prefix = lisp.lisp_ddt_compute_neg_prefix(group, ddt_entry, 
                lisp.lisp_ddt_cache)
            neg_prefix = lisp.lisp_ddt_compute_neg_prefix(eid, ddt_entry,
                ddt_entry.source_cache)
            neg_prefix = lisp.lisp_print_cour( \
                "(" + neg_prefix.print_prefix() + ", ")
            gneg_prefix = lisp.lisp_print_cour( \
                gneg_prefix.print_prefix() + ")")
            neg_prefix += gneg_prefix
        #endif

        output += "{} {} {} {} {} {}".format( \
            lisp.lisp_print_sans("DDT authoritative-prefix entry"),
            lisp.lisp_print_cour(ddt_entry.print_eid_tuple()),
            lisp.lisp_print_sans("found for EID"),
            lisp.lisp_print_cour(eid_str),
            lisp.lisp_print_sans("<br><br>Computed negative-prefix"),
            neg_prefix)
    else:
        output += "{} {} {} {} {} {}".format( \
            lisp.lisp_print_sans("DDT entry"),
            lisp.lisp_print_cour(ddt_entry.print_eid_tuple()),
            lisp.lisp_print_sans("found for EID"),
            lisp.lisp_print_cour(eid_str),
            lisp.lisp_print_sans(", delegation-type"),
            lisp.lisp_print_cour(ddt_entry.print_referral_type()))
    #endif
    return(output + "<br>")
#enddef

#
# lisp_ddt_display_ddt_cache
#
# Display each entry in the lisp_ddt_cache.
#
def lisp_ddt_display_ddt_cache(ddt_entry, output):
    prefix = ddt_entry.print_eid_tuple()
    mrs = ddt_entry.map_referrals_sent

    if (ddt_entry.is_auth_prefix()):
        output += lispconfig.lisp_table_row(prefix, "--", "auth-prefix", "--",
            mrs)
        return([True, output])
    #endif

    for child in ddt_entry.delegation_set:
        addr = child.delegate_address
        pw = str(child.priority) + "/" + str(child.weight)
        output += lispconfig.lisp_table_row(prefix, 
            addr.print_address_no_iid(), child.print_node_type(), pw, mrs)
        if (prefix != ""): 
            prefix = ""
            mrs = ""
        #endif
    #endfor
    return([True, output])
#enddef

#
# lisp_ddt_walk_ddt_cache
#
# Walk the entries in the lisp_ddt_cache(). And then subsequently walk the
# entries in lisp_ddt_entry.source_cache().
#
def lisp_ddt_walk_ddt_cache(ddt_entry, output):
    
    #
    # There is only destination state in this map-cache entry.
    #
    if (ddt_entry.group.is_null()): 
        return(lisp_ddt_display_ddt_cache(ddt_entry, output))
    #endif

    if (ddt_entry.source_cache == None): return([True, output])

    #
    # There is (source, group) state so walk all sources for this group
    # entry.
    #
    output = ddt_entry.source_cache.walk_cache(lisp_ddt_display_ddt_cache, 
        output)
    return([True, output])
#enddef

#
# lisp_ddt_show_delegations_command
#
# Walk and display each entry in the lisp_ddt_cache.
#
def lisp_ddt_show_delegations_command(parameter):

    #
    # Do lookup if there is a parameter supplied.
    #
    if (parameter != ""): 
        return(lisp_ddt_show_delegations_lookup(parameter))
    #endif

    #
    # Top part of display has the form for doing a specific lookup.
    #
    banner = "Enter EID for DDT-Cache lookup:"
    input_rectangle = \
        lisp.lisp_eid_help_hover('<input type="text" name="eid" />')
    output = '''
        <form action="/lisp/show/delegations/lookup" method="post">
        <i><font face="Courier New" size="3">
        {} {}
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></i></form>
    '''.format(lisp.lisp_print_sans(banner), input_rectangle)

    #
    # Show delegation cache.
    #
    hover = "{} entries in delegation-cache".format( \
        lisp.lisp_ddt_cache.cache_size())
    title = lisp.lisp_span("LISP-DDT Configured Delegations:", hover)

    output += lispconfig.lisp_table_header(title, "EID-Prefix or (S,G)",
        "Delegation Address", "Delegation Type", "Priority/Weight",
        "Map-Referrals Sent")

    output = lisp.lisp_ddt_cache.walk_cache(lisp_ddt_walk_ddt_cache, output)
    output += lispconfig.lisp_table_footer()
    return(output)
#enddef

#
# lisp_ddt_startup
#
# Intialize this LISP DDT-Node process. This function returns a LISP network
# listen socket.
#
def lisp_ddt_startup():
    global lisp_send_sockets
    global lisp_ipc_listen_socket
    
    lisp.lisp_i_am("ddt")
    lisp.lisp_set_exception()
    lisp.lisp_print_banner("DDT-Node starting up")

    #
    # Get local address for source RLOC for encapsulation.
    #
    if (lisp.lisp_get_local_addresses() == False): return(False)

    #
    # Open send socket and IPC socket.
    #
    lisp_ipc_listen_socket = lisp.lisp_open_listen_socket("", "lisp-ddt")
    lisp_send_sockets[0] = lisp.lisp_open_send_socket("", lisp.LISP_AFI_IPV4)
    lisp_send_sockets[1] = lisp.lisp_open_send_socket("", lisp.LISP_AFI_IPV6)
    lisp_send_sockets[2] = lisp_ipc_listen_socket
    return
#enddef

#
# lisp_ddt_shutdown
#
# Shutdown process.
#
def lisp_ddt_shutdown():

    #
    # Close sockets.
    #
    lisp.lisp_close_socket(lisp_send_sockets[0], "")
    lisp.lisp_close_socket(lisp_send_sockets[1], "")
    lisp.lisp_close_socket(lisp_ipc_listen_socket, "lisp-ddt")
    return
#enddef

#
# DDT-node commands processed by this process.
#
lisp_ddt_commands = {
    "lisp ddt-authoritative-prefix" : [lisp_ddt_auth_prefix_command, {
        "instance-id" : [False, 0, 0xffffffff, True],  
        "eid-prefix" : [False],
        "group-prefix" : [False], }],

    "lisp delegation" : [lisp_ddt_delegation_command, {
        "delegate" : [], 
        "address" : [True], 
        "node-type" : [True, "ddt-child", "map-server-child"], 
        "priority" : [True, 0, 255], 
        "weight" : [True, 0, 100],
        "public-key" : [True],
        "prefix" : [], 
        "instance-id" : [True, 0, 0xffffffff, True],  
        "eid-prefix" : [True],  
        "group-prefix" : [True] }],

    "show delegations" : [lisp_ddt_show_delegations_command, { }],
}

#------------------------------------------------------------------------------

#
# Main entry point for process.
#
if (lisp_ddt_startup()):
    lisp.lprint("lisp_ddt_startup() failed")
    lisp.lisp_print_banner("DDT-Node abnormal exit")
    exit(1)
#endif

while (True):
    opcode, source, port, packet = \
        lisp.lisp_receive(lisp_ipc_listen_socket, True)
    if (source == ""): break

    if (opcode == "command"): 
        lispconfig.lisp_process_command(lisp_ipc_listen_socket, opcode, 
            packet, "lisp-ddt", [lisp_ddt_commands])
    else:
        lisp.lisp_parse_packet(lisp_send_sockets, packet, source, port)
    #endif
#endwhile

lisp_ddt_shutdown()
lisp.lisp_print_banner("DDT-Node normal exit")
exit(0)

#------------------------------------------------------------------------------

