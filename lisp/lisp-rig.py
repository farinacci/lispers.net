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
# lisp-rig.py
#
# This file supports LISP rig. See draft-ietf-lisp-rig for details.
#
# Command line usage is:
#
#     rig [<iid>]<dest-eid> to <ddt-node> [debug] [follow-all-referrals]
#
#------------------------------------------------------------------------------
from __future__ import print_function
from builtins import str
from builtins import range
import lisp
import sys
import time
import random
import select
from builtins import input

#------------------------------------------------------------------------------

#
# Global variables.
#
lisp_listen_socket = None
lisp_ipc_socket = None
lisp_sockets = [None, None, None]
lisp_ephem_port = lisp.lisp_get_ephemeral_port()

#
# lisp_close_all_sockets
#
# All allocated sockets are in the global lisp_sockets[] array.
#
def lisp_close_all_sockets():
    global lisp_sockets
    global lisp_ipc_socket

    for s in lisp_sockets:
        if (s == None): continue
        name = "/tmp/lisp-rig" if (s == lisp_ipc_socket) else ""
        lisp.lisp_close_socket(s, name)
    #endfor
    return
#enddef

#------------------------------------------------------------------------------

#
# Main entry point.
#
argc = len(sys.argv)
dest_eid = ""
ddt_node = ""

#
# If <dest-eid> is not on input line, prompt for everything. Otherwise, get
# commandl line input.
#
if (argc == 2): 
    dest_eid = sys.argv[1]
    argc = 1
#endif
if (argc <= 1):
    while (dest_eid == ""):
        dest_eid = input("Enter destination EID (or S->G): ")
    #endwhile
    while (ddt_node == ""):
        ddt_node = input("Enter ddt-node address: ")
    #endwhile
else:
    dest_eid = sys.argv[1]
    if ("to" in sys.argv):
        index = sys.argv.index("to")        
        if (index+1 < argc): ddt_node = sys.argv[index+1]
    #endif
    if (ddt_node == ""):
        print("Usage: rig [<iid>]<dest-eid> to <ddt-node> [debug]")
        exit(1)
    #endif        
#endif

#
# Check to see if S->G or S->D was specified.
#
sg = None
if (dest_eid.find("->") != -1):
    sg = dest_eid.split("->")
    dest_eid = sg[1]
    sg = sg[0]
#endif

#
# Check if instance-ID supplied.
#
iid = 0
if (dest_eid.find("[") != -1):
    iid = dest_eid.split("]")
    dest_eid = iid[1]
    iid = iid[0]
    iid = int(iid[1::])
#endif

#
# Do not do DNS lookup when distingusihed-name supplied.
#
dist_name = (dest_eid[0] == "'" or dest_eid[-1] == "'")
geos = ["-N", "-S", "-E", "-W"]
geo_string = False
for g in geos:
    if (g in dest_eid): geo_string = True
#endfor

if (dist_name == False and geo_string == False):
    deid = lisp.lisp_gethostbyname(dest_eid)
    if (deid == ""):
        print("Cannot resolve EID name '{}'".format(dest_eid))
        exit(1)
    #endtry
    dest_eid = deid
#endif

ddt_node_addr = lisp.lisp_gethostbyname(ddt_node)
if (ddt_node_addr == ""):
    print("Cannot resolve DDT-node name '{}'".format(ddt_node))
    exit(1)
#endif
ddt_node = ddt_node_addr

#
# Was more internal debugging requested by user?
#
lisp.lisp_debug_logging = True if "debug" in sys.argv else False
follow_all = ("follow" in sys.argv)

lisp.lisp_i_am("rig")

#
# Open IPC socket because if the lisp-core is running on this machine that
# rig is running, it will get Map-Referral messages that it will IPC to 
# this named socket.
#
lisp_sockets[0] = lisp.lisp_open_send_socket("", lisp.LISP_AFI_IPV4)
lisp_sockets[1] = lisp.lisp_open_send_socket("", lisp.LISP_AFI_IPV6)
lisp_ipc_socket = lisp.lisp_open_listen_socket("", "/tmp/lisp-rig")
lisp_sockets[2] = lisp_ipc_socket

#
# If lisp-core is not running on this machine, also open up a listen socket
# for port 4342.
#
try:
    address = "0.0.0.0" if lisp.lisp_is_raspbian() else "0::0"
    lisp_listen_socket = lisp.lisp_open_listen_socket("0::0", str(4342))
    lisp_sockets.append(lisp_listen_socket)
except:
    pass
#endtry

#
# Build and send ECM based Map-Request.
#
map_request = lisp.lisp_map_request()
map_request.record_count = 1
#map_request.nonce = 0xdfdf0e1d10c20000 + random.randint(0, 65535)
map_request.nonce = 0
if (dist_name):
    afi = lisp.LISP_AFI_NAME
    ml = len(dest_eid) * 8
elif (dest_eid.find(":") != -1): 
    afi = lisp.LISP_AFI_IPV6
    ml = 128
elif (dest_eid.find(".") != -1):
    afi = lisp.LISP_AFI_IPV4
    ml = 32
elif (geo_string):
    afi = lisp.LISP_AFI_GEO_COORD
    ml = len(dest_eid) * 8
elif (dest_eid.find("-") != -1):
    afi = lisp.LISP_AFI_MAC
    ml = 48
else:
    lisp_close_all_sockets()
    print("Invalid EID address {}".format(dest_eid))
    exit(1)
#endif

if (lisp.lisp_valid_address_format("address", dest_eid) == False):
    print("Invalid address syntax '{}'".format(dest_eid))
    exit(1)
#endif

#
# Store just a destination address unless S->G was specified.
#
map_request.target_eid = lisp.lisp_address(afi, "", ml, iid)
if (sg):
    map_request.target_eid.store_address(sg)
    map_request.target_group.store_address(dest_eid)
    target_eid_str = map_request.target_eid.print_sg(map_request.target_group)
else:
    map_request.target_eid.store_address(dest_eid)
    target_eid_str = map_request.target_eid.print_address()
#endif

#
# Fill in source-eid field.
#
map_request.source_eid.afi = lisp.LISP_AFI_NONE

if (lisp.lisp_get_local_addresses() == False): 
    print("Cannot obtain a local address")
    exit(1)
#endif

#
# Fill in ITR-RLOCs field but ask for no Map-Reply.
#
local_addr = lisp.lisp_myrlocs[0].print_address_no_iid()
itr_rloc = lisp.lisp_address(lisp.LISP_AFI_IPV4, local_addr, 32, 0)
map_request.itr_rlocs.append(itr_rloc)
map_request.dont_reply_bit = True

#
# Encode the Map-Request packet and then enter transmission loop.
#
packet = map_request.encode(None, 0)
map_request.print_map_request()

#
# Build header to parse Map-Referral.
#
header = lisp.lisp_control_header()
map_referral = lisp.lisp_map_referral()
if (ddt_node.find(":") != -1): 
    afi = lisp.LISP_AFI_IPV6
    ml = 128
elif (ddt_node.find(".") != -1):
    afi = lisp.LISP_AFI_IPV4
    ml = 32
else:
    lisp_close_all_sockets()
    print("Invalid DDT-node address {}".format(ddt_node))
    exit(1)
#endif
ddt_node = lisp.lisp_address(afi, ddt_node, ml, 0)

#
# Set inner source and destination EIDs for ECM debug output.
#
if (sg):
    inner_dest = map_request.target_group
    inner_source = map_request.target_eid
else:
    inner_dest = map_request.target_eid
    inner_source = lisp.lisp_myrlocs[1] if inner_dest.is_ipv6() else itr_rloc
#endif

copy = packet
no_reply = True
retry_count = 4
depth = 8
to_ms = False

#
# Keep a list of DDT-nodes we want to send ECMs to. False means the ECM has
# not been sent yet. True means it has been sent and we are waiting for a
# reply. When a reply comes, the address string is removed from the dictionary
# array.
#
pending = { ddt_node.print_address_no_iid() : [None, ddt_node] }

while (True):
    retry_count -= 1
    if (retry_count == 0): break

    if (depth == 0):
        print("Reached depth limit for LISP-DDT traversal")
        break
    #endif

    for key in list(pending.keys()):
        if (pending[key][0] != None): continue
        ddt_node = pending[key][1]

        print("Send rig map-request to {} for EID {} ...".format( \
            ddt_node.print_address_no_iid(), target_eid_str))

        #
        # Send ECM based Map-Request to Map-Resolver..
        #
        packet = copy
        lisp.lisp_send_ecm(lisp_sockets, packet, inner_source, 
            lisp_ephem_port, inner_dest, ddt_node, to_ms=to_ms, ddt=True)
        map_request_ts = time.time()
        pending[key][0] = map_request_ts
    #endfor

    #
    # Make sure any elemecnts of the lisp_sockets array do not have None
    # values.
    #
    sockets = []
    for s in lisp_sockets:
        if (s == None): continue
        sockets.append(s)
    #endif

    #
    # Wait 2 seconds for Map-Referral and if it does not come in, retry Map-
    # Request up to count times.
    #
    ready_list, w, x = select.select(sockets, [], [], 2)

    if (lisp_sockets[0] in ready_list):
        opcode, source, port, packet = \
            lisp.lisp_receive(lisp_sockets[0], False)
    elif (lisp_sockets[1] in ready_list):
        opcode, source, port, packet = \
            lisp.lisp_receive(lisp_sockets[1], False)
    elif (lisp_ipc_socket in ready_list):
        opcode, source, port, packet = \
            lisp.lisp_receive(lisp_ipc_socket, True)
    elif (lisp_listen_socket in ready_list):
        opcode, source, port, packet = \
            lisp.lisp_receive(lisp_listen_socket, False)
    else:
        continue
    #endif

    #
    # Either process Map-Referral or retransmit if we have timed out.
    #
    if (source == ""): continue

    #
    # Did not get a packet, hmm.
    #
    if (opcode != "packet"): 
        print("Internal fatal error")
        continue
    #endif

    #
    # Did not get a Map-Referral, something is messed up in the network.
    #
    if (header.decode(packet) == None):
        print("Could not decode header")
        continue
    #endif

    #
    # If ECM received, it could have been looped back from kernel when we
    # are listening to port 4342. Sleep for 2 seconds, don't complain about
    # illegal message.
    #
    if (header.type != lisp.LISP_MAP_REFERRAL):
        if (lisp_listen_socket != None and header.type == lisp.LISP_ECM):
            time.sleep(2)
        else:
            print("Map-Referral not returned, packet type {} returned". \
                format(header.type))
        #endif
        continue
    #endif

    #
    # Not in pending queue.
    #
    if (source not in pending):
        print("Received Map-Referral from {} but no Map-Request was pending". \
                format(source))
        continue
    #endif

    map_request_ts = pending[source][0]
    pending.pop(source)

    #
    # Process Map-Referral.
    #
    rtt = round(time.time() - map_request_ts, 3)
    print("Received map-referral from {} with rtt {} secs:".format(source, rtt))
    packet = map_referral.decode(packet)
    if (packet == None):
        print("Could not decode Map-Referral packet")
        continue
    #endif
    no_reply = False
    map_referral.print_map_referral()

    for i in range(map_referral.record_count):
        eid_record = lisp.lisp_eid_record()
        packet = eid_record.decode(packet)
        if (packet == None): break

        action = lisp.lisp_map_referral_action_string[eid_record.action]
        action = lisp.bold(action, False)

        print("EID-prefix: {}, ttl: {}, referral-type: {}". \
            format(eid_record.print_prefix(), eid_record.print_ttl(), action))

        eid_record.print_record("", True)

        ref_select = 0
        if (eid_record.rloc_count != 0):
            print("  Referrals:", end=" ")
            if (lisp.lisp_debug_logging): print("\n")
            ref_select = random.randint(0, 255) % eid_record.rloc_count
        #endif

        to_ms = eid_record.action in (lisp.LISP_DDT_ACTION_MS_REFERRAL,
            lisp.LISP_DDT_ACTION_MS_ACK)

        neg_or_done = eid_record.action in (lisp.LISP_DDT_ACTION_MS_NOT_REG,
            lisp.LISP_DDT_ACTION_DELEGATION_HOLE, 
            lisp.LISP_DDT_ACTION_NOT_AUTH, lisp.LISP_DDT_ACTION_MS_ACK)

        #
        # Walk referral list.
        #
        for j in range(eid_record.rloc_count):
            rloc_record = lisp.lisp_rloc_record()
            packet = rloc_record.decode(packet, map_referral.nonce)
            if (packet == None): break
            rloc_record.print_record("  ")

            if (lisp.lisp_debug_logging == False):
                string = rloc_record.rloc.print_address_no_iid()
                if (j != eid_record.rloc_count-1): string += ","
                print(string, end=" ")
            #endif

            if (follow_all):
                if (neg_or_done): continue
            else:
                if (ref_select != j): continue
            #endif

            #
            # Cache referral to send Map-Request to at top of loop.
            #
            pending[rloc_record.rloc.print_address_no_iid()] = \
                [None, rloc_record.rloc]
        #endfor

        if (eid_record.rloc_count != 0): print("\n")
    #endfor

    #
    # If negative Map-Referrals or ms-ack, stop.
    #
    if (follow_all == False and neg_or_done):break

    #
    # Choose one of the referrals and send a DDT map-request to it. Use a
    # total depth of 16 before stopping.
    #
    depth -= 1
    retry_count = 4

#endwhile

#
# Finish up with response to user.
#
if (no_reply): print("*** No map-referral received ***")

#
# Close down resources and exit.
#
lisp_close_all_sockets()
exit(1) if (no_reply) else exit(0)

#------------------------------------------------------------------------------
