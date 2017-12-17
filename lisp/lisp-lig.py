#
# lisp-lig.py
#
# This file supports LISP lig. See RFC 6835 for details.
#
# Command line usage is:
#
#     lig [<iid>]<dest-eid> to <mr-rloc> [source <source-eid>] [count <1-5>]
#                                        [debug] [no-info] [pubsub]
#
# Parameters are position independent other than <dest-eid>, and when it
# is not supplied, interactive input is requested.
#
#------------------------------------------------------------------------------

import lisp
import sys
import time
import random
import select

#------------------------------------------------------------------------------

#
# Global variables.
#
lisp_listen_socket = None
lisp_ephem_listen_socket = None
lisp_sockets = [None, None, None]
lisp_ephem_port = lisp.lisp_get_ephemeral_port()

#------------------------------------------------------------------------------

#
# read_sockets
#
# Receive on any of the 3 sockets we have open.
#
def read_sockets(socket_list, lisp_ephem_listen_socket, lisp_listen_socket,
    lisp_ipc_socket):

    ready_list, w, x = select.select(socket_list, [], [], 2)

    if (lisp_ephem_listen_socket in ready_list):
        opcode, source, port, packet = lisp.lisp_receive( \
            lisp_ephem_listen_socket, False)
    elif (lisp_listen_socket in ready_list):
        opcode, source, port, packet = lisp.lisp_receive(lisp_listen_socket, 
            False)
    elif (lisp_ipc_socket in ready_list):
        opcode, source, port, packet = lisp.lisp_receive(lisp_ipc_socket, 
            True)
    else:
        return("", "", 0, None)
    #endif
    return(opcode, source, port, packet)
#enddef

#
# process_eid_records
#
# Proecss the EID records from either a Map-Reply or Map-Notify message.
#
def process_eid_records(record_count, nonce, packet):

    for i in range(record_count):
        eid_record = lisp.lisp_eid_record()
        packet = eid_record.decode(packet)
        if (packet == None): break
        print "EID-prefix: {}, ttl: {}, rloc-set:".format( \
            eid_record.print_prefix(), eid_record.print_ttl())

        if (eid_record.rloc_count == 0):
            action = lisp.lisp_map_reply_action_string[eid_record.action]
            action = lisp.bold(action, False)
            print "  Empty, map-reply action: {}".format(action)
        #endif
        
        eid_record.print_record("", False)
        for j in range(eid_record.rloc_count):
            rloc_record = lisp.lisp_rloc_record()
            packet = rloc_record.decode(packet, nonce)
            if (packet == None): break
            p = rloc_record.priority
            mp = rloc_record.mpriority
            print "  RLOC: {}, up/uw/mp/mw: {}/{}/{}/{}, flags: {}{}{}". \
                format(rloc_record.rloc.print_address_no_iid(), p, rloc_record.
                weight, mp, rloc_record.mweight, rloc_record.print_flags(), 
                "" if rloc_record.rloc_name == None else \
                ", " + rloc_record.print_rloc_name(),
                ", RTR" if p == 254 and mp == 255 else "")

            if (rloc_record.geo):
                print "        geo: {}".format(rloc_record.geo.print_geo())
            #endif
            if (rloc_record.elp):
                elp = rloc_record.elp.print_elp(False)
                print "        elp: {}".format(elp)
            #endif
            if (rloc_record.rle):
                rle = rloc_record.rle.print_rle()
                print "        rle: {}".format(rle)
            #endif
            if (rloc_record.json):
                json = rloc_record.json.print_json(False)
                print "        json: {}".format(json)
            #endif
            rloc_record.print_record("  ")
        #endfor
        print ""
    #endfor
#enddef

#------------------------------------------------------------------------------

#
# Main entry point.
#
argc = len(sys.argv)
dest_eid = ""
mr = ""
source_eid = ""
count = ""
pubsub = ("pubsub" in sys.argv)

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
        dest_eid = raw_input("Enter destination EID (or S->G): ")
    #endwhile
    while (mr == ""):
        mr = raw_input("Enter map-resolver address: ")
    #endwhile
    while (count == ""):
        count = raw_input("Enter map-request tries (1-5): ")
        if (count < 1 and count > 5): count = ""
    #endwhile
    source_eid = raw_input("Enter optional source EID: ")
else:
    dest_eid = sys.argv[1]
    if ("source" in sys.argv):
        index = sys.argv.index("source")
        if (index+1 < argc): source_eid = sys.argv[index+1]
    #endif
    if ("to" in sys.argv):
        index = sys.argv.index("to")        
        if (index+1 < argc): mr = sys.argv[index+1]
    #endif
    if ("count" in sys.argv):
        index = sys.argv.index("count")        
        if (index+1 < argc): 
            count = sys.argv[index+1]
            if (count.isdigit() == False): mr = ""
        #endif
    #endif
    if (mr == ""):
        print "Usage: lig [<iid>]<dest-eid> to <mr-rloc> " + \
            "[source <source-eid>] [count <1-5>] [debug] [no-info]"
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
    if (dest_eid == ""):
        print "No destination EID specified"
        exit(1)
    #endif
    iid = iid[0]
    iid = int(iid[1::])
#endif

#
# Do not do DNS lookup when distingusihed-name or geo-string supplied.
#
dist_name = (dest_eid[0] == "'" or dest_eid[-1] == "'")
geos = ["-N", "-S", "-E", "-W"]
geo_string = False
for g in geos:
    if (g in dest_eid): geo_string = True
#endfor

if (dist_name == False and geo_string == False):
    try:
        dest_eid = lisp.lisp_gethostbyname(dest_eid)
    except:
        print "Cannot resolve EID name '{}'".format(dest_eid)
        exit(1)
    #endtry
#endif

try: 
    mr = lisp.lisp_gethostbyname(mr)
except:
    print "Cannot resolve Map-Resolver name '{}'".format(mr)
    exit(1)
#endtry

#
# Was more internal debugging requested by user?
#
lisp.lisp_debug_logging = True if "debug" in sys.argv else False

#
# Default count if it was not supplied.
#
if (count == ""): count = "3"

lisp.lisp_i_am("lig")

#
# Open socket to send Map-Requests and to listen to Map-Replies.
#
port = str(lisp_ephem_port)

#
# Open IPC socket because if the lisp-core is running on this machine that
# lig is running, it will get Map-Reply/Notify messages that it will IPC to 
# this named socket. We have to listen on port 4342 because that is how IOS
# returns Map-Replies.
#
lisp_ipc_socket = lisp.lisp_open_listen_socket("", "/tmp/lisp-lig")

address = "0.0.0.0" if lisp.lisp_is_raspbian() else "0::0"
lisp_ephem_listen_socket = lisp.lisp_open_listen_socket(address, port)
lisp_ephem_listen_socket.settimeout(2)
try:
    lisp_listen_socket = lisp.lisp_open_listen_socket(address,
        str(lisp.LISP_CTRL_PORT))
    socket_list = [lisp_ephem_listen_socket, lisp_listen_socket, 
        lisp_ipc_socket]
except:
    socket_list = [lisp_ephem_listen_socket, lisp_ipc_socket]
#endtry

lisp_sockets[0] = lisp_ephem_listen_socket
lisp_sockets[1] = lisp_ephem_listen_socket

#
# Build and send ECM based Map-Request.
#
map_request = lisp.lisp_map_request()
map_request.record_count = 1
map_request.subscribe_bit = pubsub
map_request.xtr_id_present = pubsub
map_request.nonce = 0xdfdf0e1d10c10000 + random.randint(0, 65535)
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
if (source_eid == ""): 
    map_request.source_eid.afi = lisp.LISP_AFI_NONE
else:
    map_request.source_eid.afi = lisp.LISP_AFI_IPV6 if \
        source_eid.count(":") == 7 else lisp.LISP_AFI_IPV4
    map_request.source_eid.store_address(source_eid)
    map_request.source_eid.instance_id = map_request.target_eid.instance_id
#endif

#
# Map-Requests can be signed and validated on the map-resolver. Supplying
# a file name for a private key file will add a signature to the Map-Request.
# lisp_map_request.encode() will check to see if the file exists.
#
if (map_request.target_eid.is_ipv6() and source_eid != ""):
    map_request.signature_eid = map_request.source_eid
    map_request.privkey_filename = "./lisp-lig.pem"
#endif

#
# Build header to parse Map-Reply.
#
header = lisp.lisp_control_header()
map_reply = lisp.lisp_map_reply()
map_notify = lisp.lisp_map_notify(None)
if (mr.find(":") != -1): 
    afi = lisp.LISP_AFI_IPV6
    ml = 128
elif (mr.find(".") != -1):
    afi = lisp.LISP_AFI_IPV4
    ml = 32
else:
    print("Invalid Map-Resolver address {}".format(mr))
    exit(1)
#endif
mr = lisp.lisp_address(afi, mr, ml, 0)

#
# If we are behind a NAT, send a Info-Request to the DDT-node, wait for
# Info-Reply before proceeding. 
#
global_address = None
local_address = lisp.lisp_get_local_rloc()
if (local_address == None):
    print("Cannot obtain a local address")
    exit(1)
#endif
source_port = lisp.LISP_CTRL_PORT

if (local_address != None and local_address.is_private_address() and 
    "no-info" not in sys.argv):
    print "Possible NAT in path, sending Info-Request ... "

    dest = lisp.lisp_convert_4to6(mr.print_address_no_iid())
    lisp.lisp_send_info_request(lisp_sockets, dest, lisp.LISP_CTRL_PORT, None)

    #
    # Wait 2 seconds for Info-Reply.
    #
    opcode, source, port, packet = lisp.lisp_receive(lisp_ephem_listen_socket,
        False)

    if (source != ""):
        header = lisp.lisp_control_header()
        if (header.decode(packet) == None or header.info_reply == False):
            source = ""
        #endif
    #endif

    #
    # No Info-Reply received.
    #
    if (source == ""):
        print "No Info-Reply received"
        exit(1)
    #endif

    global_address, translated_port, new_rtr_set = \
        lisp.lisp_process_info_reply(None, packet, False)

    if (global_address == None):
        addr_str = port_str = "?"
    else:
        addr_str = global_address.print_address_no_iid()
        port_str = str(translated_port)    
    #endif
    print "Info-Reply received, public address {}, translated port {}\n". \
        format(addr_str, port_str)
    
    source_port = lisp_ephem_port

elif (lisp_listen_socket != None):

    #
    # This is the case where a lig is being done from a spot in the network
    # that is not behind a NAT. So the source-port of the ECM is 4342 so
    # an IOS map-server can send a forward-native negative Map-Reply.
    #
    # This cannot work when the lig client is behind a NAT because only
    # ephemeral ports can be translated.
    #
    # This cannot work when this lig client is run on a system when the
    # lisp-core process is running. Because only the lisp-core process can
    # send from source-port 4342.
    #
    lisp_sockets[0] = lisp_listen_socket
    lisp_sockets[1] = lisp_listen_socket
#endif

#
# Fill in ITR-RLOCs field. May have to put NAT translated address and port
# in Map-Request payload.
#
if (global_address == None):
    local_addr = local_address.print_address_no_iid()
    itr_rloc = lisp.lisp_address(lisp.LISP_AFI_IPV4, local_addr, 32, 0)
else:
    itr_rloc = global_address
    lisp_ephem_port = translated_port
#endif
map_request.itr_rlocs.append(itr_rloc)

#
# Encode the Map-Request packet and then enter transmission loop.
#
packet = map_request.encode(None, 0)
if (packet == None):
    print "Could not sign Map-Request"
    exit(1)
#endif
map_request.print_map_request()

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
count = int(count)

for i in range(count):
    packet = copy
    pubsub_str = "subscribe " if pubsub else ""
    print "Send lig {}map-request to {} for EID {} ...".format(pubsub_str,
        mr.print_address_no_iid(), target_eid_str)

    #
    # Send ECM based Map-Request to Map-Resolver..
    #
    packet = copy
    lisp.lisp_send_ecm(lisp_sockets, packet, inner_source, source_port,
        inner_dest, mr)

    #
    # Wait 2 seconds for Map-Reply and if it does not come in, retry Map-
    # Request up to count times.
    #
    map_request_ts = time.time()

    #
    # Wait 2 seconds for Map-Reply/Notify and if it does not come in, retry 
    # Map-Request up to count times.
    #
    opcode, source, port, packet = read_sockets(socket_list, 
        lisp_ephem_listen_socket, lisp_listen_socket, lisp_ipc_socket)

    #
    # Either process Map-Reply or retransmit if we have timed out.
    #
    if (source == ""): continue

    #
    # Did not get a packet, hmm.
    #
    if (opcode != "packet"): 
        print "Internal fatal error"
        continue
    #endif

    #
    # Did not get a Map-Reply, something is messed up in the network.
    #
    if (header.decode(packet) == None):
        print "Could not decode header"
        continue
    #endif

    if (header.type not in [lisp.LISP_MAP_REPLY, lisp.LISP_MAP_NOTIFY]):
        print "Expecting Map-Reply/Notify, packet type {} returned".format( \
            header.type)
        continue
    #endif

    mr = "map-reply" if header.type == lisp.LISP_MAP_REPLY else "map-notify"

    #
    # Process Map-Reply
    #
    rtt = round(time.time() - map_request_ts, 3)
    print "Received {} from {} with rtt {} secs:".format(mr, source, rtt)
    if (mr == "map-reply"):
        packet = map_reply.decode(packet)
        if (packet == None):
            print "Could not decode Map-Reply packet"
            continue
        #endif
        no_reply = False
        map_reply.print_map_reply()
        process_eid_records(map_reply.record_count, map_reply.nonce, packet)
    else:
        packet = map_notify.decode(packet)
        if (packet == None):
            print "Could not decode Map-Notify packet"
            continue
        #endif
        no_reply = False
        map_notify.print_notify()
        process_eid_records(map_notify.record_count, map_notify.nonce, packet)
    #endif
#endfor

#
# Finish up with response to user.
#
if (no_reply): print "*** No reply received ***"

#
# If pubsub, let's loop waiting for a notification.
#
if (pubsub):
    map_notify = lisp.lisp_map_notify(None)
    while (True):
        print "Waiting for map-notify EID {} RLOC-set changes ...".format( \
            target_eid_str)

        try:
            while (True):
                opcode, source, port, packet = read_sockets(socket_list, 
                    lisp_ephem_listen_socket, lisp_listen_socket, 
                    lisp_ipc_socket)
                if (source != ""): break
            #endwhile
        except:
            break
        #endtry

        print "Received map-notify from map-server {}".format(source)

        packet = map_notify.decode(packet)
        if (packet == None):
            print "Could not decode Map-Reply packet"
            continue
        #endif

        map_notify.print_notify()

        #
        # Process EID records.
        #
        process_eid_records(map_notify.record_count, map_notify.nonce, packet)

        #
        # Ack the Map-Notify.
        #
        map_notify.map_notify_ack = True
        map_notify.print_notify()
        packet = map_notify.encode(map_notify.eid_records, None)
        dest = lisp.lisp_convert_4to6(source)
        lisp.lisp_send(lisp_sockets, dest, lisp.LISP_CTRL_PORT, packet)
    #endwhile
#endif

#
# Close down resources and exit.
#
for s in lisp_sockets:
    if (s == None): continue
    name = "/tmp/lisp-lig" if (s == lisp_ipc_socket) else ""
    lisp.lisp_close_socket(s, name)
#endfor

exit(1) if (no_reply) else exit(0)

#------------------------------------------------------------------------------
