#!/usr/bin/python
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
# ltr.py - LISP EID Traceroute Client - Trace the encap/decap paths

# Usage: python ltr.py [-s <source-eid>] <destination-EID>
#
#   -s: Optional source EID.
#   <destination-EID>: required parameter [<iid>] in front is optional
#
# This application is run on an xTR. Typically a ITR or RTR, where the
# encapsulator adds to the ltr message with the RLOC the ITR is encapsulating
# to. Then the decapsulator will decapsulate and swap the source and
# destination addresses to return the packet to the source-EID (running the
# client program). If the ETR is not the EID, then the packet will be re-
# encapsulated in which more data is added to the ltr message.
#
# ltr messages run in UDP on port 2434 (4342 backwards) and are returned
# to the client program.
#
# The LISP-Trace message takes the following path:
#
# (1) ltr sends LISP-TRACE packet from its EID to the EID of the ETR on
# port 2434. It builds a type=9 packet with a nonce and an empty JSON field.
#
# (2) ITR will look up destination EID as part of forwarding logic and add
# RLOC information to LISP-Trace message. The message is encapsulated to
# the ETR.
#
# (3) The ETR (or RTR) will decap packet. It will add information to the LISP-
# packet. If it is the destination EID, it will send the LISP-Trace packet
# using itself as the source and the original source as the destination.
#
# (4) The local ITR will encapsulate the packet and add RLOC information to
# the LISP-Trace packet. It encapsulates the return packet to the ETR.
#
# (5) The ETR decapsulates the packet and sends it to the ltr client so the
# accumulated JSON data can be displayed for the user.
#
# This functionality works on a chain of encapsulating tunnels to give the
# user what RLOCs are used and the arrival time of the packet. It allows an
# ltr client to not only determine path and latency of the network, but if
# the encapsulation paths are symmetric or asymmetric.
#
# If there an error along the path, the node detecting the error will return
# the LISP-Trace packet to the RLOC of the originating ITR.
#
# The JSON format of an LISP-Trace packet is an array of dictionary arrays.
# The array will typically have 2 elements, one from ltr source to destination
# EID and one for the return path. Each dictionary array is keyed with "seid",
# "deid", and "paths". The array "paths" is the node data that is appended
# at each encapsulation hop. Note example below:
# 
# [ 
#   { "seid" : "[<iid>]<orig-eid>", "deid" : "[<iid>]<dest-eid>", "paths" : a
#   [
#     { "node" : "ITR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "decap-timestamp" : "<ts>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>" },
#     { "node" : "ETR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>" }, ...
#   ] },
# 
#   { "seid" : "[<iid>]<dest-eid>", "deid" : "[<iid>]<orig-eid>", "paths" :
#   [
#     { "node" : "ITR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "decap-timestamp" : "<ts>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>" },
#     { "node" : "ETR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>" }, ...
#   ] }
# ]

#------------------------------------------------------------------------------

import sys
import struct
import random
import socket
import json
import commands

#------------------------------------------------------------------------------

#
# The following variables are used to curl for the local EID. Set
# approrpriately for your deployment environment.
#
#http = "http"
#http_port = 9090

http_port = 8080
http = "https"

LISP_TRACE_PORT = 2434

#------------------------------------------------------------------------------

#
# build_packet
#
# Build LISP-Trace packet. This is what the ltr client will build, an empty
# ltr packet type 9 with a nonce.
#
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Type=9 |                     0                                 |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Nonce . . .                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         . . . Nonce                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
def build_packet():
    first_long = socket.htonl(0x90000000)
    nonce =  random.randint(0, (2**64)-1)
    packet = struct.pack("I", first_long)
    packet += struct.pack("Q", nonce)
    return(nonce, packet)
#enddef

#
# parse_packet
#
# Parse packet and return JSON data only.
#
def parse_packet(nonce, packet):
    if (len(packet) < 12): return(False)

    packet_format = "I"
    format_size = struct.calcsize(packet_format)
    first_long = struct.unpack(packet_format, packet[:format_size])[0]
    packet = packet[format_size::]
    if (socket.ntohl(first_long) != 0x90000000):
        print "Invalid LISP-Trace message"
        return({})
    #endif

    packet_format = "Q"
    format_size = struct.calcsize(packet_format)
    pnonce = struct.unpack(packet_format, packet[:format_size])[0]
    packet = packet[format_size::]

    #
    # Check compare nonce sent with one echo'ed in repsonse.
    #
    if (pnonce != nonce):
        print "Invalid nonce, sent {}, received {}".format(nonce, pnonce)
        return({})
    #endif

    if (len(packet) == 0):
        print "No JSON data in payload"
        return({})
    #endif

    #
    # Parse JSON data.
    #
    try:
        json_data = json.loads(packet)
    except:
        print "Invalid JSON data: '{}'".format(packet)
        return({})
    #endtry
    return(json_data)
#enddef

#
# display_packet
#
# Display passed in JSON data.
#
def display_packet(jd):
    for segment in jd:
        print "Path from {} to {}:".format(segment["seid"], segment["deid"])
        for path in segment["paths"]:
            if (path.has_key("encap-timestamp")):
                ts = path["encap-timestamp"]
                ed = "encap"
            #endif
            if (path.has_key("decap-timestamp")):
                ts = path["decap-timestamp"]
                ed = "decap"
            #endif
            print "  {} {}: {} -> {}, {}".format(path["node"], ed,
                path["srloc"], path["drloc"], ts)
        #endfor
        print ""
    #enfor
#enddef

#
# parse_eid
#
# Parse an EID in string format "[<iid>]<eid>".
#
def parse_eid(eid):
    index = eid.find("]")
    iid = "0" if (index == -1) else eid[1:index]
    eid = eid[index+1::]
    if (eid.count(".") != 3): return(None, None)
    return(iid, eid)
#enddef    

#
# get_db
#
# Find databaas-mapping entry so we can find our IPv4 EID using API. Try some
# different methods like different port numbers.
#
def get_db(http, port, diid):
    cmd = ("curl --silent --insecure -u root: {}://localhost:{}/lisp/" + \
        "api/data/database-mapping").format(http, port)
    out = commands.getoutput(cmd)

    try:
        jd = json.loads(out)
    except:
        return(None, None)
    #endtry

    for entry in jd:
        if (entry.has_key("eid-prefix") == False): continue
        eid = entry["eid-prefix"]
        eid = eid.split("/")[0]
        iid, eid = parse_eid(eid)
        return(iid, eid)
    #endfor
    return(None, None)
#enddef    

#------------------------------------------------------------------------------

#
# Main entry point. Get command line arguments.
#
diid, deid = parse_eid(sys.argv[-1])
if (diid == None):
    print "<destinaton-eid> parse error"
    exit(1)
#endif

#
# Get source-EID from command-line or get it from xTR configuration.
#
if ("-s" in sys.argv):
    index = sys.argv.index("-s") + 1
    siid, seid = parse_eid(sys.argv[index])
    if (siid == None):
        print "-s <source-eid> parse error"
        exit(1)
    #endif
else:
    siid, seid = get_db(http, http_port, diid)
    if (siid == None):
        print "Could not find local EID"
        exit(1)
    #endif
#endif    

#
# Verify IIDs of source and dest are the same.
#
diid = siid if diid == "0" else diid
if (diid != siid):
    print "Instance-IDs must be the same for source and destination EIDs"
    exit(1)
#endif

#
# Open send socket. Bind local EID to socket.
#
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((seid, LISP_TRACE_PORT))
sock.settimeout(3) 

#
# Build empty LISP-Trace packet and send on overlay.
#
nonce, packet = build_packet()
print "Send LISP-Trace packet [{}]{} -> [{}]{} ...".format(siid, seid,
    diid, deid)

sock.sendto(packet, (deid, LISP_TRACE_PORT))

#
# Wait for reply, timeout after 3 seconds.
#
try:
    packet, source = sock.recvfrom(9000)
    source = source[0]
except socket.timeout:
    exit(1)
except socket.error, e:
    print "recvfrom() failed, error: {}".format(e)
    exit(1)
#endtry

print "Received reply from {}:".format(source)
json_data = parse_packet(nonce, packet)
if (json_data == {}): exit(1)

#
# Display JSON and return.
#
display_packet(json_data)

sock.close()
exit(0)

#------------------------------------------------------------------------------
