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
#
# Usage: python ltr.py [-s <source-eid>] <destination-EID | DNS-name>
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
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>",
#                       "recent-rtts" : [...], "recent-hops" : [...] }, 
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "decap-timestamp" : "<ts>", "hostname" : "<hn>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>",
#                       "recent-rtts" : [...], "recent-hops" : [...] }, 
#     { "node" : "ETR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>" }, ...
#   ] },
# 
#   { "seid" : "[<iid>]<dest-eid>", "deid" : "[<iid>]<orig-eid>", "paths" :
#   [
#     { "node" : "ITR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>",
#                       "recent-rtts" : [...], "recent-hops" : [...] }, 
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "decap-timestamp" : "<ts>", "hostname" : "<hn>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>",
#                       "recent-rtts" : [...], "recent-hops" : [...] }, 
#     { "node" : "ETR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>" }, ...
#   ] }
# ]
#
# Environment variable LISP_LTR_PORT is used to determine if the connection to
# the LISP API is done with a particular port. And if the port has a minus
# sign in front of it, it will use http rather https to connect to the
# lispers.net API.
#
#------------------------------------------------------------------------------

import sys
import struct
import random
import socket
import json
import commands
import time
import os

#------------------------------------------------------------------------------

#
# The following variables are used to curl for the local EID. Set
# approrpriately via environment variables for your deployment environment.
#
http = "https"
http_port = 8080

port = os.getenv("LISP_LTR_PORT")
if (port != None):
    if (port[0] == "-"):
        http = "http"
        port = port[1::]
    #endif
    if (port.isdigit() == False):
        print "Invalid value for env variable LISP_LTR_PORT"
        exit(1)
    #endif
    http_port = int(port)
#endif

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
# |Type=9 |         0           |        Local Private Port       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                  Local Private IPv4 RLOC                      | 
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Nonce . . .                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         . . . Nonce                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
def build_packet(rloc, port):
    first_long = socket.htonl(0x90000000 + port)
    packet = struct.pack("I", first_long)

    octet = rloc.split(".")
    value = int(octet[0]) << 24
    value += int(octet[1]) << 16
    value += int(octet[2]) << 8
    value += int(octet[3])
    packet += struct.pack("I", socket.htonl(value))

    nonce =  random.randint(0, (2**64)-1)
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

    packet_format = "II"
    format_size = struct.calcsize(packet_format)
    first_long, rloc = struct.unpack(packet_format, packet[:format_size])
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
            hn = path["hostname"]
            drloc = path["drloc"]
            if (drloc.find("?") != -1): drloc = red(drloc)

            print "  {} {}: {} -> {}, ts {}, node {}".format( \
                path["node"], ed, path["srloc"], drloc, ts, blue(hn))

            if (path.has_key("recent-rtts") and path.has_key("recent-hops")):
                rtts = path["recent-rtts"]
                hops = json.dumps(path["recent-hops"])
                hops = hops.replace("u", "")
                hops = hops.replace("'", "")
                hops = hops.replace('"', "")
                print "            ",
                print "recent-rtts {}, recent-hops {}".format(rtts, hops)
            #endif
                
        #endfor
        print ""
    #enfor
#enddef

#
# parse_eid
#
# Parse an EID in string format "[<iid>]<eid> or "[<iid>]<dns-name>".
#
def parse_eid(eid):
    no_iid = True

    #
    # Look for instance-ID brackets. They are optional so may not be present.
    # Default to instance-ID 0 when not present.
    #
    index = eid.find("]")
    if (index == -1):
        iid = "0"
    else:
        no_iid = False
        iid = eid[1:index]
        eid = eid[index+1::]
    #endif

    #
    # Do not pass in a IPv6 address to gethostbyname(). Sigh.
    #
    if (eid.find(":") == -1): eid = socket.gethostbyname(eid)
    return(iid, eid, no_iid)
#enddef    

#
# get_db
#
# Find databaas-mapping entry so we can find our IPv4 EID using API. Try some
# different methods like different port numbers. Return 4-tuple of (iid, eid,
# rloc, nat-traversal) if not matching an iid/eid pair. If matching, then just
# return rloc ant nat-traversal for the EID.
#
def get_db(match_iid, match_eid, http, port, v4v6):
    cmd = ("curl --silent --insecure -u root: {}://localhost:{}/lisp/" + \
        "api/data/database-mapping").format(http, port)
    out = commands.getoutput(cmd)

    try:
        jd = json.loads(out)
    except:
        return(None, None, None, None)
    #endtry

    for entry in jd:
        if (entry.has_key("eid-prefix") == False): continue
        eid = entry["eid-prefix"]
        eid = eid.split("/")[0]
        iid, eid, no_iid = parse_eid(eid)
        if (v4v6 and eid.find(".") == -1): continue
        if (v4v6 == False and eid.find(":") == -1): continue

        rloc = entry["rlocs"][0]["rloc"]
        nat = entry["rlocs"][0].has_key("translated-rloc")

        if (match_iid == None): return(iid, eid, rloc, nat)
        if (match_iid == iid and match_eid == eid):
            return(None, None, rloc, nat)
        #endif
    #endfor
    return(None, None, None, None)
#enddef

#
# get_rtrs
#
# Look up 0.0.0.0/0 map-cache entry and get list of RTRs.
#
def get_rtrs(http, port):
    cmd = ("curl --silent --insecure -u root: {}://localhost:{}/lisp/" + \
        "api/data/map-cache").format(http, port)
    out = commands.getoutput(cmd)

    try:
        jd = json.loads(out)
    except:
        return([])
    #endtry

    rtr_list = []
    for entry in jd:
        if (entry.has_key("group-prefix")): continue
        if (entry.has_key("eid-prefix") == False): continue
        if (entry["eid-prefix"] != "0.0.0.0/0"): continue

        for rloc in entry["rloc-set"]:
            if (rloc.has_key("rloc-name") == False): continue
            if (rloc["rloc-name"] != "RTR"): continue
            if (rloc.has_key("address") == False): continue
            rtr_list.append(rloc["address"])
        #endfor
    #endfor
    return(rtr_list)
#enddef

#
# bold
#
# Print in bold font.
#
def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef

#
# blue
#
# Print hostnames in bold blue.
#
def blue(string):
    return("\033[94m" + bold(string) + "\033[0m")
#enddef

#
# red
#
# Print hostnames in bold red.
#
def red(string):
    return("\033[91m" + bold(string) + "\033[0m")
#enddef

#------------------------------------------------------------------------------

#
# Main entry point. Get command line arguments.
#
if ("-s" in sys.argv):
    args_bad = len(sys.argv) != 4
else:
    args_bad = len(sys.argv) != 2
#endif
if (args_bad):
    print "Usage: python ltr.py [-s <source-eid>] <destination-EID | DNS-name>"
    exit(1)
#endif

diid, deid, no_iid = parse_eid(sys.argv[-1])
if (diid == None):
    print "<destinaton-eid> parse error"
    exit(1)
#endif
v4v6 = deid.find(":") == -1

#
# Get source-EID from command-line or get it from xTR configuration.
#
if ("-s" in sys.argv):
    index = sys.argv.index("-s") + 1
    siid, seid, no_iid = parse_eid(sys.argv[index])
    if (siid == None):
        print "-s <source-eid> parse error"
        exit(1)
    #endif
    if (no_iid): siid = None
    x, y, rloc, nat = get_db(siid, seid, http, http_port, v4v6)
    if (rloc == None):
        print "[{}]{} is not a local EID".format(siid, seid)
        exit(1)
    #endif
else:
    siid, seid, rloc, nat = get_db(None, None, http, http_port, v4v6)
    if (siid == None):
        print "Could not find local EID, maybe lispers.net API port wrong?"
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
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.bind(("0::0", 0))
sock.settimeout(3)
port = sock.getsockname()[1]

#
# Build empty LISP-Trace packet and send on overlay.
#
nonce, packet = build_packet(rloc, port)

#
# First send RLOC packet to RTR to get translated NAT address info to RTRs.
#
if (nat):
    rtr_list = get_rtrs(http, http_port)
    for rtr in rtr_list:
        print "Send NAT-traversal LISP-Trace to RTR {} ...".format(rtr)
        sock.sendto(packet, ("::ffff:" + rtr, LISP_TRACE_PORT))
    #endfor
#endif

print "Send round-trip LISP-Trace between EIDs [{}]{} and [{}]{} ...". \
    format(siid, seid, diid, deid)

ts = time.time()

dest = deid if (deid.find(":") != -1) else "::ffff:" + deid
sock.sendto(packet, (dest, LISP_TRACE_PORT))

#
# Wait for reply, timeout after 3 seconds.
#
try:
    packet, source = sock.recvfrom(9000)
    source = source[0].replace("::ffff:", "")
except socket.timeout:
    exit(1)
except socket.error, e:
    print "recvfrom() failed, error: {}".format(e)
    exit(1)
#endtry

rtt = round(time.time() - ts, 3)

print "Received reply from {}, rtt {} secs".format(source, rtt)
print ""
json_data = parse_packet(nonce, packet)
if (json_data == {}): exit(1)

#
# Display JSON and return.
#
display_packet(json_data)

sock.close()
exit(0)

#------------------------------------------------------------------------------
