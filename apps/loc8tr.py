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
# loc8tr.py - Locator Traceroute - Traceroute paths to LISP RLOCs
#
# Last update: Wed Sep 26 14:13:59 PDT 2018
#
# Usage: python loc8tr.py [-n] [-d] [-hp <host>:<port>]
#                                   [-up <username>:<password>]
#
#   -n:
#       Do not do DNS lookups on traceroute hops
#   -d:
#       Produce more output.
#   -hp <host>:<port>:
#       Host address and Port number to get to lispers.net restful API. When
#       <port> is a negative number that means that http rather than https
#       is used.
#   -up <username>:<password>:
#       Supply username and password for lispers.net map-cache query.
#
# This application is run on an xTR. Typically a ITR or RTR so the map-cache
# can be retreived to find all the active RLOCs being used for each map-cache
# entry. The applicaiton assumes the lispers.net xTR implementation is running
# and retrieves the map-cache using this restful interface:
#
# curl --silent --insecure -u "root:" \
#      https://localhost:8080/lisp/api/data/map-cache
#
# The app will do some JSON fetching and build an RLOC data structure to
# start traceroute to each RLOC. It will then put the results in a local
# file system to be viewed later.
#
# This app will create a directory in the current directory named:
#
#     loc8ator-<data>-<time>
#
# And creates 3 files:
#
# loc8tr.log     - Output from this script in human readable form.
# loc8tr.json    - JSON for the RLOC-cache
# loc8tr-mc.json - JSON for the data pulled from the lispers.net xTR
#
# Most output is self-explanatory. You will find that a green "!" means the
# traceroute made it to the RLOC. You will find a red "X", the traceroute
# fell short of finding the RLOC.
#
from __future__ import print_function
import json
import sys
import socket
import os
import datetime
import string
try:
    from commands import getoutput
except:
    from subprocess import getoutput
#endtry    

#
# ---------- Constants and Data Structures ----------
#

#
# Caller allowed to supply username/password for curling to lispers.net.
#
userpw = "root:"
if ("-up" in sys.argv):
    userpw = sys.argv.index("-up")
    userpw = sys.argv[userpw+1]
    check = userpw.split(":")
    if (len(check) == 1):
        print("Invalid syntax for username:password pair")
        exit(1)
    #endif
#endif    

http = "https"
hp = "localhost:8080"
if ("-hp" in sys.argv):
    hp = sys.argv.index("-hp")
    hp = sys.argv[hp+1]
    check = hp.split(":")
    if (len(check) == 1):
        print("Invalid syntax for host:port pair")
        exit(1)
    #endif
    port = check[1]
    if (port[0] == "-"):
        http = "http"
        port = port[1::]
    #endif
    if (port.isdigit() == False):
        print("Invalid syntax for port")
        exit(1)
    #endif
    hp = check[0] + ":" + port
#endif    
curl_command = 'curl --silent --insecure -u "{}" {}://{}/lisp/api/data/map-cache'.format(userpw, http, hp)

#
# The parameters we use for traceroute.
#
tr_command = "traceroute -n -m 15 -q 1 -w 1 {}"
ios_tr_command = 'dohost "traceroute {}"'

#
# Logging names.
#
log_ts = datetime.datetime.now().strftime("%m-%d-%y-%H-%M-%S")
log_dir = "loc8tr-{}".format(log_ts)
log_file = "loc8tr.log"
json_file = "loc8tr.json"
mc_file = "loc8tr-mc.json"

#
# RLOC-cache dictionary array key is RLOC address and value is a n-tuple of:
#
#  "<rloc-name>",
#  "<traceroute-output>",
#  [["<tr-hop>", "<tr-ms>"], ...],
#  [<rtt1>, <rtt2>, rtt3>],
#  ["<fhop1>/<rhop1>", "<fhop2>/<rhop2>", "<fhop3>/<rhop3>"],
#  ["<flat1>/<rlat1>", "<flat2>/<rlat2>", "<flat3>/<rlat3>"],
#  ["<eid>", ...]
# 
rloc_cache = {}
RLOC_NAME = 0
TR_OUTPUT = 1
TR_HOPS   = 2
RTTS      = 3
HOPS      = 4
LATS      = 5
EIDS      = 6

no_dns = ("-n" in sys.argv)
debug = ("-d" in sys.argv)

#
# ---------- Internal Function Definitions ----------
#

#
# massage
#
# Massage the output of traceroute to return the IP address of hop and rtt for
# hop.
#
def massage(tr, cisco):
    hops = []
    lines = tr.split("\n")
    lines = lines[4::] if cisco else lines[1::]

    for line in lines:
        l = line.split()
        if (len(l) == 0): continue
        if (l[1].find("Invalid") != -1):
            hops.append(["?", "?"])
            continue
        #endif

        #
        # Cisco will display output from the same hop on multiple lines.
        # Skip it since we just get the first query RTT (since we can't do
        # -q 1 like we can with linux traceroute.
        #
        if (cisco):
            if (l[2] == "msec"): continue
            hops.append([l[1], l[2]])
        else:
            hops.append([l[1], l[-2]])
        #endif
    #endfor
    return(hops)
#enddef

#
# build_logfiles
#
# Create directory 'loc8tr-<date-timestamp>' and put log files and json files
# in directory.
#
def build_logfiles():
    os.system("mkdir {}".format(log_dir))
    os.system("touch {}/{}".format(log_dir, log_file))
    os.system("touch {}/{}".format(log_dir, json_file))
    os.system("touch {}/{}".format(log_dir, mc_file))
#enddef

#
# Print
#
# Print to both stdout and loc8tr.log.
#
def Print(string):
    print(string)
    sys.stdout.flush()

    f = open("./{}/{}".format(log_dir, log_file), "a")
    f.write(string + "\n")
    f.close()
#enddef

#
# is_v4v6
#
# Return True if 'address' is an IPv4 or IPv6 address string.
#
def is_v4v6(addr):
    if (addr.count(".") == 3):
        addr = addr.split(".")
        for a in addr:
            if (a.isdigit() == False): return(False)
        #endfor
        return(True)
    #endif
    if (addr.find(":") != -1):
        addr = addr.replace(":", "")
        for a in addr:
            if (a not in string.hexdigits): return(False)
        #endfor
        return(True)
    #endif
    return(False)
#enddef

def blue(string):
    return("\033[94m" + string + "\033[0m")
#enddef

def green(string):
    return("\033[92m" + string + "\033[0m")
#enddef

def red(string):
    return("\033[91m" + string + "\033[0m")
#enddef

def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef

#
# is_multicast
#
# Return true if first octet is in range 224 through 239, inclusive.
#
def is_multicast(address):
    if (address.find(".") != -1):
        addr = int(address.split(".")[0])
        return(addr >= 224 and addr <= 239)
    #endif
    if (address.find(":") != -1):
        return(address[0:1].lower() == "ff")
    #endif
    return(False)
#enddef

#
# ---------- Main Entry Point ----------
#

#
# Setup directory for saving data.
#
build_logfiles()

#
# Get map-cache data from lispers.net ITR or RTR.
#
if (debug): Print("Run '{}' ...".format(bold(curl_command)))
map_cache = getoutput(curl_command)
if (debug): Print("curl returned '{}'".format(map_cache))
    
if (map_cache == ""):
    Print("curl returned empty string")
    exit(1)
#endif    

try:
    map_cache = json.loads(map_cache)
except:
    Print("Invalid JSON")
    exit(1)
#endtry
    
if (type(map_cache) != list):
    Print("Could not retrieve map-cache")
    exit(1)
#endif    
if (map_cache == []):
    Print("No map-cache entries returned")
    exit(1)
#endif    
if (len(map_cache) == 1 and "?" in map_cache[0]):
    Print("Authentication failed while retrieving map-cache")
    exit(1)
#endif

#
# Build rloc_cache data structure with IPv4 and IPv6 RLOC-types only.
#
for entry in map_cache:
    eid = "[{}]".format(entry["instance-id"])
    if ("group-prefix" in entry):
        eid += "({}, {})".format(entry["eid-prefix"], entry["group-prefix"])
    else:
        eid += "{}".format(entry["eid-prefix"])
    #endif

    rloc_set = {}
    for rloc in entry["rloc-set"]:
        address = rloc["address"]
        if (is_v4v6(address) == False): continue

        rloc_set[address] = rloc
        if ("multicast-rloc-set" in rloc):
            for mrloc in rloc["multicast-rloc-set"]:
                addr = mrloc["address"] + "%" + address
                rloc_set[addr] = mrloc
            #endfor
        #endif
    #endfor

    for address in rloc_set:
        rloc = rloc_set[address]
        rn = rloc["rloc-name"] if ("rloc-name" in rloc) else "?"
        if (is_v4v6(rloc["address"]) == False): continue

        if (address not in rloc_cache):
            rtts = []
            for rtt in rloc["recent-rloc-probe-rtts"]: rtts.append(float(rtt))
            hops = []
            for hop in rloc["recent-rloc-hop-counts"]: hops.append(str(hop))
            lats = []
            for lat in rloc["recent-rloc-probe-latencies"]:
                lats.append(str(lat))
            #endfor
            rloc_cache[address] = [rn, None, [], rtts, hops, lats, []]
        #endif
        rloc_cache[address][EIDS].append(eid)
    #endfor
#endfor

Print("Found {} map-cache entries with {} distinct RLOC(s):".format( \
    len(map_cache), len(rloc_cache)))

#
# Print some RLOC state from what we found.
#
for addr in rloc_cache:
    rloc = rloc_cache[addr]
    rn = blue(rloc[RLOC_NAME])
    rtts = rloc[RTTS]
    hops = rloc[HOPS]
    lats = rloc[LATS]
    eids = rloc[EIDS]

    a = addr.split("%")
    if (len(a) == 2):
        a = bold(a[0]) + "(" + a[1] + ")"
    else:
        a = bold(addr)
    #endif

    Print("RLOC {} ({}), rtts(secs) {}, hops {}, latencies {}".format(a, rn,
        rtts, hops, lats))
    Print("     EIDs: {}".format(eids))
#endfor
Print("")

#
# Start traceroute to each RLOC.
#
for addr in rloc_cache:
    if (is_multicast(addr)):
        rloc[TR_OUTPUT] = ""
        rloc[TR_HOPS] = []
        Print("Suppress traceroute to multicast RLOC {}".format(addr))
        Print("")
        continue
    #endif

    address = addr.split("%")
    address = address[1] if (len(a) == 2) else address[0]

    #
    # Determine if we should use linux traceroute or if we are running on
    # cisco guestshell. If the latter, run IOS traceroute.
    #
    cisco = os.path.exists("/cisco/guestshell")
    if (cisco):
        cmd = ios_tr_command.format(address)
    else:
        cmd = tr_command.format(address)
    #endif

    rn = blue(rloc[RLOC_NAME])
    Print("Run {} ({}) ...".format(bold(cmd), rn)) 
    
    out = getoutput(cmd)

    rloc = rloc_cache[addr]
    rloc[TR_OUTPUT] = out
    rloc[TR_HOPS] = massage(rloc[TR_OUTPUT], cisco)
    if (no_dns): name = "-"

    for hop in rloc[TR_HOPS]:
        num = str(rloc[TR_HOPS].index(hop) + 1).rjust(2)
        if (hop[0] == "?"):
            hop[0] = hop[1] = name = "?"
        #endif
        if (no_dns == False):
            try: name = socket.gethostbyaddr(hop[0])[0]
            except: name = "?"
        #endif

        bangx = "" if (hop != rloc[TR_HOPS][-1]) else bold(green("!")) if \
            (hop[0] == address) else bold(red("X"))

        if (hop[0] == "*"):
            Print("{}  * {}".format(num, bangx))
            continue
        #endif

        Print("{}  {} ({}), rtt {} ms {}".format(num, hop[0], name, hop[1],
            bangx))
    #endfor
    Print("")
#endfor

Print("Log and JSON files created in directory ./{}".format(bold(log_dir)))

#
# Dump data structures to json files.
#
f = open("{}/{}".format(log_dir, json_file), "a")
f.write(json.dumps(rloc_cache))
f.close()        

f = open("{}/{}".format(log_dir, mc_file), "a")
f.write(json.dumps(map_cache))
f.close()        

exit(0)

#------------------------------------------------------------------------------
