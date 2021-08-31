#!/usr/bin/env python
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
# lisp-mc.py
#
# Usage: python -O lisp-mc.py [<user:pw@host:port>] [<eid>]
#        python -O lisp-mc.py [<host:port>] [<eid>]
#        python -O lisp-mc.py [<host>] [<eid>]
#
# Dispay the LISP map-cache using a command that displays the table as it
# looks like on the web interface.
#
#------------------------------------------------------------------------------
from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
from subprocess import getoutput
import sys
import json

#------------------------------------------------------------------------------

def green(string):
    return("\033[92m" + string + "\033[0m")
#enddef

def dark_green(string):
    return("\033[32;1m" + string + "\033[0m")
#enddef

def red(string):
    return("\033[91m" + string + "\033[0m")
#enddef

def blue(string):
    return("\033[94m" + string + "\033[0m")
#enddef

def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef

def format_telemetry(rloc):
    r = str(rloc["recent-rloc-probe-rtts"]).replace("u'", "")
    r = r.replace("'", "")
    h = str(rloc["recent-rloc-hop-counts"]).replace("u'", "")
    h = h.replace("'", "")
    l = str(rloc["recent-rloc-probe-latencies"]).replace("u'", "")
    l = l.replace("'", "")
    return(r, h, l)
#enddef

def print_stats(rr):
    stats = rr["stats"]
    last_sec = ("recent-packet-sec" in rr and rr["recent-packet-sec"])
    last_min = ("recent-packet-min" in rr and rr["recent-packet-min"])
    if (last_sec or last_min):
        s = stats.split(": ")
        s1 = s[1].split(",")
        count = dark_green(s1[0]) if last_sec else green(s1[0])
        s1[0] = count
        s[1] = ",".join(s1)
        stats = ": ".join(s)
    #endif
    return(stats)
#enddef

#------------------------------------------------------------------------------

if ("help" in sys.argv):
    print("Usage: ./mc [<user:pw@host:port> | <host:port> | <host> | help]")
    exit(0)
#endif

user = "root"
pw = ""
host = "localhost"
port = "8080"

#
# Get input from comamnd line, if any.

#
# First check if EID supplied.
#
eid_input = sys.argv[-1]
for e in eid_input.split("."):
    if (e.isdigit()): continue
    eid_input = None
    break
#endfor    
if (eid_input == None):
    eid_input = sys.argv[-1]
    for e in eid_input.split(":"):
        if (e == ""): continue
        try:
            int(e, 16)
            continue
        except:
            eid_input = None
            break
        #endtry
    #endfor
#endif
if (eid_input != None): sys.argv = sys.argv[0:-1]

#
# Second get hostname and port number to query.
#
if (len(sys.argv) == 2):
    args = sys.argv[1]
    args = args.split("@")
    if (len(args) == 2):
        userpw = args[0].split(":")
        if (userpw[0] != ""): user = userpw[0] 
        if (len(userpw)== 2 and userpw[1] != ""): pw = userpw[1]
        args = args[1]
    else:
        args = args[0]
    #endif
    hostport = args.split(":")
    if (hostport[0] != ""): host = hostport[0] 
    if (len(hostport) == 2 and hostport[1] != ""): port = hostport[1] 
#endif

curl = ("curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + \
    "api/data/map-cache").format(user, pw, host, port)
ver = ("curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + \
    "api/data/system").format(user, pw, host, port)

#print(curl)
host = bold("{}:{}".format(host, port))

output = getoutput(curl)
if (output == None or output == ""):
    print("No curl output returned on {}".format(host))
    exit(1)
#endif
if (output.find("not-auth") != -1):
    print("Authentication failed on {}".format(host))
    exit(1)
#endif
map_cache = json.loads(output)

#
# Get hostname from version info query.
#
output = getoutput(ver)
if (output == None or output == ""):
    print("Could not get hostname on {}".format(host))
    exit(1)
#endif
ver = json.loads(output)
hostname = blue(ver["hostname"])

print("\nLISP Map-Cache for {}, hostname {}, release {}\n".format(host,
    hostname, ver["lisp-version"]))

if (len(map_cache) == 0):
    print("Map-cache is empty")
    exit(0)
#endif    

found_eid = False
for mc in map_cache:
    eid = mc["eid-prefix"]
    group = mc["group-prefix"] if "group-prefix" in mc else ""
    if (eid_input and (eid + group).find(eid_input) == -1): continue

    found_eid = True
    if ("group-prefix" in mc): eid = "({}, {})".format(eid, mc["group-prefix"])
    eid = green("[{}]{}".format(mc["instance-id"], eid))
    eid = "EID {},".format(eid)
    ttl = mc["ttl"]
    ttl = "never" if (ttl == "--") else ttl.split(".")[0] + "m"
    uptime = "uptime {}, ttl {}".format(mc["uptime"], ttl)
    a = mc["action"]
    uptime += ", action {}".format(bold(a)) if a != "no-action" else ""
    print(eid, uptime)

    for r in mc["rloc-set"]:
        rloc_set = [r]
        if ("multicast-rloc-set" in r): rloc_set += r["multicast-rloc-set"]
            
        for rr in rloc_set:
            if (rloc_set.index(rr) == 0):
                rlocrle = "RLOC"
            else:
                rlocrle = "mRLOC"
            #endif

            rloc = rr["address"]
            if ("rle" in rr):
                rloc = rr["rle"]
                rlocrle = "RLE"
            #endif
            if ("encap-port" in rr): rloc += ":{}".format(rr["encap-port"])
            state = rr["state"]
            state = green(state) if state == "up-state" else red(state)

            rloc = "  {} {}, state {} since {}".format(rlocrle, red(rloc),
                state, rr["uptime"])
            if ("encap-crypto" in rr):
                rloc += ", {}".format(rr["encap-crypto"])
            #endif
            if ("rloc-name" in rr):
                rloc += ", {}".format(blue(rr["rloc-name"]))
            #endif

            print(rloc)
            print("    {}".format(print_stats(rr)))
            rtt, hc, lat = format_telemetry(rr)
            print("    rtts {}, hops {}, latencies {}".format(rtt, hc, lat))
        #endfor
    #endfor
    print()
#endfor

#
# If EID specified but not found, return one line message.
#
if (eid_input and found_eid == False):
    print("EID {} not in map-cache".format(green(eid_input)))
#endif    

exit(0)

#------------------------------------------------------------------------------


