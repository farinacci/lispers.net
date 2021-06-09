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
# Usage: python -O lisp-mc.py [<user:pw@host:port>]
#        python -O lisp-mc.py [<host:port>]
#        python -O lisp-mc.py [<host>]
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

for mc in map_cache:
    eid = green("[{}]{}".format(mc["instance-id"], mc["eid-prefix"]))
    eid = "EID {},".format(eid)
    ttl = mc["ttl"]
    ttl = "never" if (ttl == "--") else ttl.split(".")[0] + "m"
    uptime = "uptime {}, ttl {}".format(mc["uptime"], ttl)
    print(eid, uptime)

    for r in mc["rloc-set"]:
        uptime = "{} since {}".format(r["state"], r["uptime"])
        state = r["state"]
        state = green(state) if state == "up-state" else red(state)
        rloc = "  RLOC {}, state {} since {}".format(red(r["address"]), state,
            r["uptime"])
        if ("rloc-name" in r):rloc += ", {}".format(blue(r["rloc-name"]))
        stats = "    {}".format(r["stats"])

        print(rloc)
        print(stats)
        r, h, l = format_telemetry(r)
        print("    rtts {}, hops {}, latencies {}".format(r, h, l))
    #endfor
    print()
#endfor

exit(0)

#------------------------------------------------------------------------------


