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
# lisp-sc.py
#
# Usage: python -O lisp-sc.py [<user:pw@host:port>] [<eid>] | [<site>]
#        python -O lisp-sc.py [<host:port>] [<eid>]
#        python -O lisp-sc.py [<host>] [<eid>]
#
# Dispay the LISP registered mappings in the map-server a command that
# displays the table as it looks like on the web interface.
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

def timed_out(ts):
    if (ts.find("days") != -1): return(bold(red(ts)))
    h, m, s = ts.split(":")
    if (int(h) != 0): return(bold(red(ts)))
    if (int(m) >= 3): return(bold(red(ts)))
    return(ts)
#enddef

#------------------------------------------------------------------------------

if ("help" in sys.argv):
    print("Usage: ./sc [<user:pw@host:port> | <host:port> | <host> | help]")
    exit(0)
#endif

user = "root"
pw = ""
host = "localhost"
port = "8080"

#
# Get input from comamnd line, if any. Check site name supplied.
#
site_input = sys.argv[-1]
if (site_input.count(".") == 3 or site_input.count(":") == 2):
    site_input = None
#endif
if (site_input != None): sys.argv = sys.argv[0:-1]

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
    "api/data/site-cache").format(user, pw, host, port)
curl_sum = ("curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + \
    "api/data/site-cache-summary").format(user, pw, host, port)
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
try:
    site_cache = json.loads(output)
except:
    print("Curl output did not return JSON")
    exit(1)
#endtry

#
# Get site summary info to title each EID set.
#
output = getoutput(curl_sum)
sc_summary = json.loads(output)

sites = {}
for sc in sc_summary:
    c = sc["registrations"][0]["count"]
    r = sc["registrations"][0]["registered-count"]
    sites[sc["site"]] = (c, r)
#endfor    

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

print("\nLISP Map-Server Site-Cache for {}, hostname {}, release {}\n". \
    format(host, hostname, ver["lisp-version"]))

if (len(site_cache) == 0):
    print("Site-cache is empty")
    exit(0)
#endif    

found_eid = False
for site in sites:
    if (site_input and site_input != site): continue

    s = bold(site)
    c = sites[site][0]
    r = sites[site][1]
    r = bold(str(r))
    print("Site {}, {} EID entries, EIDs registered {}:".format(s, c, r))
    
    for sc in site_cache:
        if (sc["registered-rlocs"] == []): continue

        eid = sc["eid-prefix"]
        group = sc["group-prefix"] if "group-prefix" in sc else ""
        if (eid_input and (eid + group).find(eid_input) == -1): continue

        found_eid = True
        if ("group-prefix" in sc):
            eid = "({}, {})".format(eid, sc["group-prefix"])
        #endif
        eid = green("[{}]{}".format(sc["instance-id"], eid))
        eid = "  EID {},".format(eid)
        ttl = sc["last-registered"]
        yn = green("registered") if sc["registered"] == "yes" else \
            red("registered")
        uptime = "uptime {}, {}".format(sc["first-registered"], yn)
        site = bold(sc["site-name"])
        lr = timed_out(sc["last-registered"])
        uptime += " since {}".format(lr)
        print(eid, uptime)

        for r in sc["registered-rlocs"]:
            rloc = red(r["address"])
            up = r["upriority"]; uw = r["uweight"]
            mp = r["mpriority"]; mw = r["mweight"]
            p = "up/uw {}/{} mp/mw {}/{}".format(up, uw, mp, mw)
            rn = ", " + blue(r["rloc-name"]) if "rloc-name" in r else ""
            rloc_line = "    {}, uptime {}, {}{}".format(rloc, r["uptime"], p,
                rn)
            print(rloc_line)
        #endfor
        print()
    #endfor
#endfor

#
# If EID specified but not found, return one line message.
#
if (eid_input and found_eid == False):
    print("EID {} not in site-cache".format(green(eid_input)))
#endif    

exit(0)

#------------------------------------------------------------------------------


