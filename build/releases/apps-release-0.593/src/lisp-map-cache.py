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
# lisp-map-cache.py
#
# This script will query a list of xTRs to retrieve their map-caches.
#
# Usage: python lisp-map-cache.py [<list-of-hosts>]
#
from __future__ import print_function
import sys
import os
from builtins import input

#
# Require env variable LISPAPI_USER and LISPAPI_PW to be set. Otherwise,
# root/"" is used.
#
require_creds = False

#
# Require to type xTRs on command line or interactively.
#
require_input = False

#------------------------------------------------------------------------------

#
# print_map_cache
#
# For each xTR in list, print the map-cache retunred in tabluar format.
#
def print_map_cache(xtr, map_cache):
    print("LISP Map-Cache for '{}', {} entries\n".format(xtr, len(map_cache)))
    for mc in map_cache:
        i = mc["instance-id"]
        e = mc["eid-prefix"]
        if ("group-prefix" in mc):
            e = "({}, {})".format(e, mc["group-prefix"])
        #endif
        u = mc["uptime"]
        rlocs = mc["rloc-set"]

        rloc_set_len = len(rlocs)
        if (rloc_set_len):
            r = "{} rlocs:".format(rloc_set_len)
        else:
            r = "action: {}".format(mc["action"])
        #endif

        print("[{}]{}, uptime: {}, {}".format(i, e, u, r))
        for rloc in rlocs:
            r = rloc["address"] if ("address" in rloc) else "none"
            u = rloc["uptime"]
            s = rloc["stats"]
            p_and_w = rloc["upriority"] + "/" + rloc["uweight"] + "/" + \
                rloc["mpriority"] + "/" + rloc["mweight"]
            print("  {}, uptime: {}, {}".format(r, u, p_and_w))

            if ("geo" in rloc): print("    geo: {}".format(rloc["geo"]))
            if ("elp" in rloc): print("    elp: {}".format(rloc["elp"]))
            if ("rle" in rloc): print("    rle: {}".format(rloc["rle"]))

            index = s.find("byte-count")
            print("    {}".format(s[:index-2]))
            print("    {}".format(s[index:]))
        #endfor
        print("")
    #endfor
    return
#enddef

#------------------------------------------------------------------------------

path = os.getenv("LISPAPI_PATH")
if (path != None):
    sys.path.append(path)
else:
    sys.path.append("./")
#endif

try:
    import lispapi
except:
    if (os.path.exists("lispapi.pyo")):
        print("Try command 'python -O lisp-map-cache.py'")
    else:
        print("Cannot find lispapi module, use LISPAPI_PATH env variable")
    #endif
    exit(1)
#endtry

#
# Check if environment variables with username and password are stored.
#
username = os.getenv("LISPAPI_USER")
if (username == None):
    if (require_creds):
        print("LISPAPI_USER environment variable needs username setting")
        exit(0)
    #endif
    username = "root"
#endif
password = os.getenv("LISPAPI_PW")
if (password == None):
    if (require_creds):
        print("LISPAPI_PW environment variable needs password setting")
        exit(0)
    #endif
    password = ""
#endif
port = os.getenv("LISPAPI_PORT")
if (port == None): port = 8080

#
# The host data structure will be a 3-element array of:
#
#     [<hostname>, <api-handle>, <map-cache-contents>]
#
hosts = []
if (len(sys.argv) > 1):
    args = sys.argv[1::]
    for host in args: hosts.append([host, None, None])
else:
    if (require_input):
        while (True):
            host = input("Enter hostname (enter return when done): ")
            if (host == ""): break
            hosts.append([host, None, None])
        #endwhile
    else:
        hosts.append(["localhost", None, None])
    #endif
#endif

print("Connecting to APIs ...", end=" ")
sys.stdout.flush()

#
# Open API with each hostname. Store in 2-element of array.
#
for host in hosts:
    host[1] = lispapi.api_init(host[0], username, password, port=port)
#endfor
print("")

#
# Call lispapi.get_system() and store contents in 3-element of array.
#
for host in hosts:
    if (host[1] == None):
        print("Could not open API to {}".format(host[0]))
    else:
        print("Querying {} ... ".format(host[0]), )
        host[2] = host[1].get_map_cache()
        print("done")
    #endif
#endfor
print("")

#
# Print system info all at one time.
#
for host in hosts:
    map_cache = host[2]
    if (map_cache == None): continue
    if (type(map_cache) == list):
        if (len(map_cache) == 0): 
            print("Empty map-cache")
            continue
        #endif
        if ("?" in map_cache[0].keys()): 
            print("Not authenticated to access {}".format(host[0]))
            continue
        #endif
    #endif

    #
    # Print the map-cache.
    #
    print_map_cache(host[0], host[2])
#endfor

exit(0)

#------------------------------------------------------------------------------

