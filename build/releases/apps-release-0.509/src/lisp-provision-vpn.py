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
# lisp-provision-vpn.py
#
# Create and bring up an VPN across all xTRs, Map-Resolvers, and Map-Servers
# that need to be involved.
#
# All is required is for the lisp-core process to be running on each LISP
# component device. This script will use the lispapi.py to configure what
# is needed to bring a VPN up or down.
#
# Usage: python lisp-provision-vpn.py [<path-to-lispapi>]
#

import sys
import random
import os
import socket

if (len(sys.argv) > 1): sys.path.append(sys.argv[1])

try:
    import lispapi
except:
    if (os.path.exists("lispapi.pyo")):
        print "Try command 'python -O lisp-provision-vpn.pyo'"
    else:
        print "Cannot find lispapi module"
    #endif
    exit(1)
#endtry

#
# Get port number from environment variable.
#
port = os.getenv("LISPAPI_PORT")
port = 8080 if (port == None) else int(port)

print """
---------- Welcome to the lispers.net VPN Provisioning System ----------
"""

#
# First test if environment variable with password is setup.
#
if (os.getenv("LISPAPI_PW") == None):
    print "LISPAPI_PW environment variable needs password setting"
    exit(0)
#endif

vpn_name = raw_input("Enter VPN name: ")
vpn_iid = raw_input("Enter VPN Instance-ID: ")

map_servers = []
while (True):
    ms = raw_input("Enter Map-Server address (enter return when done): ")
    if (ms == ""): break
    ms_input = ms
    ms = socket.gethostbyname(ms)
    api = lispapi.api_init(ms, "root", port=port)
    if (api.get_enable() == None):
        print "Authentication failed to Map-Server {}".format(ms_input)
        continue
    #endif                                
    map_servers.append({"addr": ms, "api": api})
#endwhile
print "Map-Servers will be used as Map-Resolvers"

xtrs = []
while (True):
    xtr = raw_input("\nEnter LISP xTR address (enter return when done): ")
    if (xtr == ""): break
    xtr_input = xtr
    xtr = socket.gethostbyname(xtr)
    site_name = raw_input("Enter site name where xTR {} resides: ".format(xtr))
    eid = raw_input("Enter EID-prefix for site {}: ".format(site_name))
    api = lispapi.api_init(xtr, "root", port=port)
    if (api.get_enable() == None):
        print "Authentication failed to xTR {}".format(xtr_input)
        continue
    #endif                            
    xtrs.append({"addr": xtr, "eid": eid, "site_name": site_name, "api": api,
        "pw": random.randint(0, 0xffffff)})
#endwhile

#
# Summarize input before verification.
#
print "\nCreating VPN '{}' with instance-ID {}:".format(vpn_name, vpn_iid)

print "  Map-Servers: ",
for ms in map_servers: print "  {}".format(ms["addr"]), 
print "\n  LISP Sites: "
for xtr in xtrs: 
    print "    Site: {}, EID -> RLOC: {} -> {}".format(xtr["site_name"],
        xtr["eid"], xtr["addr"])
#endfor

#
# Ask for verification.
#
go_or_stop = raw_input("\ngo/stop? ")
if (go_or_stop != "go"): 
    print "Abort provisioning"
    exit(0)
#endif

#
# Ready to start talking to devices. Right now, we assume the same password
# for each device.
#
print "Provisioning VPN {} now ...".format(vpn_name)

#
# -------------------- Call APIs --------------------
#
vpn = "VPN " + vpn_name
print "  Configure Map-Servers first ... ",
for ms in map_servers:
    ms["api"].get_enable(True)
    ms["api"].enable_mr()
    ms["api"].enable_ms()
    add_site = ms["api"].add_ms_site
    build_prefix = ms["api"].build_ms_site_allowed_prefix
    for xtr in xtrs:
        prefix_list = []
        build_prefix(prefix_list, vpn_iid, xtr["eid"], "")
        add_site(xtr["site_name"], xtr["pw"], prefix_list, vpn)
    #endfor                                 
#endfor
print "complete"

print "  Configure xTRs next ...",
for xtr in xtrs:
    xtr["api"].get_enable(True)
    xtr["api"].enable_itr()
    xtr["api"].enable_etr()
    add_mr = xtr["api"].add_itr_map_resolver
    add_ms = xtr["api"].add_etr_map_server
    for ms in map_servers:
        add_mr(ms["addr"])
        add_ms(ms["addr"], xtr["pw"])
    #endfor                                 
    add_db = xtr["api"].add_etr_database_mapping
    add_db(vpn_iid, xtr["eid"], "", [xtr["addr"]])
#endfor
print "complete"

#
# All API calls worked. We are done.
#
print "Provisioning complete!"
exit(0)

#------------------------------------------------------------------------------

