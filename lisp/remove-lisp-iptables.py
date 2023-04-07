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
# remove-lisp-iptables.py
#
# This python script deconifgures iptables that lisp_itr_kernel_filter() 
# configured. This script will also remove routes and ARP entries associated
# with vlan4094 if "program-hardware = yes" is configured.
# 
# -----------------------------------------------------------------------------
from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
import os
import platform
from subprocess import getoutput

#------------------------------------------------------------------------------

#
# more_specific
#
# If 'prefix' more specific than 'agg', return True. 'agg' is always in slash
# format and 'prefix' could be either in dotted decimal or slash format.
#
def more_specific(agg, prefix):
    ls, lsm = agg.split("/")
    lsm = int(lsm)
    mask = (2 ** lsm) - 1
    mask <<= 32 - lsm

    ls = ls.split(".")
    ls = int(ls[0]) << 24 | int(ls[1]) << 16 | int(ls[2]) << 8 | int(ls[3])
    if (prefix.find("/") != -1): prefix = prefix.split("/")[0]
    ms = prefix.split(".")
    ms = int(ms[0]) << 24 | int(ms[1]) << 16 | int(ms[2]) << 8 | int(ms[3])
    return((ms & mask) == (ls & mask))
#enddef

#------------------------------------------------------------------------------

if (platform.uname()[0] != "Linux"): exit(0)

print("Removing iptables configuration")

iptables_commands = [
  "sudo iptables -t raw -D PREROUTING -j lisp",
  "sudo iptables -t raw -F lisp",
  "sudo iptables -t raw -X lisp",
  "sudo ip6tables -t raw -D PREROUTING -j lisp",
  "sudo ip6tables -t raw -F lisp",
  "sudo ip6tables -t raw -X lisp",
  "sudo iptables -D POSTROUTING -t mangle -p tcp -j CHECKSUM --checksum-fill",
  "sudo iptables -D POSTROUTING -t mangle -p udp -j CHECKSUM --checksum-fill",
  "sudo ip6tables -D POSTROUTING -t mangle -p tcp -j CHECKSUM --checksum-fill",
  "sudo ip6tables -D POSTROUTING -t mangle -p udp -j CHECKSUM --checksum-fill",
  "sudo iptables -t nat -F POSTROUTING"
]

for command in iptables_commands:
    os.system(command + " 2> /dev/null")
#endif

#
# Logic below is only executed when we are programing hardware.
#
grep = getoutput("egrep 'program-hardware = yes' ./lisp.config")
if (grep == "" or grep[0] != " "): exit(0)

print("Removing programmed routes and arp entries")

command = 'ip route | egrep vlan4094 | egrep -v "metric 1"'
routes = getoutput(command)
routes = [] if routes == "" else routes.split("\n")
arps = getoutput("arp -n | egrep vlan4094")
arps = [] if arps == "" else arps.split("\n")

for route in routes:
    prefix = route.split(" via")[0]
    os.system("ip route delete {}".format(prefix))
#endfor

for arp in arps:
    address = arp.split(" ")[0]
    os.system("arp -d {}".format(address))
#endfor

#
# Check if there are dynamic-EID prefixes configured. If so, remove the
# configured prefixes as well as all learned more-specifics.
#
grep = "egrep 'eid-prefix = .*\n.*dynamic-eid = yes' lisp.config"
grep = getoutput(grep)
if (grep == ""): exit(0)
if (grep[0] in ["<", ">", "#"]): exit(0)
grep = grep.split("\n")

agg_routes = []
for line in grep:
    if (line.find("eid-prefix") == -1): continue
    route = line.split("= ")[1]
    agg_routes.append(route)
#endfor

print("Found {} dynamic-EID prefixes: {}".format(len(agg_routes), agg_routes))

routes = getoutput("ip route")
routes = routes.split("\n")

agg = None
delete_routes = []
for route in routes:
    prefix = route.split(" ")[0]
    if (prefix in agg_routes): agg = prefix
    if (agg == None): continue

    if (more_specific(agg, prefix)): 
        delete_routes.append(prefix)
    else:
        agg = None
    #endif
#endfor

for route in delete_routes:
    os.system("ip route delete {}".format(route))
#endif
print("Deleted {} dynamic-EIDs:".format(len(delete_routes)))
print("  ", delete_routes)

exit(0)

#------------------------------------------------------------------------------
