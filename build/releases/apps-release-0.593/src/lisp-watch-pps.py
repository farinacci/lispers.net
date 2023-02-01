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
# lisp-watch-pps.py
#
# This script queries the lipsers.net map-cache and displays the packet-per-
# second stats. It must be run from the lispers.net directory and tunable
# paramters are at the top of this file.
#
# Usage: python -O lisp-watch-pps.py <eid>
#
# It will display something like the following periodically (default 1/2 
# seccond):.
#
# 3.3.3.3/32:  packet-rate: 641 pps,  bit-rate: 7.68 mbps
# 3.3.3.3/32:  packet-rate: 637 pps,  bit-rate: 7.64 mbps
# 3.3.3.3/32:  packet-rate: 631 pps,  bit-rate: 7.57 mbps
# 3.3.3.3/32:  packet-rate: 617 pps,  bit-rate: 7.4 mbps
# 3.3.3.3/32:  packet-rate: 698 pps,  bit-rate: 8.37 mbps
# 3.3.3.3/32:  packet-rate: 706 pps,  bit-rate: 8.47 mbps
# 3.3.3.3/32:  packet-rate: 644 pps,  bit-rate: 7.72 mbps
# 3.3.3.3/32:  packet-rate: 633 pps,  bit-rate: 7.6 mbps
# 3.3.3.3/32:  packet-rate: 626 pps,  bit-rate: 7.5 mbps
# 3.3.3.3/32:  packet-rate: 653 pps,  bit-rate: 7.83 mbps
# 3.3.3.3/32:  packet-rate: 641 pps,  bit-rate: 7.69 mbps
# 3.3.3.3/32:  packet-rate: 635 pps,  bit-rate: 7.62 mbps
# 3.3.3.3/32:  packet-rate: 642 pps,  bit-rate: 7.7 mbps
#------------------------------------------------------------------------------
from __future__ import print_function
import sys
import time
sys.path.append("./")
try:
    import lispapi
except:
    print("Try 'python -O lisp-watch-pps.py <eid>'")
    exit(0)
#endtry
from builtins import input

#------------------------------------------------------------------------------

#
# Set parameters below to your liking.
#
router = "localhost"
username = "root"
password = ""
port = 8080
sleeptime = .5

#------------------------------------------------------------------------------

#
# Get input parameter.
#
if (len(sys.argv) != 2):
    find_eid = input("Enter EID-prefix to watch: ")
else:
    find_eid = sys.argv[1]
#endif
password = input("Enter xTR password: ")

router = lispapi.api_init(router, username, password, port=port)
if (router == None):
    print("Cannot connect to API of router {}".format(router))
    exit(1)
#endif

while (True):
    map_cache = router.get_map_cache()
    if (map_cache == None or len(map_cache) == 0): break
    for mc in map_cache:
        if ("eid-prefix" not in mc): continue

        eid = mc["eid-prefix"]
        group = mc["group-prefix"] if ("group-prefix" in mc) else ""
        if (eid.find(find_eid) == -1): continue

        eid_str = eid if (group == "") else "({}, {})".format(eid, group)

        for rloc in mc["rloc-set"]:
            stats = rloc["stats"].split(",")
            print("eid: {},{},{}".format(eid_str, stats[1], stats[-1]))
        #endfor
    #endfor
    time.sleep(sleeptime)
#endwhile
exit(0)

#------------------------------------------------------------------------------

