#!/usr/bin/python
# 
# packet-rate
#
# Usage: python packet-rate.py [<mc-parms>]
#
# Take output from lisp-mc.py and only display EIDs that are currently moving
# packets.
#
#------------------------------------------------------------------------------
from __future__ import print_function
try:
    from commands import getoutput
except:
    from subprocess import getoutput
#endtry    
import sys

mc_parms = ""

if ("help" in sys.argv):
    print("Usage: python packet-rate.py [<mc-parms>]")
    exit(0)
#endif

if (len(sys.argv) > 1):
    mc_parms = " ".join(sys.argv[1::])
#endif

lines = getoutput("./mc {}".format(mc_parms))
lines = lines.split("\n")

entries = []
for line in lines:
    if (line.find("LISP Map-Cache") != -1): print("\n{}\n".format(line))
    if (line.find("EID") != -1): entries.append(line)
    if (line.find("RLOC") != -1): entries.append(line)
    if (line.find("packet-count") != -1): entries.append(line)
#endfor

for line in entries:
    if (line.find("EID") != -1):
        eid = line
        continue
    #endif
    if (line.find("RLOC") != -1):
        rloc = line
        continue
    #endif
    if (line.find("packet-count: 0,") != -1): continue

    rloc = rloc.split(", ")[0]
    l = "{}, {}".format(rloc, line.strip())
    print(eid, "\n", l, "\n")
#endfor
    
exit(0)

#------------------------------------------------------------------------------
                  
