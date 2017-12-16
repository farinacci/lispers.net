#
# ping-from-eeid.py - "Ping from a Ephemeral EID"
#
# This script will send IPv6 ping messages to a supplied destination. It will
# create a random ephemeral-EID and assign it to a loopback interface. The
# script will then send a few packets so an attach LISP xTR can discover
# the EID, register it to the mapping system, so the ping destination can
# send ping replies to the ephemeral-EID.
#
# We will loop and create new ephemeral-EIDs. This script is showing how
# draft-farinacci-lisp-eid-anonymity can be used without LISP procotol changes.
#
# Usage: python lisp-from-eeid.py [help] <destination-eid> [loop <num>]
#

import sys
import os
import random
import time
import commands
import platform

usage = "Usage: python lisp-from-eeid.py [help] <destination-eid> [loop <num>]"
dest_eid = ""
loop_count = 3
source_eid = "2001:5:ffff::"
debug = False

#------------------------------------------------------------------------------

#
# bold
#
# Boldface output.
#
def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef

#
# allocate_ephem_eid
#
# Allocate a 80-bit random number. Return in string hex form with a colon
# between each 16-bit entity.
#
def allocate_ephem_eid():
    num = hex(random.randint(0, 0xffffffffffffffffffff))[2:-1]
    ip = ""
    for i in range(0,5,4):
        ip += num[i:i+4] + ":"
    #endfor
    return(ip[0:-1])
#enddef

#------------------------------------------------------------------------------

#
# Get input from command line.
#
dest_eid = sys.argv[1]
if ("help" in sys.argv or len(sys.argv) <= 1 or dest_eid.find(":") == -1):
    print usage
    exit(0)
#endif
if ("loop" in sys.argv):
    index = sys.argv.index("loop") + 1
    if (index >= len(sys.argv)):
        print usage
        exit(10)
    #endif
    loop_count = int(sys.argv[index])
#endif

#
# Use correct command for OS.
#
if (platform.uname()[0] == "Linux"):
    config = "sudo ip addr add {}/128 dev lo"
    deconfig = "sudo ip addr del {}/128 dev lo"
    ping = "ping6 -c 10 -I {} {}"
    lb = "lo"
    lb_grep = "Link encap:"
else:
    config = "sudo ifconfig lo0 inet6 {}/128 alias"
    deconfig = "sudo ifconfig lo0 inet6 {}/128 -alias"
    ping = "ping6 -c 10 -S {} {} | egrep transmitted"
    lb = "lo0"
    lb_grep = "lo0:"
#endif

#
# Start ephemeral-EID allocation loop.
#
e = bold(dest_eid)
for i in range(loop_count):
    local_eid = source_eid + allocate_ephem_eid()
    l = bold(local_eid)
    ifconfig = "ifconfig {} | egrep '{}|{}'".format(lb, lb_grep, local_eid)

    print "Configure {} on interface {} ...".format(l, lb),
    os.system(config.format(local_eid))
    if (debug): print commands.getoutput(ifconfig)
    print "succeeded"

    print "Start ping6 from {} to {} ...".format(l, e)
    os.system(ping.format(local_eid, dest_eid))
    time.sleep(1)

    print "Deconfigure {} on interface {} ...".format(l, lb),
    if (debug): os.system(deconfig.format(local_eid))
    print "succeeded"
    print "------------------------------------------------------------"
#endfor
exit(0)




