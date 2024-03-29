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
# lisp-join.py
#
# This proggram is part of the lispers.net apps release. It is not built
# with the lispers.net LISP subsystem and the source is provided publicly.
#
# Open a socket to join a multicast group. There is no I/O that happens on
# the socket used in this program. This is meant to be used with multicast
# ping. So we need to allow the ICMP server to respond to multicast pings.
#
# This program modifies file /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts.
#
# Usage: python lisp-join.py <group> [<interface>] [interval=<secs>]
#
# When an overlay multicast group is joined an <interface> is not required.
# So for example, say an overlay multicast group 224.1.1.1 is being joined
# and an RLOC for 239.1.1.1 is used where the underlay is multicast capable.
# Then the following program innovationsn are required:
#
#   python lisp-join.py 224.1.1.1
#   python lisp-join.py 239.1.1.1 eth0
#
# And when 224.1.1.1 is joined, the locally running xTR will join (*,G) by
# registering (0.0.0.0/0, 224.1.1.1) to the mapping system. When the RLE is
# 239.1.1.1, that is the RLOC that is registered. So for this local xTR to
# receive underlay multicast, it needs to do the interface based join above.
#
# This program should be called from inside of ./RL. And note if you want
# an encapsulator to send on a specific port, then the following is required
# in ./RL:
#
#   ip route add 239.1.1.1 dev eth0
#
from __future__ import print_function
import socket
import time
import sys
try:
    from commands import getoutput
except:
    from subprocess import getoutput
#endtry    
import os
import signal

#------------------------------------------------------------------------------

#
# cleanup
#
# This is a signal handler that cleans up socket so the group can be left.
#
def cleanup(signum, frame):
    global reset
    
    if (reset):
        print("Returning value to icmp_echo_ignore_broadcasts ...", end="' ")
        os.system(disable_icmp)
        print("done")
    #endif

    print("Leaving group {} ...".format(group), end=" ")
    msocket.close()
    print("done")
    exit(0)
#enddef

#
# get_local_ip
#
# Get local IP address of interface we are joining. socket.setsockopt()
# requires it.
#
def get_local_ip(intf):
    out = getoutput('sudo ifconfig {} | egrep "inet "'.format(intf))
    if (out == "" or out.find("inet ") == -1): return(None)
    intf_addr = out.split()[1]

    #
    # In some OSes, second field is "addr:100.127.27.76".
    #
    intf_addr = intf_addr.split(":")[-1]
    return(intf_addr)
#enddef    

#
# join_socket
#
# Join group address on interface with 3 setsockopt() calls.
#
def join_socket(msocket, group, intf):
    msocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    intf_addr = get_local_ip(intf)
    if (intf_addr == None): return(False)

    i = socket.inet_aton(intf_addr)
    msocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, i)
    g = socket.inet_aton(group)
    msocket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, g + i)
    return(True)
#enddef

#
# leave_socket
#
# Leave group on interface.
#
def leave_socket(msocket, group, intf):
    intf_addr = get_local_ip(intf)
    if (intf_addr == None): return

    i = socket.inet_aton(intf_addr)
    g = socket.inet_aton(group)
    msocket.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, g + i)
#enddef    

#------------------------------------------------------------------------------

#
# Get group and interface parameters from command line.
#
if (len(sys.argv) < 2):
    print("Usage: python lisp-join.py <group> [<interface>] [interval=<secs>]")
    exit(1)
#endif    
group = sys.argv[1]
intf = sys.argv[2] if len(sys.argv) == 3 else "lo"
rejoin_interval = sys.argv[3] if len(sys.argv) == 4 else "interval=60"

if (intf.find("interval=") != -1):
    rejoin_interval = intf
    intf = "lo"
#endif
rejoin_interval = rejoin_interval.split("=")[1]
rejoin_interval = int(rejoin_interval)

#
# If we are using ping to test group connectivity, make sure kernel allows
# the ICMP server to respond to broadcast/multicast ping requests.
#
mypid = os.getpid()
cat = "cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
enable_icmp = "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
disable_icmp = "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"

#
# Signal handler to leave group when control-C is typed by user.
#
signal.signal(signal.SIGQUIT, cleanup)
signal.signal(signal.SIGINT, cleanup)

#
# Check if ICMP is ignoring multicast pings. If so, enable it and remember
# to set it back to its original setting.
#
reset = False
if (getoutput(cat) == "1"):
    print("Enabling ICMP to respond to multicast pings ...",)
    os.system(enable_icmp)
    print("done")
    reset = True
#endif

#
# Open socket and join group.
#
msocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("Joining group {} on {} ...".format(group, intf), end=" ")
if (join_socket(msocket, group, intf)):
    print("done")
else:
    print("failed")
    exit(1)
#endif

#
# The kernel keeps us joined but periodic IGMP reports are not set unless there
# is a IGMP querier on the LAN. Assume there isn't one in a virtual/container
# environment.
#
print("Using rejoin interval of {} seconds".format(rejoin_interval))

while (True):
    print("Rejoining group {} on {}, pid {} ...".format(group, intf, mypid),
        end=" ")
    leave_socket(msocket, group, intf)
    join_socket(msocket, group, intf)
    print("done")
    time.sleep(rejoin_interval)
#endwhile
exit(0)
