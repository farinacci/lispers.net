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
try :
 from commands import getoutput
except :
 from subprocess import getoutput
 if 64 - 64: i11iIiiIii
import os
import signal
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
def ooO0oo0oO0 ( signum , frame ) :
 global oo00
 if 88 - 88: iII111i . oO0o % ooOoO0o
 if ( oo00 ) :
  print ( "Returning value to icmp_echo_ignore_broadcasts ..." , end = "' " )
  os . system ( ooO0oooOoO0 )
  print ( "done" )
  if 21 - 21: OoOoOO00 / iII111i * OoO0O00 . II111iiii
  if 1 - 1: II111iiii - I1ii11iIi11i % i11iIiiIii + IiII . I1Ii111
 print ( "Leaving group {} ..." . format ( Oooo0000 ) , end = " " )
 i11 . close ( )
 print ( "done" )
 exit ( 0 )
 if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
 if 74 - 74: iII111i * IiII
 if 82 - 82: iIii1I11I1II1 % IiII
 if 86 - 86: OoOoOO00 % I1IiiI
 if 80 - 80: OoooooooOO . I1IiiI
 if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
 if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
 if 58 - 58: i11iIiiIii % I1Ii111
def O0OoOoo00o ( intf ) :
 iiiI11 = getoutput ( 'sudo ifconfig {} | egrep "inet "' . format ( intf ) )
 if ( iiiI11 == "" or iiiI11 . find ( "inet " ) == - 1 ) : return ( None )
 OOooO = iiiI11 . split ( ) [ 1 ]
 if 58 - 58: OoO0O00 + OoOoOO00 / Ii1I * OoooooooOO
 if 9 - 9: I1IiiI - Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
 OOooO = OOooO . split ( ":" ) [ - 1 ]
 return ( OOooO )
 if 78 - 78: OoO0O00
 if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
 if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
 if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
 if 14 - 14: I11i % O0
 if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
 if 77 - 77: Oo0Ooo . IiII % ooOoO0o
def IIiiIiI1 ( msocket , group , intf ) :
 msocket . setsockopt ( socket . SOL_SOCKET , socket . SO_REUSEADDR , 1 )
 OOooO = O0OoOoo00o ( intf )
 if ( OOooO == None ) : return ( False )
 if 41 - 41: OoOoOO00
 II = socket . inet_aton ( OOooO )
 msocket . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_IF , II )
 ooOoOoo0O = socket . inet_aton ( group )
 msocket . setsockopt ( socket . IPPROTO_IP , socket . IP_ADD_MEMBERSHIP , ooOoOoo0O + II )
 return ( True )
 if 76 - 76: O0 / o0oOOo0O0Ooo . I1IiiI * Ii1I - OOooOOo
 if 76 - 76: i11iIiiIii / iIii1I11I1II1 . I1ii11iIi11i % OOooOOo / OoooooooOO % oO0o
 if 75 - 75: iII111i
 if 97 - 97: i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 if 61 - 61: ooOoO0o
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
def oO00O00o0OOO0 ( msocket , group , intf ) :
 OOooO = O0OoOoo00o ( intf )
 if ( OOooO == None ) : return
 if 27 - 27: O0 % i1IIi * oO0o + i11iIiiIii + OoooooooOO * i1IIi
 II = socket . inet_aton ( OOooO )
 ooOoOoo0O = socket . inet_aton ( group )
 msocket . setsockopt ( socket . IPPROTO_IP , socket . IP_DROP_MEMBERSHIP , ooOoOoo0O + II )
 if 80 - 80: I11i * i11iIiiIii / I1Ii111
 if 9 - 9: Ii1I + oO0o % Ii1I + i1IIi . OOooOOo
 if 31 - 31: o0oOOo0O0Ooo + I11i + I11i / II111iiii
 if 26 - 26: OoooooooOO
 if 12 - 12: OoooooooOO % OoOoOO00 / ooOoO0o % o0oOOo0O0Ooo
 if 29 - 29: OoooooooOO
 if 23 - 23: o0oOOo0O0Ooo . II111iiii
if ( len ( sys . argv ) < 2 ) :
 print ( "Usage: python lisp-join.py <group> [<interface>] [interval=<secs>]" )
 exit ( 1 )
 if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
Oooo0000 = sys . argv [ 1 ]
i1 = sys . argv [ 2 ] if len ( sys . argv ) == 3 else "lo"
IiIiiI = sys . argv [ 3 ] if len ( sys . argv ) == 4 else "interval=60"
if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
if ( i1 . find ( "interval=" ) != - 1 ) :
 IiIiiI = i1
 i1 = "lo"
 if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
IiIiiI = IiIiiI . split ( "=" ) [ 1 ]
IiIiiI = int ( IiIiiI )
if 8 - 8: OoOoOO00
if 60 - 60: I11i / I11i
if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
if 83 - 83: OoooooooOO
if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
iii11 = os . getpid ( )
O0oo0OO0oOOOo = "cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
i1i1i11IIi = "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
ooO0oooOoO0 = "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
signal . signal ( signal . SIGQUIT , ooO0oo0oO0 )
signal . signal ( signal . SIGINT , ooO0oo0oO0 )
if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
if 58 - 58: i11iIiiIii % I11i
if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
oo00 = False
if ( getoutput ( O0oo0OO0oOOOo ) == "1" ) :
 print ( "Enabling ICMP to respond to multicast pings ..." , )
 os . system ( i1i1i11IIi )
 print ( "done" )
 oo00 = True
 if 16 - 16: I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
 if 44 - 44: oO0o
 if 88 - 88: I1Ii111 % Ii1I . II111iiii
 if 38 - 38: o0oOOo0O0Ooo
i11 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
print ( "Joining group {} on {} ..." . format ( Oooo0000 , i1 ) , end = " " )
if ( IIiiIiI1 ( i11 , Oooo0000 , i1 ) ) :
 print ( "done" )
else :
 print ( "failed" )
 exit ( 1 )
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
 if 26 - 26: iII111i
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
 if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
 if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
 if 91 - 91: oO0o % Oo0Ooo
 if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
print ( "Using rejoin interval of {} seconds" . format ( IiIiiI ) )
if 31 - 31: I11i - II111iiii . I11i
while ( True ) :
 print ( "Rejoining group {} on {}, pid {} ..." . format ( Oooo0000 , i1 , iii11 ) ,
 end = " " )
 oO00O00o0OOO0 ( i11 , Oooo0000 , i1 )
 IIiiIiI1 ( i11 , Oooo0000 , i1 )
 print ( "done" )
 time . sleep ( IiIiiI )
 if 18 - 18: o0oOOo0O0Ooo
exit ( 0 )
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
