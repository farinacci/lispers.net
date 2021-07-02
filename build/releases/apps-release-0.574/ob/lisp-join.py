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
 iiiI11 = getoutput ( "ifconfig {} | egrep inet" . format ( intf ) )
 if ( iiiI11 == "" ) :
  print ( "Cannot find interface address for {}" . format ( intf ) )
  return ( None )
  if 91 - 91: o0oOOo0O0Ooo / II111iiii . I1ii11iIi11i + OOooOOo
 iI11 = iiiI11 . split ( ) [ 1 ]
 return ( iI11 )
 if 17 - 17: o0oOOo0O0Ooo
 if 64 - 64: Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
 if 78 - 78: OoO0O00
 if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
 if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
def OoooooOoo ( msocket , group , intf ) :
 msocket . setsockopt ( socket . SOL_SOCKET , socket . SO_REUSEADDR , 1 )
 iI11 = O0OoOoo00o ( intf )
 if ( iI11 == None ) : return ( False )
 if 70 - 70: OoO0O00 . OoO0O00 - OoO0O00 / I1ii11iIi11i * OOooOOo
 OoO000 = socket . inet_aton ( iI11 )
 msocket . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_IF , OoO000 )
 IIiiIiI1 = socket . inet_aton ( group )
 msocket . setsockopt ( socket . IPPROTO_IP , socket . IP_ADD_MEMBERSHIP , IIiiIiI1 + OoO000 )
 return ( True )
 if 41 - 41: OoOoOO00
 if 13 - 13: Oo0Ooo . i11iIiiIii - iIii1I11I1II1 - OoOoOO00
 if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
 if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
 if 100 - 100: Ii1I - Ii1I - I1Ii111
 if 20 - 20: OoooooooOO
 if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
def oo ( msocket , group , intf ) :
 iI11 = O0OoOoo00o ( intf )
 if ( iI11 == None ) : return
 if 68 - 68: I11i + OOooOOo . iIii1I11I1II1 - IiII % iIii1I11I1II1 - ooOoO0o
 OoO000 = socket . inet_aton ( iI11 )
 IIiiIiI1 = socket . inet_aton ( group )
 msocket . setsockopt ( socket . IPPROTO_IP , socket . IP_DROP_MEMBERSHIP , IIiiIiI1 + OoO000 )
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
if ( len ( sys . argv ) < 2 ) :
 print ( "Usage: python lisp-join.py <group> [<interface>] [interval=<secs>]" )
 exit ( 1 )
 if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
Oooo0000 = sys . argv [ 1 ]
i1iiI11I = sys . argv [ 2 ] if len ( sys . argv ) == 3 else "lo"
iiii = sys . argv [ 3 ] if len ( sys . argv ) == 4 else "interval=60"
if 54 - 54: I1ii11iIi11i * OOooOOo
if ( i1iiI11I . find ( "interval=" ) != - 1 ) :
 iiii = i1iiI11I
 i1iiI11I = "lo"
 if 13 - 13: IiII + OoOoOO00 - OoooooooOO + I1Ii111 . iII111i + OoO0O00
iiii = iiii . split ( "=" ) [ 1 ]
iiii = int ( iiii )
if 8 - 8: iIii1I11I1II1 . I1IiiI - iIii1I11I1II1 * Ii1I
if 61 - 61: o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * oO0o / oO0o
if 75 - 75: i1IIi / OoooooooOO - O0 / OoOoOO00 . II111iiii - i1IIi
if 71 - 71: OOooOOo + Ii1I * OOooOOo - OoO0O00 * o0oOOo0O0Ooo
if 65 - 65: O0 % I1IiiI . I1ii11iIi11i % iIii1I11I1II1 / OOooOOo % I1Ii111
ooii11I = os . getpid ( )
Ooo0OO0oOO = "cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
ii11i1 = "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
ooO0oooOoO0 = "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
if 29 - 29: I1ii11iIi11i % I1IiiI + ooOoO0o / o0oOOo0O0Ooo + OOooOOo * o0oOOo0O0Ooo
if 42 - 42: Ii1I + oO0o
if 76 - 76: I1Ii111 - OoO0O00
if 70 - 70: ooOoO0o
signal . signal ( signal . SIGQUIT , ooO0oo0oO0 )
signal . signal ( signal . SIGINT , ooO0oo0oO0 )
if 61 - 61: I1ii11iIi11i . I1ii11iIi11i
if 10 - 10: OoOoOO00 * iII111i . I11i + II111iiii - ooOoO0o * i1IIi
if 56 - 56: o0oOOo0O0Ooo * IiII * II111iiii
if 80 - 80: o0oOOo0O0Ooo * II111iiii % II111iiii
if 59 - 59: iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo - I1IiiI + OOooOOo / I1ii11iIi11i
oo00 = False
if ( getoutput ( Ooo0OO0oOO ) == "1" ) :
 print ( "Enabling ICMP to respond to multicast pings ..." , )
 os . system ( ii11i1 )
 print ( "done" )
 oo00 = True
 if 24 - 24: I11i . iII111i % OOooOOo + ooOoO0o % OoOoOO00
 if 4 - 4: IiII - OoO0O00 * OoOoOO00 - I11i
 if 41 - 41: OoOoOO00 . I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
 if 44 - 44: oO0o
i11 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
print ( "Joining group {} on {}..." . format ( Oooo0000 , i1iiI11I ) , end = " " )
if ( OoooooOoo ( i11 , Oooo0000 , i1iiI11I ) ) :
 print ( "done" )
else :
 print ( "failed" )
 exit ( 1 )
 if 88 - 88: I1Ii111 % Ii1I . II111iiii
 if 38 - 38: o0oOOo0O0Ooo
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
 if 26 - 26: iII111i
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
 if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
 if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
print ( "Using rejoin interval of {} seconds" . format ( iiii ) )
if 91 - 91: oO0o % Oo0Ooo
while ( True ) :
 print ( "Rejoining group {} on {}, pid {} ..." . format ( Oooo0000 , i1iiI11I , ooii11I ) ,
 end = " " )
 oo ( i11 , Oooo0000 , i1iiI11I )
 OoooooOoo ( i11 , Oooo0000 , i1iiI11I )
 print ( "done" )
 time . sleep ( iiii )
 if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
exit ( 0 )
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
