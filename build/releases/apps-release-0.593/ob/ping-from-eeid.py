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
from __future__ import print_function
import sys
import os
import random
import time
try :
 from commands import getoutput
except :
 from subprocess import getoutput
 if 64 - 64: i11iIiiIii
import platform
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
o0OO00 = "Usage: python lisp-from-eeid.py [help] <destination-eid> [loop <num>]"
oo = ""
i1iII1IiiIiI1 = 3
iIiiiI1IiI1I1 = "2001:5:ffff::"
o0OoOoOO00 = False
if 27 - 27: OOOo0 / Oo - Ooo00oOo00o . I1IiI
if 73 - 73: OOooOOo / ii11ii1ii
if 94 - 94: OoOO + OoOO0ooOOoo0O + o0000oOoOoO0o * o00O0oo
if 97 - 97: oO0o0ooO0 - IIII / O0oO - o0oO0
if 100 - 100: i11Ii11I1Ii1i
if 67 - 67: iIii1I11I1II1 . OoOO . OoOO0ooOOoo0O / i1IIi % OOOo0 - OOooOOo
if 91 - 91: I1IiI . i11iIiiIii / OoOO0ooOOoo0O % o00O0oo / I1IiI - i11iIiiIii
if 8 - 8: ii11ii1ii * OoOO * iIii1I11I1II1 . O0oO / O0oO % O0oO
def i11 ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 41 - 41: o0oO0 . i11Ii11I1Ii1i * O0oO % i11iIiiIii
 if 74 - 74: IIII * O0oO
 if 82 - 82: iIii1I11I1II1 % O0oO
 if 86 - 86: OOooOOo % Oo
 if 80 - 80: OoooooooOO . Oo
 if 87 - 87: OoOO0ooOOoo0O / i11Ii11I1Ii1i + o0oO0 - i11Ii11I1Ii1i . i11Ii11I1Ii1i / OOOo0
 if 11 - 11: Oo % ii11ii1ii - Ooo00oOo00o
 if 58 - 58: i11iIiiIii % o0oO0
def O0OoOoo00o ( ) :
 iiiI11 = hex ( random . randint ( 0 , 0xffffffffffffffffffff ) ) [ 2 : - 1 ]
 OOooO = ""
 for OOoO00o in range ( 0 , 5 , 4 ) :
  OOooO += iiiI11 [ OOoO00o : OOoO00o + 4 ] + ":"
  if 9 - 9: Oo - oO0o0ooO0 % i1IIi % OoooooooOO
 return ( OOooO [ 0 : - 1 ] )
 if 3 - 3: IIII + O0
 if 42 - 42: o0000oOoOoO0o / i1IIi + i11iIiiIii - oO0o0ooO0
 if 78 - 78: I1IiI
 if 18 - 18: O0 - IIII / IIII + i11Ii11I1Ii1i % i11Ii11I1Ii1i - O0oO
 if 62 - 62: IIII - O0oO - OOooOOo % i1IIi / OoOO0ooOOoo0O
 if 77 - 77: OOOo0 - OOOo0 . Oo / ii11ii1ii
 if 14 - 14: o00O0oo % O0
oo = sys . argv [ 1 ]
if ( "help" in sys . argv or len ( sys . argv ) <= 1 or oo . find ( ":" ) == - 1 ) :
 print ( o0OO00 )
 exit ( 0 )
 if 41 - 41: i1IIi + o0oO0 + o0000oOoOoO0o - O0oO
if ( "loop" in sys . argv ) :
 oO = sys . argv . index ( "loop" ) + 1
 if ( oO >= len ( sys . argv ) ) :
  print ( o0OO00 )
  exit ( 10 )
  if 76 - 76: I1IiI * ii11ii1ii % i1IIi - I1IiI / Oo . o0000oOoOoO0o
 i1iII1IiiIiI1 = int ( sys . argv [ oO ] )
 if 41 - 41: OOooOOo
 if 13 - 13: Ooo00oOo00o . i11iIiiIii - iIii1I11I1II1 - OOooOOo
 if 6 - 6: Oo / Ooo00oOo00o % oO0o0ooO0
 if 84 - 84: i11iIiiIii . ii11ii1ii
 if 100 - 100: oO0o0ooO0 - oO0o0ooO0 - o0oO0
if ( platform . uname ( ) [ 0 ] == "Linux" ) :
 ii1 = "sudo ip addr add {}/128 dev lo"
 o0oO0o00oo = "sudo ip addr del {}/128 dev lo"
 II1i1Ii11Ii11 = "ping6 -c 10 -I {} {}"
 iII11i = "lo"
 O0O00o0OOO0 = "Link encap:"
else :
 ii1 = "sudo ifconfig lo0 inet6 {}/128 alias"
 o0oO0o00oo = "sudo ifconfig lo0 inet6 {}/128 -alias"
 II1i1Ii11Ii11 = "ping6 -c 10 -S {} {} | egrep transmitted"
 iII11i = "lo0"
 O0O00o0OOO0 = "lo0:"
 if 27 - 27: O0 % i1IIi * OoOO0ooOOoo0O + i11iIiiIii + OoooooooOO * i1IIi
 if 80 - 80: o00O0oo * i11iIiiIii / o0oO0
 if 9 - 9: oO0o0ooO0 + OoOO0ooOOoo0O % oO0o0ooO0 + i1IIi . o0000oOoOoO0o
 if 31 - 31: ii11ii1ii + o00O0oo + o00O0oo / OOOo0
 if 26 - 26: OoooooooOO
IiiI11Iiiii = i11 ( oo )
for OOoO00o in range ( i1iII1IiiIiI1 ) :
 ii1I1i1I = iIiiiI1IiI1I1 + O0OoOoo00o ( )
 OOoo0O0 = i11 ( ii1I1i1I )
 iiiIi1i1I = "ifconfig {} | egrep '{}|{}'" . format ( iII11i , O0O00o0OOO0 , ii1I1i1I )
 if 80 - 80: OOooOOo - I1IiI
 print ( "Configure {} on interface {} ..." . format ( OOoo0O0 , iII11i ) , end = " " )
 os . system ( ii1 . format ( ii1I1i1I ) )
 if ( o0OoOoOO00 ) : print ( getoutput ( iiiIi1i1I ) )
 print ( "succeeded" )
 if 87 - 87: OoOO0ooOOoo0O / o00O0oo - i1IIi * o0000oOoOoO0o / OoooooooOO . O0
 print ( "Start ping6 from {} to {} ..." . format ( OOoo0O0 , IiiI11Iiiii ) )
 os . system ( II1i1Ii11Ii11 . format ( ii1I1i1I , oo ) )
 time . sleep ( 1 )
 if 1 - 1: OOOo0 - o00O0oo / o00O0oo
 print ( "Deconfigure {} on interface {} ..." . format ( OOoo0O0 , iII11i ) , end = " " )
 if ( o0OoOoOO00 ) : os . system ( o0oO0o00oo . format ( ii1I1i1I ) )
 print ( "succeeded" )
 print ( "------------------------------------------------------------" )
 if 46 - 46: oO0o0ooO0 * o0000oOoOoO0o - I1IiI * OoOO0ooOOoo0O - o0oO0
exit ( 0 )
if 83 - 83: OoooooooOO
if 31 - 31: OOOo0 - o0000oOoOoO0o . o0oO0 % OOooOOo - O0
if 4 - 4: OOOo0 / i11Ii11I1Ii1i . IIII
if 58 - 58: o0000oOoOoO0o * i11iIiiIii / OOooOOo % o0oO0 - OoOO / OoOO0ooOOoo0O
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
