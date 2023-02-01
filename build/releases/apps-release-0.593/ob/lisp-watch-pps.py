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
sys . path . append ( "./" )
try :
 import lispapi
except :
 print ( "Try 'python -O lisp-watch-pps.py <eid>'" )
 exit ( 0 )
 if 64 - 64: i11iIiiIii
from builtins import input
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
II1iII1i = "localhost"
oO0oIIII = "root"
Oo0oO0oo0oO00 = ""
i111I = 8080
II1Ii1iI1i = .5
if 12 - 12: I1ii11iIi11i
if 28 - 28: i1IIi % II111iiii - I1Ii111 + iII111i
if 10 - 10: i11iIiiIii / oO0o % II111iiii
if 75 - 75: i11iIiiIii + IiII . o0oOOo0O0Ooo * iII111i
if 59 - 59: iIii1I11I1II1
if 31 - 31: IiII % i1IIi * iIii1I11I1II1 / IiII % oO0o + OoooooooOO
if ( len ( sys . argv ) != 2 ) :
 O00o0o0000o0o = input ( "Enter EID-prefix to watch: " )
else :
 O00o0o0000o0o = sys . argv [ 1 ]
 if 88 - 88: iII111i / I1IiiI + i1IIi % OoooooooOO . IiII / ooOoO0o
Oo0oO0oo0oO00 = input ( "Enter xTR password: " )
if 28 - 28: ooOoO0o + I1Ii111 - ooOoO0o . OoooooooOO
II1iII1i = lispapi . api_init ( II1iII1i , oO0oIIII , Oo0oO0oo0oO00 , port = i111I )
if ( II1iII1i == None ) :
 print ( "Cannot connect to API of router {}" . format ( II1iII1i ) )
 exit ( 1 )
 if 97 - 97: OoO0O00 . I11i
 if 32 - 32: Oo0Ooo - II111iiii - i11iIiiIii % I1Ii111
while ( True ) :
 O0OoOoo00o = II1iII1i . get_map_cache ( )
 if ( O0OoOoo00o == None or len ( O0OoOoo00o ) == 0 ) : break
 for iiiI11 in O0OoOoo00o :
  if ( "eid-prefix" not in iiiI11 ) : continue
  if 91 - 91: o0oOOo0O0Ooo / II111iiii . I1ii11iIi11i + OOooOOo
  iI11 = iiiI11 [ "eid-prefix" ]
  iII111ii = iiiI11 [ "group-prefix" ] if ( "group-prefix" in iiiI11 ) else ""
  if ( iI11 . find ( O00o0o0000o0o ) == - 1 ) : continue
  if 3 - 3: iII111i + O0
  I1Ii = iI11 if ( iII111ii == "" ) else "({}, {})" . format ( iI11 , iII111ii )
  if 66 - 66: Ii1I
  for oo0Ooo0 in iiiI11 [ "rloc-set" ] :
   I1I11I1I1I = oo0Ooo0 [ "stats" ] . split ( "," )
   print ( "eid: {},{},{}" . format ( I1Ii , I1I11I1I1I [ 1 ] , I1I11I1I1I [ - 1 ] ) )
   if 90 - 90: II111iiii + oO0o / o0oOOo0O0Ooo % II111iiii - O0
   if 29 - 29: o0oOOo0O0Ooo / iIii1I11I1II1
 time . sleep ( II1Ii1iI1i )
 if 24 - 24: O0 % o0oOOo0O0Ooo + i1IIi + I1Ii111 + I1ii11iIi11i
exit ( 0 )
if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
if 23 - 23: i11iIiiIii + I1IiiI
if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
