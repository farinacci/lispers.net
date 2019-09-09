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
#
# Set parameters below to your liking:
if 64 - 64: i11iIiiIii
OO0o = "localhost"
Oo0Ooo = "root"
O0O0OO0O0O0 = ""
iiiii = 8080
ooo0OO = .5
if 18 - 18: II111iiii . OOO0O / II1Ii / oo * OoO0O00
if 2 - 2: ooOO00oOo % oOo0O0Ooo * Ooo00oOo00o . oOoO0oo0OOOo + iiiiIi11i
if 24 - 24: II11iiII / OoOO0ooOOoo0O + o0000oOoOoO0o * i1I1ii1II1iII % oooO0oo0oOOOO
import sys
import time
sys . path . append ( "./" )
try :
 import lispapi
except :
 print "Try 'python -O lisp-watch-pps.py <eid>'"
 exit ( 0 )
 if 53 - 53: o0oo0o / Oo + OOo00O0Oo0oO / iIi * i1I1ii1II1iII - oo
 if 64 - 64: OOo00O0Oo0oO + o0oo0o
 if 10 - 10: i11iIiiIii / OoOO0ooOOoo0O % OoO0O00
 if 75 - 75: i11iIiiIii + Oo . iiiiIi11i * o0oo0o
 if 59 - 59: OOO0O
 if 31 - 31: Oo % oo * OOO0O / Oo % OoOO0ooOOoo0O + II1Ii
 if 93 - 93: o0oo0o * i11iIiiIii * ooOO00oOo % o0oo0o * o0oo0o * OoO0O00
if ( len ( sys . argv ) != 2 ) :
 o0o0Oo0oooo0 = raw_input ( "Enter EID-prefix to watch: " )
else :
 o0o0Oo0oooo0 = sys . argv [ 1 ]
 if 97 - 97: oOo0O0Ooo - iIi
O0O0OO0O0O0 = raw_input ( "Enter xTR password: " )
if 54 - 54: iIi . iIi / OOO0O / i1I1ii1II1iII + OoOO0ooOOoo0O / iiiiIi11i
OO0o = lispapi . api_init ( OO0o , Oo0Ooo , O0O0OO0O0O0 , port = iiiii )
if ( OO0o == None ) :
 print "Cannot connect to API of router {}" . format ( OO0o )
 exit ( 1 )
 if 39 - 39: i1I1ii1II1iII / OOo00O0Oo0oO . i1I1ii1II1iII - i1I1ii1II1iII
 if 68 - 68: o0000oOoOoO0o . ooOO00oOo / o0oo0o
while ( True ) :
 oOOoo = OO0o . get_map_cache ( )
 if ( oOOoo == None or len ( oOOoo ) == 0 ) : break
 for I1IiIiiIII in oOOoo :
  if ( I1IiIiiIII . has_key ( "eid-prefix" ) == False ) : continue
  if 47 - 47: oOoO0oo0OOOo / oooO0oo0oOOOO * II1Ii
  II111iiiiII = I1IiIiiIII [ "eid-prefix" ]
  oOoOo00oOo = I1IiIiiIII [ "group-prefix" ] if I1IiIiiIII . has_key ( "group-prefix" ) else ""
  if ( II111iiiiII . find ( o0o0Oo0oooo0 ) == - 1 ) : continue
  if 96 - 96: oo . oOoO0oo0OOOo * o0000oOoOoO0o % iIi
  OO0O0O00OooO = II111iiiiII if ( oOoOo00oOo == "" ) else "({}, {})" . format ( II111iiiiII , oOoOo00oOo )
  if 77 - 77: OoO0O00 - OoO0O00 . ooOO00oOo / iiiiIi11i
  for i1iIIIiI1I in I1IiIiiIII [ "rloc-set" ] :
   OOoO000O0OO = i1iIIIiI1I [ "stats" ] . split ( "," )
   print "eid: {},{},{}" . format ( OO0O0O00OooO , OOoO000O0OO [ 1 ] , OOoO000O0OO [ - 1 ] )
   if 23 - 23: i11iIiiIii + ooOO00oOo
   if 68 - 68: oOoO0oo0OOOo . OoOO0ooOOoo0O . i11iIiiIii
 time . sleep ( ooo0OO )
 if 40 - 40: OoOO0ooOOoo0O . oOoO0oo0OOOo . oOo0O0Ooo . oo
exit ( 0 )
if 33 - 33: oooO0oo0oOOOO + OoO0O00 % i11iIiiIii . iIi - ooOO00oOo
if 66 - 66: oooO0oo0oOOOO - II1Ii * II1Ii . o0000oOoOoO0o . II11iiII
if 22 - 22: II1Ii % i1I1ii1II1iII - o0oo0o . OOO0O * i11iIiiIii
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
