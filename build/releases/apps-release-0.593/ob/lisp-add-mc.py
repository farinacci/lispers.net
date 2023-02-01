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
# lisp-add-mc.py
#
# This script is a quick add to a map-cache to any xTR via the lispapi.
#
# Usage: python lisp-add-mc.py "[<iid>]<eid-prefix>" <list-of-rlocs>
# Usage: python lisp-add-mc.py <eid-prefix> <list-of-rlocs>
# Usage: python lisp-add-mc.py help
#
from __future__ import print_function
import sys
import os
from builtins import input
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
IiII1IiiIiI1 = os . getenv ( "LISPAPI_PATH" )
if ( IiII1IiiIiI1 != None ) : sys . path . append ( IiII1IiiIiI1 )
if 40 - 40: oo * OoO0O00
try :
 import lispapi
except :
 print ( "'setenv LISPAPI_PATH' to locate path to lispapi.pyo" )
 exit ( 1 )
 if 2 - 2: ooOO00oOo % oOo0O0Ooo * Ooo00oOo00o . oOoO0oo0OOOo + iiiiIi11i
 if 24 - 24: II11iiII / OoOO0ooOOoo0O + o0000oOoOoO0o * i1I1ii1II1iII % oooO0oo0oOOOO
 if 53 - 53: o0oo0o / Oo + o0oo0o / oooO0oo0oOOOO * OoooooooOO + i1I1ii1II1iII
 if 71 - 71: II11iiII * i1I1ii1II1iII . II11iiII / o0oo0o
 if 14 - 14: iIii1I11I1II1
o0oOoO00o = False
o0oOoO00o = ( "help" in sys . argv or len ( sys . argv ) < 3 )
if ( o0oOoO00o ) :
 print ( 'Usage: python lisp-add-mc.py "[<iid>]<eid-prefix>" <list-of-rlocs>' )
 print ( 'Usage: python lisp-add-mc.py <eid-prefix> <list-of-rlocs>' )
 print ( 'Usage: python lisp-add-mc.py help' )
 exit ( 0 )
 if 43 - 43: o0000oOoOoO0o . iiiiIi11i
 if 27 - 27: ooOO00oOo - O0 . o0oo0o * i1I1ii1II1iII - oOoO0oo0OOOo
 if 15 - 15: oo
 if 90 - 90: oooO0oo0oOOOO * i1IIi / o0000oOoOoO0o . ooOO00oOo * iiiiIi11i
 if 16 - 16: Oo * oooO0oo0oOOOO % OoOO0ooOOoo0O . o0oo0o / oooO0oo0oOOOO % i1I1ii1II1iII
I11 = None
while ( I11 == None ) :
 I11 = input ( "Enter lispers.net system: " )
 if ( I11 == "" ) : I11 = None
 if 23 - 23: oo + i1IIi % OoooooooOO . oooO0oo0oOOOO / Oo
I1I1i1 = None
while ( I1I1i1 == None ) :
 I1I1i1 = input ( "Enter username for {}: " . format ( I11 ) )
 if ( I1I1i1 == "" ) : I1I1i1 = None
 if 18 - 18: iIii1I11I1II1 / OoOO0ooOOoo0O + iiiiIi11i / OoO0O00 - II111iiii - OoOO0ooOOoo0O
I111IiIi = input ( "Enter password for {}: " . format ( I11 ) )
if 32 - 32: oo % ooOO00oOo / II111iiii + ooOO00oOo . II11iiII * o0oo0o
if 62 - 62: i11iIiiIii - II111iiii
if 43 - 43: oOo0O0Ooo - i1IIi + o0oo0o + o0000oOoOoO0o
if 17 - 17: Ooo00oOo00o
o00ooooO0oO = "0"
oOoOo00oOo = sys . argv [ 1 ]
Ooo00O00O0O0O = sys . argv [ 2 : : ]
if 90 - 90: II111iiii + iiiiIi11i / Ooo00oOo00o % II111iiii - O0
if 29 - 29: Ooo00oOo00o / iIii1I11I1II1
if 24 - 24: O0 % Ooo00oOo00o + i1IIi + o0oo0o + oOoO0oo0OOOo
if 70 - 70: OoO0O00 % OoO0O00 . oooO0oo0oOOOO % ooOO00oOo * Ooo00oOo00o % iiiiIi11i
iiI1IiI = oOoOo00oOo . find ( "[" )
if ( iiI1IiI != - 1 ) :
 II = oOoOo00oOo . find ( "]" )
 if ( II == - 1 ) :
  print ( "Invalid EID-prefix format" )
  exit ( 1 )
  if 57 - 57: iiiiIi11i
 o00ooooO0oO = oOoOo00oOo [ iiI1IiI + 1 : II ]
 oOoOo00oOo = oOoOo00oOo [ II + 1 : : ]
 if 14 - 14: OoO0O00 . oo / o0000oOoOoO0o
 if 38 - 38: II111iiii % i11iIiiIii . Oo - II11iiII + o0000oOoOoO0o
print ( "Connect to '{}' via lispers.net API ..." . format ( I11 ) , end = " " )
sys . stdout . flush ( )
if 66 - 66: OoooooooOO * OoooooooOO . II11iiII . i1IIi - II11iiII
o0o00ooo0 = lispapi . api_init ( I11 , I1I1i1 , I111IiIi )
if ( o0o00ooo0 . enable_status != None ) :
 print ( "success" )
else :
 print ( "failed" )
 exit ( 1 )
 if 96 - 96: O0 % iiiiIi11i % iIii1I11I1II1
 if 78 - 78: iIii1I11I1II1 - o0000oOoOoO0o * ooOO00oOo + Ooo00oOo00o + i1I1ii1II1iII + i1I1ii1II1iII
print ( "Add [{}]{} to map-cache, RLOC-set: {} ..." . format ( o00ooooO0oO , oOoOo00oOo , Ooo00O00O0O0O ) )
if 11 - 11: i1I1ii1II1iII - ooOO00oOo % Oo % i1I1ii1II1iII / oOo0O0Ooo - ooOO00oOo
if 74 - 74: i1I1ii1II1iII * O0
if 89 - 89: iiiiIi11i + OoO0O00
if 3 - 3: i1IIi / oo % OoOO0ooOOoo0O * i11iIiiIii / O0 * OoOO0ooOOoo0O
III1ii1iII = o0o00ooo0 . add_itr_map_cache ( o00ooooO0oO , oOoOo00oOo , "" , Ooo00O00O0O0O )
if 54 - 54: oo % II111iiii % II111iiii
if 13 - 13: Ooo00oOo00o . o0000oOoOoO0o
if 19 - 19: OoOO0ooOOoo0O + Oo
if 53 - 53: OoooooooOO . i1IIi
print ( "{}" . format ( "Succeeded" if III1ii1iII == "good" else "Failed" ) )
exit ( 0 )
if 18 - 18: Ooo00oOo00o
if 28 - 28: II11iiII - oooO0oo0oOOOO . oooO0oo0oOOOO + oOo0O0Ooo - OoooooooOO + O0
if 95 - 95: ooOO00oOo % iiiiIi11i . O0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
