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
if 64 - 64: i11iIiiIii
import sys
import os
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
I1IiI = os . getenv ( "LISPAPI_PATH" )
if ( I1IiI != None ) : sys . path . append ( I1IiI )
if 73 - 73: OOooOOo / ii11ii1ii
try :
 import lispapi
except :
 print "'setenv LISPAPI_PATH' to locate path to lispapi.pyo"
 exit ( 1 )
 if 94 - 94: OoOO + OoOO0ooOOoo0O + o0000oOoOoO0o * o00O0oo
 if 97 - 97: oO0o0ooO0 - IIII / o0oOOo0O0Ooo - oO0o0ooO0
 if 21 - 21: Oo0Ooo / II111iiii % OoOO0ooOOoo0O / OoOoOO00 . IIII
 if 100 - 100: i1IIi
 if 27 - 27: o00O0oo * OoooooooOO + OoOO * IIII - i11iIiiIii - o0000oOoOoO0o
IiiiIiI1iIiI1 = False
IiiiIiI1iIiI1 = ( "help" in sys . argv or len ( sys . argv ) < 3 )
if ( IiiiIiI1iIiI1 ) :
 print 'Usage: python lisp-add-mc.py "[<iid>]<eid-prefix>" <list-of-rlocs>'
 print 'Usage: python lisp-add-mc.py <eid-prefix> <list-of-rlocs>'
 print 'Usage: python lisp-add-mc.py help'
 exit ( 0 )
 if 85 - 85: OoO0O00
 if 28 - 28: OoOO0ooOOoo0O
 if 64 - 64: I1ii11iIi11i % OoO0O00
 if 1 - 1: o00O0oo
 if 91 - 91: I1ii11iIi11i * iIii1I11I1II1 . o00O0oo / OoOO0ooOOoo0O
Ooo0 = None
while ( Ooo0 == None ) :
 Ooo0 = raw_input ( "Enter lispers.net system: " )
 if ( Ooo0 == "" ) : Ooo0 = None
 if 89 - 89: OoooooooOO - o00O0oo * IIII
O0I11i1i11i1I = None
while ( O0I11i1i11i1I == None ) :
 O0I11i1i11i1I = raw_input ( "Enter username for {}: " . format ( Ooo0 ) )
 if ( O0I11i1i11i1I == "" ) : O0I11i1i11i1I = None
 if 31 - 31: i11iIiiIii / I1IiiI / IIII * OOooOOo / Oo0Ooo
Oo0o0ooO0oOOO = raw_input ( "Enter password for {}: " . format ( Ooo0 ) )
if 58 - 58: i11iIiiIii % oO0o0ooO0
if 54 - 54: ii11ii1ii % O0 + I1IiiI - o0000oOoOoO0o / OoOO
if 31 - 31: OoO0O00 + II111iiii
if 13 - 13: ii11ii1ii * OOooOOo * I1IiiI
oOOOO = "0"
i11iiII = sys . argv [ 1 ]
I1iiiiI1iII = sys . argv [ 2 : : ]
if 20 - 20: i1IIi + i11iIiiIii - OoOO0ooOOoo0O % OoO0O00 . OoooooooOO
if 96 - 96: i1IIi . OoOoOO00 * ii11ii1ii % IIII
if 60 - 60: OOooOOo * o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoOO * II111iiii + i1IIi
if 64 - 64: OOooOOo - O0 / II111iiii / o0oOOo0O0Ooo / iIii1I11I1II1
IiIIIiI1I1 = i11iiII . find ( "[" )
if ( IiIIIiI1I1 != - 1 ) :
 OoO000 = i11iiII . find ( "]" )
 if ( OoO000 == - 1 ) :
  print "Invalid EID-prefix format"
  exit ( 1 )
  if 42 - 42: OOooOOo - i1IIi / i11iIiiIii + ii11ii1ii + OoO0O00
 oOOOO = i11iiII [ IiIIIiI1I1 + 1 : OoO000 ]
 i11iiII = i11iiII [ OoO000 + 1 : : ]
 if 17 - 17: OOooOOo . Oo0Ooo . I1ii11iIi11i
 if 3 - 3: OoOoOO00 . Oo0Ooo . I1IiiI / OoOO0ooOOoo0O
print "Connect to '{}' via lispers.net API ..." . format ( Ooo0 ) ,
sys . stdout . flush ( )
if 38 - 38: II111iiii % i11iIiiIii . IIII - ii11ii1ii + OoOO0ooOOoo0O
Ooooo0Oo00oO0 = lispapi . api_init ( Ooo0 , O0I11i1i11i1I , Oo0o0ooO0oOOO )
if ( Ooooo0Oo00oO0 . enable_status != None ) :
 print "success"
else :
 print "failed"
 exit ( 1 )
 if 12 - 12: iIii1I11I1II1 * I1IiiI . IIII % OoOO + O0
 if 70 - 70: OoOO0ooOOoo0O . OOooOOo * IIII . OoOO0ooOOoo0O
print "Add [{}]{} to map-cache, RLOC-set: {} ..." . format ( oOOOO , i11iiII , I1iiiiI1iII )
if 35 - 35: o0oOOo0O0Ooo + o0000oOoOoO0o + o0000oOoOoO0o
if 11 - 11: o0000oOoOoO0o - OoO0O00 % IIII % o0000oOoOoO0o / OoOoOO00 - OoO0O00
if 74 - 74: o0000oOoOoO0o * O0
if 89 - 89: OOooOOo + Oo0Ooo
Ii1I = Ooooo0Oo00oO0 . add_itr_map_cache ( oOOOO , i11iiII , "" , I1iiiiI1iII )
if 89 - 89: i11iIiiIii / O0 * OoOoOO00 % ii11ii1ii % OOooOOo
if 50 - 50: i1IIi . I1IiiI % OoOoOO00 - OoO0O00 - OoOO
if 34 - 34: II111iiii / OoooooooOO . o0oOOo0O0Ooo . OoooooooOO % i1IIi
if 49 - 49: o0oOOo0O0Ooo * iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
print "{}" . format ( "Succeeded" if Ii1I == "good" else "Failed" )
exit ( 0 )
if 28 - 28: ii11ii1ii - o00O0oo . o00O0oo + OoOoOO00 - OoooooooOO + O0
if 95 - 95: OoO0O00 % OOooOOo . O0
if 15 - 15: IIII / OoOO0ooOOoo0O . OoOO0ooOOoo0O - i1IIi
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
