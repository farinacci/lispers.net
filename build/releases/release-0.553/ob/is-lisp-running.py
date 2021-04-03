#!/usr/bin/env python
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
# is-lisp-running.py
#
# This script checks to see if there is any LISP processes running on the
# local system.
#
# Usage: python -O is-lisp-running.pyo
#
#------------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
import os
try :
 from commands import getoutput
except :
 from subprocess import getoutput
 if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
 if 73 - 73: II111iiii
def IiII1IiiIiI1 ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 40 - 40: oo * OoO0O00
 if 2 - 2: ooOO00oOo % oOo0O0Ooo * Ooo00oOo00o . oOoO0oo0OOOo + iiiiIi11i
 if 24 - 24: II11iiII / OoOO0ooOOoo0O + o0000oOoOoO0o * i1I1ii1II1iII % oooO0oo0oOOOO
 if 53 - 53: o0oo0o / Oo + o0oo0o / oooO0oo0oOOOO * OoooooooOO + i1I1ii1II1iII
 if 71 - 71: II11iiII * i1I1ii1II1iII . II11iiII / o0oo0o
iIi = getoutput ( "cat lisp-version.txt" )
OOoO = getoutput ( "head -1 logs/lisp-core.log" )
if ( OOoO . find ( "version" ) != - 1 ) :
 OOoO = OOoO . split ( "version " ) [ 1 ]
 OOoO = OOoO . split ( "," ) [ 0 ]
 OOoO = ", release {} running" . format ( IiII1IiiIiI1 ( OOoO ) )
else :
 OOoO = None
 if 91 - 91: ooOO00oOo . i11iIiiIii / iiiiIi11i % OoOO0ooOOoo0O / ooOO00oOo - i11iIiiIii
 if 8 - 8: Ooo00oOo00o * oOoO0oo0OOOo * iIii1I11I1II1 . oooO0oo0oOOOO / oooO0oo0oOOOO % oooO0oo0oOOOO
 if 22 - 22: o0000oOoOoO0o . oooO0oo0oOOOO
 if 41 - 41: o0oo0o . Oo * oooO0oo0oOOOO % i11iIiiIii
 if 74 - 74: i1I1ii1II1iII * oooO0oo0oOOOO
oo00o0Oo0oo = "ps auxww | egrep 'lisp-' |" + "egrep -v 'grep|is-lisp-running|tee|pslisp|sudo|log'"
if 20 - 20: Oo * II111iiii
oO0o0o0ooO0oO = getoutput ( oo00o0Oo0oo )
if ( oO0o0o0ooO0oO == None or oO0o0o0ooO0oO == "" ) :
 print ( "No lispers.net code running, release {} installed" . format ( iIi ) )
 exit ( 0 )
 if 52 - 52: II111iiii - i11iIiiIii % o0oo0o
if ( OOoO == None ) : OOoO = ""
if 54 - 54: II11iiII % O0 + oo - i1I1ii1II1iII / OoOO0ooOOoo0O
print ( "--- lispers.net release {} installed{} ---" . format ( IiII1IiiIiI1 ( iIi ) , OOoO ) )
if 31 - 31: ooOO00oOo + II111iiii
i11IiIiiIIIII = oO0o0o0ooO0oO . split ( "\n" )
if 22 - 22: o0000oOoOoO0o * O0 / Ooo00oOo00o
if 64 - 64: o0000oOoOoO0o % i1IIi % OoooooooOO
if 3 - 3: i1I1ii1II1iII + O0
if 42 - 42: II11iiII / i1IIi + i11iIiiIii - o0000oOoOoO0o
if ( os . path . exists ( "/etc/alpine-release" ) ) :
 oo0Ooo0 = "PID" . ljust ( 8 )
 I1I11I1I1I = "TIME" . ljust ( 8 )
 OooO0OO = "Process"
 print ( "{}{}{}" . format ( oo0Ooo0 , I1I11I1I1I , OooO0OO ) )
 for iiiIi in i11IiIiiIIIII :
  IiIIIiI1I1 = iiiIi . split ( )
  oo0Ooo0 = IiIIIiI1I1 [ 0 ] . ljust ( 8 )
  I1I11I1I1I = IiIIIiI1I1 [ 2 ] . ljust ( 8 )
  OooO0OO = IiIIIiI1I1 [ 3 ] if ( IiIIIiI1I1 [ 3 ] . find ( "lisp-ztr" ) != - 1 ) else IiIIIiI1I1 [ - 1 ]
  if ( OooO0OO . isdigit ( ) ) : OooO0OO = IiIIIiI1I1 [ - 2 ] + " " + OooO0OO
  print ( "{}{}{}" . format ( oo0Ooo0 , I1I11I1I1I , OooO0OO ) )
  if 86 - 86: i11iIiiIii + o0000oOoOoO0o + Oo * OoOO0ooOOoo0O + Ooo00oOo00o
 exit ( 0 )
 if 61 - 61: ooOO00oOo / i11iIiiIii
 if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - oOoO0oo0OOOo + i11iIiiIii
 if 65 - 65: oOo0O0Ooo
 if 6 - 6: oo / OoO0O00 % o0000oOoOoO0o
 if 84 - 84: i11iIiiIii . Ooo00oOo00o
oo0Ooo0 = "PID" . ljust ( 8 )
I1I11I1I1I = "%CPU" . ljust ( 8 )
o0O00oooo = "%MEM" . ljust ( 8 )
O00o = "MEM" . ljust ( 8 )
OooO0OO = "Process"
print ( "{}{}{}{}{}" . format ( oo0Ooo0 , I1I11I1I1I , o0O00oooo , O00o , OooO0OO ) )
if 61 - 61: i1I1ii1II1iII . iIii1I11I1II1 * oo . Oo % OoO0O00
for iiiIi in i11IiIiiIIIII :
 IiIIIiI1I1 = iiiIi . split ( )
 oo0Ooo0 = IiIIIiI1I1 [ 1 ] . ljust ( 8 )
 I1I11I1I1I = IiIIIiI1I1 [ 2 ] . ljust ( 8 )
 o0O00oooo = IiIIIiI1I1 [ 3 ] . ljust ( 8 )
 if 72 - 72: II11iiII
 O00o = int ( IiIIIiI1I1 [ 4 ] ) / 1000
 o0Oo00OOOOO = "M"
 if ( O00o >= 1000 ) :
  O00o = round ( float ( O00o ) / 1000 , 1 )
  o0Oo00OOOOO = "G"
  if 85 - 85: Oo . i1I1ii1II1iII - ooOO00oOo % Oo % II111iiii
 O00o = "{}{}" . format ( O00o , o0Oo00OOOOO ) . ljust ( 8 )
 if 81 - 81: ooOO00oOo + II111iiii % i1I1ii1II1iII * O0
 if ( iiiIi . find ( "lisp-core.py" ) != - 1 ) :
  OooO0OO = IiIIIiI1I1 [ - 2 ] + " " + IiIIIiI1I1 [ - 1 ]
 elif ( iiiIi . find ( "lisp-join.py" ) != - 1 ) :
  oOOo0oo = IiIIIiI1I1 [ - 1 ]
  if ( oOOo0oo . count ( "." ) != 3 ) : oOOo0oo = IiIIIiI1I1 [ - 2 ] + " " + oOOo0oo
  OooO0OO = "lisp-join.py " + oOOo0oo
 else :
  OooO0OO = IiIIIiI1I1 [ - 1 ]
  if 80 - 80: OoOO0ooOOoo0O * i11iIiiIii / o0oo0o
  if 9 - 9: o0000oOoOoO0o + iiiiIi11i % o0000oOoOoO0o + i1IIi . II11iiII
 print ( "{}{}{}{}{}" . format ( oo0Ooo0 , I1I11I1I1I , o0O00oooo , O00o , OooO0OO ) )
 if 31 - 31: Ooo00oOo00o + OoOO0ooOOoo0O + OoOO0ooOOoo0O / II111iiii
exit ( 0 )
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
