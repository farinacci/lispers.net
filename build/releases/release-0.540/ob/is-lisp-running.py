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
import commands
import os
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
def o0OO00 ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 78 - 78: i11i . oOooOoO0Oo0O
 if 10 - 10: IIiI1I11i11
 if 54 - 54: i11iIi1 - oOo0O0Ooo
 if 2 - 2: o0 * i1 * ii1IiI1i % OOooOOo / I11i / Ii1I
 if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
i1I1ii1II1iII = commands . getoutput ( "cat lisp-version.txt" )
oooO0oo0oOOOO = commands . getoutput ( "head -1 logs/lisp-core.log" )
if ( oooO0oo0oOOOO . find ( "version" ) != - 1 ) :
 oooO0oo0oOOOO = oooO0oo0oOOOO . split ( "version " ) [ 1 ]
 oooO0oo0oOOOO = oooO0oo0oOOOO . split ( "," ) [ 0 ]
 oooO0oo0oOOOO = ", release {} running" . format ( o0OO00 ( oooO0oo0oOOOO ) )
else :
 oooO0oo0oOOOO = None
 if 53 - 53: I11i / IIiI1I11i11 / i11i % Ii1I / oOo0O0Ooo . ooOoO0o
 if 100 - 100: i1IIi
 if 27 - 27: IiII * OoooooooOO + I11i * ooOoO0o - i11iIiiIii - iII111i
 if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . i11i - ii1IiI1i
 if 72 - 72: i11i - oOo0O0Ooo
OOo = "ps auxww | egrep 'lisp-' |" + "egrep -v 'grep|is-lisp-running|tee|pslisp|sudo|log'"
if 1 - 1: i11i - i1 % i11iIiiIii + IiII . I1Ii111
Oooo0000 = commands . getoutput ( OOo )
if ( Oooo0000 == None or Oooo0000 == "" ) :
 print "No lispers.net code running, release {} installed" . format ( i1I1ii1II1iII )
 exit ( 0 )
 if 22 - 22: Ii1I . IiII
if ( oooO0oo0oOOOO == None ) : oooO0oo0oOOOO = ""
if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
print "--- lispers.net release {} installed{} ---" . format ( o0OO00 ( i1I1ii1II1iII ) , oooO0oo0oOOOO )
if 74 - 74: iII111i * IiII
oo00o0Oo0oo = Oooo0000 . split ( "\n" )
if 20 - 20: ooOoO0o * i11i
if 65 - 65: o0 * iIii1I11I1II1 * ooOoO0o
if 18 - 18: iIii1I11I1II1 / I11i + ii1IiI1i / IIiI1I11i11 - i11i - I11i
if 1 - 1: I11i - OOooOOo % O0 + oOooOoO0Oo0O - iII111i / I11i
if ( os . path . exists ( "/etc/alpine-release" ) ) :
 iIiiI1 = "PID" . ljust ( 8 )
 OoOooOOOO = "TIME" . ljust ( 8 )
 i11iiII = "Process"
 print "{}{}{}" . format ( iIiiI1 , OoOooOOOO , i11iiII )
 for I1iiiiI1iII in oo00o0Oo0oo :
  IiIi11i = I1iiiiI1iII . split ( )
  iIiiI1 = IiIi11i [ 0 ] . ljust ( 8 )
  OoOooOOOO = IiIi11i [ 2 ] . ljust ( 8 )
  i11iiII = IiIi11i [ 3 ] if ( IiIi11i [ 3 ] . find ( "lisp-ztr" ) != - 1 ) else IiIi11i [ - 1 ]
  if ( i11iiII . isdigit ( ) ) : i11iiII = IiIi11i [ - 2 ] + " " + i11iiII
  print "{}{}{}" . format ( iIiiI1 , OoOooOOOO , i11iiII )
  if 43 - 43: o0 * O0
 exit ( 0 )
 if 25 - 25: iII111i + ooOoO0o % ooOoO0o - ii1IiI1i * o0 % iII111i
 if 55 - 55: oOo0O0Ooo % i1IIi / Ii1I - ii1IiI1i - O0 / i11i
 if 28 - 28: iIii1I11I1II1 - i1IIi
 if 70 - 70: i11iIi1 . i11iIi1 - i11iIi1 / i1 * OOooOOo
 if 86 - 86: i11iIiiIii + Ii1I + ooOoO0o * I11i + o0
iIiiI1 = "PID" . ljust ( 8 )
OoOooOOOO = "%CPU" . ljust ( 8 )
oOoO = "%MEM" . ljust ( 8 )
oOo = "MEM" . ljust ( 8 )
i11iiII = "Process"
print "{}{}{}{}{}" . format ( iIiiI1 , OoOooOOOO , oOoO , oOo , i11iiII )
if 63 - 63: IIiI1I11i11
for I1iiiiI1iII in oo00o0Oo0oo :
 IiIi11i = I1iiiiI1iII . split ( )
 iIiiI1 = IiIi11i [ 1 ] . ljust ( 8 )
 OoOooOOOO = IiIi11i [ 2 ] . ljust ( 8 )
 oOoO = IiIi11i [ 3 ] . ljust ( 8 )
 if 57 - 57: ii1IiI1i
 oOo = int ( IiIi11i [ 4 ] ) / 1000
 iI = "M"
 if ( oOo >= 1000 ) :
  oOo = round ( float ( oOo ) / 1000 , 1 )
  iI = "G"
  if 22 - 22: IIiI1I11i11 % Ii1I
 oOo = "{}{}" . format ( oOo , iI ) . ljust ( 8 )
 if 84 - 84: i11iIiiIii . o0
 if ( I1iiiiI1iII . find ( "lisp-core.py" ) != - 1 ) :
  i11iiII = IiIi11i [ - 2 ] + " " + IiIi11i [ - 1 ]
 elif ( I1iiiiI1iII . find ( "lisp-join.py" ) != - 1 ) :
  o0O00oooo = IiIi11i [ - 1 ]
  if ( o0O00oooo . count ( "." ) != 3 ) : o0O00oooo = IiIi11i [ - 2 ] + " " + o0O00oooo
  i11iiII = "lisp-join.py " + o0O00oooo
 else :
  i11iiII = IiIi11i [ - 1 ]
  if 67 - 67: OOooOOo / OoooooooOO % I11i - iIii1I11I1II1
  if 82 - 82: i11iIiiIii . OOooOOo / IIiI1I11i11 * O0 % ii1IiI1i % iIii1I11I1II1
 print "{}{}{}{}{}" . format ( iIiiI1 , OoOooOOOO , oOoO , oOo , i11iiII )
 if 78 - 78: iIii1I11I1II1 - Ii1I * i11iIi1 + o0 + iII111i + iII111i
exit ( 0 )
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
