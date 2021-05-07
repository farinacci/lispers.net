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
from __future__ import print_function
from __future__ import division
from future import standard_library
standard_library . install_aliases ( )
from past . utils import old_div
from subprocess import getoutput
import os
if 64 - 64: i11iIiiIii
def OO0o ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 81 - 81: Iii1I1 + OO0O0O % iiiii % ii1I - ooO0OO000o
 if 4 - 4: IiII1IiiIiI1 / iIiiiI1IiI1I1
 if 87 - 87: OoOoOO00
 if 27 - 27: OOOo0 / Oo - Ooo00oOo00o . I1IiI
 if 73 - 73: OOooOOo / ii11ii1ii
O00ooOO = getoutput ( "cat lisp-version.txt" )
I1iII1iiII = getoutput ( "head -1 logs/lisp-core.log" )
if ( I1iII1iiII . find ( "version" ) != - 1 ) :
 I1iII1iiII = I1iII1iiII . split ( "version " ) [ 1 ]
 I1iII1iiII = I1iII1iiII . split ( "," ) [ 0 ]
 I1iII1iiII = ", release {} running" . format ( OO0o ( I1iII1iiII ) )
else :
 I1iII1iiII = None
 if 28 - 28: Ii11111i * iiI1i1
 if 46 - 46: Ooo0OO0oOO * Ii * Oo0o
 if 60 - 60: Ooo00oOo00o + Ii - ii11ii1ii / ii1I
 if 40 - 40: IiII1IiiIiI1 / Iii1I1 % Oo0o + Iii1I1 * ii1I
 if 27 - 27: Ooo0OO0oOO * iiiii + ii11ii1ii * Oo0o - i11iIiiIii - iiI1i1
IiiiIiI1iIiI1 = "ps auxww | egrep 'lisp-' |" + "egrep -v 'grep|is-lisp-running|tee|pslisp|sudo|log'"
if 85 - 85: OoOoOO00
iIi1IIii11I = getoutput ( IiiiIiI1iIiI1 )
if ( iIi1IIii11I == None or iIi1IIii11I == "" ) :
 print ( "No lispers.net code running, release {} installed" . format ( O00ooOO ) )
 exit ( 0 )
 if 84 - 84: OO0O0O . Ooo0OO0oOO / Ooo0OO0oOO % Ooo0OO0oOO
if ( I1iII1iiII == None ) : I1iII1iiII = ""
if 22 - 22: Ii11111i . Ooo0OO0oOO
print ( "--- lispers.net release {} installed{} ---" . format ( OO0o ( O00ooOO ) , I1iII1iiII ) )
if 41 - 41: Ii . Oo0o * Ooo0OO0oOO % i11iIiiIii
o000o0o00o0Oo = iIi1IIii11I . split ( "\n" )
if 80 - 80: iiiii . IiII1IiiIiI1
if 87 - 87: I1IiI / Oo0o + Ii - Oo0o . Oo0o / ooO0OO000o
if 11 - 11: IiII1IiiIiI1 % Oo - iIiiiI1IiI1I1
if 58 - 58: i11iIiiIii % Ii
if ( os . path . exists ( "/etc/alpine-release" ) ) :
 O0OoOoo00o = "PID" . ljust ( 8 )
 iiiI11 = "TIME" . ljust ( 8 )
 OOooO = "Process"
 print ( "{}{}{}" . format ( O0OoOoo00o , iiiI11 , OOooO ) )
 for OOoO00o in o000o0o00o0Oo :
  II111iiii = OOoO00o . split ( )
  O0OoOoo00o = II111iiii [ 0 ] . ljust ( 8 )
  iiiI11 = II111iiii [ 2 ] . ljust ( 8 )
  OOooO = II111iiii [ 3 ] if ( II111iiii [ 3 ] . find ( "lisp-ztr" ) != - 1 ) else II111iiii [ - 1 ]
  if ( OOooO . isdigit ( ) ) : OOooO = II111iiii [ - 2 ] + " " + OOooO
  print ( "{}{}{}" . format ( O0OoOoo00o , iiiI11 , OOooO ) )
  if 48 - 48: OoOoOO00 . iiiii - OOOo0 % OOooOOo / Ii11111i . Ii11111i
 exit ( 0 )
 if 11 - 11: Oo0o / Iii1I1 - ii1I
 if 85 - 85: OOooOOo % Ooo00oOo00o * Oo0o
 if 90 - 90: Oo % Oo % ii11ii1ii * OOOo0
 if 26 - 26: Ii11111i - Oo
 if 63 - 63: ooO0OO000o . ooO0OO000o
O0OoOoo00o = "PID" . ljust ( 8 )
iiiI11 = "%CPU" . ljust ( 8 )
Ii1 = "%MEM" . ljust ( 8 )
oOOoO0 = "MEM" . ljust ( 8 )
OOooO = "Process"
print ( "{}{}{}{}{}" . format ( O0OoOoo00o , iiiI11 , Ii1 , oOOoO0 , OOooO ) )
if 59 - 59: Ii11111i * i11iIiiIii + Ii11111i + Oo0o * OoOoOO00
for OOoO00o in o000o0o00o0Oo :
 II111iiii = OOoO00o . split ( )
 O0OoOoo00o = II111iiii [ 1 ] . ljust ( 8 )
 iiiI11 = II111iiii [ 2 ] . ljust ( 8 )
 Ii1 = II111iiii [ 3 ] . ljust ( 8 )
 if 75 - 75: ii1I - OoOoOO00 / IiII1IiiIiI1 . OOooOOo
 oOOoO0 = old_div ( int ( II111iiii [ 4 ] ) , 1000 )
 iiIiIIi = "M"
 if ( oOOoO0 >= 1000 ) :
  oOOoO0 = round ( float ( oOOoO0 ) / 1000 , 1 )
  iiIiIIi = "G"
  if 65 - 65: OOOo0
 oOOoO0 = "{}{}" . format ( oOOoO0 , iiIiIIi ) . ljust ( 8 )
 if 6 - 6: IiII1IiiIiI1 / iIiiiI1IiI1I1 % Ii11111i
 if ( OOoO00o . find ( "lisp-core.py" ) != - 1 ) :
  OOooO = II111iiii [ - 2 ] + " " + II111iiii [ - 1 ]
 elif ( OOoO00o . find ( "lisp-join.py" ) != - 1 ) :
  oo = II111iiii [ - 1 ]
  if ( oo . count ( "." ) != 3 ) : oo = II111iiii [ - 2 ] + " " + oo
  OOooO = "lisp-join.py " + oo
 else :
  OOooO = II111iiii [ - 1 ]
  if 54 - 54: OOooOOo + OOooOOo % Ii % i11iIiiIii / OO0O0O . OOooOOo
  if 57 - 57: Ii11111i % iiiii
 print ( "{}{}{}{}{}" . format ( O0OoOoo00o , iiiI11 , Ii1 , oOOoO0 , OOooO ) )
 if 61 - 61: iiI1i1 . OO0O0O * IiII1IiiIiI1 . Oo0o % iIiiiI1IiI1I1
exit ( 0 )
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
