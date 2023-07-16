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
iI1Ii11111iIi = "(py2)" if os . path . exists ( "./is-lisp-running.pyo" ) else "(py3)"
if ( I1iII1iiII . find ( "version" ) != - 1 ) :
 I1iII1iiII = I1iII1iiII . split ( "version " ) [ 1 ]
 I1iII1iiII = I1iII1iiII . split ( "," ) [ 0 ]
 I1iII1iiII = ", release {} running" . format ( OO0o ( I1iII1iiII ) )
else :
 I1iII1iiII = None
 if 41 - 41: I1II1
 if 100 - 100: iII1iII1i1iiI % iiIIIII1i1iI % iiI11iii111 % i1I1Ii1iI1ii
 if 11 - 11: I1IiI / ii1I % ooO0OO000o - OOOo0
 if 91 - 91: OoOoOO00 . i11iIiiIii / I1IiI % ii11ii1ii / OoOoOO00 - i11iIiiIii
 if 8 - 8: Oo * Ooo00oOo00o * OO0O0O . iiIIIII1i1iI / iiIIIII1i1iI % iiIIIII1i1iI
i11 = "ps auxww | egrep 'lisp-' |" + "egrep -v 'grep|is-lisp-running|tee|pslisp|sudo|log'"
if 41 - 41: iiI11iii111 . i1I1Ii1iI1ii * iiIIIII1i1iI % i11iIiiIii
o000o0o00o0Oo = getoutput ( i11 )
if ( o000o0o00o0Oo == None or o000o0o00o0Oo == "" ) :
 print ( "No lispers.net code running, release {} installed" . format ( O00ooOO ) )
 exit ( 0 )
 if 80 - 80: iiiii . IiII1IiiIiI1
if ( I1iII1iiII == None ) : I1iII1iiII = ""
if 87 - 87: I1IiI / i1I1Ii1iI1ii + iiI11iii111 - i1I1Ii1iI1ii . i1I1Ii1iI1ii / ooO0OO000o
print ( "--- lispers.net release {} installed {}{} ---" . format ( OO0o ( O00ooOO ) , iI1Ii11111iIi , I1iII1iiII ) )
if 11 - 11: IiII1IiiIiI1 % Oo - iIiiiI1IiI1I1
if 58 - 58: i11iIiiIii % iiI11iii111
O0OoOoo00o = o000o0o00o0Oo . split ( "\n" )
if 31 - 31: ooO0OO000o + OoOoOO00 . iiI11iii111
if 68 - 68: IiII1IiiIiI1 - i11iIiiIii - OoOoOO00 / OOooOOo - OoOoOO00 + ii1I
if 48 - 48: iiiii % Oo . IiII1IiiIiI1 - I1II1 % ii1I % iiiii
if 3 - 3: iII1iII1i1iiI + Iii1I1
if ( os . path . exists ( "/etc/alpine-release" ) ) :
 I1Ii = "PID" . ljust ( 8 )
 o0oOo0Ooo0O = "TIME" . ljust ( 8 )
 OO00O0O0O00Oo = "Process"
 print ( "{}{}{}" . format ( I1Ii , o0oOo0Ooo0O , OO00O0O0O00Oo ) )
 for IIIiiiiiIii in O0OoOoo00o :
  OO = IIIiiiiiIii . split ( )
  I1Ii = OO [ 0 ] . ljust ( 8 )
  o0oOo0Ooo0O = OO [ 2 ] . ljust ( 8 )
  OO00O0O0O00Oo = OO [ 3 ] if ( OO [ 3 ] . find ( "lisp-ztr" ) != - 1 ) else OO [ - 1 ]
  if ( OO00O0O0O00Oo . isdigit ( ) ) : OO00O0O0O00Oo = OO [ - 2 ] + " " + OO00O0O0O00Oo
  print ( "{}{}{}" . format ( I1Ii , o0oOo0Ooo0O , OO00O0O0O00Oo ) )
  if 55 - 55: OoOoOO00 / Ooo00oOo00o * OOooOOo
 exit ( 0 )
 if 86 - 86: i11iIiiIii + I1II1 + i1I1Ii1iI1ii * ii11ii1ii + Oo
 if 61 - 61: OoOoOO00 / i11iIiiIii
 if 34 - 34: iiiii + OO0O0O + i11iIiiIii - Ooo00oOo00o + i11iIiiIii
 if 65 - 65: OOOo0
 if 6 - 6: IiII1IiiIiI1 / iIiiiI1IiI1I1 % I1II1
I1Ii = "PID" . ljust ( 8 )
o0oOo0Ooo0O = "%CPU" . ljust ( 8 )
oo = "%MEM" . ljust ( 8 )
OO0O00 = "MEM" . ljust ( 8 )
OO00O0O0O00Oo = "Process"
print ( "{}{}{}{}{}" . format ( I1Ii , o0oOo0Ooo0O , oo , OO0O00 , OO00O0O0O00Oo ) )
if 20 - 20: iiiii
for IIIiiiiiIii in O0OoOoo00o :
 OO = IIIiiiiiIii . split ( )
 I1Ii = OO [ 1 ] . ljust ( 8 )
 o0oOo0Ooo0O = OO [ 2 ] . ljust ( 8 )
 oo = OO [ 3 ] . ljust ( 8 )
 if 13 - 13: ii1I - I1II1 % I1IiI / OO0O0O % iII1iII1i1iiI
 OO0O00 = old_div ( int ( OO [ 4 ] ) , 1000 )
 ooO0o0Oo = "M"
 if ( OO0O00 >= 1000 ) :
  OO0O00 = round ( float ( OO0O00 ) / 1000 , 1 )
  ooO0o0Oo = "G"
  if 78 - 78: OO0O0O - I1II1 * OoOoOO00 + Oo + iII1iII1i1iiI + iII1iII1i1iiI
 OO0O00 = "{}{}" . format ( OO0O00 , ooO0o0Oo ) . ljust ( 8 )
 if 11 - 11: iII1iII1i1iiI - OoOoOO00 % i1I1Ii1iI1ii % iII1iII1i1iiI / OOOo0 - OoOoOO00
 if ( IIIiiiiiIii . find ( "lisp-core.py" ) != - 1 ) :
  OO00O0O0O00Oo = OO [ - 2 ] + " " + OO [ - 1 ]
 elif ( IIIiiiiiIii . find ( "lisp-join.py" ) != - 1 ) :
  o0o0oOOOo0oo = OO [ - 1 ]
  if ( o0o0oOOOo0oo . count ( "." ) != 3 ) : o0o0oOOOo0oo = OO [ - 2 ] + " " + o0o0oOOOo0oo
  OO00O0O0O00Oo = "lisp-join.py " + o0o0oOOOo0oo
 else :
  OO00O0O0O00Oo = OO [ - 1 ]
  if 80 - 80: ii11ii1ii * i11iIiiIii / iiI11iii111
  if 9 - 9: I1II1 + I1IiI % I1II1 + ii1I . OOooOOo
 print ( "{}{}{}{}{}" . format ( I1Ii , o0oOo0Ooo0O , oo , OO0O00 , OO00O0O0O00Oo ) )
 if 31 - 31: Oo + ii11ii1ii + ii11ii1ii / ooO0OO000o
exit ( 0 )
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
