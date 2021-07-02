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
# lisp-sys-info.py
#
# This script takes a hostname list from the command line and uses the
# lispapi.get_system() API call to get general information from the lispers.net
# system.
#
# Usage: python lisp-sys-info.py [<list-of-hosts>]
#
# A host name can be an IPv4 address, DNS name and either can be appended with
# ":<port>" so you can query through firewalls.
#
from __future__ import print_function
import sys
import os
from builtins import input
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
def Oo0o ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 60 - 60: I1ii11iIi11i + I1Ii111 - I11i / i1IIi
 if 40 - 40: I1IiiI / O0 % ooOoO0o + O0 * i1IIi
 if 27 - 27: IiII * OoooooooOO + I11i * ooOoO0o - i11iIiiIii - iII111i
 if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . II111iiii - oO0o
ooO00oOoo = os . getenv ( "LISPAPI_PATH" )
if ( ooO00oOoo != None ) : sys . path . append ( ooO00oOoo )
if 78 - 78: I11i / OoO0O00 - O0 . IiII
try :
 import lispapi
except :
 if ( os . path . exists ( "lispapi.pyo" ) ) :
  print ( "Try command 'python -O lisp-provision-xtr.pyo'" )
 else :
  print ( "Cannot find lispapi module, use LISPAPI_PATH env variable" )
  if 91 - 91: I1ii11iIi11i * iIii1I11I1II1 . IiII / Ii1I
 exit ( 1 )
 if 87 - 87: i1IIi / Ii1I . OoO0O00 * OoooooooOO - IiII * ooOoO0o
 if 82 - 82: I11i . I1Ii111 / IiII % II111iiii % iIii1I11I1II1 % IiII
 if 86 - 86: OoOoOO00 % I1IiiI
 if 80 - 80: OoooooooOO . I1IiiI
 if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
iiIIIIi1i1 = os . getenv ( "LISPAPI_USER" )
if ( iiIIIIi1i1 == None ) :
 print ( "LISPAPI_USER environment variable needs username setting" )
 exit ( 0 )
 if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
iIiiI1 = os . getenv ( "LISPAPI_PW" )
if ( iIiiI1 == None ) :
 print ( "LISPAPI_PW environment variable needs password setting" )
 exit ( 0 )
 if 68 - 68: I1IiiI - i11iIiiIii - OoO0O00 / OOooOOo - OoO0O00 + i1IIi
 if 48 - 48: OoooooooOO % o0oOOo0O0Ooo . I1IiiI - Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
 if 78 - 78: OoO0O00
 if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
 if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
OoooooOoo = [ ]
if ( len ( sys . argv ) > 1 ) :
 OO = sys . argv [ 1 : : ]
 for oO0O in OO : OoooooOoo . append ( [ oO0O , None , None ] )
else :
 while ( True ) :
  oO0O = input ( "Enter hostname (enter return when done): " )
  if ( oO0O == "" ) : break
  OoooooOoo . append ( [ oO0O , None , None ] )
  if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
  if 23 - 23: i11iIiiIii + I1IiiI
  if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
print ( "Connecting to APIs ..." , end = " " )
sys . stdout . flush ( )
if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
if 33 - 33: Ii1I + II111iiii % i11iIiiIii . ooOoO0o - I1IiiI
if 66 - 66: Ii1I - OoooooooOO * OoooooooOO . OOooOOo . I1ii11iIi11i
if 22 - 22: OoooooooOO % I11i - iII111i . iIii1I11I1II1 * i11iIiiIii
for oO0O in OoooooOoo :
 II1i1Ii11Ii11 = oO0O [ 0 ] . split ( ":" )
 if ( len ( II1i1Ii11Ii11 ) != 2 ) : II1i1Ii11Ii11 = None
 if ( II1i1Ii11Ii11 == None ) :
  oO0O [ 1 ] = lispapi . api_init ( oO0O [ 0 ] , iiIIIIi1i1 , iIiiI1 )
 else :
  oO0O [ 1 ] = lispapi . api_init ( II1i1Ii11Ii11 [ 0 ] , iiIIIIi1i1 , iIiiI1 , port = II1i1Ii11Ii11 [ 1 ] )
  if 35 - 35: o0oOOo0O0Ooo + iII111i + iII111i
  if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
print ( "" )
if 74 - 74: iII111i * O0
if 89 - 89: oO0o + Oo0Ooo
if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
for oO0O in OoooooOoo :
 if ( oO0O [ 1 ] == None ) :
  print ( "Could not open API to {}" . format ( oO0O [ 0 ] ) )
 else :
  print ( "Querying {} ... " . format ( oO0O [ 0 ] ) , end = " " )
  oO0O [ 2 ] = oO0O [ 1 ] . get_system ( )
  print ( "done" )
  if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
  if 20 - 20: o0oOOo0O0Ooo
print ( "" )
if 77 - 77: OoOoOO00 / I11i
if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
if 95 - 95: OoO0O00 % oO0o . O0
for oO0O in OoooooOoo :
 I1i1I = oO0O [ 2 ]
 if ( I1i1I == None or len ( I1i1I ) == 0 ) : continue
 print ( "System info for {}:" . format ( Oo0o ( oO0O [ 0 ] ) ) )
 if 80 - 80: OoOoOO00 - OoO0O00
 if ( type ( I1i1I ) == list and "?" in I1i1I [ 0 ] . keys ( ) ) :
  print ( "Not authenticated" )
  continue
  if 87 - 87: oO0o / I11i - i1IIi * OOooOOo / OoooooooOO . O0
  if 1 - 1: II111iiii - I11i / I11i
 I1II1III11iii = I1i1I [ "system-uptime" ]
 if 75 - 75: iIii1I11I1II1 / OOooOOo % o0oOOo0O0Ooo * OoOoOO00
 iiii11I = I1II1III11iii . split ( "load average" ) [ 0 ]
 Ooo0OO0oOO = I1II1III11iii . split ( "load average" ) [ 1 ]
 if 50 - 50: I1IiiI
 iiii11I = iiii11I . split ( "up" ) [ 1 ]
 iiii11I = iiii11I . split ( "users" ) [ 0 ]
 iiii11I = iiii11I . split ( "," )
 iiii11I = iiii11I [ 0 ] [ 1 : : ] + ", " + iiii11I [ 1 ] [ 1 : : ] if ( len ( iiii11I ) > 1 ) else iiii11I [ 0 ]
 if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
 II1III = Ooo0OO0oOO . find ( ":" ) + 2
 Ooo0OO0oOO = Ooo0OO0oOO [ II1III : : ]
 if 19 - 19: oO0o % i1IIi % o0oOOo0O0Ooo
 print ( "  Hostname: {}, uptime: {}, load: {}" . format ( I1i1I [ "hostname" ] , iiii11I ,
 Ooo0OO0oOO ) )
 print ( "  LISP-version: {}, LISP-uptime: {}" . format ( I1i1I [ "lisp-version" ] , I1i1I [ "lisp-uptime" ] ) )
 if 93 - 93: iIii1I11I1II1 % oO0o * i1IIi
 if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
 Ii11iII1 = ""
 for Oo0O0O0ooO0O in I1i1I [ "lisp-rlocs" ] : Ii11iII1 += Oo0O0O0ooO0O + ", "
 print ( "  LISP-RLOCs: {}" . format ( Ii11iII1 [ : - 2 ] ) )
 if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 if ( I1i1I [ "traceback-log" ] == "yes" ) :
  print ( "  *** Traceback exception occurred ***" )
  if 58 - 58: i11iIiiIii % I11i
  if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
  if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
exit ( 0 )
if 16 - 16: I1IiiI * oO0o % IiII
if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
if 44 - 44: oO0o
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
