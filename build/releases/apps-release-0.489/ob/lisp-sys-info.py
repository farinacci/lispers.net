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
if 64 - 64: i11iIiiIii
import sys
import os
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
def ooO0oo0oO0 ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 100 - 100: i1IIi
 if 27 - 27: IiII * OoooooooOO + I11i * ooOoO0o - i11iIiiIii - iII111i
 if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . II111iiii - oO0o
 if 72 - 72: II111iiii - OoOoOO00
OOo = os . getenv ( "LISPAPI_PATH" )
if ( OOo != None ) : sys . path . append ( OOo )
if 1 - 1: II111iiii - I1ii11iIi11i % i11iIiiIii + IiII . I1Ii111
try :
 import lispapi
except :
 if ( os . path . exists ( "lispapi.pyo" ) ) :
  print "Try command 'python -O lisp-provision-xtr.pyo'"
 else :
  print "Cannot find lispapi module, use LISPAPI_PATH env variable"
  if 55 - 55: iIii1I11I1II1 - I1IiiI . Ii1I * IiII * i1IIi / iIii1I11I1II1
 exit ( 1 )
 if 79 - 79: oO0o + I1Ii111 . ooOoO0o * IiII % I11i . I1IiiI
 if 94 - 94: iII111i * Ii1I / IiII . i1IIi * iII111i
 if 47 - 47: i1IIi % i11iIiiIii
 if 20 - 20: ooOoO0o * II111iiii
 if 65 - 65: o0oOOo0O0Ooo * iIii1I11I1II1 * ooOoO0o
IiI1i = os . getenv ( "LISPAPI_USER" )
if ( IiI1i == None ) :
 print "LISPAPI_USER environment variable needs username setting"
 exit ( 0 )
 if 61 - 61: I1ii11iIi11i + I11i / I1Ii111 . o0oOOo0O0Ooo
OOoOoo00oo = os . getenv ( "LISPAPI_PW" )
if ( OOoOoo00oo == None ) :
 print "LISPAPI_PW environment variable needs password setting"
 exit ( 0 )
 if 41 - 41: iIii1I11I1II1 / I1Ii111 + OOooOOo
 if 91 - 91: o0oOOo0O0Ooo / II111iiii . I1ii11iIi11i + OOooOOo
 if 47 - 47: OoOoOO00 / Ii1I * OoooooooOO
 if 9 - 9: I1IiiI - Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
 if 78 - 78: OoO0O00
Iii1I111 = [ ]
if ( len ( sys . argv ) > 1 ) :
 OO0O0O00OooO = sys . argv [ 1 : : ]
 for OoooooOoo in OO0O0O00OooO : Iii1I111 . append ( [ OoooooOoo , None , None ] )
else :
 while ( True ) :
  OoooooOoo = raw_input ( "Enter hostname (enter return when done): " )
  if ( OoooooOoo == "" ) : break
  Iii1I111 . append ( [ OoooooOoo , None , None ] )
  if 70 - 70: OoO0O00 . OoO0O00 - OoO0O00 / I1ii11iIi11i * OOooOOo
  if 86 - 86: i11iIiiIii + Ii1I + ooOoO0o * I11i + o0oOOo0O0Ooo
  if 61 - 61: OoO0O00 / i11iIiiIii
print "Connecting to APIs ..." ,
sys . stdout . flush ( )
if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - I1ii11iIi11i + i11iIiiIii
if 65 - 65: OoOoOO00
if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
for OoooooOoo in Iii1I111 :
 o0O00oooo = OoooooOoo [ 0 ] . split ( ":" )
 if ( len ( o0O00oooo ) != 2 ) : o0O00oooo = None
 if ( o0O00oooo == None ) :
  OoooooOoo [ 1 ] = lispapi . api_init ( OoooooOoo [ 0 ] , IiI1i , OOoOoo00oo )
 else :
  OoooooOoo [ 1 ] = lispapi . api_init ( o0O00oooo [ 0 ] , IiI1i , OOoOoo00oo , port = o0O00oooo [ 1 ] )
  if 67 - 67: OOooOOo / OoooooooOO % I11i - iIii1I11I1II1
  if 82 - 82: i11iIiiIii . OOooOOo / Oo0Ooo * O0 % oO0o % iIii1I11I1II1
print ""
if 78 - 78: iIii1I11I1II1 - Ii1I * OoO0O00 + o0oOOo0O0Ooo + iII111i + iII111i
if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
if 74 - 74: iII111i * O0
if 89 - 89: oO0o + Oo0Ooo
for OoooooOoo in Iii1I111 :
 if ( OoooooOoo [ 1 ] == None ) :
  print "Could not open API to {}" . format ( OoooooOoo [ 0 ] )
 else :
  print "Querying {} ... " . format ( OoooooOoo [ 0 ] ) ,
  OoooooOoo [ 2 ] = OoooooOoo [ 1 ] . get_system ( )
  print "done"
  if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
  if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
print ""
if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
if 20 - 20: o0oOOo0O0Ooo
if 77 - 77: OoOoOO00 / I11i
if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
for OoooooOoo in Iii1I111 :
 I1i1I1II = OoooooOoo [ 2 ]
 if ( I1i1I1II == None or len ( I1i1I1II ) == 0 ) : continue
 print "System info for {}:" . format ( ooO0oo0oO0 ( OoooooOoo [ 0 ] ) )
 if 45 - 45: I1Ii111 . OoOoOO00
 if ( type ( I1i1I1II ) == list and "?" in I1i1I1II [ 0 ] . keys ( ) ) :
  print "Not authenticated"
  continue
  if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
  if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
 O0ooOooooO = I1i1I1II [ "system-uptime" ]
 if 60 - 60: I11i / I11i
 I1II1III11iii = O0ooOooooO . split ( "load average" ) [ 0 ]
 Oo000 = O0ooOooooO . split ( "load average" ) [ 1 ]
 if 51 - 51: i11iIiiIii . I1IiiI + II111iiii
 I1II1III11iii = I1II1III11iii . split ( "up" ) [ 1 ]
 I1II1III11iii = I1II1III11iii . split ( "users" ) [ 0 ]
 I1II1III11iii = I1II1III11iii . split ( "," )
 I1II1III11iii = I1II1III11iii [ 0 ] [ 1 : : ] + ", " + I1II1III11iii [ 1 ] [ 1 : : ] if ( len ( I1II1III11iii ) > 1 ) else I1II1III11iii [ 0 ]
 if 10 - 10: I1ii11iIi11i * ooOoO0o * II111iiii % Ii1I . OOooOOo + I1Ii111
 IIiIi11i1 = Oo000 . find ( ":" ) + 2
 Oo000 = Oo000 [ IIiIi11i1 : : ]
 if 29 - 29: I1ii11iIi11i % I1IiiI + ooOoO0o / o0oOOo0O0Ooo + OOooOOo * o0oOOo0O0Ooo
 print "  Hostname: {}, uptime: {}, load: {}" . format ( I1i1I1II [ "hostname" ] , I1II1III11iii ,
 Oo000 )
 print "  LISP-version: {}, LISP-uptime: {}" . format ( I1i1I1II [ "lisp-version" ] , I1i1I1II [ "lisp-uptime" ] )
 if 42 - 42: Ii1I + oO0o
 if 76 - 76: I1Ii111 - OoO0O00
 oOooOOo00Oo0O = ""
 for O00oO in I1i1I1II [ "lisp-rlocs" ] : oOooOOo00Oo0O += O00oO + ", "
 print "  LISP-RLOCs: {}" . format ( oOooOOo00Oo0O [ : - 2 ] )
 if 39 - 39: IiII - II111iiii * OoO0O00 % o0oOOo0O0Ooo * II111iiii % II111iiii
 if ( I1i1I1II [ "traceback-log" ] == "yes" ) :
  print "  *** Traceback exception occurred ***"
  if 59 - 59: iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo - I1IiiI + OOooOOo / I1ii11iIi11i
  if 24 - 24: I11i . iII111i % OOooOOo + ooOoO0o % OoOoOO00
  if 4 - 4: IiII - OoO0O00 * OoOoOO00 - I11i
exit ( 0 )
if 41 - 41: OoOoOO00 . I1IiiI * oO0o % IiII
if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
if 44 - 44: oO0o
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
