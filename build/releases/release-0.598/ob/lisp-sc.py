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
# lisp-sc.py
#
# Usage: python -O lisp-sc.py [<user:pw@host:port>] [<eid>]
#        python -O lisp-sc.py [<host:port>] [<eid>]
#        python -O lisp-sc.py [<host>] [<eid>]
#
# Dispay the LISP registered mappings in the map-server a command that
# displays the table as it looks like on the web interface.
#
#------------------------------------------------------------------------------
from __future__ import print_function
from future import standard_library
standard_library . install_aliases ( )
from subprocess import getoutput
import sys
import json
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
def IiII1IiiIiI1 ( string ) :
 return ( "\033[92m" + string + "\033[0m" )
 if 40 - 40: oo * OoO0O00
 if 2 - 2: ooOO00oOo % oOo0O0Ooo * Ooo00oOo00o . oOoO0oo0OOOo + iiiiIi11i
def Ii1I ( string ) :
 return ( "\033[32;1m" + string + "\033[0m" )
 if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * o00O0oo
 if 97 - 97: oO0o0ooO0 - IIII / Ooo00oOo00o - oO0o0ooO0
def II1i ( string ) :
 return ( "\033[91m" + string + "\033[0m" )
 if 32 - 32: oOo0O0Ooo . IIII * i1IIi . oO0o0ooO0 / o00O0oo
 if 88 - 88: ooOoO0o . iiiiIi11i % IIII
def ooO0oooOoO0 ( string ) :
 return ( "\033[94m" + string + "\033[0m" )
 if 21 - 21: oOo0O0Ooo / ooOoO0o * ooOO00oOo . II111iiii
 if 1 - 1: II111iiii - oOoO0oo0OOOo % i11iIiiIii + o00O0oo . oO0o0ooO0
def Oooo0000 ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 22 - 22: I1Ii111 . o00O0oo
 if 41 - 41: oO0o0ooO0 . IIII * o00O0oo % i11iIiiIii
def o000o0o00o0Oo ( ts ) :
 if ( ts . find ( "days" ) != - 1 ) : return ( Oooo0000 ( II1i ( ts ) ) )
 ooIiII1I1i1i1ii , IIIII , I1 = ts . split ( ":" )
 if ( int ( ooIiII1I1i1i1ii ) != 0 ) : return ( Oooo0000 ( II1i ( ts ) ) )
 if ( int ( IIIII ) >= 3 ) : return ( Oooo0000 ( II1i ( ts ) ) )
 return ( ts )
 if 54 - 54: iII111i % O0 + oo - ooOoO0o / IiII
 if 31 - 31: ooOO00oOo + II111iiii
 if 13 - 13: iII111i * iiiiIi11i * oo
 if 55 - 55: II111iiii
if ( "help" in sys . argv ) :
 print ( "Usage: ./sc [<user:pw@host:port> | <host:port> | <host> | help]" )
 exit ( 0 )
 if 43 - 43: oOo0O0Ooo - i1IIi + oO0o0ooO0 + I1Ii111
 if 17 - 17: Ooo00oOo00o
o00ooooO0oO = "root"
oOoOo00oOo = ""
Oo = "localhost"
o00O00O0O0O = "8080"
if 90 - 90: II111iiii + iiiiIi11i / Ooo00oOo00o % II111iiii - O0
if 29 - 29: Ooo00oOo00o / iIii1I11I1II1
if 24 - 24: O0 % Ooo00oOo00o + i1IIi + oO0o0ooO0 + oOoO0oo0OOOo
if 70 - 70: OoO0O00 % OoO0O00 . o00O0oo % ooOO00oOo * Ooo00oOo00o % iiiiIi11i
if 23 - 23: i11iIiiIii + oo
if 68 - 68: oOo0O0Ooo . iiiiIi11i . i11iIiiIii
if 40 - 40: iiiiIi11i . oOo0O0Ooo . OoO0O00 . i1IIi
I11iii = sys . argv [ - 1 ]
for OO0O00 in I11iii . split ( "." ) :
 if ( OO0O00 . isdigit ( ) ) : continue
 I11iii = None
 break
 if 20 - 20: OoooooooOO
if ( I11iii == None ) :
 I11iii = sys . argv [ - 1 ]
 for OO0O00 in I11iii . split ( ":" ) :
  if ( OO0O00 == "" ) : continue
  try :
   int ( OO0O00 , 16 )
   continue
  except :
   I11iii = None
   break
   if 13 - 13: i1IIi - I1Ii111 % iiiiIi11i / iIii1I11I1II1 % ooOoO0o
   if 97 - 97: i11iIiiIii
   if 32 - 32: OoO0O00 * O0 % iiiiIi11i % I1Ii111 . o00O0oo
if ( I11iii != None ) : sys . argv = sys . argv [ 0 : - 1 ]
if 61 - 61: IIII
if 79 - 79: OoO0O00 + oo - ooOoO0o
if 83 - 83: IIII
if 64 - 64: ooOO00oOo % IIII % ooOoO0o / oOo0O0Ooo - ooOO00oOo
if ( len ( sys . argv ) == 2 ) :
 o0o0oOOOo0oo = sys . argv [ 1 ]
 o0o0oOOOo0oo = o0o0oOOOo0oo . split ( "@" )
 if ( len ( o0o0oOOOo0oo ) == 2 ) :
  o0oo0o0O00OO = o0o0oOOOo0oo [ 0 ] . split ( ":" )
  if ( o0oo0o0O00OO [ 0 ] != "" ) : o00ooooO0oO = o0oo0o0O00OO [ 0 ]
  if ( len ( o0oo0o0O00OO ) == 2 and o0oo0o0O00OO [ 1 ] != "" ) : oOoOo00oOo = o0oo0o0O00OO [ 1 ]
  o0o0oOOOo0oo = o0o0oOOOo0oo [ 1 ]
 else :
  o0o0oOOOo0oo = o0o0oOOOo0oo [ 0 ]
  if 80 - 80: i1IIi
 oOOO0o0o = o0o0oOOOo0oo . split ( ":" )
 if ( oOOO0o0o [ 0 ] != "" ) : Oo = oOOO0o0o [ 0 ]
 if ( len ( oOOO0o0o ) == 2 and oOOO0o0o [ 1 ] != "" ) : o00O00O0O0O = oOOO0o0o [ 1 ]
 if 26 - 26: OoooooooOO
 if 12 - 12: OoooooooOO % oOo0O0Ooo / IIII % Ooo00oOo00o
iiii = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/site-cache" ) . format ( o00ooooO0oO , oOoOo00oOo , Oo , o00O00O0O0O )
if 54 - 54: oOoO0oo0OOOo * iII111i
I1IIIii = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/site-cache-summary" ) . format ( o00ooooO0oO , oOoOo00oOo , Oo , o00O00O0O0O )
if 95 - 95: ooOO00oOo % iiiiIi11i . O0
I1i1I = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/system" ) . format ( o00ooooO0oO , oOoOo00oOo , Oo , o00O00O0O0O )
if 80 - 80: oOo0O0Ooo - ooOO00oOo
if 87 - 87: iiiiIi11i / IiII - i1IIi * iII111i / OoooooooOO . O0
if 1 - 1: II111iiii - IiII / IiII
Oo = Oooo0000 ( "{}:{}" . format ( Oo , o00O00O0O0O ) )
if 46 - 46: I1Ii111 * iII111i - ooOO00oOo * iiiiIi11i - oO0o0ooO0
oo0 = getoutput ( iiii )
if ( oo0 == None or oo0 == "" ) :
 print ( "No curl output returned on {}" . format ( Oo ) )
 exit ( 1 )
 if 57 - 57: iII111i . iII111i
if ( oo0 . find ( "not-auth" ) != - 1 ) :
 print ( "Authentication failed on {}" . format ( Oo ) )
 exit ( 1 )
 if 95 - 95: O0 + ooOO00oOo . II111iiii / O0
try :
 O000oo0O = json . loads ( oo0 )
except :
 print ( "Curl output did not return JSON" )
 exit ( 1 )
 if 66 - 66: oOoO0oo0OOOo / oOo0O0Ooo - oo . iII111i / oo * iII111i
 if 29 - 29: oOoO0oo0OOOo % oo + IIII / Ooo00oOo00o + iII111i * Ooo00oOo00o
 if 42 - 42: I1Ii111 + iiiiIi11i
 if 76 - 76: oO0o0ooO0 - ooOO00oOo
 if 70 - 70: IIII
oo0 = getoutput ( I1IIIii )
oOO = json . loads ( oo0 )
if 10 - 10: oOo0O0Ooo * ooOoO0o . IiII + II111iiii - IIII * i1IIi
oO00o0O0O0ooO = { }
for oOOOoo0Oo0 in oOO :
 I1II11IiII = oOOOoo0Oo0 [ "registrations" ] [ 0 ] [ "count" ]
 OOO0OOo = oOOOoo0Oo0 [ "registrations" ] [ 0 ] [ "registered-count" ]
 oO00o0O0O0ooO [ oOOOoo0Oo0 [ "site" ] ] = ( I1II11IiII , OOO0OOo )
 if 47 - 47: iII111i + o00O0oo - o00O0oo * oo + I1Ii111 % o00O0oo
 if 4 - 4: iiiiIi11i
 if 93 - 93: ooOO00oOo % iiiiIi11i . ooOO00oOo * oO0o0ooO0 % I1Ii111 . II111iiii
 if 38 - 38: Ooo00oOo00o
 if 57 - 57: O0 / iiiiIi11i * oO0o0ooO0 / oOo0O0Ooo . II111iiii
oo0 = getoutput ( I1i1I )
if ( oo0 == None or oo0 == "" ) :
 print ( "Could not get hostname on {}" . format ( Oo ) )
 exit ( 1 )
 if 26 - 26: ooOoO0o
I1i1I = json . loads ( oo0 )
OOO = ooO0oooOoO0 ( I1i1I [ "hostname" ] )
if 59 - 59: II111iiii + OoooooooOO * oOo0O0Ooo + i1IIi
print ( "\nLISP Map-Server Site-Cache for {}, hostname {}, release {}\n" . format ( Oo , OOO , I1i1I [ "lisp-version" ] ) )
if 58 - 58: II111iiii * iII111i * oOoO0oo0OOOo / iII111i
if 75 - 75: iiiiIi11i
if ( len ( O000oo0O ) == 0 ) :
 print ( "Site-cache is empty" )
 exit ( 0 )
 if 50 - 50: I1Ii111 / OoO0O00 - iiiiIi11i - IiII % ooOoO0o - iiiiIi11i
 if 91 - 91: ooOO00oOo / IiII - II111iiii . IiII
i1I11i1I = False
for Oo0o00 in oO00o0O0O0ooO :
 I1 = Oooo0000 ( Oo0o00 )
 I1II11IiII = oO00o0O0O0ooO [ Oo0o00 ] [ 0 ]
 OOO0OOo = oO00o0O0O0ooO [ Oo0o00 ] [ 1 ]
 OOO0OOo = Oooo0000 ( str ( OOO0OOo ) )
 print ( "Site {}, {} EID entries, EIDs registered {}:" . format ( I1 , I1II11IiII , OOO0OOo ) )
 print ( "" )
 if 73 - 73: ooOoO0o * I1Ii111 + Ooo00oOo00o . iII111i + oOoO0oo0OOOo % ooOoO0o
 for oOOOoo0Oo0 in O000oo0O :
  if ( oOOOoo0Oo0 [ "registered-rlocs" ] == [ ] ) : continue
  if 95 - 95: i1IIi
  I1ii11iI = oOOOoo0Oo0 [ "eid-prefix" ]
  IIi1i = oOOOoo0Oo0 [ "group-prefix" ] if "group-prefix" in oOOOoo0Oo0 else ""
  if ( I11iii and ( I1ii11iI + IIi1i ) . find ( I11iii ) == - 1 ) : continue
  if 46 - 46: oO0o0ooO0 % IiII + ooOO00oOo . oOo0O0Ooo . ooOO00oOo
  i1I11i1I = True
  if ( "group-prefix" in oOOOoo0Oo0 ) :
   I1ii11iI = "({}, {})" . format ( I1ii11iI , oOOOoo0Oo0 [ "group-prefix" ] )
   if 96 - 96: OoO0O00
  I1ii11iI = IiII1IiiIiI1 ( "[{}]{}" . format ( oOOOoo0Oo0 [ "instance-id" ] , I1ii11iI ) )
  I1ii11iI = "  EID {}," . format ( I1ii11iI )
  Ii1I1IIii1II = oOOOoo0Oo0 [ "last-registered" ]
  O0ii1ii1ii = IiII1IiiIiI1 ( "registered" ) if oOOOoo0Oo0 [ "registered" ] == "yes" else II1i ( "registered" )
  if 91 - 91: o00O0oo
  iiIii = "uptime {}, {}" . format ( oOOOoo0Oo0 [ "first-registered" ] , O0ii1ii1ii )
  Oo0o00 = Oooo0000 ( oOOOoo0Oo0 [ "site-name" ] )
  ooo0O = o000o0o00o0Oo ( oOOOoo0Oo0 [ "last-registered" ] )
  iiIii += " since {}" . format ( ooo0O )
  print ( I1ii11iI , iiIii )
  if 75 - 75: Ooo00oOo00o % Ooo00oOo00o . oO0o0ooO0
  for OOO0OOo in oOOOoo0Oo0 [ "registered-rlocs" ] :
   III1iII1I1ii = II1i ( OOO0OOo [ "address" ] )
   oOOo0 = OOO0OOo [ "upriority" ] ; oo00O00oO = OOO0OOo [ "uweight" ]
   iIiIIIi = OOO0OOo [ "mpriority" ] ; ooo00OOOooO = OOO0OOo [ "mweight" ]
   O00OOOoOoo0O = "up/uw {}/{} mp/mw {}/{}" . format ( oOOo0 , oo00O00oO , iIiIIIi , ooo00OOOooO )
   O000OOo00oo = ", " + ooO0oooOoO0 ( OOO0OOo [ "rloc-name" ] ) if "rloc-name" in OOO0OOo else ""
   oo0OOo = "    {}, uptime {}, {}{}" . format ( III1iII1I1ii , OOO0OOo [ "uptime" ] , O00OOOoOoo0O ,
 O000OOo00oo )
   print ( oo0OOo )
   if 64 - 64: IiII
  print ( )
  if 22 - 22: OoO0O00 + I1Ii111 % oOoO0oo0OOOo
  if 9 - 9: OoooooooOO
  if 62 - 62: iII111i / ooOO00oOo + I1Ii111 / ooOO00oOo . II111iiii
  if 68 - 68: i11iIiiIii % oOoO0oo0OOOo + i11iIiiIii
  if 31 - 31: II111iiii . oo
  if 1 - 1: OoO0O00 / Ooo00oOo00o % ooOoO0o * o00O0oo . i11iIiiIii
if ( I11iii and i1I11i1I == False ) :
 print ( "EID {} not in site-cache" . format ( IiII1IiiIiI1 ( I11iii ) ) )
 if 2 - 2: oOoO0oo0OOOo * IiII - iIii1I11I1II1 + oo . iiiiIi11i % ooOoO0o
 if 92 - 92: ooOoO0o
exit ( 0 )
if 25 - 25: OoO0O00 - oo / OoooooooOO / Ooo00oOo00o
if 12 - 12: oo * ooOoO0o % i1IIi % iIii1I11I1II1
if 20 - 20: iII111i % I1Ii111 / I1Ii111 + I1Ii111
if 45 - 45: iiiiIi11i - o00O0oo - OoooooooOO - ooOO00oOo . II111iiii / O0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
