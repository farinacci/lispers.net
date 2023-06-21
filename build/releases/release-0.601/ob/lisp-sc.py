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
# Usage: python -O lisp-sc.py [<user:pw@host:port>] [<eid>] | [<site>]
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
oOo = None
if ( len ( sys . argv ) == 3 ) :
 oOo = sys . argv [ - 1 ]
 if ( oOo . count ( "." ) == 3 or oOo . count ( ":" ) == 2 ) :
  oOo = None
  if 63 - 63: OoO0O00
 if ( oOo != None ) : sys . argv = sys . argv [ 0 : - 1 ]
 if 57 - 57: iiiiIi11i
 if 14 - 14: OoO0O00 . oo / I1Ii111
 if 38 - 38: II111iiii % i11iIiiIii . IIII - iII111i + I1Ii111
 if 66 - 66: OoooooooOO * OoooooooOO . iII111i . i1IIi - iII111i
 if 77 - 77: IiII - iIii1I11I1II1
Ooo = None
if ( len ( sys . argv ) == 3 ) :
 Ooo = sys . argv [ - 1 ]
 for O0o0Oo in Ooo . split ( "." ) :
  if ( O0o0Oo . isdigit ( ) ) : continue
  Ooo = None
  break
  if 78 - 78: iIii1I11I1II1 - I1Ii111 * ooOO00oOo + Ooo00oOo00o + ooOoO0o + ooOoO0o
 if ( Ooo == None ) :
  Ooo = sys . argv [ - 1 ]
  for O0o0Oo in Ooo . split ( ":" ) :
   if ( O0o0Oo == "" ) : continue
   try :
    int ( O0o0Oo , 16 )
    continue
   except :
    Ooo = None
    break
    if 11 - 11: ooOoO0o - ooOO00oOo % IIII % ooOoO0o / oOo0O0Ooo - ooOO00oOo
    if 74 - 74: ooOoO0o * O0
    if 89 - 89: iiiiIi11i + OoO0O00
 if ( Ooo != None ) : sys . argv = sys . argv [ 0 : - 1 ]
 if 3 - 3: i1IIi / oo % IiII * i11iIiiIii / O0 * IiII
 if 49 - 49: iiiiIi11i % I1Ii111 + i1IIi . oo % oOoO0oo0OOOo
 if 48 - 48: IiII + IiII / II111iiii / iIii1I11I1II1
 if 20 - 20: Ooo00oOo00o
 if 77 - 77: oOo0O0Ooo / IiII
if ( len ( sys . argv ) == 2 ) :
 Ooooo = sys . argv [ 1 ]
 Ooooo = Ooooo . split ( "@" )
 if ( len ( Ooooo ) == 2 ) :
  I1I1i = Ooooo [ 0 ] . split ( ":" )
  if ( I1I1i [ 0 ] != "" ) : o00ooooO0oO = I1I1i [ 0 ]
  if ( len ( I1I1i ) == 2 and I1I1i [ 1 ] != "" ) : oOoOo00oOo = I1I1i [ 1 ]
  Ooooo = Ooooo [ 1 ]
 else :
  Ooooo = Ooooo [ 0 ]
  if 87 - 87: oOoO0oo0OOOo * ooOO00oOo + OoooooooOO
 I1IiIii = Ooooo . split ( ":" )
 if ( I1IiIii [ 0 ] != "" ) : Oo = I1IiIii [ 0 ]
 if ( len ( I1IiIii ) == 2 and I1IiIii [ 1 ] != "" ) : o00O00O0O0O = I1IiIii [ 1 ]
 if 57 - 57: iIii1I11I1II1 * I1Ii111
 if 61 - 61: Ooo00oOo00o / ooOO00oOo + IIII * iiiiIi11i / iiiiIi11i
OoOo = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/site-cache" ) . format ( o00ooooO0oO , oOoOo00oOo , Oo , o00O00O0O0O )
if 18 - 18: i11iIiiIii
Ii11I = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/site-cache-summary" ) . format ( o00ooooO0oO , oOoOo00oOo , Oo , o00O00O0O0O )
if 69 - 69: iiiiIi11i % oO0o0ooO0 - Ooo00oOo00o + oO0o0ooO0 - O0 % OoooooooOO
Iii111II = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/system" ) . format ( o00ooooO0oO , oOoOo00oOo , Oo , o00O00O0O0O )
if 9 - 9: ooOO00oOo
if 33 - 33: IIII . ooOoO0o
if 58 - 58: iII111i * i11iIiiIii / oOo0O0Ooo % oO0o0ooO0 - oOoO0oo0OOOo / iiiiIi11i
Oo = Oooo0000 ( "{}:{}" . format ( Oo , o00O00O0O0O ) )
if 50 - 50: oo
Ii1i11IIii1I = getoutput ( OoOo )
if ( Ii1i11IIii1I == None or Ii1i11IIii1I == "" ) :
 print ( "No curl output returned on {}" . format ( Oo ) )
 exit ( 1 )
 if 52 - 52: Ooo00oOo00o - OoooooooOO + I1Ii111 + I1Ii111 - Ooo00oOo00o / oO0o0ooO0
if ( Ii1i11IIii1I . find ( "not-auth" ) != - 1 ) :
 print ( "Authentication failed on {}" . format ( Oo ) )
 exit ( 1 )
 if 44 - 44: IIII . i1IIi - oOoO0oo0OOOo . O0 - IIII
try :
 o0O = json . loads ( Ii1i11IIii1I )
except :
 print ( "Curl output did not return JSON" )
 exit ( 1 )
 if 72 - 72: ooOoO0o / i1IIi * OoO0O00 - oO0o0ooO0
 if 51 - 51: II111iiii * ooOO00oOo % Ooo00oOo00o * II111iiii % oOoO0oo0OOOo / IIII
 if 49 - 49: Ooo00oOo00o
 if 35 - 35: oOo0O0Ooo - OoooooooOO / oOoO0oo0OOOo % i1IIi
 if 78 - 78: IiII
Ii1i11IIii1I = getoutput ( Ii11I )
OO00Oo = json . loads ( Ii1i11IIii1I )
if 51 - 51: o00O0oo * Ooo00oOo00o + IiII + ooOO00oOo
o0O0O00 = { }
for o000o in OO00Oo :
 I11IiI1I11i1i = o000o [ "registrations" ] [ 0 ] [ "count" ]
 iI1ii1Ii = o000o [ "registrations" ] [ 0 ] [ "registered-count" ]
 o0O0O00 [ o000o [ "site" ] ] = ( I11IiI1I11i1i , iI1ii1Ii )
 if 92 - 92: oOo0O0Ooo
 if 26 - 26: ooOoO0o . oO0o0ooO0
 if 68 - 68: ooOO00oOo
 if 35 - 35: ooOO00oOo - ooOoO0o / OoO0O00 / oOo0O0Ooo
 if 24 - 24: IIII - IIII / II111iiii - oOoO0oo0OOOo
Ii1i11IIii1I = getoutput ( Iii111II )
if ( Ii1i11IIii1I == None or Ii1i11IIii1I == "" ) :
 print ( "Could not get hostname on {}" . format ( Oo ) )
 exit ( 1 )
 if 69 - 69: iiiiIi11i . oO0o0ooO0 + I1Ii111 / OoO0O00 - iiiiIi11i
Iii111II = json . loads ( Ii1i11IIii1I )
OO0O0OoOO0 = ooO0oooOoO0 ( Iii111II [ "hostname" ] )
if 10 - 10: OoooooooOO % iIii1I11I1II1
print ( "\nLISP Map-Server Site-Cache for {}, hostname {}, release {}\n" . format ( Oo , OO0O0OoOO0 , Iii111II [ "lisp-version" ] ) )
if 54 - 54: oO0o0ooO0 - II111iiii % oOo0O0Ooo % IiII % iIii1I11I1II1 + IIII
if 15 - 15: IiII * IIII * OoO0O00 % i11iIiiIii % oOo0O0Ooo - iII111i
if ( len ( o0O ) == 0 ) :
 print ( "Site-cache is empty" )
 exit ( 0 )
 if 68 - 68: oO0o0ooO0 % i1IIi . o00O0oo . oOoO0oo0OOOo
 if 92 - 92: ooOoO0o . oO0o0ooO0
i1i = False
for iiI111I1iIiI in o0O0O00 :
 if ( oOo and oOo != iiI111I1iIiI ) : continue
 if 41 - 41: OoO0O00 . IIII + O0 * Ooo00oOo00o % OoO0O00 * OoO0O00
 I1 = Oooo0000 ( iiI111I1iIiI )
 I11IiI1I11i1i = o0O0O00 [ iiI111I1iIiI ] [ 0 ]
 iI1ii1Ii = o0O0O00 [ iiI111I1iIiI ] [ 1 ]
 iI1ii1Ii = Oooo0000 ( str ( iI1ii1Ii ) )
 print ( "Site {}, {} EID entries, EIDs registered {}:" . format ( I1 , I11IiI1I11i1i , iI1ii1Ii ) )
 if 19 - 19: ooOoO0o
 for o000o in o0O :
  if ( o000o [ "registered-rlocs" ] == [ ] ) : continue
  if ( o000o [ "site-name" ] != iiI111I1iIiI ) : continue
  if 46 - 46: oOoO0oo0OOOo - I1Ii111 . iIii1I11I1II1 / oOoO0oo0OOOo
  Ii1i = o000o [ "eid-prefix" ]
  I1iiIii = o000o [ "group-prefix" ] if "group-prefix" in o000o else ""
  if ( Ooo and ( Ii1i + I1iiIii ) . find ( Ooo ) == - 1 ) : continue
  if 79 - 79: OoooooooOO / O0
  i1i = True
  if ( "group-prefix" in o000o ) :
   Ii1i = "({}, {})" . format ( Ii1i , o000o [ "group-prefix" ] )
   if 75 - 75: oOo0O0Ooo % Ooo00oOo00o % Ooo00oOo00o . oO0o0ooO0
  Ii1i = IiII1IiiIiI1 ( "[{}]{}" . format ( o000o [ "instance-id" ] , Ii1i ) )
  Ii1i = "  EID {}," . format ( Ii1i )
  III1iII1I1ii = o000o [ "last-registered" ]
  oOOo0 = IiII1IiiIiI1 ( "registered" ) if o000o [ "registered" ] == "yes" else II1i ( "registered" )
  if 54 - 54: O0 - o00O0oo % iII111i
  OOoO = "uptime {}, {}" . format ( o000o [ "first-registered" ] , oOOo0 )
  iII = o000o0o00o0Oo ( o000o [ "last-registered" ] )
  OOoO += " since {}" . format ( iII )
  print ( Ii1i , OOoO )
  if 38 - 38: oO0o0ooO0
  for iI1ii1Ii in o000o [ "registered-rlocs" ] :
   Ii1 = II1i ( iI1ii1Ii [ "address" ] )
   OOooOO000 = iI1ii1Ii [ "upriority" ] ; OOoOoo = iI1ii1Ii [ "uweight" ]
   oO0000OOo00 = iI1ii1Ii [ "mpriority" ] ; iiIi1IIiIi = iI1ii1Ii [ "mweight" ]
   oOO00Oo = "up/uw {}/{} mp/mw {}/{}" . format ( OOooOO000 , OOoOoo , oO0000OOo00 , iiIi1IIiIi )
   i1iIIIi1i = ", " + ooO0oooOoO0 ( iI1ii1Ii [ "rloc-name" ] ) if "rloc-name" in iI1ii1Ii else ""
   iI1iIIiiii = "    {}, uptime {}, {}{}" . format ( Ii1 , iI1ii1Ii [ "uptime" ] , oOO00Oo ,
 i1iIIIi1i )
   print ( iI1iIIiiii )
   if 26 - 26: IiII . OoooooooOO
  print ( )
  if 39 - 39: ooOoO0o - O0 % i11iIiiIii * oO0o0ooO0 . o00O0oo
  if 58 - 58: ooOO00oOo % i11iIiiIii . ooOoO0o / iiiiIi11i
  if 84 - 84: ooOoO0o . oOoO0oo0OOOo / OoO0O00 - oo / OoooooooOO / Ooo00oOo00o
  if 12 - 12: oo * ooOoO0o % i1IIi % iIii1I11I1II1
  if 20 - 20: iII111i % I1Ii111 / I1Ii111 + I1Ii111
  if 45 - 45: iiiiIi11i - o00O0oo - OoooooooOO - ooOO00oOo . II111iiii / O0
if ( Ooo and i1i == False ) :
 print ( "EID {} not in site-cache" . format ( IiII1IiiIiI1 ( Ooo ) ) )
 if 51 - 51: O0 + ooOoO0o
 if 8 - 8: iiiiIi11i * oOo0O0Ooo - I1Ii111 - ooOO00oOo * iII111i % oo
exit ( 0 )
if 48 - 48: O0
if 11 - 11: IiII + OoooooooOO - ooOO00oOo / Ooo00oOo00o + OoO0O00 . II111iiii
if 41 - 41: I1Ii111 - O0 - O0
if 68 - 68: iII111i % oO0o0ooO0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
