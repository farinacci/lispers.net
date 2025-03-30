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
 i11 = string . replace ( "\033[94m" , "" )
 i11 = i11 . replace ( "\033[0m" , "" )
 return ( i11 )
 if 41 - 41: oO0o0ooO0 . IIII * o00O0oo % i11iIiiIii
 if 74 - 74: ooOoO0o * o00O0oo
def oo00o0Oo0oo ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 20 - 20: IIII * II111iiii
 if 65 - 65: Ooo00oOo00o * iIii1I11I1II1 * IIII
def IiI1i ( string ) :
 i11 = string . replace ( "\033[1m" , "" )
 i11 = i11 . replace ( "\033[0m" , "" )
 return ( i11 )
 if 61 - 61: oOoO0oo0OOOo + IiII / oO0o0ooO0 . Ooo00oOo00o
 if 72 - 72: OoO0O00 % iII111i . oo / IiII * oo
def iiiI11 ( string ) :
 i11 = Oooo0000 ( string )
 i11 = IiI1i ( i11 )
 return ( i11 )
 if 91 - 91: Ooo00oOo00o / II111iiii . oOoO0oo0OOOo + iII111i
 if 47 - 47: oOo0O0Ooo / I1Ii111 * OoooooooOO
def II111iiiiII ( ts ) :
 if ( ts . find ( "days" ) != - 1 ) : return ( oo00o0Oo0oo ( II1i ( ts ) ) )
 oOoOo00oOo , Oo , i11 = ts . split ( ":" )
 if ( int ( oOoOo00oOo ) != 0 ) : return ( oo00o0Oo0oo ( II1i ( ts ) ) )
 if ( int ( Oo ) >= 3 ) : return ( oo00o0Oo0oo ( II1i ( ts ) ) )
 return ( ts )
 if 85 - 85: iII111i % oOoO0oo0OOOo * IIII
 if 90 - 90: Ooo00oOo00o % Ooo00oOo00o % IiII * oOo0O0Ooo
def i1IIiiiii ( rles ) :
 rles = iiiI11 ( rles )
 rles = rles . split ( "," )
 o00o = ""
 for IiI1I1 in rles :
  OoO000 = IiI1I1 . find ( "(" )
  o00o += II1i ( IiI1I1 [ 0 : OoO000 ] )
  IIiiIiI1 = IiI1I1 . find ( ")" )
  iiIiIIi = ooO0oooOoO0 ( IiI1I1 [ OoO000 + 1 : IIiiIiI1 ] )
  o00o += "({})," . format ( iiIiIIi )
  if 65 - 65: oOo0O0Ooo
 o00o = o00o [ 0 : - 1 ]
 return ( o00o )
 if 6 - 6: oo / OoO0O00 % I1Ii111
 if 84 - 84: i11iIiiIii . Ooo00oOo00o
 if 100 - 100: I1Ii111 - I1Ii111 - oO0o0ooO0
 if 20 - 20: OoooooooOO
if ( "help" in sys . argv ) :
 print ( "Usage: ./sc [<user:pw@host:port> | <host:port> | <host> | help]" )
 exit ( 0 )
 if 13 - 13: i1IIi - I1Ii111 % iiiiIi11i / iIii1I11I1II1 % ooOoO0o
 if 97 - 97: i11iIiiIii
II1i1Ii11Ii11 = "root"
iII11i = ""
O0O00o0OOO0 = "localhost"
Ii1iIIIi1ii = "8080"
if 80 - 80: IiII * i11iIiiIii / oO0o0ooO0
if 9 - 9: I1Ii111 + iiiiIi11i % I1Ii111 + i1IIi . iII111i
if 31 - 31: Ooo00oOo00o + IiII + IiII / II111iiii
if 26 - 26: OoooooooOO
if 12 - 12: OoooooooOO % oOo0O0Ooo / IIII % Ooo00oOo00o
iiii = None
if ( len ( sys . argv ) == 3 ) :
 iiii = sys . argv [ - 1 ]
 if ( iiii . count ( "." ) == 3 or iiii . count ( ":" ) == 2 ) :
  iiii = None
  if 54 - 54: oOoO0oo0OOOo * iII111i
 if ( iiii != None ) : sys . argv = sys . argv [ 0 : - 1 ]
 if 13 - 13: o00O0oo + oOo0O0Ooo - OoooooooOO + oO0o0ooO0 . ooOoO0o + ooOO00oOo
 if 8 - 8: iIii1I11I1II1 . oo - iIii1I11I1II1 * I1Ii111
 if 61 - 61: Ooo00oOo00o / ooOO00oOo + IIII * iiiiIi11i / iiiiIi11i
 if 75 - 75: i1IIi / OoooooooOO - O0 / oOo0O0Ooo . II111iiii - i1IIi
 if 71 - 71: iII111i + I1Ii111 * iII111i - ooOO00oOo * Ooo00oOo00o
Oooo0Ooo000 = None
if ( len ( sys . argv ) == 3 ) :
 Oooo0Ooo000 = sys . argv [ - 1 ]
 for ooii11I in Oooo0Ooo000 . split ( "." ) :
  if ( ooii11I . isdigit ( ) ) : continue
  Oooo0Ooo000 = None
  break
  if 96 - 96: II111iiii % I1Ii111 . iII111i + OoooooooOO * iiiiIi11i - oOo0O0Ooo
 if ( Oooo0Ooo000 == None ) :
  Oooo0Ooo000 = sys . argv [ - 1 ]
  for ooii11I in Oooo0Ooo000 . split ( ":" ) :
   if ( ooii11I == "" ) : continue
   try :
    int ( ooii11I , 16 )
    continue
   except :
    Oooo0Ooo000 = None
    break
    if 10 - 10: iII111i / oo * iII111i
    if 29 - 29: oOoO0oo0OOOo % oo + IIII / Ooo00oOo00o + iII111i * Ooo00oOo00o
    if 42 - 42: I1Ii111 + iiiiIi11i
 if ( Oooo0Ooo000 != None ) : sys . argv = sys . argv [ 0 : - 1 ]
 if 76 - 76: oO0o0ooO0 - ooOO00oOo
 if 70 - 70: IIII
 if 61 - 61: oOoO0oo0OOOo . oOoO0oo0OOOo
 if 10 - 10: oOo0O0Ooo * ooOoO0o . IiII + II111iiii - IIII * i1IIi
 if 56 - 56: Ooo00oOo00o * o00O0oo * II111iiii
if ( len ( sys . argv ) == 2 ) :
 oO0ooO0OoOOOO = sys . argv [ 1 ]
 oO0ooO0OoOOOO = oO0ooO0OoOOOO . split ( "@" )
 if ( len ( oO0ooO0OoOOOO ) == 2 ) :
  i1Ii = oO0ooO0OoOOOO [ 0 ] . split ( ":" )
  if ( i1Ii [ 0 ] != "" ) : II1i1Ii11Ii11 = i1Ii [ 0 ]
  if ( len ( i1Ii ) == 2 and i1Ii [ 1 ] != "" ) : iII11i = i1Ii [ 1 ]
  oO0ooO0OoOOOO = oO0ooO0OoOOOO [ 1 ]
 else :
  oO0ooO0OoOOOO = oO0ooO0OoOOOO [ 0 ]
  if 78 - 78: IiII
 OO00Oo = oO0ooO0OoOOOO . split ( ":" )
 if ( OO00Oo [ 0 ] != "" ) : O0O00o0OOO0 = OO00Oo [ 0 ]
 if ( len ( OO00Oo ) == 2 and OO00Oo [ 1 ] != "" ) : Ii1iIIIi1ii = OO00Oo [ 1 ]
 if 51 - 51: o00O0oo * Ooo00oOo00o + IiII + ooOO00oOo
 if 66 - 66: oOo0O0Ooo
oO000Oo000 = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/site-cache" ) . format ( II1i1Ii11Ii11 , iII11i , O0O00o0OOO0 , Ii1iIIIi1ii )
if 4 - 4: iiiiIi11i
OOoO0O00o0 = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/site-cache-summary" ) . format ( II1i1Ii11Ii11 , iII11i , O0O00o0OOO0 , Ii1iIIIi1ii )
if 30 - 30: Ooo00oOo00o . I1Ii111 - OoooooooOO
Ii1iIiii1 = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/system" ) . format ( II1i1Ii11Ii11 , iII11i , O0O00o0OOO0 , Ii1iIIIi1ii )
if 91 - 91: ooOO00oOo . oOoO0oo0OOOo + ooOO00oOo - ooOoO0o / OoooooooOO
if 39 - 39: oOoO0oo0OOOo / IIII - II111iiii
if 98 - 98: oOoO0oo0OOOo / IiII % iiiiIi11i . oOo0O0Ooo
O0O00o0OOO0 = oo00o0Oo0oo ( "{}:{}" . format ( O0O00o0OOO0 , Ii1iIIIi1ii ) )
if 91 - 91: iiiiIi11i % OoO0O00
O0O0O0OoOO = getoutput ( oO000Oo000 )
if ( O0O0O0OoOO == None or O0O0O0OoOO == "" ) :
 print ( "No curl output returned on {}" . format ( O0O00o0OOO0 ) )
 exit ( 1 )
 if 74 - 74: II111iiii
if ( O0O0O0OoOO . find ( "not-auth" ) != - 1 ) :
 print ( "Authentication failed on {}" . format ( O0O00o0OOO0 ) )
 exit ( 1 )
 if 75 - 75: Ooo00oOo00o . IIII
try :
 Oo0O00Oo0o0 = json . loads ( O0O0O0OoOO )
except :
 print ( "Curl output did not return JSON" )
 exit ( 1 )
 if 87 - 87: IIII * OoO0O00 % i11iIiiIii % oOo0O0Ooo - iII111i
 if 68 - 68: oO0o0ooO0 % i1IIi . o00O0oo . oOoO0oo0OOOo
 if 92 - 92: ooOoO0o . oO0o0ooO0
 if 31 - 31: oO0o0ooO0 . oOo0O0Ooo / O0
 if 89 - 89: oOo0O0Ooo
O0O0O0OoOO = getoutput ( OOoO0O00o0 )
OO0oOoOO0oOO0 = json . loads ( O0O0O0OoOO )
if 86 - 86: iII111i
OOoo0O = { }
for Oo0ooOo0o in OO0oOoOO0oOO0 :
 Ii1i1 = Oo0ooOo0o [ "registrations" ] [ 0 ] [ "count" ]
 iiIii = Oo0ooOo0o [ "registrations" ] [ 0 ] [ "registered-count" ]
 OOoo0O [ Oo0ooOo0o [ "site" ] ] = ( Ii1i1 , iiIii )
 if 79 - 79: OoooooooOO / O0
 if 75 - 75: oOo0O0Ooo % Ooo00oOo00o % Ooo00oOo00o . oO0o0ooO0
 if 5 - 5: Ooo00oOo00o * IIII + oOo0O0Ooo . iII111i + oOo0O0Ooo
 if 91 - 91: O0
 if 61 - 61: II111iiii
O0O0O0OoOO = getoutput ( Ii1iIiii1 )
if ( O0O0O0OoOO == None or O0O0O0OoOO == "" ) :
 print ( "Could not get hostname on {}" . format ( O0O00o0OOO0 ) )
 exit ( 1 )
 if 64 - 64: IIII / oOo0O0Ooo - O0 - IiII
Ii1iIiii1 = json . loads ( O0O0O0OoOO )
O0oOoOOOoOO = ooO0oooOoO0 ( Ii1iIiii1 [ "hostname" ] )
if 38 - 38: oO0o0ooO0
print ( "\nLISP Map-Server Site-Cache for {}, hostname {}, release {}\n" . format ( O0O00o0OOO0 , O0oOoOOOoOO , Ii1iIiii1 [ "lisp-version" ] ) )
if 7 - 7: O0 . ooOoO0o % oOoO0oo0OOOo - oo - iIii1I11I1II1
if 36 - 36: o00O0oo % IIII % OoO0O00 - oOoO0oo0OOOo
if ( len ( Oo0O00Oo0o0 ) == 0 ) :
 print ( "Site-cache is empty" )
 exit ( 0 )
 if 22 - 22: iIii1I11I1II1 / OoO0O00 * oOoO0oo0OOOo % ooOoO0o
 if 85 - 85: iiiiIi11i % i11iIiiIii - ooOoO0o * OoooooooOO / oo % oo
IIiIi1iI = False
for i1IiiiI1iI in OOoo0O :
 if ( iiii and iiii != i1IiiiI1iI ) : continue
 if 49 - 49: I1Ii111 / ooOO00oOo . II111iiii
 i11 = oo00o0Oo0oo ( i1IiiiI1iI )
 Ii1i1 = OOoo0O [ i1IiiiI1iI ] [ 0 ]
 iiIii = OOoo0O [ i1IiiiI1iI ] [ 1 ]
 iiIii = oo00o0Oo0oo ( str ( iiIii ) )
 print ( "Site {}, {} EID entries, {} EIDs registered:" . format ( i11 , Ii1i1 , iiIii ) )
 if 68 - 68: i11iIiiIii % oOoO0oo0OOOo + i11iIiiIii
 for Oo0ooOo0o in Oo0O00Oo0o0 :
  if ( Oo0ooOo0o [ "registered-rlocs" ] == [ ] ) : continue
  if ( Oo0ooOo0o [ "site-name" ] != i1IiiiI1iI ) : continue
  if 31 - 31: II111iiii . oo
  II1I = Oo0ooOo0o [ "eid-prefix" ]
  O0i1II1Iiii1I11 = Oo0ooOo0o [ "group-prefix" ] if "group-prefix" in Oo0ooOo0o else ""
  if ( Oooo0Ooo000 and ( II1I + O0i1II1Iiii1I11 ) . find ( Oooo0Ooo000 ) == - 1 ) : continue
  if 9 - 9: oOoO0oo0OOOo / OoO0O00 - oo / OoooooooOO / iIii1I11I1II1 - Ooo00oOo00o
  IIiIi1iI = True
  if ( "group-prefix" in Oo0ooOo0o ) :
   II1I = "({}, {})" . format ( II1I , Oo0ooOo0o [ "group-prefix" ] )
   if 91 - 91: ooOoO0o % i1IIi % iIii1I11I1II1
  II1I = IiII1IiiIiI1 ( "[{}]{}" . format ( Oo0ooOo0o [ "instance-id" ] , II1I ) )
  II1I = "  EID {}," . format ( II1I )
  IIi1I11I1II = Oo0ooOo0o [ "last-registered" ]
  OooOoooOo = IiII1IiiIiI1 ( "registered" ) if Oo0ooOo0o [ "registered" ] == "yes" else II1i ( "registered" )
  if 46 - 46: ooOoO0o
  IIIII11I1IiI = "uptime {}, {}" . format ( Oo0ooOo0o [ "first-registered" ] , OooOoooOo )
  i1I = II111iiiiII ( Oo0ooOo0o [ "last-registered" ] )
  IIIII11I1IiI += " since {}" . format ( i1I )
  print ( II1I , IIIII11I1IiI )
  if 72 - 72: i1IIi / ooOO00oOo + OoooooooOO - OoO0O00
  if 29 - 29: oOoO0oo0OOOo + iiiiIi11i % O0
  if 10 - 10: IiII / oO0o0ooO0 - oo * iIii1I11I1II1 - oo
  if 97 - 97: oOoO0oo0OOOo + oo * I1Ii111 + iII111i % ooOoO0o
  for iiIii in Oo0ooOo0o [ "registered-rlocs" ] :
   if ( "rle" in iiIii ) :
    OOOOOoo0 = "RLEs: " + i1IIiiiii ( iiIii [ "rle" ] )
   else :
    OOOOOoo0 = "RLOC: " + II1i ( iiIii [ "address" ] )
    if 49 - 49: O0 . ooOoO0o
   I1iI1iIi111i = iiIii [ "upriority" ] ; iiIi1IIi1I = iiIii [ "uweight" ]
   o0OoOO000ooO0 = iiIii [ "mpriority" ] ; o0o0o0oO0oOO = iiIii [ "mweight" ]
   ii1Ii11I = "up/uw {}/{} mp/mw {}/{}" . format ( I1iI1iIi111i , iiIi1IIi1I , o0OoOO000ooO0 , o0o0o0oO0oOO )
   iiIiIIi = ", " + ooO0oooOoO0 ( iiIii [ "rloc-name" ] ) if "rloc-name" in iiIii else ""
   o00o0 = "    {}, uptime {}, {}{}" . format ( OOOOOoo0 , iiIii [ "uptime" ] , ii1Ii11I ,
 iiIiIIi )
   print ( o00o0 )
   if 45 - 45: O0
  print ( )
  if 26 - 26: IiII - iIii1I11I1II1 - oo / ooOO00oOo . oOo0O0Ooo % iIii1I11I1II1
  if 91 - 91: Ooo00oOo00o . iIii1I11I1II1 / iiiiIi11i + i1IIi
  if 42 - 42: IIII . Ooo00oOo00o . IIII - oOoO0oo0OOOo
  if 40 - 40: IIII - i11iIiiIii / I1Ii111
  if 35 - 35: I1Ii111 - oo % Ooo00oOo00o . OoooooooOO % I1Ii111
  if 47 - 47: ooOoO0o - I1Ii111 . II111iiii + OoooooooOO . i11iIiiIii
if ( Oooo0Ooo000 and IIiIi1iI == False ) :
 print ( "EID {} not in site-cache" . format ( IiII1IiiIiI1 ( Oooo0Ooo000 ) ) )
 if 94 - 94: Ooo00oOo00o * I1Ii111 / OoO0O00 / I1Ii111
 if 87 - 87: OoO0O00 . o00O0oo
exit ( 0 )
if 75 - 75: IIII + oOo0O0Ooo + Ooo00oOo00o * IiII % iiiiIi11i . ooOoO0o
if 55 - 55: iII111i . oo
if 61 - 61: OoO0O00 % o00O0oo . OoO0O00
if 100 - 100: oO0o0ooO0 * O0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
