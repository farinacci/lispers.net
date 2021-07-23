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
# lisp-mc.py
#
# Usage: python -O lisp-mc.py [<user:pw@host:port>] [<eid>]
#        python -O lisp-mc.py [<host:port>] [<eid>]
#        python -O lisp-mc.py [<host>] [<eid>]
#
# Dispay the LISP map-cache using a command that displays the table as it
# looks like on the web interface.
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
 return ( "\033[91m" + string + "\033[0m" )
 if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * o00O0oo
 if 97 - 97: oO0o0ooO0 - IIII / Ooo00oOo00o - oO0o0ooO0
def II1i ( string ) :
 return ( "\033[94m" + string + "\033[0m" )
 if 32 - 32: oOo0O0Ooo . IIII * i1IIi . oO0o0ooO0 / o00O0oo
 if 88 - 88: ooOoO0o . iiiiIi11i % IIII
def ooO0oooOoO0 ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 21 - 21: oOo0O0Ooo / ooOoO0o * ooOO00oOo . II111iiii
 if 1 - 1: II111iiii - oOoO0oo0OOOo % i11iIiiIii + o00O0oo . oO0o0ooO0
def Oooo0000 ( rloc ) :
 i11 = str ( rloc [ "recent-rloc-probe-rtts" ] ) . replace ( "u'" , "" )
 i11 = i11 . replace ( "'" , "" )
 I11 = str ( rloc [ "recent-rloc-hop-counts" ] ) . replace ( "u'" , "" )
 I11 = I11 . replace ( "'" , "" )
 Oo0o0000o0o0 = str ( rloc [ "recent-rloc-probe-latencies" ] ) . replace ( "u'" , "" )
 Oo0o0000o0o0 = Oo0o0000o0o0 . replace ( "'" , "" )
 return ( i11 , I11 , Oo0o0000o0o0 )
 if 86 - 86: oOo0O0Ooo % oo
 if 80 - 80: OoooooooOO . oo
 if 87 - 87: iiiiIi11i / IIII + oO0o0ooO0 - IIII . IIII / II111iiii
 if 11 - 11: oo % Ooo00oOo00o - OoO0O00
if ( "help" in sys . argv ) :
 print ( "Usage: ./mc [<user:pw@host:port> | <host:port> | <host> | help]" )
 exit ( 0 )
 if 58 - 58: i11iIiiIii % oO0o0ooO0
 if 54 - 54: iII111i % O0 + oo - ooOoO0o / IiII
iIiiI1 = "root"
OoOooOOOO = ""
i11iiII = "localhost"
I1iiiiI1iII = "8080"
if 20 - 20: i1IIi + i11iIiiIii - I1Ii111 % ooOO00oOo . OoooooooOO
if 96 - 96: i1IIi . oOo0O0Ooo * iII111i % IIII
if 60 - 60: iiiiIi11i * Ooo00oOo00o % Ooo00oOo00o % IiII * II111iiii + i1IIi
if 64 - 64: iiiiIi11i - O0 / II111iiii / Ooo00oOo00o / iIii1I11I1II1
if 24 - 24: O0 % Ooo00oOo00o + i1IIi + oO0o0ooO0 + oOoO0oo0OOOo
if 70 - 70: OoO0O00 % OoO0O00 . o00O0oo % ooOO00oOo * Ooo00oOo00o % iiiiIi11i
if 23 - 23: i11iIiiIii + oo
oOo = sys . argv [ - 1 ]
for oOoOoO in oOo . split ( "." ) :
 if ( oOoOoO . isdigit ( ) ) : continue
 oOo = None
 break
 if 6 - 6: oo / OoO0O00 % I1Ii111
if ( oOo == None ) :
 oOo = sys . argv [ - 1 ]
 for oOoOoO in oOo . split ( ":" ) :
  if ( oOoOoO == "" ) : continue
  try :
   int ( oOoOoO , 16 )
   continue
  except :
   oOo = None
   break
   if 84 - 84: i11iIiiIii . Ooo00oOo00o
   if 100 - 100: I1Ii111 - I1Ii111 - oO0o0ooO0
   if 20 - 20: OoooooooOO
if ( oOo != None ) : sys . argv = sys . argv [ 0 : - 1 ]
if 13 - 13: i1IIi - I1Ii111 % iiiiIi11i / iIii1I11I1II1 % ooOoO0o
if 97 - 97: i11iIiiIii
if 32 - 32: OoO0O00 * O0 % iiiiIi11i % I1Ii111 . o00O0oo
if 61 - 61: IIII
if ( len ( sys . argv ) == 2 ) :
 oOOO00o = sys . argv [ 1 ]
 oOOO00o = oOOO00o . split ( "@" )
 if ( len ( oOOO00o ) == 2 ) :
  O0O00o0OOO0 = oOOO00o [ 0 ] . split ( ":" )
  if ( O0O00o0OOO0 [ 0 ] != "" ) : iIiiI1 = O0O00o0OOO0 [ 0 ]
  if ( len ( O0O00o0OOO0 ) == 2 and O0O00o0OOO0 [ 1 ] != "" ) : OoOooOOOO = O0O00o0OOO0 [ 1 ]
  oOOO00o = oOOO00o [ 1 ]
 else :
  oOOO00o = oOOO00o [ 0 ]
  if 27 - 27: O0 % i1IIi * iiiiIi11i + i11iIiiIii + OoooooooOO * i1IIi
 o0oo0o0O00OO = oOOO00o . split ( ":" )
 if ( o0oo0o0O00OO [ 0 ] != "" ) : i11iiII = o0oo0o0O00OO [ 0 ]
 if ( len ( o0oo0o0O00OO ) == 2 and o0oo0o0O00OO [ 1 ] != "" ) : I1iiiiI1iII = o0oo0o0O00OO [ 1 ]
 if 80 - 80: i1IIi
 if 70 - 70: oOo0O0Ooo - Ooo00oOo00o
I1iii = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/map-cache" ) . format ( iIiiI1 , OoOooOOOO , i11iiII , I1iiiiI1iII )
if 20 - 20: Ooo00oOo00o
oO00 = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/system" ) . format ( iIiiI1 , OoOooOOOO , i11iiII , I1iiiiI1iII )
if 53 - 53: OoooooooOO . i1IIi
if 18 - 18: Ooo00oOo00o
if 28 - 28: iII111i - o00O0oo . o00O0oo + oOo0O0Ooo - OoooooooOO + O0
i11iiII = ooO0oooOoO0 ( "{}:{}" . format ( i11iiII , I1iiiiI1iII ) )
if 95 - 95: ooOO00oOo % iiiiIi11i . O0
I1i1I = getoutput ( I1iii )
if ( I1i1I == None or I1i1I == "" ) :
 print ( "No curl output returned on {}" . format ( i11iiII ) )
 exit ( 1 )
 if 80 - 80: oOo0O0Ooo - ooOO00oOo
if ( I1i1I . find ( "not-auth" ) != - 1 ) :
 print ( "Authentication failed on {}" . format ( i11iiII ) )
 exit ( 1 )
 if 87 - 87: iiiiIi11i / IiII - i1IIi * iII111i / OoooooooOO . O0
iii11I111 = json . loads ( I1i1I )
if 63 - 63: ooOO00oOo * iiiiIi11i - ooOoO0o * O0
if 17 - 17: oOoO0oo0OOOo % II111iiii
if 13 - 13: oO0o0ooO0 % oOo0O0Ooo - i11iIiiIii . oo + II111iiii
if 10 - 10: oOoO0oo0OOOo * IIII * II111iiii % I1Ii111 . iII111i + oO0o0ooO0
I1i1I = getoutput ( oO00 )
if ( I1i1I == None or I1i1I == "" ) :
 print ( "Could not get hostname on {}" . format ( i11iiII ) )
 exit ( 1 )
 if 19 - 19: oOo0O0Ooo - oo . iII111i / o00O0oo
oO00 = json . loads ( I1i1I )
I11II = II1i ( oO00 [ "hostname" ] )
if 32 - 32: ooOO00oOo * Ooo00oOo00o
print ( "\nLISP Map-Cache for {}, hostname {}, release {}\n" . format ( i11iiII ,
 I11II , oO00 [ "lisp-version" ] ) )
if 99 - 99: ooOO00oOo - OoO0O00 / iiiiIi11i % I1Ii111
if ( len ( iii11I111 ) == 0 ) :
 print ( "Map-cache is empty" )
 exit ( 0 )
 if 21 - 21: ooOO00oOo * iIii1I11I1II1 % iiiiIi11i * i1IIi
 if 16 - 16: O0 - oO0o0ooO0 * iIii1I11I1II1 + ooOoO0o
Ii11iII1 = False
for Oo0O0O0ooO0O in iii11I111 :
 IIIIii = Oo0O0O0ooO0O [ "eid-prefix" ]
 O0o0 = Oo0O0O0ooO0O [ "group-prefix" ] if "group-prefix" in Oo0O0O0ooO0O else ""
 if ( oOo and ( IIIIii + O0o0 ) . find ( oOo ) == - 1 ) : continue
 if 71 - 71: iII111i + IIII % i11iIiiIii + oOoO0oo0OOOo - o00O0oo
 Ii11iII1 = True
 if ( "group-prefix" in Oo0O0O0ooO0O ) : IIIIii = "({}, {})" . format ( IIIIii , Oo0O0O0ooO0O [ "group-prefix" ] )
 IIIIii = IiII1IiiIiI1 ( "[{}]{}" . format ( Oo0O0O0ooO0O [ "instance-id" ] , IIIIii ) )
 IIIIii = "EID {}," . format ( IIIIii )
 oO0OOoO0 = Oo0O0O0ooO0O [ "ttl" ]
 oO0OOoO0 = "never" if ( oO0OOoO0 == "--" ) else oO0OOoO0 . split ( "." ) [ 0 ] + "m"
 I111Ii111 = "uptime {}, ttl {}" . format ( Oo0O0O0ooO0O [ "uptime" ] , oO0OOoO0 )
 i111IiI1I = Oo0O0O0ooO0O [ "action" ]
 I111Ii111 += ", action {}" . format ( ooO0oooOoO0 ( i111IiI1I ) ) if i111IiI1I != "no-action" else ""
 print ( IIIIii , I111Ii111 )
 if 70 - 70: I1Ii111 . OoO0O00 / Ooo00oOo00o . I1Ii111 - O0 / o00O0oo
 for i11 in Oo0O0O0ooO0O [ "rloc-set" ] :
  ooOooo000oOO = [ i11 ]
  if ( "multicast-rloc-set" in i11 ) : ooOooo000oOO += i11 [ "multicast-rloc-set" ]
  if 59 - 59: II111iiii + OoooooooOO * oOo0O0Ooo + i1IIi
  for Oo0OoO00oOO0o in ooOooo000oOO :
   if ( ooOooo000oOO . index ( Oo0OoO00oOO0o ) == 0 ) :
    OOO00O = "RLOC"
   else :
    OOO00O = "mRLOC"
    if 84 - 84: iiiiIi11i * ooOO00oOo / IiII - O0
    if 30 - 30: iIii1I11I1II1 / IIII - oO0o0ooO0 - II111iiii % ooOoO0o
   IIi1i11111 = Oo0OoO00oOO0o [ "address" ]
   if ( "rle" in Oo0OoO00oOO0o ) :
    IIi1i11111 = Oo0OoO00oOO0o [ "rle" ]
    OOO00O = "RLE"
    if 81 - 81: i11iIiiIii % oOo0O0Ooo - iII111i
   if ( "encap-port" in Oo0OoO00oOO0o ) : IIi1i11111 += ":{}" . format ( Oo0OoO00oOO0o [ "encap-port" ] )
   O0ooo0O0oo0 = Oo0OoO00oOO0o [ "state" ]
   O0ooo0O0oo0 = IiII1IiiIiI1 ( O0ooo0O0oo0 ) if O0ooo0O0oo0 == "up-state" else Ii1I ( O0ooo0O0oo0 )
   if 91 - 91: iIii1I11I1II1 + oO0o0ooO0
   IIi1i11111 = "  {} {}, state {} since {}" . format ( OOO00O , Ii1I ( IIi1i11111 ) ,
 O0ooo0O0oo0 , Oo0OoO00oOO0o [ "uptime" ] )
   if ( "encap-crypto" in Oo0OoO00oOO0o ) :
    IIi1i11111 += ", {}" . format ( Oo0OoO00oOO0o [ "encap-crypto" ] )
    if 31 - 31: o00O0oo . oOo0O0Ooo . iII111i
   if ( "rloc-name" in Oo0OoO00oOO0o ) :
    IIi1i11111 += ", {}" . format ( II1i ( Oo0OoO00oOO0o [ "rloc-name" ] ) )
    if 75 - 75: IiII + ooOO00oOo . oOo0O0Ooo . IIII + OoO0O00 . ooOO00oOo
    if 96 - 96: iII111i . IIII - OoO0O00 + iIii1I11I1II1 / oOo0O0Ooo * iII111i
   print ( IIi1i11111 )
   print ( "    {}" . format ( Oo0OoO00oOO0o [ "stats" ] ) )
   O0ii1ii1ii , oooooOoo0ooo , I1I1IiI1 = Oooo0000 ( Oo0OoO00oOO0o )
   print ( "    rtts {}, hops {}, latencies {}" . format ( O0ii1ii1ii , oooooOoo0ooo , I1I1IiI1 ) )
   if 5 - 5: Ooo00oOo00o * IIII + oOo0O0Ooo . iII111i + oOo0O0Ooo
   if 91 - 91: O0
 print ( )
 if 61 - 61: II111iiii
 if 64 - 64: IIII / oOo0O0Ooo - O0 - IiII
 if 86 - 86: IiII % oOo0O0Ooo / oo / oOo0O0Ooo
 if 42 - 42: ooOO00oOo
 if 67 - 67: oO0o0ooO0 . ooOoO0o . O0
if ( oOo and Ii11iII1 == False ) :
 print ( "EID {} not in map-cache" . format ( IiII1IiiIiI1 ( oOo ) ) )
 if 10 - 10: oOoO0oo0OOOo % oOoO0oo0OOOo - iIii1I11I1II1 / iII111i + I1Ii111
 if 87 - 87: iiiiIi11i * oOoO0oo0OOOo + iII111i / iIii1I11I1II1 / ooOoO0o
exit ( 0 )
if 37 - 37: ooOoO0o - IIII * iiiiIi11i % i11iIiiIii - oO0o0ooO0
if 83 - 83: IiII / oo
if 34 - 34: o00O0oo
if 57 - 57: iiiiIi11i . IiII . i1IIi
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
