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
# Usage: python -O lisp-mc.py [<user:pw@host:port>]
#        python -O lisp-mc.py [<host:port>]
#        python -O lisp-mc.py [<host>]
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
if ( len ( sys . argv ) == 2 ) :
 IiIIIiI1I1 = sys . argv [ 1 ]
 IiIIIiI1I1 = IiIIIiI1I1 . split ( "@" )
 if ( len ( IiIIIiI1I1 ) == 2 ) :
  OoO000 = IiIIIiI1I1 [ 0 ] . split ( ":" )
  if ( OoO000 [ 0 ] != "" ) : iIiiI1 = OoO000 [ 0 ]
  if ( len ( OoO000 ) == 2 and OoO000 [ 1 ] != "" ) : OoOooOOOO = OoO000 [ 1 ]
  IiIIIiI1I1 = IiIIIiI1I1 [ 1 ]
 else :
  IiIIIiI1I1 = IiIIIiI1I1 [ 0 ]
  if 42 - 42: iiiiIi11i - i1IIi / i11iIiiIii + iII111i + ooOO00oOo
 iIi = IiIIIiI1I1 . split ( ":" )
 if ( iIi [ 0 ] != "" ) : i11iiII = iIi [ 0 ]
 if ( len ( iIi ) == 2 and iIi [ 1 ] != "" ) : I1iiiiI1iII = iIi [ 1 ]
 if 40 - 40: iiiiIi11i . oOo0O0Ooo . OoO0O00 . i1IIi
 if 33 - 33: I1Ii111 + II111iiii % i11iIiiIii . IIII - oo
O00oooo0O = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/map-cache" ) . format ( iIiiI1 , OoOooOOOO , i11iiII , I1iiiiI1iII )
if 22 - 22: OoooooooOO % IiII - ooOoO0o . iIii1I11I1II1 * i11iIiiIii
II1i1Ii11Ii11 = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/system" ) . format ( iIiiI1 , OoOooOOOO , i11iiII , I1iiiiI1iII )
if 35 - 35: Ooo00oOo00o + ooOoO0o + ooOoO0o
if 11 - 11: ooOoO0o - ooOO00oOo % IIII % ooOoO0o / oOo0O0Ooo - ooOO00oOo
if 74 - 74: ooOoO0o * O0
i11iiII = ooO0oooOoO0 ( "{}:{}" . format ( i11iiII , I1iiiiI1iII ) )
if 89 - 89: iiiiIi11i + OoO0O00
Ii1IOo0o0 = getoutput ( O00oooo0O )
if ( Ii1IOo0o0 == None or Ii1IOo0o0 == "" ) :
 print ( "No curl output returned on {}" . format ( i11iiII ) )
 exit ( 1 )
 if 49 - 49: iiiiIi11i % I1Ii111 + i1IIi . oo % oOoO0oo0OOOo
if ( Ii1IOo0o0 . find ( "not-auth" ) != - 1 ) :
 print ( "Authentication failed on {}" . format ( i11iiII ) )
 exit ( 1 )
 if 48 - 48: IiII + IiII / II111iiii / iIii1I11I1II1
i1iiI11I = json . loads ( Ii1IOo0o0 )
if 29 - 29: OoooooooOO
if 23 - 23: Ooo00oOo00o . II111iiii
if 98 - 98: iIii1I11I1II1 % oOo0O0Ooo * oOoO0oo0OOOo * oOo0O0Ooo
if 45 - 45: oO0o0ooO0 . oOo0O0Ooo
Ii1IOo0o0 = getoutput ( II1i1Ii11Ii11 )
if ( Ii1IOo0o0 == None or Ii1IOo0o0 == "" ) :
 print ( "Could not get hostname on {}" . format ( i11iiII ) )
 exit ( 1 )
 if 83 - 83: iiiiIi11i . iIii1I11I1II1 . oOoO0oo0OOOo
II1i1Ii11Ii11 = json . loads ( Ii1IOo0o0 )
I1I = II1i ( II1i1Ii11Ii11 [ "hostname" ] )
if 80 - 80: oOo0O0Ooo - ooOO00oOo
print ( "\nLISP Map-Cache for {}, hostname {}, release {}\n" . format ( i11iiII ,
 I1I , II1i1Ii11Ii11 [ "lisp-version" ] ) )
if 87 - 87: iiiiIi11i / IiII - i1IIi * iII111i / OoooooooOO . O0
if ( len ( i1iiI11I ) == 0 ) :
 print ( "Map-Cache is empty" )
 exit ( 0 )
 if 1 - 1: II111iiii - IiII / IiII
 if 46 - 46: I1Ii111 * iII111i - ooOO00oOo * iiiiIi11i - oO0o0ooO0
for oo0 in i1iiI11I :
 o00 = IiII1IiiIiI1 ( "[{}]{}" . format ( oo0 [ "instance-id" ] , oo0 [ "eid-prefix" ] ) )
 o00 = "EID {}," . format ( o00 )
 OooOooo = oo0 [ "ttl" ]
 OooOooo = "never" if ( OooOooo == "--" ) else OooOooo . split ( "." ) [ 0 ] + "m"
 O000oo0O = "uptime {}, ttl {}" . format ( oo0 [ "uptime" ] , OooOooo )
 print ( o00 , O000oo0O )
 if 66 - 66: oOoO0oo0OOOo / oOo0O0Ooo - oo . iII111i / oo * iII111i
 for i11 in oo0 [ "rloc-set" ] :
  O000oo0O = "{} since {}" . format ( i11 [ "state" ] , i11 [ "uptime" ] )
  IIIii1II1II = i11 [ "state" ]
  IIIii1II1II = IiII1IiiIiI1 ( IIIii1II1II ) if IIIii1II1II == "up-state" else Ii1I ( IIIii1II1II )
  i1I1iI = "  RLOC {}, state {} since {}" . format ( Ii1I ( i11 [ "address" ] ) , IIIii1II1II ,
 i11 [ "uptime" ] )
  if ( "rloc-name" in i11 ) : i1I1iI += ", {}" . format ( II1i ( i11 [ "rloc-name" ] ) )
  oo0OooOOo0 = "    {}" . format ( i11 [ "stats" ] )
  if 92 - 92: ooOoO0o . IiII + Ooo00oOo00o
  print ( i1I1iI )
  print ( oo0OooOOo0 )
  i11 , I11 , Oo0o0000o0o0 = Oooo0000 ( i11 )
  print ( "    rtts {}, hops {}, latencies {}" . format ( i11 , I11 , Oo0o0000o0o0 ) )
  if 28 - 28: i1IIi * OoO0O00 - Ooo00oOo00o * o00O0oo * I1Ii111 / ooOO00oOo
 print ( )
 if 94 - 94: II111iiii % oOoO0oo0OOOo / oOo0O0Ooo * iIii1I11I1II1
exit ( 0 )
if 54 - 54: Ooo00oOo00o - oo + OoooooooOO
if 70 - 70: I1Ii111 / IiII . ooOoO0o % OoO0O00
if 67 - 67: oOo0O0Ooo * Ooo00oOo00o . o00O0oo - ooOO00oOo * Ooo00oOo00o
if 46 - 46: iII111i + oOo0O0Ooo . oo * iiiiIi11i % o00O0oo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
