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
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
I1IiI = True
if 73 - 73: OOooOOo / ii11ii1ii
if 94 - 94: OoOO + OoOO0ooOOoo0O + o0000oOoOoO0o * o00O0oo
if 97 - 97: oO0o0ooO0 - IIII / o0oOOo0O0Ooo - oO0o0ooO0
def II1i ( string ) :
 return ( "\033[92m" + string + "\033[0m" )
 if 32 - 32: OoOoOO00 . IIII * i1IIi . oO0o0ooO0 / o00O0oo
 if 88 - 88: o0000oOoOoO0o . OOooOOo % IIII
def ooO0oooOoO0 ( string ) :
 return ( "\033[32;1m" + string + "\033[0m" )
 if 21 - 21: OoOoOO00 / o0000oOoOoO0o * OoO0O00 . II111iiii
 if 1 - 1: II111iiii - I1ii11iIi11i % i11iIiiIii + o00O0oo . oO0o0ooO0
def Oooo0000 ( string ) :
 return ( "\033[91m" + string + "\033[0m" )
 if 22 - 22: OoOO0ooOOoo0O . o00O0oo
 if 41 - 41: oO0o0ooO0 . IIII * o00O0oo % i11iIiiIii
def o000o0o00o0Oo ( string ) :
 return ( "\033[94m" + string + "\033[0m" )
 if 80 - 80: OoooooooOO . I1IiiI
 if 87 - 87: OOooOOo / IIII + oO0o0ooO0 - IIII . IIII / II111iiii
def iiIIIIi1i1 ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 54 - 54: ii11ii1ii % O0 + I1IiiI - o0000oOoOoO0o / OoOO
 if 31 - 31: OoO0O00 + II111iiii
def i11IiIiiIIIII ( rloc ) :
 i1iiIII111ii = str ( rloc [ "recent-rloc-probe-rtts" ] )
 i1iiIII111ii = i1iiIII111ii . replace ( "-1" , "?" )
 i1iIIi1 = i1iiIII111ii . replace ( "u'" , "" )
 i1iIIi1 = i1iIIi1 . replace ( "'" , "" )
 ii11iIi1I = str ( rloc [ "recent-rloc-hop-counts" ] ) . replace ( "u'" , "" )
 ii11iIi1I = ii11iIi1I . replace ( "'" , "" )
 iI111I11I1I1 = str ( rloc [ "recent-rloc-probe-latencies" ] ) . replace ( "u'" , "" )
 iI111I11I1I1 = iI111I11I1I1 . replace ( "'" , "" )
 return ( i1iIIi1 , ii11iIi1I , iI111I11I1I1 )
 if 55 - 55: OoOoOO00 % i1IIi / OoOO0ooOOoo0O - OOooOOo - O0 / II111iiii
 if 28 - 28: iIii1I11I1II1 - i1IIi
def OO ( rr ) :
 oO0O = rr [ "stats" ]
 OOoO000O0OO = ( "recent-packet-sec" in rr and rr [ "recent-packet-sec" ] )
 iiI1IiI = ( "recent-packet-min" in rr and rr [ "recent-packet-min" ] )
 if ( OOoO000O0OO or iiI1IiI ) :
  II = oO0O . split ( ": " )
  ooOoOoo0O = II [ 1 ] . split ( "," )
  OooO0 = iiIIIIi1i1 ( ooOoOoo0O [ 0 ] ) if OOoO000O0OO else ooO0oooOoO0 ( ooOoOoo0O [ 0 ] )
  ooOoOoo0O [ 0 ] = OooO0
  II [ 1 ] = "," . join ( ooOoOoo0O )
  oO0O = ": " . join ( II )
  if 35 - 35: ii11ii1ii % oO0o0ooO0 % i11iIiiIii / OoooooooOO
 return ( oO0O )
 if 13 - 13: i1IIi - OoOO0ooOOoo0O % OOooOOo / iIii1I11I1II1 % o0000oOoOoO0o
 if 97 - 97: i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % OOooOOo % OoOO0ooOOoo0O . o00O0oo
 if 61 - 61: IIII
if ( "help" in sys . argv ) :
 print ( "Usage: ./mc [<user:pw@host:port> | <host:port> | <host> | help]" )
 exit ( 0 )
 if 79 - 79: Oo0Ooo + I1IiiI - o0000oOoOoO0o
 if 83 - 83: IIII
OO00o0OOO0 = "root"
Ii1iIIIi1ii = ""
o0oo0o0O00OO = "localhost"
o0oO = "8080"
if 48 - 48: OoOO + OoOO / II111iiii / iIii1I11I1II1
if 20 - 20: o0oOOo0O0Ooo
if 77 - 77: OoOoOO00 / OoOO
if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
if 28 - 28: ii11ii1ii - o00O0oo . o00O0oo + OoOoOO00 - OoooooooOO + O0
if 95 - 95: OoO0O00 % OOooOOo . O0
if 15 - 15: IIII / OoOO0ooOOoo0O . OoOO0ooOOoo0O - i1IIi
o00oOO0 = sys . argv [ - 1 ]
for oOoo in o00oOO0 . split ( "." ) :
 if ( oOoo . isdigit ( ) ) : continue
 o00oOO0 = None
 break
 if 8 - 8: OoOoOO00
if ( o00oOO0 == None ) :
 o00oOO0 = sys . argv [ - 1 ]
 for oOoo in o00oOO0 . split ( ":" ) :
  if ( oOoo == "" ) : continue
  try :
   int ( oOoo , 16 )
   continue
  except :
   o00oOO0 = None
   break
   if 60 - 60: OoOO / OoOO
   if 46 - 46: OoOO0ooOOoo0O * ii11ii1ii - OoO0O00 * OOooOOo - oO0o0ooO0
   if 83 - 83: OoooooooOO
if ( o00oOO0 != None ) : sys . argv = sys . argv [ 0 : - 1 ]
if 31 - 31: II111iiii - ii11ii1ii . oO0o0ooO0 % OoOoOO00 - O0
if 4 - 4: II111iiii / IIII . o0000oOoOoO0o
if 58 - 58: ii11ii1ii * i11iIiiIii / OoOoOO00 % oO0o0ooO0 - I1ii11iIi11i / OOooOOo
if 50 - 50: I1IiiI
if ( len ( sys . argv ) == 2 ) :
 Ii1i11IIii1I = sys . argv [ 1 ]
 Ii1i11IIii1I = Ii1i11IIii1I . split ( "@" )
 if ( len ( Ii1i11IIii1I ) == 2 ) :
  OOOoO0O0o = Ii1i11IIii1I [ 0 ] . split ( ":" )
  if ( OOOoO0O0o [ 0 ] != "" ) : OO00o0OOO0 = OOOoO0O0o [ 0 ]
  if ( len ( OOOoO0O0o ) == 2 and OOOoO0O0o [ 1 ] != "" ) : Ii1iIIIi1ii = OOOoO0O0o [ 1 ]
  Ii1i11IIii1I = Ii1i11IIii1I [ 1 ]
 else :
  Ii1i11IIii1I = Ii1i11IIii1I [ 0 ]
  if 55 - 55: ii11ii1ii + IIII . i1IIi - I1ii11iIi11i . O0 - IIII
 o0O = Ii1i11IIii1I . split ( ":" )
 if ( o0O [ 0 ] != "" ) : o0oo0o0O00OO = o0O [ 0 ]
 if ( len ( o0O ) == 2 and o0O [ 1 ] != "" ) : o0oO = o0O [ 1 ]
 if 72 - 72: o0000oOoOoO0o / i1IIi * Oo0Ooo - oO0o0ooO0
 if 51 - 51: II111iiii * OoO0O00 % o0oOOo0O0Ooo * II111iiii % I1ii11iIi11i / IIII
iIIIIii1 = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/map-cache" ) . format ( OO00o0OOO0 , Ii1iIIIi1ii , o0oo0o0O00OO , o0oO )
if 58 - 58: i11iIiiIii % OoOO
OO00Oo = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/system" ) . format ( OO00o0OOO0 , Ii1iIIIi1ii , o0oo0o0O00OO , o0oO )
if 51 - 51: o00O0oo * o0oOOo0O0Ooo + OoOO + OoO0O00
if 66 - 66: OoOoOO00
if 97 - 97: OOooOOo % o00O0oo * o00O0oo
o0oo0o0O00OO = iiIIIIi1i1 ( "{}:{}" . format ( o0oo0o0O00OO , o0oO ) )
if 39 - 39: OoOO0ooOOoo0O % o00O0oo
i111IiI1I = getoutput ( iIIIIii1 )
if ( i111IiI1I == None or i111IiI1I == "" ) :
 print ( "No curl output returned on {}" . format ( o0oo0o0O00OO ) )
 exit ( 1 )
 if 70 - 70: OoOO0ooOOoo0O . Oo0Ooo / o0oOOo0O0Ooo . OoOO0ooOOoo0O - O0 / o00O0oo
if ( i111IiI1I . find ( "not-auth" ) != - 1 ) :
 print ( "Authentication failed on {}" . format ( o0oo0o0O00OO ) )
 exit ( 1 )
 if 62 - 62: iIii1I11I1II1 * OoOoOO00
try :
 i1 = json . loads ( i111IiI1I )
except :
 print ( "Curl output did not return JSON" )
 exit ( 1 )
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - o0000oOoOoO0o / OoooooooOO
 if 39 - 39: I1ii11iIi11i / IIII - II111iiii
 if 98 - 98: I1ii11iIi11i / OoOO % OOooOOo . OoOoOO00
 if 91 - 91: OOooOOo % Oo0Ooo
 if 64 - 64: OoOO % o0000oOoOoO0o - oO0o0ooO0 - OOooOOo
i111IiI1I = getoutput ( OO00Oo )
if ( i111IiI1I == None or i111IiI1I == "" ) :
 print ( "Could not get hostname on {}" . format ( o0oo0o0O00OO ) )
 exit ( 1 )
 if 31 - 31: OoOO - II111iiii . OoOO
OO00Oo = json . loads ( i111IiI1I )
i1I11i1I = o000o0o00o0Oo ( OO00Oo [ "hostname" ] )
if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1 * o00O0oo * IIII % IIII
print ( "\nLISP Map-Cache for {}, hostname {}, release {}\n" . format ( o0oo0o0O00OO ,
 i1I11i1I , OO00Oo [ "lisp-version" ] ) )
if 81 - 81: i11iIiiIii % OoOoOO00 - ii11ii1ii
if ( len ( i1 ) == 0 ) :
 print ( "Map-cache is empty" )
 exit ( 0 )
 if 68 - 68: oO0o0ooO0 % i1IIi . o00O0oo . I1ii11iIi11i
 if 92 - 92: o0000oOoOoO0o . oO0o0ooO0
i1i = False
for iiI111I1iIiI in i1 :
 IIIi1I1IIii1II = iiI111I1iIiI [ "eid-prefix" ]
 O0ii1ii1ii = iiI111I1iIiI [ "group-prefix" ] if "group-prefix" in iiI111I1iIiI else ""
 if ( o00oOO0 and ( IIIi1I1IIii1II + O0ii1ii1ii ) . find ( o00oOO0 ) == - 1 ) : continue
 if 91 - 91: o00O0oo
 i1i = True
 if ( "group-prefix" in iiI111I1iIiI ) : IIIi1I1IIii1II = "({}, {})" . format ( IIIi1I1IIii1II , iiI111I1iIiI [ "group-prefix" ] )
 IIIi1I1IIii1II = II1i ( "[{}]{}" . format ( iiI111I1iIiI [ "instance-id" ] , IIIi1I1IIii1II ) )
 IIIi1I1IIii1II = "EID {}," . format ( IIIi1I1IIii1II )
 if 15 - 15: II111iiii
 Ii = iiI111I1iIiI [ "ttl" ]
 if ( Ii == "--" ) :
  Ii = "never"
 else :
  ooo0O , oOoO0o00OO0 = Ii . split ( "." )
  if ( int ( ooo0O ) != 0 ) :
   Ii = ooo0O + "m"
  else :
   Ii = float ( oOoO0o00OO0 ) / 100 * 60
   Ii = str ( int ( Ii ) ) + "s"
   if 7 - 7: ii11ii1ii + oO0o0ooO0 + O0
   if 9 - 9: II111iiii . o0oOOo0O0Ooo - IIII / o0oOOo0O0Ooo
   if 46 - 46: OoOO . ii11ii1ii * OoOO % i1IIi
 iIIiII = "uptime {}, ttl {}" . format ( iiI111I1iIiI [ "uptime" ] , Ii )
 ii1ii11IIIiiI = iiI111I1iIiI [ "action" ]
 iIIiII += ", action {}" . format ( iiIIIIi1i1 ( ii1ii11IIIiiI ) ) if ii1ii11IIIiiI != "no-action" else ""
 if 67 - 67: OoOO * OOooOOo * I1ii11iIi11i + ii11ii1ii / i1IIi
 if ( I1IiI and "eid-memory" in iiI111I1iIiI ) : iIIiII += ", " + iiI111I1iIiI [ "eid-memory" ]
 if 11 - 11: OoOO0ooOOoo0O + o0000oOoOoO0o - IIII * OOooOOo % i11iIiiIii - oO0o0ooO0
 print ( IIIi1I1IIii1II , iIIiII )
 if 83 - 83: OoOO / I1IiiI
 if 34 - 34: o00O0oo
 if 57 - 57: OOooOOo . OoOO . i1IIi
 if 42 - 42: OoOO + I1ii11iIi11i % O0
 if 6 - 6: OOooOOo
 oOOo0oOo0 = [ ]
 for i1iIIi1 in iiI111I1iIiI [ "rloc-set" ] :
  if ( "multicast-rloc-set" in i1iIIi1 ) :
   oOOo0oOo0 += i1iIIi1
   for IIooooo in i1iIIi1 [ "multicast-rloc-set" ] :
    IIooooo [ "mrloc" ] = True
    oOOo0oOo0 . append ( IIooooo )
    if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % o0000oOoOoO0o * o00O0oo . i11iIiiIii
   continue
   if 2 - 2: I1ii11iIi11i * OoOO - iIii1I11I1II1 + I1IiiI . OOooOOo % o0000oOoOoO0o
  if ( "rle" in i1iIIi1 ) :
   for IIooooo in i1iIIi1 [ "rle" ] . values ( ) :
    IIooooo [ "rle-node" ] = True
    oOOo0oOo0 . append ( IIooooo )
   continue
   if 92 - 92: o0000oOoOoO0o
  oOOo0oOo0 . append ( i1iIIi1 )
  if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
  if 12 - 12: I1IiiI * o0000oOoOoO0o % i1IIi % iIii1I11I1II1
 for IIooooo in oOOo0oOo0 :
  IIi1I11I1II = "RLOC"
  if ( "mrloc" in IIooooo ) : IIi1I11I1II = "mRLOC"
  if ( "rle-node" in IIooooo ) : IIi1I11I1II = "RLE"
  if 63 - 63: OoooooooOO - OoO0O00 . II111iiii / o0oOOo0O0Ooo . OoOoOO00 / O0
  o0OOOO00O0Oo = IIooooo [ "address" ]
  if ( "encap-port" in IIooooo ) : o0OOOO00O0Oo += ":{}" . format ( IIooooo [ "encap-port" ] )
  ii = IIooooo [ "state" ]
  ii = II1i ( ii ) if ii == "up-state" else Oooo0000 ( ii )
  oOooOOOoOo = Oooo0000 ( o0OOOO00O0Oo )
  if 41 - 41: OoOO0ooOOoo0O - O0 - O0
  o0OOOO00O0Oo = "  {} {}, state {} since {}" . format ( IIi1I11I1II , oOooOOOoOo , ii , IIooooo [ "uptime" ] )
  if ( "encap-crypto" in IIooooo ) :
   o0OOOO00O0Oo += ", {}" . format ( IIooooo [ "encap-crypto" ] )
   if 68 - 68: ii11ii1ii % oO0o0ooO0
  if ( "rloc-name" in IIooooo ) :
   o0OOOO00O0Oo += ", {}" . format ( o000o0o00o0Oo ( IIooooo [ "rloc-name" ] ) )
   if 88 - 88: iIii1I11I1II1 - IIII + ii11ii1ii
  if ( I1IiI and "rloc-memory" in IIooooo ) : o0OOOO00O0Oo += ", " + IIooooo [ "rloc-memory" ]
  if 40 - 40: I1IiiI * OoOO0ooOOoo0O + ii11ii1ii % o0000oOoOoO0o
  print ( o0OOOO00O0Oo )
  print ( "    {}" . format ( OO ( IIooooo ) ) )
  i1iiIII111ii , OOOOOoo0 , ii1 = i11IiIiiIIIII ( IIooooo )
  print ( "    rtts {}, hops {}, latencies {}" . format ( i1iiIII111ii , OOOOOoo0 , ii1 ) )
  if 11 - 11: o00O0oo * I1IiiI . iIii1I11I1II1 % OoooooooOO + o0000oOoOoO0o
 print ( )
 if 78 - 78: OoO0O00 . ii11ii1ii + OoO0O00 / OoOO / OoO0O00
 if 54 - 54: OoOoOO00 % o0000oOoOoO0o
 if 37 - 37: OoOoOO00 * Oo0Ooo / IIII - o0000oOoOoO0o % II111iiii . OOooOOo
 if 88 - 88: o0000oOoOoO0o . II111iiii * II111iiii % oO0o0ooO0
 if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
if ( o00oOO0 and i1i == False ) :
 print ( "EID {} not in map-cache" . format ( II1i ( o00oOO0 ) ) )
 if 6 - 6: IIII / i11iIiiIii + o0000oOoOoO0o * OOooOOo
 if 80 - 80: II111iiii
exit ( 0 )
if 83 - 83: OoOO . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * OoOO
if 53 - 53: II111iiii
if 31 - 31: OoO0O00
if 80 - 80: oO0o0ooO0 . i11iIiiIii - o0oOOo0O0Ooo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
