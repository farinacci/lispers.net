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
def o000o0o00o0Oo ( rloc ) :
 ooIiII1I1i1i1ii = str ( rloc [ "recent-rloc-probe-rtts" ] ) . replace ( "u'" , "" )
 ooIiII1I1i1i1ii = ooIiII1I1i1i1ii . replace ( "'" , "" )
 IIIII = str ( rloc [ "recent-rloc-hop-counts" ] ) . replace ( "u'" , "" )
 IIIII = IIIII . replace ( "'" , "" )
 I1 = str ( rloc [ "recent-rloc-probe-latencies" ] ) . replace ( "u'" , "" )
 I1 = I1 . replace ( "'" , "" )
 return ( ooIiII1I1i1i1ii , IIIII , I1 )
 if 54 - 54: iII111i % O0 + oo - ooOoO0o / IiII
 if 31 - 31: ooOO00oOo + II111iiii
def i11IiIiiIIIII ( rr ) :
 i1iiIII111ii = rr [ "stats" ]
 i1iIIi1 = ( "recent-packet-sec" in rr and rr [ "recent-packet-sec" ] )
 ii11iIi1I = ( "recent-packet-min" in rr and rr [ "recent-packet-min" ] )
 if ( i1iIIi1 or ii11iIi1I ) :
  iI111I11I1I1 = i1iiIII111ii . split ( ": " )
  OOooO0OOoo = iI111I11I1I1 [ 1 ] . split ( "," )
  iIii1 = Oooo0000 ( OOooO0OOoo [ 0 ] ) if i1iIIi1 else Ii1I ( OOooO0OOoo [ 0 ] )
  OOooO0OOoo [ 0 ] = iIii1
  iI111I11I1I1 [ 1 ] = "," . join ( OOooO0OOoo )
  i1iiIII111ii = ": " . join ( iI111I11I1I1 )
  if 71 - 71: ooOO00oOo
 return ( i1iiIII111ii )
 if 55 - 55: ooOO00oOo / oOoO0oo0OOOo * iII111i
 if 86 - 86: i11iIiiIii + I1Ii111 + IIII * IiII + Ooo00oOo00o
 if 61 - 61: ooOO00oOo / i11iIiiIii
 if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - oOoO0oo0OOOo + i11iIiiIii
if ( "help" in sys . argv ) :
 print ( "Usage: ./mc [<user:pw@host:port> | <host:port> | <host> | help]" )
 exit ( 0 )
 if 65 - 65: oOo0O0Ooo
 if 6 - 6: oo / OoO0O00 % I1Ii111
ooOO0O00 = "root"
ii1 = ""
o0oO0o00oo = "localhost"
II1i1Ii11Ii11 = "8080"
if 35 - 35: Ooo00oOo00o + ooOoO0o + ooOoO0o
if 11 - 11: ooOoO0o - ooOO00oOo % IIII % ooOoO0o / oOo0O0Ooo - ooOO00oOo
if 74 - 74: ooOoO0o * O0
if 89 - 89: iiiiIi11i + OoO0O00
if 3 - 3: i1IIi / oo % IiII * i11iIiiIii / O0 * IiII
if 49 - 49: iiiiIi11i % I1Ii111 + i1IIi . oo % oOoO0oo0OOOo
if 48 - 48: IiII + IiII / II111iiii / iIii1I11I1II1
i1iiI11I = sys . argv [ - 1 ]
for iiii in i1iiI11I . split ( "." ) :
 if ( iiii . isdigit ( ) ) : continue
 i1iiI11I = None
 break
 if 54 - 54: oOoO0oo0OOOo * iII111i
if ( i1iiI11I == None ) :
 i1iiI11I = sys . argv [ - 1 ]
 for iiii in i1iiI11I . split ( ":" ) :
  if ( iiii == "" ) : continue
  try :
   int ( iiii , 16 )
   continue
  except :
   i1iiI11I = None
   break
   if 13 - 13: o00O0oo + oOo0O0Ooo - OoooooooOO + oO0o0ooO0 . ooOoO0o + ooOO00oOo
   if 8 - 8: iIii1I11I1II1 . oo - iIii1I11I1II1 * I1Ii111
   if 61 - 61: Ooo00oOo00o / ooOO00oOo + IIII * iiiiIi11i / iiiiIi11i
if ( i1iiI11I != None ) : sys . argv = sys . argv [ 0 : - 1 ]
if 75 - 75: i1IIi / OoooooooOO - O0 / oOo0O0Ooo . II111iiii - i1IIi
if 71 - 71: iII111i + I1Ii111 * iII111i - ooOO00oOo * Ooo00oOo00o
if 65 - 65: O0 % oo . oOoO0oo0OOOo % iIii1I11I1II1 / iII111i % oO0o0ooO0
if 51 - 51: i11iIiiIii . oo + II111iiii
if ( len ( sys . argv ) == 2 ) :
 II111ii1II1i = sys . argv [ 1 ]
 II111ii1II1i = II111ii1II1i . split ( "@" )
 if ( len ( II111ii1II1i ) == 2 ) :
  OoOo00o = II111ii1II1i [ 0 ] . split ( ":" )
  if ( OoOo00o [ 0 ] != "" ) : ooOO0O00 = OoOo00o [ 0 ]
  if ( len ( OoOo00o ) == 2 and OoOo00o [ 1 ] != "" ) : ii1 = OoOo00o [ 1 ]
  II111ii1II1i = II111ii1II1i [ 1 ]
 else :
  II111ii1II1i = II111ii1II1i [ 0 ]
  if 70 - 70: ooOoO0o * oOoO0oo0OOOo
 i1II1 = II111ii1II1i . split ( ":" )
 if ( i1II1 [ 0 ] != "" ) : o0oO0o00oo = i1II1 [ 0 ]
 if ( len ( i1II1 ) == 2 and i1II1 [ 1 ] != "" ) : II1i1Ii11Ii11 = i1II1 [ 1 ]
 if 66 - 66: OoooooooOO + I1Ii111 + I1Ii111 - i1IIi
 if 55 - 55: iII111i + IIII . i1IIi - oOoO0oo0OOOo . O0 - IIII
o0O = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/map-cache" ) . format ( ooOO0O00 , ii1 , o0oO0o00oo , II1i1Ii11Ii11 )
if 72 - 72: ooOoO0o / i1IIi * OoO0O00 - oO0o0ooO0
Oo0O0O0ooO0O = ( "curl --silent --insecure -u {}:{} https://{}:{}/lisp/" + "api/data/system" ) . format ( ooOO0O00 , ii1 , o0oO0o00oo , II1i1Ii11Ii11 )
if 15 - 15: oOoO0oo0OOOo + oOo0O0Ooo - OoooooooOO / iII111i
if 58 - 58: i11iIiiIii % IiII
if 71 - 71: iII111i + IIII % i11iIiiIii + oOoO0oo0OOOo - o00O0oo
o0oO0o00oo = Oooo0000 ( "{}:{}" . format ( o0oO0o00oo , II1i1Ii11Ii11 ) )
if 88 - 88: oOo0O0Ooo - ooOO00oOo % iII111i
iI1I111Ii111i = getoutput ( o0O )
if ( iI1I111Ii111i == None or iI1I111Ii111i == "" ) :
 print ( "No curl output returned on {}" . format ( o0oO0o00oo ) )
 exit ( 1 )
 if 7 - 7: IIII * ooOO00oOo % iiiiIi11i . o00O0oo
if ( iI1I111Ii111i . find ( "not-auth" ) != - 1 ) :
 print ( "Authentication failed on {}" . format ( o0oO0o00oo ) )
 exit ( 1 )
 if 45 - 45: i11iIiiIii * II111iiii % iIii1I11I1II1 + oOoO0oo0OOOo - I1Ii111
try :
 iIi1iIiii111 = json . loads ( iI1I111Ii111i )
except :
 print ( "Curl output did not return JSON" )
 exit ( 1 )
 if 16 - 16: oOoO0oo0OOOo + ooOO00oOo - II111iiii
 if 85 - 85: oOo0O0Ooo + i1IIi
 if 58 - 58: II111iiii * iII111i * oOoO0oo0OOOo / iII111i
 if 75 - 75: iiiiIi11i
 if 50 - 50: I1Ii111 / OoO0O00 - iiiiIi11i - IiII % ooOoO0o - iiiiIi11i
iI1I111Ii111i = getoutput ( Oo0O0O0ooO0O )
if ( iI1I111Ii111i == None or iI1I111Ii111i == "" ) :
 print ( "Could not get hostname on {}" . format ( o0oO0o00oo ) )
 exit ( 1 )
 if 91 - 91: ooOO00oOo / IiII - II111iiii . IiII
Oo0O0O0ooO0O = json . loads ( iI1I111Ii111i )
i1I11i1I = ooO0oooOoO0 ( Oo0O0O0ooO0O [ "hostname" ] )
if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1 * o00O0oo * IIII % IIII
print ( "\nLISP Map-Cache for {}, hostname {}, release {}\n" . format ( o0oO0o00oo ,
 i1I11i1I , Oo0O0O0ooO0O [ "lisp-version" ] ) )
if 81 - 81: i11iIiiIii % oOo0O0Ooo - iII111i
if ( len ( iIi1iIiii111 ) == 0 ) :
 print ( "Map-cache is empty" )
 exit ( 0 )
 if 68 - 68: oO0o0ooO0 % i1IIi . o00O0oo . oOoO0oo0OOOo
 if 92 - 92: ooOoO0o . oO0o0ooO0
i1i = False
for iiI111I1iIiI in iIi1iIiii111 :
 II = iiI111I1iIiI [ "eid-prefix" ]
 Ii1I1IIii1II = iiI111I1iIiI [ "group-prefix" ] if "group-prefix" in iiI111I1iIiI else ""
 if ( i1iiI11I and ( II + Ii1I1IIii1II ) . find ( i1iiI11I ) == - 1 ) : continue
 if 65 - 65: I1Ii111 . iIii1I11I1II1 / O0 - I1Ii111
 i1i = True
 if ( "group-prefix" in iiI111I1iIiI ) : II = "({}, {})" . format ( II , iiI111I1iIiI [ "group-prefix" ] )
 II = IiII1IiiIiI1 ( "[{}]{}" . format ( iiI111I1iIiI [ "instance-id" ] , II ) )
 II = "EID {}," . format ( II )
 iii1i1iiiiIi = iiI111I1iIiI [ "ttl" ]
 iii1i1iiiiIi = "never" if ( iii1i1iiiiIi == "--" ) else iii1i1iiiiIi . split ( "." ) [ 0 ] + "m"
 Iiii = "uptime {}, ttl {}" . format ( iiI111I1iIiI [ "uptime" ] , iii1i1iiiiIi )
 OO0OoO0o00 = iiI111I1iIiI [ "action" ]
 Iiii += ", action {}" . format ( Oooo0000 ( OO0OoO0o00 ) ) if OO0OoO0o00 != "no-action" else ""
 print ( II , Iiii )
 if 53 - 53: O0 * ooOO00oOo + iII111i
 for ooIiII1I1i1i1ii in iiI111I1iIiI [ "rloc-set" ] :
  Ii = [ ooIiII1I1i1i1ii ]
  if ( "multicast-rloc-set" in ooIiII1I1i1i1ii ) : Ii += ooIiII1I1i1i1ii [ "multicast-rloc-set" ]
  if 61 - 61: II111iiii
  for O0OOO in Ii :
   if ( Ii . index ( O0OOO ) == 0 ) :
    II11iIiIIIiI = "RLOC"
   else :
    II11iIiIIIiI = "mRLOC"
    if 67 - 67: oO0o0ooO0 . ooOoO0o . O0
    if 10 - 10: oOoO0oo0OOOo % oOoO0oo0OOOo - iIii1I11I1II1 / iII111i + I1Ii111
   OOOOoOoo0O0O0 = O0OOO [ "address" ]
   if ( "rle" in O0OOO ) :
    OOOOoOoo0O0O0 = O0OOO [ "rle" ]
    II11iIiIIIiI = "RLE"
    if 85 - 85: iiiiIi11i % i11iIiiIii - ooOoO0o * OoooooooOO / oo % oo
   if ( "encap-port" in O0OOO ) : OOOOoOoo0O0O0 += ":{}" . format ( O0OOO [ "encap-port" ] )
   IIiIi1iI = O0OOO [ "state" ]
   IIiIi1iI = IiII1IiiIiI1 ( IIiIi1iI ) if IIiIi1iI == "up-state" else II1i ( IIiIi1iI )
   if 35 - 35: I1Ii111 % O0 - O0
   if 16 - 16: II111iiii % oOo0O0Ooo - II111iiii + I1Ii111
   if 12 - 12: iII111i / iII111i + i11iIiiIii
   if 40 - 40: oo . iIii1I11I1II1 / oo / i11iIiiIii
   if ( II11iIiIIIiI == "RLE" ) :
    o0O00o = ""
    o0 = OOOOoOoo0O0O0 . split ( "," )
    for O0Oooo0O in o0 :
     O0o = O0Oooo0O . split ( "(" )
     o0O00o += II1i ( O0o [ 0 ] )
     OoOooO = O0o [ 1 ] . replace ( ")" , "" )
     o0O00o += "(" + ooO0oooOoO0 ( OoOooO ) + "), "
     if 12 - 12: oo * ooOoO0o % i1IIi % iIii1I11I1II1
    o0O00o = o0O00o [ 0 : - 2 ]
   else :
    o0O00o = II1i ( OOOOoOoo0O0O0 )
    if 20 - 20: iII111i % I1Ii111 / I1Ii111 + I1Ii111
    if 45 - 45: iiiiIi11i - o00O0oo - OoooooooOO - ooOO00oOo . II111iiii / O0
   OOOOoOoo0O0O0 = "  {} {}, state {} since {}" . format ( II11iIiIIIiI , o0O00o ,
 IIiIi1iI , O0OOO [ "uptime" ] )
   if ( "encap-crypto" in O0OOO ) :
    OOOOoOoo0O0O0 += ", {}" . format ( O0OOO [ "encap-crypto" ] )
    if 51 - 51: O0 + ooOoO0o
   if ( "rloc-name" in O0OOO ) :
    OOOOoOoo0O0O0 += ", {}" . format ( ooO0oooOoO0 ( O0OOO [ "rloc-name" ] ) )
    if 8 - 8: iiiiIi11i * oOo0O0Ooo - I1Ii111 - ooOO00oOo * iII111i % oo
    if 48 - 48: O0
   print ( OOOOoOoo0O0O0 )
   print ( "    {}" . format ( i11IiIiiIIIII ( O0OOO ) ) )
   I1IiiI , IIi , i1Iii1i1I = o000o0o00o0Oo ( O0OOO )
   print ( "    rtts {}, hops {}, latencies {}" . format ( I1IiiI , IIi , i1Iii1i1I ) )
   if 91 - 91: oOoO0oo0OOOo + oo . iII111i * oOoO0oo0OOOo + oo * OoO0O00
   if 80 - 80: ooOoO0o % iII111i % iiiiIi11i - OoO0O00 + OoO0O00
 print ( )
 if 19 - 19: oOo0O0Ooo * i1IIi
 if 14 - 14: ooOoO0o
 if 11 - 11: o00O0oo * oo . iIii1I11I1II1 % OoooooooOO + ooOoO0o
 if 78 - 78: ooOO00oOo . iII111i + ooOO00oOo / IiII / ooOO00oOo
 if 54 - 54: oOo0O0Ooo % ooOoO0o
if ( i1iiI11I and i1i == False ) :
 print ( "EID {} not in map-cache" . format ( IiII1IiiIiI1 ( i1iiI11I ) ) )
 if 37 - 37: oOo0O0Ooo * OoO0O00 / IIII - ooOoO0o % II111iiii . iiiiIi11i
 if 88 - 88: ooOoO0o . II111iiii * II111iiii % oO0o0ooO0
exit ( 0 )
if 15 - 15: i1IIi * oo + i11iIiiIii
if 6 - 6: IIII / i11iIiiIii + ooOoO0o * iiiiIi11i
if 80 - 80: II111iiii
if 83 - 83: IiII . i11iIiiIii + II111iiii . Ooo00oOo00o * IiII
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
