#!/usr/bin/python
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
# loc8tr.py - Locator Traceroute - Traceroute paths to LISP RLOCs
#
# Last update: Wed Sep 26 14:13:59 PDT 2018
#
# Usage: python loc8tr.py [-n] [-d] [-hp <host>:<port>]
#                                   [-up <username>:<password>]
#
#   -n:
#       Do not do DNS lookups on traceroute hops
#   -d:
#       Produce more output.
#   -hp <host>:<port>:
#       Host address and Port number to get to lispers.net restful API.
#   -up <username>:<password>:
#       Supply username and password for lispers.net map-cache query.
#
# This application is run on an xTR. Typically a ITR or RTR so the map-cache
# can be retreived to find all the active RLOCs being used for each map-cache
# entry. The applicaiton assumes the lispers.net xTR implementation is running
# and retrieves the map-cache using this restful interface:
#
# curl --silent --insecure -u "root:" \
#      https://localhost:8080/lisp/api/data/map-cache
#
# The app will do some JSON fetching and build an RLOC data structure to
# start traceroute to each RLOC. It will then put the results in a local
# file system to be viewed later.
#
# This app will create a directory in the current directory named:
#
#     loc8ator-<data>-<time>
#
# And creates 3 files:
#
# loc8tr.log     - Output from this script in human readable form.
# loc8tr.json    - JSON for the RLOC-cache
# loc8tr-mc.json - JSON for the data pulled from the lispers.net xTR
#
# Most output is self-explanatory. You will find that a green "!" means the
# traceroute made it to the RLOC. You will find a red "X", the traceroute
# fell short of finding the RLOC.
#
if 64 - 64: i11iIiiIii
import commands
import json
import sys
import socket
import os
import datetime
import string
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
ooO0oo0oO0 = "root:"
if ( "-up" in sys . argv ) :
 ooO0oo0oO0 = sys . argv . index ( "-up" )
 ooO0oo0oO0 = sys . argv [ ooO0oo0oO0 + 1 ]
 oo00 = ooO0oo0oO0 . split ( ":" )
 if ( len ( oo00 ) == 1 ) :
  print "Invalid syntax for username:password pair"
  exit ( 1 )
  if 88 - 88: iII111i . oO0o % ooOoO0o
  if 66 - 66: iII111i
  if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . II111iiii - oO0o
ooO00oOoo = "localhost:8080"
if ( "-hp" in sys . argv ) :
 ooO00oOoo = sys . argv . index ( "-hp" )
 ooO00oOoo = sys . argv [ ooO00oOoo + 1 ]
 oo00 = ooO00oOoo . split ( ":" )
 if ( len ( oo00 ) == 1 or oo00 [ 1 ] . isdigit ( ) == False ) :
  print "Invalid syntax for host:port pair"
  exit ( 1 )
  if 78 - 78: I11i / OoO0O00 - O0 . IiII
  if 91 - 91: I1ii11iIi11i * iIii1I11I1II1 . IiII / Ii1I
Ooo0 = 'curl --silent --insecure -u "{}" https://{}/lisp/api/data/map-cache' . format ( ooO0oo0oO0 , ooO00oOoo )
if 89 - 89: OoooooooOO - IiII * ooOoO0o
if 82 - 82: I11i . I1Ii111 / IiII % II111iiii % iIii1I11I1II1 % IiII
if 86 - 86: OoOoOO00 % I1IiiI
if 80 - 80: OoooooooOO . I1IiiI
OOO0O = "traceroute -n -m 15 -q 1 -w 1 {}"
if 94 - 94: ooOoO0o
if 18 - 18: iIii1I11I1II1 / I11i + oO0o / Oo0Ooo - II111iiii - I11i
if 1 - 1: I11i - OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
i11IiIiiIIIII = datetime . datetime . now ( ) . strftime ( "%m-%d-%y-%H-%M-%S" )
i1iiIII111ii = "loc8tr-{}" . format ( i11IiIiiIIIII )
i1iIIi1 = "loc8tr.log"
ii11iIi1I = "loc8tr.json"
iI111I11I1I1 = "loc8tr-mc.json"
if 55 - 55: OoOoOO00 % i1IIi / Ii1I - oO0o - O0 / II111iiii
if 28 - 28: iIii1I11I1II1 - i1IIi
if 70 - 70: OoO0O00 . OoO0O00 - OoO0O00 / I1ii11iIi11i * OOooOOo
if 86 - 86: i11iIiiIii + Ii1I + ooOoO0o * I11i + o0oOOo0O0Ooo
if 61 - 61: OoO0O00 / i11iIiiIii
if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - I1ii11iIi11i + i11iIiiIii
if 65 - 65: OoOoOO00
if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
if 100 - 100: Ii1I - Ii1I - I1Ii111
ii1 = { }
o0oO0o00oo = 0
II1i1Ii11Ii11 = 1
iII11i = 2
O0O00o0OOO0 = 3
Ii1iIIIi1ii = 4
if 80 - 80: I11i * i11iIiiIii / I1Ii111
I11II1i = ( "-n" in sys . argv )
IIIII = ( "-d" in sys . argv )
if 75 - 75: II111iiii % II111iiii
if 13 - 13: o0oOOo0O0Ooo . Ii1I
if 19 - 19: I11i + ooOoO0o
if 53 - 53: OoooooooOO . i1IIi
if 18 - 18: o0oOOo0O0Ooo
if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
if 95 - 95: OoO0O00 % oO0o . O0
if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
if 53 - 53: IiII + I1IiiI * oO0o
if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
if 60 - 60: I11i / I11i
def I1II1III11iii ( tr ) :
 Oo000 = [ ]
 for oo in tr . split ( "\n" ) [ 1 : : ] :
  ii11I = oo . split ( )
  if ( ii11I [ 1 ] . find ( "Invalid" ) != - 1 ) :
   Oo000 . append ( [ "?" , "?" ] )
   continue
   if 96 - 96: II111iiii % Ii1I . OOooOOo + OoooooooOO * oO0o - OoOoOO00
  Oo000 . append ( [ ii11I [ 1 ] , ii11I [ - 2 ] ] )
  if 10 - 10: OOooOOo / I1IiiI * OOooOOo
 return ( Oo000 )
 if 29 - 29: I1ii11iIi11i % I1IiiI + ooOoO0o / o0oOOo0O0Ooo + OOooOOo * o0oOOo0O0Ooo
 if 42 - 42: Ii1I + oO0o
 if 76 - 76: I1Ii111 - OoO0O00
 if 70 - 70: ooOoO0o
 if 61 - 61: I1ii11iIi11i . I1ii11iIi11i
 if 10 - 10: OoOoOO00 * iII111i . I11i + II111iiii - ooOoO0o * i1IIi
 if 56 - 56: o0oOOo0O0Ooo * IiII * II111iiii
 if 80 - 80: o0oOOo0O0Ooo * II111iiii % II111iiii
def OoOOOOO ( ) :
 os . system ( "mkdir {}" . format ( i1iiIII111ii ) )
 os . system ( "touch {}/" . format ( i1iiIII111ii , i1iIIi1 ) )
 os . system ( "touch {}/" . format ( i1iiIII111ii , ii11iIi1I ) )
 os . system ( "touch {}/" . format ( i1iiIII111ii , iI111I11I1I1 ) )
 if 33 - 33: I1ii11iIi11i % i1IIi
 if 78 - 78: I11i
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
 if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
 if 16 - 16: I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
 if 44 - 44: oO0o
def o0o0oOoOO0 ( string ) :
 print string
 sys . stdout . flush ( )
 if 17 - 17: IiII
 ooOooo000oOO = open ( "./{}/{}" . format ( i1iiIII111ii , i1iIIi1 ) , "a" )
 ooOooo000oOO . write ( string + "\n" )
 ooOooo000oOO . close ( )
 if 59 - 59: II111iiii + OoooooooOO * OoOoOO00 + i1IIi
 if 58 - 58: II111iiii * OOooOOo * I1ii11iIi11i / OOooOOo
 if 75 - 75: oO0o
 if 50 - 50: Ii1I / Oo0Ooo - oO0o - I11i % iII111i - oO0o
 if 91 - 91: OoO0O00 / I11i - II111iiii . I11i
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
def ii111111I1iII ( addr ) :
 if ( addr . count ( "." ) == 3 ) :
  addr = addr . split ( "." )
  for O00ooo0O0 in addr :
   if ( O00ooo0O0 . isdigit ( ) == False ) : return ( False )
   if 23 - 23: iII111i
  return ( True )
  if 91 - 91: iIii1I11I1II1 + I1Ii111
 if ( addr . find ( ":" ) != - 1 ) :
  addr = addr . replace ( ":" , "" )
  for O00ooo0O0 in addr :
   if ( O00ooo0O0 not in string . hexdigits ) : return ( False )
   if 31 - 31: IiII . OoOoOO00 . OOooOOo
  return ( True )
  if 75 - 75: I11i + OoO0O00 . OoOoOO00 . ooOoO0o + Oo0Ooo . OoO0O00
 return ( False )
 if 96 - 96: OOooOOo . ooOoO0o - Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * OOooOOo
 if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
def iii1i1iiiiIi ( string ) :
 return ( "\033[92m" + string + "\033[0m" )
 if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
 if 52 - 52: o0oOOo0O0Ooo
def o0OO0oOO0O0 ( string ) :
 return ( "\033[91m" + string + "\033[0m" )
 if 8 - 8: oO0o
 if 7 - 7: o0oOOo0O0Ooo - I1IiiI
def OOo00O0 ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 73 - 73: i1IIi + I1IiiI
 if 46 - 46: OoO0O00 . Oo0Ooo - OoooooooOO
 if 93 - 93: iII111i
 if 10 - 10: I11i
 if 82 - 82: I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
 if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 if 83 - 83: I11i / I1IiiI
 if 34 - 34: IiII
OoOOOOO ( )
if 57 - 57: oO0o . I11i . i1IIi
if 42 - 42: I11i + I1ii11iIi11i % O0
if 6 - 6: oO0o
if 68 - 68: OoOoOO00 - OoO0O00
if ( IIIII ) : o0o0oOoOO0 ( "Run '{}' ..." . format ( OOo00O0 ( Ooo0 ) ) )
IIi = commands . getoutput ( Ooo0 )
if ( IIIII ) : o0o0oOoOO0 ( "curl returned '{}'" . format ( IIi ) )
if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
if ( IIi == "" ) :
 o0o0oOoOO0 ( "curl returned empty string" )
 exit ( 1 )
 if 31 - 31: II111iiii . I1IiiI
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
IIi = json . loads ( IIi )
if ( type ( IIi ) != list ) :
 o0o0oOoOO0 ( "Could not retrieve map-cache" )
 exit ( 1 )
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
if ( IIi == [ ] ) :
 o0o0oOoOO0 ( "No map-cache entries returned" )
 exit ( 1 )
 if 92 - 92: iII111i
if ( len ( IIi ) == 1 and IIi [ 0 ] . has_key ( "?" ) ) :
 o0o0oOoOO0 ( "Authentication failed while retrieving map-cache" )
 exit ( 1 )
 if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
for IIIII11I1IiI in IIi :
 i1I = "[{}]{}" . format ( IIIII11I1IiI [ "instance-id" ] , IIIII11I1IiI [ "eid-prefix" ] )
 for OoOO in IIIII11I1IiI [ "rloc-set" ] :
  ooOOO0 = OoOO [ "address" ]
  if ( ii111111I1iII ( ooOOO0 ) == False ) : continue
  if ( ii1 . has_key ( ooOOO0 ) == False ) :
   o0o = [ ]
   for O0OOoO00OO0o in OoOO [ "recent-rloc-probe-rtts" ] : o0o . append ( float ( O0OOoO00OO0o ) )
   Oo000 = [ ]
   for I1111IIIIIi in OoOO [ "recent-rloc-hop-counts" ] : Oo000 . append ( str ( I1111IIIIIi ) )
   ii1 [ ooOOO0 ] = [ None , [ ] , o0o , Oo000 , [ ] ]
   if 22 - 22: i1IIi + O0 . iIii1I11I1II1 * iII111i % i11iIiiIii * I1IiiI
  ii1 [ ooOOO0 ] [ Ii1iIIIi1ii ] . append ( i1I )
  if 77 - 77: Oo0Ooo
  if 17 - 17: iII111i % OoO0O00 . OOooOOo + OoO0O00 / II111iiii
  if 75 - 75: I1IiiI - OoOoOO00 % iII111i
o0o0oOoOO0 ( "Found {} map-cache entries with {} distinct RLOC(s):" . format ( len ( IIi ) , len ( ii1 ) ) )
if 37 - 37: OoOoOO00 * Oo0Ooo / ooOoO0o - iII111i % II111iiii . oO0o
if 88 - 88: iII111i . II111iiii * II111iiii % I1Ii111
if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
if 80 - 80: II111iiii
for O0O in ii1 :
 OoOO = ii1 [ O0O ]
 o0o = OoOO [ iII11i ]
 Oo000 = OoOO [ O0O00o0OOO0 ]
 i1I1I = OoOO [ Ii1iIIIi1ii ]
 o0o0oOoOO0 ( "RLOC {}, rtts(secs) {}, hops {}" . format ( OOo00O0 ( O0O ) , o0o , Oo000 ) )
 o0o0oOoOO0 ( "     EIDs: {}" . format ( i1I1I ) )
 if 12 - 12: i11iIiiIii / OoO0O00
o0o0oOoOO0 ( "" )
if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
if 25 - 25: OoO0O00
if 62 - 62: OOooOOo + O0
if 98 - 98: o0oOOo0O0Ooo
for O0O in ii1 :
 OOOO0oo0 = OOO0O . format ( O0O )
 o0o0oOoOO0 ( "Run {} ..." . format ( OOo00O0 ( OOOO0oo0 ) ) )
 if 35 - 35: Ii1I - I1IiiI % o0oOOo0O0Ooo . OoooooooOO % Ii1I
 I1i1Iiiii = commands . getoutput ( OOOO0oo0 )
 if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 OoOO = ii1 [ O0O ]
 OoOO [ o0oO0o00oo ] = I1i1Iiiii
 OoOO [ II1i1Ii11Ii11 ] = I1II1III11iii ( OoOO [ o0oO0o00oo ] )
 if ( I11II1i ) : oO0 = "-"
 if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
 for I1111IIIIIi in OoOO [ II1i1Ii11Ii11 ] :
  oO = str ( OoOO [ II1i1Ii11Ii11 ] . index ( I1111IIIIIi ) + 1 ) . rjust ( 2 )
  if ( I1111IIIIIi [ 0 ] == "?" ) :
   I1111IIIIIi [ 0 ] = I1111IIIIIi [ 1 ] = oO0 = "?"
   if 31 - 31: OOooOOo + i11iIiiIii + Oo0Ooo * ooOoO0o
  if ( I11II1i == False ) :
   try : oO0 = socket . gethostbyaddr ( I1111IIIIIi [ 0 ] ) [ 0 ]
   except : oO0 = "?"
   if 28 - 28: O0 * Oo0Ooo - OOooOOo % iIii1I11I1II1 * Ii1I - i11iIiiIii
   if 7 - 7: Oo0Ooo + oO0o - I1Ii111 % Ii1I + I1ii11iIi11i
  ooo0OOOoo = "" if ( I1111IIIIIi != OoOO [ II1i1Ii11Ii11 ] [ - 1 ] ) else OOo00O0 ( iii1i1iiiiIi ( "!" ) ) if ( I1111IIIIIi [ 0 ] == O0O ) else OOo00O0 ( o0OO0oOO0O0 ( "X" ) )
  if 45 - 45: I1Ii111 / iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . iII111i
  if 32 - 32: o0oOOo0O0Ooo . IiII * I11i
  if ( I1111IIIIIi [ 0 ] == "*" ) :
   o0o0oOoOO0 ( "{}  * {}" . format ( oO , ooo0OOOoo ) )
   continue
   if 93 - 93: o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
   if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
  o0o0oOoOO0 ( "{}  {} ({}), rtt {}ms {}" . format ( oO , I1111IIIIIi [ 0 ] , oO0 , I1111IIIIIi [ 1 ] ,
 ooo0OOOoo ) )
  if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 o0o0oOoOO0 ( "" )
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
o0o0oOoOO0 ( "Log and JSON files created in directory ./{}" . format ( OOo00O0 ( i1iiIII111ii ) ) )
if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
if 63 - 63: OoOoOO00 * iII111i
if 69 - 69: O0 . OoO0O00
ooOooo000oOO = open ( "{}/{}" . format ( i1iiIII111ii , ii11iIi1I ) , "a" )
ooOooo000oOO . write ( json . dumps ( ii1 ) )
ooOooo000oOO . close ( )
if 49 - 49: I1IiiI - I11i
ooOooo000oOO = open ( "{}/{}" . format ( i1iiIII111ii , iI111I11I1I1 ) , "a" )
ooOooo000oOO . write ( json . dumps ( IIi ) )
ooOooo000oOO . close ( )
if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
exit ( 0 )
if 62 - 62: OoooooooOO * I1IiiI
if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
