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
#       Host address and Port number to get to lispers.net restful API. When
#       <port> is a negative number that means that http rather than https
#       is used.
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
ooO00oOoo = "https"
O0OOo = "localhost:8080"
if ( "-hp" in sys . argv ) :
 O0OOo = sys . argv . index ( "-hp" )
 O0OOo = sys . argv [ O0OOo + 1 ]
 oo00 = O0OOo . split ( ":" )
 if ( len ( oo00 ) == 1 ) :
  print "Invalid syntax for host:port pair"
  exit ( 1 )
  if 8 - 8: o0oOOo0O0Ooo * I1ii11iIi11i * iIii1I11I1II1 . IiII / IiII % IiII
 i11 = oo00 [ 1 ]
 if ( i11 [ 0 ] == "-" ) :
  ooO00oOoo = "http"
  i11 = i11 [ 1 : : ]
  if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
 if ( i11 . isdigit ( ) == False ) :
  print "Invalid syntax for port"
  exit ( 1 )
  if 74 - 74: iII111i * IiII
 O0OOo = oo00 [ 0 ] + ":" + i11
 if 82 - 82: iIii1I11I1II1 % IiII
oOo0oooo00o = 'curl --silent --insecure -u "{}" {}://{}/lisp/api/data/map-cache' . format ( ooO0oo0oO0 , ooO00oOoo , O0OOo )
if 65 - 65: o0oOOo0O0Ooo * iIii1I11I1II1 * ooOoO0o
if 18 - 18: iIii1I11I1II1 / I11i + oO0o / Oo0Ooo - II111iiii - I11i
if 1 - 1: I11i - OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
i11IiIiiIIIII = "traceroute -n -m 15 -q 1 -w 1 {}"
if 22 - 22: Ii1I * O0 / o0oOOo0O0Ooo
if 64 - 64: Ii1I % i1IIi % OoooooooOO
if 3 - 3: iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
oo0Ooo0 = datetime . datetime . now ( ) . strftime ( "%m-%d-%y-%H-%M-%S" )
I1I11I1I1I = "loc8tr-{}" . format ( oo0Ooo0 )
OooO0OO = "loc8tr.log"
iiiIi = "loc8tr.json"
IiIIIiI1I1 = "loc8tr-mc.json"
if 86 - 86: i11iIiiIii + Ii1I + ooOoO0o * I11i + o0oOOo0O0Ooo
if 61 - 61: OoO0O00 / i11iIiiIii
if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - I1ii11iIi11i + i11iIiiIii
if 65 - 65: OoOoOO00
if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
if 100 - 100: Ii1I - Ii1I - I1Ii111
if 20 - 20: OoooooooOO
if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
if 97 - 97: i11iIiiIii
II1i1Ii11Ii11 = { }
iII11i = 0
O0O00o0OOO0 = 1
Ii1iIIIi1ii = 2
o0oo0o0O00OO = 3
o0oO = 4
if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
i1iiI11I = ( "-n" in sys . argv )
iiii = ( "-d" in sys . argv )
if 54 - 54: I1ii11iIi11i * OOooOOo
if 13 - 13: IiII + OoOoOO00 - OoooooooOO + I1Ii111 . iII111i + OoO0O00
if 8 - 8: iIii1I11I1II1 . I1IiiI - iIii1I11I1II1 * Ii1I
if 61 - 61: o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * oO0o / oO0o
if 75 - 75: i1IIi / OoooooooOO - O0 / OoOoOO00 . II111iiii - i1IIi
if 71 - 71: OOooOOo + Ii1I * OOooOOo - OoO0O00 * o0oOOo0O0Ooo
if 65 - 65: O0 % I1IiiI . I1ii11iIi11i % iIii1I11I1II1 / OOooOOo % I1Ii111
if 51 - 51: i11iIiiIii . I1IiiI + II111iiii
if 10 - 10: I1ii11iIi11i * ooOoO0o * II111iiii % Ii1I . OOooOOo + I1Ii111
if 19 - 19: OoOoOO00 - I1IiiI . OOooOOo / IiII
if 33 - 33: I1Ii111 / I1ii11iIi11i % I1IiiI + ooOoO0o / OoO0O00
def OOOoO0O0o ( tr ) :
 O0o0Ooo = [ ]
 for O00 in tr . split ( "\n" ) [ 1 : : ] :
  iI1Ii11iII1 = O00 . split ( )
  if ( iI1Ii11iII1 [ 1 ] . find ( "Invalid" ) != - 1 ) :
   O0o0Ooo . append ( [ "?" , "?" ] )
   continue
   if 51 - 51: II111iiii * OoO0O00 % o0oOOo0O0Ooo * II111iiii % I1ii11iIi11i / ooOoO0o
  O0o0Ooo . append ( [ iI1Ii11iII1 [ 1 ] , iI1Ii11iII1 [ - 2 ] ] )
  if 49 - 49: o0oOOo0O0Ooo
 return ( O0o0Ooo )
 if 35 - 35: OoOoOO00 - OoooooooOO / I1ii11iIi11i % i1IIi
 if 78 - 78: I11i
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
 if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
 if 16 - 16: I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
 if 44 - 44: oO0o
 if 88 - 88: I1Ii111 % Ii1I . II111iiii
def iI1ii1Ii ( ) :
 os . system ( "mkdir {}" . format ( I1I11I1I1I ) )
 os . system ( "touch {}/" . format ( I1I11I1I1I , OooO0OO ) )
 os . system ( "touch {}/" . format ( I1I11I1I1I , iiiIi ) )
 os . system ( "touch {}/" . format ( I1I11I1I1I , IiIIIiI1I1 ) )
 if 92 - 92: OoOoOO00
 if 26 - 26: iII111i . I1Ii111
 if 68 - 68: OoO0O00
 if 35 - 35: OoO0O00 - iII111i / Oo0Ooo / OoOoOO00
 if 24 - 24: ooOoO0o - ooOoO0o / II111iiii - I1ii11iIi11i
 if 69 - 69: oO0o . I1Ii111 + Ii1I / Oo0Ooo - oO0o
 if 63 - 63: OOooOOo % oO0o * oO0o * OoO0O00 / I1ii11iIi11i
def o0ooO ( string ) :
 print string
 sys . stdout . flush ( )
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 ii111111I1iII = open ( "./{}/{}" . format ( I1I11I1I1I , OooO0OO ) , "a" )
 ii111111I1iII . write ( string + "\n" )
 ii111111I1iII . close ( )
 if 68 - 68: iII111i - iIii1I11I1II1 * i11iIiiIii / I1ii11iIi11i * I1Ii111
 if 23 - 23: iII111i
 if 91 - 91: iIii1I11I1II1 + I1Ii111
 if 31 - 31: IiII . OoOoOO00 . OOooOOo
 if 75 - 75: I11i + OoO0O00 . OoOoOO00 . ooOoO0o + Oo0Ooo . OoO0O00
 if 96 - 96: OOooOOo . ooOoO0o - Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * OOooOOo
 if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
def iii1i1iiiiIi ( addr ) :
 if ( addr . count ( "." ) == 3 ) :
  addr = addr . split ( "." )
  for Iiii in addr :
   if ( Iiii . isdigit ( ) == False ) : return ( False )
   if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
  return ( True )
  if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if ( addr . find ( ":" ) != - 1 ) :
  addr = addr . replace ( ":" , "" )
  for Iiii in addr :
   if ( Iiii not in string . hexdigits ) : return ( False )
   if 91 - 91: O0
  return ( True )
  if 61 - 61: II111iiii
 return ( False )
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
def iIIi1i1 ( string ) :
 return ( "\033[92m" + string + "\033[0m" )
 if 10 - 10: I11i
 if 82 - 82: I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
def OOOOoOoo0O0O0 ( string ) :
 return ( "\033[91m" + string + "\033[0m" )
 if 85 - 85: oO0o % i11iIiiIii - iII111i * OoooooooOO / I1IiiI % I1IiiI
 if 1 - 1: OoO0O00 - oO0o . I11i . OoO0O00 / Oo0Ooo + I11i
def Ooo ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 62 - 62: OOooOOo / OoO0O00 + Ii1I / OoO0O00 . II111iiii
 if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
 if 31 - 31: II111iiii . I1IiiI
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
 if 92 - 92: iII111i
 if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
iI1ii1Ii ( )
if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
if 51 - 51: O0 + iII111i
if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
if 48 - 48: O0
if ( iiii ) : o0ooO ( "Run '{}' ..." . format ( Ooo ( oOo0oooo00o ) ) )
I1IiiIIIi = commands . getoutput ( oOo0oooo00o )
if ( iiii ) : o0ooO ( "curl returned '{}'" . format ( I1IiiIIIi ) )
if 41 - 41: Ii1I - O0 - O0
if ( I1IiiIIIi == "" ) :
 o0ooO ( "curl returned empty string" )
 exit ( 1 )
 if 68 - 68: OOooOOo % I1Ii111
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
I1IiiIIIi = json . loads ( I1IiiIIIi )
if ( type ( I1IiiIIIi ) != list ) :
 o0ooO ( "Could not retrieve map-cache" )
 exit ( 1 )
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
if ( I1IiiIIIi == [ ] ) :
 o0ooO ( "No map-cache entries returned" )
 exit ( 1 )
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
if ( len ( I1IiiIIIi ) == 1 and I1IiiIIIi [ 0 ] . has_key ( "?" ) ) :
 o0ooO ( "Authentication failed while retrieving map-cache" )
 exit ( 1 )
 if 23 - 23: O0
 if 85 - 85: Ii1I
 if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
 if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
 if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
for O0ooO0Oo00o in I1IiiIIIi :
 ooO0oOOooOo0 = "[{}]{}" . format ( O0ooO0Oo00o [ "instance-id" ] , O0ooO0Oo00o [ "eid-prefix" ] )
 for i1I1ii11i1Iii in O0ooO0Oo00o [ "rloc-set" ] :
  I1IiiiiI = i1I1ii11i1Iii [ "address" ]
  if ( iii1i1iiiiIi ( I1IiiiiI ) == False ) : continue
  if ( II1i1Ii11Ii11 . has_key ( I1IiiiiI ) == False ) :
   o0O = [ ]
   for IiIIii1iII1II in i1I1ii11i1Iii [ "recent-rloc-probe-rtts" ] : o0O . append ( float ( IiIIii1iII1II ) )
   O0o0Ooo = [ ]
   for Iii1I1I11iiI1 in i1I1ii11i1Iii [ "recent-rloc-hop-counts" ] : O0o0Ooo . append ( str ( Iii1I1I11iiI1 ) )
   II1i1Ii11Ii11 [ I1IiiiiI ] = [ None , [ ] , o0O , O0o0Ooo , [ ] ]
   if 18 - 18: OOooOOo + iII111i - Ii1I . II111iiii + i11iIiiIii
  II1i1Ii11Ii11 [ I1IiiiiI ] [ o0oO ] . append ( ooO0oOOooOo0 )
  if 20 - 20: I1Ii111
  if 52 - 52: II111iiii - OoooooooOO % Ii1I + I1IiiI * Oo0Ooo . IiII
  if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
o0ooO ( "Found {} map-cache entries with {} distinct RLOC(s):" . format ( len ( I1IiiIIIi ) , len ( II1i1Ii11Ii11 ) ) )
if 55 - 55: OOooOOo . I1IiiI
if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
if 100 - 100: I1Ii111 * O0
if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
if 79 - 79: O0
for oOO00O in II1i1Ii11Ii11 :
 i1I1ii11i1Iii = II1i1Ii11Ii11 [ oOO00O ]
 o0O = i1I1ii11i1Iii [ Ii1iIIIi1ii ]
 O0o0Ooo = i1I1ii11i1Iii [ o0oo0o0O00OO ]
 OOOoo0OO = i1I1ii11i1Iii [ o0oO ]
 o0ooO ( "RLOC {}, rtts(secs) {}, hops {}" . format ( Ooo ( oOO00O ) , o0O , O0o0Ooo ) )
 o0ooO ( "     EIDs: {}" . format ( OOOoo0OO ) )
 if 57 - 57: OoO0O00 / ooOoO0o
o0ooO ( "" )
if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
if 13 - 13: Ii1I . i11iIiiIii
if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
for oOO00O in II1i1Ii11Ii11 :
 O00o0OO0 = i11IiIiiIIIII . format ( oOO00O )
 o0ooO ( "Run {} ..." . format ( Ooo ( O00o0OO0 ) ) )
 if 35 - 35: oO0o % ooOoO0o / I1Ii111 + iIii1I11I1II1 . OoooooooOO . I1IiiI
 o00oOOooOOo0o = commands . getoutput ( O00o0OO0 )
 if 66 - 66: iII111i - iII111i - i11iIiiIii . I1ii11iIi11i - OOooOOo
 i1I1ii11i1Iii = II1i1Ii11Ii11 [ oOO00O ]
 i1I1ii11i1Iii [ iII11i ] = o00oOOooOOo0o
 i1I1ii11i1Iii [ O0O00o0OOO0 ] = OOOoO0O0o ( i1I1ii11i1Iii [ iII11i ] )
 if ( i1iiI11I ) : oOOo0O00o = "-"
 if 8 - 8: OoO0O00
 for Iii1I1I11iiI1 in i1I1ii11i1Iii [ O0O00o0OOO0 ] :
  ii1111iII = str ( i1I1ii11i1Iii [ O0O00o0OOO0 ] . index ( Iii1I1I11iiI1 ) + 1 ) . rjust ( 2 )
  if ( Iii1I1I11iiI1 [ 0 ] == "?" ) :
   Iii1I1I11iiI1 [ 0 ] = Iii1I1I11iiI1 [ 1 ] = oOOo0O00o = "?"
   if 32 - 32: i1IIi / II111iiii . Oo0Ooo
  if ( i1iiI11I == False ) :
   try : oOOo0O00o = socket . gethostbyaddr ( Iii1I1I11iiI1 [ 0 ] ) [ 0 ]
   except : oOOo0O00o = "?"
   if 62 - 62: OoooooooOO * I1IiiI
   if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
  i1 = "" if ( Iii1I1I11iiI1 != i1I1ii11i1Iii [ O0O00o0OOO0 ] [ - 1 ] ) else Ooo ( iIIi1i1 ( "!" ) ) if ( Iii1I1I11iiI1 [ 0 ] == oOO00O ) else Ooo ( OOOOoOoo0O0O0 ( "X" ) )
  if 51 - 51: Oo0Ooo / OoOoOO00 . OOooOOo * o0oOOo0O0Ooo + OoO0O00 * IiII
  if 73 - 73: OoO0O00 + OoooooooOO - O0 - Ii1I - II111iiii
  if ( Iii1I1I11iiI1 [ 0 ] == "*" ) :
   o0ooO ( "{}  * {}" . format ( ii1111iII , i1 ) )
   continue
   if 99 - 99: ooOoO0o . Ii1I + I1Ii111 + OoooooooOO % o0oOOo0O0Ooo
   if 51 - 51: iIii1I11I1II1
  o0ooO ( "{}  {} ({}), rtt {}ms {}" . format ( ii1111iII , Iii1I1I11iiI1 [ 0 ] , oOOo0O00o , Iii1I1I11iiI1 [ 1 ] ,
 i1 ) )
  if 34 - 34: oO0o + I1IiiI - oO0o
 o0ooO ( "" )
 if 17 - 17: II111iiii % iII111i + I11i - iII111i / OOooOOo + ooOoO0o
 if 59 - 59: OOooOOo % OoOoOO00 . Ii1I * I1ii11iIi11i % I11i
o0ooO ( "Log and JSON files created in directory ./{}" . format ( Ooo ( I1I11I1I1I ) ) )
if 59 - 59: oO0o - iII111i
if 15 - 15: I1Ii111 . i11iIiiIii . OoooooooOO / OoO0O00 % Ii1I
if 93 - 93: O0 % i1IIi . OOooOOo / I1IiiI - I1Ii111 / I1IiiI
if 36 - 36: oO0o % oO0o % i1IIi / i1IIi - ooOoO0o
ii111111I1iII = open ( "{}/{}" . format ( I1I11I1I1I , iiiIi ) , "a" )
ii111111I1iII . write ( json . dumps ( II1i1Ii11Ii11 ) )
ii111111I1iII . close ( )
if 30 - 30: I11i / I1IiiI
ii111111I1iII = open ( "{}/{}" . format ( I1I11I1I1I , IiIIIiI1I1 ) , "a" )
ii111111I1iII . write ( json . dumps ( I1IiiIIIi ) )
ii111111I1iII . close ( )
if 35 - 35: II111iiii % OOooOOo . ooOoO0o + ooOoO0o % II111iiii % II111iiii
exit ( 0 )
if 72 - 72: II111iiii + i1IIi + o0oOOo0O0Ooo
if 94 - 94: oO0o . i1IIi - o0oOOo0O0Ooo % O0 - OoO0O00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
