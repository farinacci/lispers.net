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
from __future__ import print_function
import json
import sys
import socket
import os
import datetime
import string
try :
 from commands import getoutput
except :
 from subprocess import getoutput
 if 64 - 64: i11iIiiIii
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
  print ( "Invalid syntax for username:password pair" )
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
  print ( "Invalid syntax for host:port pair" )
  exit ( 1 )
  if 8 - 8: o0oOOo0O0Ooo * I1ii11iIi11i * iIii1I11I1II1 . IiII / IiII % IiII
 i11 = oo00 [ 1 ]
 if ( i11 [ 0 ] == "-" ) :
  ooO00oOoo = "http"
  i11 = i11 [ 1 : : ]
  if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
 if ( i11 . isdigit ( ) == False ) :
  print ( "Invalid syntax for port" )
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
i1iiIII111ii = 'dohost "traceroute {}"'
if 3 - 3: iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
if 78 - 78: OoO0O00
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
O0O00Ooo = datetime . datetime . now ( ) . strftime ( "%m-%d-%y-%H-%M-%S" )
OOoooooO = "loc8tr-{}" . format ( O0O00Ooo )
i1iIIIiI1I = "loc8tr.log"
OOoO000O0OO = "loc8tr.json"
iiI1IiI = "loc8tr-mc.json"
if 13 - 13: Oo0Ooo . i11iIiiIii - iIii1I11I1II1 - OoOoOO00
if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
if 100 - 100: Ii1I - Ii1I - I1Ii111
if 20 - 20: OoooooooOO
if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
if 97 - 97: i11iIiiIii
if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
if 61 - 61: ooOoO0o
if 79 - 79: Oo0Ooo + I1IiiI - iII111i
if 83 - 83: ooOoO0o
if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
o0o0oOOOo0oo = { }
o0oo0o0O00OO = 0
o0oO = 1
I1i1iii = 2
i1iiI11I = 3
iiii = 4
oO0o0O0OOOoo0 = 5
IiIiiI = 6
if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
O0ooOooooO = ( "-n" in sys . argv )
o00O = ( "-d" in sys . argv )
if 69 - 69: oO0o % I1Ii111 - o0oOOo0O0Ooo + I1Ii111 - O0 % OoooooooOO
if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
if 4 - 4: II111iiii / ooOoO0o . iII111i
if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
if 50 - 50: I1IiiI
if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
def IIIIii ( tr , cisco ) :
 O0o0 = [ ]
 OO00Oo = tr . split ( "\n" )
 OO00Oo = OO00Oo [ 4 : : ] if cisco else OO00Oo [ 1 : : ]
 if 51 - 51: IiII * o0oOOo0O0Ooo + I11i + OoO0O00
 for o0O0O00 in OO00Oo :
  o000o = o0O0O00 . split ( )
  if ( len ( o000o ) == 0 ) : continue
  if ( o000o [ 1 ] . find ( "Invalid" ) != - 1 ) :
   O0o0 . append ( [ "?" , "?" ] )
   continue
   if 7 - 7: ooOoO0o * OoO0O00 % oO0o . IiII
   if 45 - 45: i11iIiiIii * II111iiii % iIii1I11I1II1 + I1ii11iIi11i - Ii1I
   if 17 - 17: IiII
   if 62 - 62: iIii1I11I1II1 * OoOoOO00
   if 26 - 26: iII111i . I1Ii111
   if 68 - 68: OoO0O00
   if 35 - 35: OoO0O00 - iII111i / Oo0Ooo / OoOoOO00
  if ( cisco ) :
   if ( o000o [ 2 ] == "msec" ) : continue
   O0o0 . append ( [ o000o [ 1 ] , o000o [ 2 ] ] )
  else :
   O0o0 . append ( [ o000o [ 1 ] , o000o [ - 2 ] ] )
   if 24 - 24: ooOoO0o - ooOoO0o / II111iiii - I1ii11iIi11i
   if 69 - 69: oO0o . I1Ii111 + Ii1I / Oo0Ooo - oO0o
 return ( O0o0 )
 if 63 - 63: OOooOOo % oO0o * oO0o * OoO0O00 / I1ii11iIi11i
 if 74 - 74: II111iiii
 if 75 - 75: o0oOOo0O0Ooo . ooOoO0o
 if 54 - 54: II111iiii % OoOoOO00 % I11i % iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
 if 87 - 87: ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 if 92 - 92: iII111i . I1Ii111
 if 31 - 31: I1Ii111 . OoOoOO00 / O0
def o000O0o ( ) :
 os . system ( "mkdir {}" . format ( OOoooooO ) )
 os . system ( "touch {}/{}" . format ( OOoooooO , i1iIIIiI1I ) )
 os . system ( "touch {}/{}" . format ( OOoooooO , OOoO000O0OO ) )
 os . system ( "touch {}/{}" . format ( OOoooooO , iiI1IiI ) )
 if 42 - 42: OoOoOO00
 if 41 - 41: Oo0Ooo . ooOoO0o + O0 * o0oOOo0O0Ooo % Oo0Ooo * Oo0Ooo
 if 19 - 19: iII111i
 if 46 - 46: I1ii11iIi11i - Ii1I . iIii1I11I1II1 / I1ii11iIi11i
 if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
 if 13 - 13: OOooOOo / i11iIiiIii
 if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
def o0o00OO0 ( string ) :
 print ( string )
 sys . stdout . flush ( )
 if 7 - 7: OOooOOo + I1Ii111 + O0
 Ii = open ( "./{}/{}" . format ( OOoooooO , i1iIIIiI1I ) , "a" )
 Ii . write ( string + "\n" )
 Ii . close ( )
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
 if 67 - 67: I1Ii111 . iII111i . O0
 if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
 if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
def o0oOIIiIi1iI ( addr ) :
 if ( addr . count ( "." ) == 3 ) :
  addr = addr . split ( "." )
  for i1IiiiI1iI in addr :
   if ( i1IiiiI1iI . isdigit ( ) == False ) : return ( False )
   if 49 - 49: Ii1I / OoO0O00 . II111iiii
  return ( True )
  if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
 if ( addr . find ( ":" ) != - 1 ) :
  addr = addr . replace ( ":" , "" )
  for i1IiiiI1iI in addr :
   if ( i1IiiiI1iI not in string . hexdigits ) : return ( False )
   if 31 - 31: II111iiii . I1IiiI
  return ( True )
  if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 return ( False )
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
 if 92 - 92: iII111i
def IIiIiiIi ( string ) :
 return ( "\033[94m" + string + "\033[0m" )
 if 51 - 51: I11i + iII111i % iIii1I11I1II1 / oO0o / OOooOOo % OoooooooOO
 if 78 - 78: Ii1I % I1Ii111 + I1ii11iIi11i
def OOooOoooOoOo ( string ) :
 return ( "\033[92m" + string + "\033[0m" )
 if 84 - 84: IiII
 if 86 - 86: OoOoOO00 - Ii1I - OoO0O00 * iII111i
def oooo0O0 ( string ) :
 return ( "\033[91m" + string + "\033[0m" )
 if 51 - 51: OoO0O00 / OoO0O00
 if 53 - 53: Oo0Ooo
def iI1Iii ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 68 - 68: OOooOOo % I1Ii111
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
 if 23 - 23: O0
 if 85 - 85: Ii1I
 if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
def IIi1 ( address ) :
 if ( address . find ( "." ) != - 1 ) :
  I1I1I = int ( address . split ( "." ) [ 0 ] )
  return ( I1I1I >= 224 and I1I1I <= 239 )
  if 95 - 95: II111iiii + o0oOOo0O0Ooo + iII111i * iIii1I11I1II1 % oO0o / IiII
 if ( address . find ( ":" ) != - 1 ) :
  return ( address [ 0 : 1 ] . lower ( ) == "ff" )
  if 56 - 56: iII111i
 return ( False )
 if 86 - 86: II111iiii % I1Ii111
 if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 if 53 - 53: II111iiii
 if 31 - 31: OoO0O00
 if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: OoO0O00
o000O0o ( )
if 62 - 62: OOooOOo + O0
if 98 - 98: o0oOOo0O0Ooo
if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
if ( o00O ) : o0o00OO0 ( "Run '{}' ..." . format ( iI1Iii ( oOo0oooo00o ) ) )
oOoooo0O0Oo = getoutput ( oOo0oooo00o )
if ( o00O ) : o0o00OO0 ( "curl returned '{}'" . format ( oOoooo0O0Oo ) )
if 76 - 76: Ii1I + IiII
if ( oOoooo0O0Oo == "" ) :
 o0o00OO0 ( "curl returned empty string" )
 exit ( 1 )
 if 34 - 34: Oo0Ooo
 if 89 - 89: Oo0Ooo * OoOoOO00 * I1Ii111 + iII111i - I11i
oOoooo0O0Oo = json . loads ( oOoooo0O0Oo )
if ( type ( oOoooo0O0Oo ) != list ) :
 o0o00OO0 ( "Could not retrieve map-cache" )
 exit ( 1 )
 if 8 - 8: o0oOOo0O0Ooo % O0 / I1IiiI - oO0o
if ( oOoooo0O0Oo == [ ] ) :
 o0o00OO0 ( "No map-cache entries returned" )
 exit ( 1 )
 if 43 - 43: i11iIiiIii + Oo0Ooo * II111iiii * I1Ii111 * O0
if ( len ( oOoooo0O0Oo ) == 1 and "?" in oOoooo0O0Oo [ 0 ] ) :
 o0o00OO0 ( "Authentication failed while retrieving map-cache" )
 exit ( 1 )
 if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
 if 79 - 79: O0
 if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
 if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 if 57 - 57: OoO0O00 / ooOoO0o
for Ii1I1Ii in oOoooo0O0Oo :
 OOoO0 = "[{}]" . format ( Ii1I1Ii [ "instance-id" ] )
 if ( "group-prefix" in Ii1I1Ii ) :
  OOoO0 += "({}, {})" . format ( Ii1I1Ii [ "eid-prefix" ] , Ii1I1Ii [ "group-prefix" ] )
 else :
  OOoO0 += "{}" . format ( Ii1I1Ii [ "eid-prefix" ] )
  if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
  if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 O00o0OO0 = { }
 for IIi1I1iiiii in Ii1I1Ii [ "rloc-set" ] :
  o00oOOooOOo0o = IIi1I1iiiii [ "address" ]
  if ( o0oOIIiIi1iI ( o00oOOooOOo0o ) == False ) : continue
  if 66 - 66: iII111i - iII111i - i11iIiiIii . I1ii11iIi11i - OOooOOo
  O00o0OO0 [ o00oOOooOOo0o ] = IIi1I1iiiii
  if ( "multicast-rloc-set" in IIi1I1iiiii ) :
   for oOOo0O00o in IIi1I1iiiii [ "multicast-rloc-set" ] :
    I1I1I = oOOo0O00o [ "address" ] + "%" + o00oOOooOOo0o
    O00o0OO0 [ I1I1I ] = oOOo0O00o
    if 8 - 8: OoO0O00
    if 49 - 49: I1IiiI - I11i
    if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
    if 62 - 62: OoooooooOO * I1IiiI
 for o00oOOooOOo0o in O00o0OO0 :
  IIi1I1iiiii = O00o0OO0 [ o00oOOooOOo0o ]
  oOOOoo0O0oO = IIi1I1iiiii [ "rloc-name" ] if ( "rloc-name" in IIi1I1iiiii ) else "?"
  if ( o0oOIIiIi1iI ( IIi1I1iiiii [ "address" ] ) == False ) : continue
  if 6 - 6: OOooOOo * o0oOOo0O0Ooo + iII111i
  if ( o00oOOooOOo0o not in o0o0oOOOo0oo ) :
   I1IIIiIiI1 = [ ]
   for Ii1I1I11iI in IIi1I1iiiii [ "recent-rloc-probe-rtts" ] : I1IIIiIiI1 . append ( float ( Ii1I1I11iI ) )
   O0o0 = [ ]
   for ooO in IIi1I1iiiii [ "recent-rloc-hop-counts" ] : O0o0 . append ( str ( ooO ) )
   IiIi11iI = [ ]
   for Oo0O00O000 in IIi1I1iiiii [ "recent-rloc-probe-latencies" ] :
    IiIi11iI . append ( str ( Oo0O00O000 ) )
    if 3 - 3: Ii1I * I1ii11iIi11i % I11i
   o0o0oOOOo0oo [ o00oOOooOOo0o ] = [ oOOOoo0O0oO , None , [ ] , I1IIIiIiI1 , O0o0 , IiIi11iI , [ ] ]
   if 59 - 59: oO0o - iII111i
  o0o0oOOOo0oo [ o00oOOooOOo0o ] [ IiIiiI ] . append ( OOoO0 )
  if 15 - 15: I1Ii111 . i11iIiiIii . OoooooooOO / OoO0O00 % Ii1I
  if 93 - 93: O0 % i1IIi . OOooOOo / I1IiiI - I1Ii111 / I1IiiI
  if 36 - 36: oO0o % oO0o % i1IIi / i1IIi - ooOoO0o
o0o00OO0 ( "Found {} map-cache entries with {} distinct RLOC(s):" . format ( len ( oOoooo0O0Oo ) , len ( o0o0oOOOo0oo ) ) )
if 30 - 30: I11i / I1IiiI
if 35 - 35: II111iiii % OOooOOo . ooOoO0o + ooOoO0o % II111iiii % II111iiii
if 72 - 72: II111iiii + i1IIi + o0oOOo0O0Ooo
if 94 - 94: oO0o . i1IIi - o0oOOo0O0Ooo % O0 - OoO0O00
if 72 - 72: Ii1I
for I1I1I in o0o0oOOOo0oo :
 IIi1I1iiiii = o0o0oOOOo0oo [ I1I1I ]
 oOOOoo0O0oO = IIiIiiIi ( IIi1I1iiiii [ o0oo0o0O00OO ] )
 I1IIIiIiI1 = IIi1I1iiiii [ i1iiI11I ]
 O0o0 = IIi1I1iiiii [ iiii ]
 IiIi11iI = IIi1I1iiiii [ oO0o0O0OOOoo0 ]
 II11Ii1iI1iII = IIi1I1iiiii [ IiIiiI ]
 if 73 - 73: OoooooooOO * OoooooooOO * ooOoO0o * OoOoOO00 + ooOoO0o * I1Ii111
 i1IiiiI1iI = I1I1I . split ( "%" )
 if ( len ( i1IiiiI1iI ) == 2 ) :
  i1IiiiI1iI = iI1Iii ( i1IiiiI1iI [ 0 ] ) + "(" + i1IiiiI1iI [ 1 ] + ")"
 else :
  i1IiiiI1iI = iI1Iii ( I1I1I )
  if 88 - 88: I1ii11iIi11i
  if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 o0o00OO0 ( "RLOC {} ({}), rtts(secs) {}, hops {}, latencies {}" . format ( i1IiiiI1iI , oOOOoo0O0oO ,
 I1IIIiIiI1 , O0o0 , IiIi11iI ) )
 o0o00OO0 ( "     EIDs: {}" . format ( II11Ii1iI1iII ) )
 if 26 - 26: Ii1I % I1ii11iIi11i
o0o00OO0 ( "" )
if 76 - 76: IiII * iII111i
if 52 - 52: OOooOOo
if 19 - 19: I1IiiI
if 25 - 25: Ii1I / ooOoO0o
for I1I1I in o0o0oOOOo0oo :
 if ( IIi1 ( I1I1I ) ) :
  IIi1I1iiiii [ o0oO ] = ""
  IIi1I1iiiii [ I1i1iii ] = [ ]
  o0o00OO0 ( "Suppress traceroute to multicast RLOC {}" . format ( I1I1I ) )
  o0o00OO0 ( "" )
  continue
  if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
  if 71 - 71: I1Ii111 . II111iiii
 o00oOOooOOo0o = I1I1I . split ( "%" )
 o00oOOooOOo0o = o00oOOooOOo0o [ 1 ] if ( len ( i1IiiiI1iI ) == 2 ) else o00oOOooOOo0o [ 0 ]
 if 62 - 62: OoooooooOO . I11i
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
 if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 58 - 58: I1IiiI
 if 53 - 53: i1IIi
 o0OOOoO0 = os . path . exists ( "/cisco/guestshell" )
 if ( o0OOOoO0 ) :
  o0OoOo00o0o = i1iiIII111ii . format ( o00oOOooOOo0o )
 else :
  o0OoOo00o0o = i11IiIiiIIIII . format ( o00oOOooOOo0o )
  if 41 - 41: ooOoO0o % OoO0O00 - Oo0Ooo * I1Ii111 * Oo0Ooo
  if 69 - 69: OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 o0o00OO0 ( "Run {} ..." . format ( iI1Iii ( o0OoOo00o0o ) ) )
 if 23 - 23: i11iIiiIii
 II1iIi11 = getoutput ( o0OoOo00o0o )
 if 12 - 12: Ii1I + i11iIiiIii * iIii1I11I1II1 / I1ii11iIi11i . I11i
 IIi1I1iiiii = o0o0oOOOo0oo [ I1I1I ]
 IIi1I1iiiii [ o0oO ] = II1iIi11
 IIi1I1iiiii [ I1i1iii ] = IIIIii ( IIi1I1iiiii [ o0oO ] , o0OOOoO0 )
 if ( O0ooOooooO ) : Iii1iI = "-"
 if 29 - 29: I1IiiI % OOooOOo - I1IiiI / OOooOOo . i1IIi
 for ooO in IIi1I1iiiii [ I1i1iii ] :
  i11III1111iIi = str ( IIi1I1iiiii [ I1i1iii ] . index ( ooO ) + 1 ) . rjust ( 2 )
  if ( ooO [ 0 ] == "?" ) :
   ooO [ 0 ] = ooO [ 1 ] = Iii1iI = "?"
   if 38 - 38: iII111i + I11i / I1Ii111 % ooOoO0o - I1ii11iIi11i
  if ( O0ooOooooO == False ) :
   try : Iii1iI = socket . gethostbyaddr ( ooO [ 0 ] ) [ 0 ]
   except : Iii1iI = "?"
   if 14 - 14: oO0o / I1Ii111
   if 85 - 85: I11i
  iI1i11II1i = "" if ( ooO != IIi1I1iiiii [ I1i1iii ] [ - 1 ] ) else iI1Iii ( OOooOoooOoOo ( "!" ) ) if ( ooO [ 0 ] == o00oOOooOOo0o ) else iI1Iii ( oooo0O0 ( "X" ) )
  if 96 - 96: I1Ii111
  if 97 - 97: ooOoO0o
  if ( ooO [ 0 ] == "*" ) :
   o0o00OO0 ( "{}  * {}" . format ( i11III1111iIi , iI1i11II1i ) )
   continue
   if 48 - 48: i1IIi - I1Ii111
   if 56 - 56: o0oOOo0O0Ooo + II111iiii + OoOoOO00 - ooOoO0o . OoOoOO00
  o0o00OO0 ( "{}  {} ({}), rtt {} ms {}" . format ( i11III1111iIi , ooO [ 0 ] , Iii1iI , ooO [ 1 ] ,
 iI1i11II1i ) )
  if 84 - 84: OoO0O00 + i1IIi - II111iiii . I1ii11iIi11i * OoooooooOO + I1IiiI
 o0o00OO0 ( "" )
 if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
 if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
o0o00OO0 ( "Log and JSON files created in directory ./{}" . format ( iI1Iii ( OOoooooO ) ) )
if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
Ii = open ( "{}/{}" . format ( OOoooooO , OOoO000O0OO ) , "a" )
Ii . write ( json . dumps ( o0o0oOOOo0oo ) )
Ii . close ( )
if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
Ii = open ( "{}/{}" . format ( OOoooooO , iiI1IiI ) , "a" )
Ii . write ( json . dumps ( oOoooo0O0Oo ) )
Ii . close ( )
if 79 - 79: O0 * i11iIiiIii - IiII / IiII
exit ( 0 )
if 48 - 48: O0
if 93 - 93: i11iIiiIii - I1IiiI * I1ii11iIi11i * I11i % O0 + OoooooooOO
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
