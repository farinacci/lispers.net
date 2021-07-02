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
# ltr.py - LISP EID Traceroute Client - Trace the encap/decap paths
#
# Usage: python ltr.py [-s <source-eid>] <destination-EID | DNS-name>
#
#   -s: Optional source EID.
#   <destination-EID>: required parameter [<iid>] in front is optional
#
# This application is run on an xTR. Typically a ITR or RTR, where the
# encapsulator adds to the ltr message with the RLOC the ITR is encapsulating
# to. Then the decapsulator will decapsulate and swap the source and
# destination addresses to return the packet to the source-EID (running the
# client program). If the ETR is not the EID, then the packet will be re-
# encapsulated in which more data is added to the ltr message.
#
# ltr messages run in UDP on port 2434 (4342 backwards) and are returned
# to the client program.
#
# The LISP-Trace message takes the following path:
#
# (1) ltr sends LISP-TRACE packet from its EID to the EID of the ETR on
# port 2434. It builds a type=9 packet with a nonce and an empty JSON field.
#
# (2) ITR will look up destination EID as part of forwarding logic and add
# RLOC information to LISP-Trace message. The message is encapsulated to
# the ETR.
#
# (3) The ETR (or RTR) will decap packet. It will add information to the LISP-
# packet. If it is the destination EID, it will send the LISP-Trace packet
# using itself as the source and the original source as the destination.
#
# (4) The local ITR will encapsulate the packet and add RLOC information to
# the LISP-Trace packet. It encapsulates the return packet to the ETR.
#
# (5) The ETR decapsulates the packet and sends it to the ltr client so the
# accumulated JSON data can be displayed for the user.
#
# This functionality works on a chain of encapsulating tunnels to give the
# user what RLOCs are used and the arrival time of the packet. It allows an
# ltr client to not only determine path and latency of the network, but if
# the encapsulation paths are symmetric or asymmetric.
#
# If there an error along the path, the node detecting the error will return
# the LISP-Trace packet to the RLOC of the originating ITR.
#
# The JSON format of an LISP-Trace packet is an array of dictionary arrays.
# The array will typically have 2 elements, one from ltr source to destination
# EID and one for the return path. Each dictionary array is keyed with "seid",
# "deid", and "paths". The array "paths" is the node data that is appended
# at each encapsulation hop. Note example below:
# 
# [ 
#   { "se" : "[<iid>]<orig-eid>", "de" : "[<iid>]<dest-eid>", "paths" : a
#   [
#     { "n" : "ITR", "sr" : "<source-rloc>",  "dr" : "<dest_rloc>",
#       "ets" : "<ts>", "hn" : "<hn>", "rtts" : [...], "hops" : [...] }, 
#     { "n" : "RTR", "sr" : "<source-rloc>",  "dr" : "<dest_rloc>",
#       "dts" : "<ts>", "hn" : "<hn>" },
#     { "n" : "RTR", "sr" : "<source-rloc>",  "dr" : "<dest_rloc>",
#       "ets" : "<ts>", "hn" : "<hn>", "rtts" : [...], "hops" : [...] }, 
#     { "n" : "ETR", "sr" : "<source-rloc>",  "dr" : "<dest_rloc>",
#       "ets" : "<ts>", "hn" : "<hn>" }, ...
#   ] },
# 
#   { "se" : "[<iid>]<dest-eid>", "de" : "[<iid>]<orig-eid>", "paths" :
#   [
#     { "n" : "ITR", "sr" : "<source-rloc>",  "dr" : "<dest_rloc>",
#       "ets" : "<ts>", "hn" : "<hn>", "rtts" : [...], "hops" : [...] }, 
#     { "n" : "RTR", "sr" : "<source-rloc>",  "dr" : "<dest_rloc>",
#       "dts" : "<ts>", "hn" : "<hn>" },
#     { "n" : "RTR", "sr" : "<source-rloc>",  "dr" : "<dest_rloc>",
#       "ets" : "<ts>", "hn" : "<hn>", "rtts" : [...], "hops" : [...] }, 
#     { "n" : "ETR", "sr" : "<source-rloc>",  "dr" : "<dest_rloc>",
#       "ets" : "<ts>", "hn" : "<hn>" }, ...
#   ] }
# ]
#
# Environment variable LISP_LTR_PORT is used to determine if the connection to
# the LISP API is done with a particular port. And if the port has a minus
# sign in front of it, it will use http rather https to connect to the
# lispers.net API. Environment variables LISP_LTR_USER and LISP_LTR_PW are
# used when lispers.net API is running with a password on username root.
#
#------------------------------------------------------------------------------
from __future__ import print_function
from future import standard_library
standard_library . install_aliases ( )
from builtins import hex
import sys
import struct
import random
import socket
import json
import time
import os
import binascii
from subprocess import getoutput
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
II1iII1i = "https"
oO0oIIII = 8080
if 59 - 59: i1IIi * i1IIi % OOooOOo + II111iiii
II = os . getenv ( "LISP_LTR_PORT" )
if ( II != None ) :
 if ( II [ 0 ] == "-" ) :
  II1iII1i = "http"
  II = II [ 1 : : ]
  if 100 - 100: i1IIi . I1Ii111 / IiII * OoooooooOO + I11i * oO0o
 if ( II . isdigit ( ) == False ) :
  print ( "Invalid value for env variable LISP_LTR_PORT" )
  exit ( 1 )
  if 99 - 99: iII111i . OOooOOo / iIii1I11I1II1 * iIii1I11I1II1
 oO0oIIII = int ( II )
 if 11 - 11: oO0o / i1IIi % II111iiii - OoOoOO00
OOo = os . getenv ( "LISP_LTR_USER" )
Ii1IIii11 = os . getenv ( "LISP_LTR_PW" )
if ( OOo == None ) : OOo = "root"
if ( Ii1IIii11 == None ) : Ii1IIii11 = ""
if 55 - 55: iIii1I11I1II1 - I1IiiI . Ii1I * IiII * i1IIi / iIii1I11I1II1
OOo000 = 2434
if 82 - 82: I11i . I1Ii111 / IiII % II111iiii % iIii1I11I1II1 % IiII
if 86 - 86: OoOoOO00 % I1IiiI
if 80 - 80: OoooooooOO . I1IiiI
if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
if 58 - 58: i11iIiiIii % I1Ii111
if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
if 13 - 13: OOooOOo * oO0o * I1IiiI
if 55 - 55: II111iiii
if 43 - 43: OoOoOO00 - i1IIi + I1Ii111 + Ii1I
if 17 - 17: o0oOOo0O0Ooo
if 64 - 64: Ii1I % i1IIi % OoooooooOO
if 3 - 3: iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
if 78 - 78: OoO0O00
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
if 14 - 14: I11i % O0
if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
def oO ( rloc , port ) :
 OO0OOooOoO0Oo = socket . htonl ( 0x90000000 + port )
 iiIIiIiIi = struct . pack ( "I" , OO0OOooOoO0Oo )
 if 38 - 38: Ii1I / Oo0Ooo
 OooO0 = rloc . split ( "." )
 II11iiii1Ii = int ( OooO0 [ 0 ] ) << 24
 II11iiii1Ii += int ( OooO0 [ 1 ] ) << 16
 II11iiii1Ii += int ( OooO0 [ 2 ] ) << 8
 II11iiii1Ii += int ( OooO0 [ 3 ] )
 iiIIiIiIi += struct . pack ( "I" , socket . htonl ( II11iiii1Ii ) )
 if 70 - 70: oO0o / iIii1I11I1II1 % ooOoO0o % i11iIiiIii . I1IiiI
 O0o0Oo = random . randint ( 0 , ( 2 ** 64 ) - 1 )
 iiIIiIiIi += struct . pack ( "Q" , O0o0Oo )
 return ( O0o0Oo , iiIIiIiIi )
 if 78 - 78: iIii1I11I1II1 - Ii1I * OoO0O00 + o0oOOo0O0Ooo + iII111i + iII111i
 if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
 if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
def i1iiI11I ( nonce , packet ) :
 if ( len ( packet ) < 12 ) : return ( False )
 if 29 - 29: OoooooooOO
 iI = "II"
 I1i1I1II = struct . calcsize ( iI )
 OO0OOooOoO0Oo , i1 = struct . unpack ( iI , packet [ : I1i1I1II ] )
 packet = packet [ I1i1I1II : : ]
 if ( socket . ntohl ( OO0OOooOoO0Oo ) != 0x90000000 ) :
  print ( "Invalid LISP-Trace message" )
  return ( { } )
  if 48 - 48: O0 + O0 - I1ii11iIi11i . ooOoO0o / iIii1I11I1II1
  if 77 - 77: i1IIi % OoOoOO00 - IiII + ooOoO0o
 iI = "Q"
 I1i1I1II = struct . calcsize ( iI )
 I11iiIiii = struct . unpack ( iI , packet [ : I1i1I1II ] ) [ 0 ]
 packet = packet [ I1i1I1II : : ]
 if 1 - 1: II111iiii - I11i / I11i
 if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
 if 83 - 83: OoooooooOO
 if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 if ( I11iiIiii != nonce ) :
  print ( "Invalid nonce, sent {}, received {}" . format ( nonce , I11iiIiii ) )
  return ( { } )
  if 4 - 4: II111iiii / ooOoO0o . iII111i
  if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 if ( len ( packet ) == 0 ) :
  print ( "No JSON data in payload" )
  return ( { } )
  if 50 - 50: I1IiiI
  if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
  if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
  if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
  if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
 try :
  Ii11iII1 = json . loads ( packet )
 except :
  print ( "Invalid JSON data: '{}'" . format ( packet ) )
  return ( { } )
  if 51 - 51: II111iiii * OoO0O00 % o0oOOo0O0Ooo * II111iiii % I1ii11iIi11i / ooOoO0o
 return ( Ii11iII1 )
 if 49 - 49: o0oOOo0O0Ooo
 if 35 - 35: OoOoOO00 - OoooooooOO / I1ii11iIi11i % i1IIi
 if 78 - 78: I11i
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
 if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
 if 16 - 16: I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
def i1I11i1iI ( jd ) :
 for I1ii1Ii1 in jd :
  iii11 = I1ii1Ii1 [ "se" ] if ( jd . index ( I1ii1Ii1 ) == 0 ) else oOOOOo0 ( I1ii1Ii1 [ "se" ] )
  iiII1i1 = oOOOOo0 ( I1ii1Ii1 [ "de" ] ) if ( jd . index ( I1ii1Ii1 ) == 0 ) else I1ii1Ii1 [ "de" ]
  if 66 - 66: OOooOOo - I11i
  print ( "Path from {} to {}:" . format ( iii11 , iiII1i1 ) )
  for I1i1III in I1ii1Ii1 [ "paths" ] :
   if ( "ets" in I1i1III ) :
    OO0O0OoOO0 = I1i1III [ "ets" ]
    iiiI1I11i1 = "encap"
    if 49 - 49: I1IiiI % ooOoO0o . ooOoO0o . I11i * ooOoO0o
   if ( "dts" in I1i1III ) :
    OO0O0OoOO0 = I1i1III [ "dts" ]
    iiiI1I11i1 = "decap"
    if 97 - 97: Ii1I + o0oOOo0O0Ooo . OOooOOo + I1ii11iIi11i % iII111i
   oo0O = I1i1III [ "hn" ]
   o0 = I1i1III [ "dr" ]
   if ( o0 . find ( "?" ) != - 1 ) : o0 = oo0oOo ( o0 )
   if 89 - 89: OoOoOO00
   print ( "  {} {}: {} -> {}, ts {}, node {}" . format ( I1i1III [ "n" ] , iiiI1I11i1 , I1i1III [ "sr" ] , o0 , OO0O0OoOO0 , OO0oOoOO0oOO0 ( oo0O ) ) )
   if 86 - 86: OOooOOo
   if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
   if ( "rtts" in I1i1III and "hops" in I1i1III and "lats" in I1i1III ) :
    ii1ii1ii = json . dumps ( I1i1III [ "rtts" ] )
    ii1ii1ii = ii1ii1ii . replace ( "-1" , "?" )
    oooooOoo0ooo = json . dumps ( I1i1III [ "hops" ] )
    oooooOoo0ooo = oooooOoo0ooo . replace ( "u" , "" )
    oooooOoo0ooo = oooooOoo0ooo . replace ( "'" , "" )
    oooooOoo0ooo = oooooOoo0ooo . replace ( '"' , "" )
    I1I1IiI1 = json . dumps ( I1i1III [ "lats" ] )
    I1I1IiI1 = I1I1IiI1 . replace ( "u" , "" )
    I1I1IiI1 = I1I1IiI1 . replace ( "'" , "" )
    I1I1IiI1 = I1I1IiI1 . replace ( '"' , "" )
    print ( "            " , end = ' ' )
    print ( "recent-rtts {}, recent-hops {}" . format ( ii1ii1ii , oooooOoo0ooo ) )
    print ( "             recent-latencies {}" . format ( I1I1IiI1 ) )
    if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
    if 91 - 91: O0
  print ( "" )
  if 61 - 61: II111iiii
  if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
  if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
  if 42 - 42: OoO0O00
  if 67 - 67: I1Ii111 . iII111i . O0
  if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
  if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
  if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
def o0oO ( eid ) :
 IIiIi1iI = True
 if 35 - 35: Ii1I % O0 - O0
 if 16 - 16: II111iiii % OoOoOO00 - II111iiii + Ii1I
 if 12 - 12: OOooOOo / OOooOOo + i11iIiiIii
 if 40 - 40: I1IiiI . iIii1I11I1II1 / I1IiiI / i11iIiiIii
 if 75 - 75: I11i + o0oOOo0O0Ooo
 O0i1II1Iiii1I11 = eid . find ( "]" )
 if ( O0i1II1Iiii1I11 == - 1 ) :
  IIII = "0"
 else :
  IIiIi1iI = False
  IIII = eid [ 1 : O0i1II1Iiii1I11 ]
  eid = eid [ O0i1II1Iiii1I11 + 1 : : ]
  if 32 - 32: OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
  if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
  if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
  if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
  if 51 - 51: O0 + iII111i
 if ( eid . find ( ":" ) == - 1 ) :
  try : eid = socket . gethostbyname ( eid )
  except : pass
  if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 return ( IIII , eid , IIiIi1iI )
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % I1Ii111
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
def i1I1iI1iIi111i ( eid , eid_prefix , ml ) :
 iiIi1IIi1I = 2 ** ml - 1
 if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
 O0ooO0Oo00o = eid . split ( "." )
 if ( len ( O0ooO0Oo00o ) == 1 ) : O0ooO0Oo00o = eid . split ( ":" )
 if ( len ( O0ooO0Oo00o ) == 1 ) : return ( False )
 if 77 - 77: iIii1I11I1II1 * OoO0O00
 if ( len ( O0ooO0Oo00o ) == 4 ) :
  iiIi1IIi1I = iiIi1IIi1I << ( 32 - ml )
  eid = int ( O0ooO0Oo00o [ 0 ] ) << 24 | int ( O0ooO0Oo00o [ 1 ] ) << 16 | int ( O0ooO0Oo00o [ 2 ] ) << 8 | int ( O0ooO0Oo00o [ 3 ] )
  O0ooO0Oo00o = eid & iiIi1IIi1I
  eid = "{}.{}.{}.{}" . format ( ( O0ooO0Oo00o >> 24 ) & 0xff , ( O0ooO0Oo00o >> 16 ) & 0xff ,
 ( O0ooO0Oo00o >> 8 ) & 0xff , O0ooO0Oo00o & 0xff )
 else :
  iiIi1IIi1I = iiIi1IIi1I << ( 128 - ml )
  eid = socket . inet_pton ( socket . AF_INET6 , eid )
  eid = int ( binascii . hexlify ( eid ) , 16 )
  O0ooO0Oo00o = eid & iiIi1IIi1I
  eid = binascii . unhexlify ( hex ( O0ooO0Oo00o ) [ 2 : - 1 ] )
  eid = socket . inet_ntop ( socket . AF_INET6 , eid )
  if 95 - 95: I1IiiI + i11iIiiIii
 return ( eid == eid_prefix )
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 if 53 - 53: II111iiii
 if 31 - 31: OoO0O00
 if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: OoO0O00
 if 62 - 62: OOooOOo + O0
 if 98 - 98: o0oOOo0O0Ooo
 if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
def OoO0o ( match_iid , match_eid , user , pw , http , port , v4v6 ) :
 oO0o0Ooooo = ( "curl --silent --insecure -u {}:{} {}://localhost:{}/lisp/" + "api/data/database-mapping" ) . format ( user , pw , http , port )
 if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 oO0 = getoutput ( oO0o0Ooooo )
 if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
 try :
  oOI1Ii1I1 = json . loads ( oO0 )
 except :
  return ( None , None , None , None )
  if 28 - 28: O0 * Oo0Ooo - OOooOOo % iIii1I11I1II1 * Ii1I - i11iIiiIii
  if 7 - 7: Oo0Ooo + oO0o - I1Ii111 % Ii1I + I1ii11iIi11i
 for ooo0OOOoo in oOI1Ii1I1 :
  if ( ( "eid-prefix" in ooo0OOOoo ) == False ) : continue
  I1Ii1 = ooo0OOOoo [ "eid-prefix" ]
  if 46 - 46: O0 + iII111i % I1IiiI / o0oOOo0O0Ooo . IiII * I11i
  if 93 - 93: o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
  if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
  if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
  if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
  if ( I1Ii1 . count ( "'" ) == 2 ) : continue
  if ( I1Ii1 . count ( "." ) != 3 and I1Ii1 . find ( ":" ) == - 1 ) : continue
  if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
  I1Ii1 , O0oO = I1Ii1 . split ( "/" )
  IIII , I1Ii1 , IIiIi1iI = o0oO ( I1Ii1 )
  if ( v4v6 and I1Ii1 . find ( "." ) == - 1 ) : continue
  if ( v4v6 == False and I1Ii1 . find ( ":" ) == - 1 ) : continue
  if 73 - 73: I1ii11iIi11i * i11iIiiIii % oO0o . I1ii11iIi11i
  i1 = ooo0OOOoo [ "rlocs" ] [ 0 ] [ "rloc" ]
  OOOOo0 = "translated-rloc" in ooo0OOOoo [ "rlocs" ] [ 0 ]
  if 49 - 49: II111iiii % O0 . OoOoOO00 + oO0o / I1IiiI
  if ( match_iid == None ) : return ( IIII , I1Ii1 , i1 , OOOOo0 )
  if 72 - 72: ooOoO0o * Oo0Ooo . I1IiiI - II111iiii + i1IIi
  iIi1ii = i1I1iI1iIi111i ( match_eid , I1Ii1 , int ( O0oO ) )
  if ( match_iid == IIII and iIi1ii ) :
   return ( None , None , i1 , OOOOo0 )
   if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
   if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 return ( None , None , None , None )
 if 97 - 97: O0 + OoOoOO00
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
def oO00O000oO0 ( user , pw , http , port ) :
 oO0o0Ooooo = ( "curl --silent --insecure -u {}:{} {}://localhost:{}/lisp/" + "api/data/map-cache" ) . format ( user , pw , http , port )
 if 79 - 79: I11i - OoooooooOO - oO0o - iIii1I11I1II1 * OOooOOo
 oO0 = getoutput ( oO0o0Ooooo )
 if 4 - 4: i11iIiiIii . OoooooooOO / OoO0O00 % I1Ii111 % I11i * O0
 try :
  oOI1Ii1I1 = json . loads ( oO0 )
 except :
  return ( [ ] )
  if 14 - 14: OOooOOo / o0oOOo0O0Ooo
  if 32 - 32: I1IiiI * Oo0Ooo
 O0OooOo0o = [ ]
 for ooo0OOOoo in oOI1Ii1I1 :
  if ( "group-prefix" in ooo0OOOoo ) : continue
  if ( ( "eid-prefix" in ooo0OOOoo ) == False ) : continue
  if ( ooo0OOOoo [ "eid-prefix" ] != "0.0.0.0/0" ) : continue
  if 29 - 29: I1IiiI % I1IiiI
  for i1 in ooo0OOOoo [ "rloc-set" ] :
   if ( ( "rloc-name" in i1 ) == False ) : continue
   if ( i1 [ "rloc-name" ] != "RTR" ) : continue
   if ( ( "address" in i1 ) == False ) : continue
   O0OooOo0o . append ( i1 [ "address" ] )
   if 94 - 94: iIii1I11I1II1 / Oo0Ooo % iII111i * iII111i * II111iiii
   if 29 - 29: OoO0O00 + OoOoOO00 / o0oOOo0O0Ooo / OOooOOo * iIii1I11I1II1
 return ( O0OooOo0o )
 if 62 - 62: OOooOOo / oO0o - OoO0O00 . I11i
 if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
 if 76 - 76: IiII * iII111i
def oOOOOo0 ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 52 - 52: OOooOOo
 if 19 - 19: I1IiiI
 if 25 - 25: Ii1I / ooOoO0o
 if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 if 71 - 71: I1Ii111 . II111iiii
 if 62 - 62: OoooooooOO . I11i
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
def OO0oOoOO0oOO0 ( string ) :
 return ( "\033[94m" + oOOOOo0 ( string ) + "\033[0m" )
 if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 58 - 58: I1IiiI
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
def oo0oOo ( string ) :
 return ( "\033[91m" + oOOOOo0 ( string ) + "\033[0m" )
 if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 if 23 - 23: i11iIiiIii
 if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
 if 81 - 81: IiII % i1IIi . iIii1I11I1II1
 if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
 if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
 if 31 - 31: OOooOOo
 if 23 - 23: I1Ii111 . IiII
def OO0000o ( deid , v4v6 ) :
 if ( v4v6 ) :
  i1I1i1 = int ( deid . split ( "." ) [ 0 ] )
  if ( i1I1i1 < 224 or i1I1i1 >= 240 ) : return
 else :
  if ( deid [ 0 : 2 ] . lower ( ) != "ff" ) : return
  if 81 - 81: ooOoO0o - iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * I11i
 print ( "Multicast EID not supported" )
 exit ( 1 )
 if 20 - 20: oO0o % IiII
 if 19 - 19: I1ii11iIi11i % IiII + ooOoO0o / I1Ii111 . ooOoO0o
 if 12 - 12: i1IIi + i1IIi - I1ii11iIi11i * Oo0Ooo % Oo0Ooo - II111iiii
 if 52 - 52: ooOoO0o . iII111i + I1Ii111
 if 38 - 38: i1IIi - II111iiii . I1Ii111
 if 58 - 58: I1IiiI . iII111i + OoOoOO00
 if 66 - 66: iII111i / oO0o * OoooooooOO + OoooooooOO % I11i
if ( "-s" in sys . argv ) :
 IIii1111 = len ( sys . argv ) != 4
else :
 IIii1111 = len ( sys . argv ) != 2
 if 42 - 42: I11i / o0oOOo0O0Ooo . oO0o + oO0o % OoOoOO00 + i11iIiiIii
if ( IIii1111 ) :
 print ( "Usage: python ltr.py [-s <source-eid>] <destination-EID | DNS-name>" )
 exit ( 1 )
 if 56 - 56: o0oOOo0O0Ooo
 if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
iII1i1 , O0oOOoooOO0O , IIiIi1iI = o0oO ( sys . argv [ - 1 ] )
if ( iII1i1 == None ) :
 print ( "<destinaton-eid> parse error" )
 exit ( 1 )
 if 86 - 86: o0oOOo0O0Ooo
i1Iii11Ii1i1 = O0oOOoooOO0O . find ( ":" ) == - 1
if 59 - 59: Oo0Ooo % OoooooooOO . iII111i / IiII + I1IiiI
if 76 - 76: ooOoO0o
if 73 - 73: O0 * iII111i + Ii1I + ooOoO0o
if 40 - 40: II111iiii . OoOoOO00 * I1Ii111 + OOooOOo + OOooOOo
if 9 - 9: I11i % OoooooooOO . oO0o % I11i
OO0000o ( O0oOOoooOO0O , i1Iii11Ii1i1 )
if 32 - 32: i11iIiiIii
if 31 - 31: iIii1I11I1II1 / OoO0O00 / I1ii11iIi11i
if 41 - 41: Oo0Ooo
if 10 - 10: Oo0Ooo / Oo0Ooo / I1Ii111 . I1Ii111
if ( "-s" in sys . argv ) :
 O0i1II1Iiii1I11 = sys . argv . index ( "-s" ) + 1
 OOoo , iIIiiiI , IIiIi1iI = o0oO ( sys . argv [ O0i1II1Iiii1I11 ] )
 if ( OOoo == None ) :
  print ( "-s <source-eid> parse error" )
  exit ( 1 )
  if 60 - 60: I1IiiI . I1Ii111
 if ( IIiIi1iI ) : OOoo = None
 IiI111ii1ii , O0OOo , i1 , OOOOo0 = OoO0o ( OOoo , iIIiiiI , OOo , Ii1IIii11 , II1iII1i , oO0oIIII , i1Iii11Ii1i1 )
 if ( i1 == None ) :
  print ( "[{}]{} not a local EID, maybe lispers.net API pw/port wrong" . format ( OOoo , iIIiiiI ) )
  if 38 - 38: iIii1I11I1II1 + I1ii11iIi11i - OOooOOo - ooOoO0o - OoOoOO00
  exit ( 1 )
  if 71 - 71: OOooOOo / Ii1I % OoO0O00
else :
 OOoo , iIIiiiI , i1 , OOOOo0 = OoO0o ( None , None , OOo , Ii1IIii11 , II1iII1i , oO0oIIII , i1Iii11Ii1i1 )
 if ( OOoo == None ) :
  print ( "Could not find local EID, maybe lispers.net API pw/port wrong?" )
  exit ( 1 )
  if 50 - 50: OOooOOo / Ii1I % ooOoO0o . OoOoOO00
  if 41 - 41: OOooOOo * Ii1I - IiII + o0oOOo0O0Ooo
  if 64 - 64: Ii1I
  if 66 - 66: i11iIiiIii - OOooOOo * Oo0Ooo
  if 76 - 76: i11iIiiIii + o0oOOo0O0Ooo / I1ii11iIi11i - OoO0O00 - Ii1I + I1ii11iIi11i
  if 51 - 51: iIii1I11I1II1 . ooOoO0o + iIii1I11I1II1
iII1i1 = OOoo if iII1i1 == "0" else iII1i1
if ( iII1i1 != OOoo ) :
 print ( "Instance-IDs must be the same for source and destination EIDs" )
 exit ( 1 )
 if 95 - 95: I1IiiI
 if 46 - 46: OoOoOO00 + OoO0O00
 if 70 - 70: iII111i / iIii1I11I1II1
 if 85 - 85: OoooooooOO % i1IIi * OoooooooOO / I1ii11iIi11i
 if 96 - 96: OoooooooOO + oO0o
iiII1i11i = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
iiII1i11i . bind ( ( "0::0" , 0 ) )
iiII1i11i . settimeout ( 3 )
II = iiII1i11i . getsockname ( ) [ 1 ]
if 11 - 11: I1IiiI / II111iiii + o0oOOo0O0Ooo * I1ii11iIi11i - I1ii11iIi11i - I1IiiI
if 85 - 85: I11i % oO0o / iIii1I11I1II1 . iIii1I11I1II1
if 31 - 31: o0oOOo0O0Ooo % OoO0O00
if 14 - 14: oO0o / oO0o % ooOoO0o
O0o0Oo , iiIIiIiIi = oO ( i1 , II )
if 56 - 56: I1IiiI . O0 + Oo0Ooo
if 1 - 1: iII111i
if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
if ( OOOOo0 ) :
 O0OooOo0o = oO00O000oO0 ( OOo , Ii1IIii11 , II1iII1i , oO0oIIII )
 for IIii11I1i1I in O0OooOo0o :
  print ( "Send NAT-traversal LISP-Trace to RTR {} ..." . format ( IIii11I1i1I ) )
  iiII1i11i . sendto ( iiIIiIiIi , ( "::ffff:" + IIii11I1i1I , OOo000 ) )
  if 99 - 99: iII111i
  if 76 - 76: OoO0O00 * I1IiiI
  if 82 - 82: Ii1I * iII111i / I1ii11iIi11i
print ( "Send round-trip LISP-Trace between EIDs [{}]{} and [{}]{} ..." . format ( OOoo , iIIiiiI , iII1i1 , O0oOOoooOO0O ) )
if 36 - 36: OoooooooOO - i1IIi . O0 / II111iiii + o0oOOo0O0Ooo
if 33 - 33: II111iiii / ooOoO0o * O0 % Ii1I * I1Ii111
O0o = O0oOOoooOO0O if ( O0oOOoooOO0O . find ( ":" ) != - 1 ) else "::ffff:" + O0oOOoooOO0O
OO0O0OoOO0 = time . time ( )
if 72 - 72: OOooOOo % I1ii11iIi11i + OoO0O00 / oO0o + IiII
if 10 - 10: I1Ii111 / ooOoO0o + i11iIiiIii / Ii1I
if 74 - 74: OOooOOo + O0 + i1IIi - i1IIi + II111iiii
if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
try :
 iiII1i11i . sendto ( iiIIiIiIi , ( O0o , OOo000 ) )
except socket . error as O0ooO0Oo00o :
 print ( "sock.sendto() failed: {}" . format ( O0ooO0Oo00o ) )
 exit ( 1 )
 if 5 - 5: Ii1I
 if 46 - 46: IiII
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if 17 - 17: OOooOOo / OOooOOo / I11i
try :
 iiIIiIiIi , ii1 = iiII1i11i . recvfrom ( 9000 )
 ii1 = ii1 [ 0 ] . replace ( "::ffff:" , "" )
except socket . timeout :
 exit ( 1 )
except socket . error as O0ooO0Oo00o :
 print ( "sock.recvfrom() failed, error: {}" . format ( O0ooO0Oo00o ) )
 exit ( 1 )
 if 1 - 1: ooOoO0o % iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % I1IiiI
 if 89 - 89: Ii1I
ooOoOO0OoO00o = round ( time . time ( ) - OO0O0OoOO0 , 3 )
if 11 - 11: Oo0Ooo - I1IiiI * II111iiii . I1ii11iIi11i . oO0o
print ( "Received reply from {}, rtt {} secs" . format ( ii1 , ooOoOO0OoO00o ) )
print ( "" )
Ii11iII1 = i1iiI11I ( O0o0Oo , iiIIiIiIi )
if ( Ii11iII1 == { } ) : exit ( 1 )
if 61 - 61: iII111i % I1IiiI - o0oOOo0O0Ooo - II111iiii % O0
if 90 - 90: iIii1I11I1II1 + I1ii11iIi11i + ooOoO0o - I1Ii111 * IiII . I1ii11iIi11i
if 37 - 37: ooOoO0o % i11iIiiIii % II111iiii . O0 . Ii1I
if 51 - 51: OoO0O00 - O0 % oO0o - II111iiii
i1I11i1iI ( Ii11iII1 )
if 31 - 31: iII111i / Oo0Ooo - iII111i - OOooOOo
iiII1i11i . close ( )
exit ( 0 )
if 7 - 7: iII111i % O0 . OoOoOO00 + I1IiiI - I11i
if 75 - 75: I11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3