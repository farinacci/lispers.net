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
#   { "seid" : "[<iid>]<orig-eid>", "deid" : "[<iid>]<dest-eid>", "paths" : a
#   [
#     { "node" : "ITR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#       "encap-ts" : "<ts>", "hn" : "<hn>", "rtts" : [...], "hops" : [...] }, 
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#       "decap-ts" : "<ts>", "hn" : "<hn>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#       "encap-ts" : "<ts>", "hn" : "<hn>", "rtts" : [...], "hops" : [...] }, 
#     { "node" : "ETR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#       "encap-ts" : "<ts>", "hn" : "<hn>" }, ...
#   ] },
# 
#   { "seid" : "[<iid>]<dest-eid>", "deid" : "[<iid>]<orig-eid>", "paths" :
#   [
#     { "node" : "ITR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#       "encap-ts" : "<ts>", "hn" : "<hn>", "rtts" : [...], "hops" : [...] }, 
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#       "decap-ts" : "<ts>", "hn" : "<hn>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#       "encap-ts" : "<ts>", "hn" : "<hn>", "rtts" : [...], "hops" : [...] }, 
#     { "node" : "ETR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#       "encap-ts" : "<ts>", "hn" : "<hn>" }, ...
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
import sys
import struct
import random
import socket
import json
import time
import os
import binascii
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
Oo0o = "https"
OOO0o0o = 8080
if 40 - 40: I1IiiI / O0 % ooOoO0o + O0 * i1IIi
I1Ii11I1Ii1i = os . getenv ( "LISP_LTR_PORT" )
if ( I1Ii11I1Ii1i != None ) :
 if ( I1Ii11I1Ii1i [ 0 ] == "-" ) :
  Oo0o = "http"
  I1Ii11I1Ii1i = I1Ii11I1Ii1i [ 1 : : ]
  if 67 - 67: iIii1I11I1II1 . I1ii11iIi11i . oO0o / i1IIi % II111iiii - OoOoOO00
 if ( I1Ii11I1Ii1i . isdigit ( ) == False ) :
  print ( "Invalid value for env variable LISP_LTR_PORT" )
  exit ( 1 )
  if 91 - 91: OoO0O00 . i11iIiiIii / oO0o % I11i / OoO0O00 - i11iIiiIii
 OOO0o0o = int ( I1Ii11I1Ii1i )
 if 8 - 8: o0oOOo0O0Ooo * I1ii11iIi11i * iIii1I11I1II1 . IiII / IiII % IiII
i11 = os . getenv ( "LISP_LTR_USER" )
I11 = os . getenv ( "LISP_LTR_PW" )
if ( i11 == None ) : i11 = "root"
if ( I11 == None ) : I11 = ""
if 98 - 98: i11iIiiIii * I1IiiI % iII111i * iII111i * II111iiii
o0o0Oo0oooo0 = 2434
if 97 - 97: Oo0Ooo - ooOoO0o
if 54 - 54: ooOoO0o . ooOoO0o / iIii1I11I1II1 / I11i + oO0o / o0oOOo0O0Ooo
if 39 - 39: I11i / I1Ii111 . I11i - I11i
if 68 - 68: OOooOOo . I1IiiI / iII111i
if 72 - 72: OoO0O00 / OoO0O00
if 30 - 30: OoO0O00
if 95 - 95: oO0o * o0oOOo0O0Ooo / II111iiii . I1ii11iIi11i + OOooOOo
if 47 - 47: OoOoOO00 / Ii1I * OoooooooOO
if 9 - 9: I1IiiI - Ii1I % i1IIi % OoooooooOO
if 3 - 3: iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
if 78 - 78: OoO0O00
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
if 14 - 14: I11i % O0
if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
if 77 - 77: Oo0Ooo . IiII % ooOoO0o
if 42 - 42: oO0o - i1IIi / i11iIiiIii + OOooOOo + OoO0O00
if 17 - 17: oO0o . Oo0Ooo . I1ii11iIi11i
if 3 - 3: OoOoOO00 . Oo0Ooo . I1IiiI / Ii1I
def IiiiI1II1I1 ( rloc , port ) :
 oo = socket . htonl ( 0x90000000 + port )
 Ii11iI1i = struct . pack ( "I" , oo )
 if 82 - 82: i11iIiiIii . OOooOOo / Oo0Ooo * O0 % oO0o % iIii1I11I1II1
 Oo00OOOOO = rloc . split ( "." )
 O0O = int ( Oo00OOOOO [ 0 ] ) << 24
 O0O += int ( Oo00OOOOO [ 1 ] ) << 16
 O0O += int ( Oo00OOOOO [ 2 ] ) << 8
 O0O += int ( Oo00OOOOO [ 3 ] )
 Ii11iI1i += struct . pack ( "I" , socket . htonl ( O0O ) )
 if 83 - 83: I11i + II111iiii * o0oOOo0O0Ooo % OoO0O00 + I11i
 Ii1iIIIi1ii = random . randint ( 0 , ( 2 ** 64 ) - 1 )
 Ii11iI1i += struct . pack ( "Q" , Ii1iIIIi1ii )
 return ( Ii1iIIIi1ii , Ii11iI1i )
 if 80 - 80: I11i * i11iIiiIii / I1Ii111
 if 9 - 9: Ii1I + oO0o % Ii1I + i1IIi . OOooOOo
 if 31 - 31: o0oOOo0O0Ooo + I11i + I11i / II111iiii
 if 26 - 26: OoooooooOO
 if 12 - 12: OoooooooOO % OoOoOO00 / ooOoO0o % o0oOOo0O0Ooo
 if 29 - 29: OoooooooOO
 if 23 - 23: o0oOOo0O0Ooo . II111iiii
def Oo0O0OOOoo ( nonce , packet ) :
 if ( len ( packet ) < 12 ) : return ( False )
 if 95 - 95: OoO0O00 % oO0o . O0
 I1i1I = "II"
 oOO00oOO = struct . calcsize ( I1i1I )
 oo , OoOo = struct . unpack ( I1i1I , packet [ : oOO00oOO ] )
 packet = packet [ oOO00oOO : : ]
 if ( socket . ntohl ( oo ) != 0x90000000 ) :
  print ( "Invalid LISP-Trace message" )
  return ( { } )
  if 18 - 18: i11iIiiIii
  if 46 - 46: i1IIi / I11i % OOooOOo + I1Ii111
 I1i1I = "Q"
 oOO00oOO = struct . calcsize ( I1i1I )
 O0OOO00oo = struct . unpack ( I1i1I , packet [ : oOO00oOO ] ) [ 0 ]
 packet = packet [ oOO00oOO : : ]
 if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 if 4 - 4: II111iiii / ooOoO0o . iII111i
 if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 if 50 - 50: I1IiiI
 if ( O0OOO00oo != nonce ) :
  print ( "Invalid nonce, sent {}, received {}" . format ( nonce , O0OOO00oo ) )
  return ( { } )
  if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
  if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 if ( len ( packet ) == 0 ) :
  print ( "No JSON data in payload" )
  return ( { } )
  if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
  if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
  if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
  if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
  if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 try :
  oo000OO00Oo = json . loads ( packet )
 except :
  print ( "Invalid JSON data: '{}'" . format ( packet ) )
  return ( { } )
  if 51 - 51: IiII * o0oOOo0O0Ooo + I11i + OoO0O00
 return ( oo000OO00Oo )
 if 66 - 66: OoOoOO00
 if 97 - 97: oO0o % IiII * IiII
 if 39 - 39: Ii1I % IiII
 if 4 - 4: oO0o
 if 93 - 93: OoO0O00 % oO0o . OoO0O00 * I1Ii111 % Ii1I . II111iiii
 if 38 - 38: o0oOOo0O0Ooo
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
def i11iIIIIIi1 ( jd ) :
 for iiII1i1 in jd :
  print ( "Path from {} to {}:" . format ( iiII1i1 [ "seid" ] , iiII1i1 [ "deid" ] ) )
  for o00oOO0o in iiII1i1 [ "paths" ] :
   if ( "encap-ts" in o00oOO0o ) :
    OOO00O = o00oOO0o [ "encap-ts" ]
    OOoOO0oo0ooO = "encap"
    if 98 - 98: iII111i * iII111i / iII111i + I11i
   if ( "decap-ts" in o00oOO0o ) :
    OOO00O = o00oOO0o [ "decap-ts" ]
    OOoOO0oo0ooO = "decap"
    if 34 - 34: ooOoO0o
   I1111I1iII11 = o00oOO0o [ "hn" ]
   Oooo0O0oo00oO = o00oOO0o [ "drloc" ]
   if ( Oooo0O0oo00oO . find ( "?" ) != - 1 ) : Oooo0O0oo00oO = IIi1i ( Oooo0O0oo00oO )
   if 46 - 46: I1Ii111 % I11i + OoO0O00 . OoOoOO00 . OoO0O00
   print ( "  {} {}: {} -> {}, ts {}, node {}" . format ( o00oOO0o [ "node" ] , OOoOO0oo0ooO , o00oOO0o [ "srloc" ] , Oooo0O0oo00oO , OOO00O , oO00o0 ( I1111I1iII11 ) ) )
   if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
   if 25 - 25: I1ii11iIi11i
   if ( "rtts" in o00oOO0o and "hops" in o00oOO0o ) :
    Ii1i = json . dumps ( o00oOO0o [ "rtts" ] )
    Ii1i = Ii1i . replace ( "-1" , "?" )
    I1 = json . dumps ( o00oOO0o [ "hops" ] )
    I1 = I1 . replace ( "u" , "" )
    I1 = I1 . replace ( "'" , "" )
    I1 = I1 . replace ( '"' , "" )
    print ( "            " , end = ' ' )
    print ( "recent-rtts {}, recent-hops {}" . format ( Ii1i , I1 ) )
    if 15 - 15: II111iiii
    if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
    if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
  print ( "" )
  if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
  if 91 - 91: O0
  if 61 - 61: II111iiii
  if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
  if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
  if 42 - 42: OoO0O00
  if 67 - 67: I1Ii111 . iII111i . O0
  if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
def OOOOoOoo0O0O0 ( eid ) :
 OOOo00oo0oO = True
 if 1 - 1: OoO0O00 - oO0o . I11i . OoO0O00 / Oo0Ooo + I11i
 if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
 if 49 - 49: Ii1I / OoO0O00 . II111iiii
 if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
 if 31 - 31: II111iiii . I1IiiI
 II1I = eid . find ( "]" )
 if ( II1I == - 1 ) :
  O0i1II1Iiii1I11 = "0"
 else :
  OOOo00oo0oO = False
  O0i1II1Iiii1I11 = eid [ 1 : II1I ]
  eid = eid [ II1I + 1 : : ]
  if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
  if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
  if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
  if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
  if 51 - 51: O0 + iII111i
 if ( eid . find ( ":" ) == - 1 ) :
  try : eid = socket . gethostbyname ( eid )
  except : pass
  if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 return ( O0i1II1Iiii1I11 , eid , OOOo00oo0oO )
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % I1Ii111
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
def i1 ( eid , eid_prefix , ml ) :
 I1iI1iIi111i = 2 ** ml - 1
 if 44 - 44: i1IIi % II111iiii + I11i
 I1I1I = eid . split ( "." )
 if ( len ( I1I1I ) == 1 ) : I1I1I = eid . split ( ":" )
 if ( len ( I1I1I ) == 1 ) : return ( False )
 if 95 - 95: II111iiii + o0oOOo0O0Ooo + iII111i * iIii1I11I1II1 % oO0o / IiII
 if ( len ( I1I1I ) == 4 ) :
  I1iI1iIi111i = I1iI1iIi111i << ( 32 - ml )
  eid = int ( I1I1I [ 0 ] ) << 24 | int ( I1I1I [ 1 ] ) << 16 | int ( I1I1I [ 2 ] ) << 8 | int ( I1I1I [ 3 ] )
  I1I1I = eid & I1iI1iIi111i
  eid = "{}.{}.{}.{}" . format ( ( I1I1I >> 24 ) & 0xff , ( I1I1I >> 16 ) & 0xff ,
 ( I1I1I >> 8 ) & 0xff , I1I1I & 0xff )
 else :
  I1iI1iIi111i = I1iI1iIi111i << ( 128 - ml )
  eid = socket . inet_pton ( socket . AF_INET6 , eid )
  eid = int ( binascii . hexlify ( eid ) , 16 )
  I1I1I = eid & I1iI1iIi111i
  eid = binascii . unhexlify ( hex ( I1I1I ) [ 2 : - 1 ] )
  eid = socket . inet_ntop ( socket . AF_INET6 , eid )
  if 56 - 56: iII111i
 return ( eid == eid_prefix )
 if 86 - 86: II111iiii % I1Ii111
 if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 if 53 - 53: II111iiii
 if 31 - 31: OoO0O00
 if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: OoO0O00
 if 62 - 62: OOooOOo + O0
def oO0OOOO0 ( match_iid , match_eid , user , pw , http , port , v4v6 ) :
 iI1I11iiI1i = ( "curl --silent --insecure -u {}:{} {}://localhost:{}/lisp/" + "api/data/database-mapping" ) . format ( user , pw , http , port )
 if 78 - 78: oO0o % O0 % Ii1I
 ii = getoutput ( iI1I11iiI1i )
 if 5 - 5: ooOoO0o - II111iiii - OoooooooOO % Ii1I + I1IiiI * iIii1I11I1II1
 try :
  I1I1II1I11 = json . loads ( ii )
 except :
  return ( None , None , None , None )
  if 8 - 8: o0oOOo0O0Ooo % O0 / I1IiiI - oO0o
  if 43 - 43: i11iIiiIii + Oo0Ooo * II111iiii * I1Ii111 * O0
 for o00oO0oo0OO in I1I1II1I11 :
  if ( ( "eid-prefix" in o00oO0oo0OO ) == False ) : continue
  O0O0OOOOoo = o00oO0oo0OO [ "eid-prefix" ]
  if 74 - 74: I1ii11iIi11i + II111iiii / OoO0O00
  if 100 - 100: OoOoOO00 * iIii1I11I1II1
  if 86 - 86: OoO0O00 * OOooOOo . iII111i
  if 32 - 32: o0oOOo0O0Ooo . IiII * I11i
  if 93 - 93: o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
  if ( O0O0OOOOoo . count ( "'" ) == 2 ) : continue
  if ( O0O0OOOOoo . count ( "." ) != 3 and O0O0OOOOoo . find ( ":" ) == - 1 ) : continue
  if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
  O0O0OOOOoo , O00o0OO0 = O0O0OOOOoo . split ( "/" )
  O0i1II1Iiii1I11 , O0O0OOOOoo , OOOo00oo0oO = OOOOoOoo0O0O0 ( O0O0OOOOoo )
  if ( v4v6 and O0O0OOOOoo . find ( "." ) == - 1 ) : continue
  if ( v4v6 == False and O0O0OOOOoo . find ( ":" ) == - 1 ) : continue
  if 35 - 35: oO0o % ooOoO0o / I1Ii111 + iIii1I11I1II1 . OoooooooOO . I1IiiI
  OoOo = o00oO0oo0OO [ "rlocs" ] [ 0 ] [ "rloc" ]
  o00oOOooOOo0o = "translated-rloc" in o00oO0oo0OO [ "rlocs" ] [ 0 ]
  if 66 - 66: iII111i - iII111i - i11iIiiIii . I1ii11iIi11i - OOooOOo
  if ( match_iid == None ) : return ( O0i1II1Iiii1I11 , O0O0OOOOoo , OoOo , o00oOOooOOo0o )
  if 77 - 77: OoOoOO00 - II111iiii - ooOoO0o
  IiiiIIiIi1 = i1 ( match_eid , O0O0OOOOoo , int ( O00o0OO0 ) )
  if ( match_iid == O0i1II1Iiii1I11 and IiiiIIiIi1 ) :
   return ( None , None , OoOo , o00oOOooOOo0o )
   if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
   if 62 - 62: OoooooooOO * I1IiiI
 return ( None , None , None , None )
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if 97 - 97: O0 + OoOoOO00
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
def Oo ( user , pw , http , port ) :
 iI1I11iiI1i = ( "curl --silent --insecure -u {}:{} {}://localhost:{}/lisp/" + "api/data/map-cache" ) . format ( user , pw , http , port )
 if 34 - 34: oO0o + I1IiiI - oO0o
 ii = getoutput ( iI1I11iiI1i )
 if 17 - 17: II111iiii % iII111i + I11i - iII111i / OOooOOo + ooOoO0o
 try :
  I1I1II1I11 = json . loads ( ii )
 except :
  return ( [ ] )
  if 59 - 59: OOooOOo % OoOoOO00 . Ii1I * I1ii11iIi11i % I11i
  if 59 - 59: oO0o - iII111i
 I1ii1I1 = [ ]
 for o00oO0oo0OO in I1I1II1I11 :
  if ( "group-prefix" in o00oO0oo0OO ) : continue
  if ( ( "eid-prefix" in o00oO0oo0OO ) == False ) : continue
  if ( o00oO0oo0OO [ "eid-prefix" ] != "0.0.0.0/0" ) : continue
  if 93 - 93: O0 % i1IIi . OOooOOo / I1IiiI - I1Ii111 / I1IiiI
  for OoOo in o00oO0oo0OO [ "rloc-set" ] :
   if ( ( "rloc-name" in OoOo ) == False ) : continue
   if ( OoOo [ "rloc-name" ] != "RTR" ) : continue
   if ( ( "address" in OoOo ) == False ) : continue
   I1ii1I1 . append ( OoOo [ "address" ] )
   if 36 - 36: oO0o % oO0o % i1IIi / i1IIi - ooOoO0o
   if 30 - 30: I11i / I1IiiI
 return ( I1ii1I1 )
 if 35 - 35: II111iiii % OOooOOo . ooOoO0o + ooOoO0o % II111iiii % II111iiii
 if 72 - 72: II111iiii + i1IIi + o0oOOo0O0Ooo
 if 94 - 94: oO0o . i1IIi - o0oOOo0O0Ooo % O0 - OoO0O00
 if 72 - 72: Ii1I
 if 1 - 1: OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
def I1II1 ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 86 - 86: iIii1I11I1II1 / OoOoOO00 . II111iiii
 if 19 - 19: I1ii11iIi11i % OoooooooOO % IiII * o0oOOo0O0Ooo % O0
 if 67 - 67: I1IiiI . i1IIi
 if 27 - 27: ooOoO0o % I1IiiI
 if 73 - 73: OOooOOo
 if 70 - 70: iIii1I11I1II1
 if 31 - 31: IiII - I1IiiI % iIii1I11I1II1
def oO00o0 ( string ) :
 return ( "\033[94m" + I1II1 ( string ) + "\033[0m" )
 if 92 - 92: i1IIi - iIii1I11I1II1
 if 16 - 16: OoO0O00 - OoOoOO00 - OOooOOo - i1IIi / Ii1I
 if 88 - 88: OoO0O00
 if 71 - 71: I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i - I1IiiI . iIii1I11I1II1 - i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
def IIi1i ( string ) :
 return ( "\033[91m" + I1II1 ( string ) + "\033[0m" )
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
 if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 if 23 - 23: i11iIiiIii
 if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
 if 81 - 81: IiII % i1IIi . iIii1I11I1II1
 if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
 if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
def iiii111II ( deid , v4v6 ) :
 if ( v4v6 ) :
  I11iIiI1I1i11 = int ( deid . split ( "." ) [ 0 ] )
  if ( I11iIiI1I1i11 < 224 or I11iIiI1I1i11 >= 240 ) : return
 else :
  if ( deid [ 0 : 2 ] . lower ( ) != "ff" ) : return
  if 92 - 92: I1ii11iIi11i * i1IIi . oO0o / I1Ii111
 print ( "Multicast EID not supported" )
 exit ( 1 )
 if 85 - 85: I11i
 if 20 - 20: oO0o % IiII
 if 19 - 19: I1ii11iIi11i % IiII + ooOoO0o / I1Ii111 . ooOoO0o
 if 12 - 12: i1IIi + i1IIi - I1ii11iIi11i * Oo0Ooo % Oo0Ooo - II111iiii
 if 52 - 52: ooOoO0o . iII111i + I1Ii111
 if 38 - 38: i1IIi - II111iiii . I1Ii111
 if 58 - 58: I1IiiI . iII111i + OoOoOO00
if ( "-s" in sys . argv ) :
 O00OO = len ( sys . argv ) != 4
else :
 O00OO = len ( sys . argv ) != 2
 if 17 - 17: I11i / I1Ii111 + oO0o - i11iIiiIii . iII111i
if ( O00OO ) :
 print ( "Usage: python ltr.py [-s <source-eid>] <destination-EID | DNS-name>" )
 exit ( 1 )
 if 95 - 95: OoO0O00 % i1IIi * i11iIiiIii % Oo0Ooo - oO0o
 if 67 - 67: OoOoOO00 + I1ii11iIi11i . o0oOOo0O0Ooo . II111iiii
o000ooooO0o , iI1i11 , OOOo00oo0oO = OOOOoOoo0O0O0 ( sys . argv [ - 1 ] )
if ( o000ooooO0o == None ) :
 print ( "<destinaton-eid> parse error" )
 exit ( 1 )
 if 66 - 66: O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / Ii1I + I1ii11iIi11i
ooo00Ooo = iI1i11 . find ( ":" ) == - 1
if 93 - 93: i11iIiiIii - I1IiiI * I1ii11iIi11i * I11i % O0 + OoooooooOO
if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
iiii111II ( iI1i11 , ooo00Ooo )
if 19 - 19: OoO0O00 - Oo0Ooo . O0
if 60 - 60: II111iiii + Oo0Ooo
if 9 - 9: ooOoO0o * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
if 49 - 49: II111iiii
if ( "-s" in sys . argv ) :
 II1I = sys . argv . index ( "-s" ) + 1
 Iiii1iI1i , I1ii1ii11i1I , OOOo00oo0oO = OOOOoOoo0O0O0 ( sys . argv [ II1I ] )
 if ( Iiii1iI1i == None ) :
  print ( "-s <source-eid> parse error" )
  exit ( 1 )
  if 58 - 58: iII111i + Oo0Ooo
 if ( OOOo00oo0oO ) : Iiii1iI1i = None
 II1I1I1Ii , OOOOoO00o0O , OoOo , o00oOOooOOo0o = oO0OOOO0 ( Iiii1iI1i , I1ii1ii11i1I , i11 , I11 , Oo0o , OOO0o0o , ooo00Ooo )
 if ( OoOo == None ) :
  print ( "[{}]{} not a local EID, maybe lispers.net API pw/port wrong" . format ( Iiii1iI1i , I1ii1ii11i1I ) )
  if 41 - 41: OOooOOo * Ii1I - IiII + o0oOOo0O0Ooo
  exit ( 1 )
  if 64 - 64: Ii1I
else :
 Iiii1iI1i , I1ii1ii11i1I , OoOo , o00oOOooOOo0o = oO0OOOO0 ( None , None , i11 , I11 , Oo0o , OOO0o0o , ooo00Ooo )
 if ( Iiii1iI1i == None ) :
  print ( "Could not find local EID, maybe lispers.net API pw/port wrong?" )
  exit ( 1 )
  if 66 - 66: i11iIiiIii - OOooOOo * Oo0Ooo
  if 76 - 76: i11iIiiIii + o0oOOo0O0Ooo / I1ii11iIi11i - OoO0O00 - Ii1I + I1ii11iIi11i
  if 51 - 51: iIii1I11I1II1 . ooOoO0o + iIii1I11I1II1
  if 95 - 95: I1IiiI
  if 46 - 46: OoOoOO00 + OoO0O00
  if 70 - 70: iII111i / iIii1I11I1II1
o000ooooO0o = Iiii1iI1i if o000ooooO0o == "0" else o000ooooO0o
if ( o000ooooO0o != Iiii1iI1i ) :
 print ( "Instance-IDs must be the same for source and destination EIDs" )
 exit ( 1 )
 if 85 - 85: OoooooooOO % i1IIi * OoooooooOO / I1ii11iIi11i
 if 96 - 96: OoooooooOO + oO0o
 if 44 - 44: oO0o
 if 20 - 20: I11i + Ii1I / O0 % iIii1I11I1II1
 if 88 - 88: OoOoOO00 / II111iiii
OOOOO0O00 = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
OOOOO0O00 . bind ( ( "0::0" , 0 ) )
OOOOO0O00 . settimeout ( 3 )
I1Ii11I1Ii1i = OOOOO0O00 . getsockname ( ) [ 1 ]
if 30 - 30: iIii1I11I1II1 . I1IiiI . OOooOOo / o0oOOo0O0Ooo
if 42 - 42: Oo0Ooo
if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
if 46 - 46: Oo0Ooo
Ii1iIIIi1ii , Ii11iI1i = IiiiI1II1I1 ( OoOo , I1Ii11I1Ii1i )
if 1 - 1: iII111i
if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
if ( o00oOOooOOo0o ) :
 I1ii1I1 = Oo ( i11 , I11 , Oo0o , OOO0o0o )
 for Oo00o0OO0O00o in I1ii1I1 :
  print ( "Send NAT-traversal LISP-Trace to RTR {} ..." . format ( Oo00o0OO0O00o ) )
  OOOOO0O00 . sendto ( Ii11iI1i , ( "::ffff:" + Oo00o0OO0O00o , o0o0Oo0oooo0 ) )
  if 82 - 82: I11i + OoooooooOO - i1IIi . i1IIi
  if 6 - 6: o0oOOo0O0Ooo / I11i / II111iiii
  if 27 - 27: OOooOOo * ooOoO0o . I1Ii111 % IiII * IiII . i1IIi
print ( "Send round-trip LISP-Trace between EIDs [{}]{} and [{}]{} ..." . format ( Iiii1iI1i , I1ii1ii11i1I , o000ooooO0o , iI1i11 ) )
if 72 - 72: OOooOOo % I1ii11iIi11i + OoO0O00 / oO0o + IiII
if 10 - 10: I1Ii111 / ooOoO0o + i11iIiiIii / Ii1I
OOO00O = time . time ( )
if 74 - 74: OOooOOo + O0 + i1IIi - i1IIi + II111iiii
oOOO0oo0 = iI1i11 if ( iI1i11 . find ( ":" ) != - 1 ) else "::ffff:" + iI1i11
try :
 OOOOO0O00 . sendto ( Ii11iI1i , ( oOOO0oo0 , o0o0Oo0oooo0 ) )
except socket . error as I1I1I :
 print ( "socket.sendto() failed: {}" . format ( I1I1I ) )
 exit ( 1 )
 if 46 - 46: IiII
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if 17 - 17: OOooOOo / OOooOOo / I11i
 if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
try :
 Ii11iI1i , OooO0oo = OOOOO0O00 . recvfrom ( 9000 )
 OooO0oo = OooO0oo [ 0 ] . replace ( "::ffff:" , "" )
except socket . timeout :
 exit ( 1 )
except socket . error as I1I1I :
 print ( "recvfrom() failed, error: {}" . format ( I1I1I ) )
 exit ( 1 )
 if 89 - 89: Ii1I
 if 76 - 76: ooOoO0o
II = round ( time . time ( ) - OOO00O , 3 )
if 45 - 45: OoooooooOO - OOooOOo + O0 * Ii1I . I1ii11iIi11i
print ( "Received reply from {}, rtt {} secs" . format ( OooO0oo , II ) )
print ( "" )
oo000OO00Oo = Oo0O0OOOoo ( Ii1iIIIi1ii , Ii11iI1i )
if ( oo000OO00Oo == { } ) : exit ( 1 )
if 39 - 39: iIii1I11I1II1 / O0 / oO0o - Ii1I - iII111i % OOooOOo
if 31 - 31: I11i - O0 / ooOoO0o * OoOoOO00
if 12 - 12: o0oOOo0O0Ooo - ooOoO0o * I1Ii111
if 14 - 14: Oo0Ooo - Ii1I % Ii1I * O0 . i11iIiiIii / O0
i11iIIIIIi1 ( oo000OO00Oo )
if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
OOOOO0O00 . close ( )
exit ( 0 )
if 28 - 28: i1IIi - iII111i
if 54 - 54: iII111i - O0 % OOooOOo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
