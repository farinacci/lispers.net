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
  iii11 = oOOOOo0 ( I1ii1Ii1 [ "se" ] )
  iiII1i1 = oOOOOo0 ( I1ii1Ii1 [ "de" ] )
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
   print ( "  {} {}: {} -> {}, ts {}, node {}" . format ( I1i1III [ "n" ] , iiiI1I11i1 , OO0oOoOO0oOO0 ( I1i1III [ "sr" ] ) , OO0oOoOO0oOO0 ( o0 ) , OO0O0OoOO0 , oO0OOoo0OO ( oo0O ) ) )
   if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
   if 21 - 21: I1IiiI * iIii1I11I1II1
   if ( "rtts" in I1i1III and "hops" in I1i1III and "lats" in I1i1III ) :
    oooooOoo0ooo = json . dumps ( I1i1III [ "rtts" ] )
    oooooOoo0ooo = oooooOoo0ooo . replace ( "-1" , "?" )
    I1I1IiI1 = json . dumps ( I1i1III [ "hops" ] )
    I1I1IiI1 = I1I1IiI1 . replace ( "u" , "" )
    I1I1IiI1 = I1I1IiI1 . replace ( "'" , "" )
    I1I1IiI1 = I1I1IiI1 . replace ( '"' , "" )
    III1iII1I1ii = json . dumps ( I1i1III [ "lats" ] )
    III1iII1I1ii = III1iII1I1ii . replace ( "u" , "" )
    III1iII1I1ii = III1iII1I1ii . replace ( "'" , "" )
    III1iII1I1ii = III1iII1I1ii . replace ( '"' , "" )
    print ( "            " , end = ' ' )
    print ( "recent-rtts {}, recent-hops {}" . format ( oooooOoo0ooo , I1I1IiI1 ) )
    print ( "             recent-latencies {}" . format ( III1iII1I1ii ) )
    if 61 - 61: II111iiii
    if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
  print ( "" )
  if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
  if 42 - 42: OoO0O00
  if 67 - 67: I1Ii111 . iII111i . O0
  if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
  if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
  if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
  if 83 - 83: I11i / I1IiiI
  if 34 - 34: IiII
def oOo ( eid ) :
 oOO00Oo = True
 if 6 - 6: oO0o
 if 68 - 68: OoOoOO00 - OoO0O00
 if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
 if 1 - 1: iIii1I11I1II1 / II111iiii
 if 33 - 33: I11i
 iI11i1ii11 = eid . find ( "]" )
 if ( iI11i1ii11 == - 1 ) :
  OOooo0O00o = "0"
 else :
  oOO00Oo = False
  OOooo0O00o = eid [ 1 : iI11i1ii11 ]
  eid = eid [ iI11i1ii11 + 1 : : ]
  if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo
  if 32 - 32: OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
  if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
  if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
  if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if ( eid . find ( ":" ) == - 1 ) :
  try : eid = socket . gethostbyname ( eid )
  except : pass
  if 51 - 51: O0 + iII111i
 return ( OOooo0O00o , eid , oOO00Oo )
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % I1Ii111
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
def OOOOOoo0 ( eid , eid_prefix , ml ) :
 ii1 = 2 ** ml - 1
 if 11 - 11: IiII * I1IiiI . iIii1I11I1II1 % OoooooooOO + iII111i
 OOO = eid . split ( "." )
 if ( len ( OOO ) == 1 ) : OOO = eid . split ( ":" )
 if ( len ( OOO ) == 1 ) : return ( False )
 if 68 - 68: II111iiii + I11i
 if ( len ( OOO ) == 4 ) :
  ii1 = ii1 << ( 32 - ml )
  eid = int ( OOO [ 0 ] ) << 24 | int ( OOO [ 1 ] ) << 16 | int ( OOO [ 2 ] ) << 8 | int ( OOO [ 3 ] )
  OOO = eid & ii1
  eid = "{}.{}.{}.{}" . format ( ( OOO >> 24 ) & 0xff , ( OOO >> 16 ) & 0xff ,
 ( OOO >> 8 ) & 0xff , OOO & 0xff )
 else :
  ii1 = ii1 << ( 128 - ml )
  eid = socket . inet_pton ( socket . AF_INET6 , eid )
  eid = int ( binascii . hexlify ( eid ) , 16 )
  OOO = eid & ii1
  eid = binascii . unhexlify ( hex ( OOO ) [ 2 : - 1 ] )
  eid = socket . inet_ntop ( socket . AF_INET6 , eid )
  if 45 - 45: iII111i / iII111i + I1Ii111 + ooOoO0o
 return ( eid == eid_prefix )
 if 47 - 47: o0oOOo0O0Ooo + ooOoO0o
 if 82 - 82: II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
 if 77 - 77: iIii1I11I1II1 * OoO0O00
 if 95 - 95: I1IiiI + i11iIiiIii
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 if 53 - 53: II111iiii
 if 31 - 31: OoO0O00
 if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
def iIiIIi1 ( match_iid , match_eid , user , pw , http , port , v4v6 ) :
 I1IIII1i = ( "curl --silent --insecure -u {}:{} {}://localhost:{}/lisp/" + "api/data/database-mapping" ) . format ( user , pw , http , port )
 if 2 - 2: I11i + Ii1I - I1IiiI % o0oOOo0O0Ooo . iII111i
 I1I1i1I = getoutput ( I1IIII1i )
 if 30 - 30: OoooooooOO
 try :
  I1Ii1iI1 = json . loads ( I1I1i1I )
 except :
  return ( None , None , None , None )
  if 87 - 87: Oo0Ooo . IiII
  if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
 for oOI1Ii1I1 in I1Ii1iI1 :
  if ( ( "eid-prefix" in oOI1Ii1I1 ) == False ) : continue
  IiII111iI1ii1 = oOI1Ii1I1 [ "eid-prefix" ]
  if 37 - 37: oO0o - I1Ii111 % Oo0Ooo
  if 77 - 77: Oo0Ooo - i1IIi - I11i . OoOoOO00
  if 39 - 39: II111iiii / ooOoO0o + I1Ii111 / OoOoOO00
  if 13 - 13: IiII + O0 + iII111i % I1IiiI / o0oOOo0O0Ooo . IiII
  if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
  if ( IiII111iI1ii1 . count ( "'" ) == 2 ) : continue
  if ( IiII111iI1ii1 . count ( "." ) != 3 and IiII111iI1ii1 . find ( ":" ) == - 1 ) : continue
  if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
  IiII111iI1ii1 , O00o0OO0 = IiII111iI1ii1 . split ( "/" )
  OOooo0O00o , IiII111iI1ii1 , oOO00Oo = oOo ( IiII111iI1ii1 )
  if ( v4v6 and IiII111iI1ii1 . find ( "." ) == - 1 ) : continue
  if ( v4v6 == False and IiII111iI1ii1 . find ( ":" ) == - 1 ) : continue
  if 35 - 35: oO0o % ooOoO0o / I1Ii111 + iIii1I11I1II1 . OoooooooOO . I1IiiI
  i1 = oOI1Ii1I1 [ "rlocs" ] [ 0 ] [ "rloc" ]
  o00oOOooOOo0o = "translated-rloc" in oOI1Ii1I1 [ "rlocs" ] [ 0 ]
  if 66 - 66: iII111i - iII111i - i11iIiiIii . I1ii11iIi11i - OOooOOo
  if ( match_iid == None ) : return ( OOooo0O00o , IiII111iI1ii1 , i1 , o00oOOooOOo0o )
  if 77 - 77: OoOoOO00 - II111iiii - ooOoO0o
  IiiiIIiIi1 = OOOOOoo0 ( match_eid , IiII111iI1ii1 , int ( O00o0OO0 ) )
  if ( match_iid == OOooo0O00o and IiiiIIiIi1 ) :
   return ( None , None , i1 , o00oOOooOOo0o )
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
 I1IIII1i = ( "curl --silent --insecure -u {}:{} {}://localhost:{}/lisp/" + "api/data/map-cache" ) . format ( user , pw , http , port )
 if 34 - 34: oO0o + I1IiiI - oO0o
 I1I1i1I = getoutput ( I1IIII1i )
 if 17 - 17: II111iiii % iII111i + I11i - iII111i / OOooOOo + ooOoO0o
 try :
  I1Ii1iI1 = json . loads ( I1I1i1I )
 except :
  return ( [ ] )
  if 59 - 59: OOooOOo % OoOoOO00 . Ii1I * I1ii11iIi11i % I11i
  if 59 - 59: oO0o - iII111i
 I1 = [ ]
 for oOI1Ii1I1 in I1Ii1iI1 :
  if ( "group-prefix" in oOI1Ii1I1 ) : continue
  if ( ( "eid-prefix" in oOI1Ii1I1 ) == False ) : continue
  if ( oOI1Ii1I1 [ "eid-prefix" ] != "0.0.0.0/0" ) : continue
  if 11 - 11: I1IiiI
  for i1 in oOI1Ii1I1 [ "rloc-set" ] :
   if ( ( "rloc-name" in i1 ) == False ) : continue
   if ( i1 [ "rloc-name" ] != "RTR" ) : continue
   if ( ( "address" in i1 ) == False ) : continue
   I1 . append ( i1 [ "address" ] )
   if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
   if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
 return ( I1 )
 if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
 if 71 - 71: I1Ii111 + Ii1I
 if 28 - 28: OOooOOo
 if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
 if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
 if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
def I11I ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 50 - 50: I1Ii111 * i11iIiiIii * iIii1I11I1II1 - II111iiii * o0oOOo0O0Ooo * OoOoOO00
 if 94 - 94: OoooooooOO + OoooooooOO . II111iiii + I11i / I1ii11iIi11i % Ii1I
 if 18 - 18: iII111i * O0 - OoooooooOO % I1IiiI . II111iiii / i1IIi
 if 76 - 76: I11i / OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 if 71 - 71: I1Ii111 . II111iiii
 if 62 - 62: OoooooooOO . I11i
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
def oOOOOo0 ( string ) :
 return ( "\033[92m" + string + "\033[0m" )
 if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 58 - 58: I1IiiI
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
def oO0OOoo0OO ( string ) :
 return ( "\033[94m" + string + "\033[0m" )
 if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 if 23 - 23: i11iIiiIii
 if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
 if 81 - 81: IiII % i1IIi . iIii1I11I1II1
 if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
 if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
 if 31 - 31: OOooOOo
def OO0oOoOO0oOO0 ( string ) :
 return ( "\033[91m" + string + "\033[0m" )
 if 23 - 23: I1Ii111 . IiII
 if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
 if 42 - 42: Oo0Ooo
 if 76 - 76: I1IiiI * iII111i % I1Ii111
 if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
 if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
 if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
def oo0oOo ( string ) :
 return ( "\033[91m" + I11I ( string ) + "\033[0m" )
 if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
 if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
 if 42 - 42: I1IiiI
 if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
 if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
 if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
 if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
 if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
def iII1i1 ( deid , v4v6 ) :
 if ( v4v6 ) :
  O0oOOoooOO0O = int ( deid . split ( "." ) [ 0 ] )
  if ( O0oOOoooOO0O < 224 or O0oOOoooOO0O >= 240 ) : return
 else :
  if ( deid [ 0 : 2 ] . lower ( ) != "ff" ) : return
  if 86 - 86: o0oOOo0O0Ooo
 print ( "Multicast EID not supported" )
 exit ( 1 )
 if 5 - 5: IiII * OoOoOO00
 if 5 - 5: I1Ii111
 if 90 - 90: I1Ii111 . ooOoO0o / Ii1I - I11i
 if 40 - 40: OoooooooOO
 if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
 if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
 if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
if ( "-s" in sys . argv ) :
 I1iiiiIii = len ( sys . argv ) != 4
else :
 I1iiiiIii = len ( sys . argv ) != 2
 if 19 - 19: OoO0O00 - Oo0Ooo . O0
if ( I1iiiiIii ) :
 print ( "Usage: python ltr.py [-s <source-eid>] <destination-EID | DNS-name>" )
 exit ( 1 )
 if 60 - 60: II111iiii + Oo0Ooo
 if 9 - 9: ooOoO0o * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
iiIIi , iiI1iI111ii1i , oOO00Oo = oOo ( sys . argv [ - 1 ] )
if ( iiIIi == None ) :
 print ( "<destinaton-eid> parse error" )
 exit ( 1 )
 if 32 - 32: II111iiii * OoOoOO00 % i1IIi - iII111i + iIii1I11I1II1 + I1ii11iIi11i
OO0O0Oo000 = iiI1iI111ii1i . find ( ":" ) == - 1
if 41 - 41: i1IIi - I11i - Ii1I
if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
if 44 - 44: II111iiii
if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
iII1i1 ( iiI1iI111ii1i , OO0O0Oo000 )
if 35 - 35: iIii1I11I1II1
if 42 - 42: I1Ii111 . I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI
if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
Iii1iiIi1II = False
if ( "-s" in sys . argv ) :
 iI11i1ii11 = sys . argv . index ( "-s" ) + 1
 OO0O00oOo , ii1II , oOO00Oo = oOo ( sys . argv [ iI11i1ii11 ] )
 if ( OO0O00oOo == None ) :
  print ( "-s <source-eid> parse error" )
  exit ( 1 )
  if 14 - 14: oO0o / oO0o % ooOoO0o
 if ( oOO00Oo ) : OO0O00oOo = None
 ooO , ii , i1 , o00oOOooOOo0o = iIiIIi1 ( OO0O00oOo , ii1II , OOo , Ii1IIii11 , II1iII1i , oO0oIIII , OO0O0Oo000 )
 if ( i1 == None ) :
  print ( "[{}]{} not a local EID, maybe lispers.net API pw/port wrong" . format ( OO0O00oOo , ii1II ) )
  if 82 - 82: OoOoOO00 - OoO0O00 % OoOoOO00 * i11iIiiIii . II111iiii % II111iiii
  Iii1iiIi1II = True
  if 54 - 54: I11i + Ii1I
else :
 OO0O00oOo , ii1II , i1 , o00oOOooOOo0o = iIiIIi1 ( None , None , OOo , Ii1IIii11 , II1iII1i , oO0oIIII , OO0O0Oo000 )
 if ( OO0O00oOo == None ) :
  Iii1iiIi1II = True
  print ( "Could not find local EID, maybe lispers.net API pw/port wrong?" )
  if 55 - 55: iIii1I11I1II1
  if 78 - 78: iII111i + I11i . ooOoO0o - iII111i . Ii1I
if ( Iii1iiIi1II ) :
 print ( "If root password configured, set env variable LISP_LTR_PW" )
 print ( "If LISP not started on port 8080, set env variable LISP_LTR_PORT" )
 exit ( 1 )
 if 30 - 30: I1IiiI + OoO0O00 % Ii1I * iII111i / Oo0Ooo - I11i
 if 64 - 64: iIii1I11I1II1
 if 21 - 21: Oo0Ooo . II111iiii
 if 54 - 54: II111iiii % II111iiii
 if 86 - 86: O0 % Ii1I * ooOoO0o * iIii1I11I1II1 * i1IIi * I11i
iiIIi = OO0O00oOo if iiIIi == "0" else iiIIi
if ( iiIIi != OO0O00oOo ) :
 print ( "Instance-IDs must be the same for source and destination EIDs" )
 exit ( 1 )
 if 83 - 83: OoOoOO00 % II111iiii - OoOoOO00 + IiII - O0
 if 52 - 52: Oo0Ooo * ooOoO0o
 if 33 - 33: Ii1I
 if 74 - 74: OOooOOo + O0 + i1IIi - i1IIi + II111iiii
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
iIi1Ii1i1iI = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
iIi1Ii1i1iI . bind ( ( "0::0" , 0 ) )
iIi1Ii1i1iI . settimeout ( 3 )
II = iIi1Ii1i1iI . getsockname ( ) [ 1 ]
if 16 - 16: OOooOOo / Oo0Ooo / OoooooooOO * I1IiiI + i1IIi % OOooOOo
if 71 - 71: OoOoOO00
if 14 - 14: i11iIiiIii % OOooOOo
if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
O0o0Oo , iiIIiIiIi = oO ( i1 , II )
if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
if 9 - 9: Ii1I
if 59 - 59: I1IiiI * II111iiii . O0
if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
if ( o00oOOooOOo0o ) :
 I1 = Oo ( OOo , Ii1IIii11 , II1iII1i , oO0oIIII )
 for Oo00O in I1 :
  print ( "Send NAT-traversal LISP-Trace to RTR {} ..." . format ( Oo00O ) )
  iIi1Ii1i1iI . sendto ( iiIIiIiIi , ( "::ffff:" + Oo00O , OOo000 ) )
  if 12 - 12: o0oOOo0O0Ooo - ooOoO0o * I1Ii111
  if 14 - 14: Oo0Ooo - Ii1I % Ii1I * O0 . i11iIiiIii / O0
  if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
ii1III11 = I11I ( ii1II )
I1iiIIIi11 = I11I ( iiI1iI111ii1i )
print ( "Send round-trip LISP-Trace between EIDs {} and {} ..." . format ( ii1III11 , I1iiIIIi11 ) )
if 12 - 12: OoooooooOO % o0oOOo0O0Ooo * I11i % iIii1I11I1II1 / Ii1I
Ii1ii1IiIII = iiI1iI111ii1i if ( iiI1iI111ii1i . find ( ":" ) != - 1 ) else "::ffff:" + iiI1iI111ii1i
OO0O0OoOO0 = time . time ( )
if 57 - 57: iIii1I11I1II1 / I11i - i1IIi
if 51 - 51: IiII
if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
try :
 iIi1Ii1i1iI . sendto ( iiIIiIiIi , ( Ii1ii1IiIII , OOo000 ) )
except socket . error as OOO :
 print ( "sock.sendto() failed: {}" . format ( OOO ) )
 exit ( 1 )
 if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
 if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
try :
 iiIIiIiIi , oo000 = iIi1Ii1i1iI . recvfrom ( 9000 )
 oo000 = oo000 [ 0 ] . replace ( "::ffff:" , "" )
except socket . timeout :
 exit ( 1 )
except socket . error as OOO :
 print ( "sock.recvfrom() failed, error: {}" . format ( OOO ) )
 exit ( 1 )
 if 32 - 32: i1IIi . Ii1I
 if 59 - 59: OoooooooOO
i1iiiii1 = round ( time . time ( ) - OO0O0OoOO0 , 3 )
if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
print ( "Received reply from {}, rtt {} secs" . format ( oo000 , i1iiiii1 ) )
print ( "" )
Ii11iII1 = i1iiI11I ( O0o0Oo , iiIIiIiIi )
if ( Ii11iII1 == { } ) : exit ( 1 )
if 100 - 100: OoO0O00
if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
if 45 - 45: I1Ii111
i1I11i1iI ( Ii11iII1 )
if 83 - 83: OoOoOO00 . OoooooooOO
iIi1Ii1i1iI . close ( )
exit ( 0 )
if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
if 62 - 62: OoO0O00 / I1ii11iIi11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
