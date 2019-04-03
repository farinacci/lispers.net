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
if 64 - 64: i11iIiiIii
import sys
import struct
import random
import socket
import json
import commands
import time
import os
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
  print "Invalid value for env variable LISP_LTR_PORT"
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
  print "Invalid LISP-Trace message"
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
  print "Invalid nonce, sent {}, received {}" . format ( nonce , O0OOO00oo )
  return ( { } )
  if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
  if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 if ( len ( packet ) == 0 ) :
  print "No JSON data in payload"
  return ( { } )
  if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
  if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
  if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
  if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
  if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 try :
  oo000OO00Oo = json . loads ( packet )
 except :
  print "Invalid JSON data: '{}'" . format ( packet )
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
  print "Path from {} to {}:" . format ( iiII1i1 [ "seid" ] , iiII1i1 [ "deid" ] )
  for o00oOO0o in iiII1i1 [ "paths" ] :
   if ( o00oOO0o . has_key ( "encap-ts" ) ) :
    OOO00O = o00oOO0o [ "encap-ts" ]
    OOoOO0oo0ooO = "encap"
    if 98 - 98: iII111i * iII111i / iII111i + I11i
   if ( o00oOO0o . has_key ( "decap-ts" ) ) :
    OOO00O = o00oOO0o [ "decap-ts" ]
    OOoOO0oo0ooO = "decap"
    if 34 - 34: ooOoO0o
   I1111I1iII11 = o00oOO0o [ "hn" ]
   Oooo0O0oo00oO = o00oOO0o [ "drloc" ]
   if ( Oooo0O0oo00oO . find ( "?" ) != - 1 ) : Oooo0O0oo00oO = IIi1i ( Oooo0O0oo00oO )
   if 46 - 46: I1Ii111 % I11i + OoO0O00 . OoOoOO00 . OoO0O00
   print "  {} {}: {} -> {}, ts {}, node {}" . format ( o00oOO0o [ "node" ] , OOoOO0oo0ooO , o00oOO0o [ "srloc" ] , Oooo0O0oo00oO , OOO00O , oO00o0 ( I1111I1iII11 ) )
   if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
   if 25 - 25: I1ii11iIi11i
   if ( o00oOO0o . has_key ( "rtts" ) and o00oOO0o . has_key ( "hops" ) ) :
    Ii1i = json . dumps ( o00oOO0o [ "rtts" ] )
    Ii1i = Ii1i . replace ( "-1" , "?" )
    I1 = json . dumps ( o00oOO0o [ "hops" ] )
    I1 = I1 . replace ( "u" , "" )
    I1 = I1 . replace ( "'" , "" )
    I1 = I1 . replace ( '"' , "" )
    print "            " ,
    print "recent-rtts {}, recent-hops {}" . format ( Ii1i , I1 )
    if 15 - 15: II111iiii
    if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
    if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
  print ""
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
 if 23 - 23: O0
 if 85 - 85: Ii1I
 if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
def IIi1 ( match_iid , match_eid , user , pw , http , port , v4v6 ) :
 I1I1I = ( "curl --silent --insecure -u {}:{} {}://localhost:{}/lisp/" + "api/data/database-mapping" ) . format ( user , pw , http , port )
 if 95 - 95: II111iiii + o0oOOo0O0Ooo + iII111i * iIii1I11I1II1 % oO0o / IiII
 o0o0o0oO0oOO = commands . getoutput ( I1I1I )
 if 3 - 3: o0oOOo0O0Ooo
 try :
  Ii11I1 = json . loads ( o0o0o0oO0oOO )
 except :
  return ( None , None , None , None )
  if 14 - 14: OOooOOo % iIii1I11I1II1
  if 71 - 71: O0 . iII111i / o0oOOo0O0Ooo
 for Ooo in Ii11I1 :
  if ( Ooo . has_key ( "eid-prefix" ) == False ) : continue
  iIi1IiIiiII = Ooo [ "eid-prefix" ]
  iIi1IiIiiII = iIi1IiIiiII . split ( "/" ) [ 0 ]
  O0i1II1Iiii1I11 , iIi1IiIiiII , OOOo00oo0oO = OOOOoOoo0O0O0 ( iIi1IiIiiII )
  if ( v4v6 and iIi1IiIiiII . find ( "." ) == - 1 ) : continue
  if ( v4v6 == False and iIi1IiIiiII . find ( ":" ) == - 1 ) : continue
  if 25 - 25: O0 - O0 * o0oOOo0O0Ooo
  OoOo = Ooo [ "rlocs" ] [ 0 ] [ "rloc" ]
  OOOO0oo0 = Ooo [ "rlocs" ] [ 0 ] . has_key ( "translated-rloc" )
  if 35 - 35: Ii1I - I1IiiI % o0oOOo0O0Ooo . OoooooooOO % Ii1I
  if ( match_iid == None ) : return ( O0i1II1Iiii1I11 , iIi1IiIiiII , OoOo , OOOO0oo0 )
  if ( match_iid == O0i1II1Iiii1I11 and match_eid == iIi1IiIiiII ) :
   return ( None , None , OoOo , OOOO0oo0 )
   if 47 - 47: iII111i - Ii1I . II111iiii + OoooooooOO . i11iIiiIii
   if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 return ( None , None , None , None )
 if 87 - 87: Oo0Ooo . IiII
 if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
 if 55 - 55: OOooOOo . I1IiiI
 if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
 if 100 - 100: I1Ii111 * O0
 if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
 if 79 - 79: O0
def oOO00O ( user , pw , http , port ) :
 I1I1I = ( "curl --silent --insecure -u {}:{} {}://localhost:{}/lisp/" + "api/data/map-cache" ) . format ( user , pw , http , port )
 if 77 - 77: Oo0Ooo - i1IIi - I11i . OoOoOO00
 o0o0o0oO0oOO = commands . getoutput ( I1I1I )
 if 39 - 39: II111iiii / ooOoO0o + I1Ii111 / OoOoOO00
 try :
  Ii11I1 = json . loads ( o0o0o0oO0oOO )
 except :
  return ( [ ] )
  if 13 - 13: IiII + O0 + iII111i % I1IiiI / o0oOOo0O0Ooo . IiII
  if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
 oOOoo00O00o = [ ]
 for Ooo in Ii11I1 :
  if ( Ooo . has_key ( "group-prefix" ) ) : continue
  if ( Ooo . has_key ( "eid-prefix" ) == False ) : continue
  if ( Ooo [ "eid-prefix" ] != "0.0.0.0/0" ) : continue
  if 98 - 98: OOooOOo + IiII + oO0o % OoooooooOO
  for OoOo in Ooo [ "rloc-set" ] :
   if ( OoOo . has_key ( "rloc-name" ) == False ) : continue
   if ( OoOo [ "rloc-name" ] != "RTR" ) : continue
   if ( OoOo . has_key ( "address" ) == False ) : continue
   oOOoo00O00o . append ( OoOo [ "address" ] )
   if 97 - 97: O0 * OoooooooOO . OoooooooOO
   if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 return ( oOOoo00O00o )
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 if 49 - 49: I1IiiI - I11i
 if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
 if 62 - 62: OoooooooOO * I1IiiI
def oOOOoo0O0oO ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 6 - 6: OOooOOo * o0oOOo0O0Ooo + iII111i
 if 44 - 44: Ii1I % OoO0O00 + OoooooooOO - O0 - Ii1I - II111iiii
 if 99 - 99: ooOoO0o . Ii1I + I1Ii111 + OoooooooOO % o0oOOo0O0Ooo
 if 51 - 51: iIii1I11I1II1
 if 34 - 34: oO0o + I1IiiI - oO0o
 if 17 - 17: II111iiii % iII111i + I11i - iII111i / OOooOOo + ooOoO0o
 if 59 - 59: OOooOOo % OoOoOO00 . Ii1I * I1ii11iIi11i % I11i
def oO00o0 ( string ) :
 return ( "\033[94m" + oOOOoo0O0oO ( string ) + "\033[0m" )
 if 59 - 59: oO0o - iII111i
 if 15 - 15: I1Ii111 . i11iIiiIii . OoooooooOO / OoO0O00 % Ii1I
 if 93 - 93: O0 % i1IIi . OOooOOo / I1IiiI - I1Ii111 / I1IiiI
 if 36 - 36: oO0o % oO0o % i1IIi / i1IIi - ooOoO0o
 if 30 - 30: I11i / I1IiiI
 if 35 - 35: II111iiii % OOooOOo . ooOoO0o + ooOoO0o % II111iiii % II111iiii
 if 72 - 72: II111iiii + i1IIi + o0oOOo0O0Ooo
def IIi1i ( string ) :
 return ( "\033[91m" + oOOOoo0O0oO ( string ) + "\033[0m" )
 if 94 - 94: oO0o . i1IIi - o0oOOo0O0Ooo % O0 - OoO0O00
 if 72 - 72: Ii1I
 if 1 - 1: OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
if ( "-s" in sys . argv ) :
 o00Oo0oooooo = len ( sys . argv ) != 4
else :
 o00Oo0oooooo = len ( sys . argv ) != 2
 if 76 - 76: I11i / OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
if ( o00Oo0oooooo ) :
 print "Usage: python ltr.py [-s <source-eid>] <destination-EID | DNS-name>"
 exit ( 1 )
 if 71 - 71: I1Ii111 . II111iiii
 if 62 - 62: OoooooooOO . I11i
oOOOoo00 , iiIiIIIiiI , OOOo00oo0oO = OOOOoOoo0O0O0 ( sys . argv [ - 1 ] )
if ( oOOOoo00 == None ) :
 print "<destinaton-eid> parse error"
 exit ( 1 )
 if 12 - 12: O0 - o0oOOo0O0Ooo
oOoO00O0 = iiIiIIIiiI . find ( ":" ) == - 1
if 75 - 75: I1IiiI . ooOoO0o . O0 * I1Ii111
if 4 - 4: Ii1I % oO0o * OoO0O00
if 100 - 100: I1Ii111 * OOooOOo + OOooOOo
if 54 - 54: OoooooooOO + o0oOOo0O0Ooo - i1IIi % i11iIiiIii
if ( "-s" in sys . argv ) :
 II1I = sys . argv . index ( "-s" ) + 1
 iII1iIi11i , o0ooooO0o0O , OOOo00oo0oO = OOOOoOoo0O0O0 ( sys . argv [ II1I ] )
 if ( iII1iIi11i == None ) :
  print "-s <source-eid> parse error"
  exit ( 1 )
  if 24 - 24: O0 * o0oOOo0O0Ooo
 if ( OOOo00oo0oO ) : iII1iIi11i = None
 IiI1iiiIii , I1III1111iIi , OoOo , OOOO0oo0 = IIi1 ( iII1iIi11i , o0ooooO0o0O , i11 , I11 , Oo0o , OOO0o0o , oOoO00O0 )
 if ( OoOo == None ) :
  print "[{}]{} is not a local EID" . format ( iII1iIi11i , o0ooooO0o0O )
  exit ( 1 )
  if 38 - 38: iII111i + I11i / I1Ii111 % ooOoO0o - I1ii11iIi11i
else :
 iII1iIi11i , o0ooooO0o0O , OoOo , OOOO0oo0 = IIi1 ( None , None , i11 , I11 , Oo0o , OOO0o0o , oOoO00O0 )
 if ( iII1iIi11i == None ) :
  print "Could not find local EID, maybe lispers.net API port wrong?"
  exit ( 1 )
  if 14 - 14: oO0o / I1Ii111
  if 85 - 85: I11i
  if 20 - 20: oO0o % IiII
  if 19 - 19: I1ii11iIi11i % IiII + ooOoO0o / I1Ii111 . ooOoO0o
  if 12 - 12: i1IIi + i1IIi - I1ii11iIi11i * Oo0Ooo % Oo0Ooo - II111iiii
  if 52 - 52: ooOoO0o . iII111i + I1Ii111
oOOOoo00 = iII1iIi11i if oOOOoo00 == "0" else oOOOoo00
if ( oOOOoo00 != iII1iIi11i ) :
 print "Instance-IDs must be the same for source and destination EIDs"
 exit ( 1 )
 if 38 - 38: i1IIi - II111iiii . I1Ii111
 if 58 - 58: I1IiiI . iII111i + OoOoOO00
 if 66 - 66: iII111i / oO0o * OoooooooOO + OoooooooOO % I11i
 if 49 - 49: oO0o - i11iIiiIii . I1Ii111 * Ii1I % iII111i + i1IIi
 if 71 - 71: o0oOOo0O0Ooo
IIIIiIiIi1 = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
IIIIiIiIi1 . bind ( ( "0::0" , 0 ) )
IIIIiIiIi1 . settimeout ( 3 )
I1Ii11I1Ii1i = IIIIiIiIi1 . getsockname ( ) [ 1 ]
if 2 - 2: iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
if 79 - 79: O0 * i11iIiiIii - IiII / IiII
Ii1iIIIi1ii , Ii11iI1i = IiiiI1II1I1 ( OoOo , I1Ii11I1Ii1i )
if 48 - 48: O0
if 93 - 93: i11iIiiIii - I1IiiI * I1ii11iIi11i * I11i % O0 + OoooooooOO
if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
if ( OOOO0oo0 ) :
 oOOoo00O00o = oOO00O ( i11 , I11 , Oo0o , OOO0o0o )
 for II1I1Ii in oOOoo00O00o :
  print "Send NAT-traversal LISP-Trace to RTR {} ..." . format ( II1I1Ii )
  IIIIiIiIi1 . sendto ( Ii11iI1i , ( "::ffff:" + II1I1Ii , o0o0Oo0oooo0 ) )
  if 62 - 62: O0 % I11i . I11i - iIii1I11I1II1 / i11iIiiIii
  if 31 - 31: iIii1I11I1II1 / OoO0O00 / I1ii11iIi11i
  if 41 - 41: Oo0Ooo
print "Send round-trip LISP-Trace between EIDs [{}]{} and [{}]{} ..." . format ( iII1iIi11i , o0ooooO0o0O , oOOOoo00 , iiIiIIIiiI )
if 10 - 10: Oo0Ooo / Oo0Ooo / I1Ii111 . I1Ii111
if 98 - 98: Oo0Ooo / I1IiiI . O0 + OoO0O00
OOO00O = time . time ( )
if 43 - 43: II111iiii . oO0o / I1ii11iIi11i
i1iI1 = iiIiIIIiiI if ( iiIiIIIiiI . find ( ":" ) != - 1 ) else "::ffff:" + iiIiIIIiiI
try :
 IIIIiIiIi1 . sendto ( Ii11iI1i , ( i1iI1 , o0o0Oo0oooo0 ) )
except socket . error , i11ii1ii11i :
 print "socket.sendto() failed: {}" . format ( i11ii1ii11i )
 exit ( 1 )
 if 70 - 70: i1IIi - iII111i + Oo0Ooo
 if 12 - 12: o0oOOo0O0Ooo - I1ii11iIi11i % OoOoOO00 * I11i
 if 44 - 44: iII111i % Ii1I
 if 41 - 41: i1IIi - I11i - Ii1I
 if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
try :
 Ii11iI1i , IIIi11I11 = IIIIiIiIi1 . recvfrom ( 9000 )
 IIIi11I11 = IIIi11I11 [ 0 ] . replace ( "::ffff:" , "" )
except socket . timeout :
 exit ( 1 )
except socket . error , i11ii1ii11i :
 print "recvfrom() failed, error: {}" . format ( i11ii1ii11i )
 exit ( 1 )
 if 44 - 44: II111iiii
 if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
iI1 = round ( time . time ( ) - OOO00O , 3 )
if 12 - 12: I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI / iII111i
print "Received reply from {}, rtt {} secs" . format ( IIIi11I11 , iI1 )
print ""
oo000OO00Oo = Oo0O0OOOoo ( Ii1iIIIi1ii , Ii11iI1i )
if ( oo000OO00Oo == { } ) : exit ( 1 )
if 12 - 12: OOooOOo - ooOoO0o . OoooooooOO / I1ii11iIi11i . i1IIi * OoO0O00
if 19 - 19: i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
i11iIIIIIi1 ( oo000OO00Oo )
if 71 - 71: O0 - iIii1I11I1II1
IIIIiIiIi1 . close ( )
exit ( 0 )
if 12 - 12: OOooOOo / o0oOOo0O0Ooo
if 42 - 42: Oo0Ooo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
