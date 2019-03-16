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
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "decap-timestamp" : "<ts>", "hostname" : "<hn>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>" },
#     { "node" : "ETR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>" }, ...
#   ] },
# 
#   { "seid" : "[<iid>]<dest-eid>", "deid" : "[<iid>]<orig-eid>", "paths" :
#   [
#     { "node" : "ITR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "decap-timestamp" : "<ts>", "hostname" : "<hn>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>" },
#     { "node" : "ETR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>" }, ...
#   ] }
# ]
#
# Environment variable LISP_LTR_PORT is used to determine if th connection to
# the LISP API is done with a particular port. And if the port has a minus
# sign in front of it, it will use http rather https to connect to the
# lispers.net API.
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
 if 22 - 22: Ii1I . IiII
I11 = 2434
if 98 - 98: i11iIiiIii * I1IiiI % iII111i * iII111i * II111iiii
if 79 - 79: IiII
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
def IiI1I1 ( rloc , port ) :
 OoO000 = socket . htonl ( 0x90000000 + port )
 IIiiIiI1 = struct . pack ( "I" , OoO000 )
 if 41 - 41: OoOoOO00
 II = rloc . split ( "." )
 ooOoOoo0O = int ( II [ 0 ] ) << 24
 ooOoOoo0O += int ( II [ 1 ] ) << 16
 ooOoOoo0O += int ( II [ 2 ] ) << 8
 ooOoOoo0O += int ( II [ 3 ] )
 IIiiIiI1 += struct . pack ( "I" , socket . htonl ( ooOoOoo0O ) )
 if 76 - 76: O0 / o0oOOo0O0Ooo . I1IiiI * Ii1I - OOooOOo
 Oooo = random . randint ( 0 , ( 2 ** 64 ) - 1 )
 IIiiIiI1 += struct . pack ( "Q" , Oooo )
 return ( Oooo , IIiiIiI1 )
 if 67 - 67: OOooOOo / OoooooooOO % I11i - iIii1I11I1II1
 if 82 - 82: i11iIiiIii . OOooOOo / Oo0Ooo * O0 % oO0o % iIii1I11I1II1
 if 78 - 78: iIii1I11I1II1 - Ii1I * OoO0O00 + o0oOOo0O0Ooo + iII111i + iII111i
 if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
def III1ii1iII ( nonce , packet ) :
 if ( len ( packet ) < 12 ) : return ( False )
 if 54 - 54: I1IiiI % II111iiii % II111iiii
 iI1 = "II"
 i11Iiii = struct . calcsize ( iI1 )
 OoO000 , iI = struct . unpack ( iI1 , packet [ : i11Iiii ] )
 packet = packet [ i11Iiii : : ]
 if ( socket . ntohl ( OoO000 ) != 0x90000000 ) :
  print "Invalid LISP-Trace message"
  return ( { } )
  if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
  if 95 - 95: OoO0O00 % oO0o . O0
 iI1 = "Q"
 i11Iiii = struct . calcsize ( iI1 )
 I1i1I = struct . unpack ( iI1 , packet [ : i11Iiii ] ) [ 0 ]
 packet = packet [ i11Iiii : : ]
 if 80 - 80: OoOoOO00 - OoO0O00
 if 87 - 87: oO0o / I11i - i1IIi * OOooOOo / OoooooooOO . O0
 if 1 - 1: II111iiii - I11i / I11i
 if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
 if ( I1i1I != nonce ) :
  print "Invalid nonce, sent {}, received {}" . format ( nonce , I1i1I )
  return ( { } )
  if 83 - 83: OoooooooOO
  if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 if ( len ( packet ) == 0 ) :
  print "No JSON data in payload"
  return ( { } )
  if 4 - 4: II111iiii / ooOoO0o . iII111i
  if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
  if 50 - 50: I1IiiI
  if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
  if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 try :
  II1i1IiiIIi11 = json . loads ( packet )
 except :
  print "Invalid JSON data: '{}'" . format ( packet )
  return ( { } )
  if 47 - 47: iII111i
 return ( II1i1IiiIIi11 )
 if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
 if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
 if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 if 58 - 58: i11iIiiIii % I11i
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
 if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
 if 16 - 16: I1IiiI * oO0o % IiII
def Oo000o ( jd ) :
 for I11IiI1I11i1i in jd :
  print "Path from {} to {}:" . format ( I11IiI1I11i1i [ "seid" ] , I11IiI1I11i1i [ "deid" ] )
  for iI1ii1Ii in I11IiI1I11i1i [ "paths" ] :
   if ( iI1ii1Ii . has_key ( "encap-timestamp" ) ) :
    oooo000 = iI1ii1Ii [ "encap-timestamp" ]
    iIIIi1 = "encap"
    if 20 - 20: i1IIi + I1ii11iIi11i - ooOoO0o
   if ( iI1ii1Ii . has_key ( "decap-timestamp" ) ) :
    oooo000 = iI1ii1Ii [ "decap-timestamp" ]
    iIIIi1 = "decap"
    if 30 - 30: II111iiii - OOooOOo - i11iIiiIii % OoOoOO00 - II111iiii * Ii1I
   oO00O0O0O = iI1ii1Ii [ "hostname" ]
   i1ii1iiI = iI1ii1Ii [ "drloc" ]
   if ( i1ii1iiI . find ( "?" ) != - 1 ) : i1ii1iiI = O0o0O00Oo0o0 ( i1ii1iiI )
   print "  {} {}: {} -> {}, ts {}, node {}" . format ( iI1ii1Ii [ "node" ] , iIIIi1 , iI1ii1Ii [ "srloc" ] , i1ii1iiI , oooo000 , O00O0oOO00O00 ( oO00O0O0O ) )
   if 11 - 11: IiII . I1ii11iIi11i
   if 92 - 92: iII111i . I1Ii111
  print ""
  if 31 - 31: I1Ii111 . OoOoOO00 / O0
  if 89 - 89: OoOoOO00
  if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
  if 4 - 4: ooOoO0o + O0 * OOooOOo
  if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
  if 25 - 25: I1ii11iIi11i
  if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
  if 13 - 13: OOooOOo / i11iIiiIii
def Iiii ( eid ) :
 OO0OoO0o00 = True
 if 53 - 53: O0 * OoO0O00 + OOooOOo
 if 50 - 50: O0 . O0 - oO0o / I1IiiI - o0oOOo0O0Ooo * OoOoOO00
 if 61 - 61: I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
 o0o = eid . find ( "]" )
 if ( o0o == - 1 ) :
  o00 = "0"
 else :
  OO0OoO0o00 = False
  o00 = eid [ 1 : o0o ]
  eid = eid [ o0o + 1 : : ]
  if 56 - 56: I1IiiI - Oo0Ooo . Ii1I - IiII
  if 73 - 73: Oo0Ooo - i1IIi - i1IIi - iII111i . Ii1I + I1ii11iIi11i
  if 81 - 81: iII111i * oO0o - I1Ii111 . II111iiii % I11i / I1IiiI
  if 34 - 34: IiII
  if 57 - 57: oO0o . I11i . i1IIi
 if ( eid . find ( ":" ) == - 1 ) : eid = socket . gethostbyname ( eid )
 return ( o00 , eid , OO0OoO0o00 )
 if 42 - 42: I11i + I1ii11iIi11i % O0
 if 6 - 6: oO0o
 if 68 - 68: OoOoOO00 - OoO0O00
 if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
 if 1 - 1: iIii1I11I1II1 / II111iiii
 if 33 - 33: I11i
 if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
 if 87 - 87: i11iIiiIii
 if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
 if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
def o00oooO0Oo ( match_iid , match_eid , http , port , v4v6 ) :
 o0O0OOO0Ooo = ( "curl --silent --insecure -u root: {}://localhost:{}/lisp/" + "api/data/database-mapping" ) . format ( http , port )
 if 45 - 45: O0 / o0oOOo0O0Ooo
 i1 = commands . getoutput ( o0O0OOO0Ooo )
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 try :
  ii = json . loads ( i1 )
 except :
  return ( None , None , None , None )
  if 90 - 90: o0oOOo0O0Ooo % i1IIi / OoO0O00
  if 44 - 44: Oo0Ooo . OoO0O00 / I1ii11iIi11i + Ii1I
 for o0oO0OOoO00OO0o in ii :
  if ( o0oO0OOoO00OO0o . has_key ( "eid-prefix" ) == False ) : continue
  I1111IIIIIi = o0oO0OOoO00OO0o [ "eid-prefix" ]
  I1111IIIIIi = I1111IIIIIi . split ( "/" ) [ 0 ]
  o00 , I1111IIIIIi , OO0OoO0o00 = Iiii ( I1111IIIIIi )
  if ( v4v6 and I1111IIIIIi . find ( "." ) == - 1 ) : continue
  if ( v4v6 == False and I1111IIIIIi . find ( ":" ) == - 1 ) : continue
  if 22 - 22: i1IIi + O0 . iIii1I11I1II1 * iII111i % i11iIiiIii * I1IiiI
  iI = o0oO0OOoO00OO0o [ "rlocs" ] [ 0 ] [ "rloc" ]
  oo000o = o0oO0OOoO00OO0o [ "rlocs" ] [ 0 ] . has_key ( "translated-rloc" )
  if 44 - 44: i1IIi % II111iiii + I11i
  if ( match_iid == None ) : return ( o00 , I1111IIIIIi , iI , oo000o )
  if ( match_iid == o00 and match_eid == I1111IIIIIi ) :
   return ( None , None , iI , oo000o )
   if 45 - 45: iII111i / iII111i + I1Ii111 + ooOoO0o
   if 47 - 47: o0oOOo0O0Ooo + ooOoO0o
 return ( None , None , None , None )
 if 82 - 82: II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
 if 77 - 77: iIii1I11I1II1 * OoO0O00
 if 95 - 95: I1IiiI + i11iIiiIii
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 if 53 - 53: II111iiii
def i1Ii1Ii ( http , port ) :
 o0O0OOO0Ooo = ( "curl --silent --insecure -u root: {}://localhost:{}/lisp/" + "api/data/map-cache" ) . format ( http , port )
 if 52 - 52: OoO0O00 . oO0o
 i1 = commands . getoutput ( o0O0OOO0Ooo )
 if 25 - 25: O0 - O0 * o0oOOo0O0Ooo
 try :
  ii = json . loads ( i1 )
 except :
  return ( [ ] )
  if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
  if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
 oOoooo0O0Oo = [ ]
 for o0oO0OOoO00OO0o in ii :
  if ( o0oO0OOoO00OO0o . has_key ( "group-prefix" ) ) : continue
  if ( o0oO0OOoO00OO0o . has_key ( "eid-prefix" ) == False ) : continue
  if ( o0oO0OOoO00OO0o [ "eid-prefix" ] != "0.0.0.0/0" ) : continue
  if 76 - 76: Ii1I + IiII
  for iI in o0oO0OOoO00OO0o [ "rloc-set" ] :
   if ( iI . has_key ( "rloc-name" ) == False ) : continue
   if ( iI [ "rloc-name" ] != "RTR" ) : continue
   if ( iI . has_key ( "address" ) == False ) : continue
   oOoooo0O0Oo . append ( iI [ "address" ] )
   if 34 - 34: Oo0Ooo
   if 89 - 89: Oo0Ooo * OoOoOO00 * I1Ii111 + iII111i - I11i
 return ( oOoooo0O0Oo )
 if 8 - 8: o0oOOo0O0Ooo % O0 / I1IiiI - oO0o
 if 43 - 43: i11iIiiIii + Oo0Ooo * II111iiii * I1Ii111 * O0
 if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
 if 79 - 79: O0
 if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
 if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 if 57 - 57: OoO0O00 / ooOoO0o
def Ii1I1Ii ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 69 - 69: I1IiiI / o0oOOo0O0Ooo . IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
 if 13 - 13: Ii1I . i11iIiiIii
 if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
def O00O0oOO00O00 ( string ) :
 return ( "\033[94m" + Ii1I1Ii ( string ) + "\033[0m" )
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 if 49 - 49: I1IiiI - I11i
 if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
 if 62 - 62: OoooooooOO * I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
def O0o0O00Oo0o0 ( string ) :
 return ( "\033[91m" + Ii1I1Ii ( string ) + "\033[0m" )
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if 97 - 97: O0 + OoOoOO00
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
if ( "-s" in sys . argv ) :
 I11iI1i1I11I11 = len ( sys . argv ) != 4
else :
 I11iI1i1I11I11 = len ( sys . argv ) != 2
 if 69 - 69: OoOoOO00
if ( I11iI1i1I11I11 ) :
 print "Usage: python ltr.py [-s <source-eid>] <destination-EID | DNS-name>"
 exit ( 1 )
 if 97 - 97: I1ii11iIi11i % I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
ii1I1 , OooooOOoo0 , OO0OoO0o00 = Iiii ( sys . argv [ - 1 ] )
if ( ii1I1 == None ) :
 print "<destinaton-eid> parse error"
 exit ( 1 )
 if 35 - 35: I11i % OOooOOo - oO0o
ii1iii1i = OooooOOoo0 . find ( ":" ) == - 1
if 35 - 35: II111iiii % OOooOOo . ooOoO0o + ooOoO0o % II111iiii % II111iiii
if 72 - 72: II111iiii + i1IIi + o0oOOo0O0Ooo
if 94 - 94: oO0o . i1IIi - o0oOOo0O0Ooo % O0 - OoO0O00
if 72 - 72: Ii1I
if ( "-s" in sys . argv ) :
 o0o = sys . argv . index ( "-s" ) + 1
 II11Ii1iI1iII , Oo0o00OO0000 , OO0OoO0o00 = Iiii ( sys . argv [ o0o ] )
 if ( II11Ii1iI1iII == None ) :
  print "-s <source-eid> parse error"
  exit ( 1 )
  if 1 - 1: ooOoO0o . ooOoO0o / OoOoOO00 - I1Ii111
 if ( OO0OoO0o00 ) : II11Ii1iI1iII = None
 oooO , i1I1i111Ii , iI , oo000o = o00oooO0Oo ( II11Ii1iI1iII , Oo0o00OO0000 , Oo0o , OOO0o0o , ii1iii1i )
 if ( iI == None ) :
  print "[{}]{} is not a local EID" . format ( II11Ii1iI1iII , Oo0o00OO0000 )
  exit ( 1 )
  if 67 - 67: I1IiiI . i1IIi
else :
 II11Ii1iI1iII , Oo0o00OO0000 , iI , oo000o = o00oooO0Oo ( None , None , Oo0o , OOO0o0o , ii1iii1i )
 if ( II11Ii1iI1iII == None ) :
  print "Could not find local EID, maybe lispers.net API port wrong?"
  exit ( 1 )
  if 27 - 27: ooOoO0o % I1IiiI
  if 73 - 73: OOooOOo
  if 70 - 70: iIii1I11I1II1
  if 31 - 31: IiII - I1IiiI % iIii1I11I1II1
  if 92 - 92: i1IIi - iIii1I11I1II1
  if 16 - 16: OoO0O00 - OoOoOO00 - OOooOOo - i1IIi / Ii1I
ii1I1 = II11Ii1iI1iII if ii1I1 == "0" else ii1I1
if ( ii1I1 != II11Ii1iI1iII ) :
 print "Instance-IDs must be the same for source and destination EIDs"
 exit ( 1 )
 if 88 - 88: OoO0O00
 if 71 - 71: I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i - I1IiiI . iIii1I11I1II1 - i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
o0OoOo00o0o = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
o0OoOo00o0o . bind ( ( "0::0" , 0 ) )
o0OoOo00o0o . settimeout ( 3 )
I1Ii11I1Ii1i = o0OoOo00o0o . getsockname ( ) [ 1 ]
if 41 - 41: ooOoO0o % OoO0O00 - Oo0Ooo * I1Ii111 * Oo0Ooo
if 69 - 69: OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
if 23 - 23: i11iIiiIii
if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
Oooo , IIiiIiI1 = IiI1I1 ( iI , I1Ii11I1Ii1i )
if 81 - 81: IiII % i1IIi . iIii1I11I1II1
if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
if 31 - 31: OOooOOo
if ( oo000o ) :
 oOoooo0O0Oo = i1Ii1Ii ( Oo0o , OOO0o0o )
 for i1OOO0000oO in oOoooo0O0Oo :
  print "Send NAT-traversal LISP-Trace to RTR {} ..." . format ( i1OOO0000oO )
  o0OoOo00o0o . sendto ( IIiiIiI1 , ( "::ffff:" + i1OOO0000oO , I11 ) )
  if 15 - 15: OoOoOO00 % I1IiiI * I11i
  if 81 - 81: ooOoO0o - iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * I11i
  if 20 - 20: oO0o % IiII
print "Send round-trip LISP-Trace between EIDs [{}]{} and [{}]{} ..." . format ( II11Ii1iI1iII , Oo0o00OO0000 , ii1I1 , OooooOOoo0 )
if 19 - 19: I1ii11iIi11i % IiII + ooOoO0o / I1Ii111 . ooOoO0o
if 12 - 12: i1IIi + i1IIi - I1ii11iIi11i * Oo0Ooo % Oo0Ooo - II111iiii
oooo000 = time . time ( )
if 52 - 52: ooOoO0o . iII111i + I1Ii111
iiii1IIi = OooooOOoo0 if ( OooooOOoo0 . find ( ":" ) != - 1 ) else "::ffff:" + OooooOOoo0
o0OoOo00o0o . sendto ( IIiiIiI1 , ( iiii1IIi , I11 ) )
if 33 - 33: OoOoOO00 * OOooOOo - II111iiii
if 83 - 83: OoOoOO00 - Ii1I / I11i / I1Ii111 + oO0o - O0
if 4 - 4: OOooOOo * OoO0O00 % i1IIi * i11iIiiIii % Oo0Ooo - oO0o
if 67 - 67: OoOoOO00 + I1ii11iIi11i . o0oOOo0O0Ooo . II111iiii
try :
 IIiiIiI1 , o000ooooO0o = o0OoOo00o0o . recvfrom ( 9000 )
 o000ooooO0o = o000ooooO0o [ 0 ] . replace ( "::ffff:" , "" )
except socket . timeout :
 exit ( 1 )
except socket . error , iI1i11 :
 print "recvfrom() failed, error: {}" . format ( iI1i11 )
 exit ( 1 )
 if 66 - 66: O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / Ii1I + I1ii11iIi11i
 if 86 - 86: o0oOOo0O0Ooo
i1Iii11Ii1i1 = round ( time . time ( ) - oooo000 , 3 )
if 59 - 59: Oo0Ooo % OoooooooOO . iII111i / IiII + I1IiiI
print "Received reply from {}, rtt {} secs" . format ( o000ooooO0o , i1Iii11Ii1i1 )
print ""
II1i1IiiIIi11 = III1ii1iII ( Oooo , IIiiIiI1 )
if ( II1i1IiiIIi11 == { } ) : exit ( 1 )
if 76 - 76: ooOoO0o
if 73 - 73: O0 * iII111i + Ii1I + ooOoO0o
if 40 - 40: II111iiii . OoOoOO00 * I1Ii111 + OOooOOo + OOooOOo
if 9 - 9: I11i % OoooooooOO . oO0o % I11i
Oo000o ( II1i1IiiIIi11 )
if 32 - 32: i11iIiiIii
o0OoOo00o0o . close ( )
exit ( 0 )
if 31 - 31: iIii1I11I1II1 / OoO0O00 / I1ii11iIi11i
if 41 - 41: Oo0Ooo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
