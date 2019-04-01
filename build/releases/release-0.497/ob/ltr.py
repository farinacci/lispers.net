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
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>",
#                       "recent-rtts" : [...], "recent-hops" : [...] }, 
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "decap-timestamp" : "<ts>", "hostname" : "<hn>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>",
#                       "recent-rtts" : [...], "recent-hops" : [...] }, 
#     { "node" : "ETR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>" }, ...
#   ] },
# 
#   { "seid" : "[<iid>]<dest-eid>", "deid" : "[<iid>]<orig-eid>", "paths" :
#   [
#     { "node" : "ITR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>",
#                       "recent-rtts" : [...], "recent-hops" : [...] }, 
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "decap-timestamp" : "<ts>", "hostname" : "<hn>" },
#     { "node" : "RTR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>",
#                       "recent-rtts" : [...], "recent-hops" : [...] }, 
#     { "node" : "ETR", "srloc" : "<source-rloc>",  "drloc" : "<dest_rloc>",
#                       "encap-timestamp" : "<ts>", "hostname" : "<hn>" }, ...
#   ] }
# ]
#
# Environment variable LISP_LTR_PORT is used to determine if the connection to
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
   if 87 - 87: ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
   print "  {} {}: {} -> {}, ts {}, node {}" . format ( iI1ii1Ii [ "node" ] , iIIIi1 , iI1ii1Ii [ "srloc" ] , i1ii1iiI , oooo000 , O0ooo0O0oo0 ( oO00O0O0O ) )
   if 91 - 91: iIii1I11I1II1 + I1Ii111
   if 31 - 31: IiII . OoOoOO00 . OOooOOo
   if ( iI1ii1Ii . has_key ( "recent-rtts" ) and iI1ii1Ii . has_key ( "recent-hops" ) ) :
    O0oOoOO = iI1ii1Ii [ "recent-rtts" ]
    oO00o0 = json . dumps ( iI1ii1Ii [ "recent-hops" ] )
    oO00o0 = oO00o0 . replace ( "u" , "" )
    oO00o0 = oO00o0 . replace ( "'" , "" )
    oO00o0 = oO00o0 . replace ( '"' , "" )
    print "            " ,
    print "recent-rtts {}, recent-hops {}" . format ( O0oOoOO , oO00o0 )
    if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
    if 25 - 25: I1ii11iIi11i
    if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
  print ""
  if 13 - 13: OOooOOo / i11iIiiIii
  if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
  if 52 - 52: o0oOOo0O0Ooo
  if 95 - 95: Ii1I
  if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
  if 91 - 91: O0
  if 61 - 61: II111iiii
  if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
def O0oOoOOOoOO ( eid ) :
 ii1ii11IIIiiI = True
 if 67 - 67: I11i * oO0o * I1ii11iIi11i + OOooOOo / i1IIi
 if 11 - 11: Ii1I + iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 if 83 - 83: I11i / I1IiiI
 if 34 - 34: IiII
 if 57 - 57: oO0o . I11i . i1IIi
 i11Iii = eid . find ( "]" )
 if ( i11Iii == - 1 ) :
  IiIIIi1iIi = "0"
 else :
  ii1ii11IIIiiI = False
  IiIIIi1iIi = eid [ 1 : i11Iii ]
  eid = eid [ i11Iii + 1 : : ]
  if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
  if 31 - 31: II111iiii . I1IiiI
  if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
  if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
  if 92 - 92: iII111i
 if ( eid . find ( ":" ) == - 1 ) : eid = socket . gethostbyname ( eid )
 return ( IiIIIi1iIi , eid , ii1ii11IIIiiI )
 if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % I1Ii111
def ooO00OO0 ( match_iid , match_eid , http , port , v4v6 ) :
 i11111IIIII = ( "curl --silent --insecure -u root: {}://localhost:{}/lisp/" + "api/data/database-mapping" ) . format ( http , port )
 if 19 - 19: OoOoOO00 * i1IIi
 ii111iI1iIi1 = commands . getoutput ( i11111IIIII )
 if 78 - 78: OoO0O00 . OOooOOo + OoO0O00 / I11i / OoO0O00
 try :
  oO0O00OoOO0 = json . loads ( ii111iI1iIi1 )
 except :
  return ( None , None , None , None )
  if 82 - 82: II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
  if 77 - 77: iIii1I11I1II1 * OoO0O00
 for oOooOo0 in oO0O00OoOO0 :
  if ( oOooOo0 . has_key ( "eid-prefix" ) == False ) : continue
  i1I1ii11i1Iii = oOooOo0 [ "eid-prefix" ]
  i1I1ii11i1Iii = i1I1ii11i1Iii . split ( "/" ) [ 0 ]
  IiIIIi1iIi , i1I1ii11i1Iii , ii1ii11IIIiiI = O0oOoOOOoOO ( i1I1ii11i1Iii )
  if ( v4v6 and i1I1ii11i1Iii . find ( "." ) == - 1 ) : continue
  if ( v4v6 == False and i1I1ii11i1Iii . find ( ":" ) == - 1 ) : continue
  if 26 - 26: I11i - iIii1I11I1II1 - I1IiiI / OoO0O00 . OoOoOO00 % iIii1I11I1II1
  iI = oOooOo0 [ "rlocs" ] [ 0 ] [ "rloc" ]
  OO = oOooOo0 [ "rlocs" ] [ 0 ] . has_key ( "translated-rloc" )
  if 25 - 25: OoO0O00
  if ( match_iid == None ) : return ( IiIIIi1iIi , i1I1ii11i1Iii , iI , OO )
  if ( match_iid == IiIIIi1iIi and match_eid == i1I1ii11i1Iii ) :
   return ( None , None , iI , OO )
   if 62 - 62: OOooOOo + O0
   if 98 - 98: o0oOOo0O0Ooo
 return ( None , None , None , None )
 if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
 if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
 if 82 - 82: Ii1I
 if 46 - 46: OoooooooOO . i11iIiiIii
 if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 if 87 - 87: Oo0Ooo . IiII
 if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
def oO ( http , port ) :
 i11111IIIII = ( "curl --silent --insecure -u root: {}://localhost:{}/lisp/" + "api/data/map-cache" ) . format ( http , port )
 if 31 - 31: OOooOOo + i11iIiiIii + Oo0Ooo * ooOoO0o
 ii111iI1iIi1 = commands . getoutput ( i11111IIIII )
 if 28 - 28: O0 * Oo0Ooo - OOooOOo % iIii1I11I1II1 * Ii1I - i11iIiiIii
 try :
  oO0O00OoOO0 = json . loads ( ii111iI1iIi1 )
 except :
  return ( [ ] )
  if 7 - 7: Oo0Ooo + oO0o - I1Ii111 % Ii1I + I1ii11iIi11i
  if 53 - 53: i1IIi - I11i . OoOoOO00
 IiI1i = [ ]
 for oOooOo0 in oO0O00OoOO0 :
  if ( oOooOo0 . has_key ( "group-prefix" ) ) : continue
  if ( oOooOo0 . has_key ( "eid-prefix" ) == False ) : continue
  if ( oOooOo0 [ "eid-prefix" ] != "0.0.0.0/0" ) : continue
  if 92 - 92: IiII . IiII + OoO0O00
  for iI in oOooOo0 [ "rloc-set" ] :
   if ( iI . has_key ( "rloc-name" ) == False ) : continue
   if ( iI [ "rloc-name" ] != "RTR" ) : continue
   if ( iI . has_key ( "address" ) == False ) : continue
   IiI1i . append ( iI [ "address" ] )
   if 9 - 9: I1IiiI * O0 + IiII - I11i * I1Ii111
   if 64 - 64: iIii1I11I1II1 - iIii1I11I1II1 / i11iIiiIii % Oo0Ooo - iII111i
 return ( IiI1i )
 if 56 - 56: I1IiiI . I11i * Ii1I - iII111i
 if 8 - 8: OoO0O00 - I1IiiI % Ii1I * OoooooooOO - OoO0O00 * I1Ii111
 if 6 - 6: OoooooooOO
 if 17 - 17: I1IiiI % I1Ii111
 if 90 - 90: oO0o / iIii1I11I1II1 - o0oOOo0O0Ooo / OoooooooOO - OoooooooOO * OOooOOo
 if 73 - 73: I1ii11iIi11i * i11iIiiIii % oO0o . I1ii11iIi11i
 if 66 - 66: oO0o + oO0o + ooOoO0o / iII111i + OOooOOo
def iIii1111iII ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 32 - 32: i1IIi / II111iiii . Oo0Ooo
 if 62 - 62: OoooooooOO * I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if 97 - 97: O0 + OoOoOO00
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
def O0ooo0O0oo0 ( string ) :
 return ( "\033[94m" + iIii1111iII ( string ) + "\033[0m" )
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
 if 71 - 71: Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
def O0o0O00Oo0o0 ( string ) :
 return ( "\033[91m" + iIii1111iII ( string ) + "\033[0m" )
 if 69 - 69: I1Ii111
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
 if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
 if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
 if 71 - 71: I1Ii111 + Ii1I
 if 28 - 28: OOooOOo
if ( "-s" in sys . argv ) :
 I11ii1IIiIi = len ( sys . argv ) != 4
else :
 I11ii1IIiIi = len ( sys . argv ) != 2
 if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
if ( I11ii1IIiIi ) :
 print "Usage: python ltr.py [-s <source-eid>] <destination-EID | DNS-name>"
 exit ( 1 )
 if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
I11I , I11iIi1i1II11 , ii1ii11IIIiiI = O0oOoOOOoOO ( sys . argv [ - 1 ] )
if ( I11I == None ) :
 print "<destinaton-eid> parse error"
 exit ( 1 )
 if 47 - 47: OoooooooOO . OoOoOO00
i1I1i111Ii = I11iIi1i1II11 . find ( ":" ) == - 1
if 67 - 67: I1IiiI . i1IIi
if 27 - 27: ooOoO0o % I1IiiI
if 73 - 73: OOooOOo
if 70 - 70: iIii1I11I1II1
if ( "-s" in sys . argv ) :
 i11Iii = sys . argv . index ( "-s" ) + 1
 i11ii1iI , i1I , ii1ii11IIIiiI = O0oOoOOOoOO ( sys . argv [ i11Iii ] )
 if ( i11ii1iI == None ) :
  print "-s <source-eid> parse error"
  exit ( 1 )
  if 42 - 42: o0oOOo0O0Ooo + i1IIi - Ii1I / IiII
 if ( ii1ii11IIIiiI ) : i11ii1iI = None
 iiIiIIIiiI , iiI1IIIi , iI , OO = ooO00OO0 ( i11ii1iI , i1I , Oo0o , OOO0o0o , i1I1i111Ii )
 if ( iI == None ) :
  print "[{}]{} is not a local EID" . format ( i11ii1iI , i1I )
  exit ( 1 )
  if 47 - 47: Oo0Ooo % I11i % i11iIiiIii - O0 + ooOoO0o
else :
 i11ii1iI , i1I , iI , OO = ooO00OO0 ( None , None , Oo0o , OOO0o0o , i1I1i111Ii )
 if ( i11ii1iI == None ) :
  print "Could not find local EID, maybe lispers.net API port wrong?"
  exit ( 1 )
  if 94 - 94: I1Ii111
  if 4 - 4: Ii1I % oO0o * OoO0O00
  if 100 - 100: I1Ii111 * OOooOOo + OOooOOo
  if 54 - 54: OoooooooOO + o0oOOo0O0Ooo - i1IIi % i11iIiiIii
  if 3 - 3: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 83 - 83: II111iiii + I1Ii111
I11I = i11ii1iI if I11I == "0" else I11I
if ( I11I != i11ii1iI ) :
 print "Instance-IDs must be the same for source and destination EIDs"
 exit ( 1 )
 if 73 - 73: iII111i
 if 42 - 42: i11iIiiIii * iIii1I11I1II1 / I1ii11iIi11i . i11iIiiIii % I11i
 if 41 - 41: IiII / O0
 if 51 - 51: I11i % I1IiiI
 if 60 - 60: I1IiiI / OOooOOo . I1IiiI / I1Ii111 . IiII
OO0000o = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
OO0000o . bind ( ( "0::0" , 0 ) )
OO0000o . settimeout ( 3 )
I1Ii11I1Ii1i = OO0000o . getsockname ( ) [ 1 ]
if 42 - 42: Oo0Ooo
if 76 - 76: I1IiiI * iII111i % I1Ii111
if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
Oooo , IIiiIiI1 = IiI1I1 ( iI , I1Ii11I1Ii1i )
if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
if 42 - 42: I1IiiI
if ( OO ) :
 IiI1i = oO ( Oo0o , OOO0o0o )
 for II1i11I in IiI1i :
  print "Send NAT-traversal LISP-Trace to RTR {} ..." . format ( II1i11I )
  OO0000o . sendto ( IIiiIiI1 , ( "::ffff:" + II1i11I , I11 ) )
  if 50 - 50: OoooooooOO % I11i
  if 49 - 49: oO0o - i11iIiiIii . I1Ii111 * Ii1I % iII111i + i1IIi
  if 71 - 71: o0oOOo0O0Ooo
print "Send round-trip LISP-Trace between EIDs [{}]{} and [{}]{} ..." . format ( i11ii1iI , i1I , I11I , I11iIi1i1II11 )
if 38 - 38: oO0o % OoOoOO00 + I1ii11iIi11i . i11iIiiIii
if 53 - 53: i11iIiiIii * iII111i
oooo000 = time . time ( )
if 68 - 68: iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
i1i11I11 = I11iIi1i1II11 if ( I11iIi1i1II11 . find ( ":" ) != - 1 ) else "::ffff:" + I11iIi1i1II11
OO0000o . sendto ( IIiiIiI1 , ( i1i11I11 , I11 ) )
if 10 - 10: O0 - OoooooooOO . OoOoOO00
if 44 - 44: IiII - o0oOOo0O0Ooo . i1IIi . IiII * OoOoOO00
if 5 - 5: I1Ii111
if 90 - 90: I1Ii111 . ooOoO0o / Ii1I - I11i
try :
 IIiiIiI1 , ii1 = OO0000o . recvfrom ( 9000 )
 ii1 = ii1 [ 0 ] . replace ( "::ffff:" , "" )
except socket . timeout :
 exit ( 1 )
except socket . error , I1i11 :
 print "recvfrom() failed, error: {}" . format ( I1i11 )
 exit ( 1 )
 if 51 - 51: OoO0O00 . I1IiiI * ooOoO0o % Ii1I + II111iiii . ooOoO0o
 if 50 - 50: OoO0O00 * OOooOOo % O0
Ooo0O0oooo = round ( time . time ( ) - oooo000 , 3 )
if 36 - 36: OoooooooOO . OoO0O00
print "Received reply from {}, rtt {} secs" . format ( ii1 , Ooo0O0oooo )
print ""
II1i1IiiIIi11 = III1ii1iII ( Oooo , IIiiIiI1 )
if ( II1i1IiiIIi11 == { } ) : exit ( 1 )
if 56 - 56: Oo0Ooo . I1ii11iIi11i . I1IiiI
if 39 - 39: O0 + I1Ii111
if 91 - 91: OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoOoOO00 + O0
if 26 - 26: I1ii11iIi11i - OoooooooOO
Oo000o ( II1i1IiiIIi11 )
if 11 - 11: I1IiiI * oO0o
OO0000o . close ( )
exit ( 0 )
if 81 - 81: iII111i + IiII
if 98 - 98: I1IiiI
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
