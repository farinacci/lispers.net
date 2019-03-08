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
# Usage: python ltr.py [-s <source-eid>] <destination-EID>
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
def OoooooOoo ( ) :
 OO = socket . htonl ( 0x90000000 )
 oO0O = random . randint ( 0 , ( 2 ** 64 ) - 1 )
 OOoO000O0OO = struct . pack ( "I" , OO )
 OOoO000O0OO += struct . pack ( "Q" , oO0O )
 return ( oO0O , OOoO000O0OO )
 if 23 - 23: i11iIiiIii + I1IiiI
 if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
 if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
 if 33 - 33: Ii1I + II111iiii % i11iIiiIii . ooOoO0o - I1IiiI
 if 66 - 66: Ii1I - OoooooooOO * OoooooooOO . OOooOOo . I1ii11iIi11i
 if 22 - 22: OoooooooOO % I11i - iII111i . iIii1I11I1II1 * i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
def o0OOOOO00o0O0 ( nonce , packet ) :
 if ( len ( packet ) < 12 ) : return ( False )
 if 71 - 71: ooOoO0o % iII111i / o0oOOo0O0Ooo
 ii11i1iIII = "I"
 Ii1IOo0o0 = struct . calcsize ( ii11i1iIII )
 OO = struct . unpack ( ii11i1iIII , packet [ : Ii1IOo0o0 ] ) [ 0 ]
 packet = packet [ Ii1IOo0o0 : : ]
 if ( socket . ntohl ( OO ) != 0x90000000 ) :
  print "Invalid LISP-Trace message"
  return ( { } )
  if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
  if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
 ii11i1iIII = "Q"
 Ii1IOo0o0 = struct . calcsize ( ii11i1iIII )
 i1iiI11I = struct . unpack ( ii11i1iIII , packet [ : Ii1IOo0o0 ] ) [ 0 ]
 packet = packet [ Ii1IOo0o0 : : ]
 if 29 - 29: OoooooooOO
 if 23 - 23: o0oOOo0O0Ooo . II111iiii
 if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
 if 45 - 45: I1Ii111 . OoOoOO00
 if ( i1iiI11I != nonce ) :
  print "Invalid nonce, sent {}, received {}" . format ( nonce , i1iiI11I )
  return ( { } )
  if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
  if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
 if ( len ( packet ) == 0 ) :
  print "No JSON data in payload"
  return ( { } )
  if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
  if 8 - 8: OoOoOO00
  if 60 - 60: I11i / I11i
  if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
  if 83 - 83: OoooooooOO
 try :
  Iii111II = json . loads ( packet )
 except :
  print "Invalid JSON data: '{}'" . format ( packet )
  return ( { } )
  if 9 - 9: OoO0O00
 return ( Iii111II )
 if 33 - 33: ooOoO0o . iII111i
 if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 if 50 - 50: I1IiiI
 if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
 if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
 if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
def Ii11iII1 ( jd ) :
 for Oo0O0O0ooO0O in jd :
  print "Path from {} to {}:" . format ( Oo0O0O0ooO0O [ "seid" ] , Oo0O0O0ooO0O [ "deid" ] )
  for IIIIii in Oo0O0O0ooO0O [ "paths" ] :
   if ( IIIIii . has_key ( "encap-timestamp" ) ) :
    O0o0 = IIIIii [ "encap-timestamp" ]
    OO00Oo = "encap"
    if 51 - 51: IiII * o0oOOo0O0Ooo + I11i + OoO0O00
   if ( IIIIii . has_key ( "decap-timestamp" ) ) :
    O0o0 = IIIIii [ "decap-timestamp" ]
    OO00Oo = "decap"
    if 66 - 66: OoOoOO00
   oO000Oo000 = IIIIii [ "hostname" ]
   i111IiI1I = IIIIii [ "drloc" ]
   if ( i111IiI1I == "?" ) : i111IiI1I = O0iII ( i111IiI1I )
   print "  {} {}: {} -> {}, ts {}, node {}" . format ( IIIIii [ "node" ] , OO00Oo , IIIIii [ "srloc" ] , i111IiI1I , O0o0 , o0 ( oO000Oo000 ) )
   if 62 - 62: iIii1I11I1II1 * OoOoOO00
   if 26 - 26: iII111i . I1Ii111
  print ""
  if 68 - 68: OoO0O00
  if 35 - 35: OoO0O00 - iII111i / Oo0Ooo / OoOoOO00
  if 24 - 24: ooOoO0o - ooOoO0o / II111iiii - I1ii11iIi11i
  if 69 - 69: oO0o . I1Ii111 + Ii1I / Oo0Ooo - oO0o
  if 63 - 63: OOooOOo % oO0o * oO0o * OoO0O00 / I1ii11iIi11i
  if 74 - 74: II111iiii
  if 75 - 75: o0oOOo0O0Ooo . ooOoO0o
  if 54 - 54: II111iiii % OoOoOO00 % I11i % iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
def O00O0oOO00O00 ( eid ) :
 i1 = eid . find ( "]" )
 Oo00 = "0" if ( i1 == - 1 ) else eid [ 1 : i1 ]
 eid = eid [ i1 + 1 : : ]
 if ( eid . count ( "." ) != 3 ) : return ( None , None )
 return ( Oo00 , eid )
 if 31 - 31: I1Ii111 . OoOoOO00 / O0
 if 89 - 89: OoOoOO00
 if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
 if 4 - 4: ooOoO0o + O0 * OOooOOo
 if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
 if 25 - 25: I1ii11iIi11i
 if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
 if 13 - 13: OOooOOo / i11iIiiIii
def Iiii ( http , port , diid ) :
 OO0OoO0o00 = ( "curl --silent --insecure -u root: {}://localhost:{}/lisp/" + "api/data/database-mapping" ) . format ( http , port )
 if 53 - 53: O0 * OoO0O00 + OOooOOo
 Ii = commands . getoutput ( OO0OoO0o00 )
 if 61 - 61: II111iiii
 try :
  O0OOO = json . loads ( Ii )
 except :
  return ( None , None )
  if 10 - 10: OOooOOo * I11i % OoOoOO00 / I1IiiI / OoOoOO00
  if 42 - 42: OoO0O00
 for o0o in O0OOO :
  if ( o0o . has_key ( "eid-prefix" ) == False ) : continue
  o00 = o0o [ "eid-prefix" ]
  o00 = o00 . split ( "/" ) [ 0 ]
  Oo00 , o00 = O00O0oOO00O00 ( o00 )
  return ( Oo00 , o00 )
  if 56 - 56: I1IiiI - Oo0Ooo . Ii1I - IiII
 return ( None , None )
 if 73 - 73: Oo0Ooo - i1IIi - i1IIi - iII111i . Ii1I + I1ii11iIi11i
 if 81 - 81: iII111i * oO0o - I1Ii111 . II111iiii % I11i / I1IiiI
 if 34 - 34: IiII
 if 57 - 57: oO0o . I11i . i1IIi
 if 42 - 42: I11i + I1ii11iIi11i % O0
 if 6 - 6: oO0o
 if 68 - 68: OoOoOO00 - OoO0O00
def O0iII ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
 if 1 - 1: iIii1I11I1II1 / II111iiii
 if 33 - 33: I11i
 if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
 if 87 - 87: i11iIiiIii
 if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
 if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
def o0 ( string ) :
 return ( "\033[94m" + O0iII ( string ) + "\033[0m" )
 if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
i1Iii1i1I , OOoO00 = O00O0oOO00O00 ( sys . argv [ - 1 ] )
if ( i1Iii1i1I == None ) :
 print "<destinaton-eid> parse error"
 exit ( 1 )
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
 if 23 - 23: O0
 if 85 - 85: Ii1I
 if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
if ( "-s" in sys . argv ) :
 i1 = sys . argv . index ( "-s" ) + 1
 IIi1 , I1I1I = O00O0oOO00O00 ( sys . argv [ i1 ] )
 if ( IIi1 == None ) :
  print "-s <source-eid> parse error"
  exit ( 1 )
  if 95 - 95: II111iiii + o0oOOo0O0Ooo + iII111i * iIii1I11I1II1 % oO0o / IiII
else :
 IIi1 , I1I1I = Iiii ( Oo0o , OOO0o0o , i1Iii1i1I )
 if ( IIi1 == None ) :
  print "Could not find local EID, maybe lispers.net API port wrong?"
  exit ( 1 )
  if 56 - 56: iII111i
  if 86 - 86: II111iiii % I1Ii111
  if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
  if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
  if 80 - 80: II111iiii
  if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
i1Iii1i1I = IIi1 if i1Iii1i1I == "0" else i1Iii1i1I
if ( i1Iii1i1I != IIi1 ) :
 print "Instance-IDs must be the same for source and destination EIDs"
 exit ( 1 )
 if 53 - 53: II111iiii
 if 31 - 31: OoO0O00
 if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: OoO0O00
 if 62 - 62: OOooOOo + O0
oO0OOOO0 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
oO0OOOO0 . bind ( ( "0.0.0.0" , I11 ) )
oO0OOOO0 . settimeout ( 3 )
if 26 - 26: Ii1I
if 35 - 35: Ii1I - I1IiiI % o0oOOo0O0Ooo . OoooooooOO % Ii1I
if 47 - 47: iII111i - Ii1I . II111iiii + OoooooooOO . i11iIiiIii
if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
oO0O , OOoO000O0OO = OoooooOoo ( )
print "Send round-trip LISP-Trace between EIDs [{}]{} and [{}]{} ..." . format ( IIi1 , I1I1I , i1Iii1i1I , OOoO00 )
if 87 - 87: Oo0Ooo . IiII
if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
O0o0 = time . time ( )
oO0OOOO0 . sendto ( OOoO000O0OO , ( OOoO00 , I11 ) )
if 55 - 55: OOooOOo . I1IiiI
if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
if 100 - 100: I1Ii111 * O0
if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
try :
 OOoO000O0OO , o0iI11I1II = oO0OOOO0 . recvfrom ( 9000 )
 o0iI11I1II = o0iI11I1II [ 0 ]
except socket . timeout :
 exit ( 1 )
except socket . error , Ii1IIiI1i :
 print "recvfrom() failed, error: {}" . format ( Ii1IIiI1i )
 exit ( 1 )
 if 92 - 92: IiII . IiII + OoO0O00
 if 9 - 9: I1IiiI * O0 + IiII - I11i * I1Ii111
Oooo0oOO = round ( time . time ( ) - O0o0 , 3 )
if 81 - 81: O0 - ooOoO0o / o0oOOo0O0Ooo % Ii1I
print "Received reply from {}, rtt {} secs" . format ( o0iI11I1II , Oooo0oOO )
print ""
Iii111II = o0OOOOO00o0O0 ( oO0O , OOoO000O0OO )
if ( Iii111II == { } ) : exit ( 1 )
if 83 - 83: ooOoO0o
if 65 - 65: I1IiiI % Ii1I * oO0o
if 19 - 19: I1Ii111 + iIii1I11I1II1 . OoooooooOO . I11i / I1Ii111 + IiII
if 85 - 85: I1ii11iIi11i - iIii1I11I1II1
Ii11iII1 ( Iii111II )
if 31 - 31: OoooooooOO - OoooooooOO * I11i - oO0o
oO0OOOO0 . close ( )
exit ( 0 )
if 85 - 85: i11iIiiIii % oO0o . OOooOOo - Ii1I
if 42 - 42: oO0o + ooOoO0o / iII111i + OOooOOo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
