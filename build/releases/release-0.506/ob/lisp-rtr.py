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
# lisp-rtr.py
#
# This file performs LISP Reencapsualting Tunnel Router (RTR) functionality.
#
# -----------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
import lisp
import lispconfig
import socket
import time
import select
import threading
import pcappy
import os
import copy
import commands
import binascii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
II1iII1i = [ None , None , None ]
oO0oIIII = None
Oo0oO0oo0oO00 = None
i111I = None
II1Ii1iI1i = None
iiI1iIiI = lisp . lisp_get_ephemeral_port ( )
OOo = None
Ii1IIii11 = None
Oooo0000 = None
if 22 - 22: Ii1I . IiII
I11 = [ ]
if 98 - 98: i11iIiiIii * I1IiiI % iII111i * iII111i * II111iiii
if 79 - 79: IiII
if 86 - 86: OoOoOO00 % I1IiiI
if 80 - 80: OoooooooOO . I1IiiI
if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
iiIIIIi1i1 = None
if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
if 13 - 13: OOooOOo * oO0o * I1IiiI
if 55 - 55: II111iiii
IIIiI11ii = ( os . getenv ( "LISP_RTR_FAST_DATA_PLANE" ) != None )
O000oo = ( os . getenv ( "LISP_RTR_LATENCY_DEBUG" ) != None )
if 3 - 3: iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
if 78 - 78: OoO0O00
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
if 14 - 14: I11i % O0
if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
def oO ( parameter ) :
 global I11
 if 76 - 76: OoO0O00 * o0oOOo0O0Ooo % i1IIi - OoO0O00 / I1IiiI . OOooOOo
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "RTR" ,
 I11 ) )
 if 41 - 41: OoOoOO00
 if 13 - 13: Oo0Ooo . i11iIiiIii - iIii1I11I1II1 - OoOoOO00
 if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
 if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
 if 100 - 100: Ii1I - Ii1I - I1Ii111
 if 20 - 20: OoooooooOO
 if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
def oo ( parameter ) :
 global I11
 if 68 - 68: I11i + OOooOOo . iIii1I11I1II1 - IiII % iIii1I11I1II1 - ooOoO0o
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "RTR" , I11 ,
 True ) )
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
def I1i1iii ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "RTR" ) )
 if 20 - 20: o0oOOo0O0Ooo
 if 77 - 77: OoOoOO00 / I11i
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
 if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % oO0o . O0
 if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
 if 53 - 53: IiII + I1IiiI * oO0o
def OooOooooOOoo0 ( kv_pair ) :
 lispconfig . lisp_database_mapping_command ( kv_pair )
 if 71 - 71: I1Ii111 % oO0o % OOooOOo
 if 94 - 94: oO0o - iII111i * O0
 if 17 - 17: I1ii11iIi11i % II111iiii
 if 13 - 13: I1Ii111 % OoOoOO00 - i11iIiiIii . I1IiiI + II111iiii
 if 10 - 10: I1ii11iIi11i * ooOoO0o * II111iiii % Ii1I . OOooOOo + I1Ii111
 if 19 - 19: OoOoOO00 - I1IiiI . OOooOOo / IiII
 if 33 - 33: I1Ii111 / I1ii11iIi11i % I1IiiI + ooOoO0o / OoO0O00
def OOOoO0O0o ( kv_pair ) :
 O0o0Ooo = { "rloc-probe" : False }
 if 56 - 56: ooOoO0o . OoOoOO00 * iII111i . OoOoOO00
 for O00oO in kv_pair . keys ( ) :
  I11i1I1I = kv_pair [ O00oO ]
  if 83 - 83: I1ii11iIi11i / ooOoO0o
  if ( O00oO == "instance-id" ) :
   iIIIIii1 = I11i1I1I . split ( "-" )
   O0o0Ooo [ "instance-id" ] = [ 0 , 0 ]
   if ( len ( iIIIIii1 ) == 1 ) :
    O0o0Ooo [ "instance-id" ] [ 0 ] = int ( iIIIIii1 [ 0 ] )
    O0o0Ooo [ "instance-id" ] [ 1 ] = int ( iIIIIii1 [ 0 ] )
   else :
    O0o0Ooo [ "instance-id" ] [ 0 ] = int ( iIIIIii1 [ 0 ] )
    O0o0Ooo [ "instance-id" ] [ 1 ] = int ( iIIIIii1 [ 1 ] )
    if 58 - 58: i11iIiiIii % I11i
    if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
  if ( O00oO == "eid-prefix" ) :
   oO0OOoO0 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   oO0OOoO0 . store_prefix ( I11i1I1I )
   O0o0Ooo [ "eid-prefix" ] = oO0OOoO0
   if 34 - 34: IiII - IiII * I1IiiI + Ii1I % IiII
  if ( O00oO == "rloc-prefix" ) :
   i111IiI1I = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   i111IiI1I . store_prefix ( I11i1I1I )
   O0o0Ooo [ "rloc-prefix" ] = i111IiI1I
   if 70 - 70: Ii1I . Oo0Ooo / o0oOOo0O0Ooo . Ii1I - O0 / IiII
  if ( O00oO == "rloc-probe" ) :
   O0o0Ooo [ "rloc-probe" ] = ( I11i1I1I == "yes" )
   if 62 - 62: iIii1I11I1II1 * OoOoOO00
   if 26 - 26: iII111i . I1Ii111
   if 68 - 68: OoO0O00
   if 35 - 35: OoO0O00 - iII111i / Oo0Ooo / OoOoOO00
   if 24 - 24: ooOoO0o - ooOoO0o / II111iiii - I1ii11iIi11i
   if 69 - 69: oO0o . I1Ii111 + Ii1I / Oo0Ooo - oO0o
 for OO0O0OoOO0 in lisp . lisp_glean_mappings :
  if ( OO0O0OoOO0 . has_key ( "eid-prefix" ) ^ O0o0Ooo . has_key ( "eid-prefix" ) ) : continue
  if ( OO0O0OoOO0 . has_key ( "eid-prefix" ) and O0o0Ooo . has_key ( "eid-prefix" ) ) :
   iiiI1I11i1 = OO0O0OoOO0 [ "eid-prefix" ]
   IIi1i11111 = O0o0Ooo [ "eid-prefix" ]
   if ( iiiI1I11i1 . is_exact_match ( IIi1i11111 ) == False ) : continue
   if 81 - 81: i11iIiiIii % OoOoOO00 - OOooOOo
   if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
  if ( OO0O0OoOO0 . has_key ( "rloc-prefix" ) ^ O0o0Ooo . has_key ( "rloc-prefix" ) ) : continue
  if ( OO0O0OoOO0 . has_key ( "rloc-prefix" ) and O0o0Ooo . has_key ( "rloc-prefix" ) ) :
   iiiI1I11i1 = OO0O0OoOO0 [ "rloc-prefix" ]
   IIi1i11111 = O0o0Ooo [ "rloc-prefix" ]
   if ( iiiI1I11i1 . is_exact_match ( IIi1i11111 ) == False ) : continue
   if 92 - 92: iII111i . I1Ii111
   if 31 - 31: I1Ii111 . OoOoOO00 / O0
  if ( OO0O0OoOO0 . has_key ( "instance-id" ) ^ O0o0Ooo . has_key ( "instance-id" ) ) : continue
  if ( OO0O0OoOO0 . has_key ( "instance-id" ) and O0o0Ooo . has_key ( "instance-id" ) ) :
   iiiI1I11i1 = OO0O0OoOO0 [ "instance-id" ]
   IIi1i11111 = O0o0Ooo [ "instance-id" ]
   if ( iiiI1I11i1 != IIi1i11111 ) : continue
   if 89 - 89: OoOoOO00
   if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
   if 4 - 4: ooOoO0o + O0 * OOooOOo
   if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
   if 25 - 25: I1ii11iIi11i
  return
  if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
  if 13 - 13: OOooOOo / i11iIiiIii
  if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
  if 52 - 52: o0oOOo0O0Ooo
  if 95 - 95: Ii1I
 lisp . lisp_glean_mappings . append ( O0o0Ooo )
 if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
 if 61 - 61: II111iiii
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
 if 67 - 67: I1Ii111 . iII111i . O0
def IIIIiiII111 ( parameter ) :
 return ( lispconfig . lisp_itr_rtr_show_rloc_probe_command ( "RTR" ) )
 if 97 - 97: I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
 if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 if 83 - 83: I11i / I1IiiI
 if 34 - 34: IiII
 if 57 - 57: oO0o . I11i . i1IIi
 if 42 - 42: I11i + I1ii11iIi11i % O0
 if 6 - 6: oO0o
def oOOo0oOo0 ( mc , parms ) :
 II , i111IiI1I , ooooo , II1I = parms
 if 84 - 84: IiII . i11iIiiIii . IiII * I1ii11iIi11i - I11i
 ii = "{}:{}" . format ( i111IiI1I . print_address_no_iid ( ) , ooooo )
 oO0OOoO0 = lisp . green ( mc . print_eid_tuple ( ) , False )
 O0o0oOOOoOo = "Changed '{}' translated address:port to {} for EID {}, {} {}" . format ( II1I , lisp . red ( ii , False ) , oO0OOoO0 , "{}" , "{}" )
 if 17 - 17: o0oOOo0O0Ooo . I1IiiI * iII111i % iII111i
 if 24 - 24: OoooooooOO
 for Oo0O00O0O in mc . rloc_set :
  if ( Oo0O00O0O . rle ) :
   for OOooOoooOoOo in Oo0O00O0O . rle . rle_nodes :
    if ( OOooOoooOoOo . rloc_name != II1I ) : continue
    OOooOoooOoOo . store_translated_rloc ( i111IiI1I , ooooo )
    o0OOOO00O0Oo = OOooOoooOoOo . address . print_address_no_iid ( ) + ":" + str ( OOooOoooOoOo . translated_port )
    if 48 - 48: O0
    lisp . lprint ( O0o0oOOOoOo . format ( "RLE" , o0OOOO00O0Oo ) )
    if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
    if 41 - 41: Ii1I - O0 - O0
    if 68 - 68: OOooOOo % I1Ii111
  if ( Oo0O00O0O . rloc_name != II1I ) : continue
  if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
  if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
  if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
  if 23 - 23: O0
  if 85 - 85: Ii1I
  if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
  o0OOOO00O0Oo = Oo0O00O0O . rloc . print_address_no_iid ( ) + ":" + str ( Oo0O00O0O . translated_port )
  if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
  if ( lisp . lisp_crypto_keys_by_rloc_encap . has_key ( o0OOOO00O0Oo ) ) :
   o0OoOO000ooO0 = lisp . lisp_crypto_keys_by_rloc_encap [ o0OOOO00O0Oo ]
   lisp . lisp_crypto_keys_by_rloc_encap [ ii ] = o0OoOO000ooO0
   if 56 - 56: iII111i
   if 86 - 86: II111iiii % I1Ii111
   if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
   if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
   if 80 - 80: II111iiii
  Oo0O00O0O . delete_from_rloc_probe_list ( mc . eid , mc . group )
  Oo0O00O0O . store_translated_rloc ( i111IiI1I , ooooo )
  Oo0O00O0O . add_to_rloc_probe_list ( mc . eid , mc . group )
  lisp . lprint ( O0o0oOOOoOo . format ( "RLOC" , o0OOOO00O0Oo ) )
  if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
  if 53 - 53: II111iiii
  if 31 - 31: OoO0O00
  if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
  if ( lisp . lisp_rloc_probing ) :
   iIiIIi1 = None if ( mc . group . is_null ( ) ) else mc . eid
   I1IIII1i = mc . eid if ( mc . group . is_null ( ) ) else mc . group
   lisp . lisp_send_map_request ( II , 0 , iIiIIi1 , I1IIII1i , Oo0O00O0O )
   if 2 - 2: I11i + Ii1I - I1IiiI % o0oOOo0O0Ooo . iII111i
   if 18 - 18: OOooOOo + iII111i - Ii1I . II111iiii + i11iIiiIii
   if 20 - 20: I1Ii111
   if 52 - 52: II111iiii - OoooooooOO % Ii1I + I1IiiI * Oo0Ooo . IiII
   if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
   if 55 - 55: OOooOOo . I1IiiI
 lisp . lisp_write_ipc_map_cache ( True , mc )
 return ( True , parms )
 if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
 if 100 - 100: I1Ii111 * O0
 if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
 if 79 - 79: O0
 if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
 if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 if 57 - 57: OoO0O00 / ooOoO0o
def Ii1I1Ii ( mc , parms ) :
 if 69 - 69: I1IiiI / o0oOOo0O0Ooo . IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
 if 13 - 13: Ii1I . i11iIiiIii
 if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 if ( mc . group . is_null ( ) ) : return ( oOOo0oOo0 ( mc , parms ) )
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if ( mc . source_cache == None ) : return ( True , parms )
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 mc . source_cache . walk_cache ( oOOo0oOo0 , parms )
 return ( True , parms )
 if 49 - 49: I1IiiI - I11i
 if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
 if 62 - 62: OoooooooOO * I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if 97 - 97: O0 + OoOoOO00
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
def o0o0O0O00oOOo ( sockets , hostname , rloc , port ) :
 lisp . lisp_map_cache . walk_cache ( Ii1I1Ii ,
 [ sockets , rloc , port , hostname ] )
 return
 if 14 - 14: OoOoOO00 + oO0o
 if 52 - 52: OoooooooOO - ooOoO0o
 if 74 - 74: iII111i + o0oOOo0O0Ooo
 if 71 - 71: Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
def ii1I1 ( sred , packet ) :
 if ( lisp . lisp_data_plane_logging == False ) : return
 if 93 - 93: O0 % i1IIi . OOooOOo / I1IiiI - I1Ii111 / I1IiiI
 if ( sred in [ "Send" , "Receive" ] ) :
  II1IiiIi1i = binascii . hexlify ( packet [ 0 : 20 ] )
  lisp . lprint ( "Fast-{}: ip {} {} {} {} {}" . format ( sred , II1IiiIi1i [ 0 : 8 ] , II1IiiIi1i [ 8 : 16 ] ,
 II1IiiIi1i [ 16 : 24 ] , II1IiiIi1i [ 24 : 32 ] , II1IiiIi1i [ 32 : 40 ] ) )
 elif ( sred in [ "Encap" , "Decap" ] ) :
  II1IiiIi1i = binascii . hexlify ( packet [ 0 : 36 ] )
  lisp . lprint ( "Fast-{}: ip {} {} {} {} {}, udp {} {}, lisp {} {}" . format ( sred , II1IiiIi1i [ 0 : 8 ] , II1IiiIi1i [ 8 : 16 ] , II1IiiIi1i [ 16 : 24 ] , II1IiiIi1i [ 24 : 32 ] , II1IiiIi1i [ 32 : 40 ] ,
  # I11i / I1IiiI
 II1IiiIi1i [ 40 : 48 ] , II1IiiIi1i [ 48 : 56 ] , II1IiiIi1i [ 56 : 64 ] , II1IiiIi1i [ 64 : 72 ] ) )
  if 35 - 35: II111iiii % OOooOOo . ooOoO0o + ooOoO0o % II111iiii % II111iiii
  if 72 - 72: II111iiii + i1IIi + o0oOOo0O0Ooo
  if 94 - 94: oO0o . i1IIi - o0oOOo0O0Ooo % O0 - OoO0O00
  if 72 - 72: Ii1I
  if 1 - 1: OoO0O00 * IiII * OoooooooOO + ooOoO0o
  if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
  if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
  if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
def i1I1i111Ii ( dest , mc ) :
 if ( lisp . lisp_data_plane_logging == False ) : return
 if 67 - 67: I1IiiI . i1IIi
 i1i1iI1iiiI = "miss" if mc == None else "hit!"
 lisp . lprint ( "Fast-Lookup {} {}" . format ( dest . print_address ( ) , i1i1iI1iiiI ) )
 if 51 - 51: I1IiiI % I1Ii111 . oO0o / iIii1I11I1II1 / I11i . oO0o
 if 42 - 42: o0oOOo0O0Ooo + i1IIi - Ii1I / IiII
 if 9 - 9: O0 % O0 - o0oOOo0O0Ooo
 if 51 - 51: I1IiiI . iIii1I11I1II1 - I1ii11iIi11i / O0
 if 52 - 52: o0oOOo0O0Ooo + O0 + iII111i + Oo0Ooo % iII111i
 if 75 - 75: I1IiiI . ooOoO0o . O0 * I1Ii111
 if 4 - 4: Ii1I % oO0o * OoO0O00
 if 100 - 100: I1Ii111 * OOooOOo + OOooOOo
def OoOO0o ( ts , msg ) :
 global O000oo
 if 1 - 1: II111iiii
 if ( O000oo == False ) : return ( None )
 if 68 - 68: iII111i - I1IiiI / I1Ii111 / I11i
 if 12 - 12: Ii1I + i11iIiiIii * iIii1I11I1II1 / I1ii11iIi11i . I11i
 if 5 - 5: i1IIi + IiII / o0oOOo0O0Ooo . iII111i / I11i
 if 32 - 32: I1IiiI % iIii1I11I1II1 / i1IIi - I1IiiI
 if ( ts == None ) : return ( time . time ( ) )
 if 7 - 7: I1Ii111 * OoO0O00 - ooOoO0o + OOooOOo * I1IiiI % OoO0O00
 if 15 - 15: OoOoOO00 % I1IiiI * I11i
 if 81 - 81: ooOoO0o - iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * I11i
 if 20 - 20: oO0o % IiII
 ts = ( time . time ( ) - ts ) * 1000000
 lisp . lprint ( "{}-Latency: {} usecs" . format ( msg , round ( ts , 1 ) ) , "force" )
 return ( None )
 if 19 - 19: I1ii11iIi11i % IiII + ooOoO0o / I1Ii111 . ooOoO0o
 if 12 - 12: i1IIi + i1IIi - I1ii11iIi11i * Oo0Ooo % Oo0Ooo - II111iiii
 if 52 - 52: ooOoO0o . iII111i + I1Ii111
 if 38 - 38: i1IIi - II111iiii . I1Ii111
 if 58 - 58: I1IiiI . iII111i + OoOoOO00
 if 66 - 66: iII111i / oO0o * OoooooooOO + OoooooooOO % I11i
 if 49 - 49: oO0o - i11iIiiIii . I1Ii111 * Ii1I % iII111i + i1IIi
 if 71 - 71: o0oOOo0O0Ooo
def IIIIiIiIi1 ( a ) :
 I11iiiiI1i = ord ( a [ 0 ] ) << 24 | ord ( a [ 1 ] ) << 16 | ord ( a [ 2 ] ) << 8 | ord ( a [ 3 ] )
 return ( I11iiiiI1i )
 if 40 - 40: I1ii11iIi11i + i1IIi * OOooOOo
 if 85 - 85: Ii1I * Oo0Ooo . O0 - i11iIiiIii
 if 18 - 18: Ii1I + IiII - O0
 if 53 - 53: i1IIi
 if 87 - 87: i11iIiiIii + I1Ii111 . I1ii11iIi11i * I1Ii111 . ooOoO0o / I1ii11iIi11i
 if 76 - 76: O0 + i1IIi . Oo0Ooo * I1IiiI * Ii1I
 if 14 - 14: o0oOOo0O0Ooo % O0 * iII111i + Ii1I + Oo0Ooo * Ii1I
 if 3 - 3: OoOoOO00 * Oo0Ooo
 if 95 - 95: OOooOOo % oO0o . Ii1I
 if 72 - 72: OoooooooOO
 if 72 - 72: I1IiiI % i11iIiiIii . Oo0Ooo / II111iiii
 if 14 - 14: I1ii11iIi11i + OoO0O00
 if 3 - 3: I1ii11iIi11i . Oo0Ooo / II111iiii
 if 39 - 39: I1Ii111
 if 91 - 91: OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoOoOO00 + O0
 if 26 - 26: I1ii11iIi11i - OoooooooOO
 if 11 - 11: I1IiiI * oO0o
 if 81 - 81: iII111i + IiII
 if 98 - 98: I1IiiI
o00o0 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
II1III1I1I1Ii = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
if 70 - 70: OoO0O00 % oO0o + OOooOOo / Ii1I % O0
def oO00O0 ( packet ) :
 global lisp_map_cache , OOo
 if 36 - 36: oO0o - Ii1I . Oo0Ooo - i11iIiiIii - OOooOOo * Oo0Ooo
 OooOOOO = OoOO0o ( None , "Fast" )
 if 45 - 45: I1ii11iIi11i % I1IiiI - i11iIiiIii
 if 11 - 11: iIii1I11I1II1 * iIii1I11I1II1 * I1IiiI
 if 46 - 46: OoOoOO00 + OoO0O00
 if 70 - 70: iII111i / iIii1I11I1II1
 if 85 - 85: OoooooooOO % i1IIi * OoooooooOO / I1ii11iIi11i
 ooOOoO = 0
 I1i11i = None
 if ( packet [ 9 ] == '\x11' ) :
  if ( packet [ 20 : 22 ] == '\x10\xf6' ) : return ( False )
  if ( packet [ 22 : 24 ] == '\x10\xf6' ) : return ( False )
  if 11 - 11: I1IiiI / II111iiii + o0oOOo0O0Ooo * I1ii11iIi11i - I1ii11iIi11i - I1IiiI
  if ( packet [ 20 : 22 ] == '\x10\xf5' or packet [ 22 : 24 ] == '\x10\xf5' ) :
   I1i11i = packet [ 12 : 16 ]
   ooOOoO = packet [ 32 : 35 ]
   ooOOoO = ord ( ooOOoO [ 0 ] ) << 16 | ord ( ooOOoO [ 1 ] ) << 8 | ord ( ooOOoO [ 2 ] )
   if ( ooOOoO == 0xffffff ) : return ( False )
   ii1I1 ( "Decap" , packet )
   packet = packet [ 36 : : ]
   if 85 - 85: I11i % oO0o / iIii1I11I1II1 . iIii1I11I1II1
   if 31 - 31: o0oOOo0O0Ooo % OoO0O00
   if 14 - 14: oO0o / oO0o % ooOoO0o
 ii1I1 ( "Receive" , packet )
 if 56 - 56: I1IiiI . O0 + Oo0Ooo
 if 1 - 1: iII111i
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
 IIii11I1i1I = IIIIiIiIi1 ( packet [ 16 : 20 ] )
 II1III1I1I1Ii . instance_id = ooOOoO
 II1III1I1I1Ii . address = IIii11I1i1I
 if 99 - 99: iII111i
 if 76 - 76: OoO0O00 * I1IiiI
 if 82 - 82: Ii1I * iII111i / I1ii11iIi11i
 if 36 - 36: OoooooooOO - i1IIi . O0 / II111iiii + o0oOOo0O0Ooo
 if ( ( IIii11I1i1I & 0xe0000000 ) == 0xe0000000 ) : return ( False )
 if 33 - 33: II111iiii / ooOoO0o * O0 % Ii1I * I1Ii111
 if 100 - 100: IiII . I11i / Ii1I % OoOoOO00 % II111iiii - OoO0O00
 if 46 - 46: O0 * II111iiii - Oo0Ooo * ooOoO0o
 if 33 - 33: Ii1I
 IIii11I1i1I = II1III1I1I1Ii
 OOOoOoO = lisp . lisp_map_cache . lookup_cache ( IIii11I1i1I , False )
 i1I1i111Ii ( IIii11I1i1I , OOOoOoO )
 if ( OOOoOoO == None ) : return ( False )
 if 22 - 22: I1IiiI % I1ii11iIi11i
 if 57 - 57: OOooOOo + O0 . Ii1I
 if 46 - 46: IiII
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if ( I1i11i != None ) :
  i1iI1 = IIIIiIiIi1 ( packet [ 12 : 16 ] )
  o00o0 . instance_id = ooOOoO
  o00o0 . address = i1iI1
  ii1 = lisp . lisp_map_cache . lookup_cache ( o00o0 , False )
  if ( ii1 == None ) :
   I1IiiI1ii1i , O0o = lisp . lisp_allow_gleaning ( o00o0 , None )
   if ( I1IiiI1ii1i ) : return ( False )
  elif ( ii1 . gleaned ) :
   I1i11i = IIIIiIiIi1 ( I1i11i )
   if ( ii1 . rloc_set [ 0 ] . rloc . address != I1i11i ) : return ( False )
   if 54 - 54: OOooOOo
   if 45 - 45: OoooooooOO - OOooOOo + O0 * Ii1I . I1ii11iIi11i
   if 39 - 39: iIii1I11I1II1 / O0 / oO0o - Ii1I - iII111i % OOooOOo
   if 31 - 31: I11i - O0 / ooOoO0o * OoOoOO00
   if 12 - 12: o0oOOo0O0Ooo - ooOoO0o * I1Ii111
   if 14 - 14: Oo0Ooo - Ii1I % Ii1I * O0 . i11iIiiIii / O0
 if ( OOOoOoO . action == lisp . LISP_NATIVE_FORWARD_ACTION and
 OOOoOoO . eid . instance_id == 0 ) :
  IIii11I1i1I . instance_id = lisp . lisp_default_secondary_iid
  OOOoOoO = lisp . lisp_map_cache . lookup_cache ( IIii11I1i1I , False )
  i1I1i111Ii ( IIii11I1i1I , OOOoOoO )
  if ( OOOoOoO == None ) : return ( False )
  if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
  ii1III11 = len ( packet )
  I1iiIIIi11 = OOOoOoO . stats
  ii1I1 ( "Send" , packet )
 else :
  if 12 - 12: OoooooooOO % o0oOOo0O0Ooo * I11i % iIii1I11I1II1 / Ii1I
  if 27 - 27: i11iIiiIii % II111iiii % I11i . O0 - Oo0Ooo + OoOoOO00
  if 57 - 57: iIii1I11I1II1 / I11i - i1IIi
  if 51 - 51: IiII
  if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
  if ( OOOoOoO . best_rloc_set == [ ] ) : return ( False )
  if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
  IIii11I1i1I = OOOoOoO . best_rloc_set [ 0 ]
  if ( IIii11I1i1I . state != lisp . LISP_RLOC_UP_STATE ) : return ( False )
  if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
  ooOOoO = OOOoOoO . eid . instance_id
  ooooo = IIii11I1i1I . translated_port
  I1iiIIIi11 = IIii11I1i1I . stats
  IIii11I1i1I = IIii11I1i1I . rloc
  IIIII = IIii11I1i1I . address
  I1i11i = lisp . lisp_myrlocs [ 0 ] . address
  if 78 - 78: Ii1I * i1IIi
  if 1 - 1: I1IiiI / IiII * ooOoO0o
  if 1 - 1: I11i * o0oOOo0O0Ooo . OoOoOO00 / O0
  if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo % O0 * O0
  IIIii1 = '\x45\x00'
  ii1III11 = len ( packet ) + 20 + 8 + 8
  IIIii1 += chr ( ( ii1III11 >> 8 ) & 0xff ) + chr ( ii1III11 & 0xff )
  IIIii1 += '\xff\xff\x40\x00\x10\x11\x00\x00'
  IIIii1 += chr ( ( I1i11i >> 24 ) & 0xff )
  IIIii1 += chr ( ( I1i11i >> 16 ) & 0xff )
  IIIii1 += chr ( ( I1i11i >> 8 ) & 0xff )
  IIIii1 += chr ( I1i11i & 0xff )
  IIIii1 += chr ( ( IIIII >> 24 ) & 0xff )
  IIIii1 += chr ( ( IIIII >> 16 ) & 0xff )
  IIIii1 += chr ( ( IIIII >> 8 ) & 0xff )
  IIIii1 += chr ( IIIII & 0xff )
  IIIii1 = lisp . lisp_ip_checksum ( IIIii1 )
  if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
  if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
  if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
  if 100 - 100: OoO0O00
  II1i = ii1III11 - 20
  Ii1IIIIi1ii1I = '\xff\x00' if ( ooooo == 4341 ) else '\x10\xf5'
  Ii1IIIIi1ii1I += chr ( ( ooooo >> 8 ) & 0xff ) + chr ( ooooo & 0xff )
  Ii1IIIIi1ii1I += chr ( ( II1i >> 8 ) & 0xff ) + chr ( II1i & 0xff ) + '\x00\x00'
  if 13 - 13: I1IiiI % OoOoOO00 . I1ii11iIi11i / Oo0Ooo % OOooOOo . OoooooooOO
  Ii1IIIIi1ii1I += '\x08\xdf\xdf\xdf'
  Ii1IIIIi1ii1I += chr ( ( ooOOoO >> 16 ) & 0xff )
  Ii1IIIIi1ii1I += chr ( ( ooOOoO >> 8 ) & 0xff )
  Ii1IIIIi1ii1I += chr ( ooOOoO & 0xff )
  Ii1IIIIi1ii1I += '\x00'
  if 22 - 22: IiII / i11iIiiIii
  if 62 - 62: OoO0O00 / I1ii11iIi11i
  if 7 - 7: OoooooooOO . IiII
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
  packet = IIIii1 + Ii1IIIIi1ii1I + packet
  ii1I1 ( "Encap" , packet )
  if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
  if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
  if 92 - 92: ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 OOOoOoO . last_refresh_time = time . time ( )
 I1iiIIIi11 . increment ( ii1III11 )
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if 92 - 92: I11i . I1Ii111
 if 85 - 85: I1ii11iIi11i . I1Ii111
 if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
 IIii11I1i1I = IIii11I1i1I . print_address_no_iid ( )
 OOo . sendto ( packet , ( IIii11I1i1I , 0 ) )
 if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
 OoOO0o ( OooOOOO , "Fast" )
 return ( True )
 if 18 - 18: iIii1I11I1II1 % I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
def o0 ( lisp_packet , thread_name ) :
 global II1iII1i , Iii , I1iiiiI1iI
 global OOo , Ii1IIii11
 global oO0oIIII
 global iiIIIIi1i1
 global IIIiI11ii
 if 43 - 43: oO0o - OoooooooOO
 OooOOOO = OoOO0o ( None , "RTR" )
 if 3 - 3: O0 / iII111i
 if 31 - 31: OOooOOo + o0oOOo0O0Ooo . OoooooooOO
 if 89 - 89: II111iiii + i1IIi + II111iiii
 if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
 if ( IIIiI11ii ) :
  if ( oO00O0 ( lisp_packet . packet ) ) : return
  if 42 - 42: OoOoOO00 * OoOoOO00 * I1Ii111 . I11i
  if 51 - 51: OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o * iIii1I11I1II1 % OoO0O00
  if 99 - 99: oO0o * II111iiii * I1Ii111
  if 92 - 92: Oo0Ooo
  if 40 - 40: OoOoOO00 / IiII
 OOOoO000 = lisp_packet
 oOOOO = OOOoO000 . is_lisp_packet ( OOOoO000 . packet )
 if 49 - 49: II111iiii . oO0o . i11iIiiIii % IiII
 if 34 - 34: I1Ii111 % IiII
 if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
 if 83 - 83: oO0o + OoooooooOO
 if ( oOOOO == False ) :
  I111IiiIi1 = OOOoO000 . packet
  o00o , Ii1IIiiIIi , ooooo , Oo000o = lisp . lisp_is_rloc_probe ( I111IiiIi1 , - 1 )
  if ( I111IiiIi1 != o00o ) :
   if ( Ii1IIiiIIi == None ) : return
   lisp . lisp_parse_packet ( II1iII1i , o00o , Ii1IIiiIIi , ooooo , Oo000o )
   return
   if 39 - 39: I1ii11iIi11i
   if 97 - 97: OOooOOo - OoO0O00 / Ii1I . i11iIiiIii % oO0o * oO0o
   if 1 - 1: I1IiiI % ooOoO0o
   if 65 - 65: I1IiiI + OoOoOO00 / OOooOOo
   if 83 - 83: o0oOOo0O0Ooo . iII111i - Oo0Ooo
   if 65 - 65: iIii1I11I1II1 / ooOoO0o . IiII - II111iiii
 OOOoO000 . packet = lisp . lisp_reassemble ( OOOoO000 . packet )
 if ( OOOoO000 . packet == None ) : return
 if 72 - 72: iIii1I11I1II1 / IiII % iII111i % OOooOOo - I11i % OOooOOo
 if 100 - 100: Oo0Ooo + i11iIiiIii
 if 71 - 71: I11i / o0oOOo0O0Ooo / I1Ii111 % OOooOOo
 if 51 - 51: IiII * O0 / II111iiii . Ii1I % OOooOOo / I1IiiI
 if 9 - 9: I1IiiI % I1IiiI % II111iiii
 if ( lisp . lisp_flow_logging ) : OOOoO000 = copy . deepcopy ( OOOoO000 )
 if 30 - 30: IiII + I1Ii111 - IiII . IiII - II111iiii + O0
 if 86 - 86: i1IIi
 if 41 - 41: OoOoOO00 * I11i / OoOoOO00 % oO0o
 if 18 - 18: II111iiii . OoooooooOO % OoOoOO00 % Ii1I
 if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if ( oOOOO ) :
  if ( OOOoO000 . decode ( True , None , lisp . lisp_decap_stats ) == None ) : return
  OOOoO000 . print_packet ( "Receive-({})" . format ( thread_name ) , True )
  OOOoO000 . strip_outer_headers ( )
 else :
  if ( OOOoO000 . decode ( False , None , None ) == None ) : return
  OOOoO000 . print_packet ( "Receive-({})" . format ( thread_name ) , False )
  if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
  if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
  if 59 - 59: OOooOOo + i11iIiiIii
  if 88 - 88: i11iIiiIii - ooOoO0o
  if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
  if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
  if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
  if 30 - 30: OoOoOO00
  if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
  if 26 - 26: II111iiii * OoOoOO00
  if 10 - 10: II111iiii . iII111i
  if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 if ( oOOOO and OOOoO000 . lisp_header . get_instance_id ( ) == 0xffffff ) :
  ooO0oO00O0o = lisp . lisp_control_header ( )
  ooO0oO00O0o . decode ( OOOoO000 . packet )
  if ( ooO0oO00O0o . is_info_request ( ) ) :
   ooOO00oOOo000 = lisp . lisp_info ( )
   ooOO00oOOo000 . decode ( OOOoO000 . packet )
   ooOO00oOOo000 . print_info ( )
   if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
   if 67 - 67: I11i - OOooOOo . i1IIi
   if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
   if 87 - 87: OoOoOO00
   if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
   III = ooOO00oOOo000 . hostname if ( ooOO00oOOo000 . hostname != None ) else ""
   iIiIi11Ii = OOOoO000 . outer_source
   II1IiiIi1i = OOOoO000 . udp_sport
   if ( lisp . lisp_store_nat_info ( III , iIiIi11Ii , II1IiiIi1i ) ) :
    o0o0O0O00oOOo ( II1iII1i , III , iIiIi11Ii , II1IiiIi1i )
    if 23 - 23: oO0o - OOooOOo + I11i
  else :
   Ii1IIiiIIi = OOOoO000 . outer_source . print_address_no_iid ( )
   Oo000o = OOOoO000 . outer_ttl
   OOOoO000 = OOOoO000 . packet
   if ( lisp . lisp_is_rloc_probe_request ( OOOoO000 [ 28 ] ) == False and
 lisp . lisp_is_rloc_probe_reply ( OOOoO000 [ 28 ] ) == False ) : Oo000o = - 1
   OOOoO000 = OOOoO000 [ 28 : : ]
   lisp . lisp_parse_packet ( II1iII1i , OOOoO000 , Ii1IIiiIIi , 0 , Oo000o )
   if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
  return
  if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
  if 11 - 11: iII111i * Ii1I - OoOoOO00
  if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
  if 74 - 74: Oo0Ooo
  if 61 - 61: Oo0Ooo - I1Ii111 * II111iiii % ooOoO0o * iIii1I11I1II1 + OoO0O00
  if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
  if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
  if 68 - 68: OoooooooOO % II111iiii
  if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
  if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if ( oOOOO ) :
  lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( OOOoO000 . packet ) )
  if 2 - 2: Ii1I - IiII
  if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
  if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
  if 71 - 71: OoooooooOO
  if 33 - 33: I1Ii111
 OOO0ooo = None
 if ( OOOoO000 . inner_dest . is_mac ( ) ) :
  OOOoO000 . packet = lisp . lisp_mac_input ( OOOoO000 . packet )
  if ( OOOoO000 . packet == None ) : return
  OOOoO000 . encap_port = lisp . LISP_VXLAN_DATA_PORT
 elif ( OOOoO000 . inner_version == 4 ) :
  OOO0ooo , OOOoO000 . packet = lisp . lisp_ipv4_input ( OOOoO000 . packet )
  if ( OOOoO000 . packet == None ) : return
  OOOoO000 . inner_ttl = OOOoO000 . outer_ttl
 elif ( OOOoO000 . inner_version == 6 ) :
  OOOoO000 . packet = lisp . lisp_ipv6_input ( OOOoO000 )
  if ( OOOoO000 . packet == None ) : return
  OOOoO000 . inner_ttl = OOOoO000 . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
  if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
  if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
  if 45 - 45: IiII
  if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 if ( OOOoO000 . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( OOOoO000 , ed = "decap" ) == False ) : return
  OOOoO000 . outer_source . afi = lisp . LISP_AFI_NONE
  OOOoO000 . outer_dest . afi = lisp . LISP_AFI_NONE
  if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
  if 34 - 34: O0
  if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
  if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
  if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
  if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 I1IiiI1ii1i , O0o = lisp . lisp_allow_gleaning ( OOOoO000 . inner_source ,
 OOOoO000 . outer_source )
 if ( I1IiiI1ii1i ) :
  OoO = OOOoO000 . packet if ( OOO0ooo ) else None
  lisp . lisp_glean_map_cache ( OOOoO000 . inner_source , OOOoO000 . outer_source ,
 OOOoO000 . udp_sport , OoO )
  if ( OOO0ooo ) : return
  if 54 - 54: I11i / I1IiiI * oO0o + OoooooooOO - iII111i / OoooooooOO
 I111IIiii1Ii , O0o = lisp . lisp_allow_gleaning ( OOOoO000 . inner_dest , None )
 OOOoO000 . gleaned_dest = I111IIiii1Ii
 if 13 - 13: oO0o . I1IiiI * oO0o + I1IiiI
 if 59 - 59: I1IiiI + i11iIiiIii + i1IIi / I11i
 if 44 - 44: I11i . OoOoOO00 * I1IiiI + OoooooooOO - iII111i - IiII
 if 15 - 15: IiII / O0 . o0oOOo0O0Ooo . i11iIiiIii
 OOOoOoO = lisp . lisp_map_cache_lookup ( OOOoO000 . inner_source , OOOoO000 . inner_dest )
 if 59 - 59: I1Ii111 - o0oOOo0O0Ooo - ooOoO0o
 if 48 - 48: i1IIi + I11i % OoOoOO00 / Oo0Ooo - o0oOOo0O0Ooo
 if 67 - 67: oO0o % o0oOOo0O0Ooo . OoooooooOO + OOooOOo * I11i * OoOoOO00
 if 36 - 36: O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if ( OOOoOoO and ( OOOoOoO . action == lisp . LISP_NATIVE_FORWARD_ACTION or
 OOOoOoO . eid . address == 0 ) ) :
  ii1I11iIiIII1 = lisp . lisp_db_for_lookups . lookup_cache ( OOOoO000 . inner_source , False )
  if ( ii1I11iIiIII1 and ii1I11iIiIII1 . secondary_iid ) :
   oOO0OOOOoooO = OOOoO000 . inner_dest
   oOO0OOOOoooO . instance_id = ii1I11iIiIII1 . secondary_iid
   if 22 - 22: I11i + iIii1I11I1II1
   OOOoOoO = lisp . lisp_map_cache_lookup ( OOOoO000 . inner_source , oOO0OOOOoooO )
   if ( OOOoOoO ) :
    OOOoO000 . gleaned_dest = OOOoOoO . gleaned
   else :
    I111IIiii1Ii , O0o = lisp . lisp_allow_gleaning ( oOO0OOOOoooO , None )
    OOOoO000 . gleaned_dest = I111IIiii1Ii
    if 24 - 24: OoOoOO00 % i1IIi + iII111i . i11iIiiIii . I1ii11iIi11i
    if 17 - 17: I1ii11iIi11i . II111iiii . ooOoO0o / I1ii11iIi11i
    if 57 - 57: I11i
    if 67 - 67: OoO0O00 . ooOoO0o
    if 87 - 87: oO0o % Ii1I
    if 83 - 83: II111iiii - I11i
    if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
    if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
    if 51 - 51: OoOoOO00
 if ( OOOoOoO == None and I111IIiii1Ii ) :
  lisp . lprint ( "Suppress Map-Request for gleaned EID {}" . format ( lisp . green ( OOOoO000 . inner_dest . print_address ( ) , False ) ) )
  if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
  return
  if 53 - 53: Ii1I % Oo0Ooo
  if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if ( OOOoOoO == None or OOOoOoO . action == lisp . LISP_SEND_MAP_REQUEST_ACTION ) :
  if ( lisp . lisp_rate_limit_map_request ( OOOoO000 . inner_source ,
 OOOoO000 . inner_dest ) ) : return
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 OOOoO000 . inner_source , OOOoO000 . inner_dest , None )
  if 41 - 41: Ii1I % I1ii11iIi11i
  if ( OOOoO000 . is_trace ( ) ) :
   iIiIi11Ii = oO0oIIII
   i1iIiIi1I = "map-cache miss"
   lisp . lisp_trace_append ( OOOoO000 , reason = i1iIiIi1I , lisp_socket = iIiIi11Ii )
   if 37 - 37: Ii1I % OoO0O00
  return
  if 79 - 79: I1ii11iIi11i + I1IiiI / I1IiiI
  if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
  if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
  if 23 - 23: i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo - I1ii11iIi11i % iII111i * OoO0O00 - OOooOOo / iII111i
  if 29 - 29: I1ii11iIi11i
 if ( OOOoOoO and OOOoOoO . is_active ( ) and OOOoOoO . has_ttl_elapsed ( ) and
 OOOoOoO . gleaned == False ) :
  lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( OOOoOoO . print_eid_tuple ( ) , False ) ) )
  if 52 - 52: i11iIiiIii / i1IIi
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 OOOoO000 . inner_source , OOOoO000 . inner_dest , None )
  if 1 - 1: ooOoO0o
  if 78 - 78: I1ii11iIi11i + I11i - O0
  if 10 - 10: I1Ii111 % I1IiiI
  if 97 - 97: OoooooooOO - I1Ii111
  if 58 - 58: iIii1I11I1II1 + O0
  if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 OOOoOoO . stats . increment ( len ( OOOoO000 . packet ) )
 if 46 - 46: i11iIiiIii - O0 . oO0o
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 i1iiiIii11 , OOoOOO000O0 , oOo0 , II1i11I1 , iiIiIiII , Oo0O00O0O = OOOoOoO . select_rloc ( OOOoO000 , None )
 if 37 - 37: I11i / IiII + II111iiii
 if 18 - 18: I1ii11iIi11i
 if ( i1iiiIii11 == None and iiIiIiII == None ) :
  if ( II1i11I1 == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   OOOoO000 . send_packet ( OOo , OOOoO000 . inner_dest )
   if 23 - 23: II111iiii
   if ( OOOoO000 . is_trace ( ) ) :
    iIiIi11Ii = oO0oIIII
    i1iIiIi1I = "not an EID"
    lisp . lisp_trace_append ( OOOoO000 , reason = i1iIiIi1I , lisp_socket = iIiIi11Ii )
    if 24 - 24: iIii1I11I1II1 + iIii1I11I1II1 * iII111i
   OoOO0o ( OooOOOO , "RTR" )
   return
   if 18 - 18: iII111i * I11i - Ii1I
  i1iIiIi1I = "No reachable RLOCs found"
  lisp . dprint ( i1iIiIi1I )
  if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
  if ( OOOoO000 . is_trace ( ) ) :
   iIiIi11Ii = oO0oIIII
   lisp . lisp_trace_append ( OOOoO000 , reason = i1iIiIi1I , lisp_socket = iIiIi11Ii )
   if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  return
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if ( i1iiiIii11 and i1iiiIii11 . is_null ( ) ) :
  lisp . dprint ( "Drop action RLOC found" )
  if 39 - 39: iIii1I11I1II1 - OoooooooOO
  if ( OOOoO000 . is_trace ( ) ) :
   iIiIi11Ii = oO0oIIII
   i1iIiIi1I = "drop action"
   lisp . lisp_trace_append ( OOOoO000 , reason = i1iIiIi1I , lisp_socket = iIiIi11Ii )
   if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
  return
  if 23 - 23: II111iiii / oO0o
  if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
  if 19 - 19: I11i
  if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
  if 27 - 27: OOooOOo
 OOOoO000 . outer_tos = OOOoO000 . inner_tos
 OOOoO000 . outer_ttl = OOOoO000 . inner_ttl
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if ( i1iiiIii11 ) :
  OOOoO000 . encap_port = OOoOOO000O0
  if ( OOoOOO000O0 == 0 ) : OOOoO000 . encap_port = lisp . LISP_DATA_PORT
  OOOoO000 . outer_dest . copy_address ( i1iiiIii11 )
  IIiIiiiIIIIi1 = OOOoO000 . outer_dest . afi_to_version ( )
  OOOoO000 . outer_version = IIiIiiiIIIIi1
  if 39 - 39: OoO0O00 / Ii1I / I1Ii111
  O00O0 = iiIIIIi1i1 if ( IIiIiiiIIIIi1 == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 19 - 19: oO0o - II111iiii
  OOOoO000 . outer_source . copy_address ( O00O0 )
  if 63 - 63: i11iIiiIii . o0oOOo0O0Ooo
  if ( OOOoO000 . is_trace ( ) ) :
   iIiIi11Ii = oO0oIIII
   if ( lisp . lisp_trace_append ( OOOoO000 , rloc_entry = Oo0O00O0O ,
 lisp_socket = iIiIi11Ii ) == False ) : return
   if 19 - 19: II111iiii
   if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
   if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
   if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
   if 32 - 32: i11iIiiIii - I1Ii111
  if ( OOOoO000 . encode ( oOo0 ) == None ) : return
  if ( len ( OOOoO000 . packet ) <= 1500 ) : OOOoO000 . print_packet ( "Send" , True )
  if 53 - 53: OoooooooOO - IiII
  if 87 - 87: oO0o . I1IiiI
  if 17 - 17: Ii1I . i11iIiiIii
  if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
  o00oo0000 = Ii1IIii11 if IIiIiiiIIIIi1 == 6 else OOo
  OOOoO000 . send_packet ( o00oo0000 , OOOoO000 . outer_dest )
  if 44 - 44: Oo0Ooo % iIii1I11I1II1
 elif ( iiIiIiII ) :
  if 90 - 90: II111iiii + OoooooooOO % OoooooooOO
  if 35 - 35: iII111i / I1ii11iIi11i * OoooooooOO . II111iiii / Oo0Ooo
  if 1 - 1: OoooooooOO + IiII . i1IIi % I11i
  if 66 - 66: o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
  I1 = len ( OOOoO000 . packet )
  for IIiI in iiIiIiII . rle_forwarding_list :
   OOOoO000 . outer_dest . copy_address ( IIiI . address )
   OOOoO000 . encap_port = lisp . LISP_DATA_PORT if IIiI . translated_port == 0 else IIiI . translated_port
   if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
   if 21 - 21: O0 * O0 % I1ii11iIi11i
   IIiIiiiIIIIi1 = OOOoO000 . outer_dest . afi_to_version ( )
   OOOoO000 . outer_version = IIiIiiiIIIIi1
   O00O0 = lisp . lisp_myrlocs [ 0 ] if ( IIiIiiiIIIIi1 == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 94 - 94: I11i + II111iiii % i11iIiiIii
   OOOoO000 . outer_source . copy_address ( O00O0 )
   if 8 - 8: ooOoO0o * O0
   if ( OOOoO000 . is_trace ( ) ) :
    iIiIi11Ii = oO0oIIII
    i1iIiIi1I = "replicate"
    if ( lisp . lisp_trace_append ( OOOoO000 , reason = i1iIiIi1I , lisp_socket = iIiIi11Ii ) == False ) : return
    if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
    if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
    if 34 - 34: ooOoO0o
   if ( OOOoO000 . encode ( None ) == None ) : return
   if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
   OOOoO000 . print_packet ( "Replicate-to-L{}" . format ( IIiI . level ) , True )
   OOOoO000 . send_packet ( OOo , OOOoO000 . outer_dest )
   if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
   if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
   if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
   if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
   if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
   oOo0OooOo = len ( OOOoO000 . packet ) - I1
   OOOoO000 . packet = OOOoO000 . packet [ oOo0OooOo : : ]
   if 51 - 51: I11i . Oo0Ooo
   if ( lisp . lisp_flow_logging ) : OOOoO000 = copy . deepcopy ( OOOoO000 )
   if 45 - 45: i1IIi - Oo0Ooo / O0 . I1ii11iIi11i
   if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
   if 56 - 56: OoooooooOO - I11i - i1IIi
   if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
   if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
   if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 del ( OOOoO000 )
 if 53 - 53: I11i + iIii1I11I1II1
 OoOO0o ( OooOOOO , "RTR" )
 return
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
def o0OOoo ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
  if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
  if 77 - 77: OoO0O00 + I1Ii111 + I1Ii111 * Ii1I / OoooooooOO . Ii1I
  if 62 - 62: i1IIi - i1IIi
  OOOoO000 = lisp_thread . input_queue . get ( )
  if 69 - 69: OoOoOO00 % oO0o - I11i
  if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
  if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
  if 62 - 62: o0oOOo0O0Ooo - Ii1I * OoOoOO00 - i11iIiiIii % ooOoO0o
  lisp_thread . input_stats . increment ( len ( OOOoO000 ) )
  if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
  if 30 - 30: iII111i / OoO0O00 + oO0o
  if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
  if 70 - 70: OoO0O00
  lisp_thread . lisp_packet . packet = OOOoO000
  if 46 - 46: I11i - i1IIi
  if 46 - 46: I1Ii111 % Ii1I
  if 72 - 72: iIii1I11I1II1
  if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  o0 ( lisp_thread . lisp_packet , lisp_thread . thread_name )
  if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 return
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 if 84 - 84: i11iIiiIii * OoO0O00
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
def III1I ( thread ) :
 I1I111iIi = ( time . time ( ) % thread . number_of_pcap_threads )
 return ( int ( I1I111iIi ) == thread . thread_number )
 if 53 - 53: iIii1I11I1II1 + o0oOOo0O0Ooo - OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
def i1iii11 ( parms , not_used , packet ) :
 if ( III1I ( parms [ 1 ] ) == False ) : return
 if 92 - 92: OoOoOO00 . OoooooooOO - I1Ii111
 Oo0000o0O0O = parms [ 0 ]
 IIiIiIIiIi = parms [ 1 ]
 oooO = IIiIiIIiIi . number_of_worker_threads
 if 12 - 12: II111iiii
 IIiIiIIiIi . input_stats . increment ( len ( packet ) )
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 o00Ooo0 = 4 if Oo0000o0O0O == "lo0" else ( 14 if lisp . lisp_is_macos ( ) else 16 )
 packet = packet [ o00Ooo0 : : ]
 if 62 - 62: OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . OoOoOO00 + OoooooooOO
 if 77 - 77: iIii1I11I1II1 . Ii1I % oO0o / Ii1I
 if 54 - 54: oO0o + ooOoO0o - Oo0Ooo
 if 35 - 35: Ii1I - Ii1I + i1IIi - O0 - I1Ii111
 if ( oooO ) :
  oOO0o0oo0 = IIiIiIIiIi . input_stats . packet_count % oooO
  oOO0o0oo0 = oOO0o0oo0 + ( len ( I11 ) - oooO )
  oOo000O = I11 [ oOO0o0oo0 ]
  oOo000O . input_queue . put ( packet )
 else :
  IIiIiIIiIi . lisp_packet . packet = packet
  o0 ( IIiIiIIiIi . lisp_packet , IIiIiIIiIi . thread_name )
  if 1 - 1: iIii1I11I1II1
 return
 if 54 - 54: OoooooooOO - I1IiiI % I1ii11iIi11i
 if 92 - 92: OoO0O00 * ooOoO0o
 if 35 - 35: i11iIiiIii
 if 99 - 99: II111iiii . o0oOOo0O0Ooo + O0
 if 71 - 71: IiII + i1IIi * Oo0Ooo % Oo0Ooo / Oo0Ooo
 if 55 - 55: OoooooooOO + I1Ii111 + OoooooooOO * ooOoO0o
 if 68 - 68: O0
 if 2 - 2: OoO0O00 + O0 * OoO0O00 - Ii1I + oO0o
def iIIIiII1 ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 Oo0000o0O0O = "lo0" if lisp . lisp_is_macos ( ) else "any"
 I11Oo0oO00 = pcappy . open_live ( Oo0000o0O0O , 9000 , 0 , 100 )
 if 8 - 8: I1IiiI % I1IiiI . OoOoOO00 % o0oOOo0O0Ooo
 if 47 - 47: ooOoO0o + II111iiii % I1Ii111 . I11i % I1ii11iIi11i
 if 7 - 7: O0 / iII111i * oO0o
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 iIiI = commands . getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 iIiI = ( iIiI != "" and iIiI [ 0 ] == " " )
 if 81 - 81: OoOoOO00 % Ii1I
 oo0 = "(dst host "
 i1iIIi1II1iiI = ""
 for ii in lisp . lisp_get_all_addresses ( ) :
  oo0 += "{} or " . format ( ii )
  i1iIIi1II1iiI += "{} or " . format ( ii )
  if 31 - 31: o0oOOo0O0Ooo % I11i + iIii1I11I1II1 + i11iIiiIii * I1Ii111
 oo0 = oo0 [ 0 : - 4 ]
 oo0 += ") and ((udp dst port 4341 or 8472 or 4789) or "
 oo0 += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0))))"
 if 45 - 45: OOooOOo * I1Ii111 . ooOoO0o - I1Ii111 + IiII
 if 34 - 34: OOooOOo . Oo0Ooo
 if 78 - 78: I1ii11iIi11i % I1IiiI / OoooooooOO % OOooOOo - iII111i
 if 2 - 2: iIii1I11I1II1
 if 45 - 45: OoooooooOO / i11iIiiIii
 if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
 i1iIIi1II1iiI = i1iIIi1II1iiI [ 0 : - 4 ]
 oo0 += ( " or (not (src host {}) and " + "((udp src port 4342 and ip[28] == 0x28) or " + "(udp dst port 4342 and ip[28] == 0x12)))" ) . format ( i1iIIi1II1iiI )
 if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
 if 17 - 17: Ii1I
 if 39 - 39: ooOoO0o . II111iiii
 if ( iIiI ) :
  oo0 += " or (dst net 0.0.0.0/0 and not (host {}))" . format ( i1iIIi1II1iiI )
  if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
  if 77 - 77: I1Ii111 - I11i
 lisp . lprint ( "Capturing packets for: '{}'" . format ( oo0 ) )
 I11Oo0oO00 . filter = oo0
 if 11 - 11: I1ii11iIi11i
 if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
 if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
 if 55 - 55: ooOoO0o
 I11Oo0oO00 . loop ( - 1 , i1iii11 , [ Oo0000o0O0O , lisp_thread ] )
 return
 if 82 - 82: I1Ii111 - OOooOOo + OoO0O00
 if 64 - 64: o0oOOo0O0Ooo . O0 * Ii1I + OoooooooOO - Oo0Ooo . OoooooooOO
 if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
 if 55 - 55: iII111i - OoO0O00
 if 100 - 100: O0
 if 79 - 79: iIii1I11I1II1
 if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
def I1ii ( ) :
 lisp . lisp_set_exception ( )
 if 80 - 80: I1ii11iIi11i / iIii1I11I1II1 % OoOoOO00
 if 80 - 80: OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
 for o0OoOO000ooO0 in lisp . lisp_crypto_keys_by_nonce . values ( ) :
  for O0oo0O0 in o0OoOO000ooO0 : del ( O0oo0O0 )
  if 2 - 2: OoooooooOO . OOooOOo . IiII
 lisp . lisp_crypto_keys_by_nonce . clear ( )
 lisp . lisp_crypto_keys_by_nonce = { }
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 28 - 28: OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 lisp . lisp_rtr_nat_trace_cache . clear ( )
 lisp . lisp_rtr_nat_trace_cache = { }
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
 Oooo0000 = threading . Timer ( 60 , I1ii , [ ] )
 Oooo0000 . start ( )
 return
 if 46 - 46: IiII + oO0o
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
 if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
def I11i11i1 ( ) :
 global Oo0oO0oo0oO00 , II1iII1i , II1Ii1iI1i
 global OOo , Ii1IIii11 , I11
 global i111I , oO0oIIII
 global iiIIIIi1i1
 if 68 - 68: Oo0Ooo . Oo0Ooo - I1ii11iIi11i / I11i . ooOoO0o / i1IIi
 lisp . lisp_i_am ( "rtr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "RTR starting up" )
 if 12 - 12: I1ii11iIi11i * i1IIi * I11i
 if 23 - 23: OOooOOo / O0 / I1IiiI
 if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
 iiIIIIi1i1 = lisp . lisp_myrlocs [ 0 ]
 if ( lisp . lisp_on_aws ( ) ) :
  iiIIIIi1i1 = lisp . lisp_get_interface_address ( "eth0" )
  if 46 - 46: I1Ii111
  if 72 - 72: iII111i * OOooOOo
  if 67 - 67: i1IIi
  if 5 - 5: II111iiii . OoooooooOO
  if 57 - 57: I1IiiI
  if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
  if 50 - 50: OoOoOO00
 i1i1Ii11Ii = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 II1Ii1iI1i = lisp . lisp_open_listen_socket ( i1i1Ii11Ii ,
 str ( iiI1iIiI ) )
 Oo0oO0oo0oO00 = lisp . lisp_open_listen_socket ( "" , "lisp-rtr" )
 i111I = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 if 57 - 57: OOooOOo + I1Ii111 % I1ii11iIi11i . OoO0O00 / OoO0O00 * O0
 II1iII1i [ 0 ] = II1Ii1iI1i
 if 6 - 6: i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 II1iII1i [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 II1iII1i [ 2 ] = Oo0oO0oo0oO00
 if 68 - 68: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 - I1Ii111
 if 37 - 37: IiII
 if 37 - 37: Oo0Ooo / IiII * O0
 if 73 - 73: iII111i * iII111i / ooOoO0o
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 OOo = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 OOo . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 II1iII1i . append ( OOo )
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 oO0oIIII = lisp . lisp_open_listen_socket ( "0.0.0.0" ,
 str ( lisp . LISP_TRACE_PORT ) )
 if 83 - 83: o0oOOo0O0Ooo
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  Ii1IIii11 = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
  if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 i11I1I = os . getenv ( "LISP_PCAP_THREADS" )
 i11I1I = 1 if ( i11I1I == None ) else int ( i11I1I )
 oo0ooooo00o = os . getenv ( "LISP_WORKER_THREADS" )
 oo0ooooo00o = 0 if ( oo0ooooo00o == None ) else int ( oo0ooooo00o )
 if 78 - 78: iIii1I11I1II1 . o0oOOo0O0Ooo % iIii1I11I1II1 . O0 / OOooOOo
 if 76 - 76: i1IIi * OoooooooOO * O0 + I1Ii111 * I1Ii111
 if 35 - 35: o0oOOo0O0Ooo
 if 73 - 73: O0 - I1ii11iIi11i
 for ii1I in range ( i11I1I ) :
  oO0O = lisp . lisp_thread ( "pcap-{}" . format ( ii1I ) )
  oO0O . thread_number = ii1I
  oO0O . number_of_pcap_threads = i11I1I
  oO0O . number_of_worker_threads = oo0ooooo00o
  I11 . append ( oO0O )
  threading . Thread ( target = iIIIiII1 , args = [ oO0O ] ) . start ( )
  if 59 - 59: OoooooooOO * Oo0Ooo + i1IIi
  if 23 - 23: ooOoO0o
  if 13 - 13: iIii1I11I1II1
  if 77 - 77: i11iIiiIii - iIii1I11I1II1 / oO0o / ooOoO0o / OoO0O00
  if 56 - 56: OoooooooOO * O0
  if 85 - 85: OoooooooOO % OoOoOO00 * iIii1I11I1II1
 for ii1I in range ( oo0ooooo00o ) :
  oO0O = lisp . lisp_thread ( "worker-{}" . format ( ii1I ) )
  I11 . append ( oO0O )
  threading . Thread ( target = o0OOoo , args = [ oO0O ] ) . start ( )
  if 44 - 44: iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
  if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
  if 65 - 65: oO0o + OoOoOO00 + II111iiii
  if 77 - 77: II111iiii
  if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 lisp . lisp_load_checkpoint ( )
 if 68 - 68: oO0o
 if 10 - 10: Ii1I
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 Oooo0000 = threading . Timer ( 60 , I1ii , [ ] )
 Oooo0000 . start ( )
 return ( True )
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
def Ooo0oO ( ) :
 if 32 - 32: i1IIi . iII111i + II111iiii - OoO0O00 - iIii1I11I1II1
 if 20 - 20: OoOoOO00 % I1ii11iIi11i
 if 44 - 44: OoooooooOO . II111iiii . OOooOOo % OoooooooOO
 if 86 - 86: i11iIiiIii + O0 * IiII - OoO0O00 * OOooOOo + O0
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lisp-rtr" )
 lisp . lisp_close_socket ( II1Ii1iI1i , "" )
 lisp . lisp_close_socket ( oO0oIIII , "" )
 lisp . lisp_close_socket ( i111I , "lispers.net-itr" )
 OOo . close ( )
 return
 if 95 - 95: iIii1I11I1II1 . I1Ii111 % iII111i - I1Ii111 * II111iiii
 if 89 - 89: iII111i . I1IiiI
 if 59 - 59: i1IIi % iIii1I11I1II1 + OoooooooOO
 if 97 - 97: I1ii11iIi11i / Oo0Ooo + I1Ii111
 if 32 - 32: ooOoO0o % I1Ii111 * Oo0Ooo
 if 72 - 72: ooOoO0o . iII111i - I1Ii111 - Ii1I % i1IIi
 if 56 - 56: Oo0Ooo * iII111i
def II1I1ii1ii11 ( kv_pair ) :
 global II1iII1i
 global iiI1iIiI
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , iiI1iIiI ] )
  lisp . lisp_test_mr_timer . start ( )
  if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 return
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if 80 - 80: OoooooooOO + IiII
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if 43 - 43: Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
def O00ooooo00 ( kv_pair ) :
 global II1Ii1iI1i , OOo , iiI1iIiI
 if 94 - 94: I11i - II111iiii . I1IiiI - Oo0Ooo + I1ii11iIi11i * I1ii11iIi11i
 I1iiIiiii1111 = lisp . lisp_rloc_probing
 if 29 - 29: Ii1I - I1IiiI / I1IiiI * Ii1I * IiII . OOooOOo
 if 80 - 80: iIii1I11I1II1
 if 23 - 23: II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 lispconfig . lisp_xtr_command ( kv_pair )
 if 49 - 49: IiII * O0 . IiII
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 if ( I1iiIiiii1111 == False and lisp . lisp_rloc_probing ) :
  II = [ II1Ii1iI1i , II1Ii1iI1i ,
 None , OOo ]
  lisp . lisp_start_rloc_probe_timer ( 1 , II )
  O0o0Ooo = { "type" : "itr-crypto-port" , "port" : iiI1iIiI }
  lisp . lisp_write_to_dp_socket ( O0o0Ooo )
  if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
  if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
  if 96 - 96: OoooooooOO + IiII * O0
  if 86 - 86: Ii1I
  if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if 69 - 69: OoOoOO00
 if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
OooOo = {
 "lisp xtr-parameters" : [ O00ooooo00 , {
 "rloc-probing" : [ True , "yes" , "no" ] ,
 "nonce-echoing" : [ True , "yes" , "no" ] ,
 "data-plane-security" : [ True , "yes" , "no" ] ,
 "data-plane-logging" : [ True , "yes" , "no" ] ,
 "frame-logging" : [ True , "yes" , "no" ] ,
 "flow-logging" : [ True , "yes" , "no" ] ,
 "nat-traversal" : [ True , "yes" , "no" ] ,
 "checkpoint-map-cache" : [ True , "yes" , "no" ] ,
 "ipc-data-plane" : [ True , "yes" , "no" ] ,
 "decentralized-push-xtr" : [ True , "yes" , "no" ] ,
 "decentralized-pull-xtr-modulus" : [ True , 1 , 0xff ] ,
 "decentralized-pull-xtr-dns-suffix" : [ True ] ,
 "register-reachable-rtrs" : [ True , "yes" , "no" ] ,
 "program-hardware" : [ True , "yes" , "no" ] } ] ,

 "lisp interface" : [ lispconfig . lisp_interface_command , {
 "interface-name" : [ True ] ,
 "device" : [ True ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "dynamic-eid" : [ True ] ,
 "dynamic-eid-device" : [ True ] ,
 "lisp-nat" : [ True , "yes" , "no" ] ,
 "dynamic-eid-timeout" : [ True , 0 , 0xff ] } ] ,

 "lisp map-resolver" : [ II1I1ii1ii11 , {
 "mr-name" : [ True ] ,
 "ms-name" : [ True ] ,
 "dns-name" : [ True ] ,
 "address" : [ True ] } ] ,

 "lisp map-cache" : [ lispconfig . lisp_map_cache_command , {
 "prefix" : [ ] ,
 "mr-name" : [ True ] ,
 "ms-name" : [ True ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] ,
 "send-map-request" : [ True , "yes" , "no" ] ,
 "rloc" : [ ] ,
 "rloc-record-name" : [ True ] ,
 "rle-name" : [ True ] ,
 "elp-name" : [ True ] ,
 "address" : [ True ] ,
 "priority" : [ True , 0 , 255 ] ,
 "weight" : [ True , 0 , 100 ] } ] ,

 "lisp rtr-map-cache" : [ lispconfig . lisp_map_cache_command , {
 "prefix" : [ ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] ,
 "rloc" : [ ] ,
 "rloc-record-name" : [ True ] ,
 "rle-name" : [ True ] ,
 "elp-name" : [ True ] ,
 "address" : [ True ] ,
 "priority" : [ True , 0 , 255 ] ,
 "weight" : [ True , 0 , 100 ] } ] ,

 "lisp explicit-locator-path" : [ lispconfig . lisp_elp_command , {
 "elp-name" : [ False ] ,
 "elp-node" : [ ] ,
 "address" : [ True ] ,
 "probe" : [ True , "yes" , "no" ] ,
 "strict" : [ True , "yes" , "no" ] ,
 "eid" : [ True , "yes" , "no" ] } ] ,

 "lisp replication-list-entry" : [ lispconfig . lisp_rle_command , {
 "rle-name" : [ False ] ,
 "rle-node" : [ ] ,
 "address" : [ True ] ,
 "level" : [ True , 0 , 255 ] } ] ,

 "lisp json" : [ lispconfig . lisp_json_command , {
 "json-name" : [ False ] ,
 "json-string" : [ False ] } ] ,

 "lisp database-mapping" : [ OooOooooOOoo0 , {
 "prefix" : [ ] ,
 "mr-name" : [ True ] ,
 "ms-name" : [ True ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "secondary-instance-id" : [ True , 0 , 0xffffffff ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] ,
 "dynamic-eid" : [ True , "yes" , "no" ] ,
 "signature-eid" : [ True , "yes" , "no" ] ,
 "rloc" : [ ] ,
 "rloc-record-name" : [ True ] ,
 "elp-name" : [ True ] ,
 "geo-name" : [ True ] ,
 "rle-name" : [ True ] ,
 "json-name" : [ True ] ,
 "address" : [ True ] ,
 "interface" : [ True ] ,
 "priority" : [ True , 0 , 255 ] ,
 "weight" : [ True , 0 , 100 ] } ] ,

 "lisp glean-mapping" : [ OOOoO0O0o , {
 "instance-id" : [ False ] ,
 "eid-prefix" : [ True ] ,
 "rloc-prefix" : [ True ] ,
 "rloc-probe" : [ True , "yes" , "no" ] } ] ,

 "show rtr-rloc-probing" : [ IIIIiiII111 , { } ] ,
 "show rtr-keys" : [ I1i1iii , { } ] ,
 "show rtr-map-cache" : [ oO , { } ] ,
 "show rtr-map-cache-dns" : [ oo , { } ]
 }
if 67 - 67: Oo0Ooo / O0
if 88 - 88: OoOoOO00 - OOooOOo
if 63 - 63: IiII * OoooooooOO
if 19 - 19: IiII - o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00 / OOooOOo
if 87 - 87: OoOoOO00 - ooOoO0o - OOooOOo + Oo0Ooo % iIii1I11I1II1 / i11iIiiIii
if 12 - 12: ooOoO0o
def oOOO0ooOO ( lisp_socket ) :
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 Ii , Ii1IIiiIIi , ooooo , OOOoO000 = lisp . lisp_receive ( lisp_socket , False )
 ii1IOoo000000 = lisp . lisp_trace ( )
 if ( ii1IOoo000000 . decode ( OOOoO000 ) == False ) : return
 if 80 - 80: II111iiii - OOooOOo % OoooooooOO . iIii1I11I1II1 - ooOoO0o + I1IiiI
 if 21 - 21: i11iIiiIii
 if 89 - 89: iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 ii1IOoo000000 . rtr_cache_nat_trace ( Ii1IIiiIIi , ooooo )
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
if ( I11i11i1 ( ) == False ) :
 lisp . lprint ( "lisp_rtr_startup() failed" )
 lisp . lisp_print_banner ( "RTR abnormal exit" )
 exit ( 1 )
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
Ii11iiI1 = [ II1Ii1iI1i , Oo0oO0oo0oO00 ,
 i111I , oO0oIIII ]
oO0OOOoooO00o0o = [ II1Ii1iI1i ] * 3
if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
while ( True ) :
 try : OooOOOoOoo0O0 , O0OOOOo0 , OOooO0Oo00 = select . select ( Ii11iiI1 , [ ] , [ ] )
 except : break
 if 9 - 9: IiII
 if 48 - 48: o0oOOo0O0Ooo + o0oOOo0O0Ooo - Oo0Ooo
 if 27 - 27: OoO0O00 + OoOoOO00 * ooOoO0o
 if 83 - 83: iIii1I11I1II1
 if ( lisp . lisp_ipc_data_plane and i111I in OooOOOoOoo0O0 ) :
  lisp . lisp_process_punt ( i111I , II1iII1i ,
 iiI1iIiI )
  if 72 - 72: I11i
  if 87 - 87: i1IIi
  if 48 - 48: Oo0Ooo * oO0o * iIii1I11I1II1 + i11iIiiIii - OoooooooOO
  if 38 - 38: OoOoOO00 / iIii1I11I1II1 % i11iIiiIii - IiII * iII111i / OoOoOO00
  if 13 - 13: OoO0O00 * I1ii11iIi11i - I1Ii111
 if ( oO0oIIII in OooOOOoOoo0O0 ) :
  oOOO0ooOO ( oO0oIIII )
  if 79 - 79: oO0o % o0oOOo0O0Ooo % OoOoOO00
  if 45 - 45: I1IiiI * OOooOOo % OoO0O00
  if 24 - 24: ooOoO0o - I11i * oO0o
  if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
  if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if ( II1Ii1iI1i in OooOOOoOoo0O0 ) :
  Ii , Ii1IIiiIIi , ooooo , OOOoO000 = lisp . lisp_receive ( oO0OOOoooO00o0o [ 0 ] ,
 False )
  if ( Ii1IIiiIIi == "" ) : break
  if ( lisp . lisp_is_rloc_probe_request ( OOOoO000 [ 0 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
   continue
   if 79 - 79: IiII % OoO0O00
  if ( lisp . lisp_is_rloc_probe_reply ( OOOoO000 [ 0 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
   continue
   if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
  lisp . lisp_parse_packet ( oO0OOOoooO00o0o , OOOoO000 , Ii1IIiiIIi , ooooo )
  if 32 - 32: O0 . OoooooooOO
  if 15 - 15: I1IiiI . OoO0O00
  if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
  if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
  if 47 - 47: OoO0O00 + IiII / II111iiii
  if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if ( Oo0oO0oo0oO00 in OooOOOoOoo0O0 ) :
  Ii , Ii1IIiiIIi , ooooo , OOOoO000 = lisp . lisp_receive ( Oo0oO0oo0oO00 , True )
  if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
  if ( Ii1IIiiIIi == "" ) : break
  if 94 - 94: iII111i - Oo0Ooo + oO0o
  if ( Ii == "command" ) :
   if ( OOOoO000 == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
   if ( OOOoO000 . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( OOOoO000 )
    continue
    if 56 - 56: oO0o + ooOoO0o
   lispconfig . lisp_process_command ( Oo0oO0oo0oO00 , Ii ,
 OOOoO000 , "lisp-rtr" , [ OooOo ] )
  elif ( Ii == "api" ) :
   lisp . lisp_process_api ( "lisp-rtr" , Oo0oO0oo0oO00 , OOOoO000 )
  elif ( Ii == "data-packet" ) :
   o0 ( OOOoO000 , "" )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( OOOoO000 [ 0 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
    continue
    if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
   if ( lisp . lisp_is_rloc_probe_reply ( OOOoO000 [ 0 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
    continue
    if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
   lisp . lisp_parse_packet ( II1iII1i , OOOoO000 , Ii1IIiiIIi , ooooo )
   if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
   if 36 - 36: OOooOOo % i11iIiiIii
   if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
   if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
   if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
Ooo0oO ( )
lisp . lisp_print_banner ( "RTR normal exit" )
exit ( 0 )
if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
