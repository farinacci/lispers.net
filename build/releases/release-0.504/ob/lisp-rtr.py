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
if 43 - 43: OoOoOO00 - i1IIi + I1Ii111 + Ii1I
if 17 - 17: o0oOOo0O0Ooo
if 64 - 64: Ii1I % i1IIi % OoooooooOO
if 3 - 3: iII111i + O0
def I1Ii ( parameter ) :
 global I11
 if 66 - 66: Ii1I
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "RTR" ,
 I11 ) )
 if 78 - 78: OoO0O00
 if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
 if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
 if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
 if 14 - 14: I11i % O0
 if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
 if 77 - 77: Oo0Ooo . IiII % ooOoO0o
def IIiiIiI1 ( parameter ) :
 global I11
 if 41 - 41: OoOoOO00
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "RTR" , I11 ,
 True ) )
 if 13 - 13: Oo0Ooo . i11iIiiIii - iIii1I11I1II1 - OoOoOO00
 if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
 if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
 if 100 - 100: Ii1I - Ii1I - I1Ii111
 if 20 - 20: OoooooooOO
 if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
 if 97 - 97: i11iIiiIii
def II1i1Ii11Ii11 ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "RTR" ) )
 if 35 - 35: o0oOOo0O0Ooo + iII111i + iII111i
 if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
 if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
def i1iiI11I ( kv_pair ) :
 lispconfig . lisp_database_mapping_command ( kv_pair )
 if 29 - 29: OoooooooOO
 if 23 - 23: o0oOOo0O0Ooo . II111iiii
 if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
 if 45 - 45: I1Ii111 . OoOoOO00
 if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
 if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
 if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
def iIii11I ( kv_pair ) :
 OOO0OOO00oo = { "rloc-probe" : False }
 if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 for iii11 in kv_pair . keys ( ) :
  O0oo0OO0oOOOo = kv_pair [ iii11 ]
  if 35 - 35: IiII % I1IiiI
  if ( iii11 == "instance-id" ) :
   o0OOoo0OO0OOO = O0oo0OO0oOOOo . split ( "-" )
   OOO0OOO00oo [ "instance-id" ] = [ 0 , 0 ]
   if ( len ( o0OOoo0OO0OOO ) == 1 ) :
    OOO0OOO00oo [ "instance-id" ] [ 0 ] = int ( o0OOoo0OO0OOO [ 0 ] )
    OOO0OOO00oo [ "instance-id" ] [ 1 ] = int ( o0OOoo0OO0OOO [ 0 ] )
   else :
    OOO0OOO00oo [ "instance-id" ] [ 0 ] = int ( o0OOoo0OO0OOO [ 0 ] )
    OOO0OOO00oo [ "instance-id" ] [ 1 ] = int ( o0OOoo0OO0OOO [ 1 ] )
    if 19 - 19: oO0o % i1IIi % o0oOOo0O0Ooo
    if 93 - 93: iIii1I11I1II1 % oO0o * i1IIi
  if ( iii11 == "eid-prefix" ) :
   Ii11Ii1I = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   Ii11Ii1I . store_prefix ( O0oo0OO0oOOOo )
   OOO0OOO00oo [ "eid-prefix" ] = Ii11Ii1I
   if 72 - 72: iII111i / i1IIi * Oo0Ooo - I1Ii111
  if ( iii11 == "rloc-prefix" ) :
   Oo0O0O0ooO0O = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   Oo0O0O0ooO0O . store_prefix ( O0oo0OO0oOOOo )
   OOO0OOO00oo [ "rloc-prefix" ] = Oo0O0O0ooO0O
   if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
  if ( iii11 == "rloc-probe" ) :
   OOO0OOO00oo [ "rloc-probe" ] = ( O0oo0OO0oOOOo == "yes" )
   if 58 - 58: i11iIiiIii % I11i
   if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
   if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
   if 16 - 16: I1IiiI * oO0o % IiII
   if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
   if 44 - 44: oO0o
 for o0o0oOoOO0 in lisp . lisp_glean_mappings :
  if ( o0o0oOoOO0 . has_key ( "eid-prefix" ) ^ OOO0OOO00oo . has_key ( "eid-prefix" ) ) : continue
  if ( o0o0oOoOO0 . has_key ( "eid-prefix" ) and OOO0OOO00oo . has_key ( "eid-prefix" ) ) :
   iIi1iIiii111 = o0o0oOoOO0 [ "eid-prefix" ]
   iIIIi1 = OOO0OOO00oo [ "eid-prefix" ]
   if ( iIi1iIiii111 . is_exact_match ( iIIIi1 ) == False ) : continue
   if 20 - 20: i1IIi + I1ii11iIi11i - ooOoO0o
   if 30 - 30: II111iiii - OOooOOo - i11iIiiIii % OoOoOO00 - II111iiii * Ii1I
  if ( o0o0oOoOO0 . has_key ( "rloc-prefix" ) ^ OOO0OOO00oo . has_key ( "rloc-prefix" ) ) : continue
  if ( o0o0oOoOO0 . has_key ( "rloc-prefix" ) and OOO0OOO00oo . has_key ( "rloc-prefix" ) ) :
   iIi1iIiii111 = o0o0oOoOO0 [ "rloc-prefix" ]
   iIIIi1 = OOO0OOO00oo [ "rloc-prefix" ]
   if ( iIi1iIiii111 . is_exact_match ( iIIIi1 ) == False ) : continue
   if 61 - 61: oO0o - I11i % OOooOOo
   if 84 - 84: oO0o * OoO0O00 / I11i - O0
  if ( o0o0oOoOO0 . has_key ( "instance-id" ) ^ OOO0OOO00oo . has_key ( "instance-id" ) ) : continue
  if ( o0o0oOoOO0 . has_key ( "instance-id" ) and OOO0OOO00oo . has_key ( "instance-id" ) ) :
   iIi1iIiii111 = o0o0oOoOO0 [ "instance-id" ]
   iIIIi1 = OOO0OOO00oo [ "instance-id" ]
   if ( iIi1iIiii111 != iIIIi1 ) : continue
   if 30 - 30: iIii1I11I1II1 / ooOoO0o - I1Ii111 - II111iiii % iII111i
   if 49 - 49: I1IiiI % ooOoO0o . ooOoO0o . I11i * ooOoO0o
   if 97 - 97: Ii1I + o0oOOo0O0Ooo . OOooOOo + I1ii11iIi11i % iII111i
   if 95 - 95: i1IIi
   if 3 - 3: I1Ii111 - O0 / I1Ii111 % OoO0O00 / I1Ii111 . I1IiiI
  return
  if 50 - 50: IiII
  if 14 - 14: I11i % OoO0O00 * I11i
  if 16 - 16: OoOoOO00 . ooOoO0o + i11iIiiIii
  if 38 - 38: IiII * OOooOOo . o0oOOo0O0Ooo
  if 98 - 98: OoooooooOO + iII111i . OoOoOO00
 lisp . lisp_glean_mappings . append ( OOO0OOO00oo )
 if 67 - 67: i11iIiiIii - i1IIi % I1ii11iIi11i . O0
 if 77 - 77: IiII / I1IiiI
 if 15 - 15: IiII . iIii1I11I1II1 . OoooooooOO / i11iIiiIii - Ii1I . i1IIi
 if 33 - 33: I11i . o0oOOo0O0Ooo
 if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
 if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
def oOOo0 ( parameter ) :
 return ( lispconfig . lisp_itr_rtr_show_rloc_probe_command ( "RTR" ) )
 if 54 - 54: O0 - IiII % OOooOOo
 if 77 - 77: OoOoOO00 / I1IiiI / OoO0O00 + OoO0O00 . OOooOOo
 if 38 - 38: I1Ii111
 if 7 - 7: O0 . iII111i % I1ii11iIi11i - I1IiiI - iIii1I11I1II1
 if 36 - 36: IiII % ooOoO0o % Oo0Ooo - I1ii11iIi11i
 if 22 - 22: iIii1I11I1II1 / Oo0Ooo * I1ii11iIi11i % iII111i
 if 85 - 85: oO0o % i11iIiiIii - iII111i * OoooooooOO / I1IiiI % I1IiiI
def IIiIi1iI ( mc , parms ) :
 i1IiiiI1iI , Oo0O0O0ooO0O , i1iIi , ooOOoooooo = parms
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 III1Iiii1I11 = "{}:{}" . format ( Oo0O0O0ooO0O . print_address_no_iid ( ) , i1iIi )
 Ii11Ii1I = lisp . green ( mc . print_eid_tuple ( ) , False )
 IIII = "Changed '{}' translated address:port to {} for EID {}, {} {}" . format ( ooOOoooooo , lisp . red ( III1Iiii1I11 , False ) , Ii11Ii1I , "{}" , "{}" )
 if 32 - 32: OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
 for IIi1I11I1II in mc . rloc_set :
  if ( IIi1I11I1II . rle ) :
   for OooOoooOo in IIi1I11I1II . rle . rle_nodes :
    if ( OooOoooOo . rloc_name != ooOOoooooo ) : continue
    OooOoooOo . store_translated_rloc ( Oo0O0O0ooO0O , i1iIi )
    ii11IIII11I = OooOoooOo . address . print_address_no_iid ( ) + ":" + str ( OooOoooOo . translated_port )
    if 81 - 81: OoOoOO00 / O0 . IiII . I1IiiI
    lisp . lprint ( IIII . format ( "RLE" , ii11IIII11I ) )
    if 72 - 72: i1IIi / OoO0O00 + OoooooooOO - Oo0Ooo
    if 29 - 29: I1ii11iIi11i + oO0o % O0
    if 10 - 10: I11i / I1Ii111 - I1IiiI * iIii1I11I1II1 - I1IiiI
  if ( IIi1I11I1II . rloc_name != ooOOoooooo ) : continue
  if 97 - 97: I1ii11iIi11i + I1IiiI * Ii1I + OOooOOo % iII111i
  if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
  if 23 - 23: O0
  if 85 - 85: Ii1I
  if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
  if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
  ii11IIII11I = IIi1I11I1II . rloc . print_address_no_iid ( ) + ":" + str ( IIi1I11I1II . translated_port )
  if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
  if ( lisp . lisp_crypto_keys_by_rloc_encap . has_key ( ii11IIII11I ) ) :
   O0ooO0Oo00o = lisp . lisp_crypto_keys_by_rloc_encap [ ii11IIII11I ]
   lisp . lisp_crypto_keys_by_rloc_encap [ III1Iiii1I11 ] = O0ooO0Oo00o
   if 77 - 77: iIii1I11I1II1 * OoO0O00
   if 95 - 95: I1IiiI + i11iIiiIii
   if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
   if 80 - 80: II111iiii
   if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
  IIi1I11I1II . delete_from_rloc_probe_list ( mc . eid , mc . group )
  IIi1I11I1II . store_translated_rloc ( Oo0O0O0ooO0O , i1iIi )
  IIi1I11I1II . add_to_rloc_probe_list ( mc . eid , mc . group )
  lisp . lprint ( IIII . format ( "RLOC" , ii11IIII11I ) )
  if 53 - 53: II111iiii
  if 31 - 31: OoO0O00
  if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
  if 25 - 25: OoO0O00
  if ( lisp . lisp_rloc_probing ) :
   oOo0oO = None if ( mc . group . is_null ( ) ) else mc . eid
   OOOO0oo0 = mc . eid if ( mc . group . is_null ( ) ) else mc . group
   lisp . lisp_send_map_request ( i1IiiiI1iI , 0 , oOo0oO , OOOO0oo0 , IIi1I11I1II )
   if 35 - 35: Ii1I - I1IiiI % o0oOOo0O0Ooo . OoooooooOO % Ii1I
   if 47 - 47: iII111i - Ii1I . II111iiii + OoooooooOO . i11iIiiIii
   if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
   if 87 - 87: Oo0Ooo . IiII
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
 if ( mc . group . is_null ( ) ) : return ( IIiIi1iI ( mc , parms ) )
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if ( mc . source_cache == None ) : return ( True , parms )
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 mc . source_cache . walk_cache ( IIiIi1iI , parms )
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
 if 11 - 11: I1IiiI
def I1111i ( lisp_packet , thread_name ) :
 global II1iII1i , iIIii , o00O0O
 global OOo , Ii1IIii11
 global oO0oIIII
 global iiIIIIi1i1
 if 20 - 20: i1IIi - ooOoO0o
 i1iI = lisp_packet
 Oo0O0 = i1iI . is_lisp_packet ( i1iI . packet )
 if 82 - 82: II111iiii % I11i / OoO0O00 + OoOoOO00 / o0oOOo0O0Ooo / I1Ii111
 if 70 - 70: oO0o
 if 59 - 59: o0oOOo0O0Ooo % oO0o
 if 6 - 6: iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
 if ( Oo0O0 == False ) :
  o0Oo0oO0oOO00 = i1iI . packet
  oo00OO0000oO , I1II1 , i1iIi , oooO = lisp . lisp_is_rloc_probe ( o0Oo0oO0oOO00 , - 1 )
  if ( o0Oo0oO0oOO00 != oo00OO0000oO ) :
   if ( I1II1 == None ) : return
   lisp . lisp_parse_packet ( II1iII1i , oo00OO0000oO , I1II1 , i1iIi , oooO )
   return
   if 26 - 26: Ii1I % I1ii11iIi11i
   if 76 - 76: IiII * iII111i
   if 52 - 52: OOooOOo
   if 19 - 19: I1IiiI
   if 25 - 25: Ii1I / ooOoO0o
   if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 i1iI . packet = lisp . lisp_reassemble ( i1iI . packet )
 if ( i1iI . packet == None ) : return
 if 71 - 71: I1Ii111 . II111iiii
 if 62 - 62: OoooooooOO . I11i
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
 if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 58 - 58: I1IiiI
 if ( lisp . lisp_flow_logging ) : i1iI = copy . deepcopy ( i1iI )
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
 if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 if 23 - 23: i11iIiiIii
 if ( Oo0O0 ) :
  if ( i1iI . decode ( True , None , lisp . lisp_decap_stats ) == None ) : return
  i1iI . print_packet ( "Receive-({})" . format ( thread_name ) , True )
  i1iI . strip_outer_headers ( )
 else :
  if ( i1iI . decode ( False , None , None ) == None ) : return
  i1iI . print_packet ( "Receive-({})" . format ( thread_name ) , False )
  if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
  if 81 - 81: IiII % i1IIi . iIii1I11I1II1
  if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
  if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
  if 31 - 31: OOooOOo
  if 23 - 23: I1Ii111 . IiII
  if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
  if 42 - 42: Oo0Ooo
  if 76 - 76: I1IiiI * iII111i % I1Ii111
  if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
  if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
  if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
 if ( Oo0O0 and i1iI . lisp_header . get_instance_id ( ) == 0xffffff ) :
  oOoOOo0O = lisp . lisp_control_header ( )
  oOoOOo0O . decode ( i1iI . packet )
  if ( oOoOOo0O . is_info_request ( ) ) :
   OOOooo = lisp . lisp_info ( )
   OOOooo . decode ( i1iI . packet )
   OOOooo . print_info ( )
   if 94 - 94: OoooooooOO + Oo0Ooo / OoOoOO00 * OOooOOo
   if 69 - 69: ooOoO0o % oO0o
   if 50 - 50: OoooooooOO % I11i
   if 49 - 49: oO0o - i11iIiiIii . I1Ii111 * Ii1I % iII111i + i1IIi
   if 71 - 71: o0oOOo0O0Ooo
   IIIIiIiIi1 = OOOooo . hostname if ( OOOooo . hostname != None ) else ""
   I11iiiiI1i = i1iI . outer_source
   iI1i11 = i1iI . udp_sport
   if ( lisp . lisp_store_nat_info ( IIIIiIiIi1 , I11iiiiI1i , iI1i11 ) ) :
    o0o0O0O00oOOo ( II1iII1i , IIIIiIiIi1 , I11iiiiI1i , iI1i11 )
    if 66 - 66: O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / Ii1I + I1ii11iIi11i
  else :
   I1II1 = i1iI . outer_source . print_address_no_iid ( )
   oooO = i1iI . outer_ttl
   i1iI = i1iI . packet
   if ( lisp . lisp_is_rloc_probe_request ( i1iI [ 28 ] ) == False and
 lisp . lisp_is_rloc_probe_reply ( i1iI [ 28 ] ) == False ) : oooO = - 1
   i1iI = i1iI [ 28 : : ]
   lisp . lisp_parse_packet ( II1iII1i , i1iI , I1II1 , 0 , oooO )
   if 86 - 86: o0oOOo0O0Ooo
  return
  if 5 - 5: IiII * OoOoOO00
  if 5 - 5: I1Ii111
  if 90 - 90: I1Ii111 . ooOoO0o / Ii1I - I11i
  if 40 - 40: OoooooooOO
  if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
  if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
  if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
  if 19 - 19: OoO0O00 - Oo0Ooo . O0
  if 60 - 60: II111iiii + Oo0Ooo
  if 9 - 9: ooOoO0o * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
 if ( Oo0O0 ) :
  lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( i1iI . packet ) )
  if 49 - 49: II111iiii
  if 25 - 25: OoooooooOO - I1IiiI . I1IiiI * oO0o
  if 81 - 81: iII111i + IiII
  if 98 - 98: I1IiiI
  if 95 - 95: ooOoO0o / ooOoO0o
 if ( i1iI . inner_dest . is_mac ( ) ) :
  i1iI . packet = lisp . lisp_mac_input ( i1iI . packet )
  if ( i1iI . packet == None ) : return
  i1iI . encap_port = lisp . LISP_VXLAN_DATA_PORT
 elif ( i1iI . inner_version == 4 ) :
  i1iI . packet = lisp . lisp_ipv4_input ( i1iI . packet )
  if ( i1iI . packet == None ) : return
  i1iI . inner_ttl = i1iI . outer_ttl
 elif ( i1iI . inner_version == 6 ) :
  i1iI . packet = lisp . lisp_ipv6_input ( i1iI )
  if ( i1iI . packet == None ) : return
  i1iI . inner_ttl = i1iI . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
  if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
  if 41 - 41: i1IIi - I11i - Ii1I
  if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
  if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
 if ( i1iI . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( i1iI , ed = "decap" ) == False ) : return
  i1iI . outer_source . afi = lisp . LISP_AFI_NONE
  i1iI . outer_dest . afi = lisp . LISP_AFI_NONE
  if 44 - 44: II111iiii
  if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
  if 35 - 35: iIii1I11I1II1
  if 42 - 42: I1Ii111 . I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI
  if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
  if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 Iii1iiIi1II , OO0O00oOo = lisp . lisp_allow_gleaning ( i1iI . inner_source ,
 i1iI . outer_source )
 if ( Iii1iiIi1II ) :
  lisp . lisp_glean_map_cache ( i1iI . inner_source , i1iI . outer_source ,
 i1iI . udp_sport )
  if 14 - 14: I1IiiI
 IIiIiI1I , OO0O00oOo = lisp . lisp_allow_gleaning ( i1iI . inner_dest , None )
 i1iI . gleaned_dest = IIiIiI1I
 if 100 - 100: iIii1I11I1II1 + OoOoOO00 / Oo0Ooo . i11iIiiIii
 if 14 - 14: o0oOOo0O0Ooo * OOooOOo + iII111i + O0 + i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
 if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
 Oo00o0OO0O00o = lisp . lisp_map_cache_lookup ( i1iI . inner_source , i1iI . inner_dest )
 if 82 - 82: I11i + OoooooooOO - i1IIi . i1IIi
 if 6 - 6: o0oOOo0O0Ooo / I11i / II111iiii
 if 27 - 27: OOooOOo * ooOoO0o . I1Ii111 % IiII * IiII . i1IIi
 if 72 - 72: OOooOOo % I1ii11iIi11i + OoO0O00 / oO0o + IiII
 if 10 - 10: I1Ii111 / ooOoO0o + i11iIiiIii / Ii1I
 if ( Oo00o0OO0O00o and ( Oo00o0OO0O00o . action == lisp . LISP_NATIVE_FORWARD_ACTION or
 Oo00o0OO0O00o . eid . address == 0 ) ) :
  OOOoOoO = lisp . lisp_db_for_lookups . lookup_cache ( i1iI . inner_source , False )
  if ( OOOoOoO and OOOoOoO . secondary_iid ) :
   iIIIII1ii1I = i1iI . inner_dest
   iIIIII1ii1I . instance_id = OOOoOoO . secondary_iid
   if 13 - 13: i11iIiiIii + i1IIi * iIii1I11I1II1 % OoooooooOO - II111iiii * OOooOOo
   Oo00o0OO0O00o = lisp . lisp_map_cache_lookup ( i1iI . inner_source , iIIIII1ii1I )
   if ( Oo00o0OO0O00o ) :
    i1iI . gleaned_dest = Oo00o0OO0O00o . gleaned
   else :
    IIiIiI1I , OO0O00oOo = lisp . lisp_allow_gleaning ( iIIIII1ii1I , None )
    i1iI . gleaned_dest = IIiIiI1I
    if 26 - 26: OoooooooOO * I1IiiI + OOooOOo
    if 24 - 24: i11iIiiIii % iIii1I11I1II1 + OOooOOo / i11iIiiIii
    if 70 - 70: OoO0O00 * O0 . I11i + I1IiiI . IiII
    if 14 - 14: iIii1I11I1II1 % iIii1I11I1II1 * i11iIiiIii - OoO0O00 - I11i
    if 63 - 63: OoO0O00
    if 69 - 69: iIii1I11I1II1 . I1ii11iIi11i % ooOoO0o + iIii1I11I1II1 / O0 / I1ii11iIi11i
    if 61 - 61: OOooOOo % OOooOOo * o0oOOo0O0Ooo / o0oOOo0O0Ooo
    if 75 - 75: IiII . ooOoO0o
    if 50 - 50: OoOoOO00
    if 60 - 60: ooOoO0o * iIii1I11I1II1 * I1ii11iIi11i * Oo0Ooo
 if ( Oo00o0OO0O00o == None and IIiIiI1I ) :
  lisp . lprint ( "Suppress Map-Request for gleaned EID {}" . format ( lisp . green ( i1iI . inner_dest . print_address ( ) , False ) ) )
  if 69 - 69: Ii1I * O0 . i11iIiiIii / Ii1I . o0oOOo0O0Ooo
  return
  if 63 - 63: I11i + o0oOOo0O0Ooo . II111iiii - I1IiiI
  if 52 - 52: o0oOOo0O0Ooo % Oo0Ooo
 if ( Oo00o0OO0O00o == None or Oo00o0OO0O00o . action == lisp . LISP_SEND_MAP_REQUEST_ACTION ) :
  if ( lisp . lisp_rate_limit_map_request ( i1iI . inner_source ,
 i1iI . inner_dest ) ) : return
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 i1iI . inner_source , i1iI . inner_dest , None )
  if 64 - 64: O0 % I11i % O0 * OoO0O00 . oO0o + I1IiiI
  if ( i1iI . is_trace ( ) ) :
   I11iiiiI1i = oO0oIIII
   O00 = "map-cache miss"
   lisp . lisp_trace_append ( i1iI , reason = O00 , lisp_socket = I11iiiiI1i )
   if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
  return
  if 28 - 28: I11i
  if 58 - 58: OoOoOO00
  if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
  if 73 - 73: i11iIiiIii - IiII
  if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
  if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
 if ( Oo00o0OO0O00o and Oo00o0OO0O00o . is_active ( ) and Oo00o0OO0O00o . has_ttl_elapsed ( ) and
 Oo00o0OO0O00o . gleaned == False ) :
  lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( Oo00o0OO0O00o . print_eid_tuple ( ) , False ) ) )
  if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 i1iI . inner_source , i1iI . inner_dest , None )
  if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
  if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
  if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
  if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
  if 97 - 97: I1IiiI / iII111i
  if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
 Oo00o0OO0O00o . stats . increment ( len ( i1iI . packet ) )
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 IIi1ii1Ii , OoOoO , o0 , ii1i , oOOoo , IIi1I11I1II = Oo00o0OO0O00o . select_rloc ( i1iI , None )
 if 14 - 14: o0oOOo0O0Ooo * oO0o
 if 81 - 81: Ii1I * o0oOOo0O0Ooo + I1Ii111 + Oo0Ooo - OoooooooOO
 if ( IIi1ii1Ii == None and oOOoo == None ) :
  if ( ii1i == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   i1iI . send_packet ( OOo , i1iI . inner_dest )
   if 32 - 32: Ii1I * O0
   if ( i1iI . is_trace ( ) ) :
    I11iiiiI1i = oO0oIIII
    O00 = "not an EID"
    lisp . lisp_trace_append ( i1iI , reason = O00 , lisp_socket = I11iiiiI1i )
    if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
   return
   if 92 - 92: ooOoO0o
  O00 = "No reachable RLOCs found"
  lisp . dprint ( O00 )
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  if ( i1iI . is_trace ( ) ) :
   I11iiiiI1i = oO0oIIII
   lisp . lisp_trace_append ( i1iI , reason = O00 , lisp_socket = I11iiiiI1i )
   if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  return
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if ( IIi1ii1Ii and IIi1ii1Ii . is_null ( ) ) :
  lisp . dprint ( "Drop action RLOC found" )
  if 92 - 92: I11i . I1Ii111
  if ( i1iI . is_trace ( ) ) :
   I11iiiiI1i = oO0oIIII
   O00 = "drop action"
   lisp . lisp_trace_append ( i1iI , reason = O00 , lisp_socket = I11iiiiI1i )
   if 85 - 85: I1ii11iIi11i . I1Ii111
  return
  if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
  if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
  if 18 - 18: iIii1I11I1II1 % I11i
  if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
  if 75 - 75: OoooooooOO * IiII
 i1iI . outer_tos = i1iI . inner_tos
 i1iI . outer_ttl = i1iI . inner_ttl
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
 if ( IIi1ii1Ii ) :
  i1iI . encap_port = OoOoO
  if ( OoOoO == 0 ) : i1iI . encap_port = lisp . LISP_DATA_PORT
  i1iI . outer_dest . copy_address ( IIi1ii1Ii )
  iI1iIIIi1i = i1iI . outer_dest . afi_to_version ( )
  i1iI . outer_version = iI1iIIIi1i
  if 89 - 89: iIii1I11I1II1
  i11iiiiI1i = iiIIIIi1i1 if ( iI1iIIIi1i == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 37 - 37: OOooOOo / OoooooooOO - i11iIiiIii
  i1iI . outer_source . copy_address ( i11iiiiI1i )
  if 18 - 18: iII111i . I1IiiI
  if ( i1iI . is_trace ( ) ) :
   I11iiiiI1i = oO0oIIII
   if ( lisp . lisp_trace_append ( i1iI , rloc_entry = IIi1I11I1II ,
 lisp_socket = I11iiiiI1i ) == False ) : return
   if 40 - 40: O0 - OoooooooOO - IiII
   if 37 - 37: OoOoOO00 / II111iiii / O0
   if 76 - 76: I1IiiI . ooOoO0o - I1ii11iIi11i - iII111i * OoO0O00
   if 54 - 54: IiII + O0 + I11i * I1Ii111 - OOooOOo % oO0o
   if 13 - 13: ooOoO0o / iII111i * OoO0O00 . OoO0O00 * ooOoO0o
  if ( i1iI . encode ( o0 ) == None ) : return
  if ( len ( i1iI . packet ) <= 1500 ) : i1iI . print_packet ( "Send" , True )
  if 63 - 63: I1Ii111 / O0 * Oo0Ooo + II111iiii / IiII + Ii1I
  if 63 - 63: OoO0O00 + I1ii11iIi11i . I1Ii111 % I1Ii111
  if 57 - 57: II111iiii
  if 54 - 54: Oo0Ooo + oO0o + i11iIiiIii
  i1i1ii111 = Ii1IIii11 if iI1iIIIi1i == 6 else OOo
  i1iI . send_packet ( i1i1ii111 , i1iI . outer_dest )
  if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
 elif ( oOOoo ) :
  if 83 - 83: oO0o + OoooooooOO
  if 22 - 22: Ii1I % iII111i * OoooooooOO - o0oOOo0O0Ooo / iIii1I11I1II1
  if 86 - 86: OoooooooOO . iII111i % OoOoOO00 / I11i * iII111i / o0oOOo0O0Ooo
  if 64 - 64: i11iIiiIii
  I1II = len ( i1iI . packet )
  for I1iIiI11I1 in oOOoo . rle_forwarding_list :
   i1iI . outer_dest . copy_address ( I1iIiI11I1 . address )
   i1iI . encap_port = lisp . LISP_DATA_PORT if I1iIiI11I1 . translated_port == 0 else I1iIiI11I1 . translated_port
   if 27 - 27: Ii1I . i11iIiiIii % I1Ii111
   if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
   iI1iIIIi1i = i1iI . outer_dest . afi_to_version ( )
   i1iI . outer_version = iI1iIIIi1i
   i11iiiiI1i = lisp . lisp_myrlocs [ 0 ] if ( iI1iIIIi1i == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
   i1iI . outer_source . copy_address ( i11iiiiI1i )
   if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
   if ( i1iI . is_trace ( ) ) :
    I11iiiiI1i = oO0oIIII
    O00 = "replicate"
    if ( lisp . lisp_trace_append ( i1iI , reason = O00 , lisp_socket = I11iiiiI1i ) == False ) : return
    if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
    if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
    if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
   if ( i1iI . encode ( None ) == None ) : return
   if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
   i1iI . print_packet ( "Replicate-to-L{}" . format ( I1iIiI11I1 . level ) , True )
   i1iI . send_packet ( OOo , i1iI . outer_dest )
   if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
   if 95 - 95: IiII
   if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
   if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
   if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
   ii1Ii1IiIIi = len ( i1iI . packet ) - I1II
   i1iI . packet = i1iI . packet [ ii1Ii1IiIIi : : ]
   if 83 - 83: I11i / I1ii11iIi11i
   if ( lisp . lisp_flow_logging ) : i1iI = copy . deepcopy ( i1iI )
   if 34 - 34: I1IiiI * Oo0Ooo * I1Ii111 / OoO0O00 * I11i / iIii1I11I1II1
   if 74 - 74: Oo0Ooo / i11iIiiIii - II111iiii * o0oOOo0O0Ooo
   if 5 - 5: OOooOOo - OOooOOo . Oo0Ooo + OoOoOO00 - OOooOOo . oO0o
   if 31 - 31: II111iiii - iIii1I11I1II1 - iIii1I11I1II1 % I11i
   if 12 - 12: iIii1I11I1II1
   if 20 - 20: o0oOOo0O0Ooo / i1IIi
 del ( i1iI )
 return
 if 71 - 71: OoOoOO00 . i1IIi
 if 94 - 94: OOooOOo . I1Ii111
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 if 47 - 47: OoooooooOO
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 if 82 - 82: ooOoO0o + II111iiii
def II1i1i1iII1 ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  if 68 - 68: Oo0Ooo + i11iIiiIii
  if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
  if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
  if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
  i1iI = lisp_thread . input_queue . get ( )
  if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
  if 98 - 98: i1IIi
  if 65 - 65: OoOoOO00 / OoO0O00 % IiII
  if 45 - 45: OoOoOO00
  lisp_thread . input_stats . increment ( len ( i1iI ) )
  if 66 - 66: OoO0O00
  if 56 - 56: O0
  if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
  if 23 - 23: oO0o - OOooOOo + I11i
  lisp_thread . lisp_packet . packet = i1iI
  if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
  if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
  if 11 - 11: iII111i * Ii1I - OoOoOO00
  if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
  I1111i ( lisp_thread . lisp_packet , lisp_thread . thread_name )
  if 74 - 74: Oo0Ooo
 return
 if 61 - 61: Oo0Ooo - I1Ii111 * II111iiii % ooOoO0o * iIii1I11I1II1 + OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
def OO0OO00oo0 ( thread ) :
 iIIIiIii = ( time . time ( ) % thread . number_of_pcap_threads )
 return ( int ( iIIIiIii ) == thread . thread_number )
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
 if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
def OoO000O ( parms , not_used , packet ) :
 if ( OO0OO00oo0 ( parms [ 1 ] ) == False ) : return
 if 94 - 94: OoOoOO00 . O0 / Ii1I . I1ii11iIi11i - i1IIi
 iIi1III1I = parms [ 0 ]
 oo0oo0OOOOOoO = parms [ 1 ]
 Oo0000O0OOooO = oo0oo0OOOOOoO . number_of_worker_threads
 if 54 - 54: I11i / I1IiiI * oO0o + OoooooooOO - iII111i / OoooooooOO
 oo0oo0OOOOOoO . input_stats . increment ( len ( packet ) )
 if 19 - 19: IiII * ooOoO0o * o0oOOo0O0Ooo + O0 / O0
 if 73 - 73: iIii1I11I1II1 / iIii1I11I1II1 - oO0o
 if 91 - 91: oO0o + I1IiiI
 if 59 - 59: I1IiiI + i11iIiiIii + i1IIi / I11i
 if 44 - 44: I11i . OoOoOO00 * I1IiiI + OoooooooOO - iII111i - IiII
 if 15 - 15: IiII / O0 . o0oOOo0O0Ooo . i11iIiiIii
 o0OO0O0Oo = 4 if iIi1III1I == "lo0" else ( 14 if lisp . lisp_is_macos ( ) else 16 )
 packet = packet [ o0OO0O0Oo : : ]
 if 78 - 78: OoOoOO00 / Oo0Ooo - OOooOOo - iII111i * oO0o
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
 if 36 - 36: O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if ( Oo0000O0OOooO ) :
  ii1I11iIiIII1 = oo0oo0OOOOOoO . input_stats . packet_count % Oo0000O0OOooO
  ii1I11iIiIII1 = ii1I11iIiIII1 + ( len ( I11 ) - Oo0000O0OOooO )
  oOO0OOOOoooO = I11 [ ii1I11iIiIII1 ]
  oOO0OOOOoooO . input_queue . put ( packet )
 else :
  oo0oo0OOOOOoO . lisp_packet . packet = packet
  I1111i ( oo0oo0OOOOOoO . lisp_packet , oo0oo0OOOOOoO . thread_name )
  if 22 - 22: I11i + iIii1I11I1II1
 return
 if 24 - 24: OoOoOO00 % i1IIi + iII111i . i11iIiiIii . I1ii11iIi11i
 if 17 - 17: I1ii11iIi11i . II111iiii . ooOoO0o / I1ii11iIi11i
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
 if 87 - 87: oO0o % Ii1I
 if 83 - 83: II111iiii - I11i
 if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
def OooOOo0 ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 51 - 51: OoOoOO00
 iIi1III1I = "lo0" if lisp . lisp_is_macos ( ) else "any"
 I11IIIiIi11 = pcappy . open_live ( iIi1III1I , 9000 , 0 , 100 )
 if 39 - 39: Ii1I % O0 % OoOoOO00 . i1IIi
 if 86 - 86: OoO0O00 * OoooooooOO
 if 71 - 71: iIii1I11I1II1 - OOooOOo . I1IiiI % OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 IiI = commands . getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 IiI = ( IiI != "" and IiI [ 0 ] == " " )
 if 34 - 34: I11i % ooOoO0o . O0 . iIii1I11I1II1
 oo = "(dst host "
 i1II1I = ""
 for III1Iiii1I11 in lisp . lisp_get_all_addresses ( ) :
  oo += "{} or " . format ( III1Iiii1I11 )
  i1II1I += "{} or " . format ( III1Iiii1I11 )
  if 95 - 95: OoO0O00 - OOooOOo / II111iiii % I1ii11iIi11i . o0oOOo0O0Ooo
 oo = oo [ 0 : - 4 ]
 oo += ") and ((udp dst port 4341 or 8472 or 4789) or "
 oo += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0))))"
 if 24 - 24: i1IIi . i11iIiiIii
 if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
 if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
 if 81 - 81: iII111i * OOooOOo - I1ii11iIi11i * Ii1I % OoOoOO00 * OoOoOO00
 if 59 - 59: iIii1I11I1II1
 if 7 - 7: OOooOOo * I1IiiI / o0oOOo0O0Ooo * i11iIiiIii
 i1II1I = i1II1I [ 0 : - 4 ]
 oo += ( " or (not (src host {}) and " + "((udp src port 4342 and ip[28] == 0x28) or " + "(udp dst port 4342 and ip[28] == 0x12)))" ) . format ( i1II1I )
 if 84 - 84: OOooOOo . iII111i
 if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
 if 21 - 21: oO0o / OoooooooOO
 if ( IiI ) :
  oo += " or (dst net 0.0.0.0/0 and not (host {}))" . format ( i1II1I )
  if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
  if 87 - 87: I1Ii111 * i1IIi / I1ii11iIi11i
 lisp . lprint ( "Capturing packets for: '{}'" . format ( oo ) )
 I11IIIiIi11 . filter = oo
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo - OoooooooOO % OOooOOo * OoOoOO00
 if 69 - 69: i1IIi
 if 59 - 59: II111iiii - o0oOOo0O0Ooo
 if 24 - 24: Oo0Ooo - i1IIi + I11i
 I11IIIiIi11 . loop ( - 1 , OoO000O , [ iIi1III1I , lisp_thread ] )
 return
 if 38 - 38: OoooooooOO / I1ii11iIi11i . O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
 if 96 - 96: iII111i
 if 18 - 18: iII111i * I11i - Ii1I
 if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
def oO0oooooo ( ) :
 lisp . lisp_set_exception ( )
 if 65 - 65: IiII + Oo0Ooo
 if 59 - 59: OoooooooOO + I11i . I1Ii111 - O0 % iIii1I11I1II1 / O0
 if 88 - 88: Oo0Ooo . O0 % OoooooooOO / OOooOOo
 if 89 - 89: II111iiii / oO0o
 for O0ooO0Oo00o in lisp . lisp_crypto_keys_by_nonce . values ( ) :
  for II in O0ooO0Oo00o : del ( II )
  if 87 - 87: ooOoO0o + o0oOOo0O0Ooo
 lisp . lisp_crypto_keys_by_nonce . clear ( )
 lisp . lisp_crypto_keys_by_nonce = { }
 if 28 - 28: OOooOOo * I1ii11iIi11i / oO0o
 if 64 - 64: oO0o - I1IiiI / iII111i - OoO0O00
 if 37 - 37: i11iIiiIii / iII111i
 if 85 - 85: i11iIiiIii + I1Ii111 * OoOoOO00
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 1 - 1: i1IIi / Oo0Ooo . OoO0O00
 if 57 - 57: I11i . Oo0Ooo + II111iiii
 if 43 - 43: I1Ii111 % iII111i
 if 69 - 69: iII111i % OoO0O00
 if 86 - 86: oO0o / oO0o
 lisp . lisp_rtr_nat_trace_cache . clear ( )
 lisp . lisp_rtr_nat_trace_cache = { }
 if 28 - 28: i11iIiiIii / o0oOOo0O0Ooo . iIii1I11I1II1 / II111iiii
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 Oooo0000 = threading . Timer ( 60 , oO0oooooo , [ ] )
 Oooo0000 . start ( )
 return
 if 32 - 32: i11iIiiIii - I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
def iIIi1iiI1i11 ( ) :
 global Oo0oO0oo0oO00 , II1iII1i , II1Ii1iI1i
 global OOo , Ii1IIii11 , I11
 global i111I , oO0oIIII
 global iiIIIIi1i1
 if 56 - 56: OoooooooOO
 lisp . lisp_i_am ( "rtr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "RTR starting up" )
 if 30 - 30: i11iIiiIii + oO0o
 if 38 - 38: IiII . Ii1I
 if 24 - 24: o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
 if 12 - 12: iII111i . IiII . OoOoOO00 / O0
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
 if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 iiIIIIi1i1 = lisp . lisp_myrlocs [ 0 ]
 if ( lisp . lisp_on_aws ( ) ) :
  iiIIIIi1i1 = lisp . lisp_get_interface_address ( "eth0" )
  if 34 - 34: ooOoO0o
  if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
  if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
  if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
  if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
  if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
  if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 oOo0OooOo = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 II1Ii1iI1i = lisp . lisp_open_listen_socket ( oOo0OooOo ,
 str ( iiI1iIiI ) )
 Oo0oO0oo0oO00 = lisp . lisp_open_listen_socket ( "" , "lisp-rtr" )
 i111I = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 if 51 - 51: I11i . Oo0Ooo
 II1iII1i [ 0 ] = II1Ii1iI1i
 if 45 - 45: i1IIi - Oo0Ooo / O0 . I1ii11iIi11i
 II1iII1i [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 II1iII1i [ 2 ] = Oo0oO0oo0oO00
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 OOo = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 OOo . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 II1iII1i . append ( OOo )
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 if 66 - 66: Oo0Ooo
 oO0oIIII = lisp . lisp_open_listen_socket ( "0.0.0.0" ,
 str ( lisp . LISP_TRACE_PORT ) )
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  Ii1IIii11 = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 55 - 55: o0oOOo0O0Ooo . iII111i
  if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
 O00Iii1111III111 = os . getenv ( "LISP_PCAP_THREADS" )
 O00Iii1111III111 = 1 if ( O00Iii1111III111 == None ) else int ( O00Iii1111III111 )
 Ii1 = os . getenv ( "LISP_WORKER_THREADS" )
 Ii1 = 0 if ( Ii1 == None ) else int ( Ii1 )
 if 62 - 62: i1IIi - i1IIi
 if 69 - 69: OoOoOO00 % oO0o - I11i
 if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
 if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
 for OO00OO0o0 in range ( O00Iii1111III111 ) :
  oOOOooOo0O = lisp . lisp_thread ( "pcap-{}" . format ( OO00OO0o0 ) )
  oOOOooOo0O . thread_number = OO00OO0o0
  oOOOooOo0O . number_of_pcap_threads = O00Iii1111III111
  oOOOooOo0O . number_of_worker_threads = Ii1
  I11 . append ( oOOOooOo0O )
  threading . Thread ( target = OooOOo0 , args = [ oOOOooOo0O ] ) . start ( )
  if 43 - 43: o0oOOo0O0Ooo . iII111i . I11i + iIii1I11I1II1
  if 78 - 78: iIii1I11I1II1 % OoOoOO00 + I1ii11iIi11i / i1IIi % II111iiii + OOooOOo
  if 91 - 91: iIii1I11I1II1 % OoO0O00 . o0oOOo0O0Ooo + Ii1I + o0oOOo0O0Ooo
  if 95 - 95: Ii1I + I1ii11iIi11i * OOooOOo
  if 16 - 16: I11i / I1IiiI + OoO0O00 % iIii1I11I1II1 - i1IIi . oO0o
  if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 for OO00OO0o0 in range ( Ii1 ) :
  oOOOooOo0O = lisp . lisp_thread ( "worker-{}" . format ( OO00OO0o0 ) )
  I11 . append ( oOOOooOo0O )
  threading . Thread ( target = II1i1i1iII1 , args = [ oOOOooOo0O ] ) . start ( )
  if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
  if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
  if 84 - 84: i11iIiiIii * OoO0O00
  if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
  if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 lisp . lisp_load_checkpoint ( )
 if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 Oooo0000 = threading . Timer ( 60 , oO0oooooo , [ ] )
 Oooo0000 . start ( )
 return ( True )
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
def oo0ooooO ( ) :
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lisp-rtr" )
 lisp . lisp_close_socket ( II1Ii1iI1i , "" )
 lisp . lisp_close_socket ( oO0oIIII , "" )
 lisp . lisp_close_socket ( i111I , "lispers.net-itr" )
 OOo . close ( )
 return
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if 47 - 47: oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
def o0O0O0 ( kv_pair ) :
 global II1iII1i
 global iiI1iIiI
 if 55 - 55: O0 - I1Ii111
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 58 - 58: OoOoOO00 - iII111i - OoooooooOO
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , iiI1iIiI ] )
  lisp . lisp_test_mr_timer . start ( )
  if 96 - 96: iIii1I11I1II1
 return
 if 82 - 82: OoOoOO00 + O0 - IiII % oO0o * i11iIiiIii
 if 15 - 15: o0oOOo0O0Ooo
 if 39 - 39: OOooOOo / I1ii11iIi11i / I1IiiI * I1Ii111
 if 44 - 44: O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / O0 - I11i
 if 83 - 83: IiII * I11i / Oo0Ooo
 if 32 - 32: o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
 if 39 - 39: OoooooooOO * OOooOOo * O0 . I11i . OoO0O00 + ooOoO0o
 if 9 - 9: OoOoOO00 + oO0o % OoooooooOO + o0oOOo0O0Ooo
def ooOO0o ( kv_pair ) :
 global II1Ii1iI1i , OOo , iiI1iIiI
 if 51 - 51: Oo0Ooo - I1ii11iIi11i * I11i
 ii1111Ii1i = lisp . lisp_rloc_probing
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
 if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
 if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
 lispconfig . lisp_xtr_command ( kv_pair )
 if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if ( ii1111Ii1i == False and lisp . lisp_rloc_probing ) :
  i1IiiiI1iI = [ II1Ii1iI1i , II1Ii1iI1i ,
 None , OOo ]
  lisp . lisp_start_rloc_probe_timer ( 1 , i1IiiiI1iI )
  OOO0OOO00oo = { "type" : "itr-crypto-port" , "port" : iiI1iIiI }
  lisp . lisp_write_to_dp_socket ( OOO0OOO00oo )
  if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
  if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
  if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
  if 29 - 29: O0 . I1Ii111
  if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 70 - 70: I1Ii111 + oO0o
 if 93 - 93: I1Ii111 + Ii1I
 if 33 - 33: O0
 if 78 - 78: O0 / II111iiii * OoO0O00
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
o0oO0Oo = {
 "lisp xtr-parameters" : [ ooOO0o , {
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

 "lisp map-resolver" : [ o0O0O0 , {
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

 "lisp database-mapping" : [ i1iiI11I , {
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

 "lisp glean-mapping" : [ iIii11I , {
 "instance-id" : [ False ] ,
 "eid-prefix" : [ True ] ,
 "rloc-prefix" : [ True ] ,
 "rloc-probe" : [ True , "yes" , "no" ] } ] ,

 "show rtr-rloc-probing" : [ oOOo0 , { } ] ,
 "show rtr-keys" : [ II1i1Ii11Ii11 , { } ] ,
 "show rtr-map-cache" : [ I1Ii , { } ] ,
 "show rtr-map-cache-dns" : [ IIiiIiI1 , { } ]
 }
if 71 - 71: o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I % i11iIiiIii - ooOoO0o
if 82 - 82: I1Ii111 - OOooOOo + OoO0O00
if 64 - 64: o0oOOo0O0Ooo . O0 * Ii1I + OoooooooOO - Oo0Ooo . OoooooooOO
if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
if 55 - 55: iII111i - OoO0O00
if 100 - 100: O0
def o00 ( lisp_socket ) :
 if 46 - 46: iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OoOoOO00 - I1Ii111
 if 5 - 5: OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 if 11 - 11: i1IIi % OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 i1II1i , I1II1 , i1iIi , i1iI = lisp . lisp_receive ( lisp_socket , False )
 I1iIiiiI1 = lisp . lisp_trace ( )
 if ( I1iIiiiI1 . decode ( i1iI ) == False ) : return
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
 I1iIiiiI1 . rtr_cache_nat_trace ( I1II1 , i1iIi )
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
if ( iIIi1iiI1i11 ( ) == False ) :
 lisp . lprint ( "lisp_rtr_startup() failed" )
 lisp . lisp_print_banner ( "RTR abnormal exit" )
 exit ( 1 )
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
Oo00o0O0O = [ II1Ii1iI1i , Oo0oO0oo0oO00 ,
 i111I , oO0oIIII ]
o0ooO0OoOo = [ II1Ii1iI1i ] * 3
if 99 - 99: OoOoOO00
while ( True ) :
 try : oO00OoOo , OoO , i111i = select . select ( Oo00o0O0O , [ ] , [ ] )
 except : break
 if 46 - 46: OoO0O00 * Oo0Ooo % oO0o + O0 * IiII
 if 34 - 34: OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 if ( lisp . lisp_ipc_data_plane and i111I in oO00OoOo ) :
  lisp . lisp_process_punt ( i111I , II1iII1i ,
 iiI1iIiI )
  if 24 - 24: OoOoOO00
  if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
  if 28 - 28: I1IiiI
  if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
  if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if ( oO0oIIII in oO00OoOo ) :
  o00 ( oO0oIIII )
  if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
  if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
  if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
  if 79 - 79: OoOoOO00 / ooOoO0o
  if 77 - 77: Oo0Ooo
 if ( II1Ii1iI1i in oO00OoOo ) :
  i1II1i , I1II1 , i1iIi , i1iI = lisp . lisp_receive ( o0ooO0OoOo [ 0 ] ,
 False )
  if ( I1II1 == "" ) : break
  if ( lisp . lisp_is_rloc_probe_request ( i1iI [ 0 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
   continue
   if 46 - 46: I1Ii111
  if ( lisp . lisp_is_rloc_probe_reply ( i1iI [ 0 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
   continue
   if 72 - 72: iII111i * OOooOOo
  lisp . lisp_parse_packet ( o0ooO0OoOo , i1iI , I1II1 , i1iIi )
  if 67 - 67: i1IIi
  if 5 - 5: II111iiii . OoooooooOO
  if 57 - 57: I1IiiI
  if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
  if 50 - 50: OoOoOO00
  if 33 - 33: I11i
 if ( Oo0oO0oo0oO00 in oO00OoOo ) :
  i1II1i , I1II1 , i1iIi , i1iI = lisp . lisp_receive ( Oo0oO0oo0oO00 , True )
  if 98 - 98: OoOoOO00 % II111iiii
  if ( I1II1 == "" ) : break
  if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
  if ( i1II1i == "command" ) :
   if ( i1iI == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
   if ( i1iI . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( i1iI )
    continue
    if 68 - 68: o0oOOo0O0Ooo
   lispconfig . lisp_process_command ( Oo0oO0oo0oO00 , i1II1i ,
 i1iI , "lisp-rtr" , [ o0oO0Oo ] )
  elif ( i1II1i == "api" ) :
   lisp . lisp_process_api ( "lisp-rtr" , Oo0oO0oo0oO00 , i1iI )
  elif ( i1II1i == "data-packet" ) :
   I1111i ( i1iI , "" )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( i1iI [ 0 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
    continue
    if 20 - 20: I1Ii111 - I1Ii111
   if ( lisp . lisp_is_rloc_probe_reply ( i1iI [ 0 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
    continue
    if 37 - 37: IiII
   lisp . lisp_parse_packet ( II1iII1i , i1iI , I1II1 , i1iIi )
   if 37 - 37: Oo0Ooo / IiII * O0
   if 73 - 73: iII111i * iII111i / ooOoO0o
   if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
   if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
   if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
oo0ooooO ( )
lisp . lisp_print_banner ( "RTR normal exit" )
exit ( 0 )
if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
