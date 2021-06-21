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
from future import standard_library
standard_library . install_aliases ( )
from builtins import str
from builtins import range
import lisp
import lispconfig
import socket
import time
import select
import threading
import os
import copy
from subprocess import getoutput
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
if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
if 58 - 58: i11iIiiIii % I1Ii111
if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
iIiiI1 = None
if 68 - 68: I1IiiI - i11iIiiIii - OoO0O00 / OOooOOo - OoO0O00 + i1IIi
if 48 - 48: OoooooooOO % o0oOOo0O0Ooo . I1IiiI - Ii1I % i1IIi % OoooooooOO
if 3 - 3: iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
oo0Ooo0 = ( os . getenv ( "LISP_RTR_FAST_DATA_PLANE" ) != None )
I1I11I1I1I = ( os . getenv ( "LISP_RTR_LATENCY_DEBUG" ) != None )
OooO0OO = None
if 28 - 28: II111iiii
if 28 - 28: iIii1I11I1II1 - i1IIi
if 70 - 70: OoO0O00 . OoO0O00 - OoO0O00 / I1ii11iIi11i * OOooOOo
if 86 - 86: i11iIiiIii + Ii1I + ooOoO0o * I11i + o0oOOo0O0Ooo
if 61 - 61: OoO0O00 / i11iIiiIii
if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - I1ii11iIi11i + i11iIiiIii
if 65 - 65: OoOoOO00
if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
def oo ( parameter ) :
 global I11
 if 54 - 54: OOooOOo + OOooOOo % I1Ii111 % i11iIiiIii / iIii1I11I1II1 . OOooOOo
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "RTR" ,
 I11 ) )
 if 57 - 57: Ii1I % OoooooooOO
 if 61 - 61: iII111i . iIii1I11I1II1 * I1IiiI . ooOoO0o % Oo0Ooo
 if 72 - 72: OOooOOo
 if 63 - 63: Ii1I
 if 86 - 86: ooOoO0o . I1IiiI % Oo0Ooo + o0oOOo0O0Ooo
 if 35 - 35: iIii1I11I1II1 % oO0o * I11i % I11i + II111iiii * iII111i
 if 54 - 54: I11i + IiII / iII111i
def IIII ( parameter ) :
 global I11
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "RTR" , I11 ,
 True ) )
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
 if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo
 if 77 - 77: OoOoOO00 / I11i
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
 if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % oO0o . O0
def I1i1I ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "RTR" ) )
 if 80 - 80: OoOoOO00 - OoO0O00
 if 87 - 87: oO0o / I11i - i1IIi * OOooOOo / OoooooooOO . O0
 if 1 - 1: II111iiii - I11i / I11i
 if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
 if 83 - 83: OoooooooOO
 if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 if 4 - 4: II111iiii / ooOoO0o . iII111i
def O0oo0OO0oOOOo ( kv_pair ) :
 lispconfig . lisp_database_mapping_command ( kv_pair )
 if 35 - 35: IiII % I1IiiI
 if 70 - 70: iII111i * I1ii11iIi11i
 if 46 - 46: ooOoO0o / OoO0O00
 if 52 - 52: o0oOOo0O0Ooo - OoooooooOO + Ii1I + Ii1I - o0oOOo0O0Ooo / I1Ii111
 if 44 - 44: ooOoO0o . i1IIi - I1ii11iIi11i . O0 - ooOoO0o
 if 92 - 92: iII111i . I11i + o0oOOo0O0Ooo
 if 28 - 28: i1IIi * Oo0Ooo - o0oOOo0O0Ooo * IiII * Ii1I / OoO0O00
def OooO0OoOOOO ( kv_pair ) :
 i1Ii = { "rloc-probe" : False , "igmp-query" : False }
 if 78 - 78: I11i
 for OO00Oo in list ( kv_pair . keys ( ) ) :
  O0OOO0OOoO0O = kv_pair [ OO00Oo ]
  if 70 - 70: IiII * Oo0Ooo * I11i / Ii1I
  if ( OO00Oo == "instance-id" ) :
   oO = O0OOO0OOoO0O . split ( "-" )
   i1Ii [ "instance-id" ] = [ 0 , 0 ]
   if ( len ( oO ) == 1 ) :
    i1Ii [ "instance-id" ] [ 0 ] = int ( oO [ 0 ] )
    i1Ii [ "instance-id" ] [ 1 ] = int ( oO [ 0 ] )
   else :
    i1Ii [ "instance-id" ] [ 0 ] = int ( oO [ 0 ] )
    i1Ii [ "instance-id" ] [ 1 ] = int ( oO [ 1 ] )
    if 93 - 93: OoO0O00 % oO0o . OoO0O00 * I1Ii111 % Ii1I . II111iiii
    if 38 - 38: o0oOOo0O0Ooo
  if ( OO00Oo == "eid-prefix" ) :
   Oo0O = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   Oo0O . store_prefix ( O0OOO0OOoO0O )
   i1Ii [ "eid-prefix" ] = Oo0O
   if 25 - 25: OoOoOO00 . II111iiii / iII111i . OOooOOo * OoO0O00 . I1IiiI
  if ( OO00Oo == "group-prefix" ) :
   Oo0oOOo = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   Oo0oOOo . store_prefix ( O0OOO0OOoO0O )
   i1Ii [ "group-prefix" ] = Oo0oOOo
   if 58 - 58: II111iiii * OOooOOo * I1ii11iIi11i / OOooOOo
  if ( OO00Oo == "rloc-prefix" ) :
   oO0o0OOOO = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   oO0o0OOOO . store_prefix ( O0OOO0OOoO0O )
   i1Ii [ "rloc-prefix" ] = oO0o0OOOO
   if 68 - 68: iII111i - I1Ii111 - I1IiiI - I1ii11iIi11i + I11i
  if ( OO00Oo == "rloc-probe" ) :
   i1Ii [ "rloc-probe" ] = ( O0OOO0OOoO0O == "yes" )
   if 10 - 10: OoooooooOO % iIii1I11I1II1
  if ( OO00Oo == "igmp-query" ) :
   i1Ii [ "igmp-query" ] = ( O0OOO0OOoO0O == "yes" )
   if 54 - 54: I1Ii111 - II111iiii % OoOoOO00 % I11i % iIii1I11I1II1 + ooOoO0o
   if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
   if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
   if 92 - 92: iII111i . I1Ii111
   if 31 - 31: I1Ii111 . OoOoOO00 / O0
   if 89 - 89: OoOoOO00
 for OO0oOoOO0oOO0 in lisp . lisp_glean_mappings :
  if ( ( "eid-prefix" in OO0oOoOO0oOO0 ) ^ ( "eid-prefix" in i1Ii ) ) : continue
  if ( ( "eid-prefix" in OO0oOoOO0oOO0 ) and ( "eid-prefix" in i1Ii ) ) :
   oO0OOoo0OO = OO0oOoOO0oOO0 [ "eid-prefix" ]
   O0ii1ii1ii = i1Ii [ "eid-prefix" ]
   if ( oO0OOoo0OO . is_exact_match ( O0ii1ii1ii ) == False ) : continue
   if 91 - 91: IiII
   if 15 - 15: II111iiii
  if ( ( "group-prefix" in OO0oOoOO0oOO0 ) ^ ( "group-prefix" in i1Ii ) ) : continue
  if ( ( "group-prefix" in OO0oOoOO0oOO0 ) and ( "group-prefix" in i1Ii ) ) :
   oO0OOoo0OO = OO0oOoOO0oOO0 [ "group-prefix" ]
   O0ii1ii1ii = i1Ii [ "group-prefix" ]
   if ( oO0OOoo0OO . is_exact_match ( O0ii1ii1ii ) == False ) : continue
   if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
   if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
  if ( ( "rloc-prefix" in OO0oOoOO0oOO0 ) ^ ( "rloc-prefix" in i1Ii ) ) : continue
  if ( ( "rloc-prefix" in OO0oOoOO0oOO0 ) and ( "rloc-prefix" in i1Ii ) ) :
   oO0OOoo0OO = OO0oOoOO0oOO0 [ "rloc-prefix" ]
   O0ii1ii1ii = i1Ii [ "rloc-prefix" ]
   if ( oO0OOoo0OO . is_exact_match ( O0ii1ii1ii ) == False ) : continue
   if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
   if 91 - 91: O0
  if ( ( "instance-id" in OO0oOoOO0oOO0 ) ^ ( "instance-id" in i1Ii ) ) : continue
  if ( ( "instance-id" in OO0oOoOO0oOO0 ) and ( "instance-id" in i1Ii ) ) :
   oO0OOoo0OO = OO0oOoOO0oOO0 [ "instance-id" ]
   O0ii1ii1ii = i1Ii [ "instance-id" ]
   if ( oO0OOoo0OO != O0ii1ii1ii ) : continue
   if 61 - 61: II111iiii
   if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
   if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
   if 42 - 42: OoO0O00
   if 67 - 67: I1Ii111 . iII111i . O0
  return
  if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
  if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
  if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
  if 83 - 83: I11i / I1IiiI
  if 34 - 34: IiII
 lisp . lisp_glean_mappings . append ( i1Ii )
 if 57 - 57: oO0o . I11i . i1IIi
 if 42 - 42: I11i + I1ii11iIi11i % O0
 if 6 - 6: oO0o
 if 68 - 68: OoOoOO00 - OoO0O00
 if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
 if 1 - 1: iIii1I11I1II1 / II111iiii
 if 33 - 33: I11i
def iI11i1ii11 ( parameter ) :
 return ( lispconfig . lisp_itr_rtr_show_rloc_probe_command ( "RTR" ) )
 if 58 - 58: OoO0O00 % i11iIiiIii . iII111i / oO0o
 if 84 - 84: iII111i . I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
def ii ( mc , parms ) :
 oOooOOOoOo , oO0o0OOOO , i1Iii1i1I , OOoO00 = parms
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 OOOOOoo0 = "{}:{}" . format ( oO0o0OOOO . print_address_no_iid ( ) , i1Iii1i1I )
 Oo0O = lisp . green ( mc . print_eid_tuple ( ) , False )
 ii1 = "Changed '{}' translated address:port to {} for EID {}, {} {}" . format ( OOoO00 , lisp . red ( OOOOOoo0 , False ) , Oo0O , "{}" , "{}" )
 if 11 - 11: IiII * I1IiiI . iIii1I11I1II1 % OoooooooOO + iII111i
 if 78 - 78: OoO0O00 . OOooOOo + OoO0O00 / I11i / OoO0O00
 for oO0O00OoOO0 in mc . rloc_set :
  if ( oO0O00OoOO0 . rle ) :
   for OoO in oO0O00OoOO0 . rle . rle_nodes :
    if ( OoO . rloc_name != OOoO00 ) : continue
    OoO . store_translated_rloc ( oO0o0OOOO , i1Iii1i1I )
    O00 = OoO . address . print_address_no_iid ( ) + ":" + str ( OoO . translated_port )
    if 29 - 29: I1Ii111 / OoO0O00 . i1IIi * I1IiiI + i11iIiiIii
    lisp . lprint ( ii1 . format ( "RLE" , O00 ) )
    if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
    if 80 - 80: II111iiii
    if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
  if ( oO0O00OoOO0 . rloc_name != OOoO00 ) : continue
  if 53 - 53: II111iiii
  if 31 - 31: OoO0O00
  if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
  if 25 - 25: OoO0O00
  if 62 - 62: OOooOOo + O0
  if 98 - 98: o0oOOo0O0Ooo
  O00 = oO0O00OoOO0 . rloc . print_address_no_iid ( ) + ":" + str ( oO0O00OoOO0 . translated_port )
  if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
  if ( O00 in lisp . lisp_crypto_keys_by_rloc_encap ) :
   OoO0o = lisp . lisp_crypto_keys_by_rloc_encap [ O00 ]
   lisp . lisp_crypto_keys_by_rloc_encap [ OOOOOoo0 ] = OoO0o
   if 78 - 78: oO0o % O0 % Ii1I
   if 46 - 46: OoooooooOO . i11iIiiIii
   if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
   if 87 - 87: Oo0Ooo . IiII
   if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
  oO0O00OoOO0 . delete_from_rloc_probe_list ( mc . eid , mc . group )
  oO0O00OoOO0 . store_translated_rloc ( oO0o0OOOO , i1Iii1i1I )
  oO0O00OoOO0 . add_to_rloc_probe_list ( mc . eid , mc . group )
  lisp . lprint ( ii1 . format ( "RLOC" , O00 ) )
  if 55 - 55: OOooOOo . I1IiiI
  if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
  if 100 - 100: I1Ii111 * O0
  if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
  if ( lisp . lisp_rloc_probing ) :
   o0 = None if ( mc . group . is_null ( ) ) else mc . eid
   iI11I1II = mc . eid if ( mc . group . is_null ( ) ) else mc . group
   lisp . lisp_send_map_request ( oOooOOOoOo , 0 , o0 , iI11I1II , oO0O00OoOO0 )
   if 40 - 40: iIii1I11I1II1 / OoOoOO00 % I1ii11iIi11i + II111iiii
   if 27 - 27: II111iiii * OoOoOO00 * iIii1I11I1II1
   if 86 - 86: OoO0O00 * OOooOOo . iII111i
   if 32 - 32: o0oOOo0O0Ooo . IiII * I11i
   if 93 - 93: o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
   if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 lisp . lisp_write_ipc_map_cache ( True , mc )
 return ( True , parms )
 if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
def ii1111iII ( mc , parms ) :
 if 32 - 32: i1IIi / II111iiii . Oo0Ooo
 if 62 - 62: OoooooooOO * I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if ( mc . group . is_null ( ) ) : return ( ii ( mc , parms ) )
 if 97 - 97: O0 + OoOoOO00
 if ( mc . source_cache == None ) : return ( True , parms )
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 mc . source_cache . walk_cache ( ii , parms )
 return ( True , parms )
 if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
 if 71 - 71: Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
 if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
def OooOo0ooo ( sockets , hostname , rloc , port ) :
 lisp . lisp_map_cache . walk_cache ( ii1111iII ,
 [ sockets , rloc , port , hostname ] )
 return
 if 71 - 71: I1Ii111 + Ii1I
 if 28 - 28: OOooOOo
 if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
 if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
 if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
def I1II1 ( sred , packet ) :
 if ( lisp . lisp_data_plane_logging == False ) : return
 if 86 - 86: iIii1I11I1II1 / OoOoOO00 . II111iiii
 if ( sred in [ "Send" , "Receive" ] ) :
  II1i111Ii1i = binascii . hexlify ( packet [ 0 : 20 ] ) . decode ( )
  lisp . lprint ( "Fast-{}: ip {} {} {} {} {}" . format ( sred , II1i111Ii1i [ 0 : 8 ] , II1i111Ii1i [ 8 : 16 ] ,
 II1i111Ii1i [ 16 : 24 ] , II1i111Ii1i [ 24 : 32 ] , II1i111Ii1i [ 32 : 40 ] ) )
 elif ( sred in [ "Encap" , "Decap" ] ) :
  II1i111Ii1i = binascii . hexlify ( packet [ 0 : 36 ] ) . decode ( )
  lisp . lprint ( "Fast-{}: ip {} {} {} {} {}, udp {} {}, lisp {} {}" . format ( sred , II1i111Ii1i [ 0 : 8 ] , II1i111Ii1i [ 8 : 16 ] , II1i111Ii1i [ 16 : 24 ] , II1i111Ii1i [ 24 : 32 ] , II1i111Ii1i [ 32 : 40 ] ,
  # I1IiiI
 II1i111Ii1i [ 40 : 48 ] , II1i111Ii1i [ 48 : 56 ] , II1i111Ii1i [ 56 : 64 ] , II1i111Ii1i [ 64 : 72 ] ) )
  if 25 - 25: Ii1I / ooOoO0o
  if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
  if 71 - 71: I1Ii111 . II111iiii
  if 62 - 62: OoooooooOO . I11i
  if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
  if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 58 - 58: I1IiiI
  if 53 - 53: i1IIi
def o0OOOoO0 ( dest , mc ) :
 if ( lisp . lisp_data_plane_logging == False ) : return
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 Ii1iI111II1I1 = "miss" if mc == None else "hit!"
 lisp . lprint ( "Fast-Lookup {} {}" . format ( dest . print_address ( ) , Ii1iI111II1I1 ) )
 if 91 - 91: OOooOOo % OOooOOo - I1IiiI
 if 18 - 18: I11i - i11iIiiIii / II111iiii . OOooOOo
 if 55 - 55: i1IIi % II111iiii + I11i * iIii1I11I1II1
 if 81 - 81: IiII % i1IIi . iIii1I11I1II1
 if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
 if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
 if 31 - 31: OOooOOo
 if 23 - 23: I1Ii111 . IiII
def OO0000o ( ts , msg ) :
 global I1I11I1I1I
 if 42 - 42: Oo0Ooo
 if ( I1I11I1I1I == False ) : return ( None )
 if 76 - 76: I1IiiI * iII111i % I1Ii111
 if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
 if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
 if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
 if ( ts == None ) : return ( time . time ( ) )
 if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
 if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
 if 42 - 42: I1IiiI
 if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
 ts = ( time . time ( ) - ts ) * 1000000
 lisp . lprint ( "{}-Latency: {} usecs" . format ( msg , round ( ts , 1 ) ) , "force" )
 return ( None )
 if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
 if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
 if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
 if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
 if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
 if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
 if 79 - 79: O0 * i11iIiiIii - IiII / IiII
 if 48 - 48: O0
def Oo0o0O00 ( a ) :
 ii1I1i11 = ord ( a [ 0 : 1 ] ) << 24 | ord ( a [ 1 : 2 ] ) << 16 | ord ( a [ 2 : 3 ] ) << 8 | ord ( a [ 3 : 4 ] )
 if 51 - 51: OoO0O00 . I1IiiI * ooOoO0o % Ii1I + II111iiii . ooOoO0o
 return ( ii1I1i11 )
 if 50 - 50: OoO0O00 * OOooOOo % O0
 if 62 - 62: O0 % I11i . I11i - iIii1I11I1II1 / i11iIiiIii
 if 31 - 31: iIii1I11I1II1 / OoO0O00 / I1ii11iIi11i
 if 41 - 41: Oo0Ooo
 if 10 - 10: Oo0Ooo / Oo0Ooo / I1Ii111 . I1Ii111
 if 98 - 98: Oo0Ooo / I1IiiI . O0 + OoO0O00
 if 43 - 43: II111iiii . oO0o / I1ii11iIi11i
 if 20 - 20: I1IiiI
def o0oO000oo ( byte ) :
 return ( chr ( byte ) )
 if 95 - 95: ooOoO0o / ooOoO0o
def IIiI1Ii ( byte ) :
 return ( bytes ( [ byte ] ) )
 if 57 - 57: OOooOOo - ooOoO0o - I11i + OoO0O00
 if 30 - 30: Ii1I % OoOoOO00 + i1IIi - I11i - Ii1I
 if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
 if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
 if 44 - 44: II111iiii
 if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
 if 35 - 35: iIii1I11I1II1
 if 42 - 42: I1Ii111 . I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI
 if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
 if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
 if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
 if 71 - 71: O0 - iIii1I11I1II1
 if 12 - 12: OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 if 46 - 46: Oo0Ooo
 if 1 - 1: iII111i
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
oOoO0 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
Oo0 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
if 83 - 83: i11iIiiIii % o0oOOo0O0Ooo % ooOoO0o
def Ii1II1I11i1 ( packet ) :
 global lisp_map_cache , OOo
 if 59 - 59: oO0o % iIii1I11I1II1 . i1IIi
 iiIi1i = OO0000o ( None , "Fast" )
 if 27 - 27: OOooOOo * ooOoO0o . I1Ii111 % IiII * IiII . i1IIi
 if 72 - 72: OOooOOo % I1ii11iIi11i + OoO0O00 / oO0o + IiII
 if 10 - 10: I1Ii111 / ooOoO0o + i11iIiiIii / Ii1I
 if 74 - 74: OOooOOo + O0 + i1IIi - i1IIi + II111iiii
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 iIi1Ii1i1iI = 0
 IIiI1 = None
 if ( packet [ 9 : 10 ] == b'\x11' ) :
  if ( packet [ 20 : 22 ] == b'\x10\xf6' ) : return ( False )
  if ( packet [ 22 : 24 ] == b'\x10\xf6' ) : return ( False )
  if 17 - 17: OOooOOo / OOooOOo / I11i
  if ( packet [ 20 : 22 ] == b'\x10\xf5' or packet [ 22 : 24 ] == b'\x10\xf5' ) :
   IIiI1 = packet [ 12 : 16 ]
   iIi1Ii1i1iI = packet [ 32 : 35 ]
   iIi1Ii1i1iI = ord ( iIi1Ii1i1iI [ 0 : 1 ] ) << 16 | ord ( iIi1Ii1i1iI [ 1 : 2 ] ) << 8 | ord ( iIi1Ii1i1iI [ 2 : 3 ] )
   if ( iIi1Ii1i1iI == 0xffffff ) : return ( False )
   I1II1 ( "Decap" , packet )
   packet = packet [ 36 : : ]
   if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
   if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
   if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 I1II1 ( "Receive" , packet )
 if 9 - 9: Ii1I
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 Oo0OO0000oooo = Oo0o0O00 ( packet [ 16 : 20 ] )
 Oo0 . instance_id = iIi1Ii1i1iI
 Oo0 . address = Oo0OO0000oooo
 if 7 - 7: oO0o - OoO0O00 - O0 % oO0o - II111iiii
 if 31 - 31: iII111i / Oo0Ooo - iII111i - OOooOOo
 if 7 - 7: iII111i % O0 . OoOoOO00 + I1IiiI - I11i
 if 75 - 75: I11i
 if ( ( Oo0OO0000oooo & 0xf0000000 ) == 0xe0000000 ) : return ( False )
 if 71 - 71: ooOoO0o
 if 53 - 53: OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if 28 - 28: I11i
 if 58 - 58: OoOoOO00
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 if ( packet [ 9 : 10 ] == b'\x11' ) :
  if ( packet [ 20 : 22 ] == b'\x09\x82' ) : return ( False )
  if ( packet [ 22 : 24 ] == b'\x09\x82' ) : return ( False )
  if 73 - 73: i11iIiiIii - IiII
  if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
  if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
  if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
  if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 Oo0OO0000oooo = Oo0
 OoOo = lisp . lisp_map_cache . lookup_cache ( Oo0OO0000oooo , False )
 o0OOOoO0 ( Oo0OO0000oooo , OoOo )
 if ( OoOo == None ) : return ( False )
 if 35 - 35: ooOoO0o * OOooOOo . I11i * o0oOOo0O0Ooo . OoOoOO00 / O0
 if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo % O0 * O0
 if 14 - 14: I1ii11iIi11i . ooOoO0o + II111iiii / iII111i / I11i
 if 74 - 74: O0 / i1IIi
 if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
 if ( IIiI1 != None ) :
  ii1O0 = Oo0o0O00 ( packet [ 12 : 16 ] )
  oOoO0 . instance_id = iIi1Ii1i1iI
  oOoO0 . address = ii1O0
  iII1 = lisp . lisp_map_cache . lookup_cache ( oOoO0 , False )
  if ( iII1 == None ) :
   II , II1i , Ii1IIIIi1ii1I = lisp . lisp_allow_gleaning ( oOoO0 , None ,
 None )
   if ( II ) : return ( False )
  elif ( iII1 . gleaned ) :
   IIiI1 = Oo0o0O00 ( IIiI1 )
   if ( iII1 . rloc_set [ 0 ] . rloc . address != IIiI1 ) : return ( False )
   if 13 - 13: I1IiiI % OoOoOO00 . I1ii11iIi11i / Oo0Ooo % OOooOOo . OoooooooOO
   if 22 - 22: IiII / i11iIiiIii
   if 62 - 62: OoO0O00 / I1ii11iIi11i
   if 7 - 7: OoooooooOO . IiII
   if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
  OoOo . add_recent_source ( oOoO0 )
  if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
  if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
  if 92 - 92: ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if ( OoOo . action == lisp . LISP_NATIVE_FORWARD_ACTION and
 OoOo . eid . instance_id == 0 ) :
  Oo0OO0000oooo . instance_id = lisp . lisp_default_secondary_iid
  OoOo = lisp . lisp_map_cache . lookup_cache ( Oo0OO0000oooo , False )
  o0OOOoO0 ( Oo0OO0000oooo , OoOo )
  if ( OoOo == None ) : return ( False )
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  if 92 - 92: I11i . I1Ii111
  if 85 - 85: I1ii11iIi11i . I1Ii111
  if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
  if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
  if 18 - 18: iIii1I11I1II1 % I11i
 if ( OoOo . action != lisp . LISP_NATIVE_FORWARD_ACTION ) :
  if ( OoOo . best_rloc_set == [ ] ) : return ( False )
  if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
  Oo0OO0000oooo = OoOo . best_rloc_set [ 0 ]
  if ( Oo0OO0000oooo . state != lisp . LISP_RLOC_UP_STATE ) : return ( False )
  if 75 - 75: OoooooooOO * IiII
  iIi1Ii1i1iI = OoOo . eid . instance_id
  i1Iii1i1I = Oo0OO0000oooo . translated_port
  I1Iiiiiii = Oo0OO0000oooo . stats
  Oo0OO0000oooo = Oo0OO0000oooo . rloc
  I1IIIiI1I1ii1 = Oo0OO0000oooo . address
  IIiI1 = lisp . lisp_myrlocs [ 0 ] . address
  if 30 - 30: O0 * OoooooooOO
  if 38 - 38: IiII - I1ii11iIi11i . OoOoOO00 - I1Ii111 . OoooooooOO
  if 89 - 89: iIii1I11I1II1
  if 21 - 21: I11i % I11i
  iiI1 = b'\x45\x00'
  iiIIiii = len ( packet ) + 20 + 8 + 8
  iiI1 += OooO0OO ( ( iiIIiii >> 8 ) & 0xff )
  iiI1 += OooO0OO ( iiIIiii & 0xff )
  iiI1 += b'\xff\xff\x40\x00\x10\x11\x00\x00'
  iiI1 += OooO0OO ( ( IIiI1 >> 24 ) & 0xff )
  iiI1 += OooO0OO ( ( IIiI1 >> 16 ) & 0xff )
  iiI1 += OooO0OO ( ( IIiI1 >> 8 ) & 0xff )
  iiI1 += OooO0OO ( IIiI1 & 0xff )
  iiI1 += OooO0OO ( ( I1IIIiI1I1ii1 >> 24 ) & 0xff )
  iiI1 += OooO0OO ( ( I1IIIiI1I1ii1 >> 16 ) & 0xff )
  iiI1 += OooO0OO ( ( I1IIIiI1I1ii1 >> 8 ) & 0xff )
  iiI1 += OooO0OO ( I1IIIiI1I1ii1 & 0xff )
  iiI1 = lisp . lisp_ip_checksum ( iiI1 )
  if 30 - 30: iII111i
  if 31 - 31: OOooOOo + o0oOOo0O0Ooo . OoooooooOO
  if 89 - 89: II111iiii + i1IIi + II111iiii
  if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
  II1Ii11I111I = iiIIiii - 20
  I111 = b'\xff\x00' if ( i1Iii1i1I == 4341 ) else b'\x10\xf5'
  I111 += OooO0OO ( ( i1Iii1i1I >> 8 ) & 0xff )
  I111 += OooO0OO ( i1Iii1i1I & 0xff )
  I111 += OooO0OO ( ( II1Ii11I111I >> 8 ) & 0xff )
  I111 += OooO0OO ( II1Ii11I111I & 0xff )
  I111 += b'\x00'
  I111 += b'\x00'
  if 13 - 13: OoO0O00 * oO0o * iII111i
  I111 += b'\x08\xdf\xdf\xdf'
  I111 += OooO0OO ( ( iIi1Ii1i1iI >> 16 ) & 0xff )
  I111 += OooO0OO ( ( iIi1Ii1i1iI >> 8 ) & 0xff )
  I111 += OooO0OO ( iIi1Ii1i1iI & 0xff )
  I111 += b'\x00'
  if 26 - 26: O0 * Oo0Ooo + II111iiii / IiII + oO0o % o0oOOo0O0Ooo
  if 42 - 42: I1ii11iIi11i . I1Ii111 % I1Ii111
  if 57 - 57: II111iiii
  if 54 - 54: Oo0Ooo + oO0o + i11iIiiIii
  packet = iiI1 + I111 + packet
  I1II1 ( "Encap" , packet )
 else :
  iiIIiii = len ( packet )
  I1Iiiiiii = OoOo . stats
  I1II1 ( "Send" , packet )
  if 28 - 28: oO0o
  if 70 - 70: IiII
  if 34 - 34: I1Ii111 % IiII
  if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
  if 83 - 83: oO0o + OoooooooOO
 OoOo . last_refresh_time = time . time ( )
 I1Iiiiiii . increment ( iiIIiii )
 if 22 - 22: Ii1I % iII111i * OoooooooOO - o0oOOo0O0Ooo / iIii1I11I1II1
 if 86 - 86: OoooooooOO . iII111i % OoOoOO00 / I11i * iII111i / o0oOOo0O0Ooo
 if 64 - 64: i11iIiiIii
 if 38 - 38: IiII / I1IiiI - IiII . I11i
 Oo0OO0000oooo = Oo0OO0000oooo . print_address_no_iid ( )
 OOo . sendto ( packet , ( Oo0OO0000oooo , 0 ) )
 if 69 - 69: OoooooooOO + I1ii11iIi11i
 OO0000o ( iiIi1i , "Fast" )
 return ( True )
 if 97 - 97: OOooOOo - OoO0O00 / Ii1I . i11iIiiIii % oO0o * oO0o
 if 1 - 1: I1IiiI % ooOoO0o
 if 65 - 65: I1IiiI + OoOoOO00 / OOooOOo
 if 83 - 83: o0oOOo0O0Ooo . iII111i - Oo0Ooo
 if 65 - 65: iIii1I11I1II1 / ooOoO0o . IiII - II111iiii
 if 72 - 72: iIii1I11I1II1 / IiII % iII111i % OOooOOo - I11i % OOooOOo
 if 100 - 100: Oo0Ooo + i11iIiiIii
 if 71 - 71: I11i / o0oOOo0O0Ooo / I1Ii111 % OOooOOo
def O0oooo00o0Oo ( lisp_packet , thread_name ) :
 global II1iII1i , I1iii , oO0o0O0Ooo0o
 global OOo , Ii1IIii11
 global oO0oIIII
 global iIiiI1
 global oo0Ooo0
 if 21 - 21: I1Ii111 - I1IiiI + I11i
 iiIi1i = OO0000o ( None , "RTR" )
 if 78 - 78: OoooooooOO - i11iIiiIii - II111iiii
 if 77 - 77: OoOoOO00 % Ii1I
 if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
 if ( oo0Ooo0 ) :
  if ( Ii1II1I11i1 ( lisp_packet . packet ) ) : return
  if 63 - 63: I1IiiI % iIii1I11I1II1
  if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
  if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
  if 59 - 59: OOooOOo + i11iIiiIii
  if 88 - 88: i11iIiiIii - ooOoO0o
 O0iIi1IiII = lisp_packet
 I1i = O0iIi1IiII . is_lisp_packet ( O0iIi1IiII . packet )
 if 72 - 72: iIii1I11I1II1
 if 11 - 11: II111iiii / o0oOOo0O0Ooo
 if 21 - 21: i11iIiiIii / i1IIi + I1IiiI * OOooOOo . I1Ii111
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 if ( I1i == False ) :
  iii1 = O0iIi1IiII . packet
  I1iOOOO , ooO0oO00O0o , i1Iii1i1I , ooOO00oOOo000 = lisp . lisp_is_rloc_probe ( iii1 , - 1 )
  if ( iii1 != I1iOOOO ) :
   if ( ooO0oO00O0o == None ) : return
   lisp . lisp_parse_packet ( II1iII1i , I1iOOOO , ooO0oO00O0o , i1Iii1i1I , ooOO00oOOo000 )
   return
   if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
   if 67 - 67: I11i - OOooOOo . i1IIi
   if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
   if 87 - 87: OoOoOO00
   if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
   if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
 O0iIi1IiII . packet = lisp . lisp_reassemble ( O0iIi1IiII . packet )
 if ( O0iIi1IiII . packet == None ) : return
 if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
 if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
 if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
 if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
 if 93 - 93: Ii1I - OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
 if ( lisp . lisp_flow_logging ) : O0iIi1IiII = copy . deepcopy ( O0iIi1IiII )
 if 49 - 49: OoooooooOO * I11i - Oo0Ooo . oO0o
 if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
 if 46 - 46: OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if ( I1i ) :
  if ( O0iIi1IiII . decode ( True , None , lisp . lisp_decap_stats ) == None ) : return
  O0iIi1IiII . print_packet ( "Receive-({})" . format ( thread_name ) , True )
  O0iIi1IiII . strip_outer_headers ( )
 else :
  if ( O0iIi1IiII . decode ( False , None , None ) == None ) : return
  O0iIi1IiII . print_packet ( "Receive-({})" . format ( thread_name ) , False )
  if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
  if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
  if 2 - 2: Ii1I - IiII
  if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
  if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
  if 71 - 71: OoooooooOO
  if 33 - 33: I1Ii111
  if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
  if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
  if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
  if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
  if 45 - 45: IiII
 if ( I1i and O0iIi1IiII . lisp_header . get_instance_id ( ) == 0xffffff ) :
  Ii1Iii111IiI1 = lisp . lisp_control_header ( )
  Ii1Iii111IiI1 . decode ( O0iIi1IiII . packet )
  if ( Ii1Iii111IiI1 . is_info_request ( ) ) :
   O00oOooo0 = lisp . lisp_info ( )
   O00oOooo0 . decode ( O0iIi1IiII . packet )
   O00oOooo0 . print_info ( )
   if 56 - 56: II111iiii / oO0o + i11iIiiIii + OOooOOo
   if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
   if 79 - 79: Ii1I . OoO0O00
   if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
   if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
   Oo00OOOOoo0oo = O00oOooo0 . hostname if ( O00oOooo0 . hostname != None ) else ""
   O00OOooo0Ooo = O0iIi1IiII . outer_source
   II1i111Ii1i = O0iIi1IiII . udp_sport
   if ( lisp . lisp_store_nat_info ( Oo00OOOOoo0oo , O00OOooo0Ooo , II1i111Ii1i ) ) :
    OooOo0ooo ( II1iII1i , Oo00OOOOoo0oo , O00OOooo0Ooo , II1i111Ii1i )
    if 66 - 66: oO0o
  else :
   ooO0oO00O0o = O0iIi1IiII . outer_source . print_address_no_iid ( )
   ooOO00oOOo000 = O0iIi1IiII . outer_ttl
   O0iIi1IiII = O0iIi1IiII . packet
   if ( lisp . lisp_is_rloc_probe_request ( O0iIi1IiII [ 28 : 29 ] ) == False and
 lisp . lisp_is_rloc_probe_reply ( O0iIi1IiII [ 28 : 29 ] ) == False ) :
    ooOO00oOOo000 = - 1
    if 91 - 91: oO0o + I1IiiI
   O0iIi1IiII = O0iIi1IiII [ 28 : : ]
   lisp . lisp_parse_packet ( II1iII1i , O0iIi1IiII , ooO0oO00O0o , 0 , ooOO00oOOo000 )
   if 59 - 59: I1IiiI + i11iIiiIii + i1IIi / I11i
  return
  if 44 - 44: I11i . OoOoOO00 * I1IiiI + OoooooooOO - iII111i - IiII
  if 15 - 15: IiII / O0 . o0oOOo0O0Ooo . i11iIiiIii
  if 59 - 59: I1Ii111 - o0oOOo0O0Ooo - ooOoO0o
  if 48 - 48: i1IIi + I11i % OoOoOO00 / Oo0Ooo - o0oOOo0O0Ooo
  if 67 - 67: oO0o % o0oOOo0O0Ooo . OoooooooOO + OOooOOo * I11i * OoOoOO00
  if 36 - 36: O0 + Oo0Ooo
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 5 - 5: Oo0Ooo * OoOoOO00
  if 46 - 46: ooOoO0o
  if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
  if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
  if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if ( I1i ) :
  lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( O0iIi1IiII . packet ) )
  if 72 - 72: i1IIi
  if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
  if 63 - 63: I1ii11iIi11i
  if 6 - 6: ooOoO0o / I1ii11iIi11i
  if 57 - 57: I11i
 oO0 = False
 if ( O0iIi1IiII . inner_dest . is_mac ( ) ) :
  O0iIi1IiII . packet = lisp . lisp_mac_input ( O0iIi1IiII . packet )
  if ( O0iIi1IiII . packet == None ) : return
  O0iIi1IiII . encap_port = lisp . LISP_VXLAN_DATA_PORT
 elif ( O0iIi1IiII . inner_version == 4 ) :
  oO0 , O0iIi1IiII . packet = lisp . lisp_ipv4_input ( O0iIi1IiII . packet )
  if ( O0iIi1IiII . packet == None ) : return
  O0iIi1IiII . inner_ttl = O0iIi1IiII . outer_ttl
 elif ( O0iIi1IiII . inner_version == 6 ) :
  O0iIi1IiII . packet = lisp . lisp_ipv6_input ( O0iIi1IiII )
  if ( O0iIi1IiII . packet == None ) : return
  O0iIi1IiII . inner_ttl = O0iIi1IiII . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 87 - 87: oO0o % Ii1I
  if 83 - 83: II111iiii - I11i
  if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
  if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
  if 51 - 51: OoOoOO00
 if ( O0iIi1IiII . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( O0iIi1IiII , ed = "decap" ) == False ) : return
  O0iIi1IiII . outer_source . afi = lisp . LISP_AFI_NONE
  O0iIi1IiII . outer_dest . afi = lisp . LISP_AFI_NONE
  if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
  if 53 - 53: Ii1I % Oo0Ooo
  if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
  if 41 - 41: Ii1I % I1ii11iIi11i
  if 12 - 12: OOooOOo
  if 69 - 69: OoooooooOO + OOooOOo
 II , II1i , Ii1IIIIi1ii1I = lisp . lisp_allow_gleaning ( O0iIi1IiII . inner_source , None ,
 O0iIi1IiII . outer_source )
 if ( II ) :
  IIi11I1 = O0iIi1IiII . packet if ( oO0 ) else None
  lisp . lisp_glean_map_cache ( O0iIi1IiII . inner_source , O0iIi1IiII . outer_source ,
 O0iIi1IiII . udp_sport , IIi11I1 )
  if ( oO0 ) : return
  if 49 - 49: II111iiii - I1IiiI / I11i
  if 74 - 74: I11i - OOooOOo + i1IIi . I1IiiI + OOooOOo - I11i
  if 17 - 17: O0 . I1Ii111 . O0 + O0 / Oo0Ooo . ooOoO0o
  if 62 - 62: I1ii11iIi11i % iII111i * OoO0O00 - i1IIi
  if 66 - 66: i11iIiiIii / o0oOOo0O0Ooo - OoooooooOO / i1IIi . i11iIiiIii
  if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
 iI11I1II = O0iIi1IiII . inner_dest
 if ( iI11I1II . is_multicast_address ( ) ) :
  if ( iI11I1II . is_link_local_multicast ( ) ) :
   IIi1I = lisp . green ( iI11I1II . print_address ( ) , False )
   lisp . dprint ( "Drop link-local multicast EID {}" . format ( IIi1I ) )
   return
   if 27 - 27: O0 . I1Ii111 / iII111i
  OO00O000OOO = False
  II1i , Ii1IIIIi1ii1I , iI = lisp . lisp_allow_gleaning ( O0iIi1IiII . inner_source , iI11I1II , None )
 else :
  OO00O000OOO , II1i , Ii1IIIIi1ii1I = lisp . lisp_allow_gleaning ( iI11I1II , None , None )
  if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 O0iIi1IiII . gleaned_dest = OO00O000OOO
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 OoOo = lisp . lisp_map_cache_lookup ( O0iIi1IiII . inner_source , O0iIi1IiII . inner_dest )
 if ( OoOo ) : OoOo . add_recent_source ( O0iIi1IiII . inner_source )
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if ( OoOo and ( OoOo . action == lisp . LISP_NATIVE_FORWARD_ACTION or
 OoOo . eid . address == 0 ) ) :
  iIi = lisp . lisp_db_for_lookups . lookup_cache ( O0iIi1IiII . inner_source , False )
  if ( iIi and iIi . secondary_iid ) :
   iIIi = O0iIi1IiII . inner_dest
   iIIi . instance_id = iIi . secondary_iid
   if 96 - 96: iII111i
   OoOo = lisp . lisp_map_cache_lookup ( O0iIi1IiII . inner_source , iIIi )
   if ( OoOo ) :
    O0iIi1IiII . gleaned_dest = OoOo . gleaned
    OoOo . add_recent_source ( O0iIi1IiII . inner_source )
   else :
    OO00O000OOO , II1i , Ii1IIIIi1ii1I = lisp . lisp_allow_gleaning ( iIIi , None ,
 None )
    O0iIi1IiII . gleaned_dest = OO00O000OOO
    if 18 - 18: iII111i * I11i - Ii1I
    if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
    if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
    if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
    if 39 - 39: iIii1I11I1II1 - OoooooooOO
    if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
    if 23 - 23: II111iiii / oO0o
    if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
    if 19 - 19: I11i
 if ( OoOo == None and OO00O000OOO ) :
  lisp . lprint ( "Suppress Map-Request for gleaned EID {}" . format ( lisp . green ( O0iIi1IiII . inner_dest . print_address ( ) , False ) ) )
  if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
  return
  if 27 - 27: OOooOOo
  if 89 - 89: II111iiii / oO0o
 if ( OoOo == None or lisp . lisp_mr_or_pubsub ( OoOo . action ) ) :
  if ( lisp . lisp_rate_limit_map_request ( O0iIi1IiII . inner_dest ) ) : return
  if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
  IIIIIiII1 = ( OoOo and OoOo . action == lisp . LISP_SEND_PUBSUB_ACTION )
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 O0iIi1IiII . inner_source , O0iIi1IiII . inner_dest , None , IIIIIiII1 )
  if 45 - 45: I1IiiI / iII111i . iII111i
  if ( O0iIi1IiII . is_trace ( ) ) :
   O00OOooo0Ooo = oO0oIIII
   i1 = "map-cache miss"
   lisp . lisp_trace_append ( O0iIi1IiII , reason = i1 , lisp_socket = O00OOooo0Ooo )
   if 95 - 95: OoO0O00 . i1IIi / i11iIiiIii
  return
  if 38 - 38: Oo0Ooo - I11i . Oo0Ooo
  if 38 - 38: i1IIi + Ii1I
  if 91 - 91: II111iiii % iII111i % IiII + II111iiii / oO0o
  if 62 - 62: OoooooooOO - i11iIiiIii
  if 5 - 5: iIii1I11I1II1 / I11i / i1IIi % OoooooooOO
  if 50 - 50: Ii1I / OoOoOO00 * Ii1I
 if ( OoOo and OoOo . refresh ( ) ) :
  if ( lisp . lisp_rate_limit_map_request ( O0iIi1IiII . inner_dest ) == False ) :
   lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( OoOo . print_eid_tuple ( ) , False ) ) )
   if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
   lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 O0iIi1IiII . inner_source , O0iIi1IiII . inner_dest , None )
   if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
   if 32 - 32: i11iIiiIii - I1Ii111
   if 53 - 53: OoooooooOO - IiII
   if 87 - 87: oO0o . I1IiiI
   if 17 - 17: Ii1I . i11iIiiIii
   if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
   if 63 - 63: oO0o
 OoOo . last_refresh_time = time . time ( )
 OoOo . stats . increment ( len ( O0iIi1IiII . packet ) )
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 iiIiI , i1oOOOOOOOoO , I1 , IIiI , O0oOOo0o , oO0O00OoOO0 = OoOo . select_rloc ( O0iIi1IiII , None )
 if 50 - 50: iII111i . I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if ( iiIiI == None and O0oOOo0o == None ) :
  if ( IIiI == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   O0iIi1IiII . send_packet ( OOo , O0iIi1IiII . inner_dest )
   if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
   if ( O0iIi1IiII . is_trace ( ) ) :
    O00OOooo0Ooo = oO0oIIII
    i1 = "not an EID"
    lisp . lisp_trace_append ( O0iIi1IiII , reason = i1 , lisp_socket = O00OOooo0Ooo )
    if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
   OO0000o ( iiIi1i , "RTR" )
   return
   if 34 - 34: ooOoO0o
  i1 = "No reachable RLOCs found"
  lisp . dprint ( i1 )
  if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
  if ( O0iIi1IiII . is_trace ( ) ) :
   O00OOooo0Ooo = oO0oIIII
   lisp . lisp_trace_append ( O0iIi1IiII , reason = i1 , lisp_socket = O00OOooo0Ooo )
   if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
  return
  if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if ( iiIiI and iiIiI . is_null ( ) ) :
  lisp . dprint ( "Drop action RLOC found" )
  if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
  if ( O0iIi1IiII . is_trace ( ) ) :
   O00OOooo0Ooo = oO0oIIII
   i1 = "drop action"
   lisp . lisp_trace_append ( O0iIi1IiII , reason = i1 , lisp_socket = O00OOooo0Ooo )
   if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
  return
  if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
  if 87 - 87: oO0o - i11iIiiIii
  if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
  if 23 - 23: I11i
  if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 O0iIi1IiII . outer_tos = O0iIi1IiII . inner_tos
 O0iIi1IiII . outer_ttl = O0iIi1IiII . inner_ttl
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if ( iiIiI ) :
  O0iIi1IiII . encap_port = i1oOOOOOOOoO
  if ( i1oOOOOOOOoO == 0 ) : O0iIi1IiII . encap_port = lisp . LISP_DATA_PORT
  O0iIi1IiII . outer_dest . copy_address ( iiIiI )
  I1Iii1iI1 = O0iIi1IiII . outer_dest . afi_to_version ( )
  O0iIi1IiII . outer_version = I1Iii1iI1
  if 86 - 86: O0
  O0o0oOooOoOo = iIiiI1 if ( I1Iii1iI1 == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 49 - 49: OOooOOo . I1ii11iIi11i . i11iIiiIii - II111iiii / Ii1I
  O0iIi1IiII . outer_source . copy_address ( O0o0oOooOoOo )
  if 62 - 62: OOooOOo
  if ( O0iIi1IiII . is_trace ( ) ) :
   O00OOooo0Ooo = oO0oIIII
   if ( lisp . lisp_trace_append ( O0iIi1IiII , rloc_entry = oO0O00OoOO0 ,
 lisp_socket = O00OOooo0Ooo ) == False ) : return
   if 1 - 1: IiII / IiII - i11iIiiIii
   if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
   if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
   if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
   if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
  if ( O0iIi1IiII . encode ( I1 ) == None ) : return
  if ( len ( O0iIi1IiII . packet ) <= 1500 ) : O0iIi1IiII . print_packet ( "Send" , True )
  if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
  if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
  if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
  if 77 - 77: OoO0O00 + I1Ii111 + I1Ii111 * Ii1I / OoooooooOO . Ii1I
  ooo0O0OO = Ii1IIii11 if I1Iii1iI1 == 6 else OOo
  O0iIi1IiII . send_packet ( ooo0O0OO , O0iIi1IiII . outer_dest )
  if 61 - 61: IiII + iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % II111iiii
 elif ( O0oOOo0o ) :
  if 42 - 42: Ii1I * I1Ii111 . IiII * I1IiiI + OoOoOO00
  if 25 - 25: I11i . I1IiiI + oO0o
  if 75 - 75: IiII - o0oOOo0O0Ooo % iII111i + i11iIiiIii
  if 100 - 100: I11i + o0oOOo0O0Ooo - i11iIiiIii - II111iiii
  iIIIiIi1I1i = len ( O0iIi1IiII . packet )
  for OoOOoO0oOo in O0oOOo0o . rle_forwarding_list :
   O0iIi1IiII . outer_dest . copy_address ( OoOOoO0oOo . address )
   O0iIi1IiII . encap_port = lisp . LISP_DATA_PORT if OoOOoO0oOo . translated_port == 0 else OoOOoO0oOo . translated_port
   if 70 - 70: I11i % iIii1I11I1II1 . Oo0Ooo + Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
   if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
   I1Iii1iI1 = O0iIi1IiII . outer_dest . afi_to_version ( )
   O0iIi1IiII . outer_version = I1Iii1iI1
   if 87 - 87: OoO0O00 % I1IiiI
   O0o0oOooOoOo = iIiiI1 if ( I1Iii1iI1 == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
   O0iIi1IiII . outer_source . copy_address ( O0o0oOooOoOo )
   if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
   if ( O0iIi1IiII . is_trace ( ) ) :
    O00OOooo0Ooo = oO0oIIII
    i1 = "replicate"
    if ( lisp . lisp_trace_append ( O0iIi1IiII , reason = i1 , lisp_socket = O00OOooo0Ooo ) == False ) : return
    if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
    if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
    if 84 - 84: i11iIiiIii * OoO0O00
   if ( O0iIi1IiII . encode ( None ) == None ) : return
   if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
   O0iIi1IiII . print_packet ( "Replicate-to-L{}" . format ( OoOOoO0oOo . level ) , True )
   O0iIi1IiII . send_packet ( OOo , O0iIi1IiII . outer_dest )
   if 30 - 30: O0 + I1ii11iIi11i + II111iiii
   if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
   if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
   if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
   if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
   oo0o = len ( O0iIi1IiII . packet ) - iIIIiIi1I1i
   O0iIi1IiII . packet = O0iIi1IiII . packet [ oo0o : : ]
   if 51 - 51: OOooOOo . I1IiiI
   if ( lisp . lisp_flow_logging ) : O0iIi1IiII = copy . deepcopy ( O0iIi1IiII )
   if 73 - 73: OoooooooOO . I1IiiI / I1Ii111 % Ii1I
   if 65 - 65: IiII - I1IiiI - Ii1I
   if 42 - 42: II111iiii * I1IiiI % i1IIi - Ii1I % IiII
   if 36 - 36: i11iIiiIii / oO0o * I1ii11iIi11i * I1ii11iIi11i + Ii1I * I11i
   if 32 - 32: OoO0O00
   if 50 - 50: ooOoO0o + i1IIi
 del ( O0iIi1IiII )
 if 31 - 31: Ii1I
 OO0000o ( iiIi1i , "RTR" )
 return
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
def iIIiI1iiI ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  if 18 - 18: iII111i - oO0o % iII111i / I11i
  if 68 - 68: Ii1I * iIii1I11I1II1 + I1Ii111 % OoOoOO00
  if 46 - 46: OoOoOO00 % i1IIi / oO0o * Oo0Ooo * OOooOOo
  if 67 - 67: OoOoOO00 * OoOoOO00 . OoOoOO00 + Ii1I / oO0o
  O0iIi1IiII = lisp_thread . input_queue . get ( )
  if 13 - 13: iII111i
  if 80 - 80: Ii1I - o0oOOo0O0Ooo
  if 41 - 41: o0oOOo0O0Ooo - Oo0Ooo * I1IiiI
  if 82 - 82: OoO0O00 % o0oOOo0O0Ooo % OOooOOo / O0
  lisp_thread . input_stats . increment ( len ( O0iIi1IiII ) )
  if 94 - 94: I1ii11iIi11i + I1ii11iIi11i + OoooooooOO % ooOoO0o
  if 7 - 7: iII111i
  if 78 - 78: OOooOOo + iII111i . IiII
  if 91 - 91: iIii1I11I1II1 . o0oOOo0O0Ooo . I1ii11iIi11i + OoooooooOO
  lisp_thread . lisp_packet . packet = O0iIi1IiII
  if 69 - 69: I1Ii111 - I1IiiI
  if 95 - 95: I1IiiI * i11iIiiIii . ooOoO0o
  if 41 - 41: II111iiii
  if 37 - 37: I11i . Oo0Ooo % IiII * i1IIi
  O0oooo00o0Oo ( lisp_thread . lisp_packet , lisp_thread . thread_name )
  if 71 - 71: Oo0Ooo / o0oOOo0O0Ooo + OOooOOo
 return
 if 48 - 48: I1Ii111 + iII111i
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii . OoOoOO00 % ooOoO0o + oO0o . OoO0O00
 if 46 - 46: OoO0O00 - o0oOOo0O0Ooo / OoOoOO00 - OoooooooOO + oO0o
 if 58 - 58: o0oOOo0O0Ooo / o0oOOo0O0Ooo + ooOoO0o + I11i - OoOoOO00 . OOooOOo
 if 15 - 15: ooOoO0o * OoOoOO00 % IiII . OoOoOO00 . I11i
 if 97 - 97: oO0o
 if 80 - 80: I1IiiI . Ii1I
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
def OOoOoo00Oo ( thread ) :
 Iiii1iiiIiI1 = ( time . time ( ) % thread . number_of_pcap_threads )
 return ( int ( Iiii1iiiIiI1 ) == thread . thread_number )
 if 27 - 27: Ii1I + I1IiiI * iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
def OO0o0oO0O000o ( parms , not_used , packet ) :
 if ( OOoOoo00Oo ( parms [ 1 ] ) == False ) : return
 if 47 - 47: I1Ii111 - OoO0O00 / Ii1I * OoooooooOO / Ii1I . Oo0Ooo
 iiII1IiIi1iI1 = parms [ 0 ]
 oOiiI1Ii11II1I = parms [ 1 ]
 I1Ii11II1I1 = oOiiI1Ii11II1I . number_of_worker_threads
 if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
 oOiiI1Ii11II1I . input_stats . increment ( len ( packet ) )
 if 65 - 65: Oo0Ooo . OoooooooOO
 if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
 if 55 - 55: iII111i - OoO0O00
 if 100 - 100: O0
 if 79 - 79: iIii1I11I1II1
 if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
 I1ii = 4 if iiII1IiIi1iI1 == "lo0" else ( 14 if lisp . lisp_is_macos ( ) else 16 )
 packet = packet [ I1ii : : ]
 if 80 - 80: I1ii11iIi11i / iIii1I11I1II1 % OoOoOO00
 if 80 - 80: OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
 if ( I1Ii11II1I1 ) :
  O0oo0O0 = oOiiI1Ii11II1I . input_stats . packet_count % I1Ii11II1I1
  O0oo0O0 = O0oo0O0 + ( len ( I11 ) - I1Ii11II1I1 )
  iiII111iIII1Ii = I11 [ O0oo0O0 ]
  iiII111iIII1Ii . input_queue . put ( packet )
 else :
  oOiiI1Ii11II1I . lisp_packet . packet = packet
  O0oooo00o0Oo ( oOiiI1Ii11II1I . lisp_packet , oOiiI1Ii11II1I . thread_name )
  if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 return
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
def oo0O0o ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 13 - 13: iIii1I11I1II1 . OoOoOO00 * I1IiiI / oO0o * Ii1I
 iiII1IiIi1iI1 = "lo0" if lisp . lisp_is_macos ( ) else "any"
 if 64 - 64: ooOoO0o / O0 * OoOoOO00 * ooOoO0o
 if 60 - 60: I11i / i1IIi % I1ii11iIi11i / I1ii11iIi11i * I1ii11iIi11i . i11iIiiIii
 if 99 - 99: OoOoOO00
 if 77 - 77: o0oOOo0O0Ooo
 if 48 - 48: OoOoOO00 % I1ii11iIi11i / I11i . iIii1I11I1II1 * II111iiii
 oo000oO = getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 oo000oO = ( oo000oO != "" and oo000oO [ 0 ] == " " )
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 I11i11i1 = "(dst host "
 OOO = ""
 for OOOOOoo0 in lisp . lisp_get_all_addresses ( ) :
  I11i11i1 += "{} or " . format ( OOOOOoo0 )
  OOO += "{} or " . format ( OOOOOoo0 )
  if 37 - 37: O0 - I11i
 I11i11i1 = I11i11i1 [ 0 : - 4 ]
 I11i11i1 += ") and ((udp dst port 4341 or 8472 or 4789) or "
 I11i11i1 += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0))))"
 if 21 - 21: iIii1I11I1II1 / I1Ii111 + ooOoO0o - I11i / Oo0Ooo / II111iiii
 if 69 - 69: I1IiiI . OoOoOO00
 if 53 - 53: I11i
 if 68 - 68: oO0o / I1Ii111 % I1Ii111 % O0
 if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 OOO = OOO [ 0 : - 4 ]
 I11i11i1 += ( " or (not (src host {}) and " + "((udp src port 4342 and ip[28] == 0x28) or " + "(udp dst port 4342 and ip[28] == 0x12)))" ) . format ( OOO )
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 if ( oo000oO ) :
  I11i11i1 += ( " or (dst net 0.0.0.0/0 and " + "not (host {} or src net 127.0.0.0/8))" ) . format ( OOO )
  if 77 - 77: Oo0Ooo
  if 46 - 46: I1Ii111
  if 72 - 72: iII111i * OOooOOo
 lisp . lprint ( "Capturing packets for: '{}'" . format ( I11i11i1 ) )
 if 67 - 67: i1IIi
 if 5 - 5: II111iiii . OoooooooOO
 if 57 - 57: I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if ( lisp . lisp_is_python2 ( ) ) :
  import pcappy
  iii11i1 = pcappy . open_live ( iiII1IiIi1iI1 , 9000 , 0 , 100 )
  iii11i1 . filter = I11i11i1
  iii11i1 . loop ( - 1 , OO0o0oO0O000o , [ iiII1IiIi1iI1 , lisp_thread ] )
  if 48 - 48: ooOoO0o * I1ii11iIi11i
 if ( lisp . lisp_is_python3 ( ) ) :
  import pcapy
  iii11i1 = pcapy . open_live ( iiII1IiIi1iI1 , 9000 , 0 , 100 )
  iii11i1 . setfilter ( I11i11i1 )
  while ( True ) :
   Ii1Iii111IiI1 , O0iIi1IiII = iii11i1 . next ( )
   if ( len ( O0iIi1IiII ) == 0 ) : continue
   OO0o0oO0O000o ( [ iiII1IiIi1iI1 , lisp_thread ] , None , O0iIi1IiII )
   if 15 - 15: OoO0O00 * I11i % iIii1I11I1II1 * I1ii11iIi11i
   if 31 - 31: OoO0O00 * O0 . oO0o
 return
 if 59 - 59: II111iiii * i11iIiiIii
 if 54 - 54: O0 % OoooooooOO - I1IiiI
 if 61 - 61: Oo0Ooo * IiII . Oo0Ooo + Oo0Ooo / IiII * O0
 if 73 - 73: iII111i * iII111i / ooOoO0o
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
def O0oOO0o ( lisp_raw_socket , eid , geid , igmp ) :
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 O0iIi1IiII = lisp . lisp_packet ( igmp )
 if 83 - 83: o0oOOo0O0Ooo
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if 48 - 48: iII111i + IiII
 OoOo = lisp . lisp_map_cache_lookup ( eid , geid )
 if ( OoOo == None ) : return
 if ( OoOo . rloc_set == [ ] ) : return
 if ( OoOo . rloc_set [ 0 ] . rle == None ) : return
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 i1i11ii1Ii = eid . print_address_no_iid ( )
 for OoO in OoOo . rloc_set [ 0 ] . rle . rle_nodes :
  if ( OoO . rloc_name == i1i11ii1Ii ) :
   O0iIi1IiII . outer_dest . copy_address ( OoO . address )
   O0iIi1IiII . encap_port = OoO . translated_port
   break
   if 12 - 12: OOooOOo . Ii1I
   if 79 - 79: I1Ii111 / Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + o0oOOo0O0Ooo
 if ( O0iIi1IiII . outer_dest . is_null ( ) ) : return
 if 73 - 73: O0 - I1ii11iIi11i
 O0iIi1IiII . outer_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 O0iIi1IiII . outer_version = O0iIi1IiII . outer_dest . afi_to_version ( )
 O0iIi1IiII . outer_ttl = 32
 O0iIi1IiII . inner_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 O0iIi1IiII . inner_dest . store_address ( "[{}]224.0.0.1" . format ( geid . instance_id ) )
 O0iIi1IiII . inner_ttl = 1
 if 2 - 2: II111iiii / I1Ii111
 OO0oOoOO0oOO0 = lisp . green ( eid . print_address ( ) , False )
 i1 = lisp . red ( "{}:{}" . format ( O0iIi1IiII . outer_dest . print_address_no_iid ( ) ,
 O0iIi1IiII . encap_port ) , False )
 OoOoO0oOOooo = lisp . bold ( "IGMP Query" , False )
 if 99 - 99: iIii1I11I1II1
 lisp . lprint ( "Data encapsulate {} to gleaned EID {}, RLOC {}" . format ( OoOoO0oOOooo , OO0oOoOO0oOO0 , i1 ) )
 if 14 - 14: I1ii11iIi11i % I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if ( O0iIi1IiII . encode ( None ) == None ) : return
 O0iIi1IiII . print_packet ( "Send" , True )
 if 77 - 77: II111iiii
 O0iIi1IiII . send_packet ( lisp_raw_socket , O0iIi1IiII . outer_dest )
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 if 68 - 68: oO0o
 if 10 - 10: Ii1I
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if 81 - 81: IiII / OoOoOO00 * IiII . O0
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
 if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
 if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
def O000oOo0O ( lisp_raw_socket ) :
 if ( lisp . lisp_gleaned_groups == { } ) : return
 if 82 - 82: IiII
 if 86 - 86: Oo0Ooo * II111iiii * O0
 if 83 - 83: IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 OoOOoooO000 = b"\x46\xc0\x00\x24\x00\x00\x40\x00\x01\x02\x00\x00"
 OoO0o000oOo = lisp . lisp_myrlocs [ 0 ]
 oO0o0OOOO = OoO0o000oOo . address
 OoOOoooO000 += OooO0OO ( ( oO0o0OOOO >> 24 ) & 0xff )
 OoOOoooO000 += OooO0OO ( ( oO0o0OOOO >> 16 ) & 0xff )
 OoOOoooO000 += OooO0OO ( ( oO0o0OOOO >> 8 ) & 0xff )
 OoOOoooO000 += OooO0OO ( oO0o0OOOO & 0xff )
 OoOOoooO000 += b"\xe0\x00\x00\x01"
 OoOOoooO000 += b"\x94\x04\x00\x00"
 OoOOoooO000 = lisp . lisp_ip_checksum ( OoOOoooO000 , 24 )
 if 88 - 88: i1IIi * I1Ii111 * oO0o - ooOoO0o * I11i / OoooooooOO
 if 41 - 41: O0 / I1Ii111 + iIii1I11I1II1
 if 72 - 72: OoOoOO00 * iIii1I11I1II1 % I11i
 if 20 - 20: II111iiii % iIii1I11I1II1 + oO0o * II111iiii * OoO0O00 % OoO0O00
 if 15 - 15: oO0o / I1Ii111
 oO0 = b"\x11\x64\x00\x00" + b"\x00\x00\x00\x00" + b"\x02\x3c\x00\x00"
 oO0 = lisp . lisp_igmp_checksum ( oO0 )
 if 37 - 37: i11iIiiIii + I1IiiI . OOooOOo % I11i % I11i
 if 26 - 26: O0
 if 34 - 34: ooOoO0o * I1Ii111
 if 97 - 97: i11iIiiIii % oO0o / Oo0Ooo / Oo0Ooo
 if 97 - 97: II111iiii - I1Ii111 - iIii1I11I1II1 * I1IiiI
 o0 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 Oo0oOOo = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 54 - 54: iIii1I11I1II1
 for Oo0O in lisp . lisp_gleaned_groups :
  o0 . store_address ( Oo0O )
  for i111i1I1ii1i in lisp . lisp_gleaned_groups [ Oo0O ] :
   Oo0oOOo . store_address ( i111i1I1ii1i )
   II1i , Ii1IIIIi1ii1I , O0O = lisp . lisp_allow_gleaning ( o0 , Oo0oOOo , None )
   if ( O0O == False ) : continue
   O0oOO0o ( lisp_raw_socket , o0 , Oo0oOOo , OoOOoooO000 + oO0 )
   if 80 - 80: iIii1I11I1II1
   if 23 - 23: II111iiii
   if 71 - 71: I1Ii111 * Oo0Ooo . I11i
   if 49 - 49: IiII * O0 . IiII
   if 19 - 19: II111iiii - IiII
   if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
   if 89 - 89: OOooOOo
   if 69 - 69: ooOoO0o - OoooooooOO * O0
   if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
   if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
def oo00o0 ( ) :
 o0 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 Oo0oOOo = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 17 - 17: Ii1I / iIii1I11I1II1 - OoO0O00 + I1IiiI % OOooOOo
 III1III11II = [ ]
 for Oo0O in lisp . lisp_gleaned_groups :
  for i111i1I1ii1i in lisp . lisp_gleaned_groups [ Oo0O ] :
   iIi1iI = lisp . lisp_gleaned_groups [ Oo0O ] [ i111i1I1ii1i ]
   OO0Oo = time . time ( ) - iIi1iI
   if ( OO0Oo < lisp . LISP_IGMP_TIMEOUT_INTERVAL ) : continue
   III1III11II . append ( [ Oo0O , i111i1I1ii1i ] )
   if 13 - 13: o0oOOo0O0Ooo * i11iIiiIii / i11iIiiIii . OoO0O00 . OOooOOo . I1ii11iIi11i
   if 26 - 26: o0oOOo0O0Ooo . iIii1I11I1II1
   if 67 - 67: Oo0Ooo / O0
   if 88 - 88: OoOoOO00 - OOooOOo
   if 63 - 63: IiII * OoooooooOO
   if 19 - 19: IiII - o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00 / OOooOOo
   if 87 - 87: OoOoOO00 - ooOoO0o - OOooOOo + Oo0Ooo % iIii1I11I1II1 / i11iIiiIii
 i1iIIII1iiIIi = lisp . bold ( "timed out" , False )
 for Oo0O , i111i1I1ii1i in III1III11II :
  o0 . store_address ( Oo0O )
  Oo0oOOo . store_address ( i111i1I1ii1i )
  OO0oOoOO0oOO0 = lisp . green ( Oo0O , False )
  i1I1IiI1ii = lisp . green ( i111i1I1ii1i , False )
  lisp . lprint ( "{} RLE {} for gleaned group {}" . format ( OO0oOoOO0oOO0 , i1iIIII1iiIIi , i1I1IiI1ii ) )
  lisp . lisp_remove_gleaned_multicast ( o0 , Oo0oOOo )
  if 64 - 64: iII111i * I1ii11iIi11i % II111iiii - OoOoOO00 + I1ii11iIi11i
  if 62 - 62: OoOoOO00 % o0oOOo0O0Ooo % I1IiiI + IiII . OoO0O00
  if 48 - 48: I1IiiI * i11iIiiIii % II111iiii
  if 20 - 20: i1IIi / I1IiiI * oO0o
  if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
  if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
  if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
  if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
def iI111II1ii ( lisp_raw_socket ) :
 lisp . lisp_set_exception ( )
 if 62 - 62: iII111i * iIii1I11I1II1 . IiII - OoooooooOO * II111iiii
 if 45 - 45: O0 % I1IiiI - iII111i . OoO0O00
 if 42 - 42: iII111i / o0oOOo0O0Ooo + Oo0Ooo . Oo0Ooo % OOooOOo
 if 16 - 16: i1IIi + OoO0O00 % OoOoOO00 + Ii1I * Oo0Ooo
 for OoO0o in list ( lisp . lisp_crypto_keys_by_nonce . values ( ) ) :
  for i1o0oo0 in OoO0o : del ( i1o0oo0 )
  if 67 - 67: O0 * I11i - o0oOOo0O0Ooo - II111iiii
 lisp . lisp_crypto_keys_by_nonce . clear ( )
 lisp . lisp_crypto_keys_by_nonce = { }
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 lisp . lisp_rtr_nat_trace_cache . clear ( )
 lisp . lisp_rtr_nat_trace_cache = { }
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 oo00o0 ( )
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 O000oOo0O ( lisp_raw_socket )
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 if 24 - 24: ooOoO0o - I11i * oO0o
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 Oooo0000 = threading . Timer ( 60 , iI111II1ii ,
 [ lisp_raw_socket ] )
 Oooo0000 . start ( )
 return
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
def iIi1i11 ( ) :
 global Oo0oO0oo0oO00 , II1iII1i , II1Ii1iI1i
 global OOo , Ii1IIii11 , I11
 global i111I , oO0oIIII
 global iIiiI1 , OooO0OO
 if 25 - 25: I1IiiI % O0 + i1IIi - ooOoO0o
 lisp . lisp_i_am ( "rtr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "RTR starting up" )
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 iIiiI1 = lisp . lisp_myrlocs [ 0 ]
 if ( lisp . lisp_on_aws ( ) ) :
  I1IiII1I1i1I1 = lisp . bold ( "AWS RTR" , False )
  oO0o0OOOO = None
  for iiII1IiIi1iI1 in [ "eth0" , "ens5" ] :
   oO0o0OOOO = lisp . lisp_get_interface_address ( iiII1IiIi1iI1 )
   if ( oO0o0OOOO != None ) : break
   if 28 - 28: Oo0Ooo + IiII % II111iiii / OoO0O00 + i11iIiiIii
  if ( oO0o0OOOO != None ) :
   iIiiI1 = oO0o0OOOO
   OOOOOoo0 = oO0o0OOOO . print_address_no_iid ( )
   lisp . lprint ( "{} using RLOC {} on {}" . format ( I1IiII1I1i1I1 , OOOOOoo0 , iiII1IiIi1iI1 ) )
  else :
   OOOOOoo0 = iIiiI1 . print_address_no_iid ( )
   lisp . lprint ( "{} cannot obtain RLOC, using {}" . format ( I1IiII1I1i1I1 , OOOOOoo0 ) )
   if 20 - 20: I1ii11iIi11i
   if 3 - 3: OoO0O00 * i1IIi . I1IiiI . O0 - OoOoOO00
   if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
   if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
   if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
   if 10 - 10: I1ii11iIi11i / i11iIiiIii - Ii1I + oO0o * I1IiiI
   if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
   if 64 - 64: I11i + OoO0O00
 Ii = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 II1Ii1iI1i = lisp . lisp_open_listen_socket ( Ii ,
 str ( iiI1iIiI ) )
 Oo0oO0oo0oO00 = lisp . lisp_open_listen_socket ( "" , "lisp-rtr" )
 i111I = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 if 44 - 44: I1IiiI % Ii1I * I1IiiI . Oo0Ooo + I1ii11iIi11i . OOooOOo
 II1iII1i [ 0 ] = II1Ii1iI1i
 if 6 - 6: IiII * OoooooooOO + I1Ii111 / Ii1I
 II1iII1i [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 II1iII1i [ 2 ] = Oo0oO0oo0oO00
 if 35 - 35: ooOoO0o % I1IiiI - ooOoO0o - OoO0O00 - OoooooooOO
 if 46 - 46: i1IIi . i1IIi . oO0o / I11i / ooOoO0o
 if 34 - 34: OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
 if 98 - 98: oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 OOo = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 OOo . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 II1iII1i . append ( OOo )
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if ( oo0Ooo0 ) : OooO0OO = o0oO000oo if lisp . lisp_is_python2 ( ) else IIiI1Ii
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 oO0oIIII = lisp . lisp_open_listen_socket ( "0.0.0.0" ,
 str ( lisp . LISP_TRACE_PORT ) )
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  Ii1IIii11 = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
  if 33 - 33: Ii1I
 ooOOO00oOOooO = os . getenv ( "LISP_PCAP_THREADS" )
 ooOOO00oOOooO = 1 if ( ooOOO00oOOooO == None ) else int ( ooOOO00oOOooO )
 IiI = os . getenv ( "LISP_WORKER_THREADS" )
 IiI = 0 if ( IiI == None ) else int ( IiI )
 if 4 - 4: OoooooooOO + ooOoO0o . i1IIi / O0 - O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
 for iiI in range ( ooOOO00oOOooO ) :
  O0OO0o0O00oO = lisp . lisp_thread ( "pcap-{}" . format ( iiI ) )
  O0OO0o0O00oO . thread_number = iiI
  O0OO0o0O00oO . number_of_pcap_threads = ooOOO00oOOooO
  O0OO0o0O00oO . number_of_worker_threads = IiI
  I11 . append ( O0OO0o0O00oO )
  threading . Thread ( target = oo0O0o , args = [ O0OO0o0O00oO ] ) . start ( )
  if 81 - 81: IiII / I11i
  if 46 - 46: I1ii11iIi11i / I1Ii111 + IiII / oO0o / I1Ii111 / OOooOOo
  if 73 - 73: ooOoO0o + I1ii11iIi11i
  if 100 - 100: iIii1I11I1II1
  if 77 - 77: II111iiii + o0oOOo0O0Ooo
  if 47 - 47: OOooOOo
 for iiI in range ( IiI ) :
  O0OO0o0O00oO = lisp . lisp_thread ( "worker-{}" . format ( iiI ) )
  I11 . append ( O0OO0o0O00oO )
  threading . Thread ( target = iIIiI1iiI , args = [ O0OO0o0O00oO ] ) . start ( )
  if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
  if 92 - 92: OoOoOO00 % O0
  if 55 - 55: iIii1I11I1II1 * iII111i
  if 85 - 85: iIii1I11I1II1 . II111iiii
  if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
 lisp . lisp_load_checkpoint ( )
 if 22 - 22: OOooOOo
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
 if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 94 - 94: i1IIi
 if 36 - 36: I1IiiI + Oo0Ooo
 if 46 - 46: iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 Oooo0000 = threading . Timer ( 60 , iI111II1ii ,
 [ OOo ] )
 Oooo0000 . start ( )
 return ( True )
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
 if 65 - 65: ooOoO0o - i1IIi
 if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
def ooO0 ( ) :
 if 94 - 94: I11i . I1IiiI
 if 73 - 73: i1IIi / II111iiii
 if 45 - 45: Ii1I / ooOoO0o . OoooooooOO + OoO0O00
 if 51 - 51: iII111i % i11iIiiIii % IiII + I1Ii111 % I1ii11iIi11i
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lisp-rtr" )
 lisp . lisp_close_socket ( II1Ii1iI1i , "" )
 lisp . lisp_close_socket ( oO0oIIII , "" )
 lisp . lisp_close_socket ( i111I , "lispers.net-itr" )
 OOo . close ( )
 return
 if 16 - 16: OoOoOO00 / Oo0Ooo + O0 - OoOoOO00 . OoooooooOO
 if 19 - 19: o0oOOo0O0Ooo
 if 73 - 73: I1Ii111 * Oo0Ooo * OoOoOO00
 if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
def iIIiI11iI1Ii1 ( kv_pair ) :
 global II1iII1i
 global iiI1iIiI
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , iiI1iIiI ] )
  lisp . lisp_test_mr_timer . start ( )
  if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 return
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo
 if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
def OOo000o ( kv_pair ) :
 global II1Ii1iI1i , OOo , iiI1iIiI
 if 37 - 37: iII111i
 iIIiI1111 = lisp . lisp_rloc_probing
 if 91 - 91: OoooooooOO / o0oOOo0O0Ooo . IiII - iIii1I11I1II1 - Ii1I
 if 31 - 31: IiII - OoO0O00 / OOooOOo . i1IIi / Ii1I
 if 66 - 66: OoO0O00
 if 72 - 72: I1Ii111
 lispconfig . lisp_xtr_command ( kv_pair )
 if 91 - 91: II111iiii / IiII + iIii1I11I1II1 . I11i - O0
 if 70 - 70: Ii1I * oO0o - I11i + Oo0Ooo % I1ii11iIi11i - IiII
 if 81 - 81: O0 . O0
 if 75 - 75: iIii1I11I1II1 % IiII + I1ii11iIi11i * O0 . iII111i - ooOoO0o
 if 32 - 32: Ii1I % oO0o - i1IIi
 if ( iIIiI1111 == False and lisp . lisp_rloc_probing ) :
  oOooOOOoOo = [ II1Ii1iI1i , II1Ii1iI1i ,
 None , OOo ]
  lisp . lisp_start_rloc_probe_timer ( 1 , oOooOOOoOo )
  i1Ii = { "type" : "itr-crypto-port" , "port" : iiI1iIiI }
  lisp . lisp_write_to_dp_socket ( i1Ii )
  if 40 - 40: iIii1I11I1II1 + iII111i * OoOoOO00 + oO0o
  if 15 - 15: I11i % I1IiiI - iIii1I11I1II1 * ooOoO0o
  if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
  if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
  if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
 if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
 if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
 if 93 - 93: ooOoO0o
 if 18 - 18: ooOoO0o
OOOooO00OO00O = {
 "lisp xtr-parameters" : [ OOo000o , {
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

 "lisp map-resolver" : [ iIIiI11iI1Ii1 , {
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
 "subscribe-request" : [ True , "yes" , "no" ] ,
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

 "lisp database-mapping" : [ O0oo0OO0oOOOo , {
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

 "lisp glean-mapping" : [ OooO0OoOOOO , {
 "instance-id" : [ False ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] ,
 "rloc-prefix" : [ True ] ,
 "rloc-probe" : [ True , "yes" , "no" ] ,
 "igmp-query" : [ True , "yes" , "no" ] } ] ,

 "show rtr-rloc-probing" : [ iI11i1ii11 , { } ] ,
 "show rtr-keys" : [ I1i1I , { } ] ,
 "show rtr-map-cache" : [ oo , { } ] ,
 "show rtr-map-cache-dns" : [ IIII , { } ]
 }
if 78 - 78: II111iiii - Oo0Ooo - O0 . OOooOOo + i11iIiiIii - I1ii11iIi11i
if 58 - 58: Ii1I % OoooooooOO
if 49 - 49: I1ii11iIi11i + O0 . Ii1I * OoooooooOO
if 82 - 82: I1ii11iIi11i
if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
def O0oO0oo0O0 ( lisp_socket ) :
 if 66 - 66: OOooOOo - ooOoO0o - Oo0Ooo
 if 54 - 54: iII111i . i1IIi
 if 19 - 19: ooOoO0o % oO0o
 if 22 - 22: oO0o . II111iiii . Oo0Ooo
 ooIi111iII , ooO0oO00O0o , i1Iii1i1I , O0iIi1IiII = lisp . lisp_receive ( lisp_socket , False )
 Oo0OoOo = lisp . lisp_trace ( )
 if ( Oo0OoOo . decode ( O0iIi1IiII ) == False ) : return
 if 13 - 13: o0oOOo0O0Ooo
 if 7 - 7: I1IiiI + IiII / i11iIiiIii / Oo0Ooo
 if 97 - 97: I1Ii111 . I11i / I1IiiI
 if 83 - 83: I11i - I1ii11iIi11i * oO0o
 if 90 - 90: Oo0Ooo * I1IiiI
 Oo0OoOo . rtr_cache_nat_trace ( ooO0oO00O0o , i1Iii1i1I )
 if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
 if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
 if 28 - 28: IiII * I1IiiI % IiII
 if 95 - 95: O0 / I11i . I1Ii111
 if 17 - 17: I11i
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
if ( iIi1i11 ( ) == False ) :
 lisp . lprint ( "lisp_rtr_startup() failed" )
 lisp . lisp_print_banner ( "RTR abnormal exit" )
 exit ( 1 )
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
iiI1iiii1Iii = [ II1Ii1iI1i , Oo0oO0oo0oO00 ,
 i111I , oO0oIIII ]
OoOOOOOoOo0 = [ II1Ii1iI1i ] * 3
if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
while ( True ) :
 try : iIiii1iI1i , i1iiiI , II1i = select . select ( iiI1iiii1Iii , [ ] , [ ] )
 except : break
 if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
 if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
 if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
 if 25 - 25: o0oOOo0O0Ooo
 if ( lisp . lisp_ipc_data_plane and i111I in iIiii1iI1i ) :
  lisp . lisp_process_punt ( i111I , II1iII1i ,
 iiI1iIiI )
  if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
  if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
  if 41 - 41: i1IIi - I1IiiI
  if 48 - 48: I1IiiI - II111iiii / OoO0O00 + I1IiiI
  if 5 - 5: O0
 if ( oO0oIIII in iIiii1iI1i ) :
  O0oO0oo0O0 ( oO0oIIII )
  if 75 - 75: I1Ii111 + iIii1I11I1II1
  if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
  if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
  if 92 - 92: I11i / O0 * I1IiiI - I11i
  if 99 - 99: i11iIiiIii % OoooooooOO
 if ( II1Ii1iI1i in iIiii1iI1i ) :
  ooIi111iII , ooO0oO00O0o , i1Iii1i1I , O0iIi1IiII = lisp . lisp_receive ( OoOOOOOoOo0 [ 0 ] ,
 False )
  if ( ooO0oO00O0o == "" ) : break
  if ( lisp . lisp_is_rloc_probe_request ( O0iIi1IiII [ 0 : 1 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
   continue
   if 56 - 56: IiII * I1Ii111
  if ( lisp . lisp_is_rloc_probe_reply ( O0iIi1IiII [ 0 : 1 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
   continue
   if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
  lisp . lisp_parse_packet ( OoOOOOOoOo0 , O0iIi1IiII , ooO0oO00O0o , i1Iii1i1I )
  if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
  if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
  if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
  if 56 - 56: i1IIi . i11iIiiIii
  if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
  if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
 if ( Oo0oO0oo0oO00 in iIiii1iI1i ) :
  ooIi111iII , ooO0oO00O0o , i1Iii1i1I , O0iIi1IiII = lisp . lisp_receive ( Oo0oO0oo0oO00 , True )
  if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
  if ( ooO0oO00O0o == "" ) : break
  if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
  if ( ooIi111iII == "command" ) :
   O0iIi1IiII = O0iIi1IiII . decode ( )
   if ( O0iIi1IiII == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
   if ( O0iIi1IiII . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( O0iIi1IiII )
    continue
    if 10 - 10: IiII / OoooooooOO
   lispconfig . lisp_process_command ( Oo0oO0oo0oO00 , ooIi111iII ,
 O0iIi1IiII , "lisp-rtr" , [ OOOooO00OO00O ] )
  elif ( ooIi111iII == "api" ) :
   O0iIi1IiII = O0iIi1IiII . decode ( )
   lisp . lisp_process_api ( "lisp-rtr" , Oo0oO0oo0oO00 , O0iIi1IiII )
  elif ( ooIi111iII == "data-packet" ) :
   O0oooo00o0Oo ( O0iIi1IiII , "" )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( O0iIi1IiII [ 0 : 1 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
    continue
    if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
   if ( lisp . lisp_is_rloc_probe_reply ( O0iIi1IiII [ 0 : 1 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
    continue
    if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
   lisp . lisp_parse_packet ( II1iII1i , O0iIi1IiII , ooO0oO00O0o , i1Iii1i1I )
   if 25 - 25: iIii1I11I1II1
   if 63 - 63: ooOoO0o
   if 96 - 96: I11i
   if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
ooO0 ( )
lisp . lisp_print_banner ( "RTR normal exit" )
exit ( 0 )
if 63 - 63: iII111i
if 11 - 11: iII111i - iIii1I11I1II1
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
