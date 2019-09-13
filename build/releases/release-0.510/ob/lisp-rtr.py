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
if 90 - 90: II111iiii + oO0o / o0oOOo0O0Ooo % II111iiii - O0
if 29 - 29: o0oOOo0O0Ooo / iIii1I11I1II1
if 24 - 24: O0 % o0oOOo0O0Ooo + i1IIi + I1Ii111 + I1ii11iIi11i
if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
if 23 - 23: i11iIiiIii + I1IiiI
if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
if 33 - 33: Ii1I + II111iiii % i11iIiiIii . ooOoO0o - I1IiiI
def O00oooo0O ( parameter ) :
 global I11
 if 22 - 22: OoooooooOO % I11i - iII111i . iIii1I11I1II1 * i11iIiiIii
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "RTR" ,
 I11 ) )
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 if 61 - 61: ooOoO0o
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
def Ii1IOo0o0 ( parameter ) :
 global I11
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "RTR" , I11 ,
 True ) )
 if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo
 if 77 - 77: OoOoOO00 / I11i
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
 if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % oO0o . O0
 if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
def o00oOO0 ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "RTR" ) )
 if 95 - 95: OOooOOo / OoooooooOO
 if 18 - 18: i11iIiiIii
 if 46 - 46: i1IIi / I11i % OOooOOo + I1Ii111
 if 79 - 79: I1Ii111 - o0oOOo0O0Ooo + I1Ii111 - iII111i
 if 8 - 8: I1IiiI
 if 75 - 75: iIii1I11I1II1 / OOooOOo % o0oOOo0O0Ooo * OoOoOO00
 if 9 - 9: OoO0O00
def i11 ( kv_pair ) :
 lispconfig . lisp_database_mapping_command ( kv_pair )
 if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 if 50 - 50: I1IiiI
 if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
 if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
 if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
 if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
def O0O0O ( kv_pair ) :
 oO0Oo = { "rloc-probe" : False , "igmp-query" : False }
 if 54 - 54: o0oOOo0O0Ooo - I1IiiI + OoooooooOO
 for O0o0 in kv_pair . keys ( ) :
  OO00Oo = kv_pair [ O0o0 ]
  if 51 - 51: IiII * o0oOOo0O0Ooo + I11i + OoO0O00
  if ( O0o0 == "instance-id" ) :
   o0O0O00 = OO00Oo . split ( "-" )
   oO0Oo [ "instance-id" ] = [ 0 , 0 ]
   if ( len ( o0O0O00 ) == 1 ) :
    oO0Oo [ "instance-id" ] [ 0 ] = int ( o0O0O00 [ 0 ] )
    oO0Oo [ "instance-id" ] [ 1 ] = int ( o0O0O00 [ 0 ] )
   else :
    oO0Oo [ "instance-id" ] [ 0 ] = int ( o0O0O00 [ 0 ] )
    oO0Oo [ "instance-id" ] [ 1 ] = int ( o0O0O00 [ 1 ] )
    if 86 - 86: I11i / IiII % i11iIiiIii
    if 7 - 7: ooOoO0o * OoO0O00 % oO0o . IiII
  if ( O0o0 == "eid-prefix" ) :
   Ii1iIiII1ii1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   Ii1iIiII1ii1 . store_prefix ( OO00Oo )
   oO0Oo [ "eid-prefix" ] = Ii1iIiII1ii1
   if 62 - 62: iIii1I11I1II1 * OoOoOO00
  if ( O0o0 == "group-prefix" ) :
   i1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   i1 . store_prefix ( OO00Oo )
   oO0Oo [ "group-prefix" ] = i1
   if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
  if ( O0o0 == "rloc-prefix" ) :
   iII1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   iII1 . store_prefix ( OO00Oo )
   oO0Oo [ "rloc-prefix" ] = iII1
   if 30 - 30: II111iiii - OOooOOo - i11iIiiIii % OoOoOO00 - II111iiii * Ii1I
  if ( O0o0 == "rloc-probe" ) :
   oO0Oo [ "rloc-probe" ] = ( OO00Oo == "yes" )
   if 61 - 61: oO0o - I11i % OOooOOo
  if ( O0o0 == "igmp-query" ) :
   oO0Oo [ "igmp-query" ] = ( OO00Oo == "yes" )
   if 84 - 84: oO0o * OoO0O00 / I11i - O0
   if 30 - 30: iIii1I11I1II1 / ooOoO0o - I1Ii111 - II111iiii % iII111i
   if 49 - 49: I1IiiI % ooOoO0o . ooOoO0o . I11i * ooOoO0o
   if 97 - 97: Ii1I + o0oOOo0O0Ooo . OOooOOo + I1ii11iIi11i % iII111i
   if 95 - 95: i1IIi
   if 3 - 3: I1Ii111 - O0 / I1Ii111 % OoO0O00 / I1Ii111 . I1IiiI
 for iiI111I1iIiI in lisp . lisp_glean_mappings :
  if ( iiI111I1iIiI . has_key ( "eid-prefix" ) ^ oO0Oo . has_key ( "eid-prefix" ) ) : continue
  if ( iiI111I1iIiI . has_key ( "eid-prefix" ) and oO0Oo . has_key ( "eid-prefix" ) ) :
   II = iiI111I1iIiI [ "eid-prefix" ]
   Ii1I1IIii1II = oO0Oo [ "eid-prefix" ]
   if ( II . is_exact_match ( Ii1I1IIii1II ) == False ) : continue
   if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
   if 21 - 21: I1IiiI * iIii1I11I1II1
  if ( iiI111I1iIiI . has_key ( "group-prefix" ) ^ oO0Oo . has_key ( "group-prefix" ) ) :
   continue
   if 91 - 91: IiII
  if ( iiI111I1iIiI . has_key ( "group-prefix" ) and oO0Oo . has_key ( "group-prefix" ) ) :
   II = iiI111I1iIiI [ "group-prefix" ]
   Ii1I1IIii1II = oO0Oo [ "group-prefix" ]
   if ( II . is_exact_match ( Ii1I1IIii1II ) == False ) : continue
   if 15 - 15: II111iiii
   if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
  if ( iiI111I1iIiI . has_key ( "rloc-prefix" ) ^ oO0Oo . has_key ( "rloc-prefix" ) ) : continue
  if ( iiI111I1iIiI . has_key ( "rloc-prefix" ) and oO0Oo . has_key ( "rloc-prefix" ) ) :
   II = iiI111I1iIiI [ "rloc-prefix" ]
   Ii1I1IIii1II = oO0Oo [ "rloc-prefix" ]
   if ( II . is_exact_match ( Ii1I1IIii1II ) == False ) : continue
   if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
   if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
  if ( iiI111I1iIiI . has_key ( "instance-id" ) ^ oO0Oo . has_key ( "instance-id" ) ) : continue
  if ( iiI111I1iIiI . has_key ( "instance-id" ) and oO0Oo . has_key ( "instance-id" ) ) :
   II = iiI111I1iIiI [ "instance-id" ]
   Ii1I1IIii1II = oO0Oo [ "instance-id" ]
   if ( II != Ii1I1IIii1II ) : continue
   if 91 - 91: O0
   if 61 - 61: II111iiii
   if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
   if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
   if 42 - 42: OoO0O00
  return
  if 67 - 67: I1Ii111 . iII111i . O0
  if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
  if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
  if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
  if 83 - 83: I11i / I1IiiI
 lisp . lisp_glean_mappings . append ( oO0Oo )
 if 34 - 34: IiII
 if 57 - 57: oO0o . I11i . i1IIi
 if 42 - 42: I11i + I1ii11iIi11i % O0
 if 6 - 6: oO0o
 if 68 - 68: OoOoOO00 - OoO0O00
 if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
 if 1 - 1: iIii1I11I1II1 / II111iiii
def iiI1I11i1i ( parameter ) :
 return ( lispconfig . lisp_itr_rtr_show_rloc_probe_command ( "RTR" ) )
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
 if 92 - 92: iII111i
 if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
def IIIII11I1IiI ( mc , parms ) :
 i1I , iII1 , OoOO , ooOOO0 = parms
 if 65 - 65: O0
 oO00OOoO00 = "{}:{}" . format ( iII1 . print_address_no_iid ( ) , OoOO )
 Ii1iIiII1ii1 = lisp . green ( mc . print_eid_tuple ( ) , False )
 IiI111111IIII = "Changed '{}' translated address:port to {} for EID {}, {} {}" . format ( ooOOO0 , lisp . red ( oO00OOoO00 , False ) , Ii1iIiII1ii1 , "{}" , "{}" )
 if 37 - 37: I1Ii111 / OoOoOO00
 if 23 - 23: O0
 for o00oO0oOo00 in mc . rloc_set :
  if ( o00oO0oOo00 . rle ) :
   for oO0oOo0 in o00oO0oOo00 . rle . rle_nodes :
    if ( oO0oOo0 . rloc_name != ooOOO0 ) : continue
    oO0oOo0 . store_translated_rloc ( iII1 , OoOO )
    I1I1I = oO0oOo0 . address . print_address_no_iid ( ) + ":" + str ( oO0oOo0 . translated_port )
    if 95 - 95: II111iiii + o0oOOo0O0Ooo + iII111i * iIii1I11I1II1 % oO0o / IiII
    lisp . lprint ( IiI111111IIII . format ( "RLE" , I1I1I ) )
    if 56 - 56: iII111i
    if 86 - 86: II111iiii % I1Ii111
    if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
  if ( o00oO0oOo00 . rloc_name != ooOOO0 ) : continue
  if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
  if 80 - 80: II111iiii
  if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
  if 53 - 53: II111iiii
  if 31 - 31: OoO0O00
  if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
  I1I1I = o00oO0oOo00 . rloc . print_address_no_iid ( ) + ":" + str ( o00oO0oOo00 . translated_port )
  if 25 - 25: OoO0O00
  if ( lisp . lisp_crypto_keys_by_rloc_encap . has_key ( I1I1I ) ) :
   oOo0oO = lisp . lisp_crypto_keys_by_rloc_encap [ I1I1I ]
   lisp . lisp_crypto_keys_by_rloc_encap [ oO00OOoO00 ] = oOo0oO
   if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
   if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
   if 82 - 82: Ii1I
   if 46 - 46: OoooooooOO . i11iIiiIii
   if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
  o00oO0oOo00 . delete_from_rloc_probe_list ( mc . eid , mc . group )
  o00oO0oOo00 . store_translated_rloc ( iII1 , OoOO )
  o00oO0oOo00 . add_to_rloc_probe_list ( mc . eid , mc . group )
  lisp . lprint ( IiI111111IIII . format ( "RLOC" , I1I1I ) )
  if 87 - 87: Oo0Ooo . IiII
  if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
  if 55 - 55: OOooOOo . I1IiiI
  if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
  if ( lisp . lisp_rloc_probing ) :
   o0oOO000oO0oo = None if ( mc . group . is_null ( ) ) else mc . eid
   oOO00O = mc . eid if ( mc . group . is_null ( ) ) else mc . group
   lisp . lisp_send_map_request ( i1I , 0 , o0oOO000oO0oo , oOO00O , o00oO0oOo00 )
   if 77 - 77: Oo0Ooo - i1IIi - I11i . OoOoOO00
   if 39 - 39: II111iiii / ooOoO0o + I1Ii111 / OoOoOO00
   if 13 - 13: IiII + O0 + iII111i % I1IiiI / o0oOOo0O0Ooo . IiII
   if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
   if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
   if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 lisp . lisp_write_ipc_map_cache ( True , mc )
 return ( True , parms )
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 if 49 - 49: I1IiiI - I11i
def OoOOoOooooOOo ( mc , parms ) :
 if 87 - 87: I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if 97 - 97: O0 + OoOoOO00
 if ( mc . group . is_null ( ) ) : return ( IIIII11I1IiI ( mc , parms ) )
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 if ( mc . source_cache == None ) : return ( True , parms )
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
 mc . source_cache . walk_cache ( IIIII11I1IiI , parms )
 return ( True , parms )
 if 71 - 71: Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
 if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
 if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
def o00oo0 ( sockets , hostname , rloc , port ) :
 lisp . lisp_map_cache . walk_cache ( OoOOoOooooOOo ,
 [ sockets , rloc , port , hostname ] )
 return
 if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
 if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
 if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
def o00Oo0oooooo ( sred , packet ) :
 if ( lisp . lisp_data_plane_logging == False ) : return
 if 76 - 76: I11i / OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 if ( sred in [ "Send" , "Receive" ] ) :
  o0o = binascii . hexlify ( packet [ 0 : 20 ] )
  lisp . lprint ( "Fast-{}: ip {} {} {} {} {}" . format ( sred , o0o [ 0 : 8 ] , o0o [ 8 : 16 ] ,
 o0o [ 16 : 24 ] , o0o [ 24 : 32 ] , o0o [ 32 : 40 ] ) )
 elif ( sred in [ "Encap" , "Decap" ] ) :
  o0o = binascii . hexlify ( packet [ 0 : 36 ] )
  lisp . lprint ( "Fast-{}: ip {} {} {} {} {}, udp {} {}, lisp {} {}" . format ( sred , o0o [ 0 : 8 ] , o0o [ 8 : 16 ] , o0o [ 16 : 24 ] , o0o [ 24 : 32 ] , o0o [ 32 : 40 ] ,
  # iIii1I11I1II1 / I11i . OoO0O00 - o0oOOo0O0Ooo
 o0o [ 40 : 48 ] , o0o [ 48 : 56 ] , o0o [ 56 : 64 ] , o0o [ 64 : 72 ] ) )
  if 48 - 48: i1IIi - Ii1I / O0 * OoO0O00
  if 71 - 71: I1ii11iIi11i
  if 7 - 7: I1ii11iIi11i - I1IiiI . iIii1I11I1II1 - i1IIi
  if 59 - 59: o0oOOo0O0Ooo
  if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
  if 73 - 73: I11i % i11iIiiIii - I1IiiI
  if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
  if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
def ii ( dest , mc ) :
 if ( lisp . lisp_data_plane_logging == False ) : return
 if 68 - 68: iII111i - I1IiiI / I1Ii111 / I11i
 I11iiii = "miss" if mc == None else "hit!"
 lisp . lprint ( "Fast-Lookup {} {}" . format ( dest . print_address ( ) , I11iiii ) )
 if 60 - 60: I11i . i1IIi + IiII / o0oOOo0O0Ooo . II111iiii
 if 82 - 82: I1ii11iIi11i / I1IiiI % iIii1I11I1II1 / i1IIi - I1IiiI
 if 7 - 7: I1Ii111 * OoO0O00 - ooOoO0o + OOooOOo * I1IiiI % OoO0O00
 if 15 - 15: OoOoOO00 % I1IiiI * I11i
 if 81 - 81: ooOoO0o - iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * I11i
 if 20 - 20: oO0o % IiII
 if 19 - 19: I1ii11iIi11i % IiII + ooOoO0o / I1Ii111 . ooOoO0o
 if 12 - 12: i1IIi + i1IIi - I1ii11iIi11i * Oo0Ooo % Oo0Ooo - II111iiii
def o0O ( ts , msg ) :
 global I1I11I1I1I
 if 84 - 84: OoO0O00 + i1IIi - II111iiii . I1ii11iIi11i * OoooooooOO + I1IiiI
 if ( I1I11I1I1I == False ) : return ( None )
 if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
 if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
 if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
 if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
 if ( ts == None ) : return ( time . time ( ) )
 if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
 if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
 if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
 if 79 - 79: O0 * i11iIiiIii - IiII / IiII
 ts = ( time . time ( ) - ts ) * 1000000
 lisp . lprint ( "{}-Latency: {} usecs" . format ( msg , round ( ts , 1 ) ) , "force" )
 return ( None )
 if 48 - 48: O0
 if 93 - 93: i11iIiiIii - I1IiiI * I1ii11iIi11i * I11i % O0 + OoooooooOO
 if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
 if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
 if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
 if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
 if 19 - 19: OoO0O00 - Oo0Ooo . O0
 if 60 - 60: II111iiii + Oo0Ooo
def I1IiIiiIiIII ( a ) :
 iIIi = ord ( a [ 0 ] ) << 24 | ord ( a [ 1 ] ) << 16 | ord ( a [ 2 ] ) << 8 | ord ( a [ 3 ] )
 return ( iIIi )
 if 11 - 11: I1IiiI * oO0o
 if 81 - 81: iII111i + IiII
 if 98 - 98: I1IiiI
 if 95 - 95: ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 if 41 - 41: i1IIi - I11i - Ii1I
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
iiI1I1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
ooO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
if 6 - 6: iIii1I11I1II1 . ooOoO0o % o0oOOo0O0Ooo
def I1Iii1 ( packet ) :
 global lisp_map_cache , OOo
 if 30 - 30: OoooooooOO - OoOoOO00
 Ooo00O0o = o0O ( None , "Fast" )
 if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
 if 17 - 17: i1IIi
 if 21 - 21: Oo0Ooo
 if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
 I111i1i1111 = 0
 IIII1 = None
 if ( packet [ 9 ] == '\x11' ) :
  if ( packet [ 20 : 22 ] == '\x10\xf6' ) : return ( False )
  if ( packet [ 22 : 24 ] == '\x10\xf6' ) : return ( False )
  if 10 - 10: I1Ii111 / ooOoO0o + i11iIiiIii / Ii1I
  if ( packet [ 20 : 22 ] == '\x10\xf5' or packet [ 22 : 24 ] == '\x10\xf5' ) :
   IIII1 = packet [ 12 : 16 ]
   I111i1i1111 = packet [ 32 : 35 ]
   I111i1i1111 = ord ( I111i1i1111 [ 0 ] ) << 16 | ord ( I111i1i1111 [ 1 ] ) << 8 | ord ( I111i1i1111 [ 2 ] )
   if ( I111i1i1111 == 0xffffff ) : return ( False )
   o00Oo0oooooo ( "Decap" , packet )
   packet = packet [ 36 : : ]
   if 74 - 74: OOooOOo + O0 + i1IIi - i1IIi + II111iiii
   if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
   if 5 - 5: Ii1I
 o00Oo0oooooo ( "Receive" , packet )
 if 46 - 46: IiII
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if 17 - 17: OOooOOo / OOooOOo / I11i
 ii1 = I1IiIiiIiIII ( packet [ 16 : 20 ] )
 ooO . instance_id = I111i1i1111
 ooO . address = ii1
 if 1 - 1: ooOoO0o % iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % I1IiiI
 if 89 - 89: Ii1I
 if 76 - 76: ooOoO0o
 if 15 - 15: OOooOOo . I11i + OoooooooOO - OoO0O00
 if ( ( ii1 & 0xe0000000 ) == 0xe0000000 ) : return ( False )
 if 69 - 69: iIii1I11I1II1 . I1ii11iIi11i % ooOoO0o + iIii1I11I1II1 / O0 / I1ii11iIi11i
 if 61 - 61: OOooOOo % OOooOOo * o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 75 - 75: IiII . ooOoO0o
 if 50 - 50: OoOoOO00
 ii1 = ooO
 O00o0OO0000oo = lisp . lisp_map_cache . lookup_cache ( ii1 , False )
 ii ( ii1 , O00o0OO0000oo )
 if ( O00o0OO0000oo == None ) : return ( False )
 if 27 - 27: O0
 if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
 if 28 - 28: i1IIi - iII111i
 if 54 - 54: iII111i - O0 % OOooOOo
 if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
 if ( IIII1 != None ) :
  I11ii1i1 = I1IiIiiIiIII ( packet [ 12 : 16 ] )
  iiI1I1 . instance_id = I111i1i1111
  iiI1I1 . address = I11ii1i1
  ooo0OoOOOOO = lisp . lisp_map_cache . lookup_cache ( iiI1I1 , False )
  if ( ooo0OoOOOOO == None ) :
   i1iIi1iI , i1I11IiI1iiII , o00oOo0oOoo = lisp . lisp_allow_gleaning ( iiI1I1 , None ,
 None )
   if ( i1iIi1iI ) : return ( False )
  elif ( ooo0OoOOOOO . gleaned ) :
   IIII1 = I1IiIiiIiIII ( IIII1 )
   if ( ooo0OoOOOOO . rloc_set [ 0 ] . rloc . address != IIII1 ) : return ( False )
   if 57 - 57: OoOoOO00 - I1ii11iIi11i
   if 50 - 50: I1Ii111 / i1IIi % OoO0O00 . I1IiiI / iII111i
   if 88 - 88: OOooOOo . I11i * o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . I11i
   if 10 - 10: o0oOOo0O0Ooo * Oo0Ooo % O0 * iIii1I11I1II1 . O0 % I1ii11iIi11i
   if 44 - 44: II111iiii / iII111i / I11i % II111iiii / i1IIi . Ii1I
   if 59 - 59: OoooooooOO
 if ( O00o0OO0000oo . action == lisp . LISP_NATIVE_FORWARD_ACTION and
 O00o0OO0000oo . eid . instance_id == 0 ) :
  ii1 . instance_id = lisp . lisp_default_secondary_iid
  O00o0OO0000oo = lisp . lisp_map_cache . lookup_cache ( ii1 , False )
  ii ( ii1 , O00o0OO0000oo )
  if ( O00o0OO0000oo == None ) : return ( False )
  if 47 - 47: ooOoO0o - I1IiiI / II111iiii
  if 12 - 12: OOooOOo
  if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
  if 100 - 100: OoO0O00
  if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
  if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if ( O00o0OO0000oo . action != lisp . LISP_NATIVE_FORWARD_ACTION ) :
  if ( O00o0OO0000oo . best_rloc_set == [ ] ) : return ( False )
  if 45 - 45: I1Ii111
  ii1 = O00o0OO0000oo . best_rloc_set [ 0 ]
  if ( ii1 . state != lisp . LISP_RLOC_UP_STATE ) : return ( False )
  if 83 - 83: OoOoOO00 . OoooooooOO
  I111i1i1111 = O00o0OO0000oo . eid . instance_id
  OoOO = ii1 . translated_port
  Oo0ooo = ii1 . stats
  ii1 = ii1 . rloc
  IIiIiiii = ii1 . address
  IIII1 = lisp . lisp_myrlocs [ 0 ] . address
  if 89 - 89: iII111i - ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
  if 49 - 49: Oo0Ooo - I1IiiI / IiII / O0 % o0oOOo0O0Ooo * Ii1I
  if 100 - 100: OOooOOo . iII111i / O0 * i1IIi * Ii1I * Oo0Ooo
  if 84 - 84: I1ii11iIi11i / OOooOOo % i11iIiiIii * I1Ii111 % I1ii11iIi11i - OoooooooOO
  OoOoooO = '\x45\x00'
  Ii11 = len ( packet ) + 20 + 8 + 8
  OoOoooO += chr ( ( Ii11 >> 8 ) & 0xff ) + chr ( Ii11 & 0xff )
  OoOoooO += '\xff\xff\x40\x00\x10\x11\x00\x00'
  OoOoooO += chr ( ( IIII1 >> 24 ) & 0xff )
  OoOoooO += chr ( ( IIII1 >> 16 ) & 0xff )
  OoOoooO += chr ( ( IIII1 >> 8 ) & 0xff )
  OoOoooO += chr ( IIII1 & 0xff )
  OoOoooO += chr ( ( IIiIiiii >> 24 ) & 0xff )
  OoOoooO += chr ( ( IIiIiiii >> 16 ) & 0xff )
  OoOoooO += chr ( ( IIiIiiii >> 8 ) & 0xff )
  OoOoooO += chr ( IIiIiiii & 0xff )
  OoOoooO = lisp . lisp_ip_checksum ( OoOoooO )
  if 85 - 85: I1ii11iIi11i . I1Ii111
  if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
  if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
  if 18 - 18: iIii1I11I1II1 % I11i
  O00oO0 = Ii11 - 20
  o0o0o0o0 = '\xff\x00' if ( OoOO == 4341 ) else '\x10\xf5'
  o0o0o0o0 += chr ( ( OoOO >> 8 ) & 0xff ) + chr ( OoOO & 0xff )
  o0o0o0o0 += chr ( ( O00oO0 >> 8 ) & 0xff ) + chr ( O00oO0 & 0xff ) + '\x00\x00'
  if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
  o0o0o0o0 += '\x08\xdf\xdf\xdf'
  o0o0o0o0 += chr ( ( I111i1i1111 >> 16 ) & 0xff )
  o0o0o0o0 += chr ( ( I111i1i1111 >> 8 ) & 0xff )
  o0o0o0o0 += chr ( I111i1i1111 & 0xff )
  o0o0o0o0 += '\x00'
  if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
  if 69 - 69: O0
  if 85 - 85: ooOoO0o / O0
  if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
  packet = OoOoooO + o0o0o0o0 + packet
  o00Oo0oooooo ( "Encap" , packet )
 else :
  Ii11 = len ( packet )
  Oo0ooo = O00o0OO0000oo . stats
  o00Oo0oooooo ( "Send" , packet )
  if 62 - 62: I1Ii111 . IiII . OoooooooOO
  if 11 - 11: OOooOOo / I11i
  if 73 - 73: i1IIi / i11iIiiIii
  if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
  if 85 - 85: OoOoOO00 + OOooOOo
 O00o0OO0000oo . last_refresh_time = time . time ( )
 Oo0ooo . increment ( Ii11 )
 if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
 if 27 - 27: Ii1I
 if 67 - 67: I1IiiI
 if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
 ii1 = ii1 . print_address_no_iid ( )
 OOo . sendto ( packet , ( ii1 , 0 ) )
 if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
 o0O ( Ooo00O0o , "Fast" )
 return ( True )
 if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
def i1i1i1I ( lisp_packet , thread_name ) :
 global II1iII1i , oOoo000 , OooOo00o
 global OOo , Ii1IIii11
 global oO0oIIII
 global iIiiI1
 global oo0Ooo0
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
 Ooo00O0o = o0O ( None , "RTR" )
 if 13 - 13: Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if ( oo0Ooo0 ) :
  if ( I1Iii1 ( lisp_packet . packet ) ) : return
  if 77 - 77: I1Ii111
  if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
  if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
  if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
  if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 O0O0oOOo0O = lisp_packet
 II11 = O0O0oOOo0O . is_lisp_packet ( O0O0oOOo0O . packet )
 if 68 - 68: iII111i * OoooooooOO * iIii1I11I1II1 . II111iiii
 if 81 - 81: OOooOOo / O0 + I11i + Ii1I / I1IiiI
 if 27 - 27: OoOoOO00 * IiII
 if 59 - 59: IiII . IiII - II111iiii + IiII . i1IIi . OoO0O00
 if ( II11 == False ) :
  Oo00OOo = O0O0oOOo0O . packet
  o0o0O , oOO0OooOo , OoOO , I1Ii = lisp . lisp_is_rloc_probe ( Oo00OOo , - 1 )
  if ( Oo00OOo != o0o0O ) :
   if ( oOO0OooOo == None ) : return
   lisp . lisp_parse_packet ( II1iII1i , o0o0O , oOO0OooOo , OoOO , I1Ii )
   return
   if 70 - 70: Oo0Ooo . OoooooooOO - iII111i
   if 30 - 30: I1ii11iIi11i % I1IiiI
   if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
   if 59 - 59: OOooOOo + i11iIiiIii
   if 88 - 88: i11iIiiIii - ooOoO0o
   if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 O0O0oOOo0O . packet = lisp . lisp_reassemble ( O0O0oOOo0O . packet )
 if ( O0O0oOOo0O . packet == None ) : return
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if ( lisp . lisp_flow_logging ) : O0O0oOOo0O = copy . deepcopy ( O0O0oOOo0O )
 if 10 - 10: II111iiii . iII111i
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 if 88 - 88: iII111i
 if 19 - 19: II111iiii * IiII + Ii1I
 if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
 if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
 if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
 if ( II11 ) :
  if ( O0O0oOOo0O . decode ( True , None , lisp . lisp_decap_stats ) == None ) : return
  O0O0oOOo0O . print_packet ( "Receive-({})" . format ( thread_name ) , True )
  O0O0oOOo0O . strip_outer_headers ( )
 else :
  if ( O0O0oOOo0O . decode ( False , None , None ) == None ) : return
  O0O0oOOo0O . print_packet ( "Receive-({})" . format ( thread_name ) , False )
  if 67 - 67: I11i - OOooOOo . i1IIi
  if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
  if 87 - 87: OoOoOO00
  if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
  if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
  if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
  if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
  if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
  if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
  if 93 - 93: Ii1I - OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
  if 49 - 49: OoooooooOO * I11i - Oo0Ooo . oO0o
  if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
 if ( II11 and O0O0oOOo0O . lisp_header . get_instance_id ( ) == 0xffffff ) :
  i11i11 = lisp . lisp_control_header ( )
  i11i11 . decode ( O0O0oOOo0O . packet )
  if ( i11i11 . is_info_request ( ) ) :
   OoOoO00O0 = lisp . lisp_info ( )
   OoOoO00O0 . decode ( O0O0oOOo0O . packet )
   OoOoO00O0 . print_info ( )
   if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
   if 29 - 29: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / iII111i
   if 70 - 70: i11iIiiIii % iII111i
   if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
   if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
   O00oo0ooO = OoOoO00O0 . hostname if ( OoOoO00O0 . hostname != None ) else ""
   iiIii1ii = O0O0oOOo0O . outer_source
   o0o = O0O0oOOo0O . udp_sport
   if ( lisp . lisp_store_nat_info ( O00oo0ooO , iiIii1ii , o0o ) ) :
    o00oo0 ( II1iII1i , O00oo0ooO , iiIii1ii , o0o )
    if 33 - 33: I1Ii111
  else :
   oOO0OooOo = O0O0oOOo0O . outer_source . print_address_no_iid ( )
   I1Ii = O0O0oOOo0O . outer_ttl
   O0O0oOOo0O = O0O0oOOo0O . packet
   if ( lisp . lisp_is_rloc_probe_request ( O0O0oOOo0O [ 28 ] ) == False and
 lisp . lisp_is_rloc_probe_reply ( O0O0oOOo0O [ 28 ] ) == False ) : I1Ii = - 1
   O0O0oOOo0O = O0O0oOOo0O [ 28 : : ]
   lisp . lisp_parse_packet ( II1iII1i , O0O0oOOo0O , oOO0OooOo , 0 , I1Ii )
   if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
  return
  if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
  if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
  if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
  if 45 - 45: IiII
  if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
  if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 34 - 34: O0
  if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
  if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
  if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
  if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 if ( II11 ) :
  lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( O0O0oOOo0O . packet ) )
  if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
  if 91 - 91: oO0o + OoooooooOO - i1IIi
  if 84 - 84: Ii1I / IiII
  if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
  if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 iiii1I1 = None
 if ( O0O0oOOo0O . inner_dest . is_mac ( ) ) :
  O0O0oOOo0O . packet = lisp . lisp_mac_input ( O0O0oOOo0O . packet )
  if ( O0O0oOOo0O . packet == None ) : return
  O0O0oOOo0O . encap_port = lisp . LISP_VXLAN_DATA_PORT
 elif ( O0O0oOOo0O . inner_version == 4 ) :
  iiii1I1 , O0O0oOOo0O . packet = lisp . lisp_ipv4_input ( O0O0oOOo0O . packet )
  if ( O0O0oOOo0O . packet == None ) : return
  O0O0oOOo0O . inner_ttl = O0O0oOOo0O . outer_ttl
 elif ( O0O0oOOo0O . inner_version == 6 ) :
  O0O0oOOo0O . packet = lisp . lisp_ipv6_input ( O0O0oOOo0O )
  if ( O0O0oOOo0O . packet == None ) : return
  O0O0oOOo0O . inner_ttl = O0O0oOOo0O . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 14 - 14: OoOoOO00 * I1IiiI + OoooooooOO - iII111i - IiII
  if 15 - 15: IiII / O0 . o0oOOo0O0Ooo . i11iIiiIii
  if 59 - 59: I1Ii111 - o0oOOo0O0Ooo - ooOoO0o
  if 48 - 48: i1IIi + I11i % OoOoOO00 / Oo0Ooo - o0oOOo0O0Ooo
  if 67 - 67: oO0o % o0oOOo0O0Ooo . OoooooooOO + OOooOOo * I11i * OoOoOO00
 if ( O0O0oOOo0O . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( O0O0oOOo0O , ed = "decap" ) == False ) : return
  O0O0oOOo0O . outer_source . afi = lisp . LISP_AFI_NONE
  O0O0oOOo0O . outer_dest . afi = lisp . LISP_AFI_NONE
  if 36 - 36: O0 + Oo0Ooo
  if 5 - 5: Oo0Ooo * OoOoOO00
  if 46 - 46: ooOoO0o
  if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
  if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
  if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 i1iIi1iI , i1I11IiI1iiII , o00oOo0oOoo = lisp . lisp_allow_gleaning ( O0O0oOOo0O . inner_source , None ,
 O0O0oOOo0O . outer_source )
 if ( i1iIi1iI ) :
  o00O = O0O0oOOo0O . packet if ( iiii1I1 ) else None
  lisp . lisp_glean_map_cache ( O0O0oOOo0O . inner_source , O0O0oOOo0O . outer_source ,
 O0O0oOOo0O . udp_sport , o00O )
  if ( iiii1I1 ) : return
  if 48 - 48: iII111i . i11iIiiIii
  if 5 - 5: oO0o . I1ii11iIi11i . II111iiii . OoooooooOO
  if 96 - 96: i11iIiiIii - OOooOOo % O0 / OoO0O00
  if 100 - 100: iII111i / Ii1I - OoooooooOO % II111iiii - I1IiiI % OoOoOO00
  if 60 - 60: iIii1I11I1II1 + i1IIi
  if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 oOO00O = O0O0oOOo0O . inner_dest
 if ( oOO00O . is_multicast_address ( ) ) :
  ooO000O , i1I11IiI1iiII , o00oOo0oOoo = lisp . lisp_allow_gleaning ( O0O0oOOo0O . inner_source ,
 oOO00O , None )
 else :
  ooO000O , i1I11IiI1iiII , o00oOo0oOoo = lisp . lisp_allow_gleaning ( oOO00O , None , None )
  if 53 - 53: o0oOOo0O0Ooo . iII111i / Ii1I
 O0O0oOOo0O . gleaned_dest = ooO000O
 if 39 - 39: Ii1I % O0 % OoOoOO00 . i1IIi
 if 86 - 86: OoO0O00 * OoooooooOO
 if 71 - 71: iIii1I11I1II1 - OOooOOo . I1IiiI % OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 O00o0OO0000oo = lisp . lisp_map_cache_lookup ( O0O0oOOo0O . inner_source , O0O0oOOo0O . inner_dest )
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 if ( O00o0OO0000oo and ( O00o0OO0000oo . action == lisp . LISP_NATIVE_FORWARD_ACTION or
 O00o0OO0000oo . eid . address == 0 ) ) :
  IiiIIiiiiii = lisp . lisp_db_for_lookups . lookup_cache ( O0O0oOOo0O . inner_source , False )
  if ( IiiIIiiiiii and IiiIIiiiiii . secondary_iid ) :
   OOOO0o = O0O0oOOo0O . inner_dest
   OOOO0o . instance_id = IiiIIiiiiii . secondary_iid
   if 10 - 10: I1Ii111 % I1IiiI
   O00o0OO0000oo = lisp . lisp_map_cache_lookup ( O0O0oOOo0O . inner_source , OOOO0o )
   if ( O00o0OO0000oo ) :
    O0O0oOOo0O . gleaned_dest = O00o0OO0000oo . gleaned
   else :
    ooO000O , i1I11IiI1iiII , o00oOo0oOoo = lisp . lisp_allow_gleaning ( OOOO0o , None ,
 None )
    O0O0oOOo0O . gleaned_dest = ooO000O
    if 97 - 97: OoooooooOO - I1Ii111
    if 58 - 58: iIii1I11I1II1 + O0
    if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
    if 46 - 46: i11iIiiIii - O0 . oO0o
    if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
    if 83 - 83: I1Ii111
    if 48 - 48: II111iiii * OOooOOo * I1Ii111
    if 50 - 50: IiII % i1IIi
    if 21 - 21: OoooooooOO - iIii1I11I1II1
 if ( O00o0OO0000oo == None and ooO000O ) :
  lisp . lprint ( "Suppress Map-Request for gleaned EID {}" . format ( lisp . green ( O0O0oOOo0O . inner_dest . print_address ( ) , False ) ) )
  if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
  return
  if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if ( O00o0OO0000oo == None or O00o0OO0000oo . action == lisp . LISP_SEND_MAP_REQUEST_ACTION ) :
  if ( lisp . lisp_rate_limit_map_request ( O0O0oOOo0O . inner_source ,
 O0O0oOOo0O . inner_dest ) ) : return
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 O0O0oOOo0O . inner_source , O0O0oOOo0O . inner_dest , None )
  if 62 - 62: i1IIi - OoOoOO00
  if ( O0O0oOOo0O . is_trace ( ) ) :
   iiIii1ii = oO0oIIII
   oo0O0oo = "map-cache miss"
   lisp . lisp_trace_append ( O0O0oOOo0O , reason = oo0O0oo , lisp_socket = iiIii1ii )
   if 14 - 14: O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
  return
  if 96 - 96: iII111i
  if 18 - 18: iII111i * I11i - Ii1I
  if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
  if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if ( O00o0OO0000oo and O00o0OO0000oo . is_active ( ) and O00o0OO0000oo . has_ttl_elapsed ( ) and
 O00o0OO0000oo . gleaned == False ) :
  lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( O00o0OO0000oo . print_eid_tuple ( ) , False ) ) )
  if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 O0O0oOOo0O . inner_source , O0O0oOOo0O . inner_dest , None )
  if 23 - 23: II111iiii / oO0o
  if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
  if 19 - 19: I11i
  if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
  if 27 - 27: OOooOOo
  if 89 - 89: II111iiii / oO0o
 O00o0OO0000oo . stats . increment ( len ( O0O0oOOo0O . packet ) )
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 IIiIi1 , Oo00O0ooOO , IiiI , i11ii , i11I1 , o00oO0oOo00 = O00o0OO0000oo . select_rloc ( O0O0oOOo0O , None )
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if ( IIiIi1 == None and i11I1 == None ) :
  if ( i11ii == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   O0O0oOOo0O . send_packet ( OOo , O0O0oOOo0O . inner_dest )
   if 32 - 32: i11iIiiIii - I1Ii111
   if ( O0O0oOOo0O . is_trace ( ) ) :
    iiIii1ii = oO0oIIII
    oo0O0oo = "not an EID"
    lisp . lisp_trace_append ( O0O0oOOo0O , reason = oo0O0oo , lisp_socket = iiIii1ii )
    if 53 - 53: OoooooooOO - IiII
   o0O ( Ooo00O0o , "RTR" )
   return
   if 87 - 87: oO0o . I1IiiI
  oo0O0oo = "No reachable RLOCs found"
  lisp . dprint ( oo0O0oo )
  if 17 - 17: Ii1I . i11iIiiIii
  if ( O0O0oOOo0O . is_trace ( ) ) :
   iiIii1ii = oO0oIIII
   lisp . lisp_trace_append ( O0O0oOOo0O , reason = oo0O0oo , lisp_socket = iiIii1ii )
   if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
  return
  if 63 - 63: oO0o
 if ( IIiIi1 and IIiIi1 . is_null ( ) ) :
  lisp . dprint ( "Drop action RLOC found" )
  if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
  if ( O0O0oOOo0O . is_trace ( ) ) :
   iiIii1ii = oO0oIIII
   oo0O0oo = "drop action"
   lisp . lisp_trace_append ( O0O0oOOo0O , reason = oo0O0oo , lisp_socket = iiIii1ii )
   if 36 - 36: IiII
  return
  if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
  if 74 - 74: I1Ii111 % I1ii11iIi11i
  if 7 - 7: II111iiii
  if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
  if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
 O0O0oOOo0O . outer_tos = O0O0oOOo0O . inner_tos
 O0O0oOOo0O . outer_ttl = O0O0oOOo0O . inner_ttl
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
 if ( IIiIi1 ) :
  O0O0oOOo0O . encap_port = Oo00O0ooOO
  if ( Oo00O0ooOO == 0 ) : O0O0oOOo0O . encap_port = lisp . LISP_DATA_PORT
  O0O0oOOo0O . outer_dest . copy_address ( IIiIi1 )
  o00ooo = O0O0oOOo0O . outer_dest . afi_to_version ( )
  O0O0oOOo0O . outer_version = o00ooo
  if 31 - 31: O0 * o0oOOo0O0Ooo % o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
  III1ii = iIiiI1 if ( o00ooo == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
  O0O0oOOo0O . outer_source . copy_address ( III1ii )
  if 100 - 100: Ii1I + OoO0O00
  if ( O0O0oOOo0O . is_trace ( ) ) :
   iiIii1ii = oO0oIIII
   if ( lisp . lisp_trace_append ( O0O0oOOo0O , rloc_entry = o00oO0oOo00 ,
 lisp_socket = iiIii1ii ) == False ) : return
   if 73 - 73: i1IIi - I1Ii111 % ooOoO0o / OoO0O00
   if 40 - 40: I1ii11iIi11i * ooOoO0o - I1IiiI / IiII / i11iIiiIii
   if 83 - 83: I1ii11iIi11i / I1Ii111 - i11iIiiIii . iIii1I11I1II1 + Oo0Ooo
   if 59 - 59: O0 % Oo0Ooo
   if 92 - 92: Ii1I % iII111i / I1ii11iIi11i % I1ii11iIi11i * I1IiiI
  if ( O0O0oOOo0O . encode ( IiiI ) == None ) : return
  if ( len ( O0O0oOOo0O . packet ) <= 1500 ) : O0O0oOOo0O . print_packet ( "Send" , True )
  if 74 - 74: O0 . I1IiiI % OoO0O00 % IiII
  if 87 - 87: oO0o - i11iIiiIii
  if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
  if 23 - 23: I11i
  iIiiIiiIi = Ii1IIii11 if o00ooo == 6 else OOo
  O0O0oOOo0O . send_packet ( iIiiIiiIi , O0O0oOOo0O . outer_dest )
  if 40 - 40: o0oOOo0O0Ooo
 elif ( i11I1 ) :
  if 78 - 78: iIii1I11I1II1
  if 56 - 56: OoooooooOO - I11i - i1IIi
  if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
  if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
  I11i1iIiiIiIi = len ( O0O0oOOo0O . packet )
  for I1i in i11I1 . rle_forwarding_list :
   O0O0oOOo0O . outer_dest . copy_address ( I1i . address )
   O0O0oOOo0O . encap_port = lisp . LISP_DATA_PORT if I1i . translated_port == 0 else I1i . translated_port
   if 59 - 59: OoooooooOO . Ii1I / O0 - OOooOOo
   if 1 - 1: IiII / IiII - i11iIiiIii
   o00ooo = O0O0oOOo0O . outer_dest . afi_to_version ( )
   O0O0oOOo0O . outer_version = o00ooo
   III1ii = lisp . lisp_myrlocs [ 0 ] if ( o00ooo == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
   O0O0oOOo0O . outer_source . copy_address ( III1ii )
   if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
   if ( O0O0oOOo0O . is_trace ( ) ) :
    iiIii1ii = oO0oIIII
    oo0O0oo = "replicate"
    if ( lisp . lisp_trace_append ( O0O0oOOo0O , reason = oo0O0oo , lisp_socket = iiIii1ii ) == False ) : return
    if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
    if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
    if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
   if ( O0O0oOOo0O . encode ( None ) == None ) : return
   if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
   O0O0oOOo0O . print_packet ( "Replicate-to-L{}" . format ( I1i . level ) , True )
   O0O0oOOo0O . send_packet ( OOo , O0O0oOOo0O . outer_dest )
   if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
   if 77 - 77: OoO0O00 + I1Ii111 + I1Ii111 * Ii1I / OoooooooOO . Ii1I
   if 62 - 62: i1IIi - i1IIi
   if 69 - 69: OoOoOO00 % oO0o - I11i
   if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
   I1IiIiIi1IiI1 = len ( O0O0oOOo0O . packet ) - I11i1iIiiIiIi
   O0O0oOOo0O . packet = O0O0oOOo0O . packet [ I1IiIiIi1IiI1 : : ]
   if 60 - 60: Ii1I * OoOoOO00 - i11iIiiIii % ooOoO0o
   if ( lisp . lisp_flow_logging ) : O0O0oOOo0O = copy . deepcopy ( O0O0oOOo0O )
   if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
   if 30 - 30: iII111i / OoO0O00 + oO0o
   if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
   if 70 - 70: OoO0O00
   if 46 - 46: I11i - i1IIi
   if 46 - 46: I1Ii111 % Ii1I
 del ( O0O0oOOo0O )
 if 72 - 72: iIii1I11I1II1
 o0O ( Ooo00O0o , "RTR" )
 return
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
def ooOo0O0O0oOO0 ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  if 10 - 10: Oo0Ooo + O0
  if 43 - 43: iIii1I11I1II1 / II111iiii % o0oOOo0O0Ooo - OOooOOo
  if 62 - 62: I11i
  if 63 - 63: OOooOOo + ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
  O0O0oOOo0O = lisp_thread . input_queue . get ( )
  if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  if 64 - 64: i1IIi
  if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
  lisp_thread . input_stats . increment ( len ( O0O0oOOo0O ) )
  if 18 - 18: OOooOOo + I1Ii111
  if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
  if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
  lisp_thread . lisp_packet . packet = O0O0oOOo0O
  if 50 - 50: ooOoO0o + i1IIi
  if 31 - 31: Ii1I
  if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
  if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
  i1i1i1I ( lisp_thread . lisp_packet , lisp_thread . thread_name )
  if 47 - 47: o0oOOo0O0Ooo
 return
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
def i1II11Iii1I ( thread ) :
 oO00OoOOOo = ( time . time ( ) % thread . number_of_pcap_threads )
 return ( int ( oO00OoOOOo ) == thread . thread_number )
 if 77 - 77: iIii1I11I1II1 . Ii1I % oO0o / Ii1I
 if 54 - 54: oO0o + ooOoO0o - Oo0Ooo
 if 35 - 35: Ii1I - Ii1I + i1IIi - O0 - I1Ii111
 if 58 - 58: OoOoOO00 - iII111i - OoooooooOO
 if 96 - 96: iIii1I11I1II1
 if 82 - 82: OoOoOO00 + O0 - IiII % oO0o * i11iIiiIii
 if 15 - 15: o0oOOo0O0Ooo
 if 39 - 39: OOooOOo / I1ii11iIi11i / I1IiiI * I1Ii111
def Iii1Ii ( parms , not_used , packet ) :
 if ( i1II11Iii1I ( parms [ 1 ] ) == False ) : return
 if 30 - 30: O0 - iII111i % Oo0Ooo
 O0Oo = parms [ 0 ]
 iIIiI11i = parms [ 1 ]
 Ooo = iIIiI11i . number_of_worker_threads
 if 73 - 73: ooOoO0o + oO0o . OoO0O00
 iIIiI11i . input_stats . increment ( len ( packet ) )
 if 46 - 46: OoO0O00 - o0oOOo0O0Ooo / OoOoOO00 - OoooooooOO + oO0o
 if 58 - 58: o0oOOo0O0Ooo / o0oOOo0O0Ooo + ooOoO0o + I11i - OoOoOO00 . OOooOOo
 if 15 - 15: ooOoO0o * OoOoOO00 % IiII . OoOoOO00 . I11i
 if 97 - 97: oO0o
 if 80 - 80: I1IiiI . Ii1I
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 OOoOoo00Oo = 4 if O0Oo == "lo0" else ( 14 if lisp . lisp_is_macos ( ) else 16 )
 packet = packet [ OOoOoo00Oo : : ]
 if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
 if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if ( Ooo ) :
  i11II = iIIiI11i . input_stats . packet_count % Ooo
  i11II = i11II + ( len ( I11 ) - Ooo )
  o0oo00o0O0O00 = I11 [ i11II ]
  o0oo00o0O0O00 . input_queue . put ( packet )
 else :
  iIIiI11i . lisp_packet . packet = packet
  i1i1i1I ( iIIiI11i . lisp_packet , iIIiI11i . thread_name )
  if 34 - 34: OOooOOo . Oo0Ooo
 return
 if 78 - 78: I1ii11iIi11i % I1IiiI / OoooooooOO % OOooOOo - iII111i
 if 2 - 2: iIii1I11I1II1
 if 45 - 45: OoooooooOO / i11iIiiIii
 if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
 if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
 if 17 - 17: Ii1I
 if 39 - 39: ooOoO0o . II111iiii
 if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
def o00ooOoO0 ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 15 - 15: OOooOOo * I11i / I1ii11iIi11i * o0oOOo0O0Ooo
 O0Oo = "lo0" if lisp . lisp_is_macos ( ) else "any"
 o000Oo0 = pcappy . open_live ( O0Oo , 9000 , 0 , 100 )
 if 82 - 82: I1Ii111 - OOooOOo + OoO0O00
 if 64 - 64: o0oOOo0O0Ooo . O0 * Ii1I + OoooooooOO - Oo0Ooo . OoooooooOO
 if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
 if 55 - 55: iII111i - OoO0O00
 if 100 - 100: O0
 o00 = commands . getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 o00 = ( o00 != "" and o00 [ 0 ] == " " )
 if 46 - 46: iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OoOoOO00 - I1Ii111
 Iii = "(dst host "
 IiI1iI1 = ""
 for oO00OOoO00 in lisp . lisp_get_all_addresses ( ) :
  Iii += "{} or " . format ( oO00OOoO00 )
  IiI1iI1 += "{} or " . format ( oO00OOoO00 )
  if 23 - 23: iII111i + OOooOOo * ooOoO0o / iIii1I11I1II1 - iII111i
 Iii = Iii [ 0 : - 4 ]
 Iii += ") and ((udp dst port 4341 or 8472 or 4789) or "
 Iii += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0))))"
 if 80 - 80: I1IiiI - iIii1I11I1II1 . OOooOOo + OoO0O00 - I1Ii111
 if 5 - 5: iII111i
 if 62 - 62: OoOoOO00 . OoooooooOO . OOooOOo . OoO0O00 * iII111i
 if 78 - 78: oO0o / OoO0O00 - oO0o * OoooooooOO . OoOoOO00
 if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
 if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
 IiI1iI1 = IiI1iI1 [ 0 : - 4 ]
 Iii += ( " or (not (src host {}) and " + "((udp src port 4342 and ip[28] == 0x28) or " + "(udp dst port 4342 and ip[28] == 0x12)))" ) . format ( IiI1iI1 )
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if ( o00 ) :
  Iii += ( " or (dst net 0.0.0.0/0 and " + "not (host {} or src net 127.0.0.0/8))" ) . format ( IiI1iI1 )
  if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
  if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
  if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 lisp . lprint ( "Capturing packets for: '{}'" . format ( Iii ) )
 o000Oo0 . filter = Iii
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 o000Oo0 . loop ( - 1 , Iii1Ii , [ O0Oo , lisp_thread ] )
 return
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
 if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 if 24 - 24: OoOoOO00
def Oo0oOo0ooOOOo ( lisp_raw_socket , eid , geid , igmp ) :
 if 71 - 71: II111iiii - Ii1I - iII111i * O0 * IiII
 if 46 - 46: IiII
 if 29 - 29: II111iiii . OoOoOO00 % o0oOOo0O0Ooo * II111iiii - o0oOOo0O0Ooo * iIii1I11I1II1
 if 35 - 35: II111iiii - IiII . i1IIi
 O0O0oOOo0O = lisp . lisp_packet ( igmp )
 if 95 - 95: I1IiiI + I1IiiI - OOooOOo - iII111i
 if 45 - 45: Ii1I . OoooooooOO
 if 27 - 27: Ii1I * Oo0Ooo . OoOoOO00
 if 17 - 17: II111iiii % iII111i * OOooOOo % i1IIi . I1IiiI . iIii1I11I1II1
 O00o0OO0000oo = lisp . lisp_map_cache_lookup ( eid , geid )
 if ( O00o0OO0000oo == None ) : return
 if ( O00o0OO0000oo . rloc_set == [ ] ) : return
 if ( O00o0OO0000oo . rloc_set [ 0 ] . rle == None ) : return
 if 27 - 27: i11iIiiIii - I1IiiI
 iii1IIiI = eid . print_address_no_iid ( )
 for oO0oOo0 in O00o0OO0000oo . rloc_set [ 0 ] . rle . rle_nodes :
  if ( oO0oOo0 . rloc_name == iii1IIiI ) :
   O0O0oOOo0O . outer_dest . copy_address ( oO0oOo0 . address )
   O0O0oOOo0O . encap_port = oO0oOo0 . translated_port
   break
   if 33 - 33: I11i
   if 98 - 98: OoOoOO00 % II111iiii
 if ( O0O0oOOo0O . outer_dest . is_null ( ) ) : return
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
 O0O0oOOo0O . outer_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 O0O0oOOo0O . outer_version = O0O0oOOo0O . outer_dest . afi_to_version ( )
 O0O0oOOo0O . outer_ttl = 32
 O0O0oOOo0O . inner_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 O0O0oOOo0O . inner_dest . store_address ( "[{}]224.0.0.1" . format ( geid . instance_id ) )
 O0O0oOOo0O . inner_ttl = 1
 if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 iiI111I1iIiI = lisp . green ( eid . print_address ( ) , False )
 oo0O0oo = lisp . red ( "{}:{}" . format ( O0O0oOOo0O . outer_dest . print_address_no_iid ( ) ,
 O0O0oOOo0O . encap_port ) , False )
 oooO00Oo = lisp . bold ( "IGMP Query" , False )
 if 86 - 86: II111iiii + ooOoO0o + IiII
 lisp . lprint ( "Data encapsulate {} to gleaned EID {}, RLOC {}" . format ( oooO00Oo , iiI111I1iIiI , oo0O0oo ) )
 if 9 - 9: ooOoO0o + II111iiii % ooOoO0o % IiII + iIii1I11I1II1
 if 59 - 59: i1IIi
 if 48 - 48: O0 * Ii1I * OoO0O00 . OoO0O00 * I11i - Ii1I
 if 14 - 14: I1ii11iIi11i + i11iIiiIii
 if 83 - 83: I1ii11iIi11i / i11iIiiIii + II111iiii . iII111i * OOooOOo + IiII
 if ( O0O0oOOo0O . encode ( None ) == None ) : return
 O0O0oOOo0O . print_packet ( "Send" , True )
 if 42 - 42: i1IIi % II111iiii . ooOoO0o
 O0O0oOOo0O . send_packet ( lisp_raw_socket , O0O0oOOo0O . outer_dest )
 if 7 - 7: I1ii11iIi11i - oO0o * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i
 if 85 - 85: O0
 if 32 - 32: OoooooooOO . OoO0O00 / Oo0Ooo * o0oOOo0O0Ooo / o0oOOo0O0Ooo * Ii1I
 if 19 - 19: Ii1I
 if 55 - 55: OOooOOo % OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
 if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
 if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
 if 71 - 71: iII111i
 if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
 if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
 if 58 - 58: I1ii11iIi11i
 if 2 - 2: II111iiii / I1Ii111
 if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 if 22 - 22: ooOoO0o . iIii1I11I1II1
 if 12 - 12: Ii1I
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 if 68 - 68: oO0o
def i11iIIiI1I1 ( lisp_raw_socket ) :
 if ( lisp . lisp_gleaned_groups == { } ) : return
 if 4 - 4: Oo0Ooo * Oo0Ooo / OoOoOO00
 if 4 - 4: I1IiiI * OoOoOO00 % I11i . OoOoOO00
 if 11 - 11: OOooOOo - OoOoOO00 - o0oOOo0O0Ooo * OoOoOO00 + ooOoO0o
 if 62 - 62: I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 OooOooO0O0o0 = "\x46\xc0\x00\x24\x00\x00\x40\x00\x01\x02\x00\x00"
 OOO0o0 = lisp . lisp_myrlocs [ 0 ]
 iII1 = OOO0o0 . address
 OooOooO0O0o0 += chr ( ( iII1 >> 24 ) & 0xff )
 OooOooO0O0o0 += chr ( ( iII1 >> 16 ) & 0xff )
 OooOooO0O0o0 += chr ( ( iII1 >> 8 ) & 0xff )
 OooOooO0O0o0 += chr ( iII1 & 0xff )
 OooOooO0O0o0 += "\xe0\x00\x00\x01"
 OooOooO0O0o0 += "\x94\x04\x00\x00"
 OooOooO0O0o0 = lisp . lisp_ip_checksum ( OooOooO0O0o0 , 24 )
 if 34 - 34: I1IiiI % Oo0Ooo - OoOoOO00 + iII111i
 if 79 - 79: II111iiii - ooOoO0o . i1IIi + O0 % O0 * I1IiiI
 if 7 - 7: i1IIi + OOooOOo % iII111i / o0oOOo0O0Ooo + i1IIi
 if 41 - 41: Ii1I + i11iIiiIii / IiII % I1ii11iIi11i
 if 22 - 22: OoOoOO00 % o0oOOo0O0Ooo * Ii1I - I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo
 iiii1I1 = "\x11\x64\x00\x00" + "\x00\x00\x00\x00" + "\x02\x3c\x00\x00"
 iiii1I1 = lisp . lisp_igmp_checksum ( iiii1I1 )
 if 15 - 15: OOooOOo
 if 31 - 31: iII111i / i1IIi . OoO0O00
 if 83 - 83: oO0o / iIii1I11I1II1 + i1IIi / iII111i
 if 47 - 47: oO0o + OoooooooOO . II111iiii . iII111i
 if 66 - 66: ooOoO0o * OoOoOO00
 o0oOO000oO0oo = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 2 - 2: oO0o . I1Ii111 * Oo0Ooo + O0 - I11i * iIii1I11I1II1
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  o0oOO000oO0oo . store_address ( Ii1iIiII1ii1 )
  for II111i1ii1iII in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   i1 . store_address ( II111i1ii1iII )
   i1I11IiI1iiII , o00oOo0oOoo , ooo0OoO = lisp . lisp_allow_gleaning ( o0oOO000oO0oo , i1 , None )
   if ( ooo0OoO == False ) : continue
   Oo0oOo0ooOOOo ( lisp_raw_socket , o0oOO000oO0oo , i1 , OooOooO0O0o0 + iiii1I1 )
   if 50 - 50: I1IiiI * OOooOOo + ooOoO0o
   if 88 - 88: I11i + i11iIiiIii % oO0o * OOooOOo * OOooOOo * Ii1I
   if 24 - 24: ooOoO0o / iII111i + IiII . IiII
   if 39 - 39: ooOoO0o + O0 / i1IIi % IiII / oO0o * IiII
   if 77 - 77: IiII . I1Ii111 % OoOoOO00
   if 42 - 42: IiII % iII111i % o0oOOo0O0Ooo % oO0o + I11i % OoOoOO00
   if 3 - 3: oO0o
   if 64 - 64: OoO0O00 . I1IiiI - OoooooooOO . ooOoO0o - iII111i
   if 77 - 77: Ii1I % OoOoOO00 / II111iiii % iII111i % OoooooooOO % OoO0O00
   if 19 - 19: IiII * I1Ii111 / oO0o * I1Ii111 - OoooooooOO * I11i
def iiiI1i1 ( ) :
 o0oOO000oO0oo = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 44 - 44: OOooOOo + I11i . IiII / II111iiii % iIii1I11I1II1 + IiII
 O0OOo = [ ]
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  for II111i1ii1iII in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   i1I1Iiii1 = lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] [ II111i1ii1iII ]
   O0ooooo000 = time . time ( ) - i1I1Iiii1
   if ( O0ooooo000 < lisp . LISP_IGMP_TIMEOUT_INTERVAL ) : continue
   O0OOo . append ( [ Ii1iIiII1ii1 , II111i1ii1iII ] )
   if 97 - 97: i11iIiiIii % oO0o / Oo0Ooo / Oo0Ooo
   if 97 - 97: II111iiii - I1Ii111 - iIii1I11I1II1 * I1IiiI
   if 54 - 54: iIii1I11I1II1
   if 5 - 5: IiII
   if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
   if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
   if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 i1ii1iiIi1II = lisp . bold ( "timed out" , False )
 for Ii1iIiII1ii1 , II111i1ii1iII in O0OOo :
  o0oOO000oO0oo . store_address ( Ii1iIiII1ii1 )
  i1 . store_address ( II111i1ii1iII )
  iiI111I1iIiI = lisp . green ( Ii1iIiII1ii1 , False )
  OOo000o0 = lisp . green ( II111i1ii1iII , False )
  lisp . lprint ( "{} RLE {} for gleaned group {}" . format ( iiI111I1iIiI , i1ii1iiIi1II , OOo000o0 ) )
  lisp . lisp_remove_gleaned_multicast ( o0oOO000oO0oo , i1 )
  if 69 - 69: ooOoO0o - OoooooooOO * O0
  if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
  if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
  if 96 - 96: OoooooooOO + IiII * O0
  if 86 - 86: Ii1I
  if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
  if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
  if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
def oOOoO0O ( lisp_raw_socket ) :
 lisp . lisp_set_exception ( )
 if 15 - 15: I1Ii111
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 for oOo0oO in lisp . lisp_crypto_keys_by_nonce . values ( ) :
  for O00oo in oOo0oO : del ( O00oo )
  if 75 - 75: iIii1I11I1II1 * i11iIiiIii - OoooooooOO . OoOoOO00
 lisp . lisp_crypto_keys_by_nonce . clear ( )
 lisp . lisp_crypto_keys_by_nonce = { }
 if 70 - 70: oO0o * oO0o + Oo0Ooo * OOooOOo % I1IiiI + iIii1I11I1II1
 if 2 - 2: i11iIiiIii
 if 98 - 98: oO0o / OoO0O00 - Ii1I - I1IiiI / OoOoOO00 + i11iIiiIii
 if 17 - 17: I11i
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 97 - 97: I1ii11iIi11i * I1ii11iIi11i / iII111i
 if 6 - 6: oO0o
 if 72 - 72: I11i * I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 lisp . lisp_rtr_nat_trace_cache . clear ( )
 lisp . lisp_rtr_nat_trace_cache = { }
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 iiiI1i1 ( )
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 i11iIIiI1I1 ( lisp_raw_socket )
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 Oooo0000 = threading . Timer ( 60 , oOOoO0O ,
 [ lisp_raw_socket ] )
 Oooo0000 . start ( )
 return
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
def i111IiiI1Ii ( ) :
 global Oo0oO0oo0oO00 , II1iII1i , II1Ii1iI1i
 global OOo , Ii1IIii11 , I11
 global i111I , oO0oIIII
 global iIiiI1
 if 72 - 72: O0 . OoOoOO00 * Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 lisp . lisp_i_am ( "rtr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "RTR starting up" )
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 iIiiI1 = lisp . lisp_myrlocs [ 0 ]
 if ( lisp . lisp_on_aws ( ) ) :
  iIiiI1 = lisp . lisp_get_interface_address ( "eth0" )
  if 45 - 45: I1IiiI * OOooOOo % OoO0O00
  if 24 - 24: ooOoO0o - I11i * oO0o
  if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
  if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
  if 79 - 79: IiII % OoO0O00
  if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
  if 32 - 32: O0 . OoooooooOO
 iiI = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 II1Ii1iI1i = lisp . lisp_open_listen_socket ( iiI ,
 str ( iiI1iIiI ) )
 Oo0oO0oo0oO00 = lisp . lisp_open_listen_socket ( "" , "lisp-rtr" )
 i111I = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 II1iII1i [ 0 ] = II1Ii1iI1i
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 II1iII1i [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 II1iII1i [ 2 ] = Oo0oO0oo0oO00
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 OOo = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 OOo . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 II1iII1i . append ( OOo )
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 oO0oIIII = lisp . lisp_open_listen_socket ( "0.0.0.0" ,
 str ( lisp . LISP_TRACE_PORT ) )
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  Ii1IIii11 = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
  if 45 - 45: OoooooooOO
 I1 = os . getenv ( "LISP_PCAP_THREADS" )
 I1 = 1 if ( I1 == None ) else int ( I1 )
 oo = os . getenv ( "LISP_WORKER_THREADS" )
 oo = 0 if ( oo == None ) else int ( oo )
 if 17 - 17: O0 - OoOoOO00
 if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
 if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
 if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
 for IIIi in range ( I1 ) :
  III11IiiiIi1 = lisp . lisp_thread ( "pcap-{}" . format ( IIIi ) )
  III11IiiiIi1 . thread_number = IIIi
  III11IiiiIi1 . number_of_pcap_threads = I1
  III11IiiiIi1 . number_of_worker_threads = oo
  I11 . append ( III11IiiiIi1 )
  threading . Thread ( target = o00ooOoO0 , args = [ III11IiiiIi1 ] ) . start ( )
  if 20 - 20: II111iiii - I11i + i1IIi + Ii1I
  if 7 - 7: ooOoO0o + Ii1I
  if 32 - 32: iIii1I11I1II1 % I1IiiI / i11iIiiIii + OOooOOo - o0oOOo0O0Ooo . iII111i
  if 86 - 86: i1IIi / Ii1I * I1IiiI
  if 67 - 67: I1ii11iIi11i * I1ii11iIi11i / oO0o * OoooooooOO + OoOoOO00
  if 79 - 79: i1IIi
 for IIIi in range ( oo ) :
  III11IiiiIi1 = lisp . lisp_thread ( "worker-{}" . format ( IIIi ) )
  I11 . append ( III11IiiiIi1 )
  threading . Thread ( target = ooOo0O0O0oOO0 , args = [ III11IiiiIi1 ] ) . start ( )
  if 1 - 1: oO0o / i1IIi
  if 74 - 74: I11i / OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
  if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
  if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
  if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
 lisp . lisp_load_checkpoint ( )
 if 98 - 98: oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 Oooo0000 = threading . Timer ( 60 , oOOoO0O ,
 [ OOo ] )
 Oooo0000 . start ( )
 return ( True )
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
 if 33 - 33: Ii1I
def ooOOO00oOOooO ( ) :
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if 66 - 66: O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lisp-rtr" )
 lisp . lisp_close_socket ( II1Ii1iI1i , "" )
 lisp . lisp_close_socket ( oO0oIIII , "" )
 lisp . lisp_close_socket ( i111I , "lispers.net-itr" )
 OOo . close ( )
 return
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
 if 28 - 28: iIii1I11I1II1
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 if 46 - 46: OoOoOO00 - O0
def O00Ooo ( kv_pair ) :
 global II1iII1i
 global iiI1iIiI
 if 92 - 92: OoOoOO00 % O0
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 55 - 55: iIii1I11I1II1 * iII111i
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , iiI1iIiI ] )
  lisp . lisp_test_mr_timer . start ( )
  if 85 - 85: iIii1I11I1II1 . II111iiii
 return
 if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
 if 22 - 22: OOooOOo
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
 if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 if 94 - 94: i1IIi
 if 36 - 36: I1IiiI + Oo0Ooo
 if 46 - 46: iII111i
def ooIiI11i1I11111 ( kv_pair ) :
 global II1Ii1iI1i , OOo , iiI1iIiI
 if 34 - 34: I1IiiI * OoOoOO00 * oO0o + I1ii11iIi11i
 II1i = lisp . lisp_rloc_probing
 if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 lispconfig . lisp_xtr_command ( kv_pair )
 if 64 - 64: i1IIi
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 if 25 - 25: II111iiii / OoO0O00
 if 64 - 64: O0 % ooOoO0o
 if 40 - 40: o0oOOo0O0Ooo + I11i
 if ( II1i == False and lisp . lisp_rloc_probing ) :
  i1I = [ II1Ii1iI1i , II1Ii1iI1i ,
 None , OOo ]
  lisp . lisp_start_rloc_probe_timer ( 1 , i1I )
  oO0Oo = { "type" : "itr-crypto-port" , "port" : iiI1iIiI }
  lisp . lisp_write_to_dp_socket ( oO0Oo )
  if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
  if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
  if 47 - 47: OoooooooOO
  if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
  if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
i1Ii11ii1I = {
 "lisp xtr-parameters" : [ ooIiI11i1I11111 , {
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

 "lisp map-resolver" : [ O00Ooo , {
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

 "lisp database-mapping" : [ i11 , {
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

 "lisp glean-mapping" : [ O0O0O , {
 "instance-id" : [ False ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] ,
 "rloc-prefix" : [ True ] ,
 "rloc-probe" : [ True , "yes" , "no" ] ,
 "igmp-query" : [ True , "yes" , "no" ] } ] ,

 "show rtr-rloc-probing" : [ iiI1I11i1i , { } ] ,
 "show rtr-keys" : [ o00oOO0 , { } ] ,
 "show rtr-map-cache" : [ O00oooo0O , { } ] ,
 "show rtr-map-cache-dns" : [ Ii1IOo0o0 , { } ]
 }
if 66 - 66: Oo0Ooo / OoooooooOO % I1Ii111 / iII111i + OoooooooOO
if 6 - 6: II111iiii % I1Ii111
if 41 - 41: IiII - II111iiii . II111iiii + I1IiiI
if 59 - 59: iIii1I11I1II1 % Ii1I . i11iIiiIii
if 59 - 59: o0oOOo0O0Ooo . oO0o . Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
def o0o00OOOO ( lisp_socket ) :
 if 42 - 42: ooOoO0o * iII111i
 if 2 - 2: iII111i . OoO0O00 / oO0o
 if 41 - 41: OoO0O00 . I1Ii111 * IiII * I1Ii111
 if 74 - 74: iIii1I11I1II1 / o0oOOo0O0Ooo
 Oo0o0O0o , oOO0OooOo , OoOO , O0O0oOOo0O = lisp . lisp_receive ( lisp_socket , False )
 iii1IiI1i = lisp . lisp_trace ( )
 if ( iii1IiI1i . decode ( O0O0oOOo0O ) == False ) : return
 if 93 - 93: i1IIi % OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo . O0 % OOooOOo
 if 88 - 88: oO0o % Oo0Ooo - I11i % oO0o + IiII - iII111i
 if 23 - 23: O0
 if 9 - 9: I11i * Oo0Ooo . ooOoO0o * i11iIiiIii - O0
 if 54 - 54: I1IiiI * OOooOOo + o0oOOo0O0Ooo % i1IIi - o0oOOo0O0Ooo + OoOoOO00
 iii1IiI1i . rtr_cache_nat_trace ( oOO0OooOo , OoOO )
 if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
 if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
 if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
 if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
 if 46 - 46: iIii1I11I1II1
 if 70 - 70: i1IIi . I11i
if ( i111IiiI1Ii ( ) == False ) :
 lisp . lprint ( "lisp_rtr_startup() failed" )
 lisp . lisp_print_banner ( "RTR abnormal exit" )
 exit ( 1 )
 if 74 - 74: I11i
 if 58 - 58: iIii1I11I1II1 * OoO0O00 * I1Ii111 * ooOoO0o . OoooooooOO
II1IIiiI1 = [ II1Ii1iI1i , Oo0oO0oo0oO00 ,
 i111I , oO0oIIII ]
O00O00 = [ II1Ii1iI1i ] * 3
if 66 - 66: Oo0Ooo - iIii1I11I1II1
while ( True ) :
 try : iIiIIi11iI , ooo00o0o , i1I11IiI1iiII = select . select ( II1IIiiI1 , [ ] , [ ] )
 except : break
 if 56 - 56: OoOoOO00 % I1ii11iIi11i - Ii1I % iIii1I11I1II1
 if 76 - 76: OoooooooOO * OoooooooOO - iII111i - iIii1I11I1II1 . OoooooooOO / I1ii11iIi11i
 if 86 - 86: ooOoO0o
 if 51 - 51: OoO0O00 - i11iIiiIii * I1IiiI
 if ( lisp . lisp_ipc_data_plane and i111I in iIiIIi11iI ) :
  lisp . lisp_process_punt ( i111I , II1iII1i ,
 iiI1iIiI )
  if 95 - 95: OOooOOo % I1ii11iIi11i + o0oOOo0O0Ooo % ooOoO0o
  if 36 - 36: O0 / i1IIi % II111iiii / iII111i
  if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
  if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 if ( oO0oIIII in iIiIIi11iI ) :
  o0o00OOOO ( oO0oIIII )
  if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
  if 55 - 55: oO0o
  if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
  if 97 - 97: I1Ii111 . I11i / I1IiiI
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
 if ( II1Ii1iI1i in iIiIIi11iI ) :
  Oo0o0O0o , oOO0OooOo , OoOO , O0O0oOOo0O = lisp . lisp_receive ( O00O00 [ 0 ] ,
 False )
  if ( oOO0OooOo == "" ) : break
  if ( lisp . lisp_is_rloc_probe_request ( O0O0oOOo0O [ 0 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
   continue
   if 90 - 90: Oo0Ooo * I1IiiI
  if ( lisp . lisp_is_rloc_probe_reply ( O0O0oOOo0O [ 0 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
   continue
   if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  lisp . lisp_parse_packet ( O00O00 , O0O0oOOo0O , oOO0OooOo , OoOO )
  if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
  if 28 - 28: IiII * I1IiiI % IiII
  if 95 - 95: O0 / I11i . I1Ii111
  if 17 - 17: I11i
  if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
  if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if ( Oo0oO0oo0oO00 in iIiIIi11iI ) :
  Oo0o0O0o , oOO0OooOo , OoOO , O0O0oOOo0O = lisp . lisp_receive ( Oo0oO0oo0oO00 , True )
  if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
  if ( oOO0OooOo == "" ) : break
  if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
  if ( Oo0o0O0o == "command" ) :
   if ( O0O0oOOo0O == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 38 - 38: I1Ii111
   if ( O0O0oOOo0O . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( O0O0oOOo0O )
    continue
    if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
   lispconfig . lisp_process_command ( Oo0oO0oo0oO00 , Oo0o0O0o ,
 O0O0oOOo0O , "lisp-rtr" , [ i1Ii11ii1I ] )
  elif ( Oo0o0O0o == "api" ) :
   lisp . lisp_process_api ( "lisp-rtr" , Oo0oO0oo0oO00 , O0O0oOOo0O )
  elif ( Oo0o0O0o == "data-packet" ) :
   i1i1i1I ( O0O0oOOo0O , "" )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( O0O0oOOo0O [ 0 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
    continue
    if 22 - 22: oO0o * iII111i
   if ( lisp . lisp_is_rloc_probe_reply ( O0O0oOOo0O [ 0 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
    continue
    if 4 - 4: OoOoOO00 - oO0o + I1IiiI
   lisp . lisp_parse_packet ( II1iII1i , O0O0oOOo0O , oOO0OooOo , OoOO )
   if 36 - 36: IiII
   if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
   if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
   if 43 - 43: iIii1I11I1II1 % OoO0O00
ooOOO00oOOooO ( )
lisp . lisp_print_banner ( "RTR normal exit" )
exit ( 0 )
if 84 - 84: Oo0Ooo
if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
