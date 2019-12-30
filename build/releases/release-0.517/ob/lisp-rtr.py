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
  O00o0OO0000oo . add_recent_source ( iiI1I1 )
  if 59 - 59: OoooooooOO
  if 47 - 47: ooOoO0o - I1IiiI / II111iiii
  if 12 - 12: OOooOOo
  if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
  if 100 - 100: OoO0O00
 if ( O00o0OO0000oo . action == lisp . LISP_NATIVE_FORWARD_ACTION and
 O00o0OO0000oo . eid . instance_id == 0 ) :
  ii1 . instance_id = lisp . lisp_default_secondary_iid
  O00o0OO0000oo = lisp . lisp_map_cache . lookup_cache ( ii1 , False )
  ii ( ii1 , O00o0OO0000oo )
  if ( O00o0OO0000oo == None ) : return ( False )
  if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
  if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
  if 45 - 45: I1Ii111
  if 83 - 83: OoOoOO00 . OoooooooOO
  if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
  if 62 - 62: OoO0O00 / I1ii11iIi11i
 if ( O00o0OO0000oo . action != lisp . LISP_NATIVE_FORWARD_ACTION ) :
  if ( O00o0OO0000oo . best_rloc_set == [ ] ) : return ( False )
  if 7 - 7: OoooooooOO . IiII
  ii1 = O00o0OO0000oo . best_rloc_set [ 0 ]
  if ( ii1 . state != lisp . LISP_RLOC_UP_STATE ) : return ( False )
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
  I111i1i1111 = O00o0OO0000oo . eid . instance_id
  OoOO = ii1 . translated_port
  Oooo00 = ii1 . stats
  ii1 = ii1 . rloc
  I111iIi1 = ii1 . address
  IIII1 = lisp . lisp_myrlocs [ 0 ] . address
  if 92 - 92: ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  o00 = '\x45\x00'
  oO = len ( packet ) + 20 + 8 + 8
  o00 += chr ( ( oO >> 8 ) & 0xff ) + chr ( oO & 0xff )
  o00 += '\xff\xff\x40\x00\x10\x11\x00\x00'
  o00 += chr ( ( IIII1 >> 24 ) & 0xff )
  o00 += chr ( ( IIII1 >> 16 ) & 0xff )
  o00 += chr ( ( IIII1 >> 8 ) & 0xff )
  o00 += chr ( IIII1 & 0xff )
  o00 += chr ( ( I111iIi1 >> 24 ) & 0xff )
  o00 += chr ( ( I111iIi1 >> 16 ) & 0xff )
  o00 += chr ( ( I111iIi1 >> 8 ) & 0xff )
  o00 += chr ( I111iIi1 & 0xff )
  o00 = lisp . lisp_ip_checksum ( o00 )
  if 92 - 92: IiII * Oo0Ooo * Oo0Ooo * I1IiiI . iIii1I11I1II1
  if 16 - 16: ooOoO0o % OoooooooOO - OOooOOo * Ii1I * I1ii11iIi11i / OoooooooOO
  if 31 - 31: I11i . I1Ii111 * ooOoO0o + i11iIiiIii * oO0o
  if 93 - 93: I1ii11iIi11i / iIii1I11I1II1 * i1IIi % OoooooooOO * O0 * I11i
  Ooooooo = oO - 20
  I1IIIiI1I1ii1 = '\xff\x00' if ( OoOO == 4341 ) else '\x10\xf5'
  I1IIIiI1I1ii1 += chr ( ( OoOO >> 8 ) & 0xff ) + chr ( OoOO & 0xff )
  I1IIIiI1I1ii1 += chr ( ( Ooooooo >> 8 ) & 0xff ) + chr ( Ooooooo & 0xff ) + '\x00\x00'
  if 30 - 30: O0 * OoooooooOO
  I1IIIiI1I1ii1 += '\x08\xdf\xdf\xdf'
  I1IIIiI1I1ii1 += chr ( ( I111i1i1111 >> 16 ) & 0xff )
  I1IIIiI1I1ii1 += chr ( ( I111i1i1111 >> 8 ) & 0xff )
  I1IIIiI1I1ii1 += chr ( I111i1i1111 & 0xff )
  I1IIIiI1I1ii1 += '\x00'
  if 38 - 38: IiII - I1ii11iIi11i . OoOoOO00 - I1Ii111 . OoooooooOO
  if 89 - 89: iIii1I11I1II1
  if 21 - 21: I11i % I11i
  if 27 - 27: i11iIiiIii / I1ii11iIi11i
  packet = o00 + I1IIIiI1I1ii1 + packet
  o00Oo0oooooo ( "Encap" , packet )
 else :
  oO = len ( packet )
  Oooo00 = O00o0OO0000oo . stats
  o00Oo0oooooo ( "Send" , packet )
  if 84 - 84: Oo0Ooo
  if 43 - 43: oO0o - OoooooooOO
  if 3 - 3: O0 / iII111i
  if 31 - 31: OOooOOo + o0oOOo0O0Ooo . OoooooooOO
  if 89 - 89: II111iiii + i1IIi + II111iiii
 O00o0OO0000oo . last_refresh_time = time . time ( )
 Oooo00 . increment ( oO )
 if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
 if 42 - 42: OoOoOO00 * OoOoOO00 * I1Ii111 . I11i
 if 51 - 51: OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o * iIii1I11I1II1 % OoO0O00
 if 99 - 99: oO0o * II111iiii * I1Ii111
 ii1 = ii1 . print_address_no_iid ( )
 OOo . sendto ( packet , ( ii1 , 0 ) )
 if 92 - 92: Oo0Ooo
 o0O ( Ooo00O0o , "Fast" )
 return ( True )
 if 40 - 40: OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
def IIIii ( lisp_packet , thread_name ) :
 global II1iII1i , O00OooOo00o , IiI11i1IIiiI
 global OOo , Ii1IIii11
 global oO0oIIII
 global iIiiI1
 global oo0Ooo0
 if 60 - 60: I1ii11iIi11i * I1IiiI
 Ooo00O0o = o0O ( None , "RTR" )
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if ( oo0Ooo0 ) :
  if ( I1Iii1 ( lisp_packet . packet ) ) : return
  if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
  if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
  if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
  if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
  if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 Ooooo00o0OoO = lisp_packet
 oooo0O0O0o0 = Ooooo00o0OoO . is_lisp_packet ( Ooooo00o0OoO . packet )
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
 if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
 if ( oooo0O0O0o0 == False ) :
  oOoOOo0oo0 = Ooooo00o0OoO . packet
  o0O0Oo00Oo0o , OOOo , OoOO , oo0OOo0O = lisp . lisp_is_rloc_probe ( oOoOOo0oo0 , - 1 )
  if ( oOoOOo0oo0 != o0O0Oo00Oo0o ) :
   if ( OOOo == None ) : return
   lisp . lisp_parse_packet ( II1iII1i , o0O0Oo00Oo0o , OOOo , OoOO , oo0OOo0O )
   return
   if 39 - 39: OoooooooOO + oO0o % OOooOOo / OOooOOo
   if 27 - 27: iII111i . I11i . iIii1I11I1II1 . iIii1I11I1II1
   if 20 - 20: o0oOOo0O0Ooo / i1IIi
   if 71 - 71: OoOoOO00 . i1IIi
   if 94 - 94: OOooOOo . I1Ii111
   if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 Ooooo00o0OoO . packet = lisp . lisp_reassemble ( Ooooo00o0OoO . packet )
 if ( Ooooo00o0OoO . packet == None ) : return
 if 47 - 47: OoooooooOO
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 if 82 - 82: ooOoO0o + II111iiii
 if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
 if ( lisp . lisp_flow_logging ) : Ooooo00o0OoO = copy . deepcopy ( Ooooo00o0OoO )
 if 68 - 68: Oo0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
 if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
 if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
 if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
 if 98 - 98: i1IIi
 if 65 - 65: OoOoOO00 / OoO0O00 % IiII
 if ( oooo0O0O0o0 ) :
  if ( Ooooo00o0OoO . decode ( True , None , lisp . lisp_decap_stats ) == None ) : return
  Ooooo00o0OoO . print_packet ( "Receive-({})" . format ( thread_name ) , True )
  Ooooo00o0OoO . strip_outer_headers ( )
 else :
  if ( Ooooo00o0OoO . decode ( False , None , None ) == None ) : return
  Ooooo00o0OoO . print_packet ( "Receive-({})" . format ( thread_name ) , False )
  if 45 - 45: OoOoOO00
  if 66 - 66: OoO0O00
  if 56 - 56: O0
  if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
  if 23 - 23: oO0o - OOooOOo + I11i
  if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
  if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
  if 11 - 11: iII111i * Ii1I - OoOoOO00
  if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
  if 74 - 74: Oo0Ooo
  if 61 - 61: Oo0Ooo - I1Ii111 * II111iiii % ooOoO0o * iIii1I11I1II1 + OoO0O00
  if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if ( oooo0O0O0o0 and Ooooo00o0OoO . lisp_header . get_instance_id ( ) == 0xffffff ) :
  II1I1iiIII1I1 = lisp . lisp_control_header ( )
  II1I1iiIII1I1 . decode ( Ooooo00o0OoO . packet )
  if ( II1I1iiIII1I1 . is_info_request ( ) ) :
   o0Ooo0o0ooo0 = lisp . lisp_info ( )
   o0Ooo0o0ooo0 . decode ( Ooooo00o0OoO . packet )
   o0Ooo0o0ooo0 . print_info ( )
   if 70 - 70: i11iIiiIii % iII111i
   if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
   if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
   if 76 - 76: Ii1I - II111iiii * OOooOOo / OoooooooOO
   if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
   ooo = o0Ooo0o0ooo0 . hostname if ( o0Ooo0o0ooo0 . hostname != None ) else ""
   OOOO0oooo = Ooooo00o0OoO . outer_source
   o0o = Ooooo00o0OoO . udp_sport
   if ( lisp . lisp_store_nat_info ( ooo , OOOO0oooo , o0o ) ) :
    o00oo0 ( II1iII1i , ooo , OOOO0oooo , o0o )
    if 51 - 51: O0 - i1IIi / I1IiiI
  else :
   OOOo = Ooooo00o0OoO . outer_source . print_address_no_iid ( )
   oo0OOo0O = Ooooo00o0OoO . outer_ttl
   Ooooo00o0OoO = Ooooo00o0OoO . packet
   if ( lisp . lisp_is_rloc_probe_request ( Ooooo00o0OoO [ 28 ] ) == False and
 lisp . lisp_is_rloc_probe_reply ( Ooooo00o0OoO [ 28 ] ) == False ) : oo0OOo0O = - 1
   Ooooo00o0OoO = Ooooo00o0OoO [ 28 : : ]
   lisp . lisp_parse_packet ( II1iII1i , Ooooo00o0OoO , OOOo , 0 , oo0OOo0O )
   if 37 - 37: o0oOOo0O0Ooo % ooOoO0o
  return
  if 83 - 83: OOooOOo . I1Ii111 + oO0o - OOooOOo * I1Ii111 / I1Ii111
  if 39 - 39: I1Ii111 / Oo0Ooo % OoO0O00 % i11iIiiIii
  if 90 - 90: I1Ii111 - OoooooooOO
  if 96 - 96: O0 . Ii1I % OoO0O00 * iIii1I11I1II1
  if 54 - 54: Ii1I * I1Ii111 - OoooooooOO % I1IiiI + O0
  if 6 - 6: I1ii11iIi11i - II111iiii / oO0o + i11iIiiIii + OOooOOo
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
  if 79 - 79: Ii1I . OoO0O00
  if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
  if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
  if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
 if ( oooo0O0O0o0 ) :
  lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( Ooooo00o0OoO . packet ) )
  if 52 - 52: i1IIi
  if 84 - 84: Ii1I / IiII
  if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
  if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
  if 37 - 37: i11iIiiIii + i1IIi
 I1i11II = None
 if ( Ooooo00o0OoO . inner_dest . is_mac ( ) ) :
  Ooooo00o0OoO . packet = lisp . lisp_mac_input ( Ooooo00o0OoO . packet )
  if ( Ooooo00o0OoO . packet == None ) : return
  Ooooo00o0OoO . encap_port = lisp . LISP_VXLAN_DATA_PORT
 elif ( Ooooo00o0OoO . inner_version == 4 ) :
  I1i11II , Ooooo00o0OoO . packet = lisp . lisp_ipv4_input ( Ooooo00o0OoO . packet )
  if ( Ooooo00o0OoO . packet == None ) : return
  Ooooo00o0OoO . inner_ttl = Ooooo00o0OoO . outer_ttl
 elif ( Ooooo00o0OoO . inner_version == 6 ) :
  Ooooo00o0OoO . packet = lisp . lisp_ipv6_input ( Ooooo00o0OoO )
  if ( Ooooo00o0OoO . packet == None ) : return
  Ooooo00o0OoO . inner_ttl = Ooooo00o0OoO . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 31 - 31: oO0o / IiII * o0oOOo0O0Ooo . II111iiii
  if 89 - 89: O0
  if 2 - 2: I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i * o0oOOo0O0Ooo
  if 100 - 100: Oo0Ooo % Ii1I / I11i
  if 30 - 30: Oo0Ooo - OOooOOo - iII111i
 if ( Ooooo00o0OoO . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( Ooooo00o0OoO , ed = "decap" ) == False ) : return
  Ooooo00o0OoO . outer_source . afi = lisp . LISP_AFI_NONE
  Ooooo00o0OoO . outer_dest . afi = lisp . LISP_AFI_NONE
  if 81 - 81: o0oOOo0O0Ooo . OoooooooOO + OOooOOo * ooOoO0o
  if 74 - 74: i1IIi + O0 + Oo0Ooo
  if 5 - 5: Oo0Ooo * OoOoOO00
  if 46 - 46: ooOoO0o
  if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
  if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 i1iIi1iI , i1I11IiI1iiII , o00oOo0oOoo = lisp . lisp_allow_gleaning ( Ooooo00o0OoO . inner_source , None ,
 Ooooo00o0OoO . outer_source )
 if ( i1iIi1iI ) :
  Ooo = Ooooo00o0OoO . packet if ( I1i11II ) else None
  lisp . lisp_glean_map_cache ( Ooooo00o0OoO . inner_source , Ooooo00o0OoO . outer_source ,
 Ooooo00o0OoO . udp_sport , Ooo )
  if ( I1i11II ) : return
  if 65 - 65: Oo0Ooo / I11i
  if 12 - 12: I11i % OoOoOO00
  if 48 - 48: iII111i . i11iIiiIii
  if 5 - 5: oO0o . I1ii11iIi11i . II111iiii . OoooooooOO
  if 96 - 96: i11iIiiIii - OOooOOo % O0 / OoO0O00
  if 100 - 100: iII111i / Ii1I - OoooooooOO % II111iiii - I1IiiI % OoOoOO00
 oOO00O = Ooooo00o0OoO . inner_dest
 if ( oOO00O . is_multicast_address ( ) ) :
  ooo0OO = False
  i1I11IiI1iiII , o00oOo0oOoo , iIi1IiI = lisp . lisp_allow_gleaning ( Ooooo00o0OoO . inner_source , oOO00O , None )
 else :
  ooo0OO , i1I11IiI1iiII , o00oOo0oOoo = lisp . lisp_allow_gleaning ( oOO00O , None , None )
  if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 Ooooo00o0OoO . gleaned_dest = ooo0OO
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
 O00o0OO0000oo = lisp . lisp_map_cache_lookup ( Ooooo00o0OoO . inner_source , Ooooo00o0OoO . inner_dest )
 if ( O00o0OO0000oo ) : O00o0OO0000oo . add_recent_source ( Ooooo00o0OoO . inner_source )
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 if ( O00o0OO0000oo and ( O00o0OO0000oo . action == lisp . LISP_NATIVE_FORWARD_ACTION or
 O00o0OO0000oo . eid . address == 0 ) ) :
  oo = lisp . lisp_db_for_lookups . lookup_cache ( Ooooo00o0OoO . inner_source , False )
  if ( oo and oo . secondary_iid ) :
   i1II1I = Ooooo00o0OoO . inner_dest
   i1II1I . instance_id = oo . secondary_iid
   if 95 - 95: OoO0O00 - OOooOOo / II111iiii % I1ii11iIi11i . o0oOOo0O0Ooo
   O00o0OO0000oo = lisp . lisp_map_cache_lookup ( Ooooo00o0OoO . inner_source , i1II1I )
   if ( O00o0OO0000oo ) :
    Ooooo00o0OoO . gleaned_dest = O00o0OO0000oo . gleaned
    O00o0OO0000oo . add_recent_source ( Ooooo00o0OoO . inner_source )
   else :
    ooo0OO , i1I11IiI1iiII , o00oOo0oOoo = lisp . lisp_allow_gleaning ( i1II1I , None ,
 None )
    Ooooo00o0OoO . gleaned_dest = ooo0OO
    if 24 - 24: i1IIi . i11iIiiIii
    if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
    if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
    if 81 - 81: iII111i * OOooOOo - I1ii11iIi11i * Ii1I % OoOoOO00 * OoOoOO00
    if 59 - 59: iIii1I11I1II1
    if 7 - 7: OOooOOo * I1IiiI / o0oOOo0O0Ooo * i11iIiiIii
    if 84 - 84: OOooOOo . iII111i
    if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
    if 21 - 21: oO0o / OoooooooOO
 if ( O00o0OO0000oo == None and ooo0OO ) :
  lisp . lprint ( "Suppress Map-Request for gleaned EID {}" . format ( lisp . green ( Ooooo00o0OoO . inner_dest . print_address ( ) , False ) ) )
  if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
  return
  if 87 - 87: I1Ii111 * i1IIi / I1ii11iIi11i
  if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo - OoooooooOO % OOooOOo * OoOoOO00
 if ( O00o0OO0000oo == None or O00o0OO0000oo . action == lisp . LISP_SEND_MAP_REQUEST_ACTION ) :
  if ( lisp . lisp_rate_limit_map_request ( Ooooo00o0OoO . inner_source ,
 Ooooo00o0OoO . inner_dest ) ) : return
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 Ooooo00o0OoO . inner_source , Ooooo00o0OoO . inner_dest , None )
  if 69 - 69: i1IIi
  if ( Ooooo00o0OoO . is_trace ( ) ) :
   OOOO0oooo = oO0oIIII
   ooOoOOOOo = "map-cache miss"
   lisp . lisp_trace_append ( Ooooo00o0OoO , reason = ooOoOOOOo , lisp_socket = OOOO0oooo )
   if 71 - 71: II111iiii * iIii1I11I1II1 / I1ii11iIi11i
  return
  if 23 - 23: II111iiii
  if 24 - 24: iIii1I11I1II1 + iIii1I11I1II1 * iII111i
  if 18 - 18: iII111i * I11i - Ii1I
  if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if ( O00o0OO0000oo and O00o0OO0000oo . refresh ( ) ) :
  lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( O00o0OO0000oo . print_eid_tuple ( ) , False ) ) )
  if 39 - 39: iIii1I11I1II1 - OoooooooOO
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 Ooooo00o0OoO . inner_source , Ooooo00o0OoO . inner_dest , None )
  if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
  if 23 - 23: II111iiii / oO0o
  if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
  if 19 - 19: I11i
  if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
  if 27 - 27: OOooOOo
 O00o0OO0000oo . last_refresh_time = time . time ( )
 O00o0OO0000oo . stats . increment ( len ( Ooooo00o0OoO . packet ) )
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 IIiIiiiIIIIi1 , iIi11 , O00O0 , iIiIiiiIi , i1iiIIi11I , o00oO0oOo00 = O00o0OO0000oo . select_rloc ( Ooooo00o0OoO , None )
 if 80 - 80: ooOoO0o * O0
 if 78 - 78: OoOoOO00
 if ( IIiIiiiIIIIi1 == None and i1iiIIi11I == None ) :
  if ( iIiIiiiIi == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   Ooooo00o0OoO . send_packet ( OOo , Ooooo00o0OoO . inner_dest )
   if 20 - 20: iII111i % Ii1I . Ii1I / I11i + OoOoOO00 . Ii1I
   if ( Ooooo00o0OoO . is_trace ( ) ) :
    OOOO0oooo = oO0oIIII
    ooOoOOOOo = "not an EID"
    lisp . lisp_trace_append ( Ooooo00o0OoO , reason = ooOoOOOOo , lisp_socket = OOOO0oooo )
    if 53 - 53: OOooOOo + I1IiiI / i11iIiiIii - o0oOOo0O0Ooo * oO0o / OoooooooOO
   o0O ( Ooo00O0o , "RTR" )
   return
   if 89 - 89: iIii1I11I1II1 / I1IiiI - II111iiii / Ii1I . i11iIiiIii . Ii1I
  ooOoOOOOo = "No reachable RLOCs found"
  lisp . dprint ( ooOoOOOOo )
  if 48 - 48: O0 + O0 . I1Ii111 - ooOoO0o
  if ( Ooooo00o0OoO . is_trace ( ) ) :
   OOOO0oooo = oO0oIIII
   lisp . lisp_trace_append ( Ooooo00o0OoO , reason = ooOoOOOOo , lisp_socket = OOOO0oooo )
   if 63 - 63: oO0o
  return
  if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if ( IIiIiiiIIIIi1 and IIiIiiiIIIIi1 . is_null ( ) ) :
  lisp . dprint ( "Drop action RLOC found" )
  if 36 - 36: IiII
  if ( Ooooo00o0OoO . is_trace ( ) ) :
   OOOO0oooo = oO0oIIII
   ooOoOOOOo = "drop action"
   lisp . lisp_trace_append ( Ooooo00o0OoO , reason = ooOoOOOOo , lisp_socket = OOOO0oooo )
   if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
  return
  if 74 - 74: I1Ii111 % I1ii11iIi11i
  if 7 - 7: II111iiii
  if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
  if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
  if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 Ooooo00o0OoO . outer_tos = Ooooo00o0OoO . inner_tos
 Ooooo00o0OoO . outer_ttl = Ooooo00o0OoO . inner_ttl
 if 49 - 49: I1ii11iIi11i
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
 if 94 - 94: I11i + II111iiii % i11iIiiIii
 if ( IIiIiiiIIIIi1 ) :
  Ooooo00o0OoO . encap_port = iIi11
  if ( iIi11 == 0 ) : Ooooo00o0OoO . encap_port = lisp . LISP_DATA_PORT
  Ooooo00o0OoO . outer_dest . copy_address ( IIiIiiiIIIIi1 )
  i1i1IiIiIi1Ii = Ooooo00o0OoO . outer_dest . afi_to_version ( )
  Ooooo00o0OoO . outer_version = i1i1IiIiIi1Ii
  if 64 - 64: OOooOOo + OoooooooOO * OoooooooOO
  i1IiiI1I1IIi11i1 = iIiiI1 if ( i1i1IiIiIi1Ii == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 45 - 45: ooOoO0o % o0oOOo0O0Ooo - ooOoO0o
  Ooooo00o0OoO . outer_source . copy_address ( i1IiiI1I1IIi11i1 )
  if 31 - 31: IiII / i11iIiiIii
  if ( Ooooo00o0OoO . is_trace ( ) ) :
   OOOO0oooo = oO0oIIII
   if ( lisp . lisp_trace_append ( Ooooo00o0OoO , rloc_entry = o00oO0oOo00 ,
 lisp_socket = OOOO0oooo ) == False ) : return
   if 83 - 83: I1ii11iIi11i / I1Ii111 - i11iIiiIii . iIii1I11I1II1 + Oo0Ooo
   if 59 - 59: O0 % Oo0Ooo
   if 92 - 92: Ii1I % iII111i / I1ii11iIi11i % I1ii11iIi11i * I1IiiI
   if 74 - 74: O0 . I1IiiI % OoO0O00 % IiII
   if 87 - 87: oO0o - i11iIiiIii
  if ( Ooooo00o0OoO . encode ( O00O0 ) == None ) : return
  if ( len ( Ooooo00o0OoO . packet ) <= 1500 ) : Ooooo00o0OoO . print_packet ( "Send" , True )
  if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
  if 23 - 23: I11i
  if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
  if 14 - 14: I1ii11iIi11i
  iI1 = Ii1IIii11 if i1i1IiIiIi1Ii == 6 else OOo
  Ooooo00o0OoO . send_packet ( iI1 , Ooooo00o0OoO . outer_dest )
  if 14 - 14: I1ii11iIi11i
 elif ( i1iiIIi11I ) :
  if 49 - 49: oO0o / i1IIi % Ii1I . I1IiiI
  if 93 - 93: OOooOOo
  if 43 - 43: I1ii11iIi11i / I1IiiI . ooOoO0o
  if 62 - 62: iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % O0 . I1Ii111
  Oo0oOooOoOo = len ( Ooooo00o0OoO . packet )
  for I1i in i1iiIIi11I . rle_forwarding_list :
   Ooooo00o0OoO . outer_dest . copy_address ( I1i . address )
   Ooooo00o0OoO . encap_port = lisp . LISP_DATA_PORT if I1i . translated_port == 0 else I1i . translated_port
   if 59 - 59: OoooooooOO . Ii1I / O0 - OOooOOo
   if 1 - 1: IiII / IiII - i11iIiiIii
   i1i1IiIiIi1Ii = Ooooo00o0OoO . outer_dest . afi_to_version ( )
   Ooooo00o0OoO . outer_version = i1i1IiIiIi1Ii
   if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
   i1IiiI1I1IIi11i1 = iIiiI1 if ( i1i1IiIiIi1Ii == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
   Ooooo00o0OoO . outer_source . copy_address ( i1IiiI1I1IIi11i1 )
   if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
   if ( Ooooo00o0OoO . is_trace ( ) ) :
    OOOO0oooo = oO0oIIII
    ooOoOOOOo = "replicate"
    if ( lisp . lisp_trace_append ( Ooooo00o0OoO , reason = ooOoOOOOo , lisp_socket = OOOO0oooo ) == False ) : return
    if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
    if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
    if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
   if ( Ooooo00o0OoO . encode ( None ) == None ) : return
   if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
   Ooooo00o0OoO . print_packet ( "Replicate-to-L{}" . format ( I1i . level ) , True )
   Ooooo00o0OoO . send_packet ( OOo , Ooooo00o0OoO . outer_dest )
   if 77 - 77: OoO0O00 + I1Ii111 + I1Ii111 * Ii1I / OoooooooOO . Ii1I
   if 62 - 62: i1IIi - i1IIi
   if 69 - 69: OoOoOO00 % oO0o - I11i
   if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
   if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
   OO00OO0o0 = len ( Ooooo00o0OoO . packet ) - Oo0oOooOoOo
   Ooooo00o0OoO . packet = Ooooo00o0OoO . packet [ OO00OO0o0 : : ]
   if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
   if ( lisp . lisp_flow_logging ) : Ooooo00o0OoO = copy . deepcopy ( Ooooo00o0OoO )
   if 30 - 30: iII111i / OoO0O00 + oO0o
   if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
   if 70 - 70: OoO0O00
   if 46 - 46: I11i - i1IIi
   if 46 - 46: I1Ii111 % Ii1I
   if 72 - 72: iIii1I11I1II1
 del ( Ooooo00o0OoO )
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 o0O ( Ooo00O0o , "RTR" )
 return
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 if 84 - 84: i11iIiiIii * OoO0O00
def I1I1iII1i ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  if 30 - 30: O0 + I1ii11iIi11i + II111iiii
  if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
  if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
  if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
  Ooooo00o0OoO = lisp_thread . input_queue . get ( )
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  if 64 - 64: i1IIi
  if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
  if 18 - 18: OOooOOo + I1Ii111
  lisp_thread . input_stats . increment ( len ( Ooooo00o0OoO ) )
  if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
  if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
  if 50 - 50: ooOoO0o + i1IIi
  lisp_thread . lisp_packet . packet = Ooooo00o0OoO
  if 31 - 31: Ii1I
  if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
  if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
  if 47 - 47: o0oOOo0O0Ooo
  IIIii ( lisp_thread . lisp_packet , lisp_thread . thread_name )
  if 66 - 66: I1IiiI - IiII
 return
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
def o00Ooo0 ( thread ) :
 O0O00O = ( time . time ( ) % thread . number_of_pcap_threads )
 return ( int ( O0O00O ) == thread . thread_number )
 if 4 - 4: OoOoOO00 + Ii1I / oO0o
 if 13 - 13: iII111i
 if 80 - 80: Ii1I - o0oOOo0O0Ooo
 if 41 - 41: o0oOOo0O0Ooo - Oo0Ooo * I1IiiI
 if 82 - 82: OoO0O00 % o0oOOo0O0Ooo % OOooOOo / O0
 if 94 - 94: I1ii11iIi11i + I1ii11iIi11i + OoooooooOO % ooOoO0o
 if 7 - 7: iII111i
 if 78 - 78: OOooOOo + iII111i . IiII
def Oo ( parms , not_used , packet ) :
 if ( o00Ooo0 ( parms [ 1 ] ) == False ) : return
 if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
 I1Iii1I = parms [ 0 ]
 iIi11I = parms [ 1 ]
 O0Oo = iIi11I . number_of_worker_threads
 if 39 - 39: OOooOOo - OoooooooOO + Oo0Ooo
 iIi11I . input_stats . increment ( len ( packet ) )
 if 93 - 93: ooOoO0o . iIii1I11I1II1 % i11iIiiIii . OoOoOO00 % ooOoO0o + O0
 if 65 - 65: Ii1I + OoO0O00 - OoooooooOO
 if 51 - 51: Oo0Ooo + oO0o / iII111i - i1IIi
 if 51 - 51: Oo0Ooo - I1ii11iIi11i * I11i
 if 12 - 12: iIii1I11I1II1 % ooOoO0o % ooOoO0o
 if 78 - 78: IiII . OoOoOO00 . I11i
 o0ooO0OOO = 4 if I1Iii1I == "lo0" else ( 14 if lisp . lisp_is_macos ( ) else 16 )
 packet = packet [ o0ooO0OOO : : ]
 if 74 - 74: Ii1I * i11iIiiIii / I1Ii111
 if 75 - 75: O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
 if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
 if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
 if ( O0Oo ) :
  oo0 = iIi11I . input_stats . packet_count % O0Oo
  oo0 = oo0 + ( len ( I11 ) - O0Oo )
  i1iIIi1II1iiI = I11 [ oo0 ]
  i1iIIi1II1iiI . input_queue . put ( packet )
 else :
  iIi11I . lisp_packet . packet = packet
  IIIii ( iIi11I . lisp_packet , iIi11I . thread_name )
  if 31 - 31: o0oOOo0O0Ooo % I11i + iIii1I11I1II1 + i11iIiiIii * I1Ii111
 return
 if 45 - 45: OOooOOo * I1Ii111 . ooOoO0o - I1Ii111 + IiII
 if 34 - 34: OOooOOo . Oo0Ooo
 if 78 - 78: I1ii11iIi11i % I1IiiI / OoooooooOO % OOooOOo - iII111i
 if 2 - 2: iIii1I11I1II1
 if 45 - 45: OoooooooOO / i11iIiiIii
 if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
 if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
 if 17 - 17: Ii1I
def i1i1IiIi1 ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 22 - 22: I11i * O0 . II111iiii - OoO0O00
 I1Iii1I = "lo0" if lisp . lisp_is_macos ( ) else "any"
 o0Oo00OO0 = pcappy . open_live ( I1Iii1I , 9000 , 0 , 100 )
 if 50 - 50: Ii1I * o0oOOo0O0Ooo % i11iIiiIii
 if 96 - 96: I1ii11iIi11i + Oo0Ooo * OoO0O00 % ooOoO0o - O0
 if 54 - 54: OoOoOO00 . oO0o % i11iIiiIii / OoooooooOO + IiII % oO0o
 if 36 - 36: oO0o
 if 74 - 74: OoooooooOO
 OoOoO0O = commands . getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 OoOoO0O = ( OoOoO0O != "" and OoOoO0O [ 0 ] == " " )
 if 100 - 100: O0
 o00IiI1iiII1i1i = "(dst host "
 i1IiI = ""
 for oO00OOoO00 in lisp . lisp_get_all_addresses ( ) :
  o00IiI1iiII1i1i += "{} or " . format ( oO00OOoO00 )
  i1IiI += "{} or " . format ( oO00OOoO00 )
  if 82 - 82: OoOoOO00
 o00IiI1iiII1i1i = o00IiI1iiII1i1i [ 0 : - 4 ]
 o00IiI1iiII1i1i += ") and ((udp dst port 4341 or 8472 or 4789) or "
 o00IiI1iiII1i1i += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0))))"
 if 80 - 80: OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
 if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
 if 2 - 2: OoooooooOO . OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 i1IiI = i1IiI [ 0 : - 4 ]
 o00IiI1iiII1i1i += ( " or (not (src host {}) and " + "((udp src port 4342 and ip[28] == 0x28) or " + "(udp dst port 4342 and ip[28] == 0x12)))" ) . format ( i1IiI )
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if ( OoOoO0O ) :
  o00IiI1iiII1i1i += ( " or (dst net 0.0.0.0/0 and " + "not (host {} or src net 127.0.0.0/8))" ) . format ( i1IiI )
  if 28 - 28: OOooOOo % ooOoO0o
  if 48 - 48: i11iIiiIii % oO0o
  if 29 - 29: iII111i + i11iIiiIii % I11i
 lisp . lprint ( "Capturing packets for: '{}'" . format ( o00IiI1iiII1i1i ) )
 o0Oo00OO0 . filter = o00IiI1iiII1i1i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 o0Oo00OO0 . loop ( - 1 , Oo , [ I1Iii1I , lisp_thread ] )
 return
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
 if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
def O0OOO0 ( lisp_raw_socket , eid , geid , igmp ) :
 if 8 - 8: i11iIiiIii / II111iiii + o0oOOo0O0Ooo * Ii1I % IiII . I11i
 if 6 - 6: IiII % Oo0Ooo . Oo0Ooo - I1ii11iIi11i / I11i . i1IIi
 if 99 - 99: OoOoOO00 . I1Ii111
 if 59 - 59: I11i / Oo0Ooo / OOooOOo / O0 / OoOoOO00 + o0oOOo0O0Ooo
 Ooooo00o0OoO = lisp . lisp_packet ( igmp )
 if 13 - 13: o0oOOo0O0Ooo % oO0o / I1Ii111 % I1Ii111 % O0
 if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 O00o0OO0000oo = lisp . lisp_map_cache_lookup ( eid , geid )
 if ( O00o0OO0000oo == None ) : return
 if ( O00o0OO0000oo . rloc_set == [ ] ) : return
 if ( O00o0OO0000oo . rloc_set [ 0 ] . rle == None ) : return
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 oO00o = eid . print_address_no_iid ( )
 for oO0oOo0 in O00o0OO0000oo . rloc_set [ 0 ] . rle . rle_nodes :
  if ( oO0oOo0 . rloc_name == oO00o ) :
   Ooooo00o0OoO . outer_dest . copy_address ( oO0oOo0 . address )
   Ooooo00o0OoO . encap_port = oO0oOo0 . translated_port
   break
   if 36 - 36: I1Ii111 . II111iiii % ooOoO0o
   if 84 - 84: OoooooooOO - i11iIiiIii / iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i
 if ( Ooooo00o0OoO . outer_dest . is_null ( ) ) : return
 if 4 - 4: Oo0Ooo + o0oOOo0O0Ooo
 Ooooo00o0OoO . outer_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 Ooooo00o0OoO . outer_version = Ooooo00o0OoO . outer_dest . afi_to_version ( )
 Ooooo00o0OoO . outer_ttl = 32
 Ooooo00o0OoO . inner_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 Ooooo00o0OoO . inner_dest . store_address ( "[{}]224.0.0.1" . format ( geid . instance_id ) )
 Ooooo00o0OoO . inner_ttl = 1
 if 17 - 17: OoO0O00 * OoOoOO00
 iiI111I1iIiI = lisp . green ( eid . print_address ( ) , False )
 ooOoOOOOo = lisp . red ( "{}:{}" . format ( Ooooo00o0OoO . outer_dest . print_address_no_iid ( ) ,
 Ooooo00o0OoO . encap_port ) , False )
 ii11i = lisp . bold ( "IGMP Query" , False )
 if 71 - 71: I1Ii111 / I1ii11iIi11i * iIii1I11I1II1
 lisp . lprint ( "Data encapsulate {} to gleaned EID {}, RLOC {}" . format ( ii11i , iiI111I1iIiI , ooOoOOOOo ) )
 if 57 - 57: OOooOOo + I1Ii111 % I1ii11iIi11i . OoO0O00 / OoO0O00 * O0
 if 6 - 6: i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 if 68 - 68: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 - I1Ii111
 if 37 - 37: IiII
 if ( Ooooo00o0OoO . encode ( None ) == None ) : return
 Ooooo00o0OoO . print_packet ( "Send" , True )
 if 37 - 37: Oo0Ooo / IiII * O0
 Ooooo00o0OoO . send_packet ( lisp_raw_socket , Ooooo00o0OoO . outer_dest )
 if 73 - 73: iII111i * iII111i / ooOoO0o
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 if 83 - 83: o0oOOo0O0Ooo
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if 48 - 48: iII111i + IiII
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 if 14 - 14: OOooOOo
 if 79 - 79: Ii1I
 if 76 - 76: iIii1I11I1II1
 if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
 if 93 - 93: OoooooooOO * Oo0Ooo
 if 10 - 10: I1Ii111 * OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i11iIiiIii
 if 22 - 22: I1Ii111 / o0oOOo0O0Ooo
 if 98 - 98: i1IIi
 if 51 - 51: I1ii11iIi11i + ooOoO0o + Oo0Ooo / i1IIi + i1IIi
 if 12 - 12: iIii1I11I1II1 . Ii1I . I1ii11iIi11i % I1IiiI . II111iiii . oO0o
def IIi1ii1 ( lisp_raw_socket ) :
 if ( lisp . lisp_gleaned_groups == { } ) : return
 if 48 - 48: ooOoO0o / iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . OoO0O00
 if 60 - 60: I1Ii111
 if 98 - 98: ooOoO0o
 if 34 - 34: iIii1I11I1II1 * I11i * I11i / I1ii11iIi11i
 if 28 - 28: OoO0O00 - oO0o + OoOoOO00 + Ii1I / iIii1I11I1II1
 iiiii11I1 = "\x46\xc0\x00\x24\x00\x00\x40\x00\x01\x02\x00\x00"
 Ii1 = lisp . lisp_myrlocs [ 0 ]
 iII1 = Ii1 . address
 iiiii11I1 += chr ( ( iII1 >> 24 ) & 0xff )
 iiiii11I1 += chr ( ( iII1 >> 16 ) & 0xff )
 iiiii11I1 += chr ( ( iII1 >> 8 ) & 0xff )
 iiiii11I1 += chr ( iII1 & 0xff )
 iiiii11I1 += "\xe0\x00\x00\x01"
 iiiii11I1 += "\x94\x04\x00\x00"
 iiiii11I1 = lisp . lisp_ip_checksum ( iiiii11I1 , 24 )
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 I1i11II = "\x11\x64\x00\x00" + "\x00\x00\x00\x00" + "\x02\x3c\x00\x00"
 I1i11II = lisp . lisp_igmp_checksum ( I1i11II )
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 o0oOO000oO0oo = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  o0oOO000oO0oo . store_address ( Ii1iIiII1ii1 )
  for iI1ii11Ii in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   i1 . store_address ( iI1ii11Ii )
   i1I11IiI1iiII , o00oOo0oOoo , O0OO0OO = lisp . lisp_allow_gleaning ( o0oOO000oO0oo , i1 , None )
   if ( O0OO0OO == False ) : continue
   O0OOO0 ( lisp_raw_socket , o0oOO000oO0oo , i1 , iiiii11I1 + I1i11II )
   if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
   if 84 - 84: i1IIi
   if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
   if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
   if 81 - 81: IiII / OoOoOO00 * IiII . O0
   if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
   if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
   if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
   if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
   if 61 - 61: I1Ii111 - Ii1I % I1ii11iIi11i / ooOoO0o / iII111i + iIii1I11I1II1
def O0O0oo ( ) :
 o0oOO000oO0oo = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 83 - 83: IiII / I1Ii111
 OOo000OO000 = [ ]
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  for iI1ii11Ii in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   OOOO00OooO = lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] [ iI1ii11Ii ]
   OOO = time . time ( ) - OOOO00OooO
   if ( OOO < lisp . LISP_IGMP_TIMEOUT_INTERVAL ) : continue
   OOo000OO000 . append ( [ Ii1iIiII1ii1 , iI1ii11Ii ] )
   if 32 - 32: OoooooooOO
   if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
   if 80 - 80: OoooooooOO + IiII
   if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
   if 43 - 43: Oo0Ooo . I1Ii111
   if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
   if 29 - 29: IiII . ooOoO0o - II111iiii
 ooooO0 = lisp . bold ( "timed out" , False )
 for Ii1iIiII1ii1 , iI1ii11Ii in OOo000OO000 :
  o0oOO000oO0oo . store_address ( Ii1iIiII1ii1 )
  i1 . store_address ( iI1ii11Ii )
  iiI111I1iIiI = lisp . green ( Ii1iIiII1ii1 , False )
  Iiii111 = lisp . green ( iI1ii11Ii , False )
  lisp . lprint ( "{} RLE {} for gleaned group {}" . format ( iiI111I1iIiI , ooooO0 , Iiii111 ) )
  lisp . lisp_remove_gleaned_multicast ( o0oOO000oO0oo , i1 )
  if 71 - 71: O0 / I1IiiI . I1Ii111 / I1Ii111 * ooOoO0o
  if 60 - 60: II111iiii . I1IiiI - Oo0Ooo + I1ii11iIi11i * I1ii11iIi11i
  if 27 - 27: IiII * I1IiiI . iIii1I11I1II1 - iIii1I11I1II1
  if 5 - 5: IiII
  if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
  if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
  if 71 - 71: I1Ii111 * Oo0Ooo . I11i
  if 49 - 49: IiII * O0 . IiII
def ii1II1II ( lisp_raw_socket ) :
 lisp . lisp_set_exception ( )
 if 42 - 42: Ii1I
 if 68 - 68: OOooOOo . Oo0Ooo % ooOoO0o - OoooooooOO * iII111i . OOooOOo
 if 46 - 46: i11iIiiIii - OOooOOo * I1IiiI * I11i % I1ii11iIi11i * i1IIi
 if 5 - 5: O0 / ooOoO0o . Oo0Ooo + OoooooooOO
 for oOo0oO in lisp . lisp_crypto_keys_by_nonce . values ( ) :
  for O0o in oOo0oO : del ( O0o )
  if 78 - 78: OOooOOo % iIii1I11I1II1
 lisp . lisp_crypto_keys_by_nonce . clear ( )
 lisp . lisp_crypto_keys_by_nonce = { }
 if 50 - 50: I1IiiI % iIii1I11I1II1 % OOooOOo
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if 69 - 69: OoOoOO00
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 lisp . lisp_rtr_nat_trace_cache . clear ( )
 lisp . lisp_rtr_nat_trace_cache = { }
 if 88 - 88: o0oOOo0O0Ooo
 if 1 - 1: OoooooooOO
 if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 O0O0oo ( )
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 IIi1ii1 ( lisp_raw_socket )
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 Oooo0000 = threading . Timer ( 60 , ii1II1II ,
 [ lisp_raw_socket ] )
 Oooo0000 . start ( )
 return
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
def iIIi1Ii1III ( ) :
 global Oo0oO0oo0oO00 , II1iII1i , II1Ii1iI1i
 global OOo , Ii1IIii11 , I11
 global i111I , oO0oIIII
 global iIiiI1
 if 86 - 86: i11iIiiIii + i11iIiiIii . I1Ii111 % I1IiiI . ooOoO0o
 lisp . lisp_i_am ( "rtr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "RTR starting up" )
 if 17 - 17: Ii1I
 if 67 - 67: O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 iIiiI1 = lisp . lisp_myrlocs [ 0 ]
 if ( lisp . lisp_on_aws ( ) ) :
  iIiiI1 = lisp . lisp_get_interface_address ( "eth0" )
  if 72 - 72: I1IiiI / iII111i - O0 + I11i
  if 83 - 83: O0
  if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
  if 40 - 40: OoO0O00 + OoO0O00
  if 94 - 94: iII111i * iIii1I11I1II1 . I11i
  if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
  if 41 - 41: I1ii11iIi11i
 i1iI1i = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 II1Ii1iI1i = lisp . lisp_open_listen_socket ( i1iI1i ,
 str ( iiI1iIiI ) )
 Oo0oO0oo0oO00 = lisp . lisp_open_listen_socket ( "" , "lisp-rtr" )
 i111I = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 if 59 - 59: IiII
 II1iII1i [ 0 ] = II1Ii1iI1i
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 II1iII1i [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 II1iII1i [ 2 ] = Oo0oO0oo0oO00
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 if 24 - 24: ooOoO0o - I11i * oO0o
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 OOo = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 OOo . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 II1iII1i . append ( OOo )
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 oO0oIIII = lisp . lisp_open_listen_socket ( "0.0.0.0" ,
 str ( lisp . LISP_TRACE_PORT ) )
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  Ii1IIii11 = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
  if 56 - 56: oO0o + ooOoO0o
 Ii1Ii1 = os . getenv ( "LISP_PCAP_THREADS" )
 Ii1Ii1 = 1 if ( Ii1Ii1 == None ) else int ( Ii1Ii1 )
 ii1IiI11I = os . getenv ( "LISP_WORKER_THREADS" )
 ii1IiI11I = 0 if ( ii1IiI11I == None ) else int ( ii1IiI11I )
 if 90 - 90: o0oOOo0O0Ooo % oO0o % i11iIiiIii . OOooOOo % OOooOOo
 if 36 - 36: Oo0Ooo % Ii1I / i11iIiiIii % I1Ii111 + OoO0O00
 if 23 - 23: II111iiii
 if 93 - 93: oO0o . I11i / i1IIi
 for i11ii in range ( Ii1Ii1 ) :
  oOOOOO0Ooooo = lisp . lisp_thread ( "pcap-{}" . format ( i11ii ) )
  oOOOOO0Ooooo . thread_number = i11ii
  oOOOOO0Ooooo . number_of_pcap_threads = Ii1Ii1
  oOOOOO0Ooooo . number_of_worker_threads = ii1IiI11I
  I11 . append ( oOOOOO0Ooooo )
  threading . Thread ( target = i1i1IiIi1 , args = [ oOOOOO0Ooooo ] ) . start ( )
  if 57 - 57: Ii1I - OoooooooOO
  if 68 - 68: o0oOOo0O0Ooo % I1ii11iIi11i / I1Ii111 + I1Ii111 - I1Ii111 . OoO0O00
  if 100 - 100: OoOoOO00 % Oo0Ooo
  if 76 - 76: II111iiii / OoO0O00 + OoooooooOO . I1ii11iIi11i . I11i . ooOoO0o
  if 43 - 43: i1IIi
  if 17 - 17: O0 - OoOoOO00
 for i11ii in range ( ii1IiI11I ) :
  oOOOOO0Ooooo = lisp . lisp_thread ( "worker-{}" . format ( i11ii ) )
  I11 . append ( oOOOOO0Ooooo )
  threading . Thread ( target = I1I1iII1i , args = [ oOOOOO0Ooooo ] ) . start ( )
  if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
  if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
  if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
  if 10 - 10: I1ii11iIi11i / i11iIiiIii - Ii1I + oO0o * I1IiiI
  if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
 lisp . lisp_load_checkpoint ( )
 if 64 - 64: I11i + OoO0O00
 if 25 - 25: I1IiiI . ooOoO0o + I1IiiI % Ii1I * iIii1I11I1II1
 if 31 - 31: i11iIiiIii + OOooOOo - O0
 if 51 - 51: OoO0O00 * i1IIi / Ii1I * OOooOOo + ooOoO0o % I1ii11iIi11i
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 34 - 34: oO0o * OoooooooOO + Ii1I + i11iIiiIii
 if 22 - 22: i1IIi
 if 24 - 24: I11i / I1IiiI * i1IIi % OoooooooOO
 if 99 - 99: i11iIiiIii . II111iiii . OoooooooOO
 Oooo0000 = threading . Timer ( 60 , ii1II1II ,
 [ OOo ] )
 Oooo0000 . start ( )
 return ( True )
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
 if 98 - 98: oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
def OoIi1I1I ( ) :
 if 56 - 56: O0
 if 45 - 45: OoOoOO00 - OoO0O00 - OoOoOO00
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lisp-rtr" )
 lisp . lisp_close_socket ( II1Ii1iI1i , "" )
 lisp . lisp_close_socket ( oO0oIIII , "" )
 lisp . lisp_close_socket ( i111I , "lispers.net-itr" )
 OOo . close ( )
 return
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
 if 33 - 33: Ii1I
def ooOOO00oOOooO ( kv_pair ) :
 global II1iII1i
 global iiI1iIiI
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 66 - 66: O0
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , iiI1iIiI ] )
  lisp . lisp_test_mr_timer . start ( )
  if 52 - 52: OoO0O00 * OoooooooOO
 return
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
 if 28 - 28: iIii1I11I1II1
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 if 46 - 46: OoOoOO00 - O0
def O00Ooo ( kv_pair ) :
 global II1Ii1iI1i , OOo , iiI1iIiI
 if 92 - 92: OoOoOO00 % O0
 oo00ooooOOo00 = lisp . lisp_rloc_probing
 if 16 - 16: i11iIiiIii / i1IIi % OOooOOo
 if 84 - 84: I11i - Oo0Ooo * O0 / Ii1I . Ii1I
 if 93 - 93: O0 / ooOoO0o + I1IiiI
 if 20 - 20: IiII / iII111i % OoooooooOO / iIii1I11I1II1 + I1IiiI
 lispconfig . lisp_xtr_command ( kv_pair )
 if 57 - 57: o0oOOo0O0Ooo / I1Ii111
 if 13 - 13: OoooooooOO + OoO0O00
 if 32 - 32: O0 + oO0o % Oo0Ooo
 if 7 - 7: I1ii11iIi11i / ooOoO0o
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if ( oo00ooooOOo00 == False and lisp . lisp_rloc_probing ) :
  i1I = [ II1Ii1iI1i , II1Ii1iI1i ,
 None , OOo ]
  lisp . lisp_start_rloc_probe_timer ( 1 , i1I )
  oO0Oo = { "type" : "itr-crypto-port" , "port" : iiI1iIiI }
  lisp . lisp_write_to_dp_socket ( oO0Oo )
  if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
  if 65 - 65: ooOoO0o - i1IIi
  if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
  if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  if 34 - 34: I1Ii111 - OOooOOo
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if 64 - 64: i1IIi
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 if 25 - 25: II111iiii / OoO0O00
 if 64 - 64: O0 % ooOoO0o
iI1111i = {
 "lisp xtr-parameters" : [ O00Ooo , {
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

 "lisp map-resolver" : [ ooOOO00oOOooO , {
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
if 39 - 39: I1Ii111 % OoooooooOO - II111iiii % OoOoOO00 + oO0o + O0
if 14 - 14: OoooooooOO . o0oOOo0O0Ooo . I11i
if 50 - 50: ooOoO0o * OoOoOO00 + I1ii11iIi11i - i11iIiiIii + Oo0Ooo * I1ii11iIi11i
if 20 - 20: I1Ii111 / o0oOOo0O0Ooo % OoOoOO00
if 69 - 69: I1Ii111 - i1IIi % iII111i . OOooOOo - OOooOOo
if 65 - 65: OOooOOo + II111iiii
def Oo0O0OO0OoO0 ( lisp_socket ) :
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 O0oO0oo0O , OOOo , OoOO , Ooooo00o0OoO = lisp . lisp_receive ( lisp_socket , False )
 oooOOO0ooOoOOO = lisp . lisp_trace ( )
 if ( oooOOO0ooOoOOO . decode ( Ooooo00o0OoO ) == False ) : return
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo
 if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 oooOOO0ooOoOOO . rtr_cache_nat_trace ( OOOo , OoOO )
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
 if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
 if 37 - 37: iII111i
 if 33 - 33: OoO0O00 - O0 - OoO0O00
 if 94 - 94: IiII * I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - o0oOOo0O0Ooo
 if 13 - 13: OOooOOo / IiII - OoO0O00 / OOooOOo . i1IIi
if ( iIIi1Ii1III ( ) == False ) :
 lisp . lprint ( "lisp_rtr_startup() failed" )
 lisp . lisp_print_banner ( "RTR abnormal exit" )
 exit ( 1 )
 if 22 - 22: O0 - I11i + I1Ii111 . Ii1I * i1IIi
 if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
I11III11III1 = [ II1Ii1iI1i , Oo0oO0oo0oO00 ,
 i111I , oO0oIIII ]
oooOoO00OooO0 = [ II1Ii1iI1i ] * 3
if 98 - 98: OOooOOo + Ii1I
while ( True ) :
 try : OOOO , IIIIiI11Ii1i , i1I11IiI1iiII = select . select ( I11III11III1 , [ ] , [ ] )
 except : break
 if 100 - 100: iII111i + I11i + ooOoO0o + iII111i / i1IIi
 if 74 - 74: O0 % OoooooooOO * Oo0Ooo + OOooOOo * iII111i
 if 100 - 100: OOooOOo + Ii1I * o0oOOo0O0Ooo + II111iiii
 if 70 - 70: Oo0Ooo * iIii1I11I1II1
 if ( lisp . lisp_ipc_data_plane and i111I in OOOO ) :
  lisp . lisp_process_punt ( i111I , II1iII1i ,
 iiI1iIiI )
  if 76 - 76: iII111i % OoOoOO00 % iIii1I11I1II1 . OOooOOo
  if 30 - 30: i1IIi
  if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
  if 93 - 93: ooOoO0o
  if 18 - 18: ooOoO0o
 if ( oO0oIIII in OOOO ) :
  Oo0O0OO0OoO0 ( oO0oIIII )
  if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
  if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
  if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
  if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
  if 58 - 58: O0
 if ( II1Ii1iI1i in OOOO ) :
  O0oO0oo0O , OOOo , OoOO , Ooooo00o0OoO = lisp . lisp_receive ( oooOoO00OooO0 [ 0 ] ,
 False )
  if ( OOOo == "" ) : break
  if ( lisp . lisp_is_rloc_probe_request ( Ooooo00o0OoO [ 0 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
   continue
   if 91 - 91: iII111i / I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I1ii11iIi11i
  if ( lisp . lisp_is_rloc_probe_reply ( Ooooo00o0OoO [ 0 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
   continue
   if 72 - 72: Ii1I . IiII * I1ii11iIi11i / I1ii11iIi11i / iII111i
  lisp . lisp_parse_packet ( oooOoO00OooO0 , Ooooo00o0OoO , OOOo , OoOO )
  if 13 - 13: i1IIi
  if 17 - 17: i11iIiiIii * o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoO0O00
  if 95 - 95: I1IiiI
  if 95 - 95: OOooOOo % I1ii11iIi11i + o0oOOo0O0Ooo % ooOoO0o
  if 36 - 36: O0 / i1IIi % II111iiii / iII111i
  if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
 if ( Oo0oO0oo0oO00 in OOOO ) :
  O0oO0oo0O , OOOo , OoOO , Ooooo00o0OoO = lisp . lisp_receive ( Oo0oO0oo0oO00 , True )
  if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
  if ( OOOo == "" ) : break
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
  if ( O0oO0oo0O == "command" ) :
   if ( Ooooo00o0OoO == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
   if ( Ooooo00o0OoO . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( Ooooo00o0OoO )
    continue
    if 55 - 55: oO0o
   lispconfig . lisp_process_command ( Oo0oO0oo0oO00 , O0oO0oo0O ,
 Ooooo00o0OoO , "lisp-rtr" , [ iI1111i ] )
  elif ( O0oO0oo0O == "api" ) :
   lisp . lisp_process_api ( "lisp-rtr" , Oo0oO0oo0oO00 , Ooooo00o0OoO )
  elif ( O0oO0oo0O == "data-packet" ) :
   IIIii ( Ooooo00o0OoO , "" )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( Ooooo00o0OoO [ 0 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
    continue
    if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
   if ( lisp . lisp_is_rloc_probe_reply ( Ooooo00o0OoO [ 0 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
    continue
    if 97 - 97: I1Ii111 . I11i / I1IiiI
   lisp . lisp_parse_packet ( II1iII1i , Ooooo00o0OoO , OOOo , OoOO )
   if 83 - 83: I11i - I1ii11iIi11i * oO0o
   if 90 - 90: Oo0Ooo * I1IiiI
   if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
   if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
OoIi1I1I ( )
lisp . lisp_print_banner ( "RTR normal exit" )
exit ( 0 )
if 28 - 28: IiII * I1IiiI % IiII
if 95 - 95: O0 / I11i . I1Ii111
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
