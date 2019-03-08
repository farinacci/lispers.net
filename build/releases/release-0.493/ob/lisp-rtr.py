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
II1Ii1iI1i = lisp . lisp_get_ephemeral_port ( )
iiI1iIiI = None
OOo = None
Ii1IIii11 = None
if 55 - 55: iIii1I11I1II1 - I1IiiI . Ii1I * IiII * i1IIi / iIii1I11I1II1
OOo000 = [ ]
if 82 - 82: I11i . I1Ii111 / IiII % II111iiii % iIii1I11I1II1 % IiII
if 86 - 86: OoOoOO00 % I1IiiI
if 80 - 80: OoooooooOO . I1IiiI
if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
if 58 - 58: i11iIiiIii % I1Ii111
if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
def i11IiIiiIIIII ( parameter ) :
 global OOo000
 if 22 - 22: Ii1I * O0 / o0oOOo0O0Ooo
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "RTR" ,
 OOo000 ) )
 if 64 - 64: Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
 if 78 - 78: OoO0O00
 if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
 if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
 if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
def i1iIIIiI1I ( parameter ) :
 global OOo000
 if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "RTR" , OOo000 ,
 True ) )
 if 23 - 23: i11iIiiIii + I1IiiI
 if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
 if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
 if 33 - 33: Ii1I + II111iiii % i11iIiiIii . ooOoO0o - I1IiiI
 if 66 - 66: Ii1I - OoooooooOO * OoooooooOO . OOooOOo . I1ii11iIi11i
 if 22 - 22: OoooooooOO % I11i - iII111i . iIii1I11I1II1 * i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
def o0OOOOO00o0O0 ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "RTR" ) )
 if 71 - 71: ooOoO0o % iII111i / o0oOOo0O0Ooo
 if 49 - 49: II111iiii % iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
 if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo
def oO00 ( kv_pair ) :
 lispconfig . lisp_database_mapping_command ( kv_pair )
 if 53 - 53: OoooooooOO . i1IIi
 if 18 - 18: o0oOOo0O0Ooo
 if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % oO0o . O0
 if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
 if 53 - 53: IiII + I1IiiI * oO0o
 if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
def o00O ( parameter ) :
 return ( lispconfig . lisp_itr_rtr_show_rloc_probe_command ( "RTR" ) )
 if 69 - 69: oO0o % I1Ii111 - o0oOOo0O0Ooo + I1Ii111 - O0 % OoooooooOO
 if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 if 4 - 4: II111iiii / ooOoO0o . iII111i
 if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 if 50 - 50: I1IiiI
 if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
 if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
def II1i1IiiIIi11 ( mc , parms ) :
 iI1Ii11iII1 , Oo0O0O0ooO0O , IIIIii , O0o0 = parms
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
 oO0OOoO0 = "{}:{}" . format ( Oo0O0O0ooO0O . print_address_no_iid ( ) , IIIIii )
 I111Ii111 = lisp . green ( mc . print_eid_tuple ( ) , False )
 i111IiI1I = "Changed '{}' translated address:port to {} for EID {}, {} {}" . format ( O0o0 , lisp . red ( oO0OOoO0 , False ) , I111Ii111 , "{}" , "{}" )
 if 70 - 70: Ii1I . Oo0Ooo / o0oOOo0O0Ooo . Ii1I - O0 / IiII
 if 62 - 62: iIii1I11I1II1 * OoOoOO00
 for i1 in mc . rloc_set :
  if ( i1 . rle ) :
   for OOO in i1 . rle . rle_nodes :
    if ( OOO . rloc_name != O0o0 ) : continue
    OOO . store_translated_rloc ( Oo0O0O0ooO0O , IIIIii )
    Oo0oOOo = OOO . address . print_address_no_iid ( ) + ":" + str ( OOO . translated_port )
    if 58 - 58: II111iiii * OOooOOo * I1ii11iIi11i / OOooOOo
    lisp . lprint ( i111IiI1I . format ( "RLE" , Oo0oOOo ) )
    if 75 - 75: oO0o
    if 50 - 50: Ii1I / Oo0Ooo - oO0o - I11i % iII111i - oO0o
    if 91 - 91: OoO0O00 / I11i - II111iiii . I11i
  if ( i1 . rloc_name != O0o0 ) : continue
  if 18 - 18: o0oOOo0O0Ooo
  if 98 - 98: iII111i * iII111i / iII111i + I11i
  if 34 - 34: ooOoO0o
  if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
  if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
  if 92 - 92: iII111i . I1Ii111
  Oo0oOOo = i1 . rloc . print_address_no_iid ( ) + ":" + str ( i1 . translated_port )
  if 31 - 31: I1Ii111 . OoOoOO00 / O0
  if ( lisp . lisp_crypto_keys_by_rloc_encap . has_key ( Oo0oOOo ) ) :
   o000O0o = lisp . lisp_crypto_keys_by_rloc_encap [ Oo0oOOo ]
   lisp . lisp_crypto_keys_by_rloc_encap [ oO0OOoO0 ] = o000O0o
   if 42 - 42: OoOoOO00
   if 41 - 41: Oo0Ooo . ooOoO0o + O0 * o0oOOo0O0Ooo % Oo0Ooo * Oo0Ooo
   if 19 - 19: iII111i
   if 46 - 46: I1ii11iIi11i - Ii1I . iIii1I11I1II1 / I1ii11iIi11i
   if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
  i1 . delete_from_rloc_probe_list ( mc . eid , mc . group )
  i1 . store_translated_rloc ( Oo0O0O0ooO0O , IIIIii )
  i1 . add_to_rloc_probe_list ( mc . eid , mc . group )
  lisp . lprint ( i111IiI1I . format ( "RLOC" , Oo0oOOo ) )
  if 13 - 13: OOooOOo / i11iIiiIii
  if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
  if 52 - 52: o0oOOo0O0Ooo
  if 95 - 95: Ii1I
  if ( lisp . lisp_rloc_probing ) :
   O0oOO0O = None if ( mc . group . is_null ( ) ) else mc . eid
   oO = mc . eid if ( mc . group . is_null ( ) ) else mc . group
   lisp . lisp_send_map_request ( iI1Ii11iII1 , 0 , O0oOO0O , oO , i1 )
   if 7 - 7: o0oOOo0O0Ooo - I1IiiI
   if 100 - 100: oO0o + I11i . OOooOOo * Ii1I
   if 73 - 73: i1IIi + I1IiiI
   if 46 - 46: OoO0O00 . Oo0Ooo - OoooooooOO
   if 93 - 93: iII111i
   if 10 - 10: I11i
 lisp . lisp_write_ipc_map_cache ( True , mc )
 return ( True , parms )
 if 82 - 82: I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
 if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 if 83 - 83: I11i / I1IiiI
 if 34 - 34: IiII
 if 57 - 57: oO0o . I11i . i1IIi
 if 42 - 42: I11i + I1ii11iIi11i % O0
def i1iIIIi1i ( mc , parms ) :
 if 43 - 43: OoOoOO00 % OOooOOo
 if 5 - 5: i11iIiiIii - i1IIi / iIii1I11I1II1
 if 26 - 26: I11i . OoooooooOO
 if 39 - 39: iII111i - O0 % i11iIiiIii * I1Ii111 . IiII
 if ( mc . group . is_null ( ) ) : return ( II1i1IiiIIi11 ( mc , parms ) )
 if 58 - 58: OoO0O00 % i11iIiiIii . iII111i / oO0o
 if ( mc . source_cache == None ) : return ( True , parms )
 if 84 - 84: iII111i . I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
 mc . source_cache . walk_cache ( II1i1IiiIIi11 , parms )
 return ( True , parms )
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % I1Ii111
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
def i1I1iI1iIi111i ( sockets , hostname , rloc , port ) :
 lisp . lisp_map_cache . walk_cache ( i1iIIIi1i ,
 [ sockets , rloc , port , hostname ] )
 return
 if 44 - 44: i1IIi % II111iiii + I11i
 if 45 - 45: iII111i / iII111i + I1Ii111 + ooOoO0o
 if 47 - 47: o0oOOo0O0Ooo + ooOoO0o
 if 82 - 82: II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
 if 77 - 77: iIii1I11I1II1 * OoO0O00
 if 95 - 95: I1IiiI + i11iIiiIii
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
def O0O ( lisp_packet , thread_name ) :
 global II1iII1i , i1I1I , iiI1I
 global iiI1iIiI , OOo
 if 12 - 12: i11iIiiIii - i1IIi - OoO0O00 . i1IIi - OOooOOo + O0
 oO0OOOO0 = lisp_packet
 if 26 - 26: Ii1I
 if 35 - 35: Ii1I - I1IiiI % o0oOOo0O0Ooo . OoooooooOO % Ii1I
 if 47 - 47: iII111i - Ii1I . II111iiii + OoooooooOO . i11iIiiIii
 if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 oO0 = oO0OOOO0 . packet
 O0OO0O = oO0
 O0OO0O , OO , IIIIii , OoOoO = lisp . lisp_is_rloc_probe ( O0OO0O , - 1 )
 if ( oO0 != O0OO0O ) :
  if ( OO == None ) : return
  lisp . lisp_parse_packet ( II1iII1i , O0OO0O , OO , IIIIii , OoOoO )
  return
  if 43 - 43: i11iIiiIii + Oo0Ooo * II111iiii * I1Ii111 * O0
  if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
  if 79 - 79: O0
  if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
  if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 oO0OOOO0 . packet = lisp . lisp_reassemble ( oO0OOOO0 . packet )
 if ( oO0OOOO0 . packet == None ) : return
 if 57 - 57: OoO0O00 / ooOoO0o
 if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
 if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
 if 13 - 13: Ii1I . i11iIiiIii
 if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 if ( lisp . lisp_flow_logging ) : oO0OOOO0 = copy . deepcopy ( oO0OOOO0 )
 if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 if ( oO0OOOO0 . decode ( True , None , lisp . lisp_decap_stats ) == None ) : return
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 oO0OOOO0 . print_packet ( "Receive-({})" . format ( thread_name ) , True )
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 if 49 - 49: I1IiiI - I11i
 if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
 oO0OOOO0 . strip_outer_headers ( )
 if 62 - 62: OoooooooOO * I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if 97 - 97: O0 + OoOoOO00
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
 if 71 - 71: Oo0Ooo % OOooOOo
 if ( oO0OOOO0 . lisp_header . get_instance_id ( ) == 0xffffff ) :
  O00oO000O0O = lisp . lisp_control_header ( )
  O00oO000O0O . decode ( oO0OOOO0 . packet )
  if ( O00oO000O0O . is_info_request ( ) ) :
   I1i1i1iii = lisp . lisp_info ( )
   I1i1i1iii . decode ( oO0OOOO0 . packet )
   I1i1i1iii . print_info ( )
   if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
   if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
   if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
   if 71 - 71: I1Ii111 + Ii1I
   if 28 - 28: OOooOOo
   I11ii1IIiIi = I1i1i1iii . hostname if ( I1i1i1iii . hostname != None ) else ""
   OoOOo0OOoO = oO0OOOO0 . outer_source
   ooO0O00Oo0o = oO0OOOO0 . udp_sport
   if ( lisp . lisp_store_nat_info ( I11ii1IIiIi , OoOOo0OOoO , ooO0O00Oo0o ) ) :
    i1I1iI1iIi111i ( II1iII1i , I11ii1IIiIi , OoOOo0OOoO , ooO0O00Oo0o )
    if 65 - 65: I1ii11iIi11i . I11i - I1Ii111 * IiII / I1Ii111 / ooOoO0o
  else :
   OO = oO0OOOO0 . outer_source . print_address_no_iid ( )
   OoOoO = oO0OOOO0 . outer_ttl
   oO0OOOO0 = oO0OOOO0 . packet
   if ( lisp . lisp_is_rloc_probe_request ( oO0OOOO0 [ 28 ] ) == False and
 lisp . lisp_is_rloc_probe_reply ( oO0OOOO0 [ 28 ] ) == False ) : OoOoO = - 1
   oO0OOOO0 = oO0OOOO0 [ 28 : : ]
   lisp . lisp_parse_packet ( II1iII1i , oO0OOOO0 , OO , 0 , OoOoO )
   if 40 - 40: ooOoO0o * IiII * i11iIiiIii
  return
  if 57 - 57: ooOoO0o
  if 29 - 29: OoOoOO00 - IiII * OoooooooOO + OoooooooOO . II111iiii + OoooooooOO
  if 74 - 74: Ii1I - IiII / iII111i * O0 - OOooOOo
  if 19 - 19: I1IiiI
  if 25 - 25: Ii1I / ooOoO0o
  if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 71 - 71: I1Ii111 . II111iiii
  if 62 - 62: OoooooooOO . I11i
  if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
  if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 58 - 58: I1IiiI
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( oO0OOOO0 . packet ) )
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if ( oO0OOOO0 . inner_dest . is_mac ( ) ) :
  oO0OOOO0 . packet = lisp . lisp_mac_input ( oO0OOOO0 . packet )
  if ( oO0OOOO0 . packet == None ) : return
  oO0OOOO0 . encap_port = lisp . LISP_VXLAN_DATA_PORT
 elif ( oO0OOOO0 . inner_version == 4 ) :
  oO0OOOO0 . packet = lisp . lisp_ipv4_input ( oO0OOOO0 . packet )
  if ( oO0OOOO0 . packet == None ) : return
  oO0OOOO0 . inner_ttl = oO0OOOO0 . outer_ttl
 elif ( oO0OOOO0 . inner_version == 6 ) :
  oO0OOOO0 . packet = lisp . lisp_ipv6_input ( oO0OOOO0 )
  if ( oO0OOOO0 . packet == None ) : return
  oO0OOOO0 . inner_ttl = oO0OOOO0 . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
  if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
  if 23 - 23: i11iIiiIii
  if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
  if 81 - 81: IiII % i1IIi . iIii1I11I1II1
 if ( oO0OOOO0 . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( oO0OOOO0 , "decap" ) == False ) : return
  oO0OOOO0 . outer_source . afi = lisp . LISP_AFI_NONE
  oO0OOOO0 . outer_dest . afi = lisp . LISP_AFI_NONE
  if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
  if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
  if 31 - 31: OOooOOo
  if 23 - 23: I1Ii111 . IiII
  if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
 i1I1i1 = lisp . lisp_map_cache_lookup ( oO0OOOO0 . inner_source , oO0OOOO0 . inner_dest )
 if 81 - 81: ooOoO0o - iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * I11i
 if 20 - 20: oO0o % IiII
 if 19 - 19: I1ii11iIi11i % IiII + ooOoO0o / I1Ii111 . ooOoO0o
 if 12 - 12: i1IIi + i1IIi - I1ii11iIi11i * Oo0Ooo % Oo0Ooo - II111iiii
 if 52 - 52: ooOoO0o . iII111i + I1Ii111
 if ( i1I1i1 and ( i1I1i1 . action == lisp . LISP_NATIVE_FORWARD_ACTION or
 i1I1i1 . eid . address == 0 ) ) :
  iiii1IIi = lisp . lisp_db_for_lookups . lookup_cache ( oO0OOOO0 . inner_source , False )
  if ( iiii1IIi and iiii1IIi . secondary_iid ) :
   iII1i11IIi1i = oO0OOOO0 . inner_dest
   iII1i11IIi1i . instance_id = iiii1IIi . secondary_iid
   i1I1i1 = lisp . lisp_map_cache_lookup ( oO0OOOO0 . inner_source , iII1i11IIi1i )
   if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
   if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
   if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
   if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
   if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
   if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
 if ( i1I1i1 == None or i1I1i1 . action == lisp . LISP_SEND_MAP_REQUEST_ACTION ) :
  if ( lisp . lisp_rate_limit_map_request ( oO0OOOO0 . inner_source ,
 oO0OOOO0 . inner_dest ) ) : return
  lisp . lisp_send_map_request ( II1iII1i , II1Ii1iI1i ,
 oO0OOOO0 . inner_source , oO0OOOO0 . inner_dest , None )
  if 79 - 79: O0 * i11iIiiIii - IiII / IiII
  if ( oO0OOOO0 . is_trace ( ) ) : lisp . lisp_trace_append ( oO0OOOO0 )
  return
  if 48 - 48: O0
  if 93 - 93: i11iIiiIii - I1IiiI * I1ii11iIi11i * I11i % O0 + OoooooooOO
  if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
  if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
  if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
  if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
 if ( i1I1i1 and i1I1i1 . is_active ( ) and i1I1i1 . has_ttl_elapsed ( ) ) :
  lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( i1I1i1 . print_eid_tuple ( ) , False ) ) )
  if 19 - 19: OoO0O00 - Oo0Ooo . O0
  lisp . lisp_send_map_request ( II1iII1i , II1Ii1iI1i ,
 oO0OOOO0 . inner_source , oO0OOOO0 . inner_dest , None )
  if 60 - 60: II111iiii + Oo0Ooo
  if 9 - 9: ooOoO0o * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
  if 49 - 49: II111iiii
  if 25 - 25: OoooooooOO - I1IiiI . I1IiiI * oO0o
  if 81 - 81: iII111i + IiII
  if 98 - 98: I1IiiI
 i1I1i1 . stats . increment ( len ( oO0OOOO0 . packet ) )
 if 95 - 95: ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 if 41 - 41: i1IIi - I11i - Ii1I
 III11I1 , IIi1IIIi , O00Ooo , OOOO0OOO , i1i1ii = i1I1i1 . select_rloc ( oO0OOOO0 , None )
 if 46 - 46: OoOoOO00 + OoO0O00
 if ( III11I1 == None and i1i1ii == None ) :
  if ( OOOO0OOO == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   oO0OOOO0 . send_packet ( iiI1iIiI , oO0OOOO0 . inner_dest )
   if ( oO0OOOO0 . is_trace ( ) ) : lisp . lisp_trace_append ( oO0OOOO0 )
   return
   if 70 - 70: iII111i / iIii1I11I1II1
  lisp . dprint ( "No reachable RLOCs found" )
  if ( oO0OOOO0 . is_trace ( ) ) : lisp . lisp_trace_append ( oO0OOOO0 )
  return
  if 85 - 85: OoooooooOO % i1IIi * OoooooooOO / I1ii11iIi11i
 if ( III11I1 and III11I1 . is_null ( ) ) :
  lisp . dprint ( "Drop action RLOC found" )
  if ( oO0OOOO0 . is_trace ( ) ) : lisp . lisp_trace_append ( oO0OOOO0 )
  return
  if 96 - 96: OoooooooOO + oO0o
  if 44 - 44: oO0o
  if 20 - 20: I11i + Ii1I / O0 % iIii1I11I1II1
  if 88 - 88: OoOoOO00 / II111iiii
  if 87 - 87: I1ii11iIi11i - I1ii11iIi11i - iII111i + oO0o
 oO0OOOO0 . outer_tos = oO0OOOO0 . inner_tos
 oO0OOOO0 . outer_ttl = oO0OOOO0 . inner_ttl
 if 82 - 82: oO0o / iIii1I11I1II1 . I1IiiI . OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 if 46 - 46: Oo0Ooo
 if ( III11I1 ) :
  oO0OOOO0 . encap_port = IIi1IIIi
  if ( IIi1IIIi == 0 ) : oO0OOOO0 . encap_port = lisp . LISP_DATA_PORT
  oO0OOOO0 . outer_dest . copy_address ( III11I1 )
  i1II1I1Iii1 = oO0OOOO0 . outer_dest . afi_to_version ( )
  oO0OOOO0 . outer_version = i1II1I1Iii1
  iiI11Iii = lisp . lisp_myrlocs [ 0 ] if ( i1II1I1Iii1 == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 78 - 78: iII111i + I11i . ooOoO0o - iII111i . Ii1I
  oO0OOOO0 . outer_source . copy_address ( iiI11Iii )
  if 30 - 30: I1IiiI + OoO0O00 % Ii1I * iII111i / Oo0Ooo - I11i
  if ( oO0OOOO0 . is_trace ( ) ) :
   if ( lisp . lisp_trace_append ( oO0OOOO0 ) == False ) : return
   if 64 - 64: iIii1I11I1II1
   if 21 - 21: Oo0Ooo . II111iiii
   if 54 - 54: II111iiii % II111iiii
   if 86 - 86: O0 % Ii1I * ooOoO0o * iIii1I11I1II1 * i1IIi * I11i
   if 83 - 83: OoOoOO00 % II111iiii - OoOoOO00 + IiII - O0
  if ( oO0OOOO0 . encode ( O00Ooo ) == None ) : return
  if ( len ( oO0OOOO0 . packet ) <= 1500 ) : oO0OOOO0 . print_packet ( "Send" , True )
  if 52 - 52: Oo0Ooo * ooOoO0o
  if 33 - 33: Ii1I
  if 74 - 74: OOooOOo + O0 + i1IIi - i1IIi + II111iiii
  if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
  iIi1Ii1i1iI = OOo if i1II1I1Iii1 == 6 else iiI1iIiI
  oO0OOOO0 . send_packet ( iIi1Ii1i1iI , oO0OOOO0 . outer_dest )
  if 16 - 16: OOooOOo / Oo0Ooo / OoooooooOO * I1IiiI + i1IIi % OOooOOo
 elif ( i1i1ii ) :
  if 71 - 71: OoOoOO00
  if 14 - 14: i11iIiiIii % OOooOOo
  if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
  if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
  iII1iiiiIII = len ( oO0OOOO0 . packet )
  for OOoOO0oo00Oo in i1i1ii . rle_forwarding_list :
   oO0OOOO0 . outer_dest . copy_address ( OOoOO0oo00Oo . address )
   oO0OOOO0 . encap_port = lisp . LISP_DATA_PORT if OOoOO0oo00Oo . translated_port == 0 else OOoOO0oo00Oo . translated_port
   if 50 - 50: ooOoO0o - I1Ii111 * IiII . I1ii11iIi11i
   if 37 - 37: ooOoO0o % i11iIiiIii % II111iiii . O0 . Ii1I
   i1II1I1Iii1 = oO0OOOO0 . outer_dest . afi_to_version ( )
   oO0OOOO0 . outer_version = i1II1I1Iii1
   iiI11Iii = lisp . lisp_myrlocs [ 0 ] if ( i1II1I1Iii1 == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 51 - 51: OoO0O00 - O0 % oO0o - II111iiii
   oO0OOOO0 . outer_source . copy_address ( iiI11Iii )
   if 31 - 31: iII111i / Oo0Ooo - iII111i - OOooOOo
   if ( oO0OOOO0 . is_trace ( ) ) :
    if ( lisp . lisp_trace_append ( oO0OOOO0 ) == False ) : return
    if 7 - 7: iII111i % O0 . OoOoOO00 + I1IiiI - I11i
    if 75 - 75: I11i
   if ( oO0OOOO0 . encode ( None ) == None ) : return
   if 71 - 71: ooOoO0o
   oO0OOOO0 . print_packet ( "Replicate-to-L{}" . format ( OOoOO0oo00Oo . level ) , True )
   oO0OOOO0 . send_packet ( iiI1iIiI , oO0OOOO0 . outer_dest )
   if 53 - 53: OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
   if 28 - 28: I11i
   if 58 - 58: OoOoOO00
   if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
   if 73 - 73: i11iIiiIii - IiII
   ii11I1 = len ( oO0OOOO0 . packet ) - iII1iiiiIII
   oO0OOOO0 . packet = oO0OOOO0 . packet [ ii11I1 : : ]
   if 75 - 75: OoO0O00 / II111iiii % O0
   if ( lisp . lisp_flow_logging ) : oO0OOOO0 = copy . deepcopy ( oO0OOOO0 )
   if 38 - 38: OoooooooOO * ooOoO0o % O0 * OoOoOO00
   if 29 - 29: I1ii11iIi11i / i1IIi . I1IiiI - OoOoOO00 - OoOoOO00 - Ii1I
   if 20 - 20: i1IIi % OoO0O00 . I1IiiI / IiII * i11iIiiIii * OOooOOo
   if 85 - 85: o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . O0 % I1Ii111
   if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
   if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
 del ( oO0OOOO0 )
 return
 if 74 - 74: O0 / i1IIi
 if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
 if 31 - 31: OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
def i1iiIiI1Ii1i ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  if 22 - 22: IiII / i11iIiiIii
  if 62 - 62: OoO0O00 / I1ii11iIi11i
  if 7 - 7: OoooooooOO . IiII
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
  oO0OOOO0 = lisp_thread . input_queue . get ( )
  if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
  if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
  if 92 - 92: ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  lisp_thread . input_stats . increment ( len ( oO0OOOO0 ) )
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  if 92 - 92: I11i . I1Ii111
  if 85 - 85: I1ii11iIi11i . I1Ii111
  lisp_thread . lisp_packet . packet = oO0OOOO0
  if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
  if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
  if 18 - 18: iIii1I11I1II1 % I11i
  if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
  O0O ( lisp_thread . lisp_packet , lisp_thread . thread_name )
  if 75 - 75: OoooooooOO * IiII
 return
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 if 73 - 73: i1IIi / i11iIiiIii
def OOOIiiiii1iI ( thread ) :
 IIi = ( time . time ( ) % thread . number_of_pcap_threads )
 return ( int ( IIi ) == thread . thread_number )
 if 89 - 89: II111iiii + i1IIi + II111iiii
 if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
 if 42 - 42: OoOoOO00 * OoOoOO00 * I1Ii111 . I11i
 if 51 - 51: OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o * iIii1I11I1II1 % OoO0O00
 if 99 - 99: oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
def OoO ( parms , not_used , packet ) :
 if ( OOOIiiiii1iI ( parms [ 1 ] ) == False ) : return
 if 35 - 35: OoOoOO00 + i11iIiiIii - II111iiii
 Ii1ii111i1 = parms [ 0 ]
 i1i1i1I = parms [ 1 ]
 oOoo000 = i1i1i1I . number_of_worker_threads
 if 87 - 87: OoooooooOO - o0oOOo0O0Ooo / IiII . i11iIiiIii * OoooooooOO
 i1i1i1I . input_stats . increment ( len ( packet ) )
 if 84 - 84: OoOoOO00 / I11i * iII111i / oO0o - i11iIiiIii . Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 iI11I = 4 if Ii1ii111i1 == "lo0" else ( 14 if lisp . lisp_is_macos ( ) else 16 )
 packet = packet [ iI11I : : ]
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 if ( oOoo000 ) :
  Ooooo00o0OoO = i1i1i1I . input_stats . packet_count % oOoo000
  Ooooo00o0OoO = Ooooo00o0OoO + ( len ( OOo000 ) - oOoo000 )
  oooo0O0O0o0 = OOo000 [ Ooooo00o0OoO ]
  oooo0O0O0o0 . input_queue . put ( packet )
 else :
  i1i1i1I . lisp_packet . packet = packet
  O0O ( i1i1i1I . lisp_packet , i1i1i1I . thread_name )
  if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 return
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
 if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 if 59 - 59: OOooOOo + i11iIiiIii
def oo0OOo0O ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 39 - 39: OoooooooOO + oO0o % OOooOOo / OOooOOo
 Ii1ii111i1 = "lo0" if lisp . lisp_is_macos ( ) else "any"
 if 27 - 27: iII111i . I11i . iIii1I11I1II1 . iIii1I11I1II1
 iIi1i = pcappy . open_live ( Ii1ii111i1 , 9000 , 0 , 100 )
 if 4 - 4: I1Ii111 / i11iIiiIii / OOooOOo
 OooO0ooo0o = "(dst host "
 iii1 = ""
 for oO0OOoO0 in lisp . lisp_get_all_addresses ( ) :
  OooO0ooo0o += "{} or " . format ( oO0OOoO0 )
  iii1 += "{} or " . format ( oO0OOoO0 )
  if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 OooO0ooo0o = OooO0ooo0o [ 0 : - 4 ]
 OooO0ooo0o += ") and ((udp dst port 4341 or 8472 or 4789) or "
 OooO0ooo0o += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0))))"
 if 88 - 88: iII111i
 if 19 - 19: II111iiii * IiII + Ii1I
 if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
 if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
 if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
 if 67 - 67: I11i - OOooOOo . i1IIi
 iii1 = iii1 [ 0 : - 4 ]
 OooO0ooo0o += ( " or (not (src host {}) and " + "((udp src port 4342 and ip[28] == 0x28) or " + "(udp dst port 4342 and ip[28] == 0x12)))" ) . format ( iii1 )
 if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
 if 87 - 87: OoOoOO00
 if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
 lisp . lprint ( "Capturing packets for: '{}'" . format ( OooO0ooo0o ) )
 iIi1i . filter = OooO0ooo0o
 if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
 if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
 if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
 if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
 iIi1i . loop ( - 1 , OoO , [ Ii1ii111i1 , lisp_thread ] )
 return
 if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
 if 93 - 93: Ii1I - OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
 if 49 - 49: OoooooooOO * I11i - Oo0Ooo . oO0o
 if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
 if 46 - 46: OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
def O00o00O ( ) :
 lisp . lisp_set_exception ( )
 if 3 - 3: OOooOOo
 if 20 - 20: II111iiii . iII111i / II111iiii % i11iIiiIii % iII111i
 if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
 if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
 for o000O0o in lisp . lisp_crypto_keys_by_nonce . values ( ) :
  for O00oo0ooO in o000O0o : del ( O00oo0ooO )
  if 38 - 38: iIii1I11I1II1 - II111iiii - I1IiiI
 lisp . lisp_crypto_keys_by_nonce = { }
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
 if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 Ii1IIii11 = threading . Timer ( 60 , O00o00O , [ ] )
 Ii1IIii11 . start ( )
 return
 if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
 if 34 - 34: O0
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
 if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
def oOOoo0 ( ) :
 global oO0oIIII , II1iII1i , i111I
 global iiI1iIiI , OOo , OOo000
 global Oo0oO0oo0oO00
 if 20 - 20: IiII % IiII
 lisp . lisp_i_am ( "rtr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "RTR starting up" )
 if 94 - 94: o0oOOo0O0Ooo + O0 / I11i . I1IiiI + OOooOOo . iIii1I11I1II1
 if 62 - 62: OoOoOO00 / I1IiiI - I1ii11iIi11i - I1IiiI + i11iIiiIii + i1IIi
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 8 - 8: o0oOOo0O0Ooo
 if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
 if 78 - 78: Ii1I / II111iiii % OoOoOO00
 if 52 - 52: OOooOOo - iII111i * oO0o
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
 if 36 - 36: O0 + Oo0Ooo
 iIIIi1i1I11i = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 i111I = lisp . lisp_open_listen_socket ( iIIIi1i1I11i ,
 str ( II1Ii1iI1i ) )
 oO0oIIII = lisp . lisp_open_listen_socket ( "" , "lisp-rtr" )
 Oo0oO0oo0oO00 = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 if 55 - 55: Oo0Ooo - OOooOOo
 II1iII1i [ 0 ] = i111I
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 II1iII1i [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 II1iII1i [ 2 ] = oO0oIIII
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
 if 63 - 63: I1ii11iIi11i
 if 6 - 6: ooOoO0o / I1ii11iIi11i
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
 if 87 - 87: oO0o % Ii1I
 if 83 - 83: II111iiii - I11i
 iiI1iIiI = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 iiI1iIiI . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 II1iII1i . append ( iiI1iIiI )
 if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  OOo = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
  if 51 - 51: OoOoOO00
 I11IIIiIi11 = os . getenv ( "LISP_PCAP_THREADS" )
 I11IIIiIi11 = 1 if ( I11IIIiIi11 == None ) else int ( I11IIIiIi11 )
 I11iiIi1i1 = os . getenv ( "LISP_WORKER_THREADS" )
 I11iiIi1i1 = 0 if ( I11iiIi1i1 == None ) else int ( I11iiIi1i1 )
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 for i11I1I1iiI in range ( I11IIIiIi11 ) :
  I1i1iii1Ii = lisp . lisp_thread ( "pcap-{}" . format ( i11I1I1iiI ) )
  I1i1iii1Ii . thread_number = i11I1I1iiI
  I1i1iii1Ii . number_of_pcap_threads = I11IIIiIi11
  I1i1iii1Ii . number_of_worker_threads = I11iiIi1i1
  OOo000 . append ( I1i1iii1Ii )
  threading . Thread ( target = oo0OOo0O , args = [ I1i1iii1Ii ] ) . start ( )
  if 23 - 23: i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo - I1ii11iIi11i % iII111i * OoO0O00 - OOooOOo / iII111i
  if 29 - 29: I1ii11iIi11i
  if 52 - 52: i11iIiiIii / i1IIi
  if 1 - 1: ooOoO0o
  if 78 - 78: I1ii11iIi11i + I11i - O0
 for i11I1I1iiI in range ( I11iiIi1i1 ) :
  I1i1iii1Ii = lisp . lisp_thread ( "worker-{}" . format ( i11I1I1iiI ) )
  OOo000 . append ( I1i1iii1Ii )
  threading . Thread ( target = i1iiIiI1Ii1i , args = [ I1i1iii1Ii ] ) . start ( )
  if 10 - 10: I1Ii111 % I1IiiI
  if 97 - 97: OoooooooOO - I1Ii111
  if 58 - 58: iIii1I11I1II1 + O0
  if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
  if 46 - 46: i11iIiiIii - O0 . oO0o
 lisp . lisp_load_checkpoint ( )
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 Ii1IIii11 = threading . Timer ( 60 , O00o00O , [ ] )
 Ii1IIii11 . start ( )
 return ( True )
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
 if 57 - 57: O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
def IiIIi1I1I11Ii ( ) :
 if 64 - 64: OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( oO0oIIII , "lisp-rtr" )
 lisp . lisp_close_socket ( i111I , "" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lispers.net-itr" )
 iiI1iIiI . close ( )
 return
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
def IIiIiiiIIIIi1 ( kv_pair ) :
 global II1iII1i
 global II1Ii1iI1i
 if 39 - 39: OoO0O00 / Ii1I / I1Ii111
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 81 - 81: I11i / OoO0O00 % OoooooooOO * oO0o / oO0o
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , II1Ii1iI1i ] )
  lisp . lisp_test_mr_timer . start ( )
  if 28 - 28: i11iIiiIii / o0oOOo0O0Ooo . iIii1I11I1II1 / II111iiii
 return
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
def o00oo0000 ( kv_pair ) :
 global i111I , iiI1iIiI , II1Ii1iI1i
 if 44 - 44: Oo0Ooo % iIii1I11I1II1
 oo0ooO0 = lisp . lisp_rloc_probing
 if 28 - 28: I1ii11iIi11i * OoooooooOO . II111iiii / i11iIiiIii + oO0o
 if 38 - 38: IiII . Ii1I
 if 24 - 24: o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
 if 12 - 12: iII111i . IiII . OoOoOO00 / O0
 lispconfig . lisp_xtr_command ( kv_pair )
 if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
 if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if ( oo0ooO0 == False and lisp . lisp_rloc_probing ) :
  iI1Ii11iII1 = [ i111I , i111I ,
 None , iiI1iIiI ]
  lisp . lisp_start_rloc_probe_timer ( 1 , iI1Ii11iII1 )
  iIIi1iI1I1IIi = { "type" : "itr-crypto-port" , "port" : II1Ii1iI1i }
  lisp . lisp_write_to_dp_socket ( iIIi1iI1I1IIi )
  if 77 - 77: ooOoO0o / Oo0Ooo + ooOoO0o % o0oOOo0O0Ooo - I1IiiI * I1IiiI
  if 23 - 23: iII111i . II111iiii % I1ii11iIi11i - OoooooooOO * Oo0Ooo . iIii1I11I1II1
  if 37 - 37: iII111i / Oo0Ooo . I11i * I11i
  if 80 - 80: OOooOOo % I1ii11iIi11i
  if 91 - 91: I11i / O0 - Ii1I . I1IiiI
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 82 - 82: IiII * OOooOOo / oO0o
 if 2 - 2: I1IiiI + o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0 / I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
ooO0oo0o0 = {
 "lisp xtr-parameters" : [ o00oo0000 , {
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

 "lisp map-resolver" : [ IIiIiiiIIIIi1 , {
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

 "lisp database-mapping" : [ oO00 , {
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

 "show rtr-rloc-probing" : [ o00O , { } ] ,
 "show rtr-keys" : [ o0OOOOO00o0O0 , { } ] ,
 "show rtr-map-cache" : [ i11IiIiiIIIII , { } ] ,
 "show rtr-map-cache-dns" : [ i1iIIIiI1I , { } ]
 }
if 9 - 9: I1IiiI + I1ii11iIi11i / I1IiiI . oO0o * ooOoO0o
if 45 - 45: i11iIiiIii
if 82 - 82: Ii1I + IiII
if 12 - 12: I1Ii111
if 93 - 93: i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / o0oOOo0O0Ooo / II111iiii
if 49 - 49: OOooOOo . I1ii11iIi11i . i11iIiiIii - II111iiii / Ii1I
if ( oOOoo0 ( ) == False ) :
 lisp . lprint ( "lisp_rtr_startup() failed" )
 lisp . lisp_print_banner ( "RTR abnormal exit" )
 exit ( 1 )
 if 62 - 62: OOooOOo
 if 1 - 1: IiII / IiII - i11iIiiIii
OO0o = [ i111I , oO0oIIII ,
 Oo0oO0oo0oO00 ]
IiII1iiI = [ i111I ] * 3
if 34 - 34: I1IiiI . oO0o + i1IIi
while ( True ) :
 try : OO000oOoo0O , iIIiii11iIiiI , O0Oo0 = select . select ( OO0o , [ ] , [ ] )
 except : break
 if 98 - 98: I1Ii111
 if 92 - 92: I1Ii111 - iIii1I11I1II1
 if 32 - 32: Ii1I % OoO0O00 * OoO0O00 + IiII * II111iiii * Ii1I
 if 11 - 11: oO0o % II111iiii
 if ( lisp . lisp_ipc_data_plane and Oo0oO0oo0oO00 in OO000oOoo0O ) :
  lisp . lisp_process_punt ( Oo0oO0oo0oO00 , II1iII1i ,
 II1Ii1iI1i )
  if 57 - 57: OOooOOo / Oo0Ooo
  if 69 - 69: oO0o - Oo0Ooo % IiII
  if 50 - 50: OoooooooOO
  if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
  if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if ( i111I in OO000oOoo0O ) :
  oO0OO , OO , IIIIii , oO0OOOO0 = lisp . lisp_receive ( IiII1iiI [ 0 ] ,
 False )
  if ( OO == "" ) : break
  if ( lisp . lisp_is_rloc_probe_request ( oO0OOOO0 [ 0 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
   continue
   if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
  if ( lisp . lisp_is_rloc_probe_reply ( oO0OOOO0 [ 0 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
   continue
   if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
  lisp . lisp_parse_packet ( IiII1iiI , oO0OOOO0 , OO , IIIIii )
  if 62 - 62: o0oOOo0O0Ooo
  if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
  if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
  if 72 - 72: iIii1I11I1II1
  if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if ( oO0oIIII in OO000oOoo0O ) :
  oO0OO , OO , IIIIii , oO0OOOO0 = lisp . lisp_receive ( oO0oIIII , True )
  if 87 - 87: OoO0O00 % I1IiiI
  if ( OO == "" ) : break
  if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
  if ( oO0OO == "command" ) :
   if ( oO0OOOO0 == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
   if ( oO0OOOO0 . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( oO0OOOO0 )
    continue
    if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
   lispconfig . lisp_process_command ( oO0oIIII , oO0OO ,
 oO0OOOO0 , "lisp-rtr" , [ ooO0oo0o0 ] )
  elif ( oO0OO == "api" ) :
   lisp . lisp_process_api ( "lisp-rtr" , oO0oIIII , oO0OOOO0 )
  elif ( oO0OO == "data-packet" ) :
   O0O ( oO0OOOO0 , "" )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( oO0OOOO0 [ 0 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
    continue
    if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
   if ( lisp . lisp_is_rloc_probe_reply ( oO0OOOO0 [ 0 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
    continue
    if 84 - 84: i11iIiiIii * OoO0O00
   lisp . lisp_parse_packet ( II1iII1i , oO0OOOO0 , OO , IIIIii )
   if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
   if 30 - 30: O0 + I1ii11iIi11i + II111iiii
   if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
   if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
   if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
IiIIi1I1I11Ii ( )
lisp . lisp_print_banner ( "RTR normal exit" )
exit ( 0 )
if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
if 64 - 64: i1IIi
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
