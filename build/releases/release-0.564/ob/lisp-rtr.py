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
 for O0o0 in list ( kv_pair . keys ( ) ) :
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
  if ( ( "eid-prefix" in iiI111I1iIiI ) ^ ( "eid-prefix" in oO0Oo ) ) : continue
  if ( ( "eid-prefix" in iiI111I1iIiI ) and ( "eid-prefix" in oO0Oo ) ) :
   II = iiI111I1iIiI [ "eid-prefix" ]
   Ii1I1IIii1II = oO0Oo [ "eid-prefix" ]
   if ( II . is_exact_match ( Ii1I1IIii1II ) == False ) : continue
   if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
   if 21 - 21: I1IiiI * iIii1I11I1II1
  if ( ( "group-prefix" in iiI111I1iIiI ) ^ ( "group-prefix" in oO0Oo ) ) : continue
  if ( ( "group-prefix" in iiI111I1iIiI ) and ( "group-prefix" in oO0Oo ) ) :
   II = iiI111I1iIiI [ "group-prefix" ]
   Ii1I1IIii1II = oO0Oo [ "group-prefix" ]
   if ( II . is_exact_match ( Ii1I1IIii1II ) == False ) : continue
   if 91 - 91: IiII
   if 15 - 15: II111iiii
  if ( ( "rloc-prefix" in iiI111I1iIiI ) ^ ( "rloc-prefix" in oO0Oo ) ) : continue
  if ( ( "rloc-prefix" in iiI111I1iIiI ) and ( "rloc-prefix" in oO0Oo ) ) :
   II = iiI111I1iIiI [ "rloc-prefix" ]
   Ii1I1IIii1II = oO0Oo [ "rloc-prefix" ]
   if ( II . is_exact_match ( Ii1I1IIii1II ) == False ) : continue
   if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
   if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
  if ( ( "instance-id" in iiI111I1iIiI ) ^ ( "instance-id" in oO0Oo ) ) : continue
  if ( ( "instance-id" in iiI111I1iIiI ) and ( "instance-id" in oO0Oo ) ) :
   II = iiI111I1iIiI [ "instance-id" ]
   Ii1I1IIii1II = oO0Oo [ "instance-id" ]
   if ( II != Ii1I1IIii1II ) : continue
   if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
   if 91 - 91: O0
   if 61 - 61: II111iiii
   if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
   if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
  return
  if 42 - 42: OoO0O00
  if 67 - 67: I1Ii111 . iII111i . O0
  if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
  if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
  if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 lisp . lisp_glean_mappings . append ( oO0Oo )
 if 83 - 83: I11i / I1IiiI
 if 34 - 34: IiII
 if 57 - 57: oO0o . I11i . i1IIi
 if 42 - 42: I11i + I1ii11iIi11i % O0
 if 6 - 6: oO0o
 if 68 - 68: OoOoOO00 - OoO0O00
 if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
def iiii ( parameter ) :
 return ( lispconfig . lisp_itr_rtr_show_rloc_probe_command ( "RTR" ) )
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
 if 92 - 92: iII111i
 if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
def oo0o00O ( mc , parms ) :
 o00O0OoO , iII1 , i1I , OoOO = parms
 if 53 - 53: Oo0Ooo
 iI1Iii = "{}:{}" . format ( iII1 . print_address_no_iid ( ) , i1I )
 Ii1iIiII1ii1 = lisp . green ( mc . print_eid_tuple ( ) , False )
 oO00OOoO00 = "Changed '{}' translated address:port to {} for EID {}, {} {}" . format ( OoOO , lisp . red ( iI1Iii , False ) , Ii1iIiII1ii1 , "{}" , "{}" )
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
 for i1I1iI1iIi111i in mc . rloc_set :
  if ( i1I1iI1iIi111i . rle ) :
   for iiIi1IIi1I in i1I1iI1iIi111i . rle . rle_nodes :
    if ( iiIi1IIi1I . rloc_name != OoOO ) : continue
    iiIi1IIi1I . store_translated_rloc ( iII1 , i1I )
    o0OoOO000ooO0 = iiIi1IIi1I . address . print_address_no_iid ( ) + ":" + str ( iiIi1IIi1I . translated_port )
    if 56 - 56: iII111i
    lisp . lprint ( oO00OOoO00 . format ( "RLE" , o0OoOO000ooO0 ) )
    if 86 - 86: II111iiii % I1Ii111
    if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
    if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
  if ( i1I1iI1iIi111i . rloc_name != OoOO ) : continue
  if 80 - 80: II111iiii
  if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
  if 53 - 53: II111iiii
  if 31 - 31: OoO0O00
  if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
  if 25 - 25: OoO0O00
  o0OoOO000ooO0 = i1I1iI1iIi111i . rloc . print_address_no_iid ( ) + ":" + str ( i1I1iI1iIi111i . translated_port )
  if 62 - 62: OOooOOo + O0
  if ( o0OoOO000ooO0 in lisp . lisp_crypto_keys_by_rloc_encap ) :
   oO0OOOO0 = lisp . lisp_crypto_keys_by_rloc_encap [ o0OoOO000ooO0 ]
   lisp . lisp_crypto_keys_by_rloc_encap [ iI1Iii ] = oO0OOOO0
   if 26 - 26: Ii1I
   if 35 - 35: Ii1I - I1IiiI % o0oOOo0O0Ooo . OoooooooOO % Ii1I
   if 47 - 47: iII111i - Ii1I . II111iiii + OoooooooOO . i11iIiiIii
   if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
   if 87 - 87: Oo0Ooo . IiII
  i1I1iI1iIi111i . delete_from_rloc_probe_list ( mc . eid , mc . group )
  i1I1iI1iIi111i . store_translated_rloc ( iII1 , i1I )
  i1I1iI1iIi111i . add_to_rloc_probe_list ( mc . eid , mc . group )
  lisp . lprint ( oO00OOoO00 . format ( "RLOC" , o0OoOO000ooO0 ) )
  if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
  if 55 - 55: OOooOOo . I1IiiI
  if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
  if 100 - 100: I1Ii111 * O0
  if ( lisp . lisp_rloc_probing ) :
   o00oO0oo0OO = None if ( mc . group . is_null ( ) ) else mc . eid
   O0O0OOOOoo = mc . eid if ( mc . group . is_null ( ) ) else mc . group
   lisp . lisp_send_map_request ( o00O0OoO , 0 , o00oO0oo0OO , O0O0OOOOoo , i1I1iI1iIi111i )
   if 74 - 74: I1ii11iIi11i + II111iiii / OoO0O00
   if 100 - 100: OoOoOO00 * iIii1I11I1II1
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
 if ( mc . group . is_null ( ) ) : return ( oo0o00O ( mc , parms ) )
 if 97 - 97: O0 + OoOoOO00
 if ( mc . source_cache == None ) : return ( True , parms )
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 mc . source_cache . walk_cache ( oo0o00O , parms )
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
  II1i111Ii1i = binascii . hexlify ( packet [ 0 : 20 ] )
  lisp . lprint ( "Fast-{}: ip {} {} {} {} {}" . format ( sred , II1i111Ii1i [ 0 : 8 ] , II1i111Ii1i [ 8 : 16 ] ,
 II1i111Ii1i [ 16 : 24 ] , II1i111Ii1i [ 24 : 32 ] , II1i111Ii1i [ 32 : 40 ] ) )
 elif ( sred in [ "Encap" , "Decap" ] ) :
  II1i111Ii1i = binascii . hexlify ( packet [ 0 : 36 ] )
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
 ii1 = ord ( a [ 0 ] ) << 24 | ord ( a [ 1 ] ) << 16 | ord ( a [ 2 ] ) << 8 | ord ( a [ 3 ] )
 return ( ii1 )
 if 39 - 39: Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * iII111i + I1IiiI
 if 77 - 77: Ii1I + II111iiii . OoOoOO00 * I1Ii111 + OOooOOo + OOooOOo
 if 9 - 9: I11i % OoooooooOO . oO0o % I11i
 if 32 - 32: i11iIiiIii
 if 31 - 31: iIii1I11I1II1 / OoO0O00 / I1ii11iIi11i
 if 41 - 41: Oo0Ooo
 if 10 - 10: Oo0Ooo / Oo0Ooo / I1Ii111 . I1Ii111
 if 98 - 98: Oo0Ooo / I1IiiI . O0 + OoO0O00
 if 43 - 43: II111iiii . oO0o / I1ii11iIi11i
 if 20 - 20: I1IiiI
 if 95 - 95: iII111i - I1IiiI
 if 34 - 34: ooOoO0o * I1IiiI . i1IIi * ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 if 41 - 41: i1IIi - I11i - Ii1I
 if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
 if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
 if 44 - 44: II111iiii
 if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
iI1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
IiI = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
if 21 - 21: OoO0O00 + I1IiiI % I1IiiI
def oO0o0oooO0oO ( packet ) :
 global lisp_map_cache , OOo
 if 19 - 19: i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 Iii1iiIi1II = OO0000o ( None , "Fast" )
 if 60 - 60: I1IiiI - oO0o * I11i % II111iiii
 if 62 - 62: iIii1I11I1II1
 if 12 - 12: OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 iii11I = 0
 I1Iii1 = None
 if ( packet [ 9 : 10 ] == b'\x11' ) :
  if ( packet [ 20 : 22 ] == b'\x10\xf6' ) : return ( False )
  if ( packet [ 22 : 24 ] == b'\x10\xf6' ) : return ( False )
  if 30 - 30: OoooooooOO - OoOoOO00
  if ( packet [ 20 : 22 ] == b'\x10\xf5' or packet [ 22 : 24 ] == b'\x10\xf5' ) :
   I1Iii1 = packet [ 12 : 16 ]
   iii11I = packet [ 32 : 35 ]
   iii11I = ord ( iii11I [ 0 ] ) << 16 | ord ( iii11I [ 1 ] ) << 8 | ord ( iii11I [ 2 ] )
   if ( iii11I == 0xffffff ) : return ( False )
   I1II1 ( "Decap" , packet )
   packet = packet [ 36 : : ]
   if 75 - 75: iIii1I11I1II1 - Ii1I . Oo0Ooo % i11iIiiIii % I11i
   if 55 - 55: iII111i . II111iiii % OoO0O00 * iII111i + ooOoO0o + Ii1I
   if 24 - 24: Oo0Ooo - oO0o % iIii1I11I1II1 . i1IIi / O0
 I1II1 ( "Receive" , packet )
 if 36 - 36: I1IiiI - I11i
 if 29 - 29: ooOoO0o * OOooOOo
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 I1ii11 = Oo0o0O00 ( packet [ 16 : 20 ] )
 IiI . instance_id = iii11I
 IiI . address = I1ii11
 if 74 - 74: Oo0Ooo - o0oOOo0O0Ooo . i1IIi
 if 43 - 43: iII111i / I1IiiI
 if 58 - 58: I1IiiI + i11iIiiIii % Ii1I . OoOoOO00
 if 13 - 13: i11iIiiIii + i1IIi * iIii1I11I1II1 % OoooooooOO - II111iiii * OOooOOo
 if ( ( I1ii11 & 0xe0000000 ) == 0xe0000000 ) : return ( False )
 if 26 - 26: OoooooooOO * I1IiiI + OOooOOo
 if 24 - 24: i11iIiiIii % iIii1I11I1II1 + OOooOOo / i11iIiiIii
 if 70 - 70: OoO0O00 * O0 . I11i + I1IiiI . IiII
 if 14 - 14: iIii1I11I1II1 % iIii1I11I1II1 * i11iIiiIii - OoO0O00 - I11i
 I1ii11 = IiI
 o00oo0 = lisp . lisp_map_cache . lookup_cache ( I1ii11 , False )
 o0OOOoO0 ( I1ii11 , o00oo0 )
 if ( o00oo0 == None ) : return ( False )
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
 if 27 - 27: O0
 if ( I1Iii1 != None ) :
  OOO0oOOoo = Oo0o0O00 ( packet [ 12 : 16 ] )
  iI1 . instance_id = iii11I
  iI1 . address = OOO0oOOoo
  oOOO00o000o = lisp . lisp_map_cache . lookup_cache ( iI1 , False )
  if ( oOOO00o000o == None ) :
   iIi11i1 , oO00oo0o00o0o , IiIIIIIi = lisp . lisp_allow_gleaning ( iI1 , None ,
 None )
   if ( iIi11i1 ) : return ( False )
  elif ( oOOO00o000o . gleaned ) :
   I1Iii1 = Oo0o0O00 ( I1Iii1 )
   if ( oOOO00o000o . rloc_set [ 0 ] . rloc . address != I1Iii1 ) : return ( False )
   if 11 - 11: i1IIi % i11iIiiIii - i1IIi * OoOoOO00
   if 39 - 39: I1Ii111
   if 86 - 86: I11i * I1IiiI + I11i + II111iiii
   if 8 - 8: I1Ii111 - iII111i / ooOoO0o
   if 96 - 96: OoOoOO00
  o00oo0 . add_recent_source ( iI1 )
  if 29 - 29: I1ii11iIi11i / i1IIi . I1IiiI - OoOoOO00 - OoOoOO00 - Ii1I
  if 20 - 20: i1IIi % OoO0O00 . I1IiiI / IiII * i11iIiiIii * OOooOOo
  if 85 - 85: o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . O0 % I1Ii111
  if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
  if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
 if ( o00oo0 . action == lisp . LISP_NATIVE_FORWARD_ACTION and
 o00oo0 . eid . instance_id == 0 ) :
  I1ii11 . instance_id = lisp . lisp_default_secondary_iid
  o00oo0 = lisp . lisp_map_cache . lookup_cache ( I1ii11 , False )
  o0OOOoO0 ( I1ii11 , o00oo0 )
  if ( o00oo0 == None ) : return ( False )
  if 74 - 74: O0 / i1IIi
  if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
  if 31 - 31: OoooooooOO . OOooOOo
  if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
  if 100 - 100: OoO0O00
  if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if ( o00oo0 . action != lisp . LISP_NATIVE_FORWARD_ACTION ) :
  if ( o00oo0 . best_rloc_set == [ ] ) : return ( False )
  if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
  I1ii11 = o00oo0 . best_rloc_set [ 0 ]
  if ( I1ii11 . state != lisp . LISP_RLOC_UP_STATE ) : return ( False )
  if 45 - 45: I1Ii111
  iii11I = o00oo0 . eid . instance_id
  i1I = I1ii11 . translated_port
  oO = I1ii11 . stats
  I1ii11 = I1ii11 . rloc
  IIi1iiii1iI = I1ii11 . address
  I1Iii1 = lisp . lisp_myrlocs [ 0 ] . address
  if 25 - 25: I1ii11iIi11i + O0
  if 28 - 28: OoooooooOO
  if 89 - 89: iII111i - ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
  if 49 - 49: Oo0Ooo - I1IiiI / IiII / O0 % o0oOOo0O0Ooo * Ii1I
  OOoO0 = b'\x45\x00'
  II11iI111i1 = len ( packet ) + 20 + 8 + 8
  OOoO0 += bytes ( [ ( II11iI111i1 >> 8 ) & 0xff , II11iI111i1 & 0xff ] )
  OOoO0 += b'\xff\xff\x40\x00\x10\x11\x00\x00'
  OOoO0 += bytes ( [ ( I1Iii1 >> 24 ) & 0xff , ( I1Iii1 >> 16 ) & 0xff ,
 ( I1Iii1 >> 8 ) & 0xff , I1Iii1 & 0xff ] )
  OOoO0 += bytes ( [ ( IIi1iiii1iI >> 24 ) & 0xff , ( IIi1iiii1iI >> 16 ) & 0xff ,
 ( IIi1iiii1iI >> 8 ) & 0xff , IIi1iiii1iI & 0xff ] )
  OOoO0 = lisp . lisp_ip_checksum ( OOoO0 )
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  if 92 - 92: I11i . I1Ii111
  if 85 - 85: I1ii11iIi11i . I1Ii111
  O0O0Ooooo000 = II11iI111i1 - 20
  o000oOoo0o000 = b'\xff\x00' if ( i1I == 4341 ) else b'\x10\xf5'
  o000oOoo0o000 += bytes ( [ ( i1I >> 8 ) & 0xff , i1I & 0xff ] )
  o000oOoo0o000 += bytes ( [ ( O0O0Ooooo000 >> 8 ) & 0xff , O0O0Ooooo000 & 0xff ] ) + b'\x00\x00'
  o000oOoo0o000 += b'\x08\xdf\xdf\xdf'
  o000oOoo0o000 += bytes ( [ ( iii11I >> 16 ) & 0xff , ( iii11I >> 8 ) & 0xff , iii11I & 0xff ] )
  o000oOoo0o000 += b'\x00'
  if 40 - 40: i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - I11i . i1IIi
  if 99 - 99: O0 * I11i
  if 64 - 64: II111iiii + O0 / iIii1I11I1II1 / Oo0Ooo . ooOoO0o % IiII
  if 50 - 50: iIii1I11I1II1 - IiII + OOooOOo
  packet = OOoO0 + o000oOoo0o000 + packet
  I1II1 ( "Encap" , packet )
 else :
  II11iI111i1 = len ( packet )
  oO = o00oo0 . stats
  I1II1 ( "Send" , packet )
  if 69 - 69: O0
  if 85 - 85: ooOoO0o / O0
  if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
  if 62 - 62: I1Ii111 . IiII . OoooooooOO
  if 11 - 11: OOooOOo / I11i
 o00oo0 . last_refresh_time = time . time ( )
 oO . increment ( II11iI111i1 )
 if 73 - 73: i1IIi / i11iIiiIii
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 if 85 - 85: OoOoOO00 + OOooOOo
 if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
 I1ii11 = I1ii11 . print_address_no_iid ( )
 OOo . sendto ( packet , ( I1ii11 , 0 ) )
 if 27 - 27: Ii1I
 OO0000o ( Iii1iiIi1II , "Fast" )
 return ( True )
 if 67 - 67: I1IiiI
 if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
 if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
 if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
def ooO0o ( lisp_packet , thread_name ) :
 global II1iII1i , o000 , IiI1i
 global OOo , Ii1IIii11
 global oO0oIIII
 global iIiiI1
 global oo0Ooo0
 if 87 - 87: ooOoO0o
 Iii1iiIi1II = OO0000o ( None , "RTR" )
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
 if 13 - 13: Oo0Ooo
 if ( oo0Ooo0 ) :
  if ( oO0o0oooO0oO ( lisp_packet . packet ) ) : return
  if 60 - 60: I1ii11iIi11i * I1IiiI
  if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
  if 41 - 41: Ii1I
  if 77 - 77: I1Ii111
  if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 iI11I = lisp_packet
 I1IIIiii1 = iI11I . is_lisp_packet ( iI11I . packet )
 if 65 - 65: I11i / II111iiii * Ii1I . iII111i * oO0o % OOooOOo
 if 69 - 69: ooOoO0o - OoO0O00 / i11iIiiIii + I1ii11iIi11i % OoooooooOO
 if 73 - 73: Ii1I - I1Ii111
 if 68 - 68: iII111i * OoooooooOO * iIii1I11I1II1 . II111iiii
 if ( I1IIIiii1 == False ) :
  O0Oo = iI11I . packet
  I1iii , oO0o0O0Ooo0o , i1I , i1Ii11II = lisp . lisp_is_rloc_probe ( O0Oo , - 1 )
  if ( O0Oo != I1iii ) :
   if ( oO0o0O0Ooo0o == None ) : return
   lisp . lisp_parse_packet ( II1iII1i , I1iii , oO0o0O0Ooo0o , i1I , i1Ii11II )
   return
   if 18 - 18: II111iiii . OoooooooOO % OoOoOO00 % Ii1I
   if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
   if 2 - 2: OoooooooOO % OOooOOo
   if 63 - 63: I1IiiI % iIii1I11I1II1
   if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
   if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 iI11I . packet = lisp . lisp_reassemble ( iI11I . packet )
 if ( iI11I . packet == None ) : return
 if 59 - 59: OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if ( lisp . lisp_flow_logging ) : iI11I = copy . deepcopy ( iI11I )
 if 30 - 30: OoOoOO00
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if 10 - 10: II111iiii . iII111i
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 if 88 - 88: iII111i
 if 19 - 19: II111iiii * IiII + Ii1I
 if ( I1IIIiii1 ) :
  if ( iI11I . decode ( True , None , lisp . lisp_decap_stats ) == None ) : return
  iI11I . print_packet ( "Receive-({})" . format ( thread_name ) , True )
  iI11I . strip_outer_headers ( )
 else :
  if ( iI11I . decode ( False , None , None ) == None ) : return
  iI11I . print_packet ( "Receive-({})" . format ( thread_name ) , False )
  if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
  if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
  if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
  if 67 - 67: I11i - OOooOOo . i1IIi
  if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
  if 87 - 87: OoOoOO00
  if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
  if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
  if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
  if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
  if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
  if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
 if ( I1IIIiii1 and iI11I . lisp_header . get_instance_id ( ) == 0xffffff ) :
  O0OO0oOOo = lisp . lisp_control_header ( )
  O0OO0oOOo . decode ( iI11I . packet )
  if ( O0OO0oOOo . is_info_request ( ) ) :
   OO0oO0o = lisp . lisp_info ( )
   OO0oO0o . decode ( iI11I . packet )
   OO0oO0o . print_info ( )
   if 39 - 39: o0oOOo0O0Ooo * ooOoO0o + Ii1I * II111iiii
   if 97 - 97: iIii1I11I1II1 + I11i + II111iiii % IiII % I1Ii111 % oO0o
   if 21 - 21: I1IiiI / ooOoO0o % ooOoO0o - o0oOOo0O0Ooo
   if 70 - 70: Oo0Ooo . OoOoOO00
   if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
   oooo00o0o0o = OO0oO0o . hostname if ( OO0oO0o . hostname != None ) else ""
   O0Oo00oO0O00 = iI11I . outer_source
   II1i111Ii1i = iI11I . udp_sport
   if ( lisp . lisp_store_nat_info ( oooo00o0o0o , O0Oo00oO0O00 , II1i111Ii1i ) ) :
    OooOo0ooo ( II1iII1i , oooo00o0o0o , O0Oo00oO0O00 , II1i111Ii1i )
    if 32 - 32: II111iiii . Ii1I - iII111i * I1Ii111
  else :
   oO0o0O0Ooo0o = iI11I . outer_source . print_address_no_iid ( )
   i1Ii11II = iI11I . outer_ttl
   iI11I = iI11I . packet
   if ( lisp . lisp_is_rloc_probe_request ( iI11I [ 28 : 29 ] ) == False and
 lisp . lisp_is_rloc_probe_reply ( iI11I [ 28 : 29 ] ) == False ) :
    i1Ii11II = - 1
    if 71 - 71: o0oOOo0O0Ooo % Ii1I - II111iiii * OoooooooOO
   iI11I = iI11I [ 28 : : ]
   lisp . lisp_parse_packet ( II1iII1i , iI11I , oO0o0O0Ooo0o , 0 , i1Ii11II )
   if 69 - 69: o0oOOo0O0Ooo / Oo0Ooo
  return
  if 43 - 43: I1ii11iIi11i . I1IiiI / OoooooooOO % OoooooooOO
  if 33 - 33: I1Ii111
  if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
  if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
  if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
  if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 45 - 45: IiII
  if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
  if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
  if 34 - 34: O0
  if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 if ( I1IIIiii1 ) :
  lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( iI11I . packet ) )
  if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
  if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
  if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
  if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
  if 91 - 91: oO0o + OoooooooOO - i1IIi
 o000OOooo0O = False
 if ( iI11I . inner_dest . is_mac ( ) ) :
  iI11I . packet = lisp . lisp_mac_input ( iI11I . packet )
  if ( iI11I . packet == None ) : return
  iI11I . encap_port = lisp . LISP_VXLAN_DATA_PORT
 elif ( iI11I . inner_version == 4 ) :
  o000OOooo0O , iI11I . packet = lisp . lisp_ipv4_input ( iI11I . packet )
  if ( iI11I . packet == None ) : return
  iI11I . inner_ttl = iI11I . outer_ttl
 elif ( iI11I . inner_version == 6 ) :
  iI11I . packet = lisp . lisp_ipv6_input ( iI11I )
  if ( iI11I . packet == None ) : return
  iI11I . inner_ttl = iI11I . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 34 - 34: OOooOOo
  if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
  if 37 - 37: i11iIiiIii + i1IIi
  if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
  if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 if ( iI11I . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( iI11I , ed = "decap" ) == False ) : return
  iI11I . outer_source . afi = lisp . LISP_AFI_NONE
  iI11I . outer_dest . afi = lisp . LISP_AFI_NONE
  if 8 - 8: o0oOOo0O0Ooo
  if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
  if 78 - 78: Ii1I / II111iiii % OoOoOO00
  if 52 - 52: OOooOOo - iII111i * oO0o
  if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
  if 36 - 36: O0 + Oo0Ooo
 iIi11i1 , oO00oo0o00o0o , IiIIIIIi = lisp . lisp_allow_gleaning ( iI11I . inner_source , None ,
 iI11I . outer_source )
 if ( iIi11i1 ) :
  iIIIi1i1I11i = iI11I . packet if ( o000OOooo0O ) else None
  lisp . lisp_glean_map_cache ( iI11I . inner_source , iI11I . outer_source ,
 iI11I . udp_sport , iIIIi1i1I11i )
  if ( o000OOooo0O ) : return
  if 55 - 55: Oo0Ooo - OOooOOo
  if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
  if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
  if 72 - 72: i1IIi
  if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
  if 63 - 63: I1ii11iIi11i
 O0O0OOOOoo = iI11I . inner_dest
 if ( O0O0OOOOoo . is_multicast_address ( ) ) :
  if ( O0O0OOOOoo . is_link_local_multicast ( ) ) :
   i1II = lisp . green ( O0O0OOOOoo . print_address ( ) , False )
   lisp . dprint ( "Drop link-local multicast EID {}" . format ( i1II ) )
   return
   if 2 - 2: II111iiii - OoO0O00 . IiII * iII111i / oO0o
  OOo0 = False
  oO00oo0o00o0o , IiIIIIIi , iiIii1IIi = lisp . lisp_allow_gleaning ( iI11I . inner_source , O0O0OOOOoo , None )
 else :
  OOo0 , oO00oo0o00o0o , IiIIIIIi = lisp . lisp_allow_gleaning ( O0O0OOOOoo , None , None )
  if 10 - 10: i11iIiiIii - o0oOOo0O0Ooo % iIii1I11I1II1
 iI11I . gleaned_dest = OOo0
 if 49 - 49: oO0o
 if 83 - 83: oO0o % Oo0Ooo - o0oOOo0O0Ooo . iII111i / Oo0Ooo % I1ii11iIi11i
 if 75 - 75: O0 % OoOoOO00 . IiII / IiII / OoO0O00
 if 19 - 19: I1ii11iIi11i % i11iIiiIii . OOooOOo - Oo0Ooo / OoooooooOO
 o00oo0 = lisp . lisp_map_cache_lookup ( iI11I . inner_source , iI11I . inner_dest )
 if ( o00oo0 ) : o00oo0 . add_recent_source ( iI11I . inner_source )
 if 66 - 66: OoO0O00 * Oo0Ooo
 if 28 - 28: OoO0O00 % OoOoOO00 % I1ii11iIi11i + I1IiiI / I1IiiI
 if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
 if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
 if 23 - 23: i11iIiiIii
 if ( o00oo0 and ( o00oo0 . action == lisp . LISP_NATIVE_FORWARD_ACTION or
 o00oo0 . eid . address == 0 ) ) :
  II1I11IIi = lisp . lisp_db_for_lookups . lookup_cache ( iI11I . inner_source , False )
  if ( II1I11IIi and II1I11IIi . secondary_iid ) :
   OoOOo = iI11I . inner_dest
   OoOOo . instance_id = II1I11IIi . secondary_iid
   if 17 - 17: i1IIi
   o00oo0 = lisp . lisp_map_cache_lookup ( iI11I . inner_source , OoOOo )
   if ( o00oo0 ) :
    iI11I . gleaned_dest = o00oo0 . gleaned
    o00oo0 . add_recent_source ( iI11I . inner_source )
   else :
    OOo0 , oO00oo0o00o0o , IiIIIIIi = lisp . lisp_allow_gleaning ( OoOOo , None ,
 None )
    iI11I . gleaned_dest = OOo0
    if 1 - 1: ooOoO0o
    if 78 - 78: I1ii11iIi11i + I11i - O0
    if 10 - 10: I1Ii111 % I1IiiI
    if 97 - 97: OoooooooOO - I1Ii111
    if 58 - 58: iIii1I11I1II1 + O0
    if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
    if 46 - 46: i11iIiiIii - O0 . oO0o
    if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
    if 83 - 83: I1Ii111
 if ( o00oo0 == None and OOo0 ) :
  lisp . lprint ( "Suppress Map-Request for gleaned EID {}" . format ( lisp . green ( iI11I . inner_dest . print_address ( ) , False ) ) )
  if 48 - 48: II111iiii * OOooOOo * I1Ii111
  return
  if 50 - 50: IiII % i1IIi
  if 21 - 21: OoooooooOO - iIii1I11I1II1
 if ( o00oo0 == None or lisp . lisp_mr_or_pubsub ( o00oo0 . action ) ) :
  if ( lisp . lisp_rate_limit_map_request ( iI11I . inner_dest ) ) : return
  if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
  O00ooOo = ( o00oo0 and o00oo0 . action == lisp . LISP_SEND_PUBSUB_ACTION )
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 iI11I . inner_source , iI11I . inner_dest , None , O00ooOo )
  if 80 - 80: o0oOOo0O0Ooo - OOooOOo + OoooooooOO
  if ( iI11I . is_trace ( ) ) :
   O0Oo00oO0O00 = oO0oIIII
   O0ooOoO = "map-cache miss"
   lisp . lisp_trace_append ( iI11I , reason = O0ooOoO , lisp_socket = O0Oo00oO0O00 )
   if 26 - 26: OoOoOO00 / Oo0Ooo - i1IIi + I11i
  return
  if 38 - 38: OoooooooOO / I1ii11iIi11i . O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
  if 96 - 96: iII111i
  if 18 - 18: iII111i * I11i - Ii1I
  if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if ( o00oo0 and o00oo0 . refresh ( ) ) :
  if ( lisp . lisp_rate_limit_map_request ( iI11I . inner_dest ) == False ) :
   lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( o00oo0 . print_eid_tuple ( ) , False ) ) )
   if 39 - 39: iIii1I11I1II1 - OoooooooOO
   lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 iI11I . inner_source , iI11I . inner_dest , None )
   if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
   if 23 - 23: II111iiii / oO0o
   if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
   if 19 - 19: I11i
   if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
   if 27 - 27: OOooOOo
   if 89 - 89: II111iiii / oO0o
 o00oo0 . last_refresh_time = time . time ( )
 o00oo0 . stats . increment ( len ( iI11I . packet ) )
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 IIiIi1 , Oo00O0ooOO , IiiI , i11ii , i11I1 , i1I1iI1iIi111i = o00oo0 . select_rloc ( iI11I , None )
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if ( IIiIi1 == None and i11I1 == None ) :
  if ( i11ii == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   iI11I . send_packet ( OOo , iI11I . inner_dest )
   if 32 - 32: i11iIiiIii - I1Ii111
   if ( iI11I . is_trace ( ) ) :
    O0Oo00oO0O00 = oO0oIIII
    O0ooOoO = "not an EID"
    lisp . lisp_trace_append ( iI11I , reason = O0ooOoO , lisp_socket = O0Oo00oO0O00 )
    if 53 - 53: OoooooooOO - IiII
   OO0000o ( Iii1iiIi1II , "RTR" )
   return
   if 87 - 87: oO0o . I1IiiI
  O0ooOoO = "No reachable RLOCs found"
  lisp . dprint ( O0ooOoO )
  if 17 - 17: Ii1I . i11iIiiIii
  if ( iI11I . is_trace ( ) ) :
   O0Oo00oO0O00 = oO0oIIII
   lisp . lisp_trace_append ( iI11I , reason = O0ooOoO , lisp_socket = O0Oo00oO0O00 )
   if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
  return
  if 63 - 63: oO0o
 if ( IIiIi1 and IIiIi1 . is_null ( ) ) :
  lisp . dprint ( "Drop action RLOC found" )
  if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
  if ( iI11I . is_trace ( ) ) :
   O0Oo00oO0O00 = oO0oIIII
   O0ooOoO = "drop action"
   lisp . lisp_trace_append ( iI11I , reason = O0ooOoO , lisp_socket = O0Oo00oO0O00 )
   if 36 - 36: IiII
  return
  if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
  if 74 - 74: I1Ii111 % I1ii11iIi11i
  if 7 - 7: II111iiii
  if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
  if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
 iI11I . outer_tos = iI11I . inner_tos
 iI11I . outer_ttl = iI11I . inner_ttl
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
 if ( IIiIi1 ) :
  iI11I . encap_port = Oo00O0ooOO
  if ( Oo00O0ooOO == 0 ) : iI11I . encap_port = lisp . LISP_DATA_PORT
  iI11I . outer_dest . copy_address ( IIiIi1 )
  o00ooo = iI11I . outer_dest . afi_to_version ( )
  iI11I . outer_version = o00ooo
  if 31 - 31: O0 * o0oOOo0O0Ooo % o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
  III1ii = iIiiI1 if ( o00ooo == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
  iI11I . outer_source . copy_address ( III1ii )
  if 100 - 100: Ii1I + OoO0O00
  if ( iI11I . is_trace ( ) ) :
   O0Oo00oO0O00 = oO0oIIII
   if ( lisp . lisp_trace_append ( iI11I , rloc_entry = i1I1iI1iIi111i ,
 lisp_socket = O0Oo00oO0O00 ) == False ) : return
   if 73 - 73: i1IIi - I1Ii111 % ooOoO0o / OoO0O00
   if 40 - 40: I1ii11iIi11i * ooOoO0o - I1IiiI / IiII / i11iIiiIii
   if 83 - 83: I1ii11iIi11i / I1Ii111 - i11iIiiIii . iIii1I11I1II1 + Oo0Ooo
   if 59 - 59: O0 % Oo0Ooo
   if 92 - 92: Ii1I % iII111i / I1ii11iIi11i % I1ii11iIi11i * I1IiiI
  if ( iI11I . encode ( IiiI ) == None ) : return
  if ( len ( iI11I . packet ) <= 1500 ) : iI11I . print_packet ( "Send" , True )
  if 74 - 74: O0 . I1IiiI % OoO0O00 % IiII
  if 87 - 87: oO0o - i11iIiiIii
  if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
  if 23 - 23: I11i
  iIiiIiiIi = Ii1IIii11 if o00ooo == 6 else OOo
  iI11I . send_packet ( iIiiIiiIi , iI11I . outer_dest )
  if 40 - 40: o0oOOo0O0Ooo
 elif ( i11I1 ) :
  if 78 - 78: iIii1I11I1II1
  if 56 - 56: OoooooooOO - I11i - i1IIi
  if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
  if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
  I11i1iIiiIiIi = len ( iI11I . packet )
  for I1i in i11I1 . rle_forwarding_list :
   iI11I . outer_dest . copy_address ( I1i . address )
   iI11I . encap_port = lisp . LISP_DATA_PORT if I1i . translated_port == 0 else I1i . translated_port
   if 59 - 59: OoooooooOO . Ii1I / O0 - OOooOOo
   if 1 - 1: IiII / IiII - i11iIiiIii
   o00ooo = iI11I . outer_dest . afi_to_version ( )
   iI11I . outer_version = o00ooo
   if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
   III1ii = iIiiI1 if ( o00ooo == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
   iI11I . outer_source . copy_address ( III1ii )
   if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
   if ( iI11I . is_trace ( ) ) :
    O0Oo00oO0O00 = oO0oIIII
    O0ooOoO = "replicate"
    if ( lisp . lisp_trace_append ( iI11I , reason = O0ooOoO , lisp_socket = O0Oo00oO0O00 ) == False ) : return
    if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
    if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
    if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
   if ( iI11I . encode ( None ) == None ) : return
   if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
   iI11I . print_packet ( "Replicate-to-L{}" . format ( I1i . level ) , True )
   iI11I . send_packet ( OOo , iI11I . outer_dest )
   if 77 - 77: OoO0O00 + I1Ii111 + I1Ii111 * Ii1I / OoooooooOO . Ii1I
   if 62 - 62: i1IIi - i1IIi
   if 69 - 69: OoOoOO00 % oO0o - I11i
   if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
   if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
   OO00OO0o0 = len ( iI11I . packet ) - I11i1iIiiIiIi
   iI11I . packet = iI11I . packet [ OO00OO0o0 : : ]
   if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
   if ( lisp . lisp_flow_logging ) : iI11I = copy . deepcopy ( iI11I )
   if 30 - 30: iII111i / OoO0O00 + oO0o
   if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
   if 70 - 70: OoO0O00
   if 46 - 46: I11i - i1IIi
   if 46 - 46: I1Ii111 % Ii1I
   if 72 - 72: iIii1I11I1II1
 del ( iI11I )
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 OO0000o ( Iii1iiIi1II , "RTR" )
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
  iI11I = lisp_thread . input_queue . get ( )
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  if 64 - 64: i1IIi
  if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
  if 18 - 18: OOooOOo + I1Ii111
  lisp_thread . input_stats . increment ( len ( iI11I ) )
  if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
  if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
  if 50 - 50: ooOoO0o + i1IIi
  lisp_thread . lisp_packet . packet = iI11I
  if 31 - 31: Ii1I
  if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
  if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
  if 47 - 47: o0oOOo0O0Ooo
  ooO0o ( lisp_thread . lisp_packet , lisp_thread . thread_name )
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
 O0OoiIIiI11i = iIi11I . number_of_worker_threads
 if 100 - 100: O0 . I11i . OoO0O00 + O0 * oO0o
 iIi11I . input_stats . increment ( len ( packet ) )
 if 42 - 42: oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
 I1IiIii11I = 4 if I1Iii1I == "lo0" else ( 14 if lisp . lisp_is_macos ( ) else 16 )
 packet = packet [ I1IiIii11I : : ]
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
 if 60 - 60: OoO0O00
 if ( O0OoiIIiI11i ) :
  oO00Ooo0oO = iIi11I . input_stats . packet_count % O0OoiIIiI11i
  oO00Ooo0oO = oO00Ooo0oO + ( len ( I11 ) - O0OoiIIiI11i )
  OOOo = I11 [ oO00Ooo0oO ]
  OOOo . input_queue . put ( packet )
 else :
  iIi11I . lisp_packet . packet = packet
  ooO0o ( iIi11I . lisp_packet , iIi11I . thread_name )
  if 74 - 74: Ii1I - OoooooooOO . Oo0Ooo
 return
 if 31 - 31: o0oOOo0O0Ooo % I11i + iIii1I11I1II1 + i11iIiiIii * I1Ii111
 if 45 - 45: OOooOOo * I1Ii111 . ooOoO0o - I1Ii111 + IiII
 if 34 - 34: OOooOOo . Oo0Ooo
 if 78 - 78: I1ii11iIi11i % I1IiiI / OoooooooOO % OOooOOo - iII111i
 if 2 - 2: iIii1I11I1II1
 if 45 - 45: OoooooooOO / i11iIiiIii
 if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
 if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
def iIii1iII1Ii ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 50 - 50: Ii1I
 I1Iii1I = "lo0" if lisp . lisp_is_macos ( ) else "any"
 if 22 - 22: I11i * O0 . II111iiii - OoO0O00
 if 90 - 90: oO0o
 if 94 - 94: I11i / I1ii11iIi11i * I1Ii111 - OoOoOO00
 if 44 - 44: Ii1I % i11iIiiIii - iII111i * I1ii11iIi11i + Oo0Ooo * OOooOOo
 if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
 oOIIIiI1ii1IIi = getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 oOIIIiI1ii1IIi = ( oOIIIiI1ii1IIi != "" and oOIIIiI1ii1IIi [ 0 ] == " " )
 if 55 - 55: iII111i - OoO0O00
 o0 = "(dst host "
 i1I11iI1iiI = ""
 for iI1Iii in lisp . lisp_get_all_addresses ( ) :
  o0 += "{} or " . format ( iI1Iii )
  i1I11iI1iiI += "{} or " . format ( iI1Iii )
  if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 o0 = o0 [ 0 : - 4 ]
 o0 += ") and ((udp dst port 4341 or 8472 or 4789) or "
 o0 += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0))))"
 if 11 - 11: i1IIi % OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
 if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
 if 2 - 2: OoooooooOO . OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 i1I11iI1iiI = i1I11iI1iiI [ 0 : - 4 ]
 o0 += ( " or (not (src host {}) and " + "((udp src port 4342 and ip[28] == 0x28) or " + "(udp dst port 4342 and ip[28] == 0x12)))" ) . format ( i1I11iI1iiI )
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if ( oOIIIiI1ii1IIi ) :
  o0 += ( " or (dst net 0.0.0.0/0 and " + "not (host {} or src net 127.0.0.0/8))" ) . format ( i1I11iI1iiI )
  if 28 - 28: OOooOOo % ooOoO0o
  if 48 - 48: i11iIiiIii % oO0o
  if 29 - 29: iII111i + i11iIiiIii % I11i
 lisp . lprint ( "Capturing packets for: '{}'" . format ( o0 ) )
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if ( lisp . lisp_is_python2 ( ) ) :
  import pcappy
  iii1IiI1I1 = pcappy . open_live ( I1Iii1I , 9000 , 0 , 100 )
  iii1IiI1I1 . filter = o0
  iii1IiI1I1 . loop ( - 1 , Oo , [ I1Iii1I , lisp_thread ] )
  if 64 - 64: ooOoO0o / O0 * OoOoOO00 * ooOoO0o
 if ( lisp . lisp_is_python3 ( ) ) :
  import pcapy
  iii1IiI1I1 = pcapy . open_live ( I1Iii1I , 9000 , 0 , 100 )
  iii1IiI1I1 . setfilter ( o0 )
  while ( True ) :
   O0OO0oOOo , iI11I = iii1IiI1I1 . next ( )
   Oo ( [ I1Iii1I , lisp_thread ] , None , iI11I )
   if 60 - 60: I11i / i1IIi % I1ii11iIi11i / I1ii11iIi11i * I1ii11iIi11i . i11iIiiIii
   if 99 - 99: OoOoOO00
 return
 if 77 - 77: o0oOOo0O0Ooo
 if 48 - 48: OoOoOO00 % I1ii11iIi11i / I11i . iIii1I11I1II1 * II111iiii
 if 65 - 65: OoOoOO00
 if 31 - 31: I11i * OoOoOO00 . IiII % Ii1I + Oo0Ooo
 if 47 - 47: O0 * I1IiiI * OoO0O00 . II111iiii
 if 95 - 95: Ii1I % IiII . O0 % I1Ii111
 if 68 - 68: Oo0Ooo . Oo0Ooo - I1ii11iIi11i / I11i . ooOoO0o / i1IIi
 if 12 - 12: I1ii11iIi11i * i1IIi * I11i
def i1iiI ( lisp_raw_socket , eid , geid , igmp ) :
 if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 iI11I = lisp . lisp_packet ( igmp )
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
 if 46 - 46: I1Ii111
 o00oo0 = lisp . lisp_map_cache_lookup ( eid , geid )
 if ( o00oo0 == None ) : return
 if ( o00oo0 . rloc_set == [ ] ) : return
 if ( o00oo0 . rloc_set [ 0 ] . rle == None ) : return
 if 72 - 72: iII111i * OOooOOo
 oooo = eid . print_address_no_iid ( )
 for iiIi1IIi1I in o00oo0 . rloc_set [ 0 ] . rle . rle_nodes :
  if ( iiIi1IIi1I . rloc_name == oooo ) :
   iI11I . outer_dest . copy_address ( iiIi1IIi1I . address )
   iI11I . encap_port = iiIi1IIi1I . translated_port
   break
   if 27 - 27: i11iIiiIii - I1IiiI
   if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if ( iI11I . outer_dest . is_null ( ) ) : return
 if 50 - 50: OoOoOO00
 iI11I . outer_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 iI11I . outer_version = iI11I . outer_dest . afi_to_version ( )
 iI11I . outer_ttl = 32
 iI11I . inner_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 iI11I . inner_dest . store_address ( "[{}]224.0.0.1" . format ( geid . instance_id ) )
 iI11I . inner_ttl = 1
 if 33 - 33: I11i
 iiI111I1iIiI = lisp . green ( eid . print_address ( ) , False )
 O0ooOoO = lisp . red ( "{}:{}" . format ( iI11I . outer_dest . print_address_no_iid ( ) ,
 iI11I . encap_port ) , False )
 oOo00OoO0O = lisp . bold ( "IGMP Query" , False )
 if 69 - 69: iIii1I11I1II1 * I1IiiI - iII111i + O0 + O0
 lisp . lprint ( "Data encapsulate {} to gleaned EID {}, RLOC {}" . format ( oOo00OoO0O , iiI111I1iIiI , O0ooOoO ) )
 if 65 - 65: I1Ii111 / i11iIiiIii / OoO0O00 - OOooOOo
 if 9 - 9: I1IiiI / I1Ii111 - Oo0Ooo * iIii1I11I1II1
 if 86 - 86: II111iiii + ooOoO0o + IiII
 if 9 - 9: ooOoO0o + II111iiii % ooOoO0o % IiII + iIii1I11I1II1
 if 59 - 59: i1IIi
 if ( iI11I . encode ( None ) == None ) : return
 iI11I . print_packet ( "Send" , True )
 if 48 - 48: O0 * Ii1I * OoO0O00 . OoO0O00 * I11i - Ii1I
 iI11I . send_packet ( lisp_raw_socket , iI11I . outer_dest )
 if 14 - 14: I1ii11iIi11i + i11iIiiIii
 if 83 - 83: I1ii11iIi11i / i11iIiiIii + II111iiii . iII111i * OOooOOo + IiII
 if 42 - 42: i1IIi % II111iiii . ooOoO0o
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
def oOOoo ( lisp_raw_socket ) :
 if ( lisp . lisp_gleaned_groups == { } ) : return
 if 6 - 6: OOooOOo
 if 98 - 98: OoooooooOO % O0 - O0
 if 76 - 76: i1IIi % OoOoOO00 - I1IiiI / o0oOOo0O0Ooo * ooOoO0o
 if 4 - 4: Oo0Ooo * Oo0Ooo / OoOoOO00
 if 4 - 4: I1IiiI * OoOoOO00 % I11i . OoOoOO00
 I1II1III1 = b"\x46\xc0\x00\x24\x00\x00\x40\x00\x01\x02\x00\x00"
 oooo0O0o0OoOO = lisp . lisp_myrlocs [ 0 ]
 iII1 = oooo0O0o0OoOO . address
 I1II1III1 += bytes ( [ ( iII1 >> 24 ) & 0xff , ( iII1 >> 16 ) & 0xff , ( iII1 >> 8 ) & 0xff ,
 iII1 & 0xff ] )
 I1II1III1 += b"\xe0\x00\x00\x01"
 I1II1III1 += b"\x94\x04\x00\x00"
 I1II1III1 = lisp . lisp_ip_checksum ( I1II1III1 , 24 )
 if 36 - 36: oO0o / I1Ii111 - I1IiiI . I1IiiI
 if 2 - 2: IiII + I1ii11iIi11i
 if 91 - 91: I1ii11iIi11i % ooOoO0o
 if 38 - 38: iII111i - OOooOOo . I1IiiI
 if 51 - 51: oO0o + OoO0O00 + iII111i + iII111i % o0oOOo0O0Ooo
 o000OOooo0O = b"\x11\x64\x00\x00" + b"\x00\x00\x00\x00" + b"\x02\x3c\x00\x00"
 o000OOooo0O = lisp . lisp_igmp_checksum ( o000OOooo0O )
 if 29 - 29: ooOoO0o
 if 41 - 41: O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 o00oO0oo0OO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  o00oO0oo0OO . store_address ( Ii1iIiII1ii1 )
  for Ooo0oO in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   i1 . store_address ( Ooo0oO )
   oO00oo0o00o0o , IiIIIIIi , Ii = lisp . lisp_allow_gleaning ( o00oO0oo0OO , i1 , None )
   if ( Ii == False ) : continue
   i1iiI ( lisp_raw_socket , o00oO0oo0OO , i1 , I1II1III1 + o000OOooo0O )
   if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
   if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
   if 81 - 81: IiII / OoOoOO00 * IiII . O0
   if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
   if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
   if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
   if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
   if 61 - 61: I1Ii111 - Ii1I % I1ii11iIi11i / ooOoO0o / iII111i + iIii1I11I1II1
   if 87 - 87: I1Ii111 + ooOoO0o + O0 / i1IIi % IiII / I1Ii111
   if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
def OOOO00OooO ( ) :
 o00oO0oo0OO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 64 - 64: OoO0O00 . I1IiiI - OoooooooOO . ooOoO0o - iII111i
 O0oO0o000o = [ ]
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  for Ooo0oO in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   i11i11II11i1 = lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] [ Ooo0oO ]
   iiiI1i1 = time . time ( ) - i11i11II11i1
   if ( iiiI1i1 < lisp . LISP_IGMP_TIMEOUT_INTERVAL ) : continue
   O0oO0o000o . append ( [ Ii1iIiII1ii1 , Ooo0oO ] )
   if 44 - 44: OOooOOo + I11i . IiII / II111iiii % iIii1I11I1II1 + IiII
   if 61 - 61: OOooOOo / OoO0O00 + II111iiii . oO0o / Oo0Ooo * OOooOOo
   if 46 - 46: iIii1I11I1II1
   if 33 - 33: I11i % I11i % O0 / I1IiiI . i1IIi
   if 91 - 91: ooOoO0o * I11i - II111iiii . I1IiiI - Oo0Ooo + ooOoO0o
   if 56 - 56: o0oOOo0O0Ooo / IiII * I1IiiI . o0oOOo0O0Ooo
   if 15 - 15: i11iIiiIii
 I11i1I1ii1i1 = lisp . bold ( "timed out" , False )
 for Ii1iIiII1ii1 , Ooo0oO in O0oO0o000o :
  o00oO0oo0OO . store_address ( Ii1iIiII1ii1 )
  i1 . store_address ( Ooo0oO )
  iiI111I1iIiI = lisp . green ( Ii1iIiII1ii1 , False )
  oO0ooooo0O00 = lisp . green ( Ooo0oO , False )
  lisp . lprint ( "{} RLE {} for gleaned group {}" . format ( iiI111I1iIiI , I11i1I1ii1i1 , oO0ooooo0O00 ) )
  lisp . lisp_remove_gleaned_multicast ( o00oO0oo0OO , i1 )
  if 5 - 5: OoOoOO00 % iII111i + IiII
  if 13 - 13: IiII
  if 19 - 19: II111iiii - IiII
  if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
  if 89 - 89: OOooOOo
  if 69 - 69: ooOoO0o - OoooooooOO * O0
  if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
  if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
def oo00o0 ( lisp_raw_socket ) :
 lisp . lisp_set_exception ( )
 if 17 - 17: Ii1I / iIii1I11I1II1 - OoO0O00 + I1IiiI % OOooOOo
 if 14 - 14: o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
 if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
 if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
 for oO0OOOO0 in list ( lisp . lisp_crypto_keys_by_nonce . values ( ) ) :
  for OoooooOo in oO0OOOO0 : del ( OoooooOo )
  if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 lisp . lisp_crypto_keys_by_nonce . clear ( )
 lisp . lisp_crypto_keys_by_nonce = { }
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 if 88 - 88: o0oOOo0O0Ooo
 if 1 - 1: OoooooooOO
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 lisp . lisp_rtr_nat_trace_cache . clear ( )
 lisp . lisp_rtr_nat_trace_cache = { }
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 OOOO00OooO ( )
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 oOOoo ( lisp_raw_socket )
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 Oooo0000 = threading . Timer ( 60 , oo00o0 ,
 [ lisp_raw_socket ] )
 Oooo0000 . start ( )
 return
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
def I1ii1Ii1 ( ) :
 global Oo0oO0oo0oO00 , II1iII1i , II1Ii1iI1i
 global OOo , Ii1IIii11 , I11
 global i111I , oO0oIIII
 global iIiiI1
 if 73 - 73: O0 . oO0o + i11iIiiIii + iIii1I11I1II1 - I11i / OoOoOO00
 lisp . lisp_i_am ( "rtr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "RTR starting up" )
 if 99 - 99: I1ii11iIi11i * oO0o * I1ii11iIi11i - II111iiii + Ii1I
 if 72 - 72: o0oOOo0O0Ooo % I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 iIiiI1 = lisp . lisp_myrlocs [ 0 ]
 if ( lisp . lisp_on_aws ( ) ) :
  III11I1 = lisp . bold ( "AWS RTR" , False )
  iII1 = None
  for I1Iii1I in [ "eth0" , "ens5" ] :
   iII1 = lisp . lisp_get_interface_address ( I1Iii1I )
   if ( iII1 != None ) : break
   if 61 - 61: OoOoOO00 - OoO0O00 + I1IiiI * OOooOOo % OoO0O00
  if ( iII1 != None ) :
   iIiiI1 = iII1
   iI1Iii = iII1 . print_address_no_iid ( )
   lisp . lprint ( "{} using RLOC {} on {}" . format ( III11I1 , iI1Iii , I1Iii1I ) )
  else :
   iI1Iii = iIiiI1 . print_address_no_iid ( )
   lisp . lprint ( "{} cannot obtain RLOC, using {}" . format ( III11I1 , iI1Iii ) )
   if 24 - 24: ooOoO0o - I11i * oO0o
   if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
   if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
   if 79 - 79: IiII % OoO0O00
   if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
   if 32 - 32: O0 . OoooooooOO
   if 15 - 15: I1IiiI . OoO0O00
   if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 Ii1 = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 II1Ii1iI1i = lisp . lisp_open_listen_socket ( Ii1 ,
 str ( iiI1iIiI ) )
 Oo0oO0oo0oO00 = lisp . lisp_open_listen_socket ( "" , "lisp-rtr" )
 i111I = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 if 59 - 59: Oo0Ooo % O0 . OoOoOO00
 II1iII1i [ 0 ] = II1Ii1iI1i
 if 41 - 41: i1IIi + II111iiii * ooOoO0o
 II1iII1i [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 II1iII1i [ 2 ] = Oo0oO0oo0oO00
 if 68 - 68: Ii1I - I1IiiI
 if 41 - 41: oO0o
 if 21 - 21: ooOoO0o + o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + II111iiii
 if 98 - 98: I1Ii111
 if 49 - 49: Oo0Ooo * oO0o + o0oOOo0O0Ooo - i11iIiiIii
 if 74 - 74: Oo0Ooo / iIii1I11I1II1 . II111iiii - OoO0O00
 if 62 - 62: OOooOOo / II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
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
  threading . Thread ( target = iIii1iII1Ii , args = [ III11IiiiIi1 ] ) . start ( )
  if 20 - 20: II111iiii - I11i + i1IIi + Ii1I
  if 7 - 7: ooOoO0o + Ii1I
  if 32 - 32: iIii1I11I1II1 % I1IiiI / i11iIiiIii + OOooOOo - o0oOOo0O0Ooo . iII111i
  if 86 - 86: i1IIi / Ii1I * I1IiiI
  if 67 - 67: I1ii11iIi11i * I1ii11iIi11i / oO0o * OoooooooOO + OoOoOO00
  if 79 - 79: i1IIi
 for IIIi in range ( oo ) :
  III11IiiiIi1 = lisp . lisp_thread ( "worker-{}" . format ( IIIi ) )
  I11 . append ( III11IiiiIi1 )
  threading . Thread ( target = I1I1iII1i , args = [ III11IiiiIi1 ] ) . start ( )
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
 Oooo0000 = threading . Timer ( 60 , oo00o0 ,
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
  o00O0OoO = [ II1Ii1iI1i , II1Ii1iI1i ,
 None , OOo ]
  lisp . lisp_start_rloc_probe_timer ( 1 , o00O0OoO )
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

 "show rtr-rloc-probing" : [ iiii , { } ] ,
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
 Oo0o0O0o , oO0o0O0Ooo0o , i1I , iI11I = lisp . lisp_receive ( lisp_socket , False )
 iii1IiI1i = lisp . lisp_trace ( )
 if ( iii1IiI1i . decode ( iI11I ) == False ) : return
 if 93 - 93: i1IIi % OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo . O0 % OOooOOo
 if 88 - 88: oO0o % Oo0Ooo - I11i % oO0o + IiII - iII111i
 if 23 - 23: O0
 if 9 - 9: I11i * Oo0Ooo . ooOoO0o * i11iIiiIii - O0
 if 54 - 54: I1IiiI * OOooOOo + o0oOOo0O0Ooo % i1IIi - o0oOOo0O0Ooo + OoOoOO00
 iii1IiI1i . rtr_cache_nat_trace ( oO0o0O0Ooo0o , i1I )
 if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
 if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
 if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
 if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
 if 46 - 46: iIii1I11I1II1
 if 70 - 70: i1IIi . I11i
if ( I1ii1Ii1 ( ) == False ) :
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
 try : iIiIIi11iI , ooo00o0o , oO00oo0o00o0o = select . select ( II1IIiiI1 , [ ] , [ ] )
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
  Oo0o0O0o , oO0o0O0Ooo0o , i1I , iI11I = lisp . lisp_receive ( O00O00 [ 0 ] ,
 False )
  if ( oO0o0O0Ooo0o == "" ) : break
  if ( lisp . lisp_is_rloc_probe_request ( iI11I [ 0 : 1 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
   continue
   if 90 - 90: Oo0Ooo * I1IiiI
  if ( lisp . lisp_is_rloc_probe_reply ( iI11I [ 0 : 1 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
   continue
   if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  lisp . lisp_parse_packet ( O00O00 , iI11I , oO0o0O0Ooo0o , i1I )
  if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
  if 28 - 28: IiII * I1IiiI % IiII
  if 95 - 95: O0 / I11i . I1Ii111
  if 17 - 17: I11i
  if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
  if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if ( Oo0oO0oo0oO00 in iIiIIi11iI ) :
  Oo0o0O0o , oO0o0O0Ooo0o , i1I , iI11I = lisp . lisp_receive ( Oo0oO0oo0oO00 , True )
  if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
  if ( oO0o0O0Ooo0o == "" ) : break
  if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
  if ( Oo0o0O0o == "command" ) :
   if ( iI11I == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 38 - 38: I1Ii111
   if ( iI11I . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( iI11I )
    continue
    if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
   lispconfig . lisp_process_command ( Oo0oO0oo0oO00 , Oo0o0O0o ,
 iI11I , "lisp-rtr" , [ i1Ii11ii1I ] )
  elif ( Oo0o0O0o == "api" ) :
   lisp . lisp_process_api ( "lisp-rtr" , Oo0oO0oo0oO00 , iI11I )
  elif ( Oo0o0O0o == "data-packet" ) :
   ooO0o ( iI11I , "" )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( iI11I [ 0 : 1 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
    continue
    if 22 - 22: oO0o * iII111i
   if ( lisp . lisp_is_rloc_probe_reply ( iI11I [ 0 : 1 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
    continue
    if 4 - 4: OoOoOO00 - oO0o + I1IiiI
   lisp . lisp_parse_packet ( II1iII1i , iI11I , oO0o0O0Ooo0o , i1I )
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
