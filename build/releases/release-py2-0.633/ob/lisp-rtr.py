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
I1I11I1I1I = None
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
  iiIi1IIi1I = i1I1iI1iIi111i . normalize_decent_nat_rloc_name ( )
  if ( iiIi1IIi1I != OoOO ) : continue
  if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
  if ( i1I1iI1iIi111i . rle ) :
   for O0ooO0Oo00o in i1I1iI1iIi111i . rle . rle_nodes :
    O0ooO0Oo00o . store_translated_rloc ( iII1 , i1I )
    ooO0oOOooOo0 = O0ooO0Oo00o . rloc . rloc . print_address_no_iid ( ) + ":" + str ( O0ooO0Oo00o . rloc . translated_port )
    if 38 - 38: I1Ii111
    lisp . lprint ( oO00OOoO00 . format ( "RLE" , ooO0oOOooOo0 ) )
    if 84 - 84: iIii1I11I1II1 % iII111i / iIii1I11I1II1 % I11i
    if 45 - 45: O0
    if 26 - 26: I11i - iIii1I11I1II1 - I1IiiI / OoO0O00 . OoOoOO00 % iIii1I11I1II1
    if 91 - 91: o0oOOo0O0Ooo . iIii1I11I1II1 / oO0o + i1IIi
    if 42 - 42: ooOoO0o . o0oOOo0O0Ooo . ooOoO0o - I1ii11iIi11i
    if 40 - 40: ooOoO0o - i11iIiiIii / Ii1I
    if 35 - 35: Ii1I - I1IiiI % o0oOOo0O0Ooo . OoooooooOO % Ii1I
    if 47 - 47: iII111i - Ii1I . II111iiii + OoooooooOO . i11iIiiIii
  ooO0oOOooOo0 = i1I1iI1iIi111i . rloc . print_address_no_iid ( ) + ":" + str ( i1I1iI1iIi111i . translated_port )
  if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
  if ( ooO0oOOooOo0 in lisp . lisp_crypto_keys_by_rloc_encap ) :
   oO0 = lisp . lisp_crypto_keys_by_rloc_encap [ ooO0oOOooOo0 ]
   lisp . lisp_crypto_keys_by_rloc_encap [ iI1Iii ] = oO0
   if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
   if 55 - 55: OOooOOo . I1IiiI
   if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
   if 100 - 100: I1Ii111 * O0
   if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
  i1I1iI1iIi111i . delete_from_rloc_probe_list ( mc . eid , mc . group )
  i1I1iI1iIi111i . store_translated_rloc ( iII1 , i1I )
  i1I1iI1iIi111i . add_to_rloc_probe_list ( mc . eid , mc . group )
  lisp . lprint ( oO00OOoO00 . format ( "RLOC" , ooO0oOOooOo0 ) )
  if 79 - 79: O0
  if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
  if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
  if 57 - 57: OoO0O00 / ooOoO0o
  if ( lisp . lisp_rloc_probing ) :
   Ii1I1Ii = None if ( mc . group . is_null ( ) ) else mc . eid
   OOoO0 = mc . eid if ( mc . group . is_null ( ) ) else mc . group
   lisp . lisp_send_map_request ( o00O0OoO , 0 , Ii1I1Ii , OOoO0 , i1I1iI1iIi111i )
   if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
   if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
   if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
   if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
   if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
   if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 lisp . lisp_write_ipc_map_cache ( True , mc )
 return ( True , parms )
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 if 49 - 49: I1IiiI - I11i
 if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
 if 62 - 62: OoooooooOO * I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
def i1OOoO ( mc , parms ) :
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 if ( mc . group . is_null ( ) ) : return ( oo0o00O ( mc , parms ) )
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 if ( mc . source_cache == None ) : return ( True , parms )
 if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
 if 71 - 71: Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
 mc . source_cache . walk_cache ( oo0o00O , parms )
 return ( True , parms )
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
 if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
 if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
 if 71 - 71: I1Ii111 + Ii1I
 if 28 - 28: OOooOOo
 if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
 if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
def IIo0Oo0oO0oOO00 ( sockets , hostname , rloc , port ) :
 lisp . lisp_map_cache . walk_cache ( i1OOoO ,
 [ sockets , rloc , port , hostname ] )
 return
 if 92 - 92: OoooooooOO * I1Ii111
 if 100 - 100: I1Ii111 + I1Ii111 * IiII
 if 1 - 1: ooOoO0o . ooOoO0o / OoOoOO00 - I1Ii111
 if 86 - 86: iIii1I11I1II1 / OoOoOO00 . II111iiii
 if 19 - 19: I1ii11iIi11i % OoooooooOO % IiII * o0oOOo0O0Ooo % O0
 if 67 - 67: I1IiiI . i1IIi
 if 27 - 27: ooOoO0o % I1IiiI
def o0oooOO00 ( sred , packet ) :
 if ( lisp . lisp_data_plane_logging == False ) : return
 if 32 - 32: I1Ii111
 if ( sred in [ "Send" , "Receive" ] ) :
  Iii1 = binascii . hexlify ( packet [ 0 : 20 ] ) . decode ( )
  lisp . lprint ( "Fast-{}: ip {} {} {} {} {}" . format ( sred , Iii1 [ 0 : 8 ] , Iii1 [ 8 : 16 ] ,
 Iii1 [ 16 : 24 ] , Iii1 [ 24 : 32 ] , Iii1 [ 32 : 40 ] ) )
 elif ( sred in [ "Encap" , "Decap" ] ) :
  Iii1 = binascii . hexlify ( packet [ 0 : 36 ] ) . decode ( )
  lisp . lprint ( "Fast-{}: ip {} {} {} {} {}, udp {} {}, lisp {} {}" . format ( sred , Iii1 [ 0 : 8 ] , Iii1 [ 8 : 16 ] , Iii1 [ 16 : 24 ] , Iii1 [ 24 : 32 ] , Iii1 [ 32 : 40 ] ,
  # o0oOOo0O0Ooo + o0oOOo0O0Ooo + i1IIi - i1IIi
 Iii1 [ 40 : 48 ] , Iii1 [ 48 : 56 ] , Iii1 [ 56 : 64 ] , Iii1 [ 64 : 72 ] ) )
  if 76 - 76: OoO0O00 . O0 % O0 - o0oOOo0O0Ooo - iIii1I11I1II1 - I1IiiI
  if 53 - 53: i1IIi
  if 59 - 59: o0oOOo0O0Ooo
  if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
  if 73 - 73: I11i % i11iIiiIii - I1IiiI
  if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
  if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
  if 23 - 23: i11iIiiIii
def II1iIi11 ( dest , mc ) :
 if ( lisp . lisp_data_plane_logging == False ) : return
 if 12 - 12: Ii1I + i11iIiiIii * iIii1I11I1II1 / I1ii11iIi11i . I11i
 Iii1iI = "miss" if mc == None else "hit!"
 lisp . lprint ( "Fast-Lookup {} {}" . format ( dest . print_address ( ) , Iii1iI ) )
 if 29 - 29: I1IiiI % OOooOOo - I1IiiI / OOooOOo . i1IIi
 if 31 - 31: I1Ii111
 if 88 - 88: OoO0O00 - ooOoO0o + OOooOOo * I1IiiI % iIii1I11I1II1 + Oo0Ooo
 if 76 - 76: I1IiiI * iII111i % I1Ii111
 if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
 if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
 if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
 if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
def I11IIIi ( a ) :
 iIIiiI1II1i11 = ord ( a [ 0 : 1 ] ) << 24 | ord ( a [ 1 : 2 ] ) << 16 | ord ( a [ 2 : 3 ] ) << 8 | ord ( a [ 3 : 4 ] )
 if 65 - 65: Ii1I / I11i / OoOoOO00
 return ( iIIiiI1II1i11 )
 if 92 - 92: O0 - iII111i . OOooOOo * Ii1I
 if 42 - 42: I11i / o0oOOo0O0Ooo . oO0o + oO0o % OoOoOO00 + i11iIiiIii
 if 56 - 56: o0oOOo0O0Ooo
 if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
 if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
 if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
 if 79 - 79: O0 * i11iIiiIii - IiII / IiII
 if 48 - 48: O0
def Oo0o0O00 ( byte ) :
 return ( chr ( byte ) )
 if 40 - 40: OoooooooOO
def I1i1i1 ( byte ) :
 return ( bytes ( [ byte ] ) )
 if 73 - 73: O0 * iII111i + Ii1I + ooOoO0o
 if 40 - 40: II111iiii . OoOoOO00 * I1Ii111 + OOooOOo + OOooOOo
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
 Iii1iiIi1II = lisp . lisp_latency_debug ( None , "RTR-Fast" )
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
   iii11I = ord ( iii11I [ 0 : 1 ] ) << 16 | ord ( iii11I [ 1 : 2 ] ) << 8 | ord ( iii11I [ 2 : 3 ] )
   if ( iii11I == 0xffffff ) : return ( False )
   o0oooOO00 ( "Decap" , packet )
   packet = packet [ 36 : : ]
   if 75 - 75: iIii1I11I1II1 - Ii1I . Oo0Ooo % i11iIiiIii % I11i
   if 55 - 55: iII111i . II111iiii % OoO0O00 * iII111i + ooOoO0o + Ii1I
   if 24 - 24: Oo0Ooo - oO0o % iIii1I11I1II1 . i1IIi / O0
 o0oooOO00 ( "Receive" , packet )
 if 36 - 36: I1IiiI - I11i
 if 29 - 29: ooOoO0o * OOooOOo
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 I1ii11 = I11IIIi ( packet [ 16 : 20 ] )
 IiI . instance_id = iii11I
 IiI . address = I1ii11
 if 74 - 74: Oo0Ooo - o0oOOo0O0Ooo . i1IIi
 if 43 - 43: iII111i / I1IiiI
 if 58 - 58: I1IiiI + i11iIiiIii % Ii1I . OoOoOO00
 if 13 - 13: i11iIiiIii + i1IIi * iIii1I11I1II1 % OoooooooOO - II111iiii * OOooOOo
 if ( ( I1ii11 & 0xf0000000 ) == 0xe0000000 ) : return ( False )
 if 26 - 26: OoooooooOO * I1IiiI + OOooOOo
 if 24 - 24: i11iIiiIii % iIii1I11I1II1 + OOooOOo / i11iIiiIii
 if 70 - 70: OoO0O00 * O0 . I11i + I1IiiI . IiII
 if 14 - 14: iIii1I11I1II1 % iIii1I11I1II1 * i11iIiiIii - OoO0O00 - I11i
 if 63 - 63: OoO0O00
 if ( packet [ 9 : 10 ] == b'\x11' ) :
  if ( packet [ 20 : 22 ] == b'\x09\x82' ) : return ( False )
  if ( packet [ 22 : 24 ] == b'\x09\x82' ) : return ( False )
  if 69 - 69: iIii1I11I1II1 . I1ii11iIi11i % ooOoO0o + iIii1I11I1II1 / O0 / I1ii11iIi11i
  if 61 - 61: OOooOOo % OOooOOo * o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 75 - 75: IiII . ooOoO0o
  if 50 - 50: OoOoOO00
  if 60 - 60: ooOoO0o * iIii1I11I1II1 * I1ii11iIi11i * Oo0Ooo
 I1ii11 = IiI
 O0ooooo0OOOO0 = lisp . lisp_map_cache . lookup_cache ( I1ii11 , False )
 II1iIi11 ( I1ii11 , O0ooooo0OOOO0 )
 if ( O0ooooo0OOOO0 == None ) : return ( False )
 if 9 - 9: II111iiii - o0oOOo0O0Ooo / iII111i / o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * OOooOOo . iII111i % O0
 if 9 - 9: oO0o + I11i / I11i
 if 12 - 12: OoooooooOO % o0oOOo0O0Ooo * I11i % iIii1I11I1II1 / Ii1I
 if 27 - 27: i11iIiiIii % II111iiii % I11i . O0 - Oo0Ooo + OoOoOO00
 if ( I1Iii1 != None ) :
  ooO0o = I11IIIi ( packet [ 12 : 16 ] )
  iI1 . instance_id = iii11I
  iI1 . address = ooO0o
  ooOOo00O00Oo = lisp . lisp_map_cache . lookup_cache ( iI1 , False )
  if ( ooOOo00O00Oo == None ) :
   IiII1 , I1iIi1iIiiIiI , I1i11ii = lisp . lisp_allow_gleaning ( iI1 , None ,
 None )
   if ( IiII1 ) : return ( False )
  elif ( ooOOo00O00Oo . gleaned ) :
   I1Iii1 = I11IIIi ( I1Iii1 )
   if ( ooOOo00O00Oo . rloc_set [ 0 ] . rloc . address != I1Iii1 ) : return ( False )
   if 42 - 42: iII111i + IiII
   if 96 - 96: OOooOOo
   if 85 - 85: o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . O0 % I1Ii111
   if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
   if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
  O0ooooo0OOOO0 . add_recent_source ( iI1 )
  if 74 - 74: O0 / i1IIi
  if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
  if 31 - 31: OoooooooOO . OOooOOo
  if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
  if 100 - 100: OoO0O00
 if ( O0ooooo0OOOO0 . action == lisp . LISP_NATIVE_FORWARD_ACTION and
 O0ooooo0OOOO0 . eid . instance_id == 0 ) :
  I1ii11 . instance_id = lisp . lisp_default_secondary_iid
  O0ooooo0OOOO0 = lisp . lisp_map_cache . lookup_cache ( I1ii11 , False )
  II1iIi11 ( I1ii11 , O0ooooo0OOOO0 )
  if ( O0ooooo0OOOO0 == None ) : return ( False )
  if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
  if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
  if 45 - 45: I1Ii111
  if 83 - 83: OoOoOO00 . OoooooooOO
  if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
  if 62 - 62: OoO0O00 / I1ii11iIi11i
 if ( O0ooooo0OOOO0 . action != lisp . LISP_NATIVE_FORWARD_ACTION ) :
  if ( O0ooooo0OOOO0 . best_rloc_set == [ ] ) : return ( False )
  if 7 - 7: OoooooooOO . IiII
  I1ii11 = O0ooooo0OOOO0 . best_rloc_set [ 0 ]
  if ( I1ii11 . state != lisp . LISP_RLOC_UP_STATE ) : return ( False )
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
  iii11I = O0ooooo0OOOO0 . eid . instance_id
  i1I = I1ii11 . translated_port
  Oooo00 = I1ii11 . stats
  I1ii11 = I1ii11 . rloc
  I111iIi1 = I1ii11 . address
  I1Iii1 = lisp . lisp_myrlocs [ 0 ] . address
  if 92 - 92: ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  o00 = b'\x45\x00'
  oO = len ( packet ) + 20 + 8 + 8
  o00 += I1I11I1I1I ( ( oO >> 8 ) & 0xff )
  o00 += I1I11I1I1I ( oO & 0xff )
  o00 += b'\xff\xff\x40\x00\x10\x11\x00\x00'
  o00 += I1I11I1I1I ( ( I1Iii1 >> 24 ) & 0xff )
  o00 += I1I11I1I1I ( ( I1Iii1 >> 16 ) & 0xff )
  o00 += I1I11I1I1I ( ( I1Iii1 >> 8 ) & 0xff )
  o00 += I1I11I1I1I ( I1Iii1 & 0xff )
  o00 += I1I11I1I1I ( ( I111iIi1 >> 24 ) & 0xff )
  o00 += I1I11I1I1I ( ( I111iIi1 >> 16 ) & 0xff )
  o00 += I1I11I1I1I ( ( I111iIi1 >> 8 ) & 0xff )
  o00 += I1I11I1I1I ( I111iIi1 & 0xff )
  o00 = lisp . lisp_ip_checksum ( o00 )
  if 92 - 92: IiII * Oo0Ooo * Oo0Ooo * I1IiiI . iIii1I11I1II1
  if 16 - 16: ooOoO0o % OoooooooOO - OOooOOo * Ii1I * I1ii11iIi11i / OoooooooOO
  if 31 - 31: I11i . I1Ii111 * ooOoO0o + i11iIiiIii * oO0o
  if 93 - 93: I1ii11iIi11i / iIii1I11I1II1 * i1IIi % OoooooooOO * O0 * I11i
  Ooooooo = oO - 20
  I1IIIiI1I1ii1 = b'\xff\x00' if ( i1I == 4341 ) else b'\x10\xf5'
  I1IIIiI1I1ii1 += I1I11I1I1I ( ( i1I >> 8 ) & 0xff )
  I1IIIiI1I1ii1 += I1I11I1I1I ( i1I & 0xff )
  I1IIIiI1I1ii1 += I1I11I1I1I ( ( Ooooooo >> 8 ) & 0xff )
  I1IIIiI1I1ii1 += I1I11I1I1I ( Ooooooo & 0xff )
  I1IIIiI1I1ii1 += b'\x00'
  I1IIIiI1I1ii1 += b'\x00'
  if 30 - 30: O0 * OoooooooOO
  I1IIIiI1I1ii1 += b'\x08\xdf\xdf\xdf'
  I1IIIiI1I1ii1 += I1I11I1I1I ( ( iii11I >> 16 ) & 0xff )
  I1IIIiI1I1ii1 += I1I11I1I1I ( ( iii11I >> 8 ) & 0xff )
  I1IIIiI1I1ii1 += I1I11I1I1I ( iii11I & 0xff )
  I1IIIiI1I1ii1 += b'\x00'
  if 38 - 38: IiII - I1ii11iIi11i . OoOoOO00 - I1Ii111 . OoooooooOO
  if 89 - 89: iIii1I11I1II1
  if 21 - 21: I11i % I11i
  if 27 - 27: i11iIiiIii / I1ii11iIi11i
  packet = o00 + I1IIIiI1I1ii1 + packet
  o0oooOO00 ( "Encap" , packet )
 else :
  oO = len ( packet )
  Oooo00 = O0ooooo0OOOO0 . stats
  o0oooOO00 ( "Send" , packet )
  if 84 - 84: Oo0Ooo
  if 43 - 43: oO0o - OoooooooOO
  if 3 - 3: O0 / iII111i
  if 31 - 31: OOooOOo + o0oOOo0O0Ooo . OoooooooOO
  if 89 - 89: II111iiii + i1IIi + II111iiii
 O0ooooo0OOOO0 . last_refresh_time = time . time ( )
 Oooo00 . increment ( oO )
 if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
 if 42 - 42: OoOoOO00 * OoOoOO00 * I1Ii111 . I11i
 if 51 - 51: OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o * iIii1I11I1II1 % OoO0O00
 if 99 - 99: oO0o * II111iiii * I1Ii111
 I1ii11 = I1ii11 . print_address_no_iid ( )
 OOo . sendto ( packet , ( I1ii11 , 0 ) )
 if 92 - 92: Oo0Ooo
 lisp . lisp_latency_debug ( Iii1iiIi1II , "RTR-Fast" )
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
 Iii1iiIi1II = lisp . lisp_latency_debug ( None , "RTR" )
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if ( oo0Ooo0 ) :
  if ( oO0o0oooO0oO ( lisp_packet . packet ) ) : return
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
  o0O0Oo00Oo0o , OOOo , i1I , oo0OOo0O = lisp . lisp_is_rloc_probe ( oOoOOo0oo0 , "?" , - 1 )
  if ( oOoOOo0oo0 != o0O0Oo00Oo0o ) :
   if ( OOOo == None ) : return
   lisp . lisp_parse_packet ( II1iII1i , o0O0Oo00Oo0o , OOOo , i1I , oo0OOo0O )
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
   Iii1 = Ooooo00o0OoO . udp_sport
   if ( lisp . lisp_store_nat_info ( ooo , OOOO0oooo , Iii1 ) ) :
    IIo0Oo0oO0oOO00 ( II1iII1i , ooo , OOOO0oooo , Iii1 )
    if 51 - 51: O0 - i1IIi / I1IiiI
  else :
   OOOo = Ooooo00o0OoO . outer_source . print_address_no_iid ( )
   oo0OOo0O = Ooooo00o0OoO . outer_ttl
   Ooooo00o0OoO = Ooooo00o0OoO . packet
   if ( lisp . lisp_is_rloc_probe_request ( Ooooo00o0OoO [ 28 : 29 ] ) == False and
 lisp . lisp_is_rloc_probe_reply ( Ooooo00o0OoO [ 28 : 29 ] ) == False ) :
    oo0OOo0O = - 1
    if 37 - 37: o0oOOo0O0Ooo % ooOoO0o
   Ooooo00o0OoO = Ooooo00o0OoO [ 28 : : ]
   lisp . lisp_parse_packet ( II1iII1i , Ooooo00o0OoO , OOOo , 0 , oo0OOo0O )
   if 83 - 83: OOooOOo . I1Ii111 + oO0o - OOooOOo * I1Ii111 / I1Ii111
  return
  if 39 - 39: I1Ii111 / Oo0Ooo % OoO0O00 % i11iIiiIii
  if 90 - 90: I1Ii111 - OoooooooOO
  if 96 - 96: O0 . Ii1I % OoO0O00 * iIii1I11I1II1
  if 54 - 54: Ii1I * I1Ii111 - OoooooooOO % I1IiiI + O0
  if 6 - 6: I1ii11iIi11i - II111iiii / oO0o + i11iIiiIii + OOooOOo
  if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 79 - 79: Ii1I . OoO0O00
  if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
  if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
  if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
  if 52 - 52: i1IIi
 if ( oooo0O0O0o0 ) :
  lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( Ooooo00o0OoO . packet ) )
  if 84 - 84: Ii1I / IiII
  if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
  if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
  if 37 - 37: i11iIiiIii + i1IIi
  if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 I1iIi1iiiIiI = False
 if ( Ooooo00o0OoO . inner_dest . is_mac ( ) ) :
  Ooooo00o0OoO . packet = lisp . lisp_mac_input ( Ooooo00o0OoO . packet )
  if ( Ooooo00o0OoO . packet == None ) : return
  Ooooo00o0OoO . encap_port = lisp . LISP_VXLAN_DATA_PORT
 elif ( Ooooo00o0OoO . inner_version == 4 ) :
  I1iIi1iiiIiI , Ooooo00o0OoO . packet = lisp . lisp_ipv4_input ( Ooooo00o0OoO . packet )
  if ( Ooooo00o0OoO . packet == None ) : return
  Ooooo00o0OoO . inner_ttl = Ooooo00o0OoO . outer_ttl
 elif ( Ooooo00o0OoO . inner_version == 6 ) :
  Ooooo00o0OoO . packet = lisp . lisp_ipv6_input ( Ooooo00o0OoO )
  if ( Ooooo00o0OoO . packet == None ) : return
  Ooooo00o0OoO . inner_ttl = Ooooo00o0OoO . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 41 - 41: I1ii11iIi11i * ooOoO0o - Ii1I + Oo0Ooo
  if 23 - 23: II111iiii % o0oOOo0O0Ooo + o0oOOo0O0Ooo + iII111i - iII111i
  if 62 - 62: o0oOOo0O0Ooo
  if 45 - 45: OOooOOo * ooOoO0o
  if 74 - 74: i1IIi + O0 + Oo0Ooo
 if ( Ooooo00o0OoO . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( Ooooo00o0OoO , ed = "decap" ) == False ) : return
  Ooooo00o0OoO . outer_source . afi = lisp . LISP_AFI_NONE
  Ooooo00o0OoO . outer_dest . afi = lisp . LISP_AFI_NONE
  if 5 - 5: Oo0Ooo * OoOoOO00
  if 46 - 46: ooOoO0o
  if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
  if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
  if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
  if 72 - 72: i1IIi
 IiII1 , I1iIi1iIiiIiI , I1i11ii = lisp . lisp_allow_gleaning ( Ooooo00o0OoO . inner_source , None ,
 Ooooo00o0OoO . outer_source )
 if ( IiII1 ) :
  OOoo0oo = Ooooo00o0OoO . packet if ( I1iIi1iiiIiI ) else None
  lisp . lisp_glean_map_cache ( Ooooo00o0OoO . inner_source , Ooooo00o0OoO . outer_source ,
 Ooooo00o0OoO . udp_sport , OOoo0oo )
  if ( I1iIi1iiiIiI ) : return
  if 58 - 58: oO0o
  if 4 - 4: II111iiii . ooOoO0o / I1ii11iIi11i - i11iIiiIii
  if 72 - 72: O0 / ooOoO0o + OoooooooOO * iII111i
  if 61 - 61: OoooooooOO % II111iiii - I1IiiI % I1ii11iIi11i + i1IIi
  if 39 - 39: i1IIi
  if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 OOoO0 = Ooooo00o0OoO . inner_dest
 if ( OOoO0 . is_multicast_address ( ) ) :
  if ( OOoO0 . is_link_local_multicast ( ) ) :
   ooO000O = lisp . green ( OOoO0 . print_address ( ) , False )
   lisp . dprint ( "Drop link-local multicast EID {}" . format ( ooO000O ) )
   return
   if 53 - 53: o0oOOo0O0Ooo . iII111i / Ii1I
  I11iiIi1i1 = False
  I1iIi1iIiiIiI , I1i11ii , i1IiiI1iIi = lisp . lisp_allow_gleaning ( Ooooo00o0OoO . inner_source , OOoO0 , None )
 else :
  I11iiIi1i1 , I1iIi1iIiiIiI , I1i11ii = lisp . lisp_allow_gleaning ( OOoO0 , None , None )
  if 66 - 66: OoO0O00 * Oo0Ooo
 Ooooo00o0OoO . gleaned_dest = I11iiIi1i1
 if 28 - 28: OoO0O00 % OoOoOO00 % I1ii11iIi11i + I1IiiI / I1IiiI
 if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
 if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
 if 23 - 23: i11iIiiIii
 O0ooooo0OOOO0 = lisp . lisp_map_cache_lookup ( Ooooo00o0OoO . inner_source , Ooooo00o0OoO . inner_dest )
 if ( O0ooooo0OOOO0 ) : O0ooooo0OOOO0 . add_recent_source ( Ooooo00o0OoO . inner_source )
 if 39 - 39: o0oOOo0O0Ooo - I1ii11iIi11i % iII111i * OoO0O00 - OOooOOo / iII111i
 if 29 - 29: I1ii11iIi11i
 if 52 - 52: i11iIiiIii / i1IIi
 if 1 - 1: ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if ( O0ooooo0OOOO0 and ( O0ooooo0OOOO0 . action == lisp . LISP_NATIVE_FORWARD_ACTION or
 O0ooooo0OOOO0 . eid . address == 0 ) ) :
  i1I1iIi1IiI = lisp . lisp_db_for_lookups . lookup_cache ( Ooooo00o0OoO . inner_source , False )
  if ( i1I1iIi1IiI and i1I1iIi1IiI . secondary_iid ) :
   i1111 = Ooooo00o0OoO . inner_dest
   i1111 . instance_id = i1I1iIi1IiI . secondary_iid
   if 82 - 82: ooOoO0o % Ii1I - ooOoO0o % OoOoOO00
   O0ooooo0OOOO0 = lisp . lisp_map_cache_lookup ( Ooooo00o0OoO . inner_source , i1111 )
   if ( O0ooooo0OOOO0 ) :
    Ooooo00o0OoO . gleaned_dest = O0ooooo0OOOO0 . gleaned
    O0ooooo0OOOO0 . add_recent_source ( Ooooo00o0OoO . inner_source )
   else :
    I11iiIi1i1 , I1iIi1iIiiIiI , I1i11ii = lisp . lisp_allow_gleaning ( i1111 , None ,
 None )
    Ooooo00o0OoO . gleaned_dest = I11iiIi1i1
    if 47 - 47: iIii1I11I1II1 . oO0o . OOooOOo * i1IIi
    if 32 - 32: i11iIiiIii - i1IIi % OOooOOo . O0 % OoOoOO00 * Oo0Ooo
    if 90 - 90: OOooOOo * I1Ii111
    if 50 - 50: IiII % i1IIi
    if 21 - 21: OoooooooOO - iIii1I11I1II1
    if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
    if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
    if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
    if 62 - 62: i1IIi - OoOoOO00
 if ( O0ooooo0OOOO0 == None and I11iiIi1i1 ) :
  lisp . lprint ( "Suppress Map-Request for gleaned EID {}" . format ( lisp . green ( Ooooo00o0OoO . inner_dest . print_address ( ) , False ) ) )
  if 62 - 62: i1IIi + Oo0Ooo % IiII
  return
  if 28 - 28: I1ii11iIi11i . i1IIi
  if 10 - 10: OoO0O00 / Oo0Ooo
 if ( O0ooooo0OOOO0 == None or lisp . lisp_mr_or_pubsub ( O0ooooo0OOOO0 . action ) ) :
  if ( lisp . lisp_rate_limit_map_request ( Ooooo00o0OoO . inner_dest ) ) : return
  if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
  oo0OOOOOO0 = ( O0ooooo0OOOO0 and O0ooooo0OOOO0 . action == lisp . LISP_SEND_PUBSUB_ACTION )
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 Ooooo00o0OoO . inner_source , Ooooo00o0OoO . inner_dest , None , oo0OOOOOO0 )
  if 26 - 26: iIii1I11I1II1
  if ( Ooooo00o0OoO . is_trace ( ) ) :
   OOOO0oooo = oO0oIIII
   OOOooO00OoOoo0 = "map-cache miss"
   lisp . lisp_trace_append ( Ooooo00o0OoO , reason = OOOooO00OoOoo0 , lisp_socket = OOOO0oooo )
   if 34 - 34: iII111i - OoooooooOO . I1IiiI / II111iiii
  return
  if 27 - 27: OoO0O00 / Oo0Ooo * ooOoO0o - OoO0O00
  if 19 - 19: I11i
  if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
  if 27 - 27: OOooOOo
  if 89 - 89: II111iiii / oO0o
  if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if ( O0ooooo0OOOO0 and O0ooooo0OOOO0 . refresh ( ) ) :
  if ( lisp . lisp_rate_limit_map_request ( Ooooo00o0OoO . inner_dest ) == False ) :
   lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( O0ooooo0OOOO0 . print_eid_tuple ( ) , False ) ) )
   if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
   lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 Ooooo00o0OoO . inner_source , Ooooo00o0OoO . inner_dest , None )
   if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
   if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
   if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
   if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
   if 19 - 19: i11iIiiIii
   if 54 - 54: II111iiii . I11i
   if 73 - 73: OoOoOO00 . I1IiiI
 O0ooooo0OOOO0 . last_refresh_time = time . time ( )
 O0ooooo0OOOO0 . stats . increment ( len ( Ooooo00o0OoO . packet ) )
 if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
 if 48 - 48: iII111i * iII111i
 if 13 - 13: Ii1I / I11i + OoOoOO00 . o0oOOo0O0Ooo % ooOoO0o
 if 48 - 48: I1IiiI / i11iIiiIii - o0oOOo0O0Ooo * oO0o / OoooooooOO
 OoOo , i1i , IIIiiiI , OoO00oo00 , Oo0Oo0O , i1I1iI1iIi111i = O0ooooo0OOOO0 . select_rloc ( Ooooo00o0OoO , None )
 if 44 - 44: OoooooooOO % OoooooooOO
 if 35 - 35: iII111i / I1ii11iIi11i * OoooooooOO . II111iiii / Oo0Ooo
 if ( OoOo == None and Oo0Oo0O == None ) :
  if ( OoO00oo00 == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   Ooooo00o0OoO . send_packet ( OOo , Ooooo00o0OoO . inner_dest )
   if 1 - 1: OoooooooOO + IiII . i1IIi % I11i
   if ( Ooooo00o0OoO . is_trace ( ) ) :
    OOOO0oooo = oO0oIIII
    OOOooO00OoOoo0 = "not an EID"
    lisp . lisp_trace_append ( Ooooo00o0OoO , reason = OOOooO00OoOoo0 , lisp_socket = OOOO0oooo )
    if 66 - 66: o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
   lisp . lisp_latency_debug ( Iii1iiIi1II , "RTR" )
   return
   if 12 - 12: iII111i . IiII . OoOoOO00 / O0
  OOOooO00OoOoo0 = "No reachable RLOCs found"
  lisp . dprint ( OOOooO00OoOoo0 )
  if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
  if ( Ooooo00o0OoO . is_trace ( ) ) :
   OOOO0oooo = oO0oIIII
   lisp . lisp_trace_append ( Ooooo00o0OoO , reason = OOOooO00OoOoo0 , lisp_socket = OOOO0oooo )
   if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
  return
  if 8 - 8: ooOoO0o * O0
 if ( OoOo and OoOo . is_null ( ) ) :
  lisp . dprint ( "Drop action RLOC found" )
  if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
  if ( Ooooo00o0OoO . is_trace ( ) ) :
   OOOO0oooo = oO0oIIII
   OOOooO00OoOoo0 = "drop action"
   lisp . lisp_trace_append ( Ooooo00o0OoO , reason = OOOooO00OoOoo0 , lisp_socket = OOOO0oooo )
   if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
  return
  if 34 - 34: ooOoO0o
  if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
  if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
  if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
  if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 Ooooo00o0OoO . outer_tos = Ooooo00o0OoO . inner_tos
 Ooooo00o0OoO . outer_ttl = Ooooo00o0OoO . inner_ttl
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 if ( OoOo ) :
  Ooooo00o0OoO . encap_port = i1i
  if ( i1i == 0 ) : Ooooo00o0OoO . encap_port = lisp . LISP_DATA_PORT
  Ooooo00o0OoO . outer_dest . copy_address ( OoOo )
  iIIIIiiIii = Ooooo00o0OoO . outer_dest . afi_to_version ( )
  Ooooo00o0OoO . outer_version = iIIIIiiIii
  if 58 - 58: Oo0Ooo
  IiiIIIiI1ii = iIiiI1 if ( iIIIIiiIii == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 78 - 78: O0 * OOooOOo
  Ooooo00o0OoO . outer_source . copy_address ( IiiIIIiI1ii )
  if 43 - 43: I1ii11iIi11i / I1IiiI . ooOoO0o
  if ( Ooooo00o0OoO . is_trace ( ) ) :
   OOOO0oooo = oO0oIIII
   if ( lisp . lisp_trace_append ( Ooooo00o0OoO , rloc_entry = i1I1iI1iIi111i ,
 lisp_socket = OOOO0oooo ) == False ) : return
   if 62 - 62: iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % O0 . I1Ii111
   if 93 - 93: i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / o0oOOo0O0Ooo / II111iiii
   if 49 - 49: OOooOOo . I1ii11iIi11i . i11iIiiIii - II111iiii / Ii1I
   if 62 - 62: OOooOOo
   if 1 - 1: IiII / IiII - i11iIiiIii
  if ( Ooooo00o0OoO . encode ( IIIiiiI ) == None ) : return
  if ( len ( Ooooo00o0OoO . packet ) <= 1500 ) :
   OO0o = i1I1iI1iIi111i . rloc_next_hop [ 0 ] if ( i1I1iI1iIi111i . rloc_next_hop != None ) else "?"
   IiII1iiI = "Send {}" . format ( OO0o )
   Ooooo00o0OoO . print_packet ( IiII1iiI , True )
   if 34 - 34: I1IiiI . oO0o + i1IIi
   if 98 - 98: oO0o % IiII * i11iIiiIii % I1ii11iIi11i
   if 29 - 29: IiII
   if 66 - 66: Oo0Ooo
   if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
  oO0oOo00o00oO = Ii1IIii11 if iIIIIiiIii == 6 else OOo
  Ooooo00o0OoO . send_packet ( oO0oOo00o00oO , Ooooo00o0OoO . outer_dest )
  if 95 - 95: I1IiiI
 elif ( Oo0Oo0O ) :
  oO0oOo00o00oO = Ii1IIii11 if iIIIIiiIii == 6 else OOo
  if 88 - 88: IiII % OoO0O00 + I1Ii111 + I1Ii111 * II111iiii
  if 78 - 78: OoooooooOO
  if 77 - 77: I1ii11iIi11i / i1IIi / Oo0Ooo % OOooOOo
  if 48 - 48: I11i - IiII + iIii1I11I1II1 + OoooooooOO
  Ii = len ( Ooooo00o0OoO . packet )
  for I1i111IiIiIi1 in Oo0Oo0O . rle_forwarding_list :
   if ( I1i111IiIiIi1 . rloc . up_state ( ) == False ) : continue
   if 39 - 39: I11i - I1ii11iIi11i
   Ooooo00o0OoO . outer_dest . copy_address ( I1i111IiIiIi1 . rloc . rloc )
   Ooooo00o0OoO . encap_port = lisp . LISP_DATA_PORT if I1i111IiIiIi1 . rloc . translated_port == 0 else I1i111IiIiIi1 . rloc . translated_port
   if 53 - 53: o0oOOo0O0Ooo % iII111i + ooOoO0o . Oo0Ooo - I1ii11iIi11i % o0oOOo0O0Ooo
   if 64 - 64: II111iiii
   iIIIIiiIii = Ooooo00o0OoO . outer_dest . afi_to_version ( )
   Ooooo00o0OoO . outer_version = iIIIIiiIii
   if 40 - 40: OoOoOO00 % OoO0O00
   IiiIIIiI1ii = iIiiI1 if ( iIIIIiiIii == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 62 - 62: o0oOOo0O0Ooo
   Ooooo00o0OoO . outer_source . copy_address ( IiiIIIiI1ii )
   if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
   if ( Ooooo00o0OoO . is_trace ( ) ) :
    OOOO0oooo = oO0oIIII
    OOOooO00OoOoo0 = "replicate"
    if ( lisp . lisp_trace_append ( Ooooo00o0OoO , reason = OOOooO00OoOoo0 , lisp_socket = OOOO0oooo ) == False ) : return
    if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
    if 72 - 72: iIii1I11I1II1
    if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
   if ( Ooooo00o0OoO . encode ( None ) == None ) : return
   if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
   if 87 - 87: OoO0O00 % I1IiiI
   if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
   if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
   I1i111IiIiIi1 . rloc . stats . increment ( len ( Ooooo00o0OoO . packet ) )
   if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
   Ooooo00o0OoO . print_packet ( "Replicate-to-L{}" . format ( I1i111IiIiIi1 . level ) , True )
   Ooooo00o0OoO . send_packet ( oO0oOo00o00oO , Ooooo00o0OoO . outer_dest )
   if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
   if 84 - 84: i11iIiiIii * OoO0O00
   if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
   if 30 - 30: O0 + I1ii11iIi11i + II111iiii
   if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
   I1iIiI1IiIIII = len ( Ooooo00o0OoO . packet ) - Ii
   Ooooo00o0OoO . packet = Ooooo00o0OoO . packet [ I1iIiI1IiIIII : : ]
   if 18 - 18: ooOoO0o % i11iIiiIii . iIii1I11I1II1 - iII111i
   if ( lisp . lisp_flow_logging ) : Ooooo00o0OoO = copy . deepcopy ( Ooooo00o0OoO )
   if 80 - 80: I1IiiI + oO0o - i1IIi . Ii1I / o0oOOo0O0Ooo / I1IiiI
   if 1 - 1: I11i + i11iIiiIii - I1IiiI / OOooOOo + I1Ii111
   if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
   if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
   if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
   if 50 - 50: ooOoO0o + i1IIi
 del ( Ooooo00o0OoO )
 if 31 - 31: Ii1I
 lisp . lisp_latency_debug ( Iii1iiIi1II , "RTR" )
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
  Ooooo00o0OoO = lisp_thread . input_queue . get ( )
  if 13 - 13: iII111i
  if 80 - 80: Ii1I - o0oOOo0O0Ooo
  if 41 - 41: o0oOOo0O0Ooo - Oo0Ooo * I1IiiI
  if 82 - 82: OoO0O00 % o0oOOo0O0Ooo % OOooOOo / O0
  lisp_thread . input_stats . increment ( len ( Ooooo00o0OoO ) )
  if 94 - 94: I1ii11iIi11i + I1ii11iIi11i + OoooooooOO % ooOoO0o
  if 7 - 7: iII111i
  if 78 - 78: OOooOOo + iII111i . IiII
  if 91 - 91: iIii1I11I1II1 . o0oOOo0O0Ooo . I1ii11iIi11i + OoooooooOO
  lisp_thread . lisp_packet . packet = Ooooo00o0OoO
  if 69 - 69: I1Ii111 - I1IiiI
  if 95 - 95: I1IiiI * i11iIiiIii . ooOoO0o
  if 41 - 41: II111iiii
  if 37 - 37: I11i . Oo0Ooo % IiII * i1IIi
  IIIii ( lisp_thread . lisp_packet , lisp_thread . thread_name )
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
 OO0o = parms [ 0 ]
 iiII1IiIi1iI1 = parms [ 1 ]
 oOiiI1Ii11II1I = iiII1IiIi1iI1 . number_of_worker_threads
 if 44 - 44: Ii1I % i11iIiiIii - iII111i * I1ii11iIi11i + Oo0Ooo * OOooOOo
 iiII1IiIi1iI1 . input_stats . increment ( len ( packet ) )
 if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
 if 65 - 65: Oo0Ooo . OoooooooOO
 if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
 if 55 - 55: iII111i - OoO0O00
 if 100 - 100: O0
 if 79 - 79: iIii1I11I1II1
 O00oO0o = 4 if OO0o == "lo0" else ( 14 if lisp . lisp_is_macos ( ) else 16 )
 packet = packet [ O00oO0o : : ]
 if 15 - 15: I1Ii111 + I11i . OoooooooOO . i11iIiiIii
 if 31 - 31: OoooooooOO + iII111i - OoOoOO00 . i1IIi % iII111i
 if 43 - 43: OOooOOo * ooOoO0o / iIii1I11I1II1 - Ii1I * Ii1I
 if 60 - 60: iIii1I11I1II1 . OOooOOo + I1ii11iIi11i
 if ( oOiiI1Ii11II1I ) :
  IiOoOoooO0O00 = iiII1IiIi1iI1 . input_stats . packet_count % oOiiI1Ii11II1I
  IiOoOoooO0O00 = IiOoOoooO0O00 + ( len ( I11 ) - oOiiI1Ii11II1I )
  oOO0OooO0 = I11 [ IiOoOoooO0O00 ]
  oOO0OooO0 . input_queue . put ( packet )
 else :
  iiII1IiIi1iI1 . lisp_packet . packet = packet
  IIIii ( iiII1IiIi1iI1 . lisp_packet , iiII1IiIi1iI1 . thread_name )
  if 63 - 63: i11iIiiIii + iIii1I11I1II1 / O0 - Ii1I + o0oOOo0O0Ooo
 return
 if 22 - 22: II111iiii - Ii1I / ooOoO0o % OoooooooOO + OOooOOo
 if 5 - 5: OoO0O00 / iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
def i1I1II ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 17 - 17: O0 * OoOoOO00 * I1ii11iIi11i * II111iiii * I11i % i1IIi
 OO0o = "lo0" if lisp . lisp_is_macos ( ) else "any"
 if 33 - 33: I1ii11iIi11i * I1ii11iIi11i . ooOoO0o . i11iIiiIii
 if 48 - 48: o0oOOo0O0Ooo . Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 IiIi1i = getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 IiIi1i = ( IiIi1i != "" and IiIi1i [ 0 ] == " " )
 if 99 - 99: OoOoOO00 . I1Ii111
 O0oO = "(dst host "
 IiIII = ""
 for iI1Iii in lisp . lisp_get_all_addresses ( ) :
  O0oO += "{} or " . format ( iI1Iii )
  IiIII += "{} or " . format ( iI1Iii )
  if 13 - 13: o0oOOo0O0Ooo % oO0o / I1Ii111 % I1Ii111 % O0
 O0oO = O0oO [ 0 : - 4 ]
 O0oO += ") and ((udp dst port 4341 or 8472 or 4789) or "
 O0oO += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0))))"
 if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
 IiIII = IiIII [ 0 : - 4 ]
 O0oO += ( " or (not (src host {}) and " + "((udp src port 4342) or (udp dst port 4342)))" ) . format ( IiIII )
 if 46 - 46: I1Ii111
 if 72 - 72: iII111i * OOooOOo
 if ( IiIi1i ) :
  O0oO += ( " or (dst net 0.0.0.0/0 and " + "not (host {} or src net 127.0.0.0/8))" ) . format ( IiIII )
  if 67 - 67: i1IIi
  if 5 - 5: II111iiii . OoooooooOO
  if 57 - 57: I1IiiI
 lisp . lprint ( "Capturing packets for: '{}'" . format ( O0oO ) )
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if 50 - 50: OoOoOO00
 if 33 - 33: I11i
 if 98 - 98: OoOoOO00 % II111iiii
 if ( lisp . lisp_is_python2 ( ) ) :
  import pcappy
  OoO0O000 = pcappy . open_live ( OO0o , 9000 , 0 , 100 )
  OoO0O000 . filter = O0oO
  OoO0O000 . loop ( - 1 , OO0o0oO0O000o , [ OO0o , lisp_thread ] )
  if 14 - 14: OoO0O00 / OoO0O00 * O0 . oO0o
 if ( lisp . lisp_is_python3 ( ) ) :
  import pcapy
  OoO0O000 = pcapy . open_live ( OO0o , 9000 , 0 , 100 )
  OoO0O000 . setfilter ( O0oO )
  while ( True ) :
   II1I1iiIII1I1 , Ooooo00o0OoO = OoO0O000 . next ( )
   if ( len ( Ooooo00o0OoO ) == 0 ) : continue
   OO0o0oO0O000o ( [ OO0o , lisp_thread ] , None , Ooooo00o0OoO )
   if 59 - 59: II111iiii * i11iIiiIii
   if 54 - 54: O0 % OoooooooOO - I1IiiI
 return
 if 61 - 61: Oo0Ooo * IiII . Oo0Ooo + Oo0Ooo / IiII * O0
 if 73 - 73: iII111i * iII111i / ooOoO0o
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
def iIiI1I1ii1I1 ( lisp_raw_socket , eid , geid , igmp ) :
 global iIiiI1
 if 83 - 83: OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
 if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
 if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
 Ooooo00o0OoO = lisp . lisp_packet ( igmp )
 if 71 - 71: iII111i
 if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
 if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
 O0ooooo0OOOO0 = lisp . lisp_map_cache_lookup ( eid , geid )
 if ( O0ooooo0OOOO0 == None ) : return
 if ( O0ooooo0OOOO0 . rloc_set == [ ] ) : return
 if ( O0ooooo0OOOO0 . rloc_set [ 0 ] . rle == None ) : return
 if 58 - 58: I1ii11iIi11i
 ii1I = eid . print_address_no_iid ( )
 for O0ooO0Oo00o in O0ooooo0OOOO0 . rloc_set [ 0 ] . rle . rle_nodes :
  if ( O0ooO0Oo00o . rloc . rloc_name == ii1I ) :
   Ooooo00o0OoO . outer_dest . copy_address ( O0ooO0Oo00o . rloc . rloc )
   Ooooo00o0OoO . encap_port = O0ooO0Oo00o . rloc . translated_port
   break
   if 98 - 98: i1IIi
   if 51 - 51: I1ii11iIi11i + ooOoO0o + Oo0Ooo / i1IIi + i1IIi
 if ( Ooooo00o0OoO . outer_dest . is_null ( ) ) : return
 if 12 - 12: iIii1I11I1II1 . Ii1I . I1ii11iIi11i % I1IiiI . II111iiii . oO0o
 IIi1ii1 = lisp . lisp_myrlocs [ 0 ]
 if ( iIiiI1 ) : IIi1ii1 = iIiiI1
 Ooooo00o0OoO . outer_source . copy_address ( IIi1ii1 )
 Ooooo00o0OoO . outer_version = Ooooo00o0OoO . outer_dest . afi_to_version ( )
 Ooooo00o0OoO . outer_ttl = 32
 Ooooo00o0OoO . inner_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 Ooooo00o0OoO . inner_dest . store_address ( "[{}]224.0.0.1" . format ( geid . instance_id ) )
 Ooooo00o0OoO . inner_ttl = 1
 if 48 - 48: ooOoO0o / iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . OoO0O00
 iiI111I1iIiI = lisp . green ( eid . print_address ( ) , False )
 OOOooO00OoOoo0 = lisp . red ( "{}:{}" . format ( Ooooo00o0OoO . outer_dest . print_address_no_iid ( ) ,
 Ooooo00o0OoO . encap_port ) , False )
 o0o0OO0o00o0O = lisp . bold ( "IGMP Query" , False )
 if 28 - 28: OoO0O00 - oO0o + OoOoOO00 + Ii1I / iIii1I11I1II1
 lisp . lprint ( "Data encapsulate {} to gleaned EID {}, RLOC {}" . format ( o0o0OO0o00o0O , iiI111I1iIiI , OOOooO00OoOoo0 ) )
 if 26 - 26: iIii1I11I1II1 - O0 . O0
 if 68 - 68: OOooOOo + oO0o . O0 . Ii1I % i1IIi % OOooOOo
 if 50 - 50: IiII + o0oOOo0O0Ooo
 if 96 - 96: OoO0O00
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if ( Ooooo00o0OoO . encode ( None ) == None ) : return
 Ooooo00o0OoO . print_packet ( "Send" , True )
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 Ooooo00o0OoO . send_packet ( lisp_raw_socket , Ooooo00o0OoO . outer_dest )
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
 if 61 - 61: I1Ii111 - Ii1I % I1ii11iIi11i / ooOoO0o / iII111i + iIii1I11I1II1
 if 87 - 87: I1Ii111 + ooOoO0o + O0 / i1IIi % IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
def O0000oO0o00 ( lisp_raw_socket ) :
 if ( lisp . lisp_gleaned_groups == { } ) : return
 if 80 - 80: OoooooooOO + IiII
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if 43 - 43: Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 ooooO0 = b"\x46\xc0\x00\x24\x00\x00\x40\x00\x01\x02\x00\x00"
 Iiii111 = lisp . lisp_myrlocs [ 0 ]
 iII1 = Iiii111 . address
 ooooO0 += I1I11I1I1I ( ( iII1 >> 24 ) & 0xff )
 ooooO0 += I1I11I1I1I ( ( iII1 >> 16 ) & 0xff )
 ooooO0 += I1I11I1I1I ( ( iII1 >> 8 ) & 0xff )
 ooooO0 += I1I11I1I1I ( iII1 & 0xff )
 ooooO0 += b"\xe0\x00\x00\x01"
 ooooO0 += b"\x94\x04\x00\x00"
 ooooO0 = lisp . lisp_ip_checksum ( ooooO0 , 24 )
 if 71 - 71: O0 / I1IiiI . I1Ii111 / I1Ii111 * ooOoO0o
 if 60 - 60: II111iiii . I1IiiI - Oo0Ooo + I1ii11iIi11i * I1ii11iIi11i
 if 27 - 27: IiII * I1IiiI . iIii1I11I1II1 - iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 I1iIi1iiiIiI = b"\x11\x64\x00\x00" + b"\x00\x00\x00\x00" + b"\x02\x3c\x00\x00"
 I1iIi1iiiIiI = lisp . lisp_igmp_checksum ( I1iIi1iiiIiI )
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 Ii1I1Ii = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 89 - 89: OOooOOo
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  Ii1I1Ii . store_address ( Ii1iIiII1ii1 )
  for o00oo0OO0 in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   i1 . store_address ( o00oo0OO0 )
   I1iIi1iIiiIiI , I1i11ii , oO0o000OooOoo = lisp . lisp_allow_gleaning ( Ii1I1Ii , i1 , None )
   if ( oO0o000OooOoo == False ) : continue
   iIiI1I1ii1I1 ( lisp_raw_socket , Ii1I1Ii , i1 , ooooO0 + I1iIi1iiiIiI )
   if 8 - 8: Oo0Ooo + ooOoO0o / O0 * OoooooooOO * II111iiii % Ii1I
   if 66 - 66: OoOoOO00
   if 44 - 44: OOooOOo / OOooOOo . o0oOOo0O0Ooo % IiII + OoOoOO00
   if 57 - 57: iII111i % OoO0O00 - OoO0O00
   if 5 - 5: i1IIi + OoooooooOO % OoOoOO00
   if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
   if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
   if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
   if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
   if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
def ooooO000 ( ) :
 Ii1I1Ii = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 61 - 61: ooOoO0o - OOooOOo + OOooOOo
 iii = [ ]
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  for o00oo0OO0 in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   IiIIII1iiIIi = lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] [ o00oo0OO0 ]
   i1I1IiI1ii = time . time ( ) - IiIIII1iiIIi
   if ( i1I1IiI1ii < lisp . LISP_IGMP_TIMEOUT_INTERVAL ) : continue
   iii . append ( [ Ii1iIiII1ii1 , o00oo0OO0 ] )
   if 64 - 64: iII111i * I1ii11iIi11i % II111iiii - OoOoOO00 + I1ii11iIi11i
   if 62 - 62: OoOoOO00 % o0oOOo0O0Ooo % I1IiiI + IiII . OoO0O00
   if 48 - 48: I1IiiI * i11iIiiIii % II111iiii
   if 20 - 20: i1IIi / I1IiiI * oO0o
   if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
   if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
   if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 Iii = lisp . bold ( "timed out" , False )
 for Ii1iIiII1ii1 , o00oo0OO0 in iii :
  Ii1I1Ii . store_address ( Ii1iIiII1ii1 )
  i1 . store_address ( o00oo0OO0 )
  iiI111I1iIiI = lisp . green ( Ii1iIiII1ii1 , False )
  i1iI111II1ii = lisp . green ( o00oo0OO0 , False )
  lisp . lprint ( "{} RLE {} for gleaned group {}" . format ( iiI111I1iIiI , Iii , i1iI111II1ii ) )
  lisp . lisp_remove_gleaned_multicast ( Ii1I1Ii , i1 )
  if 62 - 62: iII111i * iIii1I11I1II1 . IiII - OoooooooOO * II111iiii
  if 45 - 45: O0 % I1IiiI - iII111i . OoO0O00
  if 42 - 42: iII111i / o0oOOo0O0Ooo + Oo0Ooo . Oo0Ooo % OOooOOo
  if 16 - 16: i1IIi + OoO0O00 % OoOoOO00 + Ii1I * Oo0Ooo
  if 3 - 3: i11iIiiIii
  if 81 - 81: I1IiiI . OoooooooOO * Ii1I . oO0o - O0 * oO0o
  if 72 - 72: II111iiii - OOooOOo + I1IiiI - I11i
  if 91 - 91: II111iiii
def OOoO0O000O ( lisp_raw_socket ) :
 lisp . lisp_set_exception ( )
 if 20 - 20: I1IiiI . I11i
 if 75 - 75: ooOoO0o
 if 29 - 29: I1ii11iIi11i
 if 53 - 53: i11iIiiIii . I1ii11iIi11i % Ii1I / ooOoO0o % iIii1I11I1II1
 for oO0 in list ( lisp . lisp_crypto_keys_by_nonce . values ( ) ) :
  for iIiIii1I1 in oO0 : del ( iIiIii1I1 )
  if 81 - 81: IiII - o0oOOo0O0Ooo - Oo0Ooo - Ii1I / OOooOOo % I11i
 lisp . lisp_crypto_keys_by_nonce . clear ( )
 lisp . lisp_crypto_keys_by_nonce = { }
 if 52 - 52: I1ii11iIi11i / iII111i
 if 37 - 37: I11i
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 lisp . lisp_rtr_nat_trace_cache . clear ( )
 lisp . lisp_rtr_nat_trace_cache = { }
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 ooooO000 ( )
 if 24 - 24: ooOoO0o - I11i * oO0o
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 O0000oO0o00 ( lisp_raw_socket )
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 Oooo0000 = threading . Timer ( 60 , OOoO0O000O ,
 [ lisp_raw_socket ] )
 Oooo0000 . start ( )
 return
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
def Ii1Ii1 ( ) :
 global Oo0oO0oo0oO00 , II1iII1i , II1Ii1iI1i
 global OOo , Ii1IIii11 , I11
 global i111I , oO0oIIII
 global iIiiI1 , I1I11I1I1I
 if 35 - 35: i11iIiiIii - oO0o % i11iIiiIii
 lisp . lisp_i_am ( "rtr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "RTR starting up" )
 if 48 - 48: OoO0O00 % I11i * o0oOOo0O0Ooo % oO0o % i11iIiiIii . iII111i
 if 68 - 68: iII111i + Oo0Ooo % Ii1I / i11iIiiIii % OoOoOO00
 if 94 - 94: i11iIiiIii / I1Ii111 / Oo0Ooo
 if 9 - 9: I11i / OoOoOO00 / II111iiii + I1Ii111
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 71 - 71: iII111i / Oo0Ooo
 if 87 - 87: I1ii11iIi11i + I1ii11iIi11i - I1ii11iIi11i % O0
 if 13 - 13: II111iiii
 if 57 - 57: Ii1I - OoooooooOO
 if 68 - 68: o0oOOo0O0Ooo % I1ii11iIi11i / I1Ii111 + I1Ii111 - I1Ii111 . OoO0O00
 if 100 - 100: OoOoOO00 % Oo0Ooo
 if 76 - 76: II111iiii / OoO0O00 + OoooooooOO . I1ii11iIi11i . I11i . ooOoO0o
 if 43 - 43: i1IIi
 iIiiI1 = lisp . lisp_myrlocs [ 0 ]
 if ( lisp . lisp_on_gcp ( ) == False and lisp . lisp_on_aws ( ) ) :
  iiI1IIIii = lisp . bold ( "AWS RTR" , False )
  iII1 = None
  for OO0o in [ "eth0" , "ens5" ] :
   iII1 = lisp . lisp_get_interface_address ( OO0o )
   if ( iII1 != None ) : break
   if 24 - 24: I1IiiI . I1Ii111 % Ii1I
  if ( iII1 != None ) :
   iIiiI1 = iII1
   iI1Iii = iII1 . print_address_no_iid ( )
   lisp . lprint ( "{} using RLOC {} on {}" . format ( iiI1IIIii , iI1Iii , OO0o ) )
  else :
   iI1Iii = iIiiI1 . print_address_no_iid ( )
   lisp . lprint ( "{} cannot obtain RLOC, using {}" . format ( iiI1IIIii , iI1Iii ) )
   if 62 - 62: I1ii11iIi11i - O0 . I1IiiI . O0 * iIii1I11I1II1
   if 92 - 92: oO0o / OOooOOo . I1ii11iIi11i
   if 30 - 30: Ii1I . I1ii11iIi11i / OOooOOo
   if 2 - 2: IiII % I1IiiI - I1Ii111
   if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
   if 79 - 79: oO0o - II111iiii
   if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
   if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 Ooo00O0 = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 II1Ii1iI1i = lisp . lisp_open_listen_socket ( Ooo00O0 ,
 str ( iiI1iIiI ) )
 Oo0oO0oo0oO00 = lisp . lisp_open_listen_socket ( "" , "lisp-rtr" )
 i111I = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 if 70 - 70: I1IiiI - ooOoO0o - OoO0O00 - OoOoOO00 . i11iIiiIii % i1IIi
 II1iII1i [ 0 ] = II1Ii1iI1i
 if 1 - 1: oO0o / i1IIi
 II1iII1i [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 II1iII1i [ 2 ] = Oo0oO0oo0oO00
 if 74 - 74: I11i / OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
 if 98 - 98: oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 OOo = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 OOo . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 II1iII1i . append ( OOo )
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 if ( oo0Ooo0 ) : I1I11I1I1I = Oo0o0O00 if lisp . lisp_is_python2 ( ) else I1i1i1
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
 oO0oIIII = lisp . lisp_open_listen_socket ( "0.0.0.0" ,
 str ( lisp . LISP_TRACE_PORT ) )
 if 33 - 33: Ii1I
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  Ii1IIii11 = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 93 - 93: ooOoO0o
  if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 iI1iiIi1 = os . getenv ( "LISP_PCAP_THREADS" )
 iI1iiIi1 = 1 if ( iI1iiIi1 == None ) else int ( iI1iiIi1 )
 i1iiiIi1Iii = os . getenv ( "LISP_WORKER_THREADS" )
 i1iiiIi1Iii = 0 if ( i1iiiIi1Iii == None ) else int ( i1iiiIi1Iii )
 if 54 - 54: ooOoO0o . iIii1I11I1II1 * i1IIi
 if 44 - 44: oO0o + I1ii11iIi11i * OOooOOo - i11iIiiIii / iIii1I11I1II1
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 for II1iII1i1i in range ( iI1iiIi1 ) :
  o00oO0O0oo0o = lisp . lisp_thread ( "pcap-{}" . format ( II1iII1i1i ) )
  o00oO0O0oo0o . thread_number = II1iII1i1i
  o00oO0O0oo0o . number_of_pcap_threads = iI1iiIi1
  o00oO0O0oo0o . number_of_worker_threads = i1iiiIi1Iii
  I11 . append ( o00oO0O0oo0o )
  threading . Thread ( target = i1I1II , args = [ o00oO0O0oo0o ] ) . start ( )
  if 46 - 46: OoOoOO00 - O0
  if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
  if 49 - 49: o0oOOo0O0Ooo
  if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
  if 68 - 68: Oo0Ooo
  if 22 - 22: OOooOOo
 for II1iII1i1i in range ( i1iiiIi1Iii ) :
  o00oO0O0oo0o = lisp . lisp_thread ( "worker-{}" . format ( II1iII1i1i ) )
  I11 . append ( o00oO0O0oo0o )
  threading . Thread ( target = iIIiI1iiI , args = [ o00oO0O0oo0o ] ) . start ( )
  if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
  if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
  if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
  if 94 - 94: i1IIi
  if 36 - 36: I1IiiI + Oo0Ooo
 lisp . lisp_load_checkpoint ( )
 if 46 - 46: iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 65 - 65: ooOoO0o - i1IIi
 if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 Oooo0000 = threading . Timer ( 60 , OOoO0O000O ,
 [ OOo ] )
 Oooo0000 . start ( )
 return ( True )
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if 64 - 64: i1IIi
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 if 25 - 25: II111iiii / OoO0O00
 if 64 - 64: O0 % ooOoO0o
 if 40 - 40: o0oOOo0O0Ooo + I11i
 if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
def iIIiiIi ( ) :
 if 19 - 19: o0oOOo0O0Ooo
 if 73 - 73: I1Ii111 * Oo0Ooo * OoOoOO00
 if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lisp-rtr" )
 lisp . lisp_close_socket ( II1Ii1iI1i , "" )
 lisp . lisp_close_socket ( oO0oIIII , "" )
 lisp . lisp_close_socket ( i111I , "lispers.net-itr" )
 OOo . close ( )
 return
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
def oooo0o0OOO0 ( kv_pair ) :
 global II1iII1i
 global iiI1iIiI
 if 17 - 17: II111iiii + I1IiiI
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 59 - 59: iIii1I11I1II1 % Ii1I . i11iIiiIii
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , iiI1iIiI ] )
  lisp . lisp_test_mr_timer . start ( )
  if 59 - 59: o0oOOo0O0Ooo . oO0o . Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 return
 if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
 if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
 if 37 - 37: iII111i
 if 33 - 33: OoO0O00 - O0 - OoO0O00
 if 94 - 94: IiII * I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - o0oOOo0O0Ooo
 if 13 - 13: OOooOOo / IiII - OoO0O00 / OOooOOo . i1IIi
def IiI1i111i ( kv_pair ) :
 global II1Ii1iI1i , OOo , iiI1iIiI
 if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
 I11III11III1 = lisp . lisp_rloc_probing
 if 81 - 81: O0 . O0
 if 75 - 75: iIii1I11I1II1 % IiII + I1ii11iIi11i * O0 . iII111i - ooOoO0o
 if 32 - 32: Ii1I % oO0o - i1IIi
 if 40 - 40: iIii1I11I1II1 + iII111i * OoOoOO00 + oO0o
 lispconfig . lisp_xtr_command ( kv_pair )
 if 15 - 15: I11i % I1IiiI - iIii1I11I1II1 * ooOoO0o
 if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
 if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
 if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
 if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
 if ( I11III11III1 == False and lisp . lisp_rloc_probing ) :
  o00O0OoO = [ II1Ii1iI1i , II1Ii1iI1i ,
 None , OOo ]
  lisp . lisp_start_rloc_probe_timer ( 1 , o00O0OoO )
  oO0Oo = { "type" : "itr-crypto-port" , "port" : iiI1iIiI }
  lisp . lisp_write_to_dp_socket ( oO0Oo )
  if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
  if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
  if 93 - 93: ooOoO0o
  if 18 - 18: ooOoO0o
  if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
 if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
 if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
 if 58 - 58: O0
 if 91 - 91: iII111i / I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I1ii11iIi11i
O00 = {
 "lisp xtr-parameters" : [ IiI1i111i , {
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
 "multi-home-rtt-percentage" : [ True , 0 , 100 ] ,
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

 "lisp map-resolver" : [ oooo0o0OOO0 , {
 "mr-name" : [ True ] ,
 "ms-name" : [ True ] ,
 "dns-name" : [ True ] ,
 "address" : [ True ] } ] ,

 "lisp decent-prefix" : [ lispconfig . lisp_decent_prefix_command , {
 "instance-id" : [ False , 0 , 0xffffffff ] ,
 "eid-prefix" : [ True ] ,
 "lookup-length" : [ True , 0 , 128 ] } ] ,

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
if 90 - 90: OoooooooOO - I1ii11iIi11i
if 81 - 81: iIii1I11I1II1
if 21 - 21: I1ii11iIi11i
if 86 - 86: ooOoO0o
if 51 - 51: OoO0O00 - i11iIiiIii * I1IiiI
if 95 - 95: OOooOOo % I1ii11iIi11i + o0oOOo0O0Ooo % ooOoO0o
def Ii1i ( lisp_socket ) :
 if 19 - 19: ooOoO0o % oO0o
 if 22 - 22: oO0o . II111iiii . Oo0Ooo
 if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 oOiIi , OOOo , i1I , Ooooo00o0OoO = lisp . lisp_receive ( lisp_socket , False )
 oo0ooO = lisp . lisp_trace ( )
 if ( oo0ooO . decode ( Ooooo00o0OoO ) == False ) : return
 if 97 - 97: I1Ii111 . I11i / I1IiiI
 if 83 - 83: I11i - I1ii11iIi11i * oO0o
 if 90 - 90: Oo0Ooo * I1IiiI
 if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
 if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
 oo0ooO . rtr_cache_nat_trace ( OOOo , i1I )
 if 28 - 28: IiII * I1IiiI % IiII
 if 95 - 95: O0 / I11i . I1Ii111
 if 17 - 17: I11i
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
if ( Ii1Ii1 ( ) == False ) :
 lisp . lprint ( "lisp_rtr_startup() failed" )
 lisp . lisp_print_banner ( "RTR abnormal exit" )
 exit ( 1 )
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
iI1iIIIIIiIi1 = [ II1Ii1iI1i , Oo0oO0oo0oO00 ,
 i111I , oO0oIIII ]
iIi = [ II1Ii1iI1i ] * 3
if 52 - 52: iIii1I11I1II1
while ( True ) :
 try : iiIiIi1iI , oOO0oo , I1iIi1iIiiIiI = select . select ( iI1iIIIIIiIi1 , [ ] , [ ] )
 except : break
 if 5 - 5: I1Ii111 % OoooooooOO . OoOoOO00
 if 67 - 67: I1ii11iIi11i + Ii1I
 if 72 - 72: IiII % o0oOOo0O0Ooo
 if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
 if ( lisp . lisp_ipc_data_plane and i111I in iiIiIi1iI ) :
  lisp . lisp_process_punt ( i111I , II1iII1i ,
 iiI1iIiI )
  if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
  if 52 - 52: IiII % ooOoO0o
  if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
  if 23 - 23: i11iIiiIii
  if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
 if ( oO0oIIII in iiIiIi1iI ) :
  Ii1i ( oO0oIIII )
  if 65 - 65: II111iiii / Oo0Ooo
  if 42 - 42: i11iIiiIii . O0
  if 75 - 75: I1Ii111 + iIii1I11I1II1
  if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
  if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
 if ( II1Ii1iI1i in iiIiIi1iI ) :
  oOiIi , OOOo , i1I , Ooooo00o0OoO = lisp . lisp_receive ( iIi [ 0 ] ,
 False )
  if ( OOOo == "" ) : break
  if ( lisp . lisp_is_rloc_probe_request ( Ooooo00o0OoO [ 0 : 1 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
   continue
   if 92 - 92: I11i / O0 * I1IiiI - I11i
  if ( lisp . lisp_is_rloc_probe_reply ( Ooooo00o0OoO [ 0 : 1 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
   continue
   if 99 - 99: i11iIiiIii % OoooooooOO
  lisp . lisp_parse_packet ( iIi , Ooooo00o0OoO , OOOo , i1I )
  if 56 - 56: IiII * I1Ii111
  if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
  if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
  if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
  if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
  if 56 - 56: i1IIi . i11iIiiIii
 if ( Oo0oO0oo0oO00 in iiIiIi1iI ) :
  oOiIi , OOOo , i1I , Ooooo00o0OoO = lisp . lisp_receive ( Oo0oO0oo0oO00 , True )
  if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
  if ( OOOo == "" ) : break
  if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
  if ( oOiIi == "command" ) :
   Ooooo00o0OoO = Ooooo00o0OoO . decode ( )
   if ( Ooooo00o0OoO == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
   if ( Ooooo00o0OoO . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( Ooooo00o0OoO )
    continue
    if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
   lispconfig . lisp_process_command ( Oo0oO0oo0oO00 , oOiIi ,
 Ooooo00o0OoO , "lisp-rtr" , [ O00 ] )
  elif ( oOiIi == "api" ) :
   Ooooo00o0OoO = Ooooo00o0OoO . decode ( )
   lisp . lisp_process_api ( "lisp-rtr" , Oo0oO0oo0oO00 , Ooooo00o0OoO )
  elif ( oOiIi == "data-packet" ) :
   IIIii ( Ooooo00o0OoO , "" )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( Ooooo00o0OoO [ 0 : 1 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
    continue
    if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
   if ( lisp . lisp_is_rloc_probe_reply ( Ooooo00o0OoO [ 0 : 1 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
    continue
    if 10 - 10: IiII / OoooooooOO
   lisp . lisp_parse_packet ( II1iII1i , Ooooo00o0OoO , OOOo , i1I )
   if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
   if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
   if 25 - 25: iIii1I11I1II1
   if 63 - 63: ooOoO0o
iIIiiIi ( )
lisp . lisp_print_banner ( "RTR normal exit" )
exit ( 0 )
if 96 - 96: I11i
if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
