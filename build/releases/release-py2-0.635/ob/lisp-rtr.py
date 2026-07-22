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
  if 44 - 44: i1IIi % II111iiii + I11i
  if 45 - 45: iII111i / iII111i + I1Ii111 + ooOoO0o
  if 47 - 47: o0oOOo0O0Ooo + ooOoO0o
  if 82 - 82: II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
  if 77 - 77: iIii1I11I1II1 * OoO0O00
  if 95 - 95: I1IiiI + i11iIiiIii
  if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
  if 80 - 80: II111iiii
  if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
  if 53 - 53: II111iiii
  if 31 - 31: OoO0O00
  if ( i1I1iI1iIi111i . rle ) :
   for o0O in i1I1iI1iIi111i . rle . rle_nodes :
    IiIIii1iII1II = o0O . rloc
    if ( IiIIii1iII1II . normalize_decent_nat_rloc_name ( ) != OoOO ) : continue
    Iii1I1I11iiI1 = IiIIii1iII1II . rloc . print_address_no_iid ( ) + ":" + str ( IiIIii1iII1II . translated_port )
    if 18 - 18: OOooOOo + iII111i - Ii1I . II111iiii + i11iIiiIii
    IiIIii1iII1II . delete_from_rloc_probe_list ( mc . eid , mc . group )
    IiIIii1iII1II . store_translated_rloc ( iII1 , i1I )
    IiIIii1iII1II . add_to_rloc_probe_list ( mc . eid , mc . group )
    lisp . lprint ( oO00OOoO00 . format ( "RLE" , Iii1I1I11iiI1 ) )
    if ( lisp . lisp_rloc_probing ) :
     lisp . lisp_send_map_request ( o00O0OoO , 0 , mc . eid ,
 mc . group , IiIIii1iII1II )
     if 20 - 20: I1Ii111
     if 52 - 52: II111iiii - OoooooooOO % Ii1I + I1IiiI * Oo0Ooo . IiII
   lisp . lisp_write_ipc_map_cache ( True , mc )
   continue
   if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
   if 55 - 55: OOooOOo . I1IiiI
  oOo0O0o00o = i1I1iI1iIi111i . normalize_decent_nat_rloc_name ( )
  if ( oOo0O0o00o != OoOO ) : continue
  if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
  if 79 - 79: O0
  if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
  if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
  if 57 - 57: OoO0O00 / ooOoO0o
  if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
  Iii1I1I11iiI1 = i1I1iI1iIi111i . rloc . print_address_no_iid ( ) + ":" + str ( i1I1iI1iIi111i . translated_port )
  if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
  if ( Iii1I1I11iiI1 in lisp . lisp_crypto_keys_by_rloc_encap ) :
   i1i = lisp . lisp_crypto_keys_by_rloc_encap [ Iii1I1I11iiI1 ]
   lisp . lisp_crypto_keys_by_rloc_encap [ iI1Iii ] = i1i
   if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
   if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
   if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
   if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
   if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
  i1I1iI1iIi111i . delete_from_rloc_probe_list ( mc . eid , mc . group )
  i1I1iI1iIi111i . store_translated_rloc ( iII1 , i1I )
  i1I1iI1iIi111i . add_to_rloc_probe_list ( mc . eid , mc . group )
  lisp . lprint ( oO00OOoO00 . format ( "RLOC" , Iii1I1I11iiI1 ) )
  if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
  if 63 - 63: OoOoOO00 * iII111i
  if 69 - 69: O0 . OoO0O00
  if 49 - 49: I1IiiI - I11i
  if ( lisp . lisp_rloc_probing ) :
   OoOOoOooooOOo = None if ( mc . group . is_null ( ) ) else mc . eid
   oOo0O = mc . eid if ( mc . group . is_null ( ) ) else mc . group
   lisp . lisp_send_map_request ( o00O0OoO , 0 , OoOOoOooooOOo , oOo0O , i1I1iI1iIi111i )
   if 52 - 52: i11iIiiIii / o0oOOo0O0Ooo * ooOoO0o
   if 22 - 22: OoOoOO00 . OOooOOo * OoOoOO00
   if 54 - 54: IiII + Ii1I % OoO0O00 + OoooooooOO - O0 - o0oOOo0O0Ooo
   if 77 - 77: OOooOOo * iIii1I11I1II1
   if 98 - 98: I1IiiI % Ii1I * OoooooooOO
   if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 lisp . lisp_write_ipc_map_cache ( True , mc )
 return ( True , parms )
 if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
 if 71 - 71: Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
def Oo0OO ( mc , parms ) :
 if 78 - 78: OOooOOo - OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii
 if 29 - 29: I1IiiI % I1IiiI
 if 94 - 94: iIii1I11I1II1 / Oo0Ooo % iII111i * iII111i * II111iiii
 if 29 - 29: OoO0O00 + OoOoOO00 / o0oOOo0O0Ooo / OOooOOo * iIii1I11I1II1
 if ( mc . group . is_null ( ) ) : return ( oo0o00O ( mc , parms ) )
 if 62 - 62: OOooOOo / oO0o - OoO0O00 . I11i
 if ( mc . source_cache == None ) : return ( True , parms )
 if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
 mc . source_cache . walk_cache ( oo0o00O , parms )
 return ( True , parms )
 if 76 - 76: IiII * iII111i
 if 52 - 52: OOooOOo
 if 19 - 19: I1IiiI
 if 25 - 25: Ii1I / ooOoO0o
 if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 if 71 - 71: I1Ii111 . II111iiii
 if 62 - 62: OoooooooOO . I11i
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
def IiI1iIiIIIii ( sockets , hostname , rloc , port ) :
 lisp . lisp_map_cache . walk_cache ( Oo0OO ,
 [ sockets , rloc , port , hostname ] )
 return
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
 if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 if 23 - 23: i11iIiiIii
def II1iIi11 ( sred , packet ) :
 if ( lisp . lisp_data_plane_logging == False ) : return
 if 12 - 12: Ii1I + i11iIiiIii * iIii1I11I1II1 / I1ii11iIi11i . I11i
 if ( sred in [ "Send" , "Receive" ] ) :
  Iii1iI = binascii . hexlify ( packet [ 0 : 20 ] ) . decode ( )
  lisp . lprint ( "Fast-{}: ip {} {} {} {} {}" . format ( sred , Iii1iI [ 0 : 8 ] , Iii1iI [ 8 : 16 ] ,
 Iii1iI [ 16 : 24 ] , Iii1iI [ 24 : 32 ] , Iii1iI [ 32 : 40 ] ) )
 elif ( sred in [ "Encap" , "Decap" ] ) :
  Iii1iI = binascii . hexlify ( packet [ 0 : 36 ] ) . decode ( )
  lisp . lprint ( "Fast-{}: ip {} {} {} {} {}, udp {} {}, lisp {} {}" . format ( sred , Iii1iI [ 0 : 8 ] , Iii1iI [ 8 : 16 ] , Iii1iI [ 16 : 24 ] , Iii1iI [ 24 : 32 ] , Iii1iI [ 32 : 40 ] ,
  # I11i % I1IiiI
 Iii1iI [ 40 : 48 ] , Iii1iI [ 48 : 56 ] , Iii1iI [ 56 : 64 ] , Iii1iI [ 64 : 72 ] ) )
  if 60 - 60: I1IiiI / OOooOOo . I1IiiI / I1Ii111 . IiII
  if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
  if 42 - 42: Oo0Ooo
  if 76 - 76: I1IiiI * iII111i % I1Ii111
  if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
  if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
  if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
  if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
def I11IIIi ( dest , mc ) :
 if ( lisp . lisp_data_plane_logging == False ) : return
 if 15 - 15: I1ii11iIi11i * OoO0O00
 i1II1i = "miss" if mc == None else "hit!"
 lisp . lprint ( "Fast-Lookup {} {}" . format ( dest . print_address ( ) , i1II1i ) )
 if 83 - 83: OoOoOO00 - Ii1I / I11i / I1Ii111 + oO0o - O0
 if 4 - 4: OOooOOo * OoO0O00 % i1IIi * i11iIiiIii % Oo0Ooo - oO0o
 if 67 - 67: OoOoOO00 + I1ii11iIi11i . o0oOOo0O0Ooo . II111iiii
 if 98 - 98: iII111i
 if 68 - 68: iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
 if 38 - 38: ooOoO0o - OOooOOo / iII111i
 if 66 - 66: O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / Ii1I + I1ii11iIi11i
 if 86 - 86: o0oOOo0O0Ooo
def i1Iii11Ii1i1 ( a ) :
 OOooo0O0o0 = ord ( a [ 0 : 1 ] ) << 24 | ord ( a [ 1 : 2 ] ) << 16 | ord ( a [ 2 : 3 ] ) << 8 | ord ( a [ 3 : 4 ] )
 if 14 - 14: o0oOOo0O0Ooo % O0 * iII111i + Ii1I + Oo0Ooo * Ii1I
 return ( OOooo0O0o0 )
 if 3 - 3: OoOoOO00 * Oo0Ooo
 if 95 - 95: OOooOOo % oO0o . Ii1I
 if 72 - 72: OoooooooOO
 if 72 - 72: I1IiiI % i11iIiiIii . Oo0Ooo / II111iiii
 if 14 - 14: I1ii11iIi11i + OoO0O00
 if 3 - 3: I1ii11iIi11i . Oo0Ooo / II111iiii
 if 39 - 39: I1Ii111
 if 91 - 91: OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoOoOO00 + O0
def iIiii1iI1 ( byte ) :
 return ( chr ( byte ) )
 if 33 - 33: IiII % iIii1I11I1II1 * I1IiiI
def o00o0 ( byte ) :
 return ( bytes ( [ byte ] ) )
 if 50 - 50: Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
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
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 if 46 - 46: Oo0Ooo
 if 1 - 1: iII111i
O0O0Ooo = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
oOoO0 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
if 77 - 77: iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
def Oo00o0OO0O00o ( packet ) :
 global lisp_map_cache , OOo
 if 82 - 82: I11i + OoooooooOO - i1IIi . i1IIi
 iIi1i = lisp . lisp_latency_debug ( None , "RTR-Fast" )
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
   II1iIi11 ( "Decap" , packet )
   packet = packet [ 36 : : ]
   if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
   if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
   if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 II1iIi11 ( "Receive" , packet )
 if 9 - 9: Ii1I
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 Oo0OO0000oooo = i1Iii11Ii1i1 ( packet [ 16 : 20 ] )
 oOoO0 . instance_id = iIi1Ii1i1iI
 oOoO0 . address = Oo0OO0000oooo
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
 Oo0OO0000oooo = oOoO0
 OoOo = lisp . lisp_map_cache . lookup_cache ( Oo0OO0000oooo , False )
 I11IIIi ( Oo0OO0000oooo , OoOo )
 if ( OoOo == None ) : return ( False )
 if 35 - 35: ooOoO0o * OOooOOo . I11i * o0oOOo0O0Ooo . OoOoOO00 / O0
 if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo % O0 * O0
 if 14 - 14: I1ii11iIi11i . ooOoO0o + II111iiii / iII111i / I11i
 if 74 - 74: O0 / i1IIi
 if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
 if ( IIiI1 != None ) :
  ii1 = i1Iii11Ii1i1 ( packet [ 12 : 16 ] )
  O0O0Ooo . instance_id = iIi1Ii1i1iI
  O0O0Ooo . address = ii1
  O0iII1 = lisp . lisp_map_cache . lookup_cache ( O0O0Ooo , False )
  if ( O0iII1 == None ) :
   IIII1i , Ii1IIIIi1ii1I , IiiIiI1Ii1i = lisp . lisp_allow_gleaning ( O0O0Ooo , None ,
 None )
   if ( IIII1i ) : return ( False )
  elif ( O0iII1 . gleaned ) :
   IIiI1 = i1Iii11Ii1i1 ( IIiI1 )
   if ( O0iII1 . rloc_set [ 0 ] . rloc . address != IIiI1 ) : return ( False )
   if 22 - 22: IiII / i11iIiiIii
   if 62 - 62: OoO0O00 / I1ii11iIi11i
   if 7 - 7: OoooooooOO . IiII
   if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
   if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
  OoOo . add_recent_source ( O0O0Ooo )
  if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
  if 92 - 92: ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if ( OoOo . action == lisp . LISP_NATIVE_FORWARD_ACTION and
 OoOo . eid . instance_id == 0 ) :
  Oo0OO0000oooo . instance_id = lisp . lisp_default_secondary_iid
  OoOo = lisp . lisp_map_cache . lookup_cache ( Oo0OO0000oooo , False )
  I11IIIi ( Oo0OO0000oooo , OoOo )
  if ( OoOo == None ) : return ( False )
  if 92 - 92: I11i . I1Ii111
  if 85 - 85: I1ii11iIi11i . I1Ii111
  if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
  if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
  if 18 - 18: iIii1I11I1II1 % I11i
  if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if ( OoOo . action != lisp . LISP_NATIVE_FORWARD_ACTION ) :
  if ( OoOo . best_rloc_set == [ ] ) : return ( False )
  if 75 - 75: OoooooooOO * IiII
  Oo0OO0000oooo = OoOo . best_rloc_set [ 0 ]
  if ( Oo0OO0000oooo . state != lisp . LISP_RLOC_UP_STATE ) : return ( False )
  if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
  iIi1Ii1i1iI = OoOo . eid . instance_id
  i1I = Oo0OO0000oooo . translated_port
  I1IIIiI1I1ii1 = Oo0OO0000oooo . stats
  Oo0OO0000oooo = Oo0OO0000oooo . rloc
  iiiI1I1iIIIi1 = Oo0OO0000oooo . address
  IIiI1 = lisp . lisp_myrlocs [ 0 ] . address
  if 17 - 17: iIii1I11I1II1 . OoooooooOO / I11i % II111iiii % i1IIi / i11iIiiIii
  if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
  if 85 - 85: OoOoOO00 + OOooOOo
  if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
  i1iII1II11I = b'\x45\x00'
  O0Oo00O = len ( packet ) + 20 + 8 + 8
  i1iII1II11I += I1I11I1I1I ( ( O0Oo00O >> 8 ) & 0xff )
  i1iII1II11I += I1I11I1I1I ( O0Oo00O & 0xff )
  i1iII1II11I += b'\xff\xff\x40\x00\x10\x11\x00\x00'
  i1iII1II11I += I1I11I1I1I ( ( IIiI1 >> 24 ) & 0xff )
  i1iII1II11I += I1I11I1I1I ( ( IIiI1 >> 16 ) & 0xff )
  i1iII1II11I += I1I11I1I1I ( ( IIiI1 >> 8 ) & 0xff )
  i1iII1II11I += I1I11I1I1I ( IIiI1 & 0xff )
  i1iII1II11I += I1I11I1I1I ( ( iiiI1I1iIIIi1 >> 24 ) & 0xff )
  i1iII1II11I += I1I11I1I1I ( ( iiiI1I1iIIIi1 >> 16 ) & 0xff )
  i1iII1II11I += I1I11I1I1I ( ( iiiI1I1iIIIi1 >> 8 ) & 0xff )
  i1iII1II11I += I1I11I1I1I ( iiiI1I1iIIIi1 & 0xff )
  i1iII1II11I = lisp . lisp_ip_checksum ( i1iII1II11I )
  if 91 - 91: oO0o % Ii1I . ooOoO0o / iII111i * iIii1I11I1II1
  if 43 - 43: ooOoO0o + iII111i - I1Ii111 / O0 * Oo0Ooo + I1IiiI
  if 28 - 28: Ii1I * o0oOOo0O0Ooo - OoO0O00
  if 42 - 42: I1ii11iIi11i
  OOooOOOOOOooo = O0Oo00O - 20
  O0i11i1iiI1i = b'\xff\x00' if ( i1I == 4341 ) else b'\x10\xf5'
  O0i11i1iiI1i += I1I11I1I1I ( ( i1I >> 8 ) & 0xff )
  O0i11i1iiI1i += I1I11I1I1I ( i1I & 0xff )
  O0i11i1iiI1i += I1I11I1I1I ( ( OOooOOOOOOooo >> 8 ) & 0xff )
  O0i11i1iiI1i += I1I11I1I1I ( OOooOOOOOOooo & 0xff )
  O0i11i1iiI1i += b'\x00'
  O0i11i1iiI1i += b'\x00'
  if 87 - 87: ooOoO0o
  O0i11i1iiI1i += b'\x08\xdf\xdf\xdf'
  O0i11i1iiI1i += I1I11I1I1I ( ( iIi1Ii1i1iI >> 16 ) & 0xff )
  O0i11i1iiI1i += I1I11I1I1I ( ( iIi1Ii1i1iI >> 8 ) & 0xff )
  O0i11i1iiI1i += I1I11I1I1I ( iIi1Ii1i1iI & 0xff )
  O0i11i1iiI1i += b'\x00'
  if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
  if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
  if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
  if 13 - 13: Oo0Ooo
  packet = i1iII1II11I + O0i11i1iiI1i + packet
  II1iIi11 ( "Encap" , packet )
 else :
  O0Oo00O = len ( packet )
  I1IIIiI1I1ii1 = OoOo . stats
  II1iIi11 ( "Send" , packet )
  if 60 - 60: I1ii11iIi11i * I1IiiI
  if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
  if 41 - 41: Ii1I
  if 77 - 77: I1Ii111
  if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 OoOo . last_refresh_time = time . time ( )
 I1IIIiI1I1ii1 . increment ( O0Oo00O )
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 Oo0OO0000oooo = Oo0OO0000oooo . print_address_no_iid ( )
 OOo . sendto ( packet , ( Oo0OO0000oooo , 0 ) )
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 lisp . lisp_latency_debug ( iIi1i , "RTR-Fast" )
 return ( True )
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
 if 95 - 95: IiII
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
 if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
 if 63 - 63: I1IiiI % iIii1I11I1II1
def I1ii ( lisp_packet , thread_name ) :
 global II1iII1i , O00O0O , IIi1i1IiIIi1i
 global OOo , Ii1IIii11
 global oO0oIIII
 global iIiiI1
 global oo0Ooo0
 if 54 - 54: ooOoO0o
 iIi1i = lisp . lisp_latency_debug ( None , "RTR" )
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
 if ( oo0Ooo0 ) :
  if ( Oo00o0OO0O00o ( lisp_packet . packet ) ) : return
  if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
  if 26 - 26: II111iiii * OoOoOO00
  if 10 - 10: II111iiii . iII111i
  if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
  if 88 - 88: iII111i
 iiI11I1i1i1iI = lisp_packet
 OoOOo000o0 = iiI11I1i1i1iI . is_lisp_packet ( iiI11I1i1i1iI . packet )
 if 12 - 12: II111iiii . I11i / OOooOOo
 if 77 - 77: ooOoO0o - I1IiiI % I11i - O0
 if 67 - 67: OOooOOo + Oo0Ooo
 if 84 - 84: O0 * OoooooooOO - IiII * IiII
 if ( OoOOo000o0 == False ) :
  i1ii = iiI11I1i1i1iI . packet
  oO0O , oOO , i1I , iiiIIiIi = lisp . lisp_is_rloc_probe ( i1ii , "?" , - 1 )
  if ( i1ii != oO0O ) :
   if ( oOO == None ) : return
   lisp . lisp_parse_packet ( II1iII1i , oO0O , oOO , i1I , iiiIIiIi )
   return
   if 68 - 68: O0 + OoOoOO00 / oO0o - OOooOOo + iIii1I11I1II1 % Ii1I
   if 23 - 23: ooOoO0o % o0oOOo0O0Ooo / I11i
   if 5 - 5: iIii1I11I1II1
   if 72 - 72: oO0o . I1Ii111 / OoOoOO00 + I11i % iIii1I11I1II1
   if 42 - 42: I1ii11iIi11i * OoOoOO00 % ooOoO0o - OoOoOO00 . i11iIiiIii - I1Ii111
   if 84 - 84: I1Ii111 - I1ii11iIi11i / I11i
 iiI11I1i1i1iI . packet = lisp . lisp_reassemble ( iiI11I1i1i1iI . packet )
 if ( iiI11I1i1i1iI . packet == None ) : return
 if 13 - 13: IiII - Oo0Ooo - ooOoO0o
 if 92 - 92: ooOoO0o / OoOoOO00 * OoO0O00 . I11i % II111iiii
 if 71 - 71: I1Ii111 % i1IIi - II111iiii - OOooOOo + OOooOOo * ooOoO0o
 if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
 if 29 - 29: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / iII111i
 if ( lisp . lisp_flow_logging ) : iiI11I1i1i1iI = copy . deepcopy ( iiI11I1i1i1iI )
 if 70 - 70: i11iIiiIii % iII111i
 if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
 if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
 if 76 - 76: Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if ( OoOOo000o0 ) :
  if ( iiI11I1i1i1iI . decode ( True , None , lisp . lisp_decap_stats ) == None ) : return
  iiI11I1i1i1iI . print_packet ( "Receive-({})" . format ( thread_name ) , True )
  iiI11I1i1i1iI . strip_outer_headers ( )
 else :
  if ( iiI11I1i1i1iI . decode ( False , None , None ) == None ) : return
  iiI11I1i1i1iI . print_packet ( "Receive-({})" . format ( thread_name ) , False )
  if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
  if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
  if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
  if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
  if 45 - 45: IiII
  if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
  if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
  if 34 - 34: O0
  if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
  if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
  if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
  if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 if ( OoOOo000o0 and iiI11I1i1i1iI . lisp_header . get_instance_id ( ) == 0xffffff ) :
  OoO = lisp . lisp_control_header ( )
  OoO . decode ( iiI11I1i1i1iI . packet )
  if ( OoO . is_info_request ( ) ) :
   O00OO = lisp . lisp_info ( )
   O00OO . decode ( iiI11I1i1i1iI . packet )
   O00OO . print_info ( )
   if 65 - 65: i1IIi . OoooooooOO * Ii1I / IiII
   if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
   if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
   if 37 - 37: i11iIiiIii + i1IIi
   if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
   I1iIi1iiiIiI = O00OO . hostname if ( O00OO . hostname != None ) else ""
   III1I1Ii11iI = iiI11I1i1i1iI . outer_source
   Iii1iI = iiI11I1i1i1iI . udp_sport
   if ( lisp . lisp_store_nat_info ( I1iIi1iiiIiI , III1I1Ii11iI , Iii1iI ) ) :
    IiI1iIiIIIii ( II1iII1i , I1iIi1iiiIiI , III1I1Ii11iI , Iii1iI )
    if 52 - 52: OOooOOo - iII111i * oO0o
  else :
   oOO = iiI11I1i1i1iI . outer_source . print_address_no_iid ( )
   iiiIIiIi = iiI11I1i1i1iI . outer_ttl
   if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
   if 36 - 36: O0 + Oo0Ooo
   if 5 - 5: Oo0Ooo * OoOoOO00
   if 46 - 46: ooOoO0o
   if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
   if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
   if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
   if 72 - 72: i1IIi
   OOoo0oo = iiI11I1i1i1iI . udp_sport
   iiI11I1i1i1iI = iiI11I1i1i1iI . packet
   if ( lisp . lisp_is_rloc_probe_request ( iiI11I1i1i1iI [ 28 : 29 ] ) == False and
 lisp . lisp_is_rloc_probe_reply ( iiI11I1i1i1iI [ 28 : 29 ] ) == False ) :
    iiiIIiIi = - 1
    if 58 - 58: oO0o
   iiI11I1i1i1iI = iiI11I1i1i1iI [ 28 : : ]
   lisp . lisp_parse_packet ( II1iII1i , iiI11I1i1i1iI , oOO , OOoo0oo , iiiIIiIi )
   if 4 - 4: II111iiii . ooOoO0o / I1ii11iIi11i - i11iIiiIii
  return
  if 72 - 72: O0 / ooOoO0o + OoooooooOO * iII111i
  if 61 - 61: OoooooooOO % II111iiii - I1IiiI % I1ii11iIi11i + i1IIi
  if 39 - 39: i1IIi
  if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
  if 51 - 51: OoOoOO00
  if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 53 - 53: Ii1I % Oo0Ooo
  if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
  if 41 - 41: Ii1I % I1ii11iIi11i
  if 12 - 12: OOooOOo
  if 69 - 69: OoooooooOO + OOooOOo
 if ( OoOOo000o0 ) :
  lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( iiI11I1i1i1iI . packet ) )
  if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
  if 31 - 31: I11i % OOooOOo * I11i
  if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
  if 1 - 1: iIii1I11I1II1
  if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 O0O00OOo = False
 if ( iiI11I1i1i1iI . inner_dest . is_mac ( ) ) :
  iiI11I1i1i1iI . packet = lisp . lisp_mac_input ( iiI11I1i1i1iI . packet )
  if ( iiI11I1i1i1iI . packet == None ) : return
  iiI11I1i1i1iI . encap_port = lisp . LISP_VXLAN_DATA_PORT
 elif ( iiI11I1i1i1iI . inner_version == 4 ) :
  O0O00OOo , iiI11I1i1i1iI . packet = lisp . lisp_ipv4_input ( iiI11I1i1i1iI . packet )
  if ( iiI11I1i1i1iI . packet == None ) : return
  iiI11I1i1i1iI . inner_ttl = iiI11I1i1i1iI . outer_ttl
 elif ( iiI11I1i1i1iI . inner_version == 6 ) :
  iiI11I1i1i1iI . packet = lisp . lisp_ipv6_input ( iiI11I1i1i1iI )
  if ( iiI11I1i1i1iI . packet == None ) : return
  iiI11I1i1i1iI . inner_ttl = iiI11I1i1i1iI . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 66 - 66: i11iIiiIii / o0oOOo0O0Ooo - OoooooooOO / i1IIi . i11iIiiIii
  if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
  if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
  if 81 - 81: iII111i * OOooOOo - I1ii11iIi11i * Ii1I % OoOoOO00 * OoOoOO00
  if 59 - 59: iIii1I11I1II1
 if ( iiI11I1i1i1iI . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( iiI11I1i1i1iI , ed = "decap" ) == False ) : return
  iiI11I1i1i1iI . outer_source . afi = lisp . LISP_AFI_NONE
  iiI11I1i1i1iI . outer_dest . afi = lisp . LISP_AFI_NONE
  if 7 - 7: OOooOOo * I1IiiI / o0oOOo0O0Ooo * i11iIiiIii
  if 84 - 84: OOooOOo . iII111i
  if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
  if 21 - 21: oO0o / OoooooooOO
  if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
  if 87 - 87: I1Ii111 * i1IIi / I1ii11iIi11i
 IIII1i , Ii1IIIIi1ii1I , IiiIiI1Ii1i = lisp . lisp_allow_gleaning ( iiI11I1i1i1iI . inner_source , None ,
 iiI11I1i1i1iI . outer_source )
 if ( IIII1i ) :
  IIII1i1 = iiI11I1i1i1iI . packet if ( O0O00OOo ) else None
  lisp . lisp_glean_map_cache ( iiI11I1i1i1iI . inner_source , iiI11I1i1i1iI . outer_source ,
 iiI11I1i1i1iI . udp_sport , IIII1i1 )
  if ( O0O00OOo ) : return
  if 70 - 70: i11iIiiIii % I1ii11iIi11i / I1IiiI
  if 62 - 62: i1IIi - OoOoOO00
  if 62 - 62: i1IIi + Oo0Ooo % IiII
  if 28 - 28: I1ii11iIi11i . i1IIi
  if 10 - 10: OoO0O00 / Oo0Ooo
  if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
 oOo0O = iiI11I1i1i1iI . inner_dest
 if ( oOo0O . is_multicast_address ( ) ) :
  if ( oOo0O . is_link_local_multicast ( ) ) :
   oo0OOOOOO0 = lisp . green ( oOo0O . print_address ( ) , False )
   lisp . dprint ( "Drop link-local multicast EID {}" . format ( oo0OOOOOO0 ) )
   return
   if 26 - 26: iIii1I11I1II1
  OOOo = False
  Ii1IIIIi1ii1I , IiiIiI1Ii1i , oO00OoOoo0 = lisp . lisp_allow_gleaning ( iiI11I1i1i1iI . inner_source , oOo0O , None )
 else :
  OOOo , Ii1IIIIi1ii1I , IiiIiI1Ii1i = lisp . lisp_allow_gleaning ( oOo0O , None , None )
  if 34 - 34: iII111i - OoooooooOO . I1IiiI / II111iiii
 iiI11I1i1i1iI . gleaned_dest = OOOo
 if 27 - 27: OoO0O00 / Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 OoOo = lisp . lisp_map_cache_lookup ( iiI11I1i1i1iI . inner_source , iiI11I1i1i1iI . inner_dest )
 if ( OoOo ) : OoOo . add_recent_source ( iiI11I1i1i1iI . inner_source )
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if ( OoOo and ( OoOo . action == lisp . LISP_NATIVE_FORWARD_ACTION or
 OoOo . eid . address == 0 ) ) :
  IIiIi1 = lisp . lisp_db_for_lookups . lookup_cache ( iiI11I1i1i1iI . inner_source , False )
  if ( IIiIi1 and IIiIi1 . secondary_iid ) :
   Oo00O0ooOO = iiI11I1i1i1iI . inner_dest
   Oo00O0ooOO . instance_id = IIiIi1 . secondary_iid
   if 28 - 28: i11iIiiIii / o0oOOo0O0Ooo . iIii1I11I1II1 / II111iiii
   OoOo = lisp . lisp_map_cache_lookup ( iiI11I1i1i1iI . inner_source , Oo00O0ooOO )
   if ( OoOo ) :
    iiI11I1i1i1iI . gleaned_dest = OoOo . gleaned
    OoOo . add_recent_source ( iiI11I1i1i1iI . inner_source )
   else :
    OOOo , Ii1IIIIi1ii1I , IiiIiI1Ii1i = lisp . lisp_allow_gleaning ( Oo00O0ooOO , None ,
 None )
    iiI11I1i1i1iI . gleaned_dest = OOOo
    if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
    if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
    if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
    if 32 - 32: i11iIiiIii - I1Ii111
    if 53 - 53: OoooooooOO - IiII
    if 87 - 87: oO0o . I1IiiI
    if 17 - 17: Ii1I . i11iIiiIii
    if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
    if 63 - 63: oO0o
 if ( OoOo == None and OOOo ) :
  lisp . lprint ( "Suppress Map-Request for gleaned EID {}" . format ( lisp . green ( iiI11I1i1i1iI . inner_dest . print_address ( ) , False ) ) )
  if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
  return
  if 36 - 36: IiII
  if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if ( OoOo == None or lisp . lisp_mr_or_pubsub ( OoOo . action ) ) :
  if ( lisp . lisp_rate_limit_map_request ( iiI11I1i1i1iI . inner_dest ) ) : return
  if 74 - 74: I1Ii111 % I1ii11iIi11i
  iiIiI = ( OoOo and OoOo . action == lisp . LISP_SEND_PUBSUB_ACTION )
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 iiI11I1i1i1iI . inner_source , iiI11I1i1i1iI . inner_dest , None , iiIiI )
  if 38 - 38: IiII . Ii1I
  if ( iiI11I1i1i1iI . is_trace ( ) ) :
   III1I1Ii11iI = oO0oIIII
   IIIIIIIiI = "map-cache miss"
   lisp . lisp_trace_append ( iiI11I1i1i1iI , reason = IIIIIIIiI , lisp_socket = III1I1Ii11iI )
   if 12 - 12: iII111i . IiII . OoOoOO00 / O0
  return
  if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
  if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
  if 8 - 8: ooOoO0o * O0
  if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
  if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
  if 34 - 34: ooOoO0o
 if ( OoOo and OoOo . refresh ( ) ) :
  if ( lisp . lisp_rate_limit_map_request ( iiI11I1i1i1iI . inner_dest ) == False ) :
   lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( OoOo . print_eid_tuple ( ) , False ) ) )
   if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
   lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 iiI11I1i1i1iI . inner_source , iiI11I1i1i1iI . inner_dest , None )
   if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
   if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
   if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
   if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
   if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
   if 87 - 87: oO0o - i11iIiiIii
   if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 OoOo . last_refresh_time = time . time ( )
 OoOo . stats . increment ( len ( iiI11I1i1i1iI . packet ) )
 if 23 - 23: I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 ooO0oo0o0 , IIiIii1 , Ooo0oO0 , o0 , Oo0oOooOoOo , i1I1iI1iIi111i = OoOo . select_rloc ( iiI11I1i1i1iI , None )
 if 49 - 49: OOooOOo . I1ii11iIi11i . i11iIiiIii - II111iiii / Ii1I
 if 62 - 62: OOooOOo
 if ( ooO0oo0o0 == None and Oo0oOooOoOo == None ) :
  if ( o0 == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   iiI11I1i1i1iI . send_packet ( OOo , iiI11I1i1i1iI . inner_dest )
   if 1 - 1: IiII / IiII - i11iIiiIii
   if ( iiI11I1i1i1iI . is_trace ( ) ) :
    III1I1Ii11iI = oO0oIIII
    IIIIIIIiI = "not an EID"
    lisp . lisp_trace_append ( iiI11I1i1i1iI , reason = IIIIIIIiI , lisp_socket = III1I1Ii11iI )
    if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
   lisp . lisp_latency_debug ( iIi1i , "RTR" )
   return
   if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
  IIIIIIIiI = "No reachable RLOCs found"
  lisp . dprint ( IIIIIIIiI )
  if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
  if ( iiI11I1i1i1iI . is_trace ( ) ) :
   III1I1Ii11iI = oO0oIIII
   lisp . lisp_trace_append ( iiI11I1i1i1iI , reason = IIIIIIIiI , lisp_socket = III1I1Ii11iI )
   if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
  return
  if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
 if ( ooO0oo0o0 and ooO0oo0o0 . is_null ( ) ) :
  lisp . dprint ( "Drop action RLOC found" )
  if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
  if ( iiI11I1i1i1iI . is_trace ( ) ) :
   III1I1Ii11iI = oO0oIIII
   IIIIIIIiI = "drop action"
   lisp . lisp_trace_append ( iiI11I1i1i1iI , reason = IIIIIIIiI , lisp_socket = III1I1Ii11iI )
   if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
  return
  if 77 - 77: OoO0O00 + I1Ii111 + I1Ii111 * Ii1I / OoooooooOO . Ii1I
  if 62 - 62: i1IIi - i1IIi
  if 69 - 69: OoOoOO00 % oO0o - I11i
  if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
  if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
 iiI11I1i1i1iI . outer_tos = iiI11I1i1i1iI . inner_tos
 iiI11I1i1i1iI . outer_ttl = iiI11I1i1i1iI . inner_ttl
 if 62 - 62: o0oOOo0O0Ooo - Ii1I * OoOoOO00 - i11iIiiIii % ooOoO0o
 if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
 if 30 - 30: iII111i / OoO0O00 + oO0o
 if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
 if ( ooO0oo0o0 ) :
  iiI11I1i1i1iI . encap_port = IIiIii1
  if ( IIiIii1 == 0 ) : iiI11I1i1i1iI . encap_port = lisp . LISP_DATA_PORT
  iiI11I1i1i1iI . outer_dest . copy_address ( ooO0oo0o0 )
  oOoO0o = iiI11I1i1i1iI . outer_dest . afi_to_version ( )
  iiI11I1i1i1iI . outer_version = oOoO0o
  if 46 - 46: I1Ii111 % Ii1I
  oOOoO0OO00OOo0 = iIiiI1 if ( oOoO0o == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 18 - 18: I1IiiI + OoO0O00 % iIii1I11I1II1 - i1IIi . oO0o
  iiI11I1i1i1iI . outer_source . copy_address ( oOOoO0OO00OOo0 )
  if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
  if ( iiI11I1i1i1iI . is_trace ( ) ) :
   III1I1Ii11iI = oO0oIIII
   if ( lisp . lisp_trace_append ( iiI11I1i1i1iI , rloc_entry = i1I1iI1iIi111i ,
 lisp_socket = III1I1Ii11iI ) == False ) : return
   if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
   if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
   if 84 - 84: i11iIiiIii * OoO0O00
   if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
   if 30 - 30: O0 + I1ii11iIi11i + II111iiii
  if ( iiI11I1i1i1iI . encode ( Ooo0oO0 ) == None ) : return
  if ( len ( iiI11I1i1i1iI . packet ) <= 1500 ) :
   III1I = i1I1iI1iIi111i . rloc_next_hop [ 0 ] if ( i1I1iI1iIi111i . rloc_next_hop != None ) else "?"
   I1I111iIi = "Send {}" . format ( III1I )
   iiI11I1i1i1iI . print_packet ( I1I111iIi , True )
   if 53 - 53: iIii1I11I1II1 + o0oOOo0O0Ooo - OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
   if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
   if 64 - 64: i1IIi
   if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
   if 18 - 18: OOooOOo + I1Ii111
  OO0OO0O = Ii1IIii11 if oOoO0o == 6 else OOo
  iiI11I1i1i1iI . send_packet ( OO0OO0O , iiI11I1i1i1iI . outer_dest )
  if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 elif ( Oo0oOooOoOo ) :
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
  if 50 - 50: ooOoO0o + i1IIi
  if 31 - 31: Ii1I
  if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
  Oo0O0Oo00O = len ( iiI11I1i1i1iI . packet )
  for iI in Oo0oOooOoOo . rle_forwarding_list :
   if ( iI . rloc . up_state ( ) == False ) : continue
   if 66 - 66: I1IiiI - IiII
   iiI11I1i1i1iI . outer_dest . copy_address ( iI . rloc . rloc )
   iiI11I1i1i1iI . encap_port = lisp . LISP_DATA_PORT if iI . rloc . translated_port == 0 else iI . rloc . translated_port
   if 33 - 33: I1IiiI / OoO0O00
   if 12 - 12: II111iiii
   oOoO0o = iiI11I1i1i1iI . outer_dest . afi_to_version ( )
   iiI11I1i1i1iI . outer_version = oOoO0o
   if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
   oOOoO0OO00OOo0 = iIiiI1 if ( oOoO0o == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 25 - 25: oO0o
   iiI11I1i1i1iI . outer_source . copy_address ( oOOoO0OO00OOo0 )
   if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
   if ( iiI11I1i1i1iI . is_trace ( ) ) :
    III1I1Ii11iI = oO0oIIII
    IIIIIIIiI = "replicate"
    if ( lisp . lisp_trace_append ( iiI11I1i1i1iI , reason = IIIIIIIiI , lisp_socket = III1I1Ii11iI ) == False ) : return
    if 43 - 43: I1ii11iIi11i - iII111i
    if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
    if 47 - 47: iII111i
   if ( iiI11I1i1i1iI . encode ( None ) == None ) : return
   if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
   if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
   if 47 - 47: oO0o % iIii1I11I1II1
   if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
   iI . rloc . stats . increment ( len ( iiI11I1i1i1iI . packet ) )
   if 98 - 98: iII111i + Ii1I - OoO0O00
   OO0OO0O = Ii1IIii11 if oOoO0o == 6 else OOo
   iiI11I1i1i1iI . print_packet ( "Replicate-to-L{}" . format ( iI . level ) , True )
   iiI11I1i1i1iI . send_packet ( OO0OO0O , iiI11I1i1i1iI . outer_dest )
   if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
   if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
   if 38 - 38: O0 - IiII % I1Ii111
   if 64 - 64: iIii1I11I1II1
   if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
   I1Iii1I = len ( iiI11I1i1i1iI . packet ) - Oo0O0Oo00O
   iiI11I1i1i1iI . packet = iiI11I1i1i1iI . packet [ I1Iii1I : : ]
   if 13 - 13: o0oOOo0O0Ooo + O0
   if ( lisp . lisp_flow_logging ) : iiI11I1i1i1iI = copy . deepcopy ( iiI11I1i1i1iI )
   if 71 - 71: IiII + i1IIi * Oo0Ooo % Oo0Ooo / Oo0Ooo
   if 55 - 55: OoooooooOO + I1Ii111 + OoooooooOO * ooOoO0o
   if 68 - 68: O0
   if 2 - 2: OoO0O00 + O0 * OoO0O00 - Ii1I + oO0o
   if 43 - 43: I1ii11iIi11i - OoOoOO00
   if 36 - 36: I1ii11iIi11i - iII111i
 del ( iiI11I1i1i1iI )
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 lisp . lisp_latency_debug ( iIi1i , "RTR" )
 return
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
 if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
 if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
 if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
def OOOoo0ooOo00O ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  if 38 - 38: iIii1I11I1II1 + i11iIiiIii * OoO0O00 * ooOoO0o % OOooOOo
  if 5 - 5: ooOoO0o - I1Ii111 + I1IiiI * O0 / Oo0Ooo - Ii1I
  if 75 - 75: OoooooooOO - OOooOOo + o0oOOo0O0Ooo / iII111i % i11iIiiIii
  if 10 - 10: OoO0O00
  iiI11I1i1i1iI = lisp_thread . input_queue . get ( )
  if 22 - 22: i11iIiiIii / O0
  if 94 - 94: ooOoO0o * I11i - IiII . iIii1I11I1II1
  if 66 - 66: ooOoO0o - OOooOOo * OoOoOO00 / oO0o * II111iiii * OoO0O00
  if 91 - 91: OoooooooOO / Ii1I . I1IiiI + ooOoO0o . II111iiii
  lisp_thread . input_stats . increment ( len ( iiI11I1i1i1iI ) )
  if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
  if 77 - 77: I1Ii111 - I11i
  if 11 - 11: I1ii11iIi11i
  if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
  lisp_thread . lisp_packet . packet = iiI11I1i1i1iI
  if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
  if 55 - 55: ooOoO0o
  if 82 - 82: I1Ii111 - OOooOOo + OoO0O00
  if 64 - 64: o0oOOo0O0Ooo . O0 * Ii1I + OoooooooOO - Oo0Ooo . OoooooooOO
  I1ii ( lisp_thread . lisp_packet , lisp_thread . thread_name )
  if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
 return
 if 55 - 55: iII111i - OoO0O00
 if 100 - 100: O0
 if 79 - 79: iIii1I11I1II1
 if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
 if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 if 11 - 11: i1IIi % OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
def O0oo0O0 ( thread ) :
 ii = ( time . time ( ) % thread . number_of_pcap_threads )
 return ( int ( ii ) == thread . thread_number )
 if 9 - 9: OoO0O00 * Ii1I % i1IIi % oO0o
 if 53 - 53: oO0o * OoooooooOO . OoOoOO00
 if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
 if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
def oOO0 ( parms , not_used , packet ) :
 if ( O0oo0O0 ( parms [ 1 ] ) == False ) : return
 if 15 - 15: Oo0Ooo + I11i . ooOoO0o - iIii1I11I1II1 / O0 % iIii1I11I1II1
 III1I = parms [ 0 ]
 oO0OOo00o0O0O = parms [ 1 ]
 o0ooO0OoOo = oO0OOo00o0O0O . number_of_worker_threads
 if 99 - 99: OoOoOO00
 oO0OOo00o0O0O . input_stats . increment ( len ( packet ) )
 if 77 - 77: o0oOOo0O0Ooo
 if 48 - 48: OoOoOO00 % I1ii11iIi11i / I11i . iIii1I11I1II1 * II111iiii
 if 65 - 65: OoOoOO00
 if 31 - 31: I11i * OoOoOO00 . IiII % Ii1I + Oo0Ooo
 if 47 - 47: O0 * I1IiiI * OoO0O00 . II111iiii
 if 95 - 95: Ii1I % IiII . O0 % I1Ii111
 OOO = 4 if III1I == "lo0" else ( 14 if lisp . lisp_is_macos ( ) else 16 )
 packet = packet [ OOO : : ]
 if 37 - 37: O0 - I11i
 if 21 - 21: iIii1I11I1II1 / I1Ii111 + ooOoO0o - I11i / Oo0Ooo / II111iiii
 if 69 - 69: I1IiiI . OoOoOO00
 if 53 - 53: I11i
 if ( o0ooO0OoOo ) :
  OO000 = oO0OOo00o0O0O . input_stats . packet_count % o0ooO0OoOo
  OO000 = OO000 + ( len ( I11 ) - o0ooO0OoOo )
  oOo0o0oo0O0O = I11 [ OO000 ]
  oOo0o0oo0O0O . input_queue . put ( packet )
 else :
  oO0OOo00o0O0O . lisp_packet . packet = packet
  I1ii ( oO0OOo00o0O0O . lisp_packet , oO0OOo00o0O0O . thread_name )
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1
 return
 if 35 - 35: II111iiii - IiII . i1IIi
 if 95 - 95: I1IiiI + I1IiiI - OOooOOo - iII111i
 if 45 - 45: Ii1I . OoooooooOO
 if 27 - 27: Ii1I * Oo0Ooo . OoOoOO00
 if 17 - 17: II111iiii % iII111i * OOooOOo % i1IIi . I1IiiI . iIii1I11I1II1
 if 27 - 27: i11iIiiIii - I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if 50 - 50: OoOoOO00
def i1i1Ii11Ii ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 57 - 57: OOooOOo + I1Ii111 % I1ii11iIi11i . OoO0O00 / OoO0O00 * O0
 III1I = "lo0" if lisp . lisp_is_macos ( ) else "any"
 if 6 - 6: i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 if 68 - 68: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 - I1Ii111
 if 37 - 37: IiII
 if 37 - 37: Oo0Ooo / IiII * O0
 o0o00O0oOooO0 = getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 o0o00O0oOooO0 = ( o0o00O0oOooO0 != "" and o0o00O0oOooO0 [ 0 ] == " " )
 if 99 - 99: ooOoO0o
 o0OO00 = "(dst host "
 iIi11i = ""
 for iI1Iii in lisp . lisp_get_all_addresses ( ) :
  o0OO00 += "{} or " . format ( iI1Iii )
  iIi11i += "{} or " . format ( iI1Iii )
  if 56 - 56: i11iIiiIii . ooOoO0o / iII111i
 o0OO00 = o0OO00 [ 0 : - 4 ]
 o0OO00 += ") and ((udp dst port 4341 or 8472 or 4789) or "
 o0OO00 += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0))))"
 if 48 - 48: OoO0O00 * OOooOOo + iIii1I11I1II1 / II111iiii
 if 100 - 100: I11i
 if 59 - 59: oO0o * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i
 if 85 - 85: O0
 if 32 - 32: OoooooooOO . OoO0O00 / Oo0Ooo * o0oOOo0O0Ooo / o0oOOo0O0Ooo * Ii1I
 if 19 - 19: Ii1I
 iIi11i = iIi11i [ 0 : - 4 ]
 o0OO00 += ( " or (not (src host {}) and " + "((udp src port 4342) or (udp dst port 4342)))" ) . format ( iIi11i )
 if 55 - 55: OOooOOo % OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
 if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
 if ( o0o00O0oOooO0 ) :
  o0OO00 += ( " or (dst net 0.0.0.0/0 and " + "not (host {} or src net 127.0.0.0/8))" ) . format ( iIi11i )
  if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
  if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
  if 71 - 71: iII111i
 lisp . lprint ( "Capturing packets for: '{}'" . format ( o0OO00 ) )
 if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
 if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
 if 58 - 58: I1ii11iIi11i
 if ( lisp . lisp_is_python2 ( ) ) :
  import pcappy
  ii1I = pcappy . open_live ( III1I , 9000 , 0 , 100 )
  ii1I . filter = o0OO00
  ii1I . loop ( - 1 , oOO0 , [ III1I , lisp_thread ] )
  if 98 - 98: i1IIi
 if ( lisp . lisp_is_python3 ( ) ) :
  import pcapy
  ii1I = pcapy . open_live ( III1I , 9000 , 0 , 100 )
  ii1I . setfilter ( o0OO00 )
  while ( True ) :
   OoO , iiI11I1i1i1iI = ii1I . next ( )
   if ( len ( iiI11I1i1i1iI ) == 0 ) : continue
   oOO0 ( [ III1I , lisp_thread ] , None , iiI11I1i1i1iI )
   if 51 - 51: I1ii11iIi11i + ooOoO0o + Oo0Ooo / i1IIi + i1IIi
   if 12 - 12: iIii1I11I1II1 . Ii1I . I1ii11iIi11i % I1IiiI . II111iiii . oO0o
 return
 if 32 - 32: I1ii11iIi11i + IiII / O0 / OoOoOO00 * OoooooooOO % ooOoO0o
 if 50 - 50: OoO0O00
 if 66 - 66: iIii1I11I1II1
 if 41 - 41: I1Ii111 . O0 * I1IiiI * I1ii11iIi11i
 if 100 - 100: iII111i
 if 73 - 73: I1ii11iIi11i % II111iiii
 if 79 - 79: OoOoOO00 + OoO0O00 - II111iiii + Ii1I
 if 11 - 11: oO0o + iIii1I11I1II1
def i1ooOoo000oO ( lisp_raw_socket , eid , geid , igmp ) :
 global iIiiI1
 if 50 - 50: IiII + o0oOOo0O0Ooo
 if 96 - 96: OoO0O00
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 iiI11I1i1i1iI = lisp . lisp_packet ( igmp )
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 OoOo = lisp . lisp_map_cache_lookup ( eid , geid )
 if ( OoOo == None ) : return
 if ( OoOo . rloc_set == [ ] ) : return
 if ( OoOo . rloc_set [ 0 ] . rle == None ) : return
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 O0O = eid . print_address_no_iid ( )
 for o0O in OoOo . rloc_set [ 0 ] . rle . rle_nodes :
  if ( o0O . rloc . rloc_name == O0O ) :
   iiI11I1i1i1iI . outer_dest . copy_address ( o0O . rloc . rloc )
   iiI11I1i1i1iI . encap_port = o0O . rloc . translated_port
   break
   if 51 - 51: oO0o + OoO0O00 + iII111i + iII111i % o0oOOo0O0Ooo
   if 29 - 29: ooOoO0o
 if ( iiI11I1i1i1iI . outer_dest . is_null ( ) ) : return
 if 41 - 41: O0 % iII111i
 i1iIi1IIiIII1 = lisp . lisp_myrlocs [ 0 ]
 if ( iIiiI1 ) : i1iIi1IIiIII1 = iIiiI1
 iiI11I1i1i1iI . outer_source . copy_address ( i1iIi1IIiIII1 )
 iiI11I1i1i1iI . outer_version = iiI11I1i1i1iI . outer_dest . afi_to_version ( )
 iiI11I1i1i1iI . outer_ttl = 32
 iiI11I1i1i1iI . inner_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 iiI11I1i1i1iI . inner_dest . store_address ( "[{}]224.0.0.1" . format ( geid . instance_id ) )
 iiI11I1i1i1iI . inner_ttl = 1
 if 19 - 19: I11i
 iiI111I1iIiI = lisp . green ( eid . print_address ( ) , False )
 IIIIIIIiI = lisp . red ( "{}:{}" . format ( iiI11I1i1i1iI . outer_dest . print_address_no_iid ( ) ,
 iiI11I1i1i1iI . encap_port ) , False )
 O00O = lisp . bold ( "IGMP Query" , False )
 if 94 - 94: Ii1I - I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo
 lisp . lprint ( "Data encapsulate {} to gleaned EID {}, RLOC {}" . format ( O00O , iiI111I1iIiI , IIIIIIIiI ) )
 if 15 - 15: OOooOOo
 if 31 - 31: iII111i / i1IIi . OoO0O00
 if 83 - 83: oO0o / iIii1I11I1II1 + i1IIi / iII111i
 if 47 - 47: oO0o + OoooooooOO . II111iiii . iII111i
 if 66 - 66: ooOoO0o * OoOoOO00
 if ( iiI11I1i1i1iI . encode ( None ) == None ) : return
 iiI11I1i1i1iI . print_packet ( "Send" , True )
 if 2 - 2: oO0o . I1Ii111 * Oo0Ooo + O0 - I11i * iIii1I11I1II1
 iiI11I1i1i1iI . send_packet ( lisp_raw_socket , iiI11I1i1i1iI . outer_dest )
 if 12 - 12: o0oOOo0O0Ooo * I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
 if 81 - 81: Oo0Ooo - I11i
 if 24 - 24: OoooooooOO . OoO0O00 * II111iiii
 if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
 if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
 if 79 - 79: I1IiiI - ooOoO0o
 if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 if 83 - 83: IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if 80 - 80: OoooooooOO + IiII
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if 43 - 43: Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
def O0Oooo ( lisp_raw_socket ) :
 if ( lisp . lisp_gleaned_groups == { } ) : return
 if 27 - 27: ooOoO0o + i11iIiiIii * I11i + OoOoOO00 + iII111i
 if 87 - 87: O0
 if 87 - 87: o0oOOo0O0Ooo / II111iiii
 if 90 - 90: ooOoO0o - I1ii11iIi11i - O0 + Ii1I
 if 68 - 68: OOooOOo . Oo0Ooo % ooOoO0o - OoooooooOO * iII111i . OOooOOo
 Ii1I1i111 = b"\x46\xc0\x00\x24\x00\x00\x40\x00\x01\x02\x00\x00"
 oO = lisp . lisp_myrlocs [ 0 ]
 iII1 = oO . address
 Ii1I1i111 += I1I11I1I1I ( ( iII1 >> 24 ) & 0xff )
 Ii1I1i111 += I1I11I1I1I ( ( iII1 >> 16 ) & 0xff )
 Ii1I1i111 += I1I11I1I1I ( ( iII1 >> 8 ) & 0xff )
 Ii1I1i111 += I1I11I1I1I ( iII1 & 0xff )
 Ii1I1i111 += b"\xe0\x00\x00\x01"
 Ii1I1i111 += b"\x94\x04\x00\x00"
 Ii1I1i111 = lisp . lisp_ip_checksum ( Ii1I1i111 , 24 )
 if 33 - 33: O0
 if 96 - 96: OoooooooOO + IiII * O0
 if 86 - 86: Ii1I
 if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 O0O00OOo = b"\x11\x64\x00\x00" + b"\x00\x00\x00\x00" + b"\x02\x3c\x00\x00"
 O0O00OOo = lisp . lisp_igmp_checksum ( O0O00OOo )
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if 69 - 69: OoOoOO00
 if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 OoOOoOooooOOo = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  OoOOoOooooOOo . store_address ( Ii1iIiII1ii1 )
  for O00oo in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   i1 . store_address ( O00oo )
   Ii1IIIIi1ii1I , IiiIiI1Ii1i , OoOoooO000OO = lisp . lisp_allow_gleaning ( OoOOoOooooOOo , i1 , None )
   if ( OoOoooO000OO == False ) : continue
   i1ooOoo000oO ( lisp_raw_socket , OoOOoOooooOOo , i1 , Ii1I1i111 + O0O00OOo )
   if 62 - 62: OOooOOo + Oo0Ooo % iIii1I11I1II1 / iIii1I11I1II1 . ooOoO0o . IiII
   if 21 - 21: OoO0O00 - Ii1I - I1IiiI / OoOoOO00
   if 48 - 48: OoooooooOO
   if 16 - 16: OoOoOO00 * I1ii11iIi11i * I1ii11iIi11i / O0 * i11iIiiIii
   if 64 - 64: iII111i * I1ii11iIi11i % II111iiii - OoOoOO00 + I1ii11iIi11i
   if 62 - 62: OoOoOO00 % o0oOOo0O0Ooo % I1IiiI + IiII . OoO0O00
   if 48 - 48: I1IiiI * i11iIiiIii % II111iiii
   if 20 - 20: i1IIi / I1IiiI * oO0o
   if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
   if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
def Iiii1 ( ) :
 OoOOoOooooOOo = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 36 - 36: iII111i
 oOooOO = [ ]
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  for O00oo in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   Ii1I1 = lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] [ O00oo ]
   OO0ooO0 = time . time ( ) - Ii1I1
   if ( OO0ooO0 < lisp . LISP_IGMP_TIMEOUT_INTERVAL ) : continue
   oOooOO . append ( [ Ii1iIiII1ii1 , O00oo ] )
   if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
   if 74 - 74: oO0o
   if 34 - 34: iII111i
   if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
   if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
   if 43 - 43: OoO0O00 % OoO0O00
   if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 II1iI1IIi = lisp . bold ( "timed out" , False )
 for Ii1iIiII1ii1 , O00oo in oOooOO :
  OoOOoOooooOOo . store_address ( Ii1iIiII1ii1 )
  i1 . store_address ( O00oo )
  iiI111I1iIiI = lisp . green ( Ii1iIiII1ii1 , False )
  Ii11iiI1 = lisp . green ( O00oo , False )
  lisp . lprint ( "{} RLE {} for gleaned group {}" . format ( iiI111I1iIiI , II1iI1IIi , Ii11iiI1 ) )
  lisp . lisp_remove_gleaned_multicast ( OoOOoOooooOOo , i1 )
  if 71 - 71: o0oOOo0O0Ooo / OOooOOo % OOooOOo
  if 89 - 89: OoooooooOO + i11iIiiIii / I11i + iIii1I11I1II1 % ooOoO0o
  if 29 - 29: I1ii11iIi11i
  if 53 - 53: i11iIiiIii . I1ii11iIi11i % Ii1I / ooOoO0o % iIii1I11I1II1
  if 6 - 6: Oo0Ooo - OOooOOo . iIii1I11I1II1
  if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
  if 36 - 36: I11i % OOooOOo
  if 72 - 72: I1IiiI / iII111i - O0 + I11i
def o0iIIIIi ( lisp_raw_socket ) :
 lisp . lisp_set_exception ( )
 if 50 - 50: I1Ii111 + ooOoO0o + iII111i
 if 15 - 15: I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 for i1i in list ( lisp . lisp_crypto_keys_by_nonce . values ( ) ) :
  for i1iI1i in i1i : del ( i1iI1i )
  if 59 - 59: IiII
 lisp . lisp_crypto_keys_by_nonce . clear ( )
 lisp . lisp_crypto_keys_by_nonce = { }
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 if 24 - 24: ooOoO0o - I11i * oO0o
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 lisp . lisp_rtr_nat_trace_cache . clear ( )
 lisp . lisp_rtr_nat_trace_cache = { }
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 Iiii1 ( )
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 O0Oooo ( lisp_raw_socket )
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 Oooo0000 = threading . Timer ( 60 , o0iIIIIi ,
 [ lisp_raw_socket ] )
 Oooo0000 . start ( )
 return
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
def I1 ( ) :
 global Oo0oO0oo0oO00 , II1iII1i , II1Ii1iI1i
 global OOo , Ii1IIii11 , I11
 global i111I , oO0oIIII
 global iIiiI1 , I1I11I1I1I
 if 98 - 98: i1IIi . I1IiiI . oO0o
 lisp . lisp_i_am ( "rtr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "RTR starting up" )
 if 10 - 10: I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
 iIiiI1 = lisp . lisp_myrlocs [ 0 ]
 if ( lisp . lisp_on_gcp ( ) == False and lisp . lisp_on_aws ( ) ) :
  iI1i = lisp . bold ( "AWS RTR" , False )
  iII1 = None
  for III1I in [ "eth0" , "ens5" ] :
   iII1 = lisp . lisp_get_interface_address ( III1I )
   if ( iII1 != None ) : break
   if 3 - 3: IiII / I11i
  if ( iII1 != None ) :
   iIiiI1 = iII1
   iI1Iii = iII1 . print_address_no_iid ( )
   lisp . lprint ( "{} using RLOC {} on {}" . format ( iI1i , iI1Iii , III1I ) )
  else :
   iI1Iii = iIiiI1 . print_address_no_iid ( )
   lisp . lprint ( "{} cannot obtain RLOC, using {}" . format ( iI1i , iI1Iii ) )
   if 34 - 34: i11iIiiIii / I1Ii111 * OOooOOo . Oo0Ooo
   if 79 - 79: I1Ii111
   if 31 - 31: OOooOOo % I1Ii111
   if 98 - 98: IiII * iIii1I11I1II1 . Ii1I * Oo0Ooo / I1ii11iIi11i + ooOoO0o
   if 25 - 25: oO0o
   if 19 - 19: I1IiiI % Ii1I . IiII * ooOoO0o
   if 89 - 89: OoOoOO00 . OOooOOo
   if 7 - 7: oO0o % OoOoOO00 - I1IiiI + Oo0Ooo
 OoO0Ooo = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 II1Ii1iI1i = lisp . lisp_open_listen_socket ( OoO0Ooo ,
 str ( iiI1iIiI ) )
 Oo0oO0oo0oO00 = lisp . lisp_open_listen_socket ( "" , "lisp-rtr" )
 i111I = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 if 21 - 21: I1IiiI + I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 - OoO0O00 . Oo0Ooo
 II1iII1i [ 0 ] = II1Ii1iI1i
 if 59 - 59: OoO0O00 - OoO0O00 + iII111i
 II1iII1i [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 II1iII1i [ 2 ] = Oo0oO0oo0oO00
 if 32 - 32: i1IIi / Oo0Ooo - O0
 if 85 - 85: Ii1I - O0 * i11iIiiIii . i1IIi
 if 20 - 20: iII111i / OOooOOo
 if 28 - 28: ooOoO0o * I11i % i11iIiiIii * iII111i / Ii1I
 if 41 - 41: OOooOOo - o0oOOo0O0Ooo + Ii1I
 if 15 - 15: I11i / o0oOOo0O0Ooo + Ii1I
 if 76 - 76: Ii1I + OoooooooOO / OOooOOo % OoO0O00 / I1ii11iIi11i
 if 38 - 38: I1Ii111 . iII111i . I1IiiI * OoO0O00
 if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii / Ii1I
 OOo = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 OOo . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 II1iII1i . append ( OOo )
 if 93 - 93: ooOoO0o
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 if 19 - 19: I1ii11iIi11i
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if ( oo0Ooo0 ) : I1I11I1I1I = iIiii1iI1 if lisp . lisp_is_python2 ( ) else o00o0
 if 66 - 66: O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
 if 28 - 28: iIii1I11I1II1
 oO0oIIII = lisp . lisp_open_listen_socket ( "0.0.0.0" ,
 str ( lisp . LISP_TRACE_PORT ) )
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  Ii1IIii11 = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
  if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 I1iI1I1ii1 = os . getenv ( "LISP_PCAP_THREADS" )
 I1iI1I1ii1 = 1 if ( I1iI1I1ii1 == None ) else int ( I1iI1I1ii1 )
 iIIi1 = os . getenv ( "LISP_WORKER_THREADS" )
 iIIi1 = 0 if ( iIIi1 == None ) else int ( iIIi1 )
 if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
 if 92 - 92: OoOoOO00 % O0
 if 55 - 55: iIii1I11I1II1 * iII111i
 if 85 - 85: iIii1I11I1II1 . II111iiii
 for o0ooo0o0 in range ( I1iI1I1ii1 ) :
  O00Oooo00 = lisp . lisp_thread ( "pcap-{}" . format ( o0ooo0o0 ) )
  O00Oooo00 . thread_number = o0ooo0o0
  O00Oooo00 . number_of_pcap_threads = I1iI1I1ii1
  O00Oooo00 . number_of_worker_threads = iIIi1
  I11 . append ( O00Oooo00 )
  threading . Thread ( target = i1i1Ii11Ii , args = [ O00Oooo00 ] ) . start ( )
  if 93 - 93: O0 / ooOoO0o + I1IiiI
  if 20 - 20: IiII / iII111i % OoooooooOO / iIii1I11I1II1 + I1IiiI
  if 57 - 57: o0oOOo0O0Ooo / I1Ii111
  if 13 - 13: OoooooooOO + OoO0O00
  if 32 - 32: O0 + oO0o % Oo0Ooo
  if 7 - 7: I1ii11iIi11i / ooOoO0o
 for o0ooo0o0 in range ( iIIi1 ) :
  O00Oooo00 = lisp . lisp_thread ( "worker-{}" . format ( o0ooo0o0 ) )
  I11 . append ( O00Oooo00 )
  threading . Thread ( target = OOOoo0ooOo00O , args = [ O00Oooo00 ] ) . start ( )
  if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
  if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
  if 65 - 65: ooOoO0o - i1IIi
  if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
  if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 lisp . lisp_load_checkpoint ( )
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if 64 - 64: i1IIi
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 25 - 25: II111iiii / OoO0O00
 if 64 - 64: O0 % ooOoO0o
 if 40 - 40: o0oOOo0O0Ooo + I11i
 if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
 Oooo0000 = threading . Timer ( 60 , o0iIIIIi ,
 [ OOo ] )
 Oooo0000 . start ( )
 return ( True )
 if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
 if 47 - 47: OoooooooOO
 if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
 if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
def iIIiI11iI1Ii1 ( ) :
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lisp-rtr" )
 lisp . lisp_close_socket ( II1Ii1iI1i , "" )
 lisp . lisp_close_socket ( oO0oIIII , "" )
 lisp . lisp_close_socket ( i111I , "lispers.net-itr" )
 OOo . close ( )
 return
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo
 if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
def OOo000o ( kv_pair ) :
 global II1iII1i
 global iiI1iIiI
 if 37 - 37: iII111i
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 33 - 33: OoO0O00 - O0 - OoO0O00
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , iiI1iIiI ] )
  lisp . lisp_test_mr_timer . start ( )
  if 94 - 94: IiII * I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - o0oOOo0O0Ooo
 return
 if 13 - 13: OOooOOo / IiII - OoO0O00 / OOooOOo . i1IIi
 if 22 - 22: O0 - I11i + I1Ii111 . Ii1I * i1IIi
 if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
 if 10 - 10: I1Ii111 * oO0o % Oo0Ooo - I11i % Oo0Ooo
 if 65 - 65: iII111i * iIii1I11I1II1 / O0 . I11i
 if 94 - 94: Oo0Ooo . ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo . iII111i
 if 98 - 98: OOooOOo + Ii1I
 if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
def iiI11Ii1i ( kv_pair ) :
 global II1Ii1iI1i , OOo , iiI1iIiI
 if 100 - 100: iII111i + I11i + ooOoO0o + iII111i / i1IIi
 Oo0oOO0O00 = lisp . lisp_rloc_probing
 if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
 if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
 if 46 - 46: iIii1I11I1II1
 if 70 - 70: i1IIi . I11i
 lispconfig . lisp_xtr_command ( kv_pair )
 if 74 - 74: I11i
 if 58 - 58: iIii1I11I1II1 * OoO0O00 * I1Ii111 * ooOoO0o . OoooooooOO
 if 6 - 6: I1ii11iIi11i - oO0o * i11iIiiIii + OoOoOO00 / ooOoO0o % OOooOOo
 if 38 - 38: OOooOOo % IiII % II111iiii - Oo0Ooo - iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if ( Oo0oOO0O00 == False and lisp . lisp_rloc_probing ) :
  o00O0OoO = [ II1Ii1iI1i , II1Ii1iI1i ,
 None , OOo ]
  lisp . lisp_start_rloc_probe_timer ( 1 , o00O0OoO )
  oO0Oo = { "type" : "itr-crypto-port" , "port" : iiI1iIiI }
  lisp . lisp_write_to_dp_socket ( oO0Oo )
  if 28 - 28: OoooooooOO % oO0o + I1ii11iIi11i + O0 . I1Ii111
  if 80 - 80: i11iIiiIii % I1ii11iIi11i
  if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
  if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
  if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
 if 21 - 21: iII111i
 if 24 - 24: iII111i / ooOoO0o
 if 61 - 61: iIii1I11I1II1 + oO0o
 if 8 - 8: I1Ii111 + OoO0O00
i1Ii111 = {
 "lisp xtr-parameters" : [ iiI11Ii1i , {
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

 "lisp map-resolver" : [ OOo000o , {
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
if 20 - 20: iII111i - OoO0O00 - OoooooooOO
if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
if 55 - 55: oO0o
if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
if 97 - 97: I1Ii111 . I11i / I1IiiI
if 83 - 83: I11i - I1ii11iIi11i * oO0o
def oOO00OO0OooOo ( lisp_socket ) :
 if 13 - 13: O0 % ooOoO0o % I11i
 if 25 - 25: OoooooooOO % Ii1I * II111iiii - OoO0O00
 if 95 - 95: I1IiiI % I1Ii111 * I1IiiI + O0 . I1Ii111 % OoooooooOO
 if 6 - 6: OoOoOO00 - ooOoO0o * o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo
 OOO00000o0 , oOO , i1I , iiI11I1i1i1iI = lisp . lisp_receive ( lisp_socket , False )
 OOOO000Ooo0O = lisp . lisp_trace ( )
 if ( OOOO000Ooo0O . decode ( iiI11I1i1i1iI ) == False ) : return
 if 96 - 96: Oo0Ooo + I1Ii111 . i1IIi
 if 54 - 54: II111iiii . i1IIi / I1ii11iIi11i % I1IiiI / I1Ii111
 if 65 - 65: OoOoOO00 . OoOoOO00 - oO0o + Oo0Ooo / i11iIiiIii
 if 90 - 90: iIii1I11I1II1 + OoOoOO00
 if 9 - 9: iIii1I11I1II1 . OoooooooOO + i1IIi - Oo0Ooo
 OOOO000Ooo0O . rtr_cache_nat_trace ( oOO , i1I )
 if 30 - 30: iII111i / OoO0O00 . iII111i
 if 17 - 17: Oo0Ooo + OoooooooOO * OoooooooOO
 if 5 - 5: I1Ii111 % OoooooooOO . OoOoOO00
 if 67 - 67: I1ii11iIi11i + Ii1I
 if 72 - 72: IiII % o0oOOo0O0Ooo
 if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
 if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
if ( I1 ( ) == False ) :
 lisp . lprint ( "lisp_rtr_startup() failed" )
 lisp . lisp_print_banner ( "RTR abnormal exit" )
 exit ( 1 )
 if 52 - 52: IiII % ooOoO0o
 if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
i1oooOoOoOO = [ II1Ii1iI1i , Oo0oO0oo0oO00 ,
 i111I , oO0oIIII ]
OooOO = [ II1Ii1iI1i ] * 3
if 32 - 32: i11iIiiIii
while ( True ) :
 try : II1i , IiiiI1 , Ii1IIIIi1ii1I = select . select ( i1oooOoOoOO , [ ] , [ ] )
 except : break
 if 34 - 34: Ii1I + Oo0Ooo - i1IIi - IiII + iIii1I11I1II1
 if 75 - 75: I1ii11iIi11i
 if 92 - 92: I11i / O0 * I1IiiI - I11i
 if 99 - 99: i11iIiiIii % OoooooooOO
 if ( lisp . lisp_ipc_data_plane and i111I in II1i ) :
  lisp . lisp_process_punt ( i111I , II1iII1i ,
 iiI1iIiI )
  if 56 - 56: IiII * I1Ii111
  if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
  if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
  if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
  if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
 if ( oO0oIIII in II1i ) :
  oOO00OO0OooOo ( oO0oIIII )
  if 56 - 56: i1IIi . i11iIiiIii
  if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
  if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
  if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
  if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
 if ( II1Ii1iI1i in II1i ) :
  OOO00000o0 , oOO , i1I , iiI11I1i1i1iI = lisp . lisp_receive ( OooOO [ 0 ] ,
 False )
  if ( oOO == "" ) : break
  if ( lisp . lisp_is_rloc_probe_request ( iiI11I1i1i1iI [ 0 : 1 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
   continue
   if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
  if ( lisp . lisp_is_rloc_probe_reply ( iiI11I1i1i1iI [ 0 : 1 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
   continue
   if 10 - 10: IiII / OoooooooOO
  lisp . lisp_parse_packet ( OooOO , iiI11I1i1i1iI , oOO , i1I )
  if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
  if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
  if 25 - 25: iIii1I11I1II1
  if 63 - 63: ooOoO0o
  if 96 - 96: I11i
  if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
 if ( Oo0oO0oo0oO00 in II1i ) :
  OOO00000o0 , oOO , i1I , iiI11I1i1i1iI = lisp . lisp_receive ( Oo0oO0oo0oO00 , True )
  if 63 - 63: iII111i
  if ( oOO == "" ) : break
  if 11 - 11: iII111i - iIii1I11I1II1
  if ( OOO00000o0 == "command" ) :
   iiI11I1i1i1iI = iiI11I1i1i1iI . decode ( )
   if ( iiI11I1i1i1iI == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 92 - 92: OoO0O00
   if ( iiI11I1i1i1iI . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( iiI11I1i1i1iI )
    continue
    if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
   lispconfig . lisp_process_command ( Oo0oO0oo0oO00 , OOO00000o0 ,
 iiI11I1i1i1iI , "lisp-rtr" , [ i1Ii111 ] )
  elif ( OOO00000o0 == "api" ) :
   iiI11I1i1i1iI = iiI11I1i1i1iI . decode ( )
   lisp . lisp_process_api ( "lisp-rtr" , Oo0oO0oo0oO00 , iiI11I1i1i1iI )
  elif ( OOO00000o0 == "data-packet" ) :
   I1ii ( iiI11I1i1i1iI , "" )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( iiI11I1i1i1iI [ 0 : 1 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
    continue
    if 12 - 12: ooOoO0o
   if ( lisp . lisp_is_rloc_probe_reply ( iiI11I1i1i1iI [ 0 : 1 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
    continue
    if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
   lisp . lisp_parse_packet ( II1iII1i , iiI11I1i1i1iI , oOO , i1I )
   if 60 - 60: OOooOOo . iII111i / iIii1I11I1II1 + OOooOOo * I1Ii111
   if 82 - 82: i11iIiiIii . iIii1I11I1II1 * I1IiiI - I11i + Ii1I
   if 48 - 48: I1ii11iIi11i
   if 96 - 96: ooOoO0o . OoooooooOO
iIIiI11iI1Ii1 ( )
lisp . lisp_print_banner ( "RTR normal exit" )
exit ( 0 )
if 39 - 39: OOooOOo + OoO0O00
if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
