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
  if 57 - 57: O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
  if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if ( O0O00OOo ) : return
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 oOo0O = iiI11I1i1i1iI . inner_dest
 if ( oOo0O . is_multicast_address ( ) ) :
  if ( oOo0O . is_link_local_multicast ( ) ) :
   i1iiiIi1i = lisp . green ( oOo0O . print_address ( ) , False )
   lisp . dprint ( "Drop link-local multicast EID {}" . format ( i1iiiIi1i ) )
   return
   if 67 - 67: OoOoOO00 / o0oOOo0O0Ooo * OoO0O00 / OOooOOo * I1ii11iIi11i / oO0o
  OOoOO0OO = False
  Ii1IIIIi1ii1I , IiiIiI1Ii1i , i1oo00OoO = lisp . lisp_allow_gleaning ( iiI11I1i1i1iI . inner_source , oOo0O , None )
 else :
  OOoOO0OO , Ii1IIIIi1ii1I , IiiIiI1Ii1i = lisp . lisp_allow_gleaning ( oOo0O , None , None )
  if 30 - 30: Oo0Ooo . OoO0O00
 iiI11I1i1i1iI . gleaned_dest = OOoOO0OO
 if 57 - 57: I11i . Oo0Ooo + II111iiii
 if 43 - 43: I1Ii111 % iII111i
 if 69 - 69: iII111i % OoO0O00
 if 86 - 86: oO0o / oO0o
 OoOo = lisp . lisp_map_cache_lookup ( iiI11I1i1i1iI . inner_source , iiI11I1i1i1iI . inner_dest )
 if ( OoOo ) : OoOo . add_recent_source ( iiI11I1i1i1iI . inner_source )
 if 28 - 28: i11iIiiIii / o0oOOo0O0Ooo . iIii1I11I1II1 / II111iiii
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
 if ( OoOo and ( OoOo . action == lisp . LISP_NATIVE_FORWARD_ACTION or
 OoOo . eid . address == 0 ) ) :
  oo00ooOoo = lisp . lisp_db_for_lookups . lookup_cache ( iiI11I1i1i1iI . inner_source , False )
  if ( oo00ooOoo and oo00ooOoo . secondary_iid ) :
   iii1IIIiiiI = iiI11I1i1i1iI . inner_dest
   iii1IIIiiiI . instance_id = oo00ooOoo . secondary_iid
   if 94 - 94: O0 - I11i - iIii1I11I1II1 % ooOoO0o / Ii1I % iII111i
   OoOo = lisp . lisp_map_cache_lookup ( iiI11I1i1i1iI . inner_source , iii1IIIiiiI )
   if ( OoOo ) :
    iiI11I1i1i1iI . gleaned_dest = OoOo . gleaned
    OoOo . add_recent_source ( iiI11I1i1i1iI . inner_source )
   else :
    OOoOO0OO , Ii1IIIIi1ii1I , IiiIiI1Ii1i = lisp . lisp_allow_gleaning ( iii1IIIiiiI , None ,
 None )
    iiI11I1i1i1iI . gleaned_dest = OOoOO0OO
    if 44 - 44: Oo0Ooo % iIii1I11I1II1
    if 90 - 90: II111iiii + OoooooooOO % OoooooooOO
    if 35 - 35: iII111i / I1ii11iIi11i * OoooooooOO . II111iiii / Oo0Ooo
    if 1 - 1: OoooooooOO + IiII . i1IIi % I11i
    if 66 - 66: o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
    if 12 - 12: iII111i . IiII . OoOoOO00 / O0
    if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
    if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
    if 8 - 8: ooOoO0o * O0
 if ( OoOo == None and OOoOO0OO ) :
  lisp . lprint ( "Suppress Map-Request for gleaned EID {}" . format ( lisp . green ( iiI11I1i1i1iI . inner_dest . print_address ( ) , False ) ) )
  if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
  return
  if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
  if 34 - 34: ooOoO0o
 if ( OoOo == None or lisp . lisp_mr_or_pubsub ( OoOo . action ) ) :
  if ( lisp . lisp_rate_limit_map_request ( iiI11I1i1i1iI . inner_dest ) ) : return
  if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
  IIi11i1II = ( OoOo and OoOo . action == lisp . LISP_SEND_PUBSUB_ACTION )
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 iiI11I1i1i1iI . inner_source , iiI11I1i1i1iI . inner_dest , None , IIi11i1II )
  if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
  if ( iiI11I1i1i1iI . is_trace ( ) ) :
   III1I1Ii11iI = oO0oIIII
   OooOoOOo0oO00 = "map-cache miss"
   lisp . lisp_trace_append ( iiI11I1i1i1iI , reason = OooOoOOo0oO00 , lisp_socket = III1I1Ii11iI )
   if 73 - 73: iII111i / I1ii11iIi11i % I1ii11iIi11i * I11i / I1ii11iIi11i
  return
  if 8 - 8: Ii1I
  if 35 - 35: IiII + i1IIi * oO0o - Ii1I . Oo0Ooo
  if 31 - 31: o0oOOo0O0Ooo
  if 15 - 15: O0 / Oo0Ooo % I1ii11iIi11i + o0oOOo0O0Ooo
  if 23 - 23: iIii1I11I1II1 + O0
  if 58 - 58: Oo0Ooo
 if ( OoOo and OoOo . refresh ( ) ) :
  if ( lisp . lisp_rate_limit_map_request ( iiI11I1i1i1iI . inner_dest ) == False ) :
   lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( OoOo . print_eid_tuple ( ) , False ) ) )
   if 9 - 9: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo + OoooooooOO
   lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 iiI11I1i1i1iI . inner_source , iiI11I1i1i1iI . inner_dest , None )
   if 62 - 62: O0 / I1IiiI % O0 * OoO0O00 % I1IiiI
   if 33 - 33: I1IiiI . oO0o * OoO0O00 * iIii1I11I1II1
   if 5 - 5: Oo0Ooo / IiII % O0 . I1Ii111 * IiII
   if 83 - 83: OOooOOo
   if 12 - 12: i1IIi . i1IIi - o0oOOo0O0Ooo
   if 26 - 26: iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
   if 67 - 67: OoooooooOO
 OoOo . last_refresh_time = time . time ( )
 OoOo . stats . increment ( len ( iiI11I1i1i1iI . packet ) )
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 I1I111iI , iIiI1IIiii11 , IiI1 , oOo00o00oO , o0000 , i1I1iI1iIi111i = OoOo . select_rloc ( iiI11I1i1i1iI , None )
 if 42 - 42: I1Ii111 + I1Ii111 * II111iiii
 if 78 - 78: OoooooooOO
 if ( I1I111iI == None and o0000 == None ) :
  if ( oOo00o00oO == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   iiI11I1i1i1iI . send_packet ( OOo , iiI11I1i1i1iI . inner_dest )
   if 77 - 77: I1ii11iIi11i / i1IIi / Oo0Ooo % OOooOOo
   if ( iiI11I1i1i1iI . is_trace ( ) ) :
    III1I1Ii11iI = oO0oIIII
    OooOoOOo0oO00 = "not an EID"
    lisp . lisp_trace_append ( iiI11I1i1i1iI , reason = OooOoOOo0oO00 , lisp_socket = III1I1Ii11iI )
    if 48 - 48: I11i - IiII + iIii1I11I1II1 + OoooooooOO
   lisp . lisp_latency_debug ( iIi1i , "RTR" )
   return
   if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
  OooOoOOo0oO00 = "No reachable RLOCs found"
  lisp . dprint ( OooOoOOo0oO00 )
  if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
  if ( iiI11I1i1i1iI . is_trace ( ) ) :
   III1I1Ii11iI = oO0oIIII
   lisp . lisp_trace_append ( iiI11I1i1i1iI , reason = OooOoOOo0oO00 , lisp_socket = III1I1Ii11iI )
   if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
  return
  if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
 if ( I1I111iI and I1I111iI . is_null ( ) ) :
  lisp . dprint ( "Drop action RLOC found" )
  if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
  if ( iiI11I1i1i1iI . is_trace ( ) ) :
   III1I1Ii11iI = oO0oIIII
   OooOoOOo0oO00 = "drop action"
   lisp . lisp_trace_append ( iiI11I1i1i1iI , reason = OooOoOOo0oO00 , lisp_socket = III1I1Ii11iI )
   if 62 - 62: o0oOOo0O0Ooo
  return
  if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
  if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
  if 72 - 72: iIii1I11I1II1
  if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 iiI11I1i1i1iI . outer_tos = iiI11I1i1i1iI . inner_tos
 iiI11I1i1i1iI . outer_ttl = iiI11I1i1i1iI . inner_ttl
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if ( I1I111iI ) :
  iiI11I1i1i1iI . encap_port = iIiI1IIiii11
  if ( iIiI1IIiii11 == 0 ) : iiI11I1i1i1iI . encap_port = lisp . LISP_DATA_PORT
  iiI11I1i1i1iI . outer_dest . copy_address ( I1I111iI )
  OooOo000o0o = iiI11I1i1i1iI . outer_dest . afi_to_version ( )
  iiI11I1i1i1iI . outer_version = OooOo000o0o
  if 42 - 42: oO0o % OOooOOo
  OOO0 = iIiiI1 if ( OooOo000o0o == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 10 - 10: Oo0Ooo + O0
  iiI11I1i1i1iI . outer_source . copy_address ( OOO0 )
  if 43 - 43: iIii1I11I1II1 / II111iiii % o0oOOo0O0Ooo - OOooOOo
  if ( iiI11I1i1i1iI . is_trace ( ) ) :
   III1I1Ii11iI = oO0oIIII
   if ( lisp . lisp_trace_append ( iiI11I1i1i1iI , rloc_entry = i1I1iI1iIi111i ,
 lisp_socket = III1I1Ii11iI ) == False ) : return
   if 62 - 62: I11i
   if 63 - 63: OOooOOo + ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
   if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
   if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
   if 64 - 64: i1IIi
  if ( iiI11I1i1i1iI . encode ( IiI1 ) == None ) : return
  if ( len ( iiI11I1i1i1iI . packet ) <= 1500 ) :
   IIii1 = i1I1iI1iIi111i . rloc_next_hop [ 0 ] if ( i1I1iI1iIi111i . rloc_next_hop != None ) else "?"
   IiiiI111I = "Send {}" . format ( IIii1 )
   iiI11I1i1i1iI . print_packet ( IiiiI111I , True )
   if 49 - 49: o0oOOo0O0Ooo * Ii1I + I11i + iII111i
   if 30 - 30: o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
   if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
   if 50 - 50: ooOoO0o + i1IIi
   if 31 - 31: Ii1I
  OoOOo00 = Ii1IIii11 if OooOo000o0o == 6 else OOo
  iiI11I1i1i1iI . send_packet ( OoOOo00 , iiI11I1i1i1iI . outer_dest )
  if 53 - 53: IiII . I1Ii111 % iIii1I11I1II1 % OoOoOO00 % I11i
 elif ( o0000 ) :
  if 53 - 53: I1Ii111
  if 69 - 69: OoOoOO00 . o0oOOo0O0Ooo . I1IiiI - I1ii11iIi11i
  if 32 - 32: OoooooooOO / I1IiiI / iIii1I11I1II1 + II111iiii . oO0o . o0oOOo0O0Ooo
  if 21 - 21: iIii1I11I1II1 / II111iiii % i1IIi
  IIiI1i = len ( iiI11I1i1i1iI . packet )
  for iII1O000O in o0000 . rle_forwarding_list :
   if ( iII1O000O . rloc . up_state ( ) == False ) : continue
   if 98 - 98: iIii1I11I1II1 + I1Ii111 % OoOoOO00 + I11i % OoOoOO00
   iiI11I1i1i1iI . outer_dest . copy_address ( iII1O000O . rloc . rloc )
   iiI11I1i1i1iI . encap_port = lisp . LISP_DATA_PORT if iII1O000O . rloc . translated_port == 0 else iII1O000O . rloc . translated_port
   if 24 - 24: oO0o * I1Ii111
   if 40 - 40: Ii1I - OoOoOO00 * OoOoOO00 . OoOoOO00 + OoooooooOO
   OooOo000o0o = iiI11I1i1i1iI . outer_dest . afi_to_version ( )
   iiI11I1i1i1iI . outer_version = OooOo000o0o
   if 77 - 77: iIii1I11I1II1 . Ii1I % oO0o / Ii1I
   OOO0 = iIiiI1 if ( OooOo000o0o == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 54 - 54: oO0o + ooOoO0o - Oo0Ooo
   iiI11I1i1i1iI . outer_source . copy_address ( OOO0 )
   if 35 - 35: Ii1I - Ii1I + i1IIi - O0 - I1Ii111
   if ( iiI11I1i1i1iI . is_trace ( ) ) :
    III1I1Ii11iI = oO0oIIII
    OooOoOOo0oO00 = "replicate"
    if ( lisp . lisp_trace_append ( iiI11I1i1i1iI , reason = OooOoOOo0oO00 , lisp_socket = III1I1Ii11iI ) == False ) : return
    if 58 - 58: OoOoOO00 - iII111i - OoooooooOO
    if 96 - 96: iIii1I11I1II1
    if 82 - 82: OoOoOO00 + O0 - IiII % oO0o * i11iIiiIii
   if ( iiI11I1i1i1iI . encode ( None ) == None ) : return
   if 15 - 15: o0oOOo0O0Ooo
   if 39 - 39: OOooOOo / I1ii11iIi11i / I1IiiI * I1Ii111
   if 44 - 44: O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / O0 - I11i
   if 83 - 83: IiII * I11i / Oo0Ooo
   iII1O000O . rloc . stats . increment ( len ( iiI11I1i1i1iI . packet ) )
   if 32 - 32: o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
   OoOOo00 = Ii1IIii11 if OooOo000o0o == 6 else OOo
   iiI11I1i1i1iI . print_packet ( "Replicate-to-L{}" . format ( iII1O000O . level ) , True )
   iiI11I1i1i1iI . send_packet ( OoOOo00 , iiI11I1i1i1iI . outer_dest )
   if 39 - 39: OoooooooOO * OOooOOo * O0 . I11i . OoO0O00 + ooOoO0o
   if 9 - 9: OoOoOO00 + oO0o % OoooooooOO + o0oOOo0O0Ooo
   if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
   if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
   if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
   IiI1iiI1III1I = len ( iiI11I1i1i1iI . packet ) - IIiI1i
   iiI11I1i1i1iI . packet = iiI11I1i1i1iI . packet [ IiI1iiI1III1I : : ]
   if 97 - 97: i11iIiiIii / I11i * I1ii11iIi11i % OoOoOO00 . OoooooooOO
   if ( lisp . lisp_flow_logging ) : iiI11I1i1i1iI = copy . deepcopy ( iiI11I1i1i1iI )
   if 6 - 6: oO0o % O0 / IiII - iIii1I11I1II1 / IiII / i11iIiiIii
   if 12 - 12: OoooooooOO - OoO0O00
   if 81 - 81: OoOoOO00 % Ii1I
   if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
   if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
   if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 del ( iiI11I1i1i1iI )
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 lisp . lisp_latency_debug ( iIi1i , "RTR" )
 return
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
 if 93 - 93: I1Ii111 + Ii1I
def i1i1 ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  if 27 - 27: I1Ii111 + OoooooooOO - OoOoOO00
  if 15 - 15: oO0o / I11i * O0 . II111iiii - OoO0O00
  if 90 - 90: oO0o
  if 94 - 94: I11i / I1ii11iIi11i * I1Ii111 - OoOoOO00
  iiI11I1i1i1iI = lisp_thread . input_queue . get ( )
  if 44 - 44: Ii1I % i11iIiiIii - iII111i * I1ii11iIi11i + Oo0Ooo * OOooOOo
  if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
  if 65 - 65: Oo0Ooo . OoooooooOO
  if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
  lisp_thread . input_stats . increment ( len ( iiI11I1i1i1iI ) )
  if 55 - 55: iII111i - OoO0O00
  if 100 - 100: O0
  if 79 - 79: iIii1I11I1II1
  if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
  lisp_thread . lisp_packet . packet = iiI11I1i1i1iI
  if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
  if 11 - 11: i1IIi % OoO0O00 % iII111i
  if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
  if 13 - 13: OoO0O00
  I1ii ( lisp_thread . lisp_packet , lisp_thread . thread_name )
  if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
 return
 if 2 - 2: OoooooooOO . OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
def oOo00Ooo0o0 ( thread ) :
 i1IiII1i1I = ( time . time ( ) % thread . number_of_pcap_threads )
 return ( int ( i1IiII1i1I ) == thread . thread_number )
 if 39 - 39: I11i
 if 64 - 64: iIii1I11I1II1 / O0 % IiII . OoooooooOO + IiII + oO0o
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
 if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
def I11i11i1 ( parms , not_used , packet ) :
 if ( oOo00Ooo0o0 ( parms [ 1 ] ) == False ) : return
 if 68 - 68: Oo0Ooo . Oo0Ooo - I1ii11iIi11i / I11i . ooOoO0o / i1IIi
 IIii1 = parms [ 0 ]
 iI1i1iIi1iiII = parms [ 1 ]
 o0OoO0000o = iI1i1iIi1iiII . number_of_worker_threads
 if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
 iI1i1iIi1iiII . input_stats . increment ( len ( packet ) )
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
 if 46 - 46: I1Ii111
 o00OoooooooOo = 4 if IIii1 == "lo0" else ( 14 if lisp . lisp_is_macos ( ) else 16 )
 packet = packet [ o00OoooooooOo : : ]
 if 32 - 32: o0oOOo0O0Ooo + I1IiiI . I1Ii111
 if 41 - 41: OoOoOO00 . i11iIiiIii / I11i
 if 98 - 98: OoOoOO00 % II111iiii
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
 if ( o0OoO0000o ) :
  IiiIIi1 = iI1i1iIi1iiII . input_stats . packet_count % o0OoO0000o
  IiiIIi1 = IiiIIi1 + ( len ( I11 ) - o0OoO0000o )
  iI1iIiiI = I11 [ IiiIIi1 ]
  iI1iIiiI . input_queue . put ( packet )
 else :
  iI1i1iIi1iiII . lisp_packet . packet = packet
  I1ii ( iI1i1iIi1iiII . lisp_packet , iI1i1iIi1iiII . thread_name )
  if 95 - 95: iIii1I11I1II1 + Oo0Ooo * II111iiii + ooOoO0o + O0 * I11i
 return
 if 45 - 45: II111iiii % ooOoO0o % IiII + I1ii11iIi11i . i1IIi . OoOoOO00
 if 87 - 87: ooOoO0o . O0 % I1Ii111 + I1ii11iIi11i + Ii1I % iIii1I11I1II1
 if 19 - 19: i11iIiiIii - iII111i % I1IiiI
 if 56 - 56: i11iIiiIii . ooOoO0o / iII111i
 if 48 - 48: OoO0O00 * OOooOOo + iIii1I11I1II1 / II111iiii
 if 100 - 100: I11i
 if 59 - 59: oO0o * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i
 if 85 - 85: O0
def Iii ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 42 - 42: II111iiii + I1Ii111 - Ii1I - O0 / o0oOOo0O0Ooo % IiII
 IIii1 = "lo0" if lisp . lisp_is_macos ( ) else "any"
 if 83 - 83: OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
 if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
 if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
 if 71 - 71: iII111i
 Iiii1i11ii1Ii = getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 Iiii1i11ii1Ii = ( Iiii1i11ii1Ii != "" and Iiii1i11ii1Ii [ 0 ] == " " )
 if 12 - 12: OOooOOo . Ii1I
 O0oO = "(dst host "
 I1IiI1iIiIiii = ""
 for iI1Iii in lisp . lisp_get_all_addresses ( ) :
  O0oO += "{} or " . format ( iI1Iii )
  I1IiI1iIiIiii += "{} or " . format ( iI1Iii )
  if 29 - 29: ooOoO0o - i1IIi . I11i - I1ii11iIi11i + ooOoO0o + OoooooooOO
 O0oO = O0oO [ 0 : - 4 ]
 O0oO += ") and ((udp dst port 4341 or 8472 or 4789) or "
 O0oO += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0))))"
 if 36 - 36: i1IIi / ooOoO0o . iIii1I11I1II1
 if 12 - 12: Ii1I
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 I1IiI1iIiIiii = I1IiI1iIiIiii [ 0 : - 4 ]
 O0oO += ( " or (not (src host {}) and " + "((udp src port 4342) or (udp dst port 4342)))" ) . format ( I1IiI1iIiIiii )
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
 if ( Iiii1i11ii1Ii ) :
  O0oO += ( " or (dst net 0.0.0.0/0 and " + "not (host {} or src net 127.0.0.0/8))" ) . format ( I1IiI1iIiIiii )
  if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
  if 68 - 68: oO0o
  if 10 - 10: Ii1I
 lisp . lprint ( "Capturing packets for: '{}'" . format ( O0oO ) )
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if ( lisp . lisp_is_python2 ( ) ) :
  import pcappy
  I1 = pcappy . open_live ( IIii1 , 9000 , 0 , 100 )
  I1 . filter = O0oO
  I1 . loop ( - 1 , I11i11i1 , [ IIii1 , lisp_thread ] )
  if 35 - 35: I1IiiI
 if ( lisp . lisp_is_python3 ( ) ) :
  import pcapy
  I1 = pcapy . open_live ( IIii1 , 9000 , 0 , 100 )
  I1 . setfilter ( O0oO )
  while ( True ) :
   OoO , iiI11I1i1i1iI = I1 . next ( )
   if ( len ( iiI11I1i1i1iI ) == 0 ) : continue
   I11i11i1 ( [ IIii1 , lisp_thread ] , None , iiI11I1i1i1iI )
   if 36 - 36: i1IIi - I1ii11iIi11i - I1Ii111
   if 7 - 7: i11iIiiIii + I1IiiI
 return
 if 47 - 47: I1Ii111 - OOooOOo / ooOoO0o - Oo0Ooo + iII111i - iIii1I11I1II1
 if 68 - 68: Ii1I - oO0o + Oo0Ooo
 if 44 - 44: Ii1I * o0oOOo0O0Ooo * II111iiii
 if 5 - 5: i1IIi + O0 % O0 * O0 + OoOoOO00 % i1IIi
 if 80 - 80: iII111i / o0oOOo0O0Ooo + OoO0O00 / oO0o
 if 46 - 46: i11iIiiIii / IiII % i1IIi - I11i * OoOoOO00
 if 94 - 94: Ii1I - I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo
 if 15 - 15: OOooOOo
def i1iiI ( lisp_raw_socket , eid , geid , igmp ) :
 global iIiiI1
 if 83 - 83: oO0o / iIii1I11I1II1 + i1IIi / iII111i
 if 47 - 47: oO0o + OoooooooOO . II111iiii . iII111i
 if 66 - 66: ooOoO0o * OoOoOO00
 if 2 - 2: oO0o . I1Ii111 * Oo0Ooo + O0 - I11i * iIii1I11I1II1
 iiI11I1i1i1iI = lisp . lisp_packet ( igmp )
 if 12 - 12: o0oOOo0O0Ooo * I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
 if 81 - 81: Oo0Ooo - I11i
 if 24 - 24: OoooooooOO . OoO0O00 * II111iiii
 if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
 OoOo = lisp . lisp_map_cache_lookup ( eid , geid )
 if ( OoOo == None ) : return
 if ( OoOo . rloc_set == [ ] ) : return
 if ( OoOo . rloc_set [ 0 ] . rle == None ) : return
 if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
 oo0O0o00 = eid . print_address_no_iid ( )
 for o0O in OoOo . rloc_set [ 0 ] . rle . rle_nodes :
  if ( o0O . rloc . rloc_name == oo0O0o00 ) :
   iiI11I1i1i1iI . outer_dest . copy_address ( o0O . rloc . rloc )
   iiI11I1i1i1iI . encap_port = o0O . rloc . translated_port
   break
   if 39 - 39: ooOoO0o + O0 / i1IIi % IiII / oO0o * IiII
   if 77 - 77: IiII . I1Ii111 % OoOoOO00
 if ( iiI11I1i1i1iI . outer_dest . is_null ( ) ) : return
 if 42 - 42: IiII % iII111i % o0oOOo0O0Ooo % oO0o + I11i % OoOoOO00
 iI1iIIiii = lisp . lisp_myrlocs [ 0 ]
 if ( iIiiI1 ) : iI1iIIiii = iIiiI1
 iiI11I1i1i1iI . outer_source . copy_address ( iI1iIIiii )
 iiI11I1i1i1iI . outer_version = iiI11I1i1i1iI . outer_dest . afi_to_version ( )
 iiI11I1i1i1iI . outer_ttl = 32
 iiI11I1i1i1iI . inner_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 iiI11I1i1i1iI . inner_dest . store_address ( "[{}]224.0.0.1" . format ( geid . instance_id ) )
 iiI11I1i1i1iI . inner_ttl = 1
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 iiI111I1iIiI = lisp . green ( eid . print_address ( ) , False )
 OooOoOOo0oO00 = lisp . red ( "{}:{}" . format ( iiI11I1i1i1iI . outer_dest . print_address_no_iid ( ) ,
 iiI11I1i1i1iI . encap_port ) , False )
 oo000o = lisp . bold ( "IGMP Query" , False )
 if 95 - 95: oO0o - ooOoO0o * I11i / OoO0O00 / II111iiii + O0
 lisp . lprint ( "Data encapsulate {} to gleaned EID {}, RLOC {}" . format ( oo000o , iiI111I1iIiI , OooOoOOo0oO00 ) )
 if 37 - 37: I11i . I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if ( iiI11I1i1i1iI . encode ( None ) == None ) : return
 iiI11I1i1i1iI . print_packet ( "Send" , True )
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 iiI11I1i1i1iI . send_packet ( lisp_raw_socket , iiI11I1i1i1iI . outer_dest )
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
 if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
 if 96 - 96: OoooooooOO + IiII * O0
 if 86 - 86: Ii1I
 if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if 69 - 69: OoOoOO00
 if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 if 88 - 88: o0oOOo0O0Ooo
def iI11 ( lisp_raw_socket ) :
 if ( lisp . lisp_gleaned_groups == { } ) : return
 if 97 - 97: oO0o + Oo0Ooo * OOooOOo % Oo0Ooo
 if 31 - 31: i11iIiiIii
 if 12 - 12: ooOoO0o
 if 86 - 86: oO0o - OoO0O00
 if 63 - 63: I1IiiI / OoOoOO00 + OoooooooOO . I11i . ooOoO0o
 IiI1iiI11 = b"\x46\xc0\x00\x24\x00\x00\x40\x00\x01\x02\x00\x00"
 OOoOOOO00 = lisp . lisp_myrlocs [ 0 ]
 iII1 = OOoOOOO00 . address
 IiI1iiI11 += I1I11I1I1I ( ( iII1 >> 24 ) & 0xff )
 IiI1iiI11 += I1I11I1I1I ( ( iII1 >> 16 ) & 0xff )
 IiI1iiI11 += I1I11I1I1I ( ( iII1 >> 8 ) & 0xff )
 IiI1iiI11 += I1I11I1I1I ( iII1 & 0xff )
 IiI1iiI11 += b"\xe0\x00\x00\x01"
 IiI1iiI11 += b"\x94\x04\x00\x00"
 IiI1iiI11 = lisp . lisp_ip_checksum ( IiI1iiI11 , 24 )
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 O0O00OOo = b"\x11\x64\x00\x00" + b"\x00\x00\x00\x00" + b"\x02\x3c\x00\x00"
 O0O00OOo = lisp . lisp_igmp_checksum ( O0O00OOo )
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 OoOOoOooooOOo = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 34 - 34: iII111i
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  OoOOoOooooOOo . store_address ( Ii1iIiII1ii1 )
  for ii1IIiI1IIi in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   i1 . store_address ( ii1IIiI1IIi )
   Ii1IIIIi1ii1I , IiiIiI1Ii1i , o0OO = lisp . lisp_allow_gleaning ( OoOOoOooooOOo , i1 , None )
   if ( o0OO == False ) : continue
   i1iiI ( lisp_raw_socket , OoOOoOooooOOo , i1 , IiI1iiI11 + O0O00OOo )
   if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
   if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
   if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
   if 45 - 45: Ii1I - OOooOOo
   if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
   if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
   if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
   if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
   if 36 - 36: I11i % OOooOOo
   if 72 - 72: I1IiiI / iII111i - O0 + I11i
def o0 ( ) :
 OoOOoOooooOOo = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 48 - 48: o0oOOo0O0Ooo + o0oOOo0O0Ooo - Oo0Ooo
 iI1I11i = [ ]
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  for ii1IIiI1IIi in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   I11i11I1II = lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] [ ii1IIiI1IIi ]
   Ii = time . time ( ) - I11i11I1II
   if ( Ii < lisp . LISP_IGMP_TIMEOUT_INTERVAL ) : continue
   iI1I11i . append ( [ Ii1iIiII1ii1 , ii1IIiI1IIi ] )
   if 38 - 38: OoOoOO00 / iIii1I11I1II1 % i11iIiiIii - IiII * iII111i / OoOoOO00
   if 13 - 13: OoO0O00 * I1ii11iIi11i - I1Ii111
   if 79 - 79: oO0o % o0oOOo0O0Ooo % OoOoOO00
   if 45 - 45: I1IiiI * OOooOOo % OoO0O00
   if 24 - 24: ooOoO0o - I11i * oO0o
   if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
   if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 o0O0OOo0oO = lisp . bold ( "timed out" , False )
 for Ii1iIiII1ii1 , ii1IIiI1IIi in iI1I11i :
  OoOOoOooooOOo . store_address ( Ii1iIiII1ii1 )
  i1 . store_address ( ii1IIiI1IIi )
  iiI111I1iIiI = lisp . green ( Ii1iIiII1ii1 , False )
  Iiiii = lisp . green ( ii1IIiI1IIi , False )
  lisp . lprint ( "{} RLE {} for gleaned group {}" . format ( iiI111I1iIiI , o0O0OOo0oO , Iiiii ) )
  lisp . lisp_remove_gleaned_multicast ( OoOOoOooooOOo , i1 )
  if 15 - 15: I1IiiI . OoO0O00
  if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
  if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
  if 47 - 47: OoO0O00 + IiII / II111iiii
  if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
  if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
  if 94 - 94: iII111i - Oo0Ooo + oO0o
  if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
def oO0o0Oo ( lisp_raw_socket ) :
 lisp . lisp_set_exception ( )
 if 76 - 76: ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 for i1i in list ( lisp . lisp_crypto_keys_by_nonce . values ( ) ) :
  for Iiii1Ii in i1i : del ( Iiii1Ii )
  if 62 - 62: i1IIi % OoOoOO00
 lisp . lisp_crypto_keys_by_nonce . clear ( )
 lisp . lisp_crypto_keys_by_nonce = { }
 if 37 - 37: I11i * i1IIi
 if 20 - 20: IiII + OoOoOO00 - OOooOOo - OOooOOo - I1ii11iIi11i
 if 7 - 7: O0
 if 26 - 26: o0oOOo0O0Ooo / OoooooooOO % ooOoO0o % OOooOOo
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 54 - 54: OoOoOO00 - I1Ii111
 if 65 - 65: I1Ii111 . ooOoO0o + OOooOOo / Oo0Ooo + IiII % i1IIi
 if 28 - 28: i11iIiiIii + O0 / I1ii11iIi11i
 if 3 - 3: OoO0O00 * i1IIi . I1IiiI . O0 - OoOoOO00
 if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
 lisp . lisp_rtr_nat_trace_cache . clear ( )
 lisp . lisp_rtr_nat_trace_cache = { }
 if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
 if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
 if 10 - 10: I1ii11iIi11i / i11iIiiIii - Ii1I + oO0o * I1IiiI
 if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
 if 64 - 64: I11i + OoO0O00
 o0 ( )
 if 25 - 25: I1IiiI . ooOoO0o + I1IiiI % Ii1I * iIii1I11I1II1
 if 31 - 31: i11iIiiIii + OOooOOo - O0
 if 51 - 51: OoO0O00 * i1IIi / Ii1I * OOooOOo + ooOoO0o % I1ii11iIi11i
 if 34 - 34: oO0o * OoooooooOO + Ii1I + i11iIiiIii
 iI11 ( lisp_raw_socket )
 if 22 - 22: i1IIi
 if 24 - 24: I11i / I1IiiI * i1IIi % OoooooooOO
 if 99 - 99: i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 Oooo0000 = threading . Timer ( 60 , oO0o0Oo ,
 [ lisp_raw_socket ] )
 Oooo0000 . start ( )
 return
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
 if 98 - 98: oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
def OOooOO ( ) :
 global Oo0oO0oo0oO00 , II1iII1i , II1Ii1iI1i
 global OOo , Ii1IIii11 , I11
 global i111I , oO0oIIII
 global iIiiI1 , I1I11I1I1I
 if 59 - 59: OoO0O00 - OoO0O00 + iII111i
 lisp . lisp_i_am ( "rtr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "RTR starting up" )
 if 32 - 32: i1IIi / Oo0Ooo - O0
 if 85 - 85: Ii1I - O0 * i11iIiiIii . i1IIi
 if 20 - 20: iII111i / OOooOOo
 if 28 - 28: ooOoO0o * I11i % i11iIiiIii * iII111i / Ii1I
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 41 - 41: OOooOOo - o0oOOo0O0Ooo + Ii1I
 if 15 - 15: I11i / o0oOOo0O0Ooo + Ii1I
 if 76 - 76: Ii1I + OoooooooOO / OOooOOo % OoO0O00 / I1ii11iIi11i
 if 38 - 38: I1Ii111 . iII111i . I1IiiI * OoO0O00
 if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii / Ii1I
 if 93 - 93: ooOoO0o
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 if 19 - 19: I1ii11iIi11i
 iIiiI1 = lisp . lisp_myrlocs [ 0 ]
 if ( lisp . lisp_on_gcp ( ) == False and lisp . lisp_on_aws ( ) ) :
  IiI = lisp . bold ( "AWS RTR" , False )
  iII1 = None
  for IIii1 in [ "eth0" , "ens5" ] :
   iII1 = lisp . lisp_get_interface_address ( IIii1 )
   if ( iII1 != None ) : break
   if 4 - 4: OoooooooOO + ooOoO0o . i1IIi / O0 - O0
  if ( iII1 != None ) :
   iIiiI1 = iII1
   iI1Iii = iII1 . print_address_no_iid ( )
   lisp . lprint ( "{} using RLOC {} on {}" . format ( IiI , iI1Iii , IIii1 ) )
  else :
   iI1Iii = iIiiI1 . print_address_no_iid ( )
   lisp . lprint ( "{} cannot obtain RLOC, using {}" . format ( IiI , iI1Iii ) )
   if 52 - 52: OoO0O00 * OoooooooOO
   if 12 - 12: O0 + IiII * i1IIi . OoO0O00
   if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
   if 28 - 28: iIii1I11I1II1
   if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
   if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
   if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
   if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 iIi11I11 = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 II1Ii1iI1i = lisp . lisp_open_listen_socket ( iIi11I11 ,
 str ( iiI1iIiI ) )
 Oo0oO0oo0oO00 = lisp . lisp_open_listen_socket ( "" , "lisp-rtr" )
 i111I = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 if 40 - 40: iIii1I11I1II1
 II1iII1i [ 0 ] = II1Ii1iI1i
 if 92 - 92: OoOoOO00 % O0
 II1iII1i [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 II1iII1i [ 2 ] = Oo0oO0oo0oO00
 if 55 - 55: iIii1I11I1II1 * iII111i
 if 85 - 85: iIii1I11I1II1 . II111iiii
 if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
 if 22 - 22: OOooOOo
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
 if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 if 94 - 94: i1IIi
 if 36 - 36: I1IiiI + Oo0Ooo
 OOo = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 OOo . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 II1iII1i . append ( OOo )
 if 46 - 46: iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
 if ( oo0Ooo0 ) : I1I11I1I1I = iIiii1iI1 if lisp . lisp_is_python2 ( ) else o00o0
 if 65 - 65: ooOoO0o - i1IIi
 if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 oO0oIIII = lisp . lisp_open_listen_socket ( "0.0.0.0" ,
 str ( lisp . LISP_TRACE_PORT ) )
 if 64 - 64: i1IIi
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  Ii1IIii11 = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
  if 25 - 25: II111iiii / OoO0O00
 oo0OoOO0000 = os . getenv ( "LISP_PCAP_THREADS" )
 oo0OoOO0000 = 1 if ( oo0OoOO0000 == None ) else int ( oo0OoOO0000 )
 i11Ii1iIIIIi = os . getenv ( "LISP_WORKER_THREADS" )
 i11Ii1iIIIIi = 0 if ( i11Ii1iIIIIi == None ) else int ( i11Ii1iIIIIi )
 if 14 - 14: OoooooooOO . o0oOOo0O0Ooo . I11i
 if 50 - 50: ooOoO0o * OoOoOO00 + I1ii11iIi11i - i11iIiiIii + Oo0Ooo * I1ii11iIi11i
 if 20 - 20: I1Ii111 / o0oOOo0O0Ooo % OoOoOO00
 if 69 - 69: I1Ii111 - i1IIi % iII111i . OOooOOo - OOooOOo
 for o0oO00o in range ( oo0OoOO0000 ) :
  OOO0OoO0oo0OO = lisp . lisp_thread ( "pcap-{}" . format ( o0oO00o ) )
  OOO0OoO0oo0OO . thread_number = o0oO00o
  OOO0OoO0oo0OO . number_of_pcap_threads = oo0OoOO0000
  OOO0OoO0oo0OO . number_of_worker_threads = i11Ii1iIIIIi
  I11 . append ( OOO0OoO0oo0OO )
  threading . Thread ( target = Iii , args = [ OOO0OoO0oo0OO ] ) . start ( )
  if 31 - 31: I11i * oO0o . Ii1I
  if 35 - 35: I11i
  if 94 - 94: ooOoO0o / i11iIiiIii % O0
  if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
  if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
  if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 for o0oO00o in range ( i11Ii1iIIIIi ) :
  OOO0OoO0oo0OO = lisp . lisp_thread ( "worker-{}" . format ( o0oO00o ) )
  I11 . append ( OOO0OoO0oo0OO )
  threading . Thread ( target = i1i1 , args = [ OOO0OoO0oo0OO ] ) . start ( )
  if 68 - 68: O0
  if 76 - 76: I1ii11iIi11i
  if 99 - 99: o0oOOo0O0Ooo
  if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
  if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 lisp . lisp_load_checkpoint ( )
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
 if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
 if 37 - 37: iII111i
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 33 - 33: OoO0O00 - O0 - OoO0O00
 if 94 - 94: IiII * I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - o0oOOo0O0Ooo
 if 13 - 13: OOooOOo / IiII - OoO0O00 / OOooOOo . i1IIi
 if 22 - 22: O0 - I11i + I1Ii111 . Ii1I * i1IIi
 Oooo0000 = threading . Timer ( 60 , oO0o0Oo ,
 [ OOo ] )
 Oooo0000 . start ( )
 return ( True )
 if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
 if 10 - 10: I1Ii111 * oO0o % Oo0Ooo - I11i % Oo0Ooo
 if 65 - 65: iII111i * iIii1I11I1II1 / O0 . I11i
 if 94 - 94: Oo0Ooo . ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo . iII111i
 if 98 - 98: OOooOOo + Ii1I
 if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
 if 50 - 50: iIii1I11I1II1 - iII111i - I11i
def oo00O0O0O0o0o ( ) :
 if 74 - 74: O0 % OoooooooOO * Oo0Ooo + OOooOOo * iII111i
 if 100 - 100: OOooOOo + Ii1I * o0oOOo0O0Ooo + II111iiii
 if 70 - 70: Oo0Ooo * iIii1I11I1II1
 if 76 - 76: iII111i % OoOoOO00 % iIii1I11I1II1 . OOooOOo
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lisp-rtr" )
 lisp . lisp_close_socket ( II1Ii1iI1i , "" )
 lisp . lisp_close_socket ( oO0oIIII , "" )
 lisp . lisp_close_socket ( i111I , "lispers.net-itr" )
 OOo . close ( )
 return
 if 30 - 30: i1IIi
 if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
 if 93 - 93: ooOoO0o
 if 18 - 18: ooOoO0o
 if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
 if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
 if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
def O00oO ( kv_pair ) :
 global II1iII1i
 global iiI1iIiI
 if 65 - 65: O0 - I1Ii111 . Ii1I
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 19 - 19: I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I11i - Ii1I
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , iiI1iIiI ] )
  lisp . lisp_test_mr_timer . start ( )
  if 13 - 13: IiII * I1ii11iIi11i / I1ii11iIi11i / iIii1I11I1II1 % iIii1I11I1II1
 return
 if 21 - 21: I1ii11iIi11i
 if 86 - 86: ooOoO0o
 if 51 - 51: OoO0O00 - i11iIiiIii * I1IiiI
 if 95 - 95: OOooOOo % I1ii11iIi11i + o0oOOo0O0Ooo % ooOoO0o
 if 36 - 36: O0 / i1IIi % II111iiii / iII111i
 if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
 if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
def oO ( kv_pair ) :
 global II1Ii1iI1i , OOo , iiI1iIiI
 if 8 - 8: iIii1I11I1II1
 oOOo0ooO0 = lisp . lisp_rloc_probing
 if 38 - 38: I1Ii111
 if 18 - 18: iII111i / o0oOOo0O0Ooo + IiII % oO0o - IiII
 if 18 - 18: I1IiiI + ooOoO0o % I1ii11iIi11i - OoOoOO00 * i11iIiiIii . o0oOOo0O0Ooo
 if 16 - 16: Oo0Ooo
 lispconfig . lisp_xtr_command ( kv_pair )
 if 74 - 74: I11i
 if 98 - 98: oO0o / OoooooooOO % Ii1I * II111iiii - OoO0O00
 if 95 - 95: I1IiiI % I1Ii111 * I1IiiI + O0 . I1Ii111 % OoooooooOO
 if 6 - 6: OoOoOO00 - ooOoO0o * o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo
 if 100 - 100: OoO0O00 % I1Ii111 - I11i % I11i % I11i / ooOoO0o
 if ( oOOo0ooO0 == False and lisp . lisp_rloc_probing ) :
  o00O0OoO = [ II1Ii1iI1i , II1Ii1iI1i ,
 None , OOo ]
  lisp . lisp_start_rloc_probe_timer ( 1 , o00O0OoO )
  oO0Oo = { "type" : "itr-crypto-port" , "port" : iiI1iIiI }
  lisp . lisp_write_to_dp_socket ( oO0Oo )
  if 83 - 83: oO0o - ooOoO0o - IiII % i1IIi - iII111i . o0oOOo0O0Ooo
  if 96 - 96: Oo0Ooo + I1Ii111 . i1IIi
  if 54 - 54: II111iiii . i1IIi / I1ii11iIi11i % I1IiiI / I1Ii111
  if 65 - 65: OoOoOO00 . OoOoOO00 - oO0o + Oo0Ooo / i11iIiiIii
  if 90 - 90: iIii1I11I1II1 + OoOoOO00
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 9 - 9: iIii1I11I1II1 . OoooooooOO + i1IIi - Oo0Ooo
 if 30 - 30: iII111i / OoO0O00 . iII111i
 if 17 - 17: Oo0Ooo + OoooooooOO * OoooooooOO
 if 5 - 5: I1Ii111 % OoooooooOO . OoOoOO00
 if 67 - 67: I1ii11iIi11i + Ii1I
o0O00OooooO = {
 "lisp xtr-parameters" : [ oO , {
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

 "lisp map-resolver" : [ O00oO , {
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
if 77 - 77: I1IiiI % ooOoO0o
if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
if 52 - 52: IiII % ooOoO0o
if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
if 23 - 23: i11iIiiIii
if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
def ooOOo ( lisp_socket ) :
 if 5 - 5: O0
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
 if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
 O00o , oOO , i1I , iiI11I1i1i1iI = lisp . lisp_receive ( lisp_socket , False )
 o0o0ooOo00 = lisp . lisp_trace ( )
 if ( o0o0ooOo00 . decode ( iiI11I1i1i1iI ) == False ) : return
 if 91 - 91: OoO0O00 * I1Ii111 % OoO0O00 . o0oOOo0O0Ooo * I1ii11iIi11i . OOooOOo
 if 13 - 13: I1ii11iIi11i
 if 80 - 80: Oo0Ooo % IiII % OoooooooOO * Oo0Ooo % Ii1I
 if 41 - 41: OoooooooOO / i1IIi
 if 70 - 70: OoOoOO00 % o0oOOo0O0Ooo % i1IIi / I1ii11iIi11i % i11iIiiIii / i1IIi
 o0o0ooOo00 . rtr_cache_nat_trace ( oOO , i1I )
 if 4 - 4: IiII
 if 93 - 93: oO0o % i1IIi
 if 83 - 83: I1IiiI . Oo0Ooo - I11i . o0oOOo0O0Ooo
 if 73 - 73: I1IiiI - iII111i . iII111i
 if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
 if 64 - 64: i1IIi % I1ii11iIi11i / Ii1I % OoooooooOO
 if 24 - 24: I1Ii111 + OoooooooOO . IiII / OoOoOO00 / I11i
if ( OOooOO ( ) == False ) :
 lisp . lprint ( "lisp_rtr_startup() failed" )
 lisp . lisp_print_banner ( "RTR abnormal exit" )
 exit ( 1 )
 if 65 - 65: OoooooooOO
 if 18 - 18: O0 - i1IIi . I1Ii111
o00OOo00 = [ II1Ii1iI1i , Oo0oO0oo0oO00 ,
 i111I , oO0oIIII ]
oooO = [ II1Ii1iI1i ] * 3
if 2 - 2: iIii1I11I1II1 * I1IiiI % i1IIi % I1ii11iIi11i + OoooooooOO + I1IiiI
while ( True ) :
 try : iIi1iiI1i1 , iIi , Ii1IIIIi1ii1I = select . select ( o00OOo00 , [ ] , [ ] )
 except : break
 if 88 - 88: iII111i * OoooooooOO . iIii1I11I1II1
 if 11 - 11: oO0o + I1Ii111 . IiII * OoooooooOO - I1ii11iIi11i - OOooOOo
 if 16 - 16: iII111i / iIii1I11I1II1 + OOooOOo * iII111i * I11i
 if 8 - 8: I1Ii111
 if ( lisp . lisp_ipc_data_plane and i111I in iIi1iiI1i1 ) :
  lisp . lisp_process_punt ( i111I , II1iII1i ,
 iiI1iIiI )
  if 15 - 15: Oo0Ooo / Ii1I % O0 + I1ii11iIi11i
  if 96 - 96: ooOoO0o . OoooooooOO
  if 39 - 39: OOooOOo + OoO0O00
  if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
  if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
 if ( oO0oIIII in iIi1iiI1i1 ) :
  ooOOo ( oO0oIIII )
  if 71 - 71: ooOoO0o . i11iIiiIii
  if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
  if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
  if 67 - 67: iII111i
  if 88 - 88: Oo0Ooo
 if ( II1Ii1iI1i in iIi1iiI1i1 ) :
  O00o , oOO , i1I , iiI11I1i1i1iI = lisp . lisp_receive ( oooO [ 0 ] ,
 False )
  if ( oOO == "" ) : break
  if ( lisp . lisp_is_rloc_probe_request ( iiI11I1i1i1iI [ 0 : 1 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
   continue
   if 8 - 8: I1ii11iIi11i
  if ( lisp . lisp_is_rloc_probe_reply ( iiI11I1i1i1iI [ 0 : 1 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
   continue
   if 82 - 82: OoooooooOO
  lisp . lisp_parse_packet ( oooO , iiI11I1i1i1iI , oOO , i1I )
  if 75 - 75: II111iiii % I1IiiI + OOooOOo % OoooooooOO / IiII
  if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
  if 71 - 71: ooOoO0o . ooOoO0o - iIii1I11I1II1
  if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
  if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
 if ( Oo0oO0oo0oO00 in iIi1iiI1i1 ) :
  O00o , oOO , i1I , iiI11I1i1i1iI = lisp . lisp_receive ( Oo0oO0oo0oO00 , True )
  if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
  if ( oOO == "" ) : break
  if 29 - 29: Ii1I / ooOoO0o % I11i
  if ( O00o == "command" ) :
   iiI11I1i1i1iI = iiI11I1i1i1iI . decode ( )
   if ( iiI11I1i1i1iI == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
   if ( iiI11I1i1i1iI . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( iiI11I1i1i1iI )
    continue
    if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
   lispconfig . lisp_process_command ( Oo0oO0oo0oO00 , O00o ,
 iiI11I1i1i1iI , "lisp-rtr" , [ o0O00OooooO ] )
  elif ( O00o == "api" ) :
   iiI11I1i1i1iI = iiI11I1i1i1iI . decode ( )
   lisp . lisp_process_api ( "lisp-rtr" , Oo0oO0oo0oO00 , iiI11I1i1i1iI )
  elif ( O00o == "data-packet" ) :
   I1ii ( iiI11I1i1i1iI , "" )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( iiI11I1i1i1iI [ 0 : 1 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
    continue
    if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
   if ( lisp . lisp_is_rloc_probe_reply ( iiI11I1i1i1iI [ 0 : 1 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
    continue
    if 79 - 79: IiII + IiII + Ii1I
   lisp . lisp_parse_packet ( II1iII1i , iiI11I1i1i1iI , oOO , i1I )
   if 39 - 39: O0 - OoooooooOO
   if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
   if 79 - 79: O0
   if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
oo00O0O0O0o0o ( )
lisp . lisp_print_banner ( "RTR normal exit" )
exit ( 0 )
if 15 - 15: I1ii11iIi11i
if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
