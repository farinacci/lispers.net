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
from builtins import chr
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
try :
 import pcappy
except :
 pass
 if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
import pcapy
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
Oo0o = [ None , None , None ]
OOO0o0o = None
Ii1iI = None
Oo = None
I1Ii11I1Ii1i = None
Ooo = lisp . lisp_get_ephemeral_port ( )
o0oOoO00o = None
i1 = None
oOOoo00O0O = None
if 15 - 15: I1IiiI
O0ooo00OOo00 = [ ]
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
 global O0ooo00OOo00
 if 22 - 22: OoooooooOO % I11i - iII111i . iIii1I11I1II1 * i11iIiiIii
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "RTR" ,
 O0ooo00OOo00 ) )
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 if 61 - 61: ooOoO0o
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
def Ii1IOo0o0 ( parameter ) :
 global O0ooo00OOo00
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "RTR" , O0ooo00OOo00 ,
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
   i1OOO = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   i1OOO . store_prefix ( OO00Oo )
   oO0Oo [ "group-prefix" ] = i1OOO
   if 59 - 59: II111iiii + OoooooooOO * OoOoOO00 + i1IIi
  if ( O0o0 == "rloc-prefix" ) :
   Oo0OoO00oOO0o = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   Oo0OoO00oOO0o . store_prefix ( OO00Oo )
   oO0Oo [ "rloc-prefix" ] = Oo0OoO00oOO0o
   if 80 - 80: oO0o + OOooOOo - OOooOOo % iII111i
  if ( O0o0 == "rloc-probe" ) :
   oO0Oo [ "rloc-probe" ] = ( OO00Oo == "yes" )
   if 63 - 63: I1IiiI - I1ii11iIi11i + O0 % I11i / iIii1I11I1II1 / o0oOOo0O0Ooo
  if ( O0o0 == "igmp-query" ) :
   oO0Oo [ "igmp-query" ] = ( OO00Oo == "yes" )
   if 98 - 98: iII111i * iII111i / iII111i + I11i
   if 34 - 34: ooOoO0o
   if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
   if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
   if 92 - 92: iII111i . I1Ii111
   if 31 - 31: I1Ii111 . OoOoOO00 / O0
 for o000O0o in lisp . lisp_glean_mappings :
  if ( ( "eid-prefix" in o000O0o ) ^ ( "eid-prefix" in oO0Oo ) ) : continue
  if ( ( "eid-prefix" in o000O0o ) and ( "eid-prefix" in oO0Oo ) ) :
   iI1iII1 = o000O0o [ "eid-prefix" ]
   oO0OOoo0OO = oO0Oo [ "eid-prefix" ]
   if ( iI1iII1 . is_exact_match ( oO0OOoo0OO ) == False ) : continue
   if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
   if 21 - 21: I1IiiI * iIii1I11I1II1
  if ( ( "group-prefix" in o000O0o ) ^ ( "group-prefix" in oO0Oo ) ) : continue
  if ( ( "group-prefix" in o000O0o ) and ( "group-prefix" in oO0Oo ) ) :
   iI1iII1 = o000O0o [ "group-prefix" ]
   oO0OOoo0OO = oO0Oo [ "group-prefix" ]
   if ( iI1iII1 . is_exact_match ( oO0OOoo0OO ) == False ) : continue
   if 91 - 91: IiII
   if 15 - 15: II111iiii
  if ( ( "rloc-prefix" in o000O0o ) ^ ( "rloc-prefix" in oO0Oo ) ) : continue
  if ( ( "rloc-prefix" in o000O0o ) and ( "rloc-prefix" in oO0Oo ) ) :
   iI1iII1 = o000O0o [ "rloc-prefix" ]
   oO0OOoo0OO = oO0Oo [ "rloc-prefix" ]
   if ( iI1iII1 . is_exact_match ( oO0OOoo0OO ) == False ) : continue
   if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
   if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
  if ( ( "instance-id" in o000O0o ) ^ ( "instance-id" in oO0Oo ) ) : continue
  if ( ( "instance-id" in o000O0o ) and ( "instance-id" in oO0Oo ) ) :
   iI1iII1 = o000O0o [ "instance-id" ]
   oO0OOoo0OO = oO0Oo [ "instance-id" ]
   if ( iI1iII1 != oO0OOoo0OO ) : continue
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
 o00O0OoO , Oo0OoO00oOO0o , i1I , OoOO = parms
 if 53 - 53: Oo0Ooo
 iI1Iii = "{}:{}" . format ( Oo0OoO00oOO0o . print_address_no_iid ( ) , i1I )
 Ii1iIiII1ii1 = lisp . green ( mc . print_eid_tuple ( ) , False )
 oO00OOoO00 = "Changed '{}' translated address:port to {} for EID {}, {} {}" . format ( OoOO , lisp . red ( iI1Iii , False ) , Ii1iIiII1ii1 , "{}" , "{}" )
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
 for i1I1iI1iIi111i in mc . rloc_set :
  if ( i1I1iI1iIi111i . rle ) :
   for iiIi1IIi1I in i1I1iI1iIi111i . rle . rle_nodes :
    if ( iiIi1IIi1I . rloc_name != OoOO ) : continue
    iiIi1IIi1I . store_translated_rloc ( Oo0OoO00oOO0o , i1I )
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
  i1I1iI1iIi111i . store_translated_rloc ( Oo0OoO00oOO0o , i1I )
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
 global lisp_map_cache , o0oOoO00o
 if 19 - 19: i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 Iii1iiIi1II = OO0000o ( None , "Fast" )
 if 60 - 60: I1IiiI - oO0o * I11i % II111iiii
 if 62 - 62: iIii1I11I1II1
 if 12 - 12: OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 iii11I = 0
 I1Iii1 = None
 if ( packet [ 9 ] == '\x11' ) :
  if ( packet [ 20 : 22 ] == '\x10\xf6' ) : return ( False )
  if ( packet [ 22 : 24 ] == '\x10\xf6' ) : return ( False )
  if 30 - 30: OoooooooOO - OoOoOO00
  if ( packet [ 20 : 22 ] == '\x10\xf5' or packet [ 22 : 24 ] == '\x10\xf5' ) :
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
  OOo = '\x45\x00'
  O0II11iI111i1 = len ( packet ) + 20 + 8 + 8
  OOo += chr ( ( O0II11iI111i1 >> 8 ) & 0xff ) + chr ( O0II11iI111i1 & 0xff )
  OOo += '\xff\xff\x40\x00\x10\x11\x00\x00'
  OOo += chr ( ( I1Iii1 >> 24 ) & 0xff )
  OOo += chr ( ( I1Iii1 >> 16 ) & 0xff )
  OOo += chr ( ( I1Iii1 >> 8 ) & 0xff )
  OOo += chr ( I1Iii1 & 0xff )
  OOo += chr ( ( IIi1iiii1iI >> 24 ) & 0xff )
  OOo += chr ( ( IIi1iiii1iI >> 16 ) & 0xff )
  OOo += chr ( ( IIi1iiii1iI >> 8 ) & 0xff )
  OOo += chr ( IIi1iiii1iI & 0xff )
  OOo = lisp . lisp_ip_checksum ( OOo )
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  if 92 - 92: I11i . I1Ii111
  if 85 - 85: I1ii11iIi11i . I1Ii111
  O0O0Ooooo000 = O0II11iI111i1 - 20
  o000oOoo0o000 = '\xff\x00' if ( i1I == 4341 ) else '\x10\xf5'
  o000oOoo0o000 += chr ( ( i1I >> 8 ) & 0xff ) + chr ( i1I & 0xff )
  o000oOoo0o000 += chr ( ( O0O0Ooooo000 >> 8 ) & 0xff ) + chr ( O0O0Ooooo000 & 0xff ) + '\x00\x00'
  if 40 - 40: i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - I11i . i1IIi
  o000oOoo0o000 += '\x08\xdf\xdf\xdf'
  o000oOoo0o000 += chr ( ( iii11I >> 16 ) & 0xff )
  o000oOoo0o000 += chr ( ( iii11I >> 8 ) & 0xff )
  o000oOoo0o000 += chr ( iii11I & 0xff )
  o000oOoo0o000 += '\x00'
  if 99 - 99: O0 * I11i
  if 64 - 64: II111iiii + O0 / iIii1I11I1II1 / Oo0Ooo . ooOoO0o % IiII
  if 50 - 50: iIii1I11I1II1 - IiII + OOooOOo
  if 69 - 69: O0
  packet = OOo + o000oOoo0o000 + packet
  I1II1 ( "Encap" , packet )
 else :
  O0II11iI111i1 = len ( packet )
  oO = o00oo0 . stats
  I1II1 ( "Send" , packet )
  if 85 - 85: ooOoO0o / O0
  if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
  if 62 - 62: I1Ii111 . IiII . OoooooooOO
  if 11 - 11: OOooOOo / I11i
  if 73 - 73: i1IIi / i11iIiiIii
 o00oo0 . last_refresh_time = time . time ( )
 oO . increment ( O0II11iI111i1 )
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 if 85 - 85: OoOoOO00 + OOooOOo
 if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
 if 27 - 27: Ii1I
 I1ii11 = I1ii11 . print_address_no_iid ( )
 o0oOoO00o . sendto ( packet , ( I1ii11 , 0 ) )
 if 67 - 67: I1IiiI
 OO0000o ( Iii1iiIi1II , "Fast" )
 return ( True )
 if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
 if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
 if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
def Ii1ii111i1 ( lisp_packet , thread_name ) :
 global Oo0o , i1i1i1I , oOoo000
 global o0oOoO00o , i1
 global OOO0o0o
 global iIiiI1
 global oo0Ooo0
 if 87 - 87: OoooooooOO - o0oOOo0O0Ooo / IiII . i11iIiiIii * OoooooooOO
 Iii1iiIi1II = OO0000o ( None , "RTR" )
 if 84 - 84: OoOoOO00 / I11i * iII111i / oO0o - i11iIiiIii . Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if ( oo0Ooo0 ) :
  if ( oO0o0oooO0oO ( lisp_packet . packet ) ) : return
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
  o0o0O , oOO0OooOo , i1I , I1Ii = lisp . lisp_is_rloc_probe ( Oo00OOo , - 1 )
  if ( Oo00OOo != o0o0O ) :
   if ( oOO0OooOo == None ) : return
   lisp . lisp_parse_packet ( Oo0o , o0o0O , oOO0OooOo , i1I , I1Ii )
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
   II1i111Ii1i = O0O0oOOo0O . udp_sport
   if ( lisp . lisp_store_nat_info ( O00oo0ooO , iiIii1ii , II1i111Ii1i ) ) :
    OooOo0ooo ( Oo0o , O00oo0ooO , iiIii1ii , II1i111Ii1i )
    if 33 - 33: I1Ii111
  else :
   oOO0OooOo = O0O0oOOo0O . outer_source . print_address_no_iid ( )
   I1Ii = O0O0oOOo0O . outer_ttl
   O0O0oOOo0O = O0O0oOOo0O . packet
   if ( lisp . lisp_is_rloc_probe_request ( O0O0oOOo0O [ 28 ] ) == False and
 lisp . lisp_is_rloc_probe_reply ( O0O0oOOo0O [ 28 ] ) == False ) : I1Ii = - 1
   O0O0oOOo0O = O0O0oOOo0O [ 28 : : ]
   lisp . lisp_parse_packet ( Oo0o , O0O0oOOo0O , oOO0OooOo , 0 , I1Ii )
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
 iiii1I1 = False
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
 iIi11i1 , oO00oo0o00o0o , IiIIIIIi = lisp . lisp_allow_gleaning ( O0O0oOOo0O . inner_source , None ,
 O0O0oOOo0O . outer_source )
 if ( iIi11i1 ) :
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
 O0O0OOOOoo = O0O0oOOo0O . inner_dest
 if ( O0O0OOOOoo . is_multicast_address ( ) ) :
  if ( O0O0OOOOoo . is_link_local_multicast ( ) ) :
   ooO000O = lisp . green ( O0O0OOOOoo . print_address ( ) , False )
   lisp . dprint ( "Drop link-local multicast EID {}" . format ( ooO000O ) )
   return
   if 53 - 53: o0oOOo0O0Ooo . iII111i / Ii1I
  I11iiIi1i1 = False
  oO00oo0o00o0o , IiIIIIIi , i1IiiI1iIi = lisp . lisp_allow_gleaning ( O0O0oOOo0O . inner_source , O0O0OOOOoo , None )
 else :
  I11iiIi1i1 , oO00oo0o00o0o , IiIIIIIi = lisp . lisp_allow_gleaning ( O0O0OOOOoo , None , None )
  if 66 - 66: OoO0O00 * Oo0Ooo
 O0O0oOOo0O . gleaned_dest = I11iiIi1i1
 if 28 - 28: OoO0O00 % OoOoOO00 % I1ii11iIi11i + I1IiiI / I1IiiI
 if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
 if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
 if 23 - 23: i11iIiiIii
 o00oo0 = lisp . lisp_map_cache_lookup ( O0O0oOOo0O . inner_source , O0O0oOOo0O . inner_dest )
 if ( o00oo0 ) : o00oo0 . add_recent_source ( O0O0oOOo0O . inner_source )
 if 39 - 39: o0oOOo0O0Ooo - I1ii11iIi11i % iII111i * OoO0O00 - OOooOOo / iII111i
 if 29 - 29: I1ii11iIi11i
 if 52 - 52: i11iIiiIii / i1IIi
 if 1 - 1: ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if ( o00oo0 and ( o00oo0 . action == lisp . LISP_NATIVE_FORWARD_ACTION or
 o00oo0 . eid . address == 0 ) ) :
  i1I1iIi1IiI = lisp . lisp_db_for_lookups . lookup_cache ( O0O0oOOo0O . inner_source , False )
  if ( i1I1iIi1IiI and i1I1iIi1IiI . secondary_iid ) :
   i1111 = O0O0oOOo0O . inner_dest
   i1111 . instance_id = i1I1iIi1IiI . secondary_iid
   if 82 - 82: ooOoO0o % Ii1I - ooOoO0o % OoOoOO00
   o00oo0 = lisp . lisp_map_cache_lookup ( O0O0oOOo0O . inner_source , i1111 )
   if ( o00oo0 ) :
    O0O0oOOo0O . gleaned_dest = o00oo0 . gleaned
    o00oo0 . add_recent_source ( O0O0oOOo0O . inner_source )
   else :
    I11iiIi1i1 , oO00oo0o00o0o , IiIIIIIi = lisp . lisp_allow_gleaning ( i1111 , None ,
 None )
    O0O0oOOo0O . gleaned_dest = I11iiIi1i1
    if 47 - 47: iIii1I11I1II1 . oO0o . OOooOOo * i1IIi
    if 32 - 32: i11iIiiIii - i1IIi % OOooOOo . O0 % OoOoOO00 * Oo0Ooo
    if 90 - 90: OOooOOo * I1Ii111
    if 50 - 50: IiII % i1IIi
    if 21 - 21: OoooooooOO - iIii1I11I1II1
    if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
    if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
    if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
    if 62 - 62: i1IIi - OoOoOO00
 if ( o00oo0 == None and I11iiIi1i1 ) :
  lisp . lprint ( "Suppress Map-Request for gleaned EID {}" . format ( lisp . green ( O0O0oOOo0O . inner_dest . print_address ( ) , False ) ) )
  if 62 - 62: i1IIi + Oo0Ooo % IiII
  return
  if 28 - 28: I1ii11iIi11i . i1IIi
  if 10 - 10: OoO0O00 / Oo0Ooo
 if ( o00oo0 == None or lisp . lisp_mr_or_pubsub ( o00oo0 . action ) ) :
  if ( lisp . lisp_rate_limit_map_request ( O0O0oOOo0O . inner_dest ) ) : return
  if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
  oo0OOOOOO0 = ( o00oo0 and o00oo0 . action == lisp . LISP_SEND_PUBSUB_ACTION )
  lisp . lisp_send_map_request ( Oo0o , Ooo ,
 O0O0oOOo0O . inner_source , O0O0oOOo0O . inner_dest , None , oo0OOOOOO0 )
  if 26 - 26: iIii1I11I1II1
  if ( O0O0oOOo0O . is_trace ( ) ) :
   iiIii1ii = OOO0o0o
   OOOo = "map-cache miss"
   lisp . lisp_trace_append ( O0O0oOOo0O , reason = OOOo , lisp_socket = iiIii1ii )
   if 79 - 79: OoOoOO00 % IiII % Oo0Ooo
  return
  if 29 - 29: OoooooooOO . I1IiiI % I1ii11iIi11i - iII111i
  if 8 - 8: i1IIi
  if 32 - 32: oO0o / II111iiii
  if 45 - 45: I1ii11iIi11i + OoO0O00 * i11iIiiIii / OOooOOo % I11i * O0
  if 17 - 17: O0
  if 88 - 88: Oo0Ooo . O0 % OoooooooOO / OOooOOo
 if ( o00oo0 and o00oo0 . refresh ( ) ) :
  if ( lisp . lisp_rate_limit_map_request ( O0O0oOOo0O . inner_dest ) == False ) :
   lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( o00oo0 . print_eid_tuple ( ) , False ) ) )
   if 89 - 89: II111iiii / oO0o
   lisp . lisp_send_map_request ( Oo0o , Ooo ,
 O0O0oOOo0O . inner_source , O0O0oOOo0O . inner_dest , None )
   if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
   if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
   if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
   if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
   if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
   if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
   if 19 - 19: i11iIiiIii
 o00oo0 . last_refresh_time = time . time ( )
 o00oo0 . stats . increment ( len ( O0O0oOOo0O . packet ) )
 if 54 - 54: II111iiii . I11i
 if 73 - 73: OoOoOO00 . I1IiiI
 if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
 if 48 - 48: iII111i * iII111i
 I1I1 , iI1I1iiIi1I , I11iIiii1 , iIIIiiiI11I , I1ii1111Ii , i1I1iI1iIi111i = o00oo0 . select_rloc ( O0O0oOOo0O , None )
 if 69 - 69: IiII . OoO0O00 + II111iiii
 if 70 - 70: I1IiiI / I11i
 if ( I1I1 == None and I1ii1111Ii == None ) :
  if ( iIIIiiiI11I == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   O0O0oOOo0O . send_packet ( o0oOoO00o , O0O0oOOo0O . inner_dest )
   if 28 - 28: I1ii11iIi11i * OoooooooOO . II111iiii / i11iIiiIii + oO0o
   if ( O0O0oOOo0O . is_trace ( ) ) :
    iiIii1ii = OOO0o0o
    OOOo = "not an EID"
    lisp . lisp_trace_append ( O0O0oOOo0O , reason = OOOo , lisp_socket = iiIii1ii )
    if 38 - 38: IiII . Ii1I
   OO0000o ( Iii1iiIi1II , "RTR" )
   return
   if 24 - 24: o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
  OOOo = "No reachable RLOCs found"
  lisp . dprint ( OOOo )
  if 12 - 12: iII111i . IiII . OoOoOO00 / O0
  if ( O0O0oOOo0O . is_trace ( ) ) :
   iiIii1ii = OOO0o0o
   lisp . lisp_trace_append ( O0O0oOOo0O , reason = OOOo , lisp_socket = iiIii1ii )
   if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
  return
  if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
 if ( I1I1 and I1I1 . is_null ( ) ) :
  lisp . dprint ( "Drop action RLOC found" )
  if 8 - 8: ooOoO0o * O0
  if ( O0O0oOOo0O . is_trace ( ) ) :
   iiIii1ii = OOO0o0o
   OOOo = "drop action"
   lisp . lisp_trace_append ( O0O0oOOo0O , reason = OOOo , lisp_socket = iiIii1ii )
   if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
  return
  if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
  if 34 - 34: ooOoO0o
  if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
  if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
  if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 O0O0oOOo0O . outer_tos = O0O0oOOo0O . inner_tos
 O0O0oOOo0O . outer_ttl = O0O0oOOo0O . inner_ttl
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if ( I1I1 ) :
  O0O0oOOo0O . encap_port = iI1I1iiIi1I
  if ( iI1I1iiIi1I == 0 ) : O0O0oOOo0O . encap_port = lisp . LISP_DATA_PORT
  O0O0oOOo0O . outer_dest . copy_address ( I1I1 )
  ooOoO = O0O0oOOo0O . outer_dest . afi_to_version ( )
  O0O0oOOo0O . outer_version = ooOoO
  if 23 - 23: I11i
  iIiiIiiIi = iIiiI1 if ( ooOoO == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 40 - 40: o0oOOo0O0Ooo
  O0O0oOOo0O . outer_source . copy_address ( iIiiIiiIi )
  if 78 - 78: iIii1I11I1II1
  if ( O0O0oOOo0O . is_trace ( ) ) :
   iiIii1ii = OOO0o0o
   if ( lisp . lisp_trace_append ( O0O0oOOo0O , rloc_entry = i1I1iI1iIi111i ,
 lisp_socket = iiIii1ii ) == False ) : return
   if 56 - 56: OoooooooOO - I11i - i1IIi
   if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
   if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
   if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
   if 53 - 53: I11i + iIii1I11I1II1
  if ( O0O0oOOo0O . encode ( I11iIiii1 ) == None ) : return
  if ( len ( O0O0oOOo0O . packet ) <= 1500 ) : O0O0oOOo0O . print_packet ( "Send" , True )
  if 70 - 70: I1ii11iIi11i
  if 67 - 67: OoooooooOO
  if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
  if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
  oOOO = i1 if ooOoO == 6 else o0oOoO00o
  O0O0oOOo0O . send_packet ( oOOO , O0O0oOOo0O . outer_dest )
  if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
 elif ( I1ii1111Ii ) :
  if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
  if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
  if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
  if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
  OOO000 = len ( O0O0oOOo0O . packet )
  for Ii1 in I1ii1111Ii . rle_forwarding_list :
   O0O0oOOo0O . outer_dest . copy_address ( Ii1 . address )
   O0O0oOOo0O . encap_port = lisp . LISP_DATA_PORT if Ii1 . translated_port == 0 else Ii1 . translated_port
   if 62 - 62: i1IIi - i1IIi
   if 69 - 69: OoOoOO00 % oO0o - I11i
   ooOoO = O0O0oOOo0O . outer_dest . afi_to_version ( )
   O0O0oOOo0O . outer_version = ooOoO
   if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
   iIiiIiiIi = iIiiI1 if ( ooOoO == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
   O0O0oOOo0O . outer_source . copy_address ( iIiiIiiIi )
   if 62 - 62: o0oOOo0O0Ooo - Ii1I * OoOoOO00 - i11iIiiIii % ooOoO0o
   if ( O0O0oOOo0O . is_trace ( ) ) :
    iiIii1ii = OOO0o0o
    OOOo = "replicate"
    if ( lisp . lisp_trace_append ( O0O0oOOo0O , reason = OOOo , lisp_socket = iiIii1ii ) == False ) : return
    if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
    if 30 - 30: iII111i / OoO0O00 + oO0o
    if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
   if ( O0O0oOOo0O . encode ( None ) == None ) : return
   if 70 - 70: OoO0O00
   O0O0oOOo0O . print_packet ( "Replicate-to-L{}" . format ( Ii1 . level ) , True )
   O0O0oOOo0O . send_packet ( o0oOoO00o , O0O0oOOo0O . outer_dest )
   if 46 - 46: I11i - i1IIi
   if 46 - 46: I1Ii111 % Ii1I
   if 72 - 72: iIii1I11I1II1
   if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
   if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
   oOo0OOoooO = len ( O0O0oOOo0O . packet ) - OOO000
   O0O0oOOo0O . packet = O0O0oOOo0O . packet [ oOo0OOoooO : : ]
   if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
   if ( lisp . lisp_flow_logging ) : O0O0oOOo0O = copy . deepcopy ( O0O0oOOo0O )
   if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
   if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
   if 84 - 84: i11iIiiIii * OoO0O00
   if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
   if 30 - 30: O0 + I1ii11iIi11i + II111iiii
   if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 del ( O0O0oOOo0O )
 if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 OO0000o ( Iii1iiIi1II , "RTR" )
 return
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
def I1III111i ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  if 4 - 4: i1IIi + ooOoO0o + i1IIi
  if 31 - 31: Ii1I
  if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
  if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
  O0O0oOOo0O = lisp_thread . input_queue . get ( )
  if 47 - 47: o0oOOo0O0Ooo
  if 66 - 66: I1IiiI - IiII
  if 33 - 33: I1IiiI / OoO0O00
  if 12 - 12: II111iiii
  lisp_thread . input_stats . increment ( len ( O0O0oOOo0O ) )
  if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
  if 25 - 25: oO0o
  if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
  if 43 - 43: I1ii11iIi11i - iII111i
  lisp_thread . lisp_packet . packet = O0O0oOOo0O
  if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
  if 47 - 47: iII111i
  if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
  if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
  Ii1ii111i1 ( lisp_thread . lisp_packet , lisp_thread . thread_name )
  if 47 - 47: oO0o % iIii1I11I1II1
 return
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if 38 - 38: O0 - IiII % I1Ii111
 if 64 - 64: iIii1I11I1II1
 if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
 if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
def II11i1IiIII ( thread ) :
 oO00 = ( time . time ( ) % thread . number_of_pcap_threads )
 return ( int ( oO00 ) == thread . thread_number )
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii . OoOoOO00 % ooOoO0o + oO0o . OoO0O00
 if 46 - 46: OoO0O00 - o0oOOo0O0Ooo / OoOoOO00 - OoooooooOO + oO0o
 if 58 - 58: o0oOOo0O0Ooo / o0oOOo0O0Ooo + ooOoO0o + I11i - OoOoOO00 . OOooOOo
 if 15 - 15: ooOoO0o * OoOoOO00 % IiII . OoOoOO00 . I11i
 if 97 - 97: oO0o
 if 80 - 80: I1IiiI . Ii1I
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
def i1iii1ii ( parms , not_used , packet ) :
 if ( II11i1IiIII ( parms [ 1 ] ) == False ) : return
 if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
 oo0 = parms [ 0 ]
 i1iIIi1II1iiI = parms [ 1 ]
 III1Ii1i1I1 = i1iIIi1II1iiI . number_of_worker_threads
 if 97 - 97: I1Ii111 . ooOoO0o - I1Ii111 + I1IiiI * II111iiii
 i1iIIi1II1iiI . input_stats . increment ( len ( packet ) )
 if 10 - 10: Ii1I + I11i % OoooooooOO - I1IiiI
 if 70 - 70: OOooOOo - iII111i
 if 2 - 2: iIii1I11I1II1
 if 45 - 45: OoooooooOO / i11iIiiIii
 if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
 if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
 iIii1iII1Ii = 4 if oo0 == "lo0" else ( 14 if lisp . lisp_is_macos ( ) else 16 )
 packet = packet [ iIii1iII1Ii : : ]
 if 50 - 50: Ii1I
 if 22 - 22: I11i * O0 . II111iiii - OoO0O00
 if 90 - 90: oO0o
 if 94 - 94: I11i / I1ii11iIi11i * I1Ii111 - OoOoOO00
 if ( III1Ii1i1I1 ) :
  I1Ii11II1I1 = i1iIIi1II1iiI . input_stats . packet_count % III1Ii1i1I1
  I1Ii11II1I1 = I1Ii11II1I1 + ( len ( O0ooo00OOo00 ) - III1Ii1i1I1 )
  IiI1iI1IiiIi1 = O0ooo00OOo00 [ I1Ii11II1I1 ]
  IiI1iI1IiiIi1 . input_queue . put ( packet )
 else :
  i1iIIi1II1iiI . lisp_packet . packet = packet
  Ii1ii111i1 ( i1iIIi1II1iiI . lisp_packet , i1iIIi1II1iiI . thread_name )
  if 90 - 90: O0 + I11i - OoooooooOO . I11i
 return
 if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
 if 45 - 45: O0 . i11iIiiIii % iII111i . OoOoOO00 % IiII % iIii1I11I1II1
 if 58 - 58: iIii1I11I1II1 . OoOoOO00 - i11iIiiIii * iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if 80 - 80: I1ii11iIi11i / iIii1I11I1II1 % OoOoOO00
 if 80 - 80: OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
 if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
def ii ( lisp_thread ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 9 - 9: OoO0O00 * Ii1I % i1IIi % oO0o
 oo0 = "lo0" if lisp . lisp_is_macos ( ) else "any"
 if 53 - 53: oO0o * OoooooooOO . OoOoOO00
 if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
 if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 oOo00Ooo0o0 = getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 oOo00Ooo0o0 = ( oOo00Ooo0o0 != "" and oOo00Ooo0o0 [ 0 ] == " " )
 if 33 - 33: I11i
 oOO0 = "(dst host "
 IIi1I1i = ""
 for iI1Iii in lisp . lisp_get_all_addresses ( ) :
  oOO0 += "{} or " . format ( iI1Iii )
  IIi1I1i += "{} or " . format ( iI1Iii )
  if 13 - 13: iIii1I11I1II1 . OoOoOO00 * I1IiiI / oO0o * Ii1I
 oOO0 = oOO0 [ 0 : - 4 ]
 oOO0 += ") and ((udp dst port 4341 or 8472 or 4789) or "
 oOO0 += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0))))"
 if 64 - 64: ooOoO0o / O0 * OoOoOO00 * ooOoO0o
 if 60 - 60: I11i / i1IIi % I1ii11iIi11i / I1ii11iIi11i * I1ii11iIi11i . i11iIiiIii
 if 99 - 99: OoOoOO00
 if 77 - 77: o0oOOo0O0Ooo
 if 48 - 48: OoOoOO00 % I1ii11iIi11i / I11i . iIii1I11I1II1 * II111iiii
 if 65 - 65: OoOoOO00
 IIi1I1i = IIi1I1i [ 0 : - 4 ]
 oOO0 += ( " or (not (src host {}) and " + "((udp src port 4342 and ip[28] == 0x28) or " + "(udp dst port 4342 and ip[28] == 0x12)))" ) . format ( IIi1I1i )
 if 31 - 31: I11i * OoOoOO00 . IiII % Ii1I + Oo0Ooo
 if 47 - 47: O0 * I1IiiI * OoO0O00 . II111iiii
 if 95 - 95: Ii1I % IiII . O0 % I1Ii111
 if ( oOo00Ooo0o0 ) :
  oOO0 += ( " or (dst net 0.0.0.0/0 and " + "not (host {} or src net 127.0.0.0/8))" ) . format ( IIi1I1i )
  if 68 - 68: Oo0Ooo . Oo0Ooo - I1ii11iIi11i / I11i . ooOoO0o / i1IIi
  if 12 - 12: I1ii11iIi11i * i1IIi * I11i
  if 23 - 23: OOooOOo / O0 / I1IiiI
 lisp . lprint ( "Capturing packets for: '{}'" . format ( oOO0 ) )
 if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if ( lisp . lisp_is_python2 ( ) ) :
  II11I = pcappy . open_live ( oo0 , 9000 , 0 , 100 )
  II11I . filter = oOO0
  II11I . loop ( - 1 , i1iii1ii , [ oo0 , lisp_thread ] )
  if 31 - 31: Ii1I
 if ( lisp . lisp_is_python3 ( ) ) :
  II11I = pcapy . open_live ( oo0 , 9000 , 0 , 100 )
  II11I . setfilter ( oOO0 )
  II11I . loop ( - 1 , i1iii1ii )
  if 18 - 18: ooOoO0o + Ii1I
 return
 if 5 - 5: OoooooooOO + I11i * II111iiii
 if 98 - 98: OOooOOo % i1IIi . I1IiiI . II111iiii . I1ii11iIi11i / i11iIiiIii
 if 32 - 32: o0oOOo0O0Ooo + I1IiiI . I1Ii111
 if 41 - 41: OoOoOO00 . i11iIiiIii / I11i
 if 98 - 98: OoOoOO00 % II111iiii
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
 if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 if 68 - 68: o0oOOo0O0Ooo
def i11Ii1IIi ( lisp_raw_socket , eid , geid , igmp ) :
 if 36 - 36: O0 * OoO0O00 % iII111i * iII111i / OoO0O00 * IiII
 if 14 - 14: i1IIi . IiII + O0 * ooOoO0o
 if 76 - 76: OoO0O00
 if 92 - 92: I11i - iIii1I11I1II1 % OoooooooOO
 O0O0oOOo0O = lisp . lisp_packet ( igmp )
 if 39 - 39: iII111i . I1IiiI * OoOoOO00 - i11iIiiIii
 if 1 - 1: iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 o00oo0 = lisp . lisp_map_cache_lookup ( eid , geid )
 if ( o00oo0 == None ) : return
 if ( o00oo0 . rloc_set == [ ] ) : return
 if ( o00oo0 . rloc_set [ 0 ] . rle == None ) : return
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 iIiI1I1ii1I1 = eid . print_address_no_iid ( )
 for iiIi1IIi1I in o00oo0 . rloc_set [ 0 ] . rle . rle_nodes :
  if ( iiIi1IIi1I . rloc_name == iIiI1I1ii1I1 ) :
   O0O0oOOo0O . outer_dest . copy_address ( iiIi1IIi1I . address )
   O0O0oOOo0O . encap_port = iiIi1IIi1I . translated_port
   break
   if 83 - 83: OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
   if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
 if ( O0O0oOOo0O . outer_dest . is_null ( ) ) : return
 if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 O0O0oOOo0O . outer_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 O0O0oOOo0O . outer_version = O0O0oOOo0O . outer_dest . afi_to_version ( )
 O0O0oOOo0O . outer_ttl = 32
 O0O0oOOo0O . inner_source . copy_address ( lisp . lisp_myrlocs [ 0 ] )
 O0O0oOOo0O . inner_dest . store_address ( "[{}]224.0.0.1" . format ( geid . instance_id ) )
 O0O0oOOo0O . inner_ttl = 1
 if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
 o000O0o = lisp . green ( eid . print_address ( ) , False )
 OOOo = lisp . red ( "{}:{}" . format ( O0O0oOOo0O . outer_dest . print_address_no_iid ( ) ,
 O0O0oOOo0O . encap_port ) , False )
 oo0ooooo00o = lisp . bold ( "IGMP Query" , False )
 if 78 - 78: iIii1I11I1II1 . o0oOOo0O0Ooo % iIii1I11I1II1 . O0 / OOooOOo
 lisp . lprint ( "Data encapsulate {} to gleaned EID {}, RLOC {}" . format ( oo0ooooo00o , o000O0o , OOOo ) )
 if 76 - 76: i1IIi * OoooooooOO * O0 + I1Ii111 * I1Ii111
 if 35 - 35: o0oOOo0O0Ooo
 if 73 - 73: O0 - I1ii11iIi11i
 if 2 - 2: II111iiii / I1Ii111
 if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 if ( O0O0oOOo0O . encode ( None ) == None ) : return
 O0O0oOOo0O . print_packet ( "Send" , True )
 if 22 - 22: ooOoO0o . iIii1I11I1II1
 O0O0oOOo0O . send_packet ( lisp_raw_socket , O0O0oOOo0O . outer_dest )
 if 12 - 12: Ii1I
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
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
def IiIIiii1I ( lisp_raw_socket ) :
 if ( lisp . lisp_gleaned_groups == { } ) : return
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if 81 - 81: IiII / OoOoOO00 * IiII . O0
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
 if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
 II111 = "\x46\xc0\x00\x24\x00\x00\x40\x00\x01\x02\x00\x00"
 o0o0O0O000 = lisp . lisp_myrlocs [ 0 ]
 Oo0OoO00oOO0o = o0o0O0O000 . address
 II111 += chr ( ( Oo0OoO00oOO0o >> 24 ) & 0xff )
 II111 += chr ( ( Oo0OoO00oOO0o >> 16 ) & 0xff )
 II111 += chr ( ( Oo0OoO00oOO0o >> 8 ) & 0xff )
 II111 += chr ( Oo0OoO00oOO0o & 0xff )
 II111 += "\xe0\x00\x00\x01"
 II111 += "\x94\x04\x00\x00"
 II111 = lisp . lisp_ip_checksum ( II111 , 24 )
 if 24 - 24: ooOoO0o / iII111i + IiII . IiII
 if 39 - 39: ooOoO0o + O0 / i1IIi % IiII / oO0o * IiII
 if 77 - 77: IiII . I1Ii111 % OoOoOO00
 if 42 - 42: IiII % iII111i % o0oOOo0O0Ooo % oO0o + I11i % OoOoOO00
 if 3 - 3: oO0o
 iiii1I1 = "\x11\x64\x00\x00" + "\x00\x00\x00\x00" + "\x02\x3c\x00\x00"
 iiii1I1 = lisp . lisp_igmp_checksum ( iiii1I1 )
 if 64 - 64: OoO0O00 . I1IiiI - OoooooooOO . ooOoO0o - iII111i
 if 77 - 77: Ii1I % OoOoOO00 / II111iiii % iII111i % OoooooooOO % OoO0O00
 if 19 - 19: IiII * I1Ii111 / oO0o * I1Ii111 - OoooooooOO * I11i
 if 17 - 17: II111iiii + Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 o00oO0oo0OO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1OOO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 29 - 29: IiII . ooOoO0o - II111iiii
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  o00oO0oo0OO . store_address ( Ii1iIiII1ii1 )
  for ooooO0 in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   i1OOO . store_address ( ooooO0 )
   oO00oo0o00o0o , IiIIIIIi , Iiii111 = lisp . lisp_allow_gleaning ( o00oO0oo0OO , i1OOO , None )
   if ( Iiii111 == False ) : continue
   i11Ii1IIi ( lisp_raw_socket , o00oO0oo0OO , i1OOO , II111 + iiii1I1 )
   if 71 - 71: O0 / I1IiiI . I1Ii111 / I1Ii111 * ooOoO0o
   if 60 - 60: II111iiii . I1IiiI - Oo0Ooo + I1ii11iIi11i * I1ii11iIi11i
   if 27 - 27: IiII * I1IiiI . iIii1I11I1II1 - iIii1I11I1II1
   if 5 - 5: IiII
   if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
   if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
   if 71 - 71: I1Ii111 * Oo0Ooo . I11i
   if 49 - 49: IiII * O0 . IiII
   if 19 - 19: II111iiii - IiII
   if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
def o0OO00oo0O ( ) :
 o00oO0oo0OO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 i1OOO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 46 - 46: i11iIiiIii - OOooOOo * I1IiiI * I11i % I1ii11iIi11i * i1IIi
 Iii1I = [ ]
 for Ii1iIiII1ii1 in lisp . lisp_gleaned_groups :
  for ooooO0 in lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] :
   i1i1i1i1IiII1 = lisp . lisp_gleaned_groups [ Ii1iIiII1ii1 ] [ ooooO0 ]
   II1 = time . time ( ) - i1i1i1i1IiII1
   if ( II1 < lisp . LISP_IGMP_TIMEOUT_INTERVAL ) : continue
   Iii1I . append ( [ Ii1iIiII1ii1 , ooooO0 ] )
   if 52 - 52: OoOoOO00 * OoO0O00 - Ii1I
   if 82 - 82: OoO0O00 + I1IiiI . i1IIi + OOooOOo
   if 16 - 16: o0oOOo0O0Ooo - OoO0O00 / I1Ii111
   if 48 - 48: iIii1I11I1II1
   if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
   if 26 - 26: o0oOOo0O0Ooo
   if 12 - 12: OoooooooOO / O0 + II111iiii * I1ii11iIi11i
 Ii11ii1I1 = lisp . bold ( "timed out" , False )
 for Ii1iIiII1ii1 , ooooO0 in Iii1I :
  o00oO0oo0OO . store_address ( Ii1iIiII1ii1 )
  i1OOO . store_address ( ooooO0 )
  o000O0o = lisp . green ( Ii1iIiII1ii1 , False )
  Ii = lisp . green ( ooooO0 , False )
  lisp . lprint ( "{} RLE {} for gleaned group {}" . format ( o000O0o , Ii11ii1I1 , Ii ) )
  lisp . lisp_remove_gleaned_multicast ( o00oO0oo0OO , i1OOO )
  if 18 - 18: IiII % oO0o * OoOoOO00
  if 62 - 62: OOooOOo + Oo0Ooo % iIii1I11I1II1 / iIii1I11I1II1 . ooOoO0o . IiII
  if 21 - 21: OoO0O00 - Ii1I - I1IiiI / OoOoOO00
  if 48 - 48: OoooooooOO
  if 16 - 16: OoOoOO00 * I1ii11iIi11i * I1ii11iIi11i / O0 * i11iIiiIii
  if 64 - 64: iII111i * I1ii11iIi11i % II111iiii - OoOoOO00 + I1ii11iIi11i
  if 62 - 62: OoOoOO00 % o0oOOo0O0Ooo % I1IiiI + IiII . OoO0O00
  if 48 - 48: I1IiiI * i11iIiiIii % II111iiii
def ii1I ( lisp_raw_socket ) :
 lisp . lisp_set_exception ( )
 if 61 - 61: iIii1I11I1II1 - I11i / iII111i * I11i % Ii1I % iII111i
 if 63 - 63: OOooOOo % iIii1I11I1II1
 if 20 - 20: OoO0O00 . I1IiiI * i11iIiiIii / i11iIiiIii
 if 89 - 89: iII111i . i11iIiiIii * O0
 for oO0OOOO0 in list ( lisp . lisp_crypto_keys_by_nonce . values ( ) ) :
  for Iii in oO0OOOO0 : del ( Iii )
  if 35 - 35: IiII . OoooooooOO / OOooOOo
 lisp . lisp_crypto_keys_by_nonce . clear ( )
 lisp . lisp_crypto_keys_by_nonce = { }
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 lisp . lisp_rtr_nat_trace_cache . clear ( )
 lisp . lisp_rtr_nat_trace_cache = { }
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 o0OO00oo0O ( )
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 IiIIiii1I ( lisp_raw_socket )
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 oOOoo00O0O = threading . Timer ( 60 , ii1I ,
 [ lisp_raw_socket ] )
 oOOoo00O0O . start ( )
 return
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
def i111I11I ( ) :
 global Ii1iI , Oo0o , I1Ii11I1Ii1i
 global o0oOoO00o , i1 , O0ooo00OOo00
 global Oo , OOO0o0o
 global iIiiI1
 if 80 - 80: iIii1I11I1II1 - OoooooooOO - I1ii11iIi11i - I1ii11iIi11i . OoooooooOO
 lisp . lisp_i_am ( "rtr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "RTR starting up" )
 if 48 - 48: I1Ii111 . i11iIiiIii / i1IIi % IiII % iII111i + oO0o
 if 41 - 41: IiII
 if 3 - 3: IiII + II111iiii / iIii1I11I1II1
 if 10 - 10: II111iiii . O0
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 31 - 31: oO0o / i11iIiiIii / O0
 if 39 - 39: I1IiiI + Oo0Ooo
 if 83 - 83: i1IIi
 if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
 if 49 - 49: IiII / ooOoO0o / OOooOOo
 if 25 - 25: I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 iIiiI1 = lisp . lisp_myrlocs [ 0 ]
 if ( lisp . lisp_on_aws ( ) ) :
  O0oooOoO = lisp . bold ( "AWS RTR" , False )
  Oo0OoO00oOO0o = None
  for oo0 in [ "eth0" , "ens5" ] :
   Oo0OoO00oOO0o = lisp . lisp_get_interface_address ( oo0 )
   if ( Oo0OoO00oOO0o != None ) : break
   if 62 - 62: OOooOOo / II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
  if ( Oo0OoO00oOO0o != None ) :
   iIiiI1 = Oo0OoO00oOO0o
   iI1Iii = Oo0OoO00oOO0o . print_address_no_iid ( )
   lisp . lprint ( "{} using RLOC {} on {}" . format ( O0oooOoO , iI1Iii , oo0 ) )
  else :
   iI1Iii = iIiiI1 . print_address_no_iid ( )
   lisp . lprint ( "{} cannot obtain RLOC, using {}" . format ( O0oooOoO , iI1Iii ) )
   if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
   if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
   if 36 - 36: OOooOOo % i11iIiiIii
   if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
   if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
   if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
   if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
   if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 I1i1II1 = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 I1Ii11I1Ii1i = lisp . lisp_open_listen_socket ( I1i1II1 ,
 str ( Ooo ) )
 Ii1iI = lisp . lisp_open_listen_socket ( "" , "lisp-rtr" )
 Oo = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 if 89 - 89: OoO0O00 / OoO0O00
 Oo0o [ 0 ] = I1Ii11I1Ii1i
 if 1 - 1: I1ii11iIi11i . i11iIiiIii
 Oo0o [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 Oo0o [ 2 ] = Ii1iI
 if 74 - 74: O0 + OoooooooOO / oO0o / OoOoOO00 . I1ii11iIi11i % oO0o
 if 34 - 34: i1IIi . I1IiiI
 if 6 - 6: I1Ii111 % oO0o % Ii1I
 if 63 - 63: O0 . I1IiiI . O0 * iIii1I11I1II1
 if 92 - 92: oO0o / OOooOOo . I1ii11iIi11i
 if 30 - 30: Ii1I . I1ii11iIi11i / OOooOOo
 if 2 - 2: IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 o0oOoO00o = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 o0oOoO00o . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 Oo0o . append ( o0oOoO00o )
 if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
 OOO0o0o = lisp . lisp_open_listen_socket ( "0.0.0.0" ,
 str ( lisp . LISP_TRACE_PORT ) )
 if 12 - 12: I1ii11iIi11i / Ii1I
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  i1 = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 5 - 5: OoooooooOO
  if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
 Ii1I1 = os . getenv ( "LISP_PCAP_THREADS" )
 Ii1I1 = 1 if ( Ii1I1 == None ) else int ( Ii1I1 )
 O0oo00oOOO0o = os . getenv ( "LISP_WORKER_THREADS" )
 O0oo00oOOO0o = 0 if ( O0oo00oOOO0o == None ) else int ( O0oo00oOOO0o )
 if 5 - 5: o0oOOo0O0Ooo / I1IiiI % Ii1I . IiII
 if 86 - 86: i1IIi * OoOoOO00 . O0 - Ii1I - o0oOOo0O0Ooo - OoOoOO00
 if 47 - 47: OOooOOo + I11i
 if 50 - 50: I1Ii111 + I1ii11iIi11i
 for i1Ii in range ( Ii1I1 ) :
  OOOooOOOOOOOO = lisp . lisp_thread ( "pcap-{}" . format ( i1Ii ) )
  OOOooOOOOOOOO . thread_number = i1Ii
  OOOooOOOOOOOO . number_of_pcap_threads = Ii1I1
  OOOooOOOOOOOO . number_of_worker_threads = O0oo00oOOO0o
  O0ooo00OOo00 . append ( OOOooOOOOOOOO )
  threading . Thread ( target = ii , args = [ OOOooOOOOOOOO ] ) . start ( )
  if 81 - 81: OoooooooOO + i1IIi
  if 65 - 65: iII111i . oO0o - Ii1I
  if 93 - 93: O0
  if 4 - 4: I1IiiI / I1IiiI
  if 82 - 82: I11i / ooOoO0o * I11i % i11iIiiIii * II111iiii
  if 83 - 83: OoO0O00 + OOooOOo - o0oOOo0O0Ooo + iIii1I11I1II1 % Oo0Ooo
 for i1Ii in range ( O0oo00oOOO0o ) :
  OOOooOOOOOOOO = lisp . lisp_thread ( "worker-{}" . format ( i1Ii ) )
  O0ooo00OOo00 . append ( OOOooOOOOOOOO )
  threading . Thread ( target = I1III111i , args = [ OOOooOOOOOOOO ] ) . start ( )
  if 23 - 23: o0oOOo0O0Ooo + Ii1I % OoOoOO00 % I1IiiI % OoooooooOO
  if 78 - 78: OoO0O00 / Oo0Ooo - iIii1I11I1II1 - i11iIiiIii * iII111i
  if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
  if 33 - 33: Ii1I
  if 93 - 93: ooOoO0o
 lisp . lisp_load_checkpoint ( )
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 if 19 - 19: I1ii11iIi11i
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if 66 - 66: O0
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
 if 28 - 28: iIii1I11I1II1
 oOOoo00O0O = threading . Timer ( 60 , ii1I ,
 [ o0oOoO00o ] )
 oOOoo00O0O . start ( )
 return ( True )
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 if 46 - 46: OoOoOO00 - O0
 if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
 if 49 - 49: o0oOOo0O0Ooo
def I11 ( ) :
 if 18 - 18: iIii1I11I1II1
 if 30 - 30: O0 + OOooOOo % Oo0Ooo . i1IIi
 if 4 - 4: OOooOOo / iII111i * I11i - Oo0Ooo * I1IiiI
 if 6 - 6: Ii1I
 lisp . lisp_close_socket ( Oo0o [ 0 ] , "" )
 lisp . lisp_close_socket ( Oo0o [ 1 ] , "" )
 lisp . lisp_close_socket ( Ii1iI , "lisp-rtr" )
 lisp . lisp_close_socket ( I1Ii11I1Ii1i , "" )
 lisp . lisp_close_socket ( OOO0o0o , "" )
 lisp . lisp_close_socket ( Oo , "lispers.net-itr" )
 o0oOoO00o . close ( )
 return
 if 77 - 77: i1IIi + OoO0O00 . I1IiiI * OOooOOo / IiII / Ii1I
 if 84 - 84: OoO0O00 / iIii1I11I1II1
 if 33 - 33: i1IIi / I1Ii111 - i1IIi . Oo0Ooo
 if 18 - 18: Oo0Ooo / O0 + iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
def o0oO0o00O ( kv_pair ) :
 global Oo0o
 global Ooo
 if 6 - 6: OoooooooOO / i11iIiiIii / I1Ii111
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ Oo0o , Ooo ] )
  lisp . lisp_test_mr_timer . start ( )
  if 34 - 34: I1Ii111 - OOooOOo
 return
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if 64 - 64: i1IIi
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 if 25 - 25: II111iiii / OoO0O00
 if 64 - 64: O0 % ooOoO0o
 if 40 - 40: o0oOOo0O0Ooo + I11i
 if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
 if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
def iiI1 ( kv_pair ) :
 global I1Ii11I1Ii1i , o0oOoO00o , Ooo
 if 50 - 50: ooOoO0o * OoOoOO00 + I1ii11iIi11i - i11iIiiIii + Oo0Ooo * I1ii11iIi11i
 i11II = lisp . lisp_rloc_probing
 if 69 - 69: I1Ii111 - i1IIi % iII111i . OOooOOo - OOooOOo
 if 65 - 65: OOooOOo + II111iiii
 if 61 - 61: i11iIiiIii * oO0o % Oo0Ooo * I1Ii111 - OoooooooOO - OoO0O00
 if 83 - 83: ooOoO0o / OOooOOo
 lispconfig . lisp_xtr_command ( kv_pair )
 if 39 - 39: IiII + I11i
 if 9 - 9: I1IiiI % I11i . Oo0Ooo * I1IiiI
 if 99 - 99: O0 . o0oOOo0O0Ooo % I11i - Oo0Ooo / I11i
 if 20 - 20: OoOoOO00 * iII111i
 if 19 - 19: OoooooooOO
 if ( i11II == False and lisp . lisp_rloc_probing ) :
  o00O0OoO = [ I1Ii11I1Ii1i , I1Ii11I1Ii1i ,
 None , o0oOoO00o ]
  lisp . lisp_start_rloc_probe_timer ( 1 , o00O0OoO )
  oO0Oo = { "type" : "itr-crypto-port" , "port" : Ooo }
  lisp . lisp_write_to_dp_socket ( oO0Oo )
  if 76 - 76: OoO0O00 * oO0o
  if 63 - 63: II111iiii . II111iiii + I1ii11iIi11i + OOooOOo + O0 . Ii1I
  if 1 - 1: O0 * i11iIiiIii - ooOoO0o - Ii1I
  if 94 - 94: OoO0O00 + IiII + ooOoO0o
  if 82 - 82: Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + IiII % iIii1I11I1II1
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 61 - 61: OOooOOo / Oo0Ooo % OOooOOo - OoO0O00 + ooOoO0o / ooOoO0o
 if 82 - 82: Oo0Ooo
 if 5 - 5: OoO0O00 / OoO0O00 - O0 - I1Ii111 + I1Ii111
 if 99 - 99: I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - iIii1I11I1II1 - Ii1I
 if 31 - 31: IiII - OoO0O00 / OOooOOo . i1IIi / Ii1I
o0o000o = {
 "lisp xtr-parameters" : [ iiI1 , {
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

 "lisp map-resolver" : [ o0oO0o00O , {
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
if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
if 10 - 10: I1Ii111 * oO0o % Oo0Ooo - I11i % Oo0Ooo
if 65 - 65: iII111i * iIii1I11I1II1 / O0 . I11i
if 94 - 94: Oo0Ooo . ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo . iII111i
if 98 - 98: OOooOOo + Ii1I
if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
def iiI11Ii1i ( lisp_socket ) :
 if 100 - 100: iII111i + I11i + ooOoO0o + iII111i / i1IIi
 if 74 - 74: O0 % OoooooooOO * Oo0Ooo + OOooOOo * iII111i
 if 100 - 100: OOooOOo + Ii1I * o0oOOo0O0Ooo + II111iiii
 if 70 - 70: Oo0Ooo * iIii1I11I1II1
 O00Ooo0ooo0 , oOO0OooOo , i1I , O0O0oOOo0O = lisp . lisp_receive ( lisp_socket , False )
 oO00o0O00o = lisp . lisp_trace ( )
 if ( oO00o0O00o . decode ( O0O0oOOo0O ) == False ) : return
 if 98 - 98: ooOoO0o . OOooOOo
 if 60 - 60: OoO0O00 - i1IIi . OOooOOo + OOooOOo * OOooOOo + Ii1I
 if 66 - 66: OOooOOo * OOooOOo / iIii1I11I1II1 + OoOoOO00 . OOooOOo
 if 51 - 51: I1ii11iIi11i
 if 58 - 58: Ii1I % OoooooooOO
 oO00o0O00o . rtr_cache_nat_trace ( oOO0OooOo , i1I )
 if 49 - 49: I1ii11iIi11i + O0 . Ii1I * OoooooooOO
 if 82 - 82: I1ii11iIi11i
 if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
 if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
 if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
 if 21 - 21: iII111i
if ( i111I11I ( ) == False ) :
 lisp . lprint ( "lisp_rtr_startup() failed" )
 lisp . lisp_print_banner ( "RTR abnormal exit" )
 exit ( 1 )
 if 24 - 24: iII111i / ooOoO0o
 if 61 - 61: iIii1I11I1II1 + oO0o
i1IiiI = [ I1Ii11I1Ii1i , Ii1iI ,
 Oo , OOO0o0o ]
O0OOO0 = [ I1Ii11I1Ii1i ] * 3
if 61 - 61: ooOoO0o . i11iIiiIii + oO0o
while ( True ) :
 try : iIi , oo0ooO , oO00oo0o00o0o = select . select ( i1IiiI , [ ] , [ ] )
 except : break
 if 97 - 97: I1Ii111 . I11i / I1IiiI
 if 83 - 83: I11i - I1ii11iIi11i * oO0o
 if 90 - 90: Oo0Ooo * I1IiiI
 if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
 if ( lisp . lisp_ipc_data_plane and Oo in iIi ) :
  lisp . lisp_process_punt ( Oo , Oo0o ,
 Ooo )
  if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
  if 28 - 28: IiII * I1IiiI % IiII
  if 95 - 95: O0 / I11i . I1Ii111
  if 17 - 17: I11i
  if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if ( OOO0o0o in iIi ) :
  iiI11Ii1i ( OOO0o0o )
  if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
  if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
  if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
  if 38 - 38: I1Ii111
  if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 if ( I1Ii11I1Ii1i in iIi ) :
  O00Ooo0ooo0 , oOO0OooOo , i1I , O0O0oOOo0O = lisp . lisp_receive ( O0OOO0 [ 0 ] ,
 False )
  if ( oOO0OooOo == "" ) : break
  if ( lisp . lisp_is_rloc_probe_request ( O0O0oOOo0O [ 0 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
   continue
   if 22 - 22: oO0o * iII111i
  if ( lisp . lisp_is_rloc_probe_reply ( O0O0oOOo0O [ 0 ] ) ) :
   lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
   continue
   if 4 - 4: OoOoOO00 - oO0o + I1IiiI
  lisp . lisp_parse_packet ( O0OOO0 , O0O0oOOo0O , oOO0OooOo , i1I )
  if 36 - 36: IiII
  if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
  if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
  if 43 - 43: iIii1I11I1II1 % OoO0O00
  if 84 - 84: Oo0Ooo
  if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
 if ( Ii1iI in iIi ) :
  O00Ooo0ooo0 , oOO0OooOo , i1I , O0O0oOOo0O = lisp . lisp_receive ( Ii1iI , True )
  if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
  if ( oOO0OooOo == "" ) : break
  if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
  if ( O00Ooo0ooo0 == "command" ) :
   if ( O0O0oOOo0O == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
   if ( O0O0oOOo0O . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( O0O0oOOo0O )
    continue
    if 25 - 25: o0oOOo0O0Ooo
   lispconfig . lisp_process_command ( Ii1iI , O00Ooo0ooo0 ,
 O0O0oOOo0O , "lisp-rtr" , [ o0o000o ] )
  elif ( O00Ooo0ooo0 == "api" ) :
   lisp . lisp_process_api ( "lisp-rtr" , Ii1iI , O0O0oOOo0O )
  elif ( O00Ooo0ooo0 == "data-packet" ) :
   Ii1ii111i1 ( O0O0oOOo0O , "" )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( O0O0oOOo0O [ 0 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe request, using pcap" )
    continue
    if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
   if ( lisp . lisp_is_rloc_probe_reply ( O0O0oOOo0O [ 0 ] ) ) :
    lisp . lprint ( "RTR ignoring RLOC-probe reply, using pcap" )
    continue
    if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
   lisp . lisp_parse_packet ( Oo0o , O0O0oOOo0O , oOO0OooOo , i1I )
   if 41 - 41: i1IIi - I1IiiI
   if 48 - 48: I1IiiI - II111iiii / OoO0O00 + I1IiiI
   if 5 - 5: O0
   if 75 - 75: I1Ii111 + iIii1I11I1II1
I11 ( )
lisp . lisp_print_banner ( "RTR normal exit" )
exit ( 0 )
if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
