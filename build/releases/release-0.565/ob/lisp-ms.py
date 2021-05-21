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
# lisp-ms.py
#
# This file performs LISP Map-Server functionality.
#
# -----------------------------------------------------------------------------
from __future__ import division
from builtins import str
from builtins import range
from past . utils import old_div
import lisp
import lispconfig
import threading
import time
import os
import hmac
import hashlib
import copy
import sys
import datetime
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
i1I1ii1II1iII = None
oooO0oo0oOOOO = None
O0oO = None
o0oO0 = [ None , None , None ]
oo00 = { }
o00 = [ ]
Oo0oO0ooo = None
o0oOoO00o = None
if 43 - 43: Ii1I . oO0o
if 27 - 27: OoO0O00 - O0 . I1Ii111 * iII111i - I1ii11iIi11i
if 15 - 15: I1IiiI
if 90 - 90: IiII * i1IIi / Ii1I . OoO0O00 * oO0o
if 16 - 16: ooOoO0o * IiII % I11i . I1Ii111 / IiII % iII111i
I11 = os . getenv ( "LISP_MS_INJECT" )
Ii1iiii = 0 if I11 == None else int ( I11 )
if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
if 58 - 58: i11iIiiIii % I1Ii111
if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
if 13 - 13: OOooOOo * oO0o * I1IiiI
if 55 - 55: II111iiii
if 43 - 43: OoOoOO00 - i1IIi + I1Ii111 + Ii1I
def iII111ii ( kv_pairs ) :
 global oo00
 global o00
 if 3 - 3: iII111i + O0
 I1Ii = lisp . lisp_site ( )
 if 66 - 66: Ii1I
 oo0Ooo0 = [ ]
 if ( "address" in kv_pairs ) :
  if ( lispconfig . lisp_clause_syntax_error ( kv_pairs , "address" ,
 "allowed-rloc" ) ) : return
  for I1I11I1I1I in kv_pairs [ "address" ] :
   OooO0OO = lisp . lisp_rloc ( )
   oo0Ooo0 . append ( OooO0OO )
   if 28 - 28: II111iiii
   if 28 - 28: iIii1I11I1II1 - i1IIi
   if 70 - 70: OoO0O00 . OoO0O00 - OoO0O00 / I1ii11iIi11i * OOooOOo
 OoO000 = [ ]
 if ( lispconfig . lisp_clause_syntax_error ( kv_pairs , "eid-prefix" ,
 "allowed-prefix" ) ) : return
 for IIiiIiI1 in kv_pairs [ "eid-prefix" ] :
  iiIiIIi = lisp . lisp_site_eid ( I1Ii )
  OoO000 . append ( iiIiIIi )
  if 65 - 65: OoOoOO00
  if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
 for oo in list ( kv_pairs . keys ( ) ) :
  OO0O00 = kv_pairs [ oo ]
  if ( oo == "site-name" ) : I1Ii . site_name = OO0O00
  if ( oo == "description" ) : I1Ii . description = OO0O00
  if ( oo == "authentication-key" ) :
   I1Ii . auth_key = lisp . lisp_parse_auth_key ( OO0O00 )
   if 20 - 20: OoooooooOO
  if ( oo == "shutdown" ) :
   I1Ii . shutdown = True if OO0O00 == "yes" else False
   if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
   if 97 - 97: i11iIiiIii
  if ( oo == "instance-id" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    iiIiIIi = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    if ( iII11i == "*" ) :
     iiIiIIi . eid . store_iid_range ( 0 , 0 )
    else :
     if ( iII11i == "" ) : iII11i = "0"
     iiIiIIi . eid . instance_id = int ( iII11i )
     iiIiIIi . group . instance_id = int ( iII11i )
     if 97 - 97: I11i % I11i + II111iiii * iII111i
     if 54 - 54: I11i + IiII / iII111i
     if 9 - 9: OoOoOO00 / Oo0Ooo - IiII . i1IIi / I1IiiI % IiII
  if ( oo == "eid-prefix" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    iiIiIIi = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    if ( iII11i != "" ) : iiIiIIi . eid . store_prefix ( iII11i )
    if 71 - 71: I1Ii111 . O0
    if 73 - 73: OOooOOo % OoOoOO00 - Ii1I
  if ( oo == "group-prefix" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    iiIiIIi = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    if ( iII11i != "" ) : iiIiIIi . group . store_prefix ( iII11i )
    if 10 - 10: I1IiiI % I1ii11iIi11i
    if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
  if ( oo == "accept-more-specifics" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    iiIiIIi = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    i1iiI11I = True if ( iII11i == "yes" ) else False
    iiIiIIi . accept_more_specifics = i1iiI11I
    if 29 - 29: OoooooooOO
    if 23 - 23: o0oOOo0O0Ooo . II111iiii
  if ( oo == "force-proxy-reply" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    iiIiIIi = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    i1iiI11I = True if ( iII11i == "yes" ) else False
    iiIiIIi . force_proxy_reply = i1iiI11I
    if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
    if 45 - 45: I1Ii111 . OoOoOO00
  if ( oo == "force-ttl" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    iiIiIIi = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    if ( iII11i == "" ) : continue
    iiIiIIi . force_ttl = None if int ( iII11i ) == 0 else int ( iII11i )
    if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
    if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
  if ( oo == "echo-nonce-capable" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    iiIiIIi = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    i1iiI11I = True if ( iII11i == "yes" ) else False
    iiIiIIi . echo_nonce_capable = i1iiI11I
    if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
    if 8 - 8: OoOoOO00
  if ( oo == "force-nat-proxy-reply" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    iiIiIIi = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    i1iiI11I = True if ( iII11i == "yes" ) else False
    iiIiIIi . force_nat_proxy_reply = i1iiI11I
    if 60 - 60: I11i / I11i
    if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
  if ( oo == "pitr-proxy-reply-drop" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    iiIiIIi = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    i1iiI11I = True if ( iII11i == "yes" ) else False
    iiIiIIi . pitr_proxy_reply_drop = i1iiI11I
    if 83 - 83: OoooooooOO
    if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
  if ( oo == "proxy-reply-action" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    iiIiIIi = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    iiIiIIi . proxy_reply_action = iII11i
    if 4 - 4: II111iiii / ooOoO0o . iII111i
    if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
  if ( oo == "require-signature" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    iiIiIIi = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    i1iiI11I = True if ( iII11i == "yes" ) else False
    iiIiIIi . require_signature = i1iiI11I
    if 50 - 50: I1IiiI
    if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
  if ( oo == "encrypt-json" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    OooO0OO = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    i1iiI11I = True if ( iII11i == "yes" ) else False
    iiIiIIi . encrypt_json = i1iiI11I
    if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
    if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
  if ( oo == "policy-name" ) :
   for II1i1Ii11Ii11 in range ( len ( OoO000 ) ) :
    iiIiIIi = OoO000 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    iiIiIIi . policy = iII11i
    if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
    if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
    if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
  if ( oo == "address" ) :
   for II1i1Ii11Ii11 in range ( len ( oo0Ooo0 ) ) :
    OooO0OO = oo0Ooo0 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    if ( iII11i != "" ) : OooO0OO . rloc . store_address ( iII11i )
    if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
    if 58 - 58: i11iIiiIii % I11i
  if ( oo == "priority" ) :
   for II1i1Ii11Ii11 in range ( len ( oo0Ooo0 ) ) :
    OooO0OO = oo0Ooo0 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    if ( iII11i == "" ) : iII11i = "0"
    OooO0OO . priority = int ( iII11i )
    if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
    if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
  if ( oo == "weight" ) :
   for II1i1Ii11Ii11 in range ( len ( oo0Ooo0 ) ) :
    OooO0OO = oo0Ooo0 [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    if ( iII11i == "" ) : iII11i = "0"
    OooO0OO . weight = int ( iII11i )
    if 16 - 16: I1IiiI * oO0o % IiII
    if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
    if 44 - 44: oO0o
    if 88 - 88: I1Ii111 % Ii1I . II111iiii
    if 38 - 38: o0oOOo0O0Ooo
    if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
    if 26 - 26: iII111i
 if ( I1Ii . site_name in oo00 ) : return
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
 if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
 if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
 if 91 - 91: oO0o % Oo0Ooo
 if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
 oo00 [ I1Ii . site_name ] = I1Ii
 o00 = sorted ( oo00 )
 if 31 - 31: I11i - II111iiii . I11i
 for iiIiIIi in OoO000 :
  iiIiIIi . add_cache ( )
  i1I11i1I = iiIiIIi . build_sort_key ( )
  I1Ii . allowed_prefixes [ i1I11i1I ] = iiIiIIi
  if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1 * IiII * ooOoO0o % ooOoO0o
 for OooO0OO in oo0Ooo0 :
  i1I11i1I = OooO0OO . rloc . print_address ( )
  I1Ii . allowed_rlocs [ i1I11i1I ] = OooO0OO
  if 81 - 81: i11iIiiIii % OoOoOO00 - OOooOOo
  if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
  if 92 - 92: iII111i . I1Ii111
  if 31 - 31: I1Ii111 . OoOoOO00 / O0
  if 89 - 89: OoOoOO00
 I1Ii . allowed_prefixes_sorted = sorted ( I1Ii . allowed_prefixes )
 return
 if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
 if 4 - 4: ooOoO0o + O0 * OOooOOo
 if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
 if 25 - 25: I1ii11iIi11i
 if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
 if 13 - 13: OOooOOo / i11iIiiIii
 if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
def o0o00OO0 ( kv_pair ) :
 i1I1ii = lisp . lisp_ddt_entry ( )
 if 61 - 61: II111iiii
 for oo in list ( kv_pair . keys ( ) ) :
  OO0O00 = kv_pair [ oo ]
  if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
  if ( oo == "instance-id" ) :
   iII11i = OO0O00 . split ( "-" )
   if ( iII11i [ 0 ] == "" ) : continue
   if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
   iIIi1i1 = ( "eid-prefix" not in kv_pair or
 kv_pair [ "eid-prefix" ] == "" )
   i1IIIiiII1 = ( "group-prefix" not in kv_pair or
 kv_pair [ "group-prefix" ] == "" )
   if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
   if ( iIIi1i1 and i1IIIiiII1 ) :
    i1I1ii . eid . store_iid_range ( int ( iII11i [ 0 ] ) , int ( iII11i [ 1 ] ) )
   else :
    i1I1ii . eid . instance_id = int ( iII11i [ 0 ] )
    i1I1ii . group . instance_id = int ( iII11i [ 0 ] )
    if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
    if 83 - 83: I11i / I1IiiI
  if ( oo == "eid-prefix" ) :
   i1I1ii . eid . store_prefix ( OO0O00 )
   if 34 - 34: IiII
  if ( oo == "group-prefix" ) :
   i1I1ii . group . store_prefix ( OO0O00 )
   if 57 - 57: oO0o . I11i . i1IIi
   if 42 - 42: I11i + I1ii11iIi11i % O0
   if 6 - 6: oO0o
   if 68 - 68: OoOoOO00 - OoO0O00
   if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
   if 1 - 1: iIii1I11I1II1 / II111iiii
 i1I1ii . add_cache ( )
 return
 if 33 - 33: I11i
 if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
 if 87 - 87: i11iIiiIii
 if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
 if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
def III1IiiI ( kv_pair ) :
 iI = [ ]
 if ( lispconfig . lisp_clause_syntax_error ( kv_pair , "eid-prefix" ,
 "prefix" ) ) : return
 for II1i1Ii11Ii11 in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  i1I1ii = lisp . lisp_ddt_entry ( )
  iI . append ( i1I1ii )
  if 32 - 32: iII111i . IiII . IiII
  if 62 - 62: I1ii11iIi11i + IiII % iII111i + OOooOOo
 iii = [ ]
 if 90 - 90: o0oOOo0O0Ooo % i1IIi / OoO0O00
 if ( lispconfig . lisp_clause_syntax_error ( kv_pair , "address" ,
 "peer" ) ) : return
 for II1i1Ii11Ii11 in range ( len ( kv_pair [ "address" ] ) ) :
  IIi = lisp . lisp_ddt_node ( )
  IIi . map_server_peer = True
  iii . append ( IIi )
  if 41 - 41: Ii1I - O0 - O0
  if 68 - 68: OOooOOo % I1Ii111
 for oo in list ( kv_pair . keys ( ) ) :
  OO0O00 = kv_pair [ oo ]
  if ( oo == "instance-id" ) :
   for ooO00OO0 in range ( len ( iI ) ) :
    i1I1ii = iI [ ooO00OO0 ]
    iII11i = OO0O00 [ ooO00OO0 ] . split ( "-" )
    if ( iII11i [ 0 ] == "" ) : continue
    if 31 - 31: iII111i % iII111i % I11i
    iIIi1i1 = ( kv_pair [ "eid-prefix" ] [ ooO00OO0 ] == "" and
 kv_pair [ "group-prefix" ] [ ooO00OO0 ] == "" )
    if 69 - 69: OoO0O00 - Oo0Ooo + i1IIi / I1Ii111
    if ( iIIi1i1 ) :
     i1I1ii . eid . store_iid_range ( int ( iII11i [ 0 ] ) , int ( iII11i [ 1 ] ) )
    else :
     i1I1ii . eid . instance_id = int ( iII11i [ 0 ] )
     i1I1ii . group . instance_id = int ( iII11i [ 0 ] )
     if 49 - 49: O0 . iII111i
     if 11 - 11: IiII * I1IiiI . iIii1I11I1II1 % OoooooooOO + iII111i
     if 78 - 78: OoO0O00 . OOooOOo + OoO0O00 / I11i / OoO0O00
  if ( oo == "eid-prefix" ) :
   for ooO00OO0 in range ( len ( iI ) ) :
    i1I1ii = iI [ ooO00OO0 ]
    oO0O00OoOO0 = OO0O00 [ ooO00OO0 ]
    if ( oO0O00OoOO0 == "" ) : continue
    i1I1ii . eid . store_prefix ( oO0O00OoOO0 )
    if 82 - 82: II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
    if 77 - 77: iIii1I11I1II1 * OoO0O00
  if ( oo == "group-prefix" ) :
   for ooO00OO0 in range ( len ( iI ) ) :
    i1I1ii = iI [ ooO00OO0 ]
    oO0O00OoOO0 = OO0O00 [ ooO00OO0 ]
    if ( oO0O00OoOO0 == "" ) : continue
    i1I1ii . group . store_prefix ( oO0O00OoOO0 )
    if 95 - 95: I1IiiI + i11iIiiIii
    if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
    if 80 - 80: II111iiii
  if ( oo == "address" ) :
   for II1i1Ii11Ii11 in range ( len ( iii ) ) :
    IIi = iii [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    if ( iII11i != "" ) : IIi . delegate_address . store_address ( iII11i )
    if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
    if 53 - 53: II111iiii
  if ( oo == "priority" ) :
   for II1i1Ii11Ii11 in range ( len ( iii ) ) :
    IIi = iii [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    if ( iII11i == "" ) : iII11i = "0"
    IIi . priority = int ( iII11i )
    if 31 - 31: OoO0O00
    if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
  if ( oo == "weight" ) :
   for II1i1Ii11Ii11 in range ( len ( iii ) ) :
    IIi = iii [ II1i1Ii11Ii11 ]
    iII11i = OO0O00 [ II1i1Ii11Ii11 ]
    if ( iII11i == "" ) : iII11i = "0"
    IIi . weight = int ( iII11i )
    if 25 - 25: OoO0O00
    if 62 - 62: OOooOOo + O0
    if 98 - 98: o0oOOo0O0Ooo
    if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
    if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
    if 82 - 82: Ii1I
    if 46 - 46: OoooooooOO . i11iIiiIii
    if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 for i1I1ii in iI :
  i1I1ii . add_cache ( )
  for IIi in iii :
   i1I1ii . delegation_set . append ( IIi )
   if 87 - 87: Oo0Ooo . IiII
   if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
 return
 if 55 - 55: OOooOOo . I1IiiI
 if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
 if 100 - 100: I1Ii111 * O0
 if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
 if 79 - 79: O0
 if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
 if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
def oO0o0 ( kv_pair ) :
 iI1Ii11iIiI1 = lisp . lisp_address ( lisp . LISP_AFI_IPV6 , "" , 0 , 0 )
 if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
 for oo in list ( kv_pair . keys ( ) ) :
  OO0O00 = kv_pair [ oo ]
  if ( oo == "instance-id" ) :
   if ( OO0O00 == "*" ) : OO0O00 = "-1"
   iI1Ii11iIiI1 . instance_id = int ( OO0O00 )
   if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
  if ( oo == "eid-prefix" ) :
   iI1Ii11iIiI1 . store_prefix ( OO0O00 )
   if ( iI1Ii11iIiI1 . is_ipv6 ( ) == False ) : return
   if ( ( iI1Ii11iIiI1 . mask_len % 4 ) != 0 ) : return
   if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
   if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
   if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
   if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
   if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
   if 63 - 63: OoOoOO00 * iII111i
 lisp . lisp_eid_hashes . append ( iI1Ii11iIiI1 )
 return
 if 69 - 69: O0 . OoO0O00
 if 49 - 49: I1IiiI - I11i
 if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
 if 62 - 62: OoooooooOO * I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if 97 - 97: O0 + OoOoOO00
def OO0O000 ( kv_pair ) :
 for oo in list ( kv_pair . keys ( ) ) :
  OO0O00 = kv_pair [ oo ]
  if ( oo == "map-register-key" ) :
   lisp . lisp_ms_encryption_keys = lisp . lisp_parse_auth_key ( OO0O00 )
   if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
  if ( oo == "json-key" ) :
   lisp . lisp_ms_json_keys = lisp . lisp_parse_auth_key ( OO0O00 )
   if 77 - 77: OOooOOo * iIii1I11I1II1
   if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 return
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
 if 71 - 71: Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
 if 11 - 11: I1IiiI
def I1111i ( eid_key , group_key ) :
 if 14 - 14: OOooOOo / o0oOOo0O0Ooo
 IIiiIiI1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if ( eid_key ) :
  if ( eid_key == "[0]/0" ) :
   IIiiIiI1 . store_iid_range ( 0 , 0 )
  else :
   IIiiIiI1 . store_prefix ( eid_key )
   if 32 - 32: I1IiiI * Oo0Ooo
   if 78 - 78: OOooOOo - OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii
 iiI11ii1I1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if ( group_key ) : iiI11ii1I1 . store_prefix ( group_key )
 if 82 - 82: II111iiii % I11i / OoO0O00 + OoOoOO00 / o0oOOo0O0Ooo / I1Ii111
 oOo0OOoO0 = lisp . lisp_print_eid_tuple ( IIiiIiI1 , iiI11ii1I1 )
 oOo0OOoO0 = lisp . lisp_print_cour ( oOo0OOoO0 )
 if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 iiIiIIi = lisp . lisp_site_eid_lookup ( IIiiIiI1 , iiI11ii1I1 , True )
 if ( iiIiIIi == None ) :
  i1I1i111Ii = "Could not find EID {} in site cache" . format ( oOo0OOoO0 )
  return ( i1I1i111Ii )
  if 67 - 67: I1IiiI . i1IIi
  if 27 - 27: ooOoO0o % I1IiiI
 o0oooOO00 = lisp . space ( 4 )
 iiIiii1IIIII = lisp . space ( 8 )
 o00o = lisp . space ( 12 )
 if 45 - 45: I1ii11iIi11i . o0oOOo0O0Ooo . I1ii11iIi11i - I1IiiI . o0oOOo0O0Ooo
 iiI1IIIi = lisp . green ( "yes" , True ) if iiIiIIi . registered else lisp . red ( "no" , True )
 if 47 - 47: Oo0Ooo % I11i % i11iIiiIii - O0 + ooOoO0o
 if 94 - 94: I1Ii111
 i1I1i111Ii = '<font face="Sans-Serif">'
 if 4 - 4: Ii1I % oO0o * OoO0O00
 o0O0OOOOoOO0 = lisp . lisp_print_cour ( iiIiIIi . site . site_name )
 ii = lisp . lisp_print_cour ( str ( iiIiIIi . site_id ) )
 O0oOo00o = "0" if iiIiIIi . xtr_id == 0 else lisp . lisp_hex_string ( iiIiIIi . xtr_id )
 O0oOo00o = lisp . lisp_print_cour ( "0x" + O0oOo00o )
 o0ooooO0o0O = lisp . lisp_print_elapsed ( iiIiIIi . first_registered )
 iiIi11iI1iii = lisp . lisp_print_elapsed ( iiIiIIi . last_registered )
 if ( time . time ( ) - iiIiIIi . last_registered >=
 ( old_div ( iiIiIIi . register_ttl , 2 ) ) and iiIi11iI1iii != "never" ) :
  iiIi11iI1iii = lisp . red ( iiIi11iI1iii , True )
  if 67 - 67: O0 / I1Ii111
 if ( iiIiIIi . last_registerer . afi == lisp . LISP_AFI_NONE ) :
  OOO0000oO = "none"
 else :
  OOO0000oO = iiIiIIi . last_registerer . print_address_no_iid ( )
  if 15 - 15: OoOoOO00 % I1IiiI * I11i
 OOO0000oO = lisp . lisp_print_cour ( OOO0000oO )
 O0OoooO0 = ", " + lisp . lisp_print_cour ( "site is in admin-shutdown" ) if iiIiIIi . site . shutdown else ""
 if 85 - 85: I11i
 iI1i11II1i = ", accepting more specifics" if iiIiIIi . accept_more_specifics else ""
 if 96 - 96: I1Ii111
 if ( iI1i11II1i == "" and iiIiIIi . dynamic ) : iI1i11II1i = ", dynamic"
 i1I1i111Ii += '''Site name: {}, EID-prefix: {}, registered: {}{}{}
        <br>''' . format ( o0O0OOOOoOO0 , oOo0OOoO0 , iiI1IIIi , iI1i11II1i , O0OoooO0 )
 if 97 - 97: ooOoO0o
 i1I1i111Ii += "{}Description: {}<br>" . format ( o0oooOO00 ,
 lisp . lisp_print_cour ( iiIiIIi . site . description ) )
 i1I1i111Ii += "{}Last registerer: {}, xTR-ID: {}, site-ID: {}<br>" . format ( o0oooOO00 , OOO0000oO , O0oOo00o , ii )
 if 48 - 48: i1IIi - I1Ii111
 if 56 - 56: o0oOOo0O0Ooo + II111iiii + OoOoOO00 - ooOoO0o . OoOoOO00
 OOOooo = iiIiIIi . print_flags ( False )
 OOOooo = lisp . lisp_print_cour ( OOOooo )
 OooO0OOo0OOo0o0O0O = "none"
 if ( iiIiIIi . registered ) :
  OooO0OOo0OOo0o0O0O = "sha1" if ( iiIiIIi . auth_sha1_or_sha2 ) else "sha2"
  if 65 - 65: i11iIiiIii
 i1I1i111Ii += ( "{}First registered: {}, last registered: {}, auth-type: " + "{}, registration flags: {}<br>" ) . format ( o0oooOO00 ,
 # OOooOOo * OoO0O00 % i1IIi * i11iIiiIii % Oo0Ooo - oO0o
 lisp . lisp_print_cour ( o0ooooO0o0O ) , lisp . lisp_print_cour ( iiIi11iI1iii ) ,
 lisp . lisp_print_cour ( OooO0OOo0OOo0o0O0O ) , OOOooo )
 if 67 - 67: OoOoOO00 + I1ii11iIi11i . o0oOOo0O0Ooo . II111iiii
 o000ooooO0o = lisp . lisp_print_cour ( str ( iiIiIIi . register_ttl ) + " seconds" )
 i1I1i111Ii += "{}{} registration timeout TTL: {}<br>" . format ( o0oooOO00 , "Registered" if iiIiIIi . use_register_ttl_requested else "Default" , o000ooooO0o )
 if 40 - 40: I1ii11iIi11i + i1IIi * OOooOOo
 if 85 - 85: Ii1I * Oo0Ooo . O0 - i11iIiiIii
 if 18 - 18: Ii1I + IiII - O0
 if 53 - 53: i1IIi
 if 87 - 87: i11iIiiIii + I1Ii111 . I1ii11iIi11i * I1Ii111 . ooOoO0o / I1ii11iIi11i
 if 76 - 76: O0 + i1IIi . Oo0Ooo * I1IiiI * Ii1I
 if ( iiIiIIi . policy ) :
  II1iI1I11I = lisp . lisp_print_cour ( iiIiIIi . policy )
  i1I1i111Ii += "{}Apply policy: '{}'<br>" . format ( o0oooOO00 , II1iI1I11I )
  if 78 - 78: II111iiii
  if 100 - 100: I1Ii111 + OOooOOo + OOooOOo
  if 9 - 9: I11i % OoooooooOO . oO0o % I11i
  if 32 - 32: i11iIiiIii
  if 31 - 31: iIii1I11I1II1 / OoO0O00 / I1ii11iIi11i
 iiI1IIIi = "yes" if iiIiIIi . force_proxy_reply else "no"
 iiI1IIIi = lisp . lisp_print_cour ( iiI1IIIi )
 i1I1i111Ii += "{}Forcing proxy Map-Reply: {}<br>" . format ( o0oooOO00 , iiI1IIIi )
 if 41 - 41: Oo0Ooo
 if ( iiIiIIi . force_ttl != None ) :
  o000ooooO0o = lisp . lisp_print_cour ( str ( iiIiIIi . force_ttl ) + " seconds" )
  i1I1i111Ii += "{}Forced proxy Map-Reply TTL: {}<br>" . format ( o0oooOO00 , o000ooooO0o )
  if 10 - 10: Oo0Ooo / Oo0Ooo / I1Ii111 . I1Ii111
  if 98 - 98: Oo0Ooo / I1IiiI . O0 + OoO0O00
  if 43 - 43: II111iiii . oO0o / I1ii11iIi11i
 iiI1IIIi = "yes" if iiIiIIi . force_nat_proxy_reply else "no"
 iiI1IIIi = lisp . lisp_print_cour ( iiI1IIIi )
 i1I1i111Ii += "{}Forcing proxy Map-Reply for xTRs behind NATs: {}<br>" . format ( o0oooOO00 , iiI1IIIi )
 if 20 - 20: I1IiiI
 if 95 - 95: iII111i - I1IiiI
 iiI1IIIi = "yes" if iiIiIIi . pitr_proxy_reply_drop else "no"
 iiI1IIIi = lisp . lisp_print_cour ( iiI1IIIi )
 i1I1i111Ii += "{}Send drop-action proxy Map-Reply to PITR: {}<br>" . format ( o0oooOO00 , iiI1IIIi )
 if 34 - 34: ooOoO0o * I1IiiI . i1IIi * ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 O0O0Oo00 = "not configured" if iiIiIIi . proxy_reply_action == "" else iiIiIIi . proxy_reply_action
 if 80 - 80: oO0o + OOooOOo / I11i
 O0O0Oo00 = lisp . lisp_print_cour ( O0O0Oo00 )
 i1I1i111Ii += "{}Proxy Map-Reply action: {}<br>" . format ( o0oooOO00 , O0O0Oo00 )
 if 79 - 79: ooOoO0o
 if ( iiIiIIi . force_proxy_reply and iiIiIIi . echo_nonce_capable ) :
  i11I1I1I = lisp . lisp_print_cour ( "yes" )
  i1I1i111Ii += "{}RLOCs are echo-nonce capable: {}<br>" . format ( o0oooOO00 , i11I1I1I )
  if 64 - 64: Ii1I
  if 66 - 66: i11iIiiIii - OOooOOo * Oo0Ooo
 iiI1IIIi = "yes" if iiIiIIi . require_signature else "no"
 iiI1IIIi = lisp . lisp_print_cour ( iiI1IIIi )
 i1I1i111Ii += "{}Require signatures: {}<br>" . format ( o0oooOO00 , iiI1IIIi )
 if 76 - 76: i11iIiiIii + o0oOOo0O0Ooo / I1ii11iIi11i - OoO0O00 - Ii1I + I1ii11iIi11i
 iiI1IIIi = "yes" if iiIiIIi . encrypt_json else "no"
 iiI1IIIi = lisp . lisp_print_cour ( iiI1IIIi )
 i1I1i111Ii += "{}Encrypt JSON RLOC-records: {}<br>" . format ( o0oooOO00 , iiI1IIIi )
 if 51 - 51: iIii1I11I1II1 . ooOoO0o + iIii1I11I1II1
 if 95 - 95: I1IiiI
 if 46 - 46: OoOoOO00 + OoO0O00
 if 70 - 70: iII111i / iIii1I11I1II1
 Oo0oooO0oO = "any" if len ( iiIiIIi . site . allowed_rlocs ) == 0 else ""
 if ( Oo0oooO0oO != "" ) : Oo0oooO0oO = lisp . lisp_print_cour ( Oo0oooO0oO )
 i1I1i111Ii += "{}Allowed RLOC-set: {}<br>" . format ( o0oooOO00 , Oo0oooO0oO )
 if ( Oo0oooO0oO == "" ) :
  for OooO0OO in list ( iiIiIIi . site . allowed_rlocs . values ( ) ) :
   IiIiII1 = lisp . lisp_print_cour ( OooO0OO . rloc . print_address ( ) )
   Iii1iiIi1II = lisp . lisp_print_cour ( OooO0OO . print_state ( ) )
   OO0O00oOo = lisp . lisp_print_cour ( str ( OooO0OO . priority ) )
   ii1II = lisp . lisp_print_cour ( str ( OooO0OO . weight ) )
   iI1I = lisp . lisp_print_cour ( str ( OooO0OO . mpriority ) )
   OooOoOo = lisp . lisp_print_cour ( str ( OooO0OO . mweight ) )
   III1I1Iii1iiI = OooO0OO . print_rloc_name ( True )
   if ( III1I1Iii1iiI != "" ) : III1I1Iii1iiI = ", " + III1I1Iii1iiI
   if 17 - 17: Ii1I % iIii1I11I1II1 - iIii1I11I1II1
   i1I1i111Ii += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>''' . format ( iiIiii1IIIII , IiIiII1 , Iii1iiIi1II , OO0O00oOo , ii1II , iI1I , OooOoOo , III1I1Iii1iiI )
   if 78 - 78: iII111i + I11i . ooOoO0o - iII111i . Ii1I
   if 30 - 30: I1IiiI + OoO0O00 % Ii1I * iII111i / Oo0Ooo - I11i
   if 64 - 64: iIii1I11I1II1
   if 21 - 21: Oo0Ooo . II111iiii
 ooo000o000 = "none" if len ( iiIiIIi . registered_rlocs ) == 0 else ""
 if ( ooo000o000 != "" ) : ooo000o000 = lisp . lisp_print_cour ( ooo000o000 )
 i1I1i111Ii += "<br>Registered RLOC-set ({}): {}<br>" . format ( "merge-semantics" if ( iiIiIIi . merge_register_requested ) else "replacement-semantics" ,
 # iIii1I11I1II1 * i1IIi * iII111i % OOooOOo % I1ii11iIi11i + II111iiii
 ooo000o000 )
 if ( ooo000o000 == "" ) :
  for OooO0OO in iiIiIIi . registered_rlocs :
   IiIiII1 = lisp . lisp_print_cour ( OooO0OO . rloc . print_address ( ) )
   Iii1iiIi1II = lisp . lisp_print_cour ( OooO0OO . print_state ( ) )
   OO0O00oOo = lisp . lisp_print_cour ( str ( OooO0OO . priority ) )
   ii1II = lisp . lisp_print_cour ( str ( OooO0OO . weight ) )
   iI1I = lisp . lisp_print_cour ( str ( OooO0OO . mpriority ) )
   OooOoOo = lisp . lisp_print_cour ( str ( OooO0OO . mweight ) )
   III1I1Iii1iiI = OooO0OO . print_rloc_name ( True )
   if ( III1I1Iii1iiI != "" ) : III1I1Iii1iiI = ", " + III1I1Iii1iiI
   if 42 - 42: IiII - o0oOOo0O0Ooo . II111iiii
   i1I1i111Ii += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>''' . format ( o0oooOO00 , IiIiII1 , Iii1iiIi1II , OO0O00oOo , ii1II , iI1I , OooOoOo , III1I1Iii1iiI )
   if 94 - 94: I1IiiI * Ii1I . I11i
   if ( OooO0OO . geo ) :
    oOoOoOoo0 = lisp . lisp_print_cour ( OooO0OO . geo . print_geo_url ( ) )
    i1I1i111Ii += "{}geo: {}<br>" . format ( o00o , oOoOoOoo0 )
    if 34 - 34: OoOoOO00 - OOooOOo + O0 . Ii1I
   if ( OooO0OO . elp ) :
    iIi1i1iIi1iI = lisp . lisp_print_cour ( OooO0OO . elp . print_elp ( False ) )
    i1I1i111Ii += "{}elp: {}<br>" . format ( o00o , iIi1i1iIi1iI )
    if 26 - 26: OoooooooOO * I1IiiI + OOooOOo
   if ( OooO0OO . rle ) :
    IiIii1i111 = lisp . lisp_print_cour ( OooO0OO . rle . print_rle ( True , True ) )
    i1I1i111Ii += "{}rle: {}<br>" . format ( o00o , IiIii1i111 )
    if 43 - 43: O0
   if ( OooO0OO . json ) :
    Ii1 = lisp . lisp_print_cour ( OooO0OO . json . print_json ( True ) )
    i1I1i111Ii += "{}json: {}<br>" . format ( o00o , Ii1 )
    if 14 - 14: iIii1I11I1II1 % iIii1I11I1II1 * i11iIiiIii - OoO0O00 - I11i
    if 63 - 63: OoO0O00
    if 69 - 69: iIii1I11I1II1 . I1ii11iIi11i % ooOoO0o + iIii1I11I1II1 / O0 / I1ii11iIi11i
    if 61 - 61: OOooOOo % OOooOOo * o0oOOo0O0Ooo / o0oOOo0O0Ooo
 ooo000o000 = "none" if len ( iiIiIIi . individual_registrations ) == 0 else ""
 if ( ooo000o000 == "none" ) :
  ooo000o000 = lisp . lisp_print_cour ( ooo000o000 )
 elif ( iiIiIIi . inconsistent_registration ) :
  ooo000o000 = lisp . red ( "inconsistent registrations" , True )
  ooo000o000 = lisp . lisp_print_cour ( ooo000o000 )
  if 75 - 75: IiII . ooOoO0o
 i1I1i111Ii += "<br>Individual registrations: {}<br>" . format ( ooo000o000 )
 if 50 - 50: OoOoOO00
 if 60 - 60: ooOoO0o * iIii1I11I1II1 * I1ii11iIi11i * Oo0Ooo
 if 69 - 69: Ii1I * O0 . i11iIiiIii / Ii1I . o0oOOo0O0Ooo
 if 63 - 63: I11i + o0oOOo0O0Ooo . II111iiii - I1IiiI
 if 52 - 52: o0oOOo0O0Ooo % Oo0Ooo
 Oo000ooOOO = [ ]
 for Ii11i1I11i in list ( iiIiIIi . individual_registrations . values ( ) ) :
  if ( Ii11i1I11i . registered == False ) : continue
  o000ooooO0o = old_div ( Ii11i1I11i . register_ttl , 2 )
  if ( time . time ( ) - Ii11i1I11i . last_registered >= o000ooooO0o ) : continue
  Oo000ooOOO . append ( Ii11i1I11i )
  if 13 - 13: IiII / i11iIiiIii % II111iiii % I11i . I1ii11iIi11i
 for Ii11i1I11i in list ( iiIiIIi . individual_registrations . values ( ) ) :
  if ( Ii11i1I11i . registered == False ) : continue
  o000ooooO0o = old_div ( Ii11i1I11i . register_ttl , 2 )
  if ( time . time ( ) - Ii11i1I11i . last_registered >= o000ooooO0o ) : Oo000ooOOO . append ( Ii11i1I11i )
  if 8 - 8: OoOoOO00 + Oo0Ooo - II111iiii
 for Ii11i1I11i in list ( iiIiIIi . individual_registrations . values ( ) ) :
  if ( Ii11i1I11i . registered == False ) : Oo000ooOOO . append ( Ii11i1I11i )
  if 11 - 11: i1IIi % i11iIiiIii - i1IIi * OoOoOO00
  if 39 - 39: I1Ii111
 for iiIiIIi in Oo000ooOOO :
  iiI1IIIi = lisp . green ( "yes" , True ) if iiIiIIi . registered else lisp . red ( "no" , True )
  if 86 - 86: I11i * I1IiiI + I11i + II111iiii
  OooO0OOo0OOo0o0O0O = "sha1" if ( iiIiIIi . auth_sha1_or_sha2 ) else "sha2"
  OooO0OOo0OOo0o0O0O = lisp . lisp_print_cour ( OooO0OOo0OOo0o0O0O )
  o000ooooO0o = str ( old_div ( iiIiIIi . register_ttl , 60 ) ) + " mins"
  o000ooooO0o = lisp . lisp_print_cour ( o000ooooO0o )
  OOOooo = iiIiIIi . print_flags ( False )
  OOOooo = lisp . lisp_print_cour ( OOOooo )
  IiIiII1 = lisp . lisp_print_cour ( iiIiIIi . last_registerer . print_address_no_iid ( ) )
  if 8 - 8: I1Ii111 - iII111i / ooOoO0o
  o0ooooO0o0O = lisp . lisp_print_elapsed ( iiIiIIi . first_registered )
  o0ooooO0o0O = lisp . lisp_print_cour ( o0ooooO0o0O )
  iiIi11iI1iii = lisp . lisp_print_elapsed ( iiIiIIi . last_registered )
  if ( time . time ( ) - iiIiIIi . last_registered >=
 ( old_div ( iiIiIIi . register_ttl , 2 ) ) and iiIi11iI1iii != "never" ) :
   iiIi11iI1iii = lisp . red ( iiIi11iI1iii , True )
   if 96 - 96: OoOoOO00
  iiIi11iI1iii = lisp . lisp_print_cour ( iiIi11iI1iii )
  ii = lisp . lisp_print_cour ( str ( iiIiIIi . site_id ) )
  O0oOo00o = lisp . lisp_print_cour ( lisp . lisp_hex_string ( iiIiIIi . xtr_id ) )
  if 29 - 29: I1ii11iIi11i / i1IIi . I1IiiI - OoOoOO00 - OoOoOO00 - Ii1I
  i1I1i111Ii += '''
            {}Registerer: {}, xTR-ID: 0x{}, site-id: {}, registered: {}<br>
            {}First registered: {}, last registered: {}, registration TTL: {},
            auth-type: {}, registration flags: {}<br>
        ''' . format ( o0oooOO00 , IiIiII1 , O0oOo00o , ii , iiI1IIIi , o0oooOO00 , o0ooooO0o0O , iiIi11iI1iii , o000ooooO0o , OooO0OOo0OOo0o0O0O ,
 OOOooo )
  if 20 - 20: i1IIi % OoO0O00 . I1IiiI / IiII * i11iIiiIii * OOooOOo
  ooo000o000 = "none" if len ( iiIiIIi . registered_rlocs ) == 0 else ""
  ooo000o000 = lisp . lisp_print_cour ( ooo000o000 )
  i1I1i111Ii += "{}Registered RLOC-set: {}<br>" . format ( o0oooOO00 , ooo000o000 )
  if 85 - 85: o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . O0 % I1Ii111
  for OooO0OO in iiIiIIi . registered_rlocs :
   IiIiII1 = lisp . lisp_print_cour ( OooO0OO . rloc . print_address ( ) )
   Iii1iiIi1II = lisp . lisp_print_cour ( OooO0OO . print_state ( ) )
   OO0O00oOo = lisp . lisp_print_cour ( str ( OooO0OO . priority ) )
   ii1II = lisp . lisp_print_cour ( str ( OooO0OO . weight ) )
   iI1I = lisp . lisp_print_cour ( str ( OooO0OO . mpriority ) )
   OooOoOo = lisp . lisp_print_cour ( str ( OooO0OO . mweight ) )
   III1I1Iii1iiI = OooO0OO . print_rloc_name ( True )
   if ( III1I1Iii1iiI != "" ) : III1I1Iii1iiI = ", " + III1I1Iii1iiI
   if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
   i1I1i111Ii += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>''' . format ( iiIiii1IIIII , IiIiII1 , Iii1iiIi1II , OO0O00oOo , ii1II , iI1I , OooOoOo , III1I1Iii1iiI )
   if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
   if ( OooO0OO . geo ) :
    oOoOoOoo0 = lisp . lisp_print_cour ( OooO0OO . geo . print_geo_url ( ) )
    i1I1i111Ii += "{}geo: {}<br>" . format ( o00o , oOoOoOoo0 )
    if 74 - 74: O0 / i1IIi
   if ( OooO0OO . elp ) :
    iIi1i1iIi1iI = lisp . lisp_print_cour ( OooO0OO . elp . print_elp ( False ) )
    i1I1i111Ii += "{}elp: {}<br>" . format ( o00o , iIi1i1iIi1iI )
    if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
   if ( OooO0OO . rle ) :
    IiIii1i111 = lisp . lisp_print_cour ( OooO0OO . rle . print_rle ( True , True ) )
    i1I1i111Ii += "{}rle: {}<br>" . format ( o00o , IiIii1i111 )
    if 31 - 31: OoooooooOO . OOooOOo
   if ( OooO0OO . json ) :
    Ii1 = lisp . lisp_print_cour ( OooO0OO . json . print_json ( True ) )
    i1I1i111Ii += "{}json: {}<br>" . format ( o00o , Ii1 )
    if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
    if 100 - 100: OoO0O00
  i1I1i111Ii += "<br>"
  if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 i1I1i111Ii += "</font>"
 return ( i1I1i111Ii )
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
 if 7 - 7: OoooooooOO . IiII
 if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
def Oooo00 ( ddt_entry , output ) :
 I111iIi1 = ddt_entry . print_eid_tuple ( )
 oo00O00oO000o = ddt_entry . map_referrals_sent
 if 71 - 71: I1ii11iIi11i - ooOoO0o / OoOoOO00 * OoOoOO00 / i1IIi . i1IIi
 if ( ddt_entry . is_auth_prefix ( ) ) :
  output += lispconfig . lisp_table_row ( I111iIi1 , "--" , "auth-prefix" , "--" ,
 oo00O00oO000o )
  return ( [ True , output ] )
  if 53 - 53: I1Ii111
  if 21 - 21: I11i
 for OoO00 in ddt_entry . delegation_set :
  I1I11I1I1I = OoO00 . delegate_address
  OO0Ooooo000Oo = str ( OoO00 . priority ) + "/" + str ( OoO00 . weight )
  output += lispconfig . lisp_table_row ( I111iIi1 , I1I11I1I1I . print_address ( ) ,
 OoO00 . print_node_type ( ) , OO0Ooooo000Oo , oo00O00oO000o )
  if ( I111iIi1 != "" ) :
   I111iIi1 = ""
   oo00O00oO000o = ""
   if 97 - 97: Ii1I * I1ii11iIi11i / I1IiiI / iIii1I11I1II1 % I11i
   if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 return ( [ True , output ] )
 if 75 - 75: OoooooooOO * IiII
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
def oooO0 ( ddt_entry , output ) :
 if 16 - 16: II111iiii + oO0o - OoooooooOO
 if 3 - 3: O0 / iII111i
 if 31 - 31: OOooOOo + o0oOOo0O0Ooo . OoooooooOO
 if 89 - 89: II111iiii + i1IIi + II111iiii
 if ( ddt_entry . group . is_null ( ) ) :
  return ( Oooo00 ( ddt_entry , output ) )
  if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
  if 42 - 42: OoOoOO00 * OoOoOO00 * I1Ii111 . I11i
 if ( ddt_entry . source_cache == None ) : return ( [ True , output ] )
 if 51 - 51: OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o * iIii1I11I1II1 % OoO0O00
 if 99 - 99: oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 output = ddt_entry . source_cache . walk_cache ( Oooo00 ,
 output )
 return ( [ True , output ] )
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
def IiI11i1IIiiI ( ) :
 oOOo000oOoO0 = "{} entries configured" . format ( lisp . lisp_ddt_cache . cache_size ( ) )
 OoOo00o0OO = lisp . lisp_span ( "LISP-MS Configured Map-Server Peers & " + "Authoritative Prefixes:" , oOOo000oOoO0 )
 if 1 - 1: I1IiiI % ooOoO0o
 i1I1i111Ii = lispconfig . lisp_table_header ( OoOo00o0OO , "EID-Prefix or (S,G)" ,
 "Peer Address" , "Delegation Type" , "Priority/Weight" ,
 "Map-Referrals Sent" )
 if 65 - 65: I1IiiI + OoOoOO00 / OOooOOo
 i1I1i111Ii = lisp . lisp_ddt_cache . walk_cache ( oooO0 , i1I1i111Ii )
 i1I1i111Ii += lispconfig . lisp_table_footer ( )
 return ( i1I1i111Ii )
 if 83 - 83: o0oOOo0O0Ooo . iII111i - Oo0Ooo
 if 65 - 65: iIii1I11I1II1 / ooOoO0o . IiII - II111iiii
 if 72 - 72: iIii1I11I1II1 / IiII % iII111i % OOooOOo - I11i % OOooOOo
 if 100 - 100: Oo0Ooo + i11iIiiIii
 if 71 - 71: I11i / o0oOOo0O0Ooo / I1Ii111 % OOooOOo
 if 51 - 51: IiII * O0 / II111iiii . Ii1I % OOooOOo / I1IiiI
 if 9 - 9: I1IiiI % I1IiiI % II111iiii
 if 30 - 30: IiII + I1Ii111 - IiII . IiII - II111iiii + O0
def oOO0 ( input_str ) :
 IIiiIiI1 , i1IIiIii1i , iiI11ii1I1 , ooOOO0OooOo = lispconfig . lisp_get_lookup_string ( input_str )
 if 33 - 33: OOooOOo / i1IIi - I1IiiI % Oo0Ooo . I1ii11iIi11i
 if 17 - 17: II111iiii / I1ii11iIi11i % IiII + I1IiiI * I1Ii111
 i1I1i111Ii = "<br>"
 if 36 - 36: I1Ii111 * OoO0O00
 if 23 - 23: I11i . OoooooooOO - OOooOOo + IiII . II111iiii
 if 54 - 54: ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 iiIiIIi = lisp . lisp_site_eid_lookup ( IIiiIiI1 , iiI11ii1I1 , i1IIiIii1i )
 if ( iiIiIIi and iiIiIIi . is_star_g ( ) == False ) :
  oOo0OOoO0 = iiIiIIi . print_eid_tuple ( )
  OOOoO = lisp . green ( "registered" , True ) if iiIiIIi . registered else lisp . red ( "not registered" , True )
  if 14 - 14: I11i . iIii1I11I1II1 . OoooooooOO . II111iiii / o0oOOo0O0Ooo
  i1I1i111Ii += "{} '{}' {} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Site" ) ,
  # II111iiii % i11iIiiIii
 lisp . lisp_print_cour ( iiIiIIi . site . site_name ) ,
 lisp . lisp_print_sans ( "entry" ) ,
 lisp . lisp_print_cour ( oOo0OOoO0 ) ,
 lisp . lisp_print_sans ( "found for EID" ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "site EID is" ) ,
 lisp . lisp_print_cour ( OOOoO ) )
  return ( i1I1i111Ii + "<br>" )
  if 50 - 50: I1IiiI * i11iIiiIii
  if 68 - 68: OOooOOo * O0 . I11i - II111iiii . ooOoO0o / II111iiii
  if 47 - 47: OoooooooOO
  if 4 - 4: I1IiiI % I11i
  if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 o0oO00 , O0o , O0O0Oo00 = lisp . lisp_ms_compute_neg_prefix ( IIiiIiI1 , iiI11ii1I1 )
 if 95 - 95: OoO0O00
 if ( iiI11ii1I1 . is_null ( ) ) :
  o0oO00 = lisp . lisp_print_cour ( o0oO00 . print_prefix ( ) )
 else :
  O0o = lisp . lisp_print_cour ( O0o . print_prefix ( ) )
  o0oO00 = lisp . lisp_print_cour ( o0oO00 . print_prefix ( ) )
  o0oO00 = "(" + o0oO00 + ", " + O0o + ")"
  if 60 - 60: OoooooooOO % Oo0Ooo + OOooOOo . ooOoO0o * iIii1I11I1II1
  if 93 - 93: OoO0O00
 if ( O0O0Oo00 == lisp . LISP_DDT_ACTION_NOT_AUTH ) :
  i111I = "Site entry not found for non-authoritative EID"
  i1I1i111Ii += "{} {} {} {}" . format ( lisp . lisp_print_sans ( i111I ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 o0oO00 )
  if 57 - 57: I1IiiI % I11i - OOooOOo . I1IiiI / Oo0Ooo % iII111i
  if 56 - 56: oO0o . iII111i . IiII * OoOoOO00 . ooOoO0o / O0
  if 23 - 23: i1IIi + iII111i + IiII + OoO0O00
  if 12 - 12: iIii1I11I1II1 - I1ii11iIi11i + i11iIiiIii
  if 10 - 10: I1IiiI - i1IIi - ooOoO0o % Oo0Ooo
 if ( O0O0Oo00 == lisp . LISP_DDT_ACTION_DELEGATION_HOLE ) :
  i1I1ii = lisp . lisp_ddt_cache_lookup ( IIiiIiI1 , iiI11ii1I1 , False )
  if ( i1I1ii == None or i1I1ii . is_auth_prefix ( ) == False ) :
   i111I = "Could not find Authoritative-prefix entry for"
   i1I1i111Ii += "{} {} {} {}" . format ( lisp . lisp_print_sans ( i111I ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 o0oO00 )
  else :
   oOo0OOoO0 = i1I1ii . print_eid_tuple ( )
   i1I1i111Ii += "{} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Authoritative-prefix entry" ) ,
   # i1IIi
 lisp . lisp_print_cour ( oOo0OOoO0 ) ,
 lisp . lisp_print_sans ( "found for EID" ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 o0oO00 )
   if 46 - 46: OoOoOO00 - I11i - Ii1I . i1IIi
   if 35 - 35: II111iiii * I11i - OoooooooOO . I11i . I11i
 return ( i1I1i111Ii + "<br>" )
 if 11 - 11: I1Ii111 / OoOoOO00 + I11i % iIii1I11I1II1
 if 42 - 42: I1ii11iIi11i * OoOoOO00 % ooOoO0o - OoOoOO00 . i11iIiiIii - I1Ii111
 if 84 - 84: I1Ii111 - I1ii11iIi11i / I11i
 if 13 - 13: IiII - Oo0Ooo - ooOoO0o
 if 92 - 92: ooOoO0o / OoOoOO00 * OoO0O00 . I11i % II111iiii
 if 71 - 71: I1Ii111 % i1IIi - II111iiii - OOooOOo + OOooOOo * ooOoO0o
 if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
def IIii1i1iii1 ( site_eid , site , first , output ) :
 if 70 - 70: i11iIiiIii % iII111i
 oOo0OOoO0 = site_eid . print_eid_tuple ( )
 oOo0OOoO0 = oOo0OOoO0 . replace ( "no-address/0" , "" )
 if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
 if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
 if 76 - 76: Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 IIiiIiI1 = site_eid . eid
 iiI11ii1I1 = site_eid . group
 if ( IIiiIiI1 . is_null ( ) and iiI11ii1I1 . is_null ( ) == False ) :
  ooo = "{}-*-{}" . format ( iiI11ii1I1 . instance_id , iiI11ii1I1 . print_prefix_url ( ) )
  oOo0OOoO0 = "<a href='/lisp/show/site/{}'>{}</a>" . format ( ooo , oOo0OOoO0 )
  if 94 - 94: OoOoOO00 - Oo0Ooo - I1IiiI % i1IIi
 if ( IIiiIiI1 . is_null ( ) == False and iiI11ii1I1 . is_null ( ) ) :
  ooo = "{}" . format ( IIiiIiI1 . print_prefix_url ( ) )
  if 19 - 19: o0oOOo0O0Ooo
  if 42 - 42: i1IIi . I1IiiI / i1IIi + Ii1I
  if 54 - 54: ooOoO0o % OOooOOo . I1Ii111 + oO0o - OOooOOo * I1IiiI
  if 92 - 92: o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % OoO0O00 % IiII . OoooooooOO
  if ( ooo . find ( "'" ) != - 1 ) :
   ooo = ooo . replace ( "'" , "name-" , 1 )
   ooo = ooo . replace ( "'" , "" )
  else :
   if 52 - 52: ooOoO0o / i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + o0oOOo0O0Ooo
   if 71 - 71: oO0o % I11i * OoOoOO00 . O0 / Ii1I . I1ii11iIi11i
   if 58 - 58: Oo0Ooo / oO0o
   if 44 - 44: OOooOOo
   ooo = ooo . replace ( "+" , "plus-" )
   if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
  oOo0OOoO0 = "<a href='/lisp/show/site/{}'>{}</a>" . format ( ooo , oOo0OOoO0 )
  if 79 - 79: Ii1I . OoO0O00
 if ( IIiiIiI1 . is_null ( ) == False and iiI11ii1I1 . is_null ( ) == False ) :
  ooo = "{}-{}" . format ( IIiiIiI1 . print_prefix_url ( ) , iiI11ii1I1 . print_prefix_url ( ) )
  oOo0OOoO0 = "<a href='/lisp/show/site/{}'>{}</a>" . format ( ooo , oOo0OOoO0 )
  if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
  if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
 Oo00OOOOoo0oo = site . site_name if first else ""
 OOOooo = "--"
 if ( site_eid . registered ) : OOOooo = site_eid . print_flags ( True )
 O00OOooo0Ooo = "--"
 o000ooooO0o = "--"
 if ( site_eid . last_registerer . afi != lisp . LISP_AFI_NONE ) :
  O00OOooo0Ooo = site_eid . last_registerer . print_address_no_iid ( )
  o000ooooO0o = str ( datetime . timedelta ( seconds = site_eid . register_ttl ) )
  if 66 - 66: oO0o
 OOOoO = lisp . green ( "yes" , True ) if site_eid . registered else lisp . red ( "no" , True )
 if 91 - 91: oO0o + I1IiiI
 if ( site . shutdown ) : OOOoO = lisp . red ( "admin-shutdown" , True )
 if 59 - 59: I1IiiI + i11iIiiIii + i1IIi / I11i
 if ( site_eid . dynamic ) :
  OOOoO += " (dynamic)"
 elif ( site_eid . accept_more_specifics ) :
  OOOoO = "(ams)"
  if 44 - 44: I11i . OoOoOO00 * I1IiiI + OoooooooOO - iII111i - IiII
  if 15 - 15: IiII / O0 . o0oOOo0O0Ooo . i11iIiiIii
 o0OO0O0Oo = lisp . lisp_print_elapsed ( site_eid . last_registered )
 if ( time . time ( ) - site_eid . last_registered >=
 ( old_div ( site_eid . register_ttl , 2 ) ) and o0OO0O0Oo != "never" ) :
  o0OO0O0Oo = lisp . red ( o0OO0O0Oo , True )
  if 78 - 78: OoOoOO00 / Oo0Ooo - OOooOOo - iII111i * oO0o
 Ii1I11I = lisp . lisp_print_elapsed ( site_eid . first_registered )
 if 36 - 36: O0 + Oo0Ooo
 if ( site_eid . accept_more_specifics ) :
  iIIIi1i1I11i = len ( site_eid . more_specific_registrations )
  oOOo000oOoO0 = "{} EID-prefixes registered" . format ( iIIIi1i1I11i )
  oOo0OOoO0 = lisp . lisp_span ( oOo0OOoO0 , oOOo000oOoO0 )
  if 55 - 55: Oo0Ooo - OOooOOo
  if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 output += lispconfig . lisp_table_row ( Oo00OOOOoo0oo , oOo0OOoO0 , OOOoO ,
 O00OOooo0Ooo , Ii1I11I , o0OO0O0Oo , o000ooooO0o , OOOooo )
 return ( output )
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
 if 63 - 63: I1ii11iIi11i
 if 6 - 6: ooOoO0o / I1ii11iIi11i
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
def oO00oOo0OOO ( parameter ) :
 if 23 - 23: i1IIi . o0oOOo0O0Ooo * OoO0O00
 if 15 - 15: OoOoOO00
 if 62 - 62: Ii1I
 if 51 - 51: OoOoOO00
 if ( parameter != "" ) :
  if ( parameter . find ( "@lookup" ) != - 1 ) :
   parameter = parameter . split ( "@" )
   return ( oOO0 ( parameter [ 0 ] ) )
   if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
  IIiiIiI1 = parameter . split ( "%" ) [ 0 ]
  iiI11ii1I1 = parameter . split ( "%" ) [ 1 ]
  return ( I1111i ( IIiiIiI1 , iiI11ii1I1 ) )
  if 53 - 53: Ii1I % Oo0Ooo
  if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
  if 41 - 41: Ii1I % I1ii11iIi11i
  if 12 - 12: OOooOOo
  if 69 - 69: OoooooooOO + OOooOOo
 i111I = "Enter EID for Site-Cache lookup:"
 IIi11I1 = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 49 - 49: II111iiii - I1IiiI / I11i
 i1I1i111Ii = '''
        <form action="/lisp/show/site/lookup" method="post">
        <i><font face="Courier New" size="3">
        {} {}
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></i></form>
    ''' . format ( lisp . lisp_print_sans ( i111I ) , IIi11I1 )
 if 74 - 74: I11i - OOooOOo + i1IIi . I1IiiI + OOooOOo - I11i
 if 17 - 17: O0 . I1Ii111 . O0 + O0 / Oo0Ooo . ooOoO0o
 if 62 - 62: I1ii11iIi11i % iII111i * OoO0O00 - i1IIi
 if 66 - 66: i11iIiiIii / o0oOOo0O0Ooo - OoooooooOO / i1IIi . i11iIiiIii
 if ( lisp . lisp_ddt_cache . cache_count != 0 ) :
  i1I1i111Ii += IiI11i1IIiiI ( )
  if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
  if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
  if 81 - 81: iII111i * OOooOOo - I1ii11iIi11i * Ii1I % OoOoOO00 * OoOoOO00
  if 59 - 59: iIii1I11I1II1
  if 7 - 7: OOooOOo * I1IiiI / o0oOOo0O0Ooo * i11iIiiIii
 oOOo000oOoO0 = ( "{} sites & {} eid-prefixes configured\n{} eid-prefixes " + "registered" ) . format ( len ( oo00 ) ,
 # O0 / iII111i % I1Ii111 . Oo0Ooo + IiII
 lisp . lisp_sites_by_eid . cache_size ( ) , lisp . lisp_registered_count )
 if 27 - 27: I1Ii111 % OoooooooOO + IiII % i1IIi / oO0o / OoooooooOO
 OoOo00o0OO = lisp . lisp_span ( "LISP-MS Site Information:" , oOOo000oOoO0 )
 i1I1i111Ii += lispconfig . lisp_table_header ( OoOo00o0OO , "Site Name" ,
 "EID-Prefix or (S,G)" , "Registered" , "Last Registerer" ,
 "First Registered" , "Last Registered" , "TTL" , "Registration Flags" )
 if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
 for Oo00OOOOoo0oo in o00 :
  I1Ii = oo00 [ Oo00OOOOoo0oo ]
  o0ooOo0OOOO0o = True
  for i1I11i1I in I1Ii . allowed_prefixes_sorted :
   iiIiIIi = I1Ii . allowed_prefixes [ i1I11i1I ]
   if 98 - 98: OOooOOo + i1IIi . I1IiiI - II111iiii - o0oOOo0O0Ooo
   i1I1i111Ii = IIii1i1iii1 ( iiIiIIi , I1Ii , o0ooOo0OOOO0o , i1I1i111Ii )
   if ( o0ooOo0OOOO0o ) : o0ooOo0OOOO0o = False
   if 24 - 24: Oo0Ooo - i1IIi + I11i
   for IiiIi in iiIiIIi . more_specific_registrations :
    i1I1i111Ii = IIii1i1iii1 ( IiiIi , I1Ii , o0ooOo0OOOO0o ,
 i1I1i111Ii )
    if 10 - 10: OoO0O00 / Oo0Ooo
    if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
    if 57 - 57: O0 % OoOoOO00 % oO0o
    if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 i1I1i111Ii += lispconfig . lisp_table_footer ( )
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if ( lisp . lisp_pubsub_cache == { } ) : return ( i1I1i111Ii )
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 OoOo00o0OO = "LISP-MS Subscriber Information:"
 i1I1i111Ii += lispconfig . lisp_table_header ( OoOo00o0OO , "EID-prefix" ,
 "Uptime<br>TTL" , "Subscriber RLOC" , "xTR-ID" , "Nonce" ,
 "Map-Notifies<br>Sent" )
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 for IIiIi1 in lisp . lisp_pubsub_cache :
  IIiiIiI1 = IIiIi1
  for Oo00O0ooOO in list ( lisp . lisp_pubsub_cache [ IIiIi1 ] . values ( ) ) :
   IiiI = Oo00O0ooOO . itr . print_address_no_iid ( ) + ":" + str ( Oo00O0ooOO . port )
   if 19 - 19: II111iiii
   OoOO = lisp . lisp_print_elapsed ( Oo00O0ooOO . uptime ) + "<br>" + str ( Oo00O0ooOO . ttl ) + " mins"
   if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
   if 48 - 48: iII111i * iII111i
   I1I1 = "--"
   if ( Oo00O0ooOO . xtr_id != None ) :
    I1I1 = "0x" + lisp . lisp_hex_string ( Oo00O0ooOO . xtr_id )
    if 4 - 4: o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
   ii1IiIi11 = "0x" + lisp . lisp_hex_string ( Oo00O0ooOO . nonce )
   iiiii1ii1 = Oo00O0ooOO . map_notify_count
   i1I1i111Ii += lispconfig . lisp_table_row ( IIiiIiI1 , OoOO , IiiI , I1I1 ,
 ii1IiIi11 , iiiii1ii1 )
   IIiiIiI1 = ""
   if 48 - 48: O0 + O0 . I1Ii111 - ooOoO0o
   if 63 - 63: oO0o
 i1I1i111Ii += lispconfig . lisp_table_footer ( )
 return ( i1I1i111Ii )
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if 7 - 7: II111iiii
iIi1 = {
 "lisp site" : [ iII111ii , {
 "site-name" : [ False ] ,
 "description" : [ False ] ,
 "shutdown" : [ False ] ,
 "authentication-key" : [ False ] ,
 "allowed-prefix" : [ ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] ,
 "policy-name" : [ True ] ,
 "accept-more-specifics" : [ True , "yes" , "no" ] ,
 "force-proxy-reply" : [ True , "yes" , "no" ] ,
 "force-nat-proxy-reply" : [ True , "yes" , "no" ] ,
 "echo-nonce-capable" : [ True , "yes" , "no" ] ,
 "force-ttl" : [ True , 0 , 0x7fffffff ] ,
 "pitr-proxy-reply-drop" : [ True , "yes" , "no" ] ,
 "proxy-reply-action" : [ True , "native-forward" , "drop" ] ,
 "require-signature" : [ True , "yes" , "no" ] ,
 "encrypt-json" : [ True , "yes" , "no" ] ,
 "allowed-rloc" : [ ] ,
 "address" : [ True ] ,
 "priority" : [ True , 0 , 255 ] ,
 "weight" : [ True , 0 , 100 ] } ] ,

 "lisp ms-authoritative-prefix" : [ o0o00OO0 , {
 "instance-id" : [ False , 0 , 0xffffffff , True ] ,
 "eid-prefix" : [ False ] ,
 "group-prefix" : [ False ] } ] ,

 "lisp map-server-peer" : [ III1IiiI , {
 "peer" : [ ] ,
 "address" : [ True ] ,
 "priority" : [ True , 0 , 255 ] ,
 "weight" : [ True , 0 , 100 ] ,
 "prefix" : [ ] ,
 "instance-id" : [ True , 0 , 0xffffffff , True ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] } ] ,

 "lisp eid-crypto-hash" : [ oO0o0 , {
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "eid-prefix" : [ False ] } ] ,

 "lisp encryption-keys" : [ OO0O000 , {
 "json-key" : [ False ] ,
 "map-register-key" : [ False ] } ] ,

 "lisp geo-coordinates" : [ lispconfig . lisp_geo_command , {
 "geo-name" : [ False ] ,
 "geo-tag" : [ False ] } ] ,

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

 "show site" : [ oO00oOo0OOO , { } ]
 }
if 78 - 78: OOooOOo % o0oOOo0O0Ooo
if 39 - 39: I1ii11iIi11i + I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo
if 7 - 7: IiII . OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - II111iiii
if 37 - 37: I1Ii111 . OoOoOO00 / O0 * iII111i
if 7 - 7: OoO0O00 * I11i + II111iiii % i11iIiiIii
if 8 - 8: ooOoO0o * O0
if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
def III1ii ( site_eid , delete_list ) :
 i1I = lisp . lisp_get_timestamp ( )
 if 36 - 36: I1IiiI * Oo0Ooo
 if ( site_eid . registered == False ) : return ( delete_list )
 if ( site_eid . last_registered + site_eid . register_ttl > i1I ) :
  return ( delete_list )
  if 77 - 77: oO0o % i1IIi - Ii1I
  if 93 - 93: OoO0O00 * Oo0Ooo
  if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
  if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
  if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 Oo0Ooo0O0 = "merge" if site_eid . merge_register_requested else "replacement"
 IiIIi1IiiIiI = "dynamic " if site_eid . dynamic else ""
 site_eid . registered = False
 lisp . lisp_registered_count -= 1
 iIIIIiiIii = lisp . lisp_print_elapsed ( site_eid . first_registered )
 oO0O00OoOO0 = site_eid . print_eid_tuple ( )
 O00OOooo0Ooo = site_eid . last_registerer . print_address_no_iid ( )
 if 58 - 58: Oo0Ooo
 lisp . lprint ( ( "Registration timeout for {}EID-prefix {} site '{}' " + "from {}, was registered for {}, {}-semantics" ) . format ( IiIIi1IiiIiI ,
 # o0oOOo0O0Ooo
 lisp . green ( oO0O00OoOO0 , False ) , site_eid . site . site_name , O00OOooo0Ooo ,
 iIIIIiiIii , Oo0Ooo0O0 ) )
 if 78 - 78: iIii1I11I1II1
 if ( delete_list == None ) : return ( None )
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
 delete_list . append ( site_eid )
 return ( delete_list )
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 if 66 - 66: Oo0Ooo
def Oooo00oOo ( parent , rle_list ) :
 I1i1Ii11i11 = [ ]
 for OoO00 in list ( parent . individual_registrations . values ( ) ) :
  I1i1Ii11i11 = III1ii ( OoO00 , I1i1Ii11i11 )
  if 32 - 32: iIii1I11I1II1 * IiII / Ii1I % IiII
  if 42 - 42: I1Ii111 + I1Ii111 * II111iiii
 if ( len ( I1i1Ii11i11 ) != 0 and parent . merge_in_site_eid ( None ) ) :
  rle_list . append ( [ parent . eid , parent . group ] )
  if 78 - 78: OoooooooOO
 return ( rle_list )
 if 77 - 77: I1ii11iIi11i / i1IIi / Oo0Ooo % OOooOOo
 if 48 - 48: I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
 if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
 if 62 - 62: o0oOOo0O0Ooo
def I1i111i ( ) :
 global o0oO0
 if 42 - 42: I1ii11iIi11i / i1IIi % OoOoOO00
 lisp . lisp_set_exception ( )
 if 26 - 26: Ii1I * iIii1I11I1II1 % OoO0O00 . o0oOOo0O0Ooo + Oo0Ooo
 OOO00OOo0o0Oo = [ ]
 for I1Ii in list ( oo00 . values ( ) ) :
  for iiIiIIi in list ( I1Ii . allowed_prefixes . values ( ) ) :
   if ( iiIiIIi . merge_register_requested == False ) :
    III1ii ( iiIiIIi , None )
    if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
    if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
   ooOoOO = iiIiIIi
   if 56 - 56: iIii1I11I1II1 . i11iIiiIii - OOooOOo * II111iiii * I1Ii111
   if 5 - 5: OOooOOo / OOooOOo - I1ii11iIi11i
   if 79 - 79: I1ii11iIi11i + I1Ii111
   if 10 - 10: Oo0Ooo + O0
   if 43 - 43: iIii1I11I1II1 / II111iiii % o0oOOo0O0Ooo - OOooOOo
   OOO00OOo0o0Oo = Oooo00oOo ( ooOoOO , OOO00OOo0o0Oo )
   if 62 - 62: I11i
   if 63 - 63: OOooOOo + ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
   if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
   if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
   if 64 - 64: i1IIi
   I1i1Ii11i11 = [ ]
   for IIii1 in ooOoOO . more_specific_registrations :
    OOO00OOo0o0Oo = Oooo00oOo ( IIii1 , OOO00OOo0o0Oo )
    I1i1Ii11i11 = III1ii ( IIii1 , I1i1Ii11i11 )
    if 35 - 35: i11iIiiIii - I1IiiI / OOooOOo + Ii1I * oO0o
   for IIii1 in I1i1Ii11i11 :
    ooOoOO . more_specific_registrations . remove ( IIii1 )
    IIii1 . delete_cache ( )
    if 49 - 49: o0oOOo0O0Ooo * Ii1I + I11i + iII111i
    if 30 - 30: o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
    if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
    if 50 - 50: ooOoO0o + i1IIi
    if 31 - 31: Ii1I
    if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
    if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if ( len ( OOO00OOo0o0Oo ) != 0 ) :
  lisp . lisp_queue_multicast_map_notify ( o0oO0 , OOO00OOo0o0Oo )
  if 47 - 47: o0oOOo0O0Ooo
  if 66 - 66: I1IiiI - IiII
  if 33 - 33: I1IiiI / OoO0O00
  if 12 - 12: II111iiii
  if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 Oo0oO0ooo = threading . Timer ( lisp . LISP_SITE_TIMEOUT_CHECK_INTERVAL ,
 I1i111i , [ ] )
 Oo0oO0ooo . start ( )
 return
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
def iIii11iI1II ( ) :
 global Ii1iiii
 if 42 - 42: ooOoO0o - I1IiiI + I1ii11iIi11i % Ii1I
 if 44 - 44: i1IIi - O0 - I1ii11iIi11i * I1ii11iIi11i + OoOoOO00
 if 56 - 56: ooOoO0o / iIii1I11I1II1 . Ii1I % OoOoOO00 + OOooOOo
 if 10 - 10: I1Ii111 * i11iIiiIii - iIii1I11I1II1 . Oo0Ooo - I1ii11iIi11i
 if ( Ii1iiii == 0 ) : return
 if 20 - 20: I1ii11iIi11i / I1IiiI * OoO0O00 * I1IiiI * O0
 I11 = Ii1iiii
 II1i1Ii11Ii11 = lisp . bold ( "Injecting" , False )
 lisp . fprint ( "{} {} entries into mapping system for scale testing" . format ( II1i1Ii11Ii11 , I11 ) )
 if 1 - 1: iIii1I11I1II1 + Oo0Ooo / O0 - iII111i % IiII + IiII
 if 24 - 24: I1IiiI + Oo0Ooo + OOooOOo - OoooooooOO + Oo0Ooo
 if 93 - 93: ooOoO0o . iIii1I11I1II1 % i11iIiiIii . OoOoOO00 % ooOoO0o + O0
 if 65 - 65: Ii1I + OoO0O00 - OoooooooOO
 if 51 - 51: Oo0Ooo + oO0o / iII111i - i1IIi
 oO0O0oO0 = 1300
 I11Ii1iI11iI1 = 9990000000
 IIiiIiI1 = lisp . lisp_address ( lisp . LISP_AFI_NAME , "ct" , 0 , oO0O0oO0 )
 iiI11ii1I1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if 32 - 32: I1IiiI
 oO0O00oo = lisp . lisp_site_eid_lookup ( IIiiIiI1 , iiI11ii1I1 , False )
 if ( oO0O00oo == None ) :
  lisp . fprint ( "No site found for instance-ID {}" . format ( oO0O0oO0 ) )
  return
  if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
 if ( oO0O00oo . accept_more_specifics == False ) :
  lisp . fprint ( "Site must be configured with accept-more-specifics" )
  return
  if 29 - 29: o0oOOo0O0Ooo
  if 86 - 86: II111iiii . IiII
  if 2 - 2: OoooooooOO
  if 60 - 60: OoO0O00
  if 81 - 81: OoOoOO00 % Ii1I
 OooO0OO = lisp . lisp_rloc ( )
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 OOOo = ' "phone" : "{}", "text-interval" : "10", ' + '"gps" : "(37.623322,-122.384974579)" '
 if 74 - 74: Ii1I - OoooooooOO . Oo0Ooo
 if 31 - 31: o0oOOo0O0Ooo % I11i + iIii1I11I1II1 + i11iIiiIii * I1Ii111
 I1i1I1I11IiiI = ' "phone" : "{}", "health-state" : "not-tested" '
 if 40 - 40: I11i % OoooooooOO - OOooOOo + o0oOOo0O0Ooo / OOooOOo
 if 84 - 84: O0
 if 11 - 11: II111iiii / i11iIiiIii / O0
 if 94 - 94: ooOoO0o * I11i - IiII . iIii1I11I1II1
 O000oO0O = lisp . lisp_get_timestamp ( )
 o00ooo0 = 0
 for II1i1Ii11Ii11 in range ( 1 , I11 + 1 ) :
  iiIiIIi = lisp . lisp_site_eid ( oO0O00oo . site )
  iiIiIIi . eid = copy . deepcopy ( IIiiIiI1 )
  iiIiIIi . eid . address = hmac . new ( b"ct" , str ( I11Ii1iI11iI1 ) ,
 hashlib . sha256 ) . hexdigest ( )
  if 39 - 39: ooOoO0o . II111iiii
  iiIiIIi . dynamic = True
  iiIiIIi . parent_for_more_specifics = oO0O00oo
  iiIiIIi . add_cache ( )
  iiIiIIi . inherit_from_ams_parent ( )
  oO0O00oo . more_specific_registrations . append ( iiIiIIi )
  if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
  if 77 - 77: I1Ii111 - I11i
  if 11 - 11: I1ii11iIi11i
  if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
  III1II111Ii1 = copy . deepcopy ( OooO0OO )
  o0O0OO0o = "{" + OOOo . format ( I11Ii1iI11iI1 ) + "}"
  III1II111Ii1 . json = lisp . lisp_json ( iiIiIIi . eid . address , o0O0OO0o )
  OO = copy . deepcopy ( OooO0OO )
  o0O0OO0o = "{" + I1i1I1I11IiiI . format ( I11Ii1iI11iI1 ) + "}"
  OO . json = lisp . lisp_json ( iiIiIIi . eid . address , o0O0OO0o )
  iiIiIIi . registered_rlocs = [ III1II111Ii1 , OO ]
  o00ooo0 += sys . getsizeof ( iiIiIIi )
  if 77 - 77: i11iIiiIii / OoooooooOO + IiII % oO0o
  if 36 - 36: oO0o
  if 74 - 74: OoooooooOO
  if 72 - 72: O0 + I1IiiI - iII111i - OoO0O00
  if ( II1i1Ii11Ii11 % 100 == 0 ) :
   lisp . fprint ( "Added {} site-eid entries" . format ( II1i1Ii11Ii11 ) )
   if 100 - 100: O0
   if 79 - 79: iIii1I11I1II1
   if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
   if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
   if 11 - 11: i1IIi % OoO0O00 % iII111i
  if ( II1i1Ii11Ii11 % 10000 == 0 and II1i1Ii11Ii11 != I11 ) :
   lisp . fprint ( "Sleeping for 100ms ..." )
   time . sleep ( .1 )
   if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
  I11Ii1iI11iI1 += 1
  if 13 - 13: OoO0O00
  if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
  if 2 - 2: OoooooooOO . OOooOOo . IiII
  if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
  if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 O000oO0O = time . time ( ) - O000oO0O
 if ( O000oO0O < 60 ) :
  lisp . fprint ( "Finished in {} secs, memory {}" . format ( round ( O000oO0O , 3 ) , o00ooo0 ) )
 else :
  O000oO0O = old_div ( O000oO0O , 60 )
  lisp . fprint ( "Finished in {} mins, memory {}" . format ( round ( O000oO0O , 1 ) , o00ooo0 ) )
  if 24 - 24: o0oOOo0O0Ooo
 Ii1iiii = 0
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
def oo0O0o ( ) :
 lisp . lisp_set_exception ( )
 if 13 - 13: iIii1I11I1II1 . OoOoOO00 * I1IiiI / oO0o * Ii1I
 if 64 - 64: ooOoO0o / O0 * OoOoOO00 * ooOoO0o
 if 60 - 60: I11i / i1IIi % I1ii11iIi11i / I1ii11iIi11i * I1ii11iIi11i . i11iIiiIii
 if 99 - 99: OoOoOO00
 iIii11iI1II ( )
 if 77 - 77: o0oOOo0O0Ooo
 i1I = lisp . lisp_get_timestamp ( )
 if 48 - 48: OoOoOO00 % I1ii11iIi11i / I11i . iIii1I11I1II1 * II111iiii
 I1i1Ii11i11 = [ ]
 for IIiIi1 in lisp . lisp_pubsub_cache :
  for Oo00O0ooOO in list ( lisp . lisp_pubsub_cache [ IIiIi1 ] . values ( ) ) :
   o000ooooO0o = Oo00O0ooOO . ttl * 60
   if ( Oo00O0ooOO . uptime + o000ooooO0o > i1I ) : continue
   I1i1Ii11i11 . append ( [ IIiIi1 , Oo00O0ooOO . xtr_id ] )
   if 65 - 65: OoOoOO00
   if 31 - 31: I11i * OoOoOO00 . IiII % Ii1I + Oo0Ooo
   if 47 - 47: O0 * I1IiiI * OoO0O00 . II111iiii
   if 95 - 95: Ii1I % IiII . O0 % I1Ii111
   if 68 - 68: Oo0Ooo . Oo0Ooo - I1ii11iIi11i / I11i . ooOoO0o / i1IIi
   if 12 - 12: I1ii11iIi11i * i1IIi * I11i
 for IIiIi1 , I1I1 in I1i1Ii11i11 :
  IIiiIiI1 = lisp . green ( IIiIi1 , False )
  lisp . lprint ( "Pubsub state {} for xtr-id 0x{} has {}" . format ( IIiiIiI1 ,
 lisp . lisp_hex_string ( I1I1 ) , lisp . bold ( "timed out" , False ) ) )
  if 23 - 23: OOooOOo / O0 / I1IiiI
  if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
  if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
  if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
  Ii1i1 = lisp . lisp_pubsub_cache [ IIiIi1 ] [ I1I1 ]
  lisp . lisp_pubsub_cache [ IIiIi1 ] . pop ( I1I1 )
  del ( Ii1i1 )
  if 65 - 65: oO0o + I1ii11iIi11i / OOooOOo
  if 85 - 85: iIii1I11I1II1 / OoooooooOO % II111iiii
  if 49 - 49: i11iIiiIii % OoOoOO00 + I1Ii111 . II111iiii % iII111i * OOooOOo
  if 67 - 67: i1IIi
  if 5 - 5: II111iiii . OoooooooOO
  if ( len ( lisp . lisp_pubsub_cache [ IIiIi1 ] ) == 0 ) :
   lisp . lisp_pubsub_cache . pop ( IIiIi1 )
   if 57 - 57: I1IiiI
   if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
   if 50 - 50: OoOoOO00
   if 33 - 33: I11i
   if 98 - 98: OoOoOO00 % II111iiii
   if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
 o0oOoO00o = threading . Timer ( lisp . LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL , oo0O0o , [ ] )
 if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 o0oOoO00o . start ( )
 return
 if 68 - 68: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 - I1Ii111
 if 37 - 37: IiII
 if 37 - 37: Oo0Ooo / IiII * O0
 if 73 - 73: iII111i * iII111i / ooOoO0o
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
def OO0ooo0 ( ) :
 global i1I1ii1II1iII
 global o0oO0
 global Oo0oO0ooo , o0oOoO00o
 if 7 - 7: I1ii11iIi11i - oO0o * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i
 lisp . lisp_i_am ( "ms" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "Map-Server starting up" )
 if 85 - 85: O0
 if 32 - 32: OoooooooOO . OoO0O00 / Oo0Ooo * o0oOOo0O0Ooo / o0oOOo0O0Ooo * Ii1I
 if 19 - 19: Ii1I
 if 55 - 55: OOooOOo % OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
 if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
 if 71 - 71: iII111i
 i1I1ii1II1iII = lisp . lisp_open_listen_socket ( "" , "lisp-ms" )
 o0oO0 [ 0 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV4 )
 o0oO0 [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 o0oO0 [ 2 ] = i1I1ii1II1iII
 if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
 if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
 if 58 - 58: I1ii11iIi11i
 Oo0oO0ooo = threading . Timer ( lisp . LISP_SITE_TIMEOUT_CHECK_INTERVAL ,
 I1i111i , [ ] )
 Oo0oO0ooo . start ( )
 if 2 - 2: II111iiii / I1Ii111
 if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 if 22 - 22: ooOoO0o . iIii1I11I1II1
 if 12 - 12: Ii1I
 Oo = lisp . LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL
 if ( Ii1iiii != 0 ) : Oo = 5
 o0oOoO00o = threading . Timer ( Oo , oo0O0o , [ ] )
 o0oOoO00o . start ( )
 return ( True )
 if 12 - 12: I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
def ooo000oOO ( ) :
 global Oo0oO0ooo
 if 27 - 27: o0oOOo0O0Ooo * i11iIiiIii * OoO0O00
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 Oo0oO0ooo . cancel ( )
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 lisp . lisp_close_socket ( o0oO0 [ 0 ] , "" )
 lisp . lisp_close_socket ( o0oO0 [ 1 ] , "" )
 lisp . lisp_close_socket ( i1I1ii1II1iII , "lisp-ms" )
 return
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
if ( OO0ooo0 ( ) == False ) :
 lisp . lprint ( "lisp_ms_startup() failed" )
 lisp . lisp_print_banner ( "Map-Server abnormal exit" )
 exit ( 1 )
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
while ( True ) :
 ooooo0Oo0 , o0 , I1IIIi11ii11 , O0o0oo0oOO0oO = lisp . lisp_receive ( i1I1ii1II1iII , True )
 if 15 - 15: OoO0O00 * II111iiii
 if ( o0 == "" ) : break
 if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
 if ( ooooo0Oo0 == "command" ) :
  lispconfig . lisp_process_command ( i1I1ii1II1iII , ooooo0Oo0 ,
 O0o0oo0oOO0oO , "lisp-ms" , [ iIi1 , lisp . lisp_policy_commands ] )
 elif ( ooooo0Oo0 == "api" ) :
  lisp . lisp_process_api ( "lisp-ms" , i1I1ii1II1iII , O0o0oo0oOO0oO )
 else :
  lisp . lisp_parse_packet ( o0oO0 , O0o0oo0oOO0oO , o0 , I1IIIi11ii11 )
  if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
  if 79 - 79: I1IiiI - ooOoO0o
  if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
ooo000oOO ( )
lisp . lisp_print_banner ( "Map-Server normal exit" )
exit ( 0 )
if 83 - 83: IiII / I1Ii111
if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
