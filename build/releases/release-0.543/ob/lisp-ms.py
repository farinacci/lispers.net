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
if 64 - 64: i11iIiiIii
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
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
II1iII1i = None
oO0oIIII = None
Oo0oO0oo0oO00 = None
i111I = [ None , None , None ]
II1Ii1iI1i = { }
iiI1iIiI = [ ]
OOo = None
Ii1IIii11 = None
if 55 - 55: iIii1I11I1II1 - I1IiiI . Ii1I * IiII * i1IIi / iIii1I11I1II1
if 79 - 79: oO0o + I1Ii111 . ooOoO0o * IiII % I11i . I1IiiI
if 94 - 94: iII111i * Ii1I / IiII . i1IIi * iII111i
if 47 - 47: i1IIi % i11iIiiIii
if 20 - 20: ooOoO0o * II111iiii
oO0o0o0ooO0oO = os . getenv ( "LISP_MS_INJECT" )
oo0o0O00 = 0 if oO0o0o0ooO0oO == None else int ( oO0o0o0ooO0oO )
if 68 - 68: OOooOOo . I1IiiI / iII111i
if 72 - 72: OoO0O00 / OoO0O00
if 30 - 30: OoO0O00
if 95 - 95: oO0o * o0oOOo0O0Ooo / II111iiii . I1ii11iIi11i + OOooOOo
if 47 - 47: OoOoOO00 / Ii1I * OoooooooOO
if 9 - 9: I1IiiI - Ii1I % i1IIi % OoooooooOO
if 3 - 3: iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
def oo0Ooo0 ( kv_pairs ) :
 global II1Ii1iI1i
 global iiI1iIiI
 if 46 - 46: ooOoO0o % ooOoO0o - oO0o * o0oOOo0O0Ooo % iII111i
 OOooO0OOoo = lisp . lisp_site ( )
 if 29 - 29: o0oOOo0O0Ooo / iIii1I11I1II1
 IiIIIiI1I1 = [ ]
 if ( kv_pairs . has_key ( "address" ) ) :
  for OoO000 in kv_pairs [ "address" ] :
   IIiiIiI1 = lisp . lisp_rloc ( )
   IiIIIiI1I1 . append ( IIiiIiI1 )
   if 41 - 41: OoOoOO00
   if 13 - 13: Oo0Ooo . i11iIiiIii - iIii1I11I1II1 - OoOoOO00
   if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
 oo = [ ]
 if ( kv_pairs . has_key ( "eid-prefix" ) ) :
  for OO0O00 in kv_pairs [ "eid-prefix" ] :
   ii1 = lisp . lisp_site_eid ( OOooO0OOoo )
   oo . append ( ii1 )
   if 57 - 57: Ii1I % OoooooooOO
   if 61 - 61: iII111i . iIii1I11I1II1 * I1IiiI . ooOoO0o % Oo0Ooo
   if 72 - 72: OOooOOo
 for o0Oo00OOOOO in kv_pairs . keys ( ) :
  O0O = kv_pairs [ o0Oo00OOOOO ]
  if ( o0Oo00OOOOO == "site-name" ) : OOooO0OOoo . site_name = O0O
  if ( o0Oo00OOOOO == "description" ) : OOooO0OOoo . description = O0O
  if ( o0Oo00OOOOO == "authentication-key" ) :
   OOooO0OOoo . auth_key = lisp . lisp_parse_auth_key ( O0O )
   if 83 - 83: I11i + II111iiii * o0oOOo0O0Ooo % OoO0O00 + I11i
  if ( o0Oo00OOOOO == "shutdown" ) :
   OOooO0OOoo . shutdown = True if O0O == "yes" else False
   if 27 - 27: O0 % i1IIi * oO0o + i11iIiiIii + OoooooooOO * i1IIi
   if 80 - 80: I11i * i11iIiiIii / I1Ii111
  if ( o0Oo00OOOOO == "instance-id" ) :
   for I11II1i in range ( len ( oo ) ) :
    ii1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    if ( IIIII == "*" ) :
     ii1 . eid . store_iid_range ( 0 , 0 )
    else :
     if ( IIIII == "" ) : IIIII = "0"
     ii1 . eid . instance_id = int ( IIIII )
     ii1 . group . instance_id = int ( IIIII )
     if 75 - 75: II111iiii % II111iiii
     if 13 - 13: o0oOOo0O0Ooo . Ii1I
     if 19 - 19: I11i + ooOoO0o
  if ( o0Oo00OOOOO == "eid-prefix" ) :
   for I11II1i in range ( len ( oo ) ) :
    ii1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    if ( IIIII != "" ) : ii1 . eid . store_prefix ( IIIII )
    if 53 - 53: OoooooooOO . i1IIi
    if 18 - 18: o0oOOo0O0Ooo
  if ( o0Oo00OOOOO == "group-prefix" ) :
   for I11II1i in range ( len ( oo ) ) :
    ii1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    if ( IIIII != "" ) : ii1 . group . store_prefix ( IIIII )
    if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
    if 95 - 95: OoO0O00 % oO0o . O0
  if ( o0Oo00OOOOO == "accept-more-specifics" ) :
   for I11II1i in range ( len ( oo ) ) :
    ii1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    I1i1I = True if ( IIIII == "yes" ) else False
    ii1 . accept_more_specifics = I1i1I
    if 80 - 80: OoOoOO00 - OoO0O00
    if 87 - 87: oO0o / I11i - i1IIi * OOooOOo / OoooooooOO . O0
  if ( o0Oo00OOOOO == "force-proxy-reply" ) :
   for I11II1i in range ( len ( oo ) ) :
    ii1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    I1i1I = True if ( IIIII == "yes" ) else False
    ii1 . force_proxy_reply = I1i1I
    if 1 - 1: II111iiii - I11i / I11i
    if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
  if ( o0Oo00OOOOO == "force-ttl" ) :
   for I11II1i in range ( len ( oo ) ) :
    ii1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    if ( IIIII == "" ) : continue
    ii1 . force_ttl = None if int ( IIIII ) == 0 else int ( IIIII )
    if 83 - 83: OoooooooOO
    if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
  if ( o0Oo00OOOOO == "echo-nonce-capable" ) :
   for I11II1i in range ( len ( oo ) ) :
    ii1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    I1i1I = True if ( IIIII == "yes" ) else False
    ii1 . echo_nonce_capable = I1i1I
    if 4 - 4: II111iiii / ooOoO0o . iII111i
    if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
  if ( o0Oo00OOOOO == "force-nat-proxy-reply" ) :
   for I11II1i in range ( len ( oo ) ) :
    ii1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    I1i1I = True if ( IIIII == "yes" ) else False
    ii1 . force_nat_proxy_reply = I1i1I
    if 50 - 50: I1IiiI
    if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
  if ( o0Oo00OOOOO == "pitr-proxy-reply-drop" ) :
   for I11II1i in range ( len ( oo ) ) :
    ii1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    I1i1I = True if ( IIIII == "yes" ) else False
    ii1 . pitr_proxy_reply_drop = I1i1I
    if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
    if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
  if ( o0Oo00OOOOO == "proxy-reply-action" ) :
   for I11II1i in range ( len ( oo ) ) :
    ii1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    ii1 . proxy_reply_action = IIIII
    if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
    if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
  if ( o0Oo00OOOOO == "require-signature" ) :
   for I11II1i in range ( len ( oo ) ) :
    ii1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    I1i1I = True if ( IIIII == "yes" ) else False
    ii1 . require_signature = I1i1I
    if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
    if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
  if ( o0Oo00OOOOO == "encrypt-json" ) :
   for I11II1i in range ( len ( oo ) ) :
    IIiiIiI1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    I1i1I = True if ( IIIII == "yes" ) else False
    ii1 . encrypt_json = I1i1I
    if 58 - 58: i11iIiiIii % I11i
    if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
  if ( o0Oo00OOOOO == "policy-name" ) :
   for I11II1i in range ( len ( oo ) ) :
    ii1 = oo [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    ii1 . policy = IIIII
    if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
    if 16 - 16: I1IiiI * oO0o % IiII
    if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
  if ( o0Oo00OOOOO == "address" ) :
   for I11II1i in range ( len ( IiIIIiI1I1 ) ) :
    IIiiIiI1 = IiIIIiI1I1 [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    if ( IIIII != "" ) : IIiiIiI1 . rloc . store_address ( IIIII )
    if 44 - 44: oO0o
    if 88 - 88: I1Ii111 % Ii1I . II111iiii
  if ( o0Oo00OOOOO == "priority" ) :
   for I11II1i in range ( len ( IiIIIiI1I1 ) ) :
    IIiiIiI1 = IiIIIiI1I1 [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    if ( IIIII == "" ) : IIIII = "0"
    IIiiIiI1 . priority = int ( IIIII )
    if 38 - 38: o0oOOo0O0Ooo
    if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
  if ( o0Oo00OOOOO == "weight" ) :
   for I11II1i in range ( len ( IiIIIiI1I1 ) ) :
    IIiiIiI1 = IiIIIiI1I1 [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    if ( IIIII == "" ) : IIIII = "0"
    IIiiIiI1 . weight = int ( IIIII )
    if 26 - 26: iII111i
    if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
    if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
    if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
    if 91 - 91: oO0o % Oo0Ooo
    if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
    if 31 - 31: I11i - II111iiii . I11i
 if ( II1Ii1iI1i . has_key ( OOooO0OOoo . site_name ) ) : return
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 II1Ii1iI1i [ OOooO0OOoo . site_name ] = OOooO0OOoo
 iiI1iIiI = sorted ( II1Ii1iI1i )
 if 92 - 92: iII111i . I1Ii111
 for ii1 in oo :
  ii1 . add_cache ( )
  i1i = ii1 . build_sort_key ( )
  OOooO0OOoo . allowed_prefixes [ i1i ] = ii1
  if 50 - 50: IiII
 for IIiiIiI1 in IiIIIiI1I1 :
  i1i = IIiiIiI1 . rloc . print_address ( )
  OOooO0OOoo . allowed_rlocs [ i1i ] = IIiiIiI1
  if 14 - 14: I11i % OoO0O00 * I11i
  if 16 - 16: OoOoOO00 . ooOoO0o + i11iIiiIii
  if 38 - 38: IiII * OOooOOo . o0oOOo0O0Ooo
  if 98 - 98: OoooooooOO + iII111i . OoOoOO00
  if 67 - 67: i11iIiiIii - i1IIi % I1ii11iIi11i . O0
 OOooO0OOoo . allowed_prefixes_sorted = sorted ( OOooO0OOoo . allowed_prefixes )
 return
 if 77 - 77: IiII / I1IiiI
 if 15 - 15: IiII . iIii1I11I1II1 . OoooooooOO / i11iIiiIii - Ii1I . i1IIi
 if 33 - 33: I11i . o0oOOo0O0Ooo
 if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
 if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
 if 61 - 61: II111iiii
def O0OOO ( kv_pair ) :
 II11iIiIIIiI = lisp . lisp_ddt_entry ( )
 if 67 - 67: I1Ii111 . iII111i . O0
 for o0Oo00OOOOO in kv_pair . keys ( ) :
  O0O = kv_pair [ o0Oo00OOOOO ]
  if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
  if ( o0Oo00OOOOO == "instance-id" ) :
   IIIII = O0O . split ( "-" )
   if ( IIIII [ 0 ] == "" ) : continue
   if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
   I1111IIi = ( kv_pair . has_key ( "eid-prefix" ) == False or
 kv_pair [ "eid-prefix" ] == "" )
   Oo0oO = ( kv_pair . has_key ( "group-prefix" ) == False or
 kv_pair [ "group-prefix" ] == "" )
   if 1 - 1: OoO0O00 - oO0o . I11i . OoO0O00 / Oo0Ooo + I11i
   if ( I1111IIi and Oo0oO ) :
    II11iIiIIIiI . eid . store_iid_range ( int ( IIIII [ 0 ] ) , int ( IIIII [ 1 ] ) )
   else :
    II11iIiIIIiI . eid . instance_id = int ( IIIII [ 0 ] )
    II11iIiIIIiI . group . instance_id = int ( IIIII [ 0 ] )
    if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
    if 49 - 49: Ii1I / OoO0O00 . II111iiii
  if ( o0Oo00OOOOO == "eid-prefix" ) :
   II11iIiIIIiI . eid . store_prefix ( O0O )
   if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
  if ( o0Oo00OOOOO == "group-prefix" ) :
   II11iIiIIIiI . group . store_prefix ( O0O )
   if 31 - 31: II111iiii . I1IiiI
   if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
   if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
   if 92 - 92: iII111i
   if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
   if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
 II11iIiIIIiI . add_cache ( )
 return
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
def oO00OOoO00 ( kv_pair ) :
 IiI111111IIII = [ ]
 for I11II1i in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  II11iIiIIIiI = lisp . lisp_ddt_entry ( )
  IiI111111IIII . append ( II11iIiIIIiI )
  if 37 - 37: I1Ii111 / OoOoOO00
  if 23 - 23: O0
 o00oO0oOo00 = [ ]
 if 81 - 81: OoO0O00
 if ( kv_pair . has_key ( "address" ) ) :
  for I11II1i in range ( len ( kv_pair [ "address" ] ) ) :
   IIi1 = lisp . lisp_ddt_node ( )
   IIi1 . map_server_peer = True
   o00oO0oOo00 . append ( IIi1 )
   if 45 - 45: iII111i / iII111i + I1Ii111 + ooOoO0o
   if 47 - 47: o0oOOo0O0Ooo + ooOoO0o
   if 82 - 82: II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
 for o0Oo00OOOOO in kv_pair . keys ( ) :
  O0O = kv_pair [ o0Oo00OOOOO ]
  if ( o0Oo00OOOOO == "instance-id" ) :
   for ooO0oOOooOo0 in range ( len ( IiI111111IIII ) ) :
    II11iIiIIIiI = IiI111111IIII [ ooO0oOOooOo0 ]
    IIIII = O0O [ ooO0oOOooOo0 ] . split ( "-" )
    if ( IIIII [ 0 ] == "" ) : continue
    if 38 - 38: I1Ii111
    I1111IIi = ( kv_pair [ "eid-prefix" ] [ ooO0oOOooOo0 ] == "" and
 kv_pair [ "group-prefix" ] [ ooO0oOOooOo0 ] == "" )
    if 84 - 84: iIii1I11I1II1 % iII111i / iIii1I11I1II1 % I11i
    if ( I1111IIi ) :
     II11iIiIIIiI . eid . store_iid_range ( int ( IIIII [ 0 ] ) , int ( IIIII [ 1 ] ) )
    else :
     II11iIiIIIiI . eid . instance_id = int ( IIIII [ 0 ] )
     II11iIiIIIiI . group . instance_id = int ( IIIII [ 0 ] )
     if 45 - 45: O0
     if 26 - 26: I11i - iIii1I11I1II1 - I1IiiI / OoO0O00 . OoOoOO00 % iIii1I11I1II1
     if 91 - 91: o0oOOo0O0Ooo . iIii1I11I1II1 / oO0o + i1IIi
  if ( o0Oo00OOOOO == "eid-prefix" ) :
   for ooO0oOOooOo0 in range ( len ( IiI111111IIII ) ) :
    II11iIiIIIiI = IiI111111IIII [ ooO0oOOooOo0 ]
    I1i = O0O [ ooO0oOOooOo0 ]
    if ( I1i == "" ) : continue
    II11iIiIIIiI . eid . store_prefix ( I1i )
    if 53 - 53: I1ii11iIi11i * OoOoOO00 + ooOoO0o - II111iiii
    if 2 - 2: I11i + Ii1I - I1IiiI % o0oOOo0O0Ooo . iII111i
  if ( o0Oo00OOOOO == "group-prefix" ) :
   for ooO0oOOooOo0 in range ( len ( IiI111111IIII ) ) :
    II11iIiIIIiI = IiI111111IIII [ ooO0oOOooOo0 ]
    I1i = O0O [ ooO0oOOooOo0 ]
    if ( I1i == "" ) : continue
    II11iIiIIIiI . group . store_prefix ( I1i )
    if 18 - 18: OOooOOo + iII111i - Ii1I . II111iiii + i11iIiiIii
    if 20 - 20: I1Ii111
    if 52 - 52: II111iiii - OoooooooOO % Ii1I + I1IiiI * Oo0Ooo . IiII
  if ( o0Oo00OOOOO == "address" ) :
   for I11II1i in range ( len ( o00oO0oOo00 ) ) :
    IIi1 = o00oO0oOo00 [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    if ( IIIII != "" ) : IIi1 . delegate_address . store_address ( IIIII )
    if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
    if 55 - 55: OOooOOo . I1IiiI
  if ( o0Oo00OOOOO == "priority" ) :
   for I11II1i in range ( len ( o00oO0oOo00 ) ) :
    IIi1 = o00oO0oOo00 [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    if ( IIIII == "" ) : IIIII = "0"
    IIi1 . priority = int ( IIIII )
    if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
    if 100 - 100: I1Ii111 * O0
  if ( o0Oo00OOOOO == "weight" ) :
   for I11II1i in range ( len ( o00oO0oOo00 ) ) :
    IIi1 = o00oO0oOo00 [ I11II1i ]
    IIIII = O0O [ I11II1i ]
    if ( IIIII == "" ) : IIIII = "0"
    IIi1 . weight = int ( IIIII )
    if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
    if 79 - 79: O0
    if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
    if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
    if 57 - 57: OoO0O00 / ooOoO0o
    if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
    if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
    if 13 - 13: Ii1I . i11iIiiIii
 for II11iIiIIIiI in IiI111111IIII :
  II11iIiIIIiI . add_cache ( )
  for IIi1 in o00oO0oOo00 :
   II11iIiIIIiI . delegation_set . append ( IIi1 )
   if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
   if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 return
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 if 49 - 49: I1IiiI - I11i
def OoOOoOooooOOo ( kv_pair ) :
 oOo0O = lisp . lisp_address ( lisp . LISP_AFI_IPV6 , "" , 0 , 0 )
 if 52 - 52: i11iIiiIii / o0oOOo0O0Ooo * ooOoO0o
 for o0Oo00OOOOO in kv_pair . keys ( ) :
  O0O = kv_pair [ o0Oo00OOOOO ]
  if ( o0Oo00OOOOO == "instance-id" ) :
   if ( O0O == "*" ) : O0O = "-1"
   oOo0O . instance_id = int ( O0O )
   if 22 - 22: OoOoOO00 . OOooOOo * OoOoOO00
  if ( o0Oo00OOOOO == "eid-prefix" ) :
   oOo0O . store_prefix ( O0O )
   if ( oOo0O . is_ipv6 ( ) == False ) : return
   if ( ( oOo0O . mask_len % 4 ) != 0 ) : return
   if 54 - 54: IiII + Ii1I % OoO0O00 + OoooooooOO - O0 - o0oOOo0O0Ooo
   if 77 - 77: OOooOOo * iIii1I11I1II1
   if 98 - 98: I1IiiI % Ii1I * OoooooooOO
   if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
   if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
   if 71 - 71: Oo0Ooo % OOooOOo
 lisp . lisp_eid_hashes . append ( oOo0O )
 return
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
 if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
 if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
def o00oo0 ( kv_pair ) :
 for o0Oo00OOOOO in kv_pair . keys ( ) :
  O0O = kv_pair [ o0Oo00OOOOO ]
  if ( o0Oo00OOOOO == "map-register-key" ) :
   lisp . lisp_ms_encryption_keys = lisp . lisp_parse_auth_key ( O0O )
   if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
  if ( o0Oo00OOOOO == "json-key" ) :
   lisp . lisp_ms_json_keys = lisp . lisp_parse_auth_key ( O0O )
   if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
   if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 return
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
 if 76 - 76: IiII * iII111i
 if 52 - 52: OOooOOo
 if 19 - 19: I1IiiI
def i11i ( eid_key , group_key ) :
 if 73 - 73: OOooOOo
 OO0O00 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if ( eid_key ) :
  if ( eid_key == "[0]/0" ) :
   OO0O00 . store_iid_range ( 0 , 0 )
  else :
   OO0O00 . store_prefix ( eid_key )
   if 70 - 70: iIii1I11I1II1
   if 31 - 31: IiII - I1IiiI % iIii1I11I1II1
 oooo0OOOO = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if ( group_key ) : oooo0OOOO . store_prefix ( group_key )
 if 54 - 54: i1IIi / IiII % OoO0O00 . I11i
 II = lisp . lisp_print_eid_tuple ( OO0O00 , oooo0OOOO )
 II = lisp . lisp_print_cour ( II )
 if 51 - 51: I1IiiI . iIii1I11I1II1 - I1ii11iIi11i / O0
 if 52 - 52: o0oOOo0O0Ooo + O0 + iII111i + Oo0Ooo % iII111i
 if 75 - 75: I1IiiI . ooOoO0o . O0 * I1Ii111
 if 4 - 4: Ii1I % oO0o * OoO0O00
 ii1 = lisp . lisp_site_eid_lookup ( OO0O00 , oooo0OOOO , True )
 if ( ii1 == None ) :
  o0O0OOOOoOO0 = "Could not find EID {} in site cache" . format ( II )
  return ( o0O0OOOOoOO0 )
  if 23 - 23: i11iIiiIii
  if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
 o0ooooO0o0O = lisp . space ( 4 )
 iiIi11iI1iii = lisp . space ( 8 )
 oo000 = lisp . space ( 12 )
 if 63 - 63: ooOoO0o + OOooOOo * Ii1I
 iI1 = lisp . green ( "yes" , True ) if ii1 . registered else lisp . red ( "no" , True )
 if 48 - 48: I11i / I1Ii111 % ooOoO0o - iIii1I11I1II1 - i1IIi / oO0o
 if 93 - 93: I11i . II111iiii / oO0o % OoooooooOO * I11i % I1ii11iIi11i
 o0O0OOOOoOO0 = '<font face="Sans-Serif">'
 if 48 - 48: ooOoO0o / I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / i1IIi
 OOOOoOOo0O0 = lisp . lisp_print_cour ( ii1 . site . site_name )
 oOooo0 = lisp . lisp_print_cour ( str ( ii1 . site_id ) )
 ooO = "0" if ii1 . xtr_id == 0 else lisp . lisp_hex_string ( ii1 . xtr_id )
 ooO = lisp . lisp_print_cour ( "0x" + ooO )
 o0o00OOo0 = lisp . lisp_print_elapsed ( ii1 . first_registered )
 I1IIii1 = lisp . lisp_print_elapsed ( ii1 . last_registered )
 if ( time . time ( ) - ii1 . last_registered >=
 ( ii1 . register_ttl / 2 ) and I1IIii1 != "never" ) :
  I1IIii1 = lisp . red ( I1IIii1 , True )
  if 95 - 95: OoO0O00 % i1IIi * i11iIiiIii % Oo0Ooo - oO0o
 if ( ii1 . last_registerer . afi == lisp . LISP_AFI_NONE ) :
  OOoOoOo = "none"
 else :
  OOoOoOo = ii1 . last_registerer . print_address_no_iid ( )
  if 98 - 98: iII111i
 OOoOoOo = lisp . lisp_print_cour ( OOoOoOo )
 OooooO0oOOOO = ", " + lisp . lisp_print_cour ( "site is in admin-shutdown" ) if ii1 . site . shutdown else ""
 if 100 - 100: iII111i % OOooOOo
 OOO = ", accepting more specifics" if ii1 . accept_more_specifics else ""
 if 6 - 6: OoooooooOO
 if ( OOO == "" and ii1 . dynamic ) : OOO = ", dynamic"
 o0O0OOOOoOO0 += '''Site name: {}, EID-prefix: {}, registered: {}{}{}
        <br>''' . format ( OOOOoOOo0O0 , II , iI1 , OOO , OooooO0oOOOO )
 if 50 - 50: I1ii11iIi11i % O0 * o0oOOo0O0Ooo
 o0O0OOOOoOO0 += "{}Description: {}<br>" . format ( o0ooooO0o0O ,
 lisp . lisp_print_cour ( ii1 . site . description ) )
 o0O0OOOOoOO0 += "{}Last registerer: {}, xTR-ID: {}, site-ID: {}<br>" . format ( o0ooooO0o0O , OOoOoOo , ooO , oOooo0 )
 if 5 - 5: IiII * OoOoOO00
 if 5 - 5: I1Ii111
 O0I11Iiii1I = ii1 . print_flags ( False )
 O0I11Iiii1I = lisp . lisp_print_cour ( O0I11Iiii1I )
 oo00O0oO0O0 = "none"
 if ( ii1 . registered ) :
  oo00O0oO0O0 = "sha1" if ( ii1 . auth_sha1_or_sha2 ) else "sha2"
  if 96 - 96: i11iIiiIii % ooOoO0o / OoOoOO00
 o0O0OOOOoOO0 += ( "{}First registered: {}, last registered: {}, auth-type: " + "{}, registration flags: {}<br>" ) . format ( o0ooooO0o0O ,
 # OoO0O00 * OOooOOo % O0
 lisp . lisp_print_cour ( o0o00OOo0 ) , lisp . lisp_print_cour ( I1IIii1 ) ,
 lisp . lisp_print_cour ( oo00O0oO0O0 ) , O0I11Iiii1I )
 if 62 - 62: O0 % I11i . I11i - iIii1I11I1II1 / i11iIiiIii
 iiiII = lisp . lisp_print_cour ( str ( ii1 . register_ttl ) + " seconds" )
 o0O0OOOOoOO0 += "{}{} registration timeout TTL: {}<br>" . format ( o0ooooO0o0O , "Registered" if ii1 . use_register_ttl_requested else "Default" , iiiII )
 if 41 - 41: Oo0Ooo
 if 10 - 10: Oo0Ooo / Oo0Ooo / I1Ii111 . I1Ii111
 if 98 - 98: Oo0Ooo / I1IiiI . O0 + OoO0O00
 if 43 - 43: II111iiii . oO0o / I1ii11iIi11i
 if 20 - 20: I1IiiI
 if 95 - 95: iII111i - I1IiiI
 if ( ii1 . policy ) :
  I1ii1ii11i1I = lisp . lisp_print_cour ( ii1 . policy )
  o0O0OOOOoOO0 += "{}Apply policy: '{}'<br>" . format ( o0ooooO0o0O , I1ii1ii11i1I )
  if 58 - 58: iII111i + Oo0Ooo
  if 12 - 12: o0oOOo0O0Ooo - I1ii11iIi11i % OoOoOO00 * I11i
  if 44 - 44: iII111i % Ii1I
  if 41 - 41: i1IIi - I11i - Ii1I
  if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
 iI1 = "yes" if ii1 . force_proxy_reply else "no"
 iI1 = lisp . lisp_print_cour ( iI1 )
 o0O0OOOOoOO0 += "{}Forcing proxy Map-Reply: {}<br>" . format ( o0ooooO0o0O , iI1 )
 if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
 if ( ii1 . force_ttl != None ) :
  iiiII = lisp . lisp_print_cour ( str ( ii1 . force_ttl ) + " seconds" )
  o0O0OOOOoOO0 += "{}Forced proxy Map-Reply TTL: {}<br>" . format ( o0ooooO0o0O , iiiII )
  if 44 - 44: II111iiii
  if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
  if 35 - 35: iIii1I11I1II1
 iI1 = "yes" if ii1 . force_nat_proxy_reply else "no"
 iI1 = lisp . lisp_print_cour ( iI1 )
 o0O0OOOOoOO0 += "{}Forcing proxy Map-Reply for xTRs behind NATs: {}<br>" . format ( o0ooooO0o0O , iI1 )
 if 42 - 42: I1Ii111 . I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI
 if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
 iI1 = "yes" if ii1 . pitr_proxy_reply_drop else "no"
 iI1 = lisp . lisp_print_cour ( iI1 )
 o0O0OOOOoOO0 += "{}Send drop-action proxy Map-Reply to PITR: {}<br>" . format ( o0ooooO0o0O , iI1 )
 if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
 OOOO0O00o = "not configured" if ii1 . proxy_reply_action == "" else ii1 . proxy_reply_action
 if 62 - 62: iIii1I11I1II1
 OOOO0O00o = lisp . lisp_print_cour ( OOOO0O00o )
 o0O0OOOOoOO0 += "{}Proxy Map-Reply action: {}<br>" . format ( o0ooooO0o0O , OOOO0O00o )
 if 12 - 12: OOooOOo / o0oOOo0O0Ooo
 if ( ii1 . force_proxy_reply and ii1 . echo_nonce_capable ) :
  iiI1I1 = lisp . lisp_print_cour ( "yes" )
  o0O0OOOOoOO0 += "{}RLOCs are echo-nonce capable: {}<br>" . format ( o0ooooO0o0O , iiI1I1 )
  if 56 - 56: I1IiiI . O0 + Oo0Ooo
  if 1 - 1: iII111i
 iI1 = "yes" if ii1 . require_signature else "no"
 iI1 = lisp . lisp_print_cour ( iI1 )
 o0O0OOOOoOO0 += "{}Require signatures: {}<br>" . format ( o0ooooO0o0O , iI1 )
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 iI1 = "yes" if ii1 . encrypt_json else "no"
 iI1 = lisp . lisp_print_cour ( iI1 )
 o0O0OOOOoOO0 += "{}Encrypt JSON RLOC-records: {}<br>" . format ( o0ooooO0o0O , iI1 )
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
 if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
 if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
 iiiI = "any" if len ( ii1 . site . allowed_rlocs ) == 0 else ""
 if ( iiiI != "" ) : iiiI = lisp . lisp_print_cour ( iiiI )
 o0O0OOOOoOO0 += "{}Allowed RLOC-set: {}<br>" . format ( o0ooooO0o0O , iiiI )
 if ( iiiI == "" ) :
  for IIiiIiI1 in ii1 . site . allowed_rlocs . values ( ) :
   I1ii1 = lisp . lisp_print_cour ( IIiiIiI1 . rloc . print_address ( ) )
   O00 = lisp . lisp_print_cour ( IIiiIiI1 . print_state ( ) )
   Oo0o0000OOoO = lisp . lisp_print_cour ( str ( IIiiIiI1 . priority ) )
   IiIi1I1ii111 = lisp . lisp_print_cour ( str ( IIiiIiI1 . weight ) )
   IiIiIi = lisp . lisp_print_cour ( str ( IIiiIiI1 . mpriority ) )
   IIIII1 = lisp . lisp_print_cour ( str ( IIiiIiI1 . mweight ) )
   iIi1Ii1i1iI = IIiiIiI1 . print_rloc_name ( True )
   if ( iIi1Ii1i1iI != "" ) : iIi1Ii1i1iI = ", " + iIi1Ii1i1iI
   if 16 - 16: OOooOOo / Oo0Ooo / OoooooooOO * I1IiiI + i1IIi % OOooOOo
   o0O0OOOOoOO0 += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>''' . format ( iiIi11iI1iii , I1ii1 , O00 , Oo0o0000OOoO , IiIi1I1ii111 , IiIiIi , IIIII1 , iIi1Ii1i1iI )
   if 71 - 71: OoOoOO00
   if 14 - 14: i11iIiiIii % OOooOOo
   if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
   if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 iII1iiiiIII = "none" if len ( ii1 . registered_rlocs ) == 0 else ""
 if ( iII1iiiiIII != "" ) : iII1iiiiIII = lisp . lisp_print_cour ( iII1iiiiIII )
 o0O0OOOOoOO0 += "<br>Registered RLOC-set ({}): {}<br>" . format ( "merge-semantics" if ( ii1 . merge_register_requested ) else "replacement-semantics" ,
 # iII111i % I1IiiI - o0oOOo0O0Ooo - II111iiii % O0
 iII1iiiiIII )
 if ( iII1iiiiIII == "" ) :
  for IIiiIiI1 in ii1 . registered_rlocs :
   I1ii1 = lisp . lisp_print_cour ( IIiiIiI1 . rloc . print_address ( ) )
   O00 = lisp . lisp_print_cour ( IIiiIiI1 . print_state ( ) )
   Oo0o0000OOoO = lisp . lisp_print_cour ( str ( IIiiIiI1 . priority ) )
   IiIi1I1ii111 = lisp . lisp_print_cour ( str ( IIiiIiI1 . weight ) )
   IiIiIi = lisp . lisp_print_cour ( str ( IIiiIiI1 . mpriority ) )
   IIIII1 = lisp . lisp_print_cour ( str ( IIiiIiI1 . mweight ) )
   iIi1Ii1i1iI = IIiiIiI1 . print_rloc_name ( True )
   if ( iIi1Ii1i1iI != "" ) : iIi1Ii1i1iI = ", " + iIi1Ii1i1iI
   if 90 - 90: iIii1I11I1II1 + I1ii11iIi11i + ooOoO0o - I1Ii111 * IiII . I1ii11iIi11i
   o0O0OOOOoOO0 += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>''' . format ( o0ooooO0o0O , I1ii1 , O00 , Oo0o0000OOoO , IiIi1I1ii111 , IiIiIi , IIIII1 , iIi1Ii1i1iI )
   if 37 - 37: ooOoO0o % i11iIiiIii % II111iiii . O0 . Ii1I
   if ( IIiiIiI1 . geo ) :
    OO0oOOoo = lisp . lisp_print_cour ( IIiiIiI1 . geo . print_geo_url ( ) )
    o0O0OOOOoOO0 += "{}geo: {}<br>" . format ( oo000 , OO0oOOoo )
    if 52 - 52: o0oOOo0O0Ooo % Oo0Ooo
   if ( IIiiIiI1 . elp ) :
    Oo000ooOOO = lisp . lisp_print_cour ( IIiiIiI1 . elp . print_elp ( False ) )
    o0O0OOOOoOO0 += "{}elp: {}<br>" . format ( oo000 , Oo000ooOOO )
    if 31 - 31: iIii1I11I1II1 % I11i % ooOoO0o . Ii1I - I11i
   if ( IIiiIiI1 . rle ) :
    ii11i1ii1Ii = lisp . lisp_print_cour ( IIiiIiI1 . rle . print_rle ( True , True ) )
    o0O0OOOOoOO0 += "{}rle: {}<br>" . format ( oo000 , ii11i1ii1Ii )
    if 46 - 46: I1ii11iIi11i + II111iiii + iIii1I11I1II1
   if ( IIiiIiI1 . json ) :
    OOo0 = lisp . lisp_print_cour ( IIiiIiI1 . json . print_json ( True ) )
    o0O0OOOOoOO0 += "{}json: {}<br>" . format ( oo000 , OOo0 )
    if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
    if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
    if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
    if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 iII1iiiiIII = "none" if len ( ii1 . individual_registrations ) == 0 else ""
 if ( iII1iiiiIII == "none" ) :
  iII1iiiiIII = lisp . lisp_print_cour ( iII1iiiiIII )
 elif ( ii1 . inconsistent_registration ) :
  iII1iiiiIII = lisp . red ( "inconsistent registrations" , True )
  iII1iiiiIII = lisp . lisp_print_cour ( iII1iiiiIII )
  if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
 o0O0OOOOoOO0 += "<br>Individual registrations: {}<br>" . format ( iII1iiiiIII )
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
 for ii1 in ii1 . individual_registrations . values ( ) :
  iI1 = lisp . green ( "yes" , True ) if ii1 . registered else lisp . red ( "no" , True )
  if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
  oo00O0oO0O0 = "sha1" if ( ii1 . auth_sha1_or_sha2 ) else "sha2"
  oo00O0oO0O0 = lisp . lisp_print_cour ( oo00O0oO0O0 )
  iiiII = str ( ii1 . register_ttl / 60 ) + " mins"
  iiiII = lisp . lisp_print_cour ( iiiII )
  O0I11Iiii1I = ii1 . print_flags ( False )
  O0I11Iiii1I = lisp . lisp_print_cour ( O0I11Iiii1I )
  I1ii1 = lisp . lisp_print_cour ( ii1 . last_registerer . print_address_no_iid ( ) )
  if 97 - 97: I1IiiI / iII111i
  o0o00OOo0 = lisp . lisp_print_elapsed ( ii1 . first_registered )
  o0o00OOo0 = lisp . lisp_print_cour ( o0o00OOo0 )
  I1IIii1 = lisp . lisp_print_elapsed ( ii1 . last_registered )
  if ( time . time ( ) - ii1 . last_registered >=
 ( ii1 . register_ttl / 2 ) and I1IIii1 != "never" ) :
   I1IIii1 = lisp . red ( I1IIii1 , True )
   if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
  I1IIii1 = lisp . lisp_print_cour ( I1IIii1 )
  oOooo0 = lisp . lisp_print_cour ( str ( ii1 . site_id ) )
  ooO = lisp . lisp_print_cour ( lisp . lisp_hex_string ( ii1 . xtr_id ) )
  if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
  o0O0OOOOoOO0 += '''
            {}Registerer: {}, xTR-ID: 0x{}, site-id: {}, registered: {}<br>
            {}First registered: {}, last registered: {}, registration TTL: {},
            auth-type: {}, registration flags: {}<br>
        ''' . format ( o0ooooO0o0O , I1ii1 , ooO , oOooo0 , iI1 , o0ooooO0o0O , o0o00OOo0 , I1IIii1 , iiiII , oo00O0oO0O0 ,
 O0I11Iiii1I )
  if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
  iII1iiiiIII = "none" if len ( ii1 . registered_rlocs ) == 0 else ""
  iII1iiiiIII = lisp . lisp_print_cour ( iII1iiiiIII )
  o0O0OOOOoOO0 += "{}Registered RLOC-set: {}<br>" . format ( o0ooooO0o0O , iII1iiiiIII )
  if 100 - 100: OoO0O00
  for IIiiIiI1 in ii1 . registered_rlocs :
   I1ii1 = lisp . lisp_print_cour ( IIiiIiI1 . rloc . print_address ( ) )
   O00 = lisp . lisp_print_cour ( IIiiIiI1 . print_state ( ) )
   Oo0o0000OOoO = lisp . lisp_print_cour ( str ( IIiiIiI1 . priority ) )
   IiIi1I1ii111 = lisp . lisp_print_cour ( str ( IIiiIiI1 . weight ) )
   IiIiIi = lisp . lisp_print_cour ( str ( IIiiIiI1 . mpriority ) )
   IIIII1 = lisp . lisp_print_cour ( str ( IIiiIiI1 . mweight ) )
   iIi1Ii1i1iI = IIiiIiI1 . print_rloc_name ( True )
   if ( iIi1Ii1i1iI != "" ) : iIi1Ii1i1iI = ", " + iIi1Ii1i1iI
   if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
   o0O0OOOOoOO0 += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>''' . format ( iiIi11iI1iii , I1ii1 , O00 , Oo0o0000OOoO , IiIi1I1ii111 , IiIiIi , IIIII1 , iIi1Ii1i1iI )
   if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
   if ( IIiiIiI1 . geo ) :
    OO0oOOoo = lisp . lisp_print_cour ( IIiiIiI1 . geo . print_geo_url ( ) )
    o0O0OOOOoOO0 += "{}geo: {}<br>" . format ( oo000 , OO0oOOoo )
    if 45 - 45: I1Ii111
   if ( IIiiIiI1 . elp ) :
    Oo000ooOOO = lisp . lisp_print_cour ( IIiiIiI1 . elp . print_elp ( False ) )
    o0O0OOOOoOO0 += "{}elp: {}<br>" . format ( oo000 , Oo000ooOOO )
    if 83 - 83: OoOoOO00 . OoooooooOO
   if ( IIiiIiI1 . rle ) :
    ii11i1ii1Ii = lisp . lisp_print_cour ( IIiiIiI1 . rle . print_rle ( True , True ) )
    o0O0OOOOoOO0 += "{}rle: {}<br>" . format ( oo000 , ii11i1ii1Ii )
    if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
   if ( IIiiIiI1 . json ) :
    OOo0 = lisp . lisp_print_cour ( IIiiIiI1 . json . print_json ( True ) )
    o0O0OOOOoOO0 += "{}json: {}<br>" . format ( oo000 , OOo0 )
    if 62 - 62: OoO0O00 / I1ii11iIi11i
    if 7 - 7: OoooooooOO . IiII
  o0O0OOOOoOO0 += "<br>"
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 o0O0OOOOoOO0 += "</font>"
 return ( o0O0OOOOoOO0 )
 if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
 if 92 - 92: ooOoO0o
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if 92 - 92: I11i . I1Ii111
def oO ( ddt_entry , output ) :
 O00O0Ooooo00 = ddt_entry . print_eid_tuple ( )
 O000 = ddt_entry . map_referrals_sent
 if 79 - 79: OoooooooOO - I1IiiI
 if ( ddt_entry . is_auth_prefix ( ) ) :
  output += lispconfig . lisp_table_row ( O00O0Ooooo00 , "--" , "auth-prefix" , "--" ,
 O000 )
  return ( [ True , output ] )
  if 69 - 69: I11i
  if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 for oo0o0O0Oooooo in ddt_entry . delegation_set :
  OoO000 = oo0o0O0Oooooo . delegate_address
  i11IIIiI1I = str ( oo0o0O0Oooooo . priority ) + "/" + str ( oo0o0O0Oooooo . weight )
  output += lispconfig . lisp_table_row ( O00O0Ooooo00 , OoO000 . print_address ( ) ,
 oo0o0O0Oooooo . print_node_type ( ) , i11IIIiI1I , O000 )
  if ( O00O0Ooooo00 != "" ) :
   O00O0Ooooo00 = ""
   O000 = ""
   if 69 - 69: O0
   if 85 - 85: ooOoO0o / O0
 return ( [ True , output ] )
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 if 73 - 73: i1IIi / i11iIiiIii
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 if 85 - 85: OoOoOO00 + OOooOOo
 if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
 if 27 - 27: Ii1I
def oO0OO0 ( ddt_entry , output ) :
 if 82 - 82: IiII - IiII + OoOoOO00
 if 8 - 8: o0oOOo0O0Ooo % iII111i * oO0o % Ii1I . ooOoO0o / ooOoO0o
 if 81 - 81: OoO0O00
 if 99 - 99: oO0o * II111iiii * I1Ii111
 if ( ddt_entry . group . is_null ( ) ) :
  return ( oO ( ddt_entry , output ) )
  if 92 - 92: Oo0Ooo
  if 40 - 40: OoOoOO00 / IiII
 if ( ddt_entry . source_cache == None ) : return ( [ True , output ] )
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 output = ddt_entry . source_cache . walk_cache ( oO ,
 output )
 return ( [ True , output ] )
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
 if 13 - 13: Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
def i1i1IIii1i1 ( ) :
 oOoO00 = "{} entries configured" . format ( lisp . lisp_ddt_cache . cache_size ( ) )
 iI1IIIii = lisp . lisp_span ( "LISP-MS Configured Map-Server Peers & " + "Authoritative Prefixes:" , oOoO00 )
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 o0O0OOOOoOO0 = lispconfig . lisp_table_header ( iI1IIIii , "EID-Prefix or (S,G)" ,
 "Peer Address" , "Delegation Type" , "Priority/Weight" ,
 "Map-Referrals Sent" )
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 o0O0OOOOoOO0 = lisp . lisp_ddt_cache . walk_cache ( oO0OO0 , o0O0OOOOoOO0 )
 o0O0OOOOoOO0 += lispconfig . lisp_table_footer ( )
 return ( o0O0OOOOoOO0 )
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
 if 95 - 95: IiII
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
 if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
def oOoOOo0oo0 ( input_str ) :
 OO0O00 , o0O0Oo00Oo0o , oooo0OOOO , OOOo = lispconfig . lisp_get_lookup_string ( input_str )
 if 88 - 88: i11iIiiIii - ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 o0O0OOOOoOO0 = "<br>"
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 ii1 = lisp . lisp_site_eid_lookup ( OO0O00 , oooo0OOOO , o0O0Oo00Oo0o )
 if ( ii1 and ii1 . is_star_g ( ) == False ) :
  II = ii1 . print_eid_tuple ( )
  iiIiiii1i1i1i = lisp . green ( "registered" , True ) if ii1 . registered else lisp . red ( "not registered" , True )
  if 86 - 86: Oo0Ooo / oO0o + O0 * iII111i
  o0O0OOOOoOO0 += "{} '{}' {} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Site" ) ,
  # ooOoO0o + II111iiii
 lisp . lisp_print_cour ( ii1 . site . site_name ) ,
 lisp . lisp_print_sans ( "entry" ) ,
 lisp . lisp_print_cour ( II ) ,
 lisp . lisp_print_sans ( "found for EID" ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "site EID is" ) ,
 lisp . lisp_print_cour ( iiIiiii1i1i1i ) )
  return ( o0O0OOOOoOO0 + "<br>" )
  if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
  if 68 - 68: Oo0Ooo + i11iIiiIii
  if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
  if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
  if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
 I11 , oo0ooOO , OOOO0O00o = lisp . lisp_ms_compute_neg_prefix ( OO0O00 , oooo0OOOO )
 if 24 - 24: OoO0O00 % OoO0O00 * iIii1I11I1II1
 if ( oooo0OOOO . is_null ( ) ) :
  I11 = lisp . lisp_print_cour ( I11 . print_prefix ( ) )
 else :
  oo0ooOO = lisp . lisp_print_cour ( oo0ooOO . print_prefix ( ) )
  I11 = lisp . lisp_print_cour ( I11 . print_prefix ( ) )
  I11 = "(" + I11 + ", " + oo0ooOO + ")"
  if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
  if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
 if ( OOOO0O00o == lisp . LISP_DDT_ACTION_NOT_AUTH ) :
  OO0o0oO = "Site entry not found for non-authoritative EID"
  o0O0OOOOoOO0 += "{} {} {} {}" . format ( lisp . lisp_print_sans ( OO0o0oO ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 I11 )
  if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
  if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
  if 93 - 93: Ii1I - OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
  if 49 - 49: OoooooooOO * I11i - Oo0Ooo . oO0o
  if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
 if ( OOOO0O00o == lisp . LISP_DDT_ACTION_DELEGATION_HOLE ) :
  II11iIiIIIiI = lisp . lisp_ddt_cache_lookup ( OO0O00 , oooo0OOOO , False )
  if ( II11iIiIIIiI == None or II11iIiIIIiI . is_auth_prefix ( ) == False ) :
   OO0o0oO = "Could not find Authoritative-prefix entry for"
   o0O0OOOOoOO0 += "{} {} {} {}" . format ( lisp . lisp_print_sans ( OO0o0oO ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 I11 )
  else :
   II = II11iIiIIIiI . print_eid_tuple ( )
   o0O0OOOOoOO0 += "{} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Authoritative-prefix entry" ) ,
   # OoO0O00 . I11i % II111iiii
 lisp . lisp_print_cour ( II ) ,
 lisp . lisp_print_sans ( "found for EID" ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 I11 )
   if 71 - 71: I1Ii111 % i1IIi - II111iiii - OOooOOo + OOooOOo * ooOoO0o
   if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
 return ( o0O0OOOOoOO0 + "<br>" )
 if 29 - 29: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / iII111i
 if 70 - 70: i11iIiiIii % iII111i
 if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
 if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
 if 76 - 76: Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
def iIIIII1iiiiII ( site_eid , site , first , output ) :
 if 54 - 54: i1IIi
 II = site_eid . print_eid_tuple ( )
 II = II . replace ( "no-address/0" , "" )
 if 22 - 22: i1IIi + Ii1I
 if 54 - 54: ooOoO0o % OOooOOo . I1Ii111 + oO0o - OOooOOo * I1IiiI
 if 92 - 92: o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % OoO0O00 % IiII . OoooooooOO
 if 52 - 52: ooOoO0o / i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + o0oOOo0O0Ooo
 OO0O00 = site_eid . eid
 oooo0OOOO = site_eid . group
 if ( OO0O00 . is_null ( ) and oooo0OOOO . is_null ( ) == False ) :
  OO00oOooo0O = "{}-*-{}" . format ( oooo0OOOO . instance_id , oooo0OOOO . print_prefix_url ( ) )
  II = "<a href='/lisp/show/site/{}'>{}</a>" . format ( OO00oOooo0O , II )
  if 58 - 58: Oo0Ooo / oO0o
 if ( OO0O00 . is_null ( ) == False and oooo0OOOO . is_null ( ) ) :
  OO00oOooo0O = "{}" . format ( OO0O00 . print_prefix_url ( ) )
  if 44 - 44: OOooOOo
  if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
  if 79 - 79: Ii1I . OoO0O00
  if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
  if ( OO00oOooo0O . find ( "'" ) != - 1 ) :
   OO00oOooo0O = OO00oOooo0O . replace ( "'" , "name-" , 1 )
   OO00oOooo0O = OO00oOooo0O . replace ( "'" , "" )
  else :
   if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
   if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
   if 52 - 52: i1IIi
   if 84 - 84: Ii1I / IiII
   OO00oOooo0O = OO00oOooo0O . replace ( "+" , "plus-" )
   if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
  II = "<a href='/lisp/show/site/{}'>{}</a>" . format ( OO00oOooo0O , II )
  if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if ( OO0O00 . is_null ( ) == False and oooo0OOOO . is_null ( ) == False ) :
  OO00oOooo0O = "{}-{}" . format ( OO0O00 . print_prefix_url ( ) , oooo0OOOO . print_prefix_url ( ) )
  II = "<a href='/lisp/show/site/{}'>{}</a>" . format ( OO00oOooo0O , II )
  if 37 - 37: i11iIiiIii + i1IIi
  if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 I1iIi1iiiIiI = site . site_name if first else ""
 O0I11Iiii1I = "--"
 if ( site_eid . registered ) : O0I11Iiii1I = site_eid . print_flags ( True )
 III1I1Ii11iI = "--"
 iiiII = "--"
 if ( site_eid . last_registerer . afi != lisp . LISP_AFI_NONE ) :
  III1I1Ii11iI = site_eid . last_registerer . print_address_no_iid ( )
  iiiII = str ( datetime . timedelta ( seconds = site_eid . register_ttl ) )
  if 52 - 52: OOooOOo - iII111i * oO0o
 iiIiiii1i1i1i = lisp . green ( "yes" , True ) if site_eid . registered else lisp . red ( "no" , True )
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
 if ( site . shutdown ) : iiIiiii1i1i1i = lisp . red ( "admin-shutdown" , True )
 if 36 - 36: O0 + Oo0Ooo
 if ( site_eid . dynamic ) :
  iiIiiii1i1i1i += " (dynamic)"
 elif ( site_eid . accept_more_specifics ) :
  iiIiiii1i1i1i = "(ams)"
  if 5 - 5: Oo0Ooo * OoOoOO00
  if 46 - 46: ooOoO0o
 I11iIiII = lisp . lisp_print_elapsed ( site_eid . last_registered )
 if ( time . time ( ) - site_eid . last_registered >=
 ( site_eid . register_ttl / 2 ) and I11iIiII != "never" ) :
  I11iIiII = lisp . red ( I11iIiII , True )
  if 66 - 66: Oo0Ooo - o0oOOo0O0Ooo * IiII + OoOoOO00 + o0oOOo0O0Ooo - iIii1I11I1II1
 iiiI1ii11 = lisp . lisp_print_elapsed ( site_eid . first_registered )
 if 49 - 49: OoooooooOO / i11iIiiIii * i11iIiiIii
 if ( site_eid . accept_more_specifics ) :
  ooOooo0OO = len ( site_eid . more_specific_registrations )
  oOoO00 = "{} EID-prefixes registered" . format ( ooOooo0OO )
  II = lisp . lisp_span ( II , oOoO00 )
  if 2 - 2: II111iiii - OoO0O00 . IiII * iII111i / oO0o
  if 80 - 80: OOooOOo / I11i / OoOoOO00 + i1IIi - Oo0Ooo
 output += lispconfig . lisp_table_row ( I1iIi1iiiIiI , II , iiIiiii1i1i1i ,
 III1I1Ii11iI , iiiI1ii11 , I11iIiII , iiiII , O0I11Iiii1I )
 return ( output )
 if 11 - 11: o0oOOo0O0Ooo * OoO0O00
 if 15 - 15: OoOoOO00
 if 62 - 62: Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
def i1IiiI1iIi ( parameter ) :
 if 66 - 66: OoO0O00 * Oo0Ooo
 if 28 - 28: OoO0O00 % OoOoOO00 % I1ii11iIi11i + I1IiiI / I1IiiI
 if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
 if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
 if ( parameter != "" ) :
  if ( parameter . find ( "@lookup" ) != - 1 ) :
   parameter = parameter . split ( "@" )
   return ( oOoOOo0oo0 ( parameter [ 0 ] ) )
   if 23 - 23: i11iIiiIii
  OO0O00 = parameter . split ( "%" ) [ 0 ]
  oooo0OOOO = parameter . split ( "%" ) [ 1 ]
  return ( i11i ( OO0O00 , oooo0OOOO ) )
  if 39 - 39: o0oOOo0O0Ooo - I1ii11iIi11i % iII111i * OoO0O00 - OOooOOo / iII111i
  if 29 - 29: I1ii11iIi11i
  if 52 - 52: i11iIiiIii / i1IIi
  if 1 - 1: ooOoO0o
  if 78 - 78: I1ii11iIi11i + I11i - O0
 OO0o0oO = "Enter EID for Site-Cache lookup:"
 i1I1iIi1IiI = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 11 - 11: II111iiii
 o0O0OOOOoOO0 = '''
        <form action="/lisp/show/site/lookup" method="post">
        <i><font face="Courier New" size="3">
        {} {}
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></i></form>
    ''' . format ( lisp . lisp_print_sans ( OO0o0oO ) , i1I1iIi1IiI )
 if 95 - 95: IiII * I1ii11iIi11i % ooOoO0o % Ii1I - Ii1I
 if 97 - 97: I1ii11iIi11i + iIii1I11I1II1 . O0
 if 64 - 64: i1IIi % ooOoO0o / i11iIiiIii - i1IIi % OOooOOo . iII111i
 if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
 if ( lisp . lisp_ddt_cache . cache_count != 0 ) :
  o0O0OOOOoOO0 += i1i1IIii1i1 ( )
  if 21 - 21: oO0o / OoooooooOO
  if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
  if 87 - 87: I1Ii111 * i1IIi / I1ii11iIi11i
  if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo - OoooooooOO % OOooOOo * OoOoOO00
  if 69 - 69: i1IIi
 oOoO00 = ( "{} sites & {} eid-prefixes configured\n{} eid-prefixes " + "registered" ) . format ( len ( II1Ii1iI1i ) ,
 # oO0o / o0oOOo0O0Ooo / OoOoOO00 / oO0o
 lisp . lisp_sites_by_eid . cache_size ( ) , lisp . lisp_registered_count )
 if 37 - 37: I11i / IiII + II111iiii
 iI1IIIii = lisp . lisp_span ( "LISP-MS Site Information:" , oOoO00 )
 o0O0OOOOoOO0 += lispconfig . lisp_table_header ( iI1IIIii , "Site Name" ,
 "EID-Prefix or (S,G)" , "Registered" , "Last Registerer" ,
 "First Registered" , "Last Registered" , "TTL" , "Registration Flags" )
 if 18 - 18: I1ii11iIi11i
 for I1iIi1iiiIiI in iiI1iIiI :
  OOooO0OOoo = II1Ii1iI1i [ I1iIi1iiiIiI ]
  iiIIi = True
  for i1i in OOooO0OOoo . allowed_prefixes_sorted :
   ii1 = OOooO0OOoo . allowed_prefixes [ i1i ]
   if 96 - 96: iII111i
   o0O0OOOOoOO0 = iIIIII1iiiiII ( ii1 , OOooO0OOoo , iiIIi , o0O0OOOOoOO0 )
   if ( iiIIi ) : iiIIi = False
   if 18 - 18: iII111i * I11i - Ii1I
   for II1i1III in ii1 . more_specific_registrations :
    o0O0OOOOoOO0 = iIIIII1iiiiII ( II1i1III , OOooO0OOoo , iiIIi ,
 o0O0OOOOoOO0 )
    if 34 - 34: I1Ii111 - i11iIiiIii / iIii1I11I1II1
    if 87 - 87: I1ii11iIi11i / OoooooooOO - Oo0Ooo % OoOoOO00 % IiII % Oo0Ooo
    if 29 - 29: OoooooooOO . I1IiiI % I1ii11iIi11i - iII111i
    if 8 - 8: i1IIi
 o0O0OOOOoOO0 += lispconfig . lisp_table_footer ( )
 if 32 - 32: oO0o / II111iiii
 if 45 - 45: I1ii11iIi11i + OoO0O00 * i11iIiiIii / OOooOOo % I11i * O0
 if 17 - 17: O0
 if 88 - 88: Oo0Ooo . O0 % OoooooooOO / OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if ( lisp . lisp_pubsub_cache == { } ) : return ( o0O0OOOOoOO0 )
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
 iI1IIIii = "LISP-MS Subscriber Information:"
 o0O0OOOOoOO0 += lispconfig . lisp_table_header ( iI1IIIii , "EID-prefix" ,
 "Uptime<br>TTL" , "Subscriber RLOC" , "xTR-ID" , "Nonce" ,
 "Map-Notifies<br>Sent" )
 if 54 - 54: II111iiii . I11i
 for oOO in lisp . lisp_pubsub_cache :
  OO0O00 = oOO
  for II1i11i1iIi11 in lisp . lisp_pubsub_cache [ oOO ] . values ( ) :
   oo0O0oO0O0O = II1i11i1iIi11 . itr . print_address_no_iid ( ) + ":" + str ( II1i11i1iIi11 . port )
   if 69 - 69: oO0o / i11iIiiIii
   OOo00 = lisp . lisp_print_elapsed ( II1i11i1iIi11 . uptime ) + "<br>" + str ( II1i11i1iIi11 . ttl ) + " mins"
   if 22 - 22: oO0o
   if 33 - 33: iIii1I11I1II1 / Ii1I
   iIIIiiiI11I = "--"
   if ( II1i11i1iIi11 . xtr_id != None ) :
    iIIIiiiI11I = "0x" + lisp . lisp_hex_string ( II1i11i1iIi11 . xtr_id )
    if 6 - 6: Ii1I % i1IIi . Ii1I * Ii1I
   o0Oo = "0x" + lisp . lisp_hex_string ( II1i11i1iIi11 . nonce )
   oo0ooO0 = II1i11i1iIi11 . map_notify_count
   o0O0OOOOoOO0 += lispconfig . lisp_table_row ( OO0O00 , OOo00 , oo0O0oO0O0O , iIIIiiiI11I ,
 o0Oo , oo0ooO0 )
   OO0O00 = ""
   if 28 - 28: I1ii11iIi11i * OoooooooOO . II111iiii / i11iIiiIii + oO0o
   if 38 - 38: IiII . Ii1I
 o0O0OOOOoOO0 += lispconfig . lisp_table_footer ( )
 return ( o0O0OOOOoOO0 )
 if 24 - 24: o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
 if 12 - 12: iII111i . IiII . OoOoOO00 / O0
 if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
 if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
OOoO = {
 "lisp site" : [ oo0Ooo0 , {
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

 "lisp ms-authoritative-prefix" : [ O0OOO , {
 "instance-id" : [ False , 0 , 0xffffffff , True ] ,
 "eid-prefix" : [ False ] ,
 "group-prefix" : [ False ] } ] ,

 "lisp map-server-peer" : [ oO00OOoO00 , {
 "peer" : [ ] ,
 "address" : [ True ] ,
 "priority" : [ True , 0 , 255 ] ,
 "weight" : [ True , 0 , 100 ] ,
 "prefix" : [ ] ,
 "instance-id" : [ True , 0 , 0xffffffff , True ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] } ] ,

 "lisp eid-crypto-hash" : [ OoOOoOooooOOo , {
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "eid-prefix" : [ False ] } ] ,

 "lisp encryption-keys" : [ o00oo0 , {
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

 "show site" : [ i1IiiI1iIi , { } ]
 }
if 18 - 18: iIii1I11I1II1 + Oo0Ooo - OOooOOo + OoooooooOO * OoooooooOO
if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
if 100 - 100: Ii1I + OoO0O00
if 73 - 73: i1IIi - I1Ii111 % ooOoO0o / OoO0O00
if 40 - 40: I1ii11iIi11i * ooOoO0o - I1IiiI / IiII / i11iIiiIii
if 83 - 83: I1ii11iIi11i / I1Ii111 - i11iIiiIii . iIii1I11I1II1 + Oo0Ooo
if 59 - 59: O0 % Oo0Ooo
def O0o00O0Oo0 ( site_eid , delete_list ) :
 o0 = lisp . lisp_get_timestamp ( )
 if 35 - 35: IiII + i1IIi * oO0o - Ii1I . Oo0Ooo
 if ( site_eid . registered == False ) : return ( delete_list )
 if ( site_eid . last_registered + site_eid . register_ttl > o0 ) :
  return ( delete_list )
  if 31 - 31: o0oOOo0O0Ooo
  if 15 - 15: O0 / Oo0Ooo % I1ii11iIi11i + o0oOOo0O0Ooo
  if 23 - 23: iIii1I11I1II1 + O0
  if 58 - 58: Oo0Ooo
  if 9 - 9: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo + OoooooooOO
 Oo0o = "merge" if site_eid . merge_register_requested else "replacement"
 oOOoOoo0O0 = "dynamic " if site_eid . dynamic else ""
 site_eid . registered = False
 lisp . lisp_registered_count -= 1
 i1 = lisp . lisp_print_elapsed ( site_eid . first_registered )
 I1i = site_eid . print_eid_tuple ( )
 III1I1Ii11iI = site_eid . last_registerer . print_address_no_iid ( )
 if 20 - 20: IiII % O0 . I1Ii111
 lisp . lprint ( ( "Registration timeout for {}EID-prefix {} site '{}' " + "from {}, was registered for {}, {}-semantics" ) . format ( oOOoOoo0O0 ,
 # iII111i * OOooOOo . OoOoOO00 . i1IIi . i1IIi - o0oOOo0O0Ooo
 lisp . green ( I1i , False ) , site_eid . site . site_name , III1I1Ii11iI ,
 i1 , Oo0o ) )
 if 26 - 26: iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
 if ( delete_list == None ) : return ( None )
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 delete_list . append ( site_eid )
 return ( delete_list )
 if 66 - 66: Oo0Ooo
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 if 55 - 55: o0oOOo0O0Ooo . iII111i
 if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
 if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
 if 89 - 89: OoO0O00 + IiII * I1Ii111
 if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
def III1I1I ( parent , rle_list ) :
 i1i111i1 = [ ]
 for oo0o0O0Oooooo in parent . individual_registrations . values ( ) :
  i1i111i1 = O0o00O0Oo0 ( oo0o0O0Oooooo , i1i111i1 )
  if 99 - 99: I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % oO0o / I11i
  if 60 - 60: Ii1I * OoOoOO00 - i11iIiiIii % ooOoO0o
 if ( len ( i1i111i1 ) != 0 and parent . merge_in_site_eid ( None ) ) :
  rle_list . append ( [ parent . eid , parent . group ] )
  if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
 return ( rle_list )
 if 30 - 30: iII111i / OoO0O00 + oO0o
 if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
 if 70 - 70: OoO0O00
 if 46 - 46: I11i - i1IIi
 if 46 - 46: I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
def oOo0OOoooO ( ) :
 global i111I
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 lisp . lisp_set_exception ( )
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 OooOo000o0o = [ ]
 for OOooO0OOoo in II1Ii1iI1i . values ( ) :
  for ii1 in OOooO0OOoo . allowed_prefixes . values ( ) :
   if ( ii1 . merge_register_requested == False ) :
    O0o00O0Oo0 ( ii1 , None )
    if 42 - 42: oO0o % OOooOOo
    if 60 - 60: OoOoOO00 / I1Ii111 - II111iiii . Oo0Ooo + O0
   Ii1iI = ii1
   if 53 - 53: iIii1I11I1II1 - oO0o % OoOoOO00 * I1Ii111 % ooOoO0o
   if 29 - 29: o0oOOo0O0Ooo / Oo0Ooo * I1ii11iIi11i . o0oOOo0O0Ooo
   if 64 - 64: oO0o / ooOoO0o % i11iIiiIii
   if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
   if 64 - 64: i1IIi
   OooOo000o0o = III1I1I ( Ii1iI , OooOo000o0o )
   if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
   if 18 - 18: OOooOOo + I1Ii111
   if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
   if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
   if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
   i1i111i1 = [ ]
   for i1iii11 in Ii1iI . more_specific_registrations :
    OooOo000o0o = III1I1I ( i1iii11 , OooOo000o0o )
    i1i111i1 = O0o00O0Oo0 ( i1iii11 , i1i111i1 )
    if 92 - 92: OoOoOO00 . OoooooooOO - I1Ii111
   for i1iii11 in i1i111i1 :
    Ii1iI . more_specific_registrations . remove ( i1iii11 )
    i1iii11 . delete_cache ( )
    if 74 - 74: iIii1I11I1II1 % iII111i * OOooOOo * iIii1I11I1II1
    if 73 - 73: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
    if 60 - 60: OoOoOO00
    if 5 - 5: I1IiiI - I1IiiI - I1IiiI * OoooooooOO
    if 28 - 28: iIii1I11I1II1 + iIii1I11I1II1
    if 28 - 28: oO0o
    if 52 - 52: I1IiiI + iIii1I11I1II1
 if ( len ( OooOo000o0o ) != 0 ) :
  lisp . lisp_queue_multicast_map_notify ( i111I , OooOo000o0o )
  if 71 - 71: O0 / oO0o
  if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
  if 43 - 43: I1ii11iIi11i - iII111i
  if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
  if 47 - 47: iII111i
 OOo = threading . Timer ( lisp . LISP_SITE_TIMEOUT_CHECK_INTERVAL ,
 oOo0OOoooO , [ ] )
 OOo . start ( )
 return
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if 47 - 47: oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
def ii111Iiii ( ) :
 global oo0o0O00
 if 54 - 54: OoooooooOO - I1IiiI % I1ii11iIi11i
 if 92 - 92: OoO0O00 * ooOoO0o
 if 35 - 35: i11iIiiIii
 if 99 - 99: II111iiii . o0oOOo0O0Ooo + O0
 if ( oo0o0O00 == 0 ) : return
 if 71 - 71: IiII + i1IIi * Oo0Ooo % Oo0Ooo / Oo0Ooo
 oO0o0o0ooO0oO = oo0o0O00
 I11II1i = lisp . bold ( "Injecting" , False )
 lisp . fprint ( "{} {} entries into mapping system for scale testing" . format ( I11II1i , oO0o0o0ooO0oO ) )
 if 55 - 55: OoooooooOO + I1Ii111 + OoooooooOO * ooOoO0o
 if 68 - 68: O0
 if 2 - 2: OoO0O00 + O0 * OoO0O00 - Ii1I + oO0o
 if 43 - 43: I1ii11iIi11i - OoOoOO00
 if 36 - 36: I1ii11iIi11i - iII111i
 III1I1 = 1300
 ii1111Ii1i = 9990000000
 OO0O00 = lisp . lisp_address ( lisp . LISP_AFI_NAME , "ct" , 0 , III1I1 )
 oooo0OOOO = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 oO00oo000O = lisp . lisp_site_eid_lookup ( OO0O00 , oooo0OOOO , False )
 if ( oO00oo000O == None ) :
  lisp . fprint ( "No site found for instance-ID {}" . format ( III1I1 ) )
  return
  if 7 - 7: O0 / iII111i * oO0o
 if ( oO00oo000O . accept_more_specifics == False ) :
  lisp . fprint ( "Site must be configured with accept-more-specifics" )
  return
  if 29 - 29: o0oOOo0O0Ooo
  if 86 - 86: II111iiii . IiII
  if 2 - 2: OoooooooOO
  if 60 - 60: OoO0O00
  if 81 - 81: OoOoOO00 % Ii1I
 IIiiIiI1 = lisp . lisp_rloc ( )
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 OOOoo0ooOo00O = ' "phone" : "{}", "text-interval" : "10", ' + '"gps" : "(37.623322,-122.384974579)" '
 if 38 - 38: iIii1I11I1II1 + i11iIiiIii * OoO0O00 * ooOoO0o % OOooOOo
 if 5 - 5: ooOoO0o - I1Ii111 + I1IiiI * O0 / Oo0Ooo - Ii1I
 OoO0oO00o = ' "phone" : "{}", "health-state" : "not-tested" '
 if 10 - 10: OoO0O00
 if 22 - 22: i11iIiiIii / O0
 if 94 - 94: ooOoO0o * I11i - IiII . iIii1I11I1II1
 if 66 - 66: ooOoO0o - OOooOOo * OoOoOO00 / oO0o * II111iiii * OoO0O00
 Ooo0O = lisp . lisp_get_timestamp ( )
 iiII1IiIi1iI1 = 0
 for I11II1i in range ( 1 , oO0o0o0ooO0oO + 1 ) :
  ii1 = lisp . lisp_site_eid ( oO00oo000O . site )
  ii1 . eid = copy . deepcopy ( OO0O00 )
  ii1 . eid . address = hmac . new ( "ct" , str ( ii1111Ii1i ) ,
 hashlib . sha256 ) . hexdigest ( )
  if 72 - 72: O0
  ii1 . dynamic = True
  ii1 . parent_for_more_specifics = oO00oo000O
  ii1 . add_cache ( )
  ii1 . inherit_from_ams_parent ( )
  oO00oo000O . more_specific_registrations . append ( ii1 )
  if 58 - 58: IiII + iIii1I11I1II1
  if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
  if 79 - 79: ooOoO0o . OoOoOO00 % I1Ii111 - Oo0Ooo
  if 69 - 69: ooOoO0o - o0oOOo0O0Ooo . ooOoO0o
  iIiiIi11IIi = copy . deepcopy ( IIiiIiI1 )
  Oo0 = "{" + OOOoo0ooOo00O . format ( ii1111Ii1i ) + "}"
  iIiiIi11IIi . json = lisp . lisp_json ( ii1 . eid . address , Oo0 )
  oOII1ii1ii11I1 = copy . deepcopy ( IIiiIiI1 )
  Oo0 = "{" + OoO0oO00o . format ( ii1111Ii1i ) + "}"
  oOII1ii1ii11I1 . json = lisp . lisp_json ( ii1 . eid . address , Oo0 )
  ii1 . registered_rlocs = [ iIiiIi11IIi , oOII1ii1ii11I1 ]
  iiII1IiIi1iI1 += sys . getsizeof ( ii1 )
  if 88 - 88: I1ii11iIi11i
  if 93 - 93: iIii1I11I1II1
  if 66 - 66: i11iIiiIii * iIii1I11I1II1 % OoooooooOO
  if 5 - 5: OoOoOO00 % OoooooooOO
  if ( I11II1i % 100 == 0 ) :
   lisp . fprint ( "Added {} site-eid entries" . format ( I11II1i ) )
   if 60 - 60: OoOoOO00 . i1IIi % OoO0O00 % ooOoO0o % OOooOOo
   if 33 - 33: iIii1I11I1II1 - Ii1I * I1ii11iIi11i % iIii1I11I1II1 + OoO0O00 . OOooOOo
   if 56 - 56: i11iIiiIii * iII111i . oO0o
   if 78 - 78: OoOoOO00
   if 1 - 1: OOooOOo . IiII
  if ( I11II1i % 10000 == 0 and I11II1i != oO0o0o0ooO0oO ) :
   lisp . fprint ( "Sleeping for 100ms ..." )
   time . sleep ( .1 )
   if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
  ii1111Ii1i += 1
  if 19 - 19: oO0o * I1IiiI % i11iIiiIii
  if 24 - 24: o0oOOo0O0Ooo
  if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
  if 28 - 28: OOooOOo % ooOoO0o
  if 48 - 48: i11iIiiIii % oO0o
 Ooo0O = time . time ( ) - Ooo0O
 if ( Ooo0O < 60 ) :
  lisp . fprint ( "Finished in {} secs, memory {}" . format ( round ( Ooo0O , 3 ) , iiII1IiIi1iI1 ) )
 else :
  Ooo0O = Ooo0O / 60
  lisp . fprint ( "Finished in {} mins, memory {}" . format ( round ( Ooo0O , 1 ) , iiII1IiIi1iI1 ) )
  if 29 - 29: iII111i + i11iIiiIii % I11i
 oo0o0O00 = 0
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
def Oo00o0O0O ( ) :
 lisp . lisp_set_exception ( )
 if 84 - 84: I11i % i1IIi
 if 33 - 33: I1ii11iIi11i * I1ii11iIi11i . ooOoO0o . i11iIiiIii
 if 48 - 48: o0oOOo0O0Ooo . Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 ii111Iiii ( )
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 o0 = lisp . lisp_get_timestamp ( )
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 i1i111i1 = [ ]
 for oOO in lisp . lisp_pubsub_cache :
  for II1i11i1iIi11 in lisp . lisp_pubsub_cache [ oOO ] . values ( ) :
   iiiII = II1i11i1iIi11 . ttl * 60
   if ( II1i11i1iIi11 . uptime + iiiII > o0 ) : continue
   i1i111i1 . append ( [ oOO , II1i11i1iIi11 . xtr_id ] )
   if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
   if 24 - 24: OoOoOO00
   if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
   if 28 - 28: I1IiiI
   if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
   if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 for oOO , iIIIiiiI11I in i1i111i1 :
  OO0O00 = lisp . green ( oOO , False )
  lisp . lprint ( "Pubsub state {} for xtr-id 0x{} has {}" . format ( OO0O00 ,
 lisp . lisp_hex_string ( iIIIiiiI11I ) , lisp . bold ( "timed out" , False ) ) )
  if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
  if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
  if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
  if 79 - 79: OoOoOO00 / ooOoO0o
  oOo00o = lisp . lisp_pubsub_cache [ oOO ] [ iIIIiiiI11I ]
  lisp . lisp_pubsub_cache [ oOO ] . pop ( iIIIiiiI11I )
  del ( oOo00o )
  if 98 - 98: OOooOOo % i1IIi . I1IiiI . II111iiii . I1ii11iIi11i / i11iIiiIii
  if 32 - 32: o0oOOo0O0Ooo + I1IiiI . I1Ii111
  if 41 - 41: OoOoOO00 . i11iIiiIii / I11i
  if 98 - 98: OoOoOO00 % II111iiii
  if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
  if ( len ( lisp . lisp_pubsub_cache [ oOO ] ) == 0 ) :
   lisp . lisp_pubsub_cache . pop ( oOO )
   if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
   if 68 - 68: o0oOOo0O0Ooo
   if 20 - 20: I1Ii111 - I1Ii111
   if 37 - 37: IiII
   if 37 - 37: Oo0Ooo / IiII * O0
   if 73 - 73: iII111i * iII111i / ooOoO0o
 Ii1IIii11 = threading . Timer ( lisp . LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL , Oo00o0O0O , [ ] )
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 Ii1IIii11 . start ( )
 return
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
def oOOO0ooo ( ) :
 global II1iII1i
 global i111I
 global OOo , Ii1IIii11
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 lisp . lisp_i_am ( "ms" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "Map-Server starting up" )
 if 48 - 48: iII111i + IiII
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 if 14 - 14: OOooOOo
 if 79 - 79: Ii1I
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 76 - 76: iIii1I11I1II1
 if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
 if 93 - 93: OoooooooOO * Oo0Ooo
 if 10 - 10: I1Ii111 * OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i11iIiiIii
 II1iII1i = lisp . lisp_open_listen_socket ( "" , "lisp-ms" )
 i111I [ 0 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV4 )
 i111I [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 i111I [ 2 ] = II1iII1i
 if 22 - 22: I1Ii111 / o0oOOo0O0Ooo
 if 98 - 98: i1IIi
 if 51 - 51: I1ii11iIi11i + ooOoO0o + Oo0Ooo / i1IIi + i1IIi
 if 12 - 12: iIii1I11I1II1 . Ii1I . I1ii11iIi11i % I1IiiI . II111iiii . oO0o
 OOo = threading . Timer ( lisp . LISP_SITE_TIMEOUT_CHECK_INTERVAL ,
 oOo0OOoooO , [ ] )
 OOo . start ( )
 if 32 - 32: I1ii11iIi11i + IiII / O0 / OoOoOO00 * OoooooooOO % ooOoO0o
 if 50 - 50: OoO0O00
 if 66 - 66: iIii1I11I1II1
 if 41 - 41: I1Ii111 . O0 * I1IiiI * I1ii11iIi11i
 o0o0Oo0OOOOO = lisp . LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL
 if ( oo0o0O00 != 0 ) : o0o0Oo0OOOOO = 5
 Ii1IIii11 = threading . Timer ( o0o0Oo0OOOOO , Oo00o0O0O , [ ] )
 Ii1IIii11 . start ( )
 return ( True )
 if 49 - 49: iIii1I11I1II1 % II111iiii
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 if 68 - 68: oO0o
 if 10 - 10: Ii1I
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
def III1II1i ( ) :
 global OOo
 if 3 - 3: iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 OOo . cancel ( )
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 lisp . lisp_close_socket ( i111I [ 0 ] , "" )
 lisp . lisp_close_socket ( i111I [ 1 ] , "" )
 lisp . lisp_close_socket ( II1iII1i , "lisp-ms" )
 return
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if 81 - 81: IiII / OoOoOO00 * IiII . O0
if ( oOOO0ooo ( ) == False ) :
 lisp . lprint ( "lisp_ms_startup() failed" )
 lisp . lisp_print_banner ( "Map-Server abnormal exit" )
 exit ( 1 )
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
while ( True ) :
 IIii , oOOO0 , i111I11i1I , O00oOo0O0o00O = lisp . lisp_receive ( II1iII1i , True )
 if 91 - 91: II111iiii * iII111i . i1IIi
 if ( oOOO0 == "" ) : break
 if 22 - 22: oO0o * Ii1I * i11iIiiIii + iII111i * OoOoOO00 * OoO0O00
 if ( IIii == "command" ) :
  lispconfig . lisp_process_command ( II1iII1i , IIii ,
 O00oOo0O0o00O , "lisp-ms" , [ OOoO , lisp . lisp_policy_commands ] )
 elif ( IIii == "api" ) :
  lisp . lisp_process_api ( "lisp-ms" , II1iII1i , O00oOo0O0o00O )
 else :
  lisp . lisp_parse_packet ( i111I , O00oOo0O0o00O , oOOO0 , i111I11i1I )
  if 85 - 85: iII111i * OOooOOo % Oo0Ooo - iII111i - I11i
  if 46 - 46: O0
  if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
III1II1i ( )
lisp . lisp_print_banner ( "Map-Server normal exit" )
exit ( 0 )
if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
if 80 - 80: OoooooooOO + IiII
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
