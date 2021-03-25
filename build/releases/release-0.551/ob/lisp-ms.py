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
  if ( lispconfig . lisp_clause_syntax_error ( kv_pairs , "address" ,
 "allowed-rloc" ) ) : return
  for OoO000 in kv_pairs [ "address" ] :
   IIiiIiI1 = lisp . lisp_rloc ( )
   IiIIIiI1I1 . append ( IIiiIiI1 )
   if 41 - 41: OoOoOO00
   if 13 - 13: Oo0Ooo . i11iIiiIii - iIii1I11I1II1 - OoOoOO00
   if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
 oo = [ ]
 if ( lispconfig . lisp_clause_syntax_error ( kv_pairs , "eid-prefix" ,
 "allowed-prefix" ) ) : return
 for OO0O00 in kv_pairs [ "eid-prefix" ] :
  ii1 = lisp . lisp_site_eid ( OOooO0OOoo )
  oo . append ( ii1 )
  if 57 - 57: Ii1I % OoooooooOO
  if 61 - 61: iII111i . iIii1I11I1II1 * I1IiiI . ooOoO0o % Oo0Ooo
 for oOo00Oo00O in kv_pairs . keys ( ) :
  iI11i1I1 = kv_pairs [ oOo00Oo00O ]
  if ( oOo00Oo00O == "site-name" ) : OOooO0OOoo . site_name = iI11i1I1
  if ( oOo00Oo00O == "description" ) : OOooO0OOoo . description = iI11i1I1
  if ( oOo00Oo00O == "authentication-key" ) :
   OOooO0OOoo . auth_key = lisp . lisp_parse_auth_key ( iI11i1I1 )
   if 71 - 71: ooOoO0o % iII111i / o0oOOo0O0Ooo
  if ( oOo00Oo00O == "shutdown" ) :
   OOooO0OOoo . shutdown = True if iI11i1I1 == "yes" else False
   if 49 - 49: II111iiii % iII111i * O0
   if 89 - 89: oO0o + Oo0Ooo
  if ( oOo00Oo00O == "instance-id" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    ii1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    if ( III1ii1iII == "*" ) :
     ii1 . eid . store_iid_range ( 0 , 0 )
    else :
     if ( III1ii1iII == "" ) : III1ii1iII = "0"
     ii1 . eid . instance_id = int ( III1ii1iII )
     ii1 . group . instance_id = int ( III1ii1iII )
     if 54 - 54: I1IiiI % II111iiii % II111iiii
     if 13 - 13: o0oOOo0O0Ooo . Ii1I
     if 19 - 19: I11i + ooOoO0o
  if ( oOo00Oo00O == "eid-prefix" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    ii1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    if ( III1ii1iII != "" ) : ii1 . eid . store_prefix ( III1ii1iII )
    if 53 - 53: OoooooooOO . i1IIi
    if 18 - 18: o0oOOo0O0Ooo
  if ( oOo00Oo00O == "group-prefix" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    ii1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    if ( III1ii1iII != "" ) : ii1 . group . store_prefix ( III1ii1iII )
    if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
    if 95 - 95: OoO0O00 % oO0o . O0
  if ( oOo00Oo00O == "accept-more-specifics" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    ii1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    I1i1I = True if ( III1ii1iII == "yes" ) else False
    ii1 . accept_more_specifics = I1i1I
    if 80 - 80: OoOoOO00 - OoO0O00
    if 87 - 87: oO0o / I11i - i1IIi * OOooOOo / OoooooooOO . O0
  if ( oOo00Oo00O == "force-proxy-reply" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    ii1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    I1i1I = True if ( III1ii1iII == "yes" ) else False
    ii1 . force_proxy_reply = I1i1I
    if 1 - 1: II111iiii - I11i / I11i
    if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
  if ( oOo00Oo00O == "force-ttl" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    ii1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    if ( III1ii1iII == "" ) : continue
    ii1 . force_ttl = None if int ( III1ii1iII ) == 0 else int ( III1ii1iII )
    if 83 - 83: OoooooooOO
    if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
  if ( oOo00Oo00O == "echo-nonce-capable" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    ii1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    I1i1I = True if ( III1ii1iII == "yes" ) else False
    ii1 . echo_nonce_capable = I1i1I
    if 4 - 4: II111iiii / ooOoO0o . iII111i
    if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
  if ( oOo00Oo00O == "force-nat-proxy-reply" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    ii1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    I1i1I = True if ( III1ii1iII == "yes" ) else False
    ii1 . force_nat_proxy_reply = I1i1I
    if 50 - 50: I1IiiI
    if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
  if ( oOo00Oo00O == "pitr-proxy-reply-drop" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    ii1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    I1i1I = True if ( III1ii1iII == "yes" ) else False
    ii1 . pitr_proxy_reply_drop = I1i1I
    if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
    if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
  if ( oOo00Oo00O == "proxy-reply-action" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    ii1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    ii1 . proxy_reply_action = III1ii1iII
    if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
    if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
  if ( oOo00Oo00O == "require-signature" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    ii1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    I1i1I = True if ( III1ii1iII == "yes" ) else False
    ii1 . require_signature = I1i1I
    if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
    if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
  if ( oOo00Oo00O == "encrypt-json" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    IIiiIiI1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    I1i1I = True if ( III1ii1iII == "yes" ) else False
    ii1 . encrypt_json = I1i1I
    if 58 - 58: i11iIiiIii % I11i
    if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
  if ( oOo00Oo00O == "policy-name" ) :
   for Ii1IOo0o0 in range ( len ( oo ) ) :
    ii1 = oo [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    ii1 . policy = III1ii1iII
    if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
    if 16 - 16: I1IiiI * oO0o % IiII
    if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
  if ( oOo00Oo00O == "address" ) :
   for Ii1IOo0o0 in range ( len ( IiIIIiI1I1 ) ) :
    IIiiIiI1 = IiIIIiI1I1 [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    if ( III1ii1iII != "" ) : IIiiIiI1 . rloc . store_address ( III1ii1iII )
    if 44 - 44: oO0o
    if 88 - 88: I1Ii111 % Ii1I . II111iiii
  if ( oOo00Oo00O == "priority" ) :
   for Ii1IOo0o0 in range ( len ( IiIIIiI1I1 ) ) :
    IIiiIiI1 = IiIIIiI1I1 [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    if ( III1ii1iII == "" ) : III1ii1iII = "0"
    IIiiIiI1 . priority = int ( III1ii1iII )
    if 38 - 38: o0oOOo0O0Ooo
    if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
  if ( oOo00Oo00O == "weight" ) :
   for Ii1IOo0o0 in range ( len ( IiIIIiI1I1 ) ) :
    IIiiIiI1 = IiIIIiI1I1 [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    if ( III1ii1iII == "" ) : III1ii1iII = "0"
    IIiiIiI1 . weight = int ( III1ii1iII )
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
 for oOo00Oo00O in kv_pair . keys ( ) :
  iI11i1I1 = kv_pair [ oOo00Oo00O ]
  if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
  if ( oOo00Oo00O == "instance-id" ) :
   III1ii1iII = iI11i1I1 . split ( "-" )
   if ( III1ii1iII [ 0 ] == "" ) : continue
   if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
   I1111IIi = ( kv_pair . has_key ( "eid-prefix" ) == False or
 kv_pair [ "eid-prefix" ] == "" )
   Oo0oO = ( kv_pair . has_key ( "group-prefix" ) == False or
 kv_pair [ "group-prefix" ] == "" )
   if 1 - 1: OoO0O00 - oO0o . I11i . OoO0O00 / Oo0Ooo + I11i
   if ( I1111IIi and Oo0oO ) :
    II11iIiIIIiI . eid . store_iid_range ( int ( III1ii1iII [ 0 ] ) , int ( III1ii1iII [ 1 ] ) )
   else :
    II11iIiIIIiI . eid . instance_id = int ( III1ii1iII [ 0 ] )
    II11iIiIIIiI . group . instance_id = int ( III1ii1iII [ 0 ] )
    if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
    if 49 - 49: Ii1I / OoO0O00 . II111iiii
  if ( oOo00Oo00O == "eid-prefix" ) :
   II11iIiIIIiI . eid . store_prefix ( iI11i1I1 )
   if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
  if ( oOo00Oo00O == "group-prefix" ) :
   II11iIiIIIiI . group . store_prefix ( iI11i1I1 )
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
 if ( lispconfig . lisp_clause_syntax_error ( kv_pair , "eid-prefix" ,
 "prefix" ) ) : return
 for Ii1IOo0o0 in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  II11iIiIIIiI = lisp . lisp_ddt_entry ( )
  IiI111111IIII . append ( II11iIiIIIiI )
  if 37 - 37: I1Ii111 / OoOoOO00
  if 23 - 23: O0
 o00oO0oOo00 = [ ]
 if 81 - 81: OoO0O00
 if ( lispconfig . lisp_clause_syntax_error ( kv_pair , "address" ,
 "peer" ) ) : return
 for Ii1IOo0o0 in range ( len ( kv_pair [ "address" ] ) ) :
  IIi1 = lisp . lisp_ddt_node ( )
  IIi1 . map_server_peer = True
  o00oO0oOo00 . append ( IIi1 )
  if 45 - 45: iII111i / iII111i + I1Ii111 + ooOoO0o
  if 47 - 47: o0oOOo0O0Ooo + ooOoO0o
 for oOo00Oo00O in kv_pair . keys ( ) :
  iI11i1I1 = kv_pair [ oOo00Oo00O ]
  if ( oOo00Oo00O == "instance-id" ) :
   for OoO in range ( len ( IiI111111IIII ) ) :
    II11iIiIIIiI = IiI111111IIII [ OoO ]
    III1ii1iII = iI11i1I1 [ OoO ] . split ( "-" )
    if ( III1ii1iII [ 0 ] == "" ) : continue
    if 88 - 88: iII111i . II111iiii * II111iiii % I1Ii111
    I1111IIi = ( kv_pair [ "eid-prefix" ] [ OoO ] == "" and
 kv_pair [ "group-prefix" ] [ OoO ] == "" )
    if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
    if ( I1111IIi ) :
     II11iIiIIIiI . eid . store_iid_range ( int ( III1ii1iII [ 0 ] ) , int ( III1ii1iII [ 1 ] ) )
    else :
     II11iIiIIIiI . eid . instance_id = int ( III1ii1iII [ 0 ] )
     II11iIiIIIiI . group . instance_id = int ( III1ii1iII [ 0 ] )
     if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
     if 80 - 80: II111iiii
     if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
  if ( oOo00Oo00O == "eid-prefix" ) :
   for OoO in range ( len ( IiI111111IIII ) ) :
    II11iIiIIIiI = IiI111111IIII [ OoO ]
    oooO0 = iI11i1I1 [ OoO ]
    if ( oooO0 == "" ) : continue
    II11iIiIIIiI . eid . store_prefix ( oooO0 )
    if 46 - 46: I1Ii111
    if 60 - 60: o0oOOo0O0Ooo
  if ( oOo00Oo00O == "group-prefix" ) :
   for OoO in range ( len ( IiI111111IIII ) ) :
    II11iIiIIIiI = IiI111111IIII [ OoO ]
    oooO0 = iI11i1I1 [ OoO ]
    if ( oooO0 == "" ) : continue
    II11iIiIIIiI . group . store_prefix ( oooO0 )
    if 25 - 25: OoO0O00
    if 62 - 62: OOooOOo + O0
    if 98 - 98: o0oOOo0O0Ooo
  if ( oOo00Oo00O == "address" ) :
   for Ii1IOo0o0 in range ( len ( o00oO0oOo00 ) ) :
    IIi1 = o00oO0oOo00 [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    if ( III1ii1iII != "" ) : IIi1 . delegate_address . store_address ( III1ii1iII )
    if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
    if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
  if ( oOo00Oo00O == "priority" ) :
   for Ii1IOo0o0 in range ( len ( o00oO0oOo00 ) ) :
    IIi1 = o00oO0oOo00 [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    if ( III1ii1iII == "" ) : III1ii1iII = "0"
    IIi1 . priority = int ( III1ii1iII )
    if 82 - 82: Ii1I
    if 46 - 46: OoooooooOO . i11iIiiIii
  if ( oOo00Oo00O == "weight" ) :
   for Ii1IOo0o0 in range ( len ( o00oO0oOo00 ) ) :
    IIi1 = o00oO0oOo00 [ Ii1IOo0o0 ]
    III1ii1iII = iI11i1I1 [ Ii1IOo0o0 ]
    if ( III1ii1iII == "" ) : III1ii1iII = "0"
    IIi1 . weight = int ( III1ii1iII )
    if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
    if 87 - 87: Oo0Ooo . IiII
    if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
    if 55 - 55: OOooOOo . I1IiiI
    if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
    if 100 - 100: I1Ii111 * O0
    if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
    if 79 - 79: O0
 for II11iIiIIIiI in IiI111111IIII :
  II11iIiIIIiI . add_cache ( )
  for IIi1 in o00oO0oOo00 :
   II11iIiIIIiI . delegation_set . append ( IIi1 )
   if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
   if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 return
 if 57 - 57: OoO0O00 / ooOoO0o
 if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
 if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
 if 13 - 13: Ii1I . i11iIiiIii
 if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
def I111iI ( kv_pair ) :
 oOOo0 = lisp . lisp_address ( lisp . LISP_AFI_IPV6 , "" , 0 , 0 )
 if 16 - 16: oO0o % I1ii11iIi11i * i11iIiiIii % i11iIiiIii
 for oOo00Oo00O in kv_pair . keys ( ) :
  iI11i1I1 = kv_pair [ oOo00Oo00O ]
  if ( oOo00Oo00O == "instance-id" ) :
   if ( iI11i1I1 == "*" ) : iI11i1I1 = "-1"
   oOOo0 . instance_id = int ( iI11i1I1 )
   if 65 - 65: Ii1I - oO0o + oO0o + II111iiii
  if ( oOo00Oo00O == "eid-prefix" ) :
   oOOo0 . store_prefix ( iI11i1I1 )
   if ( oOOo0 . is_ipv6 ( ) == False ) : return
   if ( ( oOOo0 . mask_len % 4 ) != 0 ) : return
   if 96 - 96: OOooOOo % O0 / O0
   if 44 - 44: oO0o / I11i / I11i
   if 87 - 87: Oo0Ooo . I1IiiI - II111iiii + O0 / Oo0Ooo / oO0o
   if 25 - 25: I1IiiI . I1IiiI - OoOoOO00 % OoOoOO00 - i11iIiiIii / I1Ii111
   if 51 - 51: Oo0Ooo / OoOoOO00 . OOooOOo * o0oOOo0O0Ooo + OoO0O00 * IiII
   if 73 - 73: OoO0O00 + OoooooooOO - O0 - Ii1I - II111iiii
 lisp . lisp_eid_hashes . append ( oOOo0 )
 return
 if 99 - 99: ooOoO0o . Ii1I + I1Ii111 + OoooooooOO % o0oOOo0O0Ooo
 if 51 - 51: iIii1I11I1II1
 if 34 - 34: oO0o + I1IiiI - oO0o
 if 17 - 17: II111iiii % iII111i + I11i - iII111i / OOooOOo + ooOoO0o
 if 59 - 59: OOooOOo % OoOoOO00 . Ii1I * I1ii11iIi11i % I11i
 if 59 - 59: oO0o - iII111i
 if 15 - 15: I1Ii111 . i11iIiiIii . OoooooooOO / OoO0O00 % Ii1I
def OooooOOoo0 ( kv_pair ) :
 for oOo00Oo00O in kv_pair . keys ( ) :
  iI11i1I1 = kv_pair [ oOo00Oo00O ]
  if ( oOo00Oo00O == "map-register-key" ) :
   lisp . lisp_ms_encryption_keys = lisp . lisp_parse_auth_key ( iI11i1I1 )
   if 35 - 35: I11i % OOooOOo - oO0o
  if ( oOo00Oo00O == "json-key" ) :
   lisp . lisp_ms_json_keys = lisp . lisp_parse_auth_key ( iI11i1I1 )
   if 20 - 20: i1IIi - ooOoO0o
   if 30 - 30: I11i / I1IiiI
 return
 if 35 - 35: II111iiii % OOooOOo . ooOoO0o + ooOoO0o % II111iiii % II111iiii
 if 72 - 72: II111iiii + i1IIi + o0oOOo0O0Ooo
 if 94 - 94: oO0o . i1IIi - o0oOOo0O0Ooo % O0 - OoO0O00
 if 72 - 72: Ii1I
 if 1 - 1: OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
def I1II1 ( eid_key , group_key ) :
 if 86 - 86: iIii1I11I1II1 / OoOoOO00 . II111iiii
 OO0O00 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if ( eid_key ) :
  if ( eid_key == "[0]/0" ) :
   OO0O00 . store_iid_range ( 0 , 0 )
  else :
   OO0O00 . store_prefix ( eid_key )
   if 19 - 19: I1ii11iIi11i % OoooooooOO % IiII * o0oOOo0O0Ooo % O0
   if 67 - 67: I1IiiI . i1IIi
 i1i1iI1iiiI = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if ( group_key ) : i1i1iI1iiiI . store_prefix ( group_key )
 if 51 - 51: I1IiiI % I1Ii111 . oO0o / iIii1I11I1II1 / I11i . oO0o
 IIIii11 = lisp . lisp_print_eid_tuple ( OO0O00 , i1i1iI1iiiI )
 IIIii11 = lisp . lisp_print_cour ( IIIii11 )
 if 9 - 9: O0 % O0 - o0oOOo0O0Ooo
 if 51 - 51: I1IiiI . iIii1I11I1II1 - I1ii11iIi11i / O0
 if 52 - 52: o0oOOo0O0Ooo + O0 + iII111i + Oo0Ooo % iII111i
 if 75 - 75: I1IiiI . ooOoO0o . O0 * I1Ii111
 ii1 = lisp . lisp_site_eid_lookup ( OO0O00 , i1i1iI1iiiI , True )
 if ( ii1 == None ) :
  i11II1I11I1 = "Could not find EID {} in site cache" . format ( IIIii11 )
  return ( i11II1I11I1 )
  if 67 - 67: I1IiiI - o0oOOo0O0Ooo / I11i - i1IIi
  if 1 - 1: II111iiii
 O0oOo00o = lisp . space ( 4 )
 o0ooooO0o0O = lisp . space ( 8 )
 iiIi11iI1iii = lisp . space ( 12 )
 if 67 - 67: O0 / I1Ii111
 OOO0000oO = lisp . green ( "yes" , True ) if ii1 . registered else lisp . red ( "no" , True )
 if 15 - 15: OoOoOO00 % I1IiiI * I11i
 if 81 - 81: ooOoO0o - iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * I11i
 i11II1I11I1 = '<font face="Sans-Serif">'
 if 20 - 20: oO0o % IiII
 III1i1i11i = lisp . lisp_print_cour ( ii1 . site . site_name )
 oOo0 = lisp . lisp_print_cour ( str ( ii1 . site_id ) )
 OOOoOO = "0" if ii1 . xtr_id == 0 else lisp . lisp_hex_string ( ii1 . xtr_id )
 OOOoOO = lisp . lisp_print_cour ( "0x" + OOOoOO )
 I11IIIi = lisp . lisp_print_elapsed ( ii1 . first_registered )
 iIIiiI1II1i11 = lisp . lisp_print_elapsed ( ii1 . last_registered )
 if ( time . time ( ) - ii1 . last_registered >=
 ( ii1 . register_ttl / 2 ) and iIIiiI1II1i11 != "never" ) :
  iIIiiI1II1i11 = lisp . red ( iIIiiI1II1i11 , True )
  if 65 - 65: Ii1I / I11i / OoOoOO00
 if ( ii1 . last_registerer . afi == lisp . LISP_AFI_NONE ) :
  Ooo0000O0 = "none"
 else :
  Ooo0000O0 = ii1 . last_registerer . print_address_no_iid ( )
  if 24 - 24: o0oOOo0O0Ooo . oO0o + oO0o % OoOoOO00 + i11iIiiIii
 Ooo0000O0 = lisp . lisp_print_cour ( Ooo0000O0 )
 oo0o0000 = ", " + lisp . lisp_print_cour ( "site is in admin-shutdown" ) if ii1 . site . shutdown else ""
 if 11 - 11: iIii1I11I1II1
 IiIIII1i11I = ", accepting more specifics" if ii1 . accept_more_specifics else ""
 if 86 - 86: Oo0Ooo . O0 - OoooooooOO . OoO0O00 + Ii1I
 if ( IiIIII1i11I == "" and ii1 . dynamic ) : IiIIII1i11I = ", dynamic"
 i11II1I11I1 += '''Site name: {}, EID-prefix: {}, registered: {}{}{}
        <br>''' . format ( III1i1i11i , IIIii11 , OOO0000oO , IiIIII1i11I , oo0o0000 )
 if 57 - 57: o0oOOo0O0Ooo . i1IIi . IiII * i11iIiiIii + I1Ii111 . IiII
 i11II1I11I1 += "{}Description: {}<br>" . format ( O0oOo00o ,
 lisp . lisp_print_cour ( ii1 . site . description ) )
 i11II1I11I1 += "{}Last registerer: {}, xTR-ID: {}, site-ID: {}<br>" . format ( O0oOo00o , Ooo0000O0 , OOOoOO , oOo0 )
 if 57 - 57: I1Ii111
 if 32 - 32: Ii1I - Oo0Ooo % OoooooooOO . iII111i / IiII + I1IiiI
 o0O0oO0O00O0o = ii1 . print_flags ( False )
 o0O0oO0O00O0o = lisp . lisp_print_cour ( o0O0oO0O00O0o )
 II1I1Ii = "none"
 if ( ii1 . registered ) :
  II1I1Ii = "sha1" if ( ii1 . auth_sha1_or_sha2 ) else "sha2"
  if 62 - 62: O0 % I11i . I11i - iIii1I11I1II1 / i11iIiiIii
 i11II1I11I1 += ( "{}First registered: {}, last registered: {}, auth-type: " + "{}, registration flags: {}<br>" ) . format ( O0oOo00o ,
 # II111iiii + iIii1I11I1II1
 lisp . lisp_print_cour ( I11IIIi ) , lisp . lisp_print_cour ( iIIiiI1II1i11 ) ,
 lisp . lisp_print_cour ( II1I1Ii ) , o0O0oO0O00O0o )
 if 19 - 19: OoO0O00 - Oo0Ooo . O0
 ooOo00 = lisp . lisp_print_cour ( str ( ii1 . register_ttl ) + " seconds" )
 i11II1I11I1 += "{}{} registration timeout TTL: {}<br>" . format ( O0oOo00o , "Registered" if ii1 . use_register_ttl_requested else "Default" , ooOo00 )
 if 98 - 98: Oo0Ooo / I1IiiI . O0 + OoO0O00
 if 43 - 43: II111iiii . oO0o / I1ii11iIi11i
 if 20 - 20: I1IiiI
 if 95 - 95: iII111i - I1IiiI
 if 34 - 34: ooOoO0o * I1IiiI . i1IIi * ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if ( ii1 . policy ) :
  O0O0Oo00 = lisp . lisp_print_cour ( ii1 . policy )
  i11II1I11I1 += "{}Apply policy: '{}'<br>" . format ( O0oOo00o , O0O0Oo00 )
  if 80 - 80: oO0o + OOooOOo / I11i
  if 79 - 79: ooOoO0o
  if 48 - 48: I1Ii111 - o0oOOo0O0Ooo % Ii1I
  if 36 - 36: oO0o - Ii1I . Oo0Ooo - i11iIiiIii - OOooOOo * Oo0Ooo
  if 76 - 76: i11iIiiIii + o0oOOo0O0Ooo / I1ii11iIi11i - OoO0O00 - Ii1I + I1ii11iIi11i
 OOO0000oO = "yes" if ii1 . force_proxy_reply else "no"
 OOO0000oO = lisp . lisp_print_cour ( OOO0000oO )
 i11II1I11I1 += "{}Forcing proxy Map-Reply: {}<br>" . format ( O0oOo00o , OOO0000oO )
 if 51 - 51: iIii1I11I1II1 . ooOoO0o + iIii1I11I1II1
 if ( ii1 . force_ttl != None ) :
  ooOo00 = lisp . lisp_print_cour ( str ( ii1 . force_ttl ) + " seconds" )
  i11II1I11I1 += "{}Forced proxy Map-Reply TTL: {}<br>" . format ( O0oOo00o , ooOo00 )
  if 95 - 95: I1IiiI
  if 46 - 46: OoOoOO00 + OoO0O00
  if 70 - 70: iII111i / iIii1I11I1II1
 OOO0000oO = "yes" if ii1 . force_nat_proxy_reply else "no"
 OOO0000oO = lisp . lisp_print_cour ( OOO0000oO )
 i11II1I11I1 += "{}Forcing proxy Map-Reply for xTRs behind NATs: {}<br>" . format ( O0oOo00o , OOO0000oO )
 if 85 - 85: OoooooooOO % i1IIi * OoooooooOO / I1ii11iIi11i
 if 96 - 96: OoooooooOO + oO0o
 OOO0000oO = "yes" if ii1 . pitr_proxy_reply_drop else "no"
 OOO0000oO = lisp . lisp_print_cour ( OOO0000oO )
 i11II1I11I1 += "{}Send drop-action proxy Map-Reply to PITR: {}<br>" . format ( O0oOo00o , OOO0000oO )
 if 44 - 44: oO0o
 if 20 - 20: I11i + Ii1I / O0 % iIii1I11I1II1
 oOo0O = "not configured" if ii1 . proxy_reply_action == "" else ii1 . proxy_reply_action
 if 64 - 64: I1ii11iIi11i - iII111i + iII111i - I11i
 oOo0O = lisp . lisp_print_cour ( oOo0O )
 i11II1I11I1 += "{}Proxy Map-Reply action: {}<br>" . format ( O0oOo00o , oOo0O )
 if 30 - 30: iIii1I11I1II1 . I1IiiI . OOooOOo / o0oOOo0O0Ooo
 if ( ii1 . force_proxy_reply and ii1 . echo_nonce_capable ) :
  iiI1I1 = lisp . lisp_print_cour ( "yes" )
  i11II1I11I1 += "{}RLOCs are echo-nonce capable: {}<br>" . format ( O0oOo00o , iiI1I1 )
  if 56 - 56: I1IiiI . O0 + Oo0Ooo
  if 1 - 1: iII111i
 OOO0000oO = "yes" if ii1 . require_signature else "no"
 OOO0000oO = lisp . lisp_print_cour ( OOO0000oO )
 i11II1I11I1 += "{}Require signatures: {}<br>" . format ( O0oOo00o , OOO0000oO )
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 OOO0000oO = "yes" if ii1 . encrypt_json else "no"
 OOO0000oO = lisp . lisp_print_cour ( OOO0000oO )
 i11II1I11I1 += "{}Encrypt JSON RLOC-records: {}<br>" . format ( O0oOo00o , OOO0000oO )
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
 if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
 if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
 iiiI = "any" if len ( ii1 . site . allowed_rlocs ) == 0 else ""
 if ( iiiI != "" ) : iiiI = lisp . lisp_print_cour ( iiiI )
 i11II1I11I1 += "{}Allowed RLOC-set: {}<br>" . format ( O0oOo00o , iiiI )
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
   i11II1I11I1 += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>''' . format ( o0ooooO0o0O , I1ii1 , O00 , Oo0o0000OOoO , IiIi1I1ii111 , IiIiIi , IIIII1 , iIi1Ii1i1iI )
   if 71 - 71: OoOoOO00
   if 14 - 14: i11iIiiIii % OOooOOo
   if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
   if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 iII1iiiiIII = "none" if len ( ii1 . registered_rlocs ) == 0 else ""
 if ( iII1iiiiIII != "" ) : iII1iiiiIII = lisp . lisp_print_cour ( iII1iiiiIII )
 i11II1I11I1 += "<br>Registered RLOC-set ({}): {}<br>" . format ( "merge-semantics" if ( ii1 . merge_register_requested ) else "replacement-semantics" ,
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
   i11II1I11I1 += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>''' . format ( O0oOo00o , I1ii1 , O00 , Oo0o0000OOoO , IiIi1I1ii111 , IiIiIi , IIIII1 , iIi1Ii1i1iI )
   if 37 - 37: ooOoO0o % i11iIiiIii % II111iiii . O0 . Ii1I
   if ( IIiiIiI1 . geo ) :
    OO0oOOoo = lisp . lisp_print_cour ( IIiiIiI1 . geo . print_geo_url ( ) )
    i11II1I11I1 += "{}geo: {}<br>" . format ( iiIi11iI1iii , OO0oOOoo )
    if 52 - 52: o0oOOo0O0Ooo % Oo0Ooo
   if ( IIiiIiI1 . elp ) :
    Oo000ooOOO = lisp . lisp_print_cour ( IIiiIiI1 . elp . print_elp ( False ) )
    i11II1I11I1 += "{}elp: {}<br>" . format ( iiIi11iI1iii , Oo000ooOOO )
    if 31 - 31: iIii1I11I1II1 % I11i % ooOoO0o . Ii1I - I11i
   if ( IIiiIiI1 . rle ) :
    ii11i1ii1Ii = lisp . lisp_print_cour ( IIiiIiI1 . rle . print_rle ( True , True ) )
    i11II1I11I1 += "{}rle: {}<br>" . format ( iiIi11iI1iii , ii11i1ii1Ii )
    if 46 - 46: I1ii11iIi11i + II111iiii + iIii1I11I1II1
   if ( IIiiIiI1 . json ) :
    OOo0 = lisp . lisp_print_cour ( IIiiIiI1 . json . print_json ( True ) )
    i11II1I11I1 += "{}json: {}<br>" . format ( iiIi11iI1iii , OOo0 )
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
 i11II1I11I1 += "<br>Individual registrations: {}<br>" . format ( iII1iiiiIII )
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
 if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
 if 97 - 97: I1IiiI / iII111i
 if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
 O0iII1 = [ ]
 for II in ii1 . individual_registrations . values ( ) :
  if ( II . registered == False ) : continue
  ooOo00 = II . register_ttl / 2
  if ( time . time ( ) - II . last_registered >= ooOo00 ) : continue
  O0iII1 . append ( II )
  if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 for II in ii1 . individual_registrations . values ( ) :
  if ( II . registered == False ) : continue
  ooOo00 = II . register_ttl / 2
  if ( time . time ( ) - II . last_registered >= ooOo00 ) : O0iII1 . append ( II )
  if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 for II in ii1 . individual_registrations . values ( ) :
  if ( II . registered == False ) : O0iII1 . append ( II )
  if 45 - 45: I1Ii111
  if 83 - 83: OoOoOO00 . OoooooooOO
 for ii1 in O0iII1 :
  OOO0000oO = lisp . green ( "yes" , True ) if ii1 . registered else lisp . red ( "no" , True )
  if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
  II1I1Ii = "sha1" if ( ii1 . auth_sha1_or_sha2 ) else "sha2"
  II1I1Ii = lisp . lisp_print_cour ( II1I1Ii )
  ooOo00 = str ( ii1 . register_ttl / 60 ) + " mins"
  ooOo00 = lisp . lisp_print_cour ( ooOo00 )
  o0O0oO0O00O0o = ii1 . print_flags ( False )
  o0O0oO0O00O0o = lisp . lisp_print_cour ( o0O0oO0O00O0o )
  I1ii1 = lisp . lisp_print_cour ( ii1 . last_registerer . print_address_no_iid ( ) )
  if 62 - 62: OoO0O00 / I1ii11iIi11i
  I11IIIi = lisp . lisp_print_elapsed ( ii1 . first_registered )
  I11IIIi = lisp . lisp_print_cour ( I11IIIi )
  iIIiiI1II1i11 = lisp . lisp_print_elapsed ( ii1 . last_registered )
  if ( time . time ( ) - ii1 . last_registered >=
 ( ii1 . register_ttl / 2 ) and iIIiiI1II1i11 != "never" ) :
   iIIiiI1II1i11 = lisp . red ( iIIiiI1II1i11 , True )
   if 7 - 7: OoooooooOO . IiII
  iIIiiI1II1i11 = lisp . lisp_print_cour ( iIIiiI1II1i11 )
  oOo0 = lisp . lisp_print_cour ( str ( ii1 . site_id ) )
  OOOoOO = lisp . lisp_print_cour ( lisp . lisp_hex_string ( ii1 . xtr_id ) )
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
  i11II1I11I1 += '''
            {}Registerer: {}, xTR-ID: 0x{}, site-id: {}, registered: {}<br>
            {}First registered: {}, last registered: {}, registration TTL: {},
            auth-type: {}, registration flags: {}<br>
        ''' . format ( O0oOo00o , I1ii1 , OOOoOO , oOo0 , OOO0000oO , O0oOo00o , I11IIIi , iIIiiI1II1i11 , ooOo00 , II1I1Ii ,
 o0O0oO0O00O0o )
  if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
  iII1iiiiIII = "none" if len ( ii1 . registered_rlocs ) == 0 else ""
  iII1iiiiIII = lisp . lisp_print_cour ( iII1iiiiIII )
  i11II1I11I1 += "{}Registered RLOC-set: {}<br>" . format ( O0oOo00o , iII1iiiiIII )
  if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
  for IIiiIiI1 in ii1 . registered_rlocs :
   I1ii1 = lisp . lisp_print_cour ( IIiiIiI1 . rloc . print_address ( ) )
   O00 = lisp . lisp_print_cour ( IIiiIiI1 . print_state ( ) )
   Oo0o0000OOoO = lisp . lisp_print_cour ( str ( IIiiIiI1 . priority ) )
   IiIi1I1ii111 = lisp . lisp_print_cour ( str ( IIiiIiI1 . weight ) )
   IiIiIi = lisp . lisp_print_cour ( str ( IIiiIiI1 . mpriority ) )
   IIIII1 = lisp . lisp_print_cour ( str ( IIiiIiI1 . mweight ) )
   iIi1Ii1i1iI = IIiiIiI1 . print_rloc_name ( True )
   if ( iIi1Ii1i1iI != "" ) : iIi1Ii1i1iI = ", " + iIi1Ii1i1iI
   if 92 - 92: ooOoO0o
   i11II1I11I1 += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>''' . format ( o0ooooO0o0O , I1ii1 , O00 , Oo0o0000OOoO , IiIi1I1ii111 , IiIiIi , IIIII1 , iIi1Ii1i1iI )
   if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
   if ( IIiiIiI1 . geo ) :
    OO0oOOoo = lisp . lisp_print_cour ( IIiiIiI1 . geo . print_geo_url ( ) )
    i11II1I11I1 += "{}geo: {}<br>" . format ( iiIi11iI1iii , OO0oOOoo )
    if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
   if ( IIiiIiI1 . elp ) :
    Oo000ooOOO = lisp . lisp_print_cour ( IIiiIiI1 . elp . print_elp ( False ) )
    i11II1I11I1 += "{}elp: {}<br>" . format ( iiIi11iI1iii , Oo000ooOOO )
    if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
   if ( IIiiIiI1 . rle ) :
    ii11i1ii1Ii = lisp . lisp_print_cour ( IIiiIiI1 . rle . print_rle ( True , True ) )
    i11II1I11I1 += "{}rle: {}<br>" . format ( iiIi11iI1iii , ii11i1ii1Ii )
    if 92 - 92: I11i . I1Ii111
   if ( IIiiIiI1 . json ) :
    OOo0 = lisp . lisp_print_cour ( IIiiIiI1 . json . print_json ( True ) )
    i11II1I11I1 += "{}json: {}<br>" . format ( iiIi11iI1iii , OOo0 )
    if 85 - 85: I1ii11iIi11i . I1Ii111
    if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
  i11II1I11I1 += "<br>"
  if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
 i11II1I11I1 += "</font>"
 return ( i11II1I11I1 )
 if 18 - 18: iIii1I11I1II1 % I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
def iI1iIIIi1i ( ddt_entry , output ) :
 ooo = ddt_entry . print_eid_tuple ( )
 OooooO0oOO = ddt_entry . map_referrals_sent
 if 30 - 30: OoooooooOO - OoooooooOO . O0 / iII111i
 if ( ddt_entry . is_auth_prefix ( ) ) :
  output += lispconfig . lisp_table_row ( ooo , "--" , "auth-prefix" , "--" ,
 OooooO0oOO )
  return ( [ True , output ] )
  if 31 - 31: OOooOOo + o0oOOo0O0Ooo . OoooooooOO
  if 89 - 89: II111iiii + i1IIi + II111iiii
 for IiII1II11I in ddt_entry . delegation_set :
  OoO000 = IiII1II11I . delegate_address
  O0Oo00O = str ( IiII1II11I . priority ) + "/" + str ( IiII1II11I . weight )
  output += lispconfig . lisp_table_row ( ooo , OoO000 . print_address ( ) ,
 IiII1II11I . print_node_type ( ) , O0Oo00O , OooooO0oOO )
  if ( ooo != "" ) :
   ooo = ""
   OooooO0oOO = ""
   if 91 - 91: oO0o % Ii1I . ooOoO0o / iII111i * iIii1I11I1II1
   if 43 - 43: ooOoO0o + iII111i - I1Ii111 / O0 * Oo0Ooo + I1IiiI
 return ( [ True , output ] )
 if 28 - 28: Ii1I * o0oOOo0O0Ooo - OoO0O00
 if 42 - 42: I1ii11iIi11i
 if 76 - 76: I1ii11iIi11i * II111iiii . I1IiiI - Oo0Ooo + oO0o + i11iIiiIii
 if 28 - 28: oO0o
 if 70 - 70: IiII
 if 34 - 34: I1Ii111 % IiII
 if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
 if 83 - 83: oO0o + OoooooooOO
def I111IiiIi1 ( ddt_entry , output ) :
 if 88 - 88: OoooooooOO
 if 84 - 84: OoOoOO00 / I11i * iII111i / oO0o - i11iIiiIii . Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if ( ddt_entry . group . is_null ( ) ) :
  return ( iI1iIIIi1i ( ddt_entry , output ) )
  if 41 - 41: Ii1I
  if 77 - 77: I1Ii111
 if ( ddt_entry . source_cache == None ) : return ( [ True , output ] )
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 output = ddt_entry . source_cache . walk_cache ( iI1iIIIi1i ,
 output )
 return ( [ True , output ] )
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
 if 95 - 95: IiII
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
 if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
def oOoOOo0oo0 ( ) :
 o0O0Oo00Oo0o = "{} entries configured" . format ( lisp . lisp_ddt_cache . cache_size ( ) )
 OOOo = lisp . lisp_span ( "LISP-MS Configured Map-Server Peers & " + "Authoritative Prefixes:" , o0O0Oo00Oo0o )
 if 88 - 88: i11iIiiIii - ooOoO0o
 i11II1I11I1 = lispconfig . lisp_table_header ( OOOo , "EID-Prefix or (S,G)" ,
 "Peer Address" , "Delegation Type" , "Priority/Weight" ,
 "Map-Referrals Sent" )
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 i11II1I11I1 = lisp . lisp_ddt_cache . walk_cache ( I111IiiIi1 , i11II1I11I1 )
 i11II1I11I1 += lispconfig . lisp_table_footer ( )
 return ( i11II1I11I1 )
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if 10 - 10: II111iiii . iII111i
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 if 88 - 88: iII111i
def iiI11I1i1i1iI ( input_str ) :
 OO0O00 , OoOOo000o0 , i1i1iI1iiiI , ii = lispconfig . lisp_get_lookup_string ( input_str )
 if 32 - 32: Ii1I % I1ii11iIi11i - OOooOOo * o0oOOo0O0Ooo + I11i
 if 10 - 10: I1IiiI / Oo0Ooo % I1ii11iIi11i * ooOoO0o
 i11II1I11I1 = "<br>"
 if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
 if 98 - 98: i1IIi
 if 65 - 65: OoOoOO00 / OoO0O00 % IiII
 if 45 - 45: OoOoOO00
 ii1 = lisp . lisp_site_eid_lookup ( OO0O00 , i1i1iI1iiiI , OoOOo000o0 )
 if ( ii1 and ii1 . is_star_g ( ) == False ) :
  IIIii11 = ii1 . print_eid_tuple ( )
  oOooOO = lisp . green ( "registered" , True ) if ii1 . registered else lisp . red ( "not registered" , True )
  if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
  i11II1I11I1 += "{} '{}' {} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Site" ) ,
  # OoOoOO00 - I11i - Ii1I . i1IIi
 lisp . lisp_print_cour ( ii1 . site . site_name ) ,
 lisp . lisp_print_sans ( "entry" ) ,
 lisp . lisp_print_cour ( IIIii11 ) ,
 lisp . lisp_print_sans ( "found for EID" ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "site EID is" ) ,
 lisp . lisp_print_cour ( oOooOO ) )
  return ( i11II1I11I1 + "<br>" )
  if 35 - 35: II111iiii * I11i - OoooooooOO . I11i . I11i
  if 11 - 11: I1Ii111 / OoOoOO00 + I11i % iIii1I11I1II1
  if 42 - 42: I1ii11iIi11i * OoOoOO00 % ooOoO0o - OoOoOO00 . i11iIiiIii - I1Ii111
  if 84 - 84: I1Ii111 - I1ii11iIi11i / I11i
  if 13 - 13: IiII - Oo0Ooo - ooOoO0o
 O00Oo , Ii1111IiIi , oOo0O = lisp . lisp_ms_compute_neg_prefix ( OO0O00 , i1i1iI1iiiI )
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if ( i1i1iI1iiiI . is_null ( ) ) :
  O00Oo = lisp . lisp_print_cour ( O00Oo . print_prefix ( ) )
 else :
  Ii1111IiIi = lisp . lisp_print_cour ( Ii1111IiIi . print_prefix ( ) )
  O00Oo = lisp . lisp_print_cour ( O00Oo . print_prefix ( ) )
  O00Oo = "(" + O00Oo + ", " + Ii1111IiIi + ")"
  if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
  if 68 - 68: OoooooooOO % II111iiii
 if ( oOo0O == lisp . LISP_DDT_ACTION_NOT_AUTH ) :
  Ii1i1i1111 = "Site entry not found for non-authoritative EID"
  i11II1I11I1 += "{} {} {} {}" . format ( lisp . lisp_print_sans ( Ii1i1i1111 ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 O00Oo )
  if 57 - 57: Ii1I % II111iiii
  if 67 - 67: ooOoO0o + I1IiiI * i11iIiiIii - oO0o / IiII % iII111i
  if 92 - 92: Ii1I - oO0o - ooOoO0o % OoooooooOO / OOooOOo
  if 19 - 19: Oo0Ooo - OoO0O00
  if 56 - 56: I1ii11iIi11i
 if ( oOo0O == lisp . LISP_DDT_ACTION_DELEGATION_HOLE ) :
  II11iIiIIIiI = lisp . lisp_ddt_cache_lookup ( OO0O00 , i1i1iI1iiiI , False )
  if ( II11iIiIIIiI == None or II11iIiIIIiI . is_auth_prefix ( ) == False ) :
   Ii1i1i1111 = "Could not find Authoritative-prefix entry for"
   i11II1I11I1 += "{} {} {} {}" . format ( lisp . lisp_print_sans ( Ii1i1i1111 ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 O00Oo )
  else :
   IIIii11 = II11iIiIIIiI . print_eid_tuple ( )
   i11II1I11I1 += "{} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Authoritative-prefix entry" ) ,
   # I11i / OoooooooOO
 lisp . lisp_print_cour ( IIIii11 ) ,
 lisp . lisp_print_sans ( "found for EID" ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 O00Oo )
   if 16 - 16: I1Ii111 . oO0o
   if 67 - 67: Oo0Ooo - I1IiiI % i1IIi
 return ( i11II1I11I1 + "<br>" )
 if 19 - 19: o0oOOo0O0Ooo
 if 42 - 42: i1IIi . I1IiiI / i1IIi + Ii1I
 if 54 - 54: ooOoO0o % OOooOOo . I1Ii111 + oO0o - OOooOOo * I1IiiI
 if 92 - 92: o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % OoO0O00 % IiII . OoooooooOO
 if 52 - 52: ooOoO0o / i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + o0oOOo0O0Ooo
 if 71 - 71: oO0o % I11i * OoOoOO00 . O0 / Ii1I . I1ii11iIi11i
 if 58 - 58: Oo0Ooo / oO0o
def iIII1I1i1i ( site_eid , site , first , output ) :
 if 79 - 79: Ii1I . OoO0O00
 IIIii11 = site_eid . print_eid_tuple ( )
 IIIii11 = IIIii11 . replace ( "no-address/0" , "" )
 if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
 if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
 if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
 if 52 - 52: i1IIi
 OO0O00 = site_eid . eid
 i1i1iI1iiiI = site_eid . group
 if ( OO0O00 . is_null ( ) and i1i1iI1iiiI . is_null ( ) == False ) :
  o000 = "{}-*-{}" . format ( i1i1iI1iiiI . instance_id , i1i1iI1iiiI . print_prefix_url ( ) )
  IIIii11 = "<a href='/lisp/show/site/{}'>{}</a>" . format ( o000 , IIIii11 )
  if 94 - 94: o0oOOo0O0Ooo + O0 / I11i . I1IiiI + OOooOOo . iIii1I11I1II1
 if ( OO0O00 . is_null ( ) == False and i1i1iI1iiiI . is_null ( ) ) :
  o000 = "{}" . format ( OO0O00 . print_prefix_url ( ) )
  if 62 - 62: OoOoOO00 / I1IiiI - I1ii11iIi11i - I1IiiI + i11iIiiIii + i1IIi
  if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
  if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
  if 8 - 8: o0oOOo0O0Ooo
  if ( o000 . find ( "'" ) != - 1 ) :
   o000 = o000 . replace ( "'" , "name-" , 1 )
   o000 = o000 . replace ( "'" , "" )
  else :
   if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
   if 78 - 78: Ii1I / II111iiii % OoOoOO00
   if 52 - 52: OOooOOo - iII111i * oO0o
   if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
   o000 = o000 . replace ( "+" , "plus-" )
   if 36 - 36: O0 + Oo0Ooo
  IIIii11 = "<a href='/lisp/show/site/{}'>{}</a>" . format ( o000 , IIIii11 )
  if 5 - 5: Oo0Ooo * OoOoOO00
 if ( OO0O00 . is_null ( ) == False and i1i1iI1iiiI . is_null ( ) == False ) :
  o000 = "{}-{}" . format ( OO0O00 . print_prefix_url ( ) , i1i1iI1iiiI . print_prefix_url ( ) )
  IIIii11 = "<a href='/lisp/show/site/{}'>{}</a>" . format ( o000 , IIIii11 )
  if 46 - 46: ooOoO0o
  if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 O0OO0O = site . site_name if first else ""
 o0O0oO0O00O0o = "--"
 if ( site_eid . registered ) : o0O0oO0O00O0o = site_eid . print_flags ( True )
 IiiiIiiI = "--"
 ooOo00 = "--"
 if ( site_eid . last_registerer . afi != lisp . LISP_AFI_NONE ) :
  IiiiIiiI = site_eid . last_registerer . print_address_no_iid ( )
  ooOo00 = str ( datetime . timedelta ( seconds = site_eid . register_ttl ) )
  if 72 - 72: i1IIi
 oOooOO = lisp . green ( "yes" , True ) if site_eid . registered else lisp . red ( "no" , True )
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
 if ( site . shutdown ) : oOooOO = lisp . red ( "admin-shutdown" , True )
 if 63 - 63: I1ii11iIi11i
 if ( site_eid . dynamic ) :
  oOooOO += " (dynamic)"
 elif ( site_eid . accept_more_specifics ) :
  oOooOO = "(ams)"
  if 6 - 6: ooOoO0o / I1ii11iIi11i
  if 57 - 57: I11i
 oO0 = lisp . lisp_print_elapsed ( site_eid . last_registered )
 if ( time . time ( ) - site_eid . last_registered >=
 ( site_eid . register_ttl / 2 ) and oO0 != "never" ) :
  oO0 = lisp . red ( oO0 , True )
  if 87 - 87: oO0o % Ii1I
 oo0OOOoOo = lisp . lisp_print_elapsed ( site_eid . first_registered )
 if 21 - 21: OoO0O00 - O0 . oO0o + Ii1I . iIii1I11I1II1 - OoOoOO00
 if ( site_eid . accept_more_specifics ) :
  I11IIIiIi11 = len ( site_eid . more_specific_registrations )
  o0O0Oo00Oo0o = "{} EID-prefixes registered" . format ( I11IIIiIi11 )
  IIIii11 = lisp . lisp_span ( IIIii11 , o0O0Oo00Oo0o )
  if 39 - 39: Ii1I % O0 % OoOoOO00 . i1IIi
  if 86 - 86: OoO0O00 * OoooooooOO
 output += lispconfig . lisp_table_row ( O0OO0O , IIIii11 , oOooOO ,
 IiiiIiiI , oo0OOOoOo , oO0 , ooOo00 , o0O0oO0O00O0o )
 return ( output )
 if 71 - 71: iIii1I11I1II1 - OOooOOo . I1IiiI % OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
def IiiIIiiiiii ( parameter ) :
 if 100 - 100: Oo0Ooo + o0oOOo0O0Ooo - O0 % II111iiii . iII111i
 if 92 - 92: II111iiii * OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 if ( parameter != "" ) :
  if ( parameter . find ( "@lookup" ) != - 1 ) :
   parameter = parameter . split ( "@" )
   return ( iiI11I1i1i1iI ( parameter [ 0 ] ) )
   if 46 - 46: i11iIiiIii - O0 . oO0o
  OO0O00 = parameter . split ( "%" ) [ 0 ]
  i1i1iI1iiiI = parameter . split ( "%" ) [ 1 ]
  return ( I1II1 ( OO0O00 , i1i1iI1iiiI ) )
  if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
  if 83 - 83: I1Ii111
  if 48 - 48: II111iiii * OOooOOo * I1Ii111
  if 50 - 50: IiII % i1IIi
  if 21 - 21: OoooooooOO - iIii1I11I1II1
 Ii1i1i1111 = "Enter EID for Site-Cache lookup:"
 OO0OoOOO0 = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 i11II1I11I1 = '''
        <form action="/lisp/show/site/lookup" method="post">
        <i><font face="Courier New" size="3">
        {} {}
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></i></form>
    ''' . format ( lisp . lisp_print_sans ( Ii1i1i1111 ) , OO0OoOOO0 )
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
 if ( lisp . lisp_ddt_cache . cache_count != 0 ) :
  i11II1I11I1 += oOoOOo0oo0 ( )
  if 10 - 10: OoO0O00 / Oo0Ooo
  if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
  if 57 - 57: O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 o0O0Oo00Oo0o = ( "{} sites & {} eid-prefixes configured\n{} eid-prefixes " + "registered" ) . format ( len ( II1Ii1iI1i ) ,
 # oO0o / OoooooooOO . iII111i
 lisp . lisp_sites_by_eid . cache_size ( ) , lisp . lisp_registered_count )
 if 34 - 34: iII111i - OoooooooOO . I1IiiI / II111iiii
 OOOo = lisp . lisp_span ( "LISP-MS Site Information:" , o0O0Oo00Oo0o )
 i11II1I11I1 += lispconfig . lisp_table_header ( OOOo , "Site Name" ,
 "EID-Prefix or (S,G)" , "Registered" , "Last Registerer" ,
 "First Registered" , "Last Registered" , "TTL" , "Registration Flags" )
 if 27 - 27: OoO0O00 / Oo0Ooo * ooOoO0o - OoO0O00
 for O0OO0O in iiI1iIiI :
  OOooO0OOoo = II1Ii1iI1i [ O0OO0O ]
  iI11iiii1I = True
  for i1i in OOooO0OOoo . allowed_prefixes_sorted :
   ii1 = OOooO0OOoo . allowed_prefixes [ i1i ]
   if 3 - 3: O0 % OoooooooOO / OOooOOo
   i11II1I11I1 = iIII1I1i1i ( ii1 , OOooO0OOoo , iI11iiii1I , i11II1I11I1 )
   if ( iI11iiii1I ) : iI11iiii1I = False
   if 89 - 89: II111iiii / oO0o
   for IIo0OoO00 in ii1 . more_specific_registrations :
    i11II1I11I1 = iIII1I1i1i ( IIo0OoO00 , OOooO0OOoo , iI11iiii1I ,
 i11II1I11I1 )
    if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
    if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
    if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
    if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 i11II1I11I1 += lispconfig . lisp_table_footer ( )
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
 if 54 - 54: II111iiii . I11i
 if 73 - 73: OoOoOO00 . I1IiiI
 if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
 if 48 - 48: iII111i * iII111i
 if 13 - 13: Ii1I / I11i + OoOoOO00 . o0oOOo0O0Ooo % ooOoO0o
 if 48 - 48: I1IiiI / i11iIiiIii - o0oOOo0O0Ooo * oO0o / OoooooooOO
 if ( lisp . lisp_pubsub_cache == { } ) : return ( i11II1I11I1 )
 if 89 - 89: iIii1I11I1II1 / I1IiiI - II111iiii / Ii1I . i11iIiiIii . Ii1I
 if 48 - 48: O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 OOOo = "LISP-MS Subscriber Information:"
 i11II1I11I1 += lispconfig . lisp_table_header ( OOOo , "EID-prefix" ,
 "Uptime<br>TTL" , "Subscriber RLOC" , "xTR-ID" , "Nonce" ,
 "Map-Notifies<br>Sent" )
 if 36 - 36: IiII
 for i1iiI in lisp . lisp_pubsub_cache :
  OO0O00 = i1iiI
  for o0OooooOoOO in lisp . lisp_pubsub_cache [ i1iiI ] . values ( ) :
   i1i1IIIIIIIi = o0OooooOoOO . itr . print_address_no_iid ( ) + ":" + str ( o0OooooOoOO . port )
   if 65 - 65: o0oOOo0O0Ooo
   I1i = lisp . lisp_print_elapsed ( o0OooooOoOO . uptime ) + "<br>" + str ( o0OooooOoOO . ttl ) + " mins"
   if 49 - 49: I1ii11iIi11i
   if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
   ii1iI1II11ii = "--"
   if ( o0OooooOoOO . xtr_id != None ) :
    ii1iI1II11ii = "0x" + lisp . lisp_hex_string ( o0OooooOoOO . xtr_id )
    if 8 - 8: ooOoO0o * O0
   OOoO = "0x" + lisp . lisp_hex_string ( o0OooooOoOO . nonce )
   IiIIII = o0OooooOoOO . map_notify_count
   i11II1I11I1 += lispconfig . lisp_table_row ( OO0O00 , I1i , i1i1IIIIIIIi , ii1iI1II11ii ,
 OOoO , IiIIII )
   OO0O00 = ""
   if 89 - 89: OoO0O00 / I1IiiI
   if 16 - 16: Oo0Ooo + ooOoO0o / Oo0Ooo / OoO0O00 % oO0o % I1ii11iIi11i
 i11II1I11I1 += lispconfig . lisp_table_footer ( )
 return ( i11II1I11I1 )
 if 22 - 22: II111iiii * OoO0O00 * I11i + I1ii11iIi11i * o0oOOo0O0Ooo
 if 100 - 100: i1IIi / IiII
 if 3 - 3: II111iiii % I1ii11iIi11i - OoooooooOO * Oo0Ooo . iIii1I11I1II1
 if 37 - 37: iII111i / Oo0Ooo . I11i * I11i
 if 80 - 80: OOooOOo % I1ii11iIi11i
O0Ooo = {
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

 "lisp eid-crypto-hash" : [ I111iI , {
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "eid-prefix" : [ False ] } ] ,

 "lisp encryption-keys" : [ OooooOOoo0 , {
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

 "show site" : [ IiiIIiiiiii , { } ]
 }
if 78 - 78: OoO0O00 % IiII * i1IIi
if 66 - 66: Ii1I . I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1
if 51 - 51: I11i . Oo0Ooo
if 45 - 45: i1IIi - Oo0Ooo / O0 . I1ii11iIi11i
if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
if 56 - 56: OoooooooOO - I11i - i1IIi
if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
def I1Iii1iI1 ( site_eid , delete_list ) :
 o0 = lisp . lisp_get_timestamp ( )
 if 93 - 93: i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / o0oOOo0O0Ooo / II111iiii
 if ( site_eid . registered == False ) : return ( delete_list )
 if ( site_eid . last_registered + site_eid . register_ttl > o0 ) :
  return ( delete_list )
  if 49 - 49: OOooOOo . I1ii11iIi11i . i11iIiiIii - II111iiii / Ii1I
  if 62 - 62: OOooOOo
  if 1 - 1: IiII / IiII - i11iIiiIii
  if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
  if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
 iIi1I1 = "merge" if site_eid . merge_register_requested else "replacement"
 O0oOoo0OoO0O = "dynamic " if site_eid . dynamic else ""
 site_eid . registered = False
 lisp . lisp_registered_count -= 1
 oo00 = lisp . lisp_print_elapsed ( site_eid . first_registered )
 oooO0 = site_eid . print_eid_tuple ( )
 IiiiIiiI = site_eid . last_registerer . print_address_no_iid ( )
 if 33 - 33: iIii1I11I1II1 / iII111i - I1IiiI * I11i
 lisp . lprint ( ( "Registration timeout for {}EID-prefix {} site '{}' " + "from {}, was registered for {}, {}-semantics" ) . format ( O0oOoo0OoO0O ,
 # ooOoO0o . iIii1I11I1II1 * I1Ii111 * I1IiiI
 lisp . green ( oooO0 , False ) , site_eid . site . site_name , IiiiIiiI ,
 oo00 , iIi1I1 ) )
 if 56 - 56: I1IiiI . I11i * IiII % OoO0O00 + I1Ii111 + IiII
 if ( delete_list == None ) : return ( None )
 if 94 - 94: iIii1I11I1II1 % OoooooooOO
 if 77 - 77: I1ii11iIi11i / i1IIi / Oo0Ooo % OOooOOo
 if 48 - 48: I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 delete_list . append ( site_eid )
 return ( delete_list )
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
 if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
 if 62 - 62: o0oOOo0O0Ooo
 if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
 if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
def i1IIi1i1Ii1 ( parent , rle_list ) :
 Iii = [ ]
 for IiII1II11I in parent . individual_registrations . values ( ) :
  Iii = I1Iii1iI1 ( IiII1II11I , Iii )
  if 63 - 63: IiII + o0oOOo0O0Ooo
  if 1 - 1: I1ii11iIi11i / OoO0O00 + oO0o . o0oOOo0O0Ooo / I1ii11iIi11i - iII111i
 if ( len ( Iii ) != 0 and parent . merge_in_site_eid ( None ) ) :
  rle_list . append ( [ parent . eid , parent . group ] )
  if 5 - 5: OOooOOo
 return ( rle_list )
 if 4 - 4: iII111i % I1Ii111 / OoO0O00 . OOooOOo / OOooOOo - I1ii11iIi11i
 if 79 - 79: I1ii11iIi11i + I1Ii111
 if 10 - 10: Oo0Ooo + O0
 if 43 - 43: iIii1I11I1II1 / II111iiii % o0oOOo0O0Ooo - OOooOOo
 if 62 - 62: I11i
 if 63 - 63: OOooOOo + ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
def oo0o ( ) :
 global i111I
 if 51 - 51: OOooOOo . I1IiiI
 lisp . lisp_set_exception ( )
 if 73 - 73: OoooooooOO . I1IiiI / I1Ii111 % Ii1I
 o0OO0O00o = [ ]
 for OOooO0OOoo in II1Ii1iI1i . values ( ) :
  for ii1 in OOooO0OOoo . allowed_prefixes . values ( ) :
   if ( ii1 . merge_register_requested == False ) :
    I1Iii1iI1 ( ii1 , None )
    if 73 - 73: i1IIi - OOooOOo
    if 80 - 80: ooOoO0o + i11iIiiIii / oO0o * I1ii11iIi11i * I1ii11iIi11i + IiII
   OoOOo = ii1
   if 46 - 46: I1IiiI / Ii1I . I1Ii111 % i11iIiiIii + o0oOOo0O0Ooo + OoooooooOO
   if 93 - 93: Ii1I - IiII . I1Ii111 % iIii1I11I1II1 % I11i
   if 46 - 46: i11iIiiIii - OOooOOo * O0 - i11iIiiIii + o0oOOo0O0Ooo
   if 66 - 66: I1IiiI - IiII
   if 33 - 33: I1IiiI / OoO0O00
   o0OO0O00o = i1IIi1i1Ii1 ( OoOOo , o0OO0O00o )
   if 12 - 12: II111iiii
   if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
   if 25 - 25: oO0o
   if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
   if 43 - 43: I1ii11iIi11i - iII111i
   Iii = [ ]
   for O000O in OoOOo . more_specific_registrations :
    o0OO0O00o = i1IIi1i1Ii1 ( O000O , o0OO0O00o )
    Iii = I1Iii1iI1 ( O000O , Iii )
    if 98 - 98: iIii1I11I1II1 + I1Ii111 % OoOoOO00 + I11i % OoOoOO00
   for O000O in Iii :
    OoOOo . more_specific_registrations . remove ( O000O )
    O000O . delete_cache ( )
    if 24 - 24: oO0o * I1Ii111
    if 40 - 40: Ii1I - OoOoOO00 * OoOoOO00 . OoOoOO00 + OoooooooOO
    if 77 - 77: iIii1I11I1II1 . Ii1I % oO0o / Ii1I
    if 54 - 54: oO0o + ooOoO0o - Oo0Ooo
    if 35 - 35: Ii1I - Ii1I + i1IIi - O0 - I1Ii111
    if 58 - 58: OoOoOO00 - iII111i - OoooooooOO
    if 96 - 96: iIii1I11I1II1
 if ( len ( o0OO0O00o ) != 0 ) :
  lisp . lisp_queue_multicast_map_notify ( i111I , o0OO0O00o )
  if 82 - 82: OoOoOO00 + O0 - IiII % oO0o * i11iIiiIii
  if 15 - 15: o0oOOo0O0Ooo
  if 39 - 39: OOooOOo / I1ii11iIi11i / I1IiiI * I1Ii111
  if 44 - 44: O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / O0 - I11i
  if 83 - 83: IiII * I11i / Oo0Ooo
 OOo = threading . Timer ( lisp . LISP_SITE_TIMEOUT_CHECK_INTERVAL ,
 oo0o , [ ] )
 OOo . start ( )
 return
 if 32 - 32: o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
 if 39 - 39: OoooooooOO * OOooOOo * O0 . I11i . OoO0O00 + ooOoO0o
 if 9 - 9: OoOoOO00 + oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
def oO00oo000O ( ) :
 global oo0o0O00
 if 7 - 7: O0 / iII111i * oO0o
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
 if ( oo0o0O00 == 0 ) : return
 if 60 - 60: OoO0O00
 oO0o0o0ooO0oO = oo0o0O00
 Ii1IOo0o0 = lisp . bold ( "Injecting" , False )
 lisp . fprint ( "{} {} entries into mapping system for scale testing" . format ( Ii1IOo0o0 , oO0o0o0ooO0oO ) )
 if 81 - 81: OoOoOO00 % Ii1I
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 Oo0O0O00Oo = 1300
 I111Ii = 9990000000
 OO0O00 = lisp . lisp_address ( lisp . LISP_AFI_NAME , "ct" , 0 , Oo0O0O00Oo )
 i1i1iI1iiiI = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 iiO0O0o0oO0O00 = lisp . lisp_site_eid_lookup ( OO0O00 , i1i1iI1iiiI , False )
 if ( iiO0O0o0oO0O00 == None ) :
  lisp . fprint ( "No site found for instance-ID {}" . format ( Oo0O0O00Oo ) )
  return
  if 70 - 70: I1Ii111 + oO0o
 if ( iiO0O0o0oO0O00 . accept_more_specifics == False ) :
  lisp . fprint ( "Site must be configured with accept-more-specifics" )
  return
  if 93 - 93: I1Ii111 + Ii1I
  if 33 - 33: O0
  if 78 - 78: O0 / II111iiii * OoO0O00
  if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
  if 58 - 58: IiII + iIii1I11I1II1
 IIiiIiI1 = lisp . lisp_rloc ( )
 if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
 O0o0O0OO0o = ' "phone" : "{}", "text-interval" : "10", ' + '"gps" : "(37.623322,-122.384974579)" '
 if 54 - 54: OoOoOO00 . oO0o % i11iIiiIii / OoooooooOO + IiII % oO0o
 if 36 - 36: oO0o
 o0OO = ' "phone" : "{}", "health-state" : "not-tested" '
 if 7 - 7: o0oOOo0O0Ooo / OoO0O00 * i11iIiiIii * O0
 if 79 - 79: iIii1I11I1II1
 if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
 if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 ii1I111i1Ii = lisp . lisp_get_timestamp ( )
 OOOooO0OO0o = 0
 for Ii1IOo0o0 in range ( 1 , oO0o0o0ooO0oO + 1 ) :
  ii1 = lisp . lisp_site_eid ( iiO0O0o0oO0O00 . site )
  ii1 . eid = copy . deepcopy ( OO0O00 )
  ii1 . eid . address = hmac . new ( "ct" , str ( I111Ii ) ,
 hashlib . sha256 ) . hexdigest ( )
  if 10 - 10: Ii1I - OoOoOO00 . OoooooooOO . OOooOOo . OoO0O00 * iII111i
  ii1 . dynamic = True
  ii1 . parent_for_more_specifics = iiO0O0o0oO0O00
  ii1 . add_cache ( )
  ii1 . inherit_from_ams_parent ( )
  iiO0O0o0oO0O00 . more_specific_registrations . append ( ii1 )
  if 78 - 78: oO0o / OoO0O00 - oO0o * OoooooooOO . OoOoOO00
  if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
  if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
  if 48 - 48: i11iIiiIii % oO0o
  i11i11 = copy . deepcopy ( IIiiIiI1 )
  Ii11Iii = "{" + O0o0O0OO0o . format ( I111Ii ) + "}"
  i11i11 . json = lisp . lisp_json ( ii1 . eid . address , Ii11Iii )
  ooo00OoOO0o = copy . deepcopy ( IIiiIiI1 )
  Ii11Iii = "{" + o0OO . format ( I111Ii ) + "}"
  ooo00OoOO0o . json = lisp . lisp_json ( ii1 . eid . address , Ii11Iii )
  ii1 . registered_rlocs = [ i11i11 , ooo00OoOO0o ]
  OOOooO0OO0o += sys . getsizeof ( ii1 )
  if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
  if 21 - 21: OOooOOo
  if 6 - 6: IiII
  if 46 - 46: IiII + oO0o
  if ( Ii1IOo0o0 % 100 == 0 ) :
   lisp . fprint ( "Added {} site-eid entries" . format ( Ii1IOo0o0 ) )
   if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
   if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
   if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
   if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
   if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
  if ( Ii1IOo0o0 % 10000 == 0 and Ii1IOo0o0 != oO0o0o0ooO0oO ) :
   lisp . fprint ( "Sleeping for 100ms ..." )
   time . sleep ( .1 )
   if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
  I111Ii += 1
  if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
  if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
  if 24 - 24: OoOoOO00
  if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
  if 28 - 28: I1IiiI
 ii1I111i1Ii = time . time ( ) - ii1I111i1Ii
 if ( ii1I111i1Ii < 60 ) :
  lisp . fprint ( "Finished in {} secs, memory {}" . format ( round ( ii1I111i1Ii , 3 ) , OOOooO0OO0o ) )
 else :
  ii1I111i1Ii = ii1I111i1Ii / 60
  lisp . fprint ( "Finished in {} mins, memory {}" . format ( round ( ii1I111i1Ii , 1 ) , OOOooO0OO0o ) )
  if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 oo0o0O00 = 0
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
 if 46 - 46: I1Ii111
def o00OoooooooOo ( ) :
 lisp . lisp_set_exception ( )
 if 32 - 32: o0oOOo0O0Ooo + I1IiiI . I1Ii111
 if 41 - 41: OoOoOO00 . i11iIiiIii / I11i
 if 98 - 98: OoOoOO00 % II111iiii
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
 oO00oo000O ( )
 if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 o0 = lisp . lisp_get_timestamp ( )
 if 68 - 68: o0oOOo0O0Ooo
 Iii = [ ]
 for i1iiI in lisp . lisp_pubsub_cache :
  for o0OooooOoOO in lisp . lisp_pubsub_cache [ i1iiI ] . values ( ) :
   ooOo00 = o0OooooOoOO . ttl * 60
   if ( o0OooooOoOO . uptime + ooOo00 > o0 ) : continue
   Iii . append ( [ i1iiI , o0OooooOoOO . xtr_id ] )
   if 20 - 20: I1Ii111 - I1Ii111
   if 37 - 37: IiII
   if 37 - 37: Oo0Ooo / IiII * O0
   if 73 - 73: iII111i * iII111i / ooOoO0o
   if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
   if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 for i1iiI , ii1iI1II11ii in Iii :
  OO0O00 = lisp . green ( i1iiI , False )
  lisp . lprint ( "Pubsub state {} for xtr-id 0x{} has {}" . format ( OO0O00 ,
 lisp . lisp_hex_string ( ii1iI1II11ii ) , lisp . bold ( "timed out" , False ) ) )
  if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
  if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
  if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
  if 6 - 6: iIii1I11I1II1 * OoooooooOO
  iIiI1I1ii1I1 = lisp . lisp_pubsub_cache [ i1iiI ] [ ii1iI1II11ii ]
  lisp . lisp_pubsub_cache [ i1iiI ] . pop ( ii1iI1II11ii )
  del ( iIiI1I1ii1I1 )
  if 83 - 83: OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
  if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
  if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
  if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
  if 71 - 71: iII111i
  if ( len ( lisp . lisp_pubsub_cache [ i1iiI ] ) == 0 ) :
   lisp . lisp_pubsub_cache . pop ( i1iiI )
   if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
   if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
   if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
   if 58 - 58: I1ii11iIi11i
   if 2 - 2: II111iiii / I1Ii111
   if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 Ii1IIii11 = threading . Timer ( lisp . LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL , o00OoooooooOo , [ ] )
 if 22 - 22: ooOoO0o . iIii1I11I1II1
 Ii1IIii11 . start ( )
 return
 if 12 - 12: Ii1I
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
def ooo000oOO ( ) :
 global II1iII1i
 global i111I
 global OOo , Ii1IIii11
 if 27 - 27: o0oOOo0O0Ooo * i11iIiiIii * OoO0O00
 lisp . lisp_i_am ( "ms" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "Map-Server starting up" )
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 II1iII1i = lisp . lisp_open_listen_socket ( "" , "lisp-ms" )
 i111I [ 0 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV4 )
 i111I [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 i111I [ 2 ] = II1iII1i
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 OOo = threading . Timer ( lisp . LISP_SITE_TIMEOUT_CHECK_INTERVAL ,
 oo0o , [ ] )
 OOo . start ( )
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 ooooo0Oo0 = lisp . LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL
 if ( oo0o0O00 != 0 ) : ooooo0Oo0 = 5
 Ii1IIii11 = threading . Timer ( ooooo0Oo0 , o00OoooooooOo , [ ] )
 Ii1IIii11 . start ( )
 return ( True )
 if 97 - 97: IiII . oO0o . IiII
 if 91 - 91: OOooOOo + I1Ii111 . I11i
 if 15 - 15: I11i
 if 94 - 94: I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
 if 81 - 81: Oo0Ooo - I11i
 if 24 - 24: OoooooooOO . OoO0O00 * II111iiii
 if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
def OO00o0O0O000o ( ) :
 global OOo
 if 56 - 56: Oo0Ooo * iII111i
 if 13 - 13: Oo0Ooo * Oo0Ooo * II111iiii * iII111i . i1IIi / IiII
 if 92 - 92: Ii1I * i11iIiiIii + iII111i * I1Ii111
 if 48 - 48: I11i * iII111i * iII111i
 OOo . cancel ( )
 if 70 - 70: oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if 80 - 80: OoooooooOO + IiII
 lisp . lisp_close_socket ( i111I [ 0 ] , "" )
 lisp . lisp_close_socket ( i111I [ 1 ] , "" )
 lisp . lisp_close_socket ( II1iII1i , "lisp-ms" )
 return
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if 43 - 43: Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
if ( ooo000oOO ( ) == False ) :
 lisp . lprint ( "lisp_ms_startup() failed" )
 lisp . lisp_print_banner ( "Map-Server abnormal exit" )
 exit ( 1 )
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
while ( True ) :
 iiiii111 , oO0oo0o00o0O , oooI11iI1I , Iii1iiIi1II1 = lisp . lisp_receive ( II1iII1i , True )
 if 53 - 53: O0 + OOooOOo % i11iIiiIii * OOooOOo
 if ( oO0oo0o00o0O == "" ) : break
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 if ( iiiii111 == "command" ) :
  lispconfig . lisp_process_command ( II1iII1i , iiiii111 ,
 Iii1iiIi1II1 , "lisp-ms" , [ O0Ooo , lisp . lisp_policy_commands ] )
 elif ( iiiii111 == "api" ) :
  lisp . lisp_process_api ( "lisp-ms" , II1iII1i , Iii1iiIi1II1 )
 else :
  lisp . lisp_parse_packet ( i111I , Iii1iiIi1II1 , oO0oo0o00o0O , oooI11iI1I )
  if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
  if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
  if 96 - 96: OoooooooOO + IiII * O0
OO00o0O0O000o ( )
lisp . lisp_print_banner ( "Map-Server normal exit" )
exit ( 0 )
if 86 - 86: Ii1I
if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
