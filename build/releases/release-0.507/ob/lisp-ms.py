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
if 65 - 65: o0oOOo0O0Ooo * iIii1I11I1II1 * ooOoO0o
if 18 - 18: iIii1I11I1II1 / I11i + oO0o / Oo0Ooo - II111iiii - I11i
if 1 - 1: I11i - OOooOOo % O0 + I1IiiI - iII111i / I11i
def iIiiI1 ( kv_pairs ) :
 global II1Ii1iI1i
 global iiI1iIiI
 if 68 - 68: I1IiiI - i11iIiiIii - OoO0O00 / OOooOOo - OoO0O00 + i1IIi
 IiiIII111ii = lisp . lisp_site ( )
 if 3 - 3: iII111i + O0
 I1Ii = [ ]
 if ( kv_pairs . has_key ( "address" ) ) :
  for o0oOo0Ooo0O in kv_pairs [ "address" ] :
   OO00O0O0O00Oo = lisp . lisp_rloc ( )
   I1Ii . append ( OO00O0O0O00Oo )
   if 25 - 25: o0oOOo0O0Ooo % II111iiii - II111iiii . II111iiii
   if 32 - 32: i1IIi . I11i % OoO0O00 . o0oOOo0O0Ooo
   if 42 - 42: I1Ii111 + I1ii11iIi11i
 OOoO000O0OO = [ ]
 if ( kv_pairs . has_key ( "eid-prefix" ) ) :
  for iiI1IiI in kv_pairs [ "eid-prefix" ] :
   II = lisp . lisp_site_eid ( IiiIII111ii )
   OOoO000O0OO . append ( II )
   if 57 - 57: oO0o
   if 14 - 14: Oo0Ooo . I1IiiI / Ii1I
   if 38 - 38: II111iiii % i11iIiiIii . ooOoO0o - OOooOOo + Ii1I
 for Ooooo0Oo00oO0 in kv_pairs . keys ( ) :
  Iiii11I1i1Ii1 = kv_pairs [ Ooooo0Oo00oO0 ]
  if ( Ooooo0Oo00oO0 == "site-name" ) : IiiIII111ii . site_name = Iiii11I1i1Ii1
  if ( Ooooo0Oo00oO0 == "description" ) : IiiIII111ii . description = Iiii11I1i1Ii1
  if ( Ooooo0Oo00oO0 == "authentication-key" ) :
   IiiIII111ii . auth_key = lisp . lisp_parse_auth_key ( Iiii11I1i1Ii1 )
   if 86 - 86: ooOoO0o . I1IiiI % Oo0Ooo + o0oOOo0O0Ooo
  if ( Ooooo0Oo00oO0 == "shutdown" ) :
   IiiIII111ii . shutdown = True if Iiii11I1i1Ii1 == "yes" else False
   if 35 - 35: iIii1I11I1II1 % oO0o * I11i % I11i + II111iiii * iII111i
   if 54 - 54: I11i + IiII / iII111i
  if ( Ooooo0Oo00oO0 == "instance-id" ) :
   for IIII in range ( len ( OOoO000O0OO ) ) :
    II = OOoO000O0OO [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    if ( Ii1IOo0o0 == "*" ) :
     II . eid . store_iid_range ( 0 , 0 )
    else :
     if ( Ii1IOo0o0 == "" ) : Ii1IOo0o0 = "0"
     II . eid . instance_id = int ( Ii1IOo0o0 )
     II . group . instance_id = int ( Ii1IOo0o0 )
     if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
     if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
     if 20 - 20: o0oOOo0O0Ooo
  if ( Ooooo0Oo00oO0 == "eid-prefix" ) :
   for IIII in range ( len ( OOoO000O0OO ) ) :
    II = OOoO000O0OO [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    if ( Ii1IOo0o0 != "" ) : II . eid . store_prefix ( Ii1IOo0o0 )
    if 77 - 77: OoOoOO00 / I11i
    if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
  if ( Ooooo0Oo00oO0 == "group-prefix" ) :
   for IIII in range ( len ( OOoO000O0OO ) ) :
    II = OOoO000O0OO [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    if ( Ii1IOo0o0 != "" ) : II . group . store_prefix ( Ii1IOo0o0 )
    if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
    if 95 - 95: OoO0O00 % oO0o . O0
  if ( Ooooo0Oo00oO0 == "accept-more-specifics" ) :
   for IIII in range ( len ( OOoO000O0OO ) ) :
    II = OOoO000O0OO [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    I1i1I = True if ( Ii1IOo0o0 == "yes" ) else False
    II . accept_more_specifics = I1i1I
    if 80 - 80: OoOoOO00 - OoO0O00
    if 87 - 87: oO0o / I11i - i1IIi * OOooOOo / OoooooooOO . O0
  if ( Ooooo0Oo00oO0 == "force-proxy-reply" ) :
   for IIII in range ( len ( OOoO000O0OO ) ) :
    II = OOoO000O0OO [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    I1i1I = True if ( Ii1IOo0o0 == "yes" ) else False
    II . force_proxy_reply = I1i1I
    if 1 - 1: II111iiii - I11i / I11i
    if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
  if ( Ooooo0Oo00oO0 == "force-ttl" ) :
   for IIII in range ( len ( OOoO000O0OO ) ) :
    II = OOoO000O0OO [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    if ( Ii1IOo0o0 == "" ) : continue
    II . force_ttl = None if int ( Ii1IOo0o0 ) == 0 else int ( Ii1IOo0o0 )
    if 83 - 83: OoooooooOO
    if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
  if ( Ooooo0Oo00oO0 == "echo-nonce-capable" ) :
   for IIII in range ( len ( OOoO000O0OO ) ) :
    II = OOoO000O0OO [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    I1i1I = True if ( Ii1IOo0o0 == "yes" ) else False
    II . echo_nonce_capable = I1i1I
    if 4 - 4: II111iiii / ooOoO0o . iII111i
    if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
  if ( Ooooo0Oo00oO0 == "force-nat-proxy-reply" ) :
   for IIII in range ( len ( OOoO000O0OO ) ) :
    II = OOoO000O0OO [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    I1i1I = True if ( Ii1IOo0o0 == "yes" ) else False
    II . force_nat_proxy_reply = I1i1I
    if 50 - 50: I1IiiI
    if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
  if ( Ooooo0Oo00oO0 == "pitr-proxy-reply-drop" ) :
   for IIII in range ( len ( OOoO000O0OO ) ) :
    II = OOoO000O0OO [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    I1i1I = True if ( Ii1IOo0o0 == "yes" ) else False
    II . pitr_proxy_reply_drop = I1i1I
    if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
    if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
  if ( Ooooo0Oo00oO0 == "proxy-reply-action" ) :
   for IIII in range ( len ( OOoO000O0OO ) ) :
    II = OOoO000O0OO [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    II . proxy_reply_action = Ii1IOo0o0
    if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
    if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
  if ( Ooooo0Oo00oO0 == "require-signature" ) :
   for IIII in range ( len ( OOoO000O0OO ) ) :
    II = OOoO000O0OO [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    I1i1I = True if ( Ii1IOo0o0 == "yes" ) else False
    II . require_signature = I1i1I
    if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
    if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
  if ( Ooooo0Oo00oO0 == "policy-name" ) :
   for IIII in range ( len ( OOoO000O0OO ) ) :
    II = OOoO000O0OO [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    II . policy = Ii1IOo0o0
    if 58 - 58: i11iIiiIii % I11i
    if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
    if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
  if ( Ooooo0Oo00oO0 == "address" ) :
   for IIII in range ( len ( I1Ii ) ) :
    OO00O0O0O00Oo = I1Ii [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    if ( Ii1IOo0o0 != "" ) : OO00O0O0O00Oo . rloc . store_address ( Ii1IOo0o0 )
    if 16 - 16: I1IiiI * oO0o % IiII
    if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
  if ( Ooooo0Oo00oO0 == "priority" ) :
   for IIII in range ( len ( I1Ii ) ) :
    OO00O0O0O00Oo = I1Ii [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    if ( Ii1IOo0o0 == "" ) : Ii1IOo0o0 = "0"
    OO00O0O0O00Oo . priority = int ( Ii1IOo0o0 )
    if 44 - 44: oO0o
    if 88 - 88: I1Ii111 % Ii1I . II111iiii
  if ( Ooooo0Oo00oO0 == "weight" ) :
   for IIII in range ( len ( I1Ii ) ) :
    OO00O0O0O00Oo = I1Ii [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    if ( Ii1IOo0o0 == "" ) : Ii1IOo0o0 = "0"
    OO00O0O0O00Oo . weight = int ( Ii1IOo0o0 )
    if 38 - 38: o0oOOo0O0Ooo
    if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
    if 26 - 26: iII111i
    if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
    if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
    if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
    if 91 - 91: oO0o % Oo0Ooo
 if ( II1Ii1iI1i . has_key ( IiiIII111ii . site_name ) ) : return
 if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
 if 31 - 31: I11i - II111iiii . I11i
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 II1Ii1iI1i [ IiiIII111ii . site_name ] = IiiIII111ii
 iiI1iIiI = sorted ( II1Ii1iI1i )
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 for II in OOoO000O0OO :
  II . add_cache ( )
  O0ooo0O0oo0 = II . build_sort_key ( )
  IiiIII111ii . allowed_prefixes [ O0ooo0O0oo0 ] = II
  if 91 - 91: iIii1I11I1II1 + I1Ii111
 for OO00O0O0O00Oo in I1Ii :
  O0ooo0O0oo0 = OO00O0O0O00Oo . rloc . print_address ( )
  IiiIII111ii . allowed_rlocs [ O0ooo0O0oo0 ] = OO00O0O0O00Oo
  if 31 - 31: IiII . OoOoOO00 . OOooOOo
  if 75 - 75: I11i + OoO0O00 . OoOoOO00 . ooOoO0o + Oo0Ooo . OoO0O00
  if 96 - 96: OOooOOo . ooOoO0o - Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * OOooOOo
  if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
  if 21 - 21: I1IiiI * iIii1I11I1II1
 IiiIII111ii . allowed_prefixes_sorted = sorted ( IiiIII111ii . allowed_prefixes )
 return
 if 91 - 91: IiII
 if 15 - 15: II111iiii
 if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
 if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
 if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
 if 61 - 61: II111iiii
def O0OOO ( kv_pair ) :
 II11iIiIIIiI = lisp . lisp_ddt_entry ( )
 if 67 - 67: I1Ii111 . iII111i . O0
 for Ooooo0Oo00oO0 in kv_pair . keys ( ) :
  Iiii11I1i1Ii1 = kv_pair [ Ooooo0Oo00oO0 ]
  if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
  if ( Ooooo0Oo00oO0 == "instance-id" ) :
   Ii1IOo0o0 = Iiii11I1i1Ii1 . split ( "-" )
   if ( Ii1IOo0o0 [ 0 ] == "" ) : continue
   if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
   I1111IIi = ( kv_pair . has_key ( "eid-prefix" ) == False or
 kv_pair [ "eid-prefix" ] == "" )
   Oo0oO = ( kv_pair . has_key ( "group-prefix" ) == False or
 kv_pair [ "group-prefix" ] == "" )
   if 1 - 1: OoO0O00 - oO0o . I11i . OoO0O00 / Oo0Ooo + I11i
   if ( I1111IIi and Oo0oO ) :
    II11iIiIIIiI . eid . store_iid_range ( int ( Ii1IOo0o0 [ 0 ] ) , int ( Ii1IOo0o0 [ 1 ] ) )
   else :
    II11iIiIIIiI . eid . instance_id = int ( Ii1IOo0o0 [ 0 ] )
    II11iIiIIIiI . group . instance_id = int ( Ii1IOo0o0 [ 0 ] )
    if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
    if 49 - 49: Ii1I / OoO0O00 . II111iiii
  if ( Ooooo0Oo00oO0 == "eid-prefix" ) :
   II11iIiIIIiI . eid . store_prefix ( Iiii11I1i1Ii1 )
   if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
  if ( Ooooo0Oo00oO0 == "group-prefix" ) :
   II11iIiIIIiI . group . store_prefix ( Iiii11I1i1Ii1 )
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
 for IIII in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  II11iIiIIIiI = lisp . lisp_ddt_entry ( )
  IiI111111IIII . append ( II11iIiIIIiI )
  if 37 - 37: I1Ii111 / OoOoOO00
  if 23 - 23: O0
 o00oO0oOo00 = [ ]
 if 81 - 81: OoO0O00
 if ( kv_pair . has_key ( "address" ) ) :
  for IIII in range ( len ( kv_pair [ "address" ] ) ) :
   IIi1 = lisp . lisp_ddt_node ( )
   IIi1 . map_server_peer = True
   o00oO0oOo00 . append ( IIi1 )
   if 45 - 45: iII111i / iII111i + I1Ii111 + ooOoO0o
   if 47 - 47: o0oOOo0O0Ooo + ooOoO0o
   if 82 - 82: II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
 for Ooooo0Oo00oO0 in kv_pair . keys ( ) :
  Iiii11I1i1Ii1 = kv_pair [ Ooooo0Oo00oO0 ]
  if ( Ooooo0Oo00oO0 == "instance-id" ) :
   for ooO0oOOooOo0 in range ( len ( IiI111111IIII ) ) :
    II11iIiIIIiI = IiI111111IIII [ ooO0oOOooOo0 ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ ooO0oOOooOo0 ] . split ( "-" )
    if ( Ii1IOo0o0 [ 0 ] == "" ) : continue
    if 38 - 38: I1Ii111
    I1111IIi = ( kv_pair [ "eid-prefix" ] [ ooO0oOOooOo0 ] == "" and
 kv_pair [ "group-prefix" ] [ ooO0oOOooOo0 ] == "" )
    if 84 - 84: iIii1I11I1II1 % iII111i / iIii1I11I1II1 % I11i
    if ( I1111IIi ) :
     II11iIiIIIiI . eid . store_iid_range ( int ( Ii1IOo0o0 [ 0 ] ) , int ( Ii1IOo0o0 [ 1 ] ) )
    else :
     II11iIiIIIiI . eid . instance_id = int ( Ii1IOo0o0 [ 0 ] )
     II11iIiIIIiI . group . instance_id = int ( Ii1IOo0o0 [ 0 ] )
     if 45 - 45: O0
     if 26 - 26: I11i - iIii1I11I1II1 - I1IiiI / OoO0O00 . OoOoOO00 % iIii1I11I1II1
     if 91 - 91: o0oOOo0O0Ooo . iIii1I11I1II1 / oO0o + i1IIi
  if ( Ooooo0Oo00oO0 == "eid-prefix" ) :
   for ooO0oOOooOo0 in range ( len ( IiI111111IIII ) ) :
    II11iIiIIIiI = IiI111111IIII [ ooO0oOOooOo0 ]
    I1i = Iiii11I1i1Ii1 [ ooO0oOOooOo0 ]
    if ( I1i == "" ) : continue
    II11iIiIIIiI . eid . store_prefix ( I1i )
    if 53 - 53: I1ii11iIi11i * OoOoOO00 + ooOoO0o - II111iiii
    if 2 - 2: I11i + Ii1I - I1IiiI % o0oOOo0O0Ooo . iII111i
  if ( Ooooo0Oo00oO0 == "group-prefix" ) :
   for ooO0oOOooOo0 in range ( len ( IiI111111IIII ) ) :
    II11iIiIIIiI = IiI111111IIII [ ooO0oOOooOo0 ]
    I1i = Iiii11I1i1Ii1 [ ooO0oOOooOo0 ]
    if ( I1i == "" ) : continue
    II11iIiIIIiI . group . store_prefix ( I1i )
    if 18 - 18: OOooOOo + iII111i - Ii1I . II111iiii + i11iIiiIii
    if 20 - 20: I1Ii111
    if 52 - 52: II111iiii - OoooooooOO % Ii1I + I1IiiI * Oo0Ooo . IiII
  if ( Ooooo0Oo00oO0 == "address" ) :
   for IIII in range ( len ( o00oO0oOo00 ) ) :
    IIi1 = o00oO0oOo00 [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    if ( Ii1IOo0o0 != "" ) : IIi1 . delegate_address . store_address ( Ii1IOo0o0 )
    if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
    if 55 - 55: OOooOOo . I1IiiI
  if ( Ooooo0Oo00oO0 == "priority" ) :
   for IIII in range ( len ( o00oO0oOo00 ) ) :
    IIi1 = o00oO0oOo00 [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    if ( Ii1IOo0o0 == "" ) : Ii1IOo0o0 = "0"
    IIi1 . priority = int ( Ii1IOo0o0 )
    if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
    if 100 - 100: I1Ii111 * O0
  if ( Ooooo0Oo00oO0 == "weight" ) :
   for IIII in range ( len ( o00oO0oOo00 ) ) :
    IIi1 = o00oO0oOo00 [ IIII ]
    Ii1IOo0o0 = Iiii11I1i1Ii1 [ IIII ]
    if ( Ii1IOo0o0 == "" ) : Ii1IOo0o0 = "0"
    IIi1 . weight = int ( Ii1IOo0o0 )
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
 for Ooooo0Oo00oO0 in kv_pair . keys ( ) :
  Iiii11I1i1Ii1 = kv_pair [ Ooooo0Oo00oO0 ]
  if ( Ooooo0Oo00oO0 == "instance-id" ) :
   if ( Iiii11I1i1Ii1 == "*" ) : Iiii11I1i1Ii1 = "-1"
   oOo0O . instance_id = int ( Iiii11I1i1Ii1 )
   if 22 - 22: OoOoOO00 . OOooOOo * OoOoOO00
  if ( Ooooo0Oo00oO0 == "eid-prefix" ) :
   oOo0O . store_prefix ( Iiii11I1i1Ii1 )
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
 for Ooooo0Oo00oO0 in kv_pair . keys ( ) :
  Iiii11I1i1Ii1 = kv_pair [ Ooooo0Oo00oO0 ]
  if ( Ooooo0Oo00oO0 == "map-register-key" ) :
   lisp . lisp_ms_encryption_keys = lisp . lisp_parse_auth_key ( Iiii11I1i1Ii1 )
   if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
   if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
 return
 if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
 if 76 - 76: IiII * iII111i
 if 52 - 52: OOooOOo
def iiii1 ( eid_key , group_key ) :
 if 96 - 96: i11iIiiIii % OOooOOo
 iiI1IiI = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if ( eid_key ) :
  if ( eid_key == "[0]/0" ) :
   iiI1IiI . store_iid_range ( 0 , 0 )
  else :
   iiI1IiI . store_prefix ( eid_key )
   if 70 - 70: iIii1I11I1II1
   if 31 - 31: IiII - I1IiiI % iIii1I11I1II1
 oooo0OOOO = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if ( group_key ) : oooo0OOOO . store_prefix ( group_key )
 if 54 - 54: i1IIi / IiII % OoO0O00 . I11i
 IIOoO = lisp . lisp_print_eid_tuple ( iiI1IiI , oooo0OOOO )
 IIOoO = lisp . lisp_print_cour ( IIOoO )
 if 12 - 12: O0 - o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
 II = lisp . lisp_site_eid_lookup ( iiI1IiI , oooo0OOOO , True )
 if ( II == None ) :
  II1IIIIiII1i = "Could not find EID {} in site cache" . format ( IIOoO )
  return ( II1IIIIiII1i )
  if 1 - 1: II111iiii
  if 68 - 68: iII111i - I1IiiI / I1Ii111 / I11i
 I11iiii = lisp . space ( 4 )
 O0i1iI = lisp . space ( 8 )
 IiI1iiiIii = lisp . space ( 12 )
 if 7 - 7: I1Ii111 * OoO0O00 - ooOoO0o + OOooOOo * I1IiiI % OoO0O00
 iI1i111I1Ii = lisp . green ( "yes" , True ) if II . registered else lisp . red ( "no" , True )
 if 25 - 25: I1Ii111 - iII111i
 if 10 - 10: II111iiii / oO0o % OoooooooOO * I11i % I1ii11iIi11i
 II1IIIIiII1i = '<font face="Sans-Serif">'
 if 48 - 48: ooOoO0o / I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / i1IIi
 OOOOoOOo0O0 = lisp . lisp_print_cour ( II . site . site_name )
 oOooo0 = lisp . lisp_print_cour ( str ( II . site_id ) )
 ooO = "0" if II . xtr_id == 0 else lisp . lisp_hex_string ( II . xtr_id )
 ooO = lisp . lisp_print_cour ( "0x" + ooO )
 o0o00OOo0 = lisp . lisp_print_elapsed ( II . first_registered )
 I1IIii1 = lisp . lisp_print_elapsed ( II . last_registered )
 if ( time . time ( ) - II . last_registered >=
 ( II . register_ttl / 2 ) and I1IIii1 != "never" ) :
  I1IIii1 = lisp . red ( I1IIii1 , True )
  if 95 - 95: OoO0O00 % i1IIi * i11iIiiIii % Oo0Ooo - oO0o
 if ( II . last_registerer . afi == lisp . LISP_AFI_NONE ) :
  OOoOoOo = "none"
 else :
  OOoOoOo = II . last_registerer . print_address ( )
  if 98 - 98: iII111i
 OOoOoOo = lisp . lisp_print_cour ( OOoOoOo )
 OooooO0oOOOO = ", " + lisp . lisp_print_cour ( "site is in admin-shutdown" ) if II . site . shutdown else ""
 if 100 - 100: iII111i % OOooOOo
 OOO = ", accepting more specifics" if II . accept_more_specifics else ""
 if 6 - 6: OoooooooOO
 if ( OOO == "" and II . dynamic ) : OOO = ", dynamic"
 II1IIIIiII1i += '''Site name: {}, EID-prefix: {}, registered: {}{}{}
        <br>''' . format ( OOOOoOOo0O0 , IIOoO , iI1i111I1Ii , OOO , OooooO0oOOOO )
 if 50 - 50: I1ii11iIi11i % O0 * o0oOOo0O0Ooo
 II1IIIIiII1i += "{}Description: {}<br>" . format ( I11iiii ,
 lisp . lisp_print_cour ( II . site . description ) )
 II1IIIIiII1i += "{}Last registerer: {}, xTR-ID: {}, site-ID: {}<br>" . format ( I11iiii , OOoOoOo , ooO , oOooo0 )
 if 5 - 5: IiII * OoOoOO00
 if 5 - 5: I1Ii111
 O0I11Iiii1I = II . print_flags ( False )
 O0I11Iiii1I = lisp . lisp_print_cour ( O0I11Iiii1I )
 oo00O0oO0O0 = "none"
 if ( II . registered ) :
  oo00O0oO0O0 = "sha1" if ( II . auth_sha1_or_sha2 ) else "sha2"
  if 96 - 96: i11iIiiIii % ooOoO0o / OoOoOO00
 II1IIIIiII1i += ( "{}First registered: {}, last registered: {}, auth-type: " + "{}, registration flags: {}<br>" ) . format ( I11iiii ,
 # OoO0O00 * OOooOOo % O0
 lisp . lisp_print_cour ( o0o00OOo0 ) , lisp . lisp_print_cour ( I1IIii1 ) ,
 lisp . lisp_print_cour ( oo00O0oO0O0 ) , O0I11Iiii1I )
 if 62 - 62: O0 % I11i . I11i - iIii1I11I1II1 / i11iIiiIii
 iiiII = lisp . lisp_print_cour ( str ( II . register_ttl ) + " seconds" )
 II1IIIIiII1i += "{}{} registration timeout TTL: {}<br>" . format ( I11iiii , "Registered" if II . use_register_ttl_requested else "Default" , iiiII )
 if 41 - 41: Oo0Ooo
 if 10 - 10: Oo0Ooo / Oo0Ooo / I1Ii111 . I1Ii111
 if 98 - 98: Oo0Ooo / I1IiiI . O0 + OoO0O00
 if 43 - 43: II111iiii . oO0o / I1ii11iIi11i
 if 20 - 20: I1IiiI
 if 95 - 95: iII111i - I1IiiI
 if ( II . policy ) :
  I1ii1ii11i1I = lisp . lisp_print_cour ( II . policy )
  II1IIIIiII1i += "{}Apply policy: '{}'<br>" . format ( I11iiii , I1ii1ii11i1I )
  if 58 - 58: iII111i + Oo0Ooo
  if 12 - 12: o0oOOo0O0Ooo - I1ii11iIi11i % OoOoOO00 * I11i
  if 44 - 44: iII111i % Ii1I
  if 41 - 41: i1IIi - I11i - Ii1I
  if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
 iI1i111I1Ii = "yes" if II . force_proxy_reply else "no"
 iI1i111I1Ii = lisp . lisp_print_cour ( iI1i111I1Ii )
 II1IIIIiII1i += "{}Forcing proxy Map-Reply: {}<br>" . format ( I11iiii , iI1i111I1Ii )
 if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
 if ( II . force_ttl != None ) :
  iiiII = lisp . lisp_print_cour ( str ( II . force_ttl ) + " seconds" )
  II1IIIIiII1i += "{}Forced proxy Map-Reply TTL: {}<br>" . format ( I11iiii , iiiII )
  if 44 - 44: II111iiii
  if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
  if 35 - 35: iIii1I11I1II1
 iI1i111I1Ii = "yes" if II . force_nat_proxy_reply else "no"
 iI1i111I1Ii = lisp . lisp_print_cour ( iI1i111I1Ii )
 II1IIIIiII1i += "{}Forcing proxy Map-Reply for xTRs behind NATs: {}<br>" . format ( I11iiii , iI1i111I1Ii )
 if 42 - 42: I1Ii111 . I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI
 if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
 iI1i111I1Ii = "yes" if II . pitr_proxy_reply_drop else "no"
 iI1i111I1Ii = lisp . lisp_print_cour ( iI1i111I1Ii )
 II1IIIIiII1i += "{}Send drop-action proxy Map-Reply to PITR: {}<br>" . format ( I11iiii , iI1i111I1Ii )
 if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
 OOOO0O00o = "not configured" if II . proxy_reply_action == "" else II . proxy_reply_action
 if 62 - 62: iIii1I11I1II1
 OOOO0O00o = lisp . lisp_print_cour ( OOOO0O00o )
 II1IIIIiII1i += "{}Proxy Map-Reply action: {}<br>" . format ( I11iiii , OOOO0O00o )
 if 12 - 12: OOooOOo / o0oOOo0O0Ooo
 if ( II . force_proxy_reply and II . echo_nonce_capable ) :
  iiI1I1 = lisp . lisp_print_cour ( "yes" )
  II1IIIIiII1i += "{}RLOCs are echo-nonce capable: {}<br>" . format ( I11iiii , iiI1I1 )
  if 56 - 56: I1IiiI . O0 + Oo0Ooo
  if 1 - 1: iII111i
 iI1i111I1Ii = "yes" if II . require_signature else "no"
 iI1i111I1Ii = lisp . lisp_print_cour ( iI1i111I1Ii )
 II1IIIIiII1i += "{}Require signatures: {}<br>" . format ( I11iiii , iI1i111I1Ii )
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
 if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
 if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 I11i1II = "any" if len ( II . site . allowed_rlocs ) == 0 else ""
 if ( I11i1II != "" ) : I11i1II = lisp . lisp_print_cour ( I11i1II )
 II1IIIIiII1i += "{}Allowed RLOC-set: {}<br>" . format ( I11iiii , I11i1II )
 if ( I11i1II == "" ) :
  for OO00O0O0O00Oo in II . site . allowed_rlocs . values ( ) :
   Ooo = lisp . lisp_print_cour ( OO00O0O0O00Oo . rloc . print_address ( ) )
   iiIi1i = lisp . lisp_print_cour ( OO00O0O0O00Oo . print_state ( ) )
   I1i11111i1i11 = lisp . lisp_print_cour ( str ( OO00O0O0O00Oo . priority ) )
   OOoOOO0 = lisp . lisp_print_cour ( str ( OO00O0O0O00Oo . weight ) )
   I1I1i = lisp . lisp_print_cour ( str ( OO00O0O0O00Oo . mpriority ) )
   I1IIIiIiIi = lisp . lisp_print_cour ( str ( OO00O0O0O00Oo . mweight ) )
   IIIII1 = OO00O0O0O00Oo . print_rloc_name ( True )
   if ( IIIII1 != "" ) : IIIII1 = ", " + IIIII1
   if 5 - 5: Ii1I
   II1IIIIiII1i += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>''' . format ( O0i1iI , Ooo , iiIi1i , I1i11111i1i11 , OOoOOO0 , I1I1i , I1IIIiIiIi , IIIII1 )
   if 46 - 46: IiII
   if 45 - 45: ooOoO0o
   if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
   if 17 - 17: OOooOOo / OOooOOo / I11i
 ii1 = "none" if len ( II . registered_rlocs ) == 0 else ""
 if ( ii1 != "" ) : ii1 = lisp . lisp_print_cour ( ii1 )
 II1IIIIiII1i += "<br>Registered RLOC-set ({}): {}<br>" . format ( "merge-semantics" if ( II . merge_register_requested ) else "replacement-semantics" ,
 # OOooOOo
 ii1 )
 if ( ii1 == "" ) :
  for OO00O0O0O00Oo in II . registered_rlocs :
   Ooo = lisp . lisp_print_cour ( OO00O0O0O00Oo . rloc . print_address ( ) )
   iiIi1i = lisp . lisp_print_cour ( OO00O0O0O00Oo . print_state ( ) )
   I1i11111i1i11 = lisp . lisp_print_cour ( str ( OO00O0O0O00Oo . priority ) )
   OOoOOO0 = lisp . lisp_print_cour ( str ( OO00O0O0O00Oo . weight ) )
   I1I1i = lisp . lisp_print_cour ( str ( OO00O0O0O00Oo . mpriority ) )
   I1IIIiIiIi = lisp . lisp_print_cour ( str ( OO00O0O0O00Oo . mweight ) )
   IIIII1 = OO00O0O0O00Oo . print_rloc_name ( True )
   if ( IIIII1 != "" ) : IIIII1 = ", " + IIIII1
   if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
   II1IIIIiII1i += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>''' . format ( I11iiii , Ooo , iiIi1i , I1i11111i1i11 , OOoOOO0 , I1I1i , I1IIIiIiIi , IIIII1 )
   if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
   if ( OO00O0O0O00Oo . geo ) :
    iII1iiiiIII = lisp . lisp_print_cour ( OO00O0O0O00Oo . geo . print_geo_url ( ) )
    II1IIIIiII1i += "{}geo: {}<br>" . format ( IiI1iiiIii , iII1iiiiIII )
    if 78 - 78: OOooOOo * o0oOOo0O0Ooo / I11i - O0 / IiII
   if ( OO00O0O0O00Oo . elp ) :
    oOO = lisp . lisp_print_cour ( OO00O0O0O00Oo . elp . print_elp ( False ) )
    II1IIIIiII1i += "{}elp: {}<br>" . format ( IiI1iiiIii , oOO )
    if 53 - 53: I1Ii111 * IiII . Oo0Ooo - Ii1I % Ii1I * i11iIiiIii
   if ( OO00O0O0O00Oo . rle ) :
    ii = lisp . lisp_print_cour ( OO00O0O0O00Oo . rle . print_rle ( True ) )
    II1IIIIiII1i += "{}rle: {}<br>" . format ( IiI1iiiIii , ii )
    if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
   if ( OO00O0O0O00Oo . json ) :
    ii1III11 = lisp . lisp_print_cour ( OO00O0O0O00Oo . json . print_json ( True ) )
    II1IIIIiII1i += "{}json: {}<br>" . format ( IiI1iiiIii , ii1III11 )
    if 7 - 7: iII111i % O0 . OoOoOO00 + I1IiiI - I11i
    if 75 - 75: I11i
    if 71 - 71: ooOoO0o
    if 53 - 53: OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 ii1 = "none" if len ( II . individual_registrations ) == 0 else ""
 if ( ii1 == "none" ) :
  ii1 = lisp . lisp_print_cour ( ii1 )
 elif ( II . inconsistent_registration ) :
  ii1 = lisp . red ( "inconsistent registrations" , True )
  ii1 = lisp . lisp_print_cour ( ii1 )
  if 28 - 28: I11i
 II1IIIIiII1i += "<br>Individual registrations: {}<br>" . format ( ii1 )
 if 58 - 58: OoOoOO00
 for II in II . individual_registrations . values ( ) :
  iI1i111I1Ii = lisp . green ( "yes" , True ) if II . registered else lisp . red ( "no" , True )
  if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
  oo00O0oO0O0 = "sha1" if ( II . auth_sha1_or_sha2 ) else "sha2"
  oo00O0oO0O0 = lisp . lisp_print_cour ( oo00O0oO0O0 )
  O0I11Iiii1I = II . print_flags ( False )
  O0I11Iiii1I = lisp . lisp_print_cour ( O0I11Iiii1I )
  Ooo = lisp . lisp_print_cour ( II . last_registerer . print_address ( ) )
  o0o00OOo0 = lisp . lisp_print_elapsed ( II . first_registered )
  o0o00OOo0 = lisp . lisp_print_cour ( o0o00OOo0 )
  I1IIii1 = lisp . lisp_print_elapsed ( II . last_registered )
  if ( time . time ( ) - II . last_registered >=
 ( II . register_ttl / 2 ) and I1IIii1 != "never" ) :
   I1IIii1 = lisp . red ( I1IIii1 , True )
   if 73 - 73: i11iIiiIii - IiII
  I1IIii1 = lisp . lisp_print_cour ( I1IIii1 )
  oOooo0 = lisp . lisp_print_cour ( str ( II . site_id ) )
  ooO = lisp . lisp_print_cour ( lisp . lisp_hex_string ( II . xtr_id ) )
  if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
  II1IIIIiII1i += '''
            {}Registerer: {}, xTR-ID: 0x{}, site-id: {}, registered: {}<br>
            {}First registered: {}, last registered: {}, auth-type: {}, 
            registration flags: {}<br>
        ''' . format ( I11iiii , Ooo , ooO , oOooo0 , iI1i111I1Ii , I11iiii , o0o00OOo0 , I1IIii1 , oo00O0oO0O0 ,
 O0I11Iiii1I )
  if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
  ii1 = "none" if len ( II . registered_rlocs ) == 0 else ""
  ii1 = lisp . lisp_print_cour ( ii1 )
  II1IIIIiII1i += "{}Registered RLOC-set: {}<br>" . format ( I11iiii , ii1 )
  if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
  for OO00O0O0O00Oo in II . registered_rlocs :
   Ooo = lisp . lisp_print_cour ( OO00O0O0O00Oo . rloc . print_address ( ) )
   iiIi1i = lisp . lisp_print_cour ( OO00O0O0O00Oo . print_state ( ) )
   I1i11111i1i11 = lisp . lisp_print_cour ( str ( OO00O0O0O00Oo . priority ) )
   OOoOOO0 = lisp . lisp_print_cour ( str ( OO00O0O0O00Oo . weight ) )
   I1I1i = lisp . lisp_print_cour ( str ( OO00O0O0O00Oo . mpriority ) )
   I1IIIiIiIi = lisp . lisp_print_cour ( str ( OO00O0O0O00Oo . mweight ) )
   IIIII1 = OO00O0O0O00Oo . print_rloc_name ( True )
   if ( IIIII1 != "" ) : IIIII1 = ", " + IIIII1
   if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
   II1IIIIiII1i += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>''' . format ( O0i1iI , Ooo , iiIi1i , I1i11111i1i11 , OOoOOO0 , I1I1i , I1IIIiIiIi , IIIII1 )
   if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
   if ( OO00O0O0O00Oo . geo ) :
    iII1iiiiIII = lisp . lisp_print_cour ( OO00O0O0O00Oo . geo . print_geo_url ( ) )
    II1IIIIiII1i += "{}geo: {}<br>" . format ( IiI1iiiIii , iII1iiiiIII )
    if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
   if ( OO00O0O0O00Oo . elp ) :
    oOO = lisp . lisp_print_cour ( OO00O0O0O00Oo . elp . print_elp ( False ) )
    II1IIIIiII1i += "{}elp: {}<br>" . format ( IiI1iiiIii , oOO )
    if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
   if ( OO00O0O0O00Oo . rle ) :
    ii = lisp . lisp_print_cour ( OO00O0O0O00Oo . rle . print_rle ( True ) )
    II1IIIIiII1i += "{}rle: {}<br>" . format ( IiI1iiiIii , ii )
    if 97 - 97: I1IiiI / iII111i
   if ( OO00O0O0O00Oo . json ) :
    ii1III11 = lisp . lisp_print_cour ( OO00O0O0O00Oo . json . print_json ( True ) )
    II1IIIIiII1i += "{}json: {}<br>" . format ( IiI1iiiIii , ii1III11 )
    if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
    if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
  II1IIIIiII1i += "<br>"
  if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 II1IIIIiII1i += "</font>"
 return ( II1IIIIiII1i )
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
def ii1O000OOO0OOo ( ddt_entry , output ) :
 i1i1I111iIi1 = ddt_entry . print_eid_tuple ( )
 oo00O00oO000o = ddt_entry . map_referrals_sent
 if 71 - 71: I1ii11iIi11i - ooOoO0o / OoOoOO00 * OoOoOO00 / i1IIi . i1IIi
 if ( ddt_entry . is_auth_prefix ( ) ) :
  output += lispconfig . lisp_table_row ( i1i1I111iIi1 , "--" , "auth-prefix" , "--" ,
 oo00O00oO000o )
  return ( [ True , output ] )
  if 53 - 53: I1Ii111
  if 21 - 21: I11i
 for OoO00 in ddt_entry . delegation_set :
  o0oOo0Ooo0O = OoO00 . delegate_address
  OO0Ooooo000Oo = str ( OoO00 . priority ) + "/" + str ( OoO00 . weight )
  output += lispconfig . lisp_table_row ( i1i1I111iIi1 , o0oOo0Ooo0O . print_address ( ) ,
 OoO00 . print_node_type ( ) , OO0Ooooo000Oo , oo00O00oO000o )
  if ( i1i1I111iIi1 != "" ) :
   i1i1I111iIi1 = ""
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
  return ( ii1O000OOO0OOo ( ddt_entry , output ) )
  if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
  if 42 - 42: OoOoOO00 * OoOoOO00 * I1Ii111 . I11i
 if ( ddt_entry . source_cache == None ) : return ( [ True , output ] )
 if 51 - 51: OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o * iIii1I11I1II1 % OoO0O00
 if 99 - 99: oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 output = ddt_entry . source_cache . walk_cache ( ii1O000OOO0OOo ,
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
 II1IIIIiII1i = lispconfig . lisp_table_header ( OoOo00o0OO , "EID-Prefix or (S,G)" ,
 "Peer Address" , "Delegation Type" , "Priority/Weight" ,
 "Map-Referrals Sent" )
 if 65 - 65: I1IiiI + OoOoOO00 / OOooOOo
 II1IIIIiII1i = lisp . lisp_ddt_cache . walk_cache ( oooO0 , II1IIIIiII1i )
 II1IIIIiII1i += lispconfig . lisp_table_footer ( )
 return ( II1IIIIiII1i )
 if 83 - 83: o0oOOo0O0Ooo . iII111i - Oo0Ooo
 if 65 - 65: iIii1I11I1II1 / ooOoO0o . IiII - II111iiii
 if 72 - 72: iIii1I11I1II1 / IiII % iII111i % OOooOOo - I11i % OOooOOo
 if 100 - 100: Oo0Ooo + i11iIiiIii
 if 71 - 71: I11i / o0oOOo0O0Ooo / I1Ii111 % OOooOOo
 if 51 - 51: IiII * O0 / II111iiii . Ii1I % OOooOOo / I1IiiI
 if 9 - 9: I1IiiI % I1IiiI % II111iiii
 if 30 - 30: IiII + I1Ii111 - IiII . IiII - II111iiii + O0
def oOO0 ( input_str ) :
 iiI1IiI , i1IIiIii1i , oooo0OOOO , ooOOO0OooOo = lispconfig . lisp_get_lookup_string ( input_str )
 if 33 - 33: OOooOOo / i1IIi - I1IiiI % Oo0Ooo . I1ii11iIi11i
 if 17 - 17: II111iiii / I1ii11iIi11i % IiII + I1IiiI * I1Ii111
 II1IIIIiII1i = "<br>"
 if 36 - 36: I1Ii111 * OoO0O00
 if 23 - 23: I11i . OoooooooOO - OOooOOo + IiII . II111iiii
 if 54 - 54: ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 II = lisp . lisp_site_eid_lookup ( iiI1IiI , oooo0OOOO , i1IIiIii1i )
 if ( II and II . is_star_g ( ) == False ) :
  IIOoO = II . print_eid_tuple ( )
  OOOoO = lisp . green ( "registered" , True ) if II . registered else lisp . red ( "not registered" , True )
  if 14 - 14: I11i . iIii1I11I1II1 . OoooooooOO . II111iiii / o0oOOo0O0Ooo
  II1IIIIiII1i += "{} '{}' {} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Site" ) ,
  # II111iiii % i11iIiiIii
 lisp . lisp_print_cour ( II . site . site_name ) ,
 lisp . lisp_print_sans ( "entry" ) ,
 lisp . lisp_print_cour ( IIOoO ) ,
 lisp . lisp_print_sans ( "found for EID" ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "site EID is" ) ,
 lisp . lisp_print_cour ( OOOoO ) )
  return ( II1IIIIiII1i + "<br>" )
  if 50 - 50: I1IiiI * i11iIiiIii
  if 68 - 68: OOooOOo * O0 . I11i - II111iiii . ooOoO0o / II111iiii
  if 47 - 47: OoooooooOO
  if 4 - 4: I1IiiI % I11i
  if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 o0oO00 , O0o , OOOO0O00o = lisp . lisp_ms_compute_neg_prefix ( iiI1IiI , oooo0OOOO )
 if 95 - 95: OoO0O00
 if ( oooo0OOOO . is_null ( ) ) :
  o0oO00 = lisp . lisp_print_cour ( o0oO00 . print_prefix ( ) )
 else :
  O0o = lisp . lisp_print_cour ( O0o . print_prefix ( ) )
  o0oO00 = lisp . lisp_print_cour ( o0oO00 . print_prefix ( ) )
  o0oO00 = "(" + o0oO00 + ", " + O0o + ")"
  if 60 - 60: OoooooooOO % Oo0Ooo + OOooOOo . ooOoO0o * iIii1I11I1II1
  if 93 - 93: OoO0O00
 if ( OOOO0O00o == lisp . LISP_DDT_ACTION_NOT_AUTH ) :
  i111IOOO0oOoO0O = "Site entry not found for non-authoritative EID"
  II1IIIIiII1i += "{} {} {} {}" . format ( lisp . lisp_print_sans ( i111IOOO0oOoO0O ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 o0oO00 )
  if 84 - 84: O0 * OoooooooOO - IiII * IiII
  if 8 - 8: ooOoO0o / i1IIi . oO0o
  if 41 - 41: iII111i + OoO0O00
  if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
  if 56 - 56: O0
 if ( OOOO0O00o == lisp . LISP_DDT_ACTION_DELEGATION_HOLE ) :
  II11iIiIIIiI = lisp . lisp_ddt_cache_lookup ( iiI1IiI , oooo0OOOO , False )
  if ( II11iIiIIIiI == None or II11iIiIIIiI . is_auth_prefix ( ) == False ) :
   i111IOOO0oOoO0O = "Could not find Authoritative-prefix entry for"
   II1IIIIiII1i += "{} {} {} {}" . format ( lisp . lisp_print_sans ( i111IOOO0oOoO0O ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 o0oO00 )
  else :
   IIOoO = II11iIiIIIiI . print_eid_tuple ( )
   II1IIIIiII1i += "{} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Authoritative-prefix entry" ) ,
   # I1IiiI - i1IIi - ooOoO0o % Oo0Ooo
 lisp . lisp_print_cour ( IIOoO ) ,
 lisp . lisp_print_sans ( "found for EID" ) ,
 lisp . lisp_print_cour ( input_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 o0oO00 )
   if 6 - 6: I1ii11iIi11i + oO0o
   if 48 - 48: iIii1I11I1II1 % i1IIi % iII111i + ooOoO0o
 return ( II1IIIIiII1i + "<br>" )
 if 30 - 30: i11iIiiIii % iIii1I11I1II1 . I11i % iIii1I11I1II1
 if 62 - 62: Oo0Ooo * OoOoOO00
 if 79 - 79: OoO0O00 . iII111i * Ii1I - OOooOOo + ooOoO0o
 if 14 - 14: i11iIiiIii - iII111i * OoOoOO00
 if 51 - 51: I1ii11iIi11i / iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo * ooOoO0o + I1Ii111
 if 77 - 77: ooOoO0o * OoOoOO00
 if 14 - 14: I11i % I11i / IiII
def OoOoO00O0 ( site_eid , site , first , output ) :
 if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
 IIOoO = site_eid . print_eid_tuple ( )
 IIOoO = IIOoO . replace ( "no-address/0" , "" )
 if 29 - 29: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / iII111i
 if 70 - 70: i11iIiiIii % iII111i
 if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
 if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
 iiI1IiI = site_eid . eid
 oooo0OOOO = site_eid . group
 if ( iiI1IiI . is_null ( ) and oooo0OOOO . is_null ( ) == False ) :
  O00oo0ooO = "{}-*-{}" . format ( oooo0OOOO . instance_id , oooo0OOOO . print_prefix_url ( ) )
  IIOoO = "<a href='/lisp/show/site/{}'>{}</a>" . format ( O00oo0ooO , IIOoO )
  if 38 - 38: iIii1I11I1II1 - II111iiii - I1IiiI
 if ( iiI1IiI . is_null ( ) == False and oooo0OOOO . is_null ( ) ) :
  O00oo0ooO = "{}" . format ( iiI1IiI . print_prefix_url ( ) )
  if 71 - 71: OoooooooOO
  if 33 - 33: I1Ii111
  if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
  if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
  if ( O00oo0ooO . find ( "'" ) != - 1 ) :
   O00oo0ooO = O00oo0ooO . replace ( "'" , "name-" , 1 )
   O00oo0ooO = O00oo0ooO . replace ( "'" , "" )
  else :
   if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
   if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
   if 45 - 45: IiII
   if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
   O00oo0ooO = O00oo0ooO . replace ( "+" , "plus-" )
   if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
  IIOoO = "<a href='/lisp/show/site/{}'>{}</a>" . format ( O00oo0ooO , IIOoO )
  if 34 - 34: O0
 if ( iiI1IiI . is_null ( ) == False and oooo0OOOO . is_null ( ) == False ) :
  O00oo0ooO = "{}-{}" . format ( iiI1IiI . print_prefix_url ( ) , oooo0OOOO . print_prefix_url ( ) )
  IIOoO = "<a href='/lisp/show/site/{}'>{}</a>" . format ( O00oo0ooO , IIOoO )
  if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
  if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 Ii1II = site . site_name if first else ""
 O0I11Iiii1I = "--"
 if ( site_eid . registered ) : O0I11Iiii1I = site_eid . print_flags ( True )
 ooO0O0o0 = "--"
 if ( site_eid . last_registerer . afi != lisp . LISP_AFI_NONE ) :
  ooO0O0o0 = site_eid . last_registerer . print_address ( )
  if 92 - 92: Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - I1ii11iIi11i . o0oOOo0O0Ooo
 OOOoO = lisp . green ( "yes" , True ) if site_eid . registered else lisp . red ( "no" , True )
 if 95 - 95: I1Ii111 % I1IiiI
 if ( site . shutdown ) : OOOoO = lisp . red ( "admin-shutdown" , True )
 if 42 - 42: OoooooooOO - iII111i / OoooooooOO / Ii1I
 if ( site_eid . dynamic ) :
  OOOoO += " (dynamic)"
 elif ( site_eid . accept_more_specifics ) :
  OOOoO = "(ams)"
  if 86 - 86: ooOoO0o * o0oOOo0O0Ooo + O0 / I11i . I1IiiI + iIii1I11I1II1
  if 66 - 66: oO0o
 oOoOOOo = lisp . lisp_print_elapsed ( site_eid . last_registered )
 if ( time . time ( ) - site_eid . last_registered >=
 ( site_eid . register_ttl / 2 ) and oOoOOOo != "never" ) :
  oOoOOOo = lisp . red ( oOoOOOo , True )
  if 43 - 43: i1IIi
 I1i11II = lisp . lisp_print_elapsed ( site_eid . first_registered )
 if 31 - 31: oO0o / IiII * o0oOOo0O0Ooo . II111iiii
 if ( site_eid . accept_more_specifics ) :
  oo = len ( site_eid . more_specific_registrations )
  oOOo000oOoO0 = "{} EID-prefixes registered" . format ( oo )
  IIOoO = lisp . lisp_span ( IIOoO , oOOo000oOoO0 )
  if 51 - 51: I1ii11iIi11i
  if 41 - 41: I1ii11iIi11i * ooOoO0o - Ii1I + Oo0Ooo
 output += lispconfig . lisp_table_row ( Ii1II , IIOoO , OOOoO ,
 ooO0O0o0 , oOoOOOo , I1i11II , O0I11Iiii1I )
 return ( output )
 if 23 - 23: II111iiii % o0oOOo0O0Ooo + o0oOOo0O0Ooo + iII111i - iII111i
 if 62 - 62: o0oOOo0O0Ooo
 if 45 - 45: OOooOOo * ooOoO0o
 if 74 - 74: i1IIi + O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
def O0OO0O ( parameter ) :
 if 49 - 49: iIii1I11I1II1 - O0 . i1IIi - OoooooooOO
 if 37 - 37: i1IIi . I11i % OoOoOO00 + OoooooooOO / iII111i
 if 3 - 3: I1ii11iIi11i
 if 17 - 17: I1ii11iIi11i . II111iiii . ooOoO0o / I1ii11iIi11i
 if ( parameter != "" ) :
  if ( parameter . find ( "@lookup" ) != - 1 ) :
   parameter = parameter . split ( "@" )
   return ( oOO0 ( parameter [ 0 ] ) )
   if 57 - 57: I11i
  iiI1IiI = parameter . split ( "%" ) [ 0 ]
  oooo0OOOO = parameter . split ( "%" ) [ 1 ]
  return ( iiii1 ( iiI1IiI , oooo0OOOO ) )
  if 67 - 67: OoO0O00 . ooOoO0o
  if 87 - 87: oO0o % Ii1I
  if 83 - 83: II111iiii - I11i
  if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
  if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 i111IOOO0oOoO0O = "Enter EID for Site-Cache lookup:"
 ooO000O = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 53 - 53: o0oOOo0O0Ooo . iII111i / Ii1I
 II1IIIIiII1i = '''
        <form action="/lisp/show/site/lookup" method="post">
        <i><font face="Courier New" size="3">
        {} {}
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></i></form>
    ''' . format ( lisp . lisp_print_sans ( i111IOOO0oOoO0O ) , ooO000O )
 if 39 - 39: Ii1I % O0 % OoOoOO00 . i1IIi
 if 86 - 86: OoO0O00 * OoooooooOO
 if 71 - 71: iIii1I11I1II1 - OOooOOo . I1IiiI % OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if ( lisp . lisp_ddt_cache . cache_count != 0 ) :
  II1IIIIiII1i += IiI11i1IIiiI ( )
  if 31 - 31: I11i % OOooOOo * I11i
  if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
  if 1 - 1: iIii1I11I1II1
  if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
  if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 oOOo000oOoO0 = ( "{} sites & {} eid-prefixes configured\n{} eid-prefixes " + "registered" ) . format ( len ( II1Ii1iI1i ) ,
 # iII111i - II111iiii
 lisp . lisp_sites_by_eid . cache_size ( ) , lisp . lisp_registered_count )
 if 4 - 4: i1IIi - i11iIiiIii / i11iIiiIii / OoooooooOO
 OoOo00o0OO = lisp . lisp_span ( "LISP-MS Site Information:" , oOOo000oOoO0 )
 II1IIIIiII1i += lispconfig . lisp_table_header ( OoOo00o0OO , "Site Name" ,
 "EID-Prefix or (S,G)" , "Registered" , "Last Registerer" ,
 "Last Registered" , "First Registered" , "Registration Flags" )
 if 100 - 100: Oo0Ooo + o0oOOo0O0Ooo - O0 % II111iiii . iII111i
 for Ii1II in iiI1iIiI :
  IiiIII111ii = II1Ii1iI1i [ Ii1II ]
  ooOo0OoOooo00 = True
  for O0ooo0O0oo0 in IiiIII111ii . allowed_prefixes_sorted :
   II = IiiIII111ii . allowed_prefixes [ O0ooo0O0oo0 ]
   if 96 - 96: I1ii11iIi11i % ooOoO0o % Ii1I - ooOoO0o % OoOoOO00 + I1ii11iIi11i
   II1IIIIiII1i = OoOoO00O0 ( II , IiiIII111ii , ooOo0OoOooo00 , II1IIIIiII1i )
   if ( ooOo0OoOooo00 ) : ooOo0OoOooo00 = False
   if 3 - 3: O0
   for Ooo0Oo0oo0 in II . more_specific_registrations :
    II1IIIIiII1i = OoOoO00O0 ( Ooo0Oo0oo0 , IiiIII111ii , ooOo0OoOooo00 ,
 II1IIIIiII1i )
    if 83 - 83: I1Ii111
    if 48 - 48: II111iiii * OOooOOo * I1Ii111
    if 50 - 50: IiII % i1IIi
    if 21 - 21: OoooooooOO - iIii1I11I1II1
 II1IIIIiII1i += lispconfig . lisp_table_footer ( )
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
 if ( lisp . lisp_pubsub_cache == { } ) : return ( II1IIIIiII1i )
 if 57 - 57: O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 OoOo00o0OO = "LISP-MS Subscriber Information:"
 II1IIIIiII1i += lispconfig . lisp_table_header ( OoOo00o0OO , "EID-prefix" ,
 "Uptime<br>TTL" , "Subscriber RLOC" , "xTR-ID" , "Nonce" ,
 "Map-Notifies<br>Sent" )
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 for iiIiI in lisp . lisp_pubsub_cache :
  iiI1IiI = iiIiI
  for o0Ooo0O00 in lisp . lisp_pubsub_cache [ iiIiI ] . values ( ) :
   ii1o0oooO = o0Ooo0O00 . itr . print_address_no_iid ( ) + ":" + str ( o0Ooo0O00 . port )
   if 89 - 89: II111iiii / oO0o
   IIo0OoO00 = lisp . lisp_print_elapsed ( o0Ooo0O00 . uptime ) + "<br>" + str ( o0Ooo0O00 . ttl ) + " mins"
   if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
   if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
   IIiIiiiIIIIi1 = "--"
   if ( o0Ooo0O00 . xtr_id != None ) :
    IIiIiiiIIIIi1 = "0x" + lisp . lisp_hex_string ( o0Ooo0O00 . xtr_id )
    if 39 - 39: OoO0O00 / Ii1I / I1Ii111
   O00O0 = "0x" + lisp . lisp_hex_string ( o0Ooo0O00 . nonce )
   iIiIiiiIi = o0Ooo0O00 . map_notify_count
   II1IIIIiII1i += lispconfig . lisp_table_row ( iiI1IiI , IIo0OoO00 , ii1o0oooO , IIiIiiiIIIIi1 ,
 O00O0 , iIiIiiiIi )
   iiI1IiI = ""
   if 11 - 11: I11i % i1IIi
   if 16 - 16: I1IiiI + ooOoO0o % OoOoOO00
 II1IIIIiII1i += lispconfig . lisp_table_footer ( )
 return ( II1IIIIiII1i )
 if 80 - 80: ooOoO0o * O0
 if 78 - 78: OoOoOO00
 if 20 - 20: iII111i % Ii1I . Ii1I / I11i + OoOoOO00 . Ii1I
 if 53 - 53: OOooOOo + I1IiiI / i11iIiiIii - o0oOOo0O0Ooo * oO0o / OoooooooOO
 if 89 - 89: iIii1I11I1II1 / I1IiiI - II111iiii / Ii1I . i11iIiiIii . Ii1I
IiiiI1 = {
 "lisp site" : [ iIiiI1 , {
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

 "show site" : [ O0OO0O , { } ]
 }
if 100 - 100: oO0o . Ii1I % i1IIi . ooOoO0o
if 79 - 79: OoO0O00 % OOooOOo / iIii1I11I1II1 + OoOoOO00 * OoO0O00
if 30 - 30: OoooooooOO / I11i + iII111i / I1ii11iIi11i * O0
if 16 - 16: Oo0Ooo / i11iIiiIii
if 64 - 64: i11iIiiIii / Ii1I * i1IIi
if 73 - 73: Oo0Ooo - OoOoOO00 - oO0o - I1IiiI
if 65 - 65: o0oOOo0O0Ooo
def I1ii1II1iII ( site_eid , delete_list ) :
 II1i = lisp . lisp_get_timestamp ( )
 if 81 - 81: I1ii11iIi11i
 if ( site_eid . registered == False ) : return ( delete_list )
 if ( site_eid . last_registered + site_eid . register_ttl > II1i ) :
  return ( delete_list )
  if 94 - 94: I11i + II111iiii % i11iIiiIii
  if 8 - 8: ooOoO0o * O0
  if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
  if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
  if 34 - 34: ooOoO0o
 i1iI1 = "merge" if site_eid . merge_register_requested else "replacement"
 IIi11i1II = "dynamic " if site_eid . dynamic else ""
 site_eid . registered = False
 lisp . lisp_registered_count -= 1
 OO0ooo0o0 = lisp . lisp_print_elapsed ( site_eid . first_registered )
 I1i = site_eid . print_eid_tuple ( )
 ooO0O0o0 = site_eid . last_registerer . print_address_no_iid ( )
 if 69 - 69: I1ii11iIi11i - I1Ii111
 lisp . lprint ( ( "Registration timeout for {}EID-prefix {} site '{}' " + "from {}, was registered for {}, {}-semantics" ) . format ( IIi11i1II ,
 # i11iIiiIii
 lisp . green ( I1i , False ) , site_eid . site . site_name , ooO0O0o0 ,
 OO0ooo0o0 , i1iI1 ) )
 if 36 - 36: Oo0Ooo
 if ( delete_list == None ) : return ( None )
 if 59 - 59: O0 % Oo0Ooo
 if 92 - 92: Ii1I % iII111i / I1ii11iIi11i % I1ii11iIi11i * I1IiiI
 if 74 - 74: O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 23 - 23: I11i
 delete_list . append ( site_eid )
 return ( delete_list )
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
def o0o0oOO ( parent , rle_list ) :
 i1IiI = [ ]
 for OoO00 in parent . individual_registrations . values ( ) :
  i1IiI = I1ii1II1iII ( OoO00 , i1IiI )
  if 1 - 1: IiII / IiII - i11iIiiIii
  if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
 if ( len ( i1IiI ) != 0 and parent . merge_in_site_eid ( None ) ) :
  rle_list . append ( [ parent . eid , parent . group ] )
  if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
 return ( rle_list )
 if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
 if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
 if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
 if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
 if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
 if 77 - 77: OoO0O00 + I1Ii111 + I1Ii111 * Ii1I / OoooooooOO . Ii1I
 if 62 - 62: i1IIi - i1IIi
 if 69 - 69: OoOoOO00 % oO0o - I11i
def Iiii1ii ( ) :
 global i111I
 if 42 - 42: Ii1I * I1Ii111 . IiII * I1IiiI + OoOoOO00
 lisp . lisp_set_exception ( )
 if 25 - 25: I11i . I1IiiI + oO0o
 O00OO0o0 = [ ]
 for IiiIII111ii in II1Ii1iI1i . values ( ) :
  for II in IiiIII111ii . allowed_prefixes . values ( ) :
   if ( II . merge_register_requested == False ) :
    I1ii1II1iII ( II , None )
    if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
    if 30 - 30: iII111i / OoO0O00 + oO0o
   I1I = II
   if 73 - 73: Ii1I
   if 94 - 94: OoO0O00 . OoooooooOO + I11i - OoOoOO00 / II111iiii
   if 70 - 70: I11i % iIii1I11I1II1 . Oo0Ooo + Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
   if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
   if 87 - 87: OoO0O00 % I1IiiI
   O00OO0o0 = o0o0oOO ( I1I , O00OO0o0 )
   if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
   if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
   if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
   if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
   if 84 - 84: i11iIiiIii * OoO0O00
   i1IiI = [ ]
   for I1I1iII1i in I1I . more_specific_registrations :
    O00OO0o0 = o0o0oOO ( I1I1iII1i , O00OO0o0 )
    i1IiI = I1ii1II1iII ( I1I1iII1i , i1IiI )
    if 30 - 30: O0 + I1ii11iIi11i + II111iiii
   for I1I1iII1i in i1IiI :
    I1I . more_specific_registrations . remove ( I1I1iII1i )
    I1I1iII1i . delete_cache ( )
    if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
    if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
    if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
    if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
    if 64 - 64: i1IIi
    if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
    if 18 - 18: OOooOOo + I1Ii111
 if ( len ( O00OO0o0 ) != 0 ) :
  lisp . lisp_queue_multicast_map_notify ( i111I , O00OO0o0 )
  if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
  if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
  if 50 - 50: ooOoO0o + i1IIi
  if 31 - 31: Ii1I
 OOo = threading . Timer ( lisp . LISP_SITE_TIMEOUT_CHECK_INTERVAL ,
 Iiii1ii , [ ] )
 OOo . start ( )
 return
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
def iIIiI1iiI ( ) :
 lisp . lisp_set_exception ( )
 if 18 - 18: iII111i - oO0o % iII111i / I11i
 II1i = lisp . lisp_get_timestamp ( )
 if 68 - 68: Ii1I * iIii1I11I1II1 + I1Ii111 % OoOoOO00
 i1IiI = [ ]
 for iiIiI in lisp . lisp_pubsub_cache :
  for o0Ooo0O00 in lisp . lisp_pubsub_cache [ iiIiI ] . values ( ) :
   iiiII = o0Ooo0O00 . ttl * 60
   if ( o0Ooo0O00 . uptime + iiiII > II1i ) : continue
   i1IiI . append ( [ iiIiI , o0Ooo0O00 . xtr_id ] )
   if 46 - 46: OoOoOO00 % i1IIi / oO0o * Oo0Ooo * OOooOOo
   if 67 - 67: OoOoOO00 * OoOoOO00 . OoOoOO00 + Ii1I / oO0o
   if 13 - 13: iII111i
   if 80 - 80: Ii1I - o0oOOo0O0Ooo
   if 41 - 41: o0oOOo0O0Ooo - Oo0Ooo * I1IiiI
   if 82 - 82: OoO0O00 % o0oOOo0O0Ooo % OOooOOo / O0
 for iiIiI , IIiIiiiIIIIi1 in i1IiI :
  iiI1IiI = lisp . green ( iiIiI , False )
  lisp . lprint ( "Pubsub state {} for xtr-id 0x{} has {}" . format ( iiI1IiI ,
 lisp . lisp_hex_string ( IIiIiiiIIIIi1 ) , lisp . bold ( "timed out" , False ) ) )
  if 94 - 94: I1ii11iIi11i + I1ii11iIi11i + OoooooooOO % ooOoO0o
  if 7 - 7: iII111i
  if 78 - 78: OOooOOo + iII111i . IiII
  if 91 - 91: iIii1I11I1II1 . o0oOOo0O0Ooo . I1ii11iIi11i + OoooooooOO
  o0o0O0Oo = lisp . lisp_pubsub_cache [ iiIiI ] [ IIiIiiiIIIIi1 ]
  lisp . lisp_pubsub_cache [ iiIiI ] . pop ( IIiIiiiIIIIi1 )
  del ( o0o0O0Oo )
  if 1 - 1: iIii1I11I1II1 + Oo0Ooo / O0 - iII111i % IiII + IiII
  if 24 - 24: I1IiiI + Oo0Ooo + OOooOOo - OoooooooOO + Oo0Ooo
  if 93 - 93: ooOoO0o . iIii1I11I1II1 % i11iIiiIii . OoOoOO00 % ooOoO0o + O0
  if 65 - 65: Ii1I + OoO0O00 - OoooooooOO
  if 51 - 51: Oo0Ooo + oO0o / iII111i - i1IIi
  if ( len ( lisp . lisp_pubsub_cache [ iiIiI ] ) == 0 ) :
   lisp . lisp_pubsub_cache . pop ( iiIiI )
   if 51 - 51: Oo0Ooo - I1ii11iIi11i * I11i
   if 12 - 12: iIii1I11I1II1 % ooOoO0o % ooOoO0o
   if 78 - 78: IiII . OoOoOO00 . I11i
   if 97 - 97: oO0o
   if 80 - 80: I1IiiI . Ii1I
   if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 Ii1IIii11 = threading . Timer ( lisp . LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL , iIIiI1iiI , [ ] )
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
 Ii1IIii11 . start ( )
 return
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
 if 60 - 60: OoO0O00
 if 81 - 81: OoOoOO00 % Ii1I
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
def o0o ( ) :
 global II1iII1i
 global i111I
 global OOo , Ii1IIii11
 if 93 - 93: ooOoO0o % i11iIiiIii % I1Ii111
 lisp . lisp_i_am ( "ms" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "Map-Server starting up" )
 if 64 - 64: I1Ii111 + I1IiiI * O0 / Oo0Ooo - I11i % I11i
 if 59 - 59: OOooOOo + OoooooooOO
 if 55 - 55: i11iIiiIii % iIii1I11I1II1 . i1IIi + OoooooooOO / i11iIiiIii
 if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
 if 17 - 17: Ii1I
 if 39 - 39: ooOoO0o . II111iiii
 if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
 II1iII1i = lisp . lisp_open_listen_socket ( "" , "lisp-ms" )
 i111I [ 0 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV4 )
 i111I [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 i111I [ 2 ] = II1iII1i
 if 77 - 77: I1Ii111 - I11i
 if 11 - 11: I1ii11iIi11i
 if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
 if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
 OOo = threading . Timer ( lisp . LISP_SITE_TIMEOUT_CHECK_INTERVAL ,
 Iiii1ii , [ ] )
 OOo . start ( )
 if 55 - 55: ooOoO0o
 if 82 - 82: I1Ii111 - OOooOOo + OoO0O00
 if 64 - 64: o0oOOo0O0Ooo . O0 * Ii1I + OoooooooOO - Oo0Ooo . OoooooooOO
 if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
 Ii1IIii11 = threading . Timer ( lisp . LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL , iIIiI1iiI , [ ] )
 if 55 - 55: iII111i - OoO0O00
 Ii1IIii11 . start ( )
 return ( True )
 if 100 - 100: O0
 if 79 - 79: iIii1I11I1II1
 if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
 if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 if 11 - 11: i1IIi % OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
def O0oo0O0 ( ) :
 global OOo
 if 2 - 2: OoooooooOO . OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 OOo . cancel ( )
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 lisp . lisp_close_socket ( i111I [ 0 ] , "" )
 lisp . lisp_close_socket ( i111I [ 1 ] , "" )
 lisp . lisp_close_socket ( II1iII1i , "lisp-ms" )
 return
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
if ( o0o ( ) == False ) :
 lisp . lprint ( "lisp_ms_startup() failed" )
 lisp . lisp_print_banner ( "Map-Server abnormal exit" )
 exit ( 1 )
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
while ( True ) :
 OOoo0oOO00 , ii11iiIi , i11iI11I1I , Ii1iiIi1I11i = lisp . lisp_receive ( II1iII1i , True )
 if 89 - 89: I1Ii111 . IiII % Oo0Ooo . Oo0Ooo - OoooooooOO
 if ( ii11iiIi == "" ) : break
 if 56 - 56: I11i
 if ( OOoo0oOO00 == "command" ) :
  lispconfig . lisp_process_command ( II1iII1i , OOoo0oOO00 ,
 Ii1iiIi1I11i , "lisp-ms" , [ IiiiI1 , lisp . lisp_policy_commands ] )
 elif ( OOoo0oOO00 == "api" ) :
  lisp . lisp_process_api ( "lisp-ms" , II1iII1i , Ii1iiIi1I11i )
 else :
  lisp . lisp_parse_packet ( i111I , Ii1iiIi1I11i , ii11iiIi , i11iI11I1I )
  if 21 - 21: iIii1I11I1II1 / I1Ii111 + ooOoO0o - I11i / Oo0Ooo / II111iiii
  if 69 - 69: I1IiiI . OoOoOO00
  if 53 - 53: I11i
O0oo0O0 ( )
lisp . lisp_print_banner ( "Map-Server normal exit" )
exit ( 0 )
if 68 - 68: oO0o / I1Ii111 % I1Ii111 % O0
if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
