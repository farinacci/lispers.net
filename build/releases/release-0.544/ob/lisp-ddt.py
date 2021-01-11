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
# lisp-ddt.py
#
# This file performs LISP DDT node functionality.
#
# -----------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
import lisp
import lispconfig
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
i1I1ii1II1iII = [ None , None , None ]
oooO0oo0oOOOO = None
if 53 - 53: I11i / Oo0Ooo / II111iiii % Ii1I / OoOoOO00 . ooOoO0o
if 100 - 100: i1IIi
if 27 - 27: IiII * OoooooooOO + I11i * ooOoO0o - i11iIiiIii - iII111i
if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . II111iiii - oO0o
if 72 - 72: II111iiii - OoOoOO00
if 91 - 91: OoO0O00 . i11iIiiIii / oO0o % I11i / OoO0O00 - i11iIiiIii
if 8 - 8: o0oOOo0O0Ooo * I1ii11iIi11i * iIii1I11I1II1 . IiII / IiII % IiII
if 22 - 22: Ii1I . IiII
def I11 ( kv_pair ) :
 Oo0o0000o0o0 = lisp . lisp_ddt_entry ( )
 if 86 - 86: OoOoOO00 % I1IiiI
 for oo in kv_pair . keys ( ) :
  IiII1I1i1i1ii = kv_pair [ oo ]
  if 44 - 44: oO0o / Oo0Ooo - II111iiii - i11iIiiIii % I1Ii111
  if ( oo == "instance-id" ) :
   O0OoOoo00o = IiII1I1i1i1ii . split ( "-" )
   if ( O0OoOoo00o [ 0 ] == "" ) : continue
   if 31 - 31: II111iiii + OoO0O00 . I1Ii111
   OoOooOOOO = ( kv_pair . has_key ( "eid-prefix" ) == False or
 kv_pair [ "eid-prefix" ] == "" )
   i11iiII = ( kv_pair . has_key ( "group-prefix" ) == False or
 kv_pair [ "group-prefix" ] == "" )
   if 34 - 34: OOooOOo % OoooooooOO / i1IIi . iII111i + O0
   if ( OoOooOOOO and i11iiII ) :
    Oo0o0000o0o0 . eid . store_iid_range ( int ( O0OoOoo00o [ 0 ] ) , int ( O0OoOoo00o [ 1 ] ) )
   else :
    Oo0o0000o0o0 . eid . instance_id = int ( O0OoOoo00o [ 0 ] )
    Oo0o0000o0o0 . group . instance_id = int ( O0OoOoo00o [ 0 ] )
    if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
    if 78 - 78: OoO0O00
  if ( oo == "eid-prefix" ) :
   Oo0o0000o0o0 . eid . store_prefix ( IiII1I1i1i1ii )
   if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
  if ( oo == "group-prefix" ) :
   Oo0o0000o0o0 . group . store_prefix ( IiII1I1i1i1ii )
   if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
   if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
   if 14 - 14: I11i % O0
   if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
   if 77 - 77: Oo0Ooo . IiII % ooOoO0o
   if 42 - 42: oO0o - i1IIi / i11iIiiIii + OOooOOo + OoO0O00
   if 17 - 17: oO0o . Oo0Ooo . I1ii11iIi11i
 IIi = lisp . lisp_ddt_cache_lookup ( Oo0o0000o0o0 . eid , Oo0o0000o0o0 . group , True )
 if ( IIi != None and IIi . is_auth_prefix ( ) == False ) : return
 if 38 - 38: Ii1I / Oo0Ooo
 if 76 - 76: O0 / o0oOOo0O0Ooo . I1IiiI * Ii1I - OOooOOo
 if 76 - 76: i11iIiiIii / iIii1I11I1II1 . I1ii11iIi11i % OOooOOo / OoooooooOO % oO0o
 if 75 - 75: iII111i
 Oo0o0000o0o0 . add_cache ( )
 return
 if 97 - 97: i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 if 61 - 61: ooOoO0o
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
def oOOo0oo ( kv_pair ) :
 o0oo0o0O00OO = [ ]
 for o0oO in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  Oo0o0000o0o0 = lisp . lisp_ddt_entry ( )
  o0oo0o0O00OO . append ( Oo0o0000o0o0 )
  if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
  if 20 - 20: o0oOOo0O0Ooo
 oO00 = [ ]
 if ( kv_pair . has_key ( "eid-prefix" ) ) :
  for o0oO in kv_pair [ "eid-prefix" ] : oO00 . append ( o0oO )
  if 53 - 53: OoooooooOO . i1IIi
  if 18 - 18: o0oOOo0O0Ooo
 I1i1I1II = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for o0oO in range ( len ( kv_pair [ "address" ] ) ) :
   i1 = lisp . lisp_ddt_node ( )
   I1i1I1II . append ( i1 )
   if 48 - 48: O0 + O0 - I1ii11iIi11i . ooOoO0o / iIii1I11I1II1
   if 77 - 77: i1IIi % OoOoOO00 - IiII + ooOoO0o
   if 31 - 31: I11i - i1IIi * OOooOOo / OoooooooOO
 for oo in kv_pair . keys ( ) :
  IiII1I1i1i1ii = kv_pair [ oo ]
  if ( oo == "instance-id" ) :
   for iI in range ( len ( o0oo0o0O00OO ) ) :
    Oo0o0000o0o0 = o0oo0o0O00OO [ iI ]
    O0OoOoo00o = IiII1I1i1i1ii [ iI ] . split ( "-" )
    if ( O0OoOoo00o [ 0 ] == "" ) : continue
    if 60 - 60: I11i / I11i
    OoOooOOOO = ( kv_pair [ "eid-prefix" ] [ iI ] == "" and
 kv_pair [ "group-prefix" ] [ iI ] == "" )
    if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
    if ( OoOooOOOO ) :
     Oo0o0000o0o0 . eid . store_iid_range ( int ( O0OoOoo00o [ 0 ] ) , int ( O0OoOoo00o [ 1 ] ) )
    else :
     Oo0o0000o0o0 . eid . instance_id = int ( O0OoOoo00o [ 0 ] )
     Oo0o0000o0o0 . group . instance_id = int ( O0OoOoo00o [ 0 ] )
     if 83 - 83: OoooooooOO
     if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
     if 4 - 4: II111iiii / ooOoO0o . iII111i
  if ( oo == "eid-prefix" ) :
   for iI in range ( len ( o0oo0o0O00OO ) ) :
    Oo0o0000o0o0 = o0oo0o0O00OO [ iI ]
    O0oo0OO0oOOOo = IiII1I1i1i1ii [ iI ]
    if ( O0oo0OO0oOOOo == "" ) : continue
    Oo0o0000o0o0 . eid . store_prefix ( O0oo0OO0oOOOo )
    if 35 - 35: IiII % I1IiiI
    if 70 - 70: iII111i * I1ii11iIi11i
  if ( oo == "group-prefix" ) :
   for iI in range ( len ( o0oo0o0O00OO ) ) :
    Oo0o0000o0o0 = o0oo0o0O00OO [ iI ]
    O0oo0OO0oOOOo = IiII1I1i1i1ii [ iI ]
    if ( O0oo0OO0oOOOo == "" ) : continue
    Oo0o0000o0o0 . group . store_prefix ( O0oo0OO0oOOOo )
    if 46 - 46: ooOoO0o / OoO0O00
    if 52 - 52: o0oOOo0O0Ooo - OoooooooOO + Ii1I + Ii1I - o0oOOo0O0Ooo / I1Ii111
    if 44 - 44: ooOoO0o . i1IIi - I1ii11iIi11i . O0 - ooOoO0o
  if ( oo == "priority" ) :
   for iI in range ( len ( I1i1I1II ) ) :
    i1 = I1i1I1II [ iI ]
    O0OoOoo00o = IiII1I1i1i1ii [ iI ]
    if ( O0OoOoo00o == "" ) : O0OoOoo00o = "0"
    i1 . priority = int ( O0OoOoo00o )
    if 92 - 92: iII111i . I11i + o0oOOo0O0Ooo
    if 28 - 28: i1IIi * Oo0Ooo - o0oOOo0O0Ooo * IiII * Ii1I / OoO0O00
  if ( oo == "weight" ) :
   for iI in range ( len ( I1i1I1II ) ) :
    i1 = I1i1I1II [ iI ]
    O0OoOoo00o = IiII1I1i1i1ii [ iI ]
    if ( O0OoOoo00o == "" ) : O0OoOoo00o = "0"
    i1 . weight = int ( O0OoOoo00o )
    if 94 - 94: II111iiii % I1ii11iIi11i / OoOoOO00 * iIii1I11I1II1
    if 54 - 54: o0oOOo0O0Ooo - I1IiiI + OoooooooOO
  if ( oo == "address" ) :
   for iI in range ( len ( I1i1I1II ) ) :
    i1 = I1i1I1II [ iI ]
    O0OoOoo00o = IiII1I1i1i1ii [ iI ]
    if ( O0OoOoo00o != "" ) : i1 . delegate_address . store_address ( O0OoOoo00o )
    if 70 - 70: Ii1I / I11i . iII111i % Oo0Ooo
    if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . IiII - OoO0O00 * o0oOOo0O0Ooo
  if ( oo == "public_key" ) :
   for iI in range ( len ( I1i1I1II ) ) :
    i1 = I1i1I1II [ iI ]
    O0OoOoo00o = IiII1I1i1i1ii [ iI ]
    i1 . public_key = O0OoOoo00o
    if 46 - 46: OOooOOo + OoOoOO00 . I1IiiI * oO0o % IiII
    if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
  if ( oo == "node-type" ) :
   for iI in range ( len ( I1i1I1II ) ) :
    i1 = I1i1I1II [ iI ]
    O0OoOoo00o = IiII1I1i1i1ii [ iI ]
    if ( O0OoOoo00o == "map-server-child" ) : i1 . map_server_child = True
    if 44 - 44: oO0o
    if 88 - 88: I1Ii111 % Ii1I . II111iiii
    if 38 - 38: o0oOOo0O0Ooo
    if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
    if 26 - 26: iII111i
    if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
    if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
    if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
 for Oo0o0000o0o0 in o0oo0o0O00OO :
  Oo0o0000o0o0 . add_cache ( )
  for i1 in I1i1I1II :
   Oo0o0000o0o0 . delegation_set . append ( i1 )
   if 91 - 91: oO0o % Oo0Ooo
   if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
 return
 if 31 - 31: I11i - II111iiii . I11i
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 if 92 - 92: iII111i . I1Ii111
 if 31 - 31: I1Ii111 . OoOoOO00 / O0
def o000O0o ( eid_str ) :
 iI1iII1 , oO0OOoo0OO , O0ii1ii1ii , oooooOoo0ooo = lispconfig . lisp_get_lookup_string ( eid_str )
 if 6 - 6: I11i - Ii1I + iIii1I11I1II1 - I1Ii111 - i11iIiiIii
 if 79 - 79: OoOoOO00 - O0 * OoO0O00 + OoOoOO00 % O0 * O0
 oOOo0 = "<br>"
 if 54 - 54: O0 - IiII % OOooOOo
 if 77 - 77: OoOoOO00 / I1IiiI / OoO0O00 + OoO0O00 . OOooOOo
 if 38 - 38: I1Ii111
 if 7 - 7: O0 . iII111i % I1ii11iIi11i - I1IiiI - iIii1I11I1II1
 Oo0o0000o0o0 = lisp . lisp_ddt_cache_lookup ( iI1iII1 , O0ii1ii1ii , oO0OOoo0OO )
 if ( Oo0o0000o0o0 == None ) :
  I111IIIiIii = "DDT entry not found for non-authoritative EID"
  oOOo0 += "{} {}" . format ( lisp . lisp_print_sans ( I111IIIiIii ) ,
 lisp . lisp_print_cour ( eid_str ) )
  return ( oOOo0 + "<br>" )
  if 85 - 85: I1ii11iIi11i % iII111i % ooOoO0o
  if 82 - 82: i11iIiiIii - iII111i * OoooooooOO / I11i
 if ( Oo0o0000o0o0 . is_auth_prefix ( ) ) :
  if ( O0ii1ii1ii . is_null ( ) ) :
   i1oOo = lisp . lisp_ddt_compute_neg_prefix ( iI1iII1 , Oo0o0000o0o0 ,
 lisp . lisp_ddt_cache )
   i1oOo = lisp . lisp_print_cour ( i1oOo . print_prefix ( ) ) ,
  else :
   oOO00Oo = lisp . lisp_ddt_compute_neg_prefix ( O0ii1ii1ii , Oo0o0000o0o0 ,
 lisp . lisp_ddt_cache )
   i1oOo = lisp . lisp_ddt_compute_neg_prefix ( iI1iII1 , Oo0o0000o0o0 ,
 Oo0o0000o0o0 . source_cache )
   i1oOo = lisp . lisp_print_cour ( "(" + i1oOo . print_prefix ( ) + ", " )
   if 6 - 6: oO0o
   oOO00Oo = lisp . lisp_print_cour ( oOO00Oo . print_prefix ( ) + ")" )
   if 68 - 68: OoOoOO00 - OoO0O00
   i1oOo += oOO00Oo
   if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
   if 1 - 1: iIii1I11I1II1 / II111iiii
  oOOo0 += "{} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "DDT authoritative-prefix entry" ) ,
  # I11i . OoooooooOO
 lisp . lisp_print_cour ( Oo0o0000o0o0 . print_eid_tuple ( ) ) ,
 lisp . lisp_print_sans ( "found for EID" ) ,
 lisp . lisp_print_cour ( eid_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 i1oOo )
 else :
  oOOo0 += "{} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "DDT entry" ) ,
  # o0oOOo0O0Ooo % iII111i * O0
 lisp . lisp_print_cour ( Oo0o0000o0o0 . print_eid_tuple ( ) ) ,
 lisp . lisp_print_sans ( "found for EID" ) ,
 lisp . lisp_print_cour ( eid_str ) ,
 lisp . lisp_print_sans ( ", delegation-type" ) ,
 lisp . lisp_print_cour ( Oo0o0000o0o0 . print_referral_type ( ) ) )
  if 87 - 87: i11iIiiIii
 return ( oOOo0 + "<br>" )
 if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
 if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
def ii ( ddt_entry , output ) :
 oOooOOOoOo = ddt_entry . print_eid_tuple ( )
 i1Iii1i1I = ddt_entry . map_referrals_sent
 if 91 - 91: I1ii11iIi11i + I1IiiI . OOooOOo * I1ii11iIi11i + I1IiiI * Oo0Ooo
 if ( ddt_entry . is_auth_prefix ( ) ) :
  output += lispconfig . lisp_table_row ( oOooOOOoOo , "--" , "auth-prefix" , "--" ,
 i1Iii1i1I )
  return ( [ True , output ] )
  if 80 - 80: iII111i % OOooOOo % oO0o - Oo0Ooo + Oo0Ooo
  if 19 - 19: OoOoOO00 * i1IIi
 for i1 in ddt_entry . delegation_set :
  ii111iI1iIi1 = i1 . delegate_address
  OOO = str ( i1 . priority ) + "/" + str ( i1 . weight )
  output += lispconfig . lisp_table_row ( oOooOOOoOo ,
 ii111iI1iIi1 . print_address_no_iid ( ) , i1 . print_node_type ( ) , OOO , i1Iii1i1I )
  if ( oOooOOOoOo != "" ) :
   oOooOOOoOo = ""
   i1Iii1i1I = ""
   if 68 - 68: II111iiii + I11i
   if 45 - 45: iII111i / iII111i + I1Ii111 + ooOoO0o
 return ( [ True , output ] )
 if 47 - 47: o0oOOo0O0Ooo + ooOoO0o
 if 82 - 82: II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
 if 77 - 77: iIii1I11I1II1 * OoO0O00
 if 95 - 95: I1IiiI + i11iIiiIii
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 if 53 - 53: II111iiii
def i1Ii1Ii ( ddt_entry , output ) :
 if 52 - 52: OoO0O00 . oO0o
 if 25 - 25: O0 - O0 * o0oOOo0O0Ooo
 if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
 if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
 if ( ddt_entry . group . is_null ( ) ) :
  return ( ii ( ddt_entry , output ) )
  if 82 - 82: Ii1I
  if 46 - 46: OoooooooOO . i11iIiiIii
 if ( ddt_entry . source_cache == None ) : return ( [ True , output ] )
 if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 if 87 - 87: Oo0Ooo . IiII
 if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
 if 55 - 55: OOooOOo . I1IiiI
 if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
 output = ddt_entry . source_cache . walk_cache ( ii ,
 output )
 return ( [ True , output ] )
 if 100 - 100: I1Ii111 * O0
 if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
 if 79 - 79: O0
 if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
 if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 if 57 - 57: OoO0O00 / ooOoO0o
 if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
def I111I1Iiii1i ( parameter ) :
 if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if ( parameter != "" ) :
  return ( o000O0o ( parameter ) )
  if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
  if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
  if 63 - 63: OoOoOO00 * iII111i
  if 69 - 69: O0 . OoO0O00
  if 49 - 49: I1IiiI - I11i
 I111IIIiIii = "Enter EID for DDT-Cache lookup:"
 OoOOoOooooOOo = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 87 - 87: I1IiiI
 oOOo0 = '''
        <form action="/lisp/show/delegations/lookup" method="post">
        <i><font face="Courier New" size="3">
        {} {}
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></i></form>
    ''' . format ( lisp . lisp_print_sans ( I111IIIiIii ) , OoOOoOooooOOo )
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if 97 - 97: O0 + OoOoOO00
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 iiIiI1i1 = "{} entries in delegation-cache" . format ( lisp . lisp_ddt_cache . cache_size ( ) )
 if 69 - 69: ooOoO0o
 I11iII = lisp . lisp_span ( "LISP-DDT Configured Delegations:" , iiIiI1i1 )
 if 5 - 5: I1IiiI
 oOOo0 += lispconfig . lisp_table_header ( I11iII , "EID-Prefix or (S,G)" ,
 "Delegation Address" , "Delegation Type" , "Priority/Weight" ,
 "Map-Referrals Sent" )
 if 48 - 48: o0oOOo0O0Ooo - oO0o / OoooooooOO
 oOOo0 = lisp . lisp_ddt_cache . walk_cache ( i1Ii1Ii , oOOo0 )
 oOOo0 += lispconfig . lisp_table_footer ( )
 return ( oOOo0 )
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo % II111iiii % Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
 if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
 if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
def o00oo0 ( ) :
 global i1I1ii1II1iII
 global oooO0oo0oOOOO
 if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
 lisp . lisp_i_am ( "ddt" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "DDT-Node starting up" )
 if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
 if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
 if 76 - 76: IiII * iII111i
 if 52 - 52: OOooOOo
 oooO0oo0oOOOO = lisp . lisp_open_listen_socket ( "" , "lisp-ddt" )
 i1I1ii1II1iII [ 0 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV4 )
 i1I1ii1II1iII [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 i1I1ii1II1iII [ 2 ] = oooO0oo0oOOOO
 return
 if 19 - 19: I1IiiI
 if 25 - 25: Ii1I / ooOoO0o
 if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 if 71 - 71: I1Ii111 . II111iiii
 if 62 - 62: OoooooooOO . I11i
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
 if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
def oOooO ( ) :
 if 10 - 10: OoOoOO00 % OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
 if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 lisp . lisp_close_socket ( i1I1ii1II1iII [ 0 ] , "" )
 lisp . lisp_close_socket ( i1I1ii1II1iII [ 1 ] , "" )
 lisp . lisp_close_socket ( oooO0oo0oOOOO , "lisp-ddt" )
 return
 if 23 - 23: i11iIiiIii
 if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
 if 81 - 81: IiII % i1IIi . iIii1I11I1II1
 if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
 if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
iiii111II = {
 "lisp ddt-authoritative-prefix" : [ I11 , {
 "instance-id" : [ False , 0 , 0xffffffff , True ] ,
 "eid-prefix" : [ False ] ,
 "group-prefix" : [ False ] , } ] ,

 "lisp delegation" : [ oOOo0oo , {
 "delegate" : [ ] ,
 "address" : [ True ] ,
 "node-type" : [ True , "ddt-child" , "map-server-child" ] ,
 "priority" : [ True , 0 , 255 ] ,
 "weight" : [ True , 0 , 100 ] ,
 "public-key" : [ True ] ,
 "prefix" : [ ] ,
 "instance-id" : [ True , 0 , 0xffffffff , True ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] } ] ,

 "show delegations" : [ I111I1Iiii1i , { } ] ,
 }
if 50 - 50: OOooOOo * I1IiiI % iIii1I11I1II1 + Ii1I + iII111i + I1IiiI
if 71 - 71: I1ii11iIi11i * I1ii11iIi11i * i1IIi . oO0o / I1Ii111
if 85 - 85: I11i
if 20 - 20: oO0o % IiII
if 19 - 19: I1ii11iIi11i % IiII + ooOoO0o / I1Ii111 . ooOoO0o
if 12 - 12: i1IIi + i1IIi - I1ii11iIi11i * Oo0Ooo % Oo0Ooo - II111iiii
if ( o00oo0 ( ) ) :
 lisp . lprint ( "lisp_ddt_startup() failed" )
 lisp . lisp_print_banner ( "DDT-Node abnormal exit" )
 exit ( 1 )
 if 52 - 52: ooOoO0o . iII111i + I1Ii111
 if 38 - 38: i1IIi - II111iiii . I1Ii111
while ( True ) :
 ooO , o0o00OOo0 , I1IIii1 , OO0o0oOOO0O = lisp . lisp_receive ( oooO0oo0oOOOO , True )
 if 49 - 49: I1ii11iIi11i . o0oOOo0O0Ooo . II111iiii
 if ( o0o00OOo0 == "" ) : break
 if 98 - 98: iII111i
 if ( ooO == "command" ) :
  lispconfig . lisp_process_command ( oooO0oo0oOOOO , ooO ,
 OO0o0oOOO0O , "lisp-ddt" , [ iiii111II ] )
 else :
  lisp . lisp_parse_packet ( i1I1ii1II1iII , OO0o0oOOO0O , o0o00OOo0 , I1IIii1 )
  if 68 - 68: iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
  if 38 - 38: ooOoO0o - OOooOOo / iII111i
  if 66 - 66: O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / Ii1I + I1ii11iIi11i
oOooO ( )
lisp . lisp_print_banner ( "DDT-Node normal exit" )
exit ( 0 )
if 86 - 86: o0oOOo0O0Ooo
if 5 - 5: IiII * OoOoOO00
if 5 - 5: I1Ii111
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
