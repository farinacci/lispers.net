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
 if ( lispconfig . lisp_clause_syntax_error ( kv_pair , "eid-prefix" ,
 "prefix" ) ) : return
 for o0oO in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  Oo0o0000o0o0 = lisp . lisp_ddt_entry ( )
  o0oo0o0O00OO . append ( Oo0o0000o0o0 )
  if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
  if 20 - 20: o0oOOo0O0Ooo
 oO00 = [ ]
 for o0oO in kv_pair [ "eid-prefix" ] : oO00 . append ( o0oO )
 if 53 - 53: OoooooooOO . i1IIi
 ii1I1i1I = [ ]
 if ( lispconfig . lisp_clause_syntax_error ( kv_pair , "address" ,
 "delegate" ) ) : return
 for o0oO in range ( len ( kv_pair [ "address" ] ) ) :
  OOoo0O0 = lisp . lisp_ddt_node ( )
  ii1I1i1I . append ( OOoo0O0 )
  if 41 - 41: oO0o
  if 6 - 6: I1ii11iIi11i
 for oo in kv_pair . keys ( ) :
  IiII1I1i1i1ii = kv_pair [ oo ]
  if ( oo == "instance-id" ) :
   for I1I in range ( len ( o0oo0o0O00OO ) ) :
    Oo0o0000o0o0 = o0oo0o0O00OO [ I1I ]
    O0OoOoo00o = IiII1I1i1i1ii [ I1I ] . split ( "-" )
    if ( O0OoOoo00o [ 0 ] == "" ) : continue
    if 80 - 80: OoOoOO00 - OoO0O00
    OoOooOOOO = ( kv_pair [ "eid-prefix" ] [ I1I ] == "" and
 kv_pair [ "group-prefix" ] [ I1I ] == "" )
    if 87 - 87: oO0o / I11i - i1IIi * OOooOOo / OoooooooOO . O0
    if ( OoOooOOOO ) :
     Oo0o0000o0o0 . eid . store_iid_range ( int ( O0OoOoo00o [ 0 ] ) , int ( O0OoOoo00o [ 1 ] ) )
    else :
     Oo0o0000o0o0 . eid . instance_id = int ( O0OoOoo00o [ 0 ] )
     Oo0o0000o0o0 . group . instance_id = int ( O0OoOoo00o [ 0 ] )
     if 1 - 1: II111iiii - I11i / I11i
     if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
     if 83 - 83: OoooooooOO
  if ( oo == "eid-prefix" ) :
   for I1I in range ( len ( o0oo0o0O00OO ) ) :
    Oo0o0000o0o0 = o0oo0o0O00OO [ I1I ]
    Iii111II = IiII1I1i1i1ii [ I1I ]
    if ( Iii111II == "" ) : continue
    Oo0o0000o0o0 . eid . store_prefix ( Iii111II )
    if 9 - 9: OoO0O00
    if 33 - 33: ooOoO0o . iII111i
  if ( oo == "group-prefix" ) :
   for I1I in range ( len ( o0oo0o0O00OO ) ) :
    Oo0o0000o0o0 = o0oo0o0O00OO [ I1I ]
    Iii111II = IiII1I1i1i1ii [ I1I ]
    if ( Iii111II == "" ) : continue
    Oo0o0000o0o0 . group . store_prefix ( Iii111II )
    if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
    if 50 - 50: I1IiiI
    if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
  if ( oo == "priority" ) :
   for I1I in range ( len ( ii1I1i1I ) ) :
    OOoo0O0 = ii1I1i1I [ I1I ]
    O0OoOoo00o = IiII1I1i1i1ii [ I1I ]
    if ( O0OoOoo00o == "" ) : O0OoOoo00o = "0"
    OOoo0O0 . priority = int ( O0OoOoo00o )
    if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
    if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
  if ( oo == "weight" ) :
   for I1I in range ( len ( ii1I1i1I ) ) :
    OOoo0O0 = ii1I1i1I [ I1I ]
    O0OoOoo00o = IiII1I1i1i1ii [ I1I ]
    if ( O0OoOoo00o == "" ) : O0OoOoo00o = "0"
    OOoo0O0 . weight = int ( O0OoOoo00o )
    if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
    if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
  if ( oo == "address" ) :
   for I1I in range ( len ( ii1I1i1I ) ) :
    OOoo0O0 = ii1I1i1I [ I1I ]
    O0OoOoo00o = IiII1I1i1i1ii [ I1I ]
    if ( O0OoOoo00o != "" ) : OOoo0O0 . delegate_address . store_address ( O0OoOoo00o )
    if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
    if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
  if ( oo == "public_key" ) :
   for I1I in range ( len ( ii1I1i1I ) ) :
    OOoo0O0 = ii1I1i1I [ I1I ]
    O0OoOoo00o = IiII1I1i1i1ii [ I1I ]
    OOoo0O0 . public_key = O0OoOoo00o
    if 58 - 58: i11iIiiIii % I11i
    if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
  if ( oo == "node-type" ) :
   for I1I in range ( len ( ii1I1i1I ) ) :
    OOoo0O0 = ii1I1i1I [ I1I ]
    O0OoOoo00o = IiII1I1i1i1ii [ I1I ]
    if ( O0OoOoo00o == "map-server-child" ) : OOoo0O0 . map_server_child = True
    if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
    if 16 - 16: I1IiiI * oO0o % IiII
    if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
    if 44 - 44: oO0o
    if 88 - 88: I1Ii111 % Ii1I . II111iiii
    if 38 - 38: o0oOOo0O0Ooo
    if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
    if 26 - 26: iII111i
 for Oo0o0000o0o0 in o0oo0o0O00OO :
  Oo0o0000o0o0 . add_cache ( )
  for OOoo0O0 in ii1I1i1I :
   Oo0o0000o0o0 . delegation_set . append ( OOoo0O0 )
   if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
   if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
 return
 if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
 if 91 - 91: oO0o % Oo0Ooo
 if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
 if 31 - 31: I11i - II111iiii . I11i
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
def O0ooo0O0oo0 ( eid_str ) :
 oo0oOo , o000O0o , iI1iII1 , oO0OOoo0OO = lispconfig . lisp_get_lookup_string ( eid_str )
 if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
 if 21 - 21: I1IiiI * iIii1I11I1II1
 oooooOoo0ooo = "<br>"
 if 6 - 6: I11i - Ii1I + iIii1I11I1II1 - I1Ii111 - i11iIiiIii
 if 79 - 79: OoOoOO00 - O0 * OoO0O00 + OoOoOO00 % O0 * O0
 if 61 - 61: II111iiii
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 Oo0o0000o0o0 = lisp . lisp_ddt_cache_lookup ( oo0oOo , iI1iII1 , o000O0o )
 if ( Oo0o0000o0o0 == None ) :
  O0oOoOOOoOO = "DDT entry not found for non-authoritative EID"
  oooooOoo0ooo += "{} {}" . format ( lisp . lisp_print_sans ( O0oOoOOOoOO ) ,
 lisp . lisp_print_cour ( eid_str ) )
  return ( oooooOoo0ooo + "<br>" )
  if 38 - 38: I1Ii111
  if 7 - 7: O0 . iII111i % I1ii11iIi11i - I1IiiI - iIii1I11I1II1
 if ( Oo0o0000o0o0 . is_auth_prefix ( ) ) :
  if ( iI1iII1 . is_null ( ) ) :
   I111IIIiIii = lisp . lisp_ddt_compute_neg_prefix ( oo0oOo , Oo0o0000o0o0 ,
 lisp . lisp_ddt_cache )
   I111IIIiIii = lisp . lisp_print_cour ( I111IIIiIii . print_prefix ( ) ) ,
  else :
   oO0000OOo00 = lisp . lisp_ddt_compute_neg_prefix ( iI1iII1 , Oo0o0000o0o0 ,
 lisp . lisp_ddt_cache )
   I111IIIiIii = lisp . lisp_ddt_compute_neg_prefix ( oo0oOo , Oo0o0000o0o0 ,
 Oo0o0000o0o0 . source_cache )
   I111IIIiIii = lisp . lisp_print_cour ( "(" + I111IIIiIii . print_prefix ( ) + ", " )
   if 27 - 27: I1IiiI % I1IiiI
   oO0000OOo00 = lisp . lisp_print_cour ( oO0000OOo00 . print_prefix ( ) + ")" )
   if 1 - 1: OoO0O00 - oO0o . I11i . OoO0O00 / Oo0Ooo + I11i
   I111IIIiIii += oO0000OOo00
   if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
   if 49 - 49: Ii1I / OoO0O00 . II111iiii
  oooooOoo0ooo += "{} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "DDT authoritative-prefix entry" ) ,
  # OOooOOo + Oo0Ooo . i11iIiiIii - i1IIi / iIii1I11I1II1
 lisp . lisp_print_cour ( Oo0o0000o0o0 . print_eid_tuple ( ) ) ,
 lisp . lisp_print_sans ( "found for EID" ) ,
 lisp . lisp_print_cour ( eid_str ) ,
 lisp . lisp_print_sans ( "<br><br>Computed negative-prefix" ) ,
 I111IIIiIii )
 else :
  oooooOoo0ooo += "{} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "DDT entry" ) ,
  # i11iIiiIii / I11i
 lisp . lisp_print_cour ( Oo0o0000o0o0 . print_eid_tuple ( ) ) ,
 lisp . lisp_print_sans ( "found for EID" ) ,
 lisp . lisp_print_cour ( eid_str ) ,
 lisp . lisp_print_sans ( ", delegation-type" ) ,
 lisp . lisp_print_cour ( Oo0o0000o0o0 . print_referral_type ( ) ) )
  if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
 return ( oooooOoo0ooo + "<br>" )
 if 87 - 87: i11iIiiIii
 if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
 if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
def IIIII11I1IiI ( ddt_entry , output ) :
 i1I = ddt_entry . print_eid_tuple ( )
 OoOO = ddt_entry . map_referrals_sent
 if 53 - 53: Oo0Ooo
 if ( ddt_entry . is_auth_prefix ( ) ) :
  output += lispconfig . lisp_table_row ( i1I , "--" , "auth-prefix" , "--" ,
 OoOO )
  return ( [ True , output ] )
  if 29 - 29: I1ii11iIi11i + oO0o % O0
  if 10 - 10: I11i / I1Ii111 - I1IiiI * iIii1I11I1II1 - I1IiiI
 for OOoo0O0 in ddt_entry . delegation_set :
  OO0oO0 = OOoo0O0 . delegate_address
  O00OOOOOoo0 = str ( OOoo0O0 . priority ) + "/" + str ( OOoo0O0 . weight )
  output += lispconfig . lisp_table_row ( i1I ,
 OO0oO0 . print_address_no_iid ( ) , OOoo0O0 . print_node_type ( ) , O00OOOOOoo0 , OoOO )
  if ( i1I != "" ) :
   i1I = ""
   OoOO = ""
   if 49 - 49: O0 . iII111i
   if 11 - 11: IiII * I1IiiI . iIii1I11I1II1 % OoooooooOO + iII111i
 return ( [ True , output ] )
 if 78 - 78: OoO0O00 . OOooOOo + OoO0O00 / I11i / OoO0O00
 if 54 - 54: OoOoOO00 % iII111i
 if 37 - 37: OoOoOO00 * Oo0Ooo / ooOoO0o - iII111i % II111iiii . oO0o
 if 88 - 88: iII111i . II111iiii * II111iiii % I1Ii111
 if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
def oooO0 ( ddt_entry , output ) :
 if 46 - 46: I1Ii111
 if 60 - 60: o0oOOo0O0Ooo
 if 25 - 25: OoO0O00
 if 62 - 62: OOooOOo + O0
 if ( ddt_entry . group . is_null ( ) ) :
  return ( IIIII11I1IiI ( ddt_entry , output ) )
  if 98 - 98: o0oOOo0O0Ooo
  if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
 if ( ddt_entry . source_cache == None ) : return ( [ True , output ] )
 if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
 if 82 - 82: Ii1I
 if 46 - 46: OoooooooOO . i11iIiiIii
 if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 if 87 - 87: Oo0Ooo . IiII
 output = ddt_entry . source_cache . walk_cache ( IIIII11I1IiI ,
 output )
 return ( [ True , output ] )
 if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
 if 55 - 55: OOooOOo . I1IiiI
 if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
 if 100 - 100: I1Ii111 * O0
 if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
 if 79 - 79: O0
 if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
def IIIIii1I ( parameter ) :
 if 39 - 39: II111iiii / ooOoO0o + I1Ii111 / OoOoOO00
 if 13 - 13: IiII + O0 + iII111i % I1IiiI / o0oOOo0O0Ooo . IiII
 if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
 if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 if ( parameter != "" ) :
  return ( O0ooo0O0oo0 ( parameter ) )
  if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
  if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
  if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
  if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
  if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 O0oOoOOOoOO = "Enter EID for DDT-Cache lookup:"
 oO00oooOOoOo0 = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
 oooooOoo0ooo = '''
        <form action="/lisp/show/delegations/lookup" method="post">
        <i><font face="Courier New" size="3">
        {} {}
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></i></form>
    ''' . format ( lisp . lisp_print_sans ( O0oOoOOOoOO ) , oO00oooOOoOo0 )
 if 62 - 62: OoooooooOO * I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if 97 - 97: O0 + OoOoOO00
 OO0O000 = "{} entries in delegation-cache" . format ( lisp . lisp_ddt_cache . cache_size ( ) )
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 o0o0O0O00oOOo = lisp . lisp_span ( "LISP-DDT Configured Delegations:" , OO0O000 )
 if 14 - 14: OoOoOO00 + oO0o
 oooooOoo0ooo += lispconfig . lisp_table_header ( o0o0O0O00oOOo , "EID-Prefix or (S,G)" ,
 "Delegation Address" , "Delegation Type" , "Priority/Weight" ,
 "Map-Referrals Sent" )
 if 52 - 52: OoooooooOO - ooOoO0o
 oooooOoo0ooo = lisp . lisp_ddt_cache . walk_cache ( oooO0 , oooooOoo0ooo )
 oooooOoo0ooo += lispconfig . lisp_table_footer ( )
 return ( oooooOoo0ooo )
 if 74 - 74: iII111i + o0oOOo0O0Ooo
 if 71 - 71: Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
 if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
def OooOo0ooo ( ) :
 global i1I1ii1II1iII
 global oooO0oo0oOOOO
 if 71 - 71: I1Ii111 + Ii1I
 lisp . lisp_i_am ( "ddt" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "DDT-Node starting up" )
 if 28 - 28: OOooOOo
 if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
 if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
 if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
 oooO0oo0oOOOO = lisp . lisp_open_listen_socket ( "" , "lisp-ddt" )
 i1I1ii1II1iII [ 0 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV4 )
 i1I1ii1II1iII [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 i1I1ii1II1iII [ 2 ] = oooO0oo0oOOOO
 return
 if 76 - 76: IiII * iII111i
 if 52 - 52: OOooOOo
 if 19 - 19: I1IiiI
 if 25 - 25: Ii1I / ooOoO0o
 if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 if 71 - 71: I1Ii111 . II111iiii
 if 62 - 62: OoooooooOO . I11i
def oOOOoo00 ( ) :
 if 9 - 9: O0 % O0 - o0oOOo0O0Ooo
 if 51 - 51: I1IiiI . iIii1I11I1II1 - I1ii11iIi11i / O0
 if 52 - 52: o0oOOo0O0Ooo + O0 + iII111i + Oo0Ooo % iII111i
 if 75 - 75: I1IiiI . ooOoO0o . O0 * I1Ii111
 lisp . lisp_close_socket ( i1I1ii1II1iII [ 0 ] , "" )
 lisp . lisp_close_socket ( i1I1ii1II1iII [ 1 ] , "" )
 lisp . lisp_close_socket ( oooO0oo0oOOOO , "lisp-ddt" )
 return
 if 4 - 4: Ii1I % oO0o * OoO0O00
 if 100 - 100: I1Ii111 * OOooOOo + OOooOOo
 if 54 - 54: OoooooooOO + o0oOOo0O0Ooo - i1IIi % i11iIiiIii
 if 3 - 3: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 83 - 83: II111iiii + I1Ii111
oO00ooooO0o = {
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

 "show delegations" : [ IIIIii1I , { } ] ,
 }
if 75 - 75: i1IIi / O0 * o0oOOo0O0Ooo
if 29 - 29: I1IiiI % OOooOOo - I1IiiI / OOooOOo . i1IIi
if 31 - 31: I1Ii111
if 88 - 88: OoO0O00 - ooOoO0o + OOooOOo * I1IiiI % iIii1I11I1II1 + Oo0Ooo
if 76 - 76: I1IiiI * iII111i % I1Ii111
if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
if ( OooOo0ooo ( ) ) :
 lisp . lprint ( "lisp_ddt_startup() failed" )
 lisp . lisp_print_banner ( "DDT-Node abnormal exit" )
 exit ( 1 )
 if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
 if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
while ( True ) :
 oOoOOo0O , OOOooo , OooO0OO , o0OOo0o0O0O = lisp . lisp_receive ( oooO0oo0oOOOO , True )
 if 65 - 65: i11iIiiIii
 if ( OOOooo == "" ) : break
 if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
 if ( oOoOOo0O == "command" ) :
  lispconfig . lisp_process_command ( oooO0oo0oOOOO , oOoOOo0O ,
 o0OOo0o0O0O , "lisp-ddt" , [ oO00ooooO0o ] )
 else :
  lisp . lisp_parse_packet ( i1I1ii1II1iII , o0OOo0o0O0O , OOOooo , OooO0OO )
  if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
  if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
  if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
oOOOoo00 ( )
lisp . lisp_print_banner ( "DDT-Node normal exit" )
exit ( 0 )
if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
if 79 - 79: O0 * i11iIiiIii - IiII / IiII
if 48 - 48: O0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
