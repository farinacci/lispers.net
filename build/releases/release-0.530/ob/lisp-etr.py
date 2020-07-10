#-----------------------------------------------------------------------------
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
# lisp-etr.py
#
# This file performs LISP Egress Tunnel Router (ETR) functionality.
# 
# -----------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
import lisp
import lispconfig
import socket
import select
import threading
import time
import pcappy
import struct
import commands
import os
try :
 import pytun
except :
 pytun = None
 if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
 if 73 - 73: II111iiii
 if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
 if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
 if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
 if 46 - 46: ooOoO0o * I11i - OoooooooOO
 if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
Oo0o = None
OOO0o0o = None
Ii1iI = None
Oo = None
I1Ii11I1Ii1i = lisp . lisp_get_ephemeral_port ( )
Ooo = None
o0oOoO00o = [ None , None , None ]
i1 = None
oOOoo00O0O = None
i1111 = None
if 22 - 22: Ii1I . IiII
I11 = 60
if 98 - 98: i11iIiiIii * I1IiiI % iII111i * iII111i * II111iiii
if 79 - 79: IiII
if 86 - 86: OoOoOO00 % I1IiiI
if 80 - 80: OoooooooOO . I1IiiI
if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
if 58 - 58: i11iIiiIii % I1Ii111
O0OoOoo00o = ( os . getenv ( "LISP_ETR_TEST_MODE" ) != None )
iiiI11 = False
if 91 - 91: o0oOOo0O0Ooo / II111iiii . I1ii11iIi11i + OOooOOo
if 47 - 47: OoOoOO00 / Ii1I * OoooooooOO
if 9 - 9: I1IiiI - Ii1I % i1IIi % OoooooooOO
if 3 - 3: iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
if 78 - 78: OoO0O00
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
def i1iIIIiI1I ( kv_pair ) :
 global Oo0o , OOO0o0o
 global o0oOoO00o , iiiI11
 global lisp_seen_eid_done_count
 if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
 if 23 - 23: i11iIiiIii + I1IiiI
 if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
 if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
 if 33 - 33: Ii1I + II111iiii % i11iIiiIii . ooOoO0o - I1IiiI
 if 66 - 66: Ii1I - OoooooooOO * OoooooooOO . OOooOOo . I1ii11iIi11i
 if ( iiiI11 ) : return
 if 22 - 22: OoooooooOO % I11i - iII111i . iIii1I11I1II1 * i11iIiiIii
 lispconfig . lisp_database_mapping_command ( kv_pair , I1Ii11I1Ii1i ,
 ( O0OoOoo00o == False ) )
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 if 61 - 61: ooOoO0o
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if ( lisp . lisp_nat_traversal ) : return
 if ( OOO0o0o != None ) : return
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
 if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo
 if 77 - 77: OoOoOO00 / I11i
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
 if ( O0OoOoo00o ) :
  I1i1I1II = len ( lisp . lisp_db_list )
  if ( I1i1I1II % 1000 == 0 ) :
   lisp . fprint ( "{} database-mappings processed" . format ( I1i1I1II ) )
   if 45 - 45: I1Ii111 . OoOoOO00
   if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
  I1I = lisp . lisp_db_list [ - 1 ]
  if ( I1I . eid . is_dist_name ( ) == False ) : return
  if ( I1I . eid . address != "eid-done" ) : return
  iiiI11 = True
  if 80 - 80: OoOoOO00 - OoO0O00
  lisp . fprint ( "Finished batch of {} database-mappings" . format ( I1i1I1II ) )
  if 87 - 87: oO0o / I11i - i1IIi * OOooOOo / OoooooooOO . O0
  iii11I111 = threading . Timer ( 0 , OOOO00ooo0Ooo ,
 [ o0oOoO00o ] )
  Oo0o = iii11I111
  Oo0o . start ( )
  return
  if 69 - 69: o0oOOo0O0Ooo * O0 + OoO0O00 . II111iiii / O0
  if 97 - 97: ooOoO0o - OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - OoooooooOO
 if ( len ( lisp . lisp_map_servers_list ) > 0 ) :
  OOO0o0o = threading . Timer ( 5 ,
 OOOO00ooo0Ooo , [ o0oOoO00o ] )
  OOO0o0o . start ( )
  if 59 - 59: O0 + I1IiiI + IiII % I1IiiI
  if 70 - 70: iII111i * I1ii11iIi11i
  if 46 - 46: ooOoO0o / OoO0O00
  if 52 - 52: o0oOOo0O0Ooo - OoooooooOO + Ii1I + Ii1I - o0oOOo0O0Ooo / I1Ii111
  if 44 - 44: ooOoO0o . i1IIi - I1ii11iIi11i . O0 - ooOoO0o
  if 92 - 92: iII111i . I11i + o0oOOo0O0Ooo
  if 28 - 28: i1IIi * Oo0Ooo - o0oOOo0O0Ooo * IiII * Ii1I / OoO0O00
  if 94 - 94: II111iiii % I1ii11iIi11i / OoOoOO00 * iIii1I11I1II1
def oOOoo0Oo ( clause ) :
 if 78 - 78: I11i
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
 if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
 if 16 - 16: I1IiiI * oO0o % IiII
 Oo000o = lispconfig . lisp_show_myrlocs ( "" )
 if 7 - 7: ooOoO0o * OoO0O00 % oO0o . IiII
 if 45 - 45: i11iIiiIii * II111iiii % iIii1I11I1II1 + I1ii11iIi11i - Ii1I
 if 17 - 17: IiII
 if 62 - 62: iIii1I11I1II1 * OoOoOO00
 Oo000o = lispconfig . lisp_show_decap_stats ( Oo000o , "ETR" )
 if 26 - 26: iII111i . I1Ii111
 if 68 - 68: OoO0O00
 if 35 - 35: OoO0O00 - iII111i / Oo0Ooo / OoOoOO00
 if 24 - 24: ooOoO0o - ooOoO0o / II111iiii - I1ii11iIi11i
 OO = lisp . lisp_decent_dns_suffix
 if ( OO == None ) :
  OO = ":"
 else :
  OO = "&nbsp;(dns-suffix '{}'):" . format ( OO )
  if 50 - 50: Ii1I / Oo0Ooo - oO0o - I11i % iII111i - oO0o
  if 91 - 91: OoO0O00 / I11i - II111iiii . I11i
 i1I11i1I = "{} configured map-servers" . format ( len ( lisp . lisp_map_servers_list ) )
 Oo0o00 = "LISP-ETR Configured Map-Servers{}" . format ( OO )
 Oo0o00 = lisp . lisp_span ( Oo0o00 , i1I11i1I )
 if 73 - 73: iII111i * Ii1I + o0oOOo0O0Ooo . OOooOOo + I1ii11iIi11i % iII111i
 i1I11i1I = ( "P = proxy-reply requested, M = merge-registrations " + "requested, N = Map-Notify requested" )
 if 95 - 95: i1IIi
 I1ii11iI = lisp . lisp_span ( "Registration<br>flags" , i1I11i1I )
 if 14 - 14: OoOoOO00 / IiII . OoOoOO00 . I11i % OoO0O00 * I11i
 Oo000o += lispconfig . lisp_table_header ( Oo0o00 , "Address" , "Auth-Type" ,
 "xTR-ID" , "Site-ID" , I1ii11iI , "Map-Registers<br>Sent" ,
 "Map-Notifies<br>Received" )
 if 16 - 16: OoOoOO00 . ooOoO0o + i11iIiiIii
 for i1i1I1IIii1II in lisp . lisp_map_servers_list . values ( ) :
  i1i1I1IIii1II . resolve_dns_name ( )
  O0ii1ii1ii = "" if i1i1I1IIii1II . ms_name == "all" else i1i1I1IIii1II . ms_name + "<br>"
  oooooOoo0ooo = O0ii1ii1ii + i1i1I1IIii1II . map_server . print_address_no_iid ( )
  if ( i1i1I1IIii1II . dns_name ) : oooooOoo0ooo += "<br>" + i1i1I1IIii1II . dns_name
  if 6 - 6: I11i - Ii1I + iIii1I11I1II1 - I1Ii111 - i11iIiiIii
  OO0oOO0O = "0x" + lisp . lisp_hex_string ( i1i1I1IIii1II . xtr_id )
  oO = "{}-{}-{}-{}" . format ( "P" if i1i1I1IIii1II . proxy_reply else "p" ,
 "M" if i1i1I1IIii1II . merge_registrations else "m" ,
 "N" if i1i1I1IIii1II . want_map_notify else "n" ,
 "R" if i1i1I1IIii1II . refresh_registrations else "r" )
  if 7 - 7: o0oOOo0O0Ooo - I1IiiI
  OOo00O0 = i1i1I1IIii1II . map_registers_sent + i1i1I1IIii1II . map_registers_multicast_sent
  if 73 - 73: i1IIi + I1IiiI
  if 46 - 46: OoO0O00 . Oo0Ooo - OoooooooOO
  Oo000o += lispconfig . lisp_table_row ( oooooOoo0ooo ,
 "sha1" if ( i1i1I1IIii1II . alg_id == lisp . LISP_SHA_1_96_ALG_ID ) else "sha2" ,
 OO0oOO0O , i1i1I1IIii1II . site_id , oO , OOo00O0 ,
 i1i1I1IIii1II . map_notifies_received )
  if 93 - 93: iII111i
 Oo000o += lispconfig . lisp_table_footer ( )
 if 10 - 10: I11i
 if 82 - 82: I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
 if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 Oo000o = lispconfig . lisp_show_db_list ( "ETR" , Oo000o )
 if 83 - 83: I11i / I1IiiI
 if 34 - 34: IiII
 if 57 - 57: oO0o . I11i . i1IIi
 if 42 - 42: I11i + I1ii11iIi11i % O0
 if ( len ( lisp . lisp_elp_list ) != 0 ) :
  Oo000o = lispconfig . lisp_show_elp_list ( Oo000o )
  if 6 - 6: oO0o
  if 68 - 68: OoOoOO00 - OoO0O00
  if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
  if 1 - 1: iIii1I11I1II1 / II111iiii
  if 33 - 33: I11i
 if ( len ( lisp . lisp_rle_list ) != 0 ) :
  Oo000o = lispconfig . lisp_show_rle_list ( Oo000o )
  if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
  if 87 - 87: i11iIiiIii
  if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
  if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
  if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
 if ( len ( lisp . lisp_json_list ) != 0 ) :
  Oo000o = lispconfig . lisp_show_json_list ( Oo000o )
  if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
  if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
  if 51 - 51: O0 + iII111i
  if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
  if 48 - 48: O0
 if ( len ( lisp . lisp_group_mapping_list ) != 0 ) :
  Oo0o00 = "Configured Group Mappings:"
  Oo000o += lispconfig . lisp_table_header ( Oo0o00 , "Name" , "Group Prefix" ,
 "Sources" , "Use MS" )
  for I1IiiIIIi in lisp . lisp_group_mapping_list . values ( ) :
   i1Iii1i1I = ""
   for OOoO00 in I1IiiIIIi . sources : i1Iii1i1I += OOoO00 + ", "
   if ( i1Iii1i1I == "" ) :
    i1Iii1i1I = "*"
   else :
    i1Iii1i1I = i1Iii1i1I [ 0 : - 2 ]
    if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
   Oo000o += lispconfig . lisp_table_row ( I1IiiIIIi . group_name ,
 I1IiiIIIi . group_prefix . print_prefix ( ) , i1Iii1i1I , I1IiiIIIi . use_ms_name )
   if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
  Oo000o += lispconfig . lisp_table_footer ( )
  if 23 - 23: O0
 return ( Oo000o )
 if 85 - 85: Ii1I
 if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
 if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
 if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
 if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
 if 77 - 77: iIii1I11I1II1 * OoO0O00
 if 95 - 95: I1IiiI + i11iIiiIii
def I1Ii ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "ETR" ) )
 if 94 - 94: Ii1I - II111iiii . OOooOOo % I11i . i11iIiiIii + O0
 if 26 - 26: I11i - iIii1I11I1II1 - I1IiiI / OoO0O00 . OoOoOO00 % iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo . iIii1I11I1II1 / oO0o + i1IIi
 if 42 - 42: ooOoO0o . o0oOOo0O0Ooo . ooOoO0o - I1ii11iIi11i
 if 40 - 40: ooOoO0o - i11iIiiIii / Ii1I
 if 35 - 35: Ii1I - I1IiiI % o0oOOo0O0Ooo . OoooooooOO % Ii1I
 if 47 - 47: iII111i - Ii1I . II111iiii + OoooooooOO . i11iIiiIii
def OOo0oO00ooO00 ( kv_pairs ) :
 global OOO0o0o
 global Ii1iI
 if 90 - 90: OoOoOO00 * I1Ii111 + o0oOOo0O0Ooo
 OOOoOoO = [ ]
 Ii1I1i = [ ]
 OOI1iI1ii1II = 0
 O0O0OOOOoo = 0
 oOooO0 = ""
 Ii1I1Ii = False
 OOoO0 = False
 OO0Oooo0oOO0O = False
 o00O0 = False
 oOO0O00Oo0O0o = 0
 O0ii1ii1ii = None
 ii1 = 0
 I1iIIiiIIi1i = None
 if 66 - 66: iII111i - iII111i - i11iIiiIii . I1ii11iIi11i - OOooOOo
 for oOOo0O00o in kv_pairs . keys ( ) :
  iIiIi11 = kv_pairs [ oOOo0O00o ]
  if ( oOOo0O00o == "ms-name" ) :
   O0ii1ii1ii = iIiIi11 [ 0 ]
   if 87 - 87: Oo0Ooo . I1IiiI - II111iiii + O0 / Oo0Ooo / oO0o
  if ( oOOo0O00o == "address" ) :
   for IiI in range ( len ( iIiIi11 ) ) :
    OOOoOoO . append ( iIiIi11 [ IiI ] )
    if 32 - 32: o0oOOo0O0Ooo + I1IiiI + I1Ii111 . ooOoO0o - i1IIi
    if 36 - 36: OoOoOO00
  if ( oOOo0O00o == "dns-name" ) :
   for IiI in range ( len ( iIiIi11 ) ) :
    Ii1I1i . append ( iIiIi11 [ IiI ] )
    if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
    if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
  if ( oOOo0O00o == "authentication-type" ) :
   O0O0OOOOoo = lisp . LISP_SHA_1_96_ALG_ID if ( iIiIi11 == "sha1" ) else lisp . LISP_SHA_256_128_ALG_ID if ( iIiIi11 == "sha2" ) else ""
   if 77 - 77: OOooOOo * iIii1I11I1II1
   if 98 - 98: I1IiiI % Ii1I * OoooooooOO
  if ( oOOo0O00o == "authentication-key" ) :
   if ( O0O0OOOOoo == 0 ) : O0O0OOOOoo = lisp . LISP_SHA_256_128_ALG_ID
   OoiIIiIi1 = lisp . lisp_parse_auth_key ( iIiIi11 )
   OOI1iI1ii1II = OoiIIiIi1 . keys ( ) [ 0 ]
   oOooO0 = OoiIIiIi1 [ OOI1iI1ii1II ]
   if 74 - 74: iII111i + o0oOOo0O0Ooo
  if ( oOOo0O00o == "proxy-reply" ) :
   Ii1I1Ii = True if iIiIi11 == "yes" else False
   if 71 - 71: Oo0Ooo % OOooOOo
  if ( oOOo0O00o == "merge-registrations" ) :
   OOoO0 = True if iIiIi11 == "yes" else False
   if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
  if ( oOOo0O00o == "refresh-registrations" ) :
   OO0Oooo0oOO0O = True if iIiIi11 == "yes" else False
   if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
  if ( oOOo0O00o == "want-map-notify" ) :
   o00O0 = True if iIiIi11 == "yes" else False
   if 69 - 69: I1Ii111
  if ( oOOo0O00o == "site-id" ) :
   oOO0O00Oo0O0o = int ( iIiIi11 )
   if 11 - 11: I1IiiI
  if ( oOOo0O00o == "encryption-key" ) :
   I1iIIiiIIi1i = lisp . lisp_parse_auth_key ( iIiIi11 )
   ii1 = I1iIIiiIIi1i . keys ( ) [ 0 ]
   I1iIIiiIIi1i = I1iIIiiIIi1i [ ii1 ]
   if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
   if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
   if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
   if 71 - 71: I1Ii111 + Ii1I
   if 28 - 28: OOooOOo
   if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
 i1i1I1IIii1II = None
 for oooooOoo0ooo in OOOoOoO :
  if ( oooooOoo0ooo == "" ) : continue
  i1i1I1IIii1II = lisp . lisp_ms ( oooooOoo0ooo , None , O0ii1ii1ii , O0O0OOOOoo , OOI1iI1ii1II , oOooO0 ,
 Ii1I1Ii , OOoO0 , OO0Oooo0oOO0O , o00O0 , oOO0O00Oo0O0o , ii1 , I1iIIiiIIi1i )
  if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
 for II in Ii1I1i :
  if ( II == "" ) : continue
  i1i1I1IIii1II = lisp . lisp_ms ( None , II , O0ii1ii1ii , O0O0OOOOoo , OOI1iI1ii1II , oOooO0 ,
 Ii1I1Ii , OOoO0 , OO0Oooo0oOO0O , o00O0 , oOO0O00Oo0O0o , ii1 , I1iIIiiIIi1i )
  if 93 - 93: IiII * OoooooooOO + ooOoO0o
  if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
  if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
  if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
  if 26 - 26: Ii1I % I1ii11iIi11i
  if 76 - 76: IiII * iII111i
 ooooooo00o = ( len ( lisp . lisp_map_servers_list ) == 1 )
 if ( ooooooo00o ) :
  i1i1I1IIii1II = lisp . lisp_map_servers_list . values ( ) [ 0 ]
  Ii1iI = threading . Timer ( 2 , o0oooOO00 ,
 [ i1i1I1IIii1II . map_server ] )
  Ii1iI . start ( )
 else :
  if 32 - 32: I1Ii111
  if 30 - 30: iIii1I11I1II1 / I11i . OoO0O00 - o0oOOo0O0Ooo
  if 48 - 48: i1IIi - Ii1I / O0 * OoO0O00
  if 71 - 71: I1ii11iIi11i
  if 7 - 7: I1ii11iIi11i - I1IiiI . iIii1I11I1II1 - i1IIi
  if 59 - 59: o0oOOo0O0Ooo
  if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
  if 73 - 73: I11i % i11iIiiIii - I1IiiI
  if ( lisp . lisp_nat_traversal ) : return
  if ( i1i1I1IIii1II and len ( lisp . lisp_db_list ) > 0 ) :
   Ii1iI111II1I1 ( o0oOoO00o , None , None , i1i1I1IIii1II , False )
   if 91 - 91: OOooOOo % OOooOOo - I1IiiI
   if 18 - 18: I11i - i11iIiiIii / II111iiii . OOooOOo
   if 55 - 55: i1IIi % II111iiii + I11i * iIii1I11I1II1
   if 81 - 81: IiII % i1IIi . iIii1I11I1II1
   if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
   if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
   if 31 - 31: OOooOOo
 if ( O0OoOoo00o and iiiI11 ) : return
 if 23 - 23: I1Ii111 . IiII
 if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
 if 42 - 42: Oo0Ooo
 if 76 - 76: I1IiiI * iII111i % I1Ii111
 if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
 if ( len ( lisp . lisp_db_list ) > 0 ) :
  if ( OOO0o0o != None ) : return
  OOO0o0o = threading . Timer ( 5 ,
 OOOO00ooo0Ooo , [ o0oOoO00o ] )
  OOO0o0o . start ( )
  if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
 return
 if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
 if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
 if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
 if 42 - 42: I1IiiI
 if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
 if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
 if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
def ooOoOo0 ( kv_pairs ) :
 i1Iii1i1I = [ ]
 I11iiiiI1i = None
 iI1i11 = None
 O0ii1ii1ii = "all"
 if 66 - 66: O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / Ii1I + I1ii11iIi11i
 for oOOo0O00o in kv_pairs . keys ( ) :
  iIiIi11 = kv_pairs [ oOOo0O00o ]
  if ( oOOo0O00o == "group-name" ) :
   ooo00Ooo = iIiIi11
   if 93 - 93: i11iIiiIii - I1IiiI * I1ii11iIi11i * I11i % O0 + OoooooooOO
  if ( oOOo0O00o == "group-prefix" ) :
   if ( I11iiiiI1i == None ) :
    I11iiiiI1i = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
   I11iiiiI1i . store_prefix ( iIiIi11 )
   if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
  if ( oOOo0O00o == "instance-id" ) :
   if ( I11iiiiI1i == None ) :
    I11iiiiI1i = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
   I11iiiiI1i . instance_id = int ( iIiIi11 )
   if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
  if ( oOOo0O00o == "ms-name" ) :
   O0ii1ii1ii = iIiIi11 [ 0 ]
   if 19 - 19: OoO0O00 - Oo0Ooo . O0
  if ( oOOo0O00o == "address" ) :
   for ooOo00 in iIiIi11 :
    if ( ooOo00 != "" ) : i1Iii1i1I . append ( ooOo00 )
    if 98 - 98: Oo0Ooo / I1IiiI . O0 + OoO0O00
    if 43 - 43: II111iiii . oO0o / I1ii11iIi11i
  if ( oOOo0O00o == "rle-address" ) :
   if ( iI1i11 == None ) :
    iI1i11 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 20 - 20: I1IiiI
   iI1i11 . store_address ( iIiIi11 )
   if 95 - 95: iII111i - I1IiiI
   if 34 - 34: ooOoO0o * I1IiiI . i1IIi * ooOoO0o / ooOoO0o
 I1IiiIIIi = lisp . lisp_group_mapping ( ooo00Ooo , O0ii1ii1ii , I11iiiiI1i , i1Iii1i1I ,
 iI1i11 )
 I1IiiIIIi . add_group ( )
 return
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 if 41 - 41: i1IIi - I11i - Ii1I
 if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
 if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
 if 44 - 44: II111iiii
 if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
def iI1 ( quiet , db , eid , group , ttl ) :
 if 12 - 12: I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI / iII111i
 if 12 - 12: OOooOOo - ooOoO0o . OoooooooOO / I1ii11iIi11i . i1IIi * OoO0O00
 if 19 - 19: i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
 if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
 if 71 - 71: O0 - iIii1I11I1II1
 if 12 - 12: OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 II1IIiiIiI = { }
 for i1II1I1Iii1 in db . rloc_set :
  if ( i1II1I1Iii1 . translated_rloc . is_null ( ) ) : continue
  if 30 - 30: OoooooooOO - OoOoOO00
  for Ooo00O0o in lisp . lisp_rtr_list :
   Oo00o0OO0O00o = lisp . lisp_rtr_list [ Ooo00O0o ]
   if ( lisp . lisp_register_all_rtrs == False and Oo00o0OO0O00o == None ) :
    lisp . lprint ( "  Exclude unreachable RTR {}" . format ( lisp . red ( Ooo00O0o , False ) ) )
    if 82 - 82: I11i + OoooooooOO - i1IIi . i1IIi
    continue
    if 6 - 6: o0oOOo0O0Ooo / I11i / II111iiii
   if ( Oo00o0OO0O00o == None ) : continue
   II1IIiiIiI [ Ooo00O0o ] = Oo00o0OO0O00o
   if 27 - 27: OOooOOo * ooOoO0o . I1Ii111 % IiII * IiII . i1IIi
  break
  if 72 - 72: OOooOOo % I1ii11iIi11i + OoO0O00 / oO0o + IiII
  if 10 - 10: I1Ii111 / ooOoO0o + i11iIiiIii / Ii1I
 OOOoOoOiIIIII1ii1I = 0
 Ii1i1iI = ""
 for IIiI1 in [ eid . instance_id ] + eid . iid_list :
  i1iI1 = lisp . lisp_eid_record ( )
  if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
  i1iI1 . rloc_count = len ( db . rloc_set ) + len ( II1IIiiIiI )
  i1iI1 . authoritative = True
  i1iI1 . record_ttl = ttl
  i1iI1 . eid . copy_address ( eid )
  i1iI1 . eid . instance_id = IIiI1
  i1iI1 . eid . iid_list = [ ]
  i1iI1 . group . copy_address ( group )
  if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
  Ii1i1iI += i1iI1 . encode ( )
  if ( not quiet ) :
   IIi = lisp . lisp_print_eid_tuple ( eid , group )
   oOoO00oo0O = ""
   if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
    oOoO00oo0O = lisp . lisp_get_decent_index ( eid )
    oOoO00oo0O = lisp . bold ( str ( oOoO00oo0O ) , False )
    oOoO00oo0O = ", decent-index {}" . format ( oOoO00oo0O )
    if 39 - 39: iIii1I11I1II1 / O0 / oO0o - Ii1I - iII111i % OOooOOo
   lisp . lprint ( "  EID-prefix {} for ms-name '{}'{}" . format ( lisp . green ( IIi , False ) , db . use_ms_name , oOoO00oo0O ) )
   if 31 - 31: I11i - O0 / ooOoO0o * OoOoOO00
   i1iI1 . print_record ( "  " , False )
   if 12 - 12: o0oOOo0O0Ooo - ooOoO0o * I1Ii111
   if 14 - 14: Oo0Ooo - Ii1I % Ii1I * O0 . i11iIiiIii / O0
  for i1II1I1Iii1 in db . rloc_set :
   OOO0oOOoo = lisp . lisp_rloc_record ( )
   OOO0oOOoo . store_rloc_entry ( i1II1I1Iii1 )
   OOO0oOOoo . local_bit = i1II1I1Iii1 . rloc . is_local ( )
   OOO0oOOoo . reach_bit = True
   Ii1i1iI += OOO0oOOoo . encode ( )
   if ( not quiet ) : OOO0oOOoo . print_record ( "    " )
   if 52 - 52: o0oOOo0O0Ooo % Oo0Ooo
   if 64 - 64: O0 % I11i % O0 * OoO0O00 . oO0o + I1IiiI
   if 75 - 75: I11i . OoooooooOO % o0oOOo0O0Ooo * I11i % OoooooooOO
   if 13 - 13: IiII / i11iIiiIii % II111iiii % I11i . I1ii11iIi11i
   if 8 - 8: OoOoOO00 + Oo0Ooo - II111iiii
   if 11 - 11: i1IIi % i11iIiiIii - i1IIi * OoOoOO00
  for Oo00o0OO0O00o in II1IIiiIiI . values ( ) :
   OOO0oOOoo = lisp . lisp_rloc_record ( )
   OOO0oOOoo . rloc . copy_address ( Oo00o0OO0O00o )
   OOO0oOOoo . priority = 254
   OOO0oOOoo . rloc_name = "RTR"
   OOO0oOOoo . weight = 0
   OOO0oOOoo . mpriority = 255
   OOO0oOOoo . mweight = 0
   OOO0oOOoo . local_bit = False
   OOO0oOOoo . reach_bit = True
   Ii1i1iI += OOO0oOOoo . encode ( )
   if ( not quiet ) : OOO0oOOoo . print_record ( "    RTR " )
   if 39 - 39: I1Ii111
   if 86 - 86: I11i * I1IiiI + I11i + II111iiii
   if 8 - 8: I1Ii111 - iII111i / ooOoO0o
   if 96 - 96: OoOoOO00
   if 29 - 29: I1ii11iIi11i / i1IIi . I1IiiI - OoOoOO00 - OoOoOO00 - Ii1I
  OOOoOoOiIIIII1ii1I += 1
  if 20 - 20: i1IIi % OoO0O00 . I1IiiI / IiII * i11iIiiIii * OOooOOo
 return ( Ii1i1iI , OOOoOoOiIIIII1ii1I )
 if 85 - 85: o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . O0 % I1Ii111
 if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
 if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
 if 74 - 74: O0 / i1IIi
 if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
 if 31 - 31: OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
def Ii1iI111II1I1 ( lisp_sockets , ttl , eid_only , ms_only , refresh ) :
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
 if ( eid_only != None ) :
  Oo0ooo = 1
 else :
  Oo0ooo = lisp . lisp_db_list_length ( )
  if ( Oo0ooo == 0 ) : return
  if 28 - 28: oO0o . II111iiii / I1ii11iIi11i + II111iiii . OoooooooOO . IiII
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 if ( O0OoOoo00o ) :
  lisp . fprint ( "Build Map-Register for {} database-mapping entries" . format ( Oo0ooo ) )
  if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
 else :
  lisp . fprint ( "Build Map-Register for {} database-mapping entries" . format ( Oo0ooo ) )
  if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
  if 92 - 92: ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  if 92 - 92: I11i . I1Ii111
 oOO00O0Ooooo00 = lisp . lisp_decent_pull_xtr_configured ( )
 if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
 if 18 - 18: iIii1I11I1II1 % I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
 I1Iiiiiii = ( Oo0ooo > 12 )
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 o0 = { }
 if ( oOO00O0Ooooo00 ) :
  if 30 - 30: O0 * OoooooooOO
  if 38 - 38: IiII - I1ii11iIi11i . OoOoOO00 - I1Ii111 . OoooooooOO
  if 89 - 89: iIii1I11I1II1
  if 21 - 21: I11i % I11i
  if 27 - 27: i11iIiiIii / I1ii11iIi11i
  for I1I in lisp . lisp_db_list :
   oOoOOo = I1I . eid if I1I . group . is_null ( ) else I1I . group
   ii1iI = lisp . lisp_get_decent_dns_name ( oOoOOo )
   o0 [ ii1iI ] = [ ]
   if 49 - 49: o0oOOo0O0Ooo . IiII / OoO0O00 + II111iiii
 else :
  if 47 - 47: O0 / Ii1I
  if 67 - 67: I1IiiI
  if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
  if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
  if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
  for i1i1I1IIii1II in lisp . lisp_map_servers_list . values ( ) :
   if ( ms_only != None and i1i1I1IIii1II != ms_only ) : continue
   o0 [ i1i1I1IIii1II . ms_name ] = [ ]
   if 92 - 92: Oo0Ooo
   if 40 - 40: OoOoOO00 / IiII
   if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
   if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
   if 61 - 61: II111iiii
   if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 oooO0o0o0O0 = lisp . lisp_map_register ( )
 oooO0o0o0O0 . nonce = 0xaabbccdddfdfdf00
 oooO0o0o0O0 . xtr_id_present = True
 oooO0o0o0O0 . use_ttl_for_timeout = True
 if 27 - 27: OoooooooOO - iII111i / I11i
 if ( ttl == None ) : ttl = lisp . LISP_REGISTER_TTL
 if 76 - 76: o0oOOo0O0Ooo % I1IiiI . iIii1I11I1II1 - IiII * OoooooooOO . iII111i
 if 84 - 84: I1Ii111 + I11i
 if 28 - 28: oO0o - i11iIiiIii . I1ii11iIi11i + IiII / I1ii11iIi11i
 if 35 - 35: IiII
 OOoO0OoOo00o0OO = 65000 if ( O0OoOoo00o ) else 1100
 for I1I in lisp . lisp_db_list :
  if ( oOO00O0Ooooo00 ) :
   ii1IIIIiI11 = lisp . lisp_get_decent_dns_name ( I1I . eid )
  else :
   ii1IIIIiI11 = I1I . use_ms_name
   if 40 - 40: o0oOOo0O0Ooo
   if 67 - 67: oO0o + II111iiii - O0 . oO0o * II111iiii * I11i
   if 90 - 90: Ii1I . IiII
   if 81 - 81: OOooOOo - I11i % ooOoO0o - OoO0O00 / Oo0Ooo
   if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
   if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
  if ( o0 . has_key ( ii1IIIIiI11 ) == False ) : continue
  if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
  oO0Ooo0ooOO0 = o0 [ ii1IIIIiI11 ]
  if ( oO0Ooo0ooOO0 == [ ] ) :
   oO0Ooo0ooOO0 = [ "" , 0 ]
   o0 [ ii1IIIIiI11 ] . append ( oO0Ooo0ooOO0 )
  else :
   oO0Ooo0ooOO0 = o0 [ ii1IIIIiI11 ] [ - 1 ]
   if 46 - 46: Ii1I % OoOoOO00
   if 64 - 64: i11iIiiIii - II111iiii
   if 77 - 77: OoOoOO00 % Ii1I
   if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
   if 2 - 2: OoooooooOO % OOooOOo
   if 63 - 63: I1IiiI % iIii1I11I1II1
   if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
   if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
   if 59 - 59: OOooOOo + i11iIiiIii
   if 88 - 88: i11iIiiIii - ooOoO0o
  Ii1i1iI = ""
  if ( I1I . dynamic_eid_configured ( ) ) :
   for O0iIi1IiII in I1I . dynamic_eids . values ( ) :
    oOoOOo = O0iIi1IiII . dynamic_eid
    if ( eid_only == None or eid_only . is_exact_match ( oOoOOo ) ) :
     I1i , OOOoOoOiIIIII1ii1I = iI1 ( I1Iiiiiii , I1I ,
 oOoOOo , I1I . group , ttl )
     Ii1i1iI += I1i
     oO0Ooo0ooOO0 [ 1 ] += OOOoOoOiIIIII1ii1I
     if 72 - 72: iIii1I11I1II1
     if 11 - 11: II111iiii / o0oOOo0O0Ooo
  else :
   if ( eid_only == None ) :
    if ( ttl != 0 ) : ttl = I1I . register_ttl
    Ii1i1iI , OOOoOoOiIIIII1ii1I = iI1 ( I1Iiiiiii , I1I ,
 I1I . eid , I1I . group , ttl )
    oO0Ooo0ooOO0 [ 1 ] += OOOoOoOiIIIII1ii1I
    if 21 - 21: i11iIiiIii / i1IIi + I1IiiI * OOooOOo . I1Ii111
    if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
    if 47 - 47: OoooooooOO
    if 4 - 4: I1IiiI % I11i
    if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
    if 82 - 82: ooOoO0o + II111iiii
  oO0Ooo0ooOO0 [ 0 ] += Ii1i1iI
  if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
  if ( oO0Ooo0ooOO0 [ 1 ] == 20 or len ( oO0Ooo0ooOO0 [ 0 ] ) > OOoO0OoOo00o0OO ) :
   oO0Ooo0ooOO0 = [ "" , 0 ]
   o0 [ ii1IIIIiI11 ] . append ( oO0Ooo0ooOO0 )
   if 68 - 68: Oo0Ooo + i11iIiiIii
   if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
   if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
   if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
   if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
   if 98 - 98: i1IIi
 oO0O = .500 if ( O0OoOoo00o ) else .001
 OOOoOoOiIIIII1ii1I = 0
 for i1i1I1IIii1II in lisp . lisp_map_servers_list . values ( ) :
  if ( ms_only != None and i1i1I1IIii1II != ms_only ) : continue
  if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
  ii1IIIIiI11 = i1i1I1IIii1II . dns_name if oOO00O0Ooooo00 else i1i1I1IIii1II . ms_name
  if ( o0 . has_key ( ii1IIIIiI11 ) == False ) : continue
  if 56 - 56: O0
  for oO0Ooo0ooOO0 in o0 [ ii1IIIIiI11 ] :
   if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
   if 23 - 23: oO0o - OOooOOo + I11i
   if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
   if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
   oooO0o0o0O0 . record_count = oO0Ooo0ooOO0 [ 1 ]
   if ( oooO0o0o0O0 . record_count == 0 ) : continue
   if 11 - 11: iII111i * Ii1I - OoOoOO00
   oooO0o0o0O0 . nonce += 1
   oooO0o0o0O0 . alg_id = i1i1I1IIii1II . alg_id
   oooO0o0o0O0 . key_id = i1i1I1IIii1II . key_id
   oooO0o0o0O0 . proxy_reply_requested = i1i1I1IIii1II . proxy_reply
   oooO0o0o0O0 . merge_register_requested = i1i1I1IIii1II . merge_registrations
   oooO0o0o0O0 . map_notify_requested = i1i1I1IIii1II . want_map_notify
   oooO0o0o0O0 . xtr_id = i1i1I1IIii1II . xtr_id
   oooO0o0o0O0 . site_id = i1i1I1IIii1II . site_id
   oooO0o0o0O0 . encrypt_bit = ( i1i1I1IIii1II . ekey != None )
   if ( i1i1I1IIii1II . refresh_registrations ) :
    oooO0o0o0O0 . map_register_refresh = refresh
    if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
   if ( i1i1I1IIii1II . ekey != None ) : oooO0o0o0O0 . encryption_key_id = i1i1I1IIii1II . ekey_id
   oO0OO0 = oooO0o0o0O0 . encode ( )
   oooO0o0o0O0 . print_map_register ( )
   if 92 - 92: ooOoO0o / OoOoOO00 * OoO0O00 . I11i % II111iiii
   if 71 - 71: I1Ii111 % i1IIi - II111iiii - OOooOOo + OOooOOo * ooOoO0o
   if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
   if 29 - 29: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / iII111i
   if 70 - 70: i11iIiiIii % iII111i
   I11Ii11iI1 = oooO0o0o0O0 . encode_xtr_id ( "" )
   Ii1i1iI = oO0Ooo0ooOO0 [ 0 ]
   oO0OO0 = oO0OO0 + Ii1i1iI + I11Ii11iI1
   if 39 - 39: I1IiiI * i11iIiiIii - oO0o / IiII % I1Ii111 % I11i
   i1i1I1IIii1II . map_registers_sent += 1
   lisp . lisp_send_map_register ( lisp_sockets , oO0OO0 , oooO0o0o0O0 , i1i1I1IIii1II )
   if 65 - 65: oO0o - ooOoO0o % OoooooooOO / OoooooooOO % OoooooooOO
   OOOoOoOiIIIII1ii1I += 1
   if ( OOOoOoOiIIIII1ii1I % 100 == 0 and O0OoOoo00o ) :
    oO0O += .1
    lisp . fprint ( "Sent {} Map-Registers, ipd {}" . format ( OOOoOoOiIIIII1ii1I ,
 oO0O ) )
    if 52 - 52: I1ii11iIi11i + I1ii11iIi11i . II111iiii
   time . sleep ( oO0O )
   if 34 - 34: OoooooooOO . O0 / oO0o * OoOoOO00 - I1ii11iIi11i
   if 36 - 36: i1IIi / O0 / OoO0O00 - O0 - i1IIi
  if ( O0OoOoo00o ) :
   lisp . fprint ( "Sent total {} Map-Registers" . format ( OOOoOoOiIIIII1ii1I ) )
   if 22 - 22: i1IIi + Ii1I
   if 54 - 54: ooOoO0o % OOooOOo . I1Ii111 + oO0o - OOooOOo * I1IiiI
   if 92 - 92: o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % OoO0O00 % IiII . OoooooooOO
   if 52 - 52: ooOoO0o / i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + o0oOOo0O0Ooo
   if 71 - 71: oO0o % I11i * OoOoOO00 . O0 / Ii1I . I1ii11iIi11i
  i1i1I1IIii1II . resolve_dns_name ( )
  if 58 - 58: Oo0Ooo / oO0o
  if 44 - 44: OOooOOo
  if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
  if 79 - 79: Ii1I . OoO0O00
  if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
  if ( ms_only != None and i1i1I1IIii1II == ms_only ) : break
  if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
 return
 if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
 if 52 - 52: i1IIi
 if 84 - 84: Ii1I / IiII
 if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if 37 - 37: i11iIiiIii + i1IIi
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 if 8 - 8: o0oOOo0O0Ooo
def o0oooOO00 ( ms ) :
 global Ii1iI
 global Oo
 if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
 lisp . lisp_set_exception ( )
 if 78 - 78: Ii1I / II111iiii % OoOoOO00
 if 52 - 52: OOooOOo - iII111i * oO0o
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
 if 36 - 36: O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 ii1I11iIiIII1 = [ Oo , Oo , Ooo ]
 lisp . lisp_build_info_requests ( ii1I11iIiIII1 , ms , lisp . LISP_CTRL_PORT )
 if 52 - 52: o0oOOo0O0Ooo * IiII + OoOoOO00
 if 49 - 49: iIii1I11I1II1 - O0 . i1IIi - OoooooooOO
 if 37 - 37: i1IIi . I11i % OoOoOO00 + OoooooooOO / iII111i
 if 3 - 3: I1ii11iIi11i
 if 17 - 17: I1ii11iIi11i . II111iiii . ooOoO0o / I1ii11iIi11i
 oOooO00o0O = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) == None )
 for Oo00o0OO0O00o in lisp . lisp_rtr_list . values ( ) :
  if ( Oo00o0OO0O00o == None ) : continue
  if ( Oo00o0OO0O00o . is_private_address ( ) and oOooO00o0O == False ) :
   OOo0 = lisp . red ( Oo00o0OO0O00o . print_address_no_iid ( ) , False )
   lisp . lprint ( "Skip over RTR private address {}" . format ( OOo0 ) )
   continue
   if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
  lisp . lisp_build_info_requests ( ii1I11iIiIII1 , Oo00o0OO0O00o , lisp . LISP_DATA_PORT )
  if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
  if 51 - 51: OoOoOO00
  if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
  if 53 - 53: Ii1I % Oo0Ooo
  if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
  if 41 - 41: Ii1I % I1ii11iIi11i
 Ii1iI . cancel ( )
 Ii1iI = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 o0oooOO00 , [ None ] )
 Ii1iI . start ( )
 return
 if 12 - 12: OOooOOo
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
def OOOO00ooo0Ooo ( lisp_sockets ) :
 global Oo0o , OOO0o0o
 global Oo
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 lisp . lisp_set_exception ( )
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 Ii1iI111II1I1 ( lisp_sockets , None , None , None , True )
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 if 46 - 46: i11iIiiIii - O0 . oO0o
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if ( lisp . lisp_l2_overlay ) :
  oOO0o000Oo00o = [ None , "ffff-ffff-ffff" , True ]
  iii11II1I ( lisp_sockets , [ oOO0o000Oo00o ] )
  if 5 - 5: OoOoOO00 - IiII * IiII
  if 50 - 50: II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + Oo0Ooo - OOooOOo
  if 18 - 18: OoOoOO00 % i11iIiiIii % I1ii11iIi11i / oO0o / o0oOOo0O0Ooo / i1IIi
  if 48 - 48: OoOoOO00 + I11i / IiII + II111iiii
  if 18 - 18: I1ii11iIi11i
  if 23 - 23: II111iiii
 if ( OOO0o0o != None ) :
  OOO0o0o . cancel ( )
  OOO0o0o = None
  if 24 - 24: iIii1I11I1II1 + iIii1I11I1II1 * iII111i
  if 18 - 18: iII111i * I11i - Ii1I
  if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if ( Oo0o ) : Oo0o . cancel ( )
 Oo0o = threading . Timer ( I11 ,
 OOOO00ooo0Ooo , [ o0oOoO00o ] )
 Oo0o . start ( )
 return
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
def iii11II1I ( lisp_sockets , entries ) :
 IIiIiiiIIIIi1 = len ( entries )
 if ( IIiIiiiIIIIi1 == 0 ) : return
 if 39 - 39: OoO0O00 / Ii1I / I1Ii111
 O00O0 = None
 if ( entries [ 0 ] [ 1 ] . find ( ":" ) != - 1 ) : O00O0 = lisp . LISP_AFI_IPV6
 if ( entries [ 0 ] [ 1 ] . find ( "." ) != - 1 ) : O00O0 = lisp . LISP_AFI_IPV4
 if ( entries [ 0 ] [ 1 ] . find ( "-" ) != - 1 ) : O00O0 = lisp . LISP_AFI_MAC
 if ( O00O0 == None ) :
  lisp . lprint ( "lisp_send_multicast_map_register() invalid group address" )
  return
  if 19 - 19: oO0o - II111iiii
  if 63 - 63: i11iIiiIii . o0oOOo0O0Ooo
  if 19 - 19: II111iiii
  if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
  if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
  if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
  if 32 - 32: i11iIiiIii - I1Ii111
  if 53 - 53: OoooooooOO - IiII
  if 87 - 87: oO0o . I1IiiI
 i1i = [ ]
 for ooOo00 , IIIiiiI , OoO00oo00 in entries :
  if 76 - 76: OoooooooOO + Oo0Ooo % IiII . OoO0O00 + II111iiii
  i1i . append ( [ IIIiiiI , OoO00oo00 ] )
  if 70 - 70: I1IiiI / I11i
  if 28 - 28: I1ii11iIi11i * OoooooooOO . II111iiii / i11iIiiIii + oO0o
 oOO00O0Ooooo00 = lisp . lisp_decent_pull_xtr_configured ( )
 if 38 - 38: IiII . Ii1I
 o0 = { }
 entries = [ ]
 for IIIiiiI , OoO00oo00 in i1i :
  IIIIIIIiI = lisp . lisp_lookup_group ( IIIiiiI )
  if ( IIIIIIIiI == None ) :
   lisp . lprint ( "No group-mapping for {}, could be underlay group" . format ( IIIiiiI ) )
   if 12 - 12: iII111i . IiII . OoOoOO00 / O0
   continue
   if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
   if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
  lisp . lprint ( "Use group-mapping '{}' {} for group {}" . format ( IIIIIIIiI . group_name , IIIIIIIiI . group_prefix . print_prefix ( ) , IIIiiiI ) )
  if 8 - 8: ooOoO0o * O0
  if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
  IIiI1 = IIIIIIIiI . group_prefix . instance_id
  O0ii1ii1ii = IIIIIIIiI . use_ms_name
  III1ii = IIIIIIIiI . rle_address
  if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
  if 100 - 100: Ii1I + OoO0O00
  if 73 - 73: i1IIi - I1Ii111 % ooOoO0o / OoO0O00
  if 40 - 40: I1ii11iIi11i * ooOoO0o - I1IiiI / IiII / i11iIiiIii
  if 83 - 83: I1ii11iIi11i / I1Ii111 - i11iIiiIii . iIii1I11I1II1 + Oo0Ooo
  if 59 - 59: O0 % Oo0Ooo
  O0o00O0Oo0 = O0ii1ii1ii
  if ( oOO00O0Ooooo00 ) :
   O0o00O0Oo0 = lisp . lisp_get_decent_dns_name_from_str ( IIiI1 , IIIiiiI )
   o0 [ O0o00O0Oo0 ] = [ "" , 0 ]
   if 58 - 58: O0
   if 78 - 78: OoO0O00 % IiII * i1IIi
  if ( len ( IIIIIIIiI . sources ) == 0 ) :
   entries . append ( [ "0.0.0.0" , IIIiiiI , IIiI1 , O0o00O0Oo0 , III1ii , OoO00oo00 ] )
   continue
   if 66 - 66: Ii1I . I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1
  for OOoO00 in IIIIIIIiI . sources :
   o0 [ O0o00O0Oo0 ] = [ "" , 0 ]
   entries . append ( [ OOoO00 , IIIiiiI , IIiI1 , O0o00O0Oo0 , III1ii , OoO00oo00 ] )
   if 51 - 51: I11i . Oo0Ooo
   if 45 - 45: i1IIi - Oo0Ooo / O0 . I1ii11iIi11i
   if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 IIiIiiiIIIIi1 = len ( entries )
 if ( IIiIiiiIIIIi1 == 0 ) : return
 if 56 - 56: OoooooooOO - I11i - i1IIi
 lisp . lprint ( "Build Map-Register for {} multicast entries" . format ( IIiIiiiIIIIi1 ) )
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 IiIiIi1I1 = lisp . lisp_rle_node ( )
 IiIiIi1I1 . level = 128
 IiI1ii1Ii = lisp . lisp_get_any_translated_rloc ( )
 III1ii = lisp . lisp_rle ( "" )
 III1ii . rle_nodes . append ( IiIiIi1I1 )
 if 51 - 51: i11iIiiIii * o0oOOo0O0Ooo / I1IiiI
 if 40 - 40: I1IiiI
 if 36 - 36: ooOoO0o / iII111i - IiII - IiII
 if 82 - 82: I1ii11iIi11i
 if 29 - 29: IiII
 if 66 - 66: Oo0Ooo
 if ( oOO00O0Ooooo00 == False ) :
  for i1i1I1IIii1II in lisp . lisp_map_servers_list . values ( ) :
   o0 [ i1i1I1IIii1II . ms_name ] = [ "" , 0 ]
   if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
   if 55 - 55: o0oOOo0O0Ooo . iII111i
   if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
 O00 = None
 if ( lisp . lisp_nat_traversal ) : O00 = lisp . lisp_hostname
 if 32 - 32: iIii1I11I1II1 * IiII / Ii1I % IiII
 if 42 - 42: I1Ii111 + I1Ii111 * II111iiii
 if 78 - 78: OoooooooOO
 if 77 - 77: I1ii11iIi11i / i1IIi / Oo0Ooo % OOooOOo
 I1I1Iiii1 = 0
 for Oo00o0OO0O00o in lisp . lisp_rtr_list . values ( ) :
  if ( Oo00o0OO0O00o == None ) : continue
  I1I1Iiii1 += 1
  if 2 - 2: I11i + ooOoO0o
  if 76 - 76: I1Ii111
  if 99 - 99: I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % oO0o / I11i
  if 60 - 60: Ii1I * OoOoOO00 - i11iIiiIii % ooOoO0o
  if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
 Ii1i1iI = ""
 for ooOo00 , IIIiiiI , IIiI1 , ii1IIIIiI11 , i1III , OoO00oo00 in entries :
  if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
  if 70 - 70: OoO0O00
  if 46 - 46: I11i - i1IIi
  if 46 - 46: I1Ii111 % Ii1I
  if ( o0 . has_key ( ii1IIIIiI11 ) == False ) : continue
  if 72 - 72: iIii1I11I1II1
  i1iI1 = lisp . lisp_eid_record ( )
  i1iI1 . rloc_count = 1 + I1I1Iiii1
  i1iI1 . authoritative = True
  i1iI1 . record_ttl = lisp . LISP_REGISTER_TTL if OoO00oo00 else 0
  i1iI1 . eid = lisp . lisp_address ( O00O0 , ooOo00 , 0 , IIiI1 )
  if ( i1iI1 . eid . address == 0 ) : i1iI1 . eid . mask_len = 0
  i1iI1 . group = lisp . lisp_address ( O00O0 , IIIiiiI , 0 , IIiI1 )
  if ( i1iI1 . group . is_mac_broadcast ( ) and i1iI1 . eid . address == 0 ) : i1iI1 . eid . mask_len = 0
  if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
  oOoO00oo0O = ""
  O0ii1ii1ii = ""
  if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
   oOoO00oo0O = lisp . lisp_get_decent_index ( i1iI1 . group )
   oOoO00oo0O = lisp . bold ( str ( oOoO00oo0O ) , False )
   oOoO00oo0O = "with decent-index {}" . format ( oOoO00oo0O )
  else :
   oOoO00oo0O = "for ms-name '{}'" . format ( ii1IIIIiI11 )
   if 87 - 87: OoO0O00 % I1IiiI
   if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
  iIi1iIIIiIiI = lisp . green ( i1iI1 . print_eid_tuple ( ) , False )
  lisp . lprint ( "  EID-prefix {} {}{}" . format ( iIi1iIIIiIiI , O0ii1ii1ii ,
 oOoO00oo0O ) )
  if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
  Ii1i1iI += i1iI1 . encode ( )
  i1iI1 . print_record ( "  " , False )
  o0 [ ii1IIIIiI11 ] [ 1 ] += 1
  if 84 - 84: i11iIiiIii * OoO0O00
  if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
  if 30 - 30: O0 + I1ii11iIi11i + II111iiii
  if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
  OOO0oOOoo = lisp . lisp_rloc_record ( )
  OOO0oOOoo . rloc_name = O00
  if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
  if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  if 64 - 64: i1IIi
  if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
  if 18 - 18: OOooOOo + I1Ii111
  if ( IiI1ii1Ii != None ) :
   IiIiIi1I1 . address = IiI1ii1Ii
  elif ( i1III != None ) :
   IiIiIi1I1 . address = i1III
  else :
   IiIiIi1I1 . address = i1III = lisp . lisp_myrlocs [ 0 ]
   if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
   if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
  OOO0oOOoo . rle = III1ii
  OOO0oOOoo . local_bit = True
  OOO0oOOoo . reach_bit = True
  OOO0oOOoo . priority = 255
  OOO0oOOoo . weight = 0
  OOO0oOOoo . mpriority = 1
  OOO0oOOoo . mweight = 100
  Ii1i1iI += OOO0oOOoo . encode ( )
  OOO0oOOoo . print_record ( "    " )
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
  if 50 - 50: ooOoO0o + i1IIi
  if 31 - 31: Ii1I
  if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
  if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
  for Oo00o0OO0O00o in lisp . lisp_rtr_list . values ( ) :
   if ( Oo00o0OO0O00o == None ) : continue
   OOO0oOOoo = lisp . lisp_rloc_record ( )
   OOO0oOOoo . rloc . copy_address ( Oo00o0OO0O00o )
   OOO0oOOoo . priority = 254
   OOO0oOOoo . rloc_name = "RTR"
   OOO0oOOoo . weight = 0
   OOO0oOOoo . mpriority = 255
   OOO0oOOoo . mweight = 0
   OOO0oOOoo . local_bit = False
   OOO0oOOoo . reach_bit = True
   Ii1i1iI += OOO0oOOoo . encode ( )
   OOO0oOOoo . print_record ( "    RTR " )
   if 47 - 47: o0oOOo0O0Ooo
   if 66 - 66: I1IiiI - IiII
   if 33 - 33: I1IiiI / OoO0O00
   if 12 - 12: II111iiii
   if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
  o0 [ ii1IIIIiI11 ] [ 0 ] += Ii1i1iI
  if 25 - 25: oO0o
  if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
  if 43 - 43: I1ii11iIi11i - iII111i
  if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
  if 47 - 47: iII111i
 oooO0o0o0O0 = lisp . lisp_map_register ( )
 oooO0o0o0O0 . nonce = 0xaabbccdddfdfdf00
 oooO0o0o0O0 . xtr_id_present = True
 oooO0o0o0O0 . proxy_reply_requested = True
 oooO0o0o0O0 . map_notify_requested = False
 oooO0o0o0O0 . merge_register_requested = True
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if 47 - 47: oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 for i1i1I1IIii1II in lisp . lisp_map_servers_list . values ( ) :
  O0o00O0Oo0 = i1i1I1IIii1II . dns_name if oOO00O0Ooooo00 else i1i1I1IIii1II . ms_name
  if 98 - 98: iII111i + Ii1I - OoO0O00
  if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
  if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
  if 38 - 38: O0 - IiII % I1Ii111
  if ( o0 . has_key ( O0o00O0Oo0 ) == False ) : continue
  if 64 - 64: iIii1I11I1II1
  if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
  if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
  if 6 - 6: Oo0Ooo % IiII * I11i / I1IiiI + Oo0Ooo
  oooO0o0o0O0 . record_count = o0 [ O0o00O0Oo0 ] [ 1 ]
  if ( oooO0o0o0O0 . record_count == 0 ) : continue
  if 39 - 39: OoOoOO00 - Oo0Ooo / iII111i * OoooooooOO
  oooO0o0o0O0 . nonce += 1
  oooO0o0o0O0 . alg_id = i1i1I1IIii1II . alg_id
  oooO0o0o0O0 . alg_id = i1i1I1IIii1II . key_id
  oooO0o0o0O0 . xtr_id = i1i1I1IIii1II . xtr_id
  oooO0o0o0O0 . site_id = i1i1I1IIii1II . site_id
  oooO0o0o0O0 . encrypt_bit = ( i1i1I1IIii1II . ekey != None )
  oO0OO0 = oooO0o0o0O0 . encode ( )
  oooO0o0o0O0 . print_map_register ( )
  if 100 - 100: O0 . I11i . OoO0O00 + O0 * oO0o
  if 42 - 42: oO0o % OoooooooOO + o0oOOo0O0Ooo
  if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
  if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
  if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
  I11Ii11iI1 = oooO0o0o0O0 . encode_xtr_id ( "" )
  oO0OO0 = oO0OO0 + Ii1i1iI + I11Ii11iI1
  if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
  i1i1I1IIii1II . map_registers_multicast_sent += 1
  lisp . lisp_send_map_register ( lisp_sockets , oO0OO0 , oooO0o0o0O0 , i1i1I1IIii1II )
  if 52 - 52: OoO0O00 % Ii1I * II111iiii
  if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
  if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
  if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
  i1i1I1IIii1II . resolve_dns_name ( )
  if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
  if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
  if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
  if 71 - 71: IiII . I1Ii111 . OoO0O00
  time . sleep ( .001 )
  if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 return
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
 if 93 - 93: I1Ii111 + Ii1I
 if 33 - 33: O0
 if 78 - 78: O0 / II111iiii * OoO0O00
def IiIi1iI11 ( parms , not_used , packet ) :
 global Ooo , o0oOoO00o
 if 11 - 11: I1ii11iIi11i
 iiI1Ii11II1I = parms [ 0 ]
 i1 = parms [ 1 ]
 if 44 - 44: Ii1I % i11iIiiIii - iII111i * I1ii11iIi11i + Oo0Ooo * OOooOOo
 if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
 if 65 - 65: Oo0Ooo . OoooooooOO
 if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
 if 55 - 55: iII111i - OoO0O00
 if 100 - 100: O0
 if ( lisp . lisp_is_macos ( ) == False ) :
  o00 = 4 if iiI1Ii11II1I == "lo0" else 16
  packet = packet [ o00 : : ]
  if 46 - 46: iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OoOoOO00 - I1Ii111
  if 5 - 5: OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
  if 11 - 11: i1IIi % OoO0O00 % iII111i
  if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
  if 13 - 13: OoO0O00
 O0oo0O0 = struct . unpack ( "B" , packet [ 9 ] ) [ 0 ]
 if ( O0oo0O0 == 2 ) :
  ii = lisp . lisp_process_igmp_packet ( packet )
  if ( type ( ii ) != bool ) :
   iii11II1I ( o0oOoO00o , ii )
   return
   if 9 - 9: OoO0O00 * Ii1I % i1IIi % oO0o
   if 53 - 53: oO0o * OoooooooOO . OoOoOO00
   if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
   if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
   if 48 - 48: i11iIiiIii % oO0o
   if 29 - 29: iII111i + i11iIiiIii % I11i
 oOo00Ooo0o0 = packet
 packet , ooOo00 , i1IiII1i1I , iI1ii1ii1I = lisp . lisp_is_rloc_probe ( packet , 0 )
 if ( oOo00Ooo0o0 != packet ) :
  if ( ooOo00 == None ) : return
  lisp . lisp_parse_packet ( o0oOoO00o , packet , ooOo00 , i1IiII1i1I , iI1ii1ii1I )
  return
  if 18 - 18: oO0o * oO0o % oO0o
  if 17 - 17: O0 * OoOoOO00 * I1ii11iIi11i * II111iiii * I11i % i1IIi
  if 33 - 33: I1ii11iIi11i * I1ii11iIi11i . ooOoO0o . i11iIiiIii
  if 48 - 48: o0oOOo0O0Ooo . Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
  if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
  if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
  if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 IiIi1i = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 if ( lisp . lisp_nat_traversal and IiIi1i == lisp . LISP_DATA_PORT ) : return
 packet = lisp . lisp_reassemble ( packet )
 if ( packet == None ) : return
 if 99 - 99: OoOoOO00 . I1Ii111
 packet = lisp . lisp_packet ( packet )
 O0oO = packet . decode ( True , Ooo , lisp . lisp_decap_stats )
 if ( O0oO == None ) : return
 if 27 - 27: O0 / OoOoOO00 + iIii1I11I1II1 - OOooOOo % o0oOOo0O0Ooo
 if 30 - 30: I1Ii111 % I1Ii111 % IiII . OoOoOO00
 if 9 - 9: ooOoO0o / II111iiii . OoOoOO00 % o0oOOo0O0Ooo * II111iiii - ooOoO0o
 if 55 - 55: I1IiiI
 packet . print_packet ( "Receive" , True )
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
 if 46 - 46: I1Ii111
 if 72 - 72: iII111i * OOooOOo
 if 67 - 67: i1IIi
 if 5 - 5: II111iiii . OoooooooOO
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 57 - 57: I1IiiI
  ooOo00 = packet . inner_source . print_address_no_iid ( )
  packet . strip_outer_headers ( )
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , ooOo00 , IiIi1i )
  lisp . lisp_ipc ( packet , Ooo , "lisp-ms" )
  return
  if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
  if 50 - 50: OoOoOO00
  if 33 - 33: I11i
  if 98 - 98: OoOoOO00 % II111iiii
  if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
  if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
  if 68 - 68: o0oOOo0O0Ooo
  if 20 - 20: I1Ii111 - I1Ii111
  if 37 - 37: IiII
  if 37 - 37: Oo0Ooo / IiII * O0
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  o0o00O0oOooO0 = packet . packet [ 36 : : ]
  o0oO0OO00ooOO = o0o00O0oOooO0 [ 28 : : ]
  iI1ii1ii1I = - 1
  if ( lisp . lisp_is_rloc_probe_request ( o0oO0OO00ooOO [ 0 ] ) ) :
   iI1ii1ii1I = struct . unpack ( "B" , o0o00O0oOooO0 [ 8 ] ) [ 0 ] - 1
   if 5 - 5: I1IiiI * OoOoOO00 - i11iIiiIii . ooOoO0o / iII111i
  ooOo00 = packet . outer_source . print_address_no_iid ( )
  lisp . lisp_parse_packet ( o0oOoO00o , o0oO0OO00ooOO , ooOo00 , 0 , iI1ii1ii1I )
  return
  if 48 - 48: OoO0O00 * OOooOOo + iIii1I11I1II1 / II111iiii
  if 100 - 100: I11i
  if 59 - 59: oO0o * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i
  if 85 - 85: O0
  if 32 - 32: OoooooooOO . OoO0O00 / Oo0Ooo * o0oOOo0O0Ooo / o0oOOo0O0Ooo * Ii1I
  if 19 - 19: Ii1I
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 55 - 55: OOooOOo % OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
  if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
  if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
  if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
  if 71 - 71: iII111i
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
 if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
 if 58 - 58: I1ii11iIi11i
 packet . strip_outer_headers ( )
 ii1I = lisp . bold ( "Forward" , False )
 if 98 - 98: i1IIi
 if 51 - 51: I1ii11iIi11i + ooOoO0o + Oo0Ooo / i1IIi + i1IIi
 if 12 - 12: iIii1I11I1II1 . Ii1I . I1ii11iIi11i % I1IiiI . II111iiii . oO0o
 if 32 - 32: I1ii11iIi11i + IiII / O0 / OoOoOO00 * OoooooooOO % ooOoO0o
 iIiiIIi = False
 O0Ii11i1Ii1IIII = packet . inner_dest . is_mac ( )
 if ( O0Ii11i1Ii1IIII ) :
  packet . packet = lisp . lisp_mac_input ( packet . packet )
  if ( packet . packet == None ) : return
  ii1I = lisp . bold ( "Bridge" , False )
 elif ( packet . inner_version == 4 ) :
  iIiiIIi , packet . packet = lisp . lisp_ipv4_input ( packet . packet )
  if ( packet . packet == None ) : return
  if ( iIiiIIi ) :
   ii = lisp . lisp_process_igmp_packet ( packet . packet )
   if ( type ( ii ) != bool ) :
    iii11II1I ( o0oOoO00o , ii )
    return
    if 41 - 41: Ii1I / II111iiii . OoOoOO00
    if 63 - 63: O0
  packet . inner_ttl = packet . outer_ttl
 elif ( packet . inner_version == 6 ) :
  packet . packet = lisp . lisp_ipv6_input ( packet )
  if ( packet . packet == None ) : return
  packet . inner_ttl = packet . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 6 - 6: OOooOOo
  if 98 - 98: OoooooooOO % O0 - O0
  if 76 - 76: i1IIi % OoOoOO00 - I1IiiI / o0oOOo0O0Ooo * ooOoO0o
  if 4 - 4: Oo0Ooo * Oo0Ooo / OoOoOO00
  if 4 - 4: I1IiiI * OoOoOO00 % I11i . OoOoOO00
  if 11 - 11: OOooOOo - OoOoOO00 - o0oOOo0O0Ooo * OoOoOO00 + ooOoO0o
  if 62 - 62: I1IiiI * i11iIiiIii . iII111i
  if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
  if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
  if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  I1I = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( I1I ) :
   I1I . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
   return
   if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 else :
  if ( lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False ) ) :
   lisp . dprint ( "Discard echoed multicast packet (through NAT)" )
   return
   if 10 - 10: iII111i . i1IIi + Ii1I
   if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
   if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
   if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
   if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
   if 84 - 84: i1IIi
   if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
   if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 81 - 81: IiII / OoOoOO00 * IiII . O0
  if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
  if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
  if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
  if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
 oooooOoo0ooo = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 61 - 61: I1Ii111 - Ii1I % I1ii11iIi11i / ooOoO0o / iII111i + iIii1I11I1II1
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( ii1I , lisp . green ( oooooOoo0ooo , False ) ,
 # Oo0Ooo * Oo0Ooo * II111iiii * iII111i . i1IIi / IiII
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 92 - 92: Ii1I * i11iIiiIii + iII111i * I1Ii111
 if 48 - 48: I11i * iII111i * iII111i
 if 70 - 70: oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if ( O0Ii11i1Ii1IIII ) :
  packet . bridge_l2_packet ( packet . inner_dest , I1I )
  return
  if 80 - 80: OoooooooOO + IiII
  if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
  if 43 - 43: Oo0Ooo . I1Ii111
  if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
  if 29 - 29: IiII . ooOoO0o - II111iiii
  if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( oOOoo00O0O , i1111 )
  return
  if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
  if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
  if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
  if 59 - 59: I1Ii111 - IiII
  if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 i111i1I1ii1i = packet . get_raw_socket ( )
 if ( i111i1I1ii1i == None ) : i111i1I1ii1i = i1
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 if 19 - 19: II111iiii - IiII
 packet . send_packet ( i111i1I1ii1i , packet . inner_dest )
 return
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
def OO0Oo ( lisp_raw_socket , packet , source ) :
 global Ooo , o0oOoO00o
 if 13 - 13: o0oOOo0O0Ooo * i11iIiiIii / i11iIiiIii . OoO0O00 . OOooOOo . I1ii11iIi11i
 if 26 - 26: o0oOOo0O0Ooo . iIii1I11I1II1
 if 67 - 67: Oo0Ooo / O0
 if 88 - 88: OoOoOO00 - OOooOOo
 o0oo0O0oOoooO = packet
 packet = lisp . lisp_packet ( packet [ 8 : : ] )
 if ( packet . lisp_header . decode ( o0oo0O0oOoooO ) == False ) : return
 if 70 - 70: oO0o * oO0o + Oo0Ooo * OOooOOo % I1IiiI + iIii1I11I1II1
 if 2 - 2: i11iIiiIii
 if 98 - 98: oO0o / OoO0O00 - Ii1I - I1IiiI / OoOoOO00 + i11iIiiIii
 if 17 - 17: I11i
 if 97 - 97: I1ii11iIi11i * I1ii11iIi11i / iII111i
 packet . outer_source = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , source ,
 lisp . LISP_IPV4_HOST_MASK_LEN , 0 )
 if 6 - 6: oO0o
 O0oO = packet . decode ( False , Ooo ,
 lisp . lisp_decap_stats )
 if ( O0oO == None ) : return
 if 72 - 72: I11i * I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if ( lisp . lisp_flow_logging ) : packet . log_flow ( False )
 if 27 - 27: OOooOOo
 packet . print_packet ( "Kernel-decap" , False )
 lisp . dprint ( packet . lisp_header . print_header ( " " ) )
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
  IiIi1i = packet . udp_sport
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , source , IiIi1i )
  lisp . lisp_ipc ( packet , Ooo , "lisp-ms" )
  return
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
  if 45 - 45: Ii1I - OOooOOo
  if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
  if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
  if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
  if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
  if 36 - 36: I11i % OOooOOo
  if 72 - 72: I1IiiI / iII111i - O0 + I11i
  if 83 - 83: O0
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  o0o00O0oOooO0 = packet . packet
  o0oO0OO00ooOO = o0o00O0oOooO0 [ 28 : : ]
  iI1ii1ii1I = - 1
  if ( lisp . lisp_is_rloc_probe_request ( o0oO0OO00ooOO [ 0 ] ) ) :
   iI1ii1ii1I = struct . unpack ( "B" , o0o00O0oOooO0 [ 8 ] ) [ 0 ] - 1
   if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
  lisp . lisp_parse_packet ( o0oOoO00o , o0oO0OO00ooOO , source , 0 , iI1ii1ii1I )
  return
  if 40 - 40: OoO0O00 + OoO0O00
  if 94 - 94: iII111i * iIii1I11I1II1 . I11i
  if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
  if 41 - 41: I1ii11iIi11i
  if 5 - 5: Oo0Ooo
  if 100 - 100: Ii1I + iIii1I11I1II1
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 59 - 59: IiII
  if 89 - 89: OoOoOO00 % iIii1I11I1II1
  if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
  if 45 - 45: I1IiiI * OOooOOo % OoO0O00
  if 24 - 24: ooOoO0o - I11i * oO0o
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  I1I = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( I1I ) :
   I1I . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
   if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
   if 94 - 94: iII111i - Oo0Ooo + oO0o
 else :
  if ( lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False ) ) :
   lisp . dprint ( "Discard echoed multicast packet" )
   return
   if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
   if 56 - 56: oO0o + ooOoO0o
   if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
   if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
   if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
   if 36 - 36: OOooOOo % i11iIiiIii
   if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
   if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
  if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 oooooOoo0ooo = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( lisp . bold ( "NAT-Forward" , False ) , lisp . green ( oooooOoo0ooo , False ) ,
 # I1Ii111
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 44 - 44: OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00 + i11iIiiIii
 if 20 - 20: I1ii11iIi11i
 if 3 - 3: OoO0O00 * i1IIi . I1IiiI . O0 - OoOoOO00
 if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
 if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( oOOoo00O0O , i1111 )
  return
  if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
  if 10 - 10: I1ii11iIi11i / i11iIiiIii - Ii1I + oO0o * I1IiiI
  if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
  if 64 - 64: I11i + OoO0O00
  if 25 - 25: I1IiiI . ooOoO0o + I1IiiI % Ii1I * iIii1I11I1II1
 i111i1I1ii1i = packet . get_raw_socket ( )
 if ( i111i1I1ii1i == None ) : i111i1I1ii1i = lisp_raw_socket
 if 31 - 31: i11iIiiIii + OOooOOo - O0
 if 51 - 51: OoO0O00 * i1IIi / Ii1I * OOooOOo + ooOoO0o % I1ii11iIi11i
 if 34 - 34: oO0o * OoooooooOO + Ii1I + i11iIiiIii
 if 22 - 22: i1IIi
 packet . send_packet ( i111i1I1ii1i , packet . inner_dest )
 return
 if 24 - 24: I11i / I1IiiI * i1IIi % OoooooooOO
 if 99 - 99: i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
 if 98 - 98: oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
def i1IiI1Iiii ( group , joinleave ) :
 IIIIIIIiI = lisp . lisp_lookup_group ( group )
 if ( IIIIIIIiI == None ) : return
 if 87 - 87: IiII / I1Ii111 - Oo0Ooo
 oOO = [ ]
 for OOoO00 in IIIIIIIiI . sources :
  oOO . append ( [ OOoO00 , group , joinleave ] )
  if 59 - 59: OoO0O00 - OoO0O00 + iII111i
  if 32 - 32: i1IIi / Oo0Ooo - O0
 iii11II1I ( o0oOoO00o , oOO )
 return
 if 85 - 85: Ii1I - O0 * i11iIiiIii . i1IIi
 if 20 - 20: iII111i / OOooOOo
 if 28 - 28: ooOoO0o * I11i % i11iIiiIii * iII111i / Ii1I
 if 41 - 41: OOooOOo - o0oOOo0O0Ooo + Ii1I
 if 15 - 15: I11i / o0oOOo0O0Ooo + Ii1I
 if 76 - 76: Ii1I + OoooooooOO / OOooOOo % OoO0O00 / I1ii11iIi11i
 if 38 - 38: I1Ii111 . iII111i . I1IiiI * OoO0O00
 if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii / Ii1I
 if 93 - 93: ooOoO0o
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 if 19 - 19: I1ii11iIi11i
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if 66 - 66: O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
def iiI ( ) :
 global o0oOoO00o
 if 81 - 81: IiII * I1ii11iIi11i + II111iiii % IiII
 lisp . lisp_set_exception ( )
 if 46 - 46: II111iiii % iII111i - i1IIi / I11i * OoOoOO00
 oO0o0oOo = socket . htonl
 OoO0O0oo0o = [ oO0o0oOo ( 0x46000020 ) , oO0o0oOo ( 0x9fe60000 ) , oO0o0oOo ( 0x0102d7cc ) ,
 oO0o0oOo ( 0x0acfc15a ) , oO0o0oOo ( 0xe00000fb ) , oO0o0oOo ( 0x94040000 ) ]
 if 46 - 46: OoOoOO00 - O0
 oO0OO0 = ""
 for O00Ooo in OoO0O0oo0o : oO0OO0 += struct . pack ( "I" , O00Ooo )
 if 92 - 92: OoOoOO00 % O0
 if 55 - 55: iIii1I11I1II1 * iII111i
 if 85 - 85: iIii1I11I1II1 . II111iiii
 if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
 if 22 - 22: OOooOOo
 while ( True ) :
  I1I11Iiii111 = commands . getoutput ( "ls join-*" ) . replace ( "join-" , "" )
  I1I11Iiii111 = I1I11Iiii111 . split ( "\n" )
  if 38 - 38: OoO0O00 . ooOoO0o
  for IIIiiiI in I1I11Iiii111 :
   if ( lisp . lisp_valid_address_format ( "address" , IIIiiiI ) == False ) :
    continue
    if 34 - 34: i1IIi % IiII
    if 80 - 80: OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
   oOoO = ( IIIiiiI . find ( ":" ) != - 1 )
   if 32 - 32: O0 + oO0o % Oo0Ooo
   if 7 - 7: I1ii11iIi11i / ooOoO0o
   if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
   if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
   o0oO0o00O = os . path . exists ( "leave-{}" . format ( IIIiiiI ) )
   lisp . lprint ( "Internal {} group {}" . format ( "leaving" if o0oO0o00O else "joining" , IIIiiiI ) )
   if 6 - 6: OoooooooOO / i11iIiiIii / I1Ii111
   if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
   if 34 - 34: I1Ii111 - OOooOOo
   if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
   if 64 - 64: i1IIi
   if ( oOoO ) :
    if ( IIIiiiI . lower ( ) . find ( "ff02:" ) != - 1 ) :
     lisp . lprint ( "Suppress registration for link-local groups" )
     continue
     if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
    i1IiI1Iiii ( IIIiiiI , ( o0oO0o00O == False ) )
   else :
    iiII = oO0OO0
    if ( o0oO0o00O ) :
     iiII += struct . pack ( "I" , oO0o0oOo ( 0x17000000 ) )
    else :
     iiII += struct . pack ( "I" , oO0o0oOo ( 0x16000000 ) )
     if 28 - 28: ooOoO0o . OoooooooOO + o0oOOo0O0Ooo + Ii1I % iII111i
     if 80 - 80: Oo0Ooo
    OOo0oOOOOooOo = IIIiiiI . split ( "." )
    iIiIi11 = int ( OOo0oOOOOooOo [ 0 ] ) << 24
    iIiIi11 += int ( OOo0oOOOOooOo [ 1 ] ) << 16
    iIiIi11 += int ( OOo0oOOOOooOo [ 2 ] ) << 8
    iIiIi11 += int ( OOo0oOOOOooOo [ 3 ] )
    iiII += struct . pack ( "I" , oO0o0oOo ( iIiIi11 ) )
    oOO = lisp . lisp_process_igmp_packet ( iiII )
    if ( type ( oOO ) != bool ) :
     iii11II1I ( o0oOoO00o , oOO )
     if 19 - 19: o0oOOo0O0Ooo
    time . sleep ( .100 )
    if 73 - 73: I1Ii111 * Oo0Ooo * OoOoOO00
    if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
  time . sleep ( 10 )
  if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 return
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 if 68 - 68: O0
def o0oOoO00 ( ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 94 - 94: OoO0O00 + IiII + ooOoO0o
 if 82 - 82: Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + IiII % iIii1I11I1II1
 if 61 - 61: OOooOOo / Oo0Ooo % OOooOOo - OoO0O00 + ooOoO0o / ooOoO0o
 if 82 - 82: Oo0Ooo
 if 5 - 5: OoO0O00 / OoO0O00 - O0 - I1Ii111 + I1Ii111
 O0oooOO0Oo0o = lisp . lisp_get_all_multicast_rles ( )
 if 68 - 68: OoooooooOO * iIii1I11I1II1 + i1IIi - i1IIi
 if 76 - 76: OoO0O00 . OoooooooOO % I1Ii111 * Ii1I
 if 23 - 23: IiII + iIii1I11I1II1
 if 14 - 14: O0 % IiII % Ii1I * oO0o
 iiI1Ii11II1I = "any"
 if 65 - 65: I11i % oO0o + I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 / O0 . I1Ii111 % iIii1I11I1II1 % Oo0Ooo
 if 86 - 86: i11iIiiIii - o0oOOo0O0Ooo . ooOoO0o * Oo0Ooo / Ii1I % o0oOOo0O0Ooo
 oOOo00 = pcappy . open_live ( iiI1Ii11II1I , 1600 , 0 , 100 )
 if 50 - 50: iIii1I11I1II1 - iII111i - I11i
 oo00O0O0O0o0o = "(proto 2) or "
 if 74 - 74: O0 % OoooooooOO * Oo0Ooo + OOooOOo * iII111i
 oo00O0O0O0o0o += "((dst host "
 for O000OO in lisp . lisp_get_all_addresses ( ) + O0oooOO0Oo0o :
  oo00O0O0O0o0o += "{} or " . format ( O000OO )
  if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
 oo00O0O0O0o0o = oo00O0O0O0o0o [ 0 : - 4 ]
 oo00O0O0O0o0o += ") and ((udp dst port 4341 or 8472 or 4789) or "
 oo00O0O0O0o0o += "(udp src port 4341) or "
 oo00O0O0O0o0o += "(udp dst port 4342 and ip[28] == 0x12) or "
 oo00O0O0O0o0o += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0)))))"
 if 46 - 46: iIii1I11I1II1
 if 70 - 70: i1IIi . I11i
 lisp . lprint ( "Capturing packets for: '{}' on device {}" . format ( oo00O0O0O0o0o ,
 iiI1Ii11II1I ) )
 oOOo00 . filter = oo00O0O0O0o0o
 if 74 - 74: I11i
 if 58 - 58: iIii1I11I1II1 * OoO0O00 * I1Ii111 * ooOoO0o . OoooooooOO
 if 6 - 6: I1ii11iIi11i - oO0o * i11iIiiIii + OoOoOO00 / ooOoO0o % OOooOOo
 if 38 - 38: OOooOOo % IiII % II111iiii - Oo0Ooo - iIii1I11I1II1
 oOOo00 . loop ( - 1 , IiIi1iI11 , [ iiI1Ii11II1I , i1 ] )
 return
 if 9 - 9: o0oOOo0O0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 28 - 28: OoooooooOO % oO0o + I1ii11iIi11i + O0 . I1Ii111
 if 80 - 80: i11iIiiIii % I1ii11iIi11i
 if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
 if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
 if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
def iiii11IiIiI ( ) :
 global Ooo
 global Oo
 global o0oOoO00o
 global i1
 global oOOoo00O0O
 global i1111
 if 8 - 8: I1Ii111 + OoO0O00
 lisp . lisp_i_am ( "etr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "ETR starting up" )
 if 9 - 9: OOooOOo + o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: oO0o
 lisp . lisp_get_local_interfaces ( )
 lisp . lisp_get_local_macs ( )
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
 if 97 - 97: I1Ii111 . I11i / I1IiiI
 if 83 - 83: I11i - I1ii11iIi11i * oO0o
 if 90 - 90: Oo0Ooo * I1IiiI
 if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
 if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
 if 28 - 28: IiII * I1IiiI % IiII
 if 95 - 95: O0 / I11i . I1Ii111
 if 17 - 17: I11i
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 OOoO00 = lisp . lisp_open_listen_socket ( "0.0.0.0" , str ( I1Ii11I1Ii1i ) )
 OOoO00 . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_TTL , 32 )
 Oo = OOoO00
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 if 36 - 36: IiII
 if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
 Ooo = lisp . lisp_open_listen_socket ( "" , "lisp-etr" )
 if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
 o0oOoO00o [ 0 ] = Oo
 o0oOoO00o [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 o0oOoO00o [ 2 ] = Ooo
 if 43 - 43: iIii1I11I1II1 % OoO0O00
 if 84 - 84: Oo0Ooo
 if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
 if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
 if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
 if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
 if 25 - 25: o0oOOo0O0Ooo
 if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
 if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
 i1 = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 i1 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 o0oOoO00o . append ( i1 )
 if 41 - 41: i1IIi - I1IiiI
 if 48 - 48: I1IiiI - II111iiii / OoO0O00 + I1IiiI
 if 5 - 5: O0
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
 if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
 if 92 - 92: I11i / O0 * I1IiiI - I11i
 if 99 - 99: i11iIiiIii % OoooooooOO
 if 56 - 56: IiII * I1Ii111
 if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
 if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
 if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
 if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
 if 56 - 56: i1IIi . i11iIiiIii
 if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
 if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
 if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
 if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
 if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
 if 10 - 10: IiII / OoooooooOO
 if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
 if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
 if ( pytun != None ) :
  i1111 = '\x00\x00\x86\xdd'
  iiI1Ii11II1I = "lispers.net"
  try :
   oOOoo00O0O = pytun . TunTapDevice ( flags = pytun . IFF_TUN ,
 name = iiI1Ii11II1I )
   os . system ( "ip link set dev {} up" . format ( iiI1Ii11II1I ) )
  except :
   lisp . lprint ( "Cannot create tuntap interface" )
   if 25 - 25: iIii1I11I1II1
   if 63 - 63: ooOoO0o
   if 96 - 96: I11i
   if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
   if 63 - 63: iII111i
   if 11 - 11: iII111i - iIii1I11I1II1
 threading . Thread ( target = o0oOoO00 , args = [ ] ) . start ( )
 if 92 - 92: OoO0O00
 if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
 if 12 - 12: ooOoO0o
 if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
 threading . Thread ( target = iiI , args = [ ] ) . start ( )
 return ( True )
 if 60 - 60: OOooOOo . iII111i / iIii1I11I1II1 + OOooOOo * I1Ii111
 if 82 - 82: i11iIiiIii . iIii1I11I1II1 * I1IiiI - I11i + Ii1I
 if 48 - 48: I1ii11iIi11i
 if 96 - 96: ooOoO0o . OoooooooOO
 if 39 - 39: OOooOOo + OoO0O00
 if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
def o0I1iI111ii111i ( ) :
 global Oo0o
 global Ii1iI
 if 83 - 83: iIii1I11I1II1
 if 97 - 97: i11iIiiIii + Oo0Ooo * OOooOOo % iII111i . IiII
 if 4 - 4: O0 . iII111i - iIii1I11I1II1
 if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
 if ( Oo0o ) : Oo0o . cancel ( )
 if ( Ii1iI ) : Ii1iI . cancel ( )
 if 89 - 89: Ii1I
 if 51 - 51: iII111i
 if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
 if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
 lisp . lisp_close_socket ( o0oOoO00o [ 0 ] , "" )
 lisp . lisp_close_socket ( o0oOoO00o [ 1 ] , "" )
 lisp . lisp_close_socket ( Ooo , "lisp-etr" )
 return
 if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
 if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
 if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
 if 29 - 29: Ii1I / ooOoO0o % I11i
 if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
def oo0O00ooo0o ( ipc ) :
 ipc = ipc . split ( "%" )
 iIi1iIIIiIiI = ipc [ 1 ]
 ii1i1Iii = ipc [ 2 ]
 if ( ii1i1Iii == "None" ) : ii1i1Iii = None
 if 57 - 57: IiII
 oOoOOo = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 oOoOOo . store_address ( iIi1iIIIiIiI )
 if 41 - 41: iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % IiII / OOooOOo
 if 63 - 63: i1IIi % i11iIiiIii % II111iiii * OoooooooOO
 if 40 - 40: Oo0Ooo
 if 47 - 47: OoOoOO00
 I1I = lisp . lisp_db_for_lookups . lookup_cache ( oOoOOo , False )
 if ( I1I == None or I1I . dynamic_eid_configured ( ) == False ) :
  lisp . lprint ( "ITR/ETR dynamic-EID configuration out of sync for {}" . format ( lisp . green ( iIi1iIIIiIiI , False ) ) )
  if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
  return
  if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
  if 33 - 33: oO0o
  if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
  if 41 - 41: IiII % o0oOOo0O0Ooo
  if 67 - 67: O0 % I1Ii111
  if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
 O0iIi1IiII = None
 if ( I1I . dynamic_eids . has_key ( iIi1iIIIiIiI ) ) : O0iIi1IiII = I1I . dynamic_eids [ iIi1iIIIiIiI ]
 if 39 - 39: Ii1I
 if ( O0iIi1IiII == None and ii1i1Iii == None ) :
  lisp . lprint ( "ITR/ETR state mismatch for {}" . format ( lisp . green ( iIi1iIIIiIiI , False ) ) )
  if 60 - 60: OOooOOo
  return
  if 62 - 62: I1Ii111 * I11i
  if 74 - 74: OoOoOO00 . iIii1I11I1II1
  if 87 - 87: ooOoO0o
  if 41 - 41: OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
  if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
  if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
  if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
 if ( O0iIi1IiII and ii1i1Iii ) :
  if ( O0iIi1IiII . interface == ii1i1Iii ) :
   lisp . lprint ( "ITR sent redundant IPC for {}" . format ( lisp . green ( iIi1iIIIiIiI , False ) ) )
   if 44 - 44: I1Ii111 - IiII
  else :
   lisp . lprint ( "Dynamic-EID {} interface change, {} -> {}" . format ( lisp . green ( iIi1iIIIiIiI , False ) , O0iIi1IiII . interface , ii1i1Iii ) )
   if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
   O0iIi1IiII . interface = ii1i1Iii
   if 59 - 59: II111iiii
  return
  if 43 - 43: Oo0Ooo + OoooooooOO
  if 47 - 47: ooOoO0o
  if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
  if 23 - 23: II111iiii * iII111i
  if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
 if ( ii1i1Iii ) :
  O0iIi1IiII = lisp . lisp_dynamic_eid ( )
  O0iIi1IiII . dynamic_eid . copy_address ( oOoOOo )
  O0iIi1IiII . interface = ii1i1Iii
  O0iIi1IiII . get_timeout ( ii1i1Iii )
  I1I . dynamic_eids [ iIi1iIIIiIiI ] = O0iIi1IiII
  if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
  OoO0o0OO = lisp . bold ( "Registering" , False )
  iIi1iIIIiIiI = lisp . bold ( iIi1iIIIiIiI , False )
  lisp . lprint ( "{} dynamic-EID {} on interface {}, timeout {}" . format ( OoO0o0OO ,
 lisp . green ( iIi1iIIIiIiI , False ) , ii1i1Iii , O0iIi1IiII . timeout ) )
  if 10 - 10: oO0o - iII111i % II111iiii - I1Ii111 - i1IIi
  Ii1iI111II1I1 ( o0oOoO00o , None , oOoOOo , None , False )
  if 10 - 10: I1ii11iIi11i - I11i . I1Ii111
  if 8 - 8: iIii1I11I1II1 % oO0o + Oo0Ooo
  if 24 - 24: o0oOOo0O0Ooo / Ii1I / Ii1I % II111iiii - oO0o * oO0o
  if 58 - 58: OoOoOO00
  if ( lisp . lisp_is_macos ( ) == False ) :
   iIi1iIIIiIiI = oOoOOo . print_prefix_no_iid ( )
   o0oOO = "ip route add {} dev {}" . format ( iIi1iIIIiIiI , ii1i1Iii )
   os . system ( o0oOO )
   if 84 - 84: i11iIiiIii + ooOoO0o . O0
  return
  if 69 - 69: I1Ii111 / OoooooooOO % i11iIiiIii
  if 18 - 18: i11iIiiIii - ooOoO0o * oO0o + o0oOOo0O0Ooo
  if 16 - 16: OoooooooOO * i11iIiiIii . OoooooooOO - iIii1I11I1II1 * i1IIi
  if 33 - 33: I1Ii111 % II111iiii
  if 49 - 49: I1ii11iIi11i + I11i / o0oOOo0O0Ooo + OoooooooOO + OOooOOo / IiII
 if ( I1I . dynamic_eids . has_key ( iIi1iIIIiIiI ) ) :
  ii1i1Iii = I1I . dynamic_eids [ iIi1iIIIiIiI ] . interface
  i1i11I1I1 = lisp . bold ( "Deregistering" , False )
  lisp . lprint ( "{} dynamic-EID {}" . format ( i1i11I1I1 ,
 lisp . green ( iIi1iIIIiIiI , False ) ) )
  if 82 - 82: OoO0O00 - Oo0Ooo - O0 - OoooooooOO
  Ii1iI111II1I1 ( o0oOoO00o , 0 , oOoOOo , None , False )
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
  I1I . dynamic_eids . pop ( iIi1iIIIiIiI )
  if 18 - 18: Oo0Ooo % O0
  if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
  if 86 - 86: IiII
  if ( lisp . lisp_is_macos ( ) == False ) :
   iIi1iIIIiIiI = oOoOOo . print_prefix_no_iid ( )
   o0oOO = "ip route delete {} dev {}" . format ( iIi1iIIIiIiI , ii1i1Iii )
   os . system ( o0oOO )
   if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
   if 33 - 33: II111iiii - IiII - ooOoO0o
 return
 if 92 - 92: OoO0O00 * IiII
 if 92 - 92: oO0o
 if 7 - 7: iII111i
 if 73 - 73: OoO0O00 % I1ii11iIi11i
 if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
 if 62 - 62: i11iIiiIii
 if 2 - 2: I1IiiI
 if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
 if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
def i11 ( ipc ) :
 if ( lisp . lisp_register_all_rtrs ) : return
 if 89 - 89: OoO0O00 + o0oOOo0O0Ooo . OOooOOo - I1IiiI * i1IIi % II111iiii
 i1I1ii1i , Ooo00O0o , O0oO = ipc . split ( "%" )
 if ( lisp . lisp_rtr_list . has_key ( Ooo00O0o ) == False ) : return
 if 2 - 2: OoooooooOO % iIii1I11I1II1
 lisp . lprint ( "Process ITR IPC message, RTR {} has gone {}" . format (
 lisp . red ( Ooo00O0o , False ) , lisp . bold ( O0oO , False ) ) )
 if 21 - 21: IiII - I1IiiI % OoooooooOO + o0oOOo0O0Ooo
 Oo00o0OO0O00o = lisp . lisp_rtr_list [ Ooo00O0o ]
 if ( O0oO == "down" ) :
  lisp . lisp_rtr_list [ Ooo00O0o ] = None
  return
  if 92 - 92: ooOoO0o + IiII
  if 52 - 52: II111iiii / I1IiiI . oO0o * IiII . I11i
 Oo00o0OO0O00o = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , Ooo00O0o , 32 , 0 )
 lisp . lisp_rtr_list [ Ooo00O0o ] = Oo00o0OO0O00o
 return
 if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 6 - 6: oO0o . I11i
 if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
 if 50 - 50: oO0o % i1IIi * O0
 if 4 - 4: iIii1I11I1II1 . i1IIi
 if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
 if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
 if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
def oo0O ( ipc ) :
 Ooooo0O0 , i1I1ii1i , oOoO000 , Oo00o00Oo = ipc . split ( "%" )
 Oo00o00Oo = int ( Oo00o00Oo , 16 )
 if 50 - 50: ooOoO0o % Oo0Ooo
 oO0000O0Oo00O = lisp . lisp_get_echo_nonce ( None , oOoO000 )
 if ( oO0000O0Oo00O == None ) : oO0000O0Oo00O = lisp . lisp_echo_nonce ( oOoO000 )
 if 42 - 42: i11iIiiIii / I1IiiI - OoO0O00 - ooOoO0o + II111iiii % ooOoO0o
 if ( i1I1ii1i == "R" ) :
  oO0000O0Oo00O . request_nonce_sent = Oo00o00Oo
  lisp . lprint ( "Waiting for echo-nonce 0x{} from {}" . format ( lisp . lisp_hex_string ( Oo00o00Oo ) , lisp . red ( oO0000O0Oo00O . rloc_str , False ) ) )
  if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
 elif ( i1I1ii1i == "E" ) :
  oO0000O0Oo00O . echo_nonce_sent = Oo00o00Oo
  lisp . lprint ( "Sent echo-nonce 0x{} to {}" . format ( lisp . lisp_hex_string ( Oo00o00Oo ) , lisp . red ( oO0000O0Oo00O . rloc_str , False ) ) )
  if 5 - 5: O0 - I1IiiI
  if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
 return
 if 16 - 16: II111iiii
 if 100 - 100: O0 - i1IIi
 if 48 - 48: oO0o % ooOoO0o + O0
 if 27 - 27: I1ii11iIi11i / OOooOOo
 if 33 - 33: OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
O0OoOo = {
 "lisp xtr-parameters" : [ lispconfig . lisp_xtr_command , {
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

 "lisp map-server" : [ OOo0oO00ooO00 , {
 "ms-name" : [ True ] ,
 "address" : [ True ] ,
 "dns-name" : [ True ] ,
 "authentication-type" : [ False , "sha1" , "sha2" ] ,
 "authentication-key" : [ False ] ,
 "encryption-key" : [ False ] ,
 "proxy-reply" : [ False , "yes" , "no" ] ,
 "want-map-notify" : [ False , "yes" , "no" ] ,
 "merge-registrations" : [ False , "yes" , "no" ] ,
 "refresh-registrations" : [ False , "yes" , "no" ] ,
 "site-id" : [ False , 1 , 0xffffffffffffffff ] } ] ,

 "lisp database-mapping" : [ i1iIIIiI1I , {
 "prefix" : [ ] ,
 "mr-name" : [ True ] ,
 "ms-name" : [ True ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "secondary-instance-id" : [ True , 0 , 0xffffffff ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] ,
 "dynamic-eid" : [ True , "yes" , "no" ] ,
 "signature-eid" : [ True , "yes" , "no" ] ,
 "register-ttl" : [ True , 1 , 0xffffffff ] ,
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

 "lisp geo-coordinates" : [ lispconfig . lisp_geo_command , {
 "geo-name" : [ False ] ,
 "geo-tag" : [ False ] } ] ,

 "lisp json" : [ lispconfig . lisp_json_command , {
 "json-name" : [ False ] ,
 "json-string" : [ False ] } ] ,

 "lisp group-mapping" : [ ooOoOo0 , {
 "group-name" : [ False ] ,
 "ms-name" : [ True ] ,
 "group-prefix" : [ False ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "rle-address" : [ False ] ,
 "sources" : [ ] ,
 "address" : [ True ] } ] ,

 "show database-mapping" : [ oOOoo0Oo , { } ] ,
 "show etr-keys" : [ I1Ii , { } ] ,
 "show etr-dynamic-eid" : [ lispconfig . lisp_show_dynamic_eid_command , { } ]
 }
if 94 - 94: OoO0O00 + OoO0O00 + I1ii11iIi11i . OoO0O00 * Ii1I
if 62 - 62: o0oOOo0O0Ooo / iIii1I11I1II1
if 55 - 55: Ii1I / OoO0O00 + iII111i . IiII
if 47 - 47: O0
if 83 - 83: O0 + OoOoOO00 / O0 / I11i
if 68 - 68: i1IIi . I11i . i1IIi + IiII % I1IiiI
if ( iiii11IiIiI ( ) == False ) :
 lisp . lprint ( "lisp_etr_startup() failed" )
 lisp . lisp_print_banner ( "ETR abnormal exit" )
 exit ( 1 )
 if 32 - 32: OoOoOO00 . iIii1I11I1II1 % oO0o . O0 . OoOoOO00 / iII111i
 if 45 - 45: iIii1I11I1II1
I1I111IIIi1 = [ Oo , Ooo ]
if 66 - 66: o0oOOo0O0Ooo % OoOoOO00
while ( True ) :
 try : II1I1iIIiIIii , Oo00O0o0O , Ooooo0O0 = select . select ( I1I111IIIi1 , [ ] , [ ] )
 except : break
 if 86 - 86: I11i + O0 + Oo0Ooo - I11i
 if 34 - 34: II111iiii % I1IiiI % I1Ii111 + Oo0Ooo - OoOoOO00
 if 66 - 66: Ii1I * iIii1I11I1II1 - ooOoO0o / I1IiiI
 if 62 - 62: IiII . O0 . iIii1I11I1II1
 if ( Oo in II1I1iIIiIIii ) :
  i1I1ii1i , ooOo00 , i1IiII1i1I , oO0OO0 = lisp . lisp_receive ( Oo , False )
  if 94 - 94: ooOoO0o % I11i % i1IIi
  if ( ooOo00 == "" ) : break
  if 90 - 90: Ii1I * OoO0O00
  if ( i1IiII1i1I == lisp . LISP_DATA_PORT ) :
   OO0Oo ( i1 , oO0OO0 , ooOo00 )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( oO0OO0 [ 0 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
   I1IiiIi11 = lisp . lisp_parse_packet ( o0oOoO00o , oO0OO0 ,
 ooOo00 , i1IiII1i1I )
   if 20 - 20: OOooOOo - iII111i / Oo0Ooo * OoO0O00
   if 55 - 55: OoooooooOO
   if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
   if 38 - 38: O0
   if 79 - 79: i1IIi . oO0o
   if ( I1IiiIi11 ) :
    Ii1iI = threading . Timer ( 0 ,
 o0oooOO00 , [ None ] )
    Ii1iI . start ( )
    Oo0o = threading . Timer ( 0 ,
 OOOO00ooo0Ooo , [ o0oOoO00o ] )
    Oo0o . start ( )
    if 34 - 34: I1Ii111 * II111iiii
    if 71 - 71: IiII
    if 97 - 97: I1ii11iIi11i
    if 86 - 86: Oo0Ooo - OOooOOo . OoOoOO00 . II111iiii * I1IiiI . II111iiii
    if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
    if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
    if 28 - 28: i11iIiiIii
    if 51 - 51: I1IiiI + ooOoO0o * O0 . Ii1I
 if ( Ooo in II1I1iIIiIIii ) :
  i1I1ii1i , ooOo00 , i1IiII1i1I , oO0OO0 = lisp . lisp_receive ( Ooo , True )
  if 82 - 82: OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
  if ( ooOo00 == "" ) : break
  if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
  if ( i1I1ii1i == "command" ) :
   if ( oO0OO0 . find ( "learn%" ) != - 1 ) :
    oo0O00ooo0o ( oO0OO0 )
   elif ( oO0OO0 . find ( "nonce%" ) != - 1 ) :
    oo0O ( oO0OO0 )
   elif ( oO0OO0 . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( oO0OO0 )
   elif ( oO0OO0 . find ( "rtr%" ) != - 1 ) :
    i11 ( oO0OO0 )
   elif ( oO0OO0 . find ( "stats%" ) != - 1 ) :
    oO0OO0 = oO0OO0 . split ( "%" ) [ - 1 ]
    lisp . lisp_process_data_plane_decap_stats ( oO0OO0 , None )
   else :
    lispconfig . lisp_process_command ( Ooo ,
 i1I1ii1i , oO0OO0 , "lisp-etr" , [ O0OoOo ] )
    if 20 - 20: i1IIi . i1IIi - I11i
  elif ( i1I1ii1i == "api" ) :
   lisp . lisp_process_api ( "lisp-etr" , Ooo , oO0OO0 )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( oO0OO0 [ 0 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
   lisp . lisp_parse_packet ( o0oOoO00o , oO0OO0 , ooOo00 , i1IiII1i1I )
   if 35 - 35: II111iiii / OoOoOO00 - O0 . II111iiii
   if 55 - 55: Oo0Ooo % i1IIi * I11i
   if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
   if 63 - 63: iIii1I11I1II1 / ooOoO0o
o0I1iI111ii111i ( )
lisp . lisp_print_banner ( "ETR normal exit" )
exit ( 0 )
if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
if 50 - 50: II111iiii
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
