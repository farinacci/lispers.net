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
if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
def i11IiIiiIIIII ( kv_pair ) :
 global OOO0o0o
 global o0oOoO00o
 if 22 - 22: Ii1I * O0 / o0oOOo0O0Ooo
 lispconfig . lisp_database_mapping_command ( kv_pair , I1Ii11I1Ii1i )
 if 64 - 64: Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
 if 78 - 78: OoO0O00
 if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
 if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
 if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
 if 14 - 14: I11i % O0
 if ( lisp . lisp_nat_traversal ) : return
 if ( OOO0o0o != None and
 OOO0o0o . is_alive ( ) ) : return
 if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
 if ( len ( lisp . lisp_map_servers_list ) > 0 ) :
  OOO0o0o = threading . Timer ( 5 ,
 oO , [ o0oOoO00o ] )
  OOO0o0o . start ( )
  if 76 - 76: OoO0O00 * o0oOOo0O0Ooo % i1IIi - OoO0O00 / I1IiiI . OOooOOo
  if 41 - 41: OoOoOO00
  if 13 - 13: Oo0Ooo . i11iIiiIii - iIii1I11I1II1 - OoOoOO00
  if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
  if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
  if 100 - 100: Ii1I - Ii1I - I1Ii111
  if 20 - 20: OoooooooOO
  if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
def oo ( clause ) :
 if 68 - 68: I11i + OOooOOo . iIii1I11I1II1 - IiII % iIii1I11I1II1 - ooOoO0o
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 o0o0oOOOo0oo = lispconfig . lisp_show_myrlocs ( "" )
 if 80 - 80: I11i * i11iIiiIii / I1Ii111
 if 9 - 9: Ii1I + oO0o % Ii1I + i1IIi . OOooOOo
 if 31 - 31: o0oOOo0O0Ooo + I11i + I11i / II111iiii
 if 26 - 26: OoooooooOO
 o0o0oOOOo0oo = lispconfig . lisp_show_decap_stats ( o0o0oOOOo0oo , "ETR" )
 if 12 - 12: OoooooooOO % OoOoOO00 / ooOoO0o % o0oOOo0O0Ooo
 if 29 - 29: OoooooooOO
 if 23 - 23: o0oOOo0O0Ooo . II111iiii
 if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
 i1IiIiiI = lisp . lisp_decent_dns_suffix
 if ( i1IiIiiI == None ) :
  i1IiIiiI = ":"
 else :
  i1IiIiiI = "&nbsp;(dns-suffix '{}'):" . format ( i1IiIiiI )
  if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
  if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
 iIii11I = "{} configured map-servers" . format ( len ( lisp . lisp_map_servers_list ) )
 OOO0OOO00oo = "LISP-ETR Configured Map-Servers{}" . format ( i1IiIiiI )
 OOO0OOO00oo = lisp . lisp_span ( OOO0OOO00oo , iIii11I )
 if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 iIii11I = ( "P = proxy-reply requested, M = merge-registrations " + "requested, N = Map-Notify requested" )
 if 4 - 4: II111iiii / ooOoO0o . iII111i
 O0oo0OO0oOOOo = lisp . lisp_span ( "Registration<br>flags" , iIii11I )
 if 35 - 35: IiII % I1IiiI
 o0o0oOOOo0oo += lispconfig . lisp_table_header ( OOO0OOO00oo , "Address" , "Auth-Type" ,
 "xTR-ID" , "Site-ID" , O0oo0OO0oOOOo , "Map-Registers<br>Sent" ,
 "Map-Notifies<br>Received" )
 if 70 - 70: iII111i * I1ii11iIi11i
 for i1II1 in lisp . lisp_map_servers_list . values ( ) :
  i1II1 . resolve_dns_name ( )
  OoO0O0 = "" if i1II1 . ms_name == "all" else i1II1 . ms_name + "<br>"
  II1i1IiiIIi11 = OoO0O0 + i1II1 . map_server . print_address_no_iid ( )
  if ( i1II1 . dns_name ) : II1i1IiiIIi11 += "<br>" + i1II1 . dns_name
  if 47 - 47: iII111i
  Ii11iII1 = "0x" + lisp . lisp_hex_string ( i1II1 . xtr_id )
  Oo0O0O0ooO0O = "{}-{}-{}-{}" . format ( "P" if i1II1 . proxy_reply else "p" ,
 "M" if i1II1 . merge_registrations else "m" ,
 "N" if i1II1 . want_map_notify else "n" ,
 "R" if i1II1 . refresh_registrations else "r" )
  if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
  oo000OO00Oo = i1II1 . map_registers_sent + i1II1 . map_registers_multicast_sent
  if 51 - 51: IiII * o0oOOo0O0Ooo + I11i + OoO0O00
  if 66 - 66: OoOoOO00
  o0o0oOOOo0oo += lispconfig . lisp_table_row ( II1i1IiiIIi11 ,
 "sha1" if ( i1II1 . alg_id == lisp . LISP_SHA_1_96_ALG_ID ) else "sha2" ,
 Ii11iII1 , i1II1 . site_id , Oo0O0O0ooO0O , oo000OO00Oo ,
 i1II1 . map_notifies_received )
  if 97 - 97: oO0o % IiII * IiII
 o0o0oOOOo0oo += lispconfig . lisp_table_footer ( )
 if 39 - 39: Ii1I % IiII
 if 4 - 4: oO0o
 if 93 - 93: OoO0O00 % oO0o . OoO0O00 * I1Ii111 % Ii1I . II111iiii
 if 38 - 38: o0oOOo0O0Ooo
 o0o0oOOOo0oo = lispconfig . lisp_show_db_list ( "ETR" , o0o0oOOOo0oo )
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
 if 26 - 26: iII111i
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
 if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
 if ( len ( lisp . lisp_elp_list ) != 0 ) :
  o0o0oOOOo0oo = lispconfig . lisp_show_elp_list ( o0o0oOOOo0oo )
  if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
  if 91 - 91: oO0o % Oo0Ooo
  if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
  if 31 - 31: I11i - II111iiii . I11i
  if 18 - 18: o0oOOo0O0Ooo
 if ( len ( lisp . lisp_rle_list ) != 0 ) :
  o0o0oOOOo0oo = lispconfig . lisp_show_rle_list ( o0o0oOOOo0oo )
  if 98 - 98: iII111i * iII111i / iII111i + I11i
  if 34 - 34: ooOoO0o
  if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
  if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
  if 92 - 92: iII111i . I1Ii111
 if ( len ( lisp . lisp_json_list ) != 0 ) :
  o0o0oOOOo0oo = lispconfig . lisp_show_json_list ( o0o0oOOOo0oo )
  if 31 - 31: I1Ii111 . OoOoOO00 / O0
  if 89 - 89: OoOoOO00
  if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
  if 4 - 4: ooOoO0o + O0 * OOooOOo
  if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
 if ( len ( lisp . lisp_group_mapping_list ) != 0 ) :
  OOO0OOO00oo = "Configured Group Mappings:"
  o0o0oOOOo0oo += lispconfig . lisp_table_header ( OOO0OOO00oo , "Name" , "Group Prefix" ,
 "Sources" , "Use MS" )
  for ii1ii1ii in lisp . lisp_group_mapping_list . values ( ) :
   oooooOoo0ooo = ""
   for I1I1IiI1 in ii1ii1ii . sources : oooooOoo0ooo += I1I1IiI1 + ", "
   if ( oooooOoo0ooo == "" ) :
    oooooOoo0ooo = "*"
   else :
    oooooOoo0ooo = oooooOoo0ooo [ 0 : - 2 ]
    if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
   o0o0oOOOo0oo += lispconfig . lisp_table_row ( ii1ii1ii . group_name ,
 ii1ii1ii . group_prefix . print_prefix ( ) , oooooOoo0ooo , ii1ii1ii . use_ms_name )
   if 91 - 91: O0
  o0o0oOOOo0oo += lispconfig . lisp_table_footer ( )
  if 61 - 61: II111iiii
 return ( o0o0oOOOo0oo )
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
 if 67 - 67: I1Ii111 . iII111i . O0
 if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
 if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
def o0oO ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "ETR" ) )
 if 1 - 1: OoO0O00 - oO0o . I11i . OoO0O00 / Oo0Ooo + I11i
 if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
 if 49 - 49: Ii1I / OoO0O00 . II111iiii
 if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
 if 31 - 31: II111iiii . I1IiiI
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
def ooOOOoOooOoO ( kv_pairs ) :
 global OOO0o0o
 global Ii1iI
 if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
 IIi1I11I1II = [ ]
 OooOoooOo = [ ]
 ii11IIII11I = 0
 OOooo = 0
 oOooOOOoOo = ""
 i1Iii1i1I = False
 OOoO00 = False
 IiI111111IIII = False
 i1Ii = False
 ii111iI1iIi1 = 0
 OoO0O0 = None
 OOO = 0
 oo0OOo0 = None
 if 47 - 47: I1Ii111 + OoOoOO00 * Oo0Ooo / ooOoO0o - iII111i % iIii1I11I1II1
 for IIi11i1i1iI1 in kv_pairs . keys ( ) :
  iiiIi1 = kv_pairs [ IIi11i1i1iI1 ]
  if ( IIi11i1i1iI1 == "ms-name" ) :
   OoO0O0 = iiiIi1 [ 0 ]
   if 38 - 38: I1Ii111
  if ( IIi11i1i1iI1 == "address" ) :
   for Ooo00o0Oooo in range ( len ( iiiIi1 ) ) :
    IIi1I11I1II . append ( iiiIi1 [ Ooo00o0Oooo ] )
    if 84 - 84: o0oOOo0O0Ooo % II111iiii . i11iIiiIii / OoO0O00
    if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
  if ( IIi11i1i1iI1 == "dns-name" ) :
   for Ooo00o0Oooo in range ( len ( iiiIi1 ) ) :
    OooOoooOo . append ( iiiIi1 [ Ooo00o0Oooo ] )
    if 25 - 25: OoO0O00
    if 62 - 62: OOooOOo + O0
  if ( IIi11i1i1iI1 == "authentication-type" ) :
   OOooo = lisp . LISP_SHA_1_96_ALG_ID if ( iiiIi1 == "sha1" ) else lisp . LISP_SHA_256_128_ALG_ID if ( iiiIi1 == "sha2" ) else ""
   if 98 - 98: o0oOOo0O0Ooo
   if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
  if ( IIi11i1i1iI1 == "authentication-key" ) :
   if ( OOooo == 0 ) : OOooo = lisp . LISP_SHA_256_128_ALG_ID
   OoO0o = lisp . lisp_parse_auth_key ( iiiIi1 )
   ii11IIII11I = OoO0o . keys ( ) [ 0 ]
   oOooOOOoOo = OoO0o [ ii11IIII11I ]
   if 78 - 78: oO0o % O0 % Ii1I
  if ( IIi11i1i1iI1 == "proxy-reply" ) :
   i1Iii1i1I = True if iiiIi1 == "yes" else False
   if 46 - 46: OoooooooOO . i11iIiiIii
  if ( IIi11i1i1iI1 == "merge-registrations" ) :
   OOoO00 = True if iiiIi1 == "yes" else False
   if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
  if ( IIi11i1i1iI1 == "refresh-registrations" ) :
   IiI111111IIII = True if iiiIi1 == "yes" else False
   if 87 - 87: Oo0Ooo . IiII
  if ( IIi11i1i1iI1 == "want-map-notify" ) :
   i1Ii = True if iiiIi1 == "yes" else False
   if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
  if ( IIi11i1i1iI1 == "site-id" ) :
   ii111iI1iIi1 = int ( iiiIi1 )
   if 55 - 55: OOooOOo . I1IiiI
  if ( IIi11i1i1iI1 == "encryption-key" ) :
   oo0OOo0 = lisp . lisp_parse_auth_key ( iiiIi1 )
   OOO = oo0OOo0 . keys ( ) [ 0 ]
   oo0OOo0 = oo0OOo0 [ OOO ]
   if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
   if 100 - 100: I1Ii111 * O0
   if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
   if 79 - 79: O0
   if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
   if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 i1II1 = None
 for II1i1IiiIIi11 in IIi1I11I1II :
  if ( II1i1IiiIIi11 == "" ) : continue
  i1II1 = lisp . lisp_ms ( II1i1IiiIIi11 , None , OoO0O0 , OOooo , ii11IIII11I , oOooOOOoOo ,
 i1Iii1i1I , OOoO00 , IiI111111IIII , i1Ii , ii111iI1iIi1 , OOO , oo0OOo0 )
  if 57 - 57: OoO0O00 / ooOoO0o
 for Ii1I1Ii in OooOoooOo :
  if ( Ii1I1Ii == "" ) : continue
  i1II1 = lisp . lisp_ms ( None , Ii1I1Ii , OoO0O0 , OOooo , ii11IIII11I , oOooOOOoOo ,
 i1Iii1i1I , OOoO00 , IiI111111IIII , i1Ii , ii111iI1iIi1 , OOO , oo0OOo0 )
  if 69 - 69: I1IiiI / o0oOOo0O0Ooo . IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
  if 13 - 13: Ii1I . i11iIiiIii
  if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
  if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
  if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
  if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 O0oO = ( len ( lisp . lisp_map_servers_list ) == 1 )
 if ( O0oO ) :
  i1II1 = lisp . lisp_map_servers_list . values ( ) [ 0 ]
  Ii1iI = threading . Timer ( 2 , OO0ooOOO0OOO ,
 [ i1II1 . map_server ] )
  Ii1iI . start ( )
 else :
  if 63 - 63: OoOoOO00 * iII111i
  if 69 - 69: O0 . OoO0O00
  if 49 - 49: I1IiiI - I11i
  if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
  if 62 - 62: OoooooooOO * I1IiiI
  if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
  if 97 - 97: O0 + OoOoOO00
  if ( lisp . lisp_nat_traversal ) : return
  if ( i1II1 and len ( lisp . lisp_db_list ) > 0 ) :
   OO0O000 ( o0oOoO00o , None , None , i1II1 , False )
   if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
   if 77 - 77: OOooOOo * iIii1I11I1II1
   if 98 - 98: I1IiiI % Ii1I * OoooooooOO
   if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
   if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
   if 71 - 71: Oo0Ooo % OOooOOo
   if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if ( len ( lisp . lisp_db_list ) > 0 ) :
  if ( OOO0o0o != None and
 OOO0o0o . is_alive ( ) ) : return
  if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
  OOO0o0o = threading . Timer ( 5 ,
 oO , [ o0oOoO00o ] )
  OOO0o0o . start ( )
  if 69 - 69: I1Ii111
 return
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
 if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
 if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
 if 71 - 71: I1Ii111 + Ii1I
 if 28 - 28: OOooOOo
 if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
def OoOOo0OOoO ( kv_pairs ) :
 oooooOoo0ooo = [ ]
 ooO0O00Oo0o = None
 OOOOo0o00OO0000 = None
 OoO0O0 = "all"
 if 1 - 1: ooOoO0o . ooOoO0o / OoOoOO00 - I1Ii111
 for IIi11i1i1iI1 in kv_pairs . keys ( ) :
  iiiIi1 = kv_pairs [ IIi11i1i1iI1 ]
  if ( IIi11i1i1iI1 == "group-name" ) :
   oooO = iiiIi1
   if 26 - 26: Ii1I % I1ii11iIi11i
  if ( IIi11i1i1iI1 == "group-prefix" ) :
   if ( ooO0O00Oo0o == None ) :
    ooO0O00Oo0o = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 76 - 76: IiII * iII111i
   ooO0O00Oo0o . store_prefix ( iiiIi1 )
   if 52 - 52: OOooOOo
  if ( IIi11i1i1iI1 == "instance-id" ) :
   if ( ooO0O00Oo0o == None ) :
    ooO0O00Oo0o = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 19 - 19: I1IiiI
   ooO0O00Oo0o . instance_id = int ( iiiIi1 )
   if 25 - 25: Ii1I / ooOoO0o
  if ( IIi11i1i1iI1 == "ms-name" ) :
   OoO0O0 = iiiIi1 [ 0 ]
   if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
  if ( IIi11i1i1iI1 == "address" ) :
   for o0o in iiiIi1 :
    if ( o0o != "" ) : oooooOoo0ooo . append ( o0o )
    if 62 - 62: OoooooooOO . I11i
    if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
  if ( IIi11i1i1iI1 == "rle-address" ) :
   if ( OOOOo0o00OO0000 == None ) :
    OOOOo0o00OO0000 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
   OOOOo0o00OO0000 . store_address ( iiiIi1 )
   if 58 - 58: I1IiiI
   if 53 - 53: i1IIi
 ii1ii1ii = lisp . lisp_group_mapping ( oooO , OoO0O0 , ooO0O00Oo0o , oooooOoo0ooo ,
 OOOOo0o00OO0000 )
 ii1ii1ii . add_group ( )
 return
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
 if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 if 23 - 23: i11iIiiIii
 if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
def o0ooooO0o0O ( quiet , db , eid , group , ttl ) :
 if 24 - 24: O0 * o0oOOo0O0Ooo
 if 29 - 29: I1IiiI % OOooOOo - I1IiiI / OOooOOo . i1IIi
 if 31 - 31: I1Ii111
 if 88 - 88: OoO0O00 - ooOoO0o + OOooOOo * I1IiiI % iIii1I11I1II1 + Oo0Ooo
 if 76 - 76: I1IiiI * iII111i % I1Ii111
 if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
 if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
 if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
 oOoOOo0O = { }
 for OOOooo in db . rloc_set :
  if ( OOOooo . translated_rloc . is_null ( ) ) : continue
  if 94 - 94: OoooooooOO + Oo0Ooo / OoOoOO00 * OOooOOo
  for o0OOo0o0O0O in lisp . lisp_rtr_list :
   o0 = lisp . lisp_rtr_list [ o0OOo0o0O0O ]
   if ( lisp . lisp_register_all_rtrs == False and o0 == None ) :
    lisp . lprint ( "  Exclude unreachable RTR {}" . format ( lisp . red ( o0OOo0o0O0O , False ) ) )
    if 95 - 95: OoO0O00 % i1IIi * i11iIiiIii % Oo0Ooo - oO0o
    continue
    if 67 - 67: OoOoOO00 + I1ii11iIi11i . o0oOOo0O0Ooo . II111iiii
   if ( o0 == None ) : continue
   oOoOOo0O [ o0OOo0o0O0O ] = o0
   if 98 - 98: iII111i
  break
  if 68 - 68: iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
  if 38 - 38: ooOoO0o - OOooOOo / iII111i
 OoOOoooOO0O = 0
 ooo00Ooo = ""
 for Oo0o0O00 in [ eid . instance_id ] + eid . iid_list :
  ii1 = lisp . lisp_eid_record ( )
  if 39 - 39: Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * iII111i + I1IiiI
  ii1 . rloc_count = len ( db . rloc_set ) + len ( oOoOOo0O )
  ii1 . authoritative = True
  ii1 . record_ttl = ttl
  ii1 . eid . copy_address ( eid )
  ii1 . eid . instance_id = Oo0o0O00
  ii1 . eid . iid_list = [ ]
  ii1 . group . copy_address ( group )
  if 77 - 77: Ii1I + II111iiii . OoOoOO00 * I1Ii111 + OOooOOo + OOooOOo
  ooo00Ooo += ii1 . encode ( )
  if ( not quiet ) :
   I1ii1I1iiii = lisp . lisp_print_eid_tuple ( eid , group )
   iiI = ""
   if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
    iiI = lisp . lisp_get_decent_index ( eid )
    iiI = lisp . bold ( str ( iiI ) , False )
    iiI = ", decent-index {}" . format ( iiI )
    if 56 - 56: Oo0Ooo . I1ii11iIi11i . I1IiiI
   lisp . lprint ( "  EID-prefix {} for ms-name '{}'{}" . format ( lisp . green ( I1ii1I1iiii , False ) , db . use_ms_name , iiI ) )
   if 39 - 39: O0 + I1Ii111
   ii1 . print_record ( "  " , False )
   if 91 - 91: OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoOoOO00 + O0
   if 26 - 26: I1ii11iIi11i - OoooooooOO
  for OOOooo in db . rloc_set :
   iiI1iI111ii1i = lisp . lisp_rloc_record ( )
   iiI1iI111ii1i . store_rloc_entry ( OOOooo )
   iiI1iI111ii1i . local_bit = OOOooo . rloc . is_local ( )
   iiI1iI111ii1i . reach_bit = True
   ooo00Ooo += iiI1iI111ii1i . encode ( )
   if ( not quiet ) : iiI1iI111ii1i . print_record ( "    " )
   if 32 - 32: II111iiii * OoOoOO00 % i1IIi - iII111i + iIii1I11I1II1 + I1ii11iIi11i
   if 60 - 60: I1ii11iIi11i % OoOoOO00 * OoO0O00 % II111iiii
   if 70 - 70: OoO0O00 % oO0o + OOooOOo / Ii1I % O0
   if 100 - 100: o0oOOo0O0Ooo + OOooOOo * o0oOOo0O0Ooo
   if 80 - 80: o0oOOo0O0Ooo * O0 - Ii1I
   if 66 - 66: i11iIiiIii - OOooOOo * Oo0Ooo
  for o0 in oOoOOo0O . values ( ) :
   iiI1iI111ii1i = lisp . lisp_rloc_record ( )
   iiI1iI111ii1i . rloc . copy_address ( o0 )
   iiI1iI111ii1i . priority = 254
   iiI1iI111ii1i . rloc_name = "RTR"
   iiI1iI111ii1i . weight = 0
   iiI1iI111ii1i . mpriority = 255
   iiI1iI111ii1i . mweight = 0
   iiI1iI111ii1i . local_bit = False
   iiI1iI111ii1i . reach_bit = True
   ooo00Ooo += iiI1iI111ii1i . encode ( )
   if ( not quiet ) : iiI1iI111ii1i . print_record ( "    RTR " )
   if 76 - 76: i11iIiiIii + o0oOOo0O0Ooo / I1ii11iIi11i - OoO0O00 - Ii1I + I1ii11iIi11i
   if 51 - 51: iIii1I11I1II1 . ooOoO0o + iIii1I11I1II1
   if 95 - 95: I1IiiI
   if 46 - 46: OoOoOO00 + OoO0O00
   if 70 - 70: iII111i / iIii1I11I1II1
  OoOOoooOO0O += 1
  if 85 - 85: OoooooooOO % i1IIi * OoooooooOO / I1ii11iIi11i
 return ( ooo00Ooo , OoOOoooOO0O )
 if 96 - 96: OoooooooOO + oO0o
 if 44 - 44: oO0o
 if 20 - 20: I11i + Ii1I / O0 % iIii1I11I1II1
 if 88 - 88: OoOoOO00 / II111iiii
 if 87 - 87: I1ii11iIi11i - I1ii11iIi11i - iII111i + oO0o
 if 82 - 82: oO0o / iIii1I11I1II1 . I1IiiI . OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
def OO0O000 ( lisp_sockets , ttl , eid_only , ms_only , refresh ) :
 if 46 - 46: Oo0Ooo
 if 1 - 1: iII111i
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
 if ( eid_only != None ) :
  IIii11I1i1I = 1
 else :
  IIii11I1i1I = lisp . lisp_db_list_length ( )
  if ( IIii11I1i1I == 0 ) : return
  if 99 - 99: iII111i
  if 76 - 76: OoO0O00 * I1IiiI
 lisp . lprint ( "Build Map-Register for {} database-mapping entries" . format ( IIii11I1i1I ) )
 if 82 - 82: Ii1I * iII111i / I1ii11iIi11i
 if 36 - 36: OoooooooOO - i1IIi . O0 / II111iiii + o0oOOo0O0Ooo
 if 33 - 33: II111iiii / ooOoO0o * O0 % Ii1I * I1Ii111
 if 100 - 100: IiII . I11i / Ii1I % OoOoOO00 % II111iiii - OoO0O00
 if 46 - 46: O0 * II111iiii - Oo0Ooo * ooOoO0o
 i11IIIiIiIi = lisp . lisp_decent_pull_xtr_configured ( )
 if 27 - 27: I1ii11iIi11i + OoOoOO00 - OOooOOo + O0 . Ii1I
 if 46 - 46: IiII
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 i1iI1 = ( IIii11I1i1I > 12 )
 if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
 OooO0oo = { }
 if ( i11IIIiIiIi ) :
  if 89 - 89: Ii1I
  if 76 - 76: ooOoO0o
  if 15 - 15: OOooOOo . I11i + OoooooooOO - OoO0O00
  if 69 - 69: iIii1I11I1II1 . I1ii11iIi11i % ooOoO0o + iIii1I11I1II1 / O0 / I1ii11iIi11i
  if 61 - 61: OOooOOo % OOooOOo * o0oOOo0O0Ooo / o0oOOo0O0Ooo
  for o0oOO in lisp . lisp_db_list :
   O0o0OO0000ooo = o0oOO . eid if o0oOO . group . is_null ( ) else o0oOO . group
   iIIII1iIIii = lisp . lisp_get_decent_dns_name ( O0o0OO0000ooo )
   OooO0oo [ iIIII1iIIii ] = [ ]
   if 52 - 52: o0oOOo0O0Ooo % Oo0Ooo
 else :
  if 64 - 64: O0 % I11i % O0 * OoO0O00 . oO0o + I1IiiI
  if 75 - 75: I11i . OoooooooOO % o0oOOo0O0Ooo * I11i % OoooooooOO
  if 13 - 13: IiII / i11iIiiIii % II111iiii % I11i . I1ii11iIi11i
  if 8 - 8: OoOoOO00 + Oo0Ooo - II111iiii
  if 11 - 11: i1IIi % i11iIiiIii - i1IIi * OoOoOO00
  for i1II1 in lisp . lisp_map_servers_list . values ( ) :
   if ( ms_only != None and i1II1 != ms_only ) : continue
   OooO0oo [ i1II1 . ms_name ] = [ ]
   if 39 - 39: I1Ii111
   if 86 - 86: I11i * I1IiiI + I11i + II111iiii
   if 8 - 8: I1Ii111 - iII111i / ooOoO0o
   if 96 - 96: OoOoOO00
   if 29 - 29: I1ii11iIi11i / i1IIi . I1IiiI - OoOoOO00 - OoOoOO00 - Ii1I
   if 20 - 20: i1IIi % OoO0O00 . I1IiiI / IiII * i11iIiiIii * OOooOOo
 OOo = lisp . lisp_map_register ( )
 OOo . nonce = 0xaabbccdddfdfdf00
 OOo . xtr_id_present = True
 if 50 - 50: ooOoO0o
 if ( ttl == None ) : ttl = lisp . LISP_REGISTER_TTL
 if 72 - 72: I1Ii111
 if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
 if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
 if 74 - 74: O0 / i1IIi
 for o0oOO in lisp . lisp_db_list :
  if ( i11IIIiIiIi ) :
   OoO = lisp . lisp_get_decent_dns_name ( o0oOO . eid )
  else :
   OoO = o0oOO . use_ms_name
   if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
   if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
   if 100 - 100: OoO0O00
   if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
   if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
   if 45 - 45: I1Ii111
  if ( OooO0oo . has_key ( OoO ) == False ) : continue
  if 83 - 83: OoOoOO00 . OoooooooOO
  Oo0ooo = OooO0oo [ OoO ]
  if ( Oo0ooo == [ ] ) :
   Oo0ooo = [ "" , 0 ]
   OooO0oo [ OoO ] . append ( Oo0ooo )
  else :
   Oo0ooo = OooO0oo [ OoO ] [ - 1 ]
   if 28 - 28: oO0o . II111iiii / I1ii11iIi11i + II111iiii . OoooooooOO . IiII
   if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
   if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
   if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
   if 92 - 92: ooOoO0o
   if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
   if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
   if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
   if 92 - 92: I11i . I1Ii111
   if 85 - 85: I1ii11iIi11i . I1Ii111
  ooo00Ooo = ""
  if ( o0oOO . dynamic_eid_configured ( ) ) :
   for O0O0Ooooo000 in o0oOO . dynamic_eids . values ( ) :
    O0o0OO0000ooo = O0O0Ooooo000 . dynamic_eid
    if ( eid_only == None or eid_only . is_exact_match ( O0o0OO0000ooo ) ) :
     o000oOoo0o000 , OoOOoooOO0O = o0ooooO0o0O ( i1iI1 , o0oOO ,
 O0o0OO0000ooo , o0oOO . group , ttl )
     ooo00Ooo += o000oOoo0o000
     Oo0ooo [ 1 ] += OoOOoooOO0O
     if 40 - 40: i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - I11i . i1IIi
     if 99 - 99: O0 * I11i
  else :
   if ( eid_only == None ) :
    ooo00Ooo , OoOOoooOO0O = o0ooooO0o0O ( i1iI1 , o0oOO ,
 o0oOO . eid , o0oOO . group , ttl )
    Oo0ooo [ 1 ] += OoOOoooOO0O
    if 64 - 64: II111iiii + O0 / iIii1I11I1II1 / Oo0Ooo . ooOoO0o % IiII
    if 50 - 50: iIii1I11I1II1 - IiII + OOooOOo
    if 69 - 69: O0
    if 85 - 85: ooOoO0o / O0
    if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
    if 62 - 62: I1Ii111 . IiII . OoooooooOO
  Oo0ooo [ 0 ] += ooo00Ooo
  if 11 - 11: OOooOOo / I11i
  if ( Oo0ooo [ 1 ] == 20 ) :
   Oo0ooo = [ "" , 0 ]
   OooO0oo [ OoO ] . append ( Oo0ooo )
   if 73 - 73: i1IIi / i11iIiiIii
   if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
   if 85 - 85: OoOoOO00 + OOooOOo
   if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
   if 27 - 27: Ii1I
   if 67 - 67: I1IiiI
 for i1II1 in lisp . lisp_map_servers_list . values ( ) :
  if ( ms_only != None and i1II1 != ms_only ) : continue
  if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
  OoO = i1II1 . dns_name if i11IIIiIiIi else i1II1 . ms_name
  if ( OooO0oo . has_key ( OoO ) == False ) : continue
  if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
  for Oo0ooo in OooO0oo [ OoO ] :
   if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
   if 92 - 92: Oo0Ooo
   if 40 - 40: OoOoOO00 / IiII
   if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
   OOo . record_count = Oo0ooo [ 1 ]
   if ( OOo . record_count == 0 ) : continue
   if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
   OOo . nonce += 1
   OOo . alg_id = i1II1 . alg_id
   OOo . key_id = i1II1 . key_id
   OOo . proxy_reply_requested = i1II1 . proxy_reply
   OOo . merge_register_requested = i1II1 . merge_registrations
   OOo . map_notify_requested = i1II1 . want_map_notify
   OOo . xtr_id = i1II1 . xtr_id
   OOo . site_id = i1II1 . site_id
   OOo . encrypt_bit = ( i1II1 . ekey != None )
   if ( i1II1 . refresh_registrations ) :
    OOo . map_register_refresh = refresh
    if 61 - 61: II111iiii
   if ( i1II1 . ekey != None ) : OOo . encryption_key_id = i1II1 . ekey_id
   Ii1ii111i1 = OOo . encode ( )
   OOo . print_map_register ( )
   if 31 - 31: OOooOOo + O0
   if 87 - 87: ooOoO0o
   if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
   if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
   if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
   iIi1II = OOo . encode_xtr_id ( "" )
   ooo00Ooo = Oo0ooo [ 0 ]
   Ii1ii111i1 = Ii1ii111i1 + ooo00Ooo + iIi1II
   if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
   i1II1 . map_registers_sent += 1
   lisp . lisp_send_map_register ( lisp_sockets , Ii1ii111i1 , OOo , i1II1 )
   time . sleep ( .001 )
   if 41 - 41: Ii1I
   if 77 - 77: I1Ii111
   if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
   if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
   if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
  i1II1 . resolve_dns_name ( )
  if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
  if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
  if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
  if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
  if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
  if ( ms_only != None and i1II1 == ms_only ) : break
  if 95 - 95: IiII
 return
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
 if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 if 59 - 59: OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
def OO0ooOOO0OOO ( ms ) :
 global Ii1iI
 global Oo
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 lisp . lisp_set_exception ( )
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 ii = [ Oo , Oo , Ooo ]
 lisp . lisp_build_info_requests ( ii , ms , lisp . LISP_CTRL_PORT )
 if 81 - 81: O0 % Ii1I
 if 5 - 5: OoooooooOO - OoO0O00 + IiII - iII111i . OoO0O00 / ooOoO0o
 if 28 - 28: Ii1I * Ii1I - iIii1I11I1II1
 if 70 - 70: I1Ii111
 if 16 - 16: iII111i - OoooooooOO % Oo0Ooo
 i11i1iIiii = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) == None )
 for o0 in lisp . lisp_rtr_list . values ( ) :
  if ( o0 == None ) : continue
  if ( o0 . is_private_address ( ) and i11i1iIiii == False ) :
   OOO00OO0oOo = lisp . red ( o0 . print_address_no_iid ( ) , False )
   lisp . lprint ( "Skip over RTR private address {}" . format ( OOO00OO0oOo ) )
   continue
   if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
  lisp . lisp_build_info_requests ( ii , o0 , lisp . LISP_DATA_PORT )
  if 87 - 87: OoOoOO00
  if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
  if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
  if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
  if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
  if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
 Ii1iI . cancel ( )
 Ii1iI = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 OO0ooOOO0OOO , [ None ] )
 Ii1iI . start ( )
 return
 if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
 if 93 - 93: Ii1I - OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
 if 49 - 49: OoooooooOO * I11i - Oo0Ooo . oO0o
 if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
 if 46 - 46: OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
def oO ( lisp_sockets ) :
 global Oo0o
 global Oo
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 lisp . lisp_set_exception ( )
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 OO0O000 ( lisp_sockets , None , None , None , True )
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if ( lisp . lisp_l2_overlay ) :
  IIiiii = [ None , "ffff-ffff-ffff" , True ]
  iI111i1I1II ( lisp_sockets , [ IIiiii ] )
  if 96 - 96: I1Ii111 / Oo0Ooo * II111iiii - iII111i * Oo0Ooo
  if 81 - 81: IiII . o0oOOo0O0Ooo / I1Ii111
  if 17 - 17: i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + I11i - ooOoO0o
  if 78 - 78: I11i * OoOoOO00 . O0 / O0
  if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 if ( Oo0o ) : Oo0o . cancel ( )
 Oo0o = threading . Timer ( I11 ,
 oO , [ o0oOoO00o ] )
 Oo0o . start ( )
 return
 if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
 if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
 if 91 - 91: oO0o + OoooooooOO - i1IIi
 if 84 - 84: Ii1I / IiII
 if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if 37 - 37: i11iIiiIii + i1IIi
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
def iI111i1I1II ( lisp_sockets , entries ) :
 iiIII1II = len ( entries )
 if ( iiIII1II == 0 ) : return
 if 100 - 100: Oo0Ooo % Ii1I / I11i
 iIII11Ii = None
 if ( entries [ 0 ] [ 1 ] . find ( ":" ) != - 1 ) : iIII11Ii = lisp . LISP_AFI_IPV6
 if ( entries [ 0 ] [ 1 ] . find ( "." ) != - 1 ) : iIII11Ii = lisp . LISP_AFI_IPV4
 if ( entries [ 0 ] [ 1 ] . find ( "-" ) != - 1 ) : iIII11Ii = lisp . LISP_AFI_MAC
 if ( iIII11Ii == None ) :
  lisp . lprint ( "lisp_send_multicast_map_register() invalid group address" )
  return
  if 52 - 52: I1Ii111 / ooOoO0o - I11i
  if 49 - 49: OoOoOO00 / Oo0Ooo . i11iIiiIii
  if 21 - 21: OoOoOO00 + i11iIiiIii + I1IiiI * o0oOOo0O0Ooo % iII111i % II111iiii
  if 55 - 55: Oo0Ooo - OOooOOo
  if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
  if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 o00O = [ ]
 for o0o , i1i , IIi in entries :
  if ( o0o != None ) : continue
  o00O . append ( [ i1i , IIi ] )
  if 58 - 58: II111iiii
  if 19 - 19: I1ii11iIi11i - I11i . II111iiii - OoO0O00 . IiII * OoooooooOO
 i11IIIiIiIi = lisp . lisp_decent_pull_xtr_configured ( )
 if 84 - 84: iII111i % OOooOOo / I11i / I1IiiI
 OooO0oo = { }
 entries = [ ]
 for i1i , IIi in o00O :
  IIii = lisp . lisp_lookup_group ( i1i )
  if ( IIii == None ) :
   lisp . lprint ( "No group-mapping for {}, could be underlay group" . format ( i1i ) )
   if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
   continue
   if 51 - 51: OoOoOO00
   if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
  lisp . lprint ( "Use group-mapping '{}' {} for group {}" . format ( IIii . group_name , IIii . group_prefix . print_prefix ( ) , i1i ) )
  if 53 - 53: Ii1I % Oo0Ooo
  Oo0o0O00 = IIii . group_prefix . instance_id
  OoO0O0 = IIii . use_ms_name
  O0ooOo0o0Oo = IIii . rle_address
  if 71 - 71: iIii1I11I1II1 - OOooOOo . I1IiiI % OoooooooOO + OOooOOo
  if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
  if 31 - 31: I11i % OOooOOo * I11i
  if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
  if 1 - 1: iIii1I11I1II1
  if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
  O0O00OOo = OoO0O0
  if ( i11IIIiIiIi ) :
   O0O00OOo = lisp . lisp_get_decent_dns_name_from_str ( Oo0o0O00 , i1i )
   OooO0oo [ O0O00OOo ] = [ "" , 0 ]
   if 66 - 66: i11iIiiIii / o0oOOo0O0Ooo - OoooooooOO / i1IIi . i11iIiiIii
   if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
  if ( len ( IIii . sources ) == 0 ) :
   entries . append ( [ "0.0.0.0" , i1i , Oo0o0O00 , O0O00OOo , O0ooOo0o0Oo , IIi ] )
   continue
   if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
  for I1I1IiI1 in IIii . sources :
   OooO0oo [ O0O00OOo ] = [ "" , 0 ]
   entries . append ( [ I1I1IiI1 , i1i , Oo0o0O00 , O0O00OOo , O0ooOo0o0Oo , IIi ] )
   if 81 - 81: iII111i * OOooOOo - I1ii11iIi11i * Ii1I % OoOoOO00 * OoOoOO00
   if 59 - 59: iIii1I11I1II1
   if 7 - 7: OOooOOo * I1IiiI / o0oOOo0O0Ooo * i11iIiiIii
 iiIII1II = len ( entries )
 if ( iiIII1II == 0 ) : return
 if 84 - 84: OOooOOo . iII111i
 lisp . lprint ( "Build Map-Register for {} multicast entries" . format ( iiIII1II ) )
 if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
 if 21 - 21: oO0o / OoooooooOO
 if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
 if 87 - 87: I1Ii111 * i1IIi / I1ii11iIi11i
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo - OoooooooOO % OOooOOo * OoOoOO00
 if 69 - 69: i1IIi
 ooOoOOOOo = lisp . lisp_rle_node ( )
 ooOoOOOOo . level = 128
 ooooOooooOOo = lisp . lisp_get_any_translated_rloc ( )
 O0ooOo0o0Oo = lisp . lisp_rle ( "" )
 O0ooOo0o0Oo . rle_nodes . append ( ooOoOOOOo )
 if 96 - 96: iII111i
 if 18 - 18: iII111i * I11i - Ii1I
 if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if ( i11IIIiIiIi == False ) :
  for i1II1 in lisp . lisp_map_servers_list . values ( ) :
   OooO0oo [ i1II1 . ms_name ] = [ "" , 0 ]
   if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
   if 23 - 23: II111iiii / oO0o
   if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 iI11iiii1I = None
 if ( lisp . lisp_nat_traversal ) : iI11iiii1I = lisp . lisp_hostname
 if 3 - 3: O0 % OoooooooOO / OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 OOooo00 = 0
 for o0 in lisp . lisp_rtr_list . values ( ) :
  if ( o0 == None ) : continue
  OOooo00 += 1
  if 35 - 35: I1Ii111 . OoOoOO00 * i11iIiiIii
  if 44 - 44: i11iIiiIii / Oo0Ooo
  if 42 - 42: OoooooooOO + Oo0Ooo % II111iiii + OoO0O00
  if 24 - 24: iII111i * II111iiii % iII111i % IiII + OoooooooOO
  if 29 - 29: II111iiii - OoooooooOO - i11iIiiIii . o0oOOo0O0Ooo
 ooo00Ooo = ""
 for o0o , i1i , Oo0o0O00 , OoO , i11ii , IIi in entries :
  if 50 - 50: Ii1I / OoOoOO00 * Ii1I
  if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
  if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
  if 32 - 32: i11iIiiIii - I1Ii111
  if ( OooO0oo . has_key ( OoO ) == False ) : continue
  if 53 - 53: OoooooooOO - IiII
  ii1 = lisp . lisp_eid_record ( )
  ii1 . rloc_count = 1 + OOooo00
  ii1 . authoritative = True
  ii1 . record_ttl = lisp . LISP_REGISTER_TTL if IIi else 0
  ii1 . eid = lisp . lisp_address ( iIII11Ii , o0o , 0 , Oo0o0O00 )
  if ( ii1 . eid . address == 0 ) : ii1 . eid . mask_len = 0
  ii1 . group = lisp . lisp_address ( iIII11Ii , i1i , 0 , Oo0o0O00 )
  if ( ii1 . group . is_mac_broadcast ( ) and ii1 . eid . address == 0 ) : ii1 . eid . mask_len = 0
  if 87 - 87: oO0o . I1IiiI
  if 17 - 17: Ii1I . i11iIiiIii
  iiI = ""
  OoO0O0 = ""
  if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
   iiI = lisp . lisp_get_decent_index ( ii1 . group )
   iiI = lisp . bold ( str ( iiI ) , False )
   iiI = "with decent-index {}" . format ( iiI )
  else :
   iiI = "for ms-name '{}'" . format ( OoO )
   if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
   if 63 - 63: oO0o
  Oo0 = lisp . green ( ii1 . print_eid_tuple ( ) , False )
  lisp . lprint ( "  EID-prefix {} {}{}" . format ( Oo0 , OoO0O0 ,
 iiI ) )
  if 79 - 79: OoO0O00 % OOooOOo / iIii1I11I1II1 + OoOoOO00 * OoO0O00
  ooo00Ooo += ii1 . encode ( )
  ii1 . print_record ( "  " , False )
  OooO0oo [ OoO ] [ 1 ] += 1
  if 30 - 30: OoooooooOO / I11i + iII111i / I1ii11iIi11i * O0
  if 16 - 16: Oo0Ooo / i11iIiiIii
  if 64 - 64: i11iIiiIii / Ii1I * i1IIi
  if 73 - 73: Oo0Ooo - OoOoOO00 - oO0o - I1IiiI
  iiI1iI111ii1i = lisp . lisp_rloc_record ( )
  iiI1iI111ii1i . rloc_name = iI11iiii1I
  if 65 - 65: o0oOOo0O0Ooo
  if 7 - 7: IiII . OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - II111iiii
  if 37 - 37: I1Ii111 . OoOoOO00 / O0 * iII111i
  if 7 - 7: OoO0O00 * I11i + II111iiii % i11iIiiIii
  if 8 - 8: ooOoO0o * O0
  if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
  if ( ooooOooooOOo != None ) :
   ooOoOOOOo . address = ooooOooooOOo
  elif ( i11ii != None ) :
   ooOoOOOOo . address = i11ii
  else :
   ooOoOOOOo . address = i11ii = lisp . lisp_myrlocs [ 0 ]
   if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
   if 34 - 34: ooOoO0o
  iiI1iI111ii1i . rle = O0ooOo0o0Oo
  iiI1iI111ii1i . local_bit = True
  iiI1iI111ii1i . reach_bit = True
  iiI1iI111ii1i . priority = 255
  iiI1iI111ii1i . weight = 0
  iiI1iI111ii1i . mpriority = 1
  iiI1iI111ii1i . mweight = 100
  ooo00Ooo += iiI1iI111ii1i . encode ( )
  iiI1iI111ii1i . print_record ( "    " )
  if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
  if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
  if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
  if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
  if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
  for o0 in lisp . lisp_rtr_list . values ( ) :
   if ( o0 == None ) : continue
   iiI1iI111ii1i = lisp . lisp_rloc_record ( )
   iiI1iI111ii1i . rloc . copy_address ( o0 )
   iiI1iI111ii1i . priority = 254
   iiI1iI111ii1i . rloc_name = "RTR"
   iiI1iI111ii1i . weight = 0
   iiI1iI111ii1i . mpriority = 255
   iiI1iI111ii1i . mweight = 0
   iiI1iI111ii1i . local_bit = False
   iiI1iI111ii1i . reach_bit = True
   ooo00Ooo += iiI1iI111ii1i . encode ( )
   iiI1iI111ii1i . print_record ( "    RTR " )
   if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
   if 87 - 87: oO0o - i11iIiiIii
   if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
   if 23 - 23: I11i
   if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
  OooO0oo [ OoO ] [ 0 ] += ooo00Ooo
  if 14 - 14: I1ii11iIi11i
  if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
  if 56 - 56: OoooooooOO - I11i - i1IIi
  if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
  if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 OOo = lisp . lisp_map_register ( )
 OOo . nonce = 0xaabbccdddfdfdf00
 OOo . xtr_id_present = True
 OOo . proxy_reply_requested = True
 OOo . map_notify_requested = False
 OOo . merge_register_requested = True
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 for i1II1 in lisp . lisp_map_servers_list . values ( ) :
  O0O00OOo = i1II1 . dns_name if i11IIIiIiIi else i1II1 . ms_name
  if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
  if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
  if 93 - 93: i1IIi
  if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
  if ( OooO0oo . has_key ( O0O00OOo ) == False ) : continue
  if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
  if 66 - 66: Oo0Ooo
  if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
  if 55 - 55: o0oOOo0O0Ooo . iII111i
  OOo . record_count = OooO0oo [ O0O00OOo ] [ 1 ]
  if ( OOo . record_count == 0 ) : continue
  if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
  OOo . nonce += 1
  OOo . alg_id = i1II1 . alg_id
  OOo . alg_id = i1II1 . key_id
  OOo . xtr_id = i1II1 . xtr_id
  OOo . site_id = i1II1 . site_id
  OOo . encrypt_bit = ( i1II1 . ekey != None )
  Ii1ii111i1 = OOo . encode ( )
  OOo . print_map_register ( )
  if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
  if 89 - 89: OoO0O00 + IiII * I1Ii111
  if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
  if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
  if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
  iIi1II = OOo . encode_xtr_id ( "" )
  Ii1ii111i1 = Ii1ii111i1 + ooo00Ooo + iIi1II
  if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
  i1II1 . map_registers_multicast_sent += 1
  lisp . lisp_send_map_register ( lisp_sockets , Ii1ii111i1 , OOo , i1II1 )
  if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
  if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
  if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
  if 62 - 62: o0oOOo0O0Ooo
  i1II1 . resolve_dns_name ( )
  if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
  if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
  if 72 - 72: iIii1I11I1II1
  if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  time . sleep ( .001 )
  if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 return
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 if 84 - 84: i11iIiiIii * OoO0O00
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
def III1I ( parms , not_used , packet ) :
 global Ooo , o0oOoO00o
 if 11 - 11: ooOoO0o - OOooOOo + ooOoO0o * oO0o / I1IiiI
 OoOOOO = parms [ 0 ]
 i1 = parms [ 1 ]
 if 18 - 18: ooOoO0o % i11iIiiIii . iIii1I11I1II1 - iII111i
 if 80 - 80: I1IiiI + oO0o - i1IIi . Ii1I / o0oOOo0O0Ooo / I1IiiI
 if 1 - 1: I11i + i11iIiiIii - I1IiiI / OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if ( lisp . lisp_is_macos ( ) == False ) :
  i1iii11 = 4 if OoOOOO == "lo0" else 16
  packet = packet [ i1iii11 : : ]
  if 92 - 92: OoOoOO00 . OoooooooOO - I1Ii111
  if 74 - 74: iIii1I11I1II1 % iII111i * OOooOOo * iIii1I11I1II1
  if 73 - 73: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
  if 60 - 60: OoOoOO00
  if 5 - 5: I1IiiI - I1IiiI - I1IiiI * OoooooooOO
 iiiiiII = struct . unpack ( "B" , packet [ 9 ] ) [ 0 ]
 if ( iiiiiII == 2 ) :
  ii1ii = lisp . lisp_process_igmp_packet ( packet )
  if ( type ( ii1ii ) != bool ) :
   iI111i1I1II ( o0oOoO00o , ii1ii )
   return
   if 8 - 8: OoO0O00 + OoOoOO00 . iIii1I11I1II1 % O0
   if 43 - 43: I1ii11iIi11i - iII111i
   if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
   if 47 - 47: iII111i
   if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
   if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 iIii11iI1II = packet
 packet , o0o , I1II1I1I , OOo0 = lisp . lisp_is_rloc_probe ( packet , 0 )
 if ( iIii11iI1II != packet ) :
  if ( o0o == None ) : return
  lisp . lisp_parse_packet ( o0oOoO00o , packet , o0o , I1II1I1I , OOo0 )
  return
  if 58 - 58: OoOoOO00 - iII111i - OoooooooOO
  if 96 - 96: iIii1I11I1II1
  if 82 - 82: OoOoOO00 + O0 - IiII % oO0o * i11iIiiIii
  if 15 - 15: o0oOOo0O0Ooo
  if 39 - 39: OOooOOo / I1ii11iIi11i / I1IiiI * I1Ii111
  if 44 - 44: O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / O0 - I11i
  if 83 - 83: IiII * I11i / Oo0Ooo
 iIIIiI = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 if ( lisp . lisp_nat_traversal and iIIIiI == lisp . LISP_DATA_PORT ) : return
 packet = lisp . lisp_reassemble ( packet )
 if ( packet == None ) : return
 if 93 - 93: ooOoO0o . iIii1I11I1II1 % i11iIiiIii . OoOoOO00 % ooOoO0o + O0
 packet = lisp . lisp_packet ( packet )
 o0OOoOO = packet . decode ( True , Ooo , lisp . lisp_decap_stats )
 if ( o0OOoOO == None ) : return
 if 46 - 46: oO0o / iII111i - i1IIi
 if 51 - 51: Oo0Ooo - I1ii11iIi11i * I11i
 if 12 - 12: iIii1I11I1II1 % ooOoO0o % ooOoO0o
 if 78 - 78: IiII . OoOoOO00 . I11i
 packet . print_packet ( "Receive" , True )
 if 97 - 97: oO0o
 if 80 - 80: I1IiiI . Ii1I
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
 if 60 - 60: OoO0O00
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 81 - 81: OoOoOO00 % Ii1I
  o0o = packet . inner_source . print_address_no_iid ( )
  packet . strip_outer_headers ( )
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , o0o , iIIIiI )
  lisp . lisp_ipc ( packet , Ooo , "lisp-ms" )
  return
  if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
  if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
  if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
  if 71 - 71: IiII . I1Ii111 . OoO0O00
  if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
  if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
  if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
  if 29 - 29: O0 . I1Ii111
  if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
  if 70 - 70: I1Ii111 + oO0o
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  o00ooo0 = packet . packet [ 36 : : ]
  i1i1IiIi1 = o00ooo0 [ 28 : : ]
  OOo0 = - 1
  if ( lisp . lisp_is_rloc_probe_request ( i1i1IiIi1 [ 0 ] ) ) :
   OOo0 = struct . unpack ( "B" , o00ooo0 [ 8 ] ) [ 0 ] - 1
   if 22 - 22: I11i * O0 . II111iiii - OoO0O00
  o0o = packet . outer_source . print_address_no_iid ( )
  lisp . lisp_parse_packet ( o0oOoO00o , i1i1IiIi1 , o0o , 0 , OOo0 )
  return
  if 90 - 90: oO0o
  if 94 - 94: I11i / I1ii11iIi11i * I1Ii111 - OoOoOO00
  if 44 - 44: Ii1I % i11iIiiIii - iII111i * I1ii11iIi11i + Oo0Ooo * OOooOOo
  if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
  if 65 - 65: Oo0Ooo . OoooooooOO
  if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 55 - 55: iII111i - OoO0O00
  if 100 - 100: O0
  if 79 - 79: iIii1I11I1II1
  if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
  if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 11 - 11: i1IIi % OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
 if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
 packet . strip_outer_headers ( )
 iiII111iIII1Ii = lisp . bold ( "Forward" , False )
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
 iiIiII11i1 = False
 oOo00Ooo0o0 = packet . inner_dest . is_mac ( )
 if ( oOo00Ooo0o0 ) :
  packet . packet = lisp . lisp_mac_input ( packet . packet )
  if ( packet . packet == None ) : return
  iiII111iIII1Ii = lisp . bold ( "Bridge" , False )
 elif ( packet . inner_version == 4 ) :
  iiIiII11i1 , packet . packet = lisp . lisp_ipv4_input ( packet . packet )
  if ( packet . packet == None ) : return
  if ( iiIiII11i1 ) :
   ii1ii = lisp . lisp_process_igmp_packet ( packet . packet )
   if ( type ( ii1ii ) != bool ) :
    iI111i1I1II ( o0oOoO00o , ii1ii )
    return
    if 33 - 33: I11i
    if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
  packet . inner_ttl = packet . outer_ttl
 elif ( packet . inner_version == 6 ) :
  packet . packet = lisp . lisp_ipv6_input ( packet )
  if ( packet . packet == None ) : return
  packet . inner_ttl = packet . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
  if 21 - 21: OOooOOo
  if 6 - 6: IiII
  if 46 - 46: IiII + oO0o
  if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  o0oOO = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( o0oOO ) :
   o0oOO . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
   return
   if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
   if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
   if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
   if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
   if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
   if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
   if 24 - 24: OoOoOO00
   if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 28 - 28: I1IiiI
  if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
  if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
  if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
  if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 II1i1IiiIIi11 = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( iiII111iIII1Ii , lisp . green ( II1i1IiiIIi11 , False ) ,
 # II111iiii / ooOoO0o + i11iIiiIii % OoOoOO00 + OoooooooOO
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 93 - 93: ooOoO0o / OOooOOo * OoooooooOO - i11iIiiIii / I1IiiI
 if 13 - 13: I1ii11iIi11i / i11iIiiIii
 if 32 - 32: o0oOOo0O0Ooo + I1IiiI . I1Ii111
 if 41 - 41: OoOoOO00 . i11iIiiIii / I11i
 if 98 - 98: OoOoOO00 % II111iiii
 if ( oOo00Ooo0o0 ) :
  packet . bridge_l2_packet ( packet . inner_dest , o0oOO )
  return
  if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
  if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
  if 68 - 68: o0oOOo0O0Ooo
  if 20 - 20: I1Ii111 - I1Ii111
  if 37 - 37: IiII
  if 37 - 37: Oo0Ooo / IiII * O0
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( oOOoo00O0O , i1111 )
  return
  if 73 - 73: iII111i * iII111i / ooOoO0o
  if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
  if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
  if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
  if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 O0oOO0o = packet . get_raw_socket ( )
 if ( O0oOO0o == None ) : O0oOO0o = i1
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 packet . send_packet ( O0oOO0o , packet . inner_dest )
 return
 if 83 - 83: o0oOOo0O0Ooo
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if 48 - 48: iII111i + IiII
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 if 14 - 14: OOooOOo
 if 79 - 79: Ii1I
 if 76 - 76: iIii1I11I1II1
 if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
 if 93 - 93: OoooooooOO * Oo0Ooo
 if 10 - 10: I1Ii111 * OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i11iIiiIii
def i1I1i ( lisp_raw_socket , packet , source ) :
 global Ooo , o0oOoO00o
 if 22 - 22: Oo0Ooo % OoO0O00 - OoooooooOO * Oo0Ooo
 if 38 - 38: iIii1I11I1II1 / ooOoO0o
 if 13 - 13: iIii1I11I1II1
 if 77 - 77: i11iIiiIii - iIii1I11I1II1 / oO0o / ooOoO0o / OoO0O00
 ooo0O0o0OoOO = packet
 packet = lisp . lisp_packet ( packet [ 8 : : ] )
 if ( packet . lisp_header . decode ( ooo0O0o0OoOO ) == False ) : return
 if 9 - 9: OoO0O00
 if 60 - 60: I1Ii111
 if 98 - 98: ooOoO0o
 if 34 - 34: iIii1I11I1II1 * I11i * I11i / I1ii11iIi11i
 if 28 - 28: OoO0O00 - oO0o + OoOoOO00 + Ii1I / iIii1I11I1II1
 packet . outer_source = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , source ,
 lisp . LISP_IPV4_HOST_MASK_LEN , 0 )
 if 26 - 26: iIii1I11I1II1 - O0 . O0
 o0OOoOO = packet . decode ( False , Ooo ,
 lisp . lisp_decap_stats )
 if ( o0OOoOO == None ) : return
 if 68 - 68: OOooOOo + oO0o . O0 . Ii1I % i1IIi % OOooOOo
 if 50 - 50: IiII + o0oOOo0O0Ooo
 if 96 - 96: OoO0O00
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if ( lisp . lisp_flow_logging ) : packet . log_flow ( False )
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 packet . print_packet ( "Kernel-decap" , False )
 lisp . dprint ( packet . lisp_header . print_header ( " " ) )
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
  iIIIiI = packet . udp_sport
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , source , iIIIiI )
  lisp . lisp_ipc ( packet , Ooo , "lisp-ms" )
  return
  if 84 - 84: i1IIi
  if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
  if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
  if 81 - 81: IiII / OoOoOO00 * IiII . O0
  if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
  if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
  if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
  if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
  if 61 - 61: I1Ii111 - Ii1I % I1ii11iIi11i / ooOoO0o / iII111i + iIii1I11I1II1
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  o00ooo0 = packet . packet
  i1i1IiIi1 = o00ooo0 [ 28 : : ]
  OOo0 = - 1
  if ( lisp . lisp_is_rloc_probe_request ( i1i1IiIi1 [ 0 ] ) ) :
   OOo0 = struct . unpack ( "B" , o00ooo0 [ 8 ] ) [ 0 ] - 1
   if 87 - 87: I1Ii111 + ooOoO0o + O0 / i1IIi % IiII / I1Ii111
  lisp . lisp_parse_packet ( o0oOoO00o , i1i1IiIi1 , source , 0 , OOo0 )
  return
  if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
  if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
  if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
  if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
  if 80 - 80: OoooooooOO + IiII
  if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 43 - 43: Oo0Ooo . I1Ii111
  if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
  if 29 - 29: IiII . ooOoO0o - II111iiii
  if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
  if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  o0oOO = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( o0oOO ) :
   o0oOO . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
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
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
  if 96 - 96: OoooooooOO + IiII * O0
 II1i1IiiIIi11 = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 86 - 86: Ii1I
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( lisp . bold ( "NAT-Forward" , False ) , lisp . green ( II1i1IiiIIi11 , False ) ,
 # OOooOOo % iIii1I11I1II1
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 50 - 50: I1IiiI % iIii1I11I1II1 % OOooOOo
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if 69 - 69: OoOoOO00
 if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( oOOoo00O0O , i1111 )
  return
  if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
  if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
  if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
  if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
  if 88 - 88: o0oOOo0O0Ooo
 O0oOO0o = packet . get_raw_socket ( )
 if ( O0oOO0o == None ) : O0oOO0o = lisp_raw_socket
 if 1 - 1: OoooooooOO
 if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 packet . send_packet ( O0oOO0o , packet . inner_dest )
 return
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
def Iii ( group , joinleave ) :
 IIii = lisp . lisp_lookup_group ( group )
 if ( IIii == None ) : return
 if 35 - 35: IiII . OoooooooOO / OOooOOo
 O0OO0ooO00 = [ ]
 for I1I1IiI1 in IIii . sources :
  O0OO0ooO00 . append ( [ I1I1IiI1 , group , joinleave ] )
  if 83 - 83: iIii1I11I1II1
  if 63 - 63: OoooooooOO * OoO0O00 / I11i - oO0o . iIii1I11I1II1 + iII111i
 iI111i1I1II ( o0oOoO00o , O0OO0ooO00 )
 return
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
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
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
def o0oo0o00ooO00 ( ) :
 global o0oOoO00o
 if 37 - 37: OoO0O00 - I1ii11iIi11i . OoooooooOO . ooOoO0o + OoOoOO00 / Ii1I
 lisp . lisp_set_exception ( )
 if 15 - 15: IiII . i1IIi * OoOoOO00 % iIii1I11I1II1
 III11I1 = socket . htonl
 OOOO0o0O = [ III11I1 ( 0x46000020 ) , III11I1 ( 0x9fe60000 ) , III11I1 ( 0x0102d7cc ) ,
 III11I1 ( 0x0acfc15a ) , III11I1 ( 0xe00000fb ) , III11I1 ( 0x94040000 ) ]
 if 41 - 41: o0oOOo0O0Ooo + ooOoO0o
 Ii1ii111i1 = ""
 for O00O00OoO in OOOO0o0O : Ii1ii111i1 += struct . pack ( "I" , O00O00OoO )
 if 20 - 20: O0 - OoooooooOO - IiII + iIii1I11I1II1
 if 94 - 94: Ii1I . i1IIi
 if 71 - 71: iII111i + OoO0O00 - IiII . OoO0O00 . IiII + I1IiiI
 if 26 - 26: O0
 if 17 - 17: II111iiii
 while ( True ) :
  iiIiii = commands . getoutput ( "ls join-*" ) . replace ( "join-" , "" )
  iiIiii = iiIiii . split ( "\n" )
  if 39 - 39: I1IiiI + Oo0Ooo
  for i1i in iiIiii :
   if ( lisp . lisp_valid_address_format ( "address" , i1i ) == False ) :
    continue
    if 83 - 83: i1IIi
    if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
   i1i1 = ( i1i . find ( ":" ) != - 1 )
   if 68 - 68: Ii1I - I1IiiI
   if 41 - 41: oO0o
   if 21 - 21: ooOoO0o + o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + II111iiii
   if 98 - 98: I1Ii111
   IIIIIIi1IiIi = os . path . exists ( "leave-{}" . format ( i1i ) )
   lisp . lprint ( "Internal {} group {}" . format ( "leaving" if IIIIIIi1IiIi else "joining" , i1i ) )
   if 14 - 14: OoO0O00 / ooOoO0o - OOooOOo / I1IiiI
   if 27 - 27: i1IIi + I1IiiI * I1ii11iIi11i + OOooOOo . oO0o
   if 1 - 1: OOooOOo * IiII + I11i
   if 77 - 77: oO0o % i11iIiiIii . OOooOOo % OOooOOo
   if 36 - 36: Oo0Ooo % Ii1I / i11iIiiIii % I1Ii111 + OoO0O00
   if ( i1i1 ) :
    if ( i1i . lower ( ) . find ( "ff02:" ) != - 1 ) :
     lisp . lprint ( "Suppress registration for link-local groups" )
     continue
     if 23 - 23: II111iiii
    Iii ( i1i , ( IIIIIIi1IiIi == False ) )
   else :
    oOo = Ii1ii111i1
    if ( IIIIIIi1IiIi ) :
     oOo += struct . pack ( "I" , III11I1 ( 0x17000000 ) )
    else :
     oOo += struct . pack ( "I" , III11I1 ( 0x16000000 ) )
     if 72 - 72: Oo0Ooo + II111iiii
     if 91 - 91: OoooooooOO / Oo0Ooo % I1ii11iIi11i * I1ii11iIi11i + OOooOOo
    OooooOoO = i1i . split ( "." )
    iiiIi1 = int ( OooooOoO [ 0 ] ) << 24
    iiiIi1 += int ( OooooOoO [ 1 ] ) << 16
    iiiIi1 += int ( OooooOoO [ 2 ] ) << 8
    iiiIi1 += int ( OooooOoO [ 3 ] )
    oOo += struct . pack ( "I" , III11I1 ( iiiIi1 ) )
    O0OO0ooO00 = lisp . lisp_process_igmp_packet ( oOo )
    if ( type ( O0OO0ooO00 ) != bool ) :
     iI111i1I1II ( o0oOoO00o , O0OO0ooO00 )
     if 79 - 79: ooOoO0o % OOooOOo
    time . sleep ( .100 )
    if 54 - 54: OoOoOO00 - I1Ii111
    if 65 - 65: I1Ii111 . ooOoO0o + OOooOOo / Oo0Ooo + IiII % i1IIi
  time . sleep ( 10 )
  if 28 - 28: i11iIiiIii + O0 / I1ii11iIi11i
 return
 if 3 - 3: OoO0O00 * i1IIi . I1IiiI . O0 - OoOoOO00
 if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
 if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
 if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
 if 10 - 10: I1ii11iIi11i / i11iIiiIii - Ii1I + oO0o * I1IiiI
 if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
 if 64 - 64: I11i + OoO0O00
 if 25 - 25: I1IiiI . ooOoO0o + I1IiiI % Ii1I * iIii1I11I1II1
 if 31 - 31: i11iIiiIii + OOooOOo - O0
 if 51 - 51: OoO0O00 * i1IIi / Ii1I * OOooOOo + ooOoO0o % I1ii11iIi11i
def IIIiI1iiiiiIi ( ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 74 - 74: I11i / OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
 if 98 - 98: oO0o . OoooooooOO
 Oo000 = lisp . lisp_get_all_multicast_rles ( )
 if 97 - 97: O0 / OOooOOo + o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 OoOOOO = "any"
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 Ooo00OOOOOO0 = pcappy . open_live ( OoOOOO , 1600 , 0 , 100 )
 if 15 - 15: I11i / o0oOOo0O0Ooo + Ii1I
 O0oo00o = "(proto 2) or "
 if 45 - 45: I1ii11iIi11i + I1Ii111 . iII111i . iII111i
 O0oo00o += "((dst host "
 for iI1Iii11i1 in lisp . lisp_get_all_addresses ( ) + Oo000 :
  O0oo00o += "{} or " . format ( iI1Iii11i1 )
  if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 O0oo00o = O0oo00o [ 0 : - 4 ]
 O0oo00o += ") and ((udp dst port 4341 or 8472 or 4789) or "
 O0oo00o += "(udp src port 4341) or "
 O0oo00o += "(udp dst port 4342 and ip[28] == 0x12) or "
 O0oo00o += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0)))))"
 if 19 - 19: I1ii11iIi11i
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 lisp . lprint ( "Capturing packets for: '{}' on device {}" . format ( O0oo00o ,
 OoOOOO ) )
 Ooo00OOOOOO0 . filter = O0oo00o
 if 66 - 66: O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
 Ooo00OOOOOO0 . loop ( - 1 , III1I , [ OoOOOO , i1 ] )
 return
 if 28 - 28: iIii1I11I1II1
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 if 46 - 46: OoOoOO00 - O0
 if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
def ii1i11ii ( ) :
 global Ooo
 global Oo
 global o0oOoO00o
 global i1
 global oOOoo00O0O
 global i1111
 if 11 - 11: Oo0Ooo - O0
 lisp . lisp_i_am ( "etr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "ETR starting up" )
 if 77 - 77: Oo0Ooo . i11iIiiIii / i1IIi % iII111i % iII111i
 if 65 - 65: Oo0Ooo * O0 / Ii1I . I1Ii111 % Oo0Ooo
 if 24 - 24: OoO0O00
 if 99 - 99: OOooOOo / IiII / Ii1I
 lisp . lisp_get_local_interfaces ( )
 lisp . lisp_get_local_macs ( )
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 84 - 84: OoO0O00 / iIii1I11I1II1
 if 33 - 33: i1IIi / I1Ii111 - i1IIi . Oo0Ooo
 if 18 - 18: Oo0Ooo / O0 + iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
 if 65 - 65: ooOoO0o - i1IIi
 if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if 64 - 64: i1IIi
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 if 25 - 25: II111iiii / OoO0O00
 if 64 - 64: O0 % ooOoO0o
 I1I1IiI1 = lisp . lisp_open_listen_socket ( "0.0.0.0" , str ( I1Ii11I1Ii1i ) )
 I1I1IiI1 . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_TTL , 32 )
 Oo = I1I1IiI1
 if 40 - 40: o0oOOo0O0Ooo + I11i
 if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
 if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
 if 47 - 47: OoooooooOO
 Ooo = lisp . lisp_open_listen_socket ( "" , "lisp-etr" )
 if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
 o0oOoO00o [ 0 ] = Oo
 o0oOoO00o [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 o0oOoO00o [ 2 ] = Ooo
 if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 i1 = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 i1 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 o0oOoO00o . append ( i1 )
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo
 if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
 if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
 if 37 - 37: iII111i
 if 33 - 33: OoO0O00 - O0 - OoO0O00
 if 94 - 94: IiII * I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - o0oOOo0O0Ooo
 if 13 - 13: OOooOOo / IiII - OoO0O00 / OOooOOo . i1IIi
 if 22 - 22: O0 - I11i + I1Ii111 . Ii1I * i1IIi
 if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
 if 10 - 10: I1Ii111 * oO0o % Oo0Ooo - I11i % Oo0Ooo
 if 65 - 65: iII111i * iIii1I11I1II1 / O0 . I11i
 if 94 - 94: Oo0Ooo . ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo . iII111i
 if 98 - 98: OOooOOo + Ii1I
 if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
 if 50 - 50: iIii1I11I1II1 - iII111i - I11i
 if ( pytun != None ) :
  i1111 = '\x00\x00\x86\xdd'
  OoOOOO = "lispers.net"
  try :
   oOOoo00O0O = pytun . TunTapDevice ( flags = pytun . IFF_TUN ,
 name = OoOOOO )
   os . system ( "ip link set dev {} up" . format ( OoOOOO ) )
  except :
   lisp . lprint ( "Cannot create tuntap interface" )
   if 60 - 60: iIii1I11I1II1 * ooOoO0o
   if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
   if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
   if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
   if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
   if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
 threading . Thread ( target = IIIiI1iiiiiIi , args = [ ] ) . start ( )
 if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
 if 93 - 93: ooOoO0o
 if 18 - 18: ooOoO0o
 if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
 threading . Thread ( target = o0oo0o00ooO00 , args = [ ] ) . start ( )
 return ( True )
 if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
 if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
 if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
 if 58 - 58: O0
 if 91 - 91: iII111i / I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I1ii11iIi11i
 if 72 - 72: Ii1I . IiII * I1ii11iIi11i / I1ii11iIi11i / iII111i
 if 13 - 13: i1IIi
def Ii1IIII1ii1I ( ) :
 global Oo0o
 global Ii1iI
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
 if 21 - 21: iII111i
 if 24 - 24: iII111i / ooOoO0o
 if 61 - 61: iIii1I11I1II1 + oO0o
 if ( Oo0o ) : Oo0o . cancel ( )
 if ( Ii1iI ) : Ii1iI . cancel ( )
 if 8 - 8: I1Ii111 + OoO0O00
 if 9 - 9: OOooOOo + o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 lisp . lisp_close_socket ( o0oOoO00o [ 0 ] , "" )
 lisp . lisp_close_socket ( o0oOoO00o [ 1 ] , "" )
 lisp . lisp_close_socket ( Ooo , "lisp-etr" )
 return
 if 55 - 55: oO0o
 if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
 if 97 - 97: I1Ii111 . I11i / I1IiiI
 if 83 - 83: I11i - I1ii11iIi11i * oO0o
 if 90 - 90: Oo0Ooo * I1IiiI
 if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
 if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
 if 28 - 28: IiII * I1IiiI % IiII
 if 95 - 95: O0 / I11i . I1Ii111
def iII11II1II ( ipc ) :
 ipc = ipc . split ( "%" )
 Oo0 = ipc [ 1 ]
 OOO00000o0 = ipc [ 2 ]
 if ( OOO00000o0 == "None" ) : OOO00000o0 = None
 if 96 - 96: o0oOOo0O0Ooo * oO0o - OOooOOo * o0oOOo0O0Ooo * i1IIi
 O0o0OO0000ooo = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 O0o0OO0000ooo . store_address ( Oo0 )
 if 8 - 8: ooOoO0o - Oo0Ooo + iIii1I11I1II1 + i1IIi * Ii1I - iIii1I11I1II1
 if 30 - 30: I11i / I1ii11iIi11i
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 o0oOO = lisp . lisp_db_for_lookups . lookup_cache ( O0o0OO0000ooo , False )
 if ( o0oOO == None or o0oOO . dynamic_eid_configured ( ) == False ) :
  lisp . lprint ( "ITR/ETR dynamic-EID configuration out of sync for {}" . format ( lisp . green ( Oo0 , False ) ) )
  if 36 - 36: IiII
  return
  if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
  if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
  if 43 - 43: iIii1I11I1II1 % OoO0O00
  if 84 - 84: Oo0Ooo
  if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
  if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
 O0O0Ooooo000 = None
 if ( o0oOO . dynamic_eids . has_key ( Oo0 ) ) : O0O0Ooooo000 = o0oOO . dynamic_eids [ Oo0 ]
 if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
 if ( O0O0Ooooo000 == None and OOO00000o0 == None ) :
  lisp . lprint ( "ITR/ETR state mismatch for {}" . format ( lisp . green ( Oo0 , False ) ) )
  if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
  return
  if 25 - 25: o0oOOo0O0Ooo
  if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
  if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
  if 41 - 41: i1IIi - I1IiiI
  if 48 - 48: I1IiiI - II111iiii / OoO0O00 + I1IiiI
  if 5 - 5: O0
  if 75 - 75: I1Ii111 + iIii1I11I1II1
 if ( O0O0Ooooo000 and OOO00000o0 ) :
  if ( O0O0Ooooo000 . interface == OOO00000o0 ) :
   lisp . lprint ( "ITR sent redundant IPC for {}" . format ( lisp . green ( Oo0 , False ) ) )
   if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
  else :
   lisp . lprint ( "Dynamic-EID {} interface change, {} -> {}" . format ( lisp . green ( Oo0 , False ) , O0O0Ooooo000 . interface , OOO00000o0 ) )
   if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
   O0O0Ooooo000 . interface = OOO00000o0
   if 92 - 92: I11i / O0 * I1IiiI - I11i
  return
  if 99 - 99: i11iIiiIii % OoooooooOO
  if 56 - 56: IiII * I1Ii111
  if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
  if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
  if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
 if ( OOO00000o0 ) :
  O0O0Ooooo000 = lisp . lisp_dynamic_eid ( )
  O0O0Ooooo000 . dynamic_eid . copy_address ( O0o0OO0000ooo )
  O0O0Ooooo000 . interface = OOO00000o0
  O0O0Ooooo000 . get_timeout ( OOO00000o0 )
  o0oOO . dynamic_eids [ Oo0 ] = O0O0Ooooo000
  if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
  ooi1i1Ii1IiIII = lisp . bold ( "Registering" , False )
  Oo0 = lisp . bold ( Oo0 , False )
  lisp . lprint ( "{} dynamic-EID {} on interface {}, timeout {}" . format ( ooi1i1Ii1IiIII ,
 lisp . green ( Oo0 , False ) , OOO00000o0 , O0O0Ooooo000 . timeout ) )
  if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
  OO0O000 ( o0oOoO00o , None , O0o0OO0000ooo , None , False )
  if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
  if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
  if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
  if 10 - 10: IiII / OoooooooOO
  if ( lisp . lisp_is_macos ( ) == False ) :
   Oo0 = O0o0OO0000ooo . print_prefix_no_iid ( )
   IiiiIIiii = "ip route add {} dev {}" . format ( Oo0 , OOO00000o0 )
   os . system ( IiiiIIiii )
   if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
  return
  if 25 - 25: iIii1I11I1II1
  if 63 - 63: ooOoO0o
  if 96 - 96: I11i
  if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
  if 63 - 63: iII111i
 if ( o0oOO . dynamic_eids . has_key ( Oo0 ) ) :
  OOO00000o0 = o0oOO . dynamic_eids [ Oo0 ] . interface
  i1i1iIiI = lisp . bold ( "Deregistering" , False )
  lisp . lprint ( "{} dynamic-EID {}" . format ( i1i1iIiI ,
 lisp . green ( Oo0 , False ) ) )
  if 23 - 23: IiII + iIii1I11I1II1 % iIii1I11I1II1 / ooOoO0o . oO0o + iIii1I11I1II1
  OO0O000 ( o0oOoO00o , 0 , O0o0OO0000ooo , None , False )
  if 93 - 93: oO0o * o0oOOo0O0Ooo / OOooOOo - OOooOOo . iII111i / I1IiiI
  o0oOO . dynamic_eids . pop ( Oo0 )
  if 11 - 11: I1Ii111 - I11i % i11iIiiIii . iIii1I11I1II1 * I1IiiI - Oo0Ooo
  if 73 - 73: O0 + ooOoO0o - O0 / OoooooooOO * Oo0Ooo
  if 32 - 32: OoO0O00 % I1IiiI % iII111i
  if 66 - 66: OoOoOO00 + o0oOOo0O0Ooo
  if ( lisp . lisp_is_macos ( ) == False ) :
   Oo0 = O0o0OO0000ooo . print_prefix_no_iid ( )
   IiiiIIiii = "ip route delete {} dev {}" . format ( Oo0 , OOO00000o0 )
   os . system ( IiiiIIiii )
   if 54 - 54: I1ii11iIi11i + I1ii11iIi11i + I11i % i1IIi % i11iIiiIii
   if 100 - 100: I1ii11iIi11i
 return
 if 96 - 96: I1IiiI . IiII * II111iiii % IiII . I1Ii111 * i1IIi
 if 83 - 83: iIii1I11I1II1
 if 97 - 97: i11iIiiIii + Oo0Ooo * OOooOOo % iII111i . IiII
 if 4 - 4: O0 . iII111i - iIii1I11I1II1
 if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
 if 89 - 89: Ii1I
 if 51 - 51: iII111i
 if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
 if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
def Ii1IiiiI1ii ( ipc ) :
 if ( lisp . lisp_register_all_rtrs ) : return
 if 55 - 55: I1ii11iIi11i
 oOoo0OO0 , o0OOo0o0O0O , o0OOoOO = ipc . split ( "%" )
 if ( lisp . lisp_rtr_list . has_key ( o0OOo0o0O0O ) == False ) : return
 if 5 - 5: i11iIiiIii * Oo0Ooo
 lisp . lprint ( "Process ITR IPC message, RTR {} has gone {}" . format (
 lisp . red ( o0OOo0o0O0O , False ) , lisp . bold ( o0OOoOO , False ) ) )
 if 29 - 29: Ii1I / ooOoO0o % I11i
 o0 = lisp . lisp_rtr_list [ o0OOo0o0O0O ]
 if ( o0OOoOO == "down" ) :
  lisp . lisp_rtr_list [ o0OOo0o0O0O ] = None
  return
  if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 o0 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , o0OOo0o0O0O , 32 , 0 )
 lisp . lisp_rtr_list [ o0OOo0o0O0O ] = o0
 return
 if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
 if 79 - 79: O0
 if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
 if 15 - 15: I1ii11iIi11i
 if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
def OO0o0o0oo ( ipc ) :
 iIiII1 , oOoo0OO0 , i111iii1I1 , iiIiII1 = ipc . split ( "%" )
 iiIiII1 = int ( iiIiII1 , 16 )
 if 37 - 37: O0 + ooOoO0o * OOooOOo
 IiI = lisp . lisp_get_echo_nonce ( None , i111iii1I1 )
 if ( IiI == None ) : IiI = lisp . lisp_echo_nonce ( i111iii1I1 )
 if 30 - 30: o0oOOo0O0Ooo * II111iiii % O0 % I1IiiI * Ii1I
 if ( oOoo0OO0 == "R" ) :
  IiI . request_nonce_sent = iiIiII1
  lisp . lprint ( "Waiting for echo-nonce 0x{} from {}" . format ( lisp . lisp_hex_string ( iiIiII1 ) , lisp . red ( IiI . rloc_str , False ) ) )
  if 17 - 17: OoOoOO00 + OoooooooOO % OOooOOo
 elif ( oOoo0OO0 == "E" ) :
  IiI . echo_nonce_sent = iiIiII1
  lisp . lprint ( "Sent echo-nonce 0x{} to {}" . format ( lisp . lisp_hex_string ( iiIiII1 ) , lisp . red ( IiI . rloc_str , False ) ) )
  if 36 - 36: i11iIiiIii + I1ii11iIi11i % OOooOOo . I1IiiI - ooOoO0o
  if 94 - 94: I1IiiI % OoOoOO00 . IiII . ooOoO0o . OoO0O00
 return
 if 53 - 53: OoOoOO00
 if 84 - 84: OoO0O00
 if 97 - 97: i1IIi
 if 98 - 98: OoooooooOO - I1IiiI + ooOoO0o
 if 98 - 98: iII111i . IiII . IiII - OOooOOo
oOOO0o = {
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

 "lisp map-server" : [ ooOOOoOooOoO , {
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

 "lisp database-mapping" : [ i11IiIiiIIIII , {
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

 "lisp group-mapping" : [ OoOOo0OOoO , {
 "group-name" : [ False ] ,
 "ms-name" : [ True ] ,
 "group-prefix" : [ False ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "rle-address" : [ False ] ,
 "sources" : [ ] ,
 "address" : [ True ] } ] ,

 "show database-mapping" : [ oo , { } ] ,
 "show etr-keys" : [ o0oO , { } ] ,
 "show etr-dynamic-eid" : [ lispconfig . lisp_show_dynamic_eid_command , { } ]
 }
if 18 - 18: I1ii11iIi11i / Oo0Ooo - iII111i
if 69 - 69: oO0o / IiII * ooOoO0o
if 81 - 81: oO0o
if 62 - 62: Ii1I + O0 * OoO0O00
if 59 - 59: II111iiii
if 43 - 43: Oo0Ooo + OoooooooOO
if ( ii1i11ii ( ) == False ) :
 lisp . lprint ( "lisp_etr_startup() failed" )
 lisp . lisp_print_banner ( "ETR abnormal exit" )
 exit ( 1 )
 if 47 - 47: ooOoO0o
 if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
ii11Ii1IiiI1 = [ Oo , Ooo ]
if 83 - 83: ooOoO0o + i1IIi * OoooooooOO * oO0o
while ( True ) :
 try : OoO0o0OO , II11IiI1 , iIiII1 = select . select ( ii11Ii1IiiI1 , [ ] , [ ] )
 except : break
 if 21 - 21: OoO0O00
 if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
 if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
 if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
 if ( Oo in OoO0o0OO ) :
  oOoo0OO0 , o0o , I1II1I1I , Ii1ii111i1 = lisp . lisp_receive ( Oo , False )
  if 11 - 11: O0 * OoOoOO00
  if ( o0o == "" ) : break
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  if ( I1II1I1I == lisp . LISP_DATA_PORT ) :
   i1I1i ( i1 , Ii1ii111i1 , o0o )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( Ii1ii111i1 [ 0 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 18 - 18: OoooooooOO
   O0oOo00oooO = lisp . lisp_parse_packet ( o0oOoO00o , Ii1ii111i1 ,
 o0o , I1II1I1I )
   if 16 - 16: i1IIi . i1IIi / I1Ii111 % OoOoOO00 / I1IiiI * I1ii11iIi11i
   if 30 - 30: o0oOOo0O0Ooo + OoooooooOO + OOooOOo / II111iiii * Oo0Ooo
   if 59 - 59: Ii1I / OoOoOO00 * OoO0O00 * iII111i % oO0o
   if 61 - 61: Oo0Ooo - O0 - OoooooooOO
   if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
   if ( O0oOo00oooO ) :
    Ii1iI = threading . Timer ( 0 ,
 OO0ooOOO0OOO , [ None ] )
    Ii1iI . start ( )
    Oo0o = threading . Timer ( 0 ,
 oO , [ o0oOoO00o ] )
    Oo0o . start ( )
    if 18 - 18: Oo0Ooo % O0
    if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
    if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
    if 86 - 86: IiII
    if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
    if 33 - 33: II111iiii - IiII - ooOoO0o
    if 92 - 92: OoO0O00 * IiII
    if 92 - 92: oO0o
 if ( Ooo in OoO0o0OO ) :
  oOoo0OO0 , o0o , I1II1I1I , Ii1ii111i1 = lisp . lisp_receive ( Ooo , True )
  if 7 - 7: iII111i
  if ( o0o == "" ) : break
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  if ( oOoo0OO0 == "command" ) :
   if ( Ii1ii111i1 . find ( "learn%" ) != - 1 ) :
    iII11II1II ( Ii1ii111i1 )
   elif ( Ii1ii111i1 . find ( "nonce%" ) != - 1 ) :
    OO0o0o0oo ( Ii1ii111i1 )
   elif ( Ii1ii111i1 . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( Ii1ii111i1 )
   elif ( Ii1ii111i1 . find ( "rtr%" ) != - 1 ) :
    Ii1IiiiI1ii ( Ii1ii111i1 )
   elif ( Ii1ii111i1 . find ( "stats%" ) != - 1 ) :
    Ii1ii111i1 = Ii1ii111i1 . split ( "%" ) [ - 1 ]
    lisp . lisp_process_data_plane_decap_stats ( Ii1ii111i1 , None )
   else :
    lispconfig . lisp_process_command ( Ooo ,
 oOoo0OO0 , Ii1ii111i1 , "lisp-etr" , [ oOOO0o ] )
    if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  elif ( oOoo0OO0 == "api" ) :
   lisp . lisp_process_api ( "lisp-etr" , Ooo , Ii1ii111i1 )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( Ii1ii111i1 [ 0 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 62 - 62: i11iIiiIii
   lisp . lisp_parse_packet ( o0oOoO00o , Ii1ii111i1 , o0o , I1II1I1I )
   if 2 - 2: I1IiiI
   if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
   if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
   if 14 - 14: IiII . IiII % ooOoO0o
Ii1IIII1ii1I ( )
lisp . lisp_print_banner ( "ETR normal exit" )
exit ( 0 )
if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
