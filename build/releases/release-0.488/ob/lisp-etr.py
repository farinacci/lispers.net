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
IiII1IiiIiI1 = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 40 - 40: oo * OoO0O00
if 2 - 2: ooOO00oOo % oOo0O0Ooo * Ooo00oOo00o . oOoO0oo0OOOo + iiiiIi11i
if 24 - 24: II11iiII / OoOO0ooOOoo0O + o0000oOoOoO0o * i1I1ii1II1iII % oooO0oo0oOOOO
if 53 - 53: o0oo0o / Oo + o0oo0o / oooO0oo0oOOOO * OoooooooOO + i1I1ii1II1iII
if 71 - 71: II11iiII * i1I1ii1II1iII . II11iiII / o0oo0o
if 14 - 14: iIii1I11I1II1
o0oOoO00o = None
i1 = None
oOOoo00O0O = None
i1111 = None
i11 = lisp . lisp_get_ephemeral_port ( )
I11 = None
Oo0o0000o0o0 = [ None , None , None ]
oOo0oooo00o = None
oO0o0o0ooO0oO = None
oo0o0O00 = None
if 68 - 68: II11iiII . oo / i1I1ii1II1iII
oOOoo = 60
if 43 - 43: o0oo0o % oo - i11iIiiIii - ooOO00oOo / II11iiII - oOo0O0Ooo
if 45 - 45: o0oo0o + o0000oOoOoO0o
if 17 - 17: Ooo00oOo00o
if 64 - 64: o0000oOoOoO0o % i1IIi % OoooooooOO
if 3 - 3: i1I1ii1II1iII + O0
if 42 - 42: II11iiII / i1IIi + i11iIiiIii - o0000oOoOoO0o
if 78 - 78: ooOO00oOo
if 18 - 18: O0 - i1I1ii1II1iII / i1I1ii1II1iII + Oo % Oo - oooO0oo0oOOOO
if 62 - 62: i1I1ii1II1iII - oooO0oo0oOOOO - oOo0O0Ooo % i1IIi / iiiiIi11i
def OoooooOoo ( kv_pair ) :
 global i1
 global Oo0o0000o0o0
 if 70 - 70: ooOO00oOo . ooOO00oOo - ooOO00oOo / oOoO0oo0OOOo * II11iiII
 lispconfig . lisp_database_mapping_command ( kv_pair , i11 )
 if 86 - 86: i11iIiiIii + o0000oOoOoO0o + Oo * OoOO0ooOOoo0O + Ooo00oOo00o
 if 61 - 61: ooOO00oOo / i11iIiiIii
 if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - oOoO0oo0OOOo + i11iIiiIii
 if 65 - 65: oOo0O0Ooo
 if 6 - 6: oo / OoO0O00 % o0000oOoOoO0o
 if 84 - 84: i11iIiiIii . Ooo00oOo00o
 if 100 - 100: o0000oOoOoO0o - o0000oOoOoO0o - o0oo0o
 if 20 - 20: OoooooooOO
 if ( lisp . lisp_nat_traversal ) : return
 if ( i1 != None and
 i1 . is_alive ( ) ) : return
 if 13 - 13: i1IIi - o0000oOoOoO0o % iiiiIi11i / iIii1I11I1II1 % i1I1ii1II1iII
 if ( len ( lisp . lisp_map_servers_list ) > 0 ) :
  i1 = threading . Timer ( 5 ,
 ooO0o0Oo , [ Oo0o0000o0o0 ] )
  i1 . start ( )
  if 78 - 78: iIii1I11I1II1 - o0000oOoOoO0o * ooOO00oOo + Ooo00oOo00o + i1I1ii1II1iII + i1I1ii1II1iII
  if 11 - 11: i1I1ii1II1iII - ooOO00oOo % Oo % i1I1ii1II1iII / oOo0O0Ooo - ooOO00oOo
  if 74 - 74: i1I1ii1II1iII * O0
  if 89 - 89: iiiiIi11i + OoO0O00
  if 3 - 3: i1IIi / oo % OoOO0ooOOoo0O * i11iIiiIii / O0 * OoOO0ooOOoo0O
  if 49 - 49: iiiiIi11i % o0000oOoOoO0o + i1IIi . oo % oOoO0oo0OOOo
  if 48 - 48: OoOO0ooOOoo0O + OoOO0ooOOoo0O / II111iiii / iIii1I11I1II1
  if 20 - 20: Ooo00oOo00o
def oO00 ( clause ) :
 if 53 - 53: OoooooooOO . i1IIi
 if 18 - 18: Ooo00oOo00o
 if 28 - 28: II11iiII - oooO0oo0oOOOO . oooO0oo0oOOOO + oOo0O0Ooo - OoooooooOO + O0
 if 95 - 95: ooOO00oOo % iiiiIi11i . O0
 I1i1I = lispconfig . lisp_show_myrlocs ( "" )
 if 80 - 80: oOo0O0Ooo - ooOO00oOo
 if 87 - 87: iiiiIi11i / OoOO0ooOOoo0O - i1IIi * II11iiII / OoooooooOO . O0
 if 1 - 1: II111iiii - OoOO0ooOOoo0O / OoOO0ooOOoo0O
 if 46 - 46: o0000oOoOoO0o * II11iiII - ooOO00oOo * iiiiIi11i - o0oo0o
 I1i1I = lispconfig . lisp_show_decap_stats ( I1i1I , "ETR" )
 if 83 - 83: OoooooooOO
 if 31 - 31: II111iiii - II11iiII . o0oo0o % oOo0O0Ooo - O0
 if 4 - 4: II111iiii / Oo . i1I1ii1II1iII
 if 58 - 58: II11iiII * i11iIiiIii / oOo0O0Ooo % o0oo0o - oOoO0oo0OOOo / iiiiIi11i
 ii11i1 = "{} configured map-servers" . format ( len ( lisp . lisp_map_servers_list ) )
 IIIii1II1II = lisp . lisp_span ( "LISP-ETR Configured Map-Servers:" , ii11i1 )
 ii11i1 = ( "P = proxy-reply requested, M = merge-registrations " + "requested, N = Map-Notify requested" )
 if 42 - 42: o0000oOoOoO0o + iiiiIi11i
 o0O0o0Oo = lisp . lisp_span ( "Registration<br>flags" , ii11i1 )
 if 16 - 16: O0 - o0oo0o * iIii1I11I1II1 + i1I1ii1II1iII
 I1i1I += lispconfig . lisp_table_header ( IIIii1II1II , "Address" , "Auth-Type" ,
 "xTR-ID" , "Site-ID" , o0O0o0Oo , "Map-Registers<br>Sent" ,
 "Map-Notifies<br>Received" )
 if 50 - 50: II111iiii - Oo * oOoO0oo0OOOo / o0oo0o + Ooo00oOo00o
 for O0O0O in lisp . lisp_map_servers_list . values ( ) :
  O0O0O . resolve_dns_name ( )
  oO0Oo = "" if O0O0O . ms_name == "all" else O0O0O . ms_name + "<br>"
  oOOoo0Oo = oO0Oo + O0O0O . map_server . print_address ( )
  if ( O0O0O . dns_name ) : oOOoo0Oo += "<br>" + O0O0O . dns_name
  if 78 - 78: OoOO0ooOOoo0O
  OO00Oo = "0x" + lisp . lisp_hex_string ( O0O0O . xtr_id )
  O0OOO0OOoO0O = "{}-{}-{}-{}" . format ( "P" if O0O0O . proxy_reply else "p" ,
 "M" if O0O0O . merge_registrations else "m" ,
 "N" if O0O0O . want_map_notify else "n" ,
 "R" if O0O0O . refresh_registrations else "r" )
  if 70 - 70: oooO0oo0oOOOO * OoO0O00 * OoOO0ooOOoo0O / o0000oOoOoO0o
  oO = O0O0O . map_registers_sent + O0O0O . map_registers_multicast_sent
  if 93 - 93: ooOO00oOo % iiiiIi11i . ooOO00oOo * o0oo0o % o0000oOoOoO0o . II111iiii
  if 38 - 38: Ooo00oOo00o
  I1i1I += lispconfig . lisp_table_row ( oOOoo0Oo ,
 "sha1" if ( O0O0O . alg_id == lisp . LISP_SHA_1_96_ALG_ID ) else "sha2" ,
 OO00Oo , O0O0O . site_id , O0OOO0OOoO0O , oO ,
 O0O0O . map_notifies_received )
  if 57 - 57: O0 / iiiiIi11i * o0oo0o / oOo0O0Ooo . II111iiii
 I1i1I += lispconfig . lisp_table_footer ( )
 if 26 - 26: i1I1ii1II1iII
 if 91 - 91: ooOO00oOo . oOoO0oo0OOOo + ooOO00oOo - i1I1ii1II1iII / OoooooooOO
 if 39 - 39: oOoO0oo0OOOo / Oo - II111iiii
 if 98 - 98: oOoO0oo0OOOo / OoOO0ooOOoo0O % iiiiIi11i . oOo0O0Ooo
 I1i1I = lispconfig . lisp_show_db_list ( "ETR" , I1i1I )
 if 91 - 91: iiiiIi11i % OoO0O00
 if 64 - 64: OoOO0ooOOoo0O % i1I1ii1II1iII - o0oo0o - iiiiIi11i
 if 31 - 31: OoOO0ooOOoo0O - II111iiii . OoOO0ooOOoo0O
 if 18 - 18: Ooo00oOo00o
 if ( len ( lisp . lisp_elp_list ) != 0 ) :
  I1i1I = lispconfig . lisp_show_elp_list ( I1i1I )
  if 98 - 98: i1I1ii1II1iII * i1I1ii1II1iII / i1I1ii1II1iII + OoOO0ooOOoo0O
  if 34 - 34: Oo
  if 15 - 15: OoOO0ooOOoo0O * Oo * OoO0O00 % i11iIiiIii % oOo0O0Ooo - II11iiII
  if 68 - 68: o0oo0o % i1IIi . oooO0oo0oOOOO . oOoO0oo0OOOo
  if 92 - 92: i1I1ii1II1iII . o0oo0o
 if ( len ( lisp . lisp_rle_list ) != 0 ) :
  I1i1I = lispconfig . lisp_show_rle_list ( I1i1I )
  if 31 - 31: o0oo0o . oOo0O0Ooo / O0
  if 89 - 89: oOo0O0Ooo
  if 68 - 68: ooOO00oOo * OoooooooOO % O0 + ooOO00oOo + Oo
  if 4 - 4: Oo + O0 * II11iiII
  if 55 - 55: OoO0O00 + iIii1I11I1II1 / oOo0O0Ooo * iiiiIi11i - i11iIiiIii - o0000oOoOoO0o
 if ( len ( lisp . lisp_json_list ) != 0 ) :
  I1i1I = lispconfig . lisp_show_json_list ( I1i1I )
  if 25 - 25: oOoO0oo0OOOo
  if 7 - 7: i1IIi / oo * o0oo0o . oooO0oo0oOOOO . iIii1I11I1II1
  if 13 - 13: II11iiII / i11iIiiIii
  if 2 - 2: oo / O0 / Ooo00oOo00o % oOo0O0Ooo % o0000oOoOoO0o
  if 52 - 52: Ooo00oOo00o
 if ( len ( lisp . lisp_group_mapping_list ) != 0 ) :
  IIIii1II1II = "Configured Group Mappings:"
  I1i1I += lispconfig . lisp_table_header ( IIIii1II1II , "Name" , "Group Prefix" ,
 "Sources" , "Use MS" )
  for o0OO0oOO0O0 in lisp . lisp_group_mapping_list . values ( ) :
   iiiIIi1II = ""
   for o0O00oOoOO in o0OO0oOO0O0 . sources : iiiIIi1II += o0O00oOoOO + ", "
   if ( iiiIIi1II == "" ) :
    iiiIIi1II = "*"
   else :
    iiiIIi1II = iiiIIi1II [ 0 : - 2 ]
    if 42 - 42: ooOO00oOo
   I1i1I += lispconfig . lisp_table_row ( o0OO0oOO0O0 . group_name ,
 o0OO0oOO0O0 . group_prefix . print_prefix ( ) , iiiIIi1II , o0OO0oOO0O0 . use_ms_name )
   if 67 - 67: o0oo0o . i1I1ii1II1iII . O0
  I1i1I += lispconfig . lisp_table_footer ( )
  if 10 - 10: oOoO0oo0OOOo % oOoO0oo0OOOo - iIii1I11I1II1 / II11iiII + o0000oOoOoO0o
 return ( I1i1I )
 if 87 - 87: iiiiIi11i * oOoO0oo0OOOo + II11iiII / iIii1I11I1II1 / i1I1ii1II1iII
 if 37 - 37: i1I1ii1II1iII - Oo * iiiiIi11i % i11iIiiIii - o0oo0o
 if 83 - 83: OoOO0ooOOoo0O / oo
 if 34 - 34: oooO0oo0oOOOO
 if 57 - 57: iiiiIi11i . OoOO0ooOOoo0O . i1IIi
 if 42 - 42: OoOO0ooOOoo0O + oOoO0oo0OOOo % O0
 if 6 - 6: iiiiIi11i
def oOOo0oOo0 ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "ETR" ) )
 if 49 - 49: OoO0O00 . i11iIiiIii - i1IIi / II111iiii . oo
 if 1 - 1: OoO0O00 / Ooo00oOo00o % i1I1ii1II1iII * oooO0oo0oOOOO . i11iIiiIii
 if 2 - 2: oOoO0oo0OOOo * OoOO0ooOOoo0O - iIii1I11I1II1 + oo . iiiiIi11i % i1I1ii1II1iII
 if 92 - 92: i1I1ii1II1iII
 if 25 - 25: OoO0O00 - oo / OoooooooOO / Ooo00oOo00o
 if 12 - 12: oo * i1I1ii1II1iII % i1IIi % iIii1I11I1II1
 if 20 - 20: II11iiII % o0000oOoOoO0o / o0000oOoOoO0o + o0000oOoOoO0o
def III1IiiI ( kv_pairs ) :
 global i1
 global oOOoo00O0O
 if 31 - 31: Ooo00oOo00o . oo
 ii11IIII11I = [ ]
 OOooo = [ ]
 oOooOOOoOo = 0
 i1Iii1i1I = 0
 OOoO00 = ""
 IiI111111IIII = False
 i1Ii = False
 ii111iI1iIi1 = False
 OOO = False
 oo0OOo0 = 0
 oO0Oo = None
 I11IiI = 0
 O0ooO0Oo00o = None
 if 77 - 77: iIii1I11I1II1 * ooOO00oOo
 for oOooOo0 in kv_pairs . keys ( ) :
  i1I1ii11i1Iii = kv_pairs [ oOooOo0 ]
  if ( oOooOo0 == "ms-name" ) :
   oO0Oo = i1I1ii11i1Iii [ 0 ]
   if 26 - 26: OoOO0ooOOoo0O - iIii1I11I1II1 - oo / ooOO00oOo . oOo0O0Ooo % iIii1I11I1II1
  if ( oOooOo0 == "address" ) :
   for OO in range ( len ( i1I1ii11i1Iii ) ) :
    ii11IIII11I . append ( i1I1ii11i1Iii [ OO ] )
    if 25 - 25: ooOO00oOo
    if 62 - 62: II11iiII + O0
  if ( oOooOo0 == "dns-name" ) :
   for OO in range ( len ( i1I1ii11i1Iii ) ) :
    OOooo . append ( i1I1ii11i1Iii [ OO ] )
    if 98 - 98: Ooo00oOo00o
    if 51 - 51: OoO0O00 - iiiiIi11i + II111iiii * o0000oOoOoO0o . OoOO0ooOOoo0O + iiiiIi11i
  if ( oOooOo0 == "authentication-type" ) :
   i1Iii1i1I = lisp . LISP_SHA_1_96_ALG_ID if ( i1I1ii11i1Iii == "sha1" ) else lisp . LISP_SHA_256_128_ALG_ID if ( i1I1ii11i1Iii == "sha2" ) else ""
   if 78 - 78: i11iIiiIii / i1I1ii1II1iII - o0000oOoOoO0o / II11iiII + iiiiIi11i
   if 82 - 82: o0000oOoOoO0o
  if ( oOooOo0 == "authentication-key" ) :
   if ( i1Iii1i1I == 0 ) : i1Iii1i1I = lisp . LISP_SHA_256_128_ALG_ID
   ii = lisp . lisp_parse_auth_key ( i1I1ii11i1Iii )
   oOooOOOoOo = ii . keys ( ) [ 0 ]
   OOoO00 = ii [ oOooOOOoOo ]
   if 5 - 5: Oo - II111iiii - OoooooooOO % o0000oOoOoO0o + oo * iIii1I11I1II1
  if ( oOooOo0 == "proxy-reply" ) :
   IiI111111IIII = True if i1I1ii11i1Iii == "yes" else False
   if 37 - 37: oooO0oo0oOOOO % Oo + oOo0O0Ooo + Ooo00oOo00o * OoOO0ooOOoo0O % O0
  if ( oOooOo0 == "merge-registrations" ) :
   i1Ii = True if i1I1ii11i1Iii == "yes" else False
   if 61 - 61: oo - II11iiII . iiiiIi11i / II11iiII + OoO0O00
  if ( oOooOo0 == "refresh-registrations" ) :
   ii111iI1iIi1 = True if i1I1ii11i1Iii == "yes" else False
   if 5 - 5: Oo + Oo / O0 * OoO0O00 - II11iiII % Oo
  if ( oOooOo0 == "want-map-notify" ) :
   OOO = True if i1I1ii11i1Iii == "yes" else False
   if 15 - 15: i11iIiiIii % o0000oOoOoO0o . OoO0O00 + oOoO0oo0OOOo
  if ( oOooOo0 == "site-id" ) :
   oo0OOo0 = int ( i1I1ii11i1Iii )
   if 61 - 61: OoO0O00 * oOoO0oo0OOOo % OoO0O00 - i1IIi - iIii1I11I1II1
  if ( oOooOo0 == "encryption-key" ) :
   O0ooO0Oo00o = lisp . lisp_parse_auth_key ( i1I1ii11i1Iii )
   I11IiI = O0ooO0Oo00o . keys ( ) [ 0 ]
   O0ooO0Oo00o = O0ooO0Oo00o [ I11IiI ]
   if 74 - 74: oOoO0oo0OOOo + II111iiii / ooOO00oOo
   if 100 - 100: oOo0O0Ooo * iIii1I11I1II1
   if 86 - 86: ooOO00oOo * II11iiII . i1I1ii1II1iII
   if 32 - 32: Ooo00oOo00o . oooO0oo0oOOOO * OoOO0ooOOoo0O
   if 93 - 93: Ooo00oOo00o % i1IIi . o0000oOoOoO0o . i11iIiiIii
   if 56 - 56: oOoO0oo0OOOo % O0 - oo
 O0O0O = None
 for oOOoo0Oo in ii11IIII11I :
  if ( oOOoo0Oo == "" ) : continue
  O0O0O = lisp . lisp_ms ( oOOoo0Oo , None , oO0Oo , i1Iii1i1I , oOooOOOoOo , OOoO00 ,
 IiI111111IIII , i1Ii , ii111iI1iIi1 , OOO , oo0OOo0 , I11IiI , O0ooO0Oo00o )
  if 100 - 100: o0000oOoOoO0o - O0 % iiiiIi11i * II11iiII + oo
 for Oo0O0oooo in OOooo :
  if ( Oo0O0oooo == "" ) : continue
  O0O0O = lisp . lisp_ms ( None , Oo0O0oooo , oO0Oo , i1Iii1i1I , oOooOOOoOo , OOoO00 ,
 IiI111111IIII , i1Ii , ii111iI1iIi1 , OOO , oo0OOo0 , I11IiI , O0ooO0Oo00o )
  if 33 - 33: o0oo0o + i1I1ii1II1iII * iiiiIi11i / iIii1I11I1II1 - oo
  if 54 - 54: o0oo0o / II11iiII . iiiiIi11i % i1I1ii1II1iII
  if 57 - 57: i11iIiiIii . oOoO0oo0OOOo - o0000oOoOoO0o - iiiiIi11i + oOo0O0Ooo
  if 63 - 63: oOo0O0Ooo * i1I1ii1II1iII
  if 69 - 69: O0 . ooOO00oOo
  if 49 - 49: oo - OoOO0ooOOoo0O
 OoOOoOooooOOo = ( len ( lisp . lisp_map_servers_list ) == 1 )
 if ( OoOOoOooooOOo ) :
  O0O0O = lisp . lisp_map_servers_list . values ( ) [ 0 ]
  oOOoo00O0O = threading . Timer ( 2 , oOo0O ,
 [ O0O0O . map_server ] )
  oOOoo00O0O . start ( )
 else :
  if 52 - 52: i11iIiiIii / Ooo00oOo00o * Oo
  if 22 - 22: oOo0O0Ooo . II11iiII * oOo0O0Ooo
  if 54 - 54: oooO0oo0oOOOO + o0000oOoOoO0o % ooOO00oOo + OoooooooOO - O0 - Ooo00oOo00o
  if 77 - 77: II11iiII * iIii1I11I1II1
  if 98 - 98: oo % o0000oOoOoO0o * OoooooooOO
  if 51 - 51: iIii1I11I1II1 . oOo0O0Ooo / iiiiIi11i + Ooo00oOo00o
  if 33 - 33: Oo . II111iiii % i1I1ii1II1iII + Ooo00oOo00o
  if 71 - 71: OoO0O00 % II11iiII
  if ( lisp . lisp_nat_traversal ) : return
  if ( O0O0O and len ( lisp . lisp_db_list ) > 0 ) :
   O00oO000O0O ( Oo0o0000o0o0 , None , None , O0O0O , False )
   if 18 - 18: i1I1ii1II1iII - II11iiII . o0oo0o . iIii1I11I1II1
   if 2 - 2: II11iiII . ooOO00oOo
   if 78 - 78: OoOO0ooOOoo0O * iIii1I11I1II1 . oo / Ooo00oOo00o - OoooooooOO / o0oo0o
   if 35 - 35: OoOO0ooOOoo0O % II11iiII - iiiiIi11i
   if 20 - 20: i1IIi - Oo
   if 30 - 30: OoOO0ooOOoo0O / oo
   if 35 - 35: II111iiii % II11iiII . Oo + Oo % II111iiii % II111iiii
 if ( len ( lisp . lisp_db_list ) > 0 ) :
  if ( i1 != None and
 i1 . is_alive ( ) ) : return
  if 72 - 72: II111iiii + i1IIi + Ooo00oOo00o
  i1 = threading . Timer ( 5 ,
 ooO0o0Oo , [ Oo0o0000o0o0 ] )
  i1 . start ( )
  if 94 - 94: iiiiIi11i . i1IIi - Ooo00oOo00o % O0 - ooOO00oOo
 return
 if 72 - 72: o0000oOoOoO0o
 if 1 - 1: ooOO00oOo * oooO0oo0oOOOO * OoooooooOO + Oo
 if 33 - 33: O0 * Ooo00oOo00o - o0oo0o % o0oo0o
 if 18 - 18: o0oo0o / OoO0O00 * o0oo0o + o0oo0o * i11iIiiIii * oOoO0oo0OOOo
 if 11 - 11: Oo / oOo0O0Ooo - oooO0oo0oOOOO * OoooooooOO + OoooooooOO . oOo0O0Ooo
 if 26 - 26: o0000oOoOoO0o % oOoO0oo0OOOo
 if 76 - 76: oooO0oo0oOOOO * i1I1ii1II1iII
def ooooooo00o ( kv_pairs ) :
 iiiIIi1II = [ ]
 o0oooOO00 = None
 iiIiii1IIIII = None
 oO0Oo = "all"
 if 67 - 67: o0000oOoOoO0o / oooO0oo0oOOOO
 for oOooOo0 in kv_pairs . keys ( ) :
  i1I1ii11i1Iii = kv_pairs [ oOooOo0 ]
  if ( oOooOo0 == "group-name" ) :
   iiIiIIIiiI = i1I1ii11i1Iii
   if 12 - 12: O0 - Ooo00oOo00o
  if ( oOooOo0 == "group-prefix" ) :
   if ( o0oooOO00 == None ) :
    o0oooOO00 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 81 - 81: oOo0O0Ooo - oOo0O0Ooo . i1I1ii1II1iII
   o0oooOO00 . store_prefix ( i1I1ii11i1Iii )
   if 73 - 73: OoOO0ooOOoo0O % i11iIiiIii - oo
  if ( oOooOo0 == "instance-id" ) :
   if ( o0oooOO00 == None ) :
    o0oooOO00 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 7 - 7: O0 * i11iIiiIii * o0000oOoOoO0o + Oo % ooOO00oOo - Oo
   o0oooOO00 . instance_id = int ( i1I1ii11i1Iii )
   if 39 - 39: OoO0O00 * II11iiII % II11iiII - OoooooooOO + Ooo00oOo00o - OoOO0ooOOoo0O
  if ( oOooOo0 == "ms-name" ) :
   oO0Oo = i1I1ii11i1Iii [ 0 ]
   if 23 - 23: i11iIiiIii
  if ( oOooOo0 == "address" ) :
   for II1iIi11 in i1I1ii11i1Iii :
    if ( II1iIi11 != "" ) : iiiIIi1II . append ( II1iIi11 )
    if 12 - 12: o0000oOoOoO0o + i11iIiiIii * iIii1I11I1II1 / oOoO0oo0OOOo . OoOO0ooOOoo0O
    if 5 - 5: i1IIi + oooO0oo0oOOOO / Ooo00oOo00o . i1I1ii1II1iII / OoOO0ooOOoo0O
  if ( oOooOo0 == "rle-address" ) :
   if ( iiIiii1IIIII == None ) :
    iiIiii1IIIII = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 32 - 32: oo % iIii1I11I1II1 / i1IIi - oo
   iiIiii1IIIII . store_address ( i1I1ii11i1Iii )
   if 7 - 7: o0oo0o * ooOO00oOo - Oo + II11iiII * oo % ooOO00oOo
   if 15 - 15: oOo0O0Ooo % oo * OoOO0ooOOoo0O
 o0OO0oOO0O0 = lisp . lisp_group_mapping ( iiIiIIIiiI , oO0Oo , o0oooOO00 , iiiIIi1II ,
 iiIiii1IIIII )
 o0OO0oOO0O0 . add_group ( )
 return
 if 81 - 81: Oo - iIii1I11I1II1 - i1IIi / o0oo0o - O0 * OoOO0ooOOoo0O
 if 20 - 20: iiiiIi11i % oooO0oo0oOOOO
 if 19 - 19: oOoO0oo0OOOo % oooO0oo0oOOOO + Oo / o0oo0o . Oo
 if 12 - 12: i1IIi + i1IIi - oOoO0oo0OOOo * OoO0O00 % OoO0O00 - II111iiii
 if 52 - 52: Oo . i1I1ii1II1iII + o0oo0o
 if 38 - 38: i1IIi - II111iiii . o0oo0o
 if 58 - 58: oo . i1I1ii1II1iII + oOo0O0Ooo
def O00OO ( quiet , db , eid , group , ttl ) :
 if 17 - 17: OoOO0ooOOoo0O / o0oo0o + iiiiIi11i - i11iIiiIii . i1I1ii1II1iII
 if 95 - 95: ooOO00oOo % i1IIi * i11iIiiIii % OoO0O00 - iiiiIi11i
 if 67 - 67: oOo0O0Ooo + oOoO0oo0OOOo . Ooo00oOo00o . II111iiii
 if 98 - 98: i1I1ii1II1iII
 if 68 - 68: iIii1I11I1II1 * iIii1I11I1II1 . Ooo00oOo00o / II111iiii % OoO0O00
 if 38 - 38: Oo - II11iiII / i1I1ii1II1iII
 if 66 - 66: O0 % oOoO0oo0OOOo + i11iIiiIii . oOo0O0Ooo / o0000oOoOoO0o + oOoO0oo0OOOo
 if 86 - 86: Ooo00oOo00o
 i1Iii11Ii1i1 = { }
 for OOooo0O0o0 in db . rloc_set :
  if ( OOooo0O0o0 . translated_rloc . is_null ( ) ) : continue
  if 14 - 14: Ooo00oOo00o % O0 * i1I1ii1II1iII + o0000oOoOoO0o + OoO0O00 * o0000oOoOoO0o
  for iII1I1IiI11ii in lisp . lisp_rtr_list :
   OooooOoooO = lisp . lisp_rtr_list [ iII1I1IiI11ii ]
   if ( lisp . lisp_register_all_rtrs == False and OooooOoooO == None ) :
    lisp . lprint ( "  Exclude unreachable RTR {}" . format ( lisp . red ( iII1I1IiI11ii , False ) ) )
    if 56 - 56: OoO0O00 . oOoO0oo0OOOo . oo
    continue
    if 39 - 39: O0 + o0oo0o
   if ( OooooOoooO == None ) : continue
   i1Iii11Ii1i1 [ iII1I1IiI11ii ] = OooooOoooO
   if 91 - 91: OoooooooOO - iIii1I11I1II1 + oOo0O0Ooo / ooOO00oOo . oOo0O0Ooo + O0
  break
  if 26 - 26: oOoO0oo0OOOo - OoooooooOO
  if 11 - 11: oo * iiiiIi11i
 o000oo = 0
 o00o0 = ""
 for II1I in [ eid . instance_id ] + eid . iid_list :
  II1I1I1Ii = lisp . lisp_eid_record ( )
  if 70 - 70: ooOO00oOo % iiiiIi11i + II11iiII / o0000oOoOoO0o % O0
  II1I1I1Ii . rloc_count = len ( db . rloc_set ) + len ( i1Iii11Ii1i1 )
  II1I1I1Ii . authoritative = True
  II1I1I1Ii . record_ttl = ttl
  II1I1I1Ii . eid . copy_address ( eid )
  II1I1I1Ii . eid . instance_id = II1I
  II1I1I1Ii . eid . iid_list = [ ]
  II1I1I1Ii . group . copy_address ( group )
  if 100 - 100: Ooo00oOo00o + II11iiII * Ooo00oOo00o
  o00o0 += II1I1I1Ii . encode ( )
  if ( not quiet ) :
   oOOo0OOOo00O = eid . print_prefix ( )
   lisp . lprint ( "  EID-prefix {} for ms-name '{}'" . format ( lisp . green ( oOOo0OOOo00O , False ) , db . use_ms_name ) )
   if 76 - 76: i11iIiiIii + Ooo00oOo00o / oOoO0oo0OOOo - ooOO00oOo - o0000oOoOoO0o + oOoO0oo0OOOo
   II1I1I1Ii . print_record ( "  " , False )
   if 51 - 51: iIii1I11I1II1 . Oo + iIii1I11I1II1
   if 95 - 95: oo
  for OOooo0O0o0 in db . rloc_set :
   iII1ii1 = lisp . lisp_rloc_record ( )
   iII1ii1 . store_rloc_entry ( OOooo0O0o0 )
   iII1ii1 . local_bit = OOooo0O0o0 . rloc . is_local ( )
   iII1ii1 . reach_bit = True
   o00o0 += iII1ii1 . encode ( )
   if ( not quiet ) : iII1ii1 . print_record ( "    " )
   if 12 - 12: II11iiII - Oo . OoooooooOO / oOoO0oo0OOOo . i1IIi * ooOO00oOo
   if 19 - 19: i11iIiiIii + OoooooooOO - OoO0O00 - OoOO0ooOOoo0O
   if 21 - 21: O0 % oooO0oo0oOOOO . oo / II111iiii + oooO0oo0oOOOO
   if 53 - 53: iiiiIi11i - oo - iiiiIi11i * i1I1ii1II1iII
   if 71 - 71: O0 - iIii1I11I1II1
   if 12 - 12: II11iiII / Ooo00oOo00o
  for OooooOoooO in i1Iii11Ii1i1 . values ( ) :
   iII1ii1 = lisp . lisp_rloc_record ( )
   iII1ii1 . rloc . copy_address ( OooooOoooO )
   iII1ii1 . priority = 254
   iII1ii1 . rloc_name = "RTR"
   iII1ii1 . weight = 0
   iII1ii1 . mpriority = 255
   iII1ii1 . mweight = 0
   iII1ii1 . local_bit = False
   iII1ii1 . reach_bit = True
   o00o0 += iII1ii1 . encode ( )
   if ( not quiet ) : iII1ii1 . print_record ( "    RTR " )
   if 42 - 42: OoO0O00
   if 19 - 19: iiiiIi11i % oOoO0oo0OOOo * iIii1I11I1II1 + oo
   if 46 - 46: OoO0O00
   if 1 - 1: i1I1ii1II1iII
   if 97 - 97: II11iiII + i1I1ii1II1iII + O0 + i11iIiiIii
  o000oo += 1
  if 77 - 77: Ooo00oOo00o / OoooooooOO
 return ( o00o0 , o000oo )
 if 46 - 46: Ooo00oOo00o % iIii1I11I1II1 . i1I1ii1II1iII % i1I1ii1II1iII + i11iIiiIii
 if 72 - 72: iIii1I11I1II1 * o0000oOoOoO0o % Oo / ooOO00oOo
 if 35 - 35: Oo + i1IIi % oOoO0oo0OOOo % OoOO0ooOOoo0O + iiiiIi11i
 if 17 - 17: i1IIi
 if 21 - 21: OoO0O00
 if 29 - 29: OoOO0ooOOoo0O / II111iiii / Oo * II11iiII
 if 10 - 10: o0oo0o % oooO0oo0oOOOO * oooO0oo0oOOOO . OoOO0ooOOoo0O / o0000oOoOoO0o % II11iiII
 if 49 - 49: ooOO00oOo / iiiiIi11i + O0 * Ooo00oOo00o
def O00oO000O0O ( lisp_sockets , ttl , eid_only , ms_only , refresh ) :
 if 28 - 28: Oo + i11iIiiIii / OoOO0ooOOoo0O % oOo0O0Ooo % OoO0O00 - O0
 if 54 - 54: i1IIi + II111iiii
 if 83 - 83: oOoO0oo0OOOo - oo + II11iiII
 if 5 - 5: o0000oOoOoO0o
 if ( eid_only != None ) :
  iIi1i1iIi1iI = 1
 else :
  iIi1i1iIi1iI = lisp . lisp_db_list_length ( )
  if ( iIi1i1iIi1iI == 0 ) : return
  if 26 - 26: OoooooooOO * oo + II11iiII
  if 24 - 24: i11iIiiIii % iIii1I11I1II1 + II11iiII / i11iIiiIii
 lisp . lprint ( "Build Map-Register for {} database-mapping entries" . format ( iIi1i1iIi1iI ) )
 if 70 - 70: ooOO00oOo * O0 . OoOO0ooOOoo0O + oo . oooO0oo0oOOOO
 if 14 - 14: iIii1I11I1II1 % iIii1I11I1II1 * i11iIiiIii - ooOO00oOo - OoOO0ooOOoo0O
 if 63 - 63: ooOO00oOo
 if 69 - 69: iIii1I11I1II1 . oOoO0oo0OOOo % Oo + iIii1I11I1II1 / O0 / oOoO0oo0OOOo
 if 61 - 61: II11iiII % II11iiII * Ooo00oOo00o / Ooo00oOo00o
 o0 = ( iIi1i1iIi1iI > 12 )
 if 96 - 96: oOo0O0Ooo . Ooo00oOo00o - Oo
 if 99 - 99: oooO0oo0oOOOO . OoO0O00 - o0000oOoOoO0o % o0000oOoOoO0o * O0 . II111iiii
 if 4 - 4: o0000oOoOoO0o
 if 51 - 51: ooOO00oOo - O0 % iiiiIi11i - II111iiii
 if 31 - 31: i1I1ii1II1iII / OoO0O00 - i1I1ii1II1iII - II11iiII
 I1iiIIIi11 = { }
 for O0O0O in lisp . lisp_map_servers_list . values ( ) :
  if ( ms_only != None and O0O0O != ms_only ) : continue
  I1iiIIIi11 [ O0O0O . ms_name ] = [ ]
  if 12 - 12: OoooooooOO % Ooo00oOo00o * OoOO0ooOOoo0O % iIii1I11I1II1 / o0000oOoOoO0o
  if 27 - 27: i11iIiiIii % II111iiii % OoOO0ooOOoo0O . O0 - OoO0O00 + oOo0O0Ooo
  if 57 - 57: iIii1I11I1II1 / OoOO0ooOOoo0O - i1IIi
  if 51 - 51: oooO0oo0oOOOO
  if 25 - 25: OoooooooOO + oooO0oo0oOOOO * oOoO0oo0OOOo
 OoO0ooO = lisp . lisp_map_register ( )
 OoO0ooO . nonce = 0xaabbccdddfdfdf00
 OoO0ooO . xtr_id_present = True
 if 51 - 51: i1I1ii1II1iII / Oo * oOo0O0Ooo . i1I1ii1II1iII / oOoO0oo0OOOo / i11iIiiIii
 if ( ttl == None ) : ttl = lisp . LISP_REGISTER_TTL
 if 21 - 21: iiiiIi11i / oOoO0oo0OOOo + o0000oOoOoO0o + OoooooooOO
 if 91 - 91: i11iIiiIii / i1IIi + i1I1ii1II1iII + Oo * i11iIiiIii
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + OoOO0ooOOoo0O * o0oo0o . oooO0oo0oOOOO
 if 52 - 52: Oo + O0 . i1I1ii1II1iII . oOoO0oo0OOOo . ooOO00oOo
 for oo000 in lisp . lisp_db_list :
  if 32 - 32: i1IIi . o0000oOoOoO0o
  if 59 - 59: OoooooooOO
  if 47 - 47: Oo - oo / II111iiii
  if 12 - 12: II11iiII
  if ( I1iiIIIi11 . has_key ( oo000 . use_ms_name ) == False ) : continue
  if 83 - 83: i1I1ii1II1iII . O0 / OoO0O00 / II11iiII - II111iiii
  oO0oO0 = I1iiIIIi11 [ oo000 . use_ms_name ]
  if ( oO0oO0 == [ ] ) :
   oO0oO0 = [ "" , 0 ]
   I1iiIIIi11 [ oo000 . use_ms_name ] . append ( oO0oO0 )
  else :
   oO0oO0 = I1iiIIIi11 [ oo000 . use_ms_name ] [ - 1 ]
   if 14 - 14: i1I1ii1II1iII
   if 99 - 99: i1I1ii1II1iII
   if 38 - 38: oOoO0oo0OOOo - i1I1ii1II1iII / O0 . o0oo0o
   if 45 - 45: o0oo0o
   if 83 - 83: oOo0O0Ooo . OoooooooOO
   if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / oooO0oo0oOOOO / i11iIiiIii
   if 62 - 62: ooOO00oOo / oOoO0oo0OOOo
   if 7 - 7: OoooooooOO . oooO0oo0oOOOO
   if 53 - 53: o0000oOoOoO0o % o0000oOoOoO0o * Ooo00oOo00o + oOo0O0Ooo
   if 92 - 92: OoooooooOO + i1IIi / o0000oOoOoO0o * O0
  o00o0 = ""
  if ( oo000 . dynamic_eid_configured ( ) ) :
   for O00oOo00o0o in oo000 . dynamic_eids . values ( ) :
    O00oO0 = O00oOo00o0o . dynamic_eid
    if ( eid_only == None or eid_only . is_exact_match ( O00oO0 ) ) :
     O0Oo00OoOo , o000oo = O00OO ( o0 , oo000 ,
 O00oO0 , oo000 . group , ttl )
     o00o0 += O0Oo00OoOo
     oO0oO0 [ 1 ] += o000oo
     if 24 - 24: i11iIiiIii - o0oo0o
     if 21 - 21: OoOO0ooOOoo0O
  else :
   if ( eid_only == None ) :
    o00o0 , o000oo = O00OO ( o0 , oo000 ,
 oo000 . eid , oo000 . group , ttl )
    oO0oO0 [ 1 ] += o000oo
    if 92 - 92: i11iIiiIii / o0oo0o - i1I1ii1II1iII % Oo * o0oo0o + OoO0O00
    if 11 - 11: OoooooooOO . o0oo0o
    if 80 - 80: OoooooooOO - II11iiII * o0000oOoOoO0o * oOoO0oo0OOOo / oo / II11iiII
    if 13 - 13: o0oo0o * Oo + i11iIiiIii * o0oo0o - Oo
    if 23 - 23: iIii1I11I1II1 * i1IIi % OoooooooOO * oooO0oo0oOOOO
    if 9 - 9: oooO0oo0oOOOO - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
  oO0oO0 [ 0 ] += o00o0
  if 39 - 39: oooO0oo0oOOOO * OoO0O00 + iIii1I11I1II1 - oooO0oo0oOOOO + II11iiII
  if ( oO0oO0 [ 1 ] == 20 ) :
   oO0oO0 = [ "" , 0 ]
   I1iiIIIi11 [ oo000 . use_ms_name ] . append ( oO0oO0 )
   if 69 - 69: O0
   if 85 - 85: Oo / O0
   if 18 - 18: Ooo00oOo00o % O0 * oOoO0oo0OOOo
   if 62 - 62: o0oo0o . oooO0oo0oOOOO . OoooooooOO
   if 11 - 11: II11iiII / OoOO0ooOOoo0O
   if 73 - 73: i1IIi / i11iIiiIii
 for O0O0O in lisp . lisp_map_servers_list . values ( ) :
  if ( ms_only != None and O0O0O != ms_only ) : continue
  if 58 - 58: OoO0O00 . II111iiii + iiiiIi11i - i11iIiiIii / II111iiii / O0
  for oO0oO0 in I1iiIIIi11 [ O0O0O . ms_name ] :
   if 85 - 85: oOo0O0Ooo + II11iiII
   if 10 - 10: oooO0oo0oOOOO / ooOO00oOo + oOo0O0Ooo / i1IIi
   if 27 - 27: o0000oOoOoO0o
   if 67 - 67: oo
   OoO0ooO . record_count = oO0oO0 [ 1 ]
   if ( OoO0ooO . record_count == 0 ) : continue
   if 55 - 55: oOoO0oo0OOOo - i1I1ii1II1iII * Ooo00oOo00o + oOo0O0Ooo * oOo0O0Ooo * O0
   OoO0ooO . nonce += 1
   OoO0ooO . alg_id = O0O0O . alg_id
   OoO0ooO . key_id = O0O0O . key_id
   OoO0ooO . proxy_reply_requested = O0O0O . proxy_reply
   OoO0ooO . merge_register_requested = O0O0O . merge_registrations
   OoO0ooO . map_notify_requested = O0O0O . want_map_notify
   OoO0ooO . xtr_id = O0O0O . xtr_id
   OoO0ooO . site_id = O0O0O . site_id
   OoO0ooO . encrypt_bit = ( O0O0O . ekey != None )
   if ( O0O0O . refresh_registrations ) :
    OoO0ooO . map_register_refresh = refresh
    if 91 - 91: o0oo0o - II11iiII % iIii1I11I1II1 - OoooooooOO % Oo
   if ( O0O0O . ekey != None ) : OoO0ooO . encryption_key_id = O0O0O . ekey_id
   OO0 = OoO0ooO . encode ( )
   OoO0ooO . print_map_register ( )
   if 44 - 44: i1I1ii1II1iII - o0oo0o / O0 * OoO0O00 + II111iiii / oOo0O0Ooo
   if 88 - 88: Ooo00oOo00o - ooOO00oOo + oOoO0oo0OOOo . o0oo0o % o0oo0o
   if 57 - 57: II111iiii
   if 54 - 54: OoO0O00 + iiiiIi11i + i11iIiiIii
   if 28 - 28: iiiiIi11i
   ooo000o0ooO0 = OoO0ooO . encode_xtr_id ( "" )
   o00o0 = oO0oO0 [ 0 ]
   OO0 = OO0 + o00o0 + ooo000o0ooO0
   if 10 - 10: Oo . i1I1ii1II1iII + ooOO00oOo / OoooooooOO - i1I1ii1II1iII / OoOO0ooOOoo0O
   O0O0O . map_registers_sent += 1
   lisp . lisp_send_map_register ( lisp_sockets , OO0 , OoO0ooO , O0O0O )
   time . sleep ( .001 )
   if 76 - 76: Ooo00oOo00o % oo . iIii1I11I1II1 - oooO0oo0oOOOO * OoooooooOO . i1I1ii1II1iII
   if 84 - 84: o0oo0o + OoOO0ooOOoo0O
   if 28 - 28: iiiiIi11i - i11iIiiIii . oOoO0oo0OOOo + oooO0oo0oOOOO / oOoO0oo0OOOo
   if 35 - 35: oooO0oo0oOOOO
   if 75 - 75: OoO0O00 / oOoO0oo0OOOo . oooO0oo0oOOOO * II11iiII - II111iiii
  O0O0O . resolve_dns_name ( )
  if 41 - 41: o0000oOoOoO0o
  if 77 - 77: o0oo0o
  if 65 - 65: II111iiii . oo % iiiiIi11i * ooOO00oOo
  if 38 - 38: oOo0O0Ooo / i1I1ii1II1iII % OoO0O00
  if 11 - 11: i1I1ii1II1iII - iiiiIi11i + II111iiii - iIii1I11I1II1
  if ( ms_only != None and O0O0O == ms_only ) : break
  if 7 - 7: oooO0oo0oOOOO - OoOO0ooOOoo0O / II111iiii * o0000oOoOoO0o . i1I1ii1II1iII * i1I1ii1II1iII
 return
 if 61 - 61: OoOO0ooOOoo0O % Oo - ooOO00oOo / OoO0O00
 if 4 - 4: OoooooooOO - i1IIi % o0000oOoOoO0o - II11iiII * Ooo00oOo00o
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . i1I1ii1II1iII / OoooooooOO % oo % O0
 if 36 - 36: o0000oOoOoO0o / II111iiii / oooO0oo0oOOOO / oooO0oo0oOOOO + oOoO0oo0OOOo
 if 95 - 95: oooO0oo0oOOOO
 if 51 - 51: II111iiii + oooO0oo0oOOOO . i1IIi . oOoO0oo0OOOo + oOo0O0Ooo * oo
 if 72 - 72: iiiiIi11i + iiiiIi11i / II111iiii . OoooooooOO % o0000oOoOoO0o
 if 49 - 49: iiiiIi11i . ooOO00oOo - OoO0O00 * OoooooooOO . OoO0O00
 if 2 - 2: OoooooooOO % II11iiII
def oOo0O ( ms ) :
 global oOOoo00O0O
 global i1111
 if 63 - 63: oo % iIii1I11I1II1
 lisp . lisp_set_exception ( )
 if 39 - 39: i1I1ii1II1iII / II111iiii / oOoO0oo0OOOo % oo
 if 89 - 89: o0oo0o + OoooooooOO + o0oo0o * i1IIi + iIii1I11I1II1 % OoOO0ooOOoo0O
 if 59 - 59: II11iiII + i11iIiiIii
 if 88 - 88: i11iIiiIii - Oo
 if 67 - 67: II11iiII . OoO0O00 + oOo0O0Ooo - OoooooooOO
 OOOoO = [ i1111 , i1111 , I11 ]
 lisp . lisp_build_info_requests ( OOOoO , ms , lisp . LISP_CTRL_PORT )
 if 14 - 14: OoOO0ooOOoo0O . iIii1I11I1II1 . OoooooooOO . II111iiii / Ooo00oOo00o
 if 21 - 21: i11iIiiIii / i1IIi + oo * II11iiII . o0oo0o
 if 84 - 84: O0 . OoOO0ooOOoo0O - II111iiii . Oo / II111iiii
 if 47 - 47: OoooooooOO
 if 4 - 4: oo % OoOO0ooOOoo0O
 I1 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) == None )
 for OooooOoooO in lisp . lisp_rtr_list . values ( ) :
  if ( OooooOoooO == None ) : continue
  if ( OooooOoooO . is_private_address ( ) and I1 == False ) :
   oOO0o0 = lisp . red ( OooooOoooO . print_address_no_iid ( ) , False )
   lisp . lprint ( "Skip over RTR private address {}" . format ( oOO0o0 ) )
   continue
   if 19 - 19: II111iiii * oooO0oo0oOOOO + o0000oOoOoO0o
  lisp . lisp_build_info_requests ( OOOoO , OooooOoooO , lisp . LISP_DATA_PORT )
  if 65 - 65: II11iiII . o0oo0o . ooOO00oOo . i1I1ii1II1iII - II11iiII
  if 19 - 19: i11iIiiIii + i1I1ii1II1iII % Oo
  if 14 - 14: ooOO00oOo . II111iiii . OoOO0ooOOoo0O / o0000oOoOoO0o % oOoO0oo0OOOo - Oo
  if 67 - 67: OoOO0ooOOoo0O - II11iiII . i1IIi
  if 35 - 35: i1I1ii1II1iII + Oo - iiiiIi11i . i1I1ii1II1iII . oooO0oo0oOOOO
  if 87 - 87: oOo0O0Ooo
 oOOoo00O0O . cancel ( )
 oOOoo00O0O = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 oOo0O , [ None ] )
 oOOoo00O0O . start ( )
 return
 if 25 - 25: i1IIi . ooOO00oOo - oOo0O0Ooo / ooOO00oOo % ooOO00oOo * iIii1I11I1II1
 if 50 - 50: ooOO00oOo . i11iIiiIii - iiiiIi11i . iiiiIi11i
 if 31 - 31: II11iiII / OoO0O00 * i1IIi . oOo0O0Ooo
 if 57 - 57: II11iiII + iIii1I11I1II1 % i1IIi % oo
 if 83 - 83: Ooo00oOo00o / i11iIiiIii % iIii1I11I1II1 . OoOO0ooOOoo0O % iiiiIi11i . OoooooooOO
 if 94 - 94: o0000oOoOoO0o + iIii1I11I1II1 % ooOO00oOo
 if 93 - 93: o0000oOoOoO0o - II11iiII + iIii1I11I1II1 * Ooo00oOo00o + o0oo0o . i1I1ii1II1iII
def ooO0o0Oo ( lisp_sockets ) :
 global o0oOoO00o
 global i1111
 if 49 - 49: OoooooooOO * OoOO0ooOOoo0O - OoO0O00 . iiiiIi11i
 lisp . lisp_set_exception ( )
 if 89 - 89: Oo + o0000oOoOoO0o * Oo / Oo
 if 46 - 46: ooOO00oOo
 if 71 - 71: OoOO0ooOOoo0O / OoOO0ooOOoo0O * iiiiIi11i * iiiiIi11i / II111iiii
 if 35 - 35: II11iiII * Ooo00oOo00o * oo % OoO0O00 . oOo0O0Ooo
 O00oO000O0O ( lisp_sockets , None , None , None , True )
 if 58 - 58: OoOO0ooOOoo0O + II111iiii * i1I1ii1II1iII * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % OoOO0ooOOoo0O * OoOO0ooOOoo0O * oOoO0oo0OOOo
 if 24 - 24: II111iiii % o0oo0o - Oo + oo * oOoO0oo0OOOo
 if 2 - 2: o0000oOoOoO0o - oooO0oo0oOOOO
 if ( lisp . lisp_l2_overlay ) :
  OO0OO00oo0 = [ None , "ffff-ffff-ffff" , True ]
  iIIIiIii ( lisp_sockets , [ OO0OO00oo0 ] )
  if 71 - 71: OoooooooOO
  if 33 - 33: o0oo0o
  if 62 - 62: oOoO0oo0OOOo + o0000oOoOoO0o + i1IIi / OoooooooOO
  if 7 - 7: Ooo00oOo00o + i1IIi . oo / OoO0O00
  if 22 - 22: Oo - Oo % II11iiII . o0oo0o + iiiiIi11i
 if ( o0oOoO00o ) : o0oOoO00o . cancel ( )
 o0oOoO00o = threading . Timer ( oOOoo ,
 ooO0o0Oo , [ Oo0o0000o0o0 ] )
 o0oOoO00o . start ( )
 return
 if 63 - 63: oo % o0oo0o * Ooo00oOo00o + o0oo0o / OoO0O00 % i1I1ii1II1iII
 if 45 - 45: oooO0oo0oOOOO
 if 20 - 20: OoooooooOO * Ooo00oOo00o * O0 . II11iiII
 if 78 - 78: iIii1I11I1II1 + OoOO0ooOOoo0O - o0000oOoOoO0o * o0oo0o - OoooooooOO % oOo0O0Ooo
 if 34 - 34: O0
 if 80 - 80: i1IIi - OoO0O00 / ooOO00oOo - i11iIiiIii
 if 68 - 68: iiiiIi11i - oOoO0oo0OOOo % O0 % o0oo0o
 if 11 - 11: O0 / ooOO00oOo % II11iiII + Ooo00oOo00o + iIii1I11I1II1
 if 40 - 40: Oo - II11iiII . o0000oOoOoO0o * OoO0O00 % o0oo0o
def OoO ( group_str , group_mapping ) :
 II1I = group_mapping . group_prefix . instance_id
 O00OOOo0 = group_mapping . group_prefix . mask_len
 i1111IIiii1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , group_str , 32 , II1I )
 if ( i1111IIiii1 . is_more_specific ( group_mapping . group_prefix ) ) : return ( O00OOOo0 )
 return ( - 1 )
 if 49 - 49: II11iiII . iIii1I11I1II1
 if 62 - 62: oOo0O0Ooo / oo - oOoO0oo0OOOo - oo + i11iIiiIii + i1IIi
 if 23 - 23: i1I1ii1II1iII + OoOO0ooOOoo0O . oOo0O0Ooo * oo + oOoO0oo0OOOo
 if 18 - 18: oooO0oo0oOOOO * Ooo00oOo00o . oooO0oo0oOOOO / O0
 if 8 - 8: Ooo00oOo00o
 if 4 - 4: oOoO0oo0OOOo + oOoO0oo0OOOo * Oo - oOo0O0Ooo
 if 78 - 78: o0000oOoOoO0o / II111iiii % oOo0O0Ooo
 if 52 - 52: II11iiII - i1I1ii1II1iII * iiiiIi11i
 if 17 - 17: OoooooooOO + II11iiII * OoOO0ooOOoo0O * oOo0O0Ooo
 if 36 - 36: O0 + OoO0O00
 if 5 - 5: OoO0O00 * oOo0O0Ooo
def iIIIiIii ( lisp_sockets , entries ) :
 ii1I11iIiIII1 = len ( entries )
 if ( ii1I11iIiIII1 == 0 ) : return
 if 52 - 52: Ooo00oOo00o * oooO0oo0oOOOO + oOo0O0Ooo
 IiiiIiiI = None
 if ( entries [ 0 ] [ 1 ] . find ( ":" ) != - 1 ) : IiiiIiiI = lisp . LISP_AFI_IPV6
 if ( entries [ 0 ] [ 1 ] . find ( "." ) != - 1 ) : IiiiIiiI = lisp . LISP_AFI_IPV4
 if ( entries [ 0 ] [ 1 ] . find ( "-" ) != - 1 ) : IiiiIiiI = lisp . LISP_AFI_MAC
 if ( IiiiIiiI == None ) :
  lisp . lprint ( "lisp_send_multicast_map_register() invalid group address" )
  return
  if 72 - 72: i1IIi
  if 82 - 82: oOo0O0Ooo + OoooooooOO / i11iIiiIii * oOoO0oo0OOOo . OoooooooOO
  if 63 - 63: oOoO0oo0OOOo
  if 6 - 6: Oo / oOoO0oo0OOOo
  if 57 - 57: OoOO0ooOOoo0O
  if 67 - 67: ooOO00oOo . Oo
 oO00oOo0OOO = [ ]
 for II1iIi11 , i1111IIiii1 , ii1 in entries :
  if ( II1iIi11 != None ) : continue
  oO00oOo0OOO . append ( [ i1111IIiii1 , ii1 ] )
  if 51 - 51: O0 . iiiiIi11i + i11iIiiIii
  if 79 - 79: oOo0O0Ooo . iiiiIi11i . oooO0oo0oOOOO % o0000oOoOoO0o
 entries = [ ]
 for i1111IIiii1 , ii1 in oO00oOo0OOO :
  OoOo00 = None
  for o0OO0oOO0O0 in lisp . lisp_group_mapping_list . values ( ) :
   O00OOOo0 = OoO ( i1111IIiii1 , o0OO0oOO0O0 )
   if ( O00OOOo0 == - 1 ) : continue
   if ( OoOo00 == None or O00OOOo0 > OoOo00 . group_prefix . mask_len ) :
    OoOo00 = o0OO0oOO0O0
    if 39 - 39: o0000oOoOoO0o % O0 % oOo0O0Ooo . i1IIi
    if 86 - 86: ooOO00oOo * OoooooooOO
  if ( OoOo00 == None ) :
   lisp . lprint ( "No group-mapping for {}, could be underlay group" . format ( i1111IIiii1 ) )
   if 71 - 71: iIii1I11I1II1 - II11iiII . oo % OoooooooOO + II11iiII
   continue
   if 26 - 26: OoO0O00 + II11iiII / ooOO00oOo % oOo0O0Ooo % oOoO0oo0OOOo + II111iiii
   if 31 - 31: OoOO0ooOOoo0O % II11iiII * OoOO0ooOOoo0O
  lisp . lprint ( "Use group-mapping '{}' {} for group {}" . format ( OoOo00 . group_name , OoOo00 . group_prefix . print_prefix ( ) , i1111IIiii1 ) )
  if 45 - 45: i1IIi . oo + II11iiII - OoooooooOO % Oo
  II1I = OoOo00 . group_prefix . instance_id
  oO0Oo = OoOo00 . use_ms_name
  i1I = OoOo00 . rle_address
  if 7 - 7: i11iIiiIii . OoO0O00
  if ( len ( OoOo00 . sources ) == 0 ) :
   entries . append ( [ "0.0.0.0" , i1111IIiii1 , II1I , oO0Oo , i1I , ii1 ] )
   continue
   if 99 - 99: OoOO0ooOOoo0O - o0oo0o - iiiiIi11i % ooOO00oOo
  for o0O00oOoOO in OoOo00 . sources :
   entries . append ( [ o0O00oOoOO , i1111IIiii1 , II1I , oO0Oo , i1I , ii1 ] )
   if 21 - 21: II111iiii % oOoO0oo0OOOo . i1IIi - OoooooooOO
   if 4 - 4: OoooooooOO . Oo
   if 78 - 78: oOoO0oo0OOOo + OoOO0ooOOoo0O - O0
 ii1I11iIiIII1 = len ( entries )
 if ( ii1I11iIiIII1 == 0 ) : return
 if 10 - 10: o0oo0o % oo
 lisp . lprint ( "Build Map-Register for {} multicast entries" . format ( ii1I11iIiIII1 ) )
 if 97 - 97: OoooooooOO - o0oo0o
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: Oo % i1I1ii1II1iII * II11iiII - oOoO0oo0OOOo * o0000oOoOoO0o % Oo
 if 46 - 46: i11iIiiIii - O0 . iiiiIi11i
 if 100 - 100: oo / Ooo00oOo00o * i1I1ii1II1iII . O0 / II11iiII
 if 83 - 83: o0oo0o
 ii111Ii11iii = lisp . lisp_rle_node ( )
 ii111Ii11iii . level = 128
 o00 = lisp . lisp_get_any_translated_rloc ( )
 i1I = lisp . lisp_rle ( "" )
 i1I . rle_nodes . append ( ii111Ii11iii )
 if 67 - 67: Ooo00oOo00o % oOo0O0Ooo . oOo0O0Ooo - Oo
 if 90 - 90: Oo + II111iiii * oOoO0oo0OOOo / o0000oOoOoO0o . Ooo00oOo00o + Ooo00oOo00o
 if 40 - 40: Oo / oOo0O0Ooo % i11iIiiIii % oOoO0oo0OOOo / oo
 if 62 - 62: i1IIi - oOo0O0Ooo
 if 62 - 62: i1IIi + OoO0O00 % oooO0oo0oOOOO
 I1iiIIIi11 = { }
 for O0O0O in lisp . lisp_map_servers_list . values ( ) :
  I1iiIIIi11 [ O0O0O . ms_name ] = [ "" , 0 ]
  if 28 - 28: oOoO0oo0OOOo . i1IIi
  if 10 - 10: ooOO00oOo / OoO0O00
 I1i = None
 if ( lisp . lisp_nat_traversal ) : I1i = lisp . lisp_hostname
 if 50 - 50: Ooo00oOo00o * o0000oOoOoO0o % oOoO0oo0OOOo / OoO0O00 - O0 % i1I1ii1II1iII
 if 48 - 48: oo + oOoO0oo0OOOo + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * iiiiIi11i - o0000oOoOoO0o / II11iiII + OoOO0ooOOoo0O + oooO0oo0oOOOO
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 oO0oooooo = 0
 for OooooOoooO in lisp . lisp_rtr_list . values ( ) :
  if ( OooooOoooO == None ) : continue
  oO0oooooo += 1
  if 65 - 65: oooO0oo0oOOOO + OoO0O00
  if 59 - 59: OoooooooOO + OoOO0ooOOoo0O . o0oo0o - O0 % iIii1I11I1II1 / O0
  if 88 - 88: OoO0O00 . O0 % OoooooooOO / II11iiII
  if 89 - 89: II111iiii / iiiiIi11i
  if 14 - 14: II11iiII . oo * Oo + II111iiii - Oo + II11iiII
 o00o0 = ""
 for II1iIi11 , i1111IIiii1 , II1I , oO0Oo , IIIIIiII1 , ii1 in entries :
  if 45 - 45: oo / i1I1ii1II1iII . i1I1ii1II1iII
  if 35 - 35: o0oo0o . oOo0O0Ooo * i11iIiiIii
  if 44 - 44: i11iIiiIii / OoO0O00
  if 42 - 42: OoooooooOO + OoO0O00 % II111iiii + ooOO00oOo
  if ( I1iiIIIi11 . has_key ( oO0Oo ) == False ) : continue
  if 24 - 24: i1I1ii1II1iII * II111iiii % i1I1ii1II1iII % oooO0oo0oOOOO + OoooooooOO
  II1I1I1Ii = lisp . lisp_eid_record ( )
  II1I1I1Ii . rloc_count = 1 + oO0oooooo
  II1I1I1Ii . authoritative = True
  II1I1I1Ii . record_ttl = lisp . LISP_REGISTER_TTL if ii1 else 0
  II1I1I1Ii . eid = lisp . lisp_address ( IiiiIiiI , II1iIi11 , 0 , II1I )
  if ( II1I1I1Ii . eid . address == 0 ) : II1I1I1Ii . eid . mask_len = 0
  II1I1I1Ii . group = lisp . lisp_address ( IiiiIiiI , i1111IIiii1 , 0 , II1I )
  if ( II1I1I1Ii . group . is_mac_broadcast ( ) and II1I1I1Ii . eid . address == 0 ) : II1I1I1Ii . eid . mask_len = 0
  if 29 - 29: II111iiii - OoooooooOO - i11iIiiIii . Ooo00oOo00o
  if 19 - 19: II111iiii
  lisp . lprint ( "  EID-prefix {} for ms-name '{}'" . format ( lisp . green ( II1I1I1Ii . print_eid_tuple ( ) , False ) , oO0Oo ) )
  if 72 - 72: OoooooooOO / oo + o0000oOoOoO0o / oOo0O0Ooo * o0000oOoOoO0o
  if 34 - 34: O0 * O0 % OoooooooOO + i1I1ii1II1iII * iIii1I11I1II1 % o0000oOoOoO0o
  o00o0 += II1I1I1Ii . encode ( )
  II1I1I1Ii . print_record ( "  " , False )
  I1iiIIIi11 [ oO0Oo ] [ 1 ] += 1
  if 25 - 25: OoOO0ooOOoo0O + oOo0O0Ooo . Ooo00oOo00o % oOo0O0Ooo * II11iiII
  if 32 - 32: i11iIiiIii - o0oo0o
  if 53 - 53: OoooooooOO - oooO0oo0oOOOO
  if 87 - 87: iiiiIi11i . oo
  iII1ii1 = lisp . lisp_rloc_record ( )
  iII1ii1 . rloc_name = I1i
  if 17 - 17: o0000oOoOoO0o . i11iIiiIii
  if 5 - 5: oOoO0oo0OOOo + O0 + O0 . o0oo0o - Oo
  if 63 - 63: iiiiIi11i
  if 71 - 71: i1IIi . o0000oOoOoO0o * i1I1ii1II1iII % OoooooooOO + II11iiII
  if 36 - 36: oooO0oo0oOOOO
  if 49 - 49: II11iiII / OoooooooOO / oo
  if ( o00 != None ) :
   ii111Ii11iii . address = o00
  elif ( IIIIIiII1 != None ) :
   ii111Ii11iii . address = IIIIIiII1
  else :
   ii111Ii11iii . address = IIIIIiII1 = lisp . lisp_myrlocs [ 0 ]
   if 74 - 74: o0oo0o % oOoO0oo0OOOo
   if 7 - 7: II111iiii
  iII1ii1 . rle = i1I
  iII1ii1 . local_bit = True
  iII1ii1 . reach_bit = True
  iII1ii1 . priority = 255
  iII1ii1 . weight = 0
  iII1ii1 . mpriority = 1
  iII1ii1 . mweight = 100
  o00o0 += iII1ii1 . encode ( )
  iII1ii1 . print_record ( "    " )
  if 27 - 27: iiiiIi11i . OoooooooOO + i11iIiiIii
  if 86 - 86: OoOO0ooOOoo0O / Ooo00oOo00o - Ooo00oOo00o + oOoO0oo0OOOo + iiiiIi11i
  if 33 - 33: Ooo00oOo00o . i1I1ii1II1iII . oooO0oo0oOOOO . i1IIi
  if 49 - 49: oOoO0oo0OOOo
  if 84 - 84: OoOO0ooOOoo0O - OoO0O00 / O0 - o0oo0o
  for OooooOoooO in lisp . lisp_rtr_list . values ( ) :
   if ( OooooOoooO == None ) : continue
   iII1ii1 = lisp . lisp_rloc_record ( )
   iII1ii1 . rloc . copy_address ( OooooOoooO )
   iII1ii1 . priority = 254
   iII1ii1 . rloc_name = "RTR"
   iII1ii1 . weight = 0
   iII1ii1 . mpriority = 255
   iII1ii1 . mweight = 0
   iII1ii1 . local_bit = False
   iII1ii1 . reach_bit = True
   o00o0 += iII1ii1 . encode ( )
   iII1ii1 . print_record ( "    RTR " )
   if 21 - 21: O0 * O0 % oOoO0oo0OOOo
   if 94 - 94: OoOO0ooOOoo0O + II111iiii % i11iIiiIii
   if 8 - 8: Oo * O0
   if 73 - 73: Ooo00oOo00o / iiiiIi11i / OoOO0ooOOoo0O / ooOO00oOo
   if 11 - 11: oOo0O0Ooo + oooO0oo0oOOOO - OoooooooOO / ooOO00oOo
  I1iiIIIi11 [ oO0Oo ] [ 0 ] += o00o0
  if 34 - 34: Oo
  if 45 - 45: Oo / OoO0O00 / o0000oOoOoO0o
  if 44 - 44: oOoO0oo0OOOo - o0000oOoOoO0o / II111iiii * ooOO00oOo * OoO0O00
  if 73 - 73: Ooo00oOo00o - oo * i1IIi / i11iIiiIii * II11iiII % II111iiii
  if 56 - 56: OoooooooOO * OoO0O00 . OoO0O00 . oOoO0oo0OOOo
 OoO0ooO = lisp . lisp_map_register ( )
 OoO0ooO . nonce = 0xaabbccdddfdfdf00
 OoO0ooO . xtr_id_present = True
 OoO0ooO . proxy_reply_requested = True
 OoO0ooO . map_notify_requested = False
 OoO0ooO . merge_register_requested = True
 if 24 - 24: OoO0O00 . OoOO0ooOOoo0O * o0000oOoOoO0o % i1I1ii1II1iII / II11iiII
 if 58 - 58: oo - oOoO0oo0OOOo % O0 . oo % ooOO00oOo % oooO0oo0oOOOO
 if 87 - 87: iiiiIi11i - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - Ooo00oOo00o
 for O0O0O in lisp . lisp_map_servers_list . values ( ) :
  if 23 - 23: OoOO0ooOOoo0O
  if 40 - 40: Ooo00oOo00o - II111iiii / OoO0O00
  if 14 - 14: oOoO0oo0OOOo
  if 5 - 5: Ooo00oOo00o . iIii1I11I1II1 % iIii1I11I1II1
  if ( I1iiIIIi11 . has_key ( O0O0O . ms_name ) == False ) : continue
  if 56 - 56: OoooooooOO - OoOO0ooOOoo0O - i1IIi
  if 8 - 8: o0oo0o / II11iiII . oo + oOoO0oo0OOOo / i11iIiiIii
  if 31 - 31: Oo - iIii1I11I1II1 + i1I1ii1II1iII . OoO0O00 / oooO0oo0oOOOO % iIii1I11I1II1
  if 6 - 6: oooO0oo0oOOOO * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + Ooo00oOo00o / i1IIi
  OoO0ooO . record_count = I1iiIIIi11 [ O0O0O . ms_name ] [ 1 ]
  if ( OoO0ooO . record_count == 0 ) : continue
  if 53 - 53: OoOO0ooOOoo0O + iIii1I11I1II1
  OoO0ooO . nonce += 1
  OoO0ooO . alg_id = O0O0O . alg_id
  OoO0ooO . alg_id = O0O0O . key_id
  OoO0ooO . xtr_id = O0O0O . xtr_id
  OoO0ooO . site_id = O0O0O . site_id
  OoO0ooO . encrypt_bit = ( O0O0O . ekey != None )
  OO0 = OoO0ooO . encode ( )
  OoO0ooO . print_map_register ( )
  if 70 - 70: oOoO0oo0OOOo
  if 67 - 67: OoooooooOO
  if 29 - 29: O0 - i11iIiiIii - II111iiii + II11iiII * oooO0oo0oOOOO
  if 2 - 2: i1IIi - Oo + oo . Ooo00oOo00o * Ooo00oOo00o / oOo0O0Ooo
  if 93 - 93: i1IIi
  ooo000o0ooO0 = OoO0ooO . encode_xtr_id ( "" )
  OO0 = OO0 + o00o0 + ooo000o0ooO0
  if 53 - 53: OoooooooOO + OoO0O00 + iiiiIi11i
  O0O0O . map_registers_multicast_sent += 1
  lisp . lisp_send_map_register ( lisp_sockets , OO0 , OoO0ooO , O0O0O )
  if 24 - 24: i1I1ii1II1iII - oooO0oo0oOOOO - i1I1ii1II1iII * oOoO0oo0OOOo . OoooooooOO / oooO0oo0oOOOO
  if 66 - 66: OoO0O00
  if 97 - 97: i1IIi - OoooooooOO / o0oo0o * oo
  if 55 - 55: Ooo00oOo00o . i1I1ii1II1iII
  O0O0O . resolve_dns_name ( )
  if 87 - 87: Ooo00oOo00o % iIii1I11I1II1
  if 100 - 100: o0oo0o . oo * o0oo0o - oo . OoOO0ooOOoo0O * o0000oOoOoO0o
  if 89 - 89: ooOO00oOo + oooO0oo0oOOOO * o0oo0o
  if 28 - 28: OoooooooOO . iiiiIi11i % oOoO0oo0OOOo / i1IIi / II11iiII
  time . sleep ( .001 )
  if 36 - 36: Ooo00oOo00o + OoOO0ooOOoo0O - oooO0oo0oOOOO + iIii1I11I1II1 + OoooooooOO
 return
 if 4 - 4: II111iiii . OoOO0ooOOoo0O + o0000oOoOoO0o * o0oo0o . Oo
 if 87 - 87: oOo0O0Ooo / ooOO00oOo / i11iIiiIii
 if 74 - 74: iiiiIi11i / oOoO0oo0OOOo % Ooo00oOo00o
 if 88 - 88: oOo0O0Ooo - i11iIiiIii % Ooo00oOo00o * OoOO0ooOOoo0O + oOoO0oo0OOOo
 if 52 - 52: II111iiii . oo + oOo0O0Ooo % ooOO00oOo
oo0O0o00 = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 70 - 70: ooOO00oOo
if 46 - 46: OoOO0ooOOoo0O - i1IIi
if 46 - 46: o0oo0o % o0000oOoOoO0o
if 72 - 72: iIii1I11I1II1
if 45 - 45: OoO0O00 - Ooo00oOo00o % o0oo0o
if 38 - 38: o0oo0o % II11iiII - OoooooooOO
if 87 - 87: ooOO00oOo % oo
if 77 - 77: iIii1I11I1II1 - i1IIi . iiiiIi11i
if 26 - 26: Ooo00oOo00o * oooO0oo0oOOOO . i1IIi
if 59 - 59: O0 + i1IIi - Ooo00oOo00o
if 62 - 62: i11iIiiIii % II11iiII . oooO0oo0oOOOO . II11iiII
if 84 - 84: i11iIiiIii * ooOO00oOo
if 18 - 18: II11iiII - o0000oOoOoO0o - oOo0O0Ooo / o0oo0o - O0
if 30 - 30: O0 + oOoO0oo0OOOo + II111iiii
if 14 - 14: Ooo00oOo00o / II11iiII - iIii1I11I1II1 - iiiiIi11i % Oo
if 49 - 49: Oo * iiiiIi11i / Ooo00oOo00o / OoO0O00 * iIii1I11I1II1
if 57 - 57: oOo0O0Ooo - iiiiIi11i / Oo % i11iIiiIii
if 3 - 3: i1I1ii1II1iII . Oo % oo + oOoO0oo0OOOo
if 64 - 64: i1IIi
if 29 - 29: Ooo00oOo00o / i11iIiiIii / oo % iiiiIi11i % i11iIiiIii
if 18 - 18: II11iiII + o0oo0o
if 80 - 80: iiiiIi11i + Ooo00oOo00o * o0000oOoOoO0o + ooOO00oOo
if 75 - 75: OoOO0ooOOoo0O / Ooo00oOo00o / II11iiII / oooO0oo0oOOOO % Oo + II111iiii
if 4 - 4: i1I1ii1II1iII - OoO0O00 - oooO0oo0oOOOO - OoOO0ooOOoo0O % i11iIiiIii / ooOO00oOo
if 50 - 50: Oo + i1IIi
if 31 - 31: o0000oOoOoO0o
if 78 - 78: i11iIiiIii + Ooo00oOo00o + o0oo0o / Ooo00oOo00o % iIii1I11I1II1 % oooO0oo0oOOOO
if 83 - 83: iIii1I11I1II1 % oOo0O0Ooo % Ooo00oOo00o % o0oo0o . oOoO0oo0OOOo % O0
if 47 - 47: Ooo00oOo00o
if 66 - 66: oo - oooO0oo0oOOOO
if 33 - 33: oo / ooOO00oOo
if 12 - 12: II111iiii
if 2 - 2: i1IIi - oo + OoOO0ooOOoo0O . II111iiii
if 25 - 25: iiiiIi11i
if 34 - 34: oOo0O0Ooo . iIii1I11I1II1 % O0
if 43 - 43: oOoO0oo0OOOo - i1I1ii1II1iII
if 70 - 70: i1I1ii1II1iII / II11iiII % Oo - o0000oOoOoO0o
if 47 - 47: i1I1ii1II1iII
if 92 - 92: II11iiII + oOo0O0Ooo % i1IIi
if 23 - 23: o0oo0o - II11iiII + o0000oOoOoO0o - oOo0O0Ooo * oOo0O0Ooo . OoO0O00
if 47 - 47: iiiiIi11i % iIii1I11I1II1
if 11 - 11: oo % o0000oOoOoO0o - ooOO00oOo - iiiiIi11i + Ooo00oOo00o
if 98 - 98: i1I1ii1II1iII + o0000oOoOoO0o - ooOO00oOo
if 79 - 79: II11iiII / o0oo0o . oOo0O0Ooo - oOoO0oo0OOOo
if 47 - 47: OoooooooOO % O0 * i1I1ii1II1iII . o0000oOoOoO0o
if 38 - 38: O0 - oooO0oo0oOOOO % o0oo0o
if 64 - 64: iIii1I11I1II1
if 15 - 15: oOoO0oo0OOOo + II11iiII / oOoO0oo0OOOo / o0oo0o
if 31 - 31: Oo + O0 + Oo . iIii1I11I1II1 + OoO0O00 / Ooo00oOo00o
if 6 - 6: OoO0O00 % oooO0oo0oOOOO * OoOO0ooOOoo0O / oo + OoO0O00
if 39 - 39: oOo0O0Ooo - OoO0O00 / i1I1ii1II1iII * OoooooooOO
if 100 - 100: O0 . OoOO0ooOOoo0O . ooOO00oOo + O0 * iiiiIi11i
if 42 - 42: iiiiIi11i % OoooooooOO + Ooo00oOo00o
if 56 - 56: OoooooooOO + oOoO0oo0OOOo - i1I1ii1II1iII
if 24 - 24: Ooo00oOo00o + Oo + OoOO0ooOOoo0O - iIii1I11I1II1
if 49 - 49: OoOO0ooOOoo0O . Oo * oOo0O0Ooo % oooO0oo0oOOOO . O0
if 48 - 48: O0 * o0000oOoOoO0o - O0 / o0000oOoOoO0o + oOo0O0Ooo
if 52 - 52: ooOO00oOo % o0000oOoOoO0o * II111iiii
if 4 - 4: OoOO0ooOOoo0O % O0 - OoooooooOO + Oo . iiiiIi11i % II111iiii
if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
if 18 - 18: ooOO00oOo . II111iiii % oOo0O0Ooo % o0000oOoOoO0o
if 87 - 87: iIii1I11I1II1 . OoooooooOO * oOo0O0Ooo
if 100 - 100: ooOO00oOo / i1IIi - oo % o0000oOoOoO0o - iIii1I11I1II1
if 17 - 17: OoOO0ooOOoo0O / Ooo00oOo00o % OoO0O00
if 71 - 71: oooO0oo0oOOOO . o0oo0o . ooOO00oOo
if 68 - 68: i11iIiiIii % iiiiIi11i * ooOO00oOo * oooO0oo0oOOOO * II111iiii + O0
if 66 - 66: OoOO0ooOOoo0O % oOoO0oo0OOOo % OoooooooOO
if 34 - 34: Ooo00oOo00o / i1I1ii1II1iII % O0 . ooOO00oOo . i1IIi
if 29 - 29: O0 . o0oo0o
if 66 - 66: iiiiIi11i * iIii1I11I1II1 % iIii1I11I1II1 * oooO0oo0oOOOO - Oo - oooO0oo0oOOOO
if 70 - 70: o0oo0o + iiiiIi11i
if 93 - 93: o0oo0o + o0000oOoOoO0o
if 33 - 33: O0
if 78 - 78: O0 / II111iiii * ooOO00oOo
if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % o0oo0o - iIii1I11I1II1 % O0
def o0oO0Oo ( packet ) :
 global Oo0o0000o0o0
 if 71 - 71: Ooo00oOo00o - oOo0O0Ooo * i1I1ii1II1iII + o0000oOoOoO0o % i11iIiiIii - Oo
 oOO0o0 = lisp . bold ( "Receive" , False )
 lisp . lprint ( "{} {}-byte IGMP packet: {}" . format ( oOO0o0 , len ( packet ) ,
 lisp . lisp_format_packet ( packet ) ) )
 if 82 - 82: o0oo0o - II11iiII + ooOO00oOo
 if 64 - 64: Ooo00oOo00o . O0 * o0000oOoOoO0o + OoooooooOO - OoO0O00 . OoooooooOO
 if 70 - 70: OoO0O00 - iiiiIi11i . iIii1I11I1II1 % OoOO0ooOOoo0O / oOo0O0Ooo - O0
 if 55 - 55: i1I1ii1II1iII - ooOO00oOo
 o0i1I11iI1iiI = ( struct . unpack ( "B" , packet [ 0 ] ) [ 0 ] & 0x0f ) * 4
 if 48 - 48: OoOO0ooOOoo0O . OoooooooOO . oo . oOo0O0Ooo % oOoO0oo0OOOo / i1I1ii1II1iII
 if 11 - 11: i1IIi % ooOO00oOo % i1I1ii1II1iII
 if 99 - 99: Oo / iIii1I11I1II1 - o0000oOoOoO0o * oOoO0oo0OOOo % oo
 if 13 - 13: ooOO00oOo
 O0oo0O0 = packet [ o0i1I11iI1iiI : : ]
 iiII111iIII1Ii = struct . unpack ( "B" , O0oo0O0 [ 0 ] ) [ 0 ]
 i1111IIiii1 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 19 - 19: iiiiIi11i * oo % i11iIiiIii
 iiI1Ii1I = ( iiII111iIII1Ii in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( iiI1Ii1I == False ) :
  i11Ii1iIiII = "{} ({})" . format ( iiII111iIII1Ii , IiII1IiiIiI1 [ iiII111iIII1Ii ] ) if IiII1IiiIiI1 . has_key ( iiII111iIII1Ii ) else iiII111iIII1Ii
  if 81 - 81: OoOO0ooOOoo0O . OoooooooOO * oOo0O0Ooo % oooO0oo0oOOOO . OoOO0ooOOoo0O
  lisp . lprint ( "IGMP type {} not supported" . format ( i11Ii1iIiII ) )
  return
  if 60 - 60: II11iiII / oo
  if 78 - 78: OoOO0ooOOoo0O . oooO0oo0oOOOO
 if ( len ( O0oo0O0 ) < 8 ) :
  lisp . lprint ( "IGMP message too small" )
  return
  if 38 - 38: oOo0O0Ooo + oooO0oo0oOOOO
  if 15 - 15: OoO0O00 + OoOO0ooOOoo0O . Oo - iIii1I11I1II1 / O0 % iIii1I11I1II1
  if 86 - 86: oo / iiiiIi11i * o0000oOoOoO0o
  if 64 - 64: Oo / O0 * oOo0O0Ooo * Oo
  if 60 - 60: OoOO0ooOOoo0O / i1IIi % oOoO0oo0OOOo / oOoO0oo0OOOo * oOoO0oo0OOOo . i11iIiiIii
  if 99 - 99: oOo0O0Ooo
 i1111IIiii1 . address = socket . ntohl ( struct . unpack ( "II" , O0oo0O0 [ : 8 ] ) [ 1 ] )
 oO00OoOo = i1111IIiii1 . print_address_no_iid ( )
 if 74 - 74: II111iiii . O0 - oo + oooO0oo0oOOOO % i11iIiiIii % oOo0O0Ooo
 if 78 - 78: o0000oOoOoO0o + oOo0O0Ooo + oooO0oo0oOOOO - oooO0oo0oOOOO . i11iIiiIii / ooOO00oOo
 if 27 - 27: o0000oOoOoO0o - O0 % OoOO0ooOOoo0O * o0oo0o . oooO0oo0oOOOO % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % Oo
 if ( iiII111iIII1Ii == 0x17 ) :
  lisp . lprint ( "IGMPv2 leave (*, {})" . format ( lisp . bold ( oO00OoOo , False ) ) )
  iIIIiIii ( Oo0o0000o0o0 ,
 [ [ None , oO00OoOo , False ] ] )
  return
  if 24 - 24: oOo0O0Ooo
 if ( iiII111iIII1Ii in ( 0x12 , 0x16 ) ) :
  lisp . lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( iiII111iIII1Ii == 0x12 ) else 2 , lisp . bold ( oO00OoOo , False ) ) )
  if 94 - 94: i1IIi * i1IIi % II111iiii + II11iiII
  if 28 - 28: oo
  if 49 - 49: OoOO0ooOOoo0O . Ooo00oOo00o % iiiiIi11i / o0000oOoOoO0o
  if 95 - 95: O0 * oOo0O0Ooo * oooO0oo0oOOOO . Oo / iIii1I11I1II1
  if 28 - 28: oooO0oo0oOOOO + iiiiIi11i - Oo / iIii1I11I1II1 - oo
  if ( oO00OoOo . find ( "224.0.0." ) != - 1 ) :
   lisp . lprint ( "Suppress registration for link-local groups" )
  else :
   iIIIiIii ( Oo0o0000o0o0 ,
 [ [ None , oO00OoOo , True ] ] )
   if 45 - 45: O0 / i1IIi * iiiiIi11i * ooOO00oOo
   if 35 - 35: oOoO0oo0OOOo / i1I1ii1II1iII % oo + iIii1I11I1II1
   if 79 - 79: oOo0O0Ooo / Oo
   if 77 - 77: OoO0O00
   if 46 - 46: o0oo0o
  return
  if 72 - 72: i1I1ii1II1iII * II11iiII
  if 67 - 67: i1IIi
  if 5 - 5: II111iiii . OoooooooOO
  if 57 - 57: oo
  if 35 - 35: OoooooooOO - o0oo0o / ooOO00oOo
 iii11i1 = i1111IIiii1 . address
 O0oo0O0 = O0oo0O0 [ 8 : : ]
 if 48 - 48: Oo * oOoO0oo0OOOo
 II111iIiI1Ii = "BBHI"
 Ii1iiII1i = struct . calcsize ( II111iIiI1Ii )
 oO00O = "I"
 IIiI11 = struct . calcsize ( oO00O )
 II1iIi11 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 9 - 9: Oo + II111iiii % Oo % oooO0oo0oOOOO + iIii1I11I1II1
 if 59 - 59: i1IIi
 if 48 - 48: O0 * o0000oOoOoO0o * ooOO00oOo . ooOO00oOo * OoOO0ooOOoo0O - o0000oOoOoO0o
 if 14 - 14: oOoO0oo0OOOo + i11iIiiIii
 OOOoo = [ ]
 for OO in range ( iii11i1 ) :
  if ( len ( O0oo0O0 ) < Ii1iiII1i ) : return
  III1II1iii1i , O0OO0oOO , ooooO , oO0O0 = struct . unpack ( II111iIiI1Ii ,
 O0oo0O0 [ : Ii1iiII1i ] )
  if 19 - 19: o0000oOoOoO0o
  O0oo0O0 = O0oo0O0 [ Ii1iiII1i : : ]
  if 55 - 55: II11iiII % II11iiII / O0 % i1I1ii1II1iII - Ooo00oOo00o . OoO0O00
  if ( oo0O0o00 . has_key ( III1II1iii1i ) == False ) :
   lisp . lprint ( "Invalid record type {}" . format ( III1II1iii1i ) )
   continue
   if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
   if 90 - 90: Ooo00oOo00o % oOoO0oo0OOOo - iIii1I11I1II1 % oOo0O0Ooo
  IIiI11I1I1i1i = oo0O0o00 [ III1II1iii1i ]
  ooooO = socket . ntohs ( ooooO )
  i1111IIiii1 . address = socket . ntohl ( oO0O0 )
  oO00OoOo = i1111IIiii1 . print_address_no_iid ( )
  if 86 - 86: i1IIi
  lisp . lprint ( "Record type: {}, group: {}, source-count: {}" . format ( IIiI11I1I1i1i , oO00OoOo , ooooO ) )
  if 13 - 13: O0
  if 70 - 70: o0000oOoOoO0o . i11iIiiIii % o0000oOoOoO0o . O0 - iIii1I11I1II1
  if 26 - 26: II11iiII
  if 76 - 76: i1IIi * OoooooooOO * O0 + o0oo0o * o0oo0o
  if 35 - 35: Ooo00oOo00o
  if 73 - 73: O0 - oOoO0oo0OOOo
  if 2 - 2: II111iiii / o0oo0o
  ii1 = False
  if ( III1II1iii1i in ( 1 , 5 ) ) : ii1 = True
  if ( III1II1iii1i == 4 and ooooO == 0 ) : ii1 = True
  OoOoO0oOOooo = "join" if ( ii1 ) else "leave"
  if 99 - 99: iIii1I11I1II1
  if 14 - 14: oOoO0oo0OOOo % oo . II111iiii . oo - Oo
  if 45 - 45: oooO0oo0oOOOO / O0 / oOo0O0Ooo * II11iiII
  if 18 - 18: iIii1I11I1II1 + II11iiII + iIii1I11I1II1 . oOoO0oo0OOOo + o0oo0o . Oo
  if ( oO00OoOo . find ( "224.0.0." ) != - 1 ) :
   lisp . lprint ( "Suppress registration for link-local groups" )
   continue
   if 7 - 7: oOoO0oo0OOOo + iIii1I11I1II1 * OoOO0ooOOoo0O * OoOO0ooOOoo0O / II111iiii - o0000oOoOoO0o
   if 65 - 65: iiiiIi11i + oOo0O0Ooo + II111iiii
   if 77 - 77: II111iiii
   if 50 - 50: O0 . O0 . Oo % OoO0O00
   if 68 - 68: iiiiIi11i
   if 10 - 10: o0000oOoOoO0o
   if 77 - 77: II11iiII / II111iiii + oooO0oo0oOOOO + Oo - i11iIiiIii
   if 44 - 44: oo + oOo0O0Ooo + oOoO0oo0OOOo . oo * oOo0O0Ooo % iIii1I11I1II1
  if ( ooooO == 0 ) :
   OOOoo . append ( [ None , oO00OoOo , ii1 ] )
   lisp . lprint ( "IGMPv3 {} (*, {})" . format ( lisp . bold ( OoOoO0oOOooo , False ) ,
 lisp . bold ( oO00OoOo , False ) ) )
   if 72 - 72: II11iiII . II11iiII - oOoO0oo0OOOo
   if 48 - 48: OoO0O00 - Oo + OoO0O00 - oo * i11iIiiIii . i1I1ii1II1iII
   if 35 - 35: oooO0oo0oOOOO . O0 + OoO0O00 + II11iiII + i1IIi
   if 65 - 65: O0 * oo / oo . oOo0O0Ooo
   if 87 - 87: II111iiii * oOoO0oo0OOOo % OoO0O00 * OoO0O00
  for O0O in range ( ooooO ) :
   if ( len ( O0oo0O0 ) < IIiI11 ) : return
   oO0O0 = struct . unpack ( oO00O , O0oo0O0 [ : IIiI11 ] ) [ 0 ]
   II1iIi11 . address = socket . ntohl ( oO0O0 )
   OOOOO0 = II1iIi11 . print_address_no_iid ( )
   OOOoo . append ( [ OOOOO0 , oO00OoOo , ii1 ] )
   lisp . lprint ( "{} ({}, {})" . format ( OoOoO0oOOooo ,
 lisp . green ( OOOOO0 , False ) , lisp . bold ( oO00OoOo , False ) ) )
   O0oo0O0 = O0oo0O0 [ IIiI11 : : ]
   if 79 - 79: II111iiii - Oo . i1IIi + O0 % O0 * oo
   if 7 - 7: i1IIi + II11iiII % i1I1ii1II1iII / Ooo00oOo00o + i1IIi
   if 41 - 41: o0000oOoOoO0o + i11iIiiIii / oooO0oo0oOOOO % oOoO0oo0OOOo
   if 22 - 22: oOo0O0Ooo % Ooo00oOo00o * o0000oOoOoO0o - oOoO0oo0OOOo + Ooo00oOo00o - OoO0O00
   if 15 - 15: II11iiII
   if 31 - 31: i1I1ii1II1iII / i1IIi . ooOO00oOo
   if 83 - 83: iiiiIi11i / iIii1I11I1II1 + i1IIi / i1I1ii1II1iII
   if 47 - 47: iiiiIi11i + OoooooooOO . II111iiii . i1I1ii1II1iII
 if ( len ( OOOoo ) != 0 ) :
  iIIIiIii ( Oo0o0000o0o0 , OOOoo )
  if 66 - 66: Oo * oOo0O0Ooo
 return
 if 2 - 2: iiiiIi11i . o0oo0o * OoO0O00 + O0 - OoOO0ooOOoo0O * iIii1I11I1II1
 if 12 - 12: Ooo00oOo00o * o0oo0o % II111iiii * i1IIi * iIii1I11I1II1
 if 81 - 81: OoO0O00 - OoOO0ooOOoo0O
 if 24 - 24: OoooooooOO . ooOO00oOo * II111iiii
 if 59 - 59: o0oo0o + ooOO00oOo / II11iiII
 if 97 - 97: OoO0O00 * i1I1ii1II1iII % Oo . i1I1ii1II1iII - o0oo0o - II11iiII
 if 79 - 79: oo - Oo
 if 37 - 37: oooO0oo0oOOOO . OoO0O00 * OoO0O00 * II111iiii * O0
def o00O ( parms , not_used , packet ) :
 global I11
 if 88 - 88: i11iIiiIii + i1I1ii1II1iII * oOo0O0Ooo * i1I1ii1II1iII + OoOO0ooOOoo0O
 O0OOO00OooO = parms [ 0 ]
 oOo0oooo00o = parms [ 1 ]
 if 64 - 64: ooOO00oOo . oo - OoooooooOO . Oo - i1I1ii1II1iII
 if 77 - 77: o0000oOoOoO0o % oOo0O0Ooo / II111iiii % i1I1ii1II1iII % OoooooooOO % ooOO00oOo
 if 19 - 19: oooO0oo0oOOOO * o0oo0o / iiiiIi11i * o0oo0o - OoooooooOO * OoOO0ooOOoo0O
 if 17 - 17: II111iiii + OoO0O00 . o0oo0o
 if 12 - 12: o0oo0o + II11iiII + OoOO0ooOOoo0O . oooO0oo0oOOOO / o0000oOoOoO0o
 if 29 - 29: oooO0oo0oOOOO . Oo - II111iiii
 if ( lisp . lisp_is_macos ( ) == False ) :
  ooooO0 = 4 if O0OOO00OooO == "lo0" else 16
  packet = packet [ ooooO0 : : ]
  if 37 - 37: i11iIiiIii + oo . II11iiII % OoOO0ooOOoo0O % OoOO0ooOOoo0O
  if 26 - 26: O0
  if 34 - 34: Oo * o0oo0o
  if 97 - 97: i11iIiiIii % iiiiIi11i / OoO0O00 / OoO0O00
  if 97 - 97: II111iiii - o0oo0o - iIii1I11I1II1 * oo
 ooo = struct . unpack ( "B" , packet [ 9 ] ) [ 0 ]
 if ( ooo == 2 ) :
  o0oO0Oo ( packet )
  return
  if 88 - 88: o0oo0o % oooO0oo0oOOOO / o0000oOoOoO0o - oo / oo * Oo
  if 77 - 77: oooO0oo0oOOOO
  if 66 - 66: iIii1I11I1II1 . i11iIiiIii / OoOO0ooOOoo0O / Oo + o0oo0o
  if 5 - 5: oOo0O0Ooo % i1I1ii1II1iII + oooO0oo0oOOOO
  if 13 - 13: oooO0oo0oOOOO
 ii1II1II = packet
 packet , II1iIi11 , i11i11II11i , II1Ii1I1i = lisp . lisp_is_rloc_probe ( packet , 0 )
 if ( ii1II1II != packet ) :
  if ( II1iIi11 == None ) : return
  lisp . lisp_parse_packet ( Oo0o0000o0o0 , packet , II1iIi11 , i11i11II11i , II1Ii1I1i )
  return
  if 74 - 74: oOoO0oo0OOOo * i11iIiiIii / oo - O0 . Oo
  if 39 - 39: Oo / O0 * oooO0oo0oOOOO
  if 17 - 17: o0000oOoOoO0o / iIii1I11I1II1 - ooOO00oOo + oo % II11iiII
  if 14 - 14: Ooo00oOo00o % oooO0oo0oOOOO + oOoO0oo0OOOo + ooOO00oOo
  if 76 - 76: ooOO00oOo - i11iIiiIii + oOo0O0Ooo + II11iiII / OoooooooOO
  if 50 - 50: II111iiii - o0oo0o + iIii1I11I1II1 + iIii1I11I1II1
  if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + oOoO0oo0OOOo - II111iiii
 iiIiiIi1 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 if ( iiIiiIi1 == lisp . LISP_DATA_PORT ) : return
 packet = lisp . lisp_reassemble ( packet )
 if ( packet == None ) : return
 if 30 - 30: II11iiII + II111iiii - oooO0oo0oOOOO * OoooooooOO
 packet = lisp . lisp_packet ( packet )
 I1iIiiiI1 = packet . decode ( True , I11 , lisp . lisp_decap_stats )
 if ( I1iIiiiI1 == None ) : return
 if 87 - 87: oOo0O0Ooo - Oo - II11iiII + OoO0O00 % iIii1I11I1II1 / i11iIiiIii
 if 12 - 12: Oo
 if 86 - 86: iiiiIi11i - ooOO00oOo
 if 63 - 63: oo / oOo0O0Ooo + OoooooooOO . OoOO0ooOOoo0O . Oo
 packet . print_packet ( "Receive" , True )
 if 48 - 48: i1IIi - i1I1ii1II1iII - i11iIiiIii . OoOO0ooOOoo0O - i1I1ii1II1iII * OoOO0ooOOoo0O
 if 60 - 60: oOo0O0Ooo / oOoO0oo0OOOo + II11iiII - i1I1ii1II1iII
 if 49 - 49: ooOO00oOo - O0 / ooOO00oOo * oOo0O0Ooo + o0oo0o
 if 35 - 35: II111iiii . oo / i1IIi / oo * iiiiIi11i
 if 85 - 85: II111iiii . Oo % II11iiII % OoOO0ooOOoo0O
 if 80 - 80: iiiiIi11i * OoOO0ooOOoo0O / iIii1I11I1II1 % iiiiIi11i / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . OoO0O00 * i1I1ii1II1iII . i11iIiiIii * O0
 if 44 - 44: i1IIi . oo / i11iIiiIii + oooO0oo0oOOOO
 if ( lisp . lisp_decent_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 27 - 27: II11iiII
  II1iIi11 = packet . inner_source . print_address_no_iid ( )
  packet . strip_outer_headers ( )
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , II1iIi11 , iiIiiIi1 )
  lisp . lisp_ipc ( packet , I11 , "lisp-ms" )
  return
  if 52 - 52: o0oo0o % oOo0O0Ooo + iIii1I11I1II1 * iiiiIi11i . o0000oOoOoO0o
  if 95 - 95: iIii1I11I1II1 . oooO0oo0oOOOO - OoooooooOO * ooOO00oOo / Ooo00oOo00o
  if 74 - 74: iiiiIi11i
  if 34 - 34: i1I1ii1II1iII
  if 44 - 44: i1IIi % oo % Ooo00oOo00o
  if 9 - 9: OoO0O00 % OoooooooOO - o0000oOoOoO0o
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 43 - 43: ooOO00oOo % ooOO00oOo
  if 46 - 46: OoO0O00 % iIii1I11I1II1 . i1I1ii1II1iII . O0 * Oo / OoooooooOO
  if 7 - 7: iiiiIi11i - O0 * OoOO0ooOOoo0O - Ooo00oOo00o - II111iiii
  if 41 - 41: oo - o0oo0o % II111iiii . o0oo0o - OoOO0ooOOoo0O
  if 45 - 45: o0000oOoOoO0o - II11iiII
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 70 - 70: ooOO00oOo % oo / oo . OoOO0ooOOoo0O % Oo . II111iiii
 if 10 - 10: o0000oOoOoO0o - i11iIiiIii . oOoO0oo0OOOo % i1IIi
 if 78 - 78: iIii1I11I1II1 * OoO0O00 . OoO0O00 - II11iiII . iIii1I11I1II1
 if 30 - 30: Oo + Oo % oooO0oo0oOOOO - Ooo00oOo00o - oOoO0oo0OOOo
 packet . strip_outer_headers ( )
 i111IiiI1Ii = lisp . bold ( "Forward" , False )
 if 72 - 72: O0 . oOo0O0Ooo * OoO0O00 + oOoO0oo0OOOo - Ooo00oOo00o
 if 40 - 40: ooOO00oOo + ooOO00oOo
 if 94 - 94: i1I1ii1II1iII * iIii1I11I1II1 . OoOO0ooOOoo0O
 if 13 - 13: iIii1I11I1II1 * oOo0O0Ooo / o0oo0o % Oo + iiiiIi11i
 iiiI1iI1 = packet . inner_dest . is_mac ( )
 if ( iiiI1iI1 ) :
  packet . packet = lisp . lisp_mac_input ( packet . packet )
  if ( packet . packet == None ) : return
  i111IiiI1Ii = lisp . bold ( "Bridge" , False )
 elif ( packet . inner_version == 4 ) :
  packet . packet = lisp . lisp_ipv4_input ( packet . packet )
  if ( packet . packet == None ) : return
  packet . inner_ttl = packet . outer_ttl
 elif ( packet . inner_version == 6 ) :
  packet . packet = lisp . lisp_ipv6_input ( packet )
  if ( packet . packet == None ) : return
  packet . inner_ttl = packet . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 15 - 15: oooO0oo0oOOOO . i1IIi * oOo0O0Ooo % iIii1I11I1II1
  if 35 - 35: oOoO0oo0OOOo + o0oo0o - oOo0O0Ooo % iiiiIi11i % Ooo00oOo00o % oOo0O0Ooo
  if 45 - 45: oo * II11iiII % ooOO00oOo
  if 24 - 24: Oo - OoOO0ooOOoo0O * iiiiIi11i
  if 87 - 87: o0000oOoOoO0o - oOoO0oo0OOOo % oOoO0oo0OOOo . iiiiIi11i / oOoO0oo0OOOo
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  oo000 = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( oo000 ) :
   oo000 . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 6 - 6: oOo0O0Ooo / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
   return
   if 79 - 79: oooO0oo0oOOOO % ooOO00oOo
   if 81 - 81: i11iIiiIii + i11iIiiIii * ooOO00oOo + oooO0oo0oOOOO
   if 32 - 32: O0 . OoooooooOO
   if 15 - 15: oo . ooOO00oOo
   if 17 - 17: i11iIiiIii / OoO0O00 . ooOO00oOo / oo
   if 38 - 38: i1IIi . oOoO0oo0OOOo % o0000oOoOoO0o + iIii1I11I1II1 + O0
 oOOoo0Oo = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 47 - 47: ooOO00oOo + oooO0oo0oOOOO / II111iiii
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( i111IiiI1Ii , lisp . green ( oOOoo0Oo , False ) ,
 # i1IIi % o0000oOoOoO0o - ooOO00oOo / iiiiIi11i . Oo / OoO0O00
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 99 - 99: ooOO00oOo - oOo0O0Ooo * oOo0O0Ooo . II111iiii % Oo
 if 1 - 1: oOoO0oo0OOOo + OoO0O00 * iiiiIi11i + Ooo00oOo00o - OoOO0ooOOoo0O . oOoO0oo0OOOo
 if 31 - 31: iIii1I11I1II1 . II111iiii - ooOO00oOo
 if 62 - 62: II11iiII / II111iiii + oOo0O0Ooo % Oo / oOo0O0Ooo + oOoO0oo0OOOo
 if 2 - 2: i11iIiiIii - o0oo0o + ooOO00oOo % OoOO0ooOOoo0O * o0000oOoOoO0o
 if ( iiiI1iI1 ) :
  packet . bridge_l2_packet ( packet . inner_dest , oo000 )
  return
  if 54 - 54: O0 - i1I1ii1II1iII . II11iiII % i1I1ii1II1iII + i1I1ii1II1iII
  if 36 - 36: II11iiII % i11iIiiIii
  if 47 - 47: i1IIi + II111iiii . OoO0O00 * iiiiIi11i . OoOO0ooOOoo0O / i1IIi
  if 50 - 50: o0oo0o / i1IIi % OoooooooOO
  if 83 - 83: oOoO0oo0OOOo * oOoO0oo0OOOo + II11iiII
  if 57 - 57: O0 - O0 . oOoO0oo0OOOo / Ooo00oOo00o / o0000oOoOoO0o
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( oO0o0o0ooO0oO , oo0o0O00 )
  return
  if 20 - 20: II11iiII * II111iiii - oOo0O0Ooo - iiiiIi11i * o0oo0o
  if 6 - 6: Oo + II11iiII / OoO0O00 + oooO0oo0oOOOO % II111iiii / ooOO00oOo
  if 45 - 45: OoooooooOO
  if 9 - 9: OoOO0ooOOoo0O . ooOO00oOo * i1IIi . OoooooooOO
  if 32 - 32: oOo0O0Ooo . oOoO0oo0OOOo % oo - II111iiii
 iiI111 = packet . get_raw_socket ( )
 if ( iiI111 == None ) : iiI111 = oOo0oooo00o
 if 62 - 62: oOoO0oo0OOOo - O0 . oo . O0 * iIii1I11I1II1
 if 92 - 92: iiiiIi11i / II11iiII . oOoO0oo0OOOo
 if 30 - 30: o0000oOoOoO0o . oOoO0oo0OOOo / II11iiII
 if 2 - 2: oooO0oo0oOOOO % oo - o0oo0o
 packet . send_packet ( iiI111 , packet . inner_dest )
 return
 if 79 - 79: OoooooooOO / oOoO0oo0OOOo . O0
 if 79 - 79: iiiiIi11i - II111iiii
 if 43 - 43: i1IIi + O0 % ooOO00oOo / o0000oOoOoO0o * oo
 if 89 - 89: oo . OoO0O00 + oOoO0oo0OOOo . O0 % Ooo00oOo00o
 if 84 - 84: OoooooooOO + o0oo0o / oo % II11iiII % oOoO0oo0OOOo * oo
 if 58 - 58: ooOO00oOo - oOo0O0Ooo . i11iIiiIii % i11iIiiIii / i1IIi / iiiiIi11i
 if 24 - 24: oo * i1IIi % Oo / O0 + i11iIiiIii
 if 12 - 12: oOoO0oo0OOOo / o0000oOoOoO0o
 if 5 - 5: OoooooooOO
 if 18 - 18: oo % OoooooooOO - i1I1ii1II1iII . i11iIiiIii * OoO0O00 % o0000oOoOoO0o
 if 12 - 12: i1IIi / II11iiII % Oo * oooO0oo0oOOOO * O0 * iIii1I11I1II1
def OOOO ( lisp_raw_socket , packet , source ) :
 global I11 , Oo0o0000o0o0
 if 98 - 98: iiiiIi11i . OoooooooOO
 if 54 - 54: O0 / oooO0oo0oOOOO % Oo * i1IIi * O0
 if 48 - 48: Ooo00oOo00o . iiiiIi11i % oOo0O0Ooo - oOo0O0Ooo
 if 33 - 33: OoOO0ooOOoo0O % II111iiii + ooOO00oOo
 OoIi1I1I = packet
 packet = lisp . lisp_packet ( packet [ 8 : : ] )
 if ( packet . lisp_header . decode ( OoIi1I1I ) == False ) : return
 if 56 - 56: O0
 if 45 - 45: oOo0O0Ooo - ooOO00oOo - oOo0O0Ooo
 if 41 - 41: OoO0O00 / i1IIi / OoO0O00 - i1I1ii1II1iII . Ooo00oOo00o
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / oo / i1I1ii1II1iII
 if 69 - 69: Oo % Oo
 if 76 - 76: i11iIiiIii * i1I1ii1II1iII / ooOO00oOo % oOoO0oo0OOOo + II11iiII
 packet . outer_source = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , source ,
 lisp . LISP_IPV4_HOST_MASK_LEN , 0 )
 if 48 - 48: iIii1I11I1II1 % i1IIi + oOo0O0Ooo % Ooo00oOo00o
 I1iIiiiI1 = packet . decode ( False , I11 ,
 lisp . lisp_decap_stats )
 if ( I1iIiiiI1 == None ) : return
 if 79 - 79: oOo0O0Ooo % oo % o0000oOoOoO0o / i1IIi % ooOO00oOo
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * i1I1ii1II1iII
 if 84 - 84: II11iiII + o0000oOoOoO0o + Ooo00oOo00o
 if 33 - 33: o0000oOoOoO0o
 if 93 - 93: Oo
 if 34 - 34: iiiiIi11i - Oo * OoO0O00 / Ooo00oOo00o
 if 19 - 19: oOoO0oo0OOOo
 if ( lisp . lisp_flow_logging ) : packet . log_flow ( False )
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - oOo0O0Ooo % O0 / II111iiii * i1IIi
 packet . print_packet ( "Kernel-decap" , False )
 lisp . dprint ( packet . lisp_header . print_header ( " " ) )
 if 66 - 66: O0
 if 52 - 52: ooOO00oOo * OoooooooOO
 if 12 - 12: O0 + oooO0oo0oOOOO * i1IIi . ooOO00oOo
 if 71 - 71: o0oo0o - Ooo00oOo00o - II11iiII
 if 28 - 28: iIii1I11I1II1
 if 7 - 7: Ooo00oOo00o % oooO0oo0oOOOO * oOo0O0Ooo
 if 58 - 58: oooO0oo0oOOOO / OoOO0ooOOoo0O + II111iiii % i1I1ii1II1iII - OoooooooOO
 if 25 - 25: oOo0O0Ooo % OoooooooOO * OoO0O00 - i1IIi * II111iiii * iiiiIi11i
 if ( lisp . lisp_decent_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 30 - 30: OoOO0ooOOoo0O % oOo0O0Ooo / oOoO0oo0OOOo * O0 * o0000oOoOoO0o . oo
  iiIiiIi1 = packet . udp_sport
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , source , iiIiiIi1 )
  lisp . lisp_ipc ( packet , I11 , "lisp-ms" )
  return
  if 46 - 46: oOo0O0Ooo - O0
  if 70 - 70: OoOO0ooOOoo0O + OoO0O00 * iIii1I11I1II1 . oo * OoOO0ooOOoo0O
  if 49 - 49: Ooo00oOo00o
  if 25 - 25: i1I1ii1II1iII . OoooooooOO * iIii1I11I1II1 . Ooo00oOo00o / O0 + o0000oOoOoO0o
  if 68 - 68: OoO0O00
  if 22 - 22: II11iiII
  if 22 - 22: i1I1ii1II1iII * OoOO0ooOOoo0O - OoO0O00 * O0 / i11iIiiIii
  if 78 - 78: OoO0O00 * O0 / Oo + OoooooooOO + II11iiII
  if 23 - 23: i1I1ii1II1iII % OoooooooOO / iIii1I11I1II1 + oOoO0oo0OOOo / i1IIi / Ooo00oOo00o
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  packet = packet . packet
  II1Ii1I1i = - 1
  if ( lisp . lisp_is_rloc_probe_request ( packet [ 28 ] ) ) :
   II1Ii1I1i = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
   if 94 - 94: i1IIi
  packet = packet [ 28 : : ]
  lisp . lisp_parse_packet ( Oo0o0000o0o0 , packet , source , 0 , II1Ii1I1i )
  return
  if 36 - 36: oo + OoO0O00
  if 46 - 46: i1I1ii1II1iII
  if 65 - 65: i1IIi . oOoO0oo0OOOo / Oo
  if 11 - 11: oooO0oo0oOOOO * Oo / Oo - II11iiII
  if 68 - 68: oo % oooO0oo0oOOOO - oooO0oo0oOOOO / oo + oOoO0oo0OOOo - OoO0O00
  if 65 - 65: Oo - i1IIi
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 62 - 62: OoOO0ooOOoo0O / iiiiIi11i % OoO0O00 . OoooooooOO / i11iIiiIii / o0oo0o
  if 60 - 60: oo % iiiiIi11i / Ooo00oOo00o % iiiiIi11i * i11iIiiIii / i1I1ii1II1iII
  if 34 - 34: o0oo0o - II11iiII
  if 25 - 25: iiiiIi11i % oo + i11iIiiIii + O0 * OoooooooOO
  if 64 - 64: i1IIi
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 10 - 10: o0oo0o % O0 / oo % OoOO0ooOOoo0O
 if 25 - 25: II111iiii / ooOO00oOo
 if 64 - 64: O0 % Oo
 if 40 - 40: Ooo00oOo00o + OoOO0ooOOoo0O
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  oo000 = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( oo000 ) :
   oo000 . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 77 - 77: i11iIiiIii % oooO0oo0oOOOO + o0oo0o % OoooooooOO - OoOO0ooOOoo0O
   if 26 - 26: OoO0O00 + O0 - iIii1I11I1II1
   if 47 - 47: OoooooooOO
   if 2 - 2: oOo0O0Ooo % o0oo0o * OoO0O00 * oOo0O0Ooo
   if 65 - 65: i11iIiiIii + OoO0O00 * OoooooooOO - ooOO00oOo
 oOOoo0Oo = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 26 - 26: Ooo00oOo00o % II11iiII + II11iiII % OoOO0ooOOoo0O * i11iIiiIii / i1I1ii1II1iII
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( lisp . bold ( "NAT-Forward" , False ) , lisp . green ( oOOoo0Oo , False ) ,
 # II11iiII % II111iiii - II11iiII + II111iiii
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 61 - 61: i11iIiiIii * iiiiIi11i % OoO0O00 * o0oo0o - OoooooooOO - ooOO00oOo
 if 83 - 83: Oo / II11iiII
 if 39 - 39: oooO0oo0oOOOO + OoOO0ooOOoo0O
 if 9 - 9: oo % OoOO0ooOOoo0O . OoO0O00 * oo
 if 99 - 99: O0 . Ooo00oOo00o % OoOO0ooOOoo0O - OoO0O00 / OoOO0ooOOoo0O
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( oO0o0o0ooO0oO , oo0o0O00 )
  return
  if 20 - 20: oOo0O0Ooo * i1I1ii1II1iII
  if 19 - 19: OoooooooOO
  if 76 - 76: ooOO00oOo * iiiiIi11i
  if 63 - 63: II111iiii . II111iiii + oOoO0oo0OOOo + II11iiII + O0 . o0000oOoOoO0o
  if 1 - 1: O0 * i11iIiiIii - Oo - o0000oOoOoO0o
 iiI111 = packet . get_raw_socket ( )
 if ( iiI111 == None ) : iiI111 = lisp_raw_socket
 if 94 - 94: ooOO00oOo + oooO0oo0oOOOO + Oo
 if 82 - 82: OoO0O00 - OoO0O00 . iIii1I11I1II1 / II11iiII + oooO0oo0oOOOO % iIii1I11I1II1
 if 61 - 61: II11iiII / OoO0O00 % II11iiII - ooOO00oOo + Oo / Oo
 if 82 - 82: OoO0O00
 packet . send_packet ( iiI111 , packet . inner_dest )
 return
 if 5 - 5: ooOO00oOo / ooOO00oOo - O0 - o0oo0o + o0oo0o
 if 99 - 99: OoOO0ooOOoo0O * OoooooooOO / Ooo00oOo00o . oooO0oo0oOOOO - iIii1I11I1II1 - o0000oOoOoO0o
 if 31 - 31: oooO0oo0oOOOO - ooOO00oOo / II11iiII . i1IIi / o0000oOoOoO0o
 if 66 - 66: ooOO00oOo
 if 72 - 72: o0oo0o
 if 91 - 91: II111iiii / oooO0oo0oOOOO + iIii1I11I1II1 . OoOO0ooOOoo0O - O0
 if 70 - 70: o0000oOoOoO0o * iiiiIi11i - OoOO0ooOOoo0O + OoO0O00 % oOoO0oo0OOOo - oooO0oo0oOOOO
 if 81 - 81: O0 . O0
def OoO00OooO0 ( group , joinleave ) :
 OoOo00 = None
 for o0OO0oOO0O0 in lisp . lisp_group_mapping_list . values ( ) :
  O00OOOo0 = OoO ( group , o0OO0oOO0O0 )
  if ( O00OOOo0 == - 1 ) : continue
  if ( OoOo00 == None or O00OOOo0 > OoOo00 . mask_len ) : OoOo00 = o0OO0oOO0O0
  if 98 - 98: II11iiII + o0000oOoOoO0o
 if ( OoOo00 == None ) : return
 if 52 - 52: OoO0O00 / oOo0O0Ooo - o0oo0o . i1I1ii1II1iII
 iiI11Ii1i = [ ]
 for o0O00oOoOO in OoOo00 . sources :
  iiI11Ii1i . append ( [ o0O00oOoOO , group , joinleave ] )
  if 100 - 100: i1I1ii1II1iII + OoOO0ooOOoo0O + Oo + i1I1ii1II1iII / i1IIi
  if 74 - 74: O0 % OoooooooOO * OoO0O00 + II11iiII * i1I1ii1II1iII
 iIIIiIii ( Oo0o0000o0o0 , iiI11Ii1i )
 return
 if 100 - 100: II11iiII + o0000oOoOoO0o * Ooo00oOo00o + II111iiii
 if 70 - 70: OoO0O00 * iIii1I11I1II1
 if 76 - 76: i1I1ii1II1iII % oOo0O0Ooo % iIii1I11I1II1 . II11iiII
 if 30 - 30: i1IIi
 if 75 - 75: OoOO0ooOOoo0O . II11iiII - iIii1I11I1II1 * ooOO00oOo * i1I1ii1II1iII
 if 93 - 93: Oo
 if 18 - 18: Oo
 if 66 - 66: iiiiIi11i * i11iIiiIii + oOo0O0Ooo / II11iiII
 if 96 - 96: II11iiII + II11iiII % oooO0oo0oOOOO % II11iiII
 if 28 - 28: iIii1I11I1II1 + oOo0O0Ooo . Ooo00oOo00o % i11iIiiIii
 if 58 - 58: OoOO0ooOOoo0O / OoooooooOO % iiiiIi11i + ooOO00oOo
 if 58 - 58: O0
 if 91 - 91: i1I1ii1II1iII / oOoO0oo0OOOo . i1I1ii1II1iII - Ooo00oOo00o + oOoO0oo0OOOo
 if 72 - 72: o0000oOoOoO0o . oooO0oo0oOOOO * oOoO0oo0OOOo / oOoO0oo0OOOo / i1I1ii1II1iII
 if 13 - 13: i1IIi
 if 17 - 17: i11iIiiIii * Ooo00oOo00o * Ooo00oOo00o + ooOO00oOo
def o0O0O ( ) :
 global Oo0o0000o0o0
 if 45 - 45: Ooo00oOo00o % OoO0O00 * i1IIi - O0
 lisp . lisp_set_exception ( )
 if 82 - 82: II111iiii / i1I1ii1II1iII
 OOoO = socket . htonl
 i1IiiI = [ OOoO ( 0x46000020 ) , OOoO ( 0x9fe60000 ) , OOoO ( 0x0102d7cc ) ,
 OOoO ( 0x0acfc15a ) , OOoO ( 0xe00000fb ) , OOoO ( 0x94040000 ) ]
 if 70 - 70: OoOO0ooOOoo0O . II11iiII * OoO0O00 / II11iiII
 OO0 = ""
 for Oo0OoOo in i1IiiI : OO0 += struct . pack ( "I" , Oo0OoOo )
 if 13 - 13: Ooo00oOo00o
 if 7 - 7: oo + oooO0oo0oOOOO / i11iIiiIii / OoO0O00
 if 97 - 97: o0oo0o . OoOO0ooOOoo0O / oo
 if 83 - 83: OoOO0ooOOoo0O - oOoO0oo0OOOo * iiiiIi11i
 if 90 - 90: OoO0O00 * oo
 while ( True ) :
  OO0OooOo = commands . getoutput ( "ls join-*" ) . replace ( "join-" , "" )
  OO0OooOo = OO0OooOo . split ( "\n" )
  if 13 - 13: O0 % Oo % OoOO0ooOOoo0O
  for i1111IIiii1 in OO0OooOo :
   if ( lisp . lisp_valid_address_format ( "address" , i1111IIiii1 ) == False ) :
    continue
    if 25 - 25: OoooooooOO % o0000oOoOoO0o * II111iiii - ooOO00oOo
    if 95 - 95: oo % o0oo0o * oo + O0 . o0oo0o % OoooooooOO
   II11II1I = ( i1111IIiii1 . find ( ":" ) != - 1 )
   if 52 - 52: II11iiII * iiiiIi11i + OoOO0ooOOoo0O * OoOO0ooOOoo0O % i1IIi % OoOO0ooOOoo0O
   if 96 - 96: Ooo00oOo00o * iiiiIi11i - II11iiII * Ooo00oOo00o * i1IIi
   if 8 - 8: Oo - OoO0O00 + iIii1I11I1II1 + i1IIi * o0000oOoOoO0o - iIii1I11I1II1
   if 30 - 30: OoOO0ooOOoo0O / oOoO0oo0OOOo
   iI1iIIIIIiIi1 = os . path . exists ( "leave-{}" . format ( i1111IIiii1 ) )
   lisp . lprint ( "Internal {} group {}" . format ( "leaving" if iI1iIIIIIiIi1 else "joining" , i1111IIiii1 ) )
   if 19 - 19: oOo0O0Ooo . Ooo00oOo00o . OoooooooOO
   if 13 - 13: II11iiII . OoO0O00 / II111iiii
   if 43 - 43: iIii1I11I1II1 % ooOO00oOo
   if 84 - 84: OoO0O00
   if 44 - 44: OoooooooOO * i11iIiiIii / OoO0O00
   if ( II11II1I ) :
    if ( i1111IIiii1 . lower ( ) . find ( "ff02:" ) != - 1 ) :
     lisp . lprint ( "Suppress registration for link-local groups" )
     continue
     if 75 - 75: OoooooooOO . II11iiII + ooOO00oOo / o0000oOoOoO0o - oo % o0000oOoOoO0o
    OoO00OooO0 ( i1111IIiii1 , ( iI1iIIIIIiIi1 == False ) )
   else :
    O0OooooO0o0O0 = OO0
    if ( iI1iIIIIIiIi1 ) :
     O0OooooO0o0O0 += struct . pack ( "I" , OOoO ( 0x17000000 ) )
    else :
     O0OooooO0o0O0 += struct . pack ( "I" , OOoO ( 0x16000000 ) )
     if 74 - 74: oOo0O0Ooo / i1IIi % OoooooooOO
     if 52 - 52: oooO0oo0oOOOO % Oo
    I111 = i1111IIiii1 . split ( "." )
    i1I1ii11i1Iii = int ( I111 [ 0 ] ) << 24
    i1I1ii11i1Iii += int ( I111 [ 1 ] ) << 16
    i1I1ii11i1Iii += int ( I111 [ 2 ] ) << 8
    i1I1ii11i1Iii += int ( I111 [ 3 ] )
    O0OooooO0o0O0 += struct . pack ( "I" , OOoO ( i1I1ii11i1Iii ) )
    o0oO0Oo ( O0OooooO0o0O0 )
    time . sleep ( .100 )
    if 51 - 51: oOoO0oo0OOOo * iiiiIi11i
    if 23 - 23: i11iIiiIii
  time . sleep ( 10 )
  if 100 - 100: iiiiIi11i + O0 . oo + i1IIi - oOo0O0Ooo + Ooo00oOo00o
 return
 if 65 - 65: II111iiii / OoO0O00
 if 42 - 42: i11iIiiIii . O0
 if 75 - 75: o0oo0o + iIii1I11I1II1
 if 19 - 19: oo + i11iIiiIii . oooO0oo0oOOOO - OoOO0ooOOoo0O / o0000oOoOoO0o + Ooo00oOo00o
 if 38 - 38: OoO0O00 / iIii1I11I1II1 * iIii1I11I1II1 % oOoO0oo0OOOo
 if 92 - 92: OoOO0ooOOoo0O / O0 * oo - OoOO0ooOOoo0O
 if 99 - 99: i11iIiiIii % OoooooooOO
 if 56 - 56: oooO0oo0oOOOO * o0oo0o
 if 98 - 98: OoOO0ooOOoo0O + O0 * o0oo0o + i11iIiiIii - II11iiII - iIii1I11I1II1
 if 5 - 5: II11iiII % OoO0O00 % oooO0oo0oOOOO % Oo
def I1Iiii ( ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 22 - 22: o0000oOoOoO0o * OoOO0ooOOoo0O + oo - OoOO0ooOOoo0O / oOoO0oo0OOOo
 if 18 - 18: i1IIi
 if 4 - 4: oooO0oo0oOOOO
 if 93 - 93: iiiiIi11i % i1IIi
 if 83 - 83: oo . OoO0O00 - OoOO0ooOOoo0O . Ooo00oOo00o
 ooo00o0o0 = lisp . lisp_get_all_multicast_rles ( )
 if 54 - 54: o0000oOoOoO0o % OoOO0ooOOoo0O . II11iiII + iiiiIi11i * i1I1ii1II1iII - i1IIi
 if 27 - 27: o0000oOoOoO0o % i1IIi . OoO0O00 % o0oo0o
 if 10 - 10: oooO0oo0oOOOO / OoooooooOO
 if 50 - 50: i11iIiiIii - OoooooooOO . iiiiIi11i + O0 . i1IIi
 O0OOO00OooO = "any"
 if 91 - 91: Ooo00oOo00o . i1I1ii1II1iII % OoO0O00 - i1I1ii1II1iII . iiiiIi11i % i11iIiiIii
 if 25 - 25: iIii1I11I1II1
 if 63 - 63: Oo
 oO0oOOOooo = pcappy . open_live ( O0OOO00OooO , 1600 , 0 , 100 )
 if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % Ooo00oOo00o / iIii1I11I1II1 * o0oo0o
 iIi = "(proto 2) or "
 if 88 - 88: i1I1ii1II1iII * OoooooooOO . iIii1I11I1II1
 iIi += "((dst host "
 for IIi111 in lisp . lisp_get_all_addresses ( ) + ooo00o0o0 :
  iIi += "{} or " . format ( IIi111 )
  if 61 - 61: oOoO0oo0OOOo - II11iiII
 iIi = iIi [ 0 : - 4 ]
 iIi += ") and ((udp dst port 4341 or 8472 or 4789) or "
 iIi += "(udp dst port 4342 and ip[28] == 0x12) or "
 iIi += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0)))))"
 if 16 - 16: i1I1ii1II1iII / iIii1I11I1II1 + II11iiII * i1I1ii1II1iII * OoOO0ooOOoo0O
 if 8 - 8: o0oo0o
 lisp . lprint ( "Capturing packets for: '{}' on device {}" . format ( iIi ,
 O0OOO00OooO ) )
 oO0oOOOooo . filter = iIi
 if 15 - 15: OoO0O00 / o0000oOoOoO0o % O0 + oOoO0oo0OOOo
 if 96 - 96: Oo . OoooooooOO
 if 39 - 39: II11iiII + ooOO00oOo
 if 80 - 80: II11iiII % ooOO00oOo / oOo0O0Ooo
 oO0oOOOooo . loop ( - 1 , o00O , [ O0OOO00OooO , oOo0oooo00o ] )
 return
 if 54 - 54: OoO0O00 % ooOO00oOo - II11iiII - OoOO0ooOOoo0O
 if 71 - 71: Oo . i11iIiiIii
 if 56 - 56: O0 * i1I1ii1II1iII + i1I1ii1II1iII * iIii1I11I1II1 / Oo * o0oo0o
 if 25 - 25: iIii1I11I1II1 . OoOO0ooOOoo0O * i11iIiiIii + OoO0O00 * OoOO0ooOOoo0O
 if 67 - 67: i1I1ii1II1iII
 if 88 - 88: OoO0O00
 if 8 - 8: oOoO0oo0OOOo
def o000 ( ) :
 global I11
 global i1111
 global Oo0o0000o0o0
 global oOo0oooo00o
 global oO0o0o0ooO0oO
 global oo0o0O00
 if 30 - 30: o0000oOoOoO0o + II111iiii % OoooooooOO
 lisp . lisp_i_am ( "etr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "ETR starting up" )
 if 89 - 89: o0000oOoOoO0o
 if 51 - 51: i1I1ii1II1iII
 if 68 - 68: i1I1ii1II1iII - Ooo00oOo00o * ooOO00oOo % Oo . Oo - iIii1I11I1II1
 if 22 - 22: OoooooooOO / oOoO0oo0OOOo % i1I1ii1II1iII * oOo0O0Ooo
 lisp . lisp_get_local_interfaces ( )
 lisp . lisp_get_local_macs ( )
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 32 - 32: OoooooooOO % iiiiIi11i % iIii1I11I1II1 / O0
 if 61 - 61: II111iiii . O0 - o0000oOoOoO0o - oOoO0oo0OOOo / i11iIiiIii - II111iiii
 if 98 - 98: o0000oOoOoO0o - oo . i11iIiiIii * OoO0O00
 if 29 - 29: o0000oOoOoO0o / Oo % OoOO0ooOOoo0O
 if 10 - 10: iIii1I11I1II1 % OoooooooOO % oOoO0oo0OOOo
 if 39 - 39: II111iiii * oOo0O0Ooo . O0 * OoOO0ooOOoo0O
 if 89 - 89: o0000oOoOoO0o - Oo . OoOO0ooOOoo0O - o0oo0o - oo
 if 79 - 79: oooO0oo0oOOOO + oooO0oo0oOOOO + o0000oOoOoO0o
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % Ooo00oOo00o * Oo
 if 79 - 79: O0
 if 32 - 32: II111iiii . O0 + o0000oOoOoO0o / oOo0O0Ooo / oooO0oo0oOOOO / II11iiII
 if 15 - 15: oOoO0oo0OOOo
 if 4 - 4: oooO0oo0oOOOO + iIii1I11I1II1 * i1I1ii1II1iII + OoO0O00 * Ooo00oOo00o % II111iiii
 if 88 - 88: iiiiIi11i - i1IIi % i11iIiiIii % II111iiii * OoooooooOO
 o0O00oOoOO = lisp . lisp_open_listen_socket ( "0.0.0.0" , str ( i11 ) )
 o0O00oOoOO . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_TTL , 32 )
 i1111 = o0O00oOoOO
 if 40 - 40: OoO0O00
 if 47 - 47: oOo0O0Ooo
 if 65 - 65: O0 + o0oo0o % o0000oOoOoO0o * oo / Oo / oOo0O0Ooo
 if 71 - 71: i11iIiiIii / oOo0O0Ooo . iiiiIi11i
 I11 = lisp . lisp_open_listen_socket ( "" , "lisp-etr" )
 if 33 - 33: iiiiIi11i
 Oo0o0000o0o0 [ 0 ] = i1111
 Oo0o0000o0o0 [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 Oo0o0000o0o0 [ 2 ] = I11
 if 39 - 39: ooOO00oOo + O0 + Oo * II111iiii % O0 - O0
 if 41 - 41: oooO0oo0oOOOO % Ooo00oOo00o
 if 67 - 67: O0 % o0oo0o
 if 35 - 35: oo . oOo0O0Ooo + OoooooooOO % OoO0O00 % II11iiII
 if 39 - 39: o0000oOoOoO0o
 if 60 - 60: II11iiII
 if 62 - 62: o0oo0o * OoOO0ooOOoo0O
 if 74 - 74: oOo0O0Ooo . iIii1I11I1II1
 if 87 - 87: Oo
 oOo0oooo00o = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 oOo0oooo00o . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 Oo0o0000o0o0 . append ( oOo0oooo00o )
 if 41 - 41: oOo0O0Ooo . iIii1I11I1II1 % Oo + O0
 if 22 - 22: Ooo00oOo00o + OoO0O00 . Oo + oOoO0oo0OOOo * i1I1ii1II1iII . i11iIiiIii
 if 90 - 90: II11iiII * oOo0O0Ooo - OoO0O00 + Ooo00oOo00o
 if 53 - 53: OoooooooOO . OoooooooOO + Ooo00oOo00o - i1I1ii1II1iII + II11iiII
 if 44 - 44: o0oo0o - oooO0oo0oOOOO
 if 100 - 100: iiiiIi11i . ooOO00oOo - o0000oOoOoO0o + O0 * ooOO00oOo
 if 59 - 59: II111iiii
 if 43 - 43: OoO0O00 + OoooooooOO
 if 47 - 47: Oo
 if 92 - 92: OoOO0ooOOoo0O % i11iIiiIii % OoO0O00
 if 23 - 23: II111iiii * i1I1ii1II1iII
 if 80 - 80: o0oo0o / i11iIiiIii + OoooooooOO
 if 38 - 38: oOoO0oo0OOOo % Oo + i1IIi * OoooooooOO * iiiiIi11i
 if 83 - 83: iIii1I11I1II1 - Oo - o0oo0o / ooOO00oOo - O0
 if 81 - 81: o0000oOoOoO0o - iiiiIi11i * oOoO0oo0OOOo / o0oo0o
 if 21 - 21: ooOO00oOo
 if 63 - 63: OoOO0ooOOoo0O . O0 * OoOO0ooOOoo0O + iIii1I11I1II1
 if 46 - 46: i1IIi + II111iiii * i1IIi - o0000oOoOoO0o
 if 79 - 79: II111iiii - iiiiIi11i * oOoO0oo0OOOo - oOo0O0Ooo . oOoO0oo0OOOo
 if 11 - 11: O0 * oOo0O0Ooo
 if 37 - 37: oOo0O0Ooo + O0 . O0 * OoO0O00 % o0oo0o / i1I1ii1II1iII
 if 18 - 18: OoooooooOO
 if ( pytun != None ) :
  oo0o0O00 = '\x00\x00\x86\xdd'
  O0OOO00OooO = "lispers.net"
  try :
   oO0o0o0ooO0oO = pytun . TunTapDevice ( flags = pytun . IFF_TUN ,
 name = O0OOO00OooO )
   os . system ( "ip link set dev {} up" . format ( O0OOO00OooO ) )
  except :
   lisp . lprint ( "Cannot create tuntap interface" )
   if 57 - 57: Oo . oOo0O0Ooo * Ooo00oOo00o - OoooooooOO
   if 75 - 75: i11iIiiIii / Ooo00oOo00o . oooO0oo0oOOOO . i1IIi . i1IIi / OoOO0ooOOoo0O
   if 94 - 94: Oo + oo
   if 56 - 56: oOo0O0Ooo % Ooo00oOo00o
   if 40 - 40: II11iiII / oooO0oo0oOOOO
   if 29 - 29: o0000oOoOoO0o - o0000oOoOoO0o / Oo
 threading . Thread ( target = I1Iiii , args = [ ] ) . start ( )
 if 49 - 49: OoOO0ooOOoo0O + iiiiIi11i % ooOO00oOo - OoO0O00 - O0 - OoooooooOO
 if 4 - 4: II111iiii - iiiiIi11i % OoO0O00 * i11iIiiIii
 if 18 - 18: OoO0O00 % O0
 if 66 - 66: iIii1I11I1II1 % i11iIiiIii / oo
 threading . Thread ( target = o0O0O , args = [ ] ) . start ( )
 return ( True )
 if 47 - 47: oOoO0oo0OOOo * iiiiIi11i + iIii1I11I1II1 - iiiiIi11i / oooO0oo0oOOOO
 if 86 - 86: oooO0oo0oOOOO
 if 43 - 43: oo / i1I1ii1II1iII / Oo + iIii1I11I1II1 + OoooooooOO
 if 33 - 33: II111iiii - oooO0oo0oOOOO - Oo
 if 92 - 92: ooOO00oOo * oooO0oo0oOOOO
 if 92 - 92: iiiiIi11i
 if 7 - 7: i1I1ii1II1iII
def oOOoOO0O00o ( ) :
 global o0oOoO00o
 global oOOoo00O0O
 if 38 - 38: i11iIiiIii . iIii1I11I1II1 . II11iiII / ooOO00oOo
 if 18 - 18: OoO0O00 * o0oo0o
 if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * iiiiIi11i / II111iiii % OoooooooOO
 if 14 - 14: oooO0oo0oOOOO . oooO0oo0oOOOO % Oo
 if ( o0oOoO00o ) : o0oOoO00o . cancel ( )
 if ( oOOoo00O0O ) : oOOoo00O0O . cancel ( )
 if 42 - 42: Ooo00oOo00o . II11iiII - Oo
 if 33 - 33: II111iiii / O0 / oooO0oo0oOOOO - OoOO0ooOOoo0O - i1IIi
 if 8 - 8: i11iIiiIii . i1I1ii1II1iII / iIii1I11I1II1 / oOoO0oo0OOOo / oooO0oo0oOOOO - o0000oOoOoO0o
 if 32 - 32: Ooo00oOo00o . i1IIi * OoO0O00
 lisp . lisp_close_socket ( Oo0o0000o0o0 [ 0 ] , "" )
 lisp . lisp_close_socket ( Oo0o0000o0o0 [ 1 ] , "" )
 lisp . lisp_close_socket ( I11 , "lisp-etr" )
 return
 if 98 - 98: o0000oOoOoO0o - II111iiii / oo . iiiiIi11i * oooO0oo0oOOOO . OoOO0ooOOoo0O
 if 25 - 25: i11iIiiIii / oOo0O0Ooo - o0oo0o / ooOO00oOo . Ooo00oOo00o . Ooo00oOo00o
 if 6 - 6: iiiiIi11i . OoOO0ooOOoo0O
 if 43 - 43: oOoO0oo0OOOo + Ooo00oOo00o
 if 50 - 50: iiiiIi11i % i1IIi * O0
 if 4 - 4: iIii1I11I1II1 . i1IIi
 if 63 - 63: iIii1I11I1II1 + oooO0oo0oOOOO % i1IIi / oo % II111iiii
 if 60 - 60: Ooo00oOo00o . oOo0O0Ooo % o0oo0o / oo / O0
 if 19 - 19: i11iIiiIii . oo + II111iiii / II11iiII . oOoO0oo0OOOo * Oo
def oo0O ( ipc ) :
 ipc = ipc . split ( "%" )
 Ooooo0O0 = ipc [ 1 ]
 oOoO000 = ipc [ 2 ]
 if ( oOoO000 == "None" ) : oOoO000 = None
 if 86 - 86: iIii1I11I1II1 - OoOO0ooOOoo0O % Oo . II11iiII * oOo0O0Ooo . i1IIi
 O00oO0 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 O00oO0 . store_address ( Ooooo0O0 )
 if 75 - 75: OoOO0ooOOoo0O + Oo / Oo - II11iiII * ooOO00oOo * Oo
 if 53 - 53: oooO0oo0oOOOO % OoO0O00
 if 42 - 42: i11iIiiIii / oo - ooOO00oOo - Oo + II111iiii % Oo
 if 50 - 50: OoooooooOO + iiiiIi11i * oo - o0000oOoOoO0o / i11iIiiIii
 oo000 = lisp . lisp_db_for_lookups . lookup_cache ( O00oO0 , False )
 if ( oo000 == None or oo000 . dynamic_eid_configured ( ) == False ) :
  lisp . lprint ( "ITR/ETR dynamic-EID configuration out of sync for {}" . format ( lisp . green ( Ooooo0O0 , False ) ) )
  if 5 - 5: O0 - oo
  return
  if 44 - 44: II111iiii . II111iiii + II11iiII * o0000oOoOoO0o
  if 16 - 16: II111iiii
  if 100 - 100: O0 - i1IIi
  if 48 - 48: iiiiIi11i % Oo + O0
  if 27 - 27: oOoO0oo0OOOo / II11iiII
  if 33 - 33: OoooooooOO % oOoO0oo0OOOo . O0 / oOoO0oo0OOOo
 O00oOo00o0o = None
 if ( oo000 . dynamic_eids . has_key ( Ooooo0O0 ) ) : O00oOo00o0o = oo000 . dynamic_eids [ Ooooo0O0 ]
 if 63 - 63: oooO0oo0oOOOO + iIii1I11I1II1 + oo + o0oo0o
 if ( O00oOo00o0o == None and oOoO000 == None ) :
  lisp . lprint ( "ITR/ETR state mismatch for {}" . format ( lisp . green ( Ooooo0O0 , False ) ) )
  if 72 - 72: ooOO00oOo + i11iIiiIii + oOoO0oo0OOOo
  return
  if 96 - 96: iiiiIi11i % i1IIi / Ooo00oOo00o
  if 13 - 13: II111iiii - OoO0O00 % i11iIiiIii + i1I1ii1II1iII
  if 88 - 88: O0 . iiiiIi11i % oo
  if 10 - 10: oo + O0
  if 75 - 75: O0 % iIii1I11I1II1 / oOo0O0Ooo % II11iiII / oooO0oo0oOOOO
  if 31 - 31: i11iIiiIii * oOo0O0Ooo
  if 69 - 69: i11iIiiIii
 if ( O00oOo00o0o and oOoO000 ) :
  if ( O00oOo00o0o . interface == oOoO000 ) :
   lisp . lprint ( "ITR sent redundant IPC for {}" . format ( lisp . green ( Ooooo0O0 , False ) ) )
   if 61 - 61: O0
  else :
   lisp . lprint ( "Dynamic-EID {} interface change, {} -> {}" . format ( lisp . green ( Ooooo0O0 , False ) , O00oOo00o0o . interface , oOoO000 ) )
   if 21 - 21: ooOO00oOo % iIii1I11I1II1 . ooOO00oOo
   O00oOo00o0o . interface = oOoO000
   if 99 - 99: Ooo00oOo00o * II11iiII % iiiiIi11i * iiiiIi11i + OoooooooOO
  return
  if 82 - 82: OoOO0ooOOoo0O / oOo0O0Ooo - II11iiII / Oo
  if 50 - 50: II11iiII + ooOO00oOo . i11iIiiIii + oOoO0oo0OOOo + i11iIiiIii
  if 31 - 31: iiiiIi11i * o0oo0o . oOo0O0Ooo * OoOO0ooOOoo0O
  if 28 - 28: oooO0oo0oOOOO + oo - OoO0O00 % II11iiII . OoOO0ooOOoo0O + oo
  if 72 - 72: o0000oOoOoO0o / OoO0O00 / iiiiIi11i * oOo0O0Ooo + II11iiII
 if ( oOoO000 ) :
  O00oOo00o0o = lisp . lisp_dynamic_eid ( )
  O00oOo00o0o . dynamic_eid . copy_address ( O00oO0 )
  O00oOo00o0o . interface = oOoO000
  O00oOo00o0o . get_timeout ( oOoO000 )
  oo000 . dynamic_eids [ Ooooo0O0 ] = O00oOo00o0o
  if 58 - 58: Ooo00oOo00o % oo . oo * ooOO00oOo - oooO0oo0oOOOO . OoooooooOO
  iI1111i1i11Ii = lisp . bold ( "Registering" , False )
  Ooooo0O0 = lisp . bold ( Ooooo0O0 , False )
  lisp . lprint ( "{} dynamic-EID {} on interface {}, timeout {}" . format ( iI1111i1i11Ii ,
 lisp . green ( Ooooo0O0 , False ) , oOoO000 , O00oOo00o0o . timeout ) )
  if 62 - 62: i1I1ii1II1iII
  O00oO000O0O ( Oo0o0000o0o0 , None , O00oO0 , None , False )
  if 8 - 8: i1I1ii1II1iII - oo * OoO0O00 % oOoO0oo0OOOo * OoooooooOO
  if 26 - 26: i1IIi / i1I1ii1II1iII . i1I1ii1II1iII
  if 20 - 20: II11iiII - i1I1ii1II1iII / OoO0O00 * ooOO00oOo
  if 55 - 55: OoooooooOO
  if ( lisp . lisp_is_macos ( ) == False ) :
   Ooooo0O0 = O00oO0 . print_prefix_no_iid ( )
   OO0OOOOOo = "ip route add {} dev {}" . format ( Ooooo0O0 , oOoO000 )
   os . system ( OO0OOOOOo )
   if 7 - 7: O0 + o0000oOoOoO0o . II111iiii
  return
  if 12 - 12: oo - i1IIi
  if 95 - 95: OoOO0ooOOoo0O / oooO0oo0oOOOO . O0 * oooO0oo0oOOOO - Ooo00oOo00o * OoO0O00
  if 6 - 6: oOo0O0Ooo . II111iiii * oo . oo / o0000oOoOoO0o
  if 14 - 14: o0oo0o % oooO0oo0oOOOO - O0 / o0oo0o
  if 91 - 91: i11iIiiIii % o0oo0o * iiiiIi11i - oOoO0oo0OOOo . o0oo0o
 if ( oo000 . dynamic_eids . has_key ( Ooooo0O0 ) ) :
  oOoO000 = oo000 . dynamic_eids [ Ooooo0O0 ] . interface
  iI = lisp . bold ( "Deregistering" , False )
  lisp . lprint ( "{} dynamic-EID {}" . format ( iI ,
 lisp . green ( Ooooo0O0 , False ) ) )
  if 66 - 66: i1I1ii1II1iII / i11iIiiIii * O0
  O00oO000O0O ( Oo0o0000o0o0 , 0 , O00oO0 , None , False )
  if 78 - 78: oooO0oo0oOOOO - OoOO0ooOOoo0O % O0 - II11iiII % ooOO00oOo
  oo000 . dynamic_eids . pop ( Ooooo0O0 )
  if 43 - 43: ooOO00oOo
  if 90 - 90: OoooooooOO + O0 + oOoO0oo0OOOo / OoOO0ooOOoo0O / o0000oOoOoO0o * oOoO0oo0OOOo
  if 100 - 100: OoOO0ooOOoo0O
  if 82 - 82: iIii1I11I1II1
  if ( lisp . lisp_is_macos ( ) == False ) :
   Ooooo0O0 = O00oO0 . print_prefix_no_iid ( )
   OO0OOOOOo = "ip route delete {} dev {}" . format ( Ooooo0O0 , oOoO000 )
   os . system ( OO0OOOOOo )
   if 19 - 19: oo
   if 66 - 66: iiiiIi11i / oOo0O0Ooo
 return
 if 13 - 13: II111iiii
 if 55 - 55: OoO0O00 % i1IIi * OoOO0ooOOoo0O
 if 95 - 95: II11iiII / II111iiii - Ooo00oOo00o % o0oo0o . OoOO0ooOOoo0O
 if 63 - 63: iIii1I11I1II1 / Oo
 if 24 - 24: OoO0O00 / iIii1I11I1II1 % II11iiII * oOo0O0Ooo - iIii1I11I1II1
 if 50 - 50: II111iiii
 if 39 - 39: II111iiii . oOo0O0Ooo - OoO0O00 * i1IIi . OoooooooOO
 if 44 - 44: oo
 if 55 - 55: iiiiIi11i . o0oo0o * o0oo0o
def OO0OO00ooO0 ( ipc ) :
 if ( lisp . lisp_register_all_rtrs ) : return
 if 68 - 68: oOo0O0Ooo * oOoO0oo0OOOo - OoooooooOO - OoOO0ooOOoo0O + iIii1I11I1II1 * i11iIiiIii
 OoOiII11IiIi , iII1I1IiI11ii , I1iIiiiI1 = ipc . split ( "%" )
 if ( lisp . lisp_rtr_list . has_key ( iII1I1IiI11ii ) == False ) : return
 if 27 - 27: ooOO00oOo + oOo0O0Ooo
 lisp . lprint ( "Process ITR IPC message, RTR {} has gone {}" . format (
 lisp . red ( iII1I1IiI11ii , False ) , lisp . bold ( I1iIiiiI1 , False ) ) )
 if 97 - 97: i1IIi * o0oo0o . II111iiii
 OooooOoooO = lisp . lisp_rtr_list [ iII1I1IiI11ii ]
 if ( I1iIiiiI1 == "down" ) :
  lisp . lisp_rtr_list [ iII1I1IiI11ii ] = None
  return
  if 62 - 62: OoooooooOO . o0000oOoOoO0o
  if 28 - 28: iiiiIi11i . iiiiIi11i . iIii1I11I1II1 . II11iiII . oOoO0oo0OOOo * i11iIiiIii
 OooooOoooO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , iII1I1IiI11ii , 32 , 0 )
 lisp . lisp_rtr_list [ iII1I1IiI11ii ] = OooooOoooO
 return
 if 72 - 72: OoOO0ooOOoo0O
 if 26 - 26: oooO0oo0oOOOO % OoO0O00
 if 72 - 72: O0 + Ooo00oOo00o + oo / OoO0O00
 if 83 - 83: oooO0oo0oOOOO - oo . o0000oOoOoO0o
 if 34 - 34: oOo0O0Ooo - iiiiIi11i * OoooooooOO
 if 5 - 5: i11iIiiIii * i1I1ii1II1iII - o0000oOoOoO0o - oOoO0oo0OOOo - i1IIi + i1I1ii1II1iII
 if 4 - 4: Oo + O0 . i1IIi * oOoO0oo0OOOo - Ooo00oOo00o
 if 42 - 42: Ooo00oOo00o * oOo0O0Ooo . ooOO00oOo - i1I1ii1II1iII / II111iiii
def iII1ii11III ( ipc ) :
 O0OO0oOO , OoOiII11IiIi , OOOO0oO0O , ooooOO000oooO0 = ipc . split ( "%" )
 ooooOO000oooO0 = int ( ooooOO000oooO0 , 16 )
 if 75 - 75: i11iIiiIii
 Ii111III1i11I = lisp . lisp_get_echo_nonce ( None , OOOO0oO0O )
 if ( Ii111III1i11I == None ) : Ii111III1i11I = lisp . lisp_echo_nonce ( OOOO0oO0O )
 if 62 - 62: OoOO0ooOOoo0O . ooOO00oOo + ooOO00oOo + II111iiii * iIii1I11I1II1 + OoooooooOO
 if ( OoOiII11IiIi == "R" ) :
  Ii111III1i11I . request_nonce_sent = ooooOO000oooO0
  lisp . lprint ( "Waiting for echo-nonce 0x{} from {}" . format ( lisp . lisp_hex_string ( ooooOO000oooO0 ) , lisp . red ( Ii111III1i11I . rloc_str , False ) ) )
  if 77 - 77: O0 * oOoO0oo0OOOo * iiiiIi11i + ooOO00oOo + oOoO0oo0OOOo - o0oo0o
 elif ( OoOiII11IiIi == "E" ) :
  Ii111III1i11I . echo_nonce_sent = ooooOO000oooO0
  lisp . lprint ( "Sent echo-nonce 0x{} to {}" . format ( lisp . lisp_hex_string ( ooooOO000oooO0 ) , lisp . red ( Ii111III1i11I . rloc_str , False ) ) )
  if 10 - 10: oOoO0oo0OOOo + oooO0oo0oOOOO
  if 58 - 58: oo + OoooooooOO / i1I1ii1II1iII . Oo % Ooo00oOo00o / oOoO0oo0OOOo
 return
 if 62 - 62: II111iiii
 if 12 - 12: oooO0oo0oOOOO + II111iiii
 if 92 - 92: o0oo0o % iIii1I11I1II1 - i1I1ii1II1iII / i11iIiiIii % Oo * Ooo00oOo00o
 if 80 - 80: i1I1ii1II1iII
 if 3 - 3: oOoO0oo0OOOo * OoOO0ooOOoo0O
Oo00O = {
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
 "decentralized-xtr" : [ True , "yes" , "no" ] ,
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

 "lisp map-server" : [ III1IiiI , {
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

 "lisp database-mapping" : [ OoooooOoo , {
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

 "lisp group-mapping" : [ ooooooo00o , {
 "group-name" : [ False ] ,
 "ms-name" : [ True ] ,
 "group-prefix" : [ False ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "rle-address" : [ False ] ,
 "sources" : [ ] ,
 "address" : [ True ] } ] ,

 "show database-mapping" : [ oO00 , { } ] ,
 "show etr-keys" : [ oOOo0oOo0 , { } ] ,
 "show etr-dynamic-eid" : [ lispconfig . lisp_show_dynamic_eid_command , { } ]
 }
if 44 - 44: Oo * OoOO0ooOOoo0O
if 12 - 12: o0000oOoOoO0o . oo % Ooo00oOo00o
if 28 - 28: o0000oOoOoO0o - oo % ooOO00oOo * o0oo0o
if 80 - 80: II11iiII * oooO0oo0oOOOO
if 4 - 4: iIii1I11I1II1 . o0oo0o + II111iiii % OoooooooOO
if 82 - 82: OoooooooOO / Oo * OoOO0ooOOoo0O * O0 . oOoO0oo0OOOo
if ( o000 ( ) == False ) :
 lisp . lprint ( "lisp_etr_startup() failed" )
 lisp . lisp_print_banner ( "ETR abnormal exit" )
 exit ( 1 )
 if 21 - 21: II111iiii + OoO0O00
 if 59 - 59: II11iiII + oo / II111iiii / oOo0O0Ooo
oOoo00 = [ i1111 , I11 ]
if 29 - 29: II11iiII / oOo0O0Ooo . iIii1I11I1II1 / OoOO0ooOOoo0O % oOo0O0Ooo % i1I1ii1II1iII
while ( True ) :
 try : iiI1 , oooOOO0o0O0 , O0OO0oOO = select . select ( oOoo00 , [ ] , [ ] )
 except : break
 if 31 - 31: OoooooooOO - iiiiIi11i / o0oo0o
 if 62 - 62: i11iIiiIii - OoOO0ooOOoo0O
 if 81 - 81: OoOO0ooOOoo0O
 if 92 - 92: II11iiII - OoO0O00 - OoooooooOO / oooO0oo0oOOOO - i1IIi
 if ( i1111 in iiI1 ) :
  OoOiII11IiIi , II1iIi11 , i11i11II11i , OO0 = lisp . lisp_receive ( i1111 , False )
  if 81 - 81: i1IIi / o0oo0o % i11iIiiIii . iIii1I11I1II1 * oOo0O0Ooo + OoooooooOO
  if ( II1iIi11 == "" ) : break
  if 31 - 31: i1IIi % II111iiii
  if ( i11i11II11i == lisp . LISP_DATA_PORT ) :
   OOOO ( oOo0oooo00o , OO0 , II1iIi11 )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( OO0 [ 0 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . o0000oOoOoO0o % ooOO00oOo
   Ii11iIiiI = lisp . lisp_parse_packet ( Oo0o0000o0o0 , OO0 ,
 II1iIi11 , i11i11II11i )
   if 3 - 3: II111iiii / II11iiII
   if 48 - 48: Oo . oOoO0oo0OOOo
   if 49 - 49: i1IIi - oOo0O0Ooo . OoO0O00 + iIii1I11I1II1 - Oo / OoO0O00
   if 24 - 24: iiiiIi11i - i1I1ii1II1iII / Oo
   if 10 - 10: oOo0O0Ooo * i1IIi
   if ( Ii11iIiiI ) :
    oOOoo00O0O = threading . Timer ( 0 ,
 oOo0O , [ None ] )
    oOOoo00O0O . start ( )
    o0oOoO00o = threading . Timer ( 0 ,
 ooO0o0Oo , [ Oo0o0000o0o0 ] )
    o0oOoO00o . start ( )
    if 15 - 15: OoOO0ooOOoo0O + i1IIi - II111iiii % oo
    if 34 - 34: oo
    if 57 - 57: II11iiII . o0000oOoOoO0o % Ooo00oOo00o
    if 32 - 32: OoOO0ooOOoo0O / oooO0oo0oOOOO - O0 * iIii1I11I1II1
    if 70 - 70: OoooooooOO % OoooooooOO % ooOO00oOo
    if 98 - 98: ooOO00oOo
    if 18 - 18: OoOO0ooOOoo0O + OoO0O00 - ooOO00oOo / o0oo0o / II11iiII
    if 53 - 53: II11iiII + Ooo00oOo00o . iiiiIi11i / OoOO0ooOOoo0O
 if ( I11 in iiI1 ) :
  OoOiII11IiIi , II1iIi11 , i11i11II11i , OO0 = lisp . lisp_receive ( I11 , True )
  if 52 - 52: o0oo0o + o0oo0o
  if ( II1iIi11 == "" ) : break
  if 73 - 73: Ooo00oOo00o . i11iIiiIii % OoooooooOO + Oo . OoooooooOO / II11iiII
  if ( OoOiII11IiIi == "command" ) :
   if ( OO0 . find ( "learn%" ) != - 1 ) :
    oo0O ( OO0 )
   elif ( OO0 . find ( "nonce%" ) != - 1 ) :
    iII1ii11III ( OO0 )
   elif ( OO0 . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( OO0 )
   elif ( OO0 . find ( "rtr%" ) != - 1 ) :
    OO0OO00ooO0 ( OO0 )
   elif ( OO0 . find ( "stats%" ) != - 1 ) :
    OO0 = OO0 . split ( "%" ) [ - 1 ]
    lisp . lisp_process_data_plane_decap_stats ( OO0 , None )
   else :
    lispconfig . lisp_process_command ( I11 ,
 OoOiII11IiIi , OO0 , "lisp-etr" , [ Oo00O ] )
    if 54 - 54: oOo0O0Ooo . OoooooooOO
  elif ( OoOiII11IiIi == "api" ) :
   lisp . lisp_process_api ( "lisp-etr" , I11 , OO0 )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( OO0 [ 0 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 36 - 36: iiiiIi11i / II111iiii * oooO0oo0oOOOO % oOoO0oo0OOOo
   lisp . lisp_parse_packet ( Oo0o0000o0o0 , OO0 , II1iIi11 , i11i11II11i )
   if 31 - 31: II111iiii + II11iiII - OoooooooOO . OoOO0ooOOoo0O
   if 28 - 28: o0000oOoOoO0o . oOoO0oo0OOOo
   if 77 - 77: oOoO0oo0OOOo % II111iiii
   if 81 - 81: oOo0O0Ooo % o0000oOoOoO0o / O0 * iIii1I11I1II1 % oooO0oo0oOOOO . oo
oOOoOO0O00o ( )
lisp . lisp_print_banner ( "ETR normal exit" )
exit ( 0 )
if 90 - 90: Ooo00oOo00o
if 44 - 44: Ooo00oOo00o / oOoO0oo0OOOo . OoO0O00 + oOo0O0Ooo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
