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
 ii11i1 = lisp . lisp_decent_dns_suffix
 if ( ii11i1 == None ) :
  ii11i1 = ":"
 else :
  ii11i1 = "&nbsp;(dns-suffix '{}'):" . format ( ii11i1 )
  if 29 - 29: oOoO0oo0OOOo % oo + Oo / Ooo00oOo00o + II11iiII * Ooo00oOo00o
  if 42 - 42: o0000oOoOoO0o + iiiiIi11i
 o0O0o0Oo = "{} configured map-servers" . format ( len ( lisp . lisp_map_servers_list ) )
 Ii11Ii1I = "LISP-ETR Configured Map-Servers{}" . format ( ii11i1 )
 Ii11Ii1I = lisp . lisp_span ( Ii11Ii1I , o0O0o0Oo )
 if 72 - 72: i1I1ii1II1iII / i1IIi * OoO0O00 - o0oo0o
 o0O0o0Oo = ( "P = proxy-reply requested, M = merge-registrations " + "requested, N = Map-Notify requested" )
 if 51 - 51: II111iiii * ooOO00oOo % Ooo00oOo00o * II111iiii % oOoO0oo0OOOo / Oo
 iIIIIii1 = lisp . lisp_span ( "Registration<br>flags" , o0O0o0Oo )
 if 58 - 58: i11iIiiIii % OoOO0ooOOoo0O
 I1i1I += lispconfig . lisp_table_header ( Ii11Ii1I , "Address" , "Auth-Type" ,
 "xTR-ID" , "Site-ID" , iIIIIii1 , "Map-Registers<br>Sent" ,
 "Map-Notifies<br>Received" )
 if 71 - 71: II11iiII + Oo % i11iIiiIii + oOoO0oo0OOOo - oooO0oo0oOOOO
 for oO0OOoO0 in lisp . lisp_map_servers_list . values ( ) :
  oO0OOoO0 . resolve_dns_name ( )
  I111Ii111 = "" if oO0OOoO0 . ms_name == "all" else oO0OOoO0 . ms_name + "<br>"
  i111IiI1I = I111Ii111 + oO0OOoO0 . map_server . print_address_no_iid ( )
  if ( oO0OOoO0 . dns_name ) : i111IiI1I += "<br>" + oO0OOoO0 . dns_name
  if 70 - 70: o0000oOoOoO0o . OoO0O00 / Ooo00oOo00o . o0000oOoOoO0o - O0 / oooO0oo0oOOOO
  ooOooo000oOO = "0x" + lisp . lisp_hex_string ( oO0OOoO0 . xtr_id )
  Oo0oOOo = "{}-{}-{}-{}" . format ( "P" if oO0OOoO0 . proxy_reply else "p" ,
 "M" if oO0OOoO0 . merge_registrations else "m" ,
 "N" if oO0OOoO0 . want_map_notify else "n" ,
 "R" if oO0OOoO0 . refresh_registrations else "r" )
  if 58 - 58: II111iiii * II11iiII * oOoO0oo0OOOo / II11iiII
  oO0o0OOOO = oO0OOoO0 . map_registers_sent + oO0OOoO0 . map_registers_multicast_sent
  if 68 - 68: i1I1ii1II1iII - o0oo0o - oo - oOoO0oo0OOOo + OoOO0ooOOoo0O
  if 10 - 10: OoooooooOO % iIii1I11I1II1
  I1i1I += lispconfig . lisp_table_row ( i111IiI1I ,
 "sha1" if ( oO0OOoO0 . alg_id == lisp . LISP_SHA_1_96_ALG_ID ) else "sha2" ,
 ooOooo000oOO , oO0OOoO0 . site_id , Oo0oOOo , oO0o0OOOO ,
 oO0OOoO0 . map_notifies_received )
  if 54 - 54: o0oo0o - II111iiii % oOo0O0Ooo % OoOO0ooOOoo0O % iIii1I11I1II1 + Oo
 I1i1I += lispconfig . lisp_table_footer ( )
 if 15 - 15: OoOO0ooOOoo0O * Oo * OoO0O00 % i11iIiiIii % oOo0O0Ooo - II11iiII
 if 68 - 68: o0oo0o % i1IIi . oooO0oo0oOOOO . oOoO0oo0OOOo
 if 92 - 92: i1I1ii1II1iII . o0oo0o
 if 31 - 31: o0oo0o . oOo0O0Ooo / O0
 I1i1I = lispconfig . lisp_show_db_list ( "ETR" , I1i1I )
 if 89 - 89: oOo0O0Ooo
 if 68 - 68: ooOO00oOo * OoooooooOO % O0 + ooOO00oOo + Oo
 if 4 - 4: Oo + O0 * II11iiII
 if 55 - 55: OoO0O00 + iIii1I11I1II1 / oOo0O0Ooo * iiiiIi11i - i11iIiiIii - o0000oOoOoO0o
 if ( len ( lisp . lisp_elp_list ) != 0 ) :
  I1i1I = lispconfig . lisp_show_elp_list ( I1i1I )
  if 25 - 25: oOoO0oo0OOOo
  if 7 - 7: i1IIi / oo * o0oo0o . oooO0oo0oOOOO . iIii1I11I1II1
  if 13 - 13: II11iiII / i11iIiiIii
  if 2 - 2: oo / O0 / Ooo00oOo00o % oOo0O0Ooo % o0000oOoOoO0o
  if 52 - 52: Ooo00oOo00o
 if ( len ( lisp . lisp_rle_list ) != 0 ) :
  I1i1I = lispconfig . lisp_show_rle_list ( I1i1I )
  if 95 - 95: o0000oOoOoO0o
  if 87 - 87: Oo + oOo0O0Ooo . II11iiII + oOo0O0Ooo
  if 91 - 91: O0
  if 61 - 61: II111iiii
  if 64 - 64: Oo / oOo0O0Ooo - O0 - OoOO0ooOOoo0O
 if ( len ( lisp . lisp_json_list ) != 0 ) :
  I1i1I = lispconfig . lisp_show_json_list ( I1i1I )
  if 86 - 86: OoOO0ooOOoo0O % oOo0O0Ooo / oo / oOo0O0Ooo
  if 42 - 42: ooOO00oOo
  if 67 - 67: o0oo0o . i1I1ii1II1iII . O0
  if 10 - 10: oOoO0oo0OOOo % oOoO0oo0OOOo - iIii1I11I1II1 / II11iiII + o0000oOoOoO0o
  if 87 - 87: iiiiIi11i * oOoO0oo0OOOo + II11iiII / iIii1I11I1II1 / i1I1ii1II1iII
 if ( len ( lisp . lisp_group_mapping_list ) != 0 ) :
  Ii11Ii1I = "Configured Group Mappings:"
  I1i1I += lispconfig . lisp_table_header ( Ii11Ii1I , "Name" , "Group Prefix" ,
 "Sources" , "Use MS" )
  for I1111IIi in lisp . lisp_group_mapping_list . values ( ) :
   Oo0oO = ""
   for IIiIi1iI in I1111IIi . sources : Oo0oO += IIiIi1iI + ", "
   if ( Oo0oO == "" ) :
    Oo0oO = "*"
   else :
    Oo0oO = Oo0oO [ 0 : - 2 ]
    if 35 - 35: o0000oOoOoO0o % O0 - O0
   I1i1I += lispconfig . lisp_table_row ( I1111IIi . group_name ,
 I1111IIi . group_prefix . print_prefix ( ) , Oo0oO , I1111IIi . use_ms_name )
   if 16 - 16: II111iiii % oOo0O0Ooo - II111iiii + o0000oOoOoO0o
  I1i1I += lispconfig . lisp_table_footer ( )
  if 12 - 12: II11iiII / II11iiII + i11iIiiIii
 return ( I1i1I )
 if 40 - 40: oo . iIii1I11I1II1 / oo / i11iIiiIii
 if 75 - 75: OoOO0ooOOoo0O + Ooo00oOo00o
 if 84 - 84: oooO0oo0oOOOO . i11iIiiIii . oooO0oo0oOOOO * oOoO0oo0OOOo - OoOO0ooOOoo0O
 if 42 - 42: i11iIiiIii
 if 33 - 33: i1I1ii1II1iII - O0 * i1IIi * Ooo00oOo00o - OoO0O00
 if 32 - 32: OoooooooOO / iIii1I11I1II1 - Ooo00oOo00o
 if 91 - 91: i1I1ii1II1iII % i1IIi % iIii1I11I1II1
def IIi1I11I1II ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "ETR" ) )
 if 63 - 63: OoooooooOO - ooOO00oOo . II111iiii / Ooo00oOo00o . oOo0O0Ooo / O0
 if 84 - 84: oooO0oo0oOOOO
 if 86 - 86: oOo0O0Ooo - o0000oOoOoO0o - ooOO00oOo * i1I1ii1II1iII
 if 66 - 66: OoooooooOO + O0
 if 11 - 11: OoOO0ooOOoo0O + OoooooooOO - ooOO00oOo / Ooo00oOo00o + OoO0O00 . II111iiii
 if 41 - 41: o0000oOoOoO0o - O0 - O0
 if 68 - 68: II11iiII % o0oo0o
def ooO00OO0 ( kv_pairs ) :
 global i1
 global oOOoo00O0O
 if 31 - 31: i1I1ii1II1iII % i1I1ii1II1iII % OoOO0ooOOoo0O
 OOOOoo0Oo = [ ]
 ii111iI1iIi1 = [ ]
 OOO = 0
 oo0OOo0 = 0
 I11IiI = ""
 O0ooO0Oo00o = False
 ooO0oOOooOo0 = False
 i1I1ii11i1Iii = False
 I1IiiiiI = False
 o0O = 0
 I111Ii111 = None
 IiII = 0
 ii1iII1II = None
 if 48 - 48: II111iiii * o0000oOoOoO0o . OoOO0ooOOoo0O + iiiiIi11i
 for OoO0o in kv_pairs . keys ( ) :
  oO0o0Ooooo = kv_pairs [ OoO0o ]
  if ( OoO0o == "ms-name" ) :
   I111Ii111 = oO0o0Ooooo [ 0 ]
   if 94 - 94: Ooo00oOo00o * o0000oOoOoO0o / OoO0O00 / o0000oOoOoO0o
  if ( OoO0o == "address" ) :
   for oO0 in range ( len ( oO0o0Ooooo ) ) :
    OOOOoo0Oo . append ( oO0o0Ooooo [ oO0 ] )
    if 75 - 75: Oo + oOo0O0Ooo + Ooo00oOo00o * OoOO0ooOOoo0O % iiiiIi11i . i1I1ii1II1iII
    if 55 - 55: II11iiII . oo
  if ( OoO0o == "dns-name" ) :
   for oO0 in range ( len ( oO0o0Ooooo ) ) :
    ii111iI1iIi1 . append ( oO0o0Ooooo [ oO0 ] )
    if 61 - 61: OoO0O00 % oooO0oo0oOOOO . OoO0O00
    if 100 - 100: o0oo0o * O0
  if ( OoO0o == "authentication-type" ) :
   oo0OOo0 = lisp . LISP_SHA_1_96_ALG_ID if ( oO0o0Ooooo == "sha1" ) else lisp . LISP_SHA_256_128_ALG_ID if ( oO0o0Ooooo == "sha2" ) else ""
   if 64 - 64: II11iiII % iIii1I11I1II1 * iiiiIi11i
   if 79 - 79: O0
  if ( OoO0o == "authentication-key" ) :
   if ( oo0OOo0 == 0 ) : oo0OOo0 = lisp . LISP_SHA_256_128_ALG_ID
   oOO00O = lisp . lisp_parse_auth_key ( oO0o0Ooooo )
   OOO = oOO00O . keys ( ) [ 0 ]
   I11IiI = oOO00O [ OOO ]
   if 77 - 77: OoO0O00 - i1IIi - OoOO0ooOOoo0O . oOo0O0Ooo
  if ( OoO0o == "proxy-reply" ) :
   O0ooO0Oo00o = True if oO0o0Ooooo == "yes" else False
   if 39 - 39: II111iiii / Oo + o0oo0o / oOo0O0Ooo
  if ( OoO0o == "merge-registrations" ) :
   ooO0oOOooOo0 = True if oO0o0Ooooo == "yes" else False
   if 13 - 13: oooO0oo0oOOOO + O0 + i1I1ii1II1iII % oo / Ooo00oOo00o . oooO0oo0oOOOO
  if ( OoO0o == "refresh-registrations" ) :
   i1I1ii11i1Iii = True if oO0o0Ooooo == "yes" else False
   if 86 - 86: iiiiIi11i * Ooo00oOo00o % i1IIi . o0000oOoOoO0o . i11iIiiIii
  if ( OoO0o == "want-map-notify" ) :
   I1IiiiiI = True if oO0o0Ooooo == "yes" else False
   if 56 - 56: oOoO0oo0OOOo % O0 - oo
  if ( OoO0o == "site-id" ) :
   o0O = int ( oO0o0Ooooo )
   if 100 - 100: o0000oOoOoO0o - O0 % iiiiIi11i * II11iiII + oo
  if ( OoO0o == "encryption-key" ) :
   ii1iII1II = lisp . lisp_parse_auth_key ( oO0o0Ooooo )
   IiII = ii1iII1II . keys ( ) [ 0 ]
   ii1iII1II = ii1iII1II [ IiII ]
   if 88 - 88: OoooooooOO - ooOO00oOo * O0 * OoooooooOO . OoooooooOO
   if 33 - 33: o0oo0o + i1I1ii1II1iII * iiiiIi11i / iIii1I11I1II1 - oo
   if 54 - 54: o0oo0o / II11iiII . iiiiIi11i % i1I1ii1II1iII
   if 57 - 57: i11iIiiIii . oOoO0oo0OOOo - o0000oOoOoO0o - iiiiIi11i + oOo0O0Ooo
   if 63 - 63: oOo0O0Ooo * i1I1ii1II1iII
   if 69 - 69: O0 . ooOO00oOo
 oO0OOoO0 = None
 for i111IiI1I in OOOOoo0Oo :
  if ( i111IiI1I == "" ) : continue
  oO0OOoO0 = lisp . lisp_ms ( i111IiI1I , None , I111Ii111 , oo0OOo0 , OOO , I11IiI ,
 O0ooO0Oo00o , ooO0oOOooOo0 , i1I1ii11i1Iii , I1IiiiiI , o0O , IiII , ii1iII1II )
  if 49 - 49: oo - OoOO0ooOOoo0O
 for OoOOoOooooOOo in ii111iI1iIi1 :
  if ( OoOOoOooooOOo == "" ) : continue
  oO0OOoO0 = lisp . lisp_ms ( None , OoOOoOooooOOo , I111Ii111 , oo0OOo0 , OOO , I11IiI ,
 O0ooO0Oo00o , ooO0oOOooOo0 , i1I1ii11i1Iii , I1IiiiiI , o0O , IiII , ii1iII1II )
  if 87 - 87: oo
  if 58 - 58: oOo0O0Ooo % Ooo00oOo00o
  if 50 - 50: o0oo0o . Ooo00oOo00o
  if 97 - 97: O0 + oOo0O0Ooo
  if 89 - 89: Ooo00oOo00o + ooOO00oOo * OoOO0ooOOoo0O * o0000oOoOoO0o
  if 37 - 37: OoooooooOO - O0 - Ooo00oOo00o
 o0o0O0O00oOOo = ( len ( lisp . lisp_map_servers_list ) == 1 )
 if ( o0o0O0O00oOOo ) :
  oO0OOoO0 = lisp . lisp_map_servers_list . values ( ) [ 0 ]
  oOOoo00O0O = threading . Timer ( 2 , iIIIiIi ,
 [ oO0OOoO0 . map_server ] )
  oOOoo00O0O . start ( )
 else :
  if 100 - 100: oo / Ooo00oOo00o % II111iiii % OoO0O00 % II11iiII
  if 98 - 98: OoOO0ooOOoo0O % i11iIiiIii % Oo + o0000oOoOoO0o
  if 78 - 78: oOoO0oo0OOOo % iiiiIi11i / i1I1ii1II1iII - iIii1I11I1II1
  if 69 - 69: o0oo0o
  if 11 - 11: oo
  if 16 - 16: o0000oOoOoO0o + oooO0oo0oOOOO * O0 % i1IIi . oo
  if 67 - 67: OoooooooOO / oo * o0000oOoOoO0o + OoOO0ooOOoo0O
  if 65 - 65: OoooooooOO - oOoO0oo0OOOo / Oo / II111iiii / i1IIi
  if ( lisp . lisp_nat_traversal ) : return
  if ( oO0OOoO0 and len ( lisp . lisp_db_list ) > 0 ) :
   o00oo0 ( Oo0o0000o0o0 , None , None , oO0OOoO0 , False )
   if 38 - 38: Oo % II111iiii % OoOO0ooOOoo0O / ooOO00oOo + oOo0O0Ooo / i1IIi
   if 54 - 54: iIii1I11I1II1 % oOoO0oo0OOOo - II11iiII / iiiiIi11i - ooOO00oOo . OoOO0ooOOoo0O
   if 11 - 11: oOoO0oo0OOOo . ooOO00oOo * oooO0oo0oOOOO * OoooooooOO + Oo
   if 33 - 33: O0 * Ooo00oOo00o - o0oo0o % o0oo0o
   if 18 - 18: o0oo0o / OoO0O00 * o0oo0o + o0oo0o * i11iIiiIii * oOoO0oo0OOOo
   if 11 - 11: Oo / oOo0O0Ooo - oooO0oo0oOOOO * OoooooooOO + OoooooooOO . oOo0O0Ooo
   if 26 - 26: o0000oOoOoO0o % oOoO0oo0OOOo
 if ( len ( lisp . lisp_db_list ) > 0 ) :
  if ( i1 != None and
 i1 . is_alive ( ) ) : return
  if 76 - 76: oooO0oo0oOOOO * i1I1ii1II1iII
  i1 = threading . Timer ( 5 ,
 ooO0o0Oo , [ Oo0o0000o0o0 ] )
  i1 . start ( )
  if 52 - 52: II11iiII
 return
 if 19 - 19: oo
 if 25 - 25: o0000oOoOoO0o / Oo
 if 31 - 31: II11iiII . O0 % oo . Ooo00oOo00o + oooO0oo0oOOOO
 if 71 - 71: o0oo0o . II111iiii
 if 62 - 62: OoooooooOO . OoOO0ooOOoo0O
 if 61 - 61: oOo0O0Ooo - II11iiII - i1IIi
 if 25 - 25: O0 * OoOO0ooOOoo0O + oOoO0oo0OOOo . Ooo00oOo00o . Ooo00oOo00o
def oOooO ( kv_pairs ) :
 Oo0oO = [ ]
 IIIIiI11I11 = None
 oo00o0 = None
 I111Ii111 = "all"
 if 4 - 4: o0000oOoOoO0o % iiiiIi11i * ooOO00oOo
 for OoO0o in kv_pairs . keys ( ) :
  oO0o0Ooooo = kv_pairs [ OoO0o ]
  if ( OoO0o == "group-name" ) :
   o0O0OOOOoOO0 = oO0o0Ooooo
   if 23 - 23: i11iIiiIii
  if ( OoO0o == "group-prefix" ) :
   if ( IIIIiI11I11 == None ) :
    IIIIiI11I11 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 30 - 30: Ooo00oOo00o - i1IIi % II111iiii + OoOO0ooOOoo0O * iIii1I11I1II1
   IIIIiI11I11 . store_prefix ( oO0o0Ooooo )
   if 81 - 81: oooO0oo0oOOOO % i1IIi . iIii1I11I1II1
  if ( OoO0o == "instance-id" ) :
   if ( IIIIiI11I11 == None ) :
    IIIIiI11I11 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 4 - 4: i11iIiiIii % ooOO00oOo % i1IIi / oooO0oo0oOOOO
   IIIIiI11I11 . instance_id = int ( oO0o0Ooooo )
   if 6 - 6: i1I1ii1II1iII / oo % II11iiII - oo
  if ( OoO0o == "ms-name" ) :
   I111Ii111 = oO0o0Ooooo [ 0 ]
   if 31 - 31: II11iiII
  if ( OoO0o == "address" ) :
   for i1OOO0000oO in oO0o0Ooooo :
    if ( i1OOO0000oO != "" ) : Oo0oO . append ( i1OOO0000oO )
    if 15 - 15: oOo0O0Ooo % oo * OoOO0ooOOoo0O
    if 81 - 81: Oo - iIii1I11I1II1 - i1IIi / o0oo0o - O0 * OoOO0ooOOoo0O
  if ( OoO0o == "rle-address" ) :
   if ( oo00o0 == None ) :
    oo00o0 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 20 - 20: iiiiIi11i % oooO0oo0oOOOO
   oo00o0 . store_address ( oO0o0Ooooo )
   if 19 - 19: oOoO0oo0OOOo % oooO0oo0oOOOO + Oo / o0oo0o . Oo
   if 12 - 12: i1IIi + i1IIi - oOoO0oo0OOOo * OoO0O00 % OoO0O00 - II111iiii
 I1111IIi = lisp . lisp_group_mapping ( o0O0OOOOoOO0 , I111Ii111 , IIIIiI11I11 , Oo0oO ,
 oo00o0 )
 I1111IIi . add_group ( )
 return
 if 52 - 52: Oo . i1I1ii1II1iII + o0oo0o
 if 38 - 38: i1IIi - II111iiii . o0oo0o
 if 58 - 58: oo . i1I1ii1II1iII + oOo0O0Ooo
 if 66 - 66: i1I1ii1II1iII / iiiiIi11i * OoooooooOO + OoooooooOO % OoOO0ooOOoo0O
 if 49 - 49: iiiiIi11i - i11iIiiIii . o0oo0o * o0000oOoOoO0o % i1I1ii1II1iII + i1IIi
 if 71 - 71: Ooo00oOo00o
 if 38 - 38: iiiiIi11i % oOo0O0Ooo + oOoO0oo0OOOo . i11iIiiIii
def oo0000ooooO0o ( quiet , db , eid , group , ttl ) :
 if 40 - 40: oOoO0oo0OOOo + i1IIi * II11iiII
 if 85 - 85: o0000oOoOoO0o * OoO0O00 . O0 - i11iIiiIii
 if 18 - 18: o0000oOoOoO0o + oooO0oo0oOOOO - O0
 if 53 - 53: i1IIi
 if 87 - 87: i11iIiiIii + o0oo0o . oOoO0oo0OOOo * o0oo0o . Oo / oOoO0oo0OOOo
 if 76 - 76: O0 + i1IIi . OoO0O00 * oo * o0000oOoOoO0o
 if 14 - 14: Ooo00oOo00o % O0 * i1I1ii1II1iII + o0000oOoOoO0o + OoO0O00 * o0000oOoOoO0o
 if 3 - 3: oOo0O0Ooo * OoO0O00
 oOoO00oo0O = { }
 for ooo in db . rloc_set :
  if ( ooo . translated_rloc . is_null ( ) ) : continue
  if 36 - 36: OoooooooOO . ooOO00oOo
  for oO in lisp . lisp_rtr_list :
   IIiIi = lisp . lisp_rtr_list [ oO ]
   if ( lisp . lisp_register_all_rtrs == False and IIiIi == None ) :
    lisp . lprint ( "  Exclude unreachable RTR {}" . format ( lisp . red ( oO , False ) ) )
    if 91 - 91: oOoO0oo0OOOo * OoO0O00 / oo . O0 + ooOO00oOo + oOo0O0Ooo
    continue
    if 8 - 8: iiiiIi11i / oOoO0oo0OOOo
   if ( IIiIi == None ) : continue
   oOoO00oo0O [ oO ] = IIiIi
   if 20 - 20: oo
  break
  if 95 - 95: i1I1ii1II1iII - oo
  if 34 - 34: Oo * oo . i1IIi * Oo / Oo
 IIiI1Ii = 0
 O0O0O0Oo = ""
 for OOOOoO00o0O in [ eid . instance_id ] + eid . iid_list :
  I1I1I1IIi1III = lisp . lisp_eid_record ( )
  if 5 - 5: OoO0O00 % Oo % i11iIiiIii + Ooo00oOo00o / oOoO0oo0OOOo - oOoO0oo0OOOo
  I1I1I1IIi1III . rloc_count = len ( db . rloc_set ) + len ( oOoO00oo0O )
  I1I1I1IIi1III . authoritative = True
  I1I1I1IIi1III . record_ttl = ttl
  I1I1I1IIi1III . eid . copy_address ( eid )
  I1I1I1IIi1III . eid . instance_id = OOOOoO00o0O
  I1I1I1IIi1III . eid . iid_list = [ ]
  I1I1I1IIi1III . group . copy_address ( group )
  if 45 - 45: oOoO0oo0OOOo % oo - i11iIiiIii
  O0O0O0Oo += I1I1I1IIi1III . encode ( )
  if ( not quiet ) :
   ii1iiIiIII1ii = lisp . lisp_print_eid_tuple ( eid , group )
   oO0o0oooO0oO = ""
   if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
    oO0o0oooO0oO = lisp . lisp_get_decent_index ( eid )
    oO0o0oooO0oO = lisp . bold ( str ( oO0o0oooO0oO ) , False )
    oO0o0oooO0oO = ", decent-index {}" . format ( oO0o0oooO0oO )
    if 19 - 19: i11iIiiIii + OoooooooOO - OoO0O00 - OoOO0ooOOoo0O
   lisp . lprint ( "  EID-prefix {} for ms-name '{}'{}" . format ( lisp . green ( ii1iiIiIII1ii , False ) , db . use_ms_name , oO0o0oooO0oO ) )
   if 21 - 21: O0 % oooO0oo0oOOOO . oo / II111iiii + oooO0oo0oOOOO
   I1I1I1IIi1III . print_record ( "  " , False )
   if 53 - 53: iiiiIi11i - oo - iiiiIi11i * i1I1ii1II1iII
   if 71 - 71: O0 - iIii1I11I1II1
  for ooo in db . rloc_set :
   i1II = lisp . lisp_rloc_record ( )
   i1II . store_rloc_entry ( ooo )
   i1II . local_bit = ooo . rloc . is_local ( )
   i1II . reach_bit = True
   O0O0O0Oo += i1II . encode ( )
   if ( not quiet ) : i1II . print_record ( "    " )
   if 14 - 14: iiiiIi11i / iiiiIi11i % Oo
   if 56 - 56: oo . O0 + OoO0O00
   if 1 - 1: i1I1ii1II1iII
   if 97 - 97: II11iiII + i1I1ii1II1iII + O0 + i11iIiiIii
   if 77 - 77: Ooo00oOo00o / OoooooooOO
   if 46 - 46: Ooo00oOo00o % iIii1I11I1II1 . i1I1ii1II1iII % i1I1ii1II1iII + i11iIiiIii
  for IIiIi in oOoO00oo0O . values ( ) :
   i1II = lisp . lisp_rloc_record ( )
   i1II . rloc . copy_address ( IIiIi )
   i1II . priority = 254
   i1II . rloc_name = "RTR"
   i1II . weight = 0
   i1II . mpriority = 255
   i1II . mweight = 0
   i1II . local_bit = False
   i1II . reach_bit = True
   O0O0O0Oo += i1II . encode ( )
   if ( not quiet ) : i1II . print_record ( "    RTR " )
   if 72 - 72: iIii1I11I1II1 * o0000oOoOoO0o % Oo / ooOO00oOo
   if 35 - 35: Oo + i1IIi % oOoO0oo0OOOo % OoOO0ooOOoo0O + iiiiIi11i
   if 17 - 17: i1IIi
   if 21 - 21: OoO0O00
   if 29 - 29: OoOO0ooOOoo0O / II111iiii / Oo * II11iiII
  IIiI1Ii += 1
  if 10 - 10: o0oo0o % oooO0oo0oOOOO * oooO0oo0oOOOO . OoOO0ooOOoo0O / o0000oOoOoO0o % II11iiII
 return ( O0O0O0Oo , IIiI1Ii )
 if 49 - 49: ooOO00oOo / iiiiIi11i + O0 * Ooo00oOo00o
 if 28 - 28: Oo + i11iIiiIii / OoOO0ooOOoo0O % oOo0O0Ooo % OoO0O00 - O0
 if 54 - 54: i1IIi + II111iiii
 if 83 - 83: oOoO0oo0OOOo - oo + II11iiII
 if 5 - 5: o0000oOoOoO0o
 if 46 - 46: oooO0oo0oOOOO
 if 45 - 45: Oo
 if 21 - 21: iiiiIi11i . o0oo0o . II11iiII / OoO0O00 / o0oo0o
def o00oo0 ( lisp_sockets , ttl , eid_only , ms_only , refresh ) :
 if 17 - 17: II11iiII / II11iiII / OoOO0ooOOoo0O
 if 1 - 1: i1IIi . i11iIiiIii % II11iiII
 if 82 - 82: iIii1I11I1II1 + OoO0O00 . iIii1I11I1II1 % oooO0oo0oOOOO / o0000oOoOoO0o . o0000oOoOoO0o
 if 14 - 14: Ooo00oOo00o . II11iiII . OoOO0ooOOoo0O + OoooooooOO - II11iiII + oooO0oo0oOOOO
 if ( eid_only != None ) :
  iII1iiiiIII = 1
 else :
  iII1iiiiIII = lisp . lisp_db_list_length ( )
  if ( iII1iiiiIII == 0 ) : return
  if 78 - 78: II11iiII * Ooo00oOo00o / OoOO0ooOOoo0O - O0 / oooO0oo0oOOOO
  if 96 - 96: oOo0O0Ooo . Ooo00oOo00o - Oo
 lisp . lprint ( "Build Map-Register for {} database-mapping entries" . format ( iII1iiiiIII ) )
 if 99 - 99: oooO0oo0oOOOO . OoO0O00 - o0000oOoOoO0o % o0000oOoOoO0o * O0 . II111iiii
 if 4 - 4: o0000oOoOoO0o
 if 51 - 51: ooOO00oOo - O0 % iiiiIi11i - II111iiii
 if 31 - 31: i1I1ii1II1iII / OoO0O00 - i1I1ii1II1iII - II11iiII
 if 7 - 7: i1I1ii1II1iII % O0 . oOo0O0Ooo + oo - OoOO0ooOOoo0O
 o0o0O00oo0 = lisp . lisp_decent_pull_xtr_configured ( )
 if 27 - 27: i11iIiiIii % II111iiii % OoOO0ooOOoo0O . O0 - OoO0O00 + oOo0O0Ooo
 if 57 - 57: iIii1I11I1II1 / OoOO0ooOOoo0O - i1IIi
 if 51 - 51: oooO0oo0oOOOO
 if 25 - 25: OoooooooOO + oooO0oo0oOOOO * oOoO0oo0OOOo
 OoO0ooO = ( iII1iiiiIII > 12 )
 if 51 - 51: i1I1ii1II1iII / Oo * oOo0O0Ooo . i1I1ii1II1iII / oOoO0oo0OOOo / i11iIiiIii
 IIIII = { }
 if ( o0o0O00oo0 ) :
  if 78 - 78: o0000oOoOoO0o * i1IIi
  if 1 - 1: oo / oooO0oo0oOOOO * Oo
  if 1 - 1: OoOO0ooOOoo0O * Ooo00oOo00o . oOo0O0Ooo / O0
  if 100 - 100: o0oo0o . Ooo00oOo00o * OoO0O00 % O0 * O0
  if 14 - 14: oOoO0oo0OOOo . Oo + II111iiii / i1I1ii1II1iII / OoOO0ooOOoo0O
  for ooo0O in lisp . lisp_db_list :
   iII1iii = ooo0O . eid if ooo0O . group . is_null ( ) else ooo0O . group
   i11i1iiiII = lisp . lisp_get_decent_dns_name ( iII1iii )
   IIIII [ i11i1iiiII ] = [ ]
   if 68 - 68: i11iIiiIii * ooOO00oOo
 else :
  if 46 - 46: oOo0O0Ooo / iIii1I11I1II1 % i1I1ii1II1iII . iIii1I11I1II1 * i1I1ii1II1iII
  if 38 - 38: oOoO0oo0OOOo - i1I1ii1II1iII / O0 . o0oo0o
  if 45 - 45: o0oo0o
  if 83 - 83: oOo0O0Ooo . OoooooooOO
  if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / oooO0oo0oOOOO / i11iIiiIii
  for oO0OOoO0 in lisp . lisp_map_servers_list . values ( ) :
   if ( ms_only != None and oO0OOoO0 != ms_only ) : continue
   IIIII [ oO0OOoO0 . ms_name ] = [ ]
   if 62 - 62: ooOO00oOo / oOoO0oo0OOOo
   if 7 - 7: OoooooooOO . oooO0oo0oOOOO
   if 53 - 53: o0000oOoOoO0o % o0000oOoOoO0o * Ooo00oOo00o + oOo0O0Ooo
   if 92 - 92: OoooooooOO + i1IIi / o0000oOoOoO0o * O0
   if 100 - 100: Oo % iIii1I11I1II1 * II111iiii - i1I1ii1II1iII
   if 92 - 92: Oo
 II11iI111i1 = lisp . lisp_map_register ( )
 II11iI111i1 . nonce = 0xaabbccdddfdfdf00
 II11iI111i1 . xtr_id_present = True
 if 95 - 95: OoooooooOO - oooO0oo0oOOOO * oo + oOo0O0Ooo
 if ( ttl == None ) : ttl = lisp . LISP_REGISTER_TTL
 if 10 - 10: Ooo00oOo00o / i11iIiiIii
 if 92 - 92: OoOO0ooOOoo0O . o0oo0o
 if 85 - 85: oOoO0oo0OOOo . o0oo0o
 if 78 - 78: Oo * o0oo0o + iIii1I11I1II1 + iIii1I11I1II1 / o0oo0o . o0000oOoOoO0o
 for ooo0O in lisp . lisp_db_list :
  if ( o0o0O00oo0 ) :
   O000 = lisp . lisp_get_decent_dns_name ( ooo0O . eid )
  else :
   O000 = ooo0O . use_ms_name
   if 79 - 79: OoooooooOO - oo
   if 69 - 69: OoOO0ooOOoo0O
   if 95 - 95: Oo + i11iIiiIii * o0oo0o - i1IIi * o0oo0o - iIii1I11I1II1
   if 75 - 75: OoooooooOO * oooO0oo0oOOOO
   if 9 - 9: oooO0oo0oOOOO - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
   if 39 - 39: oooO0oo0oOOOO * OoO0O00 + iIii1I11I1II1 - oooO0oo0oOOOO + II11iiII
  if ( IIIII . has_key ( O000 ) == False ) : continue
  if 69 - 69: O0
  o0ooO = IIIII [ O000 ]
  if ( o0ooO == [ ] ) :
   o0ooO = [ "" , 0 ]
   IIIII [ O000 ] . append ( o0ooO )
  else :
   o0ooO = IIIII [ O000 ] [ - 1 ]
   if 74 - 74: O0 * iiiiIi11i - i11iIiiIii + o0oo0o
   if 17 - 17: iIii1I11I1II1 . OoooooooOO / OoOO0ooOOoo0O % II111iiii % i1IIi / i11iIiiIii
   if 58 - 58: OoO0O00 . II111iiii + iiiiIi11i - i11iIiiIii / II111iiii / O0
   if 85 - 85: oOo0O0Ooo + II11iiII
   if 10 - 10: oooO0oo0oOOOO / ooOO00oOo + oOo0O0Ooo / i1IIi
   if 27 - 27: o0000oOoOoO0o
   if 67 - 67: oo
   if 55 - 55: oOoO0oo0OOOo - i1I1ii1II1iII * Ooo00oOo00o + oOo0O0Ooo * oOo0O0Ooo * O0
   if 91 - 91: o0oo0o - II11iiII % iIii1I11I1II1 - OoooooooOO % Oo
   if 98 - 98: ooOO00oOo . ooOO00oOo * iiiiIi11i * II111iiii * o0oo0o
  O0O0O0Oo = ""
  if ( ooo0O . dynamic_eid_configured ( ) ) :
   for oOooO0 in ooo0O . dynamic_eids . values ( ) :
    iII1iii = oOooO0 . dynamic_eid
    if ( eid_only == None or eid_only . is_exact_match ( iII1iii ) ) :
     OOOoO000 , IIiI1Ii = oo0000ooooO0o ( OoO0ooO , ooo0O ,
 iII1iii , ooo0O . group , ttl )
     O0O0O0Oo += OOOoO000
     o0ooO [ 1 ] += IIiI1Ii
     if 57 - 57: II111iiii
     if 54 - 54: OoO0O00 + iiiiIi11i + i11iIiiIii
  else :
   if ( eid_only == None ) :
    O0O0O0Oo , IIiI1Ii = oo0000ooooO0o ( OoO0ooO , ooo0O ,
 ooo0O . eid , ooo0O . group , ttl )
    o0ooO [ 1 ] += IIiI1Ii
    if 28 - 28: iiiiIi11i
    if 70 - 70: oooO0oo0oOOOO
    if 34 - 34: o0oo0o % oooO0oo0oOOOO
    if 3 - 3: II111iiii / II11iiII + oooO0oo0oOOOO . Oo . ooOO00oOo
    if 83 - 83: iiiiIi11i + OoooooooOO
    if 22 - 22: o0000oOoOoO0o % i1I1ii1II1iII * OoooooooOO - Ooo00oOo00o / iIii1I11I1II1
  o0ooO [ 0 ] += O0O0O0Oo
  if 86 - 86: OoooooooOO . i1I1ii1II1iII % oOo0O0Ooo / OoOO0ooOOoo0O * i1I1ii1II1iII / Ooo00oOo00o
  if ( o0ooO [ 1 ] == 20 ) :
   o0ooO = [ "" , 0 ]
   IIIII [ O000 ] . append ( o0ooO )
   if 64 - 64: i11iIiiIii
   if 38 - 38: oooO0oo0oOOOO / oo - oooO0oo0oOOOO . OoOO0ooOOoo0O
   if 69 - 69: OoooooooOO + oOoO0oo0OOOo
   if 97 - 97: II11iiII - ooOO00oOo / o0000oOoOoO0o . i11iIiiIii % iiiiIi11i * iiiiIi11i
   if 1 - 1: oo % Oo
   if 65 - 65: oo + oOo0O0Ooo / II11iiII
 for oO0OOoO0 in lisp . lisp_map_servers_list . values ( ) :
  if ( ms_only != None and oO0OOoO0 != ms_only ) : continue
  if 83 - 83: Ooo00oOo00o . i1I1ii1II1iII - OoO0O00
  O000 = oO0OOoO0 . dns_name if o0o0O00oo0 else oO0OOoO0 . ms_name
  if ( IIIII . has_key ( O000 ) == False ) : continue
  if 65 - 65: iIii1I11I1II1 / Oo . oooO0oo0oOOOO - II111iiii
  for o0ooO in IIIII [ O000 ] :
   if 72 - 72: iIii1I11I1II1 / oooO0oo0oOOOO % i1I1ii1II1iII % II11iiII - OoOO0ooOOoo0O % II11iiII
   if 100 - 100: OoO0O00 + i11iIiiIii
   if 71 - 71: OoOO0ooOOoo0O / Ooo00oOo00o / o0oo0o % II11iiII
   if 51 - 51: oooO0oo0oOOOO * O0 / II111iiii . o0000oOoOoO0o % II11iiII / oo
   II11iI111i1 . record_count = o0ooO [ 1 ]
   if ( II11iI111i1 . record_count == 0 ) : continue
   if 9 - 9: oo % oo % II111iiii
   II11iI111i1 . nonce += 1
   II11iI111i1 . alg_id = oO0OOoO0 . alg_id
   II11iI111i1 . key_id = oO0OOoO0 . key_id
   II11iI111i1 . proxy_reply_requested = oO0OOoO0 . proxy_reply
   II11iI111i1 . merge_register_requested = oO0OOoO0 . merge_registrations
   II11iI111i1 . map_notify_requested = oO0OOoO0 . want_map_notify
   II11iI111i1 . xtr_id = oO0OOoO0 . xtr_id
   II11iI111i1 . site_id = oO0OOoO0 . site_id
   II11iI111i1 . encrypt_bit = ( oO0OOoO0 . ekey != None )
   if ( oO0OOoO0 . refresh_registrations ) :
    II11iI111i1 . map_register_refresh = refresh
    if 30 - 30: oooO0oo0oOOOO + o0oo0o - oooO0oo0oOOOO . oooO0oo0oOOOO - II111iiii + O0
   if ( oO0OOoO0 . ekey != None ) : II11iI111i1 . encryption_key_id = oO0OOoO0 . ekey_id
   oOO0 = II11iI111i1 . encode ( )
   II11iI111i1 . print_map_register ( )
   if 46 - 46: o0000oOoOoO0o % oOo0O0Ooo
   if 64 - 64: i11iIiiIii - II111iiii
   if 77 - 77: oOo0O0Ooo % o0000oOoOoO0o
   if 9 - 9: ooOO00oOo - OoO0O00 * OoooooooOO . OoO0O00
   if 2 - 2: OoooooooOO % II11iiII
   oOoOOo0oo0 = II11iI111i1 . encode_xtr_id ( "" )
   O0O0O0Oo = o0ooO [ 0 ]
   oOO0 = oOO0 + O0O0O0Oo + oOoOOo0oo0
   if 60 - 60: Oo * o0oo0o + OoO0O00
   oO0OOoO0 . map_registers_sent += 1
   lisp . lisp_send_map_register ( lisp_sockets , oOO0 , II11iI111i1 , oO0OOoO0 )
   time . sleep ( .001 )
   if 19 - 19: ooOO00oOo * OoOO0ooOOoo0O / OoOO0ooOOoo0O . OoooooooOO - II11iiII + i11iIiiIii
   if 88 - 88: i11iIiiIii - Oo
   if 67 - 67: II11iiII . OoO0O00 + oOo0O0Ooo - OoooooooOO
   if 70 - 70: II11iiII / II111iiii - iIii1I11I1II1 - i1I1ii1II1iII
   if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - OoOO0ooOOoo0O
  oO0OOoO0 . resolve_dns_name ( )
  if 30 - 30: oOo0O0Ooo
  if 21 - 21: i11iIiiIii / o0oo0o % II11iiII * O0 . OoOO0ooOOoo0O - iIii1I11I1II1
  if 26 - 26: II111iiii * oOo0O0Ooo
  if 10 - 10: II111iiii . i1I1ii1II1iII
  if 32 - 32: o0000oOoOoO0o . oooO0oo0oOOOO . OoooooooOO - ooOO00oOo + iiiiIi11i
  if ( ms_only != None and oO0OOoO0 == ms_only ) : break
  if 88 - 88: i1I1ii1II1iII
 return
 if 19 - 19: II111iiii * oooO0oo0oOOOO + o0000oOoOoO0o
 if 65 - 65: II11iiII . o0oo0o . ooOO00oOo . i1I1ii1II1iII - II11iiII
 if 19 - 19: i11iIiiIii + i1I1ii1II1iII % Oo
 if 14 - 14: ooOO00oOo . II111iiii . OoOO0ooOOoo0O / o0000oOoOoO0o % oOoO0oo0OOOo - Oo
 if 67 - 67: OoOO0ooOOoo0O - II11iiII . i1IIi
 if 35 - 35: i1I1ii1II1iII + Oo - iiiiIi11i . i1I1ii1II1iII . oooO0oo0oOOOO
 if 87 - 87: oOo0O0Ooo
 if 25 - 25: i1IIi . ooOO00oOo - oOo0O0Ooo / ooOO00oOo % ooOO00oOo * iIii1I11I1II1
 if 50 - 50: ooOO00oOo . i11iIiiIii - iiiiIi11i . iiiiIi11i
def iIIIiIi ( ms ) :
 global oOOoo00O0O
 global i1111
 if 31 - 31: II11iiII / OoO0O00 * i1IIi . oOo0O0Ooo
 lisp . lisp_set_exception ( )
 if 57 - 57: II11iiII + iIii1I11I1II1 % i1IIi % oo
 if 83 - 83: Ooo00oOo00o / i11iIiiIii % iIii1I11I1II1 . OoOO0ooOOoo0O % iiiiIi11i . OoooooooOO
 if 94 - 94: o0000oOoOoO0o + iIii1I11I1II1 % ooOO00oOo
 if 93 - 93: o0000oOoOoO0o - II11iiII + iIii1I11I1II1 * Ooo00oOo00o + o0oo0o . i1I1ii1II1iII
 if 49 - 49: OoooooooOO * OoOO0ooOOoo0O - OoO0O00 . iiiiIi11i
 O000o0 = [ i1111 , i1111 , I11 ]
 lisp . lisp_build_info_requests ( O000o0 , ms , lisp . LISP_CTRL_PORT )
 if 98 - 98: ooOO00oOo . OoOO0ooOOoo0O % II111iiii
 if 71 - 71: o0oo0o % i1IIi - II111iiii - II11iiII + II11iiII * Oo
 if 51 - 51: iIii1I11I1II1 / oOo0O0Ooo + II11iiII - OoOO0ooOOoo0O + i1I1ii1II1iII
 if 29 - 29: Ooo00oOo00o % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / i1I1ii1II1iII
 if 70 - 70: i11iIiiIii % i1I1ii1II1iII
 I11Ii11iI1 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) == None )
 for IIiIi in lisp . lisp_rtr_list . values ( ) :
  if ( IIiIi == None ) : continue
  if ( IIiIi . is_private_address ( ) and I11Ii11iI1 == False ) :
   IiIiiI11111I1 = lisp . red ( IIiIi . print_address_no_iid ( ) , False )
   lisp . lprint ( "Skip over RTR private address {}" . format ( IiIiiI11111I1 ) )
   continue
   if 55 - 55: Oo % OoooooooOO / OoooooooOO % OoooooooOO
  lisp . lisp_build_info_requests ( O000o0 , IIiIi , lisp . LISP_DATA_PORT )
  if 52 - 52: oOoO0oo0OOOo + oOoO0oo0OOOo . II111iiii
  if 34 - 34: OoooooooOO . O0 / iiiiIi11i * oOo0O0Ooo - oOoO0oo0OOOo
  if 36 - 36: i1IIi / O0 / ooOO00oOo - O0 - i1IIi
  if 22 - 22: i1IIi + o0000oOoOoO0o
  if 54 - 54: Oo % II11iiII . o0oo0o + iiiiIi11i - II11iiII * oo
  if 92 - 92: Ooo00oOo00o + o0oo0o / OoO0O00 % ooOO00oOo % oooO0oo0oOOOO . OoooooooOO
 oOOoo00O0O . cancel ( )
 oOOoo00O0O = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 iIIIiIi , [ None ] )
 oOOoo00O0O . start ( )
 return
 if 52 - 52: Oo / i11iIiiIii - II11iiII . oooO0oo0oOOOO % iIii1I11I1II1 + Ooo00oOo00o
 if 71 - 71: iiiiIi11i % OoOO0ooOOoo0O * oOo0O0Ooo . O0 / o0000oOoOoO0o . oOoO0oo0OOOo
 if 58 - 58: OoO0O00 / iiiiIi11i
 if 44 - 44: II11iiII
 if 54 - 54: o0000oOoOoO0o - OoOO0ooOOoo0O - o0oo0o . iIii1I11I1II1
 if 79 - 79: o0000oOoOoO0o . ooOO00oOo
 if 40 - 40: Ooo00oOo00o + OoO0O00 . Ooo00oOo00o % Oo
def ooO0o0Oo ( lisp_sockets ) :
 global o0oOoO00o
 global i1111
 if 15 - 15: o0000oOoOoO0o * OoO0O00 % oOoO0oo0OOOo * iIii1I11I1II1 - i11iIiiIii
 lisp . lisp_set_exception ( )
 if 60 - 60: oo * o0oo0o % ooOO00oOo + iiiiIi11i
 if 52 - 52: i1IIi
 if 84 - 84: o0000oOoOoO0o / oooO0oo0oOOOO
 if 86 - 86: oOo0O0Ooo * II111iiii - O0 . oOo0O0Ooo % iIii1I11I1II1 / II11iiII
 o00oo0 ( lisp_sockets , None , None , None , True )
 if 11 - 11: oo * iiiiIi11i + oOoO0oo0OOOo / oOoO0oo0OOOo
 if 37 - 37: i11iIiiIii + i1IIi
 if 23 - 23: i1I1ii1II1iII + OoOO0ooOOoo0O . oOo0O0Ooo * oo + oOoO0oo0OOOo
 if 18 - 18: oooO0oo0oOOOO * Ooo00oOo00o . oooO0oo0oOOOO / O0
 if 8 - 8: Ooo00oOo00o
 if ( lisp . lisp_l2_overlay ) :
  II1II1 = [ None , "ffff-ffff-ffff" , True ]
  Ii11iI ( lisp_sockets , [ II1II1 ] )
  if 52 - 52: II11iiII - i1I1ii1II1iII * iiiiIi11i
  if 17 - 17: OoooooooOO + II11iiII * OoOO0ooOOoo0O * oOo0O0Ooo
  if 36 - 36: O0 + OoO0O00
  if 5 - 5: OoO0O00 * oOo0O0Ooo
  if 46 - 46: Oo
 if ( o0oOoO00o ) : o0oOoO00o . cancel ( )
 o0oOoO00o = threading . Timer ( oOOoo ,
 ooO0o0Oo , [ Oo0o0000o0o0 ] )
 o0oOoO00o . start ( )
 return
 if 33 - 33: i1I1ii1II1iII - II111iiii * OoooooooOO - OoO0O00 - II11iiII
 if 84 - 84: o0oo0o + OoO0O00 - oOo0O0Ooo * oOo0O0Ooo
 if 61 - 61: OoooooooOO . iiiiIi11i . OoooooooOO / OoO0O00
 if 72 - 72: i1IIi
 if 82 - 82: oOo0O0Ooo + OoooooooOO / i11iIiiIii * oOoO0oo0OOOo . OoooooooOO
 if 63 - 63: oOoO0oo0OOOo
 if 6 - 6: Oo / oOoO0oo0OOOo
 if 57 - 57: OoOO0ooOOoo0O
 if 67 - 67: ooOO00oOo . Oo
def oO00oOo0OOO ( group_str , group_mapping ) :
 OOOOoO00o0O = group_mapping . group_prefix . instance_id
 ii1 = group_mapping . group_prefix . mask_len
 ooO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , group_str , 32 , OOOOoO00o0O )
 if ( ooO . is_more_specific ( group_mapping . group_prefix ) ) : return ( ii1 )
 return ( - 1 )
 if 62 - 62: o0000oOoOoO0o
 if 51 - 51: oOo0O0Ooo
 if 14 - 14: oooO0oo0oOOOO % iiiiIi11i % OoO0O00 - i11iIiiIii
 if 53 - 53: o0000oOoOoO0o % OoO0O00
 if 59 - 59: II11iiII % iIii1I11I1II1 . i1IIi + II111iiii * oooO0oo0oOOOO
 if 41 - 41: o0000oOoOoO0o % oOoO0oo0OOOo
 if 12 - 12: II11iiII
 if 69 - 69: OoooooooOO + II11iiII
 if 26 - 26: OoO0O00 + II11iiII / ooOO00oOo % oOo0O0Ooo % oOoO0oo0OOOo + II111iiii
 if 31 - 31: OoOO0ooOOoo0O % II11iiII * OoOO0ooOOoo0O
 if 45 - 45: i1IIi . oo + II11iiII - OoooooooOO % Oo
def Ii11iI ( lisp_sockets , entries ) :
 i1I = len ( entries )
 if ( i1I == 0 ) : return
 if 7 - 7: i11iIiiIii . OoO0O00
 O0O00OOo = None
 if ( entries [ 0 ] [ 1 ] . find ( ":" ) != - 1 ) : O0O00OOo = lisp . LISP_AFI_IPV6
 if ( entries [ 0 ] [ 1 ] . find ( "." ) != - 1 ) : O0O00OOo = lisp . LISP_AFI_IPV4
 if ( entries [ 0 ] [ 1 ] . find ( "-" ) != - 1 ) : O0O00OOo = lisp . LISP_AFI_MAC
 if ( O0O00OOo == None ) :
  lisp . lprint ( "lisp_send_multicast_map_register() invalid group address" )
  return
  if 66 - 66: i11iIiiIii / Ooo00oOo00o - OoooooooOO / i1IIi . i11iIiiIii
  if 16 - 16: OoO0O00 % oOoO0oo0OOOo + OoOO0ooOOoo0O - O0 . i1I1ii1II1iII / o0oo0o
  if 35 - 35: iiiiIi11i / o0oo0o / II111iiii - iIii1I11I1II1 + II111iiii . o0oo0o
  if 81 - 81: i1I1ii1II1iII * II11iiII - oOoO0oo0OOOo * o0000oOoOoO0o % oOo0O0Ooo * oOo0O0Ooo
  if 59 - 59: iIii1I11I1II1
  if 7 - 7: II11iiII * oo / Ooo00oOo00o * i11iIiiIii
 o00 = [ ]
 for i1OOO0000oO , ooO , II1i111 in entries :
  if ( i1OOO0000oO != None ) : continue
  o00 . append ( [ ooO , II1i111 ] )
  if 50 - 50: oooO0oo0oOOOO % i1IIi
  if 21 - 21: OoooooooOO - iIii1I11I1II1
 o0o0O00oo0 = lisp . lisp_decent_pull_xtr_configured ( )
 if 93 - 93: iiiiIi11i - Ooo00oOo00o % oOo0O0Ooo . oOo0O0Ooo - Oo
 IIIII = { }
 entries = [ ]
 for ooO , II1i111 in o00 :
  O00ooOo = None
  for I1111IIi in lisp . lisp_group_mapping_list . values ( ) :
   ii1 = oO00oOo0OOO ( ooO , I1111IIi )
   if ( ii1 == - 1 ) : continue
   if ( O00ooOo == None or ii1 > O00ooOo . group_prefix . mask_len ) :
    O00ooOo = I1111IIi
    if 80 - 80: Ooo00oOo00o - II11iiII + OoooooooOO
    if 98 - 98: II11iiII + i1IIi . oo - II111iiii - Ooo00oOo00o
  if ( O00ooOo == None ) :
   lisp . lprint ( "No group-mapping for {}, could be underlay group" . format ( ooO ) )
   if 24 - 24: OoO0O00 - i1IIi + OoOO0ooOOoo0O
   continue
   if 38 - 38: OoooooooOO / oOoO0oo0OOOo . O0 / i1IIi / OoO0O00 + iIii1I11I1II1
   if 96 - 96: i1I1ii1II1iII
  lisp . lprint ( "Use group-mapping '{}' {} for group {}" . format ( O00ooOo . group_name , O00ooOo . group_prefix . print_prefix ( ) , ooO ) )
  if 18 - 18: i1I1ii1II1iII * OoOO0ooOOoo0O - o0000oOoOoO0o
  OOOOoO00o0O = O00ooOo . group_prefix . instance_id
  I111Ii111 = O00ooOo . use_ms_name
  II1i1III = O00ooOo . rle_address
  if 34 - 34: o0oo0o - i11iIiiIii / iIii1I11I1II1
  if 87 - 87: oOoO0oo0OOOo / OoooooooOO - OoO0O00 % oOo0O0Ooo % oooO0oo0oOOOO % OoO0O00
  if 29 - 29: OoooooooOO . oo % oOoO0oo0OOOo - i1I1ii1II1iII
  if 8 - 8: i1IIi
  if 32 - 32: iiiiIi11i / II111iiii
  if 45 - 45: oOoO0oo0OOOo + ooOO00oOo * i11iIiiIii / II11iiII % OoOO0ooOOoo0O * O0
  i1o0oooO = I111Ii111
  if ( o0o0O00oo0 ) :
   i1o0oooO = lisp . lisp_get_decent_dns_name_from_str ( OOOOoO00o0O , ooO )
   IIIII [ i1o0oooO ] = [ "" , 0 ]
   if 89 - 89: II111iiii / iiiiIi11i
   if 14 - 14: II11iiII . oo * Oo + II111iiii - Oo + II11iiII
  if ( len ( O00ooOo . sources ) == 0 ) :
   entries . append ( [ "0.0.0.0" , ooO , OOOOoO00o0O , i1o0oooO , II1i1III , II1i111 ] )
   continue
   if 18 - 18: iiiiIi11i - Ooo00oOo00o - oo - oo
  for IIiIi1iI in O00ooOo . sources :
   IIIII [ i1o0oooO ] = [ "" , 0 ]
   entries . append ( [ IIiIi1iI , ooO , OOOOoO00o0O , i1o0oooO , II1i1III , II1i111 ] )
   if 54 - 54: OoO0O00 + oo / i1I1ii1II1iII . oo * oOo0O0Ooo
   if 1 - 1: oOo0O0Ooo * ooOO00oOo . i1IIi / OoO0O00 . oOoO0oo0OOOo + OoO0O00
   if 17 - 17: OoO0O00 + ooOO00oOo / o0000oOoOoO0o / i1I1ii1II1iII * II11iiII
 i1I = len ( entries )
 if ( i1I == 0 ) : return
 if 29 - 29: ooOO00oOo % OoooooooOO * iiiiIi11i / II111iiii - iiiiIi11i
 lisp . lprint ( "Build Map-Register for {} multicast entries" . format ( i1I ) )
 if 19 - 19: i11iIiiIii
 if 54 - 54: II111iiii . OoOO0ooOOoo0O
 if 73 - 73: oOo0O0Ooo . oo
 if 32 - 32: oOo0O0Ooo * oo % Oo * o0000oOoOoO0o . O0
 if 48 - 48: i1I1ii1II1iII * i1I1ii1II1iII
 if 13 - 13: o0000oOoOoO0o / OoOO0ooOOoo0O + oOo0O0Ooo . Ooo00oOo00o % Oo
 IiIi1 = lisp . lisp_rle_node ( )
 IiIi1 . level = 128
 oo00ooOoo = lisp . lisp_get_any_translated_rloc ( )
 II1i1III = lisp . lisp_rle ( "" )
 II1i1III . rle_nodes . append ( IiIi1 )
 if 28 - 28: o0000oOoOoO0o
 if 1 - 1: o0000oOoOoO0o
 if 48 - 48: O0 + O0 . o0oo0o - Oo
 if 63 - 63: iiiiIi11i
 if 71 - 71: i1IIi . o0000oOoOoO0o * i1I1ii1II1iII % OoooooooOO + II11iiII
 if 36 - 36: oooO0oo0oOOOO
 if ( o0o0O00oo0 == False ) :
  for oO0OOoO0 in lisp . lisp_map_servers_list . values ( ) :
   IIIII [ oO0OOoO0 . ms_name ] = [ "" , 0 ]
   if 49 - 49: II11iiII / OoooooooOO / oo
   if 74 - 74: o0oo0o % oOoO0oo0OOOo
   if 7 - 7: II111iiii
 iI = None
 if ( lisp . lisp_nat_traversal ) : iI = lisp . lisp_hostname
 if 38 - 38: oooO0oo0oOOOO . o0000oOoOoO0o
 if 24 - 24: Ooo00oOo00o - Ooo00oOo00o + oOoO0oo0OOOo + oo - iiiiIi11i
 if 12 - 12: i1I1ii1II1iII . oooO0oo0oOOOO . oOo0O0Ooo / O0
 if 58 - 58: Ooo00oOo00o - II111iiii % iiiiIi11i + o0oo0o . oOo0O0Ooo / oooO0oo0oOOOO
 II = 0
 for IIiIi in lisp . lisp_rtr_list . values ( ) :
  if ( IIiIi == None ) : continue
  II += 1
  if 94 - 94: OoOO0ooOOoo0O + II111iiii % i11iIiiIii
  if 8 - 8: Oo * O0
  if 73 - 73: Ooo00oOo00o / iiiiIi11i / OoOO0ooOOoo0O / ooOO00oOo
  if 11 - 11: oOo0O0Ooo + oooO0oo0oOOOO - OoooooooOO / ooOO00oOo
  if 34 - 34: Oo
 O0O0O0Oo = ""
 for i1OOO0000oO , ooO , OOOOoO00o0O , O000 , i1iI1 , II1i111 in entries :
  if 44 - 44: oOoO0oo0OOOo - o0000oOoOoO0o / II111iiii * ooOO00oOo * OoO0O00
  if 73 - 73: Ooo00oOo00o - oo * i1IIi / i11iIiiIii * II11iiII % II111iiii
  if 56 - 56: OoooooooOO * OoO0O00 . OoO0O00 . oOoO0oo0OOOo
  if 24 - 24: OoO0O00 . OoOO0ooOOoo0O * o0000oOoOoO0o % i1I1ii1II1iII / II11iiII
  if ( IIIII . has_key ( O000 ) == False ) : continue
  if 58 - 58: oo - oOoO0oo0OOOo % O0 . oo % ooOO00oOo % oooO0oo0oOOOO
  I1I1I1IIi1III = lisp . lisp_eid_record ( )
  I1I1I1IIi1III . rloc_count = 1 + II
  I1I1I1IIi1III . authoritative = True
  I1I1I1IIi1III . record_ttl = lisp . LISP_REGISTER_TTL if II1i111 else 0
  I1I1I1IIi1III . eid = lisp . lisp_address ( O0O00OOo , i1OOO0000oO , 0 , OOOOoO00o0O )
  if ( I1I1I1IIi1III . eid . address == 0 ) : I1I1I1IIi1III . eid . mask_len = 0
  I1I1I1IIi1III . group = lisp . lisp_address ( O0O00OOo , ooO , 0 , OOOOoO00o0O )
  if ( I1I1I1IIi1III . group . is_mac_broadcast ( ) and I1I1I1IIi1III . eid . address == 0 ) : I1I1I1IIi1III . eid . mask_len = 0
  if 87 - 87: iiiiIi11i - i11iIiiIii
  if 78 - 78: i11iIiiIii / iIii1I11I1II1 - Ooo00oOo00o
  oO0o0oooO0oO = ""
  I111Ii111 = ""
  if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
   oO0o0oooO0oO = lisp . lisp_get_decent_index ( I1I1I1IIi1III . group )
   oO0o0oooO0oO = lisp . bold ( str ( oO0o0oooO0oO ) , False )
   oO0o0oooO0oO = "with decent-index {}" . format ( oO0o0oooO0oO )
  else :
   oO0o0oooO0oO = "for ms-name '{}'" . format ( O000 )
   if 23 - 23: OoOO0ooOOoo0O
   if 40 - 40: Ooo00oOo00o - II111iiii / OoO0O00
  iiIiI1ii = lisp . green ( I1I1I1IIi1III . print_eid_tuple ( ) , False )
  lisp . lprint ( "  EID-prefix {} {}{}" . format ( iiIiI1ii , I111Ii111 ,
 oO0o0oooO0oO ) )
  if 56 - 56: OoooooooOO - OoOO0ooOOoo0O - i1IIi
  O0O0O0Oo += I1I1I1IIi1III . encode ( )
  I1I1I1IIi1III . print_record ( "  " , False )
  IIIII [ O000 ] [ 1 ] += 1
  if 8 - 8: o0oo0o / II11iiII . oo + oOoO0oo0OOOo / i11iIiiIii
  if 31 - 31: Oo - iIii1I11I1II1 + i1I1ii1II1iII . OoO0O00 / oooO0oo0oOOOO % iIii1I11I1II1
  if 6 - 6: oooO0oo0oOOOO * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + Ooo00oOo00o / i1IIi
  if 53 - 53: OoOO0ooOOoo0O + iIii1I11I1II1
  i1II = lisp . lisp_rloc_record ( )
  i1II . rloc_name = iI
  if 70 - 70: oOoO0oo0OOOo
  if 67 - 67: OoooooooOO
  if 29 - 29: O0 - i11iIiiIii - II111iiii + II11iiII * oooO0oo0oOOOO
  if 2 - 2: i1IIi - Oo + oo . Ooo00oOo00o * Ooo00oOo00o / oOo0O0Ooo
  if 93 - 93: i1IIi
  if 53 - 53: OoooooooOO + OoO0O00 + iiiiIi11i
  if ( oo00ooOoo != None ) :
   IiIi1 . address = oo00ooOoo
  elif ( i1iI1 != None ) :
   IiIi1 . address = i1iI1
  else :
   IiIi1 . address = i1iI1 = lisp . lisp_myrlocs [ 0 ]
   if 24 - 24: i1I1ii1II1iII - oooO0oo0oOOOO - i1I1ii1II1iII * oOoO0oo0OOOo . OoooooooOO / oooO0oo0oOOOO
   if 66 - 66: OoO0O00
  i1II . rle = II1i1III
  i1II . local_bit = True
  i1II . reach_bit = True
  i1II . priority = 255
  i1II . weight = 0
  i1II . mpriority = 1
  i1II . mweight = 100
  O0O0O0Oo += i1II . encode ( )
  i1II . print_record ( "    " )
  if 97 - 97: i1IIi - OoooooooOO / o0oo0o * oo
  if 55 - 55: Ooo00oOo00o . i1I1ii1II1iII
  if 87 - 87: Ooo00oOo00o % iIii1I11I1II1
  if 100 - 100: o0oo0o . oo * o0oo0o - oo . OoOO0ooOOoo0O * o0000oOoOoO0o
  if 89 - 89: ooOO00oOo + oooO0oo0oOOOO * o0oo0o
  for IIiIi in lisp . lisp_rtr_list . values ( ) :
   if ( IIiIi == None ) : continue
   i1II = lisp . lisp_rloc_record ( )
   i1II . rloc . copy_address ( IIiIi )
   i1II . priority = 254
   i1II . rloc_name = "RTR"
   i1II . weight = 0
   i1II . mpriority = 255
   i1II . mweight = 0
   i1II . local_bit = False
   i1II . reach_bit = True
   O0O0O0Oo += i1II . encode ( )
   i1II . print_record ( "    RTR " )
   if 28 - 28: OoooooooOO . iiiiIi11i % oOoO0oo0OOOo / i1IIi / II11iiII
   if 36 - 36: Ooo00oOo00o + OoOO0ooOOoo0O - oooO0oo0oOOOO + iIii1I11I1II1 + OoooooooOO
   if 4 - 4: II111iiii . OoOO0ooOOoo0O + o0000oOoOoO0o * o0oo0o . Oo
   if 87 - 87: oOo0O0Ooo / ooOO00oOo / i11iIiiIii
   if 74 - 74: iiiiIi11i / oOoO0oo0OOOo % Ooo00oOo00o
  IIIII [ O000 ] [ 0 ] += O0O0O0Oo
  if 88 - 88: oOo0O0Ooo - i11iIiiIii % Ooo00oOo00o * OoOO0ooOOoo0O + oOoO0oo0OOOo
  if 52 - 52: II111iiii . oo + oOo0O0Ooo % ooOO00oOo
  if 62 - 62: Ooo00oOo00o
  if 15 - 15: OoOO0ooOOoo0O + o0000oOoOoO0o . II11iiII * ooOO00oOo . oOo0O0Ooo
  if 18 - 18: i1IIi % II111iiii + o0oo0o % o0000oOoOoO0o
 II11iI111i1 = lisp . lisp_map_register ( )
 II11iI111i1 . nonce = 0xaabbccdddfdfdf00
 II11iI111i1 . xtr_id_present = True
 II11iI111i1 . proxy_reply_requested = True
 II11iI111i1 . map_notify_requested = False
 II11iI111i1 . merge_register_requested = True
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: OoO0O00 - Ooo00oOo00o % o0oo0o
 if 38 - 38: o0oo0o % II11iiII - OoooooooOO
 if 87 - 87: ooOO00oOo % oo
 for oO0OOoO0 in lisp . lisp_map_servers_list . values ( ) :
  i1o0oooO = oO0OOoO0 . dns_name if o0o0O00oo0 else oO0OOoO0 . ms_name
  if 77 - 77: iIii1I11I1II1 - i1IIi . iiiiIi11i
  if 26 - 26: Ooo00oOo00o * oooO0oo0oOOOO . i1IIi
  if 59 - 59: O0 + i1IIi - Ooo00oOo00o
  if 62 - 62: i11iIiiIii % II11iiII . oooO0oo0oOOOO . II11iiII
  if ( IIIII . has_key ( i1o0oooO ) == False ) : continue
  if 84 - 84: i11iIiiIii * ooOO00oOo
  if 18 - 18: II11iiII - o0000oOoOoO0o - oOo0O0Ooo / o0oo0o - O0
  if 30 - 30: O0 + oOoO0oo0OOOo + II111iiii
  if 14 - 14: Ooo00oOo00o / II11iiII - iIii1I11I1II1 - iiiiIi11i % Oo
  II11iI111i1 . record_count = IIIII [ i1o0oooO ] [ 1 ]
  if ( II11iI111i1 . record_count == 0 ) : continue
  if 49 - 49: Oo * iiiiIi11i / Ooo00oOo00o / OoO0O00 * iIii1I11I1II1
  II11iI111i1 . nonce += 1
  II11iI111i1 . alg_id = oO0OOoO0 . alg_id
  II11iI111i1 . alg_id = oO0OOoO0 . key_id
  II11iI111i1 . xtr_id = oO0OOoO0 . xtr_id
  II11iI111i1 . site_id = oO0OOoO0 . site_id
  II11iI111i1 . encrypt_bit = ( oO0OOoO0 . ekey != None )
  oOO0 = II11iI111i1 . encode ( )
  II11iI111i1 . print_map_register ( )
  if 57 - 57: oOo0O0Ooo - iiiiIi11i / Oo % i11iIiiIii
  if 3 - 3: i1I1ii1II1iII . Oo % oo + oOoO0oo0OOOo
  if 64 - 64: i1IIi
  if 29 - 29: Ooo00oOo00o / i11iIiiIii / oo % iiiiIi11i % i11iIiiIii
  if 18 - 18: II11iiII + o0oo0o
  oOoOOo0oo0 = II11iI111i1 . encode_xtr_id ( "" )
  oOO0 = oOO0 + O0O0O0Oo + oOoOOo0oo0
  if 80 - 80: iiiiIi11i + Ooo00oOo00o * o0000oOoOoO0o + ooOO00oOo
  oO0OOoO0 . map_registers_multicast_sent += 1
  lisp . lisp_send_map_register ( lisp_sockets , oOO0 , II11iI111i1 , oO0OOoO0 )
  if 75 - 75: OoOO0ooOOoo0O / Ooo00oOo00o / II11iiII / oooO0oo0oOOOO % Oo + II111iiii
  if 4 - 4: i1I1ii1II1iII - OoO0O00 - oooO0oo0oOOOO - OoOO0ooOOoo0O % i11iIiiIii / ooOO00oOo
  if 50 - 50: Oo + i1IIi
  if 31 - 31: o0000oOoOoO0o
  oO0OOoO0 . resolve_dns_name ( )
  if 78 - 78: i11iIiiIii + Ooo00oOo00o + o0oo0o / Ooo00oOo00o % iIii1I11I1II1 % oooO0oo0oOOOO
  if 83 - 83: iIii1I11I1II1 % oOo0O0Ooo % Ooo00oOo00o % o0oo0o . oOoO0oo0OOOo % O0
  if 47 - 47: Ooo00oOo00o
  if 66 - 66: oo - oooO0oo0oOOOO
  time . sleep ( .001 )
  if 33 - 33: oo / ooOO00oOo
 return
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - oo + OoOO0ooOOoo0O . II111iiii
 if 25 - 25: iiiiIi11i
 if 34 - 34: oOo0O0Ooo . iIii1I11I1II1 % O0
 if 43 - 43: oOoO0oo0OOOo - i1I1ii1II1iII
O000O = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 98 - 98: iIii1I11I1II1 + o0oo0o % oOo0O0Ooo + OoOO0ooOOoo0O % oOo0O0Ooo
if 24 - 24: iiiiIi11i * o0oo0o
if 40 - 40: o0000oOoOoO0o - oOo0O0Ooo * oOo0O0Ooo . oOo0O0Ooo + OoooooooOO
if 77 - 77: iIii1I11I1II1 . o0000oOoOoO0o % iiiiIi11i / o0000oOoOoO0o
if 54 - 54: iiiiIi11i + Oo - OoO0O00
if 35 - 35: o0000oOoOoO0o - o0000oOoOoO0o + i1IIi - O0 - o0oo0o
if 58 - 58: oOo0O0Ooo - i1I1ii1II1iII - OoooooooOO
if 96 - 96: iIii1I11I1II1
if 82 - 82: oOo0O0Ooo + O0 - oooO0oo0oOOOO % iiiiIi11i * i11iIiiIii
if 15 - 15: Ooo00oOo00o
if 39 - 39: II11iiII / oOoO0oo0OOOo / oo * o0oo0o
if 44 - 44: O0 + Oo . iIii1I11I1II1 + OoO0O00 / O0 - OoOO0ooOOoo0O
if 83 - 83: oooO0oo0oOOOO * OoOO0ooOOoo0O / OoO0O00
if 32 - 32: Ooo00oOo00o + oOo0O0Ooo - OoooooooOO
if 39 - 39: OoooooooOO * II11iiII * O0 . OoOO0ooOOoo0O . ooOO00oOo + Oo
if 9 - 9: oOo0O0Ooo + iiiiIi11i % OoooooooOO + Ooo00oOo00o
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
if 58 - 58: oooO0oo0oOOOO + iIii1I11I1II1
if 65 - 65: II111iiii - o0oo0o % Ooo00oOo00o - oOo0O0Ooo * i1I1ii1II1iII + o0000oOoOoO0o
if 79 - 79: Oo . oOo0O0Ooo % o0oo0o - OoO0O00
if 69 - 69: Oo - Ooo00oOo00o . Oo
if 9 - 9: iiiiIi11i % i11iIiiIii / OoO0O00
if 20 - 20: iiiiIi11i * O0 + OoOO0ooOOoo0O - OoooooooOO . OoOO0ooOOoo0O
if 60 - 60: Ooo00oOo00o . Ooo00oOo00o / i1I1ii1II1iII
if 45 - 45: O0 . i11iIiiIii % i1I1ii1II1iII . oOo0O0Ooo % oooO0oo0oOOOO % iIii1I11I1II1
if 58 - 58: iIii1I11I1II1 . oOo0O0Ooo - i11iIiiIii * iIii1I11I1II1 % i11iIiiIii / oo
if 80 - 80: oOoO0oo0OOOo / iIii1I11I1II1 % oOo0O0Ooo
if 80 - 80: ooOO00oOo % i1I1ii1II1iII
if 99 - 99: Oo / iIii1I11I1II1 - o0000oOoOoO0o * oOoO0oo0OOOo % oo
if 13 - 13: ooOO00oOo
if 70 - 70: o0oo0o + O0 . iiiiIi11i * o0000oOoOoO0o
if 2 - 2: OoooooooOO . II11iiII . oooO0oo0oOOOO
if 42 - 42: II11iiII % iiiiIi11i / ooOO00oOo - iiiiIi11i * i11iIiiIii
if 19 - 19: iiiiIi11i * oo % i11iIiiIii
if 24 - 24: Ooo00oOo00o
if 10 - 10: Ooo00oOo00o % o0000oOoOoO0o / II11iiII
if 28 - 28: II11iiII % Oo
if 48 - 48: i11iIiiIii % iiiiIi11i
if 29 - 29: i1I1ii1II1iII + i11iIiiIii % OoOO0ooOOoo0O
if 93 - 93: oOo0O0Ooo % iIii1I11I1II1
if 90 - 90: oo - II11iiII / o0000oOoOoO0o / O0 / OoOO0ooOOoo0O
if 87 - 87: oOo0O0Ooo / oooO0oo0oOOOO + iIii1I11I1II1
if 93 - 93: iIii1I11I1II1 + iiiiIi11i % Oo
if 21 - 21: II11iiII
if 6 - 6: oooO0oo0oOOOO
if 46 - 46: oooO0oo0oOOOO + iiiiIi11i
if 79 - 79: OoooooooOO - oooO0oo0oOOOO * oooO0oo0oOOOO . oOo0O0Ooo
if 100 - 100: II111iiii * OoOO0ooOOoo0O % oo / oOoO0oo0OOOo
if 90 - 90: oOoO0oo0OOOo . Oo . oOo0O0Ooo . o0000oOoOoO0o
if 4 - 4: o0000oOoOoO0o + oOo0O0Ooo % oOoO0oo0OOOo / i11iIiiIii
if 74 - 74: II111iiii . O0 - oo + oooO0oo0oOOOO % i11iIiiIii % oOo0O0Ooo
if 78 - 78: o0000oOoOoO0o + oOo0O0Ooo + oooO0oo0oOOOO - oooO0oo0oOOOO . i11iIiiIii / ooOO00oOo
if 27 - 27: o0000oOoOoO0o - O0 % OoOO0ooOOoo0O * o0oo0o . oooO0oo0oOOOO % iIii1I11I1II1
if 37 - 37: OoooooooOO + O0 - i1IIi % Oo
def i1I1i1i ( packet ) :
 global Oo0o0000o0o0
 if 36 - 36: II111iiii % O0
 IiIiiI11111I1 = lisp . bold ( "Receive" , False )
 lisp . lprint ( "{} {}-byte IGMP packet: {}" . format ( IiIiiI11111I1 , len ( packet ) ,
 lisp . lisp_format_packet ( packet ) ) )
 if 35 - 35: iIii1I11I1II1 - II11iiII % Ooo00oOo00o
 if 30 - 30: o0oo0o % o0oo0o % oooO0oo0oOOOO . oOo0O0Ooo
 if 9 - 9: Oo / II111iiii . oOo0O0Ooo % Ooo00oOo00o * II111iiii - Oo
 if 55 - 55: oo
 Ii1i1 = ( struct . unpack ( "B" , packet [ 0 ] ) [ 0 ] & 0x0f ) * 4
 if 65 - 65: iiiiIi11i + oOoO0oo0OOOo / II11iiII
 if 85 - 85: iIii1I11I1II1 / OoooooooOO % II111iiii
 if 49 - 49: i11iIiiIii % oOo0O0Ooo + o0oo0o . II111iiii % i1I1ii1II1iII * II11iiII
 if 67 - 67: i1IIi
 iii = packet [ Ii1i1 : : ]
 oOOOo = struct . unpack ( "B" , iii [ 0 ] ) [ 0 ]
 ooO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 31 - 31: oOo0O0Ooo + oOo0O0Ooo . i11iIiiIii / Oo % OoOO0ooOOoo0O / oOo0O0Ooo
 IIiI1I111iIiI = ( oOOOo in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( IIiI1I111iIiI == False ) :
  ooOoooOO0oOooO00 = "{} ({})" . format ( oOOOo , IiII1IiiIiI1 [ oOOOo ] ) if IiII1IiiIiI1 . has_key ( oOOOo ) else oOOOo
  if 37 - 37: oooO0oo0oOOOO
  lisp . lprint ( "IGMP type {} not supported" . format ( ooOoooOO0oOooO00 ) )
  return
  if 37 - 37: OoO0O00 / oooO0oo0oOOOO * O0
  if 73 - 73: i1I1ii1II1iII * i1I1ii1II1iII / Oo
 if ( len ( iii ) < 8 ) :
  lisp . lprint ( "IGMP message too small" )
  return
  if 43 - 43: oOoO0oo0OOOo . i1IIi . oooO0oo0oOOOO + O0 * o0000oOoOoO0o * O0
  if 41 - 41: oOoO0oo0OOOo + o0000oOoOoO0o % OoooooooOO . oOoO0oo0OOOo + i1I1ii1II1iII . i1I1ii1II1iII
  if 31 - 31: i11iIiiIii + II111iiii . i1I1ii1II1iII * oOo0O0Ooo
  if 66 - 66: oOo0O0Ooo + i1IIi % II111iiii . O0 * oOoO0oo0OOOo % oOoO0oo0OOOo
  if 87 - 87: II11iiII + Ooo00oOo00o . i1I1ii1II1iII - OoooooooOO
  if 6 - 6: iIii1I11I1II1 * OoooooooOO
 ooO . address = socket . ntohl ( struct . unpack ( "II" , iii [ : 8 ] ) [ 1 ] )
 iIiI1I1ii1I1 = ooO . print_address_no_iid ( )
 if 83 - 83: II11iiII / O0 % i1I1ii1II1iII - Ooo00oOo00o . OoO0O00
 if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
 if 90 - 90: Ooo00oOo00o % oOoO0oo0OOOo - iIii1I11I1II1 % oOo0O0Ooo
 if 8 - 8: oOo0O0Ooo * OoO0O00 / oooO0oo0oOOOO % o0000oOoOoO0o - oo
 if ( oOOOo == 0x17 ) :
  lisp . lprint ( "IGMPv2 leave (*, {})" . format ( lisp . bold ( iIiI1I1ii1I1 , False ) ) )
  Ii11iI ( Oo0o0000o0o0 ,
 [ [ None , iIiI1I1ii1I1 , False ] ] )
  return
  if 71 - 71: i1I1ii1II1iII
 if ( oOOOo in ( 0x12 , 0x16 ) ) :
  lisp . lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( oOOOo == 0x12 ) else 2 , lisp . bold ( iIiI1I1ii1I1 , False ) ) )
  if 23 - 23: i1IIi . iIii1I11I1II1 . II11iiII . O0 % o0000oOoOoO0o % i11iIiiIii
  if 11 - 11: O0 - II111iiii . II11iiII . o0000oOoOoO0o % o0oo0o
  if 21 - 21: OoO0O00 / i1I1ii1II1iII . o0oo0o * OoooooooOO + OoOO0ooOOoo0O - i1IIi
  if 58 - 58: oOoO0oo0OOOo
  if 2 - 2: II111iiii / o0oo0o
  if ( iIiI1I1ii1I1 . find ( "224.0.0." ) != - 1 ) :
   lisp . lprint ( "Suppress registration for link-local groups" )
  else :
   Ii11iI ( Oo0o0000o0o0 ,
 [ [ None , iIiI1I1ii1I1 , True ] ] )
   if 54 - 54: i1IIi . OoOO0ooOOoo0O - oOoO0oo0OOOo + Oo + OoO0O00 / OoO0O00
   if 22 - 22: Oo . iIii1I11I1II1
   if 12 - 12: o0000oOoOoO0o
   if 71 - 71: oo . II111iiii . oo - Oo
   if 45 - 45: oooO0oo0oOOOO / O0 / oOo0O0Ooo * II11iiII
  return
  if 18 - 18: iIii1I11I1II1 + II11iiII + iIii1I11I1II1 . oOoO0oo0OOOo + o0oo0o . Oo
  if 7 - 7: oOoO0oo0OOOo + iIii1I11I1II1 * OoOO0ooOOoo0O * OoOO0ooOOoo0O / II111iiii - o0000oOoOoO0o
  if 65 - 65: iiiiIi11i + oOo0O0Ooo + II111iiii
  if 77 - 77: II111iiii
  if 50 - 50: O0 . O0 . Oo % OoO0O00
 ooo000oOO = ooO . address
 iii = iii [ 8 : : ]
 if 27 - 27: Ooo00oOo00o * i11iIiiIii * ooOO00oOo
 oOOoO = "BBHI"
 oOo0Oo0O0O = struct . calcsize ( oOOoO )
 III1II1i = "I"
 iI1i1IiIIIIi = struct . calcsize ( III1II1i )
 i1OOO0000oO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , "" , 32 , 0 )
 if 65 - 65: O0 * oo / oo . oOo0O0Ooo
 if 87 - 87: II111iiii * oOoO0oo0OOOo % OoO0O00 * OoO0O00
 if 58 - 58: II11iiII . Ooo00oOo00o + oo % OoO0O00 - ooOO00oOo
 if 50 - 50: i1I1ii1II1iII % II111iiii - Oo . i1IIi + O0 % i1I1ii1II1iII
 i1iIi1IIiIII1 = [ ]
 for oO0 in range ( ooo000oOO ) :
  if ( len ( iii ) < oOo0Oo0O0O ) : return
  i1Ii11I1II , oOOOoo0o , iiiI1IiIIii , IIIIiii = struct . unpack ( oOOoO ,
 iii [ : oOo0Oo0O0O ] )
  if 26 - 26: OoooooooOO - Oo * i11iIiiIii + O0 * iiiiIi11i
  iii = iii [ oOo0Oo0O0O : : ]
  if 87 - 87: OoO0O00 + O0 - OoOO0ooOOoo0O * iIii1I11I1II1 . o0oo0o % Ooo00oOo00o
  if ( O000O . has_key ( i1Ii11I1II ) == False ) :
   lisp . lprint ( "Invalid record type {}" . format ( i1Ii11I1II ) )
   continue
   if 83 - 83: II111iiii * i1IIi * i1I1ii1II1iII . oOoO0oo0OOOo / OoOO0ooOOoo0O + i1IIi
   if 43 - 43: OoooooooOO
  oOOO0 = O000O [ i1Ii11I1II ]
  iiiI1IiIIii = socket . ntohs ( iiiI1IiIIii )
  ooO . address = socket . ntohl ( IIIIiii )
  iIiI1I1ii1I1 = ooO . print_address_no_iid ( )
  if 32 - 32: Oo % o0oo0o * OoO0O00
  lisp . lprint ( "Record type: {}, group: {}, source-count: {}" . format ( oOOO0 , iIiI1I1ii1I1 , iiiI1IiIIii ) )
  if 72 - 72: Oo . i1I1ii1II1iII - o0oo0o - o0000oOoOoO0o % i1IIi
  if 56 - 56: OoO0O00 * i1I1ii1II1iII
  if 13 - 13: OoO0O00 * OoO0O00 * II111iiii * i1I1ii1II1iII . i1IIi / oooO0oo0oOOOO
  if 92 - 92: o0000oOoOoO0o * i11iIiiIii + i1I1ii1II1iII * o0oo0o
  if 48 - 48: OoOO0ooOOoo0O * i1I1ii1II1iII * i1I1ii1II1iII
  if 70 - 70: iiiiIi11i + OoOO0ooOOoo0O % i11iIiiIii + O0
  if 65 - 65: iIii1I11I1II1 % iiiiIi11i + O0 / OoooooooOO
  II1i111 = False
  if ( i1Ii11I1II in ( 1 , 5 ) ) : II1i111 = True
  if ( i1Ii11I1II == 4 and iiiI1IiIIii == 0 ) : II1i111 = True
  O0000oO0o00 = "join" if ( II1i111 ) else "leave"
  if 80 - 80: OoooooooOO + oooO0oo0oOOOO
  if 95 - 95: o0oo0o / iiiiIi11i * o0oo0o - OoooooooOO * OoooooooOO % ooOO00oOo
  if 43 - 43: OoO0O00 . o0oo0o
  if 12 - 12: o0oo0o + II11iiII + OoOO0ooOOoo0O . oooO0oo0oOOOO / o0000oOoOoO0o
  if ( iIiI1I1ii1I1 . find ( "224.0.0." ) != - 1 ) :
   lisp . lprint ( "Suppress registration for link-local groups" )
   continue
   if 29 - 29: oooO0oo0oOOOO . Oo - II111iiii
   if 68 - 68: iIii1I11I1II1 + II111iiii / iiiiIi11i
   if 91 - 91: oOo0O0Ooo % iIii1I11I1II1 . oo
   if 70 - 70: OoOO0ooOOoo0O % II111iiii % O0 . i1IIi / o0oo0o
   if 100 - 100: oOoO0oo0OOOo * i11iIiiIii % iiiiIi11i / OoO0O00 / Oo + oOoO0oo0OOOo
   if 59 - 59: o0oo0o - oooO0oo0oOOOO
   if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
   if 5 - 5: oooO0oo0oOOOO
  if ( iiiI1IiIIii == 0 ) :
   i1iIi1IIiIII1 . append ( [ None , iIiI1I1ii1I1 , II1i111 ] )
   lisp . lprint ( "IGMPv3 {} (*, {})" . format ( lisp . bold ( O0000oO0o00 , False ) ,
 lisp . bold ( iIiI1I1ii1I1 , False ) ) )
   if 84 - 84: II111iiii * iiiiIi11i * II111iiii % oooO0oo0oOOOO / oo
   if 100 - 100: oooO0oo0oOOOO . o0000oOoOoO0o - iIii1I11I1II1 . i11iIiiIii / II111iiii
   if 71 - 71: o0oo0o * OoO0O00 . OoOO0ooOOoo0O
   if 49 - 49: oooO0oo0oOOOO * O0 . oooO0oo0oOOOO
   if 19 - 19: II111iiii - oooO0oo0oOOOO
  for OOOOo000o00OO in range ( iiiI1IiIIii ) :
   if ( len ( iii ) < iI1i1IiIIIIi ) : return
   IIIIiii = struct . unpack ( III1II1i , iii [ : iI1i1IiIIIIi ] ) [ 0 ]
   i1OOO0000oO . address = socket . ntohl ( IIIIiii )
   Oo0 = i1OOO0000oO . print_address_no_iid ( )
   i1iIi1IIiIII1 . append ( [ Oo0 , iIiI1I1ii1I1 , II1i111 ] )
   lisp . lprint ( "{} ({}, {})" . format ( O0000oO0o00 ,
 lisp . green ( Oo0 , False ) , lisp . bold ( iIiI1I1ii1I1 , False ) ) )
   iii = iii [ iI1i1IiIIIIi : : ]
   if 66 - 66: oOoO0oo0OOOo * Oo . II11iiII
   if 96 - 96: OoOO0ooOOoo0O % Oo
   if 57 - 57: iiiiIi11i . oo
   if 6 - 6: Oo
   if 39 - 39: Oo / O0 * oooO0oo0oOOOO
   if 17 - 17: o0000oOoOoO0o / iIii1I11I1II1 - ooOO00oOo + oo % II11iiII
   if 14 - 14: Ooo00oOo00o % oooO0oo0oOOOO + oOoO0oo0OOOo + ooOO00oOo
   if 76 - 76: ooOO00oOo - i11iIiiIii + oOo0O0Ooo + II11iiII / OoooooooOO
 if ( len ( i1iIi1IIiIII1 ) != 0 ) :
  Ii11iI ( Oo0o0000o0o0 , i1iIi1IIiIII1 )
  if 50 - 50: II111iiii - o0oo0o + iIii1I11I1II1 + iIii1I11I1II1
 return
 if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + oOoO0oo0OOOo - II111iiii
 if 26 - 26: Ooo00oOo00o
 if 12 - 12: OoooooooOO / O0 + II111iiii * oOoO0oo0OOOo
 if 46 - 46: II111iiii - oooO0oo0oOOOO * OoooooooOO / iiiiIi11i % oooO0oo0oOOOO
 if 11 - 11: iIii1I11I1II1 . oOo0O0Ooo / oooO0oo0oOOOO % Oo
 if 61 - 61: Oo - II11iiII + II11iiII
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * iiiiIi11i - iiiiIi11i + OoooooooOO % oOo0O0Ooo / oOo0O0Ooo
def i11IiI1iiI11 ( parms , not_used , packet ) :
 global I11
 if 85 - 85: oOoO0oo0OOOo - oOo0O0Ooo / oOoO0oo0OOOo + II11iiII - i1I1ii1II1iII
 IIii1III = parms [ 0 ]
 oOo0oooo00o = parms [ 1 ]
 if 94 - 94: i11iIiiIii % OoooooooOO / oo
 if 24 - 24: oo * iiiiIi11i
 if 85 - 85: II111iiii . Oo % II11iiII % OoOO0ooOOoo0O
 if 80 - 80: iiiiIi11i * OoOO0ooOOoo0O / iIii1I11I1II1 % iiiiIi11i / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . OoO0O00 * i1I1ii1II1iII . i11iIiiIii * O0
 if 44 - 44: i1IIi . oo / i11iIiiIii + oooO0oo0oOOOO
 if ( lisp . lisp_is_macos ( ) == False ) :
  iI111II1ii = 4 if IIii1III == "lo0" else 16
  packet = packet [ iI111II1ii : : ]
  if 62 - 62: i1I1ii1II1iII * iIii1I11I1II1 . oooO0oo0oOOOO - OoooooooOO * II111iiii
  if 45 - 45: O0 % oo - i1I1ii1II1iII . ooOO00oOo
  if 42 - 42: i1I1ii1II1iII / Ooo00oOo00o + OoO0O00 . OoO0O00 % II11iiII
  if 16 - 16: i1IIi + ooOO00oOo % oOo0O0Ooo + o0000oOoOoO0o * OoO0O00
  if 3 - 3: i11iIiiIii
 Oo0iII1iI1IIiI = struct . unpack ( "B" , packet [ 9 ] ) [ 0 ]
 if ( Oo0iII1iI1IIiI == 2 ) :
  i1I1i1i ( packet )
  return
  if 69 - 69: OoOO0ooOOoo0O / i11iIiiIii * Ooo00oOo00o / o0oo0o
  if 71 - 71: Ooo00oOo00o / II11iiII % II11iiII
  if 89 - 89: OoooooooOO + i11iIiiIii / OoOO0ooOOoo0O + iIii1I11I1II1 % Oo
  if 29 - 29: oOoO0oo0OOOo
  if 53 - 53: i11iIiiIii . oOoO0oo0OOOo % o0000oOoOoO0o / Oo % iIii1I11I1II1
 iIiIii1I1 = packet
 packet , i1OOO0000oO , O0OOOOo0 , OOooO0Oo00 = lisp . lisp_is_rloc_probe ( packet , 0 )
 if ( iIiIii1I1 != packet ) :
  if ( i1OOO0000oO == None ) : return
  lisp . lisp_parse_packet ( Oo0o0000o0o0 , packet , i1OOO0000oO , O0OOOOo0 , OOooO0Oo00 )
  return
  if 9 - 9: oooO0oo0oOOOO
  if 48 - 48: Ooo00oOo00o + Ooo00oOo00o - OoO0O00
  if 27 - 27: ooOO00oOo + oOo0O0Ooo * Oo
  if 83 - 83: iIii1I11I1II1
  if 72 - 72: OoOO0ooOOoo0O
  if 87 - 87: i1IIi
  if 48 - 48: OoO0O00 * iiiiIi11i * iIii1I11I1II1 + i11iIiiIii - OoooooooOO
 II1iI = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 if ( II1iI == lisp . LISP_DATA_PORT ) : return
 packet = lisp . lisp_reassemble ( packet )
 if ( packet == None ) : return
 if 5 - 5: i1IIi * oOo0O0Ooo % oo . ooOO00oOo * oOoO0oo0OOOo - o0oo0o
 packet = lisp . lisp_packet ( packet )
 oO0OOOO0o0 = packet . decode ( True , I11 , lisp . lisp_decap_stats )
 if ( oO0OOOO0o0 == None ) : return
 if 67 - 67: OoO0O00 / Oo - oooO0oo0oOOOO
 if 74 - 74: OoOO0ooOOoo0O * o0000oOoOoO0o - oOoO0oo0OOOo % iIii1I11I1II1
 if 56 - 56: oOoO0oo0OOOo - O0
 if 58 - 58: oooO0oo0oOOOO + iIii1I11I1II1
 packet . print_packet ( "Receive" , True )
 if 94 - 94: o0000oOoOoO0o . i1IIi
 if 71 - 71: i1I1ii1II1iII + ooOO00oOo - oooO0oo0oOOOO . ooOO00oOo . oooO0oo0oOOOO + oo
 if 26 - 26: O0
 if 17 - 17: II111iiii
 if 9 - 9: OoooooooOO + iiiiIi11i
 if 33 - 33: O0
 if 39 - 39: oo + OoO0O00
 if 83 - 83: i1IIi
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 76 - 76: o0000oOoOoO0o + iIii1I11I1II1 + oOo0O0Ooo . ooOO00oOo
  i1OOO0000oO = packet . inner_source . print_address_no_iid ( )
  packet . strip_outer_headers ( )
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , i1OOO0000oO , II1iI )
  lisp . lisp_ipc ( packet , I11 , "lisp-ms" )
  return
  if 49 - 49: oooO0oo0oOOOO / Oo / II11iiII
  if 25 - 25: oo % O0 + i1IIi - Oo
  if 38 - 38: Ooo00oOo00o % o0oo0o + i11iIiiIii + i1I1ii1II1iII + Oo / i11iIiiIii
  if 94 - 94: i1I1ii1II1iII - OoO0O00 + iiiiIi11i
  if 59 - 59: OoOO0ooOOoo0O . oo - iIii1I11I1II1 + iIii1I11I1II1
  if 56 - 56: iiiiIi11i + Oo
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 32 - 32: II111iiii + oOo0O0Ooo % Oo / oOo0O0Ooo + oOoO0oo0OOOo
  if 2 - 2: i11iIiiIii - o0oo0o + ooOO00oOo % OoOO0ooOOoo0O * o0000oOoOoO0o
  if 54 - 54: O0 - i1I1ii1II1iII . II11iiII % i1I1ii1II1iII + i1I1ii1II1iII
  if 36 - 36: II11iiII % i11iIiiIii
  if 47 - 47: i1IIi + II111iiii . OoO0O00 * iiiiIi11i . OoOO0ooOOoo0O / i1IIi
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 50 - 50: o0oo0o / i1IIi % OoooooooOO
 if 83 - 83: oOoO0oo0OOOo * oOoO0oo0OOOo + II11iiII
 if 57 - 57: O0 - O0 . oOoO0oo0OOOo / Ooo00oOo00o / o0000oOoOoO0o
 if 20 - 20: II11iiII * II111iiii - oOo0O0Ooo - iiiiIi11i * o0oo0o
 packet . strip_outer_headers ( )
 I1i1II1 = lisp . bold ( "Forward" , False )
 if 89 - 89: ooOO00oOo / ooOO00oOo
 if 1 - 1: oOoO0oo0OOOo . i11iIiiIii
 if 74 - 74: O0 + OoooooooOO / iiiiIi11i / oOo0O0Ooo . oOoO0oo0OOOo % iiiiIi11i
 if 34 - 34: i1IIi . oo
 i11I1IIiiii = packet . inner_dest . is_mac ( )
 if ( i11I1IIiiii ) :
  packet . packet = lisp . lisp_mac_input ( packet . packet )
  if ( packet . packet == None ) : return
  I1i1II1 = lisp . bold ( "Bridge" , False )
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
  if 85 - 85: iIii1I11I1II1
  if 92 - 92: iiiiIi11i / II11iiII . oOoO0oo0OOOo
  if 30 - 30: o0000oOoOoO0o . oOoO0oo0OOOo / II11iiII
  if 2 - 2: oooO0oo0oOOOO % oo - o0oo0o
  if 79 - 79: OoooooooOO / oOoO0oo0OOOo . O0
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  ooo0O = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( ooo0O ) :
   ooo0O . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 79 - 79: iiiiIi11i - II111iiii
   return
   if 43 - 43: i1IIi + O0 % ooOO00oOo / o0000oOoOoO0o * oo
   if 89 - 89: oo . OoO0O00 + oOoO0oo0OOOo . O0 % Ooo00oOo00o
   if 84 - 84: OoooooooOO + o0oo0o / oo % II11iiII % oOoO0oo0OOOo * oo
   if 58 - 58: ooOO00oOo - oOo0O0Ooo . i11iIiiIii % i11iIiiIii / i1IIi / iiiiIi11i
   if 24 - 24: oo * i1IIi % Oo / O0 + i11iIiiIii
   if 12 - 12: oOoO0oo0OOOo / o0000oOoOoO0o
   if 5 - 5: OoooooooOO
   if 18 - 18: oo % OoooooooOO - i1I1ii1II1iII . i11iIiiIii * OoO0O00 % o0000oOoOoO0o
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 12 - 12: i1IIi / II11iiII % Oo * oooO0oo0oOOOO * O0 * iIii1I11I1II1
  if 93 - 93: OoO0O00 / oOoO0oo0OOOo + i1IIi * iiiiIi11i . OoooooooOO
  if 54 - 54: O0 / oooO0oo0oOOOO % Oo * i1IIi * O0
  if 48 - 48: Ooo00oOo00o . iiiiIi11i % oOo0O0Ooo - oOo0O0Ooo
  if 33 - 33: OoOO0ooOOoo0O % II111iiii + ooOO00oOo
 i111IiI1I = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 93 - 93: i1IIi . oooO0oo0oOOOO / oo + oooO0oo0oOOOO
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( I1i1II1 , lisp . green ( i111IiI1I , False ) ,
 # OoO0O00 * iIii1I11I1II1 - ooOO00oOo . OoO0O00
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 59 - 59: ooOO00oOo - ooOO00oOo + i1I1ii1II1iII
 if 32 - 32: i1IIi / OoO0O00 - O0
 if 85 - 85: o0000oOoOoO0o - O0 * i11iIiiIii . i1IIi
 if 20 - 20: i1I1ii1II1iII / II11iiII
 if 28 - 28: Oo * OoOO0ooOOoo0O % i11iIiiIii * i1I1ii1II1iII / o0000oOoOoO0o
 if ( i11I1IIiiii ) :
  packet . bridge_l2_packet ( packet . inner_dest , ooo0O )
  return
  if 41 - 41: II11iiII - Ooo00oOo00o + o0000oOoOoO0o
  if 15 - 15: OoOO0ooOOoo0O / Ooo00oOo00o + o0000oOoOoO0o
  if 76 - 76: o0000oOoOoO0o + OoooooooOO / II11iiII % ooOO00oOo / oOoO0oo0OOOo
  if 38 - 38: o0oo0o . i1I1ii1II1iII . oo * ooOO00oOo
  if 69 - 69: Ooo00oOo00o % i11iIiiIii / o0000oOoOoO0o
  if 93 - 93: Oo
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( oO0o0o0ooO0oO , oo0o0O00 )
  return
  if 34 - 34: iiiiIi11i - Oo * OoO0O00 / Ooo00oOo00o
  if 19 - 19: oOoO0oo0OOOo
  if 46 - 46: iIii1I11I1II1 . i11iIiiIii - oOo0O0Ooo % O0 / II111iiii * i1IIi
  if 66 - 66: O0
  if 52 - 52: ooOO00oOo * OoooooooOO
 Ii11iiI = packet . get_raw_socket ( )
 if ( Ii11iiI == None ) : Ii11iiI = oOo0oooo00o
 if 71 - 71: o0oo0o - Ooo00oOo00o - II11iiII
 if 28 - 28: iIii1I11I1II1
 if 7 - 7: Ooo00oOo00o % oooO0oo0oOOOO * oOo0O0Ooo
 if 58 - 58: oooO0oo0oOOOO / OoOO0ooOOoo0O + II111iiii % i1I1ii1II1iII - OoooooooOO
 packet . send_packet ( Ii11iiI , packet . inner_dest )
 return
 if 25 - 25: oOo0O0Ooo % OoooooooOO * OoO0O00 - i1IIi * II111iiii * iiiiIi11i
 if 30 - 30: OoOO0ooOOoo0O % oOo0O0Ooo / oOoO0oo0OOOo * O0 * o0000oOoOoO0o . oo
 if 46 - 46: oOo0O0Ooo - O0
 if 70 - 70: OoOO0ooOOoo0O + OoO0O00 * iIii1I11I1II1 . oo * OoOO0ooOOoo0O
 if 49 - 49: Ooo00oOo00o
 if 25 - 25: i1I1ii1II1iII . OoooooooOO * iIii1I11I1II1 . Ooo00oOo00o / O0 + o0000oOoOoO0o
 if 68 - 68: OoO0O00
 if 22 - 22: II11iiII
 if 22 - 22: i1I1ii1II1iII * OoOO0ooOOoo0O - OoO0O00 * O0 / i11iIiiIii
 if 78 - 78: OoO0O00 * O0 / Oo + OoooooooOO + II11iiII
 if 23 - 23: i1I1ii1II1iII % OoooooooOO / iIii1I11I1II1 + oOoO0oo0OOOo / i1IIi / Ooo00oOo00o
def oOoO ( lisp_raw_socket , packet , source ) :
 global I11 , Oo0o0000o0o0
 if 32 - 32: O0 + iiiiIi11i % OoO0O00
 if 7 - 7: oOoO0oo0OOOo / Oo
 if 11 - 11: oooO0oo0oOOOO * Oo / Oo - II11iiII
 if 68 - 68: oo % oooO0oo0oOOOO - oooO0oo0oOOOO / oo + oOoO0oo0OOOo - OoO0O00
 o0oO0o00O = packet
 packet = lisp . lisp_packet ( packet [ 8 : : ] )
 if ( packet . lisp_header . decode ( o0oO0o00O ) == False ) : return
 if 6 - 6: OoooooooOO / i11iIiiIii / o0oo0o
 if 60 - 60: oo % iiiiIi11i / Ooo00oOo00o % iiiiIi11i * i11iIiiIii / i1I1ii1II1iII
 if 34 - 34: o0oo0o - II11iiII
 if 25 - 25: iiiiIi11i % oo + i11iIiiIii + O0 * OoooooooOO
 if 64 - 64: i1IIi
 packet . outer_source = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , source ,
 lisp . LISP_IPV4_HOST_MASK_LEN , 0 )
 if 10 - 10: o0oo0o % O0 / oo % OoOO0ooOOoo0O
 oO0OOOO0o0 = packet . decode ( False , I11 ,
 lisp . lisp_decap_stats )
 if ( oO0OOOO0o0 == None ) : return
 if 25 - 25: II111iiii / ooOO00oOo
 if 64 - 64: O0 % Oo
 if 40 - 40: Ooo00oOo00o + OoOO0ooOOoo0O
 if 77 - 77: i11iIiiIii % oooO0oo0oOOOO + o0oo0o % OoooooooOO - OoOO0ooOOoo0O
 if 26 - 26: OoO0O00 + O0 - iIii1I11I1II1
 if 47 - 47: OoooooooOO
 if 2 - 2: oOo0O0Ooo % o0oo0o * OoO0O00 * oOo0O0Ooo
 if ( lisp . lisp_flow_logging ) : packet . log_flow ( False )
 if 65 - 65: i11iIiiIii + OoO0O00 * OoooooooOO - ooOO00oOo
 packet . print_packet ( "Kernel-decap" , False )
 lisp . dprint ( packet . lisp_header . print_header ( " " ) )
 if 26 - 26: Ooo00oOo00o % II11iiII + II11iiII % OoOO0ooOOoo0O * i11iIiiIii / i1I1ii1II1iII
 if 64 - 64: iiiiIi11i % oOo0O0Ooo / II111iiii % Oo - i1I1ii1II1iII
 if 2 - 2: o0oo0o - oOoO0oo0OOOo + Ooo00oOo00o * ooOO00oOo / i1I1ii1II1iII
 if 26 - 26: II11iiII * OoO0O00
 if 31 - 31: OoOO0ooOOoo0O * iiiiIi11i . o0000oOoOoO0o
 if 35 - 35: OoOO0ooOOoo0O
 if 94 - 94: Oo / i11iIiiIii % O0
 if 70 - 70: OoOO0ooOOoo0O - OoO0O00 / OoooooooOO % OoooooooOO
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 95 - 95: OoooooooOO % OoooooooOO . o0000oOoOoO0o
  II1iI = packet . udp_sport
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , source , II1iI )
  lisp . lisp_ipc ( packet , I11 , "lisp-ms" )
  return
  if 26 - 26: iiiiIi11i + oooO0oo0oOOOO - II111iiii . II111iiii + oOoO0oo0OOOo + oOo0O0Ooo
  if 68 - 68: O0
  if 76 - 76: oOoO0oo0OOOo
  if 99 - 99: Ooo00oOo00o
  if 1 - 1: o0000oOoOoO0o * oOo0O0Ooo * ooOO00oOo + OoO0O00
  if 90 - 90: o0oo0o % OoO0O00 - OoO0O00 . iIii1I11I1II1 / II11iiII + OoOO0ooOOoo0O
  if 89 - 89: iiiiIi11i
  if 87 - 87: i1I1ii1II1iII % OoO0O00
  if 62 - 62: ooOO00oOo + Oo / i1I1ii1II1iII * i11iIiiIii
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  packet = packet . packet
  OOooO0Oo00 = - 1
  if ( lisp . lisp_is_rloc_probe_request ( packet [ 28 ] ) ) :
   OOooO0Oo00 = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
   if 37 - 37: i1I1ii1II1iII
  packet = packet [ 28 : : ]
  lisp . lisp_parse_packet ( Oo0o0000o0o0 , packet , source , 0 , OOooO0Oo00 )
  return
  if 33 - 33: ooOO00oOo - O0 - ooOO00oOo
  if 94 - 94: oooO0oo0oOOOO * OoOO0ooOOoo0O * OoooooooOO / Ooo00oOo00o . oooO0oo0oOOOO - Ooo00oOo00o
  if 13 - 13: II11iiII / oooO0oo0oOOOO - ooOO00oOo / II11iiII . i1IIi
  if 22 - 22: O0 - OoOO0ooOOoo0O + o0oo0o . o0000oOoOoO0o * i1IIi
  if 26 - 26: iIii1I11I1II1 * Ooo00oOo00o . OoOO0ooOOoo0O
  if 10 - 10: o0oo0o * iiiiIi11i % OoO0O00 - OoOO0ooOOoo0O % OoO0O00
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 65 - 65: i1I1ii1II1iII * iIii1I11I1II1 / O0 . OoOO0ooOOoo0O
  if 94 - 94: OoO0O00 . Oo * i11iIiiIii - Ooo00oOo00o . i1I1ii1II1iII
  if 98 - 98: II11iiII + o0000oOoOoO0o
  if 52 - 52: OoO0O00 / oOo0O0Ooo - o0oo0o . i1I1ii1II1iII
  if 50 - 50: iIii1I11I1II1 - i1I1ii1II1iII - OoOO0ooOOoo0O
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 60 - 60: iIii1I11I1II1 * Oo
 if 71 - 71: oOo0O0Ooo % OoO0O00 % Oo
 if 34 - 34: OoOO0ooOOoo0O / OoOO0ooOOoo0O % oooO0oo0oOOOO . oOo0O0Ooo / OoO0O00
 if 99 - 99: Oo * oo - Oo % o0000oOoOoO0o
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  ooo0O = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( ooo0O ) :
   ooo0O . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 40 - 40: II11iiII / oooO0oo0oOOOO / iIii1I11I1II1 + o0000oOoOoO0o
   if 59 - 59: OoOO0ooOOoo0O * OoooooooOO + II11iiII . iIii1I11I1II1 / i1IIi
   if 75 - 75: OoOO0ooOOoo0O . II11iiII - iIii1I11I1II1 * ooOO00oOo * i1I1ii1II1iII
   if 93 - 93: Oo
   if 18 - 18: Oo
   if 66 - 66: iiiiIi11i * i11iIiiIii + oOo0O0Ooo / II11iiII
   if 96 - 96: II11iiII + II11iiII % oooO0oo0oOOOO % II11iiII
   if 28 - 28: iIii1I11I1II1 + oOo0O0Ooo . Ooo00oOo00o % i11iIiiIii
   if 58 - 58: OoOO0ooOOoo0O / OoooooooOO % iiiiIi11i + ooOO00oOo
   if 58 - 58: O0
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 91 - 91: i1I1ii1II1iII / oOoO0oo0OOOo . i1I1ii1II1iII - Ooo00oOo00o + oOoO0oo0OOOo
  if 72 - 72: o0000oOoOoO0o . oooO0oo0oOOOO * oOoO0oo0OOOo / oOoO0oo0OOOo / i1I1ii1II1iII
 i111IiI1I = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 13 - 13: i1IIi
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( lisp . bold ( "NAT-Forward" , False ) , lisp . green ( i111IiI1I , False ) ,
 # oOoO0oo0OOOo
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 86 - 86: Oo
 if 51 - 51: ooOO00oOo - i11iIiiIii * oo
 if 95 - 95: II11iiII % oOoO0oo0OOOo + Ooo00oOo00o % Oo
 if 36 - 36: O0 / i1IIi % II111iiii / i1I1ii1II1iII
 if 96 - 96: OoO0O00 / iiiiIi11i . II111iiii . OoO0O00
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( oO0o0o0ooO0oO , oo0o0O00 )
  return
  if 91 - 91: II111iiii . II11iiII + Ooo00oOo00o
  if 8 - 8: II11iiII * OoO0O00 / i1I1ii1II1iII - ooOO00oOo - OoooooooOO
  if 100 - 100: iiiiIi11i . iIii1I11I1II1 . iIii1I11I1II1
  if 55 - 55: iiiiIi11i
  if 37 - 37: oooO0oo0oOOOO / i11iIiiIii / OoO0O00
 Ii11iiI = packet . get_raw_socket ( )
 if ( Ii11iiI == None ) : Ii11iiI = lisp_raw_socket
 if 97 - 97: o0oo0o . OoOO0ooOOoo0O / oo
 if 83 - 83: OoOO0ooOOoo0O - oOoO0oo0OOOo * iiiiIi11i
 if 90 - 90: OoO0O00 * oo
 if 75 - 75: oOoO0oo0OOOo - oOo0O0Ooo * i11iIiiIii . OoooooooOO - OoO0O00 . OoOO0ooOOoo0O
 packet . send_packet ( Ii11iiI , packet . inner_dest )
 return
 if 6 - 6: OoOO0ooOOoo0O * iiiiIi11i / OoooooooOO % o0000oOoOoO0o * Ooo00oOo00o
 if 28 - 28: oooO0oo0oOOOO * oo % oooO0oo0oOOOO
 if 95 - 95: O0 / OoOO0ooOOoo0O . o0oo0o
 if 17 - 17: OoOO0ooOOoo0O
 if 56 - 56: Oo * Ooo00oOo00o + OoOO0ooOOoo0O
 if 48 - 48: oooO0oo0oOOOO * ooOO00oOo % o0oo0o - OoOO0ooOOoo0O
 if 72 - 72: i1IIi % Oo % oooO0oo0oOOOO % iiiiIi11i - iiiiIi11i
 if 97 - 97: Ooo00oOo00o * O0 / Ooo00oOo00o * ooOO00oOo * OoO0O00
def iiI1iiii1Iii ( group , joinleave ) :
 O00ooOo = None
 for I1111IIi in lisp . lisp_group_mapping_list . values ( ) :
  ii1 = oO00oOo0OOO ( group , I1111IIi )
  if ( ii1 == - 1 ) : continue
  if ( O00ooOo == None or ii1 > O00ooOo . mask_len ) : O00ooOo = I1111IIi
  if 94 - 94: i11iIiiIii % iiiiIi11i + OoO0O00 + iiiiIi11i
 if ( O00ooOo == None ) : return
 if 33 - 33: oooO0oo0oOOOO . OoO0O00 / iIii1I11I1II1
 iiiIiIiI = [ ]
 for IIiIi1iI in O00ooOo . sources :
  iiiIiIiI . append ( [ IIiIi1iI , group , joinleave ] )
  if 30 - 30: i1I1ii1II1iII / ooOO00oOo . i1I1ii1II1iII
  if 17 - 17: OoO0O00 + OoooooooOO * OoooooooOO
 Ii11iI ( Oo0o0000o0o0 , iiiIiIiI )
 return
 if 5 - 5: o0oo0o % OoooooooOO . oOo0O0Ooo
 if 67 - 67: oOoO0oo0OOOo + o0000oOoOoO0o
 if 72 - 72: oooO0oo0oOOOO % Ooo00oOo00o
 if 93 - 93: iIii1I11I1II1 + i11iIiiIii . Ooo00oOo00o . i1IIi % oo % Oo
 if 74 - 74: oOo0O0Ooo / i1IIi % OoooooooOO
 if 52 - 52: oooO0oo0oOOOO % Oo
 if 25 - 25: OoOO0ooOOoo0O / OoOO0ooOOoo0O % OoooooooOO - oOoO0oo0OOOo * iiiiIi11i
 if 23 - 23: i11iIiiIii
 if 100 - 100: iiiiIi11i + O0 . oo + i1IIi - oOo0O0Ooo + Ooo00oOo00o
 if 65 - 65: II111iiii / OoO0O00
 if 42 - 42: i11iIiiIii . O0
 if 75 - 75: o0oo0o + iIii1I11I1II1
 if 19 - 19: oo + i11iIiiIii . oooO0oo0oOOOO - OoOO0ooOOoo0O / o0000oOoOoO0o + Ooo00oOo00o
 if 38 - 38: OoO0O00 / iIii1I11I1II1 * iIii1I11I1II1 % oOoO0oo0OOOo
 if 92 - 92: OoOO0ooOOoo0O / O0 * oo - OoOO0ooOOoo0O
 if 99 - 99: i11iIiiIii % OoooooooOO
def o0000O00oO0O ( ) :
 global Oo0o0000o0o0
 if 3 - 3: iIii1I11I1II1 % oOoO0oo0OOOo . II11iiII % OoOO0ooOOoo0O
 lisp . lisp_set_exception ( )
 if 40 - 40: Oo * o0000oOoOoO0o . o0000oOoOoO0o + II111iiii + OoooooooOO
 i11I1Iii1I = socket . htonl
 iii1 = [ i11I1Iii1I ( 0x46000020 ) , i11I1Iii1I ( 0x9fe60000 ) , i11I1Iii1I ( 0x0102d7cc ) ,
 i11I1Iii1I ( 0x0acfc15a ) , i11I1Iii1I ( 0xe00000fb ) , i11I1Iii1I ( 0x94040000 ) ]
 if 93 - 93: iiiiIi11i % i1IIi
 oOO0 = ""
 for OO in iii1 : oOO0 += struct . pack ( "I" , OO )
 if 61 - 61: OoOO0ooOOoo0O . OoOO0ooOOoo0O - ooOO00oOo
 if 62 - 62: i1I1ii1II1iII . i1I1ii1II1iII
 if 22 - 22: Oo / Oo - o0000oOoOoO0o % OoOO0ooOOoo0O . II11iiII + oooO0oo0oOOOO
 if 64 - 64: i1IIi % oOoO0oo0OOOo / o0000oOoOoO0o % OoooooooOO
 if 24 - 24: o0oo0o + OoooooooOO . oooO0oo0oOOOO / oOo0O0Ooo / OoOO0ooOOoo0O
 while ( True ) :
  ooOoo = commands . getoutput ( "ls join-*" ) . replace ( "join-" , "" )
  ooOoo = ooOoo . split ( "\n" )
  if 91 - 91: Ooo00oOo00o . i1I1ii1II1iII % OoO0O00 - i1I1ii1II1iII . iiiiIi11i % i11iIiiIii
  for ooO in ooOoo :
   if ( lisp . lisp_valid_address_format ( "address" , ooO ) == False ) :
    continue
    if 25 - 25: iIii1I11I1II1
    if 63 - 63: Oo
   oO0oOOOooo = ( ooO . find ( ":" ) != - 1 )
   if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % Ooo00oOo00o / iIii1I11I1II1 * o0oo0o
   if 3 - 3: II11iiII . oooO0oo0oOOOO / OoO0O00
   if 89 - 89: OoooooooOO . iIii1I11I1II1 . OoO0O00 * iIii1I11I1II1 - o0oo0o
   if 92 - 92: OoooooooOO - oOoO0oo0OOOo - OoooooooOO % oo % oo % iIii1I11I1II1
   O00oo0oOoO00O = os . path . exists ( "leave-{}" . format ( ooO ) )
   lisp . lprint ( "Internal {} group {}" . format ( "leaving" if O00oo0oOoO00O else "joining" , ooO ) )
   if 7 - 7: II111iiii * Oo . OoO0O00 / oo
   if 43 - 43: o0000oOoOoO0o + i1I1ii1II1iII + i1IIi - oOo0O0Ooo + Ooo00oOo00o
   if 54 - 54: oOoO0oo0OOOo + oOoO0oo0OOOo + OoOO0ooOOoo0O % i1IIi % i11iIiiIii
   if 100 - 100: oOoO0oo0OOOo
   if 96 - 96: oo . oooO0oo0oOOOO * II111iiii % oooO0oo0oOOOO . o0oo0o * i1IIi
   if ( oO0oOOOooo ) :
    if ( ooO . lower ( ) . find ( "ff02:" ) != - 1 ) :
     lisp . lprint ( "Suppress registration for link-local groups" )
     continue
     if 83 - 83: iIii1I11I1II1
    iiI1iiii1Iii ( ooO , ( O00oo0oOoO00O == False ) )
   else :
    Oo0O0O = oOO0
    if ( O00oo0oOoO00O ) :
     Oo0O0O += struct . pack ( "I" , i11I1Iii1I ( 0x17000000 ) )
    else :
     Oo0O0O += struct . pack ( "I" , i11I1Iii1I ( 0x16000000 ) )
     if 8 - 8: i11iIiiIii * O0 + oOoO0oo0OOOo . iIii1I11I1II1 % OoOO0ooOOoo0O / OoOO0ooOOoo0O
     if 70 - 70: oo + o0000oOoOoO0o
    o0o = ooO . split ( "." )
    oO0o0Ooooo = int ( o0o [ 0 ] ) << 24
    oO0o0Ooooo += int ( o0o [ 1 ] ) << 16
    oO0o0Ooooo += int ( o0o [ 2 ] ) << 8
    oO0o0Ooooo += int ( o0o [ 3 ] )
    Oo0O0O += struct . pack ( "I" , i11I1Iii1I ( oO0o0Ooooo ) )
    i1I1i1i ( Oo0O0O )
    time . sleep ( .100 )
    if 76 - 76: i1I1ii1II1iII . oooO0oo0oOOOO % i1I1ii1II1iII - o0oo0o
    if 51 - 51: OoooooooOO + Ooo00oOo00o * iIii1I11I1II1 * iiiiIi11i / i1IIi
  time . sleep ( 10 )
  if 19 - 19: i1I1ii1II1iII - oOo0O0Ooo % iiiiIi11i / OoooooooOO % i1I1ii1II1iII
 return
 if 65 - 65: O0 . iiiiIi11i
 if 85 - 85: II111iiii
 if 55 - 55: oOoO0oo0OOOo
 if 76 - 76: iiiiIi11i - i11iIiiIii
 if 27 - 27: oOoO0oo0OOOo - i11iIiiIii % o0oo0o / OoO0O00 . OoO0O00 / OoooooooOO
 if 76 - 76: OoOO0ooOOoo0O * ooOO00oOo . iIii1I11I1II1 % OoooooooOO % oOoO0oo0OOOo
 if 39 - 39: II111iiii * oOo0O0Ooo . O0 * OoOO0ooOOoo0O
 if 89 - 89: o0000oOoOoO0o - Oo . OoOO0ooOOoo0O - o0oo0o - oo
 if 79 - 79: oooO0oo0oOOOO + oooO0oo0oOOOO + o0000oOoOoO0o
 if 39 - 39: O0 - OoooooooOO
def oo0O00ooo0o ( ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 29 - 29: OoooooooOO . II111iiii % oOo0O0Ooo
 if 26 - 26: iIii1I11I1II1 - oOoO0oo0OOOo . oooO0oo0oOOOO . oooO0oo0oOOOO + iIii1I11I1II1 * OoO0O00
 if 85 - 85: II11iiII + II111iiii - II11iiII * iiiiIi11i - i1IIi % i1I1ii1II1iII
 if 1 - 1: OoooooooOO / O0 + oOo0O0Ooo + oOo0O0Ooo . o0oo0o - oOo0O0Ooo
 if 9 - 9: o0oo0o * OoooooooOO % oo / oOo0O0Ooo * OoOO0ooOOoo0O
 ii = lisp . lisp_get_all_multicast_rles ( )
 if 47 - 47: i11iIiiIii / OoO0O00 - OoO0O00 * ooOO00oOo
 if 48 - 48: oooO0oo0oOOOO
 if 96 - 96: iiiiIi11i / O0 . II111iiii + oooO0oo0oOOOO % Ooo00oOo00o
 if 67 - 67: O0 % o0oo0o
 IIii1III = "any"
 if 35 - 35: oo . oOo0O0Ooo + OoooooooOO % OoO0O00 % II11iiII
 if 39 - 39: o0000oOoOoO0o
 if 60 - 60: II11iiII
 o000ooOo0o0OO = pcappy . open_live ( IIii1III , 1600 , 0 , 100 )
 if 1 - 1: iIii1I11I1II1 % Oo + O0
 IIiII11 = "(proto 2) or "
 if 58 - 58: i1I1ii1II1iII
 IIiII11 += "((dst host "
 for I11IIIII in lisp . lisp_get_all_addresses ( ) + ii :
  IIiII11 += "{} or " . format ( I11IIIII )
  if 53 - 53: OoooooooOO . OoooooooOO + Ooo00oOo00o - i1I1ii1II1iII + II11iiII
 IIiII11 = IIiII11 [ 0 : - 4 ]
 IIiII11 += ") and ((udp dst port 4341 or 8472 or 4789) or "
 IIiII11 += "(udp dst port 4342 and ip[28] == 0x12) or "
 IIiII11 += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0)))))"
 if 44 - 44: o0oo0o - oooO0oo0oOOOO
 if 100 - 100: iiiiIi11i . ooOO00oOo - o0000oOoOoO0o + O0 * ooOO00oOo
 lisp . lprint ( "Capturing packets for: '{}' on device {}" . format ( IIiII11 ,
 IIii1III ) )
 o000ooOo0o0OO . filter = IIiII11
 if 59 - 59: II111iiii
 if 43 - 43: OoO0O00 + OoooooooOO
 if 47 - 47: Oo
 if 92 - 92: OoOO0ooOOoo0O % i11iIiiIii % OoO0O00
 o000ooOo0o0OO . loop ( - 1 , i11IiI1iiI11 , [ IIii1III , oOo0oooo00o ] )
 return
 if 23 - 23: II111iiii * i1I1ii1II1iII
 if 80 - 80: o0oo0o / i11iIiiIii + OoooooooOO
 if 38 - 38: oOoO0oo0OOOo % Oo + i1IIi * OoooooooOO * iiiiIi11i
 if 83 - 83: iIii1I11I1II1 - Oo - o0oo0o / ooOO00oOo - O0
 if 81 - 81: o0000oOoOoO0o - iiiiIi11i * oOoO0oo0OOOo / o0oo0o
 if 21 - 21: ooOO00oOo
 if 63 - 63: OoOO0ooOOoo0O . O0 * OoOO0ooOOoo0O + iIii1I11I1II1
def Ii1iIi ( ) :
 global I11
 global i1111
 global Oo0o0000o0o0
 global oOo0oooo00o
 global oO0o0o0ooO0oO
 global oo0o0O00
 if 79 - 79: II11iiII % o0oo0o / iiiiIi11i - iIii1I11I1II1 - oOo0O0Ooo
 lisp . lisp_i_am ( "etr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "ETR starting up" )
 if 60 - 60: II111iiii
 if 90 - 90: oOo0O0Ooo
 if 37 - 37: oOo0O0Ooo + O0 . O0 * OoO0O00 % o0oo0o / i1I1ii1II1iII
 if 18 - 18: OoooooooOO
 lisp . lisp_get_local_interfaces ( )
 lisp . lisp_get_local_macs ( )
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 57 - 57: Oo . oOo0O0Ooo * Ooo00oOo00o - OoooooooOO
 if 75 - 75: i11iIiiIii / Ooo00oOo00o . oooO0oo0oOOOO . i1IIi . i1IIi / OoOO0ooOOoo0O
 if 94 - 94: Oo + oo
 if 56 - 56: oOo0O0Ooo % Ooo00oOo00o
 if 40 - 40: II11iiII / oooO0oo0oOOOO
 if 29 - 29: o0000oOoOoO0o - o0000oOoOoO0o / Oo
 if 49 - 49: OoOO0ooOOoo0O + iiiiIi11i % ooOO00oOo - OoO0O00 - O0 - OoooooooOO
 if 4 - 4: II111iiii - iiiiIi11i % OoO0O00 * i11iIiiIii
 if 18 - 18: OoO0O00 % O0
 if 66 - 66: iIii1I11I1II1 % i11iIiiIii / oo
 if 47 - 47: oOoO0oo0OOOo * iiiiIi11i + iIii1I11I1II1 - iiiiIi11i / oooO0oo0oOOOO
 if 86 - 86: oooO0oo0oOOOO
 if 43 - 43: oo / i1I1ii1II1iII / Oo + iIii1I11I1II1 + OoooooooOO
 if 33 - 33: II111iiii - oooO0oo0oOOOO - Oo
 if 92 - 92: ooOO00oOo * oooO0oo0oOOOO
 IIiIi1iI = lisp . lisp_open_listen_socket ( "0.0.0.0" , str ( i11 ) )
 IIiIi1iI . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_TTL , 32 )
 i1111 = IIiIi1iI
 if 92 - 92: iiiiIi11i
 if 7 - 7: i1I1ii1II1iII
 if 73 - 73: ooOO00oOo % oOoO0oo0OOOo
 if 32 - 32: II11iiII + i1I1ii1II1iII + iIii1I11I1II1 * OoO0O00
 I11 = lisp . lisp_open_listen_socket ( "" , "lisp-etr" )
 if 62 - 62: i11iIiiIii
 Oo0o0000o0o0 [ 0 ] = i1111
 Oo0o0000o0o0 [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 Oo0o0000o0o0 [ 2 ] = I11
 if 2 - 2: oo
 if 69 - 69: OoooooooOO / OoO0O00 * o0oo0o
 if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * iiiiIi11i / II111iiii % OoooooooOO
 if 14 - 14: oooO0oo0oOOOO . oooO0oo0oOOOO % Oo
 if 42 - 42: Ooo00oOo00o . II11iiII - Oo
 if 33 - 33: II111iiii / O0 / oooO0oo0oOOOO - OoOO0ooOOoo0O - i1IIi
 if 8 - 8: i11iIiiIii . i1I1ii1II1iII / iIii1I11I1II1 / oOoO0oo0OOOo / oooO0oo0oOOOO - o0000oOoOoO0o
 if 32 - 32: Ooo00oOo00o . i1IIi * OoO0O00
 if 98 - 98: o0000oOoOoO0o - II111iiii / oo . iiiiIi11i * oooO0oo0oOOOO . OoOO0ooOOoo0O
 oOo0oooo00o = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 oOo0oooo00o . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 Oo0o0000o0o0 . append ( oOo0oooo00o )
 if 25 - 25: i11iIiiIii / oOo0O0Ooo - o0oo0o / ooOO00oOo . Ooo00oOo00o . Ooo00oOo00o
 if 6 - 6: iiiiIi11i . OoOO0ooOOoo0O
 if 43 - 43: oOoO0oo0OOOo + Ooo00oOo00o
 if 50 - 50: iiiiIi11i % i1IIi * O0
 if 4 - 4: iIii1I11I1II1 . i1IIi
 if 63 - 63: iIii1I11I1II1 + oooO0oo0oOOOO % i1IIi / oo % II111iiii
 if 60 - 60: Ooo00oOo00o . oOo0O0Ooo % o0oo0o / oo / O0
 if 19 - 19: i11iIiiIii . oo + II111iiii / II11iiII . oOoO0oo0OOOo * Oo
 if 59 - 59: iIii1I11I1II1 / oOoO0oo0OOOo % Oo
 if 84 - 84: iIii1I11I1II1 / oo . oOo0O0Ooo % OoOO0ooOOoo0O
 if 99 - 99: OoO0O00 + i11iIiiIii
 if 36 - 36: o0000oOoOoO0o * o0oo0o * iIii1I11I1II1 - OoOO0ooOOoo0O % i11iIiiIii
 if 98 - 98: iIii1I11I1II1 - i1IIi + Oo % OoOO0ooOOoo0O + Oo / iiiiIi11i
 if 97 - 97: oooO0oo0oOOOO % Oo + II111iiii - oooO0oo0oOOOO % ooOO00oOo + Oo
 if 31 - 31: Ooo00oOo00o
 if 35 - 35: oOo0O0Ooo + o0000oOoOoO0o * Oo / oOo0O0Ooo
 if 69 - 69: Oo . II11iiII - oo
 if 29 - 29: i11iIiiIii . oOoO0oo0OOOo / oo . II11iiII + i11iIiiIii
 if 26 - 26: oooO0oo0oOOOO / o0000oOoOoO0o - OoooooooOO
 if 9 - 9: OoooooooOO * oOoO0oo0OOOo
 if 9 - 9: OoO0O00 + i1I1ii1II1iII
 if 64 - 64: O0 * oo / oo
 if ( pytun != None ) :
  oo0o0O00 = '\x00\x00\x86\xdd'
  IIii1III = "lispers.net"
  try :
   oO0o0o0ooO0oO = pytun . TunTapDevice ( flags = pytun . IFF_TUN ,
 name = IIii1III )
   os . system ( "ip link set dev {} up" . format ( IIii1III ) )
  except :
   lisp . lprint ( "Cannot create tuntap interface" )
   if 57 - 57: oOoO0oo0OOOo / OoooooooOO % oOoO0oo0OOOo . O0 / oOoO0oo0OOOo
   if 63 - 63: oooO0oo0oOOOO + iIii1I11I1II1 + oo + o0oo0o
   if 72 - 72: ooOO00oOo + i11iIiiIii + oOoO0oo0OOOo
   if 96 - 96: iiiiIi11i % i1IIi / Ooo00oOo00o
   if 13 - 13: II111iiii - OoO0O00 % i11iIiiIii + i1I1ii1II1iII
   if 88 - 88: O0 . iiiiIi11i % oo
 threading . Thread ( target = oo0O00ooo0o , args = [ ] ) . start ( )
 if 10 - 10: oo + O0
 if 75 - 75: O0 % iIii1I11I1II1 / oOo0O0Ooo % II11iiII / oooO0oo0oOOOO
 if 31 - 31: i11iIiiIii * oOo0O0Ooo
 if 69 - 69: i11iIiiIii
 threading . Thread ( target = o0000O00oO0O , args = [ ] ) . start ( )
 return ( True )
 if 61 - 61: O0
 if 21 - 21: ooOO00oOo % iIii1I11I1II1 . ooOO00oOo
 if 99 - 99: Ooo00oOo00o * II11iiII % iiiiIi11i * iiiiIi11i + OoooooooOO
 if 82 - 82: OoOO0ooOOoo0O / oOo0O0Ooo - II11iiII / Oo
 if 50 - 50: II11iiII + ooOO00oOo . i11iIiiIii + oOoO0oo0OOOo + i11iIiiIii
 if 31 - 31: iiiiIi11i * o0oo0o . oOo0O0Ooo * OoOO0ooOOoo0O
 if 28 - 28: oooO0oo0oOOOO + oo - OoO0O00 % II11iiII . OoOO0ooOOoo0O + oo
def O0oO0 ( ) :
 global o0oOoO00o
 global oOOoo00O0O
 if 65 - 65: II11iiII + o0oo0o - o0000oOoOoO0o
 if 53 - 53: oo
 if 96 - 96: ooOO00oOo - oooO0oo0oOOOO . OoooooooOO
 if 10 - 10: o0oo0o
 if ( o0oOoO00o ) : o0oOoO00o . cancel ( )
 if ( oOOoo00O0O ) : oOOoo00O0O . cancel ( )
 if 48 - 48: i1I1ii1II1iII * i1IIi % OoooooooOO * o0000oOoOoO0o * ooOO00oOo
 if 7 - 7: i1I1ii1II1iII . o0000oOoOoO0o . i1I1ii1II1iII - o0oo0o
 if 33 - 33: Oo + OoooooooOO - ooOO00oOo / i1IIi / OoooooooOO
 if 82 - 82: oOoO0oo0OOOo / II11iiII - i1I1ii1II1iII / OoO0O00 * ooOO00oOo
 lisp . lisp_close_socket ( Oo0o0000o0o0 [ 0 ] , "" )
 lisp . lisp_close_socket ( Oo0o0000o0o0 [ 1 ] , "" )
 lisp . lisp_close_socket ( I11 , "lisp-etr" )
 return
 if 55 - 55: OoooooooOO
 if 73 - 73: oOo0O0Ooo - oOoO0oo0OOOo % OoO0O00 + oOoO0oo0OOOo - O0 . ooOO00oOo
 if 38 - 38: O0
 if 79 - 79: i1IIi . iiiiIi11i
 if 34 - 34: o0oo0o * II111iiii
 if 71 - 71: oooO0oo0oOOOO
 if 97 - 97: oOoO0oo0OOOo
 if 86 - 86: OoO0O00 - II11iiII . oOo0O0Ooo . II111iiii * oo . II111iiii
 if 34 - 34: Ooo00oOo00o . o0oo0o % oooO0oo0oOOOO - O0 / o0oo0o
def Oo00OOoO0oo ( ipc ) :
 ipc = ipc . split ( "%" )
 iiIiI1ii = ipc [ 1 ]
 IIi11ii11 = ipc [ 2 ]
 if ( IIi11ii11 == "None" ) : IIi11ii11 = None
 if 54 - 54: OoOO0ooOOoo0O % O0 - II11iiII % ooOO00oOo + ooOO00oOo . oooO0oo0oOOOO
 iII1iii = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 iII1iii . store_address ( iiIiI1ii )
 if 99 - 99: ooOO00oOo / i1IIi . oOoO0oo0OOOo
 if 23 - 23: o0000oOoOoO0o * Oo - OoOO0ooOOoo0O . O0 % iIii1I11I1II1
 if 19 - 19: oo
 if 66 - 66: iiiiIi11i / oOo0O0Ooo
 ooo0O = lisp . lisp_db_for_lookups . lookup_cache ( iII1iii , False )
 if ( ooo0O == None or ooo0O . dynamic_eid_configured ( ) == False ) :
  lisp . lprint ( "ITR/ETR dynamic-EID configuration out of sync for {}" . format ( lisp . green ( iiIiI1ii , False ) ) )
  if 13 - 13: II111iiii
  return
  if 55 - 55: OoO0O00 % i1IIi * OoOO0ooOOoo0O
  if 95 - 95: II11iiII / II111iiii - Ooo00oOo00o % o0oo0o . OoOO0ooOOoo0O
  if 63 - 63: iIii1I11I1II1 / Oo
  if 24 - 24: OoO0O00 / iIii1I11I1II1 % II11iiII * oOo0O0Ooo - iIii1I11I1II1
  if 50 - 50: II111iiii
  if 39 - 39: II111iiii . oOo0O0Ooo - OoO0O00 * i1IIi . OoooooooOO
 oOooO0 = None
 if ( ooo0O . dynamic_eids . has_key ( iiIiI1ii ) ) : oOooO0 = ooo0O . dynamic_eids [ iiIiI1ii ]
 if 44 - 44: oo
 if ( oOooO0 == None and IIi11ii11 == None ) :
  lisp . lprint ( "ITR/ETR state mismatch for {}" . format ( lisp . green ( iiIiI1ii , False ) ) )
  if 55 - 55: iiiiIi11i . o0oo0o * o0oo0o
  return
  if 82 - 82: oo % ooOO00oOo % OoOO0ooOOoo0O + OoOO0ooOOoo0O
  if 6 - 6: OoO0O00
  if 73 - 73: o0oo0o * oOoO0oo0OOOo + Ooo00oOo00o - OoO0O00 . OoOO0ooOOoo0O
  if 93 - 93: i11iIiiIii
  if 80 - 80: i1IIi . oo - iiiiIi11i + II11iiII + i1I1ii1II1iII % iiiiIi11i
  if 13 - 13: II111iiii / oOo0O0Ooo / oOo0O0Ooo + Oo
  if 49 - 49: O0 / II111iiii * oo - OoooooooOO . II111iiii % oooO0oo0oOOOO
 if ( oOooO0 and IIi11ii11 ) :
  if ( oOooO0 . interface == IIi11ii11 ) :
   lisp . lprint ( "ITR sent redundant IPC for {}" . format ( lisp . green ( iiIiI1ii , False ) ) )
   if 13 - 13: iiiiIi11i . iIii1I11I1II1 . II11iiII . oooO0oo0oOOOO
  else :
   lisp . lprint ( "Dynamic-EID {} interface change, {} -> {}" . format ( lisp . green ( iiIiI1ii , False ) , oOooO0 . interface , IIi11ii11 ) )
   if 58 - 58: OoOO0ooOOoo0O
   oOooO0 . interface = IIi11ii11
   if 7 - 7: II111iiii / oooO0oo0oOOOO % OoOO0ooOOoo0O + oo - O0
  return
  if 45 - 45: oo / i1I1ii1II1iII + iiiiIi11i + oooO0oo0oOOOO
  if 15 - 15: oo % ooOO00oOo
  if 66 - 66: iiiiIi11i * i11iIiiIii . o0oo0o
  if 92 - 92: iiiiIi11i
  if 81 - 81: Ooo00oOo00o % oo - i1I1ii1II1iII / i11iIiiIii
 if ( IIi11ii11 ) :
  oOooO0 = lisp . lisp_dynamic_eid ( )
  oOooO0 . dynamic_eid . copy_address ( iII1iii )
  oOooO0 . interface = IIi11ii11
  oOooO0 . get_timeout ( IIi11ii11 )
  ooo0O . dynamic_eids [ iiIiI1ii ] = oOooO0
  if 73 - 73: O0 * o0oo0o . i1IIi
  OO00OoOO = lisp . bold ( "Registering" , False )
  iiIiI1ii = lisp . bold ( iiIiI1ii , False )
  lisp . lprint ( "{} dynamic-EID {} on interface {}, timeout {}" . format ( OO00OoOO ,
 lisp . green ( iiIiI1ii , False ) , IIi11ii11 , oOooO0 . timeout ) )
  if 45 - 45: II111iiii * i1IIi
  o00oo0 ( Oo0o0000o0o0 , None , iII1iii , None , False )
  if 25 - 25: oOo0O0Ooo + iIii1I11I1II1 % OoOO0ooOOoo0O / OoO0O00 * OoO0O00
  if 51 - 51: iiiiIi11i - ooOO00oOo + i1I1ii1II1iII - Ooo00oOo00o . ooOO00oOo % oOoO0oo0OOOo
  if 14 - 14: oo / O0
  if 43 - 43: iiiiIi11i - oooO0oo0oOOOO % i11iIiiIii * II111iiii . o0oo0o - OoOO0ooOOoo0O
  if ( lisp . lisp_is_macos ( ) == False ) :
   iiIiI1ii = iII1iii . print_prefix_no_iid ( )
   i11i111 = "ip route add {} dev {}" . format ( iiIiI1ii , IIi11ii11 )
   os . system ( i11i111 )
   if 36 - 36: OoOO0ooOOoo0O - oooO0oo0oOOOO . oooO0oo0oOOOO
  return
  if 60 - 60: i11iIiiIii * OoO0O00 % ooOO00oOo + ooOO00oOo
  if 84 - 84: iIii1I11I1II1 + OoooooooOO
  if 77 - 77: O0 * oOoO0oo0OOOo * iiiiIi11i + ooOO00oOo + oOoO0oo0OOOo - o0oo0o
  if 10 - 10: oOoO0oo0OOOo + oooO0oo0oOOOO
  if 58 - 58: oo + OoooooooOO / i1I1ii1II1iII . Oo % Ooo00oOo00o / oOoO0oo0OOOo
 if ( ooo0O . dynamic_eids . has_key ( iiIiI1ii ) ) :
  IIi11ii11 = ooo0O . dynamic_eids [ iiIiI1ii ] . interface
  oooO0 = lisp . bold ( "Deregistering" , False )
  lisp . lprint ( "{} dynamic-EID {}" . format ( oooO0 ,
 lisp . green ( iiIiI1ii , False ) ) )
  if 29 - 29: o0000oOoOoO0o * II11iiII * i1IIi . o0000oOoOoO0o * o0oo0o . Oo
  o00oo0 ( Oo0o0000o0o0 , 0 , iII1iii , None , False )
  if 54 - 54: i1I1ii1II1iII . i1IIi . oOoO0oo0OOOo * Ooo00oOo00o % i1I1ii1II1iII
  ooo0O . dynamic_eids . pop ( iiIiI1ii )
  if 30 - 30: OoOO0ooOOoo0O
  if 85 - 85: II111iiii + Oo * OoOO0ooOOoo0O
  if 12 - 12: o0000oOoOoO0o . oo % Ooo00oOo00o
  if 28 - 28: o0000oOoOoO0o - oo % ooOO00oOo * o0oo0o
  if ( lisp . lisp_is_macos ( ) == False ) :
   iiIiI1ii = iII1iii . print_prefix_no_iid ( )
   i11i111 = "ip route delete {} dev {}" . format ( iiIiI1ii , IIi11ii11 )
   os . system ( i11i111 )
   if 80 - 80: II11iiII * oooO0oo0oOOOO
   if 4 - 4: iIii1I11I1II1 . o0oo0o + II111iiii % OoooooooOO
 return
 if 82 - 82: OoooooooOO / Oo * OoOO0ooOOoo0O * O0 . oOoO0oo0OOOo
 if 21 - 21: II111iiii + OoO0O00
 if 59 - 59: II11iiII + oo / II111iiii / oOo0O0Ooo
 if 80 - 80: oOo0O0Ooo + iIii1I11I1II1 . oooO0oo0oOOOO
 if 76 - 76: oo * II11iiII
 if 12 - 12: iIii1I11I1II1 / OoOO0ooOOoo0O % o0000oOoOoO0o
 if 49 - 49: ooOO00oOo + II111iiii / oooO0oo0oOOOO - O0 % o0000oOoOoO0o
 if 27 - 27: ooOO00oOo + OoO0O00
 if 92 - 92: oo % i1I1ii1II1iII
def iiiI1IiI ( ipc ) :
 if ( lisp . lisp_register_all_rtrs ) : return
 if 2 - 2: O0 % o0oo0o % oOoO0oo0OOOo % Ooo00oOo00o - OoO0O00
 i1i11ii1 , oO , oO0OOOO0o0 = ipc . split ( "%" )
 if ( lisp . lisp_rtr_list . has_key ( oO ) == False ) : return
 if 95 - 95: i11iIiiIii
 lisp . lprint ( "Process ITR IPC message, RTR {} has gone {}" . format (
 lisp . red ( oO , False ) , lisp . bold ( oO0OOOO0o0 , False ) ) )
 if 95 - 95: OoO0O00
 IIiIi = lisp . lisp_rtr_list [ oO ]
 if ( oO0OOOO0o0 == "down" ) :
  lisp . lisp_rtr_list [ oO ] = None
  return
  if 49 - 49: oo
  if 24 - 24: II111iiii / o0000oOoOoO0o . iIii1I11I1II1 - II111iiii % O0
 IIiIi = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , oO , 32 , 0 )
 lisp . lisp_rtr_list [ oO ] = IIiIi
 return
 if 8 - 8: ooOO00oOo % i1I1ii1II1iII . OoooooooOO - o0000oOoOoO0o % OoooooooOO
 if 61 - 61: Ooo00oOo00o / i11iIiiIii
 if 28 - 28: II11iiII / oOo0O0Ooo
 if 30 - 30: Oo
 if 57 - 57: Ooo00oOo00o * i11iIiiIii / oOo0O0Ooo
 if 40 - 40: iIii1I11I1II1 - Oo / OoO0O00
 if 24 - 24: iiiiIi11i - i1I1ii1II1iII / Oo
 if 10 - 10: oOo0O0Ooo * i1IIi
def I1Ii1ii ( ipc ) :
 oOOOoo0o , i1i11ii1 , iIIi1 , OoOo0O00 = ipc . split ( "%" )
 OoOo0O00 = int ( OoOo0O00 , 16 )
 if 9 - 9: II11iiII
 I1i = lisp . lisp_get_echo_nonce ( None , iIIi1 )
 if ( I1i == None ) : I1i = lisp . lisp_echo_nonce ( iIIi1 )
 if 44 - 44: ooOO00oOo . i1I1ii1II1iII / OoOO0ooOOoo0O + OoO0O00 - ooOO00oOo / II111iiii
 if ( i1i11ii1 == "R" ) :
  I1i . request_nonce_sent = OoOo0O00
  lisp . lprint ( "Waiting for echo-nonce 0x{} from {}" . format ( lisp . lisp_hex_string ( OoOo0O00 ) , lisp . red ( I1i . rloc_str , False ) ) )
  if 93 - 93: iiiiIi11i - II11iiII + Ooo00oOo00o . iiiiIi11i / OoOO0ooOOoo0O
 elif ( i1i11ii1 == "E" ) :
  I1i . echo_nonce_sent = OoOo0O00
  lisp . lprint ( "Sent echo-nonce 0x{} to {}" . format ( lisp . lisp_hex_string ( OoOo0O00 ) , lisp . red ( I1i . rloc_str , False ) ) )
  if 52 - 52: o0oo0o + o0oo0o
  if 73 - 73: Ooo00oOo00o . i11iIiiIii % OoooooooOO + Oo . OoooooooOO / II11iiII
 return
 if 54 - 54: oOo0O0Ooo . OoooooooOO
 if 36 - 36: iiiiIi11i / II111iiii * oooO0oo0oOOOO % oOoO0oo0OOOo
 if 31 - 31: II111iiii + II11iiII - OoooooooOO . OoOO0ooOOoo0O
 if 28 - 28: o0000oOoOoO0o . oOoO0oo0OOOo
 if 77 - 77: oOoO0oo0OOOo % II111iiii
OOo00o0oo0 = {
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

 "lisp map-server" : [ ooO00OO0 , {
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

 "lisp group-mapping" : [ oOooO , {
 "group-name" : [ False ] ,
 "ms-name" : [ True ] ,
 "group-prefix" : [ False ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "rle-address" : [ False ] ,
 "sources" : [ ] ,
 "address" : [ True ] } ] ,

 "show database-mapping" : [ oO00 , { } ] ,
 "show etr-keys" : [ IIi1I11I1II , { } ] ,
 "show etr-dynamic-eid" : [ lispconfig . lisp_show_dynamic_eid_command , { } ]
 }
if 33 - 33: Ooo00oOo00o . II11iiII + Ooo00oOo00o / oOoO0oo0OOOo . OoO0O00 + oOo0O0Ooo
if 32 - 32: oooO0oo0oOOOO - Oo * i1I1ii1II1iII * OoOO0ooOOoo0O
if 84 - 84: o0000oOoOoO0o + oOoO0oo0OOOo % oo + i11iIiiIii
if 37 - 37: OoOO0ooOOoo0O % oOoO0oo0OOOo / Oo
if 94 - 94: OoOO0ooOOoo0O / ooOO00oOo . Ooo00oOo00o
if 1 - 1: OoO0O00 . II111iiii
if ( Ii1iIi ( ) == False ) :
 lisp . lprint ( "lisp_etr_startup() failed" )
 lisp . lisp_print_banner ( "ETR abnormal exit" )
 exit ( 1 )
 if 93 - 93: II111iiii . i11iIiiIii + II111iiii % iiiiIi11i
 if 98 - 98: o0oo0o * iiiiIi11i * oOo0O0Ooo + o0000oOoOoO0o * i1I1ii1II1iII
ii11iI1iIiiI = [ i1111 , I11 ]
if 99 - 99: i11iIiiIii - i1I1ii1II1iII
while ( True ) :
 try : o0O0O0O00o , OoOooOo00o , oOOOoo0o = select . select ( ii11iI1iIiiI , [ ] , [ ] )
 except : break
 if 28 - 28: oOoO0oo0OOOo + oOoO0oo0OOOo % oOo0O0Ooo
 if 12 - 12: OoOO0ooOOoo0O
 if 19 - 19: o0000oOoOoO0o * i1IIi % O0 + OoOO0ooOOoo0O
 if 25 - 25: o0oo0o - o0000oOoOoO0o / O0 . OoooooooOO % oo . i1IIi
 if ( i1111 in o0O0O0O00o ) :
  i1i11ii1 , i1OOO0000oO , O0OOOOo0 , oOO0 = lisp . lisp_receive ( i1111 , False )
  if 19 - 19: II111iiii / II111iiii % oOoO0oo0OOOo + iiiiIi11i + iiiiIi11i + i1I1ii1II1iII
  if ( i1OOO0000oO == "" ) : break
  if 4 - 4: Ooo00oOo00o + OoOO0ooOOoo0O / i1I1ii1II1iII + i1IIi % Ooo00oOo00o % i1I1ii1II1iII
  if ( O0OOOOo0 == lisp . LISP_DATA_PORT ) :
   oOoO ( oOo0oooo00o , oOO0 , i1OOO0000oO )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( oOO0 [ 0 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 80 - 80: o0000oOoOoO0o
   iioOO = lisp . lisp_parse_packet ( Oo0o0000o0o0 , oOO0 ,
 i1OOO0000oO , O0OOOOo0 )
   if 38 - 38: OoOO0ooOOoo0O . oooO0oo0oOOOO - ooOO00oOo . oo
   if 65 - 65: o0oo0o
   if 31 - 31: i11iIiiIii / oOo0O0Ooo % oOoO0oo0OOOo
   if 44 - 44: II111iiii * oo + II11iiII
   if 31 - 31: o0000oOoOoO0o * Ooo00oOo00o * o0000oOoOoO0o + ooOO00oOo * Ooo00oOo00o . o0oo0o
   if ( iioOO ) :
    oOOoo00O0O = threading . Timer ( 0 ,
 iIIIiIi , [ None ] )
    oOOoo00O0O . start ( )
    o0oOoO00o = threading . Timer ( 0 ,
 ooO0o0Oo , [ Oo0o0000o0o0 ] )
    o0oOoO00o . start ( )
    if 89 - 89: OoooooooOO * o0000oOoOoO0o * oo . Oo * o0000oOoOoO0o / i1I1ii1II1iII
    if 46 - 46: i11iIiiIii
    if 15 - 15: O0 / i1IIi / i1IIi . i1I1ii1II1iII % oOo0O0Ooo + oo
    if 48 - 48: o0oo0o % i1I1ii1II1iII % o0000oOoOoO0o % iIii1I11I1II1 . o0000oOoOoO0o
    if 14 - 14: i1I1ii1II1iII * ooOO00oOo % O0 + OoOO0ooOOoo0O + oOoO0oo0OOOo
    if 23 - 23: OoO0O00 % i1I1ii1II1iII + o0000oOoOoO0o - o0oo0o
    if 65 - 65: OoooooooOO
    if 22 - 22: II11iiII + II111iiii + OoO0O00
 if ( I11 in o0O0O0O00o ) :
  i1i11ii1 , i1OOO0000oO , O0OOOOo0 , oOO0 = lisp . lisp_receive ( I11 , True )
  if 83 - 83: Oo
  if ( i1OOO0000oO == "" ) : break
  if 43 - 43: II11iiII
  if ( i1i11ii1 == "command" ) :
   if ( oOO0 . find ( "learn%" ) != - 1 ) :
    Oo00OOoO0oo ( oOO0 )
   elif ( oOO0 . find ( "nonce%" ) != - 1 ) :
    I1Ii1ii ( oOO0 )
   elif ( oOO0 . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( oOO0 )
   elif ( oOO0 . find ( "rtr%" ) != - 1 ) :
    iiiI1IiI ( oOO0 )
   elif ( oOO0 . find ( "stats%" ) != - 1 ) :
    oOO0 = oOO0 . split ( "%" ) [ - 1 ]
    lisp . lisp_process_data_plane_decap_stats ( oOO0 , None )
   else :
    lispconfig . lisp_process_command ( I11 ,
 i1i11ii1 , oOO0 , "lisp-etr" , [ OOo00o0oo0 ] )
    if 84 - 84: II11iiII . oooO0oo0oOOOO . i1I1ii1II1iII
  elif ( i1i11ii1 == "api" ) :
   lisp . lisp_process_api ( "lisp-etr" , I11 , oOO0 )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( oOO0 [ 0 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 2 - 2: OoO0O00 - oOo0O0Ooo
   lisp . lisp_parse_packet ( Oo0o0000o0o0 , oOO0 , i1OOO0000oO , O0OOOOo0 )
   if 49 - 49: o0000oOoOoO0o + II111iiii / iiiiIi11i - oOo0O0Ooo % oOo0O0Ooo + oo
   if 54 - 54: Oo % OoO0O00 - II11iiII
   if 16 - 16: oOoO0oo0OOOo * i1I1ii1II1iII / OoOO0ooOOoo0O
   if 46 - 46: II111iiii
O0oO0 ( )
lisp . lisp_print_banner ( "ETR normal exit" )
exit ( 0 )
if 13 - 13: oooO0oo0oOOOO + II111iiii % oo
if 30 - 30: OoooooooOO - i11iIiiIii + iiiiIi11i / OoO0O00 - i11iIiiIii
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
