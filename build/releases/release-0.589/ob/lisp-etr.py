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
from future import standard_library
standard_library . install_aliases ( )
from builtins import str
import lisp
import lispconfig
import socket
import select
import threading
import time
import struct
from subprocess import getoutput
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
O0O00Ooo = { }
if 64 - 64: oO0o - O0 / II111iiii / o0oOOo0O0Ooo / iIii1I11I1II1
if 24 - 24: O0 % o0oOOo0O0Ooo + i1IIi + I1Ii111 + I1ii11iIi11i
if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
if 23 - 23: i11iIiiIii + I1IiiI
if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
if 33 - 33: Ii1I + II111iiii % i11iIiiIii . ooOoO0o - I1IiiI
if 66 - 66: Ii1I - OoooooooOO * OoooooooOO . OOooOOo . I1ii11iIi11i
def IiI1i11iii1 ( kv_pair ) :
 global OOO0o0o
 global Ii1iI
 if 96 - 96: O0 % oO0o % iIii1I11I1II1
 Oo00OOOOO = lispconfig . lisp_map_server_command ( kv_pair )
 if 85 - 85: ooOoO0o . iII111i - OoO0O00 % ooOoO0o % II111iiii
 if 81 - 81: OoO0O00 + II111iiii % iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
 I1i1iii = ( len ( lisp . lisp_map_servers_list ) == 1 )
 if ( I1i1iii ) :
  Oo00OOOOO = list ( lisp . lisp_map_servers_list . values ( ) ) [ 0 ]
  Ii1iI = threading . Timer ( 2 , i1iiI11I ,
 [ Oo00OOOOO . map_server ] )
  Ii1iI . start ( )
 else :
  if 29 - 29: OoooooooOO
  if 23 - 23: o0oOOo0O0Ooo . II111iiii
  if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
  if 45 - 45: I1Ii111 . OoOoOO00
  if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
  if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
  if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
  if 8 - 8: OoOoOO00
  if ( lisp . lisp_nat_traversal ) : return
  if ( Oo00OOOOO and len ( lisp . lisp_db_list ) > 0 ) :
   o00O ( o0oOoO00o , None , None , Oo00OOOOO , False )
   if 69 - 69: oO0o % I1Ii111 - o0oOOo0O0Ooo + I1Ii111 - O0 % OoooooooOO
   if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
   if 4 - 4: II111iiii / ooOoO0o . iII111i
   if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
   if 50 - 50: I1IiiI
   if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
   if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 if ( O0OoOoo00o and iiiI11 ) : return
 if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
 if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
 if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
 if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
 if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 if ( len ( lisp . lisp_db_list ) > 0 ) :
  if ( OOO0o0o != None ) : return
  OOO0o0o = threading . Timer ( 5 ,
 oo000OO00Oo , [ o0oOoO00o ] )
  OOO0o0o . start ( )
  if 51 - 51: IiII * o0oOOo0O0Ooo + I11i + OoO0O00
  if 66 - 66: OoOoOO00
  if 97 - 97: oO0o % IiII * IiII
  if 39 - 39: Ii1I % IiII
  if 4 - 4: oO0o
  if 93 - 93: OoO0O00 % oO0o . OoO0O00 * I1Ii111 % Ii1I . II111iiii
  if 38 - 38: o0oOOo0O0Ooo
  if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
  if 26 - 26: iII111i
def OOO ( kv_pair ) :
 global Oo0o , OOO0o0o
 global o0oOoO00o , iiiI11
 global lisp_seen_eid_done_count
 if 59 - 59: II111iiii + OoooooooOO * OoOoOO00 + i1IIi
 if 58 - 58: II111iiii * OOooOOo * I1ii11iIi11i / OOooOOo
 if 75 - 75: oO0o
 if 50 - 50: Ii1I / Oo0Ooo - oO0o - I11i % iII111i - oO0o
 if 91 - 91: OoO0O00 / I11i - II111iiii . I11i
 if 18 - 18: o0oOOo0O0Ooo
 if ( iiiI11 ) : return
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 lispconfig . lisp_database_mapping_command ( kv_pair , I1Ii11I1Ii1i ,
 ( O0OoOoo00o == False ) )
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 if 92 - 92: iII111i . I1Ii111
 if 31 - 31: I1Ii111 . OoOoOO00 / O0
 if 89 - 89: OoOoOO00
 if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
 if 4 - 4: ooOoO0o + O0 * OOooOOo
 if ( lisp . lisp_nat_traversal ) : return
 if ( OOO0o0o != None ) : return
 if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
 if 25 - 25: I1ii11iIi11i
 if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
 if 13 - 13: OOooOOo / i11iIiiIii
 if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
 if ( O0OoOoo00o ) :
  o0o00OO0 = len ( lisp . lisp_db_list )
  if ( o0o00OO0 % 1000 == 0 ) :
   lisp . fprint ( "{} database-mappings processed" . format ( o0o00OO0 ) )
   if 7 - 7: OOooOOo + I1Ii111 + O0
   if 9 - 9: II111iiii . o0oOOo0O0Ooo - ooOoO0o / o0oOOo0O0Ooo
  I11OoOoOOOoOO = lisp . lisp_db_list [ - 1 ]
  if ( I11OoOoOOOoOO . eid . is_dist_name ( ) == False ) : return
  if ( I11OoOoOOOoOO . eid . address != "eid-done" ) : return
  iiiI11 = True
  if 38 - 38: I1Ii111
  lisp . fprint ( "Finished batch of {} database-mappings" . format ( o0o00OO0 ) )
  if 7 - 7: O0 . iII111i % I1ii11iIi11i - I1IiiI - iIii1I11I1II1
  I111IIIiIii = threading . Timer ( 0 , oo000OO00Oo ,
 [ o0oOoO00o ] )
  Oo0o = I111IIIiIii
  Oo0o . start ( )
  return
  if 85 - 85: I1ii11iIi11i % iII111i % ooOoO0o
  if 82 - 82: i11iIiiIii - iII111i * OoooooooOO / I11i
 if ( len ( lisp . lisp_map_servers_list ) > 0 ) :
  OOO0o0o = threading . Timer ( 5 ,
 oo000OO00Oo , [ o0oOoO00o ] )
  OOO0o0o . start ( )
  if 31 - 31: IiII . OoO0O00 - iIii1I11I1II1
  if 64 - 64: I11i
  if 22 - 22: Oo0Ooo + Ii1I % I1ii11iIi11i
  if 9 - 9: OoooooooOO
  if 62 - 62: OOooOOo / OoO0O00 + Ii1I / OoO0O00 . II111iiii
  if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
  if 31 - 31: II111iiii . I1IiiI
  if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
def III1Iiii1I11 ( clause ) :
 if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 oo0o00O = lispconfig . lisp_show_myrlocs ( "" )
 if 51 - 51: Ii1I - OoO0O00 * iII111i
 if 66 - 66: OoooooooOO + O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 oo0o00O = lispconfig . lisp_show_decap_stats ( oo0o00O , "ETR" )
 if 68 - 68: OOooOOo % I1Ii111
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
 i1I1iI1iIi111i = lisp . lisp_decent_dns_suffix
 if ( i1I1iI1iIi111i == None ) :
  i1I1iI1iIi111i = ":"
 else :
  i1I1iI1iIi111i = "&nbsp;(dns-suffix '{}'):" . format ( i1I1iI1iIi111i )
  if 44 - 44: i1IIi % II111iiii + I11i
  if 45 - 45: iII111i / iII111i + I1Ii111 + ooOoO0o
 iI111i = "{} configured map-servers" . format ( len ( lisp . lisp_map_servers_list ) )
 IIi11i1i1iI1 = "LISP-ETR Configured Map-Servers{}" . format ( i1I1iI1iIi111i )
 IIi11i1i1iI1 = lisp . lisp_span ( IIi11i1i1iI1 , iI111i )
 if 23 - 23: i11iIiiIii + o0oOOo0O0Ooo . i1IIi
 iI111i = ( "P = proxy-reply requested, M = merge-registrations " + "requested, N = Map-Notify requested" )
 if 100 - 100: I1Ii111 . oO0o * Ii1I
 i1i1Iiii1I1 = lisp . lisp_span ( "Registration<br>flags" , iI111i )
 if 53 - 53: II111iiii
 oo0o00O += lispconfig . lisp_table_header ( IIi11i1i1iI1 , "Address" , "Auth-Type" ,
 "xTR-ID" , "Site-ID" , i1i1Iiii1I1 , "Map-Registers<br>Sent" ,
 "Map-Notifies<br>Received" )
 if 31 - 31: OoO0O00
 for Oo00OOOOO in list ( lisp . lisp_map_servers_list . values ( ) ) :
  Oo00OOOOO . resolve_dns_name ( )
  o0O = "" if Oo00OOOOO . ms_name == "all" else Oo00OOOOO . ms_name + "<br>"
  IiIIii1iII1II = o0O + Oo00OOOOO . map_server . print_address_no_iid ( )
  if ( Oo00OOOOO . dns_name ) : IiIIii1iII1II += "<br>" + Oo00OOOOO . dns_name
  if 48 - 48: II111iiii * Ii1I . I11i + oO0o
  OoO0o = "0x" + lisp . lisp_hex_string ( Oo00OOOOO . xtr_id )
  oO0o0Ooooo = "{}-{}-{}-{}" . format ( "P" if Oo00OOOOO . proxy_reply else "p" ,
 "M" if Oo00OOOOO . merge_registrations else "m" ,
 "N" if Oo00OOOOO . want_map_notify else "n" ,
 "R" if Oo00OOOOO . refresh_registrations else "r" )
  if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
  oO0 = Oo00OOOOO . map_registers_sent + Oo00OOOOO . map_registers_multicast_sent
  if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
  if 55 - 55: OOooOOo . I1IiiI
  oo0o00O += lispconfig . lisp_table_row ( IiIIii1iII1II ,
 "sha1" if ( Oo00OOOOO . alg_id == lisp . LISP_SHA_1_96_ALG_ID ) else "sha2" ,
 OoO0o , Oo00OOOOO . site_id , oO0o0Ooooo , oO0 ,
 Oo00OOOOO . map_notifies_received )
  if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
 oo0o00O += lispconfig . lisp_table_footer ( )
 if 100 - 100: I1Ii111 * O0
 if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
 if 79 - 79: O0
 if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
 oo0o00O = lispconfig . lisp_show_db_list ( "ETR" , oo0o00O )
 if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 if 57 - 57: OoO0O00 / ooOoO0o
 if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
 if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
 if ( len ( lisp . lisp_elp_list ) != 0 ) :
  oo0o00O = lispconfig . lisp_show_elp_list ( oo0o00O )
  if 13 - 13: Ii1I . i11iIiiIii
  if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
  if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
  if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
  if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if ( len ( lisp . lisp_rle_list ) != 0 ) :
  oo0o00O = lispconfig . lisp_show_rle_list ( oo0o00O )
  if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
  if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
  if 63 - 63: OoOoOO00 * iII111i
  if 69 - 69: O0 . OoO0O00
  if 49 - 49: I1IiiI - I11i
 if ( len ( lisp . lisp_json_list ) != 0 ) :
  oo0o00O = lispconfig . lisp_show_json_list ( oo0o00O )
  if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
  if 62 - 62: OoooooooOO * I1IiiI
  if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
  if 97 - 97: O0 + OoOoOO00
 if ( len ( lisp . lisp_group_mapping_list ) != 0 ) :
  IIi11i1i1iI1 = "Configured Group Mappings:"
  oo0o00O += lispconfig . lisp_table_header ( IIi11i1i1iI1 , "Name" , "Group Prefix" ,
 "Sources" , "Use MS" )
  for OO0O000 in list ( lisp . lisp_group_mapping_list . values ( ) ) :
   iiIiI1i1 = ""
   for oO0O00oOOoooO in OO0O000 . sources : iiIiI1i1 += oO0O00oOOoooO + ", "
   if ( iiIiI1i1 == "" ) :
    iiIiI1i1 = "*"
   else :
    iiIiI1i1 = iiIiI1i1 [ 0 : - 2 ]
    if 46 - 46: I1IiiI - OoooooooOO - I11i * II111iiii
   oo0o00O += lispconfig . lisp_table_row ( OO0O000 . group_name ,
 OO0O000 . group_prefix . print_prefix ( ) , iiIiI1i1 , OO0O000 . use_ms_name )
   if 34 - 34: I11i - iII111i / OOooOOo + I1ii11iIi11i * Ii1I
  oo0o00O += lispconfig . lisp_table_footer ( )
  if 73 - 73: OoOoOO00 . Ii1I * I1ii11iIi11i % I1ii11iIi11i % OoooooooOO
 return ( oo0o00O )
 if 63 - 63: iIii1I11I1II1 * i11iIiiIii % iIii1I11I1II1 * i11iIiiIii
 if 32 - 32: OOooOOo
 if 42 - 42: IiII * O0 % i1IIi . OOooOOo / o0oOOo0O0Ooo
 if 32 - 32: I1IiiI * Oo0Ooo
 if 78 - 78: OOooOOo - OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii
 if 29 - 29: I1IiiI % I1IiiI
 if 94 - 94: iIii1I11I1II1 / Oo0Ooo % iII111i * iII111i * II111iiii
def IIiIiI ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "ETR" ) )
 if 94 - 94: oO0o . i1IIi - o0oOOo0O0Ooo % O0 - OoO0O00
 if 72 - 72: Ii1I
 if 1 - 1: OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
def o00Oo0oooooo ( kv_pairs ) :
 iiIiI1i1 = [ ]
 O0oO0 = None
 iII11 = None
 o0O = "all"
 if 32 - 32: I1Ii111
 for Iii1 in list ( kv_pairs . keys ( ) ) :
  oOOOoo00 = kv_pairs [ Iii1 ]
  if ( Iii1 == "group-name" ) :
   iiIiIIIiiI = oOOOoo00
   if 12 - 12: O0 - o0oOOo0O0Ooo
  if ( Iii1 == "group-prefix" ) :
   if ( O0oO0 == None ) :
    O0oO0 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
   O0oO0 . store_prefix ( oOOOoo00 )
   if 73 - 73: I11i % i11iIiiIii - I1IiiI
  if ( Iii1 == "instance-id" ) :
   if ( O0oO0 == None ) :
    O0oO0 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
   O0oO0 . instance_id = int ( oOOOoo00 )
   if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
  if ( Iii1 == "ms-name" ) :
   o0O = oOOOoo00 [ 0 ]
   if 23 - 23: i11iIiiIii
  if ( Iii1 == "address" ) :
   for II1iIi11 in oOOOoo00 :
    if ( II1iIi11 != "" ) : iiIiI1i1 . append ( II1iIi11 )
    if 12 - 12: Ii1I + i11iIiiIii * iIii1I11I1II1 / I1ii11iIi11i . I11i
    if 5 - 5: i1IIi + IiII / o0oOOo0O0Ooo . iII111i / I11i
  if ( Iii1 == "rle-address" ) :
   if ( iII11 == None ) :
    iII11 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 32 - 32: I1IiiI % iIii1I11I1II1 / i1IIi - I1IiiI
   iII11 . store_address ( oOOOoo00 )
   if 7 - 7: I1Ii111 * OoO0O00 - ooOoO0o + OOooOOo * I1IiiI % OoO0O00
   if 15 - 15: OoOoOO00 % I1IiiI * I11i
 OO0O000 = lisp . lisp_group_mapping ( iiIiIIIiiI , o0O , O0oO0 , iiIiI1i1 ,
 iII11 )
 OO0O000 . add_group ( )
 return
 if 81 - 81: ooOoO0o - iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * I11i
 if 20 - 20: oO0o % IiII
 if 19 - 19: I1ii11iIi11i % IiII + ooOoO0o / I1Ii111 . ooOoO0o
 if 12 - 12: i1IIi + i1IIi - I1ii11iIi11i * Oo0Ooo % Oo0Ooo - II111iiii
 if 52 - 52: ooOoO0o . iII111i + I1Ii111
 if 38 - 38: i1IIi - II111iiii . I1Ii111
 if 58 - 58: I1IiiI . iII111i + OoOoOO00
def O00OO ( quiet , db , eid , group , ttl ) :
 if 17 - 17: I11i / I1Ii111 + oO0o - i11iIiiIii . iII111i
 if 95 - 95: OoO0O00 % i1IIi * i11iIiiIii % Oo0Ooo - oO0o
 if 67 - 67: OoOoOO00 + I1ii11iIi11i . o0oOOo0O0Ooo . II111iiii
 if 98 - 98: iII111i
 if 68 - 68: iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
 if 38 - 38: ooOoO0o - OOooOOo / iII111i
 if 66 - 66: O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / Ii1I + I1ii11iIi11i
 if 86 - 86: o0oOOo0O0Ooo
 i1Iii11Ii1i1 = { }
 for OOooo0O0o0 in db . rloc_set :
  if ( OOooo0O0o0 . translated_rloc . is_null ( ) ) : continue
  if 14 - 14: o0oOOo0O0Ooo % O0 * iII111i + Ii1I + Oo0Ooo * Ii1I
  for iII1I1IiI11ii in lisp . lisp_rtr_list :
   OooooOoooO = lisp . lisp_rtr_list [ iII1I1IiI11ii ]
   if ( lisp . lisp_register_all_rtrs == False and OooooOoooO == None ) :
    lisp . lprint ( "  Exclude unreachable RTR {}" . format ( lisp . red ( iII1I1IiI11ii , False ) ) )
    if 56 - 56: Oo0Ooo . I1ii11iIi11i . I1IiiI
    continue
    if 39 - 39: O0 + I1Ii111
   if ( OooooOoooO == None ) : continue
   i1Iii11Ii1i1 [ iII1I1IiI11ii ] = OooooOoooO
   if 91 - 91: OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoOoOO00 + O0
  break
  if 26 - 26: I1ii11iIi11i - OoooooooOO
  if 11 - 11: I1IiiI * oO0o
 o000oo = 0
 o00o0 = b""
 for II1I in [ eid . instance_id ] + eid . iid_list :
  II1I1I1Ii = lisp . lisp_eid_record ( )
  if 70 - 70: OoO0O00 % oO0o + OOooOOo / Ii1I % O0
  II1I1I1Ii . rloc_count = len ( db . rloc_set ) + len ( i1Iii11Ii1i1 )
  II1I1I1Ii . authoritative = True
  II1I1I1Ii . record_ttl = ttl
  II1I1I1Ii . eid . copy_address ( eid )
  II1I1I1Ii . eid . instance_id = II1I
  II1I1I1Ii . eid . iid_list = [ ]
  II1I1I1Ii . group . copy_address ( group )
  if 100 - 100: o0oOOo0O0Ooo + OOooOOo * o0oOOo0O0Ooo
  o00o0 += II1I1I1Ii . encode ( )
  if ( not quiet ) :
   oOOo0OOOo00O = lisp . lisp_print_eid_tuple ( eid , group )
   OooOOOO = ""
   if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
    OooOOOO = lisp . lisp_get_decent_index ( eid )
    OooOOOO = lisp . bold ( str ( OooOOOO ) , False )
    OooOOOO = ", decent-index {}" . format ( OooOOOO )
    if 45 - 45: I1ii11iIi11i % I1IiiI - i11iIiiIii
   lisp . lprint ( "  EID-prefix {} for ms-name '{}'{}" . format ( lisp . green ( oOOo0OOOo00O , False ) , db . use_ms_name , OooOOOO ) )
   if 11 - 11: iIii1I11I1II1 * iIii1I11I1II1 * I1IiiI
   II1I1I1Ii . print_record ( "  " , False )
   if 46 - 46: OoOoOO00 + OoO0O00
   if 70 - 70: iII111i / iIii1I11I1II1
  for OOooo0O0o0 in db . rloc_set :
   Oo0oooO0oO = lisp . lisp_rloc_record ( )
   Oo0oooO0oO . store_rloc_entry ( OOooo0O0o0 )
   Oo0oooO0oO . local_bit = OOooo0O0o0 . rloc . is_local ( )
   Oo0oooO0oO . reach_bit = True
   o00o0 += Oo0oooO0oO . encode ( )
   if ( not quiet ) : Oo0oooO0oO . print_record ( "    " )
   if 19 - 19: i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
   if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
   if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
   if 71 - 71: O0 - iIii1I11I1II1
   if 12 - 12: OOooOOo / o0oOOo0O0Ooo
   if 42 - 42: Oo0Ooo
  for OooooOoooO in list ( i1Iii11Ii1i1 . values ( ) ) :
   Oo0oooO0oO = lisp . lisp_rloc_record ( )
   Oo0oooO0oO . rloc . copy_address ( OooooOoooO )
   Oo0oooO0oO . priority = 254
   Oo0oooO0oO . rloc_name = "RTR"
   Oo0oooO0oO . weight = 0
   Oo0oooO0oO . mpriority = 255
   Oo0oooO0oO . mweight = 0
   Oo0oooO0oO . local_bit = False
   Oo0oooO0oO . reach_bit = True
   o00o0 += Oo0oooO0oO . encode ( )
   if ( not quiet ) : Oo0oooO0oO . print_record ( "    RTR " )
   if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
   if 46 - 46: Oo0Ooo
   if 1 - 1: iII111i
   if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
   if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
  o000oo += 1
  if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
 return ( o00o0 , o000oo )
 if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
 if 17 - 17: i1IIi
 if 21 - 21: Oo0Ooo
 if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
def o00O ( lisp_sockets , ttl , eid_only , ms_only , refresh ) :
 if 54 - 54: i1IIi + II111iiii
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 if 5 - 5: Ii1I
 if 46 - 46: IiII
 if ( eid_only != None ) :
  ii1iIi1iIiI1i = 1
 else :
  ii1iIi1iIiI1i = lisp . lisp_db_list_length ( )
  if ( ii1iIi1iIiI1i == 0 ) : return
  if 40 - 40: i1IIi % OOooOOo
  if 71 - 71: OoOoOO00
 if ( O0OoOoo00o ) :
  lisp . lprint ( "Build Map-Register for {} database-mapping entries" . format ( ii1iIi1iIiI1i ) )
  if 14 - 14: i11iIiiIii % OOooOOo
 else :
  lisp . lprint ( "Build Map-Register for {} database-mapping entries" . format ( ii1iIi1iIiI1i ) )
  if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
  if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
  if 9 - 9: Ii1I
  if 59 - 59: I1IiiI * II111iiii . O0
  if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
  if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 Oo0OO0000oooo = lisp . lisp_decent_pull_xtr_configured ( )
 if 7 - 7: oO0o - OoO0O00 - O0 % oO0o - II111iiii
 if 31 - 31: iII111i / Oo0Ooo - iII111i - OOooOOo
 if 7 - 7: iII111i % O0 . OoOoOO00 + I1IiiI - I11i
 if 75 - 75: I11i
 oO00oo0o00o0o = ( ii1iIi1iIiI1i > 12 )
 if 7 - 7: O0 - Oo0Ooo + I1ii11iIi11i + II111iiii + iIii1I11I1II1
 OOo0 = { }
 if ( Oo0OO0000oooo ) :
  if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
  if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
  if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
  if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
  if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
  for I11OoOoOOOoOO in lisp . lisp_db_list :
   OoOoOo00o0 = I11OoOoOOOoOO . eid if I11OoOoOOOoOO . group . is_null ( ) else I11OoOoOOOoOO . group
   OO0ooo0oOO = lisp . lisp_get_decent_dns_name ( OoOoOo00o0 )
   OOo0 [ OO0ooo0oOO ] = [ ]
   if 97 - 97: I1IiiI / iII111i
 else :
  if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
  if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
  if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
  if 100 - 100: OoO0O00
  if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
  for Oo00OOOOO in list ( lisp . lisp_map_servers_list . values ( ) ) :
   if ( ms_only != None and Oo00OOOOO != ms_only ) : continue
   OOo0 [ Oo00OOOOO . ms_name ] = [ ]
   if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
   if 45 - 45: I1Ii111
   if 83 - 83: OoOoOO00 . OoooooooOO
   if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
   if 62 - 62: OoO0O00 / I1ii11iIi11i
   if 7 - 7: OoooooooOO . IiII
 O000OOO0OOo = lisp . lisp_map_register ( )
 O000OOO0OOo . nonce = 0xaabbccdddfdfdf00
 O000OOO0OOo . xtr_id_present = True
 O000OOO0OOo . use_ttl_for_timeout = True
 if 32 - 32: Ii1I * O0
 if ( ttl == None ) : ttl = lisp . LISP_REGISTER_TTL
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
 if 92 - 92: ooOoO0o
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 iIi1 = 65000 if ( O0OoOoo00o ) else 1100
 for I11OoOoOOOoOO in lisp . lisp_db_list :
  if ( Oo0OO0000oooo ) :
   i11iiI1111 = lisp . lisp_get_decent_dns_name ( I11OoOoOOOoOO . eid )
  else :
   i11iiI1111 = I11OoOoOOOoOO . use_ms_name
   if 97 - 97: Oo0Ooo * I1IiiI . iIii1I11I1II1
   if 16 - 16: ooOoO0o % OoooooooOO - OOooOOo * Ii1I * I1ii11iIi11i / OoooooooOO
   if 31 - 31: I11i . I1Ii111 * ooOoO0o + i11iIiiIii * oO0o
   if 93 - 93: I1ii11iIi11i / iIii1I11I1II1 * i1IIi % OoooooooOO * O0 * I11i
   if 64 - 64: II111iiii + O0 / iIii1I11I1II1 / Oo0Ooo . ooOoO0o % IiII
   if 50 - 50: iIii1I11I1II1 - IiII + OOooOOo
  if ( i11iiI1111 not in OOo0 ) : continue
  if 69 - 69: O0
  o0ooO = OOo0 [ i11iiI1111 ]
  if ( o0ooO == [ ] ) :
   o0ooO = [ b"" , 0 ]
   OOo0 [ i11iiI1111 ] . append ( o0ooO )
  else :
   o0ooO = OOo0 [ i11iiI1111 ] [ - 1 ]
   if 74 - 74: O0 * oO0o - i11iIiiIii + I1Ii111
   if 17 - 17: iIii1I11I1II1 . OoooooooOO / I11i % II111iiii % i1IIi / i11iIiiIii
   if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
   if 85 - 85: OoOoOO00 + OOooOOo
   if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
   if 27 - 27: Ii1I
   if 67 - 67: I1IiiI
   if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
   if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
   if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
  o00o0 = b""
  if ( I11OoOoOOOoOO . dynamic_eid_configured ( ) ) :
   for oOooO0 in list ( I11OoOoOOOoOO . dynamic_eids . values ( ) ) :
    OoOoOo00o0 = oOooO0 . dynamic_eid
    if ( eid_only == None or eid_only . is_exact_match ( OoOoOo00o0 ) ) :
     OOOoO000 , o000oo = O00OO ( oO00oo0o00o0o , I11OoOoOOOoOO ,
 OoOoOo00o0 , I11OoOoOOOoOO . group , ttl )
     o00o0 += OOOoO000
     o0ooO [ 1 ] += o000oo
     if 57 - 57: II111iiii
     if 54 - 54: Oo0Ooo + oO0o + i11iIiiIii
  else :
   if ( eid_only == None ) :
    if ( ttl != 0 ) : ttl = I11OoOoOOOoOO . register_ttl
    o00o0 , o000oo = O00OO ( oO00oo0o00o0o , I11OoOoOOOoOO ,
 I11OoOoOOOoOO . eid , I11OoOoOOOoOO . group , ttl )
    o0ooO [ 1 ] += o000oo
    if 28 - 28: oO0o
    if 70 - 70: IiII
    if 34 - 34: I1Ii111 % IiII
    if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
    if 83 - 83: oO0o + OoooooooOO
    if 22 - 22: Ii1I % iII111i * OoooooooOO - o0oOOo0O0Ooo / iIii1I11I1II1
  o0ooO [ 0 ] += o00o0
  if 86 - 86: OoooooooOO . iII111i % OoOoOO00 / I11i * iII111i / o0oOOo0O0Ooo
  if ( o0ooO [ 1 ] == 20 or len ( o0ooO [ 0 ] ) > iIi1 ) :
   o0ooO = [ b"" , 0 ]
   OOo0 [ i11iiI1111 ] . append ( o0ooO )
   if 64 - 64: i11iIiiIii
   if 38 - 38: IiII / I1IiiI - IiII . I11i
   if 69 - 69: OoooooooOO + I1ii11iIi11i
   if 97 - 97: OOooOOo - OoO0O00 / Ii1I . i11iIiiIii % oO0o * oO0o
   if 1 - 1: I1IiiI % ooOoO0o
   if 65 - 65: I1IiiI + OoOoOO00 / OOooOOo
 oOO = .500 if ( O0OoOoo00o ) else .001
 o000oo = 0
 for Oo00OOOOO in list ( lisp . lisp_map_servers_list . values ( ) ) :
  if ( ms_only != None and Oo00OOOOO != ms_only ) : continue
  if 85 - 85: oO0o - iIii1I11I1II1 / O0
  i11iiI1111 = Oo00OOOOO . dns_name if Oo0OO0000oooo else Oo00OOOOO . ms_name
  if ( i11iiI1111 not in OOo0 ) : continue
  if 99 - 99: II111iiii * IiII % iIii1I11I1II1 / Ii1I
  for o0ooO in OOo0 [ i11iiI1111 ] :
   if 90 - 90: oO0o % OOooOOo - OOooOOo % II111iiii * OoO0O00
   if 39 - 39: I11i
   if 58 - 58: i1IIi % o0oOOo0O0Ooo
   if 79 - 79: o0oOOo0O0Ooo % iII111i * OoooooooOO * iIii1I11I1II1 . iII111i / Ii1I
   O000OOO0OOo . record_count = o0ooO [ 1 ]
   if ( O000OOO0OOo . record_count == 0 ) : continue
   if 19 - 19: O0 + I11i + Ii1I / II111iiii / II111iiii
   O000OOO0OOo . nonce += 1
   O000OOO0OOo . alg_id = Oo00OOOOO . alg_id
   O000OOO0OOo . key_id = Oo00OOOOO . key_id
   O000OOO0OOo . proxy_reply_requested = Oo00OOOOO . proxy_reply
   O000OOO0OOo . merge_register_requested = Oo00OOOOO . merge_registrations
   O000OOO0OOo . map_notify_requested = Oo00OOOOO . want_map_notify
   O000OOO0OOo . xtr_id = Oo00OOOOO . xtr_id
   O000OOO0OOo . site_id = Oo00OOOOO . site_id
   O000OOO0OOo . encrypt_bit = ( Oo00OOOOO . ekey != None )
   if ( Oo00OOOOO . refresh_registrations ) :
    O000OOO0OOo . map_register_refresh = refresh
    if 86 - 86: I1ii11iIi11i * O0 * IiII
   if ( Oo00OOOOO . ekey != None ) : O000OOO0OOo . encryption_key_id = Oo00OOOOO . ekey_id
   Ooo0oo = O000OOO0OOo . encode ( )
   O000OOO0OOo . print_map_register ( )
   if 41 - 41: OoOoOO00 * I11i / OoOoOO00 % oO0o
   if 18 - 18: II111iiii . OoooooooOO % OoOoOO00 % Ii1I
   if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
   if 2 - 2: OoooooooOO % OOooOOo
   if 63 - 63: I1IiiI % iIii1I11I1II1
   I1ii = O000OOO0OOo . encode_xtr_id ( b"" )
   o00o0 = o0ooO [ 0 ]
   Ooo0oo = Ooo0oo + o00o0 + I1ii
   if 73 - 73: IiII + I1IiiI * Oo0Ooo * OoooooooOO
   Oo00OOOOO . map_registers_sent += 1
   lisp . lisp_send_map_register ( lisp_sockets , Ooo0oo , O000OOO0OOo , Oo00OOOOO )
   if 95 - 95: i1IIi + iIii1I11I1II1 % I1ii11iIi11i % Oo0Ooo / i11iIiiIii - IiII
   o000oo += 1
   if ( o000oo % 100 == 0 and O0OoOoo00o ) :
    oOO += .1
    lisp . fprint ( "Sent {} Map-Registers, ipd {}" . format ( o000oo ,
 oOO ) )
    if 26 - 26: ooOoO0o . OOooOOo - OOooOOo . OoO0O00
   time . sleep ( oOO )
   if 39 - 39: OoooooooOO + oO0o % OOooOOo / OOooOOo
   if 27 - 27: iII111i . I11i . iIii1I11I1II1 . iIii1I11I1II1
  if ( O0OoOoo00o ) :
   lisp . fprint ( "Sent total {} Map-Registers" . format ( o000oo ) )
   if 20 - 20: o0oOOo0O0Ooo / i1IIi
   if 71 - 71: OoOoOO00 . i1IIi
   if 94 - 94: OOooOOo . I1Ii111
   if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
   if 47 - 47: OoooooooOO
  Oo00OOOOO . resolve_dns_name ( )
  if 4 - 4: I1IiiI % I11i
  if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
  if 82 - 82: ooOoO0o + II111iiii
  if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
  if 68 - 68: Oo0Ooo + i11iIiiIii
  if ( ms_only != None and Oo00OOOOO == ms_only ) : break
  if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
 return
 if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
 if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
 if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
 if 98 - 98: i1IIi
 if 65 - 65: OoOoOO00 / OoO0O00 % IiII
 if 45 - 45: OoOoOO00
 if 66 - 66: OoO0O00
 if 56 - 56: O0
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
def i1iiI11I ( ms ) :
 global Ii1iI
 global Oo
 if 23 - 23: oO0o - OOooOOo + I11i
 lisp . lisp_set_exception ( )
 if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
 if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
 if 11 - 11: iII111i * Ii1I - OoOoOO00
 if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
 if 74 - 74: Oo0Ooo
 OO000o00 = [ Oo , Oo , Ooo ]
 lisp . lisp_build_info_requests ( OO000o00 , ms , lisp . LISP_CTRL_PORT )
 if 46 - 46: OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 Ii1i1i1111 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) == None )
 for OooooOoooO in list ( lisp . lisp_rtr_list . values ( ) ) :
  if ( OooooOoooO == None ) : continue
  if ( OooooOoooO . is_private_address ( ) and Ii1i1i1111 == False ) :
   o0oO0O00oOo = lisp . red ( OooooOoooO . print_address_no_iid ( ) , False )
   lisp . lprint ( "Skip over RTR private address {}" . format ( o0oO0O00oOo ) )
   continue
   if 26 - 26: IiII % I1Ii111 % oO0o % Ii1I
  lisp . lisp_build_info_requests ( OO000o00 , OooooOoooO , lisp . LISP_DATA_PORT )
  if 55 - 55: ooOoO0o % OoooooooOO / OoooooooOO % OoooooooOO
  if 52 - 52: I1ii11iIi11i + I1ii11iIi11i . II111iiii
  if 34 - 34: OoooooooOO . O0 / oO0o * OoOoOO00 - I1ii11iIi11i
  if 36 - 36: i1IIi / O0 / OoO0O00 - O0 - i1IIi
  if 22 - 22: i1IIi + Ii1I
 for O0o0O0OO00o in O0O00Ooo :
  OOo00O = O0O00Ooo [ O0o0O0OO00o ]
  lisp . lprint ( "Send NAT-Probe to ETR {}" . format ( O0o0O0OO00o ) )
  lisp . lisp_send_info_request ( OO000o00 , OOo00O , lisp . LISP_DATA_PORT , None )
  if 81 - 81: IiII . o0oOOo0O0Ooo / I1Ii111
  if 17 - 17: i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + I11i - ooOoO0o
  if 78 - 78: I11i * OoOoOO00 . O0 / O0
  if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
  if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
  if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
 Ii1iI . cancel ( )
 Ii1iI = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 i1iiI11I , [ None ] )
 Ii1iI . start ( )
 return
 if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
 if 91 - 91: oO0o + OoooooooOO - i1IIi
 if 84 - 84: Ii1I / IiII
 if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if 37 - 37: i11iIiiIii + i1IIi
def oo000OO00Oo ( lisp_sockets ) :
 global Oo0o , OOO0o0o
 global Oo
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 lisp . lisp_set_exception ( )
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 if 8 - 8: o0oOOo0O0Ooo
 if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
 if 78 - 78: Ii1I / II111iiii % OoOoOO00
 o00O ( lisp_sockets , None , None , None , True )
 if 52 - 52: OOooOOo - iII111i * oO0o
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
 if 36 - 36: O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if ( lisp . lisp_l2_overlay ) :
  I11iIiII = [ None , "ffff-ffff-ffff" , True ]
  OO0OO0OO ( lisp_sockets , [ I11iIiII ] )
  if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
  if 72 - 72: i1IIi
  if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
  if 63 - 63: I1ii11iIi11i
  if 6 - 6: ooOoO0o / I1ii11iIi11i
  if 57 - 57: I11i
 if ( OOO0o0o != None ) :
  OOO0o0o . cancel ( )
  OOO0o0o = None
  if 67 - 67: OoO0O00 . ooOoO0o
  if 87 - 87: oO0o % Ii1I
  if 83 - 83: II111iiii - I11i
  if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
  if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 if ( Oo0o ) : Oo0o . cancel ( )
 Oo0o = threading . Timer ( I11 ,
 oo000OO00Oo , [ o0oOoO00o ] )
 Oo0o . start ( )
 return
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
def OO0OO0OO ( lisp_sockets , entries ) :
 oo = len ( entries )
 if ( oo == 0 ) : return
 if 9 - 9: Oo0Ooo
 O0O00OOo = None
 if ( entries [ 0 ] [ 1 ] . find ( ":" ) != - 1 ) : O0O00OOo = lisp . LISP_AFI_IPV6
 if ( entries [ 0 ] [ 1 ] . find ( "." ) != - 1 ) : O0O00OOo = lisp . LISP_AFI_IPV4
 if ( entries [ 0 ] [ 1 ] . find ( "-" ) != - 1 ) : O0O00OOo = lisp . LISP_AFI_MAC
 if ( O0O00OOo == None ) :
  lisp . lprint ( "lisp_send_multicast_map_register() invalid group address" )
  return
  if 66 - 66: i11iIiiIii / o0oOOo0O0Ooo - OoooooooOO / i1IIi . i11iIiiIii
  if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
  if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
  if 81 - 81: iII111i * OOooOOo - I1ii11iIi11i * Ii1I % OoOoOO00 * OoOoOO00
  if 59 - 59: iIii1I11I1II1
  if 7 - 7: OOooOOo * I1IiiI / o0oOOo0O0Ooo * i11iIiiIii
  if 84 - 84: OOooOOo . iII111i
  if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
  if 21 - 21: oO0o / OoooooooOO
 III1IiIII1 = [ ]
 for II1iIi11 , O00ooOo , oOO0o00O in entries :
  if 69 - 69: i1IIi
  III1IiIII1 . append ( [ O00ooOo , oOO0o00O ] )
  if 59 - 59: II111iiii - o0oOOo0O0Ooo
  if 24 - 24: Oo0Ooo - i1IIi + I11i
 Oo0OO0000oooo = lisp . lisp_decent_pull_xtr_configured ( )
 if 38 - 38: OoooooooOO / I1ii11iIi11i . O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
 OOo0 = { }
 entries = [ ]
 for O00ooOo , oOO0o00O in III1IiIII1 :
  ooO00O00oOO = lisp . lisp_lookup_group ( O00ooOo )
  if ( ooO00O00oOO == None ) :
   lisp . lprint ( "No group-mapping for {}, could be underlay group" . format ( O00ooOo ) )
   if 40 - 40: iII111i . oO0o + I1IiiI + I1ii11iIi11i + I1Ii111
   continue
   if 26 - 26: iIii1I11I1II1
   if 87 - 87: I1ii11iIi11i / OoooooooOO - Oo0Ooo % OoOoOO00 % IiII % Oo0Ooo
  lisp . lprint ( "Use group-mapping '{}' {} for group {}" . format ( ooO00O00oOO . group_name , ooO00O00oOO . group_prefix . print_prefix ( ) , O00ooOo ) )
  if 29 - 29: OoooooooOO . I1IiiI % I1ii11iIi11i - iII111i
  if 8 - 8: i1IIi
  II1I = ooO00O00oOO . group_prefix . instance_id
  o0O = ooO00O00oOO . use_ms_name
  iIiI1 = ooO00O00oOO . rle_address
  if 37 - 37: OoO0O00 * i11iIiiIii / OOooOOo % I1Ii111
  if 71 - 71: OoooooooOO
  if 11 - 11: IiII
  if 55 - 55: Oo0Ooo
  if 77 - 77: II111iiii
  if 16 - 16: I1IiiI * II111iiii / iIii1I11I1II1 - iII111i
  IiI1IiI11iII = o0O
  if ( Oo0OO0000oooo ) :
   IiI1IiI11iII = lisp . lisp_get_decent_dns_name_from_str ( II1I , O00ooOo )
   OOo0 [ IiI1IiI11iII ] = [ b"" , 0 ]
   if 64 - 64: oO0o - I1IiiI / iII111i - OoO0O00
   if 37 - 37: i11iIiiIii / iII111i
  if ( len ( ooO00O00oOO . sources ) == 0 ) :
   entries . append ( [ "0.0.0.0" , O00ooOo , II1I , IiI1IiI11iII , iIiI1 , oOO0o00O ] )
   continue
   if 85 - 85: i11iIiiIii + I1Ii111 * OoOoOO00
  for oO0O00oOOoooO in ooO00O00oOO . sources :
   OOo0 [ IiI1IiI11iII ] = [ b"" , 0 ]
   entries . append ( [ oO0O00oOOoooO , O00ooOo , II1I , IiI1IiI11iII , iIiI1 , oOO0o00O ] )
   if 1 - 1: i1IIi / Oo0Ooo . OoO0O00
   if 57 - 57: I11i . Oo0Ooo + II111iiii
   if 43 - 43: I1Ii111 % iII111i
 oo = len ( entries )
 if ( oo == 0 ) : return
 if 69 - 69: iII111i % OoO0O00
 lisp . lprint ( "Build Map-Register for {} multicast entries" . format ( oo ) )
 if 86 - 86: oO0o / oO0o
 if 28 - 28: i11iIiiIii / o0oOOo0O0Ooo . iIii1I11I1II1 / II111iiii
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
 oo00ooOoo = lisp . lisp_rle_node ( )
 oo00ooOoo . level = 128
 iii1IIIiiiI = lisp . lisp_get_any_translated_rloc ( )
 iIiI1 = lisp . lisp_rle ( "" )
 iIiI1 . rle_nodes . append ( oo00ooOoo )
 if 94 - 94: O0 - I11i - iIii1I11I1II1 % ooOoO0o / Ii1I % iII111i
 if 44 - 44: Oo0Ooo % iIii1I11I1II1
 if 90 - 90: II111iiii + OoooooooOO % OoooooooOO
 if 35 - 35: iII111i / I1ii11iIi11i * OoooooooOO . II111iiii / Oo0Ooo
 if 1 - 1: OoooooooOO + IiII . i1IIi % I11i
 if 66 - 66: o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
 if ( Oo0OO0000oooo == False ) :
  for Oo00OOOOO in list ( lisp . lisp_map_servers_list . values ( ) ) :
   OOo0 [ Oo00OOOOO . ms_name ] = [ b"" , 0 ]
   if 12 - 12: iII111i . IiII . OoOoOO00 / O0
   if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
   if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
 i1i1IiIiIi1Ii = None
 if ( lisp . lisp_nat_traversal ) : i1i1IiIiIi1Ii = lisp . lisp_hostname
 if 64 - 64: OOooOOo + OoooooooOO * OoooooooOO
 if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
 if 100 - 100: Ii1I + OoO0O00
 if 73 - 73: i1IIi - I1Ii111 % ooOoO0o / OoO0O00
 III1iii1i11iI = 0
 for OooooOoooO in list ( lisp . lisp_rtr_list . values ( ) ) :
  if ( OooooOoooO == None ) : continue
  III1iii1i11iI += 1
  if 56 - 56: i11iIiiIii . iIii1I11I1II1 + I1ii11iIi11i + iII111i / Oo0Ooo . I1Ii111
  if 74 - 74: OoooooooOO % OOooOOo % I1Ii111 - I1IiiI - I11i
  if 58 - 58: O0
  if 78 - 78: OoO0O00 % IiII * i1IIi
  if 66 - 66: Ii1I . I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1
 o00o0 = b""
 for II1iIi11 , O00ooOo , II1I , i11iiI1111 , o0 , oOO0o00O in entries :
  if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
  if 14 - 14: I1ii11iIi11i
  if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
  if 56 - 56: OoooooooOO - I11i - i1IIi
  if ( i11iiI1111 not in OOo0 ) : continue
  if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
  II1I1I1Ii = lisp . lisp_eid_record ( )
  II1I1I1Ii . rloc_count = 1 + III1iii1i11iI
  II1I1I1Ii . authoritative = True
  II1I1I1Ii . record_ttl = lisp . LISP_REGISTER_TTL if oOO0o00O else 0
  II1I1I1Ii . eid = lisp . lisp_address ( O0O00OOo , II1iIi11 , 0 , II1I )
  if ( II1I1I1Ii . eid . address == 0 ) : II1I1I1Ii . eid . mask_len = 0
  II1I1I1Ii . group = lisp . lisp_address ( O0O00OOo , O00ooOo , 0 , II1I )
  if ( II1I1I1Ii . group . is_mac_broadcast ( ) and II1I1I1Ii . eid . address == 0 ) : II1I1I1Ii . eid . mask_len = 0
  if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
  if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
  OooOOOO = ""
  o0O = ""
  if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
   OooOOOO = lisp . lisp_get_decent_index ( II1I1I1Ii . group )
   OooOOOO = lisp . bold ( str ( OooOOOO ) , False )
   OooOOOO = "with decent-index {}" . format ( OooOOOO )
  else :
   OooOOOO = "for ms-name '{}'" . format ( i11iiI1111 )
   if 53 - 53: I11i + iIii1I11I1II1
   if 70 - 70: I1ii11iIi11i
  oo0O = lisp . green ( II1I1I1Ii . print_eid_tuple ( ) , False )
  lisp . lprint ( "  EID-prefix {} {}{}" . format ( oo0O , o0O ,
 OooOOOO ) )
  if 6 - 6: Oo0Ooo . IiII / IiII - i11iIiiIii
  o00o0 += II1I1I1Ii . encode ( )
  II1I1I1Ii . print_record ( "  " , False )
  OOo0 [ i11iiI1111 ] [ 1 ] += 1
  if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
  if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
  if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
  if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
  Oo0oooO0oO = lisp . lisp_rloc_record ( )
  Oo0oooO0oO . rloc_name = i1i1IiIiIi1Ii
  if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
  if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
  if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
  if 77 - 77: OoO0O00 + I1Ii111 + I1Ii111 * Ii1I / OoooooooOO . Ii1I
  if 62 - 62: i1IIi - i1IIi
  if 69 - 69: OoOoOO00 % oO0o - I11i
  if ( iii1IIIiiiI != None ) :
   oo00ooOoo . address = iii1IIIiiiI
  elif ( o0 != None ) :
   oo00ooOoo . address = o0
  else :
   oo00ooOoo . address = o0 = lisp . lisp_myrlocs [ 0 ]
   if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
   if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
  Oo0oooO0oO . rle = iIiI1
  Oo0oooO0oO . local_bit = True
  Oo0oooO0oO . reach_bit = True
  Oo0oooO0oO . priority = 255
  Oo0oooO0oO . weight = 0
  Oo0oooO0oO . mpriority = 1
  Oo0oooO0oO . mweight = 100
  o00o0 += Oo0oooO0oO . encode ( )
  Oo0oooO0oO . print_record ( "    " )
  if 62 - 62: o0oOOo0O0Ooo - Ii1I * OoOoOO00 - i11iIiiIii % ooOoO0o
  if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
  if 30 - 30: iII111i / OoO0O00 + oO0o
  if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
  if 70 - 70: OoO0O00
  for OooooOoooO in list ( lisp . lisp_rtr_list . values ( ) ) :
   if ( OooooOoooO == None ) : continue
   Oo0oooO0oO = lisp . lisp_rloc_record ( )
   Oo0oooO0oO . rloc . copy_address ( OooooOoooO )
   Oo0oooO0oO . priority = 254
   Oo0oooO0oO . rloc_name = "RTR"
   Oo0oooO0oO . weight = 0
   Oo0oooO0oO . mpriority = 255
   Oo0oooO0oO . mweight = 0
   Oo0oooO0oO . local_bit = False
   Oo0oooO0oO . reach_bit = True
   o00o0 += Oo0oooO0oO . encode ( )
   Oo0oooO0oO . print_record ( "    RTR " )
   if 46 - 46: I11i - i1IIi
   if 46 - 46: I1Ii111 % Ii1I
   if 72 - 72: iIii1I11I1II1
   if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
   if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
  OOo0 [ i11iiI1111 ] [ 0 ] += o00o0
  if 87 - 87: OoO0O00 % I1IiiI
  if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
  if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
  if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
  if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 O000OOO0OOo = lisp . lisp_map_register ( )
 O000OOO0OOo . nonce = 0xaabbccdddfdfdf00
 O000OOO0OOo . xtr_id_present = True
 O000OOO0OOo . proxy_reply_requested = True
 O000OOO0OOo . map_notify_requested = False
 O000OOO0OOo . merge_register_requested = True
 if 84 - 84: i11iIiiIii * OoO0O00
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 for Oo00OOOOO in list ( lisp . lisp_map_servers_list . values ( ) ) :
  IiI1IiI11iII = Oo00OOOOO . dns_name if Oo0OO0000oooo else Oo00OOOOO . ms_name
  if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
  if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  if 64 - 64: i1IIi
  if ( IiI1IiI11iII not in OOo0 ) : continue
  if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
  if 18 - 18: OOooOOo + I1Ii111
  if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
  if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
  O000OOO0OOo . record_count = OOo0 [ IiI1IiI11iII ] [ 1 ]
  if ( O000OOO0OOo . record_count == 0 ) : continue
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
  O000OOO0OOo . nonce += 1
  O000OOO0OOo . alg_id = Oo00OOOOO . alg_id
  O000OOO0OOo . alg_id = Oo00OOOOO . key_id
  O000OOO0OOo . xtr_id = Oo00OOOOO . xtr_id
  O000OOO0OOo . site_id = Oo00OOOOO . site_id
  O000OOO0OOo . encrypt_bit = ( Oo00OOOOO . ekey != None )
  Ooo0oo = O000OOO0OOo . encode ( )
  O000OOO0OOo . print_map_register ( )
  if 50 - 50: ooOoO0o + i1IIi
  if 31 - 31: Ii1I
  if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
  if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
  if 47 - 47: o0oOOo0O0Ooo
  I1ii = O000OOO0OOo . encode_xtr_id ( b"" )
  Ooo0oo = Ooo0oo + o00o0 + I1ii
  if 66 - 66: I1IiiI - IiII
  Oo00OOOOO . map_registers_multicast_sent += 1
  lisp . lisp_send_map_register ( lisp_sockets , Ooo0oo , O000OOO0OOo , Oo00OOOOO )
  if 33 - 33: I1IiiI / OoO0O00
  if 12 - 12: II111iiii
  if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
  if 25 - 25: oO0o
  Oo00OOOOO . resolve_dns_name ( )
  if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
  if 43 - 43: I1ii11iIi11i - iII111i
  if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
  if 47 - 47: iII111i
  time . sleep ( .001 )
  if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 return
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if 47 - 47: oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if 38 - 38: O0 - IiII % I1Ii111
 if 64 - 64: iIii1I11I1II1
def IIi1iI ( parms , not_used , packet ) :
 global Ooo , o0oOoO00o
 if 92 - 92: OoO0O00 * ooOoO0o
 i1iIIi1 = parms [ 0 ]
 i1 = parms [ 1 ]
 if 83 - 83: IiII * I11i / Oo0Ooo
 if 32 - 32: o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
 if 39 - 39: OoooooooOO * OOooOOo * O0 . I11i . OoO0O00 + ooOoO0o
 if 9 - 9: OoOoOO00 + oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if ( lisp . lisp_is_macos ( ) == False ) :
  I11Oo0oO00 = 4 if i1iIIi1 == "lo0" else 16
  packet = packet [ I11Oo0oO00 : : ]
  if 8 - 8: I1IiiI % I1IiiI . OoOoOO00 % o0oOOo0O0Ooo
  if 47 - 47: ooOoO0o + II111iiii % I1Ii111 . I11i % I1ii11iIi11i
  if 7 - 7: O0 / iII111i * oO0o
  if 29 - 29: o0oOOo0O0Ooo
  if 86 - 86: II111iiii . IiII
 iIiI = struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ]
 if ( iIiI == 2 ) :
  oO00Ooo0oO = lisp . lisp_process_igmp_packet ( packet )
  if ( type ( oO00Ooo0oO ) != bool ) :
   OO0OO0OO ( o0oOoO00o , oO00Ooo0oO )
   return
   if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
   if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
   if 71 - 71: IiII . I1Ii111 . OoO0O00
   if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
   if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
   if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 ii = packet
 packet , II1iIi11 , O0O0o0oO0O00 , o0O0oO0 = lisp . lisp_is_rloc_probe ( packet , i1iIIi1 , 0 )
 if ( ii != packet ) :
  if ( II1iIi11 == None ) : return
  lisp . lisp_parse_packet ( o0oOoO00o , packet , II1iIi11 , O0O0o0oO0O00 , o0O0oO0 )
  return
  if 77 - 77: O0 . Ii1I
  if 39 - 39: ooOoO0o . II111iiii
  if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
  if 77 - 77: I1Ii111 - I11i
  if 11 - 11: I1ii11iIi11i
  if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
  if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
 if ( struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ] & 0xf0 == 0x40 ) :
  o0OO0O0OO0oO0 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
  if ( lisp . lisp_nat_traversal and o0OO0O0OO0oO0 == lisp . LISP_DATA_PORT ) : return
  packet = lisp . lisp_reassemble ( packet )
  if ( packet == None ) : return
  if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
  if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 packet = lisp . lisp_packet ( packet )
 oO = packet . decode ( True , Ooo , lisp . lisp_decap_stats )
 if ( oO == None ) : return
 if 31 - 31: OoO0O00 * i11iIiiIii * Ii1I . i11iIiiIii
 if 12 - 12: OoOoOO00 % IiII % I1ii11iIi11i . i11iIiiIii * iIii1I11I1II1
 if 66 - 66: i11iIiiIii * iIii1I11I1II1 % OoooooooOO
 if 5 - 5: OoOoOO00 % OoooooooOO
 packet . print_packet ( "Receive" , True )
 if 60 - 60: OoOoOO00 . i1IIi % OoO0O00 % ooOoO0o % OOooOOo
 if 33 - 33: iIii1I11I1II1 - Ii1I * I1ii11iIi11i % iIii1I11I1II1 + OoO0O00 . OOooOOo
 if 56 - 56: i11iIiiIii * iII111i . oO0o
 if 78 - 78: OoOoOO00
 if 1 - 1: OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
  II1iIi11 = packet . inner_source . print_address_no_iid ( )
  packet . strip_outer_headers ( )
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , II1iIi11 , o0OO0O0OO0oO0 )
  lisp . lisp_ipc ( packet , Ooo , "lisp-ms" )
  return
  if 28 - 28: OOooOOo % ooOoO0o
  if 48 - 48: i11iIiiIii % oO0o
  if 29 - 29: iII111i + i11iIiiIii % I11i
  if 93 - 93: OoOoOO00 % iIii1I11I1II1
  if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
  if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
  if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
  if 21 - 21: OOooOOo
  if 6 - 6: IiII
  if 46 - 46: IiII + oO0o
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  Oo00o0O0O = packet . packet [ 36 : : ]
  o0ooO0OoOo = Oo00o0O0O [ 28 : : ]
  o0O0oO0 = - 1
  if ( lisp . lisp_is_rloc_probe_request ( o0ooO0OoOo [ 0 : 1 ] ) ) :
   o0O0oO0 = struct . unpack ( "B" , Oo00o0O0O [ 8 : 9 ] ) [ 0 ] - 1
   if 99 - 99: OoOoOO00
  II1iIi11 = packet . outer_source . print_address_no_iid ( )
  lisp . lisp_parse_packet ( o0oOoO00o , o0ooO0OoOo , II1iIi11 , 0 , o0O0oO0 )
  return
  if 77 - 77: o0oOOo0O0Ooo
  if 48 - 48: OoOoOO00 % I1ii11iIi11i / I11i . iIii1I11I1II1 * II111iiii
  if 65 - 65: OoOoOO00
  if 31 - 31: I11i * OoOoOO00 . IiII % Ii1I + Oo0Ooo
  if 47 - 47: O0 * I1IiiI * OoO0O00 . II111iiii
  if 95 - 95: Ii1I % IiII . O0 % I1Ii111
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 68 - 68: Oo0Ooo . Oo0Ooo - I1ii11iIi11i / I11i . ooOoO0o / i1IIi
  if 12 - 12: I1ii11iIi11i * i1IIi * I11i
  if 23 - 23: OOooOOo / O0 / I1IiiI
  if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
  if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 packet . strip_outer_headers ( )
 oOo00o = lisp . bold ( "Forward" , False )
 if 98 - 98: OOooOOo % i1IIi . I1IiiI . II111iiii . I1ii11iIi11i / i11iIiiIii
 if 32 - 32: o0oOOo0O0Ooo + I1IiiI . I1Ii111
 if 41 - 41: OoOoOO00 . i11iIiiIii / I11i
 if 98 - 98: OoOoOO00 % II111iiii
 OoO0O000 = False
 II1Ii = packet . inner_dest . is_mac ( )
 if ( II1Ii ) :
  packet . packet = lisp . lisp_mac_input ( packet . packet )
  if ( packet . packet == None ) : return
  oOo00o = lisp . bold ( "Bridge" , False )
 elif ( packet . inner_version == 4 ) :
  OoO0O000 , packet . packet = lisp . lisp_ipv4_input ( packet . packet )
  if ( packet . packet == None ) : return
  if ( OoO0O000 ) :
   oO00Ooo0oO = lisp . lisp_process_igmp_packet ( packet . packet )
   if ( type ( oO00Ooo0oO ) != bool ) :
    OO0OO0OO ( o0oOoO00o , oO00Ooo0oO )
    return
    if 6 - 6: i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
    if 68 - 68: o0oOOo0O0Ooo
  packet . inner_ttl = packet . outer_ttl
 elif ( packet . inner_version == 6 ) :
  packet . packet = lisp . lisp_ipv6_input ( packet )
  if ( packet . packet == None ) : return
  packet . inner_ttl = packet . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 20 - 20: I1Ii111 - I1Ii111
  if 37 - 37: IiII
  if 37 - 37: Oo0Ooo / IiII * O0
  if 73 - 73: iII111i * iII111i / ooOoO0o
  if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
  if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
  if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
  if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
  if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
  if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  I11OoOoOOOoOO = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( I11OoOoOOOoOO ) :
   I11OoOoOOOoOO . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
   return
   if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 else :
  if ( lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False ) ) :
   lisp . dprint ( "Discard echoed multicast packet (through NAT)" )
   return
   if 69 - 69: I1ii11iIi11i
   if 83 - 83: o0oOOo0O0Ooo
   if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
   if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
   if 48 - 48: iII111i + IiII
   if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
   if 14 - 14: OOooOOo
   if 79 - 79: Ii1I
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 76 - 76: iIii1I11I1II1
  if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
  if 93 - 93: OoooooooOO * Oo0Ooo
  if 10 - 10: I1Ii111 * OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i11iIiiIii
  if 22 - 22: I1Ii111 / o0oOOo0O0Ooo
 IiIIii1iII1II = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 98 - 98: i1IIi
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( oOo00o , lisp . green ( IiIIii1iII1II , False ) ,
 # Oo0Ooo % OoO0O00 - OoooooooOO * Oo0Ooo
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 38 - 38: iIii1I11I1II1 / ooOoO0o
 if 13 - 13: iIii1I11I1II1
 if 77 - 77: i11iIiiIii - iIii1I11I1II1 / oO0o / ooOoO0o / OoO0O00
 if 56 - 56: OoooooooOO * O0
 if 85 - 85: OoooooooOO % OoOoOO00 * iIii1I11I1II1
 if ( II1Ii ) :
  packet . bridge_l2_packet ( packet . inner_dest , I11OoOoOOOoOO )
  return
  if 44 - 44: iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
  if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
  if 65 - 65: oO0o + OoOoOO00 + II111iiii
  if 77 - 77: II111iiii
  if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
  if 68 - 68: oO0o
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( oOOoo00O0O , i1111 )
  return
  if 10 - 10: Ii1I
  if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
  if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
  if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
  if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 I1 = packet . get_raw_socket ( )
 if ( I1 == None ) : I1 = i1
 if 35 - 35: I1IiiI
 if 36 - 36: i1IIi - I1ii11iIi11i - I1Ii111
 if 7 - 7: i11iIiiIii + I1IiiI
 if 47 - 47: I1Ii111 - OOooOOo / ooOoO0o - Oo0Ooo + iII111i - iIii1I11I1II1
 packet . send_packet ( I1 , packet . inner_dest )
 return
 if 68 - 68: Ii1I - oO0o + Oo0Ooo
 if 44 - 44: Ii1I * o0oOOo0O0Ooo * II111iiii
 if 5 - 5: i1IIi + O0 % O0 * O0 + OoOoOO00 % i1IIi
 if 80 - 80: iII111i / o0oOOo0O0Ooo + OoO0O00 / oO0o
 if 46 - 46: i11iIiiIii / IiII % i1IIi - I11i * OoOoOO00
 if 94 - 94: Ii1I - I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo
 if 15 - 15: OOooOOo
 if 31 - 31: iII111i / i1IIi . OoO0O00
 if 83 - 83: oO0o / iIii1I11I1II1 + i1IIi / iII111i
 if 47 - 47: oO0o + OoooooooOO . II111iiii . iII111i
 if 66 - 66: ooOoO0o * OoOoOO00
def II1 ( lisp_raw_socket , packet , source ) :
 global Ooo , o0oOoO00o
 if 91 - 91: OOooOOo + I1Ii111 . I11i
 if 15 - 15: I11i
 if 94 - 94: I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
 if 81 - 81: Oo0Ooo - I11i
 ii1 = packet
 packet = lisp . lisp_packet ( packet [ 8 : : ] )
 if ( packet . lisp_header . decode ( ii1 ) == False ) : return
 if 44 - 44: OoOoOO00 - Oo0Ooo
 if 95 - 95: OOooOOo + ooOoO0o
 if 88 - 88: I11i + i11iIiiIii % oO0o * OOooOOo * OOooOOo * Ii1I
 if 24 - 24: ooOoO0o / iII111i + IiII . IiII
 if 39 - 39: ooOoO0o + O0 / i1IIi % IiII / oO0o * IiII
 packet . outer_source = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , source ,
 lisp . LISP_IPV4_HOST_MASK_LEN , 0 )
 if 77 - 77: IiII . I1Ii111 % OoOoOO00
 oO = packet . decode ( False , Ooo ,
 lisp . lisp_decap_stats )
 if ( oO == None ) : return
 if 42 - 42: IiII % iII111i % o0oOOo0O0Ooo % oO0o + I11i % OoOoOO00
 if 3 - 3: oO0o
 if 64 - 64: OoO0O00 . I1IiiI - OoooooooOO . ooOoO0o - iII111i
 if 77 - 77: Ii1I % OoOoOO00 / II111iiii % iII111i % OoooooooOO % OoO0O00
 if 19 - 19: IiII * I1Ii111 / oO0o * I1Ii111 - OoooooooOO * I11i
 if 17 - 17: II111iiii + Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if ( lisp . lisp_flow_logging ) : packet . log_flow ( False )
 if 29 - 29: IiII . ooOoO0o - II111iiii
 packet . print_packet ( "Kernel-decap" , False )
 lisp . dprint ( packet . lisp_header . print_header ( " " ) )
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
  o0OO0O0OO0oO0 = packet . udp_sport
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , source , o0OO0O0OO0oO0 )
  lisp . lisp_ipc ( packet , Ooo , "lisp-ms" )
  return
  if 71 - 71: I1Ii111 * Oo0Ooo . I11i
  if 49 - 49: IiII * O0 . IiII
  if 19 - 19: II111iiii - IiII
  if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
  if 89 - 89: OOooOOo
  if 69 - 69: ooOoO0o - OoooooooOO * O0
  if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
  if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
  if 96 - 96: OoooooooOO + IiII * O0
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  Oo00o0O0O = packet . packet
  o0ooO0OoOo = Oo00o0O0O [ 28 : : ]
  o0O0oO0 = - 1
  if ( lisp . lisp_is_rloc_probe_request ( o0ooO0OoOo [ 0 : 1 ] ) ) :
   o0O0oO0 = struct . unpack ( "B" , Oo00o0O0O [ 8 : 9 ] ) [ 0 ] - 1
   if 86 - 86: Ii1I
   if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
   if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
   if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
   if 69 - 69: OoOoOO00
   if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
   if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
  if ( lisp . lisp_is_rloc_probe_reply ( o0ooO0OoOo [ 0 : 1 ] ) ) :
   o0OO0O0OO0oO0 = socket . ntohs ( struct . unpack ( "H" , packet . packet [ 20 : 22 ] ) [ 0 ] )
   if ( o0OO0O0OO0oO0 == lisp . LISP_DATA_PORT ) :
    packet = packet . packet [ 28 : : ]
    packet = lisp . lisp_packet_ipc ( packet , source , o0OO0O0OO0oO0 )
    lisp . lisp_ipc ( packet , Ooo , "lisp-itr" )
    return
    if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
    if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
  lisp . lisp_parse_packet ( o0oOoO00o , o0ooO0OoOo , source , 0 , o0O0oO0 )
  return
  if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
  if 88 - 88: o0oOOo0O0Ooo
  if 1 - 1: OoooooooOO
  if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
  if 40 - 40: i11iIiiIii . iIii1I11I1II1
  if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 3 - 3: OoooooooOO
  if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
  if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
  if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
  if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  I11OoOoOOOoOO = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( I11OoOoOOOoOO ) :
   I11OoOoOOOoOO . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
   if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
   if 43 - 43: OoO0O00 % OoO0O00
 else :
  if ( lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False ) ) :
   lisp . dprint ( "Discard echoed multicast packet" )
   return
   if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
   if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
   if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
   if 45 - 45: Ii1I - OOooOOo
   if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
   if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
   if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
   if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 36 - 36: I11i % OOooOOo
  if 72 - 72: I1IiiI / iII111i - O0 + I11i
 IiIIii1iII1II = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 83 - 83: O0
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( lisp . bold ( "NAT-Forward" , False ) , lisp . green ( IiIIii1iII1II , False ) ,
 # OoO0O00 + o0oOOo0O0Ooo + o0oOOo0O0Ooo - II111iiii + OoO0O00 + OoO0O00
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( oOOoo00O0O , i1111 )
  return
  if 59 - 59: IiII
  if 89 - 89: OoOoOO00 % iIii1I11I1II1
  if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
  if 45 - 45: I1IiiI * OOooOOo % OoO0O00
  if 24 - 24: ooOoO0o - I11i * oO0o
 I1 = packet . get_raw_socket ( )
 if ( I1 == None ) : I1 = lisp_raw_socket
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 packet . send_packet ( I1 , packet . inner_dest )
 return
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
def O0oooOoO ( group , joinleave ) :
 ooO00O00oOO = lisp . lisp_lookup_group ( group )
 if ( ooO00O00oOO == None ) : return
 if 62 - 62: OOooOOo / II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 IiI11I111 = [ ]
 for oO0O00oOOoooO in ooO00O00oOO . sources :
  IiI11I111 . append ( [ oO0O00oOOoooO , group , joinleave ] )
  if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
  if 36 - 36: OOooOOo % i11iIiiIii
 OO0OO0OO ( o0oOoO00o , IiI11I111 )
 return
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
def OoO ( ) :
 global o0oOoO00o
 if 37 - 37: I1ii11iIi11i
 lisp . lisp_set_exception ( )
 if 68 - 68: o0oOOo0O0Ooo
 Ooo00O0 = socket . htonl
 OoO0OOoO0 = [ Ooo00O0 ( 0x46000020 ) , Ooo00O0 ( 0x9fe60000 ) , Ooo00O0 ( 0x0102d7cc ) ,
 Ooo00O0 ( 0x0acfc15a ) , Ooo00O0 ( 0xe00000fb ) , Ooo00O0 ( 0x94040000 ) ]
 if 5 - 5: i1IIi . i1IIi
 Ooo0oo = b""
 for o0o0oo0Ooo in OoO0OOoO0 : Ooo0oo += struct . pack ( "I" , o0o0oo0Ooo )
 if 12 - 12: I1ii11iIi11i / Ii1I
 if 5 - 5: OoooooooOO
 if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
 if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
 if 93 - 93: Oo0Ooo / I1ii11iIi11i + i1IIi * oO0o . OoooooooOO
 while ( True ) :
  Oo000 = getoutput ( "ls join-*" ) . replace ( "join-" , "" )
  Oo000 = Oo000 . split ( "\n" )
  if 97 - 97: O0 / OOooOOo + o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
  for O00ooOo in Oo000 :
   if ( lisp . lisp_valid_address_format ( "address" , O00ooOo ) == False ) :
    continue
    if 33 - 33: I11i % II111iiii + OoO0O00
    if 93 - 93: i1IIi . IiII / I1IiiI + IiII
   OOooOO = ( O00ooOo . find ( ":" ) != - 1 )
   if 59 - 59: OoO0O00 - OoO0O00 + iII111i
   if 32 - 32: i1IIi / Oo0Ooo - O0
   if 85 - 85: Ii1I - O0 * i11iIiiIii . i1IIi
   if 20 - 20: iII111i / OOooOOo
   I1111ii11IIII = os . path . exists ( "leave-{}" . format ( O00ooOo ) )
   lisp . lprint ( "Internal {} group {}" . format ( "leaving" if I1111ii11IIII else "joining" , O00ooOo ) )
   if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
   if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
   if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
   if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
   if 33 - 33: Ii1I
   if ( OOooOO ) :
    if ( O00ooOo . lower ( ) . find ( "ff02:" ) != - 1 ) :
     lisp . lprint ( "Suppress registration for link-local groups" )
     continue
     if 93 - 93: ooOoO0o
    O0oooOoO ( O00ooOo , ( I1111ii11IIII == False ) )
   else :
    II11iIIii = Ooo0oo
    if ( I1111ii11IIII ) :
     II11iIIii += struct . pack ( "I" , Ooo00O0 ( 0x17000000 ) )
    else :
     II11iIIii += struct . pack ( "I" , Ooo00O0 ( 0x16000000 ) )
     if 57 - 57: O0 * I1ii11iIi11i . i11iIiiIii
     if 69 - 69: O0 / II111iiii * i1IIi
    oOIiiIIi = O00ooOo . split ( "." )
    oOOOoo00 = int ( oOIiiIIi [ 0 ] ) << 24
    oOOOoo00 += int ( oOIiiIIi [ 1 ] ) << 16
    oOOOoo00 += int ( oOIiiIIi [ 2 ] ) << 8
    oOOOoo00 += int ( oOIiiIIi [ 3 ] )
    II11iIIii += struct . pack ( "I" , Ooo00O0 ( oOOOoo00 ) )
    IiI11I111 = lisp . lisp_process_igmp_packet ( II11iIIii )
    if ( type ( IiI11I111 ) != bool ) :
     OO0OO0OO ( o0oOoO00o , IiI11I111 )
     if 96 - 96: i1IIi . I11i + oO0o + I1ii11iIi11i * OOooOOo - II111iiii
    time . sleep ( .100 )
    if 1 - 1: O0
    if 40 - 40: I1Ii111 - OoOoOO00 * I11i - IiII / OoOoOO00
  time . sleep ( 10 )
  if 71 - 71: oO0o / OoooooooOO % IiII / OoOoOO00 % I1Ii111
 return
 if 19 - 19: I1Ii111 + IiII / oO0o / II111iiii
 if 92 - 92: i1IIi % ooOoO0o + ooOoO0o - iIii1I11I1II1 . Ii1I
 if 33 - 33: o0oOOo0O0Ooo / O0 + OOooOOo
 if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
 if 92 - 92: OoOoOO00 % O0
 if 55 - 55: iIii1I11I1II1 * iII111i
 if 85 - 85: iIii1I11I1II1 . II111iiii
 if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
 if 22 - 22: OOooOOo
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
def OOooO0Oo0o000 ( ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 17 - 17: iIii1I11I1II1 + I1IiiI
 if 57 - 57: o0oOOo0O0Ooo / I1Ii111
 if 13 - 13: OoooooooOO + OoO0O00
 if 32 - 32: O0 + oO0o % Oo0Ooo
 if 7 - 7: I1ii11iIi11i / ooOoO0o
 I1i1I11111iI1 = lisp . lisp_get_all_multicast_rles ( )
 if 32 - 32: I1IiiI + I1ii11iIi11i - oO0o + I1ii11iIi11i / i1IIi * oO0o
 if 90 - 90: Ii1I % oO0o
 if 6 - 6: OoooooooOO / i11iIiiIii / I1Ii111
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 i1iIIi1 = "any"
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if 64 - 64: i1IIi
 I1ii1i1iiii = "(proto 2) or "
 if 45 - 45: Ii1I / ooOoO0o . OoooooooOO + OoO0O00
 I1ii1i1iiii += "((dst host "
 for O00oO000Oo0 in lisp . lisp_get_all_addresses ( ) + I1i1I11111iI1 :
  I1ii1i1iiii += "{} or " . format ( O00oO000Oo0 )
  if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
 I1ii1i1iiii = I1ii1i1iiii [ 0 : - 4 ]
 I1ii1i1iiii += ") and ((udp dst port 4341 or 8472 or 4789) or "
 I1ii1i1iiii += "(udp src port 4341) or "
 I1ii1i1iiii += "(udp dst port 4342 and ip[28] == 0x12) or "
 I1ii1i1iiii += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0)))))"
 if 47 - 47: OoooooooOO
 if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
 lisp . lprint ( "Capturing packets for: '{}' on device {}" . format ( I1ii1i1iiii ,
 i1iIIi1 ) )
 if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 if ( lisp . lisp_is_python2 ( ) ) :
  import pcappy
  iIIiI11iI1Ii1 = pcappy . open_live ( i1iIIi1 , 1600 , 0 , 100 )
  iIIiI11iI1Ii1 . filter = I1ii1i1iiii
  iIIiI11iI1Ii1 . loop ( - 1 , IIi1iI , [ i1iIIi1 , i1 ] )
  if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if ( lisp . lisp_is_python3 ( ) ) :
  import pcapy
  iIIiI11iI1Ii1 = pcapy . open_live ( i1iIIi1 , 1600 , 0 , 100 )
  iIIiI11iI1Ii1 . setfilter ( I1ii1i1iiii )
  while ( True ) :
   O0oO0oo0O , Ooo0oo = iIIiI11iI1Ii1 . next ( )
   if ( len ( Ooo0oo ) == 0 ) : continue
   IIi1iI ( [ i1iIIi1 , i1 ] , None , Ooo0oo )
   if 82 - 82: OoooooooOO . Ii1I
   if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 return
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo
 if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
def OOo000o ( ) :
 global Ooo
 global Oo
 global o0oOoO00o
 global i1
 global oOOoo00O0O
 global i1111
 if 37 - 37: iII111i
 lisp . lisp_i_am ( "etr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "ETR starting up" )
 if 33 - 33: OoO0O00 - O0 - OoO0O00
 if 94 - 94: IiII * I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - o0oOOo0O0Ooo
 if 13 - 13: OOooOOo / IiII - OoO0O00 / OOooOOo . i1IIi
 if 22 - 22: O0 - I11i + I1Ii111 . Ii1I * i1IIi
 lisp . lisp_get_local_interfaces ( )
 lisp . lisp_get_local_macs ( )
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
 if 10 - 10: I1Ii111 * oO0o % Oo0Ooo - I11i % Oo0Ooo
 if 65 - 65: iII111i * iIii1I11I1II1 / O0 . I11i
 if 94 - 94: Oo0Ooo . ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo . iII111i
 if 98 - 98: OOooOOo + Ii1I
 if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
 if 50 - 50: iIii1I11I1II1 - iII111i - I11i
 if 60 - 60: iIii1I11I1II1 * ooOoO0o
 if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
 if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
 if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
 if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
 if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
 if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
 if 93 - 93: ooOoO0o
 oO0O00oOOoooO = lisp . lisp_open_listen_socket ( "0.0.0.0" , str ( I1Ii11I1Ii1i ) )
 oO0O00oOOoooO . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_TTL , 32 )
 Oo = oO0O00oOOoooO
 if 18 - 18: ooOoO0o
 if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
 if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
 if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
 Ooo = lisp . lisp_open_listen_socket ( "" , "lisp-etr" )
 if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
 o0oOoO00o [ 0 ] = Oo
 o0oOoO00o [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 o0oOoO00o [ 2 ] = Ooo
 if 58 - 58: O0
 if 91 - 91: iII111i / I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I1ii11iIi11i
 if 72 - 72: Ii1I . IiII * I1ii11iIi11i / I1ii11iIi11i / iII111i
 if 13 - 13: i1IIi
 if 17 - 17: i11iIiiIii * o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoO0O00
 if 95 - 95: I1IiiI
 if 95 - 95: OOooOOo % I1ii11iIi11i + o0oOOo0O0Ooo % ooOoO0o
 if 36 - 36: O0 / i1IIi % II111iiii / iII111i
 if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
 i1 = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 i1 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 o0oOoO00o . append ( i1 )
 if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: oO0o
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
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 if 36 - 36: IiII
 if ( pytun != None ) :
  i1111 = b'\x00\x00\x86\xdd'
  i1iIIi1 = "lispers.net"
  try :
   oOOoo00O0O = pytun . TunTapDevice ( flags = pytun . IFF_TUN ,
 name = i1iIIi1 )
   os . system ( "ip link set dev {} up" . format ( i1iIIi1 ) )
  except :
   lisp . lprint ( "Cannot create tuntap interface" )
   if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
   if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
   if 43 - 43: iIii1I11I1II1 % OoO0O00
   if 84 - 84: Oo0Ooo
   if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
   if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
 threading . Thread ( target = OOooO0Oo0o000 , args = [ ] ) . start ( )
 if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
 if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
 if 25 - 25: o0oOOo0O0Ooo
 if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
 threading . Thread ( target = OoO , args = [ ] ) . start ( )
 return ( True )
 if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
 if 41 - 41: i1IIi - I1IiiI
 if 48 - 48: I1IiiI - II111iiii / OoO0O00 + I1IiiI
 if 5 - 5: O0
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
 if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
def O00o ( ) :
 global Oo0o
 global Ii1iI
 if 55 - 55: ooOoO0o % I11i / i11iIiiIii
 if 20 - 20: IiII / I1Ii111 * IiII * OoO0O00
 if 72 - 72: OoO0O00 . o0oOOo0O0Ooo * I1ii11iIi11i . iIii1I11I1II1 % I1ii11iIi11i . Ii1I
 if 70 - 70: OOooOOo + ooOoO0o * Ii1I . Ii1I + OoO0O00
 if ( Oo0o ) : Oo0o . cancel ( )
 if ( Ii1iI ) : Ii1iI . cancel ( )
 if 28 - 28: i1IIi . OOooOOo
 if 88 - 88: I11i + I1IiiI - I11i / OoooooooOO - i11iIiiIii
 if 24 - 24: iIii1I11I1II1
 if 89 - 89: Ii1I / i1IIi - o0oOOo0O0Ooo % I1IiiI . Oo0Ooo - O0
 lisp . lisp_close_socket ( o0oOoO00o [ 0 ] , "" )
 lisp . lisp_close_socket ( o0oOoO00o [ 1 ] , "" )
 lisp . lisp_close_socket ( Ooo , "lisp-etr" )
 return
 if 71 - 71: OoO0O00 % I1IiiI - iII111i . iII111i
 if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
 if 64 - 64: i1IIi % I1ii11iIi11i / Ii1I % OoooooooOO
 if 24 - 24: I1Ii111 + OoooooooOO . IiII / OoOoOO00 / I11i
 if 65 - 65: OoooooooOO
 if 18 - 18: O0 - i1IIi . I1Ii111
 if 98 - 98: o0oOOo0O0Ooo
 if 73 - 73: Oo0Ooo - iII111i . oO0o % i1IIi . O0
 if 15 - 15: ooOoO0o . iIii1I11I1II1 * I1IiiI % I11i
 if 21 - 21: OoO0O00 - I1IiiI . OoooooooOO
 if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
def iIi ( ipc ) :
 ipc = ipc . split ( "%" )
 oo0O = ipc [ 1 ]
 o0oooo0OOo00 = ipc [ 2 ]
 if ( o0oooo0OOo00 == "None" ) : o0oooo0OOo00 = None
 if 90 - 90: o0oOOo0O0Ooo / OOooOOo - OOooOOo . I1IiiI
 OoOoOo00o0 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 OoOoOo00o0 . store_address ( oo0O )
 if 82 - 82: I1Ii111 . I1Ii111 - iII111i
 if 72 - 72: i11iIiiIii
 if 94 - 94: OOooOOo
 if 33 - 33: Ii1I % O0 + I1ii11iIi11i
 I11OoOoOOOoOO = lisp . lisp_db_for_lookups . lookup_cache ( OoOoOo00o0 , False )
 if ( I11OoOoOOOoOO == None or I11OoOoOOOoOO . dynamic_eid_configured ( ) == False ) :
  lisp . lprint ( "ITR/ETR dynamic-EID configuration out of sync for {}" . format ( lisp . green ( oo0O , False ) ) )
  if 96 - 96: ooOoO0o . OoooooooOO
  return
  if 39 - 39: OOooOOo + OoO0O00
  if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
  if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
  if 71 - 71: ooOoO0o . i11iIiiIii
  if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
  if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
 oOooO0 = None
 if ( oo0O in I11OoOoOOOoOO . dynamic_eids ) : oOooO0 = I11OoOoOOOoOO . dynamic_eids [ oo0O ]
 if 67 - 67: iII111i
 if ( oOooO0 == None and o0oooo0OOo00 == None ) :
  lisp . lprint ( "ITR/ETR state mismatch for {}" . format ( lisp . green ( oo0O , False ) ) )
  if 88 - 88: Oo0Ooo
  return
  if 8 - 8: I1ii11iIi11i
  if 82 - 82: OoooooooOO
  if 75 - 75: II111iiii % I1IiiI + OOooOOo % OoooooooOO / IiII
  if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
  if 71 - 71: ooOoO0o . ooOoO0o - iIii1I11I1II1
  if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
 if ( oOooO0 and o0oooo0OOo00 ) :
  if ( oOooO0 . interface == o0oooo0OOo00 ) :
   lisp . lprint ( "ITR sent redundant IPC for {}" . format ( lisp . green ( oo0O , False ) ) )
   if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
  else :
   lisp . lprint ( "Dynamic-EID {} interface change, {} -> {}" . format ( lisp . green ( oo0O , False ) , oOooO0 . interface , o0oooo0OOo00 ) )
   if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
   oOooO0 . interface = o0oooo0OOo00
   if 29 - 29: Ii1I / ooOoO0o % I11i
  return
  if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  if 79 - 79: IiII + IiII + Ii1I
  if 39 - 39: O0 - OoooooooOO
 if ( o0oooo0OOo00 ) :
  oOooO0 = lisp . lisp_dynamic_eid ( )
  oOooO0 . dynamic_eid . copy_address ( OoOoOo00o0 )
  oOooO0 . interface = o0oooo0OOo00
  oOooO0 . get_timeout ( o0oooo0OOo00 )
  I11OoOoOOOoOO . dynamic_eids [ oo0O ] = oOooO0
  if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  oo0 = lisp . bold ( "Registering" , False )
  oo0O = lisp . bold ( oo0O , False )
  lisp . lprint ( "{} dynamic-EID {} on interface {}, timeout {}" . format ( oo0 ,
 lisp . green ( oo0O , False ) , o0oooo0OOo00 , oOooO0 . timeout ) )
  if 17 - 17: O0 + OoooooooOO
  o00O ( o0oOoO00o , None , OoOoOo00o0 , None , False )
  if 78 - 78: II111iiii + IiII
  if 66 - 66: iIii1I11I1II1
  if 57 - 57: IiII
  if 41 - 41: iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % IiII / OOooOOo
  if ( lisp . lisp_is_macos ( ) == False ) :
   oo0O = OoOoOo00o0 . print_prefix_no_iid ( )
   Oo0o0ooOoO = "ip route add {} dev {}" . format ( oo0O , o0oooo0OOo00 )
   os . system ( Oo0o0ooOoO )
   if 47 - 47: OoOoOO00
  return
  if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
  if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
  if 33 - 33: oO0o
  if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
  if 41 - 41: IiII % o0oOOo0O0Ooo
 if ( oo0O in I11OoOoOOOoOO . dynamic_eids ) :
  o0oooo0OOo00 = I11OoOoOOOoOO . dynamic_eids [ oo0O ] . interface
  oo0O0oOOO0o = lisp . bold ( "Deregistering" , False )
  lisp . lprint ( "{} dynamic-EID {}" . format ( oo0O0oOOO0o ,
 lisp . green ( oo0O , False ) ) )
  if 70 - 70: Oo0Ooo % Ii1I . I1ii11iIi11i
  o00O ( o0oOoO00o , 0 , OoOoOo00o0 , None , False )
  if 8 - 8: I1IiiI - I1Ii111 * I11i % OoooooooOO / OoOoOO00
  I11OoOoOOOoOO . dynamic_eids . pop ( oo0O )
  if 15 - 15: ooOoO0o . o0oOOo0O0Ooo + OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
  if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
  if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
  if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
  if ( lisp . lisp_is_macos ( ) == False ) :
   oo0O = OoOoOo00o0 . print_prefix_no_iid ( )
   Oo0o0ooOoO = "ip route delete {} dev {}" . format ( oo0O , o0oooo0OOo00 )
   os . system ( Oo0o0ooOoO )
   if 44 - 44: I1Ii111 - IiII
   if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
 return
 if 59 - 59: II111iiii
 if 43 - 43: Oo0Ooo + OoooooooOO
 if 47 - 47: ooOoO0o
 if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
 if 23 - 23: II111iiii * iII111i
 if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
 if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
 if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
 if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
 if 21 - 21: OoO0O00
 if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
 if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
 if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
def iiII1IIii1i1 ( ipc ) :
 global O0O00Ooo
 global Oo
 if 38 - 38: iII111i * OoooooooOO
 ipc = ipc . split ( "%" )
 iIi11III = ipc [ - 2 ]
 i1i1IiIiIi1Ii = ipc [ - 1 ]
 if ( iIi11III in O0O00Ooo ) : return
 if 16 - 16: OoooooooOO * i11iIiiIii . OoooooooOO - iIii1I11I1II1 * i1IIi
 OOo00O = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , iIi11III , 32 , 0 )
 O0O00Ooo [ iIi11III ] = OOo00O
 if 33 - 33: I1Ii111 % II111iiii
 if 49 - 49: I1ii11iIi11i + I11i / o0oOOo0O0Ooo + OoooooooOO + OOooOOo / IiII
 if 29 - 29: Ii1I - Ii1I / ooOoO0o
 if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
 OO000o00 = [ Oo , Oo , Ooo ]
 lisp . lprint ( "Trigger NAT-Probe to ETR {}" . format ( iIi11III ) )
 lisp . lisp_send_info_request ( OO000o00 , OOo00O , lisp . LISP_DATA_PORT , None )
 if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
 if 18 - 18: Oo0Ooo % O0
 if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
 if 86 - 86: IiII
 if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
 iiI111i1 = i1i1IiIiIi1Ii . split ( "@tp-" )
 if ( len ( iiI111i1 ) != 2 ) :
  lisp . lprint ( "Invalid NAT IPC rloc-name {}" . format ( iiI111i1 ) )
  return
  if 41 - 41: i11iIiiIii * O0 - iII111i . II111iiii % OoO0O00 % I1ii11iIi11i
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
 ooiIii1I1111 , O0O0o0oO0O00 = iiI111i1 [ 0 ] , int ( iiI111i1 [ 1 ] )
 if ( lisp . lisp_store_nat_info ( ooiIii1I1111 , OOo00O , O0O0o0oO0O00 ) == False ) :
  lisp . lprint ( "Could not store NAT-info state for {}, {}" . format ( iIi11III ,
 i1i1IiIiIi1Ii ) )
  if 26 - 26: I1Ii111 . I1IiiI . iII111i - OoooooooOO / iIii1I11I1II1
  if 47 - 47: IiII
  if 76 - 76: OoO0O00 * iIii1I11I1II1 + I1ii11iIi11i - ooOoO0o - I11i / i1IIi
  if 27 - 27: I1ii11iIi11i . IiII
  if 66 - 66: O0 / O0 * i1IIi . OoooooooOO % iIii1I11I1II1
  if 21 - 21: IiII - I1IiiI % OoooooooOO + o0oOOo0O0Ooo
  if 92 - 92: ooOoO0o + IiII
  if 52 - 52: II111iiii / I1IiiI . oO0o * IiII . I11i
  if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 6 - 6: oO0o . I11i
  if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
  if 50 - 50: oO0o % i1IIi * O0
def iiIIi11ii1Ii ( ipc ) :
 if ( lisp . lisp_register_all_rtrs ) : return
 if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
 IiI , iII1I1IiI11ii , oO = ipc . split ( "%" )
 if ( iII1I1IiI11ii not in lisp . lisp_rtr_list ) : return
 if 34 - 34: O0 / OOooOOo
 lisp . lprint ( "Process ITR IPC message, RTR {} has gone {}" . format (
 lisp . red ( iII1I1IiI11ii , False ) , lisp . bold ( oO , False ) ) )
 if 86 - 86: I1ii11iIi11i * i1IIi + iII111i . I1ii11iIi11i
 OooooOoooO = lisp . lisp_rtr_list [ iII1I1IiI11ii ]
 if ( oO == "down" ) :
  lisp . lisp_rtr_list [ iII1I1IiI11ii ] = None
  return
  if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
  if 37 - 37: Oo0Ooo
 OooooOoooO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , iII1I1IiI11ii , 32 , 0 )
 lisp . lisp_rtr_list [ iII1I1IiI11ii ] = OooooOoooO
 return
 if 72 - 72: IiII % I1ii11iIi11i * OOooOOo . i11iIiiIii % IiII * OOooOOo
 if 15 - 15: I11i / Oo0Ooo * I11i
 if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
 if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
 if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
 if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
 if 5 - 5: O0 - I1IiiI
 if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
 if 16 - 16: II111iiii
 if 100 - 100: O0 - i1IIi
def iII1iiiiI1i ( ipc ) :
 OoOo , IiI , III1IiIi1 , oOOoO0O = ipc . split ( "%" )
 oOOoO0O = int ( oOOoO0O , 16 )
 if 76 - 76: i1IIi / iIii1I11I1II1 - I1ii11iIi11i - II111iiii
 oo00Oo = lisp . lisp_get_echo_nonce ( None , III1IiIi1 )
 if ( oo00Oo == None ) : oo00Oo = lisp . lisp_echo_nonce ( III1IiIi1 )
 if 6 - 6: I1IiiI - II111iiii . I1IiiI + I11i . OOooOOo
 if ( IiI == "R" ) :
  oo00Oo . request_nonce_sent = oOOoO0O
  lisp . lprint ( "Waiting for echo-nonce 0x{} from {}" . format ( lisp . lisp_hex_string ( oOOoO0O ) , lisp . red ( oo00Oo . rloc_str , False ) ) )
  if 74 - 74: i1IIi
 elif ( IiI == "E" ) :
  oo00Oo . echo_nonce_sent = oOOoO0O
  lisp . lprint ( "Sent echo-nonce 0x{} to {}" . format ( lisp . lisp_hex_string ( oOOoO0O ) , lisp . red ( oo00Oo . rloc_str , False ) ) )
  if 15 - 15: i1IIi + IiII % I1IiiI / i11iIiiIii * OoOoOO00
  if 69 - 69: i11iIiiIii
 return
 if 61 - 61: O0
 if 21 - 21: OoO0O00 % iIii1I11I1II1 . OoO0O00
 if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
 if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
 if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
IIi11I1i1I1I = {
 "lisp xtr-parameters" : [ lispconfig . lisp_xtr_command , {
 "rloc-probing" : [ True , "yes" , "no" ] ,
 "nonce-echoing" : [ True , "yes" , "no" ] ,
 "data-plane-security" : [ True , "yes" , "no" ] ,
 "data-plane-logging" : [ True , "yes" , "no" ] ,
 "frame-logging" : [ True , "yes" , "no" ] ,
 "flow-logging" : [ True , "yes" , "no" ] ,
 "nat-traversal" : [ True , "yes" , "no" ] ,
 "decentralized-nat" : [ True , "yes" , "no" ] ,
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

 "lisp map-server" : [ IiI1i11iii1 , {
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

 "lisp database-mapping" : [ OOO , {
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

 "lisp group-mapping" : [ o00Oo0oooooo , {
 "group-name" : [ False ] ,
 "ms-name" : [ True ] ,
 "group-prefix" : [ False ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "rle-address" : [ False ] ,
 "sources" : [ ] ,
 "address" : [ True ] } ] ,

 "show database-mapping" : [ III1Iiii1I11 , { } ] ,
 "show etr-keys" : [ IIiIiI , { } ] ,
 "show etr-dynamic-eid" : [ lispconfig . lisp_show_dynamic_eid_command , { } ]
 }
if 35 - 35: O0 + Oo0Ooo - I1IiiI % Ii1I % II111iiii
if 77 - 77: I1Ii111 + oO0o
if 38 - 38: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
if 13 - 13: I1IiiI * oO0o
if 41 - 41: IiII
if 16 - 16: iIii1I11I1II1
if ( OOo000o ( ) == False ) :
 lisp . lprint ( "lisp_etr_startup() failed" )
 lisp . lisp_print_banner ( "ETR abnormal exit" )
 exit ( 1 )
 if 94 - 94: ooOoO0o % I11i % i1IIi
 if 90 - 90: Ii1I * OoO0O00
I1i = [ Oo , Ooo ]
if 77 - 77: I1Ii111 * OOooOOo / ooOoO0o + I1ii11iIi11i
while ( True ) :
 try : iiii11i , Oo00OOOoo0 , OoOo = select . select ( I1i , [ ] , [ ] )
 except : break
 if 92 - 92: iII111i + OoOoOO00 - oO0o + I1ii11iIi11i
 if 14 - 14: OoO0O00
 if 38 - 38: O0
 if 79 - 79: i1IIi . oO0o
 if ( Oo in iiii11i ) :
  IiI , II1iIi11 , O0O0o0oO0O00 , Ooo0oo = lisp . lisp_receive ( Oo , False )
  if 34 - 34: I1Ii111 * II111iiii
  if ( II1iIi11 == "" ) : break
  if 71 - 71: IiII
  if ( O0O0o0oO0O00 == lisp . LISP_DATA_PORT ) :
   II1 ( i1 , Ooo0oo , II1iIi11 )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( Ooo0oo [ 0 : 1 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 97 - 97: I1ii11iIi11i
   OOo0oO0o = lisp . lisp_parse_packet ( o0oOoO00o , Ooo0oo ,
 II1iIi11 , O0O0o0oO0O00 )
   if 3 - 3: I1IiiI / iIii1I11I1II1 % o0oOOo0O0Ooo
   if 74 - 74: IiII - O0 / I1Ii111 * Ii1I % ooOoO0o . I1Ii111
   if 60 - 60: I1ii11iIi11i . II111iiii * i11iIiiIii . o0oOOo0O0Ooo
   if 66 - 66: iII111i / i11iIiiIii * O0
   if 78 - 78: IiII - I11i % O0 - OOooOOo % OoO0O00
   if ( OOo0oO0o ) :
    Ii1iI = threading . Timer ( 0 ,
 i1iiI11I , [ None ] )
    Ii1iI . start ( )
    Oo0o = threading . Timer ( 0 ,
 oo000OO00Oo , [ o0oOoO00o ] )
    Oo0o . start ( )
    if 43 - 43: OoO0O00
    if 90 - 90: OoooooooOO + O0 + I1ii11iIi11i / I11i / Ii1I * I1ii11iIi11i
    if 100 - 100: I11i
    if 82 - 82: iIii1I11I1II1
    if 19 - 19: I1IiiI
    if 66 - 66: oO0o / OoOoOO00
    if 13 - 13: II111iiii
    if 55 - 55: Oo0Ooo % i1IIi * I11i
 if ( Ooo in iiii11i ) :
  IiI , II1iIi11 , O0O0o0oO0O00 , Ooo0oo = lisp . lisp_receive ( Ooo , True )
  if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
  if ( II1iIi11 == "" ) : break
  if 63 - 63: iIii1I11I1II1 / ooOoO0o
  if ( IiI == "command" ) :
   Ooo0oo = Ooo0oo . decode ( )
   if ( Ooo0oo . find ( "learn%" ) != - 1 ) :
    iIi ( Ooo0oo )
   elif ( Ooo0oo . find ( "nat%" ) != - 1 ) :
    iiII1IIii1i1 ( Ooo0oo )
   elif ( Ooo0oo . find ( "nonce%" ) != - 1 ) :
    iII1iiiiI1i ( Ooo0oo )
   elif ( Ooo0oo . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( Ooo0oo )
   elif ( Ooo0oo . find ( "rtr%" ) != - 1 ) :
    iiIIi11ii1Ii ( Ooo0oo )
   elif ( Ooo0oo . find ( "stats%" ) != - 1 ) :
    Ooo0oo = Ooo0oo . split ( "%" ) [ - 1 ]
    lisp . lisp_process_data_plane_decap_stats ( Ooo0oo , None )
   else :
    lispconfig . lisp_process_command ( Ooo ,
 IiI , Ooo0oo , "lisp-etr" , [ IIi11I1i1I1I ] )
    if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
  elif ( IiI == "api" ) :
   Ooo0oo = Ooo0oo . decode ( )
   lisp . lisp_process_api ( "lisp-etr" , Ooo , Ooo0oo )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( Ooo0oo [ 0 : 1 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 50 - 50: II111iiii
   lisp . lisp_parse_packet ( o0oOoO00o , Ooo0oo , II1iIi11 , O0O0o0oO0O00 )
   if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
   if 44 - 44: I1IiiI
   if 55 - 55: oO0o . I1Ii111 * I1Ii111
   if 82 - 82: I1IiiI % OoO0O00 % I11i + I11i
O00o ( )
lisp . lisp_print_banner ( "ETR normal exit" )
exit ( 0 )
if 6 - 6: Oo0Ooo
if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
