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
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
def OoooooOoo ( kv_pair ) :
 global OOO0o0o
 global Ii1iI
 if 70 - 70: OoO0O00 . OoO0O00 - OoO0O00 / I1ii11iIi11i * OOooOOo
 OoO000 = lispconfig . lisp_map_server_command ( kv_pair )
 if 42 - 42: oO0o - i1IIi / i11iIiiIii + OOooOOo + OoO0O00
 if 17 - 17: oO0o . Oo0Ooo . I1ii11iIi11i
 if 3 - 3: OoOoOO00 . Oo0Ooo . I1IiiI / Ii1I
 if 38 - 38: II111iiii % i11iIiiIii . ooOoO0o - OOooOOo + Ii1I
 if 66 - 66: OoooooooOO * OoooooooOO . OOooOOo . i1IIi - OOooOOo
 o0o00ooo0 = ( len ( lisp . lisp_map_servers_list ) == 1 )
 if ( o0o00ooo0 ) :
  OoO000 = list ( lisp . lisp_map_servers_list . values ( ) ) [ 0 ]
  Ii1iI = threading . Timer ( 2 , oo0Oo00Oo0 ,
 [ OoO000 . map_server ] )
  Ii1iI . start ( )
 else :
  if 79 - 79: Oo0Ooo + I1IiiI - iII111i
  if 83 - 83: ooOoO0o
  if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
  if 74 - 74: iII111i * O0
  if 89 - 89: oO0o + Oo0Ooo
  if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
  if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
  if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
  if ( lisp . lisp_nat_traversal ) : return
  if ( OoO000 and len ( lisp . lisp_db_list ) > 0 ) :
   i1iiI11I ( o0oOoO00o , None , None , OoO000 , False )
   if 29 - 29: OoooooooOO
   if 23 - 23: o0oOOo0O0Ooo . II111iiii
   if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
   if 45 - 45: I1Ii111 . OoOoOO00
   if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
   if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
   if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
 if ( O0OoOoo00o and iiiI11 ) : return
 if 8 - 8: OoOoOO00
 if 60 - 60: I11i / I11i
 if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
 if 83 - 83: OoooooooOO
 if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 if ( len ( lisp . lisp_db_list ) > 0 ) :
  if ( OOO0o0o != None ) : return
  OOO0o0o = threading . Timer ( 5 ,
 iii11 , [ o0oOoO00o ] )
  OOO0o0o . start ( )
  if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
  if 50 - 50: I1IiiI
  if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
  if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
  if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
  if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
  if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
  if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
  if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
def oo000OO00Oo ( kv_pair ) :
 global Oo0o , OOO0o0o
 global o0oOoO00o , iiiI11
 global lisp_seen_eid_done_count
 if 51 - 51: IiII * o0oOOo0O0Ooo + I11i + OoO0O00
 if 66 - 66: OoOoOO00
 if 97 - 97: oO0o % IiII * IiII
 if 39 - 39: Ii1I % IiII
 if 4 - 4: oO0o
 if 93 - 93: OoO0O00 % oO0o . OoO0O00 * I1Ii111 % Ii1I . II111iiii
 if ( iiiI11 ) : return
 if 38 - 38: o0oOOo0O0Ooo
 lispconfig . lisp_database_mapping_command ( kv_pair , I1Ii11I1Ii1i ,
 ( O0OoOoo00o == False ) )
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
 if 26 - 26: iII111i
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
 if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
 if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
 if 91 - 91: oO0o % Oo0Ooo
 if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
 if 31 - 31: I11i - II111iiii . I11i
 if ( lisp . lisp_nat_traversal ) : return
 if ( OOO0o0o != None ) : return
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 if ( O0OoOoo00o ) :
  o0 = len ( lisp . lisp_db_list )
  if ( o0 % 1000 == 0 ) :
   lisp . fprint ( "{} database-mappings processed" . format ( o0 ) )
   if 91 - 91: iIii1I11I1II1 + I1Ii111
   if 31 - 31: IiII . OoOoOO00 . OOooOOo
  O0oOoOO = lisp . lisp_db_list [ - 1 ]
  if ( O0oOoOO . eid . is_dist_name ( ) == False ) : return
  if ( O0oOoOO . eid . address != "eid-done" ) : return
  iiiI11 = True
  if 96 - 96: Oo0Ooo
  lisp . fprint ( "Finished batch of {} database-mappings" . format ( o0 ) )
  if 45 - 45: O0 * o0oOOo0O0Ooo % Oo0Ooo * OoooooooOO + iII111i . OoOoOO00
  Oo0ooOo0o = threading . Timer ( 0 , iii11 ,
 [ o0oOoO00o ] )
  Oo0o = Oo0ooOo0o
  Oo0o . start ( )
  return
  if 22 - 22: iIii1I11I1II1 / i11iIiiIii * iIii1I11I1II1 * II111iiii . OOooOOo / i11iIiiIii
  if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
 if ( len ( lisp . lisp_map_servers_list ) > 0 ) :
  OOO0o0o = threading . Timer ( 5 ,
 iii11 , [ o0oOoO00o ] )
  OOO0o0o . start ( )
  if 52 - 52: o0oOOo0O0Ooo
  if 95 - 95: Ii1I
  if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
  if 91 - 91: O0
  if 61 - 61: II111iiii
  if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
  if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
  if 42 - 42: OoO0O00
def o0o ( clause ) :
 if 84 - 84: O0
 if 74 - 74: I1ii11iIi11i - I1IiiI - Oo0Ooo . Ii1I - IiII
 if 73 - 73: Oo0Ooo - i1IIi - i1IIi - iII111i . Ii1I + I1ii11iIi11i
 if 81 - 81: iII111i * oO0o - I1Ii111 . II111iiii % I11i / I1IiiI
 iIIiIi1iIII1 = lispconfig . lisp_show_myrlocs ( "" )
 if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
 if 49 - 49: Ii1I / OoO0O00 . II111iiii
 if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
 if 31 - 31: II111iiii . I1IiiI
 iIIiIi1iIII1 = lispconfig . lisp_show_decap_stats ( iIIiIi1iIII1 , "ETR" )
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
 if 92 - 92: iII111i
 if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 II111iiiI1Ii = lisp . lisp_decent_dns_suffix
 if ( II111iiiI1Ii == None ) :
  II111iiiI1Ii = ":"
 else :
  II111iiiI1Ii = "&nbsp;(dns-suffix '{}'):" . format ( II111iiiI1Ii )
  if 78 - 78: Ii1I % I1Ii111 + I1ii11iIi11i
  if 64 - 64: oO0o * O0 . I1IiiI + II111iiii
 IIi1i = "{} configured map-servers" . format ( len ( lisp . lisp_map_servers_list ) )
 OOOO00O0O = "LISP-ETR Configured Map-Servers{}" . format ( II111iiiI1Ii )
 OOOO00O0O = lisp . lisp_span ( OOOO00O0O , IIi1i )
 if 33 - 33: O0 . IiII . I1IiiI
 IIi1i = ( "P = proxy-reply requested, M = merge-registrations " + "requested, N = Map-Notify requested" )
 if 72 - 72: i1IIi / OoO0O00 + OoooooooOO - Oo0Ooo
 iI1Iii = lisp . lisp_span ( "Registration<br>flags" , IIi1i )
 if 68 - 68: OOooOOo % I1Ii111
 iIIiIi1iIII1 += lispconfig . lisp_table_header ( OOOO00O0O , "Address" , "Auth-Type" ,
 "xTR-ID" , "Site-ID" , iI1Iii , "Map-Registers<br>Sent" ,
 "Map-Notifies<br>Received" )
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 for OoO000 in list ( lisp . lisp_map_servers_list . values ( ) ) :
  OoO000 . resolve_dns_name ( )
  IiI111111IIII = "" if OoO000 . ms_name == "all" else OoO000 . ms_name + "<br>"
  i1Ii = IiI111111IIII + OoO000 . map_server . print_address_no_iid ( )
  if ( OoO000 . dns_name ) : i1Ii += "<br>" + OoO000 . dns_name
  if 14 - 14: iII111i
  I1iI1iIi111i = "0x" + lisp . lisp_hex_string ( OoO000 . xtr_id )
  iiIi1IIi1I = "{}-{}-{}-{}" . format ( "P" if OoO000 . proxy_reply else "p" ,
 "M" if OoO000 . merge_registrations else "m" ,
 "N" if OoO000 . want_map_notify else "n" ,
 "R" if OoO000 . refresh_registrations else "r" )
  if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
  O0ooO0Oo00o = OoO000 . map_registers_sent + OoO000 . map_registers_multicast_sent
  if 77 - 77: iIii1I11I1II1 * OoO0O00
  if 95 - 95: I1IiiI + i11iIiiIii
  iIIiIi1iIII1 += lispconfig . lisp_table_row ( i1Ii ,
 "sha1" if ( OoO000 . alg_id == lisp . LISP_SHA_1_96_ALG_ID ) else "sha2" ,
 I1iI1iIi111i , OoO000 . site_id , iiIi1IIi1I , O0ooO0Oo00o ,
 OoO000 . map_notifies_received )
  if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 iIIiIi1iIII1 += lispconfig . lisp_table_footer ( )
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 if 53 - 53: II111iiii
 if 31 - 31: OoO0O00
 iIIiIi1iIII1 = lispconfig . lisp_show_db_list ( "ETR" , iIIiIi1iIII1 )
 if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: OoO0O00
 if 62 - 62: OOooOOo + O0
 if 98 - 98: o0oOOo0O0Ooo
 if ( len ( lisp . lisp_elp_list ) != 0 ) :
  iIIiIi1iIII1 = lispconfig . lisp_show_elp_list ( iIIiIi1iIII1 )
  if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
  if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
  if 82 - 82: Ii1I
  if 46 - 46: OoooooooOO . i11iIiiIii
  if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 if ( len ( lisp . lisp_rle_list ) != 0 ) :
  iIIiIi1iIII1 = lispconfig . lisp_show_rle_list ( iIIiIi1iIII1 )
  if 87 - 87: Oo0Ooo . IiII
  if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
  if 55 - 55: OOooOOo . I1IiiI
  if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
  if 100 - 100: I1Ii111 * O0
 if ( len ( lisp . lisp_json_list ) != 0 ) :
  iIIiIi1iIII1 = lispconfig . lisp_show_json_list ( iIIiIi1iIII1 )
  if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
  if 79 - 79: O0
  if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
  if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
  if 57 - 57: OoO0O00 / ooOoO0o
 if ( len ( lisp . lisp_group_mapping_list ) != 0 ) :
  OOOO00O0O = "Configured Group Mappings:"
  iIIiIi1iIII1 += lispconfig . lisp_table_header ( OOOO00O0O , "Name" , "Group Prefix" ,
 "Sources" , "Use MS" )
  for Ii1I1Ii in list ( lisp . lisp_group_mapping_list . values ( ) ) :
   OOoO0 = ""
   for OO0Oooo0oOO0O in Ii1I1Ii . sources : OOoO0 += OO0Oooo0oOO0O + ", "
   if ( OOoO0 == "" ) :
    OOoO0 = "*"
   else :
    OOoO0 = OOoO0 [ 0 : - 2 ]
    if 62 - 62: I1IiiI
   iIIiIi1iIII1 += lispconfig . lisp_table_row ( Ii1I1Ii . group_name ,
 Ii1I1Ii . group_prefix . print_prefix ( ) , OOoO0 , Ii1I1Ii . use_ms_name )
   if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
  iIIiIi1iIII1 += lispconfig . lisp_table_footer ( )
  if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 return ( iIIiIi1iIII1 )
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 if 49 - 49: I1IiiI - I11i
 if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
def oooOo0OOOoo0 ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "ETR" ) )
 if 51 - 51: Oo0Ooo / OoOoOO00 . OOooOOo * o0oOOo0O0Ooo + OoO0O00 * IiII
 if 73 - 73: OoO0O00 + OoooooooOO - O0 - Ii1I - II111iiii
 if 99 - 99: ooOoO0o . Ii1I + I1Ii111 + OoooooooOO % o0oOOo0O0Ooo
 if 51 - 51: iIii1I11I1II1
 if 34 - 34: oO0o + I1IiiI - oO0o
 if 17 - 17: II111iiii % iII111i + I11i - iII111i / OOooOOo + ooOoO0o
 if 59 - 59: OOooOOo % OoOoOO00 . Ii1I * I1ii11iIi11i % I11i
def oO0o0o0oo ( kv_pairs ) :
 OOoO0 = [ ]
 iI1111iiii = None
 Oo0OO = None
 IiI111111IIII = "all"
 if 78 - 78: OOooOOo - OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii
 for iiI11ii1I1 in list ( kv_pairs . keys ( ) ) :
  Ooo0OOoOoO0 = kv_pairs [ iiI11ii1I1 ]
  if ( iiI11ii1I1 == "group-name" ) :
   oOo0OOoO0 = Ooo0OOoOoO0
   if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
  if ( iiI11ii1I1 == "group-prefix" ) :
   if ( iI1111iiii == None ) :
    iI1111iiii = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
   iI1111iiii . store_prefix ( Ooo0OOoOoO0 )
   if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
  if ( iiI11ii1I1 == "instance-id" ) :
   if ( iI1111iiii == None ) :
    iI1111iiii = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
   iI1111iiii . instance_id = int ( Ooo0OOoOoO0 )
   if 26 - 26: Ii1I % I1ii11iIi11i
  if ( iiI11ii1I1 == "ms-name" ) :
   IiI111111IIII = Ooo0OOoOoO0 [ 0 ]
   if 76 - 76: IiII * iII111i
  if ( iiI11ii1I1 == "address" ) :
   for ooooooo00o in Ooo0OOoOoO0 :
    if ( ooooooo00o != "" ) : OOoO0 . append ( ooooooo00o )
    if 73 - 73: OOooOOo
    if 70 - 70: iIii1I11I1II1
  if ( iiI11ii1I1 == "rle-address" ) :
   if ( Oo0OO == None ) :
    Oo0OO = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 31 - 31: IiII - I1IiiI % iIii1I11I1II1
   Oo0OO . store_address ( Ooo0OOoOoO0 )
   if 92 - 92: i1IIi - iIii1I11I1II1
   if 16 - 16: OoO0O00 - OoOoOO00 - OOooOOo - i1IIi / Ii1I
 Ii1I1Ii = lisp . lisp_group_mapping ( oOo0OOoO0 , IiI111111IIII , iI1111iiii , OOoO0 ,
 Oo0OO )
 Ii1I1Ii . add_group ( )
 return
 if 88 - 88: OoO0O00
 if 71 - 71: I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i - I1IiiI . iIii1I11I1II1 - i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
def II1IIIIiII1i ( quiet , db , eid , group , ttl ) :
 if 1 - 1: II111iiii
 if 68 - 68: iII111i - I1IiiI / I1Ii111 / I11i
 if 12 - 12: Ii1I + i11iIiiIii * iIii1I11I1II1 / I1ii11iIi11i . I11i
 if 5 - 5: i1IIi + IiII / o0oOOo0O0Ooo . iII111i / I11i
 if 32 - 32: I1IiiI % iIii1I11I1II1 / i1IIi - I1IiiI
 if 7 - 7: I1Ii111 * OoO0O00 - ooOoO0o + OOooOOo * I1IiiI % OoO0O00
 if 15 - 15: OoOoOO00 % I1IiiI * I11i
 if 81 - 81: ooOoO0o - iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * I11i
 iI1i11II1i = { }
 for o0o0OoOo0O0OO in db . rloc_set :
  if ( o0o0OoOo0O0OO . translated_rloc . is_null ( ) ) : continue
  if 36 - 36: OoOoOO00 - O0
  for o0OOOooo0OOo in lisp . lisp_rtr_list :
   iII1i11IIi1i = lisp . lisp_rtr_list [ o0OOOooo0OOo ]
   if ( lisp . lisp_register_all_rtrs == False and iII1i11IIi1i == None ) :
    lisp . lprint ( "  Exclude unreachable RTR {}" . format ( lisp . red ( o0OOOooo0OOo , False ) ) )
    if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
    continue
    if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
   if ( iII1i11IIi1i == None ) : continue
   iI1i11II1i [ o0OOOooo0OOo ] = iII1i11IIi1i
   if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
  break
  if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
  if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
 O00oOOooo = 0
 iI1iIii11Ii = b""
 for IIi1i1I11Iii in [ eid . instance_id ] + eid . iid_list :
  I1i1i1 = lisp . lisp_eid_record ( )
  if 73 - 73: O0 * iII111i + Ii1I + ooOoO0o
  I1i1i1 . rloc_count = len ( db . rloc_set ) + len ( iI1i11II1i )
  I1i1i1 . authoritative = True
  I1i1i1 . record_ttl = ttl
  I1i1i1 . eid . copy_address ( eid )
  I1i1i1 . eid . instance_id = IIi1i1I11Iii
  I1i1i1 . eid . iid_list = [ ]
  I1i1i1 . group . copy_address ( group )
  if 40 - 40: II111iiii . OoOoOO00 * I1Ii111 + OOooOOo + OOooOOo
  iI1iIii11Ii += I1i1i1 . encode ( )
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
   I1i1i1 . print_record ( "  " , False )
   if 91 - 91: OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoOoOO00 + O0
   if 26 - 26: I1ii11iIi11i - OoooooooOO
  for o0o0OoOo0O0OO in db . rloc_set :
   iiI1iI111ii1i = lisp . lisp_rloc_record ( )
   iiI1iI111ii1i . store_rloc_entry ( o0o0OoOo0O0OO )
   iiI1iI111ii1i . local_bit = o0o0OoOo0O0OO . rloc . is_local ( )
   iiI1iI111ii1i . reach_bit = True
   iI1iIii11Ii += iiI1iI111ii1i . encode ( )
   if ( not quiet ) : iiI1iI111ii1i . print_record ( "    " )
   if 32 - 32: II111iiii * OoOoOO00 % i1IIi - iII111i + iIii1I11I1II1 + I1ii11iIi11i
   if 60 - 60: I1ii11iIi11i % OoOoOO00 * OoO0O00 % II111iiii
   if 70 - 70: OoO0O00 % oO0o + OOooOOo / Ii1I % O0
   if 100 - 100: o0oOOo0O0Ooo + OOooOOo * o0oOOo0O0Ooo
   if 80 - 80: o0oOOo0O0Ooo * O0 - Ii1I
   if 66 - 66: i11iIiiIii - OOooOOo * Oo0Ooo
  for iII1i11IIi1i in list ( iI1i11II1i . values ( ) ) :
   iiI1iI111ii1i = lisp . lisp_rloc_record ( )
   iiI1iI111ii1i . rloc . copy_address ( iII1i11IIi1i )
   iiI1iI111ii1i . priority = 254
   iiI1iI111ii1i . rloc_name = "RTR"
   iiI1iI111ii1i . weight = 0
   iiI1iI111ii1i . mpriority = 255
   iiI1iI111ii1i . mweight = 0
   iiI1iI111ii1i . local_bit = False
   iiI1iI111ii1i . reach_bit = True
   iI1iIii11Ii += iiI1iI111ii1i . encode ( )
   if ( not quiet ) : iiI1iI111ii1i . print_record ( "    RTR " )
   if 76 - 76: i11iIiiIii + o0oOOo0O0Ooo / I1ii11iIi11i - OoO0O00 - Ii1I + I1ii11iIi11i
   if 51 - 51: iIii1I11I1II1 . ooOoO0o + iIii1I11I1II1
   if 95 - 95: I1IiiI
   if 46 - 46: OoOoOO00 + OoO0O00
   if 70 - 70: iII111i / iIii1I11I1II1
  O00oOOooo += 1
  if 85 - 85: OoooooooOO % i1IIi * OoooooooOO / I1ii11iIi11i
 return ( iI1iIii11Ii , O00oOOooo )
 if 96 - 96: OoooooooOO + oO0o
 if 44 - 44: oO0o
 if 20 - 20: I11i + Ii1I / O0 % iIii1I11I1II1
 if 88 - 88: OoOoOO00 / II111iiii
 if 87 - 87: I1ii11iIi11i - I1ii11iIi11i - iII111i + oO0o
 if 82 - 82: oO0o / iIii1I11I1II1 . I1IiiI . OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
def i1iiI11I ( lisp_sockets , ttl , eid_only , ms_only , refresh ) :
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
 if ( O0OoOoo00o ) :
  lisp . fprint ( "Build Map-Register for {} database-mapping entries" . format ( IIii11I1i1I ) )
  if 82 - 82: Ii1I * iII111i / I1ii11iIi11i
 else :
  lisp . fprint ( "Build Map-Register for {} database-mapping entries" . format ( IIii11I1i1I ) )
  if 36 - 36: OoooooooOO - i1IIi . O0 / II111iiii + o0oOOo0O0Ooo
  if 33 - 33: II111iiii / ooOoO0o * O0 % Ii1I * I1Ii111
  if 100 - 100: IiII . I11i / Ii1I % OoOoOO00 % II111iiii - OoO0O00
  if 46 - 46: O0 * II111iiii - Oo0Ooo * ooOoO0o
  if 33 - 33: Ii1I
  if 74 - 74: OOooOOo + O0 + i1IIi - i1IIi + II111iiii
 oOOO0oo0 = lisp . lisp_decent_pull_xtr_configured ( )
 if 46 - 46: IiII
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if 17 - 17: OOooOOo / OOooOOo / I11i
 ii1 = ( IIii11I1i1I > 12 )
 if 1 - 1: ooOoO0o % iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % I1IiiI
 o0o0oOoOO0O = { }
 if ( oOOO0oo0 ) :
  if 16 - 16: IiII % iIii1I11I1II1 . Ii1I
  if 59 - 59: I1IiiI * II111iiii . O0
  if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
  if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
  if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
  for O0oOoOO in lisp . lisp_db_list :
   i1OO0oOOoo = O0oOoOO . eid if O0oOoOO . group . is_null ( ) else O0oOoOO . group
   oOOO00o000o = lisp . lisp_get_decent_dns_name ( i1OO0oOOoo )
   o0o0oOoOO0O [ oOOO00o000o ] = [ ]
   if 9 - 9: oO0o + I11i / I11i
 else :
  if 12 - 12: OoooooooOO % o0oOOo0O0Ooo * I11i % iIii1I11I1II1 / Ii1I
  if 27 - 27: i11iIiiIii % II111iiii % I11i . O0 - Oo0Ooo + OoOoOO00
  if 57 - 57: iIii1I11I1II1 / I11i - i1IIi
  if 51 - 51: IiII
  if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
  for OoO000 in list ( lisp . lisp_map_servers_list . values ( ) ) :
   if ( ms_only != None and OoO000 != ms_only ) : continue
   o0o0oOoOO0O [ OoO000 . ms_name ] = [ ]
   if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
   if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
   if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
   if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
   if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
   if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
 oo000 = lisp . lisp_map_register ( )
 oo000 . nonce = 0xaabbccdddfdfdf00
 oo000 . xtr_id_present = True
 oo000 . use_ttl_for_timeout = True
 if 32 - 32: i1IIi . Ii1I
 if ( ttl == None ) : ttl = lisp . LISP_REGISTER_TTL
 if 59 - 59: OoooooooOO
 if 47 - 47: ooOoO0o - I1IiiI / II111iiii
 if 12 - 12: OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 oO0oO0 = 65000 if ( O0OoOoo00o ) else 1100
 for O0oOoOO in lisp . lisp_db_list :
  if ( oOOO0oo0 ) :
   i1i1IIIIi1i = lisp . lisp_get_decent_dns_name ( O0oOoOO . eid )
  else :
   i1i1IIIIi1i = O0oOoOO . use_ms_name
   if 7 - 7: iIii1I11I1II1 + iII111i * i11iIiiIii / OoooooooOO + iII111i - Oo0Ooo
   if 3 - 3: i1IIi / II111iiii / i11iIiiIii * i1IIi - II111iiii
   if 42 - 42: II111iiii . OoooooooOO . o0oOOo0O0Ooo * oO0o
   if 81 - 81: Ii1I * o0oOOo0O0Ooo + I1Ii111 + Oo0Ooo - OoooooooOO
   if 32 - 32: Ii1I * O0
   if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
  if ( i1i1IIIIi1i not in o0o0oOoOO0O ) : continue
  if 92 - 92: ooOoO0o
  II11iI111i1 = o0o0oOoOO0O [ i1i1IIIIi1i ]
  if ( II11iI111i1 == [ ] ) :
   II11iI111i1 = [ b"" , 0 ]
   o0o0oOoOO0O [ i1i1IIIIi1i ] . append ( II11iI111i1 )
  else :
   II11iI111i1 = o0o0oOoOO0O [ i1i1IIIIi1i ] [ - 1 ]
   if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
   if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
   if 92 - 92: I11i . I1Ii111
   if 85 - 85: I1ii11iIi11i . I1Ii111
   if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
   if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
   if 18 - 18: iIii1I11I1II1 % I11i
   if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
   if 75 - 75: OoooooooOO * IiII
   if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
  iI1iIii11Ii = b""
  if ( O0oOoOO . dynamic_eid_configured ( ) ) :
   for I1IIIiI1I1ii1 in list ( O0oOoOO . dynamic_eids . values ( ) ) :
    i1OO0oOOoo = I1IIIiI1I1ii1 . dynamic_eid
    if ( eid_only == None or eid_only . is_exact_match ( i1OO0oOOoo ) ) :
     iiiI1I1iIIIi1 , O00oOOooo = II1IIIIiII1i ( ii1 , O0oOoOO ,
 i1OO0oOOoo , O0oOoOO . group , ttl )
     iI1iIii11Ii += iiiI1I1iIIIi1
     II11iI111i1 [ 1 ] += O00oOOooo
     if 17 - 17: iIii1I11I1II1 . OoooooooOO / I11i % II111iiii % i1IIi / i11iIiiIii
     if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
  else :
   if ( eid_only == None ) :
    if ( ttl != 0 ) : ttl = O0oOoOO . register_ttl
    iI1iIii11Ii , O00oOOooo = II1IIIIiII1i ( ii1 , O0oOoOO ,
 O0oOoOO . eid , O0oOoOO . group , ttl )
    II11iI111i1 [ 1 ] += O00oOOooo
    if 85 - 85: OoOoOO00 + OOooOOo
    if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
    if 27 - 27: Ii1I
    if 67 - 67: I1IiiI
    if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
    if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
  II11iI111i1 [ 0 ] += iI1iIii11Ii
  if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
  if ( II11iI111i1 [ 1 ] == 20 or len ( II11iI111i1 [ 0 ] ) > oO0oO0 ) :
   II11iI111i1 = [ b"" , 0 ]
   o0o0oOoOO0O [ i1i1IIIIi1i ] . append ( II11iI111i1 )
   if 92 - 92: Oo0Ooo
   if 40 - 40: OoOoOO00 / IiII
   if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
   if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
   if 61 - 61: II111iiii
   if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 oooO0o0o0O0 = .500 if ( O0OoOoo00o ) else .001
 O00oOOooo = 0
 for OoO000 in list ( lisp . lisp_map_servers_list . values ( ) ) :
  if ( ms_only != None and OoO000 != ms_only ) : continue
  if 27 - 27: OoooooooOO - iII111i / I11i
  i1i1IIIIi1i = OoO000 . dns_name if oOOO0oo0 else OoO000 . ms_name
  if ( i1i1IIIIi1i not in o0o0oOoOO0O ) : continue
  if 76 - 76: o0oOOo0O0Ooo % I1IiiI . iIii1I11I1II1 - IiII * OoooooooOO . iII111i
  for II11iI111i1 in o0o0oOoOO0O [ i1i1IIIIi1i ] :
   if 84 - 84: I1Ii111 + I11i
   if 28 - 28: oO0o - i11iIiiIii . I1ii11iIi11i + IiII / I1ii11iIi11i
   if 35 - 35: IiII
   if 75 - 75: Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
   oo000 . record_count = II11iI111i1 [ 1 ]
   if ( oo000 . record_count == 0 ) : continue
   if 41 - 41: Ii1I
   oo000 . nonce += 1
   oo000 . alg_id = OoO000 . alg_id
   oo000 . key_id = OoO000 . key_id
   oo000 . proxy_reply_requested = OoO000 . proxy_reply
   oo000 . merge_register_requested = OoO000 . merge_registrations
   oo000 . map_notify_requested = OoO000 . want_map_notify
   oo000 . xtr_id = OoO000 . xtr_id
   oo000 . site_id = OoO000 . site_id
   oo000 . encrypt_bit = ( OoO000 . ekey != None )
   if ( OoO000 . refresh_registrations ) :
    oo000 . map_register_refresh = refresh
    if 77 - 77: I1Ii111
   if ( OoO000 . ekey != None ) : oo000 . encryption_key_id = OoO000 . ekey_id
   OooOOOOoO00OoOO = oo000 . encode ( )
   oo000 . print_map_register ( )
   if 85 - 85: oO0o - iIii1I11I1II1 / O0
   if 99 - 99: II111iiii * IiII % iIii1I11I1II1 / Ii1I
   if 90 - 90: oO0o % OOooOOo - OOooOOo % II111iiii * OoO0O00
   if 39 - 39: I11i
   if 58 - 58: i1IIi % o0oOOo0O0Ooo
   OO000oooo0 = oo000 . encode_xtr_id ( b"" )
   iI1iIii11Ii = II11iI111i1 [ 0 ]
   OooOOOOoO00OoOO = OooOOOOoO00OoOO + iI1iIii11Ii + OO000oooo0
   if 77 - 77: I1IiiI % O0
   OoO000 . map_registers_sent += 1
   lisp . lisp_send_map_register ( lisp_sockets , OooOOOOoO00OoOO , oo000 , OoO000 )
   if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
   O00oOOooo += 1
   if ( O00oOOooo % 100 == 0 and O0OoOoo00o ) :
    oooO0o0o0O0 += .1
    lisp . fprint ( "Sent {} Map-Registers, ipd {}" . format ( O00oOOooo ,
 oooO0o0o0O0 ) )
    if 95 - 95: IiII
   time . sleep ( oooO0o0o0O0 )
   if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
   if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
  if ( O0OoOoo00o ) :
   lisp . fprint ( "Sent total {} Map-Registers" . format ( O00oOOooo ) )
   if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
   if 2 - 2: OoooooooOO % OOooOOo
   if 63 - 63: I1IiiI % iIii1I11I1II1
   if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
   if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
  OoO000 . resolve_dns_name ( )
  if 59 - 59: OOooOOo + i11iIiiIii
  if 88 - 88: i11iIiiIii - ooOoO0o
  if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
  if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
  if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
  if ( ms_only != None and OoO000 == ms_only ) : break
  if 30 - 30: OoOoOO00
 return
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if 10 - 10: II111iiii . iII111i
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 if 88 - 88: iII111i
 if 19 - 19: II111iiii * IiII + Ii1I
 if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
 if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
 if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
def oo0Oo00Oo0 ( ms ) :
 global Ii1iI
 global Oo
 if 67 - 67: I11i - OOooOOo . i1IIi
 lisp . lisp_set_exception ( )
 if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
 if 87 - 87: OoOoOO00
 if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
 if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
 if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
 OO0o0oO = [ Oo , Oo , Ooo ]
 lisp . lisp_build_info_requests ( OO0o0oO , ms , lisp . LISP_CTRL_PORT )
 if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
 if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
 if 93 - 93: Ii1I - OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
 if 49 - 49: OoooooooOO * I11i - Oo0Ooo . oO0o
 if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
 i11i11 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) == None )
 for iII1i11IIi1i in list ( lisp . lisp_rtr_list . values ( ) ) :
  if ( iII1i11IIi1i == None ) : continue
  if ( iII1i11IIi1i . is_private_address ( ) and i11i11 == False ) :
   OoOoO00O0 = lisp . red ( iII1i11IIi1i . print_address_no_iid ( ) , False )
   lisp . lprint ( "Skip over RTR private address {}" . format ( OoOoO00O0 ) )
   continue
   if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
  lisp . lisp_build_info_requests ( OO0o0oO , iII1i11IIi1i , lisp . LISP_DATA_PORT )
  if 29 - 29: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / iII111i
  if 70 - 70: i11iIiiIii % iII111i
  if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
  if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
  if 76 - 76: Ii1I - II111iiii * OOooOOo / OoooooooOO
  if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 Ii1iI . cancel ( )
 Ii1iI = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 oo0Oo00Oo0 , [ None ] )
 Ii1iI . start ( )
 return
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
def iii11 ( lisp_sockets ) :
 global Oo0o , OOO0o0o
 global Oo
 if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 lisp . lisp_set_exception ( )
 if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
 if 34 - 34: O0
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 i1iiI11I ( lisp_sockets , None , None , None , True )
 if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
 if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
 if 91 - 91: oO0o + OoooooooOO - i1IIi
 if 84 - 84: Ii1I / IiII
 if ( lisp . lisp_l2_overlay ) :
  OOOooo0OooOoO = [ None , "ffff-ffff-ffff" , True ]
  oOoOOOo ( lisp_sockets , [ OOOooo0OooOoO ] )
  if 43 - 43: i1IIi
  if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
  if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
  if 8 - 8: o0oOOo0O0Ooo
  if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
  if 78 - 78: Ii1I / II111iiii % OoOoOO00
 if ( OOO0o0o != None ) :
  OOO0o0o . cancel ( )
  OOO0o0o = None
  if 52 - 52: OOooOOo - iII111i * oO0o
  if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
  if 36 - 36: O0 + Oo0Ooo
  if 5 - 5: Oo0Ooo * OoOoOO00
  if 46 - 46: ooOoO0o
 if ( Oo0o ) : Oo0o . cancel ( )
 Oo0o = threading . Timer ( I11 ,
 iii11 , [ o0oOoO00o ] )
 Oo0o . start ( )
 return
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
 if 63 - 63: I1ii11iIi11i
 if 6 - 6: ooOoO0o / I1ii11iIi11i
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
 if 87 - 87: oO0o % Ii1I
 if 83 - 83: II111iiii - I11i
def oOoOOOo ( lisp_sockets , entries ) :
 iiIii1IIi = len ( entries )
 if ( iiIii1IIi == 0 ) : return
 if 10 - 10: i11iIiiIii - o0oOOo0O0Ooo % iIii1I11I1II1
 i111IIIiI = None
 if ( entries [ 0 ] [ 1 ] . find ( ":" ) != - 1 ) : i111IIIiI = lisp . LISP_AFI_IPV6
 if ( entries [ 0 ] [ 1 ] . find ( "." ) != - 1 ) : i111IIIiI = lisp . LISP_AFI_IPV4
 if ( entries [ 0 ] [ 1 ] . find ( "-" ) != - 1 ) : i111IIIiI = lisp . LISP_AFI_MAC
 if ( i111IIIiI == None ) :
  lisp . lprint ( "lisp_send_multicast_map_register() invalid group address" )
  return
  if 23 - 23: Oo0Ooo % I11i - OOooOOo % iIii1I11I1II1 . OoOoOO00
  if 24 - 24: IiII / OoooooooOO + Ii1I % iIii1I11I1II1 - OOooOOo . OOooOOo
  if 32 - 32: OOooOOo . IiII / OoO0O00
  if 37 - 37: Ii1I % OoO0O00
  if 79 - 79: I1ii11iIi11i + I1IiiI / I1IiiI
  if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
  if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
  if 23 - 23: i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo - I1ii11iIi11i % iII111i * OoO0O00 - OOooOOo / iII111i
 iIiiiiii1 = [ ]
 for ooooooo00o , oOO0oo , II1iIi1IiIii in entries :
  if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
  iIiiiiii1 . append ( [ oOO0oo , II1iIi1IiIii ] )
  if 46 - 46: i11iIiiIii - O0 . oO0o
  if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 oOOO0oo0 = lisp . lisp_decent_pull_xtr_configured ( )
 if 83 - 83: I1Ii111
 o0o0oOoOO0O = { }
 entries = [ ]
 for oOO0oo , II1iIi1IiIii in iIiiiiii1 :
  ii111Ii11iii = lisp . lisp_lookup_group ( oOO0oo )
  if ( ii111Ii11iii == None ) :
   lisp . lprint ( "No group-mapping for {}, could be underlay group" . format ( oOO0oo ) )
   if 62 - 62: iIii1I11I1II1
   continue
   if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
   if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
  lisp . lprint ( "Use group-mapping '{}' {} for group {}" . format ( ii111Ii11iii . group_name , ii111Ii11iii . group_prefix . print_prefix ( ) , oOO0oo ) )
  if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
  if 62 - 62: i1IIi - OoOoOO00
  IIi1i1I11Iii = ii111Ii11iii . group_prefix . instance_id
  IiI111111IIII = ii111Ii11iii . use_ms_name
  oo0O0oo = ii111Ii11iii . rle_address
  if 14 - 14: O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
  if 96 - 96: iII111i
  if 18 - 18: iII111i * I11i - Ii1I
  if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
  iii1III1i = IiI111111IIII
  if ( oOOO0oo0 ) :
   iii1III1i = lisp . lisp_get_decent_dns_name_from_str ( IIi1i1I11Iii , oOO0oo )
   o0o0oOoOO0O [ iii1III1i ] = [ b"" , 0 ]
   if 17 - 17: II111iiii / II111iiii
   if 65 - 65: IiII + Oo0Ooo
  if ( len ( ii111Ii11iii . sources ) == 0 ) :
   entries . append ( [ "0.0.0.0" , oOO0oo , IIi1i1I11Iii , iii1III1i , oo0O0oo , II1iIi1IiIii ] )
   continue
   if 59 - 59: OoooooooOO + I11i . I1Ii111 - O0 % iIii1I11I1II1 / O0
  for OO0Oooo0oOO0O in ii111Ii11iii . sources :
   o0o0oOoOO0O [ iii1III1i ] = [ b"" , 0 ]
   entries . append ( [ OO0Oooo0oOO0O , oOO0oo , IIi1i1I11Iii , iii1III1i , oo0O0oo , II1iIi1IiIii ] )
   if 88 - 88: Oo0Ooo . O0 % OoooooooOO / OOooOOo
   if 89 - 89: II111iiii / oO0o
   if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 iiIii1IIi = len ( entries )
 if ( iiIii1IIi == 0 ) : return
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 lisp . lprint ( "Build Map-Register for {} multicast entries" . format ( iiIii1IIi ) )
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
 if 54 - 54: II111iiii . I11i
 oOO = lisp . lisp_rle_node ( )
 oOO . level = 128
 II1i11i1iIi11 = lisp . lisp_get_any_translated_rloc ( )
 oo0O0oo = lisp . lisp_rle ( "" )
 oo0O0oo . rle_nodes . append ( oOO )
 if 83 - 83: Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
 if ( oOOO0oo0 == False ) :
  for OoO000 in list ( lisp . lisp_map_servers_list . values ( ) ) :
   o0o0oOoOO0O [ OoO000 . ms_name ] = [ b"" , 0 ]
   if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
   if 63 - 63: oO0o
   if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 iIIi1iiI1i11 = None
 if ( lisp . lisp_nat_traversal ) : iIIi1iiI1i11 = lisp . lisp_hostname
 if 56 - 56: OoooooooOO
 if 30 - 30: i11iIiiIii + oO0o
 if 38 - 38: IiII . Ii1I
 if 24 - 24: o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
 I1 = 0
 for iII1i11IIi1i in list ( lisp . lisp_rtr_list . values ( ) ) :
  if ( iII1i11IIi1i == None ) : continue
  I1 += 1
  if 13 - 13: OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - Oo0Ooo / oO0o
  if 8 - 8: OoOoOO00 / O0 * O0 % I1Ii111 - Oo0Ooo + I11i
  if 83 - 83: O0 . I1IiiI
  if 95 - 95: I11i . OoooooooOO - i1IIi - OoooooooOO - OoO0O00 % iIii1I11I1II1
  if 64 - 64: OOooOOo + OoooooooOO * OoooooooOO
 iI1iIii11Ii = b""
 for ooooooo00o , oOO0oo , IIi1i1I11Iii , i1i1IIIIi1i , i1I , II1iIi1IiIii in entries :
  if 36 - 36: I1IiiI * Oo0Ooo
  if 77 - 77: oO0o % i1IIi - Ii1I
  if 93 - 93: OoO0O00 * Oo0Ooo
  if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
  if ( i1i1IIIIi1i not in o0o0oOoOO0O ) : continue
  if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
  I1i1i1 = lisp . lisp_eid_record ( )
  I1i1i1 . rloc_count = 1 + I1
  I1i1i1 . authoritative = True
  I1i1i1 . record_ttl = lisp . LISP_REGISTER_TTL if II1iIi1IiIii else 0
  I1i1i1 . eid = lisp . lisp_address ( i111IIIiI , ooooooo00o , 0 , IIi1i1I11Iii )
  if ( I1i1i1 . eid . address == 0 ) : I1i1i1 . eid . mask_len = 0
  I1i1i1 . group = lisp . lisp_address ( i111IIIiI , oOO0oo , 0 , IIi1i1I11Iii )
  if ( I1i1i1 . group . is_mac_broadcast ( ) and I1i1i1 . eid . address == 0 ) : I1i1i1 . eid . mask_len = 0
  if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
  if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
  iiI = ""
  IiI111111IIII = ""
  if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
   iiI = lisp . lisp_get_decent_index ( I1i1i1 . group )
   iiI = lisp . bold ( str ( iiI ) , False )
   iiI = "with decent-index {}" . format ( iiI )
  else :
   iiI = "for ms-name '{}'" . format ( i1i1IIIIi1i )
   if 87 - 87: oO0o - i11iIiiIii
   if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
  iIIIIiiIii = lisp . green ( I1i1i1 . print_eid_tuple ( ) , False )
  lisp . lprint ( "  EID-prefix {} {}{}" . format ( iIIIIiiIii , IiI111111IIII ,
 iiI ) )
  if 58 - 58: Oo0Ooo
  iI1iIii11Ii += I1i1i1 . encode ( )
  I1i1i1 . print_record ( "  " , False )
  o0o0oOoOO0O [ i1i1IIIIi1i ] [ 1 ] += 1
  if 9 - 9: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo + OoooooooOO
  if 62 - 62: O0 / I1IiiI % O0 * OoO0O00 % I1IiiI
  if 33 - 33: I1IiiI . oO0o * OoO0O00 * iIii1I11I1II1
  if 5 - 5: Oo0Ooo / IiII % O0 . I1Ii111 * IiII
  iiI1iI111ii1i = lisp . lisp_rloc_record ( )
  iiI1iI111ii1i . rloc_name = iIIi1iiI1i11
  if 83 - 83: OOooOOo
  if 12 - 12: i1IIi . i1IIi - o0oOOo0O0Ooo
  if 26 - 26: iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
  if 67 - 67: OoooooooOO
  if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
  if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
  if ( II1i11i1iIi11 != None ) :
   oOO . address = II1i11i1iIi11
  elif ( i1I != None ) :
   oOO . address = i1I
  else :
   oOO . address = i1I = lisp . lisp_myrlocs [ 0 ]
   if 93 - 93: i1IIi
   if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
  iiI1iI111ii1i . rle = oo0O0oo
  iiI1iI111ii1i . local_bit = True
  iiI1iI111ii1i . reach_bit = True
  iiI1iI111ii1i . priority = 255
  iiI1iI111ii1i . weight = 0
  iiI1iI111ii1i . mpriority = 1
  iiI1iI111ii1i . mweight = 100
  iI1iIii11Ii += iiI1iI111ii1i . encode ( )
  iiI1iI111ii1i . print_record ( "    " )
  if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
  if 66 - 66: Oo0Ooo
  if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
  if 55 - 55: o0oOOo0O0Ooo . iII111i
  if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
  for iII1i11IIi1i in list ( lisp . lisp_rtr_list . values ( ) ) :
   if ( iII1i11IIi1i == None ) : continue
   iiI1iI111ii1i = lisp . lisp_rloc_record ( )
   iiI1iI111ii1i . rloc . copy_address ( iII1i11IIi1i )
   iiI1iI111ii1i . priority = 254
   iiI1iI111ii1i . rloc_name = "RTR"
   iiI1iI111ii1i . weight = 0
   iiI1iI111ii1i . mpriority = 255
   iiI1iI111ii1i . mweight = 0
   iiI1iI111ii1i . local_bit = False
   iiI1iI111ii1i . reach_bit = True
   iI1iIii11Ii += iiI1iI111ii1i . encode ( )
   iiI1iI111ii1i . print_record ( "    RTR " )
   if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
   if 89 - 89: OoO0O00 + IiII * I1Ii111
   if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
   if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
   if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
  o0o0oOoOO0O [ i1i1IIIIi1i ] [ 0 ] += iI1iIii11Ii
  if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
  if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
  if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
  if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
  if 62 - 62: o0oOOo0O0Ooo
 oo000 = lisp . lisp_map_register ( )
 oo000 . nonce = 0xaabbccdddfdfdf00
 oo000 . xtr_id_present = True
 oo000 . proxy_reply_requested = True
 oo000 . map_notify_requested = False
 oo000 . merge_register_requested = True
 if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
 if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 for OoO000 in list ( lisp . lisp_map_servers_list . values ( ) ) :
  iii1III1i = OoO000 . dns_name if oOOO0oo0 else OoO000 . ms_name
  if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
  if 87 - 87: OoO0O00 % I1IiiI
  if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
  if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
  if ( iii1III1i not in o0o0oOoOO0O ) : continue
  if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
  if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
  if 84 - 84: i11iIiiIii * OoO0O00
  if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
  oo000 . record_count = o0o0oOoOO0O [ iii1III1i ] [ 1 ]
  if ( oo000 . record_count == 0 ) : continue
  if 30 - 30: O0 + I1ii11iIi11i + II111iiii
  oo000 . nonce += 1
  oo000 . alg_id = OoO000 . alg_id
  oo000 . alg_id = OoO000 . key_id
  oo000 . xtr_id = OoO000 . xtr_id
  oo000 . site_id = OoO000 . site_id
  oo000 . encrypt_bit = ( OoO000 . ekey != None )
  OooOOOOoO00OoOO = oo000 . encode ( )
  oo000 . print_map_register ( )
  if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
  if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
  if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  if 64 - 64: i1IIi
  OO000oooo0 = oo000 . encode_xtr_id ( b"" )
  OooOOOOoO00OoOO = OooOOOOoO00OoOO + iI1iIii11Ii + OO000oooo0
  if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
  OoO000 . map_registers_multicast_sent += 1
  lisp . lisp_send_map_register ( lisp_sockets , OooOOOOoO00OoOO , oo000 , OoO000 )
  if 18 - 18: OOooOOo + I1Ii111
  if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
  if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
  OoO000 . resolve_dns_name ( )
  if 50 - 50: ooOoO0o + i1IIi
  if 31 - 31: Ii1I
  if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
  if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
  time . sleep ( .001 )
  if 47 - 47: o0oOOo0O0Ooo
 return
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
def i1II11Iii1I ( parms , not_used , packet ) :
 global Ooo , o0oOoO00o
 if 92 - 92: OOooOOo % IiII % OoOoOO00
 iIi1Ii = parms [ 0 ]
 i1 = parms [ 1 ]
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if 38 - 38: O0 - IiII % I1Ii111
 if 64 - 64: iIii1I11I1II1
 if ( lisp . lisp_is_macos ( ) == False ) :
  IIi1iI = 4 if iIi1Ii == "lo0" else 16
  packet = packet [ IIi1iI : : ]
  if 92 - 92: OoO0O00 * ooOoO0o
  if 35 - 35: i11iIiiIii
  if 99 - 99: II111iiii . o0oOOo0O0Ooo + O0
  if 71 - 71: IiII + i1IIi * Oo0Ooo % Oo0Ooo / Oo0Ooo
  if 55 - 55: OoooooooOO + I1Ii111 + OoooooooOO * ooOoO0o
 oo = struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ]
 if ( oo == 2 ) :
  o0oOOO0 = lisp . lisp_process_igmp_packet ( packet )
  if ( type ( o0oOOO0 ) != bool ) :
   oOoOOOo ( o0oOoO00o , o0oOOO0 )
   return
   if 61 - 61: o0oOOo0O0Ooo / OoOoOO00 - Oo0Ooo
   if 19 - 19: iII111i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + Oo0Ooo
   if 98 - 98: iIii1I11I1II1 % OOooOOo + I11i . ooOoO0o
   if 99 - 99: O0 + O0 * I11i + O0 * oO0o
   if 80 - 80: I1IiiI . Ii1I
   if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 OOoOoo00Oo = packet
 packet , ooooooo00o , Iiii1iiiIiI1 , I11Iii1 = lisp . lisp_is_rloc_probe ( packet , 0 )
 if ( OOoOoo00Oo != packet ) :
  if ( ooooooo00o == None ) : return
  lisp . lisp_parse_packet ( o0oOoO00o , packet , ooooooo00o , Iiii1iiiIiI1 , I11Iii1 )
  return
  if 16 - 16: Ii1I * OoO0O00 / oO0o
  if 22 - 22: oO0o + iIii1I11I1II1 % Oo0Ooo / I11i / Ii1I
  if 54 - 54: OoOoOO00 % IiII . i11iIiiIii
  if 93 - 93: ooOoO0o % i11iIiiIii % I1Ii111
  if 64 - 64: I1Ii111 + I1IiiI * O0 / Oo0Ooo - I11i % I11i
  if 59 - 59: OOooOOo + OoooooooOO
  if 55 - 55: i11iIiiIii % iIii1I11I1II1 . i1IIi + OoooooooOO / i11iIiiIii
 if ( struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ] & 0xf0 == 0x40 ) :
  I11I1i1iI = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
  if ( lisp . lisp_nat_traversal and I11I1i1iI == lisp . LISP_DATA_PORT ) : return
  packet = lisp . lisp_reassemble ( packet )
  if ( packet == None ) : return
  if 90 - 90: IiII * II111iiii % I1Ii111 + oO0o
  if 93 - 93: I1Ii111 + Ii1I
 packet = lisp . lisp_packet ( packet )
 i1i1 = packet . decode ( True , Ooo , lisp . lisp_decap_stats )
 if ( i1i1 == None ) : return
 if 27 - 27: I1Ii111 + OoooooooOO - OoOoOO00
 if 15 - 15: oO0o / I11i * O0 . II111iiii - OoO0O00
 if 90 - 90: oO0o
 if 94 - 94: I11i / I1ii11iIi11i * I1Ii111 - OoOoOO00
 packet . print_packet ( "Receive" , True )
 if 44 - 44: Ii1I % i11iIiiIii - iII111i * I1ii11iIi11i + Oo0Ooo * OOooOOo
 if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
 if 65 - 65: Oo0Ooo . OoooooooOO
 if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
 if 55 - 55: iII111i - OoO0O00
 if 100 - 100: O0
 if 79 - 79: iIii1I11I1II1
 if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
  ooooooo00o = packet . inner_source . print_address_no_iid ( )
  packet . strip_outer_headers ( )
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , ooooooo00o , I11I1i1iI )
  lisp . lisp_ipc ( packet , Ooo , "lisp-ms" )
  return
  if 11 - 11: i1IIi % OoO0O00 % iII111i
  if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
  if 13 - 13: OoO0O00
  if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
  if 2 - 2: OoooooooOO . OOooOOo . IiII
  if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
  if 19 - 19: oO0o * I1IiiI % i11iIiiIii
  if 24 - 24: o0oOOo0O0Ooo
  if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
  if 28 - 28: OOooOOo % ooOoO0o
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  iiIiII11i1 = packet . packet [ 36 : : ]
  oOo00Ooo0o0 = iiIiII11i1 [ 28 : : ]
  I11Iii1 = - 1
  if ( lisp . lisp_is_rloc_probe_request ( oOo00Ooo0o0 [ 0 : 1 ] ) ) :
   I11Iii1 = struct . unpack ( "B" , iiIiII11i1 [ 8 : 9 ] ) [ 0 ] - 1
   if 33 - 33: I11i
  ooooooo00o = packet . outer_source . print_address_no_iid ( )
  lisp . lisp_parse_packet ( o0oOoO00o , oOo00Ooo0o0 , ooooooo00o , 0 , I11Iii1 )
  return
  if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
  if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
  if 21 - 21: OOooOOo
  if 6 - 6: IiII
  if 46 - 46: IiII + oO0o
  if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
  if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
  if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
  if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
  if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 if 24 - 24: OoOoOO00
 if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 packet . strip_outer_headers ( )
 iIIi11 = lisp . bold ( "Forward" , False )
 if 54 - 54: Ii1I - I1Ii111
 if 81 - 81: IiII . O0 + II111iiii * iIii1I11I1II1 * OOooOOo / OoOoOO00
 if 88 - 88: II111iiii - o0oOOo0O0Ooo * I1IiiI . OoO0O00
 if 65 - 65: IiII . i1IIi
 OOOoO0 = False
 oo0oo = packet . inner_dest . is_mac ( )
 if ( oo0oo ) :
  packet . packet = lisp . lisp_mac_input ( packet . packet )
  if ( packet . packet == None ) : return
  iIIi11 = lisp . bold ( "Bridge" , False )
 elif ( packet . inner_version == 4 ) :
  OOOoO0 , packet . packet = lisp . lisp_ipv4_input ( packet . packet )
  if ( packet . packet == None ) : return
  if ( OOOoO0 ) :
   o0oOOO0 = lisp . lisp_process_igmp_packet ( packet . packet )
   if ( type ( o0oOOO0 ) != bool ) :
    oOoOOOo ( o0oOoO00o , o0oOOO0 )
    return
    if 49 - 49: i11iIiiIii % OoOoOO00 + I1Ii111 . II111iiii % iII111i * OOooOOo
    if 67 - 67: i1IIi
  packet . inner_ttl = packet . outer_ttl
 elif ( packet . inner_version == 6 ) :
  packet . packet = lisp . lisp_ipv6_input ( packet )
  if ( packet . packet == None ) : return
  packet . inner_ttl = packet . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 5 - 5: II111iiii . OoooooooOO
  if 57 - 57: I1IiiI
  if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
  if 50 - 50: OoOoOO00
  if 33 - 33: I11i
  if 98 - 98: OoOoOO00 % II111iiii
  if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
  if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
  if 68 - 68: o0oOOo0O0Ooo
  if 20 - 20: I1Ii111 - I1Ii111
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  O0oOoOO = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( O0oOoOO ) :
   O0oOoOO . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 37 - 37: IiII
   return
   if 37 - 37: Oo0Ooo / IiII * O0
 else :
  if ( lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False ) ) :
   lisp . dprint ( "Discard echoed multicast packet (through NAT)" )
   return
   if 73 - 73: iII111i * iII111i / ooOoO0o
   if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
   if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
   if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
   if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
   if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
   if 6 - 6: iIii1I11I1II1 * OoooooooOO
   if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
  if 69 - 69: I1ii11iIi11i
  if 83 - 83: o0oOOo0O0Ooo
  if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
  if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 i1Ii = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 48 - 48: iII111i + IiII
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( iIIi11 , lisp . green ( i1Ii , False ) ,
 # I1IiiI % i11iIiiIii % i1IIi % IiII
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 15 - 15: iIii1I11I1II1 . O0
 if 70 - 70: Ii1I . i11iIiiIii % Ii1I . O0 - iIii1I11I1II1
 if 26 - 26: OOooOOo
 if 76 - 76: i1IIi * OoooooooOO * O0 + I1Ii111 * I1Ii111
 if 35 - 35: o0oOOo0O0Ooo
 if ( oo0oo ) :
  packet . bridge_l2_packet ( packet . inner_dest , O0oOoOO )
  return
  if 73 - 73: O0 - I1ii11iIi11i
  if 2 - 2: II111iiii / I1Ii111
  if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
  if 22 - 22: ooOoO0o . iIii1I11I1II1
  if 12 - 12: Ii1I
  if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( oOOoo00O0O , i1111 )
  return
  if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
  if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
  if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
  if 65 - 65: oO0o + OoOoOO00 + II111iiii
  if 77 - 77: II111iiii
 Iii = packet . get_raw_socket ( )
 if ( Iii == None ) : Iii = i1
 if 7 - 7: Oo0Ooo * OoooooooOO % O0 - Ii1I . Ii1I
 if 80 - 80: OoOoOO00 - II111iiii
 if 35 - 35: ooOoO0o - OoO0O00 . Oo0Ooo * Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 packet . send_packet ( Iii , packet . inner_dest )
 return
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
def Ooo0oO ( lisp_raw_socket , packet , source ) :
 global Ooo , o0oOoO00o
 if 32 - 32: i1IIi . iII111i + II111iiii - OoO0O00 - iIii1I11I1II1
 if 20 - 20: OoOoOO00 % I1ii11iIi11i
 if 44 - 44: OoooooooOO . II111iiii . OOooOOo % OoooooooOO
 if 86 - 86: i11iIiiIii + O0 * IiII - OoO0O00 * OOooOOo + O0
 Oo0 = packet
 packet = lisp . lisp_packet ( packet [ 8 : : ] )
 if ( packet . lisp_header . decode ( Oo0 ) == False ) : return
 if 94 - 94: I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
 if 81 - 81: Oo0Ooo - I11i
 if 24 - 24: OoooooooOO . OoO0O00 * II111iiii
 if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
 if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
 packet . outer_source = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , source ,
 lisp . LISP_IPV4_HOST_MASK_LEN , 0 )
 if 79 - 79: I1IiiI - ooOoO0o
 i1i1 = packet . decode ( False , Ooo ,
 lisp . lisp_decap_stats )
 if ( i1i1 == None ) : return
 if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 if 83 - 83: IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if 80 - 80: OoooooooOO + IiII
 if ( lisp . lisp_flow_logging ) : packet . log_flow ( False )
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 packet . print_packet ( "Kernel-decap" , False )
 lisp . dprint ( packet . lisp_header . print_header ( " " ) )
 if 43 - 43: Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
  I11I1i1iI = packet . udp_sport
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , source , I11I1i1iI )
  lisp . lisp_ipc ( packet , Ooo , "lisp-ms" )
  return
  if 5 - 5: IiII
  if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
  if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
  if 71 - 71: I1Ii111 * Oo0Ooo . I11i
  if 49 - 49: IiII * O0 . IiII
  if 19 - 19: II111iiii - IiII
  if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
  if 89 - 89: OOooOOo
  if 69 - 69: ooOoO0o - OoooooooOO * O0
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  iiIiII11i1 = packet . packet
  oOo00Ooo0o0 = iiIiII11i1 [ 28 : : ]
  I11Iii1 = - 1
  if ( lisp . lisp_is_rloc_probe_request ( oOo00Ooo0o0 [ 0 : 1 ] ) ) :
   I11Iii1 = struct . unpack ( "B" , iiIiII11i1 [ 8 : 9 ] ) [ 0 ] - 1
   if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
  lisp . lisp_parse_packet ( o0oOoO00o , oOo00Ooo0o0 , source , 0 , I11Iii1 )
  return
  if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
  if 96 - 96: OoooooooOO + IiII * O0
  if 86 - 86: Ii1I
  if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
  if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
  if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 69 - 69: OoOoOO00
  if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
  if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
  if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
  if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 if 88 - 88: o0oOOo0O0Ooo
 if 1 - 1: OoooooooOO
 if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  O0oOoOO = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( O0oOoOO ) :
   O0oOoOO . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
   if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
   if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 else :
  if ( lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False ) ) :
   lisp . dprint ( "Discard echoed multicast packet" )
   return
   if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
   if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
   if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
   if 27 - 27: OOooOOo
   if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
   if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
   if 74 - 74: oO0o
   if 34 - 34: iII111i
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
  if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 i1Ii = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 43 - 43: OoO0O00 % OoO0O00
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( lisp . bold ( "NAT-Forward" , False ) , lisp . green ( i1Ii , False ) ,
 # Ii1I * i11iIiiIii + iIii1I11I1II1
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 1 - 1: O0 * ooOoO0o / O0 . OOooOOo % oO0o
 if 91 - 91: oO0o
 if 72 - 72: II111iiii - OOooOOo + I1IiiI - I11i
 if 91 - 91: II111iiii
 if 53 - 53: OoO0O00 % o0oOOo0O0Ooo / OOooOOo % IiII % OoO0O00 % OoooooooOO
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( oOOoo00O0O , i1111 )
  return
  if 31 - 31: I1IiiI
  if 73 - 73: ooOoO0o . O0 / o0oOOo0O0Ooo - OoooooooOO % i11iIiiIii
  if 80 - 80: Ii1I / ooOoO0o % O0 . Oo0Ooo
  if 63 - 63: OOooOOo . II111iiii . I11i
  if 46 - 46: ooOoO0o % IiII - o0oOOo0O0Ooo - Oo0Ooo - Ii1I / I11i
 Iii = packet . get_raw_socket ( )
 if ( Iii == None ) : Iii = lisp_raw_socket
 if 68 - 68: i1IIi - I1ii11iIi11i / Oo0Ooo % I11i . iII111i
 if 9 - 9: IiII
 if 48 - 48: o0oOOo0O0Ooo + o0oOOo0O0Ooo - Oo0Ooo
 if 27 - 27: OoO0O00 + OoOoOO00 * ooOoO0o
 packet . send_packet ( Iii , packet . inner_dest )
 return
 if 83 - 83: iIii1I11I1II1
 if 72 - 72: I11i
 if 87 - 87: i1IIi
 if 48 - 48: Oo0Ooo * oO0o * iIii1I11I1II1 + i11iIiiIii - OoooooooOO
 if 38 - 38: OoOoOO00 / iIii1I11I1II1 % i11iIiiIii - IiII * iII111i / OoOoOO00
 if 13 - 13: OoO0O00 * I1ii11iIi11i - I1Ii111
 if 79 - 79: oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
def i111I11I ( group , joinleave ) :
 ii111Ii11iii = lisp . lisp_lookup_group ( group )
 if ( ii111Ii11iii == None ) : return
 if 80 - 80: iIii1I11I1II1 - OoooooooOO - I1ii11iIi11i - I1ii11iIi11i . OoooooooOO
 I1i = [ ]
 for OO0Oooo0oOO0O in ii111Ii11iii . sources :
  I1i . append ( [ OO0Oooo0oOO0O , group , joinleave ] )
  if 2 - 2: I11i / OoO0O00 * oO0o % i11iIiiIii + IiII
  if 3 - 3: IiII + II111iiii / iIii1I11I1II1
 oOoOOOo ( o0oOoO00o , I1i )
 return
 if 10 - 10: II111iiii . O0
 if 31 - 31: oO0o / i11iIiiIii / O0
 if 39 - 39: I1IiiI + Oo0Ooo
 if 83 - 83: i1IIi
 if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
 if 49 - 49: IiII / ooOoO0o / OOooOOo
 if 25 - 25: I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
def i11ii ( ) :
 global o0oOoO00o
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 lisp . lisp_set_exception ( )
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 I1IiII1I1i1I1 = socket . htonl
 II11iiI = [ I1IiII1I1i1I1 ( 0x46000020 ) , I1IiII1I1i1I1 ( 0x9fe60000 ) , I1IiII1I1i1I1 ( 0x0102d7cc ) ,
 I1IiII1I1i1I1 ( 0x0acfc15a ) , I1IiII1I1i1I1 ( 0xe00000fb ) , I1IiII1I1i1I1 ( 0x94040000 ) ]
 if 45 - 45: OoooooooOO
 OooOOOOoO00OoOO = b""
 for I1oo in II11iiI : OooOOOOoO00OoOO += struct . pack ( "I" , I1oo )
 if 17 - 17: O0 - OoOoOO00
 if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
 if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
 if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
 if 10 - 10: I1ii11iIi11i / i11iIiiIii - Ii1I + oO0o * I1IiiI
 while ( True ) :
  OoooOo0 = getoutput ( "ls join-*" ) . replace ( "join-" , "" )
  OoooOo0 = OoooOo0 . split ( "\n" )
  if 20 - 20: II111iiii - I11i + i1IIi + Ii1I
  for oOO0oo in OoooOo0 :
   if ( lisp . lisp_valid_address_format ( "address" , oOO0oo ) == False ) :
    continue
    if 7 - 7: ooOoO0o + Ii1I
    if 32 - 32: iIii1I11I1II1 % I1IiiI / i11iIiiIii + OOooOOo - o0oOOo0O0Ooo . iII111i
   oo00 = ( oOO0oo . find ( ":" ) != - 1 )
   if 35 - 35: ooOoO0o % I1IiiI - ooOoO0o - OoO0O00 - OoooooooOO
   if 46 - 46: i1IIi . i1IIi . oO0o / I11i / ooOoO0o
   if 34 - 34: OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
   if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
   Ii1I1i1ii1I1 = os . path . exists ( "leave-{}" . format ( oOO0oo ) )
   lisp . lprint ( "Internal {} group {}" . format ( "leaving" if Ii1I1i1ii1I1 else "joining" , oOO0oo ) )
   if 98 - 98: IiII * iIii1I11I1II1 . Ii1I * Oo0Ooo / I1ii11iIi11i + ooOoO0o
   if 25 - 25: oO0o
   if 19 - 19: I1IiiI % Ii1I . IiII * ooOoO0o
   if 89 - 89: OoOoOO00 . OOooOOo
   if 7 - 7: oO0o % OoOoOO00 - I1IiiI + Oo0Ooo
   if ( oo00 ) :
    if ( oOO0oo . lower ( ) . find ( "ff02:" ) != - 1 ) :
     lisp . lprint ( "Suppress registration for link-local groups" )
     continue
     if 70 - 70: II111iiii + I1Ii111 + i11iIiiIii - i1IIi / IiII
    i111I11I ( oOO0oo , ( Ii1I1i1ii1I1 == False ) )
   else :
    iI1IIiiIIIII = OooOOOOoO00OoOO
    if ( Ii1I1i1ii1I1 ) :
     iI1IIiiIIIII += struct . pack ( "I" , I1IiII1I1i1I1 ( 0x17000000 ) )
    else :
     iI1IIiiIIIII += struct . pack ( "I" , I1IiII1I1i1I1 ( 0x16000000 ) )
     if 43 - 43: iII111i + Oo0Ooo / OoooooooOO
     if 24 - 24: O0 + o0oOOo0O0Ooo * Ii1I - I1Ii111
    ii = oOO0oo . split ( "." )
    Ooo0OOoOoO0 = int ( ii [ 0 ] ) << 24
    Ooo0OOoOoO0 += int ( ii [ 1 ] ) << 16
    Ooo0OOoOoO0 += int ( ii [ 2 ] ) << 8
    Ooo0OOoOoO0 += int ( ii [ 3 ] )
    iI1IIiiIIIII += struct . pack ( "I" , I1IiII1I1i1I1 ( Ooo0OOoOoO0 ) )
    I1i = lisp . lisp_process_igmp_packet ( iI1IIiiIIIII )
    if ( type ( I1i ) != bool ) :
     oOoOOOo ( o0oOoO00o , I1i )
     if 20 - 20: iII111i / OOooOOo
    time . sleep ( .100 )
    if 28 - 28: ooOoO0o * I11i % i11iIiiIii * iII111i / Ii1I
    if 41 - 41: OOooOOo - o0oOOo0O0Ooo + Ii1I
  time . sleep ( 10 )
  if 15 - 15: I11i / o0oOOo0O0Ooo + Ii1I
 return
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
def o0OO0oooo ( ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 40 - 40: I1Ii111 - OoOoOO00 * I11i - IiII / OoOoOO00
 if 71 - 71: oO0o / OoooooooOO % IiII / OoOoOO00 % I1Ii111
 if 19 - 19: I1Ii111 + IiII / oO0o / II111iiii
 if 92 - 92: i1IIi % ooOoO0o + ooOoO0o - iIii1I11I1II1 . Ii1I
 if 33 - 33: o0oOOo0O0Ooo / O0 + OOooOOo
 o0Ooo0o0Oo = lisp . lisp_get_all_multicast_rles ( )
 if 55 - 55: iIii1I11I1II1 * iII111i
 if 85 - 85: iIii1I11I1II1 . II111iiii
 if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
 if 22 - 22: OOooOOo
 iIi1Ii = "any"
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
 if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 oOoO = "(proto 2) or "
 if 32 - 32: O0 + oO0o % Oo0Ooo
 oOoO += "((dst host "
 for iI1iI in lisp . lisp_get_all_addresses ( ) + o0Ooo0o0Oo :
  oOoO += "{} or " . format ( iI1iI )
  if 100 - 100: ooOoO0o / ooOoO0o - OOooOOo % OOooOOo * oO0o / IiII
 oOoO = oOoO [ 0 : - 4 ]
 oOoO += ") and ((udp dst port 4341 or 8472 or 4789) or "
 oOoO += "(udp src port 4341) or "
 oOoO += "(udp dst port 4342 and ip[28] == 0x12) or "
 oOoO += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0)))))"
 if 32 - 32: I1IiiI + I1ii11iIi11i - oO0o + I1ii11iIi11i / i1IIi * oO0o
 if 90 - 90: Ii1I % oO0o
 lisp . lprint ( "Capturing packets for: '{}' on device {}" . format ( oOoO ,
 iIi1Ii ) )
 if 6 - 6: OoooooooOO / i11iIiiIii / I1Ii111
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if ( lisp . lisp_is_python2 ( ) ) :
  import pcappy
  ooO0 = pcappy . open_live ( iIi1Ii , 1600 , 0 , 100 )
  ooO0 . filter = oOoO
  ooO0 . loop ( - 1 , i1II11Iii1I , [ iIi1Ii , i1 ] )
  if 94 - 94: I11i . I1IiiI
 if ( lisp . lisp_is_python3 ( ) ) :
  import pcapy
  ooO0 = pcapy . open_live ( iIi1Ii , 1600 , 0 , 100 )
  ooO0 . setfilter ( oOoO )
  while ( True ) :
   oooO , OooOOOOoO00OoOO = ooO0 . next ( )
   if ( len ( OooOOOOoO00OoOO ) == 0 ) : continue
   i1II11Iii1I ( [ iIi1Ii , i1 ] , None , OooOOOOoO00OoOO )
   if 64 - 64: O0 % ooOoO0o
   if 40 - 40: o0oOOo0O0Ooo + I11i
 return
 if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
 if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
 if 47 - 47: OoooooooOO
 if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
 if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
def I1II1IiI1 ( ) :
 global Ooo
 global Oo
 global o0oOoO00o
 global i1
 global oOOoo00O0O
 global i1111
 if 26 - 26: OOooOOo * Oo0Ooo
 lisp . lisp_i_am ( "etr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "ETR starting up" )
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 lisp . lisp_get_local_interfaces ( )
 lisp . lisp_get_local_macs ( )
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
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
 OO0Oooo0oOO0O = lisp . lisp_open_listen_socket ( "0.0.0.0" , str ( I1Ii11I1Ii1i ) )
 OO0Oooo0oOO0O . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_TTL , 32 )
 Oo = OO0Oooo0oOO0O
 if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
 if 10 - 10: I1Ii111 * oO0o % Oo0Ooo - I11i % Oo0Ooo
 if 65 - 65: iII111i * iIii1I11I1II1 / O0 . I11i
 if 94 - 94: Oo0Ooo . ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo . iII111i
 Ooo = lisp . lisp_open_listen_socket ( "" , "lisp-etr" )
 if 98 - 98: OOooOOo + Ii1I
 o0oOoO00o [ 0 ] = Oo
 o0oOoO00o [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 o0oOoO00o [ 2 ] = Ooo
 if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
 if 50 - 50: iIii1I11I1II1 - iII111i - I11i
 if 60 - 60: iIii1I11I1II1 * ooOoO0o
 if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
 if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
 if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
 if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
 if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
 if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
 i1 = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 i1 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 o0oOoO00o . append ( i1 )
 if 93 - 93: ooOoO0o
 if 18 - 18: ooOoO0o
 if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
 if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
 if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
 if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
 if 58 - 58: O0
 if 91 - 91: iII111i / I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I1ii11iIi11i
 if 72 - 72: Ii1I . IiII * I1ii11iIi11i / I1ii11iIi11i / iII111i
 if 13 - 13: i1IIi
 if 17 - 17: i11iIiiIii * o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoO0O00
 if 95 - 95: I1IiiI
 if 95 - 95: OOooOOo % I1ii11iIi11i + o0oOOo0O0Ooo % ooOoO0o
 if 36 - 36: O0 / i1IIi % II111iiii / iII111i
 if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
 if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: oO0o
 if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
 if 97 - 97: I1Ii111 . I11i / I1IiiI
 if 83 - 83: I11i - I1ii11iIi11i * oO0o
 if ( pytun != None ) :
  i1111 = b'\x00\x00\x86\xdd'
  iIi1Ii = "lispers.net"
  try :
   oOOoo00O0O = pytun . TunTapDevice ( flags = pytun . IFF_TUN ,
 name = iIi1Ii )
   os . system ( "ip link set dev {} up" . format ( iIi1Ii ) )
  except :
   lisp . lprint ( "Cannot create tuntap interface" )
   if 90 - 90: Oo0Ooo * I1IiiI
   if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
   if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
   if 28 - 28: IiII * I1IiiI % IiII
   if 95 - 95: O0 / I11i . I1Ii111
   if 17 - 17: I11i
 threading . Thread ( target = o0OO0oooo , args = [ ] ) . start ( )
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
 threading . Thread ( target = i11ii , args = [ ] ) . start ( )
 return ( True )
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 if 36 - 36: IiII
 if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
 if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
def iiI1iIII1ii ( ) :
 global Oo0o
 global Ii1iI
 if 5 - 5: I1Ii111 % OoooooooOO . OoOoOO00
 if 67 - 67: I1ii11iIi11i + Ii1I
 if 72 - 72: IiII % o0oOOo0O0Ooo
 if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
 if ( Oo0o ) : Oo0o . cancel ( )
 if ( Ii1iI ) : Ii1iI . cancel ( )
 if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
 if 52 - 52: IiII % ooOoO0o
 if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
 if 23 - 23: i11iIiiIii
 lisp . lisp_close_socket ( o0oOoO00o [ 0 ] , "" )
 lisp . lisp_close_socket ( o0oOoO00o [ 1 ] , "" )
 lisp . lisp_close_socket ( Ooo , "lisp-etr" )
 return
 if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
 if 65 - 65: II111iiii / Oo0Ooo
 if 42 - 42: i11iIiiIii . O0
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
 if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
 if 92 - 92: I11i / O0 * I1IiiI - I11i
 if 99 - 99: i11iIiiIii % OoooooooOO
 if 56 - 56: IiII * I1Ii111
 if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
 if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
def I1Iiii ( ipc ) :
 ipc = ipc . split ( "%" )
 iIIIIiiIii = ipc [ 1 ]
 I1I1Iii1Iiii = ipc [ 2 ]
 if ( I1I1Iii1Iiii == "None" ) : I1I1Iii1Iiii = None
 if 4 - 4: IiII
 i1OO0oOOoo = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 i1OO0oOOoo . store_address ( iIIIIiiIii )
 if 93 - 93: oO0o % i1IIi
 if 83 - 83: I1IiiI . Oo0Ooo - I11i . o0oOOo0O0Ooo
 if 73 - 73: I1IiiI - iII111i . iII111i
 if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
 O0oOoOO = lisp . lisp_db_for_lookups . lookup_cache ( i1OO0oOOoo , False )
 if ( O0oOoOO == None or O0oOoOO . dynamic_eid_configured ( ) == False ) :
  lisp . lprint ( "ITR/ETR dynamic-EID configuration out of sync for {}" . format ( lisp . green ( iIIIIiiIii , False ) ) )
  if 64 - 64: i1IIi % I1ii11iIi11i / Ii1I % OoooooooOO
  return
  if 24 - 24: I1Ii111 + OoooooooOO . IiII / OoOoOO00 / I11i
  if 65 - 65: OoooooooOO
  if 18 - 18: O0 - i1IIi . I1Ii111
  if 98 - 98: o0oOOo0O0Ooo
  if 73 - 73: Oo0Ooo - iII111i . oO0o % i1IIi . O0
  if 15 - 15: ooOoO0o . iIii1I11I1II1 * I1IiiI % I11i
 I1IIIiI1I1ii1 = None
 if ( iIIIIiiIii in O0oOoOO . dynamic_eids ) : I1IIIiI1I1ii1 = O0oOoOO . dynamic_eids [ iIIIIiiIii ]
 if 21 - 21: OoO0O00 - I1IiiI . OoooooooOO
 if ( I1IIIiI1I1ii1 == None and I1I1Iii1Iiii == None ) :
  lisp . lprint ( "ITR/ETR state mismatch for {}" . format ( lisp . green ( iIIIIiiIii , False ) ) )
  if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
  return
  if 3 - 3: OOooOOo . IiII / Oo0Ooo
  if 89 - 89: OoooooooOO . iIii1I11I1II1 . Oo0Ooo * iIii1I11I1II1 - I1Ii111
  if 92 - 92: OoooooooOO - I1ii11iIi11i - OoooooooOO % I1IiiI % I1IiiI % iIii1I11I1II1
  if 92 - 92: iII111i * O0 % I1Ii111 . iIii1I11I1II1
  if 66 - 66: I11i + Ii1I
  if 48 - 48: I1ii11iIi11i
  if 96 - 96: ooOoO0o . OoooooooOO
 if ( I1IIIiI1I1ii1 and I1I1Iii1Iiii ) :
  if ( I1IIIiI1I1ii1 . interface == I1I1Iii1Iiii ) :
   lisp . lprint ( "ITR sent redundant IPC for {}" . format ( lisp . green ( iIIIIiiIii , False ) ) )
   if 39 - 39: OOooOOo + OoO0O00
  else :
   lisp . lprint ( "Dynamic-EID {} interface change, {} -> {}" . format ( lisp . green ( iIIIIiiIii , False ) , I1IIIiI1I1ii1 . interface , I1I1Iii1Iiii ) )
   if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
   I1IIIiI1I1ii1 . interface = I1I1Iii1Iiii
   if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
  return
  if 71 - 71: ooOoO0o . i11iIiiIii
  if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
  if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
  if 67 - 67: iII111i
  if 88 - 88: Oo0Ooo
 if ( I1I1Iii1Iiii ) :
  I1IIIiI1I1ii1 = lisp . lisp_dynamic_eid ( )
  I1IIIiI1I1ii1 . dynamic_eid . copy_address ( i1OO0oOOoo )
  I1IIIiI1I1ii1 . interface = I1I1Iii1Iiii
  I1IIIiI1I1ii1 . get_timeout ( I1I1Iii1Iiii )
  O0oOoOO . dynamic_eids [ iIIIIiiIii ] = I1IIIiI1I1ii1
  if 8 - 8: I1ii11iIi11i
  o000 = lisp . bold ( "Registering" , False )
  iIIIIiiIii = lisp . bold ( iIIIIiiIii , False )
  lisp . lprint ( "{} dynamic-EID {} on interface {}, timeout {}" . format ( o000 ,
 lisp . green ( iIIIIiiIii , False ) , I1I1Iii1Iiii , I1IIIiI1I1ii1 . timeout ) )
  if 30 - 30: Ii1I + II111iiii % OoooooooOO
  i1iiI11I ( o0oOoO00o , None , i1OO0oOOoo , None , False )
  if 89 - 89: Ii1I
  if 51 - 51: iII111i
  if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
  if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  if ( lisp . lisp_is_macos ( ) == False ) :
   iIIIIiiIii = i1OO0oOOoo . print_prefix_no_iid ( )
   Ii1IiiiI1ii = "ip route add {} dev {}" . format ( iIIIIiiIii , I1I1Iii1Iiii )
   os . system ( Ii1IiiiI1ii )
   if 55 - 55: I1ii11iIi11i
  return
  if 76 - 76: oO0o - i11iIiiIii
  if 27 - 27: I1ii11iIi11i - i11iIiiIii % I1Ii111 / Oo0Ooo . Oo0Ooo / OoooooooOO
  if 76 - 76: I11i * OoO0O00 . iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
 if ( iIIIIiiIii in O0oOoOO . dynamic_eids ) :
  I1I1Iii1Iiii = O0oOoOO . dynamic_eids [ iIIIIiiIii ] . interface
  o0O00O = lisp . bold ( "Deregistering" , False )
  lisp . lprint ( "{} dynamic-EID {}" . format ( o0O00O ,
 lisp . green ( iIIIIiiIii , False ) ) )
  if 21 - 21: OoooooooOO . OoOoOO00 - iIii1I11I1II1 % IiII
  i1iiI11I ( o0oOoO00o , 0 , i1OO0oOOoo , None , False )
  if 55 - 55: O0 % I1IiiI . OoooooooOO * Oo0Ooo / OoooooooOO . Ii1I
  O0oOoOO . dynamic_eids . pop ( iIIIIiiIii )
  if 26 - 26: IiII / iIii1I11I1II1 - iIii1I11I1II1
  if 57 - 57: IiII
  if 41 - 41: iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % IiII / OOooOOo
  if 63 - 63: i1IIi % i11iIiiIii % II111iiii * OoooooooOO
  if ( lisp . lisp_is_macos ( ) == False ) :
   iIIIIiiIii = i1OO0oOOoo . print_prefix_no_iid ( )
   Ii1IiiiI1ii = "ip route delete {} dev {}" . format ( iIIIIiiIii , I1I1Iii1Iiii )
   os . system ( Ii1IiiiI1ii )
   if 40 - 40: Oo0Ooo
   if 47 - 47: OoOoOO00
 return
 if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
 if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
 if 33 - 33: oO0o
 if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
 if 41 - 41: IiII % o0oOOo0O0Ooo
 if 67 - 67: O0 % I1Ii111
 if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
 if 39 - 39: Ii1I
 if 60 - 60: OOooOOo
 if 62 - 62: I1Ii111 * I11i
 if 74 - 74: OoOoOO00 . iIii1I11I1II1
def oOOoO0oO0oo0O ( ipc ) :
 if ( lisp . lisp_register_all_rtrs ) : return
 if 55 - 55: Oo0Ooo
 IIi1i1I11IIII , o0OOOooo0OOo , i1i1 = ipc . split ( "%" )
 if ( o0OOOooo0OOo not in lisp . lisp_rtr_list ) : return
 if 55 - 55: iIii1I11I1II1 % OoO0O00 / I1ii11iIi11i / o0oOOo0O0Ooo
 lisp . lprint ( "Process ITR IPC message, RTR {} has gone {}" . format (
 lisp . red ( o0OOOooo0OOo , False ) , lisp . bold ( i1i1 , False ) ) )
 if 39 - 39: OoO0O00 % oO0o / IiII * iII111i * oO0o . oO0o
 iII1i11IIi1i = lisp . lisp_rtr_list [ o0OOOooo0OOo ]
 if ( i1i1 == "down" ) :
  lisp . lisp_rtr_list [ o0OOOooo0OOo ] = None
  return
  if 42 - 42: I1Ii111 % OoO0O00 . I1ii11iIi11i
  if 4 - 4: i1IIi + OoOoOO00
 iII1i11IIi1i = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , o0OOOooo0OOo , 32 , 0 )
 lisp . lisp_rtr_list [ o0OOOooo0OOo ] = iII1i11IIi1i
 return
 if 39 - 39: iIii1I11I1II1 + ooOoO0o
 if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
 if 23 - 23: II111iiii * iII111i
 if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
 if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
 if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
 if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
 if 21 - 21: OoO0O00
 if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
 if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
def Oo0OOOoOO ( ipc ) :
 iiII1IIii1i1 , IIi1i1I11IIII , i1iiiIIi11II , o0oooOo0oo = ipc . split ( "%" )
 o0oooOo0oo = int ( o0oooOo0oo , 16 )
 if 33 - 33: I1Ii111 % II111iiii
 IIi1II = lisp . lisp_get_echo_nonce ( None , i1iiiIIi11II )
 if ( IIi1II == None ) : IIi1II = lisp . lisp_echo_nonce ( i1iiiIIi11II )
 if 40 - 40: OOooOOo / IiII
 if ( IIi1i1I11IIII == "R" ) :
  IIi1II . request_nonce_sent = o0oooOo0oo
  lisp . lprint ( "Waiting for echo-nonce 0x{} from {}" . format ( lisp . lisp_hex_string ( o0oooOo0oo ) , lisp . red ( IIi1II . rloc_str , False ) ) )
  if 29 - 29: Ii1I - Ii1I / ooOoO0o
 elif ( IIi1i1I11IIII == "E" ) :
  IIi1II . echo_nonce_sent = o0oooOo0oo
  lisp . lprint ( "Sent echo-nonce 0x{} to {}" . format ( lisp . lisp_hex_string ( o0oooOo0oo ) , lisp . red ( IIi1II . rloc_str , False ) ) )
  if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
 return
 if 18 - 18: Oo0Ooo % O0
 if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
 if 86 - 86: IiII
 if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
iiI111i1 = {
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

 "lisp map-server" : [ OoooooOoo , {
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

 "lisp database-mapping" : [ oo000OO00Oo , {
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

 "lisp group-mapping" : [ oO0o0o0oo , {
 "group-name" : [ False ] ,
 "ms-name" : [ True ] ,
 "group-prefix" : [ False ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "rle-address" : [ False ] ,
 "sources" : [ ] ,
 "address" : [ True ] } ] ,

 "show database-mapping" : [ o0o , { } ] ,
 "show etr-keys" : [ oooOo0OOOoo0 , { } ] ,
 "show etr-dynamic-eid" : [ lispconfig . lisp_show_dynamic_eid_command , { } ]
 }
if 41 - 41: i11iIiiIii * O0 - iII111i . II111iiii % OoO0O00 % I1ii11iIi11i
if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
if 62 - 62: i11iIiiIii
if 2 - 2: I1IiiI
if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
if ( I1II1IiI1 ( ) == False ) :
 lisp . lprint ( "lisp_etr_startup() failed" )
 lisp . lisp_print_banner ( "ETR abnormal exit" )
 exit ( 1 )
 if 14 - 14: IiII . IiII % ooOoO0o
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
Iiii = [ Oo , Ooo ]
if 56 - 56: I11i - O0 / O0 * i1IIi . OoooooooOO % iIii1I11I1II1
while ( True ) :
 try : I11iIiI1 , i1I1iiii1Ii11 , iiII1IIii1i1 = select . select ( Iiii , [ ] , [ ] )
 except : break
 if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 6 - 6: oO0o . I11i
 if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
 if 50 - 50: oO0o % i1IIi * O0
 if ( Oo in I11iIiI1 ) :
  IIi1i1I11IIII , ooooooo00o , Iiii1iiiIiI1 , OooOOOOoO00OoOO = lisp . lisp_receive ( Oo , False )
  if 4 - 4: iIii1I11I1II1 . i1IIi
  if ( ooooooo00o == "" ) : break
  if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
  if ( Iiii1iiiIiI1 == lisp . LISP_DATA_PORT ) :
   Ooo0oO ( i1 , OooOOOOoO00OoOO , ooooooo00o )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( OooOOOOoO00OoOO [ 0 : 1 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
   IiI = lisp . lisp_parse_packet ( o0oOoO00o , OooOOOOoO00OoOO ,
 ooooooo00o , Iiii1iiiIiI1 )
   if 34 - 34: O0 / OOooOOo
   if 86 - 86: I1ii11iIi11i * i1IIi + iII111i . I1ii11iIi11i
   if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
   if 37 - 37: Oo0Ooo
   if 72 - 72: IiII % I1ii11iIi11i * OOooOOo . i11iIiiIii % IiII * OOooOOo
   if ( IiI ) :
    Ii1iI = threading . Timer ( 0 ,
 oo0Oo00Oo0 , [ None ] )
    Ii1iI . start ( )
    Oo0o = threading . Timer ( 0 ,
 iii11 , [ o0oOoO00o ] )
    Oo0o . start ( )
    if 15 - 15: I11i / Oo0Ooo * I11i
    if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
    if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
    if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
    if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
    if 5 - 5: O0 - I1IiiI
    if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
    if 16 - 16: II111iiii
 if ( Ooo in I11iIiI1 ) :
  IIi1i1I11IIII , ooooooo00o , Iiii1iiiIiI1 , OooOOOOoO00OoOO = lisp . lisp_receive ( Ooo , True )
  if 100 - 100: O0 - i1IIi
  if ( ooooooo00o == "" ) : break
  if 48 - 48: oO0o % ooOoO0o + O0
  if ( IIi1i1I11IIII == "command" ) :
   OooOOOOoO00OoOO = OooOOOOoO00OoOO . decode ( )
   if ( OooOOOOoO00OoOO . find ( "learn%" ) != - 1 ) :
    I1Iiii ( OooOOOOoO00OoOO )
   elif ( OooOOOOoO00OoOO . find ( "nonce%" ) != - 1 ) :
    Oo0OOOoOO ( OooOOOOoO00OoOO )
   elif ( OooOOOOoO00OoOO . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( OooOOOOoO00OoOO )
   elif ( OooOOOOoO00OoOO . find ( "rtr%" ) != - 1 ) :
    oOOoO0oO0oo0O ( OooOOOOoO00OoOO )
   elif ( OooOOOOoO00OoOO . find ( "stats%" ) != - 1 ) :
    OooOOOOoO00OoOO = OooOOOOoO00OoOO . split ( "%" ) [ - 1 ]
    lisp . lisp_process_data_plane_decap_stats ( OooOOOOoO00OoOO , None )
   else :
    lispconfig . lisp_process_command ( Ooo ,
 IIi1i1I11IIII , OooOOOOoO00OoOO , "lisp-etr" , [ iiI111i1 ] )
    if 27 - 27: I1ii11iIi11i / OOooOOo
  elif ( IIi1i1I11IIII == "api" ) :
   OooOOOOoO00OoOO = OooOOOOoO00OoOO . decode ( )
   lisp . lisp_process_api ( "lisp-etr" , Ooo , OooOOOOoO00OoOO )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( OooOOOOoO00OoOO [ 0 : 1 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 33 - 33: OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
   lisp . lisp_parse_packet ( o0oOoO00o , OooOOOOoO00OoOO , ooooooo00o , Iiii1iiiIiI1 )
   if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
   if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
   if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
   if 13 - 13: II111iiii - Oo0Ooo % i11iIiiIii + iII111i
iiI1iIII1ii ( )
lisp . lisp_print_banner ( "ETR normal exit" )
exit ( 0 )
if 88 - 88: O0 . oO0o % I1IiiI
if 10 - 10: I1IiiI + O0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
