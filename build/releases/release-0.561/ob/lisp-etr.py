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
try :
 import pcappy
except :
 pass
 if 73 - 73: II111iiii
import pcapy
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
ooO0oo0oO0 = None
oo00 = None
o00 = None
Oo0oO0ooo = None
o0oOoO00o = lisp . lisp_get_ephemeral_port ( )
i1 = None
oOOoo00O0O = [ None , None , None ]
i1111 = None
i11 = None
I11 = None
if 98 - 98: i11iIiiIii * I1IiiI % iII111i * iII111i * II111iiii
o0o0Oo0oooo0 = 60
if 97 - 97: Oo0Ooo - ooOoO0o
if 54 - 54: ooOoO0o . ooOoO0o / iIii1I11I1II1 / I11i + oO0o / o0oOOo0O0Ooo
if 39 - 39: I11i / I1Ii111 . I11i - I11i
if 68 - 68: OOooOOo . I1IiiI / iII111i
if 72 - 72: OoO0O00 / OoO0O00
if 30 - 30: OoO0O00
if 95 - 95: oO0o * o0oOOo0O0Ooo / II111iiii . I1ii11iIi11i + OOooOOo
iI11 = ( os . getenv ( "LISP_ETR_TEST_MODE" ) != None )
iII111ii = False
if 3 - 3: iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
if 78 - 78: OoO0O00
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
if 14 - 14: I11i % O0
if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
def oO ( kv_pair ) :
 global oo00
 global o00
 if 76 - 76: OoO0O00 * o0oOOo0O0Ooo % i1IIi - OoO0O00 / I1IiiI . OOooOOo
 iiIiIIi = lispconfig . lisp_map_server_command ( kv_pair )
 if 65 - 65: OoOoOO00
 if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
 if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
 if 100 - 100: Ii1I - Ii1I - I1Ii111
 if 20 - 20: OoooooooOO
 Ii11iI1i = ( len ( lisp . lisp_map_servers_list ) == 1 )
 if ( Ii11iI1i ) :
  iiIiIIi = list ( lisp . lisp_map_servers_list . values ( ) ) [ 0 ]
  o00 = threading . Timer ( 2 , Ooo ,
 [ iiIiIIi . map_server ] )
  o00 . start ( )
 else :
  if 68 - 68: I11i + OOooOOo . iIii1I11I1II1 - IiII % iIii1I11I1II1 - ooOoO0o
  if 79 - 79: Oo0Ooo + I1IiiI - iII111i
  if 83 - 83: ooOoO0o
  if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
  if 74 - 74: iII111i * O0
  if 89 - 89: oO0o + Oo0Ooo
  if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
  if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
  if ( lisp . lisp_nat_traversal ) : return
  if ( iiIiIIi and len ( lisp . lisp_db_list ) > 0 ) :
   I1i1iii ( oOOoo00O0O , None , None , iiIiIIi , False )
   if 20 - 20: o0oOOo0O0Ooo
   if 77 - 77: OoOoOO00 / I11i
   if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
   if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
   if 95 - 95: OoO0O00 % oO0o . O0
   if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
   if 53 - 53: IiII + I1IiiI * oO0o
 if ( iI11 and iII111ii ) : return
 if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
 if 60 - 60: I11i / I11i
 if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
 if 83 - 83: OoooooooOO
 if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 if ( len ( lisp . lisp_db_list ) > 0 ) :
  if ( oo00 != None ) : return
  oo00 = threading . Timer ( 5 ,
 iii11 , [ oOOoo00O0O ] )
  oo00 . start ( )
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
 global ooO0oo0oO0 , oo00
 global oOOoo00O0O , iII111ii
 global lisp_seen_eid_done_count
 if 51 - 51: IiII * o0oOOo0O0Ooo + I11i + OoO0O00
 if 66 - 66: OoOoOO00
 if 97 - 97: oO0o % IiII * IiII
 if 39 - 39: Ii1I % IiII
 if 4 - 4: oO0o
 if 93 - 93: OoO0O00 % oO0o . OoO0O00 * I1Ii111 % Ii1I . II111iiii
 if ( iII111ii ) : return
 if 38 - 38: o0oOOo0O0Ooo
 lispconfig . lisp_database_mapping_command ( kv_pair , o0oOoO00o ,
 ( iI11 == False ) )
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
 if 26 - 26: iII111i
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
 if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
 if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
 if 91 - 91: oO0o % Oo0Ooo
 if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
 if 31 - 31: I11i - II111iiii . I11i
 if ( lisp . lisp_nat_traversal ) : return
 if ( oo00 != None ) : return
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 if ( iI11 ) :
  o0 = len ( lisp . lisp_db_list )
  if ( o0 % 1000 == 0 ) :
   lisp . fprint ( "{} database-mappings processed" . format ( o0 ) )
   if 91 - 91: iIii1I11I1II1 + I1Ii111
   if 31 - 31: IiII . OoOoOO00 . OOooOOo
  O0oOoOO = lisp . lisp_db_list [ - 1 ]
  if ( O0oOoOO . eid . is_dist_name ( ) == False ) : return
  if ( O0oOoOO . eid . address != "eid-done" ) : return
  iII111ii = True
  if 96 - 96: Oo0Ooo
  lisp . fprint ( "Finished batch of {} database-mappings" . format ( o0 ) )
  if 45 - 45: O0 * o0oOOo0O0Ooo % Oo0Ooo * OoooooooOO + iII111i . OoOoOO00
  Oo0ooOo0o = threading . Timer ( 0 , iii11 ,
 [ oOOoo00O0O ] )
  ooO0oo0oO0 = Oo0ooOo0o
  ooO0oo0oO0 . start ( )
  return
  if 22 - 22: iIii1I11I1II1 / i11iIiiIii * iIii1I11I1II1 * II111iiii . OOooOOo / i11iIiiIii
  if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
 if ( len ( lisp . lisp_map_servers_list ) > 0 ) :
  oo00 = threading . Timer ( 5 ,
 iii11 , [ oOOoo00O0O ] )
  oo00 . start ( )
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
 for iiIiIIi in list ( lisp . lisp_map_servers_list . values ( ) ) :
  iiIiIIi . resolve_dns_name ( )
  IiI111111IIII = "" if iiIiIIi . ms_name == "all" else iiIiIIi . ms_name + "<br>"
  i1Ii = IiI111111IIII + iiIiIIi . map_server . print_address_no_iid ( )
  if ( iiIiIIi . dns_name ) : i1Ii += "<br>" + iiIiIIi . dns_name
  if 14 - 14: iII111i
  I1iI1iIi111i = "0x" + lisp . lisp_hex_string ( iiIiIIi . xtr_id )
  iiIi1IIi1I = "{}-{}-{}-{}" . format ( "P" if iiIiIIi . proxy_reply else "p" ,
 "M" if iiIiIIi . merge_registrations else "m" ,
 "N" if iiIiIIi . want_map_notify else "n" ,
 "R" if iiIiIIi . refresh_registrations else "r" )
  if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
  O0ooO0Oo00o = iiIiIIi . map_registers_sent + iiIiIIi . map_registers_multicast_sent
  if 77 - 77: iIii1I11I1II1 * OoO0O00
  if 95 - 95: I1IiiI + i11iIiiIii
  iIIiIi1iIII1 += lispconfig . lisp_table_row ( i1Ii ,
 "sha1" if ( iiIiIIi . alg_id == lisp . LISP_SHA_1_96_ALG_ID ) else "sha2" ,
 I1iI1iIi111i , iiIiIIi . site_id , iiIi1IIi1I , O0ooO0Oo00o ,
 iiIiIIi . map_notifies_received )
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
 iI1iIii11Ii = ""
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
def I1i1iii ( lisp_sockets , ttl , eid_only , ms_only , refresh ) :
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
 if ( iI11 ) :
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
  for iiIiIIi in list ( lisp . lisp_map_servers_list . values ( ) ) :
   if ( ms_only != None and iiIiIIi != ms_only ) : continue
   o0o0oOoOO0O [ iiIiIIi . ms_name ] = [ ]
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
 oO0oO0 = 65000 if ( iI11 ) else 1100
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
   II11iI111i1 = [ "" , 0 ]
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
  iI1iIii11Ii = ""
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
   II11iI111i1 = [ "" , 0 ]
   o0o0oOoOO0O [ i1i1IIIIi1i ] . append ( II11iI111i1 )
   if 92 - 92: Oo0Ooo
   if 40 - 40: OoOoOO00 / IiII
   if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
   if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
   if 61 - 61: II111iiii
   if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 oooO0o0o0O0 = .500 if ( iI11 ) else .001
 O00oOOooo = 0
 for iiIiIIi in list ( lisp . lisp_map_servers_list . values ( ) ) :
  if ( ms_only != None and iiIiIIi != ms_only ) : continue
  if 27 - 27: OoooooooOO - iII111i / I11i
  i1i1IIIIi1i = iiIiIIi . dns_name if oOOO0oo0 else iiIiIIi . ms_name
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
   oo000 . alg_id = iiIiIIi . alg_id
   oo000 . key_id = iiIiIIi . key_id
   oo000 . proxy_reply_requested = iiIiIIi . proxy_reply
   oo000 . merge_register_requested = iiIiIIi . merge_registrations
   oo000 . map_notify_requested = iiIiIIi . want_map_notify
   oo000 . xtr_id = iiIiIIi . xtr_id
   oo000 . site_id = iiIiIIi . site_id
   oo000 . encrypt_bit = ( iiIiIIi . ekey != None )
   if ( iiIiIIi . refresh_registrations ) :
    oo000 . map_register_refresh = refresh
    if 77 - 77: I1Ii111
   if ( iiIiIIi . ekey != None ) : oo000 . encryption_key_id = iiIiIIi . ekey_id
   Oo = oo000 . encode ( )
   oo000 . print_map_register ( )
   if 81 - 81: oO0o * OoO0O00
   if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
   if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
   if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
   if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
   Ii1iI111 = oo000 . encode_xtr_id ( "" )
   iI1iIii11Ii = II11iI111i1 [ 0 ]
   Oo = Oo + iI1iIii11Ii + Ii1iI111
   if 51 - 51: IiII * O0 / II111iiii . Ii1I % OOooOOo / I1IiiI
   iiIiIIi . map_registers_sent += 1
   lisp . lisp_send_map_register ( lisp_sockets , Oo , oo000 , iiIiIIi )
   if 9 - 9: I1IiiI % I1IiiI % II111iiii
   O00oOOooo += 1
   if ( O00oOOooo % 100 == 0 and iI11 ) :
    oooO0o0o0O0 += .1
    lisp . fprint ( "Sent {} Map-Registers, ipd {}" . format ( O00oOOooo ,
 oooO0o0o0O0 ) )
    if 30 - 30: IiII + I1Ii111 - IiII . IiII - II111iiii + O0
   time . sleep ( oooO0o0o0O0 )
   if 86 - 86: i1IIi
   if 41 - 41: OoOoOO00 * I11i / OoOoOO00 % oO0o
  if ( iI11 ) :
   lisp . fprint ( "Sent total {} Map-Registers" . format ( O00oOOooo ) )
   if 18 - 18: II111iiii . OoooooooOO % OoOoOO00 % Ii1I
   if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
   if 2 - 2: OoooooooOO % OOooOOo
   if 63 - 63: I1IiiI % iIii1I11I1II1
   if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
  iiIiIIi . resolve_dns_name ( )
  if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
  if 59 - 59: OOooOOo + i11iIiiIii
  if 88 - 88: i11iIiiIii - ooOoO0o
  if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
  if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
  if ( ms_only != None and iiIiIIi == ms_only ) : break
  if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 return
 if 30 - 30: OoOoOO00
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if 10 - 10: II111iiii . iII111i
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 if 88 - 88: iII111i
 if 19 - 19: II111iiii * IiII + Ii1I
 if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
 if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
def Ooo ( ms ) :
 global o00
 global Oo0oO0ooo
 if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
 lisp . lisp_set_exception ( )
 if 67 - 67: I11i - OOooOOo . i1IIi
 if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
 if 87 - 87: OoOoOO00
 if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
 if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
 I11I = [ Oo0oO0ooo , Oo0oO0ooo , i1 ]
 lisp . lisp_build_info_requests ( I11I , ms , lisp . LISP_CTRL_PORT )
 if 6 - 6: I1ii11iIi11i + oO0o
 if 48 - 48: iIii1I11I1II1 % i1IIi % iII111i + ooOoO0o
 if 30 - 30: i11iIiiIii % iIii1I11I1II1 . I11i % iIii1I11I1II1
 if 62 - 62: Oo0Ooo * OoOoOO00
 if 79 - 79: OoO0O00 . iII111i * Ii1I - OOooOOo + ooOoO0o
 ii11II1i = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) == None )
 for iII1i11IIi1i in list ( lisp . lisp_rtr_list . values ( ) ) :
  if ( iII1i11IIi1i == None ) : continue
  if ( iII1i11IIi1i . is_private_address ( ) and ii11II1i == False ) :
   OOO = lisp . red ( iII1i11IIi1i . print_address_no_iid ( ) , False )
   lisp . lprint ( "Skip over RTR private address {}" . format ( OOO ) )
   continue
   if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
  lisp . lisp_build_info_requests ( I11I , iII1i11IIi1i , lisp . LISP_DATA_PORT )
  if 46 - 46: OoO0O00
  if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
  if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
  if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
  if 68 - 68: OoooooooOO % II111iiii
  if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 o00 . cancel ( )
 o00 = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 Ooo , [ None ] )
 o00 . start ( )
 return
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
def iii11 ( lisp_sockets ) :
 global ooO0oo0oO0 , oo00
 global Oo0oO0ooo
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 lisp . lisp_set_exception ( )
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
 if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 I1i1iii ( lisp_sockets , None , None , None , True )
 if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
 if 34 - 34: O0
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
 if ( lisp . lisp_l2_overlay ) :
  I1i1111I = [ None , "ffff-ffff-ffff" , True ]
  OooOO0o0 ( lisp_sockets , [ I1i1111I ] )
  if 91 - 91: oO0o + OoooooooOO - i1IIi
  if 84 - 84: Ii1I / IiII
  if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
  if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
  if 37 - 37: i11iIiiIii + i1IIi
  if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if ( oo00 != None ) :
  oo00 . cancel ( )
  oo00 = None
  if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
  if 8 - 8: o0oOOo0O0Ooo
  if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
  if 78 - 78: Ii1I / II111iiii % OoOoOO00
  if 52 - 52: OOooOOo - iII111i * oO0o
 if ( ooO0oo0oO0 ) : ooO0oo0oO0 . cancel ( )
 ooO0oo0oO0 = threading . Timer ( o0o0Oo0oooo0 ,
 iii11 , [ oOOoo00O0O ] )
 ooO0oo0oO0 . start ( )
 return
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
 if 36 - 36: O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
 if 63 - 63: I1ii11iIi11i
 if 6 - 6: ooOoO0o / I1ii11iIi11i
def OooOO0o0 ( lisp_sockets , entries ) :
 oOooO00o0O = len ( entries )
 if ( oOooO00o0O == 0 ) : return
 if 80 - 80: OOooOOo / I11i / OoOoOO00 + i1IIi - Oo0Ooo
 iIIiiIIi1IiI = None
 if ( entries [ 0 ] [ 1 ] . find ( ":" ) != - 1 ) : iIIiiIIi1IiI = lisp . LISP_AFI_IPV6
 if ( entries [ 0 ] [ 1 ] . find ( "." ) != - 1 ) : iIIiiIIi1IiI = lisp . LISP_AFI_IPV4
 if ( entries [ 0 ] [ 1 ] . find ( "-" ) != - 1 ) : iIIiiIIi1IiI = lisp . LISP_AFI_MAC
 if ( iIIiiIIi1IiI == None ) :
  lisp . lprint ( "lisp_send_multicast_map_register() invalid group address" )
  return
  if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
  if 53 - 53: Ii1I % Oo0Ooo
  if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
  if 41 - 41: Ii1I % I1ii11iIi11i
  if 12 - 12: OOooOOo
  if 69 - 69: OoooooooOO + OOooOOo
  if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
  if 31 - 31: I11i % OOooOOo * I11i
  if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 i1I = [ ]
 for ooooooo00o , ii , II1I11IIi in entries :
  if 66 - 66: i11iIiiIii / o0oOOo0O0Ooo - OoooooooOO / i1IIi . i11iIiiIii
  i1I . append ( [ ii , II1I11IIi ] )
  if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
  if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
 oOOO0oo0 = lisp . lisp_decent_pull_xtr_configured ( )
 if 81 - 81: iII111i * OOooOOo - I1ii11iIi11i * Ii1I % OoOoOO00 * OoOoOO00
 o0o0oOoOO0O = { }
 entries = [ ]
 for ii , II1I11IIi in i1I :
  ooO = lisp . lisp_lookup_group ( ii )
  if ( ooO == None ) :
   lisp . lprint ( "No group-mapping for {}, could be underlay group" . format ( ii ) )
   if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
   continue
   if 83 - 83: I1Ii111
   if 48 - 48: II111iiii * OOooOOo * I1Ii111
  lisp . lprint ( "Use group-mapping '{}' {} for group {}" . format ( ooO . group_name , ooO . group_prefix . print_prefix ( ) , ii ) )
  if 50 - 50: IiII % i1IIi
  if 21 - 21: OoooooooOO - iIii1I11I1II1
  IIi1i1I11Iii = ooO . group_prefix . instance_id
  IiI111111IIII = ooO . use_ms_name
  OO0OoOOO0 = ooO . rle_address
  if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
  if 62 - 62: i1IIi - OoOoOO00
  if 62 - 62: i1IIi + Oo0Ooo % IiII
  if 28 - 28: I1ii11iIi11i . i1IIi
  if 10 - 10: OoO0O00 / Oo0Ooo
  I1i = IiI111111IIII
  if ( oOOO0oo0 ) :
   I1i = lisp . lisp_get_decent_dns_name_from_str ( IIi1i1I11Iii , ii )
   o0o0oOoOO0O [ I1i ] = [ "" , 0 ]
   if 50 - 50: o0oOOo0O0Ooo * Ii1I % I1ii11iIi11i / Oo0Ooo - O0 % iII111i
   if 48 - 48: I1IiiI + I1ii11iIi11i + II111iiii * i11iIiiIii
  if ( len ( ooO . sources ) == 0 ) :
   entries . append ( [ "0.0.0.0" , ii , IIi1i1I11Iii , I1i , OO0OoOOO0 , II1I11IIi ] )
   continue
   if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
  for OO0Oooo0oOO0O in ooO . sources :
   o0o0oOoOO0O [ I1i ] = [ "" , 0 ]
   entries . append ( [ OO0Oooo0oOO0O , ii , IIi1i1I11Iii , I1i , OO0OoOOO0 , II1I11IIi ] )
   if 39 - 39: iIii1I11I1II1 - OoooooooOO
   if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
   if 23 - 23: II111iiii / oO0o
 oOooO00o0O = len ( entries )
 if ( oOooO00o0O == 0 ) : return
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 lisp . lprint ( "Build Map-Register for {} multicast entries" . format ( oOooO00o0O ) )
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 OOooo00 = lisp . lisp_rle_node ( )
 OOooo00 . level = 128
 i1oO = lisp . lisp_get_any_translated_rloc ( )
 OO0OoOOO0 = lisp . lisp_rle ( "" )
 OO0OoOOO0 . rle_nodes . append ( OOooo00 )
 if 30 - 30: Oo0Ooo . OoO0O00
 if 57 - 57: I11i . Oo0Ooo + II111iiii
 if 43 - 43: I1Ii111 % iII111i
 if 69 - 69: iII111i % OoO0O00
 if 86 - 86: oO0o / oO0o
 if 28 - 28: i11iIiiIii / o0oOOo0O0Ooo . iIii1I11I1II1 / II111iiii
 if ( oOOO0oo0 == False ) :
  for iiIiIIi in list ( lisp . lisp_map_servers_list . values ( ) ) :
   o0o0oOoOO0O [ iiIiIIi . ms_name ] = [ "" , 0 ]
   if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
   if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
   if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 ii1IiIi11 = None
 if ( lisp . lisp_nat_traversal ) : ii1IiIi11 = lisp . lisp_hostname
 if 22 - 22: oO0o
 if 33 - 33: iIii1I11I1II1 / Ii1I
 if 1 - 1: Ii1I
 if 48 - 48: O0 + O0 . I1Ii111 - ooOoO0o
 o00oo0000 = 0
 for iII1i11IIi1i in list ( lisp . lisp_rtr_list . values ( ) ) :
  if ( iII1i11IIi1i == None ) : continue
  o00oo0000 += 1
  if 44 - 44: Oo0Ooo % iIii1I11I1II1
  if 90 - 90: II111iiii + OoooooooOO % OoooooooOO
  if 35 - 35: iII111i / I1ii11iIi11i * OoooooooOO . II111iiii / Oo0Ooo
  if 1 - 1: OoooooooOO + IiII . i1IIi % I11i
  if 66 - 66: o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
 iI1iIii11Ii = ""
 for ooooooo00o , ii , IIi1i1I11Iii , i1i1IIIIi1i , I1 , II1I11IIi in entries :
  if 13 - 13: OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - Oo0Ooo / oO0o
  if 8 - 8: OoOoOO00 / O0 * O0 % I1Ii111 - Oo0Ooo + I11i
  if 83 - 83: O0 . I1IiiI
  if 95 - 95: I11i . OoooooooOO - i1IIi - OoooooooOO - OoO0O00 % iIii1I11I1II1
  if ( i1i1IIIIi1i not in o0o0oOoOO0O ) : continue
  if 64 - 64: OOooOOo + OoooooooOO * OoooooooOO
  I1i1i1 = lisp . lisp_eid_record ( )
  I1i1i1 . rloc_count = 1 + o00oo0000
  I1i1i1 . authoritative = True
  I1i1i1 . record_ttl = lisp . LISP_REGISTER_TTL if II1I11IIi else 0
  I1i1i1 . eid = lisp . lisp_address ( iIIiiIIi1IiI , ooooooo00o , 0 , IIi1i1I11Iii )
  if ( I1i1i1 . eid . address == 0 ) : I1i1i1 . eid . mask_len = 0
  I1i1i1 . group = lisp . lisp_address ( iIIiiIIi1IiI , ii , 0 , IIi1i1I11Iii )
  if ( I1i1i1 . group . is_mac_broadcast ( ) and I1i1i1 . eid . address == 0 ) : I1i1i1 . eid . mask_len = 0
  if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
  if 100 - 100: Ii1I + OoO0O00
  iiI = ""
  IiI111111IIII = ""
  if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
   iiI = lisp . lisp_get_decent_index ( I1i1i1 . group )
   iiI = lisp . bold ( str ( iiI ) , False )
   iiI = "with decent-index {}" . format ( iiI )
  else :
   iiI = "for ms-name '{}'" . format ( i1i1IIIIi1i )
   if 73 - 73: i1IIi - I1Ii111 % ooOoO0o / OoO0O00
   if 40 - 40: I1ii11iIi11i * ooOoO0o - I1IiiI / IiII / i11iIiiIii
  OOO0o = lisp . green ( I1i1i1 . print_eid_tuple ( ) , False )
  lisp . lprint ( "  EID-prefix {} {}{}" . format ( OOO0o , IiI111111IIII ,
 iiI ) )
  if 4 - 4: Oo0Ooo . i1IIi - iII111i
  iI1iIii11Ii += I1i1i1 . encode ( )
  I1i1i1 . print_record ( "  " , False )
  o0o0oOoOO0O [ i1i1IIIIi1i ] [ 1 ] += 1
  if 10 - 10: I11i * Ii1I % OoooooooOO
  if 83 - 83: I1Ii111 - I1IiiI - I1ii11iIi11i % O0 . Ii1I
  if 35 - 35: IiII + i1IIi * oO0o - Ii1I . Oo0Ooo
  if 31 - 31: o0oOOo0O0Ooo
  iiI1iI111ii1i = lisp . lisp_rloc_record ( )
  iiI1iI111ii1i . rloc_name = ii1IiIi11
  if 15 - 15: O0 / Oo0Ooo % I1ii11iIi11i + o0oOOo0O0Ooo
  if 23 - 23: iIii1I11I1II1 + O0
  if 58 - 58: Oo0Ooo
  if 9 - 9: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo + OoooooooOO
  if 62 - 62: O0 / I1IiiI % O0 * OoO0O00 % I1IiiI
  if 33 - 33: I1IiiI . oO0o * OoO0O00 * iIii1I11I1II1
  if ( i1oO != None ) :
   OOooo00 . address = i1oO
  elif ( I1 != None ) :
   OOooo00 . address = I1
  else :
   OOooo00 . address = I1 = lisp . lisp_myrlocs [ 0 ]
   if 5 - 5: Oo0Ooo / IiII % O0 . I1Ii111 * IiII
   if 83 - 83: OOooOOo
  iiI1iI111ii1i . rle = OO0OoOOO0
  iiI1iI111ii1i . local_bit = True
  iiI1iI111ii1i . reach_bit = True
  iiI1iI111ii1i . priority = 255
  iiI1iI111ii1i . weight = 0
  iiI1iI111ii1i . mpriority = 1
  iiI1iI111ii1i . mweight = 100
  iI1iIii11Ii += iiI1iI111ii1i . encode ( )
  iiI1iI111ii1i . print_record ( "    " )
  if 12 - 12: i1IIi . i1IIi - o0oOOo0O0Ooo
  if 26 - 26: iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
  if 67 - 67: OoooooooOO
  if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
  if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
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
   if 93 - 93: i1IIi
   if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
   if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
   if 66 - 66: Oo0Ooo
   if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
  o0o0oOoOO0O [ i1i1IIIIi1i ] [ 0 ] += iI1iIii11Ii
  if 55 - 55: o0oOOo0O0Ooo . iII111i
  if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
  if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
  if 89 - 89: OoO0O00 + IiII * I1Ii111
  if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
 oo000 = lisp . lisp_map_register ( )
 oo000 . nonce = 0xaabbccdddfdfdf00
 oo000 . xtr_id_present = True
 oo000 . proxy_reply_requested = True
 oo000 . map_notify_requested = False
 oo000 . merge_register_requested = True
 if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 for iiIiIIi in list ( lisp . lisp_map_servers_list . values ( ) ) :
  I1i = iiIiIIi . dns_name if oOOO0oo0 else iiIiIIi . ms_name
  if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
  if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
  if 62 - 62: o0oOOo0O0Ooo
  if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
  if ( I1i not in o0o0oOoOO0O ) : continue
  if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
  if 72 - 72: iIii1I11I1II1
  if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
  oo000 . record_count = o0o0oOoOO0O [ I1i ] [ 1 ]
  if ( oo000 . record_count == 0 ) : continue
  if 87 - 87: OoO0O00 % I1IiiI
  oo000 . nonce += 1
  oo000 . alg_id = iiIiIIi . alg_id
  oo000 . alg_id = iiIiIIi . key_id
  oo000 . xtr_id = iiIiIIi . xtr_id
  oo000 . site_id = iiIiIIi . site_id
  oo000 . encrypt_bit = ( iiIiIIi . ekey != None )
  Oo = oo000 . encode ( )
  oo000 . print_map_register ( )
  if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
  if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
  if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
  if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
  if 84 - 84: i11iIiiIii * OoO0O00
  Ii1iI111 = oo000 . encode_xtr_id ( "" )
  Oo = Oo + iI1iIii11Ii + Ii1iI111
  if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
  iiIiIIi . map_registers_multicast_sent += 1
  lisp . lisp_send_map_register ( lisp_sockets , Oo , oo000 , iiIiIIi )
  if 30 - 30: O0 + I1ii11iIi11i + II111iiii
  if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
  if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
  if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
  iiIiIIi . resolve_dns_name ( )
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  if 64 - 64: i1IIi
  if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
  if 18 - 18: OOooOOo + I1Ii111
  time . sleep ( .001 )
  if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 return
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
def iiIii ( parms , not_used , packet ) :
 global i1 , oOOoo00O0O
 if 28 - 28: oO0o
 ooo0oo = parms [ 0 ]
 i1111 = parms [ 1 ]
 if 8 - 8: OoO0O00 + OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if ( lisp . lisp_is_macos ( ) == False ) :
  iIii11iI1II = 4 if ooo0oo == "lo0" else 16
  packet = packet [ iIii11iI1II : : ]
  if 42 - 42: ooOoO0o - I1IiiI + I1ii11iIi11i % Ii1I
  if 44 - 44: i1IIi - O0 - I1ii11iIi11i * I1ii11iIi11i + OoOoOO00
  if 56 - 56: ooOoO0o / iIii1I11I1II1 . Ii1I % OoOoOO00 + OOooOOo
  if 10 - 10: I1Ii111 * i11iIiiIii - iIii1I11I1II1 . Oo0Ooo - I1ii11iIi11i
  if 20 - 20: I1ii11iIi11i / I1IiiI * OoO0O00 * I1IiiI * O0
 IiiIIi = struct . unpack ( "B" , packet [ 9 ] ) [ 0 ]
 if ( IiiIIi == 2 ) :
  O00o0O = lisp . lisp_process_igmp_packet ( packet )
  if ( type ( O00o0O ) != bool ) :
   OooOO0o0 ( oOOoo00O0O , O00o0O )
   return
   if 32 - 32: o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
   if 39 - 39: OoooooooOO * OOooOOo * O0 . I11i . OoO0O00 + ooOoO0o
   if 9 - 9: OoOoOO00 + oO0o % OoooooooOO + o0oOOo0O0Ooo
   if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
   if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
   if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 IiI1iiI1III1I = packet
 packet , ooooooo00o , Oo000 , ooo00Oo = lisp . lisp_is_rloc_probe ( packet , 0 )
 if ( IiI1iiI1III1I != packet ) :
  if ( ooooooo00o == None ) : return
  lisp . lisp_parse_packet ( oOOoo00O0O , packet , ooooooo00o , Oo000 , ooo00Oo )
  return
  if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
  if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
  if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
  if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
  if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
  if 71 - 71: IiII . I1Ii111 . OoO0O00
  if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if ( struct . unpack ( "B" , packet [ 0 ] ) [ 0 ] & 0xf0 == 0x40 ) :
  o00OoO0oO00 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
  if ( lisp . lisp_nat_traversal and o00OoO0oO00 == lisp . LISP_DATA_PORT ) : return
  packet = lisp . lisp_reassemble ( packet )
  if ( packet == None ) : return
  if 2 - 2: iIii1I11I1II1
  if 45 - 45: OoooooooOO / i11iIiiIii
 packet = lisp . lisp_packet ( packet )
 I11I1i1iI = packet . decode ( True , i1 , lisp . lisp_decap_stats )
 if ( I11I1i1iI == None ) : return
 if 90 - 90: IiII * II111iiii % I1Ii111 + oO0o
 if 93 - 93: I1Ii111 + Ii1I
 if 33 - 33: O0
 if 78 - 78: O0 / II111iiii * OoO0O00
 packet . print_packet ( "Receive" , True )
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
 if 58 - 58: IiII + iIii1I11I1II1
 if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
 if 79 - 79: ooOoO0o . OoOoOO00 % I1Ii111 - Oo0Ooo
 if 69 - 69: ooOoO0o - o0oOOo0O0Ooo . ooOoO0o
 if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
 if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 45 - 45: O0 . i11iIiiIii % iII111i . OoOoOO00 % IiII % iIii1I11I1II1
  ooooooo00o = packet . inner_source . print_address_no_iid ( )
  packet . strip_outer_headers ( )
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , ooooooo00o , o00OoO0oO00 )
  lisp . lisp_ipc ( packet , i1 , "lisp-ms" )
  return
  if 58 - 58: iIii1I11I1II1 . OoOoOO00 - i11iIiiIii * iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if 80 - 80: I1ii11iIi11i / iIii1I11I1II1 % OoOoOO00
  if 80 - 80: OoO0O00 % iII111i
  if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
  if 13 - 13: OoO0O00
  if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
  if 2 - 2: OoooooooOO . OOooOOo . IiII
  if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
  if 19 - 19: oO0o * I1IiiI % i11iIiiIii
  if 24 - 24: o0oOOo0O0Ooo
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  iIi1Iii111I = packet . packet [ 36 : : ]
  II = iIi1Iii111I [ 28 : : ]
  ooo00Oo = - 1
  if ( lisp . lisp_is_rloc_probe_request ( II [ 0 ] ) ) :
   ooo00Oo = struct . unpack ( "B" , iIi1Iii111I [ 8 ] ) [ 0 ] - 1
   if 29 - 29: iII111i + i11iIiiIii % I11i
  ooooooo00o = packet . outer_source . print_address_no_iid ( )
  lisp . lisp_parse_packet ( oOOoo00O0O , II , ooooooo00o , 0 , ooo00Oo )
  return
  if 93 - 93: OoOoOO00 % iIii1I11I1II1
  if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
  if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
  if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
  if 21 - 21: OOooOOo
  if 6 - 6: IiII
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 46 - 46: IiII + oO0o
  if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
  if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
  if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
  if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 packet . strip_outer_headers ( )
 i1I1i1i = lisp . bold ( "Forward" , False )
 if 36 - 36: II111iiii % O0
 if 35 - 35: iIii1I11I1II1 - OOooOOo % o0oOOo0O0Ooo
 if 30 - 30: I1Ii111 % I1Ii111 % IiII . OoOoOO00
 if 9 - 9: ooOoO0o / II111iiii . OoOoOO00 % o0oOOo0O0Ooo * II111iiii - ooOoO0o
 oOOoo0 = False
 IIIIiI11I = packet . inner_dest . is_mac ( )
 if ( IIIIiI11I ) :
  packet . packet = lisp . lisp_mac_input ( packet . packet )
  if ( packet . packet == None ) : return
  i1I1i1i = lisp . bold ( "Bridge" , False )
 elif ( packet . inner_version == 4 ) :
  oOOoo0 , packet . packet = lisp . lisp_ipv4_input ( packet . packet )
  if ( packet . packet == None ) : return
  if ( oOOoo0 ) :
   O00o0O = lisp . lisp_process_igmp_packet ( packet . packet )
   if ( type ( O00o0O ) != bool ) :
    OooOO0o0 ( oOOoo00O0O , O00o0O )
    return
    if 31 - 31: Ii1I
    if 18 - 18: ooOoO0o + Ii1I
  packet . inner_ttl = packet . outer_ttl
 elif ( packet . inner_version == 6 ) :
  packet . packet = lisp . lisp_ipv6_input ( packet )
  if ( packet . packet == None ) : return
  packet . inner_ttl = packet . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 5 - 5: OoooooooOO + I11i * II111iiii
  if 98 - 98: OOooOOo % i1IIi . I1IiiI . II111iiii . I1ii11iIi11i / i11iIiiIii
  if 32 - 32: o0oOOo0O0Ooo + I1IiiI . I1Ii111
  if 41 - 41: OoOoOO00 . i11iIiiIii / I11i
  if 98 - 98: OoOoOO00 % II111iiii
  if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
  if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
  if 68 - 68: o0oOOo0O0Ooo
  if 20 - 20: I1Ii111 - I1Ii111
  if 37 - 37: IiII
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  O0oOoOO = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( O0oOoOO ) :
   O0oOoOO . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 37 - 37: Oo0Ooo / IiII * O0
   return
   if 73 - 73: iII111i * iII111i / ooOoO0o
 else :
  if ( lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False ) ) :
   lisp . dprint ( "Discard echoed multicast packet (through NAT)" )
   return
   if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
   if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
   if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
   if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
   if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
   if 6 - 6: iIii1I11I1II1 * OoooooooOO
   if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
   if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 69 - 69: I1ii11iIi11i
  if 83 - 83: o0oOOo0O0Ooo
  if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
  if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
  if 48 - 48: iII111i + IiII
 i1Ii = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( i1I1i1i , lisp . green ( i1Ii , False ) ,
 # O0
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 70 - 70: Ii1I . i11iIiiIii % Ii1I . O0 - iIii1I11I1II1
 if 26 - 26: OOooOOo
 if 76 - 76: i1IIi * OoooooooOO * O0 + I1Ii111 * I1Ii111
 if 35 - 35: o0oOOo0O0Ooo
 if 73 - 73: O0 - I1ii11iIi11i
 if ( IIIIiI11I ) :
  packet . bridge_l2_packet ( packet . inner_dest , O0oOoOO )
  return
  if 2 - 2: II111iiii / I1Ii111
  if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
  if 22 - 22: ooOoO0o . iIii1I11I1II1
  if 12 - 12: Ii1I
  if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
  if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( i11 , I11 )
  return
  if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
  if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
  if 65 - 65: oO0o + OoOoOO00 + II111iiii
  if 77 - 77: II111iiii
  if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 ooo000oOO = packet . get_raw_socket ( )
 if ( ooo000oOO == None ) : ooo000oOO = i1111
 if 27 - 27: o0oOOo0O0Ooo * i11iIiiIii * OoO0O00
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 packet . send_packet ( ooo000oOO , packet . inner_dest )
 return
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
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
def oO0O ( lisp_raw_socket , packet , source ) :
 global i1 , oOOoo00O0O
 if 26 - 26: iIii1I11I1II1 + i1IIi / OoOoOO00 % I1ii11iIi11i
 if 44 - 44: OoooooooOO . II111iiii . OOooOOo % OoooooooOO
 if 86 - 86: i11iIiiIii + O0 * IiII - OoO0O00 * OOooOOo + O0
 if 95 - 95: iIii1I11I1II1 . I1Ii111 % iII111i - I1Ii111 * II111iiii
 o0oooOoo0OoOO = packet
 packet = lisp . lisp_packet ( packet [ 8 : : ] )
 if ( packet . lisp_header . decode ( o0oooOoo0OoOO ) == False ) : return
 if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
 if 61 - 61: I1Ii111 - Ii1I % I1ii11iIi11i / ooOoO0o / iII111i + iIii1I11I1II1
 if 87 - 87: I1Ii111 + ooOoO0o + O0 / i1IIi % IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 packet . outer_source = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , source ,
 lisp . LISP_IPV4_HOST_MASK_LEN , 0 )
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 I11I1i1iI = packet . decode ( False , i1 ,
 lisp . lisp_decap_stats )
 if ( I11I1i1iI == None ) : return
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if 80 - 80: OoooooooOO + IiII
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if 43 - 43: Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if ( lisp . lisp_flow_logging ) : packet . log_flow ( False )
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 packet . print_packet ( "Kernel-decap" , False )
 lisp . dprint ( packet . lisp_header . print_header ( " " ) )
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 49 - 49: IiII * O0 . IiII
  o00OoO0oO00 = packet . udp_sport
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , source , o00OoO0oO00 )
  lisp . lisp_ipc ( packet , i1 , "lisp-ms" )
  return
  if 19 - 19: II111iiii - IiII
  if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
  if 89 - 89: OOooOOo
  if 69 - 69: ooOoO0o - OoooooooOO * O0
  if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
  if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
  if 96 - 96: OoooooooOO + IiII * O0
  if 86 - 86: Ii1I
  if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  iIi1Iii111I = packet . packet
  II = iIi1Iii111I [ 28 : : ]
  ooo00Oo = - 1
  if ( lisp . lisp_is_rloc_probe_request ( II [ 0 ] ) ) :
   ooo00Oo = struct . unpack ( "B" , iIi1Iii111I [ 8 ] ) [ 0 ] - 1
   if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
  lisp . lisp_parse_packet ( oOOoo00O0O , II , source , 0 , ooo00Oo )
  return
  if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
  if 69 - 69: OoOoOO00
  if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
  if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
  if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
  if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
  if 88 - 88: o0oOOo0O0Ooo
  if 1 - 1: OoooooooOO
  if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
  if 40 - 40: i11iIiiIii . iIii1I11I1II1
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  O0oOoOO = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( O0oOoOO ) :
   O0oOoOO . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
   if 27 - 27: OOooOOo
   if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 else :
  if ( lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False ) ) :
   lisp . dprint ( "Discard echoed multicast packet" )
   return
   if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
   if 74 - 74: oO0o
   if 34 - 34: iII111i
   if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
   if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
   if 43 - 43: OoO0O00 % OoO0O00
   if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
   if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
  if 45 - 45: Ii1I - OOooOOo
 i1Ii = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( lisp . bold ( "NAT-Forward" , False ) , lisp . green ( i1Ii , False ) ,
 # I1ii11iIi11i
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 53 - 53: i11iIiiIii . I1ii11iIi11i % Ii1I / ooOoO0o % iIii1I11I1II1
 if 6 - 6: Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( i11 , I11 )
  return
  if 83 - 83: O0
  if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
  if 40 - 40: OoO0O00 + OoO0O00
  if 94 - 94: iII111i * iIii1I11I1II1 . I11i
  if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 ooo000oOO = packet . get_raw_socket ( )
 if ( ooo000oOO == None ) : ooo000oOO = lisp_raw_socket
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 packet . send_packet ( ooo000oOO , packet . inner_dest )
 return
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 if 24 - 24: ooOoO0o - I11i * oO0o
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
def iii ( group , joinleave ) :
 ooO = lisp . lisp_lookup_group ( group )
 if ( ooO == None ) : return
 if 15 - 15: I1IiiI . OoO0O00
 IiiIi = [ ]
 for OO0Oooo0oOO0O in ooO . sources :
  IiiIi . append ( [ OO0Oooo0oOO0O , group , joinleave ] )
  if 42 - 42: iII111i + iIii1I11I1II1
  if 21 - 21: OoOoOO00 - Oo0Ooo % O0 . OoO0O00 + OoOoOO00
 OooOO0o0 ( oOOoo00O0O , IiiIi )
 return
 if 41 - 41: II111iiii * ooOoO0o
 if 68 - 68: Ii1I - I1IiiI
 if 41 - 41: oO0o
 if 21 - 21: ooOoO0o + o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + II111iiii
 if 98 - 98: I1Ii111
 if 49 - 49: Oo0Ooo * oO0o + o0oOOo0O0Ooo - i11iIiiIii
 if 74 - 74: Oo0Ooo / iIii1I11I1II1 . II111iiii - OoO0O00
 if 62 - 62: OOooOOo / II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
def I1i1II1 ( ) :
 global oOOoo00O0O
 if 89 - 89: OoO0O00 / OoO0O00
 lisp . lisp_set_exception ( )
 if 1 - 1: I1ii11iIi11i . i11iIiiIii
 OooooOo = socket . htonl
 IIIiiiIiI = [ OooooOo ( 0x46000020 ) , OooooOo ( 0x9fe60000 ) , OooooOo ( 0x0102d7cc ) ,
 OooooOo ( 0x0acfc15a ) , OooooOo ( 0xe00000fb ) , OooooOo ( 0x94040000 ) ]
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 Oo = ""
 for IiIi1Ii in IIIiiiIiI : Oo += struct . pack ( "I" , IiIi1Ii )
 if 39 - 39: Ii1I
 if 24 - 24: i11iIiiIii - Ii1I + oO0o * I1IiiI
 if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
 if 64 - 64: I11i + OoO0O00
 if 25 - 25: I1IiiI . ooOoO0o + I1IiiI % Ii1I * iIii1I11I1II1
 while ( True ) :
  iiI1iI = getoutput ( "ls join-*" ) . replace ( "join-" , "" )
  iiI1iI = iiI1iI . split ( "\n" )
  if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
  for ii in iiI1iI :
   if ( lisp . lisp_valid_address_format ( "address" , ii ) == False ) :
    continue
    if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
    if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
   iI1i = ( ii . find ( ":" ) != - 1 )
   if 3 - 3: IiII / I11i
   if 34 - 34: i11iIiiIii / I1Ii111 * OOooOOo . Oo0Ooo
   if 79 - 79: I1Ii111
   if 31 - 31: OOooOOo % I1Ii111
   O0oo00oOOO0o = os . path . exists ( "leave-{}" . format ( ii ) )
   lisp . lprint ( "Internal {} group {}" . format ( "leaving" if O0oo00oOOO0o else "joining" , ii ) )
   if 5 - 5: o0oOOo0O0Ooo / I1IiiI % Ii1I . IiII
   if 86 - 86: i1IIi * OoOoOO00 . O0 - Ii1I - o0oOOo0O0Ooo - OoOoOO00
   if 47 - 47: OOooOOo + I11i
   if 50 - 50: I1Ii111 + I1ii11iIi11i
   if 4 - 4: IiII / Oo0Ooo
   if ( iI1i ) :
    if ( ii . lower ( ) . find ( "ff02:" ) != - 1 ) :
     lisp . lprint ( "Suppress registration for link-local groups" )
     continue
     if 31 - 31: I1Ii111 - I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - oO0o
    iii ( ii , ( O0oo00oOOO0o == False ) )
   else :
    i1iIii = Oo
    if ( O0oo00oOOO0o ) :
     i1iIii += struct . pack ( "I" , OooooOo ( 0x17000000 ) )
    else :
     i1iIii += struct . pack ( "I" , OooooOo ( 0x16000000 ) )
     if 65 - 65: iII111i . oO0o - Ii1I
     if 93 - 93: O0
    iii1 = ii . split ( "." )
    Ooo0OOoOoO0 = int ( iii1 [ 0 ] ) << 24
    Ooo0OOoOoO0 += int ( iii1 [ 1 ] ) << 16
    Ooo0OOoOoO0 += int ( iii1 [ 2 ] ) << 8
    Ooo0OOoOoO0 += int ( iii1 [ 3 ] )
    i1iIii += struct . pack ( "I" , OooooOo ( Ooo0OOoOoO0 ) )
    IiiIi = lisp . lisp_process_igmp_packet ( i1iIii )
    if ( type ( IiiIi ) != bool ) :
     OooOO0o0 ( oOOoo00O0O , IiiIi )
     if 69 - 69: ooOoO0o % ooOoO0o
    time . sleep ( .100 )
    if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
    if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
  time . sleep ( 10 )
  if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 return
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
 if 33 - 33: Ii1I
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
 ooo0oo = "any"
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
 ooo0oo ) )
 if 6 - 6: OoooooooOO / i11iIiiIii / I1Ii111
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if ( lisp . lisp_is_python2 ( ) ) :
  ooO0 = pcappy . open_live ( ooo0oo , 1600 , 0 , 100 )
  ooO0 . filter = oOoO
  ooO0 . loop ( - 1 , iiIii , [ ooo0oo , i1111 ] )
  if 94 - 94: I11i . I1IiiI
 if ( lisp . lisp_is_python3 ( ) ) :
  ooO0 = pcapy . open_live ( ooo0oo , 1600 , 0 , 100 )
  ooO0 . setfilter ( oOoO )
  ooO0 . loop ( - 1 , iiIii )
  if 73 - 73: i1IIi / II111iiii
 return
 if 45 - 45: Ii1I / ooOoO0o . OoooooooOO + OoO0O00
 if 51 - 51: iII111i % i11iIiiIii % IiII + I1Ii111 % I1ii11iIi11i
 if 16 - 16: OoOoOO00 / Oo0Ooo + O0 - OoOoOO00 . OoooooooOO
 if 19 - 19: o0oOOo0O0Ooo
 if 73 - 73: I1Ii111 * Oo0Ooo * OoOoOO00
 if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
def OOoO0oO00o ( ) :
 global i1
 global Oo0oO0ooo
 global oOOoo00O0O
 global i1111
 global i11
 global I11
 if 78 - 78: Oo0Ooo * I1Ii111 - OoooooooOO - OoO0O00
 lisp . lisp_i_am ( "etr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "ETR starting up" )
 if 83 - 83: ooOoO0o / OOooOOo
 if 39 - 39: IiII + I11i
 if 9 - 9: I1IiiI % I11i . Oo0Ooo * I1IiiI
 if 99 - 99: O0 . o0oOOo0O0Ooo % I11i - Oo0Ooo / I11i
 lisp . lisp_get_local_interfaces ( )
 lisp . lisp_get_local_macs ( )
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 20 - 20: OoOoOO00 * iII111i
 if 19 - 19: OoooooooOO
 if 76 - 76: OoO0O00 * oO0o
 if 63 - 63: II111iiii . II111iiii + I1ii11iIi11i + OOooOOo + O0 . Ii1I
 if 1 - 1: O0 * i11iIiiIii - ooOoO0o - Ii1I
 if 94 - 94: OoO0O00 + IiII + ooOoO0o
 if 82 - 82: Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + IiII % iIii1I11I1II1
 if 61 - 61: OOooOOo / Oo0Ooo % OOooOOo - OoO0O00 + ooOoO0o / ooOoO0o
 if 82 - 82: Oo0Ooo
 if 5 - 5: OoO0O00 / OoO0O00 - O0 - I1Ii111 + I1Ii111
 if 99 - 99: I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - iIii1I11I1II1 - Ii1I
 if 31 - 31: IiII - OoO0O00 / OOooOOo . i1IIi / Ii1I
 if 66 - 66: OoO0O00
 if 72 - 72: I1Ii111
 if 91 - 91: II111iiii / IiII + iIii1I11I1II1 . I11i - O0
 OO0Oooo0oOO0O = lisp . lisp_open_listen_socket ( "0.0.0.0" , str ( o0oOoO00o ) )
 OO0Oooo0oOO0O . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_TTL , 32 )
 Oo0oO0ooo = OO0Oooo0oOO0O
 if 70 - 70: Ii1I * oO0o - I11i + Oo0Ooo % I1ii11iIi11i - IiII
 if 81 - 81: O0 . O0
 if 75 - 75: iIii1I11I1II1 % IiII + I1ii11iIi11i * O0 . iII111i - ooOoO0o
 if 32 - 32: Ii1I % oO0o - i1IIi
 i1 = lisp . lisp_open_listen_socket ( "" , "lisp-etr" )
 if 40 - 40: iIii1I11I1II1 + iII111i * OoOoOO00 + oO0o
 oOOoo00O0O [ 0 ] = Oo0oO0ooo
 oOOoo00O0O [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 oOOoo00O0O [ 2 ] = i1
 if 15 - 15: I11i % I1IiiI - iIii1I11I1II1 * ooOoO0o
 if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
 if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
 if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
 if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
 if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
 if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
 if 93 - 93: ooOoO0o
 if 18 - 18: ooOoO0o
 i1111 = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 i1111 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 oOOoo00O0O . append ( i1111 )
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
 if 90 - 90: Oo0Ooo * I1IiiI
 if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
 if ( pytun != None ) :
  I11 = '\x00\x00\x86\xdd'
  ooo0oo = "lispers.net"
  try :
   i11 = pytun . TunTapDevice ( flags = pytun . IFF_TUN ,
 name = ooo0oo )
   os . system ( "ip link set dev {} up" . format ( ooo0oo ) )
  except :
   lisp . lprint ( "Cannot create tuntap interface" )
   if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
   if 28 - 28: IiII * I1IiiI % IiII
   if 95 - 95: O0 / I11i . I1Ii111
   if 17 - 17: I11i
   if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
   if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 threading . Thread ( target = o0OO0oooo , args = [ ] ) . start ( )
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 threading . Thread ( target = I1i1II1 , args = [ ] ) . start ( )
 return ( True )
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 if 36 - 36: IiII
 if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
 if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
 if 43 - 43: iIii1I11I1II1 % OoO0O00
 if 84 - 84: Oo0Ooo
def iiiiI11iiIIi ( ) :
 global ooO0oo0oO0
 global o00
 if 43 - 43: I11i % Ii1I / o0oOOo0O0Ooo * I1Ii111
 if 85 - 85: iIii1I11I1II1 . OoooooooOO . o0oOOo0O0Ooo
 if 77 - 77: I1IiiI % ooOoO0o
 if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
 if ( ooO0oo0oO0 ) : ooO0oo0oO0 . cancel ( )
 if ( o00 ) : o00 . cancel ( )
 if 52 - 52: IiII % ooOoO0o
 if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
 if 23 - 23: i11iIiiIii
 if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
 lisp . lisp_close_socket ( oOOoo00O0O [ 0 ] , "" )
 lisp . lisp_close_socket ( oOOoo00O0O [ 1 ] , "" )
 lisp . lisp_close_socket ( i1 , "lisp-etr" )
 return
 if 65 - 65: II111iiii / Oo0Ooo
 if 42 - 42: i11iIiiIii . O0
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
 if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
 if 92 - 92: I11i / O0 * I1IiiI - I11i
 if 99 - 99: i11iIiiIii % OoooooooOO
 if 56 - 56: IiII * I1Ii111
 if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
def I11I111i1I1 ( ipc ) :
 ipc = ipc . split ( "%" )
 OOO0o = ipc [ 1 ]
 iii1O0Ooo0O = ipc [ 2 ]
 if ( iii1O0Ooo0O == "None" ) : iii1O0Ooo0O = None
 if 18 - 18: i1IIi
 i1OO0oOOoo = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 i1OO0oOOoo . store_address ( OOO0o )
 if 4 - 4: IiII
 if 93 - 93: oO0o % i1IIi
 if 83 - 83: I1IiiI . Oo0Ooo - I11i . o0oOOo0O0Ooo
 if 73 - 73: I1IiiI - iII111i . iII111i
 O0oOoOO = lisp . lisp_db_for_lookups . lookup_cache ( i1OO0oOOoo , False )
 if ( O0oOoOO == None or O0oOoOO . dynamic_eid_configured ( ) == False ) :
  lisp . lprint ( "ITR/ETR dynamic-EID configuration out of sync for {}" . format ( lisp . green ( OOO0o , False ) ) )
  if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
  return
  if 64 - 64: i1IIi % I1ii11iIi11i / Ii1I % OoooooooOO
  if 24 - 24: I1Ii111 + OoooooooOO . IiII / OoOoOO00 / I11i
  if 65 - 65: OoooooooOO
  if 18 - 18: O0 - i1IIi . I1Ii111
  if 98 - 98: o0oOOo0O0Ooo
  if 73 - 73: Oo0Ooo - iII111i . oO0o % i1IIi . O0
 I1IIIiI1I1ii1 = None
 if ( OOO0o in O0oOoOO . dynamic_eids ) : I1IIIiI1I1ii1 = O0oOoOO . dynamic_eids [ OOO0o ]
 if 15 - 15: ooOoO0o . iIii1I11I1II1 * I1IiiI % I11i
 if ( I1IIIiI1I1ii1 == None and iii1O0Ooo0O == None ) :
  lisp . lprint ( "ITR/ETR state mismatch for {}" . format ( lisp . green ( OOO0o , False ) ) )
  if 21 - 21: OoO0O00 - I1IiiI . OoooooooOO
  return
  if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
  if 3 - 3: OOooOOo . IiII / Oo0Ooo
  if 89 - 89: OoooooooOO . iIii1I11I1II1 . Oo0Ooo * iIii1I11I1II1 - I1Ii111
  if 92 - 92: OoooooooOO - I1ii11iIi11i - OoooooooOO % I1IiiI % I1IiiI % iIii1I11I1II1
  if 92 - 92: iII111i * O0 % I1Ii111 . iIii1I11I1II1
  if 66 - 66: I11i + Ii1I
  if 48 - 48: I1ii11iIi11i
 if ( I1IIIiI1I1ii1 and iii1O0Ooo0O ) :
  if ( I1IIIiI1I1ii1 . interface == iii1O0Ooo0O ) :
   lisp . lprint ( "ITR sent redundant IPC for {}" . format ( lisp . green ( OOO0o , False ) ) )
   if 96 - 96: ooOoO0o . OoooooooOO
  else :
   lisp . lprint ( "Dynamic-EID {} interface change, {} -> {}" . format ( lisp . green ( OOO0o , False ) , I1IIIiI1I1ii1 . interface , iii1O0Ooo0O ) )
   if 39 - 39: OOooOOo + OoO0O00
   I1IIIiI1I1ii1 . interface = iii1O0Ooo0O
   if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
  return
  if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
  if 71 - 71: ooOoO0o . i11iIiiIii
  if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
  if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
  if 67 - 67: iII111i
 if ( iii1O0Ooo0O ) :
  I1IIIiI1I1ii1 = lisp . lisp_dynamic_eid ( )
  I1IIIiI1I1ii1 . dynamic_eid . copy_address ( i1OO0oOOoo )
  I1IIIiI1I1ii1 . interface = iii1O0Ooo0O
  I1IIIiI1I1ii1 . get_timeout ( iii1O0Ooo0O )
  O0oOoOO . dynamic_eids [ OOO0o ] = I1IIIiI1I1ii1
  if 88 - 88: Oo0Ooo
  i1ii111i = lisp . bold ( "Registering" , False )
  OOO0o = lisp . bold ( OOO0o , False )
  lisp . lprint ( "{} dynamic-EID {} on interface {}, timeout {}" . format ( i1ii111i ,
 lisp . green ( OOO0o , False ) , iii1O0Ooo0O , I1IIIiI1I1ii1 . timeout ) )
  if 42 - 42: OOooOOo % OoooooooOO / IiII
  I1i1iii ( oOOoo00O0O , None , i1OO0oOOoo , None , False )
  if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
  if 71 - 71: ooOoO0o . ooOoO0o - iIii1I11I1II1
  if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
  if ( lisp . lisp_is_macos ( ) == False ) :
   OOO0o = i1OO0oOOoo . print_prefix_no_iid ( )
   Ooo0oOOoo0O = "ip route add {} dev {}" . format ( OOO0o , iii1O0Ooo0O )
   os . system ( Ooo0oOOoo0O )
   if 57 - 57: I1IiiI . i11iIiiIii * II111iiii + OoooooooOO + Ii1I
  return
  if 73 - 73: O0 % I11i + iII111i . I1ii11iIi11i . I1ii11iIi11i + IiII
  if 30 - 30: OoOoOO00
  if 89 - 89: I11i
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  if 79 - 79: IiII + IiII + Ii1I
 if ( OOO0o in O0oOoOO . dynamic_eids ) :
  iii1O0Ooo0O = O0oOoOO . dynamic_eids [ OOO0o ] . interface
  iiiII1i1I = lisp . bold ( "Deregistering" , False )
  lisp . lprint ( "{} dynamic-EID {}" . format ( iiiII1i1I ,
 lisp . green ( OOO0o , False ) ) )
  if 97 - 97: O0 . I1Ii111 / II111iiii . O0 + OoooooooOO
  I1i1iii ( oOOoo00O0O , 0 , i1OO0oOOoo , None , False )
  if 78 - 78: II111iiii + IiII
  O0oOoOO . dynamic_eids . pop ( OOO0o )
  if 66 - 66: iIii1I11I1II1
  if 57 - 57: IiII
  if 41 - 41: iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % IiII / OOooOOo
  if 63 - 63: i1IIi % i11iIiiIii % II111iiii * OoooooooOO
  if ( lisp . lisp_is_macos ( ) == False ) :
   OOO0o = i1OO0oOOoo . print_prefix_no_iid ( )
   Ooo0oOOoo0O = "ip route delete {} dev {}" . format ( OOO0o , iii1O0Ooo0O )
   os . system ( Ooo0oOOoo0O )
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
def o000ooOo0o0OO ( ipc ) :
 if ( lisp . lisp_register_all_rtrs ) : return
 if 1 - 1: iIii1I11I1II1 % ooOoO0o + O0
 IIiII11 , o0OOOooo0OOo , I11I1i1iI = ipc . split ( "%" )
 if ( o0OOOooo0OOo not in lisp . lisp_rtr_list ) : return
 if 58 - 58: iII111i
 lisp . lprint ( "Process ITR IPC message, RTR {} has gone {}" . format (
 lisp . red ( o0OOOooo0OOo , False ) , lisp . bold ( I11I1i1iI , False ) ) )
 if 2 - 2: IiII - oO0o % OoO0O00 + o0oOOo0O0Ooo + Ii1I - iIii1I11I1II1
 iII1i11IIi1i = lisp . lisp_rtr_list [ o0OOOooo0OOo ]
 if ( I11I1i1iI == "down" ) :
  lisp . lisp_rtr_list [ o0OOOooo0OOo ] = None
  return
  if 18 - 18: I1ii11iIi11i / Oo0Ooo - iII111i
  if 69 - 69: oO0o / IiII * ooOoO0o
 iII1i11IIi1i = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , o0OOOooo0OOo , 32 , 0 )
 lisp . lisp_rtr_list [ o0OOOooo0OOo ] = iII1i11IIi1i
 return
 if 81 - 81: oO0o
 if 62 - 62: Ii1I + O0 * OoO0O00
 if 59 - 59: II111iiii
 if 43 - 43: Oo0Ooo + OoooooooOO
 if 47 - 47: ooOoO0o
 if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
 if 23 - 23: II111iiii * iII111i
 if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
def III11i1iI11 ( ipc ) :
 o0o0OOo0O , IIiII11 , OOoO0ooOOOo0 , o0oOOO = ipc . split ( "%" )
 o0oOOO = int ( o0oOOO , 16 )
 if 24 - 24: o0oOOo0O0Ooo / Ii1I / Ii1I % II111iiii - oO0o * oO0o
 oOoo0oO = lisp . lisp_get_echo_nonce ( None , OOoO0ooOOOo0 )
 if ( oOoo0oO == None ) : oOoo0oO = lisp . lisp_echo_nonce ( OOoO0ooOOOo0 )
 if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
 if ( IIiII11 == "R" ) :
  oOoo0oO . request_nonce_sent = o0oOOO
  lisp . lprint ( "Waiting for echo-nonce 0x{} from {}" . format ( lisp . lisp_hex_string ( o0oOOO ) , lisp . red ( oOoo0oO . rloc_str , False ) ) )
  if 18 - 18: OoooooooOO
 elif ( IIiII11 == "E" ) :
  oOoo0oO . echo_nonce_sent = o0oOOO
  lisp . lprint ( "Sent echo-nonce 0x{} to {}" . format ( lisp . lisp_hex_string ( o0oOOO ) , lisp . red ( oOoo0oO . rloc_str , False ) ) )
  if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
  if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
 return
 if 94 - 94: ooOoO0o + I1IiiI
 if 56 - 56: OoOoOO00 % o0oOOo0O0Ooo
 if 40 - 40: OOooOOo / IiII
 if 29 - 29: Ii1I - Ii1I / ooOoO0o
 if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
Ii1I1Iiii = {
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

 "lisp map-server" : [ oO , {
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
if 80 - 80: OOooOOo . Ii1I + iIii1I11I1II1
if 32 - 32: I1IiiI
if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
if 86 - 86: IiII
if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
if 33 - 33: II111iiii - IiII - ooOoO0o
if ( OOoO0oO00o ( ) == False ) :
 lisp . lprint ( "lisp_etr_startup() failed" )
 lisp . lisp_print_banner ( "ETR abnormal exit" )
 exit ( 1 )
 if 92 - 92: OoO0O00 * IiII
 if 92 - 92: oO0o
i1i1IIiII1I = [ Oo0oO0ooo , i1 ]
if 85 - 85: Oo0Ooo . i11iIiiIii - i11iIiiIii . I1IiiI . OoO0O00 % OoooooooOO
while ( True ) :
 try : I1111i , oooO0oooOo000 , o0o0OOo0O = select . select ( i1i1IIiII1I , [ ] , [ ] )
 except : break
 if 97 - 97: iIii1I11I1II1 + I1ii11iIi11i - OOooOOo
 if 98 - 98: i1IIi % II111iiii
 if 30 - 30: I1ii11iIi11i
 if 88 - 88: i1IIi % ooOoO0o . i11iIiiIii . i1IIi
 if ( Oo0oO0ooo in I1111i ) :
  IIiII11 , ooooooo00o , Oo000 , Oo = lisp . lisp_receive ( Oo0oO0ooo , False )
  if 82 - 82: i1IIi . I1ii11iIi11i
  if ( ooooooo00o == "" ) : break
  if 53 - 53: I1IiiI % OoooooooOO + I1Ii111 - Oo0Ooo / IiII * o0oOOo0O0Ooo
  if ( Oo000 == lisp . LISP_DATA_PORT ) :
   oO0O ( i1111 , Oo , ooooooo00o )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( Oo [ 0 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 79 - 79: OoooooooOO / I1IiiI
   O00 = lisp . lisp_parse_packet ( oOOoo00O0O , Oo ,
 ooooooo00o , Oo000 )
   if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
   if 6 - 6: oO0o . I11i
   if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
   if 50 - 50: oO0o % i1IIi * O0
   if 4 - 4: iIii1I11I1II1 . i1IIi
   if ( O00 ) :
    o00 = threading . Timer ( 0 ,
 Ooo , [ None ] )
    o00 . start ( )
    ooO0oo0oO0 = threading . Timer ( 0 ,
 iii11 , [ oOOoo00O0O ] )
    ooO0oo0oO0 . start ( )
    if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
    if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
    if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
    if 59 - 59: iIii1I11I1II1 / I1ii11iIi11i % ooOoO0o
    if 84 - 84: iIii1I11I1II1 / I1IiiI . OoOoOO00 % I11i
    if 99 - 99: Oo0Ooo + i11iIiiIii
    if 36 - 36: Ii1I * I1Ii111 * iIii1I11I1II1 - I11i % i11iIiiIii
    if 98 - 98: iIii1I11I1II1 - i1IIi + ooOoO0o % I11i + ooOoO0o / oO0o
 if ( i1 in I1111i ) :
  IIiII11 , ooooooo00o , Oo000 , Oo = lisp . lisp_receive ( i1 , True )
  if 97 - 97: IiII % ooOoO0o + II111iiii - IiII % OoO0O00 + ooOoO0o
  if ( ooooooo00o == "" ) : break
  if 31 - 31: o0oOOo0O0Ooo
  if ( IIiII11 == "command" ) :
   if ( Oo . find ( "learn%" ) != - 1 ) :
    I11I111i1I1 ( Oo )
   elif ( Oo . find ( "nonce%" ) != - 1 ) :
    III11i1iI11 ( Oo )
   elif ( Oo . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( Oo )
   elif ( Oo . find ( "rtr%" ) != - 1 ) :
    o000ooOo0o0OO ( Oo )
   elif ( Oo . find ( "stats%" ) != - 1 ) :
    Oo = Oo . split ( "%" ) [ - 1 ]
    lisp . lisp_process_data_plane_decap_stats ( Oo , None )
   else :
    lispconfig . lisp_process_command ( i1 ,
 IIiII11 , Oo , "lisp-etr" , [ Ii1I1Iiii ] )
    if 35 - 35: OoOoOO00 + Ii1I * ooOoO0o / OoOoOO00
  elif ( IIiII11 == "api" ) :
   lisp . lisp_process_api ( "lisp-etr" , i1 , Oo )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( Oo [ 0 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 69 - 69: ooOoO0o . OOooOOo - I1IiiI
   lisp . lisp_parse_packet ( oOOoo00O0O , Oo , ooooooo00o , Oo000 )
   if 29 - 29: i11iIiiIii . I1ii11iIi11i / I1IiiI . OOooOOo + i11iIiiIii
   if 26 - 26: IiII / Ii1I - OoooooooOO
   if 9 - 9: OoooooooOO * I1ii11iIi11i
   if 9 - 9: Oo0Ooo + iII111i
iiiiI11iiIIi ( )
lisp . lisp_print_banner ( "ETR normal exit" )
exit ( 0 )
if 64 - 64: O0 * I1IiiI / I1IiiI
if 57 - 57: I1ii11iIi11i / OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
