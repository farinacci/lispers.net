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
I1Ii11I1Ii1i = None
Ooo = lisp . lisp_get_ephemeral_port ( )
o0oOoO00o = None
i1 = [ None , None , None ]
oOOoo00O0O = None
i1111 = None
i11 = None
if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
o000o0o00o0Oo = 60
if 80 - 80: OoooooooOO . I1IiiI
if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
if 58 - 58: i11iIiiIii % I1Ii111
if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
if 13 - 13: OOooOOo * oO0o * I1IiiI
oOOOO = ( os . getenv ( "LISP_ETR_TEST_MODE" ) != None )
i11iiII = False
if 34 - 34: OOooOOo % OoooooooOO / i1IIi . iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
if 78 - 78: OoO0O00
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
if 14 - 14: I11i % O0
IiI1I1 = { }
if 86 - 86: i11iIiiIii + Ii1I + ooOoO0o * I11i + o0oOOo0O0Ooo
if 61 - 61: OoO0O00 / i11iIiiIii
if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - I1ii11iIi11i + i11iIiiIii
if 65 - 65: OoOoOO00
if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
if 100 - 100: Ii1I - Ii1I - I1Ii111
if 20 - 20: OoooooooOO
def Ii11iI1i ( kv_pair ) :
 global OOO0o0o
 global Ii1iI
 if 82 - 82: i11iIiiIii . OOooOOo / Oo0Ooo * O0 % oO0o % iIii1I11I1II1
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
   o00O ( i1 , None , None , Oo00OOOOO , False )
   if 69 - 69: oO0o % I1Ii111 - o0oOOo0O0Ooo + I1Ii111 - O0 % OoooooooOO
   if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
   if 4 - 4: II111iiii / ooOoO0o . iII111i
   if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
   if 50 - 50: I1IiiI
   if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
   if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 if ( oOOOO and i11iiII ) : return
 if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
 if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
 if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
 if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
 if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 if ( len ( lisp . lisp_db_list ) > 0 ) :
  if ( OOO0o0o != None ) : return
  OOO0o0o = threading . Timer ( 5 ,
 oo000OO00Oo , [ i1 ] )
  OOO0o0o . start ( )
  if 51 - 51: IiII * o0oOOo0O0Ooo + I11i + OoO0O00
  if 66 - 66: OoOoOO00
  if 97 - 97: oO0o % IiII * IiII
  if 39 - 39: Ii1I % IiII
  if 4 - 4: oO0o
  if 93 - 93: OoO0O00 % oO0o . OoO0O00 * I1Ii111 % Ii1I . II111iiii
  if 38 - 38: o0oOOo0O0Ooo
  if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
def i11iIIIIIi1 ( ) :
 global Oo
 if 20 - 20: i1IIi + I1ii11iIi11i - ooOoO0o
 lisp . lisp_set_exception ( )
 if 30 - 30: II111iiii - OOooOOo - i11iIiiIii % OoOoOO00 - II111iiii * Ii1I
 lisp . lisp_timeout_igmp_database ( )
 if 61 - 61: oO0o - I11i % OOooOOo
 if Oo : Oo . cancel ( )
 Oo = threading . Timer ( 60 , i11iIIIIIi1 )
 Oo . start ( )
 if 84 - 84: oO0o * OoO0O00 / I11i - O0
 if 30 - 30: iIii1I11I1II1 / ooOoO0o - I1Ii111 - II111iiii % iII111i
 if 49 - 49: I1IiiI % ooOoO0o . ooOoO0o . I11i * ooOoO0o
 if 97 - 97: Ii1I + o0oOOo0O0Ooo . OOooOOo + I1ii11iIi11i % iII111i
 if 95 - 95: i1IIi
 if 3 - 3: I1Ii111 - O0 / I1Ii111 % OoO0O00 / I1Ii111 . I1IiiI
 if 50 - 50: IiII
 if 14 - 14: I11i % OoO0O00 * I11i
def iII ( kv_pair ) :
 global Oo0o , OOO0o0o
 global i1 , i11iiII
 global lisp_seen_eid_done_count
 if 96 - 96: Oo0Ooo
 if 45 - 45: O0 * o0oOOo0O0Ooo % Oo0Ooo * OoooooooOO + iII111i . OoOoOO00
 if 67 - 67: i11iIiiIii - i1IIi % I1ii11iIi11i . O0
 if 77 - 77: IiII / I1IiiI
 if 15 - 15: IiII . iIii1I11I1II1 . OoooooooOO / i11iIiiIii - Ii1I . i1IIi
 if 33 - 33: I11i . o0oOOo0O0Ooo
 if ( i11iiII ) : return
 if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
 lispconfig . lisp_database_mapping_command ( kv_pair , Ooo ,
 ( oOOOO == False ) )
 if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
 if 61 - 61: II111iiii
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
 if 67 - 67: I1Ii111 . iII111i . O0
 if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if ( lisp . lisp_nat_traversal ) : return
 if ( OOO0o0o != None ) : return
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
 if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 if 83 - 83: I11i / I1IiiI
 if 34 - 34: IiII
 if 57 - 57: oO0o . I11i . i1IIi
 if ( oOOOO ) :
  i11Iii = len ( lisp . lisp_db_list )
  if ( i11Iii % 1000 == 0 ) :
   lisp . fprint ( "{} database-mappings processed" . format ( i11Iii ) )
   if 16 - 16: II111iiii % OoOoOO00 - II111iiii + Ii1I
   if 12 - 12: OOooOOo / OOooOOo + i11iIiiIii
  Ii = lisp . lisp_db_list [ - 1 ]
  if ( Ii . eid . is_dist_name ( ) == False ) : return
  if ( Ii . eid . address != "eid-done" ) : return
  i11iiII = True
  if 22 - 22: II111iiii
  lisp . fprint ( "Finished batch of {} database-mappings" . format ( i11Iii ) )
  if 33 - 33: I11i
  iI11i1ii11 = threading . Timer ( 0 , oo000OO00Oo ,
 [ i1 ] )
  Oo0o = iI11i1ii11
  Oo0o . start ( )
  return
  if 58 - 58: OoO0O00 % i11iIiiIii . iII111i / oO0o
  if 84 - 84: iII111i . I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 if ( len ( lisp . lisp_map_servers_list ) > 0 ) :
  OOO0o0o = threading . Timer ( 5 ,
 oo000OO00Oo , [ i1 ] )
  OOO0o0o . start ( )
  if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
  if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
  if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
  if 51 - 51: O0 + iII111i
  if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
  if 48 - 48: O0
  if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
  if 41 - 41: Ii1I - O0 - O0
def oO00OOoO00 ( clause ) :
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
 if 23 - 23: O0
 if 85 - 85: Ii1I
 OO = lispconfig . lisp_show_myrlocs ( "" )
 if 77 - 77: Oo0Ooo
 if 17 - 17: iII111i % OoO0O00 . OOooOOo + OoO0O00 / II111iiii
 if 75 - 75: I1IiiI - OoOoOO00 % iII111i
 if 37 - 37: OoOoOO00 * Oo0Ooo / ooOoO0o - iII111i % II111iiii . oO0o
 OO = lispconfig . lisp_show_decap_stats ( OO , "ETR" )
 if 88 - 88: iII111i . II111iiii * II111iiii % I1Ii111
 if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 O0O = lisp . lisp_decent_dns_suffix
 if ( O0O == None ) :
  O0O = ":"
 else :
  O0O = "&nbsp;(dns-suffix '{}'):" . format ( O0O )
  if 1 - 1: II111iiii
  if 84 - 84: o0oOOo0O0Ooo % II111iiii . i11iIiiIii / OoO0O00
 o0O = "{} configured map-servers" . format ( len ( lisp . lisp_map_servers_list ) )
 IiIIii1iII1II = "LISP-ETR Configured Map-Servers{}" . format ( O0O )
 IiIIii1iII1II = lisp . lisp_span ( IiIIii1iII1II , o0O )
 if 48 - 48: II111iiii * Ii1I . I11i + oO0o
 o0O = ( "P = proxy-reply requested, M = merge-registrations " + "requested, N = Map-Notify requested" )
 if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
 oOoooo0O0Oo = lisp . lisp_span ( "Registration<br>flags" , o0O )
 if 76 - 76: Ii1I + IiII
 OO += lispconfig . lisp_table_header ( IiIIii1iII1II , "Address" , "Auth-Type" ,
 "xTR-ID" , "Site-ID" , oOoooo0O0Oo , "Map-Registers<br>Sent" ,
 "Map-Notifies<br>Received" )
 if 34 - 34: Oo0Ooo
 for Oo00OOOOO in list ( lisp . lisp_map_servers_list . values ( ) ) :
  Oo00OOOOO . resolve_dns_name ( )
  OO0OO0O00oO0 = "" if Oo00OOOOO . ms_name == "all" else Oo00OOOOO . ms_name + "<br>"
  oO = OO0OO0O00oO0 + Oo00OOOOO . map_server . print_address_no_iid ( )
  if ( Oo00OOOOO . dns_name ) : oO += "<br>" + Oo00OOOOO . dns_name
  if 31 - 31: OOooOOo + i11iIiiIii + Oo0Ooo * ooOoO0o
  IiII111iI1ii1 = "0x" + lisp . lisp_hex_string ( Oo00OOOOO . xtr_id )
  iI11I1II = "{}-{}-{}-{}" . format ( "P" if Oo00OOOOO . proxy_reply else "p" ,
 "M" if Oo00OOOOO . merge_registrations else "m" ,
 "N" if Oo00OOOOO . want_map_notify else "n" ,
 "R" if Oo00OOOOO . refresh_registrations else "r" )
  if 40 - 40: iIii1I11I1II1 / OoOoOO00 % I1ii11iIi11i + II111iiii
  ii1Ii1I1Ii11i = Oo00OOOOO . map_registers_sent + Oo00OOOOO . map_registers_multicast_sent
  if 35 - 35: o0oOOo0O0Ooo
  if 90 - 90: I1Ii111 % Ii1I - iIii1I11I1II1 - iIii1I11I1II1 / i11iIiiIii % I1ii11iIi11i
  OO += lispconfig . lisp_table_row ( oO ,
 "sha1" if ( Oo00OOOOO . alg_id == lisp . LISP_SHA_1_96_ALG_ID ) else "sha2" ,
 IiII111iI1ii1 , Oo00OOOOO . site_id , iI11I1II , ii1Ii1I1Ii11i ,
 Oo00OOOOO . map_notifies_received )
  if 37 - 37: oO0o - I1IiiI . I11i * Ii1I - iII111i
 OO += lispconfig . lisp_table_footer ( )
 if 8 - 8: OoO0O00 - I1IiiI % Ii1I * OoooooooOO - OoO0O00 * I1Ii111
 if 6 - 6: OoooooooOO
 if 17 - 17: I1IiiI % I1Ii111
 if 90 - 90: oO0o / iIii1I11I1II1 - o0oOOo0O0Ooo / OoooooooOO - OoooooooOO * OOooOOo
 OO = lispconfig . lisp_show_db_list ( "ETR" , OO )
 if 73 - 73: I1ii11iIi11i * i11iIiiIii % oO0o . I1ii11iIi11i
 if 66 - 66: oO0o + oO0o + ooOoO0o / iII111i + OOooOOo
 if 30 - 30: O0
 if 44 - 44: oO0o / I11i / I11i
 if ( len ( lisp . lisp_elp_list ) != 0 ) :
  OO = lispconfig . lisp_show_elp_list ( OO )
  if 87 - 87: Oo0Ooo . I1IiiI - II111iiii + O0 / Oo0Ooo / oO0o
  if 25 - 25: I1IiiI . I1IiiI - OoOoOO00 % OoOoOO00 - i11iIiiIii / I1Ii111
  if 51 - 51: Oo0Ooo / OoOoOO00 . OOooOOo * o0oOOo0O0Ooo + OoO0O00 * IiII
  if 73 - 73: OoO0O00 + OoooooooOO - O0 - Ii1I - II111iiii
  if 99 - 99: ooOoO0o . Ii1I + I1Ii111 + OoooooooOO % o0oOOo0O0Ooo
 if ( len ( lisp . lisp_rle_list ) != 0 ) :
  OO = lispconfig . lisp_show_rle_list ( OO )
  if 51 - 51: iIii1I11I1II1
  if 34 - 34: oO0o + I1IiiI - oO0o
  if 17 - 17: II111iiii % iII111i + I11i - iII111i / OOooOOo + ooOoO0o
  if 59 - 59: OOooOOo % OoOoOO00 . Ii1I * I1ii11iIi11i % I11i
  if 59 - 59: oO0o - iII111i
 if ( len ( lisp . lisp_json_list ) != 0 ) :
  OO = lispconfig . lisp_show_json_list ( OO )
  if 15 - 15: I1Ii111 . i11iIiiIii . OoooooooOO / OoO0O00 % Ii1I
  if 93 - 93: O0 % i1IIi . OOooOOo / I1IiiI - I1Ii111 / I1IiiI
  if 36 - 36: oO0o % oO0o % i1IIi / i1IIi - ooOoO0o
  if 30 - 30: I11i / I1IiiI
  if 35 - 35: II111iiii % OOooOOo . ooOoO0o + ooOoO0o % II111iiii % II111iiii
 if ( len ( lisp . lisp_group_mapping_list ) != 0 ) :
  IiIIii1iII1II = "Configured Group Mappings:"
  OO += lispconfig . lisp_table_header ( IiIIii1iII1II , "Name" , "Group Prefix" ,
 "Sources" , "Use MS" )
  for ooOoO00 in list ( lisp . lisp_group_mapping_list . values ( ) ) :
   Ii1IIiI1i = ""
   for o0O00Oo0 in ooOoO00 . sources : Ii1IIiI1i += o0O00Oo0 + ", "
   if ( Ii1IIiI1i == "" ) :
    Ii1IIiI1i = "*"
   else :
    Ii1IIiI1i = Ii1IIiI1i [ 0 : - 2 ]
    if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
   OO += lispconfig . lisp_table_row ( ooOoO00 . group_name ,
 ooOoO00 . group_prefix . print_prefix ( ) , Ii1IIiI1i , ooOoO00 . use_ms_name )
   if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
  OO += lispconfig . lisp_table_footer ( )
  if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 return ( OO )
 if 26 - 26: Ii1I % I1ii11iIi11i
 if 76 - 76: IiII * iII111i
 if 52 - 52: OOooOOo
 if 19 - 19: I1IiiI
 if 25 - 25: Ii1I / ooOoO0o
 if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 if 71 - 71: I1Ii111 . II111iiii
def oo0 ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "ETR" ) )
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
 if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 58 - 58: I1IiiI
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
def Ii1iI111II1I1 ( kv_pairs ) :
 Ii1IIiI1i = [ ]
 oOOOOoOO0o = None
 i1II1 = None
 OO0OO0O00oO0 = "all"
 if 25 - 25: I1Ii111 / iIii1I11I1II1 % iII111i
 for IiiiiI1i1Iii in list ( kv_pairs . keys ( ) ) :
  oo00oO0o = kv_pairs [ IiiiiI1i1Iii ]
  if ( IiiiiI1i1Iii == "group-name" ) :
   iiii111II = oo00oO0o
   if 50 - 50: OOooOOo * I1IiiI % iIii1I11I1II1 + Ii1I + iII111i + I1IiiI
  if ( IiiiiI1i1Iii == "group-prefix" ) :
   if ( oOOOOoOO0o == None ) :
    oOOOOoOO0o = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 71 - 71: I1ii11iIi11i * I1ii11iIi11i * i1IIi . oO0o / I1Ii111
   oOOOOoOO0o . store_prefix ( oo00oO0o )
   if 85 - 85: I11i
  if ( IiiiiI1i1Iii == "instance-id" ) :
   if ( oOOOOoOO0o == None ) :
    oOOOOoOO0o = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 20 - 20: oO0o % IiII
   oOOOOoOO0o . instance_id = int ( oo00oO0o )
   if 19 - 19: I1ii11iIi11i % IiII + ooOoO0o / I1Ii111 . ooOoO0o
  if ( IiiiiI1i1Iii == "ms-name" ) :
   OO0OO0O00oO0 = oo00oO0o [ 0 ]
   if 12 - 12: i1IIi + i1IIi - I1ii11iIi11i * Oo0Ooo % Oo0Ooo - II111iiii
  if ( IiiiiI1i1Iii == "address" ) :
   for o0OOOOooo in oo00oO0o :
    if ( o0OOOOooo != "" ) : Ii1IIiI1i . append ( o0OOOOooo )
    if 94 - 94: OoooooooOO + Oo0Ooo / OoOoOO00 * OOooOOo
    if 69 - 69: ooOoO0o % oO0o
  if ( IiiiiI1i1Iii == "rle-address" ) :
   if ( i1II1 == None ) :
    i1II1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    if 50 - 50: OoooooooOO % I11i
   i1II1 . store_address ( oo00oO0o )
   if 49 - 49: oO0o - i11iIiiIii . I1Ii111 * Ii1I % iII111i + i1IIi
   if 71 - 71: o0oOOo0O0Ooo
 ooOoO00 = lisp . lisp_group_mapping ( iiii111II , OO0OO0O00oO0 , oOOOOoOO0o , Ii1IIiI1i ,
 i1II1 )
 ooOoO00 . add_group ( )
 return
 if 38 - 38: oO0o % OoOoOO00 + I1ii11iIi11i . i11iIiiIii
 if 53 - 53: i11iIiiIii * iII111i
 if 68 - 68: iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
 if 38 - 38: ooOoO0o - OOooOOo / iII111i
 if 66 - 66: O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / Ii1I + I1ii11iIi11i
 if 86 - 86: o0oOOo0O0Ooo
 if 5 - 5: IiII * OoOoOO00
def i1Ii1i1I11Iii ( quiet , db , eid , group , ttl ) :
 if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
 if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
 if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
 if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
 if 19 - 19: OoO0O00 - Oo0Ooo . O0
 if 60 - 60: II111iiii + Oo0Ooo
 if 9 - 9: ooOoO0o * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
 if 49 - 49: II111iiii
 Iiii1iI1i = { }
 for I1ii1ii11i1I in db . rloc_set :
  if ( I1ii1ii11i1I . translated_rloc . is_null ( ) ) : continue
  if 58 - 58: iII111i + Oo0Ooo
  for II1I1I1Ii in lisp . lisp_rtr_list :
   OOOOoO00o0O = lisp . lisp_rtr_list [ II1I1I1Ii ]
   if ( lisp . lisp_register_all_rtrs == False and OOOOoO00o0O == None ) :
    lisp . lprint ( "  Exclude unreachable RTR {}" . format ( lisp . red ( II1I1I1Ii , False ) ) )
    if 41 - 41: OOooOOo * Ii1I - IiII + o0oOOo0O0Ooo
    continue
    if 64 - 64: Ii1I
   if ( OOOOoO00o0O == None ) : continue
   Iiii1iI1i [ II1I1I1Ii ] = OOOOoO00o0O
   if 66 - 66: i11iIiiIii - OOooOOo * Oo0Ooo
  break
  if 76 - 76: i11iIiiIii + o0oOOo0O0Ooo / I1ii11iIi11i - OoO0O00 - Ii1I + I1ii11iIi11i
  if 51 - 51: iIii1I11I1II1 . ooOoO0o + iIii1I11I1II1
 oOoOO = 0
 Ii1i1 = b""
 for O0o in [ eid . instance_id ] + eid . iid_list :
  i1iIiIIi = lisp . lisp_eid_record ( )
  if 62 - 62: Oo0Ooo - I11i
  i1iIiIIi . rloc_count = len ( db . rloc_set ) + len ( Iiii1iI1i )
  i1iIiIIi . authoritative = True
  i1iIiIIi . record_ttl = ttl
  i1iIiIIi . eid . copy_address ( eid )
  i1iIiIIi . eid . instance_id = O0o
  i1iIiIIi . eid . iid_list = [ ]
  i1iIiIIi . group . copy_address ( group )
  if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
  Ii1i1 += i1iIiIIi . encode ( )
  if ( not quiet ) :
   OOOO0O00o = lisp . lisp_print_eid_tuple ( eid , group )
   ooo = ""
   if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
    ooo = lisp . lisp_get_decent_index ( eid )
    ooo = lisp . bold ( str ( ooo ) , False )
    ooo = ", decent-index {}" . format ( ooo )
    if 19 - 19: OoO0O00 - Oo0Ooo . oO0o / oO0o % ooOoO0o
   lisp . lprint ( "  EID-prefix {} for ms-name '{}'{}" . format ( lisp . green ( OOOO0O00o , False ) , db . use_ms_name , ooo ) )
   if 56 - 56: I1IiiI . O0 + Oo0Ooo
   i1iIiIIi . print_record ( "  " , False )
   if 1 - 1: iII111i
   if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
  for I1ii1ii11i1I in db . rloc_set :
   oOoO0 = lisp . lisp_rloc_record ( )
   oOoO0 . store_rloc_entry ( I1ii1ii11i1I )
   oOoO0 . local_bit = I1ii1ii11i1I . rloc . is_local ( )
   oOoO0 . reach_bit = True
   Ii1i1 += oOoO0 . encode ( )
   if ( not quiet ) : oOoO0 . print_record ( "    " )
   if 77 - 77: iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
   if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
   if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
   if 17 - 17: i1IIi
   if 21 - 21: Oo0Ooo
   if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
  for OOOOoO00o0O in list ( Iiii1iI1i . values ( ) ) :
   oOoO0 = lisp . lisp_rloc_record ( )
   oOoO0 . rloc . copy_address ( OOOOoO00o0O )
   oOoO0 . priority = 254
   oOoO0 . rloc_name = "RTR"
   oOoO0 . weight = 0
   oOoO0 . mpriority = 255
   oOoO0 . mweight = 0
   oOoO0 . local_bit = False
   oOoO0 . reach_bit = True
   Ii1i1 += oOoO0 . encode ( )
   if ( not quiet ) : oOoO0 . print_record ( "    RTR " )
   if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
   if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
   if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
   if 54 - 54: i1IIi + II111iiii
   if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
  oOoOO += 1
  if 5 - 5: Ii1I
 return ( Ii1i1 , oOoOO )
 if 46 - 46: IiII
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if 17 - 17: OOooOOo / OOooOOo / I11i
 if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
 if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
 if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 if 9 - 9: Ii1I
def o00O ( lisp_sockets , ttl , eid_only , ms_only , refresh ) :
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
 if ( eid_only != None ) :
  i1OO0oOOoo = 1
 else :
  i1OO0oOOoo = lisp . lisp_db_list_length ( )
  if ( i1OO0oOOoo == 0 ) : return
  if 52 - 52: o0oOOo0O0Ooo % Oo0Ooo
  if 64 - 64: O0 % I11i % O0 * OoO0O00 . oO0o + I1IiiI
 if ( oOOOO ) :
  lisp . lprint ( "Build Map-Register for {} database-mapping entries" . format ( i1OO0oOOoo ) )
  if 75 - 75: I11i . OoooooooOO % o0oOOo0O0Ooo * I11i % OoooooooOO
 else :
  lisp . lprint ( "Build Map-Register for {} database-mapping entries" . format ( i1OO0oOOoo ) )
  if 13 - 13: IiII / i11iIiiIii % II111iiii % I11i . I1ii11iIi11i
  if 8 - 8: OoOoOO00 + Oo0Ooo - II111iiii
  if 11 - 11: i1IIi % i11iIiiIii - i1IIi * OoOoOO00
  if 39 - 39: I1Ii111
  if 86 - 86: I11i * I1IiiI + I11i + II111iiii
  if 8 - 8: I1Ii111 - iII111i / ooOoO0o
 oo0oOoo = lisp . lisp_decent_pull_xtr_configured ( )
 if 57 - 57: OoOoOO00 - I1ii11iIi11i
 if 50 - 50: I1Ii111 / i1IIi % OoO0O00 . I1IiiI / iII111i
 if 88 - 88: OOooOOo . I11i * o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . I11i
 if 10 - 10: o0oOOo0O0Ooo * Oo0Ooo % O0 * iIii1I11I1II1 . O0 % I1ii11iIi11i
 Iii1 = ( i1OO0oOOoo > 12 )
 if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
 Iiiiii111i1ii = { }
 if ( oo0oOoo ) :
  if 25 - 25: OOooOOo - ooOoO0o / i11iIiiIii
  if 41 - 41: i1IIi % iII111i + iIii1I11I1II1
  if 2 - 2: iIii1I11I1II1 * Oo0Ooo % oO0o - II111iiii - iII111i
  if 3 - 3: I1Ii111
  if 45 - 45: I1Ii111
  for Ii in lisp . lisp_db_list :
   oOIIi1iiii1iI = Ii . eid if Ii . group . is_null ( ) else Ii . group
   iIiiii = lisp . lisp_get_decent_dns_name ( oOIIi1iiii1iI )
   Iiiiii111i1ii [ iIiiii ] = [ ]
   if 89 - 89: iII111i - ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
 else :
  if 49 - 49: Oo0Ooo - I1IiiI / IiII / O0 % o0oOOo0O0Ooo * Ii1I
  if 100 - 100: OOooOOo . iII111i / O0 * i1IIi * Ii1I * Oo0Ooo
  if 84 - 84: I1ii11iIi11i / OOooOOo % i11iIiiIii * I1Ii111 % I1ii11iIi11i - OoooooooOO
  if 99 - 99: I1IiiI + O0 + i1IIi / i11iIiiIii - i1IIi * iIii1I11I1II1
  if 72 - 72: I1IiiI * I1ii11iIi11i . Ii1I * IiII * Oo0Ooo * I1Ii111
  for Oo00OOOOO in list ( lisp . lisp_map_servers_list . values ( ) ) :
   if ( ms_only != None and Oo00OOOOO != ms_only ) : continue
   Iiiiii111i1ii [ Oo00OOOOO . ms_name ] = [ ]
   if 40 - 40: I1IiiI
   if 14 - 14: I1Ii111
   if 80 - 80: OoooooooOO - OOooOOo * Ii1I * I1ii11iIi11i / I1IiiI / OOooOOo
   if 13 - 13: I1Ii111 * ooOoO0o + i11iIiiIii * I1Ii111 - ooOoO0o
   if 23 - 23: iIii1I11I1II1 * i1IIi % OoooooooOO * IiII
   if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 I1IIIiI1I1ii1 = lisp . lisp_map_register ( )
 I1IIIiI1I1ii1 . nonce = 0xaabbccdddfdfdf00
 I1IIIiI1I1ii1 . xtr_id_present = True
 I1IIIiI1I1ii1 . use_ttl_for_timeout = True
 if 30 - 30: O0 * OoooooooOO
 if ( ttl == None ) : ttl = lisp . LISP_REGISTER_TTL
 if 38 - 38: IiII - I1ii11iIi11i . OoOoOO00 - I1Ii111 . OoooooooOO
 if 89 - 89: iIii1I11I1II1
 if 21 - 21: I11i % I11i
 if 27 - 27: i11iIiiIii / I1ii11iIi11i
 oOoOOo = 65000 if ( oOOOO ) else 1100
 for Ii in lisp . lisp_db_list :
  if ( oo0oOoo ) :
   ii1iI = lisp . lisp_get_decent_dns_name ( Ii . eid )
  else :
   ii1iI = Ii . use_ms_name
   if 49 - 49: o0oOOo0O0Ooo . IiII / OoO0O00 + II111iiii
   if 47 - 47: O0 / Ii1I
   if 67 - 67: I1IiiI
   if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
   if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
   if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
  if ( ii1iI not in Iiiiii111i1ii ) : continue
  if 92 - 92: Oo0Ooo
  iI11I = Iiiiii111i1ii [ ii1iI ]
  if ( iI11I == [ ] ) :
   iI11I = [ b"" , 0 ]
   Iiiiii111i1ii [ ii1iI ] . append ( iI11I )
  else :
   iI11I = Iiiiii111i1ii [ ii1iI ] [ - 1 ]
   if 53 - 53: iIii1I11I1II1 + Ii1I - I1Ii111
   if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
   if 61 - 61: II111iiii
   if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
   if 90 - 90: iII111i
   if 31 - 31: OOooOOo + O0
   if 87 - 87: ooOoO0o
   if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
   if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
   if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
  Ii1i1 = b""
  if ( Ii . dynamic_eid_configured ( ) ) :
   for iIi1II in list ( Ii . dynamic_eids . values ( ) ) :
    oOIIi1iiii1iI = iIi1II . dynamic_eid
    if ( eid_only == None or eid_only . is_exact_match ( oOIIi1iiii1iI ) ) :
     I1iIiI11I1 , oOoOO = i1Ii1i1I11Iii ( Iii1 , Ii ,
 oOIIi1iiii1iI , Ii . group , ttl )
     Ii1i1 += I1iIiI11I1
     iI11I [ 1 ] += oOoOO
     if 27 - 27: Ii1I . i11iIiiIii % I1Ii111
     if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
  else :
   if ( eid_only == None ) :
    if ( ttl != 0 ) : ttl = Ii . register_ttl
    Ii1i1 , oOoOO = i1Ii1i1I11Iii ( Iii1 , Ii ,
 Ii . eid , Ii . group , ttl )
    iI11I [ 1 ] += oOoOO
    if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
    if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
    if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
    if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
    if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
    if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
  iI11I [ 0 ] += Ii1i1
  if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
  if ( iI11I [ 1 ] == 20 or len ( iI11I [ 0 ] ) > oOoOOo ) :
   iI11I = [ b"" , 0 ]
   Iiiiii111i1ii [ ii1iI ] . append ( iI11I )
   if 95 - 95: IiII
   if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
   if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
   if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
   if 2 - 2: OoooooooOO % OOooOOo
   if 63 - 63: I1IiiI % iIii1I11I1II1
 I1ii = .500 if ( oOOOO ) else .001
 oOoOO = 0
 for Oo00OOOOO in list ( lisp . lisp_map_servers_list . values ( ) ) :
  if ( ms_only != None and Oo00OOOOO != ms_only ) : continue
  if 73 - 73: IiII + I1IiiI * Oo0Ooo * OoooooooOO
  ii1iI = Oo00OOOOO . dns_name if oo0oOoo else Oo00OOOOO . ms_name
  if ( ii1iI not in Iiiiii111i1ii ) : continue
  if 95 - 95: i1IIi + iIii1I11I1II1 % I1ii11iIi11i % Oo0Ooo / i11iIiiIii - IiII
  for iI11I in Iiiiii111i1ii [ ii1iI ] :
   if 26 - 26: ooOoO0o . OOooOOo - OOooOOo . OoO0O00
   if 39 - 39: OoooooooOO + oO0o % OOooOOo / OOooOOo
   if 27 - 27: iII111i . I11i . iIii1I11I1II1 . iIii1I11I1II1
   if 20 - 20: o0oOOo0O0Ooo / i1IIi
   I1IIIiI1I1ii1 . record_count = iI11I [ 1 ]
   if ( I1IIIiI1I1ii1 . record_count == 0 ) : continue
   if 71 - 71: OoOoOO00 . i1IIi
   I1IIIiI1I1ii1 . nonce += 1
   I1IIIiI1I1ii1 . alg_id = Oo00OOOOO . alg_id
   I1IIIiI1I1ii1 . key_id = Oo00OOOOO . key_id
   I1IIIiI1I1ii1 . proxy_reply_requested = Oo00OOOOO . proxy_reply
   I1IIIiI1I1ii1 . merge_register_requested = Oo00OOOOO . merge_registrations
   I1IIIiI1I1ii1 . map_notify_requested = Oo00OOOOO . want_map_notify
   I1IIIiI1I1ii1 . xtr_id = Oo00OOOOO . xtr_id
   I1IIIiI1I1ii1 . site_id = Oo00OOOOO . site_id
   I1IIIiI1I1ii1 . encrypt_bit = ( Oo00OOOOO . ekey != None )
   if ( Oo00OOOOO . refresh_registrations ) :
    I1IIIiI1I1ii1 . map_register_refresh = refresh
    if 94 - 94: OOooOOo . I1Ii111
   if ( Oo00OOOOO . ekey != None ) : I1IIIiI1I1ii1 . encryption_key_id = Oo00OOOOO . ekey_id
   OoO = I1IIIiI1I1ii1 . encode ( )
   I1IIIiI1I1ii1 . print_map_register ( )
   if 73 - 73: II111iiii
   if 24 - 24: OoOoOO00 / OoooooooOO . II111iiii . I1IiiI % O0 % Ii1I
   if 5 - 5: OoooooooOO - OoO0O00 + IiII - iII111i . OoO0O00 / ooOoO0o
   if 28 - 28: Ii1I * Ii1I - iIii1I11I1II1
   if 70 - 70: I1Ii111
   i11iIIi11 = I1IIIiI1I1ii1 . encode_xtr_id ( b"" )
   Ii1i1 = iI11I [ 0 ]
   OoO = OoO + Ii1i1 + i11iIIi11
   if 98 - 98: I1Ii111
   Oo00OOOOO . map_registers_sent += 1
   lisp . lisp_send_map_register ( lisp_sockets , OoO , I1IIIiI1I1ii1 , Oo00OOOOO )
   if 12 - 12: II111iiii . I11i / OOooOOo
   oOoOO += 1
   if ( oOoOO % 100 == 0 and oOOOO ) :
    I1ii += .1
    lisp . fprint ( "Sent {} Map-Registers, ipd {}" . format ( oOoOO ,
 I1ii ) )
    if 77 - 77: ooOoO0o - I1IiiI % I11i - O0
   time . sleep ( I1ii )
   if 67 - 67: OOooOOo + Oo0Ooo
   if 84 - 84: O0 * OoooooooOO - IiII * IiII
  if ( oOOOO ) :
   lisp . fprint ( "Sent total {} Map-Registers" . format ( oOoOO ) )
   if 8 - 8: ooOoO0o / i1IIi . oO0o
   if 41 - 41: iII111i + OoO0O00
   if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
   if 56 - 56: O0
   if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
  Oo00OOOOO . resolve_dns_name ( )
  if 23 - 23: oO0o - OOooOOo + I11i
  if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
  if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
  if 11 - 11: iII111i * Ii1I - OoOoOO00
  if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
  if ( ms_only != None and Oo00OOOOO == ms_only ) : break
  if 74 - 74: Oo0Ooo
 return
 if 61 - 61: Oo0Ooo - I1Ii111 * II111iiii % ooOoO0o * iIii1I11I1II1 + OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
def i1iiI11I ( ms ) :
 global Ii1iI
 global I1Ii11I1Ii1i
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 lisp . lisp_set_exception ( )
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 Oo00OOo00O = [ I1Ii11I1Ii1i , I1Ii11I1Ii1i , o0oOoO00o ]
 lisp . lisp_build_info_requests ( Oo00OOo00O , ms , lisp . LISP_CTRL_PORT )
 if 81 - 81: IiII . o0oOOo0O0Ooo / I1Ii111
 if 17 - 17: i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + I11i - ooOoO0o
 if 78 - 78: I11i * OoOoOO00 . O0 / O0
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 Ii1II = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) == None )
 for OOOOoO00o0O in list ( lisp . lisp_rtr_list . values ( ) ) :
  if ( OOOOoO00o0O == None ) : continue
  if ( OOOOoO00o0O . is_private_address ( ) and Ii1II == False ) :
   ooO0O0o0 = lisp . red ( OOOOoO00o0O . print_address_no_iid ( ) , False )
   lisp . lprint ( "Skip over RTR private address {}" . format ( ooO0O0o0 ) )
   continue
   if 92 - 92: Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - I1ii11iIi11i . o0oOOo0O0Ooo
  lisp . lisp_build_info_requests ( Oo00OOo00O , OOOOoO00o0O , lisp . LISP_DATA_PORT )
  if 95 - 95: I1Ii111 % I1IiiI
  if 42 - 42: OoooooooOO - iII111i / OoooooooOO / Ii1I
  if 86 - 86: ooOoO0o * o0oOOo0O0Ooo + O0 / I11i . I1IiiI + iIii1I11I1II1
  if 66 - 66: oO0o
  if 91 - 91: oO0o + I1IiiI
 for OoOooo in IiI1I1 :
  oo00OOoOoO00 = IiI1I1 [ OoOooo ]
  lisp . lprint ( "Send NAT-Probe to ETR {}" . format ( OoOooo ) )
  lisp . lisp_send_info_request ( Oo00OOo00O , oo00OOoOoO00 , lisp . LISP_DATA_PORT , None )
  if 15 - 15: IiII / O0 . o0oOOo0O0Ooo . i11iIiiIii
  if 59 - 59: I1Ii111 - o0oOOo0O0Ooo - ooOoO0o
  if 48 - 48: i1IIi + I11i % OoOoOO00 / Oo0Ooo - o0oOOo0O0Ooo
  if 67 - 67: oO0o % o0oOOo0O0Ooo . OoooooooOO + OOooOOo * I11i * OoOoOO00
  if 36 - 36: O0 + Oo0Ooo
  if 5 - 5: Oo0Ooo * OoOoOO00
 Ii1iI . cancel ( )
 Ii1iI = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 i1iiI11I , [ None ] )
 Ii1iI . start ( )
 return
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
 if 63 - 63: I1ii11iIi11i
def oo000OO00Oo ( lisp_sockets ) :
 global Oo0o , OOO0o0o
 global I1Ii11I1Ii1i
 if 6 - 6: ooOoO0o / I1ii11iIi11i
 lisp . lisp_set_exception ( )
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
 if 87 - 87: oO0o % Ii1I
 if 83 - 83: II111iiii - I11i
 o00O ( lisp_sockets , None , None , None , True )
 if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
 if ( lisp . lisp_l2_overlay ) :
  O0ooOo0o0Oo = [ None , "ffff-ffff-ffff" , True ]
  OooO0oOo ( lisp_sockets , [ O0ooOo0o0Oo ] )
  if 66 - 66: OoO0O00 * Oo0Ooo
  if 28 - 28: OoO0O00 % OoOoOO00 % I1ii11iIi11i + I1IiiI / I1IiiI
  if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
  if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
  if 23 - 23: i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo - I1ii11iIi11i % iII111i * OoO0O00 - OOooOOo / iII111i
 if ( OOO0o0o != None ) :
  OOO0o0o . cancel ( )
  OOO0o0o = None
  if 29 - 29: I1ii11iIi11i
  if 52 - 52: i11iIiiIii / i1IIi
  if 1 - 1: ooOoO0o
  if 78 - 78: I1ii11iIi11i + I11i - O0
  if 10 - 10: I1Ii111 % I1IiiI
 if ( Oo0o ) : Oo0o . cancel ( )
 Oo0o = threading . Timer ( o000o0o00o0Oo ,
 oo000OO00Oo , [ i1 ] )
 Oo0o . start ( )
 return
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 if 46 - 46: i11iIiiIii - O0 . oO0o
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
def OooO0oOo ( lisp_sockets , entries ) :
 I11I = len ( entries )
 if ( I11I == 0 ) : return
 if 69 - 69: i1IIi
 ooOoOOOOo = None
 if ( entries [ 0 ] [ 1 ] . find ( ":" ) != - 1 ) : ooOoOOOOo = lisp . LISP_AFI_IPV6
 if ( entries [ 0 ] [ 1 ] . find ( "." ) != - 1 ) : ooOoOOOOo = lisp . LISP_AFI_IPV4
 if ( entries [ 0 ] [ 1 ] . find ( "-" ) != - 1 ) : ooOoOOOOo = lisp . LISP_AFI_MAC
 if ( ooOoOOOOo == None ) :
  lisp . lprint ( "lisp_send_multicast_map_register() invalid group address" )
  return
  if 71 - 71: II111iiii * iIii1I11I1II1 / I1ii11iIi11i
  if 23 - 23: II111iiii
  if 24 - 24: iIii1I11I1II1 + iIii1I11I1II1 * iII111i
  if 18 - 18: iII111i * I11i - Ii1I
  if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
  if 39 - 39: iIii1I11I1II1 - OoooooooOO
  if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 iiIiI = [ ]
 for o0OOOOooo , o0Ooo0O00 , ii1 in entries :
  if 55 - 55: Oo0Ooo
  iiIiI . append ( [ o0Ooo0O00 , ii1 ] )
  if 77 - 77: II111iiii
  if 16 - 16: I1IiiI * II111iiii / iIii1I11I1II1 - iII111i
 oo0oOoo = lisp . lisp_decent_pull_xtr_configured ( )
 if 3 - 3: I1IiiI * ooOoO0o + II111iiii - OoO0O00
 Iiiiii111i1ii = { }
 entries = [ ]
 for o0Ooo0O00 , ii1 in iiIiI :
  OOOO = lisp . lisp_lookup_group ( o0Ooo0O00 )
  if ( OOOO == None ) :
   lisp . lprint ( "No group-mapping for {}, could be underlay group" . format ( o0Ooo0O00 ) )
   if 57 - 57: I1IiiI - o0oOOo0O0Ooo + OoO0O00 % Oo0Ooo
   continue
   if 26 - 26: iII111i . iII111i
   if 35 - 35: I1Ii111 . OoOoOO00 * i11iIiiIii
  lisp . lprint ( "Use group-mapping '{}' {} for group {}" . format ( OOOO . group_name , OOOO . group_prefix . print_prefix ( ) , o0Ooo0O00 ) )
  if 44 - 44: i11iIiiIii / Oo0Ooo
  if 42 - 42: OoooooooOO + Oo0Ooo % II111iiii + OoO0O00
  O0o = OOOO . group_prefix . instance_id
  OO0OO0O00oO0 = OOOO . use_ms_name
  I11i11I1iiII = OOOO . rle_address
  if 28 - 28: i11iIiiIii / o0oOOo0O0Ooo . iIii1I11I1II1 / II111iiii
  if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
  if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
  if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
  if 32 - 32: i11iIiiIii - I1Ii111
  if 53 - 53: OoooooooOO - IiII
  oOo = OO0OO0O00oO0
  if ( oo0oOoo ) :
   oOo = lisp . lisp_get_decent_dns_name_from_str ( O0o , o0Ooo0O00 )
   Iiiiii111i1ii [ oOo ] = [ b"" , 0 ]
   if 17 - 17: Ii1I . i11iIiiIii
   if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
  if ( len ( OOOO . sources ) == 0 ) :
   entries . append ( [ "0.0.0.0" , o0Ooo0O00 , O0o , oOo , I11i11I1iiII , ii1 ] )
   continue
   if 63 - 63: oO0o
  for o0O00Oo0 in OOOO . sources :
   Iiiiii111i1ii [ oOo ] = [ b"" , 0 ]
   entries . append ( [ o0O00Oo0 , o0Ooo0O00 , O0o , oOo , I11i11I1iiII , ii1 ] )
   if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
   if 36 - 36: IiII
   if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 I11I = len ( entries )
 if ( I11I == 0 ) : return
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 lisp . lprint ( "Build Map-Register for {} multicast entries" . format ( I11I ) )
 if 7 - 7: II111iiii
 if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
 if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 ii1iI1II11ii = lisp . lisp_rle_node ( )
 ii1iI1II11ii . level = 128
 i1i1IiIiIi1Ii = lisp . lisp_get_any_translated_rloc ( )
 I11i11I1iiII = lisp . lisp_rle ( "" )
 I11i11I1iiII . rle_nodes . append ( ii1iI1II11ii )
 I11i11I1iiII . build_rle_forwarding_list ( )
 if 64 - 64: OOooOOo + OoooooooOO * OoooooooOO
 if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
 if 100 - 100: Ii1I + OoO0O00
 if 73 - 73: i1IIi - I1Ii111 % ooOoO0o / OoO0O00
 if 40 - 40: I1ii11iIi11i * ooOoO0o - I1IiiI / IiII / i11iIiiIii
 if 83 - 83: I1ii11iIi11i / I1Ii111 - i11iIiiIii . iIii1I11I1II1 + Oo0Ooo
 if ( oo0oOoo == False ) :
  for Oo00OOOOO in list ( lisp . lisp_map_servers_list . values ( ) ) :
   Iiiiii111i1ii [ Oo00OOOOO . ms_name ] = [ b"" , 0 ]
   if 59 - 59: O0 % Oo0Ooo
   if 92 - 92: Ii1I % iII111i / I1ii11iIi11i % I1ii11iIi11i * I1IiiI
   if 74 - 74: O0 . I1IiiI % OoO0O00 % IiII
   if 87 - 87: oO0o - i11iIiiIii
   if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
   if 23 - 23: I11i
 iIiiIiiIi = 0
 for OOOOoO00o0O in list ( lisp . lisp_rtr_list . values ( ) ) :
  if ( OOOOoO00o0O == None ) : continue
  iIiiIiiIi += 1
  if 40 - 40: o0oOOo0O0Ooo
  if 78 - 78: iIii1I11I1II1
  if 56 - 56: OoooooooOO - I11i - i1IIi
  if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
  if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 Ii1i1 = b""
 for o0OOOOooo , o0Ooo0O00 , O0o , ii1iI , I11i1iIiiIiIi , ii1 in entries :
  if 49 - 49: OOooOOo . I1ii11iIi11i . i11iIiiIii - II111iiii / Ii1I
  if 62 - 62: OOooOOo
  if 1 - 1: IiII / IiII - i11iIiiIii
  if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
  if ( ii1iI not in Iiiiii111i1ii ) : continue
  if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
  i1iIiIIi = lisp . lisp_eid_record ( )
  i1iIiIIi . rloc_count = 1 + iIiiIiiIi
  i1iIiIIi . authoritative = True
  i1iIiIIi . record_ttl = lisp . LISP_REGISTER_TTL if ii1 else 0
  i1iIiIIi . eid = lisp . lisp_address ( ooOoOOOOo , o0OOOOooo , 0 , O0o )
  if ( i1iIiIIi . eid . address == 0 ) : i1iIiIIi . eid . mask_len = 0
  i1iIiIIi . group = lisp . lisp_address ( ooOoOOOOo , o0Ooo0O00 , 0 , O0o )
  if ( i1iIiIIi . group . is_mac_broadcast ( ) and i1iIiIIi . eid . address == 0 ) : i1iIiIIi . eid . mask_len = 0
  if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
  if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
  ooo = ""
  OO0OO0O00oO0 = ""
  if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
   ooo = lisp . lisp_get_decent_index ( i1iIiIIi . group )
   ooo = lisp . bold ( str ( ooo ) , False )
   ooo = "with decent-index {}" . format ( ooo )
  else :
   ooo = "for ms-name '{}'" . format ( ii1iI )
   if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
   if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
  Ii11iI1ii1111 = lisp . green ( i1iIiIIi . print_eid_tuple ( ) , False )
  lisp . lprint ( "  EID-prefix {} {}{}" . format ( Ii11iI1ii1111 , OO0OO0O00oO0 ,
 ooo ) )
  if 42 - 42: I1Ii111 + I1Ii111 * II111iiii
  Ii1i1 += i1iIiIIi . encode ( )
  i1iIiIIi . print_record ( "  " , False )
  Iiiiii111i1ii [ ii1iI ] [ 1 ] += 1
  if 78 - 78: OoooooooOO
  if 77 - 77: I1ii11iIi11i / i1IIi / Oo0Ooo % OOooOOo
  if 48 - 48: I11i - IiII + iIii1I11I1II1 + OoooooooOO
  if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
  oOoO0 = lisp . lisp_rloc_record ( )
  oOoO0 . rloc_name = lisp . lisp_hostname
  if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
  if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
  if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
  if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
  if 62 - 62: o0oOOo0O0Ooo
  if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
  if ( i1i1IiIiIi1Ii != None ) :
   ii1iI1II11ii . rloc . rloc . copy_address ( i1i1IiIiIi1Ii )
  elif ( I11i1iIiiIiIi != None ) :
   ii1iI1II11ii . rloc . rloc . copy_address ( I11i1iIiiIiIi )
  else :
   I11i1iIiiIiIi = lisp . lisp_myrlocs [ 0 ]
   ii1iI1II11ii . rloc . rloc . copy_address ( I11i1iIiiIiIi )
   if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
   if 72 - 72: iIii1I11I1II1
  oOoO0 . rle = I11i11I1iiII
  oOoO0 . local_bit = True
  oOoO0 . reach_bit = True
  oOoO0 . priority = 255
  oOoO0 . weight = 0
  oOoO0 . mpriority = 1
  oOoO0 . mweight = 100
  Ii1i1 += oOoO0 . encode ( )
  oOoO0 . print_record ( "    " )
  if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
  if 87 - 87: OoO0O00 % I1IiiI
  if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
  if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
  for OOOOoO00o0O in list ( lisp . lisp_rtr_list . values ( ) ) :
   if ( OOOOoO00o0O == None ) : continue
   oOoO0 = lisp . lisp_rloc_record ( )
   oOoO0 . rloc . copy_address ( OOOOoO00o0O )
   oOoO0 . priority = 254
   oOoO0 . rloc_name = "RTR"
   oOoO0 . weight = 0
   oOoO0 . mpriority = 255
   oOoO0 . mweight = 0
   oOoO0 . local_bit = False
   oOoO0 . reach_bit = True
   Ii1i1 += oOoO0 . encode ( )
   oOoO0 . print_record ( "    RTR " )
   if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
   if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
   if 84 - 84: i11iIiiIii * OoO0O00
   if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
   if 30 - 30: O0 + I1ii11iIi11i + II111iiii
  Iiiiii111i1ii [ ii1iI ] [ 0 ] += Ii1i1
  if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
  if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
  if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  if 64 - 64: i1IIi
 I1IIIiI1I1ii1 = lisp . lisp_map_register ( )
 I1IIIiI1I1ii1 . nonce = 0xaabbccdddfdfdf00
 I1IIIiI1I1ii1 . xtr_id_present = True
 I1IIIiI1I1ii1 . proxy_reply_requested = True
 I1IIIiI1I1ii1 . map_notify_requested = False
 I1IIIiI1I1ii1 . merge_register_requested = True
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 for Oo00OOOOO in list ( lisp . lisp_map_servers_list . values ( ) ) :
  oOo = Oo00OOOOO . dns_name if oo0oOoo else Oo00OOOOO . ms_name
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
  if 50 - 50: ooOoO0o + i1IIi
  if 31 - 31: Ii1I
  if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
  if ( oOo not in Iiiiii111i1ii ) : continue
  if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
  if 47 - 47: o0oOOo0O0Ooo
  if 66 - 66: I1IiiI - IiII
  if 33 - 33: I1IiiI / OoO0O00
  I1IIIiI1I1ii1 . record_count = Iiiiii111i1ii [ oOo ] [ 1 ]
  if ( I1IIIiI1I1ii1 . record_count == 0 ) : continue
  if 12 - 12: II111iiii
  I1IIIiI1I1ii1 . nonce += 1
  I1IIIiI1I1ii1 . alg_id = Oo00OOOOO . alg_id
  I1IIIiI1I1ii1 . alg_id = Oo00OOOOO . key_id
  I1IIIiI1I1ii1 . xtr_id = Oo00OOOOO . xtr_id
  I1IIIiI1I1ii1 . site_id = Oo00OOOOO . site_id
  I1IIIiI1I1ii1 . encrypt_bit = ( Oo00OOOOO . ekey != None )
  OoO = I1IIIiI1I1ii1 . encode ( )
  I1IIIiI1I1ii1 . print_map_register ( )
  if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
  if 25 - 25: oO0o
  if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
  if 43 - 43: I1ii11iIi11i - iII111i
  if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
  i11iIIi11 = I1IIIiI1I1ii1 . encode_xtr_id ( b"" )
  OoO = OoO + Ii1i1 + i11iIIi11
  if 47 - 47: iII111i
  Oo00OOOOO . map_registers_multicast_sent += 1
  lisp . lisp_send_map_register ( lisp_sockets , OoO , I1IIIiI1I1ii1 , Oo00OOOOO )
  if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
  if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
  if 47 - 47: oO0o % iIii1I11I1II1
  if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
  Oo00OOOOO . resolve_dns_name ( )
  if 98 - 98: iII111i + Ii1I - OoO0O00
  if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
  if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
  if 38 - 38: O0 - IiII % I1Ii111
  time . sleep ( .001 )
  if 64 - 64: iIii1I11I1II1
 return
 if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
 if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
 if 6 - 6: Oo0Ooo % IiII * I11i / I1IiiI + Oo0Ooo
 if 39 - 39: OoOoOO00 - Oo0Ooo / iII111i * OoooooooOO
 if 100 - 100: O0 . I11i . OoO0O00 + O0 * oO0o
 if 42 - 42: oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
def I11 ( parms , not_used , packet ) :
 global o0oOoO00o , i1
 if 99 - 99: O0 + O0 * I11i + O0 * oO0o
 oOoO0O00oo = parms [ 0 ]
 oOOoo00O0O = parms [ 1 ]
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
 if 60 - 60: OoO0O00
 if 81 - 81: OoOoOO00 % Ii1I
 if ( lisp . lisp_is_macos ( ) == False ) :
  oo0i1iIIi1II1iiI = 4 if oOoO0O00oo == "lo0" else 16
  packet = packet [ oo0i1iIIi1II1iiI : : ]
 elif ( oOoO0O00oo == "en0" ) :
  packet = packet [ 14 : : ]
  if 31 - 31: o0oOOo0O0Ooo % I11i + iIii1I11I1II1 + i11iIiiIii * I1Ii111
  if 45 - 45: OOooOOo * I1Ii111 . ooOoO0o - I1Ii111 + IiII
  if 34 - 34: OOooOOo . Oo0Ooo
  if 78 - 78: I1ii11iIi11i % I1IiiI / OoooooooOO % OOooOOo - iII111i
  if 2 - 2: iIii1I11I1II1
 iiii1 = struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ]
 if ( iiii1 == 2 ) :
  OO0o0oO0O000o = lisp . lisp_process_igmp_packet ( packet )
  if ( type ( OO0o0oO0O000o ) != bool ) :
   OooO0oOo ( i1 , OO0o0oO0O000o )
   return
   if 47 - 47: I1Ii111 - OoO0O00 / Ii1I * OoooooooOO / Ii1I . Oo0Ooo
   if 34 - 34: ooOoO0o
   if 27 - 27: I1Ii111 + OoooooooOO - OoOoOO00
   if 15 - 15: oO0o / I11i * O0 . II111iiii - OoO0O00
   if 90 - 90: oO0o
   if 94 - 94: I11i / I1ii11iIi11i * I1Ii111 - OoOoOO00
 I1Ii11II1I1 = packet
 packet , o0OOOOooo , IiI1iI1IiiIi1 , OoO0oo = lisp . lisp_is_rloc_probe ( packet , oOoO0O00oo , 0 )
 if ( I1Ii11II1I1 != packet ) :
  if ( o0OOOOooo == None ) : return
  lisp . lisp_parse_packet ( i1 , packet , o0OOOOooo , IiI1iI1IiiIi1 , OoO0oo )
  return
  if 72 - 72: O0 + I1IiiI - iII111i - OoO0O00
  if 100 - 100: O0
  if 79 - 79: iIii1I11I1II1
  if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
  if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
  if 11 - 11: i1IIi % OoO0O00 % iII111i
  if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if ( struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ] & 0xf0 == 0x40 ) :
  i1II1i = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
  if ( lisp . lisp_nat_traversal and i1II1i == lisp . LISP_DATA_PORT ) : return
  packet = lisp . lisp_reassemble ( packet )
  if ( packet == None ) : return
  if 10 - 10: Ii1I - OoOoOO00 . OoooooooOO . OOooOOo . OoO0O00 * iII111i
  if 78 - 78: oO0o / OoO0O00 - oO0o * OoooooooOO . OoOoOO00
 packet = lisp . lisp_packet ( packet )
 OOoooOoO0Oo = packet . decode ( True , o0oOoO00o , lisp . lisp_decap_stats )
 if ( OOoooOoO0Oo == None ) : return
 if 78 - 78: OoooooooOO / OOooOOo % OoOoOO00 * OoooooooOO
 if 68 - 68: oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 packet . print_packet ( "Receive" , True )
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
  o0OOOOooo = packet . inner_source . print_address_no_iid ( )
  packet . strip_outer_headers ( )
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , o0OOOOooo , i1II1i )
  lisp . lisp_ipc ( packet , o0oOoO00o , "lisp-ms" )
  return
  if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
  if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
  if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
  if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
  if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
  if 24 - 24: OoOoOO00
  if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
  if 28 - 28: I1IiiI
  if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
  if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  I1IIi1I = packet . packet [ 36 : : ]
  iIii1i1 = I1IIi1I [ 28 : : ]
  OoO0oo = - 1
  if ( lisp . lisp_is_rloc_probe_request ( iIii1i1 [ 0 : 1 ] ) ) :
   OoO0oo = struct . unpack ( "B" , I1IIi1I [ 8 : 9 ] ) [ 0 ] - 1
   if 65 - 65: oO0o + I1ii11iIi11i / OOooOOo
  o0OOOOooo = packet . outer_source . print_address_no_iid ( )
  lisp . lisp_parse_packet ( i1 , iIii1i1 , o0OOOOooo , 0 , OoO0oo )
  return
  if 85 - 85: iIii1I11I1II1 / OoooooooOO % II111iiii
  if 49 - 49: i11iIiiIii % OoOoOO00 + I1Ii111 . II111iiii % iII111i * OOooOOo
  if 67 - 67: i1IIi
  if 5 - 5: II111iiii . OoooooooOO
  if 57 - 57: I1IiiI
  if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 50 - 50: OoOoOO00
  if 33 - 33: I11i
  if 98 - 98: OoOoOO00 % II111iiii
  if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
  if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 68 - 68: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 - I1Ii111
 if 37 - 37: IiII
 if 37 - 37: Oo0Ooo / IiII * O0
 packet . strip_outer_headers ( )
 o0o00O0oOooO0 = lisp . bold ( "Forward" , False )
 if 99 - 99: ooOoO0o
 if 76 - 76: OoO0O00
 if 92 - 92: I11i - iIii1I11I1II1 % OoooooooOO
 if 39 - 39: iII111i . I1IiiI * OoOoOO00 - i11iIiiIii
 i1II1II1iii1i = False
 O0OO0oOO = packet . inner_dest . is_mac ( )
 if ( O0OO0oOO ) :
  packet . packet = lisp . lisp_mac_input ( packet . packet )
  if ( packet . packet == None ) : return
  o0o00O0oOooO0 = lisp . bold ( "Bridge" , False )
 elif ( packet . inner_version == 4 ) :
  i1II1II1iii1i , packet . packet = lisp . lisp_ipv4_input ( packet . packet )
  if ( packet . packet == None ) : return
  if ( i1II1II1iii1i ) :
   OO0o0oO0O000o = lisp . lisp_process_igmp_packet ( packet . packet )
   if ( type ( OO0o0oO0O000o ) != bool ) :
    OooO0oOo ( i1 , OO0o0oO0O000o )
    return
    if 85 - 85: O0
    if 32 - 32: OoooooooOO . OoO0O00 / Oo0Ooo * o0oOOo0O0Ooo / o0oOOo0O0Ooo * Ii1I
  packet . inner_ttl = packet . outer_ttl
 elif ( packet . inner_version == 6 ) :
  packet . packet = lisp . lisp_ipv6_input ( packet )
  if ( packet . packet == None ) : return
  packet . inner_ttl = packet . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
  return
  if 19 - 19: Ii1I
  if 55 - 55: OOooOOo % OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
  if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
  if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
  if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
  if 71 - 71: iII111i
  if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
  if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
  if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
  if 58 - 58: I1ii11iIi11i
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  Ii = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( Ii ) :
   Ii . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 2 - 2: II111iiii / I1Ii111
   return
   if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 else :
  if ( lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False ) ) :
   lisp . dprint ( "Discard echoed multicast packet (through NAT)" )
   return
   if 22 - 22: ooOoO0o . iIii1I11I1II1
   if 12 - 12: Ii1I
   if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
   if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
   if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
   if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
   if 65 - 65: oO0o + OoOoOO00 + II111iiii
   if 77 - 77: II111iiii
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
  if 68 - 68: oO0o
  if 10 - 10: Ii1I
  if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
  if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 oO = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( o0o00O0oOooO0 , lisp . green ( oO , False ) ,
 # o0oOOo0O0Ooo * OoOoOO00 + ooOoO0o
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 62 - 62: I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if ( O0OO0oOO ) :
  packet . bridge_l2_packet ( packet . inner_dest , Ii )
  return
  if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
  if 10 - 10: iII111i . i1IIi + Ii1I
  if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
  if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
  if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
  if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( i1111 , i11 )
  return
  if 84 - 84: i1IIi
  if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
  if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
  if 81 - 81: IiII / OoOoOO00 * IiII . O0
  if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 O0o0oo0oOO0oO = packet . get_raw_socket ( )
 if ( O0o0oo0oOO0oO == None ) : O0o0oo0oOO0oO = oOOoo00O0O
 if 15 - 15: OoO0O00 * II111iiii
 if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
 if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
 if 79 - 79: I1IiiI - ooOoO0o
 packet . send_packet ( O0o0oo0oOO0oO , packet . inner_dest )
 return
 if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 if 83 - 83: IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if 80 - 80: OoooooooOO + IiII
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if 43 - 43: Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
def ooooO0 ( lisp_raw_socket , packet , source ) :
 global o0oOoO00o , i1
 if 37 - 37: i11iIiiIii + I1IiiI . OOooOOo % I11i % I11i
 if 26 - 26: O0
 if 34 - 34: ooOoO0o * I1Ii111
 if 97 - 97: i11iIiiIii % oO0o / Oo0Ooo / Oo0Ooo
 OoO00ooO = packet
 packet = lisp . lisp_packet ( packet [ 8 : : ] )
 if ( packet . lisp_header . decode ( OoO00ooO ) == False ) : return
 if 15 - 15: i11iIiiIii
 if 13 - 13: I11i * II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 packet . outer_source = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , source ,
 lisp . LISP_IPV4_HOST_MASK_LEN , 0 )
 if 19 - 19: II111iiii - IiII
 OOoooOoO0Oo = packet . decode ( False , o0oOoO00o ,
 lisp . lisp_decap_stats )
 if ( OOoooOoO0Oo == None ) : return
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
 if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
 if 96 - 96: OoooooooOO + IiII * O0
 if 86 - 86: Ii1I
 if ( lisp . lisp_flow_logging ) : packet . log_flow ( False )
 if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 packet . print_packet ( "Kernel-decap" , False )
 lisp . dprint ( packet . lisp_header . print_header ( " " ) )
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if 69 - 69: OoOoOO00
 if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 88 - 88: o0oOOo0O0Ooo
  i1II1i = packet . udp_sport
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , source , i1II1i )
  lisp . lisp_ipc ( packet , o0oOoO00o , "lisp-ms" )
  return
  if 1 - 1: OoooooooOO
  if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
  if 40 - 40: i11iIiiIii . iIii1I11I1II1
  if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
  if 3 - 3: OoooooooOO
  if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
  if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
  if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
  if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  I1IIi1I = packet . packet
  iIii1i1 = I1IIi1I [ 28 : : ]
  OoO0oo = - 1
  if ( lisp . lisp_is_rloc_probe_request ( iIii1i1 [ 0 : 1 ] ) ) :
   OoO0oo = struct . unpack ( "B" , I1IIi1I [ 8 : 9 ] ) [ 0 ] - 1
   if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
   if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
   if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
   if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
   if 27 - 27: OOooOOo
   if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
   if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
  if ( lisp . lisp_is_rloc_probe_reply ( iIii1i1 [ 0 : 1 ] ) ) :
   i1II1i = socket . ntohs ( struct . unpack ( "H" , packet . packet [ 20 : 22 ] ) [ 0 ] )
   if ( i1II1i == lisp . LISP_DATA_PORT ) :
    packet = packet . packet [ 28 : : ]
    packet = lisp . lisp_packet_ipc ( packet , source , i1II1i )
    lisp . lisp_ipc ( packet , o0oOoO00o , "lisp-itr" )
    return
    if 74 - 74: oO0o
    if 34 - 34: iII111i
  lisp . lisp_parse_packet ( i1 , iIii1i1 , source , 0 , OoO0oo )
  return
  if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
  if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
  if 43 - 43: OoO0O00 % OoO0O00
  if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
  if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 45 - 45: Ii1I - OOooOOo
  if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
  if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
  if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
  if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  Ii = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( Ii ) :
   Ii . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 100 - 100: Ii1I + iIii1I11I1II1
   if 59 - 59: IiII
   if 89 - 89: OoOoOO00 % iIii1I11I1II1
 else :
  if ( lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False ) ) :
   lisp . dprint ( "Discard echoed multicast packet" )
   return
   if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
   if 45 - 45: I1IiiI * OOooOOo % OoO0O00
   if 24 - 24: ooOoO0o - I11i * oO0o
   if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
   if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
   if 79 - 79: IiII % OoO0O00
   if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
   if 32 - 32: O0 . OoooooooOO
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 15 - 15: I1IiiI . OoO0O00
  if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 oO = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( lisp . bold ( "NAT-Forward" , False ) , lisp . green ( oO , False ) ,
 # OoOoOO00 + i1IIi + IiII
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 27 - 27: i1IIi % Ii1I - OoO0O00 / oO0o . ooOoO0o / Oo0Ooo
 if 99 - 99: OoO0O00 - OoOoOO00 * OoOoOO00 . II111iiii % ooOoO0o
 if 1 - 1: I1ii11iIi11i + Oo0Ooo * oO0o + o0oOOo0O0Ooo - I11i . I1ii11iIi11i
 if 31 - 31: iIii1I11I1II1 . II111iiii - OoO0O00
 if 62 - 62: OOooOOo / II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( i1111 , i11 )
  return
  if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
  if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
  if 36 - 36: OOooOOo % i11iIiiIii
  if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
  if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 O0o0oo0oOO0oO = packet . get_raw_socket ( )
 if ( O0o0oo0oOO0oO == None ) : O0o0oo0oOO0oO = lisp_raw_socket
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 packet . send_packet ( O0o0oo0oOO0oO , packet . inner_dest )
 return
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
def oOoO0Oo0 ( group , joinleave ) :
 OOOO = lisp . lisp_lookup_group ( group )
 if ( OOOO == None ) : return
 if 7 - 7: ooOoO0o + Ii1I
 IiiIIiI1iI1 = [ ]
 for o0O00Oo0 in OOOO . sources :
  IiiIIiI1iI1 . append ( [ o0O00Oo0 , group , joinleave ] )
  if 86 - 86: i1IIi / Ii1I * I1IiiI
  if 67 - 67: I1ii11iIi11i * I1ii11iIi11i / oO0o * OoooooooOO + OoOoOO00
 OooO0oOo ( i1 , IiiIIiI1iI1 )
 return
 if 79 - 79: i1IIi
 if 1 - 1: oO0o / i1IIi
 if 74 - 74: I11i / OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
 if 98 - 98: oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
def IiIi1II111I ( ) :
 global i1
 if 80 - 80: Ii1I / OOooOOo
 lisp . lisp_set_exception ( )
 if 21 - 21: Oo0Ooo - iIii1I11I1II1 - I1Ii111
 III1I1Iii11i = socket . htonl
 oOO00oOOo = [ III1I1Iii11i ( 0x46000020 ) , III1I1Iii11i ( 0x9fe60000 ) , III1I1Iii11i ( 0x0102d7cc ) ,
 III1I1Iii11i ( 0x0acfc15a ) , III1I1Iii11i ( 0xe00000fb ) , III1I1Iii11i ( 0x94040000 ) ]
 if 11 - 11: IiII + iIii1I11I1II1 . i11iIiiIii - OOooOOo
 OoO = b""
 for i1iiiIi1Iii in oOO00oOOo : OoO += struct . pack ( "I" , i1iiiIi1Iii )
 if 54 - 54: ooOoO0o . iIii1I11I1II1 * i1IIi
 if 44 - 44: oO0o + I1ii11iIi11i * OOooOOo - i11iIiiIii / iIii1I11I1II1
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 while ( True ) :
  I1iI1I1ii1 = getoutput ( "ls join-*" ) . replace ( "join-" , "" )
  I1iI1I1ii1 = I1iI1I1ii1 . split ( "\n" )
  if 33 - 33: o0oOOo0O0Ooo / O0 + OOooOOo
  for o0Ooo0O00 in I1iI1I1ii1 :
   if ( lisp . lisp_valid_address_format ( "address" , o0Ooo0O00 ) == False ) :
    continue
    if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
    if 92 - 92: OoOoOO00 % O0
   oo00ooooOOo00 = ( o0Ooo0O00 . find ( ":" ) != - 1 )
   if 16 - 16: i11iIiiIii / i1IIi % OOooOOo
   if 84 - 84: I11i - Oo0Ooo * O0 / Ii1I . Ii1I
   if 93 - 93: O0 / ooOoO0o + I1IiiI
   if 20 - 20: IiII / iII111i % OoooooooOO / iIii1I11I1II1 + I1IiiI
   oO0oiIiI = os . path . exists ( "leave-{}" . format ( o0Ooo0O00 ) )
   lisp . lprint ( "Internal {} group {}" . format ( "leaving" if oO0oiIiI else "joining" , o0Ooo0O00 ) )
   if 46 - 46: iII111i
   if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
   if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
   if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
   if 65 - 65: ooOoO0o - i1IIi
   if ( oo00ooooOOo00 ) :
    if ( o0Ooo0O00 . lower ( ) . find ( "ff02:" ) != - 1 ) :
     lisp . lprint ( "Suppress registration for link-local groups" )
     continue
     if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
    oOoO0Oo0 ( o0Ooo0O00 , ( oO0oiIiI == False ) )
   else :
    OooO0O0Ooo = OoO
    if ( oO0oiIiI ) :
     OooO0O0Ooo += struct . pack ( "I" , III1I1Iii11i ( 0x17000000 ) )
    else :
     OooO0O0Ooo += struct . pack ( "I" , III1I1Iii11i ( 0x16000000 ) )
     if 85 - 85: o0oOOo0O0Ooo / I1Ii111
     if 67 - 67: I11i % oO0o
    ii1iiIi = o0Ooo0O00 . split ( "." )
    oo00oO0o = int ( ii1iiIi [ 0 ] ) << 24
    oo00oO0o += int ( ii1iiIi [ 1 ] ) << 16
    oo00oO0o += int ( ii1iiIi [ 2 ] ) << 8
    oo00oO0o += int ( ii1iiIi [ 3 ] )
    OooO0O0Ooo += struct . pack ( "I" , III1I1Iii11i ( oo00oO0o ) )
    IiiIIiI1iI1 = lisp . lisp_process_igmp_packet ( OooO0O0Ooo )
    if ( type ( IiiIIiI1iI1 ) != bool ) :
     OooO0oOo ( i1 , IiiIIiI1iI1 )
     if 21 - 21: I1ii11iIi11i
    time . sleep ( .100 )
    if 84 - 84: O0 / I1IiiI % i1IIi % i1IIi / OoO0O00 / oO0o
    if 28 - 28: ooOoO0o . OoooooooOO + o0oOOo0O0Ooo + Ii1I % iII111i
  time . sleep ( 10 )
  if 80 - 80: Oo0Ooo
 return
 if 86 - 86: I1ii11iIi11i * I11i . OoOoOO00 / Oo0Ooo + oO0o
 if 8 - 8: OoOoOO00
 if 16 - 16: o0oOOo0O0Ooo . I11i
 if 50 - 50: ooOoO0o * OoOoOO00 + I1ii11iIi11i - i11iIiiIii + Oo0Ooo * I1ii11iIi11i
 if 20 - 20: I1Ii111 / o0oOOo0O0Ooo % OoOoOO00
 if 69 - 69: I1Ii111 - i1IIi % iII111i . OOooOOo - OOooOOo
 if 65 - 65: OOooOOo + II111iiii
 if 61 - 61: i11iIiiIii * oO0o % Oo0Ooo * I1Ii111 - OoooooooOO - OoO0O00
 if 83 - 83: ooOoO0o / OOooOOo
 if 39 - 39: IiII + I11i
def IIi11Ii11ii ( ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
 ooO000OO = lisp . lisp_get_all_multicast_rles ( )
 if 43 - 43: ooOoO0o * I1Ii111 % OOooOOo
 if 38 - 38: Oo0Ooo
 if 34 - 34: OoOoOO00
 if 70 - 70: iIii1I11I1II1 * IiII - OOooOOo / Oo0Ooo % oO0o
 if 66 - 66: OoooooooOO + ooOoO0o * iII111i
 oOoO0O00oo = "en0" if lisp . lisp_is_macos ( ) else "any"
 if 2 - 2: iII111i . OoO0O00 / oO0o
 if 41 - 41: OoO0O00 . I1Ii111 * IiII * I1Ii111
 ooOO = "(proto 2) or "
 if 86 - 86: Ii1I . OOooOOo / IiII - OoooooooOO
 ooOO += "((dst host "
 for iii1IiI1i in lisp . lisp_get_all_addresses ( ) + ooO000OO :
  ooOO += "{} or " . format ( iii1IiI1i )
  if 93 - 93: i1IIi % OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo . O0 % OOooOOo
 ooOO = ooOO [ 0 : - 4 ]
 ooOO += ") and ((udp dst port 4341 or 8472 or 4789) or "
 ooOO += "(udp src port 4341) or "
 ooOO += "(udp dst port 4342 and ip[28] == 0x12) or "
 ooOO += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0)))))"
 if 88 - 88: oO0o % Oo0Ooo - I11i % oO0o + IiII - iII111i
 if 23 - 23: O0
 lisp . lprint ( "Capturing packets for: '{}' on device {}" . format ( ooOO ,
 oOoO0O00oo ) )
 if 9 - 9: I11i * Oo0Ooo . ooOoO0o * i11iIiiIii - O0
 if 54 - 54: I1IiiI * OOooOOo + o0oOOo0O0Ooo % i1IIi - o0oOOo0O0Ooo + OoOoOO00
 if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
 if ( lisp . lisp_is_python2 ( ) ) :
  import pcappy
  O0i1I11I = pcappy . open_live ( oOoO0O00oo , 1600 , 0 , 100 )
  O0i1I11I . filter = ooOO
  O0i1I11I . loop ( - 1 , I11 , [ oOoO0O00oo , oOOoo00O0O ] )
  if 34 - 34: Ii1I * o0oOOo0O0Ooo + OOooOOo / IiII / Oo0Ooo
 if ( lisp . lisp_is_python3 ( ) ) :
  import pcapy
  O0i1I11I = pcapy . open_live ( oOoO0O00oo , 1600 , 0 , 100 )
  O0i1I11I . setfilter ( ooOO )
  while ( True ) :
   I111Iii1 , OoO = O0i1I11I . next ( )
   if ( len ( OoO ) == 0 ) : continue
   I11 ( [ oOoO0O00oo , oOOoo00O0O ] , None , OoO )
   if 30 - 30: i1IIi
   if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
 return
 if 93 - 93: ooOoO0o
 if 18 - 18: ooOoO0o
 if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
 if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
 if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
 if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
 if 58 - 58: O0
def O0oO ( ) :
 global o0oOoO00o
 global I1Ii11I1Ii1i
 global i1
 global oOOoo00O0O
 global i1111
 global i11
 if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
 lisp . lisp_i_am ( "etr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "ETR starting up" )
 if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
 if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
 if 21 - 21: iII111i
 lisp . lisp_get_local_interfaces ( )
 lisp . lisp_get_local_macs ( )
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 24 - 24: iII111i / ooOoO0o
 if 61 - 61: iIii1I11I1II1 + oO0o
 if 8 - 8: I1Ii111 + OoO0O00
 if 9 - 9: OOooOOo + o0oOOo0O0Ooo
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
 o0O00Oo0 = lisp . lisp_open_listen_socket ( "0.0.0.0" , str ( Ooo ) )
 o0O00Oo0 . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_TTL , 32 )
 I1Ii11I1Ii1i = o0O00Oo0
 if 17 - 17: I11i
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 o0oOoO00o = lisp . lisp_open_listen_socket ( "" , "lisp-etr" )
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
 i1 [ 0 ] = I1Ii11I1Ii1i
 i1 [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 i1 [ 2 ] = o0oOoO00o
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 if 36 - 36: IiII
 if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
 if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
 if 43 - 43: iIii1I11I1II1 % OoO0O00
 if 84 - 84: Oo0Ooo
 oOOoo00O0O = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 oOOoo00O0O . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 i1 . append ( oOOoo00O0O )
 if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
 if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
 if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
 if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
 if 25 - 25: o0oOOo0O0Ooo
 if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
 if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
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
 if ( pytun != None ) :
  i11 = b'\x00\x00\x86\xdd'
  oOoO0O00oo = "lispers.net"
  try :
   i1111 = pytun . TunTapDevice ( flags = pytun . IFF_TUN ,
 name = oOoO0O00oo )
   os . system ( "ip link set dev {} up" . format ( oOoO0O00oo ) )
  except :
   lisp . lprint ( "Cannot create tuntap interface" )
   if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
   if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
   if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
   if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
   if 10 - 10: IiII / OoooooooOO
   if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
 threading . Thread ( target = IIi11Ii11ii , args = [ ] ) . start ( )
 if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
 if 25 - 25: iIii1I11I1II1
 if 63 - 63: ooOoO0o
 if 96 - 96: I11i
 threading . Thread ( target = IiIi1II111I , args = [ ] ) . start ( )
 if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
 if 63 - 63: iII111i
 if 11 - 11: iII111i - iIii1I11I1II1
 if 92 - 92: OoO0O00
 global Oo
 Oo = threading . Timer ( 60 , i11iIIIIIi1 )
 Oo . start ( )
 if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
 return ( True )
 if 12 - 12: ooOoO0o
 if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
 if 60 - 60: OOooOOo . iII111i / iIii1I11I1II1 + OOooOOo * I1Ii111
 if 82 - 82: i11iIiiIii . iIii1I11I1II1 * I1IiiI - I11i + Ii1I
 if 48 - 48: I1ii11iIi11i
 if 96 - 96: ooOoO0o . OoooooooOO
 if 39 - 39: OOooOOo + OoO0O00
def oOoOOOO0OOO ( ) :
 global Oo0o
 global Ii1iI
 global Oo
 if 58 - 58: I11i % i11iIiiIii / i11iIiiIii * ooOoO0o - I1Ii111
 if 6 - 6: IiII * II111iiii % iIii1I11I1II1
 if 86 - 86: i1IIi * O0 % ooOoO0o . Oo0Ooo % ooOoO0o . Oo0Ooo
 if 71 - 71: iII111i . i11iIiiIii * O0 + O0
 if ( Oo0o ) : Oo0o . cancel ( )
 if ( Ii1iI ) : Ii1iI . cancel ( )
 if ( Oo ) : Oo . cancel ( )
 if 57 - 57: OoooooooOO . I11i % II111iiii % I1IiiI + Ii1I
 if 70 - 70: IiII . i11iIiiIii
 if 76 - 76: iII111i . IiII % iII111i - I1Ii111
 if 51 - 51: OoooooooOO + o0oOOo0O0Ooo * iIii1I11I1II1 * oO0o / i1IIi
 lisp . lisp_close_socket ( i1 [ 0 ] , "" )
 lisp . lisp_close_socket ( i1 [ 1 ] , "" )
 lisp . lisp_close_socket ( o0oOoO00o , "lisp-etr" )
 return
 if 19 - 19: iII111i - OoOoOO00 % oO0o / OoooooooOO % iII111i
 if 65 - 65: O0 . oO0o
 if 85 - 85: II111iiii
 if 55 - 55: I1ii11iIi11i
 if 76 - 76: oO0o - i11iIiiIii
 if 27 - 27: I1ii11iIi11i - i11iIiiIii % I1Ii111 / Oo0Ooo . Oo0Ooo / OoooooooOO
 if 76 - 76: I11i * OoO0O00 . iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
def oo0O00ooo0o ( ipc ) :
 ipc = ipc . split ( "%" )
 Ii11iI1ii1111 = ipc [ 1 ]
 ii1i1Iii = ipc [ 2 ]
 if ( ii1i1Iii == "None" ) : ii1i1Iii = None
 if 57 - 57: IiII
 oOIIi1iiii1iI = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 oOIIi1iiii1iI . store_address ( Ii11iI1ii1111 )
 if 41 - 41: iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % IiII / OOooOOo
 if 63 - 63: i1IIi % i11iIiiIii % II111iiii * OoooooooOO
 if 40 - 40: Oo0Ooo
 if 47 - 47: OoOoOO00
 Ii = lisp . lisp_db_for_lookups . lookup_cache ( oOIIi1iiii1iI , False )
 if ( Ii == None or Ii . dynamic_eid_configured ( ) == False ) :
  lisp . lprint ( "ITR/ETR dynamic-EID configuration out of sync for {}" . format ( lisp . green ( Ii11iI1ii1111 , False ) ) )
  if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
  return
  if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
  if 33 - 33: oO0o
  if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
  if 41 - 41: IiII % o0oOOo0O0Ooo
  if 67 - 67: O0 % I1Ii111
  if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
 iIi1II = None
 if ( Ii11iI1ii1111 in Ii . dynamic_eids ) : iIi1II = Ii . dynamic_eids [ Ii11iI1ii1111 ]
 if 39 - 39: Ii1I
 if ( iIi1II == None and ii1i1Iii == None ) :
  lisp . lprint ( "ITR/ETR state mismatch for {}" . format ( lisp . green ( Ii11iI1ii1111 , False ) ) )
  if 60 - 60: OOooOOo
  return
  if 62 - 62: I1Ii111 * I11i
  if 74 - 74: OoOoOO00 . iIii1I11I1II1
  if 87 - 87: ooOoO0o
  if 41 - 41: OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
  if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
  if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
  if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
 if ( iIi1II and ii1i1Iii ) :
  if ( iIi1II . interface == ii1i1Iii ) :
   lisp . lprint ( "ITR sent redundant IPC for {}" . format ( lisp . green ( Ii11iI1ii1111 , False ) ) )
   if 44 - 44: I1Ii111 - IiII
  else :
   lisp . lprint ( "Dynamic-EID {} interface change, {} -> {}" . format ( lisp . green ( Ii11iI1ii1111 , False ) , iIi1II . interface , ii1i1Iii ) )
   if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
   iIi1II . interface = ii1i1Iii
   if 59 - 59: II111iiii
  return
  if 43 - 43: Oo0Ooo + OoooooooOO
  if 47 - 47: ooOoO0o
  if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
  if 23 - 23: II111iiii * iII111i
  if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
 if ( ii1i1Iii ) :
  iIi1II = lisp . lisp_dynamic_eid ( )
  iIi1II . dynamic_eid . copy_address ( oOIIi1iiii1iI )
  iIi1II . interface = ii1i1Iii
  iIi1II . get_timeout ( ii1i1Iii )
  Ii . dynamic_eids [ Ii11iI1ii1111 ] = iIi1II
  if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
  OoO0o0OO = lisp . bold ( "Registering" , False )
  Ii11iI1ii1111 = lisp . bold ( Ii11iI1ii1111 , False )
  lisp . lprint ( "{} dynamic-EID {} on interface {}, timeout {}" . format ( OoO0o0OO ,
 lisp . green ( Ii11iI1ii1111 , False ) , ii1i1Iii , iIi1II . timeout ) )
  if 10 - 10: oO0o - iII111i % II111iiii - I1Ii111 - i1IIi
  o00O ( i1 , None , oOIIi1iiii1iI , None , False )
  if 10 - 10: I1ii11iIi11i - I11i . I1Ii111
  if 8 - 8: iIii1I11I1II1 % oO0o + Oo0Ooo
  if 24 - 24: o0oOOo0O0Ooo / Ii1I / Ii1I % II111iiii - oO0o * oO0o
  if 58 - 58: OoOoOO00
  if ( lisp . lisp_is_macos ( ) == False ) :
   Ii11iI1ii1111 = oOIIi1iiii1iI . print_prefix_no_iid ( )
   o0oOO = "ip route add {} dev {}" . format ( Ii11iI1ii1111 , ii1i1Iii )
   os . system ( o0oOO )
   if 84 - 84: i11iIiiIii + ooOoO0o . O0
  return
  if 69 - 69: I1Ii111 / OoooooooOO % i11iIiiIii
  if 18 - 18: i11iIiiIii - ooOoO0o * oO0o + o0oOOo0O0Ooo
  if 16 - 16: OoooooooOO * i11iIiiIii . OoooooooOO - iIii1I11I1II1 * i1IIi
  if 33 - 33: I1Ii111 % II111iiii
  if 49 - 49: I1ii11iIi11i + I11i / o0oOOo0O0Ooo + OoooooooOO + OOooOOo / IiII
 if ( Ii11iI1ii1111 in Ii . dynamic_eids ) :
  ii1i1Iii = Ii . dynamic_eids [ Ii11iI1ii1111 ] . interface
  i1i11I1I1 = lisp . bold ( "Deregistering" , False )
  lisp . lprint ( "{} dynamic-EID {}" . format ( i1i11I1I1 ,
 lisp . green ( Ii11iI1ii1111 , False ) ) )
  if 82 - 82: OoO0O00 - Oo0Ooo - O0 - OoooooooOO
  o00O ( i1 , 0 , oOIIi1iiii1iI , None , False )
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
  Ii . dynamic_eids . pop ( Ii11iI1ii1111 )
  if 18 - 18: Oo0Ooo % O0
  if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
  if 86 - 86: IiII
  if ( lisp . lisp_is_macos ( ) == False ) :
   Ii11iI1ii1111 = oOIIi1iiii1iI . print_prefix_no_iid ( )
   o0oOO = "ip route delete {} dev {}" . format ( Ii11iI1ii1111 , ii1i1Iii )
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
 if 14 - 14: IiII . IiII % ooOoO0o
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
 if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
 if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
def iI1 ( ipc ) :
 global IiI1I1
 global I1Ii11I1Ii1i
 if 22 - 22: IiII * Ii1I - OoooooooOO
 ipc = ipc . split ( "%" )
 i1Ii1 = ipc [ - 2 ]
 oooOOo0oOoOO = ipc [ - 1 ]
 if 6 - 6: oO0o . I11i
 iIIII1 = False
 if ( i1Ii1 in IiI1I1 ) :
  oo00OOoOoO00 = IiI1I1 [ i1Ii1 ]
 else :
  oo00OOoOoO00 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , i1Ii1 , 32 , 0 )
  IiI1I1 [ i1Ii1 ] = oo00OOoOoO00
  iIIII1 = True
  if 65 - 65: O0 / II111iiii . iIii1I11I1II1 . oO0o / Oo0Ooo % iIii1I11I1II1
  if 74 - 74: i1IIi / I1IiiI % I1ii11iIi11i / O0 % I11i - OoOoOO00
  if 31 - 31: I1IiiI / OoooooooOO . iIii1I11I1II1 * OoOoOO00 . OoooooooOO + II111iiii
  if 8 - 8: I1ii11iIi11i * I1ii11iIi11i * i1IIi + iII111i . I1ii11iIi11i
  if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
 if ( iIIII1 ) :
  Oo00OOo00O = [ I1Ii11I1Ii1i , I1Ii11I1Ii1i ,
 o0oOoO00o ]
  lisp . lprint ( "Trigger NAT-Probe to ETR {}" . format ( i1Ii1 ) )
  lisp . lisp_send_info_request ( Oo00OOo00O , oo00OOoOoO00 , lisp . LISP_DATA_PORT , None )
  if 37 - 37: Oo0Ooo
  if 72 - 72: IiII % I1ii11iIi11i * OOooOOo . i11iIiiIii % IiII * OOooOOo
  if 15 - 15: I11i / Oo0Ooo * I11i
  if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
  if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
  if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
  if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
 iiiIIiiIi = oooOOo0oOoOO . split ( lisp . LISP_TP )
 if ( len ( iiiIIiiIi ) != 2 ) :
  lisp . lprint ( "Invalid NAT IPC rloc-name {}" . format ( iiiIIiiIi ) )
  return
  if 86 - 86: OoooooooOO % II111iiii . OoooooooOO * I1ii11iIi11i
  if 9 - 9: Oo0Ooo + iII111i
 oooooO0oO0ooO , IiI1iI1IiiIi1 = iiiIIiiIi [ 0 ] , int ( iiiIIiiIi [ 1 ] )
 lisp . lisp_store_nat_info ( oooooO0oO0ooO , oo00OOoOoO00 , IiI1iI1IiiIi1 )
 if 31 - 31: I1ii11iIi11i
 if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
 if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
 if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
 if 13 - 13: II111iiii - Oo0Ooo % i11iIiiIii + iII111i
 if 88 - 88: O0 . oO0o % I1IiiI
 if 10 - 10: I1IiiI + O0
 if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
 if 31 - 31: i11iIiiIii * OoOoOO00
 if 69 - 69: i11iIiiIii
 if 61 - 61: O0
def iIiiI111I11 ( ipc ) :
 if ( lisp . lisp_register_all_rtrs ) : return
 if 86 - 86: oO0o + iII111i / OoooooooOO - I11i
 o00O0 , II1I1I1Ii , OOoooOoO0Oo = ipc . split ( "%" )
 if ( II1I1I1Ii not in lisp . lisp_rtr_list ) : return
 if 40 - 40: OoO0O00 . i11iIiiIii + I1ii11iIi11i + I1IiiI . oO0o
 lisp . lprint ( "Process ITR IPC message, RTR {} has gone {}" . format (
 lisp . red ( II1I1I1Ii , False ) , lisp . bold ( OOoooOoO0Oo , False ) ) )
 if 90 - 90: I1Ii111 . OoOoOO00 * II111iiii % ooOoO0o
 OOOOoO00o0O = lisp . lisp_rtr_list [ II1I1I1Ii ]
 if ( OOoooOoO0Oo == "down" ) :
  lisp . lisp_rtr_list [ II1I1I1Ii ] = None
  return
  if 36 - 36: I1IiiI - Oo0Ooo % OOooOOo . I11i + I11i + Ii1I
  if 28 - 28: Oo0Ooo / oO0o * OoOoOO00 + I1ii11iIi11i - I1Ii111
 OOOOoO00o0O = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , II1I1I1Ii , 32 , 0 )
 lisp . lisp_rtr_list [ II1I1I1Ii ] = OOOOoO00o0O
 return
 if 78 - 78: I1IiiI . I1IiiI * OoO0O00 - i11iIiiIii
 if 86 - 86: O0
 if 11 - 11: Ii1I + iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
 if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
 if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
 if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
 if 55 - 55: OoooooooOO
 if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
 if 38 - 38: O0
 if 79 - 79: i1IIi . oO0o
def i1i1i11iI11II ( ipc ) :
 II1 , o00O0 , iiI1iI , O0oo0000o = ipc . split ( "%" )
 O0oo0000o = int ( O0oo0000o , 16 )
 if 99 - 99: oO0o - I1ii11iIi11i . II111iiii * i11iIiiIii . OOooOOo - OoO0O00
 Iii11I111Ii11 = lisp . lisp_get_echo_nonce ( None , iiI1iI )
 if ( Iii11I111Ii11 == None ) : Iii11I111Ii11 = lisp . lisp_echo_nonce ( iiI1iI )
 if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
 if ( o00O0 == "R" ) :
  Iii11I111Ii11 . request_nonce_sent = O0oo0000o
  lisp . lprint ( "Waiting for echo-nonce 0x{} from {}" . format ( lisp . lisp_hex_string ( O0oo0000o ) , lisp . red ( Iii11I111Ii11 . rloc_str , False ) ) )
  if 20 - 20: i1IIi . i1IIi - I11i
 elif ( o00O0 == "E" ) :
  Iii11I111Ii11 . echo_nonce_sent = O0oo0000o
  lisp . lprint ( "Sent echo-nonce 0x{} to {}" . format ( lisp . lisp_hex_string ( O0oo0000o ) , lisp . red ( Iii11I111Ii11 . rloc_str , False ) ) )
  if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
  if 35 - 35: II111iiii / OoOoOO00 - O0 . II111iiii
 return
 if 55 - 55: Oo0Ooo % i1IIi * I11i
 if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
 if 63 - 63: iIii1I11I1II1 / ooOoO0o
 if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
 if 50 - 50: II111iiii
IiI = {
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

 "lisp map-server" : [ Ii11iI1i , {
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

 "lisp database-mapping" : [ iII , {
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

 "lisp group-mapping" : [ Ii1iI111II1I1 , {
 "group-name" : [ False ] ,
 "ms-name" : [ True ] ,
 "group-prefix" : [ False ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "rle-address" : [ False ] ,
 "sources" : [ ] ,
 "address" : [ True ] } ] ,

 "show database-mapping" : [ oO00OOoO00 , { } ] ,
 "show etr-keys" : [ oo0 , { } ] ,
 "show etr-dynamic-eid" : [ lispconfig . lisp_show_dynamic_eid_command , { } ]
 }
if 50 - 50: i11iIiiIii + OoooooooOO / O0 + o0oOOo0O0Ooo / i11iIiiIii + oO0o
if 90 - 90: iII111i * Ii1I - iII111i + OoO0O00 + I11i % O0
if 11 - 11: OOooOOo % I1Ii111 * OoOoOO00
if 58 - 58: OoooooooOO - I11i + iIii1I11I1II1 * i11iIiiIii
if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
if ( O0oO ( ) == False ) :
 lisp . lprint ( "lisp_etr_startup() failed" )
 lisp . lisp_print_banner ( "ETR abnormal exit" )
 exit ( 1 )
 if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
 if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
oo0oo00O0O = [ I1Ii11I1Ii1i , o0oOoO00o ]
if 35 - 35: OoO0O00
while ( True ) :
 try : oO0OO , o0OOO , II1 = select . select ( oo0oo00O0O , [ ] , [ ] )
 except : break
 if 48 - 48: OoooooooOO - I1Ii111 . i11iIiiIii * iII111i - Ii1I - o0oOOo0O0Ooo
 if 59 - 59: iII111i / I11i . Oo0Ooo
 if 100 - 100: O0
 if 94 - 94: I1ii11iIi11i - o0oOOo0O0Ooo
 if ( I1Ii11I1Ii1i in oO0OO ) :
  o00O0 , o0OOOOooo , IiI1iI1IiiIi1 , OoO = lisp . lisp_receive ( I1Ii11I1Ii1i , False )
  if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
  if ( o0OOOOooo == "" ) : break
  if 25 - 25: Oo0Ooo % OoOoOO00
  if ( IiI1iI1IiiIi1 == lisp . LISP_DATA_PORT ) :
   ooooO0 ( oOOoo00O0O , OoO , o0OOOOooo )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( OoO [ 0 : 1 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 75 - 75: i1IIi
   OOO0OO = lisp . lisp_parse_packet ( i1 , OoO ,
 o0OOOOooo , IiI1iI1IiiIi1 )
   if 45 - 45: iII111i - o0oOOo0O0Ooo . Ii1I
   if 41 - 41: II111iiii . I1IiiI / OoO0O00 . ooOoO0o
   if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
   if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
   if 36 - 36: I11i - IiII . IiII
   if ( OOO0OO ) :
    Ii1iI = threading . Timer ( 0 ,
 i1iiI11I , [ None ] )
    Ii1iI . start ( )
    Oo0o = threading . Timer ( 0 ,
 oo000OO00Oo , [ i1 ] )
    Oo0o . start ( )
    if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
    if 84 - 84: iIii1I11I1II1 + OoooooooOO
    if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
    if 10 - 10: I1ii11iIi11i + IiII
    if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
    if 62 - 62: II111iiii
    if 12 - 12: IiII + II111iiii
    if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
 if ( o0oOoO00o in oO0OO ) :
  o00O0 , o0OOOOooo , IiI1iI1IiiIi1 , OoO = lisp . lisp_receive ( o0oOoO00o , True )
  if 80 - 80: iII111i
  if ( o0OOOOooo == "" ) : break
  if 3 - 3: I1ii11iIi11i * I11i
  if ( o00O0 == "command" ) :
   OoO = OoO . decode ( )
   if ( OoO . find ( "learn%" ) != - 1 ) :
    oo0O00ooo0o ( OoO )
   elif ( OoO . find ( "nat%" ) != - 1 ) :
    iI1 ( OoO )
   elif ( OoO . find ( "nonce%" ) != - 1 ) :
    i1i1i11iI11II ( OoO )
   elif ( OoO . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( OoO )
   elif ( OoO . find ( "rtr%" ) != - 1 ) :
    iIiiI111I11 ( OoO )
   elif ( OoO . find ( "stats%" ) != - 1 ) :
    OoO = OoO . split ( "%" ) [ - 1 ]
    lisp . lisp_process_data_plane_decap_stats ( OoO , None )
   else :
    lispconfig . lisp_process_command ( o0oOoO00o ,
 o00O0 , OoO , "lisp-etr" , [ IiI ] )
    if 53 - 53: iIii1I11I1II1 / iII111i % OoO0O00 + IiII / ooOoO0o
  elif ( o00O0 == "api" ) :
   OoO = OoO . decode ( )
   lisp . lisp_process_api ( "lisp-etr" , o0oOoO00o , OoO )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( OoO [ 0 : 1 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 74 - 74: Oo0Ooo
   lisp . lisp_parse_packet ( i1 , OoO , o0OOOOooo , IiI1iI1IiiIi1 )
   if 8 - 8: I1IiiI % II111iiii - o0oOOo0O0Ooo - I11i % I1IiiI
   if 93 - 93: Ii1I * iII111i / OOooOOo
   if 88 - 88: oO0o
   if 1 - 1: Oo0Ooo
oOoOOOO0OOO ( )
lisp . lisp_print_banner ( "ETR normal exit" )
exit ( 0 )
if 95 - 95: OoooooooOO / I11i % OoooooooOO / ooOoO0o * IiII
if 75 - 75: O0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
