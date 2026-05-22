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
 Oo00OOOOO = list ( lisp . lisp_map_servers_list . values ( ) ) [ 0 ]
 if ( Ii1iI == None and lisp . lisp_nat_traversal ) :
  Ii1iI = threading . Timer ( 2 , I1i1iii , [ Oo00OOOOO . map_server ] )
  Ii1iI . start ( )
 else :
  if 20 - 20: o0oOOo0O0Ooo
  if 77 - 77: OoOoOO00 / I11i
  if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
  if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
  if 95 - 95: OoO0O00 % oO0o . O0
  if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
  if 53 - 53: IiII + I1IiiI * oO0o
  if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
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
  if ( OOO0o0o == None ) :
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
   if 26 - 26: iII111i
def OOO ( ) :
 global Oo
 if 59 - 59: II111iiii + OoooooooOO * OoOoOO00 + i1IIi
 lisp . lisp_set_exception ( )
 if 58 - 58: II111iiii * OOooOOo * I1ii11iIi11i / OOooOOo
 lisp . lisp_timeout_igmp_database ( )
 if 75 - 75: oO0o
 if Oo : Oo . cancel ( )
 Oo = threading . Timer ( 60 , OOO )
 Oo . start ( )
 if 50 - 50: Ii1I / Oo0Ooo - oO0o - I11i % iII111i - oO0o
 if 91 - 91: OoO0O00 / I11i - II111iiii . I11i
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 if 92 - 92: iII111i . I1Ii111
def i1i ( kv_pair ) :
 global Oo0o , OOO0o0o
 global i1 , i11iiII
 if 50 - 50: IiII
 if 14 - 14: I11i % OoO0O00 * I11i
 if 16 - 16: OoOoOO00 . ooOoO0o + i11iIiiIii
 if 38 - 38: IiII * OOooOOo . o0oOOo0O0Ooo
 if 98 - 98: OoooooooOO + iII111i . OoOoOO00
 if 67 - 67: i11iIiiIii - i1IIi % I1ii11iIi11i . O0
 if ( i11iiII ) : return
 if 77 - 77: IiII / I1IiiI
 lispconfig . lisp_database_mapping_command ( kv_pair , Ooo ,
 ( oOOOO == False ) )
 if 15 - 15: IiII . iIii1I11I1II1 . OoooooooOO / i11iIiiIii - Ii1I . i1IIi
 if 33 - 33: I11i . o0oOOo0O0Ooo
 if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
 if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
 if 61 - 61: II111iiii
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if ( lisp . lisp_nat_traversal ) : return
 if ( OOO0o0o != None ) : return
 if 42 - 42: OoO0O00
 if 67 - 67: I1Ii111 . iII111i . O0
 if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
 if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 if ( oOOOO ) :
  o0oO = len ( lisp . lisp_db_list )
  if ( o0oO % 1000 == 0 ) :
   lisp . fprint ( "{} database-mappings processed" . format ( o0oO ) )
   if 1 - 1: OoO0O00 - oO0o . I11i . OoO0O00 / Oo0Ooo + I11i
   if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
  i1iIi = lisp . lisp_db_list [ - 1 ]
  if ( i1iIi . eid . is_dist_name ( ) == False ) : return
  if ( i1iIi . eid . address != "eid-done" ) : return
  i11iiII = True
  if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
  lisp . fprint ( "Finished batch of {} database-mappings" . format ( o0oO ) )
  if 31 - 31: II111iiii . I1IiiI
  if ( Oo0o == None ) :
   Oo0o = threading . Timer ( 0 , oo000OO00Oo ,
 [ i1 ] )
   Oo0o . start ( )
   if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
  return
  if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
  if 92 - 92: iII111i
 if ( len ( lisp . lisp_map_servers_list ) > 0 ) :
  OOO0o0o = threading . Timer ( 5 ,
 oo000OO00Oo , [ i1 ] )
  OOO0o0o . start ( )
  if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
  if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
  if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
  if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
  if 51 - 51: O0 + iII111i
  if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
  if 48 - 48: O0
  if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
def i1Iii1i1I ( clause ) :
 if 91 - 91: I1ii11iIi11i + I1IiiI . OOooOOo * I1ii11iIi11i + I1IiiI * Oo0Ooo
 if 80 - 80: iII111i % OOooOOo % oO0o - Oo0Ooo + Oo0Ooo
 if 19 - 19: OoOoOO00 * i1IIi
 if 14 - 14: iII111i
 I1iI1iIi111i = lispconfig . lisp_show_myrlocs ( "" )
 if 44 - 44: i1IIi % II111iiii + I11i
 if 45 - 45: iII111i / iII111i + I1Ii111 + ooOoO0o
 if 47 - 47: o0oOOo0O0Ooo + ooOoO0o
 if 82 - 82: II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
 I1iI1iIi111i = lispconfig . lisp_show_decap_stats ( I1iI1iIi111i , "ETR" )
 if 77 - 77: iIii1I11I1II1 * OoO0O00
 if 95 - 95: I1IiiI + i11iIiiIii
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
 I1iI1iIi111i += lispconfig . lisp_table_header ( IiIIii1iII1II , "Address" , "Auth-Type" ,
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
  I1iI1iIi111i += lispconfig . lisp_table_row ( oO ,
 "sha1" if ( Oo00OOOOO . alg_id == lisp . LISP_SHA_1_96_ALG_ID ) else "sha2" ,
 IiII111iI1ii1 , Oo00OOOOO . site_id , iI11I1II , ii1Ii1I1Ii11i ,
 Oo00OOOOO . map_notifies_received )
  if 37 - 37: oO0o - I1IiiI . I11i * Ii1I - iII111i
 I1iI1iIi111i += lispconfig . lisp_table_footer ( )
 if 8 - 8: OoO0O00 - I1IiiI % Ii1I * OoooooooOO - OoO0O00 * I1Ii111
 if 6 - 6: OoooooooOO
 if 17 - 17: I1IiiI % I1Ii111
 if 90 - 90: oO0o / iIii1I11I1II1 - o0oOOo0O0Ooo / OoooooooOO - OoooooooOO * OOooOOo
 I1iI1iIi111i = lispconfig . lisp_show_db_list ( "ETR" , I1iI1iIi111i )
 if 73 - 73: I1ii11iIi11i * i11iIiiIii % oO0o . I1ii11iIi11i
 if 66 - 66: oO0o + oO0o + ooOoO0o / iII111i + OOooOOo
 if 30 - 30: O0
 if 44 - 44: oO0o / I11i / I11i
 if ( len ( lisp . lisp_elp_list ) != 0 ) :
  I1iI1iIi111i = lispconfig . lisp_show_elp_list ( I1iI1iIi111i )
  if 87 - 87: Oo0Ooo . I1IiiI - II111iiii + O0 / Oo0Ooo / oO0o
  if 25 - 25: I1IiiI . I1IiiI - OoOoOO00 % OoOoOO00 - i11iIiiIii / I1Ii111
  if 51 - 51: Oo0Ooo / OoOoOO00 . OOooOOo * o0oOOo0O0Ooo + OoO0O00 * IiII
  if 73 - 73: OoO0O00 + OoooooooOO - O0 - Ii1I - II111iiii
  if 99 - 99: ooOoO0o . Ii1I + I1Ii111 + OoooooooOO % o0oOOo0O0Ooo
 if ( len ( lisp . lisp_rle_list ) != 0 ) :
  I1iI1iIi111i = lispconfig . lisp_show_rle_list ( I1iI1iIi111i )
  if 51 - 51: iIii1I11I1II1
  if 34 - 34: oO0o + I1IiiI - oO0o
  if 17 - 17: II111iiii % iII111i + I11i - iII111i / OOooOOo + ooOoO0o
  if 59 - 59: OOooOOo % OoOoOO00 . Ii1I * I1ii11iIi11i % I11i
  if 59 - 59: oO0o - iII111i
 if ( len ( lisp . lisp_json_list ) != 0 ) :
  I1iI1iIi111i = lispconfig . lisp_show_json_list ( I1iI1iIi111i )
  if 15 - 15: I1Ii111 . i11iIiiIii . OoooooooOO / OoO0O00 % Ii1I
  if 93 - 93: O0 % i1IIi . OOooOOo / I1IiiI - I1Ii111 / I1IiiI
  if 36 - 36: oO0o % oO0o % i1IIi / i1IIi - ooOoO0o
  if 30 - 30: I11i / I1IiiI
  if 35 - 35: II111iiii % OOooOOo . ooOoO0o + ooOoO0o % II111iiii % II111iiii
 if ( len ( lisp . lisp_group_mapping_list ) != 0 ) :
  IiIIii1iII1II = "Configured Group Mappings:"
  I1iI1iIi111i += lispconfig . lisp_table_header ( IiIIii1iII1II , "Name" , "Group Prefix" ,
 "Sources" , "Use MS" )
  for ooOoO00 in list ( lisp . lisp_group_mapping_list . values ( ) ) :
   Ii1IIiI1i = ""
   for o0O00Oo0 in ooOoO00 . sources : Ii1IIiI1i += o0O00Oo0 + ", "
   if ( Ii1IIiI1i == "" ) :
    Ii1IIiI1i = "*"
   else :
    Ii1IIiI1i = Ii1IIiI1i [ 0 : - 2 ]
    if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
   I1iI1iIi111i += lispconfig . lisp_table_row ( ooOoO00 . group_name ,
 ooOoO00 . group_prefix . print_prefix ( ) , Ii1IIiI1i , ooOoO00 . use_ms_name )
   if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
  I1iI1iIi111i += lispconfig . lisp_table_footer ( )
  if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 return ( I1iI1iIi111i )
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
  for i1iIi in lisp . lisp_db_list :
   oOIIi1iiii1iI = i1iIi . eid if i1iIi . group . is_null ( ) else i1iIi . group
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
 for i1iIi in lisp . lisp_db_list :
  if ( oo0oOoo ) :
   ii1iI = lisp . lisp_get_decent_dns_name ( i1iIi . eid )
  else :
   ii1iI = i1iIi . use_ms_name
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
  if ( i1iIi . dynamic_eid_configured ( ) ) :
   for iIi1II in list ( i1iIi . dynamic_eids . values ( ) ) :
    oOIIi1iiii1iI = iIi1II . dynamic_eid
    if ( eid_only == None or eid_only . is_exact_match ( oOIIi1iiii1iI ) ) :
     I1iIiI11I1 , oOoOO = i1Ii1i1I11Iii ( Iii1 , i1iIi ,
 oOIIi1iiii1iI , i1iIi . group , ttl )
     Ii1i1 += I1iIiI11I1
     iI11I [ 1 ] += oOoOO
     if 27 - 27: Ii1I . i11iIiiIii % I1Ii111
     if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
  else :
   if ( eid_only == None ) :
    if ( ttl != 0 ) : ttl = i1iIi . register_ttl
    Ii1i1 , oOoOO = i1Ii1i1I11Iii ( Iii1 , i1iIi ,
 i1iIi . eid , i1iIi . group , ttl )
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
def I1i1iii ( ms ) :
 global Ii1iI
 global I1Ii11I1Ii1i
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 lisp . lisp_set_exception ( )
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 I111i1I1 = [ I1Ii11I1Ii1i , I1Ii11I1Ii1i , o0oOoO00o ]
 lisp . lisp_build_info_requests ( I111i1I1 , ms , lisp . LISP_CTRL_PORT )
 if 62 - 62: OOooOOo * I1Ii111 / Oo0Ooo * o0oOOo0O0Ooo
 if 29 - 29: Oo0Ooo % OoO0O00 % IiII . o0oOOo0O0Ooo / OoooooooOO * ooOoO0o
 if 54 - 54: O0
 if 68 - 68: OoO0O00 * o0oOOo0O0Ooo . ooOoO0o % oO0o % I1Ii111
 if 75 - 75: OoOoOO00
 i1OoOO = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) == None )
 for OOOOoO00o0O in list ( lisp . lisp_rtr_list . values ( ) ) :
  if ( OOOOoO00o0O == None ) : continue
  if ( OOOOoO00o0O . is_private_address ( ) and i1OoOO == False ) :
   iIII1I1i1i = lisp . red ( OOOOoO00o0O . print_address_no_iid ( ) , False )
   lisp . lprint ( "Skip over RTR private address {}" . format ( iIII1I1i1i ) )
   continue
   if 79 - 79: Ii1I . OoO0O00
  lisp . lisp_build_info_requests ( I111i1I1 , OOOOoO00o0O , lisp . LISP_DATA_PORT )
  if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
  if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
  if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
  if 52 - 52: i1IIi
  if 84 - 84: Ii1I / IiII
  if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 for IiIIiIIIiIii in IiI1I1 :
  I1i11II = IiI1I1 [ IiIIiIIIiIii ]
  lisp . lprint ( "Send NAT-Probe to ETR {}" . format ( IiIIiIIIiIii ) )
  lisp . lisp_build_info_requests ( I111i1I1 , I1i11II , lisp . LISP_DATA_PORT )
  if 31 - 31: oO0o / IiII * o0oOOo0O0Ooo . II111iiii
  if 89 - 89: O0
  if 2 - 2: I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i * o0oOOo0O0Ooo
  if 100 - 100: Oo0Ooo % Ii1I / I11i
  if 30 - 30: Oo0Ooo - OOooOOo - iII111i
  if 81 - 81: o0oOOo0O0Ooo . OoooooooOO + OOooOOo * ooOoO0o
 if ( Ii1iI ) :
  Ii1iI . cancel ( )
  Ii1iI = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 I1i1iii , [ None ] )
  Ii1iI . start ( )
  if 74 - 74: i1IIi + O0 + Oo0Ooo
 return
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
def oo000OO00Oo ( lisp_sockets ) :
 global Oo0o , OOO0o0o
 global I1Ii11I1Ii1i
 if 63 - 63: I1ii11iIi11i
 lisp . lisp_set_exception ( )
 if 6 - 6: ooOoO0o / I1ii11iIi11i
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
 if 87 - 87: oO0o % Ii1I
 o00O ( lisp_sockets , None , None , None , True )
 if 83 - 83: II111iiii - I11i
 if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if ( lisp . lisp_l2_overlay ) :
  o0OO000ooOo = [ None , "ffff-ffff-ffff" , True ]
  oOo00OooO0oO ( lisp_sockets , [ o0OO000ooOo ] )
  if 16 - 16: IiII / Oo0Ooo + OOooOOo / Ii1I
  if 42 - 42: Oo0Ooo + II111iiii - I1IiiI / I11i % IiII
  if 66 - 66: OOooOOo + i1IIi . I1IiiI + OOooOOo - I11i
  if 17 - 17: O0 . I1Ii111 . O0 + O0 / Oo0Ooo . ooOoO0o
  if 62 - 62: I1ii11iIi11i % iII111i * OoO0O00 - i1IIi
  if 66 - 66: i11iIiiIii / o0oOOo0O0Ooo - OoooooooOO / i1IIi . i11iIiiIii
 if ( OOO0o0o != None ) :
  OOO0o0o . cancel ( )
  OOO0o0o = None
  if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
  if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
  if 81 - 81: iII111i * OOooOOo - I1ii11iIi11i * Ii1I % OoOoOO00 * OoOoOO00
  if 59 - 59: iIii1I11I1II1
  if 7 - 7: OOooOOo * I1IiiI / o0oOOo0O0Ooo * i11iIiiIii
 if ( Oo0o != None ) :
  Oo0o . cancel ( )
  if 84 - 84: OOooOOo . iII111i
 Oo0o = threading . Timer ( o000o0o00o0Oo ,
 oo000OO00Oo , [ i1 ] )
 Oo0o . start ( )
 if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
 return
 if 21 - 21: oO0o / OoooooooOO
 if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
 if 87 - 87: I1Ii111 * i1IIi / I1ii11iIi11i
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo - OoooooooOO % OOooOOo * OoOoOO00
 if 69 - 69: i1IIi
 if 59 - 59: II111iiii - o0oOOo0O0Ooo
 if 24 - 24: Oo0Ooo - i1IIi + I11i
 if 38 - 38: OoooooooOO / I1ii11iIi11i . O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
 if 96 - 96: iII111i
 if 18 - 18: iII111i * I11i - Ii1I
 if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
def oOo00OooO0oO ( lisp_sockets , entries ) :
 iI1iii = len ( entries )
 if ( iI1iii == 0 ) : return
 if 87 - 87: I1ii11iIi11i / OoooooooOO - Oo0Ooo % OoOoOO00 % IiII % Oo0Ooo
 Ii1 = None
 if ( entries [ 0 ] [ 1 ] . find ( ":" ) != - 1 ) : Ii1 = lisp . LISP_AFI_IPV6
 if ( entries [ 0 ] [ 1 ] . find ( "." ) != - 1 ) : Ii1 = lisp . LISP_AFI_IPV4
 if ( entries [ 0 ] [ 1 ] . find ( "-" ) != - 1 ) : Ii1 = lisp . LISP_AFI_MAC
 if ( Ii1 == None ) :
  lisp . lprint ( "lisp_send_multicast_map_register() invalid group address" )
  return
  if 34 - 34: iII111i - OoooooooOO . I1IiiI / II111iiii
  if 27 - 27: OoO0O00 / Oo0Ooo * ooOoO0o - OoO0O00
  if 19 - 19: I11i
  if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
  if 27 - 27: OOooOOo
  if 89 - 89: II111iiii / oO0o
  if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
  if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
  if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 IIiIiiiIIIIi1 = [ ]
 for o0OOOOooo , iIi11 , O00O0 in entries :
  if 19 - 19: oO0o - II111iiii
  IIiIiiiIIIIi1 . append ( [ iIi11 , O00O0 ] )
  if 63 - 63: i11iIiiIii . o0oOOo0O0Ooo
  if 19 - 19: II111iiii
 oo0oOoo = lisp . lisp_decent_pull_xtr_configured ( )
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
 Iiiiii111i1ii = { }
 entries = [ ]
 for iIi11 , O00O0 in IIiIiiiIIIIi1 :
  Ii1iIi111i1i1 = lisp . lisp_lookup_group ( iIi11 )
  if ( Ii1iIi111i1i1 == None ) :
   lisp . lprint ( "No group-mapping for {}, could be underlay group" . format ( iIi11 ) )
   if 45 - 45: OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * I1IiiI % I1IiiI
   continue
   if 63 - 63: I1Ii111
   if 53 - 53: OoooooooOO - IiII
  lisp . lprint ( "Use group-mapping '{}' {} for group {}" . format ( Ii1iIi111i1i1 . group_name , Ii1iIi111i1i1 . group_prefix . print_prefix ( ) , iIi11 ) )
  if 87 - 87: oO0o . I1IiiI
  if 17 - 17: Ii1I . i11iIiiIii
  O0o = Ii1iIi111i1i1 . group_prefix . instance_id
  OO0OO0O00oO0 = Ii1iIi111i1i1 . use_ms_name
  IIIiiiI = Ii1iIi111i1i1 . rle_address
  if 94 - 94: O0 - I11i - iIii1I11I1II1 % ooOoO0o / Ii1I % iII111i
  if 44 - 44: Oo0Ooo % iIii1I11I1II1
  if 90 - 90: II111iiii + OoooooooOO % OoooooooOO
  if 35 - 35: iII111i / I1ii11iIi11i * OoooooooOO . II111iiii / Oo0Ooo
  if 1 - 1: OoooooooOO + IiII . i1IIi % I11i
  if 66 - 66: o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
  I1 = OO0OO0O00oO0
  if ( oo0oOoo ) :
   I1 = lisp . lisp_get_decent_dns_name_from_str ( O0o , iIi11 )
   Iiiiii111i1ii [ I1 ] = [ b"" , 0 ]
   if 13 - 13: OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - Oo0Ooo / oO0o
   if 8 - 8: OoOoOO00 / O0 * O0 % I1Ii111 - Oo0Ooo + I11i
  if ( len ( Ii1iIi111i1i1 . sources ) == 0 ) :
   entries . append ( [ "0.0.0.0" , iIi11 , O0o , I1 , IIIiiiI , O00O0 ] )
   continue
   if 83 - 83: O0 . I1IiiI
  for o0O00Oo0 in Ii1iIi111i1i1 . sources :
   Iiiiii111i1ii [ I1 ] = [ b"" , 0 ]
   entries . append ( [ o0O00Oo0 , iIi11 , O0o , I1 , IIIiiiI , O00O0 ] )
   if 95 - 95: I11i . OoooooooOO - i1IIi - OoooooooOO - OoO0O00 % iIii1I11I1II1
   if 64 - 64: OOooOOo + OoooooooOO * OoooooooOO
   if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
 iI1iii = len ( entries )
 if ( iI1iii == 0 ) : return
 if 100 - 100: Ii1I + OoO0O00
 lisp . lprint ( "Build Map-Register for {} multicast entries" . format ( iI1iii ) )
 if 73 - 73: i1IIi - I1Ii111 % ooOoO0o / OoO0O00
 if 40 - 40: I1ii11iIi11i * ooOoO0o - I1IiiI / IiII / i11iIiiIii
 if 83 - 83: I1ii11iIi11i / I1Ii111 - i11iIiiIii . iIii1I11I1II1 + Oo0Ooo
 if 59 - 59: O0 % Oo0Ooo
 if 92 - 92: Ii1I % iII111i / I1ii11iIi11i % I1ii11iIi11i * I1IiiI
 if 74 - 74: O0 . I1IiiI % OoO0O00 % IiII
 oOo0OooOo = lisp . lisp_rle_node ( )
 oOo0OooOo . level = 128
 o0 = lisp . lisp_get_any_translated_rloc ( )
 IIIiiiI = lisp . lisp_rle ( "" )
 IIIiiiI . rle_nodes . append ( oOo0OooOo )
 IIIiiiI . build_rle_forwarding_list ( )
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if ( oo0oOoo == False ) :
  for Oo00OOOOO in list ( lisp . lisp_map_servers_list . values ( ) ) :
   Iiiiii111i1ii [ Oo00OOOOO . ms_name ] = [ b"" , 0 ]
   if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
   if 53 - 53: I11i + iIii1I11I1II1
   if 70 - 70: I1ii11iIi11i
   if 67 - 67: OoooooooOO
   if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
   if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 oOOO = 0
 for OOOOoO00o0O in list ( lisp . lisp_rtr_list . values ( ) ) :
  if ( OOOOoO00o0O == None ) : continue
  oOOO += 1
  if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
  if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
  if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
  if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
  if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
 Ii1i1 = b""
 for o0OOOOooo , iIi11 , O0o , ii1iI , OOO000 , O00O0 in entries :
  if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
  if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
  if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
  if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
  if ( ii1iI not in Iiiiii111i1ii ) : continue
  if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
  i1iIiIIi = lisp . lisp_eid_record ( )
  i1iIiIIi . rloc_count = 1 + oOOO
  i1iIiIIi . authoritative = True
  i1iIiIIi . record_ttl = lisp . LISP_REGISTER_TTL if O00O0 else 0
  i1iIiIIi . eid = lisp . lisp_address ( Ii1 , o0OOOOooo , 0 , O0o )
  if ( i1iIiIIi . eid . address == 0 ) : i1iIiIIi . eid . mask_len = 0
  i1iIiIIi . group = lisp . lisp_address ( Ii1 , iIi11 , 0 , O0o )
  if ( i1iIiIIi . group . is_mac_broadcast ( ) and i1iIiIIi . eid . address == 0 ) : i1iIiIIi . eid . mask_len = 0
  if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
  if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
  ooo = ""
  OO0OO0O00oO0 = ""
  if ( lisp . lisp_decent_pull_xtr_configured ( ) ) :
   ooo = lisp . lisp_get_decent_index ( i1iIiIIi . group )
   ooo = lisp . bold ( str ( ooo ) , False )
   ooo = "with decent-index {}" . format ( ooo )
  else :
   ooo = "for ms-name '{}'" . format ( ii1iI )
   if 62 - 62: o0oOOo0O0Ooo
   if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
  IiIi1111ii = lisp . green ( i1iIiIIi . print_eid_tuple ( ) , False )
  lisp . lprint ( "  EID-prefix {} {}{}" . format ( IiIi1111ii , OO0OO0O00oO0 ,
 ooo ) )
  if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  Ii1i1 += i1iIiIIi . encode ( )
  i1iIiIIi . print_record ( "  " , False )
  Iiiiii111i1ii [ ii1iI ] [ 1 ] += 1
  if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
  if 87 - 87: OoO0O00 % I1IiiI
  if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
  if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
  oOoO0 = lisp . lisp_rloc_record ( )
  oOoO0 . rloc_name = lisp . lisp_hostname
  if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
  if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
  if 84 - 84: i11iIiiIii * OoO0O00
  if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
  if 30 - 30: O0 + I1ii11iIi11i + II111iiii
  if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
  if ( o0 != None ) :
   oOo0OooOo . rloc . rloc . copy_address ( o0 )
  elif ( OOO000 != None ) :
   oOo0OooOo . rloc . rloc . copy_address ( OOO000 )
  else :
   OOO000 = lisp . lisp_myrlocs [ 0 ]
   oOo0OooOo . rloc . rloc . copy_address ( OOO000 )
   if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
   if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
  oOoO0 . rle = IIIiiiI
  oOoO0 . local_bit = True
  oOoO0 . reach_bit = True
  oOoO0 . priority = 255
  oOoO0 . weight = 0
  oOoO0 . mpriority = 1
  oOoO0 . mweight = 100
  Ii1i1 += oOoO0 . encode ( )
  oOoO0 . print_record ( "    " )
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  if 64 - 64: i1IIi
  if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
  if 18 - 18: OOooOOo + I1Ii111
  if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
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
   if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
   if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
   if 50 - 50: ooOoO0o + i1IIi
   if 31 - 31: Ii1I
   if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
  Iiiiii111i1ii [ ii1iI ] [ 0 ] += Ii1i1
  if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
  if 47 - 47: o0oOOo0O0Ooo
  if 66 - 66: I1IiiI - IiII
  if 33 - 33: I1IiiI / OoO0O00
  if 12 - 12: II111iiii
 I1IIIiI1I1ii1 = lisp . lisp_map_register ( )
 I1IIIiI1I1ii1 . nonce = 0xaabbccdddfdfdf00
 I1IIIiI1I1ii1 . xtr_id_present = True
 I1IIIiI1I1ii1 . proxy_reply_requested = True
 I1IIIiI1I1ii1 . map_notify_requested = False
 I1IIIiI1I1ii1 . merge_register_requested = True
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 for Oo00OOOOO in list ( lisp . lisp_map_servers_list . values ( ) ) :
  I1 = Oo00OOOOO . dns_name if oo0oOoo else Oo00OOOOO . ms_name
  if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
  if 47 - 47: iII111i
  if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
  if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
  if ( I1 not in Iiiiii111i1ii ) : continue
  if 47 - 47: oO0o % iIii1I11I1II1
  if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
  if 98 - 98: iII111i + Ii1I - OoO0O00
  if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
  I1IIIiI1I1ii1 . record_count = Iiiiii111i1ii [ I1 ] [ 1 ]
  if ( I1IIIiI1I1ii1 . record_count == 0 ) : continue
  if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
  I1IIIiI1I1ii1 . nonce += 1
  I1IIIiI1I1ii1 . alg_id = Oo00OOOOO . alg_id
  I1IIIiI1I1ii1 . alg_id = Oo00OOOOO . key_id
  I1IIIiI1I1ii1 . xtr_id = Oo00OOOOO . xtr_id
  I1IIIiI1I1ii1 . site_id = Oo00OOOOO . site_id
  I1IIIiI1I1ii1 . encrypt_bit = ( Oo00OOOOO . ekey != None )
  OoO = I1IIIiI1I1ii1 . encode ( )
  I1IIIiI1I1ii1 . print_map_register ( )
  if 38 - 38: O0 - IiII % I1Ii111
  if 64 - 64: iIii1I11I1II1
  if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
  if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
  if 6 - 6: Oo0Ooo % IiII * I11i / I1IiiI + Oo0Ooo
  i11iIIi11 = I1IIIiI1I1ii1 . encode_xtr_id ( b"" )
  OoO = OoO + Ii1i1 + i11iIIi11
  if 39 - 39: OoOoOO00 - Oo0Ooo / iII111i * OoooooooOO
  Oo00OOOOO . map_registers_multicast_sent += 1
  lisp . lisp_send_map_register ( lisp_sockets , OoO , I1IIIiI1I1ii1 , Oo00OOOOO )
  if 100 - 100: O0 . I11i . OoO0O00 + O0 * oO0o
  if 42 - 42: oO0o % OoooooooOO + o0oOOo0O0Ooo
  if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
  if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
  Oo00OOOOO . resolve_dns_name ( )
  if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
  if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
  if 52 - 52: OoO0O00 % Ii1I * II111iiii
  if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
  time . sleep ( .001 )
  if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
 return
 if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
def ii ( parms , not_used , packet ) :
 global o0oOoO00o , i1
 if 94 - 94: ooOoO0o * I11i - IiII . iIii1I11I1II1
 O000oO0O = lisp . lisp_latency_debug ( None , "ETR-decap" )
 if 93 - 93: I1Ii111 + Ii1I
 i1i1 = parms [ 0 ]
 oOOoo00O0O = parms [ 1 ]
 if 27 - 27: I1Ii111 + OoooooooOO - OoOoOO00
 if 15 - 15: oO0o / I11i * O0 . II111iiii - OoO0O00
 if 90 - 90: oO0o
 if 94 - 94: I11i / I1ii11iIi11i * I1Ii111 - OoOoOO00
 if 44 - 44: Ii1I % i11iIiiIii - iII111i * I1ii11iIi11i + Oo0Ooo * OOooOOo
 if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
 if ( lisp . lisp_is_macos ( ) == False ) :
  oOIIIiI1ii1IIi = 4 if i1i1 == "lo0" else 16
  packet = packet [ oOIIIiI1ii1IIi : : ]
 elif ( i1i1 == "en0" ) :
  packet = packet [ 14 : : ]
  if 55 - 55: iII111i - OoO0O00
  if 100 - 100: O0
  if 79 - 79: iIii1I11I1II1
  if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
  if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 ii1I111i1Ii = struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ]
 if ( ii1I111i1Ii == 2 ) :
  OOOooO0OO0o = lisp . lisp_process_igmp_packet ( packet )
  if ( OOOooO0OO0o != [ ] ) :
   oOo00OooO0oO ( i1 , OOOooO0OO0o )
   return
   if 10 - 10: Ii1I - OoOoOO00 . OoooooooOO . OOooOOo . OoO0O00 * iII111i
   if 78 - 78: oO0o / OoO0O00 - oO0o * OoooooooOO . OoOoOO00
   if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
   if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
   if 48 - 48: i11iIiiIii % oO0o
   if 29 - 29: iII111i + i11iIiiIii % I11i
 oOo00Ooo0o0 = packet
 packet , o0OOOOooo , i1IiII1i1I , iI1ii1ii1I = lisp . lisp_is_rloc_probe ( packet , i1i1 , 0 )
 if ( oOo00Ooo0o0 != packet ) :
  if ( o0OOOOooo == None ) : return
  lisp . lisp_parse_packet ( i1 , packet , o0OOOOooo , i1IiII1i1I , iI1ii1ii1I )
  return
  if 18 - 18: oO0o * oO0o % oO0o
  if 17 - 17: O0 * OoOoOO00 * I1ii11iIi11i * II111iiii * I11i % i1IIi
  if 33 - 33: I1ii11iIi11i * I1ii11iIi11i . ooOoO0o . i11iIiiIii
  if 48 - 48: o0oOOo0O0Ooo . Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
  if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
  if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
  if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if ( struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ] & 0xf0 == 0x40 ) :
  IiIi1i = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
  if ( lisp . lisp_nat_traversal and IiIi1i == lisp . LISP_DATA_PORT ) : return
  packet = lisp . lisp_reassemble ( packet )
  if ( packet == None ) : return
  if 99 - 99: OoOoOO00 . I1Ii111
  if 59 - 59: I11i / Oo0Ooo / OOooOOo / O0 / OoOoOO00 + o0oOOo0O0Ooo
 packet = lisp . lisp_packet ( packet )
 IIiI1111i1 = packet . decode ( True , o0oOoO00o , lisp . lisp_decap_stats )
 if ( IIiI1111i1 == None ) : return
 if 46 - 46: IiII
 if 29 - 29: II111iiii . OoOoOO00 % o0oOOo0O0Ooo * II111iiii - o0oOOo0O0Ooo * iIii1I11I1II1
 if 35 - 35: II111iiii - IiII . i1IIi
 if 95 - 95: I1IiiI + I1IiiI - OOooOOo - iII111i
 packet . print_packet ( "Receive" , True )
 if 45 - 45: Ii1I . OoooooooOO
 if 27 - 27: Ii1I * Oo0Ooo . OoOoOO00
 if 17 - 17: II111iiii % iII111i * OOooOOo % i1IIi . I1IiiI . iIii1I11I1II1
 if 27 - 27: i11iIiiIii - I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if 50 - 50: OoOoOO00
 if 33 - 33: I11i
 if 98 - 98: OoOoOO00 % II111iiii
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
  o0OOOOooo = packet . inner_source . print_address_no_iid ( )
  packet . strip_outer_headers ( )
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , o0OOOOooo , IiIi1i )
  lisp . lisp_ipc ( packet , o0oOoO00o , "lisp-ms" )
  return
  if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
  if 68 - 68: o0oOOo0O0Ooo
  if 20 - 20: I1Ii111 - I1Ii111
  if 37 - 37: IiII
  if 37 - 37: Oo0Ooo / IiII * O0
  if 73 - 73: iII111i * iII111i / ooOoO0o
  if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
  if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
  if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
  if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  O0oOO0o = packet . packet [ 36 : : ]
  iiiiI1IiI1I1 = O0oOO0o
  iI1ii1ii1I = - 1
  if ( lisp . lisp_is_rloc_probe_request ( iiiiI1IiI1I1 [ 0 : 1 ] ) ) :
   iI1ii1ii1I = struct . unpack ( "B" , O0oOO0o [ 8 : 9 ] ) [ 0 ] - 1
   if 19 - 19: Ii1I
  o0OOOOooo = packet . outer_source . print_address_no_iid ( )
  lisp . lisp_parse_packet ( i1 , iiiiI1IiI1I1 , o0OOOOooo , 0 , iI1ii1ii1I )
  return
  if 55 - 55: OOooOOo % OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
  if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
  if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
  if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
  if 71 - 71: iII111i
  if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
  if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
  if 58 - 58: I1ii11iIi11i
  if 2 - 2: II111iiii / I1Ii111
  if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 22 - 22: ooOoO0o . iIii1I11I1II1
 if 12 - 12: Ii1I
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 packet . strip_outer_headers ( )
 IiIIiiI = lisp . bold ( "Forward" , False )
 if 60 - 60: I1Ii111
 if 98 - 98: ooOoO0o
 if 34 - 34: iIii1I11I1II1 * I11i * I11i / I1ii11iIi11i
 if 28 - 28: OoO0O00 - oO0o + OoOoOO00 + Ii1I / iIii1I11I1II1
 iiiii11I1 = False
 Ii1OOOo = packet . inner_dest . is_mac ( )
 if ( Ii1OOOo ) :
  packet . packet = lisp . lisp_mac_input ( packet . packet )
  if ( packet . packet == None ) : return
  IiIIiiI = lisp . bold ( "Bridge" , False )
 elif ( packet . inner_version == 4 ) :
  iiiii11I1 , packet . packet = lisp . lisp_ipv4_input ( packet . packet )
  if ( packet . packet == None ) : return
  if ( iiiii11I1 ) :
   OOOooO0OO0o = lisp . lisp_process_igmp_packet ( packet . packet )
   if ( OOOooO0OO0o != [ ] ) :
    oOo00OooO0oO ( i1 , OOOooO0OO0o )
    return
    if 35 - 35: ooOoO0o - OoO0O00 . Oo0Ooo * Oo0Ooo / i11iIiiIii + I1ii11iIi11i
    if 87 - 87: OoOoOO00 % iIii1I11I1II1
  packet . inner_ttl = packet . outer_ttl
 elif ( packet . inner_version == 6 ) :
  packet . packet = lisp . lisp_ipv6_input ( packet )
  if ( packet . packet == None ) : return
  packet . inner_ttl = packet . outer_ttl
 else :
  lisp . dprint ( "Cannot parse inner packet header" )
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
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  i1iIi = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( i1iIi ) :
   i1iIi . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
   return
   if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 else :
  if ( lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False ) ) :
   lisp . dprint ( "Discard echoed multicast packet (through NAT)" )
   return
   if 84 - 84: i1IIi
   if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
   if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
   if 81 - 81: IiII / OoOoOO00 * IiII . O0
   if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
   if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
   if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
   if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 61 - 61: I1Ii111 - Ii1I % I1ii11iIi11i / ooOoO0o / iII111i + iIii1I11I1II1
  if 87 - 87: I1Ii111 + ooOoO0o + O0 / i1IIi % IiII / I1Ii111
  if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
  if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
  if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 oO = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( IiIIiiI , lisp . green ( oO , False ) ,
 # OoO0O00 / IiII / IiII * I1Ii111 / I1Ii111
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 65 - 65: ooOoO0o * I11i / OoO0O00 / OoO0O00
 if 27 - 27: Oo0Ooo
 if 95 - 95: I11i
 if 44 - 44: OOooOOo + I11i . IiII / II111iiii % iIii1I11I1II1 + IiII
 if 61 - 61: OOooOOo / OoO0O00 + II111iiii . oO0o / Oo0Ooo * OOooOOo
 if ( Ii1OOOo ) :
  packet . bridge_l2_packet ( packet . inner_dest , i1iIi )
  return
  if 46 - 46: iIii1I11I1II1
  if 33 - 33: I11i % I11i % O0 / I1IiiI . i1IIi
  if 91 - 91: ooOoO0o * I11i - II111iiii . I1IiiI - Oo0Ooo + ooOoO0o
  if 56 - 56: o0oOOo0O0Ooo / IiII * I1IiiI . o0oOOo0O0Ooo
  if 15 - 15: i11iIiiIii
  if 13 - 13: I11i * II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( i1111 , i11 )
  return
  if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
  if 71 - 71: I1Ii111 * Oo0Ooo . I11i
  if 49 - 49: IiII * O0 . IiII
  if 19 - 19: II111iiii - IiII
  if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 o0OO00oo0O = packet . get_raw_socket ( )
 if ( o0OO00oo0O == None ) : o0OO00oo0O = oOOoo00O0O
 if 46 - 46: i11iIiiIii - OOooOOo * I1IiiI * I11i % I1ii11iIi11i * i1IIi
 if 5 - 5: O0 / ooOoO0o . Oo0Ooo + OoooooooOO
 if 97 - 97: IiII . Ii1I . Ii1I / iIii1I11I1II1 - OoO0O00 + iII111i
 if 32 - 32: OOooOOo . o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
 packet . send_packet ( o0OO00oo0O , packet . inner_dest )
 if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
 lisp . lisp_latency_debug ( O000oO0O , "ETR-decap" )
 return
 if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
 if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
 if 26 - 26: o0oOOo0O0Ooo
 if 12 - 12: OoooooooOO / O0 + II111iiii * I1ii11iIi11i
 if 46 - 46: II111iiii - IiII * OoooooooOO / oO0o % IiII
 if 11 - 11: iIii1I11I1II1 . OoOoOO00 / IiII % ooOoO0o
 if 61 - 61: ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
def OOoOOOO00 ( lisp_raw_socket , packet , source ) :
 global o0oOoO00o , i1
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 O000oO0O = lisp . lisp_latency_debug ( None , "ETR-NAT-decap" )
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 Iii = packet
 packet = lisp . lisp_packet ( packet [ 8 : : ] )
 if ( packet . lisp_header . decode ( Iii ) == False ) : return
 if 35 - 35: IiII . OoooooooOO / OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 packet . outer_source = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , source ,
 lisp . LISP_IPV4_HOST_MASK_LEN , 0 )
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 IIiI1111i1 = packet . decode ( False , o0oOoO00o ,
 lisp . lisp_decap_stats )
 if ( IIiI1111i1 == None ) : return
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if ( lisp . lisp_flow_logging ) : packet . log_flow ( False )
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 packet . print_packet ( "Kernel-decap" , False )
 lisp . dprint ( packet . lisp_header . print_header ( " " ) )
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if ( lisp . lisp_decent_push_configured and
 packet . inner_dest . is_multicast_address ( ) and packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
  IiIi1i = packet . udp_sport
  packet = packet . packet [ 28 : : ]
  packet = lisp . lisp_packet_ipc ( packet , source , IiIi1i )
  lisp . lisp_ipc ( packet , o0oOoO00o , "lisp-ms" )
  return
  if 41 - 41: I1ii11iIi11i
  if 5 - 5: Oo0Ooo
  if 100 - 100: Ii1I + iIii1I11I1II1
  if 59 - 59: IiII
  if 89 - 89: OoOoOO00 % iIii1I11I1II1
  if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
  if 45 - 45: I1IiiI * OOooOOo % OoO0O00
  if 24 - 24: ooOoO0o - I11i * oO0o
  if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if ( packet . lisp_header . get_instance_id ( ) == 0xffffff ) :
  O0oOO0o = packet . packet
  iiiiI1IiI1I1 = O0oOO0o [ 28 : : ]
  iI1ii1ii1I = - 1
  if ( lisp . lisp_is_rloc_probe_request ( iiiiI1IiI1I1 [ 0 : 1 ] ) ) :
   iI1ii1ii1I = struct . unpack ( "B" , O0oOO0o [ 8 : 9 ] ) [ 0 ] - 1
   if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
   if 79 - 79: IiII % OoO0O00
   if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
   if 32 - 32: O0 . OoooooooOO
   if 15 - 15: I1IiiI . OoO0O00
   if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
   if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
  if ( lisp . lisp_is_rloc_probe_reply ( iiiiI1IiI1I1 [ 0 : 1 ] ) ) :
   IiIi1i = socket . ntohs ( struct . unpack ( "H" , packet . packet [ 20 : 22 ] ) [ 0 ] )
   if ( IiIi1i == lisp . LISP_DATA_PORT ) :
    packet = packet . packet [ 28 : : ]
    packet = lisp . lisp_packet_ipc ( packet , source , IiIi1i )
    lisp . lisp_ipc ( packet , o0oOoO00o , "lisp-itr" )
    return
    if 47 - 47: OoO0O00 + IiII / II111iiii
    if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
  lisp . lisp_parse_packet ( i1 , iiiiI1IiI1I1 , source , 0 , iI1ii1ii1I )
  return
  if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
  if 94 - 94: iII111i - Oo0Ooo + oO0o
  if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
  if 56 - 56: oO0o + ooOoO0o
  if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
  if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . dprint ( "Drop packet, external data-plane active" )
  return
  if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
  if 36 - 36: OOooOOo % i11iIiiIii
  if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
  if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
  if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 lisp . lisp_decap_stats [ "good-packets" ] . increment ( len ( packet . packet ) )
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if ( packet . inner_dest . is_multicast_address ( ) == False ) :
  i1iIi = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( i1iIi ) :
   i1iIi . increment_decap_stats ( packet )
  else :
   lisp . dprint ( "No database-mapping found for EID {}" . format ( lisp . green ( packet . inner_dest . print_address ( ) , False ) ) )
   if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
   if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
   if 79 - 79: oO0o - II111iiii
 else :
  if ( lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False ) ) :
   lisp . dprint ( "Discard echoed multicast packet" )
   return
   if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
   if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
   if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
   if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
   if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
   if 12 - 12: I1ii11iIi11i / Ii1I
   if 5 - 5: OoooooooOO
   if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
 if ( packet . is_trace ( ) ) :
  if ( lisp . lisp_trace_append ( packet , ed = "decap" ) == False ) : return
  if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
  if 93 - 93: Oo0Ooo / I1ii11iIi11i + i1IIi * oO0o . OoooooooOO
 oO = "{} -> {}" . format ( packet . inner_source . print_address ( ) ,
 packet . inner_dest . print_address ( ) )
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 lisp . dprint ( "{} packet for EIDs {}: {} ..." . format ( lisp . bold ( "NAT-Forward" , False ) , lisp . green ( oO , False ) ,
 # O0 - Ii1I - oO0o
 lisp . lisp_format_packet ( packet . packet [ 0 : 60 ] ) ) )
 if 51 - 51: I1IiiI + OOooOOo + I11i
 if 50 - 50: I1Ii111 + I1ii11iIi11i
 if 4 - 4: IiII / Oo0Ooo
 if 31 - 31: I1Ii111 - I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - oO0o
 if 43 - 43: iII111i + Oo0Ooo / OoooooooOO
 if ( packet . inner_version == 6 ) :
  packet . send_l2_packet ( i1111 , i11 )
  return
  if 24 - 24: O0 + o0oOOo0O0Ooo * Ii1I - I1Ii111
  if 10 - 10: i11iIiiIii
  if 21 - 21: I1IiiI / iII111i
  if 69 - 69: ooOoO0o % ooOoO0o
  if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 o0OO00oo0O = packet . get_raw_socket ( )
 if ( o0OO00oo0O == None ) : o0OO00oo0O = lisp_raw_socket
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
 packet . send_packet ( o0OO00oo0O , packet . inner_dest )
 if 33 - 33: Ii1I
 lisp . lisp_latency_debug ( O000oO0O , "ETR-NAT-decap" )
 return
 if 93 - 93: ooOoO0o
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 if 19 - 19: I1ii11iIi11i
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if 66 - 66: O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
def iiI ( group , joinleave ) :
 Ii1iIi111i1i1 = lisp . lisp_lookup_group ( group )
 if ( Ii1iIi111i1i1 == None ) : return
 if 81 - 81: IiII * I1ii11iIi11i + II111iiii % IiII
 IiI1ii11I1 = [ ]
 for o0O00Oo0 in Ii1iIi111i1i1 . sources :
  IiI1ii11I1 . append ( [ o0O00Oo0 , group , joinleave ] )
  if 19 - 19: I1Ii111 + IiII / oO0o / II111iiii
  if 92 - 92: i1IIi % ooOoO0o + ooOoO0o - iIii1I11I1II1 . Ii1I
 oOo00OooO0oO ( i1 , IiI1ii11I1 )
 return
 if 33 - 33: o0oOOo0O0Ooo / O0 + OOooOOo
 if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
 if 92 - 92: OoOoOO00 % O0
 if 55 - 55: iIii1I11I1II1 * iII111i
 if 85 - 85: iIii1I11I1II1 . II111iiii
 if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
 if 22 - 22: OOooOOo
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
 if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 if 94 - 94: i1IIi
 if 36 - 36: I1IiiI + Oo0Ooo
 if 46 - 46: iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
def o0oO0o00O ( ) :
 global i1
 if 6 - 6: OoooooooOO / i11iIiiIii / I1Ii111
 lisp . lisp_set_exception ( )
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 i1Ii11II = socket . htonl
 i1iiiiI11ii = [ i1Ii11II ( 0x46000020 ) , i1Ii11II ( 0x9fe60000 ) , i1Ii11II ( 0x0102d7cc ) ,
 i1Ii11II ( 0x0acfc15a ) , i1Ii11II ( 0xe00000fb ) , i1Ii11II ( 0x94040000 ) ]
 if 73 - 73: i1IIi % OoooooooOO
 OoO = b""
 for iIi1i1I in i1iiiiI11ii : OoO += struct . pack ( "I" , iIi1i1I )
 if 17 - 17: I11i - iII111i % Ii1I
 if 2 - 2: Ii1I * I1ii11iIi11i * OoooooooOO
 if 73 - 73: OoOoOO00 + Oo0Ooo
 if 61 - 61: iIii1I11I1II1
 if 47 - 47: OoooooooOO
 while ( True ) :
  II111IIIII = getoutput ( "ls join-*" ) . replace ( "join-" , "" )
  II111IIIII = II111IIIII . split ( "\n" )
  if 4 - 4: I1ii11iIi11i + OoO0O00 / I1Ii111 / o0oOOo0O0Ooo % OOooOOo + OOooOOo
  for iIi11 in II111IIIII :
   if ( lisp . lisp_valid_address_format ( "address" , iIi11 ) == False ) :
    continue
    if 66 - 66: i1IIi % iII111i . OOooOOo - oO0o % OoOoOO00 / OOooOOo
    if 26 - 26: iII111i * Ii1I . I1Ii111 - Oo0Ooo
   OoO0oo0O = ( iIi11 . find ( ":" ) != - 1 )
   if 39 - 39: IiII + I11i
   if 9 - 9: I1IiiI % I11i . Oo0Ooo * I1IiiI
   if 99 - 99: O0 . o0oOOo0O0Ooo % I11i - Oo0Ooo / I11i
   if 20 - 20: OoOoOO00 * iII111i
   i1i1I1iiIiIII = os . path . exists ( "leave-{}" . format ( iIi11 ) )
   lisp . lprint ( "Internal {} group {}" . format ( "leaving" if i1i1I1iiIiIII else "joining" , iIi11 ) )
   if 68 - 68: O0
   if 76 - 76: I1ii11iIi11i
   if 99 - 99: o0oOOo0O0Ooo
   if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
   if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
   if ( OoO0oo0O ) :
    if ( iIi11 . lower ( ) . find ( "ff02:" ) != - 1 ) :
     lisp . lprint ( "Suppress registration for link-local groups" )
     continue
     if 89 - 89: oO0o
    iiI ( iIi11 , ( i1i1I1iiIiIII == False ) )
   else :
    o0OOOOOo00 = OoO
    if ( i1i1I1iiIiIII ) :
     o0OOOOOo00 += struct . pack ( "I" , i1Ii11II ( 0x17000000 ) )
    else :
     o0OOOOOo00 += struct . pack ( "I" , i1Ii11II ( 0x16000000 ) )
     if 82 - 82: Oo0Ooo
     if 5 - 5: OoO0O00 / OoO0O00 - O0 - I1Ii111 + I1Ii111
    O0oooOO0Oo0o = iIi11 . split ( "." )
    oo00oO0o = int ( O0oooOO0Oo0o [ 0 ] ) << 24
    oo00oO0o += int ( O0oooOO0Oo0o [ 1 ] ) << 16
    oo00oO0o += int ( O0oooOO0Oo0o [ 2 ] ) << 8
    oo00oO0o += int ( O0oooOO0Oo0o [ 3 ] )
    o0OOOOOo00 += struct . pack ( "I" , i1Ii11II ( oo00oO0o ) )
    IiI1ii11I1 = lisp . lisp_process_igmp_packet ( o0OOOOOo00 )
    if ( IiI1ii11I1 != [ ] ) :
     oOo00OooO0oO ( i1 , IiI1ii11I1 )
     if 68 - 68: OoooooooOO * iIii1I11I1II1 + i1IIi - i1IIi
    time . sleep ( .100 )
    if 76 - 76: OoO0O00 . OoooooooOO % I1Ii111 * Ii1I
    if 23 - 23: IiII + iIii1I11I1II1
  time . sleep ( 10 )
  if 14 - 14: O0 % IiII % Ii1I * oO0o
 return
 if 65 - 65: I11i % oO0o + I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 / O0 . I1Ii111 % iIii1I11I1II1 % Oo0Ooo
 if 86 - 86: i11iIiiIii - o0oOOo0O0Ooo . ooOoO0o * Oo0Ooo / Ii1I % o0oOOo0O0Ooo
 if 61 - 61: o0oOOo0O0Ooo + OoOoOO00
 if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
 if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
 if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
 if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
 if 46 - 46: iIii1I11I1II1
def oo0oO00o0O00o ( ) :
 lisp . lisp_set_exception ( )
 if ( lisp . lisp_myrlocs [ 0 ] == None ) : return
 if 98 - 98: ooOoO0o . OOooOOo
 if 60 - 60: OoO0O00 - i1IIi . OOooOOo + OOooOOo * OOooOOo + Ii1I
 if 66 - 66: OOooOOo * OOooOOo / iIii1I11I1II1 + OoOoOO00 . OOooOOo
 if 51 - 51: I1ii11iIi11i
 if 58 - 58: Ii1I % OoooooooOO
 IIii11i = lisp . lisp_get_all_multicast_rles ( )
 if 82 - 82: I1ii11iIi11i
 if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
 if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
 if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
 i1i1 = "en0" if lisp . lisp_is_macos ( ) else "any"
 if 21 - 21: iII111i
 if 24 - 24: iII111i / ooOoO0o
 ooOooO = "(proto 2) or "
 if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
 ooOooO += "((dst host "
 for I1iII1IIi1IiI in lisp . lisp_get_all_addresses ( ) + IIii11i :
  ooOooO += "{} or " . format ( I1iII1IIi1IiI )
  if 8 - 8: iIii1I11I1II1
 ooOooO = ooOooO [ 0 : - 4 ]
 ooOooO += ") and ((udp dst port 4341 or 8472 or 4789) or "
 ooOooO += "(udp src port 4341) or "
 ooOooO += "(udp dst port 4342) or "
 ooOooO += "(proto 17 and (ip[6]&0xe0 == 0x20 or " + "(ip[6]&0xe0 == 0 and ip[7] != 0)))))"
 if 55 - 55: oO0o
 if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
 lisp . lprint ( "Capturing packets for: '{}' on device {}" . format ( ooOooO ,
 i1i1 ) )
 if 97 - 97: I1Ii111 . I11i / I1IiiI
 if 83 - 83: I11i - I1ii11iIi11i * oO0o
 if 90 - 90: Oo0Ooo * I1IiiI
 if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
 if ( lisp . lisp_is_python2 ( ) ) :
  import pcappy
  I1iI1i11IiI11 = pcappy . open_live ( i1i1 , 1600 , 0 , 100 )
  I1iI1i11IiI11 . filter = ooOooO
  I1iI1i11IiI11 . loop ( - 1 , ii , [ i1i1 , oOOoo00O0O ] )
  if 82 - 82: I1Ii111 * OoO0O00
 if ( lisp . lisp_is_python3 ( ) ) :
  import pcapy
  I1iI1i11IiI11 = pcapy . open_live ( i1i1 , 1600 , 0 , 100 )
  I1iI1i11IiI11 . setfilter ( ooOooO )
  while ( True ) :
   i1o0 , OoO = I1iI1i11IiI11 . next ( )
   if ( len ( OoO ) == 0 ) : continue
   ii ( [ i1i1 , oOOoo00O0O ] , None , OoO )
   if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
   if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 return
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 if 36 - 36: IiII
def iIi ( ) :
 global o0oOoO00o
 global I1Ii11I1Ii1i
 global i1
 global oOOoo00O0O
 global i1111
 global i11
 if 52 - 52: iIii1I11I1II1
 lisp . lisp_i_am ( "etr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "ETR starting up" )
 if 49 - 49: OOooOOo
 if 23 - 23: OoO0O00 / iII111i / iIii1I11I1II1
 if 44 - 44: Oo0Ooo . Oo0Ooo + OoooooooOO * i11iIiiIii / I11i + I1Ii111
 if 17 - 17: OOooOOo + II111iiii
 lisp . lisp_get_local_interfaces ( )
 lisp . lisp_get_local_macs ( )
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 43 - 43: I11i % Ii1I / o0oOOo0O0Ooo * I1Ii111
 if 85 - 85: iIii1I11I1II1 . OoooooooOO . o0oOOo0O0Ooo
 if 77 - 77: I1IiiI % ooOoO0o
 if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
 if 52 - 52: IiII % ooOoO0o
 if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
 if 23 - 23: i11iIiiIii
 if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
 if 65 - 65: II111iiii / Oo0Ooo
 if 42 - 42: i11iIiiIii . O0
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
 if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
 if 92 - 92: I11i / O0 * I1IiiI - I11i
 if 99 - 99: i11iIiiIii % OoooooooOO
 o0O00Oo0 = lisp . lisp_open_listen_socket ( "0.0.0.0" , str ( Ooo ) )
 o0O00Oo0 . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_TTL , 32 )
 I1Ii11I1Ii1i = o0O00Oo0
 if 56 - 56: IiII * I1Ii111
 if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
 if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
 if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
 o0oOoO00o = lisp . lisp_open_listen_socket ( "" , "lisp-etr" )
 if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
 i1 [ 0 ] = I1Ii11I1Ii1i
 i1 [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 i1 [ 2 ] = o0oOoO00o
 if 56 - 56: i1IIi . i11iIiiIii
 if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
 if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
 if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
 if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
 if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
 if 10 - 10: IiII / OoooooooOO
 if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
 if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
 oOOoo00O0O = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 oOOoo00O0O . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 i1 . append ( oOOoo00O0O )
 if 25 - 25: iIii1I11I1II1
 if 63 - 63: ooOoO0o
 if 96 - 96: I11i
 if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
 if 63 - 63: iII111i
 if 11 - 11: iII111i - iIii1I11I1II1
 if 92 - 92: OoO0O00
 if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
 if 12 - 12: ooOoO0o
 if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
 if 60 - 60: OOooOOo . iII111i / iIii1I11I1II1 + OOooOOo * I1Ii111
 if 82 - 82: i11iIiiIii . iIii1I11I1II1 * I1IiiI - I11i + Ii1I
 if 48 - 48: I1ii11iIi11i
 if 96 - 96: ooOoO0o . OoooooooOO
 if 39 - 39: OOooOOo + OoO0O00
 if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
 if 71 - 71: ooOoO0o . i11iIiiIii
 if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
 if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
 if 67 - 67: iII111i
 if 88 - 88: Oo0Ooo
 if ( pytun != None ) :
  i11 = b'\x00\x00\x86\xdd'
  i1i1 = "lispers.net"
  try :
   i1111 = pytun . TunTunnel ( )
   i1ii111i = i1111 . name
   lisp . lprint ( "Rename tunnel name from '{}' to '{}'" . format ( i1ii111i , i1i1 ) )
   os . system ( "ip link set {} name {} up" . format ( i1ii111i , i1i1 ) )
  except :
   lisp . lprint ( "Cannot create tuntap interface" )
   if 42 - 42: OOooOOo % OoooooooOO / IiII
   if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
   if 71 - 71: ooOoO0o . ooOoO0o - iIii1I11I1II1
   if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
   if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
   if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
 threading . Thread ( target = oo0oO00o0O00o , args = [ ] ) . start ( )
 if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
 if 29 - 29: Ii1I / ooOoO0o % I11i
 if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 threading . Thread ( target = o0oO0o00O , args = [ ] ) . start ( )
 if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
 global Oo
 Oo = threading . Timer ( 60 , OOO )
 Oo . start ( )
 if 79 - 79: O0
 return ( True )
 if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
 if 15 - 15: I1ii11iIi11i
 if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
 if 88 - 88: oO0o - i1IIi % i11iIiiIii % II111iiii * OoooooooOO
 if 40 - 40: Oo0Ooo
 if 47 - 47: OoOoOO00
 if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
def oooOO ( ) :
 global Oo0o
 global Ii1iI
 global Oo
 if 33 - 33: oO0o
 if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
 if 41 - 41: IiII % o0oOOo0O0Ooo
 if 67 - 67: O0 % I1Ii111
 if ( Oo0o ) : Oo0o . cancel ( )
 if ( Ii1iI ) : Ii1iI . cancel ( )
 if ( Oo ) : Oo . cancel ( )
 if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
 if 39 - 39: Ii1I
 if 60 - 60: OOooOOo
 if 62 - 62: I1Ii111 * I11i
 lisp . lisp_close_socket ( i1 [ 0 ] , "" )
 lisp . lisp_close_socket ( i1 [ 1 ] , "" )
 lisp . lisp_close_socket ( o0oOoO00o , "lisp-etr" )
 return
 if 74 - 74: OoOoOO00 . iIii1I11I1II1
 if 87 - 87: ooOoO0o
 if 41 - 41: OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
 if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
 if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
 if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
 if 44 - 44: I1Ii111 - IiII
 if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
 if 59 - 59: II111iiii
 if 43 - 43: Oo0Ooo + OoooooooOO
 if 47 - 47: ooOoO0o
def o00oOoo0o00 ( ipc ) :
 ipc = ipc . split ( "%" )
 IiIi1111ii = ipc [ 1 ]
 iIiiI11II11i = ipc [ 2 ]
 if ( iIiiI11II11i == "None" ) : iIiiI11II11i = None
 if 98 - 98: iII111i - iII111i
 oOIIi1iiii1iI = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 oOIIi1iiii1iI . store_address ( IiIi1111ii )
 if 58 - 58: oO0o
 if 98 - 98: o0oOOo0O0Ooo * OoO0O00
 if 10 - 10: oO0o - iII111i % II111iiii - I1Ii111 - i1IIi
 if 10 - 10: I1ii11iIi11i - I11i . I1Ii111
 i1iIi = lisp . lisp_db_for_lookups . lookup_cache ( oOIIi1iiii1iI , False )
 if ( i1iIi == None or i1iIi . dynamic_eid_configured ( ) == False ) :
  lisp . lprint ( "ITR/ETR dynamic-EID configuration out of sync for {}" . format ( lisp . green ( IiIi1111ii , False ) ) )
  if 8 - 8: iIii1I11I1II1 % oO0o + Oo0Ooo
  return
  if 24 - 24: o0oOOo0O0Ooo / Ii1I / Ii1I % II111iiii - oO0o * oO0o
  if 58 - 58: OoOoOO00
  if 60 - 60: II111iiii
  if 90 - 90: OoOoOO00
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  if 18 - 18: OoooooooOO
 iIi1II = None
 if ( IiIi1111ii in i1iIi . dynamic_eids ) : iIi1II = i1iIi . dynamic_eids [ IiIi1111ii ]
 if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
 if ( iIi1II == None and iIiiI11II11i == None ) :
  lisp . lprint ( "ITR/ETR state mismatch for {}" . format ( lisp . green ( IiIi1111ii , False ) ) )
  if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
  return
  if 94 - 94: ooOoO0o + I1IiiI
  if 56 - 56: OoOoOO00 % o0oOOo0O0Ooo
  if 40 - 40: OOooOOo / IiII
  if 29 - 29: Ii1I - Ii1I / ooOoO0o
  if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
  if 18 - 18: Oo0Ooo % O0
 if ( iIi1II and iIiiI11II11i ) :
  if ( iIi1II . interface == iIiiI11II11i ) :
   lisp . lprint ( "ITR sent redundant IPC for {}" . format ( lisp . green ( IiIi1111ii , False ) ) )
   if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
  else :
   lisp . lprint ( "Dynamic-EID {} interface change, {} -> {}" . format ( lisp . green ( IiIi1111ii , False ) , iIi1II . interface , iIiiI11II11i ) )
   if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
   iIi1II . interface = iIiiI11II11i
   if 86 - 86: IiII
  return
  if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
  if 33 - 33: II111iiii - IiII - ooOoO0o
  if 92 - 92: OoO0O00 * IiII
  if 92 - 92: oO0o
  if 7 - 7: iII111i
 if ( iIiiI11II11i ) :
  iIi1II = lisp . lisp_dynamic_eid ( )
  iIi1II . dynamic_eid . copy_address ( oOIIi1iiii1iI )
  iIi1II . interface = iIiiI11II11i
  iIi1II . get_timeout ( iIiiI11II11i )
  i1iIi . dynamic_eids [ IiIi1111ii ] = iIi1II
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  I1I11i = lisp . bold ( "Registering" , False )
  IiIi1111ii = lisp . bold ( IiIi1111ii , False )
  lisp . lprint ( "{} dynamic-EID {} on interface {}, timeout {}" . format ( I1I11i ,
 lisp . green ( IiIi1111ii , False ) , iIiiI11II11i , iIi1II . timeout ) )
  if 38 - 38: i11iIiiIii . iIii1I11I1II1 . OOooOOo / OoO0O00
  o00O ( i1 , None , oOIIi1iiii1iI , None , False )
  if 18 - 18: Oo0Ooo * I1Ii111
  if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  if 14 - 14: IiII . IiII % ooOoO0o
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  if ( lisp . lisp_is_macos ( ) == False ) :
   IiIi1111ii = oOIIi1iiii1iI . print_prefix_no_iid ( )
   Iiii = "ip route add {} dev {}" . format ( IiIi1111ii , iIiiI11II11i )
   os . system ( Iiii )
   if 56 - 56: I11i - O0 / O0 * i1IIi . OoooooooOO % iIii1I11I1II1
  return
  if 21 - 21: IiII - I1IiiI % OoooooooOO + o0oOOo0O0Ooo
  if 92 - 92: ooOoO0o + IiII
  if 52 - 52: II111iiii / I1IiiI . oO0o * IiII . I11i
  if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 6 - 6: oO0o . I11i
 if ( IiIi1111ii in i1iIi . dynamic_eids ) :
  iIiiI11II11i = i1iIi . dynamic_eids [ IiIi1111ii ] . interface
  iIIII1 = lisp . bold ( "Deregistering" , False )
  lisp . lprint ( "{} dynamic-EID {}" . format ( iIIII1 ,
 lisp . green ( IiIi1111ii , False ) ) )
  if 65 - 65: O0 / II111iiii . iIii1I11I1II1 . oO0o / Oo0Ooo % iIii1I11I1II1
  o00O ( i1 , 0 , oOIIi1iiii1iI , None , False )
  if 74 - 74: i1IIi / I1IiiI % I1ii11iIi11i / O0 % I11i - OoOoOO00
  i1iIi . dynamic_eids . pop ( IiIi1111ii )
  if 31 - 31: I1IiiI / OoooooooOO . iIii1I11I1II1 * OoOoOO00 . OoooooooOO + II111iiii
  if 8 - 8: I1ii11iIi11i * I1ii11iIi11i * i1IIi + iII111i . I1ii11iIi11i
  if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
  if 37 - 37: Oo0Ooo
  if ( lisp . lisp_is_macos ( ) == False ) :
   IiIi1111ii = oOIIi1iiii1iI . print_prefix_no_iid ( )
   Iiii = "ip route delete {} dev {}" . format ( IiIi1111ii , iIiiI11II11i )
   os . system ( Iiii )
   if 72 - 72: IiII % I1ii11iIi11i * OOooOOo . i11iIiiIii % IiII * OOooOOo
   if 15 - 15: I11i / Oo0Ooo * I11i
 return
 if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
 if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
 if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
 if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
 if 5 - 5: O0 - I1IiiI
 if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
 if 16 - 16: II111iiii
 if 100 - 100: O0 - i1IIi
 if 48 - 48: oO0o % ooOoO0o + O0
 if 27 - 27: I1ii11iIi11i / OOooOOo
 if 33 - 33: OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
 if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
 if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
def oOooOoOOo0O ( ipc ) :
 global IiI1I1
 global I1Ii11I1Ii1i
 if 41 - 41: iII111i
 ipc = ipc . split ( "%" )
 oo = ipc [ - 2 ]
 OooOoo = ipc [ - 1 ]
 if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
 iiI1iiIiiiI1I = False
 if ( oo in IiI1I1 ) :
  I1i11II = IiI1I1 [ oo ]
 else :
  I1i11II = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , oo , 32 , 0 )
  IiI1I1 [ oo ] = I1i11II
  iiI1iiIiiiI1I = True
  if 6 - 6: OoO0O00
  if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
  if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
  if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
  if 31 - 31: oO0o * I1Ii111 . OoOoOO00 * I11i
 if ( iiI1iiIiiiI1I ) :
  I111i1I1 = [ I1Ii11I1Ii1i , I1Ii11I1Ii1i ,
 o0oOoO00o ]
  lisp . lprint ( "Trigger NAT-Probe to ETR {}" . format ( oo ) )
  lisp . lisp_send_info_request ( I111i1I1 , I1i11II , lisp . LISP_DATA_PORT , None )
  if 28 - 28: IiII + I1IiiI - Oo0Ooo % OOooOOo . I11i + I1IiiI
  if 72 - 72: Ii1I / Oo0Ooo / oO0o * OoOoOO00 + OOooOOo
  if 58 - 58: o0oOOo0O0Ooo % I1IiiI . I1IiiI * OoO0O00 - IiII . OoooooooOO
  if 10 - 10: I1Ii111
  if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
  if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
  if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
 OOO0 = OooOoo . split ( lisp . LISP_TP )
 if ( len ( OOO0 ) != 2 ) :
  lisp . lprint ( "Invalid NAT IPC rloc-name {}" . format ( OOO0 ) )
  return
  if 21 - 21: Oo0Ooo * o0oOOo0O0Ooo + OoooooooOO . I1Ii111 % oO0o
  if 50 - 50: OoOoOO00 - oO0o + iIii1I11I1II1 - OoO0O00 . Oo0Ooo
 iiiiIii11i1 , i1IiII1i1I = OOO0 [ 0 ] , int ( OOO0 [ 1 ] )
 lisp . lisp_store_nat_info ( iiiiIii11i1 , I1i11II , i1IiII1i1I )
 if 7 - 7: O0 * IiII - o0oOOo0O0Ooo * O0 + iIii1I11I1II1 % OoOoOO00
 if 92 - 92: I1IiiI . II111iiii
 if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
 if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
 if 28 - 28: i11iIiiIii
 if 51 - 51: I1IiiI + ooOoO0o * O0 . Ii1I
 if 82 - 82: OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
 if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
 if 20 - 20: i1IIi . i1IIi - I11i
 if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
 if 35 - 35: II111iiii / OoOoOO00 - O0 . II111iiii
def oO0o000oOO ( ipc ) :
 if ( lisp . lisp_register_all_rtrs ) : return
 if 27 - 27: O0 - I11i * II111iiii - iIii1I11I1II1 / ooOoO0o
 II1i , II1I1I1Ii , IIiI1111i1 = ipc . split ( "%" )
 if ( II1I1I1Ii not in lisp . lisp_rtr_list ) : return
 if 98 - 98: OoOoOO00 - OoOoOO00 . II111iiii . iII111i + O0
 lisp . lprint ( "Process ITR IPC message, RTR {} has gone {}" . format (
 lisp . red ( II1I1I1Ii , False ) , lisp . bold ( IIiI1111i1 , False ) ) )
 if 28 - 28: IiII + i11iIiiIii + OoooooooOO / OoO0O00
 OOOOoO00o0O = lisp . lisp_rtr_list [ II1I1I1Ii ]
 if ( IIiI1111i1 == "down" ) :
  lisp . lisp_rtr_list [ II1I1I1Ii ] = None
  return
  if 6 - 6: I1IiiI - i11iIiiIii
  if 61 - 61: I1Ii111 * I1ii11iIi11i % I1IiiI % OoO0O00 % I11i + I11i
 OOOOoO00o0O = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , II1I1I1Ii , 32 , 0 )
 lisp . lisp_rtr_list [ II1I1I1Ii ] = OOOOoO00o0O
 return
 if 6 - 6: Oo0Ooo
 if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
 if 93 - 93: i11iIiiIii
 if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
 if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
 if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
 if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
 if 58 - 58: I11i
 if 7 - 7: II111iiii / IiII % I11i + I1IiiI - O0
 if 45 - 45: I1IiiI / iII111i + oO0o + IiII
def iIIII1Iii11 ( ipc ) :
 II1IIIi1i1I , II1i , o0III11IiI , o0ooo = ipc . split ( "%" )
 o0ooo = int ( o0ooo , 16 )
 if 77 - 77: I11i + i1IIi . I11i
 oO0OOO = lisp . lisp_get_echo_nonce ( None , o0III11IiI )
 if ( oO0OOO == None ) : oO0OOO = lisp . lisp_echo_nonce ( o0III11IiI )
 if 42 - 42: iIii1I11I1II1 % Ii1I - I1ii11iIi11i + iIii1I11I1II1
 if ( II1i == "R" ) :
  oO0OOO . request_nonce_sent = o0ooo
  lisp . lprint ( "Waiting for echo-nonce 0x{} from {}" . format ( lisp . lisp_hex_string ( o0ooo ) , lisp . red ( oO0OOO . rloc_str , False ) ) )
  if 27 - 27: O0 / OoO0O00
 elif ( II1i == "E" ) :
  oO0OOO . echo_nonce_sent = o0ooo
  lisp . lprint ( "Sent echo-nonce 0x{} to {}" . format ( lisp . lisp_hex_string ( o0ooo ) , lisp . red ( oO0OOO . rloc_str , False ) ) )
  if 99 - 99: Ii1I - IiII * iIii1I11I1II1 . II111iiii
  if 56 - 56: iIii1I11I1II1 % OoO0O00 . ooOoO0o % IiII . I1Ii111 * Oo0Ooo
 return
 if 41 - 41: iIii1I11I1II1 % IiII * oO0o - ooOoO0o
 if 5 - 5: OoO0O00 + OoO0O00 + II111iiii * iIii1I11I1II1 + OoooooooOO
 if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
 if 10 - 10: I1ii11iIi11i + IiII
 if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
oooO0 = {
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

 "lisp database-mapping" : [ i1i , {
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

 "show database-mapping" : [ i1Iii1i1I , { } ] ,
 "show etr-keys" : [ oo0 , { } ] ,
 "show etr-dynamic-eid" : [ lispconfig . lisp_show_dynamic_eid_command , { } ]
 }
if 29 - 29: Ii1I * OOooOOo * i1IIi . Ii1I * I1Ii111 . ooOoO0o
if 54 - 54: iII111i . i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo % iII111i
if 30 - 30: I11i
if 85 - 85: II111iiii + ooOoO0o * I11i
if 12 - 12: Ii1I . I1IiiI % o0oOOo0O0Ooo
if 28 - 28: Ii1I - I1IiiI % OoO0O00 * I1Ii111
if ( iIi ( ) == False ) :
 lisp . lprint ( "lisp_etr_startup() failed" )
 lisp . lisp_print_banner ( "ETR abnormal exit" )
 exit ( 1 )
 if 80 - 80: OOooOOo * IiII
 if 4 - 4: iIii1I11I1II1 . I1Ii111 + II111iiii % OoooooooOO
Oo000 = [ I1Ii11I1Ii1i , o0oOoO00o ]
if 75 - 75: O0
while ( True ) :
 try : oOoO , OOooooO , II1IIIi1i1I = select . select ( Oo000 , [ ] , [ ] )
 except : break
 if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
 if 76 - 76: I1IiiI * OOooOOo
 if 12 - 12: iIii1I11I1II1 / I11i % Ii1I
 if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
 if ( I1Ii11I1Ii1i in oOoO ) :
  II1i , o0OOOOooo , i1IiII1i1I , OoO = lisp . lisp_receive ( I1Ii11I1Ii1i , False )
  if 27 - 27: OoO0O00 + Oo0Ooo
  if ( o0OOOOooo == "" ) : break
  if 92 - 92: I1IiiI % iII111i
  if ( i1IiII1i1I == lisp . LISP_DATA_PORT ) :
   OOoOOOO00 ( oOOoo00O0O , OoO , o0OOOOooo )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( OoO [ 0 : 1 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 31 - 31: OoooooooOO - oO0o / I1Ii111
   oo00o000O = lisp . lisp_parse_packet ( i1 , OoO ,
 o0OOOOooo , i1IiII1i1I )
   if 66 - 66: OoooooooOO + o0oOOo0O0Ooo . i1IIi * iII111i
   if 92 - 92: I11i / I1Ii111
   if 4 - 4: I1Ii111
   if 11 - 11: OoooooooOO + i1IIi / Ii1I
   if 25 - 25: Ii1I . OOooOOo
   if ( oo00o000O ) :
    if ( Ii1iI == None ) :
     Ii1iI = threading . Timer ( 0 ,
 I1i1iii , [ None ] )
     Ii1iI . start ( )
     if 14 - 14: O0 / I11i . OoO0O00 % iII111i . oO0o
    if ( Oo0o == None ) :
     Oo0o = threading . Timer ( 0 ,
 oo000OO00Oo , [ i1 ] )
     Oo0o . start ( )
     if 16 - 16: OoooooooOO % I1IiiI - o0oOOo0O0Ooo / II111iiii . i1IIi
     if 27 - 27: II111iiii + ooOoO0o . OoOoOO00 - I1Ii111
     if 54 - 54: OoOoOO00 . Oo0Ooo
     if 38 - 38: i1IIi . Oo0Ooo * Oo0Ooo / I1ii11iIi11i
     if 65 - 65: ooOoO0o % O0
     if 17 - 17: i1IIi + oO0o . I11i + i1IIi - II111iiii % I1IiiI
     if 34 - 34: I1IiiI
     if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
     if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
 if ( o0oOoO00o in oOoO ) :
  II1i , o0OOOOooo , i1IiII1i1I , OoO = lisp . lisp_receive ( o0oOoO00o , True )
  if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
  if ( o0OOOOooo == "" ) : break
  if 98 - 98: OoO0O00
  if ( II1i == "command" ) :
   OoO = OoO . decode ( )
   if ( OoO . find ( "learn%" ) != - 1 ) :
    o00oOoo0o00 ( OoO )
   elif ( OoO . find ( "nat%" ) != - 1 ) :
    oOooOoOOo0O ( OoO )
   elif ( OoO . find ( "nonce%" ) != - 1 ) :
    iIIII1Iii11 ( OoO )
   elif ( OoO . find ( "clear%" ) != - 1 ) :
    lispconfig . lisp_clear_decap_stats ( OoO )
   elif ( OoO . find ( "rtr%" ) != - 1 ) :
    oO0o000oOO ( OoO )
   elif ( OoO . find ( "stats%" ) != - 1 ) :
    OoO = OoO . split ( "%" ) [ - 1 ]
    lisp . lisp_process_data_plane_decap_stats ( OoO , None )
   else :
    lispconfig . lisp_process_command ( o0oOoO00o ,
 II1i , OoO , "lisp-etr" , [ oooO0 ] )
    if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
  elif ( II1i == "api" ) :
   OoO = OoO . decode ( )
   lisp . lisp_process_api ( "lisp-etr" , o0oOoO00o , OoO )
  else :
   if ( lisp . lisp_is_rloc_probe_request ( OoO [ 0 : 1 ] ) ) :
    lisp . lprint ( "ETR ignoring RLOC-probe request, using pcap" )
    continue
    if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
   lisp . lisp_parse_packet ( i1 , OoO , o0OOOOooo , i1IiII1i1I )
   if 52 - 52: I1Ii111 + I1Ii111
   if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
   if 54 - 54: OoOoOO00 . OoooooooOO
   if 36 - 36: oO0o / II111iiii * IiII % I1ii11iIi11i
oooOO ( )
lisp . lisp_print_banner ( "ETR normal exit" )
exit ( 0 )
if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
if 28 - 28: Ii1I . I1ii11iIi11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
