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
# lispconfig.py
#
# This file contains all configuration support for the LISP subsystem. That
# includes lisp.config file processing and the RESTful interface via the
# bottle module.
# 
# -----------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
import lisp
import os
import commands
import time
import socket
import bottle
import hmac
import hashlib
import select
import copy
import math
from json import dumps as json_dumps
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
LISP_USER_TIMEOUT = 1800
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
lisp_commands = {
 "lisp user-account" : [ "lisp-core" ] ,
 "lisp enable" : [ "lisp-core" ] ,
 "lisp debug" : [ "lisp-core" ] ,
 "lisp xtr-parameters" : [ "lisp-itr" , "lisp-rtr" , "lisp-etr" ] ,
 "lisp interface" : [ "lisp-itr" , "lisp-etr" , "lisp-rtr" ] ,
 "lisp rtr-list" : [ "lisp-core" ] ,
 "lisp map-resolver" : [ "lisp-itr" , "lisp-rtr" ] ,
 "lisp map-cache" : [ "lisp-itr" , "lisp-rtr" ] ,
 "lisp itr-map-cache" : [ "lisp-itr" ] ,
 "lisp rtr-map-cache" : [ "lisp-rtr" ] ,
 "lisp map-server" : [ "lisp-etr" ] ,
 "lisp database-mapping" : [ "lisp-itr" , "lisp-etr" , "lisp-rtr" ] ,
 "lisp group-mapping" : [ "lisp-etr" ] ,
 "lisp glean-mapping" : [ "lisp-rtr" ] ,
 "lisp explicit-locator-path" : [ "lisp-itr" , "lisp-rtr" , "lisp-etr" ,
 "lisp-ms" ] ,
 "lisp replication-list-entry" : [ "lisp-itr" , "lisp-rtr" , "lisp-etr" ,
 "lisp-ms" ] ,
 "lisp geo-coordinates" : [ "lisp-itr" , "lisp-etr" , "lisp-ms" ] ,
 "lisp json" : [ "lisp-itr" , "lisp-etr" , "lisp-rtr" ,
 "lisp-ms" ] ,
 "lisp ddt-root" : [ "lisp-mr" ] ,
 "lisp referral-cache" : [ "lisp-mr" ] ,
 "lisp site" : [ "lisp-ms" ] ,
 "lisp eid-crypto-hash" : [ "lisp-ms" ] ,
 "lisp encryption-keys" : [ "lisp-ms" ] ,
 "lisp map-server-peer" : [ "lisp-ms" ] ,
 "lisp ms-authoritative-prefix" : [ "lisp-ms" ] ,
 "lisp ddt-authoritative-prefix" : [ "lisp-ddt" ] ,
 "lisp delegation" : [ "lisp-ddt" ] ,
 "lisp policy" : [ "lisp-ms" ] ,
 "show itr-map-cache" : [ "lisp-itr" ] ,
 "show itr-rloc-probing" : [ "lisp-itr" ] ,
 "show rtr-map-cache" : [ "lisp-rtr" ] ,
 "show rtr-map-cache-dns" : [ "lisp-rtr" ] ,
 "show rtr-rloc-probing" : [ "lisp-rtr" ] ,
 "show database-mapping" : [ "lisp-etr" ] ,
 "show referral-cache" : [ "lisp-mr" ] ,
 "show delegations" : [ "lisp-ddt" ] ,
 "show site" : [ "lisp-ms" ] ,
 "show itr-dynamic-eid" : [ "lisp-itr" ] ,
 "show etr-dynamic-eid" : [ "lisp-etr" ] ,
 "show itr-keys" : [ "lisp-itr" ] ,
 "show etr-keys" : [ "lisp-etr" ] ,
 "show rtr-keys" : [ "lisp-rtr" ]
 }
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
lisp_core_commands = {
 "lisp enable" : [ "" , {
 "itr" : [ False , "yes" , "no" ] ,
 "etr" : [ False , "yes" , "no" ] ,
 "rtr" : [ False , "yes" , "no" ] ,
 "map-resolver" : [ False , "yes" , "no" ] ,
 "map-server" : [ False , "yes" , "no" ] ,
 "ddt-node" : [ False , "yes" , "no" ] } ] ,

 "lisp debug" : [ "" , {
 "core" : [ False , "yes" , "no" ] ,
 "itr" : [ False , "yes" , "no" ] ,
 "etr" : [ False , "yes" , "no" ] ,
 "rtr" : [ False , "yes" , "no" ] ,
 "map-resolver" : [ False , "yes" , "no" ] ,
 "map-server" : [ False , "yes" , "no" ] ,
 "ddt-node" : [ False , "yes" , "no" ] } ] ,

 "lisp user-account" : [ "" , {
 "username" : [ False ] ,
 "password" : [ False ] ,
 "super-user" : [ False , "yes" , "no" ] } ] ,

 "lisp rtr-list" : [ "" , {
 "address" : [ True ] } ]
 }
if 94 - 94: i1IIi % Oo0Ooo
if 68 - 68: Ii1I / O0
if 46 - 46: O0 * II111iiii / IiII * Oo0Ooo * iII111i . I11i
if 62 - 62: i11iIiiIii - II111iiii % I1Ii111 - iIii1I11I1II1 . I1ii11iIi11i . II111iiii
if 61 - 61: oO0o / OoOoOO00 / iII111i * OoO0O00 . II111iiii
if 1 - 1: II111iiii - I1ii11iIi11i % i11iIiiIii + IiII . I1Ii111
if 55 - 55: iIii1I11I1II1 - I1IiiI . Ii1I * IiII * i1IIi / iIii1I11I1II1
if 79 - 79: oO0o + I1Ii111 . ooOoO0o * IiII % I11i . I1IiiI
def lisp_banner_top ( no_hover ) :
 O0o0o00o0Oo0 = socket . gethostname ( )
 ii11 = lisp . lisp_print_cour ( O0o0o00o0Oo0 )
 if ( no_hover == False ) :
  I1I1i1 = commands . getoutput ( "ifconfig" )
  ii11 = lisp . lisp_span ( ii11 , I1I1i1 )
  if 18 - 18: iIii1I11I1II1 / I11i + oO0o / Oo0Ooo - II111iiii - I11i
  if 1 - 1: I11i - OOooOOo % O0 + I1IiiI - iII111i / I11i
 ii11 = '''
        <a href="/lisp/traceback" style="text-decoration: none">{}</a>
    ''' . format ( ii11 )
 if 31 - 31: OoO0O00 + II111iiii
 i11IiIiiIIIII = '''
        <head><title>{}</title></head>
        <body bgcolor="gray">
        <div style="margin:20px;background-color:#F5F5F5;padding:15px;
        border-radius:20px;border:5px solid #666666;">
        <table width="100%"><tr>
          <td align="left" width="50%">
            <a href="/lisp" style="text-decoration: none"><font size="8"><i>
            {}<font color="black">.</font>{}</i></font></a><br>
            <font size="4"><i>{}</i></font>
          </td>
          <td align="right" valign="bottom" width="50%">{}</td>
        </tr></table>
        <hr style="border: none; border-bottom: 1px solid gray;">
    ''' . format ( O0o0o00o0Oo0 , lisp . green ( "lispers" , True ) , lisp . red ( "net" , True ) ,
 lisp . bold ( "Scalable Open Overlay Networking" , True ) , ii11 )
 if 22 - 22: Ii1I * O0 / o0oOOo0O0Ooo
 return ( i11IiIiiIIIII )
 if 64 - 64: Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
 if 78 - 78: OoO0O00
 if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
 if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
 if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
def lisp_banner_bottom ( ) :
 ii11 = socket . gethostname ( )
 i1iIIIiI1I = commands . getoutput ( "date" )
 OOoO000O0OO = lisp . lisp_print_elapsed ( lisp . lisp_uptime )
 if 23 - 23: i11iIiiIii + I1IiiI
 i11IiIiiIIIII = '''<br><hr style="border: none; border-bottom: 1px solid gray;">
        <i><font size="2">{} - Uptime 
        {}, Version {}<br>Copyright 2013-2019 - all rights reserved by
        <a href="http://www.lispers.net"><b>lispers.net</b></a> LLC<br>
        Features/Bugs go to <a href=
"mailto:support@lispers.net?subject=lispers.net v{} bug-report from '{}'">
        support@lispers.net</a></i></font><br><br>
    ''' . format ( i1iIIIiI1I , OOoO000O0OO , lisp . bold ( lisp . lisp_version , True ) ,
 lisp . lisp_version , ii11 )
 if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
 return ( i11IiIiiIIIII )
 if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
 if 33 - 33: Ii1I + II111iiii % i11iIiiIii . ooOoO0o - I1IiiI
 if 66 - 66: Ii1I - OoooooooOO * OoooooooOO . OOooOOo . I1ii11iIi11i
 if 22 - 22: OoooooooOO % I11i - iII111i . iIii1I11I1II1 * i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 if 61 - 61: ooOoO0o
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
def lisp_show_wrapper ( output ) :
 return ( lisp_banner_top ( False ) + output + lisp_banner_bottom ( ) )
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
 if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
def lisp_table_header ( title , * args ) :
 i1iiI11I = '''
        <font face="Sans-Serif"><h3><i>{}</i></h3></font>
        <table border="1" cellspacing="3x" cellpadding="5x">
        <tr>
    ''' . format ( title )
 if 29 - 29: OoooooooOO
 for iI in args :
  i1iiI11I += '''
            <td><font face="Sans-Serif"><b>{}</b></font></td>
        ''' . format ( iI )
  if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 i1iiI11I += "</tr>"
 return ( i1iiI11I )
 if 95 - 95: OoO0O00 % oO0o . O0
 if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
 if 53 - 53: IiII + I1IiiI * oO0o
 if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
 if 60 - 60: I11i / I11i
 if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
 if 83 - 83: OoooooooOO
def lisp_table_row ( * args ) :
 i1iiI11I = "<tr>"
 for iI in args :
  i1iiI11I += '''
            <td><font face="Sans-Serif">{}</font></td>
        ''' . format ( iI )
  if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 i1iiI11I += "</tr>"
 return ( i1iiI11I )
 if 4 - 4: II111iiii / ooOoO0o . iII111i
 if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 if 50 - 50: I1IiiI
 if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
 if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
 if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
def lisp_table_footer ( ) :
 return ( "</table>" )
 if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
 if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
 if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 if 58 - 58: i11iIiiIii % I11i
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
 if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
 if 16 - 16: I1IiiI * oO0o % IiII
def lisp_write_last_changed_date ( new , line ) :
 Oo000o = commands . getoutput ( "date" )
 I11IiI1I11i1i = line . find ( ":" )
 line = line [ 0 : I11IiI1I11i1i + 1 ] + " " + Oo000o + "\n"
 new . write ( line )
 return
 if 38 - 38: o0oOOo0O0Ooo
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
 if 26 - 26: iII111i
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
 if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
 if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
 if 91 - 91: oO0o % Oo0Ooo
 if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
def lisp_comment ( line ) :
 return ( True if line [ 0 ] == "#" else False )
 if 31 - 31: I11i - II111iiii . I11i
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 if 92 - 92: iII111i . I1Ii111
def lisp_begin_clause ( line ) :
 return ( False if line . find ( "{" ) == - 1 else True )
 if 31 - 31: I1Ii111 . OoOoOO00 / O0
 if 89 - 89: OoOoOO00
 if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
 if 4 - 4: ooOoO0o + O0 * OOooOOo
 if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
 if 25 - 25: I1ii11iIi11i
def lisp_end_clause ( line ) :
 return ( False if line . find ( "}" ) == - 1 else True )
 if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
 if 13 - 13: OOooOOo / i11iIiiIii
 if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
 if 52 - 52: o0oOOo0O0Ooo
 if 95 - 95: Ii1I
 if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
 if 61 - 61: II111iiii
def lisp_end_file ( line ) :
 return ( True if ( line [ 0 : 10 ] == "#---------" and line [ - 2 ] == "#" ) else False )
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
 if 67 - 67: I1Ii111 . iII111i . O0
 if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
 if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 if 83 - 83: I11i / I1IiiI
def lisp_write_error ( line , error ) :
 iIIiIi1iIII1 = "%>>> " + line + " <<< " + error + "\n"
 return ( iIIiIi1iIII1 )
 if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
 if 49 - 49: Ii1I / OoO0O00 . II111iiii
 if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
 if 31 - 31: II111iiii . I1IiiI
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
 if 92 - 92: iII111i
 if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
def lisp_write_line ( line ) :
 return ( "#" + line + "\n" )
 if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
def lisp_not_supported ( ) :
 return ( lisp_show_wrapper ( "" ) )
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % I1Ii111
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
 if 23 - 23: O0
 if 85 - 85: Ii1I
 if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
def lisp_hash_password ( plaintext ) :
 IIi1 = hmac . new ( "lispers.net" , plaintext , hashlib . sha1 ) . hexdigest ( )
 return ( IIi1 )
 if 45 - 45: iII111i / iII111i + I1Ii111 + ooOoO0o
 if 47 - 47: o0oOOo0O0Ooo + ooOoO0o
 if 82 - 82: II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
 if 77 - 77: iIii1I11I1II1 * OoO0O00
 if 95 - 95: I1IiiI + i11iIiiIii
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 if 53 - 53: II111iiii
 if 31 - 31: OoO0O00
 if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: OoO0O00
 if 62 - 62: OOooOOo + O0
 if 98 - 98: o0oOOo0O0Ooo
def lisp_validate_input_address_string ( input_str ) :
 OOOO0oo0 = input_str
 I11iiI1i1 = None
 if ( input_str . find ( "->" ) != - 1 ) :
  I1i1Iiiii = input_str . split ( "->" )
  OOOO0oo0 = I1i1Iiiii [ 0 ]
  I11iiI1i1 = I1i1Iiiii [ 1 ]
  if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
  if 87 - 87: Oo0Ooo . IiII
 O0OO0O = lisp_valid_iid_format ( OOOO0oo0 )
 if ( O0OO0O == - 1 ) : return ( False )
 if ( O0OO0O == len ( OOOO0oo0 ) ) : return ( True )
 if 81 - 81: oO0o . o0oOOo0O0Ooo % O0 / I1IiiI - oO0o
 Ii1I1i = OOOO0oo0 [ O0OO0O : : ]
 if 99 - 99: oO0o . iII111i + ooOoO0o % oO0o . i11iIiiIii % O0
 if ( Ii1I1i . find ( "/" ) == - 1 ) :
  oOO00O = lisp . lisp_valid_address_format ( "address" , Ii1I1i )
 else :
  oOO00O = lisp_valid_prefix_format ( Ii1I1i )
  if 77 - 77: Oo0Ooo - i1IIi - I11i . OoOoOO00
 if ( oOO00O == False ) : return ( False )
 if 39 - 39: II111iiii / ooOoO0o + I1Ii111 / OoOoOO00
 if 13 - 13: IiII + O0 + iII111i % I1IiiI / o0oOOo0O0Ooo . IiII
 if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
 if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 if ( I11iiI1i1 == None ) : return ( True )
 if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 O0OO0O = lisp_valid_iid_format ( I11iiI1i1 )
 if ( O0OO0O == - 1 ) : return ( False )
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 Ii1I1i = I11iiI1i1 [ O0OO0O : : ]
 if ( I11iiI1i1 . find ( "/" ) == - 1 ) :
  oOO00O = lisp . lisp_valid_address_format ( "address" , Ii1I1i )
 else :
  oOO00O = lisp_valid_prefix_format ( Ii1I1i )
  if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if ( oOO00O == False ) : return ( False )
 return ( True )
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 if 49 - 49: I1IiiI - I11i
 if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
 if 62 - 62: OoooooooOO * I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if 97 - 97: O0 + OoOoOO00
def lisp_valid_iid_format ( iid_str ) :
 OO0O000 = iid_str . find ( "[" )
 if ( OO0O000 == - 1 ) : return ( 0 )
 if ( OO0O000 != 0 ) : return ( - 1 )
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 o0o0O0O00oOOo = iid_str . find ( "]" )
 if ( o0o0O0O00oOOo == - 1 ) : return ( - 1 )
 if 14 - 14: OoOoOO00 + oO0o
 if ( ( OO0O000 + 1 ) == ( o0o0O0O00oOOo - 1 ) ) :
  oo00oO0O0 = iid_str [ OO0O000 + 1 ]
 else :
  oo00oO0O0 = iid_str [ OO0O000 + 1 : o0o0O0O00oOOo - 1 ]
  if 30 - 30: OOooOOo + I1ii11iIi11i * I11i % i11iIiiIii % OoOoOO00
 if ( oo00oO0O0 . isdigit ( ) == False ) : return ( - 1 )
 return ( o0o0O0O00oOOo + 1 )
 if 97 - 97: I1ii11iIi11i % I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
 if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
 if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
 if 71 - 71: I1Ii111 + Ii1I
 if 28 - 28: OOooOOo
 if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
def lisp_valid_prefix_format ( prefix ) :
 if ( prefix . find ( "'" ) == - 1 and prefix . find ( "/" ) == - 1 ) : return ( False )
 if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
 II = prefix . split ( "/" )
 if ( len ( II ) != 2 ) :
  if ( prefix . find ( "'" ) == - 1 ) : return ( False )
  II = [ prefix , len ( prefix ) ]
  if 93 - 93: IiII * OoooooooOO + ooOoO0o
 return ( lisp . lisp_valid_address_format ( "address" , II [ 0 ] ) )
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
 if 76 - 76: IiII * iII111i
 if 52 - 52: OOooOOo
 if 19 - 19: I1IiiI
 if 25 - 25: Ii1I / ooOoO0o
 if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
def lisp_validate_range ( value ) :
 if ( value == "*" ) : return ( [ 0 , 0 ] )
 if 71 - 71: I1Ii111 . II111iiii
 value = value . split ( "-" )
 oo0 = int ( value [ 0 ] )
 oOOOoo00 = int ( value [ 1 ] )
 if ( oo0 > oOOOoo00 ) : return ( [ 0 , - 1 ] )
 if 9 - 9: O0 % O0 - o0oOOo0O0Ooo
 if 51 - 51: I1IiiI . iIii1I11I1II1 - I1ii11iIi11i / O0
 if 52 - 52: o0oOOo0O0Ooo + O0 + iII111i + Oo0Ooo % iII111i
 if 75 - 75: I1IiiI . ooOoO0o . O0 * I1Ii111
 if 4 - 4: Ii1I % oO0o * OoO0O00
 o0O0OOOOoOO0 = oOOOoo00 - oo0 + 1
 ii = str ( math . log ( o0O0OOOOoOO0 , 2 ) )
 ii = ii . split ( "." )
 if ( len ( ii ) == 1 or int ( ii [ 1 ] ) != 0 ) : return ( [ 0 , 0 ] )
 if 68 - 68: iII111i - I1IiiI / I1Ii111 / I11i
 ii = 32 - int ( ii [ 0 ] )
 return ( [ oo0 , ii ] )
 if 12 - 12: Ii1I + i11iIiiIii * iIii1I11I1II1 / I1ii11iIi11i . I11i
 if 5 - 5: i1IIi + IiII / o0oOOo0O0Ooo . iII111i / I11i
 if 32 - 32: I1IiiI % iIii1I11I1II1 / i1IIi - I1IiiI
 if 7 - 7: I1Ii111 * OoO0O00 - ooOoO0o + OOooOOo * I1IiiI % OoO0O00
 if 15 - 15: OoOoOO00 % I1IiiI * I11i
 if 81 - 81: ooOoO0o - iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * I11i
 if 20 - 20: oO0o % IiII
 if 19 - 19: I1ii11iIi11i % IiII + ooOoO0o / I1Ii111 . ooOoO0o
 if 12 - 12: i1IIi + i1IIi - I1ii11iIi11i * Oo0Ooo % Oo0Ooo - II111iiii
 if 52 - 52: ooOoO0o . iII111i + I1Ii111
 if 38 - 38: i1IIi - II111iiii . I1Ii111
 if 58 - 58: I1IiiI . iII111i + OoOoOO00
 if 66 - 66: iII111i / oO0o * OoooooooOO + OoooooooOO % I11i
 if 49 - 49: oO0o - i11iIiiIii . I1Ii111 * Ii1I % iII111i + i1IIi
 if 71 - 71: o0oOOo0O0Ooo
 if 38 - 38: oO0o % OoOoOO00 + I1ii11iIi11i . i11iIiiIii
 if 53 - 53: i11iIiiIii * iII111i
 if 68 - 68: iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
 if 38 - 38: ooOoO0o - OOooOOo / iII111i
 if 66 - 66: O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / Ii1I + I1ii11iIi11i
 if 86 - 86: o0oOOo0O0Ooo
 if 5 - 5: IiII * OoOoOO00
 if 5 - 5: I1Ii111
 if 90 - 90: I1Ii111 . ooOoO0o / Ii1I - I11i
 if 40 - 40: OoooooooOO
 if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
 if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
 if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
 if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
 if 19 - 19: OoO0O00 - Oo0Ooo . O0
 if 60 - 60: II111iiii + Oo0Ooo
def lisp_setup_kv_pairs ( clause ) :
 I1IiIiiIiIII = { }
 if 8 - 8: oO0o / I1ii11iIi11i
 if 20 - 20: I1IiiI
 if 95 - 95: iII111i - I1IiiI
 if 34 - 34: ooOoO0o * I1IiiI . i1IIi * ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 O0OO0O = clause . find ( "#" )
 while ( O0OO0O != - 1 ) :
  o0o0O0O00oOOo = clause [ O0OO0O : : ] . find ( "\n" )
  if ( o0o0O0O00oOOo == - 1 ) : o0o0O0O00oOOo = 0
  clause = clause [ : O0OO0O ] + clause [ O0OO0O + o0o0O0O00oOOo + 1 : : ]
  O0OO0O = clause . find ( "#" )
  if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
  if 41 - 41: i1IIi - I11i - Ii1I
 III11I1 = clause . count ( " prefix {" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "instance-id" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "secondary-instance-id" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "eid-prefix" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "group-prefix" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "mr-name" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "ms-name" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "dynamic-eid" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "signature-eid" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "send-map-request" ] = [ "" ] * III11I1
  if 36 - 36: oO0o - Ii1I . Oo0Ooo - i11iIiiIii - OOooOOo * Oo0Ooo
  if 76 - 76: i11iIiiIii + o0oOOo0O0Ooo / I1ii11iIi11i - OoO0O00 - Ii1I + I1ii11iIi11i
 III11I1 = clause . count ( " rloc {" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "address" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "interface" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "rloc-record-name" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "elp-name" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "geo-name" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "rle-name" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "json-name" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "priority" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "weight" ] = [ "" ] * III11I1
  if 51 - 51: iIii1I11I1II1 . ooOoO0o + iIii1I11I1II1
  if 95 - 95: I1IiiI
 III11I1 = clause . count ( " match {" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "instance-id" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "source-eid" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "destination-eid" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "source-rloc" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "destination-rloc" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "rloc-record-name" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "elp-name" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "geo-name" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "rle-name" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "json-name" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "datetime-range" ] = [ "" ] * III11I1
  if 46 - 46: OoOoOO00 + OoO0O00
  if 70 - 70: iII111i / iIii1I11I1II1
 III11I1 = clause . count ( " elp-node {" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "address" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "strict" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "probe" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "eid" ] = [ "" ] * III11I1
  if 85 - 85: OoooooooOO % i1IIi * OoooooooOO / I1ii11iIi11i
  if 96 - 96: OoooooooOO + oO0o
 III11I1 = clause . count ( " rle-node {" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "address" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "level" ] = [ "" ] * III11I1
  if 44 - 44: oO0o
  if 20 - 20: I11i + Ii1I / O0 % iIii1I11I1II1
 III11I1 = clause . count ( " referral {" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "address" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "priority" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "weight" ] = [ "" ] * III11I1
  if 88 - 88: OoOoOO00 / II111iiii
  if 87 - 87: I1ii11iIi11i - I1ii11iIi11i - iII111i + oO0o
 III11I1 = clause . count ( " delegate {" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "address" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "node-type" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "priority" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "weight" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "public-key" ] = [ "" ] * III11I1
  if 82 - 82: oO0o / iIii1I11I1II1 . I1IiiI . OOooOOo / o0oOOo0O0Ooo
  if 42 - 42: Oo0Ooo
 III11I1 = clause . count ( " allowed-rloc {" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "address" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "priority" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "weight" ] = [ "" ] * III11I1
  if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
  if 46 - 46: Oo0Ooo
 III11I1 = clause . count ( " allowed-prefix {" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "instance-id" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "eid-prefix" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "group-prefix" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "accept-more-specifics" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "force-proxy-reply" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "force-nat-proxy-reply" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "force-ttl" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "pitr-proxy-reply-drop" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "proxy-reply-action" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "require-signature" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "echo-nonce-capable" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "policy-name" ] = [ "" ] * III11I1
  if 1 - 1: iII111i
  if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 III11I1 = clause . count ( " peer {" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "address" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "priority" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "weight" ] = [ "" ] * III11I1
  if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
  if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
  if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
  if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
  if 17 - 17: i1IIi
 III11I1 = clause . count ( "data-plane-security =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "data-plane-security" ] = [ "" ] * III11I1
  if 21 - 21: Oo0Ooo
 III11I1 = clause . count ( "data-plane-logging =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "data-plane-logging" ] = [ "" ] * III11I1
  if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
 III11I1 = clause . count ( "frame-logging =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "frame-logging" ] = [ "" ] * III11I1
  if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 III11I1 = clause . count ( "flow-logging =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "flow-logging" ] = [ "" ] * III11I1
  if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 III11I1 = clause . count ( "nat-traversal =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "nat-traversal" ] = [ "" ] * III11I1
  if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
 III11I1 = clause . count ( "rloc-probing =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "rloc-probing" ] = [ "" ] * III11I1
  if 54 - 54: i1IIi + II111iiii
 III11I1 = clause . count ( "nonce-echoing =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "nonce-echoing" ] = [ "" ] * III11I1
  if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 III11I1 = clause . count ( "checkpoint-map-cache =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "checkpoint-map-cache" ] = [ "" ] * III11I1
  if 5 - 5: Ii1I
 III11I1 = clause . count ( "ipc-data-plane =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "ipc-data-plane" ] = [ "" ] * III11I1
  if 46 - 46: IiII
 III11I1 = clause . count ( "program-hardware =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "program-hardware" ] = [ "" ] * III11I1
  if 45 - 45: ooOoO0o
 III11I1 = clause . count ( "decentralized-push-xtr =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "decentralized-push-xtr" ] = [ "" ] * III11I1
  if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 III11I1 = clause . count ( "decentralized-pull-xtr-modulus =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "decentralized-pull-xtr-modulus" ] = [ "" ] * III11I1
  if 17 - 17: OOooOOo / OOooOOo / I11i
 III11I1 = clause . count ( "decentralized-pull-xtr-dns-suffix =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "decentralized-pull-xtr-dns-suffix" ] = [ "" ] * III11I1
  if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
 III11I1 = clause . count ( "register-reachable-rtrs =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "register-reachable-rtrs" ] = [ "" ] * III11I1
  if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
  if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
  if 9 - 9: Ii1I
  if 59 - 59: I1IiiI * II111iiii . O0
  if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
  if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
  if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
  if 27 - 27: O0
 if ( I1IiIiiIiIII == { } ) :
  III11I1 = max ( clause . count ( "address =" ) , clause . count ( "dns-name =" ) )
  if ( III11I1 != 0 ) : I1IiIiiIiIII [ "address" ] = [ "" ] * III11I1
  if ( III11I1 != 0 ) : I1IiIiiIiIII [ "dns-name" ] = [ "" ] * III11I1
  III11I1 = clause . count ( "mr-name =" )
  if ( III11I1 != 0 ) : I1IiIiiIiIII [ "mr-name" ] = [ "" ] * III11I1
  III11I1 = clause . count ( "ms-name =" )
  if ( III11I1 != 0 ) : I1IiIiiIiIII [ "ms-name" ] = [ "" ] * III11I1
  if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
 return ( I1IiIiiIiIII )
 if 28 - 28: i1IIi - iII111i
 if 54 - 54: iII111i - O0 % OOooOOo
 if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
 if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if 28 - 28: I11i
 if 58 - 58: OoOoOO00
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 if 73 - 73: i11iIiiIii - IiII
def lisp_syntax_check ( kv_pairs , clause ) :
 if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
 if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
 if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
 OoOoOo00o0 = lisp_setup_kv_pairs ( clause )
 if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
 clause = clause . split ( "\n" )
 I1iii11 = ""
 ooo0O = 0
 iII1iii = False
 O0OO0O = 0
 i11i1iiiII = ""
 if 68 - 68: i11iIiiIii * OoO0O00
 for II1i in clause :
  if ( len ( II1i ) == 0 ) : continue
  if ( II1i == "" ) : continue
  if ( lisp_comment ( II1i ) ) :
   II1i = II1i . replace ( "#" , "%" )
   I1iii11 += lisp_write_line ( II1i )
   continue
   if 2 - 2: iIii1I11I1II1 * Oo0Ooo % oO0o - II111iiii - iII111i
   if 3 - 3: I1Ii111
  i1iiIiI1Ii1i = II1i . find ( "json-string" ) != - 1
  if 22 - 22: IiII / i11iIiiIii
  if ( lisp_begin_clause ( II1i ) and i1iiIiI1Ii1i == False ) :
   I1iii11 += lisp_write_line ( II1i )
   ooo0O += 1
   if ( i11i1iiiII == II1i ) :
    O0OO0O += 1
   else :
    O0OO0O = 0
    i11i1iiiII = II1i
    if 62 - 62: OoO0O00 / I1ii11iIi11i
   continue
   if 7 - 7: OoooooooOO . IiII
  if ( lisp_end_clause ( II1i ) and i1iiIiI1Ii1i == False ) :
   ooo0O -= 1
   if ( ooo0O == 0 ) :
    I1iii11 += lisp_write_line ( II1i )
    break
    if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
   if ( iII1iii ) :
    I1iii11 += "%" + II1i + "\n"
   else :
    I1iii11 += lisp_write_line ( II1i )
    if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
   continue
   if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
  if ( iII1iii ) :
   I1iii11 += "%" + II1i + "\n"
   continue
   if 92 - 92: ooOoO0o
   if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
   if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
   if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
   if 92 - 92: I11i . I1Ii111
   if 85 - 85: I1ii11iIi11i . I1Ii111
  O0O0Ooooo000 = II1i . split ( "=" , 1 )
  if 65 - 65: OOooOOo * I1Ii111
  if ( len ( O0O0Ooooo000 ) == 1 ) :
   I1iii11 += lisp_write_error ( II1i , "no equal sign" )
   iII1iii = True
   continue
   if 79 - 79: OoooooooOO - I1IiiI
   if 69 - 69: I11i
  O00oO0 = O0O0Ooooo000 [ 0 ] . replace ( " " , "" )
  if 97 - 97: I1Ii111 - iIii1I11I1II1
  if 75 - 75: OoooooooOO * IiII
  if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
  if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
  if 69 - 69: O0
  if ( O00oO0 == "description" or O00oO0 == "geo-tag" ) :
   oo00oO0O0 = O0O0Ooooo000 [ 1 ]
  elif ( O00oO0 == "json-string" ) :
   oo00oO0O0 = O0O0Ooooo000 [ 1 ] [ 1 : : ]
  else :
   if ( O00oO0 == "eid-prefix" and O0O0Ooooo000 [ 1 ] . count ( "'" ) == 2 ) :
    oo00oO0O0 = O0O0Ooooo000 [ 1 ] [ 1 : : ]
   elif ( O00oO0 == "instance-id" ) :
    oo00oO0O0 = O0O0Ooooo000 [ 1 ] [ 1 : : ]
   else :
    oo00oO0O0 = O0O0Ooooo000 [ 1 ] . replace ( " " , "" )
    if 85 - 85: ooOoO0o / O0
    if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
    if 62 - 62: I1Ii111 . IiII . OoooooooOO
  O00oO0 = O00oO0 . replace ( "\t" , "" )
  oo00oO0O0 = oo00oO0O0 . replace ( "\t" , "" )
  if 11 - 11: OOooOOo / I11i
  if ( not kv_pairs . has_key ( O00oO0 ) ) :
   I1iii11 += lisp_write_error ( II1i , "invalid command keyword" )
   iII1iii = True
   continue
   if 73 - 73: i1IIi / i11iIiiIii
   if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
   if 85 - 85: OoOoOO00 + OOooOOo
   if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
   if 27 - 27: Ii1I
   if 67 - 67: I1IiiI
   if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
   if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
  if ( len ( kv_pairs [ O00oO0 ] ) <= 1 ) :
   OO0 = ""
   if ( O00oO0 == "eid-prefix" and not lisp_valid_prefix_format ( oo00oO0O0 ) ) :
    OO0 = "invalid prefix"
    if 44 - 44: iII111i - I1Ii111 / O0 * Oo0Ooo + II111iiii / OoOoOO00
   if ( O00oO0 == "address" and not lisp . lisp_valid_address_format ( O00oO0 , oo00oO0O0 ) ) :
    if 88 - 88: o0oOOo0O0Ooo - OoO0O00 + I1ii11iIi11i . I1Ii111 % I1Ii111
    OO0 = "invalid address"
    if 57 - 57: II111iiii
   if ( OO0 != "" ) :
    I1iii11 += lisp_write_error ( II1i , OO0 )
    iII1iii = True
    continue
    if 54 - 54: Oo0Ooo + oO0o + i11iIiiIii
    if 28 - 28: oO0o
    if 70 - 70: IiII
    if 34 - 34: I1Ii111 % IiII
    if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
    if 83 - 83: oO0o + OoooooooOO
    if 22 - 22: Ii1I % iII111i * OoooooooOO - o0oOOo0O0Ooo / iIii1I11I1II1
  if ( len ( kv_pairs [ O00oO0 ] ) == 4 and kv_pairs [ O00oO0 ] [ 3 ] ) :
   if ( O00oO0 == "instance-id" ) :
    Oo = ( oo00oO0O0 . find ( "-" ) != - 1 )
    OO00 = ( oo00oO0O0 == "*" )
    if 28 - 28: oO0o - i11iIiiIii . I1ii11iIi11i + IiII / I1ii11iIi11i
    if ( Oo or OO00 ) :
     oo0 , ii = lisp_validate_range ( oo00oO0O0 )
     if ( ii == - 1 ) :
      I1iii11 += lisp_write_error ( II1i , "invalid range" )
      iII1iii = True
      continue
      if 35 - 35: IiII
    else :
     oo0 = oo00oO0O0
     ii = 32
     if 75 - 75: Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
     if 41 - 41: Ii1I
    oo00oO0O0 = str ( oo0 ) + "-" + str ( ii )
    if 77 - 77: I1Ii111
    if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
    if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
    if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
    if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
    if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
    if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
    if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
  if ( kv_pairs [ O00oO0 ] [ 0 ] and OoOoOo00o0 . has_key ( O00oO0 ) ) :
   if ( OoOoOo00o0 [ O00oO0 ] [ O0OO0O ] != "" ) : O0OO0O += 1
   OoOoOo00o0 [ O00oO0 ] [ O0OO0O ] = oo00oO0O0
  else :
   OoOoOo00o0 [ O00oO0 ] = oo00oO0O0
   if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
   if 95 - 95: IiII
   if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
   if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
   if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
   if 2 - 2: OoooooooOO % OOooOOo
  if ( len ( kv_pairs [ O00oO0 ] ) > 1 ) :
   oOoOOo0oo0 = kv_pairs [ O00oO0 ] [ 1 ]
   if ( type ( oOoOOo0oo0 ) == int ) :
    if ( oo00oO0O0 < kv_pairs [ O00oO0 ] [ 1 ] and oo00oO0O0 > kv_pairs [ O00oO0 ] [ 2 ] ) :
     I1iii11 += lisp_write_error ( II1i , "invalid range value" )
     iII1iii = True
     continue
     if 60 - 60: ooOoO0o * I1Ii111 + Oo0Ooo
   elif ( oo00oO0O0 not in kv_pairs [ O00oO0 ] [ 1 : : ] ) :
    I1iii11 += lisp_write_error ( II1i , "invalid value keyword" )
    iII1iii = True
    continue
    if 19 - 19: OoO0O00 * I11i / I11i . OoooooooOO - OOooOOo + i11iIiiIii
    if 88 - 88: i11iIiiIii - ooOoO0o
    if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
    if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
    if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
    if 30 - 30: OoOoOO00
  I1iii11 += lisp_write_line ( II1i )
  if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
  if 26 - 26: II111iiii * OoOoOO00
 if ( iII1iii == True ) :
  I1iii11 = I1iii11 . replace ( "%" , "#" )
 else :
  I1iii11 = I1iii11 . replace ( "#" , "" )
  I1iii11 = I1iii11 . replace ( "%" , "#" )
  if 10 - 10: II111iiii . iII111i
 return ( [ iII1iii , I1iii11 , OoOoOo00o0 ] )
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 if 88 - 88: iII111i
 if 19 - 19: II111iiii * IiII + Ii1I
 if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
 if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
 if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
 if 67 - 67: I11i - OOooOOo . i1IIi
 if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
def lisp_process_command ( lisp_socket , opcode , clause , process , command_set ) :
 if 87 - 87: OoOoOO00
 if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
 if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
 if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
 if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
 if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
 o00oO00 = clause . split ( " " )
 if 59 - 59: OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
 if 49 - 49: OoooooooOO * I11i - Oo0Ooo . oO0o
 if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
 if 46 - 46: OoO0O00
 if ( clause . find ( "lisp debug" ) != - 1 ) :
  if ( clause . find ( "= yes" ) != - 1 ) :
   lisp . lisp_debug_logging = True
   O0000 = lisp . bold ( "Enable" , False )
   lisp . lprint ( "{} process debug logging" . format ( O0000 ) )
   if 64 - 64: II111iiii - I1IiiI
  if ( clause . find ( "= no" ) != - 1 ) :
   O0O0ooOOO = lisp . bold ( "Disable" , False )
   lisp . lprint ( "{} process debug logging" . format ( O0O0ooOOO ) )
   lisp . lisp_debug_logging = False
   if 67 - 67: iII111i % iII111i / iII111i
  return
  if 53 - 53: iIii1I11I1II1
  if 68 - 68: OoooooooOO % II111iiii
  if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
  if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
  if 2 - 2: Ii1I - IiII
  if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 IIIiIi = ( o00oO00 [ 0 ] == "show" )
 if ( IIIiIi ) :
  Iii = clause . split ( "%" )
  o00oO00 = Iii [ 0 ] . split ( " " )
  IIIII1iii = len ( Iii )
  if ( IIIII1iii == 2 ) :
   Iii = Iii [ 1 ]
  elif ( IIIII1iii == 3 ) :
   Iii = Iii [ 1 ] + "%" + Iii [ 2 ] + "%"
  else :
   Iii = ""
   if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
   if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 o00oO00 = o00oO00 [ 0 ] + " " + o00oO00 [ 1 ]
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 for iiI1i1Iii111 in command_set :
  if ( iiI1i1Iii111 . has_key ( o00oO00 ) ) :
   i111I11i , I1IiIiiIiIII = iiI1i1Iii111 [ o00oO00 ]
   break
   if 46 - 46: O0 . Ii1I
  if ( iiI1i1Iii111 == command_set [ - 1 ] ) :
   lisp . lprint ( "Invalid command found '{}'" . format ( o00oO00 ) )
   return
   if 56 - 56: II111iiii / oO0o + i11iIiiIii + OOooOOo
   if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
   if 79 - 79: Ii1I . OoO0O00
   if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
   if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
   if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
   if 52 - 52: i1IIi
   if 84 - 84: Ii1I / IiII
   if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
   if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 iII1iii = False
 if ( len ( I1IiIiiIiIII ) != 0 ) :
  iII1iii , I1iii11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
  if ( iII1iii ) :
   lisp . lprint ( "Command syntax error: {}" . format ( I1iii11 ) )
  else :
   i111I11i ( I1IiIiiIiIII )
   if 37 - 37: i11iIiiIii + i1IIi
 else :
  if ( IIIiIi ) : I1IiIiiIiIII = Iii
  I1iii11 = i111I11i ( I1IiIiiIiIII )
  if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
  if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 iiIII1II = lisp . lisp_command_ipc ( I1iii11 , process )
 lisp . lisp_ipc ( iiIII1II , lisp_socket , "lisp-core" )
 return
 if 100 - 100: Oo0Ooo % Ii1I / I11i
 if 30 - 30: Oo0Ooo - OOooOOo - iII111i
 if 81 - 81: o0oOOo0O0Ooo . OoooooooOO + OOooOOo * ooOoO0o
 if 74 - 74: i1IIi + O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
def lisp_is_user_superuser ( username ) :
 if ( username == None ) : username = lisp_get_user ( )
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
 oooo0OOo = commands . getoutput ( "egrep -A 4 user-account ./lisp.config" )
 if 72 - 72: O0 / ooOoO0o + OoooooooOO * iII111i
 OoOo0OOOoOo = "username = {}" . format ( username )
 O0OO0O = oooo0OOo . find ( OoOo0OOOoOo )
 o0o0O0O00oOOo = oooo0OOo [ O0OO0O : : ] . find ( "}" )
 if ( O0OO0O == - 1 or o0o0O0O00oOOo == - 1 ) : return ( False )
 if 21 - 21: OoO0O00 - O0 . oO0o + Ii1I . iIii1I11I1II1 - OoOoOO00
 I11IIIiIi11 = oooo0OOo [ O0OO0O : O0OO0O + o0o0O0O00oOOo ] . find ( "super-user = yes" )
 return ( I11IIIiIi11 != - 1 )
 if 39 - 39: Ii1I % O0 % OoOoOO00 . i1IIi
 if 86 - 86: OoO0O00 * OoooooooOO
 if 71 - 71: iIii1I11I1II1 - OOooOOo . I1IiiI % OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
def lisp_find_user_account ( username , password ) :
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 oooo0OOo = commands . getoutput ( "egrep -A 4 user-account ./lisp.config" )
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 O0OO0O = oooo0OOo . find ( "username = {}\n" . format ( username ) )
 if ( O0OO0O == - 1 ) : return ( False )
 if 46 - 46: i11iIiiIii - O0 . oO0o
 oooo0OOo = oooo0OOo [ O0OO0O : : ]
 oooo0OOo = oooo0OOo . replace ( "\t" , "" )
 oooo0OOo = oooo0OOo . replace ( " " , "" )
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 O0OO0O = oooo0OOo . find ( "password=" )
 if ( O0OO0O == - 1 ) : return ( False )
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 oooo0OOo = oooo0OOo [ O0OO0O : : ]
 o0o0O0O00oOOo = oooo0OOo . find ( "\n" )
 if ( o0o0O0O00oOOo == - 1 ) : return ( False )
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
 if 57 - 57: O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 iiIiI = oooo0OOo [ : o0o0O0O00oOOo ] . split ( "=" )
 if ( iiIiI [ 1 ] == "" ) :
  IIi1 = lisp_hash_password ( password )
  if ( iiIiI [ 2 ] != IIi1 ) : return ( False )
 else :
  if ( iiIiI [ 1 ] != password ) : return ( False )
  if 87 - 87: ooOoO0o - OoooooooOO + i11iIiiIii
  if 73 - 73: I11i * OoooooooOO . O0 . IiII
  if 55 - 55: Oo0Ooo
  if 77 - 77: II111iiii
  if 16 - 16: I1IiiI * II111iiii / iIii1I11I1II1 - iII111i
  if 3 - 3: I1IiiI * ooOoO0o + II111iiii - OoO0O00
 return ( True )
 if 97 - 97: I1ii11iIi11i / oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
 if 54 - 54: II111iiii . I11i
 if 73 - 73: OoOoOO00 . I1IiiI
def lisp_validate_user ( ) :
 II1i11i1iIi11 = bottle . request . forms . get ( 'username' )
 if 83 - 83: Ii1I
 if ( II1i11i1iIi11 == None ) :
  I1iI1I1 = bottle . request . get_cookie ( "lisp-login" )
  if ( I1iI1I1 ) : return ( True )
  if 48 - 48: I1IiiI / i11iIiiIii - o0oOOo0O0Ooo * oO0o / OoooooooOO
  if 89 - 89: iIii1I11I1II1 / I1IiiI - II111iiii / Ii1I . i11iIiiIii . Ii1I
 IiiiI1 = bottle . request . forms . get ( 'password' )
 if ( II1i11i1iIi11 == None or IiiiI1 == None ) : return ( False )
 if 100 - 100: oO0o . Ii1I % i1IIi . ooOoO0o
 if ( lisp_find_user_account ( II1i11i1iIi11 , IiiiI1 ) == False ) : return ( False )
 if 79 - 79: OoO0O00 % OOooOOo / iIii1I11I1II1 + OoOoOO00 * OoO0O00
 if 30 - 30: OoooooooOO / I11i + iII111i / I1ii11iIi11i * O0
 if 16 - 16: Oo0Ooo / i11iIiiIii
 if 64 - 64: i11iIiiIii / Ii1I * i1IIi
 OOOOOOoO = None if os . getenv ( "LISP_NO_USER_TIMEOUT" ) == "" else LISP_USER_TIMEOUT
 if 12 - 12: iII111i . IiII . OoOoOO00 / O0
 bottle . response . set_cookie ( "lisp-login" , II1i11i1iIi11 , max_age = OOOOOOoO )
 return ( True )
 if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
 if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
def lisp_get_user ( ) :
 II1i11i1iIi11 = bottle . request . forms . get ( 'username' )
 if ( II1i11i1iIi11 ) : return ( II1i11i1iIi11 )
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 return ( bottle . request . get_cookie ( "lisp-login" ) )
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 23 - 23: I11i
def lisp_login_page ( ) :
 i1iiI11I = '''
        <center><br><br>
        <form action="/lisp/login" method="post">
        <font size="3"><i>
        Username:<input type="text" name="username" />
        {}Password:<input type="password" name="password" />
        {}<input style="background-color:transparent;border-radius:10px;" type="submit" value="Login" />
        </i></font></form>
        </center>
    ''' . format ( lisp . lisp_space ( 4 ) , lisp . lisp_space ( 2 ) )
 return ( lisp_banner_top ( True ) + i1iiI11I + "<br><hr>" )
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
def lisp_is_any_xtr_logging_on ( log_type ) :
 o00oO00 = "egrep '" + log_type + " = '" + " ./lisp.config"
 o00oO00 = commands . getoutput ( o00oO00 )
 if ( o00oO00 == "" ) : return ( False )
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 o00oO00 = o00oO00 . split ( "\n" )
 for oOOO in o00oO00 :
  iIi1I1 = oOOO . find ( "    {} = " . format ( log_type ) ) != - 1
  if ( oOOO [ 0 ] == " " and iIi1I1 ) :
   o00oO00 = oOOO . replace ( " " , "" )
   o00oO00 = o00oO00 . split ( "=" )
   if ( o00oO00 [ 1 ] == "yes" ) : return ( True )
   if 63 - 63: iII111i * I1ii11iIi11i . OoooooooOO / OOooOOo * Oo0Ooo . ooOoO0o
   if 62 - 62: i1IIi / ooOoO0o . I1IiiI * o0oOOo0O0Ooo
 return ( False )
 if 21 - 21: o0oOOo0O0Ooo
 if 81 - 81: I11i / iIii1I11I1II1 - ooOoO0o * I1Ii111 . I1IiiI * I1ii11iIi11i
 if 95 - 95: I1IiiI
 if 88 - 88: IiII % OoO0O00 + I1Ii111 + I1Ii111 * II111iiii
 if 78 - 78: OoooooooOO
 if 77 - 77: I1ii11iIi11i / i1IIi / Oo0Ooo % OOooOOo
 if 48 - 48: I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
def lisp_landing_page ( ) :
 oOoOo = lisp . green ( "yes" , True )
 oO0OO = lisp . red ( "no" , True )
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
 OoiIIIiIi1I1i = oOoOo if lisp . lisp_is_running ( "lisp-itr" ) else oO0OO
 OoOOoO0oOo = oOoOo if lisp . lisp_is_running ( "lisp-etr" ) else oO0OO
 O0ooOOOO0O0 = oOoOo if lisp . lisp_is_running ( "lisp-rtr" ) else oO0OO
 i1IIi1i1Ii1 = oOoOo if lisp . lisp_is_running ( "lisp-mr" ) else oO0OO
 Iiio0Oo0oO = oOoOo if lisp . lisp_is_running ( "lisp-ms" ) else oO0OO
 iIII1iiIi11 = oOoOo if lisp . lisp_is_running ( "lisp-ddt" ) else oO0OO
 if 84 - 84: i11iIiiIii * OoO0O00
 i1iiI11I = '''
        <center>
        <i><b>LISP Subsystem Run Status:</b>
        </center><br>
        <table border="1" align="center">
        <tr>
        <th><i>ITR</i></th>
        <th><i>RTR</i></th>
        <th><i>ETR</i></th>
        <th><i>MR</i></th>
        <th><i>DDT</i></th>
        <th><i>MS</i></th>
        </tr>
        <tr align="center">
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        </tr>
        </table>
        <br>
    ''' . format ( OoiIIIiIi1I1i , O0ooOOOO0O0 , OoOOoO0oOo , i1IIi1i1Ii1 , iIII1iiIi11 , Iiio0Oo0oO )
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 i1iiI11I += '''
        <center>
        <style type="text/css">
        form { display:inline }
        </style>

        <a href="/lisp/show/status">
        <button style="background-color:transparent;border-radius:10px;
        type="button">system status</button></a>
    '''
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 III1I = lisp_get_clause_for_api ( "lisp debug" ) [ 0 ]
 III1I = III1I [ "lisp debug" ] if III1I . has_key ( "lisp debug" ) else None
 I1I111iIi = "lisp xtr-parameters"
 OoOOOO = lisp_get_clause_for_api ( I1I111iIi ) [ 0 ]
 I1iiIi111I = False
 if ( OoOOOO . has_key ( I1I111iIi ) ) :
  Iiii1iIii = { "data-plane-logging" : "yes" }
  oOoooO000O = { "flow-logging" : "yes" }
  I1iiIi111I = ( Iiii1iIii in OoOOOO [ I1I111iIi ] or oOoooO000O in OoOOOO [ I1I111iIi ] )
  if 49 - 49: o0oOOo0O0Ooo * Ii1I + I11i + iII111i
  if 30 - 30: o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 I1III111i = { }
 for iiI1iii in III1I : I1III111i [ iiI1iii . keys ( ) [ 0 ] ] = iiI1iii . values ( ) [ 0 ]
 III1I = I1III111i
 III1I [ "ddt" ] = III1I [ "ddt-node" ]
 III1I [ "mr" ] = III1I [ "map-resolver" ]
 III1I [ "ms" ] = III1I [ "map-server" ]
 if 79 - 79: OoO0O00 * OoOoOO00 . OoooooooOO - I11i * o0oOOo0O0Ooo
 if 78 - 78: IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 III11I1 = commands . getoutput ( "wc -l logs/lisp-core.log" )
 III11I1 = III11I1 . replace ( " " , "" )
 III11I1 = III11I1 . split ( "logs" ) [ 0 ]
 oo0ooooO = "on" if III1I [ "core" ] == "yes" else "off"
 i1iiI11I += '''
        <form>
        <select size="1" style="width: 110px"
                onchange="parent.window.location=this.value">
        <option value="">show logging:</option>
        <option value="/lisp/show/log/lisp-core/100">[{}] core log [{}]
        </option>''' . format ( oo0ooooO , III11I1 )
 if 12 - 12: II111iiii
 if ( os . path . exists ( "./logs/lisp-itr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-itr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  oo0ooooO = "on" if III1I [ "itr" ] == "yes" else "off"
  i1iiI11I += '''
            <option value="/lisp/show/log/lisp-itr/100">[{}] ITR log [{}]
            </option>''' . format ( oo0ooooO , III11I1 )
  if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if ( os . path . exists ( "./logs/lisp-rtr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-rtr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  oo0ooooO = "on" if III1I [ "rtr" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-rtr/100">[{}] RTR 
           log [{}]</option>''' . format ( oo0ooooO , III11I1 )
  if 25 - 25: oO0o
 if ( os . path . exists ( "./logs/lisp-etr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-etr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  oo0ooooO = "on" if III1I [ "etr" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-etr/100">[{}] ETR 
            log [{}]</option>''' . format ( oo0ooooO , III11I1 )
  if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if ( os . path . exists ( "./logs/lisp-xtr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-xtr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  oo0ooooO = "on" if III1I [ "itr" ] == "yes" or III1I [ "etr" ] == "yes" or III1I [ "rtr" ] == "yes" else "off"
  if 43 - 43: I1ii11iIi11i - iII111i
  i1iiI11I += '''<option value="/lisp/show/log/lisp-xtr/100">[{}] XTR 
           log [{}]</option>''' . format ( oo0ooooO , III11I1 )
  if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if ( os . path . exists ( "./logs/lisp-mr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-mr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  oo0ooooO = "on" if III1I [ "mr" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-mr/100">[{}] MR 
            log [{}] </option>''' . format ( oo0ooooO , III11I1 )
  if 47 - 47: iII111i
 if ( os . path . exists ( "./logs/lisp-ddt.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-ddt.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  oo0ooooO = "on" if III1I [ "ddt" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-ddt/100">[{}] DDT 
            log [{}]</option>''' . format ( oo0ooooO , III11I1 )
  if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if ( os . path . exists ( "./logs/lisp-ms.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-ms.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  oo0ooooO = "on" if III1I [ "ms" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-ms/100">[{}] MS 
            log [{}]</option>''' . format ( oo0ooooO , III11I1 )
  if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 iIii11iI1II = lisp_is_any_xtr_logging_on ( "flow-logging" )
 if ( os . path . exists ( "./logs/lisp-flow.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-flow.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  oo0ooooO = "on" if iIii11iI1II else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-flow/100">[{}] flow 
            log [{}]</option>''' . format ( oo0ooooO , III11I1 )
  if 42 - 42: ooOoO0o - I1IiiI + I1ii11iIi11i % Ii1I
 i1iiI11I += "</select></form>"
 if 44 - 44: i1IIi - O0 - I1ii11iIi11i * I1ii11iIi11i + OoOoOO00
 if 56 - 56: ooOoO0o / iIii1I11I1II1 . Ii1I % OoOoOO00 + OOooOOo
 if 10 - 10: I1Ii111 * i11iIiiIii - iIii1I11I1II1 . Oo0Ooo - I1ii11iIi11i
 if 20 - 20: I1ii11iIi11i / I1IiiI * OoO0O00 * I1IiiI * O0
 I11IIIiIi11 = lisp_is_user_superuser ( None )
 if ( I11IIIiIi11 ) :
  i1iiI11I += '''
            <form>
            <select size="1" style="width: 120px"
                    onchange="parent.window.location=this.value">
            <option value="">manage logging:</option>
        '''
  if 1 - 1: iIii1I11I1II1 + Oo0Ooo / O0 - iII111i % IiII + IiII
  if 24 - 24: I1IiiI + Oo0Ooo + OOooOOo - OoooooooOO + Oo0Ooo
  if 93 - 93: ooOoO0o . iIii1I11I1II1 % i11iIiiIii . OoOoOO00 % ooOoO0o + O0
  if 65 - 65: Ii1I + OoO0O00 - OoooooooOO
  if 51 - 51: Oo0Ooo + oO0o / iII111i - i1IIi
  if ( "yes" in III1I . values ( ) or I1iiIi111I ) :
   i1iiI11I += '''<option value="/lisp/debug/{}%{}">disable all logging
                </option>''' . format ( "disable" , "all" )
   if 51 - 51: Oo0Ooo - I1ii11iIi11i * I11i
   if 12 - 12: iIii1I11I1II1 % ooOoO0o % ooOoO0o
  o0 = False
  i1iI1iiI1I = False
  for oO00oo000O in III1I :
   if ( lisp . lisp_is_running ( "lisp-" + oO00oo000O ) == False ) : continue
   if 7 - 7: O0 / iII111i * oO0o
   if ( oO00oo000O in [ "itr" , "etr" , "rtr" ] ) :
    o0 = True
    i1iI1iiI1I = True
    if 29 - 29: o0oOOo0O0Ooo
    if 86 - 86: II111iiii . IiII
   iIiI = III1I [ oO00oo000O ]
   oO00Ooo0oO = oO00oo000O
   if ( oO00Ooo0oO == "mr" ) : oO00Ooo0oO = "map-resolver"
   if ( oO00Ooo0oO == "ms" ) : oO00Ooo0oO = "map-server"
   if ( oO00Ooo0oO == "ddt" ) : oO00Ooo0oO = "ddt-node"
   if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
   i1iiI11I += '''<option value="/lisp/debug/{}%{}">{} {} logging
                </option>''' . format ( oO00Ooo0oO , "yes" if iIiI == "no" else "no" ,
 "enable" if iIiI == "no" else "disable" ,
 oO00oo000O . upper ( ) if oO00oo000O != "core" else "core" )
   if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
  if ( o0 ) :
   o0o = lisp_is_any_xtr_logging_on ( "data-plane-logging" )
   i1iiI11I += '''<option value="/lisp/debug/data-plane-logging%{}">{} 
                data-plane logging </option>''' . format ( "yes" if o0o == False else "no" ,
   # OOooOOo + OOooOOo * I1Ii111 . ooOoO0o - I1Ii111 + IiII
 "enable" if o0o == False else "disable" )
   if 34 - 34: OOooOOo . Oo0Ooo
  if ( i1iI1iiI1I ) :
   o0o = iIii11iI1II
   i1iiI11I += '''<option value="/lisp/debug/flow-logging%{}">{} 
                flow logging </option>''' . format (
 "yes" if o0o == False else "no" ,
 "enable" if o0o == False else "disable" )
   if 78 - 78: I1ii11iIi11i % I1IiiI / OoooooooOO % OOooOOo - iII111i
  i1iiI11I += "</select></form>"
  if 2 - 2: iIii1I11I1II1
  if 45 - 45: OoooooooOO / i11iIiiIii
 i1iiI11I += "<br><br>"
 if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
 if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
 if 17 - 17: Ii1I
 if 39 - 39: ooOoO0o . II111iiii
 iIiIi1iI11iiI = lisp . lisp_button ( "{}:<br>show map-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-itr" ) ) :
  iIiIi1iI11iiI = '<a href="/lisp/show/itr/map-cache">' + iIiIi1iI11iiI + '</a>'
  iIiIi1iI11iiI = iIiIi1iI11iiI . format ( lisp . green ( "ITR" , True ) )
 else :
  iIiIi1iI11iiI = iIiIi1iI11iiI . format ( lisp . red ( "ITR" , True ) )
  iIiIi1iI11iiI = lisp . lisp_span ( iIiIi1iI11iiI , "ITR not running" )
  if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
  if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
 o0OO0O0OO0oO0 = lisp . lisp_button ( "{}:<br>show map-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-rtr" ) ) :
  o0OO0O0OO0oO0 = '<a href="/lisp/show/rtr/map-cache">' + o0OO0O0OO0oO0 + '</a>'
  o0OO0O0OO0oO0 = o0OO0O0OO0oO0 . format ( lisp . green ( "RTR" , True ) )
 else :
  o0OO0O0OO0oO0 = o0OO0O0OO0oO0 . format ( lisp . red ( "RTR" , True ) )
  o0OO0O0OO0oO0 = lisp . lisp_span ( o0OO0O0OO0oO0 , "RTR not running" )
  if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
  if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 oO = lisp . lisp_button ( "{}:<br>show referral-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-mr" ) ) :
  oO = '<a href="/lisp/show/referral">' + oO + '</a>'
  oO = oO . format ( lisp . green ( "MR" , True ) )
 else :
  oO = oO . format ( lisp . red ( "MR" , True ) )
  oO = lisp . lisp_span ( oO , "MR not running" )
  if 31 - 31: OoO0O00 * i11iIiiIii * Ii1I . i11iIiiIii
  if 12 - 12: OoOoOO00 % IiII % I1ii11iIi11i . i11iIiiIii * iIii1I11I1II1
 oo0oooo0OoO0o = lisp . lisp_button ( "{}:<br>show delegations" , None )
 if ( lisp . lisp_is_running ( "lisp-ddt" ) ) :
  oo0oooo0OoO0o = '<a href="/lisp/show/delegations">' + oo0oooo0OoO0o + '</a>'
  oo0oooo0OoO0o = oo0oooo0OoO0o . format ( lisp . green ( "DDT" , True ) )
 else :
  oo0oooo0OoO0o = oo0oooo0OoO0o . format ( lisp . red ( "DDT" , True ) )
  oo0oooo0OoO0o = lisp . lisp_span ( oo0oooo0OoO0o , "DDT not running" )
  if 50 - 50: iII111i / iII111i + OOooOOo * ooOoO0o / I1ii11iIi11i
  if 14 - 14: Ii1I % I1IiiI - iIii1I11I1II1 . OOooOOo + OoO0O00 - I1Ii111
 iI1iIiiiI1I1 = lisp . lisp_button ( "{}:<br>show site-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-ms" ) ) :
  iI1iIiiiI1I1 = '<a href="/lisp/show/site">' + iI1iIiiiI1I1 + '</a>'
  iI1iIiiiI1I1 = iI1iIiiiI1I1 . format ( lisp . green ( "MS" , True ) )
 else :
  iI1iIiiiI1I1 = iI1iIiiiI1I1 . format ( lisp . red ( "MS" , True ) )
  iI1iIiiiI1I1 = lisp . lisp_span ( iI1iIiiiI1I1 , "MS not running" )
  if 78 - 78: oO0o / OoO0O00 - oO0o * OoooooooOO . OoOoOO00
  if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
 Ii1Iii11 = lisp . lisp_button ( "{}:<br>show database-mappings" , None )
 if ( lisp . lisp_is_running ( "lisp-etr" ) ) :
  Ii1Iii11 = '<a href="/lisp/show/database">' + Ii1Iii11 + '</a>'
  Ii1Iii11 = Ii1Iii11 . format ( lisp . green ( "ETR" , True ) )
 else :
  Ii1Iii11 = Ii1Iii11 . format ( lisp . red ( "ETR" , True ) )
  Ii1Iii11 = lisp . lisp_span ( Ii1Iii11 , "ETR not running" )
  if 97 - 97: OOooOOo / oO0o . II111iiii
  if 44 - 44: Ii1I % I11i . I1Ii111
 Ii11Iii = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 ooo00OoOO0o = lisp . lisp_geo_help_hover ( '<input type="text" name="geo-point" size="30" required />' )
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 iii1IiI1I1 = lisp . lisp_geo_help_hover ( '<input type="text" name="geo-prefix" size="30" required />' )
 if 64 - 64: ooOoO0o / O0 * OoOoOO00 * ooOoO0o
 if 60 - 60: I11i / i1IIi % I1ii11iIi11i / I1ii11iIi11i * I1ii11iIi11i . i11iIiiIii
 o0oOO00 = lisp . lisp_button ( "API Documentation" , "/lisp/show/api-doc" )
 ii11iiIi = lisp . lisp_button ( "Command Documentation" , "/lisp/show/command-doc" )
 i11iI11I1I = lisp . lisp_button ( "IETF LISP WG Drafts" ,
 "http://datatracker.ietf.org/wg/lisp/" )
 Ii1iiIi1I11i = lisp . lisp_button ( "ddt-root.org" , "http://ddt-root.net" )
 O0OOO = lisp . lisp_button ( "LISP Facebook Group" ,
 "https://www.facebook.com/groups/407716795982512" )
 ii1i1iiI = lisp . lisp_button ( "LISP LinkedIn Group" ,
 "http://www.linkedin.com/groups/3776183" )
 if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 iIIi11 = lisp . lisp_space ( 2 )
 i1iiI11I += '''     
        <table><tr>
          <td width="50%" align="center">
          <table border="1">
            <tr><td align="center"><i><b>Data-Plane</b></i><br>
            {}{}{}{}{}{}{}
            </td></tr>
          </table>
          </td>
 
          <td width="50%" align="center">
          <table border="1">
            <tr><td align="center"><i><b>Control-Plane</b></i><br>
            {}{}{}{}{}{}{}
            </td></tr>
          </table>
          </td>
        </tr></table>

        <br><hr><br>

        <form action="/lisp/lig" method="post">
        <font face="Courier New" size="2">
        Run <b><i>lig</i></b> on EID: {}
        to Map-Resolver: <input type="text" name="mr" />
        count (1-5): <input type="text" name="count" />
        no-nat: <input type="checkbox" name="no-nat" value="yes">
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form><br><br>

        <form action="/lisp/rig" method="post">
        <font face="Courier New" size="2">
        Run <b><i>rig</i></b> on EID: {}
        to any DDT-node: <input type="text" name="ddt" />
        follow-all-referrals: <input type="checkbox" name="follow" 
        value="yes">
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form><br><br>

        <form action="/lisp/geo" method="post">
        <font face="Courier New" size="2">
        Run <b><i>geo-test</i></b> on geo-point: {}
        for geo-prefix: {}
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form>
        </center><br>

        <hr>
        <center><br>{}{}{}{}{}{}
        </center>

    ''' . format ( iIIi11 , iIiIi1iI11iiI , iIIi11 , o0OO0O0OO0oO0 , iIIi11 , Ii1Iii11 , iIIi11 , iIIi11 , oO , iIIi11 , oo0oooo0OoO0o , iIIi11 , iI1iIiiiI1I1 , iIIi11 ,
 Ii11Iii , Ii11Iii , ooo00OoOO0o , iii1IiI1I1 , o0oOO00 , ii11iiIi , i11iI11I1I , Ii1iiIi1I11i , O0OOO , ii1i1iiI )
 if 54 - 54: Ii1I - I1Ii111
 return ( lisp_show_wrapper ( i1iiI11I ) )
 if 81 - 81: IiII . O0 + II111iiii * iIii1I11I1II1 * OOooOOo / OoOoOO00
 if 88 - 88: II111iiii - o0oOOo0O0Ooo * I1IiiI . OoO0O00
 if 65 - 65: IiII . i1IIi
 if 95 - 95: I1IiiI + I1IiiI - OOooOOo - iII111i
 if 45 - 45: Ii1I . OoooooooOO
 if 27 - 27: Ii1I * Oo0Ooo . OoOoOO00
 if 17 - 17: II111iiii % iII111i * OOooOOo % i1IIi . I1IiiI . iIii1I11I1II1
 if 27 - 27: i11iIiiIii - I1IiiI
def lisp_drain_socket ( lisp_socket , process ) :
 lisp . lprint ( "Draining socket looking for {}" . format ( process ) )
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 iii11i1 = None
 while ( True ) :
  try :
   select . select ( [ lisp_socket ] , [ ] , [ ] )
  except :
   return ( iii11i1 )
   if 48 - 48: ooOoO0o * I1ii11iIi11i
   if 15 - 15: OoO0O00 * I11i % iIii1I11I1II1 * I1ii11iIi11i
  lisp . lisp_ipc_lock . acquire ( )
  iIiiIIi1iiII , oooO00Oo , ooO00o , i1iiI11I = lisp . lisp_receive ( lisp_socket , True )
  lisp . lisp_ipc_lock . release ( )
  if 73 - 73: iII111i * iII111i / ooOoO0o
  if ( oooO00Oo != process ) :
   lisp . lprint ( "Discarding IPC message from {}" . format ( oooO00Oo ) )
  elif ( iii11i1 == None ) :
   iii11i1 = i1iiI11I
   if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
   if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 return
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 if 83 - 83: o0oOOo0O0Ooo
def lisp_process_show_command ( lisp_socket , command ) :
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if 48 - 48: iII111i + IiII
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 i1i11ii1Ii = command . split ( "%" )
 i1i11ii1Ii = i1i11ii1Ii [ 0 ]
 if 12 - 12: OOooOOo . Ii1I
 if 79 - 79: I1Ii111 / Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + o0oOOo0O0Ooo
 if 73 - 73: O0 - I1ii11iIi11i
 if 2 - 2: II111iiii / I1Ii111
 oO00oo000O = lisp_commands [ i1i11ii1Ii ]
 oO00oo000O = oO00oo000O [ 0 ]
 if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 if ( lisp . lisp_is_running ( oO00oo000O ) == False ) :
  i1iiI11I = ( "<i>Process '{}' is not running, command cannot be " + "executed</i><br>" ) . format ( oO00oo000O )
  if 22 - 22: ooOoO0o . iIii1I11I1II1
  return ( lisp_show_wrapper ( i1iiI11I ) )
  if 12 - 12: Ii1I
  if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 command = lisp . lisp_command_ipc ( command , "lisp-core" )
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 lisp . lisp_ipc_lock . acquire ( )
 if 77 - 77: II111iiii
 lisp . lisp_ipc ( command , lisp_socket , oO00oo000O )
 lisp . lprint ( "Waiting for response to show command '{}'" . format ( command ) )
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 iIiiIIi1iiII , oooO00Oo , ooO00o , i1iiI11I = lisp . lisp_receive ( lisp_socket , True )
 if 68 - 68: oO0o
 lisp . lisp_ipc_lock . release ( )
 if 10 - 10: Ii1I
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if ( oooO00Oo == "" ) :
  lisp . lprint ( "Command '{}' timed out to {}" . format ( command , oO00oo000O ) )
 elif ( oooO00Oo != oO00oo000O ) :
  lisp . lprint ( "Received response from {} but expecting from {}" . format ( oooO00Oo , oO00oo000O ) )
  if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
  i1iiI11I = lisp_drain_socket ( lisp_socket , oO00oo000O )
  if ( i1iiI11I == None ) : i1iiI11I = "<i>Fatal error, retry later</i><br>"
  if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 return ( lisp_show_wrapper ( i1iiI11I ) )
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
def lisp_start_stop_process ( process , startstop ) :
 if ( startstop and lisp . lisp_is_running ( process ) ) : return
 if ( startstop == False and lisp . lisp_is_running ( process ) == False ) : return
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 oO0O = process + ".pyo"
 Iiii1I = "./logs/" + process + ".log"
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if ( lisp . lisp_is_ubuntu ( ) or lisp . lisp_is_raspbian ( ) or lisp . lisp_is_debian ( ) or lisp . lisp_is_debian_kali ( ) ) :
  if 81 - 81: IiII / OoOoOO00 * IiII . O0
  OOOOo00oo00O = "python -O " + oO0O + " 2>&1 > " + Iiii1I + " &"
 else :
  OOOOo00oo00O = "python -O " + oO0O + " >& " + Iiii1I + " &"
  if 83 - 83: II111iiii * i1IIi * iII111i . I1ii11iIi11i / I11i + i1IIi
  if 43 - 43: OoooooooOO
 oOOO0 = commands . getoutput ( "date" )
 if ( startstop and os . path . exists ( oO0O ) ) :
  lisp . lprint ( "Start process '{}' on {}" . format ( process , oOOO0 ) )
  os . system ( OOOOo00oo00O )
  time . sleep ( 1 )
  return
  if 32 - 32: ooOoO0o % I1Ii111 * Oo0Ooo
  if 72 - 72: ooOoO0o . iII111i - I1Ii111 - Ii1I % i1IIi
 if ( startstop == False and os . path . exists ( oO0O ) ) :
  lisp . lprint ( "Stop process '{}' on {}" . format ( process , oOOO0 ) )
  oO0o00O0O0oo0 = commands . getoutput ( "pgrep -f " + oO0O )
  oO0o00O0O0oo0 = oO0o00O0O0oo0 . split ( "\n" ) [ 0 ]
  os . system ( "kill " + oO0o00O0O0oo0 )
  os . system ( "rm " + process )
  return
  if 24 - 24: I1Ii111 * oO0o
 return
 if 88 - 88: i11iIiiIii + iII111i * OoOoOO00 * iII111i + I11i
 if 88 - 88: OOooOOo % Oo0Ooo - iII111i - OoOoOO00 % i11iIiiIii
 if 6 - 6: Ii1I - OoO0O00 . I1IiiI - O0
 if 16 - 16: iII111i * iII111i % Ii1I % I1IiiI
 if 48 - 48: OOooOOo / Ii1I % OoO0O00 / IiII / I1Ii111
 if 89 - 89: I1Ii111 * oO0o
 if 63 - 63: OoooooooOO * OoooooooOO % OoO0O00 + O0 / I1Ii111 + iIii1I11I1II1
def lisp_enable_command ( clause ) :
 if 72 - 72: OoOoOO00 * iIii1I11I1II1 % I11i
 if 20 - 20: II111iiii % iIii1I11I1II1 + oO0o * II111iiii * OoO0O00 % OoO0O00
 if 15 - 15: oO0o / I1Ii111
 if 37 - 37: i11iIiiIii + I1IiiI . OOooOOo % I11i % I11i
 if 26 - 26: O0
 if 34 - 34: ooOoO0o * I1Ii111
 if 97 - 97: i11iIiiIii % oO0o / Oo0Ooo / Oo0Ooo
 if ( os . path . exists ( "lisp.py" ) and os . path . exists ( "lisp.pyo" ) == False ) :
  lisp . lprint ( "In manual mode, ignoring 'lisp enable' command" )
  return ( clause )
  if 97 - 97: II111iiii - I1Ii111 - iIii1I11I1II1 * I1IiiI
  if 54 - 54: iIii1I11I1II1
 o00oO00 = clause . split ( " " )
 o00oO00 = o00oO00 [ 0 ] + " " + o00oO00 [ 1 ]
 if 5 - 5: IiII
 I1IiIiiIiIII = lisp_core_commands [ "lisp enable" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 if 19 - 19: II111iiii - IiII
 iII1iii , I1iii11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
 if ( iII1iii == True ) : return ( I1iii11 )
 if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
 oo00o0 = { "itr" : "lisp-itr" , "etr" : "lisp-etr" , "rtr" : "lisp-rtr" ,
 "map-resolver" : "lisp-mr" , "map-server" : "lisp-ms" ,
 "ddt-node" : "lisp-ddt" }
 if 17 - 17: Ii1I / iIii1I11I1II1 - OoO0O00 + I1IiiI % OOooOOo
 if 14 - 14: o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
 if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
 if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
 for OoooooOo in oo00o0 . keys ( ) :
  OooOo = True if I1IiIiiIiIII [ OoooooOo ] == "yes" else False
  lisp_start_stop_process ( oo00o0 [ OoooooOo ] , OooOo )
  if 67 - 67: Oo0Ooo / O0
 return ( I1iii11 )
 if 88 - 88: OoOoOO00 - OOooOOo
 if 63 - 63: IiII * OoooooooOO
 if 19 - 19: IiII - o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00 / OOooOOo
 if 87 - 87: OoOoOO00 - ooOoO0o - OOooOOo + Oo0Ooo % iIii1I11I1II1 / i11iIiiIii
 if 12 - 12: ooOoO0o
 if 86 - 86: oO0o - OoO0O00
 if 63 - 63: I1IiiI / OoOoOO00 + OoooooooOO . I11i . ooOoO0o
def lisp_debug_command ( lisp_socket , clause , single_process ) :
 o00oO00 = clause . split ( " " )
 o00oO00 = o00oO00 [ 0 ] + " " + o00oO00 [ 1 ]
 if 48 - 48: i1IIi - iII111i - i11iIiiIii . I11i - iII111i * I11i
 I1IiIiiIiIII = lisp_core_commands [ "lisp debug" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 60 - 60: OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 iII1iii , I1iii11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if ( iII1iii == True ) : return ( I1iii11 )
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 oo00o0 = { "itr" : "lisp-itr" , "etr" : "lisp-etr" , "rtr" : "lisp-rtr" ,
 "map-resolver" : "lisp-mr" , "map-server" : "lisp-ms" ,
 "ddt-node" : "lisp-ddt" , "core" : "" }
 if 74 - 74: oO0o
 for iII1i1IIiI1I in I1IiIiiIiIII :
  oO00oo000O = oo00o0 [ iII1i1IIiI1I ]
  if ( single_process and single_process != oO00oo000O ) : continue
  if 67 - 67: Ii1I
  iIiI = I1IiIiiIiIII [ iII1i1IIiI1I ]
  o00oO00 = ( "lisp debug {\n" + "    {} = {}\n" . format ( iII1i1IIiI1I , iIiI ) + "}\n" )
  if 43 - 43: OoO0O00 % OoO0O00
  if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
  if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
  if 45 - 45: Ii1I - OOooOOo
  if ( iII1i1IIiI1I == "core" ) :
   lisp_process_command ( None , None , o00oO00 , None , [ None ] )
   continue
   if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
   if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
  o00oO00 = lisp . lisp_command_ipc ( o00oO00 , "lisp-core" )
  lisp . lisp_ipc ( o00oO00 , lisp_socket , oO00oo000O )
  if ( single_process ) : break
  if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 return ( I1iii11 )
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
def lisp_replace_password_in_clause ( clause , keyword_string ) :
 O0OO0O = clause . find ( keyword_string )
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if ( O0OO0O == - 1 ) : return ( clause )
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 O0OO0O += len ( keyword_string )
 o0o0O0O00oOOo = clause [ O0OO0O : : ] . find ( "\n" )
 o0o0O0O00oOOo += O0OO0O
 IiiiI1 = clause [ O0OO0O : o0o0O0O00oOOo ] . replace ( " " , "" )
 if 24 - 24: ooOoO0o - I11i * oO0o
 if ( len ( IiiiI1 ) != 0 and IiiiI1 [ 0 ] == "=" ) : return ( clause )
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 IiiiI1 = IiiiI1 . replace ( " " , "" )
 IiiiI1 = IiiiI1 . replace ( "\t" , "" )
 IiiiI1 = lisp_hash_password ( IiiiI1 )
 clause = clause [ 0 : O0OO0O ] + " =" + IiiiI1 + clause [ o0o0O0O00oOOo : : ]
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 return ( clause )
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
def lisp_user_account_command ( clause ) :
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 o00oO00 = clause . split ( " " )
 o00oO00 = o00oO00 [ 0 ] + " " + o00oO00 [ 1 ]
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 I1IiIiiIiIII = lisp_core_commands [ "lisp user-account" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 iII1iii , I1iii11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if ( iII1iii == False ) :
  I1iii11 = lisp_replace_password_in_clause ( I1iii11 , "password =" )
  if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 return ( I1iii11 )
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
def lisp_rtr_list_command ( clause ) :
 o00oO00 = clause . split ( " " )
 o00oO00 = o00oO00 [ 0 ] + " " + o00oO00 [ 1 ]
 if 12 - 12: I1ii11iIi11i / Ii1I
 I1IiIiiIiIII = lisp_core_commands [ "lisp rtr-list" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 5 - 5: OoooooooOO
 if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
 if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
 if 93 - 93: Oo0Ooo / I1ii11iIi11i + i1IIi * oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 iII1iii , I1iii11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if ( iII1iii ) : return ( I1iii11 )
 if 33 - 33: I11i % II111iiii + OoO0O00
 lisp . lisp_ms_rtr_list = [ ]
 if ( I1IiIiiIiIII . has_key ( "address" ) ) :
  for Ii1I1i in I1IiIiiIiIII [ "address" ] :
   II = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   II . store_address ( Ii1I1i )
   lisp . lisp_ms_rtr_list . append ( II )
   if 93 - 93: i1IIi . IiII / I1IiiI + IiII
   if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 return ( I1iii11 )
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
def lisp_process_command_lines ( lisp_socket , old , new , line ) :
 o00oO00 = line . split ( "{" )
 o00oO00 = o00oO00 [ 0 ]
 o00oO00 = o00oO00 [ 0 : - 1 ]
 if 33 - 33: Ii1I
 lisp . lprint ( "Process the '{}' command" . format ( o00oO00 ) )
 if 93 - 93: ooOoO0o
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 if 19 - 19: I1ii11iIi11i
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if ( lisp_commands . has_key ( o00oO00 ) == False ) :
  line = "#>>> " + line . replace ( "\n" , " <<< invalid command\n" )
  new . write ( line )
  return
  if 66 - 66: O0
  if 52 - 52: OoO0O00 * OoooooooOO
  if 12 - 12: O0 + IiII * i1IIi . OoO0O00
  if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
  if 28 - 28: iIii1I11I1II1
 iI11II1i1I1 = lisp_commands [ o00oO00 ]
 o0oo00O0o = False
 for oO00oo000O in iI11II1i1I1 :
  if ( oO00oo000O == "" ) :
   line = lisp_write_error ( line , "invalid command" )
   new . write ( line )
   return
   if 57 - 57: i1IIi * II111iiii * oO0o
   if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
  if ( o0oo00O0o == False ) :
   iIi11I11 = line
   III11I1 = 1
   for line in old :
    if ( lisp_begin_clause ( line ) ) : III11I1 += 1
    iIi11I11 += line
    if ( lisp_end_clause ( line ) ) :
     III11I1 -= 1
     if ( III11I1 == 0 ) : break
     if 40 - 40: iIii1I11I1II1
     if 92 - 92: OoOoOO00 % O0
     if 55 - 55: iIii1I11I1II1 * iII111i
     if 85 - 85: iIii1I11I1II1 . II111iiii
     if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
     if 22 - 22: OOooOOo
     if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
  if ( lisp . lisp_is_running ( oO00oo000O ) == False ) :
   if ( o0oo00O0o == False ) :
    for line in iIi11I11 : new . write ( line )
    o0oo00O0o = True
    if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
   lisp . lprint ( "Process '{}' is not running, do not send command" . format ( oO00oo000O ) )
   if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
   continue
   if 94 - 94: i1IIi
   if 36 - 36: I1IiiI + Oo0Ooo
   if 46 - 46: iII111i
   if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
   if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
   if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
  if ( oO00oo000O == "lisp-core" ) :
   if ( iIi11I11 . find ( "enable" ) != - 1 ) :
    I1iii11 = lisp_enable_command ( iIi11I11 )
    if 65 - 65: ooOoO0o - i1IIi
   if ( iIi11I11 . find ( "debug" ) != - 1 ) :
    I1iii11 = lisp_debug_command ( lisp_socket , iIi11I11 , None )
    if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
   if ( iIi11I11 . find ( "user-account" ) != - 1 ) :
    I1iii11 = lisp_user_account_command ( iIi11I11 )
    if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
   if ( iIi11I11 . find ( "rtr-list" ) != - 1 ) :
    I1iii11 = lisp_rtr_list_command ( iIi11I11 )
    if 34 - 34: I1Ii111 - OOooOOo
  else :
   IIIiIi1iiI = lisp . lisp_command_ipc ( iIi11I11 , "lisp-core" )
   lisp . lisp_ipc ( IIIiIi1iiI , lisp_socket , oO00oo000O )
   lisp . lprint ( "Waiting for response to config command '{}'" . format ( o00oO00 ) )
   if 15 - 15: I1ii11iIi11i . iII111i
   if 94 - 94: I11i . I1IiiI
   iIiiIIi1iiII , oooO00Oo , ooO00o , I1iii11 = lisp . lisp_receive ( lisp_socket ,
 True )
   if 73 - 73: i1IIi / II111iiii
   if ( oooO00Oo == "" ) :
    lisp . lprint ( "Command timed out to {}" . format ( oO00oo000O ) )
    I1iii11 = iIi11I11
   elif ( oooO00Oo != oO00oo000O ) :
    lisp . lprint ( "Fatal IPC error to {}, source {}" . format ( oO00oo000O ,
 oooO00Oo ) )
    if 45 - 45: Ii1I / ooOoO0o . OoooooooOO + OoO0O00
    if 51 - 51: iII111i % i11iIiiIii % IiII + I1Ii111 % I1ii11iIi11i
    if 16 - 16: OoOoOO00 / Oo0Ooo + O0 - OoOoOO00 . OoooooooOO
    if 19 - 19: o0oOOo0O0Ooo
    if 73 - 73: I1Ii111 * Oo0Ooo * OoOoOO00
    if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
    if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
  if ( o0oo00O0o == False ) :
   for line in I1iii11 : new . write ( line )
   o0oo00O0o = True
   if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
   if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 return
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
def lisp_process_config_file ( lisp_socket , file_name , startup ) :
 lisp . lprint ( "Processing configuration file {}" . format ( file_name ) )
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo
 if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 if ( os . path . exists ( file_name ) == False ) :
  lisp . lprint ( "LISP configuration file '{}' does not exist" . format ( file_name ) )
  if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
  return
  if 89 - 89: oO0o
  if 87 - 87: iII111i % Oo0Ooo
 OOo000o = file_name + ".diff"
 iiIIIIiI111 = file_name + ".bak"
 OoooOO0Oo0 = file_name + ".temp"
 I1iIiIii = "# lispers.net lisp.config file"
 if 76 - 76: OoO0O00 . OoooooooOO % I1Ii111 * Ii1I
 if 23 - 23: IiII + iIii1I11I1II1
 if 14 - 14: O0 % IiII % Ii1I * oO0o
 if 65 - 65: I11i % oO0o + I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 / O0 . I1Ii111 % iIii1I11I1II1 % Oo0Ooo
 O0O0Ooooo000 = 'egrep "{}" {}' . format ( I1iIiIii , file_name )
 iIi1I1 = commands . getoutput ( O0O0Ooooo000 )
 if ( iIi1I1 == "" ) :
  lisp . lprint ( "*** lisp.config configuration file is corrupt ***" )
  return
  if 86 - 86: i11iIiiIii - o0oOOo0O0Ooo . ooOoO0o * Oo0Ooo / Ii1I % o0oOOo0O0Ooo
  if 61 - 61: o0oOOo0O0Ooo + OoOoOO00
  if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
  if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
  if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
  if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
 I1Ii = open ( file_name , "r" )
 O00Ooo0ooo0 = open ( OoooOO0Oo0 , "w" )
 for II1i in I1Ii :
  if ( II1i . find ( I1iIiIii ) == 0 ) :
   if ( startup ) :
    O00Ooo0ooo0 . write ( II1i )
   else :
    lisp_write_last_changed_date ( O00Ooo0ooo0 , II1i )
    if 74 - 74: I11i
   continue
   if 58 - 58: iIii1I11I1II1 * OoO0O00 * I1Ii111 * ooOoO0o . OoooooooOO
   if 6 - 6: I1ii11iIi11i - oO0o * i11iIiiIii + OoOoOO00 / ooOoO0o % OOooOOo
  if ( II1i . find ( "# Hostname:" ) == 0 ) :
   O00Ooo0ooo0 . write ( "# Hostname: " + lisp . lisp_hostname + "\n" )
   continue
   if 38 - 38: OOooOOo % IiII % II111iiii - Oo0Ooo - iIii1I11I1II1
   if 9 - 9: o0oOOo0O0Ooo % I1ii11iIi11i . I1ii11iIi11i
  if ( lisp_end_file ( II1i ) ) :
   O00Ooo0ooo0 . write ( II1i + "\n" )
   break
   if 28 - 28: OoooooooOO % oO0o + I1ii11iIi11i + O0 . I1Ii111
   if 80 - 80: i11iIiiIii % I1ii11iIi11i
  if ( lisp_comment ( II1i ) ) :
   O00Ooo0ooo0 . write ( II1i )
   continue
   if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
   if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
  O0oO0oo0O0 = II1i . replace ( " " , "" )
  O0oO0oo0O0 = O0oO0oo0O0 . replace ( "\n" , "" )
  if ( O0oO0oo0O0 == "" ) : continue
  if 66 - 66: OOooOOo - ooOoO0o - Oo0Ooo
  if 54 - 54: iII111i . i1IIi
  if 19 - 19: ooOoO0o % oO0o
  if 22 - 22: oO0o . II111iiii . Oo0Ooo
  lisp_process_command_lines ( lisp_socket , I1Ii , O00Ooo0ooo0 , II1i )
  if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
 I1Ii . close ( )
 O00Ooo0ooo0 . close ( )
 if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: oO0o
 if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
 if ( os . path . exists ( OOo000o ) == False ) :
  os . system ( "touch {}" . format ( OOo000o ) )
  if 97 - 97: I1Ii111 . I11i / I1IiiI
 if ( startup == False ) :
  os . system ( "diff {} {} > {}" . format ( iiIIIIiI111 , OoooOO0Oo0 , OOo000o ) )
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
  if 90 - 90: Oo0Ooo * I1IiiI
  if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
  if 28 - 28: IiII * I1IiiI % IiII
  if 95 - 95: O0 / I11i . I1Ii111
 os . system ( "cp {} {}; rm -f {}; cp {} {}" . format ( OoooOO0Oo0 , file_name ,
 OoooOO0Oo0 , file_name , iiIIIIiI111 ) )
 return
 if 17 - 17: I11i
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 if 22 - 22: oO0o * iII111i
def lisp_send_commands ( lisp_socket , process ) :
 iIIIiIi1i = "./lisp.config"
 iiIiiIi = open ( iIIIiIi1i , "r" )
 ooOo0o = False
 III = 0
 if 36 - 36: OoooooooOO / Oo0Ooo . I1Ii111 % OoooooooOO . OOooOOo + II111iiii
 if 43 - 43: I11i % Ii1I / o0oOOo0O0Ooo * I1Ii111
 if 85 - 85: iIii1I11I1II1 . OoooooooOO . o0oOOo0O0Ooo
 if 77 - 77: I1IiiI % ooOoO0o
 for II1i in iiIiiIi :
  if ( lisp_end_file ( II1i ) ) : break
  if ( lisp_comment ( II1i ) or II1i [ 0 ] == "\n" ) : continue
  if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
  if ( lisp_begin_clause ( II1i ) ) :
   if ( III == 0 ) :
    iIi11I11 = ""
    o00oO00 = II1i . split ( "{" )
    o00oO00 = o00oO00 [ 0 ]
    o00oO00 = o00oO00 [ 0 : - 1 ]
    if ( lisp_commands . has_key ( o00oO00 ) ) :
     ooOo0o = ( process in lisp_commands [ o00oO00 ] ) or ( o00oO00 == "lisp debug" )
     if 52 - 52: IiII % ooOoO0o
     if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
     if 23 - 23: i11iIiiIii
   III += 1
   if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
   if 65 - 65: II111iiii / Oo0Ooo
   if 42 - 42: i11iIiiIii . O0
   if 75 - 75: I1Ii111 + iIii1I11I1II1
   if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
  if ( ooOo0o ) : iIi11I11 += II1i
  if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
  if 92 - 92: I11i / O0 * I1IiiI - I11i
  if 99 - 99: i11iIiiIii % OoooooooOO
  if 56 - 56: IiII * I1Ii111
  if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
  if ( lisp_end_clause ( II1i ) == False ) : continue
  III -= 1
  if ( III != 0 ) : continue
  if ( ooOo0o == False ) : continue
  if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
  if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
  if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
  if 56 - 56: i1IIi . i11iIiiIii
  if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
  if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
  lisp . lprint ( "Send command '{}' to restarting process '{}'" . format ( o00oO00 , process ) )
  if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
  if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
  if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
  if 10 - 10: IiII / OoooooooOO
  if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
  if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
  if ( o00oO00 == "lisp debug" ) :
   lisp_debug_command ( lisp_socket , iIi11I11 , process )
   ooOo0o = False
   continue
   if 25 - 25: iIii1I11I1II1
   if 63 - 63: ooOoO0o
  iIi11I11 = lisp . lisp_command_ipc ( iIi11I11 , "lisp-core" )
  lisp . lisp_ipc ( iIi11I11 , lisp_socket , process )
  if 96 - 96: I11i
  if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
  if 63 - 63: iII111i
  if 11 - 11: iII111i - iIii1I11I1II1
  if 92 - 92: OoO0O00
  lisp . lprint ( "Waiting for response to config command '{}'" . format ( o00oO00 ) )
  if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
  if 12 - 12: ooOoO0o
  iIiiIIi1iiII , oooO00Oo , ooO00o , iiIII1II = lisp . lisp_receive ( lisp_socket , True )
  if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
  if ( oooO00Oo == "" ) :
   lisp . lprint ( "Command timed out to {}" . format ( process ) )
  elif ( oooO00Oo != process ) :
   lisp . lprint ( "Fatal IPC error to {}, IPC source {}" . format ( process ,
 oooO00Oo ) )
   if 60 - 60: OOooOOo . iII111i / iIii1I11I1II1 + OOooOOo * I1Ii111
  ooOo0o = False
  if 82 - 82: i11iIiiIii . iIii1I11I1II1 * I1IiiI - I11i + Ii1I
 return
 if 48 - 48: I1ii11iIi11i
 if 96 - 96: ooOoO0o . OoooooooOO
 if 39 - 39: OOooOOo + OoO0O00
 if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
 if 71 - 71: ooOoO0o . i11iIiiIii
 if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
 if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
def lisp_config_process ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 iIIIiIi1i = "./lisp.config"
 o0oOooO0oo00 = ""
 oO00oo = True
 if 89 - 89: Ii1I
 while ( True ) :
  Oo000o = os . path . getmtime ( iIIIiIi1i )
  if ( Oo000o != o0oOooO0oo00 ) :
   if 51 - 51: iII111i
   lisp . lisp_ipc_lock . acquire ( )
   lisp_process_config_file ( lisp_socket , iIIIiIi1i , oO00oo )
   lisp . lisp_ipc_lock . release ( )
   if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
   oO00oo = False
   o0oOooO0oo00 = os . path . getmtime ( iIIIiIi1i )
   if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  time . sleep ( 1 )
  if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
 return
 if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
 if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
 if 29 - 29: Ii1I / ooOoO0o % I11i
 if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
 if 79 - 79: O0
 if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
 if 15 - 15: I1ii11iIi11i
 if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
def lisp_map_resolver_command ( kv_pair ) :
 OO0o0o0oo = None
 if 40 - 40: Oo0Ooo
 for O00oO0 in kv_pair . keys ( ) :
  if ( O00oO0 == "mr-name" ) :
   OO0o0o0oo = kv_pair [ O00oO0 ] [ 0 ]
   continue
   if 47 - 47: OoOoOO00
  if ( O00oO0 == "address" or O00oO0 == "dns-name" ) :
   Oo0000o = kv_pair [ O00oO0 ]
   for oo00oO0O0 in Oo0000o :
    if ( oo00oO0O0 == "" ) : continue
    Ii1I1i = oo00oO0O0 if ( O00oO0 == "address" ) else None
    iI1IiiiIIiiII = oo00oO0O0 if ( O00oO0 == "dns-name" ) else None
    lisp . lisp_mr ( Ii1I1i , iI1IiiiIIiiII , OO0o0o0oo )
    if 94 - 94: OoOoOO00 + IiII . ooOoO0o
    if 69 - 69: O0 - O0
    if 41 - 41: IiII % o0oOOo0O0Ooo
 return
 if 67 - 67: O0 % I1Ii111
 if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
 if 39 - 39: Ii1I
 if 60 - 60: OOooOOo
 if 62 - 62: I1Ii111 * I11i
 if 74 - 74: OoOoOO00 . iIii1I11I1II1
 if 87 - 87: ooOoO0o
def lisp_map_cache_command ( kv_pair ) :
 IIo0oo0OO = [ ]
 for i11Ii1 in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  I11IIIII = lisp . lisp_mapping ( "" , "" , [ ] )
  IIo0oo0OO . append ( I11IIIII )
  if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
  if 44 - 44: I1Ii111 - IiII
 OOO = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for i11Ii1 in range ( len ( kv_pair [ "address" ] ) ) :
   i1iIIiiIiII = lisp . lisp_rloc ( )
   OOO . append ( i1iIIiiIiII )
   if 20 - 20: ooOoO0o . OoO0O00 * iII111i
   if 71 - 71: Oo0Ooo . II111iiii / II111iiii * Ii1I * OoO0O00
   if 25 - 25: i11iIiiIii + Oo0Ooo . iII111i % I1IiiI - ooOoO0o * i1IIi
 for O00oO0 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ O00oO0 ]
  if ( O00oO0 == "instance-id" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I11IIIII = IIo0oo0OO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 == "" ) : o00OoO0o0 = "0"
    I11IIIII . eid . instance_id = int ( o00OoO0o0 )
    I11IIIII . group . instance_id = int ( o00OoO0o0 )
    if 52 - 52: iII111i . oO0o - Ii1I
    if 85 - 85: I1ii11iIi11i / i1IIi * OoO0O00 . oO0o
  if ( O00oO0 == "eid-prefix" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I11IIIII = IIo0oo0OO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) : I11IIIII . eid . store_prefix ( o00OoO0o0 )
    if 60 - 60: I11i
    if 93 - 93: Oo0Ooo
  if ( O00oO0 == "group-prefix" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I11IIIII = IIo0oo0OO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) : I11IIIII . group . store_prefix ( o00OoO0o0 )
    if 75 - 75: OoOoOO00
    if 64 - 64: IiII / o0oOOo0O0Ooo / i1IIi
  if ( O00oO0 == "send-map-request" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I11IIIII = IIo0oo0OO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 == "yes" ) : I11IIIII . action = lisp . LISP_SEND_MAP_REQUEST_ACTION
    if 79 - 79: OOooOOo % I1Ii111 / oO0o - iIii1I11I1II1 - OoOoOO00
    if 60 - 60: II111iiii
  if ( O00oO0 == "rle-name" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) :
     i1iIIiiIiII . rle_name = o00OoO0o0
     if ( lisp . lisp_rle_list . has_key ( o00OoO0o0 ) ) :
      i1iIIiiIiII . rle = lisp . lisp_rle_list [ o00OoO0o0 ]
      if 90 - 90: OoOoOO00
      if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
      if 18 - 18: OoooooooOO
      if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
  if ( O00oO0 == "elp-name" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) :
     i1iIIiiIiII . elp_name = o00OoO0o0
     if ( lisp . lisp_elp_list . has_key ( o00OoO0o0 ) ) :
      i1iIIiiIiII . elp = lisp . lisp_elp_list [ o00OoO0o0 ]
      i1iIIiiIiII . elp . select_elp_node ( )
      if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
      if 94 - 94: ooOoO0o + I1IiiI
      if 56 - 56: OoOoOO00 % o0oOOo0O0Ooo
      if 40 - 40: OOooOOo / IiII
  if ( O00oO0 == "rloc-record-name" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) : i1iIIiiIiII . rloc_name = o00OoO0o0
    if 29 - 29: Ii1I - Ii1I / ooOoO0o
    if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
    if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
  if ( O00oO0 == "priority" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 == "" ) : o00OoO0o0 = "0"
    i1iIIiiIiII . priority = int ( o00OoO0o0 )
    if 18 - 18: Oo0Ooo % O0
    if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if ( O00oO0 == "weight" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 == "" ) : o00OoO0o0 = "0"
    i1iIIiiIiII . weight = int ( o00OoO0o0 )
    if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
    if 86 - 86: IiII
  if ( O00oO0 == "address" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) : i1iIIiiIiII . rloc . store_address ( o00OoO0o0 )
    if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
    if 33 - 33: II111iiii - IiII - ooOoO0o
    if 92 - 92: OoO0O00 * IiII
    if 92 - 92: oO0o
    if 7 - 7: iII111i
    if 73 - 73: OoO0O00 % I1ii11iIi11i
    if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
    if 62 - 62: i11iIiiIii
 for I11IIIII in IIo0oo0OO :
  I11IIIII . rloc_set = OOO
  I11IIIII . build_best_rloc_set ( )
  I11IIIII . add_cache ( )
  OOO = copy . deepcopy ( OOO )
  if 2 - 2: I1IiiI
 return
 if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
 if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
 if 14 - 14: IiII . IiII % ooOoO0o
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
 if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
 if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
 if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
def lisp_display_map_cache ( mc , output ) :
 Oo000o = lisp . lisp_print_elapsed ( mc . uptime )
 O0oooo0O = Oo000o
 OOOO0oo0 = mc . print_eid_tuple ( )
 I1I1i1 = "Recent Sources: "
 I1I1i1 += "none\n" if ( mc . recent_sources == { } ) else "\n"
 for iIIi11 in mc . recent_sources :
  Ii1iiIIi1i = mc . recent_sources [ iIIi11 ]
  I1I1i1 += "  " + iIIi11 + ": " + lisp . lisp_print_elapsed ( Ii1iiIIi1i ) + "\n"
  if 44 - 44: o0oOOo0O0Ooo
 OOOO0oo0 = lisp . lisp_span ( OOOO0oo0 , I1I1i1 [ 0 : - 1 ] )
 ooO0O = mc . action
 if 30 - 30: o0oOOo0O0Ooo - OoO0O00 + OOooOOo
 if 65 - 65: O0 / II111iiii . iIii1I11I1II1 . oO0o / Oo0Ooo % iIii1I11I1II1
 if 74 - 74: i1IIi / I1IiiI % I1ii11iIi11i / O0 % I11i - OoOoOO00
 if 31 - 31: I1IiiI / OoooooooOO . iIii1I11I1II1 * OoOoOO00 . OoooooooOO + II111iiii
 if 8 - 8: I1ii11iIi11i * I1ii11iIi11i * i1IIi + iII111i . I1ii11iIi11i
 if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
 oooO00Oo = mc . mapping_source
 if ( oooO00Oo == None ) :
  oooO00Oo = "map-notify"
 else :
  oooO00Oo = "static" if oooO00Oo . is_null ( ) else oooO00Oo . print_address_no_iid ( )
  if 37 - 37: Oo0Ooo
  if 72 - 72: IiII % I1ii11iIi11i * OOooOOo . i11iIiiIii % IiII * OOooOOo
  if 15 - 15: I11i / Oo0Ooo * I11i
 if ( mc . checkpoint_entry ) : oooO00Oo = "checkpoint"
 if ( mc . gleaned ) : oooO00Oo = "gleaned"
 I1111I1Ii = mc . print_ttl ( )
 if 68 - 68: OoO0O00 + I1IiiI * o0oOOo0O0Ooo . oO0o + OoOoOO00 + ooOoO0o
 ooO0O = "encapsulate" if ooO0O == lisp . LISP_NO_ACTION else lisp . lisp_map_reply_action_string [ ooO0O ]
 if 80 - 80: OoOoOO00 * OOooOOo
 if 47 - 47: ooOoO0o
 if ( len ( mc . rloc_set ) == 0 ) :
  Oo0oo = mc . stats . get_stats ( True , True )
  output += lisp_table_row ( OOOO0oo0 , Oo000o + "<br>" + I1111I1Ii , "--" , oooO00Oo ,
 Oo0oo , ooO0O , "--" )
  return ( [ True , output ] )
  if 29 - 29: I1IiiI . OOooOOo + II111iiii . Oo0Ooo
  if 29 - 29: Ii1I - O0 . ooOoO0o / I1ii11iIi11i / i1IIi . OoOoOO00
 for i1iIIiiIiII in mc . rloc_set :
  II1iiiiI1 = ""
  if ( i1iIIiiIiII . rloc_exists ( ) ) :
   if ( i1iIIiiIiII . rloc . is_null ( ) == False ) :
    II1iiiiI1 += i1iIIiiIiII . rloc . print_address_no_iid ( ) + "<br>"
    I1I1i1 = ""
    IiiIiiIIII = lisp . lisp_nonce_echoing and i1iIIiiIiII . echo_nonce_capable
    if ( lisp . lisp_rloc_probing ) :
     I1I1i1 += i1iIIiiIiII . print_rloc_probe_state ( IiiIiiIIII )
     if 88 - 88: OoO0O00 . I1Ii111 / I11i
    if ( IiiIiiIIII ) :
     iIiI1I1 = lisp . lisp_get_echo_nonce ( i1iIIiiIiII . rloc , None )
     if ( iIiI1I1 ) : I1I1i1 += iIiI1I1 . print_echo_nonce ( )
     if 62 - 62: o0oOOo0O0Ooo / iIii1I11I1II1
    if ( I1I1i1 != "" ) : II1iiiiI1 = lisp . lisp_span ( II1iiiiI1 , I1I1i1 )
    if 55 - 55: Ii1I / OoO0O00 + iII111i . IiII
    if 47 - 47: O0
    if 83 - 83: O0 + OoOoOO00 / O0 / I11i
  if ( i1iIIiiIiII . translated_port != 0 ) :
   II1iiiiI1 += "encap-port: {}<br>" . format ( i1iIIiiIiII . translated_port )
   if 68 - 68: i1IIi . I11i . i1IIi + IiII % I1IiiI
   if 32 - 32: OoOoOO00 . iIii1I11I1II1 % oO0o . O0 . OoOoOO00 / iII111i
  if ( i1iIIiiIiII . rloc_name ) :
   II1iiiiI1 += "rloc-name: {}<br>" . format ( lisp . blue ( i1iIIiiIiII . rloc_name ,
 True ) )
   if 45 - 45: iIii1I11I1II1
   if 41 - 41: iII111i % iII111i - IiII % OoO0O00 - OoooooooOO - iII111i
  if ( i1iIIiiIiII . geo ) :
   II1iiiiI1 += "geo: {}<br>" . format ( i1iIIiiIiII . geo . print_geo_url ( ) )
   if 66 - 66: o0oOOo0O0Ooo % OoOoOO00
  if ( i1iIIiiIiII . elp ) :
   II1I1iIIiIIii = i1iIIiiIiII . elp . print_elp ( True )
   II1iiiiI1 += "elp: {}<br>" . format ( II1I1iIIiIIii )
   if 65 - 65: i11iIiiIii - ooOoO0o * I11i + ooOoO0o / IiII + o0oOOo0O0Ooo
  if ( i1iIIiiIiII . rle ) :
   IiII1I = i1iIIiiIiII . rle . print_rle ( True , True )
   II1iiiiI1 += "rle: {}<br>" . format ( IiII1I )
   if 72 - 72: Ii1I / Oo0Ooo / oO0o * OoOoOO00 + OOooOOo
  if ( i1iIIiiIiII . json ) :
   if ( lisp . lisp_is_json_telemetry ( i1iIIiiIiII . json . json_string ) == None ) :
    i1iiIiI1Ii1i = "json: { ... }<br>"
    II1iiiiI1 += lisp . lisp_span ( i1iiIiI1Ii1i , i1iIIiiIiII . json . print_json ( False ) )
    if 58 - 58: o0oOOo0O0Ooo % I1IiiI . I1IiiI * OoO0O00 - IiII . OoooooooOO
    if 10 - 10: I1Ii111
    if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
    if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
    if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
    if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
  Oo0oo = i1iIIiiIiII . stats . get_stats ( True , True )
  if 55 - 55: OoooooooOO
  if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
  if 38 - 38: O0
  if 79 - 79: i1IIi . oO0o
  i1i1i11iI11II = ""
  II1 = i1iIIiiIiII
  while ( True ) :
   iiI1iI = lisp . lisp_print_elapsed ( II1 . last_state_change )
   if ( iiI1iI == "never" ) : iiI1iI = O0oooo0O
   iIIi11 = II1 . print_state ( )
   if ( II1 . unreach_state ( ) or II1 . no_echoed_nonce_state ( ) ) :
    iIIi11 = lisp . red ( iIIi11 , True )
    if 74 - 74: IiII - O0 / I1Ii111 * Ii1I % ooOoO0o . I1Ii111
   i1i1i11iI11II += iIIi11 + " since " + iiI1iI
   if 60 - 60: I1ii11iIi11i . II111iiii * i11iIiiIii . o0oOOo0O0Ooo
   if ( lisp . lisp_rloc_probing ) :
    o00oo = II1 . print_rloc_probe_rtt ( )
    if ( o00oo != "none" ) :
     i1i1i11iI11II += "<br>rtt: {}, hops: {}, latency: {}" . format ( o00oo , II1 . print_rloc_probe_hops ( ) ,
     # o0oOOo0O0Ooo % OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
 II1 . print_rloc_probe_latency ( ) )
     if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
     if 20 - 20: i1IIi . i1IIi - I11i
     if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
   if ( lisp . lisp_rloc_probing and II1 . rloc_next_hop != None ) :
    Iiii1iIii , IiIIiII1I = II1 . rloc_next_hop
    i1i1i11iI11II += "<br>{}nh {}({}) " . format ( lisp . lisp_space ( 2 ) , IiIIiII1I , Iiii1iIii )
    if 92 - 92: I1Ii111 % Ii1I
    if 30 - 30: II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
   II1 = II1 . next_rloc
   if ( II1 == None ) : break
   i1i1i11iI11II += "<br>"
   if 63 - 63: iIii1I11I1II1 / ooOoO0o
   if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
  if ( ooO0O == "encapsulate" ) :
   ooO00o = lisp . LISP_DATA_PORT
   if ( lisp . lisp_i_am_rtr and i1iIIiiIiII . translated_port != 0 ) :
    ooO00o = i1iIIiiIiII . translated_port
    if 50 - 50: II111iiii
    if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
   Ii1I1i = i1iIIiiIiII . rloc . print_address_no_iid ( ) + ":" + str ( ooO00o )
   if ( lisp . lisp_crypto_keys_by_rloc_encap . has_key ( Ii1I1i ) ) :
    I1I111iIi = lisp . lisp_crypto_keys_by_rloc_encap [ Ii1I1i ] [ 1 ]
    if ( I1I111iIi != None and I1I111iIi . shared_key != None ) :
     ooO0O = "encap-crypto-" + I1I111iIi . cipher_suite_string
     if 44 - 44: I1IiiI
     if 55 - 55: oO0o . I1Ii111 * I1Ii111
     if 82 - 82: I1IiiI % OoO0O00 % I11i + I11i
     if 6 - 6: Oo0Ooo
  output += lisp_table_row ( OOOO0oo0 , Oo000o + "<br>" + I1111I1Ii , II1iiiiI1 , oooO00Oo ,
 Oo0oo , i1i1i11iI11II + "<br>" + ooO0O ,
 str ( i1iIIiiIiII . priority ) + "/" + str ( i1iIIiiIiII . weight ) + "<br>" + str ( i1iIIiiIiII . mpriority ) + "/" + str ( i1iIIiiIiII . mweight ) )
  if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
  if 93 - 93: i11iIiiIii
  if ( OOOO0oo0 != "" ) : OOOO0oo0 = ""
  if ( Oo000o != "" ) : Oo000o , I1111I1Ii , oooO00Oo = ( "" , "" , "" )
  if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
 return ( [ True , output ] )
 if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
 if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
 if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
 if 58 - 58: I11i
 if 7 - 7: II111iiii / IiII % I11i + I1IiiI - O0
 if 45 - 45: I1IiiI / iII111i + oO0o + IiII
 if 15 - 15: I1IiiI % OoO0O00
 if 66 - 66: oO0o * i11iIiiIii . I1Ii111
def lisp_walk_map_cache ( mc , output ) :
 if 92 - 92: oO0o
 if 81 - 81: o0oOOo0O0Ooo % I1IiiI - iII111i / i11iIiiIii
 if 73 - 73: O0 * I1Ii111 . i1IIi
 if 51 - 51: OoO0O00 - iII111i % O0 - OoOoOO00
 if ( mc . group . is_null ( ) ) : return ( lisp_display_map_cache ( mc , output ) )
 if 53 - 53: iII111i / i1IIi / i1IIi
 if ( mc . source_cache == None ) : return ( [ True , output ] )
 if 77 - 77: I11i + i1IIi . I11i
 if 89 - 89: o0oOOo0O0Ooo + OOooOOo * oO0o
 if 45 - 45: iII111i - o0oOOo0O0Ooo . Ii1I
 if 41 - 41: II111iiii . I1IiiI / OoO0O00 . ooOoO0o
 if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
 output = mc . source_cache . walk_cache ( lisp_display_map_cache , output )
 return ( [ True , output ] )
 if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
 if 36 - 36: I11i - IiII . IiII
 if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
 if 84 - 84: iIii1I11I1II1 + OoooooooOO
 if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
 if 10 - 10: I1ii11iIi11i + IiII
 if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
def lisp_show_myrlocs ( output ) :
 if ( lisp . lisp_myrlocs [ 2 ] == None ) :
  output += "No local RLOCs found"
 else :
  oooO0 = lisp . lisp_print_cour ( lisp . lisp_myrlocs [ 2 ] )
  I11Iii11i11I1 = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 0 ] != None else "not found"
  if 1 - 1: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo % II111iiii % iIii1I11I1II1
  I11Iii11i11I1 = lisp . lisp_print_cour ( I11Iii11i11I1 )
  OOo000oi1iIiII11i1 = "-f inet" if lisp . lisp_is_macos ( ) else "-4"
  Ii1I1iIiiI1 = commands . getoutput ( "netstat -rn {}" . format ( OOo000oi1iIiII11i1 ) )
  I11Iii11i11I1 = lisp . lisp_span ( I11Iii11i11I1 , Ii1I1iIiiI1 )
  if 68 - 68: iII111i . I11i
  i111iiIiiIiI = lisp . lisp_myrlocs [ 1 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 1 ] != None else "not found"
  if 59 - 59: OOooOOo + I1IiiI / II111iiii / OoOoOO00
  i111iiIiiIiI = lisp . lisp_print_cour ( i111iiIiiIiI )
  OOo000oi1iIiII11i1 = "-f inet6" if lisp . lisp_is_macos ( ) else "-6"
  Ii1I1iIiiI1 = commands . getoutput ( "netstat -rn {}" . format ( OOo000oi1iIiII11i1 ) )
  i111iiIiiIiI = lisp . lisp_span ( i111iiIiiIiI , Ii1I1iIiiI1 )
  if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
  II1i = "<i>Local RLOCs found on interface </i>{}<i>, " + "IPv4: </i>{}<i>, IPv6: </i>{}"
  if 76 - 76: I1IiiI * OOooOOo
  output += lisp . lisp_print_sans ( II1i ) . format ( oooO0 , I11Iii11i11I1 , i111iiIiiIiI )
  if 12 - 12: iIii1I11I1II1 / I11i % Ii1I
 output += "<br>"
 return ( output )
 if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
 if 27 - 27: OoO0O00 + Oo0Ooo
 if 92 - 92: I1IiiI % iII111i
 if 31 - 31: OoooooooOO - oO0o / I1Ii111
 if 62 - 62: i11iIiiIii - I11i
 if 81 - 81: I11i
 if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
def lisp_display_nat_info ( output , dc , dodns ) :
 Oo00o = len ( lisp . lisp_nat_state_info )
 if ( Oo00o == 0 ) : return ( output )
 if 3 - 3: Oo0Ooo . OoooooooOO + i1IIi / i1IIi % iIii1I11I1II1 / Ii1I
 I1I1i1 = "{} entries in the NAT-traversal port table" . format ( Oo00o )
 oooo00Oo0O = lisp . lisp_span ( "NAT-Traversed xTR Information:" , I1I1i1 )
 if 16 - 16: OoooooooOO % I1IiiI - o0oOOo0O0Ooo / II111iiii . i1IIi
 if ( dodns ) :
  output += lisp_table_header ( oooo00Oo0O , "xTR Hostname" ,
 "Translated<br>Address" , "Translated<br>{} Port" . format ( dc ) ,
 "Last<br>Info-Request" , "NAT DNS Name" )
 else :
  output += lisp_table_header ( oooo00Oo0O , "xTR Hostname" ,
 "Translated<br>Address" , "Translated<br>{} Port" . format ( dc ) ,
 "Last<br>Info-Request" )
  if 27 - 27: II111iiii + ooOoO0o . OoOoOO00 - I1Ii111
  if 54 - 54: OoOoOO00 . Oo0Ooo
 for Ii1 in lisp . lisp_nat_state_info . values ( ) :
  for iIIi11iIiiII1Ii1ii in Ii1 :
   II = iIIi11iIiiII1Ii1ii . address
   OOoO000O0OO = iIIi11iIiiII1Ii1ii . uptime
   ii11 = iIIi11iIiiII1Ii1ii . hostname
   ooO00o = iIIi11iIiiII1Ii1ii . port
   if 34 - 34: I1IiiI
   if ( iIIi11iIiiII1Ii1ii . timed_out ( ) ) :
    OOoO000O0OO = lisp . red ( lisp . lisp_print_elapsed ( OOoO000O0OO ) , True )
   else :
    OOoO000O0OO = lisp . lisp_print_elapsed ( OOoO000O0OO )
    if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
    if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
   if ( dodns ) :
    try :
     oo0oO0oOo0O = socket . gethostbyaddr ( II ) [ 0 ]
    except :
     oo0oO0oOo0O = "?"
     if 75 - 75: II111iiii + II111iiii + OOooOOo * o0oOOo0O0Ooo
    output += lisp_table_row ( ii11 , II , ooO00o , OOoO000O0OO , oo0oO0oOo0O )
   else :
    output += lisp_table_row ( ii11 , II , ooO00o , OOoO000O0OO )
    if 62 - 62: iIii1I11I1II1 - i1IIi - oO0o
    if 72 - 72: OoOoOO00 / I1Ii111 * IiII % iIii1I11I1II1
    if 53 - 53: OoO0O00 . O0 . I1IiiI * OOooOOo / o0oOOo0O0Ooo
    if 34 - 34: OoOoOO00
 output += lisp_table_footer ( )
 return ( output )
 if 16 - 16: i1IIi - I1Ii111 - II111iiii
 if 83 - 83: I1IiiI - OoO0O00 - o0oOOo0O0Ooo / O0 - I11i . II111iiii
 if 27 - 27: Ii1I
 if 59 - 59: Ii1I / II111iiii - IiII % OoOoOO00 % OoooooooOO
 if 79 - 79: iII111i . OoooooooOO . I1IiiI * O0 * OoO0O00 - OOooOOo
 if 33 - 33: I1ii11iIi11i . Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
 if 54 - 54: ooOoO0o * iII111i * iII111i % OoOoOO00 - OOooOOo % I1ii11iIi11i
def lisp_itr_rtr_show_command ( parameter , itr_or_rtr , lisp_threads , dns = False ) :
 if 44 - 44: Oo0Ooo . OOooOOo + I11i
 if 22 - 22: I1Ii111 * OoooooooOO + i11iIiiIii % OoO0O00
 if 53 - 53: I1IiiI
 if 10 - 10: I1Ii111 / i11iIiiIii - II111iiii
 if ( parameter != "" ) :
  return ( lisp_show_map_cache_lookup ( parameter ) )
  if 48 - 48: OOooOOo
  if 26 - 26: iII111i * I1Ii111 * oO0o * OoOoOO00
 i1iiI11I = ""
 if 48 - 48: iII111i % i11iIiiIii . OoooooooOO * IiII % OoO0O00 . iII111i
 if 6 - 6: O0 . ooOoO0o - oO0o / i11iIiiIii
 if 84 - 84: I11i / I1ii11iIi11i * o0oOOo0O0Ooo * OoO0O00 * OOooOOo * O0
 if 83 - 83: O0 % II111iiii + o0oOOo0O0Ooo / OoooooooOO
 i1iiI11I = lisp_show_myrlocs ( i1iiI11I )
 if 75 - 75: II111iiii . I1IiiI + OOooOOo - OoOoOO00 - O0 . I11i
 if 19 - 19: Ii1I * i1IIi % O0 + I11i
 if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
 if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
 if ( itr_or_rtr == "RTR" ) :
  i1iiI11I = lisp_show_decap_stats ( i1iiI11I , itr_or_rtr )
  if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
  if 80 - 80: Ii1I
  if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
  if 59 - 59: I1ii11iIi11i + I11i . oO0o
  if 87 - 87: OoO0O00
 if ( len ( lisp_threads ) > 1 ) :
  iIIi11 = [ ]
  for i11Ii1 in range ( len ( lisp_threads ) ) :
   Ii1iiIIi1i = lisp_threads [ i11Ii1 ]
   iIIi11 . append ( "{} Input Stats<br>queue-size: {}" . format ( Ii1iiIIi1i . thread_name ,
 Ii1iiIIi1i . input_queue . qsize ( ) ) )
   if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  i1iiI11I += lisp_table_header ( "LISP-RTR Forwarding Stats:" , * iIIi11 )
  if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
  iIIi11 = [ ]
  for i11Ii1 in range ( len ( lisp_threads ) ) :
   Ii1iiIIi1i = lisp_threads [ i11Ii1 ]
   iIIi11 . append ( Ii1iiIIi1i . input_stats . get_stats ( False , True ) )
   if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  i1iiI11I += lisp_table_row ( * iIIi11 )
  i1iiI11I += lisp_table_footer ( )
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
  if 46 - 46: i11iIiiIii
 Iiiii = lisp . lisp_decent_dns_suffix
 if ( Iiiii == None ) :
  Iiiii = ":"
 else :
  Iiiii = "&nbsp;(dns-suffix '{}'):" . format ( Iiiii )
  if 25 - 25: Oo0Ooo * I1IiiI + OOooOOo + I1Ii111 % OOooOOo
  if 84 - 84: O0 % Ii1I . Ii1I . iII111i * I11i
  if 43 - 43: OoOoOO00 . I1ii11iIi11i % i1IIi
  if 61 - 61: I1IiiI + oO0o % I1Ii111 % iIii1I11I1II1 - OoooooooOO
  if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
 I1I1i1 = "{} map-resolvers configured" . format ( len ( lisp . lisp_map_resolvers_list ) )
 if 83 - 83: ooOoO0o
 oooo00Oo0O = "LISP-{} Configured Map-Resolvers{}" . format ( itr_or_rtr , Iiiii )
 oooo00Oo0O = lisp . lisp_span ( oooo00Oo0O , I1I1i1 )
 if 43 - 43: OOooOOo
 i1iiI11I += lisp_table_header ( oooo00Oo0O , "Map-Resolver" , "Last Used" ,
 "Map-Requests<br>Sent" , "Negative Map-Replies<br>Received" ,
 "Last Negative<br>Map-Reply" , "Average RTT" )
 if 84 - 84: OOooOOo . IiII . iII111i
 for i1IIi1i1Ii1 in lisp . lisp_map_resolvers_list . values ( ) :
  i1IIi1i1Ii1 . resolve_dns_name ( )
  OO0o0o0oo = "" if i1IIi1i1Ii1 . mr_name == "all" else i1IIi1i1Ii1 . mr_name + "<br>"
  Ii1I1i = OO0o0o0oo + i1IIi1i1Ii1 . map_resolver . print_address_no_iid ( )
  if ( i1IIi1i1Ii1 . dns_name ) : Ii1I1i += "<br>" + i1IIi1i1Ii1 . dns_name
  if 2 - 2: Oo0Ooo - OoOoOO00
  Oo000o = lisp . lisp_print_elapsed ( i1IIi1i1Ii1 . last_used )
  I1iiII = lisp . lisp_print_elapsed ( i1IIi1i1Ii1 . last_reply )
  oOOOO0 = 0 if i1IIi1i1Ii1 . neg_map_replies_received == 0 else float ( i1IIi1i1Ii1 . total_rtt / i1IIi1i1Ii1 . neg_map_replies_received )
  if 99 - 99: OOooOOo + I1IiiI . I1ii11iIi11i * OoooooooOO
  oOOOO0 = str ( round ( oOOOO0 , 3 ) ) + " ms"
  if 82 - 82: i11iIiiIii + iIii1I11I1II1 / Oo0Ooo + OOooOOo * II111iiii
  i1iiI11I += lisp_table_row ( Ii1I1i , Oo000o , i1IIi1i1Ii1 . map_requests_sent ,
 i1IIi1i1Ii1 . neg_map_replies_received , I1iiII , oOOOO0 )
  if 34 - 34: o0oOOo0O0Ooo % OoooooooOO
 i1iiI11I += lisp_table_footer ( )
 if 36 - 36: I1IiiI
 if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
 if 64 - 64: ooOoO0o / i1IIi % iII111i
 if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
 if ( itr_or_rtr == "ITR" ) : i1iiI11I = lisp_show_db_list ( "ITR" , i1iiI11I )
 if 99 - 99: I1Ii111
 if 75 - 75: ooOoO0o . OOooOOo / IiII
 if 84 - 84: OoooooooOO . I1IiiI / o0oOOo0O0Ooo
 if 86 - 86: Oo0Ooo % OoOoOO00
 i11IiIiiIIIII = "<br>Enter EID for Map-Cache lookup:"
 if 77 - 77: Ii1I % OOooOOo / oO0o
 OOoOo = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 27 - 27: I1IiiI * i11iIiiIii / O0 / II111iiii
 OOoO0oOOO = itr_or_rtr . lower ( )
 if 47 - 47: OOooOOo / II111iiii % IiII . oO0o * I1ii11iIi11i
 i11IiIiiIIIII = '''
         <form action="/lisp/show/{}/map-cache/lookup" method="post">
         <font size="3"><i>{}</i> {}
         <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form>
    ''' . format ( OOoO0oOOO , lisp . lisp_print_sans ( i11IiIiiIIIII ) , OOoOo )
 if 35 - 35: Oo0Ooo * II111iiii
 IIi1i1IIi = '<a href="/lisp/show/{}/rloc-probing">RLOC State</a>' . format ( OOoO0oOOO )
 if 93 - 93: oO0o
 o0Oo = '<a href="/lisp/show/{}/keys"><br>RLOC Keys</a>' . format ( OOoO0oOOO )
 if 16 - 16: OoO0O00 % Ii1I + I1ii11iIi11i + Oo0Ooo / iIii1I11I1II1
 if 89 - 89: I1IiiI % Oo0Ooo - OoOoOO00 * iII111i + I1Ii111 + OoooooooOO
 if 29 - 29: OoOoOO00 + I1Ii111 / OOooOOo + ooOoO0o
 if 42 - 42: iIii1I11I1II1 - ooOoO0o - I11i - I1Ii111
 iIiI11II = os . path . exists ( "./show-ztr" )
 OO0Iii1iIiI111Ii = "Map-Cache"
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None or iIiI11II ) :
  OO0Iii1iIiI111Ii = '<a href="/lisp/show/lisp-xtr">Map-Cache</a>'
  if 61 - 61: OoooooooOO * OoOoOO00
  if 97 - 97: i11iIiiIii
  if 68 - 68: IiII * OoO0O00 . I11i / Ii1I . o0oOOo0O0Ooo - i11iIiiIii
  if 49 - 49: Oo0Ooo / Ii1I % I11i + oO0o - OoO0O00
  if 13 - 13: II111iiii
 I1I1i1 = "{} entries in the map-cache" . format ( lisp . lisp_map_cache . cache_size ( ) )
 if 83 - 83: OoooooooOO . I1IiiI + Ii1I * O0 / oO0o
 oooo00Oo0O = "LISP-{} {}:{}" . format ( itr_or_rtr , OO0Iii1iIiI111Ii , lisp . lisp_space ( 4 ) )
 oooo00Oo0O = lisp . lisp_span ( oooo00Oo0O , I1I1i1 )
 if 8 - 8: i1IIi + II111iiii / Ii1I + I1ii11iIi11i % Ii1I - iIii1I11I1II1
 if 29 - 29: Oo0Ooo + II111iiii
 if 95 - 95: oO0o
 if 48 - 48: I11i / iIii1I11I1II1 % II111iiii
 if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
 oooo00Oo0O += lisp . lisp_button ( "clear cache" ,
 "/lisp/clear/{}/map-cache" . format ( itr_or_rtr . lower ( ) ) )
 oooo00Oo0O += i11IiIiiIIIII
 if 100 - 100: OoooooooOO - OoooooooOO + IiII
 if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo / OoooooooOO
 i1iiI11I += lisp_table_header ( oooo00Oo0O , "EID-Prefix or (S,G)" ,
 "Uptime<br>TTL" , "RLOC Record" + o0Oo , "Map-Reply Source" ,
 "RLOC Send Stats" , IIi1i1IIi + "<br>RLOC Action" ,
 "Unicast Priority/Weight<br>Multicast Priority/Weight" )
 if 90 - 90: I1Ii111
 i1iiI11I = lisp . lisp_map_cache . walk_cache ( lisp_walk_map_cache , i1iiI11I )
 i1iiI11I += lisp_table_footer ( )
 if 35 - 35: II111iiii / Ii1I
 if 79 - 79: OoOoOO00 + I1Ii111 * iII111i * Ii1I
 if 53 - 53: OOooOOo / Oo0Ooo
 if 10 - 10: I1ii11iIi11i . o0oOOo0O0Ooo
 if ( len ( lisp . lisp_elp_list ) != 0 ) : i1iiI11I = lisp_show_elp_list ( i1iiI11I )
 if 75 - 75: O0 * i1IIi - I11i / OOooOOo % OOooOOo / OoOoOO00
 if 5 - 5: O0 - iII111i / I1Ii111 . o0oOOo0O0Ooo
 if 7 - 7: I1ii11iIi11i - OoOoOO00
 if 54 - 54: oO0o / iIii1I11I1II1 / OoooooooOO . i1IIi - OoOoOO00
 if ( len ( lisp . lisp_rle_list ) != 0 ) : i1iiI11I = lisp_show_rle_list ( i1iiI11I )
 if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
 if 46 - 46: Ii1I
 if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
 if 87 - 87: I1ii11iIi11i / I1IiiI
 if ( len ( lisp . lisp_json_list ) != 0 ) : i1iiI11I = lisp_show_json_list ( i1iiI11I )
 if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
 if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
 if 11 - 11: I1ii11iIi11i - OoooooooOO
 if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
 if ( itr_or_rtr == "RTR" ) :
  i1iiI11I = lisp_display_nat_info ( i1iiI11I , "Data" , dns )
  if 27 - 27: IiII + iIii1I11I1II1 / Oo0Ooo + OoO0O00 % Oo0Ooo + OoO0O00
  if 77 - 77: Oo0Ooo * ooOoO0o % Ii1I
  if 2 - 2: I11i / Oo0Ooo / Ii1I / I1ii11iIi11i / OoooooooOO
  if 22 - 22: iIii1I11I1II1 * I1IiiI / I11i + OoOoOO00
  if 98 - 98: OOooOOo
 return ( i1iiI11I )
 if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
 if 75 - 75: OoO0O00 % OoooooooOO
 if 16 - 16: O0 / i1IIi
 if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
 if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
 if 12 - 12: OoOoOO00 + o0oOOo0O0Ooo . I1Ii111
 if 52 - 52: OoO0O00
def lisp_itr_rtr_show_rloc_probe_command ( itr_or_rtr ) :
 oooo00Oo0O = "LISP-{} RLOC-Probe Information:" . format ( itr_or_rtr )
 i1iiI11I = lisp_table_header ( oooo00Oo0O , "RLOC Key State" , "RLOC-Probe State" )
 if 4 - 4: Ii1I % I1ii11iIi11i + I11i - I1ii11iIi11i
 for O00o0O00 in lisp . lisp_rloc_probe_list . values ( ) :
  if 77 - 77: OoOoOO00 / I11i * OOooOOo
  OOOO0oo0 = ""
  for II1 , II11Ii , oooOoo0oOO0 in O00o0O00 :
   o0o0oooO00O0 = lisp . green ( lisp . lisp_print_eid_tuple ( II11Ii , oooOoo0oOO0 ) , True )
   OOOO0oo0 += lisp . lisp_print_cour ( o0o0oooO00O0 ) + "<br>"
   if 33 - 33: i1IIi / I1IiiI
  OOOO0oo0 = ", EIDs ({}):<br>" . format ( len ( O00o0O00 ) ) + OOOO0oo0
  if 43 - 43: i1IIi * Oo0Ooo
  II1 , II11Ii , oooOoo0oOO0 = O00o0O00 [ 0 ]
  if 14 - 14: iII111i + OoO0O00 + I11i % OoO0O00 + i1IIi + Oo0Ooo
  if 82 - 82: OoooooooOO
  if 92 - 92: Ii1I . OoOoOO00 . I11i - OoooooooOO / ooOoO0o
  if 80 - 80: iIii1I11I1II1 / i11iIiiIii + iII111i
  IiIIiII1I = lisp . lisp_hex_string ( II1 . last_rloc_probe_nonce )
  if ( II1 . translated_rloc . not_set ( ) ) :
   I11I1i = II1 . rloc . print_address_no_iid ( )
  else :
   I11I1i = "{}{}{}" . format ( II1 . translated_rloc . print_address_no_iid ( ) ,
 lisp . bold ( ":" , True ) , II1 . translated_port )
   if 100 - 100: oO0o
  I11I1i = lisp . bold ( lisp . lisp_print_cour ( I11I1i ) , True )
  iiIiiiIii11i1 = II1 . rloc_name
  if ( iiIiiiIii11i1 != None ) :
   iiIiiiIii11i1 = lisp . bold ( iiIiiiIii11i1 , True )
   I11I1i += ", {}" . format ( lisp . lisp_print_cour ( lisp . blue ( iiIiiiIii11i1 , True ) ) )
   if 87 - 87: OoO0O00 + OoooooooOO . ooOoO0o * I11i
  i1i1i11iI11II = II1 . print_state ( )
  if ( II1 . up_state ( ) == False ) : i1i1i11iI11II = lisp . red ( II1 . print_state ( ) , True )
  I11I1i = "RLOC " + I11I1i + ", {}" . format ( i1i1i11iI11II )
  if 82 - 82: iIii1I11I1II1 * OoooooooOO
  i1ii1i1i1 = I11I1i + OOOO0oo0
  if 92 - 92: Oo0Ooo
  if 60 - 60: i11iIiiIii . O0 * iIii1I11I1II1 * OoOoOO00
  if 99 - 99: iIii1I11I1II1 - oO0o - OoOoOO00 / iIii1I11I1II1 * Oo0Ooo - oO0o
  if 72 - 72: IiII % i1IIi / iIii1I11I1II1
  oo = lisp . lisp_print_elapsed ( II1 . last_rloc_probe )
  oo = lisp . lisp_print_cour ( oo )
  Iiio0OO00oOOO0o0 = lisp . lisp_print_elapsed ( II1 . last_rloc_probe_reply )
  Iiio0OO00oOOO0o0 = lisp . lisp_print_cour ( Iiio0OO00oOOO0o0 )
  IiIIiII1I = lisp . lisp_hex_string ( II1 . last_rloc_probe_nonce )
  IiIIiII1I = lisp . lisp_print_cour ( "0x" + IiIIiII1I )
  iiii = ( "Last probe-request sent: {}, " + "last probe-reply received: {}, nonce: {}<br>" ) . format ( oo , Iiio0OO00oOOO0o0 , IiIIiII1I )
  if 80 - 80: I1IiiI
  if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
  o00oo = II1 . print_recent_rloc_probe_rtts ( )
  o00oo = lisp . lisp_print_cour ( o00oo )
  Iii11I1i = II1 . print_recent_rloc_probe_hops ( )
  Iii11I1i = lisp . lisp_print_cour ( Iii11I1i )
  oO0OOoOO = II1 . print_recent_rloc_probe_latencies ( )
  oO0OOoOO = lisp . lisp_print_cour ( oO0OOoOO )
  oOoO = II1 . print_rloc_probe_hops ( )
  oOoO = lisp . lisp_print_cour ( oOoO )
  I11IiI1I11i1i = II1 . print_rloc_probe_latency ( )
  I11IiI1I11i1i = lisp . lisp_print_cour ( I11IiI1I11i1i )
  II1 = II1 . print_rloc_probe_rtt ( )
  II1 = lisp . lisp_print_cour ( II1 )
  iiii += ( "Telemetry: rtt: {}, hops: {}, latency: {}<br>" + "recent-rtts: {}, recent-hops: {}, recent-latencies: {}" ) . format ( II1 , oOoO , I11IiI1I11i1i , o00oo , Iii11I1i , oO0OOoOO )
  if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
  if 23 - 23: I11i
  if 36 - 36: IiII . iII111i - i1IIi + I1Ii111
  if 54 - 54: OoooooooOO . oO0o - iII111i
  if 76 - 76: I1Ii111
  if 61 - 61: ooOoO0o / II111iiii * ooOoO0o * OoOoOO00 * I1Ii111 . i11iIiiIii
  i1iiI11I += lisp_table_row ( i1ii1i1i1 , iiii )
  if 26 - 26: I1Ii111 / ooOoO0o - OoO0O00 . iIii1I11I1II1
  if 83 - 83: ooOoO0o % Ii1I / Oo0Ooo - iII111i / O0
 i1iiI11I += lisp_table_footer ( )
 return ( i1iiI11I )
 if 97 - 97: iIii1I11I1II1 * I11i
 if 95 - 95: OoO0O00
 if 68 - 68: iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00 - II111iiii - iIii1I11I1II1
 if 75 - 75: ooOoO0o . I1IiiI * II111iiii
 if 99 - 99: iIii1I11I1II1 * I1ii11iIi11i + IiII
 if 70 - 70: i1IIi % ooOoO0o . I1ii11iIi11i - IiII + OOooOOo
 if 84 - 84: oO0o + II111iiii * II111iiii % o0oOOo0O0Ooo / iII111i + ooOoO0o
def lisp_xtr_command ( kv_pair ) :
 if 9 - 9: iII111i
 if 25 - 25: OOooOOo - Ii1I . I11i
 if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
 if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
 if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) :
  kv_pair [ "ipc-data-plane" ] = [ "yes" ]
  if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
  if 100 - 100: i1IIi % Ii1I
 for O00oO0 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ O00oO0 ] [ 0 ]
  if ( O00oO0 == "rloc-probing" ) :
   lisp . lisp_rloc_probing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_rloc_probe_list = { }
   if 55 - 55: I1IiiI + iII111i
  if ( O00oO0 == "nonce-echoing" ) :
   lisp . lisp_nonce_echoing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_nonce_echo_list = { }
   if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
  if ( O00oO0 == "data-plane-security" ) :
   lisp . lisp_data_plane_security = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) :
    lisp . lisp_crypto_keys_by_nonce = { }
    lisp . lisp_crypto_keys_by_rloc_encap = { }
    lisp . lisp_crypto_keys_by_rloc_decap = { }
    if 19 - 19: I11i / iII111i + IiII
    if 76 - 76: iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo + OoooooooOO
  if ( O00oO0 == "data-plane-logging" ) :
   lisp . lisp_data_plane_logging = ( oo00oO0O0 == "yes" )
   if 10 - 10: OoO0O00 * I11i / Oo0Ooo - I1Ii111
  if ( O00oO0 == "frame-logging" ) :
   lisp . lisp_frame_logging = ( oo00oO0O0 == "yes" )
   if 11 - 11: IiII % I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - II111iiii
  if ( O00oO0 == "flow-logging" ) :
   lisp . lisp_flow_logging = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "yes" ) : os . system ( "touch ./log-flows" )
   if 50 - 50: i1IIi * oO0o / i11iIiiIii / i11iIiiIii / oO0o
  if ( O00oO0 == "nat-traversal" ) :
   lisp . lisp_nat_traversal = ( oo00oO0O0 == "yes" )
   if 84 - 84: I1ii11iIi11i - iII111i + I1ii11iIi11i
  if ( O00oO0 == "program-hardware" ) :
   lisp . lisp_program_hardware = ( oo00oO0O0 == "yes" )
   if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
  if ( O00oO0 == "checkpoint-map-cache" ) :
   lisp . lisp_checkpoint_map_cache = ( oo00oO0O0 == "yes" )
   o0oOo00OOo0O = lisp . lisp_checkpoint_filename
   if ( oo00oO0O0 == "no" and os . path . exists ( o0oOo00OOo0O ) ) :
    os . system ( "rm {}" . format ( o0oOo00OOo0O ) )
    if 73 - 73: I1ii11iIi11i - OoOoOO00 * O0 - OoOoOO00 - OoO0O00
    if 96 - 96: I1ii11iIi11i - O0
  if ( O00oO0 == "ipc-data-plane" ) :
   I1i = ( oo00oO0O0 == "yes" )
   if ( I1i and lisp . lisp_ipc_data_plane == False ) :
    iIIi11 = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
    lisp . lisp_ipc_dp_socket = iIIi11
    if 72 - 72: I11i * OoOoOO00 % I1Ii111 % ooOoO0o
   if ( I1i == False and lisp . lisp_ipc_data_plane ) :
    lisp . lisp_ipc_dp_socket . close ( )
    lisp . lisp_ipc_dp_socket = None
    if 22 - 22: OOooOOo - I1ii11iIi11i / IiII
   lisp . lisp_ipc_data_plane = I1i
   if 95 - 95: o0oOOo0O0Ooo
  if ( O00oO0 == "decentralized-push-xtr" ) :
   lisp . lisp_decent_push_configured = ( oo00oO0O0 == "yes" )
   if 69 - 69: oO0o . I11i
  if ( O00oO0 == "decentralized-pull-xtr-modulus" ) :
   lisp . lisp_decent_modulus = int ( oo00oO0O0 )
   if 36 - 36: ooOoO0o
  if ( O00oO0 == "decentralized-pull-xtr-dns-suffix" ) :
   lisp . lisp_decent_dns_suffix = oo00oO0O0
   if 62 - 62: I11i % oO0o / OoooooooOO % OoooooooOO
  if ( O00oO0 == "register-reachable-rtrs" ) :
   lisp . lisp_register_all_rtrs = ( oo00oO0O0 == "no" )
   if 65 - 65: O0 . I1ii11iIi11i * I1Ii111
   if 39 - 39: iIii1I11I1II1 % O0 + Oo0Ooo
 return
 if 71 - 71: OoooooooOO + i1IIi + oO0o * Ii1I + i11iIiiIii - oO0o
 if 99 - 99: Oo0Ooo
 if 17 - 17: i11iIiiIii - i11iIiiIii + I1ii11iIi11i * ooOoO0o * oO0o / OoooooooOO
 if 22 - 22: I1Ii111 * I1ii11iIi11i - IiII
 if 71 - 71: iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * I1IiiI % II111iiii
 if 35 - 35: I1Ii111 - OoOoOO00
 if 61 - 61: I1Ii111 * o0oOOo0O0Ooo * OoO0O00 + I1ii11iIi11i . Oo0Ooo + i1IIi
def lisp_show_json_list ( output ) :
 if 82 - 82: Oo0Ooo + I1Ii111
 oooo00Oo0O = "Configured JSON Entries:"
 output += lisp_table_header ( oooo00Oo0O , "JSON Name" , "JSON String" )
 if 93 - 93: I11i * O0 * OOooOOo - o0oOOo0O0Ooo / I1ii11iIi11i
 oooOo0OO = sorted ( lisp . lisp_json_list )
 for iII in oooOo0OO :
  i1iiIiI1Ii1i = lisp . lisp_json_list [ iII ]
  I11Ii1iI1II = lisp . lisp_print_cour ( i1iiIiI1Ii1i . print_json ( True ) )
  output += lisp_table_row ( iII , I11Ii1iI1II )
  if 74 - 74: I1IiiI . ooOoO0o / iII111i . IiII
 output += lisp_table_footer ( )
 return ( output )
 if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
 if 72 - 72: i1IIi
 if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
 if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
 if 89 - 89: IiII - i1IIi - IiII
 if 74 - 74: OoO0O00 % OoO0O00
 if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
def lisp_show_rle_list ( output ) :
 if 91 - 91: I1IiiI / II111iiii * OOooOOo
 oooo00Oo0O = "Configured Replication List Entries (RLEs):"
 output += lisp_table_header ( oooo00Oo0O , "RLE Name" , "RLE Nodes" )
 if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
 OOOo0Ooo0o00o = sorted ( lisp . lisp_rle_list )
 for oOo in OOOo0Ooo0o00o :
  IiII1I = lisp . lisp_rle_list [ oOo ]
  output += lisp_table_row ( oOo , IiII1I . print_rle ( True , True ) )
  if 94 - 94: i1IIi / I1ii11iIi11i / I1IiiI * I1Ii111 * Oo0Ooo
 output += lisp_table_footer ( )
 return ( output )
 if 21 - 21: OoooooooOO + O0 / OoooooooOO / OOooOOo
 if 44 - 44: i1IIi . I1ii11iIi11i - ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
 if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
 if 57 - 57: oO0o
 if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
 if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
 if 37 - 37: iII111i
def lisp_show_elp_list ( output ) :
 oooo00Oo0O = "Configured Explicit Locator Paths (ELPs):"
 output += lisp_table_header ( oooo00Oo0O , "ELP Name" , "ELP Nodes" )
 if 15 - 15: o0oOOo0O0Ooo % OoO0O00 / iII111i
 II1IIIi = sorted ( lisp . lisp_elp_list )
 for Iiii in II1IIIi :
  II1I1iIIiIIii = lisp . lisp_elp_list [ Iiii ]
  output += lisp_table_row ( Iiii , II1I1iIIiIIii . print_elp ( False ) )
  if 88 - 88: I1Ii111 - Ii1I - oO0o + i1IIi
 output += lisp_table_footer ( )
 return ( output )
 if 15 - 15: OOooOOo
 if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
 if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
 if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
 if 62 - 62: OOooOOo * O0 % IiII . IiII . I1IiiI
 if 91 - 91: i1IIi . iII111i
 if 37 - 37: iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoO0O00 . o0oOOo0O0Ooo
def lisp_geo_command ( kv_pair ) :
 if 62 - 62: I1ii11iIi11i
 if 47 - 47: I1Ii111 % OOooOOo * OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
 if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
 if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
 if ( kv_pair . has_key ( "geo-name" ) == False ) : return
 o0o0Oo0oo = kv_pair [ "geo-name" ]
 O0oooOO = lisp . lisp_geo ( o0o0Oo0oo )
 if 5 - 5: OoOoOO00 % I1ii11iIi11i . ooOoO0o . I11i - i11iIiiIii
 if 39 - 39: i11iIiiIii + OOooOOo % iII111i + Ii1I * I1IiiI + I1Ii111
 if 72 - 72: II111iiii + I1Ii111 * OOooOOo . I1IiiI
 if 51 - 51: iII111i
 if ( kv_pair . has_key ( "geo-tag" ) == False ) : return
 if 81 - 81: O0
 if 38 - 38: iII111i
 if 78 - 78: i11iIiiIii . IiII % OoooooooOO - IiII - IiII + Ii1I
 if 11 - 11: I11i
 Ii = kv_pair [ "geo-tag" ] [ 1 : : ]
 if ( O0oooOO . parse_geo_string ( Ii ) == False ) : return
 if 96 - 96: Ii1I
 if 24 - 24: O0
 if 33 - 33: OoooooooOO + oO0o * II111iiii / OOooOOo
 if 87 - 87: OoooooooOO
 lisp . lisp_geo_list [ o0o0Oo0oo ] = O0oooOO
 return
 if 1 - 1: iIii1I11I1II1 / o0oOOo0O0Ooo
 if 98 - 98: O0 % I1IiiI / OoooooooOO * I1ii11iIi11i - oO0o
 if 51 - 51: iII111i + I11i
 if 54 - 54: II111iiii * O0 % I1IiiI . I11i
 if 62 - 62: Ii1I . i11iIiiIii % O0 % I1Ii111 - Oo0Ooo
 if 69 - 69: II111iiii . OoOoOO00 * OoOoOO00 % Ii1I + I1IiiI
 if 100 - 100: i11iIiiIii - Oo0Ooo
def lisp_elp_command ( kv_pair ) :
 if 47 - 47: iII111i * OoOoOO00 * IiII
 II1I1iIIiIIii = None
 iIiii1IIi1I = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for i11Ii1 in range ( len ( kv_pair [ "address" ] ) ) :
   IiIi = lisp . lisp_elp_node ( )
   iIiii1IIi1I . append ( IiIi )
   if 34 - 34: Oo0Ooo
   if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
   if 33 - 33: i1IIi / iII111i * OoO0O00
 for O00oO0 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ O00oO0 ]
  if 2 - 2: oO0o . OOooOOo
  if ( O00oO0 == "elp-name" ) :
   II1I1iIIiIIii = lisp . lisp_elp ( oo00oO0O0 )
   continue
   if 43 - 43: iIii1I11I1II1
   if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
  for I111I in iIiii1IIi1I :
   O0OO0O = iIiii1IIi1I . index ( I111I )
   if ( O0OO0O >= len ( oo00oO0O0 ) ) : O0OO0O = len ( oo00oO0O0 ) - 1
   o00OoO0o0 = oo00oO0O0 [ O0OO0O ]
   if ( O00oO0 == "probe" ) : I111I . probe = ( o00OoO0o0 == "yes" )
   if ( O00oO0 == "strict" ) : I111I . strict = ( o00OoO0o0 == "yes" )
   if ( O00oO0 == "eid" ) : I111I . eid = ( o00OoO0o0 == "yes" )
   if ( O00oO0 == "address" ) : I111I . address . store_address ( o00OoO0o0 )
   if 58 - 58: iIii1I11I1II1 / I1IiiI
   if 64 - 64: I1ii11iIi11i / iII111i / OoOoOO00 + o0oOOo0O0Ooo . Ii1I . oO0o
   if 9 - 9: IiII - II111iiii * OoO0O00
   if 78 - 78: iIii1I11I1II1 / O0 * oO0o / iII111i / OoOoOO00
   if 15 - 15: ooOoO0o / oO0o
   if 54 - 54: ooOoO0o - iIii1I11I1II1 - I11i % Ii1I / II111iiii
 if ( II1I1iIIiIIii == None ) : return
 if 80 - 80: i11iIiiIii % iIii1I11I1II1 / i11iIiiIii
 if 66 - 66: OoOoOO00 . iIii1I11I1II1 * I1ii11iIi11i - Ii1I - iIii1I11I1II1
 if 28 - 28: OoOoOO00 % OoooooooOO
 if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
 II1I1iIIiIIii . elp_nodes = iIiii1IIi1I
 lisp . lisp_elp_list [ II1I1iIIiIIii . elp_name ] = II1I1iIIiIIii
 return
 if 84 - 84: II111iiii
 if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
 if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
 if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
 if 85 - 85: i1IIi . i1IIi
 if 16 - 16: I1IiiI - OOooOOo % Ii1I . OOooOOo + I1ii11iIi11i % i11iIiiIii
 if 59 - 59: i11iIiiIii - I11i
def lisp_rle_command ( kv_pair ) :
 if 59 - 59: OoooooooOO * o0oOOo0O0Ooo / I1Ii111
 IiII1I = None
 oOooOOoo = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for i11Ii1 in range ( len ( kv_pair [ "address" ] ) ) :
   iIOoo000 = lisp . lisp_rle_node ( )
   oOooOOoo . append ( iIOoo000 )
   if 21 - 21: iII111i % IiII % Oo0Ooo % O0
   if 63 - 63: II111iiii * I1IiiI - OoooooooOO / I1IiiI
   if 50 - 50: OoOoOO00 % Ii1I + OoOoOO00 * Ii1I - OOooOOo
 for O00oO0 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ O00oO0 ]
  if 94 - 94: iIii1I11I1II1
  if ( O00oO0 == "rle-name" ) :
   IiII1I = lisp . lisp_rle ( oo00oO0O0 )
   continue
   if 1 - 1: O0
   if 2 - 2: OoO0O00 . I11i
  for I111I in oOooOOoo :
   O0OO0O = oOooOOoo . index ( I111I )
   if ( O0OO0O >= len ( oo00oO0O0 ) ) : O0OO0O = len ( oo00oO0O0 ) - 1
   o00OoO0o0 = oo00oO0O0 [ O0OO0O ]
   if ( O00oO0 == "level" ) :
    if ( o00OoO0o0 == "" ) : o00OoO0o0 = "0"
    I111I . level = int ( o00OoO0o0 )
    if 97 - 97: Oo0Ooo
   if ( O00oO0 == "address" ) : I111I . address . store_address ( o00OoO0o0 )
   if 65 - 65: Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1 . I1Ii111 + ooOoO0o
   if 92 - 92: oO0o
   if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
   if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
   if 47 - 47: IiII . OOooOOo
   if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
 if ( IiII1I == None ) : return
 if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
 if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
 if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
 if 89 - 89: ooOoO0o * I1IiiI . oO0o
 IiII1I . rle_nodes = oOooOOoo
 IiII1I . build_forwarding_list ( )
 lisp . lisp_rle_list [ IiII1I . rle_name ] = IiII1I
 return
 if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
 if 26 - 26: I11i * Ii1I % I1IiiI + iII111i
 if 38 - 38: iII111i - Oo0Ooo / Ii1I + oO0o . iII111i + IiII
 if 19 - 19: Ii1I
 if 51 - 51: iIii1I11I1II1
 if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
 if 8 - 8: OoO0O00 * Oo0Ooo
def lisp_json_command ( kv_pair ) :
 if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
 try :
  iII = kv_pair [ "json-name" ]
  I11Ii1iI1II = kv_pair [ "json-string" ]
 except :
  return
  if 4 - 4: I11i . IiII
  if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
 i1iiIiI1Ii1i = lisp . lisp_json ( iII , I11Ii1iI1II )
 i1iiIiI1Ii1i . add ( )
 return
 if 4 - 4: OoOoOO00 * O0 - I11i
 if 72 - 72: I11i + ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
 if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
 if 70 - 70: II111iiii * II111iiii . I1IiiI
 if 11 - 11: iII111i
 if 20 - 20: Ii1I . I1Ii111 % Ii1I
 if 5 - 5: OOooOOo + iII111i
 if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
 if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
 if 11 - 11: I1ii11iIi11i / O0 + II111iiii
 if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
 if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
def lisp_get_lookup_string ( input_str ) :
 if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
 if 2 - 2: Ii1I
 if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
 if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
 OOOO0oo0 = input_str
 I11iiI1i1 = None
 if ( input_str . find ( "->" ) != - 1 ) :
  I1i1Iiiii = input_str . split ( "->" )
  OOOO0oo0 = I1i1Iiiii [ 0 ]
  I11iiI1i1 = I1i1Iiiii [ 1 ]
  if 81 - 81: iIii1I11I1II1
  if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
 Ii11II11iI1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 OoOo0Oooo0o = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if 65 - 65: OoOoOO00 + I1Ii111 % I1IiiI
 if 54 - 54: I1Ii111 / o0oOOo0O0Ooo
 if 39 - 39: OOooOOo % oO0o * I1ii11iIi11i - O0 + I1IiiI + o0oOOo0O0Ooo
 if 64 - 64: II111iiii / II111iiii
 o0OOo0OOoOO0 = OOOO0oo0 . split ( "/" )
 if ( len ( o0OOo0OOoOO0 ) == 1 ) :
  Ii11II11iI1 . store_address ( o0OOo0OOoOO0 [ 0 ] )
  oo0OOo0Oo00 = False
 else :
  Ii11II11iI1 . store_prefix ( OOOO0oo0 )
  oo0OOo0Oo00 = True
  if 64 - 64: iII111i % OoooooooOO
  if 65 - 65: OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
 I111i = oo0OOo0Oo00
 if ( I11iiI1i1 ) :
  o0OOo0OOoOO0 = I11iiI1i1 . split ( "/" )
  if ( len ( o0OOo0OOoOO0 ) == 1 ) :
   OoOo0Oooo0o . store_address ( o0OOo0OOoOO0 [ 0 ] )
   I111i = False
  else :
   OoOo0Oooo0o . store_prefix ( OOOO0oo0 )
   I111i = True
   if 19 - 19: OoOoOO00 * I1ii11iIi11i * I1ii11iIi11i / O0 / ooOoO0o + I1ii11iIi11i
   if 48 - 48: OoooooooOO . iII111i + O0
 return ( [ Ii11II11iI1 , oo0OOo0Oo00 , OoOo0Oooo0o , I111i ] )
 if 85 - 85: II111iiii - Ii1I
 if 93 - 93: IiII / i11iIiiIii - oO0o + OoO0O00 / i1IIi
 if 62 - 62: I1ii11iIi11i / OoooooooOO * I1IiiI - i1IIi
 if 81 - 81: oO0o / O0 * ooOoO0o % OoOoOO00 / O0
 if 85 - 85: OoooooooOO + OoooooooOO
 if 23 - 23: i1IIi
 if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
def lisp_show_map_cache_lookup ( eid_str ) :
 Ii11II11iI1 , oo0OOo0Oo00 , OoOo0Oooo0o , I111i = lisp_get_lookup_string ( eid_str )
 if 74 - 74: Oo0Ooo - II111iiii - IiII
 i1iiI11I = "<br>"
 if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
 oooOoooOOo0 = Ii11II11iI1 if ( OoOo0Oooo0o . is_null ( ) ) else OoOo0Oooo0o
 I1IIII1 = oo0OOo0Oo00 if ( OoOo0Oooo0o . is_null ( ) ) else I111i
 if 91 - 91: II111iiii
 iiI1iii = lisp . lisp_map_cache . lookup_cache ( oooOoooOOo0 , I1IIII1 )
 if ( iiI1iii == None ) :
  i1iiI11I += "{} {}" . format ( lisp . lisp_print_sans ( "Lookup not found for" ) ,
 lisp . lisp_print_cour ( eid_str ) )
 else :
  if ( oooOoooOOo0 == OoOo0Oooo0o ) :
   iIi1II111I1i1 = iiI1iii . lookup_source_cache ( Ii11II11iI1 , oo0OOo0Oo00 )
   if ( iIi1II111I1i1 ) : iiI1iii = iIi1II111I1i1
   if 10 - 10: O0 . OoOoOO00 * IiII / I1Ii111 / i1IIi
   if 32 - 32: O0 / OOooOOo . ooOoO0o % I1Ii111
  Oo000o = lisp . lisp_print_elapsed ( iiI1iii . uptime )
  i1iiI11I += "{} {} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Exact" if oo0OOo0Oo00 else "Longest" ) ,
  # I1Ii111 - IiII
 lisp . lisp_print_sans ( "match lookup for" ) ,
 lisp . lisp_print_cour ( eid_str ) ,
 lisp . lisp_print_sans ( "found" ) ,
 lisp . lisp_print_cour ( iiI1iii . print_eid_tuple ( ) ) ,
 lisp . lisp_print_sans ( "with uptime" ) ,
 lisp . lisp_print_cour ( Oo000o ) )
  if 24 - 24: I11i / iIii1I11I1II1 . OoooooooOO % OoOoOO00 . Ii1I
 i1iiI11I += "<br>"
 return ( i1iiI11I )
 if 73 - 73: I1Ii111
 if 25 - 25: IiII
 if 77 - 77: o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO . iIii1I11I1II1
 if 87 - 87: II111iiii - OoooooooOO / i1IIi . Ii1I - Oo0Ooo . i11iIiiIii
 if 47 - 47: Oo0Ooo % OoO0O00 - ooOoO0o - Oo0Ooo * oO0o
 if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
 if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
 if 64 - 64: IiII
def lisp_get_clause_for_api ( command ) :
 iiIiiIi = open ( "./lisp.config" , "r" )
 iIi11I11 = { command : [ ] }
 OooooOOOO = { }
 oo000o = [ ]
 if 6 - 6: OOooOOo + I1ii11iIi11i + Oo0Ooo
 III = 0
 ooOo0o = False
 for II1i in iiIiiIi :
  if ( lisp_end_file ( II1i ) ) : break
  if ( lisp_comment ( II1i ) ) : continue
  if 52 - 52: IiII * Oo0Ooo + OoooooooOO
  if 93 - 93: ooOoO0o
  if 15 - 15: i11iIiiIii / o0oOOo0O0Ooo / OoO0O00 . OoOoOO00 % oO0o
  if 29 - 29: o0oOOo0O0Ooo
  if 13 - 13: Ii1I + Ii1I . I11i
  if 57 - 57: ooOoO0o
  if ( II1i . find ( command + " {" ) != - 1 ) :
   III += 1
   ooOo0o = True
   continue
   if 94 - 94: OoO0O00 - II111iiii % iIii1I11I1II1
  if ( ooOo0o == False ) : continue
  if 92 - 92: Oo0Ooo
  if ( lisp_begin_clause ( II1i ) ) :
   III += 1
   i1iII = II1i . replace ( " " , "" )
   i1iII = i1iII . replace ( "\t" , "" )
   i1iII = i1iII . replace ( "\n" , "" )
   i1iII = i1iII . replace ( "{" , "" )
   OooooOOOO = { i1iII : { } }
   continue
   if 83 - 83: o0oOOo0O0Ooo
   if 26 - 26: O0 . II111iiii * O0 + ooOoO0o + OoOoOO00 * O0
   if 46 - 46: ooOoO0o - ooOoO0o * I1ii11iIi11i / iII111i * OOooOOo / o0oOOo0O0Ooo
   if 67 - 67: OOooOOo - Ii1I % iII111i / II111iiii + I1IiiI * ooOoO0o
   if 100 - 100: I1ii11iIi11i
   if 81 - 81: I1ii11iIi11i % iII111i
  if ( lisp_end_clause ( II1i ) ) :
   III -= 1
   if ( III ) :
    iIi11I11 [ command ] . append ( OooooOOOO )
    OooooOOOO = { }
    continue
    if 22 - 22: OoooooooOO + o0oOOo0O0Ooo . I11i + I1IiiI + OoooooooOO . OoOoOO00
   oo000o . append ( iIi11I11 )
   iIi11I11 = { command : [ ] }
   ooOo0o = False
   continue
   if 93 - 93: I1IiiI
   if 89 - 89: OoooooooOO % i11iIiiIii + I1Ii111
  II1i = II1i . replace ( " " , "" )
  II1i = II1i . replace ( "\t" , "" )
  II1i = II1i . replace ( "\n" , "" )
  II1i = II1i . replace ( "{" , "" )
  II1i = II1i . split ( "=" )
  oo00oO0O0 = "" if len ( II1i ) == 1 else II1i [ 1 ]
  I1I111iIi = II1i [ 0 ]
  if 12 - 12: OoOoOO00 * ooOoO0o
  if ( len ( OooooOOOO ) == 0 ) :
   iIi11I11 [ command ] . append ( { I1I111iIi : oo00oO0O0 } )
  else :
   OooooOOOO [ i1iII ] [ I1I111iIi ] = oo00oO0O0
   if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
   if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
   if 50 - 50: ooOoO0o
 iiIiiIi . close ( )
 if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
 if ( len ( oo000o ) == 0 ) :
  oo000o = [ { "?" : [ { "?" : "not-found" } ] } ]
  if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
 return ( oo000o )
 if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
 if 29 - 29: oO0o
 if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
 if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
 if 33 - 33: OoooooooOO . O0
 if 59 - 59: iIii1I11I1II1
 if 45 - 45: O0
def lisp_duplicate_command_clause ( command , clause ) :
 oOoooO000O = open ( "./lisp.config" , "r" )
 if 78 - 78: I11i - iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - I1Ii111
 clause = command + " {\n" + clause
 for II1i in oOoooO000O :
  if ( lisp_begin_clause ( II1i ) == False ) : continue
  if ( II1i . find ( command ) == - 1 ) : continue
  if 21 - 21: OoooooooOO . O0 / i11iIiiIii
  oOOOoo0 = II1i
  for II1i in oOoooO000O :
   oOOOoo0 += II1i
   if ( II1i [ 0 ] != "}" ) : continue
   if ( oOOOoo0 != clause ) : break
   oOoooO000O . close ( )
   return ( True )
   if 43 - 43: I1ii11iIi11i * OOooOOo
  if ( lisp_end_file ( II1i ) ) : break
  if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
  if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
 oOoooO000O . close ( )
 return ( False )
 if 51 - 51: OOooOOo / I11i
 if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
 if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
 if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
 if 26 - 26: i11iIiiIii - ooOoO0o
 if 45 - 45: ooOoO0o + II111iiii % iII111i
 if 55 - 55: ooOoO0o - oO0o % I1IiiI
def lisp_put_clause_for_api ( data ) :
 if 61 - 61: ooOoO0o
 if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
 if 21 - 21: oO0o . i11iIiiIii * I11i . OOooOOo / OOooOOo
 if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
 o00oO00 = data . keys ( ) [ 0 ]
 if ( o00oO00 not in lisp_commands . keys ( ) ) :
  return ( [ { o00oO00 : [ { "?" : "add/replace" } ] } ] )
  if 1 - 1: Ii1I % I1Ii111
  if 97 - 97: OoOoOO00
 IIi1ii1IIi1 = ( o00oO00 in [ "lisp enable" , "lisp debug" , "lisp xtr-parameters" ] )
 if 73 - 73: ooOoO0o - ooOoO0o % I1IiiI . OOooOOo - ooOoO0o / Ii1I
 if 36 - 36: Ii1I + o0oOOo0O0Ooo . iII111i
 if 22 - 22: Ii1I - I11i
 if 7 - 7: OOooOOo / OoOoOO00 * Oo0Ooo % OoooooooOO - OoOoOO00 . i11iIiiIii
 if 36 - 36: oO0o * iII111i + IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1
 if 14 - 14: I11i * oO0o + i11iIiiIii
 if 84 - 84: iII111i / II111iiii
 o0ooO = False
 if ( IIi1ii1IIi1 == False ) :
  o0ooO = True
  iiIiii = commands . getoutput ( "egrep '{}' ./lisp.config" . format ( o00oO00 ) )
  iiIiii = iiIiii . split ( "\n" )
  for II1i in iiIiii :
   if ( II1i [ 0 : len ( o00oO00 ) ] == o00oO00 ) : o0ooO = False
   if 3 - 3: I11i / I1Ii111 * IiII - O0 + I1IiiI / IiII
   if 19 - 19: i1IIi % II111iiii
   if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
   if 56 - 56: Ii1I * i11iIiiIii
   if 92 - 92: II111iiii - O0 . I1Ii111
   if 59 - 59: OoOoOO00
 iiII1iiI = data [ o00oO00 ]
 iiII1iiI = lisp_unicode_to_ascii ( iiII1iiI )
 iIi11I11 = o00oO00 + " {\n" if o0ooO else ""
 if 57 - 57: i11iIiiIii - I11i / ooOoO0o / o0oOOo0O0Ooo * i11iIiiIii * o0oOOo0O0Ooo
 if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
 if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
 if 50 - 50: OoooooooOO + iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii . ooOoO0o
 if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
 if 11 - 11: I11i . Ii1I
 if 87 - 87: OOooOOo + OOooOOo
 if 45 - 45: i1IIi - Oo0Ooo
 for OO0OoOo00 in iiII1iiI :
  if ( type ( iiII1iiI ) == dict ) :
   oo00oO0O0 = iiII1iiI [ OO0OoOo00 ]
   if ( type ( oo00oO0O0 ) == dict ) : oo00oO0O0 = json_dumps ( oo00oO0O0 )
   iIi11I11 += "    " + OO0OoOo00 + " = " + oo00oO0O0 + "\n"
   continue
   if 75 - 75: iIii1I11I1II1 / II111iiii / Ii1I / OoOoOO00
   if 77 - 77: OoOoOO00
  for I1I111iIi in OO0OoOo00 :
   if ( type ( OO0OoOo00 ) == dict ) :
    i111 = I1I111iIi
    oo00oO0O0 = OO0OoOo00 [ I1I111iIi ]
    if 27 - 27: iIii1I11I1II1 + oO0o % Oo0Ooo
   if ( type ( OO0OoOo00 ) == list ) :
    i111 = I1I111iIi . keys ( ) [ 0 ]
    oo00oO0O0 = I1I111iIi . values ( ) [ 0 ]
    if 99 - 99: iIii1I11I1II1 - Oo0Ooo / O0 / IiII
    if 52 - 52: O0 + ooOoO0o
   if ( type ( oo00oO0O0 ) != dict ) :
    iIi11I11 += "    " + I1I111iIi + " = " + OO0OoOo00 [ I1I111iIi ] + "\n"
    continue
    if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
    if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
    if 1 - 1: I1IiiI . Ii1I
    if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
    if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
   iIi11I11 += "    " + i111 + " {\n"
   for ii11Ii1iii1I1 in oo00oO0O0 : iIi11I11 += "        " + ii11Ii1iii1I1 + " = " + oo00oO0O0 [ ii11Ii1iii1I1 ] + "\n"
   iIi11I11 += "    }\n"
   if 65 - 65: O0 * oO0o * II111iiii . I11i - i1IIi * OoOoOO00
   if 28 - 28: I11i % I1Ii111
 iIi11I11 += "}\n"
 if 49 - 49: IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . Ii1I * I1ii11iIi11i
 if 17 - 17: I1ii11iIi11i * OoooooooOO % i1IIi % OoooooooOO . iII111i
 if 20 - 20: OoO0O00 . oO0o
 if 4 - 4: Oo0Ooo % Ii1I % OoO0O00 * iII111i % OoooooooOO
 if ( lisp_duplicate_command_clause ( o00oO00 , iIi11I11 ) ) :
  return ( [ { o00oO00 : [ { "!" : "duplicate" } ] } ] )
  if 38 - 38: OoooooooOO . iII111i
  if 43 - 43: OoooooooOO
 i1i111I = "./lisp.config"
 OOoO0OOoOo0Oo = i1i111I + ".temp"
 if 61 - 61: iII111i % II111iiii / OoOoOO00 % I1ii11iIi11i . iIii1I11I1II1 % O0
 OOOO00oo00oo = open ( i1i111I , "r" )
 OO = open ( OOoO0OOoOo0Oo , "w" )
 if 9 - 9: II111iiii . iII111i - OoOoOO00 . iII111i
 IiiIIIi1I1 = False
 ooI1 = False
 for II1i in OOOO00oo00oo :
  if ( ooI1 ) :
   if ( lisp_end_clause ( II1i ) == False ) : continue
   ooI1 = False
   continue
   if 4 - 4: iII111i % I1ii11iIi11i
   if 9 - 9: O0 * Ii1I
   if 54 - 54: I11i % I11i - ooOoO0o
   if 32 - 32: o0oOOo0O0Ooo % II111iiii / o0oOOo0O0Ooo . OOooOOo . o0oOOo0O0Ooo
   if 29 - 29: OoooooooOO % II111iiii % i11iIiiIii - Oo0Ooo
  if ( IiiIIIi1I1 == False and lisp_begin_clause ( II1i ) and
 II1i [ 0 : len ( o00oO00 ) ] == o00oO00 ) :
   if ( IIi1ii1IIi1 == False ) :
    OO . write ( II1i )
    for iIiIII in iIi11I11 : OO . write ( iIiIII )
    IiiIIIi1I1 = True
    if 52 - 52: I1ii11iIi11i + iIii1I11I1II1 / i1IIi / I1IiiI
    if 67 - 67: Ii1I % i11iIiiIii + I11i
    if 63 - 63: i1IIi
    if 42 - 42: oO0o - i11iIiiIii % oO0o - I1Ii111 * O0 / II111iiii
    if 5 - 5: Oo0Ooo
    if 84 - 84: I1ii11iIi11i
  if ( lisp_end_file ( II1i ) ) :
   if ( o0ooO ) :
    for iIiIII in iIi11I11 : OO . write ( iIiIII )
    if 53 - 53: oO0o
   OO . write ( II1i )
   IiiIIIi1I1 = True
   break
   if 26 - 26: I1Ii111 / I1Ii111 + Oo0Ooo - o0oOOo0O0Ooo % II111iiii . OoooooooOO
   if 7 - 7: II111iiii - I1ii11iIi11i / I11i % OoooooooOO + i1IIi
   if 42 - 42: I11i + i1IIi - Ii1I / IiII . iII111i
   if 30 - 30: Oo0Ooo + Ii1I % i11iIiiIii * i1IIi + I1IiiI % OOooOOo
   if 30 - 30: i11iIiiIii * Oo0Ooo . II111iiii + I1ii11iIi11i / o0oOOo0O0Ooo % I1Ii111
  OO . write ( II1i )
  if 78 - 78: I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
  if 7 - 7: OOooOOo . IiII . I1Ii111 / Ii1I / Oo0Ooo
  if 83 - 83: I11i / Oo0Ooo
  if 23 - 23: iIii1I11I1II1
  if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
  if ( lisp_begin_clause ( II1i ) and II1i [ 0 : len ( o00oO00 ) ] == o00oO00 ) :
   if ( IIi1ii1IIi1 ) :
    ooI1 = True
    for iIiIII in iIi11I11 : OO . write ( iIiIII )
    if 64 - 64: OoO0O00 / I1IiiI
    if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
    if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
    if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
 OOOO00oo00oo . close ( )
 OO . close ( )
 if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
 os . system ( "cp {} {}" . format ( OOoO0OOoOo0Oo , i1i111I ) )
 os . system ( "rm {}" . format ( OOoO0OOoOo0Oo ) )
 return ( [ { o00oO00 : [ { "!" : "add/replace" } ] } ] )
 if 8 - 8: o0oOOo0O0Ooo
 if 78 - 78: i1IIi - Oo0Ooo
 if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
 if 42 - 42: I1Ii111
 if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
 if 80 - 80: OOooOOo
 if 12 - 12: Ii1I
 if 2 - 2: OoooooooOO
def lisp_remove_clause_for_api ( data ) :
 if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
 if 46 - 46: O0 % OoooooooOO
 if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
 if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
 o00oO00 = data . keys ( ) [ 0 ]
 if ( o00oO00 not in lisp_commands . keys ( ) ) :
  return ( [ { o00oO00 : [ { "?" : "delete" } ] } ] )
  if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
  if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
  if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
  if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
  if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
 iiII1iiI = data [ o00oO00 ]
 iiII1iiI = lisp_unicode_to_ascii ( iiII1iiI )
 if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
 if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
 if 65 - 65: I1ii11iIi11i / ooOoO0o
 if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
 oooOOO00OOo = [ ]
 I1I111iIi = iiII1iiI . keys ( ) [ 0 ]
 oo00oO0O0 = iiII1iiI [ I1I111iIi ]
 if 81 - 81: Ii1I + iIii1I11I1II1 - O0 - I1ii11iIi11i - I1IiiI
 if ( type ( oo00oO0O0 ) == dict ) :
  for I1I111iIi in oo00oO0O0 . keys ( ) :
   OO0o = oo00oO0O0 [ I1I111iIi ]
   oooOOO00OOo . append ( I1I111iIi + " = " + OO0o )
   if 84 - 84: iII111i % I1IiiI / iIii1I11I1II1 * Ii1I * iIii1I11I1II1 + I1ii11iIi11i
 else :
  oooOOO00OOo . append ( I1I111iIi + " = " + oo00oO0O0 )
  if 78 - 78: IiII / iII111i * Ii1I . OOooOOo . oO0o - I1Ii111
  if 39 - 39: ooOoO0o . i1IIi + OoooooooOO . iII111i - i11iIiiIii % I1Ii111
  if 38 - 38: oO0o
  if 9 - 9: I11i . OoO0O00 . oO0o / OoooooooOO
  if 59 - 59: iIii1I11I1II1 + i1IIi % II111iiii
  if 2 - 2: II111iiii + I11i . OoO0O00
 if ( o00oO00 == "lisp user-account" ) :
  iIi11I11 = commands . getoutput ( "egrep -A4 '{}' ./lisp.config" . format ( oooOOO00OOo [ 0 ] ) )
  if 14 - 14: OOooOOo * I1IiiI - I1ii11iIi11i
  if 10 - 10: iII111i % I1Ii111 * I1ii11iIi11i * O0 * i11iIiiIii % I1Ii111
  if ( iIi11I11 . find ( "super-user = yes" ) != - 1 ) :
   return ( [ { "lisp user-account" : [ { "?" : "found-superuser" } ] } ] )
   if 68 - 68: OoooooooOO * OoOoOO00
   if 9 - 9: I1Ii111
   if 36 - 36: I1Ii111 / OoOoOO00 + OoOoOO00 * ooOoO0o / OOooOOo * O0
   if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
   if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
   if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
   if 6 - 6: iII111i % o0oOOo0O0Ooo + I1Ii111
 OO0o0O0 = ( "lisp user-account" , "lisp site" , "lisp map-server" ,
 "lisp policy" )
 if 90 - 90: iIii1I11I1II1 % o0oOOo0O0Ooo / OoooooooOO * o0oOOo0O0Ooo
 i1i111I = "./lisp.config"
 OOOO00oo00oo = open ( i1i111I , "r" )
 if 74 - 74: oO0o % OoO0O00 / iII111i
 iIi1I1 = False
 O0o0ooo00o0O = 0
 for II1i in OOOO00oo00oo :
  if ( II1i . find ( o00oO00 ) == - 1 ) : continue
  O0o0ooo00o0O += 1
  if 72 - 72: ooOoO0o % I11i + OoO0O00
  for II1i in OOOO00oo00oo :
   if ( lisp_begin_clause ( II1i ) ) : continue
   o0o0Oo = ( lisp_end_clause ( II1i ) and iIi1I1 )
   if ( o0o0Oo ) : break
   if 55 - 55: iII111i
   Ii11I = II1i . replace ( " " , "" )
   Ii11I = Ii11I . replace ( "\n" , "" )
   Ii11I = Ii11I . replace ( "=" , " = " )
   if 2 - 2: I1Ii111 * OoO0O00 % OoooooooOO
   if ( Ii11I not in oooOOO00OOo ) :
    iIi1I1 = False
    if ( len ( oooOOO00OOo ) > 1 ) : break
    continue
    if 8 - 8: O0 * I1IiiI - OoOoOO00 + I1ii11iIi11i
   iIi1I1 = True
   if 4 - 4: II111iiii % oO0o + o0oOOo0O0Ooo / i11iIiiIii
   o0o0Oo = ( o00oO00 in OO0o0O0 )
   if ( o0o0Oo ) : break
   if 16 - 16: I1IiiI . oO0o . OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
   if 30 - 30: IiII
  if ( o0o0Oo ) : break
  if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
  if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
 OOOO00oo00oo . close ( )
 if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
 if ( not iIi1I1 ) :
  return ( [ { o00oO00 : [ { "?" : "not-found" } ] } ] )
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
  if 84 - 84: OoOoOO00 - I11i
 OOOO00oo00oo = open ( i1i111I , "r" )
 if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
 OOoO0OOoOo0Oo = i1i111I + ".temp"
 OO = open ( OOoO0OOoOo0Oo , "w" )
 if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
 if 68 - 68: OoooooooOO * I11i
 if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
 if 40 - 40: iII111i
 if 62 - 62: ooOoO0o / OOooOOo
 iIi1I1 = False
 for II1i in OOOO00oo00oo :
  if ( II1i . find ( o00oO00 ) != - 1 ) : O0o0ooo00o0O -= 1
  if ( O0o0ooo00o0O == 0 and not iIi1I1 ) :
   if ( II1i [ 0 ] == "}" ) : iIi1I1 = True
   continue
   if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
  OO . write ( II1i )
  if 92 - 92: I11i % I1Ii111
  if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
 OO . close ( )
 OOOO00oo00oo . close ( )
 if 94 - 94: I11i
 os . system ( "cp {} {}" . format ( OOoO0OOoOo0Oo , i1i111I ) )
 os . system ( "rm {}" . format ( OOoO0OOoOo0Oo ) )
 return ( [ { o00oO00 : [ { "!" : "delete" } ] } ] )
 if 37 - 37: oO0o
 if 52 - 52: I1ii11iIi11i * I1IiiI . OOooOOo + i1IIi % oO0o / iIii1I11I1II1
 if 68 - 68: I1Ii111 - OoOoOO00 . i11iIiiIii + o0oOOo0O0Ooo
 if 71 - 71: i11iIiiIii / i1IIi * I1IiiI / OoOoOO00
 if 33 - 33: I11i . Oo0Ooo
 if 89 - 89: iII111i + i1IIi - IiII + ooOoO0o . II111iiii
 if 85 - 85: iIii1I11I1II1 - Ii1I * Oo0Ooo . oO0o + I1Ii111
 if 13 - 13: O0 + iIii1I11I1II1 % II111iiii + iIii1I11I1II1
 if 85 - 85: I1IiiI * iIii1I11I1II1 . iII111i / iII111i
def lisp_u2a_walk_dict_array ( adata , a_dict ) :
 for I1I111iIi in a_dict :
  if ( type ( a_dict [ I1I111iIi ] ) == dict ) :
   i1I1I = { }
   oo00oO0O0 = a_dict [ I1I111iIi ]
   for ii11Ii1iii1I1 in oo00oO0O0 : i1I1I [ ii11Ii1iii1I1 . encode ( ) ] = oo00oO0O0 [ ii11Ii1iii1I1 ] . encode ( )
   adata [ I1I111iIi . encode ( ) ] = i1I1I
  else :
   adata [ I1I111iIi . encode ( ) ] = a_dict [ I1I111iIi ] . encode ( )
   if 45 - 45: OoOoOO00 / I1IiiI
   if 34 - 34: o0oOOo0O0Ooo % I1ii11iIi11i + Ii1I * I11i / oO0o
 return
 if 18 - 18: ooOoO0o
 if 92 - 92: OoO0O00 % iIii1I11I1II1 / IiII * iII111i . i1IIi + oO0o
 if 24 - 24: IiII . iII111i * IiII % i11iIiiIii . i11iIiiIii + i1IIi
 if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
 if 100 - 100: IiII + i1IIi * OoO0O00
 if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
 if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
def lisp_unicode_to_ascii ( udata ) :
 ooIi = ( type ( udata ) == dict )
 if ( ooIi ) : udata = [ udata ]
 if 10 - 10: O0 . II111iiii / OoooooooOO
 ooII1 = [ ]
 for o0OOO in udata :
  IiII11I1I1IIi = { }
  if 44 - 44: OoOoOO00
  if ( type ( o0OOO ) == dict ) :
   lisp_u2a_walk_dict_array ( IiII11I1I1IIi , o0OOO )
  elif ( type ( o0OOO ) == list ) :
   I111 = [ ]
   for O0ooOOO00000O in o0OOO :
    OOoo = { }
    lisp_u2a_walk_dict_array ( OOoo , O0ooOOO00000O )
    I111 . append ( OOoo )
    if 66 - 66: I1ii11iIi11i / i1IIi * I1IiiI - OoOoOO00 + oO0o
   IiII11I1I1IIi = I111
  else :
   IiII11I1I1IIi = { o0OOO . keys ( ) [ 0 ] . encode ( ) : IiII11I1I1IIi }
   if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
  ooII1 . append ( IiII11I1I1IIi )
  if 19 - 19: IiII % OoooooooOO + OoooooooOO
  if 7 - 7: i1IIi
 if ( ooIi ) : ooII1 = ooII1 [ 0 ]
 return ( ooII1 )
 if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
 if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
 if 80 - 80: IiII % OoooooooOO - IiII
 if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
 if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
 if 100 - 100: II111iiii / I1Ii111 / iII111i - I1ii11iIi11i * iIii1I11I1II1
 if 7 - 7: i1IIi . IiII % i11iIiiIii * I1ii11iIi11i . I11i % I1ii11iIi11i
 if 35 - 35: I1IiiI
 if 48 - 48: OoooooooOO % OoooooooOO - OoO0O00 . OoOoOO00
 if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
 if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
 if 41 - 41: OoooooooOO
def lisp_replace_db_list ( db ) :
 O0OO0O = - 1
 for I1I111i in lisp . lisp_db_list :
  if ( db . match_eid_tuple ( I1I111i ) ) :
   O0OO0O = lisp . lisp_db_list . index ( I1I111i )
   break
   if 63 - 63: I1ii11iIi11i . I1IiiI + OOooOOo - IiII + iII111i
   if 78 - 78: Ii1I
 if ( O0OO0O == - 1 ) : return ( False )
 if 29 - 29: II111iiii
 if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
 if 84 - 84: Oo0Ooo % I11i * O0 * I11i
 if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
 if 12 - 12: Oo0Ooo + I1IiiI
 if ( lisp . lisp_nat_traversal and lisp . lisp_i_am_etr ) :
  for i1iIIiiIiII in I1I111i . rloc_set :
   if ( i1iIIiiIiII . is_rloc_translated ( ) == False ) : continue
   II1 = db . get_rloc_by_interface ( i1iIIiiIiII . interface )
   if ( II1 == None ) : continue
   II1 . store_translated_rloc ( i1iIIiiIiII . translated_rloc , i1iIIiiIiII . translated_port )
   II1 . rloc_name = i1iIIiiIiII . rloc_name
   if 37 - 37: i1IIi * i11iIiiIii
   if 95 - 95: i11iIiiIii % I1Ii111 * Oo0Ooo + i1IIi . O0 + I1ii11iIi11i
   if 7 - 7: OoO0O00 * i11iIiiIii * iIii1I11I1II1 / OOooOOo / I1Ii111
 lisp . lisp_db_list [ O0OO0O ] = db
 return ( True )
 if 35 - 35: iII111i * OOooOOo
 if 65 - 65: II111iiii % i1IIi
 if 13 - 13: OoO0O00 * I1Ii111 + Oo0Ooo - IiII
 if 31 - 31: OoO0O00
 if 68 - 68: OoO0O00 + i1IIi / iIii1I11I1II1 + II111iiii * iIii1I11I1II1 + I1ii11iIi11i
 if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
 if 9 - 9: o0oOOo0O0Ooo
 if 55 - 55: OOooOOo % iIii1I11I1II1 + I11i . ooOoO0o
def lisp_database_mapping_command ( kv_pair , ephem_port = None ) :
 ooOo = [ ]
 OOO = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for i11Ii1 in range ( len ( kv_pair [ "address" ] ) ) :
   i1iIIiiIiII = lisp . lisp_rloc ( )
   OOO . append ( i1iIIiiIiII )
   if 47 - 47: i11iIiiIii . IiII
   if 37 - 37: I1IiiI / OoooooooOO % i11iIiiIii % I1ii11iIi11i
   if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
 IIo0oo0OO = [ ]
 for i11Ii1 in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  i1iI11IiII = lisp . lisp_mapping ( "" , "" , OOO )
  IIo0oo0OO . append ( i1iI11IiII )
  if 83 - 83: I1ii11iIi11i
  if 53 - 53: OoOoOO00 % ooOoO0o . OoO0O00 + I1IiiI / I1ii11iIi11i
 for O00oO0 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ O00oO0 ]
  if ( O00oO0 == "mr-name" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    i1iI11IiII = IIo0oo0OO [ i11Ii1 ]
    i1iI11IiII . use_mr_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ i11Ii1 ]
    if 76 - 76: I1ii11iIi11i . iIii1I11I1II1 - i11iIiiIii / I1ii11iIi11i - o0oOOo0O0Ooo
    if 95 - 95: I11i
  if ( O00oO0 == "ms-name" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    i1iI11IiII = IIo0oo0OO [ i11Ii1 ]
    i1iI11IiII . use_ms_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ i11Ii1 ]
    if 76 - 76: II111iiii - i1IIi . O0 * i11iIiiIii % o0oOOo0O0Ooo - iII111i
    if 30 - 30: I1Ii111 % oO0o + oO0o * OoooooooOO - I1ii11iIi11i
  if ( O00oO0 == "instance-id" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    i1iI11IiII = IIo0oo0OO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    o00OoO0o0 = [ "0" ] if ( o00OoO0o0 == "" ) else o00OoO0o0 . split ( )
    for OOoOOo in o00OoO0o0 : o00OoO0o0 [ o00OoO0o0 . index ( OOoOOo ) ] = int ( OOoOOo )
    i1iI11IiII . eid . instance_id = o00OoO0o0 [ 0 ]
    i1iI11IiII . eid . iid_list = o00OoO0o0 [ 1 : : ]
    i1iI11IiII . group . instance_id = o00OoO0o0 [ 0 ]
    if 22 - 22: OoOoOO00 . II111iiii
    if 24 - 24: OoooooooOO / I11i
  if ( O00oO0 == "secondary-instance-id" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    i1iI11IiII = IIo0oo0OO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 == "" ) : continue
    i1iI11IiII . secondary_iid = int ( o00OoO0o0 )
    if ( i1iI11IiII . eid . address == 0 ) :
     lisp . lisp_default_secondary_iid = int ( o00OoO0o0 )
     if 97 - 97: I1ii11iIi11i - ooOoO0o * i11iIiiIii + I1Ii111 % OoooooooOO
     if 44 - 44: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo % O0 / OoooooooOO . OOooOOo
     if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
  if ( O00oO0 == "eid-prefix" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    i1iI11IiII = IIo0oo0OO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) : i1iI11IiII . eid . store_prefix ( o00OoO0o0 )
    if ( i1iI11IiII . eid . address == 0 ) :
     lisp . lisp_default_secondary_iid = i1iI11IiII . secondary_iid
     if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
     if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
     if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
  if ( O00oO0 == "group-prefix" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    i1iI11IiII = IIo0oo0OO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) : i1iI11IiII . group . store_prefix ( o00OoO0o0 )
    if 44 - 44: OoooooooOO
    if 82 - 82: OoOoOO00 . OoOoOO00
  if ( O00oO0 == "dynamic-eid" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    i1iI11IiII = IIo0oo0OO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 == "yes" ) : i1iI11IiII . dynamic_eids = { }
    if 10 - 10: Oo0Ooo * I1ii11iIi11i . oO0o . OoooooooOO . OOooOOo * I1ii11iIi11i
    if 80 - 80: I1Ii111 + I11i . I1Ii111 + OOooOOo
  if ( O00oO0 == "signature-eid" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    i1iI11IiII = IIo0oo0OO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    i1iI11IiII . signature_eid = ( o00OoO0o0 == "yes" )
    if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
    if 43 - 43: IiII . OoooooooOO - II111iiii
    if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
  if ( O00oO0 == "priority" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 == "" ) : o00OoO0o0 = "0"
    i1iIIiiIiII . priority = int ( o00OoO0o0 )
    if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
    if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
  if ( O00oO0 == "weight" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 == "" ) : o00OoO0o0 = "0"
    i1iIIiiIiII . weight = int ( o00OoO0o0 )
    if 15 - 15: Ii1I + OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
    if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
  if ( O00oO0 == "address" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) : i1iIIiiIiII . rloc . store_address ( o00OoO0o0 )
    if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
    if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
  if ( O00oO0 == "interface" ) :
   ii11 = lisp . lisp_hostname
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) :
     i1iIIiiIiII . interface = o00OoO0o0
     II = lisp . lisp_get_interface_address ( o00OoO0o0 )
     if ( II ) :
      i1iIIiiIiII . rloc . copy_address ( II )
      lisp . lisp_myrlocs [ 0 ] = II
      if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
     i1iIIiiIiII . rloc_name = ii11
     ooOo . append ( i1iIIiiIiII )
     if 28 - 28: iIii1I11I1II1 . O0
     if 32 - 32: OoooooooOO
     if 29 - 29: I1ii11iIi11i
  if ( O00oO0 == "elp-name" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) : i1iIIiiIiII . elp_name = o00OoO0o0
    if 41 - 41: Ii1I
    if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
  if ( O00oO0 == "rle-name" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) : i1iIIiiIiII . rle_name = o00OoO0o0
    if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
    if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
  if ( O00oO0 == "json-name" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) : i1iIIiiIiII . json_name = o00OoO0o0
    if 94 - 94: IiII / I1IiiI . II111iiii
    if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
  if ( O00oO0 == "geo-name" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) : i1iIIiiIiII . geo_name = o00OoO0o0
    if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
    if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
  if ( O00oO0 == "rloc-record-name" ) :
   for i11Ii1 in range ( len ( OOO ) ) :
    i1iIIiiIiII = OOO [ i11Ii1 ]
    o00OoO0o0 = oo00oO0O0 [ i11Ii1 ]
    if ( o00OoO0o0 != "" ) : i1iIIiiIiII . rloc_name = o00OoO0o0
    if 49 - 49: I1ii11iIi11i
    if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
    if 18 - 18: Oo0Ooo + IiII
    if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
    if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
    if 31 - 31: Ii1I / iII111i
    if 3 - 3: IiII
    if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
    if 61 - 61: OOooOOo . OOooOOo
    if 17 - 17: II111iiii / ooOoO0o
 if ( len ( ooOo ) > 1 ) :
  for i1iIIiiIiII in ooOo :
   i1iIIiiIiII . rloc_name = ii11 + "-" + i1iIIiiIiII . interface
   if 80 - 80: OOooOOo * OoO0O00 + Ii1I
   if 62 - 62: OoooooooOO . O0 % Oo0Ooo
   if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
   if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
   if 88 - 88: I1Ii111 - OoO0O00
   if 79 - 79: iII111i
 for i1iI11IiII in IIo0oo0OO :
  i1iI11IiII . rloc_set = copy . deepcopy ( i1iI11IiII . rloc_set )
  i1iI11IiII . sort_rloc_set ( )
  i1iI11IiII . add_db ( )
  if ( lisp_replace_db_list ( i1iI11IiII ) ) : continue
  lisp . lisp_db_list . append ( i1iI11IiII )
  if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
  if 48 - 48: I1ii11iIi11i + Oo0Ooo
  if 76 - 76: I1ii11iIi11i
  if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
  if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
 lisp . lisp_write_ipc_database_mappings ( ephem_port )
 if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
 if 82 - 82: OoO0O00
 if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
 if 17 - 17: OoOoOO00
 if 72 - 72: iII111i . Oo0Ooo - i11iIiiIii / I1IiiI
 if 64 - 64: oO0o
 if 80 - 80: o0oOOo0O0Ooo % iIii1I11I1II1
 lisp . lisp_default_iid = lisp . lisp_db_list [ 0 ] . eid . instance_id
 if 63 - 63: IiII * i11iIiiIii
 if 86 - 86: I11i % I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
 if 26 - 26: II111iiii * iII111i + o0oOOo0O0Ooo / O0 + i1IIi - I11i
 if 56 - 56: OOooOOo
 if 76 - 76: i1IIi % iIii1I11I1II1 - o0oOOo0O0Ooo + IiII - I11i
 if 81 - 81: I1ii11iIi11i + OoooooooOO - OOooOOo * O0
 if 100 - 100: iIii1I11I1II1 - OoOoOO00
 if 28 - 28: Oo0Ooo . O0 . I11i
 for i1iI11IiII in IIo0oo0OO :
  if ( i1iI11IiII . eid . address == 0 and i1iI11IiII . eid . mask_len == 0 ) :
   if ( i1iI11IiII . eid . is_ipv4 ( ) or i1iI11IiII . eid . is_ipv6 ( ) ) :
    lisp . lisp_pitr = True
    break
    if 60 - 60: II111iiii + I1Ii111 / oO0o % OoooooooOO - i1IIi
    if 57 - 57: ooOoO0o
    if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if ( i1iI11IiII . dynamic_eids == None ) : continue
  if ( i1iI11IiII . eid . is_mac ( ) and i1iI11IiII . eid . address == 0 and i1iI11IiII . eid . mask_len == 0 ) :
   lisp . lisp_l2_overlay = True
   break
   if 52 - 52: I1ii11iIi11i
   if 93 - 93: iII111i . i11iIiiIii
   if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
   if 49 - 49: O0 . Oo0Ooo / Ii1I
   if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
   if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
   if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
   if 44 - 44: i11iIiiIii
 o0OooO0ooo00o = ( lisp . lisp_myrlocs [ 0 ] != None )
 lisp . lisp_get_local_addresses ( )
 if 29 - 29: iIii1I11I1II1 - I1Ii111 - Ii1I - o0oOOo0O0Ooo + i11iIiiIii
 if ( lisp . lisp_myrlocs [ 0 ] == None and o0OooO0ooo00o ) :
  lisp . lprint ( "No RLOCs found, local addresses changed from RLOC to EID" )
  if 78 - 78: o0oOOo0O0Ooo + iIii1I11I1II1 / I1ii11iIi11i - OoooooooOO - oO0o
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
  if 60 - 60: I1Ii111
  if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
  if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
  if 14 - 14: Ii1I - O0
  if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
  if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
  if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
  if 7 - 7: IiII * ooOoO0o + OoOoOO00
  if 22 - 22: iII111i
  if 48 - 48: I1ii11iIi11i . I1IiiI
  if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
  if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
  if 49 - 49: Oo0Ooo
  if 57 - 57: O0 * ooOoO0o - iII111i - iIii1I11I1II1 * iII111i
  if 9 - 9: IiII . I11i
  if 23 - 23: O0 % OoooooooOO - O0 . I1IiiI + i11iIiiIii
  if 96 - 96: ooOoO0o % O0
  if 51 - 51: I1IiiI - iII111i / I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i
 if ( lisp . lisp_program_hardware == False ) : return
 if 87 - 87: II111iiii . Ii1I * OoO0O00
 iIi1I1 = False
 for i1iI11IiII in IIo0oo0OO :
  if ( i1iI11IiII . dynamic_eids == None ) : continue
  OOoO00o00oo = i1iI11IiII . eid . print_prefix_no_iid ( )
  iIi1I1 = lisp . lisp_i_am_itr
  os . system ( "ip route add {} dev ma1" . format ( OOoO00o00oo ) )
  if 5 - 5: oO0o - OoooooooOO / OoOoOO00
 if ( lisp . lisp_program_hardware and iIi1I1 ) :
  O0O0Ooooo000 = "platform trident diag s cpu_control_1 URPF_MISS_TOCPU=1"
  lisp . lisp_send_to_arista ( O0O0Ooooo000 , None )
  if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
  if 55 - 55: OoO0O00
  if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
  if 32 - 32: Ii1I * oO0o
  if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
  if 28 - 28: Oo0Ooo
  if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
  if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
def lisp_show_db_list ( itr_or_etr , output ) :
 I1I1i1 = "{} database-mapping entries" . format ( len ( lisp . lisp_db_list ) )
 oooo00Oo0O = "LISP-{} Configured Database Mappings:" . format ( itr_or_etr )
 oooo00Oo0O = lisp . lisp_span ( oooo00Oo0O , I1I1i1 )
 if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
 o0Oo = '<a href="/lisp/show/etr/keys"><br>RLOC Keys</a>'
 if 69 - 69: I11i
 if ( itr_or_etr == "ITR" ) :
  output += lisp_table_header ( oooo00Oo0O , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Use MR" )
 else :
  output += lisp_table_header ( oooo00Oo0O , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" + o0Oo , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Receive Stats" ,
 "Map-Replies<br>Sent" , "Use MS" )
  if 17 - 17: I11i
  if 38 - 38: I1Ii111 % OOooOOo
 for i1iI11IiII in lisp . lisp_db_list :
  iii1I1i = lisp . lisp_print_elapsed ( i1iI11IiII . uptime )
  i1iii1i11I1 = i1iI11IiII . map_replies_sent
  if 26 - 26: i11iIiiIii - ooOoO0o / Ii1I + I11i
  if 85 - 85: I1Ii111 - I1ii11iIi11i % Oo0Ooo
  if 3 - 3: O0 % i11iIiiIii
  if 40 - 40: ooOoO0o - i11iIiiIii % I1ii11iIi11i % I1IiiI . IiII * OoO0O00
  OoOO000OO00 = ""
  if ( i1iI11IiII . dynamic_eid_configured ( ) ) :
   IIIi = i1iI11IiII . eid . print_prefix_url ( )
   Oo00o = len ( i1iI11IiII . dynamic_eids )
   OoiIIIiIi1I1i = itr_or_etr . lower ( )
   OoOO000OO00 = ( "<br><a href='/lisp/show/{}/dynamic-eid/{}'>" + "{} dynamic-eids</a>" ) . format ( OoiIIIiIi1I1i , IIIi , Oo00o )
   if 37 - 37: O0
   if 97 - 97: oO0o - OoO0O00 + iII111i * O0
   if 55 - 55: i11iIiiIii + i1IIi % II111iiii + I11i % ooOoO0o
  OO0Oo = True
  for i1iIIiiIiII in i1iI11IiII . rloc_set :
   if ( OO0Oo ) :
    i1iiiI = i1iI11IiII . print_eid_tuple ( )
    i1iiiI = i1iI11IiII . star_secondary_iid ( i1iiiI )
    i1iiiI += OoOO000OO00
    Oo000o = iii1I1i
    OO0Oo = False
   else :
    i1iiiI , Oo000o , i1iii1i11I1 = ( "" , "" , "" )
    if 83 - 83: i1IIi
    if 38 - 38: OoooooooOO * iIii1I11I1II1
   II1iiiiI1 = "" if i1iIIiiIiII . rloc . is_null ( ) else i1iIIiiIiII . rloc . print_address_no_iid ( )
   if 54 - 54: OoooooooOO . I1Ii111
   if 71 - 71: Ii1I
   if ( i1iIIiiIiII . interface != None ) :
    II1iiiiI1 += " ({})" . format ( i1iIIiiIiII . interface )
    if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
   if ( II1iiiiI1 != "" ) : II1iiiiI1 += "<br>"
   if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
   if ( i1iIIiiIiII . translated_rloc . not_set ( ) == False ) :
    II1iiiiI1 += "translated RLOC: {}<br>" . format ( i1iIIiiIiII . translated_rloc . print_address_no_iid ( ) )
    if 93 - 93: ooOoO0o % I1Ii111
    if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
    if 43 - 43: ooOoO0o . i1IIi
   O0oOOoOOoOo = i1iIIiiIiII . print_rloc_name ( True )
   if ( O0oOOoOOoOo != "" ) : II1iiiiI1 += O0oOOoOOoOo + "<br>"
   if 45 - 45: I1IiiI
   if ( i1iIIiiIiII . geo_name != None ) :
    II1iiiiI1 += "geo: " + i1iIIiiIiII . geo_name + "<br>"
    if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
   if ( i1iIIiiIiII . elp_name != None ) :
    II1iiiiI1 += "elp: " + i1iIIiiIiII . elp_name + "<br>"
    if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
   if ( i1iIIiiIiII . rle_name != None ) :
    II1iiiiI1 += "rle: " + i1iIIiiIiII . rle_name + "<br>"
    if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
   if ( i1iIIiiIiII . json_name != None ) :
    II1iiiiI1 += "json: " + i1iIIiiIiII . json_name + "<br>"
    if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
    if 61 - 61: Oo0Ooo - I1Ii111
   if ( itr_or_etr == "ITR" ) :
    output += lisp_table_row ( i1iiiI , Oo000o , II1iiiiI1 ,
 str ( i1iIIiiIiII . priority ) + "/" + str ( i1iIIiiIiII . weight ) ,
 str ( i1iIIiiIiII . mpriority ) + "/" + str ( i1iIIiiIiII . mweight ) ,
 i1iI11IiII . use_mr_name )
   else :
    Oo0oo = i1iIIiiIiII . stats . get_stats ( True , True )
    output += lisp_table_row ( i1iiiI , Oo000o , II1iiiiI1 ,
 str ( i1iIIiiIiII . priority ) + "/" + str ( i1iIIiiIiII . weight ) ,
 str ( i1iIIiiIiII . mpriority ) + "/" + str ( i1iIIiiIiII . mweight ) , Oo0oo ,
 i1iii1i11I1 , i1iI11IiII . use_ms_name )
    if 51 - 51: iII111i * ooOoO0o / O0 / O0
    if 52 - 52: OoooooooOO % O0
    if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
 output += lisp_table_footer ( )
 if 28 - 28: i1IIi / I11i . o0oOOo0O0Ooo
 if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
 if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
 if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
 if ( len ( lisp . lisp_geo_list ) != 0 ) :
  oooo00Oo0O = "Configured Geo-Coordinates:"
  output += lisp_table_header ( oooo00Oo0O , "Geo Name" ,
 "Geo-Prefix or Geo-Point" )
  iiII1i1II1iIi = sorted ( lisp . lisp_geo_list )
  for o0o0Oo0oo in iiII1i1II1iIi :
   O0oooOO = lisp . lisp_geo_list [ o0o0Oo0oo ]
   output += lisp_table_row ( o0o0Oo0oo , O0oooOO . print_geo_url ( ) )
   if 8 - 8: OoooooooOO
  output += lisp_table_footer ( )
  if 60 - 60: OOooOOo * OoOoOO00 % Oo0Ooo
 return ( output )
 if 61 - 61: I11i . iIii1I11I1II1 - II111iiii % I11i * O0 % Oo0Ooo
 if 17 - 17: i1IIi % OoOoOO00 . Oo0Ooo - I1ii11iIi11i
 if 37 - 37: I1Ii111 * Ii1I + Oo0Ooo * I1Ii111 % o0oOOo0O0Ooo . Oo0Ooo
 if 37 - 37: Ii1I / II111iiii
 if 66 - 66: ooOoO0o + oO0o % OoooooooOO
 if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
 if 17 - 17: IiII
def lisp_interface_command ( kv_pair ) :
 iiI = None
 II1ii1 = None
 OOO00O00ooo0o = None
 OoOoo = None
 O0oOoOooo00oo = None
 OOO0OO00 = None
 oOO00 = None
 II1IiII1I1II = None
 if 97 - 97: i1IIi
 for O00oO0 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ O00oO0 ]
  if ( O00oO0 == "interface-name" ) : iiI = oo00oO0O0
  if ( O00oO0 == "device" ) : II1ii1 = oo00oO0O0
  if ( O00oO0 == "instance-id" ) : OOO00O00ooo0o = oo00oO0O0
  if ( O00oO0 == "dynamic-eid" ) : OoOoo = oo00oO0O0
  if ( O00oO0 == "multi-tenant-eid" ) : oOO00 = oo00oO0O0
  if ( O00oO0 == "dynamic-eid-device" ) : O0oOoOooo00oo = oo00oO0O0
  if ( O00oO0 == "dynamic-eid-timeout" ) : OOO0OO00 = oo00oO0O0
  if ( O00oO0 == "lisp-nat" ) : II1IiII1I1II = ( oo00oO0O0 == "yes" )
  if 29 - 29: I1IiiI
  if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
 if ( II1ii1 == None ) : return
 if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
 if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
 if 59 - 59: I1Ii111 * iII111i
 if 31 - 31: I11i / O0
 if 57 - 57: i1IIi % ooOoO0o
 if 69 - 69: o0oOOo0O0Ooo
 if 69 - 69: I1Ii111
 if 83 - 83: iIii1I11I1II1 . o0oOOo0O0Ooo + I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
 if ( lisp . lisp_myinterfaces . has_key ( II1ii1 ) and oOO00 == None ) :
  o0o0O0oOOoO0 = lisp . lisp_myinterfaces [ II1ii1 ]
 else :
  o0o0O0oOOoO0 = lisp . lisp_interface ( II1ii1 )
  lisp . lisp_myinterfaces [ II1ii1 ] = o0o0O0oOOoO0
  if 3 - 3: IiII % i1IIi % OoOoOO00 + I1ii11iIi11i
  if 41 - 41: OoOoOO00 / iIii1I11I1II1
  if 92 - 92: Ii1I . iII111i % I1Ii111 % O0
  if 93 - 93: OOooOOo - i11iIiiIii . OoooooooOO
  if 86 - 86: I1IiiI . I1IiiI
 o0o0O0oOOoO0 . interface_name = iiI
 if ( OOO00O00ooo0o != None ) :
  if ( OOO00O00ooo0o . isdigit ( ) == False ) : OOO00O00ooo0o = "0"
  o0o0O0oOOoO0 . instance_id = int ( OOO00O00ooo0o )
  if 67 - 67: i11iIiiIii . ooOoO0o / iIii1I11I1II1 % Ii1I * oO0o - O0
 if ( OoOoo != None ) :
  o0o0O0oOOoO0 . dynamic_eid . store_prefix ( OoOoo )
  o0o0O0oOOoO0 . dynamic_eid . instance_id = o0o0O0oOOoO0 . instance_id
  if 100 - 100: OoooooooOO / Oo0Ooo - Ii1I . I11i / OoooooooOO - I11i
 if ( O0oOoOooo00oo != None ) :
  o0o0O0oOOoO0 . dynamic_eid_device = O0oOoOooo00oo
  if 86 - 86: I11i + Oo0Ooo * OOooOOo * i1IIi / OoooooooOO
 if ( OOO0OO00 != None ) :
  o0o0O0oOOoO0 . dynamic_eid_timeout = int ( OOO0OO00 )
  if 64 - 64: OOooOOo + o0oOOo0O0Ooo / i11iIiiIii - OoOoOO00 + OOooOOo
 if ( oOO00 != None ) :
  o0o0O0oOOoO0 . multi_tenant_eid . store_prefix ( oOO00 )
  o0o0O0oOOoO0 . multi_tenant_eid . instance_id = int ( o0o0O0oOOoO0 . instance_id )
  lisp . lisp_multi_tenant_interfaces . append ( o0o0O0oOOoO0 )
  if 90 - 90: i1IIi % OoO0O00 / ooOoO0o - O0 + i11iIiiIii
 if ( II1IiII1I1II ) :
  oO0ooOoOooO00o00 = "sudo iptables -t nat -C POSTROUTING -o {} -j MASQUERADE"
  oO0ooOoOooO00o00 = commands . getoutput ( oO0ooOoOooO00o00 . format ( II1ii1 ) )
  if ( oO0ooOoOooO00o00 != "" ) :
   o0O = lisp . lisp_get_loopback_address ( )
   if ( o0O ) :
    oo00Oo0oo0 = "sudo iptables -t nat -A POSTROUTING -s {} -j ACCEPT"
    os . system ( oo00Oo0oo0 . format ( o0O ) )
    if 22 - 22: ooOoO0o . o0oOOo0O0Ooo * Ii1I - ooOoO0o / I1IiiI
   oo00Oo0oo0 = "sudo iptables -t nat -A POSTROUTING -o {} -j MASQUERADE"
   os . system ( oo00Oo0oo0 . format ( II1ii1 ) )
   os . system ( "sudo sysctl net.ipv4.ip_forward=1" )
   if 100 - 100: I11i - OOooOOo - OoooooooOO * OoO0O00 * iII111i + oO0o
   if 100 - 100: I1Ii111 - i1IIi
   if 90 - 90: Ii1I + oO0o . II111iiii - OoOoOO00 % iIii1I11I1II1
 lisp . lisp_iid_to_interface [ OOO00O00ooo0o ] = o0o0O0oOOoO0
 if 24 - 24: IiII / Ii1I * OOooOOo
 if 33 - 33: OOooOOo
 if 22 - 22: O0 + OOooOOo % i1IIi
 if 83 - 83: O0 + Ii1I % i11iIiiIii
 if 32 - 32: I1Ii111 % Oo0Ooo - I11i + O0
 if ( "SO_BINDTODEVICE" in dir ( socket ) ) : o0o0O0oOOoO0 . set_socket ( II1ii1 )
 if ( "PF_PACKET" in dir ( socket ) ) : o0o0O0oOOoO0 . set_bridge_socket ( II1ii1 )
 if 57 - 57: OoO0O00 + I1Ii111 . I11i . i1IIi - o0oOOo0O0Ooo / Oo0Ooo
 if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
 if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
 if 76 - 76: OoO0O00 * oO0o - OoO0O00
 lisp . lisp_get_local_addresses ( )
 if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
 if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
 if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
 if 70 - 70: O0 . Ii1I
 if 33 - 33: OOooOOo * Ii1I
 if 64 - 64: i11iIiiIii . iIii1I11I1II1
 if ( OoOoo != None and lisp . lisp_program_hardware ) :
  O0O0Ooooo000 = "ip verify unicast source reachable-via rx"
  lisp . lisp_send_to_arista ( O0O0Ooooo000 , II1ii1 )
  O0O0Ooooo000 = 'sysctl -w "net.ipv4.conf.{}.rp_filter=0"' . format ( II1ii1 )
  os . system ( O0O0Ooooo000 )
  if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
  if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
  if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
  if 70 - 70: I11i . I1ii11iIi11i * oO0o
  if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
 lisp . lisp_write_ipc_interfaces ( )
 return
 if 23 - 23: I1ii11iIi11i % I11i
 if 18 - 18: OoooooooOO . i1IIi + II111iiii
 if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
 if 34 - 34: I1Ii111 * I11i
 if 31 - 31: IiII . oO0o
 if 40 - 40: Ii1I - I11i / II111iiii * i1IIi + IiII * II111iiii
 if 53 - 53: I1ii11iIi11i - i11iIiiIii . OoO0O00 / OoOoOO00 - I1Ii111
 if 99 - 99: Ii1I - IiII - i1IIi / i11iIiiIii . IiII
def lisp_parse_eid_in_url ( command , eid_prefix ) :
 I11iiI1i1 = ""
 if 58 - 58: OOooOOo
 if 12 - 12: I1IiiI . o0oOOo0O0Ooo * OoooooooOO
 if 64 - 64: OoOoOO00 + IiII - i1IIi . II111iiii . OoO0O00
 if 31 - 31: oO0o . iII111i - I11i . iIii1I11I1II1 + I11i . OoOoOO00
 if ( eid_prefix == "0--0" ) :
  command = command + "%[0]/0%"
 elif ( eid_prefix . find ( "-name-" ) != - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if ( len ( eid_prefix ) > 4 ) :
   eid_prefix = [ eid_prefix [ 0 ] , "name" , "-" . join ( eid_prefix [ 2 : - 1 ] ) ,
 eid_prefix [ - 1 ] ]
   if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
   if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
   if 30 - 30: OoooooooOO % OOooOOo
   if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
   if 81 - 81: iII111i % Ii1I . ooOoO0o
  OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]'" + eid_prefix [ 2 ] + "'" + "/" + eid_prefix [ 3 ]
  if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  command = command + "%" + OOOO0oo0 + "%"
 elif ( eid_prefix . count ( "-" ) in [ 9 , 10 ] ) :
  if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
  if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
  if 20 - 20: ooOoO0o
  if 63 - 63: iIii1I11I1II1 . OoO0O00
  eid_prefix = eid_prefix . split ( "-" )
  OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + "-" . join ( eid_prefix [ 1 : - 1 ] ) + "/" + eid_prefix [ - 1 ]
  if 100 - 100: i1IIi * i1IIi
  command = command + "%" + OOOO0oo0 + "%"
 elif ( eid_prefix . find ( "." ) == - 1 and eid_prefix . find ( ":" ) == - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
  if 94 - 94: IiII
  if 15 - 15: Ii1I - IiII / O0
  if 28 - 28: I1Ii111 . i1IIi / I1ii11iIi11i
  if ( eid_prefix [ 1 ] == "plus" ) :
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]+" + eid_prefix [ 2 ] + "/" + eid_prefix [ 3 ]
   if 77 - 77: i11iIiiIii / I1Ii111 / i11iIiiIii % OoOoOO00 - I1Ii111
   command = command + "%" + OOOO0oo0 + "%"
  else :
   if 80 - 80: I1Ii111 % OoOoOO00 . OoooooooOO . II111iiii % IiII
   if 6 - 6: I1Ii111 % IiII / Ii1I + I1Ii111 . oO0o
   if 70 - 70: iIii1I11I1II1 / Ii1I
   if 61 - 61: O0 * o0oOOo0O0Ooo + I1Ii111 - OOooOOo . I1IiiI - IiII
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "-" + eid_prefix [ 2 ] + "-" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 7 - 7: I1ii11iIi11i
   if 81 - 81: Oo0Ooo % II111iiii % o0oOOo0O0Ooo / I11i
   if 95 - 95: OoOoOO00 - O0 % OoooooooOO
   if 13 - 13: i11iIiiIii
   if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
   if ( len ( eid_prefix ) == 10 ) :
    I11iiI1i1 = "[" + eid_prefix [ 5 ] + "]" + eid_prefix [ 6 ] + "-" + eid_prefix [ 7 ] + "-" + eid_prefix [ 8 ] + "/" + eid_prefix [ 9 ]
    if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
    command = command + "%" + OOOO0oo0 + "%" + I11iiI1i1
   else :
    command = command + "%" + OOOO0oo0 + "%"
    if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
    if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
    if 69 - 69: Oo0Ooo * ooOoO0o
 else :
  if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
  if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
  if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
  if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
  eid_prefix = eid_prefix . split ( "-" )
  if ( eid_prefix [ 1 ] == "*" ) :
   OOOO0oo0 = ""
   I11iiI1i1 = "[" + eid_prefix [ 2 ] + "]" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 24 - 24: OoOoOO00 * Ii1I
  else :
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "/" + eid_prefix [ 2 ]
   if 17 - 17: OoO0O00 . I1IiiI * O0
   if ( len ( eid_prefix ) == 6 ) :
    I11iiI1i1 = "[" + eid_prefix [ 3 ] + "]" + eid_prefix [ 4 ] + "/" + eid_prefix [ 5 ]
    if 81 - 81: OOooOOo
    if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
    if 41 - 41: I11i + OoO0O00 . iII111i
  command = command + "%" + OOOO0oo0 + "%" + I11iiI1i1
  if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
 return ( command )
 if 56 - 56: i1IIi
 if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
 if 82 - 82: IiII
 if 10 - 10: Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
 if 54 - 54: i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i / I1IiiI . iIii1I11I1II1 / iII111i
 if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
 if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
def lisp_show_dynamic_eid_command ( parm ) :
 i1iiI11I = ""
 if ( parm == "" ) : return ( i1iiI11I )
 if 30 - 30: I11i - OoO0O00
 Ii11II11iI1 = lisp_get_lookup_string ( parm . split ( "%" ) [ 0 ] )
 Ii11II11iI1 = Ii11II11iI1 [ 0 ]
 if 15 - 15: OoooooooOO
 i1iI11IiII = lisp . lisp_db_for_lookups . lookup_cache ( Ii11II11iI1 , False )
 if ( i1iI11IiII == None ) : return ( i1iiI11I )
 if 31 - 31: II111iiii
 OoiIIIiIi1I1i = "ITR" if lisp . lisp_i_am_itr else "ETR"
 OOOO0oo0 = i1iI11IiII . print_eid_tuple ( )
 if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
 oooo00Oo0O = "LISP-{} Discovered Dynamic EIDs for {}:" . format ( OoiIIIiIi1I1i , OOOO0oo0 )
 if 87 - 87: IiII
 if ( OoiIIIiIi1I1i == "ITR" ) :
  i1iiI11I = lisp_table_header ( oooo00Oo0O , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Last Packet" , "Inactivity Timeout" )
 else :
  i1iiI11I = lisp_table_header ( oooo00Oo0O , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Inactivity Timeout" )
  if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
  if 55 - 55: IiII
 for OOoO00o00oo in i1iI11IiII . dynamic_eids . values ( ) :
  Ii11II11iI1 = OOoO00o00oo . dynamic_eid . print_address ( )
  iiii11IiI1 = lisp . lisp_print_elapsed ( OOoO00o00oo . uptime )
  IiiIi = str ( OOoO00o00oo . timeout ) + " secs"
  if ( OoiIIIiIi1I1i == "ITR" ) :
   OoO0o00o = lisp . lisp_print_elapsed ( OOoO00o00oo . last_packet )
   i1iiI11I += lisp_table_row ( Ii11II11iI1 , OOoO00o00oo . interface , iiii11IiI1 , OoO0o00o , IiiIi )
  else :
   i1iiI11I += lisp_table_row ( Ii11II11iI1 , OOoO00o00oo . interface , iiii11IiI1 , IiiIi )
   if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
   if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
 i1iiI11I += lisp_table_footer ( )
 return ( i1iiI11I )
 if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
 if 80 - 80: oO0o / O0
 if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
 if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
 if 59 - 59: IiII
 if 54 - 54: OOooOOo
 if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
def lisp_clear_decap_stats ( command ) :
 OoOo000o = command . split ( "%" ) [ 1 ]
 lisp . lisp_decap_stats [ OoOo000o ] = lisp . lisp_stats ( )
 if 40 - 40: Oo0Ooo * OoooooooOO + IiII
 if 58 - 58: I1IiiI
 if 21 - 21: IiII - I1IiiI . OOooOOo - oO0o
 if 1 - 1: iIii1I11I1II1 / i11iIiiIii * II111iiii
 if 48 - 48: I1ii11iIi11i + O0 * oO0o + I1ii11iIi11i + I1ii11iIi11i
 if 60 - 60: II111iiii % Oo0Ooo
 if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
def lisp_show_decap_stats ( output , etr_or_rtr ) :
 i1III1i = etr_or_rtr . upper ( )
 I11IiI1I11i1i = etr_or_rtr . lower ( )
 if 39 - 39: II111iiii - Ii1I / oO0o . IiII % I1IiiI
 iIIi11 = [ ]
 for I1I111iIi in lisp . lisp_decap_stats :
  IiiIIiIi1iIiI = "<a href='/lisp/clear/{}/stats/{}'>{}</a>" . format ( I11IiI1I11i1i , I1I111iIi , I1I111iIi )
  iIIi11 . append ( IiiIIiIi1iIiI )
  if 78 - 78: IiII
  if 58 - 58: i11iIiiIii - OoOoOO00
 OOO0 = "LISP-{} Decapsulation Stats:" . format ( i1III1i )
 output += lisp_table_header ( OOO0 , * iIIi11 )
 if 75 - 75: I1IiiI
 iIIi11 = [ ]
 for o00 in lisp . lisp_decap_stats . values ( ) :
  iIIi11 . append ( o00 . get_stats ( False , True ) )
  if 92 - 92: i1IIi
 output += lisp_table_row ( * iIIi11 )
 output += lisp_table_footer ( )
 return ( output )
 if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
 if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
 if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
 if 4 - 4: Ii1I
 if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
 if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
 if 32 - 32: I1Ii111 / oO0o / I1IiiI
 if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
def lisp_show_crypto_list ( xtr ) :
 i1iiI11I = ""
 oOoo0ooo0 = len ( lisp . lisp_crypto_keys_by_nonce ) != 0
 if 97 - 97: i1IIi % OoooooooOO
 if ( lisp . lisp_i_am_itr or lisp . lisp_i_am_rtr ) :
  if ( oOoo0ooo0 ) :
   oooo00Oo0O = "LISP-{} Nonce Crypto State" . format ( xtr )
   i1iiI11I += lisp_table_header ( oooo00Oo0O , "Nonce" , "Uptime" , "Key-ID" ,
 "Key Material" )
   for I1I111iIi in lisp . lisp_crypto_keys_by_nonce :
    i1ii1i1i1 = "0x" + lisp . lisp_hex_string ( I1I111iIi )
    oo00oO0O0 = lisp . lisp_crypto_keys_by_nonce [ I1I111iIi ]
    for O0I1i1I1IIIi1II in oo00oO0O0 :
     if ( O0I1i1I1IIIi1II == None ) : continue
     i1IiI = lisp . lisp_print_elapsed ( O0I1i1I1IIIi1II . uptime )
     o0Oo = O0I1i1I1IIIi1II . print_keys ( False )
     i1iiI11I += lisp_table_row ( i1ii1i1i1 , i1IiI , O0I1i1I1IIIi1II . key_id , o0Oo )
     i1ii1i1i1 = ""
     if 31 - 31: I11i + OoO0O00 / I1IiiI * O0 + O0
     if 34 - 34: IiII
   i1iiI11I += lisp_table_footer ( )
   if 5 - 5: OoO0O00 . I1IiiI
   if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
  oooo00Oo0O = "LISP-{} Encapsulation Crypto State" . format ( xtr )
  i1iiI11I += lisp_table_header ( oooo00Oo0O , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for I1I111iIi in lisp . lisp_crypto_keys_by_rloc_encap :
   i1ii1i1i1 = I1I111iIi
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_encap [ I1I111iIi ]
   for O0I1i1I1IIIi1II in oo00oO0O0 :
    if ( O0I1i1I1IIIi1II == None ) : continue
    i1IiI = lisp . lisp_print_elapsed ( O0I1i1I1IIIi1II . uptime )
    i1Iii = lisp . lisp_print_elapsed ( O0I1i1I1IIIi1II . last_rekey )
    o0Oo = O0I1i1I1IIIi1II . print_keys ( False )
    i1iiI11I += lisp_table_row ( i1ii1i1i1 , i1IiI , i1Iii , O0I1i1I1IIIi1II . rekey_count ,
 O0I1i1I1IIIi1II . use_count , O0I1i1I1IIIi1II . key_id , o0Oo )
    i1ii1i1i1 = ""
    if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
    if 23 - 23: i1IIi
  i1iiI11I += lisp_table_footer ( )
  if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
  if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
 if ( lisp . lisp_i_am_etr or lisp . lisp_i_am_rtr ) :
  oooo00Oo0O = "LISP-{} Decapsulation Crypto State" . format ( xtr )
  i1iiI11I += lisp_table_header ( oooo00Oo0O , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for I1I111iIi in lisp . lisp_crypto_keys_by_rloc_decap :
   i1ii1i1i1 = I1I111iIi
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_decap [ I1I111iIi ]
   for O0I1i1I1IIIi1II in oo00oO0O0 :
    if ( O0I1i1I1IIIi1II == None ) : continue
    i1IiI = lisp . lisp_print_elapsed ( O0I1i1I1IIIi1II . uptime )
    i1Iii = lisp . lisp_print_elapsed ( O0I1i1I1IIIi1II . last_rekey )
    o0Oo = O0I1i1I1IIIi1II . print_keys ( False )
    i1iiI11I += lisp_table_row ( i1ii1i1i1 , i1IiI , i1Iii , O0I1i1I1IIIi1II . rekey_count ,
 O0I1i1I1IIIi1II . use_count , O0I1i1I1IIIi1II . key_id , o0Oo )
    i1ii1i1i1 = ""
    if 31 - 31: I1Ii111 - I11i
    if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
  i1iiI11I += lisp_table_footer ( )
  if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
 return ( i1iiI11I )
 if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
 if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
 if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
