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
 "lisp interface" : [ "lisp-itr" , "lisp-etr" ] ,
 "lisp rtr-list" : [ "lisp-core" ] ,
 "lisp map-resolver" : [ "lisp-itr" , "lisp-rtr" ] ,
 "lisp map-cache" : [ "lisp-itr" , "lisp-rtr" ] ,
 "lisp itr-map-cache" : [ "lisp-itr" ] ,
 "lisp rtr-map-cache" : [ "lisp-rtr" ] ,
 "lisp map-server" : [ "lisp-etr" ] ,
 "lisp database-mapping" : [ "lisp-itr" , "lisp-etr" , "lisp-rtr" ] ,
 "lisp group-mapping" : [ "lisp-etr" ] ,
 "lisp explicit-locator-path" : [ "lisp-itr" , "lisp-rtr" , "lisp-etr" ,
 "lisp-ms" ] ,
 "lisp replication-list-entry" : [ "lisp-itr" , "lisp-rtr" , "lisp-etr" ,
 "lisp-ms" ] ,
 "lisp geo-coordinates" : [ "lisp-itr" , "lisp-etr" , "lisp-ms" ] ,
 "lisp json" : [ "lisp-etr" , "lisp-rtr" , "lisp-ms" ] ,
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
 III11I1 = clause . count ( "decentralized-xtr =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "decentralized-xtr" ] = [ "" ] * III11I1
  if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 III11I1 = clause . count ( "register-reachable-rtrs =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "register-reachable-rtrs" ] = [ "" ] * III11I1
  if 17 - 17: OOooOOo / OOooOOo / I11i
  if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
  if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
  if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
  if 9 - 9: Ii1I
  if 59 - 59: I1IiiI * II111iiii . O0
  if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
  if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 if ( I1IiIiiIiIII == { } ) :
  III11I1 = max ( clause . count ( "address =" ) , clause . count ( "dns-name =" ) )
  if ( III11I1 != 0 ) : I1IiIiiIiIII [ "address" ] = [ "" ] * III11I1
  if ( III11I1 != 0 ) : I1IiIiiIiIII [ "dns-name" ] = [ "" ] * III11I1
  III11I1 = clause . count ( "mr-name =" )
  if ( III11I1 != 0 ) : I1IiIiiIiIII [ "mr-name" ] = [ "" ] * III11I1
  III11I1 = clause . count ( "ms-name =" )
  if ( III11I1 != 0 ) : I1IiIiiIiIII [ "ms-name" ] = [ "" ] * III11I1
  if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
 return ( I1IiIiiIiIII )
 if 27 - 27: O0
 if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
 if 28 - 28: i1IIi - iII111i
 if 54 - 54: iII111i - O0 % OOooOOo
 if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
 if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if 28 - 28: I11i
 if 58 - 58: OoOoOO00
def lisp_syntax_check ( kv_pairs , clause ) :
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 if 73 - 73: i11iIiiIii - IiII
 if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
 if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
 if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 IIIII = lisp_setup_kv_pairs ( clause )
 if 78 - 78: Ii1I * i1IIi
 clause = clause . split ( "\n" )
 iI11 = ""
 o00oOoOo0 = 0
 o0O0O0ooo0oOO = False
 O0OO0O = 0
 oo000 = ""
 if 32 - 32: i1IIi . Ii1I
 for oOO in clause :
  if ( len ( oOO ) == 0 ) : continue
  if ( oOO == "" ) : continue
  if ( lisp_comment ( oOO ) ) :
   oOO = oOO . replace ( "#" , "%" )
   iI11 += lisp_write_line ( oOO )
   continue
   if 54 - 54: I1IiiI / iIii1I11I1II1 / OOooOOo . OOooOOo % iII111i . I1IiiI
   if 10 - 10: o0oOOo0O0Ooo + OOooOOo
  IIII1i = oOO . find ( "json-string" ) != - 1
  if 2 - 2: iIii1I11I1II1 * Oo0Ooo % oO0o - II111iiii - iII111i
  if ( lisp_begin_clause ( oOO ) and IIII1i == False ) :
   iI11 += lisp_write_line ( oOO )
   o00oOoOo0 += 1
   if ( oo000 == oOO ) :
    O0OO0O += 1
   else :
    O0OO0O = 0
    oo000 = oOO
    if 3 - 3: I1Ii111
   continue
   if 45 - 45: I1Ii111
  if ( lisp_end_clause ( oOO ) and IIII1i == False ) :
   o00oOoOo0 -= 1
   if ( o00oOoOo0 == 0 ) :
    iI11 += lisp_write_line ( oOO )
    break
    if 83 - 83: OoOoOO00 . OoooooooOO
   if ( o0O0O0ooo0oOO ) :
    iI11 += "%" + oOO + "\n"
   else :
    iI11 += lisp_write_line ( oOO )
    if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
   continue
   if 62 - 62: OoO0O00 / I1ii11iIi11i
  if ( o0O0O0ooo0oOO ) :
   iI11 += "%" + oOO + "\n"
   continue
   if 7 - 7: OoooooooOO . IiII
   if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
   if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
   if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
   if 92 - 92: ooOoO0o
   if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  Oo00OoOo = oOO . split ( "=" , 1 )
  if 24 - 24: i11iIiiIii - I1Ii111
  if ( len ( Oo00OoOo ) == 1 ) :
   iI11 += lisp_write_error ( oOO , "no equal sign" )
   o0O0O0ooo0oOO = True
   continue
   if 21 - 21: I11i
   if 92 - 92: i11iIiiIii / I1Ii111 - iII111i % ooOoO0o * I1Ii111 + Oo0Ooo
  ii1 = Oo00OoOo [ 0 ] . replace ( " " , "" )
  if 80 - 80: OoooooooOO - OOooOOo * Ii1I * I1ii11iIi11i / I1IiiI / OOooOOo
  if 13 - 13: I1Ii111 * ooOoO0o + i11iIiiIii * I1Ii111 - ooOoO0o
  if 23 - 23: iIii1I11I1II1 * i1IIi % OoooooooOO * IiII
  if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
  if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
  if ( ii1 == "description" or ii1 == "geo-tag" ) :
   oo00oO0O0 = Oo00OoOo [ 1 ]
  elif ( ii1 == "json-string" ) :
   oo00oO0O0 = Oo00OoOo [ 1 ] [ 1 : : ]
  else :
   if ( ii1 == "eid-prefix" and Oo00OoOo [ 1 ] . count ( "'" ) == 2 ) :
    oo00oO0O0 = Oo00OoOo [ 1 ] [ 1 : : ]
   elif ( ii1 == "instance-id" ) :
    oo00oO0O0 = Oo00OoOo [ 1 ] [ 1 : : ]
   else :
    oo00oO0O0 = Oo00OoOo [ 1 ] . replace ( " " , "" )
    if 69 - 69: O0
    if 85 - 85: ooOoO0o / O0
    if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
  ii1 = ii1 . replace ( "\t" , "" )
  oo00oO0O0 = oo00oO0O0 . replace ( "\t" , "" )
  if 62 - 62: I1Ii111 . IiII . OoooooooOO
  if ( not kv_pairs . has_key ( ii1 ) ) :
   iI11 += lisp_write_error ( oOO , "invalid command keyword" )
   o0O0O0ooo0oOO = True
   continue
   if 11 - 11: OOooOOo / I11i
   if 73 - 73: i1IIi / i11iIiiIii
   if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
   if 85 - 85: OoOoOO00 + OOooOOo
   if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
   if 27 - 27: Ii1I
   if 67 - 67: I1IiiI
   if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
  if ( len ( kv_pairs [ ii1 ] ) <= 1 ) :
   O000Oo0o = ""
   if ( ii1 == "eid-prefix" and not lisp_valid_prefix_format ( oo00oO0O0 ) ) :
    O000Oo0o = "invalid prefix"
    if 99 - 99: iIii1I11I1II1 % ooOoO0o + ooOoO0o + iII111i - I1Ii111 / I1Ii111
   if ( ii1 == "address" and not lisp . lisp_valid_address_format ( ii1 , oo00oO0O0 ) ) :
    if 7 - 7: I1IiiI + OoOoOO00 / IiII
    O000Oo0o = "invalid address"
    if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
   if ( O000Oo0o != "" ) :
    iI11 += lisp_write_error ( oOO , O000Oo0o )
    o0O0O0ooo0oOO = True
    continue
    if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
    if 61 - 61: II111iiii
    if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
    if 90 - 90: iII111i
    if 31 - 31: OOooOOo + O0
    if 87 - 87: ooOoO0o
    if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
  if ( len ( kv_pairs [ ii1 ] ) == 4 and kv_pairs [ ii1 ] [ 3 ] ) :
   if ( ii1 == "instance-id" ) :
    OoO = ( oo00oO0O0 . find ( "-" ) != - 1 )
    Iii11iI11i1I = ( oo00oO0O0 == "*" )
    if 64 - 64: i11iIiiIii
    if ( OoO or Iii11iI11i1I ) :
     oo0 , ii = lisp_validate_range ( oo00oO0O0 )
     if ( ii == - 1 ) :
      iI11 += lisp_write_error ( oOO , "invalid range" )
      o0O0O0ooo0oOO = True
      continue
      if 38 - 38: IiII / I1IiiI - IiII . I11i
    else :
     oo0 = oo00oO0O0
     ii = 32
     if 69 - 69: OoooooooOO + I1ii11iIi11i
     if 97 - 97: OOooOOo - OoO0O00 / Ii1I . i11iIiiIii % oO0o * oO0o
    oo00oO0O0 = str ( oo0 ) + "-" + str ( ii )
    if 1 - 1: I1IiiI % ooOoO0o
    if 65 - 65: I1IiiI + OoOoOO00 / OOooOOo
    if 83 - 83: o0oOOo0O0Ooo . iII111i - Oo0Ooo
    if 65 - 65: iIii1I11I1II1 / ooOoO0o . IiII - II111iiii
    if 72 - 72: iIii1I11I1II1 / IiII % iII111i % OOooOOo - I11i % OOooOOo
    if 100 - 100: Oo0Ooo + i11iIiiIii
    if 71 - 71: I11i / o0oOOo0O0Ooo / I1Ii111 % OOooOOo
    if 51 - 51: IiII * O0 / II111iiii . Ii1I % OOooOOo / I1IiiI
  if ( kv_pairs [ ii1 ] [ 0 ] and IIIII . has_key ( ii1 ) ) :
   if ( IIIII [ ii1 ] [ O0OO0O ] != "" ) : O0OO0O += 1
   IIIII [ ii1 ] [ O0OO0O ] = oo00oO0O0
  else :
   IIIII [ ii1 ] = oo00oO0O0
   if 9 - 9: I1IiiI % I1IiiI % II111iiii
   if 30 - 30: IiII + I1Ii111 - IiII . IiII - II111iiii + O0
   if 86 - 86: i1IIi
   if 41 - 41: OoOoOO00 * I11i / OoOoOO00 % oO0o
   if 18 - 18: II111iiii . OoooooooOO % OoOoOO00 % Ii1I
   if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
  if ( len ( kv_pairs [ ii1 ] ) > 1 ) :
   ii1Ii1IiIIi = kv_pairs [ ii1 ] [ 1 ]
   if ( type ( ii1Ii1IiIIi ) == int ) :
    if ( oo00oO0O0 < kv_pairs [ ii1 ] [ 1 ] and oo00oO0O0 > kv_pairs [ ii1 ] [ 2 ] ) :
     iI11 += lisp_write_error ( oOO , "invalid range value" )
     o0O0O0ooo0oOO = True
     continue
     if 83 - 83: I11i / I1ii11iIi11i
   elif ( oo00oO0O0 not in kv_pairs [ ii1 ] [ 1 : : ] ) :
    iI11 += lisp_write_error ( oOO , "invalid value keyword" )
    o0O0O0ooo0oOO = True
    continue
    if 34 - 34: I1IiiI * Oo0Ooo * I1Ii111 / OoO0O00 * I11i / iIii1I11I1II1
    if 74 - 74: Oo0Ooo / i11iIiiIii - II111iiii * o0oOOo0O0Ooo
    if 5 - 5: OOooOOo - OOooOOo . Oo0Ooo + OoOoOO00 - OOooOOo . oO0o
    if 31 - 31: II111iiii - iIii1I11I1II1 - iIii1I11I1II1 % I11i
    if 12 - 12: iIii1I11I1II1
    if 20 - 20: o0oOOo0O0Ooo / i1IIi
  iI11 += lisp_write_line ( oOO )
  if 71 - 71: OoOoOO00 . i1IIi
  if 94 - 94: OOooOOo . I1Ii111
 if ( o0O0O0ooo0oOO == True ) :
  iI11 = iI11 . replace ( "%" , "#" )
 else :
  iI11 = iI11 . replace ( "#" , "" )
  iI11 = iI11 . replace ( "%" , "#" )
  if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 return ( [ o0O0O0ooo0oOO , iI11 , IIIII ] )
 if 47 - 47: OoooooooOO
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 if 82 - 82: ooOoO0o + II111iiii
 if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
 if 68 - 68: Oo0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
 if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
def lisp_process_command ( lisp_socket , opcode , clause , process , command_set ) :
 if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
 if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
 if 98 - 98: i1IIi
 if 65 - 65: OoOoOO00 / OoO0O00 % IiII
 if 45 - 45: OoOoOO00
 if 66 - 66: OoO0O00
 oOOI11I = clause . split ( " " )
 if 6 - 6: I1ii11iIi11i + oO0o
 if 48 - 48: iIii1I11I1II1 % i1IIi % iII111i + ooOoO0o
 if 30 - 30: i11iIiiIii % iIii1I11I1II1 . I11i % iIii1I11I1II1
 if 62 - 62: Oo0Ooo * OoOoOO00
 if ( clause . find ( "lisp debug" ) != - 1 ) :
  if ( clause . find ( "= yes" ) != - 1 ) :
   lisp . lisp_debug_logging = True
   OO0 = lisp . bold ( "Enable" , False )
   lisp . lprint ( "{} process debug logging" . format ( OO0 ) )
   if 84 - 84: OoOoOO00 % ooOoO0o - OoOoOO00 . o0oOOo0O0Ooo
  if ( clause . find ( "= no" ) != - 1 ) :
   III1iI1iII1I = lisp . bold ( "Disable" , False )
   lisp . lprint ( "{} process debug logging" . format ( III1iI1iII1I ) )
   lisp . lisp_debug_logging = False
   if 39 - 39: Ii1I * ooOoO0o / OoOoOO00 * OoO0O00 . I11i % II111iiii
  return
  if 71 - 71: I1Ii111 % i1IIi - II111iiii - OOooOOo + OOooOOo * ooOoO0o
  if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
  if 29 - 29: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / iII111i
  if 70 - 70: i11iIiiIii % iII111i
  if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
  if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
 O00oo0ooO = ( oOOI11I [ 0 ] == "show" )
 if ( O00oo0ooO ) :
  iiIii1ii = clause . split ( "%" )
  oOOI11I = iiIii1ii [ 0 ] . split ( " " )
  iIIIII1iiiiII = len ( iiIii1ii )
  if ( iIIIII1iiiiII == 2 ) :
   iiIii1ii = iiIii1ii [ 1 ]
  elif ( iIIIII1iiiiII == 3 ) :
   iiIii1ii = iiIii1ii [ 1 ] + "%" + iiIii1ii [ 2 ] + "%"
  else :
   iiIii1ii = ""
   if 54 - 54: i1IIi
   if 22 - 22: i1IIi + Ii1I
 oOOI11I = oOOI11I [ 0 ] + " " + oOOI11I [ 1 ]
 if 54 - 54: ooOoO0o % OOooOOo . I1Ii111 + oO0o - OOooOOo * I1IiiI
 for OOo00O in command_set :
  if ( OOo00O . has_key ( oOOI11I ) ) :
   o0 , I1IiIiiIiIII = OOo00O [ oOOI11I ]
   break
   if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
  if ( OOo00O == command_set [ - 1 ] ) :
   lisp . lprint ( "Invalid command found '{}'" . format ( oOOI11I ) )
   return
   if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
   if 34 - 34: O0
   if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
   if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
   if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
   if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
   if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
   if 91 - 91: oO0o + OoooooooOO - i1IIi
   if 84 - 84: Ii1I / IiII
   if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 o0O0O0ooo0oOO = False
 if ( len ( I1IiIiiIiIII ) != 0 ) :
  o0O0O0ooo0oOO , iI11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
  if ( o0O0O0ooo0oOO == False ) : o0 ( I1IiIiiIiIII )
 else :
  if ( O00oo0ooO ) : I1IiIiiIiIII = iiIii1ii
  iI11 = o0 ( I1IiIiiIiIII )
  if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
  if 37 - 37: i11iIiiIii + i1IIi
 I1i11II = lisp . lisp_command_ipc ( iI11 , process )
 lisp . lisp_ipc ( I1i11II , lisp_socket , "lisp-core" )
 return
 if 31 - 31: oO0o / IiII * o0oOOo0O0Ooo . II111iiii
 if 89 - 89: O0
 if 2 - 2: I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i * o0oOOo0O0Ooo
 if 100 - 100: Oo0Ooo % Ii1I / I11i
 if 30 - 30: Oo0Ooo - OOooOOo - iII111i
 if 81 - 81: o0oOOo0O0Ooo . OoooooooOO + OOooOOo * ooOoO0o
 if 74 - 74: i1IIi + O0 + Oo0Ooo
def lisp_is_user_superuser ( username ) :
 if ( username == None ) : username = lisp_get_user ( )
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 Ooo = commands . getoutput ( "egrep -A 4 user-account ./lisp.config" )
 if 65 - 65: Oo0Ooo / I11i
 i1IIii1iiIi = "username = {}" . format ( username )
 O0OO0O = Ooo . find ( i1IIii1iiIi )
 o0o0O0O00oOOo = Ooo [ O0OO0O : : ] . find ( "}" )
 if ( O0OO0O == - 1 or o0o0O0O00oOOo == - 1 ) : return ( False )
 if 63 - 63: I1ii11iIi11i
 i1II = Ooo [ O0OO0O : O0OO0O + o0o0O0O00oOOo ] . find ( "super-user = yes" )
 return ( i1II != - 1 )
 if 2 - 2: II111iiii - OoO0O00 . IiII * iII111i / oO0o
 if 80 - 80: OOooOOo / I11i / OoOoOO00 + i1IIi - Oo0Ooo
 if 11 - 11: o0oOOo0O0Ooo * OoO0O00
 if 15 - 15: OoOoOO00
 if 62 - 62: Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
def lisp_find_user_account ( username , password ) :
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
 Ooo = commands . getoutput ( "egrep -A 4 user-account ./lisp.config" )
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 O0OO0O = Ooo . find ( "username = {}\n" . format ( username ) )
 if ( O0OO0O == - 1 ) : return ( False )
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 Ooo = Ooo [ O0OO0O : : ]
 Ooo = Ooo . replace ( "\t" , "" )
 Ooo = Ooo . replace ( " " , "" )
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 O0OO0O = Ooo . find ( "password=" )
 if ( O0OO0O == - 1 ) : return ( False )
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 if 46 - 46: i11iIiiIii - O0 . oO0o
 Ooo = Ooo [ O0OO0O : : ]
 o0o0O0O00oOOo = Ooo . find ( "\n" )
 if ( o0o0O0O00oOOo == - 1 ) : return ( False )
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 oo0O0oo = Ooo [ : o0o0O0O00oOOo ] . split ( "=" )
 if ( oo0O0oo [ 1 ] == "" ) :
  IIi1 = lisp_hash_password ( password )
  if ( oo0O0oo [ 2 ] != IIi1 ) : return ( False )
 else :
  if ( oo0O0oo [ 1 ] != password ) : return ( False )
  if 14 - 14: O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
  if 96 - 96: iII111i
  if 18 - 18: iII111i * I11i - Ii1I
  if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 return ( True )
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
def lisp_validate_user ( ) :
 IIo0OoO00 = bottle . request . forms . get ( 'username' )
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if ( IIo0OoO00 == None ) :
  OOooo00 = bottle . request . get_cookie ( "lisp-login" )
  if ( OOooo00 ) : return ( True )
  if 35 - 35: I1Ii111 . OoOoOO00 * i11iIiiIii
  if 44 - 44: i11iIiiIii / Oo0Ooo
 Ii1IIi = bottle . request . forms . get ( 'password' )
 if ( IIo0OoO00 == None or Ii1IIi == None ) : return ( False )
 if 43 - 43: I1Ii111 % iII111i
 if ( lisp_find_user_account ( IIo0OoO00 , Ii1IIi ) == False ) : return ( False )
 if 69 - 69: iII111i % OoO0O00
 if 86 - 86: oO0o / oO0o
 if 28 - 28: i11iIiiIii / o0oOOo0O0Ooo . iIii1I11I1II1 / II111iiii
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
 Ii1iIi111i1i1 = None if os . getenv ( "LISP_NO_USER_TIMEOUT" ) == "" else LISP_USER_TIMEOUT
 if 45 - 45: OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * I1IiiI % I1IiiI
 bottle . response . set_cookie ( "lisp-login" , IIo0OoO00 , max_age = Ii1iIi111i1i1 )
 return ( True )
 if 63 - 63: I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
def lisp_get_user ( ) :
 IIo0OoO00 = bottle . request . forms . get ( 'username' )
 if ( IIo0OoO00 ) : return ( IIo0OoO00 )
 if 36 - 36: IiII
 return ( bottle . request . get_cookie ( "lisp-login" ) )
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if 7 - 7: II111iiii
 if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
 if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
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
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
 if 94 - 94: I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
def lisp_is_any_xtr_logging_on ( log_type ) :
 oOOI11I = "egrep '" + log_type + " = '" + " ./lisp.config"
 oOOI11I = commands . getoutput ( oOOI11I )
 if ( oOOI11I == "" ) : return ( False )
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 oOOI11I = oOOI11I . split ( "\n" )
 for Oo0Ooo0O0 in oOOI11I :
  IiIIi1IiiIiI = Oo0Ooo0O0 . find ( "    {} = " . format ( log_type ) ) != - 1
  if ( Oo0Ooo0O0 [ 0 ] == " " and IiIIi1IiiIiI ) :
   oOOI11I = Oo0Ooo0O0 . replace ( " " , "" )
   oOOI11I = oOOI11I . split ( "=" )
   if ( oOOI11I [ 1 ] == "yes" ) : return ( True )
   if 23 - 23: I11i
   if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 return ( False )
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
def lisp_landing_page ( ) :
 oo0O = lisp . green ( "yes" , True )
 III1i1IiI1i = lisp . red ( "no" , True )
 if 32 - 32: OoooooooOO - OoOoOO00 - i11iIiiIii * o0oOOo0O0Ooo / Oo0Ooo + OoooooooOO
 ii1I1I111 = oo0O if lisp . lisp_is_running ( "lisp-itr" ) else III1i1IiI1i
 Ii1Ii = oo0O if lisp . lisp_is_running ( "lisp-etr" ) else III1i1IiI1i
 IIiii11iI = oo0O if lisp . lisp_is_running ( "lisp-rtr" ) else III1i1IiI1i
 i11i1Ii1 = oo0O if lisp . lisp_is_running ( "lisp-mr" ) else III1i1IiI1i
 o0oO0oo0000OO = oo0O if lisp . lisp_is_running ( "lisp-ms" ) else III1i1IiI1i
 I1i1ii1IiIii = oo0O if lisp . lisp_is_running ( "lisp-ddt" ) else III1i1IiI1i
 if 69 - 69: OoOoOO00 % oO0o - I11i
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
    ''' . format ( ii1I1I111 , IIiii11iI , Ii1Ii , i11i1Ii1 , I1i1ii1IiIii , o0oO0oo0000OO )
 if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
 i1iiI11I += '''
        <center>
        <style type="text/css">
        form { display:inline }
        </style>

        <a href="/lisp/show/status">
        <button style="background-color:transparent;border-radius:10px;
        type="button">system status</button></a>
    '''
 if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
 OO00OO0o0 = lisp_get_clause_for_api ( "lisp debug" ) [ 0 ]
 OO00OO0o0 = OO00OO0o0 [ "lisp debug" ] if OO00OO0o0 . has_key ( "lisp debug" ) else None
 oOOOooOo0O = "lisp xtr-parameters"
 III1i111i = lisp_get_clause_for_api ( oOOOooOo0O ) [ 0 ]
 iI1i = False
 if ( III1i111i . has_key ( oOOOooOo0O ) ) :
  i111iiIIII = { "data-plane-logging" : "yes" }
  OOO00OOo0o0Oo = { "flow-logging" : "yes" }
  iI1i = ( i111iiIIII in III1i111i [ oOOOooOo0O ] or OOO00OOo0o0Oo in III1i111i [ oOOOooOo0O ] )
  if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
  if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 ooOoOO = { }
 for Oo in OO00OO0o0 : ooOoOO [ Oo . keys ( ) [ 0 ] ] = Oo . values ( ) [ 0 ]
 OO00OO0o0 = ooOoOO
 OO00OO0o0 [ "ddt" ] = OO00OO0o0 [ "ddt-node" ]
 OO00OO0o0 [ "mr" ] = OO00OO0o0 [ "map-resolver" ]
 OO00OO0o0 [ "ms" ] = OO00OO0o0 [ "map-server" ]
 if 66 - 66: IiII
 if 67 - 67: I1Ii111 / OoO0O00 . OOooOOo / OOooOOo - Ii1I - OoooooooOO
 if 46 - 46: O0 * Oo0Ooo / O0 + OoO0O00
 if 56 - 56: OOooOOo . II111iiii
 III11I1 = commands . getoutput ( "wc -l logs/lisp-core.log" )
 III11I1 = III11I1 . replace ( " " , "" )
 III11I1 = III11I1 . split ( "logs" ) [ 0 ]
 OOo0O0O000 = "on" if OO00OO0o0 [ "core" ] == "yes" else "off"
 i1iiI11I += '''
        <form>
        <select size="1" style="width: 110px"
                onchange="parent.window.location=this.value">
        <option value="">show logging:</option>
        <option value="/lisp/show/log/lisp-core/100">[{}] core log [{}]
        </option>''' . format ( OOo0O0O000 , III11I1 )
 if 29 - 29: o0oOOo0O0Ooo / Oo0Ooo * I1ii11iIi11i . o0oOOo0O0Ooo
 if ( os . path . exists ( "./logs/lisp-itr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-itr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  OOo0O0O000 = "on" if OO00OO0o0 [ "itr" ] == "yes" else "off"
  i1iiI11I += '''
            <option value="/lisp/show/log/lisp-itr/100">[{}] ITR log [{}]
            </option>''' . format ( OOo0O0O000 , III11I1 )
  if 64 - 64: oO0o / ooOoO0o % i11iIiiIii
 if ( os . path . exists ( "./logs/lisp-rtr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-rtr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  OOo0O0O000 = "on" if OO00OO0o0 [ "rtr" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-rtr/100">[{}] RTR 
           log [{}]</option>''' . format ( OOo0O0O000 , III11I1 )
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if ( os . path . exists ( "./logs/lisp-etr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-etr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  OOo0O0O000 = "on" if OO00OO0o0 [ "etr" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-etr/100">[{}] ETR 
            log [{}]</option>''' . format ( OOo0O0O000 , III11I1 )
  if 64 - 64: i1IIi
 if ( os . path . exists ( "./logs/lisp-xtr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-xtr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  OOo0O0O000 = "on" if OO00OO0o0 [ "itr" ] == "yes" or OO00OO0o0 [ "etr" ] == "yes" or OO00OO0o0 [ "rtr" ] == "yes" else "off"
  if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
  i1iiI11I += '''<option value="/lisp/show/log/lisp-xtr/100">[{}] XTR 
           log [{}]</option>''' . format ( OOo0O0O000 , III11I1 )
  if 18 - 18: OOooOOo + I1Ii111
 if ( os . path . exists ( "./logs/lisp-mr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-mr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  OOo0O0O000 = "on" if OO00OO0o0 [ "mr" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-mr/100">[{}] MR 
            log [{}] </option>''' . format ( OOo0O0O000 , III11I1 )
  if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if ( os . path . exists ( "./logs/lisp-ddt.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-ddt.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  OOo0O0O000 = "on" if OO00OO0o0 [ "ddt" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-ddt/100">[{}] DDT 
            log [{}]</option>''' . format ( OOo0O0O000 , III11I1 )
  if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if ( os . path . exists ( "./logs/lisp-ms.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-ms.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  OOo0O0O000 = "on" if OO00OO0o0 [ "ms" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-ms/100">[{}] MS 
            log [{}]</option>''' . format ( OOo0O0O000 , III11I1 )
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 i1iii11 = lisp_is_any_xtr_logging_on ( "flow-logging" )
 if ( os . path . exists ( "./logs/lisp-flow.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-flow.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  OOo0O0O000 = "on" if i1iii11 else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-flow/100">[{}] flow 
            log [{}]</option>''' . format ( OOo0O0O000 , III11I1 )
  if 92 - 92: OoOoOO00 . OoooooooOO - I1Ii111
 i1iiI11I += "</select></form>"
 if 74 - 74: iIii1I11I1II1 % iII111i * OOooOOo * iIii1I11I1II1
 if 73 - 73: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
 if 60 - 60: OoOoOO00
 if 5 - 5: I1IiiI - I1IiiI - I1IiiI * OoooooooOO
 i1II = lisp_is_user_superuser ( None )
 if ( i1II ) :
  i1iiI11I += '''
            <form>
            <select size="1" style="width: 120px"
                    onchange="parent.window.location=this.value">
            <option value="">manage logging:</option>
        '''
  if 28 - 28: iIii1I11I1II1 + iIii1I11I1II1
  if 28 - 28: oO0o
  if 52 - 52: I1IiiI + iIii1I11I1II1
  if 71 - 71: O0 / oO0o
  if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
  if ( "yes" in OO00OO0o0 . values ( ) or iI1i ) :
   i1iiI11I += '''<option value="/lisp/debug/{}%{}">disable all logging
                </option>''' . format ( "disable" , "all" )
   if 43 - 43: I1ii11iIi11i - iII111i
   if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
  i1II11Iii1I = False
  oO00OoOOOo = False
  for Oo0 in OO00OO0o0 :
   if ( lisp . lisp_is_running ( "lisp-" + Oo0 ) == False ) : continue
   if 80 - 80: Ii1I - o0oOOo0O0Ooo
   if ( Oo0 in [ "itr" , "etr" , "rtr" ] ) :
    i1II11Iii1I = True
    oO00OoOOOo = True
    if 41 - 41: o0oOOo0O0Ooo - Oo0Ooo * I1IiiI
    if 82 - 82: OoO0O00 % o0oOOo0O0Ooo % OOooOOo / O0
   OOOO0o0 = OO00OO0o0 [ Oo0 ]
   i1IIIi111Ii = Oo0
   if ( i1IIIi111Ii == "mr" ) : i1IIIi111Ii = "map-resolver"
   if ( i1IIIi111Ii == "ms" ) : i1IIIi111Ii = "map-server"
   if ( i1IIIi111Ii == "ddt" ) : i1IIIi111Ii = "ddt-node"
   if 15 - 15: o0oOOo0O0Ooo
   i1iiI11I += '''<option value="/lisp/debug/{}%{}">{} {} logging
                </option>''' . format ( i1IIIi111Ii , "yes" if OOOO0o0 == "no" else "no" ,
 "enable" if OOOO0o0 == "no" else "disable" ,
 Oo0 . upper ( ) if Oo0 != "core" else "core" )
   if 39 - 39: OOooOOo / I1ii11iIi11i / I1IiiI * I1Ii111
  if ( i1II11Iii1I ) :
   Iii1Ii = lisp_is_any_xtr_logging_on ( "data-plane-logging" )
   i1iiI11I += '''<option value="/lisp/debug/data-plane-logging%{}">{} 
                data-plane logging </option>''' . format ( "yes" if Iii1Ii == False else "no" ,
   # o0oOOo0O0Ooo + O0
 "enable" if Iii1Ii == False else "disable" )
   if 71 - 71: IiII + i1IIi * Oo0Ooo % Oo0Ooo / Oo0Ooo
  if ( oO00OoOOOo ) :
   Iii1Ii = i1iii11
   i1iiI11I += '''<option value="/lisp/debug/flow-logging%{}">{} 
                flow logging </option>''' . format (
 "yes" if Iii1Ii == False else "no" ,
 "enable" if Iii1Ii == False else "disable" )
   if 55 - 55: OoooooooOO + I1Ii111 + OoooooooOO * ooOoO0o
  i1iiI11I += "</select></form>"
  if 68 - 68: O0
  if 2 - 2: OoO0O00 + O0 * OoO0O00 - Ii1I + oO0o
 i1iiI11I += "<br><br>"
 if 43 - 43: I1ii11iIi11i - OoOoOO00
 if 36 - 36: I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 IiI1iiI1III1I = lisp . lisp_button ( "{}:<br>show map-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-itr" ) ) :
  IiI1iiI1III1I = '<a href="/lisp/show/itr/map-cache">' + IiI1iiI1III1I + '</a>'
  IiI1iiI1III1I = IiI1iiI1III1I . format ( lisp . green ( "ITR" , True ) )
 else :
  IiI1iiI1III1I = IiI1iiI1III1I . format ( lisp . red ( "ITR" , True ) )
  IiI1iiI1III1I = lisp . lisp_span ( IiI1iiI1III1I , "ITR not running" )
  if 97 - 97: i11iIiiIii / I11i * I1ii11iIi11i % OoOoOO00 . OoooooooOO
  if 6 - 6: oO0o % O0 / IiII - iIii1I11I1II1 / IiII / i11iIiiIii
 iiI1i1I11 = lisp . lisp_button ( "{}:<br>show map-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-rtr" ) ) :
  iiI1i1I11 = '<a href="/lisp/show/rtr/map-cache">' + iiI1i1I11 + '</a>'
  iiI1i1I11 = iiI1i1I11 . format ( lisp . green ( "RTR" , True ) )
 else :
  iiI1i1I11 = iiI1i1I11 . format ( lisp . red ( "RTR" , True ) )
  iiI1i1I11 = lisp . lisp_span ( iiI1i1I11 , "RTR not running" )
  if 35 - 35: iIii1I11I1II1
  if 94 - 94: OoOoOO00
 OOOo = lisp . lisp_button ( "{}:<br>show referral-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-mr" ) ) :
  OOOo = '<a href="/lisp/show/referral">' + OOOo + '</a>'
  OOOo = OOOo . format ( lisp . green ( "MR" , True ) )
 else :
  OOOo = OOOo . format ( lisp . red ( "MR" , True ) )
  OOOo = lisp . lisp_span ( OOOo , "MR not running" )
  if 74 - 74: Ii1I - OoooooooOO . Oo0Ooo
  if 31 - 31: o0oOOo0O0Ooo % I11i + iIii1I11I1II1 + i11iIiiIii * I1Ii111
 I1i1I1I11IiiI = lisp . lisp_button ( "{}:<br>show delegations" , None )
 if ( lisp . lisp_is_running ( "lisp-ddt" ) ) :
  I1i1I1I11IiiI = '<a href="/lisp/show/delegations">' + I1i1I1I11IiiI + '</a>'
  I1i1I1I11IiiI = I1i1I1I11IiiI . format ( lisp . green ( "DDT" , True ) )
 else :
  I1i1I1I11IiiI = I1i1I1I11IiiI . format ( lisp . red ( "DDT" , True ) )
  I1i1I1I11IiiI = lisp . lisp_span ( I1i1I1I11IiiI , "DDT not running" )
  if 40 - 40: I11i % OoooooooOO - OOooOOo + o0oOOo0O0Ooo / OOooOOo
  if 84 - 84: O0
 iiii = lisp . lisp_button ( "{}:<br>show site-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-ms" ) ) :
  iiii = '<a href="/lisp/show/site">' + iiii + '</a>'
  iiii = iiii . format ( lisp . green ( "MS" , True ) )
 else :
  iiii = iiii . format ( lisp . red ( "MS" , True ) )
  iiii = lisp . lisp_span ( iiii , "MS not running" )
  if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
  if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
 iIii1iII1Ii = lisp . lisp_button ( "{}:<br>show database-mappings" , None )
 if ( lisp . lisp_is_running ( "lisp-etr" ) ) :
  iIii1iII1Ii = '<a href="/lisp/show/database">' + iIii1iII1Ii + '</a>'
  iIii1iII1Ii = iIii1iII1Ii . format ( lisp . green ( "ETR" , True ) )
 else :
  iIii1iII1Ii = iIii1iII1Ii . format ( lisp . red ( "ETR" , True ) )
  iIii1iII1Ii = lisp . lisp_span ( iIii1iII1Ii , "ETR not running" )
  if 50 - 50: Ii1I
  if 22 - 22: I11i * O0 . II111iiii - OoO0O00
 o0Oo00OO0 = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 i11Ii11II1I1 = lisp . lisp_geo_help_hover ( '<input type="text" name="geo-point" size="30" required />' )
 if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
 oO = lisp . lisp_geo_help_hover ( '<input type="text" name="geo-prefix" size="30" required />' )
 if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
 Ii = lisp . lisp_button ( "API Documentation" , "/lisp/show/api-doc" )
 o00 = lisp . lisp_button ( "Command Documentation" , "/lisp/show/command-doc" )
 IiI1iiII1i1i = lisp . lisp_button ( "IETF LISP WG Drafts" ,
 "http://datatracker.ietf.org/wg/lisp/" )
 i1IiI = lisp . lisp_button ( "ddt-root.org" , "http://ddt-root.net" )
 o0o0O00 = lisp . lisp_button ( "LISP Facebook Group" ,
 "https://www.facebook.com/groups/407716795982512" )
 oOo000OOooO0O = lisp . lisp_button ( "LISP LinkedIn Group" ,
 "http://www.linkedin.com/groups/LISP-3776183" )
 if 44 - 44: O0 . oO0o * i11iIiiIii % i11iIiiIii + O0 / OOooOOo
 o00oOOO0Ooo = lisp . lisp_space ( 2 )
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

    ''' . format ( o00oOOO0Ooo , IiI1iiI1III1I , o00oOOO0Ooo , iiI1i1I11 , o00oOOO0Ooo , iIii1iII1Ii , o00oOOO0Ooo , o00oOOO0Ooo , OOOo , o00oOOO0Ooo , I1i1I1I11IiiI , o00oOOO0Ooo , iiii , o00oOOO0Ooo ,
 o0Oo00OO0 , o0Oo00OO0 , i11Ii11II1I1 , oO , Ii , o00 , IiI1iiII1i1i , i1IiI , o0o0O00 , oOo000OOooO0O )
 if 50 - 50: Ii1I - i11iIiiIii + iIii1I11I1II1 / O0 - Ii1I + o0oOOo0O0Ooo
 return ( lisp_show_wrapper ( i1iiI11I ) )
 if 22 - 22: II111iiii - Ii1I / ooOoO0o % OoooooooOO + OOooOOo
 if 5 - 5: OoO0O00 / iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
def lisp_drain_socket ( lisp_socket , process ) :
 lisp . lprint ( "Draining socket looking for {}" . format ( process ) )
 if 46 - 46: IiII + oO0o
 Oo00o0O0O = None
 while ( True ) :
  try :
   select . select ( [ lisp_socket ] , [ ] , [ ] )
  except :
   return ( Oo00o0O0O )
   if 84 - 84: I11i % i1IIi
   if 33 - 33: I1ii11iIi11i * I1ii11iIi11i . ooOoO0o . i11iIiiIii
  lisp . lisp_ipc_lock . acquire ( )
  IIIIiIi11iiIi , i11iI11I1I , Ii1iiIi1I11i , i1iiI11I = lisp . lisp_receive ( lisp_socket , True )
  lisp . lisp_ipc_lock . release ( )
  if 89 - 89: I1Ii111 . IiII % Oo0Ooo . Oo0Ooo - OoooooooOO
  if ( i11iI11I1I != process ) :
   lisp . lprint ( "Discarding IPC message from {}" . format ( i11iI11I1I ) )
  elif ( Oo00o0O0O == None ) :
   Oo00o0O0O = i1iiI11I
   if 56 - 56: I11i
   if 21 - 21: iIii1I11I1II1 / I1Ii111 + ooOoO0o - I11i / Oo0Ooo / II111iiii
 return
 if 69 - 69: I1IiiI . OoOoOO00
 if 53 - 53: I11i
 if 68 - 68: oO0o / I1Ii111 % I1Ii111 % O0
 if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
def lisp_process_show_command ( lisp_socket , command ) :
 if 77 - 77: Oo0Ooo
 if 46 - 46: I1Ii111
 if 72 - 72: iII111i * OOooOOo
 if 67 - 67: i1IIi
 iii = command . split ( "%" )
 iii = iii [ 0 ]
 if 57 - 57: I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if 50 - 50: OoOoOO00
 if 33 - 33: I11i
 Oo0 = lisp_commands [ iii ]
 Oo0 = Oo0 [ 0 ]
 if 98 - 98: OoOoOO00 % II111iiii
 if ( lisp . lisp_is_running ( Oo0 ) == False ) :
  i1iiI11I = ( "<i>Process '{}' is not running, command cannot be " + "executed</i><br>" ) . format ( Oo0 )
  if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
  return ( lisp_show_wrapper ( i1iiI11I ) )
  if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
  if 68 - 68: o0oOOo0O0Ooo
 command = lisp . lisp_command_ipc ( command , "lisp-core" )
 if 20 - 20: I1Ii111 - I1Ii111
 if 37 - 37: IiII
 if 37 - 37: Oo0Ooo / IiII * O0
 if 73 - 73: iII111i * iII111i / ooOoO0o
 lisp . lisp_ipc_lock . acquire ( )
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 lisp . lisp_ipc ( command , lisp_socket , Oo0 )
 lisp . lprint ( "Waiting for response to show command '{}'" . format ( command ) )
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 IIIIiIi11iiIi , i11iI11I1I , Ii1iiIi1I11i , i1iiI11I = lisp . lisp_receive ( lisp_socket , True )
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 lisp . lisp_ipc_lock . release ( )
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if ( i11iI11I1I == "" ) :
  lisp . lprint ( "Command '{}' timed out to {}" . format ( command , Oo0 ) )
 elif ( i11iI11I1I != Oo0 ) :
  lisp . lprint ( "Received response from {} but expecting from {}" . format ( i11iI11I1I , Oo0 ) )
  if 69 - 69: I1ii11iIi11i
  i1iiI11I = lisp_drain_socket ( lisp_socket , Oo0 )
  if ( i1iiI11I == None ) : i1iiI11I = "<i>Fatal error, retry later</i><br>"
  if 83 - 83: o0oOOo0O0Ooo
 return ( lisp_show_wrapper ( i1iiI11I ) )
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if 48 - 48: iII111i + IiII
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 if 14 - 14: OOooOOo
 if 79 - 79: Ii1I
 if 76 - 76: iIii1I11I1II1
def lisp_start_stop_process ( process , startstop ) :
 if ( startstop and lisp . lisp_is_running ( process ) ) : return
 if ( startstop == False and lisp . lisp_is_running ( process ) == False ) : return
 if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
 ooOo000OoO0o = process + ".pyo"
 ooooo0O0 = "./logs/" + process + ".log"
 if 10 - 10: I11i - Oo0Ooo
 if ( lisp . lisp_is_ubuntu ( ) or lisp . lisp_is_raspbian ( ) or lisp . lisp_is_debian ( ) or lisp . lisp_is_debian_kali ( ) ) :
  if 59 - 59: OoooooooOO * Oo0Ooo + i1IIi
  iiii11IiiiiIi = "python -O " + ooOo000OoO0o + " 2>&1 > " + ooooo0O0 + " &"
 else :
  iiii11IiiiiIi = "python -O " + ooOo000OoO0o + " >& " + ooooo0O0 + " &"
  if 98 - 98: II111iiii - OoooooooOO * O0
  if 85 - 85: OoooooooOO % OoOoOO00 * iIii1I11I1II1
 IiI = commands . getoutput ( "date" )
 if ( startstop and os . path . exists ( ooOo000OoO0o ) ) :
  lisp . lprint ( "Start process '{}' on {}" . format ( process , IiI ) )
  os . system ( iiii11IiiiiIi )
  time . sleep ( 1 )
  return
  if 60 - 60: I1Ii111
  if 98 - 98: ooOoO0o
 if ( startstop == False and os . path . exists ( ooOo000OoO0o ) ) :
  lisp . lprint ( "Stop process '{}' on {}" . format ( process , IiI ) )
  Ii11i1Ii1IIII = commands . getoutput ( "pgrep -f " + ooOo000OoO0o )
  Ii11i1Ii1IIII = Ii11i1Ii1IIII . split ( "\n" ) [ 0 ]
  os . system ( "kill " + Ii11i1Ii1IIII )
  os . system ( "rm " + process )
  return
  if 41 - 41: Ii1I / II111iiii . OoOoOO00
 return
 if 63 - 63: O0
 if 6 - 6: OOooOOo
 if 98 - 98: OoooooooOO % O0 - O0
 if 76 - 76: i1IIi % OoOoOO00 - I1IiiI / o0oOOo0O0Ooo * ooOoO0o
 if 4 - 4: Oo0Ooo * Oo0Ooo / OoOoOO00
 if 4 - 4: I1IiiI * OoOoOO00 % I11i . OoOoOO00
 if 11 - 11: OOooOOo - OoOoOO00 - o0oOOo0O0Ooo * OoOoOO00 + ooOoO0o
def lisp_enable_command ( clause ) :
 if 62 - 62: I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if ( os . path . exists ( "lisp.py" ) and os . path . exists ( "lisp.pyo" ) == False ) :
  lisp . lprint ( "In manual mode, ignoring 'lisp enable' command" )
  return ( clause )
  if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
  if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 oOOI11I = clause . split ( " " )
 oOOI11I = oOOI11I [ 0 ] + " " + oOOI11I [ 1 ]
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 I1IiIiiIiIII = lisp_core_commands [ "lisp enable" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if 81 - 81: IiII / OoOoOO00 * IiII . O0
 o0O0O0ooo0oOO , iI11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
 if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
 if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
 if ( o0O0O0ooo0oOO == True ) : return ( iI11 )
 if 61 - 61: I1Ii111 - Ii1I % I1ii11iIi11i / ooOoO0o / iII111i + iIii1I11I1II1
 O0O0oo = { "itr" : "lisp-itr" , "etr" : "lisp-etr" , "rtr" : "lisp-rtr" ,
 "map-resolver" : "lisp-mr" , "map-server" : "lisp-ms" ,
 "ddt-node" : "lisp-ddt" }
 if 83 - 83: IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 for O0000oO0o00 in O0O0oo . keys ( ) :
  oo000o = True if I1IiIiiIiIII [ O0000oO0o00 ] == "yes" else False
  lisp_start_stop_process ( O0O0oo [ O0000oO0o00 ] , oo000o )
  if 95 - 95: oO0o - ooOoO0o * I11i / OoO0O00 / II111iiii + O0
 return ( iI11 )
 if 37 - 37: I11i . I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
def lisp_debug_command ( lisp_socket , clause , single_process ) :
 oOOI11I = clause . split ( " " )
 oOOI11I = oOOI11I [ 0 ] + " " + oOOI11I [ 1 ]
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 I1IiIiiIiIII = lisp_core_commands [ "lisp debug" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 o0O0O0ooo0oOO , iI11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 if ( o0O0O0ooo0oOO == True ) : return ( iI11 )
 if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
 O0O0oo = { "itr" : "lisp-itr" , "etr" : "lisp-etr" , "rtr" : "lisp-rtr" ,
 "map-resolver" : "lisp-mr" , "map-server" : "lisp-ms" ,
 "ddt-node" : "lisp-ddt" , "core" : "" }
 if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
 for oo00o0 in I1IiIiiIiIII :
  Oo0 = O0O0oo [ oo00o0 ]
  if ( single_process and single_process != Oo0 ) : continue
  if 17 - 17: Ii1I / iIii1I11I1II1 - OoO0O00 + I1IiiI % OOooOOo
  OOOO0o0 = I1IiIiiIiIII [ oo00o0 ]
  oOOI11I = ( "lisp debug {\n" + "    {} = {}\n" . format ( oo00o0 , OOOO0o0 ) + "}\n" )
  if 14 - 14: o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
  if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
  if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
  if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
  if 26 - 26: o0oOOo0O0Ooo
  if ( oo00o0 == "core" ) :
   lisp_process_command ( None , None , oOOI11I , None , [ None ] )
   continue
   if 12 - 12: OoooooooOO / O0 + II111iiii * I1ii11iIi11i
   if 46 - 46: II111iiii - IiII * OoooooooOO / oO0o % IiII
  oOOI11I = lisp . lisp_command_ipc ( oOOI11I , "lisp-core" )
  lisp . lisp_ipc ( oOOI11I , lisp_socket , Oo0 )
  if ( single_process ) : break
  if 11 - 11: iIii1I11I1II1 . OoOoOO00 / IiII % ooOoO0o
 return ( iI11 )
 if 61 - 61: ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
def lisp_replace_password_in_clause ( clause , keyword_string ) :
 O0OO0O = clause . find ( keyword_string )
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if ( O0OO0O == - 1 ) : return ( clause )
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 O0OO0O += len ( keyword_string )
 o0o0O0O00oOOo = clause [ O0OO0O : : ] . find ( "\n" )
 o0o0O0O00oOOo += O0OO0O
 Ii1IIi = clause [ O0OO0O : o0o0O0O00oOOo ] . replace ( " " , "" )
 if 74 - 74: oO0o
 if ( len ( Ii1IIi ) != 0 and Ii1IIi [ 0 ] == "=" ) : return ( clause )
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 Ii1IIi = Ii1IIi . replace ( " " , "" )
 Ii1IIi = Ii1IIi . replace ( "\t" , "" )
 Ii1IIi = lisp_hash_password ( Ii1IIi )
 clause = clause [ 0 : O0OO0O ] + " =" + Ii1IIi + clause [ o0o0O0O00oOOo : : ]
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 return ( clause )
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
def lisp_user_account_command ( clause ) :
 if 41 - 41: I1ii11iIi11i
 oOOI11I = clause . split ( " " )
 oOOI11I = oOOI11I [ 0 ] + " " + oOOI11I [ 1 ]
 if 5 - 5: Oo0Ooo
 I1IiIiiIiIII = lisp_core_commands [ "lisp user-account" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 o0O0O0ooo0oOO , iI11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 24 - 24: ooOoO0o - I11i * oO0o
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if ( o0O0O0ooo0oOO == False ) :
  iI11 = lisp_replace_password_in_clause ( iI11 , "password =" )
  if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 return ( iI11 )
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
def lisp_rtr_list_command ( clause ) :
 oOOI11I = clause . split ( " " )
 oOOI11I = oOOI11I [ 0 ] + " " + oOOI11I [ 1 ]
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 I1IiIiiIiIII = lisp_core_commands [ "lisp rtr-list" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 o0O0O0ooo0oOO , iI11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 36 - 36: OOooOOo % i11iIiiIii
 if ( o0O0O0ooo0oOO ) : return ( iI11 )
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 lisp . lisp_ms_rtr_list = [ ]
 if ( I1IiIiiIiIII . has_key ( "address" ) ) :
  for Ii1I1i in I1IiIiiIiIII [ "address" ] :
   II = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   II . store_address ( Ii1I1i )
   lisp . lisp_ms_rtr_list . append ( II )
   if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
   if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 return ( iI11 )
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
def lisp_process_command_lines ( lisp_socket , old , new , line ) :
 oOOI11I = line . split ( "{" )
 oOOI11I = oOOI11I [ 0 ]
 oOOI11I = oOOI11I [ 0 : - 1 ]
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 lisp . lprint ( "Process the '{}' command" . format ( oOOI11I ) )
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 if ( lisp_commands . has_key ( oOOI11I ) == False ) :
  line = "#>>> " + line . replace ( "\n" , " <<< invalid command\n" )
  new . write ( line )
  return
  if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
  if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
  if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
  if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
  if 12 - 12: I1ii11iIi11i / Ii1I
 ii11Ii11 = lisp_commands [ oOOI11I ]
 I1i1ii = False
 for Oo0 in ii11Ii11 :
  if ( Oo0 == "" ) :
   line = lisp_write_error ( line , "invalid command" )
   new . write ( line )
   return
   if 81 - 81: ooOoO0o * IiII * O0 * iIii1I11I1II1
   if 93 - 93: Oo0Ooo / I1ii11iIi11i + i1IIi * oO0o . OoooooooOO
  if ( I1i1ii == False ) :
   Oo000 = line
   III11I1 = 1
   for line in old :
    if ( lisp_begin_clause ( line ) ) : III11I1 += 1
    Oo000 += line
    if ( lisp_end_clause ( line ) ) :
     III11I1 -= 1
     if ( III11I1 == 0 ) : break
     if 97 - 97: O0 / OOooOOo + o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
     if 33 - 33: I11i % II111iiii + OoO0O00
     if 93 - 93: i1IIi . IiII / I1IiiI + IiII
     if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
     if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
     if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
     if 69 - 69: ooOoO0o % ooOoO0o
  if ( lisp . lisp_is_running ( Oo0 ) == False ) :
   if ( I1i1ii == False ) :
    for line in Oo000 : new . write ( line )
    I1i1ii = True
    if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
   lisp . lprint ( "Process '{}' is not running, do not send command" . format ( Oo0 ) )
   if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
   continue
   if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
   if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
   if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
   if 33 - 33: Ii1I
   if 93 - 93: ooOoO0o
   if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
  if ( Oo0 == "lisp-core" ) :
   if ( Oo000 . find ( "enable" ) != - 1 ) :
    iI11 = lisp_enable_command ( Oo000 )
    if 19 - 19: I1ii11iIi11i
   if ( Oo000 . find ( "debug" ) != - 1 ) :
    iI11 = lisp_debug_command ( lisp_socket , Oo000 , None )
    if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
   if ( Oo000 . find ( "user-account" ) != - 1 ) :
    iI11 = lisp_user_account_command ( Oo000 )
    if 66 - 66: O0
   if ( Oo000 . find ( "rtr-list" ) != - 1 ) :
    iI11 = lisp_rtr_list_command ( Oo000 )
    if 52 - 52: OoO0O00 * OoooooooOO
  else :
   Ii11iiI = lisp . lisp_command_ipc ( Oo000 , "lisp-core" )
   lisp . lisp_ipc ( Ii11iiI , lisp_socket , Oo0 )
   lisp . lprint ( "Waiting for response to config command '{}'" . format ( oOOI11I ) )
   if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
   if 28 - 28: iIii1I11I1II1
   IIIIiIi11iiIi , i11iI11I1I , Ii1iiIi1I11i , iI11 = lisp . lisp_receive ( lisp_socket ,
 True )
   if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
   if ( i11iI11I1I == "" ) :
    lisp . lprint ( "Command timed out to {}" . format ( Oo0 ) )
    iI11 = Oo000
   elif ( i11iI11I1I != Oo0 ) :
    lisp . lprint ( "Fatal IPC error to {}, source {}" . format ( Oo0 ,
 i11iI11I1I ) )
    if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
    if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
    if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
    if 46 - 46: OoOoOO00 - O0
    if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
    if 49 - 49: o0oOOo0O0Ooo
    if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
  if ( I1i1ii == False ) :
   for line in iI11 : new . write ( line )
   I1i1ii = True
   if 68 - 68: Oo0Ooo
   if 22 - 22: OOooOOo
 return
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
 if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 if 94 - 94: i1IIi
 if 36 - 36: I1IiiI + Oo0Ooo
 if 46 - 46: iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
def lisp_process_config_file ( lisp_socket , file_name , startup ) :
 lisp . lprint ( "Processing configuration file {}" . format ( file_name ) )
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
 if 65 - 65: ooOoO0o - i1IIi
 if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 if ( os . path . exists ( file_name ) == False ) :
  lisp . lprint ( "LISP configuration file '{}' does not exist" . format ( file_name ) )
  if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  return
  if 34 - 34: I1Ii111 - OOooOOo
  if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 ooO0 = file_name + ".diff"
 o0Iiii = file_name + ".bak"
 I1i1I = file_name + ".temp"
 i1111iI1 = "# lispers.net lisp.config file"
 if 76 - 76: OoooooooOO - II111iiii % OoOoOO00 + oO0o + iIii1I11I1II1 . OoOoOO00
 if 16 - 16: o0oOOo0O0Ooo . I11i
 if 50 - 50: ooOoO0o * OoOoOO00 + I1ii11iIi11i - i11iIiiIii + Oo0Ooo * I1ii11iIi11i
 if 20 - 20: I1Ii111 / o0oOOo0O0Ooo % OoOoOO00
 if 69 - 69: I1Ii111 - i1IIi % iII111i . OOooOOo - OOooOOo
 Oo00OoOo = 'egrep "{}" {}' . format ( i1111iI1 , file_name )
 IiIIi1IiiIiI = commands . getoutput ( Oo00OoOo )
 if ( IiIIi1IiiIiI == "" ) :
  lisp . lprint ( "*** lisp.config configuration file is corrupt ***" )
  return
  if 65 - 65: OOooOOo + II111iiii
  if 61 - 61: i11iIiiIii * oO0o % Oo0Ooo * I1Ii111 - OoooooooOO - OoO0O00
  if 83 - 83: ooOoO0o / OOooOOo
  if 39 - 39: IiII + I11i
  if 9 - 9: I1IiiI % I11i . Oo0Ooo * I1IiiI
  if 99 - 99: O0 . o0oOOo0O0Ooo % I11i - Oo0Ooo / I11i
 iI1iii1i1III1 = open ( file_name , "r" )
 iiIII1 = open ( I1i1I , "w" )
 for oOO in iI1iii1i1III1 :
  if ( oOO . find ( i1111iI1 ) == 0 ) :
   if ( startup ) :
    iiIII1 . write ( oOO )
   else :
    lisp_write_last_changed_date ( iiIII1 , oOO )
    if 11 - 11: Ii1I
   continue
   if 1 - 1: O0 * i11iIiiIii - ooOoO0o - Ii1I
   if 94 - 94: OoO0O00 + IiII + ooOoO0o
  if ( oOO . find ( "# Hostname:" ) == 0 ) :
   iiIII1 . write ( "# Hostname: " + lisp . lisp_hostname + "\n" )
   continue
   if 82 - 82: Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + IiII % iIii1I11I1II1
   if 61 - 61: OOooOOo / Oo0Ooo % OOooOOo - OoO0O00 + ooOoO0o / ooOoO0o
  if ( lisp_end_file ( oOO ) ) :
   iiIII1 . write ( oOO + "\n" )
   break
   if 82 - 82: Oo0Ooo
   if 5 - 5: OoO0O00 / OoO0O00 - O0 - I1Ii111 + I1Ii111
  if ( lisp_comment ( oOO ) ) :
   iiIII1 . write ( oOO )
   continue
   if 99 - 99: I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - iIii1I11I1II1 - Ii1I
   if 31 - 31: IiII - OoO0O00 / OOooOOo . i1IIi / Ii1I
  o0o000o = oOO . replace ( " " , "" )
  o0o000o = o0o000o . replace ( "\n" , "" )
  if ( o0o000o == "" ) : continue
  if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
  if 10 - 10: I1Ii111 * oO0o % Oo0Ooo - I11i % Oo0Ooo
  if 65 - 65: iII111i * iIii1I11I1II1 / O0 . I11i
  if 94 - 94: Oo0Ooo . ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo . iII111i
  lisp_process_command_lines ( lisp_socket , iI1iii1i1III1 , iiIII1 , oOO )
  if 98 - 98: OOooOOo + Ii1I
 iI1iii1i1III1 . close ( )
 iiIII1 . close ( )
 if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
 if 50 - 50: iIii1I11I1II1 - iII111i - I11i
 if 60 - 60: iIii1I11I1II1 * ooOoO0o
 if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
 if ( os . path . exists ( ooO0 ) == False ) :
  os . system ( "touch {}" . format ( ooO0 ) )
  if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
 if ( startup == False ) :
  os . system ( "diff {} {} > {}" . format ( o0Iiii , I1i1I , ooO0 ) )
  if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
  if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
  if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
  if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
  if 93 - 93: ooOoO0o
  if 18 - 18: ooOoO0o
 os . system ( "cp {} {}; rm -f {}; cp {} {}" . format ( I1i1I , file_name ,
 I1i1I , file_name , o0Iiii ) )
 return
 if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
 if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
 if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
 if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
 if 58 - 58: O0
 if 91 - 91: iII111i / I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I1ii11iIi11i
 if 72 - 72: Ii1I . IiII * I1ii11iIi11i / I1ii11iIi11i / iII111i
 if 13 - 13: i1IIi
def lisp_send_commands ( lisp_socket , process ) :
 Ii1IIII1ii1I = "./lisp.config"
 OO0O0OO = open ( Ii1IIII1ii1I , "r" )
 iiii11IiIiI = False
 i1IiiI = 0
 if 70 - 70: I11i . OOooOOo * Oo0Ooo / OOooOOo
 if 83 - 83: OoooooooOO + OoO0O00 * oO0o . O0
 if 13 - 13: o0oOOo0O0Ooo
 if 7 - 7: I1IiiI + IiII / i11iIiiIii / Oo0Ooo
 for oOO in OO0O0OO :
  if ( lisp_end_file ( oOO ) ) : break
  if ( lisp_comment ( oOO ) or oOO [ 0 ] == "\n" ) : continue
  if 97 - 97: I1Ii111 . I11i / I1IiiI
  if ( lisp_begin_clause ( oOO ) ) :
   if ( i1IiiI == 0 ) :
    Oo000 = ""
    oOOI11I = oOO . split ( "{" )
    oOOI11I = oOOI11I [ 0 ]
    oOOI11I = oOOI11I [ 0 : - 1 ]
    if ( lisp_commands . has_key ( oOOI11I ) ) :
     iiii11IiIiI = ( process in lisp_commands [ oOOI11I ] ) or ( oOOI11I == "lisp debug" )
     if 83 - 83: I11i - I1ii11iIi11i * oO0o
     if 90 - 90: Oo0Ooo * I1IiiI
     if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
   i1IiiI += 1
   if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
   if 28 - 28: IiII * I1IiiI % IiII
   if 95 - 95: O0 / I11i . I1Ii111
   if 17 - 17: I11i
   if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
  if ( iiii11IiIiI ) : Oo000 += oOO
  if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
  if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
  if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
  if 38 - 38: I1Ii111
  if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
  if ( lisp_end_clause ( oOO ) == False ) : continue
  i1IiiI -= 1
  if ( i1IiiI != 0 ) : continue
  if ( iiii11IiIiI == False ) : continue
  if 22 - 22: oO0o * iII111i
  if 4 - 4: OoOoOO00 - oO0o + I1IiiI
  if 36 - 36: IiII
  if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
  if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
  if 43 - 43: iIii1I11I1II1 % OoO0O00
  lisp . lprint ( "Send command '{}' to restarting process '{}'" . format ( oOOI11I , process ) )
  if 84 - 84: Oo0Ooo
  if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
  if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
  if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
  if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
  if 25 - 25: o0oOOo0O0Ooo
  if ( oOOI11I == "lisp debug" ) :
   lisp_debug_command ( lisp_socket , Oo000 , process )
   iiii11IiIiI = False
   continue
   if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
   if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
  Oo000 = lisp . lisp_command_ipc ( Oo000 , "lisp-core" )
  lisp . lisp_ipc ( Oo000 , lisp_socket , process )
  if 41 - 41: i1IIi - I1IiiI
  if 48 - 48: I1IiiI - II111iiii / OoO0O00 + I1IiiI
  if 5 - 5: O0
  if 75 - 75: I1Ii111 + iIii1I11I1II1
  if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
  lisp . lprint ( "Waiting for response to config command '{}'" . format ( oOOI11I ) )
  if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
  if 92 - 92: I11i / O0 * I1IiiI - I11i
  IIIIiIi11iiIi , i11iI11I1I , Ii1iiIi1I11i , I1i11II = lisp . lisp_receive ( lisp_socket , True )
  if 99 - 99: i11iIiiIii % OoooooooOO
  if ( i11iI11I1I == "" ) :
   lisp . lprint ( "Command timed out to {}" . format ( process ) )
  elif ( i11iI11I1I != process ) :
   lisp . lprint ( "Fatal IPC error to {}, IPC source {}" . format ( process ,
 i11iI11I1I ) )
   if 56 - 56: IiII * I1Ii111
  iiii11IiIiI = False
  if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
 return
 if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
 if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
 if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
 if 56 - 56: i1IIi . i11iIiiIii
 if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
 if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
 if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
 if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
def lisp_config_process ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 Ii1IIII1ii1I = "./lisp.config"
 I1ii1I1iii1 = ""
 iIiiiIIiii = True
 if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
 while ( True ) :
  Oo000o = os . path . getmtime ( Ii1IIII1ii1I )
  if ( Oo000o != I1ii1I1iii1 ) :
   if 25 - 25: iIii1I11I1II1
   lisp . lisp_ipc_lock . acquire ( )
   lisp_process_config_file ( lisp_socket , Ii1IIII1ii1I , iIiiiIIiii )
   lisp . lisp_ipc_lock . release ( )
   if 63 - 63: ooOoO0o
   iIiiiIIiii = False
   I1ii1I1iii1 = os . path . getmtime ( Ii1IIII1ii1I )
   if 96 - 96: I11i
  time . sleep ( 1 )
  if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
 return
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
def lisp_map_resolver_command ( kv_pair ) :
 o0I1iI111ii111i = None
 if 83 - 83: iIii1I11I1II1
 for ii1 in kv_pair . keys ( ) :
  if ( ii1 == "mr-name" ) :
   o0I1iI111ii111i = kv_pair [ ii1 ] [ 0 ]
   continue
   if 97 - 97: i11iIiiIii + Oo0Ooo * OOooOOo % iII111i . IiII
  if ( ii1 == "address" or ii1 == "dns-name" ) :
   iiOo0 = kv_pair [ ii1 ]
   for oo00oO0O0 in iiOo0 :
    if ( oo00oO0O0 == "" ) : continue
    Ii1I1i = oo00oO0O0 if ( ii1 == "address" ) else None
    OOO00 = oo00oO0O0 if ( ii1 == "dns-name" ) else None
    lisp . lisp_mr ( Ii1I1i , OOO00 , o0I1iI111ii111i )
    if 29 - 29: IiII
    if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
    if 71 - 71: ooOoO0o . ooOoO0o - iIii1I11I1II1
 return
 if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
 if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
 if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
 if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
 if 29 - 29: Ii1I / ooOoO0o % I11i
 if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
def lisp_map_cache_command ( kv_pair ) :
 O0o0O0O0O = [ ]
 for o0O00O in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  Iioo0O00ooo0o = lisp . lisp_mapping ( "" , "" , [ ] )
  O0o0O0O0O . append ( Iioo0O00ooo0o )
  if 29 - 29: OoooooooOO . II111iiii % OoOoOO00
  if 26 - 26: iIii1I11I1II1 - I1ii11iIi11i . IiII . IiII + iIii1I11I1II1 * Oo0Ooo
 O0Oo00 = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for o0O00O in range ( len ( kv_pair [ "address" ] ) ) :
   Oo0o0ooOoO = lisp . lisp_rloc ( )
   O0Oo00 . append ( Oo0o0ooOoO )
   if 47 - 47: OoOoOO00
   if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
   if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
 for ii1 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ ii1 ]
  if ( ii1 == "instance-id" ) :
   for o0O00O in range ( len ( O0o0O0O0O ) ) :
    Iioo0O00ooo0o = O0o0O0O0O [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 == "" ) : iI1IIIi11 = "0"
    Iioo0O00ooo0o . eid . instance_id = int ( iI1IIIi11 )
    Iioo0O00ooo0o . group . instance_id = int ( iI1IIIi11 )
    if 69 - 69: O0 - O0
    if 41 - 41: IiII % o0oOOo0O0Ooo
  if ( ii1 == "eid-prefix" ) :
   for o0O00O in range ( len ( O0o0O0O0O ) ) :
    Iioo0O00ooo0o = O0o0O0O0O [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) : Iioo0O00ooo0o . eid . store_prefix ( iI1IIIi11 )
    if 67 - 67: O0 % I1Ii111
    if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
  if ( ii1 == "group-prefix" ) :
   for o0O00O in range ( len ( O0o0O0O0O ) ) :
    Iioo0O00ooo0o = O0o0O0O0O [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) : Iioo0O00ooo0o . group . store_prefix ( iI1IIIi11 )
    if 39 - 39: Ii1I
    if 60 - 60: OOooOOo
  if ( ii1 == "send-map-request" ) :
   for o0O00O in range ( len ( O0o0O0O0O ) ) :
    Iioo0O00ooo0o = O0o0O0O0O [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 == "yes" ) : Iioo0O00ooo0o . action = lisp . LISP_SEND_MAP_REQUEST_ACTION
    if 62 - 62: I1Ii111 * I11i
    if 74 - 74: OoOoOO00 . iIii1I11I1II1
  if ( ii1 == "rle-name" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) :
     Oo0o0ooOoO . rle_name = iI1IIIi11
     if ( lisp . lisp_rle_list . has_key ( iI1IIIi11 ) ) :
      Oo0o0ooOoO . rle = lisp . lisp_rle_list [ iI1IIIi11 ]
      if 87 - 87: ooOoO0o
      if 41 - 41: OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
      if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
      if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
  if ( ii1 == "elp-name" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) :
     Oo0o0ooOoO . elp_name = iI1IIIi11
     if ( lisp . lisp_elp_list . has_key ( iI1IIIi11 ) ) :
      Oo0o0ooOoO . elp = lisp . lisp_elp_list [ iI1IIIi11 ]
      Oo0o0ooOoO . elp . select_elp_node ( )
      if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
      if 44 - 44: I1Ii111 - IiII
      if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
      if 59 - 59: II111iiii
  if ( ii1 == "rloc-record-name" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) : Oo0o0ooOoO . rloc_name = iI1IIIi11
    if 43 - 43: Oo0Ooo + OoooooooOO
    if 47 - 47: ooOoO0o
    if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
  if ( ii1 == "priority" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 == "" ) : iI1IIIi11 = "0"
    Oo0o0ooOoO . priority = int ( iI1IIIi11 )
    if 23 - 23: II111iiii * iII111i
    if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
  if ( ii1 == "weight" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 == "" ) : iI1IIIi11 = "0"
    Oo0o0ooOoO . weight = int ( iI1IIIi11 )
    if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
    if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
  if ( ii1 == "address" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) : Oo0o0ooOoO . rloc . store_address ( iI1IIIi11 )
    if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
    if 21 - 21: OoO0O00
    if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
    if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
    if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
    if 11 - 11: O0 * OoOoOO00
    if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
    if 18 - 18: OoooooooOO
 for Iioo0O00ooo0o in O0o0O0O0O :
  Iioo0O00ooo0o . rloc_set = O0Oo00
  Iioo0O00ooo0o . build_best_rloc_set ( )
  Iioo0O00ooo0o . add_cache ( )
  O0Oo00 = copy . deepcopy ( O0Oo00 )
  if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
 return
 if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
 if 94 - 94: ooOoO0o + I1IiiI
 if 56 - 56: OoOoOO00 % o0oOOo0O0Ooo
 if 40 - 40: OOooOOo / IiII
 if 29 - 29: Ii1I - Ii1I / ooOoO0o
 if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
 if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
def lisp_display_map_cache ( mc , output ) :
 Oo000o = lisp . lisp_print_elapsed ( mc . uptime )
 iIiII1iiiiI = Oo000o
 OOOO0oo0 = mc . print_eid_tuple ( )
 OOOOooO0 = mc . action
 if 86 - 86: IiII
 if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
 if 33 - 33: II111iiii - IiII - ooOoO0o
 if 92 - 92: OoO0O00 * IiII
 if 92 - 92: oO0o
 if 7 - 7: iII111i
 i11iI11I1I = mc . mapping_source
 if ( i11iI11I1I == None ) :
  i11iI11I1I = "map-notify"
 else :
  i11iI11I1I = "static" if i11iI11I1I . is_null ( ) else i11iI11I1I . print_address_no_iid ( )
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if 62 - 62: i11iIiiIii
 if ( mc . checkpoint_entry ) : i11iI11I1I = "checkpoint"
 i1Iii = mc . print_ttl ( )
 if 91 - 91: ooOoO0o * IiII * II111iiii
 OOOOooO0 = "encapsulate" if OOOOooO0 == lisp . LISP_NO_ACTION else lisp . lisp_map_reply_action_string [ OOOOooO0 ]
 if 79 - 79: I1Ii111
 if 8 - 8: iII111i - II111iiii
 if ( len ( mc . rloc_set ) == 0 ) :
  ii1111I = mc . stats . get_stats ( True , True )
  output += lisp_table_row ( OOOO0oo0 , Oo000o + "<br>" + i1Iii , "--" , i11iI11I1I ,
 ii1111I , OOOOooO0 , "--" )
  return ( [ True , output ] )
  if 45 - 45: o0oOOo0O0Ooo
  if 58 - 58: I1IiiI * i1IIi % II111iiii / O0
 for Oo0o0ooOoO in mc . rloc_set :
  O0oo0ooo0 = ""
  if ( Oo0o0ooOoO . rloc_exists ( ) ) :
   if ( Oo0o0ooOoO . rloc . is_null ( ) == False ) :
    O0oo0ooo0 = Oo0o0ooOoO . rloc . print_address_no_iid ( ) + "<br>"
    I1I1i1 = ""
    iII1 = lisp . lisp_nonce_echoing and Oo0o0ooOoO . echo_nonce_capable
    if ( lisp . lisp_rloc_probing ) :
     I1I1i1 += Oo0o0ooOoO . print_rloc_probe_state ( iII1 )
     if 77 - 77: OoooooooOO + o0oOOo0O0Ooo
    if ( iII1 ) :
     o00O0o = lisp . lisp_get_echo_nonce ( Oo0o0ooOoO . rloc , None )
     if ( o00O0o ) : I1I1i1 += o00O0o . print_echo_nonce ( )
     if 28 - 28: I1IiiI
    if ( I1I1i1 != "" ) : O0oo0ooo0 = lisp . lisp_span ( O0oo0ooo0 , I1I1i1 )
    if 87 - 87: IiII . i1IIi % OoooooooOO * i11iIiiIii
    if 67 - 67: I1Ii111 / OoO0O00 . OoooooooOO
    if 51 - 51: II111iiii . oO0o . OoO0O00 % II111iiii
  if ( Oo0o0ooOoO . translated_port != 0 ) :
   O0oo0ooo0 += "encap-port: {}<br>" . format ( Oo0o0ooOoO . translated_port )
   if 41 - 41: OoOoOO00 - OOooOOo + ooOoO0o - i1IIi
   if 6 - 6: II111iiii
  if ( Oo0o0ooOoO . rloc_name ) :
   O0oo0ooo0 += "rloc-name: {}<br>" . format ( lisp . blue ( Oo0o0ooOoO . rloc_name ,
 True ) )
   if 7 - 7: i1IIi
   if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
  if ( Oo0o0ooOoO . geo ) :
   O0oo0ooo0 += "geo: {}<br>" . format ( Oo0o0ooOoO . geo . print_geo_url ( ) )
   if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
  if ( Oo0o0ooOoO . elp ) :
   IiIii11I = Oo0o0ooOoO . elp . print_elp ( True )
   O0oo0ooo0 += "elp: {}<br>" . format ( IiIii11I )
   if 97 - 97: i1IIi + iII111i . ooOoO0o - iII111i
  if ( Oo0o0ooOoO . rle ) :
   ooo = Oo0o0ooOoO . rle . print_rle ( True )
   O0oo0ooo0 += "rle: {}<br>" . format ( ooo )
   if 74 - 74: ooOoO0o % OoOoOO00 / Oo0Ooo
  if ( Oo0o0ooOoO . json ) :
   IIII1i = "json: { ... }<br>"
   O0oo0ooo0 += lisp . lisp_span ( IIII1i , Oo0o0ooOoO . json . print_json ( False ) )
   if 2 - 2: IiII % IiII % I1Ii111
   if 60 - 60: OOooOOo
   if 73 - 73: ooOoO0o
   if 86 - 86: OoOoOO00 . I11i / Oo0Ooo * I11i
   if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
  ii1111I = Oo0o0ooOoO . stats . get_stats ( True , True )
  if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
  if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
  if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
  if 5 - 5: O0 - I1IiiI
  IiiI1iii1iIiiI = ""
  II1iiiiI1 = Oo0o0ooOoO
  while ( True ) :
   IiiIiiIIII = lisp . lisp_print_elapsed ( II1iiiiI1 . last_state_change )
   if ( IiiIiiIIII == "never" ) : IiiIiiIIII = iIiII1iiiiI
   o00oOOO0Ooo = II1iiiiI1 . print_state ( )
   if ( II1iiiiI1 . unreach_state ( ) or II1iiiiI1 . no_echoed_nonce_state ( ) ) :
    o00oOOO0Ooo = lisp . red ( o00oOOO0Ooo , True )
    if 88 - 88: OoO0O00 . I1Ii111 / I11i
   IiiI1iii1iIiiI += o00oOOO0Ooo + " since " + IiiIiiIIII
   if 47 - 47: OoO0O00 + I1ii11iIi11i . ooOoO0o
   if ( lisp . lisp_rloc_probing ) :
    IiiIiIIi1 = II1iiiiI1 . print_rloc_probe_rtt ( )
    if ( IiiIiIIi1 != "none" ) : IiiI1iii1iIiiI += "<br>rtt: {}, hops: {}" . format ( IiiIiIIi1 , II1iiiiI1 . print_rloc_probe_hops ( ) )
    if 40 - 40: iII111i . OoOoOO00 * O0
    if 6 - 6: I1IiiI - II111iiii . I1IiiI + I11i . OOooOOo
    if 74 - 74: i1IIi
   if ( lisp . lisp_rloc_probing and II1iiiiI1 . rloc_next_hop != None ) :
    i111iiIIII , Ii11ii1 = II1iiiiI1 . rloc_next_hop
    IiiI1iii1iIiiI += "<br>{}nh {}({}) " . format ( lisp . lisp_space ( 2 ) , Ii11ii1 , i111iiIIII )
    if 1 - 1: iIii1I11I1II1 % oO0o . iIii1I11I1II1
    if 10 - 10: iII111i + OoO0O00
   II1iiiiI1 = II1iiiiI1 . next_rloc
   if ( II1iiiiI1 == None ) : break
   IiiI1iii1iIiiI += "<br>"
   if 6 - 6: OoO0O00
   if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
  if ( OOOOooO0 == "encapsulate" ) :
   Ii1iiIi1I11i = lisp . LISP_DATA_PORT
   if ( lisp . lisp_i_am_rtr and Oo0o0ooOoO . translated_port != 0 ) :
    Ii1iiIi1I11i = Oo0o0ooOoO . translated_port
    if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
    if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
   Ii1I1i = Oo0o0ooOoO . rloc . print_address_no_iid ( ) + ":" + str ( Ii1iiIi1I11i )
   if ( lisp . lisp_crypto_keys_by_rloc_encap . has_key ( Ii1I1i ) ) :
    oOOOooOo0O = lisp . lisp_crypto_keys_by_rloc_encap [ Ii1I1i ] [ 1 ]
    if ( oOOOooOo0O != None and oOOOooOo0O . shared_key != None ) :
     OOOOooO0 = "encap-crypto-" + oOOOooOo0O . cipher_suite_string
     if 31 - 31: oO0o * I1Ii111 . OoOoOO00 * I11i
     if 28 - 28: IiII + I1IiiI - Oo0Ooo % OOooOOo . I11i + I1IiiI
     if 72 - 72: Ii1I / Oo0Ooo / oO0o * OoOoOO00 + OOooOOo
     if 58 - 58: o0oOOo0O0Ooo % I1IiiI . I1IiiI * OoO0O00 - IiII . OoooooooOO
  output += lisp_table_row ( OOOO0oo0 , Oo000o + "<br>" + i1Iii , O0oo0ooo0 , i11iI11I1I ,
 ii1111I , IiiI1iii1iIiiI + "<br>" + OOOOooO0 ,
 str ( Oo0o0ooOoO . priority ) + "/" + str ( Oo0o0ooOoO . weight ) + "<br>" + str ( Oo0o0ooOoO . mpriority ) + "/" + str ( Oo0o0ooOoO . mweight ) )
  if 10 - 10: I1Ii111
  if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
  if ( OOOO0oo0 != "" ) : OOOO0oo0 = ""
  if ( Oo000o != "" ) : Oo000o , i1Iii , i11iI11I1I = ( "" , "" , "" )
  if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
 return ( [ True , output ] )
 if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
 if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
 if 55 - 55: OoooooooOO
 if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
 if 38 - 38: O0
 if 79 - 79: i1IIi . oO0o
 if 34 - 34: I1Ii111 * II111iiii
 if 71 - 71: IiII
def lisp_walk_map_cache ( mc , output ) :
 if 97 - 97: I1ii11iIi11i
 if 86 - 86: Oo0Ooo - OOooOOo . OoOoOO00 . II111iiii * I1IiiI . II111iiii
 if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
 if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
 if ( mc . group . is_null ( ) ) : return ( lisp_display_map_cache ( mc , output ) )
 if 28 - 28: i11iIiiIii
 if ( mc . source_cache == None ) : return ( [ True , output ] )
 if 51 - 51: I1IiiI + ooOoO0o * O0 . Ii1I
 if 82 - 82: OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
 if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
 if 20 - 20: i1IIi . i1IIi - I11i
 if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
 output = mc . source_cache . walk_cache ( lisp_display_map_cache , output )
 return ( [ True , output ] )
 if 35 - 35: II111iiii / OoOoOO00 - O0 . II111iiii
 if 55 - 55: Oo0Ooo % i1IIi * I11i
 if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
 if 63 - 63: iIii1I11I1II1 / ooOoO0o
 if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
 if 50 - 50: II111iiii
 if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
def lisp_show_myrlocs ( output ) :
 if ( lisp . lisp_myrlocs [ 2 ] == None ) :
  output += "No local RLOCs found"
 else :
  iIIiI = lisp . lisp_print_cour ( lisp . lisp_myrlocs [ 2 ] )
  O0O0O0OO00oo = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 0 ] != None else "not found"
  if 39 - 39: IiII % OoOoOO00 * I1ii11iIi11i - OoooooooOO - Oo0Ooo
  O0O0O0OO00oo = lisp . lisp_print_cour ( O0O0O0OO00oo )
  Oo0oOOO = "-f inet" if lisp . lisp_is_macos ( ) else "-4"
  o00OoOooo = commands . getoutput ( "netstat -rn {}" . format ( Oo0oOOO ) )
  O0O0O0OO00oo = lisp . lisp_span ( O0O0O0OO00oo , o00OoOooo )
  if 47 - 47: ooOoO0o + iII111i + i1IIi
  IIiii = lisp . lisp_myrlocs [ 1 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 1 ] != None else "not found"
  if 77 - 77: iIii1I11I1II1 * oO0o
  IIiii = lisp . lisp_print_cour ( IIiii )
  Oo0oOOO = "-f inet6" if lisp . lisp_is_macos ( ) else "-6"
  o00OoOooo = commands . getoutput ( "netstat -rn {}" . format ( Oo0oOOO ) )
  IIiii = lisp . lisp_span ( IIiii , o00OoOooo )
  if 15 - 15: iIii1I11I1II1 . OOooOOo . I1ii11iIi11i * i11iIiiIii
  oOO = "<i>Local RLOCs found on interface </i>{}<i>, " + "IPv4: </i>{}<i>, IPv6: </i>{}"
  if 72 - 72: I11i
  output += lisp . lisp_print_sans ( oOO ) . format ( iIIiI , O0O0O0OO00oo , IIiii )
  if 26 - 26: IiII % Oo0Ooo
 output += "<br>"
 return ( output )
 if 72 - 72: O0 + o0oOOo0O0Ooo + I1IiiI / Oo0Ooo
 if 83 - 83: IiII - I1IiiI . Ii1I
 if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
 if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
 if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
 if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
 if 25 - 25: Oo0Ooo % OoOoOO00
def lisp_display_nat_info ( output , dc , dodns ) :
 o00O = len ( lisp . lisp_nat_state_info )
 if ( o00O == 0 ) : return ( output )
 if 36 - 36: OOooOOo * OoO0O00 - I1ii11iIi11i + iII111i
 I1I1i1 = "{} entries in the NAT-traversal port table" . format ( o00O )
 IIIiiiiiI1I = lisp . lisp_span ( "NAT-Traversed xTR Information:" , I1I1i1 )
 if 64 - 64: IiII * iIii1I11I1II1 . I1ii11iIi11i / I11i * iIii1I11I1II1
 if ( dodns ) :
  output += lisp_table_header ( IIIiiiiiI1I , "xTR Hostname" ,
 "Translated<br>Address" , "Translated<br>{} Port" . format ( dc ) ,
 "Last<br>Info-Request" , "NAT DNS Name" )
 else :
  output += lisp_table_header ( IIIiiiiiI1I , "xTR Hostname" ,
 "Translated<br>Address" , "Translated<br>{} Port" . format ( dc ) ,
 "Last<br>Info-Request" )
  if 4 - 4: ooOoO0o % IiII . I1Ii111
  if 91 - 91: I1ii11iIi11i + iIii1I11I1II1 % IiII
 for O0o0OOOO0 in lisp . lisp_nat_state_info . values ( ) :
  for ii1O0O in O0o0OOOO0 :
   II = ii1O0O . address
   OOoO000O0OO = ii1O0O . uptime
   ii11 = ii1O0O . hostname
   Ii1iiIi1I11i = ii1O0O . port
   if 37 - 37: OoO0O00 + I1ii11iIi11i - O0 * II111iiii
   if ( ii1O0O . timed_out ( ) ) :
    OOoO000O0OO = lisp . red ( lisp . lisp_print_elapsed ( OOoO000O0OO ) , True )
   else :
    OOoO000O0OO = lisp . lisp_print_elapsed ( OOoO000O0OO )
    if 35 - 35: I1ii11iIi11i * OoO0O00 * I1IiiI / OoooooooOO
    if 15 - 15: ooOoO0o % o0oOOo0O0Ooo / oO0o - II111iiii . iIii1I11I1II1
   if ( dodns ) :
    try :
     ii1111Iii11i = socket . gethostbyaddr ( II ) [ 0 ]
    except :
     ii1111Iii11i = "?"
     if 91 - 91: Ii1I - iII111i . i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo % iII111i
    output += lisp_table_row ( ii11 , II , Ii1iiIi1I11i , OOoO000O0OO , ii1111Iii11i )
   else :
    output += lisp_table_row ( ii11 , II , Ii1iiIi1I11i , OOoO000O0OO )
    if 30 - 30: I11i
    if 85 - 85: II111iiii + ooOoO0o * I11i
    if 12 - 12: Ii1I . I1IiiI % o0oOOo0O0Ooo
    if 28 - 28: Ii1I - I1IiiI % OoO0O00 * I1Ii111
 output += lisp_table_footer ( )
 return ( output )
 if 80 - 80: OOooOOo * IiII
 if 4 - 4: iIii1I11I1II1 . I1Ii111 + II111iiii % OoooooooOO
 if 82 - 82: OoooooooOO / ooOoO0o * I11i * O0 . I1ii11iIi11i
 if 21 - 21: II111iiii + Oo0Ooo
 if 59 - 59: OOooOOo + I1IiiI / II111iiii / OoOoOO00
 if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
 if 76 - 76: I1IiiI * OOooOOo
def lisp_itr_rtr_show_command ( parameter , itr_or_rtr , lisp_threads , dns = False ) :
 if 12 - 12: iIii1I11I1II1 / I11i % Ii1I
 if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
 if 27 - 27: OoO0O00 + Oo0Ooo
 if 92 - 92: I1IiiI % iII111i
 if ( parameter != "" ) :
  return ( lisp_show_map_cache_lookup ( parameter ) )
  if 31 - 31: OoooooooOO - oO0o / I1Ii111
  if 62 - 62: i11iIiiIii - I11i
 i1iiI11I = ""
 if 81 - 81: I11i
 if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
 if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
 if 31 - 31: i1IIi % II111iiii
 i1iiI11I = lisp_show_myrlocs ( i1iiI11I )
 if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
 if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
 if 3 - 3: II111iiii / OOooOOo
 if 48 - 48: ooOoO0o . I1ii11iIi11i
 if ( itr_or_rtr == "RTR" ) :
  i1iiI11I = lisp_show_decap_stats ( i1iiI11I , itr_or_rtr )
  if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
  if 24 - 24: oO0o - iII111i / ooOoO0o
  if 10 - 10: OoOoOO00 * i1IIi
  if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
  if 34 - 34: I1IiiI
 if ( len ( lisp_threads ) > 1 ) :
  o00oOOO0Ooo = [ ]
  for o0O00O in range ( len ( lisp_threads ) ) :
   o0OoOo0O00 = lisp_threads [ o0O00O ]
   o00oOOO0Ooo . append ( "{} Input Stats<br>queue-size: {}" . format ( o0OoOo0O00 . thread_name ,
 o0OoOo0O00 . input_queue . qsize ( ) ) )
   if 9 - 9: OOooOOo
  i1iiI11I += lisp_table_header ( "LISP-RTR Forwarding Stats:" , * o00oOOO0Ooo )
  if 38 - 38: I11i . OoO0O00 . i11iIiiIii * OoooooooOO + iII111i
  o00oOOO0Ooo = [ ]
  for o0O00O in range ( len ( lisp_threads ) ) :
   o0OoOo0O00 = lisp_threads [ o0O00O ]
   o00oOOO0Ooo . append ( o0OoOo0O00 . input_stats . get_stats ( False , True ) )
   if 49 - 49: Oo0Ooo - OoO0O00 / I1Ii111 / o0oOOo0O0Ooo % oO0o
  i1iiI11I += lisp_table_row ( * o00oOOO0Ooo )
  i1iiI11I += lisp_table_footer ( )
  if 38 - 38: o0oOOo0O0Ooo . oO0o / o0oOOo0O0Ooo % II111iiii
  if 47 - 47: I11i * iIii1I11I1II1 * iII111i - OoO0O00 . O0 . ooOoO0o
  if 32 - 32: o0oOOo0O0Ooo % I1IiiI
  if 7 - 7: Oo0Ooo . i1IIi - oO0o
  if 93 - 93: IiII % I1ii11iIi11i
 I1I1i1 = "{} map-resolvers configured" . format ( len ( lisp . lisp_map_resolvers_list ) )
 if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
 IIIiiiiiI1I = "LISP-{} Configured Map-Resolvers:" . format ( itr_or_rtr )
 IIIiiiiiI1I = lisp . lisp_span ( IIIiiiiiI1I , I1I1i1 )
 i1iiI11I += lisp_table_header ( IIIiiiiiI1I , "Map-Resolver" , "Last Used" ,
 "Map-Requests<br>Sent" , "Negative Map-Replies<br>Received" ,
 "Last Negative<br>Map-Reply" , "Average RTT" )
 if 28 - 28: Ii1I . I1ii11iIi11i
 for i11i1Ii1 in lisp . lisp_map_resolvers_list . values ( ) :
  i11i1Ii1 . resolve_dns_name ( )
  o0I1iI111ii111i = "" if i11i1Ii1 . mr_name == "all" else i11i1Ii1 . mr_name + "<br>"
  Ii1I1i = o0I1iI111ii111i + i11i1Ii1 . map_resolver . print_address ( )
  if ( i11i1Ii1 . dns_name ) : Ii1I1i += "<br>" + i11i1Ii1 . dns_name
  if 77 - 77: I1ii11iIi11i % II111iiii
  Oo000o = lisp . lisp_print_elapsed ( i11i1Ii1 . last_used )
  OOo00o0oo0 = lisp . lisp_print_elapsed ( i11i1Ii1 . last_reply )
  IIIIiII = 0 if i11i1Ii1 . neg_map_replies_received is 0 else float ( i11i1Ii1 . total_rtt / i11i1Ii1 . neg_map_replies_received )
  if 39 - 39: o0oOOo0O0Ooo / IiII - iII111i
  IIIIiII = str ( round ( IIIIiII , 3 ) ) + " ms"
  if 96 - 96: I11i * I1ii11iIi11i * Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
  i1iiI11I += lisp_table_row ( Ii1I1i , Oo000o , i11i1Ii1 . map_requests_sent ,
 i11i1Ii1 . neg_map_replies_received , OOo00o0oo0 , IIIIiII )
  if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
 i1iiI11I += lisp_table_footer ( )
 if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
 if 1 - 1: Oo0Ooo . II111iiii
 if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
 if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
 if ( itr_or_rtr == "ITR" ) : i1iiI11I = lisp_show_db_list ( "ITR" , i1iiI11I )
 if 4 - 4: IiII
 if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
 if 99 - 99: i11iIiiIii - iII111i
 if 85 - 85: I1Ii111 % I1ii11iIi11i
 i11IiIiiIIIII = "<br>Enter EID for Map-Cache lookup:"
 if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
 oooOo00 = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 1 - 1: I1IiiI + I1ii11iIi11i
 Ooo0oO0 = itr_or_rtr . lower ( )
 if 77 - 77: Oo0Ooo / I11i . iII111i / I1Ii111 - OoooooooOO
 i11IiIiiIIIII = '''
         <form action="/lisp/show/{}/map-cache/lookup" method="post">
         <font size="3"><i>{}</i> {}
         <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form>
    ''' . format ( Ooo0oO0 , lisp . lisp_print_sans ( i11IiIiiIIIII ) , oooOo00 )
 if 76 - 76: O0
 oooIi1i = '<a href="/lisp/show/{}/rloc-probing">RLOC State</a>' . format ( Ooo0oO0 )
 if 49 - 49: oO0o + oO0o + i11iIiiIii % iII111i
 I1I1 = '<a href="/lisp/show/{}/keys"><br>RLOC Keys</a>' . format ( Ooo0oO0 )
 if 80 - 80: o0oOOo0O0Ooo % iII111i
 if 80 - 80: Ii1I
 if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
 if 59 - 59: I1ii11iIi11i + I11i . oO0o
 oOOo0oO = os . path . exists ( "./show-ztr" )
 iIIII1iII1i = "Map-Cache"
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None or oOOo0oO ) :
  iIIII1iII1i = '<a href="/lisp/show/lisp-xtr">Map-Cache</a>'
  if 98 - 98: I1Ii111 % OoO0O00 - ooOoO0o % i11iIiiIii + I1Ii111 - IiII
  if 97 - 97: ooOoO0o / iIii1I11I1II1 % ooOoO0o / I1IiiI * iII111i % OoOoOO00
  if 17 - 17: iIii1I11I1II1
  if 89 - 89: i1IIi . i1IIi
  if 10 - 10: iII111i % Oo0Ooo
 I1I1i1 = "{} entries in the map-cache" . format ( lisp . lisp_map_cache . cache_size ( ) )
 if 48 - 48: OOooOOo + I1Ii111 % OOooOOo
 IIIiiiiiI1I = "LISP-{} {}:{}" . format ( itr_or_rtr , iIIII1iII1i , lisp . lisp_space ( 4 ) )
 IIIiiiiiI1I = lisp . lisp_span ( IIIiiiiiI1I , I1I1i1 )
 if 84 - 84: O0 % Ii1I . Ii1I . iII111i * I11i
 if 43 - 43: OoOoOO00 . I1ii11iIi11i % i1IIi
 if 61 - 61: I1IiiI + oO0o % I1Ii111 % iIii1I11I1II1 - OoooooooOO
 if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
 if 83 - 83: ooOoO0o
 IIIiiiiiI1I += lisp . lisp_button ( "clear cache" ,
 "/lisp/clear/{}/map-cache" . format ( itr_or_rtr . lower ( ) ) )
 IIIiiiiiI1I += i11IiIiiIIIII
 if 43 - 43: OOooOOo
 if 84 - 84: OOooOOo . IiII . iII111i
 i1iiI11I += lisp_table_header ( IIIiiiiiI1I , "EID-Prefix or (S,G)" ,
 "Uptime<br>TTL" , "RLOC Record" + I1I1 , "Map-Reply Source" ,
 "RLOC Send Stats" , oooIi1i + "<br>RLOC Action" ,
 "Unicast Priority/Weight<br>Multicast Priority/Weight" )
 if 2 - 2: Oo0Ooo - OoOoOO00
 i1iiI11I = lisp . lisp_map_cache . walk_cache ( lisp_walk_map_cache , i1iiI11I )
 i1iiI11I += lisp_table_footer ( )
 if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
 if 54 - 54: ooOoO0o % Oo0Ooo - OOooOOo
 if 16 - 16: I1ii11iIi11i * iII111i / I11i
 if 46 - 46: II111iiii
 if ( len ( lisp . lisp_elp_list ) != 0 ) : i1iiI11I = lisp_show_elp_list ( i1iiI11I )
 if 13 - 13: IiII + II111iiii % I1IiiI
 if 30 - 30: OoooooooOO - i11iIiiIii + oO0o / Oo0Ooo - i11iIiiIii
 if 74 - 74: O0 . I11i
 if 64 - 64: ooOoO0o / i1IIi % iII111i
 if ( len ( lisp . lisp_rle_list ) != 0 ) : i1iiI11I = lisp_show_rle_list ( i1iiI11I )
 if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
 if 99 - 99: I1Ii111
 if 75 - 75: ooOoO0o . OOooOOo / IiII
 if 84 - 84: OoooooooOO . I1IiiI / o0oOOo0O0Ooo
 if ( len ( lisp . lisp_json_list ) != 0 ) : i1iiI11I = lisp_show_json_list ( i1iiI11I )
 if 86 - 86: Oo0Ooo % OoOoOO00
 if 77 - 77: Ii1I % OOooOOo / oO0o
 if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
 if 23 - 23: I1IiiI
 if ( itr_or_rtr == "RTR" ) :
  i1iiI11I = lisp_display_nat_info ( i1iiI11I , "Data" , dns )
  if 7 - 7: iII111i % I1ii11iIi11i
  if 64 - 64: I1Ii111 + i11iIiiIii
  if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
  if 68 - 68: IiII . ooOoO0o
  if 64 - 64: i1IIi + Oo0Ooo * I1IiiI / OOooOOo
 return ( i1iiI11I )
 if 3 - 3: Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
 if 50 - 50: iIii1I11I1II1 * oO0o
 if 85 - 85: i1IIi
 if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
 if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
 if 54 - 54: OoOoOO00 * iII111i + OoO0O00
 if 93 - 93: o0oOOo0O0Ooo / I1IiiI
def lisp_itr_rtr_show_rloc_probe_command ( itr_or_rtr ) :
 IIIiiiiiI1I = "LISP-{} RLOC-Probe Information:" . format ( itr_or_rtr )
 i1iiI11I = lisp_table_header ( IIIiiiiiI1I , "RLOC Key State" , "RLOC-Probe State" )
 if 47 - 47: Oo0Ooo * OOooOOo
 for oOoO0O00o in lisp . lisp_rloc_probe_list . values ( ) :
  if 25 - 25: O0 + I11i + OOooOOo * I1ii11iIi11i
  OOOO0oo0 = ""
  for II1iiiiI1 , OO0Iii1iIiI111Ii , ooO0oo0000oOo in oOoO0O00o :
   oOOoO0oO00O = lisp . green ( lisp . lisp_print_eid_tuple ( OO0Iii1iIiI111Ii , ooO0oo0000oOo ) , True )
   OOOO0oo0 += lisp . lisp_print_cour ( oOOoO0oO00O ) + "<br>"
   if 72 - 72: OoO0O00 - iIii1I11I1II1 . iII111i / Ii1I
  OOOO0oo0 = ", EIDs ({}):<br>" . format ( len ( oOoO0O00o ) ) + OOOO0oo0
  if 12 - 12: I1IiiI + I1Ii111
  II1iiiiI1 , OO0Iii1iIiI111Ii , ooO0oo0000oOo = oOoO0O00o [ 0 ]
  if 80 - 80: oO0o . O0
  if 90 - 90: II111iiii / OoO0O00 / Ii1I
  if 70 - 70: Ii1I - II111iiii . Oo0Ooo / Oo0Ooo
  if 30 - 30: oO0o . OoO0O00 + I11i / iIii1I11I1II1 % Oo0Ooo / oO0o
  Ii11ii1 = lisp . lisp_hex_string ( II1iiiiI1 . last_rloc_probe_nonce )
  if ( II1iiiiI1 . translated_rloc . not_set ( ) ) :
   iIi11 = II1iiiiI1 . rloc . print_address_no_iid ( )
  else :
   iIi11 = "{}{}{}" . format ( II1iiiiI1 . translated_rloc . print_address_no_iid ( ) ,
 lisp . bold ( ":" , True ) , II1iiiiI1 . translated_port )
   if 100 - 100: OoooooooOO - OoooooooOO + IiII
  iIi11 = lisp . bold ( lisp . lisp_print_cour ( iIi11 ) , True )
  iIiIi1i1Iiii = II1iiiiI1 . rloc_name
  if ( iIiIi1i1Iiii != None ) :
   iIiIi1i1Iiii = lisp . bold ( iIiIi1i1Iiii , True )
   iIi11 += ", {}" . format ( lisp . lisp_print_cour ( lisp . blue ( iIiIi1i1Iiii , True ) ) )
   if 78 - 78: Oo0Ooo - I1Ii111 + iII111i * Ii1I * o0oOOo0O0Ooo
  IiiI1iii1iIiiI = II1iiiiI1 . print_state ( )
  if ( II1iiiiI1 . up_state ( ) == False ) : IiiI1iii1iIiiI = lisp . red ( II1iiiiI1 . print_state ( ) , True )
  iIi11 = "RLOC " + iIi11 + ", {}" . format ( IiiI1iii1iIiiI )
  if 23 - 23: Oo0Ooo - O0
  iI111iIi = iIi11 + OOOO0oo0
  if 26 - 26: OOooOOo % OOooOOo / i11iIiiIii + I1ii11iIi11i - O0
  if 20 - 20: I1Ii111 . O0 - I1ii11iIi11i / OoOoOO00 - o0oOOo0O0Ooo
  if 79 - 79: OoooooooOO - iIii1I11I1II1
  if 9 - 9: i1IIi - OoOoOO00
  Oo00o0OOo0OO = lisp . lisp_print_elapsed ( II1iiiiI1 . last_rloc_probe )
  Oo00o0OOo0OO = lisp . lisp_print_cour ( Oo00o0OOo0OO )
  I1i1iiIi = lisp . lisp_print_elapsed ( II1iiiiI1 . last_rloc_probe_reply )
  I1i1iiIi = lisp . lisp_print_cour ( I1i1iiIi )
  IIi1IiiIi1III = ( "Last probe-request sent: {}, " + "last probe-reply received: {}<br>" ) . format ( Oo00o0OOo0OO , I1i1iiIi )
  if 19 - 19: i1IIi % I1IiiI - iIii1I11I1II1 - oO0o / I1ii11iIi11i
  if 16 - 16: Ii1I
  Ii11ii1 = lisp . lisp_hex_string ( II1iiiiI1 . last_rloc_probe_nonce )
  Ii11ii1 = lisp . lisp_print_cour ( "0x" + Ii11ii1 )
  IiiIiIIi1 = II1iiiiI1 . print_recent_rloc_probe_rtts ( )
  IiiIiIIi1 = lisp . lisp_print_cour ( IiiIiIIi1 )
  Oo00O00o0 = II1iiiiI1 . print_recent_rloc_probe_hops ( )
  Oo00O00o0 = lisp . lisp_print_cour ( Oo00O00o0 )
  IiII1 = II1iiiiI1 . print_rloc_probe_hops ( )
  IiII1 = lisp . lisp_print_cour ( IiII1 )
  II1iiiiI1 = II1iiiiI1 . print_rloc_probe_rtt ( )
  II1iiiiI1 = lisp . lisp_print_cour ( II1iiiiI1 )
  IIi1IiiIi1III += ( "Nonce: {}, rtt: {}, hops: {}<br>" + "Recent-rtts: {}, recent-hops: {}" ) . format ( Ii11ii1 , II1iiiiI1 , IiII1 , IiiIiIIi1 , Oo00O00o0 )
  if 45 - 45: OoO0O00 + OoO0O00 % ooOoO0o
  if 36 - 36: Ii1I * I11i . I11i / Oo0Ooo / I1IiiI
  if 80 - 80: OoooooooOO - i1IIi
  if 51 - 51: i1IIi . OoOoOO00 / OoOoOO00 % i11iIiiIii * OOooOOo - I1Ii111
  if 49 - 49: Oo0Ooo - iIii1I11I1II1
  i1iiI11I += lisp_table_row ( iI111iIi , IIi1IiiIi1III )
  if 64 - 64: I1Ii111 + iIii1I11I1II1
  if 14 - 14: Ii1I / OoooooooOO + II111iiii . O0 / i1IIi
 i1iiI11I += lisp_table_footer ( )
 return ( i1iiI11I )
 if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
 if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
 if 12 - 12: OoOoOO00 + o0oOOo0O0Ooo . I1Ii111
 if 52 - 52: OoO0O00
 if 4 - 4: Ii1I % I1ii11iIi11i + I11i - I1ii11iIi11i
 if 98 - 98: Ii1I - O0 * oO0o * Ii1I * Ii1I
 if 44 - 44: IiII + I11i
def lisp_xtr_command ( kv_pair ) :
 if 66 - 66: oO0o
 if 34 - 34: iII111i % i11iIiiIii + i11iIiiIii - iII111i
 if 2 - 2: II111iiii + i1IIi
 if 68 - 68: OOooOOo + Ii1I
 if 58 - 58: IiII * Ii1I . i1IIi
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) :
  kv_pair [ "ipc-data-plane" ] = [ "yes" ]
  if 19 - 19: oO0o
  if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
 for ii1 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ ii1 ] [ 0 ]
  if ( ii1 == "rloc-probing" ) :
   lisp . lisp_rloc_probing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_rloc_probe_list = { }
   if 94 - 94: iIii1I11I1II1 + IiII
  if ( ii1 == "nonce-echoing" ) :
   lisp . lisp_nonce_echoing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_nonce_echo_list = { }
   if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
  if ( ii1 == "data-plane-security" ) :
   lisp . lisp_data_plane_security = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) :
    lisp . lisp_crypto_keys_by_nonce = { }
    lisp . lisp_crypto_keys_by_rloc_encap = { }
    lisp . lisp_crypto_keys_by_rloc_decap = { }
    if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
    if 36 - 36: OoOoOO00 . i11iIiiIii
  if ( ii1 == "data-plane-logging" ) :
   lisp . lisp_data_plane_logging = ( oo00oO0O0 == "yes" )
   if 81 - 81: Oo0Ooo * iII111i * OoO0O00
  if ( ii1 == "frame-logging" ) :
   lisp . lisp_frame_logging = ( oo00oO0O0 == "yes" )
   if 85 - 85: O0 * oO0o
  if ( ii1 == "flow-logging" ) :
   lisp . lisp_flow_logging = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "yes" ) : os . system ( "touch ./log-flows" )
   if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
  if ( ii1 == "nat-traversal" ) :
   lisp . lisp_nat_traversal = ( oo00oO0O0 == "yes" )
   if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
  if ( ii1 == "program-hardware" ) :
   lisp . lisp_program_hardware = ( oo00oO0O0 == "yes" )
   if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
  if ( ii1 == "checkpoint-map-cache" ) :
   lisp . lisp_checkpoint_map_cache = ( oo00oO0O0 == "yes" )
   O0oo = lisp . lisp_checkpoint_filename
   if ( oo00oO0O0 == "no" and os . path . exists ( O0oo ) ) :
    os . system ( "rm {}" . format ( O0oo ) )
    if 50 - 50: I1Ii111 - II111iiii
    if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
  if ( ii1 == "ipc-data-plane" ) :
   ii1iI11IiIIi = ( oo00oO0O0 == "yes" )
   if ( ii1iI11IiIIi and lisp . lisp_ipc_data_plane == False ) :
    o00oOOO0Ooo = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
    lisp . lisp_ipc_dp_socket = o00oOOO0Ooo
    if 47 - 47: OOooOOo . oO0o + OoOoOO00 % IiII % i1IIi / iIii1I11I1II1
   if ( ii1iI11IiIIi == False and lisp . lisp_ipc_data_plane ) :
    lisp . lisp_ipc_dp_socket . close ( )
    lisp . lisp_ipc_dp_socket = None
    if 95 - 95: O0 . OoO0O00
   lisp . lisp_ipc_data_plane = ii1iI11IiIIi
   if 89 - 89: i1IIi
  if ( ii1 == "decentralized-xtr" ) :
   lisp . lisp_decent_configured = ( oo00oO0O0 == "yes" )
   if 19 - 19: ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
  if ( ii1 == "register-reachable-rtrs" ) :
   lisp . lisp_register_all_rtrs = ( oo00oO0O0 == "no" )
   if 14 - 14: I1ii11iIi11i - i11iIiiIii * I1Ii111
   if 39 - 39: OoooooooOO
 return
 if 19 - 19: i11iIiiIii
 if 80 - 80: I1IiiI
 if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
 if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
 if 26 - 26: o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
 if 97 - 97: i1IIi
 if 46 - 46: I1ii11iIi11i
def lisp_show_json_list ( output ) :
 if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
 IIIiiiiiI1I = "Configured JSON Entries:"
 output += lisp_table_header ( IIIiiiiiI1I , "JSON Name" , "JSON String" )
 if 23 - 23: I11i
 I1I = sorted ( lisp . lisp_json_list )
 for o0OO in I1I :
  IIII1i = lisp . lisp_json_list [ o0OO ]
  iI11i1I1i = lisp . lisp_print_cour ( IIII1i . print_json ( True ) )
  output += lisp_table_row ( o0OO , iI11i1I1i )
  if 96 - 96: I1Ii111 / IiII * iIii1I11I1II1 + i11iIiiIii * I1ii11iIi11i / I1IiiI
 output += lisp_table_footer ( )
 return ( output )
 if 93 - 93: O0 * iIii1I11I1II1 + Ii1I % iII111i
 if 96 - 96: oO0o % Oo0Ooo
 if 20 - 20: ooOoO0o . IiII / I11i . OoooooooOO * OOooOOo + Ii1I
 if 2 - 2: I1IiiI
 if 11 - 11: OOooOOo + iIii1I11I1II1 / OoOoOO00 % O0
 if 98 - 98: II111iiii + Oo0Ooo * iIii1I11I1II1 * I1ii11iIi11i + OOooOOo * Ii1I
 if 76 - 76: ooOoO0o . oO0o
def lisp_show_rle_list ( output ) :
 if 60 - 60: OOooOOo * ooOoO0o * OoO0O00
 IIIiiiiiI1I = "Configured Replication List Entries (RLEs):"
 output += lisp_table_header ( IIIiiiiiI1I , "RLE Name" , "RLE Nodes" )
 if 64 - 64: I11i / II111iiii / OoO0O00 - ooOoO0o * iIii1I11I1II1 . iII111i
 iIi11I1II = sorted ( lisp . lisp_rle_list )
 for oO00Oo0O0 in iIi11I1II :
  ooo = lisp . lisp_rle_list [ oO00Oo0O0 ]
  output += lisp_table_row ( oO00Oo0O0 , ooo . print_rle ( True ) )
  if 91 - 91: I11i + Ii1I + IiII
 output += lisp_table_footer ( )
 return ( output )
 if 58 - 58: iII111i * Ii1I - i11iIiiIii % I1ii11iIi11i
 if 3 - 3: I1Ii111 . I11i % II111iiii * I1IiiI % i1IIi * OoO0O00
 if 5 - 5: II111iiii * i1IIi % Ii1I
 if 55 - 55: I1IiiI + iII111i
 if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
 if 19 - 19: I11i / iII111i + IiII
 if 76 - 76: iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo + OoooooooOO
def lisp_show_elp_list ( output ) :
 IIIiiiiiI1I = "Configured Explicit Locator Paths (ELPs):"
 output += lisp_table_header ( IIIiiiiiI1I , "ELP Name" , "ELP Nodes" )
 if 10 - 10: OoO0O00 * I11i / Oo0Ooo - I1Ii111
 I1iIi1IiI1i = sorted ( lisp . lisp_elp_list )
 for IiiIiiiiI1III in I1iIi1IiI1i :
  IiIii11I = lisp . lisp_elp_list [ IiiIiiiiI1III ]
  output += lisp_table_row ( IiiIiiiiI1III , IiIii11I . print_elp ( False ) )
  if 42 - 42: oO0o - ooOoO0o * I11i % iII111i * Oo0Ooo / I1Ii111
 output += lisp_table_footer ( )
 return ( output )
 if 94 - 94: ooOoO0o + iIii1I11I1II1
 if 86 - 86: o0oOOo0O0Ooo / ooOoO0o . o0oOOo0O0Ooo % I1IiiI + oO0o % I11i
 if 72 - 72: ooOoO0o - I1ii11iIi11i + oO0o . OoOoOO00
 if 44 - 44: I1ii11iIi11i / O0 - IiII + OOooOOo . I11i . I1ii11iIi11i
 if 95 - 95: OoOoOO00 % I1Ii111 % i1IIi * o0oOOo0O0Ooo + OOooOOo
 if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
 if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
def lisp_geo_command ( kv_pair ) :
 if 76 - 76: oO0o / OoOoOO00
 if 12 - 12: I1Ii111
 if 58 - 58: OoO0O00 + iIii1I11I1II1 % O0 + I11i + OoOoOO00 * OoooooooOO
 if 41 - 41: oO0o * I1IiiI
 if ( kv_pair . has_key ( "geo-name" ) == False ) : return
 OO = kv_pair [ "geo-name" ]
 oo0OoO = lisp . lisp_geo ( OO )
 if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
 if 58 - 58: IiII % iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * iII111i
 if 32 - 32: OoooooooOO + o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o - I1Ii111 * I1Ii111
 if ( kv_pair . has_key ( "geo-tag" ) == False ) : return
 if 55 - 55: iIii1I11I1II1 + I1IiiI - Oo0Ooo
 if 24 - 24: OoO0O00 / I1Ii111 + iII111i * I11i * iII111i
 if 10 - 10: I1IiiI - I1ii11iIi11i - Oo0Ooo - o0oOOo0O0Ooo
 if 21 - 21: OoooooooOO + I1Ii111
 iiIi1111Ii1 = kv_pair [ "geo-tag" ] [ 1 : : ]
 if ( oo0OoO . parse_geo_string ( iiIi1111Ii1 ) == False ) : return
 if 31 - 31: o0oOOo0O0Ooo * I11i - i11iIiiIii - I1IiiI
 if 19 - 19: iII111i . I11i * OoooooooOO - OOooOOo + O0 * I1Ii111
 if 90 - 90: i1IIi . oO0o / I1Ii111 . OOooOOo / I1Ii111
 if 1 - 1: iII111i % ooOoO0o
 lisp . lisp_geo_list [ OO ] = oo0OoO
 return
 if 99 - 99: iII111i + iIii1I11I1II1 . OOooOOo / OoO0O00 * I1ii11iIi11i
 if 87 - 87: IiII / II111iiii % OoO0O00 % OoO0O00
 if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
 if 91 - 91: I1IiiI / II111iiii * OOooOOo
 if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
 if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
 if 81 - 81: OoO0O00 - iIii1I11I1II1
def lisp_elp_command ( kv_pair ) :
 if 60 - 60: I1Ii111
 IiIii11I = None
 ooO0IIiIIiiiiiII1 = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for o0O00O in range ( len ( kv_pair [ "address" ] ) ) :
   iIi1i1II = lisp . lisp_elp_node ( )
   ooO0IIiIIiiiiiII1 . append ( iIi1i1II )
   if 62 - 62: Oo0Ooo * iIii1I11I1II1
   if 11 - 11: I1ii11iIi11i + iII111i
   if 77 - 77: i1IIi
 for ii1 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ ii1 ]
  if 63 - 63: oO0o . I1Ii111 * II111iiii - oO0o
  if ( ii1 == "elp-name" ) :
   IiIii11I = lisp . lisp_elp ( oo00oO0O0 )
   continue
   if 45 - 45: oO0o % ooOoO0o + I1Ii111 + o0oOOo0O0Ooo . Oo0Ooo
   if 15 - 15: ooOoO0o / IiII * i11iIiiIii + iII111i
  for iIiI1I1II1 in ooO0IIiIIiiiiiII1 :
   O0OO0O = ooO0IIiIIiiiiiII1 . index ( iIiI1I1II1 )
   if ( O0OO0O >= len ( oo00oO0O0 ) ) : O0OO0O = len ( oo00oO0O0 ) - 1
   iI1IIIi11 = oo00oO0O0 [ O0OO0O ]
   if ( ii1 == "probe" ) : iIiI1I1II1 . probe = ( iI1IIIi11 == "yes" )
   if ( ii1 == "strict" ) : iIiI1I1II1 . strict = ( iI1IIIi11 == "yes" )
   if ( ii1 == "eid" ) : iIiI1I1II1 . eid = ( iI1IIIi11 == "yes" )
   if ( ii1 == "address" ) : iIiI1I1II1 . address . store_address ( iI1IIIi11 )
   if 45 - 45: I1IiiI + I11i + i1IIi
   if 22 - 22: IiII / OOooOOo
   if 62 - 62: Ii1I - oO0o + iIii1I11I1II1 / OOooOOo . iII111i / Ii1I
   if 63 - 63: i1IIi
   if 56 - 56: Oo0Ooo
   if 52 - 52: OOooOOo + Oo0Ooo
 if ( IiIii11I == None ) : return
 if 67 - 67: I1ii11iIi11i % OoooooooOO
 if 41 - 41: OoO0O00 / IiII + I1Ii111 . I1Ii111 / oO0o
 if 74 - 74: Ii1I % i11iIiiIii . O0 * I1IiiI * i1IIi * OoooooooOO
 if 22 - 22: I1Ii111 + iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoooooooOO
 IiIii11I . elp_nodes = ooO0IIiIIiiiiiII1
 lisp . lisp_elp_list [ IiIii11I . elp_name ] = IiIii11I
 return
 if 42 - 42: OoooooooOO - OoOoOO00 - OOooOOo * I1Ii111
 if 98 - 98: OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
 if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
 if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
 if 95 - 95: oO0o
 if 80 - 80: IiII
 if 42 - 42: OoooooooOO * II111iiii
def lisp_rle_command ( kv_pair ) :
 if 53 - 53: I1Ii111 + i1IIi . OoO0O00 / i11iIiiIii + Ii1I % OoOoOO00
 ooo = None
 I1Io0Oo00 = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for o0O00O in range ( len ( kv_pair [ "address" ] ) ) :
   I1II11IIi11i = lisp . lisp_rle_node ( )
   I1Io0Oo00 . append ( I1II11IIi11i )
   if 67 - 67: iIii1I11I1II1 - iII111i
   if 81 - 81: O0
   if 38 - 38: iII111i
 for ii1 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ ii1 ]
  if 78 - 78: i11iIiiIii . IiII % OoooooooOO - IiII - IiII + Ii1I
  if ( ii1 == "rle-name" ) :
   ooo = lisp . lisp_rle ( oo00oO0O0 )
   continue
   if 11 - 11: I11i
   if 20 - 20: O0 . i11iIiiIii * i1IIi % O0 . I1IiiI
  for iIiI1I1II1 in I1Io0Oo00 :
   O0OO0O = I1Io0Oo00 . index ( iIiI1I1II1 )
   if ( O0OO0O >= len ( oo00oO0O0 ) ) : O0OO0O = len ( oo00oO0O0 ) - 1
   iI1IIIi11 = oo00oO0O0 [ O0OO0O ]
   if ( ii1 == "level" ) :
    if ( iI1IIIi11 == "" ) : iI1IIIi11 = "0"
    iIiI1I1II1 . level = int ( iI1IIIi11 )
    if 53 - 53: ooOoO0o / OoooooooOO - II111iiii
   if ( ii1 == "address" ) : iIiI1I1II1 . address . store_address ( iI1IIIi11 )
   if 68 - 68: OoooooooOO . OoooooooOO . iIii1I11I1II1 / ooOoO0o - I11i % O0
   if 19 - 19: OoooooooOO * oO0o
   if 60 - 60: II111iiii - iII111i + o0oOOo0O0Ooo % OOooOOo
   if 97 - 97: O0 % O0
   if 35 - 35: iII111i - Ii1I . i11iIiiIii % O0 % I1ii11iIi11i
   if 92 - 92: OOooOOo % II111iiii . iII111i
 if ( ooo == None ) : return
 if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
 if 47 - 47: iII111i * OoOoOO00 * IiII
 if 46 - 46: Ii1I
 if 42 - 42: iIii1I11I1II1
 ooo . rle_nodes = I1Io0Oo00
 ooo . build_forwarding_list ( )
 lisp . lisp_rle_list [ ooo . rle_name ] = ooo
 return
 if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
 if 34 - 34: Oo0Ooo
 if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
 if 33 - 33: i1IIi / iII111i * OoO0O00
 if 2 - 2: oO0o . OOooOOo
 if 43 - 43: iIii1I11I1II1
 if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
def lisp_json_command ( kv_pair ) :
 if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
 try :
  o0OO = kv_pair [ "json-name" ]
  iI11i1I1i = kv_pair [ "json-string" ]
 except :
  return
  if 98 - 98: i1IIi - iII111i
  if 49 - 49: o0oOOo0O0Ooo . Ii1I . oO0o
 IIII1i = lisp . lisp_json ( o0OO , iI11i1I1i )
 IIII1i . add ( )
 return
 if 9 - 9: IiII - II111iiii * OoO0O00
 if 78 - 78: iIii1I11I1II1 / O0 * oO0o / iII111i / OoOoOO00
 if 15 - 15: ooOoO0o / oO0o
 if 54 - 54: ooOoO0o - iIii1I11I1II1 - I11i % Ii1I / II111iiii
 if 80 - 80: i11iIiiIii % iIii1I11I1II1 / i11iIiiIii
 if 66 - 66: OoOoOO00 . iIii1I11I1II1 * I1ii11iIi11i - Ii1I - iIii1I11I1II1
 if 28 - 28: OoOoOO00 % OoooooooOO
 if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
 if 84 - 84: II111iiii
 if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
 if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
 if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
def lisp_get_lookup_string ( input_str ) :
 if 85 - 85: i1IIi . i1IIi
 if 16 - 16: I1IiiI - OOooOOo % Ii1I . OOooOOo + I1ii11iIi11i % i11iIiiIii
 if 59 - 59: i11iIiiIii - I11i
 if 59 - 59: OoooooooOO * o0oOOo0O0Ooo / I1Ii111
 OOOO0oo0 = input_str
 I11iiI1i1 = None
 if ( input_str . find ( "->" ) != - 1 ) :
  I1i1Iiiii = input_str . split ( "->" )
  OOOO0oo0 = I1i1Iiiii [ 0 ]
  I11iiI1i1 = I1i1Iiiii [ 1 ]
  if 75 - 75: o0oOOo0O0Ooo - OoooooooOO
  if 21 - 21: I1IiiI + iIii1I11I1II1 / i11iIiiIii / oO0o
 Ooo000 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 I1111IiII1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if 26 - 26: i1IIi / I1IiiI / I11i + I11i
 if 46 - 46: I1Ii111 % I1ii11iIi11i + Ii1I
 if 67 - 67: iIii1I11I1II1 . i11iIiiIii . i11iIiiIii . i11iIiiIii / I11i + ooOoO0o
 if 10 - 10: ooOoO0o - Oo0Ooo % II111iiii
 oo = OOOO0oo0 . split ( "/" )
 if ( len ( oo ) == 1 ) :
  Ooo000 . store_address ( oo [ 0 ] )
  i11iI1111ii1I = False
 else :
  Ooo000 . store_prefix ( OOOO0oo0 )
  i11iI1111ii1I = True
  if 89 - 89: i11iIiiIii / O0 - i1IIi % Oo0Ooo + i11iIiiIii
  if 44 - 44: i11iIiiIii / OOooOOo * ooOoO0o
 Ooo00o000o = i11iI1111ii1I
 if ( I11iiI1i1 ) :
  oo = I11iiI1i1 . split ( "/" )
  if ( len ( oo ) == 1 ) :
   I1111IiII1 . store_address ( oo [ 0 ] )
   Ooo00o000o = False
  else :
   I1111IiII1 . store_prefix ( OOOO0oo0 )
   Ooo00o000o = True
   if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
   if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
 return ( [ Ooo000 , i11iI1111ii1I , I1111IiII1 , Ooo00o000o ] )
 if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
 if 89 - 89: ooOoO0o * I1IiiI . oO0o
 if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
 if 26 - 26: I11i * Ii1I % I1IiiI + iII111i
 if 38 - 38: iII111i - Oo0Ooo / Ii1I + oO0o . iII111i + IiII
 if 19 - 19: Ii1I
 if 51 - 51: iIii1I11I1II1
def lisp_show_map_cache_lookup ( eid_str ) :
 Ooo000 , i11iI1111ii1I , I1111IiII1 , Ooo00o000o = lisp_get_lookup_string ( eid_str )
 if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
 i1iiI11I = "<br>"
 if 8 - 8: OoO0O00 * Oo0Ooo
 IIiII = Ooo000 if ( I1111IiII1 . is_null ( ) ) else I1111IiII1
 IIi1oo0OO0Oo = i11iI1111ii1I if ( I1111IiII1 . is_null ( ) ) else Ooo00o000o
 if 4 - 4: OoOoOO00 * O0 - I11i
 Oo = lisp . lisp_map_cache . lookup_cache ( IIiII , IIi1oo0OO0Oo )
 if ( Oo == None ) :
  i1iiI11I += "{} {}" . format ( lisp . lisp_print_sans ( "Lookup not found for" ) ,
 lisp . lisp_print_cour ( eid_str ) )
 else :
  if ( IIiII == I1111IiII1 ) :
   O0o0oo0 = Oo . lookup_source_cache ( Ooo000 , i11iI1111ii1I )
   if ( O0o0oo0 ) : Oo = O0o0oo0
   if 86 - 86: i11iIiiIii + iIii1I11I1II1
   if 87 - 87: OoO0O00 * OoOoOO00 - Oo0Ooo % OOooOOo * i11iIiiIii
  Oo000o = lisp . lisp_print_elapsed ( Oo . uptime )
  i1iiI11I += "{} {} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Exact" if i11iI1111ii1I else "Longest" ) ,
  # OoOoOO00 % II111iiii * II111iiii . I1IiiI
 lisp . lisp_print_sans ( "match lookup for" ) ,
 lisp . lisp_print_cour ( eid_str ) ,
 lisp . lisp_print_sans ( "found" ) ,
 lisp . lisp_print_cour ( Oo . print_eid_tuple ( ) ) ,
 lisp . lisp_print_sans ( "with uptime" ) ,
 lisp . lisp_print_cour ( Oo000o ) )
  if 11 - 11: iII111i
 i1iiI11I += "<br>"
 return ( i1iiI11I )
 if 20 - 20: Ii1I . I1Ii111 % Ii1I
 if 5 - 5: OOooOOo + iII111i
 if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
 if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
 if 11 - 11: I1ii11iIi11i / O0 + II111iiii
 if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
 if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
 if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
def lisp_get_clause_for_api ( command ) :
 OO0O0OO = open ( "./lisp.config" , "r" )
 Oo000 = { command : [ ] }
 iiIIi1i111i = { }
 iII = [ ]
 if 55 - 55: iIii1I11I1II1 . IiII - o0oOOo0O0Ooo . I1ii11iIi11i * i1IIi
 i1IiiI = 0
 iiii11IiIiI = False
 for oOO in OO0O0OO :
  if ( lisp_end_file ( oOO ) ) : break
  if ( lisp_comment ( oOO ) ) : continue
  if 76 - 76: i1IIi + O0 / IiII + i11iIiiIii % I1Ii111 % Oo0Ooo
  if 61 - 61: iIii1I11I1II1 % Ii1I - oO0o * OoooooooOO % II111iiii - Ii1I
  if 44 - 44: O0
  if 9 - 9: oO0o . Oo0Ooo + iII111i + I1IiiI * I1IiiI - I1IiiI
  if 95 - 95: IiII + OOooOOo % oO0o * OOooOOo
  if 58 - 58: OoOoOO00 . o0oOOo0O0Ooo + oO0o
  if ( oOO . find ( command + " {" ) != - 1 ) :
   i1IiiI += 1
   iiii11IiIiI = True
   continue
   if 26 - 26: II111iiii / o0oOOo0O0Ooo
  if ( iiii11IiIiI == False ) : continue
  if 32 - 32: I1ii11iIi11i * I1IiiI + o0oOOo0O0Ooo % II111iiii + OOooOOo + Ii1I
  if ( lisp_begin_clause ( oOO ) ) :
   i1IiiI += 1
   oo0OOo0Oo00 = oOO . replace ( " " , "" )
   oo0OOo0Oo00 = oo0OOo0Oo00 . replace ( "\t" , "" )
   oo0OOo0Oo00 = oo0OOo0Oo00 . replace ( "\n" , "" )
   oo0OOo0Oo00 = oo0OOo0Oo00 . replace ( "{" , "" )
   iiIIi1i111i = { oo0OOo0Oo00 : { } }
   continue
   if 64 - 64: iII111i % OoooooooOO
   if 65 - 65: OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
   if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
   if 93 - 93: I1ii11iIi11i * I1ii11iIi11i / OoooooooOO
   if 6 - 6: I1ii11iIi11i * Oo0Ooo + iIii1I11I1II1
   if 19 - 19: O0 % II111iiii * o0oOOo0O0Ooo
  if ( lisp_end_clause ( oOO ) ) :
   i1IiiI -= 1
   if ( i1IiiI ) :
    Oo000 [ command ] . append ( iiIIi1i111i )
    iiIIi1i111i = { }
    continue
    if 27 - 27: OOooOOo * IiII / i11iIiiIii - oO0o + II111iiii
   iII . append ( Oo000 )
   Oo000 = { command : [ ] }
   iiii11IiIiI = False
   continue
   if 43 - 43: I1ii11iIi11i - II111iiii
   if 56 - 56: I1ii11iIi11i . i1IIi / iII111i % oO0o / O0 * I11i
  oOO = oOO . replace ( " " , "" )
  oOO = oOO . replace ( "\t" , "" )
  oOO = oOO . replace ( "\n" , "" )
  oOO = oOO . replace ( "{" , "" )
  oOO = oOO . split ( "=" )
  oo00oO0O0 = "" if len ( oOO ) == 1 else oOO [ 1 ]
  oOOOooOo0O = oOO [ 0 ]
  if 98 - 98: O0 + iII111i
  if ( len ( iiIIi1i111i ) == 0 ) :
   Oo000 [ command ] . append ( { oOOOooOo0O : oo00oO0O0 } )
  else :
   iiIIi1i111i [ oo0OOo0Oo00 ] [ oOOOooOo0O ] = oo00oO0O0
   if 23 - 23: OoooooooOO . iIii1I11I1II1 / i1IIi
   if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
   if 74 - 74: Oo0Ooo - II111iiii - IiII
 OO0O0OO . close ( )
 if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
 if ( len ( iII ) == 0 ) :
  iII = [ { "?" : [ { "?" : "not-found" } ] } ]
  if 70 - 70: i1IIi % OoO0O00 / i1IIi
 return ( iII )
 if 30 - 30: OoOoOO00 - i11iIiiIii
 if 94 - 94: OoOoOO00 % iII111i
 if 39 - 39: OoOoOO00 + I1Ii111 % O0
 if 26 - 26: ooOoO0o + OoOoOO00
 if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
 if 6 - 6: I1Ii111
 if 46 - 46: II111iiii * I1Ii111
def lisp_duplicate_command_clause ( command , clause ) :
 OOO00OOo0o0Oo = open ( "./lisp.config" , "r" )
 if 23 - 23: i1IIi - O0
 clause = command + " {\n" + clause
 for oOO in OOO00OOo0o0Oo :
  if ( lisp_begin_clause ( oOO ) == False ) : continue
  if ( oOO . find ( command ) == - 1 ) : continue
  if 6 - 6: ooOoO0o % OoooooooOO * I1Ii111 - IiII
  I1ii = oOO
  for oOO in OOO00OOo0o0Oo :
   I1ii += oOO
   if ( oOO [ 0 ] != "}" ) : continue
   if ( I1ii != clause ) : break
   OOO00OOo0o0Oo . close ( )
   return ( True )
   if 82 - 82: OoOoOO00 . Ii1I
  if ( lisp_end_file ( oOO ) ) : break
  if 73 - 73: I1Ii111
  if 25 - 25: IiII
 OOO00OOo0o0Oo . close ( )
 return ( False )
 if 77 - 77: o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO . iIii1I11I1II1
 if 87 - 87: II111iiii - OoooooooOO / i1IIi . Ii1I - Oo0Ooo . i11iIiiIii
 if 47 - 47: Oo0Ooo % OoO0O00 - ooOoO0o - Oo0Ooo * oO0o
 if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
 if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
 if 64 - 64: IiII
 if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
def lisp_put_clause_for_api ( data ) :
 if 89 - 89: O0 + IiII * I1Ii111
 if 30 - 30: OoOoOO00
 if 39 - 39: I1ii11iIi11i + o0oOOo0O0Ooo + I1Ii111 + IiII
 if 48 - 48: I1Ii111 / ooOoO0o . iIii1I11I1II1
 oOOI11I = data . keys ( ) [ 0 ]
 if ( oOOI11I not in lisp_commands . keys ( ) ) :
  return ( [ { oOOI11I : [ { "?" : "add/replace" } ] } ] )
  if 72 - 72: i1IIi . o0oOOo0O0Ooo
  if 3 - 3: OoOoOO00 % II111iiii - O0
 oO0o00O = ( oOOI11I in [ "lisp enable" , "lisp debug" , "lisp xtr-parameters" ] )
 if 7 - 7: Oo0Ooo * OoO0O00 - II111iiii % I1Ii111 . Oo0Ooo . Oo0Ooo
 if 5 - 5: OoooooooOO * I1ii11iIi11i
 if 42 - 42: o0oOOo0O0Ooo . I1Ii111 / O0 . II111iiii * OoOoOO00
 if 7 - 7: I1Ii111 * O0 + OoOoOO00
 if 90 - 90: IiII * II111iiii * IiII - iII111i
 if 34 - 34: OOooOOo - I1ii11iIi11i * iII111i % Ii1I
 if 25 - 25: II111iiii + I1IiiI * ooOoO0o * I1ii11iIi11i . iII111i
 I1i1IiiI = False
 if ( oO0o00O == False ) :
  I1i1IiiI = True
  IiiiI1i = commands . getoutput ( "egrep '{}' ./lisp.config" . format ( oOOI11I ) )
  IiiiI1i = IiiiI1i . split ( "\n" )
  for oOO in IiiiI1i :
   if ( oOO [ 0 : len ( oOOI11I ) ] == oOOI11I ) : I1i1IiiI = False
   if 32 - 32: iII111i + OoOoOO00 . I1Ii111 . i1IIi . OoOoOO00 * ooOoO0o
   if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
   if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
   if 50 - 50: ooOoO0o
   if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
   if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
 O0ooO0oOO = data [ oOOI11I ]
 O0ooO0oOO = lisp_unicode_to_ascii ( O0ooO0oOO )
 Oo000 = oOOI11I + " {\n" if I1i1IiiI else ""
 if 53 - 53: O0 / II111iiii - OOooOOo - oO0o . OOooOOo
 if 4 - 4: OOooOOo - Oo0Ooo % II111iiii - OoO0O00 % i1IIi % ooOoO0o
 if 31 - 31: iIii1I11I1II1 / OoooooooOO
 if 8 - 8: iIii1I11I1II1 . iIii1I11I1II1 + Ii1I . OOooOOo
 if 58 - 58: iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - i1IIi * OoOoOO00
 if 4 - 4: OoooooooOO
 if 7 - 7: IiII
 if 26 - 26: OOooOOo + Oo0Ooo
 for oo0iI1i11II1i1i in O0ooO0oOO :
  if ( type ( O0ooO0oOO ) == dict ) :
   oo00oO0O0 = O0ooO0oOO [ oo0iI1i11II1i1i ]
   if ( type ( oo00oO0O0 ) == dict ) : oo00oO0O0 = json_dumps ( oo00oO0O0 )
   Oo000 += "    " + oo0iI1i11II1i1i + " = " + oo00oO0O0 + "\n"
   continue
   if 61 - 61: I11i * Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
   if 51 - 51: OOooOOo / I11i
  for oOOOooOo0O in oo0iI1i11II1i1i :
   if ( type ( oo0iI1i11II1i1i ) == dict ) :
    O0OOO00O0OO0 = oOOOooOo0O
    oo00oO0O0 = oo0iI1i11II1i1i [ oOOOooOo0O ]
    if 5 - 5: oO0o + Ii1I
   if ( type ( oo0iI1i11II1i1i ) == list ) :
    O0OOO00O0OO0 = oOOOooOo0O . keys ( ) [ 0 ]
    oo00oO0O0 = oOOOooOo0O . values ( ) [ 0 ]
    if 48 - 48: I1Ii111 * i1IIi - I1ii11iIi11i / I1IiiI + i11iIiiIii - i1IIi
    if 91 - 91: o0oOOo0O0Ooo / i11iIiiIii
   if ( type ( oo00oO0O0 ) != dict ) :
    Oo000 += "    " + oOOOooOo0O + " = " + oo0iI1i11II1i1i [ oOOOooOo0O ] + "\n"
    continue
    if 96 - 96: OoO0O00 + iII111i * II111iiii
    if 82 - 82: o0oOOo0O0Ooo + Ii1I * I1IiiI - oO0o
    if 6 - 6: OOooOOo / iIii1I11I1II1 / ooOoO0o / I1IiiI - i1IIi - OOooOOo
    if 8 - 8: i11iIiiIii * I11i . OOooOOo / OOooOOo
    if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
   Oo000 += "    " + O0OOO00O0OO0 + " {\n"
   for i111iIi11Ii in oo00oO0O0 : Oo000 += "        " + i111iIi11Ii + " = " + oo00oO0O0 [ i111iIi11Ii ] + "\n"
   Oo000 += "    }\n"
   if 67 - 67: Ii1I . Oo0Ooo
   if 39 - 39: I11i * I1Ii111
 Oo000 += "}\n"
 if 63 - 63: ooOoO0o % I1IiiI . OOooOOo - ooOoO0o / Oo0Ooo % I1IiiI
 if 39 - 39: o0oOOo0O0Ooo . i1IIi % oO0o / I11i % O0
 if 100 - 100: I1Ii111 - OoOoOO00
 if 78 - 78: OoooooooOO - OoOoOO00 . i11iIiiIii
 if ( lisp_duplicate_command_clause ( oOOI11I , Oo000 ) ) :
  return ( [ { oOOI11I : [ { "!" : "duplicate" } ] } ] )
  if 36 - 36: oO0o * iII111i + IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1
  if 14 - 14: I11i * oO0o + i11iIiiIii
 o0o0o = "./lisp.config"
 IiIiiIiii = o0o0o + ".temp"
 if 3 - 3: I11i / I1Ii111 * IiII - O0 + I1IiiI / IiII
 iii1II11II1 = open ( o0o0o , "r" )
 I11i1 = open ( IiIiiIiii , "w" )
 if 43 - 43: O0 / I1Ii111 . iIii1I11I1II1 - OoOoOO00
 iiII1iiI = False
 Ooo0o00O0 = False
 for oOO in iii1II11II1 :
  if ( Ooo0o00O0 ) :
   if ( lisp_end_clause ( oOO ) == False ) : continue
   Ooo0o00O0 = False
   continue
   if 1 - 1: Ii1I / OoooooooOO % O0 - i1IIi
   if 67 - 67: I1IiiI - OoO0O00
   if 60 - 60: i1IIi / iIii1I11I1II1 * oO0o + ooOoO0o + OoooooooOO + II111iiii
   if 13 - 13: iIii1I11I1II1 - OOooOOo
   if 14 - 14: ooOoO0o
  if ( iiII1iiI == False and lisp_begin_clause ( oOO ) and
 oOO [ 0 : len ( oOOI11I ) ] == oOOI11I ) :
   if ( oO0o00O == False ) :
    I11i1 . write ( oOO )
    for Ooo0OO00oo in Oo000 : I11i1 . write ( Ooo0OO00oo )
    iiII1iiI = True
    if 21 - 21: I11i
    if 79 - 79: OoO0O00 / OOooOOo - i1IIi + i1IIi - IiII + IiII
    if 67 - 67: OoO0O00 * OoO0O00 / OoooooooOO
    if 79 - 79: o0oOOo0O0Ooo % iIii1I11I1II1 / II111iiii / Ii1I / Ii1I + O0
    if 46 - 46: i1IIi / IiII
    if 84 - 84: OoOoOO00 / iIii1I11I1II1 + oO0o % ooOoO0o + oO0o - iIii1I11I1II1
  if ( lisp_end_file ( oOO ) ) :
   if ( I1i1IiiI ) :
    for Ooo0OO00oo in Oo000 : I11i1 . write ( Ooo0OO00oo )
    if 27 - 27: O0 / o0oOOo0O0Ooo * I1IiiI
   I11i1 . write ( oOO )
   iiII1iiI = True
   break
   if 41 - 41: ooOoO0o
   if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
   if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
   if 1 - 1: I1IiiI . Ii1I
   if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
  I11i1 . write ( oOO )
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  if 21 - 21: O0 * ooOoO0o % OoO0O00
  if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
  if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
  if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
  if ( lisp_begin_clause ( oOO ) and oOO [ 0 : len ( oOOI11I ) ] == oOOI11I ) :
   if ( oO0o00O ) :
    Ooo0o00O0 = True
    for Ooo0OO00oo in Oo000 : I11i1 . write ( Ooo0OO00oo )
    if 76 - 76: I11i . I1ii11iIi11i * OoooooooOO % iII111i
    if 24 - 24: OoooooooOO
    if 83 - 83: O0 / OoO0O00
    if 62 - 62: I11i
 iii1II11II1 . close ( )
 I11i1 . close ( )
 if 73 - 73: Ii1I % OoO0O00 * OOooOOo
 os . system ( "cp {} {}" . format ( IiIiiIiii , o0o0o ) )
 os . system ( "rm {}" . format ( IiIiiIiii ) )
 return ( [ { oOOI11I : [ { "!" : "add/replace" } ] } ] )
 if 84 - 84: Oo0Ooo
 if 18 - 18: OoooooooOO
 if 85 - 85: OoooooooOO . OoO0O00 . OoO0O00
 if 70 - 70: I11i
 if 72 - 72: I1Ii111 - ooOoO0o - I1IiiI - iII111i + OOooOOo - i1IIi
 if 45 - 45: OoO0O00 * I1IiiI
 if 61 - 61: iII111i % II111iiii / OoOoOO00 % I1ii11iIi11i . iIii1I11I1II1 % O0
 if 74 - 74: I1ii11iIi11i * oO0o + iII111i % O0
def lisp_remove_clause_for_api ( data ) :
 if 18 - 18: i1IIi % IiII . O0 - O0 - O0 - II111iiii
 if 55 - 55: OoOoOO00 . iIii1I11I1II1 * OOooOOo % iIii1I11I1II1 . OoO0O00
 if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
 if 2 - 2: OOooOOo
 oOOI11I = data . keys ( ) [ 0 ]
 if ( oOOI11I not in lisp_commands . keys ( ) ) :
  return ( [ { oOOI11I : [ { "?" : "delete" } ] } ] )
  if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
  if 79 - 79: Ii1I + oO0o % ooOoO0o % I1IiiI
  if 68 - 68: II111iiii - OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % II111iiii
  if 53 - 53: iII111i . oO0o / Oo0Ooo . OoO0O00 . i11iIiiIii
  if 60 - 60: II111iiii
 O0ooO0oOO = data [ oOOI11I ]
 O0ooO0oOO = lisp_unicode_to_ascii ( O0ooO0oOO )
 if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
 if 57 - 57: II111iiii . i1IIi
 if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
 if 6 - 6: IiII + I1ii11iIi11i
 OOOoooooO0oOOoO = [ ]
 oOOOooOo0O = O0ooO0oOO . keys ( ) [ 0 ]
 oo00oO0O0 = O0ooO0oOO [ oOOOooOo0O ]
 if 26 - 26: I1Ii111 / I1Ii111 + Oo0Ooo - o0oOOo0O0Ooo % II111iiii . OoooooooOO
 if ( type ( oo00oO0O0 ) == dict ) :
  for oOOOooOo0O in oo00oO0O0 . keys ( ) :
   IiiI11Iii = oo00oO0O0 [ oOOOooOo0O ]
   OOOoooooO0oOOoO . append ( oOOOooOo0O + " = " + IiiI11Iii )
   if 42 - 42: I11i + i1IIi - Ii1I / IiII . iII111i
 else :
  OOOoooooO0oOOoO . append ( oOOOooOo0O + " = " + oo00oO0O0 )
  if 30 - 30: Oo0Ooo + Ii1I % i11iIiiIii * i1IIi + I1IiiI % OOooOOo
  if 30 - 30: i11iIiiIii * Oo0Ooo . II111iiii + I1ii11iIi11i / o0oOOo0O0Ooo % I1Ii111
  if 78 - 78: I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
  if 7 - 7: OOooOOo . IiII . I1Ii111 / Ii1I / Oo0Ooo
  if 83 - 83: I11i / Oo0Ooo
  if 23 - 23: iIii1I11I1II1
 if ( oOOI11I == "lisp user-account" ) :
  Oo000 = commands . getoutput ( "egrep -A4 '{}' ./lisp.config" . format ( OOOoooooO0oOOoO [ 0 ] ) )
  if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
  if 64 - 64: OoO0O00 / I1IiiI
  if ( Oo000 . find ( "super-user = yes" ) != - 1 ) :
   return ( [ { "lisp user-account" : [ { "?" : "found-superuser" } ] } ] )
   if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
   if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
   if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
   if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
   if 8 - 8: o0oOOo0O0Ooo
   if 78 - 78: i1IIi - Oo0Ooo
   if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
 i11iII11I1III = ( "lisp user-account" , "lisp site" , "lisp map-server" ,
 "lisp policy" )
 if 44 - 44: OOooOOo . iIii1I11I1II1 . i11iIiiIii % OoooooooOO . ooOoO0o
 o0o0o = "./lisp.config"
 iii1II11II1 = open ( o0o0o , "r" )
 if 53 - 53: IiII + O0
 IiIIi1IiiIiI = False
 oOo = 0
 for oOO in iii1II11II1 :
  if ( oOO . find ( oOOI11I ) == - 1 ) : continue
  oOo += 1
  if 75 - 75: OoooooooOO
  for oOO in iii1II11II1 :
   if ( lisp_begin_clause ( oOO ) ) : continue
   I1IiII = ( lisp_end_clause ( oOO ) and IiIIi1IiiIiI )
   if ( I1IiII ) : break
   if 85 - 85: I1Ii111 - ooOoO0o - iII111i
   IiIOOo000OOoOO = oOO . replace ( " " , "" )
   IiIOOo000OOoOO = IiIOOo000OOoOO . replace ( "\n" , "" )
   IiIOOo000OOoOO = IiIOOo000OOoOO . replace ( "=" , " = " )
   if 13 - 13: Oo0Ooo
   if ( IiIOOo000OOoOO not in OOOoooooO0oOOoO ) :
    IiIIi1IiiIiI = False
    if ( len ( OOOoooooO0oOOoO ) > 1 ) : break
    continue
    if 70 - 70: iII111i
   IiIIi1IiiIiI = True
   if 51 - 51: O0 - I1ii11iIi11i / I11i * II111iiii + OoO0O00 % I1ii11iIi11i
   I1IiII = ( oOOI11I in i11iII11I1III )
   if ( I1IiII ) : break
   if 58 - 58: oO0o + IiII % iII111i - Ii1I - OOooOOo % Ii1I
   if 86 - 86: o0oOOo0O0Ooo
  if ( I1IiII ) : break
  if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
  if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
 iii1II11II1 . close ( )
 if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
 if ( not IiIIi1IiiIiI ) :
  return ( [ { oOOI11I : [ { "?" : "not-found" } ] } ] )
  if 65 - 65: I1ii11iIi11i / ooOoO0o
  if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
 iii1II11II1 = open ( o0o0o , "r" )
 if 57 - 57: iII111i
 IiIiiIiii = o0o0o + ".temp"
 I11i1 = open ( IiIiiIiii , "w" )
 if 29 - 29: I1IiiI
 if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
 if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
 if 22 - 22: O0 % IiII % iII111i % I1IiiI
 if 34 - 34: iII111i . Oo0Ooo % I1ii11iIi11i . iII111i % IiII / IiII
 IiIIi1IiiIiI = False
 for oOO in iii1II11II1 :
  if ( oOO . find ( oOOI11I ) != - 1 ) : oOo -= 1
  if ( oOo == 0 and not IiIIi1IiiIiI ) :
   if ( oOO [ 0 ] == "}" ) : IiIIi1IiiIiI = True
   continue
   if 84 - 84: Ii1I
  I11i1 . write ( oOO )
  if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
  if 9 - 9: iII111i - iII111i
 I11i1 . close ( )
 iii1II11II1 . close ( )
 if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
 os . system ( "cp {} {}" . format ( IiIiiIiii , o0o0o ) )
 os . system ( "rm {}" . format ( IiIiiIiii ) )
 return ( [ { oOOI11I : [ { "!" : "delete" } ] } ] )
 if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
 if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
 if 41 - 41: I1ii11iIi11i % I1ii11iIi11i + IiII . iII111i % I1Ii111 * ooOoO0o
 if 57 - 57: Ii1I . I1Ii111 . II111iiii % OoooooooOO * O0 + iIii1I11I1II1
 if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
 if 93 - 93: ooOoO0o / OOooOOo * O0
 if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
 if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
 if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
def lisp_u2a_walk_dict_array ( adata , a_dict ) :
 for oOOOooOo0O in a_dict :
  if ( type ( a_dict [ oOOOooOo0O ] ) == dict ) :
   i1II111II1 = { }
   oo00oO0O0 = a_dict [ oOOOooOo0O ]
   for i111iIi11Ii in oo00oO0O0 : i1II111II1 [ i111iIi11Ii . encode ( ) ] = oo00oO0O0 [ i111iIi11Ii ] . encode ( )
   adata [ oOOOooOo0O . encode ( ) ] = i1II111II1
  else :
   adata [ oOOOooOo0O . encode ( ) ] = a_dict [ oOOOooOo0O ] . encode ( )
   if 8 - 8: IiII - I1ii11iIi11i * iIii1I11I1II1 % o0oOOo0O0Ooo / OoooooooOO * o0oOOo0O0Ooo
   if 74 - 74: oO0o % OoO0O00 / iII111i
 return
 if 88 - 88: iII111i * OOooOOo / i11iIiiIii / i1IIi
 if 76 - 76: Ii1I . I11i - OOooOOo + OoOoOO00 * OoO0O00 % I1Ii111
 if 24 - 24: iIii1I11I1II1 % Oo0Ooo % i11iIiiIii
 if 55 - 55: iII111i
 if 19 - 19: OoooooooOO / OOooOOo * i11iIiiIii - I1IiiI
 if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
 if 60 - 60: I1ii11iIi11i
def lisp_unicode_to_ascii ( udata ) :
 oOoOoo0 = ( type ( udata ) == dict )
 if ( oOoOoo0 ) : udata = [ udata ]
 if 4 - 4: oO0o . I11i
 OO0Ooo0O0OOOo = [ ]
 for I111IIi in udata :
  oo0OoOIiI1IIIiI1I1i = { }
  if 84 - 84: OoOoOO00 - I11i
  if ( type ( I111IIi ) == dict ) :
   lisp_u2a_walk_dict_array ( oo0OoOIiI1IIIiI1I1i , I111IIi )
  elif ( type ( I111IIi ) == list ) :
   OoO00O00O0 = [ ]
   for ooOo0o0o00 in I111IIi :
    iIIi1Iii = { }
    lisp_u2a_walk_dict_array ( iIIi1Iii , ooOo0o0o00 )
    OoO00O00O0 . append ( iIIi1Iii )
    if 96 - 96: iII111i % iII111i % I1Ii111 / I1Ii111 - I1ii11iIi11i
   oo0OoOIiI1IIIiI1I1i = OoO00O00O0
  else :
   oo0OoOIiI1IIIiI1I1i = { I111IIi . keys ( ) [ 0 ] . encode ( ) : oo0OoOIiI1IIIiI1I1i }
   if 11 - 11: OOooOOo / OoooooooOO * Ii1I
  OO0Ooo0O0OOOo . append ( oo0OoOIiI1IIIiI1I1i )
  if 73 - 73: I1Ii111 / ooOoO0o + I1Ii111 / OOooOOo / oO0o + OOooOOo
  if 11 - 11: iIii1I11I1II1 * Oo0Ooo % oO0o . ooOoO0o - I1ii11iIi11i * i11iIiiIii
 if ( oOoOoo0 ) : OO0Ooo0O0OOOo = OO0Ooo0O0OOOo [ 0 ]
 return ( OO0Ooo0O0OOOo )
 if 33 - 33: iII111i % OoooooooOO / oO0o
 if 12 - 12: I1ii11iIi11i - iIii1I11I1II1 * OoOoOO00 + o0oOOo0O0Ooo . I11i
 if 59 - 59: iII111i . i1IIi
 if 31 - 31: I1IiiI + I1IiiI
 if 11 - 11: IiII + OoOoOO00 % o0oOOo0O0Ooo * OoO0O00 / IiII
 if 5 - 5: iII111i / oO0o % ooOoO0o . i11iIiiIii % OoOoOO00 + oO0o
 if 95 - 95: I1ii11iIi11i
 if 48 - 48: I11i
 if 14 - 14: iIii1I11I1II1 / o0oOOo0O0Ooo * IiII
 if 35 - 35: iIii1I11I1II1
 if 34 - 34: OoO0O00 % I1IiiI . o0oOOo0O0Ooo % OoO0O00 % OoO0O00
 if 30 - 30: I1IiiI + I1IiiI
def lisp_replace_db_list ( db ) :
 O0OO0O = - 1
 for OOO00o0O in lisp . lisp_db_list :
  if ( db . match_eid_tuple ( OOO00o0O ) ) :
   O0OO0O = lisp . lisp_db_list . index ( OOO00o0O )
   break
   if 18 - 18: ooOoO0o
   if 92 - 92: OoO0O00 % iIii1I11I1II1 / IiII * iII111i . i1IIi + oO0o
 if ( O0OO0O == - 1 ) : return ( False )
 if 24 - 24: IiII . iII111i * IiII % i11iIiiIii . i11iIiiIii + i1IIi
 if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
 if 100 - 100: IiII + i1IIi * OoO0O00
 if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
 if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
 if ( lisp . lisp_nat_traversal and lisp . lisp_i_am_etr ) :
  for Oo0o0ooOoO in OOO00o0O . rloc_set :
   if ( Oo0o0ooOoO . is_rloc_translated ( ) == False ) : continue
   II1iiiiI1 = db . get_rloc_by_interface ( Oo0o0ooOoO . interface )
   if ( II1iiiiI1 == None ) : continue
   II1iiiiI1 . store_translated_rloc ( Oo0o0ooOoO . translated_rloc , Oo0o0ooOoO . translated_port )
   II1iiiiI1 . rloc_name = Oo0o0ooOoO . rloc_name
   if 74 - 74: i1IIi . iIii1I11I1II1
   if 85 - 85: I1IiiI
   if 10 - 10: O0 . II111iiii / OoooooooOO
 lisp . lisp_db_list [ O0OO0O ] = db
 return ( True )
 if 72 - 72: OoooooooOO . o0oOOo0O0Ooo + O0
 if 46 - 46: OoOoOO00 * I11i / oO0o + Oo0Ooo + IiII
 if 95 - 95: o0oOOo0O0Ooo - Ii1I
 if 67 - 67: I1ii11iIi11i * Oo0Ooo % o0oOOo0O0Ooo
 if 19 - 19: OoOoOO00 . OOooOOo . OoooooooOO
 if 79 - 79: OOooOOo * ooOoO0o * I1IiiI * I1ii11iIi11i / I1ii11iIi11i
 if 62 - 62: ooOoO0o * Ii1I % I1ii11iIi11i - i1IIi - I1ii11iIi11i
 if 24 - 24: OOooOOo
def lisp_database_mapping_command ( kv_pair , ephem_port = None ) :
 o0oOoOOO = [ ]
 O0Oo00 = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for o0O00O in range ( len ( kv_pair [ "address" ] ) ) :
   Oo0o0ooOoO = lisp . lisp_rloc ( )
   O0Oo00 . append ( Oo0o0ooOoO )
   if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
   if 19 - 19: IiII % OoooooooOO + OoooooooOO
   if 7 - 7: i1IIi
 O0o0O0O0O = [ ]
 for o0O00O in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  oOoO0oOO = lisp . lisp_mapping ( "" , "" , O0Oo00 )
  O0o0O0O0O . append ( oOoO0oOO )
  if 92 - 92: iII111i . Ii1I
  if 10 - 10: Ii1I + o0oOOo0O0Ooo * IiII / I1ii11iIi11i / oO0o
 for ii1 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ ii1 ]
  if ( ii1 == "mr-name" ) :
   for o0O00O in range ( len ( O0o0O0O0O ) ) :
    oOoO0oOO = O0o0O0O0O [ o0O00O ]
    oOoO0oOO . use_mr_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ o0O00O ]
    if 94 - 94: o0oOOo0O0Ooo - I1IiiI - I11i / Oo0Ooo % OoooooooOO - oO0o
    if 40 - 40: iII111i
  if ( ii1 == "ms-name" ) :
   for o0O00O in range ( len ( O0o0O0O0O ) ) :
    oOoO0oOO = O0o0O0O0O [ o0O00O ]
    oOoO0oOO . use_ms_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ o0O00O ]
    if 76 - 76: i1IIi % I1IiiI / oO0o * IiII % iIii1I11I1II1 - O0
    if 84 - 84: i1IIi
  if ( ii1 == "instance-id" ) :
   for o0O00O in range ( len ( O0o0O0O0O ) ) :
    oOoO0oOO = O0o0O0O0O [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    iI1IIIi11 = [ "0" ] if ( iI1IIIi11 == "" ) else iI1IIIi11 . split ( )
    for OooO00OOooOO in iI1IIIi11 : iI1IIIi11 [ iI1IIIi11 . index ( OooO00OOooOO ) ] = int ( OooO00OOooOO )
    oOoO0oOO . eid . instance_id = iI1IIIi11 [ 0 ]
    oOoO0oOO . eid . iid_list = iI1IIIi11 [ 1 : : ]
    oOoO0oOO . group . instance_id = iI1IIIi11 [ 0 ]
    if 74 - 74: OoooooooOO - i11iIiiIii
    if 42 - 42: I1ii11iIi11i / ooOoO0o . iIii1I11I1II1
  if ( ii1 == "secondary-instance-id" ) :
   for o0O00O in range ( len ( O0o0O0O0O ) ) :
    oOoO0oOO = O0o0O0O0O [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 == "" ) : continue
    oOoO0oOO . secondary_iid = int ( iI1IIIi11 )
    if 5 - 5: OoooooooOO
    if 21 - 21: OOooOOo
  if ( ii1 == "eid-prefix" ) :
   for o0O00O in range ( len ( O0o0O0O0O ) ) :
    oOoO0oOO = O0o0O0O0O [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) : oOoO0oOO . eid . store_prefix ( iI1IIIi11 )
    if 71 - 71: OOooOOo + oO0o . I11i
    if 9 - 9: OoO0O00
  if ( ii1 == "group-prefix" ) :
   for o0O00O in range ( len ( O0o0O0O0O ) ) :
    oOoO0oOO = O0o0O0O0O [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) : oOoO0oOO . group . store_prefix ( iI1IIIi11 )
    if 13 - 13: I11i . OoO0O00
    if 73 - 73: Ii1I * OoooooooOO * I11i - i11iIiiIii
  if ( ii1 == "dynamic-eid" ) :
   for o0O00O in range ( len ( O0o0O0O0O ) ) :
    oOoO0oOO = O0o0O0O0O [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 == "yes" ) : oOoO0oOO . dynamic_eids = { }
    if 58 - 58: o0oOOo0O0Ooo + OoOoOO00 - IiII
    if 82 - 82: Ii1I . iIii1I11I1II1 / Ii1I / oO0o % iIii1I11I1II1
  if ( ii1 == "signature-eid" ) :
   for o0O00O in range ( len ( O0o0O0O0O ) ) :
    oOoO0oOO = O0o0O0O0O [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    oOoO0oOO . signature_eid = ( iI1IIIi11 == "yes" )
    if 34 - 34: OOooOOo
    if 99 - 99: II111iiii
    if 13 - 13: I11i - ooOoO0o + iII111i % I11i . iII111i - i1IIi
  if ( ii1 == "priority" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 == "" ) : iI1IIIi11 = "0"
    Oo0o0ooOoO . priority = int ( iI1IIIi11 )
    if 67 - 67: OOooOOo . i11iIiiIii + ooOoO0o . iIii1I11I1II1
    if 28 - 28: I1IiiI + I1IiiI + I1Ii111
  if ( ii1 == "weight" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 == "" ) : iI1IIIi11 = "0"
    Oo0o0ooOoO . weight = int ( iI1IIIi11 )
    if 22 - 22: I1Ii111
    if 89 - 89: ooOoO0o . OoO0O00 * OoooooooOO + OoOoOO00 / O0
  if ( ii1 == "address" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) : Oo0o0ooOoO . rloc . store_address ( iI1IIIi11 )
    if 60 - 60: I11i
    if 97 - 97: i11iIiiIii * iIii1I11I1II1 / II111iiii
  if ( ii1 == "interface" ) :
   ii11 = lisp . lisp_hostname
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) :
     Oo0o0ooOoO . interface = iI1IIIi11
     II = lisp . lisp_get_interface_address ( iI1IIIi11 )
     if ( II ) :
      Oo0o0ooOoO . rloc . copy_address ( II )
      lisp . lisp_myrlocs [ 0 ] = II
      if 66 - 66: II111iiii + iII111i * oO0o % I11i / i1IIi / iIii1I11I1II1
     Oo0o0ooOoO . rloc_name = ii11
     o0oOoOOO . append ( Oo0o0ooOoO )
     if 62 - 62: OoOoOO00 + oO0o * IiII + O0 / OOooOOo + ooOoO0o
     if 38 - 38: i1IIi / iIii1I11I1II1 + iII111i
     if 26 - 26: I1ii11iIi11i . Ii1I % o0oOOo0O0Ooo
  if ( ii1 == "elp-name" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) : Oo0o0ooOoO . elp_name = iI1IIIi11
    if 4 - 4: I1Ii111
    if 80 - 80: Oo0Ooo . O0 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if ( ii1 == "rle-name" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) : Oo0o0ooOoO . rle_name = iI1IIIi11
    if 52 - 52: OoO0O00 % i11iIiiIii . ooOoO0o % OoOoOO00 % OoooooooOO
    if 5 - 5: OoOoOO00 / O0 / i11iIiiIii
  if ( ii1 == "json-name" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) : Oo0o0ooOoO . json_name = iI1IIIi11
    if 88 - 88: II111iiii - iII111i / OoooooooOO
    if 71 - 71: I1ii11iIi11i
  if ( ii1 == "geo-name" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) : Oo0o0ooOoO . geo_name = iI1IIIi11
    if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
    if 1 - 1: IiII % i1IIi
  if ( ii1 == "rloc-record-name" ) :
   for o0O00O in range ( len ( O0Oo00 ) ) :
    Oo0o0ooOoO = O0Oo00 [ o0O00O ]
    iI1IIIi11 = oo00oO0O0 [ o0O00O ]
    if ( iI1IIIi11 != "" ) : Oo0o0ooOoO . rloc_name = iI1IIIi11
    if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
    if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
    if 80 - 80: I1ii11iIi11i
    if 67 - 67: II111iiii
    if 2 - 2: o0oOOo0O0Ooo - O0 * Ii1I % IiII
    if 64 - 64: i1IIi . ooOoO0o
    if 7 - 7: oO0o . iII111i - iII111i / I1Ii111 % Oo0Ooo
    if 61 - 61: oO0o - I1ii11iIi11i / iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
    if 10 - 10: i11iIiiIii / OoOoOO00
    if 27 - 27: I1IiiI / OoooooooOO
 if ( len ( o0oOoOOO ) > 1 ) :
  for Oo0o0ooOoO in o0oOoOOO :
   Oo0o0ooOoO . rloc_name = ii11 + "-" + Oo0o0ooOoO . interface
   if 74 - 74: I1ii11iIi11i % I1Ii111 - OoO0O00 * I11i . OoooooooOO * OoO0O00
   if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
   if 6 - 6: OOooOOo
   if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
   if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
   if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
 for oOoO0oOO in O0o0O0O0O :
  oOoO0oOO . rloc_set = copy . deepcopy ( oOoO0oOO . rloc_set )
  oOoO0oOO . sort_rloc_set ( )
  oOoO0oOO . add_db ( )
  if ( lisp_replace_db_list ( oOoO0oOO ) ) : continue
  lisp . lisp_db_list . append ( oOoO0oOO )
  if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
  if 44 - 44: OoooooooOO
  if 82 - 82: OoOoOO00 . OoOoOO00
  if 10 - 10: Oo0Ooo * I1ii11iIi11i . oO0o . OoooooooOO . OOooOOo * I1ii11iIi11i
  if 80 - 80: I1Ii111 + I11i . I1Ii111 + OOooOOo
 lisp . lisp_write_ipc_database_mappings ( ephem_port )
 if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
 if 43 - 43: IiII . OoooooooOO - II111iiii
 if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
 if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
 if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
 if 15 - 15: Ii1I + OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
 if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
 lisp . lisp_default_iid = lisp . lisp_db_list [ 0 ] . eid . instance_id
 if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
 if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
 if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
 if 28 - 28: iIii1I11I1II1 . O0
 if 32 - 32: OoooooooOO
 if 29 - 29: I1ii11iIi11i
 if 41 - 41: Ii1I
 if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
 for oOoO0oOO in O0o0O0O0O :
  if ( oOoO0oOO . eid . address == 0 and oOoO0oOO . eid . mask_len == 0 ) :
   if ( oOoO0oOO . eid . is_ipv4 ( ) or oOoO0oOO . eid . is_ipv6 ( ) ) :
    lisp . lisp_pitr = True
    break
    if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
    if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
    if 94 - 94: IiII / I1IiiI . II111iiii
  if ( oOoO0oOO . dynamic_eids == None ) : continue
  if ( oOoO0oOO . eid . is_mac ( ) and oOoO0oOO . eid . address == 0 and oOoO0oOO . eid . mask_len == 0 ) :
   lisp . lisp_l2_overlay = True
   break
   if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
   if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
   if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
   if 49 - 49: I1ii11iIi11i
   if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
   if 18 - 18: Oo0Ooo + IiII
   if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
   if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
 i11i = ( lisp . lisp_myrlocs [ 0 ] != None )
 lisp . lisp_get_local_addresses ( )
 if 14 - 14: Ii1I + Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
 if ( lisp . lisp_myrlocs [ 0 ] == None and i11i ) :
  lisp . lprint ( "No RLOCs found, local addresses changed from RLOC to EID" )
  if 61 - 61: OOooOOo . OOooOOo
  if 17 - 17: II111iiii / ooOoO0o
  if 80 - 80: OOooOOo * OoO0O00 + Ii1I
  if 62 - 62: OoooooooOO . O0 % Oo0Ooo
  if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
  if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
  if 88 - 88: I1Ii111 - OoO0O00
  if 79 - 79: iII111i
  if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
  if 48 - 48: I1ii11iIi11i + Oo0Ooo
  if 76 - 76: I1ii11iIi11i
  if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
  if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
  if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
  if 82 - 82: OoO0O00
  if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
  if 17 - 17: OoOoOO00
  if 72 - 72: iII111i . Oo0Ooo - i11iIiiIii / I1IiiI
  if 64 - 64: oO0o
  if 80 - 80: o0oOOo0O0Ooo % iIii1I11I1II1
  if 63 - 63: IiII * i11iIiiIii
 if ( lisp . lisp_program_hardware == False ) : return
 if 86 - 86: I11i % I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
 IiIIi1IiiIiI = False
 for oOoO0oOO in O0o0O0O0O :
  if ( oOoO0oOO . dynamic_eids == None ) : continue
  IiI1iIIiIi1Ii = oOoO0oOO . eid . print_prefix_no_iid ( )
  IiIIi1IiiIiI = lisp . lisp_i_am_itr
  os . system ( "ip route add {} dev ma1" . format ( IiI1iIIiIi1Ii ) )
  if 69 - 69: OOooOOo % I1ii11iIi11i / OoOoOO00 . OOooOOo - IiII
 if ( lisp . lisp_program_hardware and IiIIi1IiiIiI ) :
  Oo00OoOo = "platform trident diag s cpu_control_1 URPF_MISS_TOCPU=1"
  lisp . lisp_send_to_arista ( Oo00OoOo , None )
  if 74 - 74: OoO0O00 - o0oOOo0O0Ooo - IiII . O0 % ooOoO0o
  if 32 - 32: OoOoOO00 . OoO0O00 / Oo0Ooo . i11iIiiIii
  if 9 - 9: I11i - II111iiii + I1Ii111 / oO0o % I1ii11iIi11i
  if 17 - 17: iIii1I11I1II1 - ooOoO0o
  if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if 52 - 52: I1ii11iIi11i
  if 93 - 93: iII111i . i11iIiiIii
  if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
def lisp_show_db_list ( itr_or_etr , output ) :
 I1I1i1 = "{} database-mapping entries" . format ( len ( lisp . lisp_db_list ) )
 IIIiiiiiI1I = "LISP-{} Configured Database Mappings:" . format ( itr_or_etr )
 IIIiiiiiI1I = lisp . lisp_span ( IIIiiiiiI1I , I1I1i1 )
 if 49 - 49: O0 . Oo0Ooo / Ii1I
 I1I1 = '<a href="/lisp/show/etr/keys"><br>RLOC Keys</a>'
 if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
 if ( itr_or_etr == "ITR" ) :
  output += lisp_table_header ( IIIiiiiiI1I , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Use MR" )
 else :
  output += lisp_table_header ( IIIiiiiiI1I , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" + I1I1 , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Receive Stats" ,
 "Map-Replies<br>Sent" , "Use MS" )
  if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
  if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
 for oOoO0oOO in lisp . lisp_db_list :
  i1 = lisp . lisp_print_elapsed ( oOoO0oOO . uptime )
  IIiiI1iii1 = oOoO0oOO . map_replies_sent
  if 100 - 100: iII111i / o0oOOo0O0Ooo
  if 11 - 11: I1ii11iIi11i * OoOoOO00 % i11iIiiIii - Ii1I
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . I1ii11iIi11i
  if 63 - 63: oO0o
  OOOOoO0O = ""
  if ( oOoO0oOO . dynamic_eid_configured ( ) ) :
   o0iI1iIi1i11I1 = oOoO0oOO . eid . print_prefix_url ( )
   o00O = len ( oOoO0oOO . dynamic_eids )
   ii1I1I111 = itr_or_etr . lower ( )
   OOOOoO0O = ( "<br><a href='/lisp/show/{}/dynamic-eid/{}'>" + "{} dynamic-eids</a>" ) . format ( ii1I1I111 , o0iI1iIi1i11I1 , o00O )
   if 64 - 64: OoooooooOO % ooOoO0o . i11iIiiIii - I1Ii111
   if 90 - 90: O0 . I1IiiI + I1IiiI
   if 96 - 96: I11i + iIii1I11I1II1 % II111iiii
  O00 = True
  for Oo0o0ooOoO in oOoO0oOO . rloc_set :
   if ( O00 ) :
    oO0Ooo0OO = oOoO0oOO . print_eid_tuple ( )
    oO0Ooo0OO = oOoO0oOO . star_secondary_iid ( oO0Ooo0OO )
    oO0Ooo0OO += OOOOoO0O
    Oo000o = i1
    O00 = False
   else :
    oO0Ooo0OO , Oo000o , IIiiI1iii1 = ( "" , "" , "" )
    if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
    if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
   O0oo0ooo0 = "" if Oo0o0ooOoO . rloc . is_null ( ) else Oo0o0ooOoO . rloc . print_address_no_iid ( )
   if 7 - 7: IiII * ooOoO0o + OoOoOO00
   if 22 - 22: iII111i
   if ( Oo0o0ooOoO . interface != None ) :
    O0oo0ooo0 += " ({})" . format ( Oo0o0ooOoO . interface )
    if 48 - 48: I1ii11iIi11i . I1IiiI
   if ( O0oo0ooo0 != "" ) : O0oo0ooo0 += "<br>"
   if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
   if ( Oo0o0ooOoO . translated_rloc . not_set ( ) == False ) :
    O0oo0ooo0 += "translated RLOC: {}<br>" . format ( Oo0o0ooOoO . translated_rloc . print_address_no_iid ( ) )
    if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
    if 49 - 49: Oo0Ooo
    if 57 - 57: O0 * ooOoO0o - iII111i - iIii1I11I1II1 * iII111i
   i1o0oOoooOoo0 = Oo0o0ooOoO . print_rloc_name ( True )
   if ( i1o0oOoooOoo0 != "" ) : O0oo0ooo0 += i1o0oOoooOoo0 + "<br>"
   if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
   if ( Oo0o0ooOoO . geo_name != None ) :
    O0oo0ooo0 += "geo: " + Oo0o0ooOoO . geo_name + "<br>"
    if 57 - 57: I1ii11iIi11i - OoO0O00 * iIii1I11I1II1
   if ( Oo0o0ooOoO . elp_name != None ) :
    O0oo0ooo0 += "elp: " + Oo0o0ooOoO . elp_name + "<br>"
    if 26 - 26: OoO0O00 % ooOoO0o % o0oOOo0O0Ooo % OoOoOO00 . iII111i % O0
   if ( Oo0o0ooOoO . rle_name != None ) :
    O0oo0ooo0 += "rle: " + Oo0o0ooOoO . rle_name + "<br>"
    if 91 - 91: II111iiii . Oo0Ooo . oO0o - OoooooooOO / OoOoOO00
   if ( Oo0o0ooOoO . json_name != None ) :
    O0oo0ooo0 += "json: " + Oo0o0ooOoO . json_name + "<br>"
    if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
    if 55 - 55: OoO0O00
   if ( itr_or_etr == "ITR" ) :
    output += lisp_table_row ( oO0Ooo0OO , Oo000o , O0oo0ooo0 ,
 str ( Oo0o0ooOoO . priority ) + "/" + str ( Oo0o0ooOoO . weight ) ,
 str ( Oo0o0ooOoO . mpriority ) + "/" + str ( Oo0o0ooOoO . mweight ) ,
 oOoO0oOO . use_mr_name )
   else :
    ii1111I = Oo0o0ooOoO . stats . get_stats ( True , True )
    output += lisp_table_row ( oO0Ooo0OO , Oo000o , O0oo0ooo0 ,
 str ( Oo0o0ooOoO . priority ) + "/" + str ( Oo0o0ooOoO . weight ) ,
 str ( Oo0o0ooOoO . mpriority ) + "/" + str ( Oo0o0ooOoO . mweight ) , ii1111I ,
 IIiiI1iii1 , oOoO0oOO . use_ms_name )
    if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
    if 32 - 32: Ii1I * oO0o
    if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
 output += lisp_table_footer ( )
 if 28 - 28: Oo0Ooo
 if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
 if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
 if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
 if ( len ( lisp . lisp_geo_list ) != 0 ) :
  IIIiiiiiI1I = "Configured Geo-Coordinates:"
  output += lisp_table_header ( IIIiiiiiI1I , "Geo Name" ,
 "Geo-Prefix or Geo-Point" )
  ooo0Oo000o = sorted ( lisp . lisp_geo_list )
  for OO in ooo0Oo000o :
   oo0OoO = lisp . lisp_geo_list [ OO ]
   output += lisp_table_row ( OO , oo0OoO . print_geo_url ( ) )
   if 18 - 18: O0
  output += lisp_table_footer ( )
  if 14 - 14: Ii1I / IiII - O0
 return ( output )
 if 16 - 16: I1Ii111 % iIii1I11I1II1 . i1IIi
 if 72 - 72: ooOoO0o * OOooOOo
 if 69 - 69: oO0o - i11iIiiIii
 if 29 - 29: Ii1I + iII111i % I1ii11iIi11i + I11i * Oo0Ooo - i11iIiiIii
 if 24 - 24: i11iIiiIii . ooOoO0o + ooOoO0o - i11iIiiIii % OOooOOo
 if 58 - 58: I1IiiI
 if 94 - 94: o0oOOo0O0Ooo + Ii1I % o0oOOo0O0Ooo . I1Ii111 - ooOoO0o * I1IiiI
def lisp_interface_command ( kv_pair ) :
 OO0oOOoOoo0OO = None
 o00oO0O = None
 IIi1OOoO0OooO = None
 Iii = None
 OoiiiIiii11i1i = None
 ooo0O0Oo0O = None
 Oo0o = None
 i1i = None
 if 68 - 68: OoOoOO00 * ooOoO0o % ooOoO0o - IiII + O0 * I1ii11iIi11i
 for ii1 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ ii1 ]
  if ( ii1 == "interface-name" ) : OO0oOOoOoo0OO = oo00oO0O0
  if ( ii1 == "device" ) : o00oO0O = oo00oO0O0
  if ( ii1 == "instance-id" ) : IIi1OOoO0OooO = oo00oO0O0
  if ( ii1 == "dynamic-eid" ) : Iii = oo00oO0O0
  if ( ii1 == "multi-tenant-eid" ) : Oo0o = oo00oO0O0
  if ( ii1 == "dynamic-eid-device" ) : OoiiiIiii11i1i = oo00oO0O0
  if ( ii1 == "dynamic-eid-timeout" ) : ooo0O0Oo0O = oo00oO0O0
  if ( ii1 == "lisp-nat" ) : i1i = ( oo00oO0O0 == "yes" )
  if 60 - 60: i11iIiiIii / i1IIi * OOooOOo
  if 89 - 89: iIii1I11I1II1 * o0oOOo0O0Ooo + OoOoOO00 . i11iIiiIii + I1ii11iIi11i
 if ( o00oO0O == None ) : return
 if 1 - 1: I1IiiI . I11i . I1ii11iIi11i
 if 19 - 19: O0 * I11i % OoooooooOO
 if 36 - 36: o0oOOo0O0Ooo % I11i * I1ii11iIi11i % Ii1I + i1IIi - Oo0Ooo
 if 56 - 56: I1ii11iIi11i
 if 32 - 32: OoOoOO00 % O0 % i11iIiiIii - ooOoO0o . I1IiiI
 if 24 - 24: oO0o % o0oOOo0O0Ooo / I1Ii111 + o0oOOo0O0Ooo
 if 59 - 59: II111iiii % I1IiiI * O0 . OoooooooOO - OoooooooOO % O0
 if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
 if ( lisp . lisp_myinterfaces . has_key ( o00oO0O ) and Oo0o == None ) :
  iii1I = lisp . lisp_myinterfaces [ o00oO0O ]
 else :
  iii1I = lisp . lisp_interface ( o00oO0O )
  lisp . lisp_myinterfaces [ o00oO0O ] = iii1I
  if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
  if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
  if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
  if 10 - 10: II111iiii . OOooOOo / iII111i
  if 35 - 35: iII111i / Oo0Ooo + O0 * iIii1I11I1II1 - O0
 iii1I . interface_name = OO0oOOoOoo0OO
 if ( IIi1OOoO0OooO != None ) :
  if ( IIi1OOoO0OooO . isdigit ( ) == False ) : IIi1OOoO0OooO = "0"
  iii1I . instance_id = int ( IIi1OOoO0OooO )
  if 3 - 3: I1ii11iIi11i
 if ( Iii != None ) :
  iii1I . dynamic_eid . store_prefix ( Iii )
  iii1I . dynamic_eid . instance_id = iii1I . instance_id
  if 42 - 42: I11i % Oo0Ooo + IiII - I11i . iIii1I11I1II1 - Ii1I
 if ( OoiiiIiii11i1i != None ) :
  iii1I . dynamic_eid_device = OoiiiIiii11i1i
  if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
 if ( ooo0O0Oo0O != None ) :
  iii1I . dynamic_eid_timeout = int ( ooo0O0Oo0O )
  if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
 if ( Oo0o != None ) :
  iii1I . multi_tenant_eid . store_prefix ( Oo0o )
  iii1I . multi_tenant_eid . instance_id = int ( iii1I . instance_id )
  lisp . lisp_multi_tenant_interfaces . append ( iii1I )
  if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
 if ( i1i ) :
  o00OooO = "sudo iptables -t nat -C POSTROUTING -o {} -j MASQUERADE"
  if ( commands . getoutput ( o00OooO . format ( o00oO0O ) ) != "" ) :
   IIiii1 = lisp . lisp_get_loopback_address ( )
   if ( IIiii1 ) :
    iiI = "sudo iptables -t nat -A POSTROUTING -s {} -j ACCEPT"
    os . system ( iiI . format ( IIiii1 ) )
    if 14 - 14: OOooOOo + II111iiii % OOooOOo . oO0o * ooOoO0o
   iiI = "sudo iptables -t nat -A POSTROUTING -o {} -j MASQUERADE"
   os . system ( iiI . format ( o00oO0O ) )
   os . system ( "sudo sysctl net.ipv4.ip_forward=1" )
   if 54 - 54: ooOoO0o * I11i - I1Ii111
   if 15 - 15: iII111i / O0
   if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
 lisp . lisp_iid_to_interface [ IIi1OOoO0OooO ] = iii1I
 if 19 - 19: o0oOOo0O0Ooo . II111iiii / i1IIi
 if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
 if 47 - 47: I1ii11iIi11i * I1IiiI / I1ii11iIi11i + Ii1I * II111iiii
 if 78 - 78: I1Ii111 - i1IIi + OoOoOO00 + Oo0Ooo * I1ii11iIi11i * o0oOOo0O0Ooo
 if 97 - 97: i1IIi
 if ( "SO_BINDTODEVICE" in dir ( socket ) ) : iii1I . set_socket ( o00oO0O )
 if ( "PF_PACKET" in dir ( socket ) ) : iii1I . set_bridge_socket ( o00oO0O )
 if 29 - 29: I1IiiI
 if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
 if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
 if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
 lisp . lisp_get_local_addresses ( )
 if 59 - 59: I1Ii111 * iII111i
 if 31 - 31: I11i / O0
 if 57 - 57: i1IIi % ooOoO0o
 if 69 - 69: o0oOOo0O0Ooo
 if 69 - 69: I1Ii111
 if 83 - 83: iIii1I11I1II1 . o0oOOo0O0Ooo + I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
 if ( Iii != None and lisp . lisp_program_hardware ) :
  Oo00OoOo = "ip verify unicast source reachable-via rx"
  lisp . lisp_send_to_arista ( Oo00OoOo , o00oO0O )
  Oo00OoOo = 'sysctl -w "net.ipv4.conf.{}.rp_filter=0"' . format ( o00oO0O )
  os . system ( Oo00OoOo )
  if 90 - 90: Ii1I * iII111i / OOooOOo
  if 68 - 68: OoOoOO00
  if 65 - 65: oO0o
  if 82 - 82: o0oOOo0O0Ooo
  if 80 - 80: i1IIi % OoOoOO00 + OoO0O00 - OoooooooOO / iIii1I11I1II1 + I1Ii111
 lisp . lisp_write_ipc_interfaces ( )
 return
 if 65 - 65: Ii1I
 if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
 if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
 if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
 if 78 - 78: oO0o % OoooooooOO
 if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
 if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
 if 37 - 37: IiII % Ii1I % i1IIi
def lisp_parse_eid_in_url ( command , eid_prefix ) :
 I11iiI1i1 = ""
 if 23 - 23: ooOoO0o - O0 + i11iIiiIii
 if 98 - 98: OoooooooOO
 if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
 if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
 if ( eid_prefix == "0--0" ) :
  command = command + "%[0]/0%"
 elif ( eid_prefix . find ( "-name-" ) != - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if ( len ( eid_prefix ) > 4 ) :
   eid_prefix = [ eid_prefix [ 0 ] , "name" , "-" . join ( eid_prefix [ 2 : - 1 ] ) ,
 eid_prefix [ - 1 ] ]
   if 71 - 71: Ii1I * OoOoOO00
   if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
   if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
   if 87 - 87: OoO0O00 * Oo0Ooo
   if 83 - 83: i1IIi * I1Ii111 - IiII / Ii1I
  OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]'" + eid_prefix [ 2 ] + "'" + "/" + eid_prefix [ 3 ]
  if 48 - 48: oO0o . II111iiii - OoOoOO00 % i1IIi . OoOoOO00
  command = command + "%" + OOOO0oo0 + "%"
 elif ( eid_prefix . count ( "-" ) in [ 9 , 10 ] ) :
  if 32 - 32: Ii1I * I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
  if 67 - 67: OoOoOO00 % Oo0Ooo
  if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
  if 73 - 73: I1ii11iIi11i
  eid_prefix = eid_prefix . split ( "-" )
  OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + "-" . join ( eid_prefix [ 1 : - 1 ] ) + "/" + eid_prefix [ - 1 ]
  if 92 - 92: i11iIiiIii + O0 * I11i
  command = command + "%" + OOOO0oo0 + "%"
 elif ( eid_prefix . find ( "." ) == - 1 and eid_prefix . find ( ":" ) == - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if 60 - 60: o0oOOo0O0Ooo / Oo0Ooo
  if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
  if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
  if 76 - 76: OoO0O00 * oO0o - OoO0O00
  if ( eid_prefix [ 1 ] == "plus" ) :
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]+" + eid_prefix [ 2 ] + "/" + eid_prefix [ 3 ]
   if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
   command = command + "%" + OOOO0oo0 + "%"
  else :
   if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
   if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
   if 70 - 70: O0 . Ii1I
   if 33 - 33: OOooOOo * Ii1I
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "-" + eid_prefix [ 2 ] + "-" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 64 - 64: i11iIiiIii . iIii1I11I1II1
   if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
   if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
   if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
   if 70 - 70: I11i . I1ii11iIi11i * oO0o
   if ( len ( eid_prefix ) == 10 ) :
    I11iiI1i1 = "[" + eid_prefix [ 5 ] + "]" + eid_prefix [ 6 ] + "-" + eid_prefix [ 7 ] + "-" + eid_prefix [ 8 ] + "/" + eid_prefix [ 9 ]
    if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
    command = command + "%" + OOOO0oo0 + "%" + I11iiI1i1
   else :
    command = command + "%" + OOOO0oo0 + "%"
    if 23 - 23: I1ii11iIi11i % I11i
    if 18 - 18: OoooooooOO . i1IIi + II111iiii
    if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
 else :
  if 34 - 34: I1Ii111 * I11i
  if 31 - 31: IiII . oO0o
  if 40 - 40: Ii1I - I11i / II111iiii * i1IIi + IiII * II111iiii
  if 53 - 53: I1ii11iIi11i - i11iIiiIii . OoO0O00 / OoOoOO00 - I1Ii111
  eid_prefix = eid_prefix . split ( "-" )
  if ( eid_prefix [ 1 ] == "*" ) :
   OOOO0oo0 = ""
   I11iiI1i1 = "[" + eid_prefix [ 2 ] + "]" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 99 - 99: Ii1I - IiII - i1IIi / i11iIiiIii . IiII
  else :
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "/" + eid_prefix [ 2 ]
   if 58 - 58: OOooOOo
   if ( len ( eid_prefix ) == 6 ) :
    I11iiI1i1 = "[" + eid_prefix [ 3 ] + "]" + eid_prefix [ 4 ] + "/" + eid_prefix [ 5 ]
    if 12 - 12: I1IiiI . o0oOOo0O0Ooo * OoooooooOO
    if 64 - 64: OoOoOO00 + IiII - i1IIi . II111iiii . OoO0O00
    if 31 - 31: oO0o . iII111i - I11i . iIii1I11I1II1 + I11i . OoOoOO00
  command = command + "%" + OOOO0oo0 + "%" + I11iiI1i1
  if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
 return ( command )
 if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
 if 30 - 30: OoooooooOO % OOooOOo
 if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
 if 81 - 81: iII111i % Ii1I . ooOoO0o
 if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
 if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
 if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
def lisp_show_dynamic_eid_command ( parm ) :
 i1iiI11I = ""
 if ( parm == "" ) : return ( i1iiI11I )
 if 20 - 20: ooOoO0o
 Ooo000 = lisp_get_lookup_string ( parm . split ( "%" ) [ 0 ] )
 Ooo000 = Ooo000 [ 0 ]
 if 63 - 63: iIii1I11I1II1 . OoO0O00
 oOoO0oOO = lisp . lisp_db_for_lookups . lookup_cache ( Ooo000 , False )
 if ( oOoO0oOO == None ) : return ( i1iiI11I )
 if 100 - 100: i1IIi * i1IIi
 ii1I1I111 = "ITR" if lisp . lisp_i_am_itr else "ETR"
 OOOO0oo0 = oOoO0oOO . print_eid_tuple ( )
 if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
 IIIiiiiiI1I = "LISP-{} Discovered Dynamic EIDs for {}:" . format ( ii1I1I111 , OOOO0oo0 )
 if 94 - 94: IiII
 if ( ii1I1I111 == "ITR" ) :
  i1iiI11I = lisp_table_header ( IIIiiiiiI1I , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Last Packet" , "Inactivity Timeout" )
 else :
  i1iiI11I = lisp_table_header ( IIIiiiiiI1I , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Inactivity Timeout" )
  if 15 - 15: Ii1I - IiII / O0
  if 28 - 28: I1Ii111 . i1IIi / I1ii11iIi11i
 for IiI1iIIiIi1Ii in oOoO0oOO . dynamic_eids . values ( ) :
  Ooo000 = IiI1iIIiIi1Ii . dynamic_eid . print_address ( )
  Ooo0 = lisp . lisp_print_elapsed ( IiI1iIIiIi1Ii . uptime )
  oO00000o = str ( IiI1iIIiIi1Ii . timeout ) + " secs"
  if ( ii1I1I111 == "ITR" ) :
   i1io00o0O0o0O0 = lisp . lisp_print_elapsed ( IiI1iIIiIi1Ii . last_packet )
   i1iiI11I += lisp_table_row ( Ooo000 , IiI1iIIiIi1Ii . interface , Ooo0 , i1io00o0O0o0O0 , oO00000o )
  else :
   i1iiI11I += lisp_table_row ( Ooo000 , IiI1iIIiIi1Ii . interface , Ooo0 , oO00000o )
   if 33 - 33: Ii1I . oO0o
   if 87 - 87: Oo0Ooo . o0oOOo0O0Ooo - OoooooooOO * oO0o % IiII + O0
 i1iiI11I += lisp_table_footer ( )
 return ( i1iiI11I )
 if 16 - 16: I1ii11iIi11i % Oo0Ooo % II111iiii % II111iiii
 if 51 - 51: OoOoOO00 * OoOoOO00 - O0 % iIii1I11I1II1 / O0
 if 5 - 5: i11iIiiIii * ooOoO0o % iII111i - I11i
 if 5 - 5: O0 * IiII * OOooOOo + I1Ii111 % Oo0Ooo - I1ii11iIi11i
 if 62 - 62: I1ii11iIi11i + I11i
 if 90 - 90: iIii1I11I1II1
 if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
def lisp_clear_decap_stats ( command ) :
 oO000oOo0oO0 = command . split ( "%" ) [ 1 ]
 lisp . lisp_decap_stats [ oO000oOo0oO0 ] = lisp . lisp_stats ( )
 if 2 - 2: o0oOOo0O0Ooo - I1IiiI - i11iIiiIii / OoooooooOO
 if 87 - 87: o0oOOo0O0Ooo + oO0o + OoooooooOO * OOooOOo
 if 50 - 50: Oo0Ooo * i1IIi - I1ii11iIi11i * I1IiiI
 if 24 - 24: OoOoOO00 * Ii1I
 if 17 - 17: OoO0O00 . I1IiiI * O0
 if 81 - 81: OOooOOo
 if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
def lisp_show_decap_stats ( output , etr_or_rtr ) :
 i1iI11I = etr_or_rtr . upper ( )
 I11IiI1I11i1i = etr_or_rtr . lower ( )
 if 96 - 96: Oo0Ooo
 o00oOOO0Ooo = [ ]
 for oOOOooOo0O in lisp . lisp_decap_stats :
  iIIiiiI1 = "<a href='/lisp/clear/{}/stats/{}'>{}</a>" . format ( I11IiI1I11i1i , oOOOooOo0O , oOOOooOo0O )
  o00oOOO0Ooo . append ( iIIiiiI1 )
  if 5 - 5: IiII - I11i
  if 16 - 16: IiII . iII111i . Oo0Ooo % OOooOOo / IiII
 OOO0oo0ooOoo = "LISP-{} Decapsulation Stats:" . format ( i1iI11I )
 output += lisp_table_header ( OOO0oo0ooOoo , * o00oOOO0Ooo )
 if 31 - 31: iII111i
 o00oOOO0Ooo = [ ]
 for I11I in lisp . lisp_decap_stats . values ( ) :
  o00oOOO0Ooo . append ( I11I . get_stats ( False , True ) )
  if 64 - 64: o0oOOo0O0Ooo % ooOoO0o % oO0o
 output += lisp_table_row ( * o00oOOO0Ooo )
 output += lisp_table_footer ( )
 return ( output )
 if 29 - 29: Ii1I % OoO0O00 . II111iiii . oO0o / OoO0O00 % iIii1I11I1II1
 if 8 - 8: O0 / II111iiii
 if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
 if 87 - 87: IiII
 if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
 if 55 - 55: IiII
 if 43 - 43: OOooOOo
 if 17 - 17: i11iIiiIii
def lisp_show_crypto_list ( xtr ) :
 i1iiI11I = ""
 OoO0oOoo = len ( lisp . lisp_crypto_keys_by_nonce ) != 0
 if 25 - 25: I11i / I1ii11iIi11i * OoO0O00 . iII111i
 if ( lisp . lisp_i_am_itr or lisp . lisp_i_am_rtr ) :
  if ( OoO0oOoo ) :
   IIIiiiiiI1I = "LISP-{} Nonce Crypto State" . format ( xtr )
   i1iiI11I += lisp_table_header ( IIIiiiiiI1I , "Nonce" , "Uptime" , "Key-ID" ,
 "Key Material" )
   for oOOOooOo0O in lisp . lisp_crypto_keys_by_nonce :
    iI111iIi = "0x" + lisp . lisp_hex_string ( oOOOooOo0O )
    oo00oO0O0 = lisp . lisp_crypto_keys_by_nonce [ oOOOooOo0O ]
    for IiIII1111iI in oo00oO0O0 :
     if ( IiIII1111iI == None ) : continue
     O000o0O0 = lisp . lisp_print_elapsed ( IiIII1111iI . uptime )
     I1I1 = IiIII1111iI . print_keys ( False )
     i1iiI11I += lisp_table_row ( iI111iIi , O000o0O0 , IiIII1111iI . key_id , I1I1 )
     iI111iIi = ""
     if 51 - 51: ooOoO0o * Ii1I * OoooooooOO % OoOoOO00
     if 25 - 25: iIii1I11I1II1 * OoooooooOO * Ii1I - i1IIi
   i1iiI11I += lisp_table_footer ( )
   if 23 - 23: o0oOOo0O0Ooo . ooOoO0o - OoooooooOO + I11i
   if 73 - 73: OoOoOO00
  IIIiiiiiI1I = "LISP-{} Encapsulation Crypto State" . format ( xtr )
  i1iiI11I += lisp_table_header ( IIIiiiiiI1I , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for oOOOooOo0O in lisp . lisp_crypto_keys_by_rloc_encap :
   iI111iIi = oOOOooOo0O
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_encap [ oOOOooOo0O ]
   for IiIII1111iI in oo00oO0O0 :
    if ( IiIII1111iI == None ) : continue
    O000o0O0 = lisp . lisp_print_elapsed ( IiIII1111iI . uptime )
    Oo0OOOOOOOo0O = lisp . lisp_print_elapsed ( IiIII1111iI . last_rekey )
    I1I1 = IiIII1111iI . print_keys ( False )
    i1iiI11I += lisp_table_row ( iI111iIi , O000o0O0 , Oo0OOOOOOOo0O , IiIII1111iI . rekey_count ,
 IiIII1111iI . use_count , IiIII1111iI . key_id , I1I1 )
    iI111iIi = ""
    if 11 - 11: Ii1I / OoOoOO00 - OoO0O00 + OoOoOO00
    if 51 - 51: ooOoO0o
  i1iiI11I += lisp_table_footer ( )
  if 42 - 42: o0oOOo0O0Ooo - OOooOOo / OOooOOo / iII111i * Oo0Ooo . Oo0Ooo
  if 96 - 96: OoooooooOO + I1ii11iIi11i * O0
 if ( lisp . lisp_i_am_etr or lisp . lisp_i_am_rtr ) :
  IIIiiiiiI1I = "LISP-{} Decapsulation Crypto State" . format ( xtr )
  i1iiI11I += lisp_table_header ( IIIiiiiiI1I , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for oOOOooOo0O in lisp . lisp_crypto_keys_by_rloc_decap :
   iI111iIi = oOOOooOo0O
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_decap [ oOOOooOo0O ]
   for IiIII1111iI in oo00oO0O0 :
    if ( IiIII1111iI == None ) : continue
    O000o0O0 = lisp . lisp_print_elapsed ( IiIII1111iI . uptime )
    Oo0OOOOOOOo0O = lisp . lisp_print_elapsed ( IiIII1111iI . last_rekey )
    I1I1 = IiIII1111iI . print_keys ( False )
    i1iiI11I += lisp_table_row ( iI111iIi , O000o0O0 , Oo0OOOOOOOo0O , IiIII1111iI . rekey_count ,
 IiIII1111iI . use_count , IiIII1111iI . key_id , I1I1 )
    iI111iIi = ""
    if 33 - 33: I1ii11iIi11i - IiII
    if 17 - 17: OOooOOo - oO0o
  i1iiI11I += lisp_table_footer ( )
  if 1 - 1: iIii1I11I1II1 / i11iIiiIii * II111iiii
 return ( i1iiI11I )
 if 48 - 48: I1ii11iIi11i + O0 * oO0o + I1ii11iIi11i + I1ii11iIi11i
 if 60 - 60: II111iiii % Oo0Ooo
 if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
