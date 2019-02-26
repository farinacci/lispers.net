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
  if ( iII1iii == False ) : i111I11i ( I1IiIiiIiIII )
 else :
  if ( IIIiIi ) : I1IiIiiIiIII = Iii
  I1iii11 = i111I11i ( I1IiIiiIiIII )
  if 37 - 37: i11iIiiIii + i1IIi
  if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 I1iIi1iiiIiI = lisp . lisp_command_ipc ( I1iii11 , process )
 lisp . lisp_ipc ( I1iIi1iiiIiI , lisp_socket , "lisp-core" )
 return
 if 41 - 41: I1ii11iIi11i * ooOoO0o - Ii1I + Oo0Ooo
 if 23 - 23: II111iiii % o0oOOo0O0Ooo + o0oOOo0O0Ooo + iII111i - iII111i
 if 62 - 62: o0oOOo0O0Ooo
 if 45 - 45: OOooOOo * ooOoO0o
 if 74 - 74: i1IIi + O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
def lisp_is_user_superuser ( username ) :
 if ( username == None ) : username = lisp_get_user ( )
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 OOoo0oo = commands . getoutput ( "egrep -A 4 user-account ./lisp.config" )
 if 58 - 58: oO0o
 Ii = "username = {}" . format ( username )
 O0OO0O = OOoo0oo . find ( Ii )
 o0o0O0O00oOOo = OOoo0oo [ O0OO0O : : ] . find ( "}" )
 if ( O0OO0O == - 1 or o0o0O0O00oOOo == - 1 ) : return ( False )
 if 19 - 19: I1ii11iIi11i - I11i . II111iiii - OoO0O00 . IiII * OoooooooOO
 O0oOo0OOOoO = OOoo0oo [ O0OO0O : O0OO0O + o0o0O0O00oOOo ] . find ( "super-user = yes" )
 return ( O0oOo0OOOoO != - 1 )
 if 11 - 11: o0oOOo0O0Ooo * OoO0O00
 if 15 - 15: OoOoOO00
 if 62 - 62: Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
def lisp_find_user_account ( username , password ) :
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 OOoo0oo = commands . getoutput ( "egrep -A 4 user-account ./lisp.config" )
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 O0OO0O = OOoo0oo . find ( "username = {}\n" . format ( username ) )
 if ( O0OO0O == - 1 ) : return ( False )
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 OOoo0oo = OOoo0oo [ O0OO0O : : ]
 OOoo0oo = OOoo0oo . replace ( "\t" , "" )
 OOoo0oo = OOoo0oo . replace ( " " , "" )
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 O0OO0O = OOoo0oo . find ( "password=" )
 if ( O0OO0O == - 1 ) : return ( False )
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 if 46 - 46: i11iIiiIii - O0 . oO0o
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 OOoo0oo = OOoo0oo [ O0OO0O : : ]
 o0o0O0O00oOOo = OOoo0oo . find ( "\n" )
 if ( o0o0O0O00oOOo == - 1 ) : return ( False )
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
 iIIi = OOoo0oo [ : o0o0O0O00oOOo ] . split ( "=" )
 if ( iIIi [ 1 ] == "" ) :
  IIi1 = lisp_hash_password ( password )
  if ( iIIi [ 2 ] != IIi1 ) : return ( False )
 else :
  if ( iIIi [ 1 ] != password ) : return ( False )
  if 96 - 96: iII111i
  if 18 - 18: iII111i * I11i - Ii1I
  if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
  if 39 - 39: iIii1I11I1II1 - OoooooooOO
 return ( True )
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
def lisp_validate_user ( ) :
 IIIIIiII1 = bottle . request . forms . get ( 'username' )
 if 45 - 45: I1IiiI / iII111i . iII111i
 if ( IIIIIiII1 == None ) :
  i1 = bottle . request . get_cookie ( "lisp-login" )
  if ( i1 ) : return ( True )
  if 95 - 95: OoO0O00 . i1IIi / i11iIiiIii
  if 38 - 38: Oo0Ooo - I11i . Oo0Ooo
 ii1111i = bottle . request . forms . get ( 'password' )
 if ( IIIIIiII1 == None or ii1111i == None ) : return ( False )
 if 75 - 75: IiII + II111iiii / oO0o - oO0o / OoooooooOO
 if ( lisp_find_user_account ( IIIIIiII1 , ii1111i ) == False ) : return ( False )
 if 2 - 2: o0oOOo0O0Ooo
 if 19 - 19: II111iiii
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 I1iI1I1 = None if os . getenv ( "LISP_NO_USER_TIMEOUT" ) == "" else LISP_USER_TIMEOUT
 if 48 - 48: I1IiiI / i11iIiiIii - o0oOOo0O0Ooo * oO0o / OoooooooOO
 bottle . response . set_cookie ( "lisp-login" , IIIIIiII1 , max_age = I1iI1I1 )
 return ( True )
 if 89 - 89: iIii1I11I1II1 / I1IiiI - II111iiii / Ii1I . i11iIiiIii . Ii1I
 if 48 - 48: O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
def lisp_get_user ( ) :
 IIIIIiII1 = bottle . request . forms . get ( 'username' )
 if ( IIIIIiII1 ) : return ( IIIIIiII1 )
 if 7 - 7: II111iiii
 return ( bottle . request . get_cookie ( "lisp-login" ) )
 if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
 if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
 if 94 - 94: I11i + II111iiii % i11iIiiIii
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
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
def lisp_is_any_xtr_logging_on ( log_type ) :
 o00oO00 = "egrep '" + log_type + " = '" + " ./lisp.config"
 o00oO00 = commands . getoutput ( o00oO00 )
 if ( o00oO00 == "" ) : return ( False )
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 o00oO00 = o00oO00 . split ( "\n" )
 for iIIIIiiIii in o00oO00 :
  ooO0oo = iIIIIiiIii . find ( "    {} = " . format ( log_type ) ) != - 1
  if ( iIIIIiiIii [ 0 ] == " " and ooO0oo ) :
   o00oO00 = iIIIIiiIii . replace ( " " , "" )
   o00oO00 = o00oO00 . split ( "=" )
   if ( o00oO00 [ 1 ] == "yes" ) : return ( True )
   if 56 - 56: OoooooooOO - I11i - i1IIi
   if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 return ( False )
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
def lisp_landing_page ( ) :
 ooOOOo = lisp . green ( "yes" , True )
 OO000oOoo0O = lisp . red ( "no" , True )
 if 9 - 9: oO0o * i1IIi - i1IIi
 IiIiiI11i1Ii = ooOOOo if lisp . lisp_is_running ( "lisp-itr" ) else OO000oOoo0O
 O00 = ooOOOo if lisp . lisp_is_running ( "lisp-etr" ) else OO000oOoo0O
 Iii1111III111 = ooOOOo if lisp . lisp_is_running ( "lisp-rtr" ) else OO000oOoo0O
 Ii1 = ooOOOo if lisp . lisp_is_running ( "lisp-mr" ) else OO000oOoo0O
 ooo0O0OO = ooOOOo if lisp . lisp_is_running ( "lisp-ms" ) else OO000oOoo0O
 O0Oooo = ooOOOo if lisp . lisp_is_running ( "lisp-ddt" ) else OO000oOoo0O
 if 77 - 77: II111iiii
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
    ''' . format ( IiIiiI11i1Ii , Iii1111III111 , O00 , Ii1 , O0Oooo , ooo0O0OO )
 if 42 - 42: Ii1I * I1Ii111 . IiII * I1IiiI + OoOoOO00
 i1iiI11I += '''
        <center>
        <style type="text/css">
        form { display:inline }
        </style>

        <a href="/lisp/show/status">
        <button style="background-color:transparent;border-radius:10px;
        type="button">system status</button></a>
    '''
 if 25 - 25: I11i . I1IiiI + oO0o
 O00OO0o0 = lisp_get_clause_for_api ( "lisp debug" ) [ 0 ]
 O00OO0o0 = O00OO0o0 [ "lisp debug" ] if O00OO0o0 . has_key ( "lisp debug" ) else None
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
 for Ooo00o0oOo0O0O in O00OO0o0 : ooOoOO [ Ooo00o0oOo0O0O . keys ( ) [ 0 ] ] = Ooo00o0oOo0O0O . values ( ) [ 0 ]
 O00OO0o0 = ooOoOO
 O00OO0o0 [ "ddt" ] = O00OO0o0 [ "ddt-node" ]
 O00OO0o0 [ "mr" ] = O00OO0o0 [ "map-resolver" ]
 O00OO0o0 [ "ms" ] = O00OO0o0 [ "map-server" ]
 if 79 - 79: I1ii11iIi11i + I1Ii111
 if 10 - 10: Oo0Ooo + O0
 if 43 - 43: iIii1I11I1II1 / II111iiii % o0oOOo0O0Ooo - OOooOOo
 if 62 - 62: I11i
 III11I1 = commands . getoutput ( "wc -l logs/lisp-core.log" )
 III11I1 = III11I1 . replace ( " " , "" )
 III11I1 = III11I1 . split ( "logs" ) [ 0 ]
 O000oOo = "on" if O00OO0o0 [ "core" ] == "yes" else "off"
 i1iiI11I += '''
        <form>
        <select size="1" style="width: 110px"
                onchange="parent.window.location=this.value">
        <option value="">show logging:</option>
        <option value="/lisp/show/log/lisp-core/100">[{}] core log [{}]
        </option>''' . format ( O000oOo , III11I1 )
 if 53 - 53: iIii1I11I1II1 + o0oOOo0O0Ooo - OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if ( os . path . exists ( "./logs/lisp-itr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-itr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  O000oOo = "on" if O00OO0o0 [ "itr" ] == "yes" else "off"
  i1iiI11I += '''
            <option value="/lisp/show/log/lisp-itr/100">[{}] ITR log [{}]
            </option>''' . format ( O000oOo , III11I1 )
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if ( os . path . exists ( "./logs/lisp-rtr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-rtr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  O000oOo = "on" if O00OO0o0 [ "rtr" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-rtr/100">[{}] RTR 
           log [{}]</option>''' . format ( O000oOo , III11I1 )
  if 64 - 64: i1IIi
 if ( os . path . exists ( "./logs/lisp-etr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-etr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  O000oOo = "on" if O00OO0o0 [ "etr" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-etr/100">[{}] ETR 
            log [{}]</option>''' . format ( O000oOo , III11I1 )
  if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if ( os . path . exists ( "./logs/lisp-xtr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-xtr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  O000oOo = "on" if O00OO0o0 [ "itr" ] == "yes" or O00OO0o0 [ "etr" ] == "yes" or O00OO0o0 [ "rtr" ] == "yes" else "off"
  if 18 - 18: OOooOOo + I1Ii111
  i1iiI11I += '''<option value="/lisp/show/log/lisp-xtr/100">[{}] XTR 
           log [{}]</option>''' . format ( O000oOo , III11I1 )
  if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if ( os . path . exists ( "./logs/lisp-mr.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-mr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  O000oOo = "on" if O00OO0o0 [ "mr" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-mr/100">[{}] MR 
            log [{}] </option>''' . format ( O000oOo , III11I1 )
  if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if ( os . path . exists ( "./logs/lisp-ddt.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-ddt.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  O000oOo = "on" if O00OO0o0 [ "ddt" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-ddt/100">[{}] DDT 
            log [{}]</option>''' . format ( O000oOo , III11I1 )
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if ( os . path . exists ( "./logs/lisp-ms.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-ms.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  O000oOo = "on" if O00OO0o0 [ "ms" ] == "yes" else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-ms/100">[{}] MS 
            log [{}]</option>''' . format ( O000oOo , III11I1 )
  if 50 - 50: ooOoO0o + i1IIi
 i11IiIIi11I = lisp_is_any_xtr_logging_on ( "flow-logging" )
 if ( os . path . exists ( "./logs/lisp-flow.log" ) ) :
  III11I1 = commands . getoutput ( "wc -l logs/lisp-flow.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  O000oOo = "on" if i11IiIIi11I else "off"
  i1iiI11I += '''<option value="/lisp/show/log/lisp-flow/100">[{}] flow 
            log [{}]</option>''' . format ( O000oOo , III11I1 )
  if 78 - 78: IiII
 i1iiI11I += "</select></form>"
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 O0oOo0OOOoO = lisp_is_user_superuser ( None )
 if ( O0oOo0OOOoO ) :
  i1iiI11I += '''
            <form>
            <select size="1" style="width: 120px"
                    onchange="parent.window.location=this.value">
            <option value="">manage logging:</option>
        '''
  if 12 - 12: II111iiii
  if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
  if 25 - 25: oO0o
  if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
  if 43 - 43: I1ii11iIi11i - iII111i
  if ( "yes" in O00OO0o0 . values ( ) or iI1i ) :
   i1iiI11I += '''<option value="/lisp/debug/{}%{}">disable all logging
                </option>''' . format ( "disable" , "all" )
   if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
   if 47 - 47: iII111i
  o00Ooo0 = False
  O0O00O = False
  for iIi1Ii in O00OO0o0 :
   if ( lisp . lisp_is_running ( "lisp-" + iIi1Ii ) == False ) : continue
   if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
   if ( iIi1Ii in [ "itr" , "etr" , "rtr" ] ) :
    o00Ooo0 = True
    O0O00O = True
    if 98 - 98: iII111i + Ii1I - OoO0O00
    if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
   Ii1ii11IIIi = O00OO0o0 [ iIi1Ii ]
   OOoooOOOo0oO = iIi1Ii
   if ( OOoooOOOo0oO == "mr" ) : OOoooOOOo0oO = "map-resolver"
   if ( OOoooOOOo0oO == "ms" ) : OOoooOOOo0oO = "map-server"
   if ( OOoooOOOo0oO == "ddt" ) : OOoooOOOo0oO = "ddt-node"
   if 92 - 92: OoO0O00 * ooOoO0o
   i1iiI11I += '''<option value="/lisp/debug/{}%{}">{} {} logging
                </option>''' . format ( OOoooOOOo0oO , "yes" if Ii1ii11IIIi == "no" else "no" ,
 "enable" if Ii1ii11IIIi == "no" else "disable" ,
 iIi1Ii . upper ( ) if iIi1Ii != "core" else "core" )
   if 35 - 35: i11iIiiIii
  if ( o00Ooo0 ) :
   ooO = lisp_is_any_xtr_logging_on ( "data-plane-logging" )
   i1iiI11I += '''<option value="/lisp/debug/data-plane-logging%{}">{} 
                data-plane logging </option>''' . format ( "yes" if ooO == False else "no" ,
   # I11i . Oo0Ooo % IiII * i1IIi
 "enable" if ooO == False else "disable" )
   if 71 - 71: Oo0Ooo / o0oOOo0O0Ooo + OOooOOo
  if ( O0O00O ) :
   ooO = i11IiIIi11I
   i1iiI11I += '''<option value="/lisp/debug/flow-logging%{}">{} 
                flow logging </option>''' . format (
 "yes" if ooO == False else "no" ,
 "enable" if ooO == False else "disable" )
   if 48 - 48: I1Ii111 + iII111i
  i1iiI11I += "</select></form>"
  if 16 - 16: iIii1I11I1II1 % i11iIiiIii . OoOoOO00 % ooOoO0o + oO0o . OoO0O00
  if 46 - 46: OoO0O00 - o0oOOo0O0Ooo / OoOoOO00 - OoooooooOO + oO0o
 i1iiI11I += "<br><br>"
 if 58 - 58: o0oOOo0O0Ooo / o0oOOo0O0Ooo + ooOoO0o + I11i - OoOoOO00 . OOooOOo
 if 15 - 15: ooOoO0o * OoOoOO00 % IiII . OoOoOO00 . I11i
 if 97 - 97: oO0o
 if 80 - 80: I1IiiI . Ii1I
 I1I11ii = lisp . lisp_button ( "{}:<br>show map-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-itr" ) ) :
  I1I11ii = '<a href="/lisp/show/itr/map-cache">' + I1I11ii + '</a>'
  I1I11ii = I1I11ii . format ( lisp . green ( "ITR" , True ) )
 else :
  I1I11ii = I1I11ii . format ( lisp . red ( "ITR" , True ) )
  I1I11ii = lisp . lisp_span ( I1I11ii , "ITR not running" )
  if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
  if 29 - 29: o0oOOo0O0Ooo
 oo0iIiI = lisp . lisp_button ( "{}:<br>show map-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-rtr" ) ) :
  oo0iIiI = '<a href="/lisp/show/rtr/map-cache">' + oo0iIiI + '</a>'
  oo0iIiI = oo0iIiI . format ( lisp . green ( "RTR" , True ) )
 else :
  oo0iIiI = oo0iIiI . format ( lisp . red ( "RTR" , True ) )
  oo0iIiI = lisp . lisp_span ( oo0iIiI , "RTR not running" )
  if 81 - 81: OoOoOO00 % Ii1I
  if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
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
 Iio00 = lisp . lisp_button ( "API Documentation" , "/lisp/show/api-doc" )
 IiI1iiII1i1i = lisp . lisp_button ( "Command Documentation" , "/lisp/show/command-doc" )
 i1IiI = lisp . lisp_button ( "IETF LISP WG Drafts" ,
 "http://datatracker.ietf.org/wg/lisp/" )
 o0o0O00 = lisp . lisp_button ( "ddt-root.org" , "http://ddt-root.net" )
 oOo000OOooO0O = lisp . lisp_button ( "LISP Facebook Group" ,
 "https://www.facebook.com/groups/407716795982512" )
 IiOoOoooO0O00 = lisp . lisp_button ( "LISP LinkedIn Group" ,
 "http://www.linkedin.com/groups/3776183" )
 if 70 - 70: o0oOOo0O0Ooo - OoO0O00
 OoI1IiiiIiI = lisp . lisp_space ( 2 )
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

    ''' . format ( OoI1IiiiIiI , I1I11ii , OoI1IiiiIiI , oo0iIiI , OoI1IiiiIiI , iIii1iII1Ii , OoI1IiiiIiI , OoI1IiiiIiI , OOOo , OoI1IiiiIiI , I1i1I1I11IiiI , OoI1IiiiIiI , iiii , OoI1IiiiIiI ,
 o0Oo00OO0 , o0Oo00OO0 , i11Ii11II1I1 , oO , Iio00 , IiI1iiII1i1i , i1IiI , o0o0O00 , oOo000OOooO0O , IiOoOoooO0O00 )
 if 77 - 77: Ii1I / II111iiii - Ii1I / OOooOOo
 return ( lisp_show_wrapper ( i1iiI11I ) )
 if 97 - 97: OOooOOo / oO0o . II111iiii
 if 44 - 44: Ii1I % I11i . I1Ii111
 if 18 - 18: iIii1I11I1II1 + I11i * I1IiiI - OOooOOo / I1IiiI
 if 78 - 78: I11i . IiII
 if 38 - 38: OoOoOO00 + IiII
 if 15 - 15: Oo0Ooo + I11i . ooOoO0o - iIii1I11I1II1 / O0 % iIii1I11I1II1
 if 86 - 86: I1IiiI / oO0o * Ii1I
 if 64 - 64: ooOoO0o / O0 * OoOoOO00 * ooOoO0o
def lisp_drain_socket ( lisp_socket , process ) :
 lisp . lprint ( "Draining socket looking for {}" . format ( process ) )
 if 60 - 60: I11i / i1IIi % I1ii11iIi11i / I1ii11iIi11i * I1ii11iIi11i . i11iIiiIii
 o0oOO00 = None
 while ( True ) :
  try :
   select . select ( [ lisp_socket ] , [ ] , [ ] )
  except :
   return ( o0oOO00 )
   if 46 - 46: i11iIiiIii - I11i
   if 95 - 95: II111iiii
  lisp . lisp_ipc_lock . acquire ( )
  oo000oO , O0OOO0 , IiIi1 , i1iiI11I = lisp . lisp_receive ( lisp_socket , True )
  lisp . lisp_ipc_lock . release ( )
  if 55 - 55: O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
  if ( O0OOO0 != process ) :
   lisp . lprint ( "Discarding IPC message from {}" . format ( O0OOO0 ) )
  elif ( o0oOO00 == None ) :
   o0oOO00 = i1iiI11I
   if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
   if 24 - 24: OoOoOO00
 return
 if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 if 28 - 28: I1IiiI
 if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
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
 iIi1Ii = lisp_commands [ iii ]
 iIi1Ii = iIi1Ii [ 0 ]
 if 98 - 98: OoOoOO00 % II111iiii
 if ( lisp . lisp_is_running ( iIi1Ii ) == False ) :
  i1iiI11I = ( "<i>Process '{}' is not running, command cannot be " + "executed</i><br>" ) . format ( iIi1Ii )
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
 lisp . lisp_ipc ( command , lisp_socket , iIi1Ii )
 lisp . lprint ( "Waiting for response to show command '{}'" . format ( command ) )
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 oo000oO , O0OOO0 , IiIi1 , i1iiI11I = lisp . lisp_receive ( lisp_socket , True )
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 lisp . lisp_ipc_lock . release ( )
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if ( O0OOO0 == "" ) :
  lisp . lprint ( "Command '{}' timed out to {}" . format ( command , iIi1Ii ) )
 elif ( O0OOO0 != iIi1Ii ) :
  lisp . lprint ( "Received response from {} but expecting from {}" . format ( O0OOO0 , iIi1Ii ) )
  if 69 - 69: I1ii11iIi11i
  i1iiI11I = lisp_drain_socket ( lisp_socket , iIi1Ii )
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
 o00oO00 = clause . split ( " " )
 o00oO00 = o00oO00 [ 0 ] + " " + o00oO00 [ 1 ]
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 I1IiIiiIiIII = lisp_core_commands [ "lisp enable" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if 81 - 81: IiII / OoOoOO00 * IiII . O0
 iII1iii , I1iii11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
 if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
 if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
 if ( iII1iii == True ) : return ( I1iii11 )
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
 return ( I1iii11 )
 if 37 - 37: I11i . I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
def lisp_debug_command ( lisp_socket , clause , single_process ) :
 o00oO00 = clause . split ( " " )
 o00oO00 = o00oO00 [ 0 ] + " " + o00oO00 [ 1 ]
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 I1IiIiiIiIII = lisp_core_commands [ "lisp debug" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 iII1iii , I1iii11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 if ( iII1iii == True ) : return ( I1iii11 )
 if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
 O0O0oo = { "itr" : "lisp-itr" , "etr" : "lisp-etr" , "rtr" : "lisp-rtr" ,
 "map-resolver" : "lisp-mr" , "map-server" : "lisp-ms" ,
 "ddt-node" : "lisp-ddt" , "core" : "" }
 if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
 for oo00o0 in I1IiIiiIiIII :
  iIi1Ii = O0O0oo [ oo00o0 ]
  if ( single_process and single_process != iIi1Ii ) : continue
  if 17 - 17: Ii1I / iIii1I11I1II1 - OoO0O00 + I1IiiI % OOooOOo
  Ii1ii11IIIi = I1IiIiiIiIII [ oo00o0 ]
  o00oO00 = ( "lisp debug {\n" + "    {} = {}\n" . format ( oo00o0 , Ii1ii11IIIi ) + "}\n" )
  if 14 - 14: o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
  if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
  if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
  if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
  if 26 - 26: o0oOOo0O0Ooo
  if ( oo00o0 == "core" ) :
   lisp_process_command ( None , None , o00oO00 , None , [ None ] )
   continue
   if 12 - 12: OoooooooOO / O0 + II111iiii * I1ii11iIi11i
   if 46 - 46: II111iiii - IiII * OoooooooOO / oO0o % IiII
  o00oO00 = lisp . lisp_command_ipc ( o00oO00 , "lisp-core" )
  lisp . lisp_ipc ( o00oO00 , lisp_socket , iIi1Ii )
  if ( single_process ) : break
  if 11 - 11: iIii1I11I1II1 . OoOoOO00 / IiII % ooOoO0o
 return ( I1iii11 )
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
 ii1111i = clause [ O0OO0O : o0o0O0O00oOOo ] . replace ( " " , "" )
 if 74 - 74: oO0o
 if ( len ( ii1111i ) != 0 and ii1111i [ 0 ] == "=" ) : return ( clause )
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 ii1111i = ii1111i . replace ( " " , "" )
 ii1111i = ii1111i . replace ( "\t" , "" )
 ii1111i = lisp_hash_password ( ii1111i )
 clause = clause [ 0 : O0OO0O ] + " =" + ii1111i + clause [ o0o0O0O00oOOo : : ]
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
 o00oO00 = clause . split ( " " )
 o00oO00 = o00oO00 [ 0 ] + " " + o00oO00 [ 1 ]
 if 5 - 5: Oo0Ooo
 I1IiIiiIiIII = lisp_core_commands [ "lisp user-account" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 iII1iii , I1iii11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 24 - 24: ooOoO0o - I11i * oO0o
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if ( iII1iii == False ) :
  I1iii11 = lisp_replace_password_in_clause ( I1iii11 , "password =" )
  if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 return ( I1iii11 )
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
def lisp_rtr_list_command ( clause ) :
 o00oO00 = clause . split ( " " )
 o00oO00 = o00oO00 [ 0 ] + " " + o00oO00 [ 1 ]
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 I1IiIiiIiIII = lisp_core_commands [ "lisp rtr-list" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 iII1iii , I1iii11 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 36 - 36: OOooOOo % i11iIiiIii
 if ( iII1iii ) : return ( I1iii11 )
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 lisp . lisp_ms_rtr_list = [ ]
 if ( I1IiIiiIiIII . has_key ( "address" ) ) :
  for Ii1I1i in I1IiIiiIiIII [ "address" ] :
   II = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   II . store_address ( Ii1I1i )
   lisp . lisp_ms_rtr_list . append ( II )
   if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
   if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 return ( I1iii11 )
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
def lisp_process_command_lines ( lisp_socket , old , new , line ) :
 o00oO00 = line . split ( "{" )
 o00oO00 = o00oO00 [ 0 ]
 o00oO00 = o00oO00 [ 0 : - 1 ]
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 lisp . lprint ( "Process the '{}' command" . format ( o00oO00 ) )
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 if ( lisp_commands . has_key ( o00oO00 ) == False ) :
  line = "#>>> " + line . replace ( "\n" , " <<< invalid command\n" )
  new . write ( line )
  return
  if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
  if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
  if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
  if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
  if 12 - 12: I1ii11iIi11i / Ii1I
 ii11Ii11 = lisp_commands [ o00oO00 ]
 I1i1ii = False
 for iIi1Ii in ii11Ii11 :
  if ( iIi1Ii == "" ) :
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
  if ( lisp . lisp_is_running ( iIi1Ii ) == False ) :
   if ( I1i1ii == False ) :
    for line in Oo000 : new . write ( line )
    I1i1ii = True
    if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
   lisp . lprint ( "Process '{}' is not running, do not send command" . format ( iIi1Ii ) )
   if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
   continue
   if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
   if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
   if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
   if 33 - 33: Ii1I
   if 93 - 93: ooOoO0o
   if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
  if ( iIi1Ii == "lisp-core" ) :
   if ( Oo000 . find ( "enable" ) != - 1 ) :
    I1iii11 = lisp_enable_command ( Oo000 )
    if 19 - 19: I1ii11iIi11i
   if ( Oo000 . find ( "debug" ) != - 1 ) :
    I1iii11 = lisp_debug_command ( lisp_socket , Oo000 , None )
    if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
   if ( Oo000 . find ( "user-account" ) != - 1 ) :
    I1iii11 = lisp_user_account_command ( Oo000 )
    if 66 - 66: O0
   if ( Oo000 . find ( "rtr-list" ) != - 1 ) :
    I1iii11 = lisp_rtr_list_command ( Oo000 )
    if 52 - 52: OoO0O00 * OoooooooOO
  else :
   Ii11iiI = lisp . lisp_command_ipc ( Oo000 , "lisp-core" )
   lisp . lisp_ipc ( Ii11iiI , lisp_socket , iIi1Ii )
   lisp . lprint ( "Waiting for response to config command '{}'" . format ( o00oO00 ) )
   if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
   if 28 - 28: iIii1I11I1II1
   oo000oO , O0OOO0 , IiIi1 , I1iii11 = lisp . lisp_receive ( lisp_socket ,
 True )
   if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
   if ( O0OOO0 == "" ) :
    lisp . lprint ( "Command timed out to {}" . format ( iIi1Ii ) )
    I1iii11 = Oo000
   elif ( O0OOO0 != iIi1Ii ) :
    lisp . lprint ( "Fatal IPC error to {}, source {}" . format ( iIi1Ii ,
 O0OOO0 ) )
    if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
    if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
    if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
    if 46 - 46: OoOoOO00 - O0
    if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
    if 49 - 49: o0oOOo0O0Ooo
    if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
  if ( I1i1ii == False ) :
   for line in I1iii11 : new . write ( line )
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
 o0 = file_name + ".bak"
 Iiii = file_name + ".temp"
 I1i1I = "# lispers.net lisp.config file"
 if 17 - 17: I11i - iII111i % Ii1I
 if 2 - 2: Ii1I * I1ii11iIi11i * OoooooooOO
 if 73 - 73: OoOoOO00 + Oo0Ooo
 if 61 - 61: iIii1I11I1II1
 if 47 - 47: OoooooooOO
 O0O0Ooooo000 = 'egrep "{}" {}' . format ( I1i1I , file_name )
 ooO0oo = commands . getoutput ( O0O0Ooooo000 )
 if ( ooO0oo == "" ) :
  lisp . lprint ( "*** lisp.config configuration file is corrupt ***" )
  return
  if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
  if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
  if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
  if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
  if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
  if 26 - 26: OOooOOo * Oo0Ooo
 i1iI1Ii11Ii1 = open ( file_name , "r" )
 o0OoO0oo0O0o = open ( Iiii , "w" )
 for II1i in i1iI1Ii11Ii1 :
  if ( II1i . find ( I1i1I ) == 0 ) :
   if ( startup ) :
    o0OoO0oo0O0o . write ( II1i )
   else :
    lisp_write_last_changed_date ( o0OoO0oo0O0o , II1i )
    if 6 - 6: II111iiii % I1Ii111
   continue
   if 41 - 41: IiII - II111iiii . II111iiii + I1IiiI
   if 59 - 59: iIii1I11I1II1 % Ii1I . i11iIiiIii
  if ( II1i . find ( "# Hostname:" ) == 0 ) :
   o0OoO0oo0O0o . write ( "# Hostname: " + lisp . lisp_hostname + "\n" )
   continue
   if 59 - 59: o0oOOo0O0Ooo . oO0o . Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
   if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
  if ( lisp_end_file ( II1i ) ) :
   o0OoO0oo0O0o . write ( II1i + "\n" )
   break
   if 89 - 89: oO0o
   if 87 - 87: iII111i % Oo0Ooo
  if ( lisp_comment ( II1i ) ) :
   o0OoO0oo0O0o . write ( II1i )
   continue
   if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
   if 37 - 37: iII111i
  iIIiI1111 = II1i . replace ( " " , "" )
  iIIiI1111 = iIIiI1111 . replace ( "\n" , "" )
  if ( iIIiI1111 == "" ) : continue
  if 91 - 91: OoooooooOO / o0oOOo0O0Ooo . IiII - iIii1I11I1II1 - Ii1I
  if 31 - 31: IiII - OoO0O00 / OOooOOo . i1IIi / Ii1I
  if 66 - 66: OoO0O00
  if 72 - 72: I1Ii111
  lisp_process_command_lines ( lisp_socket , i1iI1Ii11Ii1 , o0OoO0oo0O0o , II1i )
  if 91 - 91: II111iiii / IiII + iIii1I11I1II1 . I11i - O0
 i1iI1Ii11Ii1 . close ( )
 o0OoO0oo0O0o . close ( )
 if 70 - 70: Ii1I * oO0o - I11i + Oo0Ooo % I1ii11iIi11i - IiII
 if 81 - 81: O0 . O0
 if 75 - 75: iIii1I11I1II1 % IiII + I1ii11iIi11i * O0 . iII111i - ooOoO0o
 if 32 - 32: Ii1I % oO0o - i1IIi
 if ( os . path . exists ( ooO0 ) == False ) :
  os . system ( "touch {}" . format ( ooO0 ) )
  if 40 - 40: iIii1I11I1II1 + iII111i * OoOoOO00 + oO0o
 if ( startup == False ) :
  os . system ( "diff {} {} > {}" . format ( o0 , Iiii , ooO0 ) )
  if 15 - 15: I11i % I1IiiI - iIii1I11I1II1 * ooOoO0o
  if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
  if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
  if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
  if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
  if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
 os . system ( "cp {} {}; rm -f {}; cp {} {}" . format ( Iiii , file_name ,
 Iiii , file_name , o0 ) )
 return
 if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
 if 93 - 93: ooOoO0o
 if 18 - 18: ooOoO0o
 if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
 if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
 if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
 if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
 if 58 - 58: O0
def lisp_send_commands ( lisp_socket , process ) :
 O0oO = "./lisp.config"
 OOO00o0 = open ( O0oO , "r" )
 OOoO = False
 ooo = 0
 if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
 if 21 - 21: iII111i
 if 24 - 24: iII111i / ooOoO0o
 for II1i in OOO00o0 :
  if ( lisp_end_file ( II1i ) ) : break
  if ( lisp_comment ( II1i ) or II1i [ 0 ] == "\n" ) : continue
  if 61 - 61: iIii1I11I1II1 + oO0o
  if ( lisp_begin_clause ( II1i ) ) :
   if ( ooo == 0 ) :
    Oo000 = ""
    o00oO00 = II1i . split ( "{" )
    o00oO00 = o00oO00 [ 0 ]
    o00oO00 = o00oO00 [ 0 : - 1 ]
    if ( lisp_commands . has_key ( o00oO00 ) ) :
     OOoO = ( process in lisp_commands [ o00oO00 ] ) or ( o00oO00 == "lisp debug" )
     if 8 - 8: I1Ii111 + OoO0O00
     if 9 - 9: OOooOOo + o0oOOo0O0Ooo
     if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
   ooo += 1
   if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
   if 55 - 55: oO0o
   if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
   if 97 - 97: I1Ii111 . I11i / I1IiiI
   if 83 - 83: I11i - I1ii11iIi11i * oO0o
  if ( OOoO ) : Oo000 += II1i
  if 90 - 90: Oo0Ooo * I1IiiI
  if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
  if 28 - 28: IiII * I1IiiI % IiII
  if 95 - 95: O0 / I11i . I1Ii111
  if ( lisp_end_clause ( II1i ) == False ) : continue
  ooo -= 1
  if ( ooo != 0 ) : continue
  if ( OOoO == False ) : continue
  if 17 - 17: I11i
  if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
  if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
  if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
  if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
  if 38 - 38: I1Ii111
  lisp . lprint ( "Send command '{}' to restarting process '{}'" . format ( o00oO00 , process ) )
  if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
  if 22 - 22: oO0o * iII111i
  if 4 - 4: OoOoOO00 - oO0o + I1IiiI
  if 36 - 36: IiII
  if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
  if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
  if ( o00oO00 == "lisp debug" ) :
   lisp_debug_command ( lisp_socket , Oo000 , process )
   OOoO = False
   continue
   if 43 - 43: iIii1I11I1II1 % OoO0O00
   if 84 - 84: Oo0Ooo
  Oo000 = lisp . lisp_command_ipc ( Oo000 , "lisp-core" )
  lisp . lisp_ipc ( Oo000 , lisp_socket , process )
  if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
  if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
  if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
  if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
  if 25 - 25: o0oOOo0O0Ooo
  lisp . lprint ( "Waiting for response to config command '{}'" . format ( o00oO00 ) )
  if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
  if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
  oo000oO , O0OOO0 , IiIi1 , I1iIi1iiiIiI = lisp . lisp_receive ( lisp_socket , True )
  if 41 - 41: i1IIi - I1IiiI
  if ( O0OOO0 == "" ) :
   lisp . lprint ( "Command timed out to {}" . format ( process ) )
  elif ( O0OOO0 != process ) :
   lisp . lprint ( "Fatal IPC error to {}, IPC source {}" . format ( process ,
 O0OOO0 ) )
   if 48 - 48: I1IiiI - II111iiii / OoO0O00 + I1IiiI
  OOoO = False
  if 5 - 5: O0
 return
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
 if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
 if 92 - 92: I11i / O0 * I1IiiI - I11i
 if 99 - 99: i11iIiiIii % OoooooooOO
 if 56 - 56: IiII * I1Ii111
 if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
 if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
def lisp_config_process ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 O0oO = "./lisp.config"
 I1Iiii = ""
 I1I1Iii1Iiii = True
 if 4 - 4: IiII
 while ( True ) :
  Oo000o = os . path . getmtime ( O0oO )
  if ( Oo000o != I1Iiii ) :
   if 93 - 93: oO0o % i1IIi
   lisp . lisp_ipc_lock . acquire ( )
   lisp_process_config_file ( lisp_socket , O0oO , I1I1Iii1Iiii )
   lisp . lisp_ipc_lock . release ( )
   if 83 - 83: I1IiiI . Oo0Ooo - I11i . o0oOOo0O0Ooo
   I1I1Iii1Iiii = False
   I1Iiii = os . path . getmtime ( O0oO )
   if 73 - 73: I1IiiI - iII111i . iII111i
  time . sleep ( 1 )
  if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
 return
 if 64 - 64: i1IIi % I1ii11iIi11i / Ii1I % OoooooooOO
 if 24 - 24: I1Ii111 + OoooooooOO . IiII / OoOoOO00 / I11i
 if 65 - 65: OoooooooOO
 if 18 - 18: O0 - i1IIi . I1Ii111
 if 98 - 98: o0oOOo0O0Ooo
 if 73 - 73: Oo0Ooo - iII111i . oO0o % i1IIi . O0
 if 15 - 15: ooOoO0o . iIii1I11I1II1 * I1IiiI % I11i
 if 21 - 21: OoO0O00 - I1IiiI . OoooooooOO
 if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
 if 3 - 3: OOooOOo . IiII / Oo0Ooo
 if 89 - 89: OoooooooOO . iIii1I11I1II1 . Oo0Ooo * iIii1I11I1II1 - I1Ii111
 if 92 - 92: OoooooooOO - I1ii11iIi11i - OoooooooOO % I1IiiI % I1IiiI % iIii1I11I1II1
 if 92 - 92: iII111i * O0 % I1Ii111 . iIii1I11I1II1
def lisp_map_resolver_command ( kv_pair ) :
 o00OoO = None
 if 96 - 96: ooOoO0o . OoooooooOO
 for O00oO0 in kv_pair . keys ( ) :
  if ( O00oO0 == "mr-name" ) :
   o00OoO = kv_pair [ O00oO0 ] [ 0 ]
   continue
   if 39 - 39: OOooOOo + OoO0O00
  if ( O00oO0 == "address" or O00oO0 == "dns-name" ) :
   oOoOOOO0OOO = kv_pair [ O00oO0 ]
   for oo00oO0O0 in oOoOOOO0OOO :
    if ( oo00oO0O0 == "" ) : continue
    Ii1I1i = oo00oO0O0 if ( O00oO0 == "address" ) else None
    O0oo0oO00o = oo00oO0O0 if ( O00oO0 == "dns-name" ) else None
    lisp . lisp_mr ( Ii1I1i , O0oo0oO00o , o00OoO )
    if 35 - 35: iII111i * iIii1I11I1II1 / ooOoO0o * i1IIi * O0 % iIii1I11I1II1
    if 97 - 97: i11iIiiIii + Oo0Ooo * OOooOOo % iII111i . IiII
    if 4 - 4: O0 . iII111i - iIii1I11I1II1
 return
 if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
 if 89 - 89: Ii1I
 if 51 - 51: iII111i
 if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
 if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
 if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
 if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
def lisp_map_cache_command ( kv_pair ) :
 O0oo0oOo = [ ]
 for i111iI1i1iI in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  IiiI1i111I1i = lisp . lisp_mapping ( "" , "" , [ ] )
  O0oo0oOo . append ( IiiI1i111I1i )
  if 97 - 97: OOooOOo % I1IiiI * I1IiiI % Oo0Ooo
  if 86 - 86: Ii1I * i1IIi + oO0o
 iI1i1I11i = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for i111iI1i1iI in range ( len ( kv_pair [ "address" ] ) ) :
   iiiIii1iIi1Ii = lisp . lisp_rloc ( )
   iI1i1I11i . append ( iiiIii1iIi1Ii )
   if 13 - 13: IiII . IiII + iIii1I11I1II1 * Oo0Ooo
   if 85 - 85: OOooOOo + II111iiii - OOooOOo * oO0o - i1IIi % iII111i
   if 1 - 1: OoooooooOO / O0 + OoOoOO00 + OoOoOO00 . I1Ii111 - OoOoOO00
 for O00oO0 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ O00oO0 ]
  if ( O00oO0 == "instance-id" ) :
   for i111iI1i1iI in range ( len ( O0oo0oOo ) ) :
    IiiI1i111I1i = O0oo0oOo [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii == "" ) : I11iii1I1Iiii = "0"
    IiiI1i111I1i . eid . instance_id = int ( I11iii1I1Iiii )
    IiiI1i111I1i . group . instance_id = int ( I11iii1I1Iiii )
    if 47 - 47: i11iIiiIii / Oo0Ooo - Oo0Ooo * OoO0O00
    if 48 - 48: IiII
  if ( O00oO0 == "eid-prefix" ) :
   for i111iI1i1iI in range ( len ( O0oo0oOo ) ) :
    IiiI1i111I1i = O0oo0oOo [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) : IiiI1i111I1i . eid . store_prefix ( I11iii1I1Iiii )
    if 96 - 96: oO0o / O0 . II111iiii + IiII % o0oOOo0O0Ooo
    if 67 - 67: O0 % I1Ii111
  if ( O00oO0 == "group-prefix" ) :
   for i111iI1i1iI in range ( len ( O0oo0oOo ) ) :
    IiiI1i111I1i = O0oo0oOo [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) : IiiI1i111I1i . group . store_prefix ( I11iii1I1Iiii )
    if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
    if 39 - 39: Ii1I
  if ( O00oO0 == "send-map-request" ) :
   for i111iI1i1iI in range ( len ( O0oo0oOo ) ) :
    IiiI1i111I1i = O0oo0oOo [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii == "yes" ) : IiiI1i111I1i . action = lisp . LISP_SEND_MAP_REQUEST_ACTION
    if 60 - 60: OOooOOo
    if 62 - 62: I1Ii111 * I11i
  if ( O00oO0 == "rle-name" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) :
     iiiIii1iIi1Ii . rle_name = I11iii1I1Iiii
     if ( lisp . lisp_rle_list . has_key ( I11iii1I1Iiii ) ) :
      iiiIii1iIi1Ii . rle = lisp . lisp_rle_list [ I11iii1I1Iiii ]
      if 74 - 74: OoOoOO00 . iIii1I11I1II1
      if 87 - 87: ooOoO0o
      if 41 - 41: OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
      if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
  if ( O00oO0 == "elp-name" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) :
     iiiIii1iIi1Ii . elp_name = I11iii1I1Iiii
     if ( lisp . lisp_elp_list . has_key ( I11iii1I1Iiii ) ) :
      iiiIii1iIi1Ii . elp = lisp . lisp_elp_list [ I11iii1I1Iiii ]
      iiiIii1iIi1Ii . elp . select_elp_node ( )
      if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
      if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
      if 44 - 44: I1Ii111 - IiII
      if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if ( O00oO0 == "rloc-record-name" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) : iiiIii1iIi1Ii . rloc_name = I11iii1I1Iiii
    if 59 - 59: II111iiii
    if 43 - 43: Oo0Ooo + OoooooooOO
    if 47 - 47: ooOoO0o
  if ( O00oO0 == "priority" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii == "" ) : I11iii1I1Iiii = "0"
    iiiIii1iIi1Ii . priority = int ( I11iii1I1Iiii )
    if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
    if 23 - 23: II111iiii * iII111i
  if ( O00oO0 == "weight" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii == "" ) : I11iii1I1Iiii = "0"
    iiiIii1iIi1Ii . weight = int ( I11iii1I1Iiii )
    if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
    if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
  if ( O00oO0 == "address" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) : iiiIii1iIi1Ii . rloc . store_address ( I11iii1I1Iiii )
    if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
    if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
    if 21 - 21: OoO0O00
    if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
    if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
    if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
    if 11 - 11: O0 * OoOoOO00
    if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
 for IiiI1i111I1i in O0oo0oOo :
  IiiI1i111I1i . rloc_set = iI1i1I11i
  IiiI1i111I1i . build_best_rloc_set ( )
  IiiI1i111I1i . add_cache ( )
  iI1i1I11i = copy . deepcopy ( iI1i1I11i )
  if 18 - 18: OoooooooOO
 return
 if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
 if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
 if 94 - 94: ooOoO0o + I1IiiI
 if 56 - 56: OoOoOO00 % o0oOOo0O0Ooo
 if 40 - 40: OOooOOo / IiII
 if 29 - 29: Ii1I - Ii1I / ooOoO0o
 if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
def lisp_display_map_cache ( mc , output ) :
 Oo000o = lisp . lisp_print_elapsed ( mc . uptime )
 Ii1I1Iiii = Oo000o
 OOOO0oo0 = mc . print_eid_tuple ( )
 oOIii = mc . action
 if 33 - 33: IiII % Oo0Ooo - oO0o
 if 53 - 53: II111iiii
 if 61 - 61: O0 * OoO0O00 * I1IiiI % OoooooooOO / OoOoOO00 % ooOoO0o
 if 43 - 43: OoooooooOO
 if 33 - 33: II111iiii - IiII - ooOoO0o
 if 92 - 92: OoO0O00 * IiII
 O0OOO0 = mc . mapping_source
 if ( O0OOO0 == None ) :
  O0OOO0 = "map-notify"
 else :
  O0OOO0 = "static" if O0OOO0 . is_null ( ) else O0OOO0 . print_address_no_iid ( )
  if 92 - 92: oO0o
  if 7 - 7: iII111i
  if 73 - 73: OoO0O00 % I1ii11iIi11i
 if ( mc . checkpoint_entry ) : O0OOO0 = "checkpoint"
 I1I11i = mc . print_ttl ( )
 if 38 - 38: i11iIiiIii . iIii1I11I1II1 . OOooOOo / OoO0O00
 oOIii = "encapsulate" if oOIii == lisp . LISP_NO_ACTION else lisp . lisp_map_reply_action_string [ oOIii ]
 if 18 - 18: Oo0Ooo * I1Ii111
 if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
 if ( len ( mc . rloc_set ) == 0 ) :
  i11 = mc . stats . get_stats ( True , True )
  output += lisp_table_row ( OOOO0oo0 , Oo000o + "<br>" + I1I11i , "--" , O0OOO0 ,
 i11 , oOIii , "--" )
  return ( [ True , output ] )
  if 89 - 89: OoO0O00 + o0oOOo0O0Ooo . OOooOOo - I1IiiI * i1IIi % II111iiii
  if 30 - 30: I1ii11iIi11i
 for iiiIii1iIi1Ii in mc . rloc_set :
  Ooo0ooo0oo = ""
  if ( iiiIii1iIi1Ii . rloc_exists ( ) ) :
   if ( iiiIii1iIi1Ii . rloc . is_null ( ) == False ) :
    Ooo0ooo0oo = iiiIii1iIi1Ii . rloc . print_address_no_iid ( ) + "<br>"
    I1I1i1 = ""
    I11iIiI1 = lisp . lisp_nonce_echoing and iiiIii1iIi1Ii . echo_nonce_capable
    if ( lisp . lisp_rloc_probing ) :
     I1I1i1 += iiiIii1iIi1Ii . print_rloc_probe_state ( I11iIiI1 )
     if 22 - 22: IiII * Ii1I - OoooooooOO
    if ( I11iIiI1 ) :
     i1Ii1 = lisp . lisp_get_echo_nonce ( iiiIii1iIi1Ii . rloc , None )
     if ( i1Ii1 ) : I1I1i1 += i1Ii1 . print_echo_nonce ( )
     if 75 - 75: OoooooooOO * i11iIiiIii
    if ( I1I1i1 != "" ) : Ooo0ooo0oo = lisp . lisp_span ( Ooo0ooo0oo , I1I1i1 )
    if 67 - 67: I1Ii111 / OoO0O00 . OoooooooOO
    if 51 - 51: II111iiii . oO0o . OoO0O00 % II111iiii
    if 41 - 41: OoOoOO00 - OOooOOo + ooOoO0o - i1IIi
  if ( iiiIii1iIi1Ii . translated_port != 0 ) :
   Ooo0ooo0oo += "encap-port: {}<br>" . format ( iiiIii1iIi1Ii . translated_port )
   if 6 - 6: II111iiii
   if 7 - 7: i1IIi
  if ( iiiIii1iIi1Ii . rloc_name ) :
   Ooo0ooo0oo += "rloc-name: {}<br>" . format ( lisp . blue ( iiiIii1iIi1Ii . rloc_name ,
 True ) )
   if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
   if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
  if ( iiiIii1iIi1Ii . geo ) :
   Ooo0ooo0oo += "geo: {}<br>" . format ( iiiIii1iIi1Ii . geo . print_geo_url ( ) )
   if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
  if ( iiiIii1iIi1Ii . elp ) :
   oo0O = iiiIii1iIi1Ii . elp . print_elp ( True )
   Ooo0ooo0oo += "elp: {}<br>" . format ( oo0O )
   if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
  if ( iiiIii1iIi1Ii . rle ) :
   i11111 = iiiIii1iIi1Ii . rle . print_rle ( True )
   Ooo0ooo0oo += "rle: {}<br>" . format ( i11111 )
   if 60 - 60: OOooOOo
  if ( iiiIii1iIi1Ii . json ) :
   i1iiIiI1Ii1i = "json: { ... }<br>"
   Ooo0ooo0oo += lisp . lisp_span ( i1iiIiI1Ii1i , iiiIii1iIi1Ii . json . print_json ( False ) )
   if 73 - 73: ooOoO0o
   if 86 - 86: OoOoOO00 . I11i / Oo0Ooo * I11i
   if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
   if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
   if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
  i11 = iiiIii1iIi1Ii . stats . get_stats ( True , True )
  if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
  if 5 - 5: O0 - I1IiiI
  if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
  if 16 - 16: II111iiii
  oooOO0OO0 = ""
  iiI1i = iiiIii1iIi1Ii
  while ( True ) :
   OoOo = lisp . lisp_print_elapsed ( iiI1i . last_state_change )
   if ( OoOo == "never" ) : OoOo = Ii1I1Iiii
   OoI1IiiiIiI = iiI1i . print_state ( )
   if ( iiI1i . unreach_state ( ) or iiI1i . no_echoed_nonce_state ( ) ) :
    OoI1IiiiIiI = lisp . red ( OoI1IiiiIiI , True )
    if 9 - 9: o0oOOo0O0Ooo - IiII + iIii1I11I1II1 + OoO0O00
   oooOO0OO0 += OoI1IiiiIiI + " since " + OoOo
   if 32 - 32: OoOoOO00 % OoO0O00 + i11iIiiIii + ooOoO0o - Ii1I + oO0o
   if ( lisp . lisp_rloc_probing ) :
    iiIIi1II = iiI1i . print_rloc_probe_rtt ( )
    if ( iiIIi1II != "none" ) : oooOO0OO0 += "<br>rtt: {}, hops: {}" . format ( iiIIi1II , iiI1i . print_rloc_probe_hops ( ) )
    if 1 - 1: OoOoOO00 * O0 . oO0o % O0 + II111iiii
    if 49 - 49: I11i . OOooOOo
    if 74 - 74: i1IIi
   if ( lisp . lisp_rloc_probing and iiI1i . rloc_next_hop != None ) :
    i111iiIIII , Ii11ii1 = iiI1i . rloc_next_hop
    oooOO0OO0 += "<br>{}nh {}({}) " . format ( lisp . lisp_space ( 2 ) , Ii11ii1 , i111iiIIII )
    if 1 - 1: iIii1I11I1II1 % oO0o . iIii1I11I1II1
    if 10 - 10: iII111i + OoO0O00
   iiI1i = iiI1i . next_rloc
   if ( iiI1i == None ) : break
   oooOO0OO0 += "<br>"
   if 6 - 6: OoO0O00
   if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
  if ( oOIii == "encapsulate" ) :
   IiIi1 = lisp . LISP_DATA_PORT
   if ( lisp . lisp_i_am_rtr and iiiIii1iIi1Ii . translated_port != 0 ) :
    IiIi1 = iiiIii1iIi1Ii . translated_port
    if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
    if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
   Ii1I1i = iiiIii1iIi1Ii . rloc . print_address_no_iid ( ) + ":" + str ( IiIi1 )
   if ( lisp . lisp_crypto_keys_by_rloc_encap . has_key ( Ii1I1i ) ) :
    oOOOooOo0O = lisp . lisp_crypto_keys_by_rloc_encap [ Ii1I1i ] [ 1 ]
    if ( oOOOooOo0O != None and oOOOooOo0O . shared_key != None ) :
     oOIii = "encap-crypto-" + oOOOooOo0O . cipher_suite_string
     if 31 - 31: oO0o * I1Ii111 . OoOoOO00 * I11i
     if 28 - 28: IiII + I1IiiI - Oo0Ooo % OOooOOo . I11i + I1IiiI
     if 72 - 72: Ii1I / Oo0Ooo / oO0o * OoOoOO00 + OOooOOo
     if 58 - 58: o0oOOo0O0Ooo % I1IiiI . I1IiiI * OoO0O00 - IiII . OoooooooOO
  output += lisp_table_row ( OOOO0oo0 , Oo000o + "<br>" + I1I11i , Ooo0ooo0oo , O0OOO0 ,
 i11 , oooOO0OO0 + "<br>" + oOIii ,
 str ( iiiIii1iIi1Ii . priority ) + "/" + str ( iiiIii1iIi1Ii . weight ) + "<br>" + str ( iiiIii1iIi1Ii . mpriority ) + "/" + str ( iiiIii1iIi1Ii . mweight ) )
  if 10 - 10: I1Ii111
  if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
  if ( OOOO0oo0 != "" ) : OOOO0oo0 = ""
  if ( Oo000o != "" ) : Oo000o , I1I11i , O0OOO0 = ( "" , "" , "" )
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
  Oo0 = "-f inet" if lisp . lisp_is_macos ( ) else "-4"
  oOOO = commands . getoutput ( "netstat -rn {}" . format ( Oo0 ) )
  O0O0O0OO00oo = lisp . lisp_span ( O0O0O0OO00oo , oOOO )
  if 62 - 62: Ii1I - oO0o % iIii1I11I1II1
  ooOOO = lisp . lisp_myrlocs [ 1 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 1 ] != None else "not found"
  if 97 - 97: i1IIi * I1Ii111 . II111iiii
  ooOOO = lisp . lisp_print_cour ( ooOOO )
  Oo0 = "-f inet6" if lisp . lisp_is_macos ( ) else "-6"
  oOOO = commands . getoutput ( "netstat -rn {}" . format ( Oo0 ) )
  ooOOO = lisp . lisp_span ( ooOOO , oOOO )
  if 62 - 62: OoooooooOO . Ii1I
  II1i = "<i>Local RLOCs found on interface </i>{}<i>, " + "IPv4: </i>{}<i>, IPv6: </i>{}"
  if 28 - 28: oO0o . oO0o . iIii1I11I1II1 . OOooOOo . I1ii11iIi11i * i11iIiiIii
  output += lisp . lisp_print_sans ( II1i ) . format ( iIIiI , O0O0O0OO00oo , ooOOO )
  if 72 - 72: I11i
 output += "<br>"
 return ( output )
 if 26 - 26: IiII % Oo0Ooo
 if 72 - 72: O0 + o0oOOo0O0Ooo + I1IiiI / Oo0Ooo
 if 83 - 83: IiII - I1IiiI . Ii1I
 if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
 if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
 if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
 if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
def lisp_display_nat_info ( output , dc , dodns ) :
 iII1ii11III = len ( lisp . lisp_nat_state_info )
 if ( iII1ii11III == 0 ) : return ( output )
 if 92 - 92: OoO0O00 - I1ii11iIi11i + iIii1I11I1II1 % o0oOOo0O0Ooo
 I1I1i1 = "{} entries in the NAT-traversal port table" . format ( iII1ii11III )
 ooooooO0O = lisp . lisp_span ( "NAT-Traversed xTR Information:" , I1I1i1 )
 if 64 - 64: IiII * iIii1I11I1II1 . I1ii11iIi11i / I11i * iIii1I11I1II1
 if ( dodns ) :
  output += lisp_table_header ( ooooooO0O , "xTR Hostname" ,
 "Translated<br>Address" , "Translated<br>{} Port" . format ( dc ) ,
 "Last<br>Info-Request" , "NAT DNS Name" )
 else :
  output += lisp_table_header ( ooooooO0O , "xTR Hostname" ,
 "Translated<br>Address" , "Translated<br>{} Port" . format ( dc ) ,
 "Last<br>Info-Request" )
  if 4 - 4: ooOoO0o % IiII . I1Ii111
  if 91 - 91: I1ii11iIi11i + iIii1I11I1II1 % IiII
 for O0o0OOOO0 in lisp . lisp_nat_state_info . values ( ) :
  for ii1 in O0o0OOOO0 :
   II = ii1 . address
   OOoO000O0OO = ii1 . uptime
   ii11 = ii1 . hostname
   IiIi1 = ii1 . port
   if 92 - 92: IiII . Oo0Ooo - Oo0Ooo - o0oOOo0O0Ooo + I1Ii111 - O0
   if ( ii1 . timed_out ( ) ) :
    OOoO000O0OO = lisp . red ( lisp . lisp_print_elapsed ( OOoO000O0OO ) , True )
   else :
    OOoO000O0OO = lisp . lisp_print_elapsed ( OOoO000O0OO )
    if 30 - 30: IiII - iII111i - OoO0O00
    if 33 - 33: iIii1I11I1II1 / iII111i
   if ( dodns ) :
    try :
     OOOO = socket . gethostbyaddr ( II ) [ 0 ]
    except :
     OOOO = "?"
     if 10 - 10: II111iiii . OoO0O00
    output += lisp_table_row ( ii11 , II , IiIi1 , OOoO000O0OO , OOOO )
   else :
    output += lisp_table_row ( ii11 , II , IiIi1 , OOoO000O0OO )
    if 89 - 89: ooOoO0o * Ii1I
    if 93 - 93: i1IIi . Ii1I * I1Ii111 . ooOoO0o
    if 54 - 54: iII111i . i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo % iII111i
    if 30 - 30: I11i
 output += lisp_table_footer ( )
 return ( output )
 if 85 - 85: II111iiii + ooOoO0o * I11i
 if 12 - 12: Ii1I . I1IiiI % o0oOOo0O0Ooo
 if 28 - 28: Ii1I - I1IiiI % OoO0O00 * I1Ii111
 if 80 - 80: OOooOOo * IiII
 if 4 - 4: iIii1I11I1II1 . I1Ii111 + II111iiii % OoooooooOO
 if 82 - 82: OoooooooOO / ooOoO0o * I11i * O0 . I1ii11iIi11i
 if 21 - 21: II111iiii + Oo0Ooo
def lisp_itr_rtr_show_command ( parameter , itr_or_rtr , lisp_threads , dns = False ) :
 if 59 - 59: OOooOOo + I1IiiI / II111iiii / OoOoOO00
 if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
 if 76 - 76: I1IiiI * OOooOOo
 if 12 - 12: iIii1I11I1II1 / I11i % Ii1I
 if ( parameter != "" ) :
  return ( lisp_show_map_cache_lookup ( parameter ) )
  if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
  if 27 - 27: OoO0O00 + Oo0Ooo
 i1iiI11I = ""
 if 92 - 92: I1IiiI % iII111i
 if 31 - 31: OoooooooOO - oO0o / I1Ii111
 if 62 - 62: i11iIiiIii - I11i
 if 81 - 81: I11i
 i1iiI11I = lisp_show_myrlocs ( i1iiI11I )
 if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
 if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
 if 31 - 31: i1IIi % II111iiii
 if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
 if ( itr_or_rtr == "RTR" ) :
  i1iiI11I = lisp_show_decap_stats ( i1iiI11I , itr_or_rtr )
  if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
  if 3 - 3: II111iiii / OOooOOo
  if 48 - 48: ooOoO0o . I1ii11iIi11i
  if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
  if 24 - 24: oO0o - iII111i / ooOoO0o
 if ( len ( lisp_threads ) > 1 ) :
  OoI1IiiiIiI = [ ]
  for i111iI1i1iI in range ( len ( lisp_threads ) ) :
   iIiiII1Ii1ii = lisp_threads [ i111iI1i1iI ]
   OoI1IiiiIiI . append ( "{} Input Stats<br>queue-size: {}" . format ( iIiiII1Ii1ii . thread_name ,
 iIiiII1Ii1ii . input_queue . qsize ( ) ) )
   if 34 - 34: I1IiiI
  i1iiI11I += lisp_table_header ( "LISP-RTR Forwarding Stats:" , * OoI1IiiiIiI )
  if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
  OoI1IiiiIiI = [ ]
  for i111iI1i1iI in range ( len ( lisp_threads ) ) :
   iIiiII1Ii1ii = lisp_threads [ i111iI1i1iI ]
   OoI1IiiiIiI . append ( iIiiII1Ii1ii . input_stats . get_stats ( False , True ) )
   if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
  i1iiI11I += lisp_table_row ( * OoI1IiiiIiI )
  i1iiI11I += lisp_table_footer ( )
  if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
  if 98 - 98: OoO0O00
 I1IIiIi = lisp . lisp_decent_dns_suffix
 if ( I1IIiIi == None ) :
  I1IIiIi = ":"
 else :
  I1IIiIi = "&nbsp;(dns-suffix '{}'):" . format ( I1IIiIi )
  if 93 - 93: oO0o - OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  if 52 - 52: I1Ii111 + I1Ii111
  if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
  if 54 - 54: OoOoOO00 . OoooooooOO
  if 36 - 36: oO0o / II111iiii * IiII % I1ii11iIi11i
 I1I1i1 = "{} map-resolvers configured" . format ( len ( lisp . lisp_map_resolvers_list ) )
 if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
 ooooooO0O = "LISP-{} Configured Map-Resolvers{}" . format ( itr_or_rtr , I1IIiIi )
 ooooooO0O = lisp . lisp_span ( ooooooO0O , I1I1i1 )
 if 28 - 28: Ii1I . I1ii11iIi11i
 i1iiI11I += lisp_table_header ( ooooooO0O , "Map-Resolver" , "Last Used" ,
 "Map-Requests<br>Sent" , "Negative Map-Replies<br>Received" ,
 "Last Negative<br>Map-Reply" , "Average RTT" )
 if 77 - 77: I1ii11iIi11i % II111iiii
 for Ii1 in lisp . lisp_map_resolvers_list . values ( ) :
  Ii1 . resolve_dns_name ( )
  o00OoO = "" if Ii1 . mr_name == "all" else Ii1 . mr_name + "<br>"
  Ii1I1i = o00OoO + Ii1 . map_resolver . print_address_no_iid ( )
  if ( Ii1 . dns_name ) : Ii1I1i += "<br>" + Ii1 . dns_name
  if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
  Oo000o = lisp . lisp_print_elapsed ( Ii1 . last_used )
  oOOoOoOO = lisp . lisp_print_elapsed ( Ii1 . last_reply )
  iII11 = 0 if Ii1 . neg_map_replies_received is 0 else float ( Ii1 . total_rtt / Ii1 . neg_map_replies_received )
  if 96 - 96: I11i * I1ii11iIi11i * Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
  iII11 = str ( round ( iII11 , 3 ) ) + " ms"
  if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
  i1iiI11I += lisp_table_row ( Ii1I1i , Oo000o , Ii1 . map_requests_sent ,
 Ii1 . neg_map_replies_received , oOOoOoOO , iII11 )
  if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
 i1iiI11I += lisp_table_footer ( )
 if 1 - 1: Oo0Ooo . II111iiii
 if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
 if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
 if 4 - 4: IiII
 if ( itr_or_rtr == "ITR" ) : i1iiI11I = lisp_show_db_list ( "ITR" , i1iiI11I )
 if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
 if 99 - 99: i11iIiiIii - iII111i
 if 85 - 85: I1Ii111 % I1ii11iIi11i
 if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
 i11IiIiiIIIII = "<br>Enter EID for Map-Cache lookup:"
 if 73 - 73: OoO0O00
 ii11iiII = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 57 - 57: OoOoOO00 - O0 . OoooooooOO % ooOoO0o - Ii1I
 oo0o0O = itr_or_rtr . lower ( )
 if 91 - 91: iIii1I11I1II1 % O0
 i11IiIiiIIIII = '''
         <form action="/lisp/show/{}/map-cache/lookup" method="post">
         <font size="3"><i>{}</i> {}
         <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form>
    ''' . format ( oo0o0O , lisp . lisp_print_sans ( i11IiIiiIIIII ) , ii11iiII )
 if 71 - 71: I1IiiI . i1IIi
 Ii1i = '<a href="/lisp/show/{}/rloc-probing">RLOC State</a>' . format ( oo0o0O )
 if 49 - 49: oO0o + oO0o + i11iIiiIii % iII111i
 I1I1 = '<a href="/lisp/show/{}/keys"><br>RLOC Keys</a>' . format ( oo0o0O )
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
 ooooooO0O = "LISP-{} {}:{}" . format ( itr_or_rtr , iIIII1iII1i , lisp . lisp_space ( 4 ) )
 ooooooO0O = lisp . lisp_span ( ooooooO0O , I1I1i1 )
 if 84 - 84: O0 % Ii1I . Ii1I . iII111i * I11i
 if 43 - 43: OoOoOO00 . I1ii11iIi11i % i1IIi
 if 61 - 61: I1IiiI + oO0o % I1Ii111 % iIii1I11I1II1 - OoooooooOO
 if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
 if 83 - 83: ooOoO0o
 ooooooO0O += lisp . lisp_button ( "clear cache" ,
 "/lisp/clear/{}/map-cache" . format ( itr_or_rtr . lower ( ) ) )
 ooooooO0O += i11IiIiiIIIII
 if 43 - 43: OOooOOo
 if 84 - 84: OOooOOo . IiII . iII111i
 i1iiI11I += lisp_table_header ( ooooooO0O , "EID-Prefix or (S,G)" ,
 "Uptime<br>TTL" , "RLOC Record" + I1I1 , "Map-Reply Source" ,
 "RLOC Send Stats" , Ii1i + "<br>RLOC Action" ,
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
 ooooooO0O = "LISP-{} RLOC-Probe Information:" . format ( itr_or_rtr )
 i1iiI11I = lisp_table_header ( ooooooO0O , "RLOC Key State" , "RLOC-Probe State" )
 if 47 - 47: Oo0Ooo * OOooOOo
 for oOoO0O00o in lisp . lisp_rloc_probe_list . values ( ) :
  if 25 - 25: O0 + I11i + OOooOOo * I1ii11iIi11i
  OOOO0oo0 = ""
  for iiI1i , OO0Iii1iIiI111Ii , ooO0oo0000oOo in oOoO0O00o :
   oOOoO0oO00O = lisp . green ( lisp . lisp_print_eid_tuple ( OO0Iii1iIiI111Ii , ooO0oo0000oOo ) , True )
   OOOO0oo0 += lisp . lisp_print_cour ( oOOoO0oO00O ) + "<br>"
   if 72 - 72: OoO0O00 - iIii1I11I1II1 . iII111i / Ii1I
  OOOO0oo0 = ", EIDs ({}):<br>" . format ( len ( oOoO0O00o ) ) + OOOO0oo0
  if 12 - 12: I1IiiI + I1Ii111
  iiI1i , OO0Iii1iIiI111Ii , ooO0oo0000oOo = oOoO0O00o [ 0 ]
  if 80 - 80: oO0o . O0
  if 90 - 90: II111iiii / OoO0O00 / Ii1I
  if 70 - 70: Ii1I - II111iiii . Oo0Ooo / Oo0Ooo
  if 30 - 30: oO0o . OoO0O00 + I11i / iIii1I11I1II1 % Oo0Ooo / oO0o
  Ii11ii1 = lisp . lisp_hex_string ( iiI1i . last_rloc_probe_nonce )
  if ( iiI1i . translated_rloc . not_set ( ) ) :
   iIi11 = iiI1i . rloc . print_address_no_iid ( )
  else :
   iIi11 = "{}{}{}" . format ( iiI1i . translated_rloc . print_address_no_iid ( ) ,
 lisp . bold ( ":" , True ) , iiI1i . translated_port )
   if 100 - 100: OoooooooOO - OoooooooOO + IiII
  iIi11 = lisp . bold ( lisp . lisp_print_cour ( iIi11 ) , True )
  iIiIi1i1Iiii = iiI1i . rloc_name
  if ( iIiIi1i1Iiii != None ) :
   iIiIi1i1Iiii = lisp . bold ( iIiIi1i1Iiii , True )
   iIi11 += ", {}" . format ( lisp . lisp_print_cour ( lisp . blue ( iIiIi1i1Iiii , True ) ) )
   if 78 - 78: Oo0Ooo - I1Ii111 + iII111i * Ii1I * o0oOOo0O0Ooo
  oooOO0OO0 = iiI1i . print_state ( )
  if ( iiI1i . up_state ( ) == False ) : oooOO0OO0 = lisp . red ( iiI1i . print_state ( ) , True )
  iIi11 = "RLOC " + iIi11 + ", {}" . format ( oooOO0OO0 )
  if 23 - 23: Oo0Ooo - O0
  iI111iIi = iIi11 + OOOO0oo0
  if 26 - 26: OOooOOo % OOooOOo / i11iIiiIii + I1ii11iIi11i - O0
  if 20 - 20: I1Ii111 . O0 - I1ii11iIi11i / OoOoOO00 - o0oOOo0O0Ooo
  if 79 - 79: OoooooooOO - iIii1I11I1II1
  if 9 - 9: i1IIi - OoOoOO00
  Oo00o0OOo0OO = lisp . lisp_print_elapsed ( iiI1i . last_rloc_probe )
  Oo00o0OOo0OO = lisp . lisp_print_cour ( Oo00o0OOo0OO )
  I1i1iiIi = lisp . lisp_print_elapsed ( iiI1i . last_rloc_probe_reply )
  I1i1iiIi = lisp . lisp_print_cour ( I1i1iiIi )
  IIi1IiiIi1III = ( "Last probe-request sent: {}, " + "last probe-reply received: {}<br>" ) . format ( Oo00o0OOo0OO , I1i1iiIi )
  if 19 - 19: i1IIi % I1IiiI - iIii1I11I1II1 - oO0o / I1ii11iIi11i
  if 16 - 16: Ii1I
  Ii11ii1 = lisp . lisp_hex_string ( iiI1i . last_rloc_probe_nonce )
  Ii11ii1 = lisp . lisp_print_cour ( "0x" + Ii11ii1 )
  iiIIi1II = iiI1i . print_recent_rloc_probe_rtts ( )
  iiIIi1II = lisp . lisp_print_cour ( iiIIi1II )
  Oo00O00o0 = iiI1i . print_recent_rloc_probe_hops ( )
  Oo00O00o0 = lisp . lisp_print_cour ( Oo00O00o0 )
  IiII1 = iiI1i . print_rloc_probe_hops ( )
  IiII1 = lisp . lisp_print_cour ( IiII1 )
  iiI1i = iiI1i . print_rloc_probe_rtt ( )
  iiI1i = lisp . lisp_print_cour ( iiI1i )
  IIi1IiiIi1III += ( "Nonce: {}, rtt: {}, hops: {}<br>" + "Recent-rtts: {}, recent-hops: {}" ) . format ( Ii11ii1 , iiI1i , IiII1 , iiIIi1II , Oo00O00o0 )
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
 for O00oO0 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ O00oO0 ] [ 0 ]
  if ( O00oO0 == "rloc-probing" ) :
   lisp . lisp_rloc_probing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_rloc_probe_list = { }
   if 94 - 94: iIii1I11I1II1 + IiII
  if ( O00oO0 == "nonce-echoing" ) :
   lisp . lisp_nonce_echoing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_nonce_echo_list = { }
   if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
  if ( O00oO0 == "data-plane-security" ) :
   lisp . lisp_data_plane_security = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) :
    lisp . lisp_crypto_keys_by_nonce = { }
    lisp . lisp_crypto_keys_by_rloc_encap = { }
    lisp . lisp_crypto_keys_by_rloc_decap = { }
    if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
    if 36 - 36: OoOoOO00 . i11iIiiIii
  if ( O00oO0 == "data-plane-logging" ) :
   lisp . lisp_data_plane_logging = ( oo00oO0O0 == "yes" )
   if 81 - 81: Oo0Ooo * iII111i * OoO0O00
  if ( O00oO0 == "frame-logging" ) :
   lisp . lisp_frame_logging = ( oo00oO0O0 == "yes" )
   if 85 - 85: O0 * oO0o
  if ( O00oO0 == "flow-logging" ) :
   lisp . lisp_flow_logging = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "yes" ) : os . system ( "touch ./log-flows" )
   if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
  if ( O00oO0 == "nat-traversal" ) :
   lisp . lisp_nat_traversal = ( oo00oO0O0 == "yes" )
   if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
  if ( O00oO0 == "program-hardware" ) :
   lisp . lisp_program_hardware = ( oo00oO0O0 == "yes" )
   if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
  if ( O00oO0 == "checkpoint-map-cache" ) :
   lisp . lisp_checkpoint_map_cache = ( oo00oO0O0 == "yes" )
   O0oo = lisp . lisp_checkpoint_filename
   if ( oo00oO0O0 == "no" and os . path . exists ( O0oo ) ) :
    os . system ( "rm {}" . format ( O0oo ) )
    if 50 - 50: I1Ii111 - II111iiii
    if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
  if ( O00oO0 == "ipc-data-plane" ) :
   ii1iI11IiIIi = ( oo00oO0O0 == "yes" )
   if ( ii1iI11IiIIi and lisp . lisp_ipc_data_plane == False ) :
    OoI1IiiiIiI = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
    lisp . lisp_ipc_dp_socket = OoI1IiiiIiI
    if 47 - 47: OOooOOo . oO0o + OoOoOO00 % IiII % i1IIi / iIii1I11I1II1
   if ( ii1iI11IiIIi == False and lisp . lisp_ipc_data_plane ) :
    lisp . lisp_ipc_dp_socket . close ( )
    lisp . lisp_ipc_dp_socket = None
    if 95 - 95: O0 . OoO0O00
   lisp . lisp_ipc_data_plane = ii1iI11IiIIi
   if 89 - 89: i1IIi
  if ( O00oO0 == "decentralized-push-xtr" ) :
   lisp . lisp_decent_push_configured = ( oo00oO0O0 == "yes" )
   if 19 - 19: ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
  if ( O00oO0 == "decentralized-pull-xtr-modulus" ) :
   lisp . lisp_decent_modulus = int ( oo00oO0O0 )
   if 14 - 14: I1ii11iIi11i - i11iIiiIii * I1Ii111
  if ( O00oO0 == "decentralized-pull-xtr-dns-suffix" ) :
   lisp . lisp_decent_dns_suffix = oo00oO0O0
   if 39 - 39: OoooooooOO
  if ( O00oO0 == "register-reachable-rtrs" ) :
   lisp . lisp_register_all_rtrs = ( oo00oO0O0 == "no" )
   if 19 - 19: i11iIiiIii
   if 80 - 80: I1IiiI
 return
 if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
 if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
 if 26 - 26: o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
 if 97 - 97: i1IIi
 if 46 - 46: I1ii11iIi11i
 if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
 if 23 - 23: I11i
def lisp_show_json_list ( output ) :
 if 36 - 36: IiII . iII111i - i1IIi + I1Ii111
 ooooooO0O = "Configured JSON Entries:"
 output += lisp_table_header ( ooooooO0O , "JSON Name" , "JSON String" )
 if 54 - 54: OoooooooOO . oO0o - iII111i
 oO0o00o000Oo0 = sorted ( lisp . lisp_json_list )
 for ii1I1iIi in oO0o00o000Oo0 :
  i1iiIiI1Ii1i = lisp . lisp_json_list [ ii1I1iIi ]
  O0o0OOo0o0o = lisp . lisp_print_cour ( i1iiIiI1Ii1i . print_json ( True ) )
  output += lisp_table_row ( ii1I1iIi , O0o0OOo0o0o )
  if 90 - 90: I11i
 output += lisp_table_footer ( )
 return ( output )
 if 95 - 95: OoO0O00
 if 68 - 68: iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00 - II111iiii - iIii1I11I1II1
 if 75 - 75: ooOoO0o . I1IiiI * II111iiii
 if 99 - 99: iIii1I11I1II1 * I1ii11iIi11i + IiII
 if 70 - 70: i1IIi % ooOoO0o . I1ii11iIi11i - IiII + OOooOOo
 if 84 - 84: oO0o + II111iiii * II111iiii % o0oOOo0O0Ooo / iII111i + ooOoO0o
 if 9 - 9: iII111i
def lisp_show_rle_list ( output ) :
 if 25 - 25: OOooOOo - Ii1I . I11i
 ooooooO0O = "Configured Replication List Entries (RLEs):"
 output += lisp_table_header ( ooooooO0O , "RLE Name" , "RLE Nodes" )
 if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
 III1I11II11I = sorted ( lisp . lisp_rle_list )
 for OO in III1I11II11I :
  i11111 = lisp . lisp_rle_list [ OO ]
  output += lisp_table_row ( OO , i11111 . print_rle ( True ) )
  if 3 - 3: I1Ii111 . I11i % II111iiii * I1IiiI % i1IIi * OoO0O00
 output += lisp_table_footer ( )
 return ( output )
 if 5 - 5: II111iiii * i1IIi % Ii1I
 if 55 - 55: I1IiiI + iII111i
 if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
 if 19 - 19: I11i / iII111i + IiII
 if 76 - 76: iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo + OoooooooOO
 if 10 - 10: OoO0O00 * I11i / Oo0Ooo - I1Ii111
 if 11 - 11: IiII % I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - II111iiii
def lisp_show_elp_list ( output ) :
 ooooooO0O = "Configured Explicit Locator Paths (ELPs):"
 output += lisp_table_header ( ooooooO0O , "ELP Name" , "ELP Nodes" )
 if 50 - 50: i1IIi * oO0o / i11iIiiIii / i11iIiiIii / oO0o
 oOO0OO00 = sorted ( lisp . lisp_elp_list )
 for O0oO00oO0o00o in oOO0OO00 :
  oo0O = lisp . lisp_elp_list [ O0oO00oO0o00o ]
  output += lisp_table_row ( O0oO00oO0o00o , oo0O . print_elp ( False ) )
  if 54 - 54: ooOoO0o
 output += lisp_table_footer ( )
 return ( output )
 if 79 - 79: I1IiiI + oO0o % I11i % oO0o
 if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
 if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
 if 99 - 99: o0oOOo0O0Ooo + OOooOOo
 if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
 if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
 if 76 - 76: oO0o / OoOoOO00
def lisp_geo_command ( kv_pair ) :
 if 12 - 12: I1Ii111
 if 58 - 58: OoO0O00 + iIii1I11I1II1 % O0 + I11i + OoOoOO00 * OoooooooOO
 if 41 - 41: oO0o * I1IiiI
 if 76 - 76: oO0o . O0 * OoooooooOO + ooOoO0o
 if ( kv_pair . has_key ( "geo-name" ) == False ) : return
 oo0O00 = kv_pair [ "geo-name" ]
 IiI1 = lisp . lisp_geo ( oo0O00 )
 if 92 - 92: IiII - IiII % iIii1I11I1II1 / iII111i
 if 4 - 4: o0oOOo0O0Ooo
 if 96 - 96: I1IiiI % I1IiiI / o0oOOo0O0Ooo / OoOoOO00 * ooOoO0o - I1Ii111
 if 94 - 94: Oo0Ooo - iIii1I11I1II1 + I1IiiI - i1IIi + OoooooooOO % OoO0O00
 if ( kv_pair . has_key ( "geo-tag" ) == False ) : return
 if 36 - 36: iII111i * I11i * O0 * OOooOOo - o0oOOo0O0Ooo / I1ii11iIi11i
 if 54 - 54: i1IIi - OoO0O00 / OoooooooOO
 if 95 - 95: O0 + iIii1I11I1II1 . I1ii11iIi11i
 if 61 - 61: Ii1I * Ii1I
 O0III1Iiii1i11 = kv_pair [ "geo-tag" ] [ 1 : : ]
 if ( IiI1 . parse_geo_string ( O0III1Iiii1i11 ) == False ) : return
 if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
 if 72 - 72: i1IIi
 if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
 if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
 lisp . lisp_geo_list [ oo0O00 ] = IiI1
 return
 if 89 - 89: IiII - i1IIi - IiII
 if 74 - 74: OoO0O00 % OoO0O00
 if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
 if 91 - 91: I1IiiI / II111iiii * OOooOOo
 if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
 if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
 if 81 - 81: OoO0O00 - iIii1I11I1II1
def lisp_elp_command ( kv_pair ) :
 if 60 - 60: I1Ii111
 oo0O = None
 ooO0IIiIIiiiiiII1 = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for i111iI1i1iI in range ( len ( kv_pair [ "address" ] ) ) :
   iIi1i1II = lisp . lisp_elp_node ( )
   ooO0IIiIIiiiiiII1 . append ( iIi1i1II )
   if 62 - 62: Oo0Ooo * iIii1I11I1II1
   if 11 - 11: I1ii11iIi11i + iII111i
   if 77 - 77: i1IIi
 for O00oO0 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ O00oO0 ]
  if 63 - 63: oO0o . I1Ii111 * II111iiii - oO0o
  if ( O00oO0 == "elp-name" ) :
   oo0O = lisp . lisp_elp ( oo00oO0O0 )
   continue
   if 45 - 45: oO0o % ooOoO0o + I1Ii111 + o0oOOo0O0Ooo . Oo0Ooo
   if 15 - 15: ooOoO0o / IiII * i11iIiiIii + iII111i
  for iIiI1I1II1 in ooO0IIiIIiiiiiII1 :
   O0OO0O = ooO0IIiIIiiiiiII1 . index ( iIiI1I1II1 )
   if ( O0OO0O >= len ( oo00oO0O0 ) ) : O0OO0O = len ( oo00oO0O0 ) - 1
   I11iii1I1Iiii = oo00oO0O0 [ O0OO0O ]
   if ( O00oO0 == "probe" ) : iIiI1I1II1 . probe = ( I11iii1I1Iiii == "yes" )
   if ( O00oO0 == "strict" ) : iIiI1I1II1 . strict = ( I11iii1I1Iiii == "yes" )
   if ( O00oO0 == "eid" ) : iIiI1I1II1 . eid = ( I11iii1I1Iiii == "yes" )
   if ( O00oO0 == "address" ) : iIiI1I1II1 . address . store_address ( I11iii1I1Iiii )
   if 45 - 45: I1IiiI + I11i + i1IIi
   if 22 - 22: IiII / OOooOOo
   if 62 - 62: Ii1I - oO0o + iIii1I11I1II1 / OOooOOo . iII111i / Ii1I
   if 63 - 63: i1IIi
   if 56 - 56: Oo0Ooo
   if 52 - 52: OOooOOo + Oo0Ooo
 if ( oo0O == None ) : return
 if 67 - 67: I1ii11iIi11i % OoooooooOO
 if 41 - 41: OoO0O00 / IiII + I1Ii111 . I1Ii111 / oO0o
 if 74 - 74: Ii1I % i11iIiiIii . O0 * I1IiiI * i1IIi * OoooooooOO
 if 22 - 22: I1Ii111 + iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoooooooOO
 oo0O . elp_nodes = ooO0IIiIIiiiiiII1
 lisp . lisp_elp_list [ oo0O . elp_name ] = oo0O
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
 i11111 = None
 I1I = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for i111iI1i1iI in range ( len ( kv_pair [ "address" ] ) ) :
   o0Oo00 = lisp . lisp_rle_node ( )
   I1I . append ( o0Oo00 )
   if 34 - 34: Ii1I * I1IiiI + I11i * OoOoOO00 - II111iiii
   if 92 - 92: OOooOOo . o0oOOo0O0Ooo / iII111i . iIii1I11I1II1 % Oo0Ooo . OoooooooOO
   if 81 - 81: i11iIiiIii * iII111i . oO0o * oO0o . IiII
 for O00oO0 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ O00oO0 ]
  if 47 - 47: iIii1I11I1II1 % I11i . I11i / O0 . i11iIiiIii * Ii1I
  if ( O00oO0 == "rle-name" ) :
   i11111 = lisp . lisp_rle ( oo00oO0O0 )
   continue
   if 24 - 24: O0
   if 33 - 33: OoooooooOO + oO0o * II111iiii / OOooOOo
  for iIiI1I1II1 in I1I :
   O0OO0O = I1I . index ( iIiI1I1II1 )
   if ( O0OO0O >= len ( oo00oO0O0 ) ) : O0OO0O = len ( oo00oO0O0 ) - 1
   I11iii1I1Iiii = oo00oO0O0 [ O0OO0O ]
   if ( O00oO0 == "level" ) :
    if ( I11iii1I1Iiii == "" ) : I11iii1I1Iiii = "0"
    iIiI1I1II1 . level = int ( I11iii1I1Iiii )
    if 87 - 87: OoooooooOO
   if ( O00oO0 == "address" ) : iIiI1I1II1 . address . store_address ( I11iii1I1Iiii )
   if 1 - 1: iIii1I11I1II1 / o0oOOo0O0Ooo
   if 98 - 98: O0 % I1IiiI / OoooooooOO * I1ii11iIi11i - oO0o
   if 51 - 51: iII111i + I11i
   if 54 - 54: II111iiii * O0 % I1IiiI . I11i
   if 62 - 62: Ii1I . i11iIiiIii % O0 % I1Ii111 - Oo0Ooo
   if 69 - 69: II111iiii . OoOoOO00 * OoOoOO00 % Ii1I + I1IiiI
 if ( i11111 == None ) : return
 if 100 - 100: i11iIiiIii - Oo0Ooo
 if 47 - 47: iII111i * OoOoOO00 * IiII
 if 46 - 46: Ii1I
 if 42 - 42: iIii1I11I1II1
 i11111 . rle_nodes = I1I
 i11111 . build_forwarding_list ( )
 lisp . lisp_rle_list [ i11111 . rle_name ] = i11111
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
  ii1I1iIi = kv_pair [ "json-name" ]
  O0o0OOo0o0o = kv_pair [ "json-string" ]
 except :
  return
  if 98 - 98: i1IIi - iII111i
  if 49 - 49: o0oOOo0O0Ooo . Ii1I . oO0o
 i1iiIiI1Ii1i = lisp . lisp_json ( ii1I1iIi , O0o0OOo0o0o )
 i1iiIiI1Ii1i . add ( )
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
 Ooo00o0oOo0O0O = lisp . lisp_map_cache . lookup_cache ( IIiII , IIi1oo0OO0Oo )
 if ( Ooo00o0oOo0O0O == None ) :
  i1iiI11I += "{} {}" . format ( lisp . lisp_print_sans ( "Lookup not found for" ) ,
 lisp . lisp_print_cour ( eid_str ) )
 else :
  if ( IIiII == I1111IiII1 ) :
   O0o0oo0 = Ooo00o0oOo0O0O . lookup_source_cache ( Ooo000 , i11iI1111ii1I )
   if ( O0o0oo0 ) : Ooo00o0oOo0O0O = O0o0oo0
   if 86 - 86: i11iIiiIii + iIii1I11I1II1
   if 87 - 87: OoO0O00 * OoOoOO00 - Oo0Ooo % OOooOOo * i11iIiiIii
  Oo000o = lisp . lisp_print_elapsed ( Ooo00o0oOo0O0O . uptime )
  i1iiI11I += "{} {} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Exact" if i11iI1111ii1I else "Longest" ) ,
  # OoOoOO00 % II111iiii * II111iiii . I1IiiI
 lisp . lisp_print_sans ( "match lookup for" ) ,
 lisp . lisp_print_cour ( eid_str ) ,
 lisp . lisp_print_sans ( "found" ) ,
 lisp . lisp_print_cour ( Ooo00o0oOo0O0O . print_eid_tuple ( ) ) ,
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
 OOO00o0 = open ( "./lisp.config" , "r" )
 Oo000 = { command : [ ] }
 iiIIi1i111i = { }
 iII = [ ]
 if 55 - 55: iIii1I11I1II1 . IiII - o0oOOo0O0Ooo . I1ii11iIi11i * i1IIi
 ooo = 0
 OOoO = False
 for II1i in OOO00o0 :
  if ( lisp_end_file ( II1i ) ) : break
  if ( lisp_comment ( II1i ) ) : continue
  if 76 - 76: i1IIi + O0 / IiII + i11iIiiIii % I1Ii111 % Oo0Ooo
  if 61 - 61: iIii1I11I1II1 % Ii1I - oO0o * OoooooooOO % II111iiii - Ii1I
  if 44 - 44: O0
  if 9 - 9: oO0o . Oo0Ooo + iII111i + I1IiiI * I1IiiI - I1IiiI
  if 95 - 95: IiII + OOooOOo % oO0o * OOooOOo
  if 58 - 58: OoOoOO00 . o0oOOo0O0Ooo + oO0o
  if ( II1i . find ( command + " {" ) != - 1 ) :
   ooo += 1
   OOoO = True
   continue
   if 26 - 26: II111iiii / o0oOOo0O0Ooo
  if ( OOoO == False ) : continue
  if 32 - 32: I1ii11iIi11i * I1IiiI + o0oOOo0O0Ooo % II111iiii + OOooOOo + Ii1I
  if ( lisp_begin_clause ( II1i ) ) :
   ooo += 1
   oo0OOo0Oo00 = II1i . replace ( " " , "" )
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
  if ( lisp_end_clause ( II1i ) ) :
   ooo -= 1
   if ( ooo ) :
    Oo000 [ command ] . append ( iiIIi1i111i )
    iiIIi1i111i = { }
    continue
    if 27 - 27: OOooOOo * IiII / i11iIiiIii - oO0o + II111iiii
   iII . append ( Oo000 )
   Oo000 = { command : [ ] }
   OOoO = False
   continue
   if 43 - 43: I1ii11iIi11i - II111iiii
   if 56 - 56: I1ii11iIi11i . i1IIi / iII111i % oO0o / O0 * I11i
  II1i = II1i . replace ( " " , "" )
  II1i = II1i . replace ( "\t" , "" )
  II1i = II1i . replace ( "\n" , "" )
  II1i = II1i . replace ( "{" , "" )
  II1i = II1i . split ( "=" )
  oo00oO0O0 = "" if len ( II1i ) == 1 else II1i [ 1 ]
  oOOOooOo0O = II1i [ 0 ]
  if 98 - 98: O0 + iII111i
  if ( len ( iiIIi1i111i ) == 0 ) :
   Oo000 [ command ] . append ( { oOOOooOo0O : oo00oO0O0 } )
  else :
   iiIIi1i111i [ oo0OOo0Oo00 ] [ oOOOooOo0O ] = oo00oO0O0
   if 23 - 23: OoooooooOO . iIii1I11I1II1 / i1IIi
   if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
   if 74 - 74: Oo0Ooo - II111iiii - IiII
 OOO00o0 . close ( )
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
 for II1i in OOO00OOo0o0Oo :
  if ( lisp_begin_clause ( II1i ) == False ) : continue
  if ( II1i . find ( command ) == - 1 ) : continue
  if 6 - 6: ooOoO0o % OoooooooOO * I1Ii111 - IiII
  I1ii = II1i
  for II1i in OOO00OOo0o0Oo :
   I1ii += II1i
   if ( II1i [ 0 ] != "}" ) : continue
   if ( I1ii != clause ) : break
   OOO00OOo0o0Oo . close ( )
   return ( True )
   if 82 - 82: OoOoOO00 . Ii1I
  if ( lisp_end_file ( II1i ) ) : break
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
 o00oO00 = data . keys ( ) [ 0 ]
 if ( o00oO00 not in lisp_commands . keys ( ) ) :
  return ( [ { o00oO00 : [ { "?" : "add/replace" } ] } ] )
  if 72 - 72: i1IIi . o0oOOo0O0Ooo
  if 3 - 3: OoOoOO00 % II111iiii - O0
 oO0o00O = ( o00oO00 in [ "lisp enable" , "lisp debug" , "lisp xtr-parameters" ] )
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
  IiiiI1i = commands . getoutput ( "egrep '{}' ./lisp.config" . format ( o00oO00 ) )
  IiiiI1i = IiiiI1i . split ( "\n" )
  for II1i in IiiiI1i :
   if ( II1i [ 0 : len ( o00oO00 ) ] == o00oO00 ) : I1i1IiiI = False
   if 32 - 32: iII111i + OoOoOO00 . I1Ii111 . i1IIi . OoOoOO00 * ooOoO0o
   if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
   if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
   if 50 - 50: ooOoO0o
   if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
   if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
 O0ooO0oOO = data [ o00oO00 ]
 O0ooO0oOO = lisp_unicode_to_ascii ( O0ooO0oOO )
 Oo000 = o00oO00 + " {\n" if I1i1IiiI else ""
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
 if ( lisp_duplicate_command_clause ( o00oO00 , Oo000 ) ) :
  return ( [ { o00oO00 : [ { "!" : "duplicate" } ] } ] )
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
 for II1i in iii1II11II1 :
  if ( Ooo0o00O0 ) :
   if ( lisp_end_clause ( II1i ) == False ) : continue
   Ooo0o00O0 = False
   continue
   if 1 - 1: Ii1I / OoooooooOO % O0 - i1IIi
   if 67 - 67: I1IiiI - OoO0O00
   if 60 - 60: i1IIi / iIii1I11I1II1 * oO0o + ooOoO0o + OoooooooOO + II111iiii
   if 13 - 13: iIii1I11I1II1 - OOooOOo
   if 14 - 14: ooOoO0o
  if ( iiII1iiI == False and lisp_begin_clause ( II1i ) and
 II1i [ 0 : len ( o00oO00 ) ] == o00oO00 ) :
   if ( oO0o00O == False ) :
    I11i1 . write ( II1i )
    for Ooo0OO00oo in Oo000 : I11i1 . write ( Ooo0OO00oo )
    iiII1iiI = True
    if 21 - 21: I11i
    if 79 - 79: OoO0O00 / OOooOOo - i1IIi + i1IIi - IiII + IiII
    if 67 - 67: OoO0O00 * OoO0O00 / OoooooooOO
    if 79 - 79: o0oOOo0O0Ooo % iIii1I11I1II1 / II111iiii / Ii1I / Ii1I + O0
    if 46 - 46: i1IIi / IiII
    if 84 - 84: OoOoOO00 / iIii1I11I1II1 + oO0o % ooOoO0o + oO0o - iIii1I11I1II1
  if ( lisp_end_file ( II1i ) ) :
   if ( I1i1IiiI ) :
    for Ooo0OO00oo in Oo000 : I11i1 . write ( Ooo0OO00oo )
    if 27 - 27: O0 / o0oOOo0O0Ooo * I1IiiI
   I11i1 . write ( II1i )
   iiII1iiI = True
   break
   if 41 - 41: ooOoO0o
   if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
   if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
   if 1 - 1: I1IiiI . Ii1I
   if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
  I11i1 . write ( II1i )
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  if 21 - 21: O0 * ooOoO0o % OoO0O00
  if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
  if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
  if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
  if ( lisp_begin_clause ( II1i ) and II1i [ 0 : len ( o00oO00 ) ] == o00oO00 ) :
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
 return ( [ { o00oO00 : [ { "!" : "add/replace" } ] } ] )
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
 o00oO00 = data . keys ( ) [ 0 ]
 if ( o00oO00 not in lisp_commands . keys ( ) ) :
  return ( [ { o00oO00 : [ { "?" : "delete" } ] } ] )
  if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
  if 79 - 79: Ii1I + oO0o % ooOoO0o % I1IiiI
  if 68 - 68: II111iiii - OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % II111iiii
  if 53 - 53: iII111i . oO0o / Oo0Ooo . OoO0O00 . i11iIiiIii
  if 60 - 60: II111iiii
 O0ooO0oOO = data [ o00oO00 ]
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
 if ( o00oO00 == "lisp user-account" ) :
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
 ooO0oo = False
 oOo = 0
 for II1i in iii1II11II1 :
  if ( II1i . find ( o00oO00 ) == - 1 ) : continue
  oOo += 1
  if 75 - 75: OoooooooOO
  for II1i in iii1II11II1 :
   if ( lisp_begin_clause ( II1i ) ) : continue
   I1IiII = ( lisp_end_clause ( II1i ) and ooO0oo )
   if ( I1IiII ) : break
   if 85 - 85: I1Ii111 - ooOoO0o - iII111i
   IiIOOo000OOoOO = II1i . replace ( " " , "" )
   IiIOOo000OOoOO = IiIOOo000OOoOO . replace ( "\n" , "" )
   IiIOOo000OOoOO = IiIOOo000OOoOO . replace ( "=" , " = " )
   if 13 - 13: Oo0Ooo
   if ( IiIOOo000OOoOO not in OOOoooooO0oOOoO ) :
    ooO0oo = False
    if ( len ( OOOoooooO0oOOoO ) > 1 ) : break
    continue
    if 70 - 70: iII111i
   ooO0oo = True
   if 51 - 51: O0 - I1ii11iIi11i / I11i * II111iiii + OoO0O00 % I1ii11iIi11i
   I1IiII = ( o00oO00 in i11iII11I1III )
   if ( I1IiII ) : break
   if 58 - 58: oO0o + IiII % iII111i - Ii1I - OOooOOo % Ii1I
   if 86 - 86: o0oOOo0O0Ooo
  if ( I1IiII ) : break
  if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
  if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
 iii1II11II1 . close ( )
 if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
 if ( not ooO0oo ) :
  return ( [ { o00oO00 : [ { "?" : "not-found" } ] } ] )
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
 ooO0oo = False
 for II1i in iii1II11II1 :
  if ( II1i . find ( o00oO00 ) != - 1 ) : oOo -= 1
  if ( oOo == 0 and not ooO0oo ) :
   if ( II1i [ 0 ] == "}" ) : ooO0oo = True
   continue
   if 84 - 84: Ii1I
  I11i1 . write ( II1i )
  if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
  if 9 - 9: iII111i - iII111i
 I11i1 . close ( )
 iii1II11II1 . close ( )
 if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
 os . system ( "cp {} {}" . format ( IiIiiIiii , o0o0o ) )
 os . system ( "rm {}" . format ( IiIiiIiii ) )
 return ( [ { o00oO00 : [ { "!" : "delete" } ] } ] )
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
  oo0OoO = { }
  if 28 - 28: O0 * ooOoO0o - o0oOOo0O0Ooo + iIii1I11I1II1 + oO0o
  if ( type ( I111IIi ) == dict ) :
   lisp_u2a_walk_dict_array ( oo0OoO , I111IIi )
  elif ( type ( I111IIi ) == list ) :
   Oo0oOO00O0 = [ ]
   for I1I11I11I1 in I111IIi :
    i1I11i = { }
    lisp_u2a_walk_dict_array ( i1I11i , I1I11I11I1 )
    Oo0oOO00O0 . append ( i1I11i )
    if 19 - 19: Oo0Ooo + iII111i . OoooooooOO - i1IIi
   oo0OoO = Oo0oOO00O0
  else :
   oo0OoO = { I111IIi . keys ( ) [ 0 ] . encode ( ) : oo0OoO }
   if 96 - 96: iII111i % iII111i % I1Ii111 / I1Ii111 - I1ii11iIi11i
  OO0Ooo0O0OOOo . append ( oo0OoO )
  if 11 - 11: OOooOOo / OoooooooOO * Ii1I
  if 73 - 73: I1Ii111 / ooOoO0o + I1Ii111 / OOooOOo / oO0o + OOooOOo
 if ( oOoOoo0 ) : OO0Ooo0O0OOOo = OO0Ooo0O0OOOo [ 0 ]
 return ( OO0Ooo0O0OOOo )
 if 11 - 11: iIii1I11I1II1 * Oo0Ooo % oO0o . ooOoO0o - I1ii11iIi11i * i11iIiiIii
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
def lisp_replace_db_list ( db ) :
 O0OO0O = - 1
 for iII11II in lisp . lisp_db_list :
  if ( db . match_eid_tuple ( iII11II ) ) :
   O0OO0O = lisp . lisp_db_list . index ( iII11II )
   break
   if 59 - 59: I1IiiI % oO0o % iIii1I11I1II1 / I1Ii111 * iII111i * OoO0O00
   if 34 - 34: IiII
 if ( O0OO0O == - 1 ) : return ( False )
 if 89 - 89: iII111i
 if 38 - 38: i1IIi - ooOoO0o
 if 14 - 14: iII111i * IiII % i11iIiiIii . i11iIiiIii + oO0o / I1ii11iIi11i
 if 19 - 19: I1IiiI
 if 86 - 86: I1ii11iIi11i + OoOoOO00 * IiII + ooOoO0o
 if ( lisp . lisp_nat_traversal and lisp . lisp_i_am_etr ) :
  for iiiIii1iIi1Ii in iII11II . rloc_set :
   if ( iiiIii1iIi1Ii . is_rloc_translated ( ) == False ) : continue
   iiI1i = db . get_rloc_by_interface ( iiiIii1iIi1Ii . interface )
   if ( iiI1i == None ) : continue
   iiI1i . store_translated_rloc ( iiiIii1iIi1Ii . translated_rloc , iiiIii1iIi1Ii . translated_port )
   iiI1i . rloc_name = iiiIii1iIi1Ii . rloc_name
   if 23 - 23: OoO0O00 - oO0o * iIii1I11I1II1
   if 1 - 1: I11i - Oo0Ooo / i1IIi
   if 96 - 96: OoooooooOO % iII111i - OoooooooOO % O0
 lisp . lisp_db_list [ O0OO0O ] = db
 return ( True )
 if 21 - 21: iII111i
 if 1 - 1: Oo0Ooo . i11iIiiIii
 if 9 - 9: OoooooooOO / I11i
 if 47 - 47: OoooooooOO
 if 48 - 48: OoOoOO00 . IiII % I1IiiI + I11i
 if 37 - 37: Oo0Ooo + I1Ii111 * oO0o / o0oOOo0O0Ooo
 if 78 - 78: IiII + I11i - o0oOOo0O0Ooo + OoO0O00 / iIii1I11I1II1
 if 47 - 47: OOooOOo
def lisp_database_mapping_command ( kv_pair , ephem_port = None ) :
 I1I111iiII = [ ]
 iI1i1I11i = [ ]
 if ( kv_pair . has_key ( "address" ) ) :
  for i111iI1i1iI in range ( len ( kv_pair [ "address" ] ) ) :
   iiiIii1iIi1Ii = lisp . lisp_rloc ( )
   iI1i1I11i . append ( iiiIii1iIi1Ii )
   if 62 - 62: ooOoO0o * Ii1I % I1ii11iIi11i - i1IIi - I1ii11iIi11i
   if 24 - 24: OOooOOo
   if 71 - 71: IiII - i1IIi
 O0oo0oOo = [ ]
 for i111iI1i1iI in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  oOO00o0 = lisp . lisp_mapping ( "" , "" , iI1i1I11i )
  O0oo0oOo . append ( oOO00o0 )
  if 29 - 29: II111iiii - iII111i / oO0o % OoooooooOO % iII111i + IiII
  if 44 - 44: O0 / O0
 for O00oO0 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ O00oO0 ]
  if ( O00oO0 == "mr-name" ) :
   for i111iI1i1iI in range ( len ( O0oo0oOo ) ) :
    oOO00o0 = O0oo0oOo [ i111iI1i1iI ]
    oOO00o0 . use_mr_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ i111iI1i1iI ]
    if 25 - 25: o0oOOo0O0Ooo + iIii1I11I1II1 + IiII + I1ii11iIi11i / I1Ii111 - i1IIi
    if 15 - 15: O0 % Oo0Ooo % IiII % OoooooooOO - IiII
  if ( O00oO0 == "ms-name" ) :
   for i111iI1i1iI in range ( len ( O0oo0oOo ) ) :
    oOO00o0 = O0oo0oOo [ i111iI1i1iI ]
    oOO00o0 . use_ms_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ i111iI1i1iI ]
    if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
    if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
  if ( O00oO0 == "instance-id" ) :
   for i111iI1i1iI in range ( len ( O0oo0oOo ) ) :
    oOO00o0 = O0oo0oOo [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    I11iii1I1Iiii = [ "0" ] if ( I11iii1I1Iiii == "" ) else I11iii1I1Iiii . split ( )
    for Ooo0 in I11iii1I1Iiii : I11iii1I1Iiii [ I11iii1I1Iiii . index ( Ooo0 ) ] = int ( Ooo0 )
    oOO00o0 . eid . instance_id = I11iii1I1Iiii [ 0 ]
    oOO00o0 . eid . iid_list = I11iii1I1Iiii [ 1 : : ]
    oOO00o0 . group . instance_id = I11iii1I1Iiii [ 0 ]
    if 65 - 65: I1ii11iIi11i * O0 . OoooooooOO * I11i / IiII
    if 87 - 87: iIii1I11I1II1
  if ( O00oO0 == "secondary-instance-id" ) :
   for i111iI1i1iI in range ( len ( O0oo0oOo ) ) :
    oOO00o0 = O0oo0oOo [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii == "" ) : continue
    oOO00o0 . secondary_iid = int ( I11iii1I1Iiii )
    if 58 - 58: I1ii11iIi11i % i11iIiiIii + OoOoOO00 / I11i - OoooooooOO
    if 62 - 62: OoO0O00 . OoOoOO00
  if ( O00oO0 == "eid-prefix" ) :
   for i111iI1i1iI in range ( len ( O0oo0oOo ) ) :
    oOO00o0 = O0oo0oOo [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) : oOO00o0 . eid . store_prefix ( I11iii1I1Iiii )
    if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
    if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  if ( O00oO0 == "group-prefix" ) :
   for i111iI1i1iI in range ( len ( O0oo0oOo ) ) :
    oOO00o0 = O0oo0oOo [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) : oOO00o0 . group . store_prefix ( I11iii1I1Iiii )
    if 41 - 41: OoooooooOO
    if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
  if ( O00oO0 == "dynamic-eid" ) :
   for i111iI1i1iI in range ( len ( O0oo0oOo ) ) :
    oOO00o0 = O0oo0oOo [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii == "yes" ) : oOO00o0 . dynamic_eids = { }
    if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
    if 78 - 78: Ii1I
  if ( O00oO0 == "signature-eid" ) :
   for i111iI1i1iI in range ( len ( O0oo0oOo ) ) :
    oOO00o0 = O0oo0oOo [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    oOO00o0 . signature_eid = ( I11iii1I1Iiii == "yes" )
    if 29 - 29: II111iiii
    if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
    if 84 - 84: Oo0Ooo % I11i * O0 * I11i
  if ( O00oO0 == "priority" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii == "" ) : I11iii1I1Iiii = "0"
    iiiIii1iIi1Ii . priority = int ( I11iii1I1Iiii )
    if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
    if 12 - 12: Oo0Ooo + I1IiiI
  if ( O00oO0 == "weight" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii == "" ) : I11iii1I1Iiii = "0"
    iiiIii1iIi1Ii . weight = int ( I11iii1I1Iiii )
    if 37 - 37: i1IIi * i11iIiiIii
    if 95 - 95: i11iIiiIii % I1Ii111 * Oo0Ooo + i1IIi . O0 + I1ii11iIi11i
  if ( O00oO0 == "address" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) : iiiIii1iIi1Ii . rloc . store_address ( I11iii1I1Iiii )
    if 7 - 7: OoO0O00 * i11iIiiIii * iIii1I11I1II1 / OOooOOo / I1Ii111
    if 35 - 35: iII111i * OOooOOo
  if ( O00oO0 == "interface" ) :
   ii11 = lisp . lisp_hostname
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) :
     iiiIii1iIi1Ii . interface = I11iii1I1Iiii
     II = lisp . lisp_get_interface_address ( I11iii1I1Iiii )
     if ( II ) :
      iiiIii1iIi1Ii . rloc . copy_address ( II )
      lisp . lisp_myrlocs [ 0 ] = II
      if 65 - 65: II111iiii % i1IIi
     iiiIii1iIi1Ii . rloc_name = ii11
     I1I111iiII . append ( iiiIii1iIi1Ii )
     if 13 - 13: OoO0O00 * I1Ii111 + Oo0Ooo - IiII
     if 31 - 31: OoO0O00
     if 68 - 68: OoO0O00 + i1IIi / iIii1I11I1II1 + II111iiii * iIii1I11I1II1 + I1ii11iIi11i
  if ( O00oO0 == "elp-name" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) : iiiIii1iIi1Ii . elp_name = I11iii1I1Iiii
    if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
    if 9 - 9: o0oOOo0O0Ooo
  if ( O00oO0 == "rle-name" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) : iiiIii1iIi1Ii . rle_name = I11iii1I1Iiii
    if 55 - 55: OOooOOo % iIii1I11I1II1 + I11i . ooOoO0o
    if 71 - 71: i11iIiiIii / i1IIi + OoOoOO00
  if ( O00oO0 == "json-name" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) : iiiIii1iIi1Ii . json_name = I11iii1I1Iiii
    if 23 - 23: i11iIiiIii
    if 88 - 88: II111iiii - iII111i / OoooooooOO
  if ( O00oO0 == "geo-name" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) : iiiIii1iIi1Ii . geo_name = I11iii1I1Iiii
    if 71 - 71: I1ii11iIi11i
    if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
  if ( O00oO0 == "rloc-record-name" ) :
   for i111iI1i1iI in range ( len ( iI1i1I11i ) ) :
    iiiIii1iIi1Ii = iI1i1I11i [ i111iI1i1iI ]
    I11iii1I1Iiii = oo00oO0O0 [ i111iI1i1iI ]
    if ( I11iii1I1Iiii != "" ) : iiiIii1iIi1Ii . rloc_name = I11iii1I1Iiii
    if 1 - 1: IiII % i1IIi
    if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
    if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
    if 80 - 80: I1ii11iIi11i
    if 67 - 67: II111iiii
    if 2 - 2: o0oOOo0O0Ooo - O0 * Ii1I % IiII
    if 64 - 64: i1IIi . ooOoO0o
    if 7 - 7: oO0o . iII111i - iII111i / I1Ii111 % Oo0Ooo
    if 61 - 61: oO0o - I1ii11iIi11i / iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
    if 10 - 10: i11iIiiIii / OoOoOO00
 if ( len ( I1I111iiII ) > 1 ) :
  for iiiIii1iIi1Ii in I1I111iiII :
   iiiIii1iIi1Ii . rloc_name = ii11 + "-" + iiiIii1iIi1Ii . interface
   if 27 - 27: I1IiiI / OoooooooOO
   if 74 - 74: I1ii11iIi11i % I1Ii111 - OoO0O00 * I11i . OoooooooOO * OoO0O00
   if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
   if 6 - 6: OOooOOo
   if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
   if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
 for oOO00o0 in O0oo0oOo :
  oOO00o0 . rloc_set = copy . deepcopy ( oOO00o0 . rloc_set )
  oOO00o0 . sort_rloc_set ( )
  oOO00o0 . add_db ( )
  if ( lisp_replace_db_list ( oOO00o0 ) ) : continue
  lisp . lisp_db_list . append ( oOO00o0 )
  if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
  if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
  if 44 - 44: OoooooooOO
  if 82 - 82: OoOoOO00 . OoOoOO00
  if 10 - 10: Oo0Ooo * I1ii11iIi11i . oO0o . OoooooooOO . OOooOOo * I1ii11iIi11i
 lisp . lisp_write_ipc_database_mappings ( ephem_port )
 if 80 - 80: I1Ii111 + I11i . I1Ii111 + OOooOOo
 if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
 if 43 - 43: IiII . OoooooooOO - II111iiii
 if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
 if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
 if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
 if 15 - 15: Ii1I + OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
 lisp . lisp_default_iid = lisp . lisp_db_list [ 0 ] . eid . instance_id
 if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
 if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
 if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
 if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
 if 28 - 28: iIii1I11I1II1 . O0
 if 32 - 32: OoooooooOO
 if 29 - 29: I1ii11iIi11i
 if 41 - 41: Ii1I
 for oOO00o0 in O0oo0oOo :
  if ( oOO00o0 . eid . address == 0 and oOO00o0 . eid . mask_len == 0 ) :
   if ( oOO00o0 . eid . is_ipv4 ( ) or oOO00o0 . eid . is_ipv6 ( ) ) :
    lisp . lisp_pitr = True
    break
    if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
    if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
    if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
  if ( oOO00o0 . dynamic_eids == None ) : continue
  if ( oOO00o0 . eid . is_mac ( ) and oOO00o0 . eid . address == 0 and oOO00o0 . eid . mask_len == 0 ) :
   lisp . lisp_l2_overlay = True
   break
   if 94 - 94: IiII / I1IiiI . II111iiii
   if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
   if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
   if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
   if 49 - 49: I1ii11iIi11i
   if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
   if 18 - 18: Oo0Ooo + IiII
   if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
 iI1I1iii11i = ( lisp . lisp_myrlocs [ 0 ] != None )
 lisp . lisp_get_local_addresses ( )
 if 14 - 14: Ii1I + Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
 if ( lisp . lisp_myrlocs [ 0 ] == None and iI1I1iii11i ) :
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
 ooO0oo = False
 for oOO00o0 in O0oo0oOo :
  if ( oOO00o0 . dynamic_eids == None ) : continue
  IiI1iIIiIi1Ii = oOO00o0 . eid . print_prefix_no_iid ( )
  ooO0oo = lisp . lisp_i_am_itr
  os . system ( "ip route add {} dev ma1" . format ( IiI1iIIiIi1Ii ) )
  if 69 - 69: OOooOOo % I1ii11iIi11i / OoOoOO00 . OOooOOo - IiII
 if ( lisp . lisp_program_hardware and ooO0oo ) :
  O0O0Ooooo000 = "platform trident diag s cpu_control_1 URPF_MISS_TOCPU=1"
  lisp . lisp_send_to_arista ( O0O0Ooooo000 , None )
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
 ooooooO0O = "LISP-{} Configured Database Mappings:" . format ( itr_or_etr )
 ooooooO0O = lisp . lisp_span ( ooooooO0O , I1I1i1 )
 if 49 - 49: O0 . Oo0Ooo / Ii1I
 I1I1 = '<a href="/lisp/show/etr/keys"><br>RLOC Keys</a>'
 if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
 if ( itr_or_etr == "ITR" ) :
  output += lisp_table_header ( ooooooO0O , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Use MR" )
 else :
  output += lisp_table_header ( ooooooO0O , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" + I1I1 , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Receive Stats" ,
 "Map-Replies<br>Sent" , "Use MS" )
  if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
  if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
 for oOO00o0 in lisp . lisp_db_list :
  i1IIiiI1iii1 = lisp . lisp_print_elapsed ( oOO00o0 . uptime )
  o0OoO = oOO00o0 . map_replies_sent
  if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
  if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
  if 63 - 63: oO0o
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  Ooo0O0oO = ""
  if ( oOO00o0 . dynamic_eid_configured ( ) ) :
   I11 = oOO00o0 . eid . print_prefix_url ( )
   iII1ii11III = len ( oOO00o0 . dynamic_eids )
   IiIiiI11i1Ii = itr_or_etr . lower ( )
   Ooo0O0oO = ( "<br><a href='/lisp/show/{}/dynamic-eid/{}'>" + "{} dynamic-eids</a>" ) . format ( IiIiiI11i1Ii , I11 , iII1ii11III )
   if 36 - 36: I1ii11iIi11i - OoooooooOO % ooOoO0o . i11iIiiIii - IiII * Oo0Ooo
   if 14 - 14: OoOoOO00
   if 34 - 34: OoOoOO00 * OoOoOO00
  OoO = True
  for iiiIii1iIi1Ii in oOO00o0 . rloc_set :
   if ( OoO ) :
    o0OoOO0Ooo = oOO00o0 . print_eid_tuple ( )
    o0OoOO0Ooo = oOO00o0 . star_secondary_iid ( o0OoOO0Ooo )
    o0OoOO0Ooo += Ooo0O0oO
    Oo000o = i1IIiiI1iii1
    OoO = False
   else :
    o0OoOO0Ooo , Oo000o , o0OoO = ( "" , "" , "" )
    if 95 - 95: OoO0O00 - IiII % I1Ii111
    if 27 - 27: iIii1I11I1II1 / I1IiiI % OoOoOO00 / I1IiiI * Ii1I
   Ooo0ooo0oo = "" if iiiIii1iIi1Ii . rloc . is_null ( ) else iiiIii1iIi1Ii . rloc . print_address_no_iid ( )
   if 13 - 13: iII111i . iII111i + i11iIiiIii % O0 % I1Ii111 + IiII
   if 42 - 42: i1IIi + iII111i . OoooooooOO + I1ii11iIi11i . I11i / Ii1I
   if ( iiiIii1iIi1Ii . interface != None ) :
    Ooo0ooo0oo += " ({})" . format ( iiiIii1iIi1Ii . interface )
    if 1 - 1: o0oOOo0O0Ooo
   if ( Ooo0ooo0oo != "" ) : Ooo0ooo0oo += "<br>"
   if 95 - 95: OOooOOo / i1IIi % OoO0O00 . I1Ii111 + I1Ii111
   if ( iiiIii1iIi1Ii . translated_rloc . not_set ( ) == False ) :
    Ooo0ooo0oo += "translated RLOC: {}<br>" . format ( iiiIii1iIi1Ii . translated_rloc . print_address_no_iid ( ) )
    if 80 - 80: O0 + I1ii11iIi11i + OOooOOo
    if 95 - 95: I1ii11iIi11i
    if 98 - 98: IiII * iII111i . OoooooooOO . O0
   O00o = iiiIii1iIi1Ii . print_rloc_name ( True )
   if ( O00o != "" ) : Ooo0ooo0oo += O00o + "<br>"
   if 57 - 57: O0 . OoO0O00
   if ( iiiIii1iIi1Ii . geo_name != None ) :
    Ooo0ooo0oo += "geo: " + iiiIii1iIi1Ii . geo_name + "<br>"
    if 32 - 32: ooOoO0o
   if ( iiiIii1iIi1Ii . elp_name != None ) :
    Ooo0ooo0oo += "elp: " + iiiIii1iIi1Ii . elp_name + "<br>"
    if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
   if ( iiiIii1iIi1Ii . rle_name != None ) :
    Ooo0ooo0oo += "rle: " + iiiIii1iIi1Ii . rle_name + "<br>"
    if 57 - 57: I1ii11iIi11i - OoO0O00 * iIii1I11I1II1
   if ( iiiIii1iIi1Ii . json_name != None ) :
    Ooo0ooo0oo += "json: " + iiiIii1iIi1Ii . json_name + "<br>"
    if 26 - 26: OoO0O00 % ooOoO0o % o0oOOo0O0Ooo % OoOoOO00 . iII111i % O0
    if 91 - 91: II111iiii . Oo0Ooo . oO0o - OoooooooOO / OoOoOO00
   if ( itr_or_etr == "ITR" ) :
    output += lisp_table_row ( o0OoOO0Ooo , Oo000o , Ooo0ooo0oo ,
 str ( iiiIii1iIi1Ii . priority ) + "/" + str ( iiiIii1iIi1Ii . weight ) ,
 str ( iiiIii1iIi1Ii . mpriority ) + "/" + str ( iiiIii1iIi1Ii . mweight ) ,
 oOO00o0 . use_mr_name )
   else :
    i11 = iiiIii1iIi1Ii . stats . get_stats ( True , True )
    output += lisp_table_row ( o0OoOO0Ooo , Oo000o , Ooo0ooo0oo ,
 str ( iiiIii1iIi1Ii . priority ) + "/" + str ( iiiIii1iIi1Ii . weight ) ,
 str ( iiiIii1iIi1Ii . mpriority ) + "/" + str ( iiiIii1iIi1Ii . mweight ) , i11 ,
 o0OoO , oOO00o0 . use_ms_name )
    if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
    if 55 - 55: OoO0O00
    if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
 output += lisp_table_footer ( )
 if 32 - 32: Ii1I * oO0o
 if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
 if 28 - 28: Oo0Ooo
 if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
 if ( len ( lisp . lisp_geo_list ) != 0 ) :
  ooooooO0O = "Configured Geo-Coordinates:"
  output += lisp_table_header ( ooooooO0O , "Geo Name" ,
 "Geo-Prefix or Geo-Point" )
  O0oO0 = sorted ( lisp . lisp_geo_list )
  for oo0O00 in O0oO0 :
   IiI1 = lisp . lisp_geo_list [ oo0O00 ]
   output += lisp_table_row ( oo0O00 , IiI1 . print_geo_url ( ) )
   if 74 - 74: IiII - O0 . Ii1I . I1Ii111
  output += lisp_table_footer ( )
  if 10 - 10: I1IiiI . I1Ii111 / O0 % OoooooooOO % I11i . Oo0Ooo
 return ( output )
 if 24 - 24: OOooOOo * OoooooooOO . O0 . OoO0O00 . I1IiiI
 if 80 - 80: O0 * OoO0O00 . I1Ii111 % O0
 if 12 - 12: OoooooooOO % IiII
 if 97 - 97: II111iiii % oO0o - II111iiii . ooOoO0o
 if 50 - 50: iII111i % I1ii11iIi11i + I11i * Oo0Ooo - i11iIiiIii
 if 24 - 24: i11iIiiIii . ooOoO0o + ooOoO0o - i11iIiiIii % OOooOOo
 if 58 - 58: I1IiiI
def lisp_interface_command ( kv_pair ) :
 OO00oOO = None
 OOO00O0oOOoOo = None
 IIIII11i = None
 Oo0oOo0 = None
 OOoO0OooO = None
 IiiOo = None
 iiiIiii11i1i = None
 ooo0O0Oo0O = None
 if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
 for O00oO0 in kv_pair . keys ( ) :
  oo00oO0O0 = kv_pair [ O00oO0 ]
  if ( O00oO0 == "interface-name" ) : OO00oOO = oo00oO0O0
  if ( O00oO0 == "device" ) : OOO00O0oOOoOo = oo00oO0O0
  if ( O00oO0 == "instance-id" ) : IIIII11i = oo00oO0O0
  if ( O00oO0 == "dynamic-eid" ) : Oo0oOo0 = oo00oO0O0
  if ( O00oO0 == "multi-tenant-eid" ) : iiiIiii11i1i = oo00oO0O0
  if ( O00oO0 == "dynamic-eid-device" ) : OOoO0OooO = oo00oO0O0
  if ( O00oO0 == "dynamic-eid-timeout" ) : IiiOo = oo00oO0O0
  if ( O00oO0 == "lisp-nat" ) : ooo0O0Oo0O = ( oo00oO0O0 == "yes" )
  if 93 - 93: ooOoO0o % I1Ii111
  if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
 if ( OOO00O0oOOoOo == None ) : return
 if 43 - 43: ooOoO0o . i1IIi
 if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
 if 45 - 45: I1IiiI
 if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
 if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
 if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
 if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
 if 61 - 61: Oo0Ooo - I1Ii111
 if ( lisp . lisp_myinterfaces . has_key ( OOO00O0oOOoOo ) and iiiIiii11i1i == None ) :
  O0o0oooOo0oo = lisp . lisp_myinterfaces [ OOO00O0oOOoOo ]
 else :
  O0o0oooOo0oo = lisp . lisp_interface ( OOO00O0oOOoOo )
  lisp . lisp_myinterfaces [ OOO00O0oOOoOo ] = O0o0oooOo0oo
  if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
  if 28 - 28: i1IIi / I11i . o0oOOo0O0Ooo
  if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
  if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
  if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
 O0o0oooOo0oo . interface_name = OO00oOO
 if ( IIIII11i != None ) :
  if ( IIIII11i . isdigit ( ) == False ) : IIIII11i = "0"
  O0o0oooOo0oo . instance_id = int ( IIIII11i )
  if 10 - 10: II111iiii . OOooOOo / iII111i
 if ( Oo0oOo0 != None ) :
  O0o0oooOo0oo . dynamic_eid . store_prefix ( Oo0oOo0 )
  O0o0oooOo0oo . dynamic_eid . instance_id = O0o0oooOo0oo . instance_id
  if 35 - 35: iII111i / Oo0Ooo + O0 * iIii1I11I1II1 - O0
 if ( OOoO0OooO != None ) :
  O0o0oooOo0oo . dynamic_eid_device = OOoO0OooO
  if 3 - 3: I1ii11iIi11i
 if ( IiiOo != None ) :
  O0o0oooOo0oo . dynamic_eid_timeout = int ( IiiOo )
  if 42 - 42: I11i % Oo0Ooo + IiII - I11i . iIii1I11I1II1 - Ii1I
 if ( iiiIiii11i1i != None ) :
  O0o0oooOo0oo . multi_tenant_eid . store_prefix ( iiiIiii11i1i )
  O0o0oooOo0oo . multi_tenant_eid . instance_id = int ( O0o0oooOo0oo . instance_id )
  lisp . lisp_multi_tenant_interfaces . append ( O0o0oooOo0oo )
  if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
 if ( ooo0O0Oo0O ) :
  I111I1 = "sudo iptables -t nat -C POSTROUTING -o {} -j MASQUERADE"
  if ( commands . getoutput ( I111I1 . format ( OOO00O0oOOoOo ) ) != "" ) :
   o0oOOOoo0o = lisp . lisp_get_loopback_address ( )
   if ( o0oOOOoo0o ) :
    o00OooO = "sudo iptables -t nat -A POSTROUTING -s {} -j ACCEPT"
    os . system ( o00OooO . format ( o0oOOOoo0o ) )
    if 1 - 1: OoOoOO00 + OoooooooOO . IiII . iIii1I11I1II1
   o00OooO = "sudo iptables -t nat -A POSTROUTING -o {} -j MASQUERADE"
   os . system ( o00OooO . format ( OOO00O0oOOoOo ) )
   os . system ( "sudo sysctl net.ipv4.ip_forward=1" )
   if 30 - 30: i1IIi
   if 42 - 42: iII111i
   if 35 - 35: II111iiii % OOooOOo . oO0o * ooOoO0o
 lisp . lisp_iid_to_interface [ IIIII11i ] = O0o0oooOo0oo
 if 54 - 54: ooOoO0o * I11i - I1Ii111
 if 15 - 15: iII111i / O0
 if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
 if 19 - 19: o0oOOo0O0Ooo . II111iiii / i1IIi
 if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
 if ( "SO_BINDTODEVICE" in dir ( socket ) ) : O0o0oooOo0oo . set_socket ( OOO00O0oOOoOo )
 if ( "PF_PACKET" in dir ( socket ) ) : O0o0oooOo0oo . set_bridge_socket ( OOO00O0oOOoOo )
 if 47 - 47: I1ii11iIi11i * I1IiiI / I1ii11iIi11i + Ii1I * II111iiii
 if 78 - 78: I1Ii111 - i1IIi + OoOoOO00 + Oo0Ooo * I1ii11iIi11i * o0oOOo0O0Ooo
 if 97 - 97: i1IIi
 if 29 - 29: I1IiiI
 lisp . lisp_get_local_addresses ( )
 if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
 if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
 if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
 if 59 - 59: I1Ii111 * iII111i
 if 31 - 31: I11i / O0
 if 57 - 57: i1IIi % ooOoO0o
 if ( Oo0oOo0 != None and lisp . lisp_program_hardware ) :
  O0O0Ooooo000 = "ip verify unicast source reachable-via rx"
  lisp . lisp_send_to_arista ( O0O0Ooooo000 , OOO00O0oOOoOo )
  O0O0Ooooo000 = 'sysctl -w "net.ipv4.conf.{}.rp_filter=0"' . format ( OOO00O0oOOoOo )
  os . system ( O0O0Ooooo000 )
  if 69 - 69: o0oOOo0O0Ooo
  if 69 - 69: I1Ii111
  if 83 - 83: iIii1I11I1II1 . o0oOOo0O0Ooo + I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
  if 90 - 90: Ii1I * iII111i / OOooOOo
  if 68 - 68: OoOoOO00
 lisp . lisp_write_ipc_interfaces ( )
 return
 if 65 - 65: oO0o
 if 82 - 82: o0oOOo0O0Ooo
 if 80 - 80: i1IIi % OoOoOO00 + OoO0O00 - OoooooooOO / iIii1I11I1II1 + I1Ii111
 if 65 - 65: Ii1I
 if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
 if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
 if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
 if 78 - 78: oO0o % OoooooooOO
def lisp_parse_eid_in_url ( command , eid_prefix ) :
 I11iiI1i1 = ""
 if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
 if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
 if 37 - 37: IiII % Ii1I % i1IIi
 if 23 - 23: ooOoO0o - O0 + i11iIiiIii
 if ( eid_prefix == "0--0" ) :
  command = command + "%[0]/0%"
 elif ( eid_prefix . find ( "-name-" ) != - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if ( len ( eid_prefix ) > 4 ) :
   eid_prefix = [ eid_prefix [ 0 ] , "name" , "-" . join ( eid_prefix [ 2 : - 1 ] ) ,
 eid_prefix [ - 1 ] ]
   if 98 - 98: OoooooooOO
   if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
   if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
   if 71 - 71: Ii1I * OoOoOO00
   if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
  OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]'" + eid_prefix [ 2 ] + "'" + "/" + eid_prefix [ 3 ]
  if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
  command = command + "%" + OOOO0oo0 + "%"
 elif ( eid_prefix . count ( "-" ) in [ 9 , 10 ] ) :
  if 87 - 87: OoO0O00 * Oo0Ooo
  if 83 - 83: i1IIi * I1Ii111 - IiII / Ii1I
  if 48 - 48: oO0o . II111iiii - OoOoOO00 % i1IIi . OoOoOO00
  if 32 - 32: Ii1I * I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
  eid_prefix = eid_prefix . split ( "-" )
  OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + "-" . join ( eid_prefix [ 1 : - 1 ] ) + "/" + eid_prefix [ - 1 ]
  if 67 - 67: OoOoOO00 % Oo0Ooo
  command = command + "%" + OOOO0oo0 + "%"
 elif ( eid_prefix . find ( "." ) == - 1 and eid_prefix . find ( ":" ) == - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
  if 73 - 73: I1ii11iIi11i
  if 92 - 92: i11iIiiIii + O0 * I11i
  if 60 - 60: o0oOOo0O0Ooo / Oo0Ooo
  if ( eid_prefix [ 1 ] == "plus" ) :
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]+" + eid_prefix [ 2 ] + "/" + eid_prefix [ 3 ]
   if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
   command = command + "%" + OOOO0oo0 + "%"
  else :
   if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
   if 76 - 76: OoO0O00 * oO0o - OoO0O00
   if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
   if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "-" + eid_prefix [ 2 ] + "-" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
   if 70 - 70: O0 . Ii1I
   if 33 - 33: OOooOOo * Ii1I
   if 64 - 64: i11iIiiIii . iIii1I11I1II1
   if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
   if ( len ( eid_prefix ) == 10 ) :
    I11iiI1i1 = "[" + eid_prefix [ 5 ] + "]" + eid_prefix [ 6 ] + "-" + eid_prefix [ 7 ] + "-" + eid_prefix [ 8 ] + "/" + eid_prefix [ 9 ]
    if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
    command = command + "%" + OOOO0oo0 + "%" + I11iiI1i1
   else :
    command = command + "%" + OOOO0oo0 + "%"
    if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
    if 70 - 70: I11i . I1ii11iIi11i * oO0o
    if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
 else :
  if 23 - 23: I1ii11iIi11i % I11i
  if 18 - 18: OoooooooOO . i1IIi + II111iiii
  if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
  if 34 - 34: I1Ii111 * I11i
  eid_prefix = eid_prefix . split ( "-" )
  if ( eid_prefix [ 1 ] == "*" ) :
   OOOO0oo0 = ""
   I11iiI1i1 = "[" + eid_prefix [ 2 ] + "]" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 31 - 31: IiII . oO0o
  else :
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "/" + eid_prefix [ 2 ]
   if 40 - 40: Ii1I - I11i / II111iiii * i1IIi + IiII * II111iiii
   if ( len ( eid_prefix ) == 6 ) :
    I11iiI1i1 = "[" + eid_prefix [ 3 ] + "]" + eid_prefix [ 4 ] + "/" + eid_prefix [ 5 ]
    if 53 - 53: I1ii11iIi11i - i11iIiiIii . OoO0O00 / OoOoOO00 - I1Ii111
    if 99 - 99: Ii1I - IiII - i1IIi / i11iIiiIii . IiII
    if 58 - 58: OOooOOo
  command = command + "%" + OOOO0oo0 + "%" + I11iiI1i1
  if 12 - 12: I1IiiI . o0oOOo0O0Ooo * OoooooooOO
 return ( command )
 if 64 - 64: OoOoOO00 + IiII - i1IIi . II111iiii . OoO0O00
 if 31 - 31: oO0o . iII111i - I11i . iIii1I11I1II1 + I11i . OoOoOO00
 if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
 if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
 if 30 - 30: OoooooooOO % OOooOOo
 if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
 if 81 - 81: iII111i % Ii1I . ooOoO0o
def lisp_show_dynamic_eid_command ( parm ) :
 i1iiI11I = ""
 if ( parm == "" ) : return ( i1iiI11I )
 if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
 Ooo000 = lisp_get_lookup_string ( parm . split ( "%" ) [ 0 ] )
 Ooo000 = Ooo000 [ 0 ]
 if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
 oOO00o0 = lisp . lisp_db_for_lookups . lookup_cache ( Ooo000 , False )
 if ( oOO00o0 == None ) : return ( i1iiI11I )
 if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
 IiIiiI11i1Ii = "ITR" if lisp . lisp_i_am_itr else "ETR"
 OOOO0oo0 = oOO00o0 . print_eid_tuple ( )
 if 20 - 20: ooOoO0o
 ooooooO0O = "LISP-{} Discovered Dynamic EIDs for {}:" . format ( IiIiiI11i1Ii , OOOO0oo0 )
 if 63 - 63: iIii1I11I1II1 . OoO0O00
 if ( IiIiiI11i1Ii == "ITR" ) :
  i1iiI11I = lisp_table_header ( ooooooO0O , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Last Packet" , "Inactivity Timeout" )
 else :
  i1iiI11I = lisp_table_header ( ooooooO0O , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Inactivity Timeout" )
  if 100 - 100: i1IIi * i1IIi
  if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
 for IiI1iIIiIi1Ii in oOO00o0 . dynamic_eids . values ( ) :
  Ooo000 = IiI1iIIiIi1Ii . dynamic_eid . print_address ( )
  ooOO0o0ooOo0 = lisp . lisp_print_elapsed ( IiI1iIIiIi1Ii . uptime )
  i11iii11 = str ( IiI1iIIiIi1Ii . timeout ) + " secs"
  if ( IiIiiI11i1Ii == "ITR" ) :
   I11111i = lisp . lisp_print_elapsed ( IiI1iIIiIi1Ii . last_packet )
   i1iiI11I += lisp_table_row ( Ooo000 , IiI1iIIiIi1Ii . interface , ooOO0o0ooOo0 , I11111i , i11iii11 )
  else :
   i1iiI11I += lisp_table_row ( Ooo000 , IiI1iIIiIi1Ii . interface , ooOO0o0ooOo0 , i11iii11 )
   if 46 - 46: OoooooooOO
   if 80 - 80: O0 * iII111i
 i1iiI11I += lisp_table_footer ( )
 return ( i1iiI11I )
 if 73 - 73: IiII / Ii1I + I1Ii111 . OOooOOo - II111iiii / iIii1I11I1II1
 if 79 - 79: I1Ii111 * Oo0Ooo . o0oOOo0O0Ooo - I1Ii111
 if 16 - 16: I1IiiI - O0 * I1ii11iIi11i . I1ii11iIi11i % OOooOOo
 if 39 - 39: II111iiii / I11i - OoOoOO00 * OoOoOO00 - Ii1I
 if 8 - 8: O0 . i11iIiiIii
 if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
 if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
def lisp_clear_decap_stats ( command ) :
 OOO00 = command . split ( "%" ) [ 1 ]
 lisp . lisp_decap_stats [ OOO00 ] = lisp . lisp_stats ( )
 if 11 - 11: OoooooooOO
 if 91 - 91: i1IIi % OoooooooOO - IiII . iIii1I11I1II1 . OOooOOo / OOooOOo
 if 27 - 27: ooOoO0o + I11i * o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / I1Ii111
 if 2 - 2: o0oOOo0O0Ooo - I1IiiI - i11iIiiIii / OoooooooOO
 if 87 - 87: o0oOOo0O0Ooo + oO0o + OoooooooOO * OOooOOo
 if 50 - 50: Oo0Ooo * i1IIi - I1ii11iIi11i * I1IiiI
 if 24 - 24: OoOoOO00 * Ii1I
def lisp_show_decap_stats ( output , etr_or_rtr ) :
 iI1 = etr_or_rtr . upper ( )
 I11IiI1I11i1i = etr_or_rtr . lower ( )
 if 35 - 35: iII111i
 OoI1IiiiIiI = [ ]
 for oOOOooOo0O in lisp . lisp_decap_stats :
  I1iii111 = "<a href='/lisp/clear/{}/stats/{}'>{}</a>" . format ( I11IiI1I11i1i , oOOOooOo0O , oOOOooOo0O )
  OoI1IiiiIiI . append ( I1iii111 )
  if 22 - 22: I1IiiI
  if 76 - 76: OoO0O00 + I11i + OoO0O00 . I11i % OOooOOo
 oOoOOO = "LISP-{} Decapsulation Stats:" . format ( iI1 )
 output += lisp_table_header ( oOoOOO , * OoI1IiiiIiI )
 if 10 - 10: OOooOOo . Ii1I
 OoI1IiiiIiI = [ ]
 for i11i1i1i in lisp . lisp_decap_stats . values ( ) :
  OoI1IiiiIiI . append ( i11i1i1i . get_stats ( False , True ) )
  if 83 - 83: II111iiii + IiII - o0oOOo0O0Ooo % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 output += lisp_table_row ( * OoI1IiiiIiI )
 output += lisp_table_footer ( )
 return ( output )
 if 100 - 100: Ii1I . iIii1I11I1II1
 if 33 - 33: I1IiiI . iIii1I11I1II1 / i11iIiiIii * Ii1I
 if 18 - 18: OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % ooOoO0o % II111iiii - IiII
 if 75 - 75: OoO0O00 . II111iiii . oO0o / OoO0O00 % iIii1I11I1II1
 if 8 - 8: O0 / II111iiii
 if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
 if 87 - 87: IiII
 if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
def lisp_show_crypto_list ( xtr ) :
 i1iiI11I = ""
 oOo0ooo00OoO = len ( lisp . lisp_crypto_keys_by_nonce ) != 0
 if 88 - 88: oO0o
 if ( lisp . lisp_i_am_itr or lisp . lisp_i_am_rtr ) :
  if ( oOo0ooo00OoO ) :
   ooooooO0O = "LISP-{} Nonce Crypto State" . format ( xtr )
   i1iiI11I += lisp_table_header ( ooooooO0O , "Nonce" , "Uptime" , "Key-ID" ,
 "Key Material" )
   for oOOOooOo0O in lisp . lisp_crypto_keys_by_nonce :
    iI111iIi = "0x" + lisp . lisp_hex_string ( oOOOooOo0O )
    oo00oO0O0 = lisp . lisp_crypto_keys_by_nonce [ oOOOooOo0O ]
    for iIi1 in oo00oO0O0 :
     if ( iIi1 == None ) : continue
     OO0IiIII1111iI = lisp . lisp_print_elapsed ( iIi1 . uptime )
     I1I1 = iIi1 . print_keys ( False )
     i1iiI11I += lisp_table_row ( iI111iIi , OO0IiIII1111iI , iIi1 . key_id , I1I1 )
     iI111iIi = ""
     if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
     if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
   i1iiI11I += lisp_table_footer ( )
   if 80 - 80: oO0o / O0
   if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
  ooooooO0O = "LISP-{} Encapsulation Crypto State" . format ( xtr )
  i1iiI11I += lisp_table_header ( ooooooO0O , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for oOOOooOo0O in lisp . lisp_crypto_keys_by_rloc_encap :
   iI111iIi = oOOOooOo0O
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_encap [ oOOOooOo0O ]
   for iIi1 in oo00oO0O0 :
    if ( iIi1 == None ) : continue
    OO0IiIII1111iI = lisp . lisp_print_elapsed ( iIi1 . uptime )
    Oo0OOOOOOOo0O = lisp . lisp_print_elapsed ( iIi1 . last_rekey )
    I1I1 = iIi1 . print_keys ( False )
    i1iiI11I += lisp_table_row ( iI111iIi , OO0IiIII1111iI , Oo0OOOOOOOo0O , iIi1 . rekey_count ,
 iIi1 . use_count , iIi1 . key_id , I1I1 )
    iI111iIi = ""
    if 11 - 11: Ii1I / OoOoOO00 - OoO0O00 + OoOoOO00
    if 51 - 51: ooOoO0o
  i1iiI11I += lisp_table_footer ( )
  if 42 - 42: o0oOOo0O0Ooo - OOooOOo / OOooOOo / iII111i * Oo0Ooo . Oo0Ooo
  if 96 - 96: OoooooooOO + I1ii11iIi11i * O0
 if ( lisp . lisp_i_am_etr or lisp . lisp_i_am_rtr ) :
  ooooooO0O = "LISP-{} Decapsulation Crypto State" . format ( xtr )
  i1iiI11I += lisp_table_header ( ooooooO0O , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for oOOOooOo0O in lisp . lisp_crypto_keys_by_rloc_decap :
   iI111iIi = oOOOooOo0O
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_decap [ oOOOooOo0O ]
   for iIi1 in oo00oO0O0 :
    if ( iIi1 == None ) : continue
    OO0IiIII1111iI = lisp . lisp_print_elapsed ( iIi1 . uptime )
    Oo0OOOOOOOo0O = lisp . lisp_print_elapsed ( iIi1 . last_rekey )
    I1I1 = iIi1 . print_keys ( False )
    i1iiI11I += lisp_table_row ( iI111iIi , OO0IiIII1111iI , Oo0OOOOOOOo0O , iIi1 . rekey_count ,
 iIi1 . use_count , iIi1 . key_id , I1I1 )
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
