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
from __future__ import division
from future import standard_library
standard_library . install_aliases ( )
from builtins import str
from builtins import range
from past . utils import old_div
import lisp
import os
import time
import socket
import bottle
import hmac
import hashlib
import select
import copy
import math
from json import dumps as json_dumps
from subprocess import getoutput
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
LISP_USER_TIMEOUT = 1800
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
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
 "lisp map-server" : [ "lisp-itr" , "lisp-etr" ] ,
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
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
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
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
if 94 - 94: i1IIi % Oo0Ooo
if 68 - 68: Ii1I / O0
if 46 - 46: O0 * II111iiii / IiII * Oo0Ooo * iII111i . I11i
if 62 - 62: i11iIiiIii - II111iiii % I1Ii111 - iIii1I11I1II1 . I1ii11iIi11i . II111iiii
if 61 - 61: oO0o / OoOoOO00 / iII111i * OoO0O00 . II111iiii
if 1 - 1: II111iiii - I1ii11iIi11i % i11iIiiIii + IiII . I1Ii111
if 55 - 55: iIii1I11I1II1 - I1IiiI . Ii1I * IiII * i1IIi / iIii1I11I1II1
def lisp_banner_top ( no_hover ) :
 OOo000 = socket . gethostname ( )
 O0I11i1i11i1I = lisp . lisp_print_cour ( OOo000 )
 if ( no_hover == False ) :
  Iiii = getoutput ( "ifconfig" )
  O0I11i1i11i1I = lisp . lisp_span ( O0I11i1i11i1I , Iiii )
  if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
  if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
 O0I11i1i11i1I = '''
        <a href="/lisp/traceback" style="text-decoration: none">{}</a>
    ''' . format ( O0I11i1i11i1I )
 if 58 - 58: i11iIiiIii % I1Ii111
 O0OoOoo00o = '''
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
    ''' . format ( OOo000 , lisp . green ( "lispers" , True ) , lisp . red ( "net" , True ) ,
 lisp . bold ( "Scalable Open Overlay Networking" , True ) , O0I11i1i11i1I )
 if 31 - 31: II111iiii + OoO0O00 . I1Ii111
 return ( O0OoOoo00o )
 if 68 - 68: I1IiiI - i11iIiiIii - OoO0O00 / OOooOOo - OoO0O00 + i1IIi
 if 48 - 48: OoooooooOO % o0oOOo0O0Ooo . I1IiiI - Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
 if 78 - 78: OoO0O00
 if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
 if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
def lisp_banner_bottom ( ) :
 O0I11i1i11i1I = socket . gethostname ( )
 OoooooOoo = getoutput ( "date" )
 OO = lisp . lisp_print_elapsed ( lisp . lisp_uptime )
 if 55 - 55: OoO0O00 / I1ii11iIi11i * OOooOOo
 O0OoOoo00o = '''<br><hr style="border: none; border-bottom: 1px solid gray;">
        <i><font size="2">{} - Uptime 
        {}, Version {}<br>Copyright 2013-2019 - all rights reserved by
        <a href="http://www.lispers.net"><b>lispers.net</b></a> LLC<br>
        Features/Bugs go to <a href=
"mailto:support@lispers.net?subject=lispers.net v{} bug-report from '{}'">
        support@lispers.net</a></i></font><br><br>
    ''' . format ( OoooooOoo , OO , lisp . bold ( lisp . lisp_version , True ) ,
 lisp . lisp_version , O0I11i1i11i1I )
 if 86 - 86: i11iIiiIii + Ii1I + ooOoO0o * I11i + o0oOOo0O0Ooo
 return ( O0OoOoo00o )
 if 61 - 61: OoO0O00 / i11iIiiIii
 if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - I1ii11iIi11i + i11iIiiIii
 if 65 - 65: OoOoOO00
 if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
 if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
 if 100 - 100: Ii1I - Ii1I - I1Ii111
 if 20 - 20: OoooooooOO
def lisp_show_wrapper ( output ) :
 return ( lisp_banner_top ( False ) + output + lisp_banner_bottom ( ) )
 if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
 if 97 - 97: i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 if 61 - 61: ooOoO0o
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
def lisp_table_header ( title , * args ) :
 o0o0oOOOo0oo = '''
        <font face="Sans-Serif"><h3><i>{}</i></h3></font>
        <table border="1" cellspacing="3x" cellpadding="5x">
        <tr>
    ''' . format ( title )
 if 80 - 80: I11i * i11iIiiIii / I1Ii111
 for I11II1i in args :
  o0o0oOOOo0oo += '''
            <td><font face="Sans-Serif"><b>{}</b></font></td>
        ''' . format ( I11II1i )
  if 23 - 23: I1ii11iIi11i / o0oOOo0O0Ooo + I11i + I11i / II111iiii
 o0o0oOOOo0oo += "</tr>"
 return ( o0o0oOOOo0oo )
 if 26 - 26: OoooooooOO
 if 12 - 12: OoooooooOO % OoOoOO00 / ooOoO0o % o0oOOo0O0Ooo
 if 29 - 29: OoooooooOO
 if 23 - 23: o0oOOo0O0Ooo . II111iiii
 if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
 if 45 - 45: I1Ii111 . OoOoOO00
 if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
def lisp_table_row ( * args ) :
 o0o0oOOOo0oo = "<tr>"
 for I11II1i in args :
  o0o0oOOOo0oo += '''
            <td><font face="Sans-Serif">{}</font></td>
        ''' . format ( I11II1i )
  if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
 o0o0oOOOo0oo += "</tr>"
 return ( o0o0oOOOo0oo )
 if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
 if 8 - 8: OoOoOO00
 if 60 - 60: I11i / I11i
 if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
 if 83 - 83: OoooooooOO
 if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 if 4 - 4: II111iiii / ooOoO0o . iII111i
def lisp_table_footer ( ) :
 return ( "</table>" )
 if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 if 50 - 50: I1IiiI
 if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
 if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
 if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
 if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
def lisp_write_last_changed_date ( new , line ) :
 O0O0O = getoutput ( "date" )
 oO0Oo = line . find ( ":" )
 line = line [ 0 : oO0Oo + 1 ] + " " + O0O0O + "\n"
 new . write ( line )
 return
 if 54 - 54: o0oOOo0O0Ooo - I1IiiI + OoooooooOO
 if 70 - 70: Ii1I / I11i . iII111i % Oo0Ooo
 if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . IiII - OoO0O00 * o0oOOo0O0Ooo
 if 46 - 46: OOooOOo + OoOoOO00 . I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
 if 44 - 44: oO0o
 if 88 - 88: I1Ii111 % Ii1I . II111iiii
 if 38 - 38: o0oOOo0O0Ooo
def lisp_comment ( line ) :
 return ( True if line [ 0 ] == "#" else False )
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
 if 26 - 26: iII111i
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
 if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
 if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
 if 91 - 91: oO0o % Oo0Ooo
 if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
def lisp_begin_clause ( line ) :
 return ( False if line . find ( "{" ) == - 1 else True )
 if 31 - 31: I11i - II111iiii . I11i
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
def lisp_end_clause ( line ) :
 return ( False if line . find ( "}" ) == - 1 else True )
 if 92 - 92: iII111i . I1Ii111
 if 31 - 31: I1Ii111 . OoOoOO00 / O0
 if 89 - 89: OoOoOO00
 if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
 if 4 - 4: ooOoO0o + O0 * OOooOOo
 if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
 if 25 - 25: I1ii11iIi11i
 if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
def lisp_end_file ( line ) :
 return ( True if ( line [ 0 : 10 ] == "#---------" and line [ - 2 ] == "#" ) else False )
 if 13 - 13: OOooOOo / i11iIiiIii
 if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
 if 52 - 52: o0oOOo0O0Ooo
 if 95 - 95: Ii1I
 if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
 if 61 - 61: II111iiii
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
def lisp_write_error ( line , error ) :
 O0oOoOOOoOO = "%>>> " + line + " <<< " + error + "\n"
 return ( O0oOoOOOoOO )
 if 38 - 38: I1Ii111
 if 7 - 7: O0 . iII111i % I1ii11iIi11i - I1IiiI - iIii1I11I1II1
 if 36 - 36: IiII % ooOoO0o % Oo0Ooo - I1ii11iIi11i
 if 22 - 22: iIii1I11I1II1 / Oo0Ooo * I1ii11iIi11i % iII111i
 if 85 - 85: oO0o % i11iIiiIii - iII111i * OoooooooOO / I1IiiI % I1IiiI
 if 1 - 1: OoO0O00 - oO0o . I11i . OoO0O00 / Oo0Ooo + I11i
 if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
 if 49 - 49: Ii1I / OoO0O00 . II111iiii
def lisp_write_line ( line ) :
 return ( "#" + line + "\n" )
 if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
 if 31 - 31: II111iiii . I1IiiI
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
 if 92 - 92: iII111i
 if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
def lisp_not_supported ( ) :
 return ( lisp_show_wrapper ( "" ) )
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % I1Ii111
def lisp_hash_password ( plaintext ) :
 ooO00OO0 = hmac . new ( "lispers.net" , plaintext , hashlib . sha1 ) . hexdigest ( )
 return ( ooO00OO0 )
 if 31 - 31: iII111i % iII111i % I11i
 if 69 - 69: OoO0O00 - Oo0Ooo + i1IIi / I1Ii111
 if 49 - 49: O0 . iII111i
 if 11 - 11: IiII * I1IiiI . iIii1I11I1II1 % OoooooooOO + iII111i
 if 78 - 78: OoO0O00 . OOooOOo + OoO0O00 / I11i / OoO0O00
 if 54 - 54: OoOoOO00 % iII111i
 if 37 - 37: OoOoOO00 * Oo0Ooo / ooOoO0o - iII111i % II111iiii . oO0o
 if 88 - 88: iII111i . II111iiii * II111iiii % I1Ii111
 if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 if 53 - 53: II111iiii
 if 31 - 31: OoO0O00
def lisp_validate_input_address_string ( input_str ) :
 o0O = input_str
 IiIIii1iII1II = None
 if ( input_str . find ( "->" ) != - 1 ) :
  Iii1I1I11iiI1 = input_str . split ( "->" )
  o0O = Iii1I1I11iiI1 [ 0 ]
  IiIIii1iII1II = Iii1I1I11iiI1 [ 1 ]
  if 18 - 18: OOooOOo + iII111i - Ii1I . II111iiii + i11iIiiIii
  if 20 - 20: I1Ii111
 Oo0oO00o = lisp_valid_iid_format ( o0O )
 if ( Oo0oO00o == - 1 ) : return ( False )
 if ( Oo0oO00o == len ( o0O ) ) : return ( True )
 if 13 - 13: I11i * Oo0Ooo * ooOoO0o
 iI11iI1IiiIiI = o0O [ Oo0oO00o : : ]
 if 43 - 43: i11iIiiIii + Oo0Ooo * II111iiii * I1Ii111 * O0
 if ( iI11iI1IiiIiI . find ( "/" ) == - 1 ) :
  o00oO0oo0OO = lisp . lisp_valid_address_format ( "address" , iI11iI1IiiIiI )
 else :
  o00oO0oo0OO = lisp_valid_prefix_format ( iI11iI1IiiIiI )
  if 57 - 57: I1Ii111 % Ii1I + o0oOOo0O0Ooo - Oo0Ooo
 if ( o00oO0oo0OO == False ) : return ( False )
 if 65 - 65: I11i . OoOoOO00
 if 39 - 39: II111iiii / ooOoO0o + I1Ii111 / OoOoOO00
 if 13 - 13: IiII + O0 + iII111i % I1IiiI / o0oOOo0O0Ooo . IiII
 if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
 if ( IiIIii1iII1II == None ) : return ( True )
 if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 Oo0oO00o = lisp_valid_iid_format ( IiIIii1iII1II )
 if ( Oo0oO00o == - 1 ) : return ( False )
 if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 iI11iI1IiiIiI = IiIIii1iII1II [ Oo0oO00o : : ]
 if ( IiIIii1iII1II . find ( "/" ) == - 1 ) :
  o00oO0oo0OO = lisp . lisp_valid_address_format ( "address" , iI11iI1IiiIiI )
 else :
  o00oO0oo0OO = lisp_valid_prefix_format ( iI11iI1IiiIiI )
  if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if ( o00oO0oo0OO == False ) : return ( False )
 return ( True )
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 if 49 - 49: I1IiiI - I11i
 if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
 if 62 - 62: OoooooooOO * I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
def lisp_valid_iid_format ( iid_str ) :
 ooO0OO = iid_str . find ( "[" )
 if ( ooO0OO == - 1 ) : return ( 0 )
 if ( ooO0OO != 0 ) : return ( - 1 )
 if 54 - 54: IiII + Ii1I % OoO0O00 + OoooooooOO - O0 - o0oOOo0O0Ooo
 o0o0O0O00oOOo = iid_str . find ( "]" )
 if ( o0o0O0O00oOOo == - 1 ) : return ( - 1 )
 if 14 - 14: OoOoOO00 + oO0o
 if ( ( ooO0OO + 1 ) == ( o0o0O0O00oOOo - 1 ) ) :
  oo00oO0O0 = iid_str [ ooO0OO + 1 ]
 else :
  oo00oO0O0 = iid_str [ ooO0OO + 1 : o0o0O0O00oOOo - 1 ]
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
 Oo0oO00o = clause . find ( "#" )
 while ( Oo0oO00o != - 1 ) :
  o0o0O0O00oOOo = clause [ Oo0oO00o : : ] . find ( "\n" )
  if ( o0o0O0O00oOOo == - 1 ) : o0o0O0O00oOOo = 0
  clause = clause [ : Oo0oO00o ] + clause [ Oo0oO00o + o0o0O0O00oOOo + 1 : : ]
  Oo0oO00o = clause . find ( "#" )
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
  I1IiIiiIiIII [ "register-ttl" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "send-map-request" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "subscribe-request" ] = [ "" ] * III11I1
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
  I1IiIiiIiIII [ "encrypt-json" ] = [ "" ] * III11I1
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
 if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
def lisp_clause_syntax_error ( kv_pair , parm , clause ) :
 OoO0ooO = ( parm in kv_pair and type ( kv_pair [ parm ] ) == list )
 if ( OoO0ooO ) : return ( False )
 if 51 - 51: iII111i / ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 IIIII = lisp . bold ( "Syntax error" , False )
 lisp . fprint ( "{}, '{}' not in '{}' clause" . format ( IIIII , parm , clause ) )
 return ( True )
 if 78 - 78: Ii1I * i1IIi
 if 1 - 1: I1IiiI / IiII * ooOoO0o
 if 1 - 1: I11i * o0oOOo0O0Ooo . OoOoOO00 / O0
 if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo % O0 * O0
 if 14 - 14: I1ii11iIi11i . ooOoO0o + II111iiii / iII111i / I11i
 if 74 - 74: O0 / i1IIi
 if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
 if 31 - 31: OoooooooOO . OOooOOo
def lisp_syntax_check ( kv_pairs , clause ) :
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 oO = lisp_setup_kv_pairs ( clause )
 if 17 - 17: Oo0Ooo % OOooOOo . i1IIi / OoooooooOO
 clause = clause . split ( "\n" )
 IIiIiiii = ""
 O0000OOO0 = 0
 ooo0 = False
 Oo0oO00o = 0
 oO000oOo00o0o = ""
 if 85 - 85: iII111i + OoooooooOO * iII111i - I1Ii111 % i11iIiiIii
 for OOo00OoO in clause :
  if ( len ( OOo00OoO ) == 0 ) : continue
  if ( OOo00OoO == "" ) : continue
  if ( lisp_comment ( OOo00OoO ) ) :
   OOo00OoO = OOo00OoO . replace ( "#" , "%" )
   IIiIiiii += lisp_write_line ( OOo00OoO )
   continue
   if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
   if 92 - 92: I11i . I1Ii111
  oOO00O0Ooooo00 = OOo00OoO . find ( "json-string" ) != - 1
  if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
  if ( lisp_begin_clause ( OOo00OoO ) and oOO00O0Ooooo00 == False ) :
   IIiIiiii += lisp_write_line ( OOo00OoO )
   O0000OOO0 += 1
   if ( oO000oOo00o0o == OOo00OoO ) :
    Oo0oO00o += 1
   else :
    Oo0oO00o = 0
    oO000oOo00o0o = OOo00OoO
    if 18 - 18: iIii1I11I1II1 % I11i
   continue
   if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
  if ( lisp_end_clause ( OOo00OoO ) and oOO00O0Ooooo00 == False ) :
   O0000OOO0 -= 1
   if ( O0000OOO0 == 0 ) :
    IIiIiiii += lisp_write_line ( OOo00OoO )
    break
    if 75 - 75: OoooooooOO * IiII
   if ( ooo0 ) :
    IIiIiiii += "%" + OOo00OoO + "\n"
   else :
    IIiIiiii += lisp_write_line ( OOo00OoO )
    if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
   continue
   if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
  if ( ooo0 ) :
   IIiIiiii += "%" + OOo00OoO + "\n"
   continue
   if 69 - 69: O0
   if 85 - 85: ooOoO0o / O0
   if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
   if 62 - 62: I1Ii111 . IiII . OoooooooOO
   if 11 - 11: OOooOOo / I11i
   if 73 - 73: i1IIi / i11iIiiIii
  OOO = OOo00OoO . split ( "=" , 1 )
  if 30 - 30: OoooooooOO - OoooooooOO . O0 / iII111i
  if ( len ( OOO ) == 1 ) :
   IIiIiiii += lisp_write_error ( OOo00OoO , "no equal sign" )
   ooo0 = True
   continue
   if 31 - 31: OOooOOo + o0oOOo0O0Ooo . OoooooooOO
   if 89 - 89: II111iiii + i1IIi + II111iiii
  IiII1II11I = OOO [ 0 ] . replace ( " " , "" )
  if 54 - 54: IiII + O0 + I11i * I1Ii111 - OOooOOo % oO0o
  if 13 - 13: ooOoO0o / iII111i * OoO0O00 . OoO0O00 * ooOoO0o
  if 63 - 63: I1Ii111 / O0 * Oo0Ooo + II111iiii / IiII + Ii1I
  if 63 - 63: OoO0O00 + I1ii11iIi11i . I1Ii111 % I1Ii111
  if 57 - 57: II111iiii
  if ( IiII1II11I == "description" or IiII1II11I == "geo-tag" ) :
   oo00oO0O0 = OOO [ 1 ]
  elif ( IiII1II11I == "json-string" ) :
   oo00oO0O0 = OOO [ 1 ] [ 1 : : ]
  else :
   if ( IiII1II11I == "eid-prefix" and OOO [ 1 ] . count ( "'" ) == 2 ) :
    oo00oO0O0 = OOO [ 1 ] [ 1 : : ]
   elif ( IiII1II11I == "instance-id" ) :
    oo00oO0O0 = OOO [ 1 ] [ 1 : : ]
   else :
    oo00oO0O0 = OOO [ 1 ] . replace ( " " , "" )
    if 54 - 54: Oo0Ooo + oO0o + i11iIiiIii
    if 28 - 28: oO0o
    if 70 - 70: IiII
  IiII1II11I = IiII1II11I . replace ( "\t" , "" )
  oo00oO0O0 = oo00oO0O0 . replace ( "\t" , "" )
  if 34 - 34: I1Ii111 % IiII
  if ( IiII1II11I not in kv_pairs ) :
   IIiIiiii += lisp_write_error ( OOo00OoO , "invalid command keyword" )
   ooo0 = True
   continue
   if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
   if 83 - 83: oO0o + OoooooooOO
   if 22 - 22: Ii1I % iII111i * OoooooooOO - o0oOOo0O0Ooo / iIii1I11I1II1
   if 86 - 86: OoooooooOO . iII111i % OoOoOO00 / I11i * iII111i / o0oOOo0O0Ooo
   if 64 - 64: i11iIiiIii
   if 38 - 38: IiII / I1IiiI - IiII . I11i
   if 69 - 69: OoooooooOO + I1ii11iIi11i
   if 97 - 97: OOooOOo - OoO0O00 / Ii1I . i11iIiiIii % oO0o * oO0o
  if ( len ( kv_pairs [ IiII1II11I ] ) <= 1 ) :
   ii1IIIIiI11 = ""
   if ( IiII1II11I == "eid-prefix" and not lisp_valid_prefix_format ( oo00oO0O0 ) ) :
    ii1IIIIiI11 = "invalid prefix"
    if 40 - 40: o0oOOo0O0Ooo
   if ( IiII1II11I == "address" and not lisp . lisp_valid_address_format ( IiII1II11I , oo00oO0O0 ) ) :
    if 67 - 67: oO0o + II111iiii - O0 . oO0o * II111iiii * I11i
    ii1IIIIiI11 = "invalid address"
    if 90 - 90: Ii1I . IiII
   if ( ii1IIIIiI11 != "" ) :
    IIiIiiii += lisp_write_error ( OOo00OoO , ii1IIIIiI11 )
    ooo0 = True
    continue
    if 81 - 81: OOooOOo - I11i % ooOoO0o - OoO0O00 / Oo0Ooo
    if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
    if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
    if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
    if 95 - 95: IiII
    if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
    if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
  if ( len ( kv_pairs [ IiII1II11I ] ) == 4 and kv_pairs [ IiII1II11I ] [ 3 ] ) :
   if ( IiII1II11I == "instance-id" ) :
    III = ( oo00oO0O0 . find ( "-" ) != - 1 )
    IiiIii = ( oo00oO0O0 == "*" )
    if 84 - 84: oO0o % i1IIi
    if ( III or IiiIii ) :
     oo0 , ii = lisp_validate_range ( oo00oO0O0 )
     if ( ii == - 1 ) :
      IIiIiiii += lisp_write_error ( OOo00OoO , "invalid range" )
      ooo0 = True
      continue
      if 70 - 70: Oo0Ooo . OoooooooOO - iII111i
    else :
     oo0 = oo00oO0O0
     ii = 32
     if 30 - 30: I1ii11iIi11i % I1IiiI
     if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
    oo00oO0O0 = str ( oo0 ) + "-" + str ( ii )
    if 59 - 59: OOooOOo + i11iIiiIii
    if 88 - 88: i11iIiiIii - ooOoO0o
    if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
    if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
    if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
    if 30 - 30: OoOoOO00
    if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
    if 26 - 26: II111iiii * OoOoOO00
  if ( kv_pairs [ IiII1II11I ] [ 0 ] and IiII1II11I in oO ) :
   if ( oO [ IiII1II11I ] [ Oo0oO00o ] != "" ) : Oo0oO00o += 1
   oO [ IiII1II11I ] [ Oo0oO00o ] = oo00oO0O0
  else :
   oO [ IiII1II11I ] = oo00oO0O0
   if 10 - 10: II111iiii . iII111i
   if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
   if 88 - 88: iII111i
   if 19 - 19: II111iiii * IiII + Ii1I
   if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
   if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
  if ( len ( kv_pairs [ IiII1II11I ] ) > 1 ) :
   IIi = kv_pairs [ IiII1II11I ] [ 1 ]
   if ( type ( IIi ) == int ) :
    oo00oO0O0 = int ( oo00oO0O0 )
    if ( oo00oO0O0 < kv_pairs [ IiII1II11I ] [ 1 ] and oo00oO0O0 > kv_pairs [ IiII1II11I ] [ 2 ] ) :
     IIiIiiii += lisp_write_error ( OOo00OoO , "invalid range value" )
     ooo0 = True
     continue
     if 27 - 27: OOooOOo % Ii1I
   elif ( oo00oO0O0 not in kv_pairs [ IiII1II11I ] [ 1 : : ] ) :
    IIiIiiii += lisp_write_error ( OOo00OoO , "invalid value keyword" )
    ooo0 = True
    continue
    if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
    if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
    if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
    if 98 - 98: i1IIi
    if 65 - 65: OoOoOO00 / OoO0O00 % IiII
    if 45 - 45: OoOoOO00
  IIiIiiii += lisp_write_line ( OOo00OoO )
  if 66 - 66: OoO0O00
  if 56 - 56: O0
 if ( ooo0 == True ) :
  IIiIiiii = IIiIiiii . replace ( "%" , "#" )
 else :
  IIiIiiii = IIiIiiii . replace ( "#" , "" )
  IIiIiiii = IIiIiiii . replace ( "%" , "#" )
  if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
 return ( [ ooo0 , IIiIiiii , oO ] )
 if 23 - 23: oO0o - OOooOOo + I11i
 if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
 if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
 if 11 - 11: iII111i * Ii1I - OoOoOO00
 if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
 if 74 - 74: Oo0Ooo
 if 61 - 61: Oo0Ooo - I1Ii111 * II111iiii % ooOoO0o * iIii1I11I1II1 + OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
def lisp_process_command ( lisp_socket , opcode , clause , process , command_set ) :
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 OO0OO00oo0 = clause . split ( " " )
 if 19 - 19: Oo0Ooo - OoO0O00
 if 56 - 56: I1ii11iIi11i
 if 26 - 26: OoooooooOO % OoooooooOO
 if 33 - 33: I1Ii111
 if ( clause . find ( "lisp debug" ) != - 1 ) :
  if ( clause . find ( "= yes" ) != - 1 ) :
   lisp . lisp_debug_logging = True
   OOO0ooo = lisp . bold ( "Enable" , False )
   lisp . lprint ( "{} process debug logging" . format ( OOO0ooo ) )
   if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
  if ( clause . find ( "= no" ) != - 1 ) :
   I111i1I1 = lisp . bold ( "Disable" , False )
   lisp . lprint ( "{} process debug logging" . format ( I111i1I1 ) )
   lisp . lisp_debug_logging = False
   if 62 - 62: OOooOOo * I1Ii111 / Oo0Ooo * o0oOOo0O0Ooo
  return
  if 29 - 29: Oo0Ooo % OoO0O00 % IiII . o0oOOo0O0Ooo / OoooooooOO * ooOoO0o
  if 54 - 54: O0
  if 68 - 68: OoO0O00 * o0oOOo0O0Ooo . ooOoO0o % oO0o % I1Ii111
  if 75 - 75: OoOoOO00
  if 34 - 34: O0
  if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 OO0O0o0o0 = ( OO0OO00oo0 [ 0 ] == "show" )
 if ( OO0O0o0o0 ) :
  iIIIIIiI1I1 = clause . split ( "%" )
  OO0OO00oo0 = iIIIIIiI1I1 [ 0 ] . split ( " " )
  I11I1IIiiII1 = len ( iIIIIIiI1I1 )
  if ( I11I1IIiiII1 == 2 ) :
   iIIIIIiI1I1 = iIIIIIiI1I1 [ 1 ]
  elif ( I11I1IIiiII1 == 3 ) :
   iIIIIIiI1I1 = iIIIIIiI1I1 [ 1 ] + "%" + iIIIIIiI1I1 [ 2 ] + "%"
  else :
   iIIIIIiI1I1 = ""
   if 31 - 31: I1IiiI * oO0o + OoooooooOO - iII111i / OoooooooOO
   if 19 - 19: IiII * ooOoO0o * o0oOOo0O0Ooo + O0 / O0
 OO0OO00oo0 = OO0OO00oo0 [ 0 ] + " " + OO0OO00oo0 [ 1 ]
 if 73 - 73: iIii1I11I1II1 / iIii1I11I1II1 - oO0o
 for oOoOOOo in command_set :
  if ( OO0OO00oo0 in oOoOOOo ) :
   ii1I , I1IiIiiIiIII = oOoOOOo [ OO0OO00oo0 ]
   break
   if 85 - 85: I11i
  if ( oOoOOOo == command_set [ - 1 ] ) :
   lisp . lprint ( "Invalid command found '{}'" . format ( OO0OO00oo0 ) )
   return
   if 88 - 88: I1IiiI + OoooooooOO - oO0o
   if 85 - 85: o0oOOo0O0Ooo . IiII / O0 . o0oOOo0O0Ooo . I1ii11iIi11i . OoO0O00
   if 60 - 60: o0oOOo0O0Ooo - OoOoOO00 * Oo0Ooo % Ii1I / II111iiii % OoOoOO00
   if 52 - 52: OOooOOo - iII111i * oO0o
   if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
   if 36 - 36: O0 + Oo0Ooo
   if 5 - 5: Oo0Ooo * OoOoOO00
   if 46 - 46: ooOoO0o
   if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
   if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 ooo0 = False
 if ( len ( I1IiIiiIiIII ) != 0 ) :
  ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
  if ( ooo0 ) :
   lisp . lprint ( "Command syntax error: {}" . format ( IIiIiiii ) )
  else :
   ii1I ( I1IiIiiIiIII )
   if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 else :
  if ( OO0O0o0o0 ) : I1IiIiiIiIII = iIIIIIiI1I1
  IIiIiiii = ii1I ( I1IiIiiIiIII )
  if 72 - 72: i1IIi
  if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
 oooo0OOo = lisp . lisp_command_ipc ( IIiIiiii , process )
 lisp . lisp_ipc ( oooo0OOo , lisp_socket , "lisp-core" )
 return
 if 72 - 72: O0 / ooOoO0o + OoooooooOO * iII111i
 if 61 - 61: OoooooooOO % II111iiii - I1IiiI % I1ii11iIi11i + i1IIi
 if 39 - 39: i1IIi
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
def lisp_is_user_superuser ( username ) :
 if ( username == None ) : username = lisp_get_user ( )
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
 if 69 - 69: OoooooooOO + OOooOOo
 IIi11I1 = getoutput ( "egrep -A 4 user-account ./lisp.config" )
 if 49 - 49: II111iiii - I1IiiI / I11i
 O0O0ooOOO = "username = {}" . format ( username )
 Oo0oO00o = IIi11I1 . find ( O0O0ooOOO )
 o0o0O0O00oOOo = IIi11I1 [ Oo0oO00o : : ] . find ( "}" )
 if ( Oo0oO00o == - 1 or o0o0O0O00oOOo == - 1 ) : return ( False )
 if 70 - 70: ooOoO0o . O0 . I1Ii111 . O0 + i1IIi
 i1II1I = IIi11I1 [ Oo0oO00o : Oo0oO00o + o0o0O0O00oOOo ] . find ( "super-user = yes" )
 return ( i1II1I != - 1 )
 if 95 - 95: OoO0O00 - OOooOOo / II111iiii % I1ii11iIi11i . o0oOOo0O0Ooo
 if 24 - 24: i1IIi . i11iIiiIii
 if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
 if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
 if 81 - 81: iII111i * OOooOOo - I1ii11iIi11i * Ii1I % OoOoOO00 * OoOoOO00
 if 59 - 59: iIii1I11I1II1
 if 7 - 7: OOooOOo * I1IiiI / o0oOOo0O0Ooo * i11iIiiIii
def lisp_find_user_account ( username , password ) :
 if 84 - 84: OOooOOo . iII111i
 if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
 if 21 - 21: oO0o / OoooooooOO
 if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
 IIi11I1 = getoutput ( "egrep -A 4 user-account ./lisp.config" )
 if 87 - 87: I1Ii111 * i1IIi / I1ii11iIi11i
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo - OoooooooOO % OOooOOo * OoOoOO00
 if 69 - 69: i1IIi
 if 59 - 59: II111iiii - o0oOOo0O0Ooo
 if 24 - 24: Oo0Ooo - i1IIi + I11i
 Oo0oO00o = IIi11I1 . find ( "username = {}\n" . format ( username ) )
 if ( Oo0oO00o == - 1 ) : return ( False )
 if 38 - 38: OoooooooOO / I1ii11iIi11i . O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
 IIi11I1 = IIi11I1 [ Oo0oO00o : : ]
 IIi11I1 = IIi11I1 . replace ( "\t" , "" )
 IIi11I1 = IIi11I1 . replace ( " " , "" )
 if 96 - 96: iII111i
 if 18 - 18: iII111i * I11i - Ii1I
 if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 Oo0oO00o = IIi11I1 . find ( "password=" )
 if ( Oo0oO00o == - 1 ) : return ( False )
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 IIi11I1 = IIi11I1 [ Oo0oO00o : : ]
 o0o0O0O00oOOo = IIi11I1 . find ( "\n" )
 if ( o0o0O0O00oOOo == - 1 ) : return ( False )
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 II1iiIIiIii = IIi11I1 [ : o0o0O0O00oOOo ] . split ( "=" )
 if ( II1iiIIiIii [ 1 ] == "" ) :
  ooO00OO0 = lisp_hash_password ( password )
  if ( II1iiIIiIii [ 2 ] != ooO00OO0 ) : return ( False )
 else :
  if ( II1iiIIiIii [ 1 ] != password ) : return ( False )
  if 5 - 5: iIii1I11I1II1 / I11i / i1IIi % OoooooooOO
  if 50 - 50: Ii1I / OoOoOO00 * Ii1I
  if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
  if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
  if 32 - 32: i11iIiiIii - I1Ii111
  if 53 - 53: OoooooooOO - IiII
 return ( True )
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
def lisp_validate_user ( ) :
 iiIiI = bottle . request . forms . get ( 'username' )
 if 38 - 38: IiII . Ii1I
 if ( iiIiI == None ) :
  IIIIIIIiI = bottle . request . get_cookie ( "lisp-login" )
  if ( IIIIIIIiI ) : return ( True )
  if 12 - 12: iII111i . IiII . OoOoOO00 / O0
  if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
 IIo00ooo = bottle . request . forms . get ( 'password' )
 if ( iiIiI == None or IIo00ooo == None ) : return ( False )
 if 31 - 31: O0 * o0oOOo0O0Ooo % o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if ( lisp_find_user_account ( iiIiI , IIo00ooo ) == False ) : return ( False )
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 OO0ooo0o0 = None if os . getenv ( "LISP_NO_USER_TIMEOUT" ) == "" else LISP_USER_TIMEOUT
 if 69 - 69: I1ii11iIi11i - I1Ii111
 bottle . response . set_cookie ( "lisp-login" , iiIiI , max_age = OO0ooo0o0 )
 return ( True )
 if 16 - 16: Oo0Ooo
 if 14 - 14: i1IIi - O0 % Oo0Ooo
 if 92 - 92: Ii1I % iII111i / I1ii11iIi11i % I1ii11iIi11i * I1IiiI
 if 74 - 74: O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 23 - 23: I11i
def lisp_get_user ( ) :
 iiIiI = bottle . request . forms . get ( 'username' )
 if ( iiIiI ) : return ( iiIiI )
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 return ( bottle . request . get_cookie ( "lisp-login" ) )
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
def lisp_login_page ( ) :
 o0o0oOOOo0oo = '''
        <center><br><br>
        <form action="/lisp/login" method="post">
        <font size="3"><i>
        Username:<input type="text" name="username" />
        {}Password:<input type="password" name="password" />
        {}<input style="background-color:transparent;border-radius:10px;" type="submit" value="Login" />
        </i></font></form>
        </center>
    ''' . format ( lisp . lisp_space ( 4 ) , lisp . lisp_space ( 2 ) )
 return ( lisp_banner_top ( True ) + o0o0oOOOo0oo + "<br><hr>" )
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 if 66 - 66: Oo0Ooo
def lisp_is_any_xtr_logging_on ( log_type ) :
 OO0OO00oo0 = "egrep '" + log_type + " = '" + " ./lisp.config"
 OO0OO00oo0 = getoutput ( OO0OO00oo0 )
 if ( OO0OO00oo0 == "" ) : return ( False )
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 if 55 - 55: o0oOOo0O0Ooo . iII111i
 if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
 if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
 OO0OO00oo0 = OO0OO00oo0 . split ( "\n" )
 for oO000o in OO0OO00oo0 :
  o0Oo = oO000o . find ( "    {} = " . format ( log_type ) ) != - 1
  if ( oO000o [ 0 ] == " " and o0Oo ) :
   OO0OO00oo0 = oO000o . replace ( " " , "" )
   OO0OO00oo0 = OO0OO00oo0 . split ( "=" )
   if ( OO0OO00oo0 [ 1 ] == "yes" ) : return ( True )
   if 57 - 57: OOooOOo / Oo0Ooo
   if 69 - 69: oO0o - Oo0Ooo % IiII
 return ( False )
 if 50 - 50: OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
 if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
 if 62 - 62: o0oOOo0O0Ooo
 if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
def lisp_landing_page ( ) :
 IiIi1111ii = lisp . green ( "yes" , True )
 iI1I1II1 = lisp . red ( "no" , True )
 if 92 - 92: OoooooooOO - OoooooooOO * OoO0O00 % I1IiiI
 ooooOoO0O = IiIi1111ii if lisp . lisp_is_running ( "lisp-itr" ) else iI1I1II1
 IIII = IiIi1111ii if lisp . lisp_is_running ( "lisp-etr" ) else iI1I1II1
 IIIIoOo = IiIi1111ii if lisp . lisp_is_running ( "lisp-rtr" ) else iI1I1II1
 Oo0oOo0O0O0o = IiIi1111ii if lisp . lisp_is_running ( "lisp-mr" ) else iI1I1II1
 IiiIIiIIii1iI = IiIi1111ii if lisp . lisp_is_running ( "lisp-ms" ) else iI1I1II1
 Oo0O0O000 = IiIi1111ii if lisp . lisp_is_running ( "lisp-ddt" ) else iI1I1II1
 if 29 - 29: o0oOOo0O0Ooo / Oo0Ooo * I1ii11iIi11i . o0oOOo0O0Ooo
 o0o0oOOOo0oo = '''
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
    ''' . format ( ooooOoO0O , IIIIoOo , IIII , Oo0oOo0O0O0o , Oo0O0O000 , IiiIIiIIii1iI )
 if 64 - 64: oO0o / ooOoO0o % i11iIiiIii
 o0o0oOOOo0oo += '''
        <center>
        <style type="text/css">
        form { display:inline }
        </style>

        <a href="/lisp/show/status">
        <button style="background-color:transparent;border-radius:10px;
        type="button">system status</button></a>
    '''
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 oo0o = lisp_get_clause_for_api ( "lisp debug" ) [ 0 ]
 oo0o = oo0o [ "lisp debug" ] if ( "lisp debug" in oo0o ) else None
 o0 = "lisp xtr-parameters"
 IiiiI111I = lisp_get_clause_for_api ( o0 ) [ 0 ]
 III1I11i1iIi = False
 if ( o0 in IiiiI111I ) :
  OO0oo0O0OOO0 = { "data-plane-logging" : "yes" }
  OoOOo = { "flow-logging" : "yes" }
  III1I11i1iIi = ( OO0oo0O0OOO0 in IiiiI111I [ o0 ] or OoOOo in IiiiI111I [ o0 ] )
  if 46 - 46: I1IiiI / Ii1I . I1Ii111 % i11iIiiIii + o0oOOo0O0Ooo + OoooooooOO
  if 93 - 93: Ii1I - IiII . I1Ii111 % iIii1I11I1II1 % I11i
 Ii11IiIi = { }
 for OOo0o in oo0o : Ii11IiIi [ list ( OOo0o . keys ( ) ) [ 0 ] ] = list ( OOo0o . values ( ) ) [ 0 ]
 oo0o = Ii11IiIi
 oo0o [ "ddt" ] = oo0o [ "ddt-node" ]
 oo0o [ "mr" ] = oo0o [ "map-resolver" ]
 oo0o [ "ms" ] = oo0o [ "map-server" ]
 if 20 - 20: OoO0O00 / iIii1I11I1II1
 if 15 - 15: oO0o . o0oOOo0O0Ooo
 if 21 - 21: iIii1I11I1II1 / II111iiii % i1IIi
 if 8 - 8: OoO0O00 + OoOoOO00 . iIii1I11I1II1 % O0
 III11I1 = getoutput ( "wc -l logs/lisp-core.log" )
 III11I1 = III11I1 . replace ( " " , "" )
 III11I1 = III11I1 . split ( "logs" ) [ 0 ]
 iI11Ii111 = "on" if oo0o [ "core" ] == "yes" else "off"
 o0o0oOOOo0oo += '''
        <form>
        <select size="1" style="width: 110px"
                onchange="parent.window.location=this.value">
        <option value="">show logging:</option>
        <option value="/lisp/show/log/lisp-core/100">[{}] core log [{}]
        </option>''' . format ( iI11Ii111 , III11I1 )
 if 54 - 54: OoOoOO00 % iII111i . OoOoOO00 * OOooOOo + OoOoOO00 % i1IIi
 if ( os . path . exists ( "./logs/lisp-itr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-itr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iI11Ii111 = "on" if oo0o [ "itr" ] == "yes" else "off"
  o0o0oOOOo0oo += '''
            <option value="/lisp/show/log/lisp-itr/100">[{}] ITR log [{}]
            </option>''' . format ( iI11Ii111 , III11I1 )
  if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if ( os . path . exists ( "./logs/lisp-rtr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-rtr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iI11Ii111 = "on" if oo0o [ "rtr" ] == "yes" else "off"
  o0o0oOOOo0oo += '''<option value="/lisp/show/log/lisp-rtr/100">[{}] RTR 
           log [{}]</option>''' . format ( iI11Ii111 , III11I1 )
  if 47 - 47: oO0o % iIii1I11I1II1
 if ( os . path . exists ( "./logs/lisp-etr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-etr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iI11Ii111 = "on" if oo0o [ "etr" ] == "yes" else "off"
  o0o0oOOOo0oo += '''<option value="/lisp/show/log/lisp-etr/100">[{}] ETR 
            log [{}]</option>''' . format ( iI11Ii111 , III11I1 )
  if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if ( os . path . exists ( "./logs/lisp-xtr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-xtr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iI11Ii111 = "on" if oo0o [ "itr" ] == "yes" or oo0o [ "etr" ] == "yes" or oo0o [ "rtr" ] == "yes" else "off"
  if 98 - 98: iII111i + Ii1I - OoO0O00
  o0o0oOOOo0oo += '''<option value="/lisp/show/log/lisp-xtr/100">[{}] XTR 
           log [{}]</option>''' . format ( iI11Ii111 , III11I1 )
  if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if ( os . path . exists ( "./logs/lisp-mr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-mr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iI11Ii111 = "on" if oo0o [ "mr" ] == "yes" else "off"
  o0o0oOOOo0oo += '''<option value="/lisp/show/log/lisp-mr/100">[{}] MR 
            log [{}] </option>''' . format ( iI11Ii111 , III11I1 )
  if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if ( os . path . exists ( "./logs/lisp-ddt.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-ddt.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iI11Ii111 = "on" if oo0o [ "ddt" ] == "yes" else "off"
  o0o0oOOOo0oo += '''<option value="/lisp/show/log/lisp-ddt/100">[{}] DDT 
            log [{}]</option>''' . format ( iI11Ii111 , III11I1 )
  if 38 - 38: O0 - IiII % I1Ii111
 if ( os . path . exists ( "./logs/lisp-ms.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-ms.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iI11Ii111 = "on" if oo0o [ "ms" ] == "yes" else "off"
  o0o0oOOOo0oo += '''<option value="/lisp/show/log/lisp-ms/100">[{}] MS 
            log [{}]</option>''' . format ( iI11Ii111 , III11I1 )
  if 64 - 64: iIii1I11I1II1
 IIi1iI = lisp_is_any_xtr_logging_on ( "flow-logging" )
 if ( os . path . exists ( "./logs/lisp-flow.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-flow.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iI11Ii111 = "on" if IIi1iI else "off"
  o0o0oOOOo0oo += '''<option value="/lisp/show/log/lisp-flow/100">[{}] flow 
            log [{}]</option>''' . format ( iI11Ii111 , III11I1 )
  if 92 - 92: OoO0O00 * ooOoO0o
 o0o0oOOOo0oo += "</select></form>"
 if 35 - 35: i11iIiiIii
 if 99 - 99: II111iiii . o0oOOo0O0Ooo + O0
 if 71 - 71: IiII + i1IIi * Oo0Ooo % Oo0Ooo / Oo0Ooo
 if 55 - 55: OoooooooOO + I1Ii111 + OoooooooOO * ooOoO0o
 i1II1I = lisp_is_user_superuser ( None )
 if ( i1II1I ) :
  o0o0oOOOo0oo += '''
            <form>
            <select size="1" style="width: 120px"
                    onchange="parent.window.location=this.value">
            <option value="">manage logging:</option>
        '''
  if 68 - 68: O0
  if 2 - 2: OoO0O00 + O0 * OoO0O00 - Ii1I + oO0o
  if 43 - 43: I1ii11iIi11i - OoOoOO00
  if 36 - 36: I1ii11iIi11i - iII111i
  if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
  if ( "yes" in list ( oo0o . values ( ) ) or III1I11i1iIi ) :
   o0o0oOOOo0oo += '''<option value="/lisp/debug/{}%{}">disable all logging
                </option>''' . format ( "disable" , "all" )
   if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
   if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
  oO00oo000O = False
  ii11 = False
  for oOoo0 in oo0o :
   if ( lisp . lisp_is_running ( "lisp-" + oOoo0 ) == False ) : continue
   if 2 - 2: OoooooooOO
   if ( oOoo0 in [ "itr" , "etr" , "rtr" ] ) :
    oO00oo000O = True
    ii11 = True
    if 60 - 60: OoO0O00
    if 81 - 81: OoOoOO00 % Ii1I
   oo0i1iIIi1II1iiI = oo0o [ oOoo0 ]
   III1Ii1i1I1 = oOoo0
   if ( III1Ii1i1I1 == "mr" ) : III1Ii1i1I1 = "map-resolver"
   if ( III1Ii1i1I1 == "ms" ) : III1Ii1i1I1 = "map-server"
   if ( III1Ii1i1I1 == "ddt" ) : III1Ii1i1I1 = "ddt-node"
   if 97 - 97: I1Ii111 . ooOoO0o - I1Ii111 + I1IiiI * II111iiii
   o0o0oOOOo0oo += '''<option value="/lisp/debug/{}%{}">{} {} logging
                </option>''' . format ( III1Ii1i1I1 , "yes" if oo0i1iIIi1II1iiI == "no" else "no" ,
 "enable" if oo0i1iIIi1II1iiI == "no" else "disable" ,
 oOoo0 . upper ( ) if oOoo0 != "core" else "core" )
   if 10 - 10: Ii1I + I11i % OoooooooOO - I1IiiI
  if ( oO00oo000O ) :
   o00oooOo = lisp_is_any_xtr_logging_on ( "data-plane-logging" )
   o0o0oOOOo0oo += '''<option value="/lisp/debug/data-plane-logging%{}">{} 
                data-plane logging </option>''' . format ( "yes" if o00oooOo == False else "no" ,
   # i11iIiiIii / O0
 "enable" if o00oooOo == False else "disable" )
   if 94 - 94: ooOoO0o * I11i - IiII . iIii1I11I1II1
  if ( ii11 ) :
   o00oooOo = IIi1iI
   o0o0oOOOo0oo += '''<option value="/lisp/debug/flow-logging%{}">{} 
                flow logging </option>''' . format (
 "yes" if o00oooOo == False else "no" ,
 "enable" if o00oooOo == False else "disable" )
   if 66 - 66: ooOoO0o - OOooOOo * OoOoOO00 / oO0o * II111iiii * OoO0O00
  o0o0oOOOo0oo += "</select></form>"
  if 91 - 91: OoooooooOO / Ii1I . I1IiiI + ooOoO0o . II111iiii
  if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
 o0o0oOOOo0oo += "<br><br>"
 if 77 - 77: I1Ii111 - I11i
 if 11 - 11: I1ii11iIi11i
 if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
 if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
 o0OO0O0OO0oO0 = lisp . lisp_button ( "{}:<br>show map-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-itr" ) ) :
  o0OO0O0OO0oO0 = '<a href="/lisp/show/itr/map-cache">' + o0OO0O0OO0oO0 + '</a>'
  o0OO0O0OO0oO0 = o0OO0O0OO0oO0 . format ( lisp . green ( "ITR" , True ) )
 else :
  o0OO0O0OO0oO0 = o0OO0O0OO0oO0 . format ( lisp . red ( "ITR" , True ) )
  o0OO0O0OO0oO0 = lisp . lisp_span ( o0OO0O0OO0oO0 , "ITR not running" )
  if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
  if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 oOII1ii1ii11I1 = lisp . lisp_button ( "{}:<br>show map-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-rtr" ) ) :
  oOII1ii1ii11I1 = '<a href="/lisp/show/rtr/map-cache">' + oOII1ii1ii11I1 + '</a>'
  oOII1ii1ii11I1 = oOII1ii1ii11I1 . format ( lisp . green ( "RTR" , True ) )
 else :
  oOII1ii1ii11I1 = oOII1ii1ii11I1 . format ( lisp . red ( "RTR" , True ) )
  oOII1ii1ii11I1 = lisp . lisp_span ( oOII1ii1ii11I1 , "RTR not running" )
  if 88 - 88: I1ii11iIi11i
  if 93 - 93: iIii1I11I1II1
 oo0oooo0OoO0o = lisp . lisp_button ( "{}:<br>show referral-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-mr" ) ) :
  oo0oooo0OoO0o = '<a href="/lisp/show/referral">' + oo0oooo0OoO0o + '</a>'
  oo0oooo0OoO0o = oo0oooo0OoO0o . format ( lisp . green ( "MR" , True ) )
 else :
  oo0oooo0OoO0o = oo0oooo0OoO0o . format ( lisp . red ( "MR" , True ) )
  oo0oooo0OoO0o = lisp . lisp_span ( oo0oooo0OoO0o , "MR not running" )
  if 50 - 50: iII111i / iII111i + OOooOOo * ooOoO0o / I1ii11iIi11i
  if 14 - 14: Ii1I % I1IiiI - iIii1I11I1II1 . OOooOOo + OoO0O00 - I1Ii111
 iI1iIiiiI1I1 = lisp . lisp_button ( "{}:<br>show delegations" , None )
 if ( lisp . lisp_is_running ( "lisp-ddt" ) ) :
  iI1iIiiiI1I1 = '<a href="/lisp/show/delegations">' + iI1iIiiiI1I1 + '</a>'
  iI1iIiiiI1I1 = iI1iIiiiI1I1 . format ( lisp . green ( "DDT" , True ) )
 else :
  iI1iIiiiI1I1 = iI1iIiiiI1I1 . format ( lisp . red ( "DDT" , True ) )
  iI1iIiiiI1I1 = lisp . lisp_span ( iI1iIiiiI1I1 , "DDT not running" )
  if 78 - 78: oO0o / OoO0O00 - oO0o * OoooooooOO . OoOoOO00
  if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
 Ii1Iii11 = lisp . lisp_button ( "{}:<br>show site-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-ms" ) ) :
  Ii1Iii11 = '<a href="/lisp/show/site">' + Ii1Iii11 + '</a>'
  Ii1Iii11 = Ii1Iii11 . format ( lisp . green ( "MS" , True ) )
 else :
  Ii1Iii11 = Ii1Iii11 . format ( lisp . red ( "MS" , True ) )
  Ii1Iii11 = lisp . lisp_span ( Ii1Iii11 , "MS not running" )
  if 97 - 97: OOooOOo / oO0o . II111iiii
  if 44 - 44: Ii1I % I11i . I1Ii111
 Ii11Iii = lisp . lisp_button ( "{}:<br>show database-mappings" , None )
 if ( lisp . lisp_is_running ( "lisp-etr" ) ) :
  Ii11Iii = '<a href="/lisp/show/database">' + Ii11Iii + '</a>'
  Ii11Iii = Ii11Iii . format ( lisp . green ( "ETR" , True ) )
 else :
  Ii11Iii = Ii11Iii . format ( lisp . red ( "ETR" , True ) )
  Ii11Iii = lisp . lisp_span ( Ii11Iii , "ETR not running" )
  if 68 - 68: I1IiiI % O0
  if 74 - 74: i1IIi + OoOoOO00 + iIii1I11I1II1 * OoOoOO00 * iIii1I11I1II1 + I11i
 Oo0o = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 IiI1I1I = lisp . lisp_geo_help_hover ( '<input type="text" name="geo-point" size="30" required />' )
 if 62 - 62: IiII * O0
 oO0o00ooO0OoO = lisp . lisp_geo_help_hover ( '<input type="text" name="geo-prefix" size="30" required />' )
 if 1 - 1: OoOoOO00 . i11iIiiIii % OoOoOO00 - iII111i % i1IIi + I1ii11iIi11i
 if 2 - 2: iIii1I11I1II1 * oO0o / OoOoOO00 . I11i / IiII
 o00O0OO = lisp . lisp_button ( "API Documentation" , "/lisp/show/api-doc" )
 O0ii1I11i = lisp . lisp_button ( "Command Documentation" , "/lisp/show/command-doc" )
 O0OOO = lisp . lisp_button ( "IETF LISP WG Drafts" ,
 "http://datatracker.ietf.org/wg/lisp/" )
 ii1i1iiI = lisp . lisp_button ( "ddt-root.org" , "http://ddt-root.net" )
 Oo0oOo0ooOOOo = lisp . lisp_button ( "LISP Facebook Group" ,
 "https://www.facebook.com/groups/407716795982512" )
 OoO0000o = lisp . lisp_button ( "LISP LinkedIn Group" ,
 "http://www.linkedin.com/groups/3776183" )
 if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
 I1IIi1I = lisp . lisp_space ( 2 )
 o0o0oOOOo0oo += '''     
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

    ''' . format ( I1IIi1I , o0OO0O0OO0oO0 , I1IIi1I , oOII1ii1ii11I1 , I1IIi1I , Ii11Iii , I1IIi1I , I1IIi1I , oo0oooo0OoO0o , I1IIi1I , iI1iIiiiI1I1 , I1IIi1I , Ii1Iii11 , I1IIi1I ,
 Oo0o , Oo0o , IiI1I1I , oO0o00ooO0OoO , o00O0OO , O0ii1I11i , O0OOO , ii1i1iiI , Oo0oOo0ooOOOo , OoO0000o )
 if 14 - 14: oO0o + O0 / IiII
 return ( lisp_show_wrapper ( o0o0oOOOo0oo ) )
 if 24 - 24: OoO0O00 - oO0o + I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
 if 46 - 46: I1Ii111
 if 72 - 72: iII111i * OOooOOo
 if 67 - 67: i1IIi
 if 5 - 5: II111iiii . OoooooooOO
 if 57 - 57: I1IiiI
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
  iIiiIIi1iiII , oooO00Oo , ooO00o , o0o0oOOOo0oo = lisp . lisp_receive ( lisp_socket , True )
  lisp . lisp_ipc_lock . release ( )
  if 73 - 73: iII111i * iII111i / ooOoO0o
  if ( oooO00Oo != process ) :
   lisp . lprint ( "Discarding IPC message from {}" . format ( oooO00Oo ) )
  elif ( iii11i1 == None ) :
   iii11i1 = o0o0oOOOo0oo
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
 oOoo0 = lisp_commands [ i1i11ii1Ii ]
 oOoo0 = oOoo0 [ 0 ]
 if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 if ( lisp . lisp_is_running ( oOoo0 ) == False ) :
  o0o0oOOOo0oo = ( "<i>Process '{}' is not running, command cannot be " + "executed</i><br>" ) . format ( oOoo0 )
  if 22 - 22: ooOoO0o . iIii1I11I1II1
  return ( lisp_show_wrapper ( o0o0oOOOo0oo ) )
  if 12 - 12: Ii1I
  if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 command = lisp . lisp_command_ipc ( command , "lisp-core" )
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 lisp . lisp_ipc_lock . acquire ( )
 if 77 - 77: II111iiii
 lisp . lisp_ipc ( command , lisp_socket , oOoo0 )
 lisp . lprint ( "Waiting for response to show command '{}'" . format ( command ) )
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 iIiiIIi1iiII , oooO00Oo , ooO00o , o0o0oOOOo0oo = lisp . lisp_receive ( lisp_socket , True )
 if 68 - 68: oO0o
 lisp . lisp_ipc_lock . release ( )
 if 10 - 10: Ii1I
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if ( oooO00Oo == "" ) :
  lisp . lprint ( "Command '{}' timed out to {}" . format ( command , oOoo0 ) )
 elif ( oooO00Oo != oOoo0 ) :
  lisp . lprint ( "Received response from {} but expecting from {}" . format ( oooO00Oo , oOoo0 ) )
  if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
  o0o0oOOOo0oo = lisp_drain_socket ( lisp_socket , oOoo0 )
  if ( o0o0oOOOo0oo == None ) : o0o0oOOOo0oo = "<i>Fatal error, retry later</i><br>"
  if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 return ( lisp_show_wrapper ( o0o0oOOOo0oo ) )
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
 oO0O = "./logs/" + process + ".log"
 if 26 - 26: iIii1I11I1II1 + i1IIi / OoOoOO00 % I1ii11iIi11i
 if ( lisp . lisp_is_python2 ( ) ) :
  Ii = "python -O "
  iIi11Ii1iI1 = process + ".pyo"
 elif ( lisp . lisp_is_python3 ( ) ) :
  Ii = "python3.8 -O "
  iIi11Ii1iI1 = process + ".pyc"
 else :
  lisp . lprint ( "Cannot manage process '{}', unsupported python version" . format ( process ) )
  if 91 - 91: OOooOOo + I1Ii111 . I11i
  if 15 - 15: I11i
  if 94 - 94: I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
 if ( lisp . lisp_is_ubuntu ( ) or lisp . lisp_is_raspbian ( ) or lisp . lisp_is_debian ( ) or lisp . lisp_is_debian_kali ( ) ) :
  if 81 - 81: Oo0Ooo - I11i
  ii1 = Ii + iIi11Ii1iI1 + " 2>&1 > " + oO0O + " &"
 else :
  ii1 = Ii + iIi11Ii1iI1 + " >& " + oO0O + " &"
  if 44 - 44: OoOoOO00 - Oo0Ooo
  if 95 - 95: OOooOOo + ooOoO0o
 O00o0O = getoutput ( "date" )
 if ( startstop and os . path . exists ( iIi11Ii1iI1 ) ) :
  lisp . lprint ( "Start process '{}' on {}" . format ( process , O00o0O ) )
  os . system ( ii1 )
  time . sleep ( 1 )
  return
  if 85 - 85: OOooOOo * i1IIi % I1IiiI - ooOoO0o
  if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 if ( startstop == False and os . path . exists ( iIi11Ii1iI1 ) ) :
  lisp . lprint ( "Stop process '{}' on {}" . format ( process , O00o0O ) )
  o00O = getoutput ( "pgrep -f " + iIi11Ii1iI1 )
  o00O = o00O . split ( "\n" ) [ 0 ]
  os . system ( "kill " + o00O )
  os . system ( "rm " + process )
  return
  if 88 - 88: i11iIiiIii + iII111i * OoOoOO00 * iII111i + I11i
 return
 if 88 - 88: OOooOOo % Oo0Ooo - iII111i - OoOoOO00 % i11iIiiIii
 if 6 - 6: Ii1I - OoO0O00 . I1IiiI - O0
 if 16 - 16: iII111i * iII111i % Ii1I % I1IiiI
 if 48 - 48: OOooOOo / Ii1I % OoO0O00 / IiII / I1Ii111
 if 89 - 89: I1Ii111 * oO0o
 if 63 - 63: OoooooooOO * OoooooooOO % OoO0O00 + O0 / I1Ii111 + iIii1I11I1II1
 if 72 - 72: OoOoOO00 * iIii1I11I1II1 % I11i
def lisp_enable_command ( clause ) :
 if 20 - 20: II111iiii % iIii1I11I1II1 + oO0o * II111iiii * OoO0O00 % OoO0O00
 if 15 - 15: oO0o / I1Ii111
 if 37 - 37: i11iIiiIii + I1IiiI . OOooOOo % I11i % I11i
 if 26 - 26: O0
 if 34 - 34: ooOoO0o * I1Ii111
 if 97 - 97: i11iIiiIii % oO0o / Oo0Ooo / Oo0Ooo
 if 97 - 97: II111iiii - I1Ii111 - iIii1I11I1II1 * I1IiiI
 if ( os . path . exists ( "lisp.py" ) and os . path . exists ( "lisp.pyo" ) == False ) :
  lisp . lprint ( "In manual mode, ignoring 'lisp enable' command" )
  return ( clause )
  if 54 - 54: iIii1I11I1II1
  if 5 - 5: IiII
 OO0OO00oo0 = clause . split ( " " )
 OO0OO00oo0 = OO0OO00oo0 [ 0 ] + " " + OO0OO00oo0 [ 1 ]
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 I1IiIiiIiIII = lisp_core_commands [ "lisp enable" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
 if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
 if ( ooo0 == True ) : return ( IIiIiiii )
 if 96 - 96: OoooooooOO + IiII * O0
 oo0OoOO0o0o = { "itr" : "lisp-itr" , "etr" : "lisp-etr" , "rtr" : "lisp-rtr" ,
 "map-resolver" : "lisp-mr" , "map-server" : "lisp-ms" ,
 "ddt-node" : "lisp-ddt" }
 if 67 - 67: OoOoOO00 - OoOoOO00 * OoO0O00 - iII111i % oO0o
 if 44 - 44: I1IiiI . i1IIi + OOooOOo
 if 16 - 16: o0oOOo0O0Ooo - OoO0O00 / I1Ii111
 if 48 - 48: iIii1I11I1II1
 for OoooooOo in list ( oo0OoOO0o0o . keys ( ) ) :
  OooOo = True if I1IiIiiIiIII [ OoooooOo ] == "yes" else False
  lisp_start_stop_process ( oo0OoOO0o0o [ OoooooOo ] , OooOo )
  if 67 - 67: Oo0Ooo / O0
 return ( IIiIiiii )
 if 88 - 88: OoOoOO00 - OOooOOo
 if 63 - 63: IiII * OoooooooOO
 if 19 - 19: IiII - o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00 / OOooOOo
 if 87 - 87: OoOoOO00 - ooOoO0o - OOooOOo + Oo0Ooo % iIii1I11I1II1 / i11iIiiIii
 if 12 - 12: ooOoO0o
 if 86 - 86: oO0o - OoO0O00
 if 63 - 63: I1IiiI / OoOoOO00 + OoooooooOO . I11i . ooOoO0o
def lisp_debug_command ( lisp_socket , clause , single_process ) :
 OO0OO00oo0 = clause . split ( " " )
 OO0OO00oo0 = OO0OO00oo0 [ 0 ] + " " + OO0OO00oo0 [ 1 ]
 if 48 - 48: i1IIi - iII111i - i11iIiiIii . I11i - iII111i * I11i
 I1IiIiiIiIII = lisp_core_commands [ "lisp debug" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 60 - 60: OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if ( ooo0 == True ) : return ( IIiIiiii )
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 oo0OoOO0o0o = { "itr" : "lisp-itr" , "etr" : "lisp-etr" , "rtr" : "lisp-rtr" ,
 "map-resolver" : "lisp-mr" , "map-server" : "lisp-ms" ,
 "ddt-node" : "lisp-ddt" , "core" : "" }
 if 74 - 74: oO0o
 for iII1i1IIiI1I in I1IiIiiIiIII :
  oOoo0 = oo0OoOO0o0o [ iII1i1IIiI1I ]
  if ( single_process and single_process != oOoo0 ) : continue
  if 67 - 67: Ii1I
  oo0i1iIIi1II1iiI = I1IiIiiIiIII [ iII1i1IIiI1I ]
  OO0OO00oo0 = ( "lisp debug {\n" + "    {} = {}\n" . format ( iII1i1IIiI1I , oo0i1iIIi1II1iiI ) + "}\n" )
  if 43 - 43: OoO0O00 % OoO0O00
  if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
  if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
  if 45 - 45: Ii1I - OOooOOo
  if ( iII1i1IIiI1I == "core" ) :
   lisp_process_command ( None , None , OO0OO00oo0 , None , [ None ] )
   continue
   if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
   if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
  OO0OO00oo0 = lisp . lisp_command_ipc ( OO0OO00oo0 , "lisp-core" )
  lisp . lisp_ipc ( OO0OO00oo0 , lisp_socket , oOoo0 )
  if ( single_process ) : break
  if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 return ( IIiIiiii )
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
def lisp_replace_password_in_clause ( clause , keyword_string ) :
 Oo0oO00o = clause . find ( keyword_string )
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if ( Oo0oO00o == - 1 ) : return ( clause )
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 Oo0oO00o += len ( keyword_string )
 o0o0O0O00oOOo = clause [ Oo0oO00o : : ] . find ( "\n" )
 o0o0O0O00oOOo += Oo0oO00o
 IIo00ooo = clause [ Oo0oO00o : o0o0O0O00oOOo ] . replace ( " " , "" )
 if 24 - 24: ooOoO0o - I11i * oO0o
 if ( len ( IIo00ooo ) != 0 and IIo00ooo [ 0 ] == "=" ) : return ( clause )
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 IIo00ooo = IIo00ooo . replace ( " " , "" )
 IIo00ooo = IIo00ooo . replace ( "\t" , "" )
 IIo00ooo = lisp_hash_password ( IIo00ooo )
 clause = clause [ 0 : Oo0oO00o ] + " =" + IIo00ooo + clause [ o0o0O0O00oOOo : : ]
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
 OO0OO00oo0 = clause . split ( " " )
 OO0OO00oo0 = OO0OO00oo0 [ 0 ] + " " + OO0OO00oo0 [ 1 ]
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 I1IiIiiIiIII = lisp_core_commands [ "lisp user-account" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if ( ooo0 == False ) :
  IIiIiiii = lisp_replace_password_in_clause ( IIiIiiii , "password =" )
  if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 return ( IIiIiiii )
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
def lisp_rtr_list_command ( clause ) :
 OO0OO00oo0 = clause . split ( " " )
 OO0OO00oo0 = OO0OO00oo0 [ 0 ] + " " + OO0OO00oo0 [ 1 ]
 if 12 - 12: I1ii11iIi11i / Ii1I
 I1IiIiiIiIII = lisp_core_commands [ "lisp rtr-list" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 5 - 5: OoooooooOO
 if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
 if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
 if 93 - 93: Oo0Ooo / I1ii11iIi11i + i1IIi * oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if ( ooo0 ) : return ( IIiIiiii )
 if 33 - 33: I11i % II111iiii + OoO0O00
 lisp . lisp_ms_rtr_list = [ ]
 if ( "address" in I1IiIiiIiIII ) :
  for iI11iI1IiiIiI in I1IiIiiIiIII [ "address" ] :
   II = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   II . store_address ( iI11iI1IiiIiI )
   lisp . lisp_ms_rtr_list . append ( II )
   if 93 - 93: i1IIi . IiII / I1IiiI + IiII
   if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 return ( IIiIiiii )
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
def lisp_process_command_lines ( lisp_socket , old , new , line ) :
 OO0OO00oo0 = line . split ( "{" )
 OO0OO00oo0 = OO0OO00oo0 [ 0 ]
 OO0OO00oo0 = OO0OO00oo0 [ 0 : - 1 ]
 if 33 - 33: Ii1I
 lisp . lprint ( "Process the '{}' command" . format ( OO0OO00oo0 ) )
 if 93 - 93: ooOoO0o
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 if 19 - 19: I1ii11iIi11i
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if ( OO0OO00oo0 not in lisp_commands ) :
  line = "#>>> " + line . replace ( "\n" , " <<< invalid command\n" )
  new . write ( line )
  return
  if 66 - 66: O0
  if 52 - 52: OoO0O00 * OoooooooOO
  if 12 - 12: O0 + IiII * i1IIi . OoO0O00
  if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
  if 28 - 28: iIii1I11I1II1
 iI11II1i1I1 = lisp_commands [ OO0OO00oo0 ]
 o0oo00O0o = False
 for oOoo0 in iI11II1i1I1 :
  if ( oOoo0 == "" ) :
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
  if ( lisp . lisp_is_running ( oOoo0 ) == False ) :
   if ( o0oo00O0o == False ) :
    for line in iIi11I11 : new . write ( line )
    o0oo00O0o = True
    if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
   lisp . lprint ( "Process '{}' is not running, do not send command" . format ( oOoo0 ) )
   if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
   continue
   if 94 - 94: i1IIi
   if 36 - 36: I1IiiI + Oo0Ooo
   if 46 - 46: iII111i
   if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
   if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
   if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
  if ( oOoo0 == "lisp-core" ) :
   if ( iIi11I11 . find ( "enable" ) != - 1 ) :
    IIiIiiii = lisp_enable_command ( iIi11I11 )
    if 65 - 65: ooOoO0o - i1IIi
   if ( iIi11I11 . find ( "debug" ) != - 1 ) :
    IIiIiiii = lisp_debug_command ( lisp_socket , iIi11I11 , None )
    if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
   if ( iIi11I11 . find ( "user-account" ) != - 1 ) :
    IIiIiiii = lisp_user_account_command ( iIi11I11 )
    if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
   if ( iIi11I11 . find ( "rtr-list" ) != - 1 ) :
    IIiIiiii = lisp_rtr_list_command ( iIi11I11 )
    if 34 - 34: I1Ii111 - OOooOOo
  else :
   IIIiIi1iiI = lisp . lisp_command_ipc ( iIi11I11 , "lisp-core" )
   lisp . lisp_ipc ( IIIiIi1iiI , lisp_socket , oOoo0 )
   lisp . lprint ( "Waiting for response to config command '{}'" . format ( OO0OO00oo0 ) )
   if 15 - 15: I1ii11iIi11i . iII111i
   if 94 - 94: I11i . I1IiiI
   iIiiIIi1iiII , oooO00Oo , ooO00o , IIiIiiii = lisp . lisp_receive ( lisp_socket ,
 True )
   if 73 - 73: i1IIi / II111iiii
   if ( oooO00Oo == "" ) :
    lisp . lprint ( "Command timed out to {}" . format ( oOoo0 ) )
    IIiIiiii = iIi11I11
   elif ( oooO00Oo != oOoo0 ) :
    lisp . lprint ( "Fatal IPC error to {}, source {}" . format ( oOoo0 ,
 oooO00Oo ) )
    if 45 - 45: Ii1I / ooOoO0o . OoooooooOO + OoO0O00
    if 51 - 51: iII111i % i11iIiiIii % IiII + I1Ii111 % I1ii11iIi11i
    if 16 - 16: OoOoOO00 / Oo0Ooo + O0 - OoOoOO00 . OoooooooOO
    if 19 - 19: o0oOOo0O0Ooo
    if 73 - 73: I1Ii111 * Oo0Ooo * OoOoOO00
    if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
    if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
  if ( o0oo00O0o == False ) :
   for line in IIiIiiii : new . write ( line )
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
 OOO = 'egrep "{}" {}' . format ( I1iIiIii , file_name )
 o0Oo = getoutput ( OOO )
 if ( o0Oo == "" ) :
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
 for OOo00OoO in I1Ii :
  if ( OOo00OoO . find ( I1iIiIii ) == 0 ) :
   if ( startup ) :
    O00Ooo0ooo0 . write ( OOo00OoO )
   else :
    lisp_write_last_changed_date ( O00Ooo0ooo0 , OOo00OoO )
    if 74 - 74: I11i
   continue
   if 58 - 58: iIii1I11I1II1 * OoO0O00 * I1Ii111 * ooOoO0o . OoooooooOO
   if 6 - 6: I1ii11iIi11i - oO0o * i11iIiiIii + OoOoOO00 / ooOoO0o % OOooOOo
  if ( OOo00OoO . find ( "# Hostname:" ) == 0 ) :
   O00Ooo0ooo0 . write ( "# Hostname: " + lisp . lisp_hostname + "\n" )
   continue
   if 38 - 38: OOooOOo % IiII % II111iiii - Oo0Ooo - iIii1I11I1II1
   if 9 - 9: o0oOOo0O0Ooo % I1ii11iIi11i . I1ii11iIi11i
  if ( lisp_end_file ( OOo00OoO ) ) :
   O00Ooo0ooo0 . write ( OOo00OoO + "\n" )
   break
   if 28 - 28: OoooooooOO % oO0o + I1ii11iIi11i + O0 . I1Ii111
   if 80 - 80: i11iIiiIii % I1ii11iIi11i
  if ( lisp_comment ( OOo00OoO ) ) :
   O00Ooo0ooo0 . write ( OOo00OoO )
   continue
   if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
   if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
  O0oO0oo0O0 = OOo00OoO . replace ( " " , "" )
  O0oO0oo0O0 = O0oO0oo0O0 . replace ( "\n" , "" )
  if ( O0oO0oo0O0 == "" ) : continue
  if 66 - 66: OOooOOo - ooOoO0o - Oo0Ooo
  if 54 - 54: iII111i . i1IIi
  if 19 - 19: ooOoO0o % oO0o
  if 22 - 22: oO0o . II111iiii . Oo0Ooo
  lisp_process_command_lines ( lisp_socket , I1Ii , O00Ooo0ooo0 , OOo00OoO )
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
 IIIIiiI = 0
 if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
 if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
 if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
 if 25 - 25: o0oOOo0O0Ooo
 for OOo00OoO in iiIiiIi :
  if ( lisp_end_file ( OOo00OoO ) ) : break
  if ( lisp_comment ( OOo00OoO ) or OOo00OoO [ 0 ] == "\n" ) : continue
  if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
  if ( lisp_begin_clause ( OOo00OoO ) ) :
   if ( IIIIiiI == 0 ) :
    iIi11I11 = ""
    OO0OO00oo0 = OOo00OoO . split ( "{" )
    OO0OO00oo0 = OO0OO00oo0 [ 0 ]
    OO0OO00oo0 = OO0OO00oo0 [ 0 : - 1 ]
    if ( OO0OO00oo0 in lisp_commands ) :
     ooOo0o = ( process in lisp_commands [ OO0OO00oo0 ] ) or ( OO0OO00oo0 == "lisp debug" )
     if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
     if 41 - 41: i1IIi - I1IiiI
     if 48 - 48: I1IiiI - II111iiii / OoO0O00 + I1IiiI
   IIIIiiI += 1
   if 5 - 5: O0
   if 75 - 75: I1Ii111 + iIii1I11I1II1
   if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
   if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
   if 92 - 92: I11i / O0 * I1IiiI - I11i
  if ( ooOo0o ) : iIi11I11 += OOo00OoO
  if 99 - 99: i11iIiiIii % OoooooooOO
  if 56 - 56: IiII * I1Ii111
  if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
  if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
  if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
  if ( lisp_end_clause ( OOo00OoO ) == False ) : continue
  IIIIiiI -= 1
  if ( IIIIiiI != 0 ) : continue
  if ( ooOo0o == False ) : continue
  if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
  if 56 - 56: i1IIi . i11iIiiIii
  if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
  if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
  if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
  if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
  lisp . lprint ( "Send command '{}' to restarting process '{}'" . format ( OO0OO00oo0 , process ) )
  if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
  if 10 - 10: IiII / OoooooooOO
  if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
  if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
  if 25 - 25: iIii1I11I1II1
  if 63 - 63: ooOoO0o
  if ( OO0OO00oo0 == "lisp debug" ) :
   lisp_debug_command ( lisp_socket , iIi11I11 , process )
   ooOo0o = False
   continue
   if 96 - 96: I11i
   if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
  iIi11I11 = lisp . lisp_command_ipc ( iIi11I11 , "lisp-core" )
  lisp . lisp_ipc ( iIi11I11 , lisp_socket , process )
  if 63 - 63: iII111i
  if 11 - 11: iII111i - iIii1I11I1II1
  if 92 - 92: OoO0O00
  if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
  if 12 - 12: ooOoO0o
  lisp . lprint ( "Waiting for response to config command '{}'" . format ( OO0OO00oo0 ) )
  if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
  if 60 - 60: OOooOOo . iII111i / iIii1I11I1II1 + OOooOOo * I1Ii111
  iIiiIIi1iiII , oooO00Oo , ooO00o , oooo0OOo = lisp . lisp_receive ( lisp_socket , True )
  if 82 - 82: i11iIiiIii . iIii1I11I1II1 * I1IiiI - I11i + Ii1I
  if ( oooO00Oo == "" ) :
   lisp . lprint ( "Command timed out to {}" . format ( process ) )
  elif ( oooO00Oo != process ) :
   lisp . lprint ( "Fatal IPC error to {}, IPC source {}" . format ( process ,
 oooO00Oo ) )
   if 48 - 48: I1ii11iIi11i
  ooOo0o = False
  if 96 - 96: ooOoO0o . OoooooooOO
 return
 if 39 - 39: OOooOOo + OoO0O00
 if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
 if 71 - 71: ooOoO0o . i11iIiiIii
 if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
 if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
 if 67 - 67: iII111i
 if 88 - 88: Oo0Ooo
def lisp_config_process ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 iIIIiIi1i = "./lisp.config"
 i1ii111i = ""
 i1ii1i1Ii11 = True
 if 88 - 88: I1Ii111 % I11i - OoooooooOO + ooOoO0o
 while ( True ) :
  O0O0O = os . path . getmtime ( iIIIiIi1i )
  if ( O0O0O != i1ii111i ) :
   if 53 - 53: i1IIi . i1IIi - I11i / iII111i - OoOoOO00 % I1IiiI
   lisp . lisp_ipc_lock . acquire ( )
   lisp_process_config_file ( lisp_socket , iIIIiIi1i , i1ii1i1Ii11 )
   lisp . lisp_ipc_lock . release ( )
   if 65 - 65: iII111i . OoooooooOO - O0 . iII111i - i11iIiiIii
   i1ii1i1Ii11 = False
   i1ii111i = os . path . getmtime ( iIIIiIi1i )
   if 29 - 29: I1ii11iIi11i . I1IiiI % oO0o - i11iIiiIii
  time . sleep ( 1 )
  if 27 - 27: I1ii11iIi11i - i11iIiiIii % I1Ii111 / Oo0Ooo . Oo0Ooo / OoooooooOO
 return
 if 76 - 76: I11i * OoO0O00 . iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
 if 79 - 79: O0
 if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
 if 15 - 15: I1ii11iIi11i
 if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
 if 88 - 88: oO0o - i1IIi % i11iIiiIii % II111iiii * OoooooooOO
 if 40 - 40: Oo0Ooo
 if 47 - 47: OoOoOO00
def lisp_map_resolver_command ( kv_pair ) :
 Oo0000o = None
 if 33 - 33: OoOoOO00 * I11i
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  if ( IiII1II11I == "mr-name" ) :
   Oo0000o = kv_pair [ IiII1II11I ] [ 0 ]
   continue
   if 48 - 48: OoooooooOO . OoOoOO00
  if ( IiII1II11I == "address" or IiII1II11I == "dns-name" ) :
   oOIIIi11 = kv_pair [ IiII1II11I ]
   for oo00oO0O0 in oOIIIi11 :
    if ( oo00oO0O0 == "" ) : continue
    iI11iI1IiiIiI = oo00oO0O0 if ( IiII1II11I == "address" ) else None
    oooOo00O0 = oo00oO0O0 if ( IiII1II11I == "dns-name" ) else None
    lisp . lisp_mr ( iI11iI1IiiIiI , oooOo00O0 , Oo0000o )
    if 26 - 26: I1Ii111 . Ii1I + I1IiiI . OoOoOO00 + OOooOOo
    if 17 - 17: OOooOOo + i11iIiiIii + I1ii11iIi11i % OOooOOo . oO0o
    if 33 - 33: I11i * I1IiiI % OoOoOO00 . IiII . ooOoO0o . OoO0O00
 return
 if 53 - 53: OoOoOO00
 if 84 - 84: OoO0O00
 if 97 - 97: i1IIi
 if 98 - 98: OoooooooOO - I1IiiI + ooOoO0o
 if 98 - 98: iII111i . IiII . IiII - OOooOOo
 if 65 - 65: Oo0Ooo + o0oOOo0O0Ooo - Ii1I
 if 12 - 12: OoooooooOO + I1ii11iIi11i
def lisp_map_cache_command ( kv_pair ) :
 o0OoO0000oOO = [ ]
 if ( lisp_clause_syntax_error ( kv_pair , "eid-prefix" , "prefix" ) ) : return
 for i1iIIiiIiII in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  i11 = lisp . lisp_mapping ( "" , "" , [ ] )
  o0OoO0000oOO . append ( i11 )
  if 42 - 42: I11i % Oo0Ooo . II111iiii / II111iiii * iII111i
  if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
 III11i1iI11 = [ ]
 if ( "address" in kv_pair ) :
  if ( lisp_clause_syntax_error ( kv_pair , "address" , "rloc" ) ) : return
  for i1iIIiiIiII in range ( len ( kv_pair [ "address" ] ) ) :
   o0o0OOo0O = lisp . lisp_rloc ( )
   III11i1iI11 . append ( o0o0OOo0O )
   if 64 - 64: oO0o * I1ii11iIi11i / i1IIi * OoO0O00 . oO0o
   if 60 - 60: I11i
   if 93 - 93: Oo0Ooo
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if ( IiII1II11I == "instance-id" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    i11 = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "" ) : oOOo0oO = "0"
    i11 . eid . instance_id = int ( oOOo0oO )
    i11 . group . instance_id = int ( oOOo0oO )
    if 25 - 25: Ii1I % II111iiii - oO0o * I1ii11iIi11i - iIii1I11I1II1
    if 46 - 46: II111iiii . O0 * Oo0Ooo + iII111i
  if ( IiII1II11I == "eid-prefix" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    i11 = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : i11 . eid . store_prefix ( oOOo0oO )
    if 40 - 40: O0 . O0 * OOooOOo
    if 38 - 38: iII111i * OoooooooOO
  if ( IiII1II11I == "group-prefix" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    i11 = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : i11 . group . store_prefix ( oOOo0oO )
    if 2 - 2: oO0o - i11iIiiIii
    if 98 - 98: oO0o + OoooooooOO - I1Ii111 % i11iIiiIii / o0oOOo0O0Ooo . OoooooooOO
  if ( IiII1II11I == "send-map-request" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    i11 = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "yes" ) : i11 . action = lisp . LISP_SEND_MAP_REQUEST_ACTION
    if 87 - 87: i1IIi
    if 33 - 33: I1Ii111 % II111iiii
  if ( IiII1II11I == "subscribe-request" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    i11 = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "yes" ) : i11 . action = lisp . LISP_SEND_PUBSUB_ACTION
    if 49 - 49: I1ii11iIi11i + I11i / o0oOOo0O0Ooo + OoooooooOO + OOooOOo / IiII
    if 29 - 29: Ii1I - Ii1I / ooOoO0o
  if ( IiII1II11I == "rle-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) :
     o0o0OOo0O . rle_name = oOOo0oO
     if ( oOOo0oO in lisp . lisp_rle_list ) :
      o0o0OOo0O . rle = lisp . lisp_rle_list [ oOOo0oO ]
      if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
      if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
      if 18 - 18: Oo0Ooo % O0
      if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if ( IiII1II11I == "elp-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) :
     o0o0OOo0O . elp_name = oOOo0oO
     if ( oOOo0oO in lisp . lisp_elp_list ) :
      o0o0OOo0O . elp = lisp . lisp_elp_list [ oOOo0oO ]
      o0o0OOo0O . elp . select_elp_node ( )
      if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
      if 86 - 86: IiII
      if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
      if 33 - 33: II111iiii - IiII - ooOoO0o
  if ( IiII1II11I == "rloc-record-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . rloc_name = oOOo0oO
    if 92 - 92: OoO0O00 * IiII
    if 92 - 92: oO0o
    if 7 - 7: iII111i
  if ( IiII1II11I == "priority" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "" ) : oOOo0oO = "0"
    o0o0OOo0O . priority = int ( oOOo0oO )
    if 73 - 73: OoO0O00 % I1ii11iIi11i
    if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if ( IiII1II11I == "weight" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "" ) : oOOo0oO = "0"
    o0o0OOo0O . weight = int ( oOOo0oO )
    if 62 - 62: i11iIiiIii
    if 2 - 2: I1IiiI
  if ( IiII1II11I == "address" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . rloc . store_address ( oOOo0oO )
    if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
    if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
    if 14 - 14: IiII . IiII % ooOoO0o
    if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
    if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
    if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
    if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
    if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
 for i11 in o0OoO0000oOO :
  i11 . rloc_set = III11i1iI11
  i11 . build_best_rloc_set ( )
  i11 . add_cache ( )
  III11i1iI11 = copy . deepcopy ( III11i1iI11 )
  if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 return
 if 6 - 6: oO0o . I11i
 if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
 if 50 - 50: oO0o % i1IIi * O0
 if 4 - 4: iIii1I11I1II1 . i1IIi
 if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
 if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
 if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
def lisp_display_map_cache ( mc , output ) :
 O0O0O = lisp . lisp_print_elapsed ( mc . uptime )
 o0O = mc . print_eid_tuple ( )
 Iiii = "Recent Sources: "
 Iiii += "none\n" if ( mc . recent_sources == { } ) else "\n"
 for I1IIi1I in mc . recent_sources :
  oo0O = mc . recent_sources [ I1IIi1I ]
  Iiii += "  " + I1IIi1I + ": " + lisp . lisp_print_elapsed ( oo0O ) + "\n"
  if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
 o0O = lisp . lisp_span ( o0O , Iiii [ 0 : - 1 ] )
 i11111 = mc . action
 if 60 - 60: OOooOOo
 if 73 - 73: ooOoO0o
 if 86 - 86: OoOoOO00 . I11i / Oo0Ooo * I11i
 if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
 if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
 if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
 oooO00Oo = mc . mapping_source
 if ( oooO00Oo == None ) :
  oooO00Oo = "map-notify"
 else :
  oooO00Oo = "static" if oooO00Oo . is_null ( ) else oooO00Oo . print_address_no_iid ( )
  if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
  if 5 - 5: O0 - I1IiiI
  if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
 if ( mc . checkpoint_entry ) : oooO00Oo = "checkpoint"
 if ( mc . gleaned ) : oooO00Oo = "gleaned"
 i1iIi = mc . print_ttl ( )
 if 22 - 22: iII111i + OoO0O00 - ooOoO0o
 i11111 = "encapsulate" if i11111 == lisp . LISP_NO_ACTION else lisp . lisp_map_reply_action_string [ i11111 ]
 if 10 - 10: I1IiiI / I1ii11iIi11i
 if 68 - 68: OOooOOo - OoooooooOO
 if ( len ( mc . rloc_set ) == 0 ) :
  IiIII = mc . stats . get_stats ( True , True )
  output += lisp_table_row ( o0O , O0O0O + "<br>" + i1iIi , "--" , oooO00Oo ,
 IiIII , i11111 , "--" )
  return ( [ True , output ] )
  if 38 - 38: iIii1I11I1II1 + I1IiiI + I11i * OoO0O00 + OoO0O00 + i11iIiiIii
  if 56 - 56: Ii1I + I1IiiI - o0oOOo0O0Ooo / o0oOOo0O0Ooo . II111iiii - Ii1I
 for o0o0OOo0O in mc . rloc_set :
  i1 = ""
  if ( o0o0OOo0O . rloc_exists ( ) ) :
   if ( o0o0OOo0O . rloc . is_null ( ) == False ) :
    i1 += o0o0OOo0O . rloc . print_address_no_iid ( ) + "<br>"
    Iiii = ""
    oo = lisp . lisp_nonce_echoing and o0o0OOo0O . echo_nonce_capable
    if ( lisp . lisp_rloc_probing ) :
     Iiii += o0o0OOo0O . print_rloc_probe_state ( oo )
     if 83 - 83: O0 + OoOoOO00 / O0 / I11i
    if ( oo ) :
     Oo = lisp . lisp_get_echo_nonce ( o0o0OOo0O . rloc , None )
     if ( Oo ) : Iiii += Oo . print_echo_nonce ( )
     if 15 - 15: i1IIi + IiII % I1IiiI / i11iIiiIii * OoOoOO00
    if ( Iiii != "" ) : i1 = lisp . lisp_span ( i1 , Iiii )
    if 69 - 69: i11iIiiIii
    if 61 - 61: O0
    if 21 - 21: OoO0O00 % iIii1I11I1II1 . OoO0O00
  if ( o0o0OOo0O . translated_port != 0 ) :
   i1 += "encap-port: {}<br>" . format ( o0o0OOo0O . translated_port )
   if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
   if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
  if ( o0o0OOo0O . rloc_name ) :
   i1 += "rloc-name: {}<br>" . format ( lisp . blue ( o0o0OOo0O . rloc_name ,
 True ) )
   if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
   if 31 - 31: oO0o * I1Ii111 . OoOoOO00 * I11i
  if ( o0o0OOo0O . geo ) :
   i1 += "geo: {}<br>" . format ( o0o0OOo0O . geo . print_geo_url ( ) )
   if 28 - 28: IiII + I1IiiI - Oo0Ooo % OOooOOo . I11i + I1IiiI
  if ( o0o0OOo0O . elp ) :
   O0oO0 = o0o0OOo0O . elp . print_elp ( True )
   i1 += "elp: {}<br>" . format ( O0oO0 )
   if 65 - 65: OOooOOo + I1Ii111 - Ii1I
  if ( o0o0OOo0O . rle ) :
   o0OOO = o0o0OOo0O . rle . print_rle ( True , True )
   i1 += "rle: {}<br>" . format ( o0OOO )
   if 5 - 5: O0 . I1Ii111 . Ii1I + iII111i * i1IIi % IiII
  if ( o0o0OOo0O . json ) :
   if ( lisp . lisp_is_json_telemetry ( o0o0OOo0O . json . json_string ) == None ) :
    oOO00O0Ooooo00 = "json: { ... }<br>"
    i1 += lisp . lisp_span ( oOO00O0Ooooo00 , o0o0OOo0O . json . print_json ( False ) )
    if 18 - 18: OoO0O00 % oO0o . iII111i . Ii1I . iII111i - I1Ii111
    if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
    if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
    if 55 - 55: OoooooooOO
    if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
    if 38 - 38: O0
  IiIII = o0o0OOo0O . stats . get_stats ( True , True )
  if 79 - 79: i1IIi . oO0o
  if 34 - 34: I1Ii111 * II111iiii
  if 71 - 71: IiII
  if 97 - 97: I1ii11iIi11i
  OOo0oO0o = ""
  iI1iI = o0o0OOo0O
  while ( True ) :
   O0oo0000o = lisp . lisp_print_elapsed ( iI1iI . last_state_change )
   if ( O0oo0000o == "never" ) :
    O0oo0000o = lisp . lisp_print_elapsed ( iI1iI . uptime )
    if 99 - 99: oO0o - I1ii11iIi11i . II111iiii * i11iIiiIii . OOooOOo - OoO0O00
   I1IIi1I = iI1iI . print_state ( )
   if ( iI1iI . unreach_state ( ) or iI1iI . no_echoed_nonce_state ( ) ) :
    I1IIi1I = lisp . red ( I1IIi1I , True )
    if 31 - 31: i11iIiiIii * Ii1I . o0oOOo0O0Ooo % OOooOOo * I1ii11iIi11i % O0
   OOo0oO0o += I1IIi1I + " since " + O0oo0000o
   if 77 - 77: OoO0O00 + OoO0O00 . ooOoO0o * OoooooooOO + OoO0O00
   if ( lisp . lisp_rloc_probing ) :
    ii111I1i1 = iI1iI . print_rloc_probe_rtt ( )
    if ( ii111I1i1 != "none" ) :
     OOo0oO0o += "<br>rtt: {}, hops: {}, latency: {}" . format ( ii111I1i1 , iI1iI . print_rloc_probe_hops ( ) ,
     # iIii1I11I1II1 . i11iIiiIii / OOooOOo + II111iiii / oO0o
 iI1iI . print_rloc_probe_latency ( ) )
     if 48 - 48: O0
     if 26 - 26: I11i + I1Ii111 + I11i / I1Ii111
     if 79 - 79: o0oOOo0O0Ooo - II111iiii
   if ( lisp . lisp_rloc_probing and iI1iI . rloc_next_hop != None ) :
    OO0oo0O0OOO0 , O0Ooo0o = iI1iI . rloc_next_hop
    OOo0oO0o += "<br>{}nh {}({}) " . format ( lisp . lisp_space ( 2 ) , O0Ooo0o , OO0oo0O0OOO0 )
    if 75 - 75: iII111i + iIii1I11I1II1
    if 98 - 98: OoOoOO00 - OoOoOO00 . II111iiii . iII111i + O0
   iI1iI = iI1iI . next_rloc
   if ( iI1iI == None ) : break
   OOo0oO0o += "<br>"
   if 28 - 28: IiII + i11iIiiIii + OoooooooOO / OoO0O00
   if 6 - 6: I1IiiI - i11iIiiIii
  if ( i11111 == "encapsulate" ) :
   ooO00o = lisp . LISP_DATA_PORT
   if ( lisp . lisp_i_am_rtr and o0o0OOo0O . translated_port != 0 ) :
    ooO00o = o0o0OOo0O . translated_port
    if 61 - 61: I1Ii111 * I1ii11iIi11i % I1IiiI % OoO0O00 % I11i + I11i
    if 6 - 6: Oo0Ooo
   iI11iI1IiiIiI = o0o0OOo0O . rloc . print_address_no_iid ( ) + ":" + str ( ooO00o )
   if ( iI11iI1IiiIiI in lisp . lisp_crypto_keys_by_rloc_encap ) :
    o0 = lisp . lisp_crypto_keys_by_rloc_encap [ iI11iI1IiiIiI ] [ 1 ]
    if ( o0 != None and o0 . shared_key != None ) :
     i11111 = "encap-crypto-" + o0 . cipher_suite_string
     if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
     if 93 - 93: i11iIiiIii
     if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
     if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
  output += lisp_table_row ( o0O , O0O0O + "<br>" + i1iIi , i1 , oooO00Oo ,
 IiIII , OOo0oO0o + "<br>" + i11111 ,
 str ( o0o0OOo0O . priority ) + "/" + str ( o0o0OOo0O . weight ) + "<br>" + str ( o0o0OOo0O . mpriority ) + "/" + str ( o0o0OOo0O . mweight ) )
  if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
  if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
  if ( o0O != "" ) : o0O = ""
  if ( O0O0O != "" ) : O0O0O , i1iIi , oooO00Oo = ( "" , "" , "" )
  if 58 - 58: I11i
 return ( [ True , output ] )
 if 7 - 7: II111iiii / IiII % I11i + I1IiiI - O0
 if 45 - 45: I1IiiI / iII111i + oO0o + IiII
 if 15 - 15: I1IiiI % OoO0O00
 if 66 - 66: oO0o * i11iIiiIii . I1Ii111
 if 92 - 92: oO0o
 if 81 - 81: o0oOOo0O0Ooo % I1IiiI - iII111i / i11iIiiIii
 if 73 - 73: O0 * I1Ii111 . i1IIi
 if 51 - 51: OoO0O00 - iII111i % O0 - OoOoOO00
def lisp_walk_map_cache ( mc , output ) :
 if 53 - 53: iII111i / i1IIi / i1IIi
 if 77 - 77: I11i + i1IIi . I11i
 if 89 - 89: o0oOOo0O0Ooo + OOooOOo * oO0o
 if 45 - 45: iII111i - o0oOOo0O0Ooo . Ii1I
 if ( mc . group . is_null ( ) ) : return ( lisp_display_map_cache ( mc , output ) )
 if 41 - 41: II111iiii . I1IiiI / OoO0O00 . ooOoO0o
 if ( mc . source_cache == None ) : return ( [ True , output ] )
 if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
 if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
 if 36 - 36: I11i - IiII . IiII
 if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
 if 84 - 84: iIii1I11I1II1 + OoooooooOO
 output = mc . source_cache . walk_cache ( lisp_display_map_cache , output )
 return ( [ True , output ] )
 if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
 if 10 - 10: I1ii11iIi11i + IiII
 if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
 if 62 - 62: II111iiii
 if 12 - 12: IiII + II111iiii
 if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
 if 80 - 80: iII111i
def lisp_show_myrlocs ( output ) :
 if ( lisp . lisp_myrlocs [ 2 ] == None ) :
  output += "No local RLOCs found"
 else :
  iI1I1ii11IIi1 = lisp . lisp_print_cour ( lisp . lisp_myrlocs [ 2 ] )
  OOo = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 0 ] != None else "not found"
  if 80 - 80: o0oOOo0O0Ooo / oO0o / Ii1I - I1IiiI % I1Ii111
  OOo = lisp . lisp_print_cour ( OOo )
  Ii1I1iIiiI1 = "-f inet" if lisp . lisp_is_macos ( ) else "-4"
  o00 = getoutput ( "netstat -rn {}" . format ( Ii1I1iIiiI1 ) )
  OOo = lisp . lisp_span ( OOo , o00 )
  if 29 - 29: ooOoO0o * IiII
  oOiiIIIII = lisp . lisp_myrlocs [ 1 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 1 ] != None else "not found"
  if 19 - 19: II111iiii / OoOoOO00
  oOiiIIIII = lisp . lisp_print_cour ( oOiiIIIII )
  Ii1I1iIiiI1 = "-f inet6" if lisp . lisp_is_macos ( ) else "-6"
  o00 = getoutput ( "netstat -rn {}" . format ( Ii1I1iIiiI1 ) )
  oOiiIIIII = lisp . lisp_span ( oOiiIIIII , o00 )
  if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
  OOo00OoO = "<i>Local RLOCs found on interface </i>{}<i>, " + "IPv4: </i>{}<i>, IPv6: </i>{}"
  if 76 - 76: I1IiiI * OOooOOo
  output += lisp . lisp_print_sans ( OOo00OoO ) . format ( iI1I1ii11IIi1 , OOo , oOiiIIIII )
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
 Iiii = "{} entries in the NAT-traversal port table" . format ( Oo00o )
 oooo00Oo0O = lisp . lisp_span ( "NAT-Traversed xTR Information:" , Iiii )
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
 for Ii1 in list ( lisp . lisp_nat_state_info . values ( ) ) :
  for iIIi11 in Ii1 :
   II = iIIi11 . address
   OO = iIIi11 . uptime
   O0I11i1i11i1I = iIIi11 . hostname
   ooO00o = iIIi11 . port
   if 10 - 10: OoOoOO00 * i1IIi
   if ( iIIi11 . timed_out ( ) ) :
    OO = lisp . red ( lisp . lisp_print_elapsed ( OO ) , True )
   else :
    OO = lisp . lisp_print_elapsed ( OO )
    if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
    if 34 - 34: I1IiiI
   if ( dodns ) :
    try :
     o0OoOo0O00 = socket . gethostbyaddr ( II ) [ 0 ]
    except :
     o0OoOo0O00 = "?"
     if 9 - 9: OOooOOo
    output += lisp_table_row ( O0I11i1i11i1I , II , ooO00o , OO , o0OoOo0O00 )
   else :
    output += lisp_table_row ( O0I11i1i11i1I , II , ooO00o , OO )
    if 38 - 38: I11i . OoO0O00 . i11iIiiIii * OoooooooOO + iII111i
    if 49 - 49: Oo0Ooo - OoO0O00 / I1Ii111 / o0oOOo0O0Ooo % oO0o
    if 38 - 38: o0oOOo0O0Ooo . oO0o / o0oOOo0O0Ooo % II111iiii
    if 47 - 47: I11i * iIii1I11I1II1 * iII111i - OoO0O00 . O0 . ooOoO0o
 output += lisp_table_footer ( )
 return ( output )
 if 32 - 32: o0oOOo0O0Ooo % I1IiiI
 if 7 - 7: Oo0Ooo . i1IIi - oO0o
 if 93 - 93: IiII % I1ii11iIi11i
 if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
 if 28 - 28: Ii1I . I1ii11iIi11i
 if 77 - 77: I1ii11iIi11i % II111iiii
 if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
def lisp_itr_rtr_show_command ( parameter , itr_or_rtr , lisp_threads , dns = False ) :
 if 90 - 90: o0oOOo0O0Ooo
 if 44 - 44: o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo + OoOoOO00
 if 32 - 32: IiII - ooOoO0o * iII111i * I11i
 if 84 - 84: Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
 if ( parameter != "" ) :
  return ( lisp_show_map_cache_lookup ( parameter ) )
  if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
  if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
 o0o0oOOOo0oo = ""
 if 1 - 1: Oo0Ooo . II111iiii
 if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
 if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
 if 4 - 4: IiII
 o0o0oOOOo0oo = lisp_show_myrlocs ( o0o0oOOOo0oo )
 if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
 if 99 - 99: i11iIiiIii - iII111i
 if 85 - 85: I1Ii111 % I1ii11iIi11i
 if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
 if ( itr_or_rtr == "RTR" ) :
  o0o0oOOOo0oo = lisp_show_decap_stats ( o0o0oOOOo0oo , itr_or_rtr )
  if 73 - 73: OoO0O00
  if 28 - 28: OoooooooOO - I11i
  if 84 - 84: II111iiii
  if 36 - 36: OOooOOo - OoOoOO00 - iIii1I11I1II1
  if 10 - 10: I1ii11iIi11i / Ii1I * i1IIi % O0 + I11i
 if ( len ( lisp_threads ) > 1 ) :
  I1IIi1I = [ ]
  for i1iIIiiIiII in range ( len ( lisp_threads ) ) :
   oo0O = lisp_threads [ i1iIIiiIiII ]
   I1IIi1I . append ( "{} Input Stats<br>queue-size: {}" . format ( oo0O . thread_name ,
 oo0O . input_queue . qsize ( ) ) )
   if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
  o0o0oOOOo0oo += lisp_table_header ( "LISP-RTR Forwarding Stats:" , * I1IIi1I )
  if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
  I1IIi1I = [ ]
  for i1iIIiiIiII in range ( len ( lisp_threads ) ) :
   oo0O = lisp_threads [ i1iIIiiIiII ]
   I1IIi1I . append ( oo0O . input_stats . get_stats ( False , True ) )
   if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
  o0o0oOOOo0oo += lisp_table_row ( * I1IIi1I )
  o0o0oOOOo0oo += lisp_table_footer ( )
  if 80 - 80: Ii1I
  if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
 oOo0O0 = lisp . lisp_decent_dns_suffix
 if ( oOo0O0 == None ) :
  oOo0O0 = ":"
 else :
  oOo0O0 = "&nbsp;(dns-suffix '{}'):" . format ( oOo0O0 )
  if 1 - 1: oO0o + I1Ii111 . I1IiiI
  if 47 - 47: iII111i . OoOoOO00
  if 58 - 58: iII111i + Oo0Ooo / I1IiiI
  if 68 - 68: IiII * Ii1I
  if 91 - 91: Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
 Iiii = "{} map-resolvers configured" . format ( len ( lisp . lisp_map_resolvers_list ) )
 if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
 oooo00Oo0O = "LISP-{} Configured Map-Resolvers{}" . format ( itr_or_rtr , oOo0O0 )
 oooo00Oo0O = lisp . lisp_span ( oooo00Oo0O , Iiii )
 if 46 - 46: i11iIiiIii
 o0o0oOOOo0oo += lisp_table_header ( oooo00Oo0O , "Map-Resolver" , "Last Used" ,
 "Map-Requests<br>Sent" , "Negative Map-Replies<br>Received" ,
 "Last Negative<br>Map-Reply" , "Average RTT" )
 if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
 for Oo0oOo0O0O0o in list ( lisp . lisp_map_resolvers_list . values ( ) ) :
  Oo0oOo0O0O0o . resolve_dns_name ( )
  Oo0000o = "" if Oo0oOo0O0O0o . mr_name == "all" else Oo0oOo0O0O0o . mr_name + "<br>"
  iI11iI1IiiIiI = Oo0000o + Oo0oOo0O0O0o . map_resolver . print_address_no_iid ( )
  if ( Oo0oOo0O0O0o . dns_name ) : iI11iI1IiiIiI += "<br>" + Oo0oOo0O0O0o . dns_name
  if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
  O0O0O = lisp . lisp_print_elapsed ( Oo0oOo0O0O0o . last_used )
  I11IIiI1IiI1 = lisp . lisp_print_elapsed ( Oo0oOo0O0O0o . last_reply )
  iI11IiiiIII = 0 if Oo0oOo0O0O0o . neg_map_replies_received == 0 else float ( old_div ( Oo0oOo0O0O0o . total_rtt / Oo0oOo0O0O0o . neg_map_replies_received ) )
  if 43 - 43: iII111i + i11iIiiIii
  iI11IiiiIII = str ( round ( iI11IiiiIII , 3 ) ) + " ms"
  if 96 - 96: OOooOOo . OoOoOO00 * O0
  o0o0oOOOo0oo += lisp_table_row ( iI11iI1IiiIiI , O0O0O , Oo0oOo0O0O0o . map_requests_sent ,
 Oo0oOo0O0O0o . neg_map_replies_received , I11IIiI1IiI1 , iI11IiiiIII )
  if 69 - 69: IiII
 o0o0oOOOo0oo += lisp_table_footer ( )
 if 81 - 81: I1IiiI
 if 58 - 58: OoOoOO00 + OoO0O00 * Ii1I
 if 31 - 31: oO0o - iII111i
 if 46 - 46: I1IiiI + Oo0Ooo - Ii1I
 if ( itr_or_rtr == "ITR" ) : o0o0oOOOo0oo = lisp_show_db_list ( "ITR" , o0o0oOOOo0oo )
 if 99 - 99: OOooOOo + I1IiiI . I1ii11iIi11i * OoooooooOO
 if 82 - 82: i11iIiiIii + iIii1I11I1II1 / Oo0Ooo + OOooOOo * II111iiii
 if 34 - 34: o0oOOo0O0Ooo % OoooooooOO
 if 36 - 36: I1IiiI
 O0OoOoo00o = "<br>Enter EID for Map-Cache lookup:"
 if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
 o00o0 = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
 o0Oo0oO00Oooo = itr_or_rtr . lower ( )
 if 31 - 31: i1IIi * Oo0Ooo % Ii1I + OoO0O00
 O0OoOoo00o = '''
         <form action="/lisp/show/{}/map-cache/lookup" method="post">
         <font size="3"><i>{}</i> {}
         <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form>
    ''' . format ( o0Oo0oO00Oooo , lisp . lisp_print_sans ( O0OoOoo00o ) , o00o0 )
 if 75 - 75: OOooOOo / I1Ii111 - II111iiii % i11iIiiIii + OoO0O00
 i1iiiiii1 = '<a href="/lisp/show/{}/rloc-probing">RLOC State</a>' . format ( o0Oo0oO00Oooo )
 if 83 - 83: I1IiiI - I1Ii111 + I1IiiI . I1IiiI
 ii11ii11II = '<a href="/lisp/show/{}/keys"><br>RLOC Keys</a>' . format ( o0Oo0oO00Oooo )
 if 35 - 35: Oo0Ooo * II111iiii
 if 32 - 32: oO0o . Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
 if 50 - 50: iIii1I11I1II1 * oO0o
 if 85 - 85: i1IIi
 Oo00 = os . path . exists ( "./show-ztr" )
 iIIiIi111iI = "Map-Cache"
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None or Oo00 ) :
  iIIiIi111iI = '<a href="/lisp/show/lisp-xtr">Map-Cache</a>'
  if 40 - 40: OoOoOO00 + OoO0O00 % OoooooooOO * o0oOOo0O0Ooo / OoOoOO00 + OoooooooOO
  if 91 - 91: ooOoO0o - oO0o + oO0o
  if 14 - 14: I1ii11iIi11i * I1Ii111 % i1IIi / I1ii11iIi11i
  if 48 - 48: Oo0Ooo
  if 75 - 75: I1ii11iIi11i - IiII * Oo0Ooo . OoooooooOO * I1Ii111 * I1IiiI
 Iiii = "{} entries in the map-cache" . format ( lisp . lisp_map_cache . cache_size ( ) )
 if 30 - 30: OoOoOO00 / oO0o / Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
 oooo00Oo0O = "LISP-{} {}:{}" . format ( itr_or_rtr , iIIiIi111iI , lisp . lisp_space ( 4 ) )
 oooo00Oo0O = lisp . lisp_span ( oooo00Oo0O , Iiii )
 if 93 - 93: OoOoOO00
 if 97 - 97: i11iIiiIii
 if 68 - 68: IiII * OoO0O00 . I11i / Ii1I . o0oOOo0O0Ooo - i11iIiiIii
 if 49 - 49: Oo0Ooo / Ii1I % I11i + oO0o - OoO0O00
 if 13 - 13: II111iiii
 oooo00Oo0O += lisp . lisp_button ( "clear cache" ,
 "/lisp/clear/{}/map-cache" . format ( itr_or_rtr . lower ( ) ) )
 oooo00Oo0O += O0OoOoo00o
 if 83 - 83: OoooooooOO . I1IiiI + Ii1I * O0 / oO0o
 if 8 - 8: i1IIi + II111iiii / Ii1I + I1ii11iIi11i % Ii1I - iIii1I11I1II1
 o0o0oOOOo0oo += lisp_table_header ( oooo00Oo0O , "EID-Prefix or (S,G)" ,
 "Uptime<br>TTL" , "RLOC Record" + ii11ii11II , "Map-Reply Source" ,
 "RLOC Send Stats" , i1iiiiii1 + "<br>RLOC Action" ,
 "Unicast Priority/Weight<br>Multicast Priority/Weight" )
 if 29 - 29: Oo0Ooo + II111iiii
 o0o0oOOOo0oo = lisp . lisp_map_cache . walk_cache ( lisp_walk_map_cache , o0o0oOOOo0oo )
 o0o0oOOOo0oo += lisp_table_footer ( )
 if 95 - 95: oO0o
 if 48 - 48: I11i / iIii1I11I1II1 % II111iiii
 if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
 if 100 - 100: OoooooooOO - OoooooooOO + IiII
 if ( len ( lisp . lisp_elp_list ) != 0 ) : o0o0oOOOo0oo = lisp_show_elp_list ( o0o0oOOOo0oo )
 if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo / OoooooooOO
 if 90 - 90: I1Ii111
 if 35 - 35: II111iiii / Ii1I
 if 79 - 79: OoOoOO00 + I1Ii111 * iII111i * Ii1I
 if ( len ( lisp . lisp_rle_list ) != 0 ) : o0o0oOOOo0oo = lisp_show_rle_list ( o0o0oOOOo0oo )
 if 53 - 53: OOooOOo / Oo0Ooo
 if 10 - 10: I1ii11iIi11i . o0oOOo0O0Ooo
 if 75 - 75: O0 * i1IIi - I11i / OOooOOo % OOooOOo / OoOoOO00
 if 5 - 5: O0 - iII111i / I1Ii111 . o0oOOo0O0Ooo
 if ( len ( lisp . lisp_json_list ) != 0 ) : o0o0oOOOo0oo = lisp_show_json_list ( o0o0oOOOo0oo )
 if 7 - 7: I1ii11iIi11i - OoOoOO00
 if 54 - 54: oO0o / iIii1I11I1II1 / OoooooooOO . i1IIi - OoOoOO00
 if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
 if 46 - 46: Ii1I
 if ( itr_or_rtr == "RTR" ) :
  o0o0oOOOo0oo = lisp_display_nat_info ( o0o0oOOOo0oo , "Data" , dns )
  if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
  if 87 - 87: I1ii11iIi11i / I1IiiI
  if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
  if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
  if 11 - 11: I1ii11iIi11i - OoooooooOO
 return ( o0o0oOOOo0oo )
 if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
 if 27 - 27: IiII + iIii1I11I1II1 / Oo0Ooo + OoO0O00 % Oo0Ooo + OoO0O00
 if 77 - 77: Oo0Ooo * ooOoO0o % Ii1I
 if 2 - 2: I11i / Oo0Ooo / Ii1I / I1ii11iIi11i / OoooooooOO
 if 22 - 22: iIii1I11I1II1 * I1IiiI / I11i + OoOoOO00
 if 98 - 98: OOooOOo
 if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
def lisp_itr_rtr_show_rloc_probe_command ( itr_or_rtr ) :
 oooo00Oo0O = "LISP-{} RLOC-Probe Information:" . format ( itr_or_rtr )
 o0o0oOOOo0oo = lisp_table_header ( oooo00Oo0O , "RLOC Key State" , "RLOC-Probe State" )
 if 75 - 75: OoO0O00 % OoooooooOO
 for iiiI in list ( lisp . lisp_rloc_probe_list . values ( ) ) :
  o0O = ""
  for iI1iI , ooo0o00o , O0oOOo0 in iiiI :
   oooOOOoO0O = lisp . green ( lisp . lisp_print_eid_tuple ( ooo0o00o , O0oOOo0 ) , True )
   o0O += lisp . lisp_print_cour ( oooOOOoO0O ) + "<br>"
   if 2 - 2: o0oOOo0O0Ooo . Ii1I % OoOoOO00
  o0O = ", EIDs ({}):<br>" . format ( len ( iiiI ) ) + o0O
  if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
  iI1iI , ooo0o00o , O0oOOo0 = iiiI [ 0 ]
  if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
  if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
  if 58 - 58: iII111i
  if 2 - 2: II111iiii + i1IIi
  O0Ooo0o = lisp . lisp_hex_string ( iI1iI . last_rloc_probe_nonce )
  if ( iI1iI . translated_rloc . not_set ( ) ) :
   oO0OO00 = iI1iI . rloc . print_address_no_iid ( )
  else :
   oO0OO00 = "{}{}{}" . format ( iI1iI . translated_rloc . print_address_no_iid ( ) ,
 lisp . bold ( ":" , True ) , iI1iI . translated_port )
   if 16 - 16: OoooooooOO / oO0o . Ii1I * ooOoO0o - I1IiiI
  oO0OO00 = lisp . bold ( lisp . lisp_print_cour ( oO0OO00 ) , True )
  iiIi = iI1iI . rloc_name
  if ( iiIi != None ) :
   iiIi = lisp . bold ( iiIi , True )
   oO0OO00 += ", {}" . format ( lisp . lisp_print_cour ( lisp . blue ( iiIi , True ) ) )
   if 94 - 94: iIii1I11I1II1 + IiII
  OOo0oO0o = iI1iI . print_state ( )
  if ( iI1iI . up_state ( ) == False ) : OOo0oO0o = lisp . red ( iI1iI . print_state ( ) , True )
  oO0OO00 = "RLOC " + oO0OO00 + ", {}" . format ( OOo0oO0o )
  if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
  Ii1iII1ii1 = oO0OO00 + o0O
  if 80 - 80: iIii1I11I1II1 / i11iIiiIii + iII111i
  if 41 - 41: I1Ii111 + OoO0O00 * I1IiiI * O0 * Oo0Ooo - OoOoOO00
  if 96 - 96: I1IiiI - iIii1I11I1II1
  if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
  ooo000 = [ iI1iI ]
  if ( iI1iI . multicast_rloc_probe_list != { } ) :
   ooo000 += list ( iI1iI . multicast_rloc_probe_list . values ( ) )
   if 82 - 82: iIii1I11I1II1 * OoooooooOO
   if 50 - 50: I1Ii111 - II111iiii
   if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
   if 16 - 16: IiII
   if 10 - 10: OoOoOO00 . IiII * iIii1I11I1II1 - oO0o - OoOoOO00 / I1Ii111
  II1I11 = ""
  for iI1iI in ooo000 :
   if ( len ( ooo000 ) != 1 ) :
    oO0OO00 = iI1iI . rloc . print_address_no_iid ( )
    oO0OO00 = lisp . bold ( lisp . lisp_print_cour ( oO0OO00 ) , True )
    if ( ooo000 . index ( iI1iI ) != 0 ) : II1I11 += "<br><br>"
    II1I11 += "RLOC {}:<br>" . format ( oO0OO00 )
    if 20 - 20: I1Ii111 . i1IIi
    if 9 - 9: OoO0O00
   ooOo = lisp . lisp_print_elapsed ( iI1iI . last_rloc_probe )
   ooOo = lisp . lisp_print_cour ( ooOo )
   OO00oOOO = lisp . lisp_print_elapsed ( iI1iI . last_rloc_probe_reply )
   OO00oOOO = lisp . lisp_print_cour ( OO00oOOO )
   O0Ooo0o = lisp . lisp_hex_string ( iI1iI . last_rloc_probe_nonce )
   O0Ooo0o = lisp . lisp_print_cour ( "0x" + O0Ooo0o )
   II1I11 += ( "Last probe-request sent: {}, " + "last probe-reply received: {}, nonce: {}<br>" ) . format ( ooOo ,
   # I1Ii111 . i11iIiiIii + OoooooooOO / i11iIiiIii . OoooooooOO % I1IiiI
 OO00oOOO , O0Ooo0o )
   if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
   ii111I1i1 = iI1iI . print_recent_rloc_probe_rtts ( )
   ii111I1i1 = lisp . lisp_print_cour ( ii111I1i1 )
   Iii11I1i = iI1iI . print_recent_rloc_probe_hops ( )
   Iii11I1i = lisp . lisp_print_cour ( Iii11I1i )
   oO0OOoOO = iI1iI . print_recent_rloc_probe_latencies ( )
   oO0OOoOO = lisp . lisp_print_cour ( oO0OOoOO )
   oOoO = iI1iI . print_rloc_probe_hops ( )
   oOoO = lisp . lisp_print_cour ( oOoO )
   oO0Oo = iI1iI . print_rloc_probe_latency ( )
   oO0Oo = lisp . lisp_print_cour ( oO0Oo )
   iI1iI = iI1iI . print_rloc_probe_rtt ( )
   iI1iI = lisp . lisp_print_cour ( iI1iI )
   II1I11 += ( "Telemetry: rtt: {}, hops: {}, latency: {}<br>" + "recent-rtts: {}, recent-hops: {}, recent-latencies: {}" ) . format ( iI1iI , oOoO , oO0Oo , ii111I1i1 , Iii11I1i , oO0OOoOO )
   if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
   if 23 - 23: I11i
   if 36 - 36: IiII . iII111i - i1IIi + I1Ii111
   if 54 - 54: OoooooooOO . oO0o - iII111i
   if 76 - 76: I1Ii111
   if 61 - 61: ooOoO0o / II111iiii * ooOoO0o * OoOoOO00 * I1Ii111 . i11iIiiIii
   if 26 - 26: I1Ii111 / ooOoO0o - OoO0O00 . iIii1I11I1II1
  o0o0oOOOo0oo += lisp_table_row ( Ii1iII1ii1 , II1I11 )
  if 83 - 83: ooOoO0o % Ii1I / Oo0Ooo - iII111i / O0
  if 97 - 97: iIii1I11I1II1 * I11i
 o0o0oOOOo0oo += lisp_table_footer ( )
 return ( o0o0oOOOo0oo )
 if 95 - 95: OoO0O00
 if 68 - 68: iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00 - II111iiii - iIii1I11I1II1
 if 75 - 75: ooOoO0o . I1IiiI * II111iiii
 if 99 - 99: iIii1I11I1II1 * I1ii11iIi11i + IiII
 if 70 - 70: i1IIi % ooOoO0o . I1ii11iIi11i - IiII + OOooOOo
 if 84 - 84: oO0o + II111iiii * II111iiii % o0oOOo0O0Ooo / iII111i + ooOoO0o
 if 9 - 9: iII111i
def lisp_xtr_command ( kv_pair ) :
 if 25 - 25: OOooOOo - Ii1I . I11i
 if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
 if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
 if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
 if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) :
  kv_pair [ "ipc-data-plane" ] = [ "yes" ]
  if 100 - 100: i1IIi % Ii1I
  if 55 - 55: I1IiiI + iII111i
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ] [ 0 ]
  if ( IiII1II11I == "rloc-probing" ) :
   lisp . lisp_rloc_probing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_rloc_probe_list = { }
   if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
  if ( IiII1II11I == "nonce-echoing" ) :
   lisp . lisp_nonce_echoing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_nonce_echo_list = { }
   if 19 - 19: I11i / iII111i + IiII
  if ( IiII1II11I == "data-plane-security" ) :
   lisp . lisp_data_plane_security = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) :
    lisp . lisp_crypto_keys_by_nonce = { }
    lisp . lisp_crypto_keys_by_rloc_encap = { }
    lisp . lisp_crypto_keys_by_rloc_decap = { }
    if 76 - 76: iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo + OoooooooOO
    if 10 - 10: OoO0O00 * I11i / Oo0Ooo - I1Ii111
  if ( IiII1II11I == "data-plane-logging" ) :
   lisp . lisp_data_plane_logging = ( oo00oO0O0 == "yes" )
   if 11 - 11: IiII % I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - II111iiii
  if ( IiII1II11I == "frame-logging" ) :
   lisp . lisp_frame_logging = ( oo00oO0O0 == "yes" )
   if 50 - 50: i1IIi * oO0o / i11iIiiIii / i11iIiiIii / oO0o
  if ( IiII1II11I == "flow-logging" ) :
   lisp . lisp_flow_logging = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "yes" ) : os . system ( "touch ./log-flows" )
   if 84 - 84: I1ii11iIi11i - iII111i + I1ii11iIi11i
  if ( IiII1II11I == "nat-traversal" ) :
   lisp . lisp_nat_traversal = ( oo00oO0O0 == "yes" )
   if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
  if ( IiII1II11I == "program-hardware" ) :
   lisp . lisp_program_hardware = ( oo00oO0O0 == "yes" )
   if 96 - 96: IiII
  if ( IiII1II11I == "checkpoint-map-cache" ) :
   lisp . lisp_checkpoint_map_cache = ( oo00oO0O0 == "yes" )
   oo00OOo0 = lisp . lisp_checkpoint_filename
   if ( oo00oO0O0 == "no" and os . path . exists ( oo00OOo0 ) ) :
    os . system ( "rm {}" . format ( oo00OOo0 ) )
    if 61 - 61: oO0o % ooOoO0o - I1ii11iIi11i + oO0o . OoOoOO00
    if 44 - 44: I1ii11iIi11i / O0 - IiII + OOooOOo . I11i . I1ii11iIi11i
  if ( IiII1II11I == "ipc-data-plane" ) :
   OO000oOO0o = ( oo00oO0O0 == "yes" )
   if ( OO000oOO0o and lisp . lisp_ipc_data_plane == False ) :
    I1IIi1I = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
    lisp . lisp_ipc_dp_socket = I1IIi1I
    if 57 - 57: iIii1I11I1II1 * OOooOOo - i11iIiiIii / I11i - iIii1I11I1II1 + ooOoO0o
   if ( OO000oOO0o == False and lisp . lisp_ipc_data_plane ) :
    lisp . lisp_ipc_dp_socket . close ( )
    lisp . lisp_ipc_dp_socket = None
    if 62 - 62: I11i % oO0o / OoooooooOO % OoooooooOO
   lisp . lisp_ipc_data_plane = OO000oOO0o
   if 65 - 65: O0 . I1ii11iIi11i * I1Ii111
  if ( IiII1II11I == "decentralized-push-xtr" ) :
   lisp . lisp_decent_push_configured = ( oo00oO0O0 == "yes" )
   if 39 - 39: iIii1I11I1II1 % O0 + Oo0Ooo
  if ( IiII1II11I == "decentralized-pull-xtr-modulus" ) :
   lisp . lisp_decent_modulus = int ( oo00oO0O0 )
   if 71 - 71: OoooooooOO + i1IIi + oO0o * Ii1I + i11iIiiIii - oO0o
  if ( IiII1II11I == "decentralized-pull-xtr-dns-suffix" ) :
   lisp . lisp_decent_dns_suffix = oo00oO0O0
   if 99 - 99: Oo0Ooo
  if ( IiII1II11I == "register-reachable-rtrs" ) :
   lisp . lisp_register_all_rtrs = ( oo00oO0O0 == "no" )
   if 17 - 17: i11iIiiIii - i11iIiiIii + I1ii11iIi11i * ooOoO0o * oO0o / OoooooooOO
   if 22 - 22: I1Ii111 * I1ii11iIi11i - IiII
 return
 if 71 - 71: iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * I1IiiI % II111iiii
 if 35 - 35: I1Ii111 - OoOoOO00
 if 61 - 61: I1Ii111 * o0oOOo0O0Ooo * OoO0O00 + I1ii11iIi11i . Oo0Ooo + i1IIi
 if 82 - 82: Oo0Ooo + I1Ii111
 if 93 - 93: I11i * O0 * OOooOOo - o0oOOo0O0Ooo / I1ii11iIi11i
 if 54 - 54: i1IIi - OoO0O00 / OoooooooOO
 if 95 - 95: O0 + iIii1I11I1II1 . I1ii11iIi11i
def lisp_show_json_list ( output ) :
 if 61 - 61: Ii1I * Ii1I
 oooo00Oo0O = "Configured JSON Entries:"
 output += lisp_table_header ( oooo00Oo0O , "JSON Name" , "JSON String" )
 if 70 - 70: I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
 OoI1 = sorted ( lisp . lisp_json_list )
 for OoO00o00 in OoI1 :
  oOO00O0Ooooo00 = lisp . lisp_json_list [ OoO00o00 ]
  ooOoo0oo00000O = lisp . lisp_print_cour ( oOO00O0Ooooo00 . print_json ( True ) )
  output += lisp_table_row ( OoO00o00 , ooOoo0oo00000O )
  if 84 - 84: iIii1I11I1II1
 output += lisp_table_footer ( )
 return ( output )
 if 25 - 25: OoO0O00 * IiII - i1IIi - I11i * II111iiii
 if 70 - 70: II111iiii + iII111i * OoOoOO00
 if 61 - 61: OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
 if 91 - 91: I1IiiI / II111iiii * OOooOOo
 if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
 if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
 if 81 - 81: OoO0O00 - iIii1I11I1II1
def lisp_show_rle_list ( output ) :
 if 60 - 60: I1Ii111
 oooo00Oo0O = "Configured Replication List Entries (RLEs):"
 output += lisp_table_header ( oooo00Oo0O , "RLE Name" , "RLE Nodes" )
 if 77 - 77: I1IiiI / I1ii11iIi11i
 o0OoOOoooooOO = sorted ( lisp . lisp_rle_list )
 for oOOo in o0OoOOoooooOO :
  o0OOO = lisp . lisp_rle_list [ oOOo ]
  output += lisp_table_row ( oOOo , o0OOO . print_rle ( True , True ) )
  if 97 - 97: OOooOOo
 output += lisp_table_footer ( )
 return ( output )
 if 41 - 41: OoooooooOO - Oo0Ooo * iIii1I11I1II1 . i1IIi
 if 39 - 39: Ii1I % i1IIi . I1ii11iIi11i - O0
 if 65 - 65: oO0o * oO0o / I11i + oO0o % ooOoO0o + OoOoOO00
 if 92 - 92: o0oOOo0O0Ooo
 if 37 - 37: oO0o
 if 18 - 18: IiII * i11iIiiIii + iIii1I11I1II1 % I11i + i1IIi - OoO0O00
 if 85 - 85: OoO0O00 * I11i + OoO0O00
def lisp_show_elp_list ( output ) :
 oooo00Oo0O = "Configured Explicit Locator Paths (ELPs):"
 output += lisp_table_header ( oooo00Oo0O , "ELP Name" , "ELP Nodes" )
 if 39 - 39: Oo0Ooo / i1IIi % i1IIi
 iII1I1IIiiiI = sorted ( lisp . lisp_elp_list )
 for IIiiIiIIiI1 in iII1I1IIiiiI :
  O0oO0 = lisp . lisp_elp_list [ IIiiIiIIiI1 ]
  output += lisp_table_row ( IIiiIiIIiI1 , O0oO0 . print_elp ( False ) )
  if 39 - 39: I11i / OoooooooOO - Ii1I + OoO0O00 / OoOoOO00
 output += lisp_table_footer ( )
 return ( output )
 if 87 - 87: I1Ii111
 if 32 - 32: I11i - OOooOOo * O0 % IiII . IiII . I1IiiI
 if 91 - 91: i1IIi . iII111i
 if 37 - 37: iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoO0O00 . o0oOOo0O0Ooo
 if 62 - 62: I1ii11iIi11i
 if 47 - 47: I1Ii111 % OOooOOo * OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
 if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
def lisp_geo_command ( kv_pair ) :
 if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
 if 95 - 95: oO0o
 if 80 - 80: IiII
 if 42 - 42: OoooooooOO * II111iiii
 if ( "geo-name" not in kv_pair ) : return
 O0oooOO = kv_pair [ "geo-name" ]
 IIiIi1I1iI1 = lisp . lisp_geo ( O0oooOO )
 if 39 - 39: OOooOOo
 if 70 - 70: IiII % OoO0O00 % I1IiiI
 if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
 if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
 if ( "geo-tag" not in kv_pair ) : return
 if 2 - 2: oO0o * oO0o . OoOoOO00 * Ii1I * iIii1I11I1II1
 if 13 - 13: I11i / O0 . i11iIiiIii * i1IIi % i11iIiiIii
 if 8 - 8: OoOoOO00 - OoooooooOO
 if 99 - 99: II111iiii / IiII % OoooooooOO . i11iIiiIii
 iI1 = kv_pair [ "geo-tag" ] [ 1 : : ]
 if ( IIiIi1I1iI1 . parse_geo_string ( iI1 ) == False ) : return
 if 70 - 70: OoooooooOO . ooOoO0o / oO0o . oO0o - o0oOOo0O0Ooo
 if 29 - 29: I11i % OOooOOo - ooOoO0o
 if 26 - 26: O0 . I11i + iII111i - Ii1I . I11i
 if 2 - 2: I1ii11iIi11i . Oo0Ooo * OOooOOo % II111iiii . iII111i
 lisp . lisp_geo_list [ O0oooOO ] = IIiIi1I1iI1
 return
 if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
 if 47 - 47: iII111i * OoOoOO00 * IiII
 if 46 - 46: Ii1I
 if 42 - 42: iIii1I11I1II1
 if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
 if 34 - 34: Oo0Ooo
 if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
def lisp_elp_command ( kv_pair ) :
 if 33 - 33: i1IIi / iII111i * OoO0O00
 O0oO0 = None
 iI1ii1 = [ ]
 if ( "address" in kv_pair ) :
  for i1iIIiiIiII in range ( len ( kv_pair [ "address" ] ) ) :
   O0oOOo = lisp . lisp_elp_node ( )
   iI1ii1 . append ( O0oOOo )
   if 33 - 33: I1IiiI * I1Ii111
   if 98 - 98: I1ii11iIi11i - OoooooooOO / I1IiiI . ooOoO0o - i1IIi
   if 60 - 60: OoOoOO00 % OoOoOO00
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if 2 - 2: Ii1I . O0 - oO0o + IiII
  if ( IiII1II11I == "elp-name" ) :
   O0oO0 = lisp . lisp_elp ( oo00oO0O0 )
   continue
   if 96 - 96: Ii1I + Ii1I
   if 28 - 28: iII111i
  for ii1Iiii1I in iI1ii1 :
   Oo0oO00o = iI1ii1 . index ( ii1Iiii1I )
   if ( Oo0oO00o >= len ( oo00oO0O0 ) ) : Oo0oO00o = len ( oo00oO0O0 ) - 1
   oOOo0oO = oo00oO0O0 [ Oo0oO00o ]
   if ( IiII1II11I == "probe" ) : ii1Iiii1I . probe = ( oOOo0oO == "yes" )
   if ( IiII1II11I == "strict" ) : ii1Iiii1I . strict = ( oOOo0oO == "yes" )
   if ( IiII1II11I == "eid" ) : ii1Iiii1I . eid = ( oOOo0oO == "yes" )
   if ( IiII1II11I == "address" ) : ii1Iiii1I . address . store_address ( oOOo0oO )
   if 54 - 54: ooOoO0o - iIii1I11I1II1 - I11i % Ii1I / II111iiii
   if 80 - 80: i11iIiiIii % iIii1I11I1II1 / i11iIiiIii
   if 66 - 66: OoOoOO00 . iIii1I11I1II1 * I1ii11iIi11i - Ii1I - iIii1I11I1II1
   if 28 - 28: OoOoOO00 % OoooooooOO
   if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
   if 84 - 84: II111iiii
 if ( O0oO0 == None ) : return
 if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
 if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
 if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
 if 85 - 85: i1IIi . i1IIi
 O0oO0 . elp_nodes = iI1ii1
 lisp . lisp_elp_list [ O0oO0 . elp_name ] = O0oO0
 return
 if 16 - 16: I1IiiI - OOooOOo % Ii1I . OOooOOo + I1ii11iIi11i % i11iIiiIii
 if 59 - 59: i11iIiiIii - I11i
 if 59 - 59: OoooooooOO * o0oOOo0O0Ooo / I1Ii111
 if 75 - 75: o0oOOo0O0Ooo - OoooooooOO
 if 21 - 21: I1IiiI + iIii1I11I1II1 / i11iIiiIii / oO0o
 if 66 - 66: OoooooooOO + iII111i . IiII % i1IIi
 if 58 - 58: OOooOOo % iII111i * O0 + I1ii11iIi11i - IiII
def lisp_rle_command ( kv_pair ) :
 if 26 - 26: i1IIi / I1IiiI / I11i + I11i
 o0OOO = None
 i1II111iiii = [ ]
 if ( "address" in kv_pair ) :
  for i1iIIiiIiII in range ( len ( kv_pair [ "address" ] ) ) :
   iiI11 = lisp . lisp_rle_node ( )
   i1II111iiii . append ( iiI11 )
   if 10 - 10: ooOoO0o - Oo0Ooo % II111iiii
   if 66 - 66: iIii1I11I1II1 . iIii1I11I1II1
   if 46 - 46: I1Ii111 * oO0o . Ii1I * I1Ii111 * iIii1I11I1II1 / I11i
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if 46 - 46: II111iiii % I1ii11iIi11i . OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
  if ( IiII1II11I == "rle-name" ) :
   o0OOO = lisp . lisp_rle ( oo00oO0O0 )
   continue
   if 47 - 47: IiII . OOooOOo
   if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
  for ii1Iiii1I in i1II111iiii :
   Oo0oO00o = i1II111iiii . index ( ii1Iiii1I )
   if ( Oo0oO00o >= len ( oo00oO0O0 ) ) : Oo0oO00o = len ( oo00oO0O0 ) - 1
   oOOo0oO = oo00oO0O0 [ Oo0oO00o ]
   if ( IiII1II11I == "level" ) :
    if ( oOOo0oO == "" ) : oOOo0oO = "0"
    ii1Iiii1I . level = int ( oOOo0oO )
    if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
   if ( IiII1II11I == "address" ) : ii1Iiii1I . address . store_address ( oOOo0oO )
   if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
   if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
   if 89 - 89: ooOoO0o * I1IiiI . oO0o
   if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
   if 26 - 26: I11i * Ii1I % I1IiiI + iII111i
   if 38 - 38: iII111i - Oo0Ooo / Ii1I + oO0o . iII111i + IiII
 if ( o0OOO == None ) : return
 if 19 - 19: Ii1I
 if 51 - 51: iIii1I11I1II1
 if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
 if 8 - 8: OoO0O00 * Oo0Ooo
 o0OOO . rle_nodes = i1II111iiii
 o0OOO . build_forwarding_list ( )
 lisp . lisp_rle_list [ o0OOO . rle_name ] = o0OOO
 return
 if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
 if 4 - 4: I11i . IiII
 if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
 if 4 - 4: OoOoOO00 * O0 - I11i
 if 72 - 72: I11i + ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
 if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
 if 70 - 70: II111iiii * II111iiii . I1IiiI
def lisp_json_command ( kv_pair ) :
 if 11 - 11: iII111i
 try :
  OoO00o00 = kv_pair [ "json-name" ]
  ooOoo0oo00000O = kv_pair [ "json-string" ]
 except :
  return
  if 20 - 20: Ii1I . I1Ii111 % Ii1I
  if 5 - 5: OOooOOo + iII111i
 oOO00O0Ooooo00 = lisp . lisp_json ( OoO00o00 , ooOoo0oo00000O )
 oOO00O0Ooooo00 . add ( )
 return
 if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
 if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
 if 11 - 11: I1ii11iIi11i / O0 + II111iiii
 if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
 if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
 if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
 if 2 - 2: Ii1I
 if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
 if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
 if 81 - 81: iIii1I11I1II1
 if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
 if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
def lisp_get_lookup_string ( input_str ) :
 if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
 if 7 - 7: IiII
 if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
 if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
 o0O = input_str
 IiIIii1iII1II = None
 if ( input_str . find ( "->" ) != - 1 ) :
  Iii1I1I11iiI1 = input_str . split ( "->" )
  o0O = Iii1I1I11iiI1 [ 0 ]
  IiIIii1iII1II = Iii1I1I11iiI1 [ 1 ]
  if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
  if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
 Oo0OOo = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 I1i1i1IIi1I = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if 18 - 18: oO0o * Ii1I / OoooooooOO % OoOoOO00 - i1IIi
 if 49 - 49: o0oOOo0O0Ooo - iIii1I11I1II1
 if 61 - 61: iII111i * ooOoO0o
 if 1 - 1: I1Ii111 * OoOoOO00
 OOooO = o0O . split ( "/" )
 if ( len ( OOooO ) == 1 ) :
  Oo0OOo . store_address ( OOooO [ 0 ] )
  OOooO0o = False
 else :
  Oo0OOo . store_prefix ( o0O )
  OOooO0o = True
  if 85 - 85: II111iiii - Ii1I
  if 93 - 93: IiII / i11iIiiIii - oO0o + OoO0O00 / i1IIi
 OO0oO = OOooO0o
 if ( IiIIii1iII1II ) :
  OOooO = IiIIii1iII1II . split ( "/" )
  if ( len ( OOooO ) == 1 ) :
   I1i1i1IIi1I . store_address ( OOooO [ 0 ] )
   OO0oO = False
  else :
   I1i1i1IIi1I . store_prefix ( o0O )
   OO0oO = True
   if 32 - 32: iII111i % i1IIi
   if 62 - 62: I11i . II111iiii * O0 + i1IIi * OoooooooOO + OoooooooOO
 return ( [ Oo0OOo , OOooO0o , I1i1i1IIi1I , OO0oO ] )
 if 23 - 23: i1IIi
 if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
 if 74 - 74: Oo0Ooo - II111iiii - IiII
 if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
 if 70 - 70: i1IIi % OoO0O00 / i1IIi
 if 30 - 30: OoOoOO00 - i11iIiiIii
 if 94 - 94: OoOoOO00 % iII111i
def lisp_show_map_cache_lookup ( eid_str ) :
 Oo0OOo , OOooO0o , I1i1i1IIi1I , OO0oO = lisp_get_lookup_string ( eid_str )
 if 39 - 39: OoOoOO00 + I1Ii111 % O0
 o0o0oOOOo0oo = "<br>"
 if 26 - 26: ooOoO0o + OoOoOO00
 II111I1i1 = Oo0OOo if ( I1i1i1IIi1I . is_null ( ) ) else I1i1i1IIi1I
 Iio0o0o = OOooO0o if ( I1i1i1IIi1I . is_null ( ) ) else OO0oO
 if 32 - 32: O0 / OOooOOo . ooOoO0o % I1Ii111
 OOo0o = lisp . lisp_map_cache . lookup_cache ( II111I1i1 , Iio0o0o )
 if ( OOo0o == None ) :
  o0o0oOOOo0oo += "{} {}" . format ( lisp . lisp_print_sans ( "Lookup not found for" ) ,
 lisp . lisp_print_cour ( eid_str ) )
 else :
  if ( II111I1i1 == I1i1i1IIi1I ) :
   I1i1i1ii1iiI1 = OOo0o . lookup_source_cache ( Oo0OOo , OOooO0o )
   if ( I1i1i1ii1iiI1 ) : OOo0o = I1i1i1ii1iiI1
   if 73 - 73: I1Ii111
   if 25 - 25: IiII
  O0O0O = lisp . lisp_print_elapsed ( OOo0o . uptime )
  o0o0oOOOo0oo += "{} {} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Exact" if OOooO0o else "Longest" ) ,
  # i11iIiiIii - O0 - i11iIiiIii . iIii1I11I1II1 . IiII
 lisp . lisp_print_sans ( "match lookup for" ) ,
 lisp . lisp_print_cour ( eid_str ) ,
 lisp . lisp_print_sans ( "found" ) ,
 lisp . lisp_print_cour ( OOo0o . print_eid_tuple ( ) ) ,
 lisp . lisp_print_sans ( "with uptime" ) ,
 lisp . lisp_print_cour ( O0O0O ) )
  if 84 - 84: i1IIi / iIii1I11I1II1 / oO0o / Ii1I
 o0o0oOOOo0oo += "<br>"
 return ( o0o0oOOOo0oo )
 if 7 - 7: OoOoOO00 . OOooOOo % Oo0Ooo
 if 55 - 55: ooOoO0o - Oo0Ooo * oO0o
 if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
 if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
 if 64 - 64: IiII
 if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
 if 89 - 89: O0 + IiII * I1Ii111
 if 30 - 30: OoOoOO00
def lisp_get_clause_for_api ( command ) :
 iiIiiIi = open ( "./lisp.config" , "r" )
 iIi11I11 = { command : [ ] }
 IIIII11 = { }
 i1i1 = [ ]
 if 15 - 15: i11iIiiIii / o0oOOo0O0Ooo / OoO0O00 . OoOoOO00 % oO0o
 IIIIiiI = 0
 ooOo0o = False
 for OOo00OoO in iiIiiIi :
  if ( lisp_end_file ( OOo00OoO ) ) : break
  if ( lisp_comment ( OOo00OoO ) ) : continue
  if 29 - 29: o0oOOo0O0Ooo
  if 13 - 13: Ii1I + Ii1I . I11i
  if 57 - 57: ooOoO0o
  if 94 - 94: OoO0O00 - II111iiii % iIii1I11I1II1
  if 92 - 92: Oo0Ooo
  if 40 - 40: I1IiiI
  if ( OOo00OoO . find ( command + " {" ) != - 1 ) :
   IIIIiiI += 1
   ooOo0o = True
   continue
   if 96 - 96: OoO0O00 - iII111i
  if ( ooOo0o == False ) : continue
  if 16 - 16: I1Ii111 / O0 . II111iiii * OoOoOO00
  if ( lisp_begin_clause ( OOo00OoO ) ) :
   IIIIiiI += 1
   i1IiI1I111iI1 = OOo00OoO . replace ( " " , "" )
   i1IiI1I111iI1 = i1IiI1I111iI1 . replace ( "\t" , "" )
   i1IiI1I111iI1 = i1IiI1I111iI1 . replace ( "\n" , "" )
   i1IiI1I111iI1 = i1IiI1I111iI1 . replace ( "{" , "" )
   IIIII11 = { i1IiI1I111iI1 : { } }
   continue
   if 82 - 82: o0oOOo0O0Ooo - OOooOOo
   if 84 - 84: iII111i % i1IIi % OoO0O00 % II111iiii
   if 94 - 94: ooOoO0o * O0
   if 60 - 60: iII111i / iII111i - ooOoO0o / OoooooooOO + O0
   if 55 - 55: OoO0O00 % O0 / OoooooooOO
   if 49 - 49: I1IiiI . OoO0O00 * OoooooooOO % i11iIiiIii + iIii1I11I1II1 * i1IIi
  if ( lisp_end_clause ( OOo00OoO ) ) :
   IIIIiiI -= 1
   if ( IIIIiiI ) :
    iIi11I11 [ command ] . append ( IIIII11 )
    IIIII11 = { }
    continue
    if 88 - 88: I1ii11iIi11i * iII111i + II111iiii
   i1i1 . append ( iIi11I11 )
   iIi11I11 = { command : [ ] }
   ooOo0o = False
   continue
   if 62 - 62: OoooooooOO
   if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
  OOo00OoO = OOo00OoO . replace ( " " , "" )
  OOo00OoO = OOo00OoO . replace ( "\t" , "" )
  OOo00OoO = OOo00OoO . replace ( "\n" , "" )
  OOo00OoO = OOo00OoO . replace ( "{" , "" )
  OOo00OoO = OOo00OoO . split ( "=" )
  oo00oO0O0 = "" if len ( OOo00OoO ) == 1 else OOo00OoO [ 1 ]
  o0 = OOo00OoO [ 0 ]
  if 50 - 50: ooOoO0o
  if ( len ( IIIII11 ) == 0 ) :
   iIi11I11 [ command ] . append ( { o0 : oo00oO0O0 } )
  else :
   IIIII11 [ i1IiI1I111iI1 ] [ o0 ] = oo00oO0O0
   if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
   if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
   if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
 iiIiiIi . close ( )
 if 29 - 29: oO0o
 if ( len ( i1i1 ) == 0 ) :
  i1i1 = [ { "?" : [ { "?" : "not-found" } ] } ]
  if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
 return ( i1i1 )
 if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
 if 33 - 33: OoooooooOO . O0
 if 59 - 59: iIii1I11I1II1
 if 45 - 45: O0
 if 78 - 78: I11i - iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - I1Ii111
 if 21 - 21: OoooooooOO . O0 / i11iIiiIii
 if 86 - 86: OoOoOO00 / OOooOOo
def lisp_duplicate_command_clause ( command , clause ) :
 OoOOo = open ( "./lisp.config" , "r" )
 if 40 - 40: iIii1I11I1II1 / ooOoO0o / I1IiiI + I1ii11iIi11i * OOooOOo
 clause = command + " {\n" + clause
 for OOo00OoO in OoOOo :
  if ( lisp_begin_clause ( OOo00OoO ) == False ) : continue
  if ( OOo00OoO . find ( command ) == - 1 ) : continue
  if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
  O0O00Oo = OOo00OoO
  for OOo00OoO in OoOOo :
   O0O00Oo += OOo00OoO
   if ( OOo00OoO [ 0 ] != "}" ) : continue
   if ( O0O00Oo != clause ) : break
   OoOOo . close ( )
   return ( True )
   if 49 - 49: i1IIi - OOooOOo / o0oOOo0O0Ooo % IiII - ooOoO0o
  if ( lisp_end_file ( OOo00OoO ) ) : break
  if 62 - 62: I1Ii111 + OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 76 - 76: I1IiiI
 OoOOo . close ( )
 return ( False )
 if 41 - 41: OoOoOO00 % I1Ii111 * oO0o * i1IIi
 if 32 - 32: I1IiiI + i11iIiiIii - I1Ii111 / II111iiii
 if 27 - 27: ooOoO0o . Oo0Ooo + ooOoO0o + iII111i
 if 28 - 28: OoO0O00 - ooOoO0o - oO0o % oO0o / O0
 if 99 - 99: II111iiii - iIii1I11I1II1
 if 24 - 24: I1IiiI - i1IIi - O0 % I1Ii111 - iIii1I11I1II1 . I11i
 if 26 - 26: OoO0O00 % i1IIi * O0 . I1Ii111
def lisp_put_clause_for_api ( data ) :
 if 31 - 31: O0 - IiII * i11iIiiIii * i1IIi
 if 78 - 78: ooOoO0o * OoOoOO00 . Ii1I . OoOoOO00 % iIii1I11I1II1
 if 67 - 67: Ii1I . Oo0Ooo
 if 39 - 39: I11i * I1Ii111
 OO0OO00oo0 = list ( data . keys ( ) ) [ 0 ]
 if ( OO0OO00oo0 not in list ( lisp_commands . keys ( ) ) ) :
  return ( [ { OO0OO00oo0 : [ { "?" : "add/replace" } ] } ] )
  if 63 - 63: ooOoO0o % I1IiiI . OOooOOo - ooOoO0o / Oo0Ooo % I1IiiI
  if 39 - 39: o0oOOo0O0Ooo . i1IIi % oO0o / I11i % O0
 o0O0OOooO = ( OO0OO00oo0 in [ "lisp enable" , "lisp debug" , "lisp xtr-parameters" ] )
 if 1 - 1: I1Ii111 * OoO0O00 - iII111i
 if 97 - 97: iII111i . I1ii11iIi11i - iIii1I11I1II1 . ooOoO0o + I1IiiI % oO0o
 if 4 - 4: I1IiiI / II111iiii % O0 * ooOoO0o / II111iiii . Oo0Ooo
 if 16 - 16: O0 + O0 - I1IiiI
 if 30 - 30: ooOoO0o
 if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
 if 19 - 19: i1IIi % II111iiii
 O00OO0oO = False
 if ( o0O0OOooO == False ) :
  O00OO0oO = True
  Ii1IIiii1Ii = getoutput ( "egrep '{}' ./lisp.config" . format ( OO0OO00oo0 ) )
  Ii1IIiii1Ii = Ii1IIiii1Ii . split ( "\n" )
  for OOo00OoO in Ii1IIiii1Ii :
   if ( OOo00OoO [ 0 : len ( OO0OO00oo0 ) ] == OO0OO00oo0 ) : O00OO0oO = False
   if 48 - 48: o0oOOo0O0Ooo + I1ii11iIi11i / I1ii11iIi11i
   if 80 - 80: OoooooooOO
   if 65 - 65: oO0o * i1IIi . OoooooooOO % ooOoO0o
   if 87 - 87: i11iIiiIii * II111iiii - Ii1I % OoooooooOO
   if 55 - 55: i1IIi
   if 67 - 67: I1IiiI - OoO0O00
 Oo0oO = data [ OO0OO00oo0 ]
 Oo0oO = lisp_unicode_to_ascii ( Oo0oO )
 iIi11I11 = OO0OO00oo0 + " {\n" if O00OO0oO else ""
 if 65 - 65: OoO0O00 * II111iiii / iIii1I11I1II1
 if 19 - 19: OOooOOo . i11iIiiIii . I11i * I11i
 if 69 - 69: i1IIi
 if 96 - 96: I11i - i11iIiiIii % i1IIi . iIii1I11I1II1
 if 73 - 73: I1IiiI * OOooOOo + OoO0O00 % oO0o / i1IIi
 if 36 - 36: OOooOOo * I1Ii111 + II111iiii + OoooooooOO + iII111i % I11i
 if 53 - 53: II111iiii . II111iiii
 if 18 - 18: Ii1I + OoOoOO00 . i1IIi / IiII / iII111i
 for oOo0OO0 in Oo0oO :
  if ( type ( Oo0oO ) == dict ) :
   oo00oO0O0 = Oo0oO [ oOo0OO0 ]
   if ( type ( oo00oO0O0 ) == dict ) : oo00oO0O0 = json_dumps ( oo00oO0O0 )
   iIi11I11 += "    " + oOo0OO0 + " = " + oo00oO0O0 + "\n"
   continue
   if 56 - 56: II111iiii . II111iiii + IiII . o0oOOo0O0Ooo
   if 32 - 32: ooOoO0o . IiII . II111iiii
  for o0 in oOo0OO0 :
   if ( type ( oOo0OO0 ) == dict ) :
    I1I11I1i1i1II = o0
    oo00oO0O0 = oOo0OO0 [ o0 ]
    if 1 - 1: I1IiiI . Ii1I
   if ( type ( oOo0OO0 ) == list ) :
    I1I11I1i1i1II = list ( o0 . keys ( ) ) [ 0 ]
    oo00oO0O0 = list ( o0 . values ( ) ) [ 0 ]
    if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
    if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
   if ( type ( oo00oO0O0 ) != dict ) :
    iIi11I11 += "    " + o0 + " = " + oOo0OO0 [ o0 ] + "\n"
    continue
    if 21 - 21: O0 * ooOoO0o % OoO0O00
    if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
    if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
    if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
    if 76 - 76: I11i . I1ii11iIi11i * OoooooooOO % iII111i
   iIi11I11 += "    " + I1I11I1i1i1II + " {\n"
   for i1ii in oo00oO0O0 : iIi11I11 += "        " + i1ii + " = " + oo00oO0O0 [ i1ii ] + "\n"
   iIi11I11 += "    }\n"
   if 7 - 7: i11iIiiIii - I11i % Oo0Ooo
   if 76 - 76: OoO0O00 * iII111i % Oo0Ooo . i11iIiiIii / OoooooooOO
 iIi11I11 += "}\n"
 if 85 - 85: OoooooooOO . OoO0O00 . OoO0O00
 if 70 - 70: I11i
 if 72 - 72: I1Ii111 - ooOoO0o - I1IiiI - iII111i + OOooOOo - i1IIi
 if 45 - 45: OoO0O00 * I1IiiI
 if ( lisp_duplicate_command_clause ( OO0OO00oo0 , iIi11I11 ) ) :
  return ( [ { OO0OO00oo0 : [ { "!" : "duplicate" } ] } ] )
  if 61 - 61: iII111i % II111iiii / OoOoOO00 % I1ii11iIi11i . iIii1I11I1II1 % O0
  if 74 - 74: I1ii11iIi11i * oO0o + iII111i % O0
 Iii1IiIiIii = "./lisp.config"
 OOo0ooOOOo0O0 = Iii1IiIiIii + ".temp"
 if 100 - 100: i11iIiiIii . OOooOOo . i11iIiiIii
 o00Oo = open ( Iii1IiIiIii , "r" )
 I1I = open ( OOo0ooOOOo0O0 , "w" )
 if 38 - 38: oO0o % ooOoO0o % OOooOOo / o0oOOo0O0Ooo % II111iiii
 ii1IiI1i = False
 ooOoOoOoo = False
 for OOo00OoO in o00Oo :
  if ( ooOoOoOoo ) :
   if ( lisp_end_clause ( OOo00OoO ) == False ) : continue
   ooOoOoOoo = False
   continue
   if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
   if 57 - 57: II111iiii . i1IIi
   if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
   if 6 - 6: IiII + I1ii11iIi11i
   if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
  if ( ii1IiI1i == False and lisp_begin_clause ( OOo00OoO ) and
 OOo00OoO [ 0 : len ( OO0OO00oo0 ) ] == OO0OO00oo0 ) :
   if ( o0O0OOooO == False ) :
    I1I . write ( OOo00OoO )
    for iiIIiIi1i1I1 in iIi11I11 : I1I . write ( iiIIiIi1i1I1 )
    ii1IiI1i = True
    if 52 - 52: o0oOOo0O0Ooo % II111iiii . OoooooooOO
    if 7 - 7: II111iiii - I1ii11iIi11i / I11i % OoooooooOO + i1IIi
    if 42 - 42: I11i + i1IIi - Ii1I / IiII . iII111i
    if 30 - 30: Oo0Ooo + Ii1I % i11iIiiIii * i1IIi + I1IiiI % OOooOOo
    if 30 - 30: i11iIiiIii * Oo0Ooo . II111iiii + I1ii11iIi11i / o0oOOo0O0Ooo % I1Ii111
    if 78 - 78: I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
  if ( lisp_end_file ( OOo00OoO ) ) :
   if ( O00OO0oO ) :
    for iiIIiIi1i1I1 in iIi11I11 : I1I . write ( iiIIiIi1i1I1 )
    if 7 - 7: OOooOOo . IiII . I1Ii111 / Ii1I / Oo0Ooo
   I1I . write ( OOo00OoO )
   ii1IiI1i = True
   break
   if 83 - 83: I11i / Oo0Ooo
   if 23 - 23: iIii1I11I1II1
   if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
   if 64 - 64: OoO0O00 / I1IiiI
   if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
  I1I . write ( OOo00OoO )
  if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
  if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
  if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
  if 8 - 8: o0oOOo0O0Ooo
  if 78 - 78: i1IIi - Oo0Ooo
  if ( lisp_begin_clause ( OOo00OoO ) and OOo00OoO [ 0 : len ( OO0OO00oo0 ) ] == OO0OO00oo0 ) :
   if ( o0O0OOooO ) :
    ooOoOoOoo = True
    for iiIIiIi1i1I1 in iIi11I11 : I1I . write ( iiIIiIi1i1I1 )
    if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
    if 42 - 42: I1Ii111
    if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
    if 80 - 80: OOooOOo
 o00Oo . close ( )
 I1I . close ( )
 if 12 - 12: Ii1I
 os . system ( "cp {} {}" . format ( OOo0ooOOOo0O0 , Iii1IiIiIii ) )
 os . system ( "rm {}" . format ( OOo0ooOOOo0O0 ) )
 return ( [ { OO0OO00oo0 : [ { "!" : "add/replace" } ] } ] )
 if 2 - 2: OoooooooOO
 if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
 if 46 - 46: O0 % OoooooooOO
 if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
 if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
 if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
 if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
 if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
def lisp_remove_clause_for_api ( data ) :
 if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
 if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
 if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
 if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
 OO0OO00oo0 = list ( data . keys ( ) ) [ 0 ]
 if ( OO0OO00oo0 not in list ( lisp_commands . keys ( ) ) ) :
  return ( [ { OO0OO00oo0 : [ { "?" : "delete" } ] } ] )
  if 65 - 65: I1ii11iIi11i / ooOoO0o
  if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
  if 57 - 57: iII111i
  if 29 - 29: I1IiiI
  if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
 Oo0oO = data [ OO0OO00oo0 ]
 Oo0oO = lisp_unicode_to_ascii ( Oo0oO )
 if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
 if 22 - 22: O0 % IiII % iII111i % I1IiiI
 if 34 - 34: iII111i . Oo0Ooo % I1ii11iIi11i . iII111i % IiII / IiII
 if 84 - 84: Ii1I
 II1I1i1I = [ ]
 o0 = list ( Oo0oO . keys ( ) ) [ 0 ]
 oo00oO0O0 = Oo0oO [ o0 ]
 if 21 - 21: OoooooooOO
 if ( type ( oo00oO0O0 ) == dict ) :
  for o0 in list ( oo00oO0O0 . keys ( ) ) :
   Oo0OoOoOo0o = oo00oO0O0 [ o0 ]
   II1I1i1I . append ( o0 + " = " + Oo0OoOoOo0o )
   if 41 - 41: OoooooooOO - I1ii11iIi11i
 else :
  II1I1i1I . append ( o0 + " = " + oo00oO0O0 )
  if 45 - 45: I11i . II111iiii / i11iIiiIii
  if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
  if 41 - 41: I1ii11iIi11i % I1ii11iIi11i + IiII . iII111i % I1Ii111 * ooOoO0o
  if 57 - 57: Ii1I . I1Ii111 . II111iiii % OoooooooOO * O0 + iIii1I11I1II1
  if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
  if 93 - 93: ooOoO0o / OOooOOo * O0
 if ( OO0OO00oo0 == "lisp user-account" ) :
  iIi11I11 = getoutput ( "egrep -A4 '{}' ./lisp.config" . format ( II1I1i1I [ 0 ] ) )
  if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
  if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
  if ( iIi11I11 . find ( "super-user = yes" ) != - 1 ) :
   return ( [ { "lisp user-account" : [ { "?" : "found-superuser" } ] } ] )
   if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
   if 6 - 6: iII111i % o0oOOo0O0Ooo + I1Ii111
   if 91 - 91: o0oOOo0O0Ooo + O0 * oO0o * IiII * I1ii11iIi11i
   if 83 - 83: OoooooooOO
   if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
   if 88 - 88: OOooOOo / i11iIiiIii / Ii1I / i11iIiiIii * I1ii11iIi11i % I11i
   if 43 - 43: OoOoOO00 * OoO0O00 % i1IIi * Ii1I + iIii1I11I1II1
 oOIIii = ( "lisp user-account" , "lisp site" , "lisp map-server" ,
 "lisp policy" )
 if 100 - 100: i11iIiiIii - ooOoO0o + OOooOOo * OoooooooOO + O0
 Iii1IiIiIii = "./lisp.config"
 o00Oo = open ( Iii1IiIiIii , "r" )
 if 66 - 66: I1ii11iIi11i . Oo0Ooo / I1ii11iIi11i + I1ii11iIi11i . II111iiii % OoO0O00
 o0Oo = False
 ooo0oooO = 0
 for OOo00OoO in o00Oo :
  if ( OOo00OoO . find ( OO0OO00oo0 ) == - 1 ) : continue
  ooo0oooO += 1
  if 73 - 73: ooOoO0o - OOooOOo - II111iiii - iIii1I11I1II1
  for OOo00OoO in o00Oo :
   if ( lisp_begin_clause ( OOo00OoO ) ) : continue
   oOOOoOOO00 = ( lisp_end_clause ( OOo00OoO ) and o0Oo )
   if ( oOOOoOOO00 ) : break
   if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
   IiIi11iI1 = OOo00OoO . replace ( " " , "" )
   IiIi11iI1 = IiIi11iI1 . replace ( "\n" , "" )
   IiIi11iI1 = IiIi11iI1 . replace ( "=" , " = " )
   if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
   if ( IiIi11iI1 not in II1I1i1I ) :
    o0Oo = False
    if ( len ( II1I1i1I ) > 1 ) : break
    continue
    if 84 - 84: OoOoOO00 - I11i
   o0Oo = True
   if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
   oOOOoOOO00 = ( OO0OO00oo0 in oOIIii )
   if ( oOOOoOOO00 ) : break
   if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
   if 68 - 68: OoooooooOO * I11i
  if ( oOOOoOOO00 ) : break
  if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
  if 40 - 40: iII111i
 o00Oo . close ( )
 if 62 - 62: ooOoO0o / OOooOOo
 if ( not o0Oo ) :
  return ( [ { OO0OO00oo0 : [ { "?" : "not-found" } ] } ] )
  if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
  if 92 - 92: I11i % I1Ii111
 o00Oo = open ( Iii1IiIiIii , "r" )
 if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
 OOo0ooOOOo0O0 = Iii1IiIiIii + ".temp"
 I1I = open ( OOo0ooOOOo0O0 , "w" )
 if 94 - 94: I11i
 if 37 - 37: oO0o
 if 52 - 52: I1ii11iIi11i * I1IiiI . OOooOOo + i1IIi % oO0o / iIii1I11I1II1
 if 68 - 68: I1Ii111 - OoOoOO00 . i11iIiiIii + o0oOOo0O0Ooo
 if 71 - 71: i11iIiiIii / i1IIi * I1IiiI / OoOoOO00
 o0Oo = False
 for OOo00OoO in o00Oo :
  if ( OOo00OoO . find ( OO0OO00oo0 ) != - 1 ) : ooo0oooO -= 1
  if ( ooo0oooO == 0 and not o0Oo ) :
   if ( OOo00OoO [ 0 ] == "}" ) : o0Oo = True
   continue
   if 33 - 33: I11i . Oo0Ooo
  I1I . write ( OOo00OoO )
  if 89 - 89: iII111i + i1IIi - IiII + ooOoO0o . II111iiii
  if 85 - 85: iIii1I11I1II1 - Ii1I * Oo0Ooo . oO0o + I1Ii111
 I1I . close ( )
 o00Oo . close ( )
 if 13 - 13: O0 + iIii1I11I1II1 % II111iiii + iIii1I11I1II1
 os . system ( "cp {} {}" . format ( OOo0ooOOOo0O0 , Iii1IiIiIii ) )
 os . system ( "rm {}" . format ( OOo0ooOOOo0O0 ) )
 return ( [ { OO0OO00oo0 : [ { "!" : "delete" } ] } ] )
 if 85 - 85: I1IiiI * iIii1I11I1II1 . iII111i / iII111i
 if 43 - 43: I1IiiI
 if 78 - 78: OoO0O00 % II111iiii + OoOoOO00 / I1IiiI
 if 34 - 34: o0oOOo0O0Ooo % I1ii11iIi11i + Ii1I * I11i / oO0o
 if 18 - 18: ooOoO0o
 if 92 - 92: OoO0O00 % iIii1I11I1II1 / IiII * iII111i . i1IIi + oO0o
 if 24 - 24: IiII . iII111i * IiII % i11iIiiIii . i11iIiiIii + i1IIi
 if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
 if 100 - 100: IiII + i1IIi * OoO0O00
def lisp_u2a_walk_dict_array ( adata , a_dict ) :
 for o0 in a_dict :
  if ( type ( a_dict [ o0 ] ) == dict ) :
   oOooOO0oOo0O0 = { }
   oo00oO0O0 = a_dict [ o0 ]
   for i1ii in oo00oO0O0 : oOooOO0oOo0O0 [ i1ii . encode ( ) ] = oo00oO0O0 [ i1ii ] . encode ( )
   adata [ o0 . encode ( ) ] = oOooOO0oOo0O0
  else :
   adata [ o0 . encode ( ) ] = a_dict [ o0 ] . encode ( )
   if 18 - 18: I11i % O0 / iIii1I11I1II1 / iII111i
   if 1 - 1: Oo0Ooo . i11iIiiIii
 return
 if 9 - 9: OoooooooOO / I11i
 if 47 - 47: OoooooooOO
 if 48 - 48: OoOoOO00 . IiII % I1IiiI + I11i
 if 37 - 37: Oo0Ooo + I1Ii111 * oO0o / o0oOOo0O0Ooo
 if 78 - 78: IiII + I11i - o0oOOo0O0Ooo + OoO0O00 / iIii1I11I1II1
 if 47 - 47: OOooOOo
 if 20 - 20: I1Ii111 % ooOoO0o - I1Ii111 * OoooooooOO / I1ii11iIi11i
def lisp_unicode_to_ascii ( udata ) :
 O0000OOOoO = ( type ( udata ) == dict )
 if ( O0000OOOoO ) : udata = [ udata ]
 if 24 - 24: OOooOOo
 o0oOoOOO = [ ]
 for O0o0 in udata :
  o00O0 = { }
  if 19 - 19: IiII % OoooooooOO + OoooooooOO
  if ( type ( O0o0 ) == dict ) :
   lisp_u2a_walk_dict_array ( o00O0 , O0o0 )
  elif ( type ( O0o0 ) == list ) :
   i1II = [ ]
   for i1iII1i in O0o0 :
    Ii1I11Ii1iI = { }
    lisp_u2a_walk_dict_array ( Ii1I11Ii1iI , i1iII1i )
    i1II . append ( Ii1I11Ii1iI )
    if 61 - 61: o0oOOo0O0Ooo * I1ii11iIi11i - i1IIi + I11i % o0oOOo0O0Ooo + OoooooooOO
   o00O0 = i1II
  else :
   o00O0 = { list ( O0o0 . keys ( ) ) [ 0 ] . encode ( ) : o00O0 }
   if 64 - 64: iII111i . ooOoO0o % Ii1I
  o0oOoOOO . append ( o00O0 )
  if 21 - 21: I1Ii111 / oO0o
  if 82 - 82: iIii1I11I1II1 - iII111i . i1IIi . IiII % i11iIiiIii * iIii1I11I1II1
 if ( O0000OOOoO ) : o0oOoOOO = o0oOoOOO [ 0 ]
 return ( o0oOoOOO )
 if 58 - 58: I1ii11iIi11i % i11iIiiIii + OoOoOO00 / I11i - OoooooooOO
 if 62 - 62: OoO0O00 . OoOoOO00
 if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
 if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
 if 41 - 41: OoooooooOO
 if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
 if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
 if 78 - 78: Ii1I
 if 29 - 29: II111iiii
 if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
 if 84 - 84: Oo0Ooo % I11i * O0 * I11i
 if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
def lisp_replace_db_list ( db ) :
 Oo0oO00o = - 1
 for iIiIi1i in lisp . lisp_db_list :
  if ( db . match_eid_tuple ( iIiIi1i ) ) :
   Oo0oO00o = lisp . lisp_db_list . index ( iIiIi1i )
   break
   if 3 - 3: Ii1I * ooOoO0o . OoO0O00 * OoooooooOO + OoOoOO00 / O0
   if 60 - 60: I11i
 if ( Oo0oO00o == - 1 ) : return ( False )
 if 97 - 97: i11iIiiIii * iIii1I11I1II1 / II111iiii
 if 66 - 66: II111iiii + iII111i * oO0o % I11i / i1IIi / iIii1I11I1II1
 if 62 - 62: OoOoOO00 + oO0o * IiII + O0 / OOooOOo + ooOoO0o
 if 38 - 38: i1IIi / iIii1I11I1II1 + iII111i
 if 26 - 26: I1ii11iIi11i . Ii1I % o0oOOo0O0Ooo
 if ( lisp . lisp_nat_traversal and lisp . lisp_i_am_etr ) :
  for o0o0OOo0O in iIiIi1i . rloc_set :
   if ( o0o0OOo0O . is_rloc_translated ( ) == False ) : continue
   iI1iI = db . get_rloc_by_interface ( o0o0OOo0O . interface )
   if ( iI1iI == None ) : continue
   iI1iI . store_translated_rloc ( o0o0OOo0O . translated_rloc , o0o0OOo0O . translated_port )
   iI1iI . rloc_name = o0o0OOo0O . rloc_name
   if 4 - 4: I1Ii111
   if 80 - 80: Oo0Ooo . O0 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
   if 52 - 52: OoO0O00 % i11iIiiIii . ooOoO0o % OoOoOO00 % OoooooooOO
 lisp . lisp_db_list [ Oo0oO00o ] = db
 return ( True )
 if 5 - 5: OoOoOO00 / O0 / i11iIiiIii
 if 88 - 88: II111iiii - iII111i / OoooooooOO
 if 71 - 71: I1ii11iIi11i
 if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
 if 1 - 1: IiII % i1IIi
 if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
 if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
def lisp_map_server_command ( kv_pairs ) :
 oOoooOOO0 = [ ]
 I1Iiii1i1iI = [ ]
 O000O = 0
 OOoO00OOo = 0
 IIo00ooo = ""
 iii = False
 iiiii = False
 OOO00Oo00o = False
 IiII1Iiii = False
 I1 = 0
 o000o00OO00Oo = None
 I1II11I11111i = 0
 I1II1II = None
 if 51 - 51: OoooooooOO . II111iiii % i11iIiiIii
 for IiII1II11I in list ( kv_pairs . keys ( ) ) :
  oo00oO0O0 = kv_pairs [ IiII1II11I ]
  if ( IiII1II11I == "ms-name" ) :
   o000o00OO00Oo = oo00oO0O0 [ 0 ]
   if 48 - 48: iII111i . Oo0Ooo * O0
  if ( IiII1II11I == "address" ) :
   for i1iIIiiIiII in range ( len ( oo00oO0O0 ) ) :
    oOoooOOO0 . append ( oo00oO0O0 [ i1iIIiiIiII ] )
    if 60 - 60: oO0o
    if 9 - 9: IiII
  if ( IiII1II11I == "dns-name" ) :
   for i1iIIiiIiII in range ( len ( oo00oO0O0 ) ) :
    I1Iiii1i1iI . append ( oo00oO0O0 [ i1iIIiiIiII ] )
    if 68 - 68: I1ii11iIi11i % I1Ii111 + I11i . Oo0Ooo
    if 95 - 95: OOooOOo * i11iIiiIii . I11i + Ii1I / Ii1I
  if ( IiII1II11I == "authentication-type" ) :
   OOoO00OOo = lisp . LISP_SHA_1_96_ALG_ID if ( oo00oO0O0 == "sha1" ) else lisp . LISP_SHA_256_128_ALG_ID if ( oo00oO0O0 == "sha2" ) else ""
   if 43 - 43: IiII . OoooooooOO - II111iiii
   if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
  if ( IiII1II11I == "authentication-key" ) :
   if ( OOoO00OOo == 0 ) : OOoO00OOo = lisp . LISP_SHA_256_128_ALG_ID
   I11iIIiiIiIi = lisp . lisp_parse_auth_key ( oo00oO0O0 )
   O000O = list ( I11iIIiiIiIi . keys ( ) ) [ 0 ]
   IIo00ooo = I11iIIiiIiIi [ O000O ]
   if 7 - 7: I1ii11iIi11i
  if ( IiII1II11I == "proxy-reply" ) :
   iii = True if oo00oO0O0 == "yes" else False
   if 11 - 11: ooOoO0o
  if ( IiII1II11I == "merge-registrations" ) :
   iiiii = True if oo00oO0O0 == "yes" else False
   if 36 - 36: OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
  if ( IiII1II11I == "refresh-registrations" ) :
   OOO00Oo00o = True if oo00oO0O0 == "yes" else False
   if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
  if ( IiII1II11I == "want-map-notify" ) :
   IiII1Iiii = True if oo00oO0O0 == "yes" else False
   if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
  if ( IiII1II11I == "site-id" ) :
   I1 = int ( oo00oO0O0 )
   if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
  if ( IiII1II11I == "encryption-key" ) :
   I1II1II = lisp . lisp_parse_auth_key ( oo00oO0O0 )
   I1II11I11111i = list ( I1II1II . keys ( ) ) [ 0 ]
   I1II1II = I1II1II [ I1II11I11111i ]
   if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
   if 28 - 28: iIii1I11I1II1 . O0
   if 32 - 32: OoooooooOO
   if 29 - 29: I1ii11iIi11i
   if 41 - 41: Ii1I
   if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
 for iI11iI1IiiIiI in oOoooOOO0 :
  if ( iI11iI1IiiIiI == "" ) : continue
  IiiIIiIIii1iI = lisp . lisp_ms ( iI11iI1IiiIiI , None , o000o00OO00Oo , OOoO00OOo , O000O , IIo00ooo ,
 iii , iiiii , OOO00Oo00o , IiII1Iiii , I1 , I1II11I11111i , I1II1II )
  if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
 for O0OOO0o0O in I1Iiii1i1iI :
  if ( O0OOO0o0O == "" ) : continue
  IiiIIiIIii1iI = lisp . lisp_ms ( None , O0OOO0o0O , o000o00OO00Oo , OOoO00OOo , O000O , IIo00ooo ,
 iii , iiiii , OOO00Oo00o , IiII1Iiii , I1 , I1II11I11111i , I1II1II )
  if 62 - 62: Oo0Ooo * IiII / O0
 return ( IiiIIiIIii1iI )
 if 35 - 35: OOooOOo / iIii1I11I1II1
 if 62 - 62: O0 % OoOoOO00 % OOooOOo + OOooOOo + Oo0Ooo
 if 8 - 8: OOooOOo
 if 7 - 7: Ii1I - i1IIi % OoO0O00 / iIii1I11I1II1 % o0oOOo0O0Ooo
 if 26 - 26: OoOoOO00 . I1ii11iIi11i . OOooOOo
 if 31 - 31: o0oOOo0O0Ooo
 if 59 - 59: Oo0Ooo / Oo0Ooo
 if 87 - 87: I1ii11iIi11i % OoOoOO00 + Ii1I . i11iIiiIii / Ii1I
def lisp_database_mapping_command ( kv_pair , ephem_port = None , replace = True ) :
 i1I1I1 = [ ]
 o0OoO0000oOO = [ ]
 III11i1iI11 = [ ]
 if 31 - 31: Ii1I / iII111i
 iI1111iI1iII = 1
 if ( "address" in kv_pair ) :
  if ( lisp_clause_syntax_error ( kv_pair , "address" , "rloc" ) ) : return
  iI1111iI1iII = len ( kv_pair [ "address" ] )
 elif ( "interface" in kv_pair ) :
  if ( lisp_clause_syntax_error ( kv_pair , "interface" , "rloc" ) ) : return
  iI1111iI1iII = len ( kv_pair [ "interface" ] )
  if 61 - 61: OOooOOo . OOooOOo
 for i1iIIiiIiII in range ( iI1111iI1iII ) :
  o0o0OOo0O = lisp . lisp_rloc ( )
  III11i1iI11 . append ( o0o0OOo0O )
  if 17 - 17: II111iiii / ooOoO0o
  if 80 - 80: OOooOOo * OoO0O00 + Ii1I
 if ( lisp_clause_syntax_error ( kv_pair , "eid-prefix" , "prefix" ) ) : return
 for i1iIIiiIiII in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  oo0iI1IIIi11iIII = lisp . lisp_mapping ( "" , "" , III11i1iI11 )
  o0OoO0000oOO . append ( oo0iI1IIIi11iIII )
  if 72 - 72: IiII . I1ii11iIi11i / OoO0O00 * i11iIiiIii % OoO0O00 % ooOoO0o
  if 41 - 41: iII111i . O0
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if ( IiII1II11I == "mr-name" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    oo0iI1IIIi11iIII = o0OoO0000oOO [ i1iIIiiIiII ]
    oo0iI1IIIi11iIII . use_mr_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ i1iIIiiIiII ]
    if 74 - 74: o0oOOo0O0Ooo . Ii1I / i1IIi + I1ii11iIi11i + Ii1I + i11iIiiIii
    if 56 - 56: Oo0Ooo - o0oOOo0O0Ooo / iIii1I11I1II1 / Ii1I - IiII - Oo0Ooo
  if ( IiII1II11I == "ms-name" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    oo0iI1IIIi11iIII = o0OoO0000oOO [ i1iIIiiIiII ]
    oo0iI1IIIi11iIII . use_ms_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ i1iIIiiIiII ]
    if 76 - 76: OOooOOo . I1IiiI + OOooOOo + iIii1I11I1II1 + IiII / iIii1I11I1II1
    if 95 - 95: I11i
  if ( IiII1II11I == "instance-id" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    oo0iI1IIIi11iIII = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    oOOo0oO = [ "0" ] if ( oOOo0oO == "" ) else oOOo0oO . split ( )
    for I111I1iI1 in oOOo0oO : oOOo0oO [ oOOo0oO . index ( I111I1iI1 ) ] = int ( I111I1iI1 )
    oo0iI1IIIi11iIII . eid . instance_id = oOOo0oO [ 0 ]
    oo0iI1IIIi11iIII . eid . iid_list = oOOo0oO [ 1 : : ]
    oo0iI1IIIi11iIII . group . instance_id = oOOo0oO [ 0 ]
    if 77 - 77: oO0o / I11i
    if 49 - 49: IiII
  if ( IiII1II11I == "secondary-instance-id" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    oo0iI1IIIi11iIII = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "" ) : continue
    oo0iI1IIIi11iIII . secondary_iid = int ( oOOo0oO )
    if ( oo0iI1IIIi11iIII . eid . address == 0 ) :
     lisp . lisp_default_secondary_iid = int ( oOOo0oO )
     if 56 - 56: O0 / I11i + OOooOOo
     if 7 - 7: Oo0Ooo - i11iIiiIii / oO0o / oO0o . i1IIi % I11i
     if 51 - 51: oO0o
  if ( IiII1II11I == "eid-prefix" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    oo0iI1IIIi11iIII = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : oo0iI1IIIi11iIII . eid . store_prefix ( oOOo0oO )
    if ( oo0iI1IIIi11iIII . eid . address == 0 ) :
     lisp . lisp_default_secondary_iid = oo0iI1IIIi11iIII . secondary_iid
     if 23 - 23: i11iIiiIii * IiII * I11i % I11i - OoOoOO00 + II111iiii
     if 91 - 91: OoooooooOO + I1Ii111 / II111iiii * iII111i + o0oOOo0O0Ooo / Oo0Ooo
     if 7 - 7: I11i / i11iIiiIii - Ii1I % iII111i
  if ( IiII1II11I == "group-prefix" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    oo0iI1IIIi11iIII = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : oo0iI1IIIi11iIII . group . store_prefix ( oOOo0oO )
    if 67 - 67: iIii1I11I1II1 - OoOoOO00
    if 51 - 51: I11i * I1ii11iIi11i % I1ii11iIi11i + o0oOOo0O0Ooo
  if ( IiII1II11I == "dynamic-eid" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    oo0iI1IIIi11iIII = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "yes" ) : oo0iI1IIIi11iIII . dynamic_eids = { }
    if 16 - 16: O0 % I1IiiI * iIii1I11I1II1 - II111iiii + iIii1I11I1II1 + Oo0Ooo
    if 4 - 4: I11i
  if ( IiII1II11I == "signature-eid" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    oo0iI1IIIi11iIII = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    oo0iI1IIIi11iIII . signature_eid = ( oOOo0oO == "yes" )
    if 60 - 60: II111iiii + I1Ii111 / oO0o % OoooooooOO - i1IIi
    if 57 - 57: ooOoO0o
  if ( IiII1II11I == "register-ttl" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    if ( oo00oO0O0 [ i1iIIiiIiII ] == "" ) : continue
    oo0iI1IIIi11iIII = o0OoO0000oOO [ i1iIIiiIiII ]
    oo0iI1IIIi11iIII . register_ttl = int ( oo00oO0O0 [ i1iIIiiIiII ] )
    if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
    if 52 - 52: I1ii11iIi11i
  if ( IiII1II11I == "priority" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "" ) : oOOo0oO = "0"
    o0o0OOo0O . priority = int ( oOOo0oO )
    if 93 - 93: iII111i . i11iIiiIii
    if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
  if ( IiII1II11I == "weight" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "" ) : oOOo0oO = "0"
    o0o0OOo0O . weight = int ( oOOo0oO )
    if 49 - 49: O0 . Oo0Ooo / Ii1I
    if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
  if ( IiII1II11I == "address" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . rloc . store_address ( oOOo0oO )
    if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
    if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  if ( IiII1II11I == "interface" ) :
   O0I11i1i11i1I = lisp . lisp_hostname
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) :
     o0o0OOo0O . interface = oOOo0oO
     II = lisp . lisp_get_interface_address ( oOOo0oO )
     if ( II ) :
      o0o0OOo0O . rloc . copy_address ( II )
      lisp . lisp_myrlocs [ 0 ] = II
      if 44 - 44: i11iIiiIii
     o0o0OOo0O . rloc_name = O0I11i1i11i1I
     i1I1I1 . append ( o0o0OOo0O )
     if 69 - 69: OOooOOo * O0 + i11iIiiIii
     if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
     if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
  if ( IiII1II11I == "elp-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . elp_name = oOOo0oO
    if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
    if 63 - 63: oO0o
  if ( IiII1II11I == "rle-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . rle_name = oOOo0oO
    if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
    if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
  if ( IiII1II11I == "json-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . json_name = oOOo0oO
    if 60 - 60: I1Ii111
    if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
  if ( IiII1II11I == "geo-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . geo_name = oOOo0oO
    if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
    if 14 - 14: Ii1I - O0
  if ( IiII1II11I == "rloc-record-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . rloc_name = oOOo0oO
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
 if ( len ( i1I1I1 ) > 1 ) :
  for o0o0OOo0O in i1I1I1 :
   o0o0OOo0O . rloc_name = O0I11i1i11i1I + "-" + o0o0OOo0O . interface
   if 9 - 9: IiII . I11i
   if 23 - 23: O0 % OoooooooOO - O0 . I1IiiI + i11iIiiIii
   if 96 - 96: ooOoO0o % O0
   if 51 - 51: I1IiiI - iII111i / I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i
   if 87 - 87: II111iiii . Ii1I * OoO0O00
   if 74 - 74: o0oOOo0O0Ooo % OoOoOO00 . iII111i % I1Ii111 . O0 % II111iiii
 for oo0iI1IIIi11iIII in o0OoO0000oOO :
  oo0iI1IIIi11iIII . rloc_set = copy . deepcopy ( oo0iI1IIIi11iIII . rloc_set )
  oo0iI1IIIi11iIII . sort_rloc_set ( )
  oo0iI1IIIi11iIII . add_db ( )
  if ( replace and lisp_replace_db_list ( oo0iI1IIIi11iIII ) ) : continue
  lisp . lisp_db_list . append ( oo0iI1IIIi11iIII )
  if 5 - 5: oO0o - OoooooooOO / OoOoOO00
  if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
  if 55 - 55: OoO0O00
  if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
  if 32 - 32: Ii1I * oO0o
 lisp . lisp_write_ipc_database_mappings ( ephem_port )
 if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
 if 28 - 28: Oo0Ooo
 if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
 if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
 if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
 if 69 - 69: I11i
 if 17 - 17: I11i
 lisp . lisp_default_iid = lisp . lisp_db_list [ 0 ] . eid . instance_id
 if 38 - 38: I1Ii111 % OOooOOo
 if 9 - 9: O0 . iIii1I11I1II1
 if 44 - 44: I1ii11iIi11i % IiII
 if 6 - 6: OoO0O00
 if 82 - 82: iIii1I11I1II1 . I11i / IiII / OOooOOo * II111iiii % oO0o
 if 62 - 62: II111iiii
 if 96 - 96: I11i % OoOoOO00 * I1ii11iIi11i
 if 94 - 94: Oo0Ooo - i1IIi . O0 % Oo0Ooo . ooOoO0o
 for oo0iI1IIIi11iIII in o0OoO0000oOO :
  if ( oo0iI1IIIi11iIII . eid . address == 0 and oo0iI1IIIi11iIII . eid . mask_len == 0 ) :
   if ( oo0iI1IIIi11iIII . eid . is_ipv4 ( ) or oo0iI1IIIi11iIII . eid . is_ipv6 ( ) ) :
    lisp . lisp_pitr = True
    break
    if 63 - 63: i11iIiiIii % I1ii11iIi11i % I1IiiI . IiII * o0oOOo0O0Ooo + OOooOOo
    if 77 - 77: o0oOOo0O0Ooo
    if 63 - 63: ooOoO0o * oO0o + ooOoO0o * Ii1I + Oo0Ooo / I1ii11iIi11i
  if ( oo0iI1IIIi11iIII . dynamic_eids == None ) : continue
  if ( oo0iI1IIIi11iIII . eid . is_mac ( ) and oo0iI1IIIi11iIII . eid . address == 0 and oo0iI1IIIi11iIII . eid . mask_len == 0 ) :
   lisp . lisp_l2_overlay = True
   break
   if 15 - 15: O0 . I1ii11iIi11i * I1ii11iIi11i
   if 65 - 65: I1Ii111 + O0 % o0oOOo0O0Ooo
   if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
   if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
   if 50 - 50: OoooooooOO * i1IIi / oO0o
   if 83 - 83: i1IIi
   if 38 - 38: OoooooooOO * iIii1I11I1II1
   if 54 - 54: OoooooooOO . I1Ii111
 oo0o0oo0O0O = ( lisp . lisp_myrlocs [ 0 ] != None )
 lisp . lisp_get_local_addresses ( )
 if 1 - 1: I1Ii111 - i1IIi - I1Ii111 . Oo0Ooo . i1IIi
 if ( lisp . lisp_myrlocs [ 0 ] == None and oo0o0oo0O0O ) :
  lisp . lprint ( "No RLOCs found, local addresses changed from RLOC to EID" )
  if 14 - 14: OOooOOo / I1Ii111 * Ii1I + I1ii11iIi11i * OoOoOO00 * IiII
  if 87 - 87: I1ii11iIi11i
  if 60 - 60: i11iIiiIii / i1IIi * OOooOOo
  if 89 - 89: iIii1I11I1II1 * o0oOOo0O0Ooo + OoOoOO00 . i11iIiiIii + I1ii11iIi11i
  if 1 - 1: I1IiiI . I11i . I1ii11iIi11i
  if 19 - 19: O0 * I11i % OoooooooOO
  if 36 - 36: o0oOOo0O0Ooo % I11i * I1ii11iIi11i % Ii1I + i1IIi - Oo0Ooo
  if 56 - 56: I1ii11iIi11i
  if 32 - 32: OoOoOO00 % O0 % i11iIiiIii - ooOoO0o . I1IiiI
  if 24 - 24: oO0o % o0oOOo0O0Ooo / I1Ii111 + o0oOOo0O0Ooo
  if 59 - 59: II111iiii % I1IiiI * O0 . OoooooooOO - OoooooooOO % O0
  if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
  if 28 - 28: i1IIi / I11i . o0oOOo0O0Ooo
  if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
  if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
  if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
  if 10 - 10: II111iiii . OOooOOo / iII111i
  if 35 - 35: iII111i / Oo0Ooo + O0 * iIii1I11I1II1 - O0
  if 3 - 3: I1ii11iIi11i
  if 42 - 42: I11i % Oo0Ooo + IiII - I11i . iIii1I11I1II1 - Ii1I
  if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
 if ( lisp . lisp_program_hardware == False ) : return
 if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
 o0Oo = False
 for oo0iI1IIIi11iIII in o0OoO0000oOO :
  if ( oo0iI1IIIi11iIII . dynamic_eids == None ) : continue
  IiIIIii1iIII1 = oo0iI1IIIi11iIII . eid . print_prefix_no_iid ( )
  o0Oo = lisp . lisp_i_am_itr
  os . system ( "ip route add {} dev ma1" . format ( IiIIIii1iIII1 ) )
  if 69 - 69: i1IIi / i11iIiiIii + Oo0Ooo - OoOoOO00
 if ( lisp . lisp_program_hardware and o0Oo ) :
  OOO = "platform trident diag s cpu_control_1 URPF_MISS_TOCPU=1"
  lisp . lisp_send_to_arista ( OOO , None )
  if 13 - 13: IiII . iIii1I11I1II1
  if 30 - 30: i1IIi
  if 42 - 42: iII111i
  if 35 - 35: II111iiii % OOooOOo . oO0o * ooOoO0o
  if 54 - 54: ooOoO0o * I11i - I1Ii111
  if 15 - 15: iII111i / O0
  if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
  if 19 - 19: o0oOOo0O0Ooo . II111iiii / i1IIi
def lisp_show_db_list ( itr_or_etr , output ) :
 Iiii = "{} database-mapping entries" . format ( len ( lisp . lisp_db_list ) )
 oooo00Oo0O = "LISP-{} Configured Database Mappings:" . format ( itr_or_etr )
 oooo00Oo0O = lisp . lisp_span ( oooo00Oo0O , Iiii )
 if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
 ii11ii11II = '<a href="/lisp/show/etr/keys"><br>RLOC Keys</a>'
 if 47 - 47: I1ii11iIi11i * I1IiiI / I1ii11iIi11i + Ii1I * II111iiii
 if ( itr_or_etr == "ITR" ) :
  output += lisp_table_header ( oooo00Oo0O , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Use MR" )
 else :
  output += lisp_table_header ( oooo00Oo0O , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" + ii11ii11II , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Receive Stats" ,
 "Map-Replies<br>Sent" , "Use MS" )
  if 78 - 78: I1Ii111 - i1IIi + OoOoOO00 + Oo0Ooo * I1ii11iIi11i * o0oOOo0O0Ooo
  if 97 - 97: i1IIi
 for oo0iI1IIIi11iIII in lisp . lisp_db_list :
  iII1I1 = lisp . lisp_print_elapsed ( oo0iI1IIIi11iIII . uptime )
  OoO0O = oo0iI1IIIi11iIII . map_replies_sent
  if 33 - 33: Oo0Ooo - OoooooooOO * i1IIi * ooOoO0o + Oo0Ooo . I11i
  if 99 - 99: I1Ii111 + II111iiii
  if 100 - 100: I1ii11iIi11i - IiII / iII111i * I1IiiI / I11i / O0
  if 57 - 57: i1IIi % ooOoO0o
  o0o000oo = ""
  if ( oo0iI1IIIi11iIII . dynamic_eid_configured ( ) ) :
   I1i = oo0iI1IIIi11iIII . eid . print_prefix_url ( )
   Oo00o = len ( oo0iI1IIIi11iIII . dynamic_eids )
   ooooOoO0O = itr_or_etr . lower ( )
   o0o000oo = ( "<br><a href='/lisp/show/{}/dynamic-eid/{}'>" + "{} dynamic-eids</a>" ) . format ( ooooOoO0O , I1i , Oo00o )
   if 16 - 16: II111iiii * OoO0O00 * I1Ii111
   if 80 - 80: OOooOOo * OOooOOo
   if 5 - 5: OoooooooOO - iII111i - i11iIiiIii
  O0oOOOOooOo0 = True
  for o0o0OOo0O in oo0iI1IIIi11iIII . rloc_set :
   if ( O0oOOOOooOo0 ) :
    o0000o0OOOo = oo0iI1IIIi11iIII . print_eid_tuple ( )
    o0000o0OOOo = oo0iI1IIIi11iIII . star_secondary_iid ( o0000o0OOOo )
    o0000o0OOOo += o0o000oo
    O0O0O = iII1I1
    O0oOOOOooOo0 = False
   else :
    o0000o0OOOo , O0O0O , OoO0O = ( "" , "" , "" )
    if 3 - 3: IiII
    if 18 - 18: I1IiiI
   i1 = "" if o0o0OOo0O . rloc . is_null ( ) else o0o0OOo0O . rloc . print_address_no_iid ( )
   if 32 - 32: iIii1I11I1II1 * I1IiiI . OOooOOo * iIii1I11I1II1
   if 92 - 92: oO0o - ooOoO0o . OoooooooOO * oO0o / Oo0Ooo
   if ( o0o0OOo0O . interface != None ) :
    i1 += " ({})" . format ( o0o0OOo0O . interface )
    if 16 - 16: I11i / OoooooooOO - IiII % I1IiiI % I11i
   if ( i1 != "" ) : i1 += "<br>"
   if 97 - 97: OOooOOo * i1IIi / OoooooooOO
   if ( o0o0OOo0O . translated_rloc . not_set ( ) == False ) :
    i1 += "translated RLOC: {}<br>" . format ( o0o0OOo0O . translated_rloc . print_address_no_iid ( ) )
    if 64 - 64: OOooOOo + o0oOOo0O0Ooo / i11iIiiIii - OoOoOO00 + OOooOOo
    if 90 - 90: i1IIi % OoO0O00 / ooOoO0o - O0 + i11iIiiIii
    if 98 - 98: OoooooooOO
   OOooOo = o0o0OOo0O . print_rloc_name ( True )
   if ( OOooOo != "" ) : i1 += OOooOo + "<br>"
   if 10 - 10: ooOoO0o * ooOoO0o / oO0o % OoooooooOO
   if ( o0o0OOo0O . geo_name != None ) :
    i1 += "geo: " + o0o0OOo0O . geo_name + "<br>"
    if 9 - 9: iII111i - I11i + IiII / OoOoOO00 % Ii1I / iIii1I11I1II1
   if ( o0o0OOo0O . elp_name != None ) :
    i1 += "elp: " + o0o0OOo0O . elp_name + "<br>"
    if 21 - 21: OOooOOo / ooOoO0o . o0oOOo0O0Ooo * Ii1I - ooOoO0o / I1IiiI
   if ( o0o0OOo0O . rle_name != None ) :
    i1 += "rle: " + o0o0OOo0O . rle_name + "<br>"
    if 100 - 100: I11i - OOooOOo - OoooooooOO * OoO0O00 * iII111i + oO0o
   if ( o0o0OOo0O . json_name != None ) :
    i1 += "json: " + o0o0OOo0O . json_name + "<br>"
    if 100 - 100: I1Ii111 - i1IIi
    if 90 - 90: Ii1I + oO0o . II111iiii - OoOoOO00 % iIii1I11I1II1
   if ( itr_or_etr == "ITR" ) :
    output += lisp_table_row ( o0000o0OOOo , O0O0O , i1 ,
 str ( o0o0OOo0O . priority ) + "/" + str ( o0o0OOo0O . weight ) ,
 str ( o0o0OOo0O . mpriority ) + "/" + str ( o0o0OOo0O . mweight ) ,
 oo0iI1IIIi11iIII . use_mr_name )
   else :
    IiIII = o0o0OOo0O . stats . get_stats ( True , True )
    output += lisp_table_row ( o0000o0OOOo , O0O0O , i1 ,
 str ( o0o0OOo0O . priority ) + "/" + str ( o0o0OOo0O . weight ) ,
 str ( o0o0OOo0O . mpriority ) + "/" + str ( o0o0OOo0O . mweight ) , IiIII ,
 OoO0O , oo0iI1IIIi11iIII . use_ms_name )
    if 24 - 24: IiII / Ii1I * OOooOOo
    if 33 - 33: OOooOOo
    if 22 - 22: O0 + OOooOOo % i1IIi
 output += lisp_table_footer ( )
 if 83 - 83: O0 + Ii1I % i11iIiiIii
 if 32 - 32: I1Ii111 % Oo0Ooo - I11i + O0
 if 57 - 57: OoO0O00 + I1Ii111 . I11i . i1IIi - o0oOOo0O0Ooo / Oo0Ooo
 if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
 if ( len ( lisp . lisp_geo_list ) != 0 ) :
  oooo00Oo0O = "Configured Geo-Coordinates:"
  output += lisp_table_header ( oooo00Oo0O , "Geo Name" ,
 "Geo-Prefix or Geo-Point" )
  Ii1ii1I1I = sorted ( lisp . lisp_geo_list )
  for O0oooOO in Ii1ii1I1I :
   IIiIi1I1iI1 = lisp . lisp_geo_list [ O0oooOO ]
   output += lisp_table_row ( O0oooOO , IIiIi1I1iI1 . print_geo_url ( ) )
   if 95 - 95: oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
  output += lisp_table_footer ( )
  if 22 - 22: OoOoOO00
 return ( output )
 if 49 - 49: oO0o
 if 78 - 78: OOooOOo
 if 68 - 68: ooOoO0o
 if 70 - 70: OoOoOO00 - Oo0Ooo - I1Ii111 * OOooOOo * OOooOOo * I1IiiI
 if 12 - 12: Ii1I
 if 33 - 33: OOooOOo * Ii1I
 if 64 - 64: i11iIiiIii . iIii1I11I1II1
def lisp_interface_command ( kv_pair ) :
 III1II1I1iI = None
 oOOOO = None
 Oo0OO0o0oOO0 = None
 i1II1IiIIi = None
 o0O0 = None
 iiI = None
 i1I1IIIII1IIi = None
 i11iii1II1I1 = None
 if 25 - 25: II111iiii * i1IIi + IiII * o0oOOo0O0Ooo / OOooOOo
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if ( IiII1II11I == "interface-name" ) : III1II1I1iI = oo00oO0O0
  if ( IiII1II11I == "device" ) : oOOOO = oo00oO0O0
  if ( IiII1II11I == "instance-id" ) : Oo0OO0o0oOO0 = oo00oO0O0
  if ( IiII1II11I == "dynamic-eid" ) : i1II1IiIIi = oo00oO0O0
  if ( IiII1II11I == "multi-tenant-eid" ) : i1I1IIIII1IIi = oo00oO0O0
  if ( IiII1II11I == "dynamic-eid-device" ) : o0O0 = oo00oO0O0
  if ( IiII1II11I == "dynamic-eid-timeout" ) : iiI = oo00oO0O0
  if ( IiII1II11I == "lisp-nat" ) : i11iii1II1I1 = ( oo00oO0O0 == "yes" )
  if 66 - 66: i11iIiiIii . OoO0O00 / OoOoOO00 - I1Ii111
  if 99 - 99: Ii1I - IiII - i1IIi / i11iIiiIii . IiII
 if ( oOOOO == None ) : return
 if 58 - 58: OOooOOo
 if 12 - 12: I1IiiI . o0oOOo0O0Ooo * OoooooooOO
 if 64 - 64: OoOoOO00 + IiII - i1IIi . II111iiii . OoO0O00
 if 31 - 31: oO0o . iII111i - I11i . iIii1I11I1II1 + I11i . OoOoOO00
 if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
 if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
 if 30 - 30: OoooooooOO % OOooOOo
 if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
 if ( oOOOO in lisp . lisp_myinterfaces and i1I1IIIII1IIi == None ) :
  o0o00O00Oo0 = lisp . lisp_myinterfaces [ oOOOO ]
 else :
  o0o00O00Oo0 = lisp . lisp_interface ( oOOOO )
  lisp . lisp_myinterfaces [ oOOOO ] = o0o00O00Oo0
  if 96 - 96: iII111i
  if 9 - 9: IiII + II111iiii . I1IiiI * iII111i
  if 6 - 6: iII111i % I1Ii111
  if 17 - 17: II111iiii - OoooooooOO + I11i % Ii1I % OoooooooOO
  if 14 - 14: i1IIi - iIii1I11I1II1 . ooOoO0o + IiII / i1IIi / II111iiii
 o0o00O00Oo0 . interface_name = III1II1I1iI
 if ( Oo0OO0o0oOO0 != None ) :
  if ( Oo0OO0o0oOO0 . isdigit ( ) == False ) : Oo0OO0o0oOO0 = "0"
  o0o00O00Oo0 . instance_id = int ( Oo0OO0o0oOO0 )
  if 47 - 47: OOooOOo
 if ( i1II1IiIIi != None ) :
  o0o00O00Oo0 . dynamic_eid . store_prefix ( i1II1IiIIi )
  o0o00O00Oo0 . dynamic_eid . instance_id = o0o00O00Oo0 . instance_id
  if 68 - 68: I1Ii111 + IiII . iIii1I11I1II1
 if ( o0O0 != None ) :
  o0o00O00Oo0 . dynamic_eid_device = o0O0
  if 48 - 48: I1IiiI % O0 * Oo0Ooo / O0
 if ( iiI != None ) :
  o0o00O00Oo0 . dynamic_eid_timeout = int ( iiI )
  if 95 - 95: I1ii11iIi11i / Ii1I
 if ( i1I1IIIII1IIi != None ) :
  o0o00O00Oo0 . multi_tenant_eid . store_prefix ( i1I1IIIII1IIi )
  o0o00O00Oo0 . multi_tenant_eid . instance_id = int ( o0o00O00Oo0 . instance_id )
  lisp . lisp_multi_tenant_interfaces . append ( o0o00O00Oo0 )
  if 82 - 82: II111iiii . I1Ii111
 if ( i11iii1II1I1 ) :
  oO00000o = "sudo iptables -t nat -C POSTROUTING -o {} -j MASQUERADE"
  oO00000o = getoutput ( oO00000o . format ( oOOOO ) )
  if ( oO00000o != "" ) :
   i1i = lisp . lisp_get_loopback_address ( )
   if ( i1i ) :
    o00o0O0o0O0 = "sudo iptables -t nat -A POSTROUTING -s {} -j ACCEPT"
    os . system ( o00o0O0o0O0 . format ( i1i ) )
    if 33 - 33: Ii1I . oO0o
   o00o0O0o0O0 = "sudo iptables -t nat -A POSTROUTING -o {} -j MASQUERADE"
   os . system ( o00o0O0o0O0 . format ( oOOOO ) )
   os . system ( "sudo sysctl net.ipv4.ip_forward=1" )
   if 87 - 87: Oo0Ooo . o0oOOo0O0Ooo - OoooooooOO * oO0o % IiII + O0
   if 16 - 16: I1ii11iIi11i % Oo0Ooo % II111iiii % II111iiii
   if 51 - 51: OoOoOO00 * OoOoOO00 - O0 % iIii1I11I1II1 / O0
 lisp . lisp_iid_to_interface [ Oo0OO0o0oOO0 ] = o0o00O00Oo0
 if 5 - 5: i11iIiiIii * ooOoO0o % iII111i - I11i
 if 5 - 5: O0 * IiII * OOooOOo + I1Ii111 % Oo0Ooo - I1ii11iIi11i
 if 62 - 62: I1ii11iIi11i + I11i
 if 90 - 90: iIii1I11I1II1
 if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
 if ( "SO_BINDTODEVICE" in dir ( socket ) ) : o0o00O00Oo0 . set_socket ( oOOOO )
 if ( "PF_PACKET" in dir ( socket ) ) : o0o00O00Oo0 . set_bridge_socket ( oOOOO )
 if 69 - 69: Oo0Ooo * ooOoO0o
 if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
 if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
 if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
 lisp . lisp_get_local_addresses ( )
 if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
 if 24 - 24: OoOoOO00 * Ii1I
 if 17 - 17: OoO0O00 . I1IiiI * O0
 if 81 - 81: OOooOOo
 if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
 if 41 - 41: I11i + OoO0O00 . iII111i
 if ( i1II1IiIIi != None and lisp . lisp_program_hardware ) :
  OOO = "ip verify unicast source reachable-via rx"
  lisp . lisp_send_to_arista ( OOO , oOOOO )
  OOO = 'sysctl -w "net.ipv4.conf.{}.rp_filter=0"' . format ( oOOOO )
  os . system ( OOO )
  if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
  if 56 - 56: i1IIi
  if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
  if 82 - 82: IiII
  if 10 - 10: Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
 lisp . lisp_write_ipc_interfaces ( )
 return
 if 54 - 54: i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i / I1IiiI . iIii1I11I1II1 / iII111i
 if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
 if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
 if 30 - 30: I11i - OoO0O00
 if 15 - 15: OoooooooOO
 if 31 - 31: II111iiii
 if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
 if 87 - 87: IiII
def lisp_parse_eid_in_url ( command , eid_prefix ) :
 IiIIii1iII1II = ""
 if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
 if 55 - 55: IiII
 if 43 - 43: OOooOOo
 if 17 - 17: i11iIiiIii
 if ( eid_prefix == "0--0" ) :
  command = command + "%[0]/0%"
 elif ( eid_prefix . find ( "-name-" ) != - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if ( len ( eid_prefix ) > 4 ) :
   eid_prefix = [ eid_prefix [ 0 ] , "name" , "-" . join ( eid_prefix [ 2 : - 1 ] ) ,
 eid_prefix [ - 1 ] ]
   if 94 - 94: OoooooooOO - IiII + oO0o . OoooooooOO / i1IIi
   if 53 - 53: I1Ii111 % I1ii11iIi11i
   if 17 - 17: OoooooooOO % Ii1I % O0
   if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
   if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
  o0O = "[" + eid_prefix [ 0 ] + "]'" + eid_prefix [ 2 ] + "'" + "/" + eid_prefix [ 3 ]
  if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
  command = command + "%" + o0O + "%"
 elif ( eid_prefix . count ( "-" ) in [ 9 , 10 ] ) :
  if 80 - 80: oO0o / O0
  if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
  if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
  if 59 - 59: IiII
  eid_prefix = eid_prefix . split ( "-" )
  o0O = "[" + eid_prefix [ 0 ] + "]" + "-" . join ( eid_prefix [ 1 : - 1 ] ) + "/" + eid_prefix [ - 1 ]
  if 54 - 54: OOooOOo
  command = command + "%" + o0O + "%"
 elif ( eid_prefix . find ( "." ) == - 1 and eid_prefix . find ( ":" ) == - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
  if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
  if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
  if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
  if ( eid_prefix [ 1 ] == "plus" ) :
   o0O = "[" + eid_prefix [ 0 ] + "]+" + eid_prefix [ 2 ] + "/" + eid_prefix [ 3 ]
   if 33 - 33: oO0o % OoO0O00 . iIii1I11I1II1 / IiII
   command = command + "%" + o0O + "%"
  else :
   if 3 - 3: Ii1I + OoO0O00
   if 60 - 60: OoO0O00 . OoOoOO00 - I1ii11iIi11i - I1IiiI - II111iiii % Oo0Ooo
   if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
   if 47 - 47: I1Ii111 + I1IiiI
   o0O = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "-" + eid_prefix [ 2 ] + "-" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
   if 80 - 80: oO0o
   if 81 - 81: OoooooooOO / ooOoO0o * iIii1I11I1II1 . Oo0Ooo + oO0o / O0
   if 84 - 84: II111iiii - o0oOOo0O0Ooo
   if 78 - 78: IiII
   if ( len ( eid_prefix ) == 10 ) :
    IiIIii1iII1II = "[" + eid_prefix [ 5 ] + "]" + eid_prefix [ 6 ] + "-" + eid_prefix [ 7 ] + "-" + eid_prefix [ 8 ] + "/" + eid_prefix [ 9 ]
    if 58 - 58: i11iIiiIii - OoOoOO00
    command = command + "%" + o0O + "%" + IiIIii1iII1II
   else :
    command = command + "%" + o0O + "%"
    if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
    if 99 - 99: ooOoO0o . Ii1I
    if 92 - 92: i1IIi
 else :
  if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
  if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
  if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
  if 4 - 4: Ii1I
  eid_prefix = eid_prefix . split ( "-" )
  if ( eid_prefix [ 1 ] == "*" ) :
   o0O = ""
   IiIIii1iII1II = "[" + eid_prefix [ 2 ] + "]" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
  else :
   o0O = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "/" + eid_prefix [ 2 ]
   if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
   if ( len ( eid_prefix ) == 6 ) :
    IiIIii1iII1II = "[" + eid_prefix [ 3 ] + "]" + eid_prefix [ 4 ] + "/" + eid_prefix [ 5 ]
    if 32 - 32: I1Ii111 / oO0o / I1IiiI
    if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
    if 69 - 69: oO0o - I1IiiI
  command = command + "%" + o0O + "%" + IiIIii1iII1II
  if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
 return ( command )
 if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
 if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
 if 35 - 35: I1ii11iIi11i % OoooooooOO
 if 59 - 59: I1IiiI % I11i
 if 32 - 32: I1IiiI * O0 + O0
 if 34 - 34: IiII
 if 5 - 5: OoO0O00 . I1IiiI
def lisp_show_dynamic_eid_command ( parm ) :
 o0o0oOOOo0oo = ""
 if ( parm == "" ) : return ( o0o0oOOOo0oo )
 if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
 Oo0OOo = lisp_get_lookup_string ( parm . split ( "%" ) [ 0 ] )
 Oo0OOo = Oo0OOo [ 0 ]
 if 47 - 47: iII111i / OoooooooOO - II111iiii
 oo0iI1IIIi11iIII = lisp . lisp_db_for_lookups . lookup_cache ( Oo0OOo , False )
 if ( oo0iI1IIIi11iIII == None ) : return ( o0o0oOOOo0oo )
 if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
 ooooOoO0O = "ITR" if lisp . lisp_i_am_itr else "ETR"
 o0O = oo0iI1IIIi11iIII . print_eid_tuple ( )
 if 23 - 23: i1IIi
 oooo00Oo0O = "LISP-{} Discovered Dynamic EIDs for {}:" . format ( ooooOoO0O , o0O )
 if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
 if ( ooooOoO0O == "ITR" ) :
  o0o0oOOOo0oo = lisp_table_header ( oooo00Oo0O , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Last Packet" , "Inactivity Timeout" )
 else :
  o0o0oOOOo0oo = lisp_table_header ( oooo00Oo0O , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Inactivity Timeout" )
  if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
  if 31 - 31: I1Ii111 - I11i
 for IiIIIii1iIII1 in list ( oo0iI1IIIi11iIII . dynamic_eids . values ( ) ) :
  Oo0OOo = IiIIIii1iIII1 . dynamic_eid . print_address ( )
  IiIiIIi1 = lisp . lisp_print_elapsed ( IiIIIii1iIII1 . uptime )
  IIi1Iii = str ( IiIIIii1iIII1 . timeout ) + " secs"
  if ( ooooOoO0O == "ITR" ) :
   iI1II1III = lisp . lisp_print_elapsed ( IiIIIii1iIII1 . last_packet )
   o0o0oOOOo0oo += lisp_table_row ( Oo0OOo , IiIIIii1iIII1 . interface , IiIiIIi1 , iI1II1III , IIi1Iii )
  else :
   o0o0oOOOo0oo += lisp_table_row ( Oo0OOo , IiIIIii1iIII1 . interface , IiIiIIi1 , IIi1Iii )
   if 80 - 80: o0oOOo0O0Ooo . OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
   if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
 o0o0oOOOo0oo += lisp_table_footer ( )
 return ( o0o0oOOOo0oo )
 if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
 if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
 if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
 if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
 if 97 - 97: Ii1I % i1IIi % IiII + Oo0Ooo - O0 - I11i
 if 64 - 64: Ii1I - iII111i
 if 12 - 12: i1IIi
def lisp_clear_decap_stats ( command ) :
 oo0O0o0O = command . split ( "%" ) [ 1 ]
 lisp . lisp_decap_stats [ oo0O0o0O ] = lisp . lisp_stats ( )
 if 87 - 87: iII111i - OoO0O00 * Oo0Ooo - IiII . I1ii11iIi11i * i1IIi
 if 79 - 79: iII111i
 if 32 - 32: Ii1I % I11i + OOooOOo % OoooooooOO
 if 68 - 68: I11i
 if 13 - 13: i11iIiiIii - ooOoO0o
 if 54 - 54: I1IiiI * I1IiiI - I11i . O0 . iII111i - Ii1I
 if 86 - 86: I1IiiI . II111iiii * i1IIi % I1IiiI . OOooOOo
def lisp_show_decap_stats ( output , etr_or_rtr ) :
 oO0o0O = etr_or_rtr . upper ( )
 oO0Oo = etr_or_rtr . lower ( )
 if 60 - 60: i1IIi / I11i - o0oOOo0O0Ooo - ooOoO0o
 I1IIi1I = [ ]
 for o0 in lisp . lisp_decap_stats :
  OO0OoO0 = "<a href='/lisp/clear/{}/stats/{}'>{}</a>" . format ( oO0Oo , o0 , o0 )
  I1IIi1I . append ( OO0OoO0 )
  if 83 - 83: OoooooooOO + I1IiiI
  if 88 - 88: II111iiii
 IioO0OO0O = "LISP-{} Decapsulation Stats:" . format ( oO0o0O )
 output += lisp_table_header ( IioO0OO0O , * I1IIi1I )
 if 1 - 1: o0oOOo0O0Ooo / II111iiii + I11i . i11iIiiIii + ooOoO0o . OoOoOO00
 I1IIi1I = [ ]
 for OO00 in list ( lisp . lisp_decap_stats . values ( ) ) :
  I1IIi1I . append ( OO00 . get_stats ( False , True ) )
  if 41 - 41: ooOoO0o * i11iIiiIii
 output += lisp_table_row ( * I1IIi1I )
 output += lisp_table_footer ( )
 return ( output )
 if 67 - 67: ooOoO0o . iIii1I11I1II1 . OoO0O00 + I1Ii111
 if 51 - 51: oO0o
 if 68 - 68: I1ii11iIi11i - Ii1I - I1Ii111
 if 58 - 58: OoOoOO00 . Ii1I / IiII * oO0o
 if 70 - 70: OoooooooOO
 if 51 - 51: oO0o / II111iiii + ooOoO0o / I11i . iII111i
 if 77 - 77: iIii1I11I1II1 * OoOoOO00 + i11iIiiIii * ooOoO0o
 if 81 - 81: Ii1I * iII111i % Ii1I % i11iIiiIii % i1IIi / o0oOOo0O0Ooo
def lisp_show_crypto_list ( xtr ) :
 o0o0oOOOo0oo = ""
 oOO00oo = len ( lisp . lisp_crypto_keys_by_nonce ) != 0
 if 41 - 41: iII111i + I11i . oO0o - ooOoO0o . OoooooooOO
 if ( lisp . lisp_i_am_itr or lisp . lisp_i_am_rtr ) :
  if ( oOO00oo ) :
   oooo00Oo0O = "LISP-{} Nonce Crypto State" . format ( xtr )
   o0o0oOOOo0oo += lisp_table_header ( oooo00Oo0O , "Nonce" , "Uptime" , "Key-ID" ,
 "Key Material" )
   for o0 in lisp . lisp_crypto_keys_by_nonce :
    Ii1iII1ii1 = "0x" + lisp . lisp_hex_string ( o0 )
    oo00oO0O0 = lisp . lisp_crypto_keys_by_nonce [ o0 ]
    for OoooooooOo00O in oo00oO0O0 :
     if ( OoooooooOo00O == None ) : continue
     oo0oo00 = lisp . lisp_print_elapsed ( OoooooooOo00O . uptime )
     ii11ii11II = OoooooooOo00O . print_keys ( False )
     o0o0oOOOo0oo += lisp_table_row ( Ii1iII1ii1 , oo0oo00 , OoooooooOo00O . key_id , ii11ii11II )
     Ii1iII1ii1 = ""
     if 84 - 84: OoooooooOO - Oo0Ooo
     if 79 - 79: O0 - oO0o + oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
   o0o0oOOOo0oo += lisp_table_footer ( )
   if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
   if 18 - 18: OoOoOO00
  oooo00Oo0O = "LISP-{} Encapsulation Crypto State" . format ( xtr )
  o0o0oOOOo0oo += lisp_table_header ( oooo00Oo0O , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for o0 in lisp . lisp_crypto_keys_by_rloc_encap :
   Ii1iII1ii1 = o0
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_encap [ o0 ]
   for OoooooooOo00O in oo00oO0O0 :
    if ( OoooooooOo00O == None ) : continue
    oo0oo00 = lisp . lisp_print_elapsed ( OoooooooOo00O . uptime )
    ii1Ii = lisp . lisp_print_elapsed ( OoooooooOo00O . last_rekey )
    ii11ii11II = OoooooooOo00O . print_keys ( False )
    o0o0oOOOo0oo += lisp_table_row ( Ii1iII1ii1 , oo0oo00 , ii1Ii , OoooooooOo00O . rekey_count ,
 OoooooooOo00O . use_count , OoooooooOo00O . key_id , ii11ii11II )
    Ii1iII1ii1 = ""
    if 42 - 42: iII111i
    if 6 - 6: OoO0O00 + OOooOOo
  o0o0oOOOo0oo += lisp_table_footer ( )
  if 22 - 22: Oo0Ooo . OoooooooOO % I1Ii111
  if 16 - 16: I1ii11iIi11i
 if ( lisp . lisp_i_am_etr or lisp . lisp_i_am_rtr ) :
  oooo00Oo0O = "LISP-{} Decapsulation Crypto State" . format ( xtr )
  o0o0oOOOo0oo += lisp_table_header ( oooo00Oo0O , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for o0 in lisp . lisp_crypto_keys_by_rloc_decap :
   Ii1iII1ii1 = o0
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_decap [ o0 ]
   for OoooooooOo00O in oo00oO0O0 :
    if ( OoooooooOo00O == None ) : continue
    oo0oo00 = lisp . lisp_print_elapsed ( OoooooooOo00O . uptime )
    ii1Ii = lisp . lisp_print_elapsed ( OoooooooOo00O . last_rekey )
    ii11ii11II = OoooooooOo00O . print_keys ( False )
    o0o0oOOOo0oo += lisp_table_row ( Ii1iII1ii1 , oo0oo00 , ii1Ii , OoooooooOo00O . rekey_count ,
 OoooooooOo00O . use_count , OoooooooOo00O . key_id , ii11ii11II )
    Ii1iII1ii1 = ""
    if 78 - 78: OoO0O00 * iIii1I11I1II1
    if 58 - 58: I1ii11iIi11i * i11iIiiIii
  o0o0oOOOo0oo += lisp_table_footer ( )
  if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
 return ( o0o0oOOOo0oo )
 if 47 - 47: Ii1I . OoOoOO00 . iIii1I11I1II1 . o0oOOo0O0Ooo
 if 39 - 39: o0oOOo0O0Ooo
 if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
