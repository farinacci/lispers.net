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
 "lisp decent-prefix" : [ "lisp-itr" ] ,

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
 "address" : [ True ] ,
 "dns-name" : [ True ] } ]
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
 oO0O = " (py2)" if lisp . lisp_is_python2 ( ) else " (py3)"
 if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
 O0OoOoo00o = '''<br><hr style="border: none; border-bottom: 1px solid gray;">
        <i><font size="2">{} - Uptime
        {}, Version {}<br>Copyright 2013-2019 - all rights reserved by
        <a href="http://www.lispers.net"><b>lispers.net</b></a> LLC<br>
        Features/Bugs go to <a href=
"mailto:support@lispers.net?subject=lispers.net v{} bug-report from '{}'">
        support@lispers.net</a></i></font><br><br>
    ''' . format ( OoooooOoo , OO , lisp . bold ( lisp . lisp_version + oO0O , True ) ,
 lisp . lisp_version + oO0O , O0I11i1i11i1I )
 if 23 - 23: i11iIiiIii + I1IiiI
 return ( O0OoOoo00o )
 if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
 if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
 if 33 - 33: Ii1I + II111iiii % i11iIiiIii . ooOoO0o - I1IiiI
 if 66 - 66: Ii1I - OoooooooOO * OoooooooOO . OOooOOo . I1ii11iIi11i
 if 22 - 22: OoooooooOO % I11i - iII111i . iIii1I11I1II1 * i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 if 61 - 61: ooOoO0o
def lisp_show_wrapper ( output ) :
 return ( lisp_banner_top ( False ) + output + lisp_banner_bottom ( ) )
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
def lisp_table_header ( title , * args ) :
 I1i1iii = '''
        <font face="Sans-Serif"><h3><i>{}</i></h3></font>
        <table border="1" cellspacing="3x" cellpadding="5x">
        <tr>
    ''' . format ( title )
 if 20 - 20: o0oOOo0O0Ooo
 for oO00 in args :
  I1i1iii += '''
            <td><font face="Sans-Serif"><b>{}</b></font></td>
        ''' . format ( oO00 )
  if 53 - 53: OoooooooOO . i1IIi
 I1i1iii += "</tr>"
 return ( I1i1iii )
 if 18 - 18: o0oOOo0O0Ooo
 if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % oO0o . O0
 if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
 if 53 - 53: IiII + I1IiiI * oO0o
 if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
 if 60 - 60: I11i / I11i
def lisp_table_row ( * args ) :
 I1i1iii = "<tr>"
 for oO00 in args :
  I1i1iii += '''
            <td><font face="Sans-Serif">{}</font></td>
        ''' . format ( oO00 )
  if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
 I1i1iii += "</tr>"
 return ( I1i1iii )
 if 83 - 83: OoooooooOO
 if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 if 4 - 4: II111iiii / ooOoO0o . iII111i
 if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 if 50 - 50: I1IiiI
 if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
 if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
def lisp_table_footer ( ) :
 return ( "</table>" )
 if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
 if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
 if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
 if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
 if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 if 58 - 58: i11iIiiIii % I11i
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
def lisp_write_last_changed_date ( new , line ) :
 oO0OOoO0 = getoutput ( "date" )
 I111Ii111 = line . find ( ":" )
 line = line [ 0 : I111Ii111 + 1 ] + " " + oO0OOoO0 + "\n"
 new . write ( line )
 return
 if 4 - 4: oO0o
 if 93 - 93: OoO0O00 % oO0o . OoO0O00 * I1Ii111 % Ii1I . II111iiii
 if 38 - 38: o0oOOo0O0Ooo
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
 if 26 - 26: iII111i
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
 if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
 if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
def lisp_comment ( line ) :
 return ( True if line [ 0 ] == "#" else False )
 if 91 - 91: oO0o % Oo0Ooo
 if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
 if 31 - 31: I11i - II111iiii . I11i
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
def lisp_begin_clause ( line ) :
 return ( False if line . find ( "{" ) == - 1 else True )
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 if 92 - 92: iII111i . I1Ii111
 if 31 - 31: I1Ii111 . OoOoOO00 / O0
 if 89 - 89: OoOoOO00
 if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
 if 4 - 4: ooOoO0o + O0 * OOooOOo
def lisp_end_clause ( line ) :
 return ( False if line . find ( "}" ) == - 1 else True )
 if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
 if 25 - 25: I1ii11iIi11i
 if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
 if 13 - 13: OOooOOo / i11iIiiIii
 if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
 if 52 - 52: o0oOOo0O0Ooo
 if 95 - 95: Ii1I
 if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
def lisp_end_file ( line ) :
 return ( True if ( line [ 0 : 10 ] == "#---------" and line [ - 2 ] == "#" ) else False )
 if 91 - 91: O0
 if 61 - 61: II111iiii
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
 if 67 - 67: I1Ii111 . iII111i . O0
 if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
def lisp_write_error ( line , error ) :
 I1111IIi = "%>>> " + line + " <<< " + error + "\n"
 return ( I1111IIi )
 if 93 - 93: OoooooooOO / I1IiiI % i11iIiiIii + I1ii11iIi11i * OoO0O00
 if 15 - 15: I11i . OoO0O00 / Oo0Ooo + I11i
 if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
 if 49 - 49: Ii1I / OoO0O00 . II111iiii
 if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
 if 31 - 31: II111iiii . I1IiiI
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
def lisp_write_line ( line ) :
 return ( "#" + line + "\n" )
 if 92 - 92: iII111i
 if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
def lisp_not_supported ( ) :
 return ( lisp_show_wrapper ( "" ) )
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % I1Ii111
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
 if 23 - 23: O0
def lisp_hash_password ( plaintext ) :
 o00oO0oOo00 = plaintext . encode ( )
 oO0oOo0 = hmac . new ( b"lispers.net" , o00oO0oOo00 , hashlib . sha1 ) . hexdigest ( )
 return ( oO0oOo0 )
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
 III11I1 = clause . count ( " decent-prefix {" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "instance-id" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "eid-prefix" ] = [ "" ] * III11I1
  I1IiIiiIiIII [ "lookup-length" ] = [ "" ] * III11I1
  if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
  if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
  if 17 - 17: i1IIi
  if 21 - 21: Oo0Ooo
  if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
 III11I1 = clause . count ( "data-plane-security =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "data-plane-security" ] = [ "" ] * III11I1
  if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 III11I1 = clause . count ( "data-plane-logging =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "data-plane-logging" ] = [ "" ] * III11I1
  if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 III11I1 = clause . count ( "frame-logging =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "frame-logging" ] = [ "" ] * III11I1
  if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
 III11I1 = clause . count ( "flow-logging =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "flow-logging" ] = [ "" ] * III11I1
  if 54 - 54: i1IIi + II111iiii
 III11I1 = clause . count ( "nat-traversal =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "nat-traversal" ] = [ "" ] * III11I1
  if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 III11I1 = clause . count ( "decentralized-nat =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "decentralized-nat" ] = [ "" ] * III11I1
  if 5 - 5: Ii1I
 III11I1 = clause . count ( "rloc-probing =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "rloc-probing" ] = [ "" ] * III11I1
  if 46 - 46: IiII
 III11I1 = clause . count ( "nonce-echoing =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "nonce-echoing" ] = [ "" ] * III11I1
  if 45 - 45: ooOoO0o
 III11I1 = clause . count ( "checkpoint-map-cache =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "checkpoint-map-cache" ] = [ "" ] * III11I1
  if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 III11I1 = clause . count ( "ipc-data-plane =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "ipc-data-plane" ] = [ "" ] * III11I1
  if 17 - 17: OOooOOo / OOooOOo / I11i
 III11I1 = clause . count ( "program-hardware =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "program-hardware" ] = [ "" ] * III11I1
  if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
 III11I1 = clause . count ( "decentralized-push-xtr =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "decentralized-push-xtr" ] = [ "" ] * III11I1
  if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
 III11I1 = clause . count ( "decentralized-pull-xtr-modulus =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "decentralized-pull-xtr-modulus" ] = [ "" ] * III11I1
  if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 III11I1 = clause . count ( "decentralized-pull-xtr-dns-suffix =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "decentralized-pull-xtr-dns-suffix" ] = [ "" ] * III11I1
  if 9 - 9: Ii1I
 III11I1 = clause . count ( "register-reachable-rtrs =" )
 if ( III11I1 != 0 ) :
  I1IiIiiIiIII [ "register-reachable-rtrs" ] = [ "" ] * III11I1
  if 59 - 59: I1IiiI * II111iiii . O0
  if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
  if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
  if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
  if 27 - 27: O0
  if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
  if 28 - 28: i1IIi - iII111i
  if 54 - 54: iII111i - O0 % OOooOOo
  if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
  if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if ( I1IiIiiIiIII == { } ) :
  if ( clause . find ( "lisp rtr-list" ) != - 1 ) :
   III11I1 = clause . count ( "address =" ) + clause . count ( "dns-name =" )
   if ( III11I1 != 0 ) : I1IiIiiIiIII [ "address" ] = [ "" ] * III11I1
   if ( III11I1 != 0 ) : I1IiIiiIiIII [ "dns-name" ] = [ "" ] * III11I1
  else :
   III11I1 = max ( clause . count ( "address =" ) , clause . count ( "dns-name =" ) )
   if ( III11I1 != 0 ) : I1IiIiiIiIII [ "address" ] = [ "" ] * III11I1
   if ( III11I1 != 0 ) : I1IiIiiIiIII [ "dns-name" ] = [ "" ] * III11I1
   III11I1 = clause . count ( "mr-name =" )
   if ( III11I1 != 0 ) : I1IiIiiIiIII [ "mr-name" ] = [ "" ] * III11I1
   III11I1 = clause . count ( "ms-name =" )
   if ( III11I1 != 0 ) : I1IiIiiIiIII [ "ms-name" ] = [ "" ] * III11I1
   if ( III11I1 != 0 ) : I1IiIiiIiIII [ "ms-name" ] = [ "" ] * III11I1
   if 28 - 28: I11i
   if 58 - 58: OoOoOO00
 return ( I1IiIiiIiIII )
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 if 73 - 73: i11iIiiIii - IiII
 if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
 if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
 if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
 if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
def lisp_clause_syntax_error ( kv_pair , parm , clause ) :
 oo000 = ( parm in kv_pair and type ( kv_pair [ parm ] ) == list )
 if ( oo000 ) : return ( False )
 if 32 - 32: i1IIi . Ii1I
 oOO = lisp . bold ( "Syntax error" , False )
 lisp . fprint ( "{}, '{}' not in '{}' clause" . format ( oOO , parm , clause ) )
 return ( True )
 if 54 - 54: I1IiiI / iIii1I11I1II1 / OOooOOo . OOooOOo % iII111i . I1IiiI
 if 10 - 10: o0oOOo0O0Ooo + OOooOOo
 if 27 - 27: OoO0O00 . I11i + OoOoOO00 / iIii1I11I1II1 % iII111i . ooOoO0o
 if 14 - 14: oO0o + I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
def lisp_syntax_check ( kv_pairs , clause ) :
 if 7 - 7: OoooooooOO . IiII
 if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
 if 92 - 92: ooOoO0o
 II11iI111i1 = lisp_setup_kv_pairs ( clause )
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 clause = clause . split ( "\n" )
 iIi1 = ""
 i11iiI1111 = 0
 oOoooo000Oo00 = False
 O0OO0O = 0
 OOoo = ""
 if 69 - 69: I11i
 for O00oO0 in clause :
  if ( len ( O00oO0 ) == 0 ) : continue
  if ( O00oO0 == "" ) : continue
  if ( lisp_comment ( O00oO0 ) ) :
   O00oO0 = O00oO0 . replace ( "#" , "%" )
   iIi1 += lisp_write_line ( O00oO0 )
   continue
   if 97 - 97: I1Ii111 - iIii1I11I1II1
   if 75 - 75: OoooooooOO * IiII
  I1Iiiiiii = O00oO0 . find ( "json-string" ) != - 1
  if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
  if ( lisp_begin_clause ( O00oO0 ) and I1Iiiiiii == False ) :
   iIi1 += lisp_write_line ( O00oO0 )
   i11iiI1111 += 1
   if ( OOoo == O00oO0 ) :
    O0OO0O += 1
   else :
    O0OO0O = 0
    OOoo = O00oO0
    if 69 - 69: O0
   continue
   if 85 - 85: ooOoO0o / O0
  if ( lisp_end_clause ( O00oO0 ) and I1Iiiiiii == False ) :
   i11iiI1111 -= 1
   if ( i11iiI1111 == 0 ) :
    iIi1 += lisp_write_line ( O00oO0 )
    break
    if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
   if ( oOoooo000Oo00 ) :
    iIi1 += "%" + O00oO0 + "\n"
   else :
    iIi1 += lisp_write_line ( O00oO0 )
    if 62 - 62: I1Ii111 . IiII . OoooooooOO
   continue
   if 11 - 11: OOooOOo / I11i
  if ( oOoooo000Oo00 ) :
   iIi1 += "%" + O00oO0 + "\n"
   continue
   if 73 - 73: i1IIi / i11iIiiIii
   if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
   if 85 - 85: OoOoOO00 + OOooOOo
   if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
   if 27 - 27: Ii1I
   if 67 - 67: I1IiiI
  OO00OO0O0 = O00oO0 . split ( "=" , 1 )
  if 48 - 48: I1Ii111
  if ( len ( OO00OO0O0 ) == 1 ) :
   iIi1 += lisp_write_error ( O00oO0 , "no equal sign" )
   oOoooo000Oo00 = True
   continue
   if 72 - 72: iII111i * oO0o % Ii1I . OoooooooOO
   if 99 - 99: iIii1I11I1II1 % ooOoO0o + ooOoO0o + iII111i - I1Ii111 / I1Ii111
  iiiI11 = OO00OO0O0 [ 0 ] . replace ( " " , "" )
  if 63 - 63: OoO0O00 + I1ii11iIi11i . I1Ii111 % I1Ii111
  if 57 - 57: II111iiii
  if 54 - 54: Oo0Ooo + oO0o + i11iIiiIii
  if 28 - 28: oO0o
  if 70 - 70: IiII
  if ( iiiI11 == "description" or iiiI11 == "geo-tag" ) :
   oo00oO0O0 = OO00OO0O0 [ 1 ]
  elif ( iiiI11 == "json-string" ) :
   oo00oO0O0 = OO00OO0O0 [ 1 ] [ 1 : : ]
  else :
   if ( iiiI11 == "eid-prefix" and OO00OO0O0 [ 1 ] . count ( "'" ) == 2 ) :
    oo00oO0O0 = OO00OO0O0 [ 1 ] [ 1 : : ]
   elif ( iiiI11 == "instance-id" ) :
    oo00oO0O0 = OO00OO0O0 [ 1 ] [ 1 : : ]
   else :
    oo00oO0O0 = OO00OO0O0 [ 1 ] . replace ( " " , "" )
    if 34 - 34: I1Ii111 % IiII
    if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
    if 83 - 83: oO0o + OoooooooOO
  iiiI11 = iiiI11 . replace ( "\t" , "" )
  oo00oO0O0 = oo00oO0O0 . replace ( "\t" , "" )
  if 22 - 22: Ii1I % iII111i * OoooooooOO - o0oOOo0O0Ooo / iIii1I11I1II1
  if ( iiiI11 not in kv_pairs ) :
   iIi1 += lisp_write_error ( O00oO0 , "invalid command keyword" )
   oOoooo000Oo00 = True
   continue
   if 86 - 86: OoooooooOO . iII111i % OoOoOO00 / I11i * iII111i / o0oOOo0O0Ooo
   if 64 - 64: i11iIiiIii
   if 38 - 38: IiII / I1IiiI - IiII . I11i
   if 69 - 69: OoooooooOO + I1ii11iIi11i
   if 97 - 97: OOooOOo - OoO0O00 / Ii1I . i11iIiiIii % oO0o * oO0o
   if 1 - 1: I1IiiI % ooOoO0o
   if 65 - 65: I1IiiI + OoOoOO00 / OOooOOo
   if 83 - 83: o0oOOo0O0Ooo . iII111i - Oo0Ooo
  if ( len ( kv_pairs [ iiiI11 ] ) <= 1 ) :
   Ooo0O = ""
   if ( iiiI11 == "eid-prefix" and not lisp_valid_prefix_format ( oo00oO0O0 ) ) :
    Ooo0O = "invalid prefix"
    if 87 - 87: IiII % II111iiii
   if ( iiiI11 == "address" and not lisp . lisp_valid_address_format ( iiiI11 , oo00oO0O0 ) ) :
    if 15 - 15: iII111i * oO0o % OOooOOo - OOooOOo % ooOoO0o
    Ooo0O = "invalid address"
    if 26 - 26: i11iIiiIii + I1ii11iIi11i % OoooooooOO
   if ( Ooo0O != "" ) :
    iIi1 += lisp_write_error ( O00oO0 , Ooo0O )
    oOoooo000Oo00 = True
    continue
    if 73 - 73: Ii1I - I1Ii111
    if 68 - 68: iII111i * OoooooooOO * iIii1I11I1II1 . II111iiii
    if 81 - 81: OOooOOo / O0 + I11i + Ii1I / I1IiiI
    if 27 - 27: OoOoOO00 * IiII
    if 59 - 59: IiII . IiII - II111iiii + IiII . i1IIi . OoO0O00
    if 57 - 57: I1IiiI + Ii1I % oO0o + oO0o / II111iiii . Ii1I
    if 17 - 17: Ii1I + oO0o . OoO0O00 - Oo0Ooo * i11iIiiIii
  if ( len ( kv_pairs [ iiiI11 ] ) == 4 and kv_pairs [ iiiI11 ] [ 3 ] ) :
   if ( iiiI11 == "instance-id" ) :
    iioOo0OoOOo0 = ( oo00oO0O0 . find ( "-" ) != - 1 )
    iII11I1Ii1 = ( oo00oO0O0 == "*" )
    if 92 - 92: I11i / I11i . I1ii11iIi11i
    if ( iioOo0OoOOo0 or iII11I1Ii1 ) :
     oo0 , ii = lisp_validate_range ( oo00oO0O0 )
     if ( ii == - 1 ) :
      iIi1 += lisp_write_error ( O00oO0 , "invalid range" )
      oOoooo000Oo00 = True
      continue
      if 17 - 17: i11iIiiIii - II111iiii * o0oOOo0O0Ooo
    else :
     oo0 = oo00oO0O0
     ii = 32
     if 5 - 5: OOooOOo - OOooOOo . Oo0Ooo + OoOoOO00 - OOooOOo . oO0o
     if 31 - 31: II111iiii - iIii1I11I1II1 - iIii1I11I1II1 % I11i
    oo00oO0O0 = str ( oo0 ) + "-" + str ( ii )
    if 12 - 12: iIii1I11I1II1
    if 20 - 20: o0oOOo0O0Ooo / i1IIi
    if 71 - 71: OoOoOO00 . i1IIi
    if 94 - 94: OOooOOo . I1Ii111
    if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
    if 47 - 47: OoooooooOO
    if 4 - 4: I1IiiI % I11i
    if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
  if ( kv_pairs [ iiiI11 ] [ 0 ] and iiiI11 in II11iI111i1 ) :
   if ( II11iI111i1 [ iiiI11 ] [ O0OO0O ] != "" ) : O0OO0O += 1
   II11iI111i1 [ iiiI11 ] [ O0OO0O ] = oo00oO0O0
  else :
   II11iI111i1 [ iiiI11 ] = oo00oO0O0
   if 82 - 82: ooOoO0o + II111iiii
   if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
   if 68 - 68: Oo0Ooo + i11iIiiIii
   if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
   if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
   if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
   if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
  if ( len ( kv_pairs [ iiiI11 ] ) > 1 ) :
   oOOo = kv_pairs [ iiiI11 ] [ 1 ]
   if ( type ( oOOo ) == int ) :
    if ( type ( oo00oO0O0 ) == str ) : oo00oO0O0 = oo00oO0O0 . split ( "-" ) [ 0 ]
    oo00oO0O0 = int ( oo00oO0O0 )
    if ( oo00oO0O0 < kv_pairs [ iiiI11 ] [ 1 ] and oo00oO0O0 > kv_pairs [ iiiI11 ] [ 2 ] ) :
     iIi1 += lisp_write_error ( O00oO0 , "invalid range value" )
     oOoooo000Oo00 = True
     continue
     if 46 - 46: IiII + iIii1I11I1II1 + OOooOOo + OoO0O00 . I1ii11iIi11i
   elif ( oo00oO0O0 not in kv_pairs [ iiiI11 ] [ 1 : : ] ) :
    iIi1 += lisp_write_error ( O00oO0 , "invalid value keyword" )
    oOoooo000Oo00 = True
    continue
    if 1 - 1: oO0o
    if 62 - 62: i1IIi - OOooOOo
    if 96 - 96: i1IIi . I1ii11iIi11i + oO0o
    if 48 - 48: iIii1I11I1II1 % i1IIi % iII111i + ooOoO0o
    if 30 - 30: i11iIiiIii % iIii1I11I1II1 . I11i % iIii1I11I1II1
    if 62 - 62: Oo0Ooo * OoOoOO00
  iIi1 += lisp_write_line ( O00oO0 )
  if 79 - 79: OoO0O00 . iII111i * Ii1I - OOooOOo + ooOoO0o
  if 14 - 14: i11iIiiIii - iII111i * OoOoOO00
 if ( oOoooo000Oo00 == True ) :
  iIi1 = iIi1 . replace ( "%" , "#" )
 else :
  iIi1 = iIi1 . replace ( "#" , "" )
  iIi1 = iIi1 . replace ( "%" , "#" )
  if 51 - 51: I1ii11iIi11i / iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo * ooOoO0o + I1Ii111
 return ( [ oOoooo000Oo00 , iIi1 , II11iI111i1 ] )
 if 77 - 77: ooOoO0o * OoOoOO00
 if 14 - 14: I11i % I11i / IiII
 if 72 - 72: i1IIi - II111iiii - OOooOOo + OOooOOo * o0oOOo0O0Ooo * OOooOOo
 if 33 - 33: Oo0Ooo
 if 49 - 49: OoO0O00 % iII111i % iII111i / iII111i
 if 53 - 53: iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
def lisp_process_command ( lisp_socket , opcode , clause , process , command_set ) :
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 I111i1I1 = clause . split ( " " )
 if 62 - 62: OOooOOo * I1Ii111 / Oo0Ooo * o0oOOo0O0Ooo
 if 29 - 29: Oo0Ooo % OoO0O00 % IiII . o0oOOo0O0Ooo / OoooooooOO * ooOoO0o
 if 54 - 54: O0
 if 68 - 68: OoO0O00 * o0oOOo0O0Ooo . ooOoO0o % oO0o % I1Ii111
 if ( clause . find ( "lisp debug" ) != - 1 ) :
  if ( clause . find ( "= yes" ) != - 1 ) :
   lisp . lisp_debug_logging = True
   oooo0OO = lisp . bold ( "Enable" , False )
   lisp . lprint ( "{} process debug logging" . format ( oooo0OO ) )
   if 23 - 23: oO0o + OoO0O00
  if ( clause . find ( "= no" ) != - 1 ) :
   III1I1i1 = lisp . bold ( "Disable" , False )
   lisp . lprint ( "{} process debug logging" . format ( III1I1i1 ) )
   lisp . lisp_debug_logging = False
   if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
  return
  if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
  if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
  if 91 - 91: oO0o + OoooooooOO - i1IIi
  if 84 - 84: Ii1I / IiII
  if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
  if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 iiii1I1 = ( I111i1I1 [ 0 ] == "show" )
 if ( iiii1I1 ) :
  IIIiIiI11iIi = clause . split ( "%" )
  I111i1I1 = IIIiIiI11iIi [ 0 ] . split ( " " )
  oo = len ( IIIiIiI11iIi )
  if ( oo == 2 ) :
   IIIiIiI11iIi = IIIiIiI11iIi [ 1 ]
  elif ( oo == 3 ) :
   IIIiIiI11iIi = IIIiIiI11iIi [ 1 ] + "%" + IIIiIiI11iIi [ 2 ] + "%"
  else :
   IIIiIiI11iIi = ""
   if 51 - 51: I1ii11iIi11i
   if 41 - 41: I1ii11iIi11i * ooOoO0o - Ii1I + Oo0Ooo
 I111i1I1 = I111i1I1 [ 0 ] + " " + I111i1I1 [ 1 ]
 if 23 - 23: II111iiii % o0oOOo0O0Ooo + o0oOOo0O0Ooo + iII111i - iII111i
 for oOo0O00O in command_set :
  if ( I111i1I1 in oOo0O00O ) :
   iiIii1I , I1IiIiiIiIII = oOo0O00O [ I111i1I1 ]
   break
   if 47 - 47: ooOoO0o . I11i / o0oOOo0O0Ooo
  if ( oOo0O00O == command_set [ - 1 ] ) :
   lisp . lprint ( "Invalid command found '{}'" . format ( I111i1I1 ) )
   return
   if 83 - 83: o0oOOo0O0Ooo / OOooOOo / OOooOOo + o0oOOo0O0Ooo * I1Ii111 + o0oOOo0O0Ooo
   if 36 - 36: OoOoOO00 + o0oOOo0O0Ooo - OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
   if 72 - 72: i1IIi
   if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
   if 63 - 63: I1ii11iIi11i
   if 6 - 6: ooOoO0o / I1ii11iIi11i
   if 57 - 57: I11i
   if 67 - 67: OoO0O00 . ooOoO0o
   if 87 - 87: oO0o % Ii1I
   if 83 - 83: II111iiii - I11i
 oOoooo000Oo00 = False
 if ( len ( I1IiIiiIiIII ) != 0 ) :
  oOoooo000Oo00 , iIi1 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
  if ( oOoooo000Oo00 ) :
   lisp . lprint ( "Command syntax error: {}" . format ( iIi1 ) )
  else :
   iiIii1I ( I1IiIiiIiIII )
   if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
 else :
  if ( iiii1I1 ) : I1IiIiiIiIII = IIIiIiI11iIi
  iIi1 = iiIii1I ( I1IiIiiIiIII )
  if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
  if 51 - 51: OoOoOO00
 I11IIIiIi11 = lisp . lisp_command_ipc ( iIi1 , process )
 lisp . lisp_ipc ( I11IIIiIi11 , lisp_socket , "lisp-core" )
 return
 if 39 - 39: Ii1I % O0 % OoOoOO00 . i1IIi
 if 86 - 86: OoO0O00 * OoooooooOO
 if 71 - 71: iIii1I11I1II1 - OOooOOo . I1IiiI % OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
def lisp_is_user_superuser ( username ) :
 if ( username == None ) : username = lisp_get_user ( )
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 oOO0oo = getoutput ( "egrep -A 4 user-account ./lisp.config" )
 if 29 - 29: I1IiiI * II111iiii * OoooooooOO - I1ii11iIi11i * II111iiii
 iiO00O00O000OOO = "username = {}" . format ( username )
 O0OO0O = oOO0oo . find ( iiO00O00O000OOO )
 o0o0O0O00oOOo = oOO0oo [ O0OO0O : : ] . find ( "}" )
 if ( O0OO0O == - 1 or o0o0O0O00oOOo == - 1 ) : return ( False )
 if 3 - 3: O0
 Ooo0Oo0oo0 = oOO0oo [ O0OO0O : O0OO0O + o0o0O0O00oOOo ] . find ( "super-user = yes" )
 return ( Ooo0Oo0oo0 != - 1 )
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
def lisp_find_user_account ( username , password ) :
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
 oOO0oo = getoutput ( "egrep -A 4 user-account ./lisp.config" )
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
 if 57 - 57: O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 O0OO0O = oOO0oo . find ( "username = {}\n" . format ( username ) )
 if ( O0OO0O == - 1 ) : return ( False )
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 oOO0oo = oOO0oo [ O0OO0O : : ]
 oOO0oo = oOO0oo . replace ( "\t" , "" )
 oOO0oo = oOO0oo . replace ( " " , "" )
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 O0OO0O = oOO0oo . find ( "password=" )
 if ( O0OO0O == - 1 ) : return ( False )
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 oOO0oo = oOO0oo [ O0OO0O : : ]
 o0o0O0O00oOOo = oOO0oo . find ( "\n" )
 if ( o0o0O0O00oOOo == - 1 ) : return ( False )
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
 if 54 - 54: II111iiii . I11i
 if 73 - 73: OoOoOO00 . I1IiiI
 if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
 if 48 - 48: iII111i * iII111i
 if 13 - 13: Ii1I / I11i + OoOoOO00 . o0oOOo0O0Ooo % ooOoO0o
 IiIi1 = oOO0oo [ : o0o0O0O00oOOo ] . split ( "=" )
 if ( len ( IiIi1 ) < 2 ) : return ( False )
 if ( IiIi1 [ 1 ] == "" ) :
  if ( len ( IiIi1 ) < 3 ) : return ( False )
  oO0oOo0 = lisp_hash_password ( password )
  if ( IiIi1 [ 2 ] != oO0oOo0 ) : return ( False )
 else :
  if ( IiIi1 [ 1 ] != password ) : return ( False )
  if 53 - 53: OoooooooOO - IiII
  if 87 - 87: oO0o . I1IiiI
  if 17 - 17: Ii1I . i11iIiiIii
  if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
  if 63 - 63: oO0o
  if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 return ( True )
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if 7 - 7: II111iiii
 if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
 if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
def lisp_validate_user ( ) :
 O0oOOo0o = bottle . request . forms . get ( 'username' )
 if 50 - 50: iII111i . I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
 if ( O0oOOo0o == None ) :
  i1i1IiIiIi1Ii = bottle . request . get_cookie ( "lisp-login" )
  if ( i1i1IiIiIi1Ii ) : return ( True )
  if 64 - 64: OOooOOo + OoooooooOO * OoooooooOO
  if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
 o0O0OO = bottle . request . forms . get ( 'password' )
 if ( O0oOOo0o == None or o0O0OO == None ) : return ( False )
 if 22 - 22: II111iiii * OoO0O00 * I11i + I1ii11iIi11i * o0oOOo0O0Ooo
 if ( lisp_find_user_account ( O0oOOo0o , o0O0OO ) == False ) : return ( False )
 if 100 - 100: i1IIi / IiII
 if 3 - 3: II111iiii % I1ii11iIi11i - OoooooooOO * Oo0Ooo . iIii1I11I1II1
 if 37 - 37: iII111i / Oo0Ooo . I11i * I11i
 if 80 - 80: OOooOOo % I1ii11iIi11i
 O0Ooo = None if os . getenv ( "LISP_NO_USER_TIMEOUT" ) == "" else LISP_USER_TIMEOUT
 if 78 - 78: OoO0O00 % IiII * i1IIi
 bottle . response . set_cookie ( "lisp-login" , O0oOOo0o , max_age = O0Ooo )
 return ( True )
 if 66 - 66: Ii1I . I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1
 if 51 - 51: I11i . Oo0Ooo
 if 45 - 45: i1IIi - Oo0Ooo / O0 . I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
def lisp_get_user ( ) :
 O0oOOo0o = bottle . request . forms . get ( 'username' )
 if ( O0oOOo0o ) : return ( O0oOOo0o )
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 return ( bottle . request . get_cookie ( "lisp-login" ) )
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
def lisp_login_page ( ) :
 I1i1iii = '''
        <center><br><br>
        <form action="/lisp/login" method="post">
        <font size="3"><i>
        Username:<input type="text" name="username" />
        {}Password:<input type="password" name="password" />
        {}<input style="background-color:transparent;border-radius:10px;" type="submit" value="Login" />
        </i></font></form>
        </center>
    ''' . format ( lisp . lisp_space ( 4 ) , lisp . lisp_space ( 2 ) )
 return ( lisp_banner_top ( True ) + I1i1iii + "<br><hr>" )
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 if 66 - 66: Oo0Ooo
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 if 55 - 55: o0oOOo0O0Ooo . iII111i
 if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
 if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
 if 89 - 89: OoO0O00 + IiII * I1Ii111
 if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
def lisp_is_any_xtr_logging_on ( log_type ) :
 I111i1I1 = "egrep '" + log_type + " = '" + " ./lisp.config"
 I111i1I1 = getoutput ( I111i1I1 )
 if ( I111i1I1 == "" ) : return ( False )
 if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 I111i1I1 = I111i1I1 . split ( "\n" )
 for OO0o0OO0 in I111i1I1 :
  OooOo0OOO = OO0o0OO0 . find ( "    {} = " . format ( log_type ) ) != - 1
  if ( OO0o0OO0 [ 0 ] == " " and OooOo0OOO ) :
   I111i1I1 = OO0o0OO0 . replace ( " " , "" )
   I111i1I1 = I111i1I1 . split ( "=" )
   if ( I111i1I1 [ 1 ] == "yes" ) : return ( True )
   if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
   if 70 - 70: OoO0O00
 return ( False )
 if 46 - 46: I11i - i1IIi
 if 46 - 46: I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
def lisp_landing_page ( ) :
 ooOoOO = lisp . green ( "yes" , True )
 Oo = lisp . red ( "no" , True )
 if 66 - 66: IiII
 O0oOo = ooOoOO if lisp . lisp_is_running ( "lisp-itr" ) else Oo
 OO0oOO0ooO = ooOoOO if lisp . lisp_is_running ( "lisp-etr" ) else Oo
 iIii1iI = ooOoOO if lisp . lisp_is_running ( "lisp-rtr" ) else Oo
 Oo0O0O000 = ooOoOO if lisp . lisp_is_running ( "lisp-mr" ) else Oo
 II1Ii = ooOoOO if lisp . lisp_is_running ( "lisp-ms" ) else Oo
 OOoO00ooO = ooOoOO if lisp . lisp_is_running ( "lisp-ddt" ) else Oo
 if 12 - 12: ooOoO0o % I1IiiI + oO0o - i1IIi . Ii1I / I1IiiI
 I1i1iii = '''
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
    ''' . format ( O0oOo , iIii1iI , OO0oOO0ooO , Oo0O0O000 , OOoO00ooO , II1Ii )
 if 51 - 51: OOooOOo . I1IiiI
 I1i1iii += '''
        <center>
        <style type="text/css">
        form { display:inline }
        </style>

        <a href="/lisp/show/status">
        <button style="background-color:transparent;border-radius:10px;
        type="button">system status</button></a>
    '''
 if 73 - 73: OoooooooOO . I1IiiI / I1Ii111 % Ii1I
 o0OO0O00o = lisp_get_clause_for_api ( "lisp debug" ) [ 0 ]
 o0OO0O00o = o0OO0O00o [ "lisp debug" ] if ( "lisp debug" in o0OO0O00o ) else None
 oo000O0o = "lisp xtr-parameters"
 I1III111i = lisp_get_clause_for_api ( oo000O0o ) [ 0 ]
 iiI1iii = False
 if ( oo000O0o in I1III111i ) :
  OOoOOo00O0o0 = { "data-plane-logging" : "yes" }
  Oo0O0Oo00O = { "flow-logging" : "yes" }
  iiI1iii = ( OOoOOo00O0o0 in I1III111i [ oo000O0o ] or Oo0O0Oo00O in I1III111i [ oo000O0o ] )
  if 9 - 9: o0oOOo0O0Ooo . I1IiiI - I1ii11iIi11i
  if 32 - 32: OoooooooOO / I1IiiI / iIii1I11I1II1 + II111iiii . oO0o . o0oOOo0O0Ooo
 ii1ii = { }
 for IIiI1i in o0OO0O00o : ii1ii [ list ( IIiI1i . keys ( ) ) [ 0 ] ] = list ( IIiI1i . values ( ) ) [ 0 ]
 o0OO0O00o = ii1ii
 o0OO0O00o [ "ddt" ] = o0OO0O00o [ "ddt-node" ]
 o0OO0O00o [ "mr" ] = o0OO0O00o [ "map-resolver" ]
 o0OO0O00o [ "ms" ] = o0OO0O00o [ "map-server" ]
 if 6 - 6: I1ii11iIi11i / iII111i - OOooOOo
 if 62 - 62: I11i % OOooOOo
 if 54 - 54: OoOoOO00 % iII111i . OoOoOO00 * OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 III11I1 = getoutput ( "wc -l logs/lisp-core.log" )
 III11I1 = III11I1 . replace ( " " , "" )
 III11I1 = III11I1 . split ( "logs" ) [ 0 ]
 iIii11iI1II = "on" if o0OO0O00o [ "core" ] == "yes" else "off"
 I1i1iii += '''
        <form>
        <select size="1" style="width: 110px"
                onchange="parent.window.location=this.value">
        <option value="">show logging:</option>
        <option value="/lisp/show/log/lisp-core/100">[{}] core log [{}]
        </option>''' . format ( iIii11iI1II , III11I1 )
 if 42 - 42: ooOoO0o - I1IiiI + I1ii11iIi11i % Ii1I
 if ( os . path . exists ( "./logs/lisp-itr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-itr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIii11iI1II = "on" if o0OO0O00o [ "itr" ] == "yes" else "off"
  I1i1iii += '''
            <option value="/lisp/show/log/lisp-itr/100">[{}] ITR log [{}]
            </option>''' . format ( iIii11iI1II , III11I1 )
  if 44 - 44: i1IIi - O0 - I1ii11iIi11i * I1ii11iIi11i + OoOoOO00
 if ( os . path . exists ( "./logs/lisp-rtr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-rtr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIii11iI1II = "on" if o0OO0O00o [ "rtr" ] == "yes" else "off"
  I1i1iii += '''<option value="/lisp/show/log/lisp-rtr/100">[{}] RTR
           log [{}]</option>''' . format ( iIii11iI1II , III11I1 )
  if 56 - 56: ooOoO0o / iIii1I11I1II1 . Ii1I % OoOoOO00 + OOooOOo
 if ( os . path . exists ( "./logs/lisp-etr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-etr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIii11iI1II = "on" if o0OO0O00o [ "etr" ] == "yes" else "off"
  I1i1iii += '''<option value="/lisp/show/log/lisp-etr/100">[{}] ETR
            log [{}]</option>''' . format ( iIii11iI1II , III11I1 )
  if 10 - 10: I1Ii111 * i11iIiiIii - iIii1I11I1II1 . Oo0Ooo - I1ii11iIi11i
 if ( os . path . exists ( "./logs/lisp-xtr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-xtr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIii11iI1II = "on" if o0OO0O00o [ "itr" ] == "yes" or o0OO0O00o [ "etr" ] == "yes" or o0OO0O00o [ "rtr" ] == "yes" else "off"
  if 20 - 20: I1ii11iIi11i / I1IiiI * OoO0O00 * I1IiiI * O0
  I1i1iii += '''<option value="/lisp/show/log/lisp-xtr/100">[{}] XTR
           log [{}]</option>''' . format ( iIii11iI1II , III11I1 )
  if 1 - 1: iIii1I11I1II1 + Oo0Ooo / O0 - iII111i % IiII + IiII
 if ( os . path . exists ( "./logs/lisp-mr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-mr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIii11iI1II = "on" if o0OO0O00o [ "mr" ] == "yes" else "off"
  I1i1iii += '''<option value="/lisp/show/log/lisp-mr/100">[{}] MR
            log [{}] </option>''' . format ( iIii11iI1II , III11I1 )
  if 24 - 24: I1IiiI + Oo0Ooo + OOooOOo - OoooooooOO + Oo0Ooo
 if ( os . path . exists ( "./logs/lisp-ddt.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-ddt.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIii11iI1II = "on" if o0OO0O00o [ "ddt" ] == "yes" else "off"
  I1i1iii += '''<option value="/lisp/show/log/lisp-ddt/100">[{}] DDT
            log [{}]</option>''' . format ( iIii11iI1II , III11I1 )
  if 93 - 93: ooOoO0o . iIii1I11I1II1 % i11iIiiIii . OoOoOO00 % ooOoO0o + O0
 if ( os . path . exists ( "./logs/lisp-ms.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-ms.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIii11iI1II = "on" if o0OO0O00o [ "ms" ] == "yes" else "off"
  I1i1iii += '''<option value="/lisp/show/log/lisp-ms/100">[{}] MS
            log [{}]</option>''' . format ( iIii11iI1II , III11I1 )
  if 65 - 65: Ii1I + OoO0O00 - OoooooooOO
 OOoOO0o = lisp_is_any_xtr_logging_on ( "flow-logging" )
 if ( os . path . exists ( "./logs/lisp-flow.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-flow.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIii11iI1II = "on" if OOoOO0o else "off"
  I1i1iii += '''<option value="/lisp/show/log/lisp-flow/100">[{}] flow
            log [{}]</option>''' . format ( iIii11iI1II , III11I1 )
  if 51 - 51: Oo0Ooo - I1ii11iIi11i * I11i
 I1i1iii += "</select></form>"
 if 12 - 12: iIii1I11I1II1 % ooOoO0o % ooOoO0o
 if 78 - 78: IiII . OoOoOO00 . I11i
 if 97 - 97: oO0o
 if 80 - 80: I1IiiI . Ii1I
 Ooo0Oo0oo0 = lisp_is_user_superuser ( None )
 if ( Ooo0Oo0oo0 ) :
  I1i1iii += '''
            <form>
            <select size="1" style="width: 120px"
                    onchange="parent.window.location=this.value">
            <option value="">manage logging:</option>
        '''
  if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
  if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
  if 29 - 29: o0oOOo0O0Ooo
  if 86 - 86: II111iiii . IiII
  if 2 - 2: OoooooooOO
  if ( "yes" in list ( o0OO0O00o . values ( ) ) or iiI1iii ) :
   I1i1iii += '''<option value="/lisp/debug/{}%{}">disable all logging
                </option>''' . format ( "disable" , "all" )
   if 60 - 60: OoO0O00
   if 81 - 81: OoOoOO00 % Ii1I
  oo0i1iIIi1II1iiI = False
  III1Ii1i1I1 = False
  for O0O00OooO in o0OO0O00o :
   if ( lisp . lisp_is_running ( "lisp-" + O0O00OooO ) == False ) : continue
   if 40 - 40: I11i % OoooooooOO - OOooOOo + o0oOOo0O0Ooo / OOooOOo
   if ( O0O00OooO in [ "itr" , "etr" , "rtr" ] ) :
    oo0i1iIIi1II1iiI = True
    III1Ii1i1I1 = True
    if 84 - 84: O0
    if 11 - 11: II111iiii / i11iIiiIii / O0
   O0O0o0oO0O00 = o0OO0O00o [ O0O00OooO ]
   o00oO0oOo00 = O0O00OooO
   if ( o00oO0oOo00 == "mr" ) : o00oO0oOo00 = "map-resolver"
   if ( o00oO0oOo00 == "ms" ) : o00oO0oOo00 = "map-server"
   if ( o00oO0oOo00 == "ddt" ) : o00oO0oOo00 = "ddt-node"
   if 70 - 70: I1Ii111 + oO0o
   I1i1iii += '''<option value="/lisp/debug/{}%{}">{} {} logging
                </option>''' . format ( o00oO0oOo00 , "yes" if O0O0o0oO0O00 == "no" else "no" ,
 "enable" if O0O0o0oO0O00 == "no" else "disable" ,
 O0O00OooO . upper ( ) if O0O00OooO != "core" else "core" )
   if 93 - 93: I1Ii111 + Ii1I
  if ( oo0i1iIIi1II1iiI ) :
   i1 = lisp_is_any_xtr_logging_on ( "data-plane-logging" )
   I1i1iii += '''<option value="/lisp/debug/data-plane-logging%{}">{}
                data-plane logging </option>''' . format ( "yes" if i1 == False else "no" ,
   # O0 / II111iiii * OoO0O00
 "enable" if i1 == False else "disable" )
   if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
  if ( III1Ii1i1I1 ) :
   i1 = OOoOO0o
   I1i1iii += '''<option value="/lisp/debug/flow-logging%{}">{}
                flow logging </option>''' . format (
 "yes" if i1 == False else "no" ,
 "enable" if i1 == False else "disable" )
   if 58 - 58: IiII + iIii1I11I1II1
  I1i1iii += "</select></form>"
  if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
  if 79 - 79: ooOoO0o . OoOoOO00 % I1Ii111 - Oo0Ooo
 I1i1iii += "<br><br>"
 if 69 - 69: ooOoO0o - o0oOOo0O0Ooo . ooOoO0o
 if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
 if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
 Ii = lisp . lisp_button ( "{}:<br>show map-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-itr" ) ) :
  Ii = '<a href="/lisp/show/itr/map-cache">' + Ii + '</a>'
  Ii = Ii . format ( lisp . green ( "ITR" , True ) )
 else :
  Ii = Ii . format ( lisp . red ( "ITR" , True ) )
  Ii = lisp . lisp_span ( Ii , "ITR not running" )
  if 79 - 79: iIii1I11I1II1
  if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
 I1 = lisp . lisp_button ( "{}:<br>show map-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-rtr" ) ) :
  I1 = '<a href="/lisp/show/rtr/map-cache">' + I1 + '</a>'
  I1 = I1 . format ( lisp . green ( "RTR" , True ) )
 else :
  I1 = I1 . format ( lisp . red ( "RTR" , True ) )
  I1 = lisp . lisp_span ( I1 , "RTR not running" )
  if 14 - 14: I1IiiI . Ii1I
  if 46 - 46: iII111i - iIii1I11I1II1
 I1I1 = lisp . lisp_button ( "{}:<br>show referral-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-mr" ) ) :
  I1I1 = '<a href="/lisp/show/referral">' + I1I1 + '</a>'
  I1I1 = I1I1 . format ( lisp . green ( "MR" , True ) )
 else :
  I1I1 = I1I1 . format ( lisp . red ( "MR" , True ) )
  I1I1 = lisp . lisp_span ( I1I1 , "MR not running" )
  if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
  if 13 - 13: OoO0O00
 O0oo0O0 = lisp . lisp_button ( "{}:<br>show delegations" , None )
 if ( lisp . lisp_is_running ( "lisp-ddt" ) ) :
  O0oo0O0 = '<a href="/lisp/show/delegations">' + O0oo0O0 + '</a>'
  O0oo0O0 = O0oo0O0 . format ( lisp . green ( "DDT" , True ) )
 else :
  O0oo0O0 = O0oo0O0 . format ( lisp . red ( "DDT" , True ) )
  O0oo0O0 = lisp . lisp_span ( O0oo0O0 , "DDT not running" )
  if 2 - 2: OoooooooOO . OOooOOo . IiII
  if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 iI1IiiiIiI1Ii = lisp . lisp_button ( "{}:<br>show site-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-ms" ) ) :
  iI1IiiiIiI1Ii = '<a href="/lisp/show/site">' + iI1IiiiIiI1Ii + '</a>'
  iI1IiiiIiI1Ii = iI1IiiiIiI1Ii . format ( lisp . green ( "MS" , True ) )
 else :
  iI1IiiiIiI1Ii = iI1IiiiIiI1Ii . format ( lisp . red ( "MS" , True ) )
  iI1IiiiIiI1Ii = lisp . lisp_span ( iI1IiiiIiI1Ii , "MS not running" )
  if 78 - 78: OoooooooOO / OOooOOo % OoOoOO00 * OoooooooOO
  if 68 - 68: oO0o
 i11i11 = lisp . lisp_button ( "{}:<br>show database-mappings" , None )
 if ( lisp . lisp_is_running ( "lisp-etr" ) ) :
  i11i11 = '<a href="/lisp/show/database">' + i11i11 + '</a>'
  i11i11 = i11i11 . format ( lisp . green ( "ETR" , True ) )
 else :
  i11i11 = i11i11 . format ( lisp . red ( "ETR" , True ) )
  i11i11 = lisp . lisp_span ( i11i11 , "ETR not running" )
  if 18 - 18: iIii1I11I1II1 + I11i * I1IiiI - OOooOOo / I1IiiI
  if 78 - 78: I11i . IiII
 iI1i1II = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 I1ii1ii1I = lisp . lisp_geo_help_hover ( '<input type="text" name="geo-point" size="30" required />' )
 if 18 - 18: oO0o * oO0o % oO0o
 Ii1I1I1i11ii = lisp . lisp_geo_help_hover ( '<input type="text" name="geo-prefix" size="30" required />' )
 if 58 - 58: iIii1I11I1II1 - i11iIiiIii - i11iIiiIii * Ii1I + o0oOOo0O0Ooo . OoOoOO00
 if 80 - 80: i1IIi + i11iIiiIii - I1Ii111 % II111iiii . oO0o
 i111i = lisp . lisp_button ( "API Documentation" , "/lisp/show/api-doc" )
 II1III1i1iiI = lisp . lisp_button ( "Command Documentation" , "/lisp/show/command-doc" )
 I11i11i1 = lisp . lisp_button ( "IETF LISP WG Drafts" ,
 "http://datatracker.ietf.org/wg/lisp/" )
 OOO = lisp . lisp_button ( "LISP Facebook Group" ,
 "https://www.facebook.com/groups/407716795982512" )
 ii1i1iiI = lisp . lisp_button ( "LISP LinkedIn Group" ,
 "http://www.linkedin.com/groups/3776183" )
 if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 iIIi11 = lisp . lisp_space ( 2 )
 I1i1iii += '''
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

    ''' . format ( iIIi11 , Ii , iIIi11 , I1 , iIIi11 , i11i11 , iIIi11 , iIIi11 , I1I1 , iIIi11 , O0oo0O0 , iIIi11 , iI1IiiiIiI1Ii , iIIi11 , iI1i1II ,
 iI1i1II , I1ii1ii1I , Ii1I1I1i11ii , i111i , II1III1i1iiI , "<br><br>" , I11i11i1 , OOO , ii1i1iiI )
 if 54 - 54: Ii1I - I1Ii111
 return ( lisp_show_wrapper ( I1i1iii ) )
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
  iIiiIIi1iiII , oooO00Oo , ooO00o , I1i1iii = lisp . lisp_receive ( lisp_socket , True )
  lisp . lisp_ipc_lock . release ( )
  if 73 - 73: iII111i * iII111i / ooOoO0o
  if ( oooO00Oo != process ) :
   lisp . lprint ( "Discarding IPC message from {}" . format ( oooO00Oo ) )
  elif ( iii11i1 == None ) :
   iii11i1 = I1i1iii
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
 O0O00OooO = lisp_commands [ i1i11ii1Ii ]
 O0O00OooO = O0O00OooO [ 0 ]
 if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 if ( lisp . lisp_is_running ( O0O00OooO ) == False ) :
  I1i1iii = ( "<i>Process '{}' is not running, command cannot be " + "executed</i><br>" ) . format ( O0O00OooO )
  if 22 - 22: ooOoO0o . iIii1I11I1II1
  return ( lisp_show_wrapper ( I1i1iii ) )
  if 12 - 12: Ii1I
  if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 I11IIIiIi11 = lisp . lisp_command_ipc ( command , "lisp-core" )
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 lisp . lisp_ipc_lock . acquire ( )
 if 77 - 77: II111iiii
 lisp . lisp_ipc ( I11IIIiIi11 , lisp_socket , O0O00OooO )
 lisp . lprint ( "Waiting for response to show command '{}'" . format ( command ) )
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 iIiiIIi1iiII , oooO00Oo , ooO00o , I1i1iii = lisp . lisp_receive ( lisp_socket , True )
 I1i1iii = I1i1iii . decode ( )
 if 68 - 68: oO0o
 lisp . lisp_ipc_lock . release ( )
 if 10 - 10: Ii1I
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if ( oooO00Oo == "" ) :
  lisp . lprint ( "Command '{}' timed out to {}" . format ( command , O0O00OooO ) )
 elif ( oooO00Oo != O0O00OooO ) :
  lisp . lprint ( "Received response from {} but expecting from {}" . format ( oooO00Oo , O0O00OooO ) )
  if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
  I1i1iii = lisp_drain_socket ( lisp_socket , O0O00OooO )
  if ( I1i1iii == None ) : I1i1iii = "<i>Fatal error, retry later</i><br>"
  if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 return ( lisp_show_wrapper ( I1i1iii ) )
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
 oO0OIiii1I = "./logs/" + process + ".log"
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if ( lisp . lisp_is_python2 ( ) ) :
  oO0O = "python2 -O "
  O00O = process + ".pyo"
 elif ( lisp . lisp_is_python3 ( ) ) :
  oO0O = "python3.8 -O "
  O00O = process + ".pyc"
 else :
  lisp . lprint ( "Cannot manage process '{}', unsupported python version" . format ( process ) )
  if 2 - 2: oO0o . I1Ii111 * Oo0Ooo + O0 - I11i * iIii1I11I1II1
  if 12 - 12: o0oOOo0O0Ooo * I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
  if 81 - 81: Oo0Ooo - I11i
 if ( lisp . lisp_is_ubuntu ( ) or lisp . lisp_is_raspbian ( ) or lisp . lisp_is_debian ( ) or lisp . lisp_is_debian_kali ( ) ) :
  if 24 - 24: OoooooooOO . OoO0O00 * II111iiii
  o0oO00 = oO0O + O00O + " 2>&1 > " + oO0OIiii1I + " &"
 else :
  o0oO00 = oO0O + O00O + " >& " + oO0OIiii1I + " &"
  if 88 - 88: I11i + i11iIiiIii % oO0o * OOooOOo * OOooOOo * Ii1I
  if 24 - 24: ooOoO0o / iII111i + IiII . IiII
 I1ii1i = getoutput ( "date" )
 if ( startstop and os . path . exists ( O00O ) ) :
  lisp . lprint ( "Start process '{}' on {}" . format ( process , I1ii1i ) )
  os . system ( o0oO00 )
  time . sleep ( 1 )
  return
  if 22 - 22: oO0o * Ii1I * i11iIiiIii + iII111i * OoOoOO00 * OoO0O00
  if 85 - 85: iII111i * OOooOOo % Oo0Ooo - iII111i - I11i
 if ( startstop == False and os . path . exists ( O00O ) ) :
  lisp . lprint ( "Stop process '{}' on {}" . format ( process , I1ii1i ) )
  iI = getoutput ( "pgrep -f " + O00O )
  iI = iI . split ( "\n" ) [ 0 ]
  os . system ( "kill " + iI )
  os . system ( "rm " + process )
  return
  if 64 - 64: OoO0O00 . I1IiiI - OoooooooOO . ooOoO0o - iII111i
 return
 if 77 - 77: Ii1I % OoOoOO00 / II111iiii % iII111i % OoooooooOO % OoO0O00
 if 19 - 19: IiII * I1Ii111 / oO0o * I1Ii111 - OoooooooOO * I11i
 if 17 - 17: II111iiii + Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
def lisp_enable_command ( clause ) :
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if ( os . path . exists ( "lisp.py" ) and os . path . exists ( "lisp.pyo" ) == False ) :
  lisp . lprint ( "In manual mode, ignoring 'lisp enable' command" )
  return ( clause )
  if 71 - 71: I1Ii111 * Oo0Ooo . I11i
  if 49 - 49: IiII * O0 . IiII
 I111i1I1 = clause . split ( " " )
 I111i1I1 = I111i1I1 [ 0 ] + " " + I111i1I1 [ 1 ]
 if 19 - 19: II111iiii - IiII
 I1IiIiiIiIII = lisp_core_commands [ "lisp enable" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
 if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
 oOoooo000Oo00 , iIi1 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 96 - 96: OoooooooOO + IiII * O0
 if 86 - 86: Ii1I
 if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 if ( oOoooo000Oo00 == True ) : return ( iIi1 )
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 oOOoO0O = { "itr" : "lisp-itr" , "etr" : "lisp-etr" , "rtr" : "lisp-rtr" ,
 "map-resolver" : "lisp-mr" , "map-server" : "lisp-ms" ,
 "ddt-node" : "lisp-ddt" }
 if 15 - 15: I1Ii111
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 for O00oo in list ( oOOoO0O . keys ( ) ) :
  OoOoooO000OO = True if I1IiIiiIiIII [ O00oo ] == "yes" else False
  lisp_start_stop_process ( oOOoO0O [ O00oo ] , OoOoooO000OO )
  if 62 - 62: OOooOOo + Oo0Ooo % iIii1I11I1II1 / iIii1I11I1II1 . ooOoO0o . IiII
 return ( iIi1 )
 if 21 - 21: OoO0O00 - Ii1I - I1IiiI / OoOoOO00
 if 48 - 48: OoooooooOO
 if 16 - 16: OoOoOO00 * I1ii11iIi11i * I1ii11iIi11i / O0 * i11iIiiIii
 if 64 - 64: iII111i * I1ii11iIi11i % II111iiii - OoOoOO00 + I1ii11iIi11i
 if 62 - 62: OoOoOO00 % o0oOOo0O0Ooo % I1IiiI + IiII . OoO0O00
 if 48 - 48: I1IiiI * i11iIiiIii % II111iiii
 if 20 - 20: i1IIi / I1IiiI * oO0o
def lisp_debug_command ( lisp_socket , clause , single_process ) :
 I111i1I1 = clause . split ( " " )
 I111i1I1 = I111i1I1 [ 0 ] + " " + I111i1I1 [ 1 ]
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 I1IiIiiIiIII = lisp_core_commands [ "lisp debug" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 oOoooo000Oo00 , iIi1 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if ( oOoooo000Oo00 == True ) : return ( iIi1 )
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 oOOoO0O = { "itr" : "lisp-itr" , "etr" : "lisp-etr" , "rtr" : "lisp-rtr" ,
 "map-resolver" : "lisp-mr" , "map-server" : "lisp-ms" ,
 "ddt-node" : "lisp-ddt" , "core" : "" }
 if 43 - 43: OoO0O00 % OoO0O00
 for IIiii11ii1i in I1IiIiiIiIII :
  O0O00OooO = oOOoO0O [ IIiii11ii1i ]
  if ( single_process and single_process != O0O00OooO ) : continue
  if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
  O0O0o0oO0O00 = I1IiIiiIiIII [ IIiii11ii1i ]
  I111i1I1 = ( "lisp debug {\n" + "    {} = {}\n" . format ( IIiii11ii1i , O0O0o0oO0O00 ) + "}\n" )
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
  if 45 - 45: Ii1I - OOooOOo
  if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
  if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
  if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
  if ( IIiii11ii1i == "core" ) :
   lisp_process_command ( None , None , I111i1I1 , None , [ None ] )
   continue
   if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
   if 36 - 36: I11i % OOooOOo
  I111i1I1 = lisp . lisp_command_ipc ( I111i1I1 , "lisp-core" )
  lisp . lisp_ipc ( I111i1I1 , lisp_socket , O0O00OooO )
  if ( single_process ) : break
  if 72 - 72: I1IiiI / iII111i - O0 + I11i
 return ( iIi1 )
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
def lisp_replace_password_in_clause ( clause , keyword_string ) :
 O0OO0O = clause . find ( keyword_string )
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if ( O0OO0O == - 1 ) : return ( clause )
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 if 24 - 24: ooOoO0o - I11i * oO0o
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 O0OO0O += len ( keyword_string )
 o0o0O0O00oOOo = clause [ O0OO0O : : ] . find ( "\n" )
 o0o0O0O00oOOo += O0OO0O
 o0O0OO = clause [ O0OO0O : o0o0O0O00oOOo ] . replace ( " " , "" )
 if 79 - 79: IiII % OoO0O00
 if ( len ( o0O0OO ) != 0 and o0O0OO [ 0 ] == "=" ) : return ( clause )
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 o0O0OO = o0O0OO . replace ( " " , "" )
 o0O0OO = o0O0OO . replace ( "\t" , "" )
 o0O0OO = lisp_hash_password ( o0O0OO )
 clause = clause [ 0 : O0OO0O ] + " =" + o0O0OO + clause [ o0o0O0O00oOOo : : ]
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 return ( clause )
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
def lisp_user_account_command ( clause ) :
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 I111i1I1 = clause . split ( " " )
 I111i1I1 = I111i1I1 [ 0 ] + " " + I111i1I1 [ 1 ]
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 I1IiIiiIiIII = lisp_core_commands [ "lisp user-account" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 oOoooo000Oo00 , iIi1 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 if ( oOoooo000Oo00 == False ) :
  iIi1 = lisp_replace_password_in_clause ( iIi1 , "password =" )
  if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 return ( iIi1 )
 if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
 if 12 - 12: I1ii11iIi11i / Ii1I
 if 5 - 5: OoooooooOO
 if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
def lisp_rtr_list_command ( clause ) :
 I111i1I1 = clause . split ( " " )
 I111i1I1 = I111i1I1 [ 0 ] + " " + I111i1I1 [ 1 ]
 if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
 I1IiIiiIiIII = lisp_core_commands [ "lisp rtr-list" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 93 - 93: Oo0Ooo / I1ii11iIi11i + i1IIi * oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 oOoooo000Oo00 , iIi1 , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 if ( oOoooo000Oo00 ) : return ( iIi1 )
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 lisp . lisp_ms_rtr_list = [ ]
 if ( "address" in I1IiIiiIiIII ) :
  for Ii1I1i in I1IiIiiIiIII [ "address" ] :
   if ( Ii1I1i == "" ) : continue
   II = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   II . store_address ( Ii1I1i )
   lisp . lisp_ms_rtr_list . append ( II )
   if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
   if 69 - 69: ooOoO0o % ooOoO0o
 if ( "dns-name" in I1IiIiiIiIII ) :
  for Ooo00OOOOOO0 in I1IiIiiIiIII [ "dns-name" ] :
   if ( Ooo00OOOOOO0 == "" ) : continue
   i1II = socket . gethostbyname_ex ( Ooo00OOOOOO0 )
   OO0oo00oOO = i1II [ 2 ]
   for I1i in OO0oo00oOO :
    II = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
    II . store_address ( I1i )
    lisp . lisp_ms_rtr_list . append ( II )
    if 82 - 82: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo % i11iIiiIii / I1Ii111 % OoooooooOO
    if 96 - 96: oO0o - oO0o
    if 87 - 87: Oo0Ooo / OoooooooOO - I1ii11iIi11i . IiII + iIii1I11I1II1 . I1ii11iIi11i
 return ( iIi1 )
 if 4 - 4: OoooooooOO + ooOoO0o . i1IIi / O0 - O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
 if 28 - 28: iIii1I11I1II1
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
def lisp_process_command_lines ( lisp_socket , old , new , line ) :
 I111i1I1 = line . split ( "{" )
 I111i1I1 = I111i1I1 [ 0 ]
 I111i1I1 = I111i1I1 [ 0 : - 1 ]
 if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 lisp . lprint ( "Process the '{}' command" . format ( I111i1I1 ) )
 if 46 - 46: OoOoOO00 - O0
 if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
 if 49 - 49: o0oOOo0O0Ooo
 if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
 if ( I111i1I1 not in lisp_commands ) :
  line = "#>>> " + line . replace ( "\n" , " <<< invalid command\n" )
  new . write ( line )
  return
  if 68 - 68: Oo0Ooo
  if 22 - 22: OOooOOo
  if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
  if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
  if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 oOoO = lisp_commands [ I111i1I1 ]
 ii1IIii = False
 for O0O00OooO in oOoO :
  if ( O0O00OooO == "" ) :
   line = lisp_write_error ( line , "invalid command" )
   new . write ( line )
   return
   if 31 - 31: iIii1I11I1II1 * ooOoO0o - OoooooooOO * ooOoO0o
   if 60 - 60: OOooOOo % OOooOOo * oO0o / I1IiiI * OoOoOO00 * I1IiiI
  if ( ii1IIii == False ) :
   OOoO0o = line
   III11I1 = 1
   for line in old :
    if ( lisp_begin_clause ( line ) ) : III11I1 += 1
    OOoO0o += line
    if ( lisp_end_clause ( line ) ) :
     III11I1 -= 1
     if ( III11I1 == 0 ) : break
     if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
     if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
     if 34 - 34: I1Ii111 - OOooOOo
     if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
     if 64 - 64: i1IIi
     if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
     if 25 - 25: II111iiii / OoO0O00
  if ( lisp . lisp_is_running ( O0O00OooO ) == False ) :
   if ( ii1IIii == False ) :
    for line in OOoO0o : new . write ( line )
    ii1IIii = True
    if 64 - 64: O0 % ooOoO0o
   lisp . lprint ( "Process '{}' is not running, do not send command" . format ( O0O00OooO ) )
   if 40 - 40: o0oOOo0O0Ooo + I11i
   continue
   if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
   if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
   if 47 - 47: OoooooooOO
   if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
   if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
   if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
  if ( O0O00OooO == "lisp-core" ) :
   if ( OOoO0o . find ( "enable" ) != - 1 ) :
    iIi1 = lisp_enable_command ( OOoO0o )
    if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
   if ( OOoO0o . find ( "debug" ) != - 1 ) :
    iIi1 = lisp_debug_command ( lisp_socket , OOoO0o , None )
    if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
   if ( OOoO0o . find ( "user-account" ) != - 1 ) :
    iIi1 = lisp_user_account_command ( OOoO0o )
    if 26 - 26: OOooOOo * Oo0Ooo
   if ( OOoO0o . find ( "rtr-list" ) != - 1 ) :
    iIi1 = lisp_rtr_list_command ( OOoO0o )
    if 31 - 31: I11i * oO0o . Ii1I
  else :
   I11IIIiIi11 = lisp . lisp_command_ipc ( OOoO0o , "lisp-core" )
   lisp . lisp_ipc ( I11IIIiIi11 , lisp_socket , O0O00OooO )
   lisp . lprint ( "Waiting for response to config command '{}'" . format ( I111i1I1 ) )
   if 35 - 35: I11i
   if 94 - 94: ooOoO0o / i11iIiiIii % O0
   iIiiIIi1iiII , oooO00Oo , ooO00o , iIi1 = lisp . lisp_receive ( lisp_socket ,
 True )
   if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
   if ( oooO00Oo == "" ) :
    lisp . lprint ( "Command timed out to {}" . format ( O0O00OooO ) )
    iIi1 = OOoO0o
   elif ( oooO00Oo != O0O00OooO ) :
    lisp . lprint ( "Fatal IPC error to {}, source {}" . format ( O0O00OooO ,
 oooO00Oo ) )
    if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
   iIi1 = iIi1 . decode ( )
   if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
   if 68 - 68: O0
   if 76 - 76: I1ii11iIi11i
   if 99 - 99: o0oOOo0O0Ooo
   if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
   if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
  if ( ii1IIii == False ) :
   for line in iIi1 : new . write ( line )
   ii1IIii = True
   if 89 - 89: oO0o
   if 87 - 87: iII111i % Oo0Ooo
 return
 if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
 if 37 - 37: iII111i
 if 33 - 33: OoO0O00 - O0 - OoO0O00
 if 94 - 94: IiII * I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - o0oOOo0O0Ooo
 if 13 - 13: OOooOOo / IiII - OoO0O00 / OOooOOo . i1IIi
 if 22 - 22: O0 - I11i + I1Ii111 . Ii1I * i1IIi
 if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
def lisp_process_config_file ( lisp_socket , file_name , startup ) :
 lisp . lprint ( "Processing configuration file {}" . format ( file_name ) )
 if 10 - 10: I1Ii111 * oO0o % Oo0Ooo - I11i % Oo0Ooo
 if 65 - 65: iII111i * iIii1I11I1II1 / O0 . I11i
 if 94 - 94: Oo0Ooo . ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo . iII111i
 if 98 - 98: OOooOOo + Ii1I
 if ( os . path . exists ( file_name ) == False ) :
  lisp . lprint ( "LISP configuration file '{}' does not exist" . format ( file_name ) )
  if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
  return
  if 50 - 50: iIii1I11I1II1 - iII111i - I11i
  if 60 - 60: iIii1I11I1II1 * ooOoO0o
 oO0O0o0o000 = file_name + ".diff"
 III1 = file_name + ".bak"
 OOO000OOo0o0O = file_name + ".temp"
 I111Iii1 = "# lispers.net lisp.config file"
 if 30 - 30: i1IIi
 if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
 if 93 - 93: ooOoO0o
 if 18 - 18: ooOoO0o
 if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
 OO00OO0O0 = 'egrep "{}" {}' . format ( I111Iii1 , file_name )
 OooOo0OOO = getoutput ( OO00OO0O0 )
 if ( OooOo0OOO == "" ) :
  lisp . lprint ( "*** lisp.config configuration file is corrupt ***" )
  return
  if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
  if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
  if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
  if 58 - 58: O0
  if 91 - 91: iII111i / I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I1ii11iIi11i
  if 72 - 72: Ii1I . IiII * I1ii11iIi11i / I1ii11iIi11i / iII111i
 iiI1 = open ( file_name , "r" )
 IIII1ii1 = open ( OOO000OOo0o0O , "w" )
 for O00oO0 in iiI1 :
  if ( O00oO0 . find ( I111Iii1 ) == 0 ) :
   if ( startup ) :
    IIII1ii1 . write ( O00oO0 )
   else :
    lisp_write_last_changed_date ( IIII1ii1 , O00oO0 )
    if 52 - 52: OoO0O00 - OOooOOo - ooOoO0o - o0oOOo0O0Ooo + i1IIi
   continue
   if 10 - 10: OoooooooOO / iII111i / oO0o * Oo0Ooo / iIii1I11I1II1
   if 63 - 63: II111iiii
  if ( O00oO0 . find ( "# Hostname:" ) == 0 ) :
   IIII1ii1 . write ( "# Hostname: " + lisp . lisp_hostname + "\n" )
   continue
   if 39 - 39: O0 + OoO0O00 / o0oOOo0O0Ooo % I11i . OOooOOo * OoooooooOO
   if 38 - 38: oO0o % OoooooooOO + OoO0O00 * i11iIiiIii
  if ( lisp_end_file ( O00oO0 ) ) :
   IIII1ii1 . write ( O00oO0 + "\n" )
   break
   if 61 - 61: iIii1I11I1II1
   if 11 - 11: oO0o . I1IiiI + IiII / i1IIi
  if ( lisp_comment ( O00oO0 ) ) :
   IIII1ii1 . write ( O00oO0 )
   continue
   if 1 - 1: Oo0Ooo * I1Ii111 . OoooooooOO
   if 73 - 73: OoOoOO00 % o0oOOo0O0Ooo
  OO0o0OO0O0OooOooO = O00oO0 . replace ( " " , "" )
  OO0o0OO0O0OooOooO = OO0o0OO0O0OooOooO . replace ( "\n" , "" )
  if ( OO0o0OO0O0OooOooO == "" ) : continue
  if 74 - 74: I11i
  if 98 - 98: oO0o / OoooooooOO % Ii1I * II111iiii - OoO0O00
  if 95 - 95: I1IiiI % I1Ii111 * I1IiiI + O0 . I1Ii111 % OoooooooOO
  if 6 - 6: OoOoOO00 - ooOoO0o * o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo
  lisp_process_command_lines ( lisp_socket , iiI1 , IIII1ii1 , O00oO0 )
  if 100 - 100: OoO0O00 % I1Ii111 - I11i % I11i % I11i / ooOoO0o
 iiI1 . close ( )
 IIII1ii1 . close ( )
 if 83 - 83: oO0o - ooOoO0o - IiII % i1IIi - iII111i . o0oOOo0O0Ooo
 if 96 - 96: Oo0Ooo + I1Ii111 . i1IIi
 if 54 - 54: II111iiii . i1IIi / I1ii11iIi11i % I1IiiI / I1Ii111
 if 65 - 65: OoOoOO00 . OoOoOO00 - oO0o + Oo0Ooo / i11iIiiIii
 if ( os . path . exists ( oO0O0o0o000 ) == False ) :
  os . system ( "touch {}" . format ( oO0O0o0o000 ) )
  if 90 - 90: iIii1I11I1II1 + OoOoOO00
 if ( startup == False ) :
  os . system ( "diff {} {} > {}" . format ( III1 , OOO000OOo0o0O , oO0O0o0o000 ) )
  if 9 - 9: iIii1I11I1II1 . OoooooooOO + i1IIi - Oo0Ooo
  if 30 - 30: iII111i / OoO0O00 . iII111i
  if 17 - 17: Oo0Ooo + OoooooooOO * OoooooooOO
  if 5 - 5: I1Ii111 % OoooooooOO . OoOoOO00
  if 67 - 67: I1ii11iIi11i + Ii1I
  if 72 - 72: IiII % o0oOOo0O0Ooo
 os . system ( "cp {} {}; rm -f {}; cp {} {}" . format ( OOO000OOo0o0O , file_name ,
 OOO000OOo0o0O , file_name , III1 ) )
 return
 if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
 if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
 if 52 - 52: IiII % ooOoO0o
 if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
 if 23 - 23: i11iIiiIii
 if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
 if 65 - 65: II111iiii / Oo0Ooo
 if 42 - 42: i11iIiiIii . O0
def lisp_send_commands ( lisp_socket , process ) :
 o0oo0Oo = "./lisp.config"
 i1i1I1II = open ( o0oo0Oo , "r" )
 o0o0oO = False
 O00o = 0
 if 55 - 55: ooOoO0o % I11i / i11iIiiIii
 if 20 - 20: IiII / I1Ii111 * IiII * OoO0O00
 if 72 - 72: OoO0O00 . o0oOOo0O0Ooo * I1ii11iIi11i . iIii1I11I1II1 % I1ii11iIi11i . Ii1I
 if 70 - 70: OOooOOo + ooOoO0o * Ii1I . Ii1I + OoO0O00
 for O00oO0 in i1i1I1II :
  if ( lisp_end_file ( O00oO0 ) ) : break
  if ( lisp_comment ( O00oO0 ) or O00oO0 [ 0 ] == "\n" ) : continue
  if 28 - 28: i1IIi . OOooOOo
  if ( lisp_begin_clause ( O00oO0 ) ) :
   if ( O00o == 0 ) :
    OOoO0o = ""
    I111i1I1 = O00oO0 . split ( "{" )
    I111i1I1 = I111i1I1 [ 0 ]
    I111i1I1 = I111i1I1 [ 0 : - 1 ]
    if ( I111i1I1 in lisp_commands ) :
     o0o0oO = ( process in lisp_commands [ I111i1I1 ] ) or ( I111i1I1 == "lisp debug" )
     if 88 - 88: I11i + I1IiiI - I11i / OoooooooOO - i11iIiiIii
     if 24 - 24: iIii1I11I1II1
     if 89 - 89: Ii1I / i1IIi - o0oOOo0O0Ooo % I1IiiI . Oo0Ooo - O0
   O00o += 1
   if 71 - 71: OoO0O00 % I1IiiI - iII111i . iII111i
   if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
   if 64 - 64: i1IIi % I1ii11iIi11i / Ii1I % OoooooooOO
   if 24 - 24: I1Ii111 + OoooooooOO . IiII / OoOoOO00 / I11i
   if 65 - 65: OoooooooOO
  if ( o0o0oO ) : OOoO0o += O00oO0
  if 18 - 18: O0 - i1IIi . I1Ii111
  if 98 - 98: o0oOOo0O0Ooo
  if 73 - 73: Oo0Ooo - iII111i . oO0o % i1IIi . O0
  if 15 - 15: ooOoO0o . iIii1I11I1II1 * I1IiiI % I11i
  if 21 - 21: OoO0O00 - I1IiiI . OoooooooOO
  if ( lisp_end_clause ( O00oO0 ) == False ) : continue
  O00o -= 1
  if ( O00o != 0 ) : continue
  if ( o0o0oO == False ) : continue
  if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
  if 3 - 3: OOooOOo . IiII / Oo0Ooo
  if 89 - 89: OoooooooOO . iIii1I11I1II1 . Oo0Ooo * iIii1I11I1II1 - I1Ii111
  if 92 - 92: OoooooooOO - I1ii11iIi11i - OoooooooOO % I1IiiI % I1IiiI % iIii1I11I1II1
  if 92 - 92: iII111i * O0 % I1Ii111 . iIii1I11I1II1
  if 66 - 66: I11i + Ii1I
  lisp . lprint ( "Send command '{}' to restarting process '{}'" . format ( I111i1I1 , process ) )
  if 48 - 48: I1ii11iIi11i
  if 96 - 96: ooOoO0o . OoooooooOO
  if 39 - 39: OOooOOo + OoO0O00
  if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
  if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
  if 71 - 71: ooOoO0o . i11iIiiIii
  if ( I111i1I1 == "lisp debug" ) :
   lisp_debug_command ( lisp_socket , OOoO0o , process )
   o0o0oO = False
   continue
   if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
   if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
  OOoO0o = lisp . lisp_command_ipc ( OOoO0o , "lisp-core" )
  lisp . lisp_ipc ( OOoO0o , lisp_socket , process )
  if 67 - 67: iII111i
  if 88 - 88: Oo0Ooo
  if 8 - 8: I1ii11iIi11i
  if 82 - 82: OoooooooOO
  if 75 - 75: II111iiii % I1IiiI + OOooOOo % OoooooooOO / IiII
  lisp . lprint ( "Waiting for response to config command '{}'" . format ( I111i1I1 ) )
  if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
  if 71 - 71: ooOoO0o . ooOoO0o - iIii1I11I1II1
  iIiiIIi1iiII , oooO00Oo , ooO00o , Ii1IOoO0o0O = lisp . lisp_receive ( lisp_socket , True )
  if 20 - 20: O0
  if ( oooO00Oo == "" ) :
   lisp . lprint ( "Command timed out to {}" . format ( process ) )
  elif ( oooO00Oo != process ) :
   lisp . lprint ( "Fatal IPC error to {}, IPC source {}" . format ( process ,
 oooO00Oo ) )
   if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
  o0o0oO = False
  if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
 return
 if 29 - 29: Ii1I / ooOoO0o % I11i
 if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
 if 79 - 79: O0
def lisp_config_process ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 o0oo0Oo = "./lisp.config"
 IiI = ""
 iiIi1IiiIi1 = True
 if 41 - 41: iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % IiII / OOooOOo
 while ( True ) :
  oO0OOoO0 = os . path . getmtime ( o0oo0Oo )
  if ( oO0OOoO0 != IiI ) :
   if 63 - 63: i1IIi % i11iIiiIii % II111iiii * OoooooooOO
   lisp . lisp_ipc_lock . acquire ( )
   lisp_process_config_file ( lisp_socket , o0oo0Oo , iiIi1IiiIi1 )
   lisp . lisp_ipc_lock . release ( )
   if 40 - 40: Oo0Ooo
   iiIi1IiiIi1 = False
   IiI = os . path . getmtime ( o0oo0Oo )
   if 47 - 47: OoOoOO00
  time . sleep ( 1 )
  if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
 return
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
 if 87 - 87: ooOoO0o
 if 41 - 41: OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
 if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
def lisp_map_resolver_command ( kv_pair ) :
 O0OOOOOO0ooO = None
 if 18 - 18: Oo0Ooo - OOooOOo * II111iiii + oO0o
 for iiiI11 in list ( kv_pair . keys ( ) ) :
  if ( iiiI11 == "mr-name" ) :
   O0OOOOOO0ooO = kv_pair [ iiiI11 ] [ 0 ]
   continue
   if 93 - 93: iII111i * oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if ( iiiI11 == "address" or iiiI11 == "dns-name" ) :
   oOoOO = kv_pair [ iiiI11 ]
   for oo00oO0O0 in oOoOO :
    if ( oo00oO0O0 == "" ) : continue
    Ii1I1i = oo00oO0O0 if ( iiiI11 == "address" ) else None
    i11 = oo00oO0O0 if ( iiiI11 == "dns-name" ) else None
    lisp . lisp_mr ( Ii1I1i , i11 , O0OOOOOO0ooO )
    if 42 - 42: I11i % Oo0Ooo . II111iiii / II111iiii * iII111i
    if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
    if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
 return
 if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
 if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
 if 21 - 21: OoO0O00
 if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
 if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
 if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
 if 11 - 11: O0 * OoOoOO00
def lisp_map_cache_command ( kv_pair ) :
 IIii1i = [ ]
 if ( lisp_clause_syntax_error ( kv_pair , "eid-prefix" , "prefix" ) ) : return
 for o00oo in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  Ii11IIIi1 = lisp . lisp_mapping ( "" , "" , [ ] )
  IIii1i . append ( Ii11IIIi1 )
  if 93 - 93: i11iIiiIii . o0oOOo0O0Ooo
  if 16 - 16: i1IIi . i1IIi / I1Ii111 % OoOoOO00 / I1IiiI * I1ii11iIi11i
 IIIii11 = [ ]
 if ( "address" in kv_pair ) :
  if ( lisp_clause_syntax_error ( kv_pair , "address" , "rloc" ) ) : return
  for o00oo in range ( len ( kv_pair [ "address" ] ) ) :
   i1i11I1I1 = lisp . lisp_rloc ( )
   IIIii11 . append ( i1i11I1I1 )
   if 82 - 82: OoO0O00 - Oo0Ooo - O0 - OoooooooOO
   if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
   if 18 - 18: Oo0Ooo % O0
 for iiiI11 in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ iiiI11 ]
  if ( iiiI11 == "instance-id" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    Ii11IIIi1 = IIii1i [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO == "" ) : oooooO00OOO = "0"
    Ii11IIIi1 . eid . instance_id = int ( oooooO00OOO )
    Ii11IIIi1 . group . instance_id = int ( oooooO00OOO )
    if 53 - 53: II111iiii
    if 61 - 61: O0 * OoO0O00 * I1IiiI % OoooooooOO / OoOoOO00 % ooOoO0o
  if ( iiiI11 == "eid-prefix" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    Ii11IIIi1 = IIii1i [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) : Ii11IIIi1 . eid . store_prefix ( oooooO00OOO )
    if 43 - 43: OoooooooOO
    if 33 - 33: II111iiii - IiII - ooOoO0o
  if ( iiiI11 == "group-prefix" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    Ii11IIIi1 = IIii1i [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) : Ii11IIIi1 . group . store_prefix ( oooooO00OOO )
    if 92 - 92: OoO0O00 * IiII
    if 92 - 92: oO0o
  if ( iiiI11 == "send-map-request" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    Ii11IIIi1 = IIii1i [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO == "yes" ) : Ii11IIIi1 . action = lisp . LISP_SEND_MAP_REQUEST_ACTION
    if 7 - 7: iII111i
    if 73 - 73: OoO0O00 % I1ii11iIi11i
  if ( iiiI11 == "subscribe-request" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    Ii11IIIi1 = IIii1i [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO == "yes" ) : Ii11IIIi1 . action = lisp . LISP_SEND_PUBSUB_ACTION
    if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
    if 62 - 62: i11iIiiIii
  if ( iiiI11 == "rle-name" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) :
     i1i11I1I1 . rle_name = oooooO00OOO
     if ( oooooO00OOO in lisp . lisp_rle_list ) :
      i1i11I1I1 . rle = lisp . lisp_rle_list [ oooooO00OOO ]
      if 2 - 2: I1IiiI
      if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
      if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
      if 14 - 14: IiII . IiII % ooOoO0o
  if ( iiiI11 == "elp-name" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) :
     i1i11I1I1 . elp_name = oooooO00OOO
     if ( oooooO00OOO in lisp . lisp_elp_list ) :
      i1i11I1I1 . elp = lisp . lisp_elp_list [ oooooO00OOO ]
      i1i11I1I1 . elp . select_elp_node ( )
      if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
      if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
      if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
      if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
  if ( iiiI11 == "rloc-record-name" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) : i1i11I1I1 . rloc_name = oooooO00OOO
    if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
    if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
    if 6 - 6: oO0o . I11i
  if ( iiiI11 == "priority" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO == "" ) : oooooO00OOO = "0"
    i1i11I1I1 . priority = int ( oooooO00OOO )
    if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
    if 50 - 50: oO0o % i1IIi * O0
  if ( iiiI11 == "weight" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO == "" ) : oooooO00OOO = "0"
    i1i11I1I1 . weight = int ( oooooO00OOO )
    if 4 - 4: iIii1I11I1II1 . i1IIi
    if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
  if ( iiiI11 == "address" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) : i1i11I1I1 . rloc . store_address ( oooooO00OOO )
    if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
    if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
    if 59 - 59: iIii1I11I1II1 / I1ii11iIi11i % ooOoO0o
    if 84 - 84: iIii1I11I1II1 / I1IiiI . OoOoOO00 % I11i
    if 99 - 99: Oo0Ooo + i11iIiiIii
    if 36 - 36: Ii1I * I1Ii111 * iIii1I11I1II1 - I11i % i11iIiiIii
    if 98 - 98: iIii1I11I1II1 - i1IIi + ooOoO0o % I11i + ooOoO0o / oO0o
    if 97 - 97: IiII % ooOoO0o + II111iiii - IiII % OoO0O00 + ooOoO0o
 for Ii11IIIi1 in IIii1i :
  Ii11IIIi1 . rloc_set = IIIii11
  Ii11IIIi1 . build_best_rloc_set ( )
  Ii11IIIi1 . add_cache ( )
  IIIii11 = copy . deepcopy ( IIIii11 )
  if 31 - 31: o0oOOo0O0Ooo
 return
 if 35 - 35: OoOoOO00 + Ii1I * ooOoO0o / OoOoOO00
 if 69 - 69: ooOoO0o . OOooOOo - I1IiiI
 if 29 - 29: i11iIiiIii . I1ii11iIi11i / I1IiiI . OOooOOo + i11iIiiIii
 if 26 - 26: IiII / Ii1I - OoooooooOO
 if 9 - 9: OoooooooOO * I1ii11iIi11i
 if 9 - 9: Oo0Ooo + iII111i
 if 64 - 64: O0 * I1IiiI / I1IiiI
def lisp_display_map_cache ( mc , output ) :
 oO0OOoO0 = lisp . lisp_print_elapsed ( mc . uptime )
 OOOO0oo0 = mc . print_eid_tuple ( )
 Iiii = "Recent Sources: "
 Iiii += "none\n" if ( mc . recent_sources == { } ) else "\n"
 for iIIi11 in mc . recent_sources :
  OO0oo = mc . recent_sources [ iIIi11 ]
  Iiii += "  " + iIIi11 + ": " + lisp . lisp_print_elapsed ( OO0oo ) + "\n"
  if 56 - 56: I1ii11iIi11i . oO0o
 OOOO0oo0 = lisp . lisp_span ( OOOO0oo0 , Iiii [ 0 : - 1 ] )
 oOoOo00OOOOo = mc . action
 if 56 - 56: Ii1I + I1IiiI - o0oOOo0O0Ooo / o0oOOo0O0Ooo . II111iiii - Ii1I
 if 40 - 40: iII111i . OoOoOO00 * O0
 if 6 - 6: I1IiiI - II111iiii . I1IiiI + I11i . OOooOOo
 if 74 - 74: i1IIi
 if 15 - 15: i1IIi + IiII % I1IiiI / i11iIiiIii * OoOoOO00
 if 69 - 69: i11iIiiIii
 oooO00Oo = mc . mapping_source
 if ( oooO00Oo == None ) :
  oooO00Oo = "map-notify"
 else :
  oooO00Oo = "static" if oooO00Oo . is_null ( ) else oooO00Oo . print_address_no_iid ( )
  if 61 - 61: O0
  if 21 - 21: OoO0O00 % iIii1I11I1II1 . OoO0O00
  if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
 if ( mc . checkpoint_entry ) : oooO00Oo = "checkpoint"
 if ( mc . gleaned ) : oooO00Oo = "gleaned"
 O0OO = mc . print_ttl ( )
 if 30 - 30: OoOoOO00 * Oo0Ooo % iIii1I11I1II1 % OoO0O00 + i11iIiiIii
 oOoOo00OOOOo = "encapsulate" if oOoOo00OOOOo == lisp . LISP_NO_ACTION else lisp . lisp_map_reply_action_string [ oOoOo00OOOOo ]
 if 46 - 46: I1IiiI . IiII - i11iIiiIii - I1Ii111
 if 97 - 97: II111iiii % Oo0Ooo * IiII
 if ( len ( mc . rloc_set ) == 0 ) :
  oOoOO0O00o = mc . stats . get_stats ( True , True )
  output += lisp_table_row ( OOOO0oo0 , oO0OOoO0 + "<br>" + O0OO , "--" , oooO00Oo ,
 oOoOO0O00o , oOoOo00OOOOo , "--" )
  return ( [ True , output ] )
  if 77 - 77: I1Ii111 + oO0o
  if 38 - 38: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 for i1i11I1I1 in mc . rloc_set :
  iIIIi1iii1I11 = ""
  if ( i1i11I1I1 . rloc_exists ( ) ) :
   if ( i1i11I1I1 . rloc . is_null ( ) == False ) :
    iIIIi1iii1I11 += i1i11I1I1 . rloc . print_address_no_iid ( ) + "<br>"
    Iiii = ""
    O0o0 = lisp . lisp_nonce_echoing and i1i11I1I1 . echo_nonce_capable
    if ( lisp . lisp_rloc_probing ) :
     Iiii += i1i11I1I1 . print_rloc_probe_state ( O0o0 )
     if 76 - 76: oO0o . iII111i . O0
    if ( O0o0 ) :
     O0o0O0OooOoo = lisp . lisp_get_echo_nonce ( i1i11I1I1 . rloc , None )
     if ( O0o0O0OooOoo ) : Iiii += O0o0O0OooOoo . print_echo_nonce ( )
     if 17 - 17: OoooooooOO % oO0o - i1IIi % IiII % Oo0Ooo
    if ( Iiii != "" ) : iIIIi1iii1I11 = lisp . lisp_span ( iIIIi1iii1I11 , Iiii )
    if 41 - 41: OoooooooOO . I1Ii111 % OoOoOO00 - iII111i
    if 58 - 58: oO0o + iIii1I11I1II1 - O0
    if 43 - 43: O0 . II111iiii % iIii1I11I1II1
  if ( i1i11I1I1 . translated_port != 0 ) :
   iIIIi1iii1I11 += "encap-port: {}<br>" . format ( i1i11I1I1 . translated_port )
   if 24 - 24: i1IIi / I1Ii111 * I11i / O0
   if 88 - 88: I1ii11iIi11i . I1Ii111 * Oo0Ooo - OOooOOo . OoOoOO00 . I1Ii111
  if ( i1i11I1I1 . rloc_name ) :
   iIIIi1iii1I11 += "rloc-name: {}<br>" . format ( lisp . blue ( i1i11I1I1 . rloc_name ,
 True ) )
   if 27 - 27: I1IiiI
   if 27 - 27: iIii1I11I1II1 % I11i - I1Ii111
  if ( i1i11I1I1 . geo ) :
   iIIIi1iii1I11 += "geo: {}<br>" . format ( i1i11I1I1 . geo . print_geo_url ( ) )
   if 67 - 67: O0 / I1Ii111 * Ii1I % ooOoO0o . I1ii11iIi11i * oO0o
  if ( i1i11I1I1 . elp ) :
   IiiiIIIi11ii1 = i1i11I1I1 . elp . print_elp ( True )
   iIIIi1iii1I11 += "elp: {}<br>" . format ( IiiiIIIi11ii1 )
   if 82 - 82: OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
  if ( i1i11I1I1 . rle ) :
   iI1 = i1i11I1I1 . rle . print_rle ( True , True )
   iIIIi1iii1I11 += "rle: {}<br>" . format ( iI1 )
   if 99 - 99: OoO0O00 / i1IIi . I1ii11iIi11i
  if ( i1i11I1I1 . json ) :
   if ( lisp . lisp_is_json_telemetry ( i1i11I1I1 . json . json_string ) == None ) :
    I1Iiiiiii = "json: { ... }<br>"
    iIIIi1iii1I11 += lisp . lisp_span ( I1Iiiiiii , i1i11I1I1 . json . print_json ( False ) )
    if 23 - 23: Ii1I * ooOoO0o - I11i . O0 % iIii1I11I1II1
    if 19 - 19: I1IiiI
    if 66 - 66: oO0o / OoOoOO00
    if 13 - 13: II111iiii
    if 55 - 55: Oo0Ooo % i1IIi * I11i
    if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
  oOoOO0O00o = i1i11I1I1 . stats . get_stats ( True , True )
  if 63 - 63: iIii1I11I1II1 / ooOoO0o
  if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
  if 50 - 50: II111iiii
  if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
  iIIiI = ""
  O0O0O0OO00oo = i1i11I1I1
  while ( O0O0O0OO00oo != None ) :
   I11IIIIiI1 = ""
   if ( O0O0O0OO00oo . rloc_next_hop != None ) :
    OOoOOo00O0o0 , o0 = O0O0O0OO00oo . rloc_next_hop
    iIIiI += "next-hop {}({}), " . format ( o0 , OOoOOo00O0o0 )
    I11IIIIiI1 = lisp . lisp_space ( 2 )
    if 96 - 96: i1IIi
    if 55 - 55: oO0o + OOooOOo + Ii1I
   OOo = lisp . lisp_print_elapsed ( O0O0O0OO00oo . last_state_change )
   if ( OOo == "never" ) :
    OOo = lisp . lisp_print_elapsed ( O0O0O0OO00oo . uptime )
    if 27 - 27: OoO0O00 + OoOoOO00
   iIIi11 = O0O0O0OO00oo . print_state ( )
   if ( O0O0O0OO00oo . unreach_state ( ) or O0O0O0OO00oo . no_echoed_nonce_state ( ) ) :
    iIIi11 = lisp . red ( iIIi11 , True )
    if 97 - 97: i1IIi * I1Ii111 . II111iiii
   iIIiI += iIIi11 + " since " + OOo
   if 62 - 62: OoooooooOO . Ii1I
   if ( lisp . lisp_rloc_probing ) :
    IIi = O0O0O0OO00oo . print_rloc_probe_rtt ( )
    if ( IIi != "none" ) :
     iIIiI += "<br>{}rtt: {}, hops: {}, latency: {}" . format ( I11IIIIiI1 , IIi , O0O0O0OO00oo . print_rloc_probe_hops ( ) ,
     # iIii1I11I1II1 . OOooOOo . I1ii11iIi11i * i11iIiiIii
 O0O0O0OO00oo . print_rloc_probe_latency ( ) )
     if 72 - 72: I11i
     if 26 - 26: IiII % Oo0Ooo
     if 72 - 72: O0 + o0oOOo0O0Ooo + I1IiiI / Oo0Ooo
   O0O0O0OO00oo = O0O0O0OO00oo . next_rloc
   if ( O0O0O0OO00oo == None ) : break
   iIIiI += "<br>"
   if 83 - 83: IiII - I1IiiI . Ii1I
   if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
  if ( oOoOo00OOOOo == "encapsulate" ) :
   ooO00o = lisp . LISP_DATA_PORT
   if ( lisp . lisp_i_am_rtr and i1i11I1I1 . translated_port != 0 ) :
    ooO00o = i1i11I1I1 . translated_port
    if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
    if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
   Ii1I1i = i1i11I1I1 . rloc . print_address_no_iid ( ) + ":" + str ( ooO00o )
   if ( Ii1I1i in lisp . lisp_crypto_keys_by_rloc_encap ) :
    oo000O0o = lisp . lisp_crypto_keys_by_rloc_encap [ Ii1I1i ] [ 1 ]
    if ( oo000O0o != None and oo000O0o . shared_key != None ) :
     oOoOo00OOOOo = "encap-crypto-" + oo000O0o . cipher_suite_string
     if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
     if 25 - 25: Oo0Ooo % OoOoOO00
     if 75 - 75: i1IIi
     if 74 - 74: Oo0Ooo + I1Ii111 - oO0o - OoO0O00 + iII111i - iIii1I11I1II1
  output += lisp_table_row ( OOOO0oo0 , oO0OOoO0 + "<br>" + O0OO , iIIIi1iii1I11 , oooO00Oo ,
 oOoOO0O00o , iIIiI + "<br>" + oOoOo00OOOOo ,
 str ( i1i11I1I1 . priority ) + "/" + str ( i1i11I1I1 . weight ) + "<br>" + str ( i1i11I1I1 . mpriority ) + "/" + str ( i1i11I1I1 . mweight ) )
  if 54 - 54: I1ii11iIi11i + II111iiii . I1IiiI / OoO0O00 . ooOoO0o
  if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
  if ( OOOO0oo0 != "" ) : OOOO0oo0 = ""
  if ( oO0OOoO0 != "" ) : oO0OOoO0 , O0OO , oooO00Oo = ( "" , "" , "" )
  if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
 return ( [ True , output ] )
 if 36 - 36: I11i - IiII . IiII
 if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
 if 84 - 84: iIii1I11I1II1 + OoooooooOO
 if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
 if 10 - 10: I1ii11iIi11i + IiII
 if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
 if 62 - 62: II111iiii
 if 12 - 12: IiII + II111iiii
def lisp_walk_map_cache ( mc , output ) :
 if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
 if 80 - 80: iII111i
 if 3 - 3: I1ii11iIi11i * I11i
 if 53 - 53: iIii1I11I1II1 / iII111i % OoO0O00 + IiII / ooOoO0o
 if ( mc . group . is_null ( ) ) : return ( lisp_display_map_cache ( mc , output ) )
 if 74 - 74: Oo0Ooo
 if ( mc . source_cache == None ) : return ( [ True , output ] )
 if 8 - 8: I1IiiI % II111iiii - o0oOOo0O0Ooo - I11i % I1IiiI
 if 93 - 93: Ii1I * iII111i / OOooOOo
 if 88 - 88: oO0o
 if 1 - 1: Oo0Ooo
 if 95 - 95: OoooooooOO / I11i % OoooooooOO / ooOoO0o * IiII
 output = mc . source_cache . walk_cache ( lisp_display_map_cache , output )
 return ( [ True , output ] )
 if 75 - 75: O0
 if 56 - 56: OoO0O00 / II111iiii
 if 39 - 39: OoOoOO00 - OoooooooOO - i1IIi / II111iiii
 if 49 - 49: Oo0Ooo + O0 + IiII . II111iiii % ooOoO0o
 if 33 - 33: OoOoOO00 . iIii1I11I1II1 / I11i % Ii1I
 if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
 if 27 - 27: OoO0O00 + Oo0Ooo
def lisp_show_myrlocs ( output ) :
 if ( lisp . lisp_myrlocs [ 2 ] == None ) :
  output += "No local RLOCs found"
 else :
  oO0oOOooO0 = lisp . lisp_print_cour ( lisp . lisp_myrlocs [ 2 ] )
  oo00o000O = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 0 ] != None else "not found"
  if 66 - 66: OoooooooOO + o0oOOo0O0Ooo . i1IIi * iII111i
  oo00o000O = lisp . lisp_print_cour ( oo00o000O )
  o00o = "-f inet" if lisp . lisp_is_macos ( ) else "-4"
  III = getoutput ( "netstat -rn {}" . format ( o00o ) )
  oo00o000O = lisp . lisp_span ( oo00o000O , III )
  if 16 - 16: Ii1I / i1IIi
  iIi1iii11Ii = lisp . lisp_myrlocs [ 1 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 1 ] != None else "not found"
  if 84 - 84: I11i . OoooooooOO % I1IiiI - I1IiiI
  iIi1iii11Ii = lisp . lisp_print_cour ( iIi1iii11Ii )
  o00o = "-f inet6" if lisp . lisp_is_macos ( ) else "-6"
  III = getoutput ( "netstat -rn {}" . format ( o00o ) )
  iIi1iii11Ii = lisp . lisp_span ( iIi1iii11Ii , III )
  if 52 - 52: II111iiii
  O00oO0 = "<i>Local RLOCs found on interface </i>{}<i>, " + "IPv4: </i>{}<i>, IPv6: </i>{}"
  if 21 - 21: OoOoOO00 - II111iiii
  output += lisp . lisp_print_sans ( O00oO0 ) . format ( oO0oOOooO0 , oo00o000O , iIi1iii11Ii )
  if 10 - 10: OoOoOO00 - o0oOOo0O0Ooo * i11iIiiIii / Oo0Ooo + o0oOOo0O0Ooo + iIii1I11I1II1
 output += "<br>"
 return ( output )
 if 23 - 23: i1IIi + I1ii11iIi11i + I1IiiI - ooOoO0o % OoooooooOO . IiII
 if 49 - 49: oO0o . OoOoOO00
 if 73 - 73: Ii1I / I1IiiI / OoooooooOO + I1IiiI
 if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
 if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
 if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
 if 98 - 98: OoO0O00
def lisp_display_nat_info ( output , dc , dodns ) :
 I1IIiIi = len ( lisp . lisp_nat_state_info )
 if ( I1IIiIi == 0 ) : return ( output )
 if 93 - 93: oO0o - OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
 Iiii = "{} entries in the NAT-traversal port table" . format ( I1IIiIi )
 o0000oO = lisp . lisp_span ( "NAT-Traversed xTR Information:" , Iiii )
 if 83 - 83: OoO0O00
 if ( dodns ) :
  output += lisp_table_header ( o0000oO , "xTR Hostname" ,
 "Translated<br>Address" , "Translated<br>{} Port" . format ( dc ) ,
 "Last<br>Info-Request" , "NAT DNS Name" )
 else :
  output += lisp_table_header ( o0000oO , "xTR Hostname" ,
 "Translated<br>Address" , "Translated<br>{} Port" . format ( dc ) ,
 "Last<br>Info-Request" )
  if 16 - 16: ooOoO0o
  if 32 - 32: o0oOOo0O0Ooo % I1IiiI
 for iII in list ( lisp . lisp_nat_state_info . values ( ) ) :
  for Ii11IiIIiIIii in iII :
   II = Ii11IiIIiIIii . address
   OO = Ii11IiIIiIIii . uptime
   O0I11i1i11i1I = Ii11IiIIiIIii . hostname
   ooO00o = Ii11IiIIiIIii . port
   if 74 - 74: iIii1I11I1II1 / Ii1I
   if ( Ii11IiIIiIIii . timed_out ( ) ) :
    OO = lisp . red ( lisp . lisp_print_elapsed ( OO ) , True )
   else :
    OO = lisp . lisp_print_elapsed ( OO )
    if 59 - 59: Ii1I / II111iiii - IiII % OoOoOO00 % OoooooooOO
    if 79 - 79: iII111i . OoooooooOO . I1IiiI * O0 * OoO0O00 - OOooOOo
   if ( dodns ) :
    try :
     IIIiII11 = socket . gethostbyaddr ( II ) [ 0 ]
    except :
     IIIiII11 = "?"
     if 96 - 96: I11i * I1ii11iIi11i * Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
    output += lisp_table_row ( O0I11i1i11i1I , II , ooO00o , OO , IIIiII11 )
   else :
    output += lisp_table_row ( O0I11i1i11i1I , II , ooO00o , OO )
    if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
    if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
    if 1 - 1: Oo0Ooo . II111iiii
    if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
 output += lisp_table_footer ( )
 return ( output )
 if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
 if 4 - 4: IiII
 if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
 if 99 - 99: i11iIiiIii - iII111i
 if 85 - 85: I1Ii111 % I1ii11iIi11i
 if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
 if 73 - 73: OoO0O00
def lisp_itr_rtr_show_command ( parameter , itr_or_rtr , lisp_threads , dns = False ) :
 if 28 - 28: OoooooooOO - I11i
 if 84 - 84: II111iiii
 if 36 - 36: OOooOOo - OoOoOO00 - iIii1I11I1II1
 if 10 - 10: I1ii11iIi11i / Ii1I * i1IIi % O0 + I11i
 if ( parameter != "" ) :
  return ( lisp_show_map_cache_lookup ( parameter ) )
  if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
  if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
 I1i1iii = ""
 if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
 if 80 - 80: Ii1I
 if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
 if 59 - 59: I1ii11iIi11i + I11i . oO0o
 I1i1iii = lisp_show_myrlocs ( I1i1iii )
 if 87 - 87: OoO0O00
 if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
 if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
 if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
 if ( itr_or_rtr == "RTR" ) :
  I1i1iii = lisp_show_decap_stats ( I1i1iii , itr_or_rtr )
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
  if 46 - 46: i11iIiiIii
  if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
  if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
  if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
 if ( len ( lisp_threads ) > 1 ) :
  iIIi11 = [ ]
  for o00oo in range ( len ( lisp_threads ) ) :
   OO0oo = lisp_threads [ o00oo ]
   iIIi11 . append ( "{} Input Stats<br>queue-size: {}" . format ( OO0oo . thread_name ,
 OO0oo . input_queue . qsize ( ) ) )
   if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
  I1i1iii += lisp_table_header ( "LISP-RTR Forwarding Stats:" , * iIIi11 )
  if 65 - 65: OoooooooOO
  iIIi11 = [ ]
  for o00oo in range ( len ( lisp_threads ) ) :
   OO0oo = lisp_threads [ o00oo ]
   iIIi11 . append ( OO0oo . input_stats . get_stats ( False , True ) )
   if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
  I1i1iii += lisp_table_row ( * iIIi11 )
  I1i1iii += lisp_table_footer ( )
  if 83 - 83: ooOoO0o
  if 43 - 43: OOooOOo
 o0IiiIIII1I1i = lisp . lisp_decent_dns_suffix
 if ( o0IiiIIII1I1i == None ) :
  o0IiiIIII1I1i = ":"
 else :
  o0IiiIIII1I1i = "&nbsp;(dns-suffix '{}'):" . format ( o0IiiIIII1I1i )
  if 26 - 26: iII111i - Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
  if 37 - 37: o0oOOo0O0Ooo * OOooOOo + I1IiiI . I1ii11iIi11i * OoooooooOO
  if 82 - 82: i11iIiiIii + iIii1I11I1II1 / Oo0Ooo + OOooOOo * II111iiii
  if 34 - 34: o0oOOo0O0Ooo % OoooooooOO
  if 36 - 36: I1IiiI
 Iiii = "{} map-resolvers configured" . format ( len ( lisp . lisp_map_resolvers_list ) )
 if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
 o0000oO = "LISP-{} Configured Map-Resolvers{}" . format ( itr_or_rtr , o0IiiIIII1I1i )
 o0000oO = lisp . lisp_span ( o0000oO , Iiii )
 if 64 - 64: ooOoO0o / i1IIi % iII111i
 I1i1iii += lisp_table_header ( o0000oO , "Map-Resolver" , "Last Used" ,
 "Map-Requests<br>Sent" , "Negative Map-Replies<br>Received" ,
 "Last Negative<br>Map-Reply" , "Average RTT" )
 if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
 for Oo0O0O000 in list ( lisp . lisp_map_resolvers_list . values ( ) ) :
  Oo0O0O000 . resolve_dns_name ( )
  O0OOOOOO0ooO = "" if Oo0O0O000 . mr_name == "all" else Oo0O0O000 . mr_name + "<br>"
  Ii1I1i = O0OOOOOO0ooO + Oo0O0O000 . map_resolver . print_address_no_iid ( )
  if ( Oo0O0O000 . dns_name ) : Ii1I1i += "<br>" + Oo0O0O000 . dns_name
  if 99 - 99: I1Ii111
  oO0OOoO0 = lisp . lisp_print_elapsed ( Oo0O0O000 . last_used )
  o0I1IiiiiI1i1I = lisp . lisp_print_elapsed ( Oo0O0O000 . last_reply )
  I11i1I1 = 0 if Oo0O0O000 . neg_map_replies_received == 0 else float ( old_div ( Oo0O0O000 . total_rtt , Oo0O0O000 . neg_map_replies_received ) )
  if 68 - 68: i11iIiiIii + OoO0O00
  I11i1I1 = str ( round ( I11i1I1 , 3 ) ) + " ms"
  if 13 - 13: ooOoO0o - I1IiiI
  I1i1iii += lisp_table_row ( Ii1I1i , oO0OOoO0 , Oo0O0O000 . map_requests_sent ,
 Oo0O0O000 . neg_map_replies_received , o0I1IiiiiI1i1I , I11i1I1 )
  if 23 - 23: I1IiiI
 I1i1iii += lisp_table_footer ( )
 if 7 - 7: iII111i % I1ii11iIi11i
 if 64 - 64: I1Ii111 + i11iIiiIii
 if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
 if 68 - 68: IiII . ooOoO0o
 if ( itr_or_rtr == "ITR" ) : I1i1iii = lisp_show_db_list ( "ITR" , I1i1iii )
 if 64 - 64: i1IIi + Oo0Ooo * I1IiiI / OOooOOo
 if 3 - 3: Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
 if 50 - 50: iIii1I11I1II1 * oO0o
 if 85 - 85: i1IIi
 O0OoOoo00o = "<br>Enter EID for Map-Cache lookup:"
 if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
 IIi11 = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 77 - 77: Oo0Ooo - IiII
 iI1iiIIIi1I = itr_or_rtr . lower ( )
 if 66 - 66: oO0o + iIii1I11I1II1 - ooOoO0o - I11i - I1IiiI * i1IIi
 O0OoOoo00o = '''
         <form action="/lisp/show/{}/map-cache/lookup" method="post">
         <font size="3"><i>{}</i> {}
         <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form>
    ''' . format ( iI1iiIIIi1I , lisp . lisp_print_sans ( O0OoOoo00o ) , IIi11 )
 if 57 - 57: Oo0Ooo . IiII % OOooOOo
 OoO0o00oo0oO = '<a href="/lisp/show/{}/rloc-probing">RLOC State</a>' . format ( iI1iiIIIi1I )
 if 25 - 25: Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
 o0oo000 = '<a href="/lisp/show/{}/keys"><br>RLOC Keys</a>' . format ( iI1iiIIIi1I )
 if 87 - 87: OoO0O00
 if 27 - 27: Ii1I . o0oOOo0O0Ooo - OoOoOO00 . II111iiii % Oo0Ooo
 if 83 - 83: I11i + oO0o - iIii1I11I1II1 + II111iiii . iII111i
 if 76 - 76: OoooooooOO
 i1iiIi1IiiiI = os . path . exists ( "./show-ztr" )
 OO0oooOO = "Map-Cache"
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None or i1iiIi1IiiiI ) :
  OO0oooOO = '<a href="/lisp/show/lisp-xtr">Map-Cache</a>'
  if 30 - 30: oO0o . OoO0O00 + I11i / iIii1I11I1II1 % Oo0Ooo / oO0o
  if 3 - 3: I1ii11iIi11i / II111iiii
  if 73 - 73: OoO0O00 * OoooooooOO - OoooooooOO + I1IiiI * Oo0Ooo
  if 87 - 87: o0oOOo0O0Ooo / IiII / i11iIiiIii
  if 95 - 95: i1IIi / Ii1I / Ii1I
 Iiii = "{} entries in the map-cache" . format ( lisp . lisp_map_cache . cache_size ( ) )
 if 65 - 65: I1Ii111 + iII111i * iII111i
 o0000oO = "LISP-{} {}:{}" . format ( itr_or_rtr , OO0oooOO , lisp . lisp_space ( 4 ) )
 o0000oO = lisp . lisp_span ( o0000oO , Iiii )
 if 79 - 79: i1IIi / Oo0Ooo - I1IiiI . O0
 if 56 - 56: IiII % O0 * i1IIi - II111iiii
 if 74 - 74: i1IIi - OoOoOO00 % oO0o . O0 - OoooooooOO
 if 84 - 84: I1Ii111
 if 53 - 53: i1IIi
 o0000oO += lisp . lisp_button ( "clear cache" ,
 "/lisp/clear/{}/map-cache" . format ( itr_or_rtr . lower ( ) ) )
 o0000oO += O0OoOoo00o
 if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
 if 9 - 9: i1IIi - OoOoOO00
 I1i1iii += lisp_table_header ( o0000oO , "EID-Prefix or (S,G)" ,
 "Uptime<br>TTL" , "RLOC Record" + o0oo000 , "Map-Reply Source" ,
 "RLOC Send Stats" , OoO0o00oo0oO + "<br>RLOC Action" ,
 "Unicast Priority/Weight<br>Multicast Priority/Weight" )
 if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
 I1i1iii = lisp . lisp_map_cache . walk_cache ( lisp_walk_map_cache , I1i1iii )
 I1i1iii += lisp_table_footer ( )
 if 46 - 46: Ii1I
 if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
 if 87 - 87: I1ii11iIi11i / I1IiiI
 if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
 if ( len ( lisp . lisp_elp_list ) != 0 ) : I1i1iii = lisp_show_elp_list ( I1i1iii )
 if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
 if 11 - 11: I1ii11iIi11i - OoooooooOO
 if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
 if 27 - 27: IiII + iIii1I11I1II1 / Oo0Ooo + OoO0O00 % Oo0Ooo + OoO0O00
 if ( len ( lisp . lisp_rle_list ) != 0 ) : I1i1iii = lisp_show_rle_list ( I1i1iii )
 if 77 - 77: Oo0Ooo * ooOoO0o % Ii1I
 if 2 - 2: I11i / Oo0Ooo / Ii1I / I1ii11iIi11i / OoooooooOO
 if 22 - 22: iIii1I11I1II1 * I1IiiI / I11i + OoOoOO00
 if 98 - 98: OOooOOo
 if ( len ( lisp . lisp_json_list ) != 0 ) : I1i1iii = lisp_show_json_list ( I1i1iii )
 if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
 if 75 - 75: OoO0O00 % OoooooooOO
 if 16 - 16: O0 / i1IIi
 if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
 if ( itr_or_rtr == "RTR" ) :
  I1i1iii = lisp_display_nat_info ( I1i1iii , "Data" , dns )
  if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
  if 12 - 12: OoOoOO00 + o0oOOo0O0Ooo . I1Ii111
  if 52 - 52: OoO0O00
  if 4 - 4: Ii1I % I1ii11iIi11i + I11i - I1ii11iIi11i
  if 98 - 98: Ii1I - O0 * oO0o * Ii1I * Ii1I
 return ( I1i1iii )
 if 44 - 44: IiII + I11i
 if 66 - 66: oO0o
 if 34 - 34: iII111i % i11iIiiIii + i11iIiiIii - iII111i
 if 2 - 2: II111iiii + i1IIi
 if 68 - 68: OOooOOo + Ii1I
 if 58 - 58: IiII * Ii1I . i1IIi
 if 19 - 19: oO0o
def lisp_itr_rtr_show_rloc_probe_command ( itr_or_rtr ) :
 o0000oO = "LISP-{} RLOC-Probe Information:" . format ( itr_or_rtr )
 I1i1iii = lisp_table_header ( o0000oO , "RLOC Key State" , "RLOC-Probe State" )
 if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
 for oo0O0O in list ( lisp . lisp_rloc_probe_list . values ( ) ) :
  OOOO0oo0 = ""
  for O0O0O0OO00oo , IIIIiI1ii1 , ooOO0oo00Oo in oo0O0O :
   i1I11I1i = lisp . green ( lisp . lisp_print_eid_tuple ( IIIIiI1ii1 , ooOO0oo00Oo ) , True )
   OOOO0oo0 += lisp . lisp_print_cour ( i1I11I1i ) + "<br>"
   if 100 - 100: oO0o
  OOOO0oo0 = ", EIDs ({}):<br>" . format ( len ( oo0O0O ) ) + OOOO0oo0
  if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
  O0O0O0OO00oo , IIIIiI1ii1 , ooOO0oo00Oo = oo0O0O [ 0 ]
  if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
  if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
  if 75 - 75: IiII / OoooooooOO . I1IiiI + I1Ii111 - II111iiii
  if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
  o0 = lisp . lisp_hex_string ( O0O0O0OO00oo . last_rloc_probe_nonce )
  if ( O0O0O0OO00oo . translated_port == 0 ) :
   ii1iI11IiIIi = O0O0O0OO00oo . rloc . print_address_no_iid ( )
  else :
   ii1iI11IiIIi = "{}{}{}" . format ( O0O0O0OO00oo . rloc . print_address_no_iid ( ) ,
 lisp . bold ( ":" , True ) , O0O0O0OO00oo . translated_port )
   if 47 - 47: OOooOOo . oO0o + OoOoOO00 % IiII % i1IIi / iIii1I11I1II1
  ii1iI11IiIIi = lisp . bold ( lisp . lisp_print_cour ( ii1iI11IiIIi ) , True )
  ooIii = O0O0O0OO00oo . rloc_name
  if ( ooIii != None ) :
   ooIii = lisp . bold ( ooIii , True )
   ii1iI11IiIIi += ", {}" . format ( lisp . lisp_print_cour ( lisp . blue ( ooIii , True ) ) )
   if 66 - 66: OOooOOo * o0oOOo0O0Ooo
  iIIiI = O0O0O0OO00oo . print_state ( )
  if ( O0O0O0OO00oo . up_state ( ) == False ) : iIIiI = lisp . red ( O0O0O0OO00oo . print_state ( ) , True )
  ii1iI11IiIIi = "RLOC " + ii1iI11IiIIi + ", {}" . format ( iIIiI )
  if 58 - 58: iIii1I11I1II1 % OOooOOo + I1Ii111 - I1Ii111 . i11iIiiIii + OoooooooOO
  i1iIII1IIi = ii1iI11IiIIi + OOOO0oo0
  if 63 - 63: II111iiii . I1Ii111 % IiII + II111iiii
  if 81 - 81: OOooOOo - I1IiiI % o0oOOo0O0Ooo
  if 7 - 7: ooOoO0o - i1IIi . OoOoOO00
  if 12 - 12: IiII / OoO0O00 / O0 * IiII
  o0o0oo0OOo0O0 = [ O0O0O0OO00oo ]
  if ( O0O0O0OO00oo . multicast_rloc_probe_list != { } ) :
   o0o0oo0OOo0O0 += list ( O0O0O0OO00oo . multicast_rloc_probe_list . values ( ) )
   if 37 - 37: o0oOOo0O0Ooo * Oo0Ooo
   if 11 - 11: oO0o
   if 62 - 62: OoooooooOO % oO0o * II111iiii * I1Ii111 * I1Ii111 / ooOoO0o
   if 90 - 90: I1Ii111 . II111iiii . I1ii11iIi11i
   if 32 - 32: ooOoO0o - OoO0O00 . iII111i . iII111i % i1IIi * Ii1I
  o0o0 = ""
  for O0O0O0OO00oo in o0o0oo0OOo0O0 :
   if ( len ( o0o0oo0OOo0O0 ) != 1 ) :
    ii1iI11IiIIi = O0O0O0OO00oo . rloc . print_address_no_iid ( )
    ii1iI11IiIIi = lisp . bold ( lisp . lisp_print_cour ( ii1iI11IiIIi ) , True )
    if ( o0o0oo0OOo0O0 . index ( O0O0O0OO00oo ) != 0 ) : o0o0 += "<br><br>"
    if ( O0O0O0OO00oo . rloc . is_multicast_address ( ) ) :
     o0o0 += "RLOC {}:<br>" . format ( ii1iI11IiIIi )
    else :
     ooIii = ", " + O0O0O0OO00oo . rloc_name if O0O0O0OO00oo . rloc_name != None else ""
     o0o0 += "mRLOC {}{}:<br>" . format ( ii1iI11IiIIi , ooIii )
     if 28 - 28: I11i . OoooooooOO * OOooOOo + i11iIiiIii % I1IiiI . iIii1I11I1II1
     if 63 - 63: II111iiii - I11i . OoOoOO00
     if 8 - 8: I1IiiI * ooOoO0o / IiII + OoOoOO00 . IiII - OOooOOo
   Oo0O = lisp . lisp_print_elapsed ( O0O0O0OO00oo . last_rloc_probe )
   Oo0O = lisp . lisp_print_cour ( Oo0O )
   oO00OO0o0ooO = lisp . lisp_print_elapsed ( O0O0O0OO00oo . last_rloc_probe_reply )
   oO00OO0o0ooO = lisp . lisp_print_cour ( oO00OO0o0ooO )
   o0 = lisp . lisp_hex_string ( O0O0O0OO00oo . last_rloc_probe_nonce )
   o0 = lisp . lisp_print_cour ( "0x" + o0 )
   Iii1iIIIi11I1 = lisp . lisp_print_cour ( str ( hex ( id ( O0O0O0OO00oo ) ) ) )
   o0o0 += ( "RLOC-memory: {}<br>Last probe-request sent: {}, " + "last probe-reply received: {}, nonce: {}<br>" ) . format ( Iii1iIIIi11I1 , Oo0O ,
   # I1Ii111 - oO0o + I1ii11iIi11i
 oO00OO0o0ooO , o0 )
   if 80 - 80: iIii1I11I1II1 - Oo0Ooo % I1Ii111 % Oo0Ooo + I1IiiI % Ii1I
   IIi = O0O0O0OO00oo . print_recent_rloc_probe_rtts ( )
   IIi = lisp . lisp_print_cour ( IIi )
   O00O00oO = O0O0O0OO00oo . print_recent_rloc_probe_hops ( )
   O00O00oO = lisp . lisp_print_cour ( O00O00oO )
   I11 = O0O0O0OO00oo . print_recent_rloc_probe_latencies ( )
   I11 = lisp . lisp_print_cour ( I11 )
   O0O0o = O0O0O0OO00oo . print_rloc_probe_hops ( )
   O0O0o = lisp . lisp_print_cour ( O0O0o )
   I111Ii111 = O0O0O0OO00oo . print_rloc_probe_latency ( )
   I111Ii111 = lisp . lisp_print_cour ( I111Ii111 )
   O0O0O0OO00oo = O0O0O0OO00oo . print_rloc_probe_rtt ( )
   O0O0O0OO00oo = lisp . lisp_print_cour ( O0O0O0OO00oo )
   o0o0 += ( "Telemetry: rtt: {}, hops: {}, latency: {}<br>" + "recent-rtts: {}, recent-hops: {}, recent-latencies: {}" ) . format ( O0O0O0OO00oo , O0O0o , I111Ii111 , IIi , O00O00oO , I11 )
   if 45 - 45: OoOoOO00
   if 100 - 100: i1IIi % Ii1I
   if 55 - 55: I1IiiI + iII111i
   if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
   if 19 - 19: I11i / iII111i + IiII
   if 76 - 76: iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo + OoooooooOO
   if 10 - 10: OoO0O00 * I11i / Oo0Ooo - I1Ii111
  I1i1iii += lisp_table_row ( i1iIII1IIi , o0o0 )
  if 11 - 11: IiII % I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - II111iiii
  if 50 - 50: i1IIi * oO0o / i11iIiiIii / i11iIiiIii / oO0o
 I1i1iii += lisp_table_footer ( )
 return ( I1i1iii )
 if 84 - 84: I1ii11iIi11i - iII111i + I1ii11iIi11i
 if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
 if 96 - 96: IiII
 if 99 - 99: iIii1I11I1II1 - ooOoO0o
 if 79 - 79: I1IiiI + oO0o % I11i % oO0o
 if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
 if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
def lisp_xtr_command ( kv_pair ) :
 if 99 - 99: o0oOOo0O0Ooo + OOooOOo
 if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
 if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
 if 76 - 76: oO0o / OoOoOO00
 if 12 - 12: I1Ii111
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) :
  kv_pair [ "ipc-data-plane" ] = [ "yes" ]
  if 58 - 58: OoO0O00 + iIii1I11I1II1 % O0 + I11i + OoOoOO00 * OoooooooOO
  if 41 - 41: oO0o * I1IiiI
 for iiiI11 in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ iiiI11 ] [ 0 ]
  if ( iiiI11 == "rloc-probing" ) :
   lisp . lisp_rloc_probing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_rloc_probe_list = { }
   if 76 - 76: oO0o . O0 * OoooooooOO + ooOoO0o
  if ( iiiI11 == "nonce-echoing" ) :
   lisp . lisp_nonce_echoing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_nonce_echo_list = { }
   if 53 - 53: Oo0Ooo
  if ( iiiI11 == "data-plane-security" ) :
   lisp . lisp_data_plane_security = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) :
    lisp . lisp_crypto_keys_by_nonce = { }
    lisp . lisp_crypto_keys_by_rloc_encap = { }
    lisp . lisp_crypto_keys_by_rloc_decap = { }
    if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
    if 58 - 58: IiII % iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * iII111i
  if ( iiiI11 == "data-plane-logging" ) :
   lisp . lisp_data_plane_logging = ( oo00oO0O0 == "yes" )
   if 32 - 32: OoooooooOO + o0oOOo0O0Ooo
  if ( iiiI11 == "frame-logging" ) :
   lisp . lisp_frame_logging = ( oo00oO0O0 == "yes" )
   if 91 - 91: ooOoO0o - I1Ii111 * I1Ii111
  if ( iiiI11 == "flow-logging" ) :
   lisp . lisp_flow_logging = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "yes" ) : os . system ( "touch ./log-flows" )
   if 55 - 55: iIii1I11I1II1 + I1IiiI - Oo0Ooo
  if ( iiiI11 == "nat-traversal" ) :
   lisp . lisp_nat_traversal = ( oo00oO0O0 == "yes" )
   if 24 - 24: OoO0O00 / I1Ii111 + iII111i * I11i * iII111i
  if ( iiiI11 == "decentralized-nat" ) :
   lisp . lisp_decent_nat = ( oo00oO0O0 == "yes" )
   if 10 - 10: I1IiiI - I1ii11iIi11i - Oo0Ooo - o0oOOo0O0Ooo
  if ( iiiI11 == "program-hardware" ) :
   lisp . lisp_program_hardware = ( oo00oO0O0 == "yes" )
   if 21 - 21: OoooooooOO + I1Ii111
  if ( iiiI11 == "checkpoint-map-cache" ) :
   lisp . lisp_checkpoint_map_cache = ( oo00oO0O0 == "yes" )
   iiIi1111Ii1 = lisp . lisp_checkpoint_filename
   if ( oo00oO0O0 == "no" and os . path . exists ( iiIi1111Ii1 ) ) :
    os . system ( "rm {}" . format ( iiIi1111Ii1 ) )
    if 31 - 31: o0oOOo0O0Ooo * I11i - i11iIiiIii - I1IiiI
    if 19 - 19: iII111i . I11i * OoooooooOO - OOooOOo + O0 * I1Ii111
  if ( iiiI11 == "ipc-data-plane" ) :
   OoI1 = ( oo00oO0O0 == "yes" )
   if ( OoI1 and lisp . lisp_ipc_data_plane == False ) :
    iIIi11 = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
    lisp . lisp_ipc_dp_socket = iIIi11
    if 21 - 21: i11iIiiIii * iII111i / ooOoO0o % iII111i * Oo0Ooo
   if ( OoI1 == False and lisp . lisp_ipc_data_plane ) :
    lisp . lisp_ipc_dp_socket . close ( )
    lisp . lisp_ipc_dp_socket = None
    if 84 - 84: iIii1I11I1II1
   lisp . lisp_ipc_data_plane = OoI1
   if 25 - 25: OoO0O00 * IiII - i1IIi - I11i * II111iiii
  if ( iiiI11 == "decentralized-push-xtr" ) :
   lisp . lisp_decent_push_configured = ( oo00oO0O0 == "yes" )
   if 70 - 70: II111iiii + iII111i * OoOoOO00
  if ( iiiI11 == "decentralized-pull-xtr-modulus" ) :
   lisp . lisp_decent_modulus = int ( oo00oO0O0 )
   if 61 - 61: OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
  if ( iiiI11 == "decentralized-pull-xtr-dns-suffix" ) :
   lisp . lisp_decent_dns_suffix = oo00oO0O0
   if 91 - 91: I1IiiI / II111iiii * OOooOOo
  if ( iiiI11 == "register-reachable-rtrs" ) :
   lisp . lisp_register_all_rtrs = ( oo00oO0O0 == "no" )
   if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
   if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
 return
 if 81 - 81: OoO0O00 - iIii1I11I1II1
 if 60 - 60: I1Ii111
 if 77 - 77: I1IiiI / I1ii11iIi11i
 if 95 - 95: I1Ii111 * i1IIi + oO0o
 if 40 - 40: II111iiii
 if 7 - 7: OOooOOo / OoO0O00
 if 88 - 88: i1IIi
def lisp_show_json_list ( output ) :
 if 53 - 53: ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
 o0000oO = "Configured JSON Entries:"
 output += lisp_table_header ( o0000oO , "JSON Name" , "JSON String" )
 if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
 o00OoOO00 = sorted ( lisp . lisp_json_list )
 for oO0oOOoOo000O in o00OoOO00 :
  I1Iiiiiii = lisp . lisp_json_list [ oO0oOOoOo000O ]
  II1 = lisp . lisp_print_cour ( I1Iiiiiii . print_json ( True ) )
  output += lisp_table_row ( oO0oOOoOo000O , II1 )
  if 55 - 55: iII111i + Oo0Ooo
 output += lisp_table_footer ( )
 return ( output )
 if 95 - 95: I11i + Oo0Ooo + Oo0Ooo
 if 33 - 33: i1IIi % OoooooooOO / OoooooooOO
 if 88 - 88: I1Ii111 - Ii1I - oO0o + i1IIi
 if 15 - 15: OOooOOo
 if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
 if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
 if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
def lisp_show_rle_list ( output ) :
 if 62 - 62: OOooOOo * O0 % IiII . IiII . I1IiiI
 o0000oO = "Configured Replication List Entries (RLEs):"
 output += lisp_table_header ( o0000oO , "RLE Name" , "RLE Nodes" )
 if 91 - 91: i1IIi . iII111i
 I1I1iiI1i = sorted ( lisp . lisp_rle_list )
 for IiII1111I in I1I1iiI1i :
  iI1 = lisp . lisp_rle_list [ IiII1111I ]
  output += lisp_table_row ( IiII1111I , iI1 . print_rle ( True , True ) )
  if 15 - 15: iIii1I11I1II1 % Oo0Ooo + OoooooooOO
 output += lisp_table_footer ( )
 return ( output )
 if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
 if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
 if 95 - 95: oO0o
 if 80 - 80: IiII
 if 42 - 42: OoooooooOO * II111iiii
 if 53 - 53: I1Ii111 + i1IIi . OoO0O00 / i11iIiiIii + Ii1I % OoOoOO00
 if 9 - 9: ooOoO0o . I11i - Oo0Ooo . I1Ii111
def lisp_show_elp_list ( output ) :
 o0000oO = "Configured Explicit Locator Paths (ELPs):"
 output += lisp_table_header ( o0000oO , "ELP Name" , "ELP Nodes" )
 if 39 - 39: OOooOOo
 o00OO00OOo0 = sorted ( lisp . lisp_elp_list )
 for ooOo00ooO in o00OO00OOo0 :
  IiiiIIIi11ii1 = lisp . lisp_elp_list [ ooOo00ooO ]
  output += lisp_table_row ( ooOo00ooO , IiiiIIIi11ii1 . print_elp ( False ) )
  if 16 - 16: IiII % i11iIiiIii . IiII % OoooooooOO - oO0o
 output += lisp_table_footer ( )
 return ( output )
 if 88 - 88: Ii1I * iIii1I11I1II1 . I11i
 if 20 - 20: O0 . i11iIiiIii * i1IIi % O0 . I1IiiI
 if 53 - 53: ooOoO0o / OoooooooOO - II111iiii
 if 68 - 68: OoooooooOO . OoooooooOO . iIii1I11I1II1 / ooOoO0o - I11i % O0
 if 19 - 19: OoooooooOO * oO0o
 if 60 - 60: II111iiii - iII111i + o0oOOo0O0Ooo % OOooOOo
 if 97 - 97: O0 % O0
def lisp_geo_command ( kv_pair ) :
 if 35 - 35: iII111i - Ii1I . i11iIiiIii % O0 % I1ii11iIi11i
 if 92 - 92: OOooOOo % II111iiii . iII111i
 if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
 if 47 - 47: iII111i * OoOoOO00 * IiII
 if ( "geo-name" not in kv_pair ) : return
 iIiii1IIi1I = kv_pair [ "geo-name" ]
 IiIi = lisp . lisp_geo ( iIiii1IIi1I )
 if 34 - 34: Oo0Ooo
 if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
 if 33 - 33: i1IIi / iII111i * OoO0O00
 if 2 - 2: oO0o . OOooOOo
 if ( "geo-tag" not in kv_pair ) : return
 if 43 - 43: iIii1I11I1II1
 if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
 if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
 if 98 - 98: i1IIi - iII111i
 iIIiII11iI1 = kv_pair [ "geo-tag" ] [ 1 : : ]
 if ( IiIi . parse_geo_string ( iIIiII11iI1 ) == False ) : return
 if 80 - 80: iII111i . O0
 if 25 - 25: iII111i / iIii1I11I1II1 + I1IiiI / ooOoO0o
 if 61 - 61: oO0o % I1ii11iIi11i * I11i . I11i
 if 20 - 20: Ii1I / iII111i + II111iiii . i11iIiiIii . OOooOOo
 lisp . lisp_geo_list [ iIiii1IIi1I ] = IiIi
 return
 if 77 - 77: OoOoOO00
 if 91 - 91: oO0o
 if 56 - 56: iIii1I11I1II1 % II111iiii / OoOoOO00 % OoooooooOO
 if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
 if 84 - 84: II111iiii
 if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
 if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
def lisp_elp_command ( kv_pair ) :
 if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
 IiiiIIIi11ii1 = None
 ooiIi11i1I11Ii = [ ]
 if ( "address" in kv_pair ) :
  for o00oo in range ( len ( kv_pair [ "address" ] ) ) :
   oo0OO0oo = lisp . lisp_elp_node ( )
   ooiIi11i1I11Ii . append ( oo0OO0oo )
   if 54 - 54: II111iiii % o0oOOo0O0Ooo - i1IIi . I1IiiI - II111iiii / iIii1I11I1II1
   if 29 - 29: oO0o
   if 66 - 66: OoooooooOO + iII111i . IiII % i1IIi
 for iiiI11 in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ iiiI11 ]
  if 58 - 58: OOooOOo % iII111i * O0 + I1ii11iIi11i - IiII
  if ( iiiI11 == "elp-name" ) :
   IiiiIIIi11ii1 = lisp . lisp_elp ( oo00oO0O0 )
   continue
   if 26 - 26: i1IIi / I1IiiI / I11i + I11i
   if 46 - 46: I1Ii111 % I1ii11iIi11i + Ii1I
  for Ooii in ooiIi11i1I11Ii :
   O0OO0O = ooiIi11i1I11Ii . index ( Ooii )
   if ( O0OO0O >= len ( oo00oO0O0 ) ) : O0OO0O = len ( oo00oO0O0 ) - 1
   oooooO00OOO = oo00oO0O0 [ O0OO0O ]
   if ( iiiI11 == "probe" ) : Ooii . probe = ( oooooO00OOO == "yes" )
   if ( iiiI11 == "strict" ) : Ooii . strict = ( oooooO00OOO == "yes" )
   if ( iiiI11 == "eid" ) : Ooii . eid = ( oooooO00OOO == "yes" )
   if ( iiiI11 == "address" ) : Ooii . address . store_address ( oooooO00OOO )
   if 28 - 28: OoO0O00
   if 73 - 73: Oo0Ooo . ooOoO0o - Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1
   if 15 - 15: ooOoO0o * iIii1I11I1II1 * oO0o
   if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
   if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
   if 47 - 47: IiII . OOooOOo
 if ( IiiiIIIi11ii1 == None ) : return
 if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
 if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
 if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
 if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
 IiiiIIIi11ii1 . elp_nodes = ooiIi11i1I11Ii
 lisp . lisp_elp_list [ IiiiIIIi11ii1 . elp_name ] = IiiiIIIi11ii1
 return
 if 89 - 89: ooOoO0o * I1IiiI . oO0o
 if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
 if 26 - 26: I11i * Ii1I % I1IiiI + iII111i
 if 38 - 38: iII111i - Oo0Ooo / Ii1I + oO0o . iII111i + IiII
 if 19 - 19: Ii1I
 if 51 - 51: iIii1I11I1II1
 if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
def lisp_rle_command ( kv_pair ) :
 if 8 - 8: OoO0O00 * Oo0Ooo
 iI1 = None
 IIiII = [ ]
 if ( "address" in kv_pair ) :
  for o00oo in range ( len ( kv_pair [ "address" ] ) ) :
   IIi1 = lisp . lisp_rle_node ( )
   IIiII . append ( IIi1 )
   if 87 - 87: O0 - oO0o % Oo0Ooo
   if 98 - 98: i11iIiiIii . I1Ii111 + OoOoOO00
   if 55 - 55: I11i
 for iiiI11 in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ iiiI11 ]
  if 72 - 72: I11i + ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
  if ( iiiI11 == "rle-name" ) :
   iI1 = lisp . lisp_rle ( oo00oO0O0 )
   continue
   if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
   if 70 - 70: II111iiii * II111iiii . I1IiiI
  for Ooii in IIiII :
   O0OO0O = IIiII . index ( Ooii )
   if ( O0OO0O >= len ( oo00oO0O0 ) ) : O0OO0O = len ( oo00oO0O0 ) - 1
   oooooO00OOO = oo00oO0O0 [ O0OO0O ]
   if ( iiiI11 == "level" ) :
    if ( oooooO00OOO == "" ) : oooooO00OOO = "0"
    Ooii . level = int ( oooooO00OOO )
    if 11 - 11: iII111i
   if ( iiiI11 == "address" ) : Ooii . rloc . rloc . store_address ( oooooO00OOO )
   if 20 - 20: Ii1I . I1Ii111 % Ii1I
   if 5 - 5: OOooOOo + iII111i
   if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
   if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
   if 11 - 11: I1ii11iIi11i / O0 + II111iiii
   if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
 if ( iI1 == None ) : return
 if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
 if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
 if 2 - 2: Ii1I
 if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
 iI1 . rle_nodes = IIiII
 iI1 . build_rle_forwarding_list ( )
 lisp . lisp_rle_list [ iI1 . rle_name ] = iI1
 return
 if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
 if 81 - 81: iIii1I11I1II1
 if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
 if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
 if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
 if 7 - 7: IiII
 if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
def lisp_json_command ( kv_pair ) :
 if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
 try :
  oO0oOOoOo000O = kv_pair [ "json-name" ]
  II1 = kv_pair [ "json-string" ]
 except :
  return
  if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
  if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
 I1Iiiiiii = lisp . lisp_json ( oO0oOOoOo000O , II1 )
 I1Iiiiiii . add ( )
 return
 if 91 - 91: I1IiiI + o0oOOo0O0Ooo % II111iiii + OoO0O00
 if 66 - 66: iIii1I11I1II1 * II111iiii % Oo0Ooo % I1IiiI - Ii1I
 if 59 - 59: IiII % oO0o
 if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
 if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
 if 93 - 93: I1ii11iIi11i * I1ii11iIi11i / OoooooooOO
 if 6 - 6: I1ii11iIi11i * Oo0Ooo + iIii1I11I1II1
 if 19 - 19: O0 % II111iiii * o0oOOo0O0Ooo
 if 27 - 27: OOooOOo * IiII / i11iIiiIii - oO0o + II111iiii
 if 43 - 43: I1ii11iIi11i - II111iiii
 if 56 - 56: I1ii11iIi11i . i1IIi / iII111i % oO0o / O0 * I11i
 if 98 - 98: O0 + iII111i
def lisp_get_lookup_string ( input_str ) :
 if 23 - 23: OoooooooOO . iIii1I11I1II1 / i1IIi
 if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
 if 74 - 74: Oo0Ooo - II111iiii - IiII
 if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
 OOOO0oo0 = input_str
 I11iiI1i1 = None
 if ( input_str . find ( "->" ) != - 1 ) :
  I1i1Iiiii = input_str . split ( "->" )
  OOOO0oo0 = I1i1Iiiii [ 0 ]
  I11iiI1i1 = I1i1Iiiii [ 1 ]
  if 70 - 70: i1IIi % OoO0O00 / i1IIi
  if 30 - 30: OoOoOO00 - i11iIiiIii
 oO0OOOO00o = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 i1Ii1I = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if 60 - 60: ooOoO0o * Ii1I + I1Ii111 . OOooOOo . O0
 if 8 - 8: II111iiii + II111iiii * i1IIi * o0oOOo0O0Ooo / O0 / O0
 if 66 - 66: I1Ii111 * o0oOOo0O0Ooo / IiII * iII111i / OoooooooOO
 if 72 - 72: iIii1I11I1II1
 oO0 = OOOO0oo0 . split ( "/" )
 if ( len ( oO0 ) == 1 ) :
  oO0OOOO00o . store_address ( oO0 [ 0 ] )
  ooo00OoOooooo = False
 else :
  oO0OOOO00o . store_prefix ( OOOO0oo0 )
  ooo00OoOooooo = True
  if 87 - 87: II111iiii - OoooooooOO / i1IIi . Ii1I - Oo0Ooo . i11iIiiIii
  if 47 - 47: Oo0Ooo % OoO0O00 - ooOoO0o - Oo0Ooo * oO0o
 OOOOO0oOOoO = ooo00OoOooooo
 if ( I11iiI1i1 ) :
  oO0 = I11iiI1i1 . split ( "/" )
  if ( len ( oO0 ) == 1 ) :
   i1Ii1I . store_address ( oO0 [ 0 ] )
   OOOOO0oOOoO = False
  else :
   i1Ii1I . store_prefix ( OOOO0oo0 )
   OOOOO0oOOoO = True
   if 42 - 42: I1IiiI + i11iIiiIii / OoO0O00
   if 64 - 64: IiII
 return ( [ oO0OOOO00o , ooo00OoOooooo , i1Ii1I , OOOOO0oOOoO ] )
 if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
 if 89 - 89: O0 + IiII * I1Ii111
 if 30 - 30: OoOoOO00
 if 39 - 39: I1ii11iIi11i + o0oOOo0O0Ooo + I1Ii111 + IiII
 if 48 - 48: I1Ii111 / ooOoO0o . iIii1I11I1II1
 if 72 - 72: i1IIi . o0oOOo0O0Ooo
 if 3 - 3: OoOoOO00 % II111iiii - O0
def lisp_show_map_cache_lookup ( eid_str ) :
 oO0OOOO00o , ooo00OoOooooo , i1Ii1I , OOOOO0oOOoO = lisp_get_lookup_string ( eid_str )
 if 52 - 52: OoO0O00
 I1i1iii = "<br>"
 if 49 - 49: Ii1I . I1ii11iIi11i % ooOoO0o . Oo0Ooo * OOooOOo
 Ii1iI = oO0OOOO00o if ( i1Ii1I . is_null ( ) ) else i1Ii1I
 i1iII = ooo00OoOooooo if ( i1Ii1I . is_null ( ) ) else OOOOO0oOOoO
 if 83 - 83: o0oOOo0O0Ooo
 IIiI1i = lisp . lisp_map_cache . lookup_cache ( Ii1iI , i1iII )
 if ( IIiI1i == None ) :
  I1i1iii += "{} {}" . format ( lisp . lisp_print_sans ( "Lookup not found for" ) ,
 lisp . lisp_print_cour ( eid_str ) )
 else :
  if ( Ii1iI == i1Ii1I ) :
   IiooO00Oo = IIiI1i . lookup_source_cache ( oO0OOOO00o , ooo00OoOooooo )
   if ( IiooO00Oo ) : IIiI1i = IiooO00Oo
   if 46 - 46: ooOoO0o - ooOoO0o * I1ii11iIi11i / iII111i * OOooOOo / o0oOOo0O0Ooo
   if 67 - 67: OOooOOo - Ii1I % iII111i / II111iiii + I1IiiI * ooOoO0o
  oO0OOoO0 = lisp . lisp_print_elapsed ( IIiI1i . uptime )
  I1i1iii += "{} {} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Exact" if ooo00OoOooooo else "Longest" ) ,
  # I1ii11iIi11i . II111iiii % I1ii11iIi11i % i1IIi * OoOoOO00 * OoooooooOO
 lisp . lisp_print_sans ( "match lookup for" ) ,
 lisp . lisp_print_cour ( eid_str ) ,
 lisp . lisp_print_sans ( "found" ) ,
 lisp . lisp_print_cour ( IIiI1i . print_eid_tuple ( ) ) ,
 lisp . lisp_print_sans ( "with uptime" ) ,
 lisp . lisp_print_cour ( oO0OOoO0 ) )
  if 10 - 10: I11i + I1IiiI + OoooooooOO . OoOoOO00
 I1i1iii += "<br>"
 return ( I1i1iii )
 if 93 - 93: I1IiiI
 if 89 - 89: OoooooooOO % i11iIiiIii + I1Ii111
 if 12 - 12: OoOoOO00 * ooOoO0o
 if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
 if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
 if 50 - 50: ooOoO0o
 if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
 if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
def lisp_get_clause_for_api ( command ) :
 i1i1I1II = open ( "./lisp.config" , "r" )
 OOoO0o = { command : [ ] }
 O0ooO0oOO = { }
 OoOoO = [ ]
 if 70 - 70: oO0o
 O00o = 0
 o0o0oO = False
 for O00oO0 in i1i1I1II :
  if ( lisp_end_file ( O00oO0 ) ) : break
  if ( lisp_comment ( O00oO0 ) ) : continue
  if 69 - 69: IiII
  if 67 - 67: Oo0Ooo % II111iiii - OoO0O00 % i1IIi % ooOoO0o
  if 31 - 31: iIii1I11I1II1 / OoooooooOO
  if 8 - 8: iIii1I11I1II1 . iIii1I11I1II1 + Ii1I . OOooOOo
  if 58 - 58: iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - i1IIi * OoOoOO00
  if 4 - 4: OoooooooOO
  if ( O00oO0 . find ( command + " {" ) != - 1 ) :
   O00o += 1
   o0o0oO = True
   continue
   if 7 - 7: IiII
  if ( o0o0oO == False ) : continue
  if 26 - 26: OOooOOo + Oo0Ooo
  if ( lisp_begin_clause ( O00oO0 ) ) :
   O00o += 1
   oo0iI1i11II1i1i = O00oO0 . replace ( " " , "" )
   oo0iI1i11II1i1i = oo0iI1i11II1i1i . replace ( "\t" , "" )
   oo0iI1i11II1i1i = oo0iI1i11II1i1i . replace ( "\n" , "" )
   oo0iI1i11II1i1i = oo0iI1i11II1i1i . replace ( "{" , "" )
   O0ooO0oOO = { oo0iI1i11II1i1i : { } }
   continue
   if 61 - 61: I11i * Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
   if 51 - 51: OOooOOo / I11i
   if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
   if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
   if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
   if 26 - 26: i11iIiiIii - ooOoO0o
  if ( lisp_end_clause ( O00oO0 ) ) :
   O00o -= 1
   if ( O00o ) :
    OOoO0o [ command ] . append ( O0ooO0oOO )
    O0ooO0oOO = { }
    continue
    if 45 - 45: ooOoO0o + II111iiii % iII111i
   OoOoO . append ( OOoO0o )
   OOoO0o = { command : [ ] }
   o0o0oO = False
   continue
   if 55 - 55: ooOoO0o - oO0o % I1IiiI
   if 61 - 61: ooOoO0o
  O00oO0 = O00oO0 . replace ( " " , "" )
  O00oO0 = O00oO0 . replace ( "\t" , "" )
  O00oO0 = O00oO0 . replace ( "\n" , "" )
  O00oO0 = O00oO0 . replace ( "{" , "" )
  O00oO0 = O00oO0 . split ( "=" )
  oo00oO0O0 = "" if len ( O00oO0 ) == 1 else O00oO0 [ 1 ]
  oo000O0o = O00oO0 [ 0 ]
  if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
  if ( len ( O0ooO0oOO ) == 0 ) :
   OOoO0o [ command ] . append ( { oo000O0o : oo00oO0O0 } )
  else :
   O0ooO0oOO [ oo0iI1i11II1i1i ] [ oo000O0o ] = oo00oO0O0
   if 21 - 21: oO0o . i11iIiiIii * I11i . OOooOOo / OOooOOo
   if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
   if 1 - 1: Ii1I % I1Ii111
 i1i1I1II . close ( )
 if 97 - 97: OoOoOO00
 if ( len ( OoOoO ) == 0 ) :
  OoOoO = [ { "?" : [ { "?" : "not-found" } ] } ]
  if 13 - 13: OoOoOO00 % OOooOOo . O0 / Oo0Ooo % Oo0Ooo
 return ( OoOoO )
 if 19 - 19: I1Ii111 % ooOoO0o - ooOoO0o % I1IiiI . OOooOOo - OoooooooOO
 if 100 - 100: I1IiiI + Ii1I + o0oOOo0O0Ooo . i1IIi % OoooooooOO
 if 64 - 64: O0 % i1IIi * I1Ii111 - Ii1I + Oo0Ooo
 if 65 - 65: OoOoOO00 . i11iIiiIii
 if 36 - 36: oO0o * iII111i + IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1
 if 14 - 14: I11i * oO0o + i11iIiiIii
 if 84 - 84: iII111i / II111iiii
def lisp_duplicate_command_clause ( command , clause ) :
 Oo0O0Oo00O = open ( "./lisp.config" , "r" )
 if 86 - 86: I1IiiI
 clause = command + " {\n" + clause
 for O00oO0 in Oo0O0Oo00O :
  if ( lisp_begin_clause ( O00oO0 ) == False ) : continue
  if ( O00oO0 . find ( command ) == - 1 ) : continue
  if 97 - 97: II111iiii
  iIiIii = O00oO0
  for O00oO0 in Oo0O0Oo00O :
   iIiIii += O00oO0
   if ( O00oO0 [ 0 ] != "}" ) : continue
   if ( iIiIii != clause ) : break
   Oo0O0Oo00O . close ( )
   return ( True )
   if 30 - 30: ooOoO0o
  if ( lisp_end_file ( O00oO0 ) ) : break
  if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
  if 19 - 19: i1IIi % II111iiii
 Oo0O0Oo00O . close ( )
 return ( False )
 if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
 if 56 - 56: Ii1I * i11iIiiIii
 if 92 - 92: II111iiii - O0 . I1Ii111
 if 59 - 59: OoOoOO00
 if 47 - 47: II111iiii - I1ii11iIi11i - Ii1I
 if 9 - 9: I1ii11iIi11i - IiII
 if 64 - 64: i1IIi
def lisp_put_clause_for_api ( data ) :
 if 71 - 71: IiII * o0oOOo0O0Ooo
 if 99 - 99: o0oOOo0O0Ooo
 if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
 if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
 I111i1I1 = list ( data . keys ( ) ) [ 0 ]
 if ( I111i1I1 not in list ( lisp_commands . keys ( ) ) ) :
  return ( [ { I111i1I1 : [ { "?" : "add/replace" } ] } ] )
  if 50 - 50: OoooooooOO + iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii . ooOoO0o
  if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
 i11oO0OoO = ( I111i1I1 in [ "lisp enable" , "lisp debug" , "lisp xtr-parameters" ] )
 if 21 - 21: IiII * OoOoOO00 - I1Ii111
 if 44 - 44: OoooooooOO + Ii1I
 if 84 - 84: i1IIi - II111iiii . OoooooooOO / OoOoOO00 % Ii1I
 if 7 - 7: i1IIi / IiII / iII111i
 if 97 - 97: OoO0O00 + iIii1I11I1II1
 if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
 if 26 - 26: IiII
 oo0o0o = False
 if ( i11oO0OoO == False ) :
  oo0o0o = True
  I1I11I1i1i1II = getoutput ( "egrep '{}' ./lisp.config" . format ( I111i1I1 ) )
  I1I11I1i1i1II = I1I11I1i1i1II . split ( "\n" )
  for O00oO0 in I1I11I1i1i1II :
   if ( O00oO0 [ 0 : len ( I111i1I1 ) ] == I111i1I1 ) : oo0o0o = False
   if 1 - 1: I1IiiI . Ii1I
   if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
   if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
   if 21 - 21: O0 * ooOoO0o % OoO0O00
   if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
   if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
 O000oOo = data [ I111i1I1 ]
 O000oOo = lisp_unicode_to_ascii ( O000oOo )
 OOoO0o = I111i1I1 + " {\n" if oo0o0o else ""
 if 58 - 58: OOooOOo
 if 94 - 94: OoooooooOO - ooOoO0o % OOooOOo - iII111i / i1IIi
 if 5 - 5: OoooooooOO % II111iiii
 if 7 - 7: i11iIiiIii - I11i % Oo0Ooo
 if 76 - 76: OoO0O00 * iII111i % Oo0Ooo . i11iIiiIii / OoooooooOO
 if 85 - 85: OoooooooOO . OoO0O00 . OoO0O00
 if 70 - 70: I11i
 if 72 - 72: I1Ii111 - ooOoO0o - I1IiiI - iII111i + OOooOOo - i1IIi
 for iIiI111ii1Ii in O000oOo :
  if ( type ( O000oOo ) == dict ) :
   oo00oO0O0 = O000oOo [ iIiI111ii1Ii ]
   if ( type ( oo00oO0O0 ) == dict ) : oo00oO0O0 = json_dumps ( oo00oO0O0 )
   OOoO0o += "    " + iIiI111ii1Ii + " = " + oo00oO0O0 + "\n"
   continue
   if 59 - 59: O0 . o0oOOo0O0Ooo % I1ii11iIi11i * oO0o + I11i
   if 82 - 82: OoooooooOO
  for oo000O0o in iIiI111ii1Ii :
   if ( type ( iIiI111ii1Ii ) == dict ) :
    Oo0OIIi = oo000O0o
    oo00oO0O0 = iIiI111ii1Ii [ oo000O0o ]
    if 27 - 27: i11iIiiIii % iII111i + Ii1I . OOooOOo
   if ( type ( iIiI111ii1Ii ) == list ) :
    Oo0OIIi = list ( oo000O0o . keys ( ) ) [ 0 ]
    oo00oO0O0 = list ( oo000O0o . values ( ) ) [ 0 ]
    if 9 - 9: OoO0O00
    if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
   if ( type ( oo00oO0O0 ) != dict ) :
    OOoO0o += "    " + oo000O0o + " = " + iIiI111ii1Ii [ oo000O0o ] + "\n"
    continue
    if 2 - 2: OOooOOo
    if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
    if 79 - 79: Ii1I + oO0o % ooOoO0o % I1IiiI
    if 68 - 68: II111iiii - OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % II111iiii
    if 53 - 53: iII111i . oO0o / Oo0Ooo . OoO0O00 . i11iIiiIii
   OOoO0o += "    " + Oo0OIIi + " {\n"
   for ooOOO in oo00oO0O0 : OOoO0o += "        " + ooOOO + " = " + oo00oO0O0 [ ooOOO ] + "\n"
   OOoO0o += "    }\n"
   if 52 - 52: I1ii11iIi11i + iIii1I11I1II1 / i1IIi / I1IiiI
   if 67 - 67: Ii1I % i11iIiiIii + I11i
 OOoO0o += "}\n"
 if 63 - 63: i1IIi
 if 42 - 42: oO0o - i11iIiiIii % oO0o - I1Ii111 * O0 / II111iiii
 if 5 - 5: Oo0Ooo
 if 84 - 84: I1ii11iIi11i
 if ( lisp_duplicate_command_clause ( I111i1I1 , OOoO0o ) ) :
  return ( [ { I111i1I1 : [ { "!" : "duplicate" } ] } ] )
  if 53 - 53: oO0o
  if 26 - 26: I1Ii111 / I1Ii111 + Oo0Ooo - o0oOOo0O0Ooo % II111iiii . OoooooooOO
 IiiI11Iii = "./lisp.config"
 I1Iii1 = IiiI11Iii + ".temp"
 if 9 - 9: II111iiii % Oo0Ooo * Ii1I + IiII % OoO0O00 . i1IIi
 oo00ooOOoo = open ( IiiI11Iii , "r" )
 O000OOOo = open ( I1Iii1 , "w" )
 if 99 - 99: OoOoOO00 * iII111i
 I1I1i1 = False
 Ii1Ii = False
 for O00oO0 in oo00ooOOoo :
  if ( Ii1Ii ) :
   if ( lisp_end_clause ( O00oO0 ) == False ) : continue
   Ii1Ii = False
   continue
   if 15 - 15: O0
   if 60 - 60: Ii1I % oO0o - I1ii11iIi11i / oO0o
   if 20 - 20: I1IiiI + i1IIi
   if 89 - 89: ooOoO0o % oO0o * Ii1I - Oo0Ooo / o0oOOo0O0Ooo + OoO0O00
   if 56 - 56: i11iIiiIii * iII111i / i11iIiiIii * Ii1I . iIii1I11I1II1 . I1ii11iIi11i
  if ( I1I1i1 == False and lisp_begin_clause ( O00oO0 ) and
 O00oO0 [ 0 : len ( I111i1I1 ) ] == I111i1I1 ) :
   if ( i11oO0OoO == False ) :
    O000OOOo . write ( O00oO0 )
    for oO0oo0 in OOoO0o : O000OOOo . write ( oO0oo0 )
    I1I1i1 = True
    if 12 - 12: i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
    if 8 - 8: o0oOOo0O0Ooo
    if 78 - 78: i1IIi - Oo0Ooo
    if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
    if 42 - 42: I1Ii111
    if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
  if ( lisp_end_file ( O00oO0 ) ) :
   if ( oo0o0o ) :
    for oO0oo0 in OOoO0o : O000OOOo . write ( oO0oo0 )
    if 80 - 80: OOooOOo
   O000OOOo . write ( O00oO0 )
   I1I1i1 = True
   break
   if 12 - 12: Ii1I
   if 2 - 2: OoooooooOO
   if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
   if 46 - 46: O0 % OoooooooOO
   if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
  O000OOOo . write ( O00oO0 )
  if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
  if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
  if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
  if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
  if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
  if ( lisp_begin_clause ( O00oO0 ) and O00oO0 [ 0 : len ( I111i1I1 ) ] == I111i1I1 ) :
   if ( i11oO0OoO ) :
    Ii1Ii = True
    for oO0oo0 in OOoO0o : O000OOOo . write ( oO0oo0 )
    if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
    if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
    if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
    if 65 - 65: I1ii11iIi11i / ooOoO0o
 oo00ooOOoo . close ( )
 O000OOOo . close ( )
 if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
 os . system ( "cp {} {}" . format ( I1Iii1 , IiiI11Iii ) )
 os . system ( "rm {}" . format ( I1Iii1 ) )
 return ( [ { I111i1I1 : [ { "!" : "add/replace" } ] } ] )
 if 57 - 57: iII111i
 if 29 - 29: I1IiiI
 if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
 if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
 if 22 - 22: O0 % IiII % iII111i % I1IiiI
 if 34 - 34: iII111i . Oo0Ooo % I1ii11iIi11i . iII111i % IiII / IiII
 if 84 - 84: Ii1I
 if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
def lisp_remove_clause_for_api ( data ) :
 if 9 - 9: iII111i - iII111i
 if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
 if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
 if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
 I111i1I1 = list ( data . keys ( ) ) [ 0 ]
 if ( I111i1I1 not in list ( lisp_commands . keys ( ) ) ) :
  return ( [ { I111i1I1 : [ { "?" : "delete" } ] } ] )
  if 41 - 41: I1ii11iIi11i % I1ii11iIi11i + IiII . iII111i % I1Ii111 * ooOoO0o
  if 57 - 57: Ii1I . I1Ii111 . II111iiii % OoooooooOO * O0 + iIii1I11I1II1
  if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
  if 93 - 93: ooOoO0o / OOooOOo * O0
  if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
 O000oOo = data [ I111i1I1 ]
 O000oOo = lisp_unicode_to_ascii ( O000oOo )
 if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
 if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
 if 6 - 6: iII111i % o0oOOo0O0Ooo + I1Ii111
 if 91 - 91: o0oOOo0O0Ooo + O0 * oO0o * IiII * I1ii11iIi11i
 oO0oO0OoO00 = [ ]
 oo000O0o = list ( O000oOo . keys ( ) ) [ 0 ]
 oo00oO0O0 = O000oOo [ oo000O0o ]
 if 54 - 54: OoooooooOO * I1IiiI % i1IIi . ooOoO0o % Ii1I . I1ii11iIi11i
 if ( type ( oo00oO0O0 ) == dict ) :
  for oo000O0o in list ( oo00oO0O0 . keys ( ) ) :
   o0O0O0oO0o = oo00oO0O0 [ oo000O0o ]
   oO0oO0OoO00 . append ( oo000O0o + " = " + o0O0O0oO0o )
   if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
 else :
  oO0oO0OoO00 . append ( oo000O0o + " = " + oo00oO0O0 )
  if 63 - 63: ooOoO0o . OOooOOo
  if 66 - 66: I1IiiI
  if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
  if 60 - 60: I1ii11iIi11i
  if 78 - 78: oO0o + II111iiii
  if 55 - 55: OoooooooOO
 if ( I111i1I1 == "lisp user-account" ) :
  OOoO0o = getoutput ( "egrep -A4 '{}' ./lisp.config" . format ( oO0oO0OoO00 [ 0 ] ) )
  if 90 - 90: I1IiiI
  if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
  if ( OOoO0o . find ( "super-user = yes" ) != - 1 ) :
   return ( [ { "lisp user-account" : [ { "?" : "found-superuser" } ] } ] )
   if 30 - 30: IiII
   if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
   if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
   if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
   if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
   if 84 - 84: OoOoOO00 - I11i
   if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
 O0O0oOo0o0o0 = ( "lisp user-account" , "lisp site" , "lisp map-server" ,
 "lisp policy" )
 if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
 IiiI11Iii = "./lisp.config"
 oo00ooOOoo = open ( IiiI11Iii , "r" )
 if 40 - 40: iII111i
 OooOo0OOO = False
 o000 = 0
 for O00oO0 in oo00ooOOoo :
  if ( O00oO0 . find ( I111i1I1 ) == - 1 ) : continue
  o000 += 1
  if 85 - 85: i1IIi % o0oOOo0O0Ooo * I1ii11iIi11i * OoO0O00 . II111iiii
  for O00oO0 in oo00ooOOoo :
   if ( lisp_begin_clause ( O00oO0 ) ) : continue
   O000 = ( lisp_end_clause ( O00oO0 ) and OooOo0OOO )
   if ( O000 ) : break
   if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
   oOoOO00Ooo = O00oO0 . replace ( " " , "" )
   oOoOO00Ooo = oOoOO00Ooo . replace ( "\n" , "" )
   oOoOO00Ooo = oOoOO00Ooo . replace ( "=" , " = " )
   if 49 - 49: i1IIi % oO0o / OOooOOo . I1ii11iIi11i - I1Ii111
   if ( oOoOO00Ooo not in oO0oO0OoO00 ) :
    OooOo0OOO = False
    if ( len ( oO0oO0OoO00 ) > 1 ) : break
    continue
    if 12 - 12: i11iIiiIii + I11i - I1ii11iIi11i
   OooOo0OOO = True
   if 27 - 27: iII111i
   O000 = ( I111i1I1 in O0O0oOo0o0o0 )
   if ( O000 ) : break
   if 22 - 22: OoOoOO00 / I1IiiI
   if 33 - 33: I11i
  if ( O000 ) : break
  if 37 - 37: OoOoOO00 % o0oOOo0O0Ooo * OoO0O00 / i11iIiiIii * II111iiii * iII111i
  if 70 - 70: ooOoO0o . i11iIiiIii % OoOoOO00 + oO0o
 oo00ooOOoo . close ( )
 if 95 - 95: I1ii11iIi11i
 if ( not OooOo0OOO ) :
  return ( [ { I111i1I1 : [ { "?" : "not-found" } ] } ] )
  if 48 - 48: I11i
  if 14 - 14: iIii1I11I1II1 / o0oOOo0O0Ooo * IiII
 oo00ooOOoo = open ( IiiI11Iii , "r" )
 if 35 - 35: iIii1I11I1II1
 I1Iii1 = IiiI11Iii + ".temp"
 O000OOOo = open ( I1Iii1 , "w" )
 if 34 - 34: OoO0O00 % I1IiiI . o0oOOo0O0Ooo % OoO0O00 % OoO0O00
 if 30 - 30: I1IiiI + I1IiiI
 if 75 - 75: I1IiiI - ooOoO0o - I1IiiI % oO0o % OoooooooOO
 if 13 - 13: ooOoO0o * OoO0O00 % iIii1I11I1II1 / IiII * iII111i . Oo0Ooo
 if 23 - 23: ooOoO0o / IiII . iII111i * Ii1I
 OooOo0OOO = False
 for O00oO0 in oo00ooOOoo :
  if ( O00oO0 . find ( I111i1I1 ) != - 1 ) : o000 -= 1
  if ( o000 == 0 and not OooOo0OOO ) :
   if ( O00oO0 [ 0 ] == "}" ) : OooOo0OOO = True
   continue
   if 87 - 87: i11iIiiIii
  O000OOOo . write ( O00oO0 )
  if 34 - 34: i1IIi
  if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
 O000OOOo . close ( )
 oo00ooOOoo . close ( )
 if 100 - 100: IiII + i1IIi * OoO0O00
 os . system ( "cp {} {}" . format ( I1Iii1 , IiiI11Iii ) )
 os . system ( "rm {}" . format ( I1Iii1 ) )
 return ( [ { I111i1I1 : [ { "!" : "delete" } ] } ] )
 if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
 if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
 if 74 - 74: i1IIi . iIii1I11I1II1
 if 85 - 85: I1IiiI
 if 10 - 10: O0 . II111iiii / OoooooooOO
 if 72 - 72: OoooooooOO . o0oOOo0O0Ooo + O0
 if 46 - 46: OoOoOO00 * I11i / oO0o + Oo0Ooo + IiII
 if 95 - 95: o0oOOo0O0Ooo - Ii1I
 if 67 - 67: I1ii11iIi11i * Oo0Ooo % o0oOOo0O0Ooo
def lisp_u2a_walk_dict_array ( adata , a_dict ) :
 for oo000O0o in a_dict :
  if ( type ( a_dict [ oo000O0o ] ) == dict ) :
   iIi = { }
   oo00oO0O0 = a_dict [ oo000O0o ]
   for ooOOO in oo00oO0O0 : iIi [ str ( ooOOO ) ] = str ( oo00oO0O0 [ ooOOO ] )
   adata [ str ( oo000O0o ) ] = iIi
  else :
   adata [ str ( oo000O0o ) ] = str ( a_dict [ oo000O0o ] )
   if 69 - 69: I11i % I1Ii111
   if 66 - 66: I1Ii111 * OoooooooOO / I1ii11iIi11i - I11i - ooOoO0o * I11i
 return
 if 80 - 80: oO0o - I1ii11iIi11i / OoooooooOO / OOooOOo
 if 71 - 71: IiII - i1IIi
 if 56 - 56: OoOoOO00 + oO0o
 if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
 if 19 - 19: IiII % OoooooooOO + OoooooooOO
 if 7 - 7: i1IIi
 if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
def lisp_unicode_to_ascii ( udata ) :
 I1ii11i1 = ( type ( udata ) == dict )
 if ( I1ii11i1 ) : udata = [ udata ]
 if 40 - 40: o0oOOo0O0Ooo * IiII / I1ii11iIi11i / I1Ii111 - IiII
 OOo00OOo = [ ]
 for o0Oooo0O00Ooo in udata :
  o000i11IIiiI = { }
  if 66 - 66: oO0o / i11iIiiIii / OoOoOO00 + I1ii11iIi11i / O0
  if ( type ( o0Oooo0O00Ooo ) == dict ) :
   lisp_u2a_walk_dict_array ( o000i11IIiiI , o0Oooo0O00Ooo )
  elif ( type ( o0Oooo0O00Ooo ) == list ) :
   ooi11 = [ ]
   for iiI1iiIii in o0Oooo0O00Ooo :
    I1I111i = { }
    lisp_u2a_walk_dict_array ( I1I111i , iiI1iiIii )
    ooi11 . append ( I1I111i )
    if 63 - 63: I1ii11iIi11i . I1IiiI + OOooOOo - IiII + iII111i
   o000i11IIiiI = ooi11
  else :
   o000i11IIiiI = { str ( list ( o0Oooo0O00Ooo . keys ( ) ) [ 0 ] ) : o000i11IIiiI }
   if 78 - 78: Ii1I
  OOo00OOo . append ( o000i11IIiiI )
  if 29 - 29: II111iiii
  if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
 if ( I1ii11i1 ) : OOo00OOo = OOo00OOo [ 0 ]
 return ( OOo00OOo )
 if 84 - 84: Oo0Ooo % I11i * O0 * I11i
 if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
 if 12 - 12: Oo0Ooo + I1IiiI
 if 37 - 37: i1IIi * i11iIiiIii
 if 95 - 95: i11iIiiIii % I1Ii111 * Oo0Ooo + i1IIi . O0 + I1ii11iIi11i
 if 7 - 7: OoO0O00 * i11iIiiIii * iIii1I11I1II1 / OOooOOo / I1Ii111
 if 35 - 35: iII111i * OOooOOo
 if 65 - 65: II111iiii % i1IIi
 if 13 - 13: OoO0O00 * I1Ii111 + Oo0Ooo - IiII
 if 31 - 31: OoO0O00
 if 68 - 68: OoO0O00 + i1IIi / iIii1I11I1II1 + II111iiii * iIii1I11I1II1 + I1ii11iIi11i
 if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
def lisp_replace_db_list ( db ) :
 O0OO0O = - 1
 for iII11Iii in lisp . lisp_db_list :
  if ( db . match_eid_tuple ( iII11Iii ) ) :
   O0OO0O = lisp . lisp_db_list . index ( iII11Iii )
   break
   if 72 - 72: OoOoOO00 % i11iIiiIii / i1IIi + i1IIi + i11iIiiIii . IiII
   if 37 - 37: I1IiiI / OoooooooOO % i11iIiiIii % I1ii11iIi11i
 if ( O0OO0O == - 1 ) : return ( False )
 if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
 if 1 - 1: IiII % i1IIi
 if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
 if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
 if 80 - 80: I1ii11iIi11i
 if ( lisp . lisp_nat_traversal and lisp . lisp_i_am_etr ) :
  for i1i11I1I1 in iII11Iii . rloc_set :
   if ( i1i11I1I1 . is_rloc_translated ( ) == False ) : continue
   O0O0O0OO00oo = db . get_rloc_by_interface ( i1i11I1I1 . interface )
   if ( O0O0O0OO00oo == None ) : continue
   O0O0O0OO00oo . store_translated_rloc ( i1i11I1I1 . translated_rloc , i1i11I1I1 . translated_port )
   O0O0O0OO00oo . rloc_name = i1i11I1I1 . rloc_name
   if 67 - 67: II111iiii
   if 2 - 2: o0oOOo0O0Ooo - O0 * Ii1I % IiII
   if 64 - 64: i1IIi . ooOoO0o
 lisp . lisp_db_list [ O0OO0O ] = db
 return ( True )
 if 7 - 7: oO0o . iII111i - iII111i / I1Ii111 % Oo0Ooo
 if 61 - 61: oO0o - I1ii11iIi11i / iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
 if 10 - 10: i11iIiiIii / OoOoOO00
 if 27 - 27: I1IiiI / OoooooooOO
 if 74 - 74: I1ii11iIi11i % I1Ii111 - OoO0O00 * I11i . OoooooooOO * OoO0O00
 if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
 if 6 - 6: OOooOOo
def lisp_map_server_command ( kv_pairs ) :
 i1II = [ ]
 Ii1111i11 = [ ]
 O0Ooo000OO00 = 0
 O000oo0O0OO0 = 0
 o0O0OO = ""
 oOoo0ooO = False
 i1IiIiIii11I = False
 O0o0O00 = False
 OoI11II = False
 Iii11IiIi = 0
 OOOoO000oOOo = None
 IIiI = 0
 iI11IIiII1iII = None
 if 51 - 51: iIii1I11I1II1 * OoOoOO00 / Ii1I * OoO0O00
 for iiiI11 in list ( kv_pairs . keys ( ) ) :
  oo00oO0O0 = kv_pairs [ iiiI11 ]
  if ( iiiI11 == "ms-name" ) :
   OOOoO000oOOo = oo00oO0O0 [ 0 ]
   if 58 - 58: O0 - i1IIi / iII111i
  if ( iiiI11 == "address" ) :
   for o00oo in range ( len ( oo00oO0O0 ) ) :
    i1II . append ( oo00oO0O0 [ o00oo ] )
    if 59 - 59: Oo0Ooo % I1ii11iIi11i % ooOoO0o % I11i * iIii1I11I1II1
    if 22 - 22: I1IiiI * i11iIiiIii * I1ii11iIi11i / I1IiiI . iII111i
  if ( iiiI11 == "dns-name" ) :
   for o00oo in range ( len ( oo00oO0O0 ) ) :
    Ii1111i11 . append ( oo00oO0O0 [ o00oo ] )
    if 3 - 3: I1Ii111
    if 28 - 28: iIii1I11I1II1 . O0
  if ( iiiI11 == "authentication-type" ) :
   O000oo0O0OO0 = lisp . LISP_SHA_1_96_ALG_ID if ( oo00oO0O0 == "sha1" ) else lisp . LISP_SHA_256_128_ALG_ID if ( oo00oO0O0 == "sha2" ) else ""
   if 32 - 32: OoooooooOO
   if 29 - 29: I1ii11iIi11i
  if ( iiiI11 == "authentication-key" ) :
   if ( O000oo0O0OO0 == 0 ) : O000oo0O0OO0 = lisp . LISP_SHA_256_128_ALG_ID
   iI111iiI1II = lisp . lisp_parse_auth_key ( oo00oO0O0 )
   O0Ooo000OO00 = list ( iI111iiI1II . keys ( ) ) [ 0 ]
   o0O0OO = iI111iiI1II [ O0Ooo000OO00 ]
   if 96 - 96: OoOoOO00 * O0 - II111iiii . ooOoO0o - Ii1I
  if ( iiiI11 == "proxy-reply" ) :
   oOoo0ooO = True if oo00oO0O0 == "yes" else False
   if 84 - 84: oO0o * o0oOOo0O0Ooo * o0oOOo0O0Ooo - iII111i
  if ( iiiI11 == "merge-registrations" ) :
   i1IiIiIii11I = True if oo00oO0O0 == "yes" else False
   if 25 - 25: oO0o + I1Ii111 + I1IiiI + O0 * II111iiii + I1IiiI
  if ( iiiI11 == "refresh-registrations" ) :
   O0o0O00 = True if oo00oO0O0 == "yes" else False
   if 66 - 66: oO0o
  if ( iiiI11 == "want-map-notify" ) :
   OoI11II = True if oo00oO0O0 == "yes" else False
   if 73 - 73: OOooOOo . Oo0Ooo + Oo0Ooo % Oo0Ooo % O0
  if ( iiiI11 == "site-id" ) :
   Iii11IiIi = int ( oo00oO0O0 )
   if 8 - 8: iII111i . Ii1I - i1IIi % OoO0O00 / I11i
  if ( iiiI11 == "encryption-key" ) :
   iI11IIiII1iII = lisp . lisp_parse_auth_key ( oo00oO0O0 )
   IIiI = list ( iI11IIiII1iII . keys ( ) ) [ 0 ]
   iI11IIiII1iII = iI11IIiII1iII [ IIiI ]
   if 13 - 13: Oo0Ooo / OoOoOO00 . I1ii11iIi11i . OOooOOo
   if 31 - 31: o0oOOo0O0Ooo
   if 59 - 59: Oo0Ooo / Oo0Ooo
   if 87 - 87: I1ii11iIi11i % OoOoOO00 + Ii1I . i11iIiiIii / Ii1I
   if 32 - 32: Ii1I + IiII + I1ii11iIi11i
   if 79 - 79: i1IIi / Ii1I
 for Ii1I1i in i1II :
  if ( Ii1I1i == "" ) : continue
  II1Ii = lisp . lisp_ms ( Ii1I1i , None , OOOoO000oOOo , O000oo0O0OO0 , O0Ooo000OO00 , o0O0OO ,
 oOoo0ooO , i1IiIiIii11I , O0o0O00 , OoI11II , Iii11IiIi , IIiI , iI11IIiII1iII )
  if 81 - 81: iIii1I11I1II1
 for o000oO0oOOO in Ii1111i11 :
  if ( o000oO0oOOO == "" ) : continue
  II1Ii = lisp . lisp_ms ( None , o000oO0oOOO , OOOoO000oOOo , O000oo0O0OO0 , O0Ooo000OO00 , o0O0OO ,
 oOoo0ooO , i1IiIiIii11I , O0o0O00 , OoI11II , Iii11IiIi , IIiI , iI11IIiII1iII )
  if 23 - 23: OOooOOo
 return ( II1Ii )
 if 68 - 68: OoooooooOO
 if 18 - 18: Ii1I * OoO0O00
 if 89 - 89: OoO0O00 + oO0o % iIii1I11I1II1 + I11i / O0
 if 38 - 38: ooOoO0o - o0oOOo0O0Ooo - O0 + ooOoO0o % OoOoOO00 . o0oOOo0O0Ooo
 if 40 - 40: iIii1I11I1II1 * OoooooooOO * I1Ii111 - Ii1I + i11iIiiIii
 if 81 - 81: OoO0O00 * OoooooooOO / iII111i
 if 8 - 8: O0 * i1IIi - OoOoOO00 % I1IiiI / I1ii11iIi11i
 if 39 - 39: I1ii11iIi11i . oO0o * II111iiii + I1IiiI - iIii1I11I1II1
def lisp_database_mapping_command ( kv_pair , ephem_port = None , replace = True ) :
 O0O00o0O = [ ]
 IIii1i = [ ]
 IIIii11 = [ ]
 if 31 - 31: I1IiiI - OoooooooOO . IiII
 I1I = 1
 if ( "address" in kv_pair ) :
  if ( lisp_clause_syntax_error ( kv_pair , "address" , "rloc" ) ) : return
  I1I = len ( kv_pair [ "address" ] )
 elif ( "interface" in kv_pair ) :
  if ( lisp_clause_syntax_error ( kv_pair , "interface" , "rloc" ) ) : return
  I1I = len ( kv_pair [ "interface" ] )
  if 77 - 77: ooOoO0o % oO0o % O0 % OoO0O00
 for o00oo in range ( I1I ) :
  i1i11I1I1 = lisp . lisp_rloc ( )
  IIIii11 . append ( i1i11I1I1 )
  if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
  if 17 - 17: OoOoOO00
 if ( lisp_clause_syntax_error ( kv_pair , "eid-prefix" , "prefix" ) ) : return
 for o00oo in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  O0oooO = lisp . lisp_mapping ( "" , "" , IIIii11 )
  IIii1i . append ( O0oooO )
  if 4 - 4: i1IIi % o0oOOo0O0Ooo % oO0o . i1IIi
  if 85 - 85: IiII . Ii1I * o0oOOo0O0Ooo % Oo0Ooo % II111iiii + I1Ii111
 for iiiI11 in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ iiiI11 ]
  if ( iiiI11 == "mr-name" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    O0oooO = IIii1i [ o00oo ]
    O0oooO . use_mr_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ o00oo ]
    if 85 - 85: II111iiii / ooOoO0o * II111iiii
    if 43 - 43: o0oOOo0O0Ooo / O0 + i1IIi - I1ii11iIi11i % i11iIiiIii
  if ( iiiI11 == "ms-name" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    O0oooO = IIii1i [ o00oo ]
    O0oooO . use_ms_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ o00oo ]
    if 69 - 69: OOooOOo % I1ii11iIi11i / OoOoOO00 . OOooOOo - IiII
    if 74 - 74: OoO0O00 - o0oOOo0O0Ooo - IiII . O0 % ooOoO0o
  if ( iiiI11 == "instance-id" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    O0oooO = IIii1i [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    oooooO00OOO = [ "0" ] if ( oooooO00OOO == "" ) else oooooO00OOO . split ( )
    for IIiiii1I1 in oooooO00OOO : oooooO00OOO [ oooooO00OOO . index ( IIiiii1I1 ) ] = int ( IIiiii1I1 )
    O0oooO . eid . instance_id = oooooO00OOO [ 0 ]
    O0oooO . eid . iid_list = oooooO00OOO [ 1 : : ]
    O0oooO . group . instance_id = oooooO00OOO [ 0 ]
    if 39 - 39: I1Ii111 / iII111i
    if 65 - 65: i1IIi . iIii1I11I1II1 - ooOoO0o * OOooOOo
  if ( iiiI11 == "secondary-instance-id" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    O0oooO = IIii1i [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO == "" ) : continue
    O0oooO . secondary_iid = int ( oooooO00OOO )
    if ( O0oooO . eid . address == 0 ) :
     lisp . lisp_default_secondary_iid = int ( oooooO00OOO )
     if 50 - 50: I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
     if 52 - 52: I1ii11iIi11i
     if 93 - 93: iII111i . i11iIiiIii
  if ( iiiI11 == "eid-prefix" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    O0oooO = IIii1i [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) : O0oooO . eid . store_prefix ( oooooO00OOO )
    if ( O0oooO . eid . address == 0 ) :
     lisp . lisp_default_secondary_iid = O0oooO . secondary_iid
     if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
     if 49 - 49: O0 . Oo0Ooo / Ii1I
     if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
  if ( iiiI11 == "group-prefix" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    O0oooO = IIii1i [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) : O0oooO . group . store_prefix ( oooooO00OOO )
    if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
    if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  if ( iiiI11 == "dynamic-eid" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    O0oooO = IIii1i [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO == "yes" ) : O0oooO . dynamic_eids = { }
    if 44 - 44: i11iIiiIii
    if 69 - 69: OOooOOo * O0 + i11iIiiIii
  if ( iiiI11 == "signature-eid" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    O0oooO = IIii1i [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    O0oooO . signature_eid = ( oooooO00OOO == "yes" )
    if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
    if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
  if ( iiiI11 == "register-ttl" ) :
   for o00oo in range ( len ( IIii1i ) ) :
    if ( oo00oO0O0 [ o00oo ] == "" ) : continue
    O0oooO = IIii1i [ o00oo ]
    O0oooO . register_ttl = int ( oo00oO0O0 [ o00oo ] )
    if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
    if 63 - 63: oO0o
  if ( iiiI11 == "priority" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO == "" ) : oooooO00OOO = "0"
    i1i11I1I1 . priority = int ( oooooO00OOO )
    if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
    if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
  if ( iiiI11 == "weight" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO == "" ) : oooooO00OOO = "0"
    i1i11I1I1 . weight = int ( oooooO00OOO )
    if 60 - 60: I1Ii111
    if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
  if ( iiiI11 == "address" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) : i1i11I1I1 . rloc . store_address ( oooooO00OOO )
    if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
    if 14 - 14: Ii1I - O0
  if ( iiiI11 == "interface" ) :
   O0I11i1i11i1I = lisp . lisp_hostname
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) :
     i1i11I1I1 . interface = oooooO00OOO
     II = lisp . lisp_get_interface_address ( oooooO00OOO )
     if ( II ) :
      i1i11I1I1 . rloc . copy_address ( II )
      lisp . lisp_myrlocs [ 0 ] = II
      if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
     i1i11I1I1 . rloc_name = O0I11i1i11i1I
     O0O00o0O . append ( i1i11I1I1 )
     if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
     if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
     if 7 - 7: IiII * ooOoO0o + OoOoOO00
  if ( iiiI11 == "elp-name" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) : i1i11I1I1 . elp_name = oooooO00OOO
    if 22 - 22: iII111i
    if 48 - 48: I1ii11iIi11i . I1IiiI
  if ( iiiI11 == "rle-name" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) : i1i11I1I1 . rle_name = oooooO00OOO
    if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
    if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
  if ( iiiI11 == "json-name" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) : i1i11I1I1 . json_name = oooooO00OOO
    if 49 - 49: Oo0Ooo
    if 57 - 57: O0 * ooOoO0o - iII111i - iIii1I11I1II1 * iII111i
  if ( iiiI11 == "geo-name" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) : i1i11I1I1 . geo_name = oooooO00OOO
    if 9 - 9: IiII . I11i
    if 23 - 23: O0 % OoooooooOO - O0 . I1IiiI + i11iIiiIii
  if ( iiiI11 == "rloc-record-name" ) :
   for o00oo in range ( len ( IIIii11 ) ) :
    i1i11I1I1 = IIIii11 [ o00oo ]
    oooooO00OOO = oo00oO0O0 [ o00oo ]
    if ( oooooO00OOO != "" ) : i1i11I1I1 . rloc_name = oooooO00OOO
    if 96 - 96: ooOoO0o % O0
    if 51 - 51: I1IiiI - iII111i / I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i
    if 87 - 87: II111iiii . Ii1I * OoO0O00
    if 74 - 74: o0oOOo0O0Ooo % OoOoOO00 . iII111i % I1Ii111 . O0 % II111iiii
    if 5 - 5: oO0o - OoooooooOO / OoOoOO00
    if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
    if 55 - 55: OoO0O00
    if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
    if 32 - 32: Ii1I * oO0o
    if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
 if ( len ( O0O00o0O ) > 1 ) :
  for i1i11I1I1 in O0O00o0O :
   i1i11I1I1 . rloc_name = O0I11i1i11i1I + "-" + i1i11I1I1 . interface
   if 28 - 28: Oo0Ooo
   if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
   if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
   if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
   if 69 - 69: I11i
   if 17 - 17: I11i
 for O0oooO in IIii1i :
  O0oooO . rloc_set = copy . deepcopy ( O0oooO . rloc_set )
  O0oooO . sort_rloc_set ( )
  O0oooO . add_db ( )
  if ( replace and lisp_replace_db_list ( O0oooO ) ) : continue
  lisp . lisp_db_list . append ( O0oooO )
  if 38 - 38: I1Ii111 % OOooOOo
  if 9 - 9: O0 . iIii1I11I1II1
  if 44 - 44: I1ii11iIi11i % IiII
  if 6 - 6: OoO0O00
  if 82 - 82: iIii1I11I1II1 . I11i / IiII / OOooOOo * II111iiii % oO0o
 lisp . lisp_write_ipc_database_mappings ( ephem_port )
 if 62 - 62: II111iiii
 if 96 - 96: I11i % OoOoOO00 * I1ii11iIi11i
 if 94 - 94: Oo0Ooo - i1IIi . O0 % Oo0Ooo . ooOoO0o
 if 63 - 63: i11iIiiIii % I1ii11iIi11i % I1IiiI . IiII * o0oOOo0O0Ooo + OOooOOo
 if 77 - 77: o0oOOo0O0Ooo
 if 63 - 63: ooOoO0o * oO0o + ooOoO0o * Ii1I + Oo0Ooo / I1ii11iIi11i
 if 15 - 15: O0 . I1ii11iIi11i * I1ii11iIi11i
 lisp . lisp_default_iid = lisp . lisp_db_list [ 0 ] . eid . instance_id
 if 65 - 65: I1Ii111 + O0 % o0oOOo0O0Ooo
 if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
 if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
 if 50 - 50: OoooooooOO * i1IIi / oO0o
 if 83 - 83: i1IIi
 if 38 - 38: OoooooooOO * iIii1I11I1II1
 if 54 - 54: OoooooooOO . I1Ii111
 if 71 - 71: Ii1I
 for O0oooO in IIii1i :
  if ( O0oooO . group . is_null ( ) == False ) : continue
  if ( O0oooO . eid . address == 0 and O0oooO . eid . mask_len == 0 ) :
   if ( O0oooO . eid . is_ipv4 ( ) or O0oooO . eid . is_ipv6 ( ) ) :
    lisp . lisp_pitr = True
    break
    if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
    if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
    if 93 - 93: ooOoO0o % I1Ii111
  if ( O0oooO . dynamic_eids == None ) : continue
  if ( O0oooO . eid . is_mac ( ) and O0oooO . eid . address == 0 and O0oooO . eid . mask_len == 0 ) :
   lisp . lisp_l2_overlay = True
   break
   if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
   if 43 - 43: ooOoO0o . i1IIi
   if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
   if 45 - 45: I1IiiI
   if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
   if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
   if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
   if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
 oO0OO00o = ( lisp . lisp_myrlocs [ 0 ] != None )
 lisp . lisp_get_local_addresses ( )
 if 97 - 97: O0 . o0oOOo0O0Ooo
 if ( lisp . lisp_myrlocs [ 0 ] == None and oO0OO00o ) :
  lisp . lprint ( "No RLOCs found, local addresses changed from RLOC to EID" )
  if 17 - 17: O0 . oO0o - oO0o - i1IIi * OOooOOo
  if 16 - 16: OoOoOO00 / II111iiii
  if 22 - 22: I11i
  if 53 - 53: OoO0O00
  if 96 - 96: OoooooooOO - iIii1I11I1II1 . oO0o
  if 2 - 2: i1IIi
  if 6 - 6: i1IIi % I11i . IiII + IiII . I11i / i11iIiiIii
  if 78 - 78: O0
  if 34 - 34: II111iiii
  if 20 - 20: I1IiiI % i1IIi % OoOoOO00 % I1Ii111 + O0
  if 54 - 54: O0
  if 3 - 3: I1ii11iIi11i
  if 42 - 42: I11i % Oo0Ooo + IiII - I11i . iIii1I11I1II1 - Ii1I
  if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
  if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
  if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
  if 66 - 66: ooOoO0o + oO0o % OoooooooOO
  if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
  if 17 - 17: IiII
  if 12 - 12: i1IIi . OoO0O00
  if 14 - 14: OOooOOo + II111iiii % OOooOOo . oO0o * ooOoO0o
 if ( lisp . lisp_program_hardware == False ) : return
 if 54 - 54: ooOoO0o * I11i - I1Ii111
 OooOo0OOO = False
 for O0oooO in IIii1i :
  if ( O0oooO . dynamic_eids == None ) : continue
  i1iI1 = O0oooO . eid . print_prefix_no_iid ( )
  OooOo0OOO = lisp . lisp_i_am_itr
  os . system ( "ip route add {} dev ma1" . format ( i1iI1 ) )
  if 27 - 27: i1IIi + iIii1I11I1II1
 if ( lisp . lisp_program_hardware and OooOo0OOO ) :
  OO00OO0O0 = "platform trident diag s cpu_control_1 URPF_MISS_TOCPU=1"
  lisp . lisp_send_to_arista ( OO00OO0O0 , None )
  if 97 - 97: ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo . II111iiii / iII111i / iII111i
  if 25 - 25: iII111i
  if 85 - 85: Oo0Ooo + Oo0Ooo % I11i + I1Ii111
  if 57 - 57: OoOoOO00 / I1ii11iIi11i
  if 90 - 90: Ii1I / oO0o * Oo0Ooo * Oo0Ooo / OoOoOO00
  if 86 - 86: I1ii11iIi11i * ooOoO0o - O0
  if 21 - 21: I1IiiI . Oo0Ooo
  if 54 - 54: I1Ii111 - I1Ii111 * O0 / Ii1I + I1IiiI - I1Ii111
def lisp_show_db_list ( itr_or_etr , output ) :
 Iiii = "{} database-mapping entries" . format ( len ( lisp . lisp_db_list ) )
 o0000oO = "LISP-{} Configured Database Mappings:" . format ( itr_or_etr )
 o0000oO = lisp . lisp_span ( o0000oO , Iiii )
 if 58 - 58: OoooooooOO * i1IIi * OoOoOO00
 o0oo000 = '<a href="/lisp/show/etr/keys"><br>RLOC Keys</a>'
 if 99 - 99: Oo0Ooo
 if ( itr_or_etr == "ITR" ) :
  output += lisp_table_header ( o0000oO , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Use MR" )
 else :
  output += lisp_table_header ( o0000oO , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" + o0oo000 , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Receive Stats" ,
 "Map-Replies<br>Sent" , "Use MS" )
  if 72 - 72: Oo0Ooo / II111iiii * ooOoO0o * I1ii11iIi11i - IiII / I1Ii111
  if 82 - 82: I1IiiI / I11i
 for O0oooO in lisp . lisp_db_list :
  I1i1 = lisp . lisp_print_elapsed ( O0oooO . uptime )
  o0o000oo = O0oooO . map_replies_sent
  if 37 - 37: I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
  if 90 - 90: Ii1I * iII111i / OOooOOo
  if 68 - 68: OoOoOO00
  if 65 - 65: oO0o
  o000oOOO = ""
  if ( O0oooO . dynamic_eid_configured ( ) ) :
   iIi1o0000o0OOOo = O0oooO . eid . print_prefix_url ( )
   I1IIiIi = len ( O0oooO . dynamic_eids )
   O0oOo = itr_or_etr . lower ( )
   o000oOOO = ( "<br><a href='/lisp/show/{}/dynamic-eid/{}'>" + "{} dynamic-eids</a>" ) . format ( O0oOo , iIi1o0000o0OOOo , I1IIiIi )
   if 3 - 3: IiII
   if 18 - 18: I1IiiI
   if 32 - 32: iIii1I11I1II1 * I1IiiI . OOooOOo * iIii1I11I1II1
  OOo00ooO = True
  for i1i11I1I1 in O0oooO . rloc_set :
   if ( OOo00ooO ) :
    ii1Ii111I11 = O0oooO . print_eid_tuple ( )
    ii1Ii111I11 = O0oooO . star_secondary_iid ( ii1Ii111I11 )
    ii1Ii111I11 += o000oOOO
    oO0OOoO0 = I1i1
    OOo00ooO = False
   else :
    ii1Ii111I11 , oO0OOoO0 , o0o000oo = ( "" , "" , "" )
    if 36 - 36: i1IIi - OoooooooOO / Ii1I - OOooOOo + o0oOOo0O0Ooo / oO0o
    if 1 - 1: OOooOOo + iII111i * Ii1I
   iIIIi1iii1I11 = "" if i1i11I1I1 . rloc . is_null ( ) else i1i11I1I1 . rloc . print_address_no_iid ( )
   if 23 - 23: o0oOOo0O0Ooo + ooOoO0o
   if 47 - 47: i11iIiiIii
   if ( i1i11I1I1 . interface != None ) :
    iIIIi1iii1I11 += " ({})" . format ( i1i11I1I1 . interface )
    if 98 - 98: OoooooooOO
   if ( iIIIi1iii1I11 != "" ) : iIIIi1iii1I11 += "<br>"
   if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
   if ( i1i11I1I1 . translated_rloc . not_set ( ) == False ) :
    iIIIi1iii1I11 += "translated RLOC: {}<br>" . format ( i1i11I1I1 . translated_rloc . print_address_no_iid ( ) )
    if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
    if 71 - 71: Ii1I * OoOoOO00
    if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
   O0O00 = i1i11I1I1 . print_rloc_name ( True )
   if ( O0O00 != "" ) : iIIIi1iii1I11 += O0O00 + "<br>"
   if 57 - 57: OOooOOo - OoooooooOO * OoO0O00 * iII111i + oO0o
   if ( i1i11I1I1 . geo_name != None ) :
    iIIIi1iii1I11 += "geo: " + i1i11I1I1 . geo_name + "<br>"
    if 100 - 100: I1Ii111 - i1IIi
   if ( i1i11I1I1 . elp_name != None ) :
    iIIIi1iii1I11 += "elp: " + i1i11I1I1 . elp_name + "<br>"
    if 90 - 90: Ii1I + oO0o . II111iiii - OoOoOO00 % iIii1I11I1II1
   if ( i1i11I1I1 . rle_name != None ) :
    iIIIi1iii1I11 += "rle: " + i1i11I1I1 . rle_name + "<br>"
    if 24 - 24: IiII / Ii1I * OOooOOo
   if ( i1i11I1I1 . json_name != None ) :
    iIIIi1iii1I11 += "json: " + i1i11I1I1 . json_name + "<br>"
    if 33 - 33: OOooOOo
    if 22 - 22: O0 + OOooOOo % i1IIi
   if ( itr_or_etr == "ITR" ) :
    output += lisp_table_row ( ii1Ii111I11 , oO0OOoO0 , iIIIi1iii1I11 ,
 str ( i1i11I1I1 . priority ) + "/" + str ( i1i11I1I1 . weight ) ,
 str ( i1i11I1I1 . mpriority ) + "/" + str ( i1i11I1I1 . mweight ) ,
 O0oooO . use_mr_name )
   else :
    oOoOO0O00o = i1i11I1I1 . stats . get_stats ( True , True )
    output += lisp_table_row ( ii1Ii111I11 , oO0OOoO0 , iIIIi1iii1I11 ,
 str ( i1i11I1I1 . priority ) + "/" + str ( i1i11I1I1 . weight ) ,
 str ( i1i11I1I1 . mpriority ) + "/" + str ( i1i11I1I1 . mweight ) , oOoOO0O00o ,
 o0o000oo , O0oooO . use_ms_name )
    if 83 - 83: O0 + Ii1I % i11iIiiIii
    if 32 - 32: I1Ii111 % Oo0Ooo - I11i + O0
    if 57 - 57: OoO0O00 + I1Ii111 . I11i . i1IIi - o0oOOo0O0Ooo / Oo0Ooo
 output += lisp_table_footer ( )
 if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
 if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
 if 76 - 76: OoO0O00 * oO0o - OoO0O00
 if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
 if ( len ( lisp . lisp_geo_list ) != 0 ) :
  o0000oO = "Configured Geo-Coordinates:"
  output += lisp_table_header ( o0000oO , "Geo Name" ,
 "Geo-Prefix or Geo-Point" )
  Ii111IIII1 = sorted ( lisp . lisp_geo_list )
  for iIiii1IIi1I in Ii111IIII1 :
   IiIi = lisp . lisp_geo_list [ iIiii1IIi1I ]
   output += lisp_table_row ( iIiii1IIi1I , IiIi . print_geo_url ( ) )
   if 94 - 94: I1Ii111 % I1IiiI % O0 . I1IiiI % ooOoO0o / OOooOOo
  output += lisp_table_footer ( )
  if 79 - 79: iIii1I11I1II1 / iIii1I11I1II1 . iII111i . Ii1I
 return ( output )
 if 49 - 49: I1ii11iIi11i * I1Ii111 + OoOoOO00
 if 72 - 72: OoO0O00
 if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
 if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
 if 70 - 70: I11i . I1ii11iIi11i * oO0o
 if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
 if 23 - 23: I1ii11iIi11i % I11i
def lisp_interface_command ( kv_pair ) :
 iiI = None
 i1I1IIIII1IIi = None
 i11iii1II1I1 = None
 IiIi11iI1IIi = None
 iII111I = None
 Ooooo0Oo0oOo = None
 IiI1III1 = None
 iiiiII1i1Iii1I1 = None
 if 87 - 87: OoooooooOO - oO0o - ooOoO0o * I1ii11iIi11i
 for iiiI11 in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ iiiI11 ]
  if ( iiiI11 == "interface-name" ) : iiI = oo00oO0O0
  if ( iiiI11 == "device" ) : i1I1IIIII1IIi = oo00oO0O0
  if ( iiiI11 == "instance-id" ) : i11iii1II1I1 = oo00oO0O0
  if ( iiiI11 == "dynamic-eid" ) : IiIi11iI1IIi = oo00oO0O0
  if ( iiiI11 == "multi-tenant-eid" ) : IiI1III1 = oo00oO0O0
  if ( iiiI11 == "dynamic-eid-device" ) : iII111I = oo00oO0O0
  if ( iiiI11 == "dynamic-eid-timeout" ) : Ooooo0Oo0oOo = oo00oO0O0
  if ( iiiI11 == "lisp-nat" ) : iiiiII1i1Iii1I1 = ( oo00oO0O0 == "yes" )
  if 44 - 44: oO0o * II111iiii * II111iiii + I1IiiI / Oo0Ooo
  if 9 - 9: Oo0Ooo - IiII
 if ( i1I1IIIII1IIi == None ) : return
 if 30 - 30: OoooooooOO % OOooOOo
 if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
 if 81 - 81: iII111i % Ii1I . ooOoO0o
 if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
 if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
 if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
 if 20 - 20: ooOoO0o
 if 63 - 63: iIii1I11I1II1 . OoO0O00
 if ( i1I1IIIII1IIi in lisp . lisp_myinterfaces and IiI1III1 == None ) :
  ooooOo00OO0o = lisp . lisp_myinterfaces [ i1I1IIIII1IIi ]
 else :
  ooooOo00OO0o = lisp . lisp_interface ( i1I1IIIII1IIi )
  lisp . lisp_myinterfaces [ i1I1IIIII1IIi ] = ooooOo00OO0o
  if 86 - 86: OoOoOO00
  if 61 - 61: IiII / II111iiii . O0 + OoooooooOO * i1IIi
  if 59 - 59: OoooooooOO % II111iiii . Ii1I * o0oOOo0O0Ooo . OoOoOO00
  if 95 - 95: Ii1I % i11iIiiIii * OoooooooOO + Ii1I . II111iiii
  if 89 - 89: iII111i
 ooooOo00OO0o . interface_name = iiI
 if ( i11iii1II1I1 != None ) :
  if ( i11iii1II1I1 . isdigit ( ) == False ) : i11iii1II1I1 = "0"
  ooooOo00OO0o . instance_id = int ( i11iii1II1I1 )
 else :
  ooooOo00OO0o . instance_id = 0
  if 73 - 73: IiII / Ii1I + I1Ii111 . OOooOOo - II111iiii / iIii1I11I1II1
 if ( IiIi11iI1IIi != None ) :
  ooooOo00OO0o . dynamic_eid . store_prefix ( IiIi11iI1IIi )
  ooooOo00OO0o . dynamic_eid . instance_id = ooooOo00OO0o . instance_id
  if 79 - 79: I1Ii111 * Oo0Ooo . o0oOOo0O0Ooo - I1Ii111
 if ( iII111I != None ) :
  ooooOo00OO0o . dynamic_eid_device = iII111I
  if 16 - 16: I1IiiI - O0 * I1ii11iIi11i . I1ii11iIi11i % OOooOOo
 if ( Ooooo0Oo0oOo != None ) :
  ooooOo00OO0o . dynamic_eid_timeout = int ( Ooooo0Oo0oOo )
  if 39 - 39: II111iiii / I11i - OoOoOO00 * OoOoOO00 - Ii1I
 if ( IiI1III1 != None ) :
  ooooOo00OO0o . multi_tenant_eid . store_prefix ( IiI1III1 )
  ooooOo00OO0o . multi_tenant_eid . instance_id = int ( ooooOo00OO0o . instance_id )
  lisp . lisp_multi_tenant_interfaces . append ( ooooOo00OO0o )
  if 8 - 8: O0 . i11iIiiIii
 if ( iiiiII1i1Iii1I1 ) :
  O0O0o00o00O00 = "sudo iptables -t nat -C POSTROUTING -o {} -j MASQUERADE"
  O0O0o00o00O00 = getoutput ( O0O0o00o00O00 . format ( i1I1IIIII1IIi ) )
  if ( O0O0o00o00O00 != "" ) :
   OOOoOO = lisp . lisp_get_loopback_address ( )
   if ( OOOoOO ) :
    Ooo = "sudo iptables -t nat -A POSTROUTING -s {} -j ACCEPT"
    os . system ( Ooo . format ( OOOoOO ) )
    if 91 - 91: i1IIi % OoooooooOO - IiII . iIii1I11I1II1 . OOooOOo / OOooOOo
   Ooo = "sudo iptables -t nat -A POSTROUTING -o {} -j MASQUERADE"
   os . system ( Ooo . format ( i1I1IIIII1IIi ) )
   os . system ( "sudo sysctl net.ipv4.ip_forward=1" )
   if 27 - 27: ooOoO0o + I11i * o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / I1Ii111
   if 2 - 2: o0oOOo0O0Ooo - I1IiiI - i11iIiiIii / OoooooooOO
   if 87 - 87: o0oOOo0O0Ooo + oO0o + OoooooooOO * OOooOOo
 lisp . lisp_iid_to_interface [ i11iii1II1I1 ] = ooooOo00OO0o
 if 50 - 50: Oo0Ooo * i1IIi - I1ii11iIi11i * I1IiiI
 if 24 - 24: OoOoOO00 * Ii1I
 if 17 - 17: OoO0O00 . I1IiiI * O0
 if 81 - 81: OOooOOo
 if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
 if ( "SO_BINDTODEVICE" in dir ( socket ) ) : ooooOo00OO0o . set_socket ( i1I1IIIII1IIi )
 if ( "PF_PACKET" in dir ( socket ) ) : ooooOo00OO0o . set_bridge_socket ( i1I1IIIII1IIi )
 if 41 - 41: I11i + OoO0O00 . iII111i
 if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
 if 56 - 56: i1IIi
 if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
 lisp . lisp_get_local_addresses ( )
 if 82 - 82: IiII
 if 10 - 10: Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
 if 54 - 54: i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i / I1IiiI . iIii1I11I1II1 / iII111i
 if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
 if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
 if 30 - 30: I11i - OoO0O00
 if ( IiIi11iI1IIi != None and lisp . lisp_program_hardware ) :
  OO00OO0O0 = "ip verify unicast source reachable-via rx"
  lisp . lisp_send_to_arista ( OO00OO0O0 , i1I1IIIII1IIi )
  OO00OO0O0 = 'sysctl -w "net.ipv4.conf.{}.rp_filter=0"' . format ( i1I1IIIII1IIi )
  os . system ( OO00OO0O0 )
  if 15 - 15: OoooooooOO
  if 31 - 31: II111iiii
  if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
  if 87 - 87: IiII
  if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
 lisp . lisp_write_ipc_interfaces ( )
 return
 if 55 - 55: IiII
 if 43 - 43: OOooOOo
 if 17 - 17: i11iIiiIii
 if 94 - 94: OoooooooOO - IiII + oO0o . OoooooooOO / i1IIi
 if 53 - 53: I1Ii111 % I1ii11iIi11i
 if 17 - 17: OoooooooOO % Ii1I % O0
 if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
 if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
def lisp_parse_eid_in_url ( command , eid_prefix ) :
 I11iiI1i1 = ""
 if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
 if 80 - 80: oO0o / O0
 if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
 if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
 if ( eid_prefix == "0--0" ) :
  command = command + "%[0]/0%"
 elif ( eid_prefix . find ( "-name-" ) != - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if ( len ( eid_prefix ) > 4 ) :
   eid_prefix = [ eid_prefix [ 0 ] , "name" , "-" . join ( eid_prefix [ 2 : - 1 ] ) ,
 eid_prefix [ - 1 ] ]
   if 59 - 59: IiII
   if 54 - 54: OOooOOo
   if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
   if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
   if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
  OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]'" + eid_prefix [ 2 ] + "'" + "/" + eid_prefix [ 3 ]
  if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
  command = command + "%" + OOOO0oo0 + "%"
 elif ( eid_prefix . count ( "-" ) in [ 9 , 10 ] ) :
  if 33 - 33: oO0o % OoO0O00 . iIii1I11I1II1 / IiII
  if 3 - 3: Ii1I + OoO0O00
  if 60 - 60: OoO0O00 . OoOoOO00 - I1ii11iIi11i - I1IiiI - II111iiii % Oo0Ooo
  if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
  eid_prefix = eid_prefix . split ( "-" )
  OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + "-" . join ( eid_prefix [ 1 : - 1 ] ) + "/" + eid_prefix [ - 1 ]
  if 47 - 47: I1Ii111 + I1IiiI
  command = command + "%" + OOOO0oo0 + "%"
 elif ( eid_prefix . find ( "." ) == - 1 and eid_prefix . find ( ":" ) == - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
  if 80 - 80: oO0o
  if 81 - 81: OoooooooOO / ooOoO0o * iIii1I11I1II1 . Oo0Ooo + oO0o / O0
  if 84 - 84: II111iiii - o0oOOo0O0Ooo
  if ( eid_prefix [ 1 ] == "plus" ) :
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]+" + eid_prefix [ 2 ] + "/" + eid_prefix [ 3 ]
   if 78 - 78: IiII
   command = command + "%" + OOOO0oo0 + "%"
  else :
   if 58 - 58: i11iIiiIii - OoOoOO00
   if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
   if 99 - 99: ooOoO0o . Ii1I
   if 92 - 92: i1IIi
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "-" + eid_prefix [ 2 ] + "-" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
   if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
   if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
   if 4 - 4: Ii1I
   if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
   if ( len ( eid_prefix ) == 10 ) :
    I11iiI1i1 = "[" + eid_prefix [ 5 ] + "]" + eid_prefix [ 6 ] + "-" + eid_prefix [ 7 ] + "-" + eid_prefix [ 8 ] + "/" + eid_prefix [ 9 ]
    if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
    command = command + "%" + OOOO0oo0 + "%" + I11iiI1i1
   else :
    command = command + "%" + OOOO0oo0 + "%"
    if 32 - 32: I1Ii111 / oO0o / I1IiiI
    if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
    if 69 - 69: oO0o - I1IiiI
 else :
  if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
  if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
  if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
  if 35 - 35: I1ii11iIi11i % OoooooooOO
  eid_prefix = eid_prefix . split ( "-" )
  if ( eid_prefix [ 1 ] == "*" ) :
   OOOO0oo0 = ""
   I11iiI1i1 = "[" + eid_prefix [ 2 ] + "]" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 59 - 59: I1IiiI % I11i
  else :
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "/" + eid_prefix [ 2 ]
   if 32 - 32: I1IiiI * O0 + O0
   if ( len ( eid_prefix ) == 6 ) :
    I11iiI1i1 = "[" + eid_prefix [ 3 ] + "]" + eid_prefix [ 4 ] + "/" + eid_prefix [ 5 ]
    if 34 - 34: IiII
    if 5 - 5: OoO0O00 . I1IiiI
    if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
  command = command + "%" + OOOO0oo0 + "%" + I11iiI1i1
  if 47 - 47: iII111i / OoooooooOO - II111iiii
 return ( command )
 if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
 if 23 - 23: i1IIi
 if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
 if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
 if 31 - 31: I1Ii111 - I11i
 if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
 if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
def lisp_show_dynamic_eid_command ( parm ) :
 I1i1iii = ""
 if ( parm == "" ) : return ( I1i1iii )
 if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
 oO0OOOO00o = lisp_get_lookup_string ( parm . split ( "%" ) [ 0 ] )
 oO0OOOO00o = oO0OOOO00o [ 0 ]
 if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
 O0oooO = lisp . lisp_db_for_lookups . lookup_cache ( oO0OOOO00o , False )
 if ( O0oooO == None ) : return ( I1i1iii )
 if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
 O0oOo = "ITR" if lisp . lisp_i_am_itr else "ETR"
 OOOO0oo0 = O0oooO . print_eid_tuple ( )
 if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
 o0000oO = "LISP-{} Discovered Dynamic EIDs for {}:" . format ( O0oOo , OOOO0oo0 )
 if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
 if ( O0oOo == "ITR" ) :
  I1i1iii = lisp_table_header ( o0000oO , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Last Packet" , "Inactivity Timeout" )
 else :
  I1i1iii = lisp_table_header ( o0000oO , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Inactivity Timeout" )
  if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
  if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
 for i1iI1 in list ( O0oooO . dynamic_eids . values ( ) ) :
  oO0OOOO00o = i1iI1 . dynamic_eid . print_address ( )
  ooI1111 = lisp . lisp_print_elapsed ( i1iI1 . uptime )
  o0OOOo0 = str ( i1iI1 . timeout ) + " secs"
  if ( O0oOo == "ITR" ) :
   o00ooo0O = lisp . lisp_print_elapsed ( i1iI1 . last_packet )
   I1i1iii += lisp_table_row ( oO0OOOO00o , i1iI1 . interface , ooI1111 , o00ooo0O , o0OOOo0 )
  else :
   I1i1iii += lisp_table_row ( oO0OOOO00o , i1iI1 . interface , ooI1111 , o0OOOo0 )
   if 54 - 54: I1ii11iIi11i * IiII
   if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
 I1i1iii += lisp_table_footer ( )
 return ( I1i1iii )
 if 15 - 15: I1ii11iIi11i * Ii1I / iII111i . o0oOOo0O0Ooo / Ii1I % OoOoOO00
 if 75 - 75: OoooooooOO % i11iIiiIii % iIii1I11I1II1 % I1ii11iIi11i / i11iIiiIii
 if 96 - 96: ooOoO0o * oO0o / iIii1I11I1II1 / I11i
 if 5 - 5: o0oOOo0O0Ooo
 if 83 - 83: I11i * I1IiiI . II111iiii * i1IIi % O0
 if 35 - 35: OoOoOO00 % OoO0O00 + O0 * o0oOOo0O0Ooo % I1ii11iIi11i
 if 57 - 57: oO0o / I11i
 if 63 - 63: ooOoO0o * OoO0O00 * ooOoO0o + OoOoOO00
 if 25 - 25: iII111i * OoOoOO00 / I1IiiI / IiII
def lisp_clear_decap_stats ( command ) :
 i1iiIi = command . split ( "%" ) [ 1 ]
 lisp . lisp_decap_stats [ i1iiIi ] = lisp . lisp_stats ( )
 if 49 - 49: o0oOOo0O0Ooo * Ii1I + Oo0Ooo
 if 1 - 1: o0oOOo0O0Ooo / II111iiii + I11i . i11iIiiIii + ooOoO0o . OoOoOO00
 if 95 - 95: o0oOOo0O0Ooo / I1Ii111 % II111iiii + ooOoO0o
 if 97 - 97: OOooOOo
 if 55 - 55: ooOoO0o
 if 1 - 1: OoO0O00
 if 43 - 43: iIii1I11I1II1 - OOooOOo - o0oOOo0O0Ooo + I1ii11iIi11i - I1Ii111 % I1ii11iIi11i
def lisp_show_decap_stats ( output , etr_or_rtr ) :
 oo000O0 = etr_or_rtr . upper ( )
 I111Ii111 = etr_or_rtr . lower ( )
 if 1 - 1: Ii1I - II111iiii
 iIIi11 = [ ]
 for oo000O0o in lisp . lisp_decap_stats :
  oo0o0 = "<a href='/lisp/clear/{}/stats/{}'>{}</a>" . format ( I111Ii111 , oo000O0o , oo000O0o )
  iIIi11 . append ( oo0o0 )
  if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
  if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
 iI11iiI1 = "LISP-{} Decapsulation Stats:" . format ( oo000O0 )
 output += lisp_table_header ( iI11iiI1 , * iIIi11 )
 if 45 - 45: I11i . oO0o - ooOoO0o . iII111i / IiII
 iIIi11 = [ ]
 for ooo in list ( lisp . lisp_decap_stats . values ( ) ) :
  iIIi11 . append ( ooo . get_stats ( False , True ) )
  if 17 - 17: II111iiii
 output += lisp_table_row ( * iIIi11 )
 output += lisp_table_footer ( )
 return ( output )
 if 66 - 66: IiII * oO0o
 if 73 - 73: i11iIiiIii + O0 % O0
 if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
 if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
 if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
 if 18 - 18: OoOoOO00
 if 30 - 30: II111iiii
 if 27 - 27: i1IIi - iIii1I11I1II1 + O0 % Oo0Ooo / OOooOOo + i1IIi
def lisp_show_crypto_list ( xtr ) :
 I1i1iii = ""
 i1i1ii = len ( lisp . lisp_crypto_keys_by_nonce ) != 0
 if 60 - 60: IiII / iIii1I11I1II1 + OoooooooOO - I1ii11iIi11i * i11iIiiIii
 if ( lisp . lisp_i_am_itr or lisp . lisp_i_am_rtr ) :
  if ( i1i1ii ) :
   o0000oO = "LISP-{} Nonce Crypto State" . format ( xtr )
   I1i1iii += lisp_table_header ( o0000oO , "Nonce" , "Uptime" , "Key-ID" ,
 "Key Material" )
   for oo000O0o in lisp . lisp_crypto_keys_by_nonce :
    i1iIII1IIi = "0x" + lisp . lisp_hex_string ( oo000O0o )
    oo00oO0O0 = lisp . lisp_crypto_keys_by_nonce [ oo000O0o ]
    for Iii1iIIi1iIii in oo00oO0O0 :
     if ( Iii1iIIi1iIii == None ) : continue
     oO = lisp . lisp_print_elapsed ( Iii1iIIi1iIii . uptime )
     o0oo000 = Iii1iIIi1iIii . print_keys ( False )
     I1i1iii += lisp_table_row ( i1iIII1IIi , oO , Iii1iIIi1iIii . key_id , o0oo000 )
     i1iIII1IIi = ""
     if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
     if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
   I1i1iii += lisp_table_footer ( )
   if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
   if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
  o0000oO = "LISP-{} Encapsulation Crypto State" . format ( xtr )
  I1i1iii += lisp_table_header ( o0000oO , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for oo000O0o in lisp . lisp_crypto_keys_by_rloc_encap :
   i1iIII1IIi = oo000O0o
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_encap [ oo000O0o ]
   for Iii1iIIi1iIii in oo00oO0O0 :
    if ( Iii1iIIi1iIii == None ) : continue
    oO = lisp . lisp_print_elapsed ( Iii1iIIi1iIii . uptime )
    IiIIIiI11i1 = lisp . lisp_print_elapsed ( Iii1iIIi1iIii . last_rekey )
    o0oo000 = Iii1iIIi1iIii . print_keys ( False )
    I1i1iii += lisp_table_row ( i1iIII1IIi , oO , IiIIIiI11i1 , Iii1iIIi1iIii . rekey_count ,
 Iii1iIIi1iIii . use_count , Iii1iIIi1iIii . key_id , o0oo000 )
    i1iIII1IIi = ""
    if 14 - 14: Oo0Ooo % iIii1I11I1II1 - iIii1I11I1II1 . iIii1I11I1II1 - o0oOOo0O0Ooo * I1Ii111
    if 10 - 10: OoO0O00 - II111iiii % o0oOOo0O0Ooo - OoOoOO00 + OoO0O00
  I1i1iii += lisp_table_footer ( )
  if 88 - 88: iIii1I11I1II1 % ooOoO0o + o0oOOo0O0Ooo * OoOoOO00 / I11i . OoO0O00
  if 66 - 66: iIii1I11I1II1 * II111iiii . iIii1I11I1II1 * i11iIiiIii + I11i + Ii1I
 if ( lisp . lisp_i_am_etr or lisp . lisp_i_am_rtr ) :
  o0000oO = "LISP-{} Decapsulation Crypto State" . format ( xtr )
  I1i1iii += lisp_table_header ( o0000oO , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for oo000O0o in lisp . lisp_crypto_keys_by_rloc_decap :
   i1iIII1IIi = oo000O0o
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_decap [ oo000O0o ]
   for Iii1iIIi1iIii in oo00oO0O0 :
    if ( Iii1iIIi1iIii == None ) : continue
    oO = lisp . lisp_print_elapsed ( Iii1iIIi1iIii . uptime )
    IiIIIiI11i1 = lisp . lisp_print_elapsed ( Iii1iIIi1iIii . last_rekey )
    o0oo000 = Iii1iIIi1iIii . print_keys ( False )
    I1i1iii += lisp_table_row ( i1iIII1IIi , oO , IiIIIiI11i1 , Iii1iIIi1iIii . rekey_count ,
 Iii1iIIi1iIii . use_count , Iii1iIIi1iIii . key_id , o0oo000 )
    i1iIII1IIi = ""
    if 94 - 94: i1IIi * I11i - OoooooooOO . i1IIi / o0oOOo0O0Ooo
    if 51 - 51: i11iIiiIii * OoooooooOO
  I1i1iii += lisp_table_footer ( )
  if 23 - 23: II111iiii + I11i / O0 . I11i . I1Ii111 + iIii1I11I1II1
 return ( I1i1iii )
 if 2 - 2: i1IIi . O0 / o0oOOo0O0Ooo . II111iiii / OoO0O00 % i1IIi
 if 12 - 12: o0oOOo0O0Ooo
 if 58 - 58: iIii1I11I1II1 * Ii1I . ooOoO0o . Oo0Ooo * Ii1I
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
