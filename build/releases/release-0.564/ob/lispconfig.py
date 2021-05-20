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
 O0OO0O = 0
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
    O0OO0O += 1
   else :
    O0OO0O = 0
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
   if ( oO [ IiII1II11I ] [ O0OO0O ] != "" ) : O0OO0O += 1
   oO [ IiII1II11I ] [ O0OO0O ] = oo00oO0O0
  else :
   oO [ IiII1II11I ] = oo00oO0O0
   if 10 - 10: II111iiii . iII111i
   if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
   if 88 - 88: iII111i
   if 19 - 19: II111iiii * IiII + Ii1I
   if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
   if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
   if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
  if ( len ( kv_pairs [ IiII1II11I ] ) > 1 ) :
   o0oOoO0O = kv_pairs [ IiII1II11I ] [ 1 ]
   if ( type ( o0oOoO0O ) == int ) :
    if ( type ( oo00oO0O0 ) == str ) : oo00oO0O0 = oo00oO0O0 . split ( "-" ) [ 0 ]
    oo00oO0O0 = int ( oo00oO0O0 )
    if ( oo00oO0O0 < kv_pairs [ IiII1II11I ] [ 1 ] and oo00oO0O0 > kv_pairs [ IiII1II11I ] [ 2 ] ) :
     IIiIiiii += lisp_write_error ( OOo00OoO , "invalid range value" )
     ooo0 = True
     continue
     if 84 - 84: O0 * OoooooooOO - IiII * IiII
   elif ( oo00oO0O0 not in kv_pairs [ IiII1II11I ] [ 1 : : ] ) :
    IIiIiiii += lisp_write_error ( OOo00OoO , "invalid value keyword" )
    ooo0 = True
    continue
    if 8 - 8: ooOoO0o / i1IIi . oO0o
    if 41 - 41: iII111i + OoO0O00
    if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
    if 56 - 56: O0
    if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
    if 23 - 23: oO0o - OOooOOo + I11i
  IIiIiiii += lisp_write_line ( OOo00OoO )
  if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
  if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
 if ( ooo0 == True ) :
  IIiIiiii = IIiIiiii . replace ( "%" , "#" )
 else :
  IIiIiiii = IIiIiiii . replace ( "#" , "" )
  IIiIiiii = IIiIiiii . replace ( "%" , "#" )
  if 11 - 11: iII111i * Ii1I - OoOoOO00
 return ( [ ooo0 , IIiIiiii , oO ] )
 if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
 if 74 - 74: Oo0Ooo
 if 61 - 61: Oo0Ooo - I1Ii111 * II111iiii % ooOoO0o * iIii1I11I1II1 + OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
def lisp_process_command ( lisp_socket , opcode , clause , process , command_set ) :
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 OOO0ooo = clause . split ( " " )
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
 if ( clause . find ( "lisp debug" ) != - 1 ) :
  if ( clause . find ( "= yes" ) != - 1 ) :
   lisp . lisp_debug_logging = True
   Ii1Iii111IiI1 = lisp . bold ( "Enable" , False )
   lisp . lprint ( "{} process debug logging" . format ( Ii1Iii111IiI1 ) )
   if 98 - 98: I1Ii111 - OoooooooOO % I1IiiI + O0 . Ii1I
  if ( clause . find ( "= no" ) != - 1 ) :
   OoOO = lisp . bold ( "Disable" , False )
   lisp . lprint ( "{} process debug logging" . format ( OoOO ) )
   lisp . lisp_debug_logging = False
   if 44 - 44: OOooOOo
  return
  if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
  if 79 - 79: Ii1I . OoO0O00
  if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
  if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
  if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
  if 52 - 52: i1IIi
 o000 = ( OOO0ooo [ 0 ] == "show" )
 if ( o000 ) :
  OOooo0O = clause . split ( "%" )
  OOO0ooo = OOooo0O [ 0 ] . split ( " " )
  iiI1iIIiI = len ( OOooo0O )
  if ( iiI1iIIiI == 2 ) :
   OOooo0O = OOooo0O [ 1 ]
  elif ( iiI1iIIiI == 3 ) :
   OOooo0O = OOooo0O [ 1 ] + "%" + OOooo0O [ 2 ] + "%"
  else :
   OOooo0O = ""
   if 57 - 57: OoO0O00 / i1IIi . i1IIi
   if 74 - 74: iIii1I11I1II1 * IiII % OoOoOO00
 OOO0ooo = OOO0ooo [ 0 ] + " " + OOO0ooo [ 1 ]
 if 36 - 36: OoooooooOO - oO0o
 for OOo in command_set :
  if ( OOO0ooo in OOo ) :
   oo , I1IiIiiIiIII = OOo [ OOO0ooo ]
   break
   if 51 - 51: I1ii11iIi11i
  if ( OOo == command_set [ - 1 ] ) :
   lisp . lprint ( "Invalid command found '{}'" . format ( OOO0ooo ) )
   return
   if 41 - 41: I1ii11iIi11i * ooOoO0o - Ii1I + Oo0Ooo
   if 23 - 23: II111iiii % o0oOOo0O0Ooo + o0oOOo0O0Ooo + iII111i - iII111i
   if 62 - 62: o0oOOo0O0Ooo
   if 45 - 45: OOooOOo * ooOoO0o
   if 74 - 74: i1IIi + O0 + Oo0Ooo
   if 5 - 5: Oo0Ooo * OoOoOO00
   if 46 - 46: ooOoO0o
   if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
   if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
   if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 ooo0 = False
 if ( len ( I1IiIiiIiIII ) != 0 ) :
  ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
  if ( ooo0 ) :
   lisp . lprint ( "Command syntax error: {}" . format ( IIiIiiii ) )
  else :
   oo ( I1IiIiiIiIII )
   if 72 - 72: i1IIi
 else :
  if ( o000 ) : I1IiIiiIiIII = OOooo0O
  IIiIiiii = oo ( I1IiIiiIiIII )
  if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
  if 63 - 63: I1ii11iIi11i
 i1II = lisp . lisp_command_ipc ( IIiIiiii , process )
 lisp . lisp_ipc ( i1II , lisp_socket , "lisp-core" )
 return
 if 2 - 2: II111iiii - OoO0O00 . IiII * iII111i / oO0o
 if 80 - 80: OOooOOo / I11i / OoOoOO00 + i1IIi - Oo0Ooo
 if 11 - 11: o0oOOo0O0Ooo * OoO0O00
 if 15 - 15: OoOoOO00
 if 62 - 62: Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
def lisp_is_user_superuser ( username ) :
 if ( username == None ) : username = lisp_get_user ( )
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
 ooOo0O = getoutput ( "egrep -A 4 user-account ./lisp.config" )
 if 37 - 37: Ii1I % OoO0O00
 oOooO0 = "username = {}" . format ( username )
 O0OO0O = ooOo0O . find ( oOooO0 )
 o0o0O0O00oOOo = ooOo0O [ O0OO0O : : ] . find ( "}" )
 if ( O0OO0O == - 1 or o0o0O0O00oOOo == - 1 ) : return ( False )
 if 74 - 74: I11i - OOooOOo + i1IIi . I1IiiI + OOooOOo - I11i
 Ii = ooOo0O [ O0OO0O : O0OO0O + o0o0O0O00oOOo ] . find ( "super-user = yes" )
 return ( Ii != - 1 )
 if 15 - 15: O0 + O0 / Oo0Ooo . oO0o * I11i - I1ii11iIi11i
 if 95 - 95: OoO0O00 - OOooOOo / II111iiii % I1ii11iIi11i . o0oOOo0O0Ooo
 if 24 - 24: i1IIi . i11iIiiIii
 if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
 if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
 if 81 - 81: iII111i * OOooOOo - I1ii11iIi11i * Ii1I % OoOoOO00 * OoOoOO00
 if 59 - 59: iIii1I11I1II1
def lisp_find_user_account ( username , password ) :
 if 7 - 7: OOooOOo * I1IiiI / o0oOOo0O0Ooo * i11iIiiIii
 if 84 - 84: OOooOOo . iII111i
 if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
 if 21 - 21: oO0o / OoooooooOO
 ooOo0O = getoutput ( "egrep -A 4 user-account ./lisp.config" )
 if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
 if 87 - 87: I1Ii111 * i1IIi / I1ii11iIi11i
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo - OoooooooOO % OOooOOo * OoOoOO00
 if 69 - 69: i1IIi
 if 59 - 59: II111iiii - o0oOOo0O0Ooo
 O0OO0O = ooOo0O . find ( "username = {}\n" . format ( username ) )
 if ( O0OO0O == - 1 ) : return ( False )
 if 24 - 24: Oo0Ooo - i1IIi + I11i
 ooOo0O = ooOo0O [ O0OO0O : : ]
 ooOo0O = ooOo0O . replace ( "\t" , "" )
 ooOo0O = ooOo0O . replace ( " " , "" )
 if 38 - 38: OoooooooOO / I1ii11iIi11i . O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
 if 96 - 96: iII111i
 if 18 - 18: iII111i * I11i - Ii1I
 if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 O0OO0O = ooOo0O . find ( "password=" )
 if ( O0OO0O == - 1 ) : return ( False )
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 ooOo0O = ooOo0O [ O0OO0O : : ]
 o0o0O0O00oOOo = ooOo0O . find ( "\n" )
 if ( o0o0O0O00oOOo == - 1 ) : return ( False )
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 IIiIi1 = ooOo0O [ : o0o0O0O00oOOo ] . split ( "=" )
 if ( IIiIi1 [ 1 ] == "" ) :
  oO0oOo0 = lisp_hash_password ( password )
  if ( IIiIi1 [ 2 ] != oO0oOo0 ) : return ( False )
 else :
  if ( IIiIi1 [ 1 ] != password ) : return ( False )
  if 91 - 91: II111iiii % iII111i % IiII + II111iiii / oO0o
  if 62 - 62: OoooooooOO - i11iIiiIii
  if 5 - 5: iIii1I11I1II1 / I11i / i1IIi % OoooooooOO
  if 50 - 50: Ii1I / OoOoOO00 * Ii1I
  if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
  if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 return ( True )
 if 32 - 32: i11iIiiIii - I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
def lisp_validate_user ( ) :
 i1iiI = bottle . request . forms . get ( 'username' )
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if ( i1iiI == None ) :
  iiIiI = bottle . request . get_cookie ( "lisp-login" )
  if ( iiIiI ) : return ( True )
  if 38 - 38: IiII . Ii1I
  if 24 - 24: o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
 I1 = bottle . request . forms . get ( 'password' )
 if ( i1iiI == None or I1 == None ) : return ( False )
 if 13 - 13: OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - Oo0Ooo / oO0o
 if ( lisp_find_user_account ( i1iiI , I1 ) == False ) : return ( False )
 if 8 - 8: OoOoOO00 / O0 * O0 % I1Ii111 - Oo0Ooo + I11i
 if 83 - 83: O0 . I1IiiI
 if 95 - 95: I11i . OoooooooOO - i1IIi - OoooooooOO - OoO0O00 % iIii1I11I1II1
 if 64 - 64: OOooOOo + OoooooooOO * OoooooooOO
 i1I = None if os . getenv ( "LISP_NO_USER_TIMEOUT" ) == "" else LISP_USER_TIMEOUT
 if 36 - 36: I1IiiI * Oo0Ooo
 bottle . response . set_cookie ( "lisp-login" , i1iiI , max_age = i1I )
 return ( True )
 if 77 - 77: oO0o % i1IIi - Ii1I
 if 93 - 93: OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
def lisp_get_user ( ) :
 i1iiI = bottle . request . forms . get ( 'username' )
 if ( i1iiI ) : return ( i1iiI )
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 return ( bottle . request . get_cookie ( "lisp-login" ) )
 if 23 - 23: I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
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
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
def lisp_is_any_xtr_logging_on ( log_type ) :
 OOO0ooo = "egrep '" + log_type + " = '" + " ./lisp.config"
 OOO0ooo = getoutput ( OOO0ooo )
 if ( OOO0ooo == "" ) : return ( False )
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 if 66 - 66: Oo0Ooo
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 if 55 - 55: o0oOOo0O0Ooo . iII111i
 OOO0ooo = OOO0ooo . split ( "\n" )
 for oOo00o00oO in OOO0ooo :
  o0000 = oOo00o00oO . find ( "    {} = " . format ( log_type ) ) != - 1
  if ( oOo00o00oO [ 0 ] == " " and o0000 ) :
   OOO0ooo = oOo00o00oO . replace ( " " , "" )
   OOO0ooo = OOO0ooo . split ( "=" )
   if ( OOO0ooo [ 1 ] == "yes" ) : return ( True )
   if 42 - 42: I1Ii111 + I1Ii111 * II111iiii
   if 78 - 78: OoooooooOO
 return ( False )
 if 77 - 77: I1ii11iIi11i / i1IIi / Oo0Ooo % OOooOOo
 if 48 - 48: I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
 if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
 if 62 - 62: o0oOOo0O0Ooo
def lisp_landing_page ( ) :
 I1i111i = lisp . green ( "yes" , True )
 iI1i = lisp . red ( "no" , True )
 if 46 - 46: I1Ii111 % Ii1I
 oOO = I1i111i if lisp . lisp_is_running ( "lisp-itr" ) else iI1i
 oO0OO00OOo0 = I1i111i if lisp . lisp_is_running ( "lisp-etr" ) else iI1i
 Ii1IIii = I1i111i if lisp . lisp_is_running ( "lisp-rtr" ) else iI1i
 II1Ii = I1i111i if lisp . lisp_is_running ( "lisp-mr" ) else iI1i
 oOOoOoOOO = I1i111i if lisp . lisp_is_running ( "lisp-ms" ) else iI1i
 oOo = I1i111i if lisp . lisp_is_running ( "lisp-ddt" ) else iI1i
 if 86 - 86: II111iiii * i11iIiiIii * OoooooooOO + oO0o % OOooOOo
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
    ''' . format ( oOO , Ii1IIii , oO0OO00OOo0 , II1Ii , oOo , oOOoOoOOO )
 if 60 - 60: OoOoOO00 / I1Ii111 - II111iiii . Oo0Ooo + O0
 I1i1iii += '''
        <center>
        <style type="text/css">
        form { display:inline }
        </style>

        <a href="/lisp/show/status">
        <button style="background-color:transparent;border-radius:10px;
        type="button">system status</button></a>
    '''
 if 43 - 43: iIii1I11I1II1 / II111iiii % o0oOOo0O0Ooo - OOooOOo
 oO0O000oOo = lisp_get_clause_for_api ( "lisp debug" ) [ 0 ]
 oO0O000oOo = oO0O000oOo [ "lisp debug" ] if ( "lisp debug" in oO0O000oOo ) else None
 OoOOOO = "lisp xtr-parameters"
 I1iiIi111I = lisp_get_clause_for_api ( OoOOOO ) [ 0 ]
 Iiii1iIii = False
 if ( OoOOOO in I1iiIi111I ) :
  oOoooO000O = { "data-plane-logging" : "yes" }
  III1I11i1iIi = { "flow-logging" : "yes" }
  Iiii1iIii = ( oOoooO000O in I1iiIi111I [ OoOOOO ] or III1I11i1iIi in I1iiIi111I [ OoOOOO ] )
  if 69 - 69: Oo0Ooo * II111iiii * ooOoO0o . iII111i - I1ii11iIi11i
  if 39 - 39: Ii1I * I1IiiI % OoO0O00 . OoOoOO00
 iiii111IiIIi1 = { }
 for Oo0000o0O0O in oO0O000oOo : iiii111IiIIi1 [ list ( Oo0000o0O0O . keys ( ) ) [ 0 ] ] = list ( Oo0000o0O0O . values ( ) ) [ 0 ]
 oO0O000oOo = iiii111IiIIi1
 oO0O000oOo [ "ddt" ] = oO0O000oOo [ "ddt-node" ]
 oO0O000oOo [ "mr" ] = oO0O000oOo [ "map-resolver" ]
 oO0O000oOo [ "ms" ] = oO0O000oOo [ "map-server" ]
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . o0oOOo0O0Ooo . I1IiiI - I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 III11I1 = getoutput ( "wc -l logs/lisp-core.log" )
 III11I1 = III11I1 . replace ( " " , "" )
 III11I1 = III11I1 . split ( "logs" ) [ 0 ]
 iIIiI1iiI = "on" if oO0O000oOo [ "core" ] == "yes" else "off"
 I1i1iii += '''
        <form>
        <select size="1" style="width: 110px"
                onchange="parent.window.location=this.value">
        <option value="">show logging:</option>
        <option value="/lisp/show/log/lisp-core/100">[{}] core log [{}]
        </option>''' . format ( iIIiI1iiI , III11I1 )
 if 18 - 18: iII111i - oO0o % iII111i / I11i
 if ( os . path . exists ( "./logs/lisp-itr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-itr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIIiI1iiI = "on" if oO0O000oOo [ "itr" ] == "yes" else "off"
  I1i1iii += '''
            <option value="/lisp/show/log/lisp-itr/100">[{}] ITR log [{}]
            </option>''' . format ( iIIiI1iiI , III11I1 )
  if 68 - 68: Ii1I * iIii1I11I1II1 + I1Ii111 % OoOoOO00
 if ( os . path . exists ( "./logs/lisp-rtr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-rtr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIIiI1iiI = "on" if oO0O000oOo [ "rtr" ] == "yes" else "off"
  I1i1iii += '''<option value="/lisp/show/log/lisp-rtr/100">[{}] RTR 
           log [{}]</option>''' . format ( iIIiI1iiI , III11I1 )
  if 46 - 46: OoOoOO00 % i1IIi / oO0o * Oo0Ooo * OOooOOo
 if ( os . path . exists ( "./logs/lisp-etr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-etr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIIiI1iiI = "on" if oO0O000oOo [ "etr" ] == "yes" else "off"
  I1i1iii += '''<option value="/lisp/show/log/lisp-etr/100">[{}] ETR 
            log [{}]</option>''' . format ( iIIiI1iiI , III11I1 )
  if 67 - 67: OoOoOO00 * OoOoOO00 . OoOoOO00 + Ii1I / oO0o
 if ( os . path . exists ( "./logs/lisp-xtr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-xtr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIIiI1iiI = "on" if oO0O000oOo [ "itr" ] == "yes" or oO0O000oOo [ "etr" ] == "yes" or oO0O000oOo [ "rtr" ] == "yes" else "off"
  if 13 - 13: iII111i
  I1i1iii += '''<option value="/lisp/show/log/lisp-xtr/100">[{}] XTR 
           log [{}]</option>''' . format ( iIIiI1iiI , III11I1 )
  if 80 - 80: Ii1I - o0oOOo0O0Ooo
 if ( os . path . exists ( "./logs/lisp-mr.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-mr.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIIiI1iiI = "on" if oO0O000oOo [ "mr" ] == "yes" else "off"
  I1i1iii += '''<option value="/lisp/show/log/lisp-mr/100">[{}] MR 
            log [{}] </option>''' . format ( iIIiI1iiI , III11I1 )
  if 41 - 41: o0oOOo0O0Ooo - Oo0Ooo * I1IiiI
 if ( os . path . exists ( "./logs/lisp-ddt.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-ddt.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIIiI1iiI = "on" if oO0O000oOo [ "ddt" ] == "yes" else "off"
  I1i1iii += '''<option value="/lisp/show/log/lisp-ddt/100">[{}] DDT 
            log [{}]</option>''' . format ( iIIiI1iiI , III11I1 )
  if 82 - 82: OoO0O00 % o0oOOo0O0Ooo % OOooOOo / O0
 if ( os . path . exists ( "./logs/lisp-ms.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-ms.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIIiI1iiI = "on" if oO0O000oOo [ "ms" ] == "yes" else "off"
  I1i1iii += '''<option value="/lisp/show/log/lisp-ms/100">[{}] MS 
            log [{}]</option>''' . format ( iIIiI1iiI , III11I1 )
  if 94 - 94: I1ii11iIi11i + I1ii11iIi11i + OoooooooOO % ooOoO0o
 i1IIIi111Ii = lisp_is_any_xtr_logging_on ( "flow-logging" )
 if ( os . path . exists ( "./logs/lisp-flow.log" ) ) :
  III11I1 = getoutput ( "wc -l logs/lisp-flow.log" )
  III11I1 = III11I1 . replace ( " " , "" )
  III11I1 = III11I1 . split ( "logs" ) [ 0 ]
  iIIiI1iiI = "on" if i1IIIi111Ii else "off"
  I1i1iii += '''<option value="/lisp/show/log/lisp-flow/100">[{}] flow 
            log [{}]</option>''' . format ( iIIiI1iiI , III11I1 )
  if 15 - 15: o0oOOo0O0Ooo
 I1i1iii += "</select></form>"
 if 39 - 39: OOooOOo / I1ii11iIi11i / I1IiiI * I1Ii111
 if 44 - 44: O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / O0 - I11i
 if 83 - 83: IiII * I11i / Oo0Ooo
 if 32 - 32: o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
 Ii = lisp_is_user_superuser ( None )
 if ( Ii ) :
  I1i1iii += '''
            <form>
            <select size="1" style="width: 120px"
                    onchange="parent.window.location=this.value">
            <option value="">manage logging:</option>
        '''
  if 39 - 39: OoooooooOO * OOooOOo * O0 . I11i . OoO0O00 + ooOoO0o
  if 9 - 9: OoOoOO00 + oO0o % OoooooooOO + o0oOOo0O0Ooo
  if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
  if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
  if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
  if ( "yes" in list ( oO0O000oOo . values ( ) ) or Iiii1iIii ) :
   I1i1iii += '''<option value="/lisp/debug/{}%{}">disable all logging
                </option>''' . format ( "disable" , "all" )
   if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
   if 52 - 52: OoO0O00 % Ii1I * II111iiii
  I1IiIii11I = False
  i1iii1ii = False
  for II1 in oO0O000oOo :
   if ( lisp . lisp_is_running ( "lisp-" + II1 ) == False ) : continue
   if 27 - 27: Ii1I + I1IiiI * iIii1I11I1II1 . OoooooooOO * OoOoOO00
   if ( II1 in [ "itr" , "etr" , "rtr" ] ) :
    I1IiIii11I = True
    i1iii1ii = True
    if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
    if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
   o0o = oO0O000oOo [ II1 ]
   o00oO0oOo00 = II1
   if ( o00oO0oOo00 == "mr" ) : o00oO0oOo00 = "map-resolver"
   if ( o00oO0oOo00 == "ms" ) : o00oO0oOo00 = "map-server"
   if ( o00oO0oOo00 == "ddt" ) : o00oO0oOo00 = "ddt-node"
   if 93 - 93: ooOoO0o % i11iIiiIii % I1Ii111
   I1i1iii += '''<option value="/lisp/debug/{}%{}">{} {} logging
                </option>''' . format ( o00oO0oOo00 , "yes" if o0o == "no" else "no" ,
 "enable" if o0o == "no" else "disable" ,
 II1 . upper ( ) if II1 != "core" else "core" )
   if 64 - 64: I1Ii111 + I1IiiI * O0 / Oo0Ooo - I11i % I11i
  if ( I1IiIii11I ) :
   o0oO00 = lisp_is_any_xtr_logging_on ( "data-plane-logging" )
   I1i1iii += '''<option value="/lisp/debug/data-plane-logging%{}">{} 
                data-plane logging </option>''' . format ( "yes" if o0oO00 == False else "no" ,
   # O0
 "enable" if o0oO00 == False else "disable" )
   if 11 - 11: II111iiii / i11iIiiIii / O0
  if ( i1iii1ii ) :
   o0oO00 = i1IIIi111Ii
   I1i1iii += '''<option value="/lisp/debug/flow-logging%{}">{} 
                flow logging </option>''' . format (
 "yes" if o0oO00 == False else "no" ,
 "enable" if o0oO00 == False else "disable" )
   if 94 - 94: ooOoO0o * I11i - IiII . iIii1I11I1II1
  I1i1iii += "</select></form>"
  if 66 - 66: ooOoO0o - OOooOOo * OoOoOO00 / oO0o * II111iiii * OoO0O00
  if 91 - 91: OoooooooOO / Ii1I . I1IiiI + ooOoO0o . II111iiii
 I1i1iii += "<br><br>"
 if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
 if 77 - 77: I1Ii111 - I11i
 if 11 - 11: I1ii11iIi11i
 if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
 III1II111Ii1 = lisp . lisp_button ( "{}:<br>show map-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-itr" ) ) :
  III1II111Ii1 = '<a href="/lisp/show/itr/map-cache">' + III1II111Ii1 + '</a>'
  III1II111Ii1 = III1II111Ii1 . format ( lisp . green ( "ITR" , True ) )
 else :
  III1II111Ii1 = III1II111Ii1 . format ( lisp . red ( "ITR" , True ) )
  III1II111Ii1 = lisp . lisp_span ( III1II111Ii1 , "ITR not running" )
  if 82 - 82: I1Ii111 - OOooOOo + OoO0O00
  if 64 - 64: o0oOOo0O0Ooo . O0 * Ii1I + OoooooooOO - Oo0Ooo . OoooooooOO
 OOoO0oo0O = lisp . lisp_button ( "{}:<br>show map-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-rtr" ) ) :
  OOoO0oo0O = '<a href="/lisp/show/rtr/map-cache">' + OOoO0oo0O + '</a>'
  OOoO0oo0O = OOoO0oo0O . format ( lisp . green ( "RTR" , True ) )
 else :
  OOoO0oo0O = OOoO0oo0O . format ( lisp . red ( "RTR" , True ) )
  OOoO0oo0O = lisp . lisp_span ( OOoO0oo0O , "RTR not running" )
  if 49 - 49: o0oOOo0O0Ooo
  if 31 - 31: OoO0O00 * i11iIiiIii * Ii1I . i11iIiiIii
 II11iI1iiI = lisp . lisp_button ( "{}:<br>show referral-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-mr" ) ) :
  II11iI1iiI = '<a href="/lisp/show/referral">' + II11iI1iiI + '</a>'
  II11iI1iiI = II11iI1iiI . format ( lisp . green ( "MR" , True ) )
 else :
  II11iI1iiI = II11iI1iiI . format ( lisp . red ( "MR" , True ) )
  II11iI1iiI = lisp . lisp_span ( II11iI1iiI , "MR not running" )
  if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
  if 11 - 11: i1IIi % OoO0O00 % iII111i
 O0Oo0 = lisp . lisp_button ( "{}:<br>show delegations" , None )
 if ( lisp . lisp_is_running ( "lisp-ddt" ) ) :
  O0Oo0 = '<a href="/lisp/show/delegations">' + O0Oo0 + '</a>'
  O0Oo0 = O0Oo0 . format ( lisp . green ( "DDT" , True ) )
 else :
  O0Oo0 = O0Oo0 . format ( lisp . red ( "DDT" , True ) )
  O0Oo0 = lisp . lisp_span ( O0Oo0 , "DDT not running" )
  if 80 - 80: I1IiiI - iIii1I11I1II1 . OOooOOo + OoO0O00 - I1Ii111
  if 5 - 5: iII111i
 OOiI1 = lisp . lisp_button ( "{}:<br>show site-cache" , None )
 if ( lisp . lisp_is_running ( "lisp-ms" ) ) :
  OOiI1 = '<a href="/lisp/show/site">' + OOiI1 + '</a>'
  OOiI1 = OOiI1 . format ( lisp . green ( "MS" , True ) )
 else :
  OOiI1 = OOiI1 . format ( lisp . red ( "MS" , True ) )
  OOiI1 = lisp . lisp_span ( OOiI1 , "MS not running" )
  if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
  if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 iiI1Ii1I = lisp . lisp_button ( "{}:<br>show database-mappings" , None )
 if ( lisp . lisp_is_running ( "lisp-etr" ) ) :
  iiI1Ii1I = '<a href="/lisp/show/database">' + iiI1Ii1I + '</a>'
  iiI1Ii1I = iiI1Ii1I . format ( lisp . green ( "ETR" , True ) )
 else :
  iiI1Ii1I = iiI1Ii1I . format ( lisp . red ( "ETR" , True ) )
  iiI1Ii1I = lisp . lisp_span ( iiI1Ii1I , "ETR not running" )
  if 28 - 28: OOooOOo % ooOoO0o
  if 48 - 48: i11iIiiIii % oO0o
 i11i11 = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 Ii11Iii = lisp . lisp_geo_help_hover ( '<input type="text" name="geo-point" size="30" required />' )
 if 68 - 68: I1IiiI % O0
 OoOO0o = lisp . lisp_geo_help_hover ( '<input type="text" name="geo-prefix" size="30" required />' )
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 iIiI1I1IIi11 = lisp . lisp_button ( "API Documentation" , "/lisp/show/api-doc" )
 I1I1i11 = lisp . lisp_button ( "Command Documentation" , "/lisp/show/command-doc" )
 i1IiIi1i = lisp . lisp_button ( "IETF LISP WG Drafts" ,
 "http://datatracker.ietf.org/wg/lisp/" )
 IIIIiIi11iiIi = lisp . lisp_button ( "ddt-root.org" , "http://ddt-root.net" )
 i11iI11I1I = lisp . lisp_button ( "LISP Facebook Group" ,
 "https://www.facebook.com/groups/407716795982512" )
 Ii1iiIi1I11i = lisp . lisp_button ( "LISP LinkedIn Group" ,
 "http://www.linkedin.com/groups/3776183" )
 if 89 - 89: I1Ii111 . IiII % Oo0Ooo . Oo0Ooo - OoooooooOO
 oo0ooO0O0o = lisp . lisp_space ( 2 )
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

    ''' . format ( oo0ooO0O0o , III1II111Ii1 , oo0ooO0O0o , OOoO0oo0O , oo0ooO0O0o , iiI1Ii1I , oo0ooO0O0o , oo0ooO0O0o , II11iI1iiI , oo0ooO0O0o , O0Oo0 , oo0ooO0O0o , OOiI1 , oo0ooO0O0o ,
 i11i11 , i11i11 , Ii11Iii , OoOO0o , iIiI1I1IIi11 , I1I1i11 , i1IiIi1i , IIIIiIi11iiIi , i11iI11I1I , Ii1iiIi1I11i )
 if 75 - 75: II111iiii + OOooOOo
 return ( lisp_show_wrapper ( I1i1iii ) )
 if 28 - 28: I1IiiI
 if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
def lisp_drain_socket ( lisp_socket , process ) :
 lisp . lprint ( "Draining socket looking for {}" . format ( process ) )
 if 46 - 46: I1Ii111
 o00OoooooooOo = None
 while ( True ) :
  try :
   select . select ( [ lisp_socket ] , [ ] , [ ] )
  except :
   return ( o00OoooooooOo )
   if 32 - 32: o0oOOo0O0Ooo + I1IiiI . I1Ii111
   if 41 - 41: OoOoOO00 . i11iIiiIii / I11i
  lisp . lisp_ipc_lock . acquire ( )
  oOo00OoO0O , OoOoO0OooOOo , oOIIi , I1i1iii = lisp . lisp_receive ( lisp_socket , True )
  lisp . lisp_ipc_lock . release ( )
  if 32 - 32: I1Ii111 * iIii1I11I1II1 + Oo0Ooo * Oo0Ooo
  if ( OoOoO0OooOOo != process ) :
   lisp . lprint ( "Discarding IPC message from {}" . format ( OoOoO0OooOOo ) )
  elif ( o00OoooooooOo == None ) :
   o00OoooooooOo = I1i1iii
   if 29 - 29: IiII * I11i . OoO0O00
   if 100 - 100: iII111i / OoO0O00 * iIii1I11I1II1 * O0 - i1IIi
 return
 if 48 - 48: O0 * Ii1I * OoO0O00 . OoO0O00 * I11i - Ii1I
 if 14 - 14: I1ii11iIi11i + i11iIiiIii
 if 83 - 83: I1ii11iIi11i / i11iIiiIii + II111iiii . iII111i * OOooOOo + IiII
 if 42 - 42: i1IIi % II111iiii . ooOoO0o
 if 7 - 7: I1ii11iIi11i - oO0o * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i
 if 85 - 85: O0
 if 32 - 32: OoooooooOO . OoO0O00 / Oo0Ooo * o0oOOo0O0Ooo / o0oOOo0O0Ooo * Ii1I
 if 19 - 19: Ii1I
def lisp_process_show_command ( lisp_socket , command ) :
 if 55 - 55: OOooOOo % OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
 if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
 if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
 oo0ooooo00o = command . split ( "%" )
 oo0ooooo00o = oo0ooooo00o [ 0 ]
 if 78 - 78: iIii1I11I1II1 . o0oOOo0O0Ooo % iIii1I11I1II1 . O0 / OOooOOo
 if 76 - 76: i1IIi * OoooooooOO * O0 + I1Ii111 * I1Ii111
 if 35 - 35: o0oOOo0O0Ooo
 if 73 - 73: O0 - I1ii11iIi11i
 II1 = lisp_commands [ oo0ooooo00o ]
 II1 = II1 [ 0 ]
 if 2 - 2: II111iiii / I1Ii111
 if ( lisp . lisp_is_running ( II1 ) == False ) :
  I1i1iii = ( "<i>Process '{}' is not running, command cannot be " + "executed</i><br>" ) . format ( II1 )
  if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
  return ( lisp_show_wrapper ( I1i1iii ) )
  if 22 - 22: ooOoO0o . iIii1I11I1II1
  if 12 - 12: Ii1I
 command = lisp . lisp_command_ipc ( command , "lisp-core" )
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 lisp . lisp_ipc_lock . acquire ( )
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 lisp . lisp_ipc ( command , lisp_socket , II1 )
 lisp . lprint ( "Waiting for response to show command '{}'" . format ( command ) )
 if 77 - 77: II111iiii
 oOo00OoO0O , OoOoO0OooOOo , oOIIi , I1i1iii = lisp . lisp_receive ( lisp_socket , True )
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 lisp . lisp_ipc_lock . release ( )
 if 68 - 68: oO0o
 if 10 - 10: Ii1I
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if ( OoOoO0OooOOo == "" ) :
  lisp . lprint ( "Command '{}' timed out to {}" . format ( command , II1 ) )
 elif ( OoOoO0OooOOo != II1 ) :
  lisp . lprint ( "Received response from {} but expecting from {}" . format ( OoOoO0OooOOo , II1 ) )
  if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
  I1i1iii = lisp_drain_socket ( lisp_socket , II1 )
  if ( I1i1iii == None ) : I1i1iii = "<i>Fatal error, retry later</i><br>"
  if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 return ( lisp_show_wrapper ( I1i1iii ) )
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
def lisp_start_stop_process ( process , startstop ) :
 if ( startstop and lisp . lisp_is_running ( process ) ) : return
 if ( startstop == False and lisp . lisp_is_running ( process ) == False ) : return
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 Ooo0oO = "./logs/" + process + ".log"
 if 32 - 32: i1IIi . iII111i + II111iiii - OoO0O00 - iIii1I11I1II1
 if ( lisp . lisp_is_python2 ( ) ) :
  oO0O = "python -O "
  iIIIIiiii1I = process + ".pyo"
 elif ( lisp . lisp_is_python3 ( ) ) :
  oO0O = "python3.8 -O "
  iIIIIiiii1I = process + ".pyc"
 else :
  lisp . lprint ( "Cannot manage process '{}', unsupported python version" . format ( process ) )
  if 18 - 18: OoOoOO00 * IiII . oO0o . I1Ii111 * Oo0Ooo + OOooOOo
  if 10 - 10: iIii1I11I1II1 % I11i . o0oOOo0O0Ooo * I1Ii111 % II111iiii * IiII
  if 24 - 24: iII111i
 if ( lisp . lisp_is_ubuntu ( ) or lisp . lisp_is_raspbian ( ) or lisp . lisp_is_debian ( ) or lisp . lisp_is_debian_kali ( ) ) :
  if 33 - 33: I11i + OoO0O00 / OoooooooOO . ooOoO0o
  iII1iI111 = oO0O + iIIIIiiii1I + " 2>&1 > " + Ooo0oO + " &"
 else :
  iII1iI111 = oO0O + iIIIIiiii1I + " >& " + Ooo0oO + " &"
  if 94 - 94: iII111i % ooOoO0o . oO0o
  if 85 - 85: OOooOOo * i1IIi % I1IiiI - ooOoO0o
 I11 = getoutput ( "date" )
 if ( startstop and os . path . exists ( iIIIIiiii1I ) ) :
  lisp . lprint ( "Start process '{}' on {}" . format ( process , I11 ) )
  os . system ( iII1iI111 )
  time . sleep ( 1 )
  return
  if 39 - 39: ooOoO0o + O0 / i1IIi % IiII / oO0o * IiII
  if 77 - 77: IiII . I1Ii111 % OoOoOO00
 if ( startstop == False and os . path . exists ( iIIIIiiii1I ) ) :
  lisp . lprint ( "Stop process '{}' on {}" . format ( process , I11 ) )
  I1111III11 = getoutput ( "pgrep -f " + iIIIIiiii1I )
  I1111III11 = I1111III11 . split ( "\n" ) [ 0 ]
  os . system ( "kill " + I1111III11 )
  os . system ( "rm " + process )
  return
  if 46 - 46: O0
 return
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if 80 - 80: OoooooooOO + IiII
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if 43 - 43: Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
def lisp_enable_command ( clause ) :
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 if 5 - 5: IiII
 if ( os . path . exists ( "lisp.py" ) and os . path . exists ( "lisp.pyo" ) == False ) :
  lisp . lprint ( "In manual mode, ignoring 'lisp enable' command" )
  return ( clause )
  if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
  if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 OOO0ooo = clause . split ( " " )
 OOO0ooo = OOO0ooo [ 0 ] + " " + OOO0ooo [ 1 ]
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 I1IiIiiIiIII = lisp_core_commands [ "lisp enable" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 49 - 49: IiII * O0 . IiII
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
 if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
 if 96 - 96: OoooooooOO + IiII * O0
 if 86 - 86: Ii1I
 if ( ooo0 == True ) : return ( IIiIiiii )
 if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 O0OOO00 = { "itr" : "lisp-itr" , "etr" : "lisp-etr" , "rtr" : "lisp-rtr" ,
 "map-resolver" : "lisp-mr" , "map-server" : "lisp-ms" ,
 "ddt-node" : "lisp-ddt" }
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if 69 - 69: OoOoOO00
 if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 for OooOo in list ( O0OOO00 . keys ( ) ) :
  oOo0 = True if I1IiIiiIiIII [ OooOo ] == "yes" else False
  lisp_start_stop_process ( O0OOO00 [ OooOo ] , oOo0 )
  if 30 - 30: OOooOOo + II111iiii - IiII * OoooooooOO
 return ( IIiIiiii )
 if 19 - 19: IiII - o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00 / OOooOOo
 if 87 - 87: OoOoOO00 - ooOoO0o - OOooOOo + Oo0Ooo % iIii1I11I1II1 / i11iIiiIii
 if 12 - 12: ooOoO0o
 if 86 - 86: oO0o - OoO0O00
 if 63 - 63: I1IiiI / OoOoOO00 + OoooooooOO . I11i . ooOoO0o
 if 48 - 48: i1IIi - iII111i - i11iIiiIii . I11i - iII111i * I11i
 if 60 - 60: OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
def lisp_debug_command ( lisp_socket , clause , single_process ) :
 OOO0ooo = clause . split ( " " )
 OOO0ooo = OOO0ooo [ 0 ] + " " + OOO0ooo [ 1 ]
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 I1IiIiiIiIII = lisp_core_commands [ "lisp debug" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if ( ooo0 == True ) : return ( IIiIiiii )
 if 34 - 34: iII111i
 O0OOO00 = { "itr" : "lisp-itr" , "etr" : "lisp-etr" , "rtr" : "lisp-rtr" ,
 "map-resolver" : "lisp-mr" , "map-server" : "lisp-ms" ,
 "ddt-node" : "lisp-ddt" , "core" : "" }
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 for iIIi1Ii1III in I1IiIiiIiIII :
  II1 = O0OOO00 [ iIIi1Ii1III ]
  if ( single_process and single_process != II1 ) : continue
  if 86 - 86: i11iIiiIii + i11iIiiIii . I1Ii111 % I1IiiI . ooOoO0o
  o0o = I1IiIiiIiIII [ iIIi1Ii1III ]
  OOO0ooo = ( "lisp debug {\n" + "    {} = {}\n" . format ( iIIi1Ii1III , o0o ) + "}\n" )
  if 17 - 17: Ii1I
  if 67 - 67: O0 * I11i - o0oOOo0O0Ooo - II111iiii
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
  if 45 - 45: Ii1I - OOooOOo
  if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
  if ( iIIi1Ii1III == "core" ) :
   lisp_process_command ( None , None , OOO0ooo , None , [ None ] )
   continue
   if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
   if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
  OOO0ooo = lisp . lisp_command_ipc ( OOO0ooo , "lisp-core" )
  lisp . lisp_ipc ( OOO0ooo , lisp_socket , II1 )
  if ( single_process ) : break
  if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 return ( IIiIiiii )
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
def lisp_replace_password_in_clause ( clause , keyword_string ) :
 O0OO0O = clause . find ( keyword_string )
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if ( O0OO0O == - 1 ) : return ( clause )
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 if 24 - 24: ooOoO0o - I11i * oO0o
 O0OO0O += len ( keyword_string )
 o0o0O0O00oOOo = clause [ O0OO0O : : ] . find ( "\n" )
 o0o0O0O00oOOo += O0OO0O
 I1 = clause [ O0OO0O : o0o0O0O00oOOo ] . replace ( " " , "" )
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if ( len ( I1 ) != 0 and I1 [ 0 ] == "=" ) : return ( clause )
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 I1 = I1 . replace ( " " , "" )
 I1 = I1 . replace ( "\t" , "" )
 I1 = lisp_hash_password ( I1 )
 clause = clause [ 0 : O0OO0O ] + " =" + I1 + clause [ o0o0O0O00oOOo : : ]
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 return ( clause )
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
def lisp_user_account_command ( clause ) :
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 OOO0ooo = clause . split ( " " )
 OOO0ooo = OOO0ooo [ 0 ] + " " + OOO0ooo [ 1 ]
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 I1IiIiiIiIII = lisp_core_commands [ "lisp user-account" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if ( ooo0 == False ) :
  IIiIiiii = lisp_replace_password_in_clause ( IIiIiiii , "password =" )
  if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 return ( IIiIiiii )
 if 79 - 79: oO0o - II111iiii
 if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
 if 12 - 12: I1ii11iIi11i / Ii1I
def lisp_rtr_list_command ( clause ) :
 OOO0ooo = clause . split ( " " )
 OOO0ooo = OOO0ooo [ 0 ] + " " + OOO0ooo [ 1 ]
 if 5 - 5: OoooooooOO
 I1IiIiiIiIII = lisp_core_commands [ "lisp rtr-list" ]
 I1IiIiiIiIII = I1IiIiiIiIII [ 1 ]
 if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
 if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
 if 93 - 93: Oo0Ooo / I1ii11iIi11i + i1IIi * oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 33 - 33: I11i % II111iiii + OoO0O00
 if ( ooo0 ) : return ( IIiIiiii )
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 lisp . lisp_ms_rtr_list = [ ]
 if ( "address" in I1IiIiiIiIII ) :
  for Ii1I1i in I1IiIiiIiIII [ "address" ] :
   II = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   II . store_address ( Ii1I1i )
   lisp . lisp_ms_rtr_list . append ( II )
   if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
   if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 return ( IIiIiiii )
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
 if 33 - 33: Ii1I
def lisp_process_command_lines ( lisp_socket , old , new , line ) :
 OOO0ooo = line . split ( "{" )
 OOO0ooo = OOO0ooo [ 0 ]
 OOO0ooo = OOO0ooo [ 0 : - 1 ]
 if 93 - 93: ooOoO0o
 lisp . lprint ( "Process the '{}' command" . format ( OOO0ooo ) )
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 if 19 - 19: I1ii11iIi11i
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if 66 - 66: O0
 if ( OOO0ooo not in lisp_commands ) :
  line = "#>>> " + line . replace ( "\n" , " <<< invalid command\n" )
  new . write ( line )
  return
  if 52 - 52: OoO0O00 * OoooooooOO
  if 12 - 12: O0 + IiII * i1IIi . OoO0O00
  if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
  if 28 - 28: iIii1I11I1II1
  if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 O0O00 = lisp_commands [ OOO0ooo ]
 Iii11I1iII1 = False
 for II1 in O0O00 :
  if ( II1 == "" ) :
   line = lisp_write_error ( line , "invalid command" )
   new . write ( line )
   return
   if 24 - 24: oO0o / I1Ii111 / I11i % OoOoOO00 / I1ii11iIi11i * ooOoO0o
   if 8 - 8: Ii1I
  if ( Iii11I1iII1 == False ) :
   iIIi1 = line
   III11I1 = 1
   for line in old :
    if ( lisp_begin_clause ( line ) ) : III11I1 += 1
    iIIi1 += line
    if ( lisp_end_clause ( line ) ) :
     III11I1 -= 1
     if ( III11I1 == 0 ) : break
     if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
     if 92 - 92: OoOoOO00 % O0
     if 55 - 55: iIii1I11I1II1 * iII111i
     if 85 - 85: iIii1I11I1II1 . II111iiii
     if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
     if 22 - 22: OOooOOo
     if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
  if ( lisp . lisp_is_running ( II1 ) == False ) :
   if ( Iii11I1iII1 == False ) :
    for line in iIIi1 : new . write ( line )
    Iii11I1iII1 = True
    if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
   lisp . lprint ( "Process '{}' is not running, do not send command" . format ( II1 ) )
   if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
   continue
   if 94 - 94: i1IIi
   if 36 - 36: I1IiiI + Oo0Ooo
   if 46 - 46: iII111i
   if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
   if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
   if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
  if ( II1 == "lisp-core" ) :
   if ( iIIi1 . find ( "enable" ) != - 1 ) :
    IIiIiiii = lisp_enable_command ( iIIi1 )
    if 65 - 65: ooOoO0o - i1IIi
   if ( iIIi1 . find ( "debug" ) != - 1 ) :
    IIiIiiii = lisp_debug_command ( lisp_socket , iIIi1 , None )
    if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
   if ( iIIi1 . find ( "user-account" ) != - 1 ) :
    IIiIiiii = lisp_user_account_command ( iIIi1 )
    if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
   if ( iIIi1 . find ( "rtr-list" ) != - 1 ) :
    IIiIiiii = lisp_rtr_list_command ( iIIi1 )
    if 34 - 34: I1Ii111 - OOooOOo
  else :
   IIIiIi1iiI = lisp . lisp_command_ipc ( iIIi1 , "lisp-core" )
   lisp . lisp_ipc ( IIIiIi1iiI , lisp_socket , II1 )
   lisp . lprint ( "Waiting for response to config command '{}'" . format ( OOO0ooo ) )
   if 15 - 15: I1ii11iIi11i . iII111i
   if 94 - 94: I11i . I1IiiI
   oOo00OoO0O , OoOoO0OooOOo , oOIIi , IIiIiiii = lisp . lisp_receive ( lisp_socket ,
 True )
   if 73 - 73: i1IIi / II111iiii
   if ( OoOoO0OooOOo == "" ) :
    lisp . lprint ( "Command timed out to {}" . format ( II1 ) )
    IIiIiiii = iIIi1
   elif ( OoOoO0OooOOo != II1 ) :
    lisp . lprint ( "Fatal IPC error to {}, source {}" . format ( II1 ,
 OoOoO0OooOOo ) )
    if 45 - 45: Ii1I / ooOoO0o . OoooooooOO + OoO0O00
    if 51 - 51: iII111i % i11iIiiIii % IiII + I1Ii111 % I1ii11iIi11i
    if 16 - 16: OoOoOO00 / Oo0Ooo + O0 - OoOoOO00 . OoooooooOO
    if 19 - 19: o0oOOo0O0Ooo
    if 73 - 73: I1Ii111 * Oo0Ooo * OoOoOO00
    if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
    if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
  if ( Iii11I1iII1 == False ) :
   for line in IIiIiiii : new . write ( line )
   Iii11I1iII1 = True
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
 o0000 = getoutput ( OOO )
 if ( o0000 == "" ) :
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
    iIIi1 = ""
    OOO0ooo = OOo00OoO . split ( "{" )
    OOO0ooo = OOO0ooo [ 0 ]
    OOO0ooo = OOO0ooo [ 0 : - 1 ]
    if ( OOO0ooo in lisp_commands ) :
     ooOo0o = ( process in lisp_commands [ OOO0ooo ] ) or ( OOO0ooo == "lisp debug" )
     if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
     if 41 - 41: i1IIi - I1IiiI
     if 48 - 48: I1IiiI - II111iiii / OoO0O00 + I1IiiI
   IIIIiiI += 1
   if 5 - 5: O0
   if 75 - 75: I1Ii111 + iIii1I11I1II1
   if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
   if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
   if 92 - 92: I11i / O0 * I1IiiI - I11i
  if ( ooOo0o ) : iIIi1 += OOo00OoO
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
  lisp . lprint ( "Send command '{}' to restarting process '{}'" . format ( OOO0ooo , process ) )
  if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
  if 10 - 10: IiII / OoooooooOO
  if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
  if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
  if 25 - 25: iIii1I11I1II1
  if 63 - 63: ooOoO0o
  if ( OOO0ooo == "lisp debug" ) :
   lisp_debug_command ( lisp_socket , iIIi1 , process )
   ooOo0o = False
   continue
   if 96 - 96: I11i
   if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
  iIIi1 = lisp . lisp_command_ipc ( iIIi1 , "lisp-core" )
  lisp . lisp_ipc ( iIIi1 , lisp_socket , process )
  if 63 - 63: iII111i
  if 11 - 11: iII111i - iIii1I11I1II1
  if 92 - 92: OoO0O00
  if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
  if 12 - 12: ooOoO0o
  lisp . lprint ( "Waiting for response to config command '{}'" . format ( OOO0ooo ) )
  if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
  if 60 - 60: OOooOOo . iII111i / iIii1I11I1II1 + OOooOOo * I1Ii111
  oOo00OoO0O , OoOoO0OooOOo , oOIIi , i1II = lisp . lisp_receive ( lisp_socket , True )
  if 82 - 82: i11iIiiIii . iIii1I11I1II1 * I1IiiI - I11i + Ii1I
  if ( OoOoO0OooOOo == "" ) :
   lisp . lprint ( "Command timed out to {}" . format ( process ) )
  elif ( OoOoO0OooOOo != process ) :
   lisp . lprint ( "Fatal IPC error to {}, IPC source {}" . format ( process ,
 OoOoO0OooOOo ) )
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
  oO0OOoO0 = os . path . getmtime ( iIIIiIi1i )
  if ( oO0OOoO0 != i1ii111i ) :
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
    Ii1I1i = oo00oO0O0 if ( IiII1II11I == "address" ) else None
    oooOo00O0 = oo00oO0O0 if ( IiII1II11I == "dns-name" ) else None
    lisp . lisp_mr ( Ii1I1i , oooOo00O0 , Oo0000o )
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
 oO0OOoO0 = lisp . lisp_print_elapsed ( mc . uptime )
 OOOO0oo0 = mc . print_eid_tuple ( )
 Iiii = "Recent Sources: "
 Iiii += "none\n" if ( mc . recent_sources == { } ) else "\n"
 for oo0ooO0O0o in mc . recent_sources :
  oo0O = mc . recent_sources [ oo0ooO0O0o ]
  Iiii += "  " + oo0ooO0O0o + ": " + lisp . lisp_print_elapsed ( oo0O ) + "\n"
  if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
 OOOO0oo0 = lisp . lisp_span ( OOOO0oo0 , Iiii [ 0 : - 1 ] )
 i11111 = mc . action
 if 60 - 60: OOooOOo
 if 73 - 73: ooOoO0o
 if 86 - 86: OoOoOO00 . I11i / Oo0Ooo * I11i
 if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
 if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
 if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
 OoOoO0OooOOo = mc . mapping_source
 if ( OoOoO0OooOOo == None ) :
  OoOoO0OooOOo = "map-notify"
 else :
  OoOoO0OooOOo = "static" if OoOoO0OooOOo . is_null ( ) else OoOoO0OooOOo . print_address_no_iid ( )
  if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
  if 5 - 5: O0 - I1IiiI
  if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
 if ( mc . checkpoint_entry ) : OoOoO0OooOOo = "checkpoint"
 if ( mc . gleaned ) : OoOoO0OooOOo = "gleaned"
 i1iIi = mc . print_ttl ( )
 if 22 - 22: iII111i + OoO0O00 - ooOoO0o
 i11111 = "encapsulate" if i11111 == lisp . LISP_NO_ACTION else lisp . lisp_map_reply_action_string [ i11111 ]
 if 10 - 10: I1IiiI / I1ii11iIi11i
 if 68 - 68: OOooOOo - OoooooooOO
 if ( len ( mc . rloc_set ) == 0 ) :
  IiIII = mc . stats . get_stats ( True , True )
  output += lisp_table_row ( OOOO0oo0 , oO0OOoO0 + "<br>" + i1iIi , "--" , OoOoO0OooOOo ,
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
    ooOooOoo = lisp . lisp_nonce_echoing and o0o0OOo0O . echo_nonce_capable
    if ( lisp . lisp_rloc_probing ) :
     Iiii += o0o0OOo0O . print_rloc_probe_state ( ooOooOoo )
     if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
    if ( ooOooOoo ) :
     iiI1iiIiiiI1I = lisp . lisp_get_echo_nonce ( o0o0OOo0O . rloc , None )
     if ( iiI1iiIiiiI1I ) : Iiii += iiI1iiIiiiI1I . print_echo_nonce ( )
     if 6 - 6: OoO0O00
    if ( Iiii != "" ) : i1 = lisp . lisp_span ( i1 , Iiii )
    if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
    if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
    if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
  if ( o0o0OOo0O . translated_port != 0 ) :
   i1 += "encap-port: {}<br>" . format ( o0o0OOo0O . translated_port )
   if 31 - 31: oO0o * I1Ii111 . OoOoOO00 * I11i
   if 28 - 28: IiII + I1IiiI - Oo0Ooo % OOooOOo . I11i + I1IiiI
  if ( o0o0OOo0O . rloc_name ) :
   i1 += "rloc-name: {}<br>" . format ( lisp . blue ( o0o0OOo0O . rloc_name ,
 True ) )
   if 72 - 72: Ii1I / Oo0Ooo / oO0o * OoOoOO00 + OOooOOo
   if 58 - 58: o0oOOo0O0Ooo % I1IiiI . I1IiiI * OoO0O00 - IiII . OoooooooOO
  if ( o0o0OOo0O . geo ) :
   i1 += "geo: {}<br>" . format ( o0o0OOo0O . geo . print_geo_url ( ) )
   if 10 - 10: I1Ii111
  if ( o0o0OOo0O . elp ) :
   I11i1i11IiIi1 = o0o0OOo0O . elp . print_elp ( True )
   i1 += "elp: {}<br>" . format ( I11i1i11IiIi1 )
   if 8 - 8: iII111i - I1IiiI * Oo0Ooo % I1ii11iIi11i * OoooooooOO
  if ( o0o0OOo0O . rle ) :
   iii11 = o0o0OOo0O . rle . print_rle ( True , True )
   i1 += "rle: {}<br>" . format ( iii11 )
   if 20 - 20: OOooOOo - iII111i / Oo0Ooo * OoO0O00
  if ( o0o0OOo0O . json ) :
   if ( lisp . lisp_is_json_telemetry ( o0o0OOo0O . json . json_string ) == None ) :
    oOO00O0Ooooo00 = "json: { ... }<br>"
    i1 += lisp . lisp_span ( oOO00O0Ooooo00 , o0o0OOo0O . json . print_json ( False ) )
    if 55 - 55: OoooooooOO
    if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
    if 38 - 38: O0
    if 79 - 79: i1IIi . oO0o
    if 34 - 34: I1Ii111 * II111iiii
    if 71 - 71: IiII
  IiIII = o0o0OOo0O . stats . get_stats ( True , True )
  if 97 - 97: I1ii11iIi11i
  if 86 - 86: Oo0Ooo - OOooOOo . OoOoOO00 . II111iiii * I1IiiI . II111iiii
  if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
  if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
  iI = ""
  o00oo = o0o0OOo0O
  while ( True ) :
   O000Oo00 = lisp . lisp_print_elapsed ( o00oo . last_state_change )
   if ( O000Oo00 == "never" ) :
    O000Oo00 = lisp . lisp_print_elapsed ( o00oo . uptime )
    if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
   oo0ooO0O0o = o00oo . print_state ( )
   if ( o00oo . unreach_state ( ) or o00oo . no_echoed_nonce_state ( ) ) :
    oo0ooO0O0o = lisp . red ( oo0ooO0O0o , True )
    if 20 - 20: i1IIi . i1IIi - I11i
   iI += oo0ooO0O0o + " since " + O000Oo00
   if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
   if ( lisp . lisp_rloc_probing ) :
    IiIIiII1I = o00oo . print_rloc_probe_rtt ( )
    if ( IiIIiII1I != "none" ) :
     iI += "<br>rtt: {}, hops: {}, latency: {}" . format ( IiIIiII1I , o00oo . print_rloc_probe_hops ( ) ,
     # I11i / Ii1I * OOooOOo / II111iiii - o0oOOo0O0Ooo % O0
 o00oo . print_rloc_probe_latency ( ) )
     if 91 - 91: II111iiii - iIii1I11I1II1 / i1IIi * i1IIi % Oo0Ooo
     if 82 - 82: ooOoO0o
     if 70 - 70: iIii1I11I1II1 + i11iIiiIii + Oo0Ooo / iII111i
   if ( lisp . lisp_rloc_probing and o00oo . rloc_next_hop != None ) :
    oOoooO000O , iI1IiiiIi = o00oo . rloc_next_hop
    iI += "<br>{}nh {}({}) " . format ( lisp . lisp_space ( 2 ) , iI1IiiiIi , oOoooO000O )
    if 31 - 31: i11iIiiIii + IiII - I1Ii111 * iII111i
    if 60 - 60: iII111i + OoO0O00 + I11i % iIii1I11I1II1 . Oo0Ooo
   o00oo = o00oo . next_rloc
   if ( o00oo == None ) : break
   iI += "<br>"
   if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
   if 93 - 93: i11iIiiIii
  if ( i11111 == "encapsulate" ) :
   oOIIi = lisp . LISP_DATA_PORT
   if ( lisp . lisp_i_am_rtr and o0o0OOo0O . translated_port != 0 ) :
    oOIIi = o0o0OOo0O . translated_port
    if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
    if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
   Ii1I1i = o0o0OOo0O . rloc . print_address_no_iid ( ) + ":" + str ( oOIIi )
   if ( Ii1I1i in lisp . lisp_crypto_keys_by_rloc_encap ) :
    OoOOOO = lisp . lisp_crypto_keys_by_rloc_encap [ Ii1I1i ] [ 1 ]
    if ( OoOOOO != None and OoOOOO . shared_key != None ) :
     i11111 = "encap-crypto-" + OoOOOO . cipher_suite_string
     if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
     if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
     if 58 - 58: I11i
     if 7 - 7: II111iiii / IiII % I11i + I1IiiI - O0
  output += lisp_table_row ( OOOO0oo0 , oO0OOoO0 + "<br>" + i1iIi , i1 , OoOoO0OooOOo ,
 IiIII , iI + "<br>" + i11111 ,
 str ( o0o0OOo0O . priority ) + "/" + str ( o0o0OOo0O . weight ) + "<br>" + str ( o0o0OOo0O . mpriority ) + "/" + str ( o0o0OOo0O . mweight ) )
  if 45 - 45: I1IiiI / iII111i + oO0o + IiII
  if 15 - 15: I1IiiI % OoO0O00
  if ( OOOO0oo0 != "" ) : OOOO0oo0 = ""
  if ( oO0OOoO0 != "" ) : oO0OOoO0 , i1iIi , OoOoO0OooOOo = ( "" , "" , "" )
  if 66 - 66: oO0o * i11iIiiIii . I1Ii111
 return ( [ True , output ] )
 if 92 - 92: oO0o
 if 81 - 81: o0oOOo0O0Ooo % I1IiiI - iII111i / i11iIiiIii
 if 73 - 73: O0 * I1Ii111 . i1IIi
 if 51 - 51: OoO0O00 - iII111i % O0 - OoOoOO00
 if 53 - 53: iII111i / i1IIi / i1IIi
 if 77 - 77: I11i + i1IIi . I11i
 if 89 - 89: o0oOOo0O0Ooo + OOooOOo * oO0o
 if 45 - 45: iII111i - o0oOOo0O0Ooo . Ii1I
def lisp_walk_map_cache ( mc , output ) :
 if 41 - 41: II111iiii . I1IiiI / OoO0O00 . ooOoO0o
 if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
 if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
 if 36 - 36: I11i - IiII . IiII
 if ( mc . group . is_null ( ) ) : return ( lisp_display_map_cache ( mc , output ) )
 if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
 if ( mc . source_cache == None ) : return ( [ True , output ] )
 if 84 - 84: iIii1I11I1II1 + OoooooooOO
 if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
 if 10 - 10: I1ii11iIi11i + IiII
 if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
 if 62 - 62: II111iiii
 output = mc . source_cache . walk_cache ( lisp_display_map_cache , output )
 return ( [ True , output ] )
 if 12 - 12: IiII + II111iiii
 if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
 if 80 - 80: iII111i
 if 3 - 3: I1ii11iIi11i * I11i
 if 53 - 53: iIii1I11I1II1 / iII111i % OoO0O00 + IiII / ooOoO0o
 if 74 - 74: Oo0Ooo
 if 8 - 8: I1IiiI % II111iiii - o0oOOo0O0Ooo - I11i % I1IiiI
def lisp_show_myrlocs ( output ) :
 if ( lisp . lisp_myrlocs [ 2 ] == None ) :
  output += "No local RLOCs found"
 else :
  o0o0O0oOooO00 = lisp . lisp_print_cour ( lisp . lisp_myrlocs [ 2 ] )
  i1ii1111iiI = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 0 ] != None else "not found"
  if 21 - 21: II111iiii + Oo0Ooo
  i1ii1111iiI = lisp . lisp_print_cour ( i1ii1111iiI )
  OOooooO = "-f inet" if lisp . lisp_is_macos ( ) else "-4"
  oOoo00 = getoutput ( "netstat -rn {}" . format ( OOooooO ) )
  i1ii1111iiI = lisp . lisp_span ( i1ii1111iiI , oOoo00 )
  if 29 - 29: OOooOOo / OoOoOO00 . iIii1I11I1II1 / I11i % OoOoOO00 % iII111i
  iiI1 = lisp . lisp_myrlocs [ 1 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 1 ] != None else "not found"
  if 79 - 79: Ii1I
  iiI1 = lisp . lisp_print_cour ( iiI1 )
  OOooooO = "-f inet6" if lisp . lisp_is_macos ( ) else "-6"
  oOoo00 = getoutput ( "netstat -rn {}" . format ( OOooooO ) )
  iiI1 = lisp . lisp_span ( iiI1 , oOoo00 )
  if 27 - 27: OoO0O00 + Oo0Ooo
  OOo00OoO = "<i>Local RLOCs found on interface </i>{}<i>, " + "IPv4: </i>{}<i>, IPv6: </i>{}"
  if 92 - 92: I1IiiI % iII111i
  output += lisp . lisp_print_sans ( OOo00OoO ) . format ( o0o0O0oOooO00 , i1ii1111iiI , iiI1 )
  if 31 - 31: OoooooooOO - oO0o / I1Ii111
 output += "<br>"
 return ( output )
 if 62 - 62: i11iIiiIii - I11i
 if 81 - 81: I11i
 if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
 if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
 if 31 - 31: i1IIi % II111iiii
 if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
 if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
def lisp_display_nat_info ( output , dc , dodns ) :
 iiII = len ( lisp . lisp_nat_state_info )
 if ( iiII == 0 ) : return ( output )
 if 30 - 30: ooOoO0o
 Iiii = "{} entries in the NAT-traversal port table" . format ( iiII )
 oOooOOOOoo0O = lisp . lisp_span ( "NAT-Traversed xTR Information:" , Iiii )
 if 24 - 24: oO0o - iII111i / ooOoO0o
 if ( dodns ) :
  output += lisp_table_header ( oOooOOOOoo0O , "xTR Hostname" ,
 "Translated<br>Address" , "Translated<br>{} Port" . format ( dc ) ,
 "Last<br>Info-Request" , "NAT DNS Name" )
 else :
  output += lisp_table_header ( oOooOOOOoo0O , "xTR Hostname" ,
 "Translated<br>Address" , "Translated<br>{} Port" . format ( dc ) ,
 "Last<br>Info-Request" )
  if 10 - 10: OoOoOO00 * i1IIi
  if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
 for iIIi1OoOo0O00 in list ( lisp . lisp_nat_state_info . values ( ) ) :
  for iI1i1iI1iI in iIIi1OoOo0O00 :
   II = iI1i1iI1iI . address
   OO = iI1i1iI1iI . uptime
   O0I11i1i11i1I = iI1i1iI1iI . hostname
   oOIIi = iI1i1iI1iI . port
   if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
   if ( iI1i1iI1iI . timed_out ( ) ) :
    OO = lisp . red ( lisp . lisp_print_elapsed ( OO ) , True )
   else :
    OO = lisp . lisp_print_elapsed ( OO )
    if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
    if 52 - 52: I1Ii111 + I1Ii111
   if ( dodns ) :
    try :
     OO0 = socket . gethostbyaddr ( II ) [ 0 ]
    except :
     OO0 = "?"
     if 1 - 1: O0 . I1IiiI * OoooooooOO
    output += lisp_table_row ( O0I11i1i11i1I , II , oOIIi , OO , OO0 )
   else :
    output += lisp_table_row ( O0I11i1i11i1I , II , oOIIi , OO )
    if 70 - 70: O0 / OoooooooOO + I1ii11iIi11i + i1IIi
    if 63 - 63: iII111i / I1ii11iIi11i * oO0o / II111iiii + OOooOOo - O0
    if 16 - 16: II111iiii / Ii1I . Ii1I - Ii1I / I1ii11iIi11i
    if 28 - 28: OOooOOo * OoooooooOO + ooOoO0o % iII111i . iIii1I11I1II1
 output += lisp_table_footer ( )
 return ( output )
 if 17 - 17: IiII / o0oOOo0O0Ooo . OOooOOo + o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo
 if 39 - 39: o0oOOo0O0Ooo / IiII - iII111i
 if 96 - 96: I11i * I1ii11iIi11i * Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
 if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
 if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
 if 1 - 1: Oo0Ooo . II111iiii
 if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
def lisp_itr_rtr_show_command ( parameter , itr_or_rtr , lisp_threads , dns = False ) :
 if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
 if 4 - 4: IiII
 if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
 if 99 - 99: i11iIiiIii - iII111i
 if ( parameter != "" ) :
  return ( lisp_show_map_cache_lookup ( parameter ) )
  if 85 - 85: I1Ii111 % I1ii11iIi11i
  if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
 I1i1iii = ""
 if 73 - 73: OoO0O00
 if 28 - 28: OoooooooOO - I11i
 if 84 - 84: II111iiii
 if 36 - 36: OOooOOo - OoOoOO00 - iIii1I11I1II1
 I1i1iii = lisp_show_myrlocs ( I1i1iii )
 if 10 - 10: I1ii11iIi11i / Ii1I * i1IIi % O0 + I11i
 if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
 if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
 if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
 if ( itr_or_rtr == "RTR" ) :
  I1i1iii = lisp_show_decap_stats ( I1i1iii , itr_or_rtr )
  if 80 - 80: Ii1I
  if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
  if 59 - 59: I1ii11iIi11i + I11i . oO0o
  if 87 - 87: OoO0O00
  if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
 if ( len ( lisp_threads ) > 1 ) :
  oo0ooO0O0o = [ ]
  for i1iIIiiIiII in range ( len ( lisp_threads ) ) :
   oo0O = lisp_threads [ i1iIIiiIiII ]
   oo0ooO0O0o . append ( "{} Input Stats<br>queue-size: {}" . format ( oo0O . thread_name ,
 oo0O . input_queue . qsize ( ) ) )
   if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
  I1i1iii += lisp_table_header ( "LISP-RTR Forwarding Stats:" , * oo0ooO0O0o )
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  oo0ooO0O0o = [ ]
  for i1iIIiiIiII in range ( len ( lisp_threads ) ) :
   oo0O = lisp_threads [ i1iIIiiIiII ]
   oo0ooO0O0o . append ( oo0O . input_stats . get_stats ( False , True ) )
   if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
  I1i1iii += lisp_table_row ( * oo0ooO0O0o )
  I1i1iii += lisp_table_footer ( )
  if 46 - 46: i11iIiiIii
  if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
 I11111ii1i = lisp . lisp_decent_dns_suffix
 if ( I11111ii1i == None ) :
  I11111ii1i = ":"
 else :
  I11111ii1i = "&nbsp;(dns-suffix '{}'):" . format ( I11111ii1i )
  if 78 - 78: I11i % Oo0Ooo + OoOoOO00 . I1ii11iIi11i % oO0o / Ii1I
  if 37 - 37: oO0o % I1Ii111 % oO0o
  if 14 - 14: OoO0O00 / I1IiiI
  if 66 - 66: Oo0Ooo / i11iIiiIii % ooOoO0o
  if 43 - 43: OOooOOo
 Iiii = "{} map-resolvers configured" . format ( len ( lisp . lisp_map_resolvers_list ) )
 if 84 - 84: OOooOOo . IiII . iII111i
 oOooOOOOoo0O = "LISP-{} Configured Map-Resolvers{}" . format ( itr_or_rtr , I11111ii1i )
 oOooOOOOoo0O = lisp . lisp_span ( oOooOOOOoo0O , Iiii )
 if 2 - 2: Oo0Ooo - OoOoOO00
 I1i1iii += lisp_table_header ( oOooOOOOoo0O , "Map-Resolver" , "Last Used" ,
 "Map-Requests<br>Sent" , "Negative Map-Replies<br>Received" ,
 "Last Negative<br>Map-Reply" , "Average RTT" )
 if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
 for II1Ii in list ( lisp . lisp_map_resolvers_list . values ( ) ) :
  II1Ii . resolve_dns_name ( )
  Oo0000o = "" if II1Ii . mr_name == "all" else II1Ii . mr_name + "<br>"
  Ii1I1i = Oo0000o + II1Ii . map_resolver . print_address_no_iid ( )
  if ( II1Ii . dns_name ) : Ii1I1i += "<br>" + II1Ii . dns_name
  if 54 - 54: ooOoO0o % Oo0Ooo - OOooOOo
  oO0OOoO0 = lisp . lisp_print_elapsed ( II1Ii . last_used )
  iIi11IiiiII11 = lisp . lisp_print_elapsed ( II1Ii . last_reply )
  i1IiI = 0 if II1Ii . neg_map_replies_received == 0 else float ( old_div ( II1Ii . total_rtt / II1Ii . neg_map_replies_received ) )
  if 2 - 2: I1ii11iIi11i - Oo0Ooo
  i1IiI = str ( round ( i1IiI , 3 ) ) + " ms"
  if 4 - 4: O0 / I11i . OoO0O00 - ooOoO0o / OOooOOo
  I1i1iii += lisp_table_row ( Ii1I1i , oO0OOoO0 , II1Ii . map_requests_sent ,
 II1Ii . neg_map_replies_received , iIi11IiiiII11 , i1IiI )
  if 25 - 25: I11i * OoOoOO00 - Oo0Ooo . ooOoO0o . oO0o
 I1i1iii += lisp_table_footer ( )
 if 89 - 89: O0 * I11i * OoO0O00
 if 3 - 3: OOooOOo / iII111i * iIii1I11I1II1 + II111iiii / o0oOOo0O0Ooo / IiII
 if 25 - 25: OoOoOO00 + OoO0O00 % Ii1I % OOooOOo / oO0o
 if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
 if ( itr_or_rtr == "ITR" ) : I1i1iii = lisp_show_db_list ( "ITR" , I1i1iii )
 if 23 - 23: I1IiiI
 if 7 - 7: iII111i % I1ii11iIi11i
 if 64 - 64: I1Ii111 + i11iIiiIii
 if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
 O0OoOoo00o = "<br>Enter EID for Map-Cache lookup:"
 if 68 - 68: IiII . ooOoO0o
 Oo0OooooOO0o0OO = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 24 - 24: oO0o . O0 * ooOoO0o / OoooooooOO - Ii1I . I11i
 iIIiIi111iI = itr_or_rtr . lower ( )
 if 40 - 40: OoOoOO00 + OoO0O00 % OoooooooOO * o0oOOo0O0Ooo / OoOoOO00 + OoooooooOO
 O0OoOoo00o = '''
         <form action="/lisp/show/{}/map-cache/lookup" method="post">
         <font size="3"><i>{}</i> {}
         <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form>
    ''' . format ( iIIiIi111iI , lisp . lisp_print_sans ( O0OoOoo00o ) , Oo0OooooOO0o0OO )
 if 91 - 91: ooOoO0o - oO0o + oO0o
 II11iiIIiI11I = '<a href="/lisp/show/{}/rloc-probing">RLOC State</a>' . format ( iIIiIi111iI )
 if 56 - 56: OoooooooOO * IiII + I1Ii111 / I1IiiI * IiII / i1IIi
 i111IiIi1 = '<a href="/lisp/show/{}/keys"><br>RLOC Keys</a>' . format ( iIIiIi111iI )
 if 16 - 16: i11iIiiIii * OOooOOo . IiII
 if 100 - 100: OoO0O00 . I11i / Ii1I . o0oOOo0O0Ooo - OoOoOO00 . I11i
 if 30 - 30: Ii1I % I11i + o0oOOo0O0Ooo
 if 65 - 65: iIii1I11I1II1 . iII111i / Ii1I
 iI11ii = os . path . exists ( "./show-ztr" )
 oOoooO00OO0o = "Map-Cache"
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None or iI11ii ) :
  oOoooO00OO0o = '<a href="/lisp/show/lisp-xtr">Map-Cache</a>'
  if 29 - 29: Oo0Ooo + II111iiii
  if 95 - 95: oO0o
  if 48 - 48: I11i / iIii1I11I1II1 % II111iiii
  if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
  if 100 - 100: OoooooooOO - OoooooooOO + IiII
 Iiii = "{} entries in the map-cache" . format ( lisp . lisp_map_cache . cache_size ( ) )
 if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo / OoooooooOO
 oOooOOOOoo0O = "LISP-{} {}:{}" . format ( itr_or_rtr , oOoooO00OO0o , lisp . lisp_space ( 4 ) )
 oOooOOOOoo0O = lisp . lisp_span ( oOooOOOOoo0O , Iiii )
 if 90 - 90: I1Ii111
 if 35 - 35: II111iiii / Ii1I
 if 79 - 79: OoOoOO00 + I1Ii111 * iII111i * Ii1I
 if 53 - 53: OOooOOo / Oo0Ooo
 if 10 - 10: I1ii11iIi11i . o0oOOo0O0Ooo
 oOooOOOOoo0O += lisp . lisp_button ( "clear cache" ,
 "/lisp/clear/{}/map-cache" . format ( itr_or_rtr . lower ( ) ) )
 oOooOOOOoo0O += O0OoOoo00o
 if 75 - 75: O0 * i1IIi - I11i / OOooOOo % OOooOOo / OoOoOO00
 if 5 - 5: O0 - iII111i / I1Ii111 . o0oOOo0O0Ooo
 I1i1iii += lisp_table_header ( oOooOOOOoo0O , "EID-Prefix or (S,G)" ,
 "Uptime<br>TTL" , "RLOC Record" + i111IiIi1 , "Map-Reply Source" ,
 "RLOC Send Stats" , II11iiIIiI11I + "<br>RLOC Action" ,
 "Unicast Priority/Weight<br>Multicast Priority/Weight" )
 if 7 - 7: I1ii11iIi11i - OoOoOO00
 I1i1iii = lisp . lisp_map_cache . walk_cache ( lisp_walk_map_cache , I1i1iii )
 I1i1iii += lisp_table_footer ( )
 if 54 - 54: oO0o / iIii1I11I1II1 / OoooooooOO . i1IIi - OoOoOO00
 if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
 if 46 - 46: Ii1I
 if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
 if ( len ( lisp . lisp_elp_list ) != 0 ) : I1i1iii = lisp_show_elp_list ( I1i1iii )
 if 87 - 87: I1ii11iIi11i / I1IiiI
 if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
 if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
 if 11 - 11: I1ii11iIi11i - OoooooooOO
 if ( len ( lisp . lisp_rle_list ) != 0 ) : I1i1iii = lisp_show_rle_list ( I1i1iii )
 if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
 if 27 - 27: IiII + iIii1I11I1II1 / Oo0Ooo + OoO0O00 % Oo0Ooo + OoO0O00
 if 77 - 77: Oo0Ooo * ooOoO0o % Ii1I
 if 2 - 2: I11i / Oo0Ooo / Ii1I / I1ii11iIi11i / OoooooooOO
 if ( len ( lisp . lisp_json_list ) != 0 ) : I1i1iii = lisp_show_json_list ( I1i1iii )
 if 22 - 22: iIii1I11I1II1 * I1IiiI / I11i + OoOoOO00
 if 98 - 98: OOooOOo
 if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
 if 75 - 75: OoO0O00 % OoooooooOO
 if ( itr_or_rtr == "RTR" ) :
  I1i1iii = lisp_display_nat_info ( I1i1iii , "Data" , dns )
  if 16 - 16: O0 / i1IIi
  if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
  if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
  if 12 - 12: OoOoOO00 + o0oOOo0O0Ooo . I1Ii111
  if 52 - 52: OoO0O00
 return ( I1i1iii )
 if 4 - 4: Ii1I % I1ii11iIi11i + I11i - I1ii11iIi11i
 if 98 - 98: Ii1I - O0 * oO0o * Ii1I * Ii1I
 if 44 - 44: IiII + I11i
 if 66 - 66: oO0o
 if 34 - 34: iII111i % i11iIiiIii + i11iIiiIii - iII111i
 if 2 - 2: II111iiii + i1IIi
 if 68 - 68: OOooOOo + Ii1I
def lisp_itr_rtr_show_rloc_probe_command ( itr_or_rtr ) :
 oOooOOOOoo0O = "LISP-{} RLOC-Probe Information:" . format ( itr_or_rtr )
 I1i1iii = lisp_table_header ( oOooOOOOoo0O , "RLOC Key State" , "RLOC-Probe State" )
 if 58 - 58: IiII * Ii1I . i1IIi
 for i11I1iiii in list ( lisp . lisp_rloc_probe_list . values ( ) ) :
  OOOO0oo0 = ""
  for o00oo , i1iIioOO00OOOoO0o , Ii1iII1ii1 in i11I1iiii :
   ooOo0 = lisp . green ( lisp . lisp_print_eid_tuple ( i1iIioOO00OOOoO0o , Ii1iII1ii1 ) , True )
   OOOO0oo0 += lisp . lisp_print_cour ( ooOo0 ) + "<br>"
   if 41 - 41: I1Ii111 + OoO0O00 * I1IiiI * O0 * Oo0Ooo - OoOoOO00
  OOOO0oo0 = ", EIDs ({}):<br>" . format ( len ( i11I1iiii ) ) + OOOO0oo0
  if 96 - 96: I1IiiI - iIii1I11I1II1
  o00oo , i1iIioOO00OOOoO0o , Ii1iII1ii1 = i11I1iiii [ 0 ]
  if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
  if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
  if 75 - 75: IiII / OoooooooOO . I1IiiI + I1Ii111 - II111iiii
  if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
  iI1IiiiIi = lisp . lisp_hex_string ( o00oo . last_rloc_probe_nonce )
  if ( o00oo . translated_rloc . not_set ( ) ) :
   ii1iI11IiIIi = o00oo . rloc . print_address_no_iid ( )
  else :
   ii1iI11IiIIi = "{}{}{}" . format ( o00oo . translated_rloc . print_address_no_iid ( ) ,
 lisp . bold ( ":" , True ) , o00oo . translated_port )
   if 47 - 47: OOooOOo . oO0o + OoOoOO00 % IiII % i1IIi / iIii1I11I1II1
  ii1iI11IiIIi = lisp . bold ( lisp . lisp_print_cour ( ii1iI11IiIIi ) , True )
  ooIii = o00oo . rloc_name
  if ( ooIii != None ) :
   ooIii = lisp . bold ( ooIii , True )
   ii1iI11IiIIi += ", {}" . format ( lisp . lisp_print_cour ( lisp . blue ( ooIii , True ) ) )
   if 66 - 66: OOooOOo * o0oOOo0O0Ooo
  iI = o00oo . print_state ( )
  if ( o00oo . up_state ( ) == False ) : iI = lisp . red ( o00oo . print_state ( ) , True )
  ii1iI11IiIIi = "RLOC " + ii1iI11IiIIi + ", {}" . format ( iI )
  if 58 - 58: iIii1I11I1II1 % OOooOOo + I1Ii111 - I1Ii111 . i11iIiiIii + OoooooooOO
  i1iIII1IIi = ii1iI11IiIIi + OOOO0oo0
  if 63 - 63: II111iiii . I1Ii111 % IiII + II111iiii
  if 81 - 81: OOooOOo - I1IiiI % o0oOOo0O0Ooo
  if 7 - 7: ooOoO0o - i1IIi . OoOoOO00
  if 12 - 12: IiII / OoO0O00 / O0 * IiII
  o0o0oo0OOo0O0 = [ o00oo ]
  if ( o00oo . multicast_rloc_probe_list != { } ) :
   o0o0oo0OOo0O0 += list ( o00oo . multicast_rloc_probe_list . values ( ) )
   if 37 - 37: o0oOOo0O0Ooo * Oo0Ooo
   if 11 - 11: oO0o
   if 62 - 62: OoooooooOO % oO0o * II111iiii * I1Ii111 * I1Ii111 / ooOoO0o
   if 90 - 90: I1Ii111 . II111iiii . I1ii11iIi11i
   if 32 - 32: ooOoO0o - OoO0O00 . iII111i . iII111i % i1IIi * Ii1I
  o0o0 = ""
  for o00oo in o0o0oo0OOo0O0 :
   if ( len ( o0o0oo0OOo0O0 ) != 1 ) :
    ii1iI11IiIIi = o00oo . rloc . print_address_no_iid ( )
    ii1iI11IiIIi = lisp . bold ( lisp . lisp_print_cour ( ii1iI11IiIIi ) , True )
    if ( o0o0oo0OOo0O0 . index ( o00oo ) != 0 ) : o0o0 += "<br><br>"
    o0o0 += "RLOC {}:<br>" . format ( ii1iI11IiIIi )
    if 28 - 28: I11i . OoooooooOO * OOooOOo + i11iIiiIii % I1IiiI . iIii1I11I1II1
    if 63 - 63: II111iiii - I11i . OoOoOO00
   IIi1I1iII111 = lisp . lisp_print_elapsed ( o00oo . last_rloc_probe )
   IIi1I1iII111 = lisp . lisp_print_cour ( IIi1I1iII111 )
   o0O = lisp . lisp_print_elapsed ( o00oo . last_rloc_probe_reply )
   o0O = lisp . lisp_print_cour ( o0O )
   iI1IiiiIi = lisp . lisp_hex_string ( o00oo . last_rloc_probe_nonce )
   iI1IiiiIi = lisp . lisp_print_cour ( "0x" + iI1IiiiIi )
   o0o0 += ( "Last probe-request sent: {}, " + "last probe-reply received: {}, nonce: {}<br>" ) . format ( IIi1I1iII111 ,
   # IiII + iII111i - OoO0O00 * oO0o
 o0O , iI1IiiiIi )
   if 87 - 87: II111iiii % II111iiii
   IiIIiII1I = o00oo . print_recent_rloc_probe_rtts ( )
   IiIIiII1I = lisp . lisp_print_cour ( IiIIiII1I )
   o0oo0oOOOo00 = o00oo . print_recent_rloc_probe_hops ( )
   o0oo0oOOOo00 = lisp . lisp_print_cour ( o0oo0oOOOo00 )
   OO0OOO = o00oo . print_recent_rloc_probe_latencies ( )
   OO0OOO = lisp . lisp_print_cour ( OO0OOO )
   Oo0O00OO = o00oo . print_rloc_probe_hops ( )
   Oo0O00OO = lisp . lisp_print_cour ( Oo0O00OO )
   I111Ii111 = o00oo . print_rloc_probe_latency ( )
   I111Ii111 = lisp . lisp_print_cour ( I111Ii111 )
   o00oo = o00oo . print_rloc_probe_rtt ( )
   o00oo = lisp . lisp_print_cour ( o00oo )
   o0o0 += ( "Telemetry: rtt: {}, hops: {}, latency: {}<br>" + "recent-rtts: {}, recent-hops: {}, recent-latencies: {}" ) . format ( o00oo , Oo0O00OO , I111Ii111 , IiIIiII1I , o0oo0oOOOo00 , OO0OOO )
   if 75 - 75: IiII % o0oOOo0O0Ooo - I1Ii111
   if 82 - 82: OOooOOo % I1ii11iIi11i . I1Ii111 . O0
   if 93 - 93: iII111i % iII111i / ooOoO0o + OoO0O00 / i11iIiiIii
   if 46 - 46: Ii1I / Ii1I / I1IiiI - I1IiiI + iII111i % IiII
   if 34 - 34: iII111i % iII111i / I11i . oO0o
   if 32 - 32: Oo0Ooo / I11i / Oo0Ooo
   if 81 - 81: ooOoO0o % iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % Oo0Ooo
  I1i1iii += lisp_table_row ( i1iIII1IIi , o0o0 )
  if 70 - 70: I1ii11iIi11i . IiII
  if 41 - 41: o0oOOo0O0Ooo % Oo0Ooo
 I1i1iii += lisp_table_footer ( )
 return ( I1i1iii )
 if 93 - 93: ooOoO0o
 if 82 - 82: I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - OoOoOO00 / iII111i
 if 99 - 99: oO0o / i1IIi
 if 2 - 2: oO0o . iII111i
 if 42 - 42: OoO0O00 - I1ii11iIi11i * IiII - ooOoO0o
 if 75 - 75: iII111i * Oo0Ooo / I1Ii111 * Oo0Ooo / ooOoO0o
 if 14 - 14: i1IIi * iIii1I11I1II1 - Ii1I * OoOoOO00 - iII111i / oO0o
def lisp_xtr_command ( kv_pair ) :
 if 73 - 73: I1ii11iIi11i - OoOoOO00 * O0 - OoOoOO00 - OoO0O00
 if 96 - 96: I1ii11iIi11i - O0
 if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
 if 99 - 99: o0oOOo0O0Ooo + OOooOOo
 if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) :
  kv_pair [ "ipc-data-plane" ] = [ "yes" ]
  if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
  if 76 - 76: oO0o / OoOoOO00
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ] [ 0 ]
  if ( IiII1II11I == "rloc-probing" ) :
   lisp . lisp_rloc_probing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_rloc_probe_list = { }
   if 12 - 12: I1Ii111
  if ( IiII1II11I == "nonce-echoing" ) :
   lisp . lisp_nonce_echoing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_nonce_echo_list = { }
   if 58 - 58: OoO0O00 + iIii1I11I1II1 % O0 + I11i + OoOoOO00 * OoooooooOO
  if ( IiII1II11I == "data-plane-security" ) :
   lisp . lisp_data_plane_security = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) :
    lisp . lisp_crypto_keys_by_nonce = { }
    lisp . lisp_crypto_keys_by_rloc_encap = { }
    lisp . lisp_crypto_keys_by_rloc_decap = { }
    if 41 - 41: oO0o * I1IiiI
    if 76 - 76: oO0o . O0 * OoooooooOO + ooOoO0o
  if ( IiII1II11I == "data-plane-logging" ) :
   lisp . lisp_data_plane_logging = ( oo00oO0O0 == "yes" )
   if 53 - 53: Oo0Ooo
  if ( IiII1II11I == "frame-logging" ) :
   lisp . lisp_frame_logging = ( oo00oO0O0 == "yes" )
   if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
  if ( IiII1II11I == "flow-logging" ) :
   lisp . lisp_flow_logging = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "yes" ) : os . system ( "touch ./log-flows" )
   if 58 - 58: IiII % iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * iII111i
  if ( IiII1II11I == "nat-traversal" ) :
   lisp . lisp_nat_traversal = ( oo00oO0O0 == "yes" )
   if 32 - 32: OoooooooOO + o0oOOo0O0Ooo
  if ( IiII1II11I == "program-hardware" ) :
   lisp . lisp_program_hardware = ( oo00oO0O0 == "yes" )
   if 91 - 91: ooOoO0o - I1Ii111 * I1Ii111
  if ( IiII1II11I == "checkpoint-map-cache" ) :
   lisp . lisp_checkpoint_map_cache = ( oo00oO0O0 == "yes" )
   ooOOOo0 = lisp . lisp_checkpoint_filename
   if ( oo00oO0O0 == "no" and os . path . exists ( ooOOOo0 ) ) :
    os . system ( "rm {}" . format ( ooOOOo0 ) )
    if 19 - 19: I1Ii111 + iII111i * I1Ii111
    if 71 - 71: o0oOOo0O0Ooo . I1IiiI - I1ii11iIi11i - Oo0Ooo - i1IIi - I1IiiI
  if ( IiII1II11I == "ipc-data-plane" ) :
   iIIiiiIIi1111 = ( oo00oO0O0 == "yes" )
   if ( iIIiiiIIi1111 and lisp . lisp_ipc_data_plane == False ) :
    oo0ooO0O0o = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
    lisp . lisp_ipc_dp_socket = oo0ooO0O0o
    if 53 - 53: I1Ii111
   if ( iIIiiiIIi1111 == False and lisp . lisp_ipc_data_plane ) :
    lisp . lisp_ipc_dp_socket . close ( )
    lisp . lisp_ipc_dp_socket = None
    if 31 - 31: o0oOOo0O0Ooo * I11i - i11iIiiIii - I1IiiI
   lisp . lisp_ipc_data_plane = iIIiiiIIi1111
   if 19 - 19: iII111i . I11i * OoooooooOO - OOooOOo + O0 * I1Ii111
  if ( IiII1II11I == "decentralized-push-xtr" ) :
   lisp . lisp_decent_push_configured = ( oo00oO0O0 == "yes" )
   if 90 - 90: i1IIi . oO0o / I1Ii111 . OOooOOo / I1Ii111
  if ( IiII1II11I == "decentralized-pull-xtr-modulus" ) :
   lisp . lisp_decent_modulus = int ( oo00oO0O0 )
   if 1 - 1: iII111i % ooOoO0o
  if ( IiII1II11I == "decentralized-pull-xtr-dns-suffix" ) :
   lisp . lisp_decent_dns_suffix = oo00oO0O0
   if 99 - 99: iII111i + iIii1I11I1II1 . OOooOOo / OoO0O00 * I1ii11iIi11i
  if ( IiII1II11I == "register-reachable-rtrs" ) :
   lisp . lisp_register_all_rtrs = ( oo00oO0O0 == "no" )
   if 87 - 87: IiII / II111iiii % OoO0O00 % OoO0O00
   if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
 return
 if 91 - 91: I1IiiI / II111iiii * OOooOOo
 if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
 if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
 if 81 - 81: OoO0O00 - iIii1I11I1II1
 if 60 - 60: I1Ii111
 if 77 - 77: I1IiiI / I1ii11iIi11i
 if 95 - 95: I1Ii111 * i1IIi + oO0o
def lisp_show_json_list ( output ) :
 if 40 - 40: II111iiii
 oOooOOOOoo0O = "Configured JSON Entries:"
 output += lisp_table_header ( oOooOOOOoo0O , "JSON Name" , "JSON String" )
 if 7 - 7: OOooOOo / OoO0O00
 oOOo = sorted ( lisp . lisp_json_list )
 for oOOOo0Oooo in oOOo :
  oOO00O0Ooooo00 = lisp . lisp_json_list [ oOOOo0Oooo ]
  I1iiIIiI11I = lisp . lisp_print_cour ( oOO00O0Ooooo00 . print_json ( True ) )
  output += lisp_table_row ( oOOOo0Oooo , I1iiIIiI11I )
  if 29 - 29: I11i + oO0o % ooOoO0o + OoOoOO00
 output += lisp_table_footer ( )
 return ( output )
 if 92 - 92: o0oOOo0O0Ooo
 if 37 - 37: oO0o
 if 18 - 18: IiII * i11iIiiIii + iIii1I11I1II1 % I11i + i1IIi - OoO0O00
 if 85 - 85: OoO0O00 * I11i + OoO0O00
 if 39 - 39: Oo0Ooo / i1IIi % i1IIi
 if 20 - 20: OOooOOo * oO0o
 if 91 - 91: OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
def lisp_show_rle_list ( output ) :
 if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
 oOooOOOOoo0O = "Configured Replication List Entries (RLEs):"
 output += lisp_table_header ( oOooOOOOoo0O , "RLE Name" , "RLE Nodes" )
 if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
 ii1i1I1111ii = sorted ( lisp . lisp_rle_list )
 for oo0ooo0O0O0O in ii1i1I1111ii :
  iii11 = lisp . lisp_rle_list [ oo0ooo0O0O0O ]
  output += lisp_table_row ( oo0ooo0O0O0O , iii11 . print_rle ( True , True ) )
  if 71 - 71: I1ii11iIi11i . I1Ii111
 output += lisp_table_footer ( )
 return ( output )
 if 16 - 16: oO0o - I1ii11iIi11i . OoOoOO00
 if 99 - 99: ooOoO0o * iIii1I11I1II1 - Ii1I + Oo0Ooo . Oo0Ooo
 if 18 - 18: OOooOOo
 if 82 - 82: OoooooooOO - ooOoO0o * I1ii11iIi11i * ooOoO0o * O0 * iIii1I11I1II1
 if 31 - 31: ooOoO0o . OOooOOo % ooOoO0o
 if 33 - 33: O0 * Ii1I - IiII . OoooooooOO + IiII
 if 20 - 20: I1Ii111 - OoOoOO00
def lisp_show_elp_list ( output ) :
 oOooOOOOoo0O = "Configured Explicit Locator Paths (ELPs):"
 output += lisp_table_header ( oOooOOOOoo0O , "ELP Name" , "ELP Nodes" )
 if 91 - 91: i1IIi
 ii11IiI = sorted ( lisp . lisp_elp_list )
 for I1iI1Ii11 in ii11IiI :
  I11i1i11IiIi1 = lisp . lisp_elp_list [ I1iI1Ii11 ]
  output += lisp_table_row ( I1iI1Ii11 , I11i1i11IiIi1 . print_elp ( False ) )
  if 34 - 34: Ii1I * I1IiiI + I11i * OoOoOO00 - II111iiii
 output += lisp_table_footer ( )
 return ( output )
 if 92 - 92: OOooOOo . o0oOOo0O0Ooo / iII111i . iIii1I11I1II1 % Oo0Ooo . OoooooooOO
 if 81 - 81: i11iIiiIii * iII111i . oO0o * oO0o . IiII
 if 47 - 47: iIii1I11I1II1 % I11i . I11i / O0 . i11iIiiIii * Ii1I
 if 24 - 24: O0
 if 33 - 33: OoooooooOO + oO0o * II111iiii / OOooOOo
 if 87 - 87: OoooooooOO
 if 1 - 1: iIii1I11I1II1 / o0oOOo0O0Ooo
def lisp_geo_command ( kv_pair ) :
 if 98 - 98: O0 % I1IiiI / OoooooooOO * I1ii11iIi11i - oO0o
 if 51 - 51: iII111i + I11i
 if 54 - 54: II111iiii * O0 % I1IiiI . I11i
 if 62 - 62: Ii1I . i11iIiiIii % O0 % I1Ii111 - Oo0Ooo
 if ( "geo-name" not in kv_pair ) : return
 Oo = kv_pair [ "geo-name" ]
 oOO0o0oOoO = lisp . lisp_geo ( Oo )
 if 47 - 47: iII111i * OoOoOO00 * IiII
 if 46 - 46: Ii1I
 if 42 - 42: iIii1I11I1II1
 if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
 if ( "geo-tag" not in kv_pair ) : return
 if 34 - 34: Oo0Ooo
 if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
 if 33 - 33: i1IIi / iII111i * OoO0O00
 if 2 - 2: oO0o . OOooOOo
 ii1 = kv_pair [ "geo-tag" ] [ 1 : : ]
 if ( oOO0o0oOoO . parse_geo_string ( ii1 ) == False ) : return
 if 81 - 81: ooOoO0o + OoO0O00 . i1IIi + i1IIi / I1IiiI * I1Ii111
 if 98 - 98: I1ii11iIi11i - OoooooooOO / I1IiiI . ooOoO0o - i1IIi
 if 60 - 60: OoOoOO00 % OoOoOO00
 if 2 - 2: Ii1I . O0 - oO0o + IiII
 lisp . lisp_geo_list [ Oo ] = oOO0o0oOoO
 return
 if 96 - 96: Ii1I + Ii1I
 if 28 - 28: iII111i
 if 6 - 6: I1IiiI - iII111i
 if 49 - 49: II111iiii
 if 33 - 33: o0oOOo0O0Ooo - oO0o % I1ii11iIi11i * I11i . OoooooooOO % Ii1I
 if 29 - 29: iII111i + II111iiii . i11iIiiIii . Ii1I - O0
 if 47 - 47: oO0o . I1ii11iIi11i - iIii1I11I1II1 % II111iiii / OoOoOO00 % OoooooooOO
def lisp_elp_command ( kv_pair ) :
 if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
 I11i1i11IiIi1 = None
 oOO0o = [ ]
 if ( "address" in kv_pair ) :
  for i1iIIiiIiII in range ( len ( kv_pair [ "address" ] ) ) :
   ooIi11II1IIIIIi = lisp . lisp_elp_node ( )
   oOO0o . append ( ooIi11II1IIIIIi )
   if 83 - 83: iIii1I11I1II1 + II111iiii * oO0o / O0 - iII111i
   if 23 - 23: i1IIi
   if 24 - 24: IiII
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if 51 - 51: OOooOOo % i11iIiiIii
  if ( IiII1II11I == "elp-name" ) :
   I11i1i11IiIi1 = lisp . lisp_elp ( oo00oO0O0 )
   continue
   if 77 - 77: OOooOOo % i11iIiiIii - I1ii11iIi11i
   if 21 - 21: I11i . Oo0Ooo - OoooooooOO * i1IIi
  for OoOOooOOoo in oOO0o :
   O0OO0O = oOO0o . index ( OoOOooOOoo )
   if ( O0OO0O >= len ( oo00oO0O0 ) ) : O0OO0O = len ( oo00oO0O0 ) - 1
   oOOo0oO = oo00oO0O0 [ O0OO0O ]
   if ( IiII1II11I == "probe" ) : OoOOooOOoo . probe = ( oOOo0oO == "yes" )
   if ( IiII1II11I == "strict" ) : OoOOooOOoo . strict = ( oOOo0oO == "yes" )
   if ( IiII1II11I == "eid" ) : OoOOooOOoo . eid = ( oOOo0oO == "yes" )
   if ( IiII1II11I == "address" ) : OoOOooOOoo . address . store_address ( oOOo0oO )
   if 12 - 12: oO0o . OOooOOo
   if 52 - 52: i11iIiiIii / I11i % IiII
   if 21 - 21: iII111i % IiII % Oo0Ooo % O0
   if 63 - 63: II111iiii * I1IiiI - OoooooooOO / I1IiiI
   if 50 - 50: OoOoOO00 % Ii1I + OoOoOO00 * Ii1I - OOooOOo
   if 94 - 94: iIii1I11I1II1
 if ( I11i1i11IiIi1 == None ) : return
 if 1 - 1: O0
 if 2 - 2: OoO0O00 . I11i
 if 97 - 97: Oo0Ooo
 if 65 - 65: Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1 . I1Ii111 + ooOoO0o
 I11i1i11IiIi1 . elp_nodes = oOO0o
 lisp . lisp_elp_list [ I11i1i11IiIi1 . elp_name ] = I11i1i11IiIi1
 return
 if 92 - 92: oO0o
 if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
 if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
 if 47 - 47: IiII . OOooOOo
 if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
 if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
 if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
def lisp_rle_command ( kv_pair ) :
 if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
 iii11 = None
 o0oOO00O000O0 = [ ]
 if ( "address" in kv_pair ) :
  for i1iIIiiIiII in range ( len ( kv_pair [ "address" ] ) ) :
   OOOoO000 = lisp . lisp_rle_node ( )
   o0oOO00O000O0 . append ( OOOoO000 )
   if 79 - 79: iII111i / I1Ii111 + o0oOOo0O0Ooo
   if 82 - 82: OoO0O00 + Ii1I
   if 11 - 11: iII111i + OoooooooOO * Ii1I . o0oOOo0O0Ooo
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if 11 - 11: O0
  if ( IiII1II11I == "rle-name" ) :
   iii11 = lisp . lisp_rle ( oo00oO0O0 )
   continue
   if 96 - 96: iII111i + o0oOOo0O0Ooo
   if 10 - 10: i11iIiiIii . OoooooooOO . O0 % ooOoO0o / OoO0O00
  for OoOOooOOoo in o0oOO00O000O0 :
   O0OO0O = o0oOO00O000O0 . index ( OoOOooOOoo )
   if ( O0OO0O >= len ( oo00oO0O0 ) ) : O0OO0O = len ( oo00oO0O0 ) - 1
   oOOo0oO = oo00oO0O0 [ O0OO0O ]
   if ( IiII1II11I == "level" ) :
    if ( oOOo0oO == "" ) : oOOo0oO = "0"
    OoOOooOOoo . level = int ( oOOo0oO )
    if 36 - 36: I1IiiI % i1IIi + OoO0O00
   if ( IiII1II11I == "address" ) : OoOOooOOoo . address . store_address ( oOOo0oO )
   if 59 - 59: i11iIiiIii - i11iIiiIii + I1IiiI
   if 4 - 4: Oo0Ooo * O0 - oO0o % ooOoO0o + OoOoOO00
   if 3 - 3: OoOoOO00
   if 91 - 91: O0 - I11i % I1Ii111
   if 46 - 46: ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
   if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
 if ( iii11 == None ) : return
 if 70 - 70: II111iiii * II111iiii . I1IiiI
 if 11 - 11: iII111i
 if 20 - 20: Ii1I . I1Ii111 % Ii1I
 if 5 - 5: OOooOOo + iII111i
 iii11 . rle_nodes = o0oOO00O000O0
 iii11 . build_forwarding_list ( )
 lisp . lisp_rle_list [ iii11 . rle_name ] = iii11
 return
 if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
 if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
 if 11 - 11: I1ii11iIi11i / O0 + II111iiii
 if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
 if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
 if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
 if 2 - 2: Ii1I
def lisp_json_command ( kv_pair ) :
 if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
 try :
  oOOOo0Oooo = kv_pair [ "json-name" ]
  I1iiIIiI11I = kv_pair [ "json-string" ]
 except :
  return
  if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
  if 81 - 81: iIii1I11I1II1
 oOO00O0Ooooo00 = lisp . lisp_json ( oOOOo0Oooo , I1iiIIiI11I )
 oOO00O0Ooooo00 . add ( )
 return
 if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
 if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
 if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
 if 7 - 7: IiII
 if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
 if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
 if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
 if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
 if 91 - 91: I1IiiI + o0oOOo0O0Ooo % II111iiii + OoO0O00
 if 66 - 66: iIii1I11I1II1 * II111iiii % Oo0Ooo % I1IiiI - Ii1I
 if 59 - 59: IiII % oO0o
 if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
def lisp_get_lookup_string ( input_str ) :
 if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
 if 93 - 93: I1ii11iIi11i * I1ii11iIi11i / OoooooooOO
 if 6 - 6: I1ii11iIi11i * Oo0Ooo + iIii1I11I1II1
 if 19 - 19: O0 % II111iiii * o0oOOo0O0Ooo
 OOOO0oo0 = input_str
 I11iiI1i1 = None
 if ( input_str . find ( "->" ) != - 1 ) :
  I1i1Iiiii = input_str . split ( "->" )
  OOOO0oo0 = I1i1Iiiii [ 0 ]
  I11iiI1i1 = I1i1Iiiii [ 1 ]
  if 27 - 27: OOooOOo * IiII / i11iIiiIii - oO0o + II111iiii
  if 43 - 43: I1ii11iIi11i - II111iiii
 OOoIiI1i11iIi1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 iii = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 if 11 - 11: I1ii11iIi11i / I1ii11iIi11i
 if 39 - 39: O0 . I11i
 if 45 - 45: oO0o + o0oOOo0O0Ooo + IiII / Ii1I + o0oOOo0O0Ooo
 if 33 - 33: iII111i - Oo0Ooo - I11i
 O0ooOo = OOOO0oo0 . split ( "/" )
 if ( len ( O0ooOo ) == 1 ) :
  OOoIiI1i11iIi1 . store_address ( O0ooOo [ 0 ] )
  iIi1i1I1I = False
 else :
  OOoIiI1i11iIi1 . store_prefix ( OOOO0oo0 )
  iIi1i1I1I = True
  if 35 - 35: I11i + O0 * II111iiii
  if 23 - 23: OoOoOO00 * IiII / oO0o
 O0O0o0o0oo0O = iIi1i1I1I
 if ( I11iiI1i1 ) :
  O0ooOo = I11iiI1i1 . split ( "/" )
  if ( len ( O0ooOo ) == 1 ) :
   iii . store_address ( O0ooOo [ 0 ] )
   O0O0o0o0oo0O = False
  else :
   iii . store_prefix ( OOOO0oo0 )
   O0O0o0o0oo0O = True
   if 30 - 30: I1Ii111 / I1IiiI / i1IIi - O0 . Ii1I - ooOoO0o
   if 95 - 95: I1Ii111 - IiII
 return ( [ OOoIiI1i11iIi1 , iIi1i1I1I , iii , O0O0o0o0oo0O ] )
 if 24 - 24: I11i / iIii1I11I1II1 . OoooooooOO % OoOoOO00 . Ii1I
 if 73 - 73: I1Ii111
 if 25 - 25: IiII
 if 77 - 77: o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO . iIii1I11I1II1
 if 87 - 87: II111iiii - OoooooooOO / i1IIi . Ii1I - Oo0Ooo . i11iIiiIii
 if 47 - 47: Oo0Ooo % OoO0O00 - ooOoO0o - Oo0Ooo * oO0o
 if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
def lisp_show_map_cache_lookup ( eid_str ) :
 OOoIiI1i11iIi1 , iIi1i1I1I , iii , O0O0o0o0oo0O = lisp_get_lookup_string ( eid_str )
 if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
 I1i1iii = "<br>"
 if 64 - 64: IiII
 OooooOOOO = OOoIiI1i11iIi1 if ( iii . is_null ( ) ) else iii
 oo000o = iIi1i1I1I if ( iii . is_null ( ) ) else O0O0o0o0oo0O
 if 6 - 6: OOooOOo + I1ii11iIi11i + Oo0Ooo
 Oo0000o0O0O = lisp . lisp_map_cache . lookup_cache ( OooooOOOO , oo000o )
 if ( Oo0000o0O0O == None ) :
  I1i1iii += "{} {}" . format ( lisp . lisp_print_sans ( "Lookup not found for" ) ,
 lisp . lisp_print_cour ( eid_str ) )
 else :
  if ( OooooOOOO == iii ) :
   o0OOo0o0o0ooo = Oo0000o0O0O . lookup_source_cache ( OOoIiI1i11iIi1 , iIi1i1I1I )
   if ( o0OOo0o0o0ooo ) : Oo0000o0O0O = o0OOo0o0o0ooo
   if 53 - 53: OoO0O00
   if 80 - 80: II111iiii - o0oOOo0O0Ooo . iIii1I11I1II1
  oO0OOoO0 = lisp . lisp_print_elapsed ( Oo0000o0O0O . uptime )
  I1i1iii += "{} {} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Exact" if iIi1i1I1I else "Longest" ) ,
  # Ii1I + Ii1I . I11i
 lisp . lisp_print_sans ( "match lookup for" ) ,
 lisp . lisp_print_cour ( eid_str ) ,
 lisp . lisp_print_sans ( "found" ) ,
 lisp . lisp_print_cour ( Oo0000o0O0O . print_eid_tuple ( ) ) ,
 lisp . lisp_print_sans ( "with uptime" ) ,
 lisp . lisp_print_cour ( oO0OOoO0 ) )
  if 57 - 57: ooOoO0o
 I1i1iii += "<br>"
 return ( I1i1iii )
 if 94 - 94: OoO0O00 - II111iiii % iIii1I11I1II1
 if 92 - 92: Oo0Ooo
 if 40 - 40: I1IiiI
 if 96 - 96: OoO0O00 - iII111i
 if 16 - 16: I1Ii111 / O0 . II111iiii * OoOoOO00
 if 7 - 7: I1Ii111 * O0 + OoOoOO00
 if 90 - 90: IiII * II111iiii * IiII - iII111i
 if 34 - 34: OOooOOo - I1ii11iIi11i * iII111i % Ii1I
def lisp_get_clause_for_api ( command ) :
 iiIiiIi = open ( "./lisp.config" , "r" )
 iIIi1 = { command : [ ] }
 Ii1i11i = { }
 O0O0o = [ ]
 if 96 - 96: O0 . Oo0Ooo - I11i
 IIIIiiI = 0
 ooOo0o = False
 for OOo00OoO in iiIiiIi :
  if ( lisp_end_file ( OOo00OoO ) ) : break
  if ( lisp_comment ( OOo00OoO ) ) : continue
  if 42 - 42: OoooooooOO . OoOoOO00
  if 93 - 93: I1IiiI
  if 89 - 89: OoooooooOO % i11iIiiIii + I1Ii111
  if 12 - 12: OoOoOO00 * ooOoO0o
  if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
  if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
  if ( OOo00OoO . find ( command + " {" ) != - 1 ) :
   IIIIiiI += 1
   ooOo0o = True
   continue
   if 50 - 50: ooOoO0o
  if ( ooOo0o == False ) : continue
  if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
  if ( lisp_begin_clause ( OOo00OoO ) ) :
   IIIIiiI += 1
   oo0ooO0O = OOo00OoO . replace ( " " , "" )
   oo0ooO0O = oo0ooO0O . replace ( "\t" , "" )
   oo0ooO0O = oo0ooO0O . replace ( "\n" , "" )
   oo0ooO0O = oo0ooO0O . replace ( "{" , "" )
   Ii1i11i = { oo0ooO0O : { } }
   continue
   if 83 - 83: Oo0Ooo / ooOoO0o
   if 11 - 11: o0oOOo0O0Ooo - II111iiii % oO0o . II111iiii
   if 65 - 65: oO0o . i11iIiiIii % OOooOOo * iII111i % Oo0Ooo
   if 51 - 51: OoO0O00 % iII111i
   if 24 - 24: I1IiiI / iIii1I11I1II1 / O0 . iIii1I11I1II1 - OoO0O00 . iIii1I11I1II1
   if 8 - 8: I1ii11iIi11i % OoO0O00 % oO0o . I1ii11iIi11i * I1ii11iIi11i
  if ( lisp_end_clause ( OOo00OoO ) ) :
   IIIIiiI -= 1
   if ( IIIIiiI ) :
    iIIi1 [ command ] . append ( Ii1i11i )
    Ii1i11i = { }
    continue
    if 94 - 94: i11iIiiIii + OoooooooOO
   O0O0o . append ( iIIi1 )
   iIIi1 = { command : [ ] }
   ooOo0o = False
   continue
   if 20 - 20: i11iIiiIii
   if 86 - 86: OoOoOO00 / OOooOOo
  OOo00OoO = OOo00OoO . replace ( " " , "" )
  OOo00OoO = OOo00OoO . replace ( "\t" , "" )
  OOo00OoO = OOo00OoO . replace ( "\n" , "" )
  OOo00OoO = OOo00OoO . replace ( "{" , "" )
  OOo00OoO = OOo00OoO . split ( "=" )
  oo00oO0O0 = "" if len ( OOo00OoO ) == 1 else OOo00OoO [ 1 ]
  OoOOOO = OOo00OoO [ 0 ]
  if 40 - 40: iIii1I11I1II1 / ooOoO0o / I1IiiI + I1ii11iIi11i * OOooOOo
  if ( len ( Ii1i11i ) == 0 ) :
   iIIi1 [ command ] . append ( { OoOOOO : oo00oO0O0 } )
  else :
   Ii1i11i [ oo0ooO0O ] [ OoOOOO ] = oo00oO0O0
   if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
   if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
   if 51 - 51: OOooOOo / I11i
 iiIiiIi . close ( )
 if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
 if ( len ( O0O0o ) == 0 ) :
  O0O0o = [ { "?" : [ { "?" : "not-found" } ] } ]
  if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
 return ( O0O0o )
 if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
 if 26 - 26: i11iIiiIii - ooOoO0o
 if 45 - 45: ooOoO0o + II111iiii % iII111i
 if 55 - 55: ooOoO0o - oO0o % I1IiiI
 if 61 - 61: ooOoO0o
 if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
 if 21 - 21: oO0o . i11iIiiIii * I11i . OOooOOo / OOooOOo
def lisp_duplicate_command_clause ( command , clause ) :
 III1I11i1iIi = open ( "./lisp.config" , "r" )
 if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
 clause = command + " {\n" + clause
 for OOo00OoO in III1I11i1iIi :
  if ( lisp_begin_clause ( OOo00OoO ) == False ) : continue
  if ( OOo00OoO . find ( command ) == - 1 ) : continue
  if 1 - 1: Ii1I % I1Ii111
  oo00Oo0 = OOo00OoO
  for OOo00OoO in III1I11i1iIi :
   oo00Oo0 += OOo00OoO
   if ( OOo00OoO [ 0 ] != "}" ) : continue
   if ( oo00Oo0 != clause ) : break
   III1I11i1iIi . close ( )
   return ( True )
   if 28 - 28: Ii1I
  if ( lisp_end_file ( OOo00OoO ) ) : break
  if 36 - 36: I1Ii111 / I1Ii111 % oO0o
  if 97 - 97: OoooooooOO * o0oOOo0O0Ooo + OoooooooOO % Ii1I * Oo0Ooo
 III1I11i1iIi . close ( )
 return ( False )
 if 35 - 35: iIii1I11I1II1 % iII111i - i1IIi
 if 20 - 20: I11i % ooOoO0o . OOooOOo / I1Ii111
 if 50 - 50: oO0o + i11iIiiIii / i11iIiiIii + ooOoO0o + I1Ii111
 if 65 - 65: ooOoO0o * O0 * iII111i
 if 60 - 60: iIii1I11I1II1 . ooOoO0o + I1IiiI % oO0o
 if 4 - 4: I1IiiI / II111iiii % O0 * ooOoO0o / II111iiii . Oo0Ooo
 if 16 - 16: O0 + O0 - I1IiiI
def lisp_put_clause_for_api ( data ) :
 if 30 - 30: ooOoO0o
 if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
 if 19 - 19: i1IIi % II111iiii
 if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
 OOO0ooo = list ( data . keys ( ) ) [ 0 ]
 if ( OOO0ooo not in list ( lisp_commands . keys ( ) ) ) :
  return ( [ { OOO0ooo : [ { "?" : "add/replace" } ] } ] )
  if 56 - 56: Ii1I * i11iIiiIii
  if 92 - 92: II111iiii - O0 . I1Ii111
 oOOOoOO = ( OOO0ooo in [ "lisp enable" , "lisp debug" , "lisp xtr-parameters" ] )
 if 80 - 80: OoooooooOO
 if 65 - 65: oO0o * i1IIi . OoooooooOO % ooOoO0o
 if 87 - 87: i11iIiiIii * II111iiii - Ii1I % OoooooooOO
 if 55 - 55: i1IIi
 if 67 - 67: I1IiiI - OoO0O00
 if 60 - 60: i1IIi / iIii1I11I1II1 * oO0o + ooOoO0o + OoooooooOO + II111iiii
 if 13 - 13: iIii1I11I1II1 - OOooOOo
 i111ii1II11ii = False
 if ( oOOOoOO == False ) :
  i111ii1II11ii = True
  i11iII1IiI = getoutput ( "egrep '{}' ./lisp.config" . format ( OOO0ooo ) )
  i11iII1IiI = i11iII1IiI . split ( "\n" )
  for OOo00OoO in i11iII1IiI :
   if ( OOo00OoO [ 0 : len ( OOO0ooo ) ] == OOO0ooo ) : i111ii1II11ii = False
   if 21 - 21: IiII * OoOoOO00 - I1Ii111
   if 44 - 44: OoooooooOO + Ii1I
   if 84 - 84: i1IIi - II111iiii . OoooooooOO / OoOoOO00 % Ii1I
   if 7 - 7: i1IIi / IiII / iII111i
   if 97 - 97: OoO0O00 + iIii1I11I1II1
   if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
 iIiIi1i1ii11 = data [ OOO0ooo ]
 iIiIi1i1ii11 = lisp_unicode_to_ascii ( iIiIi1i1ii11 )
 iIIi1 = OOO0ooo + " {\n" if i111ii1II11ii else ""
 if 86 - 86: I1Ii111 * ooOoO0o - ooOoO0o . I1IiiI
 if 69 - 69: i11iIiiIii - iIii1I11I1II1 / Ii1I / II111iiii
 if 81 - 81: OOooOOo - I1ii11iIi11i * Oo0Ooo + oO0o
 if 90 - 90: Oo0Ooo * Ii1I
 if 54 - 54: I1ii11iIi11i + iIii1I11I1II1 % IiII
 if 24 - 24: OoO0O00 / O0 * ooOoO0o % iIii1I11I1II1 + i1IIi % O0
 if 26 - 26: ooOoO0o + IiII - O0 * oO0o * II111iiii . I1ii11iIi11i
 if 75 - 75: OoOoOO00 / OoooooooOO / I11i % OoOoOO00 * Ii1I * IiII
 for IIi1 in iIiIi1i1ii11 :
  if ( type ( iIiIi1i1ii11 ) == dict ) :
   oo00oO0O0 = iIiIi1i1ii11 [ IIi1 ]
   if ( type ( oo00oO0O0 ) == dict ) : oo00oO0O0 = json_dumps ( oo00oO0O0 )
   iIIi1 += "    " + IIi1 + " = " + oo00oO0O0 + "\n"
   continue
   if 94 - 94: OoooooooOO - ooOoO0o % OOooOOo - iII111i / i1IIi
   if 5 - 5: OoooooooOO % II111iiii
  for OoOOOO in IIi1 :
   if ( type ( IIi1 ) == dict ) :
    ii11I111I = OoOOOO
    oo00oO0O0 = IIi1 [ OoOOOO ]
    if 69 - 69: Oo0Ooo . i11iIiiIii / iII111i / O0 + O0 . OoO0O00
   if ( type ( IIi1 ) == list ) :
    ii11I111I = list ( OoOOOO . keys ( ) ) [ 0 ]
    oo00oO0O0 = list ( OoOOOO . values ( ) ) [ 0 ]
    if 44 - 44: I11i . IiII % I1Ii111 - ooOoO0o - I1ii11iIi11i
    if 34 - 34: I1ii11iIi11i % i1IIi - OoO0O00
   if ( type ( oo00oO0O0 ) != dict ) :
    iIIi1 += "    " + OoOOOO + " = " + IIi1 [ OoOOOO ] + "\n"
    continue
    if 18 - 18: I1IiiI + I1Ii111 - iII111i % II111iiii / OoOoOO00 % O0
    if 59 - 59: O0 . o0oOOo0O0Ooo % I1ii11iIi11i * oO0o + I11i
    if 82 - 82: OoooooooOO
    if 88 - 88: O0 / o0oOOo0O0Ooo * o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0
    if 27 - 27: i11iIiiIii % iII111i + Ii1I . OOooOOo
   iIIi1 += "    " + ii11I111I + " {\n"
   for iIIi1I1 in oo00oO0O0 : iIIi1 += "        " + iIIi1I1 + " = " + oo00oO0O0 [ iIIi1I1 ] + "\n"
   iIIi1 += "    }\n"
   if 100 - 100: i11iIiiIii . OOooOOo . i11iIiiIii
   if 81 - 81: I1IiiI
 iIIi1 += "}\n"
 if 76 - 76: O0 - ooOoO0o / Ii1I . Oo0Ooo - Ii1I
 if 75 - 75: ooOoO0o % OOooOOo / o0oOOo0O0Ooo % II111iiii
 if 30 - 30: o0oOOo0O0Ooo
 if 15 - 15: II111iiii - Ii1I - iII111i . oO0o / i11iIiiIii
 if ( lisp_duplicate_command_clause ( OOO0ooo , iIIi1 ) ) :
  return ( [ { OOO0ooo : [ { "!" : "duplicate" } ] } ] )
  if 38 - 38: OoO0O00
  if 3 - 3: II111iiii . I1IiiI / Oo0Ooo + o0oOOo0O0Ooo
 ooooooOO = "./lisp.config"
 Oo0OooII1iII11 = ooooooOO + ".temp"
 if 19 - 19: II111iiii
 i1iIIi = open ( ooooooOO , "r" )
 oo0O0OO0Oooo = open ( Oo0OooII1iII11 , "w" )
 if 7 - 7: II111iiii - I1ii11iIi11i / I11i % OoooooooOO + i1IIi
 I1Iii1 = False
 Ii1II111iIi = False
 for OOo00OoO in i1iIIi :
  if ( Ii1II111iIi ) :
   if ( lisp_end_clause ( OOo00OoO ) == False ) : continue
   Ii1II111iIi = False
   continue
   if 68 - 68: II111iiii % I1Ii111 * i11iIiiIii
   if 9 - 9: II111iiii + I1ii11iIi11i / iII111i
   if 51 - 51: I11i % I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
   if 7 - 7: OOooOOo . IiII . I1Ii111 / Ii1I / Oo0Ooo
   if 83 - 83: I11i / Oo0Ooo
  if ( I1Iii1 == False and lisp_begin_clause ( OOo00OoO ) and
 OOo00OoO [ 0 : len ( OOO0ooo ) ] == OOO0ooo ) :
   if ( oOOOoOO == False ) :
    oo0O0OO0Oooo . write ( OOo00OoO )
    for iiI in iIIi1 : oo0O0OO0Oooo . write ( iiI )
    I1Iii1 = True
    if 53 - 53: o0oOOo0O0Ooo % OoooooooOO - oO0o - i1IIi / OoO0O00
    if 33 - 33: IiII * I11i
    if 96 - 96: o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + OoO0O00 - IiII - IiII
    if 2 - 2: ooOoO0o % i11iIiiIii
    if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
    if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
  if ( lisp_end_file ( OOo00OoO ) ) :
   if ( i111ii1II11ii ) :
    for iiI in iIIi1 : oo0O0OO0Oooo . write ( iiI )
    if 8 - 8: o0oOOo0O0Ooo
   oo0O0OO0Oooo . write ( OOo00OoO )
   I1Iii1 = True
   break
   if 78 - 78: i1IIi - Oo0Ooo
   if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
   if 42 - 42: I1Ii111
   if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
   if 80 - 80: OOooOOo
  oo0O0OO0Oooo . write ( OOo00OoO )
  if 12 - 12: Ii1I
  if 2 - 2: OoooooooOO
  if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
  if 46 - 46: O0 % OoooooooOO
  if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
  if ( lisp_begin_clause ( OOo00OoO ) and OOo00OoO [ 0 : len ( OOO0ooo ) ] == OOO0ooo ) :
   if ( oOOOoOO ) :
    Ii1II111iIi = True
    for iiI in iIIi1 : oo0O0OO0Oooo . write ( iiI )
    if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
    if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
    if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
    if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
 i1iIIi . close ( )
 oo0O0OO0Oooo . close ( )
 if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
 os . system ( "cp {} {}" . format ( Oo0OooII1iII11 , ooooooOO ) )
 os . system ( "rm {}" . format ( Oo0OooII1iII11 ) )
 return ( [ { OOO0ooo : [ { "!" : "add/replace" } ] } ] )
 if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
 if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
 if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
 if 65 - 65: I1ii11iIi11i / ooOoO0o
 if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
 if 57 - 57: iII111i
 if 29 - 29: I1IiiI
 if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
def lisp_remove_clause_for_api ( data ) :
 if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
 if 22 - 22: O0 % IiII % iII111i % I1IiiI
 if 34 - 34: iII111i . Oo0Ooo % I1ii11iIi11i . iII111i % IiII / IiII
 if 84 - 84: Ii1I
 OOO0ooo = list ( data . keys ( ) ) [ 0 ]
 if ( OOO0ooo not in list ( lisp_commands . keys ( ) ) ) :
  return ( [ { OOO0ooo : [ { "?" : "delete" } ] } ] )
  if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
  if 9 - 9: iII111i - iII111i
  if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
  if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
  if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
 iIiIi1i1ii11 = data [ OOO0ooo ]
 iIiIi1i1ii11 = lisp_unicode_to_ascii ( iIiIi1i1ii11 )
 if 41 - 41: I1ii11iIi11i % I1ii11iIi11i + IiII . iII111i % I1Ii111 * ooOoO0o
 if 57 - 57: Ii1I . I1Ii111 . II111iiii % OoooooooOO * O0 + iIii1I11I1II1
 if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
 if 93 - 93: ooOoO0o / OOooOOo * O0
 iI11 = [ ]
 OoOOOO = list ( iIiIi1i1ii11 . keys ( ) ) [ 0 ]
 oo00oO0O0 = iIiIi1i1ii11 [ OoOOOO ]
 if 32 - 32: ooOoO0o - OoooooooOO + OoO0O00
 if ( type ( oo00oO0O0 ) == dict ) :
  for OoOOOO in list ( oo00oO0O0 . keys ( ) ) :
   OO0oO = oo00oO0O0 [ OoOOOO ]
   iI11 . append ( OoOOOO + " = " + OO0oO )
   if 5 - 5: i11iIiiIii / OoO0O00 % O0 / OOooOOo + Oo0Ooo % o0oOOo0O0Ooo
 else :
  iI11 . append ( OoOOOO + " = " + oo00oO0O0 )
  if 93 - 93: OoOoOO00 % I1Ii111 - iII111i . IiII - I1ii11iIi11i * iII111i
  if 11 - 11: ooOoO0o - OoooooooOO
  if 55 - 55: I11i + i1IIi - iII111i + o0oOOo0O0Ooo * IiII
  if 85 - 85: I1IiiI % i11iIiiIii
  if 23 - 23: i11iIiiIii * I1ii11iIi11i % OoO0O00 % ooOoO0o % OoOoOO00
  if 71 - 71: i1IIi * Ii1I + iIii1I11I1II1
 if ( OOO0ooo == "lisp user-account" ) :
  iIIi1 = getoutput ( "egrep -A4 '{}' ./lisp.config" . format ( iI11 [ 0 ] ) )
  if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
  if 63 - 63: ooOoO0o . OOooOOo
  if ( iIIi1 . find ( "super-user = yes" ) != - 1 ) :
   return ( [ { "lisp user-account" : [ { "?" : "found-superuser" } ] } ] )
   if 66 - 66: I1IiiI
   if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
   if 60 - 60: I1ii11iIi11i
   if 78 - 78: oO0o + II111iiii
   if 55 - 55: OoooooooOO
   if 90 - 90: I1IiiI
   if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
 iI1IIIiIII11 = ( "lisp user-account" , "lisp site" , "lisp map-server" ,
 "lisp policy" )
 if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
 ooooooOO = "./lisp.config"
 i1iIIi = open ( ooooooOO , "r" )
 if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
 o0000 = False
 IiI1I1 = 0
 for OOo00OoO in i1iIIi :
  if ( OOo00OoO . find ( OOO0ooo ) == - 1 ) : continue
  IiI1I1 += 1
  if 16 - 16: I1ii11iIi11i / I11i + o0oOOo0O0Ooo % i11iIiiIii % OOooOOo - Ii1I
  for OOo00OoO in i1iIIi :
   if ( lisp_begin_clause ( OOo00OoO ) ) : continue
   II11I1iIi1i1 = ( lisp_end_clause ( OOo00OoO ) and o0000 )
   if ( II11I1iIi1i1 ) : break
   if 18 - 18: II111iiii * o0oOOo0O0Ooo / Oo0Ooo + iII111i . oO0o
   i11111i1I1IiI = OOo00OoO . replace ( " " , "" )
   i11111i1I1IiI = i11111i1I1IiI . replace ( "\n" , "" )
   i11111i1I1IiI = i11111i1I1IiI . replace ( "=" , " = " )
   if 27 - 27: OoooooooOO * I11i % OoooooooOO * Oo0Ooo * ooOoO0o
   if ( i11111i1I1IiI not in iI11 ) :
    o0000 = False
    if ( len ( iI11 ) > 1 ) : break
    continue
    if 18 - 18: OOooOOo / oO0o + iIii1I11I1II1 % I1Ii111 * I11i . Oo0Ooo
   o0000 = True
   if 3 - 3: ooOoO0o - I1ii11iIi11i * I1IiiI . OoOoOO00
   II11I1iIi1i1 = ( OOO0ooo in iI1IIIiIII11 )
   if ( II11I1iIi1i1 ) : break
   if 69 - 69: OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % I1Ii111 - iIii1I11I1II1
   if 49 - 49: o0oOOo0O0Ooo . I1ii11iIi11i % II111iiii
  if ( II11I1iIi1i1 ) : break
  if 4 - 4: I1IiiI / OoOoOO00 / I1IiiI / I11i . IiII + iII111i
  if 48 - 48: i1IIi - IiII + ooOoO0o . iII111i / oO0o % iIii1I11I1II1
 i1iIIi . close ( )
 if 96 - 96: Oo0Ooo . oO0o + iIii1I11I1II1 * OoOoOO00 - O0
 if ( not o0000 ) :
  return ( [ { OOO0ooo : [ { "?" : "not-found" } ] } ] )
  if 74 - 74: OoOoOO00
  if 28 - 28: iII111i
 i1iIIi = open ( ooooooOO , "r" )
 if 53 - 53: OoooooooOO + I1IiiI . iII111i % O0 + Ii1I / o0oOOo0O0Ooo
 Oo0OooII1iII11 = ooooooOO + ".temp"
 oo0O0OO0Oooo = open ( Oo0OooII1iII11 , "w" )
 if 80 - 80: II111iiii + OoOoOO00 / I1IiiI
 if 34 - 34: o0oOOo0O0Ooo % I1ii11iIi11i + Ii1I * I11i / oO0o
 if 18 - 18: ooOoO0o
 if 92 - 92: OoO0O00 % iIii1I11I1II1 / IiII * iII111i . i1IIi + oO0o
 if 24 - 24: IiII . iII111i * IiII % i11iIiiIii . i11iIiiIii + i1IIi
 o0000 = False
 for OOo00OoO in i1iIIi :
  if ( OOo00OoO . find ( OOO0ooo ) != - 1 ) : IiI1I1 -= 1
  if ( IiI1I1 == 0 and not o0000 ) :
   if ( OOo00OoO [ 0 ] == "}" ) : o0000 = True
   continue
   if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
  oo0O0OO0Oooo . write ( OOo00OoO )
  if 100 - 100: IiII + i1IIi * OoO0O00
  if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
 oo0O0OO0Oooo . close ( )
 i1iIIi . close ( )
 if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
 os . system ( "cp {} {}" . format ( Oo0OooII1iII11 , ooooooOO ) )
 os . system ( "rm {}" . format ( Oo0OooII1iII11 ) )
 return ( [ { OOO0ooo : [ { "!" : "delete" } ] } ] )
 if 74 - 74: i1IIi . iIii1I11I1II1
 if 85 - 85: I1IiiI
 if 10 - 10: O0 . II111iiii / OoooooooOO
 if 72 - 72: OoooooooOO . o0oOOo0O0Ooo + O0
 if 46 - 46: OoOoOO00 * I11i / oO0o + Oo0Ooo + IiII
 if 95 - 95: o0oOOo0O0Ooo - Ii1I
 if 67 - 67: I1ii11iIi11i * Oo0Ooo % o0oOOo0O0Ooo
 if 19 - 19: OoOoOO00 . OOooOOo . OoooooooOO
 if 79 - 79: OOooOOo * ooOoO0o * I1IiiI * I1ii11iIi11i / I1ii11iIi11i
def lisp_u2a_walk_dict_array ( adata , a_dict ) :
 for OoOOOO in a_dict :
  if ( type ( a_dict [ OoOOOO ] ) == dict ) :
   O000OOOoOooO = { }
   oo00oO0O0 = a_dict [ OoOOOO ]
   for iIIi1I1 in oo00oO0O0 : O000OOOoOooO [ str ( iIIi1I1 ) ] = str ( oo00oO0O0 [ iIIi1I1 ] )
   adata [ str ( OoOOOO ) ] = O000OOOoOooO
  else :
   adata [ str ( OoOOOO ) ] = str ( a_dict [ OoOOOO ] )
   if 71 - 71: IiII - i1IIi
   if 56 - 56: OoOoOO00 + oO0o
 return
 if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
 if 19 - 19: IiII % OoooooooOO + OoooooooOO
 if 7 - 7: i1IIi
 if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
 if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
 if 80 - 80: IiII % OoooooooOO - IiII
 if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
def lisp_unicode_to_ascii ( udata ) :
 IIIiIIi111 = ( type ( udata ) == dict )
 if ( IIIiIIi111 ) : udata = [ udata ]
 if 77 - 77: I1IiiI / I1Ii111
 OOoo0oo000oo = [ ]
 for OOOooOO0oO in udata :
  iIiIi1 = { }
  if 15 - 15: OoooooooOO
  if ( type ( OOOooOO0oO ) == dict ) :
   lisp_u2a_walk_dict_array ( iIiIi1 , OOOooOO0oO )
  elif ( type ( OOOooOO0oO ) == list ) :
   i11iiI1iiIii = [ ]
   for I1I111i in OOOooOO0oO :
    OOiII111i1 = { }
    lisp_u2a_walk_dict_array ( OOiII111i1 , I1I111i )
    i11iiI1iiIii . append ( OOiII111i1 )
    if 29 - 29: II111iiii
   iIiIi1 = i11iiI1iiIii
  else :
   iIiIi1 = { str ( list ( OOOooOO0oO . keys ( ) ) [ 0 ] ) : iIiIi1 }
   if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
  OOoo0oo000oo . append ( iIiIi1 )
  if 84 - 84: Oo0Ooo % I11i * O0 * I11i
  if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
 if ( IIIiIIi111 ) : OOoo0oo000oo = OOoo0oo000oo [ 0 ]
 return ( OOoo0oo000oo )
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
 if 9 - 9: o0oOOo0O0Ooo
 if 55 - 55: OOooOOo % iIii1I11I1II1 + I11i . ooOoO0o
def lisp_replace_db_list ( db ) :
 O0OO0O = - 1
 for ooOo in lisp . lisp_db_list :
  if ( db . match_eid_tuple ( ooOo ) ) :
   O0OO0O = lisp . lisp_db_list . index ( ooOo )
   break
   if 47 - 47: i11iIiiIii . IiII
   if 37 - 37: I1IiiI / OoooooooOO % i11iIiiIii % I1ii11iIi11i
 if ( O0OO0O == - 1 ) : return ( False )
 if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
 if 1 - 1: IiII % i1IIi
 if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
 if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
 if 80 - 80: I1ii11iIi11i
 if ( lisp . lisp_nat_traversal and lisp . lisp_i_am_etr ) :
  for o0o0OOo0O in ooOo . rloc_set :
   if ( o0o0OOo0O . is_rloc_translated ( ) == False ) : continue
   o00oo = db . get_rloc_by_interface ( o0o0OOo0O . interface )
   if ( o00oo == None ) : continue
   o00oo . store_translated_rloc ( o0o0OOo0O . translated_rloc , o0o0OOo0O . translated_port )
   o00oo . rloc_name = o0o0OOo0O . rloc_name
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
 Ii1111i11 = [ ]
 O0Ooo000OO00 = [ ]
 O000oo0O0OO0 = 0
 oOoo0ooO = 0
 I1 = ""
 i1IiIiIii11I = False
 O0o0O00 = False
 OoI11II = False
 Iii11IiIi = False
 OOOoO000oOOo = 0
 IIiI = None
 iI11IIiII1iII = 0
 OooO00OOOOoo = None
 if 22 - 22: Ii1I - Oo0Ooo % I1ii11iIi11i % ooOoO0o % IiII
 for IiII1II11I in list ( kv_pairs . keys ( ) ) :
  oo00oO0O0 = kv_pairs [ IiII1II11I ]
  if ( IiII1II11I == "ms-name" ) :
   IIiI = oo00oO0O0 [ 0 ]
   if 72 - 72: i1IIi
  if ( IiII1II11I == "address" ) :
   for i1iIIiiIiII in range ( len ( oo00oO0O0 ) ) :
    Ii1111i11 . append ( oo00oO0O0 [ i1iIIiiIiII ] )
    if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
    if 28 - 28: iIii1I11I1II1 . O0
  if ( IiII1II11I == "dns-name" ) :
   for i1iIIiiIiII in range ( len ( oo00oO0O0 ) ) :
    O0Ooo000OO00 . append ( oo00oO0O0 [ i1iIIiiIiII ] )
    if 32 - 32: OoooooooOO
    if 29 - 29: I1ii11iIi11i
  if ( IiII1II11I == "authentication-type" ) :
   oOoo0ooO = lisp . LISP_SHA_1_96_ALG_ID if ( oo00oO0O0 == "sha1" ) else lisp . LISP_SHA_256_128_ALG_ID if ( oo00oO0O0 == "sha2" ) else ""
   if 41 - 41: Ii1I
   if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
  if ( IiII1II11I == "authentication-key" ) :
   if ( oOoo0ooO == 0 ) : oOoo0ooO = lisp . LISP_SHA_256_128_ALG_ID
   Iii = lisp . lisp_parse_auth_key ( oo00oO0O0 )
   O000oo0O0OO0 = list ( Iii . keys ( ) ) [ 0 ]
   I1 = Iii [ O000oo0O0OO0 ]
   if 52 - 52: iII111i % I1Ii111 - I1Ii111 - oO0o - iII111i - i1IIi
  if ( IiII1II11I == "proxy-reply" ) :
   i1IiIiIii11I = True if oo00oO0O0 == "yes" else False
   if 98 - 98: OoO0O00 - Oo0Ooo * I1IiiI
  if ( IiII1II11I == "merge-registrations" ) :
   O0o0O00 = True if oo00oO0O0 == "yes" else False
   if 90 - 90: I1IiiI
  if ( IiII1II11I == "refresh-registrations" ) :
   OoI11II = True if oo00oO0O0 == "yes" else False
   if 27 - 27: iIii1I11I1II1 - oO0o
  if ( IiII1II11I == "want-map-notify" ) :
   Iii11IiIi = True if oo00oO0O0 == "yes" else False
   if 73 - 73: OOooOOo . Oo0Ooo + Oo0Ooo % Oo0Ooo % O0
  if ( IiII1II11I == "site-id" ) :
   OOOoO000oOOo = int ( oo00oO0O0 )
   if 8 - 8: iII111i . Ii1I - i1IIi % OoO0O00 / I11i
  if ( IiII1II11I == "encryption-key" ) :
   OooO00OOOOoo = lisp . lisp_parse_auth_key ( oo00oO0O0 )
   iI11IIiII1iII = list ( OooO00OOOOoo . keys ( ) ) [ 0 ]
   OooO00OOOOoo = OooO00OOOOoo [ iI11IIiII1iII ]
   if 13 - 13: Oo0Ooo / OoOoOO00 . I1ii11iIi11i . OOooOOo
   if 31 - 31: o0oOOo0O0Ooo
   if 59 - 59: Oo0Ooo / Oo0Ooo
   if 87 - 87: I1ii11iIi11i % OoOoOO00 + Ii1I . i11iIiiIii / Ii1I
   if 32 - 32: Ii1I + IiII + I1ii11iIi11i
   if 79 - 79: i1IIi / Ii1I
 for Ii1I1i in Ii1111i11 :
  if ( Ii1I1i == "" ) : continue
  oOOoOoOOO = lisp . lisp_ms ( Ii1I1i , None , IIiI , oOoo0ooO , O000oo0O0OO0 , I1 ,
 i1IiIiIii11I , O0o0O00 , OoI11II , Iii11IiIi , OOOoO000oOOo , iI11IIiII1iII , OooO00OOOOoo )
  if 81 - 81: iIii1I11I1II1
 for o000oO0oOOO in O0Ooo000OO00 :
  if ( o000oO0oOOO == "" ) : continue
  oOOoOoOOO = lisp . lisp_ms ( None , o000oO0oOOO , IIiI , oOoo0ooO , O000oo0O0OO0 , I1 ,
 i1IiIiIii11I , O0o0O00 , OoI11II , Iii11IiIi , OOOoO000oOOo , iI11IIiII1iII , OooO00OOOOoo )
  if 23 - 23: OOooOOo
 return ( oOOoOoOOO )
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
 o0OoO0000oOO = [ ]
 III11i1iI11 = [ ]
 if 31 - 31: I1IiiI - OoooooooOO . IiII
 I1I = 1
 if ( "address" in kv_pair ) :
  if ( lisp_clause_syntax_error ( kv_pair , "address" , "rloc" ) ) : return
  I1I = len ( kv_pair [ "address" ] )
 elif ( "interface" in kv_pair ) :
  if ( lisp_clause_syntax_error ( kv_pair , "interface" , "rloc" ) ) : return
  I1I = len ( kv_pair [ "interface" ] )
  if 77 - 77: ooOoO0o % oO0o % O0 % OoO0O00
 for i1iIIiiIiII in range ( I1I ) :
  o0o0OOo0O = lisp . lisp_rloc ( )
  III11i1iI11 . append ( o0o0OOo0O )
  if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
  if 17 - 17: OoOoOO00
 if ( lisp_clause_syntax_error ( kv_pair , "eid-prefix" , "prefix" ) ) : return
 for i1iIIiiIiII in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  O0oooO = lisp . lisp_mapping ( "" , "" , III11i1iI11 )
  o0OoO0000oOO . append ( O0oooO )
  if 4 - 4: i1IIi % o0oOOo0O0Ooo % oO0o . i1IIi
  if 85 - 85: IiII . Ii1I * o0oOOo0O0Ooo % Oo0Ooo % II111iiii + I1Ii111
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if ( IiII1II11I == "mr-name" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    O0oooO = o0OoO0000oOO [ i1iIIiiIiII ]
    O0oooO . use_mr_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ i1iIIiiIiII ]
    if 85 - 85: II111iiii / ooOoO0o * II111iiii
    if 43 - 43: o0oOOo0O0Ooo / O0 + i1IIi - I1ii11iIi11i % i11iIiiIii
  if ( IiII1II11I == "ms-name" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    O0oooO = o0OoO0000oOO [ i1iIIiiIiII ]
    O0oooO . use_ms_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ i1iIIiiIiII ]
    if 69 - 69: OOooOOo % I1ii11iIi11i / OoOoOO00 . OOooOOo - IiII
    if 74 - 74: OoO0O00 - o0oOOo0O0Ooo - IiII . O0 % ooOoO0o
  if ( IiII1II11I == "instance-id" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    O0oooO = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    oOOo0oO = [ "0" ] if ( oOOo0oO == "" ) else oOOo0oO . split ( )
    for IIi in oOOo0oO : oOOo0oO [ oOOo0oO . index ( IIi ) ] = int ( IIi )
    O0oooO . eid . instance_id = oOOo0oO [ 0 ]
    O0oooO . eid . iid_list = oOOo0oO [ 1 : : ]
    O0oooO . group . instance_id = oOOo0oO [ 0 ]
    if 45 - 45: Oo0Ooo
    if 4 - 4: I11i
  if ( IiII1II11I == "secondary-instance-id" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    O0oooO = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "" ) : continue
    O0oooO . secondary_iid = int ( oOOo0oO )
    if ( O0oooO . eid . address == 0 ) :
     lisp . lisp_default_secondary_iid = int ( oOOo0oO )
     if 60 - 60: II111iiii + I1Ii111 / oO0o % OoooooooOO - i1IIi
     if 57 - 57: ooOoO0o
     if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if ( IiII1II11I == "eid-prefix" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    O0oooO = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : O0oooO . eid . store_prefix ( oOOo0oO )
    if ( O0oooO . eid . address == 0 ) :
     lisp . lisp_default_secondary_iid = O0oooO . secondary_iid
     if 52 - 52: I1ii11iIi11i
     if 93 - 93: iII111i . i11iIiiIii
     if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
  if ( IiII1II11I == "group-prefix" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    O0oooO = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : O0oooO . group . store_prefix ( oOOo0oO )
    if 49 - 49: O0 . Oo0Ooo / Ii1I
    if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
  if ( IiII1II11I == "dynamic-eid" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    O0oooO = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "yes" ) : O0oooO . dynamic_eids = { }
    if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
    if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  if ( IiII1II11I == "signature-eid" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    O0oooO = o0OoO0000oOO [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    O0oooO . signature_eid = ( oOOo0oO == "yes" )
    if 44 - 44: i11iIiiIii
    if 69 - 69: OOooOOo * O0 + i11iIiiIii
  if ( IiII1II11I == "register-ttl" ) :
   for i1iIIiiIiII in range ( len ( o0OoO0000oOO ) ) :
    if ( oo00oO0O0 [ i1iIIiiIiII ] == "" ) : continue
    O0oooO = o0OoO0000oOO [ i1iIIiiIiII ]
    O0oooO . register_ttl = int ( oo00oO0O0 [ i1iIIiiIiII ] )
    if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
    if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
  if ( IiII1II11I == "priority" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "" ) : oOOo0oO = "0"
    o0o0OOo0O . priority = int ( oOOo0oO )
    if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
    if 63 - 63: oO0o
  if ( IiII1II11I == "weight" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO == "" ) : oOOo0oO = "0"
    o0o0OOo0O . weight = int ( oOOo0oO )
    if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
    if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
  if ( IiII1II11I == "address" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . rloc . store_address ( oOOo0oO )
    if 60 - 60: I1Ii111
    if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
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
      if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
     o0o0OOo0O . rloc_name = O0I11i1i11i1I
     O0O00o0O . append ( o0o0OOo0O )
     if 14 - 14: Ii1I - O0
     if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
     if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
  if ( IiII1II11I == "elp-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . elp_name = oOOo0oO
    if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
    if 7 - 7: IiII * ooOoO0o + OoOoOO00
  if ( IiII1II11I == "rle-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . rle_name = oOOo0oO
    if 22 - 22: iII111i
    if 48 - 48: I1ii11iIi11i . I1IiiI
  if ( IiII1II11I == "json-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . json_name = oOOo0oO
    if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
    if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
  if ( IiII1II11I == "geo-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . geo_name = oOOo0oO
    if 49 - 49: Oo0Ooo
    if 57 - 57: O0 * ooOoO0o - iII111i - iIii1I11I1II1 * iII111i
  if ( IiII1II11I == "rloc-record-name" ) :
   for i1iIIiiIiII in range ( len ( III11i1iI11 ) ) :
    o0o0OOo0O = III11i1iI11 [ i1iIIiiIiII ]
    oOOo0oO = oo00oO0O0 [ i1iIIiiIiII ]
    if ( oOOo0oO != "" ) : o0o0OOo0O . rloc_name = oOOo0oO
    if 9 - 9: IiII . I11i
    if 23 - 23: O0 % OoooooooOO - O0 . I1IiiI + i11iIiiIii
    if 96 - 96: ooOoO0o % O0
    if 51 - 51: I1IiiI - iII111i / I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i
    if 87 - 87: II111iiii . Ii1I * OoO0O00
    if 74 - 74: o0oOOo0O0Ooo % OoOoOO00 . iII111i % I1Ii111 . O0 % II111iiii
    if 5 - 5: oO0o - OoooooooOO / OoOoOO00
    if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
    if 55 - 55: OoO0O00
    if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
 if ( len ( O0O00o0O ) > 1 ) :
  for o0o0OOo0O in O0O00o0O :
   o0o0OOo0O . rloc_name = O0I11i1i11i1I + "-" + o0o0OOo0O . interface
   if 32 - 32: Ii1I * oO0o
   if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
   if 28 - 28: Oo0Ooo
   if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
   if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
   if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
 for O0oooO in o0OoO0000oOO :
  O0oooO . rloc_set = copy . deepcopy ( O0oooO . rloc_set )
  O0oooO . sort_rloc_set ( )
  O0oooO . add_db ( )
  if ( replace and lisp_replace_db_list ( O0oooO ) ) : continue
  lisp . lisp_db_list . append ( O0oooO )
  if 69 - 69: I11i
  if 17 - 17: I11i
  if 38 - 38: I1Ii111 % OOooOOo
  if 9 - 9: O0 . iIii1I11I1II1
  if 44 - 44: I1ii11iIi11i % IiII
 lisp . lisp_write_ipc_database_mappings ( ephem_port )
 if 6 - 6: OoO0O00
 if 82 - 82: iIii1I11I1II1 . I11i / IiII / OOooOOo * II111iiii % oO0o
 if 62 - 62: II111iiii
 if 96 - 96: I11i % OoOoOO00 * I1ii11iIi11i
 if 94 - 94: Oo0Ooo - i1IIi . O0 % Oo0Ooo . ooOoO0o
 if 63 - 63: i11iIiiIii % I1ii11iIi11i % I1IiiI . IiII * o0oOOo0O0Ooo + OOooOOo
 if 77 - 77: o0oOOo0O0Ooo
 lisp . lisp_default_iid = lisp . lisp_db_list [ 0 ] . eid . instance_id
 if 63 - 63: ooOoO0o * oO0o + ooOoO0o * Ii1I + Oo0Ooo / I1ii11iIi11i
 if 15 - 15: O0 . I1ii11iIi11i * I1ii11iIi11i
 if 65 - 65: I1Ii111 + O0 % o0oOOo0O0Ooo
 if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
 if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
 if 50 - 50: OoooooooOO * i1IIi / oO0o
 if 83 - 83: i1IIi
 if 38 - 38: OoooooooOO * iIii1I11I1II1
 for O0oooO in o0OoO0000oOO :
  if ( O0oooO . eid . address == 0 and O0oooO . eid . mask_len == 0 ) :
   if ( O0oooO . eid . is_ipv4 ( ) or O0oooO . eid . is_ipv6 ( ) ) :
    lisp . lisp_pitr = True
    break
    if 54 - 54: OoooooooOO . I1Ii111
    if 71 - 71: Ii1I
    if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
  if ( O0oooO . dynamic_eids == None ) : continue
  if ( O0oooO . eid . is_mac ( ) and O0oooO . eid . address == 0 and O0oooO . eid . mask_len == 0 ) :
   lisp . lisp_l2_overlay = True
   break
   if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
   if 93 - 93: ooOoO0o % I1Ii111
   if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
   if 43 - 43: ooOoO0o . i1IIi
   if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
   if 45 - 45: I1IiiI
   if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
   if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
 IIII1iIii1Ii = ( lisp . lisp_myrlocs [ 0 ] != None )
 lisp . lisp_get_local_addresses ( )
 if 54 - 54: i1IIi - Oo0Ooo - o0oOOo0O0Ooo * IiII - iII111i
 if ( lisp . lisp_myrlocs [ 0 ] == None and IIII1iIii1Ii ) :
  lisp . lprint ( "No RLOCs found, local addresses changed from RLOC to EID" )
  if 28 - 28: O0 / o0oOOo0O0Ooo . Ii1I / O0 . oO0o - o0oOOo0O0Ooo
  if 63 - 63: OOooOOo / II111iiii . OoOoOO00 / i1IIi / I11i . o0oOOo0O0Ooo
  if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
  if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
  if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
  if 10 - 10: II111iiii . OOooOOo / iII111i
  if 35 - 35: iII111i / Oo0Ooo + O0 * iIii1I11I1II1 - O0
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
  if 54 - 54: ooOoO0o * I11i - I1Ii111
  if 15 - 15: iII111i / O0
  if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
  if 19 - 19: o0oOOo0O0Ooo . II111iiii / i1IIi
 if ( lisp . lisp_program_hardware == False ) : return
 if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
 o0000 = False
 for O0oooO in o0OoO0000oOO :
  if ( O0oooO . dynamic_eids == None ) : continue
  IIiiII11i11I = O0oooO . eid . print_prefix_no_iid ( )
  o0000 = lisp . lisp_i_am_itr
  os . system ( "ip route add {} dev ma1" . format ( IIiiII11i11I ) )
  if 95 - 95: Oo0Ooo / IiII + Oo0Ooo
 if ( lisp . lisp_program_hardware and o0000 ) :
  OOO = "platform trident diag s cpu_control_1 URPF_MISS_TOCPU=1"
  lisp . lisp_send_to_arista ( OOO , None )
  if 94 - 94: ooOoO0o - i1IIi . O0 / I1IiiI
  if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
  if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
  if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
  if 59 - 59: I1Ii111 * iII111i
  if 31 - 31: I11i / O0
  if 57 - 57: i1IIi % ooOoO0o
  if 69 - 69: o0oOOo0O0Ooo
def lisp_show_db_list ( itr_or_etr , output ) :
 Iiii = "{} database-mapping entries" . format ( len ( lisp . lisp_db_list ) )
 oOooOOOOoo0O = "LISP-{} Configured Database Mappings:" . format ( itr_or_etr )
 oOooOOOOoo0O = lisp . lisp_span ( oOooOOOOoo0O , Iiii )
 if 69 - 69: I1Ii111
 i111IiIi1 = '<a href="/lisp/show/etr/keys"><br>RLOC Keys</a>'
 if 83 - 83: iIii1I11I1II1 . o0oOOo0O0Ooo + I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
 if ( itr_or_etr == "ITR" ) :
  output += lisp_table_header ( oOooOOOOoo0O , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Use MR" )
 else :
  output += lisp_table_header ( oOooOOOOoo0O , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" + i111IiIi1 , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Receive Stats" ,
 "Map-Replies<br>Sent" , "Use MS" )
  if 90 - 90: Ii1I * iII111i / OOooOOo
  if 68 - 68: OoOoOO00
 for O0oooO in lisp . lisp_db_list :
  o0oO000oO = lisp . lisp_print_elapsed ( O0oooO . uptime )
  IiiIi1 = O0oooO . map_replies_sent
  if 65 - 65: Ii1I
  if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
  if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
  if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
  oOo000O00O = ""
  if ( O0oooO . dynamic_eid_configured ( ) ) :
   OooO = O0oooO . eid . print_prefix_url ( )
   iiII = len ( O0oooO . dynamic_eids )
   oOO = itr_or_etr . lower ( )
   oOo000O00O = ( "<br><a href='/lisp/show/{}/dynamic-eid/{}'>" + "{} dynamic-eids</a>" ) . format ( oOO , OooO , iiII )
   if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
   if 37 - 37: IiII % Ii1I % i1IIi
   if 23 - 23: ooOoO0o - O0 + i11iIiiIii
  oO0ooOoOooO00o00 = True
  for o0o0OOo0O in O0oooO . rloc_set :
   if ( oO0ooOoOooO00o00 ) :
    o0Ooo00Oo0oo0 = O0oooO . print_eid_tuple ( )
    o0Ooo00Oo0oo0 = O0oooO . star_secondary_iid ( o0Ooo00Oo0oo0 )
    o0Ooo00Oo0oo0 += oOo000O00O
    oO0OOoO0 = o0oO000oO
    oO0ooOoOooO00o00 = False
   else :
    o0Ooo00Oo0oo0 , oO0OOoO0 , IiiIi1 = ( "" , "" , "" )
    if 22 - 22: ooOoO0o . o0oOOo0O0Ooo * Ii1I - ooOoO0o / I1IiiI
    if 100 - 100: I11i - OOooOOo - OoooooooOO * OoO0O00 * iII111i + oO0o
   i1 = "" if o0o0OOo0O . rloc . is_null ( ) else o0o0OOo0O . rloc . print_address_no_iid ( )
   if 100 - 100: I1Ii111 - i1IIi
   if 90 - 90: Ii1I + oO0o . II111iiii - OoOoOO00 % iIii1I11I1II1
   if ( o0o0OOo0O . interface != None ) :
    i1 += " ({})" . format ( o0o0OOo0O . interface )
    if 24 - 24: IiII / Ii1I * OOooOOo
   if ( i1 != "" ) : i1 += "<br>"
   if 33 - 33: OOooOOo
   if ( o0o0OOo0O . translated_rloc . not_set ( ) == False ) :
    i1 += "translated RLOC: {}<br>" . format ( o0o0OOo0O . translated_rloc . print_address_no_iid ( ) )
    if 22 - 22: O0 + OOooOOo % i1IIi
    if 83 - 83: O0 + Ii1I % i11iIiiIii
    if 32 - 32: I1Ii111 % Oo0Ooo - I11i + O0
   OOo0o0 = o0o0OOo0O . print_rloc_name ( True )
   if ( OOo0o0 != "" ) : i1 += OOo0o0 + "<br>"
   if 60 - 60: o0oOOo0O0Ooo / Oo0Ooo
   if ( o0o0OOo0O . geo_name != None ) :
    i1 += "geo: " + o0o0OOo0O . geo_name + "<br>"
    if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
   if ( o0o0OOo0O . elp_name != None ) :
    i1 += "elp: " + o0o0OOo0O . elp_name + "<br>"
    if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
   if ( o0o0OOo0O . rle_name != None ) :
    i1 += "rle: " + o0o0OOo0O . rle_name + "<br>"
    if 76 - 76: OoO0O00 * oO0o - OoO0O00
   if ( o0o0OOo0O . json_name != None ) :
    i1 += "json: " + o0o0OOo0O . json_name + "<br>"
    if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
    if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
   if ( itr_or_etr == "ITR" ) :
    output += lisp_table_row ( o0Ooo00Oo0oo0 , oO0OOoO0 , i1 ,
 str ( o0o0OOo0O . priority ) + "/" + str ( o0o0OOo0O . weight ) ,
 str ( o0o0OOo0O . mpriority ) + "/" + str ( o0o0OOo0O . mweight ) ,
 O0oooO . use_mr_name )
   else :
    IiIII = o0o0OOo0O . stats . get_stats ( True , True )
    output += lisp_table_row ( o0Ooo00Oo0oo0 , oO0OOoO0 , i1 ,
 str ( o0o0OOo0O . priority ) + "/" + str ( o0o0OOo0O . weight ) ,
 str ( o0o0OOo0O . mpriority ) + "/" + str ( o0o0OOo0O . mweight ) , IiIII ,
 IiiIi1 , O0oooO . use_ms_name )
    if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
    if 70 - 70: O0 . Ii1I
    if 33 - 33: OOooOOo * Ii1I
 output += lisp_table_footer ( )
 if 64 - 64: i11iIiiIii . iIii1I11I1II1
 if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
 if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
 if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
 if ( len ( lisp . lisp_geo_list ) != 0 ) :
  oOooOOOOoo0O = "Configured Geo-Coordinates:"
  output += lisp_table_header ( oOooOOOOoo0O , "Geo Name" ,
 "Geo-Prefix or Geo-Point" )
  o0 = sorted ( lisp . lisp_geo_list )
  for Oo in o0 :
   oOO0o0oOoO = lisp . lisp_geo_list [ Oo ]
   output += lisp_table_row ( Oo , oOO0o0oOoO . print_geo_url ( ) )
   if 98 - 98: ooOoO0o - iIii1I11I1II1 + OOooOOo - iIii1I11I1II1
  output += lisp_table_footer ( )
  if 70 - 70: OOooOOo / I1ii11iIi11i
 return ( output )
 if 72 - 72: OoooooooOO + OoooooooOO
 if 42 - 42: ooOoO0o / IiII
 if 62 - 62: I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + I1IiiI / II111iiii
 if 91 - 91: I1IiiI % O0 / oO0o * I1Ii111 + Ii1I - i1IIi
 if 71 - 71: OoOoOO00 / IiII / II111iiii * OOooOOo - I1ii11iIi11i - iIii1I11I1II1
 if 5 - 5: oO0o + OoOoOO00
 if 94 - 94: o0oOOo0O0Ooo % o0oOOo0O0Ooo % II111iiii * iIii1I11I1II1 / IiII . I1ii11iIi11i
def lisp_interface_command ( kv_pair ) :
 IIiIiI1III1 = None
 iiiiII1i1Iii1I1 = None
 OoOO00OO0 = None
 OoOoooOooOO0o = None
 I1i = None
 ooOOooO = None
 O0O00o00O0 = None
 O00o0 = None
 if 9 - 9: IiII + II111iiii . I1IiiI * iII111i
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if ( IiII1II11I == "interface-name" ) : IIiIiI1III1 = oo00oO0O0
  if ( IiII1II11I == "device" ) : iiiiII1i1Iii1I1 = oo00oO0O0
  if ( IiII1II11I == "instance-id" ) : OoOO00OO0 = oo00oO0O0
  if ( IiII1II11I == "dynamic-eid" ) : OoOoooOooOO0o = oo00oO0O0
  if ( IiII1II11I == "multi-tenant-eid" ) : O0O00o00O0 = oo00oO0O0
  if ( IiII1II11I == "dynamic-eid-device" ) : I1i = oo00oO0O0
  if ( IiII1II11I == "dynamic-eid-timeout" ) : ooOOooO = oo00oO0O0
  if ( IiII1II11I == "lisp-nat" ) : O00o0 = ( oo00oO0O0 == "yes" )
  if 6 - 6: iII111i % I1Ii111
  if 17 - 17: II111iiii - OoooooooOO + I11i % Ii1I % OoooooooOO
 if ( iiiiII1i1Iii1I1 == None ) : return
 if 14 - 14: i1IIi - iIii1I11I1II1 . ooOoO0o + IiII / i1IIi / II111iiii
 if 47 - 47: OOooOOo
 if 68 - 68: I1Ii111 + IiII . iIii1I11I1II1
 if 48 - 48: I1IiiI % O0 * Oo0Ooo / O0
 if 95 - 95: I1ii11iIi11i / Ii1I
 if 82 - 82: II111iiii . I1Ii111
 if 80 - 80: o0oOOo0O0Ooo
 if 46 - 46: iII111i % I1Ii111 % OoOoOO00 . OoooooooOO . II111iiii % IiII
 if ( iiiiII1i1Iii1I1 in lisp . lisp_myinterfaces and O0O00o00O0 == None ) :
  I1i1I1i1I1 = lisp . lisp_myinterfaces [ iiiiII1i1Iii1I1 ]
 else :
  I1i1I1i1I1 = lisp . lisp_interface ( iiiiII1i1Iii1I1 )
  lisp . lisp_myinterfaces [ iiiiII1i1Iii1I1 ] = I1i1I1i1I1
  if 33 - 33: Ii1I . oO0o
  if 87 - 87: Oo0Ooo . o0oOOo0O0Ooo - OoooooooOO * oO0o % IiII + O0
  if 16 - 16: I1ii11iIi11i % Oo0Ooo % II111iiii % II111iiii
  if 51 - 51: OoOoOO00 * OoOoOO00 - O0 % iIii1I11I1II1 / O0
  if 5 - 5: i11iIiiIii * ooOoO0o % iII111i - I11i
 I1i1I1i1I1 . interface_name = IIiIiI1III1
 if ( OoOO00OO0 != None ) :
  if ( OoOO00OO0 . isdigit ( ) == False ) : OoOO00OO0 = "0"
  I1i1I1i1I1 . instance_id = int ( OoOO00OO0 )
  if 5 - 5: O0 * IiII * OOooOOo + I1Ii111 % Oo0Ooo - I1ii11iIi11i
 if ( OoOoooOooOO0o != None ) :
  I1i1I1i1I1 . dynamic_eid . store_prefix ( OoOoooOooOO0o )
  I1i1I1i1I1 . dynamic_eid . instance_id = I1i1I1i1I1 . instance_id
  if 62 - 62: I1ii11iIi11i + I11i
 if ( I1i != None ) :
  I1i1I1i1I1 . dynamic_eid_device = I1i
  if 90 - 90: iIii1I11I1II1
 if ( ooOOooO != None ) :
  I1i1I1i1I1 . dynamic_eid_timeout = int ( ooOOooO )
  if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
 if ( O0O00o00O0 != None ) :
  I1i1I1i1I1 . multi_tenant_eid . store_prefix ( O0O00o00O0 )
  I1i1I1i1I1 . multi_tenant_eid . instance_id = int ( I1i1I1i1I1 . instance_id )
  lisp . lisp_multi_tenant_interfaces . append ( I1i1I1i1I1 )
  if 69 - 69: Oo0Ooo * ooOoO0o
 if ( O00o0 ) :
  OOII1iI = "sudo iptables -t nat -C POSTROUTING -o {} -j MASQUERADE"
  OOII1iI = getoutput ( OOII1iI . format ( iiiiII1i1Iii1I1 ) )
  if ( OOII1iI != "" ) :
   Ooooo0OO = lisp . lisp_get_loopback_address ( )
   if ( Ooooo0OO ) :
    o0o0OO0OO = "sudo iptables -t nat -A POSTROUTING -s {} -j ACCEPT"
    os . system ( o0o0OO0OO . format ( Ooooo0OO ) )
    if 21 - 21: I1IiiI - OoooooooOO / OoOoOO00 * OoooooooOO % OoooooooOO + OoO0O00
   o0o0OO0OO = "sudo iptables -t nat -A POSTROUTING -o {} -j MASQUERADE"
   os . system ( o0o0OO0OO . format ( iiiiII1i1Iii1I1 ) )
   os . system ( "sudo sysctl net.ipv4.ip_forward=1" )
   if 89 - 89: iII111i . OOooOOo . I1ii11iIi11i
   if 93 - 93: II111iiii
   if 8 - 8: Ii1I * OoooooooOO / Ii1I / OoO0O00 % OoOoOO00 + I11i
 lisp . lisp_iid_to_interface [ OoOO00OO0 ] = I1i1I1i1I1
 if 16 - 16: I11i % ooOoO0o - i11iIiiIii
 if 38 - 38: o0oOOo0O0Ooo / I1ii11iIi11i - O0
 if 21 - 21: OOooOOo
 if 77 - 77: II111iiii
 if 54 - 54: OoooooooOO % O0 % O0 * Ii1I % II111iiii + OOooOOo
 if ( "SO_BINDTODEVICE" in dir ( socket ) ) : I1i1I1i1I1 . set_socket ( iiiiII1i1Iii1I1 )
 if ( "PF_PACKET" in dir ( socket ) ) : I1i1I1i1I1 . set_bridge_socket ( iiiiII1i1Iii1I1 )
 if 89 - 89: IiII - o0oOOo0O0Ooo - II111iiii * Ii1I . iIii1I11I1II1
 if 33 - 33: I1IiiI . iIii1I11I1II1 / i11iIiiIii * Ii1I
 if 18 - 18: OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % ooOoO0o % II111iiii - IiII
 if 75 - 75: OoO0O00 . II111iiii . oO0o / OoO0O00 % iIii1I11I1II1
 lisp . lisp_get_local_addresses ( )
 if 8 - 8: O0 / II111iiii
 if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
 if 87 - 87: IiII
 if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
 if 55 - 55: IiII
 if 43 - 43: OOooOOo
 if ( OoOoooOooOO0o != None and lisp . lisp_program_hardware ) :
  OOO = "ip verify unicast source reachable-via rx"
  lisp . lisp_send_to_arista ( OOO , iiiiII1i1Iii1I1 )
  OOO = 'sysctl -w "net.ipv4.conf.{}.rp_filter=0"' . format ( iiiiII1i1Iii1I1 )
  os . system ( OOO )
  if 17 - 17: i11iIiiIii
  if 94 - 94: OoooooooOO - IiII + oO0o . OoooooooOO / i1IIi
  if 53 - 53: I1Ii111 % I1ii11iIi11i
  if 17 - 17: OoooooooOO % Ii1I % O0
  if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
 lisp . lisp_write_ipc_interfaces ( )
 return
 if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
 if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
 if 80 - 80: oO0o / O0
 if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
 if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
 if 59 - 59: IiII
 if 54 - 54: OOooOOo
 if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
def lisp_parse_eid_in_url ( command , eid_prefix ) :
 I11iiI1i1 = ""
 if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
 if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
 if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
 if 33 - 33: oO0o % OoO0O00 . iIii1I11I1II1 / IiII
 if ( eid_prefix == "0--0" ) :
  command = command + "%[0]/0%"
 elif ( eid_prefix . find ( "-name-" ) != - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if ( len ( eid_prefix ) > 4 ) :
   eid_prefix = [ eid_prefix [ 0 ] , "name" , "-" . join ( eid_prefix [ 2 : - 1 ] ) ,
 eid_prefix [ - 1 ] ]
   if 3 - 3: Ii1I + OoO0O00
   if 60 - 60: OoO0O00 . OoOoOO00 - I1ii11iIi11i - I1IiiI - II111iiii % Oo0Ooo
   if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
   if 47 - 47: I1Ii111 + I1IiiI
   if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
  OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]'" + eid_prefix [ 2 ] + "'" + "/" + eid_prefix [ 3 ]
  if 80 - 80: oO0o
  command = command + "%" + OOOO0oo0 + "%"
 elif ( eid_prefix . count ( "-" ) in [ 9 , 10 ] ) :
  if 81 - 81: OoooooooOO / ooOoO0o * iIii1I11I1II1 . Oo0Ooo + oO0o / O0
  if 84 - 84: II111iiii - o0oOOo0O0Ooo
  if 78 - 78: IiII
  if 58 - 58: i11iIiiIii - OoOoOO00
  eid_prefix = eid_prefix . split ( "-" )
  OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + "-" . join ( eid_prefix [ 1 : - 1 ] ) + "/" + eid_prefix [ - 1 ]
  if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
  command = command + "%" + OOOO0oo0 + "%"
 elif ( eid_prefix . find ( "." ) == - 1 and eid_prefix . find ( ":" ) == - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if 99 - 99: ooOoO0o . Ii1I
  if 92 - 92: i1IIi
  if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
  if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
  if ( eid_prefix [ 1 ] == "plus" ) :
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]+" + eid_prefix [ 2 ] + "/" + eid_prefix [ 3 ]
   if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
   command = command + "%" + OOOO0oo0 + "%"
  else :
   if 4 - 4: Ii1I
   if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
   if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
   if 32 - 32: I1Ii111 / oO0o / I1IiiI
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "-" + eid_prefix [ 2 ] + "-" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
   if 69 - 69: oO0o - I1IiiI
   if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
   if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
   if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
   if ( len ( eid_prefix ) == 10 ) :
    I11iiI1i1 = "[" + eid_prefix [ 5 ] + "]" + eid_prefix [ 6 ] + "-" + eid_prefix [ 7 ] + "-" + eid_prefix [ 8 ] + "/" + eid_prefix [ 9 ]
    if 35 - 35: I1ii11iIi11i % OoooooooOO
    command = command + "%" + OOOO0oo0 + "%" + I11iiI1i1
   else :
    command = command + "%" + OOOO0oo0 + "%"
    if 59 - 59: I1IiiI % I11i
    if 32 - 32: I1IiiI * O0 + O0
    if 34 - 34: IiII
 else :
  if 5 - 5: OoO0O00 . I1IiiI
  if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
  if 47 - 47: iII111i / OoooooooOO - II111iiii
  if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
  eid_prefix = eid_prefix . split ( "-" )
  if ( eid_prefix [ 1 ] == "*" ) :
   OOOO0oo0 = ""
   I11iiI1i1 = "[" + eid_prefix [ 2 ] + "]" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 23 - 23: i1IIi
  else :
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "/" + eid_prefix [ 2 ]
   if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
   if ( len ( eid_prefix ) == 6 ) :
    I11iiI1i1 = "[" + eid_prefix [ 3 ] + "]" + eid_prefix [ 4 ] + "/" + eid_prefix [ 5 ]
    if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
    if 31 - 31: I1Ii111 - I11i
    if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
  command = command + "%" + OOOO0oo0 + "%" + I11iiI1i1
  if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
 return ( command )
 if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
 if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
 if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
 if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
 if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
 if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
 if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
def lisp_show_dynamic_eid_command ( parm ) :
 I1i1iii = ""
 if ( parm == "" ) : return ( I1i1iii )
 if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
 OOoIiI1i11iIi1 = lisp_get_lookup_string ( parm . split ( "%" ) [ 0 ] )
 OOoIiI1i11iIi1 = OOoIiI1i11iIi1 [ 0 ]
 if 97 - 97: Ii1I % i1IIi % IiII + Oo0Ooo - O0 - I11i
 O0oooO = lisp . lisp_db_for_lookups . lookup_cache ( OOoIiI1i11iIi1 , False )
 if ( O0oooO == None ) : return ( I1i1iii )
 if 64 - 64: Ii1I - iII111i
 oOO = "ITR" if lisp . lisp_i_am_itr else "ETR"
 OOOO0oo0 = O0oooO . print_eid_tuple ( )
 if 12 - 12: i1IIi
 oOooOOOOoo0O = "LISP-{} Discovered Dynamic EIDs for {}:" . format ( oOO , OOOO0oo0 )
 if 99 - 99: II111iiii - I1ii11iIi11i * IiII
 if ( oOO == "ITR" ) :
  I1i1iii = lisp_table_header ( oOooOOOOoo0O , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Last Packet" , "Inactivity Timeout" )
 else :
  I1i1iii = lisp_table_header ( oOooOOOOoo0O , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Inactivity Timeout" )
  if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
  if 15 - 15: I1ii11iIi11i * Ii1I / iII111i . o0oOOo0O0Ooo / Ii1I % OoOoOO00
 for IIiiII11i11I in list ( O0oooO . dynamic_eids . values ( ) ) :
  OOoIiI1i11iIi1 = IIiiII11i11I . dynamic_eid . print_address ( )
  Oo0o0ooOo0 = lisp . lisp_print_elapsed ( IIiiII11i11I . uptime )
  OoOoo0ooO0000 = str ( IIiiII11i11I . timeout ) + " secs"
  if ( oOO == "ITR" ) :
   ii1iiI11III1 = lisp . lisp_print_elapsed ( IIiiII11i11I . last_packet )
   I1i1iii += lisp_table_row ( OOoIiI1i11iIi1 , IIiiII11i11I . interface , Oo0o0ooOo0 , ii1iiI11III1 , OoOoo0ooO0000 )
  else :
   I1i1iii += lisp_table_row ( OOoIiI1i11iIi1 , IIiiII11i11I . interface , Oo0o0ooOo0 , OoOoo0ooO0000 )
   if 8 - 8: I1ii11iIi11i - i1IIi - oO0o / oO0o % o0oOOo0O0Ooo
   if 98 - 98: OoO0O00 * ooOoO0o + i1IIi + IiII - i1IIi % OoOoOO00
 I1i1iii += lisp_table_footer ( )
 return ( I1i1iii )
 if 19 - 19: iIii1I11I1II1 * Oo0Ooo / OOooOOo
 if 5 - 5: o0oOOo0O0Ooo
 if 24 - 24: IiII + OoO0O00 - Ii1I
 if 38 - 38: I1Ii111
 if 30 - 30: II111iiii + I11i . i11iIiiIii + iIii1I11I1II1
 if 100 - 100: oO0o * o0oOOo0O0Ooo / iII111i
 if 92 - 92: ooOoO0o / i11iIiiIii * OOooOOo
def lisp_clear_decap_stats ( command ) :
 oooOO0OoO0OOO = command . split ( "%" ) [ 1 ]
 lisp . lisp_decap_stats [ oooOO0OoO0OOO ] = lisp . lisp_stats ( )
 if 60 - 60: I1ii11iIi11i * i11iIiiIii - II111iiii + I1Ii111 % IiII
 if 63 - 63: OoooooooOO . Ii1I - oO0o / II111iiii + I1IiiI
 if 97 - 97: I11i
 if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
 if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
 if 24 - 24: OoO0O00 % O0 % I11i
def lisp_show_decap_stats ( output , etr_or_rtr ) :
 O0o = etr_or_rtr . upper ( )
 I111Ii111 = etr_or_rtr . lower ( )
 if 83 - 83: OoooooooOO * iIii1I11I1II1 . OoooooooOO / II111iiii . OoooooooOO - IiII
 oo0ooO0O0o = [ ]
 for OoOOOO in lisp . lisp_decap_stats :
  OOOo0oo000 = "<a href='/lisp/clear/{}/stats/{}'>{}</a>" . format ( I111Ii111 , OoOOOO , OoOOOO )
  oo0ooO0O0o . append ( OOOo0oo000 )
  if 28 - 28: Oo0Ooo . iII111i % O0 - OoOoOO00
  if 62 - 62: oO0o
 III1I111 = "LISP-{} Decapsulation Stats:" . format ( O0o )
 output += lisp_table_header ( III1I111 , * oo0ooO0O0o )
 if 58 - 58: O0 / OoOoOO00
 oo0ooO0O0o = [ ]
 for ii1Ii in list ( lisp . lisp_decap_stats . values ( ) ) :
  oo0ooO0O0o . append ( ii1Ii . get_stats ( False , True ) )
  if 42 - 42: iII111i
 output += lisp_table_row ( * oo0ooO0O0o )
 output += lisp_table_footer ( )
 return ( output )
 if 6 - 6: OoO0O00 + OOooOOo
 if 22 - 22: Oo0Ooo . OoooooooOO % I1Ii111
 if 16 - 16: I1ii11iIi11i
 if 78 - 78: OoO0O00 * iIii1I11I1II1
 if 58 - 58: I1ii11iIi11i * i11iIiiIii
 if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
 if 47 - 47: Ii1I . OoOoOO00 . iIii1I11I1II1 . o0oOOo0O0Ooo
 if 39 - 39: o0oOOo0O0Ooo
def lisp_show_crypto_list ( xtr ) :
 I1i1iii = ""
 Ooo0o00 = len ( lisp . lisp_crypto_keys_by_nonce ) != 0
 if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
 if ( lisp . lisp_i_am_itr or lisp . lisp_i_am_rtr ) :
  if ( Ooo0o00 ) :
   oOooOOOOoo0O = "LISP-{} Nonce Crypto State" . format ( xtr )
   I1i1iii += lisp_table_header ( oOooOOOOoo0O , "Nonce" , "Uptime" , "Key-ID" ,
 "Key Material" )
   for OoOOOO in lisp . lisp_crypto_keys_by_nonce :
    i1iIII1IIi = "0x" + lisp . lisp_hex_string ( OoOOOO )
    oo00oO0O0 = lisp . lisp_crypto_keys_by_nonce [ OoOOOO ]
    for I1i11iiIiIi in oo00oO0O0 :
     if ( I1i11iiIiIi == None ) : continue
     O00 = lisp . lisp_print_elapsed ( I1i11iiIiIi . uptime )
     i111IiIi1 = I1i11iiIiIi . print_keys ( False )
     I1i1iii += lisp_table_row ( i1iIII1IIi , O00 , I1i11iiIiIi . key_id , i111IiIi1 )
     i1iIII1IIi = ""
     if 74 - 74: iII111i / OoOoOO00 % oO0o / i1IIi
     if 19 - 19: O0 + OoOoOO00 * OoOoOO00 . iII111i
   I1i1iii += lisp_table_footer ( )
   if 73 - 73: ooOoO0o
   if 14 - 14: Oo0Ooo % iIii1I11I1II1 - iIii1I11I1II1 . iIii1I11I1II1 - o0oOOo0O0Ooo * I1Ii111
  oOooOOOOoo0O = "LISP-{} Encapsulation Crypto State" . format ( xtr )
  I1i1iii += lisp_table_header ( oOooOOOOoo0O , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for OoOOOO in lisp . lisp_crypto_keys_by_rloc_encap :
   i1iIII1IIi = OoOOOO
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_encap [ OoOOOO ]
   for I1i11iiIiIi in oo00oO0O0 :
    if ( I1i11iiIiIi == None ) : continue
    O00 = lisp . lisp_print_elapsed ( I1i11iiIiIi . uptime )
    II1iIIII = lisp . lisp_print_elapsed ( I1i11iiIiIi . last_rekey )
    i111IiIi1 = I1i11iiIiIi . print_keys ( False )
    I1i1iii += lisp_table_row ( i1iIII1IIi , O00 , II1iIIII , I1i11iiIiIi . rekey_count ,
 I1i11iiIiIi . use_count , I1i11iiIiIi . key_id , i111IiIi1 )
    i1iIII1IIi = ""
    if 43 - 43: OOooOOo * OoOoOO00 . I1Ii111 * II111iiii - i11iIiiIii + I11i
    if 44 - 44: ooOoO0o * i11iIiiIii . iII111i / iIii1I11I1II1
  I1i1iii += lisp_table_footer ( )
  if 44 - 44: OoO0O00
  if 74 - 74: Ii1I * i1IIi * I11i - OoooooooOO . I1IiiI
 if ( lisp . lisp_i_am_etr or lisp . lisp_i_am_rtr ) :
  oOooOOOOoo0O = "LISP-{} Decapsulation Crypto State" . format ( xtr )
  I1i1iii += lisp_table_header ( oOooOOOOoo0O , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for OoOOOO in lisp . lisp_crypto_keys_by_rloc_decap :
   i1iIII1IIi = OoOOOO
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_decap [ OoOOOO ]
   for I1i11iiIiIi in oo00oO0O0 :
    if ( I1i11iiIiIi == None ) : continue
    O00 = lisp . lisp_print_elapsed ( I1i11iiIiIi . uptime )
    II1iIIII = lisp . lisp_print_elapsed ( I1i11iiIiIi . last_rekey )
    i111IiIi1 = I1i11iiIiIi . print_keys ( False )
    I1i1iii += lisp_table_row ( i1iIII1IIi , O00 , II1iIIII , I1i11iiIiIi . rekey_count ,
 I1i11iiIiIi . use_count , I1i11iiIiIi . key_id , i111IiIi1 )
    i1iIII1IIi = ""
    if 24 - 24: II111iiii - i11iIiiIii * i1IIi . ooOoO0o
    if 42 - 42: I11i / i11iIiiIii
  I1i1iii += lisp_table_footer ( )
  if 7 - 7: I11i
 return ( I1i1iii )
 if 50 - 50: i11iIiiIii . i11iIiiIii * i1IIi / i11iIiiIii . i1IIi - II111iiii
 if 72 - 72: iIii1I11I1II1 / o0oOOo0O0Ooo . I1ii11iIi11i
 if 78 - 78: iIii1I11I1II1 . i11iIiiIii % IiII * Ii1I + iII111i - iIii1I11I1II1
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
