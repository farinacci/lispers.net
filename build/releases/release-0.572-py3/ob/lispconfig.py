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
 ooo0 = False
 if ( len ( I1IiIiiIiIII ) != 0 ) :
  ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
  if ( ooo0 ) :
   lisp . lprint ( "Command syntax error: {}" . format ( IIiIiiii ) )
  else :
   iiIii1I ( I1IiIiiIiIII )
   if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
 else :
  if ( iiii1I1 ) : I1IiIiiIiIII = IIIiIiI11iIi
  IIiIiiii = iiIii1I ( I1IiIiiIiIII )
  if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
  if 51 - 51: OoOoOO00
 I11IIIiIi11 = lisp . lisp_command_ipc ( IIiIiiii , process )
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
 if ( IiIi1 [ 1 ] == "" ) :
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
 OOOii1i1iiI = lisp . lisp_button ( "ddt-root.org" , "http://ddt-root.net" )
 Oo0oOo0ooOOOo = lisp . lisp_button ( "LISP Facebook Group" ,
 "https://www.facebook.com/groups/407716795982512" )
 OoO0000o = lisp . lisp_button ( "LISP LinkedIn Group" ,
 "http://www.linkedin.com/groups/3776183" )
 if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
 I1IIi1I = lisp . lisp_space ( 2 )
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

    ''' . format ( I1IIi1I , Ii , I1IIi1I , I1 , I1IIi1I , i11i11 , I1IIi1I , I1IIi1I , I1I1 , I1IIi1I , O0oo0O0 , I1IIi1I , iI1IiiiIiI1Ii , I1IIi1I ,
 iI1i1II , iI1i1II , I1ii1ii1I , Ii1I1I1i11ii , i111i , II1III1i1iiI , I11i11i1 , OOOii1i1iiI , Oo0oOo0ooOOOo , OoO0000o )
 if 14 - 14: oO0o + O0 / IiII
 return ( lisp_show_wrapper ( I1i1iii ) )
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
  oO0O = "python -O "
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
 ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 96 - 96: OoooooooOO + IiII * O0
 if 86 - 86: Ii1I
 if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 if ( ooo0 == True ) : return ( IIiIiiii )
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
 return ( IIiIiiii )
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
 ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if ( ooo0 == True ) : return ( IIiIiiii )
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
 return ( IIiIiiii )
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
 ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 if ( ooo0 == False ) :
  IIiIiiii = lisp_replace_password_in_clause ( IIiIiiii , "password =" )
  if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 return ( IIiIiiii )
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
 ooo0 , IIiIiiii , I1IiIiiIiIII = lisp_syntax_check ( I1IiIiiIiIII , clause )
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 if ( ooo0 ) : return ( IIiIiiii )
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 lisp . lisp_ms_rtr_list = [ ]
 if ( "address" in I1IiIiiIiIII ) :
  for Ii1I1i in I1IiIiiIiIII [ "address" ] :
   II = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
   II . store_address ( Ii1I1i )
   lisp . lisp_ms_rtr_list . append ( II )
   if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
   if 69 - 69: ooOoO0o % ooOoO0o
 return ( IIiIiiii )
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
 if 33 - 33: Ii1I
 if 93 - 93: ooOoO0o
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
def lisp_process_command_lines ( lisp_socket , old , new , line ) :
 I111i1I1 = line . split ( "{" )
 I111i1I1 = I111i1I1 [ 0 ]
 I111i1I1 = I111i1I1 [ 0 : - 1 ]
 if 19 - 19: I1ii11iIi11i
 lisp . lprint ( "Process the '{}' command" . format ( I111i1I1 ) )
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if 66 - 66: O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if ( I111i1I1 not in lisp_commands ) :
  line = "#>>> " + line . replace ( "\n" , " <<< invalid command\n" )
  new . write ( line )
  return
  if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
  if 28 - 28: iIii1I11I1II1
  if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
  if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
  if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 I1iI1I1ii1 = lisp_commands [ I111i1I1 ]
 iIIi1 = False
 for O0O00OooO in I1iI1I1ii1 :
  if ( O0O00OooO == "" ) :
   line = lisp_write_error ( line , "invalid command" )
   new . write ( line )
   return
   if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
   if 92 - 92: OoOoOO00 % O0
  if ( iIIi1 == False ) :
   oo00ooooOOo00 = line
   III11I1 = 1
   for line in old :
    if ( lisp_begin_clause ( line ) ) : III11I1 += 1
    oo00ooooOOo00 += line
    if ( lisp_end_clause ( line ) ) :
     III11I1 -= 1
     if ( III11I1 == 0 ) : break
     if 16 - 16: i11iIiiIii / i1IIi % OOooOOo
     if 84 - 84: I11i - Oo0Ooo * O0 / Ii1I . Ii1I
     if 93 - 93: O0 / ooOoO0o + I1IiiI
     if 20 - 20: IiII / iII111i % OoooooooOO / iIii1I11I1II1 + I1IiiI
     if 57 - 57: o0oOOo0O0Ooo / I1Ii111
     if 13 - 13: OoooooooOO + OoO0O00
     if 32 - 32: O0 + oO0o % Oo0Ooo
  if ( lisp . lisp_is_running ( O0O00OooO ) == False ) :
   if ( iIIi1 == False ) :
    for line in oo00ooooOOo00 : new . write ( line )
    iIIi1 = True
    if 7 - 7: I1ii11iIi11i / ooOoO0o
   lisp . lprint ( "Process '{}' is not running, do not send command" . format ( O0O00OooO ) )
   if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
   continue
   if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
   if 65 - 65: ooOoO0o - i1IIi
   if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
   if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
   if 34 - 34: I1Ii111 - OOooOOo
   if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
  if ( O0O00OooO == "lisp-core" ) :
   if ( oo00ooooOOo00 . find ( "enable" ) != - 1 ) :
    IIiIiiii = lisp_enable_command ( oo00ooooOOo00 )
    if 64 - 64: i1IIi
   if ( oo00ooooOOo00 . find ( "debug" ) != - 1 ) :
    IIiIiiii = lisp_debug_command ( lisp_socket , oo00ooooOOo00 , None )
    if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
   if ( oo00ooooOOo00 . find ( "user-account" ) != - 1 ) :
    IIiIiiii = lisp_user_account_command ( oo00ooooOOo00 )
    if 25 - 25: II111iiii / OoO0O00
   if ( oo00ooooOOo00 . find ( "rtr-list" ) != - 1 ) :
    IIiIiiii = lisp_rtr_list_command ( oo00ooooOOo00 )
    if 64 - 64: O0 % ooOoO0o
  else :
   I11IIIiIi11 = lisp . lisp_command_ipc ( oo00ooooOOo00 , "lisp-core" )
   lisp . lisp_ipc ( I11IIIiIi11 , lisp_socket , O0O00OooO )
   lisp . lprint ( "Waiting for response to config command '{}'" . format ( I111i1I1 ) )
   if 40 - 40: o0oOOo0O0Ooo + I11i
   if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
   iIiiIIi1iiII , oooO00Oo , ooO00o , IIiIiiii = lisp . lisp_receive ( lisp_socket ,
 True )
   if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
   if ( oooO00Oo == "" ) :
    lisp . lprint ( "Command timed out to {}" . format ( O0O00OooO ) )
    IIiIiiii = oo00ooooOOo00
   elif ( oooO00Oo != O0O00OooO ) :
    lisp . lprint ( "Fatal IPC error to {}, source {}" . format ( O0O00OooO ,
 oooO00Oo ) )
    if 47 - 47: OoooooooOO
   IIiIiiii = IIiIiiii . decode ( )
   if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
   if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
   if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
   if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
   if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
   if 26 - 26: OOooOOo * Oo0Ooo
  if ( iIIi1 == False ) :
   for line in IIiIiiii : new . write ( line )
   iIIi1 = True
   if 31 - 31: I11i * oO0o . Ii1I
   if 35 - 35: I11i
 return
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo
def lisp_process_config_file ( lisp_socket , file_name , startup ) :
 lisp . lprint ( "Processing configuration file {}" . format ( file_name ) )
 if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
 if ( os . path . exists ( file_name ) == False ) :
  lisp . lprint ( "LISP configuration file '{}' does not exist" . format ( file_name ) )
  if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
  return
  if 37 - 37: iII111i
  if 33 - 33: OoO0O00 - O0 - OoO0O00
 O000oooOO0Oo0 = file_name + ".diff"
 I1iIiIii = file_name + ".bak"
 OO0 = file_name + ".temp"
 I1iiI1iiI1i1 = "# lispers.net lisp.config file"
 if 88 - 88: oO0o % Oo0Ooo - I11i % oO0o + IiII - iII111i
 if 23 - 23: O0
 if 9 - 9: I11i * Oo0Ooo . ooOoO0o * i11iIiiIii - O0
 if 54 - 54: I1IiiI * OOooOOo + o0oOOo0O0Ooo % i1IIi - o0oOOo0O0Ooo + OoOoOO00
 if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 OOO = 'egrep "{}" {}' . format ( I1iiI1iiI1i1 , file_name )
 OooOo0OOO = getoutput ( OOO )
 if ( OooOo0OOO == "" ) :
  lisp . lprint ( "*** lisp.config configuration file is corrupt ***" )
  return
  if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
  if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
  if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
  if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
  if 46 - 46: iIii1I11I1II1
  if 70 - 70: i1IIi . I11i
 oO00o0O00o = open ( file_name , "r" )
 o0 = open ( OO0 , "w" )
 for OOo00OoO in oO00o0O00o :
  if ( OOo00OoO . find ( I1iiI1iiI1i1 ) == 0 ) :
   if ( startup ) :
    o0 . write ( OOo00OoO )
   else :
    lisp_write_last_changed_date ( o0 , OOo00OoO )
    if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
   continue
   if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
   if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
  if ( OOo00OoO . find ( "# Hostname:" ) == 0 ) :
   o0 . write ( "# Hostname: " + lisp . lisp_hostname + "\n" )
   continue
   if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
   if 58 - 58: O0
  if ( lisp_end_file ( OOo00OoO ) ) :
   o0 . write ( OOo00OoO + "\n" )
   break
   if 91 - 91: iII111i / I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I1ii11iIi11i
   if 72 - 72: Ii1I . IiII * I1ii11iIi11i / I1ii11iIi11i / iII111i
  if ( lisp_comment ( OOo00OoO ) ) :
   o0 . write ( OOo00OoO )
   continue
   if 13 - 13: i1IIi
   if 17 - 17: i11iIiiIii * o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoO0O00
  o0O0O = OOo00OoO . replace ( " " , "" )
  o0O0O = o0O0O . replace ( "\n" , "" )
  if ( o0O0O == "" ) : continue
  if 45 - 45: o0oOOo0O0Ooo % Oo0Ooo * i1IIi - O0
  if 82 - 82: II111iiii / iII111i
  if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
  if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
  lisp_process_command_lines ( lisp_socket , oO00o0O00o , o0 , OOo00OoO )
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 oO00o0O00o . close ( )
 o0 . close ( )
 if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: oO0o
 if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
 if 97 - 97: I1Ii111 . I11i / I1IiiI
 if ( os . path . exists ( O000oooOO0Oo0 ) == False ) :
  os . system ( "touch {}" . format ( O000oooOO0Oo0 ) )
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
 if ( startup == False ) :
  os . system ( "diff {} {} > {}" . format ( I1iIiIii , OO0 , O000oooOO0Oo0 ) )
  if 90 - 90: Oo0Ooo * I1IiiI
  if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
  if 28 - 28: IiII * I1IiiI % IiII
  if 95 - 95: O0 / I11i . I1Ii111
  if 17 - 17: I11i
 os . system ( "cp {} {}; rm -f {}; cp {} {}" . format ( OO0 , file_name ,
 OO0 , file_name , I1iIiIii ) )
 return
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
def lisp_send_commands ( lisp_socket , process ) :
 iiIiIiIiiIiI = "./lisp.config"
 iIi1i = open ( iiIiIiIiiIiI , "r" )
 IIIIiiI = False
 OoO = 0
 if 67 - 67: I1ii11iIi11i + Ii1I
 if 72 - 72: IiII % o0oOOo0O0Ooo
 if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
 if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
 for OOo00OoO in iIi1i :
  if ( lisp_end_file ( OOo00OoO ) ) : break
  if ( lisp_comment ( OOo00OoO ) or OOo00OoO [ 0 ] == "\n" ) : continue
  if 52 - 52: IiII % ooOoO0o
  if ( lisp_begin_clause ( OOo00OoO ) ) :
   if ( OoO == 0 ) :
    oo00ooooOOo00 = ""
    I111i1I1 = OOo00OoO . split ( "{" )
    I111i1I1 = I111i1I1 [ 0 ]
    I111i1I1 = I111i1I1 [ 0 : - 1 ]
    if ( I111i1I1 in lisp_commands ) :
     IIIIiiI = ( process in lisp_commands [ I111i1I1 ] ) or ( I111i1I1 == "lisp debug" )
     if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
     if 23 - 23: i11iIiiIii
     if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
   OoO += 1
   if 65 - 65: II111iiii / Oo0Ooo
   if 42 - 42: i11iIiiIii . O0
   if 75 - 75: I1Ii111 + iIii1I11I1II1
   if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
   if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
  if ( IIIIiiI ) : oo00ooooOOo00 += OOo00OoO
  if 92 - 92: I11i / O0 * I1IiiI - I11i
  if 99 - 99: i11iIiiIii % OoooooooOO
  if 56 - 56: IiII * I1Ii111
  if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
  if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
  if ( lisp_end_clause ( OOo00OoO ) == False ) : continue
  OoO -= 1
  if ( OoO != 0 ) : continue
  if ( IIIIiiI == False ) : continue
  if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
  if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
  if 56 - 56: i1IIi . i11iIiiIii
  if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
  if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
  if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
  lisp . lprint ( "Send command '{}' to restarting process '{}'" . format ( I111i1I1 , process ) )
  if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
  if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
  if 10 - 10: IiII / OoooooooOO
  if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
  if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
  if 25 - 25: iIii1I11I1II1
  if ( I111i1I1 == "lisp debug" ) :
   lisp_debug_command ( lisp_socket , oo00ooooOOo00 , process )
   IIIIiiI = False
   continue
   if 63 - 63: ooOoO0o
   if 96 - 96: I11i
  oo00ooooOOo00 = lisp . lisp_command_ipc ( oo00ooooOOo00 , "lisp-core" )
  lisp . lisp_ipc ( oo00ooooOOo00 , lisp_socket , process )
  if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
  if 63 - 63: iII111i
  if 11 - 11: iII111i - iIii1I11I1II1
  if 92 - 92: OoO0O00
  if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
  lisp . lprint ( "Waiting for response to config command '{}'" . format ( I111i1I1 ) )
  if 12 - 12: ooOoO0o
  if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
  iIiiIIi1iiII , oooO00Oo , ooO00o , O0o = lisp . lisp_receive ( lisp_socket , True )
  if 82 - 82: I1Ii111 . I1Ii111 - iII111i
  if ( oooO00Oo == "" ) :
   lisp . lprint ( "Command timed out to {}" . format ( process ) )
  elif ( oooO00Oo != process ) :
   lisp . lprint ( "Fatal IPC error to {}, IPC source {}" . format ( process ,
 oooO00Oo ) )
   if 72 - 72: i11iIiiIii
  IIIIiiI = False
  if 94 - 94: OOooOOo
 return
 if 33 - 33: Ii1I % O0 + I1ii11iIi11i
 if 96 - 96: ooOoO0o . OoooooooOO
 if 39 - 39: OOooOOo + OoO0O00
 if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
 if 71 - 71: ooOoO0o . i11iIiiIii
 if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
 if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
def lisp_config_process ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 iiIiIiIiiIiI = "./lisp.config"
 o0oOooO0oo00 = ""
 oO00oo = True
 if 89 - 89: Ii1I
 while ( True ) :
  oO0OOoO0 = os . path . getmtime ( iiIiIiIiiIiI )
  if ( oO0OOoO0 != o0oOooO0oo00 ) :
   if 51 - 51: iII111i
   lisp . lisp_ipc_lock . acquire ( )
   lisp_process_config_file ( lisp_socket , iiIiIiIiiIiI , oO00oo )
   lisp . lisp_ipc_lock . release ( )
   if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
   oO00oo = False
   o0oOooO0oo00 = os . path . getmtime ( iiIiIiIiiIiI )
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
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  if ( IiII1II11I == "mr-name" ) :
   OO0o0o0oo = kv_pair [ IiII1II11I ] [ 0 ]
   continue
   if 47 - 47: OoOoOO00
  if ( IiII1II11I == "address" or IiII1II11I == "dns-name" ) :
   Oo0000o = kv_pair [ IiII1II11I ]
   for oo00oO0O0 in Oo0000o :
    if ( oo00oO0O0 == "" ) : continue
    Ii1I1i = oo00oO0O0 if ( IiII1II11I == "address" ) else None
    iI1IiiiIIiiII = oo00oO0O0 if ( IiII1II11I == "dns-name" ) else None
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
 if ( lisp_clause_syntax_error ( kv_pair , "eid-prefix" , "prefix" ) ) : return
 for i11Ii1 in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  I11IIIII = lisp . lisp_mapping ( "" , "" , [ ] )
  IIo0oo0OO . append ( I11IIIII )
  if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
  if 44 - 44: I1Ii111 - IiII
 OOOi1iIIiiIiII = [ ]
 if ( "address" in kv_pair ) :
  if ( lisp_clause_syntax_error ( kv_pair , "address" , "rloc" ) ) : return
  for i11Ii1 in range ( len ( kv_pair [ "address" ] ) ) :
   i11 = lisp . lisp_rloc ( )
   OOOi1iIIiiIiII . append ( i11 )
   if 42 - 42: I11i % Oo0Ooo . II111iiii / II111iiii * iII111i
   if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
   if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if ( IiII1II11I == "instance-id" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I11IIIII = IIo0oo0OO [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO == "" ) : OoO0o0OO = "0"
    I11IIIII . eid . instance_id = int ( OoO0o0OO )
    I11IIIII . group . instance_id = int ( OoO0o0OO )
    if 10 - 10: oO0o - iII111i % II111iiii - I1Ii111 - i1IIi
    if 10 - 10: I1ii11iIi11i - I11i . I1Ii111
  if ( IiII1II11I == "eid-prefix" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I11IIIII = IIo0oo0OO [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) : I11IIIII . eid . store_prefix ( OoO0o0OO )
    if 8 - 8: iIii1I11I1II1 % oO0o + Oo0Ooo
    if 24 - 24: o0oOOo0O0Ooo / Ii1I / Ii1I % II111iiii - oO0o * oO0o
  if ( IiII1II11I == "group-prefix" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I11IIIII = IIo0oo0OO [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) : I11IIIII . group . store_prefix ( OoO0o0OO )
    if 58 - 58: OoOoOO00
    if 60 - 60: II111iiii
  if ( IiII1II11I == "send-map-request" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I11IIIII = IIo0oo0OO [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO == "yes" ) : I11IIIII . action = lisp . LISP_SEND_MAP_REQUEST_ACTION
    if 90 - 90: OoOoOO00
    if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  if ( IiII1II11I == "subscribe-request" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I11IIIII = IIo0oo0OO [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO == "yes" ) : I11IIIII . action = lisp . LISP_SEND_PUBSUB_ACTION
    if 18 - 18: OoooooooOO
    if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
  if ( IiII1II11I == "rle-name" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) :
     i11 . rle_name = OoO0o0OO
     if ( OoO0o0OO in lisp . lisp_rle_list ) :
      i11 . rle = lisp . lisp_rle_list [ OoO0o0OO ]
      if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
      if 94 - 94: ooOoO0o + I1IiiI
      if 56 - 56: OoOoOO00 % o0oOOo0O0Ooo
      if 40 - 40: OOooOOo / IiII
  if ( IiII1II11I == "elp-name" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) :
     i11 . elp_name = OoO0o0OO
     if ( OoO0o0OO in lisp . lisp_elp_list ) :
      i11 . elp = lisp . lisp_elp_list [ OoO0o0OO ]
      i11 . elp . select_elp_node ( )
      if 29 - 29: Ii1I - Ii1I / ooOoO0o
      if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
      if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
      if 18 - 18: Oo0Ooo % O0
  if ( IiII1II11I == "rloc-record-name" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) : i11 . rloc_name = OoO0o0OO
    if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
    if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
    if 86 - 86: IiII
  if ( IiII1II11I == "priority" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO == "" ) : OoO0o0OO = "0"
    i11 . priority = int ( OoO0o0OO )
    if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
    if 33 - 33: II111iiii - IiII - ooOoO0o
  if ( IiII1II11I == "weight" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO == "" ) : OoO0o0OO = "0"
    i11 . weight = int ( OoO0o0OO )
    if 92 - 92: OoO0O00 * IiII
    if 92 - 92: oO0o
  if ( IiII1II11I == "address" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) : i11 . rloc . store_address ( OoO0o0OO )
    if 7 - 7: iII111i
    if 73 - 73: OoO0O00 % I1ii11iIi11i
    if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
    if 62 - 62: i11iIiiIii
    if 2 - 2: I1IiiI
    if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
    if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
    if 14 - 14: IiII . IiII % ooOoO0o
 for I11IIIII in IIo0oo0OO :
  I11IIIII . rloc_set = OOOi1iIIiiIiII
  I11IIIII . build_best_rloc_set ( )
  I11IIIII . add_cache ( )
  OOOi1iIIiiIiII = copy . deepcopy ( OOOi1iIIiiIiII )
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
 return
 if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
 if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
 if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
 if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
 if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 6 - 6: oO0o . I11i
 if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
def lisp_display_map_cache ( mc , output ) :
 oO0OOoO0 = lisp . lisp_print_elapsed ( mc . uptime )
 OOOO0oo0 = mc . print_eid_tuple ( )
 Iiii = "Recent Sources: "
 Iiii += "none\n" if ( mc . recent_sources == { } ) else "\n"
 for I1IIi1I in mc . recent_sources :
  iI1iiiiiii = mc . recent_sources [ I1IIi1I ]
  Iiii += "  " + I1IIi1I + ": " + lisp . lisp_print_elapsed ( iI1iiiiiii ) + "\n"
  if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
 OOOO0oo0 = lisp . lisp_span ( OOOO0oo0 , Iiii [ 0 : - 1 ] )
 OO0iiiii1iiIIii = mc . action
 if 8 - 8: I1ii11iIi11i * I1ii11iIi11i * i1IIi + iII111i . I1ii11iIi11i
 if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
 if 37 - 37: Oo0Ooo
 if 72 - 72: IiII % I1ii11iIi11i * OOooOOo . i11iIiiIii % IiII * OOooOOo
 if 15 - 15: I11i / Oo0Ooo * I11i
 if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
 oooO00Oo = mc . mapping_source
 if ( oooO00Oo == None ) :
  oooO00Oo = "map-notify"
 else :
  oooO00Oo = "static" if oooO00Oo . is_null ( ) else oooO00Oo . print_address_no_iid ( )
  if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
  if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
  if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
 if ( mc . checkpoint_entry ) : oooO00Oo = "checkpoint"
 if ( mc . gleaned ) : oooO00Oo = "gleaned"
 iiiIIiiIi = mc . print_ttl ( )
 if 86 - 86: OoooooooOO % II111iiii . OoooooooOO * I1ii11iIi11i
 OO0iiiii1iiIIii = "encapsulate" if OO0iiiii1iiIIii == lisp . LISP_NO_ACTION else lisp . lisp_map_reply_action_string [ OO0iiiii1iiIIii ]
 if 9 - 9: Oo0Ooo + iII111i
 if 64 - 64: O0 * I1IiiI / I1IiiI
 if ( len ( mc . rloc_set ) == 0 ) :
  OO0oo = mc . stats . get_stats ( True , True )
  output += lisp_table_row ( OOOO0oo0 , oO0OOoO0 + "<br>" + iiiIIiiIi , "--" , oooO00Oo ,
 OO0oo , OO0iiiii1iiIIii , "--" )
  return ( [ True , output ] )
  if 56 - 56: I1ii11iIi11i . oO0o
  if 55 - 55: OoO0O00 * OoO0O00 . I1IiiI
 for i11 in mc . rloc_set :
  OOOOoO0 = ""
  if ( i11 . rloc_exists ( ) ) :
   if ( i11 . rloc . is_null ( ) == False ) :
    OOOOoO0 += i11 . rloc . print_address_no_iid ( ) + "<br>"
    Iiii = ""
    IiiIiIIi1 = lisp . lisp_nonce_echoing and i11 . echo_nonce_capable
    if ( lisp . lisp_rloc_probing ) :
     Iiii += i11 . print_rloc_probe_state ( IiiIiIIi1 )
     if 40 - 40: iII111i . OoOoOO00 * O0
    if ( IiiIiIIi1 ) :
     IIiiIii11 = lisp . lisp_get_echo_nonce ( i11 . rloc , None )
     if ( IIiiIii11 ) : Iiii += IIiiIii11 . print_echo_nonce ( )
     if 74 - 74: i1IIi
    if ( Iiii != "" ) : OOOOoO0 = lisp . lisp_span ( OOOOoO0 , Iiii )
    if 15 - 15: i1IIi + IiII % I1IiiI / i11iIiiIii * OoOoOO00
    if 69 - 69: i11iIiiIii
    if 61 - 61: O0
  if ( i11 . translated_port != 0 ) :
   OOOOoO0 += "encap-port: {}<br>" . format ( i11 . translated_port )
   if 21 - 21: OoO0O00 % iIii1I11I1II1 . OoO0O00
   if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
  if ( i11 . rloc_name ) :
   OOOOoO0 += "rloc-name: {}<br>" . format ( lisp . blue ( i11 . rloc_name ,
 True ) )
   if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
   if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
  if ( i11 . geo ) :
   OOOOoO0 += "geo: {}<br>" . format ( i11 . geo . print_geo_url ( ) )
   if 31 - 31: oO0o * I1Ii111 . OoOoOO00 * I11i
  if ( i11 . elp ) :
   I1II1I = i11 . elp . print_elp ( True )
   OOOOoO0 += "elp: {}<br>" . format ( I1II1I )
   if 7 - 7: I11i + I11i + II111iiii % Ii1I
  if ( i11 . rle ) :
   iIIIII11Iii1 = i11 . rle . print_rle ( True , True )
   OOOOoO0 += "rle: {}<br>" . format ( iIIIII11Iii1 )
   if 35 - 35: i11iIiiIii + OoooooooOO * iIii1I11I1II1 . I1Ii111
  if ( i11 . json ) :
   if ( lisp . lisp_is_json_telemetry ( i11 . json . json_string ) == None ) :
    oOO00O0Ooooo00 = "json: { ... }<br>"
    OOOOoO0 += lisp . lisp_span ( oOO00O0Ooooo00 , i11 . json . print_json ( False ) )
    if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
    if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
    if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
    if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
    if 55 - 55: OoooooooOO
    if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
  OO0oo = i11 . stats . get_stats ( True , True )
  if 38 - 38: O0
  if 79 - 79: i1IIi . oO0o
  if 34 - 34: I1Ii111 * II111iiii
  if 71 - 71: IiII
  o00OOo0o = ""
  IiIiI = i11
  while ( True ) :
   o00O0oo0 = lisp . lisp_print_elapsed ( IiIiI . last_state_change )
   if ( o00O0oo0 == "never" ) :
    o00O0oo0 = lisp . lisp_print_elapsed ( IiIiI . uptime )
    if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
   I1IIi1I = IiIiI . print_state ( )
   if ( IiIiI . unreach_state ( ) or IiIiI . no_echoed_nonce_state ( ) ) :
    I1IIi1I = lisp . red ( I1IIi1I , True )
    if 28 - 28: i11iIiiIii
   o00OOo0o += I1IIi1I + " since " + o00O0oo0
   if 51 - 51: I1IiiI + ooOoO0o * O0 . Ii1I
   if ( lisp . lisp_rloc_probing ) :
    O00Oo00OOoO0 = IiIiI . print_rloc_probe_rtt ( )
    if ( O00Oo00OOoO0 != "none" ) :
     o00OOo0o += "<br>rtt: {}, hops: {}, latency: {}" . format ( O00Oo00OOoO0 , IiIiI . print_rloc_probe_hops ( ) ,
     # OoooooooOO + O0 + I1ii11iIi11i / I11i / Ii1I * I1ii11iIi11i
 IiIiI . print_rloc_probe_latency ( ) )
     if 100 - 100: I11i
     if 82 - 82: iIii1I11I1II1
     if 19 - 19: I1IiiI
   if ( lisp . lisp_rloc_probing and IiIiI . rloc_next_hop != None ) :
    OOoOOo00O0o0 , oOOoo = IiIiI . rloc_next_hop
    o00OOo0o += "<br>{}nh {}({}) " . format ( lisp . lisp_space ( 2 ) , oOOoo , OOoOOo00O0o0 )
    if 26 - 26: I11i + I1Ii111 + I11i / I1Ii111
    if 79 - 79: o0oOOo0O0Ooo - II111iiii
   IiIiI = IiIiI . next_rloc
   if ( IiIiI == None ) : break
   o00OOo0o += "<br>"
   if 70 - 70: I1Ii111 . oO0o % i1IIi / iIii1I11I1II1
   if 98 - 98: i1IIi % Oo0Ooo
  if ( OO0iiiii1iiIIii == "encapsulate" ) :
   ooO00o = lisp . LISP_DATA_PORT
   if ( lisp . lisp_i_am_rtr and i11 . translated_port != 0 ) :
    ooO00o = i11 . translated_port
    if 82 - 82: ooOoO0o
    if 70 - 70: iIii1I11I1II1 + i11iIiiIii + Oo0Ooo / iII111i
   Ii1I1i = i11 . rloc . print_address_no_iid ( ) + ":" + str ( ooO00o )
   if ( Ii1I1i in lisp . lisp_crypto_keys_by_rloc_encap ) :
    oo000O0o = lisp . lisp_crypto_keys_by_rloc_encap [ Ii1I1i ] [ 1 ]
    if ( oo000O0o != None and oo000O0o . shared_key != None ) :
     OO0iiiii1iiIIii = "encap-crypto-" + oo000O0o . cipher_suite_string
     if 9 - 9: OoOoOO00 - IiII
     if 39 - 39: i1IIi
     if 19 - 19: I1IiiI . I1IiiI - i11iIiiIii
     if 61 - 61: I1Ii111 * I1ii11iIi11i % I1IiiI % OoO0O00 % I11i + I11i
  output += lisp_table_row ( OOOO0oo0 , oO0OOoO0 + "<br>" + iiiIIiiIi , OOOOoO0 , oooO00Oo ,
 OO0oo , o00OOo0o + "<br>" + OO0iiiii1iiIIii ,
 str ( i11 . priority ) + "/" + str ( i11 . weight ) + "<br>" + str ( i11 . mpriority ) + "/" + str ( i11 . mweight ) )
  if 6 - 6: Oo0Ooo
  if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
  if ( OOOO0oo0 != "" ) : OOOO0oo0 = ""
  if ( oO0OOoO0 != "" ) : oO0OOoO0 , iiiIIiiIi , oooO00Oo = ( "" , "" , "" )
  if 93 - 93: i11iIiiIii
 return ( [ True , output ] )
 if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
 if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
 if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
 if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
 if 58 - 58: I11i
 if 7 - 7: II111iiii / IiII % I11i + I1IiiI - O0
 if 45 - 45: I1IiiI / iII111i + oO0o + IiII
 if 15 - 15: I1IiiI % OoO0O00
def lisp_walk_map_cache ( mc , output ) :
 if 66 - 66: oO0o * i11iIiiIii . I1Ii111
 if 92 - 92: oO0o
 if 81 - 81: o0oOOo0O0Ooo % I1IiiI - iII111i / i11iIiiIii
 if 73 - 73: O0 * I1Ii111 . i1IIi
 if ( mc . group . is_null ( ) ) : return ( lisp_display_map_cache ( mc , output ) )
 if 51 - 51: OoO0O00 - iII111i % O0 - OoOoOO00
 if ( mc . source_cache == None ) : return ( [ True , output ] )
 if 53 - 53: iII111i / i1IIi / i1IIi
 if 77 - 77: I11i + i1IIi . I11i
 if 89 - 89: o0oOOo0O0Ooo + OOooOOo * oO0o
 if 45 - 45: iII111i - o0oOOo0O0Ooo . Ii1I
 if 41 - 41: II111iiii . I1IiiI / OoO0O00 . ooOoO0o
 output = mc . source_cache . walk_cache ( lisp_display_map_cache , output )
 return ( [ True , output ] )
 if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
 if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
 if 36 - 36: I11i - IiII . IiII
 if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
 if 84 - 84: iIii1I11I1II1 + OoooooooOO
 if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
 if 10 - 10: I1ii11iIi11i + IiII
def lisp_show_myrlocs ( output ) :
 if ( lisp . lisp_myrlocs [ 2 ] == None ) :
  output += "No local RLOCs found"
 else :
  Ooooo00 = lisp . lisp_print_cour ( lisp . lisp_myrlocs [ 2 ] )
  oOOooooO = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 0 ] != None else "not found"
  if 89 - 89: ooOoO0o * Ii1I
  oOOooooO = lisp . lisp_print_cour ( oOOooooO )
  Oo0 = "-f inet" if lisp . lisp_is_macos ( ) else "-4"
  o0O0o0oo0O0O = getoutput ( "netstat -rn {}" . format ( Oo0 ) )
  oOOooooO = lisp . lisp_span ( oOOooooO , o0O0o0oo0O0O )
  if 84 - 84: I11i . iII111i
  i111ii1iIiII11i1 = lisp . lisp_myrlocs [ 1 ] . print_address_no_iid ( ) if lisp . lisp_myrlocs [ 1 ] != None else "not found"
  if 44 - 44: I1IiiI % OOooOOo * i11iIiiIii * i11iIiiIii - Oo0Ooo . I1Ii111
  i111ii1iIiII11i1 = lisp . lisp_print_cour ( i111ii1iIiII11i1 )
  Oo0 = "-f inet6" if lisp . lisp_is_macos ( ) else "-6"
  o0O0o0oo0O0O = getoutput ( "netstat -rn {}" . format ( Oo0 ) )
  i111ii1iIiII11i1 = lisp . lisp_span ( i111ii1iIiII11i1 , o0O0o0oo0O0O )
  if 68 - 68: iII111i . I11i
  OOo00OoO = "<i>Local RLOCs found on interface </i>{}<i>, " + "IPv4: </i>{}<i>, IPv6: </i>{}"
  if 29 - 29: ooOoO0o * IiII
  output += lisp . lisp_print_sans ( OOo00OoO ) . format ( Ooooo00 , oOOooooO , i111ii1iIiII11i1 )
  if 75 - 75: O0
 output += "<br>"
 return ( output )
 if 56 - 56: OoO0O00 / II111iiii
 if 39 - 39: OoOoOO00 - OoooooooOO - i1IIi / II111iiii
 if 49 - 49: Oo0Ooo + O0 + IiII . II111iiii % ooOoO0o
 if 33 - 33: OoOoOO00 . iIii1I11I1II1 / I11i % Ii1I
 if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
 if 27 - 27: OoO0O00 + Oo0Ooo
 if 92 - 92: I1IiiI % iII111i
def lisp_display_nat_info ( output , dc , dodns ) :
 iiiI1IiI = len ( lisp . lisp_nat_state_info )
 if ( iiiI1IiI == 0 ) : return ( output )
 if 2 - 2: O0 % I1Ii111 % I1ii11iIi11i % o0oOOo0O0Ooo - Oo0Ooo
 Iiii = "{} entries in the NAT-traversal port table" . format ( iiiI1IiI )
 i1i11ii1 = lisp . lisp_span ( "NAT-Traversed xTR Information:" , Iiii )
 if 95 - 95: i11iIiiIii
 if ( dodns ) :
  output += lisp_table_header ( i1i11ii1 , "xTR Hostname" ,
 "Translated<br>Address" , "Translated<br>{} Port" . format ( dc ) ,
 "Last<br>Info-Request" , "NAT DNS Name" )
 else :
  output += lisp_table_header ( i1i11ii1 , "xTR Hostname" ,
 "Translated<br>Address" , "Translated<br>{} Port" . format ( dc ) ,
 "Last<br>Info-Request" )
  if 95 - 95: Oo0Ooo
  if 49 - 49: I1IiiI
 for Iii1 in list ( lisp . lisp_nat_state_info . values ( ) ) :
  for oooo00Oo0O in Iii1 :
   II = oooo00Oo0O . address
   OO = oooo00Oo0O . uptime
   O0I11i1i11i1I = oooo00Oo0O . hostname
   ooO00o = oooo00Oo0O . port
   if 16 - 16: OoooooooOO % I1IiiI - o0oOOo0O0Ooo / II111iiii . i1IIi
   if ( oooo00Oo0O . timed_out ( ) ) :
    OO = lisp . red ( lisp . lisp_print_elapsed ( OO ) , True )
   else :
    OO = lisp . lisp_print_elapsed ( OO )
    if 27 - 27: II111iiii + ooOoO0o . OoOoOO00 - I1Ii111
    if 54 - 54: OoOoOO00 . Oo0Ooo
   if ( dodns ) :
    try :
     Ii1 = socket . gethostbyaddr ( II ) [ 0 ]
    except :
     Ii1 = "?"
     if 40 - 40: I1ii11iIi11i + oO0o
    output += lisp_table_row ( O0I11i1i11i1I , II , ooO00o , OO , Ii1 )
   else :
    output += lisp_table_row ( O0I11i1i11i1I , II , ooO00o , OO )
    if 34 - 34: O0 * IiII / i1IIi + oO0o . OoOoOO00
    if 73 - 73: Ii1I / I1IiiI / OoooooooOO + I1IiiI
    if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
    if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
 output += lisp_table_footer ( )
 return ( output )
 if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
 if 98 - 98: OoO0O00
 if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
 if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
 if 52 - 52: I1Ii111 + I1Ii111
 if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
 if 54 - 54: OoOoOO00 . OoooooooOO
def lisp_itr_rtr_show_command ( parameter , itr_or_rtr , lisp_threads , dns = False ) :
 if 36 - 36: oO0o / II111iiii * IiII % I1ii11iIi11i
 if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
 if 28 - 28: Ii1I . I1ii11iIi11i
 if 77 - 77: I1ii11iIi11i % II111iiii
 if ( parameter != "" ) :
  return ( lisp_show_map_cache_lookup ( parameter ) )
  if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
  if 90 - 90: o0oOOo0O0Ooo
 I1i1iii = ""
 if 44 - 44: o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo + OoOoOO00
 if 32 - 32: IiII - ooOoO0o * iII111i * I11i
 if 84 - 84: Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
 if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
 I1i1iii = lisp_show_myrlocs ( I1i1iii )
 if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
 if 1 - 1: Oo0Ooo . II111iiii
 if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
 if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
 if ( itr_or_rtr == "RTR" ) :
  I1i1iii = lisp_show_decap_stats ( I1i1iii , itr_or_rtr )
  if 4 - 4: IiII
  if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
  if 99 - 99: i11iIiiIii - iII111i
  if 85 - 85: I1Ii111 % I1ii11iIi11i
  if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
 if ( len ( lisp_threads ) > 1 ) :
  I1IIi1I = [ ]
  for i11Ii1 in range ( len ( lisp_threads ) ) :
   iI1iiiiiii = lisp_threads [ i11Ii1 ]
   I1IIi1I . append ( "{} Input Stats<br>queue-size: {}" . format ( iI1iiiiiii . thread_name ,
 iI1iiiiiii . input_queue . qsize ( ) ) )
   if 73 - 73: OoO0O00
  I1i1iii += lisp_table_header ( "LISP-RTR Forwarding Stats:" , * I1IIi1I )
  if 28 - 28: OoooooooOO - I11i
  I1IIi1I = [ ]
  for i11Ii1 in range ( len ( lisp_threads ) ) :
   iI1iiiiiii = lisp_threads [ i11Ii1 ]
   I1IIi1I . append ( iI1iiiiiii . input_stats . get_stats ( False , True ) )
   if 84 - 84: II111iiii
  I1i1iii += lisp_table_row ( * I1IIi1I )
  I1i1iii += lisp_table_footer ( )
  if 36 - 36: OOooOOo - OoOoOO00 - iIii1I11I1II1
  if 10 - 10: I1ii11iIi11i / Ii1I * i1IIi % O0 + I11i
 I1i1ii1ii = lisp . lisp_decent_dns_suffix
 if ( I1i1ii1ii == None ) :
  I1i1ii1ii = ":"
 else :
  I1i1ii1ii = "&nbsp;(dns-suffix '{}'):" . format ( I1i1ii1ii )
  if 32 - 32: IiII / OoooooooOO
  if 30 - 30: OoOoOO00 / I1IiiI - OoO0O00 - iII111i - i11iIiiIii
  if 84 - 84: i1IIi - I1IiiI % iII111i
  if 80 - 80: o0oOOo0O0Ooo % iII111i
  if 80 - 80: Ii1I
 Iiii = "{} map-resolvers configured" . format ( len ( lisp . lisp_map_resolvers_list ) )
 if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
 i1i11ii1 = "LISP-{} Configured Map-Resolvers{}" . format ( itr_or_rtr , I1i1ii1ii )
 i1i11ii1 = lisp . lisp_span ( i1i11ii1 , Iiii )
 if 59 - 59: I1ii11iIi11i + I11i . oO0o
 I1i1iii += lisp_table_header ( i1i11ii1 , "Map-Resolver" , "Last Used" ,
 "Map-Requests<br>Sent" , "Negative Map-Replies<br>Received" ,
 "Last Negative<br>Map-Reply" , "Average RTT" )
 if 87 - 87: OoO0O00
 for Oo0O0O000 in list ( lisp . lisp_map_resolvers_list . values ( ) ) :
  Oo0O0O000 . resolve_dns_name ( )
  OO0o0o0oo = "" if Oo0O0O000 . mr_name == "all" else Oo0O0O000 . mr_name + "<br>"
  Ii1I1i = OO0o0o0oo + Oo0O0O000 . map_resolver . print_address_no_iid ( )
  if ( Oo0O0O000 . dns_name ) : Ii1I1i += "<br>" + Oo0O0O000 . dns_name
  if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  oO0OOoO0 = lisp . lisp_print_elapsed ( Oo0O0O000 . last_used )
  II1iII1 = lisp . lisp_print_elapsed ( Oo0O0O000 . last_reply )
  I11II11IiI11 = 0 if Oo0O0O000 . neg_map_replies_received == 0 else float ( old_div ( Oo0O0O000 . total_rtt / Oo0O0O000 . neg_map_replies_received ) )
  if 97 - 97: ooOoO0o / iIii1I11I1II1 % ooOoO0o / I1IiiI * iII111i % OoOoOO00
  I11II11IiI11 = str ( round ( I11II11IiI11 , 3 ) ) + " ms"
  if 17 - 17: iIii1I11I1II1
  I1i1iii += lisp_table_row ( Ii1I1i , oO0OOoO0 , Oo0O0O000 . map_requests_sent ,
 Oo0O0O000 . neg_map_replies_received , II1iII1 , I11II11IiI11 )
  if 89 - 89: i1IIi . i1IIi
 I1i1iii += lisp_table_footer ( )
 if 10 - 10: iII111i % Oo0Ooo
 if 48 - 48: OOooOOo + I1Ii111 % OOooOOo
 if 84 - 84: O0 % Ii1I . Ii1I . iII111i * I11i
 if 43 - 43: OoOoOO00 . I1ii11iIi11i % i1IIi
 if ( itr_or_rtr == "ITR" ) : I1i1iii = lisp_show_db_list ( "ITR" , I1i1iii )
 if 61 - 61: I1IiiI + oO0o % I1Ii111 % iIii1I11I1II1 - OoooooooOO
 if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
 if 83 - 83: ooOoO0o
 if 43 - 43: OOooOOo
 O0OoOoo00o = "<br>Enter EID for Map-Cache lookup:"
 if 84 - 84: OOooOOo . IiII . iII111i
 iIII1I1i = lisp . lisp_eid_help_hover ( '<input type="text" name="eid" />' )
 if 26 - 26: iII111i - Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
 III1iI1Ii11Ii = itr_or_rtr . lower ( )
 if 29 - 29: OoOoOO00
 O0OoOoo00o = '''
         <form action="/lisp/show/{}/map-cache/lookup" method="post">
         <font size="3"><i>{}</i> {}
         <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form>
    ''' . format ( III1iI1Ii11Ii , lisp . lisp_print_sans ( O0OoOoo00o ) , iIII1I1i )
 if 37 - 37: II111iiii % II111iiii + o0oOOo0O0Ooo % Oo0Ooo / I1IiiI . oO0o
 o0i1I = '<a href="/lisp/show/{}/rloc-probing">RLOC State</a>' . format ( III1iI1Ii11Ii )
 if 44 - 44: OOooOOo * i1IIi
 OOOoOo0O0O = '<a href="/lisp/show/{}/keys"><br>RLOC Keys</a>' . format ( III1iI1Ii11Ii )
 if 99 - 99: I1Ii111
 if 75 - 75: ooOoO0o . OOooOOo / IiII
 if 84 - 84: OoooooooOO . I1IiiI / o0oOOo0O0Ooo
 if 86 - 86: Oo0Ooo % OoOoOO00
 o0o0O00oOo = os . path . exists ( "./show-ztr" )
 iI1ii = "Map-Cache"
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None or o0o0O00oOo ) :
  iI1ii = '<a href="/lisp/show/lisp-xtr">Map-Cache</a>'
  if 2 - 2: II111iiii . I11i
  if 83 - 83: I1IiiI - I1Ii111 + I1IiiI . I1IiiI
  if 45 - 45: i1IIi % OOooOOo % II111iiii
  if 4 - 4: oO0o * I1IiiI - ooOoO0o / II111iiii + OOooOOo / i11iIiiIii
  if 63 - 63: OoO0O00 + ooOoO0o
 Iiii = "{} entries in the map-cache" . format ( lisp . lisp_map_cache . cache_size ( ) )
 if 3 - 3: OoOoOO00 - I1Ii111 / oO0o . O0 * ooOoO0o / I1ii11iIi11i
 i1i11ii1 = "LISP-{} {}:{}" . format ( itr_or_rtr , iI1ii , lisp . lisp_space ( 4 ) )
 i1i11ii1 = lisp . lisp_span ( i1i11ii1 , Iiii )
 if 18 - 18: Ii1I
 if 74 - 74: Ii1I + I1ii11iIi11i + I1IiiI
 if 37 - 37: IiII
 if 97 - 97: o0oOOo0O0Ooo / IiII + OoOoOO00 + OoO0O00 % I1Ii111
 if 18 - 18: I1IiiI - OoOoOO00
 i1i11ii1 += lisp . lisp_button ( "clear cache" ,
 "/lisp/clear/{}/map-cache" . format ( itr_or_rtr . lower ( ) ) )
 i1i11ii1 += O0OoOoo00o
 if 18 - 18: OOooOOo + OoO0O00 * oO0o - oO0o . I1ii11iIi11i * I11i
 if 95 - 95: I1ii11iIi11i / OoOoOO00
 I1i1iii += lisp_table_header ( i1i11ii1 , "EID-Prefix or (S,G)" ,
 "Uptime<br>TTL" , "RLOC Record" + OOOoOo0O0O , "Map-Reply Source" ,
 "RLOC Send Stats" , o0i1I + "<br>RLOC Action" ,
 "Unicast Priority/Weight<br>Multicast Priority/Weight" )
 if 10 - 10: IiII % I1ii11iIi11i - IiII
 I1i1iii = lisp . lisp_map_cache . walk_cache ( lisp_walk_map_cache , I1i1iii )
 I1i1iii += lisp_table_footer ( )
 if 86 - 86: Oo0Ooo
 if 88 - 88: I1Ii111 * I1IiiI
 if 30 - 30: OoOoOO00 / oO0o / Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
 if 93 - 93: OoOoOO00
 if ( len ( lisp . lisp_elp_list ) != 0 ) : I1i1iii = lisp_show_elp_list ( I1i1iii )
 if 97 - 97: i11iIiiIii
 if 68 - 68: IiII * OoO0O00 . I11i / Ii1I . o0oOOo0O0Ooo - i11iIiiIii
 if 49 - 49: Oo0Ooo / Ii1I % I11i + oO0o - OoO0O00
 if 13 - 13: II111iiii
 if ( len ( lisp . lisp_rle_list ) != 0 ) : I1i1iii = lisp_show_rle_list ( I1i1iii )
 if 83 - 83: OoooooooOO . I1IiiI + Ii1I * O0 / oO0o
 if 8 - 8: i1IIi + II111iiii / Ii1I + I1ii11iIi11i % Ii1I - iIii1I11I1II1
 if 29 - 29: Oo0Ooo + II111iiii
 if 95 - 95: oO0o
 if ( len ( lisp . lisp_json_list ) != 0 ) : I1i1iii = lisp_show_json_list ( I1i1iii )
 if 48 - 48: I11i / iIii1I11I1II1 % II111iiii
 if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
 if 100 - 100: OoooooooOO - OoooooooOO + IiII
 if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo / OoooooooOO
 if ( itr_or_rtr == "RTR" ) :
  I1i1iii = lisp_display_nat_info ( I1i1iii , "Data" , dns )
  if 90 - 90: I1Ii111
  if 35 - 35: II111iiii / Ii1I
  if 79 - 79: OoOoOO00 + I1Ii111 * iII111i * Ii1I
  if 53 - 53: OOooOOo / Oo0Ooo
  if 10 - 10: I1ii11iIi11i . o0oOOo0O0Ooo
 return ( I1i1iii )
 if 75 - 75: O0 * i1IIi - I11i / OOooOOo % OOooOOo / OoOoOO00
 if 5 - 5: O0 - iII111i / I1Ii111 . o0oOOo0O0Ooo
 if 7 - 7: I1ii11iIi11i - OoOoOO00
 if 54 - 54: oO0o / iIii1I11I1II1 / OoooooooOO . i1IIi - OoOoOO00
 if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
 if 46 - 46: Ii1I
 if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
def lisp_itr_rtr_show_rloc_probe_command ( itr_or_rtr ) :
 i1i11ii1 = "LISP-{} RLOC-Probe Information:" . format ( itr_or_rtr )
 I1i1iii = lisp_table_header ( i1i11ii1 , "RLOC Key State" , "RLOC-Probe State" )
 if 87 - 87: I1ii11iIi11i / I1IiiI
 for IIi1IiiIi1III in list ( lisp . lisp_rloc_probe_list . values ( ) ) :
  OOOO0oo0 = ""
  for IiIiI , IiIiIiiIIii , OOo00O00o0O0 in IIi1IiiIi1III :
   iI1III = lisp . green ( lisp . lisp_print_eid_tuple ( IiIiIiiIIii , OOo00O00o0O0 ) , True )
   OOOO0oo0 += lisp . lisp_print_cour ( iI1III ) + "<br>"
   if 42 - 42: ooOoO0o + iII111i + Ii1I * I11i . i1IIi
  OOOO0oo0 = ", EIDs ({}):<br>" . format ( len ( IIi1IiiIi1III ) ) + OOOO0oo0
  if 72 - 72: I1IiiI + Ii1I
  IiIiI , IiIiIiiIIii , OOo00O00o0O0 = IIi1IiiIi1III [ 0 ]
  if 33 - 33: i1IIi / IiII - i1IIi . I1IiiI
  if 48 - 48: ooOoO0o + OOooOOo . I1Ii111 % II111iiii + oO0o
  if 38 - 38: oO0o
  if 28 - 28: iIii1I11I1II1 * I11i . I1IiiI
  oOOoo = lisp . lisp_hex_string ( IiIiI . last_rloc_probe_nonce )
  if ( IiIiI . translated_rloc . not_set ( ) ) :
   ooo = IiIiI . rloc . print_address_no_iid ( )
  else :
   ooo = "{}{}{}" . format ( IiIiI . translated_rloc . print_address_no_iid ( ) ,
 lisp . bold ( ":" , True ) , IiIiI . translated_port )
   if 20 - 20: i1IIi
  ooo = lisp . bold ( lisp . lisp_print_cour ( ooo ) , True )
  OOoo0 = IiIiI . rloc_name
  if ( OOoo0 != None ) :
   OOoo0 = lisp . bold ( OOoo0 , True )
   ooo += ", {}" . format ( lisp . lisp_print_cour ( lisp . blue ( OOoo0 , True ) ) )
   if 7 - 7: I1IiiI % I1Ii111 * IiII + OoOoOO00 / OoOoOO00
  o00OOo0o = IiIiI . print_state ( )
  if ( IiIiI . up_state ( ) == False ) : o00OOo0o = lisp . red ( IiIiI . print_state ( ) , True )
  ooo = "RLOC " + ooo + ", {}" . format ( o00OOo0o )
  if 34 - 34: II111iiii % i11iIiiIii % OoO0O00 . OoOoOO00 + i11iIiiIii
  OoOoO00O = ooo + OOOO0oo0
  if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
  if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
  if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
  if 58 - 58: iII111i
  iii1iII = [ IiIiI ]
  if ( IiIiI . multicast_rloc_probe_list != { } ) :
   iii1iII += list ( IiIiI . multicast_rloc_probe_list . values ( ) )
   if 77 - 77: IiII + OoooooooOO * i1IIi % OoooooooOO
   if 3 - 3: Ii1I * ooOoO0o - I1IiiI / i1IIi
   if 21 - 21: II111iiii + I1Ii111
   if 22 - 22: IiII . iII111i + Oo0Ooo
   if 45 - 45: Oo0Ooo % Oo0Ooo + Oo0Ooo / O0 % OoooooooOO
  O0oIii11IiiIi = ""
  for IiIiI in iii1iII :
   if ( len ( iii1iII ) != 1 ) :
    ooo = IiIiI . rloc . print_address_no_iid ( )
    ooo = lisp . bold ( lisp . lisp_print_cour ( ooo ) , True )
    if ( iii1iII . index ( IiIiI ) != 0 ) : O0oIii11IiiIi += "<br><br>"
    O0oIii11IiiIi += "RLOC {}:<br>" . format ( ooo )
    if 81 - 81: Oo0Ooo * iII111i * OoO0O00
    if 85 - 85: O0 * oO0o
   iiIiiiIii11i1 = lisp . lisp_print_elapsed ( IiIiI . last_rloc_probe )
   iiIiiiIii11i1 = lisp . lisp_print_cour ( iiIiiiIii11i1 )
   OOoo00 = lisp . lisp_print_elapsed ( IiIiI . last_rloc_probe_reply )
   OOoo00 = lisp . lisp_print_cour ( OOoo00 )
   oOOoo = lisp . lisp_hex_string ( IiIiI . last_rloc_probe_nonce )
   oOOoo = lisp . lisp_print_cour ( "0x" + oOOoo )
   O0oIii11IiiIi += ( "Last probe-request sent: {}, " + "last probe-reply received: {}, nonce: {}<br>" ) . format ( iiIiiiIii11i1 ,
   # OoooooooOO % iIii1I11I1II1 * OoOoOO00 . oO0o / I1Ii111
 OOoo00 , oOOoo )
   if 27 - 27: I1IiiI % IiII
   O00Oo00OOoO0 = IiIiI . print_recent_rloc_probe_rtts ( )
   O00Oo00OOoO0 = lisp . lisp_print_cour ( O00Oo00OOoO0 )
   IiIIIii1i1iI = IiIiI . print_recent_rloc_probe_hops ( )
   IiIIIii1i1iI = lisp . lisp_print_cour ( IiIIIii1i1iI )
   OoOOoO0o = IiIiI . print_recent_rloc_probe_latencies ( )
   OoOOoO0o = lisp . lisp_print_cour ( OoOOoO0o )
   o0O00ooo0 = IiIiI . print_rloc_probe_hops ( )
   o0O00ooo0 = lisp . lisp_print_cour ( o0O00ooo0 )
   I111Ii111 = IiIiI . print_rloc_probe_latency ( )
   I111Ii111 = lisp . lisp_print_cour ( I111Ii111 )
   IiIiI = IiIiI . print_rloc_probe_rtt ( )
   IiIiI = lisp . lisp_print_cour ( IiIiI )
   O0oIii11IiiIi += ( "Telemetry: rtt: {}, hops: {}, latency: {}<br>" + "recent-rtts: {}, recent-hops: {}, recent-latencies: {}" ) . format ( IiIiI , o0O00ooo0 , I111Ii111 , O00Oo00OOoO0 , IiIIIii1i1iI , OoOOoO0o )
   if 23 - 23: O0
   if 41 - 41: i1IIi . OOooOOo / ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
   if 14 - 14: I1ii11iIi11i - i11iIiiIii * I1Ii111
   if 39 - 39: OoooooooOO
   if 19 - 19: i11iIiiIii
   if 80 - 80: I1IiiI
   if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
  I1i1iii += lisp_table_row ( OoOoO00O , O0oIii11IiiIi )
  if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
  if 26 - 26: o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
 I1i1iii += lisp_table_footer ( )
 return ( I1i1iii )
 if 97 - 97: i1IIi
 if 46 - 46: I1ii11iIi11i
 if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
 if 23 - 23: I11i
 if 36 - 36: IiII . iII111i - i1IIi + I1Ii111
 if 54 - 54: OoooooooOO . oO0o - iII111i
 if 76 - 76: I1Ii111
def lisp_xtr_command ( kv_pair ) :
 if 61 - 61: ooOoO0o / II111iiii * ooOoO0o * OoOoOO00 * I1Ii111 . i11iIiiIii
 if 26 - 26: I1Ii111 / ooOoO0o - OoO0O00 . iIii1I11I1II1
 if 83 - 83: ooOoO0o % Ii1I / Oo0Ooo - iII111i / O0
 if 97 - 97: iIii1I11I1II1 * I11i
 if 95 - 95: OoO0O00
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) :
  kv_pair [ "ipc-data-plane" ] = [ "yes" ]
  if 68 - 68: iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00 - II111iiii - iIii1I11I1II1
  if 75 - 75: ooOoO0o . I1IiiI * II111iiii
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ] [ 0 ]
  if ( IiII1II11I == "rloc-probing" ) :
   lisp . lisp_rloc_probing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_rloc_probe_list = { }
   if 99 - 99: iIii1I11I1II1 * I1ii11iIi11i + IiII
  if ( IiII1II11I == "nonce-echoing" ) :
   lisp . lisp_nonce_echoing = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) : lisp . lisp_nonce_echo_list = { }
   if 70 - 70: i1IIi % ooOoO0o . I1ii11iIi11i - IiII + OOooOOo
  if ( IiII1II11I == "data-plane-security" ) :
   lisp . lisp_data_plane_security = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "no" ) :
    lisp . lisp_crypto_keys_by_nonce = { }
    lisp . lisp_crypto_keys_by_rloc_encap = { }
    lisp . lisp_crypto_keys_by_rloc_decap = { }
    if 84 - 84: oO0o + II111iiii * II111iiii % o0oOOo0O0Ooo / iII111i + ooOoO0o
    if 9 - 9: iII111i
  if ( IiII1II11I == "data-plane-logging" ) :
   lisp . lisp_data_plane_logging = ( oo00oO0O0 == "yes" )
   if 25 - 25: OOooOOo - Ii1I . I11i
  if ( IiII1II11I == "frame-logging" ) :
   lisp . lisp_frame_logging = ( oo00oO0O0 == "yes" )
   if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
  if ( IiII1II11I == "flow-logging" ) :
   lisp . lisp_flow_logging = ( oo00oO0O0 == "yes" )
   if ( oo00oO0O0 == "yes" ) : os . system ( "touch ./log-flows" )
   if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
  if ( IiII1II11I == "nat-traversal" ) :
   lisp . lisp_nat_traversal = ( oo00oO0O0 == "yes" )
   if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
  if ( IiII1II11I == "program-hardware" ) :
   lisp . lisp_program_hardware = ( oo00oO0O0 == "yes" )
   if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
  if ( IiII1II11I == "checkpoint-map-cache" ) :
   lisp . lisp_checkpoint_map_cache = ( oo00oO0O0 == "yes" )
   oo0OoOO000O = lisp . lisp_checkpoint_filename
   if ( oo00oO0O0 == "no" and os . path . exists ( oo0OoOO000O ) ) :
    os . system ( "rm {}" . format ( oo0OoOO000O ) )
    if 62 - 62: i1IIi * iIii1I11I1II1 % oO0o % OoOoOO00 / OoooooooOO
    if 39 - 39: Oo0Ooo % iII111i
  if ( IiII1II11I == "ipc-data-plane" ) :
   OooO00O0OO0oo = ( oo00oO0O0 == "yes" )
   if ( OooO00O0OO0oo and lisp . lisp_ipc_data_plane == False ) :
    I1IIi1I = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
    lisp . lisp_ipc_dp_socket = I1IIi1I
    if 60 - 60: II111iiii + o0oOOo0O0Ooo % I1Ii111 + ooOoO0o . IiII % II111iiii
   if ( OooO00O0OO0oo == False and lisp . lisp_ipc_data_plane ) :
    lisp . lisp_ipc_dp_socket . close ( )
    lisp . lisp_ipc_dp_socket = None
    if 58 - 58: ooOoO0o
   lisp . lisp_ipc_data_plane = OooO00O0OO0oo
   if 45 - 45: o0oOOo0O0Ooo
  if ( IiII1II11I == "decentralized-push-xtr" ) :
   lisp . lisp_decent_push_configured = ( oo00oO0O0 == "yes" )
   if 67 - 67: iII111i + ooOoO0o
  if ( IiII1II11I == "decentralized-pull-xtr-modulus" ) :
   lisp . lisp_decent_modulus = int ( oo00oO0O0 )
   if 25 - 25: i1IIi - i11iIiiIii
  if ( IiII1II11I == "decentralized-pull-xtr-dns-suffix" ) :
   lisp . lisp_decent_dns_suffix = oo00oO0O0
   if 25 - 25: oO0o
  if ( IiII1II11I == "register-reachable-rtrs" ) :
   lisp . lisp_register_all_rtrs = ( oo00oO0O0 == "no" )
   if 84 - 84: I1ii11iIi11i - iII111i + I1ii11iIi11i
   if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
 return
 if 96 - 96: IiII
 if 99 - 99: iIii1I11I1II1 - ooOoO0o
 if 79 - 79: I1IiiI + oO0o % I11i % oO0o
 if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
 if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
 if 99 - 99: o0oOOo0O0Ooo + OOooOOo
 if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
def lisp_show_json_list ( output ) :
 if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
 i1i11ii1 = "Configured JSON Entries:"
 output += lisp_table_header ( i1i11ii1 , "JSON Name" , "JSON String" )
 if 76 - 76: oO0o / OoOoOO00
 iI1II1iIiI11I = sorted ( lisp . lisp_json_list )
 for i1II in iI1II1iIiI11I :
  oOO00O0Ooooo00 = lisp . lisp_json_list [ i1II ]
  OOoo0OoO = lisp . lisp_print_cour ( oOO00O0Ooooo00 . print_json ( True ) )
  output += lisp_table_row ( i1II , OOoo0OoO )
  if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
 output += lisp_table_footer ( )
 return ( output )
 if 58 - 58: IiII % iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * iII111i
 if 32 - 32: OoooooooOO + o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o - I1Ii111 * I1Ii111
 if 55 - 55: iIii1I11I1II1 + I1IiiI - Oo0Ooo
 if 24 - 24: OoO0O00 / I1Ii111 + iII111i * I11i * iII111i
 if 10 - 10: I1IiiI - I1ii11iIi11i - Oo0Ooo - o0oOOo0O0Ooo
 if 21 - 21: OoooooooOO + I1Ii111
def lisp_show_rle_list ( output ) :
 if 43 - 43: i11iIiiIii . I1ii11iIi11i . oO0o
 i1i11ii1 = "Configured Replication List Entries (RLEs):"
 output += lisp_table_header ( i1i11ii1 , "RLE Name" , "RLE Nodes" )
 if 31 - 31: Ii1I % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
 OoI1 = sorted ( lisp . lisp_rle_list )
 for OoO00o00 in OoI1 :
  iIIIII11Iii1 = lisp . lisp_rle_list [ OoO00o00 ]
  output += lisp_table_row ( OoO00o00 , iIIIII11Iii1 . print_rle ( True , True ) )
  if 72 - 72: i1IIi
 output += lisp_table_footer ( )
 return ( output )
 if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
 if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
 if 89 - 89: IiII - i1IIi - IiII
 if 74 - 74: OoO0O00 % OoO0O00
 if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
 if 91 - 91: I1IiiI / II111iiii * OOooOOo
 if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
def lisp_show_elp_list ( output ) :
 i1i11ii1 = "Configured Explicit Locator Paths (ELPs):"
 output += lisp_table_header ( i1i11ii1 , "ELP Name" , "ELP Nodes" )
 if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
 oOoOo00oo = sorted ( lisp . lisp_elp_list )
 for II11IiIIiiiii in oOoOo00oo :
  I1II1I = lisp . lisp_elp_list [ II11IiIIiiiii ]
  output += lisp_table_row ( II11IiIIiiiii , I1II1I . print_elp ( False ) )
  if 66 - 66: O0 * o0oOOo0O0Ooo / I1ii11iIi11i
 output += lisp_table_footer ( )
 return ( output )
 if 15 - 15: OOooOOo . o0oOOo0O0Ooo + OoooooooOO - Oo0Ooo * iIii1I11I1II1 . i1IIi
 if 39 - 39: Ii1I % i1IIi . I1ii11iIi11i - O0
 if 65 - 65: oO0o * oO0o / I11i + oO0o % ooOoO0o + OoOoOO00
 if 92 - 92: o0oOOo0O0Ooo
 if 37 - 37: oO0o
 if 18 - 18: IiII * i11iIiiIii + iIii1I11I1II1 % I11i + i1IIi - OoO0O00
 if 85 - 85: OoO0O00 * I11i + OoO0O00
def lisp_geo_command ( kv_pair ) :
 if 39 - 39: Oo0Ooo / i1IIi % i1IIi
 if 20 - 20: OOooOOo * oO0o
 if 91 - 91: OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
 if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
 if ( "geo-name" not in kv_pair ) : return
 I1i1Ii = kv_pair [ "geo-name" ]
 III1 = lisp . lisp_geo ( I1i1Ii )
 if 14 - 14: I1Ii111 / I11i - OOooOOo * O0 % IiII . O0
 if 86 - 86: i1IIi * OoooooooOO
 if 22 - 22: I1Ii111 + iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoooooooOO
 if 42 - 42: OoooooooOO - OoOoOO00 - OOooOOo * I1Ii111
 if ( "geo-tag" not in kv_pair ) : return
 if 98 - 98: OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
 if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
 if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
 if 95 - 95: oO0o
 oOo0ooO0O0oo = kv_pair [ "geo-tag" ] [ 1 : : ]
 if ( III1 . parse_geo_string ( oOo0ooO0O0oo ) == False ) : return
 if 31 - 31: i11iIiiIii + Ii1I % OoOoOO00
 if 9 - 9: ooOoO0o . I11i - Oo0Ooo . I1Ii111
 if 39 - 39: OOooOOo
 if 70 - 70: IiII % OoO0O00 % I1IiiI
 lisp . lisp_geo_list [ I1i1Ii ] = III1
 return
 if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
 if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
 if 2 - 2: oO0o * oO0o . OoOoOO00 * Ii1I * iIii1I11I1II1
 if 13 - 13: I11i / O0 . i11iIiiIii * i1IIi % i11iIiiIii
 if 8 - 8: OoOoOO00 - OoooooooOO
 if 99 - 99: II111iiii / IiII % OoooooooOO . i11iIiiIii
 if 18 - 18: o0oOOo0O0Ooo . ooOoO0o
def lisp_elp_command ( kv_pair ) :
 if 70 - 70: OoooooooOO . ooOoO0o / oO0o . oO0o - o0oOOo0O0Ooo
 I1II1I = None
 i1II1i1iiI1 = [ ]
 if ( "address" in kv_pair ) :
  for i11Ii1 in range ( len ( kv_pair [ "address" ] ) ) :
   O0ooO0O00oo0 = lisp . lisp_elp_node ( )
   i1II1i1iiI1 . append ( O0ooO0O00oo0 )
   if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
   if 47 - 47: iII111i * OoOoOO00 * IiII
   if 46 - 46: Ii1I
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if 42 - 42: iIii1I11I1II1
  if ( IiII1II11I == "elp-name" ) :
   I1II1I = lisp . lisp_elp ( oo00oO0O0 )
   continue
   if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
   if 34 - 34: Oo0Ooo
  for IiI1I1i1 in i1II1i1iiI1 :
   O0OO0O = i1II1i1iiI1 . index ( IiI1I1i1 )
   if ( O0OO0O >= len ( oo00oO0O0 ) ) : O0OO0O = len ( oo00oO0O0 ) - 1
   OoO0o0OO = oo00oO0O0 [ O0OO0O ]
   if ( IiII1II11I == "probe" ) : IiI1I1i1 . probe = ( OoO0o0OO == "yes" )
   if ( IiII1II11I == "strict" ) : IiI1I1i1 . strict = ( OoO0o0OO == "yes" )
   if ( IiII1II11I == "eid" ) : IiI1I1i1 . eid = ( OoO0o0OO == "yes" )
   if ( IiII1II11I == "address" ) : IiI1I1i1 . address . store_address ( OoO0o0OO )
   if 6 - 6: I1IiiI . II111iiii + I1Ii111 / OoO0O00 % I1IiiI . OoooooooOO
   if 64 - 64: iIii1I11I1II1 + II111iiii . iII111i % Oo0Ooo * ooOoO0o
   if 7 - 7: i1IIi + i1IIi / IiII
   if 32 - 32: Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . ooOoO0o - i1IIi
   if 60 - 60: OoOoOO00 % OoOoOO00
   if 2 - 2: Ii1I . O0 - oO0o + IiII
 if ( I1II1I == None ) : return
 if 96 - 96: Ii1I + Ii1I
 if 28 - 28: iII111i
 if 6 - 6: I1IiiI - iII111i
 if 49 - 49: II111iiii
 I1II1I . elp_nodes = i1II1i1iiI1
 lisp . lisp_elp_list [ I1II1I . elp_name ] = I1II1I
 return
 if 33 - 33: o0oOOo0O0Ooo - oO0o % I1ii11iIi11i * I11i . OoooooooOO % Ii1I
 if 29 - 29: iII111i + II111iiii . i11iIiiIii . Ii1I - O0
 if 47 - 47: oO0o . I1ii11iIi11i - iIii1I11I1II1 % II111iiii / OoOoOO00 % OoooooooOO
 if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
 if 84 - 84: II111iiii
 if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
 if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
def lisp_rle_command ( kv_pair ) :
 if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
 iIIIII11Iii1 = None
 ooiIi11i1I11Ii = [ ]
 if ( "address" in kv_pair ) :
  for i11Ii1 in range ( len ( kv_pair [ "address" ] ) ) :
   oo0OO0oo = lisp . lisp_rle_node ( )
   ooiIi11i1I11Ii . append ( oo0OO0oo )
   if 54 - 54: II111iiii % o0oOOo0O0Ooo - i1IIi . I1IiiI - II111iiii / iIii1I11I1II1
   if 29 - 29: oO0o
   if 66 - 66: OoooooooOO + iII111i . IiII % i1IIi
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if 58 - 58: OOooOOo % iII111i * O0 + I1ii11iIi11i - IiII
  if ( IiII1II11I == "rle-name" ) :
   iIIIII11Iii1 = lisp . lisp_rle ( oo00oO0O0 )
   continue
   if 26 - 26: i1IIi / I1IiiI / I11i + I11i
   if 46 - 46: I1Ii111 % I1ii11iIi11i + Ii1I
  for IiI1I1i1 in ooiIi11i1I11Ii :
   O0OO0O = ooiIi11i1I11Ii . index ( IiI1I1i1 )
   if ( O0OO0O >= len ( oo00oO0O0 ) ) : O0OO0O = len ( oo00oO0O0 ) - 1
   OoO0o0OO = oo00oO0O0 [ O0OO0O ]
   if ( IiII1II11I == "level" ) :
    if ( OoO0o0OO == "" ) : OoO0o0OO = "0"
    IiI1I1i1 . level = int ( OoO0o0OO )
    if 67 - 67: iIii1I11I1II1 . i11iIiiIii . i11iIiiIii . i11iIiiIii / I11i + ooOoO0o
   if ( IiII1II11I == "address" ) : IiI1I1i1 . address . store_address ( OoO0o0OO )
   if 10 - 10: ooOoO0o - Oo0Ooo % II111iiii
   if 66 - 66: iIii1I11I1II1 . iIii1I11I1II1
   if 46 - 46: I1Ii111 * oO0o . Ii1I * I1Ii111 * iIii1I11I1II1 / I11i
   if 46 - 46: II111iiii % I1ii11iIi11i . OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
   if 47 - 47: IiII . OOooOOo
   if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
 if ( iIIIII11Iii1 == None ) : return
 if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
 if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
 if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
 if 89 - 89: ooOoO0o * I1IiiI . oO0o
 iIIIII11Iii1 . rle_nodes = ooiIi11i1I11Ii
 iIIIII11Iii1 . build_forwarding_list ( )
 lisp . lisp_rle_list [ iIIIII11Iii1 . rle_name ] = iIIIII11Iii1
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
  i1II = kv_pair [ "json-name" ]
  OOoo0OoO = kv_pair [ "json-string" ]
 except :
  return
  if 4 - 4: I11i . IiII
  if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
 oOO00O0Ooooo00 = lisp . lisp_json ( i1II , OOoo0OoO )
 oOO00O0Ooooo00 . add ( )
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
 I1i1iii = "<br>"
 if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
 oooOoooOOo0 = Ii11II11iI1 if ( OoOo0Oooo0o . is_null ( ) ) else OoOo0Oooo0o
 I1IIII1 = oo0OOo0Oo00 if ( OoOo0Oooo0o . is_null ( ) ) else I111i
 if 91 - 91: II111iiii
 IIiI1i = lisp . lisp_map_cache . lookup_cache ( oooOoooOOo0 , I1IIII1 )
 if ( IIiI1i == None ) :
  I1i1iii += "{} {}" . format ( lisp . lisp_print_sans ( "Lookup not found for" ) ,
 lisp . lisp_print_cour ( eid_str ) )
 else :
  if ( oooOoooOOo0 == OoOo0Oooo0o ) :
   iIi1II111I1i1 = IIiI1i . lookup_source_cache ( Ii11II11iI1 , oo0OOo0Oo00 )
   if ( iIi1II111I1i1 ) : IIiI1i = iIi1II111I1i1
   if 10 - 10: O0 . OoOoOO00 * IiII / I1Ii111 / i1IIi
   if 32 - 32: O0 / OOooOOo . ooOoO0o % I1Ii111
  oO0OOoO0 = lisp . lisp_print_elapsed ( IIiI1i . uptime )
  I1i1iii += "{} {} {} {} {} {} {}" . format ( lisp . lisp_print_sans ( "Exact" if oo0OOo0Oo00 else "Longest" ) ,
  # I1Ii111 - IiII
 lisp . lisp_print_sans ( "match lookup for" ) ,
 lisp . lisp_print_cour ( eid_str ) ,
 lisp . lisp_print_sans ( "found" ) ,
 lisp . lisp_print_cour ( IIiI1i . print_eid_tuple ( ) ) ,
 lisp . lisp_print_sans ( "with uptime" ) ,
 lisp . lisp_print_cour ( oO0OOoO0 ) )
  if 24 - 24: I11i / iIii1I11I1II1 . OoooooooOO % OoOoOO00 . Ii1I
 I1i1iii += "<br>"
 return ( I1i1iii )
 if 73 - 73: I1Ii111
 if 25 - 25: IiII
 if 77 - 77: o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO . iIii1I11I1II1
 if 87 - 87: II111iiii - OoooooooOO / i1IIi . Ii1I - Oo0Ooo . i11iIiiIii
 if 47 - 47: Oo0Ooo % OoO0O00 - ooOoO0o - Oo0Ooo * oO0o
 if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
 if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
 if 64 - 64: IiII
def lisp_get_clause_for_api ( command ) :
 iIi1i = open ( "./lisp.config" , "r" )
 oo00ooooOOo00 = { command : [ ] }
 OooooOOOO = { }
 oo000o = [ ]
 if 6 - 6: OOooOOo + I1ii11iIi11i + Oo0Ooo
 OoO = 0
 IIIIiiI = False
 for OOo00OoO in iIi1i :
  if ( lisp_end_file ( OOo00OoO ) ) : break
  if ( lisp_comment ( OOo00OoO ) ) : continue
  if 52 - 52: IiII * Oo0Ooo + OoooooooOO
  if 93 - 93: ooOoO0o
  if 15 - 15: i11iIiiIii / o0oOOo0O0Ooo / OoO0O00 . OoOoOO00 % oO0o
  if 29 - 29: o0oOOo0O0Ooo
  if 13 - 13: Ii1I + Ii1I . I11i
  if 57 - 57: ooOoO0o
  if ( OOo00OoO . find ( command + " {" ) != - 1 ) :
   OoO += 1
   IIIIiiI = True
   continue
   if 94 - 94: OoO0O00 - II111iiii % iIii1I11I1II1
  if ( IIIIiiI == False ) : continue
  if 92 - 92: Oo0Ooo
  if ( lisp_begin_clause ( OOo00OoO ) ) :
   OoO += 1
   i1iII = OOo00OoO . replace ( " " , "" )
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
  if ( lisp_end_clause ( OOo00OoO ) ) :
   OoO -= 1
   if ( OoO ) :
    oo00ooooOOo00 [ command ] . append ( OooooOOOO )
    OooooOOOO = { }
    continue
    if 22 - 22: OoooooooOO + o0oOOo0O0Ooo . I11i + I1IiiI + OoooooooOO . OoOoOO00
   oo000o . append ( oo00ooooOOo00 )
   oo00ooooOOo00 = { command : [ ] }
   IIIIiiI = False
   continue
   if 93 - 93: I1IiiI
   if 89 - 89: OoooooooOO % i11iIiiIii + I1Ii111
  OOo00OoO = OOo00OoO . replace ( " " , "" )
  OOo00OoO = OOo00OoO . replace ( "\t" , "" )
  OOo00OoO = OOo00OoO . replace ( "\n" , "" )
  OOo00OoO = OOo00OoO . replace ( "{" , "" )
  OOo00OoO = OOo00OoO . split ( "=" )
  oo00oO0O0 = "" if len ( OOo00OoO ) == 1 else OOo00OoO [ 1 ]
  oo000O0o = OOo00OoO [ 0 ]
  if 12 - 12: OoOoOO00 * ooOoO0o
  if ( len ( OooooOOOO ) == 0 ) :
   oo00ooooOOo00 [ command ] . append ( { oo000O0o : oo00oO0O0 } )
  else :
   OooooOOOO [ i1iII ] [ oo000O0o ] = oo00oO0O0
   if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
   if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
   if 50 - 50: ooOoO0o
 iIi1i . close ( )
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
 Oo0O0Oo00O = open ( "./lisp.config" , "r" )
 if 78 - 78: I11i - iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - I1Ii111
 clause = command + " {\n" + clause
 for OOo00OoO in Oo0O0Oo00O :
  if ( lisp_begin_clause ( OOo00OoO ) == False ) : continue
  if ( OOo00OoO . find ( command ) == - 1 ) : continue
  if 21 - 21: OoooooooOO . O0 / i11iIiiIii
  oOOO = OOo00OoO
  for OOo00OoO in Oo0O0Oo00O :
   oOOO += OOo00OoO
   if ( OOo00OoO [ 0 ] != "}" ) : continue
   if ( oOOO != clause ) : break
   Oo0O0Oo00O . close ( )
   return ( True )
   if 71 - 71: I1IiiI . ooOoO0o
  if ( lisp_end_file ( OOo00OoO ) ) : break
  if 43 - 43: I1ii11iIi11i * OOooOOo
  if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
 Oo0O0Oo00O . close ( )
 return ( False )
 if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
 if 51 - 51: OOooOOo / I11i
 if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
 if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
 if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
 if 26 - 26: i11iIiiIii - ooOoO0o
 if 45 - 45: ooOoO0o + II111iiii % iII111i
def lisp_put_clause_for_api ( data ) :
 if 55 - 55: ooOoO0o - oO0o % I1IiiI
 if 61 - 61: ooOoO0o
 if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
 if 21 - 21: oO0o . i11iIiiIii * I11i . OOooOOo / OOooOOo
 I111i1I1 = list ( data . keys ( ) ) [ 0 ]
 if ( I111i1I1 not in list ( lisp_commands . keys ( ) ) ) :
  return ( [ { I111i1I1 : [ { "?" : "add/replace" } ] } ] )
  if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
  if 1 - 1: Ii1I % I1Ii111
 oo00Oo0 = ( I111i1I1 in [ "lisp enable" , "lisp debug" , "lisp xtr-parameters" ] )
 if 28 - 28: Ii1I
 if 36 - 36: I1Ii111 / I1Ii111 % oO0o
 if 97 - 97: OoooooooOO * o0oOOo0O0Ooo + OoooooooOO % Ii1I * Oo0Ooo
 if 35 - 35: iIii1I11I1II1 % iII111i - i1IIi
 if 20 - 20: I11i % ooOoO0o . OOooOOo / I1Ii111
 if 50 - 50: oO0o + i11iIiiIii / i11iIiiIii + ooOoO0o + I1Ii111
 if 65 - 65: ooOoO0o * O0 * iII111i
 OoOOOo0oo = False
 if ( oo00Oo0 == False ) :
  OoOOOo0oo = True
  ooo0ooOoOOoO = getoutput ( "egrep '{}' ./lisp.config" . format ( I111i1I1 ) )
  ooo0ooOoOOoO = ooo0ooOoOOoO . split ( "\n" )
  for OOo00OoO in ooo0ooOoOOoO :
   if ( OOo00OoO [ 0 : len ( I111i1I1 ) ] == I111i1I1 ) : OoOOOo0oo = False
   if 8 - 8: i11iIiiIii / ooOoO0o
   if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
   if 19 - 19: i1IIi % II111iiii
   if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
   if 56 - 56: Ii1I * i11iIiiIii
   if 92 - 92: II111iiii - O0 . I1Ii111
 oOOOoOO = data [ I111i1I1 ]
 oOOOoOO = lisp_unicode_to_ascii ( oOOOoOO )
 oo00ooooOOo00 = I111i1I1 + " {\n" if OoOOOo0oo else ""
 if 80 - 80: OoooooooOO
 if 65 - 65: oO0o * i1IIi . OoooooooOO % ooOoO0o
 if 87 - 87: i11iIiiIii * II111iiii - Ii1I % OoooooooOO
 if 55 - 55: i1IIi
 if 67 - 67: I1IiiI - OoO0O00
 if 60 - 60: i1IIi / iIii1I11I1II1 * oO0o + ooOoO0o + OoooooooOO + II111iiii
 if 13 - 13: iIii1I11I1II1 - OOooOOo
 if 14 - 14: ooOoO0o
 for Ooo0OO00oo in oOOOoOO :
  if ( type ( oOOOoOO ) == dict ) :
   oo00oO0O0 = oOOOoOO [ Ooo0OO00oo ]
   if ( type ( oo00oO0O0 ) == dict ) : oo00oO0O0 = json_dumps ( oo00oO0O0 )
   oo00ooooOOo00 += "    " + Ooo0OO00oo + " = " + oo00oO0O0 + "\n"
   continue
   if 21 - 21: I11i
   if 79 - 79: OoO0O00 / OOooOOo - i1IIi + i1IIi - IiII + IiII
  for oo000O0o in Ooo0OO00oo :
   if ( type ( Ooo0OO00oo ) == dict ) :
    oOoOo000Ooooo = oo000O0o
    oo00oO0O0 = Ooo0OO00oo [ oo000O0o ]
    if 18 - 18: Ii1I + OoOoOO00 . i1IIi / IiII / iII111i
   if ( type ( Ooo0OO00oo ) == list ) :
    oOoOo000Ooooo = list ( oo000O0o . keys ( ) ) [ 0 ]
    oo00oO0O0 = list ( oo000O0o . values ( ) ) [ 0 ]
    if 97 - 97: OoO0O00 + iIii1I11I1II1
    if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
   if ( type ( oo00oO0O0 ) != dict ) :
    oo00ooooOOo00 += "    " + oo000O0o + " = " + Ooo0OO00oo [ oo000O0o ] + "\n"
    continue
    if 26 - 26: IiII
    if 52 - 52: O0 + ooOoO0o
    if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
    if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
    if 1 - 1: I1IiiI . Ii1I
   oo00ooooOOo00 += "    " + oOoOo000Ooooo + " {\n"
   for II11IIII1 in oo00oO0O0 : oo00ooooOOo00 += "        " + II11IIII1 + " = " + oo00oO0O0 [ II11IIII1 ] + "\n"
   oo00ooooOOo00 += "    }\n"
   if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
   if 21 - 21: O0 * ooOoO0o % OoO0O00
 oo00ooooOOo00 += "}\n"
 if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
 if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
 if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
 if 76 - 76: I11i . I1ii11iIi11i * OoooooooOO % iII111i
 if ( lisp_duplicate_command_clause ( I111i1I1 , oo00ooooOOo00 ) ) :
  return ( [ { I111i1I1 : [ { "!" : "duplicate" } ] } ] )
  if 24 - 24: OoooooooOO
  if 83 - 83: O0 / OoO0O00
 o0O000O00o = "./lisp.config"
 iiooo = o0O000O00o + ".temp"
 if 42 - 42: OoooooooOO % I11i % IiII
 O0OoO0OOo = open ( o0O000O00o , "r" )
 iIiI111ii1Ii = open ( iiooo , "w" )
 if 59 - 59: O0 . o0oOOo0O0Ooo % I1ii11iIi11i * oO0o + I11i
 o00o = False
 IiIiIiiI = False
 for OOo00OoO in O0OoO0OOo :
  if ( IiIiIiiI ) :
   if ( lisp_end_clause ( OOo00OoO ) == False ) : continue
   IiIiIiiI = False
   continue
   if 83 - 83: OoOoOO00
   if 84 - 84: Ii1I
   if 70 - 70: iIii1I11I1II1
   if 45 - 45: O0 - OoOoOO00 % OOooOOo
   if 100 - 100: i11iIiiIii . OOooOOo . i11iIiiIii
  if ( o00o == False and lisp_begin_clause ( OOo00OoO ) and
 OOo00OoO [ 0 : len ( I111i1I1 ) ] == I111i1I1 ) :
   if ( oo00Oo0 == False ) :
    iIiI111ii1Ii . write ( OOo00OoO )
    for o00Oo in oo00ooooOOo00 : iIiI111ii1Ii . write ( o00Oo )
    o00o = True
    if 20 - 20: Ii1I . Oo0Ooo - I11i % I11i - I1IiiI * OOooOOo
    if 80 - 80: II111iiii / o0oOOo0O0Ooo . OOooOOo . o0oOOo0O0Ooo
    if 29 - 29: OoooooooOO % II111iiii % i11iIiiIii - Oo0Ooo
    if 5 - 5: I1ii11iIi11i . II111iiii . i1IIi
    if 35 - 35: o0oOOo0O0Ooo + OoO0O00 - I1ii11iIi11i
    if 24 - 24: II111iiii
  if ( lisp_end_file ( OOo00OoO ) ) :
   if ( OoOOOo0oo ) :
    for o00Oo in oo00ooooOOo00 : iIiI111ii1Ii . write ( o00Oo )
    if 23 - 23: Oo0Ooo - iII111i
   iIiI111ii1Ii . write ( OOo00OoO )
   o00o = True
   break
   if 79 - 79: I11i . O0 - i1IIi
   if 42 - 42: oO0o - i11iIiiIii % oO0o - I1Ii111 * O0 / II111iiii
   if 5 - 5: Oo0Ooo
   if 84 - 84: I1ii11iIi11i
   if 53 - 53: oO0o
  iIiI111ii1Ii . write ( OOo00OoO )
  if 26 - 26: I1Ii111 / I1Ii111 + Oo0Ooo - o0oOOo0O0Ooo % II111iiii . OoooooooOO
  if 7 - 7: II111iiii - I1ii11iIi11i / I11i % OoooooooOO + i1IIi
  if 42 - 42: I11i + i1IIi - Ii1I / IiII . iII111i
  if 30 - 30: Oo0Ooo + Ii1I % i11iIiiIii * i1IIi + I1IiiI % OOooOOo
  if 30 - 30: i11iIiiIii * Oo0Ooo . II111iiii + I1ii11iIi11i / o0oOOo0O0Ooo % I1Ii111
  if ( lisp_begin_clause ( OOo00OoO ) and OOo00OoO [ 0 : len ( I111i1I1 ) ] == I111i1I1 ) :
   if ( oo00Oo0 ) :
    IiIiIiiI = True
    for o00Oo in oo00ooooOOo00 : iIiI111ii1Ii . write ( o00Oo )
    if 78 - 78: I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
    if 7 - 7: OOooOOo . IiII . I1Ii111 / Ii1I / Oo0Ooo
    if 83 - 83: I11i / Oo0Ooo
    if 23 - 23: iIii1I11I1II1
 O0OoO0OOo . close ( )
 iIiI111ii1Ii . close ( )
 if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
 os . system ( "cp {} {}" . format ( iiooo , o0O000O00o ) )
 os . system ( "rm {}" . format ( iiooo ) )
 return ( [ { I111i1I1 : [ { "!" : "add/replace" } ] } ] )
 if 64 - 64: OoO0O00 / I1IiiI
 if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
 if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
 if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
 if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
 if 8 - 8: o0oOOo0O0Ooo
 if 78 - 78: i1IIi - Oo0Ooo
 if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
def lisp_remove_clause_for_api ( data ) :
 if 42 - 42: I1Ii111
 if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
 if 80 - 80: OOooOOo
 if 12 - 12: Ii1I
 I111i1I1 = list ( data . keys ( ) ) [ 0 ]
 if ( I111i1I1 not in list ( lisp_commands . keys ( ) ) ) :
  return ( [ { I111i1I1 : [ { "?" : "delete" } ] } ] )
  if 2 - 2: OoooooooOO
  if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
  if 46 - 46: O0 % OoooooooOO
  if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
  if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
 oOOOoOO = data [ I111i1I1 ]
 oOOOoOO = lisp_unicode_to_ascii ( oOOOoOO )
 if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
 if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
 if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
 if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
 IIIiIi11 = [ ]
 oo000O0o = list ( oOOOoOO . keys ( ) ) [ 0 ]
 oo00oO0O0 = oOOOoOO [ oo000O0o ]
 if 57 - 57: ooOoO0o * iIii1I11I1II1 * iII111i * Ii1I / Ii1I
 if ( type ( oo00oO0O0 ) == dict ) :
  for oo000O0o in list ( oo00oO0O0 . keys ( ) ) :
   IiIiIiIII1Iii = oo00oO0O0 [ oo000O0o ]
   IIIiIi11 . append ( oo000O0o + " = " + IiIiIiIII1Iii )
   if 57 - 57: oO0o / OOooOOo / OOooOOo * o0oOOo0O0Ooo * I1ii11iIi11i - i11iIiiIii
 else :
  IIIiIi11 . append ( oo000O0o + " = " + oo00oO0O0 )
  if 82 - 82: I1IiiI . OoO0O00
  if 67 - 67: I1ii11iIi11i * i11iIiiIii + Ii1I % Ii1I + iIii1I11I1II1 - OOooOOo
  if 10 - 10: I1IiiI - I1Ii111 - I1ii11iIi11i / iII111i
  if 10 - 10: Ii1I * I1IiiI % I1Ii111 + iII111i . Ii1I
  if 40 - 40: I1ii11iIi11i
  if 78 - 78: IiII / iII111i * Ii1I . OOooOOo . oO0o - I1Ii111
 if ( I111i1I1 == "lisp user-account" ) :
  oo00ooooOOo00 = getoutput ( "egrep -A4 '{}' ./lisp.config" . format ( IIIiIi11 [ 0 ] ) )
  if 39 - 39: ooOoO0o . i1IIi + OoooooooOO . iII111i - i11iIiiIii % I1Ii111
  if 38 - 38: oO0o
  if ( oo00ooooOOo00 . find ( "super-user = yes" ) != - 1 ) :
   return ( [ { "lisp user-account" : [ { "?" : "found-superuser" } ] } ] )
   if 9 - 9: I11i . OoO0O00 . oO0o / OoooooooOO
   if 59 - 59: iIii1I11I1II1 + i1IIi % II111iiii
   if 2 - 2: II111iiii + I11i . OoO0O00
   if 14 - 14: OOooOOo * I1IiiI - I1ii11iIi11i
   if 10 - 10: iII111i % I1Ii111 * I1ii11iIi11i * O0 * i11iIiiIii % I1Ii111
   if 68 - 68: OoooooooOO * OoOoOO00
   if 9 - 9: I1Ii111
 I1II = ( "lisp user-account" , "lisp site" , "lisp map-server" ,
 "lisp policy" )
 if 93 - 93: ooOoO0o / OOooOOo * O0
 o0O000O00o = "./lisp.config"
 O0OoO0OOo = open ( o0O000O00o , "r" )
 if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
 OooOo0OOO = False
 IIiI1IiI1iIi1 = 0
 for OOo00OoO in O0OoO0OOo :
  if ( OOo00OoO . find ( I111i1I1 ) == - 1 ) : continue
  IIiI1IiI1iIi1 += 1
  if 30 - 30: iII111i
  for OOo00OoO in O0OoO0OOo :
   if ( lisp_begin_clause ( OOo00OoO ) ) : continue
   iIOO000O = ( lisp_end_clause ( OOo00OoO ) and OooOo0OOO )
   if ( iIOO000O ) : break
   if 52 - 52: iII111i . IiII - I1ii11iIi11i * iIii1I11I1II1 % o0oOOo0O0Ooo / ooOoO0o
   II1IiI11I1 = OOo00OoO . replace ( " " , "" )
   II1IiI11I1 = II1IiI11I1 . replace ( "\n" , "" )
   II1IiI11I1 = II1IiI11I1 . replace ( "=" , " = " )
   if 85 - 85: I1IiiI % i11iIiiIii
   if ( II1IiI11I1 not in IIIiIi11 ) :
    OooOo0OOO = False
    if ( len ( IIIiIi11 ) > 1 ) : break
    continue
    if 23 - 23: i11iIiiIii * I1ii11iIi11i % OoO0O00 % ooOoO0o % OoOoOO00
   OooOo0OOO = True
   if 71 - 71: i1IIi * Ii1I + iIii1I11I1II1
   iIOO000O = ( I111i1I1 in I1II )
   if ( iIOO000O ) : break
   if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
   if 63 - 63: ooOoO0o . OOooOOo
  if ( iIOO000O ) : break
  if 66 - 66: I1IiiI
  if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
 O0OoO0OOo . close ( )
 if 60 - 60: I1ii11iIi11i
 if ( not OooOo0OOO ) :
  return ( [ { I111i1I1 : [ { "?" : "not-found" } ] } ] )
  if 78 - 78: oO0o + II111iiii
  if 55 - 55: OoooooooOO
 O0OoO0OOo = open ( o0O000O00o , "r" )
 if 90 - 90: I1IiiI
 iiooo = o0O000O00o + ".temp"
 iIiI111ii1Ii = open ( iiooo , "w" )
 if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
 if 30 - 30: IiII
 if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
 if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
 if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
 OooOo0OOO = False
 for OOo00OoO in O0OoO0OOo :
  if ( OOo00OoO . find ( I111i1I1 ) != - 1 ) : IIiI1IiI1iIi1 -= 1
  if ( IIiI1IiI1iIi1 == 0 and not OooOo0OOO ) :
   if ( OOo00OoO [ 0 ] == "}" ) : OooOo0OOO = True
   continue
   if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
  iIiI111ii1Ii . write ( OOo00OoO )
  if 84 - 84: OoOoOO00 - I11i
  if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
 iIiI111ii1Ii . close ( )
 O0OoO0OOo . close ( )
 if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
 os . system ( "cp {} {}" . format ( iiooo , o0O000O00o ) )
 os . system ( "rm {}" . format ( iiooo ) )
 return ( [ { I111i1I1 : [ { "!" : "delete" } ] } ] )
 if 68 - 68: OoooooooOO * I11i
 if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
 if 40 - 40: iII111i
 if 62 - 62: ooOoO0o / OOooOOo
 if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
 if 92 - 92: I11i % I1Ii111
 if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
 if 94 - 94: I11i
 if 37 - 37: oO0o
def lisp_u2a_walk_dict_array ( adata , a_dict ) :
 for oo000O0o in a_dict :
  if ( type ( a_dict [ oo000O0o ] ) == dict ) :
   OOooO00ooOo0O = { }
   oo00oO0O0 = a_dict [ oo000O0o ]
   for II11IIII1 in oo00oO0O0 : OOooO00ooOo0O [ str ( II11IIII1 ) ] = str ( oo00oO0O0 [ II11IIII1 ] )
   adata [ str ( oo000O0o ) ] = OOooO00ooOo0O
  else :
   adata [ str ( oo000O0o ) ] = str ( a_dict [ oo000O0o ] )
   if 58 - 58: OoOoOO00 . i11iIiiIii + I11i - II111iiii - iII111i . i1IIi
   if 31 - 31: I1IiiI + I1IiiI
 return
 if 11 - 11: IiII + OoOoOO00 % o0oOOo0O0Ooo * OoO0O00 / IiII
 if 5 - 5: iII111i / oO0o % ooOoO0o . i11iIiiIii % OoOoOO00 + oO0o
 if 95 - 95: I1ii11iIi11i
 if 48 - 48: I11i
 if 14 - 14: iIii1I11I1II1 / o0oOOo0O0Ooo * IiII
 if 35 - 35: iIii1I11I1II1
 if 34 - 34: OoO0O00 % I1IiiI . o0oOOo0O0Ooo % OoO0O00 % OoO0O00
def lisp_unicode_to_ascii ( udata ) :
 iII11II = ( type ( udata ) == dict )
 if ( iII11II ) : udata = [ udata ]
 if 59 - 59: I1IiiI % oO0o % iIii1I11I1II1 / I1Ii111 * iII111i * OoO0O00
 i1i1IiIi1i11 = [ ]
 for OooOooOOooo0 in udata :
  o0OO00oOO = { }
  if 45 - 45: iIii1I11I1II1 - Oo0Ooo . I11i - Oo0Ooo / ooOoO0o / o0oOOo0O0Ooo
  if ( type ( OooOooOOooo0 ) == dict ) :
   lisp_u2a_walk_dict_array ( o0OO00oOO , OooOooOOooo0 )
  elif ( type ( OooOooOOooo0 ) == list ) :
   o00oooo0 = [ ]
   for iIi in OooOooOOooo0 :
    ii1Ii = { }
    lisp_u2a_walk_dict_array ( ii1Ii , iIi )
    o00oooo0 . append ( ii1Ii )
    if 17 - 17: O0 - Ii1I + IiII
   o0OO00oOO = o00oooo0
  else :
   o0OO00oOO = { str ( list ( OooOooOOooo0 . keys ( ) ) [ 0 ] ) : o0OO00oOO }
   if 49 - 49: Oo0Ooo % oO0o
  i1i1IiIi1i11 . append ( o0OO00oOO )
  if 49 - 49: I1Ii111 * oO0o / o0oOOo0O0Ooo
  if 78 - 78: IiII + I11i - o0oOOo0O0Ooo + OoO0O00 / iIii1I11I1II1
 if ( iII11II ) : i1i1IiIi1i11 = i1i1IiIi1i11 [ 0 ]
 return ( i1i1IiIi1i11 )
 if 47 - 47: OOooOOo
 if 20 - 20: I1Ii111 % ooOoO0o - I1Ii111 * OoooooooOO / I1ii11iIi11i
 if 57 - 57: IiII % I11i * OOooOOo % I1ii11iIi11i
 if 65 - 65: i1IIi - OoooooooOO
 if 66 - 66: I1ii11iIi11i / i1IIi * I1IiiI - OoOoOO00 + oO0o
 if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
 if 19 - 19: IiII % OoooooooOO + OoooooooOO
 if 7 - 7: i1IIi
 if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
 if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
 if 80 - 80: IiII % OoooooooOO - IiII
 if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
def lisp_replace_db_list ( db ) :
 O0OO0O = - 1
 for IIIiIIi111 in lisp . lisp_db_list :
  if ( db . match_eid_tuple ( IIIiIIi111 ) ) :
   O0OO0O = lisp . lisp_db_list . index ( IIIiIIi111 )
   break
   if 77 - 77: I1IiiI / I1Ii111
   if 65 - 65: I1ii11iIi11i * O0 . OoooooooOO * I11i / IiII
 if ( O0OO0O == - 1 ) : return ( False )
 if 87 - 87: iIii1I11I1II1
 if 58 - 58: I1ii11iIi11i % i11iIiiIii + OoOoOO00 / I11i - OoooooooOO
 if 62 - 62: OoO0O00 . OoOoOO00
 if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
 if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
 if ( lisp . lisp_nat_traversal and lisp . lisp_i_am_etr ) :
  for i11 in IIIiIIi111 . rloc_set :
   if ( i11 . is_rloc_translated ( ) == False ) : continue
   IiIiI = db . get_rloc_by_interface ( i11 . interface )
   if ( IiIiI == None ) : continue
   IiIiI . store_translated_rloc ( i11 . translated_rloc , i11 . translated_port )
   IiIiI . rloc_name = i11 . rloc_name
   if 41 - 41: OoooooooOO
   if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
   if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
 lisp . lisp_db_list [ O0OO0O ] = db
 return ( True )
 if 78 - 78: Ii1I
 if 29 - 29: II111iiii
 if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
 if 84 - 84: Oo0Ooo % I11i * O0 * I11i
 if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
 if 12 - 12: Oo0Ooo + I1IiiI
 if 37 - 37: i1IIi * i11iIiiIii
def lisp_map_server_command ( kv_pairs ) :
 Oo00OOooOoO = [ ]
 II1iiiiI1Ii11 = [ ]
 O0oo = 0
 III1II1iiI11 = 0
 o0O0OO = ""
 iiIi = False
 ooO00Oo = False
 IIiI1iiIII1 = False
 oo0OooOoOo = False
 iIIii1i1iIiI = 0
 oOooooo = None
 OO00 = 0
 iI1iII1 = None
 if 70 - 70: ooOoO0o . OoO0O00 + I1IiiI
 for IiII1II11I in list ( kv_pairs . keys ( ) ) :
  oo00oO0O0 = kv_pairs [ IiII1II11I ]
  if ( IiII1II11I == "ms-name" ) :
   oOooooo = oo00oO0O0 [ 0 ]
   if 34 - 34: Ii1I % I1ii11iIi11i . iIii1I11I1II1 - II111iiii
  if ( IiII1II11I == "address" ) :
   for i11Ii1 in range ( len ( oo00oO0O0 ) ) :
    Oo00OOooOoO . append ( oo00oO0O0 [ i11Ii1 ] )
    if 2 - 2: o0oOOo0O0Ooo - O0 * Ii1I % IiII
    if 64 - 64: i1IIi . ooOoO0o
  if ( IiII1II11I == "dns-name" ) :
   for i11Ii1 in range ( len ( oo00oO0O0 ) ) :
    II1iiiiI1Ii11 . append ( oo00oO0O0 [ i11Ii1 ] )
    if 7 - 7: oO0o . iII111i - iII111i / I1Ii111 % Oo0Ooo
    if 61 - 61: oO0o - I1ii11iIi11i / iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
  if ( IiII1II11I == "authentication-type" ) :
   III1II1iiI11 = lisp . LISP_SHA_1_96_ALG_ID if ( oo00oO0O0 == "sha1" ) else lisp . LISP_SHA_256_128_ALG_ID if ( oo00oO0O0 == "sha2" ) else ""
   if 10 - 10: i11iIiiIii / OoOoOO00
   if 27 - 27: I1IiiI / OoooooooOO
  if ( IiII1II11I == "authentication-key" ) :
   if ( III1II1iiI11 == 0 ) : III1II1iiI11 = lisp . LISP_SHA_256_128_ALG_ID
   OOO00Oo00o = lisp . lisp_parse_auth_key ( oo00oO0O0 )
   O0oo = list ( OOO00Oo00o . keys ( ) ) [ 0 ]
   o0O0OO = OOO00Oo00o [ O0oo ]
   if 44 - 44: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo % O0 / OoooooooOO . OOooOOo
  if ( IiII1II11I == "proxy-reply" ) :
   iiIi = True if oo00oO0O0 == "yes" else False
   if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
  if ( IiII1II11I == "merge-registrations" ) :
   ooO00Oo = True if oo00oO0O0 == "yes" else False
   if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
  if ( IiII1II11I == "refresh-registrations" ) :
   IIiI1iiIII1 = True if oo00oO0O0 == "yes" else False
   if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
  if ( IiII1II11I == "want-map-notify" ) :
   oo0OooOoOo = True if oo00oO0O0 == "yes" else False
   if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
  if ( IiII1II11I == "site-id" ) :
   iIIii1i1iIiI = int ( oo00oO0O0 )
   if 44 - 44: OoooooooOO
  if ( IiII1II11I == "encryption-key" ) :
   iI1iII1 = lisp . lisp_parse_auth_key ( oo00oO0O0 )
   OO00 = list ( iI1iII1 . keys ( ) ) [ 0 ]
   iI1iII1 = iI1iII1 [ OO00 ]
   if 82 - 82: OoOoOO00 . OoOoOO00
   if 10 - 10: Oo0Ooo * I1ii11iIi11i . oO0o . OoooooooOO . OOooOOo * I1ii11iIi11i
   if 80 - 80: I1Ii111 + I11i . I1Ii111 + OOooOOo
   if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
   if 43 - 43: IiII . OoooooooOO - II111iiii
   if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
 for Ii1I1i in Oo00OOooOoO :
  if ( Ii1I1i == "" ) : continue
  II1Ii = lisp . lisp_ms ( Ii1I1i , None , oOooooo , III1II1iiI11 , O0oo , o0O0OO ,
 iiIi , ooO00Oo , IIiI1iiIII1 , oo0OooOoOo , iIIii1i1iIiI , OO00 , iI1iII1 )
  if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
 for IIiI in II1iiiiI1Ii11 :
  if ( IIiI == "" ) : continue
  II1Ii = lisp . lisp_ms ( None , IIiI , oOooooo , III1II1iiI11 , O0oo , o0O0OO ,
 iiIi , ooO00Oo , IIiI1iiIII1 , oo0OooOoOo , iIIii1i1iIiI , OO00 , iI1iII1 )
  if 11 - 11: ooOoO0o
 return ( II1Ii )
 if 36 - 36: OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
 if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
 if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
 if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
 if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
 if 28 - 28: iIii1I11I1II1 . O0
 if 32 - 32: OoooooooOO
 if 29 - 29: I1ii11iIi11i
def lisp_database_mapping_command ( kv_pair , ephem_port = None , replace = True ) :
 iI111iiI1II = [ ]
 IIo0oo0OO = [ ]
 OOOi1iIIiiIiII = [ ]
 if 96 - 96: OoOoOO00 * O0 - II111iiii . ooOoO0o - Ii1I
 OO0OOO0o0OOO0 = 1
 if ( "address" in kv_pair ) :
  if ( lisp_clause_syntax_error ( kv_pair , "address" , "rloc" ) ) : return
  OO0OOO0o0OOO0 = len ( kv_pair [ "address" ] )
 elif ( "interface" in kv_pair ) :
  if ( lisp_clause_syntax_error ( kv_pair , "interface" , "rloc" ) ) : return
  OO0OOO0o0OOO0 = len ( kv_pair [ "interface" ] )
  if 39 - 39: O0 * I1IiiI
 for i11Ii1 in range ( OO0OOO0o0OOO0 ) :
  i11 = lisp . lisp_rloc ( )
  OOOi1iIIiiIiII . append ( i11 )
  if 27 - 27: iIii1I11I1II1 - oO0o
  if 73 - 73: OOooOOo . Oo0Ooo + Oo0Ooo % Oo0Ooo % O0
 if ( lisp_clause_syntax_error ( kv_pair , "eid-prefix" , "prefix" ) ) : return
 for i11Ii1 in range ( len ( kv_pair [ "eid-prefix" ] ) ) :
  I1OooO0oOoOoO = lisp . lisp_mapping ( "" , "" , OOOi1iIIiiIiII )
  IIo0oo0OO . append ( I1OooO0oOoOoO )
  if 5 - 5: I1IiiI - o0oOOo0O0Ooo . OoooooooOO - II111iiii
  if 38 - 38: Ii1I * I1ii11iIi11i % OoO0O00
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if ( IiII1II11I == "mr-name" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I1OooO0oOoOoO = IIo0oo0OO [ i11Ii1 ]
    I1OooO0oOoOoO . use_mr_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ i11Ii1 ]
    if 50 - 50: Ii1I
    if 27 - 27: Ii1I
  if ( IiII1II11I == "ms-name" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I1OooO0oOoOoO = IIo0oo0OO [ i11Ii1 ]
    I1OooO0oOoOoO . use_ms_name = "all" if oo00oO0O0 [ 0 ] == "" else oo00oO0O0 [ i11Ii1 ]
    if 32 - 32: Ii1I + IiII + I1ii11iIi11i
    if 79 - 79: i1IIi / Ii1I
  if ( IiII1II11I == "instance-id" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I1OooO0oOoOoO = IIo0oo0OO [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    OoO0o0OO = [ "0" ] if ( OoO0o0OO == "" ) else OoO0o0OO . split ( )
    for o0O in OoO0o0OO : OoO0o0OO [ OoO0o0OO . index ( o0O ) ] = int ( o0O )
    I1OooO0oOoOoO . eid . instance_id = OoO0o0OO [ 0 ]
    I1OooO0oOoOoO . eid . iid_list = OoO0o0OO [ 1 : : ]
    I1OooO0oOoOoO . group . instance_id = OoO0o0OO [ 0 ]
    if 80 - 80: IiII % OoO0O00 / O0 % I1IiiI + i1IIi - O0
    if 70 - 70: OoooooooOO . II111iiii / Ii1I * IiII + OOooOOo
  if ( IiII1II11I == "secondary-instance-id" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I1OooO0oOoOoO = IIo0oo0OO [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO == "" ) : continue
    I1OooO0oOoOoO . secondary_iid = int ( OoO0o0OO )
    if ( I1OooO0oOoOoO . eid . address == 0 ) :
     lisp . lisp_default_secondary_iid = int ( OoO0o0OO )
     if 48 - 48: oO0o % iIii1I11I1II1 + OoooooooOO
     if 71 - 71: Oo0Ooo
     if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
  if ( IiII1II11I == "eid-prefix" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I1OooO0oOoOoO = IIo0oo0OO [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) : I1OooO0oOoOoO . eid . store_prefix ( OoO0o0OO )
    if ( I1OooO0oOoOoO . eid . address == 0 ) :
     lisp . lisp_default_secondary_iid = I1OooO0oOoOoO . secondary_iid
     if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
     if 88 - 88: I1Ii111 - OoO0O00
     if 79 - 79: iII111i
  if ( IiII1II11I == "group-prefix" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I1OooO0oOoOoO = IIo0oo0OO [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) : I1OooO0oOoOoO . group . store_prefix ( OoO0o0OO )
    if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
    if 48 - 48: I1ii11iIi11i + Oo0Ooo
  if ( IiII1II11I == "dynamic-eid" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I1OooO0oOoOoO = IIo0oo0OO [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO == "yes" ) : I1OooO0oOoOoO . dynamic_eids = { }
    if 76 - 76: I1ii11iIi11i
    if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
  if ( IiII1II11I == "signature-eid" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    I1OooO0oOoOoO = IIo0oo0OO [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    I1OooO0oOoOoO . signature_eid = ( OoO0o0OO == "yes" )
    if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
    if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
  if ( IiII1II11I == "register-ttl" ) :
   for i11Ii1 in range ( len ( IIo0oo0OO ) ) :
    if ( oo00oO0O0 [ i11Ii1 ] == "" ) : continue
    I1OooO0oOoOoO = IIo0oo0OO [ i11Ii1 ]
    I1OooO0oOoOoO . register_ttl = int ( oo00oO0O0 [ i11Ii1 ] )
    if 82 - 82: OoO0O00
    if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
  if ( IiII1II11I == "priority" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO == "" ) : OoO0o0OO = "0"
    i11 . priority = int ( OoO0o0OO )
    if 17 - 17: OoOoOO00
    if 72 - 72: iII111i . Oo0Ooo - i11iIiiIii / I1IiiI
  if ( IiII1II11I == "weight" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO == "" ) : OoO0o0OO = "0"
    i11 . weight = int ( OoO0o0OO )
    if 64 - 64: oO0o
    if 80 - 80: o0oOOo0O0Ooo % iIii1I11I1II1
  if ( IiII1II11I == "address" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) : i11 . rloc . store_address ( OoO0o0OO )
    if 63 - 63: IiII * i11iIiiIii
    if 86 - 86: I11i % I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
  if ( IiII1II11I == "interface" ) :
   O0I11i1i11i1I = lisp . lisp_hostname
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) :
     i11 . interface = OoO0o0OO
     II = lisp . lisp_get_interface_address ( OoO0o0OO )
     if ( II ) :
      i11 . rloc . copy_address ( II )
      lisp . lisp_myrlocs [ 0 ] = II
      if 26 - 26: II111iiii * iII111i + o0oOOo0O0Ooo / O0 + i1IIi - I11i
     i11 . rloc_name = O0I11i1i11i1I
     iI111iiI1II . append ( i11 )
     if 56 - 56: OOooOOo
     if 76 - 76: i1IIi % iIii1I11I1II1 - o0oOOo0O0Ooo + IiII - I11i
     if 81 - 81: I1ii11iIi11i + OoooooooOO - OOooOOo * O0
  if ( IiII1II11I == "elp-name" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) : i11 . elp_name = OoO0o0OO
    if 100 - 100: iIii1I11I1II1 - OoOoOO00
    if 28 - 28: Oo0Ooo . O0 . I11i
  if ( IiII1II11I == "rle-name" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) : i11 . rle_name = OoO0o0OO
    if 60 - 60: II111iiii + I1Ii111 / oO0o % OoooooooOO - i1IIi
    if 57 - 57: ooOoO0o
  if ( IiII1II11I == "json-name" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) : i11 . json_name = OoO0o0OO
    if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
    if 52 - 52: I1ii11iIi11i
  if ( IiII1II11I == "geo-name" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) : i11 . geo_name = OoO0o0OO
    if 93 - 93: iII111i . i11iIiiIii
    if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
  if ( IiII1II11I == "rloc-record-name" ) :
   for i11Ii1 in range ( len ( OOOi1iIIiiIiII ) ) :
    i11 = OOOi1iIIiiIiII [ i11Ii1 ]
    OoO0o0OO = oo00oO0O0 [ i11Ii1 ]
    if ( OoO0o0OO != "" ) : i11 . rloc_name = OoO0o0OO
    if 49 - 49: O0 . Oo0Ooo / Ii1I
    if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
    if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
    if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
    if 44 - 44: i11iIiiIii
    if 69 - 69: OOooOOo * O0 + i11iIiiIii
    if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
    if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
    if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
    if 63 - 63: oO0o
 if ( len ( iI111iiI1II ) > 1 ) :
  for i11 in iI111iiI1II :
   i11 . rloc_name = O0I11i1i11i1I + "-" + i11 . interface
   if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
   if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
   if 60 - 60: I1Ii111
   if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
   if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
   if 14 - 14: Ii1I - O0
 for I1OooO0oOoOoO in IIo0oo0OO :
  I1OooO0oOoOoO . rloc_set = copy . deepcopy ( I1OooO0oOoOoO . rloc_set )
  I1OooO0oOoOoO . sort_rloc_set ( )
  I1OooO0oOoOoO . add_db ( )
  if ( replace and lisp_replace_db_list ( I1OooO0oOoOoO ) ) : continue
  lisp . lisp_db_list . append ( I1OooO0oOoOoO )
  if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
  if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
  if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
  if 7 - 7: IiII * ooOoO0o + OoOoOO00
  if 22 - 22: iII111i
 lisp . lisp_write_ipc_database_mappings ( ephem_port )
 if 48 - 48: I1ii11iIi11i . I1IiiI
 if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
 if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
 if 49 - 49: Oo0Ooo
 if 57 - 57: O0 * ooOoO0o - iII111i - iIii1I11I1II1 * iII111i
 if 9 - 9: IiII . I11i
 if 23 - 23: O0 % OoooooooOO - O0 . I1IiiI + i11iIiiIii
 lisp . lisp_default_iid = lisp . lisp_db_list [ 0 ] . eid . instance_id
 if 96 - 96: ooOoO0o % O0
 if 51 - 51: I1IiiI - iII111i / I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i
 if 87 - 87: II111iiii . Ii1I * OoO0O00
 if 74 - 74: o0oOOo0O0Ooo % OoOoOO00 . iII111i % I1Ii111 . O0 % II111iiii
 if 5 - 5: oO0o - OoooooooOO / OoOoOO00
 if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
 if 55 - 55: OoO0O00
 if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
 for I1OooO0oOoOoO in IIo0oo0OO :
  if ( I1OooO0oOoOoO . eid . address == 0 and I1OooO0oOoOoO . eid . mask_len == 0 ) :
   if ( I1OooO0oOoOoO . eid . is_ipv4 ( ) or I1OooO0oOoOoO . eid . is_ipv6 ( ) ) :
    lisp . lisp_pitr = True
    break
    if 32 - 32: Ii1I * oO0o
    if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
    if 28 - 28: Oo0Ooo
  if ( I1OooO0oOoOoO . dynamic_eids == None ) : continue
  if ( I1OooO0oOoOoO . eid . is_mac ( ) and I1OooO0oOoOoO . eid . address == 0 and I1OooO0oOoOoO . eid . mask_len == 0 ) :
   lisp . lisp_l2_overlay = True
   break
   if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
   if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
   if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
   if 69 - 69: I11i
   if 17 - 17: I11i
   if 38 - 38: I1Ii111 % OOooOOo
   if 9 - 9: O0 . iIii1I11I1II1
   if 44 - 44: I1ii11iIi11i % IiII
 i11iii1 = ( lisp . lisp_myrlocs [ 0 ] != None )
 lisp . lisp_get_local_addresses ( )
 if 19 - 19: OOooOOo * II111iiii % oO0o - II111iiii . OoOoOO00 * Ii1I
 if ( lisp . lisp_myrlocs [ 0 ] == None and i11iii1 ) :
  lisp . lprint ( "No RLOCs found, local addresses changed from RLOC to EID" )
  if 71 - 71: I1ii11iIi11i + I11i * Oo0Ooo - i1IIi . O0 % i11iIiiIii
  if 40 - 40: ooOoO0o - i11iIiiIii % I1ii11iIi11i % I1IiiI . IiII * OoO0O00
  if 51 - 51: O0 % oO0o - ooOoO0o * I1IiiI * oO0o
  if 90 - 90: Ii1I + Oo0Ooo / iIii1I11I1II1 - O0 + ooOoO0o . I1ii11iIi11i
  if 58 - 58: OoO0O00 + iII111i * o0oOOo0O0Ooo . I11i
  if 48 - 48: OOooOOo
  if 25 - 25: OOooOOo / ooOoO0o % OOooOOo
  if 58 - 58: ooOoO0o - Oo0Ooo
  if 23 - 23: OoOoOO00
  if 38 - 38: I1IiiI . oO0o / O0 % Oo0Ooo / IiII / OoooooooOO
  if 11 - 11: O0 / I1Ii111 / iIii1I11I1II1 % Ii1I
  if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
  if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
  if 93 - 93: ooOoO0o % I1Ii111
  if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  if 43 - 43: ooOoO0o . i1IIi
  if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
  if 45 - 45: I1IiiI
  if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
  if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
  if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
 if ( lisp . lisp_program_hardware == False ) : return
 if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
 OooOo0OOO = False
 for I1OooO0oOoOoO in IIo0oo0OO :
  if ( I1OooO0oOoOoO . dynamic_eids == None ) : continue
  oO0OO00o = I1OooO0oOoOoO . eid . print_prefix_no_iid ( )
  OooOo0OOO = lisp . lisp_i_am_itr
  os . system ( "ip route add {} dev ma1" . format ( oO0OO00o ) )
  if 97 - 97: O0 . o0oOOo0O0Ooo
 if ( lisp . lisp_program_hardware and OooOo0OOO ) :
  OOO = "platform trident diag s cpu_control_1 URPF_MISS_TOCPU=1"
  lisp . lisp_send_to_arista ( OOO , None )
  if 17 - 17: O0 . oO0o - oO0o - i1IIi * OOooOOo
  if 16 - 16: OoOoOO00 / II111iiii
  if 22 - 22: I11i
  if 53 - 53: OoO0O00
  if 96 - 96: OoooooooOO - iIii1I11I1II1 . oO0o
  if 2 - 2: i1IIi
  if 6 - 6: i1IIi % I11i . IiII + IiII . I11i / i11iIiiIii
  if 78 - 78: O0
def lisp_show_db_list ( itr_or_etr , output ) :
 Iiii = "{} database-mapping entries" . format ( len ( lisp . lisp_db_list ) )
 i1i11ii1 = "LISP-{} Configured Database Mappings:" . format ( itr_or_etr )
 i1i11ii1 = lisp . lisp_span ( i1i11ii1 , Iiii )
 if 34 - 34: II111iiii
 OOOoOo0O0O = '<a href="/lisp/show/etr/keys"><br>RLOC Keys</a>'
 if 20 - 20: I1IiiI % i1IIi % OoOoOO00 % I1Ii111 + O0
 if ( itr_or_etr == "ITR" ) :
  output += lisp_table_header ( i1i11ii1 , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Use MR" )
 else :
  output += lisp_table_header ( i1i11ii1 , "EID-Prefix Record" ,
 "Uptime" , "RLOC Record" + OOOoOo0O0O , "Unicast<br>Priority/Weight" ,
 "Multicast<br>Priority/Weight" , "Receive Stats" ,
 "Map-Replies<br>Sent" , "Use MS" )
  if 54 - 54: O0
  if 3 - 3: I1ii11iIi11i
 for I1OooO0oOoOoO in lisp . lisp_db_list :
  I1III1i1Ii = lisp . lisp_print_elapsed ( I1OooO0oOoOoO . uptime )
  o00oOoO0ooOO = I1OooO0oOoOoO . map_replies_sent
  if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
  if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
  if 66 - 66: ooOoO0o + oO0o % OoooooooOO
  if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
  iiiiiIi1II1i = ""
  if ( I1OooO0oOoOoO . dynamic_eid_configured ( ) ) :
   II1II11I11ii = I1OooO0oOoOoO . eid . print_prefix_url ( )
   iiiI1IiI = len ( I1OooO0oOoOoO . dynamic_eids )
   O0oOo = itr_or_etr . lower ( )
   iiiiiIi1II1i = ( "<br><a href='/lisp/show/{}/dynamic-eid/{}'>" + "{} dynamic-eids</a>" ) . format ( O0oOo , II1II11I11ii , iiiI1IiI )
   if 32 - 32: oO0o . II111iiii % I1IiiI / iIii1I11I1II1 / ooOoO0o
   if 99 - 99: OoooooooOO * O0 + i1IIi - i1IIi / iII111i % i1IIi
   if 8 - 8: o0oOOo0O0Ooo * Oo0Ooo + Oo0Ooo % I11i + I1ii11iIi11i * II111iiii
  i11i11I1I = True
  for i11 in I1OooO0oOoOoO . rloc_set :
   if ( i11i11I1I ) :
    i1I1II1 = I1OooO0oOoOoO . print_eid_tuple ( )
    i1I1II1 = I1OooO0oOoOoO . star_secondary_iid ( i1I1II1 )
    i1I1II1 += iiiiiIi1II1i
    oO0OOoO0 = I1III1i1Ii
    i11i11I1I = False
   else :
    i1I1II1 , oO0OOoO0 , o00oOoO0ooOO = ( "" , "" , "" )
    if 7 - 7: O0 / I1IiiI
    if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
   OOOOoO0 = "" if i11 . rloc . is_null ( ) else i11 . rloc . print_address_no_iid ( )
   if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
   if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
   if ( i11 . interface != None ) :
    OOOOoO0 += " ({})" . format ( i11 . interface )
    if 59 - 59: I1Ii111 * iII111i
   if ( OOOOoO0 != "" ) : OOOOoO0 += "<br>"
   if 31 - 31: I11i / O0
   if ( i11 . translated_rloc . not_set ( ) == False ) :
    OOOOoO0 += "translated RLOC: {}<br>" . format ( i11 . translated_rloc . print_address_no_iid ( ) )
    if 57 - 57: i1IIi % ooOoO0o
    if 69 - 69: o0oOOo0O0Ooo
    if 69 - 69: I1Ii111
   OoOoooO0o0O00o0O = i11 . print_rloc_name ( True )
   if ( OoOoooO0o0O00o0O != "" ) : OOOOoO0 += OoOoooO0o0O00o0O + "<br>"
   if 68 - 68: OoOoOO00
   if ( i11 . geo_name != None ) :
    OOOOoO0 += "geo: " + i11 . geo_name + "<br>"
    if 65 - 65: oO0o
   if ( i11 . elp_name != None ) :
    OOOOoO0 += "elp: " + i11 . elp_name + "<br>"
    if 82 - 82: o0oOOo0O0Ooo
   if ( i11 . rle_name != None ) :
    OOOOoO0 += "rle: " + i11 . rle_name + "<br>"
    if 80 - 80: i1IIi % OoOoOO00 + OoO0O00 - OoooooooOO / iIii1I11I1II1 + I1Ii111
   if ( i11 . json_name != None ) :
    OOOOoO0 += "json: " + i11 . json_name + "<br>"
    if 65 - 65: Ii1I
    if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
   if ( itr_or_etr == "ITR" ) :
    output += lisp_table_row ( i1I1II1 , oO0OOoO0 , OOOOoO0 ,
 str ( i11 . priority ) + "/" + str ( i11 . weight ) ,
 str ( i11 . mpriority ) + "/" + str ( i11 . mweight ) ,
 I1OooO0oOoOoO . use_mr_name )
   else :
    OO0oo = i11 . stats . get_stats ( True , True )
    output += lisp_table_row ( i1I1II1 , oO0OOoO0 , OOOOoO0 ,
 str ( i11 . priority ) + "/" + str ( i11 . weight ) ,
 str ( i11 . mpriority ) + "/" + str ( i11 . mweight ) , OO0oo ,
 o00oOoO0ooOO , I1OooO0oOoOoO . use_ms_name )
    if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
    if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
    if 78 - 78: oO0o % OoooooooOO
 output += lisp_table_footer ( )
 if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
 if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
 if 37 - 37: IiII % Ii1I % i1IIi
 if 23 - 23: ooOoO0o - O0 + i11iIiiIii
 if ( len ( lisp . lisp_geo_list ) != 0 ) :
  i1i11ii1 = "Configured Geo-Coordinates:"
  output += lisp_table_header ( i1i11ii1 , "Geo Name" ,
 "Geo-Prefix or Geo-Point" )
  oO0ooOoOooO00o00 = sorted ( lisp . lisp_geo_list )
  for I1i1Ii in oO0ooOoOooO00o00 :
   III1 = lisp . lisp_geo_list [ I1i1Ii ]
   output += lisp_table_row ( I1i1Ii , III1 . print_geo_url ( ) )
   if 64 - 64: IiII . OOooOOo
  output += lisp_table_footer ( )
  if 85 - 85: II111iiii % Ii1I * OoOoOO00
 return ( output )
 if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
 if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
 if 87 - 87: OoO0O00 * Oo0Ooo
 if 83 - 83: i1IIi * I1Ii111 - IiII / Ii1I
 if 48 - 48: oO0o . II111iiii - OoOoOO00 % i1IIi . OoOoOO00
 if 32 - 32: Ii1I * I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
 if 67 - 67: OoOoOO00 % Oo0Ooo
def lisp_interface_command ( kv_pair ) :
 IiiI11III1i = None
 OOo0o0 = None
 oOOoO = None
 iIiiI = None
 ooo0O0O0OO = None
 oOooOOoO = None
 o0o000OOO = None
 I1111iii1ii11 = None
 if 79 - 79: iIii1I11I1II1 / iIii1I11I1II1 . iII111i . Ii1I
 for IiII1II11I in list ( kv_pair . keys ( ) ) :
  oo00oO0O0 = kv_pair [ IiII1II11I ]
  if ( IiII1II11I == "interface-name" ) : IiiI11III1i = oo00oO0O0
  if ( IiII1II11I == "device" ) : OOo0o0 = oo00oO0O0
  if ( IiII1II11I == "instance-id" ) : oOOoO = oo00oO0O0
  if ( IiII1II11I == "dynamic-eid" ) : iIiiI = oo00oO0O0
  if ( IiII1II11I == "multi-tenant-eid" ) : o0o000OOO = oo00oO0O0
  if ( IiII1II11I == "dynamic-eid-device" ) : ooo0O0O0OO = oo00oO0O0
  if ( IiII1II11I == "dynamic-eid-timeout" ) : oOooOOoO = oo00oO0O0
  if ( IiII1II11I == "lisp-nat" ) : I1111iii1ii11 = ( oo00oO0O0 == "yes" )
  if 49 - 49: I1ii11iIi11i * I1Ii111 + OoOoOO00
  if 72 - 72: OoO0O00
 if ( OOo0o0 == None ) : return
 if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
 if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
 if 70 - 70: I11i . I1ii11iIi11i * oO0o
 if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
 if 23 - 23: I1ii11iIi11i % I11i
 if 18 - 18: OoooooooOO . i1IIi + II111iiii
 if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
 if 34 - 34: I1Ii111 * I11i
 if ( OOo0o0 in lisp . lisp_myinterfaces and o0o000OOO == None ) :
  i1oO0o00oOo00oO = lisp . lisp_myinterfaces [ OOo0o0 ]
 else :
  i1oO0o00oOo00oO = lisp . lisp_interface ( OOo0o0 )
  lisp . lisp_myinterfaces [ OOo0o0 ] = i1oO0o00oOo00oO
  if 68 - 68: iIii1I11I1II1 - I1IiiI . oO0o + OoOoOO00
  if 94 - 94: o0oOOo0O0Ooo % o0oOOo0O0Ooo % II111iiii * iIii1I11I1II1 / IiII . I1ii11iIi11i
  if 13 - 13: OoOoOO00 . I1IiiI . o0oOOo0O0Ooo * oO0o / Ii1I
  if 38 - 38: IiII - i1IIi . i11iIiiIii
  if 28 - 28: I1Ii111 / oO0o . I1ii11iIi11i
 i1oO0o00oOo00oO . interface_name = IiiI11III1i
 if ( oOOoO != None ) :
  if ( oOOoO . isdigit ( ) == False ) : oOOoO = "0"
  i1oO0o00oOo00oO . instance_id = int ( oOOoO )
  if 83 - 83: I11i
 if ( iIiiI != None ) :
  i1oO0o00oOo00oO . dynamic_eid . store_prefix ( iIiiI )
  i1oO0o00oOo00oO . dynamic_eid . instance_id = i1oO0o00oOo00oO . instance_id
  if 36 - 36: iIii1I11I1II1
 if ( ooo0O0O0OO != None ) :
  i1oO0o00oOo00oO . dynamic_eid_device = ooo0O0O0OO
  if 74 - 74: IiII * I1ii11iIi11i - OoooooooOO
 if ( oOooOOoO != None ) :
  i1oO0o00oOo00oO . dynamic_eid_timeout = int ( oOooOOoO )
  if 59 - 59: ooOoO0o * OoO0O00 - I1Ii111 % oO0o
 if ( o0o000OOO != None ) :
  i1oO0o00oOo00oO . multi_tenant_eid . store_prefix ( o0o000OOO )
  i1oO0o00oOo00oO . multi_tenant_eid . instance_id = int ( i1oO0o00oOo00oO . instance_id )
  lisp . lisp_multi_tenant_interfaces . append ( i1oO0o00oOo00oO )
  if 95 - 95: II111iiii + II111iiii
 if ( I1111iii1ii11 ) :
  iiI = "sudo iptables -t nat -C POSTROUTING -o {} -j MASQUERADE"
  iiI = getoutput ( iiI . format ( OOo0o0 ) )
  if ( iiI != "" ) :
   Ii1i1 = lisp . lisp_get_loopback_address ( )
   if ( Ii1i1 ) :
    IIiIoOOO = "sudo iptables -t nat -A POSTROUTING -s {} -j ACCEPT"
    os . system ( IIiIoOOO . format ( Ii1i1 ) )
    if 70 - 70: iII111i + i11iIiiIii % ooOoO0o % I11i - IiII
   IIiIoOOO = "sudo iptables -t nat -A POSTROUTING -o {} -j MASQUERADE"
   os . system ( IIiIoOOO . format ( OOo0o0 ) )
   os . system ( "sudo sysctl net.ipv4.ip_forward=1" )
   if 57 - 57: ooOoO0o % OoooooooOO
   if 81 - 81: OOooOOo
   if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
 lisp . lisp_iid_to_interface [ oOOoO ] = i1oO0o00oOo00oO
 if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
 if 20 - 20: ooOoO0o
 if 63 - 63: iIii1I11I1II1 . OoO0O00
 if 100 - 100: i1IIi * i1IIi
 if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
 if ( "SO_BINDTODEVICE" in dir ( socket ) ) : i1oO0o00oOo00oO . set_socket ( OOo0o0 )
 if ( "PF_PACKET" in dir ( socket ) ) : i1oO0o00oOo00oO . set_bridge_socket ( OOo0o0 )
 if 94 - 94: IiII
 if 15 - 15: Ii1I - IiII / O0
 if 28 - 28: I1Ii111 . i1IIi / I1ii11iIi11i
 if 77 - 77: i11iIiiIii / I1Ii111 / i11iIiiIii % OoOoOO00 - I1Ii111
 lisp . lisp_get_local_addresses ( )
 if 80 - 80: I1Ii111 % OoOoOO00 . OoooooooOO . II111iiii % IiII
 if 6 - 6: I1Ii111 % IiII / Ii1I + I1Ii111 . oO0o
 if 70 - 70: iIii1I11I1II1 / Ii1I
 if 61 - 61: O0 * o0oOOo0O0Ooo + I1Ii111 - OOooOOo . I1IiiI - IiII
 if 7 - 7: I1ii11iIi11i
 if 81 - 81: Oo0Ooo % II111iiii % o0oOOo0O0Ooo / I11i
 if ( iIiiI != None and lisp . lisp_program_hardware ) :
  OOO = "ip verify unicast source reachable-via rx"
  lisp . lisp_send_to_arista ( OOO , OOo0o0 )
  OOO = 'sysctl -w "net.ipv4.conf.{}.rp_filter=0"' . format ( OOo0o0 )
  os . system ( OOO )
  if 95 - 95: OoOoOO00 - O0 % OoooooooOO
  if 13 - 13: i11iIiiIii
  if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
  if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
  if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
 lisp . lisp_write_ipc_interfaces ( )
 return
 if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
 if 69 - 69: Oo0Ooo * ooOoO0o
 if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
 if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
 if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
 if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
 if 24 - 24: OoOoOO00 * Ii1I
 if 17 - 17: OoO0O00 . I1IiiI * O0
def lisp_parse_eid_in_url ( command , eid_prefix ) :
 I11iiI1i1 = ""
 if 81 - 81: OOooOOo
 if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
 if 41 - 41: I11i + OoO0O00 . iII111i
 if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
 if ( eid_prefix == "0--0" ) :
  command = command + "%[0]/0%"
 elif ( eid_prefix . find ( "-name-" ) != - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if ( len ( eid_prefix ) > 4 ) :
   eid_prefix = [ eid_prefix [ 0 ] , "name" , "-" . join ( eid_prefix [ 2 : - 1 ] ) ,
 eid_prefix [ - 1 ] ]
   if 56 - 56: i1IIi
   if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
   if 82 - 82: IiII
   if 10 - 10: Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
   if 54 - 54: i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i / I1IiiI . iIii1I11I1II1 / iII111i
  OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]'" + eid_prefix [ 2 ] + "'" + "/" + eid_prefix [ 3 ]
  if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
  command = command + "%" + OOOO0oo0 + "%"
 elif ( eid_prefix . count ( "-" ) in [ 9 , 10 ] ) :
  if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
  if 30 - 30: I11i - OoO0O00
  if 15 - 15: OoooooooOO
  if 31 - 31: II111iiii
  eid_prefix = eid_prefix . split ( "-" )
  OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + "-" . join ( eid_prefix [ 1 : - 1 ] ) + "/" + eid_prefix [ - 1 ]
  if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
  command = command + "%" + OOOO0oo0 + "%"
 elif ( eid_prefix . find ( "." ) == - 1 and eid_prefix . find ( ":" ) == - 1 ) :
  eid_prefix = eid_prefix . split ( "-" )
  if 87 - 87: IiII
  if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
  if 55 - 55: IiII
  if 43 - 43: OOooOOo
  if ( eid_prefix [ 1 ] == "plus" ) :
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]+" + eid_prefix [ 2 ] + "/" + eid_prefix [ 3 ]
   if 17 - 17: i11iIiiIii
   command = command + "%" + OOOO0oo0 + "%"
  else :
   if 94 - 94: OoooooooOO - IiII + oO0o . OoooooooOO / i1IIi
   if 53 - 53: I1Ii111 % I1ii11iIi11i
   if 17 - 17: OoooooooOO % Ii1I % O0
   if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "-" + eid_prefix [ 2 ] + "-" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
   if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
   if 80 - 80: oO0o / O0
   if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
   if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
   if ( len ( eid_prefix ) == 10 ) :
    I11iiI1i1 = "[" + eid_prefix [ 5 ] + "]" + eid_prefix [ 6 ] + "-" + eid_prefix [ 7 ] + "-" + eid_prefix [ 8 ] + "/" + eid_prefix [ 9 ]
    if 59 - 59: IiII
    command = command + "%" + OOOO0oo0 + "%" + I11iiI1i1
   else :
    command = command + "%" + OOOO0oo0 + "%"
    if 54 - 54: OOooOOo
    if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
    if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
 else :
  if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
  if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
  if 33 - 33: oO0o % OoO0O00 . iIii1I11I1II1 / IiII
  if 3 - 3: Ii1I + OoO0O00
  eid_prefix = eid_prefix . split ( "-" )
  if ( eid_prefix [ 1 ] == "*" ) :
   OOOO0oo0 = ""
   I11iiI1i1 = "[" + eid_prefix [ 2 ] + "]" + eid_prefix [ 3 ] + "/" + eid_prefix [ 4 ]
   if 60 - 60: OoO0O00 . OoOoOO00 - I1ii11iIi11i - I1IiiI - II111iiii % Oo0Ooo
  else :
   OOOO0oo0 = "[" + eid_prefix [ 0 ] + "]" + eid_prefix [ 1 ] + "/" + eid_prefix [ 2 ]
   if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
   if ( len ( eid_prefix ) == 6 ) :
    I11iiI1i1 = "[" + eid_prefix [ 3 ] + "]" + eid_prefix [ 4 ] + "/" + eid_prefix [ 5 ]
    if 47 - 47: I1Ii111 + I1IiiI
    if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
    if 80 - 80: oO0o
  command = command + "%" + OOOO0oo0 + "%" + I11iiI1i1
  if 81 - 81: OoooooooOO / ooOoO0o * iIii1I11I1II1 . Oo0Ooo + oO0o / O0
 return ( command )
 if 84 - 84: II111iiii - o0oOOo0O0Ooo
 if 78 - 78: IiII
 if 58 - 58: i11iIiiIii - OoOoOO00
 if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
 if 99 - 99: ooOoO0o . Ii1I
 if 92 - 92: i1IIi
 if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
def lisp_show_dynamic_eid_command ( parm ) :
 I1i1iii = ""
 if ( parm == "" ) : return ( I1i1iii )
 if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
 Ii11II11iI1 = lisp_get_lookup_string ( parm . split ( "%" ) [ 0 ] )
 Ii11II11iI1 = Ii11II11iI1 [ 0 ]
 if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
 I1OooO0oOoOoO = lisp . lisp_db_for_lookups . lookup_cache ( Ii11II11iI1 , False )
 if ( I1OooO0oOoOoO == None ) : return ( I1i1iii )
 if 4 - 4: Ii1I
 O0oOo = "ITR" if lisp . lisp_i_am_itr else "ETR"
 OOOO0oo0 = I1OooO0oOoOoO . print_eid_tuple ( )
 if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
 i1i11ii1 = "LISP-{} Discovered Dynamic EIDs for {}:" . format ( O0oOo , OOOO0oo0 )
 if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
 if ( O0oOo == "ITR" ) :
  I1i1iii = lisp_table_header ( i1i11ii1 , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Last Packet" , "Inactivity Timeout" )
 else :
  I1i1iii = lisp_table_header ( i1i11ii1 , "Dynamic-EID" , "Interface" , "Uptime" ,
 "Inactivity Timeout" )
  if 32 - 32: I1Ii111 / oO0o / I1IiiI
  if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
 for oO0OO00o in list ( I1OooO0oOoOoO . dynamic_eids . values ( ) ) :
  Ii11II11iI1 = oO0OO00o . dynamic_eid . print_address ( )
  oOoo0ooo0 = lisp . lisp_print_elapsed ( oO0OO00o . uptime )
  ooo00o0OO0 = str ( oO0OO00o . timeout ) + " secs"
  if ( O0oOo == "ITR" ) :
   oO0OOOo0OO = lisp . lisp_print_elapsed ( oO0OO00o . last_packet )
   I1i1iii += lisp_table_row ( Ii11II11iI1 , oO0OO00o . interface , oOoo0ooo0 , oO0OOOo0OO , ooo00o0OO0 )
  else :
   I1i1iii += lisp_table_row ( Ii11II11iI1 , oO0OO00o . interface , oOoo0ooo0 , ooo00o0OO0 )
   if 25 - 25: OOooOOo / OoooooooOO - I1ii11iIi11i
   if 31 - 31: I11i + OoO0O00 / I1IiiI * O0 + O0
 I1i1iii += lisp_table_footer ( )
 return ( I1i1iii )
 if 34 - 34: IiII
 if 5 - 5: OoO0O00 . I1IiiI
 if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
 if 47 - 47: iII111i / OoooooooOO - II111iiii
 if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
 if 23 - 23: i1IIi
 if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
 if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
 if 31 - 31: I1Ii111 - I11i
def lisp_clear_decap_stats ( command ) :
 IiIiIIi1 = command . split ( "%" ) [ 1 ]
 lisp . lisp_decap_stats [ IiIiIIi1 ] = lisp . lisp_stats ( )
 if 50 - 50: Oo0Ooo + iII111i . O0 - i1IIi / Oo0Ooo
 if 59 - 59: oO0o * ooOoO0o + oO0o + I1ii11iIi11i
 if 80 - 80: o0oOOo0O0Ooo . OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
 if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
 if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
 if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
 if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
def lisp_show_decap_stats ( output , etr_or_rtr ) :
 ooI1111 = etr_or_rtr . upper ( )
 I111Ii111 = etr_or_rtr . lower ( )
 if 80 - 80: IiII + o0oOOo0O0Ooo
 I1IIi1I = [ ]
 for oo000O0o in lisp . lisp_decap_stats :
  I1o00ooo0O = "<a href='/lisp/clear/{}/stats/{}'>{}</a>" . format ( I111Ii111 , oo000O0o , oo000O0o )
  I1IIi1I . append ( I1o00ooo0O )
  if 54 - 54: I1ii11iIi11i * IiII
  if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
 IIi1i1iI11I11 = "LISP-{} Decapsulation Stats:" . format ( ooI1111 )
 output += lisp_table_header ( IIi1i1iI11I11 , * I1IIi1I )
 if 67 - 67: i11iIiiIii % I11i
 I1IIi1I = [ ]
 for ii1I11iIi in list ( lisp . lisp_decap_stats . values ( ) ) :
  I1IIi1I . append ( ii1I11iIi . get_stats ( False , True ) )
  if 13 - 13: O0 . iII111i - IiII % i11iIiiIii % I1IiiI
 output += lisp_table_row ( * I1IIi1I )
 output += lisp_table_footer ( )
 return ( output )
 if 88 - 88: i1IIi % O0
 if 35 - 35: OoOoOO00 % OoO0O00 + O0 * o0oOOo0O0Ooo % I1ii11iIi11i
 if 57 - 57: oO0o / I11i
 if 63 - 63: ooOoO0o * OoO0O00 * ooOoO0o + OoOoOO00
 if 25 - 25: iII111i * OoOoOO00 / I1IiiI / IiII
 if 11 - 11: OOooOOo + i11iIiiIii
 if 14 - 14: OoOoOO00 / IiII + OoO0O00 - Ii1I
 if 38 - 38: I1Ii111
def lisp_show_crypto_list ( xtr ) :
 I1i1iii = ""
 Iii1Ii = len ( lisp . lisp_crypto_keys_by_nonce ) != 0
 if 11 - 11: I1Ii111 + i1IIi - iII111i - OoO0O00 * ooOoO0o / ooOoO0o
 if ( lisp . lisp_i_am_itr or lisp . lisp_i_am_rtr ) :
  if ( Iii1Ii ) :
   i1i11ii1 = "LISP-{} Nonce Crypto State" . format ( xtr )
   I1i1iii += lisp_table_header ( i1i11ii1 , "Nonce" , "Uptime" , "Key-ID" ,
 "Key Material" )
   for oo000O0o in lisp . lisp_crypto_keys_by_nonce :
    OoOoO00O = "0x" + lisp . lisp_hex_string ( oo000O0o )
    oo00oO0O0 = lisp . lisp_crypto_keys_by_nonce [ oo000O0o ]
    for Ii1iiII1 in oo00oO0O0 :
     if ( Ii1iiII1 == None ) : continue
     o0OOOO00O = lisp . lisp_print_elapsed ( Ii1iiII1 . uptime )
     OOOoOo0O0O = Ii1iiII1 . print_keys ( False )
     I1i1iii += lisp_table_row ( OoOoO00O , o0OOOO00O , Ii1iiII1 . key_id , OOOoOo0O0O )
     OoOoO00O = ""
     if 58 - 58: OoOoOO00
     if 27 - 27: IiII * OOooOOo - OoooooooOO . Ii1I - II111iiii
   I1i1iii += lisp_table_footer ( )
   if 62 - 62: I1IiiI / iIii1I11I1II1 * I11i
   if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
  i1i11ii1 = "LISP-{} Encapsulation Crypto State" . format ( xtr )
  I1i1iii += lisp_table_header ( i1i11ii1 , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for oo000O0o in lisp . lisp_crypto_keys_by_rloc_encap :
   OoOoO00O = oo000O0o
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_encap [ oo000O0o ]
   for Ii1iiII1 in oo00oO0O0 :
    if ( Ii1iiII1 == None ) : continue
    o0OOOO00O = lisp . lisp_print_elapsed ( Ii1iiII1 . uptime )
    O00000oooOO = lisp . lisp_print_elapsed ( Ii1iiII1 . last_rekey )
    OOOoOo0O0O = Ii1iiII1 . print_keys ( False )
    I1i1iii += lisp_table_row ( OoOoO00O , o0OOOO00O , O00000oooOO , Ii1iiII1 . rekey_count ,
 Ii1iiII1 . use_count , Ii1iiII1 . key_id , OOOoOo0O0O )
    OoOoO00O = ""
    if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
    if 24 - 24: OoO0O00 % O0 % I11i
  I1i1iii += lisp_table_footer ( )
  if 61 - 61: ooOoO0o . iII111i / ooOoO0o * OoooooooOO
  if 13 - 13: II111iiii
 if ( lisp . lisp_i_am_etr or lisp . lisp_i_am_rtr ) :
  i1i11ii1 = "LISP-{} Decapsulation Crypto State" . format ( xtr )
  I1i1iii += lisp_table_header ( i1i11ii1 , "RLOC" , "Uptime" , "Last Rekey" ,
 "Rekey Count" , "Use Count" , "Key-ID" , "Key Material" )
  for oo000O0o in lisp . lisp_crypto_keys_by_rloc_decap :
   OoOoO00O = oo000O0o
   oo00oO0O0 = lisp . lisp_crypto_keys_by_rloc_decap [ oo000O0o ]
   for Ii1iiII1 in oo00oO0O0 :
    if ( Ii1iiII1 == None ) : continue
    o0OOOO00O = lisp . lisp_print_elapsed ( Ii1iiII1 . uptime )
    O00000oooOO = lisp . lisp_print_elapsed ( Ii1iiII1 . last_rekey )
    OOOoOo0O0O = Ii1iiII1 . print_keys ( False )
    I1i1iii += lisp_table_row ( OoOoO00O , o0OOOO00O , O00000oooOO , Ii1iiII1 . rekey_count ,
 Ii1iiII1 . use_count , Ii1iiII1 . key_id , OOOoOo0O0O )
    OoOoO00O = ""
    if 17 - 17: II111iiii
    if 66 - 66: IiII * oO0o
  I1i1iii += lisp_table_footer ( )
  if 73 - 73: i11iIiiIii + O0 % O0
 return ( I1i1iii )
 if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
 if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
 if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
