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
# lisp-provision-site.py
#
# This script creates "lisp site" command for map-servers. It provisions
# LISP sites so ETRs can get their Map-Registers accepted.
#
# Usage: python lisp-provision-site.py [<path-to-lispapi>]
#
from __future__ import print_function
import sys
import os
import socket
from builtins import input
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
class IiII1IiiIiI1 ( ) :
 def __init__ ( self ) :
  self . eid_prefix = ""
  self . group = ""
  self . instance_id = ""
  self . ams = False
  self . fpr = False
  self . fnpr = False
  self . pprd = False
  self . pra = ""
  if 40 - 40: oo * OoO0O00
 def parse_eid_prefix ( self , string ) :
  IIiIiII11i = input ( string )
  if ( IIiIiII11i == "" ) : return
  if 51 - 51: oOo0O0Ooo * I1ii11iIi11i
  self . instance_id = "0"
  I1IiI = IIiIiII11i . find ( "[" )
  o0OOO = IIiIiII11i . find ( "]" )
  if ( I1IiI == - 1 ) :
   self . eid_prefix = IIiIiII11i
  else :
   self . instance_id = IIiIiII11i [ I1IiI + 1 : o0OOO ]
   self . eid_prefix = IIiIiII11i [ o0OOO + 1 : : ]
   if 13 - 13: ooOo + Oo
   if 67 - 67: O00ooOO . I1iII1iiII
 def print_eid_prefix ( self ) :
  if ( self . instance_id == "" ) : return ( self . eid_prefix )
  return ( "[" + self . instance_id + "]" + self . eid_prefix )
  if 28 - 28: Ii11111i * iiI1i1
  if 46 - 46: Ooo0OO0oOO * Ii * Oo0o
  if 60 - 60: Oo0oO0oo0oO00 + i1IIi . Oo0o / Ii
def o00 ( string ) :
 while ( True ) :
  Oo0oO0ooo = input ( string )
  if ( Oo0oO0ooo == "yes" or Oo0oO0ooo == "no" ) : break
  if 56 - 56: Ii11111i - i1IIi
 return ( ( Oo0oO0ooo == "yes" ) )
 if 64 - 64: Oo0o + Ooo0OO0oOO
 if 10 - 10: i11iIiiIii / O00ooOO % II111iiii
def Ooo00O0 ( value ) :
 return ( "yes" if value else "no" )
 if 59 - 59: iIii1I11I1II1
 if 31 - 31: Ii % i1IIi * iIii1I11I1II1 / Ii % O00ooOO + OoooooooOO
 if 93 - 93: Ooo0OO0oOO * i11iIiiIii * oo % Ooo0OO0oOO * Ooo0OO0oOO * II111iiii
if ( len ( sys . argv ) > 1 ) : sys . path . append ( sys . argv [ 1 ] )
if 79 - 79: Ii
try :
 import lispapi
except :
 if ( os . path . exists ( "lispapi.pyo" ) ) :
  print ( "Try command 'python -O lisp-provision-site.pyo'" )
 else :
  print ( "Cannot find lispapi module" )
  if 86 - 86: I1ii11iIi11i % oo
 exit ( 1 )
 if 80 - 80: OoooooooOO . oo
 if 87 - 87: O00ooOO / Oo0oO0oo0oO00 + Oo0o - Oo0oO0oo0oO00 . Oo0oO0oo0oO00 / II111iiii
print ( """
---------- lispers.net Map-Server Site Provisioning Tool  ----------
""" )
if 11 - 11: oo % ooOo - OoO0O00
if 58 - 58: i11iIiiIii % Oo0o
if 54 - 54: I1iII1iiII % O0 + oo - Ooo0OO0oOO / Ii11111i
if 31 - 31: oOo0O0Ooo + II111iiii
if ( os . getenv ( "LISPAPI_PW" ) == None ) :
 print ( "LISPAPI_PW environment variable needs password setting" )
 exit ( 0 )
 if 13 - 13: I1iII1iiII * O00ooOO * oo
 if 55 - 55: II111iiii
IIIiI11ii = input ( "Enter Site name: " )
O000oo = input ( "Enter Site description: " )
i1iIIi1 = input ( "Enter authentication key: " )
if 50 - 50: i11iIiiIii - iiI1i1
oo0Ooo0 = [ ]
while ( True ) :
 I1I11I1I1I = input ( "Enter Map-Server address (enter return when done): " )
 if ( I1I11I1I1I == "" ) : break
 OooO0OO = I1I11I1I1I
 I1I11I1I1I = socket . gethostbyname ( I1I11I1I1I )
 iiiIi = lispapi . api_init ( I1I11I1I1I , "root" )
 if ( iiiIi . get_enable ( ) == None ) :
  print ( "Authentication failed to Map-Server {}" . format ( OooO0OO ) )
  continue
  if 24 - 24: O0 % ooOo + i1IIi + Oo0o + Oo
 oo0Ooo0 . append ( { "addr" : I1I11I1I1I , "api" : iiiIi } )
 if 70 - 70: OoO0O00 % OoO0O00 . Ii % oOo0O0Ooo * ooOo % O00ooOO
print ( "" )
if 23 - 23: i11iIiiIii + oo
oOo = [ ]
while ( True ) :
 oOoOoO = IiII1IiiIiI1 ( )
 oOoOoO . parse_eid_prefix ( "Alllowed EID-prefix: (enter return when done): " )
 if ( oOoOoO . eid_prefix == "" ) : break
 oOoOoO . ams = o00 ( "  accept-more-specifics (yes/no): " )
 oOoOoO . fpr = o00 ( "  force-proxy-reply (yes/no): " )
 oOoOoO . pprd = o00 ( "  pitr-proxy-reply-drop (yes/no): " )
 oOoOoO . pra = input ( "  proxy-reply-action (native-forward/drop/<enter>): " )
 if ( oOoOoO . pra != "native-forward" and oOoOoO . pra != "drop" ) : oOoOoO . pra = ""
 oOo . append ( oOoOoO )
 if 6 - 6: oo / OoO0O00 % iiI1i1
 if 84 - 84: i11iIiiIii . ooOo
 if 100 - 100: iiI1i1 - iiI1i1 - Oo0o
 if 20 - 20: OoooooooOO
 if 13 - 13: i1IIi - iiI1i1 % O00ooOO / iIii1I11I1II1 % Ooo0OO0oOO
print ( "\nConfigure site '{}' in Map-Servers: " . format ( IIIiI11ii ) , end = " " )
for I1I11I1I1I in oo0Ooo0 : print ( "{}  " . format ( I1I11I1I1I [ "addr" ] ) , end = " " )
print ( "" )
print ( "  Site Name: {}" . format ( IIIiI11ii ) )
print ( "  Site Description: {}" . format ( O000oo ) )
print ( "  Authentication Key: {}" . format ( i1iIIi1 ) )
if 97 - 97: i11iIiiIii
for oOoOoO in oOo :
 print ( "  Allowed EID-prefix: {}" . format ( oOoOoO . eid_prefix ) )
 print ( "    accept-more-specifics = {}" . format ( Ooo00O0 ( oOoOoO . ams ) ) )
 print ( "    force-proxy-reply = {}" . format ( Ooo00O0 ( oOoOoO . fpr ) ) )
 print ( "    force-nat-proxy-reply = {}" . format ( Ooo00O0 ( oOoOoO . fnpr ) ) )
 print ( "    pitr-proxy-reply-drop = {}" . format ( Ooo00O0 ( oOoOoO . pprd ) ) )
 if ( oOoOoO . pra != "" ) : print ( "    proxy-reply-action = {}" . format ( oOoOoO . pra ) )
 if 32 - 32: OoO0O00 * O0 % O00ooOO % iiI1i1 . Ii
 if 61 - 61: Oo0oO0oo0oO00
 if 79 - 79: OoO0O00 + oo - Ooo0OO0oOO
 if 83 - 83: Oo0oO0oo0oO00
 if 64 - 64: oOo0O0Ooo % Oo0oO0oo0oO00 % Ooo0OO0oOO / I1ii11iIi11i - oOo0O0Ooo
o0o0oOOOo0oo = input ( "\ngo/stop? " )
if ( o0o0oOOOo0oo != "go" ) :
 print ( "Abort provisioning" )
 exit ( 0 )
 if 80 - 80: Ii11111i * i11iIiiIii / Oo0o
 if 9 - 9: iiI1i1 + O00ooOO % iiI1i1 + i1IIi . I1iII1iiII
 if 31 - 31: ooOo + Ii11111i + Ii11111i / II111iiii
 if 26 - 26: OoooooooOO
 if 12 - 12: OoooooooOO % I1ii11iIi11i / Oo0oO0oo0oO00 % ooOo
 if 29 - 29: OoooooooOO
print ( "Configuring Site {} now ..." . format ( IIIiI11ii ) )
if 23 - 23: ooOo . II111iiii
if 98 - 98: iIii1I11I1II1 % I1ii11iIi11i * Oo * I1ii11iIi11i
if 45 - 45: Oo0o . I1ii11iIi11i
if 83 - 83: O00ooOO . iIii1I11I1II1 . Oo
for I1I11I1I1I in oo0Ooo0 :
 I1I = I1I11I1I1I [ "api" ] . add_ms_site
 oOO00oOO = I1I11I1I1I [ "api" ] . build_ms_site_allowed_prefix
 OoOo = iiiIi . enable_ms
 print ( "Provisioning Map-Server {} ... " . format ( I1I11I1I1I [ "addr" ] ) , end = " " )
 iI = [ ]
 for oOoOoO in oOo :
  oOO00oOO ( iI , oOoOoO . instance_id , oOoOoO . eid_prefix , oOoOoO . group , oOoOoO . ams ,
 oOoOoO . fpr , oOoOoO . fnpr , oOoOoO . pprd , oOoOoO . pra )
  if 60 - 60: Ii11111i / Ii11111i
 I1II1III11iii = I1I ( IIIiI11ii , i1iIIi1 , iI , O000oo )
 print ( "{}\n" . format ( "complete" if I1II1III11iii == "good" else "failed" ) )
 if ( I1II1III11iii != "good" ) : break
 OoOo ( )
 if 75 - 75: iIii1I11I1II1 / I1iII1iiII % ooOo * I1ii11iIi11i
 if 9 - 9: oOo0O0Ooo
 if 33 - 33: Oo0oO0oo0oO00 . Ooo0OO0oOO
 if 58 - 58: I1iII1iiII * i11iIiiIii / I1ii11iIi11i % Oo0o - Oo / O00ooOO
 if 50 - 50: oo
print ( "Site provisioning complete!" )
exit ( 0 )
if 34 - 34: oo * II111iiii % Ooo0OO0oOO * I1ii11iIi11i - oo
if 33 - 33: ooOo + I1iII1iiII * oOo0O0Ooo - OoO0O00 / O00ooOO % iiI1i1
if 21 - 21: oOo0O0Ooo * iIii1I11I1II1 % O00ooOO * i1IIi
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
