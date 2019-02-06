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
if 64 - 64: i11iIiiIii
import sys
import os
import socket
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
class I1IiI ( ) :
 def __init__ ( self ) :
  self . eid_prefix = ""
  self . group = ""
  self . instance_id = ""
  self . ams = False
  self . fpr = False
  self . fnpr = False
  self . pprd = False
  self . pra = ""
  if 73 - 73: OOooOOo / ii11ii1ii
 def parse_eid_prefix ( self , string ) :
  O00ooOO = raw_input ( string )
  if ( O00ooOO == "" ) : return
  if 47 - 47: oO0ooO % iI1Ii11111iIi + ii1II11I1ii1I + oO0o0ooO0 - iiIIIII1i1iI
  self . instance_id = "0"
  o0oO0 = O00ooOO . find ( "[" )
  oo00 = O00ooOO . find ( "]" )
  if ( o0oO0 == - 1 ) :
   self . eid_prefix = O00ooOO
  else :
   self . instance_id = O00ooOO [ o0oO0 + 1 : oo00 ]
   self . eid_prefix = O00ooOO [ oo00 + 1 : : ]
   if 88 - 88: O0Oo0oO0o . iIii1I11I1II1 . I1ii11iIi11i
   if 28 - 28: i1IIi % II111iiii - iiIIIII1i1iI + ii1II11I1ii1I
 def print_eid_prefix ( self ) :
  if ( self . instance_id == "" ) : return ( self . eid_prefix )
  return ( "[" + self . instance_id + "]" + self . eid_prefix )
  if 10 - 10: i11iIiiIii / OOooOOo % II111iiii
  if 75 - 75: i11iIiiIii + oO0o0ooO0 . o0oOOo0O0Ooo * ii1II11I1ii1I
  if 59 - 59: iIii1I11I1II1
def I11iii11IIi ( string ) :
 while ( True ) :
  O00o0o0000o0o = raw_input ( string )
  if ( O00o0o0000o0o == "yes" or O00o0o0000o0o == "no" ) : break
  if 88 - 88: ii1II11I1ii1I / I1IiiI + i1IIi % OoooooooOO . oO0o0ooO0 / O0Oo0oO0o
 return ( ( O00o0o0000o0o == "yes" ) )
 if 28 - 28: O0Oo0oO0o + iiIIIII1i1iI - O0Oo0oO0o . OoooooooOO
 if 97 - 97: OoO0O00 . oO0ooO
def IIIi1i1I ( value ) :
 return ( "yes" if value else "no" )
 if 72 - 72: Oo0Ooo % ii11ii1ii . I1IiiI / oO0ooO * I1IiiI
 if 31 - 31: II111iiii + OoO0O00 . iiIIIII1i1iI
 if 68 - 68: I1IiiI - i11iIiiIii - OoO0O00 / ii11ii1ii - OoO0O00 + i1IIi
if ( len ( sys . argv ) > 1 ) : sys . path . append ( sys . argv [ 1 ] )
if 48 - 48: OoooooooOO % o0oOOo0O0Ooo . I1IiiI - iI1Ii11111iIi % i1IIi % OoooooooOO
try :
 import lispapi
except :
 if ( os . path . exists ( "lispapi.pyo" ) ) :
  print "Try command 'python -O lisp-provision-site.pyo'"
 else :
  print "Cannot find lispapi module"
  if 3 - 3: ii1II11I1ii1I + O0
 exit ( 1 )
 if 42 - 42: ii11ii1ii / i1IIi + i11iIiiIii - iI1Ii11111iIi
 if 78 - 78: OoO0O00
print """
---------- lispers.net Map-Server Site Provisioning Tool  ----------
"""
if 18 - 18: O0 - ii1II11I1ii1I / ii1II11I1ii1I + O0Oo0oO0o % O0Oo0oO0o - oO0o0ooO0
if 62 - 62: ii1II11I1ii1I - oO0o0ooO0 - OoOoOO00 % i1IIi / OOooOOo
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
if 14 - 14: oO0ooO % O0
if ( os . getenv ( "LISPAPI_PW" ) == None ) :
 print "LISPAPI_PW environment variable needs password setting"
 exit ( 0 )
 if 41 - 41: i1IIi + iiIIIII1i1iI + ii11ii1ii - oO0o0ooO0
 if 77 - 77: Oo0Ooo . oO0o0ooO0 % O0Oo0oO0o
IIiiIiI1 = raw_input ( "Enter Site name: " )
iiIiIIi = raw_input ( "Enter Site description: " )
ooOoo0O = raw_input ( "Enter authentication key: " )
if 76 - 76: O0 / o0oOOo0O0Ooo . I1IiiI * iI1Ii11111iIi - ii11ii1ii
Oooo = [ ]
while ( True ) :
 O00o = raw_input ( "Enter Map-Server address (enter return when done): " )
 if ( O00o == "" ) : break
 O00 = O00o
 O00o = socket . gethostbyname ( O00o )
 i11I1 = lispapi . api_init ( O00o , "root" )
 if ( i11I1 . get_enable ( ) == None ) :
  print "Authentication failed to Map-Server {}" . format ( O00 )
  continue
  if 8 - 8: iIii1I11I1II1 - oO0o0ooO0 % iIii1I11I1II1 - iI1Ii11111iIi * I1IiiI
 Oooo . append ( { "addr" : O00o , "api" : i11I1 } )
 if 43 - 43: I1IiiI - ii1II11I1ii1I * iIii1I11I1II1
print ""
if 97 - 97: oO0ooO % oO0ooO + II111iiii * ii1II11I1ii1I
o0o00o0 = [ ]
while ( True ) :
 iIi1ii1I1 = I1IiI ( )
 iIi1ii1I1 . parse_eid_prefix ( "Alllowed EID-prefix: (enter return when done): " )
 if ( iIi1ii1I1 . eid_prefix == "" ) : break
 iIi1ii1I1 . ams = I11iii11IIi ( "  accept-more-specifics (yes/no): " )
 iIi1ii1I1 . fpr = I11iii11IIi ( "  force-proxy-reply (yes/no): " )
 iIi1ii1I1 . pprd = I11iii11IIi ( "  pitr-proxy-reply-drop (yes/no): " )
 iIi1ii1I1 . pra = raw_input ( "  proxy-reply-action (native-forward/drop/<enter>): " )
 if ( iIi1ii1I1 . pra != "native-forward" and iIi1ii1I1 . pra != "drop" ) : iIi1ii1I1 . pra = ""
 o0o00o0 . append ( iIi1ii1I1 )
 if 71 - 71: iiIIIII1i1iI . O0
 if 73 - 73: ii11ii1ii % OoOoOO00 - iI1Ii11111iIi
 if 10 - 10: I1IiiI % I1ii11iIi11i
 if 48 - 48: oO0ooO + oO0ooO / II111iiii / iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo
print "\nConfigure site '{}' in Map-Servers: " . format ( IIiiIiI1 ) ,
for O00o in Oooo : print "{}  " . format ( O00o [ "addr" ] ) ,
print ""
print "  Site Name: {}" . format ( IIiiIiI1 )
print "  Site Description: {}" . format ( iiIiIIi )
print "  Authentication Key: {}" . format ( ooOoo0O )
if 77 - 77: OoOoOO00 / oO0ooO
for iIi1ii1I1 in o0o00o0 :
 print "  Allowed EID-prefix: {}" . format ( iIi1ii1I1 . eid_prefix )
 print "    accept-more-specifics = {}" . format ( IIIi1i1I ( iIi1ii1I1 . ams ) )
 print "    force-proxy-reply = {}" . format ( IIIi1i1I ( iIi1ii1I1 . fpr ) )
 print "    force-nat-proxy-reply = {}" . format ( IIIi1i1I ( iIi1ii1I1 . fnpr ) )
 print "    pitr-proxy-reply-drop = {}" . format ( IIIi1i1I ( iIi1ii1I1 . pprd ) )
 if ( iIi1ii1I1 . pra != "" ) : print "    proxy-reply-action = {}" . format ( iIi1ii1I1 . pra )
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
 if 28 - 28: ii11ii1ii - oO0o0ooO0 . oO0o0ooO0 + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % OOooOOo . O0
 if 15 - 15: O0Oo0oO0o / iI1Ii11111iIi . iI1Ii11111iIi - i1IIi
 if 53 - 53: oO0o0ooO0 + I1IiiI * OOooOOo
OooOooooOOoo0 = raw_input ( "\ngo/stop? " )
if ( OooOooooOOoo0 != "go" ) :
 print "Abort provisioning"
 exit ( 0 )
 if 71 - 71: iiIIIII1i1iI % OOooOOo % ii11ii1ii
 if 94 - 94: OOooOOo - ii1II11I1ii1I * O0
 if 17 - 17: I1ii11iIi11i % II111iiii
 if 13 - 13: iiIIIII1i1iI % OoOoOO00 - i11iIiiIii . I1IiiI + II111iiii
 if 10 - 10: I1ii11iIi11i * O0Oo0oO0o * II111iiii % iI1Ii11111iIi . ii11ii1ii + iiIIIII1i1iI
 if 19 - 19: OoOoOO00 - I1IiiI . ii11ii1ii / oO0o0ooO0
print "Configuring Site {} now ..." . format ( IIiiIiI1 )
if 33 - 33: iiIIIII1i1iI / I1ii11iIi11i % I1IiiI + O0Oo0oO0o / OoO0O00
if 52 - 52: o0oOOo0O0Ooo - OoooooooOO + iI1Ii11111iIi + iI1Ii11111iIi - o0oOOo0O0Ooo / iiIIIII1i1iI
if 44 - 44: O0Oo0oO0o . i1IIi - I1ii11iIi11i . O0 - O0Oo0oO0o
if 92 - 92: ii1II11I1ii1I . oO0ooO + o0oOOo0O0Ooo
for O00o in Oooo :
 IiII1I11i1I1I = O00o [ "api" ] . add_ms_site
 oO0Oo = O00o [ "api" ] . build_ms_site_allowed_prefix
 oOOoo0Oo = i11I1 . enable_ms
 print "Provisioning Map-Server {} ... " . format ( O00o [ "addr" ] ) ,
 o00OO00OoO = [ ]
 for iIi1ii1I1 in o0o00o0 :
  oO0Oo ( o00OO00OoO , iIi1ii1I1 . instance_id , iIi1ii1I1 . eid_prefix , iIi1ii1I1 . group , iIi1ii1I1 . ams ,
 iIi1ii1I1 . fpr , iIi1ii1I1 . fnpr , iIi1ii1I1 . pprd , iIi1ii1I1 . pra )
  if 60 - 60: OoO0O00 * OoOoOO00 - OoO0O00 % OoooooooOO - O0Oo0oO0o + I1IiiI
 O00Oo000ooO0 = IiII1I11i1I1I ( IIiiIiI1 , ooOoo0O , o00OO00OoO , iiIiIIi )
 print "{}\n" . format ( "complete" if O00Oo000ooO0 == "good" else "failed" )
 if ( O00Oo000ooO0 != "good" ) : break
 oOOoo0Oo ( )
 if 100 - 100: O0 + oO0o0ooO0 - ii11ii1ii + i11iIiiIii * iI1Ii11111iIi
 if 30 - 30: o0oOOo0O0Ooo . iI1Ii11111iIi - OoooooooOO
 if 8 - 8: i1IIi - iIii1I11I1II1 * II111iiii + i11iIiiIii / iiIIIII1i1iI % ii11ii1ii
 if 16 - 16: I1ii11iIi11i + OoO0O00 - II111iiii
 if 85 - 85: OoOoOO00 + i1IIi
print "Site provisioning complete!"
exit ( 0 )
if 58 - 58: II111iiii * ii11ii1ii * I1ii11iIi11i / ii11ii1ii
if 75 - 75: OOooOOo
if 50 - 50: iI1Ii11111iIi / Oo0Ooo - OOooOOo - oO0ooO % ii1II11I1ii1I - OOooOOo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
