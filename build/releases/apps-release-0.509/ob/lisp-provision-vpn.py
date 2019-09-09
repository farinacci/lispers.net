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
# lisp-provision-vpn.py
#
# Create and bring up an VPN across all xTRs, Map-Resolvers, and Map-Servers
# that need to be involved.
#
# All is required is for the lisp-core process to be running on each LISP
# component device. This script will use the lispapi.py to configure what
# is needed to bring a VPN up or down.
#
# Usage: python lisp-provision-vpn.py [<path-to-lispapi>]
#
if 64 - 64: i11iIiiIii
import sys
import random
import os
import socket
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if ( len ( sys . argv ) > 1 ) : sys . path . append ( sys . argv [ 1 ] )
if 73 - 73: II111iiii
try :
 import lispapi
except :
 if ( os . path . exists ( "lispapi.pyo" ) ) :
  print "Try command 'python -O lisp-provision-vpn.pyo'"
 else :
  print "Cannot find lispapi module"
  if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
 exit ( 1 )
 if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
 if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
 if 46 - 46: ooOoO0o * I11i - OoooooooOO
 if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
 if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
ooO0oo0oO0 = os . getenv ( "LISPAPI_PORT" )
ooO0oo0oO0 = 8080 if ( ooO0oo0oO0 == None ) else int ( ooO0oo0oO0 )
if 100 - 100: i1IIi
print """
---------- Welcome to the lispers.net VPN Provisioning System ----------
"""
if 27 - 27: IiII * OoooooooOO + I11i * ooOoO0o - i11iIiiIii - iII111i
if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . II111iiii - oO0o
if 72 - 72: II111iiii - OoOoOO00
if 91 - 91: OoO0O00 . i11iIiiIii / oO0o % I11i / OoO0O00 - i11iIiiIii
if ( os . getenv ( "LISPAPI_PW" ) == None ) :
 print "LISPAPI_PW environment variable needs password setting"
 exit ( 0 )
 if 8 - 8: o0oOOo0O0Ooo * I1ii11iIi11i * iIii1I11I1II1 . IiII / IiII % IiII
 if 22 - 22: Ii1I . IiII
I11 = raw_input ( "Enter VPN name: " )
Oo0o0000o0o0 = raw_input ( "Enter VPN Instance-ID: " )
if 86 - 86: OoOoOO00 % I1IiiI
oo = [ ]
while ( True ) :
 IiII1I1i1i1ii = raw_input ( "Enter Map-Server address (enter return when done): " )
 if ( IiII1I1i1i1ii == "" ) : break
 IIIII = IiII1I1i1i1ii
 IiII1I1i1i1ii = socket . gethostbyname ( IiII1I1i1i1ii )
 I1 = lispapi . api_init ( IiII1I1i1i1ii , "root" , port = ooO0oo0oO0 )
 if ( I1 . get_enable ( ) == None ) :
  print "Authentication failed to Map-Server {}" . format ( IIIII )
  continue
  if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
 oo . append ( { "addr" : IiII1I1i1i1ii , "api" : I1 } )
 if 31 - 31: OoO0O00 + II111iiii
print "Map-Servers will be used as Map-Resolvers"
if 13 - 13: OOooOOo * oO0o * I1IiiI
oOOOO = [ ]
while ( True ) :
 i11iiII = raw_input ( "\nEnter LISP xTR address (enter return when done): " )
 if ( i11iiII == "" ) : break
 I1iiiiI1iII = i11iiII
 i11iiII = socket . gethostbyname ( i11iiII )
 IiIi11i = raw_input ( "Enter site name where xTR {} resides: " . format ( i11iiII ) )
 iIii1I111I11I = raw_input ( "Enter EID-prefix for site {}: " . format ( IiIi11i ) )
 I1 = lispapi . api_init ( i11iiII , "root" , port = ooO0oo0oO0 )
 if ( I1 . get_enable ( ) == None ) :
  print "Authentication failed to xTR {}" . format ( I1iiiiI1iII )
  continue
  if 72 - 72: o0oOOo0O0Ooo % I11i * II111iiii + i1IIi
 oOOOO . append ( { "addr" : i11iiII , "eid" : iIii1I111I11I , "site_name" : IiIi11i , "api" : I1 ,
 "pw" : random . randint ( 0 , 0xffffff ) } )
 if 64 - 64: oO0o - O0 / II111iiii / o0oOOo0O0Ooo / iIii1I11I1II1
 if 24 - 24: O0 % o0oOOo0O0Ooo + i1IIi + I1Ii111 + I1ii11iIi11i
 if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
 if 23 - 23: i11iIiiIii + I1IiiI
 if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
print "\nCreating VPN '{}' with instance-ID {}:" . format ( I11 , Oo0o0000o0o0 )
if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
print "  Map-Servers: " ,
for IiII1I1i1i1ii in oo : print "  {}" . format ( IiII1I1i1i1ii [ "addr" ] ) ,
print "\n  LISP Sites: "
for i11iiII in oOOOO :
 print "    Site: {}, EID -> RLOC: {} -> {}" . format ( i11iiII [ "site_name" ] ,
 i11iiII [ "eid" ] , i11iiII [ "addr" ] )
 if 33 - 33: Ii1I + II111iiii % i11iIiiIii . ooOoO0o - I1IiiI
 if 66 - 66: Ii1I - OoooooooOO * OoooooooOO . OOooOOo . I1ii11iIi11i
 if 22 - 22: OoooooooOO % I11i - iII111i . iIii1I11I1II1 * i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 if 61 - 61: ooOoO0o
oOOO00o = raw_input ( "\ngo/stop? " )
if ( oOOO00o != "go" ) :
 print "Abort provisioning"
 exit ( 0 )
 if 97 - 97: I11i % I11i + II111iiii * iII111i
 if 54 - 54: I11i + IiII / iII111i
 if 9 - 9: OoOoOO00 / Oo0Ooo - IiII . i1IIi / I1IiiI % IiII
 if 71 - 71: I1Ii111 . O0
 if 73 - 73: OOooOOo % OoOoOO00 - Ii1I
 if 10 - 10: I1IiiI % I1ii11iIi11i
print "Provisioning VPN {} now ..." . format ( I11 )
if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
if 20 - 20: o0oOOo0O0Ooo
if 77 - 77: OoOoOO00 / I11i
if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
I1i1I1II = "VPN " + I11
print "  Configure Map-Servers first ... " ,
for IiII1I1i1i1ii in oo :
 IiII1I1i1i1ii [ "api" ] . get_enable ( True )
 IiII1I1i1i1ii [ "api" ] . enable_mr ( )
 IiII1I1i1i1ii [ "api" ] . enable_ms ( )
 i1 = IiII1I1i1i1ii [ "api" ] . add_ms_site
 IiIiiI = IiII1I1i1i1ii [ "api" ] . build_ms_site_allowed_prefix
 for i11iiII in oOOOO :
  I1I = [ ]
  IiIiiI ( I1I , Oo0o0000o0o0 , i11iiII [ "eid" ] , "" )
  i1 ( i11iiII [ "site_name" ] , i11iiII [ "pw" ] , I1I , I1i1I1II )
  if 80 - 80: OoOoOO00 - OoO0O00
  if 87 - 87: oO0o / I11i - i1IIi * OOooOOo / OoooooooOO . O0
print "complete"
if 1 - 1: II111iiii - I11i / I11i
print "  Configure xTRs next ..." ,
for i11iiII in oOOOO :
 i11iiII [ "api" ] . get_enable ( True )
 i11iiII [ "api" ] . enable_itr ( )
 i11iiII [ "api" ] . enable_etr ( )
 I1II1III11iii = i11iiII [ "api" ] . add_itr_map_resolver
 Oo000 = i11iiII [ "api" ] . add_etr_map_server
 for IiII1I1i1i1ii in oo :
  I1II1III11iii ( IiII1I1i1i1ii [ "addr" ] )
  Oo000 ( IiII1I1i1i1ii [ "addr" ] , i11iiII [ "pw" ] )
  if 51 - 51: i11iIiiIii . I1IiiI + II111iiii
 II111ii1II1i = i11iiII [ "api" ] . add_etr_database_mapping
 II111ii1II1i ( Oo0o0000o0o0 , i11iiII [ "eid" ] , "" , [ i11iiII [ "addr" ] ] )
 if 59 - 59: O0 + I1IiiI + IiII % I1IiiI
print "complete"
if 70 - 70: iII111i * I1ii11iIi11i
if 46 - 46: ooOoO0o / OoO0O00
if 52 - 52: o0oOOo0O0Ooo - OoooooooOO + Ii1I + Ii1I - o0oOOo0O0Ooo / I1Ii111
if 44 - 44: ooOoO0o . i1IIi - I1ii11iIi11i . O0 - ooOoO0o
print "Provisioning complete!"
exit ( 0 )
if 92 - 92: iII111i . I11i + o0oOOo0O0Ooo
if 28 - 28: i1IIi * Oo0Ooo - o0oOOo0O0Ooo * IiII * Ii1I / OoO0O00
if 94 - 94: II111iiii % I1ii11iIi11i / OoOoOO00 * iIii1I11I1II1
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
