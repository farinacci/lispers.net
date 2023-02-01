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
# lisp-provision-xtr.py
#
# This script creates "lisp database-mapping" commands for xTRs. And can
# also configure map-server and map-resolver command clauses that xTRs use.
#
# Usage: python lisp-provision-xtr.py [<path-to-lispapi>]
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
  self . rloc_set = [ ]
  if 40 - 40: oo * OoO0O00
 def parse_prefix ( self , string ) :
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
 def print_prefix ( self ) :
  if ( self . instance_id == "" ) : return ( self . eid_prefix )
  return ( "[" + self . instance_id + "]" + self . eid_prefix )
  if 28 - 28: Ii11111i * iiI1i1
 def add_rloc ( self , rloc ) :
  self . rloc_set . append ( rloc )
  if 46 - 46: Ooo0OO0oOO * Ii * Oo0o
  if 60 - 60: Oo0oO0oo0oO00 + i1IIi . Oo0o / Ii
  if 88 - 88: Ooo0OO0oOO . O00ooOO % Oo0oO0oo0oO00
  if 66 - 66: Ooo0OO0oOO
  if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . II111iiii - O00ooOO
if ( len ( sys . argv ) > 1 ) : sys . path . append ( sys . argv [ 1 ] )
if 72 - 72: II111iiii - I1ii11iIi11i
try :
 import lispapi
except :
 if ( os . path . exists ( "lispapi.pyo" ) ) :
  print ( "Try command 'python -O lisp-provision-xtr.pyo'" )
 else :
  print ( "Cannot find lispapi module" )
  if 91 - 91: oOo0O0Ooo . i11iIiiIii / O00ooOO % Ii11111i / oOo0O0Ooo - i11iIiiIii
 exit ( 1 )
 if 8 - 8: ooOo * Oo * iIii1I11I1II1 . Ii / Ii % Ii
 if 22 - 22: iiI1i1 . Ii
 if 41 - 41: Oo0o . Oo0oO0oo0oO00 * Ii % i11iIiiIii
 if 74 - 74: Ooo0OO0oOO * Ii
 if 82 - 82: iIii1I11I1II1 % Ii
oOo0oooo00o = os . getenv ( "LISPAPI_PORT" )
oOo0oooo00o = 8080 if ( oOo0oooo00o == None ) else int ( oOo0oooo00o )
if 65 - 65: ooOo * iIii1I11I1II1 * Oo0oO0oo0oO00
print ( """
---------- lispers.net xTR Provisioning Tool  ----------
""" )
if 18 - 18: iIii1I11I1II1 / Ii11111i + O00ooOO / OoO0O00 - II111iiii - Ii11111i
if 1 - 1: Ii11111i - I1iII1iiII % O0 + oo - Ooo0OO0oOO / Ii11111i
if 31 - 31: oOo0O0Ooo + II111iiii
if 13 - 13: I1iII1iiII * O00ooOO * oo
if ( os . getenv ( "LISPAPI_PW" ) == None ) :
 print ( "LISPAPI_PW environment variable needs password setting" )
 exit ( 0 )
 if 55 - 55: II111iiii
 if 43 - 43: I1ii11iIi11i - i1IIi + Oo0o + iiI1i1
 if 17 - 17: ooOo
 if 64 - 64: iiI1i1 % i1IIi % OoooooooOO
 if 3 - 3: Ooo0OO0oOO + O0
I1Ii = input ( "Enter xTR RLOC address to provision: " )
if 66 - 66: iiI1i1
if 78 - 78: oOo0O0Ooo
if 18 - 18: O0 - Ooo0OO0oOO / Ooo0OO0oOO + Oo0oO0oo0oO00 % Oo0oO0oo0oO00 - Ii
if 62 - 62: Ooo0OO0oOO - Ii - I1ii11iIi11i % i1IIi / O00ooOO
OoooooOoo = lispapi . api_init ( I1Ii , "root" , port = oOo0oooo00o )
if ( OoooooOoo . get_enable ( ) == None ) :
 print ( "Authentication failed to xTR {}" . format ( I1Ii ) )
 exit ( 0 )
 if 70 - 70: oOo0O0Ooo . oOo0O0Ooo - oOo0O0Ooo / Oo * I1iII1iiII
 if 86 - 86: i11iIiiIii + iiI1i1 + Oo0oO0oo0oO00 * Ii11111i + ooOo
 if 61 - 61: oOo0O0Ooo / i11iIiiIii
 if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - Oo + i11iIiiIii
 if 65 - 65: I1ii11iIi11i
while ( True ) :
 ii1I = input ( "Configure Map-Servers for this xTR (yes/no): " )
 if ( ii1I in ( "yes" , "no" ) ) : break
 if 76 - 76: O0 / ooOo . oo * iiI1i1 - I1iII1iiII
 if 76 - 76: i11iIiiIii / iIii1I11I1II1 . Oo % I1iII1iiII / OoooooooOO % O00ooOO
 if 75 - 75: Ooo0OO0oOO
 if 97 - 97: i11iIiiIii
 if 32 - 32: OoO0O00 * O0 % O00ooOO % iiI1i1 . Ii
 if 61 - 61: Oo0oO0oo0oO00
oOOO00o = [ ]
if ( ii1I == "yes" ) :
 while ( True ) :
  O0O00o0OOO0 = input ( "Enter Map-Server address (enter return when done): " )
  if ( O0O00o0OOO0 == "" ) : break
  Ii1iIIIi1ii = input ( "Enter authentication key for Map-Server: " )
  O0O00o0OOO0 = socket . gethostbyname ( O0O00o0OOO0 )
  oOOO00o . append ( [ O0O00o0OOO0 , Ii1iIIIi1ii ] )
  if 80 - 80: Ii11111i * i11iIiiIii / Oo0o
 print ( "Map-Servers will be used as Map-Resolvers" )
 if 9 - 9: iiI1i1 + O00ooOO % iiI1i1 + i1IIi . I1iII1iiII
print ( "" )
if 31 - 31: ooOo + Ii11111i + Ii11111i / II111iiii
if 26 - 26: OoooooooOO
if 12 - 12: OoooooooOO % I1ii11iIi11i / Oo0oO0oo0oO00 % ooOo
if 29 - 29: OoooooooOO
if 23 - 23: ooOo . II111iiii
Oo0O0OOOoo = [ ]
while ( True ) :
 oOoOooOo0o0 = IiII1IiiIiI1 ( )
 oOoOooOo0o0 . parse_prefix ( "Enter EID-prefix: (enter return when done): " )
 if ( oOoOooOo0o0 . eid_prefix == "" ) : break
 while ( True ) :
  OOOO = input ( ( "Enter RLOC (or local interface) for " + "EID-prefix {} (enter return when done): " ) . format ( oOoOooOo0o0 . print_prefix ( ) ) )
  if 87 - 87: O00ooOO / Ii11111i - i1IIi * I1iII1iiII / OoooooooOO . O0
  if 1 - 1: II111iiii - Ii11111i / Ii11111i
  if ( OOOO == "" ) : break
  oOoOooOo0o0 . add_rloc ( OOOO )
  if 46 - 46: iiI1i1 * I1iII1iiII - oOo0O0Ooo * O00ooOO - Oo0o
 Oo0O0OOOoo . append ( oOoOooOo0o0 )
 if 83 - 83: OoooooooOO
 if 31 - 31: II111iiii - I1iII1iiII . Oo0o % I1ii11iIi11i - O0
 if 4 - 4: II111iiii / Oo0oO0oo0oO00 . Ooo0OO0oOO
 if 58 - 58: I1iII1iiII * i11iIiiIii / I1ii11iIi11i % Oo0o - Oo / O00ooOO
 if 50 - 50: oo
if ( len ( Oo0O0OOOoo ) != 0 ) :
 print ( "\nConfigure database-mappings in xTR {}: " . format ( I1Ii ) )
 for oOoOooOo0o0 in Oo0O0OOOoo :
  print ( "  EID-prefix: {}, RLOC-set: " . format ( oOoOooOo0o0 . print_prefix ( ) ) , end = " " )
  for OOOO in oOoOooOo0o0 . rloc_set : print ( "{}  " . format ( OOOO ) , end = " " )
  print ( "" )
  if 34 - 34: oo * II111iiii % Ooo0OO0oOO * I1ii11iIi11i - oo
  if 33 - 33: ooOo + I1iII1iiII * oOo0O0Ooo - OoO0O00 / O00ooOO % iiI1i1
  if 21 - 21: oOo0O0Ooo * iIii1I11I1II1 % O00ooOO * i1IIi
if ( len ( oOOO00o ) != 0 ) :
 print ( "\nConfigure Map-Servers in xTR {}:" . format ( I1Ii ) )
 print ( "  " , end = " " )
 for O0O00o0OOO0 in oOOO00o : print ( "{}  " . format ( O0O00o0OOO0 [ 0 ] ) , end = " " )
 if 16 - 16: O0 - Oo0o * iIii1I11I1II1 + Ooo0OO0oOO
 if 50 - 50: II111iiii - Oo0oO0oo0oO00 * Oo / Oo0o + ooOo
 if 88 - 88: iiI1i1 / Oo0o + Ooo0OO0oOO - II111iiii / Oo0oO0oo0oO00 - I1ii11iIi11i
 if 15 - 15: Oo + I1ii11iIi11i - OoooooooOO / I1iII1iiII
 if 58 - 58: i11iIiiIii % Ii11111i
OO00Oo = input ( "\ngo/stop? " )
if ( OO00Oo != "go" ) :
 print ( "Abort provisioning" )
 exit ( 0 )
 if 51 - 51: Ii * ooOo + Ii11111i + oOo0O0Ooo
 if 66 - 66: I1ii11iIi11i
print ( "Configuring ITR and ETR ... " , end = " " )
OoooooOoo . enable_itr ( )
OoooooOoo . enable_etr ( )
print ( "complete" )
if 97 - 97: O00ooOO % Ii * Ii
if ( len ( oOOO00o ) != 0 ) :
 print ( "Configuring Map-Servers ... " , end = " " )
 for O0O00o0OOO0 in oOOO00o : OoooooOoo . add_etr_map_server ( O0O00o0OOO0 [ 0 ] , O0O00o0OOO0 [ 1 ] )
 print ( "complete" )
 print ( "Configuring Map-Resolvers ... " , end = " " )
 for O0O00o0OOO0 in oOOO00o : OoooooOoo . add_itr_map_resolver ( O0O00o0OOO0 [ 0 ] )
 print ( "complete" )
 if 39 - 39: iiI1i1 % Ii
 if 4 - 4: O00ooOO
if ( len ( Oo0O0OOOoo ) != 0 ) : print ( "Configuring Database-Mappings ... " , end = " " )
for oOoOooOo0o0 in Oo0O0OOOoo :
 OoooooOoo . add_etr_database_mapping ( oOoOooOo0o0 . instance_id , oOoOooOo0o0 . eid_prefix , oOoOooOo0o0 . group ,
 oOoOooOo0o0 . rloc_set )
 if 93 - 93: oOo0O0Ooo % O00ooOO . oOo0O0Ooo * Oo0o % iiI1i1 . II111iiii
print ( "complete" )
print ( "" )
if 38 - 38: ooOo
if 57 - 57: O0 / O00ooOO * Oo0o / I1ii11iIi11i . II111iiii
if 26 - 26: Ooo0OO0oOO
if 91 - 91: oOo0O0Ooo . Oo + oOo0O0Ooo - Ooo0OO0oOO / OoooooooOO
print ( "xTR provisioning complete!" )
exit ( 0 )
if 39 - 39: Oo / Oo0oO0oo0oO00 - II111iiii
if 98 - 98: Oo / Ii11111i % O00ooOO . I1ii11iIi11i
if 91 - 91: O00ooOO % OoO0O00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
