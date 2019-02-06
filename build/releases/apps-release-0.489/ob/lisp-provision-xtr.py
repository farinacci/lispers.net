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
  self . rloc_set = [ ]
  if 73 - 73: OOooOOo / ii11ii1ii
 def parse_prefix ( self , string ) :
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
 def print_prefix ( self ) :
  if ( self . instance_id == "" ) : return ( self . eid_prefix )
  return ( "[" + self . instance_id + "]" + self . eid_prefix )
  if 10 - 10: i11iIiiIii / OOooOOo % II111iiii
 def add_rloc ( self , rloc ) :
  self . rloc_set . append ( rloc )
  if 75 - 75: i11iIiiIii + oO0o0ooO0 . o0oOOo0O0Ooo * ii1II11I1ii1I
  if 59 - 59: iIii1I11I1II1
  if 31 - 31: oO0o0ooO0 % i1IIi * iIii1I11I1II1 / oO0o0ooO0 % OOooOOo + OoooooooOO
  if 93 - 93: ii1II11I1ii1I * i11iIiiIii * I1IiiI % ii1II11I1ii1I * ii1II11I1ii1I * II111iiii
  if 79 - 79: oO0o0ooO0
if ( len ( sys . argv ) > 1 ) : sys . path . append ( sys . argv [ 1 ] )
if 86 - 86: OoOoOO00 % I1IiiI
try :
 import lispapi
except :
 if ( os . path . exists ( "lispapi.pyo" ) ) :
  print "Try command 'python -O lisp-provision-xtr.pyo'"
 else :
  print "Cannot find lispapi module"
  if 80 - 80: OoooooooOO . I1IiiI
 exit ( 1 )
 if 87 - 87: OOooOOo / O0Oo0oO0o + iiIIIII1i1iI - O0Oo0oO0o . O0Oo0oO0o / II111iiii
 if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
 if 58 - 58: i11iIiiIii % iiIIIII1i1iI
 if 54 - 54: ii11ii1ii % O0 + I1IiiI - ii1II11I1ii1I / oO0ooO
 if 31 - 31: OoO0O00 + II111iiii
i11IiIiiIIIII = os . getenv ( "LISPAPI_PORT" )
i11IiIiiIIIII = 8080 if ( i11IiIiiIIIII == None ) else int ( i11IiIiiIIIII )
if 22 - 22: iI1Ii11111iIi * O0 / o0oOOo0O0Ooo
print """
---------- lispers.net xTR Provisioning Tool  ----------
"""
if 64 - 64: iI1Ii11111iIi % i1IIi % OoooooooOO
if 3 - 3: ii1II11I1ii1I + O0
if 42 - 42: ii11ii1ii / i1IIi + i11iIiiIii - iI1Ii11111iIi
if 78 - 78: OoO0O00
if ( os . getenv ( "LISPAPI_PW" ) == None ) :
 print "LISPAPI_PW environment variable needs password setting"
 exit ( 0 )
 if 18 - 18: O0 - ii1II11I1ii1I / ii1II11I1ii1I + O0Oo0oO0o % O0Oo0oO0o - oO0o0ooO0
 if 62 - 62: ii1II11I1ii1I - oO0o0ooO0 - OoOoOO00 % i1IIi / OOooOOo
 if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
 if 14 - 14: oO0ooO % O0
 if 41 - 41: i1IIi + iiIIIII1i1iI + ii11ii1ii - oO0o0ooO0
oO = raw_input ( "Enter xTR RLOC address to provision: " )
if 76 - 76: OoO0O00 * o0oOOo0O0Ooo % i1IIi - OoO0O00 / I1IiiI . ii11ii1ii
if 41 - 41: OoOoOO00
if 13 - 13: Oo0Ooo . i11iIiiIii - iIii1I11I1II1 - OoOoOO00
if 6 - 6: I1IiiI / Oo0Ooo % iI1Ii11111iIi
oo = lispapi . api_init ( oO , "root" , port = i11IiIiiIIIII )
if ( oo . get_enable ( ) == None ) :
 print "Authentication failed to xTR {}" . format ( oO )
 exit ( 0 )
 if 54 - 54: ii11ii1ii + ii11ii1ii % iiIIIII1i1iI % i11iIiiIii / iIii1I11I1II1 . ii11ii1ii
 if 57 - 57: iI1Ii11111iIi % OoooooooOO
 if 61 - 61: ii1II11I1ii1I . iIii1I11I1II1 * I1IiiI . O0Oo0oO0o % Oo0Ooo
 if 72 - 72: ii11ii1ii
 if 63 - 63: iI1Ii11111iIi
while ( True ) :
 O00 = raw_input ( "Configure Map-Servers for this xTR (yes/no): " )
 if ( O00 in ( "yes" , "no" ) ) : break
 if 35 - 35: o0oOOo0O0Ooo + ii1II11I1ii1I + ii1II11I1ii1I
 if 11 - 11: ii1II11I1ii1I - OoO0O00 % O0Oo0oO0o % ii1II11I1ii1I / OoOoOO00 - OoO0O00
 if 74 - 74: ii1II11I1ii1I * O0
 if 89 - 89: OOooOOo + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % oO0ooO * i11iIiiIii / O0 * oO0ooO
 if 49 - 49: OOooOOo % iI1Ii11111iIi + i1IIi . I1IiiI % I1ii11iIi11i
I1i1iii = [ ]
if ( O00 == "yes" ) :
 while ( True ) :
  i1iiI11I = raw_input ( "Enter Map-Server address (enter return when done): " )
  if ( i1iiI11I == "" ) : break
  iiii = raw_input ( "Enter authentication key for Map-Server: " )
  i1iiI11I = socket . gethostbyname ( i1iiI11I )
  I1i1iii . append ( [ i1iiI11I , iiii ] )
  if 54 - 54: I1ii11iIi11i * ii11ii1ii
 print "Map-Servers will be used as Map-Resolvers"
 if 13 - 13: oO0o0ooO0 + OoOoOO00 - OoooooooOO + iiIIIII1i1iI . ii1II11I1ii1I + OoO0O00
print ""
if 8 - 8: iIii1I11I1II1 . I1IiiI - iIii1I11I1II1 * iI1Ii11111iIi
if 61 - 61: o0oOOo0O0Ooo / OoO0O00 + O0Oo0oO0o * OOooOOo / OOooOOo
if 75 - 75: i1IIi / OoooooooOO - O0 / OoOoOO00 . II111iiii - i1IIi
if 71 - 71: ii11ii1ii + iI1Ii11111iIi * ii11ii1ii - OoO0O00 * o0oOOo0O0Ooo
if 65 - 65: O0 % I1IiiI . I1ii11iIi11i % iIii1I11I1II1 / ii11ii1ii % iiIIIII1i1iI
ooii11I = [ ]
while ( True ) :
 Ooo0OO0oOO = I1IiI ( )
 Ooo0OO0oOO . parse_prefix ( "Enter EID-prefix: (enter return when done): " )
 if ( Ooo0OO0oOO . eid_prefix == "" ) : break
 while ( True ) :
  ii11i1 = raw_input ( ( "Enter RLOC (or local interface) for " + "EID-prefix {} (enter return when done): " ) . format ( Ooo0OO0oOO . print_prefix ( ) ) )
  if 29 - 29: I1ii11iIi11i % I1IiiI + O0Oo0oO0o / o0oOOo0O0Ooo + ii11ii1ii * o0oOOo0O0Ooo
  if 42 - 42: iI1Ii11111iIi + OOooOOo
  if ( ii11i1 == "" ) : break
  Ooo0OO0oOO . add_rloc ( ii11i1 )
  if 76 - 76: iiIIIII1i1iI - OoO0O00
 ooii11I . append ( Ooo0OO0oOO )
 if 70 - 70: O0Oo0oO0o
 if 61 - 61: I1ii11iIi11i . I1ii11iIi11i
 if 10 - 10: OoOoOO00 * ii1II11I1ii1I . oO0ooO + II111iiii - O0Oo0oO0o * i1IIi
 if 56 - 56: o0oOOo0O0Ooo * oO0o0ooO0 * II111iiii
 if 80 - 80: o0oOOo0O0Ooo * II111iiii % II111iiii
if ( len ( ooii11I ) != 0 ) :
 print "\nConfigure database-mappings in xTR {}: " . format ( oO )
 for Ooo0OO0oOO in ooii11I :
  print "  EID-prefix: {}, RLOC-set: " . format ( Ooo0OO0oOO . print_prefix ( ) ) ,
  for ii11i1 in Ooo0OO0oOO . rloc_set : print "{}  " . format ( ii11i1 ) ,
  print ""
  if 59 - 59: iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo - I1IiiI + ii11ii1ii / I1ii11iIi11i
  if 24 - 24: oO0ooO . ii1II11I1ii1I % ii11ii1ii + O0Oo0oO0o % OoOoOO00
  if 4 - 4: oO0o0ooO0 - OoO0O00 * OoOoOO00 - oO0ooO
if ( len ( I1i1iii ) != 0 ) :
 print "\nConfigure Map-Servers in xTR {}:" . format ( oO )
 print "  " ,
 for i1iiI11I in I1i1iii : print "{}  " . format ( i1iiI11I [ 0 ] ) ,
 if 41 - 41: OoOoOO00 . I1IiiI * OOooOOo % oO0o0ooO0
 if 86 - 86: I1IiiI + iI1Ii11111iIi % i11iIiiIii * OOooOOo . O0Oo0oO0o * oO0ooO
 if 44 - 44: OOooOOo
 if 88 - 88: iiIIIII1i1iI % iI1Ii11111iIi . II111iiii
 if 38 - 38: o0oOOo0O0Ooo
Oo0O = raw_input ( "\ngo/stop? " )
if ( Oo0O != "go" ) :
 print "Abort provisioning"
 exit ( 0 )
 if 25 - 25: OoOoOO00 . II111iiii / ii1II11I1ii1I . ii11ii1ii * OoO0O00 . I1IiiI
 if 59 - 59: II111iiii + OoooooooOO * OoOoOO00 + i1IIi
print "Configuring ITR and ETR ... " ,
oo . enable_itr ( )
oo . enable_etr ( )
print "complete"
if 58 - 58: II111iiii * ii11ii1ii * I1ii11iIi11i / ii11ii1ii
if ( len ( I1i1iii ) != 0 ) :
 print "Configuring Map-Servers ... " ,
 for i1iiI11I in I1i1iii : oo . add_etr_map_server ( i1iiI11I [ 0 ] , i1iiI11I [ 1 ] )
 print "complete"
 print "Configuring Map-Resolvers ... " ,
 for i1iiI11I in I1i1iii : oo . add_itr_map_resolver ( i1iiI11I [ 0 ] )
 print "complete"
 if 75 - 75: OOooOOo
 if 50 - 50: iI1Ii11111iIi / Oo0Ooo - OOooOOo - oO0ooO % ii1II11I1ii1I - OOooOOo
if ( len ( ooii11I ) != 0 ) : print "Configuring Database-Mappings ... " ,
for Ooo0OO0oOO in ooii11I :
 oo . add_etr_database_mapping ( Ooo0OO0oOO . instance_id , Ooo0OO0oOO . eid_prefix , Ooo0OO0oOO . group ,
 Ooo0OO0oOO . rloc_set )
 if 91 - 91: OoO0O00 / oO0ooO - II111iiii . oO0ooO
print "complete"
print ""
if 18 - 18: o0oOOo0O0Ooo
if 98 - 98: ii1II11I1ii1I * ii1II11I1ii1I / ii1II11I1ii1I + oO0ooO
if 34 - 34: O0Oo0oO0o
if 15 - 15: oO0ooO * O0Oo0oO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - ii11ii1ii
print "xTR provisioning complete!"
exit ( 0 )
if 68 - 68: iiIIIII1i1iI % i1IIi . oO0o0ooO0 . I1ii11iIi11i
if 92 - 92: ii1II11I1ii1I . iiIIIII1i1iI
if 31 - 31: iiIIIII1i1iI . OoOoOO00 / O0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
