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
# lisp-map-cache.py
#
# This script will query a list of xTRs to retrieve their map-caches.
#
# Usage: python lisp-map-cache.py [<list-of-hosts>]
#
from __future__ import print_function
import sys
import os
from builtins import input
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
IiiIII111iI = False
if 34 - 34: iii1I1I / O00oOoOoO0o0O . O0oo0OO0 + Oo0ooO0oo0oO . OoO0O00 - I1ii11iIi11i
if 53 - 53: I11i / Oo0Ooo / II111iiii % Ii1I / OoOoOO00 . Oo0ooO0oo0oO
if 100 - 100: i1IIi
if 27 - 27: O00oOoOoO0o0O * OoooooooOO + I11i * Oo0ooO0oo0oO - i11iIiiIii - iii1I1I
IiiiIiI1iIiI1 = False
if 85 - 85: OoO0O00
if 28 - 28: Ii1I
if 64 - 64: I1ii11iIi11i % OoO0O00
if 1 - 1: O00oOoOoO0o0O
if 91 - 91: I1ii11iIi11i * iIii1I11I1II1 . O00oOoOoO0o0O / Ii1I
if 87 - 87: i1IIi / Ii1I . OoO0O00 * OoooooooOO - O00oOoOoO0o0O * Oo0ooO0oo0oO
if 82 - 82: I11i . O0oo0OO0 / O00oOoOoO0o0O % II111iiii % iIii1I11I1II1 % O00oOoOoO0o0O
if 86 - 86: OoOoOO00 % I1IiiI
def oo ( xtr , map_cache ) :
 print ( "LISP Map-Cache for '{}', {} entries\n" . format ( xtr , len ( map_cache ) ) )
 for IiII1I1i1i1ii in map_cache :
  IIIII = IiII1I1i1i1ii [ "instance-id" ]
  I1 = IiII1I1i1i1ii [ "eid-prefix" ]
  if ( "group-prefix" in IiII1I1i1i1ii ) :
   I1 = "({}, {})" . format ( I1 , IiII1I1i1i1ii [ "group-prefix" ] )
   if 54 - 54: OOooOOo % O0 + I1IiiI - iii1I1I / I11i
  iIiiI1 = IiII1I1i1i1ii [ "uptime" ]
  OoOooOOOO = IiII1I1i1i1ii [ "rloc-set" ]
  if 45 - 45: O0oo0OO0 + Ii1I
  iII111ii = len ( OoOooOOOO )
  if ( iII111ii ) :
   i1iIIi1 = "{} rlocs:" . format ( iII111ii )
  else :
   i1iIIi1 = "action: {}" . format ( IiII1I1i1i1ii [ "action" ] )
   if 50 - 50: i11iIiiIii - Ii1I
   if 78 - 78: OoO0O00
  print ( "[{}]{}, uptime: {}, {}" . format ( IIIII , I1 , iIiiI1 , i1iIIi1 ) )
  for Iii1I111 in OoOooOOOO :
   i1iIIi1 = Iii1I111 [ "address" ] if ( "address" in Iii1I111 ) else "none"
   iIiiI1 = Iii1I111 [ "uptime" ]
   OO0O0O00OooO = Iii1I111 [ "stats" ]
   OoooooOoo = Iii1I111 [ "upriority" ] + "/" + Iii1I111 [ "uweight" ] + "/" + Iii1I111 [ "mpriority" ] + "/" + Iii1I111 [ "mweight" ]
   if 70 - 70: OoO0O00 . OoO0O00 - OoO0O00 / I1ii11iIi11i * OOooOOo
   print ( "  {}, uptime: {}, {}" . format ( i1iIIi1 , iIiiI1 , OoooooOoo ) )
   if 86 - 86: i11iIiiIii + Ii1I + Oo0ooO0oo0oO * I11i + o0oOOo0O0Ooo
   if ( "geo" in Iii1I111 ) : print ( "    geo: {}" . format ( Iii1I111 [ "geo" ] ) )
   if ( "elp" in Iii1I111 ) : print ( "    elp: {}" . format ( Iii1I111 [ "elp" ] ) )
   if ( "rle" in Iii1I111 ) : print ( "    rle: {}" . format ( Iii1I111 [ "rle" ] ) )
   if 61 - 61: OoO0O00 / i11iIiiIii
   IiIiIi = OO0O0O00OooO . find ( "byte-count" )
   print ( "    {}" . format ( OO0O0O00OooO [ : IiIiIi - 2 ] ) )
   print ( "    {}" . format ( OO0O0O00OooO [ IiIiIi : ] ) )
   if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
  print ( "" )
  if 33 - 33: Ii1I + II111iiii % i11iIiiIii . Oo0ooO0oo0oO - I1IiiI
 return
 if 66 - 66: Ii1I - OoooooooOO * OoooooooOO . OOooOOo . I1ii11iIi11i
 if 22 - 22: OoooooooOO % I11i - iii1I1I . iIii1I11I1II1 * i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . O00oOoOoO0o0O
 if 61 - 61: Oo0ooO0oo0oO
oOOO00o = os . getenv ( "LISPAPI_PATH" )
if ( oOOO00o != None ) :
 sys . path . append ( oOOO00o )
else :
 sys . path . append ( "./" )
 if 97 - 97: I11i % I11i + II111iiii * iii1I1I
 if 54 - 54: I11i + O00oOoOoO0o0O / iii1I1I
try :
 import lispapi
except :
 if ( os . path . exists ( "lispapi.pyo" ) ) :
  print ( "Try command 'python -O lisp-map-cache.py'" )
 else :
  print ( "Cannot find lispapi module, use LISPAPI_PATH env variable" )
  if 9 - 9: OoOoOO00 / Oo0Ooo - O00oOoOoO0o0O . i1IIi / I1IiiI % O00oOoOoO0o0O
 exit ( 1 )
 if 71 - 71: O0oo0OO0 . O0
 if 73 - 73: OOooOOo % OoOoOO00 - Ii1I
 if 10 - 10: I1IiiI % I1ii11iIi11i
 if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo
oO00 = os . getenv ( "LISPAPI_USER" )
if ( oO00 == None ) :
 if ( IiiIII111iI ) :
  print ( "LISPAPI_USER environment variable needs username setting" )
  exit ( 0 )
  if 53 - 53: OoooooooOO . i1IIi
 oO00 = "root"
 if 18 - 18: o0oOOo0O0Ooo
I1i1I1II = os . getenv ( "LISPAPI_PW" )
if ( I1i1I1II == None ) :
 if ( IiiIII111iI ) :
  print ( "LISPAPI_PW environment variable needs password setting" )
  exit ( 0 )
  if 45 - 45: O0oo0OO0 . OoOoOO00
 I1i1I1II = ""
 if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
I1I = os . getenv ( "LISPAPI_PORT" )
if ( I1I == None ) : I1I = 8080
if 80 - 80: OoOoOO00 - OoO0O00
if 87 - 87: oO0o / I11i - i1IIi * OOooOOo / OoooooooOO . O0
if 1 - 1: II111iiii - I11i / I11i
if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - O0oo0OO0
if 83 - 83: OoooooooOO
if 31 - 31: II111iiii - OOooOOo . O0oo0OO0 % OoOoOO00 - O0
iii11 = [ ]
if ( len ( sys . argv ) > 1 ) :
 O0oo0OO0oOOOo = sys . argv [ 1 : : ]
 for i1i1i11IIi in O0oo0OO0oOOOo : iii11 . append ( [ i1i1i11IIi , None , None ] )
else :
 if ( IiiiIiI1iIiI1 ) :
  while ( True ) :
   i1i1i11IIi = input ( "Enter hostname (enter return when done): " )
   if ( i1i1i11IIi == "" ) : break
   iii11 . append ( [ i1i1i11IIi , None , None ] )
   if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 else :
  iii11 . append ( [ "localhost" , None , None ] )
  if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
  if 16 - 16: O0 - O0oo0OO0 * iIii1I11I1II1 + iii1I1I
  if 50 - 50: II111iiii - Oo0ooO0oo0oO * I1ii11iIi11i / O0oo0OO0 + o0oOOo0O0Ooo
print ( "Connecting to APIs ..." , end = " " )
sys . stdout . flush ( )
if 88 - 88: Ii1I / O0oo0OO0 + iii1I1I - II111iiii / Oo0ooO0oo0oO - OoOoOO00
if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
if 58 - 58: i11iIiiIii % I11i
if 71 - 71: OOooOOo + Oo0ooO0oo0oO % i11iIiiIii + I1ii11iIi11i - O00oOoOoO0o0O
for i1i1i11IIi in iii11 :
 i1i1i11IIi [ 1 ] = lispapi . api_init ( i1i1i11IIi [ 0 ] , oO00 , I1i1I1II , port = I1I )
 if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
print ( "" )
if 16 - 16: I1IiiI * oO0o % O00oOoOoO0o0O
if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . Oo0ooO0oo0oO * I11i
if 44 - 44: oO0o
if 88 - 88: O0oo0OO0 % Ii1I . II111iiii
for i1i1i11IIi in iii11 :
 if ( i1i1i11IIi [ 1 ] == None ) :
  print ( "Could not open API to {}" . format ( i1i1i11IIi [ 0 ] ) )
 else :
  print ( "Querying {} ... " . format ( i1i1i11IIi [ 0 ] ) , )
  i1i1i11IIi [ 2 ] = i1i1i11IIi [ 1 ] . get_map_cache ( )
  print ( "done" )
  if 38 - 38: o0oOOo0O0Ooo
  if 57 - 57: O0 / oO0o * O0oo0OO0 / OoOoOO00 . II111iiii
print ( "" )
if 26 - 26: iii1I1I
if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iii1I1I / OoooooooOO
if 39 - 39: I1ii11iIi11i / Oo0ooO0oo0oO - II111iiii
if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
for i1i1i11IIi in iii11 :
 oOOOO00O0O0 = i1i1i11IIi [ 2 ]
 if ( oOOOO00O0O0 == None ) : continue
 if ( type ( oOOOO00O0O0 ) == list ) :
  if ( len ( oOOOO00O0O0 ) == 0 ) :
   print ( "Empty map-cache" )
   continue
   if 65 - 65: I1ii11iIi11i + I11i
  if ( "?" in oOOOO00O0O0 [ 0 ] . keys ( ) ) :
   print ( "Not authenticated to access {}" . format ( i1i1i11IIi [ 0 ] ) )
   continue
   if 10 - 10: OoooooooOO % iIii1I11I1II1
   if 54 - 54: O0oo0OO0 - II111iiii % OoOoOO00 % I11i % iIii1I11I1II1 + Oo0ooO0oo0oO
   if 15 - 15: I11i * Oo0ooO0oo0oO * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
   if 68 - 68: O0oo0OO0 % i1IIi . O00oOoOoO0o0O . I1ii11iIi11i
   if 92 - 92: iii1I1I . O0oo0OO0
   if 31 - 31: O0oo0OO0 . OoOoOO00 / O0
 oo ( i1i1i11IIi [ 0 ] , i1i1i11IIi [ 2 ] )
 if 89 - 89: OoOoOO00
 if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + Oo0ooO0oo0oO
exit ( 0 )
if 4 - 4: Oo0ooO0oo0oO + O0 * OOooOOo
if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
if 25 - 25: I1ii11iIi11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
