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
# lisp-onoff.py
#
# This script will toggle "yes" or "no" valued configuration file item. What
# are supported are "lisp enable", "lisp debug", and "lisp xtr-parameters"
# sub-commands.
#
# This script will prompt for system, username, and password.
#
# Usage: python -O lisp-onoff.pyo [<command-name> [yes | no]]
#
#------------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
import sys
import os
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
def ooO0oo0oO0 ( lisp , command , yn ) :
 oo00 = { "map-resolver" : "mr" , "map-server" : "ms" ,
 "ddt-node" : "ddt" }
 if 88 - 88: iII111i . oO0o % ooOoO0o
 ooO0oooOoO0 = False
 II11i = command . find ( "debug-" )
 if ( II11i != - 1 ) :
  command = command [ len ( "debug-" ) : : ]
  ooO0oooOoO0 = True
  if 43 - 43: Ii1I . oO0o
  if 27 - 27: OoO0O00 - O0 . I1Ii111 * iII111i - I1ii11iIi11i
 i1111 = "enable_" if yn == "yes" else "disable_"
 if ( command in oo00 ) : command = oo00 [ command ]
 if 22 - 22: Ii1I . IiII
 if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
 if 74 - 74: iII111i * IiII
 if 82 - 82: iIii1I11I1II1 % IiII
 if ( ooO0oooOoO0 ) :
  oOo0oooo00o = getattr ( lisp , i1111 + command + "_debug" )
  return ( oOo0oooo00o ( ) )
  if 65 - 65: o0oOOo0O0Ooo * iIii1I11I1II1 * ooOoO0o
  if 18 - 18: iIii1I11I1II1 / I11i + oO0o / Oo0Ooo - II111iiii - I11i
  if 1 - 1: I11i - OOooOOo % O0 + I1IiiI - iII111i / I11i
  if 31 - 31: OoO0O00 + II111iiii
  if 13 - 13: OOooOOo * oO0o * I1IiiI
 if ( command in lisp . enable_status ) :
  oOo0oooo00o = getattr ( lisp , i1111 + command )
  return ( oOo0oooo00o ( ) )
  if 55 - 55: II111iiii
  if 43 - 43: OoOoOO00 - i1IIi + I1Ii111 + Ii1I
  if 17 - 17: o0oOOo0O0Ooo
  if 64 - 64: Ii1I % i1IIi % OoooooooOO
  if 3 - 3: iII111i + O0
 if ( command in lisp . xtr_parameters ) :
  if ( command == "data-plane-security" ) :
   command = "itr_security"
  elif ( command == "nat-traversal" ) :
   command = "xtr_nat_traversal"
  elif ( command == "rloc-probing" ) :
   command = "xtr_rloc_probing"
  elif ( command == "nonce-echoing" ) :
   command = "xtr_nonce_echoing"
  elif ( command == "data-plane-logging" ) :
   command = "xtr_data_plane_logging"
  elif ( command == "flow-logging" ) :
   command = "xtr_flow_logging"
  else :
   return ( False )
   if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
  oOo0oooo00o = getattr ( lisp , i1111 + command )
  return ( oOo0oooo00o ( ) )
  if 78 - 78: OoO0O00
 return ( False )
 if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
 if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
 if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
 if 14 - 14: I11i % O0
 if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
 if 77 - 77: Oo0Ooo . IiII % ooOoO0o
 if 42 - 42: oO0o - i1IIi / i11iIiiIii + OOooOOo + OoO0O00
def iIi ( lisp ) :
 for II in lisp . enable_status :
  print "  {}" . format ( II )
  if 14 - 14: Oo0Ooo . I1IiiI / Ii1I
 for II in lisp . debug_status :
  print "  debug-{}" . format ( II )
  if 38 - 38: II111iiii % i11iIiiIii . ooOoO0o - OOooOOo + Ii1I
 for II in lisp . xtr_parameters :
  print "  {}" . format ( II )
  if 66 - 66: OoooooooOO * OoooooooOO . OOooOOo . i1IIi - OOooOOo
  if 77 - 77: I11i - iIii1I11I1II1
  if 82 - 82: i11iIiiIii . OOooOOo / Oo0Ooo * O0 % oO0o % iIii1I11I1II1
  if 78 - 78: iIii1I11I1II1 - Ii1I * OoO0O00 + o0oOOo0O0Ooo + iII111i + iII111i
  if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
  if 74 - 74: iII111i * O0
  if 89 - 89: oO0o + Oo0Ooo
  if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
def III1ii1iII ( data ) :
 for oo0oooooO0 in data :
  i11Iiii = data [ oo0oooooO0 ]
  if ( i11Iiii == "yes" ) : i11Iiii = iI ( i11Iiii )
  if ( i11Iiii == "no" ) : i11Iiii = I1i1I1II ( i11Iiii )
  print "  {} = {}" . format ( oo0oooooO0 , i11Iiii )
  if 45 - 45: I1Ii111 . OoOoOO00
  if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
  if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
  if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
  if 8 - 8: OoOoOO00
  if 60 - 60: I11i / I11i
  if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
  if 83 - 83: OoooooooOO
def Iii111II ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 9 - 9: OoO0O00
 if 33 - 33: ooOoO0o . iII111i
 if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 if 50 - 50: I1IiiI
 if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
 if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
def iI ( string ) :
 return ( "\033[92m" + string + "\033[0m" )
 if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
 if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
 if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
 if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 if 58 - 58: i11iIiiIii % I11i
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
 if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
def I1i1I1II ( string ) :
 return ( "\033[91m" + string + "\033[0m" )
 if 16 - 16: I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
 if 44 - 44: oO0o
 if 88 - 88: I1Ii111 % Ii1I . II111iiii
iI1ii1Ii = os . getenv ( "LISPAPI_PATH" )
if ( iI1ii1Ii != None ) : sys . path . append ( iI1ii1Ii )
if 92 - 92: OoOoOO00
try :
 import lispapi
except :
 if ( os . path . exists ( "lispapi.pyo" ) ) :
  print "Try command 'python -O lisp-onoff.pyo'"
 else :
  print "Cannot find lispapi module, use LISPAPI_PATH env variable"
  if 26 - 26: iII111i . I1Ii111
 exit ( 1 )
 if 68 - 68: OoO0O00
 if 35 - 35: OoO0O00 - iII111i / Oo0Ooo / OoOoOO00
 if 24 - 24: ooOoO0o - ooOoO0o / II111iiii - I1ii11iIi11i
 if 69 - 69: oO0o . I1Ii111 + Ii1I / Oo0Ooo - oO0o
 if 63 - 63: OOooOOo % oO0o * oO0o * OoO0O00 / I1ii11iIi11i
if ( "help" in sys . argv ) :
 print "Usage: python -O lisp-onoff.pyo [<command-name> [yes | no]]"
 exit ( 0 )
 if 74 - 74: II111iiii
 if 75 - 75: o0oOOo0O0Ooo . ooOoO0o
 if 54 - 54: II111iiii % OoOoOO00 % I11i % iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
 if 87 - 87: ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
o0 = os . getenv ( "LISPAPI_SYSTEM" )
oo0oOo = os . getenv ( "LISPAPI_USER" )
o000O0o = os . getenv ( "LISPAPI_PW" )
II = None
if 42 - 42: OoOoOO00
if 41 - 41: Oo0Ooo . ooOoO0o + O0 * o0oOOo0O0Ooo % Oo0Ooo * Oo0Ooo
if 19 - 19: iII111i
if 46 - 46: I1ii11iIi11i - Ii1I . iIii1I11I1II1 / I1ii11iIi11i
if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
if 13 - 13: OOooOOo / i11iIiiIii
if ( o0 == None and os . path . exists ( "RESTART-LISP" ) ) :
 o0 = "localhost"
 oo0oOo = "root"
 o000O0o = ""
 if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
 if 52 - 52: o0oOOo0O0Ooo
 if 95 - 95: Ii1I
 if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
while ( o0 == None ) :
 o0 = raw_input ( "Enter lispers.net system: " )
 if ( o0 == "" ) : o0 = None
 if 61 - 61: II111iiii
while ( oo0oOo == None ) :
 oo0oOo = raw_input ( "Enter username for {}: " . format ( o0 ) )
 if ( oo0oOo == "" ) : oo0oOo = None
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
while ( o000O0o == None ) :
 o000O0o = raw_input ( "Enter password for {}: " . format ( o0 ) )
 if ( o000O0o == "" ) : o000O0o = None
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
print "Connecting to {} ..." . format ( Iii111II ( o0 ) ) ,
sys . stdout . flush ( )
o0o = lispapi . api_init ( o0 , oo0oOo , o000O0o )
if ( o0o == None or o0o . enable_status == None ) :
 print "failed"
 exit ( 1 )
 if 84 - 84: O0
print "connected"
print ""
if 74 - 74: I1ii11iIi11i - I1IiiI - Oo0Ooo . Ii1I - IiII
if 73 - 73: Oo0Ooo - i1IIi - i1IIi - iII111i . Ii1I + I1ii11iIi11i
if 81 - 81: iII111i * oO0o - I1Ii111 . II111iiii % I11i / I1IiiI
if 34 - 34: IiII
II = sys . argv [ 1 ] if ( len ( sys . argv ) >= 2 ) else None
oOo = sys . argv [ 2 ] if ( len ( sys . argv ) == 3 ) else None
if ( oOo ) :
 if ( oOo in [ "yes" , "y" ] ) :
  oOo = "yes"
 elif ( oOo in [ "no" , "n" ] ) :
  oOo = "no"
 else :
  oOo = None
  if 75 - 75: I1IiiI + Oo0Ooo
  if 73 - 73: O0 - OoooooooOO . OOooOOo - OOooOOo / OoOoOO00
  if 45 - 45: iIii1I11I1II1 % OoO0O00
if ( II ) :
 I1iIIii = II
 II11i = II . find ( "debug-" )
 if ( II11i != - 1 ) : I1iIIii = II [ len ( "debug-" ) : : ]
 if 22 - 22: II111iiii
 iiI1I11i1i = o0o . enable_status . keys ( ) + o0o . debug_status . keys ( ) + o0o . xtr_parameters . keys ( )
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
 if ( I1iIIii not in iiI1I11i1i ) :
  print "Invalid command '{}', valid commands are:" . format ( II )
  iIi ( o0o )
  exit ( 1 )
  if 92 - 92: iII111i
  if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 while ( oOo == None ) :
  oOo = "Enter 'y' to enable or 'n' to disable '{}': " . format ( II )
  oOo = raw_input ( oOo )
  oOo = "yes" if oOo == "y" else "no" if oOo == "n" else None
  if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
  if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 III1IiiI = Iii111II ( "'{} = {}'" . format ( II , oOo ) )
 iIi1 = raw_input ( "Confirm to set {}, y/n: " . format ( III1IiiI ) )
 if ( iIi1 != "y" ) : exit ( 0 )
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 print ""
 print "Sending command '{} = {}' ..." . format ( II , oOo ) ,
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % I1Ii111
 ooO00OO0 = ooO0oo0oO0 ( o0o , II , oOo )
 if ( ooO00OO0 == False ) : print Iii111II ( "failed" )
 print Iii111II ( "done" )
 print ""
 if 31 - 31: iII111i % iII111i % I11i
 if 69 - 69: OoO0O00 - Oo0Ooo + i1IIi / I1Ii111
print "lisp enable {" ,
sys . stdout . flush ( )
o0o . get_enable ( )
print ""
III1ii1iII ( o0o . enable_status )
print "}"
if 49 - 49: O0 . iII111i
print "lisp debug {" ,
sys . stdout . flush ( )
o0o . get_debug ( )
print ""
III1ii1iII ( o0o . debug_status )
print "}"
if 11 - 11: IiII * I1IiiI . iIii1I11I1II1 % OoooooooOO + iII111i
print "lisp xtr-parameters {" ,
sys . stdout . flush ( )
o0o . get_xtr_parameters ( )
print ""
III1ii1iII ( o0o . xtr_parameters )
print "}"
if 78 - 78: OoO0O00 . OOooOOo + OoO0O00 / I11i / OoO0O00
exit ( 0 )
if 54 - 54: OoOoOO00 % iII111i
if 37 - 37: OoOoOO00 * Oo0Ooo / ooOoO0o - iII111i % II111iiii . oO0o
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
