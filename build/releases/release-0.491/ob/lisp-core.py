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
# lisp-core.py
#
# This is the core process that is used to demux to the specific LISP 
# functional components. The 4342 listen socket is centralized here.
#
#
#        +------------- data encapsulation via network --------------+
#        |                                                           |
#        |               IPC when mr & ms colocated                  |
#        |           +--------------------------------+              |
#        |           |                                |              |
#        |           |  IPC when mr & ddt colo        |              |
#        |           |    +------------+              |              |
#        |           |    |            |              |              |
#        |           |    |            v              v              v 4341
#  +-------------+  +----------+   +----------+   +----------+   +----------+ 
#  | lisp-[ir]tr |  | lisp-mr  |   | lisp-ddt |   | lisp-ms  |   | lisp-etr |
#  +-------------+  +----------+   +----------+   +----------+   +----------+ 
#        ^ IPC          ^ IPC          ^ IPC          ^ IPC          ^ IPC
#        |              |              |              |              |
#        |              |              |              |              |
#        |              |              |              |              |
#        +--------------+--------------+--------------+--------------+
#                                      |
#                                      | for dispatching control messages
#                                +-----------+
#                                | lisp-core |
#                                +-----------+
#                                      | 4342
#                                      |
#                                  via network
#
# -----------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
import lisp
import lispconfig
import multiprocessing
import threading
import commands
import time
import os
import bottle
from cherrypy import wsgiserver
from cherrypy . wsgiserver . ssl_pyopenssl import pyOpenSSLAdapter
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
import json
import sys
import socket
import thread
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
Oo0o = ""
if 60 - 60: I1ii11iIi11i + I1Ii111 - I11i / i1IIi
Ii1iI = None
Oo = None
I1Ii11I1Ii1i = None
Ooo = [ None , None , None ]
o0oOoO00o = None
if 43 - 43: Ii1I . oO0o
if 27 - 27: OoO0O00 - O0 . I1Ii111 * iII111i - I1ii11iIi11i
if 15 - 15: I1IiiI
if 90 - 90: IiII * i1IIi / Ii1I . OoO0O00 * oO0o
if 16 - 16: ooOoO0o * IiII % I11i . I1Ii111 / IiII % iII111i
if 27 - 27: IiII . i1IIi * OoOoOO00 % Ii1I / i1IIi
if 3 - 3: IiII / ooOoO0o
if 28 - 28: ooOoO0o + I1Ii111 - ooOoO0o . OoooooooOO
@ bottle . route ( '/lisp/api' , method = "get" )
@ bottle . route ( '/lisp/api/<command>' , method = "get" )
@ bottle . route ( '/lisp/api/<command>/<data_structure>' , method = "get" )
def oO0 ( command = "" , data_structure = "" ) :
 IIIi1i1I = [ { "?" : [ { "?" : "not-auth" } ] } ]
 if 72 - 72: Oo0Ooo % OOooOOo . I1IiiI / I11i * I1IiiI
 if 31 - 31: II111iiii + OoO0O00 . I1Ii111
 if 68 - 68: I1IiiI - i11iIiiIii - OoO0O00 / OOooOOo - OoO0O00 + i1IIi
 if 48 - 48: OoooooooOO % o0oOOo0O0Ooo . I1IiiI - Ii1I % i1IIi % OoooooooOO
 if ( bottle . request . auth != None ) :
  i1iIIi1 , ii11iIi1I = bottle . request . auth
  if ( lispconfig . lisp_find_user_account ( i1iIIi1 , ii11iIi1I ) == False ) :
   return ( json . dumps ( IIIi1i1I ) )
   if 6 - 6: OoOoOO00 * iII111i
 else :
  if ( bottle . request . headers [ "User-Agent" ] . find ( "python" ) != - 1 ) :
   return ( json . dumps ( IIIi1i1I ) )
   if 67 - 67: ooOoO0o - oO0o * o0oOOo0O0Ooo % o0oOOo0O0Ooo % I11i * OoOoOO00
  if ( lispconfig . lisp_validate_user ( ) == False ) :
   return ( json . dumps ( IIIi1i1I ) )
   if 26 - 26: Ii1I - o0oOOo0O0Ooo
   if 63 - 63: II111iiii . II111iiii
   if 32 - 32: i1IIi . I11i % OoO0O00 . o0oOOo0O0Ooo
   if 42 - 42: I1Ii111 + I1ii11iIi11i
   if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
   if 23 - 23: i11iIiiIii + I1IiiI
   if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
 if ( command == "data" and data_structure != "" ) :
  II = bottle . request . body . readline ( )
  IIIi1i1I = json . loads ( II ) if II != "" else ""
  if ( IIIi1i1I != "" ) : IIIi1i1I = IIIi1i1I . values ( ) [ 0 ]
  if ( IIIi1i1I == [ ] ) : IIIi1i1I = ""
  if 14 - 14: Oo0Ooo . I1IiiI / Ii1I
  if ( type ( IIIi1i1I ) == dict and type ( IIIi1i1I . values ( ) [ 0 ] ) == dict ) :
   IIIi1i1I = IIIi1i1I . values ( ) [ 0 ]
   if 38 - 38: II111iiii % i11iIiiIii . ooOoO0o - OOooOOo + Ii1I
   if 66 - 66: OoooooooOO * OoooooooOO . OOooOOo . i1IIi - OOooOOo
  IIIi1i1I = o0o00ooo0 ( data_structure , IIIi1i1I )
  return ( IIIi1i1I )
  if 96 - 96: O0 % oO0o % iIii1I11I1II1
  if 78 - 78: iIii1I11I1II1 - Ii1I * OoO0O00 + o0oOOo0O0Ooo + iII111i + iII111i
  if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
  if 74 - 74: iII111i * O0
  if 89 - 89: oO0o + Oo0Ooo
 if ( command != "" ) :
  command = "lisp " + command
 else :
  II = bottle . request . body . readline ( )
  if ( II == "" ) :
   IIIi1i1I = [ { "?" : [ { "?" : "no-body" } ] } ]
   return ( json . dumps ( IIIi1i1I ) )
   if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
   if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
  IIIi1i1I = json . loads ( II )
  command = IIIi1i1I . keys ( ) [ 0 ]
  if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
  if 20 - 20: o0oOOo0O0Ooo
 IIIi1i1I = lispconfig . lisp_get_clause_for_api ( command )
 return ( json . dumps ( IIIi1i1I ) )
 if 77 - 77: OoOoOO00 / I11i
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
 if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % oO0o . O0
 if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
 if 53 - 53: IiII + I1IiiI * oO0o
 if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
def o00O ( ) :
 IIIi1i1I = { }
 IIIi1i1I [ "hostname" ] = socket . gethostname ( )
 IIIi1i1I [ "system-uptime" ] = commands . getoutput ( "uptime" )
 IIIi1i1I [ "lisp-uptime" ] = lisp . lisp_print_elapsed ( lisp . lisp_uptime )
 IIIi1i1I [ "lisp-version" ] = lisp . lisp_version
 if 69 - 69: oO0o % I1Ii111 - o0oOOo0O0Ooo + I1Ii111 - O0 % OoooooooOO
 Iii111II = "yes" if os . path . exists ( "./logs/lisp-traceback.log" ) else "no"
 IIIi1i1I [ "traceback-log" ] = Iii111II
 if 9 - 9: OoO0O00
 i11 = lisp . lisp_myrlocs [ 0 ]
 O0oo0OO0oOOOo = lisp . lisp_myrlocs [ 1 ]
 i11 = "none" if ( i11 == None ) else i11 . print_address_no_iid ( )
 O0oo0OO0oOOOo = "none" if ( O0oo0OO0oOOOo == None ) else O0oo0OO0oOOOo . print_address_no_iid ( )
 IIIi1i1I [ "lisp-rlocs" ] = [ i11 , O0oo0OO0oOOOo ]
 return ( json . dumps ( IIIi1i1I ) )
 if 35 - 35: IiII % I1IiiI
 if 70 - 70: iII111i * I1ii11iIi11i
 if 46 - 46: ooOoO0o / OoO0O00
 if 52 - 52: o0oOOo0O0Ooo - OoooooooOO + Ii1I + Ii1I - o0oOOo0O0Ooo / I1Ii111
 if 44 - 44: ooOoO0o . i1IIi - I1ii11iIi11i . O0 - ooOoO0o
 if 92 - 92: iII111i . I11i + o0oOOo0O0Ooo
 if 28 - 28: i1IIi * Oo0Ooo - o0oOOo0O0Ooo * IiII * Ii1I / OoO0O00
 if 94 - 94: II111iiii % I1ii11iIi11i / OoOoOO00 * iIii1I11I1II1
 if 54 - 54: o0oOOo0O0Ooo - I1IiiI + OoooooooOO
 if 70 - 70: Ii1I / I11i . iII111i % Oo0Ooo
 if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . IiII - OoO0O00 * o0oOOo0O0Ooo
 if 46 - 46: OOooOOo + OoOoOO00 . I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
 if 44 - 44: oO0o
 if 88 - 88: I1Ii111 % Ii1I . II111iiii
def o0o00ooo0 ( data_structure , data ) :
 iI1ii1Ii = [ "site-cache" , "map-cache" , "system" , "map-resolver" ,
 "map-server" ]
 if 92 - 92: OoOoOO00
 if ( data_structure not in iI1ii1Ii ) : return ( json . dumps ( [ ] ) )
 if 26 - 26: iII111i . I1Ii111
 if 68 - 68: OoO0O00
 if 35 - 35: OoO0O00 - iII111i / Oo0Ooo / OoOoOO00
 if 24 - 24: ooOoO0o - ooOoO0o / II111iiii - I1ii11iIi11i
 if ( data_structure == "system" ) : return ( o00O ( ) )
 if 69 - 69: oO0o . I1Ii111 + Ii1I / Oo0Ooo - oO0o
 if 63 - 63: OOooOOo % oO0o * oO0o * OoO0O00 / I1ii11iIi11i
 if 74 - 74: II111iiii
 if 75 - 75: o0oOOo0O0Ooo . ooOoO0o
 if ( data != "" ) : data = json . dumps ( data )
 Oo0O00Oo0o0 = lisp . lisp_api_ipc ( "lisp-core" , data_structure + "%" + data )
 if 87 - 87: ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if ( data_structure in [ "map-cache" , "map-resolver" ] ) :
  if ( lisp . lisp_is_running ( "lisp-rtr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( Oo0O00Oo0o0 , Oo , "lisp-rtr" )
  elif ( lisp . lisp_is_running ( "lisp-itr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( Oo0O00Oo0o0 , Oo , "lisp-itr" )
  else :
   return ( json . dumps ( [ ] ) )
   if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
   if 92 - 92: iII111i . I1Ii111
 if ( data_structure == "map-server" ) :
  if ( lisp . lisp_is_running ( "lisp-etr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( Oo0O00Oo0o0 , Oo , "lisp-etr" )
  else :
   return ( json . dumps ( [ ] ) )
   if 31 - 31: I1Ii111 . OoOoOO00 / O0
   if 89 - 89: OoOoOO00
 if ( data_structure == "site-cache" ) :
  if ( lisp . lisp_is_running ( "lisp-ms" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( Oo0O00Oo0o0 , Oo , "lisp-ms" )
  else :
   return ( json . dumps ( [ ] ) )
   if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
   if 4 - 4: ooOoO0o + O0 * OOooOOo
   if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
 lisp . lprint ( "Waiting for api get-data '{}', parmameters: '{}'" . format ( data_structure , data ) )
 if 25 - 25: I1ii11iIi11i
 if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
 iIii , ooo0O , oOoO0o00OO0 , i1I1ii = lisp . lisp_receive ( Oo , True )
 lisp . lisp_ipc_lock . release ( )
 return ( i1I1ii )
 if 61 - 61: II111iiii
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
 if 67 - 67: I1Ii111 . iII111i . O0
 if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
@ bottle . route ( '/lisp/api' , method = "put" )
@ bottle . route ( '/lisp/api/<command>' , method = "put" )
@ bottle . route ( '/lisp/api/<command>' , method = "delete" )
def I1111IIi ( command = "" ) :
 IIIi1i1I = [ { "?" : [ { "?" : "not-auth" } ] } ]
 if ( bottle . request . auth == None ) : return ( IIIi1i1I )
 if 93 - 93: OoooooooOO / I1IiiI % i11iIiiIii + I1ii11iIi11i * OoO0O00
 if 15 - 15: I11i . OoO0O00 / Oo0Ooo + I11i
 if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
 if 49 - 49: Ii1I / OoO0O00 . II111iiii
 if ( bottle . request . auth != None ) :
  i1iIIi1 , ii11iIi1I = bottle . request . auth
  if ( lispconfig . lisp_find_user_account ( i1iIIi1 , ii11iIi1I ) == False ) :
   return ( json . dumps ( IIIi1i1I ) )
   if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
 else :
  if ( bottle . request . headers [ "User-Agent" ] . find ( "python" ) != - 1 ) :
   return ( json . dumps ( IIIi1i1I ) )
   if 31 - 31: II111iiii . I1IiiI
  if ( lispconfig . lisp_validate_user ( ) == False ) :
   return ( json . dumps ( IIIi1i1I ) )
   if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
   if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
   if 92 - 92: iII111i
   if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
   if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
   if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
   if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if ( command == "user-account" ) :
  if ( lispconfig . lisp_is_user_superuser ( i1iIIi1 ) == False ) :
   IIIi1i1I = [ { "user-account" : [ { "?" : "not-auth" } ] } ]
   return ( json . dumps ( IIIi1i1I ) )
   if 51 - 51: O0 + iII111i
   if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
   if 48 - 48: O0
   if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
   if 41 - 41: Ii1I - O0 - O0
   if 68 - 68: OOooOOo % I1Ii111
 II = bottle . request . body . readline ( )
 if ( II == "" ) :
  IIIi1i1I = [ { "?" : [ { "?" : "no-body" } ] } ]
  return ( json . dumps ( IIIi1i1I ) )
  if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
  if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 IIIi1i1I = json . loads ( II )
 if ( command != "" ) :
  command = "lisp " + command
 else :
  command = IIIi1i1I [ 0 ] . keys ( ) [ 0 ]
  if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
  if 23 - 23: O0
  if 85 - 85: Ii1I
  if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
  if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
  if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
 lisp . lisp_ipc_lock . acquire ( )
 if ( bottle . request . method == "DELETE" ) :
  IIIi1i1I = lispconfig . lisp_remove_clause_for_api ( IIIi1i1I )
 else :
  IIIi1i1I = lispconfig . lisp_put_clause_for_api ( IIIi1i1I )
  if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
 lisp . lisp_ipc_lock . release ( )
 return ( json . dumps ( IIIi1i1I ) )
 if 77 - 77: iIii1I11I1II1 * OoO0O00
 if 95 - 95: I1IiiI + i11iIiiIii
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
@ bottle . route ( '/lisp/show/api-doc' , method = "get" )
def oooO0 ( ) :
 if ( os . path . exists ( "lispapi.py" ) ) : os . system ( "pydoc lispapi > lispapi.txt" )
 if ( os . path . exists ( "lispapi.txt" ) == False ) :
  return ( "lispapi.txt file not found" )
  if 46 - 46: I1Ii111
 return ( bottle . static_file ( "lispapi.txt" , root = "./" ) )
 if 60 - 60: o0oOOo0O0Ooo
 if 25 - 25: OoO0O00
 if 62 - 62: OOooOOo + O0
 if 98 - 98: o0oOOo0O0Ooo
 if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
@ bottle . route ( '/lisp/show/command-doc' , method = "get" )
def OoO0o ( ) :
 return ( bottle . static_file ( "lisp.config.example" , root = "./" ,
 mimetype = "text/plain" ) )
 if 78 - 78: oO0o % O0 % Ii1I
 if 46 - 46: OoooooooOO . i11iIiiIii
 if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 if 87 - 87: Oo0Ooo . IiII
 if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
 if 55 - 55: OOooOOo . I1IiiI
 if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
@ bottle . route ( '/lisp/show/lisp-xtr' , method = "get" )
def o0oOO000oO0oo ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 77 - 77: Oo0Ooo - i1IIi - I11i . OoOoOO00
  if 39 - 39: II111iiii / ooOoO0o + I1Ii111 / OoOoOO00
  if 13 - 13: IiII + O0 + iII111i % I1IiiI / o0oOOo0O0Ooo . IiII
  if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
  if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
  if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 if ( os . path . exists ( "./show-ztr" ) ) :
  Oo0O0oooo = open ( "./show-ztr" , "r" ) ; I111iI = Oo0O0oooo . read ( ) ; Oo0O0oooo . close ( )
 else :
  Oo0O0oooo = open ( "./show-xtr" , "r" ) ; I111iI = Oo0O0oooo . read ( ) ; Oo0O0oooo . close ( )
  if 56 - 56: I1IiiI
  if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 OoO0OOOOo0O = ""
 I111iI = I111iI . split ( "\n" )
 for OooOO in I111iI :
  if ( OooOO [ 0 : 4 ] == "    " ) : OoO0OOOOo0O += lisp . lisp_space ( 4 )
  if ( OooOO [ 0 : 2 ] == "  " ) : OoO0OOOOo0O += lisp . lisp_space ( 2 )
  OoO0OOOOo0O += OooOO + "<br>"
  if 21 - 21: I11i / IiII % iIii1I11I1II1 * Oo0Ooo
 OoO0OOOOo0O = lisp . convert_font ( OoO0OOOOo0O )
 return ( lisp . lisp_print_sans ( OoO0OOOOo0O ) )
 if 57 - 57: II111iiii + i1IIi
 if 10 - 10: oO0o + i1IIi
 if 87 - 87: I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if 97 - 97: O0 + OoOoOO00
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
@ bottle . route ( '/lisp/show/<xtr>/keys' , method = "get" )
def iiIiI1i1 ( xtr ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 69 - 69: ooOoO0o
 I11iII = lispconfig . lisp_is_user_superuser ( None )
 if 5 - 5: I1IiiI
 if ( I11iII == False ) :
  i1I1ii = "Permission denied"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( i1I1ii ) ) )
  if 48 - 48: o0oOOo0O0Ooo - oO0o / OoooooooOO
  if 100 - 100: I1IiiI / o0oOOo0O0Ooo % II111iiii % Oo0Ooo % OOooOOo
 if ( xtr not in [ "itr" , "etr" , "rtr" ] ) :
  i1I1ii = "Invalid URL"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( i1I1ii ) ) )
  if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 OOoOO0o0o0 = "show {}-keys" . format ( xtr )
 return ( lispconfig . lisp_process_show_command ( Oo , OOoOO0o0o0 ) )
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
 if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
 if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
 if 71 - 71: I1Ii111 + Ii1I
 if 28 - 28: OOooOOo
 if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
 if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
@ bottle . route ( '/lisp/geo-map/<geo_prefix>' )
def IIo0Oo0oO0oOO00 ( geo_prefix ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 92 - 92: OoooooooOO * I1Ii111
  if 100 - 100: I1Ii111 + I1Ii111 * IiII
 geo_prefix = geo_prefix . split ( "-" )
 geo_prefix = "-" . join ( geo_prefix [ 0 : - 1 ] ) + "/" + geo_prefix [ - 1 ]
 I1i = lisp . lisp_geo ( "" )
 I1i . parse_geo_string ( geo_prefix )
 O00Oooo , i11I = I1i . dms_to_decimal ( )
 o00Oo0oooooo = I1i . radius * 1000
 if 76 - 76: I11i / OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 o0o = open ( "./lispers.net-geo.html" , "r" ) ; oo0 = o0o . read ( ) ; o0o . close ( )
 oo0 = oo0 . replace ( "$LAT" , str ( O00Oooo ) )
 oo0 = oo0 . replace ( "$LON" , str ( i11I ) )
 oo0 = oo0 . replace ( "$RADIUS" , str ( o00Oo0oooooo ) )
 return ( oo0 )
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
 if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 58 - 58: I1IiiI
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
@ bottle . route ( '/lisp/login' , method = "get" )
def oOO00O ( ) :
 return ( lispconfig . lisp_login_page ( ) )
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
 if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 if 23 - 23: i11iIiiIii
 if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
 if 81 - 81: IiII % i1IIi . iIii1I11I1II1
 if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
 if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
 if 31 - 31: OOooOOo
@ bottle . route ( '/lisp/login' , method = "post" )
def i1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) ) :
  return ( lispconfig . lisp_landing_page ( ) )
  if 88 - 88: OoO0O00 - ooOoO0o + OOooOOo * I1IiiI % iIii1I11I1II1 + Oo0Ooo
 return ( oOO00O ( ) )
 if 76 - 76: I1IiiI * iII111i % I1Ii111
 if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
 if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
 if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
 if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
 if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
 if 42 - 42: I1IiiI
@ bottle . route ( '/lisp' )
def II1i11I ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 50 - 50: OoooooooOO % I11i
 return ( lispconfig . lisp_landing_page ( ) )
 if 49 - 49: oO0o - i11iIiiIii . I1Ii111 * Ii1I % iII111i + i1IIi
 if 71 - 71: o0oOOo0O0Ooo
 if 38 - 38: oO0o % OoOoOO00 + I1ii11iIi11i . i11iIiiIii
 if 53 - 53: i11iIiiIii * iII111i
 if 68 - 68: iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
 if 38 - 38: ooOoO0o - OOooOOo / iII111i
 if 66 - 66: O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / Ii1I + I1ii11iIi11i
@ bottle . route ( '/lisp/traceback' )
def ooo00Ooo ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 93 - 93: i11iIiiIii - I1IiiI * I1ii11iIi11i * I11i % O0 + OoooooooOO
  if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
 o0O0oo0OO0O = True
 if 68 - 68: oO0o . I11i % OoooooooOO . I11i
 if 64 - 64: iIii1I11I1II1 / I1IiiI . II111iiii + OoooooooOO . OoO0O00
 if 56 - 56: Oo0Ooo . I1ii11iIi11i . I1IiiI
 if 39 - 39: O0 + I1Ii111
 if ( os . path . exists ( "./logs/lisp-traceback.log" ) ) :
  i1I1ii = commands . getoutput ( "cat ./logs/lisp-traceback.log" )
  if ( i1I1ii ) :
   i1I1ii = i1I1ii . replace ( "----------" , "<b>----------</b>" )
   i1I1ii = i1I1ii . replace ( "\n" , "<br>" )
   o0O0oo0OO0O = False
   if 91 - 91: OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoOoOO00 + O0
   if 26 - 26: I1ii11iIi11i - OoooooooOO
   if 11 - 11: I1IiiI * oO0o
   if 81 - 81: iII111i + IiII
   if 98 - 98: I1IiiI
   if 95 - 95: ooOoO0o / ooOoO0o
 if ( o0O0oo0OO0O ) :
  i1I1ii = ""
  IIiI1Ii = "egrep --with-filename Traceback ./logs/*.log"
  O0O0O0Oo = commands . getoutput ( IIiI1Ii )
  for OOOOoO00o0O in O0O0O0Oo :
   if ( OOOOoO00o0O . find ( ":" ) == - 1 ) : continue
   OooOO = OOOOoO00o0O . split ( ":" )
   if ( OooOO [ 1 ] == "0" ) : continue
   i1I1ii += "Found Tracebacks in log file {}<br>" . format ( OooOO [ 0 ] )
   o0O0oo0OO0O = False
   if 41 - 41: OOooOOo * Ii1I - IiII + o0oOOo0O0Ooo
  i1I1ii = i1I1ii [ 0 : - 4 ]
  if 64 - 64: Ii1I
  if 66 - 66: i11iIiiIii - OOooOOo * Oo0Ooo
 if ( o0O0oo0OO0O ) :
  i1I1ii = "No Tracebacks found - a stable system is a happy system"
  if 76 - 76: i11iIiiIii + o0oOOo0O0Ooo / I1ii11iIi11i - OoO0O00 - Ii1I + I1ii11iIi11i
  if 51 - 51: iIii1I11I1II1 . ooOoO0o + iIii1I11I1II1
 i1I1ii = lisp . lisp_print_cour ( i1I1ii )
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 95 - 95: I1IiiI
 if 46 - 46: OoOoOO00 + OoO0O00
 if 70 - 70: iII111i / iIii1I11I1II1
 if 85 - 85: OoooooooOO % i1IIi * OoooooooOO / I1ii11iIi11i
 if 96 - 96: OoooooooOO + oO0o
 if 44 - 44: oO0o
 if 20 - 20: I11i + Ii1I / O0 % iIii1I11I1II1
@ bottle . route ( '/lisp/show/not-supported' )
def oOo0O ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 64 - 64: I1ii11iIi11i - iII111i + iII111i - I11i
 return ( lispconfig . lisp_not_supported ( ) )
 if 30 - 30: iIii1I11I1II1 . I1IiiI . OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 if 46 - 46: Oo0Ooo
 if 1 - 1: iII111i
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
@ bottle . route ( '/lisp/show/status' )
def IIii11I1i1I ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 99 - 99: iII111i
  if 76 - 76: OoO0O00 * I1IiiI
  if 82 - 82: Ii1I * iII111i / I1ii11iIi11i
  if 36 - 36: OoooooooOO - i1IIi . O0 / II111iiii + o0oOOo0O0Ooo
  if 33 - 33: II111iiii / ooOoO0o * O0 % Ii1I * I1Ii111
 i1I1ii = ""
 I11iII = lispconfig . lisp_is_user_superuser ( None )
 if ( I11iII ) :
  O0o = lisp . lisp_button ( "show configuration" , "/lisp/show/conf" )
  O0OOoOOO0oO = lisp . lisp_button ( "show configuration diff" , "/lisp/show/diff" )
  I1ii11 = lisp . lisp_button ( "archive configuration" , "/lisp/archive/conf" )
  oOoOoOoo0 = lisp . lisp_button ( "clear configuration" , "/lisp/clear/conf/verify" )
  OOOOoO00o0O = lisp . lisp_button ( "log flows" , "/lisp/log/flows" )
  III1ii1I = lisp . lisp_button ( "install LISP software" , "/lisp/install/image" )
  Ii1i1iI = lisp . lisp_button ( "restart LISP subsystem" , "/lisp/restart/verify" )
  if 16 - 16: OOooOOo / Oo0Ooo / OoooooooOO * I1IiiI + i1IIi % OOooOOo
  i1I1ii = "<center>{}{}{}{}{}{}{}</center><hr>" . format ( O0o , O0OOoOOO0oO , I1ii11 , oOoOoOoo0 ,
 OOOOoO00o0O , III1ii1I , Ii1i1iI )
  if 71 - 71: OoOoOO00
  if 14 - 14: i11iIiiIii % OOooOOo
 OooO0oo = commands . getoutput ( "uptime" )
 o0o0oOoOO0O = commands . getoutput ( "uname -pv" )
 i1ii1II1ii = lisp . lisp_version . replace ( "+" , "" )
 if 28 - 28: I1ii11iIi11i
 if 61 - 61: OOooOOo % OOooOOo * o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 75 - 75: IiII . ooOoO0o
 if 50 - 50: OoOoOO00
 if 60 - 60: ooOoO0o * iIii1I11I1II1 * I1ii11iIi11i * Oo0Ooo
 O0ooooo0OOOO0 = multiprocessing . cpu_count ( )
 if 9 - 9: II111iiii - o0oOOo0O0Ooo / iII111i / o0oOOo0O0Ooo
 I1i111iiIIIi = OooO0oo . find ( ", load" )
 OooO0oo = OooO0oo [ 0 : I1i111iiIIIi ]
 O00 = lisp . lisp_print_elapsed ( lisp . lisp_uptime )
 if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 iIiIIIIIii = "Not available"
 if 58 - 58: o0oOOo0O0Ooo / IiII . OoOoOO00 / OoooooooOO + I1Ii111
 if 86 - 86: I11i * I1IiiI + I11i + II111iiii
 if 8 - 8: I1Ii111 - iII111i / ooOoO0o
 if 96 - 96: OoOoOO00
 OOoOO0o0o0 = "ps auww" if lisp . lisp_is_macos ( ) else "ps aux"
 IIiiI = commands . getoutput ( "{} | egrep 'PID|python lisp|python -O lisp' | egrep -v grep" . format ( OOoOO0o0o0 ) )
 if 31 - 31: I1ii11iIi11i + Ii1I + I1Ii111 / Ii1I
 if 25 - 25: OoO0O00
 IIiiI = IIiiI . replace ( " " , lisp . space ( 1 ) )
 IIiiI = IIiiI . replace ( "\n" , "<br>" )
 if 24 - 24: IiII * i11iIiiIii * OOooOOo
 if 85 - 85: o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . O0 % I1Ii111
 if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
 if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
 if ( o0o0oOoOO0O . find ( "Darwin" ) != - 1 ) :
  O0ooooo0OOOO0 = O0ooooo0OOOO0 / 2
  iIiIIIIIii = commands . getoutput ( "top -l 1 | head -50" )
  iIiIIIIIii = iIiIIIIIii . split ( "PID" )
  iIiIIIIIii = iIiIIIIIii [ 0 ]
  if 74 - 74: O0 / i1IIi
  if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
  if 31 - 31: OoooooooOO . OOooOOo
  if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
  if 100 - 100: OoO0O00
  I1i111iiIIIi = iIiIIIIIii . find ( "Load Avg" )
  II1i = iIiIIIIIii [ 0 : I1i111iiIIIi ] . find ( "threads" )
  Ii1IIIIi1ii1I = iIiIIIIIii [ 0 : II1i + 7 ]
  iIiIIIIIii = Ii1IIIIi1ii1I + "<br>" + iIiIIIIIii [ I1i111iiIIIi : : ]
  I1i111iiIIIi = iIiIIIIIii . find ( "CPU usage" )
  iIiIIIIIii = iIiIIIIIii [ 0 : I1i111iiIIIi ] + "<br>" + iIiIIIIIii [ I1i111iiIIIi : : ]
  I1i111iiIIIi = iIiIIIIIii . find ( "SharedLibs:" )
  iIiIIIIIii = iIiIIIIIii [ 0 : I1i111iiIIIi ] + "<br>" + iIiIIIIIii [ I1i111iiIIIi : : ]
  I1i111iiIIIi = iIiIIIIIii . find ( "MemRegions" )
  iIiIIIIIii = iIiIIIIIii [ 0 : I1i111iiIIIi ] + "<br>" + iIiIIIIIii [ I1i111iiIIIi : : ]
  I1i111iiIIIi = iIiIIIIIii . find ( "PhysMem" )
  iIiIIIIIii = iIiIIIIIii [ 0 : I1i111iiIIIi ] + "<br>" + iIiIIIIIii [ I1i111iiIIIi : : ]
  I1i111iiIIIi = iIiIIIIIii . find ( "VM:" )
  iIiIIIIIii = iIiIIIIIii [ 0 : I1i111iiIIIi ] + "<br>" + iIiIIIIIii [ I1i111iiIIIi : : ]
  I1i111iiIIIi = iIiIIIIIii . find ( "Networks" )
  iIiIIIIIii = iIiIIIIIii [ 0 : I1i111iiIIIi ] + "<br>" + iIiIIIIIii [ I1i111iiIIIi : : ]
  I1i111iiIIIi = iIiIIIIIii . find ( "Disks" )
  iIiIIIIIii = iIiIIIIIii [ 0 : I1i111iiIIIi ] + "<br>" + iIiIIIIIii [ I1i111iiIIIi : : ]
 else :
  if 13 - 13: I1IiiI % OoOoOO00 . I1ii11iIi11i / Oo0Ooo % OOooOOo . OoooooooOO
  if 22 - 22: IiII / i11iIiiIii
  if 62 - 62: OoO0O00 / I1ii11iIi11i
  if 7 - 7: OoooooooOO . IiII
  I111iI = commands . getoutput ( "top -b -n 1 | head -50" )
  I111iI = I111iI . split ( "PID" )
  I111iI [ 1 ] = I111iI [ 1 ] . replace ( " " , lisp . space ( 1 ) )
  I111iI = I111iI [ 0 ] + I111iI [ 1 ]
  iIiIIIIIii = I111iI . replace ( "\n" , "<br>" )
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
  if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
 O00oOo00o0o = commands . getoutput ( "cat release-notes.txt" )
 O00oOo00o0o = O00oOo00o0o . replace ( "\n" , "<br>" )
 if 85 - 85: iII111i + OoooooooOO * iII111i - I1Ii111 % i11iIiiIii
 i1I1ii += '''
        <br><table align="center" border="1" cellspacing="3x" cellpadding="5x">
        <tr>
        <td width="20%"><i>LISP Subsystem Version:<br>
        LISP Release {} Build Date:</i></td>
        <td width="80%"><font face="Courier New">{}<br>
        {}</font></td>
        </tr>

        <tr>
        <td width="20%"><i>LISP Subsystem Uptime:<br>System Uptime:</i></td>
        <td width="80%"><font face="Courier New">{}<br>
        {}</font></td>
        </tr>

        <tr>
        <td width="20%"><i>System Architecture:<br>
        Number of CPUs:<font face="Courier New">{}{}</font></td>
        <td width="80%"><font face="Courier New">{}</font></td>
        </tr>

        <tr>
        <td width="20%" valign="top"><i>LISP Process Status:</i></td>
        <td width="80%">
            <div style="height: 100px; overflow: auto">
            <font size="2" face="Courier New">{}</font></div></td>
        </tr>

        <tr>
        <td width="20%" valign="top"><i>System Resource Utilization:</i></td>
        <td width="80%">
            <div style="height: 200px; overflow: auto">
            <font face="Courier New">{}</font></td>
        </tr>

        <tr>
        <td width="20%" valign="top"><i>Release Notes:</i></td>
        <td width="80%">
            <div style="height: 300px; overflow: auto">
            <font size="2" face="Courier New">{}</font></div></td>
        </tr>

        </table>
        ''' . format ( i1ii1II1ii , lisp . lisp_version , Oo0o , O00 ,
 OooO0oo , lisp . lisp_space ( 1 ) , O0ooooo0OOOO0 , o0o0oOoOO0O , IIiiI , iIiIIIIIii ,
 O00oOo00o0o )
 if 71 - 71: I1ii11iIi11i - ooOoO0o / OoOoOO00 * OoOoOO00 / i1IIi . i1IIi
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 53 - 53: I1Ii111
 if 21 - 21: I11i
 if 92 - 92: i11iIiiIii / I1Ii111 - iII111i % ooOoO0o * I1Ii111 + Oo0Ooo
 if 11 - 11: OoooooooOO . I1Ii111
 if 80 - 80: OoooooooOO - OOooOOo * Ii1I * I1ii11iIi11i / I1IiiI / OOooOOo
 if 13 - 13: I1Ii111 * ooOoO0o + i11iIiiIii * I1Ii111 - ooOoO0o
 if 23 - 23: iIii1I11I1II1 * i1IIi % OoooooooOO * IiII
@ bottle . route ( '/lisp/show/conf' )
def I1Iiiiiii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 return ( bottle . static_file ( "lisp.config" , root = "./" , mimetype = "text/plain" ) )
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 if 73 - 73: i1IIi / i11iIiiIii
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
@ bottle . route ( '/lisp/show/diff' )
def oOOoOo ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 89 - 89: II111iiii + i1IIi + II111iiii
 return ( bottle . static_file ( "lisp.config.diff" , root = "./" ,
 mimetype = "text/plain" ) )
 if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
 if 42 - 42: OoOoOO00 * OoOoOO00 * I1Ii111 . I11i
 if 51 - 51: OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o * iIii1I11I1II1 % OoO0O00
 if 99 - 99: oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
@ bottle . route ( '/lisp/archive/conf' )
def OoO ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 35 - 35: OoOoOO00 + i11iIiiIii - II111iiii
  if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 lisp . lisp_ipc_lock . acquire ( )
 os . system ( "cp ./lisp.config ./lisp.config.archive" )
 lisp . lisp_ipc_lock . release ( )
 if 90 - 90: iII111i
 i1I1ii = "Configuration file saved to "
 i1I1ii = lisp . lisp_print_sans ( i1I1ii )
 i1I1ii += lisp . lisp_print_cour ( "./lisp.config.archive" )
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
 if 13 - 13: Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
@ bottle . route ( '/lisp/clear/conf' )
def I1iIiI11I1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 27 - 27: Ii1I . i11iIiiIii % I1Ii111
  if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 os . system ( "cp ./lisp.config ./lisp.config.before-clear" )
 lisp . lisp_ipc_lock . acquire ( )
 iI11I ( )
 lisp . lisp_ipc_lock . release ( )
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 i1I1ii = "Configuration cleared, a backup copy is stored in "
 i1I1ii = lisp . lisp_print_sans ( i1I1ii )
 i1I1ii += lisp . lisp_print_cour ( "./lisp.config.before-clear" )
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
 if 95 - 95: IiII
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
@ bottle . route ( '/lisp/clear/conf/verify' )
def OOoOoo0 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 17 - 17: Ii1I + oO0o . OoO0O00 - Oo0Ooo * i11iIiiIii
  if 20 - 20: I1IiiI . OoooooooOO % OOooOOo
 i1I1ii = "<br>Are you sure you want to clear the configuration?"
 i1I1ii = lisp . lisp_print_sans ( i1I1ii )
 if 63 - 63: I1IiiI % iIii1I11I1II1
 I1ii = lisp . lisp_button ( "yes" , "/lisp/clear/conf" )
 O00O0O = lisp . lisp_button ( "cancel" , "/lisp" )
 i1I1ii += I1ii + O00O0O + "<br>"
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 19 - 19: OoO0O00 * I11i / I11i . OoooooooOO - OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if 10 - 10: II111iiii . iII111i
def I1iOOOO ( ) :
 oOoO0o00OO0 = ""
 if 88 - 88: iII111i
 for iiI11I1i1i1iI in [ "443" , "-8080" , "8080" ] :
  OoOOo000o0 = 'ps auxww | egrep "lisp-core.pyo {}" | egrep -v grep' . format ( iiI11I1i1i1iI )
  i1I1ii = commands . getoutput ( OoOOo000o0 )
  if ( i1I1ii == "" ) : continue
  if 12 - 12: II111iiii . I11i / OOooOOo
  i1I1ii = i1I1ii . split ( "\n" ) [ 0 ]
  i1I1ii = i1I1ii . split ( " " )
  if ( i1I1ii [ - 2 ] == "lisp-core.pyo" and i1I1ii [ - 1 ] == iiI11I1i1i1iI ) : oOoO0o00OO0 = iiI11I1i1i1iI
  break
  if 77 - 77: ooOoO0o - I1IiiI % I11i - O0
 return ( oOoO0o00OO0 )
 if 67 - 67: OOooOOo + Oo0Ooo
 if 84 - 84: O0 * OoooooooOO - IiII * IiII
 if 8 - 8: ooOoO0o / i1IIi . oO0o
 if 41 - 41: iII111i + OoO0O00
 if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
 if 56 - 56: O0
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
@ bottle . route ( '/lisp/restart' )
def iIII1i1i ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 35 - 35: II111iiii * I11i - OoooooooOO . I11i . I11i
  if 11 - 11: I1Ii111 / OoOoOO00 + I11i % iIii1I11I1II1
  if 42 - 42: I1ii11iIi11i * OoOoOO00 % ooOoO0o - OoOoOO00 . i11iIiiIii - I1Ii111
  if 84 - 84: I1Ii111 - I1ii11iIi11i / I11i
  if 13 - 13: IiII - Oo0Ooo - ooOoO0o
  if 92 - 92: ooOoO0o / OoOoOO00 * OoO0O00 . I11i % II111iiii
 OooOO = commands . getoutput ( "egrep requiretty /etc/sudoers" ) . split ( " " )
 if ( OooOO [ - 1 ] == "requiretty" and OooOO [ 0 ] == "Defaults" ) :
  i1I1ii = "Need to remove 'requiretty' from /etc/sudoers"
  i1I1ii = lisp . lisp_print_sans ( i1I1ii )
  return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
  if 71 - 71: I1Ii111 % i1IIi - II111iiii - OOooOOo + OOooOOo * ooOoO0o
  if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
 lisp . lprint ( lisp . bold ( "LISP subsystem restart request received" , False ) )
 if 29 - 29: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / iII111i
 if 70 - 70: i11iIiiIii % iII111i
 if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
 if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
 if 76 - 76: Ii1I - II111iiii * OOooOOo / OoooooooOO
 oOoO0o00OO0 = I1iOOOO ( )
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 OoOOo000o0 = "sleep 1; sudo ./RESTART-LISP {}" . format ( oOoO0o00OO0 )
 thread . start_new_thread ( os . system , ( OoOOo000o0 , ) )
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 i1I1ii = lisp . lisp_print_sans ( "Restarting LISP subsystem ..." )
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
 if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
 if 34 - 34: O0
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
@ bottle . route ( '/lisp/restart/verify' )
def OO0O0o0o0 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 31 - 31: Ii1I
  if 44 - 44: OoOoOO00 - iIii1I11I1II1 - Oo0Ooo
 i1I1ii = "<br>Are you sure you want to restart the LISP subsystem?"
 i1I1ii = lisp . lisp_print_sans ( i1I1ii )
 if 80 - 80: iIii1I11I1II1 * I1Ii111 % I11i % Oo0Ooo
 I1ii = lisp . lisp_button ( "yes" , "/lisp/restart" )
 O00O0O = lisp . lisp_button ( "cancel" , "/lisp" )
 i1I1ii += I1ii + O00O0O + "<br>"
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 95 - 95: iIii1I11I1II1 - I1ii11iIi11i . I1Ii111 - I1IiiI
 if 75 - 75: OoO0O00 + o0oOOo0O0Ooo - i1IIi . OoooooooOO * Ii1I / IiII
 if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if 37 - 37: i11iIiiIii + i1IIi
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
@ bottle . route ( '/lisp/install' , method = "post" )
def iiIII1II ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 100 - 100: Oo0Ooo % Ii1I / I11i
  if 30 - 30: Oo0Ooo - OOooOOo - iII111i
 OOO = bottle . request . forms . get ( "image_url" )
 if ( OOO . find ( "lispers.net" ) == - 1 or OOO . find ( ".tgz" ) == - 1 ) :
  I11IIiIiI = "Invalid install request for file {}" . format ( OOO )
  lisp . lprint ( lisp . bold ( I11IIiIiI , False ) )
  i1I1ii = lisp . lisp_print_sans ( "Invalid lispers.net tarball file name" )
  return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
  if 5 - 5: Oo0Ooo * OoOoOO00
  if 46 - 46: ooOoO0o
 if ( lisp . lisp_is_ubuntu ( ) ) :
  OoOOo000o0 = "python lisp-get-bits.pyo {} force 2>&1 > /dev/null" . format ( OOO )
 else :
  OoOOo000o0 = "python lisp-get-bits.pyo {} force >& /dev/null" . format ( OOO )
  if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 IIiiI = os . system ( OoOOo000o0 )
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 OoooO0o = OOO . split ( "/" ) [ - 1 ]
 if 24 - 24: OoOoOO00 % i1IIi + iII111i . i11iIiiIii . I1ii11iIi11i
 if ( os . path . exists ( OoooO0o ) ) :
  IIi1II = OOO . split ( "release-" ) [ 1 ]
  IIi1II = IIi1II . split ( ".tgz" ) [ 0 ]
  if 2 - 2: II111iiii - OoO0O00 . IiII * iII111i / oO0o
  i1I1ii = "Install completed for release {}" . format ( IIi1II )
  i1I1ii = lisp . lisp_print_sans ( i1I1ii )
  if 80 - 80: OOooOOo / I11i / OoOoOO00 + i1IIi - Oo0Ooo
  i1I1ii += "<br><br>" + lisp . lisp_button ( "restart LISP subsystem" ,
 "/lisp/restart/verify" ) + "<br>"
 else :
  I11IIiIiI = lisp . lisp_print_cour ( OOO )
  i1I1ii = "Install failed for file {}" . format ( I11IIiIiI )
  i1I1ii = lisp . lisp_print_sans ( i1I1ii )
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00
  if 15 - 15: OoOoOO00
 I11IIiIiI = "Install request for file {} {}" . format ( OOO ,
 "succeeded" if ( IIiiI == 0 ) else "failed" )
 lisp . lprint ( lisp . bold ( I11IIiIiI , False ) )
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 62 - 62: Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
@ bottle . route ( '/lisp/install/image' )
def ooOo0O ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 37 - 37: Ii1I % OoO0O00
  if 79 - 79: I1ii11iIi11i + I1IiiI / I1IiiI
 I11IIiIiI = lisp . lisp_print_sans ( "<br>Enter lispers.net tarball URL:" )
 i1I1ii = '''
        <form action="/lisp/install" method="post" style="display: inline;">
        {}
        <input type="text" name="image_url" size="75" required/>
        <input type="submit" style="background-color:transparent;border-radius:10px;" value="Submit" />
        </form><br>''' . format ( I11IIiIiI )
 if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
 if 23 - 23: i11iIiiIii
 if 39 - 39: o0oOOo0O0Ooo - I1ii11iIi11i % iII111i * OoO0O00 - OOooOOo / iII111i
 if 29 - 29: I1ii11iIi11i
 if 52 - 52: i11iIiiIii / i1IIi
 if 1 - 1: ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
@ bottle . route ( '/lisp/log/flows' )
def oo0OoOooo ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 95 - 95: IiII * I1ii11iIi11i % ooOoO0o % Ii1I - Ii1I
  if 97 - 97: I1ii11iIi11i + iIii1I11I1II1 . O0
 os . system ( "touch ./log-flows" )
 if 64 - 64: i1IIi % ooOoO0o / i11iIiiIii - i1IIi % OOooOOo . iII111i
 i1I1ii = lisp . lisp_print_sans ( "Flow data appended to file " )
 II1i111 = "<a href='/lisp/show/log/lisp-flow/100'>logs/lisp-flows.log</a>"
 i1I1ii += lisp . lisp_print_cour ( II1i111 )
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
@ bottle . route ( '/lisp/search/log/<name>/<num>/<keyword>' )
def iIIi ( name = "" , num = "" , keyword = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 96 - 96: iII111i
  if 18 - 18: iII111i * I11i - Ii1I
 OOoOO0o0o0 = "tail -n {} logs/{}.log | egrep -B10 -A10 {}" . format ( num , name ,
 keyword )
 i1I1ii = commands . getoutput ( OOoOO0o0o0 )
 if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
 if ( i1I1ii ) :
  iI1iii = i1I1ii . count ( keyword )
  i1I1ii = lisp . convert_font ( i1I1ii )
  i1I1ii = i1I1ii . replace ( "--\n--\n" , "--\n" )
  i1I1ii = i1I1ii . replace ( "\n" , "<br>" )
  i1I1ii = i1I1ii . replace ( "--<br>" , "<hr>" )
  i1I1ii = "Found <b>{}</b> occurences<hr>" . format ( iI1iii ) + i1I1ii
 else :
  i1I1ii = "Keyword {} not found" . format ( keyword )
  if 87 - 87: I1ii11iIi11i / OoooooooOO - Oo0Ooo % OoOoOO00 % IiII % Oo0Ooo
  if 29 - 29: OoooooooOO . I1IiiI % I1ii11iIi11i - iII111i
  if 8 - 8: i1IIi
  if 32 - 32: oO0o / II111iiii
  if 45 - 45: I1ii11iIi11i + OoO0O00 * i11iIiiIii / OOooOOo % I11i * O0
 i1o0oooO = "<font color='blue'><b>{}</b>" . format ( keyword )
 i1I1ii = i1I1ii . replace ( keyword , i1o0oooO )
 i1I1ii = i1I1ii . replace ( keyword , keyword + "</font>" )
 if 89 - 89: II111iiii / oO0o
 i1I1ii = lisp . lisp_print_cour ( i1I1ii )
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
@ bottle . post ( '/lisp/search/log/<name>/<num>' )
def oo0oOO ( name = "" , num = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
  if 48 - 48: iII111i * iII111i
 I1I1 = bottle . request . forms . get ( "keyword" )
 return ( iIIi ( name , num , I1I1 ) )
 if 4 - 4: o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
@ bottle . route ( '/lisp/show/log/<name>/<num>' )
def Oo0 ( name = "" , num = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 79 - 79: OoO0O00 % OOooOOo / iIii1I11I1II1 + OoOoOO00 * OoO0O00
  if 30 - 30: OoooooooOO / I11i + iII111i / I1ii11iIi11i * O0
  if 16 - 16: Oo0Ooo / i11iIiiIii
  if 64 - 64: i11iIiiIii / Ii1I * i1IIi
  if 73 - 73: Oo0Ooo - OoOoOO00 - oO0o - I1IiiI
 if ( num == "" ) : num = 100
 if 65 - 65: o0oOOo0O0Ooo
 I1ii1II1iII = '''
        <form action="/lisp/search/log/{}/{}" method="post">
        <i>Keyword search:</i>
        <input type="text" name="keyword" />
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </form><hr>
    ''' . format ( name , num )
 if 8 - 8: OoOoOO00 / O0 * O0 % I1Ii111 - Oo0Ooo + I11i
 if ( os . path . exists ( "logs/{}.log" . format ( name ) ) ) :
  i1I1ii = commands . getoutput ( "tail -n {} logs/{}.log" . format ( num , name ) )
  i1I1ii = lisp . convert_font ( i1I1ii )
  i1I1ii = i1I1ii . replace ( "\n" , "<br>" )
  i1I1ii = I1ii1II1iII + lisp . lisp_print_cour ( i1I1ii )
 else :
  oo = lisp . lisp_print_sans ( "File" )
  Ii1IiIiIi1IiI = lisp . lisp_print_cour ( "logs/{}.log" . format ( name ) )
  i1iiIIi1I = lisp . lisp_print_sans ( "does not exist" )
  i1I1ii = "{} {} {}" . format ( oo , Ii1IiIiIi1IiI , i1iiIIi1I )
  if 36 - 36: I1IiiI * Oo0Ooo
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 77 - 77: oO0o % i1IIi - Ii1I
 if 93 - 93: OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
@ bottle . route ( '/lisp/debug/<name>' )
def ooOoO ( name = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 23 - 23: I11i
  if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
  if 14 - 14: I1ii11iIi11i
  if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
  if 56 - 56: OoooooooOO - I11i - i1IIi
 if ( name == "disable%all" ) :
  IIIi1i1I = lispconfig . lisp_get_clause_for_api ( "lisp debug" )
  if ( IIIi1i1I [ 0 ] . has_key ( "lisp debug" ) ) :
   OoO0OOOOo0O = [ ]
   for I1i1I in IIIi1i1I [ 0 ] [ "lisp debug" ] :
    iii1I1Iii = I1i1I . keys ( ) [ 0 ]
    OoO0OOOOo0O . append ( { iii1I1Iii : "no" } )
    if 82 - 82: Ii1I + IiII
   OoO0OOOOo0O = { "lisp debug" : OoO0OOOOo0O }
   lispconfig . lisp_put_clause_for_api ( OoO0OOOOo0O )
   if 12 - 12: I1Ii111
   if 93 - 93: i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / o0oOOo0O0Ooo / II111iiii
  IIIi1i1I = lispconfig . lisp_get_clause_for_api ( "lisp xtr-parameters" )
  if ( IIIi1i1I [ 0 ] . has_key ( "lisp xtr-parameters" ) ) :
   OoO0OOOOo0O = [ ]
   for I1i1I in IIIi1i1I [ 0 ] [ "lisp xtr-parameters" ] :
    iii1I1Iii = I1i1I . keys ( ) [ 0 ]
    if ( iii1I1Iii in [ "data-plane-logging" , "flow-logging" ] ) :
     OoO0OOOOo0O . append ( { iii1I1Iii : "no" } )
    else :
     OoO0OOOOo0O . append ( { iii1I1Iii : I1i1I [ iii1I1Iii ] } )
     if 49 - 49: OOooOOo . I1ii11iIi11i . i11iIiiIii - II111iiii / Ii1I
     if 62 - 62: OOooOOo
   OoO0OOOOo0O = { "lisp xtr-parameters" : OoO0OOOOo0O }
   lispconfig . lisp_put_clause_for_api ( OoO0OOOOo0O )
   if 1 - 1: IiII / IiII - i11iIiiIii
   if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
  return ( lispconfig . lisp_landing_page ( ) )
  if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
  if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
  if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
  if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
  if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
 name = name . split ( "%" )
 Ii11iI1ii1111 = name [ 0 ]
 Iii111II = name [ 1 ]
 if 42 - 42: I1Ii111 + I1Ii111 * II111iiii
 o0Oo = [ "data-plane-logging" , "flow-logging" ]
 if 57 - 57: OOooOOo / Oo0Ooo
 oO0O0Ooo = "lisp xtr-parameters" if ( Ii11iI1ii1111 in o0Oo ) else "lisp debug"
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 IIIi1i1I = lispconfig . lisp_get_clause_for_api ( oO0O0Ooo )
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if ( IIIi1i1I [ 0 ] . has_key ( oO0O0Ooo ) ) :
  OoO0OOOOo0O = { }
  for I1i1I in IIIi1i1I [ 0 ] [ oO0O0Ooo ] :
   OoO0OOOOo0O [ I1i1I . keys ( ) [ 0 ] ] = I1i1I . values ( ) [ 0 ]
   if ( OoO0OOOOo0O . has_key ( Ii11iI1ii1111 ) ) : OoO0OOOOo0O [ Ii11iI1ii1111 ] = Iii111II
   if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
  OoO0OOOOo0O = { oO0O0Ooo : OoO0OOOOo0O }
  lispconfig . lisp_put_clause_for_api ( OoO0OOOOo0O )
  if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
 return ( lispconfig . lisp_landing_page ( ) )
 if 62 - 62: o0oOOo0O0Ooo
 if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
 if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
@ bottle . route ( '/lisp/clear/<name>' )
@ bottle . route ( '/lisp/clear/etr/<etr_name>/<stats_name>' )
@ bottle . route ( '/lisp/clear/rtr/<rtr_name>/<stats_name>' )
@ bottle . route ( '/lisp/clear/itr/<itr_name>' )
@ bottle . route ( '/lisp/clear/rtr/<rtr_name>' )
def ooooOoO0O ( name = "" , itr_name = '' , rtr_name = "" , etr_name = "" ,
 stats_name = "" ) :
 if 1 - 1: I1ii11iIi11i / OoO0O00 + oO0o . o0oOOo0O0Ooo / I1ii11iIi11i - iII111i
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 5 - 5: OOooOOo
  if 4 - 4: iII111i % I1Ii111 / OoO0O00 . OOooOOo / OOooOOo - I1ii11iIi11i
  if 79 - 79: I1ii11iIi11i + I1Ii111
  if 10 - 10: Oo0Ooo + O0
  if 43 - 43: iIii1I11I1II1 / II111iiii % o0oOOo0O0Ooo - OOooOOo
 if ( lispconfig . lisp_is_user_superuser ( None ) == False ) :
  i1I1ii = lisp . lisp_print_sans ( "Not authorized" )
  return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
  if 62 - 62: I11i
  if 63 - 63: OOooOOo + ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 Oo0O00Oo0o0 = "clear"
 if ( name == "referral" ) :
  OOoO00ooO = "lisp-mr"
  I1IIIIiii1i = "Referral"
 elif ( itr_name == "map-cache" ) :
  OOoO00ooO = "lisp-itr"
  I1IIIIiii1i = "ITR <a href='/lisp/show/itr/map-cache'>map-cache</a>"
 elif ( rtr_name == "map-cache" ) :
  OOoO00ooO = "lisp-rtr"
  I1IIIIiii1i = "RTR <a href='/lisp/show/rtr/map-cache'>map-cache</a>"
 elif ( etr_name == "stats" ) :
  OOoO00ooO = "lisp-etr"
  I1IIIIiii1i = ( "ETR '{}' decapsulation <a href='/lisp/show/" + "database'>stats</a>" ) . format ( stats_name )
  if 51 - 51: OOooOOo . I1IiiI
  Oo0O00Oo0o0 += "%" + stats_name
 elif ( rtr_name == "stats" ) :
  OOoO00ooO = "lisp-rtr"
  I1IIIIiii1i = ( "RTR '{}' decapsulation <a href='/lisp/show/" + "rtr/map-cache'>stats</a>" ) . format ( stats_name )
  if 73 - 73: OoooooooOO . I1IiiI / I1Ii111 % Ii1I
  Oo0O00Oo0o0 += "%" + stats_name
 else :
  i1I1ii = lisp . lisp_print_sans ( "Invalid command" )
  return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
  if 65 - 65: IiII - I1IiiI - Ii1I
  if 42 - 42: II111iiii * I1IiiI % i1IIi - Ii1I % IiII
  if 36 - 36: i11iIiiIii / oO0o * I1ii11iIi11i * I1ii11iIi11i + Ii1I * I11i
  if 32 - 32: OoO0O00
  if 50 - 50: ooOoO0o + i1IIi
 Oo0O00Oo0o0 = lisp . lisp_command_ipc ( Oo0O00Oo0o0 , "lisp-core" )
 lisp . lisp_ipc ( Oo0O00Oo0o0 , Oo , OOoO00ooO )
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 oo0ooooO = commands . getoutput ( "egrep 'lisp map-cache' ./lisp.config" )
 if ( oo0ooooO != "" ) :
  os . system ( "touch ./lisp.config" )
  if 12 - 12: II111iiii
  if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 i1I1ii = lisp . lisp_print_sans ( "{} cleared" . format ( I1IIIIiii1i ) )
 return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
@ bottle . route ( '/lisp/show/map-server' )
def iIii11iI1II ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 42 - 42: ooOoO0o - I1IiiI + I1ii11iIi11i % Ii1I
  if 44 - 44: i1IIi - O0 - I1ii11iIi11i * I1ii11iIi11i + OoOoOO00
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show map-server" ) )
 if 56 - 56: ooOoO0o / iIii1I11I1II1 . Ii1I % OoOoOO00 + OOooOOo
 if 10 - 10: I1Ii111 * i11iIiiIii - iIii1I11I1II1 . Oo0Ooo - I1ii11iIi11i
 if 20 - 20: I1ii11iIi11i / I1IiiI * OoO0O00 * I1IiiI * O0
 if 1 - 1: iIii1I11I1II1 + Oo0Ooo / O0 - iII111i % IiII + IiII
 if 24 - 24: I1IiiI + Oo0Ooo + OOooOOo - OoooooooOO + Oo0Ooo
 if 93 - 93: ooOoO0o . iIii1I11I1II1 % i11iIiiIii . OoOoOO00 % ooOoO0o + O0
 if 65 - 65: Ii1I + OoO0O00 - OoooooooOO
@ bottle . route ( '/lisp/show/database' )
def OOoOO0o ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 51 - 51: Oo0Ooo - I1ii11iIi11i * I11i
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show database-mapping" ) )
 if 12 - 12: iIii1I11I1II1 % ooOoO0o % ooOoO0o
 if 78 - 78: IiII . OoOoOO00 . I11i
 if 97 - 97: oO0o
 if 80 - 80: I1IiiI . Ii1I
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
 if 29 - 29: o0oOOo0O0Ooo
@ bottle . route ( '/lisp/show/itr/map-cache' )
def oo0iIiI ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 81 - 81: OoOoOO00 % Ii1I
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show itr-map-cache" ) )
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
@ bottle . route ( '/lisp/show/itr/rloc-probing' )
def ii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 94 - 94: ooOoO0o * I11i - IiII . iIii1I11I1II1
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show itr-rloc-probing" ) )
 if 66 - 66: ooOoO0o - OOooOOo * OoOoOO00 / oO0o * II111iiii * OoO0O00
 if 91 - 91: OoooooooOO / Ii1I . I1IiiI + ooOoO0o . II111iiii
 if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
 if 77 - 77: I1Ii111 - I11i
 if 11 - 11: I1ii11iIi11i
 if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
 if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
@ bottle . post ( '/lisp/show/itr/map-cache/lookup' )
def o0OO0O0OO0oO0 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
  if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 oO = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oO ) == False ) :
  i1I1ii = "Address '{}' has invalid format" . format ( oO )
  i1I1ii = lisp . lisp_print_sans ( i1I1ii )
  return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
  if 31 - 31: OoO0O00 * i11iIiiIii * Ii1I . i11iIiiIii
  if 12 - 12: OoOoOO00 % IiII % I1ii11iIi11i . i11iIiiIii * iIii1I11I1II1
 OOoOO0o0o0 = "show itr-map-cache" + "%" + oO
 return ( lispconfig . lisp_process_show_command ( Oo ,
 OOoOO0o0o0 ) )
 if 66 - 66: i11iIiiIii * iIii1I11I1II1 % OoooooooOO
 if 5 - 5: OoOoOO00 % OoooooooOO
 if 60 - 60: OoOoOO00 . i1IIi % OoO0O00 % ooOoO0o % OOooOOo
 if 33 - 33: iIii1I11I1II1 - Ii1I * I1ii11iIi11i % iIii1I11I1II1 + OoO0O00 . OOooOOo
 if 56 - 56: i11iIiiIii * iII111i . oO0o
 if 78 - 78: OoOoOO00
 if 1 - 1: OOooOOo . IiII
@ bottle . route ( '/lisp/show/rtr/map-cache' )
@ bottle . route ( '/lisp/show/rtr/map-cache/<dns>' )
def I1iIII1IiiI ( dns = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
  if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
 if ( dns == "dns" ) :
  return ( lispconfig . lisp_process_show_command ( Oo ,
 "show rtr-map-cache-dns" ) )
 else :
  return ( lispconfig . lisp_process_show_command ( Oo ,
 "show rtr-map-cache" ) )
  if 48 - 48: i11iIiiIii % oO0o
  if 29 - 29: iII111i + i11iIiiIii % I11i
  if 93 - 93: OoOoOO00 % iIii1I11I1II1
  if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
  if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
  if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
  if 21 - 21: OOooOOo
  if 6 - 6: IiII
@ bottle . route ( '/lisp/show/rtr/rloc-probing' )
def i1I1II ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 17 - 17: O0 * OoOoOO00 * I1ii11iIi11i * II111iiii * I11i % i1IIi
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show rtr-rloc-probing" ) )
 if 33 - 33: I1ii11iIi11i * I1ii11iIi11i . ooOoO0o . i11iIiiIii
 if 48 - 48: o0oOOo0O0Ooo . Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 if 24 - 24: OoOoOO00
@ bottle . post ( '/lisp/show/rtr/map-cache/lookup' )
def Oo0oOo0ooOOOo ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 71 - 71: II111iiii - Ii1I - iII111i * O0 * IiII
  if 46 - 46: IiII
 oO = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oO ) == False ) :
  i1I1ii = "Address '{}' has invalid format" . format ( oO )
  i1I1ii = lisp . lisp_print_sans ( i1I1ii )
  return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
  if 29 - 29: II111iiii . OoOoOO00 % o0oOOo0O0Ooo * II111iiii - o0oOOo0O0Ooo * iIii1I11I1II1
  if 35 - 35: II111iiii - IiII . i1IIi
 OOoOO0o0o0 = "show rtr-map-cache" + "%" + oO
 return ( lispconfig . lisp_process_show_command ( Oo ,
 OOoOO0o0o0 ) )
 if 95 - 95: I1IiiI + I1IiiI - OOooOOo - iII111i
 if 45 - 45: Ii1I . OoooooooOO
 if 27 - 27: Ii1I * Oo0Ooo . OoOoOO00
 if 17 - 17: II111iiii % iII111i * OOooOOo % i1IIi . I1IiiI . iIii1I11I1II1
 if 27 - 27: i11iIiiIii - I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if 50 - 50: OoOoOO00
@ bottle . route ( '/lisp/show/referral' )
def i1i1Ii11Ii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 57 - 57: OOooOOo + I1Ii111 % I1ii11iIi11i . OoO0O00 / OoO0O00 * O0
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show referral-cache" ) )
 if 6 - 6: i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 if 68 - 68: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 - I1Ii111
 if 37 - 37: IiII
 if 37 - 37: Oo0Ooo / IiII * O0
 if 73 - 73: iII111i * iII111i / ooOoO0o
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
@ bottle . post ( '/lisp/show/referral/lookup' )
def II11ii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 39 - 39: iII111i . I1IiiI * OoOoOO00 - i11iIiiIii
  if 1 - 1: iII111i * OoOoOO00
 oO = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oO ) == False ) :
  i1I1ii = "Address '{}' has invalid format" . format ( oO )
  i1I1ii = lisp . lisp_print_sans ( i1I1ii )
  return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
  if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
  if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 OOoOO0o0o0 = "show referral-cache" + "%" + oO
 return ( lispconfig . lisp_process_show_command ( Oo , OOoOO0o0o0 ) )
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 if 83 - 83: o0oOOo0O0Ooo
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
@ bottle . route ( '/lisp/show/delegations' )
def i11I1I ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 71 - 71: iII111i
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show delegations" ) )
 if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
 if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
 if 58 - 58: I1ii11iIi11i
 if 2 - 2: II111iiii / I1Ii111
 if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 if 22 - 22: ooOoO0o . iIii1I11I1II1
@ bottle . post ( '/lisp/show/delegations/lookup' )
def i1IiiiiIi1I ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 56 - 56: OoooooooOO * O0
  if 85 - 85: OoooooooOO % OoOoOO00 * iIii1I11I1II1
 oO = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oO ) == False ) :
  i1I1ii = "Address '{}' has invalid format" . format ( oO )
  i1I1ii = lisp . lisp_print_sans ( i1I1ii )
  return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
  if 44 - 44: iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
  if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 OOoOO0o0o0 = "show delegations" + "%" + oO
 return ( lispconfig . lisp_process_show_command ( Oo , OOoOO0o0o0 ) )
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 if 68 - 68: oO0o
 if 10 - 10: Ii1I
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
@ bottle . route ( '/lisp/show/site' )
@ bottle . route ( '/lisp/show/site/<eid_prefix>' )
def I1 ( eid_prefix = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 35 - 35: I1IiiI
  if 36 - 36: i1IIi - I1ii11iIi11i - I1Ii111
 OOoOO0o0o0 = "show site"
 if 7 - 7: i11iIiiIii + I1IiiI
 if ( eid_prefix != "" ) :
  OOoOO0o0o0 = lispconfig . lisp_parse_eid_in_url ( OOoOO0o0o0 , eid_prefix )
  if 47 - 47: I1Ii111 - OOooOOo / ooOoO0o - Oo0Ooo + iII111i - iIii1I11I1II1
 return ( lispconfig . lisp_process_show_command ( Oo , OOoOO0o0o0 ) )
 if 68 - 68: Ii1I - oO0o + Oo0Ooo
 if 44 - 44: Ii1I * o0oOOo0O0Ooo * II111iiii
 if 5 - 5: i1IIi + O0 % O0 * O0 + OoOoOO00 % i1IIi
 if 80 - 80: iII111i / o0oOOo0O0Ooo + OoO0O00 / oO0o
 if 46 - 46: i11iIiiIii / IiII % i1IIi - I11i * OoOoOO00
 if 94 - 94: Ii1I - I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo
 if 15 - 15: OOooOOo
@ bottle . route ( '/lisp/show/itr/dynamic-eid/<eid_prefix>' )
def i1iiI ( eid_prefix = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 83 - 83: oO0o / iIii1I11I1II1 + i1IIi / iII111i
  if 47 - 47: oO0o + OoooooooOO . II111iiii . iII111i
 OOoOO0o0o0 = "show itr-dynamic-eid"
 if 66 - 66: ooOoO0o * OoOoOO00
 if ( eid_prefix != "" ) :
  OOoOO0o0o0 = lispconfig . lisp_parse_eid_in_url ( OOoOO0o0o0 , eid_prefix )
  if 2 - 2: oO0o . I1Ii111 * Oo0Ooo + O0 - I11i * iIii1I11I1II1
 return ( lispconfig . lisp_process_show_command ( Oo , OOoOO0o0o0 ) )
 if 12 - 12: o0oOOo0O0Ooo * I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
 if 81 - 81: Oo0Ooo - I11i
 if 24 - 24: OoooooooOO . OoO0O00 * II111iiii
 if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
 if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
 if 79 - 79: I1IiiI - ooOoO0o
 if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
@ bottle . route ( '/lisp/show/etr/dynamic-eid/<eid_prefix>' )
def o00OOo000O ( eid_prefix = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 42 - 42: IiII % iII111i % o0oOOo0O0Ooo % oO0o + I11i % OoOoOO00
  if 3 - 3: oO0o
 OOoOO0o0o0 = "show etr-dynamic-eid"
 if 64 - 64: OoO0O00 . I1IiiI - OoooooooOO . ooOoO0o - iII111i
 if ( eid_prefix != "" ) :
  OOoOO0o0o0 = lispconfig . lisp_parse_eid_in_url ( OOoOO0o0o0 , eid_prefix )
  if 77 - 77: Ii1I % OoOoOO00 / II111iiii % iII111i % OoooooooOO % OoO0O00
 return ( lispconfig . lisp_process_show_command ( Oo , OOoOO0o0o0 ) )
 if 19 - 19: IiII * I1Ii111 / oO0o * I1Ii111 - OoooooooOO * I11i
 if 17 - 17: II111iiii + Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
@ bottle . post ( '/lisp/show/site/lookup' )
def OO0ooOoOO0OOo ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo / iIii1I11I1II1 . iIii1I11I1II1 . iII111i * I11i
  if 93 - 93: oO0o * Ii1I
 oO = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oO ) == False ) :
  i1I1ii = "Address '{}' has invalid format" . format ( oO )
  i1I1ii = lisp . lisp_print_sans ( i1I1ii )
  return ( lispconfig . lisp_show_wrapper ( i1I1ii ) )
  if 27 - 27: I1IiiI * ooOoO0o
  if 77 - 77: IiII
 OOoOO0o0o0 = "show site" + "%" + oO + "@lookup"
 return ( lispconfig . lisp_process_show_command ( Oo , OOoOO0o0o0 ) )
 if 66 - 66: iIii1I11I1II1 . i11iIiiIii / I11i / ooOoO0o + I1Ii111
 if 5 - 5: OoOoOO00 % iII111i + IiII
 if 13 - 13: IiII
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
@ bottle . post ( '/lisp/lig' )
def O0Oo0O0 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
  if 96 - 96: OoooooooOO + IiII * O0
 oo0OoOO0o0o = bottle . request . forms . get ( "eid" )
 OO0OOO00 = bottle . request . forms . get ( "mr" )
 ooOOo0o = bottle . request . forms . get ( "count" )
 IiI1Iii1 = "no-info" if bottle . request . forms . get ( "no-nat" ) == "yes" else ""
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 if ( OO0OOO00 == "" ) : OO0OOO00 = "localhost"
 if 88 - 88: o0oOOo0O0Ooo
 if 1 - 1: OoooooooOO
 if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if ( oo0OoOO0o0o == "" ) :
  i1I1ii = "Need to supply EID address"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( i1I1ii ) ) )
  if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
  if 3 - 3: OoooooooOO
 O0OoO0o = ""
 if os . path . exists ( "lisp-lig.pyo" ) : O0OoO0o = "-O lisp-lig.pyo"
 if os . path . exists ( "lisp-lig.py" ) : O0OoO0o = "lisp-lig.py"
 if 1 - 1: ooOoO0o % I11i * I1ii11iIi11i - II111iiii
 if 49 - 49: oO0o - iII111i % OoOoOO00
 if 72 - 72: I1IiiI + IiII . OoOoOO00 + OoOoOO00
 if 94 - 94: i11iIiiIii % OoooooooOO / I1IiiI
 if ( O0OoO0o == "" ) :
  i1I1ii = "Cannot find lisp-lig.py or lisp-lig.pyo"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( i1I1ii ) ) )
  if 24 - 24: I1IiiI * oO0o
  if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if ( ooOOo0o != "" ) : ooOOo0o = "count {}" . format ( ooOOo0o )
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 OOoOO0o0o0 = 'python {} "{}" to {} {} {}' . format ( O0OoO0o , oo0OoOO0o0o , OO0OOO00 , ooOOo0o , IiI1Iii1 )
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 i1I1ii = commands . getoutput ( OOoOO0o0o0 )
 i1I1ii = i1I1ii . replace ( "\n" , "<br>" )
 i1I1ii = lisp . convert_font ( i1I1ii )
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 iI111II1ii = lisp . space ( 2 ) + "RLOC:"
 i1I1ii = i1I1ii . replace ( "RLOC:" , iI111II1ii )
 O0ooO00ooOO0o = lisp . space ( 2 ) + "Empty,"
 i1I1ii = i1I1ii . replace ( "Empty," , O0ooO00ooOO0o )
 I1i = lisp . space ( 4 ) + "geo:"
 i1I1ii = i1I1ii . replace ( "geo:" , I1i )
 o0O = lisp . space ( 4 ) + "elp:"
 i1I1ii = i1I1ii . replace ( "elp:" , o0O )
 I1II = lisp . space ( 4 ) + "rle:"
 i1I1ii = i1I1ii . replace ( "rle:" , I1II )
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( i1I1ii ) ) )
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
@ bottle . post ( '/lisp/rig' )
def I1ii1Ii1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 73 - 73: O0 . oO0o + i11iIiiIii + iIii1I11I1II1 - I11i / OoOoOO00
  if 99 - 99: I1ii11iIi11i * oO0o * I1ii11iIi11i - II111iiii + Ii1I
 oo0OoOO0o0o = bottle . request . forms . get ( "eid" )
 OOooO0Oo00 = bottle . request . forms . get ( "ddt" )
 iIIIIIIIiIII = "follow-all-referrals" if bottle . request . forms . get ( "follow" ) == "yes" else ""
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if ( OOooO0Oo00 == "" ) : OOooO0Oo00 = "localhost"
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 if ( oo0OoOO0o0o == "" ) :
  i1I1ii = "Need to supply EID address"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( i1I1ii ) ) )
  if 24 - 24: ooOoO0o - I11i * oO0o
  if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 II1io0 = ""
 if os . path . exists ( "lisp-rig.pyo" ) : II1io0 = "-O lisp-rig.pyo"
 if os . path . exists ( "lisp-rig.py" ) : II1io0 = "lisp-rig.py"
 if 25 - 25: OoO0O00 * oO0o % i11iIiiIii + i11iIiiIii * OoO0O00
 if 42 - 42: II111iiii / O0 . iIii1I11I1II1 / O0 / OoO0O00 / OoooooooOO
 if 62 - 62: O0 . Oo0Ooo
 if 33 - 33: Oo0Ooo / iIii1I11I1II1 % i1IIi
 if ( II1io0 == "" ) :
  i1I1ii = "Cannot find lisp-rig.py or lisp-rig.pyo"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( i1I1ii ) ) )
  if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
  if 49 - 49: IiII / ooOoO0o / OOooOOo
 OOoOO0o0o0 = 'python {} "{}" to {} {}' . format ( II1io0 , oo0OoOO0o0o , OOooO0Oo00 , iIIIIIIIiIII )
 if 25 - 25: I1IiiI % O0 + i1IIi - ooOoO0o
 i1I1ii = commands . getoutput ( OOoOO0o0o0 )
 i1I1ii = i1I1ii . replace ( "\n" , "<br>" )
 i1I1ii = lisp . convert_font ( i1I1ii )
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 o0OOOOOo0 = lisp . space ( 2 ) + "Referrals:"
 i1I1ii = i1I1ii . replace ( "Referrals:" , o0OOOOOo0 )
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( i1I1ii ) ) )
 if 57 - 57: iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
def oOOOOO0Ooooo ( eid1 , eid2 ) :
 O0OoO0o = None
 if os . path . exists ( "lisp-lig.pyo" ) : O0OoO0o = "-O lisp-lig.pyo"
 if os . path . exists ( "lisp-lig.py" ) : O0OoO0o = "lisp-lig.py"
 if ( O0OoO0o == None ) : return ( [ None , None ] )
 if 57 - 57: Ii1I - OoooooooOO
 if 68 - 68: o0oOOo0O0Ooo % I1ii11iIi11i / I1Ii111 + I1Ii111 - I1Ii111 . OoO0O00
 if 100 - 100: OoOoOO00 % Oo0Ooo
 if 76 - 76: II111iiii / OoO0O00 + OoooooooOO . I1ii11iIi11i . I11i . ooOoO0o
 iiiI = commands . getoutput ( "egrep -A 2 'lisp map-resolver {' ./lisp.config" )
 OO0OOO00 = None
 for I1I1 in [ "address = " , "dns-name = " ] :
  OO0OOO00 = None
  iIIIiiiIiI1 = iiiI . find ( I1I1 )
  if ( iIIIiiiIiI1 == - 1 ) : continue
  OO0OOO00 = iiiI [ iIIIiiiIiI1 + len ( I1I1 ) : : ]
  iIIIiiiIiI1 = OO0OOO00 . find ( "\n" )
  if ( iIIIiiiIiI1 == - 1 ) : continue
  OO0OOO00 = OO0OOO00 [ 0 : iIIIiiiIiI1 ]
  break
  if 95 - 95: Ii1I - I1ii11iIi11i - O0 . I1IiiI . iII111i
 if ( OO0OOO00 == None ) : return ( [ None , None ] )
 if 7 - 7: I1Ii111
 if 45 - 45: O0 - OOooOOo
 if 56 - 56: O0 + Ii1I
 if 24 - 24: i11iIiiIii - Ii1I + oO0o * I1IiiI
 OoooOo0 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 IiI1Ii1ii = [ ]
 for oo0OoOO0o0o in [ eid1 , eid2 ] :
  if 44 - 44: I1IiiI % Ii1I * I1IiiI . Oo0Ooo + I1ii11iIi11i . OOooOOo
  if 6 - 6: IiII * OoooooooOO + I1Ii111 / Ii1I
  if 35 - 35: ooOoO0o % I1IiiI - ooOoO0o - OoO0O00 - OoooooooOO
  if 46 - 46: i1IIi . i1IIi . oO0o / I11i / ooOoO0o
  if 34 - 34: OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
  if ( OoooOo0 . is_geo_string ( oo0OoOO0o0o ) ) :
   IiI1Ii1ii . append ( oo0OoOO0o0o )
   continue
   if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
   if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
  OOoOO0o0o0 = 'python {} "{}" to {} count 1' . format ( O0OoO0o , oo0OoOO0o0o , OO0OOO00 )
  for IIiI1Ii in [ OOoOO0o0o0 , OOoOO0o0o0 + " no-info" ] :
   i1I1ii = commands . getoutput ( OOoOO0o0o0 )
   iIIIiiiIiI1 = i1I1ii . find ( "geo: " )
   if ( iIIIiiiIiI1 == - 1 ) :
    if ( IIiI1Ii != OOoOO0o0o0 ) : IiI1Ii1ii . append ( None )
    continue
    if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
   i1I1ii = i1I1ii [ iIIIiiiIiI1 + len ( "geo: " ) : : ]
   iIIIiiiIiI1 = i1I1ii . find ( "\n" )
   if ( iIIIiiiIiI1 == - 1 ) :
    if ( IIiI1Ii != OOoOO0o0o0 ) : IiI1Ii1ii . append ( None )
    continue
    if 98 - 98: oO0o . OoooooooOO
   IiI1Ii1ii . append ( i1I1ii [ 0 : iIIIiiiIiI1 ] )
   break
   if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
   if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 return ( IiI1Ii1ii )
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
@ bottle . post ( '/lisp/geo' )
def IiIi1II111I ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( oOO00O ( ) )
  if 80 - 80: Ii1I / OOooOOo
  if 21 - 21: Oo0Ooo - iIii1I11I1II1 - I1Ii111
 oo0OoOO0o0o = bottle . request . forms . get ( "geo-point" )
 III1I1Iii11i = bottle . request . forms . get ( "geo-prefix" )
 i1I1ii = ""
 if 96 - 96: oO0o - oO0o
 if 87 - 87: Oo0Ooo / OoooooooOO - I1ii11iIi11i . IiII + iIii1I11I1II1 . I1ii11iIi11i
 if 4 - 4: OoooooooOO + ooOoO0o . i1IIi / O0 - O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 o0OO0oooo = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 I11II1i1 = lisp . lisp_geo ( "" )
 IiI1ii11I1 = lisp . lisp_geo ( "" )
 I1i1iI , I1iI1I1ii1 = oOOOOO0Ooooo ( oo0OoOO0o0o , III1I1Iii11i )
 if 33 - 33: o0oOOo0O0Ooo / O0 + OOooOOo
 if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
 if 92 - 92: OoOoOO00 % O0
 if 55 - 55: iIii1I11I1II1 * iII111i
 if 85 - 85: iIii1I11I1II1 . II111iiii
 if ( o0OO0oooo . is_geo_string ( oo0OoOO0o0o ) ) :
  if ( I11II1i1 . parse_geo_string ( oo0OoOO0o0o ) == False ) :
   i1I1ii = "Could not parse geo-point format"
   if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
 elif ( I1i1iI == None ) :
  i1I1ii = "EID {} lookup could not find geo-point" . format (
 lisp . bold ( oo0OoOO0o0o , True ) )
 elif ( I11II1i1 . parse_geo_string ( I1i1iI ) == False ) :
  i1I1ii = "Could not parse geo-point format returned from lookup"
  if 22 - 22: OOooOOo
  if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
  if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
  if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
  if 94 - 94: i1IIi
  if 36 - 36: I1IiiI + Oo0Ooo
 if ( i1I1ii == "" ) :
  if ( o0OO0oooo . is_geo_string ( III1I1Iii11i ) ) :
   if ( IiI1ii11I1 . parse_geo_string ( III1I1Iii11i ) == False ) :
    i1I1ii = "Could not parse geo-prefix format"
    if 46 - 46: iII111i
  elif ( I1iI1I1ii1 == None ) :
   i1I1ii = "EID-prefix {} lookup could not find geo-prefix" . format ( lisp . bold ( III1I1Iii11i , True ) )
   if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
  elif ( IiI1ii11I1 . parse_geo_string ( I1iI1I1ii1 ) == False ) :
   i1I1ii = "Could not parse geo-prefix format returned from lookup"
   if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
   if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
   if 65 - 65: ooOoO0o - i1IIi
   if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
   if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
   if 34 - 34: I1Ii111 - OOooOOo
   if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if ( i1I1ii == "" ) :
  oo0OoOO0o0o = "" if ( oo0OoOO0o0o == I1i1iI ) else ", EID {}" . format ( oo0OoOO0o0o )
  III1I1Iii11i = "" if ( III1I1Iii11i == I1iI1I1ii1 ) else ", EID-prefix {}" . format ( III1I1Iii11i )
  if 64 - 64: i1IIi
  if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
  iiII = I11II1i1 . print_geo_url ( )
  I1iI1111i = IiI1ii11I1 . print_geo_url ( )
  I1Ii1iIIIIi = IiI1ii11I1 . radius
  iii = I11II1i1 . dms_to_decimal ( )
  iii = ( round ( iii [ 0 ] , 6 ) , round ( iii [ 1 ] , 6 ) )
  O000OOO = IiI1ii11I1 . dms_to_decimal ( )
  O000OOO = ( round ( O000OOO [ 0 ] , 6 ) , round ( O000OOO [ 1 ] , 6 ) )
  o0 = round ( IiI1ii11I1 . get_distance ( I11II1i1 ) , 2 )
  IIi1 = "inside" if IiI1ii11I1 . point_in_circle ( I11II1i1 ) else "outside"
  if 73 - 73: OOooOOo + OOooOOo % I11i * i1IIi
  if 4 - 4: OOooOOo - oO0o % OoOoOO00 / II111iiii % oO0o
  O0OO0OoO = lisp . space ( 2 )
  o0OOo = lisp . space ( 1 )
  IiI1Ii11Ii = lisp . space ( 3 )
  if 99 - 99: O0 . o0oOOo0O0Ooo % I11i - Oo0Ooo / I11i
  i1I1ii = ( "Geo-Point:{}{} {}{}<br>Geo-Prefix:{}{} {}, {} " + "kilometer radius{}<br>" ) . format ( O0OO0OoO , iiII , iii , oo0OoOO0o0o ,
  # I1Ii111 / OoOoOO00
 o0OOo , I1iI1111i , O000OOO , I1Ii1iIIIIi , III1I1Iii11i )
  i1I1ii += "Distance:{}{} kilometers, point is {} of circle" . format ( IiI1Ii11Ii ,
 o0 , lisp . bold ( IIi1 , True ) )
  if 82 - 82: OoooooooOO . Ii1I
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( i1I1ii ) ) )
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo
 if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
 if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
def iiIIIIiI111 ( addr_str , port , nonce ) :
 if ( addr_str != None ) :
  for OoooOO0Oo0 in lisp . lisp_info_sources_by_address . values ( ) :
   I1iIiIii = OoooOO0Oo0 . address . print_address_no_iid ( )
   if ( I1iIiIii == addr_str and OoooOO0Oo0 . port == port ) :
    return ( OoooOO0Oo0 )
    if 76 - 76: OoO0O00 . OoooooooOO % I1Ii111 * Ii1I
    if 23 - 23: IiII + iIii1I11I1II1
  return ( None )
  if 14 - 14: O0 % IiII % Ii1I * oO0o
  if 65 - 65: I11i % oO0o + I1ii11iIi11i
 if ( nonce != None ) :
  if ( nonce not in lisp . lisp_info_sources_by_nonce ) : return ( None )
  return ( lisp . lisp_info_sources_by_nonce [ nonce ] )
  if 86 - 86: iIii1I11I1II1 / O0 . I1Ii111 % iIii1I11I1II1 % Oo0Ooo
 return ( None )
 if 86 - 86: i11iIiiIii - o0oOOo0O0Ooo . ooOoO0o * Oo0Ooo / Ii1I % o0oOOo0O0Ooo
 if 61 - 61: o0oOOo0O0Ooo + OoOoOO00
 if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
 if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
 if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
 if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
 if 46 - 46: iIii1I11I1II1
def oo0oO00o0O00o ( lisp_sockets , info_source , packet ) :
 if 98 - 98: ooOoO0o . OOooOOo
 if 60 - 60: OoO0O00 - i1IIi . OOooOOo + OOooOOo * OOooOOo + Ii1I
 if 66 - 66: OOooOOo * OOooOOo / iIii1I11I1II1 + OoOoOO00 . OOooOOo
 if 51 - 51: I1ii11iIi11i
 o0oOOOOoo0 = lisp . lisp_ecm ( 0 )
 packet = o0oOOOOoo0 . decode ( packet )
 if ( packet == None ) :
  lisp . lprint ( "Could not decode ECM packet" )
  return ( True )
  if 80 - 80: i11iIiiIii % I1ii11iIi11i
  if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
 I1ii1II1iII = lisp . lisp_control_header ( )
 if ( I1ii1II1iII . decode ( packet ) == None ) :
  lisp . lprint ( "Could not decode control header" )
  return ( True )
  if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
 if ( I1ii1II1iII . type != lisp . LISP_MAP_REQUEST ) :
  lisp . lprint ( "Received ECM without Map-Request inside" )
  return ( True )
  if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
  if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
  if 21 - 21: iII111i
  if 24 - 24: iII111i / ooOoO0o
  if 61 - 61: iIii1I11I1II1 + oO0o
 i1IiiI = lisp . lisp_map_request ( )
 packet = i1IiiI . decode ( packet , None , 0 )
 O0OOO0 = i1IiiI . nonce
 o0OIi = info_source . address . print_address_no_iid ( )
 if 11 - 11: oO0o . I1IiiI + IiII / i1IIi
 if 1 - 1: Oo0Ooo * I1Ii111 . OoooooooOO
 if 73 - 73: OoOoOO00 % o0oOOo0O0Ooo
 if 71 - 71: oO0o - OoooooooOO * Oo0Ooo * I11i + o0oOOo0O0Ooo * I1ii11iIi11i
 i1IiiI . print_map_request ( )
 if 85 - 85: i11iIiiIii . OoooooooOO - iIii1I11I1II1
 lisp . lprint ( "Process {} from info-source {}, port {}, nonce 0x{}" . format ( lisp . bold ( "nat-proxy Map-Request" , False ) ,
 # O0 % ooOoO0o % I11i
 lisp . red ( o0OIi , False ) , info_source . port ,
 lisp . lisp_hex_string ( O0OOO0 ) ) )
 if 25 - 25: OoooooooOO % Ii1I * II111iiii - OoO0O00
 if 95 - 95: I1IiiI % I1Ii111 * I1IiiI + O0 . I1Ii111 % OoooooooOO
 if 6 - 6: OoOoOO00 - ooOoO0o * o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo
 if 100 - 100: OoO0O00 % I1Ii111 - I11i % I11i % I11i / ooOoO0o
 if 83 - 83: oO0o - ooOoO0o - IiII % i1IIi - iII111i . o0oOOo0O0Ooo
 info_source . cache_nonce_for_info_source ( O0OOO0 )
 if 96 - 96: Oo0Ooo + I1Ii111 . i1IIi
 if 54 - 54: II111iiii . i1IIi / I1ii11iIi11i % I1IiiI / I1Ii111
 if 65 - 65: OoOoOO00 . OoOoOO00 - oO0o + Oo0Ooo / i11iIiiIii
 if 90 - 90: iIii1I11I1II1 + OoOoOO00
 if 9 - 9: iIii1I11I1II1 . OoooooooOO + i1IIi - Oo0Ooo
 info_source . no_timeout = i1IiiI . subscribe_bit
 if 30 - 30: iII111i / OoO0O00 . iII111i
 if 17 - 17: Oo0Ooo + OoooooooOO * OoooooooOO
 if 5 - 5: I1Ii111 % OoooooooOO . OoOoOO00
 if 67 - 67: I1ii11iIi11i + Ii1I
 if 72 - 72: IiII % o0oOOo0O0Ooo
 if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
 for oO0oo in i1IiiI . itr_rlocs :
  if ( oO0oo . is_local ( ) ) : return ( False )
  if 52 - 52: IiII % ooOoO0o
  if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
  if 23 - 23: i11iIiiIii
  if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
  if 65 - 65: II111iiii / Oo0Ooo
 iiII1i = lisp . lisp_myrlocs [ 0 ]
 i1IiiI . itr_rloc_count = 0
 i1IiiI . itr_rlocs = [ ]
 i1IiiI . itr_rlocs . append ( iiII1i )
 if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
 packet = i1IiiI . encode ( None , 0 )
 i1IiiI . print_map_request ( )
 if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
 O00o = i1IiiI . target_eid
 if ( O00o . is_ipv6 ( ) ) :
  o0o0ooOo00 = lisp . lisp_myrlocs [ 1 ]
  if ( o0o0ooOo00 != None ) : iiII1i = o0o0ooOo00
  if 91 - 91: OoO0O00 * I1Ii111 % OoO0O00 . o0oOOo0O0Ooo * I1ii11iIi11i . OOooOOo
  if 13 - 13: I1ii11iIi11i
  if 80 - 80: Oo0Ooo % IiII % OoooooooOO * Oo0Ooo % Ii1I
  if 41 - 41: OoooooooOO / i1IIi
  if 70 - 70: OoOoOO00 % o0oOOo0O0Ooo % i1IIi / I1ii11iIi11i % i11iIiiIii / i1IIi
 i1i1Ii1IiIII = lisp . lisp_is_running ( "lisp-ms" )
 lisp . lisp_send_ecm ( lisp_sockets , packet , O00o , lisp . LISP_CTRL_PORT ,
 O00o , iiII1i , to_ms = i1i1Ii1IiIII , ddt = False )
 return ( True )
 if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
 if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
 if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
 if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
 if 10 - 10: IiII / OoooooooOO
 if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
 if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
 if 25 - 25: iIii1I11I1II1
 if 63 - 63: ooOoO0o
def oO0oOOOooo ( lisp_sockets , info_source , packet , mr_or_mn ) :
 o0OIi = info_source . address . print_address_no_iid ( )
 oOoO0o00OO0 = info_source . port
 O0OOO0 = info_source . nonce
 if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
 mr_or_mn = "Reply" if mr_or_mn else "Notify"
 mr_or_mn = lisp . bold ( "nat-proxy Map-{}" . format ( mr_or_mn ) , False )
 if 3 - 3: OOooOOo . IiII / Oo0Ooo
 lisp . lprint ( "Forward {} to info-source {}, port {}, nonce 0x{}" . format ( mr_or_mn , lisp . red ( o0OIi , False ) , oOoO0o00OO0 ,
 # iIii1I11I1II1 % iIii1I11I1II1 / ooOoO0o . oO0o + I1Ii111 . I1Ii111
 lisp . lisp_hex_string ( O0OOO0 ) ) )
 if 90 - 90: o0oOOo0O0Ooo / OOooOOo - OOooOOo . I1IiiI
 if 82 - 82: I1Ii111 . I1Ii111 - iII111i
 if 72 - 72: i11iIiiIii
 if 94 - 94: OOooOOo
 i1IiI1ii1i = lisp . lisp_convert_4to6 ( o0OIi )
 lisp . lisp_send ( lisp_sockets , i1IiI1ii1i , oOoO0o00OO0 , packet )
 if 39 - 39: OOooOOo + OoO0O00
 if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
 if 71 - 71: ooOoO0o . i11iIiiIii
 if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
 if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
 if 67 - 67: iII111i
def oooO0o ( lisp_sockets , source , sport , packet ) :
 global Oo
 if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
 I1ii1II1iII = lisp . lisp_control_header ( )
 if ( I1ii1II1iII . decode ( packet ) == None ) :
  lisp . lprint ( "Could not decode control header" )
  return
  if 89 - 89: Ii1I
  if 51 - 51: iII111i
  if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
  if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
  if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
  if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
  if 29 - 29: Ii1I / ooOoO0o % I11i
  if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 if ( I1ii1II1iII . type == lisp . LISP_NAT_INFO ) :
  if ( I1ii1II1iII . info_reply == False ) :
   lisp . lisp_process_info_request ( lisp_sockets , packet , source , sport ,
 lisp . lisp_ms_rtr_list )
   if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  return
  if 79 - 79: IiII + IiII + Ii1I
  if 39 - 39: O0 - OoooooooOO
 oo0O00ooo0o = packet
 packet = lisp . lisp_packet_ipc ( packet , source , sport )
 if 29 - 29: OoooooooOO . II111iiii % OoOoOO00
 if 26 - 26: iIii1I11I1II1 - I1ii11iIi11i . IiII . IiII + iIii1I11I1II1 * Oo0Ooo
 if 85 - 85: OOooOOo + II111iiii - OOooOOo * oO0o - i1IIi % iII111i
 if 1 - 1: OoooooooOO / O0 + OoOoOO00 + OoOoOO00 . I1Ii111 - OoOoOO00
 if ( I1ii1II1iII . type in ( lisp . LISP_MAP_REGISTER , lisp . LISP_MAP_NOTIFY_ACK ) ) :
  lisp . lisp_ipc ( packet , Oo , "lisp-ms" )
  return
  if 9 - 9: I1Ii111 * OoooooooOO % I1IiiI / OoOoOO00 * I11i
  if 48 - 48: OoooooooOO . OoOoOO00
  if 65 - 65: oO0o . Oo0Ooo
  if 94 - 94: OoOoOO00 + IiII . ooOoO0o
  if 69 - 69: O0 - O0
 if ( I1ii1II1iII . type == lisp . LISP_MAP_REPLY ) :
  i1I1i1i1I1 = lisp . lisp_map_reply ( )
  i1I1i1i1I1 . decode ( oo0O00ooo0o )
  if 17 - 17: OoOoOO00 + OoooooooOO % OOooOOo
  OoooOO0Oo0 = iiIIIIiI111 ( None , 0 , i1I1i1i1I1 . nonce )
  if ( OoooOO0Oo0 ) :
   oO0oOOOooo ( lisp_sockets , OoooOO0Oo0 , oo0O00ooo0o , True )
  else :
   O0OoO0o = "/tmp/lisp-lig"
   if ( os . path . exists ( O0OoO0o ) ) :
    lisp . lisp_ipc ( packet , Oo , O0OoO0o )
   else :
    lisp . lisp_ipc ( packet , Oo , "lisp-itr" )
    if 36 - 36: i11iIiiIii + I1ii11iIi11i % OOooOOo . I1IiiI - ooOoO0o
    if 94 - 94: I1IiiI % OoOoOO00 . IiII . ooOoO0o . OoO0O00
  return
  if 53 - 53: OoOoOO00
  if 84 - 84: OoO0O00
  if 97 - 97: i1IIi
  if 98 - 98: OoooooooOO - I1IiiI + ooOoO0o
  if 98 - 98: iII111i . IiII . IiII - OOooOOo
 if ( I1ii1II1iII . type == lisp . LISP_MAP_NOTIFY ) :
  oOOO0o = lisp . lisp_map_notify ( lisp_sockets )
  oOOO0o . decode ( oo0O00ooo0o )
  if 18 - 18: I1ii11iIi11i / Oo0Ooo - iII111i
  OoooOO0Oo0 = iiIIIIiI111 ( None , 0 , oOOO0o . nonce )
  if ( OoooOO0Oo0 ) :
   oO0oOOOooo ( lisp_sockets , OoooOO0Oo0 , oo0O00ooo0o ,
 False )
  else :
   O0OoO0o = "/tmp/lisp-lig"
   if ( os . path . exists ( O0OoO0o ) ) :
    lisp . lisp_ipc ( packet , Oo , O0OoO0o )
   else :
    OOoO00ooO = "lisp-rtr" if lisp . lisp_is_running ( "lisp-rtr" ) else "lisp-etr"
    if 69 - 69: oO0o / IiII * ooOoO0o
    lisp . lisp_ipc ( packet , Oo , OOoO00ooO )
    if 81 - 81: oO0o
    if 62 - 62: Ii1I + O0 * OoO0O00
  return
  if 59 - 59: II111iiii
  if 43 - 43: Oo0Ooo + OoooooooOO
  if 47 - 47: ooOoO0o
  if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
  if 23 - 23: II111iiii * iII111i
  if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
 if ( I1ii1II1iII . type == lisp . LISP_MAP_REFERRAL ) :
  II1io0 = "/tmp/lisp-rig"
  if ( os . path . exists ( II1io0 ) ) :
   lisp . lisp_ipc ( packet , Oo , II1io0 )
  else :
   lisp . lisp_ipc ( packet , Oo , "lisp-mr" )
   if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
  return
  if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
  if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  if 21 - 21: OoO0O00
  if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
  if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
  if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
 if ( I1ii1II1iII . type == lisp . LISP_MAP_REQUEST ) :
  OOoO00ooO = "lisp-itr" if ( I1ii1II1iII . is_smr ( ) ) else "lisp-etr"
  if 11 - 11: O0 * OoOoOO00
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  if 18 - 18: OoooooooOO
  if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
  if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
  if ( I1ii1II1iII . rloc_probe ) : return
  if 94 - 94: ooOoO0o + I1IiiI
  lisp . lisp_ipc ( packet , Oo , OOoO00ooO )
  return
  if 56 - 56: OoOoOO00 % o0oOOo0O0Ooo
  if 40 - 40: OOooOOo / IiII
  if 29 - 29: Ii1I - Ii1I / ooOoO0o
  if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
  if 18 - 18: Oo0Ooo % O0
  if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
 if ( I1ii1II1iII . type == lisp . LISP_ECM ) :
  OoooOO0Oo0 = iiIIIIiI111 ( source , sport , None )
  if ( OoooOO0Oo0 ) :
   if ( oo0oO00o0O00o ( lisp_sockets , OoooOO0Oo0 ,
 oo0O00ooo0o ) ) : return
   if 86 - 86: IiII
   if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
  OOoO00ooO = "lisp-mr"
  if ( I1ii1II1iII . is_to_etr ( ) ) :
   OOoO00ooO = "lisp-etr"
  elif ( I1ii1II1iII . is_to_ms ( ) ) :
   OOoO00ooO = "lisp-ms"
  elif ( I1ii1II1iII . is_ddt ( ) ) :
   if ( lisp . lisp_is_running ( "lisp-ddt" ) ) :
    OOoO00ooO = "lisp-ddt"
   elif ( lisp . lisp_is_running ( "lisp-ms" ) ) :
    OOoO00ooO = "lisp-ms"
    if 33 - 33: II111iiii - IiII - ooOoO0o
  elif ( lisp . lisp_is_running ( "lisp-mr" ) == False ) :
   OOoO00ooO = "lisp-etr"
   if 92 - 92: OoO0O00 * IiII
  lisp . lisp_ipc ( packet , Oo , OOoO00ooO )
  if 92 - 92: oO0o
 return
 if 7 - 7: iII111i
 if 73 - 73: OoO0O00 % I1ii11iIi11i
 if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
 if 62 - 62: i11iIiiIii
 if 2 - 2: I1IiiI
 if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
 if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
 if 14 - 14: IiII . IiII % ooOoO0o
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
 if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
 if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
 if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
class O0oooo0O ( bottle . ServerAdapter ) :
 def run ( self , hand ) :
  Ii1iiIIi1i = "./lisp-cert.pem"
  if 44 - 44: o0oOOo0O0Ooo
  if 51 - 51: II111iiii
  if 10 - 10: OoO0O00 % OoO0O00 / o0oOOo0O0Ooo - OoOoOO00
  if 44 - 44: ooOoO0o - O0 / II111iiii . iIii1I11I1II1 . i1IIi
  if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
  if ( os . path . exists ( Ii1iiIIi1i ) == False ) :
   os . system ( "cp ./lisp-cert.pem.default {}" . format ( Ii1iiIIi1i ) )
   lisp . lprint ( ( "{} does not exist, creating a copy from lisp-" + "cert.pem.default" ) . format ( Ii1iiIIi1i ) )
   if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
   if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
   if 59 - 59: iIii1I11I1II1 / I1ii11iIi11i % ooOoO0o
  Oooo = wsgiserver . CherryPyWSGIServer ( ( self . host , self . port ) , hand )
  Oooo . ssl_adapter = pyOpenSSLAdapter ( Ii1iiIIi1i , Ii1iiIIi1i , None )
  if 74 - 74: ooOoO0o % OoOoOO00 / Oo0Ooo
  if 2 - 2: IiII % IiII % I1Ii111
  try :
   Oooo . start ( )
  finally :
   Oooo . stop ( )
   if 60 - 60: OOooOOo
   if 73 - 73: ooOoO0o
   if 86 - 86: OoOoOO00 . I11i / Oo0Ooo * I11i
   if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
   if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
   if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
   if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
   if 5 - 5: O0 - I1IiiI
   if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
   if 16 - 16: II111iiii
   if 100 - 100: O0 - i1IIi
   if 48 - 48: oO0o % ooOoO0o + O0
   if 27 - 27: I1ii11iIi11i / OOooOOo
   if 33 - 33: OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
   if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
   if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
def oOooOoOOo0O ( bottle_port ) :
 lisp . lisp_set_exception ( )
 if 41 - 41: iII111i
 if 88 - 88: O0 . oO0o % I1IiiI
 if 10 - 10: I1IiiI + O0
 if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
 if 31 - 31: i11iIiiIii * OoOoOO00
 if ( bottle_port < 0 ) :
  bottle . run ( host = "0.0.0.0" , port = - bottle_port )
  return
  if 69 - 69: i11iIiiIii
  if 61 - 61: O0
 bottle . server_names [ "lisp-ssl-server" ] = O0oooo0O
 if 21 - 21: OoO0O00 % iIii1I11I1II1 . OoO0O00
 if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
 if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
 if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
 try :
  bottle . run ( host = "0.0.0.0" , port = bottle_port , server = "lisp-ssl-server" ,
 fast = True )
 except :
  bottle . run ( host = "0.0.0.0" , port = bottle_port , fast = True )
  if 31 - 31: oO0o * I1Ii111 . OoOoOO00 * I11i
 return
 if 28 - 28: IiII + I1IiiI - Oo0Ooo % OOooOOo . I11i + I1IiiI
 if 72 - 72: Ii1I / Oo0Ooo / oO0o * OoOoOO00 + OOooOOo
 if 58 - 58: o0oOOo0O0Ooo % I1IiiI . I1IiiI * OoO0O00 - IiII . OoooooooOO
 if 10 - 10: I1Ii111
 if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
 if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
 if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
 if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
def o00OIIIIIiiI ( ) :
 lisp . lisp_set_exception ( )
 if 38 - 38: O0
 return
 if 79 - 79: i1IIi . oO0o
 if 34 - 34: I1Ii111 * II111iiii
 if 71 - 71: IiII
 if 97 - 97: I1ii11iIi11i
 if 86 - 86: Oo0Ooo - OOooOOo . OoOoOO00 . II111iiii * I1IiiI . II111iiii
 if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
 if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
 if 28 - 28: i11iIiiIii
 if 51 - 51: I1IiiI + ooOoO0o * O0 . Ii1I
def O00Oo00OOoO0 ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 IIiiI = { "lisp-itr" : False , "lisp-etr" : False , "lisp-rtr" : False ,
 "lisp-mr" : False , "lisp-ms" : False , "lisp-ddt" : False }
 if 99 - 99: OoO0O00 / i1IIi . I1ii11iIi11i
 while ( True ) :
  time . sleep ( 1 )
  I1I1i11iiiiI = IIiiI
  IIiiI = { }
  if 66 - 66: oO0o / OoOoOO00
  for OOoO00ooO in I1I1i11iiiiI :
   IIiiI [ OOoO00ooO ] = lisp . lisp_is_running ( OOoO00ooO )
   if ( I1I1i11iiiiI [ OOoO00ooO ] == IIiiI [ OOoO00ooO ] ) : continue
   if 13 - 13: II111iiii
   lisp . lprint ( "*** Process '{}' has {} ***" . format ( OOoO00ooO ,
 "come up" if IIiiI [ OOoO00ooO ] else "gone down" ) )
   if 55 - 55: Oo0Ooo % i1IIi * I11i
   if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
   if 63 - 63: iIii1I11I1II1 / ooOoO0o
   if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
   if ( IIiiI [ OOoO00ooO ] == True ) :
    lisp . lisp_ipc_lock . acquire ( )
    lispconfig . lisp_send_commands ( lisp_socket , OOoO00ooO )
    lisp . lisp_ipc_lock . release ( )
    if 50 - 50: II111iiii
    if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
    if 44 - 44: I1IiiI
 return
 if 55 - 55: oO0o . I1Ii111 * I1Ii111
 if 82 - 82: I1IiiI % OoO0O00 % I11i + I11i
 if 6 - 6: Oo0Ooo
 if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
 if 93 - 93: i11iIiiIii
 if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
 if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
def Ii1i ( ) :
 lisp . lisp_set_exception ( )
 ooooOoOooo00Oo = 60
 if 72 - 72: I11i
 while ( True ) :
  time . sleep ( ooooOoOooo00Oo )
  if 26 - 26: IiII % Oo0Ooo
  OoOOoo = [ ]
  II1ii1 = lisp . lisp_get_timestamp ( )
  if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
  if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
  if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
  if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
  for iii1I1Iii in lisp . lisp_info_sources_by_address :
   OoooOO0Oo0 = lisp . lisp_info_sources_by_address [ iii1I1Iii ]
   if ( OoooOO0Oo0 . no_timeout ) : continue
   if ( OoooOO0Oo0 . uptime + ooooOoOooo00Oo < II1ii1 ) : continue
   if 25 - 25: Oo0Ooo % OoOoOO00
   OoOOoo . append ( iii1I1Iii )
   if 75 - 75: i1IIi
   O0OOO0 = OoooOO0Oo0 . nonce
   if ( O0OOO0 == None ) : continue
   if ( O0OOO0 in lisp . lisp_info_sources_by_nonce ) :
    lisp . lisp_info_sources_by_nonce . pop ( O0OOO0 )
    if 74 - 74: Oo0Ooo + I1Ii111 - oO0o - OoO0O00 + iII111i - iIii1I11I1II1
    if 54 - 54: I1ii11iIi11i + II111iiii . I1IiiI / OoO0O00 . ooOoO0o
    if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
    if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
    if 36 - 36: I11i - IiII . IiII
    if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
  for iii1I1Iii in OoOOoo :
   lisp . lisp_info_sources_by_address . pop ( iii1I1Iii )
   if 84 - 84: iIii1I11I1II1 + OoooooooOO
   if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
 return
 if 10 - 10: I1ii11iIi11i + IiII
 if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
 if 62 - 62: II111iiii
 if 12 - 12: IiII + II111iiii
 if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
 if 80 - 80: iII111i
 if 3 - 3: I1ii11iIi11i * I11i
 if 53 - 53: iIii1I11I1II1 / iII111i % OoO0O00 + IiII / ooOoO0o
def oo00oO ( lisp_ipc_control_socket , lisp_sockets ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  try : I11i1I11 = lisp_ipc_control_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  IIIi1i1I = I11i1I11 [ 0 ] . split ( "@" )
  ooo0O = I11i1I11 [ 1 ]
  if 32 - 32: IiII - oO0o . iIii1I11I1II1 . I1Ii111 + II111iiii % OoooooooOO
  iIii = IIIi1i1I [ 0 ]
  i1IiI1ii1i = IIIi1i1I [ 1 ]
  oOoO0o00OO0 = int ( IIIi1i1I [ 2 ] )
  Oo000 = IIIi1i1I [ 3 : : ]
  if 75 - 75: O0
  if ( len ( Oo000 ) > 1 ) :
   Oo000 = lisp . lisp_bit_stuff ( Oo000 )
  else :
   Oo000 = Oo000 [ 0 ]
   if 56 - 56: OoO0O00 / II111iiii
   if 39 - 39: OoOoOO00 - OoooooooOO - i1IIi / II111iiii
  if ( iIii != "control-packet" ) :
   lisp . lprint ( ( "lisp_core_control_packet_process() received" + "unexpected control-packet, message ignored" ) )
   if 49 - 49: Oo0Ooo + O0 + IiII . II111iiii % ooOoO0o
   continue
   if 33 - 33: OoOoOO00 . iIii1I11I1II1 / I11i % Ii1I
   if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
  lisp . lprint ( ( "{} {} bytes from {}, dest/port: {}/{}, control-" + "packet: {}" ) . format ( lisp . bold ( "Receive" , False ) , len ( Oo000 ) ,
  # Oo0Ooo / OoO0O00
 ooo0O , i1IiI1ii1i , oOoO0o00OO0 , lisp . lisp_format_packet ( Oo000 ) ) )
  if 40 - 40: I11i / iII111i + OoO0O00 / OoooooooOO - oO0o / I1Ii111
  if 62 - 62: i11iIiiIii - I11i
  if 81 - 81: I11i
  if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
  if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
  if 31 - 31: i1IIi % II111iiii
  I1ii1II1iII = lisp . lisp_control_header ( )
  I1ii1II1iII . decode ( Oo000 )
  if ( I1ii1II1iII . type == lisp . LISP_MAP_REPLY ) :
   i1I1i1i1I1 = lisp . lisp_map_reply ( )
   i1I1i1i1I1 . decode ( Oo000 )
   if ( iiIIIIiI111 ( None , 0 , i1I1i1i1I1 . nonce ) ) :
    oooO0o ( lisp_sockets , ooo0O , oOoO0o00OO0 , Oo000 )
    continue
    if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
    if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
    if 3 - 3: II111iiii / OOooOOo
    if 48 - 48: ooOoO0o . I1ii11iIi11i
    if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
    if 24 - 24: oO0o - iII111i / ooOoO0o
    if 10 - 10: OoOoOO00 * i1IIi
    if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
  if ( I1ii1II1iII . type == lisp . LISP_MAP_NOTIFY and ooo0O == "lisp-etr" ) :
   Oo0O00Oo0o0 = lisp . lisp_packet_ipc ( Oo000 , ooo0O , oOoO0o00OO0 )
   lisp . lisp_ipc ( Oo0O00Oo0o0 , Oo , "lisp-itr" )
   continue
   if 34 - 34: I1IiiI
   if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
   if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
   if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
   if 98 - 98: OoO0O00
   if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
   if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  OoooOo0 = lisp . lisp_convert_4to6 ( i1IiI1ii1i )
  OoooOo0 = lisp . lisp_address ( lisp . LISP_AFI_IPV6 , "" , 128 , 0 )
  if ( OoooOo0 . is_ipv4_string ( i1IiI1ii1i ) ) : i1IiI1ii1i = "::ffff:" + i1IiI1ii1i
  OoooOo0 . store_address ( i1IiI1ii1i )
  if 52 - 52: I1Ii111 + I1Ii111
  if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
  if 54 - 54: OoOoOO00 . OoooooooOO
  if 36 - 36: oO0o / II111iiii * IiII % I1ii11iIi11i
  lisp . lisp_send ( lisp_sockets , OoooOo0 , oOoO0o00OO0 , Oo000 )
  if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
 return
 if 28 - 28: Ii1I . I1ii11iIi11i
 if 77 - 77: I1ii11iIi11i % II111iiii
 if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
 if 90 - 90: o0oOOo0O0Ooo
 if 44 - 44: o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo + OoOoOO00
 if 32 - 32: IiII - ooOoO0o * iII111i * I11i
 if 84 - 84: Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
 if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
def iI11I ( ) :
 Oo0O0oooo = open ( "./lisp.config.example" , "r" ) ; I111iI = Oo0O0oooo . read ( ) ; Oo0O0oooo . close ( )
 Oo0O0oooo = open ( "./lisp.config" , "w" )
 I111iI = I111iI . split ( "\n" )
 for OooOO in I111iI :
  Oo0O0oooo . write ( OooOO + "\n" )
  if ( OooOO [ 0 ] == "#" and OooOO [ - 1 ] == "#" and len ( OooOO ) >= 4 ) :
   o0oO = OooOO [ 1 : - 2 ]
   ooOo0 = len ( o0oO ) * "-"
   if ( o0oO == ooOo0 ) : break
   if 61 - 61: II111iiii
   if 48 - 48: OOooOOo
 Oo0O0oooo . close ( )
 return
 if 26 - 26: iII111i * I1Ii111 * oO0o * OoOoOO00
 if 48 - 48: iII111i % i11iIiiIii . OoooooooOO * IiII % OoO0O00 . iII111i
 if 6 - 6: O0 . ooOoO0o - oO0o / i11iIiiIii
 if 84 - 84: I11i / I1ii11iIi11i * o0oOOo0O0Ooo * OoO0O00 * OOooOOo * O0
 if 83 - 83: O0 % II111iiii + o0oOOo0O0Ooo / OoooooooOO
 if 75 - 75: II111iiii . I1IiiI + OOooOOo - OoOoOO00 - O0 . I11i
 if 19 - 19: Ii1I * i1IIi % O0 + I11i
 if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
def Ii1iIIII1i ( bottle_port ) :
 global Oo0o
 global Ii1iI
 global Oo
 global I1Ii11I1Ii1i
 global Ooo
 global o0oOoO00o
 if 84 - 84: i1IIi - I1IiiI % iII111i
 lisp . lisp_i_am ( "core" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "core-process starting up" )
 lisp . lisp_uptime = lisp . lisp_get_timestamp ( )
 lisp . lisp_version = commands . getoutput ( "cat lisp-version.txt" )
 Oo0o = commands . getoutput ( "cat lisp-build-date.txt" )
 if 80 - 80: o0oOOo0O0Ooo % iII111i
 if 80 - 80: Ii1I
 if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
 if 59 - 59: I1ii11iIi11i + I11i . oO0o
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 87 - 87: OoO0O00
 if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
 if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
 if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
 if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
 lisp . lisp_ipc_lock = multiprocessing . Lock ( )
 if 46 - 46: i11iIiiIii
 if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
 if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
 if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
 if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
 if 65 - 65: OoooooooOO
 if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
 if ( os . path . exists ( "lisp.py" ) ) : lisp . lisp_version += "+"
 if 83 - 83: ooOoO0o
 if 43 - 43: OOooOOo
 if 84 - 84: OOooOOo . IiII . iII111i
 if 2 - 2: Oo0Ooo - OoOoOO00
 if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
 if 54 - 54: ooOoO0o % Oo0Ooo - OOooOOo
 iIi11IiiiII11 = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 if ( os . getenv ( "LISP_ANYCAST_MR" ) == None or lisp . lisp_myrlocs [ 0 ] == None ) :
  Ii1iI = lisp . lisp_open_listen_socket ( iIi11IiiiII11 ,
 str ( lisp . LISP_CTRL_PORT ) )
 else :
  iIi11IiiiII11 = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( )
  Ii1iI = lisp . lisp_open_listen_socket ( iIi11IiiiII11 ,
 str ( lisp . LISP_CTRL_PORT ) )
  if 26 - 26: iII111i / OoooooooOO - Oo0Ooo
 lisp . lprint ( "Listen on {}, port 4342" . format ( iIi11IiiiII11 ) )
 if 2 - 2: I1ii11iIi11i - Oo0Ooo
 if 4 - 4: O0 / I11i . OoO0O00 - ooOoO0o / OOooOOo
 if 25 - 25: I11i * OoOoOO00 - Oo0Ooo . ooOoO0o . oO0o
 if 89 - 89: O0 * I11i * OoO0O00
 if 3 - 3: OOooOOo / iII111i * iIii1I11I1II1 + II111iiii / o0oOOo0O0Ooo / IiII
 if 25 - 25: OoOoOO00 + OoO0O00 % Ii1I % OOooOOo / oO0o
 if ( lisp . lisp_external_data_plane ( ) == False ) :
  o0oOoO00o = lisp . lisp_open_listen_socket ( iIi11IiiiII11 ,
 str ( lisp . LISP_DATA_PORT ) )
  lisp . lprint ( "Listen on {}, port 4341" . format ( iIi11IiiiII11 ) )
  if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
  if 23 - 23: I1IiiI
  if 7 - 7: iII111i % I1ii11iIi11i
  if 64 - 64: I1Ii111 + i11iIiiIii
  if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
  if 68 - 68: IiII . ooOoO0o
 Oo = lisp . lisp_open_send_socket ( "lisp-core" , "" )
 Oo . settimeout ( 3 )
 if 64 - 64: i1IIi + Oo0Ooo * I1IiiI / OOooOOo
 if 3 - 3: Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
 if 50 - 50: iIii1I11I1II1 * oO0o
 if 85 - 85: i1IIi
 if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
 I1Ii11I1Ii1i = lisp . lisp_open_listen_socket ( "" , "lisp-core-pkt" )
 if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
 Ooo = [ Ii1iI , Ii1iI ,
 Oo ]
 if 54 - 54: OoOoOO00 * iII111i + OoO0O00
 if 93 - 93: o0oOOo0O0Ooo / I1IiiI
 if 47 - 47: Oo0Ooo * OOooOOo
 if 98 - 98: oO0o - oO0o . ooOoO0o
 if 60 - 60: I1IiiI * I1ii11iIi11i / O0 + I11i + IiII
 threading . Thread ( target = oo00oO ,
 args = [ I1Ii11I1Ii1i , Ooo ] ) . start ( )
 if 66 - 66: IiII * Oo0Ooo . OoooooooOO * I1Ii111
 if 93 - 93: IiII / i1IIi
 if 47 - 47: ooOoO0o - Ii1I
 if 98 - 98: oO0o . I1Ii111 / OoOoOO00 . ooOoO0o
 if 1 - 1: OOooOOo
 if 87 - 87: O0 * II111iiii + iIii1I11I1II1 % oO0o % i11iIiiIii - OoOoOO00
 if ( os . path . exists ( "./lisp.config" ) == False ) :
  lisp . lprint ( ( "./lisp.config does not exist, creating a copy " + "from lisp.config.example" ) )
  if 73 - 73: iII111i + Ii1I
  iI11I ( )
  if 37 - 37: oO0o - iIii1I11I1II1 + II111iiii . Ii1I % iIii1I11I1II1
  if 17 - 17: I1Ii111 + i1IIi % O0
  if 65 - 65: IiII
  if 50 - 50: II111iiii / OoO0O00
  if 79 - 79: I1ii11iIi11i - iIii1I11I1II1 % i1IIi / Oo0Ooo + II111iiii
  if 95 - 95: oO0o
 i11ii ( Ii1iI )
 if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
 threading . Thread ( target = lispconfig . lisp_config_process ,
 args = [ Oo ] ) . start ( )
 if 100 - 100: OoooooooOO - OoooooooOO + IiII
 if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo / OoooooooOO
 if 90 - 90: I1Ii111
 if 35 - 35: II111iiii / Ii1I
 threading . Thread ( target = oOooOoOOo0O ,
 args = [ bottle_port ] ) . start ( )
 threading . Thread ( target = o00OIIIIIiiI , args = [ ] ) . start ( )
 if 79 - 79: OoOoOO00 + I1Ii111 * iII111i * Ii1I
 if 53 - 53: OOooOOo / Oo0Ooo
 if 10 - 10: I1ii11iIi11i . o0oOOo0O0Ooo
 if 75 - 75: O0 * i1IIi - I11i / OOooOOo % OOooOOo / OoOoOO00
 threading . Thread ( target = O00Oo00OOoO0 ,
 args = [ Oo ] ) . start ( )
 if 5 - 5: O0 - iII111i / I1Ii111 . o0oOOo0O0Ooo
 if 7 - 7: I1ii11iIi11i - OoOoOO00
 if 54 - 54: oO0o / iIii1I11I1II1 / OoooooooOO . i1IIi - OoOoOO00
 if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
 threading . Thread ( target = Ii1i ) . start ( )
 return ( True )
 if 46 - 46: Ii1I
 if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
 if 87 - 87: I1ii11iIi11i / I1IiiI
 if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
 if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
 if 11 - 11: I1ii11iIi11i - OoooooooOO
 if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
def I1iiII1 ( ) :
 if 45 - 45: OoO0O00 + OoO0O00 % ooOoO0o
 if 36 - 36: Ii1I * I11i . I11i / Oo0Ooo / I1IiiI
 if 80 - 80: OoooooooOO - i1IIi
 if 51 - 51: i1IIi . OoOoOO00 / OoOoOO00 % i11iIiiIii * OOooOOo - I1Ii111
 lisp . lisp_close_socket ( Oo , "lisp-core" )
 lisp . lisp_close_socket ( I1Ii11I1Ii1i , "lisp-core-pkt" )
 lisp . lisp_close_socket ( Ii1iI , "" )
 lisp . lisp_close_socket ( o0oOoO00o , "" )
 return
 if 49 - 49: Oo0Ooo - iIii1I11I1II1
 if 64 - 64: I1Ii111 + iIii1I11I1II1
 if 14 - 14: Ii1I / OoooooooOO + II111iiii . O0 / i1IIi
 if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
 if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
 if 12 - 12: OoOoOO00 + o0oOOo0O0Ooo . I1Ii111
 if 52 - 52: OoO0O00
 if 4 - 4: Ii1I % I1ii11iIi11i + I11i - I1ii11iIi11i
 if 98 - 98: Ii1I - O0 * oO0o * Ii1I * Ii1I
 if 44 - 44: IiII + I11i
 if 66 - 66: oO0o
 if 34 - 34: iII111i % i11iIiiIii + i11iIiiIii - iII111i
def i11ii ( lisp_socket ) :
 if 2 - 2: II111iiii + i1IIi
 Oo0O0oooo = open ( "./lisp.config" , "r" ) ; I111iI = Oo0O0oooo . read ( ) ; Oo0O0oooo . close ( )
 I111iI = I111iI . split ( "\n" )
 if 68 - 68: OOooOOo + Ii1I
 if 58 - 58: IiII * Ii1I . i1IIi
 if 19 - 19: oO0o
 if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
 if 94 - 94: iIii1I11I1II1 + IiII
 II11II = False
 for OooOO in I111iI :
  if ( OooOO [ 0 : 1 ] == "#-" and OooOO [ - 2 : - 1 ] == "-#" ) : break
  if ( OooOO == "" or OooOO [ 0 ] == "#" ) : continue
  if ( OooOO . find ( "decentralized-push-xtr = yes" ) == - 1 ) : continue
  II11II = True
  break
  if 40 - 40: iII111i + O0
 if ( II11II == False ) : return
 if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
 if 36 - 36: OoOoOO00 . i11iIiiIii
 if 81 - 81: Oo0Ooo * iII111i * OoO0O00
 if 85 - 85: O0 * oO0o
 if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
 Ii1 = [ ]
 o0OOOoo0000 = False
 for OooOO in I111iI :
  if ( OooOO [ 0 : 1 ] == "#-" and OooOO [ - 2 : - 1 ] == "-#" ) : break
  if ( OooOO == "" or OooOO [ 0 ] == "#" ) : continue
  if 19 - 19: OoooooooOO . I1IiiI + I1Ii111 - I1IiiI / I1IiiI % IiII
  if ( OooOO . find ( "lisp map-server" ) != - 1 ) :
   o0OOOoo0000 = True
   continue
   if 4 - 4: i11iIiiIii * I1ii11iIi11i + OoooooooOO - IiII . ooOoO0o . iIii1I11I1II1
  if ( OooOO [ 0 ] == "}" ) :
   o0OOOoo0000 = False
   continue
   if 48 - 48: o0oOOo0O0Ooo * oO0o . I1IiiI - I1Ii111 + OOooOOo . Oo0Ooo
   if 62 - 62: I11i + OoooooooOO * iIii1I11I1II1 / i1IIi * O0
   if 10 - 10: iIii1I11I1II1 * OoooooooOO / OOooOOo
   if 33 - 33: o0oOOo0O0Ooo % IiII - iIii1I11I1II1 % OOooOOo + I1Ii111 - i11iIiiIii
   if 91 - 91: OoooooooOO . iIii1I11I1II1 / i11iIiiIii
  if ( o0OOOoo0000 and OooOO . find ( "address = " ) != - 1 ) :
   oOOOO = OooOO . split ( "address = " ) [ 1 ]
   OoOOoo0 = int ( oOOOO . split ( "." ) [ 0 ] )
   if ( OoOOoo0 >= 224 and OoOOoo0 < 240 ) : Ii1 . append ( oOOOO )
   if 93 - 93: II111iiii * OoOoOO00 % o0oOOo0O0Ooo
   if 67 - 67: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o - i1IIi . OoOoOO00
 if ( oOOOO == [ ] ) : return
 if 12 - 12: IiII / OoO0O00 / O0 * IiII
 if 51 - 51: ooOoO0o * iII111i / i1IIi
 if 2 - 2: oO0o + IiII . iII111i - i1IIi + I1Ii111
 if 54 - 54: OoooooooOO . oO0o - iII111i
 II1i111 = commands . getoutput ( 'ifconfig eth0 | egrep "inet "' )
 if ( II1i111 == "" ) : return
 oO0o00o000Oo0 = II1i111 . split ( ) [ 1 ]
 if 1 - 1: I1IiiI - I1Ii111
 if 62 - 62: OoO0O00 . iII111i . iII111i % i1IIi * oO0o % Oo0Ooo
 if 20 - 20: ooOoO0o . IiII / I11i . OoooooooOO * OOooOOo + Ii1I
 if 2 - 2: I1IiiI
 I1i111iiIIIi = socket . inet_aton ( oO0o00o000Oo0 )
 for oOOOO in Ii1 :
  lisp_socket . setsockopt ( socket . SOL_SOCKET , socket . SO_REUSEADDR , 1 )
  lisp_socket . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_IF , I1i111iiIIIi )
  IIii1Ii = socket . inet_aton ( oOOOO ) + I1i111iiIIIi
  lisp_socket . setsockopt ( socket . IPPROTO_IP , socket . IP_ADD_MEMBERSHIP , IIii1Ii )
  lisp . lprint ( "Setting multicast listen socket for group {}" . format ( oOOOO ) )
  if 98 - 98: II111iiii + Oo0Ooo * iIii1I11I1II1 * I1ii11iIi11i + OOooOOo * Ii1I
  if 76 - 76: ooOoO0o . oO0o
 return
 if 60 - 60: OOooOOo * ooOoO0o * OoO0O00
 if 64 - 64: I11i / II111iiii / OoO0O00 - ooOoO0o * iIii1I11I1II1 . iII111i
 if 25 - 25: OOooOOo - Ii1I . I11i
 if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
III1I11II11I = int ( sys . argv [ 1 ] ) if ( len ( sys . argv ) > 1 ) else 8080
if 78 - 78: I1ii11iIi11i . I1Ii111 . I1Ii111 . I11i % iII111i
if 26 - 26: ooOoO0o + OoO0O00 / OoOoOO00 . II111iiii * Ii1I
if 21 - 21: I1IiiI - I1IiiI + iII111i % I1IiiI * oO0o
if 74 - 74: iII111i / I11i . I1IiiI - OoooooooOO + II111iiii + I11i
if ( Ii1iIIII1i ( III1I11II11I ) == False ) :
 lisp . lprint ( "lisp_core_startup() failed" )
 lisp . lisp_print_banner ( "lisp-core abnormal exit" )
 exit ( 1 )
 if 36 - 36: Ii1I * I1IiiI * I1ii11iIi11i . I11i * I1ii11iIi11i
 if 76 - 76: OOooOOo + O0 / IiII - OoO0O00
while ( True ) :
 if 27 - 27: Oo0Ooo - iIii1I11I1II1 * iII111i * II111iiii * I1ii11iIi11i
 if 9 - 9: i11iIiiIii + OOooOOo - OoOoOO00 / ooOoO0o % i1IIi / oO0o
 if 22 - 22: i1IIi
 if 3 - 3: OoO0O00 * I1ii11iIi11i - iII111i + I1ii11iIi11i
 if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
 iIii , ooo0O , oOoO0o00OO0 , Oo000 = lisp . lisp_receive ( Ii1iI , False )
 if 96 - 96: IiII
 if ( ooo0O == "" ) : break
 if 99 - 99: iIii1I11I1II1 - ooOoO0o
 if 79 - 79: I1IiiI + oO0o % I11i % oO0o
 if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
 if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
 ooo0O = lisp . lisp_convert_6to4 ( ooo0O )
 oooO0o ( Ooo , ooo0O , oOoO0o00OO0 , Oo000 )
 if 99 - 99: o0oOOo0O0Ooo + OOooOOo
 if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
I1iiII1 ( )
lisp . lisp_print_banner ( "lisp-core normal exit" )
exit ( 0 )
if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
if 76 - 76: oO0o / OoOoOO00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
