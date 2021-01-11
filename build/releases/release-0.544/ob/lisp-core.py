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
 if 38 - 38: o0oOOo0O0Ooo
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
def o0o00ooo0 ( data_structure , data ) :
 i11iIIIIIi1 = [ "site-cache" , "map-cache" , "system" , "map-resolver" ,
 "map-server" , "database-mapping" , "site-cache-summary" ]
 if 20 - 20: i1IIi + I1ii11iIi11i - ooOoO0o
 if ( data_structure not in i11iIIIIIi1 ) : return ( json . dumps ( [ ] ) )
 if 30 - 30: II111iiii - OOooOOo - i11iIiiIii % OoOoOO00 - II111iiii * Ii1I
 if 61 - 61: oO0o - I11i % OOooOOo
 if 84 - 84: oO0o * OoO0O00 / I11i - O0
 if 30 - 30: iIii1I11I1II1 / ooOoO0o - I1Ii111 - II111iiii % iII111i
 if ( data_structure == "system" ) : return ( o00O ( ) )
 if 49 - 49: I1IiiI % ooOoO0o . ooOoO0o . I11i * ooOoO0o
 if 97 - 97: Ii1I + o0oOOo0O0Ooo . OOooOOo + I1ii11iIi11i % iII111i
 if 95 - 95: i1IIi
 if 3 - 3: I1Ii111 - O0 / I1Ii111 % OoO0O00 / I1Ii111 . I1IiiI
 if ( data != "" ) : data = json . dumps ( data )
 iiI111I1iIiI = lisp . lisp_api_ipc ( "lisp-core" , data_structure + "%" + data )
 if 41 - 41: Oo0Ooo . ooOoO0o + O0 * o0oOOo0O0Ooo % Oo0Ooo * Oo0Ooo
 if ( data_structure in [ "map-cache" , "map-resolver" ] ) :
  if ( lisp . lisp_is_running ( "lisp-rtr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( iiI111I1iIiI , Oo , "lisp-rtr" )
  elif ( lisp . lisp_is_running ( "lisp-itr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( iiI111I1iIiI , Oo , "lisp-itr" )
  else :
   return ( json . dumps ( [ ] ) )
   if 19 - 19: iII111i
   if 46 - 46: I1ii11iIi11i - Ii1I . iIii1I11I1II1 / I1ii11iIi11i
 if ( data_structure in [ "map-server" , "database-mapping" ] ) :
  if ( lisp . lisp_is_running ( "lisp-etr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( iiI111I1iIiI , Oo , "lisp-etr" )
  elif ( lisp . lisp_is_running ( "lisp-itr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( iiI111I1iIiI , Oo , "lisp-itr" )
  else :
   return ( json . dumps ( [ ] ) )
   if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
   if 13 - 13: OOooOOo / i11iIiiIii
 if ( data_structure in [ "site-cache" , "site-cache-summary" ] ) :
  if ( lisp . lisp_is_running ( "lisp-ms" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( iiI111I1iIiI , Oo , "lisp-ms" )
  else :
   return ( json . dumps ( [ ] ) )
   if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
   if 52 - 52: o0oOOo0O0Ooo
   if 95 - 95: Ii1I
 lisp . lprint ( "Waiting for api get-data '{}', parmameters: '{}'" . format ( data_structure , data ) )
 if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
 oOOo0 , oo00O00oO , iIiIIIi , ooo00OOOooO = lisp . lisp_receive ( Oo , True )
 lisp . lisp_ipc_lock . release ( )
 return ( ooo00OOOooO )
 if 67 - 67: I11i * oO0o * I1ii11iIi11i + OOooOOo / i1IIi
 if 11 - 11: Ii1I + iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 if 83 - 83: I11i / I1IiiI
 if 34 - 34: IiII
 if 57 - 57: oO0o . I11i . i1IIi
 if 42 - 42: I11i + I1ii11iIi11i % O0
 if 6 - 6: oO0o
@ bottle . route ( '/lisp/api' , method = "put" )
@ bottle . route ( '/lisp/api/<command>' , method = "put" )
@ bottle . route ( '/lisp/api/<command>' , method = "delete" )
def oOOo0oOo0 ( command = "" ) :
 IIIi1i1I = [ { "?" : [ { "?" : "not-auth" } ] } ]
 if ( bottle . request . auth == None ) : return ( IIIi1i1I )
 if 49 - 49: Oo0Ooo . i11iIiiIii - i1IIi / II111iiii . I1IiiI
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
 if 92 - 92: iII111i
 if ( bottle . request . auth != None ) :
  i1iIIi1 , ii11iIi1I = bottle . request . auth
  if ( lispconfig . lisp_find_user_account ( i1iIIi1 , ii11iIi1I ) == False ) :
   return ( json . dumps ( IIIi1i1I ) )
   if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 else :
  if ( bottle . request . headers [ "User-Agent" ] . find ( "python" ) != - 1 ) :
   return ( json . dumps ( IIIi1i1I ) )
   if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
  if ( lispconfig . lisp_validate_user ( ) == False ) :
   return ( json . dumps ( IIIi1i1I ) )
   if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
   if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
   if 51 - 51: O0 + iII111i
   if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
   if 48 - 48: O0
   if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
   if 41 - 41: Ii1I - O0 - O0
 if ( command == "user-account" ) :
  if ( lispconfig . lisp_is_user_superuser ( i1iIIi1 ) == False ) :
   IIIi1i1I = [ { "user-account" : [ { "?" : "not-auth" } ] } ]
   return ( json . dumps ( IIIi1i1I ) )
   if 68 - 68: OOooOOo % I1Ii111
   if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
   if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
   if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
   if 23 - 23: O0
   if 85 - 85: Ii1I
 II = bottle . request . body . readline ( )
 if ( II == "" ) :
  IIIi1i1I = [ { "?" : [ { "?" : "no-body" } ] } ]
  return ( json . dumps ( IIIi1i1I ) )
  if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
  if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
 IIIi1i1I = json . loads ( II )
 if ( command != "" ) :
  command = "lisp " + command
 else :
  command = IIIi1i1I [ 0 ] . keys ( ) [ 0 ]
  if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
  if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
  if 77 - 77: iIii1I11I1II1 * OoO0O00
  if 95 - 95: I1IiiI + i11iIiiIii
  if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
  if 80 - 80: II111iiii
 lisp . lisp_ipc_lock . acquire ( )
 if ( bottle . request . method == "DELETE" ) :
  IIIi1i1I = lispconfig . lisp_remove_clause_for_api ( IIIi1i1I )
 else :
  IIIi1i1I = lispconfig . lisp_put_clause_for_api ( IIIi1i1I )
  if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 lisp . lisp_ipc_lock . release ( )
 return ( json . dumps ( IIIi1i1I ) )
 if 53 - 53: II111iiii
 if 31 - 31: OoO0O00
 if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: OoO0O00
 if 62 - 62: OOooOOo + O0
@ bottle . route ( '/lisp/show/api-doc' , method = "get" )
def oO0OOOO0 ( ) :
 if ( os . path . exists ( "lispapi.py" ) ) : os . system ( "pydoc lispapi > lispapi.txt" )
 if ( os . path . exists ( "lispapi.txt" ) == False ) :
  return ( "lispapi.txt file not found" )
  if 26 - 26: Ii1I
 return ( bottle . static_file ( "lispapi.txt" , root = "./" ) )
 if 35 - 35: Ii1I - I1IiiI % o0oOOo0O0Ooo . OoooooooOO % Ii1I
 if 47 - 47: iII111i - Ii1I . II111iiii + OoooooooOO . i11iIiiIii
 if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 if 87 - 87: Oo0Ooo . IiII
 if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
@ bottle . route ( '/lisp/show/command-doc' , method = "get" )
def oO ( ) :
 return ( bottle . static_file ( "lisp.config.example" , root = "./" ,
 mimetype = "text/plain" ) )
 if 31 - 31: OOooOOo + i11iIiiIii + Oo0Ooo * ooOoO0o
 if 28 - 28: O0 * Oo0Ooo - OOooOOo % iIii1I11I1II1 * Ii1I - i11iIiiIii
 if 7 - 7: Oo0Ooo + oO0o - I1Ii111 % Ii1I + I1ii11iIi11i
 if 53 - 53: i1IIi - I11i . OoOoOO00
 if 39 - 39: II111iiii / ooOoO0o + I1Ii111 / OoOoOO00
 if 13 - 13: IiII + O0 + iII111i % I1IiiI / o0oOOo0O0Ooo . IiII
 if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
@ bottle . route ( '/lisp/show/lisp-xtr' , method = "get" )
def oOOoo00O00o ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 97 - 97: O0 * OoooooooOO . OoooooooOO
  if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
  if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
  if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
  if 63 - 63: OoOoOO00 * iII111i
  if 69 - 69: O0 . OoO0O00
 if ( os . path . exists ( "./show-ztr" ) ) :
  ii1111iII = open ( "./show-ztr" , "r" ) ; iiiiI = ii1111iII . read ( ) ; ii1111iII . close ( )
 else :
  ii1111iII = open ( "./show-xtr" , "r" ) ; iiiiI = ii1111iII . read ( ) ; ii1111iII . close ( )
  if 62 - 62: OoooooooOO * I1IiiI
  if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 i1 = ""
 iiiiI = iiiiI . split ( "\n" )
 for OOoO in iiiiI :
  if ( OOoO [ 0 : 4 ] == "    " ) : i1 += lisp . lisp_space ( 4 )
  if ( OOoO [ 0 : 2 ] == "  " ) : i1 += lisp . lisp_space ( 2 )
  i1 += OOoO + "<br>"
  if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 i1 = lisp . convert_font ( i1 )
 return ( lisp . lisp_print_sans ( i1 ) )
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
 if 71 - 71: Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
@ bottle . route ( '/lisp/show/<xtr>/keys' , method = "get" )
def OOoOO0o0o0 ( xtr ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 11 - 11: I1IiiI
 I1111i = lispconfig . lisp_is_user_superuser ( None )
 if 14 - 14: OOooOOo / o0oOOo0O0Ooo
 if ( I1111i == False ) :
  ooo00OOOooO = "Permission denied"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( ooo00OOOooO ) ) )
  if 32 - 32: I1IiiI * Oo0Ooo
  if 78 - 78: OOooOOo - OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii
 if ( xtr not in [ "itr" , "etr" , "rtr" ] ) :
  ooo00OOOooO = "Invalid URL"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( ooo00OOOooO ) ) )
  if 29 - 29: I1IiiI % I1IiiI
 Oo0O0 = "show {}-keys" . format ( xtr )
 return ( lispconfig . lisp_process_show_command ( Oo , Oo0O0 ) )
 if 82 - 82: II111iiii % I11i / OoO0O00 + OoOoOO00 / o0oOOo0O0Ooo / I1Ii111
 if 70 - 70: oO0o
 if 59 - 59: o0oOOo0O0Ooo % oO0o
 if 6 - 6: iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
 if 93 - 93: IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
@ bottle . route ( '/lisp/geo-map/<geo_prefix>' )
def i1I1i111Ii ( geo_prefix ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 67 - 67: I1IiiI . i1IIi
  if 27 - 27: ooOoO0o % I1IiiI
 geo_prefix = geo_prefix . split ( "-" )
 geo_prefix = "-" . join ( geo_prefix [ 0 : - 1 ] ) + "/" + geo_prefix [ - 1 ]
 o0oooOO00 = lisp . lisp_geo ( "" )
 o0oooOO00 . parse_geo_string ( geo_prefix )
 iiIiii1IIIII , o00o = o0oooOO00 . dms_to_decimal ( )
 IIIIiiIiiI = o0oooOO00 . radius * 1000
 if 10 - 10: OoOoOO00 % OoOoOO00 - OoOoOO00 . iII111i
 o0OoOo00o0o = open ( "./lispers.net-geo.html" , "r" ) ; I1II1I11I1I = o0OoOo00o0o . read ( ) ; o0OoOo00o0o . close ( )
 I1II1I11I1I = I1II1I11I1I . replace ( "$LAT" , str ( iiIiii1IIIII ) )
 I1II1I11I1I = I1II1I11I1I . replace ( "$LON" , str ( o00o ) )
 I1II1I11I1I = I1II1I11I1I . replace ( "$RADIUS" , str ( IIIIiiIiiI ) )
 return ( I1II1I11I1I )
 if 54 - 54: OoooooooOO + o0oOOo0O0Ooo - i1IIi % i11iIiiIii
 if 3 - 3: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 83 - 83: II111iiii + I1Ii111
 if 73 - 73: iII111i
 if 42 - 42: i11iIiiIii * iIii1I11I1II1 / I1ii11iIi11i . i11iIiiIii % I11i
 if 41 - 41: IiII / O0
 if 51 - 51: I11i % I1IiiI
@ bottle . route ( '/lisp/login' , method = "get" )
def O0O00Oo ( ) :
 return ( lispconfig . lisp_login_page ( ) )
 if 60 - 60: I1IiiI / OOooOOo . I1IiiI / I1Ii111 . IiII
 if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
 if 42 - 42: Oo0Ooo
 if 76 - 76: I1IiiI * iII111i % I1Ii111
 if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
 if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
 if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
 if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
@ bottle . route ( '/lisp/login' , method = "post" )
def I11IIIi ( ) :
 if ( lispconfig . lisp_validate_user ( ) ) :
  return ( lispconfig . lisp_landing_page ( ) )
  if 15 - 15: I1ii11iIi11i * OoO0O00
 return ( O0O00Oo ( ) )
 if 16 - 16: iII111i + OoOoOO00
 if 66 - 66: iII111i / oO0o * OoooooooOO + OoooooooOO % I11i
 if 49 - 49: oO0o - i11iIiiIii . I1Ii111 * Ii1I % iII111i + i1IIi
 if 71 - 71: o0oOOo0O0Ooo
 if 38 - 38: oO0o % OoOoOO00 + I1ii11iIi11i . i11iIiiIii
 if 53 - 53: i11iIiiIii * iII111i
 if 68 - 68: iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
@ bottle . route ( '/lisp' )
def i1i11I11 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 10 - 10: O0 - OoooooooOO . OoOoOO00
 return ( lispconfig . lisp_landing_page ( ) )
 if 44 - 44: IiII - o0oOOo0O0Ooo . i1IIi . IiII * OoOoOO00
 if 5 - 5: I1Ii111
 if 90 - 90: I1Ii111 . ooOoO0o / Ii1I - I11i
 if 40 - 40: OoooooooOO
 if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
 if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
 if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
@ bottle . route ( '/lisp/traceback' )
def I1iiiiIii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 19 - 19: OoO0O00 - Oo0Ooo . O0
  if 60 - 60: II111iiii + Oo0Ooo
 I1IiIiiIiIII = True
 if 8 - 8: oO0o / I1ii11iIi11i
 if 20 - 20: I1IiiI
 if 95 - 95: iII111i - I1IiiI
 if 34 - 34: ooOoO0o * I1IiiI . i1IIi * ooOoO0o / ooOoO0o
 if ( os . path . exists ( "./logs/lisp-traceback.log" ) ) :
  ooo00OOOooO = commands . getoutput ( "cat ./logs/lisp-traceback.log" )
  if ( ooo00OOOooO ) :
   ooo00OOOooO = ooo00OOOooO . replace ( "----------" , "<b>----------</b>" )
   ooo00OOOooO = ooo00OOOooO . replace ( "\n" , "<br>" )
   I1IiIiiIiIII = False
   if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
   if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
   if 41 - 41: i1IIi - I11i - Ii1I
   if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
   if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
   if 44 - 44: II111iiii
 if ( I1IiIiiIiIII ) :
  ooo00OOOooO = ""
  OOOO0OOO = "egrep --with-filename Traceback ./logs/*.log"
  i1i1ii = commands . getoutput ( OOOO0OOO )
  i1i1ii = i1i1ii . split ( "\n" )
  for iII1ii1 in i1i1ii :
   if ( iII1ii1 . find ( ":" ) == - 1 ) : continue
   OOoO = iII1ii1 . split ( ":" )
   if ( OOoO [ 1 ] == "0" ) : continue
   ooo00OOOooO += "Found Tracebacks in log file {}<br>" . format ( OOoO [ 0 ] )
   I1IiIiiIiIII = False
   if 12 - 12: OOooOOo - ooOoO0o . OoooooooOO / I1ii11iIi11i . i1IIi * OoO0O00
  ooo00OOOooO = ooo00OOOooO [ 0 : - 4 ]
  if 19 - 19: i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
  if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
 if ( I1IiIiiIiIII ) :
  ooo00OOOooO = "No Tracebacks found - a stable system is a happy system"
  if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
  if 71 - 71: O0 - iIii1I11I1II1
 ooo00OOOooO = lisp . lisp_print_cour ( ooo00OOOooO )
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 12 - 12: OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 if 46 - 46: Oo0Ooo
 if 1 - 1: iII111i
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
@ bottle . route ( '/lisp/show/not-supported' )
def IIii11I1i1I ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 99 - 99: iII111i
 return ( lispconfig . lisp_not_supported ( ) )
 if 76 - 76: OoO0O00 * I1IiiI
 if 82 - 82: Ii1I * iII111i / I1ii11iIi11i
 if 36 - 36: OoooooooOO - i1IIi . O0 / II111iiii + o0oOOo0O0Ooo
 if 33 - 33: II111iiii / ooOoO0o * O0 % Ii1I * I1Ii111
 if 100 - 100: IiII . I11i / Ii1I % OoOoOO00 % II111iiii - OoO0O00
 if 46 - 46: O0 * II111iiii - Oo0Ooo * ooOoO0o
 if 33 - 33: Ii1I
@ bottle . route ( '/lisp/show/status' )
def OOOoOoO ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 22 - 22: I1IiiI % I1ii11iIi11i
  if 57 - 57: OOooOOo + O0 . Ii1I
  if 46 - 46: IiII
  if 45 - 45: ooOoO0o
  if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 ooo00OOOooO = ""
 I1111i = lispconfig . lisp_is_user_superuser ( None )
 if ( I1111i ) :
  i1iI1 = lisp . lisp_button ( "show configuration" , "/lisp/show/conf" )
  ii1 = lisp . lisp_button ( "show configuration diff" , "/lisp/show/diff" )
  I1IiiI1ii1i = lisp . lisp_button ( "archive configuration" , "/lisp/archive/conf" )
  O0o = lisp . lisp_button ( "clear configuration" , "/lisp/clear/conf/verify" )
  iII1ii1 = lisp . lisp_button ( "log flows" , "/lisp/log/flows" )
  oO0OoO00o = lisp . lisp_button ( "install LISP software" , "/lisp/install/image" )
  II1iiiiII = lisp . lisp_button ( "restart LISP subsystem" , "/lisp/restart/verify" )
  if 61 - 61: iII111i % I1IiiI - o0oOOo0O0Ooo - II111iiii % O0
  ooo00OOOooO = "<center>{}{}{}{}{}{}{}</center><hr>" . format ( i1iI1 , ii1 , I1IiiI1ii1i , O0o ,
 iII1ii1 , oO0OoO00o , II1iiiiII )
  if 90 - 90: iIii1I11I1II1 + I1ii11iIi11i + ooOoO0o - I1Ii111 * IiII . I1ii11iIi11i
  if 37 - 37: ooOoO0o % i11iIiiIii % II111iiii . O0 . Ii1I
 OO0oOOoo = commands . getoutput ( "uptime" )
 oOOO00o000o = commands . getoutput ( "uname -pv" )
 iIi11i1 = lisp . lisp_version . replace ( "+" , "" )
 if 71 - 71: ooOoO0o
 if 53 - 53: OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if 28 - 28: I11i
 if 58 - 58: OoOoOO00
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 oo0oOOo0 = multiprocessing . cpu_count ( )
 if 86 - 86: I11i * I1IiiI + I11i + II111iiii
 i1i111iI = OO0oOOoo . find ( ", load" )
 OO0oOOoo = OO0oOOoo [ 0 : i1i111iI ]
 IIiiI = lisp . lisp_print_elapsed ( lisp . lisp_uptime )
 if 31 - 31: I1ii11iIi11i + Ii1I + I1Ii111 / Ii1I
 iiI111 = "Not available"
 if 1 - 1: I11i * o0oOOo0O0Ooo . OoOoOO00 / O0
 if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo % O0 * O0
 if 14 - 14: I1ii11iIi11i . ooOoO0o + II111iiii / iII111i / I11i
 if 74 - 74: O0 / i1IIi
 Oo0O0 = "ps auww" if lisp . lisp_is_macos ( ) else "ps aux"
 OoO = commands . getoutput ( "{} | egrep 'PID|python lisp|python -O lisp' | egrep -v grep" . format ( Oo0O0 ) )
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 OoO = OoO . replace ( " " , lisp . space ( 1 ) )
 OoO = OoO . replace ( "\n" , "<br>" )
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if ( oOOO00o000o . find ( "Darwin" ) != - 1 ) :
  oo0oOOo0 = oo0oOOo0 / 2
  iiI111 = commands . getoutput ( "top -l 1 | head -50" )
  iiI111 = iiI111 . split ( "PID" )
  iiI111 = iiI111 [ 0 ]
  if 83 - 83: OoOoOO00 . OoooooooOO
  if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
  if 62 - 62: OoO0O00 / I1ii11iIi11i
  if 7 - 7: OoooooooOO . IiII
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
  i1i111iI = iiI111 . find ( "Load Avg" )
  Oooo00 = iiI111 [ 0 : i1i111iI ] . find ( "threads" )
  I111iIi1 = iiI111 [ 0 : Oooo00 + 7 ]
  iiI111 = I111iIi1 + "<br>" + iiI111 [ i1i111iI : : ]
  i1i111iI = iiI111 . find ( "CPU usage" )
  iiI111 = iiI111 [ 0 : i1i111iI ] + "<br>" + iiI111 [ i1i111iI : : ]
  i1i111iI = iiI111 . find ( "SharedLibs:" )
  iiI111 = iiI111 [ 0 : i1i111iI ] + "<br>" + iiI111 [ i1i111iI : : ]
  i1i111iI = iiI111 . find ( "MemRegions" )
  iiI111 = iiI111 [ 0 : i1i111iI ] + "<br>" + iiI111 [ i1i111iI : : ]
  i1i111iI = iiI111 . find ( "PhysMem" )
  iiI111 = iiI111 [ 0 : i1i111iI ] + "<br>" + iiI111 [ i1i111iI : : ]
  i1i111iI = iiI111 . find ( "VM:" )
  iiI111 = iiI111 [ 0 : i1i111iI ] + "<br>" + iiI111 [ i1i111iI : : ]
  i1i111iI = iiI111 . find ( "Networks" )
  iiI111 = iiI111 [ 0 : i1i111iI ] + "<br>" + iiI111 [ i1i111iI : : ]
  i1i111iI = iiI111 . find ( "Disks" )
  iiI111 = iiI111 [ 0 : i1i111iI ] + "<br>" + iiI111 [ i1i111iI : : ]
 else :
  if 92 - 92: ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  iiiiI = commands . getoutput ( "top -b -n 1 | head -50" )
  iiiiI = iiiiI . split ( "PID" )
  iiiiI [ 1 ] = iiiiI [ 1 ] . replace ( " " , lisp . space ( 1 ) )
  iiiiI = iiiiI [ 0 ] + iiiiI [ 1 ]
  iiI111 = iiiiI . replace ( "\n" , "<br>" )
  if 92 - 92: I11i . I1Ii111
  if 85 - 85: I1ii11iIi11i . I1Ii111
 O0O0Ooooo000 = commands . getoutput ( "cat release-notes.txt" )
 O0O0Ooooo000 = O0O0Ooooo000 . replace ( "\n" , "<br>" )
 if 65 - 65: OOooOOo * I1Ii111
 ooo00OOOooO += '''
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
        ''' . format ( iIi11i1 , lisp . lisp_version , Oo0o , IIiiI ,
 OO0oOOoo , lisp . lisp_space ( 1 ) , oo0oOOo0 , oOOO00o000o , OoO , iiI111 ,
 O0O0Ooooo000 )
 if 79 - 79: OoooooooOO - I1IiiI
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 69 - 69: I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
@ bottle . route ( '/lisp/show/conf' )
def iI1iIIIi1i ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 89 - 89: iIii1I11I1II1
 return ( bottle . static_file ( "lisp.config" , root = "./" , mimetype = "text/plain" ) )
 if 21 - 21: I11i % I11i
 if 27 - 27: i11iIiiIii / I1ii11iIi11i
 if 84 - 84: Oo0Ooo
 if 43 - 43: oO0o - OoooooooOO
 if 3 - 3: O0 / iII111i
 if 31 - 31: OOooOOo + o0oOOo0O0Ooo . OoooooooOO
 if 89 - 89: II111iiii + i1IIi + II111iiii
@ bottle . route ( '/lisp/show/diff' )
def IiII1II11I ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 54 - 54: IiII + O0 + I11i * I1Ii111 - OOooOOo % oO0o
 return ( bottle . static_file ( "lisp.config.diff" , root = "./" ,
 mimetype = "text/plain" ) )
 if 13 - 13: ooOoO0o / iII111i * OoO0O00 . OoO0O00 * ooOoO0o
 if 63 - 63: I1Ii111 / O0 * Oo0Ooo + II111iiii / IiII + Ii1I
 if 63 - 63: OoO0O00 + I1ii11iIi11i . I1Ii111 % I1Ii111
 if 57 - 57: II111iiii
 if 54 - 54: Oo0Ooo + oO0o + i11iIiiIii
 if 28 - 28: oO0o
 if 70 - 70: IiII
@ bottle . route ( '/lisp/archive/conf' )
def i11i1iiI1i ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 87 - 87: ooOoO0o
  if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 lisp . lisp_ipc_lock . acquire ( )
 os . system ( "cp ./lisp.config ./lisp.config.archive" )
 lisp . lisp_ipc_lock . release ( )
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
 ooo00OOOooO = "Configuration file saved to "
 ooo00OOOooO = lisp . lisp_print_sans ( ooo00OOOooO )
 ooo00OOOooO += lisp . lisp_print_cour ( "./lisp.config.archive" )
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
 if 13 - 13: Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
@ bottle . route ( '/lisp/clear/conf' )
def iI11I ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
  if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 os . system ( "cp ./lisp.config ./lisp.config.before-clear" )
 lisp . lisp_ipc_lock . acquire ( )
 O0O0oOOo0O ( )
 lisp . lisp_ipc_lock . release ( )
 if 19 - 19: o0oOOo0O0Ooo / I1Ii111 % o0oOOo0O0Ooo % iII111i * IiII
 ooo00OOOooO = "Configuration cleared, a backup copy is stored in "
 ooo00OOOooO = lisp . lisp_print_sans ( ooo00OOOooO )
 ooo00OOOooO += lisp . lisp_print_cour ( "./lisp.config.before-clear" )
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 19 - 19: iIii1I11I1II1
 if 26 - 26: OoooooooOO % I1IiiI % Oo0Ooo . I1IiiI % Ii1I
 if 34 - 34: IiII / OoOoOO00
 if 87 - 87: O0 * o0oOOo0O0Ooo * Oo0Ooo * II111iiii
 if 6 - 6: i1IIi . I1ii11iIi11i + OoOoOO00 * I11i / OoOoOO00 % oO0o
 if 18 - 18: II111iiii . OoooooooOO % OoOoOO00 % Ii1I
 if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
@ bottle . route ( '/lisp/clear/conf/verify' )
def ii1Ii1IiIIi ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 83 - 83: I11i / I1ii11iIi11i
  if 34 - 34: I1IiiI * Oo0Ooo * I1Ii111 / OoO0O00 * I11i / iIii1I11I1II1
 ooo00OOOooO = "<br>Are you sure you want to clear the configuration?"
 ooo00OOOooO = lisp . lisp_print_sans ( ooo00OOOooO )
 if 74 - 74: Oo0Ooo / i11iIiiIii - II111iiii * o0oOOo0O0Ooo
 IIi1IIIIi = lisp . lisp_button ( "yes" , "/lisp/clear/conf" )
 OOOoO = lisp . lisp_button ( "cancel" , "/lisp" )
 ooo00OOOooO += IIi1IIIIi + OOOoO + "<br>"
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 14 - 14: I11i . iIii1I11I1II1 . OoooooooOO . II111iiii / o0oOOo0O0Ooo
 if 21 - 21: i11iIiiIii / i1IIi + I1IiiI * OOooOOo . I1Ii111
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 if 47 - 47: OoooooooOO
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 if 82 - 82: ooOoO0o + II111iiii
 if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
 if 68 - 68: Oo0Ooo + i11iIiiIii
def Oo0oOooo000OO ( ) :
 iIiIIIi = ""
 if 98 - 98: o0oOOo0O0Ooo + O0 % i1IIi - OOooOOo + Oo0Ooo
 for OoOo000oOo0oo in [ "443" , "-8080" , "8080" ] :
  oO0O = 'ps auxww | egrep "lisp-core.pyo {}" | egrep -v grep' . format ( OoOo000oOo0oo )
  ooo00OOOooO = commands . getoutput ( oO0O )
  if ( ooo00OOOooO == "" ) : continue
  if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
  ooo00OOOooO = ooo00OOOooO . split ( "\n" ) [ 0 ]
  ooo00OOOooO = ooo00OOOooO . split ( " " )
  if ( ooo00OOOooO [ - 2 ] == "lisp-core.pyo" and ooo00OOOooO [ - 1 ] == OoOo000oOo0oo ) : iIiIIIi = OoOo000oOo0oo
  break
  if 56 - 56: O0
 return ( iIiIIIi )
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
 if 23 - 23: oO0o - OOooOOo + I11i
 if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
 if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
 if 11 - 11: iII111i * Ii1I - OoOoOO00
 if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
 if 74 - 74: Oo0Ooo
@ bottle . route ( '/lisp/restart' )
def OO000o00 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 46 - 46: OoO0O00
  if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
  if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
  if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
  if 68 - 68: OoooooooOO % II111iiii
  if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 OOoO = commands . getoutput ( "egrep requiretty /etc/sudoers" ) . split ( " " )
 if ( OOoO [ - 1 ] == "requiretty" and OOoO [ 0 ] == "Defaults" ) :
  ooo00OOOooO = "Need to remove 'requiretty' from /etc/sudoers"
  ooo00OOOooO = lisp . lisp_print_sans ( ooo00OOOooO )
  return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
  if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
  if 2 - 2: Ii1I - IiII
 lisp . lprint ( lisp . bold ( "LISP subsystem restart request received" , False ) )
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 iIiIIIi = Oo0oOooo000OO ( )
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
 oO0O = "sleep 1; sudo ./RESTART-LISP {}" . format ( iIiIIIi )
 thread . start_new_thread ( os . system , ( oO0O , ) )
 if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 ooo00OOOooO = lisp . lisp_print_sans ( "Restarting LISP subsystem ..." )
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
 if 34 - 34: O0
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
 if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
@ bottle . route ( '/lisp/restart/verify' )
def oOOoo0 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 20 - 20: IiII % IiII
  if 94 - 94: o0oOOo0O0Ooo + O0 / I11i . I1IiiI + OOooOOo . iIii1I11I1II1
 ooo00OOOooO = "<br>Are you sure you want to restart the LISP subsystem?"
 ooo00OOOooO = lisp . lisp_print_sans ( ooo00OOOooO )
 if 62 - 62: OoOoOO00 / I1IiiI - I1ii11iIi11i - I1IiiI + i11iIiiIii + i1IIi
 IIi1IIIIi = lisp . lisp_button ( "yes" , "/lisp/restart" )
 OOOoO = lisp . lisp_button ( "cancel" , "/lisp" )
 ooo00OOOooO += IIi1IIIIi + OOOoO + "<br>"
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 if 8 - 8: o0oOOo0O0Ooo
 if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
 if 78 - 78: Ii1I / II111iiii % OoOoOO00
 if 52 - 52: OOooOOo - iII111i * oO0o
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
@ bottle . route ( '/lisp/install' , method = "post" )
def iiIii1I ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 47 - 47: ooOoO0o . I11i / o0oOOo0O0Ooo
  if 83 - 83: o0oOOo0O0Ooo / OOooOOo / OOooOOo + o0oOOo0O0Ooo * I1Ii111 + o0oOOo0O0Ooo
 IIIIiii = bottle . request . forms . get ( "image_url" )
 if ( IIIIiii . find ( "lispers.net" ) == - 1 or IIIIiii . find ( ".tgz" ) == - 1 ) :
  oO0oIIIii1iiIi = "Invalid install request for file {}" . format ( IIIIiii )
  lisp . lprint ( lisp . bold ( oO0oIIIii1iiIi , False ) )
  ooo00OOOooO = lisp . lisp_print_sans ( "Invalid lispers.net tarball file name" )
  return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
  if 63 - 63: I1ii11iIi11i
  if 6 - 6: ooOoO0o / I1ii11iIi11i
 if ( lisp . lisp_is_ubuntu ( ) ) :
  oO0O = "python lisp-get-bits.pyo {} force 2>&1 > /dev/null" . format ( IIIIiii )
 else :
  oO0O = "python lisp-get-bits.pyo {} force >& /dev/null" . format ( IIIIiii )
  if 57 - 57: I11i
 OoO = os . system ( oO0O )
 if 67 - 67: OoO0O00 . ooOoO0o
 oO00oOo0OOO = IIIIiii . split ( "/" ) [ - 1 ]
 if 23 - 23: i1IIi . o0oOOo0O0Ooo * OoO0O00
 if ( os . path . exists ( oO00oOo0OOO ) ) :
  iIi1IiI = IIIIiii . split ( "release-" ) [ 1 ]
  iIi1IiI = iIi1IiI . split ( ".tgz" ) [ 0 ]
  if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
  ooo00OOOooO = "Install completed for release {}" . format ( iIi1IiI )
  ooo00OOOooO = lisp . lisp_print_sans ( ooo00OOOooO )
  if 53 - 53: Ii1I % Oo0Ooo
  ooo00OOOooO += "<br><br>" + lisp . lisp_button ( "restart LISP subsystem" ,
 "/lisp/restart/verify" ) + "<br>"
 else :
  oO0oIIIii1iiIi = lisp . lisp_print_cour ( IIIIiii )
  ooo00OOOooO = "Install failed for file {}" . format ( oO0oIIIii1iiIi )
  ooo00OOOooO = lisp . lisp_print_sans ( ooo00OOOooO )
  if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
  if 41 - 41: Ii1I % I1ii11iIi11i
 oO0oIIIii1iiIi = "Install request for file {} {}" . format ( IIIIiii ,
 "succeeded" if ( OoO == 0 ) else "failed" )
 lisp . lprint ( lisp . bold ( oO0oIIIii1iiIi , False ) )
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 12 - 12: OOooOOo
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
@ bottle . route ( '/lisp/install/image' )
def O0O00OOo ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 66 - 66: i11iIiiIii / o0oOOo0O0Ooo - OoooooooOO / i1IIi . i11iIiiIii
  if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
 oO0oIIIii1iiIi = lisp . lisp_print_sans ( "<br>Enter lispers.net tarball URL:" )
 ooo00OOOooO = '''
        <form action="/lisp/install" method="post" style="display: inline;">
        {}
        <input type="text" name="image_url" size="75" required/>
        <input type="submit" style="background-color:transparent;border-radius:10px;" value="Submit" />
        </form><br>''' . format ( oO0oIIIii1iiIi )
 if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 81 - 81: iII111i * OOooOOo - I1ii11iIi11i * Ii1I % OoOoOO00 * OoOoOO00
 if 59 - 59: iIii1I11I1II1
 if 7 - 7: OOooOOo * I1IiiI / o0oOOo0O0Ooo * i11iIiiIii
 if 84 - 84: OOooOOo . iII111i
 if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
 if 21 - 21: oO0o / OoooooooOO
 if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
 if 87 - 87: I1Ii111 * i1IIi / I1ii11iIi11i
@ bottle . route ( '/lisp/log/flows' )
def IIII1i1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 70 - 70: i11iIiiIii % I1ii11iIi11i / I1IiiI
  if 62 - 62: i1IIi - OoOoOO00
 os . system ( "touch ./log-flows" )
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 ooo00OOOooO = lisp . lisp_print_sans ( "Flow data appended to file " )
 iIi = "<a href='/lisp/show/log/lisp-flow/100'>logs/lisp-flows.log</a>"
 ooo00OOOooO += lisp . lisp_print_cour ( iIi )
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 10 - 10: OoO0O00 / Oo0Ooo
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
 if 57 - 57: O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
@ bottle . route ( '/lisp/search/log/<name>/<num>/<keyword>' )
def iII1Iii1I11i ( name = "" , num = "" , keyword = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 17 - 17: O0
  if 88 - 88: Oo0Ooo . O0 % OoooooooOO / OOooOOo
 Oo0O0 = "tail -n {} logs/{}.log | egrep -B10 -A10 {}" . format ( num , name ,
 keyword )
 ooo00OOOooO = commands . getoutput ( Oo0O0 )
 if 89 - 89: II111iiii / oO0o
 if ( ooo00OOOooO ) :
  IIo0OoO00 = ooo00OOOooO . count ( keyword )
  ooo00OOOooO = lisp . convert_font ( ooo00OOOooO )
  ooo00OOOooO = ooo00OOOooO . replace ( "--\n--\n" , "--\n" )
  ooo00OOOooO = ooo00OOOooO . replace ( "\n" , "<br>" )
  ooo00OOOooO = ooo00OOOooO . replace ( "--<br>" , "<hr>" )
  ooo00OOOooO = "Found <b>{}</b> occurences<hr>" . format ( IIo0OoO00 ) + ooo00OOOooO
 else :
  ooo00OOOooO = "Keyword {} not found" . format ( keyword )
  if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
  if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
  if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
  if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
  if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 iI = "<font color='blue'><b>{}</b>" . format ( keyword )
 ooo00OOOooO = ooo00OOOooO . replace ( keyword , iI )
 ooo00OOOooO = ooo00OOOooO . replace ( keyword , keyword + "</font>" )
 if 19 - 19: II111iiii
 ooo00OOOooO = lisp . lisp_print_cour ( ooo00OOOooO )
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
@ bottle . post ( '/lisp/search/log/<name>/<num>' )
def IIIiiiI ( name = "" , num = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 94 - 94: O0 - I11i - iIii1I11I1II1 % ooOoO0o / Ii1I % iII111i
  if 44 - 44: Oo0Ooo % iIii1I11I1II1
 oo0ooO0 = bottle . request . forms . get ( "keyword" )
 return ( iII1Iii1I11i ( name , num , oo0ooO0 ) )
 if 28 - 28: I1ii11iIi11i * OoooooooOO . II111iiii / i11iIiiIii + oO0o
 if 38 - 38: IiII . Ii1I
 if 24 - 24: o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
 if 12 - 12: iII111i . IiII . OoOoOO00 / O0
 if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
 if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
@ bottle . route ( '/lisp/show/log/<name>/<num>' )
def OOoOIiIIII ( name = "" , num = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 89 - 89: OoO0O00 / I1IiiI
  if 16 - 16: Oo0Ooo + ooOoO0o / Oo0Ooo / OoO0O00 % oO0o % I1ii11iIi11i
  if 22 - 22: II111iiii * OoO0O00 * I11i + I1ii11iIi11i * o0oOOo0O0Ooo
  if 100 - 100: i1IIi / IiII
  if 3 - 3: II111iiii % I1ii11iIi11i - OoooooooOO * Oo0Ooo . iIii1I11I1II1
 if ( num == "" ) : num = 100
 if 37 - 37: iII111i / Oo0Ooo . I11i * I11i
 o0O0Oo0Ooo0 = '''
        <form action="/lisp/search/log/{}/{}" method="post">
        <i>Keyword search:</i>
        <input type="text" name="keyword" />
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </form><hr>
    ''' . format ( name , num )
 if 35 - 35: IiII + i1IIi * oO0o - Ii1I . Oo0Ooo
 if ( os . path . exists ( "logs/{}.log" . format ( name ) ) ) :
  ooo00OOOooO = commands . getoutput ( "tail -n {} logs/{}.log" . format ( num , name ) )
  ooo00OOOooO = lisp . convert_font ( ooo00OOOooO )
  ooo00OOOooO = ooo00OOOooO . replace ( "\n" , "<br>" )
  ooo00OOOooO = o0O0Oo0Ooo0 + lisp . lisp_print_cour ( ooo00OOOooO )
 else :
  iiIii1II = lisp . lisp_print_sans ( "File" )
  OoOo = lisp . lisp_print_cour ( "logs/{}.log" . format ( name ) )
  IIIiiIIIiI1ii = lisp . lisp_print_sans ( "does not exist" )
  ooo00OOOooO = "{} {} {}" . format ( iiIii1II , OoOo , IIIiiIIIiI1ii )
  if 78 - 78: O0 * OOooOOo
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 43 - 43: I1ii11iIi11i / I1IiiI . ooOoO0o
 if 62 - 62: iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % O0 . I1Ii111
 if 93 - 93: i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / o0oOOo0O0Ooo / II111iiii
 if 49 - 49: OOooOOo . I1ii11iIi11i . i11iIiiIii - II111iiii / Ii1I
 if 62 - 62: OOooOOo
 if 1 - 1: IiII / IiII - i11iIiiIii
 if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
@ bottle . route ( '/lisp/debug/<name>' )
def I1iiIII ( name = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
  if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
  if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
  if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
  if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
 if ( name == "disable%all" ) :
  IIIi1i1I = lispconfig . lisp_get_clause_for_api ( "lisp debug" )
  if ( IIIi1i1I [ 0 ] . has_key ( "lisp debug" ) ) :
   i1 = [ ]
   for OOO000 in IIIi1i1I [ 0 ] [ "lisp debug" ] :
    Ii1 = OOO000 . keys ( ) [ 0 ]
    i1 . append ( { Ii1 : "no" } )
    if 62 - 62: i1IIi - i1IIi
   i1 = { "lisp debug" : i1 }
   lispconfig . lisp_put_clause_for_api ( i1 )
   if 69 - 69: OoOoOO00 % oO0o - I11i
   if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
  IIIi1i1I = lispconfig . lisp_get_clause_for_api ( "lisp xtr-parameters" )
  if ( IIIi1i1I [ 0 ] . has_key ( "lisp xtr-parameters" ) ) :
   i1 = [ ]
   for OOO000 in IIIi1i1I [ 0 ] [ "lisp xtr-parameters" ] :
    Ii1 = OOO000 . keys ( ) [ 0 ]
    if ( Ii1 in [ "data-plane-logging" , "flow-logging" ] ) :
     i1 . append ( { Ii1 : "no" } )
    else :
     i1 . append ( { Ii1 : OOO000 [ Ii1 ] } )
     if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
     if 62 - 62: o0oOOo0O0Ooo - Ii1I * OoOoOO00 - i11iIiiIii % ooOoO0o
   i1 = { "lisp xtr-parameters" : i1 }
   lispconfig . lisp_put_clause_for_api ( i1 )
   if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
   if 30 - 30: iII111i / OoO0O00 + oO0o
  return ( lispconfig . lisp_landing_page ( ) )
  if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
  if 70 - 70: OoO0O00
  if 46 - 46: I11i - i1IIi
  if 46 - 46: I1Ii111 % Ii1I
  if 72 - 72: iIii1I11I1II1
 name = name . split ( "%" )
 iI1I1II1 = name [ 0 ]
 Iii111II = name [ 1 ]
 if 92 - 92: OoooooooOO - OoooooooOO * OoO0O00 % I1IiiI
 ooooOoO0O = [ "data-plane-logging" , "flow-logging" ]
 if 1 - 1: I1ii11iIi11i / OoO0O00 + oO0o . o0oOOo0O0Ooo / I1ii11iIi11i - iII111i
 ii111i1iI = "lisp xtr-parameters" if ( iI1I1II1 in ooooOoO0O ) else "lisp debug"
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 IIIi1i1I = lispconfig . lisp_get_clause_for_api ( ii111i1iI )
 if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 if ( IIIi1i1I [ 0 ] . has_key ( ii111i1iI ) ) :
  i1 = { }
  for OOO000 in IIIi1i1I [ 0 ] [ ii111i1iI ] :
   i1 [ OOO000 . keys ( ) [ 0 ] ] = OOO000 . values ( ) [ 0 ]
   if ( i1 . has_key ( iI1I1II1 ) ) : i1 [ iI1I1II1 ] = Iii111II
   if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
  i1 = { ii111i1iI : i1 }
  lispconfig . lisp_put_clause_for_api ( i1 )
  if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 return ( lispconfig . lisp_landing_page ( ) )
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
@ bottle . route ( '/lisp/clear/<name>' )
@ bottle . route ( '/lisp/clear/etr/<etr_name>/<stats_name>' )
@ bottle . route ( '/lisp/clear/rtr/<rtr_name>/<stats_name>' )
@ bottle . route ( '/lisp/clear/itr/<itr_name>' )
@ bottle . route ( '/lisp/clear/rtr/<rtr_name>' )
def i1iii11 ( name = "" , itr_name = '' , rtr_name = "" , etr_name = "" ,
 stats_name = "" ) :
 if 92 - 92: OoOoOO00 . OoooooooOO - I1Ii111
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 74 - 74: iIii1I11I1II1 % iII111i * OOooOOo * iIii1I11I1II1
  if 73 - 73: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
  if 60 - 60: OoOoOO00
  if 5 - 5: I1IiiI - I1IiiI - I1IiiI * OoooooooOO
  if 28 - 28: iIii1I11I1II1 + iIii1I11I1II1
 if ( lispconfig . lisp_is_user_superuser ( None ) == False ) :
  ooo00OOOooO = lisp . lisp_print_sans ( "Not authorized" )
  return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
  if 28 - 28: oO0o
  if 52 - 52: I1IiiI + iIii1I11I1II1
 iiI111I1iIiI = "clear"
 if ( name == "referral" ) :
  ooOO = "lisp-mr"
  i1iiIiI = "Referral"
 elif ( itr_name == "map-cache" ) :
  ooOO = "lisp-itr"
  i1iiIiI = "ITR <a href='/lisp/show/itr/map-cache'>map-cache</a>"
 elif ( rtr_name == "map-cache" ) :
  ooOO = "lisp-rtr"
  i1iiIiI = "RTR <a href='/lisp/show/rtr/map-cache'>map-cache</a>"
 elif ( etr_name == "stats" ) :
  ooOO = "lisp-etr"
  i1iiIiI = ( "ETR '{}' decapsulation <a href='/lisp/show/" + "database'>stats</a>" ) . format ( stats_name )
  if 60 - 60: oO0o % iII111i / OOooOOo % ooOoO0o - OoOoOO00 % iIii1I11I1II1
  iiI111I1iIiI += "%" + stats_name
 elif ( rtr_name == "stats" ) :
  ooOO = "lisp-rtr"
  i1iiIiI = ( "RTR '{}' decapsulation <a href='/lisp/show/" + "rtr/map-cache'>stats</a>" ) . format ( stats_name )
  if 82 - 82: OoOoOO00 + I11i % i1IIi + IiII / I1Ii111 - Oo0Ooo
  iiI111I1iIiI += "%" + stats_name
 else :
  ooo00OOOooO = lisp . lisp_print_sans ( "Invalid command" )
  return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
  if 70 - 70: IiII % i11iIiiIii + Oo0Ooo + OoOoOO00
  if 18 - 18: iIii1I11I1II1 - iII111i . I1IiiI % Ii1I - o0oOOo0O0Ooo
  if 41 - 41: o0oOOo0O0Ooo - Oo0Ooo * I1IiiI
  if 82 - 82: OoO0O00 % o0oOOo0O0Ooo % OOooOOo / O0
  if 94 - 94: I1ii11iIi11i + I1ii11iIi11i + OoooooooOO % ooOoO0o
 iiI111I1iIiI = lisp . lisp_command_ipc ( iiI111I1iIiI , "lisp-core" )
 lisp . lisp_ipc ( iiI111I1iIiI , Oo , ooOO )
 if 7 - 7: iII111i
 if 78 - 78: OOooOOo + iII111i . IiII
 if 91 - 91: iIii1I11I1II1 . o0oOOo0O0Ooo . I1ii11iIi11i + OoooooooOO
 if 69 - 69: I1Ii111 - I1IiiI
 oOoo0OooOOo00 = commands . getoutput ( "egrep 'lisp map-cache' ./lisp.config" )
 if ( oOoo0OooOOo00 != "" ) :
  os . system ( "touch ./lisp.config" )
  if 36 - 36: i1IIi * Oo0Ooo % Oo0Ooo / o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
  if 39 - 39: OoooooooOO * OOooOOo * O0 . I11i . OoO0O00 + ooOoO0o
 ooo00OOOooO = lisp . lisp_print_sans ( "{} cleared" . format ( i1iiIiI ) )
 return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
 if 9 - 9: OoOoOO00 + oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
 if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
@ bottle . route ( '/lisp/show/map-server' )
def Iiii1iiiIiI1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 27 - 27: Ii1I + I1IiiI * iIii1I11I1II1 . OoooooooOO * OoOoOO00
  if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show map-server" ) )
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
@ bottle . route ( '/lisp/show/database' )
def o0O0oO0 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 77 - 77: O0 . Ii1I
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show database-mapping" ) )
 if 39 - 39: ooOoO0o . II111iiii
 if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
 if 77 - 77: I1Ii111 - I11i
 if 11 - 11: I1ii11iIi11i
 if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
 if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
 if 55 - 55: ooOoO0o
@ bottle . route ( '/lisp/show/itr/map-cache' )
def o0O0OO0o ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 54 - 54: OoOoOO00 . oO0o % i11iIiiIii / OoooooooOO + IiII % oO0o
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show itr-map-cache" ) )
 if 36 - 36: oO0o
 if 74 - 74: OoooooooOO
 if 72 - 72: O0 + I1IiiI - iII111i - OoO0O00
 if 100 - 100: O0
 if 79 - 79: iIii1I11I1II1
 if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
 if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
@ bottle . route ( '/lisp/show/itr/rloc-probing' )
def ii1I111i1Ii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 84 - 84: I1ii11iIi11i % iIii1I11I1II1 + OoO0O00 . I1ii11iIi11i % OoO0O00
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show itr-rloc-probing" ) )
 if 93 - 93: O0
 if 85 - 85: i11iIiiIii % i11iIiiIii + O0 / OOooOOo
 if 89 - 89: Ii1I % i1IIi % oO0o
 if 53 - 53: oO0o * OoooooooOO . OoOoOO00
 if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
 if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
@ bottle . post ( '/lisp/show/itr/map-cache/lookup' )
def i11i11 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 18 - 18: iIii1I11I1II1 + I11i * I1IiiI - OOooOOo / I1IiiI
  if 78 - 78: I11i . IiII
 iI1i1II = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( iI1i1II ) == False ) :
  ooo00OOOooO = "Address '{}' has invalid format" . format ( iI1i1II )
  ooo00OOOooO = lisp . lisp_print_sans ( ooo00OOOooO )
  return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
  if 14 - 14: ooOoO0o - iIii1I11I1II1 / O0 % IiII . OoOoOO00
  if 18 - 18: oO0o * oO0o % oO0o
 Oo0O0 = "show itr-map-cache" + "%" + iI1i1II
 return ( lispconfig . lisp_process_show_command ( Oo ,
 Oo0O0 ) )
 if 17 - 17: O0 * OoOoOO00 * I1ii11iIi11i * II111iiii * I11i % i1IIi
 if 33 - 33: I1ii11iIi11i * I1ii11iIi11i . ooOoO0o . i11iIiiIii
 if 48 - 48: o0oOOo0O0Ooo . Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
@ bottle . route ( '/lisp/show/rtr/map-cache' )
@ bottle . route ( '/lisp/show/rtr/map-cache/<dns>' )
def i1I1i1i ( dns = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 36 - 36: II111iiii % O0
  if 35 - 35: iIii1I11I1II1 - OOooOOo % o0oOOo0O0Ooo
 if ( dns == "dns" ) :
  return ( lispconfig . lisp_process_show_command ( Oo ,
 "show rtr-map-cache-dns" ) )
 else :
  return ( lispconfig . lisp_process_show_command ( Oo ,
 "show rtr-map-cache" ) )
  if 30 - 30: I1Ii111 % I1Ii111 % IiII . OoOoOO00
  if 9 - 9: ooOoO0o / II111iiii . OoOoOO00 % o0oOOo0O0Ooo * II111iiii - ooOoO0o
  if 55 - 55: I1IiiI
  if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
  if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
  if 79 - 79: OoOoOO00 / ooOoO0o
  if 77 - 77: Oo0Ooo
  if 46 - 46: I1Ii111
@ bottle . route ( '/lisp/show/rtr/rloc-probing' )
def o00OoooooooOo ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 32 - 32: o0oOOo0O0Ooo + I1IiiI . I1Ii111
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show rtr-rloc-probing" ) )
 if 41 - 41: OoOoOO00 . i11iIiiIii / I11i
 if 98 - 98: OoOoOO00 % II111iiii
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
 if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 if 68 - 68: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 - I1Ii111
 if 37 - 37: IiII
@ bottle . post ( '/lisp/show/rtr/map-cache/lookup' )
def iI11i ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 73 - 73: iII111i * iII111i / ooOoO0o
  if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 iI1i1II = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( iI1i1II ) == False ) :
  ooo00OOOooO = "Address '{}' has invalid format" . format ( iI1i1II )
  ooo00OOOooO = lisp . lisp_print_sans ( ooo00OOOooO )
  return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
  if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
  if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 Oo0O0 = "show rtr-map-cache" + "%" + iI1i1II
 return ( lispconfig . lisp_process_show_command ( Oo ,
 Oo0O0 ) )
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 if 83 - 83: o0oOOo0O0Ooo
@ bottle . route ( '/lisp/show/referral' )
def i1iiii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show referral-cache" ) )
 if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
 if 71 - 71: iII111i
 if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
 if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
 if 58 - 58: I1ii11iIi11i
 if 2 - 2: II111iiii / I1Ii111
@ bottle . post ( '/lisp/show/referral/lookup' )
def OoOoO0oOOooo ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 99 - 99: iIii1I11I1II1
  if 14 - 14: I1ii11iIi11i % I1IiiI . II111iiii . I1IiiI - ooOoO0o
 iI1i1II = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( iI1i1II ) == False ) :
  ooo00OOOooO = "Address '{}' has invalid format" . format ( iI1i1II )
  ooo00OOOooO = lisp . lisp_print_sans ( ooo00OOOooO )
  return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
  if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
  if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 Oo0O0 = "show referral-cache" + "%" + iI1i1II
 return ( lispconfig . lisp_process_show_command ( Oo , Oo0O0 ) )
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 if 68 - 68: oO0o
 if 10 - 10: Ii1I
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
@ bottle . route ( '/lisp/show/delegations' )
def IiIIiI ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 87 - 87: OoOoOO00 % iIii1I11I1II1
 return ( lispconfig . lisp_process_show_command ( Oo ,
 "show delegations" ) )
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
@ bottle . post ( '/lisp/show/delegations/lookup' )
def i1iIi1IIiIII1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 19 - 19: I11i
  if 87 - 87: ooOoO0o / OoOoOO00 % o0oOOo0O0Ooo * oO0o
 iI1i1II = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( iI1i1II ) == False ) :
  ooo00OOOooO = "Address '{}' has invalid format" . format ( iI1i1II )
  ooo00OOOooO = lisp . lisp_print_sans ( ooo00OOOooO )
  return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
  if 77 - 77: oO0o - Oo0Ooo - iIii1I11I1II1
  if 16 - 16: OoO0O00 / iII111i / i1IIi . iII111i + oO0o
 Oo0O0 = "show delegations" + "%" + iI1i1II
 return ( lispconfig . lisp_process_show_command ( Oo , Oo0O0 ) )
 if 26 - 26: iIii1I11I1II1 + i1IIi / OoOoOO00 % I1ii11iIi11i
 if 44 - 44: OoooooooOO . II111iiii . OOooOOo % OoooooooOO
 if 86 - 86: i11iIiiIii + O0 * IiII - OoO0O00 * OOooOOo + O0
 if 95 - 95: iIii1I11I1II1 . I1Ii111 % iII111i - I1Ii111 * II111iiii
 if 89 - 89: iII111i . I1IiiI
 if 59 - 59: i1IIi % iIii1I11I1II1 + OoooooooOO
 if 97 - 97: I1ii11iIi11i / Oo0Ooo + I1Ii111
 if 32 - 32: ooOoO0o % I1Ii111 * Oo0Ooo
 if 72 - 72: ooOoO0o . iII111i - I1Ii111 - Ii1I % i1IIi
@ bottle . route ( '/lisp/show/site' )
@ bottle . route ( '/lisp/show/site/<eid_prefix>' )
def oO0o00O0O0oo0 ( eid_prefix = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 24 - 24: I1Ii111 * oO0o
  if 88 - 88: i11iIiiIii + iII111i * OoOoOO00 * iII111i + I11i
 Oo0O0 = "show site"
 if 88 - 88: OOooOOo % Oo0Ooo - iII111i - OoOoOO00 % i11iIiiIii
 if ( eid_prefix != "" ) :
  Oo0O0 = lispconfig . lisp_parse_eid_in_url ( Oo0O0 , eid_prefix )
  if 6 - 6: Ii1I - OoO0O00 . I1IiiI - O0
 return ( lispconfig . lisp_process_show_command ( Oo , Oo0O0 ) )
 if 16 - 16: iII111i * iII111i % Ii1I % I1IiiI
 if 48 - 48: OOooOOo / Ii1I % OoO0O00 / IiII / I1Ii111
 if 89 - 89: I1Ii111 * oO0o
 if 63 - 63: OoooooooOO * OoooooooOO % OoO0O00 + O0 / I1Ii111 + iIii1I11I1II1
 if 72 - 72: OoOoOO00 * iIii1I11I1II1 % I11i
 if 20 - 20: II111iiii % iIii1I11I1II1 + oO0o * II111iiii * OoO0O00 % OoO0O00
 if 15 - 15: oO0o / I1Ii111
@ bottle . route ( '/lisp/show/itr/dynamic-eid/<eid_prefix>' )
def Iiii111 ( eid_prefix = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 71 - 71: O0 / I1IiiI . I1Ii111 / I1Ii111 * ooOoO0o
  if 60 - 60: II111iiii . I1IiiI - Oo0Ooo + I1ii11iIi11i * I1ii11iIi11i
 Oo0O0 = "show itr-dynamic-eid"
 if 27 - 27: IiII * I1IiiI . iIii1I11I1II1 - iIii1I11I1II1
 if ( eid_prefix != "" ) :
  Oo0O0 = lispconfig . lisp_parse_eid_in_url ( Oo0O0 , eid_prefix )
  if 5 - 5: IiII
 return ( lispconfig . lisp_process_show_command ( Oo , Oo0O0 ) )
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
@ bottle . route ( '/lisp/show/etr/dynamic-eid/<eid_prefix>' )
def o00oo0OO0 ( eid_prefix = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 60 - 60: ooOoO0o
  if 66 - 66: I11i / ooOoO0o % i1IIi - oO0o . O0 / O0
 Oo0O0 = "show etr-dynamic-eid"
 if 96 - 96: OoooooooOO + IiII * O0
 if ( eid_prefix != "" ) :
  Oo0O0 = lispconfig . lisp_parse_eid_in_url ( Oo0O0 , eid_prefix )
  if 86 - 86: Ii1I
 return ( lispconfig . lisp_process_show_command ( Oo , Oo0O0 ) )
 if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if 69 - 69: OoOoOO00
 if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
@ bottle . post ( '/lisp/show/site/lookup' )
def i1I1Ii11i ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 19 - 19: IiII - o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00 / OOooOOo
  if 87 - 87: OoOoOO00 - ooOoO0o - OOooOOo + Oo0Ooo % iIii1I11I1II1 / i11iIiiIii
 iI1i1II = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( iI1i1II ) == False ) :
  ooo00OOOooO = "Address '{}' has invalid format" . format ( iI1i1II )
  ooo00OOOooO = lisp . lisp_print_sans ( ooo00OOOooO )
  return ( lispconfig . lisp_show_wrapper ( ooo00OOOooO ) )
  if 12 - 12: ooOoO0o
  if 86 - 86: oO0o - OoO0O00
 Oo0O0 = "show site" + "%" + iI1i1II + "@lookup"
 return ( lispconfig . lisp_process_show_command ( Oo , Oo0O0 ) )
 if 63 - 63: I1IiiI / OoOoOO00 + OoooooooOO . I11i . ooOoO0o
 if 48 - 48: i1IIi - iII111i - i11iIiiIii . I11i - iII111i * I11i
 if 60 - 60: OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
@ bottle . post ( '/lisp/lig' )
def Iiii1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 36 - 36: iII111i
  if 90 - 90: O0
 Iii = bottle . request . forms . get ( "eid" )
 i1iI111II1ii = bottle . request . forms . get ( "mr" )
 O0ooO00ooOO0o = bottle . request . forms . get ( "count" )
 o0O = "no-info" if bottle . request . forms . get ( "no-nat" ) == "yes" else ""
 if 42 - 42: iII111i / o0oOOo0O0Ooo + Oo0Ooo . Oo0Ooo % OOooOOo
 if 16 - 16: i1IIi + OoO0O00 % OoOoOO00 + Ii1I * Oo0Ooo
 if 3 - 3: i11iIiiIii
 if 81 - 81: I1IiiI . OoooooooOO * Ii1I . oO0o - O0 * oO0o
 if ( i1iI111II1ii == "" ) : i1iI111II1ii = "localhost"
 if 72 - 72: II111iiii - OOooOOo + I1IiiI - I11i
 if 91 - 91: II111iiii
 if 53 - 53: OoO0O00 % o0oOOo0O0Ooo / OOooOOo % IiII % OoO0O00 % OoooooooOO
 if 31 - 31: I1IiiI
 if ( Iii == "" ) :
  ooo00OOOooO = "Need to supply EID address"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( ooo00OOOooO ) ) )
  if 73 - 73: ooOoO0o . O0 / o0oOOo0O0Ooo - OoooooooOO % i11iIiiIii
  if 80 - 80: Ii1I / ooOoO0o % O0 . Oo0Ooo
 oOiI111I1III = ""
 if os . path . exists ( "lisp-lig.pyo" ) : oOiI111I1III = "-O lisp-lig.pyo"
 if os . path . exists ( "lisp-lig.py" ) : oOiI111I1III = "lisp-lig.py"
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if ( oOiI111I1III == "" ) :
  ooo00OOOooO = "Cannot find lisp-lig.py or lisp-lig.pyo"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( ooo00OOOooO ) ) )
  if 40 - 40: OoO0O00 + OoO0O00
  if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if ( O0ooO00ooOO0o != "" ) : O0ooO00ooOO0o = "count {}" . format ( O0ooO00ooOO0o )
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 Oo0O0 = 'python {} "{}" to {} {} {}' . format ( oOiI111I1III , Iii , i1iI111II1ii , O0ooO00ooOO0o , o0O )
 if 41 - 41: I1ii11iIi11i
 ooo00OOOooO = commands . getoutput ( Oo0O0 )
 ooo00OOOooO = ooo00OOOooO . replace ( "\n" , "<br>" )
 ooo00OOOooO = lisp . convert_font ( ooo00OOOooO )
 if 5 - 5: Oo0Ooo
 o0oOo00 = lisp . space ( 2 ) + "RLOC:"
 ooo00OOOooO = ooo00OOOooO . replace ( "RLOC:" , o0oOo00 )
 IiI1III = lisp . space ( 2 ) + "Empty,"
 ooo00OOOooO = ooo00OOOooO . replace ( "Empty," , IiI1III )
 o0oooOO00 = lisp . space ( 4 ) + "geo:"
 ooo00OOOooO = ooo00OOOooO . replace ( "geo:" , o0oooOO00 )
 O0O0OOO = lisp . space ( 4 ) + "elp:"
 ooo00OOOooO = ooo00OOOooO . replace ( "elp:" , O0O0OOO )
 I1IIi = lisp . space ( 4 ) + "rle:"
 ooo00OOOooO = ooo00OOOooO . replace ( "rle:" , I1IIi )
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( ooo00OOOooO ) ) )
 if 40 - 40: IiII * oO0o % I11i * I1ii11iIi11i
 if 80 - 80: iIii1I11I1II1 - OoooooooOO - I1ii11iIi11i - I1ii11iIi11i . OoooooooOO
 if 48 - 48: I1Ii111 . i11iIiiIii / i1IIi % IiII % iII111i + oO0o
 if 41 - 41: IiII
 if 3 - 3: IiII + II111iiii / iIii1I11I1II1
 if 10 - 10: II111iiii . O0
 if 31 - 31: oO0o / i11iIiiIii / O0
@ bottle . post ( '/lisp/rig' )
def iiI1ii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
  if 49 - 49: IiII / ooOoO0o / OOooOOo
 Iii = bottle . request . forms . get ( "eid" )
 IiIiIi1I11I = bottle . request . forms . get ( "ddt" )
 IiI1i1i = "follow-all-referrals" if bottle . request . forms . get ( "follow" ) == "yes" else ""
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if ( IiIiIi1I11I == "" ) : IiIiIi1I11I = "localhost"
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if ( Iii == "" ) :
  ooo00OOOooO = "Need to supply EID address"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( ooo00OOOooO ) ) )
  if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
  if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 I1IiII1I1i1I1 = ""
 if os . path . exists ( "lisp-rig.pyo" ) : I1IiII1I1i1I1 = "-O lisp-rig.pyo"
 if os . path . exists ( "lisp-rig.py" ) : I1IiII1I1i1I1 = "lisp-rig.py"
 if 28 - 28: Oo0Ooo + IiII % II111iiii / OoO0O00 + i11iIiiIii
 if 20 - 20: I1ii11iIi11i
 if 3 - 3: OoO0O00 * i1IIi . I1IiiI . O0 - OoOoOO00
 if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
 if ( I1IiII1I1i1I1 == "" ) :
  ooo00OOOooO = "Cannot find lisp-rig.py or lisp-rig.pyo"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( ooo00OOOooO ) ) )
  if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
  if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
 Oo0O0 = 'python {} "{}" to {} {}' . format ( I1IiII1I1i1I1 , Iii , IiIiIi1I11I , IiI1i1i )
 if 10 - 10: I1ii11iIi11i / i11iIiiIii - Ii1I + oO0o * I1IiiI
 ooo00OOOooO = commands . getoutput ( Oo0O0 )
 ooo00OOOooO = ooo00OOOooO . replace ( "\n" , "<br>" )
 ooo00OOOooO = lisp . convert_font ( ooo00OOOooO )
 if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
 o0Oo0oo = lisp . space ( 2 ) + "Referrals:"
 ooo00OOOooO = ooo00OOOooO . replace ( "Referrals:" , o0Oo0oo )
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( ooo00OOOooO ) ) )
 if 44 - 44: I1IiiI % Ii1I * I1IiiI . Oo0Ooo + I1ii11iIi11i . OOooOOo
 if 6 - 6: IiII * OoooooooOO + I1Ii111 / Ii1I
 if 35 - 35: ooOoO0o % I1IiiI - ooOoO0o - OoO0O00 - OoooooooOO
 if 46 - 46: i1IIi . i1IIi . oO0o / I11i / ooOoO0o
 if 34 - 34: OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
def oOIii11111iiI ( eid1 , eid2 ) :
 oOiI111I1III = None
 if os . path . exists ( "lisp-lig.pyo" ) : oOiI111I1III = "-O lisp-lig.pyo"
 if os . path . exists ( "lisp-lig.py" ) : oOiI111I1III = "lisp-lig.py"
 if ( oOiI111I1III == None ) : return ( [ None , None ] )
 if 67 - 67: o0oOOo0O0Ooo
 if 76 - 76: OoOoOO00 - I1IiiI + OOooOOo + I11i
 if 50 - 50: I1Ii111 + I1ii11iIi11i
 if 4 - 4: IiII / Oo0Ooo
 I1IIiiII = commands . getoutput ( "egrep -A 2 'lisp map-resolver {' ./lisp.config" )
 i1iI111II1ii = None
 for oo0ooO0 in [ "address = " , "dns-name = " ] :
  i1iI111II1ii = None
  oOOO0oOoo = I1IIiiII . find ( oo0ooO0 )
  if ( oOOO0oOoo == - 1 ) : continue
  i1iI111II1ii = I1IIiiII [ oOOO0oOoo + len ( oo0ooO0 ) : : ]
  oOOO0oOoo = i1iI111II1ii . find ( "\n" )
  if ( oOOO0oOoo == - 1 ) : continue
  i1iI111II1ii = i1iI111II1ii [ 0 : oOOO0oOoo ]
  break
  if 65 - 65: iII111i . oO0o - Ii1I
 if ( i1iI111II1ii == None ) : return ( [ None , None ] )
 if 93 - 93: O0
 if 4 - 4: I1IiiI / I1IiiI
 if 82 - 82: I11i / ooOoO0o * I11i % i11iIiiIii * II111iiii
 if 83 - 83: OoO0O00 + OOooOOo - o0oOOo0O0Ooo + iIii1I11I1II1 % Oo0Ooo
 II111I1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 i1iIIIIi1i1 = [ ]
 for Iii in [ eid1 , eid2 ] :
  if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
  if 33 - 33: Ii1I
  if 93 - 93: ooOoO0o
  if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
  if 19 - 19: I1ii11iIi11i
  if ( II111I1 . is_geo_string ( Iii ) ) :
   i1iIIIIi1i1 . append ( Iii )
   continue
   if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
   if 66 - 66: O0
  Oo0O0 = 'python {} "{}" to {} count 1' . format ( oOiI111I1III , Iii , i1iI111II1ii )
  for OOOO0OOO in [ Oo0O0 , Oo0O0 + " no-info" ] :
   ooo00OOOooO = commands . getoutput ( Oo0O0 )
   oOOO0oOoo = ooo00OOOooO . find ( "geo: " )
   if ( oOOO0oOoo == - 1 ) :
    if ( OOOO0OOO != Oo0O0 ) : i1iIIIIi1i1 . append ( None )
    continue
    if 52 - 52: OoO0O00 * OoooooooOO
   ooo00OOOooO = ooo00OOOooO [ oOOO0oOoo + len ( "geo: " ) : : ]
   oOOO0oOoo = ooo00OOOooO . find ( "\n" )
   if ( oOOO0oOoo == - 1 ) :
    if ( OOOO0OOO != Oo0O0 ) : i1iIIIIi1i1 . append ( None )
    continue
    if 12 - 12: O0 + IiII * i1IIi . OoO0O00
   i1iIIIIi1i1 . append ( ooo00OOOooO [ 0 : oOOO0oOoo ] )
   break
   if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
   if 28 - 28: iIii1I11I1II1
 return ( i1iIIIIi1i1 )
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 if 46 - 46: OoOoOO00 - O0
 if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
 if 49 - 49: o0oOOo0O0Ooo
@ bottle . post ( '/lisp/geo' )
def I11 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 18 - 18: iIii1I11I1II1
  if 30 - 30: O0 + OOooOOo % Oo0Ooo . i1IIi
 Iii = bottle . request . forms . get ( "geo-point" )
 I111 = bottle . request . forms . get ( "geo-prefix" )
 ooo00OOOooO = ""
 if 65 - 65: Oo0Ooo * O0 / Ii1I . I1Ii111 % Oo0Ooo
 if 24 - 24: OoO0O00
 if 99 - 99: OOooOOo / IiII / Ii1I
 if 84 - 84: OoO0O00 / iIii1I11I1II1
 if 33 - 33: i1IIi / I1Ii111 - i1IIi . Oo0Ooo
 iIIi1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 oo = lisp . lisp_geo ( "" )
 IiI11i1I11111 = lisp . lisp_geo ( "" )
 Ii1IIIIIIiI1 , Ii11IiIiiii1 = oOIii11111iiI ( Iii , I111 )
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if 64 - 64: i1IIi
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 if ( iIIi1 . is_geo_string ( Iii ) ) :
  if ( oo . parse_geo_string ( Iii ) == False ) :
   ooo00OOOooO = "Could not parse geo-point format"
   if 25 - 25: II111iiii / OoO0O00
 elif ( Ii1IIIIIIiI1 == None ) :
  ooo00OOOooO = "EID {} lookup could not find geo-point" . format (
 lisp . bold ( Iii , True ) )
 elif ( oo . parse_geo_string ( Ii1IIIIIIiI1 ) == False ) :
  ooo00OOOooO = "Could not parse geo-point format returned from lookup"
  if 64 - 64: O0 % ooOoO0o
  if 40 - 40: o0oOOo0O0Ooo + I11i
  if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
  if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
  if 47 - 47: OoooooooOO
  if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
 if ( ooo00OOOooO == "" ) :
  if ( iIIi1 . is_geo_string ( I111 ) ) :
   if ( IiI11i1I11111 . parse_geo_string ( I111 ) == False ) :
    ooo00OOOooO = "Could not parse geo-prefix format"
    if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
  elif ( Ii11IiIiiii1 == None ) :
   ooo00OOOooO = "EID-prefix {} lookup could not find geo-prefix" . format ( lisp . bold ( I111 , True ) )
   if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
  elif ( IiI11i1I11111 . parse_geo_string ( Ii11IiIiiii1 ) == False ) :
   ooo00OOOooO = "Could not parse geo-prefix format returned from lookup"
   if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
   if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
   if 26 - 26: OOooOOo * Oo0Ooo
   if 31 - 31: I11i * oO0o . Ii1I
   if 35 - 35: I11i
   if 94 - 94: ooOoO0o / i11iIiiIii % O0
   if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if ( ooo00OOOooO == "" ) :
  Iii = "" if ( Iii == Ii1IIIIIIiI1 ) else ", EID {}" . format ( Iii )
  I111 = "" if ( I111 == Ii11IiIiiii1 ) else ", EID-prefix {}" . format ( I111 )
  if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
  if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
  o0 = oo . print_geo_url ( )
  IiIiI111IIII1 = IiI11i1I11111 . print_geo_url ( )
  OOOoOooO000oO = IiI11i1I11111 . radius
  o0OOOOOo00 = oo . dms_to_decimal ( )
  o0OOOOOo00 = ( round ( o0OOOOOo00 [ 0 ] , 6 ) , round ( o0OOOOOo00 [ 1 ] , 6 ) )
  oo0oOO = IiI11i1I11111 . dms_to_decimal ( )
  oo0oOO = ( round ( oo0oOO [ 0 ] , 6 ) , round ( oo0oOO [ 1 ] , 6 ) )
  IIO000oooOO0Oo0 = round ( IiI11i1I11111 . get_distance ( oo ) , 2 )
  I1iIiIii = "inside" if IiI11i1I11111 . point_in_circle ( oo ) else "outside"
  if 76 - 76: OoO0O00 . OoooooooOO % I1Ii111 * Ii1I
  if 23 - 23: IiII + iIii1I11I1II1
  Ii1111III1 = lisp . space ( 2 )
  oO00oooo0 = lisp . space ( 1 )
  OO0 = lisp . space ( 3 )
  if 96 - 96: O0 . iII111i - I1IiiI * Oo0Ooo
  ooo00OOOooO = ( "Geo-Point:{}{} {}{}<br>Geo-Prefix:{}{} {}, {} " + "kilometer radius{}<br>" ) . format ( Ii1111III1 , o0 , o0OOOOOo00 , Iii ,
  # o0oOOo0O0Ooo % i1IIi - o0oOOo0O0Ooo + iIii1I11I1II1 + I1Ii111
 oO00oooo0 , IiIiI111IIII1 , oo0oOO , OOOoOooO000oO , I111 )
  ooo00OOOooO += "Distance:{}{} kilometers, point is {} of circle" . format ( OO0 ,
 IIO000oooOO0Oo0 , lisp . bold ( I1iIiIii , True ) )
  if 84 - 84: oO0o + OOooOOo . iII111i
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( ooo00OOOooO ) ) )
 if 71 - 71: ooOoO0o / ooOoO0o . OoOoOO00 % iII111i
 if 50 - 50: ooOoO0o + iII111i / I11i / I11i % O0
 if 87 - 87: Oo0Ooo + ooOoO0o
 if 66 - 66: o0oOOo0O0Ooo * OOooOOo + Ii1I * o0oOOo0O0Ooo + OOooOOo / OoooooooOO
 if 86 - 86: Ii1I . iII111i - iII111i
 if 71 - 71: iIii1I11I1II1 . II111iiii % iIii1I11I1II1
 if 22 - 22: i11iIiiIii % I1ii11iIi11i % ooOoO0o % ooOoO0o . OoO0O00
 if 85 - 85: ooOoO0o . O0 / OOooOOo * ooOoO0o - OoO0O00 - i11iIiiIii
 if 25 - 25: ooOoO0o % Oo0Ooo - OOooOOo
def O0OoOOooO0O ( addr_str , port , nonce ) :
 if ( addr_str != None ) :
  for Ii11iIII in lisp . lisp_info_sources_by_address . values ( ) :
   o0ooOO0OOO00o = Ii11iIII . address . print_address_no_iid ( )
   if ( o0ooOO0OOO00o == addr_str and Ii11iIII . port == port ) :
    return ( Ii11iIII )
    if 76 - 76: OoooooooOO * OoooooooOO - iII111i - iIii1I11I1II1 . OoooooooOO / I1ii11iIi11i
    if 86 - 86: ooOoO0o
  return ( None )
  if 51 - 51: OoO0O00 - i11iIiiIii * I1IiiI
  if 95 - 95: OOooOOo % I1ii11iIi11i + o0oOOo0O0Ooo % ooOoO0o
 if ( nonce != None ) :
  if ( nonce not in lisp . lisp_info_sources_by_nonce ) : return ( None )
  return ( lisp . lisp_info_sources_by_nonce [ nonce ] )
  if 36 - 36: O0 / i1IIi % II111iiii / iII111i
 return ( None )
 if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
 if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: oO0o
 if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
 if 97 - 97: I1Ii111 . I11i / I1IiiI
 if 83 - 83: I11i - I1ii11iIi11i * oO0o
def oOO00OO0OooOo ( lisp_sockets , info_source , packet ) :
 if 13 - 13: O0 % ooOoO0o % I11i
 if 25 - 25: OoooooooOO % Ii1I * II111iiii - OoO0O00
 if 95 - 95: I1IiiI % I1Ii111 * I1IiiI + O0 . I1Ii111 % OoooooooOO
 if 6 - 6: OoOoOO00 - ooOoO0o * o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo
 OOO00000o0 = lisp . lisp_ecm ( 0 )
 packet = OOO00000o0 . decode ( packet )
 if ( packet == None ) :
  lisp . lprint ( "Could not decode ECM packet" )
  return ( True )
  if 96 - 96: o0oOOo0O0Ooo * oO0o - OOooOOo * o0oOOo0O0Ooo * i1IIi
  if 8 - 8: ooOoO0o - Oo0Ooo + iIii1I11I1II1 + i1IIi * Ii1I - iIii1I11I1II1
 o0O0Oo0Ooo0 = lisp . lisp_control_header ( )
 if ( o0O0Oo0Ooo0 . decode ( packet ) == None ) :
  lisp . lprint ( "Could not decode control header" )
  return ( True )
  if 30 - 30: I11i / I1ii11iIi11i
 if ( o0O0Oo0Ooo0 . type != lisp . LISP_MAP_REQUEST ) :
  lisp . lprint ( "Received ECM without Map-Request inside" )
  return ( True )
  if 22 - 22: oO0o * iII111i
  if 4 - 4: OoOoOO00 - oO0o + I1IiiI
  if 36 - 36: IiII
  if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
  if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
 iiI1iIII1ii = lisp . lisp_map_request ( )
 packet = iiI1iIII1ii . decode ( packet , None , 0 )
 i1iiIIiII1 = iiI1iIII1ii . nonce
 o0O00OooooO = info_source . address . print_address_no_iid ( )
 if 77 - 77: I1IiiI % ooOoO0o
 if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
 if 52 - 52: IiII % ooOoO0o
 if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
 iiI1iIII1ii . print_map_request ( )
 if 23 - 23: i11iIiiIii
 lisp . lprint ( "Process {} from info-source {}, port {}, nonce 0x{}" . format ( lisp . bold ( "nat-proxy Map-Request" , False ) ,
 # OoO0O00 * O0 - OoO0O00 . oO0o / I1IiiI / OoOoOO00
 lisp . red ( o0O00OooooO , False ) , info_source . port ,
 lisp . lisp_hex_string ( i1iiIIiII1 ) ) )
 if 51 - 51: II111iiii / Oo0Ooo / I1IiiI + i11iIiiIii
 if 5 - 5: I11i
 if 22 - 22: iIii1I11I1II1 * I1Ii111 / Oo0Ooo
 if 31 - 31: i11iIiiIii
 if 56 - 56: I11i / Ii1I + Oo0Ooo - i1IIi - IiII + iIii1I11I1II1
 info_source . cache_nonce_for_info_source ( i1iiIIiII1 )
 if 75 - 75: I1ii11iIi11i
 if 92 - 92: I11i / O0 * I1IiiI - I11i
 if 99 - 99: i11iIiiIii % OoooooooOO
 if 56 - 56: IiII * I1Ii111
 if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
 info_source . no_timeout = iiI1iIII1ii . subscribe_bit
 if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
 if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
 if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
 if 56 - 56: i1IIi . i11iIiiIii
 if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
 if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
 for oO000o0OO0OO0 in iiI1iIII1ii . itr_rlocs :
  if ( oO000o0OO0OO0 . is_local ( ) ) : return ( False )
  if 23 - 23: iII111i - Ii1I
  if 16 - 16: Oo0Ooo % I1Ii111
  if 10 - 10: IiII / OoooooooOO
  if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
  if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
 iIiO0O = lisp . lisp_myrlocs [ 0 ]
 iiI1iIII1ii . itr_rloc_count = 0
 iiI1iIII1ii . itr_rlocs = [ ]
 iiI1iIII1ii . itr_rlocs . append ( iIiO0O )
 if 71 - 71: I1ii11iIi11i + OoO0O00
 packet = iiI1iIII1ii . encode ( None , 0 )
 iiI1iIII1ii . print_map_request ( )
 if 17 - 17: O0 . OOooOOo
 oooO0o0oOoO = iiI1iIII1ii . target_eid
 if ( oooO0o0oOoO . is_ipv6 ( ) ) :
  I11iii = lisp . lisp_myrlocs [ 1 ]
  if ( I11iii != None ) : iIiO0O = I11iii
  if 11 - 11: oO0o + I1Ii111 . IiII * OoooooooOO - I1ii11iIi11i - OOooOOo
  if 16 - 16: iII111i / iIii1I11I1II1 + OOooOOo * iII111i * I11i
  if 8 - 8: I1Ii111
  if 15 - 15: Oo0Ooo / Ii1I % O0 + I1ii11iIi11i
  if 96 - 96: ooOoO0o . OoooooooOO
 i1I1I1I = lisp . lisp_is_running ( "lisp-ms" )
 lisp . lisp_send_ecm ( lisp_sockets , packet , oooO0o0oOoO , lisp . LISP_CTRL_PORT ,
 oooO0o0oOoO , iIiO0O , to_ms = i1I1I1I , ddt = False )
 return ( True )
 if 25 - 25: o0oOOo0O0Ooo + iII111i - Oo0Ooo
 if 59 - 59: OOooOOo - I11i % i1IIi
 if 1 - 1: I1ii11iIi11i . I1Ii111 * I1IiiI . IiII * II111iiii % iIii1I11I1II1
 if 86 - 86: i1IIi * O0 % ooOoO0o . Oo0Ooo % ooOoO0o . Oo0Ooo
 if 71 - 71: iII111i . i11iIiiIii * O0 + O0
 if 57 - 57: OoooooooOO . I11i % II111iiii % I1IiiI + Ii1I
 if 70 - 70: IiII . i11iIiiIii
 if 76 - 76: iII111i . IiII % iII111i - I1Ii111
 if 51 - 51: OoooooooOO + o0oOOo0O0Ooo * iIii1I11I1II1 * oO0o / i1IIi
def I11IiI1i ( lisp_sockets , info_source , packet , mr_or_mn ) :
 o0O00OooooO = info_source . address . print_address_no_iid ( )
 iIiIIIi = info_source . port
 i1iiIIiII1 = info_source . nonce
 if 81 - 81: iIii1I11I1II1 / oO0o . i11iIiiIii * II111iiii
 mr_or_mn = "Reply" if mr_or_mn else "Notify"
 mr_or_mn = lisp . bold ( "nat-proxy Map-{}" . format ( mr_or_mn ) , False )
 if 55 - 55: I1ii11iIi11i
 lisp . lprint ( "Forward {} to info-source {}, port {}, nonce 0x{}" . format ( mr_or_mn , lisp . red ( o0O00OooooO , False ) , iIiIIIi ,
 # I1ii11iIi11i / i11iIiiIii - ooOoO0o / I1ii11iIi11i - Ii1I
 lisp . lisp_hex_string ( i1iiIIiII1 ) ) )
 if 5 - 5: i11iIiiIii * Oo0Ooo
 if 29 - 29: Ii1I / ooOoO0o % I11i
 if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 O0o0O0O0O = lisp . lisp_convert_4to6 ( o0O00OooooO )
 lisp . lisp_send ( lisp_sockets , O0o0O0O0O , iIiIIIi , packet )
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
 if 79 - 79: O0
 if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
 if 15 - 15: I1ii11iIi11i
 if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
def OO0o0o0oo ( lisp_sockets , source , sport , packet ) :
 global Oo
 if 40 - 40: Oo0Ooo
 o0O0Oo0Ooo0 = lisp . lisp_control_header ( )
 if ( o0O0Oo0Ooo0 . decode ( packet ) == None ) :
  lisp . lprint ( "Could not decode control header" )
  return
  if 47 - 47: OoOoOO00
  if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
  if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
  if 33 - 33: oO0o
  if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
  if 41 - 41: IiII % o0oOOo0O0Ooo
  if 67 - 67: O0 % I1Ii111
  if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
  if 39 - 39: Ii1I
  if 60 - 60: OOooOOo
 if ( o0O0Oo0Ooo0 . type == lisp . LISP_NAT_INFO ) :
  if ( o0O0Oo0Ooo0 . info_reply == False ) :
   lisp . lisp_process_info_request ( lisp_sockets , packet , source , sport ,
 lisp . lisp_ms_rtr_list )
   if 62 - 62: I1Ii111 * I11i
  return
  if 74 - 74: OoOoOO00 . iIii1I11I1II1
  if 87 - 87: ooOoO0o
 IIo0oo0OO = packet
 packet = lisp . lisp_packet_ipc ( packet , source , sport )
 if 17 - 17: ooOoO0o + I1ii11iIi11i * i11iIiiIii
 if 82 - 82: IiII
 if 51 - 51: oO0o % OoO0O00 + o0oOOo0O0Ooo + Ii1I - OoooooooOO . OoO0O00
 if 18 - 18: Oo0Ooo - OOooOOo * II111iiii + oO0o
 if ( o0O0Oo0Ooo0 . type in ( lisp . LISP_MAP_REGISTER , lisp . LISP_MAP_NOTIFY_ACK ) ) :
  lisp . lisp_ipc ( packet , Oo , "lisp-ms" )
  return
  if 93 - 93: iII111i * oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if 59 - 59: II111iiii
  if 43 - 43: Oo0Ooo + OoooooooOO
  if 47 - 47: ooOoO0o
  if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
 if ( o0O0Oo0Ooo0 . type == lisp . LISP_MAP_REPLY ) :
  ii11Ii1IiiI1 = lisp . lisp_map_reply ( )
  ii11Ii1IiiI1 . decode ( IIo0oo0OO )
  if 83 - 83: ooOoO0o + i1IIi * OoooooooOO * oO0o
  Ii11iIII = O0OoOOooO0O ( None , 0 , ii11Ii1IiiI1 . nonce )
  if ( Ii11iIII ) :
   I11IiI1i ( lisp_sockets , Ii11iIII , IIo0oo0OO , True )
  else :
   oOiI111I1III = "/tmp/lisp-lig"
   if ( os . path . exists ( oOiI111I1III ) ) :
    lisp . lisp_ipc ( packet , Oo , oOiI111I1III )
   else :
    lisp . lisp_ipc ( packet , Oo , "lisp-itr" )
    if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
    if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  return
  if 21 - 21: OoO0O00
  if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
  if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
  if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
  if 11 - 11: O0 * OoOoOO00
 if ( o0O0Oo0Ooo0 . type == lisp . LISP_MAP_NOTIFY ) :
  IIii1i = lisp . lisp_map_notify ( lisp_sockets )
  IIii1i . decode ( IIo0oo0OO )
  if 69 - 69: I1Ii111 / OoooooooOO % i11iIiiIii
  Ii11iIII = O0OoOOooO0O ( None , 0 , IIii1i . nonce )
  if ( Ii11iIII ) :
   I11IiI1i ( lisp_sockets , Ii11iIII , IIo0oo0OO ,
 False )
  else :
   oOiI111I1III = "/tmp/lisp-lig"
   if ( os . path . exists ( oOiI111I1III ) ) :
    lisp . lisp_ipc ( packet , Oo , oOiI111I1III )
   else :
    ooOO = "lisp-rtr" if lisp . lisp_is_running ( "lisp-rtr" ) else "lisp-etr"
    if 18 - 18: i11iIiiIii - ooOoO0o * oO0o + o0oOOo0O0Ooo
    lisp . lisp_ipc ( packet , Oo , ooOO )
    if 16 - 16: OoooooooOO * i11iIiiIii . OoooooooOO - iIii1I11I1II1 * i1IIi
    if 33 - 33: I1Ii111 % II111iiii
  return
  if 49 - 49: I1ii11iIi11i + I11i / o0oOOo0O0Ooo + OoooooooOO + OOooOOo / IiII
  if 29 - 29: Ii1I - Ii1I / ooOoO0o
  if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
  if 18 - 18: Oo0Ooo % O0
  if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if ( o0O0Oo0Ooo0 . type == lisp . LISP_MAP_REFERRAL ) :
  I1IiII1I1i1I1 = "/tmp/lisp-rig"
  if ( os . path . exists ( I1IiII1I1i1I1 ) ) :
   lisp . lisp_ipc ( packet , Oo , I1IiII1I1i1I1 )
  else :
   lisp . lisp_ipc ( packet , Oo , "lisp-mr" )
   if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
  return
  if 86 - 86: IiII
  if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
  if 33 - 33: II111iiii - IiII - ooOoO0o
  if 92 - 92: OoO0O00 * IiII
  if 92 - 92: oO0o
  if 7 - 7: iII111i
 if ( o0O0Oo0Ooo0 . type == lisp . LISP_MAP_REQUEST ) :
  ooOO = "lisp-itr" if ( o0O0Oo0Ooo0 . is_smr ( ) ) else "lisp-etr"
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if 62 - 62: i11iIiiIii
  if 2 - 2: I1IiiI
  if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
  if ( o0O0Oo0Ooo0 . rloc_probe ) : return
  if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  lisp . lisp_ipc ( packet , Oo , ooOO )
  return
  if 14 - 14: IiII . IiII % ooOoO0o
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
  if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
  if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
  if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
  if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 6 - 6: oO0o . I11i
 if ( o0O0Oo0Ooo0 . type == lisp . LISP_ECM ) :
  Ii11iIII = O0OoOOooO0O ( source , sport , None )
  if ( Ii11iIII ) :
   if ( oOO00OO0OooOo ( lisp_sockets , Ii11iIII ,
 IIo0oo0OO ) ) : return
   if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
   if 50 - 50: oO0o % i1IIi * O0
  ooOO = "lisp-mr"
  if ( o0O0Oo0Ooo0 . is_to_etr ( ) ) :
   ooOO = "lisp-etr"
  elif ( o0O0Oo0Ooo0 . is_to_ms ( ) ) :
   ooOO = "lisp-ms"
  elif ( o0O0Oo0Ooo0 . is_ddt ( ) ) :
   if ( lisp . lisp_is_running ( "lisp-ddt" ) ) :
    ooOO = "lisp-ddt"
   elif ( lisp . lisp_is_running ( "lisp-ms" ) ) :
    ooOO = "lisp-ms"
    if 4 - 4: iIii1I11I1II1 . i1IIi
  elif ( lisp . lisp_is_running ( "lisp-mr" ) == False ) :
   ooOO = "lisp-etr"
   if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
  lisp . lisp_ipc ( packet , Oo , ooOO )
  if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
 return
 if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
 if 59 - 59: iIii1I11I1II1 / I1ii11iIi11i % ooOoO0o
 if 84 - 84: iIii1I11I1II1 / I1IiiI . OoOoOO00 % I11i
 if 99 - 99: Oo0Ooo + i11iIiiIii
 if 36 - 36: Ii1I * I1Ii111 * iIii1I11I1II1 - I11i % i11iIiiIii
 if 98 - 98: iIii1I11I1II1 - i1IIi + ooOoO0o % I11i + ooOoO0o / oO0o
 if 97 - 97: IiII % ooOoO0o + II111iiii - IiII % OoO0O00 + ooOoO0o
 if 31 - 31: o0oOOo0O0Ooo
 if 35 - 35: OoOoOO00 + Ii1I * ooOoO0o / OoOoOO00
 if 69 - 69: ooOoO0o . OOooOOo - I1IiiI
 if 29 - 29: i11iIiiIii . I1ii11iIi11i / I1IiiI . OOooOOo + i11iIiiIii
 if 26 - 26: IiII / Ii1I - OoooooooOO
class iiIiiII1II1ii ( bottle . ServerAdapter ) :
 def run ( self , hand ) :
  i1iI1iiI = "./lisp-cert.pem"
  if 31 - 31: I1ii11iIi11i
  if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
  if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
  if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
  if 13 - 13: II111iiii - Oo0Ooo % i11iIiiIii + iII111i
  if ( os . path . exists ( i1iI1iiI ) == False ) :
   os . system ( "cp ./lisp-cert.pem.default {}" . format ( i1iI1iiI ) )
   lisp . lprint ( ( "{} does not exist, creating a copy from lisp-" + "cert.pem.default" ) . format ( i1iI1iiI ) )
   if 88 - 88: O0 . oO0o % I1IiiI
   if 10 - 10: I1IiiI + O0
   if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
  iiI1iiIiiiI1I = wsgiserver . CherryPyWSGIServer ( ( self . host , self . port ) , hand )
  iiI1iiIiiiI1I . ssl_adapter = pyOpenSSLAdapter ( i1iI1iiI , i1iI1iiI , None )
  if 6 - 6: OoO0O00
  if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
  try :
   iiI1iiIiiiI1I . start ( )
  finally :
   iiI1iiIiiiI1I . stop ( )
   if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
   if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
   if 31 - 31: oO0o * I1Ii111 . OoOoOO00 * I11i
   if 28 - 28: IiII + I1IiiI - Oo0Ooo % OOooOOo . I11i + I1IiiI
   if 72 - 72: Ii1I / Oo0Ooo / oO0o * OoOoOO00 + OOooOOo
   if 58 - 58: o0oOOo0O0Ooo % I1IiiI . I1IiiI * OoO0O00 - IiII . OoooooooOO
   if 10 - 10: I1Ii111
   if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
   if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
   if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
   if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
   if 55 - 55: OoooooooOO
   if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
   if 38 - 38: O0
   if 79 - 79: i1IIi . oO0o
   if 34 - 34: I1Ii111 * II111iiii
def o0oO00OOo0oO ( bottle_port ) :
 lisp . lisp_set_exception ( )
 if 92 - 92: I1IiiI . II111iiii
 if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
 if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
 if 28 - 28: i11iIiiIii
 if 51 - 51: I1IiiI + ooOoO0o * O0 . Ii1I
 if ( bottle_port < 0 ) :
  bottle . run ( host = "0.0.0.0" , port = - bottle_port )
  return
  if 82 - 82: OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
  if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
 bottle . server_names [ "lisp-ssl-server" ] = iiIiiII1II1ii
 if 20 - 20: i1IIi . i1IIi - I11i
 if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
 if 35 - 35: II111iiii / OoOoOO00 - O0 . II111iiii
 if 55 - 55: Oo0Ooo % i1IIi * I11i
 try :
  bottle . run ( host = "0.0.0.0" , port = bottle_port , server = "lisp-ssl-server" ,
 fast = True )
 except :
  bottle . run ( host = "0.0.0.0" , port = bottle_port , fast = True )
  if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
 return
 if 63 - 63: iIii1I11I1II1 / ooOoO0o
 if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
 if 50 - 50: II111iiii
 if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
 if 44 - 44: I1IiiI
 if 55 - 55: oO0o . I1Ii111 * I1Ii111
 if 82 - 82: I1IiiI % OoO0O00 % I11i + I11i
 if 6 - 6: Oo0Ooo
def O0OOOOoO00oo ( ) :
 lisp . lisp_set_exception ( )
 if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
 return
 if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
 if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
 if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
 if 58 - 58: I11i
 if 7 - 7: II111iiii / IiII % I11i + I1IiiI - O0
 if 45 - 45: I1IiiI / iII111i + oO0o + IiII
 if 15 - 15: I1IiiI % OoO0O00
 if 66 - 66: oO0o * i11iIiiIii . I1Ii111
 if 92 - 92: oO0o
def OOOOo0o0O0o ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 OoO = { "lisp-itr" : False , "lisp-etr" : False , "lisp-rtr" : False ,
 "lisp-mr" : False , "lisp-ms" : False , "lisp-ddt" : False }
 if 8 - 8: o0oOOo0O0Ooo / o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo * OoOoOO00 . o0oOOo0O0Ooo
 while ( True ) :
  time . sleep ( 1 )
  iiii1II1ii11 = OoO
  OoO = { }
  if 37 - 37: I1Ii111 - oO0o - OoO0O00
  for ooOO in iiii1II1ii11 :
   OoO [ ooOO ] = lisp . lisp_is_running ( ooOO )
   if ( iiii1II1ii11 [ ooOO ] == OoO [ ooOO ] ) : continue
   if 42 - 42: iIii1I11I1II1 % Ii1I - I1ii11iIi11i + iIii1I11I1II1
   lisp . lprint ( "*** Process '{}' has {} ***" . format ( ooOO ,
 "come up" if OoO [ ooOO ] else "gone down" ) )
   if 27 - 27: O0 / OoO0O00
   if 99 - 99: Ii1I - IiII * iIii1I11I1II1 . II111iiii
   if 56 - 56: iIii1I11I1II1 % OoO0O00 . ooOoO0o % IiII . I1Ii111 * Oo0Ooo
   if 41 - 41: iIii1I11I1II1 % IiII * oO0o - ooOoO0o
   if ( OoO [ ooOO ] == True ) :
    lisp . lisp_ipc_lock . acquire ( )
    lispconfig . lisp_send_commands ( lisp_socket , ooOO )
    lisp . lisp_ipc_lock . release ( )
    if 5 - 5: OoO0O00 + OoO0O00 + II111iiii * iIii1I11I1II1 + OoooooooOO
    if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
    if 10 - 10: I1ii11iIi11i + IiII
 return
 if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
 if 62 - 62: II111iiii
 if 12 - 12: IiII + II111iiii
 if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
 if 80 - 80: iII111i
 if 3 - 3: I1ii11iIi11i * I11i
 if 53 - 53: iIii1I11I1II1 / iII111i % OoO0O00 + IiII / ooOoO0o
def oo00oO ( ) :
 lisp . lisp_set_exception ( )
 I11i1I11 = 60
 if 32 - 32: IiII - oO0o . iIii1I11I1II1 . I1Ii111 + II111iiii % OoooooooOO
 while ( True ) :
  time . sleep ( I11i1I11 )
  if 82 - 82: OoooooooOO / ooOoO0o * I11i * O0 . I1ii11iIi11i
  iiIIIII = [ ]
  iiI1 = lisp . lisp_get_timestamp ( )
  if 40 - 40: O0 + IiII . Ii1I
  if 29 - 29: OOooOOo / OoOoOO00 . iIii1I11I1II1 / I11i % OoOoOO00 % iII111i
  if 49 - 49: II111iiii / IiII - Ii1I
  if 7 - 7: I1IiiI / OoO0O00 + I1Ii111 + I11i / I1IiiI
  for Ii1 in lisp . lisp_info_sources_by_address :
   Ii11iIII = lisp . lisp_info_sources_by_address [ Ii1 ]
   if ( Ii11iIII . no_timeout ) : continue
   if ( Ii11iIII . uptime + I11i1I11 < iiI1 ) : continue
   if 82 - 82: I1ii11iIi11i + OoooooooOO
   iiIIIII . append ( Ii1 )
   if 21 - 21: oO0o * oO0o / I11i . iII111i
   i1iiIIiII1 = Ii11iIII . nonce
   if ( i1iiIIiII1 == None ) : continue
   if ( i1iiIIiII1 in lisp . lisp_info_sources_by_nonce ) :
    lisp . lisp_info_sources_by_nonce . pop ( i1iiIIiII1 )
    if 10 - 10: Ii1I * OOooOOo - Oo0Ooo - OoooooooOO / o0oOOo0O0Ooo
    if 86 - 86: I1Ii111 % I1IiiI
    if 22 - 22: i11iIiiIii * I1Ii111 . Oo0Ooo . OoooooooOO + I1IiiI
    if 24 - 24: II111iiii / Ii1I . iIii1I11I1II1 - II111iiii % O0
    if 8 - 8: OoO0O00 % iII111i . OoooooooOO - Ii1I % OoooooooOO
    if 61 - 61: o0oOOo0O0Ooo / i11iIiiIii
  for Ii1 in iiIIIII :
   lisp . lisp_info_sources_by_address . pop ( Ii1 )
   if 28 - 28: OOooOOo / OoOoOO00
   if 30 - 30: ooOoO0o
 return
 if 57 - 57: o0oOOo0O0Ooo * i11iIiiIii / OoOoOO00
 if 40 - 40: iIii1I11I1II1 - ooOoO0o / Oo0Ooo
 if 24 - 24: oO0o - iII111i / ooOoO0o
 if 10 - 10: OoOoOO00 * i1IIi
 if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
 if 34 - 34: I1IiiI
 if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
 if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
def oo0oO0oOo0O ( lisp_ipc_control_socket , lisp_sockets ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  try : OoOo00 = lisp_ipc_control_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  IIIi1i1I = OoOo00 [ 0 ] . split ( "@" )
  oo00O00oO = OoOo00 [ 1 ]
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  oOOo0 = IIIi1i1I [ 0 ]
  O0o0O0O0O = IIIi1i1I [ 1 ]
  iIiIIIi = int ( IIIi1i1I [ 2 ] )
  o0000oO = IIIi1i1I [ 3 : : ]
  if 83 - 83: OoO0O00
  if ( len ( o0000oO ) > 1 ) :
   o0000oO = lisp . lisp_bit_stuff ( o0000oO )
  else :
   o0000oO = o0000oO [ 0 ]
   if 16 - 16: ooOoO0o
   if 32 - 32: o0oOOo0O0Ooo % I1IiiI
  if ( oOOo0 != "control-packet" ) :
   lisp . lprint ( ( "lisp_core_control_packet_process() received" + "unexpected control-packet, message ignored" ) )
   if 7 - 7: Oo0Ooo . i1IIi - oO0o
   continue
   if 93 - 93: IiII % I1ii11iIi11i
   if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
  lisp . lprint ( ( "{} {} bytes from {}, dest/port: {}/{}, control-" + "packet: {}" ) . format ( lisp . bold ( "Receive" , False ) , len ( o0000oO ) ,
  # iIii1I11I1II1 / Ii1I
 oo00O00oO , O0o0O0O0O , iIiIIIi , lisp . lisp_format_packet ( o0000oO ) ) )
  if 59 - 59: Ii1I / II111iiii - IiII % OoOoOO00 % OoooooooOO
  if 79 - 79: iII111i . OoooooooOO . I1IiiI * O0 * OoO0O00 - OOooOOo
  if 33 - 33: I1ii11iIi11i . Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
  if 54 - 54: ooOoO0o * iII111i * iII111i % OoOoOO00 - OOooOOo % I1ii11iIi11i
  if 44 - 44: Oo0Ooo . OOooOOo + I11i
  if 22 - 22: I1Ii111 * OoooooooOO + i11iIiiIii % OoO0O00
  o0O0Oo0Ooo0 = lisp . lisp_control_header ( )
  o0O0Oo0Ooo0 . decode ( o0000oO )
  if ( o0O0Oo0Ooo0 . type == lisp . LISP_MAP_REPLY ) :
   ii11Ii1IiiI1 = lisp . lisp_map_reply ( )
   ii11Ii1IiiI1 . decode ( o0000oO )
   if ( O0OoOOooO0O ( None , 0 , ii11Ii1IiiI1 . nonce ) ) :
    OO0o0o0oo ( lisp_sockets , oo00O00oO , iIiIIIi , o0000oO )
    continue
    if 53 - 53: I1IiiI
    if 10 - 10: I1Ii111 / i11iIiiIii - II111iiii
    if 48 - 48: OOooOOo
    if 26 - 26: iII111i * I1Ii111 * oO0o * OoOoOO00
    if 48 - 48: iII111i % i11iIiiIii . OoooooooOO * IiII % OoO0O00 . iII111i
    if 6 - 6: O0 . ooOoO0o - oO0o / i11iIiiIii
    if 84 - 84: I11i / I1ii11iIi11i * o0oOOo0O0Ooo * OoO0O00 * OOooOOo * O0
    if 83 - 83: O0 % II111iiii + o0oOOo0O0Ooo / OoooooooOO
  if ( o0O0Oo0Ooo0 . type == lisp . LISP_MAP_NOTIFY and oo00O00oO == "lisp-etr" ) :
   iiI111I1iIiI = lisp . lisp_packet_ipc ( o0000oO , oo00O00oO , iIiIIIi )
   lisp . lisp_ipc ( iiI111I1iIiI , Oo , "lisp-itr" )
   continue
   if 75 - 75: II111iiii . I1IiiI + OOooOOo - OoOoOO00 - O0 . I11i
   if 19 - 19: Ii1I * i1IIi % O0 + I11i
   if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
   if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
   if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
   if 80 - 80: Ii1I
   if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
  II111I1 = lisp . lisp_convert_4to6 ( O0o0O0O0O )
  II111I1 = lisp . lisp_address ( lisp . LISP_AFI_IPV6 , "" , 128 , 0 )
  if ( II111I1 . is_ipv4_string ( O0o0O0O0O ) ) : O0o0O0O0O = "::ffff:" + O0o0O0O0O
  II111I1 . store_address ( O0o0O0O0O )
  if 59 - 59: I1ii11iIi11i + I11i . oO0o
  if 87 - 87: OoO0O00
  if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
  lisp . lisp_send ( lisp_sockets , II111I1 , iIiIIIi , o0000oO )
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
 return
 if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
 if 46 - 46: i11iIiiIii
 if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
 if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
 if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
 if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
 if 65 - 65: OoooooooOO
 if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
def O0O0oOOo0O ( ) :
 ii1111iII = open ( "./lisp.config.example" , "r" ) ; iiiiI = ii1111iII . read ( ) ; ii1111iII . close ( )
 ii1111iII = open ( "./lisp.config" , "w" )
 iiiiI = iiiiI . split ( "\n" )
 for OOoO in iiiiI :
  ii1111iII . write ( OOoO + "\n" )
  if ( OOoO [ 0 ] == "#" and OOoO [ - 1 ] == "#" and len ( OOoO ) >= 4 ) :
   oOo00Oo0o00oo = OOoO [ 1 : - 2 ]
   oO0O0oo = len ( oOo00Oo0o00oo ) * "-"
   if ( oOo00Oo0o00oo == oO0O0oo ) : break
   if 64 - 64: OoOoOO00 % OoOoOO00 + o0oOOo0O0Ooo + Oo0Ooo
   if 79 - 79: Oo0Ooo - OoooooooOO % I1Ii111 + OoooooooOO - I11i % OoOoOO00
 ii1111iII . close ( )
 return
 if 5 - 5: OoOoOO00 . Oo0Ooo
 if 89 - 89: I1IiiI / iII111i / OoooooooOO - i11iIiiIii + I1IiiI
 if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
 if 64 - 64: ooOoO0o / i1IIi % iII111i
 if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
 if 99 - 99: I1Ii111
 if 75 - 75: ooOoO0o . OOooOOo / IiII
 if 84 - 84: OoooooooOO . I1IiiI / o0oOOo0O0Ooo
def oOO0O00o0O0 ( bottle_port ) :
 global Oo0o
 global Ii1iI
 global Oo
 global I1Ii11I1Ii1i
 global Ooo
 global o0oOoO00o
 if 68 - 68: i11iIiiIii + OoO0O00
 lisp . lisp_i_am ( "core" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "core-process starting up" )
 lisp . lisp_uptime = lisp . lisp_get_timestamp ( )
 lisp . lisp_version = commands . getoutput ( "cat lisp-version.txt" )
 Oo0o = commands . getoutput ( "cat lisp-build-date.txt" )
 if 13 - 13: ooOoO0o - I1IiiI
 if 23 - 23: I1IiiI
 if 7 - 7: iII111i % I1ii11iIi11i
 if 64 - 64: I1Ii111 + i11iIiiIii
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
 if 68 - 68: IiII . ooOoO0o
 if 64 - 64: i1IIi + Oo0Ooo * I1IiiI / OOooOOo
 if 3 - 3: Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
 if 50 - 50: iIii1I11I1II1 * oO0o
 lisp . lisp_ipc_lock = multiprocessing . Lock ( )
 if 85 - 85: i1IIi
 if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
 if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
 if 54 - 54: OoOoOO00 * iII111i + OoO0O00
 if 93 - 93: o0oOOo0O0Ooo / I1IiiI
 if 47 - 47: Oo0Ooo * OOooOOo
 if 98 - 98: oO0o - oO0o . ooOoO0o
 if ( os . path . exists ( "lisp.py" ) ) : lisp . lisp_version += "+"
 if 60 - 60: I1IiiI * I1ii11iIi11i / O0 + I11i + IiII
 if 66 - 66: IiII * Oo0Ooo . OoooooooOO * I1Ii111
 if 93 - 93: IiII / i1IIi
 if 47 - 47: ooOoO0o - Ii1I
 if 98 - 98: oO0o . I1Ii111 / OoOoOO00 . ooOoO0o
 if 1 - 1: OOooOOo
 OoOo0o0OOoO0 = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 if ( os . getenv ( "LISP_ANYCAST_MR" ) == None or lisp . lisp_myrlocs [ 0 ] == None ) :
  Ii1iI = lisp . lisp_open_listen_socket ( OoOo0o0OOoO0 ,
 str ( lisp . LISP_CTRL_PORT ) )
 else :
  OoOo0o0OOoO0 = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( )
  Ii1iI = lisp . lisp_open_listen_socket ( OoOo0o0OOoO0 ,
 str ( lisp . LISP_CTRL_PORT ) )
  if 30 - 30: Ii1I % I11i + o0oOOo0O0Ooo
 lisp . lprint ( "Listen on {}, port 4342" . format ( OoOo0o0OOoO0 ) )
 if 65 - 65: iIii1I11I1II1 . iII111i / Ii1I
 if 12 - 12: I1IiiI + I1Ii111
 if 80 - 80: oO0o . O0
 if 90 - 90: II111iiii / OoO0O00 / Ii1I
 if 70 - 70: Ii1I - II111iiii . Oo0Ooo / Oo0Ooo
 if 30 - 30: oO0o . OoO0O00 + I11i / iIii1I11I1II1 % Oo0Ooo / oO0o
 if ( lisp . lisp_external_data_plane ( ) == False ) :
  o0oOoO00o = lisp . lisp_open_listen_socket ( OoOo0o0OOoO0 ,
 str ( lisp . LISP_DATA_PORT ) )
  lisp . lprint ( "Listen on {}, port 4341" . format ( OoOo0o0OOoO0 ) )
  if 3 - 3: I1ii11iIi11i / II111iiii
  if 73 - 73: OoO0O00 * OoooooooOO - OoooooooOO + I1IiiI * Oo0Ooo
  if 87 - 87: o0oOOo0O0Ooo / IiII / i11iIiiIii
  if 95 - 95: i1IIi / Ii1I / Ii1I
  if 65 - 65: I1Ii111 + iII111i * iII111i
  if 79 - 79: i1IIi / Oo0Ooo - I1IiiI . O0
 Oo = lisp . lisp_open_send_socket ( "lisp-core" , "" )
 Oo . settimeout ( 3 )
 if 56 - 56: IiII % O0 * i1IIi - II111iiii
 if 74 - 74: i1IIi - OoOoOO00 % oO0o . O0 - OoooooooOO
 if 84 - 84: I1Ii111
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
 I1Ii11I1Ii1i = lisp . lisp_open_listen_socket ( "" , "lisp-core-pkt" )
 if 9 - 9: i1IIi - OoOoOO00
 Ooo = [ Ii1iI , Ii1iI ,
 Oo ]
 if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
 if 46 - 46: Ii1I
 if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
 if 87 - 87: I1ii11iIi11i / I1IiiI
 if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
 threading . Thread ( target = oo0oO0oOo0O ,
 args = [ I1Ii11I1Ii1i , Ooo ] ) . start ( )
 if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
 if 11 - 11: I1ii11iIi11i - OoooooooOO
 if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
 if 27 - 27: IiII + iIii1I11I1II1 / Oo0Ooo + OoO0O00 % Oo0Ooo + OoO0O00
 if 77 - 77: Oo0Ooo * ooOoO0o % Ii1I
 if 2 - 2: I11i / Oo0Ooo / Ii1I / I1ii11iIi11i / OoooooooOO
 if ( os . path . exists ( "./lisp.config" ) == False ) :
  lisp . lprint ( ( "./lisp.config does not exist, creating a copy " + "from lisp.config.example" ) )
  if 22 - 22: iIii1I11I1II1 * I1IiiI / I11i + OoOoOO00
  O0O0oOOo0O ( )
  if 98 - 98: OOooOOo
  if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
  if 75 - 75: OoO0O00 % OoooooooOO
  if 16 - 16: O0 / i1IIi
  if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
  if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
 iIiI1I ( Ii1iI )
 if 2 - 2: o0oOOo0O0Ooo . Ii1I % OoOoOO00
 threading . Thread ( target = lispconfig . lisp_config_process ,
 args = [ Oo ] ) . start ( )
 if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
 if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
 if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
 if 58 - 58: iII111i
 threading . Thread ( target = o0oO00OOo0oO ,
 args = [ bottle_port ] ) . start ( )
 threading . Thread ( target = O0OOOOoO00oo , args = [ ] ) . start ( )
 if 2 - 2: II111iiii + i1IIi
 if 68 - 68: OOooOOo + Ii1I
 if 58 - 58: IiII * Ii1I . i1IIi
 if 19 - 19: oO0o
 threading . Thread ( target = OOOOo0o0O0o ,
 args = [ Oo ] ) . start ( )
 if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
 if 94 - 94: iIii1I11I1II1 + IiII
 if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
 if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
 threading . Thread ( target = oo00oO ) . start ( )
 return ( True )
 if 36 - 36: OoOoOO00 . i11iIiiIii
 if 81 - 81: Oo0Ooo * iII111i * OoO0O00
 if 85 - 85: O0 * oO0o
 if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
 if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
 if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
 if 75 - 75: IiII / OoooooooOO . I1IiiI + I1Ii111 - II111iiii
def I1i11 ( ) :
 if 5 - 5: o0oOOo0O0Ooo - i11iIiiIii . IiII
 if 10 - 10: OoOoOO00 . IiII * iIii1I11I1II1 - oO0o - OoOoOO00 / I1Ii111
 if 13 - 13: oO0o + OoOoOO00 % IiII % OoooooooOO
 if 22 - 22: I1Ii111
 lisp . lisp_close_socket ( Oo , "lisp-core" )
 lisp . lisp_close_socket ( I1Ii11I1Ii1i , "lisp-core-pkt" )
 lisp . lisp_close_socket ( Ii1iI , "" )
 lisp . lisp_close_socket ( o0oOoO00o , "" )
 return
 if 23 - 23: O0
 if 41 - 41: i1IIi . OOooOOo / ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
 if 14 - 14: I1ii11iIi11i - i11iIiiIii * I1Ii111
 if 39 - 39: OoooooooOO
 if 19 - 19: i11iIiiIii
 if 80 - 80: I1IiiI
 if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
 if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
 if 26 - 26: o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
 if 97 - 97: i1IIi
 if 46 - 46: I1ii11iIi11i
 if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
def iIiI1I ( lisp_socket ) :
 if 23 - 23: I11i
 ii1111iII = open ( "./lisp.config" , "r" ) ; iiiiI = ii1111iII . read ( ) ; ii1111iII . close ( )
 iiiiI = iiiiI . split ( "\n" )
 if 36 - 36: IiII . iII111i - i1IIi + I1Ii111
 if 54 - 54: OoooooooOO . oO0o - iII111i
 if 76 - 76: I1Ii111
 if 61 - 61: ooOoO0o / II111iiii * ooOoO0o * OoOoOO00 * I1Ii111 . i11iIiiIii
 if 26 - 26: I1Ii111 / ooOoO0o - OoO0O00 . iIii1I11I1II1
 O0o0OOo0o0o = False
 for OOoO in iiiiI :
  if ( OOoO [ 0 : 1 ] == "#-" and OOoO [ - 2 : - 1 ] == "-#" ) : break
  if ( OOoO == "" or OOoO [ 0 ] == "#" ) : continue
  if ( OOoO . find ( "decentralized-push-xtr = yes" ) == - 1 ) : continue
  O0o0OOo0o0o = True
  break
  if 90 - 90: I11i
 if ( O0o0OOo0o0o == False ) : return
 if 95 - 95: OoO0O00
 if 68 - 68: iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00 - II111iiii - iIii1I11I1II1
 if 75 - 75: ooOoO0o . I1IiiI * II111iiii
 if 99 - 99: iIii1I11I1II1 * I1ii11iIi11i + IiII
 if 70 - 70: i1IIi % ooOoO0o . I1ii11iIi11i - IiII + OOooOOo
 OO0o0oo = [ ]
 o0oo0oOOOo00 = False
 for OOoO in iiiiI :
  if ( OOoO [ 0 : 1 ] == "#-" and OOoO [ - 2 : - 1 ] == "-#" ) : break
  if ( OOoO == "" or OOoO [ 0 ] == "#" ) : continue
  if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
  if ( OOoO . find ( "lisp map-server" ) != - 1 ) :
   o0oo0oOOOo00 = True
   continue
   if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
  if ( OOoO [ 0 ] == "}" ) :
   o0oo0oOOOo00 = False
   continue
   if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
   if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
   if 100 - 100: i1IIi % Ii1I
   if 55 - 55: I1IiiI + iII111i
   if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
  if ( o0oo0oOOOo00 and OOoO . find ( "address = " ) != - 1 ) :
   i1I11 = OOoO . split ( "address = " ) [ 1 ]
   OoO00 = int ( i1I11 . split ( "." ) [ 0 ] )
   if ( OoO00 >= 224 and OoO00 < 240 ) : OO0o0oo . append ( i1I11 )
   if 57 - 57: Oo0Ooo - OoooooooOO % I1ii11iIi11i . OoO0O00 * II111iiii
   if 72 - 72: I1Ii111 + ooOoO0o . IiII % II111iiii
 if ( i1I11 == [ ] ) : return
 if 58 - 58: ooOoO0o
 if 45 - 45: o0oOOo0O0Ooo
 if 67 - 67: iII111i + ooOoO0o
 if 25 - 25: i1IIi - i11iIiiIii
 iIi = commands . getoutput ( 'ifconfig eth0 | egrep "inet "' )
 if ( iIi == "" ) : return
 i1IIII1II = iIi . split ( ) [ 1 ]
 if 89 - 89: I11i % iII111i * Oo0Ooo / I1Ii111 * Oo0Ooo / ooOoO0o
 if 14 - 14: i1IIi * iIii1I11I1II1 - Ii1I * OoOoOO00 - iII111i / oO0o
 if 73 - 73: I1ii11iIi11i - OoOoOO00 * O0 - OoOoOO00 - OoO0O00
 if 96 - 96: I1ii11iIi11i - O0
 i1i111iI = socket . inet_aton ( i1IIII1II )
 for i1I11 in OO0o0oo :
  lisp_socket . setsockopt ( socket . SOL_SOCKET , socket . SO_REUSEADDR , 1 )
  lisp_socket . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_IF , i1i111iI )
  I1i = socket . inet_aton ( i1I11 ) + i1i111iI
  lisp_socket . setsockopt ( socket . IPPROTO_IP , socket . IP_ADD_MEMBERSHIP , I1i )
  lisp . lprint ( "Setting multicast listen socket for group {}" . format ( i1I11 ) )
  if 72 - 72: I11i * OoOoOO00 % I1Ii111 % ooOoO0o
  if 22 - 22: OOooOOo - I1ii11iIi11i / IiII
 return
 if 95 - 95: o0oOOo0O0Ooo
 if 69 - 69: oO0o . I11i
 if 36 - 36: ooOoO0o
 if 62 - 62: I11i % oO0o / OoooooooOO % OoooooooOO
oo0 = int ( sys . argv [ 1 ] ) if ( len ( sys . argv ) > 1 ) else 8080
if 58 - 58: OoO0O00 + iIii1I11I1II1 % O0 + I11i + OoOoOO00 * OoooooooOO
if 41 - 41: oO0o * I1IiiI
if 76 - 76: oO0o . O0 * OoooooooOO + ooOoO0o
if 53 - 53: Oo0Ooo
if ( oOO0O00o0O0 ( oo0 ) == False ) :
 lisp . lprint ( "lisp_core_startup() failed" )
 lisp . lisp_print_banner ( "lisp-core abnormal exit" )
 exit ( 1 )
 if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
 if 58 - 58: IiII % iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * iII111i
while ( True ) :
 if 32 - 32: OoooooooOO + o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o - I1Ii111 * I1Ii111
 if 55 - 55: iIii1I11I1II1 + I1IiiI - Oo0Ooo
 if 24 - 24: OoO0O00 / I1Ii111 + iII111i * I11i * iII111i
 if 10 - 10: I1IiiI - I1ii11iIi11i - Oo0Ooo - o0oOOo0O0Ooo
 oOOo0 , oo00O00oO , iIiIIIi , o0000oO = lisp . lisp_receive ( Ii1iI , False )
 if 21 - 21: OoooooooOO + I1Ii111
 if ( oo00O00oO == "" ) : break
 if 43 - 43: i11iIiiIii . I1ii11iIi11i . oO0o
 if 31 - 31: Ii1I % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
 if 74 - 74: I1IiiI . ooOoO0o / iII111i . IiII
 if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
 oo00O00oO = lisp . lisp_convert_6to4 ( oo00O00oO )
 OO0o0o0oo ( Ooo , oo00O00oO , iIiIIIi , o0000oO )
 if 72 - 72: i1IIi
 if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
I1i11 ( )
lisp . lisp_print_banner ( "lisp-core normal exit" )
exit ( 0 )
if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
if 89 - 89: IiII - i1IIi - IiII
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
