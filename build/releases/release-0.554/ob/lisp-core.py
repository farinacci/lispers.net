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
import json
import sys
import socket
import thread
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
try :
 from cherrypy . wsgiserver import CherryPyWSGIServer as wsgi_server
 from cherrypy . wsgiserver . ssl_pyopenssl import pyOpenSSLAdapter as ssl_adaptor
except :
 from cheroot . wsgi import Server as wsgi_server
 from cheroot . ssl . builtin import BuiltinSSLAdapter as ssl_adaptor
 if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
 if 46 - 46: ooOoO0o * I11i - OoooooooOO
 if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
 if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
 if 94 - 94: i1IIi % Oo0Ooo
 if 68 - 68: Ii1I / O0
 if 46 - 46: O0 * II111iiii / IiII * Oo0Ooo * iII111i . I11i
Oo0oO0ooo = ""
if 56 - 56: I11i - i1IIi
o00oOoo = None
O0OOo = None
II1Iiii1111i = None
i1IIi11111i = [ None , None , None ]
o000o0o00o0Oo = None
if 80 - 80: OoooooooOO . I1IiiI
if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
if 58 - 58: i11iIiiIii % I1Ii111
if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
if 13 - 13: OOooOOo * oO0o * I1IiiI
if 55 - 55: II111iiii
@ bottle . route ( '/lisp/api' , method = "get" )
@ bottle . route ( '/lisp/api/<command>' , method = "get" )
@ bottle . route ( '/lisp/api/<command>/<data_structure>' , method = "get" )
def IIIiI11ii ( command = "" , data_structure = "" ) :
 O000oo = [ { "?" : [ { "?" : "not-auth" } ] } ]
 if 3 - 3: iII111i + O0
 if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
 if 78 - 78: OoO0O00
 if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
 if ( bottle . request . auth != None ) :
  O0O00Ooo , OOoooooO = bottle . request . auth
  if ( lispconfig . lisp_find_user_account ( O0O00Ooo , OOoooooO ) == False ) :
   return ( json . dumps ( O000oo ) )
   if 14 - 14: I11i % O0
 else :
  if ( bottle . request . headers [ "User-Agent" ] . find ( "python" ) != - 1 ) :
   return ( json . dumps ( O000oo ) )
   if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
  if ( lispconfig . lisp_validate_user ( ) == False ) :
   return ( json . dumps ( O000oo ) )
   if 77 - 77: Oo0Ooo . IiII % ooOoO0o
   if 42 - 42: oO0o - i1IIi / i11iIiiIii + OOooOOo + OoO0O00
   if 17 - 17: oO0o . Oo0Ooo . I1ii11iIi11i
   if 3 - 3: OoOoOO00 . Oo0Ooo . I1IiiI / Ii1I
   if 38 - 38: II111iiii % i11iIiiIii . ooOoO0o - OOooOOo + Ii1I
   if 66 - 66: OoooooooOO * OoooooooOO . OOooOOo . i1IIi - OOooOOo
   if 77 - 77: I11i - iIii1I11I1II1
 if ( command == "data" and data_structure != "" ) :
  Ooo = bottle . request . body . readline ( )
  O000oo = json . loads ( Ooo ) if Ooo != "" else ""
  if ( O000oo != "" ) : O000oo = O000oo . values ( ) [ 0 ]
  if ( O000oo == [ ] ) : O000oo = ""
  if 68 - 68: I11i + OOooOOo . iIii1I11I1II1 - IiII % iIii1I11I1II1 - ooOoO0o
  if ( type ( O000oo ) == dict and type ( O000oo . values ( ) [ 0 ] ) == dict ) :
   O000oo = O000oo . values ( ) [ 0 ]
   if 79 - 79: Oo0Ooo + I1IiiI - iII111i
   if 83 - 83: ooOoO0o
  O000oo = OO00o0OOO0 ( data_structure , O000oo )
  return ( O000oo )
  if 27 - 27: O0 % i1IIi * oO0o + i11iIiiIii + OoooooooOO * i1IIi
  if 80 - 80: I11i * i11iIiiIii / I1Ii111
  if 9 - 9: Ii1I + oO0o % Ii1I + i1IIi . OOooOOo
  if 31 - 31: o0oOOo0O0Ooo + I11i + I11i / II111iiii
  if 26 - 26: OoooooooOO
 if ( command != "" ) :
  command = "lisp " + command
 else :
  Ooo = bottle . request . body . readline ( )
  if ( Ooo == "" ) :
   O000oo = [ { "?" : [ { "?" : "no-body" } ] } ]
   return ( json . dumps ( O000oo ) )
   if 12 - 12: OoooooooOO % OoOoOO00 / ooOoO0o % o0oOOo0O0Ooo
   if 29 - 29: OoooooooOO
  O000oo = json . loads ( Ooo )
  command = O000oo . keys ( ) [ 0 ]
  if 23 - 23: o0oOOo0O0Ooo . II111iiii
  if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
 O000oo = lispconfig . lisp_get_clause_for_api ( command )
 return ( json . dumps ( O000oo ) )
 if 45 - 45: I1Ii111 . OoOoOO00
 if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
 if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
 if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
 if 8 - 8: OoOoOO00
 if 60 - 60: I11i / I11i
 if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
def oo0 ( ) :
 O000oo = { }
 O000oo [ "hostname" ] = socket . gethostname ( )
 O000oo [ "system-uptime" ] = commands . getoutput ( "uptime" )
 O000oo [ "lisp-uptime" ] = lisp . lisp_print_elapsed ( lisp . lisp_uptime )
 O000oo [ "lisp-version" ] = lisp . lisp_version
 if 57 - 57: OOooOOo . OOooOOo
 OooOooo = "yes" if os . path . exists ( "./logs/lisp-traceback.log" ) else "no"
 O000oo [ "traceback-log" ] = OooOooo
 if 97 - 97: ooOoO0o - OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - OoooooooOO
 OoOo00o = lisp . lisp_myrlocs [ 0 ]
 o0OOoo0OO0OOO = lisp . lisp_myrlocs [ 1 ]
 OoOo00o = "none" if ( OoOo00o == None ) else OoOo00o . print_address_no_iid ( )
 o0OOoo0OO0OOO = "none" if ( o0OOoo0OO0OOO == None ) else o0OOoo0OO0OOO . print_address_no_iid ( )
 O000oo [ "lisp-rlocs" ] = [ OoOo00o , o0OOoo0OO0OOO ]
 return ( json . dumps ( O000oo ) )
 if 19 - 19: oO0o % i1IIi % o0oOOo0O0Ooo
 if 93 - 93: iIii1I11I1II1 % oO0o * i1IIi
 if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
 if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
 if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
 if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 if 58 - 58: i11iIiiIii % I11i
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
 if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
 if 16 - 16: I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
 if 44 - 44: oO0o
 if 88 - 88: I1Ii111 % Ii1I . II111iiii
 if 38 - 38: o0oOOo0O0Ooo
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
 if 26 - 26: iII111i
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
def OO00o0OOO0 ( data_structure , data ) :
 iII1 = [ "site-cache" , "map-cache" , "system" , "map-resolver" ,
 "map-server" , "database-mapping" , "site-cache-summary" ]
 if 30 - 30: II111iiii - OOooOOo - i11iIiiIii % OoOoOO00 - II111iiii * Ii1I
 if ( data_structure not in iII1 ) : return ( json . dumps ( [ ] ) )
 if 61 - 61: oO0o - I11i % OOooOOo
 if 84 - 84: oO0o * OoO0O00 / I11i - O0
 if 30 - 30: iIii1I11I1II1 / ooOoO0o - I1Ii111 - II111iiii % iII111i
 if 49 - 49: I1IiiI % ooOoO0o . ooOoO0o . I11i * ooOoO0o
 if ( data_structure == "system" ) : return ( oo0 ( ) )
 if 97 - 97: Ii1I + o0oOOo0O0Ooo . OOooOOo + I1ii11iIi11i % iII111i
 if 95 - 95: i1IIi
 if 3 - 3: I1Ii111 - O0 / I1Ii111 % OoO0O00 / I1Ii111 . I1IiiI
 if 50 - 50: IiII
 if ( data != "" ) : data = json . dumps ( data )
 i11I1iIiII = lisp . lisp_api_ipc ( "lisp-core" , data_structure + "%" + data )
 if 96 - 96: Oo0Ooo
 if ( data_structure in [ "map-cache" , "map-resolver" ] ) :
  if ( lisp . lisp_is_running ( "lisp-rtr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( i11I1iIiII , O0OOo , "lisp-rtr" )
  elif ( lisp . lisp_is_running ( "lisp-itr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( i11I1iIiII , O0OOo , "lisp-itr" )
  else :
   return ( json . dumps ( [ ] ) )
   if 45 - 45: O0 * o0oOOo0O0Ooo % Oo0Ooo * OoooooooOO + iII111i . OoOoOO00
   if 67 - 67: i11iIiiIii - i1IIi % I1ii11iIi11i . O0
 if ( data_structure in [ "map-server" , "database-mapping" ] ) :
  if ( lisp . lisp_is_running ( "lisp-etr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( i11I1iIiII , O0OOo , "lisp-etr" )
  elif ( lisp . lisp_is_running ( "lisp-itr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( i11I1iIiII , O0OOo , "lisp-itr" )
  else :
   return ( json . dumps ( [ ] ) )
   if 77 - 77: IiII / I1IiiI
   if 15 - 15: IiII . iIii1I11I1II1 . OoooooooOO / i11iIiiIii - Ii1I . i1IIi
 if ( data_structure in [ "site-cache" , "site-cache-summary" ] ) :
  if ( lisp . lisp_is_running ( "lisp-ms" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( i11I1iIiII , O0OOo , "lisp-ms" )
  else :
   return ( json . dumps ( [ ] ) )
   if 33 - 33: I11i . o0oOOo0O0Ooo
   if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
   if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 lisp . lprint ( "Waiting for api get-data '{}', parmameters: '{}'" . format ( data_structure , data ) )
 if 91 - 91: O0
 if 61 - 61: II111iiii
 O0OOO , II11iIiIIIiI , o0o , o00 = lisp . lisp_receive ( O0OOo , True )
 lisp . lisp_ipc_lock . release ( )
 return ( o00 )
 if 56 - 56: I1IiiI - Oo0Ooo . Ii1I - IiII
 if 73 - 73: Oo0Ooo - i1IIi - i1IIi - iII111i . Ii1I + I1ii11iIi11i
 if 81 - 81: iII111i * oO0o - I1Ii111 . II111iiii % I11i / I1IiiI
 if 34 - 34: IiII
 if 57 - 57: oO0o . I11i . i1IIi
 if 42 - 42: I11i + I1ii11iIi11i % O0
 if 6 - 6: oO0o
@ bottle . route ( '/lisp/api' , method = "put" )
@ bottle . route ( '/lisp/api/<command>' , method = "put" )
@ bottle . route ( '/lisp/api/<command>' , method = "delete" )
def oOOo0oOo0 ( command = "" ) :
 O000oo = [ { "?" : [ { "?" : "not-auth" } ] } ]
 if ( bottle . request . auth == None ) : return ( O000oo )
 if 49 - 49: Oo0Ooo . i11iIiiIii - i1IIi / II111iiii . I1IiiI
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
 if 92 - 92: iII111i
 if ( bottle . request . auth != None ) :
  O0O00Ooo , OOoooooO = bottle . request . auth
  if ( lispconfig . lisp_find_user_account ( O0O00Ooo , OOoooooO ) == False ) :
   return ( json . dumps ( O000oo ) )
   if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 else :
  if ( bottle . request . headers [ "User-Agent" ] . find ( "python" ) != - 1 ) :
   return ( json . dumps ( O000oo ) )
   if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
  if ( lispconfig . lisp_validate_user ( ) == False ) :
   return ( json . dumps ( O000oo ) )
   if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
   if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
   if 51 - 51: O0 + iII111i
   if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
   if 48 - 48: O0
   if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
   if 41 - 41: Ii1I - O0 - O0
 if ( command == "user-account" ) :
  if ( lispconfig . lisp_is_user_superuser ( O0O00Ooo ) == False ) :
   O000oo = [ { "user-account" : [ { "?" : "not-auth" } ] } ]
   return ( json . dumps ( O000oo ) )
   if 68 - 68: OOooOOo % I1Ii111
   if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
   if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
   if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
   if 23 - 23: O0
   if 85 - 85: Ii1I
 Ooo = bottle . request . body . readline ( )
 if ( Ooo == "" ) :
  O000oo = [ { "?" : [ { "?" : "no-body" } ] } ]
  return ( json . dumps ( O000oo ) )
  if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
  if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
 O000oo = json . loads ( Ooo )
 if ( command != "" ) :
  command = "lisp " + command
 else :
  command = O000oo [ 0 ] . keys ( ) [ 0 ]
  if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
  if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
  if 77 - 77: iIii1I11I1II1 * OoO0O00
  if 95 - 95: I1IiiI + i11iIiiIii
  if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
  if 80 - 80: II111iiii
 lisp . lisp_ipc_lock . acquire ( )
 if ( bottle . request . method == "DELETE" ) :
  O000oo = lispconfig . lisp_remove_clause_for_api ( O000oo )
 else :
  O000oo = lispconfig . lisp_put_clause_for_api ( O000oo )
  if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 lisp . lisp_ipc_lock . release ( )
 return ( json . dumps ( O000oo ) )
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
  o00 = "Permission denied"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( o00 ) ) )
  if 32 - 32: I1IiiI * Oo0Ooo
  if 78 - 78: OOooOOo - OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii
 if ( xtr not in [ "itr" , "etr" , "rtr" ] ) :
  o00 = "Invalid URL"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( o00 ) ) )
  if 29 - 29: I1IiiI % I1IiiI
 Oo0O0 = "show {}-keys" . format ( xtr )
 return ( lispconfig . lisp_process_show_command ( O0OOo , Oo0O0 ) )
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
 II = o0oooOO00 . radius * 1000
 if 7 - 7: I1ii11iIi11i - I1IiiI . iIii1I11I1II1 - i1IIi
 o0OOOoO0 = open ( "./lispers.net-geo.html" , "r" ) ; o0OoOo00o0o = o0OOOoO0 . read ( ) ; o0OOOoO0 . close ( )
 o0OoOo00o0o = o0OoOo00o0o . replace ( "$LAT" , str ( iiIiii1IIIII ) )
 o0OoOo00o0o = o0OoOo00o0o . replace ( "$LON" , str ( o00o ) )
 o0OoOo00o0o = o0OoOo00o0o . replace ( "$RADIUS" , str ( II ) )
 return ( o0OoOo00o0o )
 if 41 - 41: ooOoO0o % OoO0O00 - Oo0Ooo * I1Ii111 * Oo0Ooo
 if 69 - 69: OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 if 23 - 23: i11iIiiIii
 if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
 if 81 - 81: IiII % i1IIi . iIii1I11I1II1
 if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
 if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
@ bottle . route ( '/lisp/login' , method = "get" )
def O0O00Oo ( ) :
 return ( lispconfig . lisp_login_page ( ) )
 if 31 - 31: OOooOOo
 if 23 - 23: I1Ii111 . IiII
 if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
 if 42 - 42: Oo0Ooo
 if 76 - 76: I1IiiI * iII111i % I1Ii111
 if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
 if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
 if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
@ bottle . route ( '/lisp/login' , method = "post" )
def oOoOOo0O ( ) :
 if ( lispconfig . lisp_validate_user ( ) ) :
  return ( lispconfig . lisp_landing_page ( ) )
  if 84 - 84: OoO0O00 + i1IIi - II111iiii . I1ii11iIi11i * OoooooooOO + I1IiiI
 return ( O0O00Oo ( ) )
 if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
 if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
 if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
 if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
 if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
 if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
 if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
@ bottle . route ( '/lisp' )
def OoOoo00Ooo00 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 57 - 57: I1Ii111
 return ( lispconfig . lisp_landing_page ( ) )
 if 32 - 32: Ii1I - Oo0Ooo % OoooooooOO . iII111i / IiII + I1IiiI
 if 76 - 76: ooOoO0o
 if 73 - 73: O0 * iII111i + Ii1I + ooOoO0o
 if 40 - 40: II111iiii . OoOoOO00 * I1Ii111 + OOooOOo + OOooOOo
 if 9 - 9: I11i % OoooooooOO . oO0o % I11i
 if 32 - 32: i11iIiiIii
 if 31 - 31: iIii1I11I1II1 / OoO0O00 / I1ii11iIi11i
@ bottle . route ( '/lisp/traceback' )
def iiIiIi ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 39 - 39: I1Ii111
  if 91 - 91: OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoOoOO00 + O0
 iIiii1iI1 = True
 if 33 - 33: IiII % iIii1I11I1II1 * I1IiiI
 if 95 - 95: ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 if ( os . path . exists ( "./logs/lisp-traceback.log" ) ) :
  o00 = commands . getoutput ( "cat ./logs/lisp-traceback.log" )
  if ( o00 ) :
   o00 = o00 . replace ( "----------" , "<b>----------</b>" )
   o00 = o00 . replace ( "\n" , "<br>" )
   iIiii1iI1 = False
   if 41 - 41: i1IIi - I11i - Ii1I
   if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
   if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
   if 44 - 44: II111iiii
   if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
   if 35 - 35: iIii1I11I1II1
 if ( iIiii1iI1 ) :
  o00 = ""
  I1i = "egrep --with-filename Traceback ./logs/*.log"
  iIII = commands . getoutput ( I1i )
  iIII = iIII . split ( "\n" )
  for o0o0O in iIII :
   if ( o0o0O . find ( ":" ) == - 1 ) : continue
   OOoO = o0o0O . split ( ":" )
   if ( OOoO [ 1 ] == "0" ) : continue
   o00 += "Found Tracebacks in log file {}<br>" . format ( OOoO [ 0 ] )
   iIiii1iI1 = False
   if 68 - 68: ooOoO0o
  o00 = o00 [ 0 : - 4 ]
  if 25 - 25: I1ii11iIi11i . ooOoO0o
  if 24 - 24: oO0o / i11iIiiIii + oO0o
 if ( iIiii1iI1 ) :
  o00 = "No Tracebacks found - a stable system is a happy system"
  if 20 - 20: I11i + Ii1I / O0 % iIii1I11I1II1
  if 88 - 88: OoOoOO00 / II111iiii
 o00 = lisp . lisp_print_cour ( o00 )
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
 if 87 - 87: I1ii11iIi11i - I1ii11iIi11i - iII111i + oO0o
 if 82 - 82: oO0o / iIii1I11I1II1 . I1IiiI . OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 if 46 - 46: Oo0Ooo
 if 1 - 1: iII111i
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
@ bottle . route ( '/lisp/show/not-supported' )
def oOoO0 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 77 - 77: iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
 return ( lispconfig . lisp_not_supported ( ) )
 if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
 if 17 - 17: i1IIi
 if 21 - 21: Oo0Ooo
 if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
@ bottle . route ( '/lisp/show/status' )
def I1ii11 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 74 - 74: Oo0Ooo - o0oOOo0O0Ooo . i1IIi
  if 43 - 43: iII111i / I1IiiI
  if 58 - 58: I1IiiI + i11iIiiIii % Ii1I . OoOoOO00
  if 13 - 13: i11iIiiIii + i1IIi * iIii1I11I1II1 % OoooooooOO - II111iiii * OOooOOo
  if 26 - 26: OoooooooOO * I1IiiI + OOooOOo
 o00 = ""
 I1111i = lispconfig . lisp_is_user_superuser ( None )
 if ( I1111i ) :
  IiIii1i111 = lisp . lisp_button ( "show configuration" , "/lisp/show/conf" )
  iI = lisp . lisp_button ( "show configuration diff" , "/lisp/show/diff" )
  o0o00 = lisp . lisp_button ( "archive configuration" , "/lisp/archive/conf" )
  IIi = lisp . lisp_button ( "clear configuration" , "/lisp/clear/conf/verify" )
  o0o0O = lisp . lisp_button ( "log flows" , "/lisp/log/flows" )
  oOoO00oo0O = lisp . lisp_button ( "install LISP software" , "/lisp/install/image" )
  IiiiI = lisp . lisp_button ( "restart LISP subsystem" , "/lisp/restart/verify" )
  if 61 - 61: OOooOOo % OOooOOo * o0oOOo0O0Ooo / o0oOOo0O0Ooo
  o00 = "<center>{}{}{}{}{}{}{}</center><hr>" . format ( IiIii1i111 , iI , o0o00 , IIi ,
 o0o0O , oOoO00oo0O , IiiiI )
  if 75 - 75: IiII . ooOoO0o
  if 50 - 50: OoOoOO00
 O00o0OO0000oo = commands . getoutput ( "uptime" )
 i1OO0oOOoo = commands . getoutput ( "uname -pv" )
 oOOO00o000o = lisp . lisp_version . replace ( "+" , "" )
 if 9 - 9: oO0o + I11i / I11i
 if 12 - 12: OoooooooOO % o0oOOo0O0Ooo * I11i % iIii1I11I1II1 / Ii1I
 if 27 - 27: i11iIiiIii % II111iiii % I11i . O0 - Oo0Ooo + OoOoOO00
 if 57 - 57: iIii1I11I1II1 / I11i - i1IIi
 if 51 - 51: IiII
 ii11I1 = multiprocessing . cpu_count ( )
 if 75 - 75: OoO0O00 / II111iiii % O0
 Ii111iIi1iIi = O00o0OO0000oo . find ( ", load" )
 O00o0OO0000oo = O00o0OO0000oo [ 0 : Ii111iIi1iIi ]
 IIIII = lisp . lisp_print_elapsed ( lisp . lisp_uptime )
 if 78 - 78: Ii1I * i1IIi
 iI11 = "Not available"
 if 96 - 96: OOooOOo
 if 85 - 85: o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . O0 % I1Ii111
 if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
 if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
 Oo0O0 = "ps auww" if lisp . lisp_is_macos ( ) else "ps aux"
 ooo0O = commands . getoutput ( "{} | egrep 'PID|python lisp|python -O lisp' | egrep -v grep" . format ( Oo0O0 ) )
 if 16 - 16: OoOoOO00
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
 ooo0O = ooo0O . replace ( " " , lisp . space ( 1 ) )
 ooo0O = ooo0O . replace ( "\n" , "<br>" )
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if ( i1OO0oOOoo . find ( "Darwin" ) != - 1 ) :
  ii11I1 = ii11I1 / 2
  iI11 = commands . getoutput ( "top -l 1 | head -50" )
  iI11 = iI11 . split ( "PID" )
  iI11 = iI11 [ 0 ]
  if 45 - 45: I1Ii111
  if 83 - 83: OoOoOO00 . OoooooooOO
  if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
  if 62 - 62: OoO0O00 / I1ii11iIi11i
  if 7 - 7: OoooooooOO . IiII
  Ii111iIi1iIi = iI11 . find ( "Load Avg" )
  O000OOO0OOo = iI11 [ 0 : Ii111iIi1iIi ] . find ( "threads" )
  i1i1I111iIi1 = iI11 [ 0 : O000OOO0OOo + 7 ]
  iI11 = i1i1I111iIi1 + "<br>" + iI11 [ Ii111iIi1iIi : : ]
  Ii111iIi1iIi = iI11 . find ( "CPU usage" )
  iI11 = iI11 [ 0 : Ii111iIi1iIi ] + "<br>" + iI11 [ Ii111iIi1iIi : : ]
  Ii111iIi1iIi = iI11 . find ( "SharedLibs:" )
  iI11 = iI11 [ 0 : Ii111iIi1iIi ] + "<br>" + iI11 [ Ii111iIi1iIi : : ]
  Ii111iIi1iIi = iI11 . find ( "MemRegions" )
  iI11 = iI11 [ 0 : Ii111iIi1iIi ] + "<br>" + iI11 [ Ii111iIi1iIi : : ]
  Ii111iIi1iIi = iI11 . find ( "PhysMem" )
  iI11 = iI11 [ 0 : Ii111iIi1iIi ] + "<br>" + iI11 [ Ii111iIi1iIi : : ]
  Ii111iIi1iIi = iI11 . find ( "VM:" )
  iI11 = iI11 [ 0 : Ii111iIi1iIi ] + "<br>" + iI11 [ Ii111iIi1iIi : : ]
  Ii111iIi1iIi = iI11 . find ( "Networks" )
  iI11 = iI11 [ 0 : Ii111iIi1iIi ] + "<br>" + iI11 [ Ii111iIi1iIi : : ]
  Ii111iIi1iIi = iI11 . find ( "Disks" )
  iI11 = iI11 [ 0 : Ii111iIi1iIi ] + "<br>" + iI11 [ Ii111iIi1iIi : : ]
 else :
  if 92 - 92: ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  iiiiI = commands . getoutput ( "top -b -n 1 | head -50" )
  iiiiI = iiiiI . split ( "PID" )
  iiiiI [ 1 ] = iiiiI [ 1 ] . replace ( " " , lisp . space ( 1 ) )
  iiiiI = iiiiI [ 0 ] + iiiiI [ 1 ]
  iI11 = iiiiI . replace ( "\n" , "<br>" )
  if 92 - 92: I11i . I1Ii111
  if 85 - 85: I1ii11iIi11i . I1Ii111
 O0O0Ooooo000 = commands . getoutput ( "cat release-notes.txt" )
 O0O0Ooooo000 = O0O0Ooooo000 . replace ( "\n" , "<br>" )
 if 65 - 65: OOooOOo * I1Ii111
 o00 += '''
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
        ''' . format ( oOOO00o000o , lisp . lisp_version , Oo0oO0ooo , IIIII ,
 O00o0OO0000oo , lisp . lisp_space ( 1 ) , ii11I1 , i1OO0oOOoo , ooo0O , iI11 ,
 O0O0Ooooo000 )
 if 79 - 79: OoooooooOO - I1IiiI
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
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
 o00 = "Configuration file saved to "
 o00 = lisp . lisp_print_sans ( o00 )
 o00 += lisp . lisp_print_cour ( "./lisp.config.archive" )
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
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
 o00 = "Configuration cleared, a backup copy is stored in "
 o00 = lisp . lisp_print_sans ( o00 )
 o00 += lisp . lisp_print_cour ( "./lisp.config.before-clear" )
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
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
 o00 = "<br>Are you sure you want to clear the configuration?"
 o00 = lisp . lisp_print_sans ( o00 )
 if 74 - 74: Oo0Ooo / i11iIiiIii - II111iiii * o0oOOo0O0Ooo
 IIi1IIIIi = lisp . lisp_button ( "yes" , "/lisp/clear/conf" )
 OOOoO = lisp . lisp_button ( "cancel" , "/lisp" )
 o00 += IIi1IIIIi + OOOoO + "<br>"
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
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
 o0o = ""
 if 98 - 98: o0oOOo0O0Ooo + O0 % i1IIi - OOooOOo + Oo0Ooo
 for OoOo000oOo0oo in [ "443" , "-8080" , "8080" ] :
  oO0O = 'ps auxww | egrep "lisp-core.pyo {}" | egrep -v grep' . format ( OoOo000oOo0oo )
  o00 = commands . getoutput ( oO0O )
  if ( o00 == "" ) : continue
  if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
  o00 = o00 . split ( "\n" ) [ 0 ]
  o00 = o00 . split ( " " )
  if ( o00 [ - 2 ] == "lisp-core.pyo" and o00 [ - 1 ] == OoOo000oOo0oo ) : o0o = OoOo000oOo0oo
  break
  if 56 - 56: O0
 return ( o0o )
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
  o00 = "Need to remove 'requiretty' from /etc/sudoers"
  o00 = lisp . lisp_print_sans ( o00 )
  return ( lispconfig . lisp_show_wrapper ( o00 ) )
  if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
  if 2 - 2: Ii1I - IiII
 lisp . lprint ( lisp . bold ( "LISP subsystem restart request received" , False ) )
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 o0o = Oo0oOooo000OO ( )
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
 oO0O = "sleep 1; sudo ./RESTART-LISP {}" . format ( o0o )
 thread . start_new_thread ( os . system , ( oO0O , ) )
 if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 o00 = lisp . lisp_print_sans ( "Restarting LISP subsystem ..." )
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
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
 o00 = "<br>Are you sure you want to restart the LISP subsystem?"
 o00 = lisp . lisp_print_sans ( o00 )
 if 62 - 62: OoOoOO00 / I1IiiI - I1ii11iIi11i - I1IiiI + i11iIiiIii + i1IIi
 IIi1IIIIi = lisp . lisp_button ( "yes" , "/lisp/restart" )
 OOOoO = lisp . lisp_button ( "cancel" , "/lisp" )
 o00 += IIi1IIIIi + OOOoO + "<br>"
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
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
  o00 = lisp . lisp_print_sans ( "Invalid lispers.net tarball file name" )
  return ( lispconfig . lisp_show_wrapper ( o00 ) )
  if 63 - 63: I1ii11iIi11i
  if 6 - 6: ooOoO0o / I1ii11iIi11i
 if ( lisp . lisp_is_ubuntu ( ) ) :
  oO0O = "python lisp-get-bits.pyo {} force 2>&1 > /dev/null" . format ( IIIIiii )
 else :
  oO0O = "python lisp-get-bits.pyo {} force >& /dev/null" . format ( IIIIiii )
  if 57 - 57: I11i
 ooo0O = os . system ( oO0O )
 if 67 - 67: OoO0O00 . ooOoO0o
 oO00oOo0OOO = IIIIiii . split ( "/" ) [ - 1 ]
 if 23 - 23: i1IIi . o0oOOo0O0Ooo * OoO0O00
 if ( os . path . exists ( oO00oOo0OOO ) ) :
  iIi1IiI = IIIIiii . split ( "release-" ) [ 1 ]
  iIi1IiI = iIi1IiI . split ( ".tgz" ) [ 0 ]
  if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
  o00 = "Install completed for release {}" . format ( iIi1IiI )
  o00 = lisp . lisp_print_sans ( o00 )
  if 53 - 53: Ii1I % Oo0Ooo
  o00 += "<br><br>" + lisp . lisp_button ( "restart LISP subsystem" ,
 "/lisp/restart/verify" ) + "<br>"
 else :
  oO0oIIIii1iiIi = lisp . lisp_print_cour ( IIIIiii )
  o00 = "Install failed for file {}" . format ( oO0oIIIii1iiIi )
  o00 = lisp . lisp_print_sans ( o00 )
  if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
  if 41 - 41: Ii1I % I1ii11iIi11i
 oO0oIIIii1iiIi = "Install request for file {} {}" . format ( IIIIiii ,
 "succeeded" if ( ooo0O == 0 ) else "failed" )
 lisp . lprint ( lisp . bold ( oO0oIIIii1iiIi , False ) )
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
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
 o00 = '''
        <form action="/lisp/install" method="post" style="display: inline;">
        {}
        <input type="text" name="image_url" size="75" required/>
        <input type="submit" style="background-color:transparent;border-radius:10px;" value="Submit" />
        </form><br>''' . format ( oO0oIIIii1iiIi )
 if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
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
 o00 = lisp . lisp_print_sans ( "Flow data appended to file " )
 iIi = "<a href='/lisp/show/log/lisp-flow/100'>logs/lisp-flows.log</a>"
 o00 += lisp . lisp_print_cour ( iIi )
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
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
 o00 = commands . getoutput ( Oo0O0 )
 if 89 - 89: II111iiii / oO0o
 if ( o00 ) :
  IIo0OoO00 = o00 . count ( keyword )
  o00 = lisp . convert_font ( o00 )
  o00 = o00 . replace ( "--\n--\n" , "--\n" )
  o00 = o00 . replace ( "\n" , "<br>" )
  o00 = o00 . replace ( "--<br>" , "<hr>" )
  o00 = "Found <b>{}</b> occurences<hr>" . format ( IIo0OoO00 ) + o00
 else :
  o00 = "Keyword {} not found" . format ( keyword )
  if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
  if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
  if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
  if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
  if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 iIi11ii = "<font color='blue'><b>{}</b>" . format ( keyword )
 o00 = o00 . replace ( keyword , iIi11ii )
 o00 = o00 . replace ( keyword , keyword + "</font>" )
 if 50 - 50: Ii1I / OoOoOO00 * Ii1I
 o00 = lisp . lisp_print_cour ( o00 )
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
@ bottle . post ( '/lisp/search/log/<name>/<num>' )
def o00oo0000 ( name = "" , num = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 44 - 44: Oo0Ooo % iIii1I11I1II1
  if 90 - 90: II111iiii + OoooooooOO % OoooooooOO
 I11Ii = bottle . request . forms . get ( "keyword" )
 return ( iII1Iii1I11i ( name , num , I11Ii ) )
 if 16 - 16: Oo0Ooo / i11iIiiIii
 if 64 - 64: i11iIiiIii / Ii1I * i1IIi
 if 73 - 73: Oo0Ooo - OoOoOO00 - oO0o - I1IiiI
 if 65 - 65: o0oOOo0O0Ooo
 if 7 - 7: IiII . OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - II111iiii
 if 37 - 37: I1Ii111 . OoOoOO00 / O0 * iII111i
 if 7 - 7: OoO0O00 * I11i + II111iiii % i11iIiiIii
@ bottle . route ( '/lisp/show/log/<name>/<num>' )
def i1i1IiIiIi1Ii ( name = "" , num = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 64 - 64: OOooOOo + OoooooooOO * OoooooooOO
  if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
  if 100 - 100: Ii1I + OoO0O00
  if 73 - 73: i1IIi - I1Ii111 % ooOoO0o / OoO0O00
  if 40 - 40: I1ii11iIi11i * ooOoO0o - I1IiiI / IiII / i11iIiiIii
 if ( num == "" ) : num = 100
 if 83 - 83: I1ii11iIi11i / I1Ii111 - i11iIiiIii . iIii1I11I1II1 + Oo0Ooo
 ooO0000o00O = '''
        <form action="/lisp/search/log/{}/{}" method="post">
        <i>Keyword search:</i>
        <input type="text" name="keyword" />
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </form><hr>
    ''' . format ( name , num )
 if 91 - 91: I11i / O0 - Ii1I . I1IiiI
 if ( os . path . exists ( "logs/{}.log" . format ( name ) ) ) :
  o00 = commands . getoutput ( "tail -n {} logs/{}.log" . format ( num , name ) )
  o00 = lisp . convert_font ( o00 )
  o00 = o00 . replace ( "\n" , "<br>" )
  o00 = ooO0000o00O + lisp . lisp_print_cour ( o00 )
 else :
  o0oOOo0OooOo = lisp . lisp_print_sans ( "File" )
  o0 = lisp . lisp_print_cour ( "logs/{}.log" . format ( name ) )
  iIiiIiiIi = lisp . lisp_print_sans ( "does not exist" )
  o00 = "{} {} {}" . format ( o0oOOo0OooOo , o0 , iIiiIiiIi )
  if 40 - 40: o0oOOo0O0Ooo
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
 if 78 - 78: iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
@ bottle . route ( '/lisp/debug/<name>' )
def oo0O ( name = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 6 - 6: Oo0Ooo . IiII / IiII - i11iIiiIii
  if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
  if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
  if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
  if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
 if ( name == "disable%all" ) :
  O000oo = lispconfig . lisp_get_clause_for_api ( "lisp debug" )
  if ( O000oo [ 0 ] . has_key ( "lisp debug" ) ) :
   i1 = [ ]
   for OO0 in O000oo [ 0 ] [ "lisp debug" ] :
    Ooo0 = OO0 . keys ( ) [ 0 ]
    i1 . append ( { Ooo0 : "no" } )
    if 91 - 91: i1IIi - iIii1I11I1II1
   i1 = { "lisp debug" : i1 }
   lispconfig . lisp_put_clause_for_api ( i1 )
   if 55 - 55: I1IiiI * o0oOOo0O0Ooo % ooOoO0o . iIii1I11I1II1 * I1Ii111
   if 92 - 92: I1Ii111 - iIii1I11I1II1
  O000oo = lispconfig . lisp_get_clause_for_api ( "lisp xtr-parameters" )
  if ( O000oo [ 0 ] . has_key ( "lisp xtr-parameters" ) ) :
   i1 = [ ]
   for OO0 in O000oo [ 0 ] [ "lisp xtr-parameters" ] :
    Ooo0 = OO0 . keys ( ) [ 0 ]
    if ( Ooo0 in [ "data-plane-logging" , "flow-logging" ] ) :
     i1 . append ( { Ooo0 : "no" } )
    else :
     i1 . append ( { Ooo0 : OO0 [ Ooo0 ] } )
     if 32 - 32: Ii1I % OoO0O00 * OoO0O00 + IiII * II111iiii * Ii1I
     if 11 - 11: oO0o % II111iiii
   i1 = { "lisp xtr-parameters" : i1 }
   lispconfig . lisp_put_clause_for_api ( i1 )
   if 57 - 57: OOooOOo / Oo0Ooo
   if 69 - 69: oO0o - Oo0Ooo % IiII
  return ( lispconfig . lisp_landing_page ( ) )
  if 50 - 50: OoooooooOO
  if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
  if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
  if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
  if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
 name = name . split ( "%" )
 Oo = name [ 0 ]
 OooOooo = name [ 1 ]
 if 40 - 40: OoOoOO00 % OoO0O00
 oo0O0o00 = [ "data-plane-logging" , "flow-logging" ]
 if 70 - 70: OoO0O00
 i1iIi1111 = "lisp xtr-parameters" if ( Oo in oo0O0o00 ) else "lisp debug"
 if 13 - 13: OoO0O00
 if 37 - 37: Ii1I + I1Ii111 - Oo0Ooo + Ii1I
 O000oo = lispconfig . lisp_get_clause_for_api ( i1iIi1111 )
 if 92 - 92: OoooooooOO - OoooooooOO * OoO0O00 % I1IiiI
 if ( O000oo [ 0 ] . has_key ( i1iIi1111 ) ) :
  i1 = { }
  for OO0 in O000oo [ 0 ] [ i1iIi1111 ] :
   i1 [ OO0 . keys ( ) [ 0 ] ] = OO0 . values ( ) [ 0 ]
   if ( i1 . has_key ( Oo ) ) : i1 [ Oo ] = OooOooo
   if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
  i1 = { i1iIi1111 : i1 }
  lispconfig . lisp_put_clause_for_api ( i1 )
  if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 return ( lispconfig . lisp_landing_page ( ) )
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 if 84 - 84: i11iIiiIii * OoO0O00
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
@ bottle . route ( '/lisp/clear/<name>' )
@ bottle . route ( '/lisp/clear/etr/<etr_name>/<stats_name>' )
@ bottle . route ( '/lisp/clear/rtr/<rtr_name>/<stats_name>' )
@ bottle . route ( '/lisp/clear/itr/<itr_name>' )
@ bottle . route ( '/lisp/clear/rtr/<rtr_name>' )
def OOoO00ooO ( name = "" , itr_name = '' , rtr_name = "" , etr_name = "" ,
 stats_name = "" ) :
 if 12 - 12: ooOoO0o % I1IiiI + oO0o - i1IIi . Ii1I / I1IiiI
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 51 - 51: OOooOOo . I1IiiI
  if 73 - 73: OoooooooOO . I1IiiI / I1Ii111 % Ii1I
  if 65 - 65: IiII - I1IiiI - Ii1I
  if 42 - 42: II111iiii * I1IiiI % i1IIi - Ii1I % IiII
  if 36 - 36: i11iIiiIii / oO0o * I1ii11iIi11i * I1ii11iIi11i + Ii1I * I11i
 if ( lispconfig . lisp_is_user_superuser ( None ) == False ) :
  o00 = lisp . lisp_print_sans ( "Not authorized" )
  return ( lispconfig . lisp_show_wrapper ( o00 ) )
  if 32 - 32: OoO0O00
  if 50 - 50: ooOoO0o + i1IIi
 i11I1iIiII = "clear"
 if ( name == "referral" ) :
  i11IiIIi11I = "lisp-mr"
  o000o0O0Oo00 = "Referral"
 elif ( itr_name == "map-cache" ) :
  i11IiIIi11I = "lisp-itr"
  o000o0O0Oo00 = "ITR <a href='/lisp/show/itr/map-cache'>map-cache</a>"
 elif ( rtr_name == "map-cache" ) :
  i11IiIIi11I = "lisp-rtr"
  o000o0O0Oo00 = "RTR <a href='/lisp/show/rtr/map-cache'>map-cache</a>"
 elif ( etr_name == "stats" ) :
  i11IiIIi11I = "lisp-etr"
  o000o0O0Oo00 = ( "ETR '{}' decapsulation <a href='/lisp/show/" + "database'>stats</a>" ) . format ( stats_name )
  if 60 - 60: OoOoOO00
  i11I1iIiII += "%" + stats_name
 elif ( rtr_name == "stats" ) :
  i11IiIIi11I = "lisp-rtr"
  o000o0O0Oo00 = ( "RTR '{}' decapsulation <a href='/lisp/show/" + "rtr/map-cache'>stats</a>" ) . format ( stats_name )
  if 5 - 5: I1IiiI - I1IiiI - I1IiiI * OoooooooOO
  i11I1iIiII += "%" + stats_name
 else :
  o00 = lisp . lisp_print_sans ( "Invalid command" )
  return ( lispconfig . lisp_show_wrapper ( o00 ) )
  if 28 - 28: iIii1I11I1II1 + iIii1I11I1II1
  if 28 - 28: oO0o
  if 52 - 52: I1IiiI + iIii1I11I1II1
  if 71 - 71: O0 / oO0o
  if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 i11I1iIiII = lisp . lisp_command_ipc ( i11I1iIiII , "lisp-core" )
 lisp . lisp_ipc ( i11I1iIiII , O0OOo , i11IiIIi11I )
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 I1I1I11Ii = commands . getoutput ( "egrep 'lisp map-cache' ./lisp.config" )
 if ( I1I1I11Ii != "" ) :
  os . system ( "touch ./lisp.config" )
  if 48 - 48: OoooooooOO + oO0o % iIii1I11I1II1
  if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 o00 = lisp . lisp_print_sans ( "{} cleared" . format ( o000o0O0Oo00 ) )
 return ( lispconfig . lisp_show_wrapper ( o00 ) )
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if 38 - 38: O0 - IiII % I1Ii111
 if 64 - 64: iIii1I11I1II1
 if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
 if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
@ bottle . route ( '/lisp/show/map-server' )
def II11i1IiIII ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 67 - 67: Oo0Ooo / iII111i * OoooooooOO
  if 100 - 100: O0 . I11i . OoO0O00 + O0 * oO0o
 return ( lispconfig . lisp_process_show_command ( O0OOo ,
 "show map-server" ) )
 if 42 - 42: oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
 if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
@ bottle . route ( '/lisp/show/database' )
def Iiii1iiiIiI1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 27 - 27: Ii1I + I1IiiI * iIii1I11I1II1 . OoooooooOO * OoOoOO00
 return ( lispconfig . lisp_process_show_command ( O0OOo ,
 "show database-mapping" ) )
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
@ bottle . route ( '/lisp/show/itr/map-cache' )
def OO0o0oO0O000o ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 47 - 47: I1Ii111 - OoO0O00 / Ii1I * OoooooooOO / Ii1I . Oo0Ooo
 return ( lispconfig . lisp_process_show_command ( O0OOo ,
 "show itr-map-cache" ) )
 if 34 - 34: ooOoO0o
 if 27 - 27: I1Ii111 + OoooooooOO - OoOoOO00
 if 15 - 15: oO0o / I11i * O0 . II111iiii - OoO0O00
 if 90 - 90: oO0o
 if 94 - 94: I11i / I1ii11iIi11i * I1Ii111 - OoOoOO00
 if 44 - 44: Ii1I % i11iIiiIii - iII111i * I1ii11iIi11i + Oo0Ooo * OOooOOo
 if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
@ bottle . route ( '/lisp/show/itr/rloc-probing' )
def oOIIIiI1ii1IIi ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 55 - 55: iII111i - OoO0O00
 return ( lispconfig . lisp_process_show_command ( O0OOo ,
 "show itr-rloc-probing" ) )
 if 100 - 100: O0
 if 79 - 79: iIii1I11I1II1
 if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
 if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 if 11 - 11: i1IIi % OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
@ bottle . post ( '/lisp/show/itr/map-cache/lookup' )
def O0oo0O0 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 2 - 2: OoooooooOO . OOooOOo . IiII
  if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 iI1IiiiIiI1Ii = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( iI1IiiiIiI1Ii ) == False ) :
  o00 = "Address '{}' has invalid format" . format ( iI1IiiiIiI1Ii )
  o00 = lisp . lisp_print_sans ( o00 )
  return ( lispconfig . lisp_show_wrapper ( o00 ) )
  if 78 - 78: OoooooooOO / OOooOOo % OoOoOO00 * OoooooooOO
  if 68 - 68: oO0o
 Oo0O0 = "show itr-map-cache" + "%" + iI1IiiiIiI1Ii
 return ( lispconfig . lisp_process_show_command ( O0OOo ,
 Oo0O0 ) )
 if 29 - 29: iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
@ bottle . route ( '/lisp/show/rtr/map-cache' )
@ bottle . route ( '/lisp/show/rtr/map-cache/<dns>' )
def i1I1II ( dns = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 17 - 17: O0 * OoOoOO00 * I1ii11iIi11i * II111iiii * I11i % i1IIi
  if 33 - 33: I1ii11iIi11i * I1ii11iIi11i . ooOoO0o . i11iIiiIii
 if ( dns == "dns" ) :
  return ( lispconfig . lisp_process_show_command ( O0OOo ,
 "show rtr-map-cache-dns" ) )
 else :
  return ( lispconfig . lisp_process_show_command ( O0OOo ,
 "show rtr-map-cache" ) )
  if 48 - 48: o0oOOo0O0Ooo . Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
  if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
  if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
  if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
  if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
  if 24 - 24: OoOoOO00
  if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
  if 28 - 28: I1IiiI
@ bottle . route ( '/lisp/show/rtr/rloc-probing' )
def I11 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 54 - 54: Ii1I - I1Ii111
 return ( lispconfig . lisp_process_show_command ( O0OOo ,
 "show rtr-rloc-probing" ) )
 if 81 - 81: IiII . O0 + II111iiii * iIii1I11I1II1 * OOooOOo / OoOoOO00
 if 88 - 88: II111iiii - o0oOOo0O0Ooo * I1IiiI . OoO0O00
 if 65 - 65: IiII . i1IIi
 if 95 - 95: I1IiiI + I1IiiI - OOooOOo - iII111i
 if 45 - 45: Ii1I . OoooooooOO
 if 27 - 27: Ii1I * Oo0Ooo . OoOoOO00
 if 17 - 17: II111iiii % iII111i * OOooOOo % i1IIi . I1IiiI . iIii1I11I1II1
@ bottle . post ( '/lisp/show/rtr/map-cache/lookup' )
def iiiIIIii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 93 - 93: iIii1I11I1II1 + I1IiiI + i11iIiiIii
  if 74 - 74: I11i / II111iiii + ooOoO0o * iIii1I11I1II1 - I1Ii111 - OoO0O00
 iI1IiiiIiI1Ii = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( iI1IiiiIiI1Ii ) == False ) :
  o00 = "Address '{}' has invalid format" . format ( iI1IiiiIiI1Ii )
  o00 = lisp . lisp_print_sans ( o00 )
  return ( lispconfig . lisp_show_wrapper ( o00 ) )
  if 69 - 69: iIii1I11I1II1 * I1IiiI - iII111i + O0 + O0
  if 65 - 65: I1Ii111 / i11iIiiIii / OoO0O00 - OOooOOo
 Oo0O0 = "show rtr-map-cache" + "%" + iI1IiiiIiI1Ii
 return ( lispconfig . lisp_process_show_command ( O0OOo ,
 Oo0O0 ) )
 if 9 - 9: I1IiiI / I1Ii111 - Oo0Ooo * iIii1I11I1II1
 if 86 - 86: II111iiii + ooOoO0o + IiII
 if 9 - 9: ooOoO0o + II111iiii % ooOoO0o % IiII + iIii1I11I1II1
 if 59 - 59: i1IIi
 if 48 - 48: O0 * Ii1I * OoO0O00 . OoO0O00 * I11i - Ii1I
 if 14 - 14: I1ii11iIi11i + i11iIiiIii
 if 83 - 83: I1ii11iIi11i / i11iIiiIii + II111iiii . iII111i * OOooOOo + IiII
@ bottle . route ( '/lisp/show/referral' )
def iiii1i1II1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 63 - 63: iIii1I11I1II1 % I1ii11iIi11i - iII111i
 return ( lispconfig . lisp_process_show_command ( O0OOo ,
 "show referral-cache" ) )
 if 17 - 17: I1IiiI
 if 88 - 88: OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 if 83 - 83: o0oOOo0O0Ooo
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
@ bottle . post ( '/lisp/show/referral/lookup' )
def I1III1iIi ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 82 - 82: I1IiiI + iII111i + I1ii11iIi11i * I1IiiI % i11iIiiIii % iII111i
  if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 iI1IiiiIiI1Ii = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( iI1IiiiIiI1Ii ) == False ) :
  o00 = "Address '{}' has invalid format" . format ( iI1IiiiIiI1Ii )
  o00 = lisp . lisp_print_sans ( o00 )
  return ( lispconfig . lisp_show_wrapper ( o00 ) )
  if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
  if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
 Oo0O0 = "show referral-cache" + "%" + iI1IiiiIiI1Ii
 return ( lispconfig . lisp_process_show_command ( O0OOo , Oo0O0 ) )
 if 58 - 58: I1ii11iIi11i
 if 2 - 2: II111iiii / I1Ii111
 if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 if 22 - 22: ooOoO0o . iIii1I11I1II1
 if 12 - 12: Ii1I
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
@ bottle . route ( '/lisp/show/delegations' )
def IiIIiiI ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 60 - 60: I1Ii111
 return ( lispconfig . lisp_process_show_command ( O0OOo ,
 "show delegations" ) )
 if 98 - 98: ooOoO0o
 if 34 - 34: iIii1I11I1II1 * I11i * I11i / I1ii11iIi11i
 if 28 - 28: OoO0O00 - oO0o + OoOoOO00 + Ii1I / iIii1I11I1II1
 if 26 - 26: iIii1I11I1II1 - O0 . O0
 if 68 - 68: OOooOOo + oO0o . O0 . Ii1I % i1IIi % OOooOOo
 if 50 - 50: IiII + o0oOOo0O0Ooo
 if 96 - 96: OoO0O00
@ bottle . post ( '/lisp/show/delegations/lookup' )
def oOOoO ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 87 - 87: OoOoOO00 % iIii1I11I1II1
  if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 iI1IiiiIiI1Ii = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( iI1IiiiIiI1Ii ) == False ) :
  o00 = "Address '{}' has invalid format" . format ( iI1IiiiIiI1Ii )
  o00 = lisp . lisp_print_sans ( o00 )
  return ( lispconfig . lisp_show_wrapper ( o00 ) )
  if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
  if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 Oo0O0 = "show delegations" + "%" + iI1IiiiIiI1Ii
 return ( lispconfig . lisp_process_show_command ( O0OOo , Oo0O0 ) )
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
@ bottle . route ( '/lisp/show/site' )
@ bottle . route ( '/lisp/show/site/<eid_prefix>' )
def oO0OIiii1I ( eid_prefix = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
  if 81 - 81: IiII / OoOoOO00 * IiII . O0
 Oo0O0 = "show site"
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 if ( eid_prefix != "" ) :
  Oo0O0 = lispconfig . lisp_parse_eid_in_url ( Oo0O0 , eid_prefix )
  if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
 return ( lispconfig . lisp_process_show_command ( O0OOo , Oo0O0 ) )
 if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
 if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
 if 61 - 61: I1Ii111 - Ii1I % I1ii11iIi11i / ooOoO0o / iII111i + iIii1I11I1II1
 if 87 - 87: I1Ii111 + ooOoO0o + O0 / i1IIi % IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
@ bottle . route ( '/lisp/show/itr/dynamic-eid/<eid_prefix>' )
def O0000oO0o00 ( eid_prefix = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 80 - 80: OoooooooOO + IiII
  if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 Oo0O0 = "show itr-dynamic-eid"
 if 43 - 43: Oo0Ooo . I1Ii111
 if ( eid_prefix != "" ) :
  Oo0O0 = lispconfig . lisp_parse_eid_in_url ( Oo0O0 , eid_prefix )
  if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 return ( lispconfig . lisp_process_show_command ( O0OOo , Oo0O0 ) )
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
@ bottle . route ( '/lisp/show/etr/dynamic-eid/<eid_prefix>' )
def i111i1I1ii1i ( eid_prefix = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
  if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 Oo0O0 = "show etr-dynamic-eid"
 if 49 - 49: IiII * O0 . IiII
 if ( eid_prefix != "" ) :
  Oo0O0 = lispconfig . lisp_parse_eid_in_url ( Oo0O0 , eid_prefix )
  if 19 - 19: II111iiii - IiII
 return ( lispconfig . lisp_process_show_command ( O0OOo , Oo0O0 ) )
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
 if 69 - 69: ooOoO0o - OoooooooOO * O0
 if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
 if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
 if 96 - 96: OoooooooOO + IiII * O0
 if 86 - 86: Ii1I
@ bottle . post ( '/lisp/show/site/lookup' )
def IiII1i1iI ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
  if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 iI1IiiiIiI1Ii = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( iI1IiiiIiI1Ii ) == False ) :
  o00 = "Address '{}' has invalid format" . format ( iI1IiiiIiI1Ii )
  o00 = lisp . lisp_print_sans ( o00 )
  return ( lispconfig . lisp_show_wrapper ( o00 ) )
  if 69 - 69: OoOoOO00
  if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 Oo0O0 = "show site" + "%" + iI1IiiiIiI1Ii + "@lookup"
 return ( lispconfig . lisp_process_show_command ( O0OOo , Oo0O0 ) )
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 if 88 - 88: o0oOOo0O0Ooo
 if 1 - 1: OoooooooOO
 if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
@ bottle . post ( '/lisp/lig' )
def iii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
  if 3 - 3: OoooooooOO
 O0OoO0o = bottle . request . forms . get ( "eid" )
 I111IIiIII = bottle . request . forms . get ( "mr" )
 OO0OOoo0OOO = bottle . request . forms . get ( "count" )
 ooooOoo0OO = "no-info" if bottle . request . forms . get ( "no-nat" ) == "yes" else ""
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if ( I111IIiIII == "" ) : I111IIiIII = "localhost"
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if ( O0OoO0o == "" ) :
  o00 = "Need to supply EID address"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( o00 ) ) )
  if 34 - 34: iII111i
  if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 iIIi1Ii1III = ""
 if os . path . exists ( "lisp-lig.pyo" ) : iIIi1Ii1III = "-O lisp-lig.pyo"
 if os . path . exists ( "lisp-lig.py" ) : iIIi1Ii1III = "lisp-lig.py"
 if 86 - 86: i11iIiiIii + i11iIiiIii . I1Ii111 % I1IiiI . ooOoO0o
 if 17 - 17: Ii1I
 if 67 - 67: O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if ( iIIi1Ii1III == "" ) :
  o00 = "Cannot find lisp-lig.py or lisp-lig.pyo"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( o00 ) ) )
  if 45 - 45: Ii1I - OOooOOo
  if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if ( OO0OOoo0OOO != "" ) : OO0OOoo0OOO = "count {}" . format ( OO0OOoo0OOO )
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 Oo0O0 = 'python {} "{}" to {} {} {}' . format ( iIIi1Ii1III , O0OoO0o , I111IIiIII , OO0OOoo0OOO , ooooOoo0OO )
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 o00 = commands . getoutput ( Oo0O0 )
 o00 = o00 . replace ( "\n" , "<br>" )
 o00 = lisp . convert_font ( o00 )
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 i111IiiI1Ii = lisp . space ( 2 ) + "RLOC:"
 o00 = o00 . replace ( "RLOC:" , i111IiiI1Ii )
 OooOOOOOo = lisp . space ( 2 ) + "Empty,"
 o00 = o00 . replace ( "Empty," , OooOOOOOo )
 o0oooOO00 = lisp . space ( 4 ) + "geo:"
 o00 = o00 . replace ( "geo:" , o0oooOO00 )
 i1I11ii = lisp . space ( 4 ) + "elp:"
 o00 = o00 . replace ( "elp:" , i1I11ii )
 o0ooO00O0O = lisp . space ( 4 ) + "rle:"
 o00 = o00 . replace ( "rle:" , o0ooO00O0O )
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( o00 ) ) )
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
@ bottle . post ( '/lisp/rig' )
def i111I11I ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 80 - 80: iIii1I11I1II1 - OoooooooOO - I1ii11iIi11i - I1ii11iIi11i . OoooooooOO
  if 48 - 48: I1Ii111 . i11iIiiIii / i1IIi % IiII % iII111i + oO0o
 O0OoO0o = bottle . request . forms . get ( "eid" )
 iiII1iiiiiii = bottle . request . forms . get ( "ddt" )
 iiIiii = "follow-all-referrals" if bottle . request . forms . get ( "follow" ) == "yes" else ""
 if 39 - 39: I1IiiI + Oo0Ooo
 if 83 - 83: i1IIi
 if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
 if 49 - 49: IiII / ooOoO0o / OOooOOo
 if 25 - 25: I1IiiI % O0 + i1IIi - ooOoO0o
 if ( iiII1iiiiiii == "" ) : iiII1iiiiiii = "localhost"
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if ( O0OoO0o == "" ) :
  o00 = "Need to supply EID address"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( o00 ) ) )
  if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
  if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 Ooo000O00 = ""
 if os . path . exists ( "lisp-rig.pyo" ) : Ooo000O00 = "-O lisp-rig.pyo"
 if os . path . exists ( "lisp-rig.py" ) : Ooo000O00 = "lisp-rig.py"
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if ( Ooo000O00 == "" ) :
  o00 = "Cannot find lisp-rig.py or lisp-rig.pyo"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( o00 ) ) )
  if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
  if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 Oo0O0 = 'python {} "{}" to {} {}' . format ( Ooo000O00 , O0OoO0o , iiII1iiiiiii , iiIiii )
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 o00 = commands . getoutput ( Oo0O0 )
 o00 = o00 . replace ( "\n" , "<br>" )
 o00 = lisp . convert_font ( o00 )
 if 45 - 45: OoooooooOO
 I1 = lisp . space ( 2 ) + "Referrals:"
 o00 = o00 . replace ( "Referrals:" , I1 )
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( o00 ) ) )
 if 98 - 98: i1IIi . I1IiiI . oO0o
 if 10 - 10: I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
def Ii1iiI1 ( eid1 , eid2 ) :
 iIIi1Ii1III = None
 if os . path . exists ( "lisp-lig.pyo" ) : iIIi1Ii1III = "-O lisp-lig.pyo"
 if os . path . exists ( "lisp-lig.py" ) : iIIi1Ii1III = "lisp-lig.py"
 if ( iIIi1Ii1III == None ) : return ( [ None , None ] )
 if 76 - 76: Ii1I * iIii1I11I1II1
 if 31 - 31: i11iIiiIii + OOooOOo - O0
 if 51 - 51: OoO0O00 * i1IIi / Ii1I * OOooOOo + ooOoO0o % I1ii11iIi11i
 if 34 - 34: oO0o * OoooooooOO + Ii1I + i11iIiiIii
 iiIi = commands . getoutput ( "egrep -A 2 'lisp map-resolver {' ./lisp.config" )
 I111IIiIII = None
 for I11Ii in [ "address = " , "dns-name = " ] :
  I111IIiIII = None
  O0oo0 = iiIi . find ( I11Ii )
  if ( O0oo0 == - 1 ) : continue
  I111IIiIII = iiIi [ O0oo0 + len ( I11Ii ) : : ]
  O0oo0 = I111IIiIII . find ( "\n" )
  if ( O0oo0 == - 1 ) : continue
  I111IIiIII = I111IIiIII [ 0 : O0oo0 ]
  break
  if 37 - 37: i11iIiiIii
 if ( I111IIiIII == None ) : return ( [ None , None ] )
 if 12 - 12: I1ii11iIi11i / Ii1I
 if 5 - 5: OoooooooOO
 if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
 if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
 OOOO = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 oOIii11111iiI = [ ]
 for O0OoO0o in [ eid1 , eid2 ] :
  if 67 - 67: o0oOOo0O0Ooo
  if 76 - 76: OoOoOO00 - I1IiiI + OOooOOo + I11i
  if 50 - 50: I1Ii111 + I1ii11iIi11i
  if 4 - 4: IiII / Oo0Ooo
  if 31 - 31: I1Ii111 - I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - oO0o
  if ( OOOO . is_geo_string ( O0OoO0o ) ) :
   oOIii11111iiI . append ( O0OoO0o )
   continue
   if 43 - 43: iII111i + Oo0Ooo / OoooooooOO
   if 24 - 24: O0 + o0oOOo0O0Ooo * Ii1I - I1Ii111
  Oo0O0 = 'python {} "{}" to {} count 1' . format ( iIIi1Ii1III , O0OoO0o , I111IIiIII )
  for I1i in [ Oo0O0 , Oo0O0 + " no-info" ] :
   o00 = commands . getoutput ( Oo0O0 )
   O0oo0 = o00 . find ( "geo: " )
   if ( O0oo0 == - 1 ) :
    if ( I1i != Oo0O0 ) : oOIii11111iiI . append ( None )
    continue
    if 10 - 10: i11iIiiIii
   o00 = o00 [ O0oo0 + len ( "geo: " ) : : ]
   O0oo0 = o00 . find ( "\n" )
   if ( O0oo0 == - 1 ) :
    if ( I1i != Oo0O0 ) : oOIii11111iiI . append ( None )
    continue
    if 21 - 21: I1IiiI / iII111i
   oOIii11111iiI . append ( o00 [ 0 : O0oo0 ] )
   break
   if 69 - 69: ooOoO0o % ooOoO0o
   if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 return ( oOIii11111iiI )
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
 if 33 - 33: Ii1I
 if 93 - 93: ooOoO0o
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
@ bottle . post ( '/lisp/geo' )
def iI1iiIi1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( O0O00Oo ( ) )
  if 49 - 49: ooOoO0o . II111iiii
  if 24 - 24: O0 . OoooooooOO - OoO0O00 * OoooooooOO
 O0OoO0o = bottle . request . forms . get ( "geo-point" )
 Ii11iiI = bottle . request . forms . get ( "geo-prefix" )
 o00 = ""
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
 if 28 - 28: iIii1I11I1II1
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 I1iI1I1ii1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 iIIi1 = lisp . lisp_geo ( "" )
 o0Ooo0o0Oo = lisp . lisp_geo ( "" )
 oo00ooooOOo00 , ii1i = Ii1iiI1 ( O0OoO0o , Ii11iiI )
 if 70 - 70: oO0o % IiII % I1IiiI + i11iIiiIii . Ii1I % I1Ii111
 if 38 - 38: OoO0O00 . ooOoO0o
 if 34 - 34: i1IIi % IiII
 if 80 - 80: OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 if 94 - 94: i1IIi
 if ( I1iI1I1ii1 . is_geo_string ( O0OoO0o ) ) :
  if ( iIIi1 . parse_geo_string ( O0OoO0o ) == False ) :
   o00 = "Could not parse geo-point format"
   if 36 - 36: I1IiiI + Oo0Ooo
 elif ( oo00ooooOOo00 == None ) :
  o00 = "EID {} lookup could not find geo-point" . format (
 lisp . bold ( O0OoO0o , True ) )
 elif ( iIIi1 . parse_geo_string ( oo00ooooOOo00 ) == False ) :
  o00 = "Could not parse geo-point format returned from lookup"
  if 46 - 46: iII111i
  if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
  if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
  if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
  if 65 - 65: ooOoO0o - i1IIi
  if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 if ( o00 == "" ) :
  if ( I1iI1I1ii1 . is_geo_string ( Ii11iiI ) ) :
   if ( o0Ooo0o0Oo . parse_geo_string ( Ii11iiI ) == False ) :
    o00 = "Could not parse geo-prefix format"
    if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  elif ( ii1i == None ) :
   o00 = "EID-prefix {} lookup could not find geo-prefix" . format ( lisp . bold ( Ii11iiI , True ) )
   if 34 - 34: I1Ii111 - OOooOOo
  elif ( o0Ooo0o0Oo . parse_geo_string ( ii1i ) == False ) :
   o00 = "Could not parse geo-prefix format returned from lookup"
   if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
   if 64 - 64: i1IIi
   if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
   if 25 - 25: II111iiii / OoO0O00
   if 64 - 64: O0 % ooOoO0o
   if 40 - 40: o0oOOo0O0Ooo + I11i
   if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
 if ( o00 == "" ) :
  O0OoO0o = "" if ( O0OoO0o == oo00ooooOOo00 ) else ", EID {}" . format ( O0OoO0o )
  Ii11iiI = "" if ( Ii11iiI == ii1i ) else ", EID-prefix {}" . format ( Ii11iiI )
  if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
  if 47 - 47: OoooooooOO
  II111IIIII = iIIi1 . print_geo_url ( )
  IIiIi1 = o0Ooo0o0Oo . print_geo_url ( )
  O00O00o = o0Ooo0o0Oo . radius
  I11IiI1iI = iIIi1 . dms_to_decimal ( )
  I11IiI1iI = ( round ( I11IiI1iI [ 0 ] , 6 ) , round ( I11IiI1iI [ 1 ] , 6 ) )
  O0OO0OoO = o0Ooo0o0Oo . dms_to_decimal ( )
  O0OO0OoO = ( round ( O0OO0OoO [ 0 ] , 6 ) , round ( O0OO0OoO [ 1 ] , 6 ) )
  o0OOo = round ( o0Ooo0o0Oo . get_distance ( iIIi1 ) , 2 )
  IiI1Ii11Ii = "inside" if o0Ooo0o0Oo . point_in_circle ( iIIi1 ) else "outside"
  if 99 - 99: O0 . o0oOOo0O0Ooo % I11i - Oo0Ooo / I11i
  if 20 - 20: OoOoOO00 * iII111i
  i1i1 = lisp . space ( 2 )
  I1iiIiIII = lisp . space ( 1 )
  o0IiIiI111IIII1 = lisp . space ( 3 )
  if 100 - 100: OOooOOo * O0 + I1IiiI + OoOoOO00 . OOooOOo
  o00 = ( "Geo-Point:{}{} {}{}<br>Geo-Prefix:{}{} {}, {} " + "kilometer radius{}<br>" ) . format ( i1i1 , II111IIIII , I11IiI1iI , O0OoO0o ,
  # iIii1I11I1II1 * IiII - OOooOOo / Oo0Ooo % oO0o
 I1iiIiIII , IIiIi1 , O0OO0OoO , O00O00o , Ii11iiI )
  o00 += "Distance:{}{} kilometers, point is {} of circle" . format ( o0IiIiI111IIII1 ,
 o0OOo , lisp . bold ( IiI1Ii11Ii , True ) )
  if 66 - 66: OoooooooOO + ooOoO0o * iII111i
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( o00 ) ) )
 if 2 - 2: iII111i . OoO0O00 / oO0o
 if 41 - 41: OoO0O00 . I1Ii111 * IiII * I1Ii111
 if 74 - 74: iIii1I11I1II1 / o0oOOo0O0Ooo
 if 58 - 58: iIii1I11I1II1 - I1IiiI % o0oOOo0O0Ooo % OoooooooOO * iIii1I11I1II1 + OOooOOo
 if 25 - 25: OOooOOo % O0
 if 44 - 44: I1Ii111 . Ii1I * II111iiii / IiII + iIii1I11I1II1
 if 14 - 14: O0 % IiII % Ii1I * oO0o
 if 65 - 65: I11i % oO0o + I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 / O0 . I1Ii111 % iIii1I11I1II1 % Oo0Ooo
def OooO00oO ( addr_str , port , nonce ) :
 if ( addr_str != None ) :
  for OOoOOOo0 in lisp . lisp_info_sources_by_address . values ( ) :
   oOoO00O = OOoOOOo0 . address . print_address_no_iid ( )
   if ( oOoO00O == addr_str and OOoOOOo0 . port == port ) :
    return ( OOoOOOo0 )
    if 31 - 31: ooOoO0o . OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * iII111i
    if 22 - 22: I11i % IiII . OoOoOO00 / ooOoO0o + OOooOOo
  return ( None )
  if 85 - 85: I1IiiI - ooOoO0o % Oo0Ooo % II111iiii - OoooooooOO % IiII
  if 40 - 40: Ii1I
 if ( nonce != None ) :
  if ( nonce not in lisp . lisp_info_sources_by_nonce ) : return ( None )
  return ( lisp . lisp_info_sources_by_nonce [ nonce ] )
  if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
 return ( None )
 if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
 if 93 - 93: ooOoO0o
 if 18 - 18: ooOoO0o
 if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
 if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
 if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
 if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
 if 58 - 58: O0
def O0oO ( lisp_sockets , info_source , packet ) :
 if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
 if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
 if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
 iiii11IiIiI = lisp . lisp_ecm ( 0 )
 packet = iiii11IiIiI . decode ( packet )
 if ( packet == None ) :
  lisp . lprint ( "Could not decode ECM packet" )
  return ( True )
  if 8 - 8: I1Ii111 + OoO0O00
  if 9 - 9: OOooOOo + o0oOOo0O0Ooo
 ooO0000o00O = lisp . lisp_control_header ( )
 if ( ooO0000o00O . decode ( packet ) == None ) :
  lisp . lprint ( "Could not decode control header" )
  return ( True )
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 if ( ooO0000o00O . type != lisp . LISP_MAP_REQUEST ) :
  lisp . lprint ( "Received ECM without Map-Request inside" )
  return ( True )
  if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
  if 55 - 55: oO0o
  if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
  if 97 - 97: I1Ii111 . I11i / I1IiiI
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
 oOO00OO0OooOo = lisp . lisp_map_request ( )
 packet = oOO00OO0OooOo . decode ( packet , None , 0 )
 ii111iI1i1 = oOO00OO0OooOo . nonce
 OO000 = info_source . address . print_address_no_iid ( )
 if 31 - 31: OoO0O00 * O0 / I11i . OoooooooOO * I11i . I1ii11iIi11i
 if 50 - 50: OoO0O00 * I11i - o0oOOo0O0Ooo + IiII * OoO0O00 % oO0o
 if 92 - 92: I11i % i1IIi % ooOoO0o % IiII % o0oOOo0O0Ooo
 if 61 - 61: OOooOOo * o0oOOo0O0Ooo * O0 / iII111i
 oOO00OO0OooOo . print_map_request ( )
 if 52 - 52: Oo0Ooo + iIii1I11I1II1 + i1IIi * Ii1I - II111iiii . II111iiii
 lisp . lprint ( "Process {} from info-source {}, port {}, nonce 0x{}" . format ( lisp . bold ( "nat-proxy Map-Request" , False ) ,
 # I1ii11iIi11i % i1IIi
 lisp . red ( OO000 , False ) , info_source . port ,
 lisp . lisp_hex_string ( ii111iI1i1 ) ) )
 if 31 - 31: iII111i - OoOoOO00 . OoOoOO00 - oO0o + Oo0Ooo / i11iIiiIii
 if 90 - 90: iIii1I11I1II1 + OoOoOO00
 if 9 - 9: iIii1I11I1II1 . OoooooooOO + i1IIi - Oo0Ooo
 if 30 - 30: iII111i / OoO0O00 . iII111i
 if 17 - 17: Oo0Ooo + OoooooooOO * OoooooooOO
 info_source . cache_nonce_for_info_source ( ii111iI1i1 )
 if 5 - 5: I1Ii111 % OoooooooOO . OoOoOO00
 if 67 - 67: I1ii11iIi11i + Ii1I
 if 72 - 72: IiII % o0oOOo0O0Ooo
 if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
 if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
 info_source . no_timeout = oOO00OO0OooOo . subscribe_bit
 if 52 - 52: IiII % ooOoO0o
 if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
 if 23 - 23: i11iIiiIii
 if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
 if 65 - 65: II111iiii / Oo0Ooo
 if 42 - 42: i11iIiiIii . O0
 for o0oo0Oo in oOO00OO0OooOo . itr_rlocs :
  if ( o0oo0Oo . is_local ( ) ) : return ( False )
  if 10 - 10: I1ii11iIi11i
  if 87 - 87: Oo0Ooo % Ii1I
  if 53 - 53: i1IIi - IiII + iIii1I11I1II1
  if 75 - 75: I1ii11iIi11i
  if 92 - 92: I11i / O0 * I1IiiI - I11i
 oooOo00000 = lisp . lisp_myrlocs [ 0 ]
 oOO00OO0OooOo . itr_rloc_count = 0
 oOO00OO0OooOo . itr_rlocs = [ ]
 oOO00OO0OooOo . itr_rlocs . append ( oooOo00000 )
 if 45 - 45: O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
 packet = oOO00OO0OooOo . encode ( None , 0 )
 oOO00OO0OooOo . print_map_request ( )
 if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
 I1Iiii = oOO00OO0OooOo . target_eid
 if ( I1Iiii . is_ipv6 ( ) ) :
  I1I1Iii1Iiii = lisp . lisp_myrlocs [ 1 ]
  if ( I1I1Iii1Iiii != None ) : oooOo00000 = I1I1Iii1Iiii
  if 4 - 4: IiII
  if 93 - 93: oO0o % i1IIi
  if 83 - 83: I1IiiI . Oo0Ooo - I11i . o0oOOo0O0Ooo
  if 73 - 73: I1IiiI - iII111i . iII111i
  if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
 OooO00oo0O0 = lisp . lisp_is_running ( "lisp-ms" )
 lisp . lisp_send_ecm ( lisp_sockets , packet , I1Iiii , lisp . LISP_CTRL_PORT ,
 I1Iiii , oooOo00000 , to_ms = OooO00oo0O0 , ddt = False )
 return ( True )
 if 10 - 10: IiII / OoooooooOO
 if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
 if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
 if 25 - 25: iIii1I11I1II1
 if 63 - 63: ooOoO0o
 if 96 - 96: I11i
 if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
 if 63 - 63: iII111i
 if 11 - 11: iII111i - iIii1I11I1II1
def ooOo0O0 ( lisp_sockets , info_source , packet , mr_or_mn ) :
 OO000 = info_source . address . print_address_no_iid ( )
 o0o = info_source . port
 ii111iI1i1 = info_source . nonce
 if 83 - 83: OoooooooOO
 mr_or_mn = "Reply" if mr_or_mn else "Notify"
 mr_or_mn = lisp . bold ( "nat-proxy Map-{}" . format ( mr_or_mn ) , False )
 if 12 - 12: ooOoO0o
 lisp . lprint ( "Forward {} to info-source {}, port {}, nonce 0x{}" . format ( mr_or_mn , lisp . red ( OO000 , False ) , o0o ,
 # iIii1I11I1II1 - I1Ii111 * IiII
 lisp . lisp_hex_string ( ii111iI1i1 ) ) )
 if 61 - 61: I1ii11iIi11i - OOooOOo
 if 16 - 16: iII111i / iIii1I11I1II1 + OOooOOo * iII111i * I11i
 if 8 - 8: I1Ii111
 if 15 - 15: Oo0Ooo / Ii1I % O0 + I1ii11iIi11i
 o0oi1I1I1I = lisp . lisp_convert_4to6 ( OO000 )
 lisp . lisp_send ( lisp_sockets , o0oi1I1I1I , o0o , packet )
 if 25 - 25: o0oOOo0O0Ooo + iII111i - Oo0Ooo
 if 59 - 59: OOooOOo - I11i % i1IIi
 if 1 - 1: I1ii11iIi11i . I1Ii111 * I1IiiI . IiII * II111iiii % iIii1I11I1II1
 if 86 - 86: i1IIi * O0 % ooOoO0o . Oo0Ooo % ooOoO0o . Oo0Ooo
 if 71 - 71: iII111i . i11iIiiIii * O0 + O0
 if 57 - 57: OoooooooOO . I11i % II111iiii % I1IiiI + Ii1I
 if 70 - 70: IiII . i11iIiiIii
def O0O00O0Oo0 ( lisp_sockets , source , sport , packet ) :
 global O0OOo
 if 53 - 53: i1IIi . i1IIi - I11i / iII111i - OoOoOO00 % I1IiiI
 ooO0000o00O = lisp . lisp_control_header ( )
 if ( ooO0000o00O . decode ( packet ) == None ) :
  lisp . lprint ( "Could not decode control header" )
  return
  if 65 - 65: iII111i . OoooooooOO - O0 . iII111i - i11iIiiIii
  if 29 - 29: I1ii11iIi11i . I1IiiI % oO0o - i11iIiiIii
  if 27 - 27: I1ii11iIi11i - i11iIiiIii % I1Ii111 / Oo0Ooo . Oo0Ooo / OoooooooOO
  if 76 - 76: I11i * OoO0O00 . iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  if 79 - 79: IiII + IiII + Ii1I
  if 39 - 39: O0 - OoooooooOO
  if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  if 79 - 79: O0
 if ( ooO0000o00O . type == lisp . LISP_NAT_INFO ) :
  if ( ooO0000o00O . info_reply == False ) :
   lisp . lisp_process_info_request ( lisp_sockets , packet , source , sport ,
 lisp . lisp_ms_rtr_list )
   if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
  return
  if 15 - 15: I1ii11iIi11i
  if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
 OO0o0o0oo = packet
 packet = lisp . lisp_packet_ipc ( packet , source , sport )
 if 40 - 40: Oo0Ooo
 if 47 - 47: OoOoOO00
 if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
 if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
 if ( ooO0000o00O . type in ( lisp . LISP_MAP_REGISTER , lisp . LISP_MAP_NOTIFY_ACK ) ) :
  lisp . lisp_ipc ( packet , O0OOo , "lisp-ms" )
  return
  if 33 - 33: oO0o
  if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
  if 41 - 41: IiII % o0oOOo0O0Ooo
  if 67 - 67: O0 % I1Ii111
  if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
 if ( ooO0000o00O . type == lisp . LISP_MAP_REPLY ) :
  iIi1Ii1111i = lisp . lisp_map_reply ( )
  iIi1Ii1111i . decode ( OO0o0o0oo )
  if 16 - 16: IiII . ooOoO0o . OoO0O00
  OOoOOOo0 = OooO00oO ( None , 0 , iIi1Ii1111i . nonce )
  if ( OOoOOOo0 ) :
   ooOo0O0 ( lisp_sockets , OOoOOOo0 , OO0o0o0oo , True )
  else :
   iIIi1Ii1III = "/tmp/lisp-lig"
   if ( os . path . exists ( iIIi1Ii1III ) ) :
    lisp . lisp_ipc ( packet , O0OOo , iIIi1Ii1III )
   else :
    lisp . lisp_ipc ( packet , O0OOo , "lisp-itr" )
    if 53 - 53: OoOoOO00
    if 84 - 84: OoO0O00
  return
  if 97 - 97: i1IIi
  if 98 - 98: OoooooooOO - I1IiiI + ooOoO0o
  if 98 - 98: iII111i . IiII . IiII - OOooOOo
  if 65 - 65: Oo0Ooo + o0oOOo0O0Ooo - Ii1I
  if 12 - 12: OoooooooOO + I1ii11iIi11i
 if ( ooO0000o00O . type == lisp . LISP_MAP_NOTIFY ) :
  o0OoO0000oOO = lisp . lisp_map_notify ( lisp_sockets )
  o0OoO0000oOO . decode ( OO0o0o0oo )
  if 42 - 42: I1Ii111 % OoO0O00 . I1ii11iIi11i
  OOoOOOo0 = OooO00oO ( None , 0 , o0OoO0000oOO . nonce )
  if ( OOoOOOo0 ) :
   ooOo0O0 ( lisp_sockets , OOoOOOo0 , OO0o0o0oo ,
 False )
  else :
   iIIi1Ii1III = "/tmp/lisp-lig"
   if ( os . path . exists ( iIIi1Ii1III ) ) :
    lisp . lisp_ipc ( packet , O0OOo , iIIi1Ii1III )
   else :
    i11IiIIi11I = "lisp-rtr" if lisp . lisp_is_running ( "lisp-rtr" ) else "lisp-etr"
    if 4 - 4: i1IIi + OoOoOO00
    lisp . lisp_ipc ( packet , O0OOo , i11IiIIi11I )
    if 39 - 39: iIii1I11I1II1 + ooOoO0o
    if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
  return
  if 23 - 23: II111iiii * iII111i
  if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
  if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
  if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
  if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  if 21 - 21: OoO0O00
 if ( ooO0000o00O . type == lisp . LISP_MAP_REFERRAL ) :
  Ooo000O00 = "/tmp/lisp-rig"
  if ( os . path . exists ( Ooo000O00 ) ) :
   lisp . lisp_ipc ( packet , O0OOo , Ooo000O00 )
  else :
   lisp . lisp_ipc ( packet , O0OOo , "lisp-mr" )
   if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
  return
  if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
  if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
  if 11 - 11: O0 * OoOoOO00
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  if 18 - 18: OoooooooOO
  if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
 if ( ooO0000o00O . type == lisp . LISP_MAP_REQUEST ) :
  i11IiIIi11I = "lisp-itr" if ( ooO0000o00O . is_smr ( ) ) else "lisp-etr"
  if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
  if 94 - 94: ooOoO0o + I1IiiI
  if 56 - 56: OoOoOO00 % o0oOOo0O0Ooo
  if 40 - 40: OOooOOo / IiII
  if 29 - 29: Ii1I - Ii1I / ooOoO0o
  if ( ooO0000o00O . rloc_probe ) : return
  if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
  lisp . lisp_ipc ( packet , O0OOo , i11IiIIi11I )
  return
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
  if 18 - 18: Oo0Ooo % O0
  if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
  if 86 - 86: IiII
  if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
  if 33 - 33: II111iiii - IiII - ooOoO0o
  if 92 - 92: OoO0O00 * IiII
 if ( ooO0000o00O . type == lisp . LISP_ECM ) :
  OOoOOOo0 = OooO00oO ( source , sport , None )
  if ( OOoOOOo0 ) :
   if ( O0oO ( lisp_sockets , OOoOOOo0 ,
 OO0o0o0oo ) ) : return
   if 92 - 92: oO0o
   if 7 - 7: iII111i
  i11IiIIi11I = "lisp-mr"
  if ( ooO0000o00O . is_to_etr ( ) ) :
   i11IiIIi11I = "lisp-etr"
  elif ( ooO0000o00O . is_to_ms ( ) ) :
   i11IiIIi11I = "lisp-ms"
  elif ( ooO0000o00O . is_ddt ( ) ) :
   if ( lisp . lisp_is_running ( "lisp-ddt" ) ) :
    i11IiIIi11I = "lisp-ddt"
   elif ( lisp . lisp_is_running ( "lisp-ms" ) ) :
    i11IiIIi11I = "lisp-ms"
    if 73 - 73: OoO0O00 % I1ii11iIi11i
  elif ( lisp . lisp_is_running ( "lisp-mr" ) == False ) :
   i11IiIIi11I = "lisp-etr"
   if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  lisp . lisp_ipc ( packet , O0OOo , i11IiIIi11I )
  if 62 - 62: i11iIiiIii
 return
 if 2 - 2: I1IiiI
 if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
 if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
 if 14 - 14: IiII . IiII % ooOoO0o
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
 if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
 if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
 if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
 if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
 if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 6 - 6: oO0o . I11i
 if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
class iI1iiiiiii ( bottle . ServerAdapter ) :
 def run ( self , hand ) :
  Oo00oo = "./lisp-cert.pem"
  if 79 - 79: I1ii11iIi11i / O0 % o0oOOo0O0Ooo
  if 71 - 71: I1Ii111 / I1IiiI / O0
  if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
  if 59 - 59: iIii1I11I1II1 / I1ii11iIi11i % ooOoO0o
  if 84 - 84: iIii1I11I1II1 / I1IiiI . OoOoOO00 % I11i
  if ( os . path . exists ( Oo00oo ) == False ) :
   os . system ( "cp ./lisp-cert.pem.default {}" . format ( Oo00oo ) )
   lisp . lprint ( ( "{} does not exist, creating a copy from lisp-" + "cert.pem.default" ) . format ( Oo00oo ) )
   if 99 - 99: Oo0Ooo + i11iIiiIii
   if 36 - 36: Ii1I * I1Ii111 * iIii1I11I1II1 - I11i % i11iIiiIii
   if 98 - 98: iIii1I11I1II1 - i1IIi + ooOoO0o % I11i + ooOoO0o / oO0o
  O0O0Oo00OO = wsgi_server ( ( self . host , self . port ) , hand )
  O0O0Oo00OO . ssl_adapter = ssl_adaptor ( Oo00oo , Oo00oo , None )
  try :
   O0O0Oo00OO . start ( )
  finally :
   O0O0Oo00OO . stop ( )
   if 100 - 100: o0oOOo0O0Ooo . I1IiiI
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
   if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
   if 13 - 13: II111iiii - Oo0Ooo % i11iIiiIii + iII111i
   if 88 - 88: O0 . oO0o % I1IiiI
   if 10 - 10: I1IiiI + O0
def Oooo0Oo00o ( bottle_port ) :
 lisp . lisp_set_exception ( )
 if 32 - 32: OoOoOO00 . iIii1I11I1II1 % oO0o . O0 . OoOoOO00 / iII111i
 if 45 - 45: iIii1I11I1II1
 if 41 - 41: iII111i % iII111i - IiII % OoO0O00 - OoooooooOO - iII111i
 if 66 - 66: o0oOOo0O0Ooo % OoOoOO00
 if 30 - 30: OoOoOO00 * Oo0Ooo % iIii1I11I1II1 % OoO0O00 + i11iIiiIii
 if ( bottle_port < 0 ) :
  bottle . run ( host = "0.0.0.0" , port = - bottle_port )
  return
  if 46 - 46: I1IiiI . IiII - i11iIiiIii - I1Ii111
  if 97 - 97: II111iiii % Oo0Ooo * IiII
 bottle . server_names [ "lisp-ssl-server" ] = iI1iiiiiii
 if 51 - 51: Oo0Ooo % OOooOOo . Oo0Ooo
 if 72 - 72: Ii1I % Ii1I / I1IiiI
 if 40 - 40: Oo0Ooo - OOooOOo + I1Ii111 - o0oOOo0O0Ooo % I1IiiI . ooOoO0o
 if 35 - 35: i11iIiiIii + OoooooooOO * iIii1I11I1II1 . I1Ii111
 try :
  bottle . run ( host = "0.0.0.0" , port = bottle_port , server = "lisp-ssl-server" ,
 fast = True )
 except :
  bottle . run ( host = "0.0.0.0" , port = bottle_port , fast = True )
  if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
 return
 if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
 if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
 if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
 if 55 - 55: OoooooooOO
 if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
 if 38 - 38: O0
 if 79 - 79: i1IIi . oO0o
 if 34 - 34: I1Ii111 * II111iiii
def o0oO00OOo0oO ( ) :
 lisp . lisp_set_exception ( )
 if 92 - 92: I1IiiI . II111iiii
 return
 if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
 if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
 if 28 - 28: i11iIiiIii
 if 51 - 51: I1IiiI + ooOoO0o * O0 . Ii1I
 if 82 - 82: OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
 if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
 if 20 - 20: i1IIi . i1IIi - I11i
 if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
 if 35 - 35: II111iiii / OoOoOO00 - O0 . II111iiii
def oO0o000oOO ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 ooo0O = { "lisp-itr" : False , "lisp-etr" : False , "lisp-rtr" : False ,
 "lisp-mr" : False , "lisp-ms" : False , "lisp-ddt" : False }
 if 27 - 27: O0 - I11i * II111iiii - iIii1I11I1II1 / ooOoO0o
 while ( True ) :
  time . sleep ( 1 )
  II1i = ooo0O
  ooo0O = { }
  if 98 - 98: OoOoOO00 - OoOoOO00 . II111iiii . iII111i + O0
  for i11IiIIi11I in II1i :
   ooo0O [ i11IiIIi11I ] = lisp . lisp_is_running ( i11IiIIi11I )
   if ( II1i [ i11IiIIi11I ] == ooo0O [ i11IiIIi11I ] ) : continue
   if 28 - 28: IiII + i11iIiiIii + OoooooooOO / OoO0O00
   lisp . lprint ( "*** Process '{}' has {} ***" . format ( i11IiIIi11I ,
 "come up" if ooo0O [ i11IiIIi11I ] else "gone down" ) )
   if 6 - 6: I1IiiI - i11iIiiIii
   if 61 - 61: I1Ii111 * I1ii11iIi11i % I1IiiI % OoO0O00 % I11i + I11i
   if 6 - 6: Oo0Ooo
   if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
   if ( ooo0O [ i11IiIIi11I ] == True ) :
    lisp . lisp_ipc_lock . acquire ( )
    lispconfig . lisp_send_commands ( lisp_socket , i11IiIIi11I )
    lisp . lisp_ipc_lock . release ( )
    if 93 - 93: i11iIiiIii
    if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
    if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
 return
 if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
 if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
 if 58 - 58: I11i
 if 7 - 7: II111iiii / IiII % I11i + I1IiiI - O0
 if 45 - 45: I1IiiI / iII111i + oO0o + IiII
 if 15 - 15: I1IiiI % OoO0O00
 if 66 - 66: oO0o * i11iIiiIii . I1Ii111
def o0O0OOOo0 ( ) :
 lisp . lisp_set_exception ( )
 I1ii1i = 60
 if 51 - 51: OoO0O00 - iII111i % O0 - OoOoOO00
 while ( True ) :
  time . sleep ( I1ii1i )
  if 53 - 53: iII111i / i1IIi / i1IIi
  o0oo00O = [ ]
  IIIIII1iI1II = lisp . lisp_get_timestamp ( )
  if 14 - 14: I1IiiI / O0
  if 43 - 43: oO0o - IiII % i11iIiiIii * II111iiii . I1Ii111 - I11i
  if 13 - 13: OoO0O00
  if 70 - 70: IiII . I1Ii111 * OoO0O00 + I11i - IiII . IiII
  for Ooo0 in lisp . lisp_info_sources_by_address :
   OOoOOOo0 = lisp . lisp_info_sources_by_address [ Ooo0 ]
   if ( OOoOOOo0 . no_timeout ) : continue
   if ( OOoOOOo0 . uptime + I1ii1i < IIIIII1iI1II ) : continue
   if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
   o0oo00O . append ( Ooo0 )
   if 84 - 84: iIii1I11I1II1 + OoooooooOO
   ii111iI1i1 = OOoOOOo0 . nonce
   if ( ii111iI1i1 == None ) : continue
   if ( ii111iI1i1 in lisp . lisp_info_sources_by_nonce ) :
    lisp . lisp_info_sources_by_nonce . pop ( ii111iI1i1 )
    if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
    if 10 - 10: I1ii11iIi11i + IiII
    if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
    if 62 - 62: II111iiii
    if 12 - 12: IiII + II111iiii
    if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
  for Ooo0 in o0oo00O :
   lisp . lisp_info_sources_by_address . pop ( Ooo0 )
   if 80 - 80: iII111i
   if 3 - 3: I1ii11iIi11i * I11i
 return
 if 53 - 53: iIii1I11I1II1 / iII111i % OoO0O00 + IiII / ooOoO0o
 if 74 - 74: Oo0Ooo
 if 8 - 8: I1IiiI % II111iiii - o0oOOo0O0Ooo - I11i % I1IiiI
 if 93 - 93: Ii1I * iII111i / OOooOOo
 if 88 - 88: oO0o
 if 1 - 1: Oo0Ooo
 if 95 - 95: OoooooooOO / I11i % OoooooooOO / ooOoO0o * IiII
 if 75 - 75: O0
def oOoO ( lisp_ipc_control_socket , lisp_sockets ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  try : OOooooO = lisp_ipc_control_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  O000oo = OOooooO [ 0 ] . split ( "@" )
  II11iIiIIIiI = OOooooO [ 1 ]
  if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
  O0OOO = O000oo [ 0 ]
  o0oi1I1I1I = O000oo [ 1 ]
  o0o = int ( O000oo [ 2 ] )
  ooOoOoo000O0O = O000oo [ 3 : : ]
  if 42 - 42: o0oOOo0O0Ooo / IiII
  if ( len ( ooOoOoo000O0O ) > 1 ) :
   ooOoOoo000O0O = lisp . lisp_bit_stuff ( ooOoOoo000O0O )
  else :
   ooOoOoo000O0O = ooOoOoo000O0O [ 0 ]
   if 79 - 79: Ii1I
   if 27 - 27: OoO0O00 + Oo0Ooo
  if ( O0OOO != "control-packet" ) :
   lisp . lprint ( ( "lisp_core_control_packet_process() received" + "unexpected control-packet, message ignored" ) )
   if 92 - 92: I1IiiI % iII111i
   continue
   if 31 - 31: OoooooooOO - oO0o / I1Ii111
   if 62 - 62: i11iIiiIii - I11i
  lisp . lprint ( ( "{} {} bytes from {}, dest/port: {}/{}, control-" + "packet: {}" ) . format ( lisp . bold ( "Receive" , False ) , len ( ooOoOoo000O0O ) ,
  # I11i . Ii1I * OOooOOo - Oo0Ooo - OoooooooOO
 II11iIiIIIiI , o0oi1I1I1I , o0o , lisp . lisp_format_packet ( ooOoOoo000O0O ) ) )
  if 16 - 16: i1IIi * I1Ii111 % i1IIi / I11i
  if 95 - 95: i11iIiiIii
  if 95 - 95: Oo0Ooo
  if 49 - 49: I1IiiI
  if 24 - 24: II111iiii / Ii1I . iIii1I11I1II1 - II111iiii % O0
  if 8 - 8: OoO0O00 % iII111i . OoooooooOO - Ii1I % OoooooooOO
  ooO0000o00O = lisp . lisp_control_header ( )
  ooO0000o00O . decode ( ooOoOoo000O0O )
  if ( ooO0000o00O . type == lisp . LISP_MAP_REPLY ) :
   iIi1Ii1111i = lisp . lisp_map_reply ( )
   iIi1Ii1111i . decode ( ooOoOoo000O0O )
   if ( OooO00oO ( None , 0 , iIi1Ii1111i . nonce ) ) :
    O0O00O0Oo0 ( lisp_sockets , II11iIiIIIiI , o0o , ooOoOoo000O0O )
    continue
    if 61 - 61: o0oOOo0O0Ooo / i11iIiiIii
    if 28 - 28: OOooOOo / OoOoOO00
    if 30 - 30: ooOoO0o
    if 57 - 57: o0oOOo0O0Ooo * i11iIiiIii / OoOoOO00
    if 40 - 40: iIii1I11I1II1 - ooOoO0o / Oo0Ooo
    if 24 - 24: oO0o - iII111i / ooOoO0o
    if 10 - 10: OoOoOO00 * i1IIi
    if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
  if ( ooO0000o00O . type == lisp . LISP_MAP_NOTIFY and II11iIiIIIiI == "lisp-etr" ) :
   i11I1iIiII = lisp . lisp_packet_ipc ( ooOoOoo000O0O , II11iIiIIIiI , o0o )
   lisp . lisp_ipc ( i11I1iIiII , O0OOo , "lisp-itr" )
   continue
   if 34 - 34: I1IiiI
   if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
   if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
   if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
   if 98 - 98: OoO0O00
   if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
   if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  OOOO = lisp . lisp_convert_4to6 ( o0oi1I1I1I )
  OOOO = lisp . lisp_address ( lisp . LISP_AFI_IPV6 , "" , 128 , 0 )
  if ( OOOO . is_ipv4_string ( o0oi1I1I1I ) ) : o0oi1I1I1I = "::ffff:" + o0oi1I1I1I
  OOOO . store_address ( o0oi1I1I1I )
  if 52 - 52: I1Ii111 + I1Ii111
  if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
  if 54 - 54: OoOoOO00 . OoooooooOO
  if 36 - 36: oO0o / II111iiii * IiII % I1ii11iIi11i
  lisp . lisp_send ( lisp_sockets , OOOO , o0o , ooOoOoo000O0O )
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
def O0O0oOOo0O ( ) :
 ii1111iII = open ( "./lisp.config.example" , "r" ) ; iiiiI = ii1111iII . read ( ) ; ii1111iII . close ( )
 ii1111iII = open ( "./lisp.config" , "w" )
 iiiiI = iiiiI . split ( "\n" )
 for OOoO in iiiiI :
  ii1111iII . write ( OOoO + "\n" )
  if ( OOoO [ 0 ] == "#" and OOoO [ - 1 ] == "#" and len ( OOoO ) >= 4 ) :
   o0oO = OOoO [ 1 : - 2 ]
   ooOo0 = len ( o0oO ) * "-"
   if ( o0oO == ooOo0 ) : break
   if 61 - 61: II111iiii
   if 48 - 48: OOooOOo
 ii1111iII . close ( )
 return
 if 26 - 26: iII111i * I1Ii111 * oO0o * OoOoOO00
 if 48 - 48: iII111i % i11iIiiIii . OoooooooOO * IiII % OoO0O00 . iII111i
 if 6 - 6: O0 . ooOoO0o - oO0o / i11iIiiIii
 if 84 - 84: I11i / I1ii11iIi11i * o0oOOo0O0Ooo * OoO0O00 * OOooOOo * O0
 if 83 - 83: O0 % II111iiii + o0oOOo0O0Ooo / OoooooooOO
 if 75 - 75: II111iiii . I1IiiI + OOooOOo - OoOoOO00 - O0 . I11i
 if 19 - 19: Ii1I * i1IIi % O0 + I11i
 if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
def Ii1i ( bottle_port ) :
 global Oo0oO0ooo
 global o00oOoo
 global O0OOo
 global II1Iiii1111i
 global i1IIi11111i
 global o000o0o00o0Oo
 if 49 - 49: oO0o + oO0o + i11iIiiIii % iII111i
 lisp . lisp_i_am ( "core" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "core-process starting up" )
 lisp . lisp_uptime = lisp . lisp_get_timestamp ( )
 lisp . lisp_version = commands . getoutput ( "cat lisp-version.txt" )
 Oo0oO0ooo = commands . getoutput ( "cat lisp-build-date.txt" )
 if 39 - 39: I11i / iII111i + i1IIi % OOooOOo
 if 51 - 51: O0 % II111iiii % i11iIiiIii + OOooOOo . OoooooooOO
 if 14 - 14: Oo0Ooo + i11iIiiIii - oO0o % IiII
 if 1 - 1: oO0o + I1Ii111 . I1IiiI
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 47 - 47: iII111i . OoOoOO00
 if 58 - 58: iII111i + Oo0Ooo / I1IiiI
 if 68 - 68: IiII * Ii1I
 if 91 - 91: Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
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
  o00oOoo = lisp . lisp_open_listen_socket ( iIi11IiiiII11 ,
 str ( lisp . LISP_CTRL_PORT ) )
 else :
  iIi11IiiiII11 = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( )
  o00oOoo = lisp . lisp_open_listen_socket ( iIi11IiiiII11 ,
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
  o000o0o00o0Oo = lisp . lisp_open_listen_socket ( iIi11IiiiII11 ,
 str ( lisp . LISP_DATA_PORT ) )
  lisp . lprint ( "Listen on {}, port 4341" . format ( iIi11IiiiII11 ) )
  if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
  if 23 - 23: I1IiiI
  if 7 - 7: iII111i % I1ii11iIi11i
  if 64 - 64: I1Ii111 + i11iIiiIii
  if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
  if 68 - 68: IiII . ooOoO0o
 O0OOo = lisp . lisp_open_send_socket ( "lisp-core" , "" )
 O0OOo . settimeout ( 3 )
 if 64 - 64: i1IIi + Oo0Ooo * I1IiiI / OOooOOo
 if 3 - 3: Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
 if 50 - 50: iIii1I11I1II1 * oO0o
 if 85 - 85: i1IIi
 if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
 II1Iiii1111i = lisp . lisp_open_listen_socket ( "" , "lisp-core-pkt" )
 if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
 i1IIi11111i = [ o00oOoo , o00oOoo ,
 O0OOo ]
 if 54 - 54: OoOoOO00 * iII111i + OoO0O00
 if 93 - 93: o0oOOo0O0Ooo / I1IiiI
 if 47 - 47: Oo0Ooo * OOooOOo
 if 98 - 98: oO0o - oO0o . ooOoO0o
 if 60 - 60: I1IiiI * I1ii11iIi11i / O0 + I11i + IiII
 threading . Thread ( target = oOoO ,
 args = [ II1Iiii1111i , i1IIi11111i ] ) . start ( )
 if 66 - 66: IiII * Oo0Ooo . OoooooooOO * I1Ii111
 if 93 - 93: IiII / i1IIi
 if 47 - 47: ooOoO0o - Ii1I
 if 98 - 98: oO0o . I1Ii111 / OoOoOO00 . ooOoO0o
 if 1 - 1: OOooOOo
 if 87 - 87: O0 * II111iiii + iIii1I11I1II1 % oO0o % i11iIiiIii - OoOoOO00
 if ( os . path . exists ( "./lisp.config" ) == False ) :
  lisp . lprint ( ( "./lisp.config does not exist, creating a copy " + "from lisp.config.example" ) )
  if 73 - 73: iII111i + Ii1I
  O0O0oOOo0O ( )
  if 37 - 37: oO0o - iIii1I11I1II1 + II111iiii . Ii1I % iIii1I11I1II1
  if 17 - 17: I1Ii111 + i1IIi % O0
  if 65 - 65: IiII
  if 50 - 50: II111iiii / OoO0O00
  if 79 - 79: I1ii11iIi11i - iIii1I11I1II1 % i1IIi / Oo0Ooo + II111iiii
  if 95 - 95: oO0o
 i11ii ( o00oOoo )
 if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
 threading . Thread ( target = lispconfig . lisp_config_process ,
 args = [ O0OOo ] ) . start ( )
 if 100 - 100: OoooooooOO - OoooooooOO + IiII
 if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo / OoooooooOO
 if 90 - 90: I1Ii111
 if 35 - 35: II111iiii / Ii1I
 threading . Thread ( target = Oooo0Oo00o ,
 args = [ bottle_port ] ) . start ( )
 threading . Thread ( target = o0oO00OOo0oO , args = [ ] ) . start ( )
 if 79 - 79: OoOoOO00 + I1Ii111 * iII111i * Ii1I
 if 53 - 53: OOooOOo / Oo0Ooo
 if 10 - 10: I1ii11iIi11i . o0oOOo0O0Ooo
 if 75 - 75: O0 * i1IIi - I11i / OOooOOo % OOooOOo / OoOoOO00
 threading . Thread ( target = oO0o000oOO ,
 args = [ O0OOo ] ) . start ( )
 if 5 - 5: O0 - iII111i / I1Ii111 . o0oOOo0O0Ooo
 if 7 - 7: I1ii11iIi11i - OoOoOO00
 if 54 - 54: oO0o / iIii1I11I1II1 / OoooooooOO . i1IIi - OoOoOO00
 if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
 threading . Thread ( target = o0O0OOOo0 ) . start ( )
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
 lisp . lisp_close_socket ( O0OOo , "lisp-core" )
 lisp . lisp_close_socket ( II1Iiii1111i , "lisp-core-pkt" )
 lisp . lisp_close_socket ( o00oOoo , "" )
 lisp . lisp_close_socket ( o000o0o00o0Oo , "" )
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
 ii1111iII = open ( "./lisp.config" , "r" ) ; iiiiI = ii1111iII . read ( ) ; ii1111iII . close ( )
 iiiiI = iiiiI . split ( "\n" )
 if 68 - 68: OOooOOo + Ii1I
 if 58 - 58: IiII * Ii1I . i1IIi
 if 19 - 19: oO0o
 if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
 if 94 - 94: iIii1I11I1II1 + IiII
 II11II = False
 for OOoO in iiiiI :
  if ( OOoO [ 0 : 1 ] == "#-" and OOoO [ - 2 : - 1 ] == "-#" ) : break
  if ( OOoO == "" or OOoO [ 0 ] == "#" ) : continue
  if ( OOoO . find ( "decentralized-push-xtr = yes" ) == - 1 ) : continue
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
 for OOoO in iiiiI :
  if ( OOoO [ 0 : 1 ] == "#-" and OOoO [ - 2 : - 1 ] == "-#" ) : break
  if ( OOoO == "" or OOoO [ 0 ] == "#" ) : continue
  if 19 - 19: OoooooooOO . I1IiiI + I1Ii111 - I1IiiI / I1IiiI % IiII
  if ( OOoO . find ( "lisp map-server" ) != - 1 ) :
   o0OOOoo0000 = True
   continue
   if 4 - 4: i11iIiiIii * I1ii11iIi11i + OoooooooOO - IiII . ooOoO0o . iIii1I11I1II1
  if ( OOoO [ 0 ] == "}" ) :
   o0OOOoo0000 = False
   continue
   if 48 - 48: o0oOOo0O0Ooo * oO0o . I1IiiI - I1Ii111 + OOooOOo . Oo0Ooo
   if 62 - 62: I11i + OoooooooOO * iIii1I11I1II1 / i1IIi * O0
   if 10 - 10: iIii1I11I1II1 * OoooooooOO / OOooOOo
   if 33 - 33: o0oOOo0O0Ooo % IiII - iIii1I11I1II1 % OOooOOo + I1Ii111 - i11iIiiIii
   if 91 - 91: OoooooooOO . iIii1I11I1II1 / i11iIiiIii
  if ( o0OOOoo0000 and OOoO . find ( "address = " ) != - 1 ) :
   oOOOO = OOoO . split ( "address = " ) [ 1 ]
   OoOOoo0 = int ( oOOOO . split ( "." ) [ 0 ] )
   if ( OoOOoo0 >= 224 and OoOOoo0 < 240 ) : Ii1 . append ( oOOOO )
   if 93 - 93: II111iiii * OoOoOO00 % o0oOOo0O0Ooo
   if 67 - 67: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o - i1IIi . OoOoOO00
 if ( oOOOO == [ ] ) : return
 if 12 - 12: IiII / OoO0O00 / O0 * IiII
 if 51 - 51: ooOoO0o * iII111i / i1IIi
 if 2 - 2: oO0o + IiII . iII111i - i1IIi + I1Ii111
 if 54 - 54: OoooooooOO . oO0o - iII111i
 iIi = commands . getoutput ( 'ifconfig eth0 | egrep "inet "' )
 if ( iIi == "" ) : return
 oO0o00o000Oo0 = iIi . split ( ) [ 1 ]
 if 1 - 1: I1IiiI - I1Ii111
 if 62 - 62: OoO0O00 . iII111i . iII111i % i1IIi * oO0o % Oo0Ooo
 if 20 - 20: ooOoO0o . IiII / I11i . OoooooooOO * OOooOOo + Ii1I
 if 2 - 2: I1IiiI
 Ii111iIi1iIi = socket . inet_aton ( oO0o00o000Oo0 )
 for oOOOO in Ii1 :
  lisp_socket . setsockopt ( socket . SOL_SOCKET , socket . SO_REUSEADDR , 1 )
  lisp_socket . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_IF , Ii111iIi1iIi )
  IIii1Ii = socket . inet_aton ( oOOOO ) + Ii111iIi1iIi
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
if ( Ii1i ( III1I11II11I ) == False ) :
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
 O0OOO , II11iIiIIIiI , o0o , ooOoOoo000O0O = lisp . lisp_receive ( o00oOoo , False )
 if 96 - 96: IiII
 if ( II11iIiIIIiI == "" ) : break
 if 99 - 99: iIii1I11I1II1 - ooOoO0o
 if 79 - 79: I1IiiI + oO0o % I11i % oO0o
 if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
 if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
 II11iIiIIIiI = lisp . lisp_convert_6to4 ( II11iIiIIIiI )
 O0O00O0Oo0 ( i1IIi11111i , II11iIiIIIiI , o0o , ooOoOoo000O0O )
 if 99 - 99: o0oOOo0O0Ooo + OOooOOo
 if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
I1iiII1 ( )
lisp . lisp_print_banner ( "lisp-core normal exit" )
exit ( 0 )
if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
if 76 - 76: oO0o / OoOoOO00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
