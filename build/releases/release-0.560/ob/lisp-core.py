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
try :
 from commands import getoutput
except :
 from subprocess import getoutput
 if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
import time
import os
import bottle
import json
import sys
import socket
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
try :
 from cherrypy . wsgiserver import CherryPyWSGIServer as wsgi_server
 from cherrypy . wsgiserver . ssl_pyopenssl import pyOpenSSLAdapter as ssl_adaptor
except :
 from cheroot . wsgi import Server as wsgi_server
 from cheroot . ssl . builtin import BuiltinSSLAdapter as ssl_adaptor
 if 46 - 46: ooOoO0o * I11i - OoooooooOO
 if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
 if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
 if 94 - 94: i1IIi % Oo0Ooo
 if 68 - 68: Ii1I / O0
 if 46 - 46: O0 * II111iiii / IiII * Oo0Ooo * iII111i . I11i
 if 62 - 62: i11iIiiIii - II111iiii % I1Ii111 - iIii1I11I1II1 . I1ii11iIi11i . II111iiii
OOoO = ""
if 91 - 91: OoO0O00 . i11iIiiIii / oO0o % I11i / OoO0O00 - i11iIiiIii
II1Iiii1111i = None
i1IIi11111i = None
o000o0o00o0Oo = None
oo = [ None , None , None ]
IiII1I1i1i1ii = None
if 44 - 44: oO0o / Oo0Ooo - II111iiii - i11iIiiIii % I1Ii111
if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
if 13 - 13: OOooOOo * oO0o * I1IiiI
if 55 - 55: II111iiii
if 43 - 43: OoOoOO00 - i1IIi + I1Ii111 + Ii1I
if 17 - 17: o0oOOo0O0Ooo
if 64 - 64: Ii1I % i1IIi % OoooooooOO
@ bottle . route ( '/lisp/api' , method = "get" )
@ bottle . route ( '/lisp/api/<command>' , method = "get" )
@ bottle . route ( '/lisp/api/<command>/<data_structure>' , method = "get" )
def i1iIIi1 ( command = "" , data_structure = "" ) :
 ii11iIi1I = [ { "?" : [ { "?" : "not-auth" } ] } ]
 if 6 - 6: OoOoOO00 * iII111i
 if 67 - 67: ooOoO0o - oO0o * o0oOOo0O0Ooo % o0oOOo0O0Ooo % I11i * OoOoOO00
 if 26 - 26: Ii1I - o0oOOo0O0Ooo
 if 63 - 63: II111iiii . II111iiii
 if ( bottle . request . auth != None ) :
  Ii1 , oOOoO0 = bottle . request . auth
  if ( lispconfig . lisp_find_user_account ( Ii1 , oOOoO0 ) == False ) :
   return ( json . dumps ( ii11iIi1I ) )
   if 59 - 59: Ii1I * i11iIiiIii + Ii1I + ooOoO0o * OoO0O00
 else :
  if ( bottle . request . headers [ "User-Agent" ] . find ( "python" ) != - 1 ) :
   return ( json . dumps ( ii11iIi1I ) )
   if 75 - 75: i1IIi - OoO0O00 / I1IiiI . OOooOOo
  if ( lispconfig . lisp_validate_user ( ) == False ) :
   return ( json . dumps ( ii11iIi1I ) )
   if 41 - 41: OoOoOO00
   if 13 - 13: Oo0Ooo . i11iIiiIii - iIii1I11I1II1 - OoOoOO00
   if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
   if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
   if 100 - 100: Ii1I - Ii1I - I1Ii111
   if 20 - 20: OoooooooOO
   if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
 if ( command == "data" and data_structure != "" ) :
  ooO0o0Oo = bottle . request . body . readline ( )
  ii11iIi1I = json . loads ( ooO0o0Oo ) if ooO0o0Oo != "" else ""
  if ( ii11iIi1I != "" ) : ii11iIi1I = ii11iIi1I . values ( ) [ 0 ]
  if ( ii11iIi1I == [ ] ) : ii11iIi1I = ""
  if 78 - 78: iIii1I11I1II1 - Ii1I * OoO0O00 + o0oOOo0O0Ooo + iII111i + iII111i
  if ( type ( ii11iIi1I ) == dict and type ( ii11iIi1I . values ( ) [ 0 ] ) == dict ) :
   ii11iIi1I = ii11iIi1I . values ( ) [ 0 ]
   if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
   if 74 - 74: iII111i * O0
  ii11iIi1I = oOOo0oo ( data_structure , ii11iIi1I )
  return ( ii11iIi1I )
  if 80 - 80: I11i * i11iIiiIii / I1Ii111
  if 9 - 9: Ii1I + oO0o % Ii1I + i1IIi . OOooOOo
  if 31 - 31: o0oOOo0O0Ooo + I11i + I11i / II111iiii
  if 26 - 26: OoooooooOO
  if 12 - 12: OoooooooOO % OoOoOO00 / ooOoO0o % o0oOOo0O0Ooo
 if ( command != "" ) :
  command = "lisp " + command
 else :
  ooO0o0Oo = bottle . request . body . readline ( )
  if ( ooO0o0Oo == "" ) :
   ii11iIi1I = [ { "?" : [ { "?" : "no-body" } ] } ]
   return ( json . dumps ( ii11iIi1I ) )
   if 29 - 29: OoooooooOO
   if 23 - 23: o0oOOo0O0Ooo . II111iiii
  ii11iIi1I = json . loads ( ooO0o0Oo )
  command = ii11iIi1I . keys ( ) [ 0 ]
  if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
  if 45 - 45: I1Ii111 . OoOoOO00
 ii11iIi1I = lispconfig . lisp_get_clause_for_api ( command )
 return ( json . dumps ( ii11iIi1I ) )
 if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
 if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
 if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
 if 8 - 8: OoOoOO00
 if 60 - 60: I11i / I11i
 if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
 if 83 - 83: OoooooooOO
def Iii111II ( ) :
 ii11iIi1I = { }
 ii11iIi1I [ "hostname" ] = socket . gethostname ( )
 ii11iIi1I [ "system-uptime" ] = getoutput ( "uptime" )
 ii11iIi1I [ "lisp-uptime" ] = lisp . lisp_print_elapsed ( lisp . lisp_uptime )
 ii11iIi1I [ "lisp-version" ] = lisp . lisp_version
 if 9 - 9: OoO0O00
 i11 = "yes" if os . path . exists ( "./logs/lisp-traceback.log" ) else "no"
 ii11iIi1I [ "traceback-log" ] = i11
 if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 ii11i1 = lisp . lisp_myrlocs [ 0 ]
 IIIii1II1II = lisp . lisp_myrlocs [ 1 ]
 ii11i1 = "none" if ( ii11i1 == None ) else ii11i1 . print_address_no_iid ( )
 IIIii1II1II = "none" if ( IIIii1II1II == None ) else IIIii1II1II . print_address_no_iid ( )
 ii11iIi1I [ "lisp-rlocs" ] = [ ii11i1 , IIIii1II1II ]
 return ( json . dumps ( ii11iIi1I ) )
 if 42 - 42: Ii1I + oO0o
 if 76 - 76: I1Ii111 - OoO0O00
 if 70 - 70: ooOoO0o
 if 61 - 61: I1ii11iIi11i . I1ii11iIi11i
 if 10 - 10: OoOoOO00 * iII111i . I11i + II111iiii - ooOoO0o * i1IIi
 if 56 - 56: o0oOOo0O0Ooo * IiII * II111iiii
 if 80 - 80: o0oOOo0O0Ooo * II111iiii % II111iiii
 if 59 - 59: iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo - I1IiiI + OOooOOo / I1ii11iIi11i
 if 24 - 24: I11i . iII111i % OOooOOo + ooOoO0o % OoOoOO00
 if 4 - 4: IiII - OoO0O00 * OoOoOO00 - I11i
 if 41 - 41: OoOoOO00 . I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
 if 44 - 44: oO0o
 if 88 - 88: I1Ii111 % Ii1I . II111iiii
 if 38 - 38: o0oOOo0O0Ooo
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
 if 26 - 26: iII111i
def oOOo0oo ( data_structure , data ) :
 OOO = [ "site-cache" , "map-cache" , "system" , "map-resolver" ,
 "map-server" , "database-mapping" , "site-cache-summary" ]
 if 59 - 59: II111iiii + OoooooooOO * OoOoOO00 + i1IIi
 if ( data_structure not in OOO ) : return ( json . dumps ( [ ] ) )
 if 58 - 58: II111iiii * OOooOOo * I1ii11iIi11i / OOooOOo
 if 75 - 75: oO0o
 if 50 - 50: Ii1I / Oo0Ooo - oO0o - I11i % iII111i - oO0o
 if 91 - 91: OoO0O00 / I11i - II111iiii . I11i
 if ( data_structure == "system" ) : return ( Iii111II ( ) )
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if ( data != "" ) : data = json . dumps ( data )
 O0ooo0O0oo0 = lisp . lisp_api_ipc ( "lisp-core" , data_structure + "%" + data )
 if 91 - 91: iIii1I11I1II1 + I1Ii111
 if ( data_structure in [ "map-cache" , "map-resolver" ] ) :
  if ( lisp . lisp_is_running ( "lisp-rtr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , i1IIi11111i , "lisp-rtr" )
  elif ( lisp . lisp_is_running ( "lisp-itr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , i1IIi11111i , "lisp-itr" )
  else :
   return ( json . dumps ( [ ] ) )
   if 31 - 31: IiII . OoOoOO00 . OOooOOo
   if 75 - 75: I11i + OoO0O00 . OoOoOO00 . ooOoO0o + Oo0Ooo . OoO0O00
 if ( data_structure in [ "map-server" , "database-mapping" ] ) :
  if ( lisp . lisp_is_running ( "lisp-etr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , i1IIi11111i , "lisp-etr" )
  elif ( lisp . lisp_is_running ( "lisp-itr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , i1IIi11111i , "lisp-itr" )
  else :
   return ( json . dumps ( [ ] ) )
   if 96 - 96: OOooOOo . ooOoO0o - Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * OOooOOo
   if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
 if ( data_structure in [ "site-cache" , "site-cache-summary" ] ) :
  if ( lisp . lisp_is_running ( "lisp-ms" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , i1IIi11111i , "lisp-ms" )
  else :
   return ( json . dumps ( [ ] ) )
   if 21 - 21: I1IiiI * iIii1I11I1II1
   if 91 - 91: IiII
   if 15 - 15: II111iiii
 lisp . lprint ( "Waiting for api get-data '{}', parmameters: '{}'" . format ( data_structure , data ) )
 if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
 if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
 III1iII1I1ii , oOOo0 , oo00O00oO , iIiIIIi = lisp . lisp_receive ( i1IIi11111i , True )
 lisp . lisp_ipc_lock . release ( )
 return ( iIiIIIi )
 if 93 - 93: iII111i
 if 10 - 10: I11i
 if 82 - 82: I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
 if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 if 83 - 83: I11i / I1IiiI
 if 34 - 34: IiII
@ bottle . route ( '/lisp/api' , method = "put" )
@ bottle . route ( '/lisp/api/<command>' , method = "put" )
@ bottle . route ( '/lisp/api/<command>' , method = "delete" )
def oOo ( command = "" ) :
 ii11iIi1I = [ { "?" : [ { "?" : "not-auth" } ] } ]
 if ( bottle . request . auth == None ) : return ( ii11iIi1I )
 if 75 - 75: I1IiiI + Oo0Ooo
 if 73 - 73: O0 - OoooooooOO . OOooOOo - OOooOOo / OoOoOO00
 if 45 - 45: iIii1I11I1II1 % OoO0O00
 if 29 - 29: OOooOOo + Oo0Ooo . i11iIiiIii - i1IIi / iIii1I11I1II1
 if ( bottle . request . auth != None ) :
  Ii1 , oOOoO0 = bottle . request . auth
  if ( lispconfig . lisp_find_user_account ( Ii1 , oOOoO0 ) == False ) :
   return ( json . dumps ( ii11iIi1I ) )
   if 26 - 26: I11i . OoooooooOO
 else :
  if ( bottle . request . headers [ "User-Agent" ] . find ( "python" ) != - 1 ) :
   return ( json . dumps ( ii11iIi1I ) )
   if 39 - 39: iII111i - O0 % i11iIiiIii * I1Ii111 . IiII
  if ( lispconfig . lisp_validate_user ( ) == False ) :
   return ( json . dumps ( ii11iIi1I ) )
   if 58 - 58: OoO0O00 % i11iIiiIii . iII111i / oO0o
   if 84 - 84: iII111i . I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
   if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
   if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
   if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
   if 51 - 51: O0 + iII111i
   if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if ( command == "user-account" ) :
  if ( lispconfig . lisp_is_user_superuser ( Ii1 ) == False ) :
   ii11iIi1I = [ { "user-account" : [ { "?" : "not-auth" } ] } ]
   return ( json . dumps ( ii11iIi1I ) )
   if 48 - 48: O0
   if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
   if 41 - 41: Ii1I - O0 - O0
   if 68 - 68: OOooOOo % I1Ii111
   if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
   if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 ooO0o0Oo = bottle . request . body . readline ( )
 if ( ooO0o0Oo == "" ) :
  ii11iIi1I = [ { "?" : [ { "?" : "no-body" } ] } ]
  return ( json . dumps ( ii11iIi1I ) )
  if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
  if 23 - 23: O0
 ii11iIi1I = json . loads ( ooO0o0Oo )
 if ( command != "" ) :
  command = "lisp " + command
 else :
  command = ii11iIi1I [ 0 ] . keys ( ) [ 0 ]
  if 85 - 85: Ii1I
  if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
  if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
  if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
  if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
  if 77 - 77: iIii1I11I1II1 * OoO0O00
 lisp . lisp_ipc_lock . acquire ( )
 if ( bottle . request . method == "DELETE" ) :
  ii11iIi1I = lispconfig . lisp_remove_clause_for_api ( ii11iIi1I )
 else :
  ii11iIi1I = lispconfig . lisp_put_clause_for_api ( ii11iIi1I )
  if 95 - 95: I1IiiI + i11iIiiIii
 lisp . lisp_ipc_lock . release ( )
 return ( json . dumps ( ii11iIi1I ) )
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 if 53 - 53: II111iiii
 if 31 - 31: OoO0O00
@ bottle . route ( '/lisp/show/api-doc' , method = "get" )
def o0O ( ) :
 if ( os . path . exists ( "lispapi.py" ) ) : os . system ( "pydoc lispapi > lispapi.txt" )
 if ( os . path . exists ( "lispapi.txt" ) == False ) :
  return ( "lispapi.txt file not found" )
  if 2 - 2: iIii1I11I1II1 / oO0o + OoO0O00 / OOooOOo
 return ( bottle . static_file ( "lispapi.txt" , root = "./" ) )
 if 9 - 9: o0oOOo0O0Ooo . ooOoO0o - Oo0Ooo - oO0o + II111iiii * i11iIiiIii
 if 79 - 79: oO0o % I11i % I1IiiI
 if 5 - 5: OoooooooOO % OoOoOO00 % oO0o % iII111i
 if 7 - 7: II111iiii + OoooooooOO . I1Ii111 . ooOoO0o - o0oOOo0O0Ooo
 if 26 - 26: Oo0Ooo / IiII % iIii1I11I1II1 / IiII + I11i
@ bottle . route ( '/lisp/show/command-doc' , method = "get" )
def oOO0O00oO0Ooo ( ) :
 return ( bottle . static_file ( "lisp.config.example" , root = "./" ,
 mimetype = "text/plain" ) )
 if 67 - 67: OoO0O00 - OOooOOo
 if 36 - 36: IiII
 if 36 - 36: ooOoO0o / O0 * Oo0Ooo - OOooOOo % iIii1I11I1II1 * oO0o
 if 79 - 79: O0
 if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
 if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 if 57 - 57: OoO0O00 / ooOoO0o
@ bottle . route ( '/lisp/show/lisp-xtr' , method = "get" )
def Ii1I1Ii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
  if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
  if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
  if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
  if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
  if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if ( os . path . exists ( "./show-ztr" ) ) :
  Oo = open ( "./show-ztr" , "r" ) ; O0OOOOo0O = Oo . read ( ) ; Oo . close ( )
 else :
  Oo = open ( "./show-xtr" , "r" ) ; O0OOOOo0O = Oo . read ( ) ; Oo . close ( )
  if 81 - 81: O0 / OoO0O00 . i1IIi + I1IiiI - I11i
  if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
 oooOo0OOOoo0 = ""
 O0OOOOo0O = O0OOOOo0O . split ( "\n" )
 for OOoOOO0O000 in O0OOOOo0O :
  if ( OOoOOO0O000 [ 0 : 4 ] == "    " ) : oooOo0OOOoo0 += lisp . lisp_space ( 4 )
  if ( OOoOOO0O000 [ 0 : 2 ] == "  " ) : oooOo0OOOoo0 += lisp . lisp_space ( 2 )
  oooOo0OOOoo0 += OOoOOO0O000 + "<br>"
  if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 oooOo0OOOoo0 = lisp . convert_font ( oooOo0OOOoo0 )
 return ( lisp . lisp_print_sans ( oooOo0OOOoo0 ) )
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
 if 71 - 71: Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
@ bottle . route ( '/lisp/show/<xtr>/keys' , method = "get" )
def ooooo0O0000oo ( xtr ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 21 - 21: o0oOOo0O0Ooo - I1IiiI
 II11I1 = lispconfig . lisp_is_user_superuser ( None )
 if 62 - 62: I1ii11iIi11i / i1IIi
 if ( II11I1 == False ) :
  iIiIIIi = "Permission denied"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 98 - 98: i1IIi / I11i
  if 32 - 32: Ii1I * iIii1I11I1II1 / OOooOOo
 if ( xtr not in [ "itr" , "etr" , "rtr" ] ) :
  iIiIIIi = "Invalid URL"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
 OoOOo0OOoO = "show {}-keys" . format ( xtr )
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i , OoOOo0OOoO ) )
 if 72 - 72: Ii1I
 if 1 - 1: OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
 if 76 - 76: IiII * iII111i
 if 52 - 52: OOooOOo
@ bottle . route ( '/lisp/geo-map/<geo_prefix>' )
def iiii1 ( geo_prefix ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 96 - 96: i11iIiiIii % OOooOOo
  if 70 - 70: iIii1I11I1II1
 geo_prefix = geo_prefix . split ( "-" )
 geo_prefix = "-" . join ( geo_prefix [ 0 : - 1 ] ) + "/" + geo_prefix [ - 1 ]
 i11ii1iI = lisp . lisp_geo ( "" )
 i11ii1iI . parse_geo_string ( geo_prefix )
 i1I , IIIii11 = i11ii1iI . dms_to_decimal ( )
 iiIiIIIiiI = i11ii1iI . radius * 1000
 if 12 - 12: O0 - o0oOOo0O0Ooo
 oOoO00O0 = open ( "./lispers.net-geo.html" , "r" ) ; OO = oOoO00O0 . read ( ) ; oOoO00O0 . close ( )
 OO = OO . replace ( "$LAT" , str ( i1I ) )
 OO = OO . replace ( "$LON" , str ( IIIii11 ) )
 OO = OO . replace ( "$RADIUS" , str ( iiIiIIIiiI ) )
 return ( OO )
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
 if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 if 23 - 23: i11iIiiIii
 if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
 if 81 - 81: IiII % i1IIi . iIii1I11I1II1
 if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
 if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
@ bottle . route ( '/lisp/login' , method = "get" )
def OOoO0 ( ) :
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
 return ( OOoO0 ( ) )
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
  return ( OOoO0 ( ) )
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
  return ( OOoO0 ( ) )
  if 39 - 39: I1Ii111
  if 91 - 91: OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoOoOO00 + O0
 iIiii1iI1 = True
 if 33 - 33: IiII % iIii1I11I1II1 * I1IiiI
 if 95 - 95: ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 if ( os . path . exists ( "./logs/lisp-traceback.log" ) ) :
  iIiIIIi = getoutput ( "cat ./logs/lisp-traceback.log" )
  if ( iIiIIIi ) :
   iIiIIIi = iIiIIIi . replace ( "----------" , "<b>----------</b>" )
   iIiIIIi = iIiIIIi . replace ( "\n" , "<br>" )
   iIiii1iI1 = False
   if 41 - 41: i1IIi - I11i - Ii1I
   if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
   if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
   if 44 - 44: II111iiii
   if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
   if 35 - 35: iIii1I11I1II1
 if ( iIiii1iI1 ) :
  iIiIIIi = ""
  I1i = "egrep --with-filename Traceback ./logs/*.log"
  iIII = getoutput ( I1i )
  iIII = iIII . split ( "\n" )
  for o0o0O in iIII :
   if ( o0o0O . find ( ":" ) == - 1 ) : continue
   OOoOOO0O000 = o0o0O . split ( ":" )
   if ( OOoOOO0O000 [ 1 ] == "0" ) : continue
   iIiIIIi += "Found Tracebacks in log file {}<br>" . format ( OOoOOO0O000 [ 0 ] )
   iIiii1iI1 = False
   if 68 - 68: ooOoO0o
  iIiIIIi = iIiIIIi [ 0 : - 4 ]
  if 25 - 25: I1ii11iIi11i . ooOoO0o
  if 24 - 24: oO0o / i11iIiiIii + oO0o
 if ( iIiii1iI1 ) :
  iIiIIIi = "No Tracebacks found - a stable system is a happy system"
  if 20 - 20: I11i + Ii1I / O0 % iIii1I11I1II1
  if 88 - 88: OoOoOO00 / II111iiii
 iIiIIIi = lisp . lisp_print_cour ( iIiIIIi )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
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
  return ( OOoO0 ( ) )
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
  return ( OOoO0 ( ) )
  if 74 - 74: Oo0Ooo - o0oOOo0O0Ooo . i1IIi
  if 43 - 43: iII111i / I1IiiI
  if 58 - 58: I1IiiI + i11iIiiIii % Ii1I . OoOoOO00
  if 13 - 13: i11iIiiIii + i1IIi * iIii1I11I1II1 % OoooooooOO - II111iiii * OOooOOo
  if 26 - 26: OoooooooOO * I1IiiI + OOooOOo
 iIiIIIi = ""
 II11I1 = lispconfig . lisp_is_user_superuser ( None )
 if ( II11I1 ) :
  IiIii1i111 = lisp . lisp_button ( "show configuration" , "/lisp/show/conf" )
  iI = lisp . lisp_button ( "show configuration diff" , "/lisp/show/diff" )
  o0o00 = lisp . lisp_button ( "archive configuration" , "/lisp/archive/conf" )
  IIi = lisp . lisp_button ( "clear configuration" , "/lisp/clear/conf/verify" )
  o0o0O = lisp . lisp_button ( "log flows" , "/lisp/log/flows" )
  oOoO00oo0O = lisp . lisp_button ( "install LISP software" , "/lisp/install/image" )
  IiiiI = lisp . lisp_button ( "restart LISP subsystem" , "/lisp/restart/verify" )
  if 61 - 61: OOooOOo % OOooOOo * o0oOOo0O0Ooo / o0oOOo0O0Ooo
  iIiIIIi = "<center>{}{}{}{}{}{}{}</center><hr>" . format ( IiIii1i111 , iI , o0o00 , IIi ,
 o0o0O , oOoO00oo0O , IiiiI )
  if 75 - 75: IiII . ooOoO0o
  if 50 - 50: OoOoOO00
 O00o0OO0000oo = getoutput ( "uptime" )
 i1 = getoutput ( "uname -pv" )
 OO0oOOoo = lisp . lisp_version . replace ( "+" , "" )
 if 52 - 52: o0oOOo0O0Ooo % Oo0Ooo
 if 64 - 64: O0 % I11i % O0 * OoO0O00 . oO0o + I1IiiI
 if 75 - 75: I11i . OoooooooOO % o0oOOo0O0Ooo * I11i % OoooooooOO
 if 13 - 13: IiII / i11iIiiIii % II111iiii % I11i . I1ii11iIi11i
 if 8 - 8: OoOoOO00 + Oo0Ooo - II111iiii
 IiIi1iIIi1 = multiprocessing . cpu_count ( )
 if 86 - 86: I11i * I1IiiI + I11i + II111iiii
 i1i111iI = O00o0OO0000oo . find ( ", load" )
 O00o0OO0000oo = O00o0OO0000oo [ 0 : i1i111iI ]
 IIiiI = lisp . lisp_print_elapsed ( lisp . lisp_uptime )
 if 31 - 31: I1ii11iIi11i + Ii1I + I1Ii111 / Ii1I
 iiI111 = "Not available"
 if 1 - 1: I11i * o0oOOo0O0Ooo . OoOoOO00 / O0
 if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo % O0 * O0
 if 14 - 14: I1ii11iIi11i . ooOoO0o + II111iiii / iII111i / I11i
 if 74 - 74: O0 / i1IIi
 OoOOo0OOoO = "ps auww" if lisp . lisp_is_macos ( ) else "ps aux"
 OoO = getoutput ( "{} | egrep 'PID|python lisp|python -O lisp' | egrep -v grep" . format ( OoOOo0OOoO ) )
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 OoO = OoO . replace ( " " , lisp . space ( 1 ) )
 OoO = OoO . replace ( "\n" , "<br>" )
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if ( i1 . find ( "Darwin" ) != - 1 ) :
  IiIi1iIIi1 = IiIi1iIIi1 / 2
  iiI111 = getoutput ( "top -l 1 | head -50" )
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
  O0OOOOo0O = getoutput ( "top -b -n 1 | head -50" )
  O0OOOOo0O = O0OOOOo0O . split ( "PID" )
  O0OOOOo0O [ 1 ] = O0OOOOo0O [ 1 ] . replace ( " " , lisp . space ( 1 ) )
  O0OOOOo0O = O0OOOOo0O [ 0 ] + O0OOOOo0O [ 1 ]
  iiI111 = O0OOOOo0O . replace ( "\n" , "<br>" )
  if 92 - 92: I11i . I1Ii111
  if 85 - 85: I1ii11iIi11i . I1Ii111
 O0O0Ooooo000 = getoutput ( "cat release-notes.txt" )
 O0O0Ooooo000 = O0O0Ooooo000 . replace ( "\n" , "<br>" )
 if 65 - 65: OOooOOo * I1Ii111
 iIiIIIi += '''
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
        ''' . format ( OO0oOOoo , lisp . lisp_version , OOoO , IIiiI ,
 O00o0OO0000oo , lisp . lisp_space ( 1 ) , IiIi1iIIi1 , i1 , OoO , iiI111 ,
 O0O0Ooooo000 )
 if 79 - 79: OoooooooOO - I1IiiI
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
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
  return ( OOoO0 ( ) )
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
  return ( OOoO0 ( ) )
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
  return ( OOoO0 ( ) )
  if 87 - 87: ooOoO0o
  if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 lisp . lisp_ipc_lock . acquire ( )
 os . system ( "cp ./lisp.config ./lisp.config.archive" )
 lisp . lisp_ipc_lock . release ( )
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
 iIiIIIi = "Configuration file saved to "
 iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
 iIiIIIi += lisp . lisp_print_cour ( "./lisp.config.archive" )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
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
  return ( OOoO0 ( ) )
  if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
  if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 os . system ( "cp ./lisp.config ./lisp.config.before-clear" )
 lisp . lisp_ipc_lock . acquire ( )
 O0O0oOOo0O ( )
 lisp . lisp_ipc_lock . release ( )
 if 19 - 19: o0oOOo0O0Ooo / I1Ii111 % o0oOOo0O0Ooo % iII111i * IiII
 iIiIIIi = "Configuration cleared, a backup copy is stored in "
 iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
 iIiIIIi += lisp . lisp_print_cour ( "./lisp.config.before-clear" )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
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
  return ( OOoO0 ( ) )
  if 83 - 83: I11i / I1ii11iIi11i
  if 34 - 34: I1IiiI * Oo0Ooo * I1Ii111 / OoO0O00 * I11i / iIii1I11I1II1
 iIiIIIi = "<br>Are you sure you want to clear the configuration?"
 iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
 if 74 - 74: Oo0Ooo / i11iIiiIii - II111iiii * o0oOOo0O0Ooo
 IIi1IIIIi = lisp . lisp_button ( "yes" , "/lisp/clear/conf" )
 OOOoO = lisp . lisp_button ( "cancel" , "/lisp" )
 iIiIIIi += IIi1IIIIi + OOOoO + "<br>"
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
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
 oo00O00oO = ""
 if 98 - 98: o0oOOo0O0Ooo + O0 % i1IIi - OOooOOo + Oo0Ooo
 for OoOo000oOo0oo in [ "443" , "-8080" , "8080" ] :
  oO0O = 'ps auxww | egrep "lisp-core.pyo {}" | egrep -v grep' . format ( OoOo000oOo0oo )
  iIiIIIi = getoutput ( oO0O )
  if ( iIiIIIi == "" ) : continue
  if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
  iIiIIIi = iIiIIIi . split ( "\n" ) [ 0 ]
  iIiIIIi = iIiIIIi . split ( " " )
  if ( iIiIIIi [ - 2 ] == "lisp-core.pyo" and iIiIIIi [ - 1 ] == OoOo000oOo0oo ) : oo00O00oO = OoOo000oOo0oo
  break
  if 56 - 56: O0
 return ( oo00O00oO )
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
  return ( OOoO0 ( ) )
  if 46 - 46: OoO0O00
  if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
  if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
  if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
  if 68 - 68: OoooooooOO % II111iiii
  if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 OOoOOO0O000 = getoutput ( "egrep requiretty /etc/sudoers" ) . split ( " " )
 if ( OOoOOO0O000 [ - 1 ] == "requiretty" and OOoOOO0O000 [ 0 ] == "Defaults" ) :
  iIiIIIi = "Need to remove 'requiretty' from /etc/sudoers"
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
  if 2 - 2: Ii1I - IiII
 lisp . lprint ( lisp . bold ( "LISP subsystem restart request received" , False ) )
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 oo00O00oO = Oo0oOooo000OO ( )
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
 OoOOo0OOoO = "sleep 1; sudo ./RESTART-LISP {}" . format ( oo00O00oO )
 threading . Thread ( target = Ii1Iii111IiI1 , args = [ OoOOo0OOoO ] ) . start ( )
 if 98 - 98: I1Ii111 - OoooooooOO % I1IiiI + O0 . Ii1I
 iIiIIIi = lisp . lisp_print_sans ( "Restarting LISP subsystem ..." )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 56 - 56: II111iiii / oO0o + i11iIiiIii + OOooOOo
 if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
 if 79 - 79: Ii1I . OoO0O00
 if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
 if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
 if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
 if 52 - 52: i1IIi
def Ii1Iii111IiI1 ( command ) :
 os . system ( command )
 if 84 - 84: Ii1I / IiII
 if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if 37 - 37: i11iIiiIii + i1IIi
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 if 8 - 8: o0oOOo0O0Ooo
@ bottle . route ( '/lisp/restart/verify' )
def II1II1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 48 - 48: i1IIi + I11i % OoOoOO00 / Oo0Ooo - o0oOOo0O0Ooo
  if 67 - 67: oO0o % o0oOOo0O0Ooo . OoooooooOO + OOooOOo * I11i * OoOoOO00
 iIiIIIi = "<br>Are you sure you want to restart the LISP subsystem?"
 iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
 if 36 - 36: O0 + Oo0Ooo
 IIi1IIIIi = lisp . lisp_button ( "yes" , "/lisp/restart" )
 OOOoO = lisp . lisp_button ( "cancel" , "/lisp" )
 iIiIIIi += IIi1IIIIi + OOOoO + "<br>"
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
@ bottle . route ( '/lisp/install' , method = "post" )
def oooo0OOo ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 72 - 72: O0 / ooOoO0o + OoooooooOO * iII111i
  if 61 - 61: OoooooooOO % II111iiii - I1IiiI % I1ii11iIi11i + i1IIi
 i1II = bottle . request . forms . get ( "image_url" )
 if ( i1II . find ( "lispers.net" ) == - 1 or i1II . find ( ".tgz" ) == - 1 ) :
  iIi1IiI = "Invalid install request for file {}" . format ( i1II )
  lisp . lprint ( lisp . bold ( iIi1IiI , False ) )
  iIiIIIi = lisp . lisp_print_sans ( "Invalid lispers.net tarball file name" )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
  if 53 - 53: Ii1I % Oo0Ooo
 if ( lisp . lisp_is_ubuntu ( ) ) :
  oO0O = "python lisp-get-bits.pyo {} force 2>&1 > /dev/null" . format ( i1II )
 else :
  oO0O = "python lisp-get-bits.pyo {} force >& /dev/null" . format ( i1II )
  if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 OoO = os . system ( oO0O )
 if 41 - 41: Ii1I % I1ii11iIi11i
 i1iIiIi1I = i1II . split ( "/" ) [ - 1 ]
 if 37 - 37: Ii1I % OoO0O00
 if ( os . path . exists ( i1iIiIi1I ) ) :
  oOooO0 = i1II . split ( "release-" ) [ 1 ]
  oOooO0 = oOooO0 . split ( ".tgz" ) [ 0 ]
  if 74 - 74: I11i - OOooOOo + i1IIi . I1IiiI + OOooOOo - I11i
  iIiIIIi = "Install completed for release {}" . format ( oOooO0 )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  if 17 - 17: O0 . I1Ii111 . O0 + O0 / Oo0Ooo . ooOoO0o
  iIiIIIi += "<br><br>" + lisp . lisp_button ( "restart LISP subsystem" ,
 "/lisp/restart/verify" ) + "<br>"
 else :
  iIi1IiI = lisp . lisp_print_cour ( i1II )
  iIiIIIi = "Install failed for file {}" . format ( iIi1IiI )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  if 62 - 62: I1ii11iIi11i % iII111i * OoO0O00 - i1IIi
  if 66 - 66: i11iIiiIii / o0oOOo0O0Ooo - OoooooooOO / i1IIi . i11iIiiIii
 iIi1IiI = "Install request for file {} {}" . format ( i1II ,
 "succeeded" if ( OoO == 0 ) else "failed" )
 lisp . lprint ( lisp . bold ( iIi1IiI , False ) )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 16 - 16: Oo0Ooo % I1ii11iIi11i + I11i - O0 . iII111i / I1Ii111
 if 35 - 35: oO0o / I1Ii111 / II111iiii - iIii1I11I1II1 + II111iiii . I1Ii111
 if 81 - 81: iII111i * OOooOOo - I1ii11iIi11i * Ii1I % OoOoOO00 * OoOoOO00
 if 59 - 59: iIii1I11I1II1
 if 7 - 7: OOooOOo * I1IiiI / o0oOOo0O0Ooo * i11iIiiIii
 if 84 - 84: OOooOOo . iII111i
 if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
@ bottle . route ( '/lisp/install/image' )
def iIii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
  if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 iIi1IiI = lisp . lisp_print_sans ( "<br>Enter lispers.net tarball URL:" )
 iIiIIIi = '''
        <form action="/lisp/install" method="post" style="display: inline;">
        {}
        <input type="text" name="image_url" size="75" required/>
        <input type="submit" style="background-color:transparent;border-radius:10px;" value="Submit" />
        </form><br>''' . format ( iIi1IiI )
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
 if 57 - 57: O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
@ bottle . route ( '/lisp/log/flows' )
def iii1III1i ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 17 - 17: II111iiii / II111iiii
  if 65 - 65: IiII + Oo0Ooo
 os . system ( "touch ./log-flows" )
 if 59 - 59: OoooooooOO + I11i . I1Ii111 - O0 % iIii1I11I1II1 / O0
 iIiIIIi = lisp . lisp_print_sans ( "Flow data appended to file " )
 OOooO0o = "<a href='/lisp/show/log/lisp-flow/100'>logs/lisp-flows.log</a>"
 iIiIIIi += lisp . lisp_print_cour ( OOooO0o )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 25 - 25: iIii1I11I1II1 - iII111i
 if 3 - 3: I1IiiI * ooOoO0o + II111iiii - OoO0O00
 if 97 - 97: I1ii11iIi11i / oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
@ bottle . route ( '/lisp/search/log/<name>/<num>/<keyword>' )
def oo0 ( name = "" , num = "" , keyword = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 73 - 73: OoOoOO00 . I1IiiI
  if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
 OoOOo0OOoO = "tail -n {} logs/{}.log | egrep -B10 -A10 {}" . format ( num , name ,
 keyword )
 iIiIIIi = getoutput ( OoOOo0OOoO )
 if 48 - 48: iII111i * iII111i
 if ( iIiIIIi ) :
  I1I1 = iIiIIIi . count ( keyword )
  iIiIIIi = lisp . convert_font ( iIiIIIi )
  iIiIIIi = iIiIIIi . replace ( "--\n--\n" , "--\n" )
  iIiIIIi = iIiIIIi . replace ( "\n" , "<br>" )
  iIiIIIi = iIiIIIi . replace ( "--<br>" , "<hr>" )
  iIiIIIi = "Found <b>{}</b> occurences<hr>" . format ( I1I1 ) + iIiIIIi
 else :
  iIiIIIi = "Keyword {} not found" . format ( keyword )
  if 4 - 4: o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
  if 32 - 32: i11iIiiIii - I1Ii111
  if 53 - 53: OoooooooOO - IiII
  if 87 - 87: oO0o . I1IiiI
  if 17 - 17: Ii1I . i11iIiiIii
 IIIiiiI = "<font color='blue'><b>{}</b>" . format ( keyword )
 iIiIIIi = iIiIIIi . replace ( keyword , IIIiiiI )
 iIiIIIi = iIiIIIi . replace ( keyword , keyword + "</font>" )
 if 94 - 94: O0 - I11i - iIii1I11I1II1 % ooOoO0o / Ii1I % iII111i
 iIiIIIi = lisp . lisp_print_cour ( iIiIIIi )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 44 - 44: Oo0Ooo % iIii1I11I1II1
 if 90 - 90: II111iiii + OoooooooOO % OoooooooOO
 if 35 - 35: iII111i / I1ii11iIi11i * OoooooooOO . II111iiii / Oo0Ooo
 if 1 - 1: OoooooooOO + IiII . i1IIi % I11i
 if 66 - 66: o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
 if 12 - 12: iII111i . IiII . OoOoOO00 / O0
 if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
@ bottle . post ( '/lisp/search/log/<name>/<num>' )
def II ( name = "" , num = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 94 - 94: I11i + II111iiii % i11iIiiIii
  if 8 - 8: ooOoO0o * O0
 OOoOIiIIII = bottle . request . forms . get ( "keyword" )
 return ( oo0 ( name , num , OOoOIiIIII ) )
 if 89 - 89: OoO0O00 / I1IiiI
 if 16 - 16: Oo0Ooo + ooOoO0o / Oo0Ooo / OoO0O00 % oO0o % I1ii11iIi11i
 if 22 - 22: II111iiii * OoO0O00 * I11i + I1ii11iIi11i * o0oOOo0O0Ooo
 if 100 - 100: i1IIi / IiII
 if 3 - 3: II111iiii % I1ii11iIi11i - OoooooooOO * Oo0Ooo . iIii1I11I1II1
 if 37 - 37: iII111i / Oo0Ooo . I11i * I11i
 if 80 - 80: OOooOOo % I1ii11iIi11i
@ bottle . route ( '/lisp/show/log/<name>/<num>' )
def O0Ooo ( name = "" , num = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 78 - 78: OoO0O00 % IiII * i1IIi
  if 66 - 66: Ii1I . I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1
  if 51 - 51: I11i . Oo0Ooo
  if 45 - 45: i1IIi - Oo0Ooo / O0 . I1ii11iIi11i
  if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if ( num == "" ) : num = 100
 if 56 - 56: OoooooooOO - I11i - i1IIi
 I1i1I = '''
        <form action="/lisp/search/log/{}/{}" method="post">
        <i>Keyword search:</i>
        <input type="text" name="keyword" />
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </form><hr>
    ''' . format ( name , num )
 if 35 - 35: i11iIiiIii - I1IiiI
 if ( os . path . exists ( "logs/{}.log" . format ( name ) ) ) :
  iIiIIIi = getoutput ( "tail -n {} logs/{}.log" . format ( num , name ) )
  iIiIIIi = lisp . convert_font ( iIiIIIi )
  iIiIIIi = iIiIIIi . replace ( "\n" , "<br>" )
  iIiIIIi = I1i1I + lisp . lisp_print_cour ( iIiIIIi )
 else :
  OOoo0oO00oo00 = lisp . lisp_print_sans ( "File" )
  O0ii = lisp . lisp_print_cour ( "logs/{}.log" . format ( name ) )
  ooO0o0oO = lisp . lisp_print_sans ( "does not exist" )
  iIiIIIi = "{} {} {}" . format ( OOoo0oO00oo00 , O0ii , ooO0o0oO )
  if 67 - 67: OoooooooOO
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 if 66 - 66: Oo0Ooo
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
@ bottle . route ( '/lisp/debug/<name>' )
def oO0 ( name = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
  if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
  if 89 - 89: OoO0O00 + IiII * I1Ii111
  if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
  if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if ( name == "disable%all" ) :
  ii11iIi1I = lispconfig . lisp_get_clause_for_api ( "lisp debug" )
  if ( ii11iIi1I [ 0 ] . has_key ( "lisp debug" ) ) :
   oooOo0OOOoo0 = [ ]
   for Ii in ii11iIi1I [ 0 ] [ "lisp debug" ] :
    I1i111IiIiIi1 = Ii . keys ( ) [ 0 ]
    oooOo0OOOoo0 . append ( { I1i111IiIiIi1 : "no" } )
    if 39 - 39: I11i - I1ii11iIi11i
   oooOo0OOOoo0 = { "lisp debug" : oooOo0OOOoo0 }
   lispconfig . lisp_put_clause_for_api ( oooOo0OOOoo0 )
   if 53 - 53: o0oOOo0O0Ooo % iII111i + ooOoO0o . Oo0Ooo - I1ii11iIi11i % o0oOOo0O0Ooo
   if 64 - 64: II111iiii
  ii11iIi1I = lispconfig . lisp_get_clause_for_api ( "lisp xtr-parameters" )
  if ( ii11iIi1I [ 0 ] . has_key ( "lisp xtr-parameters" ) ) :
   oooOo0OOOoo0 = [ ]
   for Ii in ii11iIi1I [ 0 ] [ "lisp xtr-parameters" ] :
    I1i111IiIiIi1 = Ii . keys ( ) [ 0 ]
    if ( I1i111IiIiIi1 in [ "data-plane-logging" , "flow-logging" ] ) :
     oooOo0OOOoo0 . append ( { I1i111IiIiIi1 : "no" } )
    else :
     oooOo0OOOoo0 . append ( { I1i111IiIiIi1 : Ii [ I1i111IiIiIi1 ] } )
     if 40 - 40: OoOoOO00 % OoO0O00
     if 62 - 62: o0oOOo0O0Ooo
   oooOo0OOOoo0 = { "lisp xtr-parameters" : oooOo0OOOoo0 }
   lispconfig . lisp_put_clause_for_api ( oooOo0OOOoo0 )
   if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
   if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
  return ( lispconfig . lisp_landing_page ( ) )
  if 72 - 72: iIii1I11I1II1
  if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
  if 87 - 87: OoO0O00 % I1IiiI
  if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 name = name . split ( "%" )
 iIi1iIIIiIiI = name [ 0 ]
 i11 = name [ 1 ]
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 ooOo0O0O0oOO0 = [ "data-plane-logging" , "flow-logging" ]
 if 10 - 10: Oo0Ooo + O0
 Ii1iI = "lisp xtr-parameters" if ( iIi1iIIIiIiI in ooOo0O0O0oOO0 ) else "lisp debug"
 if 53 - 53: iIii1I11I1II1 - oO0o % OoOoOO00 * I1Ii111 % ooOoO0o
 if 29 - 29: o0oOOo0O0Ooo / Oo0Ooo * I1ii11iIi11i . o0oOOo0O0Ooo
 ii11iIi1I = lispconfig . lisp_get_clause_for_api ( Ii1iI )
 if 64 - 64: oO0o / ooOoO0o % i11iIiiIii
 if ( ii11iIi1I [ 0 ] . has_key ( Ii1iI ) ) :
  oooOo0OOOoo0 = { }
  for Ii in ii11iIi1I [ 0 ] [ Ii1iI ] :
   oooOo0OOOoo0 [ Ii . keys ( ) [ 0 ] ] = Ii . values ( ) [ 0 ]
   if ( oooOo0OOOoo0 . has_key ( iIi1iIIIiIiI ) ) : oooOo0OOOoo0 [ iIi1iIIIiIiI ] = i11
   if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  oooOo0OOOoo0 = { Ii1iI : oooOo0OOOoo0 }
  lispconfig . lisp_put_clause_for_api ( oooOo0OOOoo0 )
  if 64 - 64: i1IIi
 return ( lispconfig . lisp_landing_page ( ) )
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
@ bottle . route ( '/lisp/clear/<name>' )
@ bottle . route ( '/lisp/clear/etr/<etr_name>/<stats_name>' )
@ bottle . route ( '/lisp/clear/rtr/<rtr_name>/<stats_name>' )
@ bottle . route ( '/lisp/clear/itr/<itr_name>' )
@ bottle . route ( '/lisp/clear/rtr/<rtr_name>' )
def OoOOo00 ( name = "" , itr_name = '' , rtr_name = "" , etr_name = "" ,
 stats_name = "" ) :
 if 53 - 53: IiII . I1Ii111 % iIii1I11I1II1 % OoOoOO00 % I11i
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 53 - 53: I1Ii111
  if 69 - 69: OoOoOO00 . o0oOOo0O0Ooo . I1IiiI - I1ii11iIi11i
  if 32 - 32: OoooooooOO / I1IiiI / iIii1I11I1II1 + II111iiii . oO0o . o0oOOo0O0Ooo
  if 21 - 21: iIii1I11I1II1 / II111iiii % i1IIi
  if 8 - 8: OoO0O00 + OoOoOO00 . iIii1I11I1II1 % O0
 if ( lispconfig . lisp_is_user_superuser ( None ) == False ) :
  iIiIIIi = lisp . lisp_print_sans ( "Not authorized" )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 43 - 43: I1ii11iIi11i - iII111i
  if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 O0ooo0O0oo0 = "clear"
 if ( name == "referral" ) :
  i1II11Iii1I = "lisp-mr"
  oO00OoOOOo = "Referral"
 elif ( itr_name == "map-cache" ) :
  i1II11Iii1I = "lisp-itr"
  oO00OoOOOo = "ITR <a href='/lisp/show/itr/map-cache'>map-cache</a>"
 elif ( rtr_name == "map-cache" ) :
  i1II11Iii1I = "lisp-rtr"
  oO00OoOOOo = "RTR <a href='/lisp/show/rtr/map-cache'>map-cache</a>"
 elif ( etr_name == "stats" ) :
  i1II11Iii1I = "lisp-etr"
  oO00OoOOOo = ( "ETR '{}' decapsulation <a href='/lisp/show/" + "database'>stats</a>" ) . format ( stats_name )
  if 77 - 77: iIii1I11I1II1 . Ii1I % oO0o / Ii1I
  O0ooo0O0oo0 += "%" + stats_name
 elif ( rtr_name == "stats" ) :
  i1II11Iii1I = "lisp-rtr"
  oO00OoOOOo = ( "RTR '{}' decapsulation <a href='/lisp/show/" + "rtr/map-cache'>stats</a>" ) . format ( stats_name )
  if 54 - 54: oO0o + ooOoO0o - Oo0Ooo
  O0ooo0O0oo0 += "%" + stats_name
 else :
  iIiIIIi = lisp . lisp_print_sans ( "Invalid command" )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 35 - 35: Ii1I - Ii1I + i1IIi - O0 - I1Ii111
  if 58 - 58: OoOoOO00 - iII111i - OoooooooOO
  if 96 - 96: iIii1I11I1II1
  if 82 - 82: OoOoOO00 + O0 - IiII % oO0o * i11iIiiIii
  if 15 - 15: o0oOOo0O0Ooo
 O0ooo0O0oo0 = lisp . lisp_command_ipc ( O0ooo0O0oo0 , "lisp-core" )
 lisp . lisp_ipc ( O0ooo0O0oo0 , i1IIi11111i , i1II11Iii1I )
 if 39 - 39: OOooOOo / I1ii11iIi11i / I1IiiI * I1Ii111
 if 44 - 44: O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / O0 - I11i
 if 83 - 83: IiII * I11i / Oo0Ooo
 if 32 - 32: o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
 Ii11iii1II1i = getoutput ( "egrep 'lisp map-cache' ./lisp.config" )
 if ( Ii11iii1II1i != "" ) :
  os . system ( "touch ./lisp.config" )
  if 65 - 65: Ii1I + OoO0O00 - OoooooooOO
  if 51 - 51: Oo0Ooo + oO0o / iII111i - i1IIi
 iIiIIIi = lisp . lisp_print_sans ( "{} cleared" . format ( oO00OoOOOo ) )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 51 - 51: Oo0Ooo - I1ii11iIi11i * I11i
 if 12 - 12: iIii1I11I1II1 % ooOoO0o % ooOoO0o
 if 78 - 78: IiII . OoOoOO00 . I11i
 if 97 - 97: oO0o
 if 80 - 80: I1IiiI . Ii1I
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
@ bottle . route ( '/lisp/show/map-server' )
def i1iii1ii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
  if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i ,
 "show map-server" ) )
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
@ bottle . route ( '/lisp/show/database' )
def OO0o0oO0O000o ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 47 - 47: I1Ii111 - OoO0O00 / Ii1I * OoooooooOO / Ii1I . Oo0Ooo
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i ,
 "show database-mapping" ) )
 if 34 - 34: ooOoO0o
 if 27 - 27: I1Ii111 + OoooooooOO - OoOoOO00
 if 15 - 15: oO0o / I11i * O0 . II111iiii - OoO0O00
 if 90 - 90: oO0o
 if 94 - 94: I11i / I1ii11iIi11i * I1Ii111 - OoOoOO00
 if 44 - 44: Ii1I % i11iIiiIii - iII111i * I1ii11iIi11i + Oo0Ooo * OOooOOo
 if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
@ bottle . route ( '/lisp/show/itr/map-cache' )
def oO ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i ,
 "show itr-map-cache" ) )
 if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
 if 45 - 45: O0 . i11iIiiIii % iII111i . OoOoOO00 % IiII % iIii1I11I1II1
 if 58 - 58: iIii1I11I1II1 . OoOoOO00 - i11iIiiIii * iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if 80 - 80: I1ii11iIi11i / iIii1I11I1II1 % OoOoOO00
 if 80 - 80: OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
@ bottle . route ( '/lisp/show/itr/rloc-probing' )
def O0oo0O0 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 2 - 2: OoooooooOO . OOooOOo . IiII
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i ,
 "show itr-rloc-probing" ) )
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
@ bottle . post ( '/lisp/show/itr/map-cache/lookup' )
def oOo00Ooo0o0 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 33 - 33: I11i
  if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 oo0O0o = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oo0O0o ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( oo0O0o )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 13 - 13: iIii1I11I1II1 . OoOoOO00 * I1IiiI / oO0o * Ii1I
  if 64 - 64: ooOoO0o / O0 * OoOoOO00 * ooOoO0o
 OoOOo0OOoO = "show itr-map-cache" + "%" + oo0O0o
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i ,
 OoOOo0OOoO ) )
 if 60 - 60: I11i / i1IIi % I1ii11iIi11i / I1ii11iIi11i * I1ii11iIi11i . i11iIiiIii
 if 99 - 99: OoOoOO00
 if 77 - 77: o0oOOo0O0Ooo
 if 48 - 48: OoOoOO00 % I1ii11iIi11i / I11i . iIii1I11I1II1 * II111iiii
 if 65 - 65: OoOoOO00
 if 31 - 31: I11i * OoOoOO00 . IiII % Ii1I + Oo0Ooo
 if 47 - 47: O0 * I1IiiI * OoO0O00 . II111iiii
@ bottle . route ( '/lisp/show/rtr/map-cache' )
@ bottle . route ( '/lisp/show/rtr/map-cache/<dns>' )
def O0o00o000oO ( dns = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 62 - 62: I1ii11iIi11i / I11i . i1IIi
  if 99 - 99: OoOoOO00 . I1Ii111
 if ( dns == "dns" ) :
  return ( lispconfig . lisp_process_show_command ( i1IIi11111i ,
 "show rtr-map-cache-dns" ) )
 else :
  return ( lispconfig . lisp_process_show_command ( i1IIi11111i ,
 "show rtr-map-cache" ) )
  if 59 - 59: I11i / Oo0Ooo / OOooOOo / O0 / OoOoOO00 + o0oOOo0O0Ooo
  if 13 - 13: o0oOOo0O0Ooo % oO0o / I1Ii111 % I1Ii111 % O0
  if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
  if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
  if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
  if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
  if 79 - 79: OoOoOO00 / ooOoO0o
  if 77 - 77: Oo0Ooo
@ bottle . route ( '/lisp/show/rtr/rloc-probing' )
def i1i111Iiiiiii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 19 - 19: I1IiiI . Oo0Ooo + OoooooooOO - I1IiiI
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i ,
 "show rtr-rloc-probing" ) )
 if 93 - 93: iIii1I11I1II1 + I1IiiI + i11iIiiIii
 if 74 - 74: I11i / II111iiii + ooOoO0o * iIii1I11I1II1 - I1Ii111 - OoO0O00
 if 69 - 69: iIii1I11I1II1 * I1IiiI - iII111i + O0 + O0
 if 65 - 65: I1Ii111 / i11iIiiIii / OoO0O00 - OOooOOo
 if 9 - 9: I1IiiI / I1Ii111 - Oo0Ooo * iIii1I11I1II1
 if 86 - 86: II111iiii + ooOoO0o + IiII
 if 9 - 9: ooOoO0o + II111iiii % ooOoO0o % IiII + iIii1I11I1II1
@ bottle . post ( '/lisp/show/rtr/map-cache/lookup' )
def oO00 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 7 - 7: O0 % I1Ii111 + I1ii11iIi11i + Ii1I % OoooooooOO . Oo0Ooo
  if 56 - 56: iII111i
 oo0O0o = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oo0O0o ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( oo0O0o )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 84 - 84: OoOoOO00 - i11iIiiIii
  if 1 - 1: iII111i * OoOoOO00
 OoOOo0OOoO = "show rtr-map-cache" + "%" + oo0O0o
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i ,
 OoOOo0OOoO ) )
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
  return ( OOoO0 ( ) )
  if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i ,
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
  return ( OOoO0 ( ) )
  if 99 - 99: iIii1I11I1II1
  if 14 - 14: I1ii11iIi11i % I1IiiI . II111iiii . I1IiiI - ooOoO0o
 oo0O0o = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oo0O0o ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( oo0O0o )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
  if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 OoOOo0OOoO = "show referral-cache" + "%" + oo0O0o
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i , OoOOo0OOoO ) )
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
  return ( OOoO0 ( ) )
  if 87 - 87: OoOoOO00 % iIii1I11I1II1
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i ,
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
  return ( OOoO0 ( ) )
  if 19 - 19: I11i
  if 87 - 87: ooOoO0o / OoOoOO00 % o0oOOo0O0Ooo * oO0o
 oo0O0o = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oo0O0o ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( oo0O0o )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 77 - 77: oO0o - Oo0Ooo - iIii1I11I1II1
  if 16 - 16: OoO0O00 / iII111i / i1IIi . iII111i + oO0o
 OoOOo0OOoO = "show delegations" + "%" + oo0O0o
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i , OoOOo0OOoO ) )
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
  return ( OOoO0 ( ) )
  if 24 - 24: I1Ii111 * oO0o
  if 88 - 88: i11iIiiIii + iII111i * OoOoOO00 * iII111i + I11i
 OoOOo0OOoO = "show site"
 if 88 - 88: OOooOOo % Oo0Ooo - iII111i - OoOoOO00 % i11iIiiIii
 if ( eid_prefix != "" ) :
  OoOOo0OOoO = lispconfig . lisp_parse_eid_in_url ( OoOOo0OOoO , eid_prefix )
  if 6 - 6: Ii1I - OoO0O00 . I1IiiI - O0
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i , OoOOo0OOoO ) )
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
  return ( OOoO0 ( ) )
  if 71 - 71: O0 / I1IiiI . I1Ii111 / I1Ii111 * ooOoO0o
  if 60 - 60: II111iiii . I1IiiI - Oo0Ooo + I1ii11iIi11i * I1ii11iIi11i
 OoOOo0OOoO = "show itr-dynamic-eid"
 if 27 - 27: IiII * I1IiiI . iIii1I11I1II1 - iIii1I11I1II1
 if ( eid_prefix != "" ) :
  OoOOo0OOoO = lispconfig . lisp_parse_eid_in_url ( OoOOo0OOoO , eid_prefix )
  if 5 - 5: IiII
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i , OoOOo0OOoO ) )
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
  return ( OOoO0 ( ) )
  if 60 - 60: ooOoO0o
  if 66 - 66: I11i / ooOoO0o % i1IIi - oO0o . O0 / O0
 OoOOo0OOoO = "show etr-dynamic-eid"
 if 96 - 96: OoooooooOO + IiII * O0
 if ( eid_prefix != "" ) :
  OoOOo0OOoO = lispconfig . lisp_parse_eid_in_url ( OoOOo0OOoO , eid_prefix )
  if 86 - 86: Ii1I
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i , OoOOo0OOoO ) )
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
  return ( OOoO0 ( ) )
  if 19 - 19: IiII - o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00 / OOooOOo
  if 87 - 87: OoOoOO00 - ooOoO0o - OOooOOo + Oo0Ooo % iIii1I11I1II1 / i11iIiiIii
 oo0O0o = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oo0O0o ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( oo0O0o )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 12 - 12: ooOoO0o
  if 86 - 86: oO0o - OoO0O00
 OoOOo0OOoO = "show site" + "%" + oo0O0o + "@lookup"
 return ( lispconfig . lisp_process_show_command ( i1IIi11111i , OoOOo0OOoO ) )
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
  return ( OOoO0 ( ) )
  if 36 - 36: iII111i
  if 90 - 90: O0
 Iii = bottle . request . forms . get ( "eid" )
 i1iI111II1ii = bottle . request . forms . get ( "mr" )
 O0ooO00ooOO0o = bottle . request . forms . get ( "count" )
 o0OI1II = "no-info" if bottle . request . forms . get ( "no-nat" ) == "yes" else ""
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if ( i1iI111II1ii == "" ) : i1iI111II1ii = "localhost"
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 if ( Iii == "" ) :
  iIiIIIi = "Need to supply EID address"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
  if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 i111IiiI1Ii = ""
 if os . path . exists ( "lisp-lig.pyo" ) : i111IiiI1Ii = "-O lisp-lig.pyo"
 if os . path . exists ( "lisp-lig.py" ) : i111IiiI1Ii = "lisp-lig.py"
 if 72 - 72: O0 . OoOoOO00 * Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if ( i111IiiI1Ii == "" ) :
  iIiIIIi = "Cannot find lisp-lig.py or lisp-lig.pyo"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 41 - 41: I1ii11iIi11i
  if 5 - 5: Oo0Ooo
 if ( O0ooO00ooOO0o != "" ) : O0ooO00ooOO0o = "count {}" . format ( O0ooO00ooOO0o )
 if 100 - 100: Ii1I + iIii1I11I1II1
 OoOOo0OOoO = 'python {} "{}" to {} {} {}' . format ( i111IiiI1Ii , Iii , i1iI111II1ii , O0ooO00ooOO0o , o0OI1II )
 if 59 - 59: IiII
 iIiIIIi = getoutput ( OoOOo0OOoO )
 iIiIIIi = iIiIIIi . replace ( "\n" , "<br>" )
 iIiIIIi = lisp . convert_font ( iIiIIIi )
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 III11I1 = lisp . space ( 2 ) + "RLOC:"
 iIiIIIi = iIiIIIi . replace ( "RLOC:" , III11I1 )
 OOOO0o0O = lisp . space ( 2 ) + "Empty,"
 iIiIIIi = iIiIIIi . replace ( "Empty," , OOOO0o0O )
 i11ii1iI = lisp . space ( 4 ) + "geo:"
 iIiIIIi = iIiIIIi . replace ( "geo:" , i11ii1iI )
 iI111I = lisp . space ( 4 ) + "elp:"
 iIiIIIi = iIiIIIi . replace ( "elp:" , iI111I )
 O00OoOoO = lisp . space ( 4 ) + "rle:"
 iIiIIIi = iIiIIIi . replace ( "rle:" , O00OoOoO )
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
 if 58 - 58: I1ii11iIi11i
 if 19 - 19: iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
@ bottle . post ( '/lisp/rig' )
def Ii1oOooOOOOo0o ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
  if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 Iii = bottle . request . forms . get ( "eid" )
 o0OOOOOo0 = bottle . request . forms . get ( "ddt" )
 oooOoO = "follow-all-referrals" if bottle . request . forms . get ( "follow" ) == "yes" else ""
 if 62 - 62: OOooOOo / II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if ( o0OOOOOo0 == "" ) : o0OOOOOo0 = "localhost"
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if ( Iii == "" ) :
  iIiIIIi = "Need to supply EID address"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
  if 45 - 45: OoooooooOO
 I1 = ""
 if os . path . exists ( "lisp-rig.pyo" ) : I1 = "-O lisp-rig.pyo"
 if os . path . exists ( "lisp-rig.py" ) : I1 = "lisp-rig.py"
 if 98 - 98: i1IIi . I1IiiI . oO0o
 if 10 - 10: I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if ( I1 == "" ) :
  iIiIIIi = "Cannot find lisp-rig.py or lisp-rig.pyo"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
  if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 OoOOo0OOoO = 'python {} "{}" to {} {}' . format ( I1 , Iii , o0OOOOOo0 , oooOoO )
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 iIiIIIi = getoutput ( OoOOo0OOoO )
 iIiIIIi = iIiIIIi . replace ( "\n" , "<br>" )
 iIiIIIi = lisp . convert_font ( iIiIIIi )
 if 79 - 79: oO0o - II111iiii
 Ii1iiI1 = lisp . space ( 2 ) + "Referrals:"
 iIiIIIi = iIiIIIi . replace ( "Referrals:" , Ii1iiI1 )
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
 if 76 - 76: Ii1I * iIii1I11I1II1
 if 31 - 31: i11iIiiIii + OOooOOo - O0
 if 51 - 51: OoO0O00 * i1IIi / Ii1I * OOooOOo + ooOoO0o % I1ii11iIi11i
 if 34 - 34: oO0o * OoooooooOO + Ii1I + i11iIiiIii
 if 22 - 22: i1IIi
 if 24 - 24: I11i / I1IiiI * i1IIi % OoooooooOO
 if 99 - 99: i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
def Ii1I1i1ii1I1 ( eid1 , eid2 ) :
 i111IiiI1Ii = None
 if os . path . exists ( "lisp-lig.pyo" ) : i111IiiI1Ii = "-O lisp-lig.pyo"
 if os . path . exists ( "lisp-lig.py" ) : i111IiiI1Ii = "lisp-lig.py"
 if ( i111IiiI1Ii == None ) : return ( [ None , None ] )
 if 98 - 98: IiII * iIii1I11I1II1 . Ii1I * Oo0Ooo / I1ii11iIi11i + ooOoO0o
 if 25 - 25: oO0o
 if 19 - 19: I1IiiI % Ii1I . IiII * ooOoO0o
 if 89 - 89: OoOoOO00 . OOooOOo
 IIIIIiI11Ii = getoutput ( "egrep -A 2 'lisp map-resolver {' ./lisp.config" )
 i1iI111II1ii = None
 for OOoOIiIIII in [ "address = " , "dns-name = " ] :
  i1iI111II1ii = None
  Iiii1Ii1I = IIIIIiI11Ii . find ( OOoOIiIIII )
  if ( Iiii1Ii1I == - 1 ) : continue
  i1iI111II1ii = IIIIIiI11Ii [ Iiii1Ii1I + len ( OOoOIiIIII ) : : ]
  Iiii1Ii1I = i1iI111II1ii . find ( "\n" )
  if ( Iiii1Ii1I == - 1 ) : continue
  i1iI111II1ii = i1iI111II1ii [ 0 : Iiii1Ii1I ]
  break
  if 94 - 94: iIii1I11I1II1 - OoO0O00 . Oo0Ooo
 if ( i1iI111II1ii == None ) : return ( [ None , None ] )
 if 59 - 59: OoO0O00 - OoO0O00 + iII111i
 if 32 - 32: i1IIi / Oo0Ooo - O0
 if 85 - 85: Ii1I - O0 * i11iIiiIii . i1IIi
 if 20 - 20: iII111i / OOooOOo
 I1111ii11IIII = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 IiIi1II111I = [ ]
 for Iii in [ eid1 , eid2 ] :
  if 80 - 80: Ii1I / OOooOOo
  if 21 - 21: Oo0Ooo - iIii1I11I1II1 - I1Ii111
  if 1 - 1: I1IiiI * OOooOOo + Ii1I + I1IiiI - i11iIiiIii
  if 79 - 79: ooOoO0o . oO0o / oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
  if 19 - 19: I1ii11iIi11i
  if ( I1111ii11IIII . is_geo_string ( Iii ) ) :
   IiIi1II111I . append ( Iii )
   continue
   if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
   if 66 - 66: O0
  OoOOo0OOoO = 'python {} "{}" to {} count 1' . format ( i111IiiI1Ii , Iii , i1iI111II1ii )
  for I1i in [ OoOOo0OOoO , OoOOo0OOoO + " no-info" ] :
   iIiIIIi = getoutput ( OoOOo0OOoO )
   Iiii1Ii1I = iIiIIIi . find ( "geo: " )
   if ( Iiii1Ii1I == - 1 ) :
    if ( I1i != OoOOo0OOoO ) : IiIi1II111I . append ( None )
    continue
    if 52 - 52: OoO0O00 * OoooooooOO
   iIiIIIi = iIiIIIi [ Iiii1Ii1I + len ( "geo: " ) : : ]
   Iiii1Ii1I = iIiIIIi . find ( "\n" )
   if ( Iiii1Ii1I == - 1 ) :
    if ( I1i != OoOOo0OOoO ) : IiIi1II111I . append ( None )
    continue
    if 12 - 12: O0 + IiII * i1IIi . OoO0O00
   IiIi1II111I . append ( iIiIIIi [ 0 : Iiii1Ii1I ] )
   break
   if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
   if 28 - 28: iIii1I11I1II1
 return ( IiIi1II111I )
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
  return ( OOoO0 ( ) )
  if 18 - 18: iIii1I11I1II1
  if 30 - 30: O0 + OOooOOo % Oo0Ooo . i1IIi
 Iii = bottle . request . forms . get ( "geo-point" )
 I111 = bottle . request . forms . get ( "geo-prefix" )
 iIiIIIi = ""
 if 65 - 65: Oo0Ooo * O0 / Ii1I . I1Ii111 % Oo0Ooo
 if 24 - 24: OoO0O00
 if 99 - 99: OOooOOo / IiII / Ii1I
 if 84 - 84: OoO0O00 / iIii1I11I1II1
 if 33 - 33: i1IIi / I1Ii111 - i1IIi . Oo0Ooo
 iIIi1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 ooIiI11i1I11111 = lisp . lisp_geo ( "" )
 Ii1IIIIIIiI1 = lisp . lisp_geo ( "" )
 Ii11IiIiiii1 , OooO0O0Ooo = Ii1I1i1ii1I1 ( Iii , I111 )
 if 85 - 85: o0oOOo0O0Ooo / I1Ii111
 if 67 - 67: I11i % oO0o
 if 39 - 39: i11iIiiIii + IiII
 if 7 - 7: iIii1I11I1II1 - i1IIi
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 if ( iIIi1 . is_geo_string ( Iii ) ) :
  if ( ooIiI11i1I11111 . parse_geo_string ( Iii ) == False ) :
   iIiIIIi = "Could not parse geo-point format"
   if 25 - 25: II111iiii / OoO0O00
 elif ( Ii11IiIiiii1 == None ) :
  iIiIIIi = "EID {} lookup could not find geo-point" . format (
 lisp . bold ( Iii , True ) )
 elif ( ooIiI11i1I11111 . parse_geo_string ( Ii11IiIiiii1 ) == False ) :
  iIiIIIi = "Could not parse geo-point format returned from lookup"
  if 64 - 64: O0 % ooOoO0o
  if 40 - 40: o0oOOo0O0Ooo + I11i
  if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
  if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
  if 47 - 47: OoooooooOO
  if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
 if ( iIiIIIi == "" ) :
  if ( iIIi1 . is_geo_string ( I111 ) ) :
   if ( Ii1IIIIIIiI1 . parse_geo_string ( I111 ) == False ) :
    iIiIIIi = "Could not parse geo-prefix format"
    if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
  elif ( OooO0O0Ooo == None ) :
   iIiIIIi = "EID-prefix {} lookup could not find geo-prefix" . format ( lisp . bold ( I111 , True ) )
   if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
  elif ( Ii1IIIIIIiI1 . parse_geo_string ( OooO0O0Ooo ) == False ) :
   iIiIIIi = "Could not parse geo-prefix format returned from lookup"
   if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
   if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
   if 26 - 26: OOooOOo * Oo0Ooo
   if 31 - 31: I11i * oO0o . Ii1I
   if 35 - 35: I11i
   if 94 - 94: ooOoO0o / i11iIiiIii % O0
   if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if ( iIiIIIi == "" ) :
  Iii = "" if ( Iii == Ii11IiIiiii1 ) else ", EID {}" . format ( Iii )
  I111 = "" if ( I111 == OooO0O0Ooo ) else ", EID-prefix {}" . format ( I111 )
  if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
  if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
  o0 = ooIiI11i1I11111 . print_geo_url ( )
  IiIiI111IIII1 = Ii1IIIIIIiI1 . print_geo_url ( )
  OOOoOooO000oO = Ii1IIIIIIiI1 . radius
  o0OOOOOo00 = ooIiI11i1I11111 . dms_to_decimal ( )
  o0OOOOOo00 = ( round ( o0OOOOOo00 [ 0 ] , 6 ) , round ( o0OOOOOo00 [ 1 ] , 6 ) )
  oo0oOO = Ii1IIIIIIiI1 . dms_to_decimal ( )
  oo0oOO = ( round ( oo0oOO [ 0 ] , 6 ) , round ( oo0oOO [ 1 ] , 6 ) )
  IIO000oooOO0Oo0 = round ( Ii1IIIIIIiI1 . get_distance ( ooIiI11i1I11111 ) , 2 )
  I1iIiIii = "inside" if Ii1IIIIIIiI1 . point_in_circle ( ooIiI11i1I11111 ) else "outside"
  if 76 - 76: OoO0O00 . OoooooooOO % I1Ii111 * Ii1I
  if 23 - 23: IiII + iIii1I11I1II1
  Ii1111III1 = lisp . space ( 2 )
  oO00oooo0 = lisp . space ( 1 )
  OO0 = lisp . space ( 3 )
  if 96 - 96: O0 . iII111i - I1IiiI * Oo0Ooo
  iIiIIIi = ( "Geo-Point:{}{} {}{}<br>Geo-Prefix:{}{} {}, {} " + "kilometer radius{}<br>" ) . format ( Ii1111III1 , o0 , o0OOOOOo00 , Iii ,
  # o0oOOo0O0Ooo % i1IIi - o0oOOo0O0Ooo + iIii1I11I1II1 + I1Ii111
 oO00oooo0 , IiIiI111IIII1 , oo0oOO , OOOoOooO000oO , I111 )
  iIiIIIi += "Distance:{}{} kilometers, point is {} of circle" . format ( OO0 ,
 IIO000oooOO0Oo0 , lisp . bold ( I1iIiIii , True ) )
  if 84 - 84: oO0o + OOooOOo . iII111i
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
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
 I1i1I = lisp . lisp_control_header ( )
 if ( I1i1I . decode ( packet ) == None ) :
  lisp . lprint ( "Could not decode control header" )
  return ( True )
  if 30 - 30: I11i / I1ii11iIi11i
 if ( I1i1I . type != lisp . LISP_MAP_REQUEST ) :
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
 iIi = lisp . lisp_myrlocs [ 0 ]
 iiI1iIII1ii . itr_rloc_count = 0
 iiI1iIII1ii . itr_rlocs = [ ]
 iiI1iIII1ii . itr_rlocs . append ( iIi )
 if 97 - 97: I11i . I11i + OoOoOO00 / OoO0O00 - I1IiiI . OoooooooOO
 packet = iiI1iIII1ii . encode ( None , 0 )
 iiI1iIII1ii . print_map_request ( )
 if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
 iIio0oooo0OOo00 = iiI1iIII1ii . target_eid
 if ( iIio0oooo0OOo00 . is_ipv6 ( ) ) :
  OOO0 = lisp . lisp_myrlocs [ 1 ]
  if ( OOO0 != None ) : iIi = OOO0
  if 16 - 16: iII111i / iIii1I11I1II1 + OOooOOo * iII111i * I11i
  if 8 - 8: I1Ii111
  if 15 - 15: Oo0Ooo / Ii1I % O0 + I1ii11iIi11i
  if 96 - 96: ooOoO0o . OoooooooOO
  if 39 - 39: OOooOOo + OoO0O00
 oOoOOOO0OOO = lisp . lisp_is_running ( "lisp-ms" )
 lisp . lisp_send_ecm ( lisp_sockets , packet , iIio0oooo0OOo00 , lisp . LISP_CTRL_PORT ,
 iIio0oooo0OOo00 , iIi , to_ms = oOoOOOO0OOO , ddt = False )
 return ( True )
 if 58 - 58: I11i % i11iIiiIii / i11iIiiIii * ooOoO0o - I1Ii111
 if 6 - 6: IiII * II111iiii % iIii1I11I1II1
 if 86 - 86: i1IIi * O0 % ooOoO0o . Oo0Ooo % ooOoO0o . Oo0Ooo
 if 71 - 71: iII111i . i11iIiiIii * O0 + O0
 if 57 - 57: OoooooooOO . I11i % II111iiii % I1IiiI + Ii1I
 if 70 - 70: IiII . i11iIiiIii
 if 76 - 76: iII111i . IiII % iII111i - I1Ii111
 if 51 - 51: OoooooooOO + o0oOOo0O0Ooo * iIii1I11I1II1 * oO0o / i1IIi
 if 19 - 19: iII111i - OoOoOO00 % oO0o / OoooooooOO % iII111i
def ooO ( lisp_sockets , info_source , packet , mr_or_mn ) :
 o0O00OooooO = info_source . address . print_address_no_iid ( )
 oo00O00oO = info_source . port
 i1iiIIiII1 = info_source . nonce
 if 85 - 85: II111iiii
 mr_or_mn = "Reply" if mr_or_mn else "Notify"
 mr_or_mn = lisp . bold ( "nat-proxy Map-{}" . format ( mr_or_mn ) , False )
 if 55 - 55: I1ii11iIi11i
 lisp . lprint ( "Forward {} to info-source {}, port {}, nonce 0x{}" . format ( mr_or_mn , lisp . red ( o0O00OooooO , False ) , oo00O00oO ,
 # I1ii11iIi11i / i11iIiiIii - ooOoO0o / I1ii11iIi11i - Ii1I
 lisp . lisp_hex_string ( i1iiIIiII1 ) ) )
 if 5 - 5: i11iIiiIii * Oo0Ooo
 if 29 - 29: Ii1I / ooOoO0o % I11i
 if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 O0o0O0O0O = lisp . lisp_convert_4to6 ( o0O00OooooO )
 lisp . lisp_send ( lisp_sockets , O0o0O0O0O , oo00O00oO , packet )
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
 if 79 - 79: O0
 if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
 if 15 - 15: I1ii11iIi11i
 if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
def OO0o0o0oo ( lisp_sockets , source , sport , packet ) :
 global i1IIi11111i
 if 40 - 40: Oo0Ooo
 I1i1I = lisp . lisp_control_header ( )
 if ( I1i1I . decode ( packet ) == None ) :
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
 if ( I1i1I . type == lisp . LISP_NAT_INFO ) :
  if ( I1i1I . info_reply == False ) :
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
 if ( I1i1I . type in ( lisp . LISP_MAP_REGISTER , lisp . LISP_MAP_NOTIFY_ACK ) ) :
  lisp . lisp_ipc ( packet , i1IIi11111i , "lisp-ms" )
  return
  if 93 - 93: iII111i * oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if 59 - 59: II111iiii
  if 43 - 43: Oo0Ooo + OoooooooOO
  if 47 - 47: ooOoO0o
  if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
 if ( I1i1I . type == lisp . LISP_MAP_REPLY ) :
  ii11Ii1IiiI1 = lisp . lisp_map_reply ( )
  ii11Ii1IiiI1 . decode ( IIo0oo0OO )
  if 83 - 83: ooOoO0o + i1IIi * OoooooooOO * oO0o
  Ii11iIII = O0OoOOooO0O ( None , 0 , ii11Ii1IiiI1 . nonce )
  if ( Ii11iIII ) :
   ooO ( lisp_sockets , Ii11iIII , IIo0oo0OO , True )
  else :
   i111IiiI1Ii = "/tmp/lisp-lig"
   if ( os . path . exists ( i111IiiI1Ii ) ) :
    lisp . lisp_ipc ( packet , i1IIi11111i , i111IiiI1Ii )
   else :
    lisp . lisp_ipc ( packet , i1IIi11111i , "lisp-itr" )
    if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
    if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  return
  if 21 - 21: OoO0O00
  if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
  if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
  if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
  if 11 - 11: O0 * OoOoOO00
 if ( I1i1I . type == lisp . LISP_MAP_NOTIFY ) :
  IIii1i = lisp . lisp_map_notify ( lisp_sockets )
  IIii1i . decode ( IIo0oo0OO )
  if 69 - 69: I1Ii111 / OoooooooOO % i11iIiiIii
  Ii11iIII = O0OoOOooO0O ( None , 0 , IIii1i . nonce )
  if ( Ii11iIII ) :
   ooO ( lisp_sockets , Ii11iIII , IIo0oo0OO ,
 False )
  else :
   i111IiiI1Ii = "/tmp/lisp-lig"
   if ( os . path . exists ( i111IiiI1Ii ) ) :
    lisp . lisp_ipc ( packet , i1IIi11111i , i111IiiI1Ii )
   else :
    i1II11Iii1I = "lisp-rtr" if lisp . lisp_is_running ( "lisp-rtr" ) else "lisp-etr"
    if 18 - 18: i11iIiiIii - ooOoO0o * oO0o + o0oOOo0O0Ooo
    lisp . lisp_ipc ( packet , i1IIi11111i , i1II11Iii1I )
    if 16 - 16: OoooooooOO * i11iIiiIii . OoooooooOO - iIii1I11I1II1 * i1IIi
    if 33 - 33: I1Ii111 % II111iiii
  return
  if 49 - 49: I1ii11iIi11i + I11i / o0oOOo0O0Ooo + OoooooooOO + OOooOOo / IiII
  if 29 - 29: Ii1I - Ii1I / ooOoO0o
  if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
  if 18 - 18: Oo0Ooo % O0
  if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if ( I1i1I . type == lisp . LISP_MAP_REFERRAL ) :
  I1 = "/tmp/lisp-rig"
  if ( os . path . exists ( I1 ) ) :
   lisp . lisp_ipc ( packet , i1IIi11111i , I1 )
  else :
   lisp . lisp_ipc ( packet , i1IIi11111i , "lisp-mr" )
   if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
  return
  if 86 - 86: IiII
  if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
  if 33 - 33: II111iiii - IiII - ooOoO0o
  if 92 - 92: OoO0O00 * IiII
  if 92 - 92: oO0o
  if 7 - 7: iII111i
 if ( I1i1I . type == lisp . LISP_MAP_REQUEST ) :
  i1II11Iii1I = "lisp-itr" if ( I1i1I . is_smr ( ) ) else "lisp-etr"
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if 62 - 62: i11iIiiIii
  if 2 - 2: I1IiiI
  if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
  if ( I1i1I . rloc_probe ) : return
  if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  lisp . lisp_ipc ( packet , i1IIi11111i , i1II11Iii1I )
  return
  if 14 - 14: IiII . IiII % ooOoO0o
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
  if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
  if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
  if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
  if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 6 - 6: oO0o . I11i
 if ( I1i1I . type == lisp . LISP_ECM ) :
  Ii11iIII = O0OoOOooO0O ( source , sport , None )
  if ( Ii11iIII ) :
   if ( oOO00OO0OooOo ( lisp_sockets , Ii11iIII ,
 IIo0oo0OO ) ) : return
   if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
   if 50 - 50: oO0o % i1IIi * O0
  i1II11Iii1I = "lisp-mr"
  if ( I1i1I . is_to_etr ( ) ) :
   i1II11Iii1I = "lisp-etr"
  elif ( I1i1I . is_to_ms ( ) ) :
   i1II11Iii1I = "lisp-ms"
  elif ( I1i1I . is_ddt ( ) ) :
   if ( lisp . lisp_is_running ( "lisp-ddt" ) ) :
    i1II11Iii1I = "lisp-ddt"
   elif ( lisp . lisp_is_running ( "lisp-ms" ) ) :
    i1II11Iii1I = "lisp-ms"
    if 4 - 4: iIii1I11I1II1 . i1IIi
  elif ( lisp . lisp_is_running ( "lisp-mr" ) == False ) :
   i1II11Iii1I = "lisp-etr"
   if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
  lisp . lisp_ipc ( packet , i1IIi11111i , i1II11Iii1I )
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
  iiI1iiIiiiI1I = wsgi_server ( ( self . host , self . port ) , hand )
  iiI1iiIiiiI1I . ssl_adapter = ssl_adaptor ( i1iI1iiI , i1iI1iiI , None )
  try :
   iiI1iiIiiiI1I . start ( )
  finally :
   iiI1iiIiiiI1I . stop ( )
   if 6 - 6: OoO0O00
   if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
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
def ooOi1i1i11iI11II ( bottle_port ) :
 lisp . lisp_set_exception ( )
 if 6 - 6: OoOoOO00 . II111iiii * I1IiiI . I1IiiI / Ii1I
 if 14 - 14: I1Ii111 % IiII - O0 / I1Ii111
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
  for i1II11Iii1I in iiii1II1ii11 :
   OoO [ i1II11Iii1I ] = lisp . lisp_is_running ( i1II11Iii1I )
   if ( iiii1II1ii11 [ i1II11Iii1I ] == OoO [ i1II11Iii1I ] ) : continue
   if 42 - 42: iIii1I11I1II1 % Ii1I - I1ii11iIi11i + iIii1I11I1II1
   lisp . lprint ( "*** Process '{}' has {} ***" . format ( i1II11Iii1I ,
 "come up" if OoO [ i1II11Iii1I ] else "gone down" ) )
   if 27 - 27: O0 / OoO0O00
   if 99 - 99: Ii1I - IiII * iIii1I11I1II1 . II111iiii
   if 56 - 56: iIii1I11I1II1 % OoO0O00 . ooOoO0o % IiII . I1Ii111 * Oo0Ooo
   if 41 - 41: iIii1I11I1II1 % IiII * oO0o - ooOoO0o
   if ( OoO [ i1II11Iii1I ] == True ) :
    lisp . lisp_ipc_lock . acquire ( )
    lispconfig . lisp_send_commands ( lisp_socket , i1II11Iii1I )
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
  for I1i111IiIiIi1 in lisp . lisp_info_sources_by_address :
   Ii11iIII = lisp . lisp_info_sources_by_address [ I1i111IiIiIi1 ]
   if ( Ii11iIII . no_timeout ) : continue
   if ( Ii11iIII . uptime + I11i1I11 < iiI1 ) : continue
   if 82 - 82: I1ii11iIi11i + OoooooooOO
   iiIIIII . append ( I1i111IiIiIi1 )
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
  for I1i111IiIiIi1 in iiIIIII :
   lisp . lisp_info_sources_by_address . pop ( I1i111IiIiIi1 )
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
  ii11iIi1I = OoOo00 [ 0 ] . split ( "@" )
  oOOo0 = OoOo00 [ 1 ]
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  III1iII1I1ii = ii11iIi1I [ 0 ]
  O0o0O0O0O = ii11iIi1I [ 1 ]
  oo00O00oO = int ( ii11iIi1I [ 2 ] )
  o0000oO = ii11iIi1I [ 3 : : ]
  if 83 - 83: OoO0O00
  if ( len ( o0000oO ) > 1 ) :
   o0000oO = lisp . lisp_bit_stuff ( o0000oO )
  else :
   o0000oO = o0000oO [ 0 ]
   if 16 - 16: ooOoO0o
   if 32 - 32: o0oOOo0O0Ooo % I1IiiI
  if ( III1iII1I1ii != "control-packet" ) :
   lisp . lprint ( ( "lisp_core_control_packet_process() received" + "unexpected control-packet, message ignored" ) )
   if 7 - 7: Oo0Ooo . i1IIi - oO0o
   continue
   if 93 - 93: IiII % I1ii11iIi11i
   if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
  lisp . lprint ( ( "{} {} bytes from {}, dest/port: {}/{}, control-" + "packet: {}" ) . format ( lisp . bold ( "Receive" , False ) , len ( o0000oO ) ,
  # iIii1I11I1II1 / Ii1I
 oOOo0 , O0o0O0O0O , oo00O00oO , lisp . lisp_format_packet ( o0000oO ) ) )
  if 59 - 59: Ii1I / II111iiii - IiII % OoOoOO00 % OoooooooOO
  if 79 - 79: iII111i . OoooooooOO . I1IiiI * O0 * OoO0O00 - OOooOOo
  if 33 - 33: I1ii11iIi11i . Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
  if 54 - 54: ooOoO0o * iII111i * iII111i % OoOoOO00 - OOooOOo % I1ii11iIi11i
  if 44 - 44: Oo0Ooo . OOooOOo + I11i
  if 22 - 22: I1Ii111 * OoooooooOO + i11iIiiIii % OoO0O00
  I1i1I = lisp . lisp_control_header ( )
  I1i1I . decode ( o0000oO )
  if ( I1i1I . type == lisp . LISP_MAP_REPLY ) :
   ii11Ii1IiiI1 = lisp . lisp_map_reply ( )
   ii11Ii1IiiI1 . decode ( o0000oO )
   if ( O0OoOOooO0O ( None , 0 , ii11Ii1IiiI1 . nonce ) ) :
    OO0o0o0oo ( lisp_sockets , oOOo0 , oo00O00oO , o0000oO )
    continue
    if 53 - 53: I1IiiI
    if 10 - 10: I1Ii111 / i11iIiiIii - II111iiii
    if 48 - 48: OOooOOo
    if 26 - 26: iII111i * I1Ii111 * oO0o * OoOoOO00
    if 48 - 48: iII111i % i11iIiiIii . OoooooooOO * IiII % OoO0O00 . iII111i
    if 6 - 6: O0 . ooOoO0o - oO0o / i11iIiiIii
    if 84 - 84: I11i / I1ii11iIi11i * o0oOOo0O0Ooo * OoO0O00 * OOooOOo * O0
    if 83 - 83: O0 % II111iiii + o0oOOo0O0Ooo / OoooooooOO
  if ( I1i1I . type == lisp . LISP_MAP_NOTIFY and oOOo0 == "lisp-etr" ) :
   O0ooo0O0oo0 = lisp . lisp_packet_ipc ( o0000oO , oOOo0 , oo00O00oO )
   lisp . lisp_ipc ( O0ooo0O0oo0 , i1IIi11111i , "lisp-itr" )
   continue
   if 75 - 75: II111iiii . I1IiiI + OOooOOo - OoOoOO00 - O0 . I11i
   if 19 - 19: Ii1I * i1IIi % O0 + I11i
   if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
   if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
   if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
   if 80 - 80: Ii1I
   if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
  I1111ii11IIII = lisp . lisp_convert_4to6 ( O0o0O0O0O )
  I1111ii11IIII = lisp . lisp_address ( lisp . LISP_AFI_IPV6 , "" , 128 , 0 )
  if ( I1111ii11IIII . is_ipv4_string ( O0o0O0O0O ) ) : O0o0O0O0O = "::ffff:" + O0o0O0O0O
  I1111ii11IIII . store_address ( O0o0O0O0O )
  if 59 - 59: I1ii11iIi11i + I11i . oO0o
  if 87 - 87: OoO0O00
  if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
  lisp . lisp_send ( lisp_sockets , I1111ii11IIII , oo00O00oO , o0000oO )
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
 Oo = open ( "./lisp.config.example" , "r" ) ; O0OOOOo0O = Oo . read ( ) ; Oo . close ( )
 Oo = open ( "./lisp.config" , "w" )
 O0OOOOo0O = O0OOOOo0O . split ( "\n" )
 for OOoOOO0O000 in O0OOOOo0O :
  Oo . write ( OOoOOO0O000 + "\n" )
  if ( OOoOOO0O000 [ 0 ] == "#" and OOoOOO0O000 [ - 1 ] == "#" and len ( OOoOOO0O000 ) >= 4 ) :
   oOo00Oo0o00oo = OOoOOO0O000 [ 1 : - 2 ]
   oO0O0oo = len ( oOo00Oo0o00oo ) * "-"
   if ( oOo00Oo0o00oo == oO0O0oo ) : break
   if 64 - 64: OoOoOO00 % OoOoOO00 + o0oOOo0O0Ooo + Oo0Ooo
   if 79 - 79: Oo0Ooo - OoooooooOO % I1Ii111 + OoooooooOO - I11i % OoOoOO00
 Oo . close ( )
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
 global OOoO
 global II1Iiii1111i
 global i1IIi11111i
 global o000o0o00o0Oo
 global oo
 global IiII1I1i1i1ii
 if 68 - 68: i11iIiiIii + OoO0O00
 lisp . lisp_i_am ( "core" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "core-process starting up" )
 lisp . lisp_uptime = lisp . lisp_get_timestamp ( )
 lisp . lisp_version = getoutput ( "cat lisp-version.txt" )
 OOoO = getoutput ( "cat lisp-build-date.txt" )
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
  II1Iiii1111i = lisp . lisp_open_listen_socket ( OoOo0o0OOoO0 ,
 str ( lisp . LISP_CTRL_PORT ) )
 else :
  OoOo0o0OOoO0 = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( )
  II1Iiii1111i = lisp . lisp_open_listen_socket ( OoOo0o0OOoO0 ,
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
  IiII1I1i1i1ii = lisp . lisp_open_listen_socket ( OoOo0o0OOoO0 ,
 str ( lisp . LISP_DATA_PORT ) )
  lisp . lprint ( "Listen on {}, port 4341" . format ( OoOo0o0OOoO0 ) )
  if 3 - 3: I1ii11iIi11i / II111iiii
  if 73 - 73: OoO0O00 * OoooooooOO - OoooooooOO + I1IiiI * Oo0Ooo
  if 87 - 87: o0oOOo0O0Ooo / IiII / i11iIiiIii
  if 95 - 95: i1IIi / Ii1I / Ii1I
  if 65 - 65: I1Ii111 + iII111i * iII111i
  if 79 - 79: i1IIi / Oo0Ooo - I1IiiI . O0
 i1IIi11111i = lisp . lisp_open_send_socket ( "lisp-core" , "" )
 i1IIi11111i . settimeout ( 3 )
 if 56 - 56: IiII % O0 * i1IIi - II111iiii
 if 74 - 74: i1IIi - OoOoOO00 % oO0o . O0 - OoooooooOO
 if 84 - 84: I1Ii111
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
 o000o0o00o0Oo = lisp . lisp_open_listen_socket ( "" , "lisp-core-pkt" )
 if 9 - 9: i1IIi - OoOoOO00
 oo = [ II1Iiii1111i , II1Iiii1111i ,
 i1IIi11111i ]
 if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
 if 46 - 46: Ii1I
 if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
 if 87 - 87: I1ii11iIi11i / I1IiiI
 if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
 threading . Thread ( target = oo0oO0oOo0O ,
 args = [ o000o0o00o0Oo , oo ] ) . start ( )
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
 iIiI1I ( II1Iiii1111i )
 if 2 - 2: o0oOOo0O0Ooo . Ii1I % OoOoOO00
 threading . Thread ( target = lispconfig . lisp_config_process ,
 args = [ i1IIi11111i ] ) . start ( )
 if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
 if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
 if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
 if 58 - 58: iII111i
 threading . Thread ( target = ooOi1i1i11iI11II ,
 args = [ bottle_port ] ) . start ( )
 threading . Thread ( target = O0OOOOoO00oo , args = [ ] ) . start ( )
 if 2 - 2: II111iiii + i1IIi
 if 68 - 68: OOooOOo + Ii1I
 if 58 - 58: IiII * Ii1I . i1IIi
 if 19 - 19: oO0o
 threading . Thread ( target = OOOOo0o0O0o ,
 args = [ i1IIi11111i ] ) . start ( )
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
 lisp . lisp_close_socket ( i1IIi11111i , "lisp-core" )
 lisp . lisp_close_socket ( o000o0o00o0Oo , "lisp-core-pkt" )
 lisp . lisp_close_socket ( II1Iiii1111i , "" )
 lisp . lisp_close_socket ( IiII1I1i1i1ii , "" )
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
 Oo = open ( "./lisp.config" , "r" ) ; O0OOOOo0O = Oo . read ( ) ; Oo . close ( )
 O0OOOOo0O = O0OOOOo0O . split ( "\n" )
 if 36 - 36: IiII . iII111i - i1IIi + I1Ii111
 if 54 - 54: OoooooooOO . oO0o - iII111i
 if 76 - 76: I1Ii111
 if 61 - 61: ooOoO0o / II111iiii * ooOoO0o * OoOoOO00 * I1Ii111 . i11iIiiIii
 if 26 - 26: I1Ii111 / ooOoO0o - OoO0O00 . iIii1I11I1II1
 O0o0OOo0o0o = False
 for OOoOOO0O000 in O0OOOOo0O :
  if ( OOoOOO0O000 [ 0 : 1 ] == "#-" and OOoOOO0O000 [ - 2 : - 1 ] == "-#" ) : break
  if ( OOoOOO0O000 == "" or OOoOOO0O000 [ 0 ] == "#" ) : continue
  if ( OOoOOO0O000 . find ( "decentralized-push-xtr = yes" ) == - 1 ) : continue
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
 for OOoOOO0O000 in O0OOOOo0O :
  if ( OOoOOO0O000 [ 0 : 1 ] == "#-" and OOoOOO0O000 [ - 2 : - 1 ] == "-#" ) : break
  if ( OOoOOO0O000 == "" or OOoOOO0O000 [ 0 ] == "#" ) : continue
  if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
  if ( OOoOOO0O000 . find ( "lisp map-server" ) != - 1 ) :
   o0oo0oOOOo00 = True
   continue
   if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
  if ( OOoOOO0O000 [ 0 ] == "}" ) :
   o0oo0oOOOo00 = False
   continue
   if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
   if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
   if 100 - 100: i1IIi % Ii1I
   if 55 - 55: I1IiiI + iII111i
   if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
  if ( o0oo0oOOOo00 and OOoOOO0O000 . find ( "address = " ) != - 1 ) :
   i1I11 = OOoOOO0O000 . split ( "address = " ) [ 1 ]
   OoO00 = int ( i1I11 . split ( "." ) [ 0 ] )
   if ( OoO00 >= 224 and OoO00 < 240 ) : OO0o0oo . append ( i1I11 )
   if 57 - 57: Oo0Ooo - OoooooooOO % I1ii11iIi11i . OoO0O00 * II111iiii
   if 72 - 72: I1Ii111 + ooOoO0o . IiII % II111iiii
 if ( i1I11 == [ ] ) : return
 if 58 - 58: ooOoO0o
 if 45 - 45: o0oOOo0O0Ooo
 if 67 - 67: iII111i + ooOoO0o
 if 25 - 25: i1IIi - i11iIiiIii
 OOooO0o = getoutput ( 'ifconfig eth0 | egrep "inet "' )
 if ( OOooO0o == "" ) : return
 i1IIII1II = OOooO0o . split ( ) [ 1 ]
 if 89 - 89: I11i % iII111i * Oo0Ooo / I1Ii111 * Oo0Ooo / ooOoO0o
 if 14 - 14: i1IIi * iIii1I11I1II1 - Ii1I * OoOoOO00 - iII111i / oO0o
 if 73 - 73: I1ii11iIi11i - OoOoOO00 * O0 - OoOoOO00 - OoO0O00
 if 96 - 96: I1ii11iIi11i - O0
 i1i111iI = socket . inet_aton ( i1IIII1II )
 for i1I11 in OO0o0oo :
  lisp_socket . setsockopt ( socket . SOL_SOCKET , socket . SO_REUSEADDR , 1 )
  lisp_socket . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_IF , i1i111iI )
  I1iO00O000oOO0oO = socket . inet_aton ( i1I11 ) + i1i111iI
  lisp_socket . setsockopt ( socket . IPPROTO_IP , socket . IP_ADD_MEMBERSHIP , I1iO00O000oOO0oO )
  lisp . lprint ( "Setting multicast listen socket for group {}" . format ( i1I11 ) )
  if 88 - 88: o0oOOo0O0Ooo . I1IiiI % oO0o . Oo0Ooo % ooOoO0o . oO0o
  if 53 - 53: i1IIi % Ii1I - OoooooooOO / OoOoOO00 - iIii1I11I1II1
 return
 if 9 - 9: I1Ii111 - OoO0O00 + iIii1I11I1II1 % O0 + I11i + IiII
 if 50 - 50: i1IIi + ooOoO0o
 if 64 - 64: o0oOOo0O0Ooo % oO0o . ooOoO0o
 if 6 - 6: ooOoO0o / i11iIiiIii - Oo0Ooo
I11iIiiI = int ( sys . argv [ 1 ] ) if ( len ( sys . argv ) > 1 ) else 8080
if 88 - 88: I1ii11iIi11i - I11i * OoooooooOO * iII111i . i11iIiiIii . o0oOOo0O0Ooo
if 96 - 96: I1IiiI % I1IiiI / o0oOOo0O0Ooo / OoOoOO00 * ooOoO0o - I1Ii111
if 94 - 94: Oo0Ooo - iIii1I11I1II1 + I1IiiI - i1IIi + OoooooooOO % OoO0O00
if 36 - 36: iII111i * I11i * O0 * OOooOOo - o0oOOo0O0Ooo / I1ii11iIi11i
if ( oOO0O00o0O0 ( I11iIiiI ) == False ) :
 lisp . lprint ( "lisp_core_startup() failed" )
 lisp . lisp_print_banner ( "lisp-core abnormal exit" )
 exit ( 1 )
 if 54 - 54: i1IIi - OoO0O00 / OoooooooOO
 if 95 - 95: O0 + iIii1I11I1II1 . I1ii11iIi11i
while ( True ) :
 if 61 - 61: Ii1I * Ii1I
 if 70 - 70: I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
 if 74 - 74: I1IiiI . ooOoO0o / iII111i . IiII
 if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
 if 72 - 72: i1IIi
 III1iII1I1ii , oOOo0 , oo00O00oO , o0000oO = lisp . lisp_receive ( II1Iiii1111i , False )
 if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
 if ( oOOo0 == "" ) : break
 if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
 if 89 - 89: IiII - i1IIi - IiII
 if 74 - 74: OoO0O00 % OoO0O00
 if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
 oOOo0 = lisp . lisp_convert_6to4 ( oOOo0 )
 OO0o0o0oo ( oo , oOOo0 , oo00O00oO , o0000oO )
 if 91 - 91: I1IiiI / II111iiii * OOooOOo
 if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
I1i11 ( )
lisp . lisp_print_banner ( "lisp-core normal exit" )
exit ( 0 )
if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
if 81 - 81: OoO0O00 - iIii1I11I1II1
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
