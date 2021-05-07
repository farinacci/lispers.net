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
from __future__ import division
from future import standard_library
standard_library . install_aliases ( )
from builtins import str
from past . utils import old_div
import lisp
import lispconfig
import multiprocessing
import threading
from subprocess import getoutput
import time
import os
import bottle
import json
import sys
import socket
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
try :
 from cherrypy . wsgiserver import CherryPyWSGIServer as wsgi_server
 from cherrypy . wsgiserver . ssl_pyopenssl import pyOpenSSLAdapter as ssl_adaptor
except :
 from cheroot . wsgi import Server as wsgi_server
 from cheroot . ssl . builtin import BuiltinSSLAdapter as ssl_adaptor
 if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
 if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
 if 46 - 46: ooOoO0o * I11i - OoooooooOO
 if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
 if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
 if 94 - 94: i1IIi % Oo0Ooo
 if 68 - 68: Ii1I / O0
Iiii111Ii11I1 = ""
if 66 - 66: iII111i
IiiiIiI1iIiI1 = None
ooo0Oo0 = None
oo = None
O0Oooo00 = [ None , None , None ]
Ooo0 = None
if 89 - 89: OoooooooOO - IiII * ooOoO0o
if 82 - 82: I11i . I1Ii111 / IiII % II111iiii % iIii1I11I1II1 % IiII
if 86 - 86: OoOoOO00 % I1IiiI
if 80 - 80: OoooooooOO . I1IiiI
if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
if 58 - 58: i11iIiiIii % I1Ii111
if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
@ bottle . route ( '/lisp/api' , method = "get" )
@ bottle . route ( '/lisp/api/<command>' , method = "get" )
@ bottle . route ( '/lisp/api/<command>/<data_structure>' , method = "get" )
def iIiiI1 ( command = "" , data_structure = "" ) :
 OoOooOOOO = [ { "?" : [ { "?" : "not-auth" } ] } ]
 if 45 - 45: I1Ii111 + Ii1I
 if 17 - 17: o0oOOo0O0Ooo
 if 64 - 64: Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 if ( bottle . request . auth != None ) :
  I1Ii , o0oOo0Ooo0O = bottle . request . auth
  if ( lispconfig . lisp_find_user_account ( I1Ii , o0oOo0Ooo0O ) == False ) :
   return ( json . dumps ( OoOooOOOO ) )
   if 81 - 81: I1ii11iIi11i * IiII * I11i - iII111i - o0oOOo0O0Ooo
 else :
  if ( bottle . request . headers [ "User-Agent" ] . find ( "python" ) != - 1 ) :
   return ( json . dumps ( OoOooOOOO ) )
   if 90 - 90: II111iiii + oO0o / o0oOOo0O0Ooo % II111iiii - O0
  if ( lispconfig . lisp_validate_user ( ) == False ) :
   return ( json . dumps ( OoOooOOOO ) )
   if 29 - 29: o0oOOo0O0Ooo / iIii1I11I1II1
   if 24 - 24: O0 % o0oOOo0O0Ooo + i1IIi + I1Ii111 + I1ii11iIi11i
   if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
   if 23 - 23: i11iIiiIii + I1IiiI
   if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
   if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
   if 33 - 33: Ii1I + II111iiii % i11iIiiIii . ooOoO0o - I1IiiI
 if ( command == "data" and data_structure != "" ) :
  O00oooo0O = bottle . request . body . readline ( )
  OoOooOOOO = json . loads ( O00oooo0O ) if O00oooo0O != "" else ""
  if ( OoOooOOOO != "" ) : OoOooOOOO = list ( OoOooOOOO . values ( ) ) [ 0 ]
  if ( OoOooOOOO == [ ] ) : OoOooOOOO = ""
  if 22 - 22: OoooooooOO % I11i - iII111i . iIii1I11I1II1 * i11iIiiIii
  if ( type ( OoOooOOOO ) == dict and type ( list ( OoOooOOOO . values ( ) ) [ 0 ] ) == dict ) :
   OoOooOOOO = list ( OoOooOOOO . values ( ) ) [ 0 ]
   if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
   if 61 - 61: ooOoO0o
  OoOooOOOO = oOOO00o ( data_structure , OoOooOOOO )
  return ( OoOooOOOO )
  if 97 - 97: I11i % I11i + II111iiii * iII111i
  if 54 - 54: I11i + IiII / iII111i
  if 9 - 9: OoOoOO00 / Oo0Ooo - IiII . i1IIi / I1IiiI % IiII
  if 71 - 71: I1Ii111 . O0
  if 73 - 73: OOooOOo % OoOoOO00 - Ii1I
 if ( command != "" ) :
  command = "lisp " + command
 else :
  O00oooo0O = bottle . request . body . readline ( )
  if ( O00oooo0O == "" ) :
   OoOooOOOO = [ { "?" : [ { "?" : "no-body" } ] } ]
   return ( json . dumps ( OoOooOOOO ) )
   if 10 - 10: I1IiiI % I1ii11iIi11i
   if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
  OoOooOOOO = json . loads ( O00oooo0O )
  command = list ( OoOooOOOO . keys ( ) ) [ 0 ]
  if 20 - 20: o0oOOo0O0Ooo
  if 77 - 77: OoOoOO00 / I11i
 OoOooOOOO = lispconfig . lisp_get_clause_for_api ( command )
 return ( json . dumps ( OoOooOOOO ) )
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
 if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % oO0o . O0
 if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
 if 53 - 53: IiII + I1IiiI * oO0o
 if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
 if 60 - 60: I11i / I11i
def I1II1III11iii ( ) :
 OoOooOOOO = { }
 OoOooOOOO [ "hostname" ] = socket . gethostname ( )
 OoOooOOOO [ "system-uptime" ] = getoutput ( "uptime" )
 OoOooOOOO [ "lisp-uptime" ] = lisp . lisp_print_elapsed ( lisp . lisp_uptime )
 OoOooOOOO [ "lisp-version" ] = lisp . lisp_version
 if 75 - 75: iIii1I11I1II1 / OOooOOo % o0oOOo0O0Ooo * OoOoOO00
 iiii11I = "yes" if os . path . exists ( "./logs/lisp-traceback.log" ) else "no"
 OoOooOOOO [ "traceback-log" ] = iiii11I
 if 96 - 96: II111iiii % Ii1I . OOooOOo + OoooooooOO * oO0o - OoOoOO00
 i11i1 = lisp . lisp_myrlocs [ 0 ]
 IIIii1II1II = lisp . lisp_myrlocs [ 1 ]
 i11i1 = "none" if ( i11i1 == None ) else i11i1 . print_address_no_iid ( )
 IIIii1II1II = "none" if ( IIIii1II1II == None ) else IIIii1II1II . print_address_no_iid ( )
 OoOooOOOO [ "lisp-rlocs" ] = [ i11i1 , IIIii1II1II ]
 return ( json . dumps ( OoOooOOOO ) )
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
def oOOO00o ( data_structure , data ) :
 OOO = [ "site-cache" , "map-cache" , "system" , "map-resolver" ,
 "map-server" , "database-mapping" , "site-cache-summary" ]
 if 59 - 59: II111iiii + OoooooooOO * OoOoOO00 + i1IIi
 if ( data_structure not in OOO ) : return ( json . dumps ( [ ] ) )
 if 58 - 58: II111iiii * OOooOOo * I1ii11iIi11i / OOooOOo
 if 75 - 75: oO0o
 if 50 - 50: Ii1I / Oo0Ooo - oO0o - I11i % iII111i - oO0o
 if 91 - 91: OoO0O00 / I11i - II111iiii . I11i
 if ( data_structure == "system" ) : return ( I1II1III11iii ( ) )
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
   lisp . lisp_ipc ( O0ooo0O0oo0 , ooo0Oo0 , "lisp-rtr" )
  elif ( lisp . lisp_is_running ( "lisp-itr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , ooo0Oo0 , "lisp-itr" )
  else :
   return ( json . dumps ( [ ] ) )
   if 31 - 31: IiII . OoOoOO00 . OOooOOo
   if 75 - 75: I11i + OoO0O00 . OoOoOO00 . ooOoO0o + Oo0Ooo . OoO0O00
 if ( data_structure in [ "map-server" , "database-mapping" ] ) :
  if ( lisp . lisp_is_running ( "lisp-etr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , ooo0Oo0 , "lisp-etr" )
  elif ( lisp . lisp_is_running ( "lisp-itr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , ooo0Oo0 , "lisp-itr" )
  else :
   return ( json . dumps ( [ ] ) )
   if 96 - 96: OOooOOo . ooOoO0o - Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * OOooOOo
   if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
 if ( data_structure in [ "site-cache" , "site-cache-summary" ] ) :
  if ( lisp . lisp_is_running ( "lisp-ms" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , ooo0Oo0 , "lisp-ms" )
  else :
   return ( json . dumps ( [ ] ) )
   if 21 - 21: I1IiiI * iIii1I11I1II1
   if 91 - 91: IiII
   if 15 - 15: II111iiii
 lisp . lprint ( "Waiting for api get-data '{}', parmameters: '{}'" . format ( data_structure , data ) )
 if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
 if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
 III1iII1I1ii , oOOo0 , oo00O00oO , iIiIIIi = lisp . lisp_receive ( ooo0Oo0 , True )
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
 OoOooOOOO = [ { "?" : [ { "?" : "not-auth" } ] } ]
 if ( bottle . request . auth == None ) : return ( OoOooOOOO )
 if 75 - 75: I1IiiI + Oo0Ooo
 if 73 - 73: O0 - OoooooooOO . OOooOOo - OOooOOo / OoOoOO00
 if 45 - 45: iIii1I11I1II1 % OoO0O00
 if 29 - 29: OOooOOo + Oo0Ooo . i11iIiiIii - i1IIi / iIii1I11I1II1
 if ( bottle . request . auth != None ) :
  I1Ii , o0oOo0Ooo0O = bottle . request . auth
  if ( lispconfig . lisp_find_user_account ( I1Ii , o0oOo0Ooo0O ) == False ) :
   return ( json . dumps ( OoOooOOOO ) )
   if 26 - 26: I11i . OoooooooOO
 else :
  if ( bottle . request . headers [ "User-Agent" ] . find ( "python" ) != - 1 ) :
   return ( json . dumps ( OoOooOOOO ) )
   if 39 - 39: iII111i - O0 % i11iIiiIii * I1Ii111 . IiII
  if ( lispconfig . lisp_validate_user ( ) == False ) :
   return ( json . dumps ( OoOooOOOO ) )
   if 58 - 58: OoO0O00 % i11iIiiIii . iII111i / oO0o
   if 84 - 84: iII111i . I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
   if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
   if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
   if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
   if 51 - 51: O0 + iII111i
   if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if ( command == "user-account" ) :
  if ( lispconfig . lisp_is_user_superuser ( I1Ii ) == False ) :
   OoOooOOOO = [ { "user-account" : [ { "?" : "not-auth" } ] } ]
   return ( json . dumps ( OoOooOOOO ) )
   if 48 - 48: O0
   if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
   if 41 - 41: Ii1I - O0 - O0
   if 68 - 68: OOooOOo % I1Ii111
   if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
   if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 O00oooo0O = bottle . request . body . readline ( )
 if ( O00oooo0O == "" ) :
  OoOooOOOO = [ { "?" : [ { "?" : "no-body" } ] } ]
  return ( json . dumps ( OoOooOOOO ) )
  if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
  if 23 - 23: O0
 OoOooOOOO = json . loads ( O00oooo0O )
 if ( command != "" ) :
  command = "lisp " + command
 else :
  command = list ( OoOooOOOO [ 0 ] . keys ( ) ) [ 0 ]
  if 85 - 85: Ii1I
  if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
  if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
  if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
  if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
  if 77 - 77: iIii1I11I1II1 * OoO0O00
 lisp . lisp_ipc_lock . acquire ( )
 if ( bottle . request . method == "DELETE" ) :
  OoOooOOOO = lispconfig . lisp_remove_clause_for_api ( OoOooOOOO )
 else :
  OoOooOOOO = lispconfig . lisp_put_clause_for_api ( OoOooOOOO )
  if 95 - 95: I1IiiI + i11iIiiIii
 lisp . lisp_ipc_lock . release ( )
 return ( json . dumps ( OoOooOOOO ) )
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
 for OOoO in O0OOOOo0O :
  if ( OOoO [ 0 : 4 ] == "    " ) : oooOo0OOOoo0 += lisp . lisp_space ( 4 )
  if ( OOoO [ 0 : 2 ] == "  " ) : oooOo0OOOoo0 += lisp . lisp_space ( 2 )
  oooOo0OOOoo0 += OOoO + "<br>"
  if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 oooOo0OOOoo0 = lisp . convert_font ( oooOo0OOOoo0 )
 return ( lisp . lisp_print_sans ( oooOo0OOOoo0 ) )
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
  return ( OOoO0 ( ) )
  if 11 - 11: I1IiiI
 I1111i = lispconfig . lisp_is_user_superuser ( None )
 if 14 - 14: OOooOOo / o0oOOo0O0Ooo
 if ( I1111i == False ) :
  iIiIIIi = "Permission denied"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 32 - 32: I1IiiI * Oo0Ooo
  if 78 - 78: OOooOOo - OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii
 if ( xtr not in [ "itr" , "etr" , "rtr" ] ) :
  iIiIIIi = "Invalid URL"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 29 - 29: I1IiiI % I1IiiI
 Oo0O0 = "show {}-keys" . format ( xtr )
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 , Oo0O0 ) )
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
  return ( OOoO0 ( ) )
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
   OOoO = o0o0O . split ( ":" )
   if ( OOoO [ 1 ] == "0" ) : continue
   iIiIIIi += "Found Tracebacks in log file {}<br>" . format ( OOoO [ 0 ] )
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
 OoO = "ps auww" if lisp . lisp_is_macos ( ) else "ps aux"
 Iiiiii111i1ii = "egrep 'PID|python lisp|python -O lisp|python3.8 -O lisp'"
 Iiiiii111i1ii += "| egrep -v grep"
 i1i1iII1 = getoutput ( "{} | {}" . format ( OoO , Iiiiii111i1ii ) )
 i1i1iII1 = i1i1iII1 . replace ( " " , lisp . space ( 1 ) )
 i1i1iII1 = i1i1iII1 . replace ( "\n" , "<br>" )
 if 25 - 25: iIii1I11I1II1 % iII111i . ooOoO0o
 if 14 - 14: oO0o + I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
 if ( i1 . find ( "Darwin" ) != - 1 ) :
  IiIi1iIIi1 = old_div ( IiIi1iIIi1 , 2 )
  iiI111 = getoutput ( "top -l 1 | head -50" )
  iiI111 = iiI111 . split ( "PID" )
  iiI111 = iiI111 [ 0 ]
  if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
  if 62 - 62: OoO0O00 / I1ii11iIi11i
  if 7 - 7: OoooooooOO . IiII
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
  if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
  i1i111iI = iiI111 . find ( "Load Avg" )
  O00oOo00o0o = iiI111 [ 0 : i1i111iI ] . find ( "threads" )
  O00oO0 = iiI111 [ 0 : O00oOo00o0o + 7 ]
  iiI111 = O00oO0 + "<br>" + iiI111 [ i1i111iI : : ]
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
  if 70 - 70: I11i . I1ii11iIi11i * OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  if 92 - 92: I11i . I1Ii111
  if 85 - 85: I1ii11iIi11i . I1Ii111
  O0OOOOo0O = getoutput ( "top -b -n 1 | head -50" )
  O0OOOOo0O = O0OOOOo0O . split ( "PID" )
  O0OOOOo0O [ 1 ] = O0OOOOo0O [ 1 ] . replace ( " " , lisp . space ( 1 ) )
  O0OOOOo0O = O0OOOOo0O [ 0 ] + O0OOOOo0O [ 1 ]
  iiI111 = O0OOOOo0O . replace ( "\n" , "<br>" )
  if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
  if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
 ii111I11iI = getoutput ( "cat release-notes.txt" )
 ii111I11iI = ii111I11iI . replace ( "\n" , "<br>" )
 if 93 - 93: I1ii11iIi11i / iIii1I11I1II1 * i1IIi % OoooooooOO * O0 * I11i
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
        ''' . format ( OO0oOOoo , lisp . lisp_version , Iiii111Ii11I1 , IIiiI ,
 O00o0OO0000oo , lisp . lisp_space ( 1 ) , IiIi1iIIi1 , i1 , i1i1iII1 , iiI111 ,
 ii111I11iI )
 if 64 - 64: II111iiii + O0 / iIii1I11I1II1 / Oo0Ooo . ooOoO0o % IiII
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 50 - 50: iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 if 73 - 73: i1IIi / i11iIiiIii
@ bottle . route ( '/lisp/show/conf' )
def OOOIiiiii1iI ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 49 - 49: o0oOOo0O0Ooo . IiII / OoO0O00 + II111iiii
 return ( bottle . static_file ( "lisp.config" , root = "./" , mimetype = "text/plain" ) )
 if 47 - 47: O0 / Ii1I
 if 67 - 67: I1IiiI
 if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
 if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
 if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
@ bottle . route ( '/lisp/show/diff' )
def OOOoO000 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 57 - 57: II111iiii
 return ( bottle . static_file ( "lisp.config.diff" , root = "./" ,
 mimetype = "text/plain" ) )
 if 54 - 54: Oo0Ooo + oO0o + i11iIiiIii
 if 28 - 28: oO0o
 if 70 - 70: IiII
 if 34 - 34: I1Ii111 % IiII
 if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
 if 83 - 83: oO0o + OoooooooOO
 if 22 - 22: Ii1I % iII111i * OoooooooOO - o0oOOo0O0Ooo / iIii1I11I1II1
@ bottle . route ( '/lisp/archive/conf' )
def OoOO00 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 28 - 28: oO0o - i11iIiiIii . I1ii11iIi11i + IiII / I1ii11iIi11i
  if 35 - 35: IiII
 lisp . lisp_ipc_lock . acquire ( )
 os . system ( "cp ./lisp.config ./lisp.config.archive" )
 lisp . lisp_ipc_lock . release ( )
 if 75 - 75: Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 iIiIIIi = "Configuration file saved to "
 iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
 iIiIIIi += lisp . lisp_print_cour ( "./lisp.config.archive" )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
@ bottle . route ( '/lisp/clear/conf' )
def Ii1iI111 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 51 - 51: IiII * O0 / II111iiii . Ii1I % OOooOOo / I1IiiI
  if 9 - 9: I1IiiI % I1IiiI % II111iiii
 os . system ( "cp ./lisp.config ./lisp.config.before-clear" )
 lisp . lisp_ipc_lock . acquire ( )
 I1I1i1I ( )
 lisp . lisp_ipc_lock . release ( )
 if 87 - 87: O0 / iIii1I11I1II1 * i1IIi
 iIiIIIi = "Configuration cleared, a backup copy is stored in "
 iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
 iIiIIIi += lisp . lisp_print_cour ( "./lisp.config.before-clear" )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 41 - 41: OoOoOO00 * I11i / OoOoOO00 % oO0o
 if 18 - 18: II111iiii . OoooooooOO % OoOoOO00 % Ii1I
 if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
@ bottle . route ( '/lisp/clear/conf/verify' )
def oOo0oO ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 5 - 5: OOooOOo - OOooOOo . Oo0Ooo + OoOoOO00 - OOooOOo . oO0o
  if 31 - 31: II111iiii - iIii1I11I1II1 - iIii1I11I1II1 % I11i
 iIiIIIi = "<br>Are you sure you want to clear the configuration?"
 iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
 if 12 - 12: iIii1I11I1II1
 iIi1i = lisp . lisp_button ( "yes" , "/lisp/clear/conf" )
 i1ii = lisp . lisp_button ( "cancel" , "/lisp" )
 iIiIIIi += iIi1i + i1ii + "<br>"
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 68 - 68: OOooOOo * O0 . I11i - II111iiii . ooOoO0o / II111iiii
 if 47 - 47: OoooooooOO
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 if 82 - 82: ooOoO0o + II111iiii
 if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
 if 68 - 68: Oo0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
 if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
def iI1I1iIi11 ( ) :
 oo00O00oO = ""
 if 87 - 87: OoOoOO00
 for Ii in [ "443" , "-8080" , "8080" ] :
  oO0O = 'ps auxww | egrep "lisp-core.pyo {}" | egrep -v grep' . format ( Ii )
  iIiIIIi = getoutput ( oO0O )
  if ( iIiIIIi == "" ) : continue
  if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
  iIiIIIi = iIiIIIi . split ( "\n" ) [ 0 ]
  iIiIIIi = iIiIIIi . split ( " " )
  if ( iIiIIIi [ - 2 ] == "lisp-core.pyo" and iIiIIIi [ - 1 ] == Ii ) : oo00O00oO = Ii
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
 OOoO = getoutput ( "egrep requiretty /etc/sudoers" ) . split ( " " )
 if ( OOoO [ - 1 ] == "requiretty" and OOoO [ 0 ] == "Defaults" ) :
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
 oo00O00oO = iI1I1iIi11 ( )
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
 Oo0O0 = "sleep 1; sudo ./RESTART-LISP {}" . format ( oo00O00oO )
 threading . Thread ( target = Ii1Iii111IiI1 , args = [ Oo0O0 ] ) . start ( )
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
 iIi1i = lisp . lisp_button ( "yes" , "/lisp/restart" )
 i1ii = lisp . lisp_button ( "cancel" , "/lisp" )
 iIiIIIi += iIi1i + i1ii + "<br>"
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
 if ( lisp . lisp_is_python2 ( ) ) :
  O0ooOo0o0Oo = "python -O "
  OooO0oOo = "pyo"
  if 66 - 66: OoO0O00 * Oo0Ooo
 if ( lisp . lisp_is_python3 ( ) ) :
  O0ooOo0o0Oo = "python3.8 -O "
  OooO0oOo = "pyc"
  if 28 - 28: OoO0O00 % OoOoOO00 % I1ii11iIi11i + I1IiiI / I1IiiI
 if ( lisp . lisp_is_ubuntu ( ) ) :
  oO0O = "{} lisp-get-bits.{} {} force 2>&1 > /dev/null" . format ( O0ooOo0o0Oo , OooO0oOo , i1II )
  if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
 else :
  oO0O = "{} lisp-get-bits.{} {} force >& /dev/null" . format ( O0ooOo0o0Oo , OooO0oOo , i1II )
  if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
  if 23 - 23: i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo - I1ii11iIi11i % iII111i * OoO0O00 - OOooOOo / iII111i
  if 29 - 29: I1ii11iIi11i
  if 52 - 52: i11iIiiIii / i1IIi
  if 1 - 1: ooOoO0o
 i1i1iII1 = os . system ( oO0O )
 if 78 - 78: I1ii11iIi11i + I11i - O0
 i1I1iIi1IiI = i1II . split ( "/" ) [ - 1 ]
 if 11 - 11: II111iiii
 if ( os . path . exists ( i1I1iIi1IiI ) ) :
  O00O00O000OOO = i1II . split ( "release-" ) [ 1 ]
  O00O00O000OOO = O00O00O000OOO . split ( ".tgz" ) [ 0 ]
  if 3 - 3: O0
  iIiIIIi = "Install completed for release {}" . format ( O00O00O000OOO )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  if 64 - 64: i1IIi % ooOoO0o / i11iIiiIii - i1IIi % OOooOOo . iII111i
  iIiIIIi += "<br><br>" + lisp . lisp_button ( "restart LISP subsystem" ,
 "/lisp/restart/verify" ) + "<br>"
 else :
  iIi1IiI = lisp . lisp_print_cour ( i1II )
  iIiIIIi = "Install failed for file {}" . format ( iIi1IiI )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  if 8 - 8: Oo0Ooo + II111iiii * OOooOOo * OoOoOO00 * I11i / IiII
  if 21 - 21: oO0o / OoooooooOO
 iIi1IiI = "Install request for file {} {}" . format ( i1II ,
 "succeeded" if ( i1i1iII1 == 0 ) else "failed" )
 lisp . lprint ( lisp . bold ( iIi1IiI , False ) )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 11 - 11: OOooOOo % Ii1I - i11iIiiIii - oO0o + ooOoO0o + IiII
 if 87 - 87: I1Ii111 * i1IIi / I1ii11iIi11i
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo - OoooooooOO % OOooOOo * OoOoOO00
 if 69 - 69: i1IIi
 if 59 - 59: II111iiii - o0oOOo0O0Ooo
 if 24 - 24: Oo0Ooo - i1IIi + I11i
 if 38 - 38: OoooooooOO / I1ii11iIi11i . O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
@ bottle . route ( '/lisp/install/image' )
def ooO00O00oOO ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 40 - 40: iII111i . oO0o + I1IiiI + I1ii11iIi11i + I1Ii111
  if 26 - 26: iIii1I11I1II1
 iIi1IiI = lisp . lisp_print_sans ( "<br>Enter lispers.net tarball URL:" )
 iIiIIIi = '''
        <form action="/lisp/install" method="post" style="display: inline;">
        {}
        <input type="text" name="image_url" size="75" required/>
        <input type="submit" style="background-color:transparent;border-radius:10px;" value="Submit" />
        </form><br>''' . format ( iIi1IiI )
 if 87 - 87: I1ii11iIi11i / OoooooooOO - Oo0Ooo % OoOoOO00 % IiII % Oo0Ooo
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 29 - 29: OoooooooOO . I1IiiI % I1ii11iIi11i - iII111i
 if 8 - 8: i1IIi
 if 32 - 32: oO0o / II111iiii
 if 45 - 45: I1ii11iIi11i + OoO0O00 * i11iIiiIii / OOooOOo % I11i * O0
 if 17 - 17: O0
 if 88 - 88: Oo0Ooo . O0 % OoooooooOO / OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
@ bottle . route ( '/lisp/log/flows' )
def IIIIIiII1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 45 - 45: I1IiiI / iII111i . iII111i
  if 35 - 35: I1Ii111 . OoOoOO00 * i11iIiiIii
 os . system ( "touch ./log-flows" )
 if 44 - 44: i11iIiiIii / Oo0Ooo
 iIiIIIi = lisp . lisp_print_sans ( "Flow data appended to file " )
 Ii1IIi = "<a href='/lisp/show/log/lisp-flow/100'>logs/lisp-flows.log</a>"
 iIiIIIi += lisp . lisp_print_cour ( Ii1IIi )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 43 - 43: I1Ii111 % iII111i
 if 69 - 69: iII111i % OoO0O00
 if 86 - 86: oO0o / oO0o
 if 28 - 28: i11iIiiIii / o0oOOo0O0Ooo . iIii1I11I1II1 / II111iiii
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
@ bottle . route ( '/lisp/search/log/<name>/<num>/<keyword>' )
def oo00ooOoo ( name = "" , num = "" , keyword = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 28 - 28: Ii1I
  if 1 - 1: Ii1I
 Oo0O0 = "tail -n {} logs/{}.log | egrep -B10 -A10 {}" . format ( num , name ,
 keyword )
 iIiIIIi = getoutput ( Oo0O0 )
 if 48 - 48: O0 + O0 . I1Ii111 - ooOoO0o
 if ( iIiIIIi ) :
  o00oo0000 = iIiIIIi . count ( keyword )
  iIiIIIi = lisp . convert_font ( iIiIIIi )
  iIiIIIi = iIiIIIi . replace ( "--\n--\n" , "--\n" )
  iIiIIIi = iIiIIIi . replace ( "\n" , "<br>" )
  iIiIIIi = iIiIIIi . replace ( "--<br>" , "<hr>" )
  iIiIIIi = "Found <b>{}</b> occurences<hr>" . format ( o00oo0000 ) + iIiIIIi
 else :
  iIiIIIi = "Keyword {} not found" . format ( keyword )
  if 44 - 44: Oo0Ooo % iIii1I11I1II1
  if 90 - 90: II111iiii + OoooooooOO % OoooooooOO
  if 35 - 35: iII111i / I1ii11iIi11i * OoooooooOO . II111iiii / Oo0Ooo
  if 1 - 1: OoooooooOO + IiII . i1IIi % I11i
  if 66 - 66: o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
 I1 = "<font color='blue'><b>{}</b>" . format ( keyword )
 iIiIIIi = iIiIIIi . replace ( keyword , I1 )
 iIiIIIi = iIiIIIi . replace ( keyword , keyword + "</font>" )
 if 13 - 13: OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - Oo0Ooo / oO0o
 iIiIIIi = lisp . lisp_print_cour ( iIiIIIi )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 8 - 8: OoOoOO00 / O0 * O0 % I1Ii111 - Oo0Ooo + I11i
 if 83 - 83: O0 . I1IiiI
 if 95 - 95: I11i . OoooooooOO - i1IIi - OoooooooOO - OoO0O00 % iIii1I11I1II1
 if 64 - 64: OOooOOo + OoooooooOO * OoooooooOO
 if 41 - 41: ooOoO0o . Oo0Ooo + I1IiiI
 if 100 - 100: Ii1I + OoO0O00
 if 73 - 73: i1IIi - I1Ii111 % ooOoO0o / OoO0O00
@ bottle . post ( '/lisp/search/log/<name>/<num>' )
def III1iii1i11iI ( name = "" , num = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 56 - 56: i11iIiiIii . iIii1I11I1II1 + I1ii11iIi11i + iII111i / Oo0Ooo . I1Ii111
  if 74 - 74: OoooooooOO % OOooOOo % I1Ii111 - I1IiiI - I11i
 o0 = bottle . request . forms . get ( "keyword" )
 return ( oo00ooOoo ( name , num , o0 ) )
 if 35 - 35: IiII + i1IIi * oO0o - Ii1I . Oo0Ooo
 if 31 - 31: o0oOOo0O0Ooo
 if 15 - 15: O0 / Oo0Ooo % I1ii11iIi11i + o0oOOo0O0Ooo
 if 23 - 23: iIii1I11I1II1 + O0
 if 58 - 58: Oo0Ooo
 if 9 - 9: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo + OoooooooOO
 if 62 - 62: O0 / I1IiiI % O0 * OoO0O00 % I1IiiI
@ bottle . route ( '/lisp/show/log/<name>/<num>' )
def IiOOoo0oO00oo00 ( name = "" , num = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 87 - 87: OOooOOo . OoOoOO00 . i1IIi . i1IIi - o0oOOo0O0Ooo
  if 26 - 26: iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
  if 67 - 67: OoooooooOO
  if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
  if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if ( num == "" ) : num = 100
 if 93 - 93: i1IIi
 ooOOOo = '''
        <form action="/lisp/search/log/{}/{}" method="post">
        <i>Keyword search:</i>
        <input type="text" name="keyword" />
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </form><hr>
    ''' . format ( name , num )
 if 98 - 98: oO0o % IiII * i11iIiiIii % I1ii11iIi11i
 if ( os . path . exists ( "logs/{}.log" . format ( name ) ) ) :
  iIiIIIi = getoutput ( "tail -n {} logs/{}.log" . format ( num , name ) )
  iIiIIIi = lisp . convert_font ( iIiIIIi )
  iIiIIIi = iIiIIIi . replace ( "\n" , "<br>" )
  iIiIIIi = ooOOOo + lisp . lisp_print_cour ( iIiIIIi )
 else :
  iIiI1IIiii11 = lisp . lisp_print_sans ( "File" )
  IiI1 = lisp . lisp_print_cour ( "logs/{}.log" . format ( name ) )
  oOo00o00oO = lisp . lisp_print_sans ( "does not exist" )
  iIiIIIi = "{} {} {}" . format ( iIiI1IIiii11 , IiI1 , oOo00o00oO )
  if 95 - 95: I1IiiI
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 88 - 88: IiII % OoO0O00 + I1Ii111 + I1Ii111 * II111iiii
 if 78 - 78: OoooooooOO
 if 77 - 77: I1ii11iIi11i / i1IIi / Oo0Ooo % OOooOOo
 if 48 - 48: I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
@ bottle . route ( '/lisp/debug/<name>' )
def OO0o0OO0 ( name = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 56 - 56: i11iIiiIii - Oo0Ooo / iII111i / OoOoOO00
  if 43 - 43: o0oOOo0O0Ooo . iII111i . I11i + iIii1I11I1II1
  if 78 - 78: iIii1I11I1II1 % OoOoOO00 + I1ii11iIi11i / i1IIi % II111iiii + OOooOOo
  if 91 - 91: iIii1I11I1II1 % OoO0O00 . o0oOOo0O0Ooo + Ii1I + o0oOOo0O0Ooo
  if 95 - 95: Ii1I + I1ii11iIi11i * OOooOOo
 if ( name == "disable%all" ) :
  OoOooOOOO = lispconfig . lisp_get_clause_for_api ( "lisp debug" )
  if ( "lisp debug" in OoOooOOOO [ 0 ] ) :
   oooOo0OOOoo0 = [ ]
   for I1IiooooOoO0O in OoOooOOOO [ 0 ] [ "lisp debug" ] :
    IIII = list ( I1IiooooOoO0O . keys ( ) ) [ 0 ]
    oooOo0OOOoo0 . append ( { IIII : "no" } )
    if 8 - 8: o0oOOo0O0Ooo / I1ii11iIi11i - i11iIiiIii % iIii1I11I1II1
   oooOo0OOOoo0 = { "lisp debug" : oooOo0OOOoo0 }
   lispconfig . lisp_put_clause_for_api ( oooOo0OOOoo0 )
   if 66 - 66: IiII
   if 67 - 67: I1Ii111 / OoO0O00 . OOooOOo / OOooOOo - Ii1I - OoooooooOO
  OoOooOOOO = lispconfig . lisp_get_clause_for_api ( "lisp xtr-parameters" )
  if ( "lisp xtr-parameters" in OoOooOOOO [ 0 ] ) :
   oooOo0OOOoo0 = [ ]
   for I1IiooooOoO0O in OoOooOOOO [ 0 ] [ "lisp xtr-parameters" ] :
    IIII = list ( I1IiooooOoO0O . keys ( ) ) [ 0 ]
    if ( IIII in [ "data-plane-logging" , "flow-logging" ] ) :
     oooOo0OOOoo0 . append ( { IIII : "no" } )
    else :
     oooOo0OOOoo0 . append ( { IIII : I1IiooooOoO0O [ IIII ] } )
     if 46 - 46: O0 * Oo0Ooo / O0 + OoO0O00
     if 56 - 56: OOooOOo . II111iiii
   oooOo0OOOoo0 = { "lisp xtr-parameters" : oooOo0OOOoo0 }
   lispconfig . lisp_put_clause_for_api ( oooOo0OOOoo0 )
   if 53 - 53: oO0o % I11i . ooOoO0o - OoOoOO00
   if 69 - 69: II111iiii * I1IiiI - ooOoO0o - iIii1I11I1II1 + o0oOOo0O0Ooo - oO0o
  return ( lispconfig . lisp_landing_page ( ) )
  if 50 - 50: I11i - ooOoO0o
  if 1 - 1: oO0o
  if 12 - 12: ooOoO0o % I1IiiI + oO0o - i1IIi . Ii1I / I1IiiI
  if 51 - 51: OOooOOo . I1IiiI
  if 73 - 73: OoooooooOO . I1IiiI / I1Ii111 % Ii1I
 name = name . split ( "%" )
 o0OO0O00o = name [ 0 ]
 iiii11I = name [ 1 ]
 if 73 - 73: i1IIi - OOooOOo
 O0oo0O = [ "data-plane-logging" , "flow-logging" ]
 if 85 - 85: I1ii11iIi11i + Ii1I * I1IiiI % i11iIiiIii
 iI1i = "lisp xtr-parameters" if ( o0OO0O00o in O0oo0O ) else "lisp debug"
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 OoOooOOOO = lispconfig . lisp_get_clause_for_api ( iI1i )
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if ( iI1i in OoOooOOOO [ 0 ] ) :
  oooOo0OOOoo0 = { }
  for I1IiooooOoO0O in OoOooOOOO [ 0 ] [ iI1i ] :
   oooOo0OOOoo0 [ list ( I1IiooooOoO0O . keys ( ) ) [ 0 ] ] = list ( I1IiooooOoO0O . values ( ) ) [ 0 ]
   if ( o0OO0O00o in oooOo0OOOoo0 ) : oooOo0OOOoo0 [ o0OO0O00o ] = iiii11I
   if 47 - 47: o0oOOo0O0Ooo
  oooOo0OOOoo0 = { iI1i : oooOo0OOOoo0 }
  lispconfig . lisp_put_clause_for_api ( oooOo0OOOoo0 )
  if 66 - 66: I1IiiI - IiII
 return ( lispconfig . lisp_landing_page ( ) )
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
@ bottle . route ( '/lisp/clear/<name>' )
@ bottle . route ( '/lisp/clear/etr/<etr_name>/<stats_name>' )
@ bottle . route ( '/lisp/clear/rtr/<rtr_name>/<stats_name>' )
@ bottle . route ( '/lisp/clear/itr/<itr_name>' )
@ bottle . route ( '/lisp/clear/rtr/<rtr_name>' )
def i1II11Iii1I ( name = "" , itr_name = '' , rtr_name = "" , etr_name = "" ,
 stats_name = "" ) :
 if 92 - 92: OOooOOo % IiII % OoOoOO00
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 4 - 4: OoOoOO00 + Ii1I / oO0o
  if 13 - 13: iII111i
  if 80 - 80: Ii1I - o0oOOo0O0Ooo
  if 41 - 41: o0oOOo0O0Ooo - Oo0Ooo * I1IiiI
  if 82 - 82: OoO0O00 % o0oOOo0O0Ooo % OOooOOo / O0
 if ( lispconfig . lisp_is_user_superuser ( None ) == False ) :
  iIiIIIi = lisp . lisp_print_sans ( "Not authorized" )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 94 - 94: I1ii11iIi11i + I1ii11iIi11i + OoooooooOO % ooOoO0o
  if 7 - 7: iII111i
 O0ooo0O0oo0 = "clear"
 if ( name == "referral" ) :
  oOo000O = "lisp-mr"
  iII = "Referral"
 elif ( itr_name == "map-cache" ) :
  oOo000O = "lisp-itr"
  iII = "ITR <a href='/lisp/show/itr/map-cache'>map-cache</a>"
 elif ( rtr_name == "map-cache" ) :
  oOo000O = "lisp-rtr"
  iII = "RTR <a href='/lisp/show/rtr/map-cache'>map-cache</a>"
 elif ( etr_name == "stats" ) :
  oOo000O = "lisp-etr"
  iII = ( "ETR '{}' decapsulation <a href='/lisp/show/" + "database'>stats</a>" ) . format ( stats_name )
  if 58 - 58: I1IiiI % I1ii11iIi11i
  O0ooo0O0oo0 += "%" + stats_name
 elif ( rtr_name == "stats" ) :
  oOo000O = "lisp-rtr"
  iII = ( "RTR '{}' decapsulation <a href='/lisp/show/" + "rtr/map-cache'>stats</a>" ) . format ( stats_name )
  if 92 - 92: OoO0O00 * ooOoO0o
  O0ooo0O0oo0 += "%" + stats_name
 else :
  iIiIIIi = lisp . lisp_print_sans ( "Invalid command" )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 35 - 35: i11iIiiIii
  if 99 - 99: II111iiii . o0oOOo0O0Ooo + O0
  if 71 - 71: IiII + i1IIi * Oo0Ooo % Oo0Ooo / Oo0Ooo
  if 55 - 55: OoooooooOO + I1Ii111 + OoooooooOO * ooOoO0o
  if 68 - 68: O0
 O0ooo0O0oo0 = lisp . lisp_command_ipc ( O0ooo0O0oo0 , "lisp-core" )
 lisp . lisp_ipc ( O0ooo0O0oo0 , ooo0Oo0 , oOo000O )
 if 2 - 2: OoO0O00 + O0 * OoO0O00 - Ii1I + oO0o
 if 43 - 43: I1ii11iIi11i - OoOoOO00
 if 36 - 36: I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 I11 = getoutput ( "egrep 'lisp map-cache' ./lisp.config" )
 if ( I11 != "" ) :
  os . system ( "touch ./lisp.config" )
  if 99 - 99: O0 + O0 * I11i + O0 * oO0o
  if 80 - 80: I1IiiI . Ii1I
 iIiIIIi = lisp . lisp_print_sans ( "{} cleared" . format ( iII ) )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
 if 60 - 60: OoO0O00
 if 81 - 81: OoOoOO00 % Ii1I
@ bottle . route ( '/lisp/show/map-server' )
def oo0 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 16 - 16: Ii1I * OoO0O00 / oO0o
  if 22 - 22: oO0o + iIii1I11I1II1 % Oo0Ooo / I11i / Ii1I
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 ,
 "show map-server" ) )
 if 54 - 54: OoOoOO00 % IiII . i11iIiiIii
 if 93 - 93: ooOoO0o % i11iIiiIii % I1Ii111
 if 64 - 64: I1Ii111 + I1IiiI * O0 / Oo0Ooo - I11i % I11i
 if 59 - 59: OOooOOo + OoooooooOO
 if 55 - 55: i11iIiiIii % iIii1I11I1II1 . i1IIi + OoooooooOO / i11iIiiIii
 if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
 if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
@ bottle . route ( '/lisp/show/database' )
def iIii1iII1Ii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 50 - 50: Ii1I
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 ,
 "show database-mapping" ) )
 if 22 - 22: I11i * O0 . II111iiii - OoO0O00
 if 90 - 90: oO0o
 if 94 - 94: I11i / I1ii11iIi11i * I1Ii111 - OoOoOO00
 if 44 - 44: Ii1I % i11iIiiIii - iII111i * I1ii11iIi11i + Oo0Ooo * OOooOOo
 if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
 if 65 - 65: Oo0Ooo . OoooooooOO
 if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
@ bottle . route ( '/lisp/show/itr/map-cache' )
def o0O0oo0o ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 12 - 12: OoOoOO00 % IiII % I1ii11iIi11i . i11iIiiIii * iIii1I11I1II1
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 ,
 "show itr-map-cache" ) )
 if 66 - 66: i11iIiiIii * iIii1I11I1II1 % OoooooooOO
 if 5 - 5: OoOoOO00 % OoooooooOO
 if 60 - 60: OoOoOO00 . i1IIi % OoO0O00 % ooOoO0o % OOooOOo
 if 33 - 33: iIii1I11I1II1 - Ii1I * I1ii11iIi11i % iIii1I11I1II1 + OoO0O00 . OOooOOo
 if 56 - 56: i11iIiiIii * iII111i . oO0o
 if 78 - 78: OoOoOO00
 if 1 - 1: OOooOOo . IiII
@ bottle . route ( '/lisp/show/itr/rloc-probing' )
def I1iIII1IiiI ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 ,
 "show itr-rloc-probing" ) )
 if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
@ bottle . post ( '/lisp/show/itr/map-cache/lookup' )
def iii1IiI1I1 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 64 - 64: ooOoO0o / O0 * OoOoOO00 * ooOoO0o
  if 60 - 60: I11i / i1IIi % I1ii11iIi11i / I1ii11iIi11i * I1ii11iIi11i . i11iIiiIii
 o0oOO00 = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( o0oOO00 ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( o0oOO00 )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 46 - 46: i11iIiiIii - I11i
  if 95 - 95: II111iiii
 Oo0O0 = "show itr-map-cache" + "%" + o0oOO00
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 ,
 Oo0O0 ) )
 if 65 - 65: OoOoOO00
 if 31 - 31: I11i * OoOoOO00 . IiII % Ii1I + Oo0Ooo
 if 47 - 47: O0 * I1IiiI * OoO0O00 . II111iiii
 if 95 - 95: Ii1I % IiII . O0 % I1Ii111
 if 68 - 68: Oo0Ooo . Oo0Ooo - I1ii11iIi11i / I11i . ooOoO0o / i1IIi
 if 12 - 12: I1ii11iIi11i * i1IIi * I11i
 if 23 - 23: OOooOOo / O0 / I1IiiI
@ bottle . route ( '/lisp/show/rtr/map-cache' )
@ bottle . route ( '/lisp/show/rtr/map-cache/<dns>' )
def I11o0000o0Oo ( dns = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 90 - 90: iIii1I11I1II1 * II111iiii
  if 70 - 70: o0oOOo0O0Ooo * II111iiii - ooOoO0o
 if ( dns == "dns" ) :
  return ( lispconfig . lisp_process_show_command ( ooo0Oo0 ,
 "show rtr-map-cache-dns" ) )
 else :
  return ( lispconfig . lisp_process_show_command ( ooo0Oo0 ,
 "show rtr-map-cache" ) )
  if 55 - 55: I1IiiI
  if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
  if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
  if 79 - 79: OoOoOO00 / ooOoO0o
  if 77 - 77: Oo0Ooo
  if 46 - 46: I1Ii111
  if 72 - 72: iII111i * OOooOOo
  if 67 - 67: i1IIi
@ bottle . route ( '/lisp/show/rtr/rloc-probing' )
def iii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 57 - 57: I1IiiI
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 ,
 "show rtr-rloc-probing" ) )
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if 50 - 50: OoOoOO00
 if 33 - 33: I11i
 if 98 - 98: OoOoOO00 % II111iiii
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
 if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 if 68 - 68: o0oOOo0O0Ooo
@ bottle . post ( '/lisp/show/rtr/map-cache/lookup' )
def i11Ii1IIi ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 36 - 36: O0 * OoO0O00 % iII111i * iII111i / OoO0O00 * IiII
  if 14 - 14: i1IIi . IiII + O0 * ooOoO0o
 o0oOO00 = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( o0oOO00 ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( o0oOO00 )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 76 - 76: OoO0O00
  if 92 - 92: I11i - iIii1I11I1II1 % OoooooooOO
 Oo0O0 = "show rtr-map-cache" + "%" + o0oOO00
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 ,
 Oo0O0 ) )
 if 39 - 39: iII111i . I1IiiI * OoOoOO00 - i11iIiiIii
 if 1 - 1: iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
@ bottle . route ( '/lisp/show/referral' )
def o0oOOOO0 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 11 - 11: i1IIi
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 ,
 "show referral-cache" ) )
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if 48 - 48: iII111i + IiII
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 if 14 - 14: OOooOOo
 if 79 - 79: Ii1I
 if 76 - 76: iIii1I11I1II1
 if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
@ bottle . post ( '/lisp/show/referral/lookup' )
def ooOo000OoO0o ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 58 - 58: I1ii11iIi11i
  if 2 - 2: II111iiii / I1Ii111
 o0oOO00 = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( o0oOO00 ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( o0oOO00 )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
  if 22 - 22: ooOoO0o . iIii1I11I1II1
 Oo0O0 = "show referral-cache" + "%" + o0oOO00
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 , Oo0O0 ) )
 if 12 - 12: Ii1I
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
@ bottle . route ( '/lisp/show/delegations' )
def Iii ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 7 - 7: Oo0Ooo * OoooooooOO % O0 - Ii1I . Ii1I
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 ,
 "show delegations" ) )
 if 80 - 80: OoOoOO00 - II111iiii
 if 35 - 35: ooOoO0o - OoO0O00 . Oo0Ooo * Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
@ bottle . post ( '/lisp/show/delegations/lookup' )
def Oo0O0OOO0o0O ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 51 - 51: oO0o + OoO0O00 + iII111i + iII111i % o0oOOo0O0Ooo
  if 29 - 29: ooOoO0o
 o0oOO00 = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( o0oOO00 ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( o0oOO00 )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 41 - 41: O0 % iII111i
  if 10 - 10: iII111i . i1IIi + Ii1I
 Oo0O0 = "show delegations" + "%" + o0oOO00
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 , Oo0O0 ) )
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if 81 - 81: IiII / OoOoOO00 * IiII . O0
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
@ bottle . route ( '/lisp/show/site' )
@ bottle . route ( '/lisp/show/site/<eid_prefix>' )
def O0o0oo0oOO0oO ( eid_prefix = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 15 - 15: OoO0O00 * II111iiii
  if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
 Oo0O0 = "show site"
 if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
 if ( eid_prefix != "" ) :
  Oo0O0 = lispconfig . lisp_parse_eid_in_url ( Oo0O0 , eid_prefix )
  if 79 - 79: I1IiiI - ooOoO0o
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 , Oo0O0 ) )
 if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 if 83 - 83: IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if 80 - 80: OoooooooOO + IiII
@ bottle . route ( '/lisp/show/itr/dynamic-eid/<eid_prefix>' )
def O00O ( eid_prefix = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 63 - 63: OoooooooOO * OoooooooOO % OoO0O00 + O0 / I1Ii111 + iIii1I11I1II1
  if 72 - 72: OoOoOO00 * iIii1I11I1II1 % I11i
 Oo0O0 = "show itr-dynamic-eid"
 if 20 - 20: II111iiii % iIii1I11I1II1 + oO0o * II111iiii * OoO0O00 % OoO0O00
 if ( eid_prefix != "" ) :
  Oo0O0 = lispconfig . lisp_parse_eid_in_url ( Oo0O0 , eid_prefix )
  if 15 - 15: oO0o / I1Ii111
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 , Oo0O0 ) )
 if 37 - 37: i11iIiiIii + I1IiiI . OOooOOo % I11i % I11i
 if 26 - 26: O0
 if 34 - 34: ooOoO0o * I1Ii111
 if 97 - 97: i11iIiiIii % oO0o / Oo0Ooo / Oo0Ooo
 if 97 - 97: II111iiii - I1Ii111 - iIii1I11I1II1 * I1IiiI
 if 54 - 54: iIii1I11I1II1
 if 5 - 5: IiII
@ bottle . route ( '/lisp/show/etr/dynamic-eid/<eid_prefix>' )
def Oo0O0oo0o00o0 ( eid_prefix = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 66 - 66: iIii1I11I1II1 . i11iIiiIii / I11i / ooOoO0o + I1Ii111
  if 5 - 5: OoOoOO00 % iII111i + IiII
 Oo0O0 = "show etr-dynamic-eid"
 if 13 - 13: IiII
 if ( eid_prefix != "" ) :
  Oo0O0 = lispconfig . lisp_parse_eid_in_url ( Oo0O0 , eid_prefix )
  if 19 - 19: II111iiii - IiII
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 , Oo0O0 ) )
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
  return ( OOoO0 ( ) )
  if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
  if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 o0oOO00 = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( o0oOO00 ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( o0oOO00 )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 69 - 69: OoOoOO00
  if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 Oo0O0 = "show site" + "%" + o0oOO00 + "@lookup"
 return ( lispconfig . lisp_process_show_command ( ooo0Oo0 , Oo0O0 ) )
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 if 88 - 88: o0oOOo0O0Ooo
 if 1 - 1: OoooooooOO
 if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
@ bottle . post ( '/lisp/lig' )
def iiiIiIIII1iiIIi ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 17 - 17: I11i
  if 97 - 97: I1ii11iIi11i * I1ii11iIi11i / iII111i
 i1111IIiI = bottle . request . forms . get ( "eid" )
 I11I1IIii = bottle . request . forms . get ( "mr" )
 oO0O0oo = bottle . request . forms . get ( "count" )
 ii1I = "no-info" if bottle . request . forms . get ( "no-nat" ) == "yes" else ""
 if 61 - 61: iIii1I11I1II1 - I11i / iII111i * I11i % Ii1I % iII111i
 if 63 - 63: OOooOOo % iIii1I11I1II1
 if 20 - 20: OoO0O00 . I1IiiI * i11iIiiIii / i11iIiiIii
 if 89 - 89: iII111i . i11iIiiIii * O0
 if ( I11I1IIii == "" ) : I11I1IIii = "localhost"
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if ( i1111IIiI == "" ) :
  iIiIIIi = "Need to supply EID address"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 74 - 74: oO0o
  if 34 - 34: iII111i
 ii1IIiI1IIi = ""
 if os . path . exists ( "lisp-lig.pyo" ) : ii1IIiI1IIi = "python -O lisp-lig.pyo"
 if os . path . exists ( "lisp-lig.pyc" ) : ii1IIiI1IIi = "python3.8 -O lisp-lig.pyc"
 if os . path . exists ( "lisp-lig.py" ) : ii1IIiI1IIi = "python lisp-lig.py"
 if 76 - 76: iII111i / OoO0O00 + OoOoOO00
 if 86 - 86: i11iIiiIii + i11iIiiIii . I1Ii111 % I1IiiI . ooOoO0o
 if 17 - 17: Ii1I
 if 67 - 67: O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if ( ii1IIiI1IIi == "" ) :
  iIiIIIi = "Cannot find lisp-lig.py or lisp-lig.pyo"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
  if 45 - 45: Ii1I - OOooOOo
 if ( oO0O0oo != "" ) : oO0O0oo = "count {}" . format ( oO0O0oo )
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 Oo0O0 = '{} "{}" to {} {} {}' . format ( ii1IIiI1IIi , i1111IIiI , I11I1IIii , oO0O0oo , ii1I )
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 iIiIIIi = getoutput ( Oo0O0 )
 iIiIIIi = iIiIIIi . replace ( "\n" , "<br>" )
 iIiIIIi = lisp . convert_font ( iIiIIIi )
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 I111I1I = lisp . space ( 2 ) + "RLOC:"
 iIiIIIi = iIiIIIi . replace ( "RLOC:" , I111I1I )
 Oo0000 = lisp . space ( 2 ) + "Empty,"
 iIiIIIi = iIiIIIi . replace ( "Empty," , Oo0000 )
 o0oooOO00 = lisp . space ( 4 ) + "geo:"
 iIiIIIi = iIiIIIi . replace ( "geo:" , o0oooOO00 )
 oO0Oo = lisp . space ( 4 ) + "elp:"
 iIiIIIi = iIiIIIi . replace ( "elp:" , oO0Oo )
 OooOOOOOo = lisp . space ( 4 ) + "rle:"
 iIiIIIi = iIiIIIi . replace ( "rle:" , OooOOOOOo )
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
 if 50 - 50: I1Ii111 + ooOoO0o + iII111i
 if 15 - 15: I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
@ bottle . post ( '/lisp/rig' )
def oOoO0OOO00O ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 73 - 73: o0oOOo0O0Ooo % OoO0O00 + IiII + I1IiiI
  if 80 - 80: i1IIi + o0oOOo0O0Ooo + IiII * I11i
 i1111IIiI = bottle . request . forms . get ( "eid" )
 OO00OoOoOO = bottle . request . forms . get ( "ddt" )
 II1i = "follow-all-referrals" if bottle . request . forms . get ( "follow" ) == "yes" else ""
 if 94 - 94: Ii1I . i1IIi
 if 71 - 71: iII111i + OoO0O00 - IiII . OoO0O00 . IiII + I1IiiI
 if 26 - 26: O0
 if 17 - 17: II111iiii
 if 9 - 9: OoooooooOO + oO0o
 if ( OO00OoOoOO == "" ) : OO00OoOoOO = "localhost"
 if 33 - 33: O0
 if 39 - 39: I1IiiI + Oo0Ooo
 if 83 - 83: i1IIi
 if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
 if ( i1111IIiI == "" ) :
  iIiIIIi = "Need to supply EID address"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 49 - 49: IiII / ooOoO0o / OOooOOo
  if 25 - 25: I1IiiI % O0 + i1IIi - ooOoO0o
 III1IiI1i1i = ""
 if os . path . exists ( "lisp-rig.pyo" ) : III1IiI1i1i = "python -O lisp-rig.pyo"
 if os . path . exists ( "lisp-rig.pyc" ) : III1IiI1i1i = "python3.8 -O lisp-rig.pyo"
 if os . path . exists ( "lisp-rig.py" ) : III1IiI1i1i = "python lisp-rig.py"
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if ( III1IiI1i1i == "" ) :
  iIiIIIi = "Cannot find lisp-rig.py or lisp-rig.pyo"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
  if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 Oo0O0 = '{} "{}" to {} {}' . format ( III1IiI1i1i , i1111IIiI , OO00OoOoOO , II1i )
 if 36 - 36: OOooOOo % i11iIiiIii
 iIiIIIi = getoutput ( Oo0O0 )
 iIiIIIi = iIiIIIi . replace ( "\n" , "<br>" )
 iIiIIIi = lisp . convert_font ( iIiIIIi )
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 i11ii = lisp . space ( 2 ) + "Referrals:"
 iIiIIIi = iIiIIIi . replace ( "Referrals:" , i11ii )
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
def OO0OOoooo0o ( eid1 , eid2 ) :
 ii1IIiI1IIi = None
 if os . path . exists ( "lisp-lig.pyo" ) : ii1IIiI1IIi = "python -O lisp-lig.pyo"
 if os . path . exists ( "lisp-lig.pyc" ) : ii1IIiI1IIi = "python3.8 -O lisp-lig.pyc"
 if os . path . exists ( "lisp-lig.py" ) : ii1IIiI1IIi = "python lisp-lig.py"
 if ( ii1IIiI1IIi == None ) : return ( [ None , None ] )
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 Ii1iiI1 = getoutput ( "egrep -A 2 'lisp map-resolver {' ./lisp.config" )
 I11I1IIii = None
 for o0 in [ "address = " , "dns-name = " ] :
  I11I1IIii = None
  o0ooOOoO0oO0 = Ii1iiI1 . find ( o0 )
  if ( o0ooOOoO0oO0 == - 1 ) : continue
  I11I1IIii = Ii1iiI1 [ o0ooOOoO0oO0 + len ( o0 ) : : ]
  o0ooOOoO0oO0 = I11I1IIii . find ( "\n" )
  if ( o0ooOOoO0oO0 == - 1 ) : continue
  I11I1IIii = I11I1IIii [ 0 : o0ooOOoO0oO0 ]
  break
  if 86 - 86: i1IIi / Ii1I * I1IiiI
 if ( I11I1IIii == None ) : return ( [ None , None ] )
 if 67 - 67: I1ii11iIi11i * I1ii11iIi11i / oO0o * OoooooooOO + OoOoOO00
 if 79 - 79: i1IIi
 if 1 - 1: oO0o / i1IIi
 if 74 - 74: I11i / OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
 Ooi1IIii11i1I1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 Ii1I1 = [ ]
 for i1111IIiI in [ eid1 , eid2 ] :
  if 98 - 98: IiII * iIii1I11I1II1 . Ii1I * Oo0Ooo / I1ii11iIi11i + ooOoO0o
  if 25 - 25: oO0o
  if 19 - 19: I1IiiI % Ii1I . IiII * ooOoO0o
  if 89 - 89: OoOoOO00 . OOooOOo
  if 7 - 7: oO0o % OoOoOO00 - I1IiiI + Oo0Ooo
  if ( Ooi1IIii11i1I1 . is_geo_string ( i1111IIiI ) ) :
   Ii1I1 . append ( i1111IIiI )
   continue
   if 70 - 70: II111iiii + I1Ii111 + i11iIiiIii - i1IIi / IiII
   if 40 - 40: I1ii11iIi11i * I1Ii111
  Oo0O0 = '{} "{}" to {} count 1' . format ( ii1IIiI1IIi , i1111IIiI , I11I1IIii )
  for I1i in [ Oo0O0 , Oo0O0 + " no-info" ] :
   iIiIIIi = getoutput ( Oo0O0 )
   o0ooOOoO0oO0 = iIiIIIi . find ( "geo: " )
   if ( o0ooOOoO0oO0 == - 1 ) :
    if ( I1i != Oo0O0 ) : Ii1I1 . append ( None )
    continue
    if 38 - 38: O0 . Oo0Ooo + OoOoOO00 - oO0o
   iIiIIIi = iIiIIIi [ o0ooOOoO0oO0 + len ( "geo: " ) : : ]
   o0ooOOoO0oO0 = iIiIIIi . find ( "\n" )
   if ( o0ooOOoO0oO0 == - 1 ) :
    if ( I1i != Oo0O0 ) : Ii1I1 . append ( None )
    continue
    if 43 - 43: iII111i + Oo0Ooo / OoooooooOO
   Ii1I1 . append ( iIiIIIi [ 0 : o0ooOOoO0oO0 ] )
   break
   if 24 - 24: O0 + o0oOOo0O0Ooo * Ii1I - I1Ii111
   if 10 - 10: i11iIiiIii
 return ( Ii1I1 )
 if 21 - 21: I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
@ bottle . post ( '/lisp/geo' )
def i1i1iIII11i ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 40 - 40: iIii1I11I1II1 / OoOoOO00 - O0 * iIii1I11I1II1
  if 56 - 56: OOooOOo
 i1111IIiI = bottle . request . forms . get ( "geo-point" )
 i1iiiIi1Iii = bottle . request . forms . get ( "geo-prefix" )
 iIiIIIi = ""
 if 54 - 54: ooOoO0o . iIii1I11I1II1 * i1IIi
 if 44 - 44: oO0o + I1ii11iIi11i * OOooOOo - i11iIiiIii / iIii1I11I1II1
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 I1iI1I1ii1 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 iIIi1 = lisp . lisp_geo ( "" )
 o0Ooo0o0Oo = lisp . lisp_geo ( "" )
 oo00ooooOOo00 , ii1i = OO0OOoooo0o ( i1111IIiI , i1iiiIi1Iii )
 if 70 - 70: oO0o % IiII % I1IiiI + i11iIiiIii . Ii1I % I1Ii111
 if 38 - 38: OoO0O00 . ooOoO0o
 if 34 - 34: i1IIi % IiII
 if 80 - 80: OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 if 94 - 94: i1IIi
 if ( I1iI1I1ii1 . is_geo_string ( i1111IIiI ) ) :
  if ( iIIi1 . parse_geo_string ( i1111IIiI ) == False ) :
   iIiIIIi = "Could not parse geo-point format"
   if 36 - 36: I1IiiI + Oo0Ooo
 elif ( oo00ooooOOo00 == None ) :
  iIiIIIi = "EID {} lookup could not find geo-point" . format (
 lisp . bold ( i1111IIiI , True ) )
 elif ( iIIi1 . parse_geo_string ( oo00ooooOOo00 ) == False ) :
  iIiIIIi = "Could not parse geo-point format returned from lookup"
  if 46 - 46: iII111i
  if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
  if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
  if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
  if 65 - 65: ooOoO0o - i1IIi
  if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 if ( iIiIIIi == "" ) :
  if ( I1iI1I1ii1 . is_geo_string ( i1iiiIi1Iii ) ) :
   if ( o0Ooo0o0Oo . parse_geo_string ( i1iiiIi1Iii ) == False ) :
    iIiIIIi = "Could not parse geo-prefix format"
    if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  elif ( ii1i == None ) :
   iIiIIIi = "EID-prefix {} lookup could not find geo-prefix" . format ( lisp . bold ( i1iiiIi1Iii , True ) )
   if 34 - 34: I1Ii111 - OOooOOo
  elif ( o0Ooo0o0Oo . parse_geo_string ( ii1i ) == False ) :
   iIiIIIi = "Could not parse geo-prefix format returned from lookup"
   if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
   if 64 - 64: i1IIi
   if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
   if 25 - 25: II111iiii / OoO0O00
   if 64 - 64: O0 % ooOoO0o
   if 40 - 40: o0oOOo0O0Ooo + I11i
   if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
 if ( iIiIIIi == "" ) :
  i1111IIiI = "" if ( i1111IIiI == oo00ooooOOo00 ) else ", EID {}" . format ( i1111IIiI )
  i1iiiIi1Iii = "" if ( i1iiiIi1Iii == ii1i ) else ", EID-prefix {}" . format ( i1iiiIi1Iii )
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
  iIiIIIi = ( "Geo-Point:{}{} {}{}<br>Geo-Prefix:{}{} {}, {} " + "kilometer radius{}<br>" ) . format ( i1i1 , II111IIIII , I11IiI1iI , i1111IIiI ,
  # iIii1I11I1II1 * IiII - OOooOOo / Oo0Ooo % oO0o
 I1iiIiIII , IIiIi1 , O0OO0OoO , O00O00o , i1iiiIi1Iii )
  iIiIIIi += "Distance:{}{} kilometers, point is {} of circle" . format ( o0IiIiI111IIII1 ,
 o0OOo , lisp . bold ( IiI1Ii11Ii , True ) )
  if 66 - 66: OoooooooOO + ooOoO0o * iII111i
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
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
  for OOoOOOo0 in list ( lisp . lisp_info_sources_by_address . values ( ) ) :
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
 ooOOOo = lisp . lisp_control_header ( )
 if ( ooOOOo . decode ( packet ) == None ) :
  lisp . lprint ( "Could not decode control header" )
  return ( True )
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 if ( ooOOOo . type != lisp . LISP_MAP_REQUEST ) :
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
 oo00O00oO = info_source . port
 ii111iI1i1 = info_source . nonce
 if 83 - 83: OoooooooOO
 mr_or_mn = "Reply" if mr_or_mn else "Notify"
 mr_or_mn = lisp . bold ( "nat-proxy Map-{}" . format ( mr_or_mn ) , False )
 if 12 - 12: ooOoO0o
 lisp . lprint ( "Forward {} to info-source {}, port {}, nonce 0x{}" . format ( mr_or_mn , lisp . red ( OO000 , False ) , oo00O00oO ,
 # iIii1I11I1II1 - I1Ii111 * IiII
 lisp . lisp_hex_string ( ii111iI1i1 ) ) )
 if 61 - 61: I1ii11iIi11i - OOooOOo
 if 16 - 16: iII111i / iIii1I11I1II1 + OOooOOo * iII111i * I11i
 if 8 - 8: I1Ii111
 if 15 - 15: Oo0Ooo / Ii1I % O0 + I1ii11iIi11i
 o0o = lisp . lisp_convert_4to6 ( OO000 )
 lisp . lisp_send ( lisp_sockets , o0o , oo00O00oO , packet )
 if 39 - 39: OOooOOo + OoO0O00
 if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
 if 71 - 71: ooOoO0o . i11iIiiIii
 if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
 if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
 if 67 - 67: iII111i
def oooO0o ( lisp_sockets , source , sport , packet ) :
 global ooo0Oo0
 if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
 ooOOOo = lisp . lisp_control_header ( )
 if ( ooOOOo . decode ( packet ) == None ) :
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
 if ( ooOOOo . type == lisp . LISP_NAT_INFO ) :
  if ( ooOOOo . info_reply == False ) :
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
 if ( ooOOOo . type in ( lisp . LISP_MAP_REGISTER , lisp . LISP_MAP_NOTIFY_ACK ) ) :
  lisp . lisp_ipc ( packet , ooo0Oo0 , "lisp-ms" )
  return
  if 9 - 9: I1Ii111 * OoooooooOO % I1IiiI / OoOoOO00 * I11i
  if 48 - 48: OoooooooOO . OoOoOO00
  if 65 - 65: oO0o . Oo0Ooo
  if 94 - 94: OoOoOO00 + IiII . ooOoO0o
  if 69 - 69: O0 - O0
 if ( ooOOOo . type == lisp . LISP_MAP_REPLY ) :
  i1I1i1i1I1 = lisp . lisp_map_reply ( )
  i1I1i1i1I1 . decode ( oo0O00ooo0o )
  if 17 - 17: OoOoOO00 + OoooooooOO % OOooOOo
  OOoOOOo0 = OooO00oO ( None , 0 , i1I1i1i1I1 . nonce )
  if ( OOoOOOo0 ) :
   ooOo0O0 ( lisp_sockets , OOoOOOo0 , oo0O00ooo0o , True )
  else :
   ii1IIiI1IIi = "/tmp/lisp-lig"
   if ( os . path . exists ( ii1IIiI1IIi ) ) :
    lisp . lisp_ipc ( packet , ooo0Oo0 , ii1IIiI1IIi )
   else :
    lisp . lisp_ipc ( packet , ooo0Oo0 , "lisp-itr" )
    if 36 - 36: i11iIiiIii + I1ii11iIi11i % OOooOOo . I1IiiI - ooOoO0o
    if 94 - 94: I1IiiI % OoOoOO00 . IiII . ooOoO0o . OoO0O00
  return
  if 53 - 53: OoOoOO00
  if 84 - 84: OoO0O00
  if 97 - 97: i1IIi
  if 98 - 98: OoooooooOO - I1IiiI + ooOoO0o
  if 98 - 98: iII111i . IiII . IiII - OOooOOo
 if ( ooOOOo . type == lisp . LISP_MAP_NOTIFY ) :
  oOOO0o = lisp . lisp_map_notify ( lisp_sockets )
  oOOO0o . decode ( oo0O00ooo0o )
  if 18 - 18: I1ii11iIi11i / Oo0Ooo - iII111i
  OOoOOOo0 = OooO00oO ( None , 0 , oOOO0o . nonce )
  if ( OOoOOOo0 ) :
   ooOo0O0 ( lisp_sockets , OOoOOOo0 , oo0O00ooo0o ,
 False )
  else :
   ii1IIiI1IIi = "/tmp/lisp-lig"
   if ( os . path . exists ( ii1IIiI1IIi ) ) :
    lisp . lisp_ipc ( packet , ooo0Oo0 , ii1IIiI1IIi )
   else :
    oOo000O = "lisp-rtr" if lisp . lisp_is_running ( "lisp-rtr" ) else "lisp-etr"
    if 69 - 69: oO0o / IiII * ooOoO0o
    lisp . lisp_ipc ( packet , ooo0Oo0 , oOo000O )
    if 81 - 81: oO0o
    if 62 - 62: Ii1I + O0 * OoO0O00
  return
  if 59 - 59: II111iiii
  if 43 - 43: Oo0Ooo + OoooooooOO
  if 47 - 47: ooOoO0o
  if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
  if 23 - 23: II111iiii * iII111i
  if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
 if ( ooOOOo . type == lisp . LISP_MAP_REFERRAL ) :
  III1IiI1i1i = "/tmp/lisp-rig"
  if ( os . path . exists ( III1IiI1i1i ) ) :
   lisp . lisp_ipc ( packet , ooo0Oo0 , III1IiI1i1i )
  else :
   lisp . lisp_ipc ( packet , ooo0Oo0 , "lisp-mr" )
   if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
  return
  if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
  if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  if 21 - 21: OoO0O00
  if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
  if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
  if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
 if ( ooOOOo . type == lisp . LISP_MAP_REQUEST ) :
  oOo000O = "lisp-itr" if ( ooOOOo . is_smr ( ) ) else "lisp-etr"
  if 11 - 11: O0 * OoOoOO00
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  if 18 - 18: OoooooooOO
  if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
  if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
  if ( ooOOOo . rloc_probe ) : return
  if 94 - 94: ooOoO0o + I1IiiI
  lisp . lisp_ipc ( packet , ooo0Oo0 , oOo000O )
  return
  if 56 - 56: OoOoOO00 % o0oOOo0O0Ooo
  if 40 - 40: OOooOOo / IiII
  if 29 - 29: Ii1I - Ii1I / ooOoO0o
  if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
  if 18 - 18: Oo0Ooo % O0
  if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
 if ( ooOOOo . type == lisp . LISP_ECM ) :
  OOoOOOo0 = OooO00oO ( source , sport , None )
  if ( OOoOOOo0 ) :
   if ( O0oO ( lisp_sockets , OOoOOOo0 ,
 oo0O00ooo0o ) ) : return
   if 86 - 86: IiII
   if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
  oOo000O = "lisp-mr"
  if ( ooOOOo . is_to_etr ( ) ) :
   oOo000O = "lisp-etr"
  elif ( ooOOOo . is_to_ms ( ) ) :
   oOo000O = "lisp-ms"
  elif ( ooOOOo . is_ddt ( ) ) :
   if ( lisp . lisp_is_running ( "lisp-ddt" ) ) :
    oOo000O = "lisp-ddt"
   elif ( lisp . lisp_is_running ( "lisp-ms" ) ) :
    oOo000O = "lisp-ms"
    if 33 - 33: II111iiii - IiII - ooOoO0o
  elif ( lisp . lisp_is_running ( "lisp-mr" ) == False ) :
   oOo000O = "lisp-etr"
   if 92 - 92: OoO0O00 * IiII
  lisp . lisp_ipc ( packet , ooo0Oo0 , oOo000O )
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
  Oooo = wsgi_server ( ( self . host , self . port ) , hand )
  Oooo . ssl_adapter = ssl_adaptor ( Ii1iiIIi1i , Ii1iiIIi1i , None )
  try :
   Oooo . start ( )
  finally :
   Oooo . stop ( )
   if 74 - 74: ooOoO0o % OoOoOO00 / Oo0Ooo
   if 2 - 2: IiII % IiII % I1Ii111
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
def O0OoOo ( bottle_port ) :
 lisp . lisp_set_exception ( )
 if 94 - 94: OoO0O00 + OoO0O00 + I1ii11iIi11i . OoO0O00 * Ii1I
 if 62 - 62: o0oOOo0O0Ooo / iIii1I11I1II1
 if 55 - 55: Ii1I / OoO0O00 + iII111i . IiII
 if 47 - 47: O0
 if 83 - 83: O0 + OoOoOO00 / O0 / I11i
 if ( bottle_port < 0 ) :
  bottle . run ( host = "0.0.0.0" , port = - bottle_port )
  return
  if 68 - 68: i1IIi . I11i . i1IIi + IiII % I1IiiI
  if 32 - 32: OoOoOO00 . iIii1I11I1II1 % oO0o . O0 . OoOoOO00 / iII111i
 bottle . server_names [ "lisp-ssl-server" ] = O0oooo0O
 if 45 - 45: iIii1I11I1II1
 if 41 - 41: iII111i % iII111i - IiII % OoO0O00 - OoooooooOO - iII111i
 if 66 - 66: o0oOOo0O0Ooo % OoOoOO00
 if 30 - 30: OoOoOO00 * Oo0Ooo % iIii1I11I1II1 % OoO0O00 + i11iIiiIii
 try :
  bottle . run ( host = "0.0.0.0" , port = bottle_port , server = "lisp-ssl-server" ,
 fast = True )
 except :
  bottle . run ( host = "0.0.0.0" , port = bottle_port , fast = True )
  if 46 - 46: I1IiiI . IiII - i11iIiiIii - I1Ii111
 return
 if 97 - 97: II111iiii % Oo0Ooo * IiII
 if 51 - 51: Oo0Ooo % OOooOOo . Oo0Ooo
 if 72 - 72: Ii1I % Ii1I / I1IiiI
 if 40 - 40: Oo0Ooo - OOooOOo + I1Ii111 - o0oOOo0O0Ooo % I1IiiI . ooOoO0o
 if 35 - 35: i11iIiiIii + OoooooooOO * iIii1I11I1II1 . I1Ii111
 if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
 if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
 if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
def OOO0 ( ) :
 lisp . lisp_set_exception ( )
 if 21 - 21: Oo0Ooo * o0oOOo0O0Ooo + OoooooooOO . I1Ii111 % oO0o
 return
 if 50 - 50: OoOoOO00 - oO0o + iIii1I11I1II1 - OoO0O00 . Oo0Ooo
 if 8 - 8: Ii1I
 if 30 - 30: i1IIi
 if 61 - 61: I1Ii111 / I1Ii111
 if 26 - 26: IiII . O0 * IiII - o0oOOo0O0Ooo * Oo0Ooo
 if 6 - 6: OoOoOO00 . II111iiii * I1IiiI . I1IiiI / Ii1I
 if 14 - 14: I1Ii111 % IiII - O0 / I1Ii111
 if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
 if 28 - 28: i11iIiiIii
def Oo00oo0 ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 i1i1iII1 = { "lisp-itr" : False , "lisp-etr" : False , "lisp-rtr" : False ,
 "lisp-mr" : False , "lisp-ms" : False , "lisp-ddt" : False }
 if 82 - 82: OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
 while ( True ) :
  time . sleep ( 1 )
  iI1 = i1i1iII1
  i1i1iII1 = { }
  if 99 - 99: OoO0O00 / i1IIi . I1ii11iIi11i
  for oOo000O in iI1 :
   i1i1iII1 [ oOo000O ] = lisp . lisp_is_running ( oOo000O )
   if ( iI1 [ oOo000O ] == i1i1iII1 [ oOo000O ] ) : continue
   if 23 - 23: Ii1I * ooOoO0o - I11i . O0 % iIii1I11I1II1
   lisp . lprint ( "*** Process '{}' has {} ***" . format ( oOo000O ,
 "come up" if i1i1iII1 [ oOo000O ] else "gone down" ) )
   if 19 - 19: I1IiiI
   if 66 - 66: oO0o / OoOoOO00
   if 13 - 13: II111iiii
   if 55 - 55: Oo0Ooo % i1IIi * I11i
   if ( i1i1iII1 [ oOo000O ] == True ) :
    lisp . lisp_ipc_lock . acquire ( )
    lispconfig . lisp_send_commands ( lisp_socket , oOo000O )
    lisp . lisp_ipc_lock . release ( )
    if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
    if 63 - 63: iIii1I11I1II1 / ooOoO0o
    if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
 return
 if 50 - 50: II111iiii
 if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
 if 44 - 44: I1IiiI
 if 55 - 55: oO0o . I1Ii111 * I1Ii111
 if 82 - 82: I1IiiI % OoO0O00 % I11i + I11i
 if 6 - 6: Oo0Ooo
 if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
def o0oOOO ( ) :
 lisp . lisp_set_exception ( )
 o00OoOooo = 60
 if 47 - 47: ooOoO0o + iII111i + i1IIi
 while ( True ) :
  time . sleep ( o00OoOooo )
  if 6 - 6: oO0o / O0 / Ii1I / IiII / oO0o . iIii1I11I1II1
  oo0O0 = [ ]
  Ii11I = lisp . lisp_get_timestamp ( )
  if 72 - 72: O0 + o0oOOo0O0Ooo + I1IiiI / Oo0Ooo
  if 83 - 83: IiII - I1IiiI . Ii1I
  if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
  if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
  for IIII in lisp . lisp_info_sources_by_address :
   OOoOOOo0 = lisp . lisp_info_sources_by_address [ IIII ]
   if ( OOoOOOo0 . no_timeout ) : continue
   if ( OOoOOOo0 . uptime + o00OoOooo < Ii11I ) : continue
   if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
   oo0O0 . append ( IIII )
   if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
   ii111iI1i1 = OOoOOOo0 . nonce
   if ( ii111iI1i1 == None ) : continue
   if ( ii111iI1i1 in lisp . lisp_info_sources_by_nonce ) :
    lisp . lisp_info_sources_by_nonce . pop ( ii111iI1i1 )
    if 25 - 25: Oo0Ooo % OoOoOO00
    if 75 - 75: i1IIi
    if 74 - 74: Oo0Ooo + I1Ii111 - oO0o - OoO0O00 + iII111i - iIii1I11I1II1
    if 54 - 54: I1ii11iIi11i + II111iiii . I1IiiI / OoO0O00 . ooOoO0o
    if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
    if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
  for IIII in oo0O0 :
   lisp . lisp_info_sources_by_address . pop ( IIII )
   if 36 - 36: I11i - IiII . IiII
   if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
 return
 if 84 - 84: iIii1I11I1II1 + OoooooooOO
 if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
 if 10 - 10: I1ii11iIi11i + IiII
 if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
 if 62 - 62: II111iiii
 if 12 - 12: IiII + II111iiii
 if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
 if 80 - 80: iII111i
def iI1I1ii11IIi1 ( lisp_ipc_control_socket , lisp_sockets ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  try : OOo = lisp_ipc_control_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  OoOooOOOO = OOo [ 0 ] . split ( "@" )
  oOOo0 = OOo [ 1 ]
  if 80 - 80: o0oOOo0O0Ooo / oO0o / Ii1I - I1IiiI % I1Ii111
  III1iII1I1ii = OoOooOOOO [ 0 ]
  o0o = OoOooOOOO [ 1 ]
  oo00O00oO = int ( OoOooOOOO [ 2 ] )
  Ii1I1iIiiI1 = OoOooOOOO [ 3 : : ]
  if 68 - 68: iII111i . I11i
  if ( len ( Ii1I1iIiiI1 ) > 1 ) :
   Ii1I1iIiiI1 = lisp . lisp_bit_stuff ( Ii1I1iIiiI1 )
  else :
   Ii1I1iIiiI1 = Ii1I1iIiiI1 [ 0 ]
   if 29 - 29: ooOoO0o * IiII
   if 75 - 75: O0
  if ( III1iII1I1ii != "control-packet" ) :
   lisp . lprint ( ( "lisp_core_control_packet_process() received" + "unexpected control-packet, message ignored" ) )
   if 56 - 56: OoO0O00 / II111iiii
   continue
   if 39 - 39: OoOoOO00 - OoooooooOO - i1IIi / II111iiii
   if 49 - 49: Oo0Ooo + O0 + IiII . II111iiii % ooOoO0o
  lisp . lprint ( ( "{} {} bytes from {}, dest/port: {}/{}, control-" + "packet: {}" ) . format ( lisp . bold ( "Receive" , False ) , len ( Ii1I1iIiiI1 ) ,
  # iIii1I11I1II1 - OoOoOO00
 oOOo0 , o0o , oo00O00oO , lisp . lisp_format_packet ( Ii1I1iIiiI1 ) ) )
  if 32 - 32: OOooOOo
  if 71 - 71: iII111i + OoO0O00 + II111iiii / IiII - Ii1I
  if 7 - 7: I1IiiI / OoO0O00 + I1Ii111 + I11i / I1IiiI
  if 82 - 82: I1ii11iIi11i + OoooooooOO
  if 21 - 21: oO0o * oO0o / I11i . iII111i
  if 10 - 10: Ii1I * OOooOOo - Oo0Ooo - OoooooooOO / o0oOOo0O0Ooo
  ooOOOo = lisp . lisp_control_header ( )
  ooOOOo . decode ( Ii1I1iIiiI1 )
  if ( ooOOOo . type == lisp . LISP_MAP_REPLY ) :
   i1I1i1i1I1 = lisp . lisp_map_reply ( )
   i1I1i1i1I1 . decode ( Ii1I1iIiiI1 )
   if ( OooO00oO ( None , 0 , i1I1i1i1I1 . nonce ) ) :
    oooO0o ( lisp_sockets , oOOo0 , oo00O00oO , Ii1I1iIiiI1 )
    continue
    if 86 - 86: I1Ii111 % I1IiiI
    if 22 - 22: i11iIiiIii * I1Ii111 . Oo0Ooo . OoooooooOO + I1IiiI
    if 24 - 24: II111iiii / Ii1I . iIii1I11I1II1 - II111iiii % O0
    if 8 - 8: OoO0O00 % iII111i . OoooooooOO - Ii1I % OoooooooOO
    if 61 - 61: o0oOOo0O0Ooo / i11iIiiIii
    if 28 - 28: OOooOOo / OoOoOO00
    if 30 - 30: ooOoO0o
    if 57 - 57: o0oOOo0O0Ooo * i11iIiiIii / OoOoOO00
  if ( ooOOOo . type == lisp . LISP_MAP_NOTIFY and oOOo0 == "lisp-etr" ) :
   O0ooo0O0oo0 = lisp . lisp_packet_ipc ( Ii1I1iIiiI1 , oOOo0 , oo00O00oO )
   lisp . lisp_ipc ( O0ooo0O0oo0 , ooo0Oo0 , "lisp-itr" )
   continue
   if 40 - 40: iIii1I11I1II1 - ooOoO0o / Oo0Ooo
   if 24 - 24: oO0o - iII111i / ooOoO0o
   if 10 - 10: OoOoOO00 * i1IIi
   if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
   if 34 - 34: I1IiiI
   if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
   if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
  Ooi1IIii11i1I1 = lisp . lisp_convert_4to6 ( o0o )
  Ooi1IIii11i1I1 = lisp . lisp_address ( lisp . LISP_AFI_IPV6 , "" , 128 , 0 )
  if ( Ooi1IIii11i1I1 . is_ipv4_string ( o0o ) ) : o0o = "::ffff:" + o0o
  Ooi1IIii11i1I1 . store_address ( o0o )
  if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
  if 98 - 98: OoO0O00
  if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  lisp . lisp_send ( lisp_sockets , Ooi1IIii11i1I1 , oo00O00oO , Ii1I1iIiiI1 )
  if 52 - 52: I1Ii111 + I1Ii111
 return
 if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
 if 54 - 54: OoOoOO00 . OoooooooOO
 if 36 - 36: oO0o / II111iiii * IiII % I1ii11iIi11i
 if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
 if 28 - 28: Ii1I . I1ii11iIi11i
 if 77 - 77: I1ii11iIi11i % II111iiii
 if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
 if 90 - 90: o0oOOo0O0Ooo
def I1I1i1I ( ) :
 Oo = open ( "./lisp.config.example" , "r" ) ; O0OOOOo0O = Oo . read ( ) ; Oo . close ( )
 Oo = open ( "./lisp.config" , "w" )
 O0OOOOo0O = O0OOOOo0O . split ( "\n" )
 for OOoO in O0OOOOo0O :
  Oo . write ( OOoO + "\n" )
  if ( OOoO [ 0 ] == "#" and OOoO [ - 1 ] == "#" and len ( OOoO ) >= 4 ) :
   IIiII = OOoO [ 1 : - 2 ]
   iII11 = len ( IIiII ) * "-"
   if ( IIiII == iII11 ) : break
   if 96 - 96: I11i * I1ii11iIi11i * Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
   if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
 Oo . close ( )
 return
 if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
 if 1 - 1: Oo0Ooo . II111iiii
 if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
 if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
 if 4 - 4: IiII
 if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
 if 99 - 99: i11iIiiIii - iII111i
 if 85 - 85: I1Ii111 % I1ii11iIi11i
def OO00o0O0oOooO ( bottle_port ) :
 global Iiii111Ii11I1
 global IiiiIiI1iIiI1
 global ooo0Oo0
 global oo
 global O0Oooo00
 global Ooo0
 if 18 - 18: i11iIiiIii * Oo0Ooo / I1ii11iIi11i + I1ii11iIi11i % OoOoOO00
 lisp . lisp_i_am ( "core" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "core-process starting up" )
 lisp . lisp_uptime = lisp . lisp_get_timestamp ( )
 lisp . lisp_version = getoutput ( "cat lisp-version.txt" )
 Iiii111Ii11I1 = getoutput ( "cat lisp-build-date.txt" )
 if 12 - 12: I11i
 if 19 - 19: Ii1I * i1IIi % O0 + I11i
 if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
 if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
 if 80 - 80: Ii1I
 if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
 if 59 - 59: I1ii11iIi11i + I11i . oO0o
 if 87 - 87: OoO0O00
 lisp . lisp_ipc_lock = multiprocessing . Lock ( )
 if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
 if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
 if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
 if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
 if 46 - 46: i11iIiiIii
 if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
 if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
 if ( os . path . exists ( "lisp.py" ) ) : lisp . lisp_version += "+"
 if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
 if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
 if 65 - 65: OoooooooOO
 if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
 if 83 - 83: ooOoO0o
 if 43 - 43: OOooOOo
 o0IiiIIII1I1i = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 if ( os . getenv ( "LISP_ANYCAST_MR" ) == None or lisp . lisp_myrlocs [ 0 ] == None ) :
  IiiiIiI1iIiI1 = lisp . lisp_open_listen_socket ( o0IiiIIII1I1i ,
 str ( lisp . LISP_CTRL_PORT ) )
 else :
  o0IiiIIII1I1i = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( )
  IiiiIiI1iIiI1 = lisp . lisp_open_listen_socket ( o0IiiIIII1I1i ,
 str ( lisp . LISP_CTRL_PORT ) )
  if 26 - 26: iII111i - Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
 lisp . lprint ( "Listen on {}, port 4342" . format ( o0IiiIIII1I1i ) )
 if 37 - 37: o0oOOo0O0Ooo * OOooOOo + I1IiiI . I1ii11iIi11i * OoooooooOO
 if 82 - 82: i11iIiiIii + iIii1I11I1II1 / Oo0Ooo + OOooOOo * II111iiii
 if 34 - 34: o0oOOo0O0Ooo % OoooooooOO
 if 36 - 36: I1IiiI
 if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
 if 64 - 64: ooOoO0o / i1IIi % iII111i
 if ( lisp . lisp_external_data_plane ( ) == False ) :
  Ooo0 = lisp . lisp_open_listen_socket ( o0IiiIIII1I1i ,
 str ( lisp . LISP_DATA_PORT ) )
  lisp . lprint ( "Listen on {}, port 4341" . format ( o0IiiIIII1I1i ) )
  if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
  if 99 - 99: I1Ii111
  if 75 - 75: ooOoO0o . OOooOOo / IiII
  if 84 - 84: OoooooooOO . I1IiiI / o0oOOo0O0Ooo
  if 86 - 86: Oo0Ooo % OoOoOO00
  if 77 - 77: Ii1I % OOooOOo / oO0o
 ooo0Oo0 = lisp . lisp_open_send_socket ( "lisp-core" , "" )
 ooo0Oo0 . settimeout ( 3 )
 if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
 if 23 - 23: I1IiiI
 if 7 - 7: iII111i % I1ii11iIi11i
 if 64 - 64: I1Ii111 + i11iIiiIii
 if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
 oo = lisp . lisp_open_listen_socket ( "" , "lisp-core-pkt" )
 if 68 - 68: IiII . ooOoO0o
 O0Oooo00 = [ IiiiIiI1iIiI1 , IiiiIiI1iIiI1 ,
 ooo0Oo0 ]
 if 64 - 64: i1IIi + Oo0Ooo * I1IiiI / OOooOOo
 if 3 - 3: Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
 if 50 - 50: iIii1I11I1II1 * oO0o
 if 85 - 85: i1IIi
 if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
 threading . Thread ( target = iI1I1ii11IIi1 ,
 args = [ oo , O0Oooo00 ] ) . start ( )
 if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
 if 54 - 54: OoOoOO00 * iII111i + OoO0O00
 if 93 - 93: o0oOOo0O0Ooo / I1IiiI
 if 47 - 47: Oo0Ooo * OOooOOo
 if 98 - 98: oO0o - oO0o . ooOoO0o
 if 60 - 60: I1IiiI * I1ii11iIi11i / O0 + I11i + IiII
 if ( os . path . exists ( "./lisp.config" ) == False ) :
  lisp . lprint ( ( "./lisp.config does not exist, creating a copy " + "from lisp.config.example" ) )
  if 66 - 66: IiII * Oo0Ooo . OoooooooOO * I1Ii111
  I1I1i1I ( )
  if 93 - 93: IiII / i1IIi
  if 47 - 47: ooOoO0o - Ii1I
  if 98 - 98: oO0o . I1Ii111 / OoOoOO00 . ooOoO0o
  if 1 - 1: OOooOOo
  if 87 - 87: O0 * II111iiii + iIii1I11I1II1 % oO0o % i11iIiiIii - OoOoOO00
  if 73 - 73: iII111i + Ii1I
 IIIiii11 ( IiiiIiI1iIiI1 )
 if 12 - 12: I1IiiI + I1Ii111
 threading . Thread ( target = lispconfig . lisp_config_process ,
 args = [ ooo0Oo0 ] ) . start ( )
 if 80 - 80: oO0o . O0
 if 90 - 90: II111iiii / OoO0O00 / Ii1I
 if 70 - 70: Ii1I - II111iiii . Oo0Ooo / Oo0Ooo
 if 30 - 30: oO0o . OoO0O00 + I11i / iIii1I11I1II1 % Oo0Ooo / oO0o
 threading . Thread ( target = O0OoOo ,
 args = [ bottle_port ] ) . start ( )
 threading . Thread ( target = OOO0 , args = [ ] ) . start ( )
 if 3 - 3: I1ii11iIi11i / II111iiii
 if 73 - 73: OoO0O00 * OoooooooOO - OoooooooOO + I1IiiI * Oo0Ooo
 if 87 - 87: o0oOOo0O0Ooo / IiII / i11iIiiIii
 if 95 - 95: i1IIi / Ii1I / Ii1I
 threading . Thread ( target = Oo00oo0 ,
 args = [ ooo0Oo0 ] ) . start ( )
 if 65 - 65: I1Ii111 + iII111i * iII111i
 if 79 - 79: i1IIi / Oo0Ooo - I1IiiI . O0
 if 56 - 56: IiII % O0 * i1IIi - II111iiii
 if 74 - 74: i1IIi - OoOoOO00 % oO0o . O0 - OoooooooOO
 threading . Thread ( target = o0oOOO ) . start ( )
 return ( True )
 if 84 - 84: I1Ii111
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
 if 9 - 9: i1IIi - OoOoOO00
 if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
 if 46 - 46: Ii1I
 if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
def oOoO0o0Ooo ( ) :
 if 44 - 44: OoO0O00 * oO0o
 if 54 - 54: Ii1I % i1IIi
 if 51 - 51: iIii1I11I1II1 - I1IiiI
 if 61 - 61: OoooooooOO . Ii1I % oO0o * OoooooooOO
 lisp . lisp_close_socket ( ooo0Oo0 , "lisp-core" )
 lisp . lisp_close_socket ( oo , "lisp-core-pkt" )
 lisp . lisp_close_socket ( IiiiIiI1iIiI1 , "" )
 lisp . lisp_close_socket ( Ooo0 , "" )
 return
 if 96 - 96: Ii1I - II111iiii % OoOoOO00 * I1IiiI * I1IiiI . Oo0Ooo
 if 75 - 75: Oo0Ooo + Ii1I + OoO0O00
 if 97 - 97: ooOoO0o % i11iIiiIii % I11i
 if 21 - 21: Oo0Ooo / Ii1I / I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 if 86 - 86: i1IIi
 if 33 - 33: OoOoOO00 % i11iIiiIii * OOooOOo
 if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
 if 75 - 75: OoO0O00 % OoooooooOO
 if 16 - 16: O0 / i1IIi
 if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
 if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
 if 12 - 12: OoOoOO00 + o0oOOo0O0Ooo . I1Ii111
def IIIiii11 ( lisp_socket ) :
 if 52 - 52: OoO0O00
 Oo = open ( "./lisp.config" , "r" ) ; O0OOOOo0O = Oo . read ( ) ; Oo . close ( )
 O0OOOOo0O = O0OOOOo0O . split ( "\n" )
 if 4 - 4: Ii1I % I1ii11iIi11i + I11i - I1ii11iIi11i
 if 98 - 98: Ii1I - O0 * oO0o * Ii1I * Ii1I
 if 44 - 44: IiII + I11i
 if 66 - 66: oO0o
 if 34 - 34: iII111i % i11iIiiIii + i11iIiiIii - iII111i
 iii1iII = False
 for OOoO in O0OOOOo0O :
  if ( OOoO [ 0 : 1 ] == "#-" and OOoO [ - 2 : - 1 ] == "-#" ) : break
  if ( OOoO == "" or OOoO [ 0 ] == "#" ) : continue
  if ( OOoO . find ( "decentralized-push-xtr = yes" ) == - 1 ) : continue
  iii1iII = True
  break
  if 77 - 77: IiII + OoooooooOO * i1IIi % OoooooooOO
 if ( iii1iII == False ) : return
 if 3 - 3: Ii1I * ooOoO0o - I1IiiI / i1IIi
 if 21 - 21: II111iiii + I1Ii111
 if 22 - 22: IiII . iII111i + Oo0Ooo
 if 45 - 45: Oo0Ooo % Oo0Ooo + Oo0Ooo / O0 % OoooooooOO
 if 92 - 92: Ii1I . OoOoOO00 . I11i - OoooooooOO / ooOoO0o
 ooOo0 = [ ]
 I11I1i = False
 for OOoO in O0OOOOo0O :
  if ( OOoO [ 0 : 1 ] == "#-" and OOoO [ - 2 : - 1 ] == "-#" ) : break
  if ( OOoO == "" or OOoO [ 0 ] == "#" ) : continue
  if 100 - 100: oO0o
  if ( OOoO . find ( "lisp map-server" ) != - 1 ) :
   I11I1i = True
   continue
   if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
  if ( OOoO [ 0 ] == "}" ) :
   I11I1i = False
   continue
   if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
   if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
   if 75 - 75: IiII / OoooooooOO . I1IiiI + I1Ii111 - II111iiii
   if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
   if 16 - 16: IiII
  if ( I11I1i and OOoO . find ( "address = " ) != - 1 ) :
   II1 = OOoO . split ( "address = " ) [ 1 ]
   OOOiiIII1I11iii = int ( II1 . split ( "." ) [ 0 ] )
   if ( OOOiiIII1I11iii >= 224 and OOOiiIII1I11iii < 240 ) : ooOo0 . append ( II1 )
   if 95 - 95: O0 . OoO0O00
   if 89 - 89: i1IIi
 if ( II1 == [ ] ) : return
 if 19 - 19: ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
 if 14 - 14: I1ii11iIi11i - i11iIiiIii * I1Ii111
 if 39 - 39: OoooooooOO
 if 19 - 19: i11iIiiIii
 Ii1IIi = getoutput ( 'ifconfig eth0 | egrep "inet "' )
 if ( Ii1IIi == "" ) : return
 oOOOO = Ii1IIi . split ( ) [ 1 ]
 if 82 - 82: i1IIi + o0oOOo0O0Ooo - II111iiii . Ii1I
 if 93 - 93: II111iiii * OoOoOO00 % o0oOOo0O0Ooo
 if 67 - 67: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o - i1IIi . OoOoOO00
 if 12 - 12: IiII / OoO0O00 / O0 * IiII
 i1i111iI = socket . inet_aton ( oOOOO )
 for II1 in ooOo0 :
  lisp_socket . setsockopt ( socket . SOL_SOCKET , socket . SO_REUSEADDR , 1 )
  lisp_socket . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_IF , i1i111iI )
  o0o0oo0OOo0O0 = socket . inet_aton ( II1 ) + i1i111iI
  lisp_socket . setsockopt ( socket . IPPROTO_IP , socket . IP_ADD_MEMBERSHIP , o0o0oo0OOo0O0 )
  lisp . lprint ( "Setting multicast listen socket for group {}" . format ( II1 ) )
  if 37 - 37: o0oOOo0O0Ooo * Oo0Ooo
  if 11 - 11: oO0o
 return
 if 62 - 62: OoooooooOO % oO0o * II111iiii * I1Ii111 * I1Ii111 / ooOoO0o
 if 90 - 90: I1Ii111 . II111iiii . I1ii11iIi11i
 if 32 - 32: ooOoO0o - OoO0O00 . iII111i . iII111i % i1IIi * Ii1I
 if 65 - 65: iII111i / ooOoO0o . II111iiii
o0oO00oooo = int ( sys . argv [ 1 ] ) if ( len ( sys . argv ) > 1 ) else 8080
if 63 - 63: II111iiii - I11i . OoOoOO00
if 8 - 8: I1IiiI * ooOoO0o / IiII + OoOoOO00 . IiII - OOooOOo
if 80 - 80: iIii1I11I1II1 / oO0o * Oo0Ooo - OOooOOo * iII111i
if 97 - 97: IiII - I11i / II111iiii
if ( OO00o0O0oOooO ( o0oO00oooo ) == False ) :
 lisp . lprint ( "lisp_core_startup() failed" )
 lisp . lisp_print_banner ( "lisp-core abnormal exit" )
 exit ( 1 )
 if 26 - 26: iII111i + O0 * iII111i . i1IIi
 if 50 - 50: iIii1I11I1II1 - I11i % iII111i - Oo0Ooo
while ( True ) :
 if 52 - 52: oO0o + Ii1I - I1ii11iIi11i * Ii1I . OOooOOo + I1Ii111
 if 43 - 43: I1IiiI % IiII % I1ii11iIi11i
 if 53 - 53: oO0o % OOooOOo % I1ii11iIi11i . I1Ii111 . I1Ii111 . iII111i
 if 73 - 73: iII111i / ooOoO0o + OoO0O00 / OoOoOO00 . II111iiii * Ii1I
 if 21 - 21: I1IiiI - I1IiiI + iII111i % I1IiiI * oO0o
 III1iII1I1ii , oOOo0 , oo00O00oO , Ii1I1iIiiI1 = lisp . lisp_receive ( IiiiIiI1iIiI1 , False )
 if 74 - 74: iII111i / I11i . I1IiiI - OoooooooOO + II111iiii + I11i
 if ( oOOo0 == "" ) : break
 if 36 - 36: Ii1I * I1IiiI * I1ii11iIi11i . I11i * I1ii11iIi11i
 if 76 - 76: OOooOOo + O0 / IiII - OoO0O00
 if 27 - 27: Oo0Ooo - iIii1I11I1II1 * iII111i * II111iiii * I1ii11iIi11i
 if 9 - 9: i11iIiiIii + OOooOOo - OoOoOO00 / ooOoO0o % i1IIi / oO0o
 oOOo0 = lisp . lisp_convert_6to4 ( oOOo0 )
 oooO0o ( O0Oooo00 , oOOo0 , oo00O00oO , Ii1I1iIiiI1 )
 if 22 - 22: i1IIi
 if 3 - 3: OoO0O00 * I1ii11iIi11i - iII111i + I1ii11iIi11i
oOoO0o0Ooo ( )
lisp . lisp_print_banner ( "lisp-core normal exit" )
exit ( 0 )
if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
if 96 - 96: IiII
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
