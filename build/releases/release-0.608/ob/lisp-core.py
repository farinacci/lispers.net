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
from cheroot . wsgi import Server as wsgi_server
from cheroot . ssl . builtin import BuiltinSSLAdapter as ssl_adaptor
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
if 94 - 94: i1IIi % Oo0Ooo
o0oO0 = ""
if 100 - 100: i1IIi
I1Ii11I1Ii1i = None
Ooo = None
o0oOoO00o = None
i1 = [ None , None , None ]
oOOoo00O0O = None
if 15 - 15: I1IiiI
if 90 - 90: IiII * i1IIi / Ii1I . OoO0O00 * oO0o
if 16 - 16: ooOoO0o * IiII % I11i . I1Ii111 / IiII % iII111i
if 27 - 27: IiII . i1IIi * OoOoOO00 % Ii1I / i1IIi
if 3 - 3: IiII / ooOoO0o
if 28 - 28: ooOoO0o + I1Ii111 - ooOoO0o . OoooooooOO
if 97 - 97: OoO0O00 . I11i
if 32 - 32: Oo0Ooo - II111iiii - i11iIiiIii % I1Ii111
@ bottle . route ( '/lisp/api' , method = "get" )
@ bottle . route ( '/lisp/api/<command>' , method = "get" )
@ bottle . route ( '/lisp/api/<command>/<data_structure>' , method = "get" )
def O0OoOoo00o ( command = "" , data_structure = "" ) :
 iiiI11 = [ { "?" : [ { "?" : "not-auth" } ] } ]
 if 91 - 91: o0oOOo0O0Ooo / II111iiii . I1ii11iIi11i + OOooOOo
 if 47 - 47: OoOoOO00 / Ii1I * OoooooooOO
 if 9 - 9: I1IiiI - Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 if ( bottle . request . auth != None ) :
  I1Ii , o0oOo0Ooo0O = bottle . request . auth
  if ( lispconfig . lisp_find_user_account ( I1Ii , o0oOo0Ooo0O ) == False ) :
   return ( json . dumps ( iiiI11 ) )
   if 81 - 81: I1ii11iIi11i * IiII * I11i - iII111i - o0oOOo0O0Ooo
 else :
  if ( bottle . request . headers [ "User-Agent" ] . find ( "python" ) != - 1 ) :
   return ( json . dumps ( iiiI11 ) )
   if 90 - 90: II111iiii + oO0o / o0oOOo0O0Ooo % II111iiii - O0
  if ( lispconfig . lisp_validate_user ( ) == False ) :
   return ( json . dumps ( iiiI11 ) )
   if 29 - 29: o0oOOo0O0Ooo / iIii1I11I1II1
   if 24 - 24: O0 % o0oOOo0O0Ooo + i1IIi + I1Ii111 + I1ii11iIi11i
   if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
   if 23 - 23: i11iIiiIii + I1IiiI
   if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
   if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
   if 33 - 33: Ii1I + II111iiii % i11iIiiIii . ooOoO0o - I1IiiI
 if ( command == "data" and data_structure != "" ) :
  O00oooo0O = bottle . request . body . readline ( )
  if ( type ( O00oooo0O ) == bytes ) : O00oooo0O = O00oooo0O . decode ( )
  iiiI11 = json . loads ( O00oooo0O ) if O00oooo0O != "" else ""
  if ( iiiI11 != "" ) : iiiI11 = list ( iiiI11 . values ( ) ) [ 0 ]
  if ( iiiI11 == [ ] ) : iiiI11 = ""
  if 22 - 22: OoooooooOO % I11i - iII111i . iIii1I11I1II1 * i11iIiiIii
  if ( type ( iiiI11 ) == dict and type ( list ( iiiI11 . values ( ) ) [ 0 ] ) == dict ) :
   iiiI11 = list ( iiiI11 . values ( ) ) [ 0 ]
   if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
   if 61 - 61: ooOoO0o
  iiiI11 = oOOO00o ( data_structure , iiiI11 )
  return ( iiiI11 )
  if 97 - 97: I11i % I11i + II111iiii * iII111i
  if 54 - 54: I11i + IiII / iII111i
  if 9 - 9: OoOoOO00 / Oo0Ooo - IiII . i1IIi / I1IiiI % IiII
  if 71 - 71: I1Ii111 . O0
  if 73 - 73: OOooOOo % OoOoOO00 - Ii1I
 if ( command != "" ) :
  command = "lisp " + command
 else :
  O00oooo0O = bottle . request . body . readline ( )
  if ( type ( O00oooo0O ) == bytes ) : O00oooo0O = O00oooo0O . decode ( )
  if ( O00oooo0O == "" ) :
   iiiI11 = [ { "?" : [ { "?" : "no-body" } ] } ]
   return ( json . dumps ( iiiI11 ) )
   if 10 - 10: I1IiiI % I1ii11iIi11i
   if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
  iiiI11 = json . loads ( O00oooo0O )
  command = list ( iiiI11 . keys ( ) ) [ 0 ]
  if 20 - 20: o0oOOo0O0Ooo
  if 77 - 77: OoOoOO00 / I11i
 iiiI11 = lispconfig . lisp_get_clause_for_api ( command )
 return ( json . dumps ( iiiI11 ) )
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
 if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % oO0o . O0
 if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
 if 53 - 53: IiII + I1IiiI * oO0o
 if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
 if 60 - 60: I11i / I11i
def I1II1III11iii ( ) :
 iiiI11 = { }
 iiiI11 [ "hostname" ] = socket . gethostname ( )
 iiiI11 [ "system-uptime" ] = getoutput ( "uptime" )
 iiiI11 [ "lisp-uptime" ] = lisp . lisp_print_elapsed ( lisp . lisp_uptime )
 iiiI11 [ "lisp-version" ] = lisp . lisp_version
 if 75 - 75: iIii1I11I1II1 / OOooOOo % o0oOOo0O0Ooo * OoOoOO00
 iiii11I = "yes" if os . path . exists ( "./logs/lisp-traceback.log" ) else "no"
 iiiI11 [ "traceback-log" ] = iiii11I
 if 96 - 96: II111iiii % Ii1I . OOooOOo + OoooooooOO * oO0o - OoOoOO00
 i11i1 = lisp . lisp_myrlocs [ 0 ]
 IIIii1II1II = lisp . lisp_myrlocs [ 1 ]
 i11i1 = "none" if ( i11i1 == None ) else i11i1 . print_address_no_iid ( )
 IIIii1II1II = "none" if ( IIIii1II1II == None ) else IIIii1II1II . print_address_no_iid ( )
 iiiI11 [ "lisp-rlocs" ] = [ i11i1 , IIIii1II1II ]
 return ( json . dumps ( iiiI11 ) )
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
   lisp . lisp_ipc ( O0ooo0O0oo0 , Ooo , "lisp-rtr" )
  elif ( lisp . lisp_is_running ( "lisp-itr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , Ooo , "lisp-itr" )
  else :
   return ( json . dumps ( [ ] ) )
   if 31 - 31: IiII . OoOoOO00 . OOooOOo
   if 75 - 75: I11i + OoO0O00 . OoOoOO00 . ooOoO0o + Oo0Ooo . OoO0O00
 if ( data_structure in [ "map-server" , "database-mapping" ] ) :
  if ( lisp . lisp_is_running ( "lisp-etr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , Ooo , "lisp-etr" )
  elif ( lisp . lisp_is_running ( "lisp-itr" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , Ooo , "lisp-itr" )
  else :
   return ( json . dumps ( [ ] ) )
   if 96 - 96: OOooOOo . ooOoO0o - Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * OOooOOo
   if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
 if ( data_structure in [ "site-cache" , "site-cache-summary" ] ) :
  if ( lisp . lisp_is_running ( "lisp-ms" ) ) :
   lisp . lisp_ipc_lock . acquire ( )
   lisp . lisp_ipc ( O0ooo0O0oo0 , Ooo , "lisp-ms" )
  else :
   return ( json . dumps ( [ ] ) )
   if 21 - 21: I1IiiI * iIii1I11I1II1
   if 91 - 91: IiII
   if 15 - 15: II111iiii
 lisp . lprint ( "Waiting for api get-data '{}', parmameters: '{}'" . format ( data_structure , data ) )
 if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
 if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
 III1iII1I1ii , oOOo0 , oo00O00oO , iIiIIIi = lisp . lisp_receive ( Ooo , True )
 lisp . lisp_ipc_lock . release ( )
 iIiIIIi = iIiIIIi . decode ( )
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
 iiiI11 = [ { "?" : [ { "?" : "not-auth" } ] } ]
 if ( bottle . request . auth == None ) : return ( iiiI11 )
 if 75 - 75: I1IiiI + Oo0Ooo
 if 73 - 73: O0 - OoooooooOO . OOooOOo - OOooOOo / OoOoOO00
 if 45 - 45: iIii1I11I1II1 % OoO0O00
 if 29 - 29: OOooOOo + Oo0Ooo . i11iIiiIii - i1IIi / iIii1I11I1II1
 if ( bottle . request . auth != None ) :
  I1Ii , o0oOo0Ooo0O = bottle . request . auth
  if ( lispconfig . lisp_find_user_account ( I1Ii , o0oOo0Ooo0O ) == False ) :
   return ( json . dumps ( iiiI11 ) )
   if 26 - 26: I11i . OoooooooOO
 else :
  if ( bottle . request . headers [ "User-Agent" ] . find ( "python" ) != - 1 ) :
   return ( json . dumps ( iiiI11 ) )
   if 39 - 39: iII111i - O0 % i11iIiiIii * I1Ii111 . IiII
  if ( lispconfig . lisp_validate_user ( ) == False ) :
   return ( json . dumps ( iiiI11 ) )
   if 58 - 58: OoO0O00 % i11iIiiIii . iII111i / oO0o
   if 84 - 84: iII111i . I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
   if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
   if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
   if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
   if 51 - 51: O0 + iII111i
   if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if ( command == "user-account" ) :
  if ( lispconfig . lisp_is_user_superuser ( I1Ii ) == False ) :
   iiiI11 = [ { "user-account" : [ { "?" : "not-auth" } ] } ]
   return ( json . dumps ( iiiI11 ) )
   if 48 - 48: O0
   if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
   if 41 - 41: Ii1I - O0 - O0
   if 68 - 68: OOooOOo % I1Ii111
   if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
   if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 O00oooo0O = bottle . request . body . readline ( )
 if ( type ( O00oooo0O ) == bytes ) : O00oooo0O = O00oooo0O . decode ( )
 if ( O00oooo0O == "" ) :
  iiiI11 = [ { "?" : [ { "?" : "no-body" } ] } ]
  return ( json . dumps ( iiiI11 ) )
  if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
  if 23 - 23: O0
 iiiI11 = json . loads ( O00oooo0O )
 if ( command != "" ) :
  command = "lisp " + command
 else :
  command = list ( iiiI11 [ 0 ] . keys ( ) ) [ 0 ]
  if 85 - 85: Ii1I
  if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
  if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
  if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
  if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
  if 77 - 77: iIii1I11I1II1 * OoO0O00
 lisp . lisp_ipc_lock . acquire ( )
 if ( bottle . request . method == "DELETE" ) :
  iiiI11 = lispconfig . lisp_remove_clause_for_api ( iiiI11 )
 else :
  iiiI11 = lispconfig . lisp_put_clause_for_api ( iiiI11 )
  if 95 - 95: I1IiiI + i11iIiiIii
 lisp . lisp_ipc_lock . release ( )
 return ( json . dumps ( iiiI11 ) )
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
 return ( bottle . static_file ( "lisp-config-commands.txt" , root = "./" ,
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
 return ( lispconfig . lisp_process_show_command ( Ooo , Oo0O0 ) )
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
 i1OO0oOOoo = getoutput ( "uname -pv" )
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
 ooo0O = "ps auww" if lisp . lisp_is_macos ( ) else "ps aux"
 iII1iii = "egrep 'PID|python lisp|python -O lisp|python3.8 -O lisp'"
 iII1iii += "| egrep -v grep"
 i11i1iiiII = getoutput ( "{} | {}" . format ( ooo0O , iII1iii ) )
 i11i1iiiII = i11i1iiiII . replace ( " " , lisp . space ( 1 ) )
 i11i1iiiII = i11i1iiiII . replace ( "\n" , "<br>" )
 if 68 - 68: i11iIiiIii * OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if ( i1OO0oOOoo . find ( "Darwin" ) != - 1 ) :
  ii11I1 = old_div ( ii11I1 , 2 )
  iI11 = getoutput ( "top -l 1 | head -50" )
  iI11 = iI11 . split ( "PID" )
  iI11 = iI11 [ 0 ]
  if 83 - 83: OoOoOO00 . OoooooooOO
  if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
  if 62 - 62: OoO0O00 / I1ii11iIi11i
  if 7 - 7: OoooooooOO . IiII
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
  Ii111iIi1iIi = iI11 . find ( "Load Avg" )
  Oooo00 = iI11 [ 0 : Ii111iIi1iIi ] . find ( "threads" )
  I111iIi1 = iI11 [ 0 : Oooo00 + 7 ]
  iI11 = I111iIi1 + "<br>" + iI11 [ Ii111iIi1iIi : : ]
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
  O0OOOOo0O = getoutput ( "top -b -n 1 | head -50" )
  O0OOOOo0O = O0OOOOo0O . split ( "PID" )
  O0OOOOo0O [ 1 ] = O0OOOOo0O [ 1 ] . replace ( " " , lisp . space ( 1 ) )
  O0OOOOo0O = O0OOOOo0O [ 0 ] + O0OOOOo0O [ 1 ]
  iI11 = O0OOOOo0O . replace ( "\n" , "<br>" )
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
        ''' . format ( oOOO00o000o , lisp . lisp_version , o0oO0 , IIIII ,
 O00o0OO0000oo , lisp . lisp_space ( 1 ) , ii11I1 , i1OO0oOOoo , i11i1iiiII , iI11 ,
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
 oo00O00oO = Oo0oOooo000OO ( )
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
 i11i1iiiII = os . system ( oO0O )
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
 "succeeded" if ( i11i1iiiII == 0 ) else "failed" )
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
def Ii ( name = "" , num = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 99 - 99: OoO0O00 * i11iIiiIii . OoooooooOO % Oo0Ooo
  if 76 - 76: O0 . I1Ii111 * iII111i * OOooOOo . OoOoOO00 . i11iIiiIii
  if 21 - 21: o0oOOo0O0Ooo / OoOoOO00 / iIii1I11I1II1 % OOooOOo
  if 2 - 2: i11iIiiIii - II111iiii / oO0o % O0
  if 66 - 66: Oo0Ooo
 if ( num == "" ) : num = 100
 if 28 - 28: IiII - IiII . i1IIi - ooOoO0o + I1IiiI . IiII
 oO0ooOOO = '''
        <form action="/lisp/search/log/{}/{}" method="post">
        <i>Keyword search:</i>
        <input type="text" name="keyword" />
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </form><hr>
    ''' . format ( name , num )
 if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
 if ( os . path . exists ( "logs/{}.log" . format ( name ) ) ) :
  iIiIIIi = getoutput ( "tail -n {} logs/{}.log" . format ( num , name ) )
  iIiIIIi = lisp . convert_font ( iIiIIIi )
  iIiIIIi = iIiIIIi . replace ( "\n" , "<br>" )
  iIiIIIi = oO0ooOOO + lisp . lisp_print_cour ( iIiIIIi )
 else :
  O00oOoo0OoO0 = lisp . lisp_print_sans ( "File" )
  Ooo0 = lisp . lisp_print_cour ( "logs/{}.log" . format ( name ) )
  oooO00o0 = lisp . lisp_print_sans ( "does not exist" )
  iIiIIIi = "{} {} {}" . format ( O00oOoo0OoO0 , Ooo0 , oooO00o0 )
  if 53 - 53: ooOoO0o
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 98 - 98: I1Ii111
 if 92 - 92: I1Ii111 - iIii1I11I1II1
 if 32 - 32: Ii1I % OoO0O00 * OoO0O00 + IiII * II111iiii * Ii1I
 if 11 - 11: oO0o % II111iiii
 if 57 - 57: OOooOOo / Oo0Ooo
 if 69 - 69: oO0o - Oo0Ooo % IiII
 if 50 - 50: OoooooooOO
@ bottle . route ( '/lisp/debug/<name>' )
def IiI1i111IiIiIi1 ( name = "" ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 39 - 39: I11i - I1ii11iIi11i
  if 53 - 53: o0oOOo0O0Ooo % iII111i + ooOoO0o . Oo0Ooo - I1ii11iIi11i % o0oOOo0O0Ooo
  if 64 - 64: II111iiii
  if 40 - 40: OoOoOO00 % OoO0O00
  if 62 - 62: o0oOOo0O0Ooo
 if ( name == "disable%all" ) :
  iiiI11 = lispconfig . lisp_get_clause_for_api ( "lisp debug" )
  if ( "lisp debug" in iiiI11 [ 0 ] ) :
   oooOo0OOOoo0 = [ ]
   for I1i111i in iiiI11 [ 0 ] [ "lisp debug" ] :
    iI1i = list ( I1i111i . keys ( ) ) [ 0 ]
    oooOo0OOOoo0 . append ( { iI1i : "no" } )
    if 46 - 46: I1Ii111 % Ii1I
   oooOo0OOOoo0 = { "lisp debug" : oooOo0OOOoo0 }
   lispconfig . lisp_put_clause_for_api ( oooOo0OOOoo0 )
   if 72 - 72: iIii1I11I1II1
   if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  iiiI11 = lispconfig . lisp_get_clause_for_api ( "lisp xtr-parameters" )
  if ( "lisp xtr-parameters" in iiiI11 [ 0 ] ) :
   oooOo0OOOoo0 = [ ]
   for I1i111i in iiiI11 [ 0 ] [ "lisp xtr-parameters" ] :
    iI1i = list ( I1i111i . keys ( ) ) [ 0 ]
    if ( iI1i in [ "data-plane-logging" , "flow-logging" ] ) :
     oooOo0OOOoo0 . append ( { iI1i : "no" } )
    else :
     oooOo0OOOoo0 . append ( { iI1i : I1i111i [ iI1i ] } )
     if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
     if 87 - 87: OoO0O00 % I1IiiI
   oooOo0OOOoo0 = { "lisp xtr-parameters" : oooOo0OOOoo0 }
   lispconfig . lisp_put_clause_for_api ( oooOo0OOOoo0 )
   if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
   if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
  return ( lispconfig . lisp_landing_page ( ) )
  if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
  if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
  if 84 - 84: i11iIiiIii * OoO0O00
  if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
  if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 name = name . split ( "%" )
 III1I = name [ 0 ]
 iiii11I = name [ 1 ]
 if 11 - 11: ooOoO0o - OOooOOo + ooOoO0o * oO0o / I1IiiI
 OoOOOO = [ "data-plane-logging" , "flow-logging" ]
 if 18 - 18: ooOoO0o % i11iIiiIii . iIii1I11I1II1 - iII111i
 OOOOoo = "lisp xtr-parameters" if ( III1I in OoOOOO ) else "lisp debug"
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
 iiiI11 = lispconfig . lisp_get_clause_for_api ( OOOOoo )
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if ( OOOOoo in iiiI11 [ 0 ] ) :
  oooOo0OOOoo0 = { }
  for I1i111i in iiiI11 [ 0 ] [ OOOOoo ] :
   oooOo0OOOoo0 [ list ( I1i111i . keys ( ) ) [ 0 ] ] = list ( I1i111i . values ( ) ) [ 0 ]
   if ( III1I in oooOo0OOOoo0 ) : oooOo0OOOoo0 [ III1I ] = iiii11I
   if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
  oooOo0OOOoo0 = { OOOOoo : oooOo0OOOoo0 }
  lispconfig . lisp_put_clause_for_api ( oooOo0OOOoo0 )
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 return ( lispconfig . lisp_landing_page ( ) )
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
@ bottle . route ( '/lisp/clear/<name>' )
@ bottle . route ( '/lisp/clear/etr/<etr_name>/<stats_name>' )
@ bottle . route ( '/lisp/clear/rtr/<rtr_name>/<stats_name>' )
@ bottle . route ( '/lisp/clear/itr/<itr_name>' )
@ bottle . route ( '/lisp/clear/rtr/<rtr_name>' )
def iiIIi ( name = "" , itr_name = '' , rtr_name = "" , etr_name = "" ,
 stats_name = "" ) :
 if 36 - 36: I11i . II111iiii
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 25 - 25: oO0o
  if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
  if 43 - 43: I1ii11iIi11i - iII111i
  if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
  if 47 - 47: iII111i
 if ( lispconfig . lisp_is_user_superuser ( None ) == False ) :
  iIiIIIi = lisp . lisp_print_sans ( "Not authorized" )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
  if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 O0ooo0O0oo0 = "clear"
 if ( name == "referral" ) :
  iIii11iI1II = "lisp-mr"
  I1II1I1I = "Referral"
 elif ( itr_name == "map-cache" ) :
  iIii11iI1II = "lisp-itr"
  I1II1I1I = "ITR <a href='/lisp/show/itr/map-cache'>map-cache</a>"
 elif ( rtr_name == "map-cache" ) :
  iIii11iI1II = "lisp-rtr"
  I1II1I1I = "RTR <a href='/lisp/show/rtr/map-cache'>map-cache</a>"
 elif ( etr_name == "stats" ) :
  iIii11iI1II = "lisp-etr"
  I1II1I1I = ( "ETR '{}' decapsulation <a href='/lisp/show/" + "database'>stats</a>" ) . format ( stats_name )
  if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
  O0ooo0O0oo0 += "%" + stats_name
 elif ( rtr_name == "stats" ) :
  iIii11iI1II = "lisp-rtr"
  I1II1I1I = ( "RTR '{}' decapsulation <a href='/lisp/show/" + "rtr/map-cache'>stats</a>" ) . format ( stats_name )
  if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
  O0ooo0O0oo0 += "%" + stats_name
 else :
  iIiIIIi = lisp . lisp_print_sans ( "Invalid command" )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 38 - 38: O0 - IiII % I1Ii111
  if 64 - 64: iIii1I11I1II1
  if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
  if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
  if 6 - 6: Oo0Ooo % IiII * I11i / I1IiiI + Oo0Ooo
 O0ooo0O0oo0 = lisp . lisp_command_ipc ( O0ooo0O0oo0 , "lisp-core" )
 lisp . lisp_ipc ( O0ooo0O0oo0 , Ooo , iIii11iI1II )
 if 39 - 39: OoOoOO00 - Oo0Ooo / iII111i * OoooooooOO
 if 100 - 100: O0 . I11i . OoO0O00 + O0 * oO0o
 if 42 - 42: oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 III1I1 = getoutput ( "egrep 'lisp map-cache' ./lisp.config" )
 if ( III1I1 != "" ) :
  os . system ( "touch ./lisp.config" )
  if 12 - 12: iIii1I11I1II1 % ooOoO0o % ooOoO0o
  if 78 - 78: IiII . OoOoOO00 . I11i
 iIiIIIi = lisp . lisp_print_sans ( "{} cleared" . format ( I1II1I1I ) )
 return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
 if 97 - 97: oO0o
 if 80 - 80: I1IiiI . Ii1I
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
@ bottle . route ( '/lisp/show/map-server' )
def o0o0O00 ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 35 - 35: iIii1I11I1II1
  if 94 - 94: OoOoOO00
 return ( lispconfig . lisp_process_show_command ( Ooo ,
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
 return ( lispconfig . lisp_process_show_command ( Ooo ,
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
 return ( lispconfig . lisp_process_show_command ( Ooo ,
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
 return ( lispconfig . lisp_process_show_command ( Ooo ,
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
 Oo0O0 = "show itr-map-cache" + "%" + oo0O0o
 return ( lispconfig . lisp_process_show_command ( Ooo ,
 Oo0O0 ) )
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
  return ( lispconfig . lisp_process_show_command ( Ooo ,
 "show rtr-map-cache-dns" ) )
 else :
  return ( lispconfig . lisp_process_show_command ( Ooo ,
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
 return ( lispconfig . lisp_process_show_command ( Ooo ,
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
 Oo0O0 = "show rtr-map-cache" + "%" + oo0O0o
 return ( lispconfig . lisp_process_show_command ( Ooo ,
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
  return ( OOoO0 ( ) )
  if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 return ( lispconfig . lisp_process_show_command ( Ooo ,
 "show referral-cache" ) )
 if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
 if 71 - 71: iII111i
 if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
 if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
 if 58 - 58: I1ii11iIi11i
 if 2 - 2: II111iiii / I1Ii111
@ bottle . post ( '/lisp/show/referral/lookup' )
def OoO ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 71 - 71: OoO0O00 - OoooooooOO * Oo0Ooo
  if 38 - 38: iIii1I11I1II1 / ooOoO0o
 oo0O0o = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oo0O0o ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( oo0O0o )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 13 - 13: iIii1I11I1II1
  if 77 - 77: i11iIiiIii - iIii1I11I1II1 / oO0o / ooOoO0o / OoO0O00
 Oo0O0 = "show referral-cache" + "%" + oo0O0o
 return ( lispconfig . lisp_process_show_command ( Ooo , Oo0O0 ) )
 if 56 - 56: OoooooooOO * O0
 if 85 - 85: OoooooooOO % OoOoOO00 * iIii1I11I1II1
 if 44 - 44: iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
@ bottle . route ( '/lisp/show/delegations' )
def ooo000oOO ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 27 - 27: o0oOOo0O0Ooo * i11iIiiIii * OoO0O00
 return ( lispconfig . lisp_process_show_command ( Ooo ,
 "show delegations" ) )
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
@ bottle . post ( '/lisp/show/delegations/lookup' )
def O0O ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 51 - 51: oO0o + OoO0O00 + iII111i + iII111i % o0oOOo0O0Ooo
  if 29 - 29: ooOoO0o
 oo0O0o = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oo0O0o ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( oo0O0o )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 41 - 41: O0 % iII111i
  if 10 - 10: iII111i . i1IIi + Ii1I
 Oo0O0 = "show delegations" + "%" + oo0O0o
 return ( lispconfig . lisp_process_show_command ( Ooo , Oo0O0 ) )
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
 return ( lispconfig . lisp_process_show_command ( Ooo , Oo0O0 ) )
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
 return ( lispconfig . lisp_process_show_command ( Ooo , Oo0O0 ) )
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
 return ( lispconfig . lisp_process_show_command ( Ooo , Oo0O0 ) )
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
 oo0O0o = bottle . request . forms . get ( "eid" )
 if ( lispconfig . lisp_validate_input_address_string ( oo0O0o ) == False ) :
  iIiIIIi = "Address '{}' has invalid format" . format ( oo0O0o )
  iIiIIIi = lisp . lisp_print_sans ( iIiIIIi )
  return ( lispconfig . lisp_show_wrapper ( iIiIIIi ) )
  if 69 - 69: OoOoOO00
  if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 Oo0O0 = "show site" + "%" + oo0O0o + "@lookup"
 return ( lispconfig . lisp_process_show_command ( Ooo , Oo0O0 ) )
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
  return ( OOoO0 ( ) )
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
  iIiIIIi = "Need to supply EID address"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 34 - 34: iII111i
  if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 iIIi1Ii1III = ""
 if os . path . exists ( "lisp-lig.pyo" ) : iIIi1Ii1III = "python -O lisp-lig.pyo"
 if os . path . exists ( "lisp-lig.pyc" ) : iIIi1Ii1III = "python3.8 -O lisp-lig.pyc"
 if os . path . exists ( "lisp-lig.py" ) : iIIi1Ii1III = "python lisp-lig.py"
 if 86 - 86: i11iIiiIii + i11iIiiIii . I1Ii111 % I1IiiI . ooOoO0o
 if 17 - 17: Ii1I
 if 67 - 67: O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if ( iIIi1Ii1III == "" ) :
  iIiIIIi = "Cannot find lisp-lig.py or lisp-lig.pyo"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 45 - 45: Ii1I - OOooOOo
  if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if ( OO0OOoo0OOO != "" ) : OO0OOoo0OOO = "count {}" . format ( OO0OOoo0OOO )
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 Oo0O0 = '{} "{}" to {} {} {}' . format ( iIIi1Ii1III , O0OoO0o , I111IIiIII , OO0OOoo0OOO , ooooOoo0OO )
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 iIiIIIi = getoutput ( Oo0O0 )
 iIiIIIi = iIiIIIi . replace ( "\n" , "<br>" )
 iIiIIIi = lisp . convert_font ( iIiIIIi )
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 i111IiiI1Ii = lisp . space ( 2 ) + "RLOC:"
 iIiIIIi = iIiIIIi . replace ( "RLOC:" , i111IiiI1Ii )
 OooOOOOOo = lisp . space ( 2 ) + "Empty,"
 iIiIIIi = iIiIIIi . replace ( "Empty," , OooOOOOOo )
 o0oooOO00 = lisp . space ( 4 ) + "geo:"
 iIiIIIi = iIiIIIi . replace ( "geo:" , o0oooOO00 )
 i1I11ii = lisp . space ( 4 ) + "elp:"
 iIiIIIi = iIiIIIi . replace ( "elp:" , i1I11ii )
 o0ooO00O0O = lisp . space ( 4 ) + "rle:"
 iIiIIIi = iIiIIIi . replace ( "rle:" , o0ooO00O0O )
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
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
  return ( OOoO0 ( ) )
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
  iIiIIIi = "Need to supply EID address"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
  if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 Ooo000O00 = ""
 if os . path . exists ( "lisp-rig.pyo" ) : Ooo000O00 = "python -O lisp-rig.pyo"
 if os . path . exists ( "lisp-rig.pyc" ) : Ooo000O00 = "python3.8 -O lisp-rig.pyo"
 if os . path . exists ( "lisp-rig.py" ) : Ooo000O00 = "python lisp-rig.py"
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if ( Ooo000O00 == "" ) :
  iIiIIIi = "Cannot find lisp-rig.py or lisp-rig.pyo"
  return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
  if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
  if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 Oo0O0 = '{} "{}" to {} {}' . format ( Ooo000O00 , O0OoO0o , iiII1iiiiiii , iiIiii )
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 iIiIIIi = getoutput ( Oo0O0 )
 iIiIIIi = iIiIIIi . replace ( "\n" , "<br>" )
 iIiIIIi = lisp . convert_font ( iIiIIIi )
 if 45 - 45: OoooooooOO
 I1oo = lisp . space ( 2 ) + "Referrals:"
 iIiIIIi = iIiIIIi . replace ( "Referrals:" , I1oo )
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
 if 17 - 17: O0 - OoOoOO00
 if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
 if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
 if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
 if 10 - 10: I1ii11iIi11i / i11iIiiIii - Ii1I + oO0o * I1IiiI
 if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
 if 64 - 64: I11i + OoO0O00
 if 25 - 25: I1IiiI . ooOoO0o + I1IiiI % Ii1I * iIii1I11I1II1
def iiI1iI ( eid1 , eid2 ) :
 iIIi1Ii1III = None
 if os . path . exists ( "lisp-lig.pyo" ) : iIIi1Ii1III = "python -O lisp-lig.pyo"
 if os . path . exists ( "lisp-lig.pyc" ) : iIIi1Ii1III = "python3.8 -O lisp-lig.pyc"
 if os . path . exists ( "lisp-lig.py" ) : iIIi1Ii1III = "python lisp-lig.py"
 if ( iIIi1Ii1III == None ) : return ( [ None , None ] )
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
 if 12 - 12: I1ii11iIi11i / Ii1I
 ii11 = getoutput ( "egrep -A 2 'lisp map-resolver {' ./lisp.config" )
 I111IIiIII = None
 for o0 in [ "address = " , "dns-name = " ] :
  I111IIiIII = None
  Ii11 = ii11 . find ( o0 )
  if ( Ii11 == - 1 ) : continue
  I111IIiIII = ii11 [ Ii11 + len ( o0 ) : : ]
  Ii11 = I111IIiIII . find ( "\n" )
  if ( Ii11 == - 1 ) : continue
  I111IIiIII = I111IIiIII [ 0 : Ii11 ]
  break
  if 3 - 3: Ii1I + I1Ii111 . i1IIi / OOooOOo % I1Ii111
 if ( I111IIiIII == None ) : return ( [ None , None ] )
 if 98 - 98: IiII * iIii1I11I1II1 . Ii1I * Oo0Ooo / I1ii11iIi11i + ooOoO0o
 if 25 - 25: oO0o
 if 19 - 19: I1IiiI % Ii1I . IiII * ooOoO0o
 if 89 - 89: OoOoOO00 . OOooOOo
 IIIIIiI11Ii = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 Iiii1Ii1I = [ ]
 for O0OoO0o in [ eid1 , eid2 ] :
  if 94 - 94: iIii1I11I1II1 - OoO0O00 . Oo0Ooo
  if 59 - 59: OoO0O00 - OoO0O00 + iII111i
  if 32 - 32: i1IIi / Oo0Ooo - O0
  if 85 - 85: Ii1I - O0 * i11iIiiIii . i1IIi
  if 20 - 20: iII111i / OOooOOo
  if ( IIIIIiI11Ii . is_geo_string ( O0OoO0o ) ) :
   Iiii1Ii1I . append ( O0OoO0o )
   continue
   if 28 - 28: ooOoO0o * I11i % i11iIiiIii * iII111i / Ii1I
   if 41 - 41: OOooOOo - o0oOOo0O0Ooo + Ii1I
  Oo0O0 = '{} "{}" to {} count 1' . format ( iIIi1Ii1III , O0OoO0o , I111IIiIII )
  for I1i in [ Oo0O0 , Oo0O0 + " no-info" ] :
   iIiIIIi = getoutput ( Oo0O0 )
   Ii11 = iIiIIIi . find ( "geo: " )
   if ( Ii11 == - 1 ) :
    if ( I1i != Oo0O0 ) : Iiii1Ii1I . append ( None )
    continue
    if 15 - 15: I11i / o0oOOo0O0Ooo + Ii1I
   iIiIIIi = iIiIIIi [ Ii11 + len ( "geo: " ) : : ]
   Ii11 = iIiIIIi . find ( "\n" )
   if ( Ii11 == - 1 ) :
    if ( I1i != Oo0O0 ) : Iiii1Ii1I . append ( None )
    continue
    if 76 - 76: Ii1I + OoooooooOO / OOooOOo % OoO0O00 / I1ii11iIi11i
   Iiii1Ii1I . append ( iIiIIIi [ 0 : Ii11 ] )
   break
   if 38 - 38: I1Ii111 . iII111i . I1IiiI * OoO0O00
   if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii / Ii1I
 return ( Iiii1Ii1I )
 if 93 - 93: ooOoO0o
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 if 19 - 19: I1ii11iIi11i
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if 66 - 66: O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
@ bottle . post ( '/lisp/geo' )
def o0OO0oooo ( ) :
 if ( lispconfig . lisp_validate_user ( ) == False ) :
  return ( OOoO0 ( ) )
  if 40 - 40: I1Ii111 - OoOoOO00 * I11i - IiII / OoOoOO00
  if 71 - 71: oO0o / OoooooooOO % IiII / OoOoOO00 % I1Ii111
 O0OoO0o = bottle . request . forms . get ( "geo-point" )
 I1i1iI = bottle . request . forms . get ( "geo-prefix" )
 iIiIIIi = ""
 if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 if 46 - 46: OoOoOO00 - O0
 if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
 if 49 - 49: o0oOOo0O0Ooo
 if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
 ooo0o0 = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
 O00Oooo00 = lisp . lisp_geo ( "" )
 ooO0 = lisp . lisp_geo ( "" )
 ii111iiIii , oO0oiIiI = iiI1iI ( O0OoO0o , I1i1iI )
 if 46 - 46: iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
 if 65 - 65: ooOoO0o - i1IIi
 if ( ooo0o0 . is_geo_string ( O0OoO0o ) ) :
  if ( O00Oooo00 . parse_geo_string ( O0OoO0o ) == False ) :
   iIiIIIi = "Could not parse geo-point format"
   if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 elif ( ii111iiIii == None ) :
  iIiIIIi = "EID {} lookup could not find geo-point" . format (
 lisp . bold ( O0OoO0o , True ) )
 elif ( O00Oooo00 . parse_geo_string ( ii111iiIii ) == False ) :
  iIiIIIi = "Could not parse geo-point format returned from lookup"
  if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  if 34 - 34: I1Ii111 - OOooOOo
  if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
  if 64 - 64: i1IIi
  if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
  if 25 - 25: II111iiii / OoO0O00
 if ( iIiIIIi == "" ) :
  if ( ooo0o0 . is_geo_string ( I1i1iI ) ) :
   if ( ooO0 . parse_geo_string ( I1i1iI ) == False ) :
    iIiIIIi = "Could not parse geo-prefix format"
    if 64 - 64: O0 % ooOoO0o
  elif ( oO0oiIiI == None ) :
   iIiIIIi = "EID-prefix {} lookup could not find geo-prefix" . format ( lisp . bold ( I1i1iI , True ) )
   if 40 - 40: o0oOOo0O0Ooo + I11i
  elif ( ooO0 . parse_geo_string ( oO0oiIiI ) == False ) :
   iIiIIIi = "Could not parse geo-prefix format returned from lookup"
   if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
   if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
   if 47 - 47: OoooooooOO
   if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
   if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
   if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
   if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if ( iIiIIIi == "" ) :
  O0OoO0o = "" if ( O0OoO0o == ii111iiIii ) else ", EID {}" . format ( O0OoO0o )
  I1i1iI = "" if ( I1i1iI == oO0oiIiI ) else ", EID-prefix {}" . format ( I1i1iI )
  if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
  if 26 - 26: OOooOOo * Oo0Ooo
  i1iI1Ii11Ii1 = O00Oooo00 . print_geo_url ( )
  o0OoO0oo0O0o = ooO0 . print_geo_url ( )
  ii1III1iiIi = ooO0 . radius
  I1ii1iI = O00Oooo00 . dms_to_decimal ( )
  I1ii1iI = ( round ( I1ii1iI [ 0 ] , 6 ) , round ( I1ii1iI [ 1 ] , 6 ) )
  ooO000OO = ooO0 . dms_to_decimal ( )
  ooO000OO = ( round ( ooO000OO [ 0 ] , 6 ) , round ( ooO000OO [ 1 ] , 6 ) )
  i111IIiIiiI1 = round ( ooO0 . get_distance ( O00Oooo00 ) , 2 )
  OO0 = "inside" if ooO0 . point_in_circle ( O00Oooo00 ) else "outside"
  if 28 - 28: Oo0Ooo % OOooOOo - OoO0O00 + ooOoO0o / ooOoO0o
  if 82 - 82: Oo0Ooo
  IIIIIi11111iiiII1I = lisp . space ( 2 )
  I1I1i = lisp . space ( 1 )
  iii1IiI1i = lisp . space ( 3 )
  if 93 - 93: i1IIi % OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo . O0 % OOooOOo
  iIiIIIi = ( "Geo-Point:{}{} {}{}<br>Geo-Prefix:{}{} {}, {} " + "kilometer radius{}<br>" ) . format ( IIIIIi11111iiiII1I , i1iI1Ii11Ii1 , I1ii1iI , O0OoO0o ,
  # Ii1I * oO0o - I11i + Oo0Ooo % I1ii11iIi11i - IiII
 I1I1i , o0OoO0oo0O0o , ooO000OO , ii1III1iiIi , I1i1iI )
  iIiIIIi += "Distance:{}{} kilometers, point is {} of circle" . format ( iii1IiI1i ,
 i111IIiIiiI1 , lisp . bold ( OO0 , True ) )
  if 81 - 81: O0 . O0
 return ( lispconfig . lisp_show_wrapper ( lisp . lisp_print_cour ( iIiIIIi ) ) )
 if 75 - 75: iIii1I11I1II1 % IiII + I1ii11iIi11i * O0 . iII111i - ooOoO0o
 if 32 - 32: Ii1I % oO0o - i1IIi
 if 40 - 40: iIii1I11I1II1 + iII111i * OoOoOO00 + oO0o
 if 15 - 15: I11i % I1IiiI - iIii1I11I1II1 * ooOoO0o
 if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
 if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
 if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
 if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
 if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
def O0Oo0O00o0oo0OO ( addr_str , port , nonce ) :
 if ( addr_str != None ) :
  for OooO00 in list ( lisp . lisp_info_sources_by_address . values ( ) ) :
   o0O00OoOOo = OooO00 . address . print_address_no_iid ( )
   if ( o0O00OoOOo == addr_str and OooO00 . port == port ) :
    return ( OooO00 )
    if 9 - 9: o0oOOo0O0Ooo % I1ii11iIi11i . I1ii11iIi11i
    if 28 - 28: OoooooooOO % oO0o + I1ii11iIi11i + O0 . I1Ii111
  return ( None )
  if 80 - 80: i11iIiiIii % I1ii11iIi11i
  if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
 if ( nonce != None ) :
  if ( nonce not in lisp . lisp_info_sources_by_nonce ) : return ( None )
  return ( lisp . lisp_info_sources_by_nonce [ nonce ] )
  if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
 return ( None )
 if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
 if 21 - 21: iII111i
 if 24 - 24: iII111i / ooOoO0o
 if 61 - 61: iIii1I11I1II1 + oO0o
 if 8 - 8: I1Ii111 + OoO0O00
 if 9 - 9: OOooOOo + o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
def oOiIi ( lisp_sockets , info_source , packet ) :
 if 65 - 65: II111iiii + i1IIi * i11iIiiIii
 if 38 - 38: iIii1I11I1II1 + OoooooooOO * I1IiiI % OoOoOO00 % I11i - IiII
 if 56 - 56: OoooooooOO * Oo0Ooo * I11i + ooOoO0o
 if 54 - 54: OoOoOO00 * i11iIiiIii . OoooooooOO - iIii1I11I1II1
 I1OO0o = lisp . lisp_ecm ( 0 )
 packet = I1OO0o . decode ( packet )
 if ( packet == None ) :
  lisp . lprint ( "Could not decode ECM packet" )
  return ( True )
  if 99 - 99: II111iiii - I1Ii111 + iII111i * IiII / I1Ii111
  if 41 - 41: O0 . I11i
 oO0ooOOO = lisp . lisp_control_header ( )
 if ( oO0ooOOO . decode ( packet ) == None ) :
  lisp . lprint ( "Could not decode control header" )
  return ( True )
  if 95 - 95: O0
 if ( oO0ooOOO . type != lisp . LISP_MAP_REQUEST ) :
  lisp . lprint ( "Received ECM without Map-Request inside" )
  return ( True )
  if 75 - 75: IiII + OoO0O00 * I11i - OoOoOO00
  if 52 - 52: OOooOOo * oO0o + I11i * I11i % i1IIi % I11i
  if 96 - 96: o0oOOo0O0Ooo * oO0o - OOooOOo * o0oOOo0O0Ooo * i1IIi
  if 8 - 8: ooOoO0o - Oo0Ooo + iIii1I11I1II1 + i1IIi * Ii1I - iIii1I11I1II1
  if 30 - 30: I11i / I1ii11iIi11i
 iI1iIIIIIiIi1 = lisp . lisp_map_request ( )
 packet = iI1iIIIIIiIi1 . decode ( packet , None , 0 )
 iIi = iI1iIIIIIiIi1 . nonce
 oOoooOo0o = info_source . address . print_address_no_iid ( )
 if 44 - 44: Oo0Ooo . Oo0Ooo + OoooooooOO * i11iIiiIii / I11i + I1Ii111
 if 17 - 17: OOooOOo + II111iiii
 if 43 - 43: I11i % Ii1I / o0oOOo0O0Ooo * I1Ii111
 if 85 - 85: iIii1I11I1II1 . OoooooooOO . o0oOOo0O0Ooo
 iI1iIIIIIiIi1 . print_map_request ( )
 if 77 - 77: I1IiiI % ooOoO0o
 lisp . lprint ( "Process {} from info-source {}, port {}, nonce 0x{}" . format ( lisp . bold ( "nat-proxy Map-Request" , False ) ,
 # II111iiii + Ii1I + OoooooooOO / i1IIi - Ii1I
 lisp . red ( oOoooOo0o , False ) , info_source . port ,
 lisp . lisp_hex_string ( iIi ) ) )
 if 87 - 87: iII111i / I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
 if 23 - 23: i11iIiiIii
 if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
 if 65 - 65: II111iiii / Oo0Ooo
 if 42 - 42: i11iIiiIii . O0
 info_source . cache_nonce_for_info_source ( iIi )
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
 if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
 if 92 - 92: I11i / O0 * I1IiiI - I11i
 if 99 - 99: i11iIiiIii % OoooooooOO
 info_source . no_timeout = iI1iIIIIIiIi1 . subscribe_bit
 if 56 - 56: IiII * I1Ii111
 if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
 if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
 if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
 if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
 if 56 - 56: i1IIi . i11iIiiIii
 for Ii1Ii1IiIIIi1 in iI1iIIIIIiIi1 . itr_rlocs :
  if ( Ii1Ii1IiIIIi1 . is_local ( ) ) : return ( False )
  if 55 - 55: oO0o + O0 / iII111i % ooOoO0o / OoooooooOO
  if 98 - 98: Ii1I * iIii1I11I1II1 % Oo0Ooo % OOooOOo
  if 88 - 88: iII111i - II111iiii / iII111i - Ii1I
  if 16 - 16: Oo0Ooo % I1Ii111
  if 10 - 10: IiII / OoooooooOO
 IiiiIIiii = lisp . lisp_myrlocs [ 0 ]
 iI1iIIIIIiIi1 . itr_rloc_count = 0
 iI1iIIIIIiIi1 . itr_rlocs = [ ]
 iI1iIIIIIiIi1 . itr_rlocs . append ( IiiiIIiii )
 if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
 packet = iI1iIIIIIiIi1 . encode ( None , 0 )
 iI1iIIIIIiIi1 . print_map_request ( )
 if 25 - 25: iIii1I11I1II1
 o0o0O0oOOOooo = iI1iIIIIIiIi1 . target_eid
 if ( o0o0O0oOOOooo . is_ipv6 ( ) ) :
  Ii1iiI1i1 = lisp . lisp_myrlocs [ 1 ]
  if ( Ii1iiI1i1 != None ) : IiiiIIiii = Ii1iiI1i1
  if 3 - 3: OOooOOo . IiII / Oo0Ooo
  if 89 - 89: OoooooooOO . iIii1I11I1II1 . Oo0Ooo * iIii1I11I1II1 - I1Ii111
  if 92 - 92: OoooooooOO - I1ii11iIi11i - OoooooooOO % I1IiiI % I1IiiI % iIii1I11I1II1
  if 92 - 92: iII111i * O0 % I1Ii111 . iIii1I11I1II1
  if 66 - 66: I11i + Ii1I
 i1ii1iIi = lisp . lisp_is_running ( "lisp-ms" )
 lisp . lisp_send_ecm ( lisp_sockets , packet , o0o0O0oOOOooo , lisp . LISP_CTRL_PORT ,
 o0o0O0oOOOooo , IiiiIIiii , to_ms = i1ii1iIi , ddt = False )
 return ( True )
 if 43 - 43: Ii1I + iII111i + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
 if 54 - 54: I1ii11iIi11i + I1ii11iIi11i + I11i % i1IIi % i11iIiiIii
 if 100 - 100: I1ii11iIi11i
 if 96 - 96: I1IiiI . IiII * II111iiii % IiII . I1Ii111 * i1IIi
 if 83 - 83: iIii1I11I1II1
 if 97 - 97: i11iIiiIii + Oo0Ooo * OOooOOo % iII111i . IiII
 if 4 - 4: O0 . iII111i - iIii1I11I1II1
 if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
 if 89 - 89: Ii1I
def o00O00O0Oo0 ( lisp_sockets , info_source , packet , mr_or_mn ) :
 oOoooOo0o = info_source . address . print_address_no_iid ( )
 oo00O00oO = info_source . port
 iIi = info_source . nonce
 if 53 - 53: i1IIi . i1IIi - I11i / iII111i - OoOoOO00 % I1IiiI
 mr_or_mn = "Reply" if mr_or_mn else "Notify"
 mr_or_mn = lisp . bold ( "nat-proxy Map-{}" . format ( mr_or_mn ) , False )
 if 65 - 65: iII111i . OoooooooOO - O0 . iII111i - i11iIiiIii
 lisp . lprint ( "Forward {} to info-source {}, port {}, nonce 0x{}" . format ( mr_or_mn , lisp . red ( oOoooOo0o , False ) , oo00O00oO ,
 # O0 - I1ii11iIi11i
 lisp . lisp_hex_string ( iIi ) ) )
 if 76 - 76: oO0o - i11iIiiIii
 if 27 - 27: I1ii11iIi11i - i11iIiiIii % I1Ii111 / Oo0Ooo . Oo0Ooo / OoooooooOO
 if 76 - 76: I11i * OoO0O00 . iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 O0o0O0O0O = lisp . lisp_convert_4to6 ( oOoooOo0o )
 lisp . lisp_send ( lisp_sockets , O0o0O0O0O , oo00O00oO , packet )
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
 if 79 - 79: O0
 if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
 if 15 - 15: I1ii11iIi11i
 if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
def OO0o0o0oo ( lisp_sockets , source , sport , packet ) :
 global Ooo
 if 40 - 40: Oo0Ooo
 oO0ooOOO = lisp . lisp_control_header ( )
 if ( oO0ooOOO . decode ( packet ) == None ) :
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
 if ( oO0ooOOO . type == lisp . LISP_NAT_INFO ) :
  if ( oO0ooOOO . info_reply == False ) :
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
 if ( oO0ooOOO . type in ( lisp . LISP_MAP_REGISTER , lisp . LISP_MAP_NOTIFY_ACK ) ) :
  lisp . lisp_ipc ( packet , Ooo , "lisp-ms" )
  return
  if 93 - 93: iII111i * oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if 59 - 59: II111iiii
  if 43 - 43: Oo0Ooo + OoooooooOO
  if 47 - 47: ooOoO0o
  if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
 if ( oO0ooOOO . type == lisp . LISP_MAP_REPLY ) :
  ii11Ii1IiiI1 = lisp . lisp_map_reply ( )
  ii11Ii1IiiI1 . decode ( IIo0oo0OO )
  if 83 - 83: ooOoO0o + i1IIi * OoooooooOO * oO0o
  OooO00 = O0Oo0O00o0oo0OO ( None , 0 , ii11Ii1IiiI1 . nonce )
  if ( OooO00 ) :
   o00O00O0Oo0 ( lisp_sockets , OooO00 , IIo0oo0OO , True )
  else :
   iIIi1Ii1III = "/tmp/lisp-lig"
   if ( os . path . exists ( iIIi1Ii1III ) ) :
    lisp . lisp_ipc ( packet , Ooo , iIIi1Ii1III )
   else :
    lisp . lisp_ipc ( packet , Ooo , "lisp-itr" )
    if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
    if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  return
  if 21 - 21: OoO0O00
  if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
  if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
  if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
  if 11 - 11: O0 * OoOoOO00
 if ( oO0ooOOO . type == lisp . LISP_MAP_NOTIFY ) :
  IIii1i = lisp . lisp_map_notify ( lisp_sockets )
  IIii1i . decode ( IIo0oo0OO )
  if 69 - 69: I1Ii111 / OoooooooOO % i11iIiiIii
  OooO00 = O0Oo0O00o0oo0OO ( None , 0 , IIii1i . nonce )
  if ( OooO00 ) :
   o00O00O0Oo0 ( lisp_sockets , OooO00 , IIo0oo0OO ,
 False )
  else :
   iIIi1Ii1III = "/tmp/lisp-lig"
   if ( os . path . exists ( iIIi1Ii1III ) ) :
    lisp . lisp_ipc ( packet , Ooo , iIIi1Ii1III )
   else :
    iIii11iI1II = "lisp-rtr" if lisp . lisp_is_running ( "lisp-rtr" ) else "lisp-etr"
    if 18 - 18: i11iIiiIii - ooOoO0o * oO0o + o0oOOo0O0Ooo
    lisp . lisp_ipc ( packet , Ooo , iIii11iI1II )
    if 16 - 16: OoooooooOO * i11iIiiIii . OoooooooOO - iIii1I11I1II1 * i1IIi
    if 33 - 33: I1Ii111 % II111iiii
  return
  if 49 - 49: I1ii11iIi11i + I11i / o0oOOo0O0Ooo + OoooooooOO + OOooOOo / IiII
  if 29 - 29: Ii1I - Ii1I / ooOoO0o
  if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
  if 18 - 18: Oo0Ooo % O0
  if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if ( oO0ooOOO . type == lisp . LISP_MAP_REFERRAL ) :
  Ooo000O00 = "/tmp/lisp-rig"
  if ( os . path . exists ( Ooo000O00 ) ) :
   lisp . lisp_ipc ( packet , Ooo , Ooo000O00 )
  else :
   lisp . lisp_ipc ( packet , Ooo , "lisp-mr" )
   if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
  return
  if 86 - 86: IiII
  if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
  if 33 - 33: II111iiii - IiII - ooOoO0o
  if 92 - 92: OoO0O00 * IiII
  if 92 - 92: oO0o
  if 7 - 7: iII111i
 if ( oO0ooOOO . type == lisp . LISP_MAP_REQUEST ) :
  iIii11iI1II = "lisp-itr" if ( oO0ooOOO . is_smr ( ) ) else "lisp-etr"
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if 62 - 62: i11iIiiIii
  if 2 - 2: I1IiiI
  if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
  if ( oO0ooOOO . rloc_probe ) : return
  if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  lisp . lisp_ipc ( packet , Ooo , iIii11iI1II )
  return
  if 14 - 14: IiII . IiII % ooOoO0o
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
  if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
  if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
  if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
  if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 6 - 6: oO0o . I11i
 if ( oO0ooOOO . type == lisp . LISP_ECM ) :
  OooO00 = O0Oo0O00o0oo0OO ( source , sport , None )
  if ( OooO00 ) :
   if ( oOiIi ( lisp_sockets , OooO00 ,
 IIo0oo0OO ) ) : return
   if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
   if 50 - 50: oO0o % i1IIi * O0
  iIii11iI1II = "lisp-mr"
  if ( oO0ooOOO . is_to_etr ( ) ) :
   iIii11iI1II = "lisp-etr"
  elif ( oO0ooOOO . is_to_ms ( ) ) :
   iIii11iI1II = "lisp-ms"
  elif ( oO0ooOOO . is_ddt ( ) ) :
   if ( lisp . lisp_is_running ( "lisp-ddt" ) ) :
    iIii11iI1II = "lisp-ddt"
   elif ( lisp . lisp_is_running ( "lisp-ms" ) ) :
    iIii11iI1II = "lisp-ms"
    if 4 - 4: iIii1I11I1II1 . i1IIi
  elif ( lisp . lisp_is_running ( "lisp-mr" ) == False ) :
   iIii11iI1II = "lisp-etr"
   if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
  lisp . lisp_ipc ( packet , Ooo , iIii11iI1II )
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
def ooO ( bottle_port ) :
 lisp . lisp_set_exception ( )
 if 34 - 34: I1Ii111 * II111iiii
 if 71 - 71: IiII
 if 97 - 97: I1ii11iIi11i
 if 86 - 86: Oo0Ooo - OOooOOo . OoOoOO00 . II111iiii * I1IiiI . II111iiii
 if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
 if ( bottle_port < 0 ) :
  bottle . run ( host = "0.0.0.0" , port = - bottle_port )
  return
  if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
  if 28 - 28: i11iIiiIii
 bottle . server_names [ "lisp-ssl-server" ] = iiIiiII1II1ii
 if 51 - 51: I1IiiI + ooOoO0o * O0 . Ii1I
 if 82 - 82: OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
 if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
 if 20 - 20: i1IIi . i1IIi - I11i
 try :
  bottle . run ( host = "0.0.0.0" , port = bottle_port , server = "lisp-ssl-server" ,
 fast = True )
 except :
  lisp . lprint ( "Could not startup lisp-ssl-server, running insecurely" )
  bottle . run ( host = "0.0.0.0" , port = bottle_port )
  if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
 return
 if 35 - 35: II111iiii / OoOoOO00 - O0 . II111iiii
 if 55 - 55: Oo0Ooo % i1IIi * I11i
 if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
 if 63 - 63: iIii1I11I1II1 / ooOoO0o
 if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
 if 50 - 50: II111iiii
 if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
 if 44 - 44: I1IiiI
def oOO0O0O0OO00oo ( ) :
 lisp . lisp_set_exception ( )
 if 39 - 39: IiII % OoOoOO00 * I1ii11iIi11i - OoooooooOO - Oo0Ooo
 return
 if 75 - 75: i11iIiiIii . ooOoO0o % i1IIi . I1IiiI - oO0o + Oo0Ooo
 if 66 - 66: oO0o % I1ii11iIi11i . II111iiii / OoOoOO00 / OoO0O00
 if 47 - 47: iII111i + O0 / II111iiii * I1IiiI - OoooooooOO . Ii1I
 if 28 - 28: oO0o . oO0o . iIii1I11I1II1 . OOooOOo . I1ii11iIi11i * i11iIiiIii
 if 72 - 72: I11i
 if 26 - 26: IiII % Oo0Ooo
 if 72 - 72: O0 + o0oOOo0O0Ooo + I1IiiI / Oo0Ooo
 if 83 - 83: IiII - I1IiiI . Ii1I
 if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
def IiI1I1IIIi1i ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 i11i1iiiII = { "lisp-itr" : False , "lisp-etr" : False , "lisp-rtr" : False ,
 "lisp-mr" : False , "lisp-ms" : False , "lisp-ddt" : False }
 if 73 - 73: O0 * I1Ii111 . i1IIi
 while ( True ) :
  time . sleep ( 1 )
  OO00OoOO = i11i1iiiII
  i11i1iiiII = { }
  if 45 - 45: II111iiii * i1IIi
  for iIii11iI1II in OO00OoOO :
   i11i1iiiII [ iIii11iI1II ] = lisp . lisp_is_running ( iIii11iI1II )
   if ( OO00OoOO [ iIii11iI1II ] == i11i1iiiII [ iIii11iI1II ] ) : continue
   if 25 - 25: OoOoOO00 + iIii1I11I1II1 % I11i / Oo0Ooo * Oo0Ooo
   lisp . lprint ( "*** Process '{}' has {} ***" . format ( iIii11iI1II ,
 "come up" if i11i1iiiII [ iIii11iI1II ] else "gone down" ) )
   if 51 - 51: oO0o - OoO0O00 + iII111i - o0oOOo0O0Ooo . OoO0O00 % I1ii11iIi11i
   if 14 - 14: I1IiiI / O0
   if 43 - 43: oO0o - IiII % i11iIiiIii * II111iiii . I1Ii111 - I11i
   if 13 - 13: OoO0O00
   if ( i11i1iiiII [ iIii11iI1II ] == True ) :
    lisp . lisp_ipc_lock . acquire ( )
    lispconfig . lisp_send_commands ( lisp_socket , iIii11iI1II )
    lisp . lisp_ipc_lock . release ( )
    if 70 - 70: IiII . I1Ii111 * OoO0O00 + I11i - IiII . IiII
    if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
    if 84 - 84: iIii1I11I1II1 + OoooooooOO
 return
 if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
 if 10 - 10: I1ii11iIi11i + IiII
 if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
 if 62 - 62: II111iiii
 if 12 - 12: IiII + II111iiii
 if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
 if 80 - 80: iII111i
def iI1I1ii11IIi1 ( ) :
 lisp . lisp_set_exception ( )
 OOo = 60
 if 80 - 80: o0oOOo0O0Ooo / oO0o / Ii1I - I1IiiI % I1Ii111
 while ( True ) :
  time . sleep ( OOo )
  if 44 - 44: I1IiiI % OOooOOo * i11iIiiIii * i11iIiiIii - Oo0Ooo . I1Ii111
  o00 = [ ]
  i111iiIiiIiI = lisp . lisp_get_timestamp ( )
  if 59 - 59: OOooOOo + I1IiiI / II111iiii / OoOoOO00
  if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
  if 76 - 76: I1IiiI * OOooOOo
  if 12 - 12: iIii1I11I1II1 / I11i % Ii1I
  for iI1i in lisp . lisp_info_sources_by_address :
   OooO00 = lisp . lisp_info_sources_by_address [ iI1i ]
   if ( OooO00 . no_timeout ) : continue
   if ( OooO00 . uptime + OOo < i111iiIiiIiI ) : continue
   if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
   o00 . append ( iI1i )
   if 27 - 27: OoO0O00 + Oo0Ooo
   iIi = OooO00 . nonce
   if ( iIi == None ) : continue
   if ( iIi in lisp . lisp_info_sources_by_nonce ) :
    lisp . lisp_info_sources_by_nonce . pop ( iIi )
    if 92 - 92: I1IiiI % iII111i
    if 31 - 31: OoooooooOO - oO0o / I1Ii111
    if 62 - 62: i11iIiiIii - I11i
    if 81 - 81: I11i
    if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
    if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
  for iI1i in o00 :
   lisp . lisp_info_sources_by_address . pop ( iI1i )
   if 31 - 31: i1IIi % II111iiii
   if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
 return
 if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
 if 3 - 3: II111iiii / OOooOOo
 if 48 - 48: ooOoO0o . I1ii11iIi11i
 if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
 if 24 - 24: oO0o - iII111i / ooOoO0o
 if 10 - 10: OoOoOO00 * i1IIi
 if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
 if 34 - 34: I1IiiI
def o0OoOo0O00 ( lisp_ipc_control_socket , lisp_sockets ) :
 lisp . lisp_set_exception ( )
 while ( True ) :
  try : iI1i1iI1iI = lisp_ipc_control_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  iiiI11 = iI1i1iI1iI [ 0 ] . split ( b"@" )
  oOOo0 = iI1i1iI1iI [ 1 ]
  if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
  III1iII1I1ii = iiiI11 [ 0 ] . decode ( )
  O0o0O0O0O = iiiI11 [ 1 ] . decode ( )
  oo00O00oO = int ( iiiI11 [ 2 ] )
  OOoOoO = iiiI11 [ 3 : : ]
  if 72 - 72: OoOoOO00 / I1Ii111 * IiII % iIii1I11I1II1
  if 53 - 53: OoO0O00 . O0 . I1IiiI * OOooOOo / o0oOOo0O0Ooo
  if 34 - 34: OoOoOO00
  if 16 - 16: i1IIi - I1Ii111 - II111iiii
  if ( len ( OOoOoO ) > 1 ) :
   OOoOoO = lisp . lisp_bit_stuff ( OOoOoO )
  else :
   OOoOoO = OOoOoO [ 0 ]
   if 83 - 83: I1IiiI - OoO0O00 - o0oOOo0O0Ooo / O0 - I11i . II111iiii
   if 27 - 27: Ii1I
  if ( III1iII1I1ii != "control-packet" ) :
   lisp . lprint ( ( "lisp_core_control_packet_process() received " + "unexpected control-packet, message ignored" ) )
   if 59 - 59: Ii1I / II111iiii - IiII % OoOoOO00 % OoooooooOO
   continue
   if 79 - 79: iII111i . OoooooooOO . I1IiiI * O0 * OoO0O00 - OOooOOo
   if 33 - 33: I1ii11iIi11i . Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
  lisp . lprint ( ( "{} {} bytes from {}, dest/port: {}/{}, control-" + "packet: {}" ) . format ( lisp . bold ( "Receive" , False ) , len ( OOoOoO ) ,
  # iII111i * I1Ii111 * I11i * iII111i
 oOOo0 , O0o0O0O0O , oo00O00oO , lisp . lisp_format_packet ( OOoOoO ) ) )
  if 57 - 57: OOooOOo % OoO0O00 - I1IiiI
  if 3 - 3: OOooOOo + i1IIi % I1ii11iIi11i
  if 100 - 100: OoooooooOO + i11iIiiIii % o0oOOo0O0Ooo + I1IiiI . Oo0Ooo . II111iiii
  if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
  if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
  if 4 - 4: IiII
  oO0ooOOO = lisp . lisp_control_header ( )
  oO0ooOOO . decode ( OOoOoO )
  if ( oO0ooOOO . type == lisp . LISP_MAP_REPLY ) :
   ii11Ii1IiiI1 = lisp . lisp_map_reply ( )
   ii11Ii1IiiI1 . decode ( OOoOoO )
   if ( O0Oo0O00o0oo0OO ( None , 0 , ii11Ii1IiiI1 . nonce ) ) :
    OO0o0o0oo ( lisp_sockets , oOOo0 , oo00O00oO , OOoOoO )
    continue
    if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
    if 99 - 99: i11iIiiIii - iII111i
    if 85 - 85: I1Ii111 % I1ii11iIi11i
    if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
    if 73 - 73: OoO0O00
    if 28 - 28: OoooooooOO - I11i
    if 84 - 84: II111iiii
    if 36 - 36: OOooOOo - OoOoOO00 - iIii1I11I1II1
  if ( oO0ooOOO . type == lisp . LISP_MAP_NOTIFY and oOOo0 == "lisp-etr" ) :
   O0ooo0O0oo0 = lisp . lisp_packet_ipc ( OOoOoO , oOOo0 , oo00O00oO )
   lisp . lisp_ipc ( O0ooo0O0oo0 , Ooo , "lisp-itr" )
   continue
   if 10 - 10: I1ii11iIi11i / Ii1I * i1IIi % O0 + I11i
   if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
   if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
   if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
   if 80 - 80: Ii1I
   if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
   if 59 - 59: I1ii11iIi11i + I11i . oO0o
  IIIIIiI11Ii = lisp . lisp_convert_4to6 ( O0o0O0O0O )
  IIIIIiI11Ii = lisp . lisp_address ( lisp . LISP_AFI_IPV6 , "" , 128 , 0 )
  if ( IIIIIiI11Ii . is_ipv4_string ( O0o0O0O0O ) ) : O0o0O0O0O = "::ffff:" + O0o0O0O0O
  IIIIIiI11Ii . store_address ( O0o0O0O0O )
  if 87 - 87: OoO0O00
  if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  lisp . lisp_send ( lisp_sockets , IIIIIiI11Ii , oo00O00oO , OOoOoO )
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
 return
 if 46 - 46: i11iIiiIii
 if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
 if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
 if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
 if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
 if 65 - 65: OoooooooOO
 if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
 if 83 - 83: ooOoO0o
def O0O0oOOo0O ( ) :
 Oo = open ( "./lisp.config.example" , "r" ) ; O0OOOOo0O = Oo . read ( ) ; Oo . close ( )
 Oo = open ( "./lisp.config" , "w" )
 O0OOOOo0O = O0OOOOo0O . split ( "\n" )
 for OOoO in O0OOOOo0O :
  Oo . write ( OOoO + "\n" )
  if ( OOoO [ 0 ] == "#" and OOoO [ - 1 ] == "#" and len ( OOoO ) >= 4 ) :
   i1Ii1i11ii = OOoO [ 1 : - 2 ]
   oO0O0oo = len ( i1Ii1i11ii ) * "-"
   if ( i1Ii1i11ii == oO0O0oo ) : break
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
 global o0oO0
 global I1Ii11I1Ii1i
 global Ooo
 global o0oOoO00o
 global i1
 global oOOoo00O0O
 if 68 - 68: i11iIiiIii + OoO0O00
 lisp . lisp_i_am ( "core" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "core-process starting up" )
 lisp . lisp_version = getoutput ( "cat lisp-version.txt" )
 o0oO0 = getoutput ( "cat lisp-build-date.txt" )
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
  I1Ii11I1Ii1i = lisp . lisp_open_listen_socket ( OoOo0o0OOoO0 ,
 str ( lisp . LISP_CTRL_PORT ) )
 else :
  OoOo0o0OOoO0 = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( )
  I1Ii11I1Ii1i = lisp . lisp_open_listen_socket ( OoOo0o0OOoO0 ,
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
  oOOoo00O0O = lisp . lisp_open_listen_socket ( OoOo0o0OOoO0 ,
 str ( lisp . LISP_DATA_PORT ) )
  lisp . lprint ( "Listen on {}, port 4341" . format ( OoOo0o0OOoO0 ) )
  if 3 - 3: I1ii11iIi11i / II111iiii
  if 73 - 73: OoO0O00 * OoooooooOO - OoooooooOO + I1IiiI * Oo0Ooo
  if 87 - 87: o0oOOo0O0Ooo / IiII / i11iIiiIii
  if 95 - 95: i1IIi / Ii1I / Ii1I
  if 65 - 65: I1Ii111 + iII111i * iII111i
  if 79 - 79: i1IIi / Oo0Ooo - I1IiiI . O0
 Ooo = lisp . lisp_open_send_socket ( "lisp-core" , "" )
 Ooo . settimeout ( 3 )
 if 56 - 56: IiII % O0 * i1IIi - II111iiii
 if 74 - 74: i1IIi - OoOoOO00 % oO0o . O0 - OoooooooOO
 if 84 - 84: I1Ii111
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
 o0oOoO00o = lisp . lisp_open_listen_socket ( "" , "lisp-core-pkt" )
 if 9 - 9: i1IIi - OoOoOO00
 i1 = [ I1Ii11I1Ii1i , I1Ii11I1Ii1i ,
 Ooo ]
 if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
 if 46 - 46: Ii1I
 if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
 if 87 - 87: I1ii11iIi11i / I1IiiI
 if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
 threading . Thread ( target = o0OoOo0O00 ,
 args = [ o0oOoO00o , i1 ] ) . start ( )
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
 iIiI1I ( I1Ii11I1Ii1i )
 if 2 - 2: o0oOOo0O0Ooo . Ii1I % OoOoOO00
 threading . Thread ( target = lispconfig . lisp_config_process ,
 args = [ Ooo ] ) . start ( )
 if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
 if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
 if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
 if 58 - 58: iII111i
 threading . Thread ( target = ooO ,
 args = [ bottle_port ] ) . start ( )
 threading . Thread ( target = oOO0O0O0OO00oo , args = [ ] ) . start ( )
 if 2 - 2: II111iiii + i1IIi
 if 68 - 68: OOooOOo + Ii1I
 if 58 - 58: IiII * Ii1I . i1IIi
 if 19 - 19: oO0o
 threading . Thread ( target = IiI1I1IIIi1i ,
 args = [ Ooo ] ) . start ( )
 if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
 if 94 - 94: iIii1I11I1II1 + IiII
 if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
 if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
 threading . Thread ( target = iI1I1ii11IIi1 ) . start ( )
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
 lisp . lisp_close_socket ( Ooo , "lisp-core" )
 lisp . lisp_close_socket ( o0oOoO00o , "lisp-core-pkt" )
 lisp . lisp_close_socket ( I1Ii11I1Ii1i , "" )
 lisp . lisp_close_socket ( oOOoo00O0O , "" )
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
 for OOoO in O0OOOOo0O :
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
 for OOoO in O0OOOOo0O :
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
 Ii1IIi = getoutput ( 'ifconfig eth0 | egrep "inet "' )
 if ( Ii1IIi == "" ) : return
 i1IIII1II = Ii1IIi . split ( ) [ 1 ]
 if 89 - 89: I11i % iII111i * Oo0Ooo / I1Ii111 * Oo0Ooo / ooOoO0o
 if 14 - 14: i1IIi * iIii1I11I1II1 - Ii1I * OoOoOO00 - iII111i / oO0o
 if 73 - 73: I1ii11iIi11i - OoOoOO00 * O0 - OoOoOO00 - OoO0O00
 if 96 - 96: I1ii11iIi11i - O0
 Ii111iIi1iIi = socket . inet_aton ( i1IIII1II )
 for i1I11 in OO0o0oo :
  lisp_socket . setsockopt ( socket . SOL_SOCKET , socket . SO_REUSEADDR , 1 )
  lisp_socket . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_IF , Ii111iIi1iIi )
  I1iO00O000oOO0oO = socket . inet_aton ( i1I11 ) + Ii111iIi1iIi
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
 III1iII1I1ii , oOOo0 , oo00O00oO , OOoOoO = lisp . lisp_receive ( I1Ii11I1Ii1i , False )
 if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
 if ( oOOo0 == "" ) : break
 if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
 if 89 - 89: IiII - i1IIi - IiII
 if 74 - 74: OoO0O00 % OoO0O00
 if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
 oOOo0 = lisp . lisp_convert_6to4 ( oOOo0 )
 OO0o0o0oo ( i1 , oOOo0 , oo00O00oO , OOoOoO )
 if 91 - 91: I1IiiI / II111iiii * OOooOOo
 if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
I1i11 ( )
lisp . lisp_print_banner ( "lisp-core normal exit" )
exit ( 0 )
if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
if 81 - 81: OoO0O00 - iIii1I11I1II1
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
