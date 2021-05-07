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
# lispapi.py
#
# This file containse API definitions that users call in their python programs.
# 
# When this file is changed, remote file lispapi.html and click the "API
# Documentation" button on the landing page to build a pydoc lispapi.txt
# file.
#
# If you modify this file, please run:
#
#    pydoc lispapi.py > lispapi.txt
#
# So the API documentation stays up to date. Then commit lispapi.txt to the
# repo.
#
# -----------------------------------------------------------------------------
from __future__ import print_function
from builtins import str
from builtins import range
from builtins import object
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
if 94 - 94: i1IIi % Oo0Ooo
if 68 - 68: Ii1I / O0
if 46 - 46: O0 * II111iiii / IiII * Oo0Ooo * iII111i . I11i
if 62 - 62: i11iIiiIii - II111iiii % I1Ii111 - iIii1I11I1II1 . I1ii11iIi11i . II111iiii
if 61 - 61: oO0o / OoOoOO00 / iII111i * OoO0O00 . II111iiii
if 1 - 1: II111iiii - I1ii11iIi11i % i11iIiiIii + IiII . I1Ii111
if 55 - 55: iIii1I11I1II1 - I1IiiI . Ii1I * IiII * i1IIi / iIii1I11I1II1
if 79 - 79: oO0o + I1Ii111 . ooOoO0o * IiII % I11i . I1IiiI
if 94 - 94: iII111i * Ii1I / IiII . i1IIi * iII111i
if 47 - 47: i1IIi % i11iIiiIii
if 20 - 20: ooOoO0o * II111iiii
if 65 - 65: o0oOOo0O0Ooo * iIii1I11I1II1 * ooOoO0o
if 18 - 18: iIii1I11I1II1 / I11i + oO0o / Oo0Ooo - II111iiii - I11i
if 1 - 1: I11i - OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
if 13 - 13: OOooOOo * oO0o * I1IiiI
if 55 - 55: II111iiii
if 43 - 43: OoOoOO00 - i1IIi + I1Ii111 + Ii1I
if 17 - 17: o0oOOo0O0Ooo
if 64 - 64: Ii1I % i1IIi % OoooooooOO
if 3 - 3: iII111i + O0
import requests
import json
import os
from builtins import str as uc
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
REQ_TIMEOUT = 3
if 78 - 78: OoO0O00
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
class api_init ( object ) :
 def __init__ ( self , host , user , pw = None , port = 8080 , api_debug = False ,
 do_get = True ) :
  if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
  if 14 - 14: I11i % O0
  if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
  if 77 - 77: Oo0Ooo . IiII % ooOoO0o
  if 42 - 42: oO0o - i1IIi / i11iIiiIii + OOooOOo + OoO0O00
  if 17 - 17: oO0o . Oo0Ooo . I1ii11iIi11i
  if 3 - 3: OoOoOO00 . Oo0Ooo . I1IiiI / Ii1I
  self . host = host
  self . user = user
  if ( pw == None ) : pw = os . getenv ( "LISPAPI_PW_" + host )
  if ( pw == None ) : pw = os . getenv ( "LISPAPI_PW" )
  self . pw = pw
  if 38 - 38: II111iiii % i11iIiiIii . ooOoO0o - OOooOOo + Ii1I
  Ooooo0Oo00oO0 = "https://"
  if ( port < 0 ) :
   port = - port
   Ooooo0Oo00oO0 = Ooooo0Oo00oO0 . replace ( "s" , "" )
   if 12 - 12: iIii1I11I1II1 * I1IiiI . ooOoO0o % I11i + O0
  self . url = Ooooo0Oo00oO0 + self . host + ":{}/lisp/api/" . format ( str ( port ) )
  if 70 - 70: Ii1I . oO0o * ooOoO0o . Ii1I
  self . enable_status = None
  self . debug_status = None
  self . api_debug = api_debug
  self . enable_status = None
  self . debug_status = None
  self . xtr_parameters = None
  if 35 - 35: o0oOOo0O0Ooo + iII111i + iII111i
  if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
  if 74 - 74: iII111i * O0
  if 89 - 89: oO0o + Oo0Ooo
  if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
  if ( do_get ) :
   self . get_enable ( )
   self . get_debug ( )
   self . get_xtr_parameters ( )
   if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
   if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
   if 20 - 20: o0oOOo0O0Ooo
 def api_print ( self ) :
  print ( "url: {}@{}, enable-status: {}, debug-status: {}" . format ( self . user , self . url , self . enable_status , self . debug_status ) )
  if 77 - 77: OoOoOO00 / I11i
  if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
  if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
  if 95 - 95: OoO0O00 % oO0o . O0
 def api_enable_debug ( self ) :
  self . api_debug = True
  if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
  if 53 - 53: IiII + I1IiiI * oO0o
  if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
 def api_disable_debug ( self ) :
  self . api_debug = False
  if 60 - 60: I11i / I11i
  if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
  if 83 - 83: OoooooooOO
 def get_enable ( self , force_query = False ) :
  if ( force_query == False and self . enable_status != None ) :
   if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
   if 4 - 4: II111iiii / ooOoO0o . iII111i
   if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
   return ( self . enable_status )
   if 50 - 50: I1IiiI
  Ii1i11IIii1I = self . __get ( "lisp enable" )
  self . enable_status = Ii1i11IIii1I
  return ( Ii1i11IIii1I )
  if 52 - 52: o0oOOo0O0Ooo - OoooooooOO + Ii1I + Ii1I - o0oOOo0O0Ooo / I1Ii111
  if 44 - 44: ooOoO0o . i1IIi - I1ii11iIi11i . O0 - ooOoO0o
 def get_debug ( self ) :
  if ( self . debug_status != None ) : return ( self . debug_status )
  if 92 - 92: iII111i . I11i + o0oOOo0O0Ooo
  if 28 - 28: i1IIi * Oo0Ooo - o0oOOo0O0Ooo * IiII * Ii1I / OoO0O00
  if 94 - 94: II111iiii % I1ii11iIi11i / OoOoOO00 * iIii1I11I1II1
  Ii1i11IIii1I = self . __get ( "lisp debug" )
  self . debug_status = Ii1i11IIii1I
  return ( Ii1i11IIii1I )
  if 54 - 54: o0oOOo0O0Ooo - I1IiiI + OoooooooOO
  if 70 - 70: Ii1I / I11i . iII111i % Oo0Ooo
 def get_xtr_parameters ( self ) :
  if ( self . xtr_parameters != None ) : return ( self . xtr_parameters )
  if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . IiII - OoO0O00 * o0oOOo0O0Ooo
  if 46 - 46: OOooOOo + OoOoOO00 . I1IiiI * oO0o % IiII
  if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
  Ii1i11IIii1I = self . __get ( "lisp xtr-parameters" )
  self . xtr_parameters = Ii1i11IIii1I
  return ( Ii1i11IIii1I )
  if 44 - 44: oO0o
  if 88 - 88: I1Ii111 % Ii1I . II111iiii
 def is_itr_enabled ( self ) :
  return ( self . enable_status and self . enable_status [ "itr" ] == "yes" )
  if 38 - 38: o0oOOo0O0Ooo
  if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
  if 26 - 26: iII111i
 def is_etr_enabled ( self ) :
  return ( self . enable_status and self . enable_status [ "etr" ] == "yes" )
  if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
  if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
  if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
 def is_rtr_enabled ( self ) :
  return ( self . enable_status and self . enable_status [ "rtr" ] == "yes" )
  if 91 - 91: oO0o % Oo0Ooo
  if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
  if 31 - 31: I11i - II111iiii . I11i
 def is_mr_enabled ( self ) :
  return ( self . enable_status and
  # o0oOOo0O0Ooo . ooOoO0o
 self . enable_status [ "map-resolver" ] == "yes" )
  if 54 - 54: II111iiii % OoOoOO00 % I11i % iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
  if 87 - 87: ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 def is_ms_enabled ( self ) :
  return ( self . enable_status and
  # iII111i - iIii1I11I1II1 * i11iIiiIii / I1ii11iIi11i * I1Ii111
 self . enable_status [ "map-server" ] == "yes" )
  if 23 - 23: iII111i
  if 91 - 91: iIii1I11I1II1 + I1Ii111
 def is_ddt_enabled ( self ) :
  return ( self . enable_status and self . enable_status [ "ddt-node" ] == "yes" )
  if 31 - 31: IiII . OoOoOO00 . OOooOOo
  if 75 - 75: I11i + OoO0O00 . OoOoOO00 . ooOoO0o + Oo0Ooo . OoO0O00
  if 96 - 96: OOooOOo . ooOoO0o - Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * OOooOOo
 def is_itr_debug_enabled ( self ) :
  return ( self . debug_status and self . debug_status [ "itr" ] == "yes" )
  if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
  if 21 - 21: I1IiiI * iIii1I11I1II1
  if 91 - 91: IiII
 def is_etr_debug_enabled ( self ) :
  return ( self . debug_status and self . debug_status [ "etr" ] == "yes" )
  if 15 - 15: II111iiii
  if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
  if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
 def is_rtr_debug_enabled ( self ) :
  return ( self . debug_status and self . debug_status [ "rtr" ] == "yes" )
  if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
  if 91 - 91: O0
  if 61 - 61: II111iiii
 def is_mr_debug_enabled ( self ) :
  return ( self . debug_status and
  # I1IiiI - o0oOOo0O0Ooo * oO0o + O0
 self . debug_status [ "map-resolver" ] == "yes" )
  if 71 - 71: Ii1I - i1IIi % i1IIi + OoOoOO00 + O0 + OoO0O00
  if 67 - 67: I1Ii111 . iII111i . O0
 def is_ms_debug_enabled ( self ) :
  return ( self . debug_status and self . debug_status [ "map-server" ] == "yes" )
  if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
  if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
  if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 def is_ddt_debug_enabled ( self ) :
  return ( self . debug_status and self . debug_status [ "ddt-node" ] == "yes" )
  if 83 - 83: I11i / I1IiiI
  if 34 - 34: IiII
  if 57 - 57: oO0o . I11i . i1IIi
 def enable_itr ( self ) :
  if ( self . enable_status == None ) : return
  if 42 - 42: I11i + I1ii11iIi11i % O0
  if 6 - 6: oO0o
  self . enable_status [ "itr" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp enable" , self . enable_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 68 - 68: OoOoOO00 - OoO0O00
  if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
 def enable_etr ( self ) :
  if ( self . enable_status == None ) : return
  if 1 - 1: iIii1I11I1II1 / II111iiii
  if 33 - 33: I11i
  self . enable_status [ "etr" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp enable" , self . enable_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
  if 87 - 87: i11iIiiIii
 def enable_rtr ( self ) :
  if ( self . enable_status == None ) : return
  if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
  if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
  self . enable_status [ "rtr" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp enable" , self . enable_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
  if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 def enable_mr ( self ) :
  if ( self . enable_status == None ) : return
  if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
  if 51 - 51: O0 + iII111i
  self . enable_status [ "map-resolver" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp enable" , self . enable_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
  if 48 - 48: O0
 def enable_ms ( self ) :
  if ( self . enable_status == None ) : return
  if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
  if 41 - 41: Ii1I - O0 - O0
  self . enable_status [ "map-server" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp enable" , self . enable_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 68 - 68: OOooOOo % I1Ii111
  if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 def enable_ddt ( self ) :
  if ( self . enable_status == None ) : return
  if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
  if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
  self . enable_status [ "ddt-node" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp enable" , self . enable_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 23 - 23: O0
  if 85 - 85: Ii1I
 def disable_itr ( self ) :
  if ( self . enable_status == None ) : return
  if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
  if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
  self . enable_status [ "itr" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp enable" , self . enable_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
  if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
 def disable_etr ( self ) :
  if ( self . enable_status == None ) : return
  if 77 - 77: iIii1I11I1II1 * OoO0O00
  if 95 - 95: I1IiiI + i11iIiiIii
  self . enable_status [ "etr" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp enable" , self . enable_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
  if 80 - 80: II111iiii
 def disable_rtr ( self ) :
  if ( self . enable_status == None ) : return
  if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
  if 53 - 53: II111iiii
  self . enable_status [ "rtr" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp enable" , self . enable_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 31 - 31: OoO0O00
  if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
 def disable_mr ( self ) :
  if ( self . enable_status == None ) : return
  if 25 - 25: OoO0O00
  if 62 - 62: OOooOOo + O0
  self . enable_status [ "map-resolver" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp enable" , self . enable_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 98 - 98: o0oOOo0O0Ooo
  if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
 def disable_ms ( self ) :
  if ( self . enable_status == None ) : return
  if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
  if 82 - 82: Ii1I
  self . enable_status [ "map-server" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp enable" , self . enable_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 46 - 46: OoooooooOO . i11iIiiIii
  if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 def disable_ddt ( self ) :
  if ( self . enable_status == None ) : return
  if 87 - 87: Oo0Ooo . IiII
  if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
  self . enable_status [ "ddt-node" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp enable" , self . enable_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 55 - 55: OOooOOo . I1IiiI
  if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
 def enable_core_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 100 - 100: I1Ii111 * O0
  if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
  self . debug_status [ "core" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 79 - 79: O0
  if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
 def enable_itr_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
  if 57 - 57: OoO0O00 / ooOoO0o
  self . debug_status [ "itr" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
  if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
 def enable_etr_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 13 - 13: Ii1I . i11iIiiIii
  if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
  self . debug_status [ "etr" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
  if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 def enable_rtr_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
  if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
  self . debug_status [ "rtr" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
  if 63 - 63: OoOoOO00 * iII111i
 def enable_mr_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 69 - 69: O0 . OoO0O00
  if 49 - 49: I1IiiI - I11i
  self . debug_status [ "map-resolver" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
  if 62 - 62: OoooooooOO * I1IiiI
 def enable_ms_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
  self . debug_status [ "map-server" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 97 - 97: O0 + OoOoOO00
  if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 def enable_ddt_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
  if 77 - 77: OOooOOo * iIii1I11I1II1
  self . debug_status [ "ddt-node" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 98 - 98: I1IiiI % Ii1I * OoooooooOO
  if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 def disable_core_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
  if 71 - 71: Oo0Ooo % OOooOOo
  self . debug_status [ "core" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
  if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 def disable_itr_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 69 - 69: I1Ii111
  if 11 - 11: I1IiiI
  self . debug_status [ "itr" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
  if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
 def disable_etr_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
  if 71 - 71: I1Ii111 + Ii1I
  self . debug_status [ "etr" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 28 - 28: OOooOOo
  if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
 def disable_rtr_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
  if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
  self . debug_status [ "rtr" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
  if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 def disable_mr_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
  if 26 - 26: Ii1I % I1ii11iIi11i
  self . debug_status [ "map-resolver" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 76 - 76: IiII * iII111i
  if 52 - 52: OOooOOo
 def disable_ms_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 19 - 19: I1IiiI
  if 25 - 25: Ii1I / ooOoO0o
  self . debug_status [ "map-server" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
  if 71 - 71: I1Ii111 . II111iiii
 def disable_ddt_debug ( self ) :
  if ( self . debug_status == None ) : return
  if 62 - 62: OoooooooOO . I11i
  if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
  self . debug_status [ "ddt-node" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp debug" , self . debug_status )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 58 - 58: I1IiiI
 def add_user_account ( self , username , password ) :
  if ( self . enable_status == None ) : return
  if 53 - 53: i1IIi
  if 59 - 59: o0oOOo0O0Ooo
  Ii1i11IIii1I = self . __put ( "lisp user-account" ,
 { "username" : username , "password" : password } )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
  if 73 - 73: I11i % i11iIiiIii - I1IiiI
 def delete_user_account ( self , username ) :
  if ( self . enable_status == None ) : return
  if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
  if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
  Ii1i11IIii1I = self . __delete ( "lisp user-account" , { "username" : username } )
  return ( self . __error ( Ii1i11IIii1I ) == False )
  if 23 - 23: i11iIiiIii
  if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
 def enable_itr_security ( self ) :
  if ( self . enable_status == None ) : return
  if 81 - 81: IiII % i1IIi . iIii1I11I1II1
  if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
  self . xtr_parameters [ "data-plane-security" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp xtr-parameters" , self . xtr_parameters )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
  if 31 - 31: OOooOOo
 def disable_itr_security ( self ) :
  if ( self . enable_status == None ) : return
  if 23 - 23: I1Ii111 . IiII
  if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
  self . xtr_parameters [ "data-plane-security" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp xtr-parameters" , self . xtr_parameters )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 42 - 42: Oo0Ooo
  if 76 - 76: I1IiiI * iII111i % I1Ii111
 def enable_xtr_nat_traversal ( self ) :
  if ( self . enable_status == None ) : return
  if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
  if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
  if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
  if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
  self . xtr_parameters [ "nat-traversal" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp xtr-parameters" , self . xtr_parameters )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
  if 42 - 42: I1IiiI
 def disable_xtr_nat_traversal ( self ) :
  if ( self . enable_status == None ) : return
  if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
  if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
  self . xtr_parameters [ "nat-traversal" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp xtr-parameters" , self . xtr_parameters )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
  if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
 def enable_xtr_rloc_probing ( self ) :
  if ( self . enable_status == None ) : return
  if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
  if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
  self . xtr_parameters [ "rloc-probing" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp xtr-parameters" , self . xtr_parameters )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
  if 79 - 79: O0 * i11iIiiIii - IiII / IiII
 def disable_xtr_rloc_probing ( self ) :
  if ( self . enable_status == None ) : return
  if 48 - 48: O0
  if 93 - 93: i11iIiiIii - I1IiiI * I1ii11iIi11i * I11i % O0 + OoooooooOO
  self . xtr_parameters [ "rloc-probing" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp xtr-parameters" , self . xtr_parameters )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
  if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
 def enable_xtr_nonce_echoing ( self ) :
  if ( self . enable_status == None ) : return
  if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
  if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
  self . xtr_parameters [ "nonce-echoing" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp xtr-parameters" , self . xtr_parameters )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 19 - 19: OoO0O00 - Oo0Ooo . O0
  if 60 - 60: II111iiii + Oo0Ooo
 def disable_xtr_nonce_echoing ( self ) :
  if ( self . enable_status == None ) : return
  if 9 - 9: ooOoO0o * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
  if 49 - 49: II111iiii
  self . xtr_parameters [ "nonce-echoing" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp xtr-parameters" , self . xtr_parameters )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 25 - 25: OoooooooOO - I1IiiI . I1IiiI * oO0o
  if 81 - 81: iII111i + IiII
 def enable_xtr_data_plane_logging ( self ) :
  if ( self . enable_status == None ) : return
  if 98 - 98: I1IiiI
  if 95 - 95: ooOoO0o / ooOoO0o
  self . xtr_parameters [ "data-plane-logging" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp xtr-parameters" , self . xtr_parameters )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
  if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 def disable_xtr_data_plane_logging ( self ) :
  if ( self . enable_status == None ) : return
  if 41 - 41: i1IIi - I11i - Ii1I
  if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
  self . xtr_parameters [ "data-plane-logging" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp xtr-parameters" , self . xtr_parameters )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
  if 44 - 44: II111iiii
 def enable_xtr_flow_logging ( self ) :
  if ( self . enable_status == None ) : return
  if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
  if 35 - 35: iIii1I11I1II1
  self . xtr_parameters [ "flow-logging" ] = "yes"
  Ii1i11IIii1I = self . __put ( "lisp xtr-parameters" , self . xtr_parameters )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 42 - 42: I1Ii111 . I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI
  if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
 def disable_xtr_flow_logging ( self ) :
  if ( self . enable_status == None ) : return
  if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
  if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
  self . xtr_parameters [ "flow-logging" ] = "no"
  Ii1i11IIii1I = self . __put ( "lisp xtr-parameters" , self . xtr_parameters )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
  if 71 - 71: O0 - iIii1I11I1II1
 def add_mr_ddt_root ( self , address = "" ) :
  if ( address == "" ) : return ( "no address supplied" )
  if 12 - 12: OOooOOo / o0oOOo0O0Ooo
  if 42 - 42: Oo0Ooo
  if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
  if 46 - 46: Oo0Ooo
  if ( self . __check_address_syntax ( address ) == False ) :
   return ( "bad address syntax" )
   if 1 - 1: iII111i
   if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
  if ( self . enable_status == None ) : return
  if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
  Ii1i11IIii1I = self . __put ( "lisp ddt-root" , { "address" : address } )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
  if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 def delete_mr_ddt_root ( self , address = "" ) :
  if ( address == "" ) : return ( "no address supplied" )
  if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
  if 17 - 17: i1IIi
  if 21 - 21: Oo0Ooo
  if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
  if ( self . __check_address_syntax ( address ) == False ) :
   return ( "bad address syntax" )
   if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
   if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
  if ( self . enable_status == None ) : return
  if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
  Ii1i11IIii1I = self . __delete ( "lisp ddt-root" , { "address" : address } )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "delete error" )
  return ( "good" )
  if 54 - 54: i1IIi + II111iiii
  if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 def add_mr_referral ( self , iid = "0" , prefix = "" , group = "" , referral_set = [ ] ) :
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if 5 - 5: Ii1I
  if 46 - 46: IiII
  if 45 - 45: ooOoO0o
  if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
  if 17 - 17: OOooOOo / OOooOOo / I11i
  if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
  if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
  if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
  if ( referral_set == "" ) : return ( "no referral-set supplied" )
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 9 - 9: Ii1I
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 59 - 59: I1IiiI * II111iiii . O0
  if ( self . __check_address_set_syntax ( referral_set , False ) == False ) :
   return ( "bad address syntax in referral-set" )
   if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
   if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
  if ( self . enable_status == None ) : return
  if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group )
  Ii1i11IIii1I = [ Ii1i11IIii1I ]
  for i1 in referral_set :
   Ii1i11IIii1I . append ( { "referral" : { "address" : i1 } } )
   if 51 - 51: OoO0O00 - O0 % oO0o - II111iiii
  Ii1i11IIii1I = self . __put ( "lisp referral-cache" , Ii1i11IIii1I )
  if 31 - 31: iII111i / Oo0Ooo - iII111i - OOooOOo
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 7 - 7: iII111i % O0 . OoOoOO00 + I1IiiI - I11i
  if 75 - 75: I11i
 def delete_mr_referral ( self , iid = "0" , prefix = "" , group = "" ) :
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if 71 - 71: ooOoO0o
  if 53 - 53: OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
  if 28 - 28: I11i
  if 58 - 58: OoOoOO00
  if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 73 - 73: i11iIiiIii - IiII
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
   if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
  if ( self . enable_status == None ) : return
  if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group )
  Ii1i11IIii1I = self . __delete ( "lisp referral-cache" , Ii1i11IIii1I )
  if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "delete error" )
  return ( "good" )
  if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
  if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
 def add_ddt_delegation ( self , iid = "0" , prefix = "" , group = "" ,
 referral_set = [ ] ) :
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
  if 97 - 97: I1IiiI / iII111i
  if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
  if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
  if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
  if 100 - 100: OoO0O00
  if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
  if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
  if ( referral_set == "" ) : return ( "no referral-set supplied" )
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 45 - 45: I1Ii111
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 83 - 83: OoOoOO00 . OoooooooOO
  if ( self . __check_address_set_syntax ( referral_set , False ) == False ) :
   return ( "bad address syntax in referral-set" )
   if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
   if 62 - 62: OoO0O00 / I1ii11iIi11i
  if ( self . enable_status == None ) : return
  if 7 - 7: OoooooooOO . IiII
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group )
  Ii1i11IIii1I = [ Ii1i11IIii1I ]
  for i1 in referral_set :
   Ii1i11IIii1I . append ( { "delegate" : { "address" : i1 } } )
   if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
   if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
  Ii1i11IIii1I = self . __put ( "lisp delegation" , Ii1i11IIii1I )
  if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 92 - 92: ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 def delete_ddt_delegation ( self , iid = "0" , prefix = "" , group = "" ) :
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  if 92 - 92: I11i . I1Ii111
  if 85 - 85: I1ii11iIi11i . I1Ii111
  if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 18 - 18: iIii1I11I1II1 % I11i
   if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
  if ( self . enable_status == None ) : return
  if 75 - 75: OoooooooOO * IiII
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group )
  Ii1i11IIii1I = self . __delete ( "lisp delegation" , Ii1i11IIii1I )
  if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "delete error" )
  return ( "good" )
  if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
  if 69 - 69: O0
 def add_ddt_auth_prefix ( self , iid = "0" , auth_prefix = "" , group = "" ) :
  if ( auth_prefix == "" ) : return ( "no prefix supplied" )
  if 85 - 85: ooOoO0o / O0
  if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
  if 62 - 62: I1Ii111 . IiII . OoooooooOO
  if 11 - 11: OOooOOo / I11i
  if ( self . __check_prefix_syntax ( auth_prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 73 - 73: i1IIi / i11iIiiIii
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
   if 85 - 85: OoOoOO00 + OOooOOo
  if ( self . enable_status == None ) : return
  if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , auth_prefix , group )
  Ii1i11IIii1I = [ Ii1i11IIii1I [ "prefix" ] ]
  Ii1i11IIii1I = self . __put ( "lisp ddt-authoritative-prefix" , Ii1i11IIii1I )
  if 27 - 27: Ii1I
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 67 - 67: I1IiiI
  if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
 def delete_ddt_auth_prefix ( self , iid = "0" , auth_prefix = "" , group = "" ) :
  if ( auth_prefix == "" ) : return ( "no auth-prefix supplied" )
  if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
  if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
  if 92 - 92: Oo0Ooo
  if 40 - 40: OoOoOO00 / IiII
  if ( self . __check_prefix_syntax ( auth_prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
   if 61 - 61: II111iiii
  if ( self . enable_status == None ) : return
  if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , auth_prefix , group )
  Ii1i11IIii1I = self . __delete ( "lisp ddt-authoritative-prefix" , Ii1i11IIii1I )
  if 90 - 90: iII111i
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "delete error" )
  return ( "good" )
  if 31 - 31: OOooOOo + O0
  if 87 - 87: ooOoO0o
 def add_ms_map_server_peer ( self , iid = "0" , prefix = "" , group = "" ,
 peer_set = [ ] ) :
  if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
  if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
  if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
  if 13 - 13: Oo0Ooo
  if 60 - 60: I1ii11iIi11i * I1IiiI
  if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
  if 41 - 41: Ii1I
  if 77 - 77: I1Ii111
  if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
  if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
  if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
  if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
  if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if ( peer_set == "" ) : return ( "no peer-set supplied" )
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
  if ( self . __check_address_set_syntax ( peer_set , False ) == False ) :
   return ( "bad address syntax in referral-set" )
   if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
   if 95 - 95: IiII
  if ( self . enable_status == None ) : return
  if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group )
  Ii1i11IIii1I = [ Ii1i11IIii1I ]
  for OOoOoo0 in peer_set :
   Ii1i11IIii1I . append ( { "peer" : { "address" : OOoOoo0 } } )
   if 17 - 17: Ii1I + oO0o . OoO0O00 - Oo0Ooo * i11iIiiIii
   if 20 - 20: I1IiiI . OoooooooOO % OOooOOo
  Ii1i11IIii1I = self . __put ( "lisp map-server-peer" , Ii1i11IIii1I )
  if 63 - 63: I1IiiI % iIii1I11I1II1
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
  if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 def delete_ms_map_server_peer ( self , iid = "0" , prefix = "" , group = "" ) :
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if 59 - 59: OOooOOo + i11iIiiIii
  if 88 - 88: i11iIiiIii - ooOoO0o
  if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
  if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
  if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 30 - 30: OoOoOO00
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
   if 26 - 26: II111iiii * OoOoOO00
  if ( self . enable_status == None ) : return
  if 10 - 10: II111iiii . iII111i
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group )
  Ii1i11IIii1I = self . __delete ( "lisp map-server-peer" , Ii1i11IIii1I )
  if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "delete error" )
  return ( "good" )
  if 88 - 88: iII111i
  if 19 - 19: II111iiii * IiII + Ii1I
 def add_ms_site ( self , site_name , auth_key , prefix_list , description = "" ) :
  if ( site_name == "" ) : return ( "no site-name supplied" )
  if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
  if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
  if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
  if ( auth_key == "" ) : return ( "no auth_key supplied" )
  if 67 - 67: I11i - OOooOOo . i1IIi
  I1I1iI = self . __check_prefix_list ( prefix_list )
  if ( I1I1iI != True ) : return ( I1I1iI )
  if 16 - 16: IiII * OoOoOO00 . ooOoO0o / i1IIi . OoO0O00 - i1IIi
  if ( self . enable_status == None ) : return
  if 46 - 46: IiII + iIii1I11I1II1 + OOooOOo + OoO0O00 . I1ii11iIi11i
  Ii1i11IIii1I = [ ]
  Ii1i11IIii1I . append ( { "site-name" : site_name } )
  Ii1i11IIii1I . append ( { "description" : description } )
  Ii1i11IIii1I . append ( { "authentication-key" : auth_key } )
  Ii1i11IIii1I . append ( prefix_list )
  Ii1i11IIii1I = self . __put ( "lisp site" , Ii1i11IIii1I )
  if 1 - 1: oO0o
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 62 - 62: i1IIi - OOooOOo
  if 96 - 96: i1IIi . I1ii11iIi11i + oO0o
 def build_ms_site_allowed_prefix ( self , prefix_list , iid = "0" , prefix = "" ,
 group = "" , ams = False , fpr = False , fnpr = False , pprd = False , pra = "" ) :
  if 48 - 48: iIii1I11I1II1 % i1IIi % iII111i + ooOoO0o
  if 30 - 30: i11iIiiIii % iIii1I11I1II1 . I11i % iIii1I11I1II1
  if 62 - 62: Oo0Ooo * OoOoOO00
  if 79 - 79: OoO0O00 . iII111i * Ii1I - OOooOOo + ooOoO0o
  if 14 - 14: i11iIiiIii - iII111i * OoOoOO00
  if 51 - 51: I1ii11iIi11i / iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo * ooOoO0o + I1Ii111
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 77 - 77: ooOoO0o * OoOoOO00
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 14 - 14: I11i % I11i / IiII
   if 72 - 72: i1IIi - II111iiii - OOooOOo + OOooOOo * o0oOOo0O0Ooo * OOooOOo
  if ( self . enable_status == None ) : return
  if 33 - 33: Oo0Ooo
  if 49 - 49: OoO0O00 % iII111i % iII111i / iII111i
  if 53 - 53: iIii1I11I1II1
  if 68 - 68: OoooooooOO % II111iiii
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group ,
 kw = "allowed-prefix" )
  Ii1i1i1111 = Ii1i11IIii1I [ "allowed-prefix" ]
  if ( ams ) : Ii1i1i1111 [ "accept-more-specifics" ] = "yes"
  if ( fpr ) : Ii1i1i1111 [ "force-proxy-reply" ] = "yes"
  if ( fnpr ) : Ii1i1i1111 [ "force-nat-proxy-reply" ] = "yes"
  if ( pprd ) : Ii1i1i1111 [ "pitr-proxy-reply-drop" ] = "yes"
  if ( pra != "" ) : Ii1i1i1111 [ "proxy-reply-action" ] = pra
  if 57 - 57: Ii1I % II111iiii
  prefix_list . append ( Ii1i11IIii1I )
  return ( "good" )
  if 67 - 67: ooOoO0o + I1IiiI * i11iIiiIii - oO0o / IiII % iII111i
  if 92 - 92: Ii1I - oO0o - ooOoO0o % OoooooooOO / OOooOOo
 def delete_ms_site ( self , site_name ) :
  if 19 - 19: Oo0Ooo - OoO0O00
  if 56 - 56: I1ii11iIi11i
  if 26 - 26: OoooooooOO % OoooooooOO
  if 33 - 33: I1Ii111
  if ( site_name == "" ) : return ( "no site-name supplied" )
  if ( self . enable_status == None ) : return
  if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
  Ii1i11IIii1I = self . __delete ( "lisp site" , { "site-name" : site_name } )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "delete error" )
  return ( "good" )
  if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
  if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 def add_etr_database_mapping ( self , iid = "0" , prefix = "" , group = "" ,
 rloc_set = [ ] ) :
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
  if 45 - 45: IiII
  if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
  if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
  if ( rloc_set == "" ) : return ( "no rloc-set supplied" )
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 34 - 34: O0
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
  if ( self . __check_address_set_syntax ( rloc_set , True ) == False ) :
   return ( "bad address syntax in rloc-set" )
   if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
   if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
  if ( self . enable_status == None ) : return
  if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group )
  Ii1i11IIii1I = [ Ii1i11IIii1I ]
  for i1 in rloc_set :
   if ( type ( i1 ) == dict ) :
    Ii1i11IIii1I . append ( { "rloc" : i1 } )
    continue
    if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
    if 91 - 91: oO0o + OoooooooOO - i1IIi
   if ( i1 in [ "en0" , "en1" , "eth0" , "eth1" ] ) :
    Ii1i11IIii1I . append ( { "rloc" : { "interface" : i1 } } )
   else :
    if ( self . __is_dist_name ( i1 ) ) :
     Ii1i11IIii1I . append ( { "rloc" : { "rloc-record-name" : i1 } } )
    else :
     Ii1i11IIii1I . append ( { "rloc" : { "address" : i1 } } )
     if 84 - 84: Ii1I / IiII
     if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
     if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
     if 37 - 37: i11iIiiIii + i1IIi
  Ii1i11IIii1I = self . __put ( "lisp database-mapping" , Ii1i11IIii1I )
  if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
  if 8 - 8: o0oOOo0O0Ooo
 def delete_etr_database_mapping ( self , iid = "0" , prefix = "" , group = "" ) :
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 78 - 78: Ii1I / II111iiii % OoOoOO00
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 52 - 52: OOooOOo - iII111i * oO0o
   if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
  if ( self . enable_status == None ) : return
  if 36 - 36: O0 + Oo0Ooo
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group )
  Ii1i11IIii1I = self . __delete ( "lisp database-mapping" , Ii1i11IIii1I )
  if 5 - 5: Oo0Ooo * OoOoOO00
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "delete error" )
  return ( "good" )
  if 46 - 46: ooOoO0o
  if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 def add_etr_map_server ( self , address = "" , auth_key = None ,
 address_is_name = False ) :
  if ( address == "" ) : return ( "no address supplied" )
  if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
  if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
  if 72 - 72: i1IIi
  if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
  if 63 - 63: I1ii11iIi11i
  if ( address_is_name == False ) :
   if ( self . __check_address_syntax ( address ) == False ) :
    return ( "bad address syntax" )
    if 6 - 6: ooOoO0o / I1ii11iIi11i
   oOooO00o0O = "address"
  else :
   oOooO00o0O = "dns-name"
   if 80 - 80: OOooOOo / I11i / OoOoOO00 + i1IIi - Oo0Ooo
   if 11 - 11: o0oOOo0O0Ooo * OoO0O00
  if ( auth_key == None ) : return ( "no auth-key supplied" )
  if 15 - 15: OoOoOO00
  if ( self . enable_status == None ) : return
  if 62 - 62: Ii1I
  Ii1i11IIii1I = self . __put ( "lisp map-server" ,
 { oOooO00o0O : address , "authentication-type" : "sha2" ,
 "authentication-key" : auth_key } )
  if 51 - 51: OoOoOO00
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
  if 53 - 53: Ii1I % Oo0Ooo
 def get_etr_map_server ( self , address , address_is_name = False ) :
  if ( self . enable_status == None ) : return
  if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
  if 41 - 41: Ii1I % I1ii11iIi11i
  if 12 - 12: OOooOOo
  if 69 - 69: OoooooooOO + OOooOOo
  if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
  if ( address == "" ) : return ( "no address supplied" )
  if 31 - 31: I11i % OOooOOo * I11i
  if ( address_is_name == False ) :
   if ( self . __check_address_syntax ( address ) == False ) :
    return ( "bad address syntax" )
    if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
   oOooO00o0O = "address"
  else :
   oOooO00o0O = "dns-name"
   if 1 - 1: iIii1I11I1II1
   if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
  Ii1i11IIii1I = self . __get_data ( "lisp map-server" , { oOooO00o0O : address } )
  return ( Ii1i11IIii1I )
  if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
  if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 def delete_etr_map_server ( self , address , address_is_name = False ) :
  if ( address == "" ) : return ( "no address supplied" )
  if 4 - 4: OoooooooOO . ooOoO0o
  if 78 - 78: I1ii11iIi11i + I11i - O0
  if 10 - 10: I1Ii111 % I1IiiI
  if 97 - 97: OoooooooOO - I1Ii111
  if 58 - 58: iIii1I11I1II1 + O0
  if ( address_is_name == False ) :
   if ( self . __check_address_syntax ( address ) == False ) :
    return ( "bad address syntax" )
    if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
   oOooO00o0O = "address"
  else :
   oOooO00o0O = "dns-name"
   if 46 - 46: i11iIiiIii - O0 . oO0o
   if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
  if ( self . enable_status == None ) : return
  if 83 - 83: I1Ii111
  Ii1i11IIii1I = self . __delete ( "lisp map-server" , { oOooO00o0O : address } )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "delete error" )
  return ( "good" )
  if 48 - 48: II111iiii * OOooOOo * I1Ii111
  if 50 - 50: IiII % i1IIi
 def add_itr_map_resolver ( self , address , address_is_name = False ) :
  if ( address == "" ) : return ( "no address supplied" )
  if 21 - 21: OoooooooOO - iIii1I11I1II1
  if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
  if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
  if 62 - 62: i1IIi - OoOoOO00
  if ( address_is_name == False ) :
   if ( self . __check_address_syntax ( address ) == False ) :
    return ( "bad address syntax" )
    if 62 - 62: i1IIi + Oo0Ooo % IiII
   oOooO00o0O = "address"
  else :
   oOooO00o0O = "dns-name"
   if 28 - 28: I1ii11iIi11i . i1IIi
   if 10 - 10: OoO0O00 / Oo0Ooo
  if ( self . enable_status == None ) : return
  if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
  Ii1i11IIii1I = self . __put ( "lisp map-resolver" , { oOooO00o0O : address } )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 57 - 57: O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 def get_itr_map_resolver ( self , address , address_is_name = False ) :
  if ( self . enable_status == None ) : return
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
  if 39 - 39: iIii1I11I1II1 - OoooooooOO
  if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
  if 23 - 23: II111iiii / oO0o
  if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
  if ( address == "" ) : return ( "no address supplied" )
  if 19 - 19: I11i
  if ( address_is_name == False ) :
   if ( self . __check_address_syntax ( address ) == False ) :
    return ( "bad address syntax" )
    if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
   oOooO00o0O = "address"
  else :
   oOooO00o0O = "dns-name"
   if 27 - 27: OOooOOo
   if 89 - 89: II111iiii / oO0o
  Ii1i11IIii1I = self . __get_data ( "lisp map-resolver" , { oOooO00o0O : address } )
  return ( Ii1i11IIii1I )
  if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
  if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 def delete_itr_map_resolver ( self , address , address_is_name = False ) :
  if ( address == "" ) : return ( "no address supplied" )
  if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
  if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
  if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
  if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
  if 19 - 19: i11iIiiIii
  if ( address_is_name == False ) :
   if ( self . __check_address_syntax ( address ) == False ) :
    return ( "bad address syntax" )
    if 54 - 54: II111iiii . I11i
   oOooO00o0O = "address"
  else :
   oOooO00o0O = "dns-name"
   if 73 - 73: OoOoOO00 . I1IiiI
   if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
  if ( self . enable_status == None ) : return
  if 48 - 48: iII111i * iII111i
  Ii1i11IIii1I = self . __delete ( "lisp map-resolver" , { oOooO00o0O : address } )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "delete error" )
  return ( "good" )
  if 13 - 13: Ii1I / I11i + OoOoOO00 . o0oOOo0O0Ooo % ooOoO0o
  if 48 - 48: I1IiiI / i11iIiiIii - o0oOOo0O0Ooo * oO0o / OoooooooOO
 def build_rloc_record ( self , rloc_or_int , upriority , uweight ,
 rloc_name = None , mpriority = 255 , mweight = 0 , rloc_set = [ ] ) :
  OoOo = { }
  if 17 - 17: Ii1I . i11iIiiIii
  if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
  if 63 - 63: oO0o
  if ( rloc_or_int in [ "en0" , "en1" , "eth0" , "eth1" ] ) :
   OoOo [ "interface" ] = rloc_or_int
  else :
   OoOo [ "address" ] = rloc_or_int
   if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
  if ( rloc_name ) : OoOo [ "rloc-record-name" ] = rloc_name
  OoOo [ "priority" ] = upriority
  OoOo [ "weight" ] = uweight
  if 36 - 36: IiII
  if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
  rloc_set . append ( OoOo )
  return ( rloc_set )
  if 74 - 74: I1Ii111 % I1ii11iIi11i
  if 7 - 7: II111iiii
 def add_itr_map_cache ( self , iid = "0" , prefix = "" , group = "" , rloc_set = [ ] ) :
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
  if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
  if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
  if 49 - 49: I1ii11iIi11i
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 21 - 21: O0 * O0 % I1ii11iIi11i
  if ( self . __check_address_set_syntax ( rloc_set , False ) == False ) :
   return ( "bad address syntax in rloc-set" )
   if 94 - 94: I11i + II111iiii % i11iIiiIii
   if 8 - 8: ooOoO0o * O0
  if ( self . enable_status == None ) : return
  if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group )
  Ii1i11IIii1I = [ Ii1i11IIii1I ]
  for i1 in rloc_set :
   if ( type ( i1 ) == dict ) :
    Ii1i11IIii1I . append ( { "rloc" : i1 } )
    continue
    if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
   Ii1i11IIii1I . append ( { "rloc" : { "address" : i1 } } )
   if 34 - 34: ooOoO0o
   if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
  Ii1i11IIii1I = self . __put ( "lisp map-cache" , Ii1i11IIii1I )
  if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
  if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 def delete_itr_map_cache ( self , iid = "0" , prefix = "" , group = "" ) :
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 87 - 87: oO0o - i11iIiiIii
   if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
  if ( self . enable_status == None ) : return
  if 23 - 23: I11i
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group )
  Ii1i11IIii1I = self . __delete ( "lisp map-cache" , Ii1i11IIii1I )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "delete error" )
  return ( "good" )
  if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
  if 14 - 14: I1ii11iIi11i
 def get_system ( self ) :
  if ( self . enable_status == None ) : return
  if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
  if 56 - 56: OoooooooOO - I11i - i1IIi
  if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
  if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
  Ii1i11IIii1I = self . __get_data ( "lisp system" , "" )
  return ( Ii1i11IIii1I )
  if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
  if 53 - 53: I11i + iIii1I11I1II1
 def get_map_cache ( self ) :
  if ( self . enable_status == None ) : return
  if 70 - 70: I1ii11iIi11i
  if 67 - 67: OoooooooOO
  if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
  if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
  if 93 - 93: i1IIi
  Ii1i11IIii1I = self . __get_data ( "lisp map-cache" , "" )
  return ( Ii1i11IIii1I )
  if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
  if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 def get_map_cache_entry ( self , iid = "" , prefix = "" , group = "" ) :
  if 66 - 66: Oo0Ooo
  if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
  if 55 - 55: o0oOOo0O0Ooo . iII111i
  if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
  if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 89 - 89: OoO0O00 + IiII * I1Ii111
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
   if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
  if ( self . enable_status == None ) : return
  if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group )
  Ii1i11IIii1I = self . __get_data ( "lisp map-cache" , Ii1i11IIii1I )
  return ( Ii1i11IIii1I )
  if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
  if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 def get_site_cache ( self ) :
  if ( self . enable_status == None ) : return
  if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
  if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
  if 62 - 62: o0oOOo0O0Ooo
  if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
  if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
  Ii1i11IIii1I = self . __get_data ( "lisp site-cache" , "" )
  return ( Ii1i11IIii1I )
  if 72 - 72: iIii1I11I1II1
  if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 def get_site_cache_entry ( self , iid = "" , prefix = "" , group = "" ) :
  if ( self . enable_status == None ) : return
  if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
  if 87 - 87: OoO0O00 % I1IiiI
  if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
  if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
  if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
  if ( prefix == "" ) : return ( "no prefix supplied" )
  if ( self . __check_prefix_syntax ( prefix ) == False ) :
   return ( "bad prefix syntax" )
   if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
  if ( group != "" and self . __check_prefix_syntax ( group ) == False ) :
   return ( "bad group syntax" )
   if 84 - 84: i11iIiiIii * OoO0O00
   if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
  Ii1i11IIii1I = self . __build_prefix_tuple ( iid , prefix , group )
  Ii1i11IIii1I = self . __get_data ( "lisp site-cache" , Ii1i11IIii1I )
  return ( Ii1i11IIii1I )
  if 30 - 30: O0 + I1ii11iIi11i + II111iiii
  if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 def add_policy ( self , policy_name , match_iid = "0" , match_seid = "" ,
 match_deid = "" , match_srloc = "" , match_drloc = "" , match_rloc_name = "" ,
 match_geo = "" , match_elp = "" , match_rle = "" , match_json = "" ,
 match_datetime_range = "" , set_action = "drop" , set_record_ttl = "" ,
 set_iid = "" , set_seid = "" , set_deid = "" , set_rloc = "" , set_rloc_name = "" ,
 set_geo = "" , set_elp = "" , set_rle = "" , set_json = "" ) :
  if ( self . enable_status == None ) : return
  if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
  if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  if 64 - 64: i1IIi
  IIii1 = { "policy-name" : policy_name }
  if ( set_action != "" and set_action != None ) :
   if ( set_action not in [ "process" , "drop" ] ) :
    return ( "bad set-action value" )
    if 35 - 35: i11iIiiIii - I1IiiI / OOooOOo + Ii1I * oO0o
   IIii1 [ "set-action" ] = set_action
   if 49 - 49: o0oOOo0O0Ooo * Ii1I + I11i + iII111i
  if ( set_record_ttl != "" and set_record_ttl != None ) :
   if ( set_record_ttl . isdigit ( ) == False ) :
    return ( "bad set-record-ttl value" )
    if 30 - 30: o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
   IIii1 [ "set-record-ttl" ] = set_record_ttl
   if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
  if ( set_iid != "" and set_iid != None ) :
   if ( set_iid . isdigit ( ) == False ) :
    return ( "bad set-iid value" )
    if 50 - 50: ooOoO0o + i1IIi
   IIii1 [ "set-instance-id" ] = set_iid
   if 31 - 31: Ii1I
  if ( set_seid != "" and set_seid != None ) :
   if ( self . __check_prefix_syntax ( set_seid ) == False ) :
    return ( "bad set-source-eid prefix syntax" )
    if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
   IIii1 [ "set-source-eid" ] = set_seid
   if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
  if ( set_deid != "" and set_deid != None ) :
   if ( self . __check_prefix_syntax ( set_deid ) == False ) :
    return ( "bad set-destination-eid prefix syntax" )
    if 47 - 47: o0oOOo0O0Ooo
   IIii1 [ "set-destination-eid" ] = set_deid
   if 66 - 66: I1IiiI - IiII
  if ( set_rloc != "" and set_rloc != None ) :
   if ( self . __check_address_syntax ( set_rloc ) == False ) :
    return ( "bad set-rloc-address syntax" )
    if 33 - 33: I1IiiI / OoO0O00
   IIii1 [ "set-rloc-address" ] = set_rloc
   if 12 - 12: II111iiii
  if ( set_rloc_name != "" and set_rloc_name != None ) :
   IIii1 [ "set-rloc-record-name" ] = set_rloc_name
   if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
  if ( set_geo != "" and set_geo != None ) :
   IIii1 [ "set-geo-name" ] = set_geo
   if 25 - 25: oO0o
  if ( set_elp != "" and set_elp != None ) :
   IIii1 [ "set-elp-name" ] = set_elp
   if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
  if ( set_rle != "" and set_rle != None ) :
   IIii1 [ "set-rle-name" ] = set_rle
   if 43 - 43: I1ii11iIi11i - iII111i
  if ( set_json != "" and set_json != None ) :
   IIii1 [ "set-json-name" ] = set_json
   if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
   if 47 - 47: iII111i
  o00Ooo0 = { }
  if ( match_iid != "" and match_iid != None ) :
   if ( match_iid . isdigit ( ) == False ) :
    return ( "bad instance-id value" )
    if 62 - 62: OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . OoOoOO00 + OoooooooOO
   o00Ooo0 [ "instance-id" ] = match_iid
   if 77 - 77: iIii1I11I1II1 . Ii1I % oO0o / Ii1I
  if ( match_seid != "" and match_seid != None ) :
   if ( self . __check_prefix_syntax ( match_seid ) == False ) :
    return ( "bad source-eid prefix syntax" )
    if 54 - 54: oO0o + ooOoO0o - Oo0Ooo
   o00Ooo0 [ "source-eid" ] = match_seid
   if 35 - 35: Ii1I - Ii1I + i1IIi - O0 - I1Ii111
  if ( match_deid != "" and match_deid != None ) :
   if ( self . __check_prefix_syntax ( match_deid ) == False ) :
    return ( "bad destination-eid prefix syntax" )
    if 58 - 58: OoOoOO00 - iII111i - OoooooooOO
   o00Ooo0 [ "destination-eid" ] = match_deid
   if 96 - 96: iIii1I11I1II1
  if ( match_srloc != "" and match_srloc != None ) :
   if ( self . __check_prefix_syntax ( match_srloc ) == False ) :
    return ( "bad source-rloc prefix syntax" )
    if 82 - 82: OoOoOO00 + O0 - IiII % oO0o * i11iIiiIii
   o00Ooo0 [ "source-rloc" ] = match_srloc
   if 15 - 15: o0oOOo0O0Ooo
  if ( match_drloc != "" and match_drloc != None ) :
   if ( self . __check_prefix_syntax ( match_drloc ) == False ) :
    return ( "bad destination-rloc prefix syntax" )
    if 39 - 39: OOooOOo / I1ii11iIi11i / I1IiiI * I1Ii111
   o00Ooo0 [ "destination-rloc" ] = match_drloc
   if 44 - 44: O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / O0 - I11i
  if ( match_rloc_name != "" and match_rloc_name != None ) :
   o00Ooo0 [ "rloc-record-name" ] = match_rloc_name
   if 83 - 83: IiII * I11i / Oo0Ooo
  if ( match_geo != "" and match_geo != None ) :
   o00Ooo0 [ "geo-name" ] = match_geo
   if 32 - 32: o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
  if ( match_elp != "" and match_elp != None ) :
   o00Ooo0 [ "elp-name" ] = match_elp
   if 39 - 39: OoooooooOO * OOooOOo * O0 . I11i . OoO0O00 + ooOoO0o
  if ( match_rle != "" and match_rle != None ) :
   o00Ooo0 [ "rle-name" ] = match_rle
   if 9 - 9: OoOoOO00 + oO0o % OoooooooOO + o0oOOo0O0Ooo
  if ( match_json != "" and match_json != None ) :
   o00Ooo0 [ "json-name" ] = match_json
   if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
  if ( match_datetime_range != "" and
 match_datetime_range != None ) :
   o00Ooo0 [ "datetime-range" ] = match_datetime_range
   if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
  o00Ooo0 = { "match" : o00Ooo0 }
  if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
  Ii1i11IIii1I = [ ]
  Ii1i11IIii1I . append ( IIii1 )
  Ii1i11IIii1I . append ( o00Ooo0 )
  if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
  Ii1i11IIii1I = self . __put ( "lisp policy" , Ii1i11IIii1I )
  if 52 - 52: OoO0O00 % Ii1I * II111iiii
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "put error" )
  return ( "good" )
  if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
  if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
 def delete_policy ( self , policy_name ) :
  if ( self . enable_status == None ) : return
  if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
  if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
  Ii1i11IIii1I = self . __delete ( "lisp policy" , { "policy-name" : policy_name } )
  if ( self . __error ( Ii1i11IIii1I ) ) : return ( "delete error" )
  return ( "good" )
  if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
  if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
  if 71 - 71: IiII . I1Ii111 . OoO0O00
  if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
  if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 def __get ( self , command ) :
  II11 = self . url + command . split ( " " ) [ 1 ]
  if 2 - 2: iIii1I11I1II1
  self . __api_debug ( "get command: {}" . format ( command ) )
  try :
   iiii1 = requests . get ( II11 , auth = ( self . user , self . pw ) , verify = False ,
 timeout = REQ_TIMEOUT )
  except :
   return ( None )
   if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
  if ( iiii1 == None or iiii1 . text == None ) : return ( None )
  self . __api_debug ( "get returned: {}" . format ( iiii1 . text ) )
  if ( iiii1 . text == "" ) : return ( None )
  if 70 - 70: I1Ii111 + oO0o
  return ( self . __unicode_to_ascii ( command , iiii1 . text ) )
  if 93 - 93: I1Ii111 + Ii1I
  if 33 - 33: O0
 def __get_data ( self , command , data ) :
  II11 = self . url + "data/" + command . split ( " " ) [ 1 ]
  data = self . __ascii_to_unicode ( command , data )
  if 78 - 78: O0 / II111iiii * OoO0O00
  self . __api_debug ( "get api data: {}" . format ( data ) )
  try :
   iiii1 = requests . get ( II11 , data = data , auth = ( self . user , self . pw ) ,
 verify = False , timeout = REQ_TIMEOUT )
  except :
   return ( None )
   if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
  if ( iiii1 == None or iiii1 . text == None ) : return ( None )
  self . __api_debug ( "get returned: {}" . format ( iiii1 . text ) )
  if ( iiii1 . text == "" ) : return ( None )
  if 58 - 58: IiII + iIii1I11I1II1
  if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
  if 79 - 79: ooOoO0o . OoOoOO00 % I1Ii111 - Oo0Ooo
  if 69 - 69: ooOoO0o - o0oOOo0O0Ooo . ooOoO0o
  if ( iiii1 . text . find ( "<html>" ) != - 1 ) : return ( None )
  if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
  data = iiii1 . text . encode ( )
  return ( json . loads ( data ) )
  if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
  if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
 def __put ( self , command , data ) :
  II11 = self . url + command . split ( " " ) [ 1 ]
  data = self . __ascii_to_unicode ( command , data )
  if 45 - 45: O0 . i11iIiiIii % iII111i . OoOoOO00 % IiII % iIii1I11I1II1
  self . __api_debug ( "put data: {}" . format ( data ) )
  try :
   iiii1 = requests . put ( II11 , data = data , auth = ( self . user , self . pw ) ,
 verify = False , timeout = REQ_TIMEOUT )
  except :
   return ( None )
   if 58 - 58: iIii1I11I1II1 . OoOoOO00 - i11iIiiIii * iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if ( iiii1 == None or iiii1 . text == None ) : return ( None )
  self . __api_debug ( "put returned: {}" . format ( iiii1 . text ) )
  if ( iiii1 . text == "" ) : return ( None )
  if 80 - 80: I1ii11iIi11i / iIii1I11I1II1 % OoOoOO00
  return ( self . __unicode_to_ascii ( command , iiii1 . text ) )
  if 80 - 80: OoO0O00 % iII111i
  if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 def __delete ( self , command , data ) :
  II11 = self . url + command . split ( " " ) [ 1 ]
  data = self . __ascii_to_unicode ( command , data )
  if 13 - 13: OoO0O00
  self . __api_debug ( "delete data: {}" . format ( data ) )
  try :
   iiii1 = requests . delete ( II11 , data = data , auth = ( self . user , self . pw ) ,
 verify = False , timeout = REQ_TIMEOUT )
  except :
   return ( None )
   if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
  if ( iiii1 == None or iiii1 . text == None ) : return ( None )
  self . __api_debug ( "delete returned: {}" . format ( iiii1 . text ) )
  if ( iiii1 . text == "" ) : return ( None )
  if 2 - 2: OoooooooOO . OOooOOo . IiII
  return ( self . __unicode_to_ascii ( command , iiii1 . text ) )
  if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
  if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 def __unicode_to_ascii ( self , command , rtext ) :
  if 24 - 24: o0oOOo0O0Ooo
  if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
  if 28 - 28: OOooOOo % ooOoO0o
  if 48 - 48: i11iIiiIii % oO0o
  if ( rtext . find ( "<html>" ) != - 1 ) : return ( None )
  if 29 - 29: iII111i + i11iIiiIii % I11i
  Ii1i11IIii1I = json . loads ( rtext ) [ 0 ]
  oOo00Ooo0o0 = uc ( command )
  if ( oOo00Ooo0o0 not in Ii1i11IIii1I ) : return ( None )
  if 33 - 33: I11i
  if ( type ( Ii1i11IIii1I ) == dict ) :
   Ii1i11IIii1I = Ii1i11IIii1I [ oOo00Ooo0o0 ]
   oOO0 = { }
   for IIi1I1i in Ii1i11IIii1I :
    for oOo00Ooo0o0 in IIi1I1i :
     oOO0 [ oOo00Ooo0o0 . encode ( ) ] = IIi1I1i [ oOo00Ooo0o0 ] . encode ( )
     if 13 - 13: iIii1I11I1II1 . OoOoOO00 * I1IiiI / oO0o * Ii1I
     if 64 - 64: ooOoO0o / O0 * OoOoOO00 * ooOoO0o
  else :
   oOO0 = [ ]
   for O00oo in Ii1i11IIii1I :
    OoOo0oO0o = { }
    o0OoOo00ooO = list ( O00oo . values ( ) ) [ 0 ]
    for oOo00Ooo0o0 in o0OoOo00ooO : OoOo0oO0o [ oOo00Ooo0o0 . encode ( ) ] = o0OoOo00ooO [ oOo00Ooo0o0 ] . encode ( )
    OoOo0oO0o = { list ( O00oo . keys ( ) ) [ 0 ] . encode ( ) : OoOo0oO0o }
    oOO0 . append ( OoOo0oO0o )
    if 10 - 10: I11i / I11i * i11iIiiIii
    if 46 - 46: OoO0O00 * Oo0Ooo % oO0o + O0 * IiII
  return ( oOO0 )
  if 34 - 34: OoO0O00
  if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 def __walk_dict_array ( self , udata , u_dict ) :
  for oOo00Ooo0o0 in u_dict :
   IiIi1i = uc ( u_dict [ oOo00Ooo0o0 ] )
   if 99 - 99: OoOoOO00 . I1Ii111
   if 59 - 59: I11i / Oo0Ooo / OOooOOo / O0 / OoOoOO00 + o0oOOo0O0Ooo
   if 13 - 13: o0oOOo0O0Ooo % oO0o / I1Ii111 % I1Ii111 % O0
   if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
   if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
   if ( type ( u_dict [ oOo00Ooo0o0 ] ) == dict ) :
    Ii1i1 = { }
    IiIi1i = u_dict [ oOo00Ooo0o0 ]
    for oOoO00 in IiIi1i : Ii1i1 [ uc ( oOoO00 ) ] = uc ( IiIi1i [ oOoO00 ] )
    IiIi1i = Ii1i1
    if 45 - 45: Ii1I . OoooooooOO
    if 27 - 27: Ii1I * Oo0Ooo . OoOoOO00
    if 17 - 17: II111iiii % iII111i * OOooOOo % i1IIi . I1IiiI . iIii1I11I1II1
    if 27 - 27: i11iIiiIii - I1IiiI
    if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
   udata [ uc ( oOo00Ooo0o0 ) ] = IiIi1i
   if 50 - 50: OoOoOO00
   if 33 - 33: I11i
   if 98 - 98: OoOoOO00 % II111iiii
 def __ascii_to_unicode ( self , command , ascii_data ) :
  OoO0O000 = ( type ( ascii_data ) == dict )
  if ( OoO0O000 ) : ascii_data = [ ascii_data ]
  if 14 - 14: OoO0O00 / OoO0O00 * O0 . oO0o
  oooOO0oOooO00 = { }
  iIIiI11i1I11 = [ ]
  for O00oo in ascii_data :
   oooOO0oOooO00 = { }
   if 29 - 29: OoO0O00 * iIii1I11I1II1 * O0 - OoOoOO00 / IiII
   if ( type ( O00oo ) == dict ) :
    self . __walk_dict_array ( oooOO0oOooO00 , O00oo )
   elif ( type ( O00oo ) == list ) :
    o0oO0OO00ooOO = [ ]
    for IiIIiii11II1 in O00oo :
     iiii1i1II1 = { }
     self . __walk_dict_array ( iiii1i1II1 , IiIIiii11II1 )
     o0oO0OO00ooOO . append ( iiii1i1II1 )
     if 63 - 63: iIii1I11I1II1 % I1ii11iIi11i - iII111i
    oooOO0oOooO00 = o0oO0OO00ooOO
   else :
    oooOO0oOooO00 = { uc ( list ( O00oo . keys ( ) ) [ 0 ] ) : oooOO0oOooO00 }
    if 17 - 17: I1IiiI
   iIIiI11i1I11 . append ( oooOO0oOooO00 )
   if 88 - 88: OoooooooOO
  oooOO0oOooO00 = iIIiI11i1I11
  if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
  Oo0O = { }
  Oo0O [ uc ( command ) ] = oooOO0oOooO00 [ 0 ] if OoO0O000 else oooOO0oOooO00
  return ( json . dumps ( Oo0O ) )
  if 88 - 88: I1IiiI % OOooOOo % I1ii11iIi11i . i11iIiiIii % o0oOOo0O0Ooo
  if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 def __error ( self , data ) :
  if ( data == None ) : return ( True )
  if ( "!" in data ) : return ( False )
  return ( True )
  if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
  if 48 - 48: iII111i + IiII
 def __api_debug ( self , string ) :
  if ( self . api_debug ) :
   print ( "lispapi[{}@{}]: {}" . format ( self . user , self . host , string ) )
   if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
   if 14 - 14: OOooOOo
   if 79 - 79: Ii1I
 def __check_prefix_syntax ( self , prefix ) :
  if 76 - 76: iIii1I11I1II1
  if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
  if 93 - 93: OoooooooOO * Oo0Ooo
  if 10 - 10: I1Ii111 * OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i11iIiiIii
  if ( self . __is_dist_name ( prefix ) ) : return ( True )
  if 22 - 22: I1Ii111 / o0oOOo0O0Ooo
  oO0O = prefix . find ( "/" )
  if ( oO0O == - 1 ) : return ( False )
  return ( self . __check_address_syntax ( prefix [ 0 : oO0O ] ) )
  if 59 - 59: OoooooooOO * Oo0Ooo + i1IIi
  if 23 - 23: ooOoO0o
 def __check_prefix_list ( self , prefix_list ) :
  if ( type ( prefix_list ) != list ) : return ( "prefix_list must be an array" )
  if ( len ( prefix_list ) == 0 ) :
   return ( "prefix_list has no array elements supplied" )
   if 13 - 13: iIii1I11I1II1
  if ( type ( prefix_list [ 0 ] ) != dict ) :
   return ( "prefix_list must be array of type dict" )
   if 77 - 77: i11iIiiIii - iIii1I11I1II1 / oO0o / ooOoO0o / OoO0O00
  if ( "allowed-prefix" not in prefix_list [ 0 ] ) :
   return ( "prefix_list is incorrectly formated" )
   if 56 - 56: OoooooooOO * O0
  return ( True )
  if 85 - 85: OoooooooOO % OoOoOO00 * iIii1I11I1II1
  if 44 - 44: iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 def __check_address_set_syntax ( self , address_set , allow_interfaces ) :
  for II1i11 in address_set :
   if ( type ( II1i11 ) == str ) :
    Ii1IIIII = II1i11
   else :
    Ii1IIIII = II1i11 [ "address" ] if ( "address" in II1i11 ) else II1i11 [ "interface" ] if ( "interface" in II1i11 ) else ""
    if 49 - 49: iIii1I11I1II1 % II111iiii
    if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
   if ( allow_interfaces and
 Ii1IIIII in [ "en0" , "en1" , "eth0" , "eth1" ] ) : continue
   if ( self . __check_address_syntax ( Ii1IIIII ) ) : continue
   return ( False )
   if 68 - 68: oO0o
  return ( True )
  if 10 - 10: Ii1I
  if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 def __is_dist_name ( self , addr_str ) :
  if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
  if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
  if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
  if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
  return ( addr_str [ 0 ] == "'" and addr_str [ - 1 ] == "'" )
  if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
  if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 def __check_address_syntax ( self , address ) :
  if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
  if ( self . __is_dist_name ( address ) ) : return ( True )
  if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
  if 10 - 10: iII111i . i1IIi + Ii1I
  if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
  if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
  II1i11 = address . split ( "." )
  if ( len ( II1i11 ) > 1 ) :
   if ( len ( II1i11 ) != 4 ) : return ( False )
   for Oo00O0OO in range ( 4 ) :
    if ( II1i11 [ Oo00O0OO ] . isdigit ( ) == False ) : return ( False )
    oOOOoo0o = int ( II1i11 [ Oo00O0OO ] )
    if ( oOOOoo0o < 0 or oOOOoo0o > 255 ) : return ( False )
    if 44 - 44: O0 % i1IIi
   return ( True )
   if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
   if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
   if 81 - 81: IiII / OoOoOO00 * IiII . O0
   if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
   if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
  II1i11 = address . split ( ":" )
  if ( len ( II1i11 ) > 1 ) :
   if ( len ( II1i11 ) > 8 ) : return ( False )
   for IIii in II1i11 :
    if ( IIii == "" ) : continue
    try : int ( IIii , 16 )
    except : return ( False )
    if 97 - 97: I1ii11iIi11i / Oo0Ooo + I1Ii111
   return ( True )
   if 32 - 32: ooOoO0o % I1Ii111 * Oo0Ooo
   if 72 - 72: ooOoO0o . iII111i - I1Ii111 - Ii1I % i1IIi
   if 56 - 56: Oo0Ooo * iII111i
   if 13 - 13: Oo0Ooo * Oo0Ooo * II111iiii * iII111i . i1IIi / IiII
   if 92 - 92: Ii1I * i11iIiiIii + iII111i * I1Ii111
  II1i11 = address . split ( "-" )
  if ( len ( II1i11 ) > 1 ) :
   if ( len ( II1i11 ) != 3 ) : return ( False )
   for IIii in II1i11 :
    try : int ( IIii , 16 )
    except : return ( False )
    if 48 - 48: I11i * iII111i * iII111i
   return ( True )
   if 70 - 70: oO0o + I11i % i11iIiiIii + O0
  return ( False )
  if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
  if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 def __build_prefix_tuple ( self , iid , eid_prefix , group , kw = "prefix" ) :
  Ii1i11IIii1I = { }
  Ii1i11IIii1I [ "instance-id" ] = iid
  Ii1i11IIii1I [ "eid-prefix" ] = eid_prefix
  if ( group != "" ) : Ii1i11IIii1I [ "group-prefix" ] = group
  return ( { kw : Ii1i11IIii1I } )
  if 80 - 80: OoooooooOO + IiII
  if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
  if 43 - 43: Oo0Ooo . I1Ii111
  if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
