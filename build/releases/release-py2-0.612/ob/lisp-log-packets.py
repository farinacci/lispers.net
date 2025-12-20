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
# lisp-log-packets.py
#
# Set the following commands in the local system:
# 
# lisp debug {
#     itr = yes
#     etr = yes
# }
# lisp xtr-parameters {
#     data-plane-logging = yes
# }
#
# By using the lispapi. The command will toggle the setting. When environment
# variable LISP_PW is set, the value is the password that is used to connect.
# to the LISP API.
#
# Usage: python lisp-log-packets.py [show] [force] [<api-port>] [help]
#
# Note when <api-port> is negative, it is passed into the lispapi to tell it
# to use http versus https. This port number should be the same value as
# passed on the ./RESTART-LISP command.
#
#------------------------------------------------------------------------------
from __future__ import print_function
import lispapi
import sys
import os
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
I1IiI = ( "show" in sys . argv )
o0OOO = True
iIiiiI = 8080
for Iii1ii1II11i in sys . argv [ 1 : : ] :
 if ( Iii1ii1II11i == "help" ) :
  print ( "Usage: ./log-packets [show] [force] [<api-port>] [help]" )
  exit ( 0 )
  if 10 - 10: I1iII1iiII + I1Ii111 / OOo
 if ( Iii1ii1II11i == "force" ) : o0OOO = True
 if ( Iii1ii1II11i . isdigit ( ) ) : iIiiiI = int ( Iii1ii1II11i )
 if ( Iii1ii1II11i [ 0 ] == "-" and Iii1ii1II11i [ 1 : : ] . isdigit ( ) ) : iIiiiI = - int ( Iii1ii1II11i [ 1 : : ] )
 if 41 - 41: I1II1
 if 100 - 100: iII1iII1i1iiI % iiIIIII1i1iI % iiI11iii111 % i1I1Ii1iI1ii
 if 11 - 11: I1iII1iiII / i1IIi % II111iiii - OoOoOO00
 if 91 - 91: OoO0O00 . i11iIiiIii / I1iII1iiII % OOo / OoO0O00 - i11iIiiIii
 if 8 - 8: o0oOOo0O0Ooo * I1ii11iIi11i * iIii1I11I1II1 . iiIIIII1i1iI / iiIIIII1i1iI % iiIIIII1i1iI
i11 = os . getenv ( "LISP_PW" )
if ( i11 == None ) : i11 = ""
if 41 - 41: iiI11iii111 . i1I1Ii1iI1ii * iiIIIII1i1iI % i11iIiiIii
if 74 - 74: iII1iII1i1iiI * iiIIIII1i1iI
if 82 - 82: iIii1I11I1II1 % iiIIIII1i1iI
if 86 - 86: OoOoOO00 % I1IiiI
oo = lispapi . api_init ( "localhost" , "root" , i11 , port = iIiiiI )
if ( oo . debug_status == None ) :
 print ( "Could not connect to API, is lispers.net running?, " + "LISP_PW set?, or using the correct port number?" )
 if 33 - 33: II111iiii * Oo0Ooo - o0oOOo0O0Ooo * iIii1I11I1II1 * OoooooooOO * i1I1Ii1iI1ii
 exit ( 1 )
 if 27 - 27: OoO0O00
 if 73 - 73: o0oOOo0O0Ooo - Oo0Ooo
 if 58 - 58: i11iIiiIii % iiI11iii111
 if 54 - 54: I1Ii111 % O0 + I1IiiI - iII1iII1i1iiI / OOo
 if 31 - 31: OoO0O00 + II111iiii
i11IiIiiIIIII = oo . is_itr_debug_enabled ( )
i1iiIII111ii = oo . is_etr_debug_enabled ( )
i1iIIi1 = oo . is_rtr_debug_enabled ( )
if 50 - 50: i11iIiiIii - I1II1
if 78 - 78: OoO0O00
if 18 - 18: O0 - iII1iII1i1iiI / iII1iII1i1iiI + i1I1Ii1iI1ii % i1I1Ii1iI1ii - iiIIIII1i1iI
if 62 - 62: iII1iII1i1iiI - iiIIIII1i1iI - OoOoOO00 % i1IIi / I1iII1iiII
OoooooOoo = oo . get_xtr_parameters ( )
if ( OoooooOoo == None ) :
 print ( "Could not get xtr-parameters from API" )
 exit ( 1 )
 if 70 - 70: OoO0O00 . OoO0O00 - OoO0O00 / I1ii11iIi11i * I1Ii111
 if 86 - 86: i11iIiiIii + I1II1 + i1I1Ii1iI1ii * OOo + o0oOOo0O0Ooo
oOoO = OoooooOoo [ "data-plane-logging" ] == "yes"
if 68 - 68: OoOoOO00 . I1iII1iiII . i11iIiiIii
if 40 - 40: I1iII1iiII . OoOoOO00 . Oo0Ooo . i1IIi
if 33 - 33: I1II1 + II111iiii % i11iIiiIii . i1I1Ii1iI1ii - I1IiiI
if 66 - 66: I1II1 - OoooooooOO * OoooooooOO . I1Ii111 . I1ii11iIi11i
if ( I1IiI ) :
 print ( "ITR-logging:        {}" . format ( "enabled" if i11IiIiiIIIII else "disabled" ) )
 print ( "ETR-logging:        {}" . format ( "enabled" if i1iiIII111ii else "disabled" ) )
 print ( "RTR-logging:        {}" . format ( "enabled" if i1iIIi1 else "disabled" ) )
 print ( "data-plane-logging: {}" . format ( "enabled" if oOoO else "disabled" ) )
 if 22 - 22: OoooooooOO % OOo - iII1iII1i1iiI . iIii1I11I1II1 * i11iIiiIii
 exit ( 0 )
 if 32 - 32: Oo0Ooo * O0 % I1iII1iiII % I1II1 . iiIIIII1i1iI
 if 61 - 61: i1I1Ii1iI1ii
oOOO00o = oo . is_rtr_enabled ( )
if 97 - 97: OOo % OOo + II111iiii * iII1iII1i1iiI
if ( oOoO ) :
 oo . disable_xtr_data_plane_logging ( )
 oo . disable_itr_debug ( )
 oo . disable_etr_debug ( )
 if ( oOOO00o ) : oo . disable_rtr_debug ( )
 print ( "Data-plane logging has been disabled" )
else :
 if ( oOOO00o ) :
  if ( i1iIIi1 and o0OOO == False ) :
   print ( "Control-plane logging is enabled, no action taken" )
   exit ( 0 )
   if 54 - 54: OOo + iiIIIII1i1iI / iII1iII1i1iiI
  oo . enable_rtr_debug ( )
 else :
  if ( ( i11IiIiiIIIII or i1iiIII111ii ) and o0OOO == False ) :
   print ( "Control-plane logging is enabled, no action taken" )
   exit ( 0 )
   if 9 - 9: OoOoOO00 / Oo0Ooo - iiIIIII1i1iI . i1IIi / I1IiiI % iiIIIII1i1iI
  oo . enable_itr_debug ( )
  oo . enable_etr_debug ( )
  if 71 - 71: iiI11iii111 . O0
 oo . enable_xtr_data_plane_logging ( )
 print ( "Data-plane logging has been enabled" )
 if 73 - 73: I1Ii111 % OoOoOO00 - I1II1
 if 10 - 10: I1IiiI % I1ii11iIi11i
exit ( 0 )
if 48 - 48: OOo + OOo / II111iiii / iIii1I11I1II1
if 20 - 20: o0oOOo0O0Ooo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
