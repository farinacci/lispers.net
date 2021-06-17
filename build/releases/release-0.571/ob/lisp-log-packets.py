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
# Usage: python lisp-log-packets.py [force] [<api-port>] [help]
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
I1IiI = True
o0OOO = 8080
for iIiiiI in sys . argv [ 1 : : ] :
 if ( iIiiiI == "help" ) :
  print ( "Usage: python log-packets.py [force] [<api-port>] [help]" )
  exit ( 0 )
  if 23 - 23: iii1II11ii * i11iII1iiI + iI1Ii11111iIi + ii1II11I1ii1I + oO0o0ooO0 - iiIIIII1i1iI
 if ( iIiiiI == "force" ) : I1IiI = True
 if ( iIiiiI . isdigit ( ) ) : o0OOO = int ( iIiiiI )
 if ( iIiiiI [ 0 ] == "-" and iIiiiI [ 1 : : ] . isdigit ( ) ) : o0OOO = - int ( iIiiiI [ 1 : : ] )
 if 68 - 68: o00ooo0 / Oo00O0
 if 66 - 66: oO0o0ooO0
 if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . II111iiii - iii1II11ii
 if 72 - 72: II111iiii - OoOoOO00
 if 91 - 91: OoO0O00 . i11iIiiIii / iii1II11ii % iI1Ii11111iIi / OoO0O00 - i11iIiiIii
II1Iiii1111i = os . getenv ( "LISP_PW" )
if ( II1Iiii1111i == None ) : II1Iiii1111i = ""
if 25 - 25: ii1II11I1ii1I
if 89 - 89: OoooooooOO - iiIIIII1i1iI * Oo00O0
if 82 - 82: iI1Ii11111iIi . o00ooo0 / iiIIIII1i1iI % II111iiii % iIii1I11I1II1 % iiIIIII1i1iI
if 86 - 86: OoOoOO00 % I1IiiI
oo = lispapi . api_init ( "localhost" , "root" , II1Iiii1111i , port = o0OOO )
if ( oo . debug_status == None ) :
 print ( "Could not connect to API, is lispers.net running?, " + "LISP_PW set?, or using the correct port number?" )
 if 33 - 33: II111iiii * Oo0Ooo - o0oOOo0O0Ooo * iIii1I11I1II1 * OoooooooOO * Oo00O0
 exit ( 1 )
 if 27 - 27: OoO0O00
 if 73 - 73: o0oOOo0O0Ooo - Oo0Ooo
 if 58 - 58: i11iIiiIii % o00ooo0
 if 54 - 54: i11iII1iiI % O0 + I1IiiI - oO0o0ooO0 / iI1Ii11111iIi
 if 31 - 31: OoO0O00 + II111iiii
i11IiIiiIIIII = oo . is_itr_debug_enabled ( )
i1iiIII111ii = oo . is_etr_debug_enabled ( )
i1iIIi1 = oo . is_rtr_debug_enabled ( )
if 50 - 50: i11iIiiIii - ii1II11I1ii1I
if 78 - 78: OoO0O00
if 18 - 18: O0 - oO0o0ooO0 / oO0o0ooO0 + Oo00O0 % Oo00O0 - iiIIIII1i1iI
if 62 - 62: oO0o0ooO0 - iiIIIII1i1iI - OoOoOO00 % i1IIi / iii1II11ii
OoooooOoo = oo . get_xtr_parameters ( )
if ( OoooooOoo == None ) :
 print ( "Could not get xtr-parameters from API" )
 exit ( 1 )
 if 70 - 70: OoO0O00 . OoO0O00 - OoO0O00 / I1ii11iIi11i * i11iII1iiI
 if 86 - 86: i11iIiiIii + ii1II11I1ii1I + Oo00O0 * iI1Ii11111iIi + o0oOOo0O0Ooo
oOoO = OoooooOoo [ "data-plane-logging" ] == "yes"
oOo = oo . is_rtr_enabled ( )
if 63 - 63: Oo0Ooo
if ( oOoO ) :
 oo . disable_xtr_data_plane_logging ( )
 oo . disable_itr_debug ( )
 oo . disable_etr_debug ( )
 if ( oOo ) : oo . disable_rtr_debug ( )
 print ( "Data-plane logging has been disabled" )
else :
 if ( oOo ) :
  if ( i1iIIi1 and I1IiI == False ) :
   print ( "Control-plane logging is enabled, no action taken" )
   exit ( 0 )
   if 57 - 57: iii1II11ii
  oo . enable_rtr_debug ( )
 else :
  if ( ( i11IiIiiIIIII or i1iiIII111ii ) and I1IiI == False ) :
   print ( "Control-plane logging is enabled, no action taken" )
   exit ( 0 )
   if 14 - 14: Oo0Ooo . I1IiiI / ii1II11I1ii1I
  oo . enable_itr_debug ( )
  oo . enable_etr_debug ( )
  if 38 - 38: II111iiii % i11iIiiIii . Oo00O0 - i11iII1iiI + ii1II11I1ii1I
 oo . enable_xtr_data_plane_logging ( )
 print ( "Data-plane logging has been enabled" )
 if 66 - 66: OoooooooOO * OoooooooOO . i11iII1iiI . i1IIi - i11iII1iiI
 if 77 - 77: iI1Ii11111iIi - iIii1I11I1II1
exit ( 0 )
if 82 - 82: i11iIiiIii . i11iII1iiI / Oo0Ooo * O0 % iii1II11ii % iIii1I11I1II1
if 78 - 78: iIii1I11I1II1 - ii1II11I1ii1I * OoO0O00 + o0oOOo0O0Ooo + oO0o0ooO0 + oO0o0ooO0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
