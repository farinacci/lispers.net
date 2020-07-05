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
# Usage: python -O lisp-log-packets.py [force] [<api-port>] [help]
#
# Note when <api-port> is negative, it is passed into the lispapi to tell it
# to use http versus https. This port number should be the same value as
# passed on the ./RESTART-LISP command.
#
#------------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
import lispapi
import sys
import os
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
IiiIII111iI = True
IiII = 8080
for iI1Ii11111iIi in sys . argv [ 1 : : ] :
 if ( iI1Ii11111iIi == "help" ) :
  print "Usage: log-packets [force] [<api-port>] [help]"
  exit ( 0 )
  if 41 - 41: I1II1
 if ( iI1Ii11111iIi == "force" ) : IiiIII111iI = True
 if ( iI1Ii11111iIi . isdigit ( ) ) : IiII = int ( iI1Ii11111iIi )
 if ( iI1Ii11111iIi [ 0 ] == "-" and iI1Ii11111iIi [ 1 : : ] . isdigit ( ) ) : IiII = - int ( iI1Ii11111iIi [ 1 : : ] )
 if 100 - 100: iII1iII1i1iiI % iiIIIII1i1iI % iiI11iii111 % Oo0Ooo
 if 16 - 16: oO0o % OOooOOo * I1II1 . OOooOOo / iIii1I11I1II1 * iIii1I11I1II1
 if 11 - 11: oO0o / i1IIi % II111iiii - OoOoOO00
 if 91 - 91: OoO0O00 . i11iIiiIii / oO0o % I11i / OoO0O00 - i11iIiiIii
 if 8 - 8: o0oOOo0O0Ooo * I1ii11iIi11i * iIii1I11I1II1 . iII1iII1i1iiI / iII1iII1i1iiI % iII1iII1i1iiI
i11 = os . getenv ( "LISP_PW" )
if ( i11 == None ) : i11 = ""
if 41 - 41: iiIIIII1i1iI . iiI11iii111 * iII1iII1i1iiI % i11iIiiIii
if 74 - 74: I1II1 * iII1iII1i1iiI
if 82 - 82: iIii1I11I1II1 % iII1iII1i1iiI
if 86 - 86: OoOoOO00 % I1IiiI
oo = lispapi . api_init ( "localhost" , "root" , i11 , port = IiII )
if ( oo . debug_status == None ) :
 print ( "Could not connect to API, is lispers.net running?, " + "LISP_PW set?, or using the correct port number?" )
 if 33 - 33: II111iiii * Oo0Ooo - o0oOOo0O0Ooo * iIii1I11I1II1 * OoooooooOO * iiI11iii111
 exit ( 1 )
 if 27 - 27: OoO0O00
 if 73 - 73: o0oOOo0O0Ooo - Oo0Ooo
 if 58 - 58: i11iIiiIii % iiIIIII1i1iI
 if 54 - 54: OOooOOo % O0 + I1IiiI - I1II1 / I11i
 if 31 - 31: OoO0O00 + II111iiii
i11IiIiiIIIII = oo . is_itr_debug_enabled ( )
i1iiIII111ii = oo . is_etr_debug_enabled ( )
i1iIIi1 = oo . is_rtr_debug_enabled ( )
if 50 - 50: i11iIiiIii - Ii1I
if 78 - 78: OoO0O00
if 18 - 18: O0 - I1II1 / I1II1 + iiI11iii111 % iiI11iii111 - iII1iII1i1iiI
if 62 - 62: I1II1 - iII1iII1i1iiI - OoOoOO00 % i1IIi / oO0o
OoooooOoo = oo . get_xtr_parameters ( )
if ( OoooooOoo == None ) :
 print "Could not get xtr-parameters from API"
 exit ( 1 )
 if 70 - 70: OoO0O00 . OoO0O00 - OoO0O00 / I1ii11iIi11i * OOooOOo
 if 86 - 86: i11iIiiIii + Ii1I + iiI11iii111 * I11i + o0oOOo0O0Ooo
oOoO = OoooooOoo [ "data-plane-logging" ] == "yes"
oOo = oo . is_rtr_enabled ( )
if 63 - 63: Oo0Ooo
if ( oOoO ) :
 oo . disable_xtr_data_plane_logging ( )
 oo . disable_itr_debug ( )
 oo . disable_etr_debug ( )
 if ( oOo ) : oo . disable_rtr_debug ( )
 print "Data-plane logging has been disabled"
else :
 if ( oOo ) :
  if ( i1iIIi1 and IiiIII111iI == False ) :
   print "Control-plane logging is enabled, no action taken"
   exit ( 0 )
   if 57 - 57: oO0o
  oo . enable_rtr_debug ( )
 else :
  if ( ( i11IiIiiIIIII or i1iiIII111ii ) and IiiIII111iI == False ) :
   print "Control-plane logging is enabled, no action taken"
   exit ( 0 )
   if 14 - 14: Oo0Ooo . I1IiiI / Ii1I
  oo . enable_itr_debug ( )
  oo . enable_etr_debug ( )
  if 38 - 38: II111iiii % i11iIiiIii . iiI11iii111 - OOooOOo + Ii1I
 oo . enable_xtr_data_plane_logging ( )
 print "Data-plane logging has been enabled"
 if 66 - 66: OoooooooOO * OoooooooOO . OOooOOo . i1IIi - OOooOOo
 if 77 - 77: I11i - iIii1I11I1II1
exit ( 0 )
if 82 - 82: i11iIiiIii . OOooOOo / Oo0Ooo * O0 % oO0o % iIii1I11I1II1
if 78 - 78: iIii1I11I1II1 - Ii1I * OoO0O00 + o0oOOo0O0Ooo + I1II1 + I1II1
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
