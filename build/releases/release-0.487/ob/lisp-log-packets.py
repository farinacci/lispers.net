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
# Usage: python -O lisp-log-packets.py [force]
#
#------------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
import lispapi
import sys
import os
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
o0OO00 = ( "force" in sys . argv )
if 78 - 78: i11i . oOooOoO0Oo0O
if 10 - 10: IIiI1I11i11
if 54 - 54: i11iIi1 - oOo0O0Ooo
if 2 - 2: o0 * i1 * ii1IiI1i % OOooOOo / I11i / Ii1I
IiiIII111iI = os . getenv ( "LISP_PW" )
if ( IiiIII111iI == None ) : IiiIII111iI = ""
if 34 - 34: iii1I1I / O00oOoOoO0o0O . O0oo0OO0 + Oo0ooO0oo0oO . i11iIi1 - i1
if 53 - 53: I11i / IIiI1I11i11 / i11i % Ii1I / oOo0O0Ooo . Oo0ooO0oo0oO
if 100 - 100: i1IIi
if 27 - 27: O00oOoOoO0o0O * OoooooooOO + I11i * Oo0ooO0oo0oO - i11iIiiIii - iii1I1I
IiiiIiI1iIiI1 = lispapi . api_init ( "localhost" , "root" , IiiIII111iI )
if ( IiiiIiI1iIiI1 . debug_status == None ) :
 print "Could not connect to API, is lispers.net running or LISP_PW set?"
 exit ( 1 )
 if 85 - 85: i11iIi1
 if 28 - 28: Ii1I
 if 64 - 64: i1 % i11iIi1
 if 1 - 1: O00oOoOoO0o0O
 if 91 - 91: i1 * iIii1I11I1II1 . O00oOoOoO0o0O / Ii1I
Ooo0 = IiiiIiI1iIiI1 . is_itr_debug_enabled ( )
oo00000o0 = IiiiIiI1iIiI1 . is_etr_debug_enabled ( )
I11i1i11i1I = IiiiIiI1iIiI1 . is_rtr_debug_enabled ( )
if 31 - 31: i11iIiiIii / oOooOoO0Oo0O / Oo0ooO0oo0oO * ii1IiI1i / IIiI1I11i11
if 99 - 99: iIii1I11I1II1 * OoooooooOO * i11i * iIii1I11I1II1
if 44 - 44: ii1IiI1i / IIiI1I11i11 - i11i - i11iIiiIii % O0oo0OO0
if 54 - 54: OOooOOo % O0 + oOooOoO0Oo0O - iii1I1I / I11i
iIiiI1 = IiiiIiI1iIiI1 . get_xtr_parameters ( )
if ( iIiiI1 == None ) :
 print "Could not get xtr-parameters from API"
 exit ( 1 )
 if 68 - 68: oOooOoO0Oo0O - i11iIiiIii - i11iIi1 / OOooOOo - i11iIi1 + i1IIi
 if 48 - 48: OoooooooOO % o0 . oOooOoO0Oo0O - Ii1I % i1IIi % OoooooooOO
i1iIIi1 = iIiiI1 [ "data-plane-logging" ] == "yes"
ii11iIi1I = IiiiIiI1iIiI1 . is_rtr_enabled ( )
if 6 - 6: oOo0O0Ooo * iii1I1I
if ( i1iIIi1 ) :
 IiiiIiI1iIiI1 . disable_xtr_data_plane_logging ( )
 IiiiIiI1iIiI1 . disable_itr_debug ( )
 IiiiIiI1iIiI1 . disable_etr_debug ( )
 if ( ii11iIi1I ) : IiiiIiI1iIiI1 . disable_rtr_debug ( )
 print "Data-plane logging has been disabled"
else :
 if ( ii11iIi1I ) :
  if ( I11i1i11i1I and o0OO00 == False ) :
   print "Control-plane logging is enabled, no action taken"
   exit ( 0 )
   if 67 - 67: Oo0ooO0oo0oO - ii1IiI1i * o0 % o0 % I11i * oOo0O0Ooo
  IiiiIiI1iIiI1 . enable_rtr_debug ( )
 else :
  if ( ( Ooo0 or oo00000o0 ) and o0OO00 == False ) :
   print "Control-plane logging is enabled, no action taken"
   exit ( 0 )
   if 26 - 26: Ii1I - o0
  IiiiIiI1iIiI1 . enable_itr_debug ( )
  IiiiIiI1iIiI1 . enable_etr_debug ( )
  if 63 - 63: i11i . i11i
 IiiiIiI1iIiI1 . enable_xtr_data_plane_logging ( )
 print "Data-plane logging has been enabled"
 if 32 - 32: i1IIi . I11i % i11iIi1 . o0
 if 42 - 42: O0oo0OO0 + i1
exit ( 0 )
if 70 - 70: IIiI1I11i11 % IIiI1I11i11 . O00oOoOoO0o0O % i11iIi1 * o0 % ii1IiI1i
if 23 - 23: i11iIiiIii + oOooOoO0Oo0O
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
