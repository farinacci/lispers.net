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
# remove-lisp-locks.py
#
# This python script will remove an named socket file descriptors
# 
# -----------------------------------------------------------------------------
from __future__ import print_function
from future import standard_library
standard_library . install_aliases ( )
import os
from subprocess import getoutput
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
IiII1IiiIiI1 = "ls lisp-* | egrep -v 'py|log|pem|txt|config' | " + "egrep -v lisp-xtr | egrep -v lisp-ztr"
if 40 - 40: oo * OoO0O00
if 2 - 2: ooOO00oOo % oOo0O0Ooo * Ooo00oOo00o . oOoO0oo0OOOo + iiiiIi11i
Ii1I = getoutput ( IiII1IiiIiI1 )
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * o00O0oo
O0oOO0o0 = "lisp-ipc-data-plane"
if ( Ii1I != "" ) :
 print ( "Removed LISP file descriptors:" , end = " " )
 Ii1I = Ii1I . split ( "\n" )
 if 9 - 9: o0o - OOO0o0o
 if ( O0oOO0o0 in Ii1I ) : Ii1I . remove ( O0oOO0o0 )
 Ii1I . append ( "lispers.net-itr" )
 print ( Ii1I )
 if 40 - 40: oo / O0 % OOO0o0o + O0 * i1IIi
 if 27 - 27: o00O0oo * OoooooooOO + IiII * OOO0o0o - i11iIiiIii - ooOoO0o
for IiiiIiI1iIiI1 in Ii1I :
 if ( IiiiIiI1iIiI1 == "" ) : continue
 os . system ( "rm -f {}" . format ( IiiiIiI1iIiI1 ) )
 if 85 - 85: ooOO00oOo
 if 28 - 28: I1Ii111
exit ( 0 )
if 64 - 64: oOoO0oo0OOOo % ooOO00oOo
if 1 - 1: o00O0oo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
