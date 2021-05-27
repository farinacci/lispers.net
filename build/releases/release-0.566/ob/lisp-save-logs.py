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
# lisp-save-logs.py
#
# Before starting up the lisp-core.py process, save existing *.log files in
# current directory to a date/timestamped sub-directory.
# 
# -----------------------------------------------------------------------------
from __future__ import print_function
from future import standard_library
standard_library . install_aliases ( )
import os
import datetime
from subprocess import getoutput
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
IiII1IiiIiI1 = datetime . datetime . now ( ) . strftime ( "%m-%d-%y-%H:%M:%S" )
iIiiiI1IiI1I1 = "logs." + IiII1IiiIiI1
os . system ( "mkdir logs/{}" . format ( iIiiiI1IiI1I1 ) )
os . system ( "mv ./logs/*.log " + "logs/" + iIiiiI1IiI1I1 )
if 87 - 87: OoOoOO00
if 27 - 27: OOOo0 / Oo - Ooo00oOo00o . I1IiI
if 73 - 73: OOooOOo / ii11ii1ii
if 94 - 94: OoOO + OoOO0ooOOoo0O + o0000oOoOoO0o * o00O0oo
if 97 - 97: oO0o0ooO0 - IIII / O0oO - OoOO
iiI11iii111 = getoutput ( "ls -dltr logs/logs.*" )
iiI11iii111 = iiI11iii111 . split ( "\n" )
i1I1Ii1iI1ii = len ( iiI11iii111 )
if ( i1I1Ii1iI1ii > 10 ) :
 for II1iI in iiI11iii111 :
  i1iIii1Ii1II = II1iI . split ( " " )
  os . system ( "sudo rm -fr {}" . format ( i1iIii1Ii1II [ - 1 ] ) )
  print ( "Removed old log directory {}" . format ( i1iIii1Ii1II [ - 1 ] ) )
  i1I1Ii1iI1ii -= 1
  if ( i1I1Ii1iI1ii == 10 ) : break
  if 1 - 1: oO0o0ooO0
  if 91 - 91: OOooOOo * iIii1I11I1II1 . oO0o0ooO0 / o0000oOoOoO0o
  if 87 - 87: i1IIi / o0000oOoOoO0o . Oo * OoooooooOO - oO0o0ooO0 * O0oO
exit ( 0 )
if 82 - 82: OoOO0ooOOoo0O . IIII / oO0o0ooO0 % II111iiii % iIii1I11I1II1 % oO0o0ooO0
if 86 - 86: Ooo00oOo00o % OoOoOO00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
