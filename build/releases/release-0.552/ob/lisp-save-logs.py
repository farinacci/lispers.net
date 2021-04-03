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
if 64 - 64: i11iIiiIii
import os
import datetime
try :
 from commands import getoutput
except :
 from subprocess import getoutput
 if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
 if 73 - 73: II111iiii
 if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
 if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
 if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
i1I1ii1II1iII = datetime . datetime . now ( ) . strftime ( "%m-%d-%y-%H:%M:%S" )
oooO0oo0oOOOO = "logs." + i1I1ii1II1iII
os . system ( "mkdir logs/{}" . format ( oooO0oo0oOOOO ) )
os . system ( "mv ./logs/*.log " + "logs/" + oooO0oo0oOOOO )
if 53 - 53: I11i / Oo0Ooo / II111iiii % Ii1I / OoOoOO00 . ooOoO0o
if 100 - 100: i1IIi
if 27 - 27: IiII * OoooooooOO + I11i * ooOoO0o - i11iIiiIii - iII111i
if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . II111iiii - oO0o
if 72 - 72: II111iiii - OoOoOO00
OOo = getoutput ( "ls -dltr logs/logs.*" )
OOo = OOo . split ( "\n" )
Ii1IIii11 = len ( OOo )
if ( Ii1IIii11 > 10 ) :
 for Oooo0000 in OOo :
  i11 = Oooo0000 . split ( " " )
  os . system ( "sudo rm -fr {}" . format ( i11 [ - 1 ] ) )
  print ( "Removed old log directory {}" . format ( i11 [ - 1 ] ) )
  Ii1IIii11 -= 1
  if ( Ii1IIii11 == 10 ) : break
  if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
  if 74 - 74: iII111i * IiII
  if 82 - 82: iIii1I11I1II1 % IiII
exit ( 0 )
if 86 - 86: OoOoOO00 % I1IiiI
if 80 - 80: OoooooooOO . I1IiiI
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
