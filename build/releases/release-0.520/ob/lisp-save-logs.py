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
import commands
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
I1IiI = datetime . datetime . now ( ) . strftime ( "%m-%d-%y-%H:%M:%S" )
o0OOO = "logs." + I1IiI
os . system ( "mkdir logs/{}" . format ( o0OOO ) )
os . system ( "mv ./logs/*.log " + "logs/" + o0OOO )
if 13 - 13: ooOo + Oo
if 67 - 67: O00ooOO . I1iII1iiII
if 28 - 28: Ii11111i * iiI1i1
if 46 - 46: Ooo0OO0oOO * Ii * I1ii11iIi11i
if 68 - 68: iiI1i1 . i1IIi
OOO0o0o = commands . getoutput ( "ls -dltr logs/logs.*" )
OOO0o0o = OOO0o0o . split ( "\n" )
Ii1iI = len ( OOO0o0o )
if ( Ii1iI > 10 ) :
 for OoI1Ii11I1Ii1i in OOO0o0o :
  Ooo = OoI1Ii11I1Ii1i . split ( " " )
  os . system ( "sudo rm -fr {}" . format ( Ooo [ - 1 ] ) )
  print "Removed old log directory {}" . format ( Ooo [ - 1 ] )
  Ii1iI -= 1
  if ( Ii1iI == 10 ) : break
  if 56 - 56: O00ooOO - i1IIi
  if 64 - 64: Ooo0OO0oOO + Ii11111i
  if 10 - 10: i11iIiiIii / ooOo % II111iiii
exit ( 0 )
if 75 - 75: i11iIiiIii + iiI1i1 . o0oOOo0O0Ooo * Ii11111i
if 59 - 59: iIii1I11I1II1
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
