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
# lispers.net-test-install.py
#
# Usage: python lispers.net-test-install.py
#
# -----------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
import importlib
import commands
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
o0OO00 = [ "bottle" , "requests" , "cherrypy" , "pcappy" , "netifaces" ,
 "setuptools" , "Crypto.Cipher" , "OpenSSL" , "curve25519" , "geopy" , "pytun" ,
 "ecdsa" , "future" , "builtins" ]
if 78 - 78: i11i . oOooOoO0Oo0O
iI1 = [ ]
for i1I11i in o0OO00 :
 try : importlib . import_module ( i1I11i )
 except : iI1 . append ( i1I11i )
 if 73 - 73: III - oo00oOOo * Oooo000o % OOo . OOO
 if 27 - 27: Iii1IIIiiI + iI - Oo / iII11iiIII111 % iiiIIii1I1Ii . O00oOoOoO0o0O
 if 43 - 43: Oo0 * OO - O00oOoOoO0o0O - OO . OoooooooOO . OOO
 if 68 - 68: O00oOoOoO0o0O . i1IIi
 if 60 - 60: OOO + Oo0 - Oo / i1IIi
Ii1iI = commands . getoutput ( "python -m pip list | egrep pycryptodome" )
if ( Ii1iI != "" ) : Ii1iI = ( Ii1iI . find ( "pycryptodome" ) != - 1 )
if ( Ii1iI == False ) : iI1 . append ( "pycryptodome" )
if 100 - 100: i1IIi . Oo0 / O00oOoOoO0o0O * OoooooooOO + Oo * Iii1IIIiiI
if ( len ( iI1 ) == 0 ) :
 print "Install complete"
else :
 print "Install NOT complete for {}" . format ( iI1 )
 if 99 - 99: iiiIIii1I1Ii . iI / iIii1I11I1II1 * iIii1I11I1II1
 if 11 - 11: Iii1IIIiiI / i1IIi % i11i - Oooo000o
exit ( 0 )
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
