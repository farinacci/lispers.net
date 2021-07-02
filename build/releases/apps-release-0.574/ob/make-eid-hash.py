#!/usr/bin/env python
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
# make-eid-hash.py
#
# Creates an IPv6 EID with a prefix and hash of an instance-ID, EID-prefix,
# and public key. This script will ask for an instance-ID and an EID-prefix,
# then will generate a ECDSA key-pair. What is displayed to standard output
# is:
#
# (1) Instance-ID and crypto-hash EID
# (2) A public-key
# (3) A signature of the string "[<iid>]<eid>"
#
# The output (public-key and signature) can go into a lisp.config file.
#
# Usage: python make-eid-hash.py
#
#------------------------------------------------------------------------------
from __future__ import print_function
import ecdsa
import hashlib
from binascii import b2a_base64 as b2a
from builtins import input
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
I1IiI = input ( "Enter EID-prefix (zero-fill prefix bits): " )
if ( I1IiI . find ( "/" ) == - 1 or I1IiI . count ( ":" ) == 0 ) :
 print ( "EID-prefix must be an IPv6 address in slash format" )
 exit ( 1 )
 if 73 - 73: OOooOOo / ii11ii1ii
I1IiI , O00ooOO = I1IiI . split ( "/" )
O00ooOO = int ( O00ooOO )
if ( ( O00ooOO % 4 ) != 0 ) :
 print ( "Mask-length must be a multiple of 4" )
 exit ( 1 )
 if 47 - 47: oO0ooO % iI1Ii11111iIi + ii1II11I1ii1I + oO0o0ooO0 - iiIIIII1i1iI
 if 68 - 68: o00ooo0 / oO0o0ooO0
o00 = input ( "Enter Instance-ID: " )
try :
 o00 = 0 if ( o00 == "" ) else int ( o00 )
except :
 print ( "Invalid Instance-ID" )
 exit ( 1 )
 if 62 - 62: i11iIiiIii - II111iiii % iiIIIII1i1iI - iIii1I11I1II1 . I1ii11iIi11i . II111iiii
print ( "" )
if 61 - 61: OOooOOo / OoOoOO00 / ii1II11I1ii1I * OoO0O00 . II111iiii
if 1 - 1: II111iiii - I1ii11iIi11i % i11iIiiIii + oO0o0ooO0 . iiIIIII1i1iI
if 55 - 55: iIii1I11I1II1 - I1IiiI . iI1Ii11111iIi * oO0o0ooO0 * i1IIi / iIii1I11I1II1
if 79 - 79: OOooOOo + iiIIIII1i1iI . o00ooo0 * oO0o0ooO0 % oO0ooO . I1IiiI
O0o0o00o0Oo0 = ecdsa . SigningKey . generate ( curve = ecdsa . NIST256p )
ii11 = O0o0o00o0Oo0 . get_verifying_key ( ) . to_der ( )
if 28 - 28: o00ooo0 + iiIIIII1i1iI - o00ooo0 . OoooooooOO
if 97 - 97: OoO0O00 . oO0ooO
if 32 - 32: Oo0Ooo - II111iiii - i11iIiiIii % iiIIIII1i1iI
if 54 - 54: ii11ii1ii % O0 + I1IiiI - ii1II11I1ii1I / oO0ooO
I1IiI = I1IiI . replace ( ":" , "" )
I1IiI = int ( I1IiI , 16 )
if 31 - 31: OoO0O00 + II111iiii
i11IiIiiIIIII = hex ( o00 ) [ 2 : : ] . zfill ( 8 )
i1iiIII111ii = hex ( I1IiI ) [ 2 : : ]
if 3 - 3: ii1II11I1ii1I + O0
if 42 - 42: ii11ii1ii / i1IIi + i11iIiiIii - iI1Ii11111iIi
if 78 - 78: OoO0O00
if 18 - 18: O0 - ii1II11I1ii1I / ii1II11I1ii1I + o00ooo0 % o00ooo0 - oO0o0ooO0
O0O00Ooo = i11IiIiiIIIII + i1iiIII111ii + ii11
OOoooooO = hashlib . sha256 ( O0O00Ooo ) . hexdigest ( )
if 14 - 14: oO0ooO % O0
IiI1I1 = ( 128 - O00ooOO ) / 4
OoO000 = OOoooooO [ 0 : IiI1I1 ]
OOoooooO = int ( OoO000 , 16 )
if 42 - 42: OOooOOo - i1IIi / i11iIiiIii + ii11ii1ii + OoO0O00
iIi = ( I1IiI << ( 128 - O00ooOO ) ) + OOoooooO
iIi = hex ( iIi ) [ 2 : - 1 ]
iIi = iIi [ 0 : 4 ] + ":" + iIi [ 4 : 8 ] + ":" + iIi [ 8 : 12 ] + ":" + iIi [ 12 : 16 ] + ":" + iIi [ 16 : 20 ] + ":" + iIi [ 20 : 24 ] + ":" + iIi [ 24 : 28 ] + ":" + iIi [ 28 : 32 ]
if 40 - 40: OOooOOo . OoOoOO00 . Oo0Ooo . i1IIi
iIi = iIi . replace ( ":000" , ":" )
iIi = iIi . replace ( ":00" , ":" )
iIi = iIi . replace ( ":0" , ":" )
if 33 - 33: iI1Ii11111iIi + II111iiii % i11iIiiIii . o00ooo0 - I1IiiI
if 66 - 66: iI1Ii11111iIi - OoooooooOO * OoooooooOO . ii11ii1ii . I1ii11iIi11i
if 22 - 22: OoooooooOO % oO0ooO - ii1II11I1ii1I . iIii1I11I1II1 * i11iIiiIii
if 32 - 32: Oo0Ooo * O0 % OOooOOo % iI1Ii11111iIi . oO0o0ooO0
if 61 - 61: o00ooo0
if 79 - 79: Oo0Ooo + I1IiiI - ii1II11I1ii1I
oO00O00o0OOO0 = "[{}]{}" . format ( o00 , iIi )
Ii1iIIIi1ii = O0o0o00o0Oo0 . sign ( oO00O00o0OOO0 , hashfunc = hashlib . sha256 )
if 80 - 80: oO0ooO * i11iIiiIii / iiIIIII1i1iI
if 9 - 9: iI1Ii11111iIi + OOooOOo % iI1Ii11111iIi + i1IIi . ii11ii1ii
if 31 - 31: o0oOOo0O0Ooo + oO0ooO + oO0ooO / II111iiii
if 26 - 26: OoooooooOO
print ( "----------------------------------------------------------------------" )
print ( "" )
print ( "Crypto-hashed EID: {}" . format ( oO00O00o0OOO0 ) )
print ( "" )
print ( "Private-key for lisp-sig.pem/lisp-lig.pem file:\n{}" . format ( O0o0o00o0Oo0 . to_pem ( ) ) )
if 12 - 12: OoooooooOO % OoOoOO00 / o00ooo0 % o0oOOo0O0Ooo
if 29 - 29: OoooooooOO
ii11 = b2a ( O0o0o00o0Oo0 . get_verifying_key ( ) . to_pem ( ) )
print ( "Public-key for lisp.config file:\n{}" . format ( ii11 ) )
Ii1iIIIi1ii = b2a ( Ii1iIIIi1ii )
print ( "EID signature for lisp.config file:\n{}" . format ( Ii1iIIIi1ii ) )
if 23 - 23: o0oOOo0O0Ooo . II111iiii
print ( "----------------------------------------------------------------------" )
print ( "" )
if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
print ( "Add the following commands to the lisp.config file:" )
if 45 - 45: iiIIIII1i1iI . OoOoOO00
oO = OoO000
if ( ( len ( oO ) % 4 ) == 0 ) :
 OoO000 = [ ]
else :
 OoO000 = [ oO [ 0 : 2 ] ]
 oO = oO [ 2 : : ]
 if 6 - 6: I1ii11iIi11i
for I1I in range ( 0 , len ( oO ) , 4 ) :
 OoO000 . append ( oO [ I1I : I1I + 4 ] )
 if 80 - 80: OoOoOO00 - OoO0O00
 if 87 - 87: OOooOOo / oO0ooO - i1IIi * ii11ii1ii / OoooooooOO . O0
OoO000 = ":" . join ( OoO000 )
iii11I111 = iIi [ - 4 : : ]
ii11 = ii11 . replace ( "\n" , "" )
Ii1iIIIi1ii = Ii1iIIIi1ii . replace ( "\n" , "" )
if 63 - 63: OoO0O00 * OOooOOo - ii1II11I1ii1I * O0
iIii111IIi = '''
lisp json {
    json-name = pubkey-<ev>
    json-string = { "public-key" : "<pubkey>" }
}
lisp database-mapping {
    prefix {
        instance-id = <iid>
        eid-prefix = 'hash-<hv>'
    }
    rloc {
        json-name = pubkey-<ev>
        priority = 255
    }
}
lisp json {
    json-name = signature-<ev>
    json-string = { "signature-eid" : "[<iid>]<eid>", "signature" : "<sig>" }
}
lisp database-mapping {
    prefix {
        instance-id = <iid>
        eid-prefix = <eid>/128
        signature-eid = yes
    }
    rloc {
        interface = <interface>
    }
    rloc {
        json-name = signature-<ev>
        priority = 255
    }
}
'''
iIii111IIi = iIii111IIi . replace ( "<ev>" , iii11I111 )
iIii111IIi = iIii111IIi . replace ( "<hv>" , OoO000 )
iIii111IIi = iIii111IIi . replace ( "<iid>" , str ( o00 ) )
iIii111IIi = iIii111IIi . replace ( "<eid>" , iIi )
iIii111IIi = iIii111IIi . replace ( "<pubkey>" , ii11 )
iIii111IIi = iIii111IIi . replace ( "<sig>" , Ii1iIIIi1ii )
if 4 - 4: II111iiii / o00ooo0 . ii1II11I1ii1I
print ( iIii111IIi )
print ( "----------------------------------------------------------------------" )
if 58 - 58: ii11ii1ii * i11iIiiIii / OoOoOO00 % iiIIIII1i1iI - I1ii11iIi11i / OOooOOo
exit ( 0 )
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
