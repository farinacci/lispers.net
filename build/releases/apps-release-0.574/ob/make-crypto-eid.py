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
# make-crypto-eid.py
#
# This program creates a IPv6 crypto-EID. It performs the following functions:
#
# (1) Generates a key-pair. Writes private key to lisp-cert.pem in current
#     directory.
# (2) Creates a file named "lisp.config.include" in the current directory that
#     contains two "lisp database-mapping" commands. One for the crypto-EID
#     and one for the hash->pubkey. It also contains two JSON command clauses
#     for the crypto-EID signature and for the public-key encoding.
#
# Usage: python make-crypto-eid.py <iid> <hash-prefix>
#
# Both input parameters are required. <iid> is a number between 0 and 2^32-1
# and <hash-prefix> is an IPv6 prefix in slash format. An example would be:
#
#     python make-crypto-eid.py 1000 fd::/8
#
# The map-server is required to have the following command to accept Map-
# Register messages for the above generated crypto-EID:
#
# lisp eid-crypto-hash {
#     instance-id = *
#     eid-prefix = fd00::/8   
# }
#
# The complex part of this code to do key generation is from make-eid-hash.py
# and interoperates with the lispers.net implementation of draft-farinacci-
# lisp-ecdsa-auth-02.txt.
#
#------------------------------------------------------------------------------
from __future__ import print_function
import ecdsa
import sys
import hashlib
from binascii import b2a_base64 as b2a
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
def IiII1IiiIiI1 ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 40 - 40: oo * OoO0O00
 if 2 - 2: ooOO00oOo % oOo0O0Ooo * Ooo00oOo00o . oOoO0oo0OOOo + iiiiIi11i
 if 24 - 24: II11iiII / OoOO0ooOOoo0O + o0000oOoOoO0o * i1I1ii1II1iII % oooO0oo0oOOOO
 if 53 - 53: o0oo0o / Oo + o0oo0o / oooO0oo0oOOOO * OoooooooOO + i1I1ii1II1iII
 if 71 - 71: II11iiII * i1I1ii1II1iII . II11iiII / o0oo0o
 if 14 - 14: iIii1I11I1II1
 if 56 - 56: OoOO0ooOOoo0O - i1IIi
if ( len ( sys . argv ) != 3 ) :
 print ( "Usage: python make-crypto-eid.py <iid> <hash-prefix>" )
 exit ( 1 )
 if 64 - 64: o0oo0o + i1I1ii1II1iII
 if 10 - 10: i11iIiiIii / iiiiIi11i % II111iiii
Ooo00O0 = sys . argv [ 1 ]
if ( Ooo00O0 . isdigit ( ) == False ) :
 print ( "Instance-ID must be between 0 and 0xffffffff" )
 exit ( 1 )
 if 59 - 59: iIii1I11I1II1
Ooo00O0 = int ( Ooo00O0 )
if 31 - 31: oooO0oo0oOOOO % i1IIi * iIii1I11I1II1 / oooO0oo0oOOOO % iiiiIi11i + OoooooooOO
O00o0o0000o0o = sys . argv [ 2 ]
if ( O00o0o0000o0o . find ( "/" ) == - 1 or O00o0o0000o0o . count ( ":" ) == 0 ) :
 print ( "EID-prefix must be an IPv6 address in slash format" )
 exit ( 1 )
 if 88 - 88: i1I1ii1II1iII / oo + i1IIi % OoooooooOO . oooO0oo0oOOOO / Oo
O00o0o0000o0o , I1I1i1 = O00o0o0000o0o . split ( "/" )
I1I1i1 = int ( I1I1i1 )
if ( ( I1I1i1 % 4 ) != 0 ) :
 print ( "Mask-length must be a multiple of 4" )
 exit ( 1 )
 if 18 - 18: iIii1I11I1II1 / OoOO0ooOOoo0O + iiiiIi11i / OoO0O00 - II111iiii - OoOO0ooOOoo0O
 if 1 - 1: OoOO0ooOOoo0O - II11iiII % O0 + oo - i1I1ii1II1iII / OoOO0ooOOoo0O
 if 31 - 31: ooOO00oOo + II111iiii
 if 13 - 13: II11iiII * iiiiIi11i * oo
 if 55 - 55: II111iiii
print ( "Generating key-pair ..." , end = " " )
IIIiI11ii = ecdsa . SigningKey . generate ( curve = ecdsa . NIST256p )
O000oo = IIIiI11ii . get_verifying_key ( ) . to_der ( )
print ( "" )
if 3 - 3: i1I1ii1II1iII + O0
I1Ii = open ( "./lisp-sig.pem" , "w" ) ; I1Ii . write ( IIIiI11ii . to_pem ( ) ) ; I1Ii . close ( )
print ( "Private-key stored in file {}" . format ( IiII1IiiIiI1 ( "lisp-sig.pem" ) ) )
if 66 - 66: o0000oOoOoO0o
if 78 - 78: ooOO00oOo
if 18 - 18: O0 - i1I1ii1II1iII / i1I1ii1II1iII + Oo % Oo - oooO0oo0oOOOO
if 62 - 62: i1I1ii1II1iII - oooO0oo0oOOOO - oOo0O0Ooo % i1IIi / iiiiIi11i
O00o0o0000o0o = O00o0o0000o0o . replace ( ":" , "" )
O00o0o0000o0o = int ( O00o0o0000o0o , 16 )
if 77 - 77: II111iiii - II111iiii . oo / Ooo00oOo00o
i1iIIIiI1I = hex ( Ooo00O0 ) [ 2 : : ] . zfill ( 8 )
OOoO000O0OO = hex ( O00o0o0000o0o ) [ 2 : : ]
if 23 - 23: i11iIiiIii + oo
if 68 - 68: oOo0O0Ooo . iiiiIi11i . i11iIiiIii
if 40 - 40: iiiiIi11i . oOo0O0Ooo . OoO0O00 . i1IIi
if 33 - 33: o0000oOoOoO0o + II111iiii % i11iIiiIii . Oo - oo
O00oooo0O = i1iIIIiI1I + OOoO000O0OO + O000oo
IiI1i11iii1 = hashlib . sha256 ( O00oooo0O ) . hexdigest ( )
if 96 - 96: O0 % iiiiIi11i % iIii1I11I1II1
Oo00OOOOO = ( 128 - I1I1i1 ) / 4
O0O = IiI1i11iii1 [ 0 : Oo00OOOOO ]
IiI1i11iii1 = int ( O0O , 16 )
if 83 - 83: OoOO0ooOOoo0O + II111iiii * Ooo00oOo00o % ooOO00oOo + OoOO0ooOOoo0O
Ii1iIIIi1ii = ( O00o0o0000o0o << ( 128 - I1I1i1 ) ) + IiI1i11iii1
Ii1iIIIi1ii = hex ( Ii1iIIIi1ii ) [ 2 : - 1 ]
Ii1iIIIi1ii = Ii1iIIIi1ii [ 0 : 4 ] + ":" + Ii1iIIIi1ii [ 4 : 8 ] + ":" + Ii1iIIIi1ii [ 8 : 12 ] + ":" + Ii1iIIIi1ii [ 12 : 16 ] + ":" + Ii1iIIIi1ii [ 16 : 20 ] + ":" + Ii1iIIIi1ii [ 20 : 24 ] + ":" + Ii1iIIIi1ii [ 24 : 28 ] + ":" + Ii1iIIIi1ii [ 28 : 32 ]
if 80 - 80: OoOO0ooOOoo0O * i11iIiiIii / o0oo0o
Ii1iIIIi1ii = Ii1iIIIi1ii . replace ( ":000" , ":" )
Ii1iIIIi1ii = Ii1iIIIi1ii . replace ( ":00" , ":" )
Ii1iIIIi1ii = Ii1iIIIi1ii . replace ( ":0" , ":" )
if 9 - 9: o0000oOoOoO0o + iiiiIi11i % o0000oOoOoO0o + i1IIi . II11iiII
if 31 - 31: Ooo00oOo00o + OoOO0ooOOoo0O + OoOO0ooOOoo0O / II111iiii
if 26 - 26: OoooooooOO
if 12 - 12: OoooooooOO % oOo0O0Ooo / Oo % Ooo00oOo00o
if 29 - 29: OoooooooOO
if 23 - 23: Ooo00oOo00o . II111iiii
Oo0O0OOOoo = "[{}]{}" . format ( Ooo00O0 , Ii1iIIIi1ii )
oOoOooOo0o0 = IIIiI11ii . sign ( Oo0O0OOOoo , hashfunc = hashlib . sha256 )
if 61 - 61: Ooo00oOo00o / ooOO00oOo + Oo * iiiiIi11i / iiiiIi11i
if 75 - 75: i1IIi / OoooooooOO - O0 / oOo0O0Ooo . II111iiii - i1IIi
if 71 - 71: II11iiII + o0000oOoOoO0o * II11iiII - ooOO00oOo * Ooo00oOo00o
if 65 - 65: O0 % oo . oOoO0oo0OOOo % iIii1I11I1II1 / II11iiII % o0oo0o
print ( "Generated crypto-EID {}\n" . format ( IiII1IiiIiI1 ( Oo0O0OOOoo ) ) )
if 51 - 51: i11iIiiIii . oo + II111iiii
O000oo = b2a ( IIIiI11ii . get_verifying_key ( ) . to_pem ( ) )
print ( "Public-key {}" . format ( O000oo ) )
oOoOooOo0o0 = b2a ( oOoOooOo0o0 )
if 10 - 10: oOoO0oo0OOOo * Oo * II111iiii % o0000oOoOoO0o . II11iiII + o0oo0o
IIiIi11i1 = O0O
if ( ( len ( IIiIi11i1 ) % 4 ) == 0 ) :
 O0O = [ ]
else :
 O0O = [ IIiIi11i1 [ 0 : 2 ] ]
 IIiIi11i1 = IIiIi11i1 [ 2 : : ]
 if 29 - 29: oOoO0oo0OOOo % oo + Oo / Ooo00oOo00o + II11iiII * Ooo00oOo00o
for i1I1iI in range ( 0 , len ( IIiIi11i1 ) , 4 ) :
 O0O . append ( IIiIi11i1 [ i1I1iI : i1I1iI + 4 ] )
 if 93 - 93: iIii1I11I1II1 % iiiiIi11i * i1IIi
 if 16 - 16: O0 - o0oo0o * iIii1I11I1II1 + i1I1ii1II1iII
O0O = ":" . join ( O0O )
Ii11iII1 = Ii1iIIIi1ii [ - 4 : : ]
O000oo = O000oo . replace ( "\n" , "" )
oOoOooOo0o0 = oOoOooOo0o0 . replace ( "\n" , "" )
if 51 - 51: II111iiii * ooOO00oOo % Ooo00oOo00o * II111iiii % oOoO0oo0OOOo / Oo
iIIIIii1 = '''
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
        interface = eth0
    }
    rloc {
        json-name = signature-<ev>
        priority = 255
    }
}
'''
iIIIIii1 = iIIIIii1 . replace ( "<ev>" , Ii11iII1 )
iIIIIii1 = iIIIIii1 . replace ( "<hv>" , O0O )
iIIIIii1 = iIIIIii1 . replace ( "<iid>" , str ( Ooo00O0 ) )
iIIIIii1 = iIIIIii1 . replace ( "<eid>" , Ii1iIIIi1ii )
iIIIIii1 = iIIIIii1 . replace ( "<pubkey>" , O000oo )
iIIIIii1 = iIIIIii1 . replace ( "<sig>" , oOoOooOo0o0 )
if 58 - 58: i11iIiiIii % OoOO0ooOOoo0O
I1Ii = open ( "./lisp.config.include" , "w" ) ; I1Ii . write ( iIIIIii1 ) ; I1Ii . close ( )
if 71 - 71: II11iiII + Oo % i11iIiiIii + oOoO0oo0OOOo - oooO0oo0oOOOO
print ( "lispers.net commands added to file {}" . format (
 IiII1IiiIiI1 ( "lisp.config.include" ) ) )
exit ( 0 )
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
