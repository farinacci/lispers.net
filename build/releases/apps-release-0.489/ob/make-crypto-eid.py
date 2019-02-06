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
if 64 - 64: i11iIiiIii
import ecdsa
import sys
import hashlib
from binascii import b2a_base64 as b2a
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
def I1IiI ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 73 - 73: OOooOOo / ii11ii1ii
 if 94 - 94: OoOO + OoOO0ooOOoo0O + o0000oOoOoO0o * o00O0oo
 if 97 - 97: oO0o0ooO0 - IIII / o0oOOo0O0Ooo - oO0o0ooO0
 if 21 - 21: Oo0Ooo / II111iiii % OoOO0ooOOoo0O / OoOoOO00 . IIII
 if 100 - 100: i1IIi
 if 27 - 27: o00O0oo * OoooooooOO + OoOO * IIII - i11iIiiIii - o0000oOoOoO0o
 if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . II111iiii - OOooOOo
if ( len ( sys . argv ) != 3 ) :
 print "Usage: python make-crypto-eid.py <iid> <hash-prefix>"
 exit ( 1 )
 if 72 - 72: II111iiii - OoOoOO00
 if 91 - 91: OoO0O00 . i11iIiiIii / OOooOOo % OoOO / OoO0O00 - i11iIiiIii
II1Iiii1111i = sys . argv [ 1 ]
if ( II1Iiii1111i . isdigit ( ) == False ) :
 print "Instance-ID must be between 0 and 0xffffffff"
 exit ( 1 )
 if 25 - 25: OoOO0ooOOoo0O
II1Iiii1111i = int ( II1Iiii1111i )
if 89 - 89: OoooooooOO - o00O0oo * IIII
O0I11i1i11i1I = sys . argv [ 2 ]
if ( O0I11i1i11i1I . find ( "/" ) == - 1 or O0I11i1i11i1I . count ( ":" ) == 0 ) :
 print "EID-prefix must be an IPv6 address in slash format"
 exit ( 1 )
 if 31 - 31: i11iIiiIii / I1IiiI / IIII * OOooOOo / Oo0Ooo
O0I11i1i11i1I , Oo0o0ooO0oOOO = O0I11i1i11i1I . split ( "/" )
Oo0o0ooO0oOOO = int ( Oo0o0ooO0oOOO )
if ( ( Oo0o0ooO0oOOO % 4 ) != 0 ) :
 print "Mask-length must be a multiple of 4"
 exit ( 1 )
 if 58 - 58: i11iIiiIii % oO0o0ooO0
 if 54 - 54: ii11ii1ii % O0 + I1IiiI - o0000oOoOoO0o / OoOO
 if 31 - 31: OoO0O00 + II111iiii
 if 13 - 13: ii11ii1ii * OOooOOo * I1IiiI
 if 55 - 55: II111iiii
print "Generating key-pair ..." ,
IIIiI11ii = ecdsa . SigningKey . generate ( curve = ecdsa . NIST256p )
O000oo = IIIiI11ii . get_verifying_key ( ) . to_der ( )
print ""
if 3 - 3: o0000oOoOoO0o + O0
I1Ii = open ( "./lisp-sig.pem" , "w" ) ; I1Ii . write ( IIIiI11ii . to_pem ( ) ) ; I1Ii . close ( )
print "Private-key stored in file {}" . format ( I1IiI ( "lisp-sig.pem" ) )
if 66 - 66: OoOO0ooOOoo0O
if 78 - 78: OoO0O00
if 18 - 18: O0 - o0000oOoOoO0o / o0000oOoOoO0o + IIII % IIII - o00O0oo
if 62 - 62: o0000oOoOoO0o - o00O0oo - OoOoOO00 % i1IIi / OOooOOo
O0I11i1i11i1I = O0I11i1i11i1I . replace ( ":" , "" )
O0I11i1i11i1I = int ( O0I11i1i11i1I , 16 )
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
i1iIIIiI1I = hex ( II1Iiii1111i ) [ 2 : : ] . zfill ( 8 )
OOoO000O0OO = hex ( O0I11i1i11i1I ) [ 2 : : ]
if 23 - 23: i11iIiiIii + I1IiiI
if 68 - 68: OoOoOO00 . OOooOOo . i11iIiiIii
if 40 - 40: OOooOOo . OoOoOO00 . Oo0Ooo . i1IIi
if 33 - 33: OoOO0ooOOoo0O + II111iiii % i11iIiiIii . IIII - I1IiiI
O00oooo0O = i1iIIIiI1I + OOoO000O0OO + O000oo
IiI1i11iii1 = hashlib . sha256 ( O00oooo0O ) . hexdigest ( )
if 96 - 96: O0 % OOooOOo % iIii1I11I1II1
Oo00OOOOO = ( 128 - Oo0o0ooO0oOOO ) / 4
O0O = IiI1i11iii1 [ 0 : Oo00OOOOO ]
IiI1i11iii1 = int ( O0O , 16 )
if 83 - 83: OoOO + II111iiii * o0oOOo0O0Ooo % OoO0O00 + OoOO
Ii1iIIIi1ii = ( O0I11i1i11i1I << ( 128 - Oo0o0ooO0oOOO ) ) + IiI1i11iii1
Ii1iIIIi1ii = hex ( Ii1iIIIi1ii ) [ 2 : - 1 ]
Ii1iIIIi1ii = Ii1iIIIi1ii [ 0 : 4 ] + ":" + Ii1iIIIi1ii [ 4 : 8 ] + ":" + Ii1iIIIi1ii [ 8 : 12 ] + ":" + Ii1iIIIi1ii [ 12 : 16 ] + ":" + Ii1iIIIi1ii [ 16 : 20 ] + ":" + Ii1iIIIi1ii [ 20 : 24 ] + ":" + Ii1iIIIi1ii [ 24 : 28 ] + ":" + Ii1iIIIi1ii [ 28 : 32 ]
if 80 - 80: OoOO * i11iIiiIii / oO0o0ooO0
Ii1iIIIi1ii = Ii1iIIIi1ii . replace ( ":000" , ":" )
Ii1iIIIi1ii = Ii1iIIIi1ii . replace ( ":00" , ":" )
Ii1iIIIi1ii = Ii1iIIIi1ii . replace ( ":0" , ":" )
if 9 - 9: OoOO0ooOOoo0O + OOooOOo % OoOO0ooOOoo0O + i1IIi . ii11ii1ii
if 31 - 31: o0oOOo0O0Ooo + OoOO + OoOO / II111iiii
if 26 - 26: OoooooooOO
if 12 - 12: OoooooooOO % OoOoOO00 / IIII % o0oOOo0O0Ooo
if 29 - 29: OoooooooOO
if 23 - 23: o0oOOo0O0Ooo . II111iiii
Oo0O0OOOoo = "[{}]{}" . format ( II1Iiii1111i , Ii1iIIIi1ii )
oOoOooOo0o0 = IIIiI11ii . sign ( Oo0O0OOOoo , hashfunc = hashlib . sha256 )
if 61 - 61: o0oOOo0O0Ooo / OoO0O00 + IIII * OOooOOo / OOooOOo
if 75 - 75: i1IIi / OoooooooOO - O0 / OoOoOO00 . II111iiii - i1IIi
if 71 - 71: ii11ii1ii + OoOO0ooOOoo0O * ii11ii1ii - OoO0O00 * o0oOOo0O0Ooo
if 65 - 65: O0 % I1IiiI . I1ii11iIi11i % iIii1I11I1II1 / ii11ii1ii % oO0o0ooO0
print "Generated crypto-EID {}\n" . format ( I1IiI ( Oo0O0OOOoo ) )
if 51 - 51: i11iIiiIii . I1IiiI + II111iiii
O000oo = b2a ( IIIiI11ii . get_verifying_key ( ) . to_pem ( ) )
print "Public-key {}" . format ( O000oo )
oOoOooOo0o0 = b2a ( oOoOooOo0o0 )
if 10 - 10: I1ii11iIi11i * IIII * II111iiii % OoOO0ooOOoo0O . ii11ii1ii + oO0o0ooO0
IIiIi11i1 = O0O
if ( ( len ( IIiIi11i1 ) % 4 ) == 0 ) :
 O0O = [ ]
else :
 O0O = [ IIiIi11i1 [ 0 : 2 ] ]
 IIiIi11i1 = IIiIi11i1 [ 2 : : ]
 if 29 - 29: I1ii11iIi11i % I1IiiI + IIII / o0oOOo0O0Ooo + ii11ii1ii * o0oOOo0O0Ooo
for i1I1iI in range ( 0 , len ( IIiIi11i1 ) , 4 ) :
 O0O . append ( IIiIi11i1 [ i1I1iI : i1I1iI + 4 ] )
 if 93 - 93: iIii1I11I1II1 % OOooOOo * i1IIi
 if 16 - 16: O0 - oO0o0ooO0 * iIii1I11I1II1 + o0000oOoOoO0o
O0O = ":" . join ( O0O )
Ii11iII1 = Ii1iIIIi1ii [ - 4 : : ]
O000oo = O000oo . replace ( "\n" , "" )
oOoOooOo0o0 = oOoOooOo0o0 . replace ( "\n" , "" )
if 51 - 51: II111iiii * OoO0O00 % o0oOOo0O0Ooo * II111iiii % I1ii11iIi11i / IIII
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
iIIIIii1 = iIIIIii1 . replace ( "<iid>" , str ( II1Iiii1111i ) )
iIIIIii1 = iIIIIii1 . replace ( "<eid>" , Ii1iIIIi1ii )
iIIIIii1 = iIIIIii1 . replace ( "<pubkey>" , O000oo )
iIIIIii1 = iIIIIii1 . replace ( "<sig>" , oOoOooOo0o0 )
if 58 - 58: i11iIiiIii % OoOO
I1Ii = open ( "./lisp.config.include" , "w" ) ; I1Ii . write ( iIIIIii1 ) ; I1Ii . close ( )
if 71 - 71: ii11ii1ii + IIII % i11iIiiIii + I1ii11iIi11i - o00O0oo
print "lispers.net commands added to file {}" . format (
 I1IiI ( "lisp.config.include" ) )
exit ( 0 )
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
