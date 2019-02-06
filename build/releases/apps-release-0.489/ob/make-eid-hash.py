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
if 64 - 64: i11iIiiIii
import ecdsa
import hashlib
from binascii import b2a_base64 as b2a
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
IiiIII111iI = raw_input ( "Enter EID-prefix (zero-fill prefix bits): " )
if ( IiiIII111iI . find ( "/" ) == - 1 or IiiIII111iI . count ( ":" ) == 0 ) :
 print "EID-prefix must be an IPv6 address in slash format"
 exit ( 1 )
 if 34 - 34: iii1I1I / O00oOoOoO0o0O . O0oo0OO0 + Oo0ooO0oo0oO . OoO0O00 - I1ii11iIi11i
IiiIII111iI , O0oO = IiiIII111iI . split ( "/" )
O0oO = int ( O0oO )
if ( ( O0oO % 4 ) != 0 ) :
 print "Mask-length must be a multiple of 4"
 exit ( 1 )
 if 68 - 68: Ii1I / O0
 if 46 - 46: O0 * II111iiii / O00oOoOoO0o0O * Oo0Ooo * iii1I1I . I11i
Oo0oO0ooo = raw_input ( "Enter Instance-ID: " )
try :
 Oo0oO0ooo = 0 if ( Oo0oO0ooo == "" ) else int ( Oo0oO0ooo )
except :
 print "Invalid Instance-ID"
 exit ( 1 )
 if 56 - 56: I11i - i1IIi
print ""
if 64 - 64: O0oo0OO0 + iii1I1I
if 10 - 10: i11iIiiIii / oO0o % II111iiii
if 75 - 75: i11iIiiIii + O00oOoOoO0o0O . o0oOOo0O0Ooo * iii1I1I
if 59 - 59: iIii1I11I1II1
I11iii11IIi = ecdsa . SigningKey . generate ( curve = ecdsa . NIST256p )
O00o0o0000o0o = I11iii11IIi . get_verifying_key ( ) . to_der ( )
if 88 - 88: iii1I1I / I1IiiI + i1IIi % OoooooooOO . O00oOoOoO0o0O / Oo0ooO0oo0oO
if 28 - 28: Oo0ooO0oo0oO + O0oo0OO0 - Oo0ooO0oo0oO . OoooooooOO
if 97 - 97: OoO0O00 . I11i
if 32 - 32: Oo0Ooo - II111iiii - i11iIiiIii % O0oo0OO0
IiiIII111iI = IiiIII111iI . replace ( ":" , "" )
IiiIII111iI = int ( IiiIII111iI , 16 )
if 54 - 54: OOooOOo % O0 + I1IiiI - iii1I1I / I11i
iIiiI1 = hex ( Oo0oO0ooo ) [ 2 : : ] . zfill ( 8 )
OoOooOOOO = hex ( IiiIII111iI ) [ 2 : : ]
if 45 - 45: O0oo0OO0 + Ii1I
if 17 - 17: o0oOOo0O0Ooo
if 64 - 64: Ii1I % i1IIi % OoooooooOO
if 3 - 3: iii1I1I + O0
I1Ii = iIiiI1 + OoOooOOOO + O00o0o0000o0o
o0oOo0Ooo0O = hashlib . sha256 ( I1Ii ) . hexdigest ( )
if 81 - 81: I1ii11iIi11i * O00oOoOoO0o0O * I11i - iii1I1I - o0oOOo0O0Ooo
OooO0OO = ( 128 - O0oO ) / 4
iiiIi = o0oOo0Ooo0O [ 0 : OooO0OO ]
o0oOo0Ooo0O = int ( iiiIi , 16 )
if 24 - 24: O0 % o0oOOo0O0Ooo + i1IIi + O0oo0OO0 + I1ii11iIi11i
OOoO000O0OO = ( IiiIII111iI << ( 128 - O0oO ) ) + o0oOo0Ooo0O
OOoO000O0OO = hex ( OOoO000O0OO ) [ 2 : - 1 ]
OOoO000O0OO = OOoO000O0OO [ 0 : 4 ] + ":" + OOoO000O0OO [ 4 : 8 ] + ":" + OOoO000O0OO [ 8 : 12 ] + ":" + OOoO000O0OO [ 12 : 16 ] + ":" + OOoO000O0OO [ 16 : 20 ] + ":" + OOoO000O0OO [ 20 : 24 ] + ":" + OOoO000O0OO [ 24 : 28 ] + ":" + OOoO000O0OO [ 28 : 32 ]
if 23 - 23: i11iIiiIii + I1IiiI
OOoO000O0OO = OOoO000O0OO . replace ( ":000" , ":" )
OOoO000O0OO = OOoO000O0OO . replace ( ":00" , ":" )
OOoO000O0OO = OOoO000O0OO . replace ( ":0" , ":" )
if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
if 33 - 33: Ii1I + II111iiii % i11iIiiIii . Oo0ooO0oo0oO - I1IiiI
if 66 - 66: Ii1I - OoooooooOO * OoooooooOO . OOooOOo . I1ii11iIi11i
if 22 - 22: OoooooooOO % I11i - iii1I1I . iIii1I11I1II1 * i11iIiiIii
if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . O00oOoOoO0o0O
o0OOOOO00o0O0 = "[{}]{}" . format ( Oo0oO0ooo , OOoO000O0OO )
o0o0OOO0o0 = I11iii11IIi . sign ( o0OOOOO00o0O0 , hashfunc = hashlib . sha256 )
if 84 - 84: O00oOoOoO0o0O
if 25 - 25: Oo0Ooo - O00oOoOoO0o0O . OoooooooOO
if 22 - 22: O00oOoOoO0o0O + II111iiii % O0oo0OO0 . I11i . OoOoOO00
if 76 - 76: OoOoOO00 - O0 % OOooOOo / I1ii11iIi11i / OoOoOO00
print "----------------------------------------------------------------------"
print ""
print "Crypto-hashed EID: {}" . format ( o0OOOOO00o0O0 )
print ""
print "Private-key for lisp-sig.pem/lisp-lig.pem file:\n{}" . format ( I11iii11IIi . to_pem ( ) )
if 54 - 54: I1IiiI % II111iiii % II111iiii
if 13 - 13: o0oOOo0O0Ooo . Ii1I
O00o0o0000o0o = b2a ( I11iii11IIi . get_verifying_key ( ) . to_pem ( ) )
print "Public-key for lisp.config file:\n{}" . format ( O00o0o0000o0o )
o0o0OOO0o0 = b2a ( o0o0OOO0o0 )
print "EID signature for lisp.config file:\n{}" . format ( o0o0OOO0o0 )
if 19 - 19: I11i + Oo0ooO0oo0oO
print "----------------------------------------------------------------------"
print ""
if 53 - 53: OoooooooOO . i1IIi
print "Add the following commands to the lisp.config file:"
if 18 - 18: o0oOOo0O0Ooo
I1i1I1II = iiiIi
if ( ( len ( I1i1I1II ) % 4 ) == 0 ) :
 iiiIi = [ ]
else :
 iiiIi = [ I1i1I1II [ 0 : 2 ] ]
 I1i1I1II = I1i1I1II [ 2 : : ]
 if 45 - 45: O0oo0OO0 . OoOoOO00
for oO in range ( 0 , len ( I1i1I1II ) , 4 ) :
 iiiIi . append ( I1i1I1II [ oO : oO + 4 ] )
 if 6 - 6: I1ii11iIi11i
 if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + Oo0ooO0oo0oO * I1IiiI
iiiIi = ":" . join ( iiiIi )
O0ooOooooO = OOoO000O0OO [ - 4 : : ]
O00o0o0000o0o = O00o0o0000o0o . replace ( "\n" , "" )
o0o0OOO0o0 = o0o0OOO0o0 . replace ( "\n" , "" )
if 60 - 60: I11i / I11i
I1II1III11iii = '''
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
I1II1III11iii = I1II1III11iii . replace ( "<ev>" , O0ooOooooO )
I1II1III11iii = I1II1III11iii . replace ( "<hv>" , iiiIi )
I1II1III11iii = I1II1III11iii . replace ( "<iid>" , str ( Oo0oO0ooo ) )
I1II1III11iii = I1II1III11iii . replace ( "<eid>" , OOoO000O0OO )
I1II1III11iii = I1II1III11iii . replace ( "<pubkey>" , O00o0o0000o0o )
I1II1III11iii = I1II1III11iii . replace ( "<sig>" , o0o0OOO0o0 )
if 75 - 75: iIii1I11I1II1 / OOooOOo % o0oOOo0O0Ooo * OoOoOO00
print I1II1III11iii
print "----------------------------------------------------------------------"
if 9 - 9: OoO0O00
exit ( 0 )
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
