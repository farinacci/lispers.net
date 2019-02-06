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
# lisp-news-receiver.py
#
# Listen on the (S,G) and print messages received.
#
# Usage: python lisp-news-receiver.py <source> <group>
#
if 64 - 64: i11iIiiIii
import sys
import socket
import datetime
import struct
import threading
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
I1IiI = "Usage: python lisp-news-receiver.py <source> <group>"
o0OOO = ""
iIiiiI = ""
Iii1ii1II11i = ""
iI111iI = None
IiII = None
if 28 - 28: Ii11111i * iiI1i1
if 46 - 46: Ooo0OO0oOO * Ii * Oo0o
if 60 - 60: Oo0oO0oo0oO00 + i11Ii11I1Ii1i . ooO - II111iiii
def OOoO ( msocket , group ) :
 global IiII
 if 91 - 91: OoO0O00 . i11iIiiIii / Ii11111i % Ooo0OO0oOO / OoO0O00 - i11iIiiIii
 II1Iiii1111i = struct . pack ( "4sl" , socket . inet_aton ( group ) , socket . INADDR_ANY )
 msocket . setsockopt ( socket . IPPROTO_IP , socket . IP_DROP_MEMBERSHIP , II1Iiii1111i )
 msocket . setsockopt ( socket . IPPROTO_IP , socket . IP_ADD_MEMBERSHIP , II1Iiii1111i )
 IiII = threading . Timer ( 30 , OOoO , [ msocket , group ] )
 IiII . start ( )
 if 25 - 25: Ii
 if 89 - 89: OoooooooOO - Oo0oO0oo0oO00 * ooO
 if 82 - 82: Ooo0OO0oOO . i11Ii11I1Ii1i / Oo0oO0oo0oO00 % II111iiii % iIii1I11I1II1 % Oo0oO0oo0oO00
 if 86 - 86: OoOoOO00 % I1IiiI
 if 80 - 80: OoooooooOO . I1IiiI
 if 87 - 87: Ii11111i / ooO + i11Ii11I1Ii1i - ooO . ooO / II111iiii
if ( len ( sys . argv ) < 3 ) :
 print I1IiI
 exit ( 1 )
 if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
 if 58 - 58: i11iIiiIii % i11Ii11I1Ii1i
o0OOO = sys . argv [ 1 ]
iIiiiI = sys . argv [ 2 ]
if 54 - 54: iiI1i1 % O0 + I1IiiI - Oo0o / Ooo0OO0oOO
if ( o0OOO . find ( "." ) == - 1 or iIiiiI . find ( "." ) == - 1 ) :
 print "Must supply IPv4 address in dotted decimal"
 exit ( 1 )
 if 31 - 31: OoO0O00 + II111iiii
 if 13 - 13: iiI1i1 * Ii11111i * I1IiiI
Iii1ii1II11i = iIiiiI . split ( "." )
Iii1ii1II11i = 0x800 + int ( Iii1ii1II11i [ - 2 ] ) + int ( Iii1ii1II11i [ - 1 ] )
if 55 - 55: II111iiii
if 43 - 43: OoOoOO00 - i1IIi + i11Ii11I1Ii1i + Ii
if 17 - 17: o0oOOo0O0Ooo
if 64 - 64: Ii % i1IIi % OoooooooOO
print "Open listen socket ({} -> {}:{}) ... " . format ( o0OOO , iIiiiI , Iii1ii1II11i ) ,
if 3 - 3: Oo0o + O0
try :
 iI111iI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
 iI111iI . bind ( ( iIiiiI , Iii1ii1II11i ) )
 iI111iI . setsockopt ( socket . SOL_SOCKET , socket . SO_REUSEADDR , 1 )
 II1Iiii1111i = struct . pack ( "4sl" , socket . inet_aton ( iIiiiI ) , socket . INADDR_ANY )
 iI111iI . setsockopt ( socket . IPPROTO_IP , socket . IP_ADD_MEMBERSHIP , II1Iiii1111i )
 print "succeeded"
except :
 print "failed"
 exit ( 1 )
 if 42 - 42: iiI1i1 / i1IIi + i11iIiiIii - Ii
 if 78 - 78: OoO0O00
IiII = threading . Timer ( 15 , OOoO , [ iI111iI , iIiiiI ] )
IiII . start ( )
if 18 - 18: O0 - Oo0o / Oo0o + ooO % ooO - Oo0oO0oo0oO00
if 62 - 62: Oo0o - Oo0oO0oo0oO00 - OoOoOO00 % i1IIi / Ii11111i
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
if 14 - 14: Ooo0OO0oOO % O0
while ( True ) :
 try :
  IiI1I1 = iI111iI . recvfrom ( 1000 )
  IiI1I1 = IiI1I1 [ 0 ]
 except :
  break
  if 86 - 86: i11iIiiIii + Ii + ooO * Ooo0OO0oOO + o0oOOo0O0Ooo
  if 61 - 61: OoO0O00 / i11iIiiIii
 IiIiIi = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 print "Message received {}:\n{}\n" . format ( IiIiIi , IiI1I1 [ 0 : - 1 ] ) ,
 for II in range ( 40 ) : print "-" ,
 print ""
 if 14 - 14: Oo0Ooo . I1IiiI / Ii
 if 38 - 38: II111iiii % i11iIiiIii . ooO - iiI1i1 + Ii
IiII . cancel ( )
iI111iI . close ( )
exit ( 0 )
if 66 - 66: OoooooooOO * OoooooooOO . iiI1i1 . i1IIi - iiI1i1
if 77 - 77: Ooo0OO0oOO - iIii1I11I1II1
if 82 - 82: i11iIiiIii . iiI1i1 / Oo0Ooo * O0 % Ii11111i % iIii1I11I1II1
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
