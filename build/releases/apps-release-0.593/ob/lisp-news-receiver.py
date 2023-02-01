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
from __future__ import print_function
import sys
import socket
import datetime
import struct
import threading
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
IiII1IiiIiI1 = "Usage: python lisp-news-receiver.py <source> <group>"
iIiiiI1IiI1I1 = ""
o0OoOoOO00 = ""
I11i = ""
O0O = None
Oo = None
if 2 - 2: o0 * i1 * ii1IiI1i % OOooOOo / I11iIi1I / IiiIII111iI
if 34 - 34: iii1I1I / O00oOoOoO0o0O . O0oo0OO0 + Oo0ooO0oo0oO . I1i1iI1i - II
if 100 - 100: i11Ii11I1Ii1i . ooO - iii1I1I / i1IIi % II111iiii - OOooOOo
def OOo ( msocket , group ) :
 global Oo
 if 1 - 1: II111iiii - IiiIII111iI % i11iIiiIii + II . i11Ii11I1Ii1i
 Oooo0000 = struct . pack ( "4sl" , socket . inet_aton ( group ) , socket . INADDR_ANY )
 msocket . setsockopt ( socket . IPPROTO_IP , socket . IP_DROP_MEMBERSHIP , Oooo0000 )
 msocket . setsockopt ( socket . IPPROTO_IP , socket . IP_ADD_MEMBERSHIP , Oooo0000 )
 Oo = threading . Timer ( 30 , OOo , [ msocket , group ] )
 Oo . start ( )
 if 22 - 22: Oo0ooO0oo0oO . II
 if 41 - 41: i11Ii11I1Ii1i . ooO * II % i11iIiiIii
 if 74 - 74: I1i1iI1i * II
 if 82 - 82: iIii1I11I1II1 % II
 if 86 - 86: OOooOOo % o0
 if 80 - 80: OoooooooOO . o0
if ( len ( sys . argv ) < 3 ) :
 print ( IiII1IiiIiI1 )
 exit ( 1 )
 if 87 - 87: iii1I1I / ooO + i11Ii11I1Ii1i - ooO . ooO / II111iiii
 if 11 - 11: o0 % I11iIi1I - i1
iIiiiI1IiI1I1 = sys . argv [ 1 ]
o0OoOoOO00 = sys . argv [ 2 ]
if 58 - 58: i11iIiiIii % i11Ii11I1Ii1i
if ( iIiiiI1IiI1I1 . find ( "." ) == - 1 or o0OoOoOO00 . find ( "." ) == - 1 ) :
 print ( "Must supply IPv4 address in dotted decimal" )
 exit ( 1 )
 if 54 - 54: O00oOoOoO0o0O % O0 + o0 - I1i1iI1i / O0oo0OO0
 if 31 - 31: ii1IiI1i + II111iiii
I11i = o0OoOoOO00 . split ( "." )
I11i = 0x800 + int ( I11i [ - 2 ] ) + int ( I11i [ - 1 ] )
if 13 - 13: O00oOoOoO0o0O * iii1I1I * o0
if 55 - 55: II111iiii
if 43 - 43: OOooOOo - i1IIi + i11Ii11I1Ii1i + Oo0ooO0oo0oO
if 17 - 17: I11iIi1I
print ( "Open listen socket ({} -> {}:{}) ... " . format ( iIiiiI1IiI1I1 , o0OoOoOO00 , I11i ) ,
 end = " " )
if 64 - 64: Oo0ooO0oo0oO % i1IIi % OoooooooOO
try :
 O0O = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
 O0O . bind ( ( o0OoOoOO00 , I11i ) )
 O0O . setsockopt ( socket . SOL_SOCKET , socket . SO_REUSEADDR , 1 )
 Oooo0000 = struct . pack ( "4sl" , socket . inet_aton ( o0OoOoOO00 ) , socket . INADDR_ANY )
 O0O . setsockopt ( socket . IPPROTO_IP , socket . IP_ADD_MEMBERSHIP , Oooo0000 )
 print ( "succeeded" )
except :
 print ( "failed" )
 exit ( 1 )
 if 3 - 3: I1i1iI1i + O0
 if 42 - 42: O00oOoOoO0o0O / i1IIi + i11iIiiIii - Oo0ooO0oo0oO
Oo = threading . Timer ( 15 , OOo , [ O0O , o0OoOoOO00 ] )
Oo . start ( )
if 78 - 78: ii1IiI1i
if 18 - 18: O0 - I1i1iI1i / I1i1iI1i + ooO % ooO - II
if 62 - 62: I1i1iI1i - II - OOooOOo % i1IIi / iii1I1I
if 77 - 77: II111iiii - II111iiii . o0 / I11iIi1I
while ( True ) :
 try :
  i1iIIIiI1I = O0O . recvfrom ( 1000 )
  i1iIIIiI1I = i1iIIIiI1I [ 0 ]
 except :
  break
  if 70 - 70: i1 % i1 . II % ii1IiI1i * I11iIi1I % iii1I1I
  if 23 - 23: i11iIiiIii + o0
 oOo = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 print ( "Message received {}:\n{}\n" . format ( oOo , i1iIIIiI1I [ 0 : - 1 ] ) , )
 for oOoOoO in range ( 40 ) : print ( "-" , end = " " )
 print ( "" )
 if 6 - 6: o0 / i1 % Oo0ooO0oo0oO
 if 84 - 84: i11iIiiIii . I11iIi1I
Oo . cancel ( )
O0O . close ( )
exit ( 0 )
if 100 - 100: Oo0ooO0oo0oO - Oo0ooO0oo0oO - i11Ii11I1Ii1i
if 20 - 20: OoooooooOO
if 13 - 13: i1IIi - Oo0ooO0oo0oO % iii1I1I / iIii1I11I1II1 % I1i1iI1i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
