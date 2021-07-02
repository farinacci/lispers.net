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
# lisp-news-sender.py
#
# This script will run and take information from the local system and send it
# as text on a multicast socket. Will use lisp-signal-free-multicast to get
# data to receivers.
#
# Usage: python lisp-news-sender.py <source> <group>
#
from __future__ import print_function
import sys
import socket
import datetime
import time
import urllib
import urllib2
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
IiII1IiiIiI1 = "Usage: python lisp-news-sender.py <source> <group> [<delay>]"
iIiiiI1IiI1I1 = ""
o0OoOoOO00 = ""
I11i = ""
O0O = None
if 78 - 78: i11ii11iIi11i . oOoO0oo0OOOo + IiiI / Iii1ii1II11i
if 10 - 10: I1iII1iiII + I1Ii111 / OOo
if 41 - 41: I1II1
def Ooo0OO0oOO ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 86 - 86: oO0o
 if 12 - 12: OOO0o0o / o0oO0 + i111I * O0Oo0oO0o . II1iI . II111iiii
def IiIii1Ii1IIi ( messages ) :
 II1Iiii1111i = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 for i1IIi11111i in messages :
  print ( "Send message at {}:\n{}" . format ( II1Iiii1111i , i1IIi11111i ) , end = " " )
  if 74 - 74: o0oO0 * i111I
  if 82 - 82: iIii1I11I1II1 % i111I
  if 86 - 86: Iii1ii1II11i % i11ii11iIi11i
  if 80 - 80: OoooooooOO . i11ii11iIi11i
  try : O0O . sendto ( i1IIi11111i , ( o0OoOoOO00 , I11i ) )
  except socket . error as OOO0O :
   print ( "socket.sendto() failed: {}" . format ( OOO0O ) )
   if 94 - 94: II1iI
  time . sleep ( .25 )
  if 18 - 18: iIii1I11I1II1 / oO0o + OOo / oOoO0oo0OOOo - II111iiii - oO0o
  if 1 - 1: oO0o - I1II1 % O0 + i11ii11iIi11i - o0oO0 / oO0o
  if 31 - 31: IiiI + II111iiii
def i11IiIiiIIIII ( ) :
 II1Iiii1111i = str ( time . time ( ) ) . split ( "." ) [ 0 ]
 i1iiIII111ii = int ( II1Iiii1111i ) & 1
 i1IIi11111i = "time is odd\n" if i1iiIII111ii else "time is even\n"
 return ( [ i1IIi11111i ] )
 if 3 - 3: o0oO0 + O0
 if 42 - 42: I1II1 / i1IIi + i11iIiiIii - OOO0o0o
def oo0Ooo0 ( ) :
 try :
  I1I11I1I1I = urllib . urlopen ( "http://finance.yahoo.com/rss/topfinstories" )
 except :
  try :
   I1I11I1I1I = urllib2 . urlopen ( "http://finance.yahoo.com/rss/topfinstories" )
  except :
   return ( None )
   if 90 - 90: II111iiii + OOo / I1iII1iiII % II111iiii - O0
   if 29 - 29: I1iII1iiII / iIii1I11I1II1
   if 24 - 24: O0 % I1iII1iiII + i1IIi + O0Oo0oO0o + I1Ii111
   if 70 - 70: oOoO0oo0OOOo % oOoO0oo0OOOo . i111I % IiiI * I1iII1iiII % OOo
 iiI1IiI = I1I11I1I1I . read ( )
 iiI1IiI = iiI1IiI [ iiI1IiI . find ( "<item>" ) : : ]
 if 13 - 13: oOoO0oo0OOOo . i11iIiiIii - iIii1I11I1II1 - Iii1ii1II11i
 ii1I = [ ]
 OooO0 = 0
 II11iiii1Ii = socket . gethostname ( )
 OO0o = Ooo0OO0oOO ( "Sent from multicast source '{}'\n" . format ( II11iiii1Ii ) )
 while ( True ) :
  Ooo = iiI1IiI . find ( "<title>" )
  if ( Ooo == - 1 ) : break
  iiI1IiI = iiI1IiI [ Ooo + len ( "<title>" ) : : ]
  Ooo = iiI1IiI . find ( "</title>" )
  if ( Ooo == - 1 ) : break
  O0o0Oo = iiI1IiI [ 0 : Ooo ]
  iiI1IiI = iiI1IiI [ Ooo : : ]
  if 78 - 78: iIii1I11I1II1 - OOO0o0o * IiiI + I1iII1iiII + o0oO0 + o0oO0
  Ooo = iiI1IiI . find ( "<link>" )
  if ( Ooo == - 1 ) : break
  iiI1IiI = iiI1IiI [ Ooo + len ( "<link>" ) : : ]
  Ooo = iiI1IiI . find ( "</link>" )
  if ( Ooo == - 1 ) : break
  I11I11i1I = iiI1IiI [ 0 : Ooo ]
  iiI1IiI = iiI1IiI [ Ooo : : ]
  if 49 - 49: II111iiii % o0oO0 * O0
  Ooo = iiI1IiI . find ( "<pubDate>" )
  if ( Ooo == - 1 ) : break
  iiI1IiI = iiI1IiI [ Ooo + len ( "<pubDate>" ) : : ]
  Ooo = iiI1IiI . find ( "</pubDate>" )
  if ( Ooo == - 1 ) : break
  oOOo0oo = iiI1IiI [ 0 : Ooo ]
  iiI1IiI = iiI1IiI [ Ooo : : ]
  if 80 - 80: oO0o * i11iIiiIii / O0Oo0oO0o
  OO0o += "Headline: {}\n  Date: {}\n  URL: {}\n\n" . format ( Ooo0OO0oOO ( O0o0Oo ) , oOOo0oo , I11I11i1I )
  if 9 - 9: OOO0o0o + OOo % OOO0o0o + i1IIi . I1II1
  if 31 - 31: I1iII1iiII + oO0o + oO0o / II111iiii
  OooO0 += 1
  if ( OooO0 % 3 == 0 ) :
   ii1I . append ( OO0o )
   OO0o = ""
   if 26 - 26: OoooooooOO
   if 12 - 12: OoooooooOO % Iii1ii1II11i / II1iI % I1iII1iiII
 return ( ii1I )
 if 29 - 29: OoooooooOO
 if 23 - 23: I1iII1iiII . II111iiii
 if 98 - 98: iIii1I11I1II1 % Iii1ii1II11i * I1Ii111 * Iii1ii1II11i
 if 45 - 45: O0Oo0oO0o . Iii1ii1II11i
 if 83 - 83: OOo . iIii1I11I1II1 . I1Ii111
 if 31 - 31: OOO0o0o . OOO0o0o - I1iII1iiII / IiiI + II1iI * i11ii11iIi11i
 if 63 - 63: O0Oo0oO0o % i1IIi / OoooooooOO - OoooooooOO
if ( len ( sys . argv ) < 3 ) :
 print ( IiII1IiiIiI1 )
 exit ( 1 )
 if 8 - 8: Iii1ii1II11i
 if 60 - 60: oO0o / oO0o
iIiiiI1IiI1I1 = sys . argv [ 1 ]
o0OoOoOO00 = sys . argv [ 2 ]
I1II1III11iii = int ( sys . argv [ 3 ] ) if ( len ( sys . argv ) == 4 ) else 15
if 75 - 75: iIii1I11I1II1 / I1II1 % I1iII1iiII * Iii1ii1II11i
if ( iIiiiI1IiI1I1 . find ( "." ) == - 1 or o0OoOoOO00 . find ( "." ) == - 1 ) :
 print ( "Must supply IPv4 address in dotted decimal" )
 exit ( 1 )
 if 9 - 9: IiiI
 if 33 - 33: II1iI . o0oO0
I11i = o0OoOoOO00 . split ( "." )
I11i = 0x800 + int ( I11i [ - 2 ] ) + int ( I11i [ - 1 ] )
if 58 - 58: I1II1 * i11iIiiIii / Iii1ii1II11i % O0Oo0oO0o - I1Ii111 / OOo
if 50 - 50: i11ii11iIi11i
if 34 - 34: i11ii11iIi11i * II111iiii % o0oO0 * Iii1ii1II11i - i11ii11iIi11i
if 33 - 33: I1iII1iiII + I1II1 * IiiI - oOoO0oo0OOOo / OOo % OOO0o0o
print ( "Open send socket ({} -> {}:{}) ... " . format ( iIiiiI1IiI1I1 , o0OoOoOO00 , I11i ) ,
 end = " " )
if 21 - 21: IiiI * iIii1I11I1II1 % OOo * i1IIi
try :
 O0O = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
 O0O . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_TTL , 32 )
 O0O . bind ( ( iIiiiI1IiI1I1 , 0 ) )
 print ( "succeeded" )
except :
 print ( "failed" )
 exit ( 1 )
 if 16 - 16: O0 - O0Oo0oO0o * iIii1I11I1II1 + o0oO0
 if 50 - 50: II111iiii - II1iI * I1Ii111 / O0Oo0oO0o + I1iII1iiII
 if 88 - 88: OOO0o0o / O0Oo0oO0o + o0oO0 - II111iiii / II1iI - Iii1ii1II11i
 if 15 - 15: I1Ii111 + Iii1ii1II11i - OoooooooOO / I1II1
 if 58 - 58: i11iIiiIii % oO0o
while ( True ) :
 ii1I = oo0Ooo0 ( )
 if ( ii1I != None ) : IiIii1Ii1IIi ( ii1I )
 if 71 - 71: I1II1 + II1iI % i11iIiiIii + I1Ii111 - i111I
 print ( "Delay {} seconds ... " . format ( I1II1III11iii ) , end = " " )
 sys . stdout . flush ( )
 time . sleep ( I1II1III11iii )
 print ( "" )
 if 88 - 88: Iii1ii1II11i - IiiI % I1II1
 ii1I = i11IiIiiIIIII ( )
 IiIii1Ii1IIi ( ii1I )
 if 16 - 16: i11ii11iIi11i * OOo % i111I
 print ( "Delay {} seconds ... " . format ( I1II1III11iii ) , end = " " )
 sys . stdout . flush ( )
 time . sleep ( I1II1III11iii )
 print ( "" )
 if 86 - 86: i11ii11iIi11i + OOO0o0o % i11iIiiIii * OOo . II1iI * oO0o
 if 44 - 44: OOo
O0O . close ( )
exit ( 0 )
if 88 - 88: O0Oo0oO0o % OOO0o0o . II111iiii
if 38 - 38: I1iII1iiII
if 57 - 57: O0 / OOo * O0Oo0oO0o / Iii1ii1II11i . II111iiii
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
