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
if 64 - 64: i11iIiiIii
import sys
import socket
import datetime
import time
import urllib
import urllib2
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
I1IiI = "Usage: python lisp-news-sender.py <source> <group> [<delay>]"
o0OOO = ""
iIiiiI = ""
Iii1ii1II11i = ""
iI111iI = None
if 34 - 34: iii1I1I / O00oOoOoO0o0O . O0oo0OO0 + Oo0ooO0oo0oO . I1i1iI1i - II
if 100 - 100: i11Ii11I1Ii1i . ooO - iii1I1I / i1IIi % II111iiii - OoOoOO00
if 91 - 91: OoO0O00 . i11iIiiIii / iii1I1I % O0oo0OO0 / OoO0O00 - i11iIiiIii
def II1Iiii1111i ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 25 - 25: Oo0ooO0oo0oO
 if 89 - 89: OoooooooOO - II * ooO
def O0I11i1i11i1I ( messages ) :
 Iiii = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 for OOO0O in messages :
  print "Send message at {}:\n{}" . format ( Iiii , OOO0O ) ,
  if 94 - 94: ooO
  if 18 - 18: iIii1I11I1II1 / O0oo0OO0 + iii1I1I / Oo0Ooo - II111iiii - O0oo0OO0
  if 1 - 1: O0oo0OO0 - O00oOoOoO0o0O % O0 + I1IiiI - I1i1iI1i / O0oo0OO0
  if 31 - 31: OoO0O00 + II111iiii
  try : iI111iI . sendto ( OOO0O , ( iIiiiI , Iii1ii1II11i ) )
  except socket . error , i11IiIiiIIIII :
   print ( "socket.sendto() failed: {}" . format ( i11IiIiiIIIII ) )
   if 22 - 22: Oo0ooO0oo0oO * O0 / o0oOOo0O0Ooo
  time . sleep ( .25 )
  if 64 - 64: Oo0ooO0oo0oO % i1IIi % OoooooooOO
  if 3 - 3: I1i1iI1i + O0
  if 42 - 42: O00oOoOoO0o0O / i1IIi + i11iIiiIii - Oo0ooO0oo0oO
def oo0Ooo0 ( ) :
 Iiii = str ( time . time ( ) ) . split ( "." ) [ 0 ]
 I1I11I1I1I = int ( Iiii ) & 1
 OOO0O = "time is odd\n" if I1I11I1I1I else "time is even\n"
 return ( [ OOO0O ] )
 if 90 - 90: II111iiii + iii1I1I / o0oOOo0O0Ooo % II111iiii - O0
 if 29 - 29: o0oOOo0O0Ooo / iIii1I11I1II1
def IiIIIiI1I1 ( ) :
 try :
  OoO000 = urllib . urlopen ( "http://finance.yahoo.com/rss/topfinstories" )
 except :
  try :
   OoO000 = urllib2 . urlopen ( "http://finance.yahoo.com/rss/topfinstories" )
  except :
   return ( None )
   if 42 - 42: iii1I1I - i1IIi / i11iIiiIii + O00oOoOoO0o0O + OoO0O00
   if 17 - 17: iii1I1I . Oo0Ooo . I1ii11iIi11i
   if 3 - 3: OoOoOO00 . Oo0Ooo . I1IiiI / Oo0ooO0oo0oO
   if 38 - 38: II111iiii % i11iIiiIii . ooO - O00oOoOoO0o0O + Oo0ooO0oo0oO
 Ooooo0Oo00oO0 = OoO000 . read ( )
 Ooooo0Oo00oO0 = Ooooo0Oo00oO0 [ Ooooo0Oo00oO0 . find ( "<item>" ) : : ]
 if 12 - 12: iIii1I11I1II1 * I1IiiI . ooO % O0oo0OO0 + O0
 O00 = [ ]
 o0OOOOO00o0O0 = 0
 o0o0OOO0o0 = socket . gethostname ( )
 ooOOOo0oo0O0 = II1Iiii1111i ( "Sent from multicast source '{}'\n" . format ( o0o0OOO0o0 ) )
 while ( True ) :
  o0 = Ooooo0Oo00oO0 . find ( "<title>" )
  if ( o0 == - 1 ) : break
  Ooooo0Oo00oO0 = Ooooo0Oo00oO0 [ o0 + len ( "<title>" ) : : ]
  o0 = Ooooo0Oo00oO0 . find ( "</title>" )
  if ( o0 == - 1 ) : break
  I11II1i = Ooooo0Oo00oO0 [ 0 : o0 ]
  Ooooo0Oo00oO0 = Ooooo0Oo00oO0 [ o0 : : ]
  if 23 - 23: I1ii11iIi11i / o0oOOo0O0Ooo + O0oo0OO0 + O0oo0OO0 / II111iiii
  o0 = Ooooo0Oo00oO0 . find ( "<link>" )
  if ( o0 == - 1 ) : break
  Ooooo0Oo00oO0 = Ooooo0Oo00oO0 [ o0 + len ( "<link>" ) : : ]
  o0 = Ooooo0Oo00oO0 . find ( "</link>" )
  if ( o0 == - 1 ) : break
  iiI1 = Ooooo0Oo00oO0 [ 0 : o0 ]
  Ooooo0Oo00oO0 = Ooooo0Oo00oO0 [ o0 : : ]
  if 19 - 19: O0oo0OO0 + ooO
  o0 = Ooooo0Oo00oO0 . find ( "<pubDate>" )
  if ( o0 == - 1 ) : break
  Ooooo0Oo00oO0 = Ooooo0Oo00oO0 [ o0 + len ( "<pubDate>" ) : : ]
  o0 = Ooooo0Oo00oO0 . find ( "</pubDate>" )
  if ( o0 == - 1 ) : break
  ooo = Ooooo0Oo00oO0 [ 0 : o0 ]
  Ooooo0Oo00oO0 = Ooooo0Oo00oO0 [ o0 : : ]
  if 18 - 18: o0oOOo0O0Ooo
  ooOOOo0oo0O0 += "Headline: {}\n  Date: {}\n  URL: {}\n\n" . format ( II1Iiii1111i ( I11II1i ) , ooo , iiI1 )
  if 28 - 28: O00oOoOoO0o0O - II . II + OoOoOO00 - OoooooooOO + O0
  if 95 - 95: OoO0O00 % iii1I1I . O0
  o0OOOOO00o0O0 += 1
  if ( o0OOOOO00o0O0 % 3 == 0 ) :
   O00 . append ( ooOOOo0oo0O0 )
   ooOOOo0oo0O0 = ""
   if 15 - 15: ooO / Oo0ooO0oo0oO . Oo0ooO0oo0oO - i1IIi
   if 53 - 53: II + I1IiiI * iii1I1I
 return ( O00 )
 if 61 - 61: i1IIi * O00oOoOoO0o0O / OoooooooOO . i11iIiiIii . OoOoOO00
 if 60 - 60: O0oo0OO0 / O0oo0OO0
 if 46 - 46: Oo0ooO0oo0oO * O00oOoOoO0o0O - OoO0O00 * iii1I1I - i11Ii11I1Ii1i
 if 83 - 83: OoooooooOO
 if 31 - 31: II111iiii - O00oOoOoO0o0O . i11Ii11I1Ii1i % OoOoOO00 - O0
 if 4 - 4: II111iiii / ooO . I1i1iI1i
 if 58 - 58: O00oOoOoO0o0O * i11iIiiIii / OoOoOO00 % i11Ii11I1Ii1i - I1ii11iIi11i / iii1I1I
if ( len ( sys . argv ) < 3 ) :
 print I1IiI
 exit ( 1 )
 if 50 - 50: I1IiiI
 if 34 - 34: I1IiiI * II111iiii % I1i1iI1i * OoOoOO00 - I1IiiI
o0OOO = sys . argv [ 1 ]
iIiiiI = sys . argv [ 2 ]
II1III = int ( sys . argv [ 3 ] ) if ( len ( sys . argv ) == 4 ) else 15
if 19 - 19: iii1I1I % i1IIi % o0oOOo0O0Ooo
if ( o0OOO . find ( "." ) == - 1 or iIiiiI . find ( "." ) == - 1 ) :
 print "Must supply IPv4 address in dotted decimal"
 exit ( 1 )
 if 93 - 93: iIii1I11I1II1 % iii1I1I * i1IIi
 if 16 - 16: O0 - i11Ii11I1Ii1i * iIii1I11I1II1 + I1i1iI1i
Iii1ii1II11i = iIiiiI . split ( "." )
Iii1ii1II11i = 0x800 + int ( Iii1ii1II11i [ - 2 ] ) + int ( Iii1ii1II11i [ - 1 ] )
if 50 - 50: II111iiii - ooO * I1ii11iIi11i / i11Ii11I1Ii1i + o0oOOo0O0Ooo
if 88 - 88: Oo0ooO0oo0oO / i11Ii11I1Ii1i + I1i1iI1i - II111iiii / ooO - OoOoOO00
if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / O00oOoOoO0o0O
if 58 - 58: i11iIiiIii % O0oo0OO0
print "Open send socket ({} -> {}:{}) ... " . format ( o0OOO , iIiiiI , Iii1ii1II11i ) ,
if 71 - 71: O00oOoOoO0o0O + ooO % i11iIiiIii + I1ii11iIi11i - II
try :
 iI111iI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
 iI111iI . setsockopt ( socket . IPPROTO_IP , socket . IP_MULTICAST_TTL , 32 )
 iI111iI . bind ( ( o0OOO , 0 ) )
 print "succeeded"
except :
 print "failed"
 exit ( 1 )
 if 88 - 88: OoOoOO00 - OoO0O00 % O00oOoOoO0o0O
 if 16 - 16: I1IiiI * iii1I1I % II
 if 86 - 86: I1IiiI + Oo0ooO0oo0oO % i11iIiiIii * iii1I1I . ooO * O0oo0OO0
 if 44 - 44: iii1I1I
 if 88 - 88: i11Ii11I1Ii1i % Oo0ooO0oo0oO . II111iiii
while ( True ) :
 O00 = IiIIIiI1I1 ( )
 if ( O00 != None ) : O0I11i1i11i1I ( O00 )
 if 38 - 38: o0oOOo0O0Ooo
 print "Delay {} seconds ... " . format ( II1III ) ,
 sys . stdout . flush ( )
 time . sleep ( II1III )
 print ""
 if 57 - 57: O0 / iii1I1I * i11Ii11I1Ii1i / OoOoOO00 . II111iiii
 O00 = oo0Ooo0 ( )
 O0I11i1i11i1I ( O00 )
 if 26 - 26: I1i1iI1i
 print "Delay {} seconds ... " . format ( II1III ) ,
 sys . stdout . flush ( )
 time . sleep ( II1III )
 print ""
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - I1i1iI1i / OoooooooOO
 if 39 - 39: I1ii11iIi11i / ooO - II111iiii
iI111iI . close ( )
exit ( 0 )
if 98 - 98: I1ii11iIi11i / O0oo0OO0 % iii1I1I . OoOoOO00
if 91 - 91: iii1I1I % Oo0Ooo
if 64 - 64: O0oo0OO0 % I1i1iI1i - i11Ii11I1Ii1i - iii1I1I
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
