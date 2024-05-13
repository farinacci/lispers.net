#!/usr/bin/python
#
# liar.py - LISP Interactive Map-Register Agent
#
# Usage: python3 liar.py [-quic] <eid> <rloc> <ms> <ms-key>
#
# This client tool will send a Map-Register message to a Map-Server and then
# exit. It is used to import state from other systems into the LISP mapping
# system. 
#
# When the -quic switch is supplied, then the Map-Register is sent as a UDP
# message over a QUIC connection. Otherwise, the Map-Register is simply
# sent over a UDP datagra.
#
# The program will format the Map-Register with a single EID-record. The
# <eid> encoded can be an IPv4 address, an IPv6 address, or a distinguished
# name (ascii string). The RLOC-record within the EID-record contains the
# RLOC specified by <rloc>. It can be an IPv4 or IPv6 address. The RLOC-record
# will also contain an "rloc-name" accompany the <rloc> address. It will be
# "liar-<hostname>" so the map-server has knowledge that the mapping entry
# was created by this tool.
#
# This program runs stand alone and does not depend on any lispers.net code. If
# you want to lookup mapping entries you can use the lispers.net "lig" client
# which does depend on lispers.net being installed  on the system. 
#
#------------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
import sys
import socket
import struct
import random
import binascii
import hmac
import hashlib
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
I1IiI = 'Usage: python3 liar.py [-quic] "[[<iid>]]<eid>" <rloc> <ms> <ms-key>'
if 73 - 73: OOooOOo / ii11ii1ii
O00ooOO = 1
I1iII1iiII = 2
iI1Ii11111iIi = 17
i1i1II = 16387
if 96 - 96: o0OO0 - Oo0ooO0oo0oO . I1i1iI1i - o00ooo0 / o00 * Oo0oO0ooo
if 56 - 56: o0OO0 - i1IIi
if 64 - 64: o00 + I1i1iI1i
if 10 - 10: i11iIiiIii / OOooOOo % II111iiii
if 75 - 75: i11iIiiIii + o00ooo0 . o0oOOo0O0Ooo * I1i1iI1i
if 59 - 59: iIii1I11I1II1
if 31 - 31: o00ooo0 % i1IIi * iIii1I11I1II1 / o00ooo0 % OOooOOo + OoooooooOO
if 93 - 93: I1i1iI1i * i11iIiiIii * I1IiiI % I1i1iI1i * I1i1iI1i * II111iiii
def o0o0Oo0oooo0 ( ) :
 if 97 - 97: Oo0Ooo - Oo0oO0ooo
 if 54 - 54: Oo0oO0ooo . Oo0oO0ooo / iIii1I11I1II1 / o0OO0 + OOooOOo / o0oOOo0O0Ooo
 if 39 - 39: o0OO0 / o00 . o0OO0 - o0OO0
 if 68 - 68: ii11ii1ii . I1IiiI / I1i1iI1i
 if ( len ( sys . argv ) == 1 ) :
  print ( I1IiI )
  return
  if 72 - 72: OoO0O00 / OoO0O00
 i111IiI = ( "-quic" in sys . argv )
 if ( i111IiI ) : sys . argv . remove ( "-quic" )
 if 1 - 1: I1ii11iIi11i + ii11ii1ii
 if ( len ( sys . argv ) < 5 ) :
  print ( I1IiI )
  return
  if 47 - 47: OoOoOO00 / Oo0ooO0oo0oO * OoooooooOO
  if 9 - 9: I1IiiI - Oo0ooO0oo0oO % i1IIi % OoooooooOO
 i1iIIi1 = sys . argv [ 1 ]
 ii11iIi1I , iI111I11I1I1 , OOooO0OOoo , iIii1 = oOOoO0 ( i1iIIi1 )
 if ( ii11iIi1I == None ) : return
 if 59 - 59: Oo0ooO0oo0oO * i11iIiiIii + Oo0ooO0oo0oO + Oo0oO0ooo * OoO0O00
 OooOoO0Oo = sys . argv [ 2 ]
 iiIIiIiIi , i1I11 = iI ( OooOoO0Oo )
 if ( iiIIiIiIi == None ) : return
 if 100 - 100: Oo0ooO0oo0oO - Oo0ooO0oo0oO - o00
 ii1 = sys . argv [ 3 ]
 o0oO0o00oo = II1i1Ii11Ii11 ( ii1 )
 if ( o0oO0o00oo == None ) : return
 if 35 - 35: o0oOOo0O0Ooo + I1i1iI1i + I1i1iI1i
 I11I11i1I = sys . argv [ 4 ]
 if 49 - 49: II111iiii % I1i1iI1i * O0
 if 89 - 89: OOooOOo + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % o0OO0 * i11iIiiIii / O0 * o0OO0
 if 49 - 49: OOooOOo % Oo0ooO0oo0oO + i1IIi . I1IiiI % I1ii11iIi11i
 I1i1iii = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
 if 20 - 20: o0oOOo0O0Ooo
 if 77 - 77: OoOoOO00 / o0OO0
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
 if 28 - 28: ii11ii1ii - o00ooo0 . o00ooo0 + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % OOooOOo . O0
 I1i1I , oOO00oOO = OoOo ( ii11iIi1I , iI111I11I1I1 , OOooO0OOoo , iIii1 , iiIIiIiIi , i1I11 , o0oO0o00oo , I11I11i1I )
 if 18 - 18: i11iIiiIii
 if 46 - 46: i1IIi / o0OO0 % ii11ii1ii + o00
 if 79 - 79: o00 - o0oOOo0O0Ooo + o00 - I1i1iI1i
 if 8 - 8: I1IiiI
 I1i1iii . sendto ( I1i1I , ( o0oO0o00oo , 4342 ) )
 if 75 - 75: iIii1I11I1II1 / ii11ii1ii % o0oOOo0O0Ooo * OoOoOO00
 iiii11I = Ooo0OO0oOO ( i1iIIi1 ) ; ii11i1 = IIIii1II1II ( OooOoO0Oo ) ; i1I1iI = oo0OooOOo0 ( ii1 ) ;
 print ( "Map-Register sent to {} for EID {} RLOC {} with nonce {}" . format ( i1I1iI , iiii11I , ii11i1 , hex ( oOO00oOO ) ) )
 if 92 - 92: I1i1iI1i . o0OO0 + o0oOOo0O0Ooo
 if 28 - 28: i1IIi * Oo0Ooo - o0oOOo0O0Ooo * o00ooo0 * Oo0ooO0oo0oO / OoO0O00
 if 94 - 94: II111iiii % I1ii11iIi11i / OoOoOO00 * iIii1I11I1II1
 if 54 - 54: o0oOOo0O0Ooo - I1IiiI + OoooooooOO
 if 70 - 70: Oo0ooO0oo0oO / o0OO0 . I1i1iI1i % Oo0Ooo
 I1i1iii . close ( )
 return
 if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . o00ooo0 - OoO0O00 * o0oOOo0O0Ooo
 if 46 - 46: ii11ii1ii + OoOoOO00 . I1IiiI * OOooOOo % o00ooo0
 if 86 - 86: I1IiiI + Oo0ooO0oo0oO % i11iIiiIii * OOooOOo . Oo0oO0ooo * o0OO0
 if 44 - 44: OOooOOo
 if 88 - 88: o00 % Oo0ooO0oo0oO . II111iiii
 if 38 - 38: o0oOOo0O0Ooo
 if 57 - 57: O0 / OOooOOo * o00 / OoOoOO00 . II111iiii
 if 26 - 26: I1i1iI1i
 if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - I1i1iI1i / OoooooooOO
 if 39 - 39: I1ii11iIi11i / Oo0oO0ooo - II111iiii
 if 98 - 98: I1ii11iIi11i / o0OO0 % OOooOOo . OoOoOO00
 if 91 - 91: OOooOOo % Oo0Ooo
 if 64 - 64: o0OO0 % I1i1iI1i - o00 - OOooOOo
 if 31 - 31: o0OO0 - II111iiii . o0OO0
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: I1i1iI1i * I1i1iI1i / I1i1iI1i + o0OO0
 if 34 - 34: Oo0oO0ooo
 if 15 - 15: o0OO0 * Oo0oO0ooo * Oo0Ooo % i11iIiiIii % OoOoOO00 - ii11ii1ii
 if 68 - 68: o00 % i1IIi . o00ooo0 . I1ii11iIi11i
 if 92 - 92: I1i1iI1i . o00
 if 31 - 31: o00 . OoOoOO00 / O0
 if 89 - 89: OoOoOO00
 if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + Oo0oO0ooo
 if 4 - 4: Oo0oO0ooo + O0 * ii11ii1ii
 if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * OOooOOo - i11iIiiIii - Oo0ooO0oo0oO
 if 25 - 25: I1ii11iIi11i
 if 7 - 7: i1IIi / I1IiiI * o00 . o00ooo0 . iIii1I11I1II1
 if 13 - 13: ii11ii1ii / i11iIiiIii
 if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Oo0ooO0oo0oO
 if 52 - 52: o0oOOo0O0Ooo
 if 95 - 95: Oo0ooO0oo0oO
 if 87 - 87: Oo0oO0ooo + OoOoOO00 . ii11ii1ii + OoOoOO00
 if 91 - 91: O0
 if 61 - 61: II111iiii
 if 64 - 64: Oo0oO0ooo / OoOoOO00 - O0 - o0OO0
 if 86 - 86: o0OO0 % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
def OoOo ( afe , iid , eid , ml , afl , rloc , ms , ms_key ) :
 o0o = socket . htonl
 o00OooOO000 = socket . htons
 if 97 - 97: I1ii11iIi11i + ii11ii1ii / iIii1I11I1II1 / I1i1iI1i
 if 37 - 37: I1i1iI1i - Oo0oO0ooo * OOooOOo % i11iIiiIii - o00
 if 83 - 83: o0OO0 / I1IiiI
 if 34 - 34: o00ooo0
 if 57 - 57: OOooOOo . o0OO0 . i1IIi
 i11Iii = "liar-{}" . format ( socket . gethostname ( ) )
 i11Iii = ( i11Iii + "\0" ) . encode ( )
 IiIIIi1iIi = struct . pack ( "BBBB" , 1 , 100 , 0 , 0 )
 IiIIIi1iIi += struct . pack ( "HHHBB" , 0 , o00OooOO000 ( i1i1II ) , 0 , 1 , 0 )
 if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
 iii = 4 + 2 if ( afl == O00ooOO ) else 16 + 2
 iii += len ( i11Iii ) + 2
 IiIIIi1iIi += struct . pack ( "H" , o00OooOO000 ( iii ) )
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % I1i1iI1i * o00ooo0 . i11iIiiIii
 if 2 - 2: I1ii11iIi11i * o0OO0 - iIii1I11I1II1 + I1IiiI . OOooOOo % I1i1iI1i
 if 92 - 92: I1i1iI1i
 if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 IiIIIi1iIi += struct . pack ( "H" , o00OooOO000 ( afl ) )
 if ( afl == O00ooOO ) : IiIIIi1iIi += struct . pack ( "I" , o0o ( rloc ) )
 if ( afl == I1iII1iiII ) :
  II111iiiI1Ii = o0O0OOO0Ooo ( rloc >> 64 )
  iiIiI = o0O0OOO0Ooo ( rloc & 0xffffffffffffffff )
  IiIIIi1iIi += struct . pack ( "QQ" , II111iiiI1Ii , iiIiI )
  if 6 - 6: o00ooo0 . OOooOOo * OoOoOO00 - Oo0ooO0oo0oO - o00ooo0
 IiIIIi1iIi += struct . pack ( "H" , o00OooOO000 ( iI1Ii11111iIi ) )
 IiIIIi1iIi += i11Iii
 if 45 - 45: I1IiiI - OoooooooOO + iIii1I11I1II1 . I1IiiI * o0OO0
 if 51 - 51: OoO0O00 / OoO0O00
 if 53 - 53: Oo0Ooo
 if 29 - 29: I1ii11iIi11i + OOooOOo % O0
 I1I11 = struct . pack ( "IBBHHHH" , o0o ( 60 ) , 1 , ml , 0 , 0 , o00OooOO000 ( i1i1II ) , 0 )
 I1I11 += struct . pack ( "BB" , 2 , 0 )
 iii = 4 + 2
 iii += 4 if ( afe == O00ooOO ) else 16
 I1I11 += struct . pack ( "H" , o00OooOO000 ( iii ) )
 I1I11 += struct . pack ( "IH" , o0o ( iid ) , o00OooOO000 ( afe ) )
 if 34 - 34: I1IiiI . ii11ii1ii * I1ii11iIi11i + o00
 if ( afe == O00ooOO ) : I1I11 += struct . pack ( "I" , o0o ( eid ) )
 if ( afe == iI1Ii11111iIi ) : I1I11 += ( eid + "\0" ) . encode ( )
 if ( afe == I1iII1iiII ) :
  II111iiiI1Ii = o0O0OOO0Ooo ( eid >> 64 )
  iiIiI = o0O0OOO0Ooo ( eid & 0xffffffffffffffff )
  I1I11 += struct . pack ( "QQ" , II111iiiI1Ii , iiIiI )
  if 31 - 31: I1i1iI1i % I1i1iI1i % o0OO0
 I1I11 += IiIIIi1iIi
 if 69 - 69: OoO0O00 - Oo0Ooo + i1IIi / o00
 if 49 - 49: O0 . I1i1iI1i
 if 11 - 11: o00ooo0 * I1IiiI . iIii1I11I1II1 % OoooooooOO + I1i1iI1i
 if 78 - 78: OoO0O00 . ii11ii1ii + OoO0O00 / o0OO0 / OoO0O00
 if 54 - 54: OoOoOO00 % I1i1iI1i
 I1i1I = struct . pack ( "I" , o0o ( 0x30000801 ) )
 oOO00oOO = random . randint ( 0 , 0xffffffffffffffff )
 I1i1I += struct . pack ( "QBBH" , oOO00oOO , 0 , 2 , o00OooOO000 ( 32 ) )
 I1i1I += struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
 I1i1I += I1I11
 if 37 - 37: OoOoOO00 * Oo0Ooo / Oo0oO0ooo - I1i1iI1i % II111iiii . OOooOOo
 if 88 - 88: I1i1iI1i . II111iiii * II111iiii % o00
 if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
 if 6 - 6: Oo0oO0ooo / i11iIiiIii + I1i1iI1i * OOooOOo
 if 80 - 80: II111iiii
 O0O = hmac . new ( ms_key . encode ( ) , I1i1I , hashlib . sha256 ) . digest ( )
 I1i1I = I1i1I [ 0 : 16 ] + O0O + I1i1I [ 16 + 32 : : ]
 if 1 - 1: II111iiii
 if 84 - 84: o0oOOo0O0Ooo % II111iiii . i11iIiiIii / OoO0O00
 return ( I1i1I , oOO00oOO )
 if 80 - 80: o00 . i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: OoO0O00
 if 62 - 62: ii11ii1ii + O0
 if 98 - 98: o0oOOo0O0Ooo
 if 51 - 51: Oo0Ooo - OOooOOo + II111iiii * Oo0ooO0oo0oO . o0OO0 + OOooOOo
 if 78 - 78: i11iIiiIii / I1i1iI1i - Oo0ooO0oo0oO / ii11ii1ii + OOooOOo
 if 82 - 82: Oo0ooO0oo0oO
def ii ( packet ) :
 packet = binascii . hexlify ( packet )
 I1Ii1iI1 = 0
 oO0 = b""
 O0OO0O = len ( packet ) * 2
 while ( I1Ii1iI1 < O0OO0O ) :
  oO0 += packet [ I1Ii1iI1 : I1Ii1iI1 + 8 ] + b" "
  I1Ii1iI1 += 8
  O0OO0O -= 4
  if 81 - 81: OOooOOo . o0oOOo0O0Ooo % O0 / I1IiiI - OOooOOo
 print ( oO0 . decode ( ) )
 if 43 - 43: i11iIiiIii + Oo0Ooo * II111iiii * o00 * O0
 if 64 - 64: ii11ii1ii % iIii1I11I1II1 * OOooOOo
 if 79 - 79: O0
 if 78 - 78: I1ii11iIi11i + ii11ii1ii - o00
 if 38 - 38: o0oOOo0O0Ooo - OOooOOo + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 if 57 - 57: OoO0O00 / Oo0oO0ooo
 if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * ii11ii1ii . I1IiiI * I1IiiI
 if 7 - 7: o00ooo0 * o00 % Oo0ooO0oo0oO - o0oOOo0O0Ooo
def oOOoO0 ( eid ) :
 if 13 - 13: Oo0ooO0oo0oO . i11iIiiIii
 if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 if 100 - 100: Oo0ooO0oo0oO - O0 % OOooOOo * ii11ii1ii + I1IiiI
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 iI111I11I1I1 = 0
 I111iI = eid . find ( "[" ) ; oOOo0 = eid . find ( "]" )
 if ( I111iI != - 1 and oOOo0 != - 1 ) :
  iI111I11I1I1 = int ( eid [ I111iI + 1 : oOOo0 ] )
  eid = eid [ oOOo0 + 1 : : ]
  if 16 - 16: OOooOOo % I1ii11iIi11i * i11iIiiIii % i11iIiiIii
  if 65 - 65: Oo0ooO0oo0oO - OOooOOo + OOooOOo + II111iiii
 iiii11I = eid . split ( "/" )
 iIii1 = int ( iiii11I [ 1 ] ) if len ( iiii11I ) == 2 else None
 eid = iiii11I [ 0 ]
 if 96 - 96: ii11ii1ii % O0 / O0
 if 44 - 44: OOooOOo / o0OO0 / o0OO0
 if 87 - 87: Oo0Ooo . I1IiiI - II111iiii + O0 / Oo0Ooo / OOooOOo
 if 25 - 25: I1IiiI . I1IiiI - OoOoOO00 % OoOoOO00 - i11iIiiIii / o00
 if ( eid . count ( "." ) == 3 ) :
  try :
   eid = socket . inet_pton ( socket . AF_INET , eid )
  except :
   print ( "Invalid IPv4 EID address format" )
   return ( None , None , None , None )
   if 51 - 51: Oo0Ooo / OoOoOO00 . ii11ii1ii * o0oOOo0O0Ooo + OoO0O00 * o00ooo0
  eid = int ( binascii . hexlify ( eid ) , 16 )
  if ( iIii1 == None ) : iIii1 = 32
  return ( O00ooOO , iI111I11I1I1 , eid , iIii1 )
  if 73 - 73: OoO0O00 + OoooooooOO - O0 - Oo0ooO0oo0oO - II111iiii
  if 99 - 99: Oo0oO0ooo . Oo0ooO0oo0oO + o00 + OoooooooOO % o0oOOo0O0Ooo
  if 51 - 51: iIii1I11I1II1
  if 34 - 34: OOooOOo + I1IiiI - OOooOOo
  if 17 - 17: II111iiii % I1i1iI1i + o0OO0 - I1i1iI1i / ii11ii1ii + Oo0oO0ooo
 if ( eid . find ( ":" ) != - 1 ) :
  try :
   eid = socket . inet_pton ( socket . AF_INET6 , eid )
  except :
   print ( "Invalid IPv6 EID address format" )
   return ( None , None , None , None )
   if 59 - 59: ii11ii1ii % OoOoOO00 . Oo0ooO0oo0oO * I1ii11iIi11i % o0OO0
  eid = int ( binascii . hexlify ( eid ) , 16 )
  if ( iIii1 == None ) : iIii1 = 128
  return ( I1iII1iiII , iI111I11I1I1 , eid , iIii1 )
  if 59 - 59: OOooOOo - I1i1iI1i
  if 15 - 15: o00 . i11iIiiIii . OoooooooOO / OoO0O00 % Oo0ooO0oo0oO
 if ( eid . count ( "." ) > 3 ) :
  print ( "Invalid distinguished-name EID format" )
  return ( None , None , None , None )
  if 93 - 93: O0 % i1IIi . ii11ii1ii / I1IiiI - o00 / I1IiiI
  if 36 - 36: OOooOOo % OOooOOo % i1IIi / i1IIi - Oo0oO0ooo
  if 30 - 30: o0OO0 / I1IiiI
  if 35 - 35: II111iiii % ii11ii1ii . Oo0oO0ooo + Oo0oO0ooo % II111iiii % II111iiii
  if 72 - 72: II111iiii + i1IIi + o0oOOo0O0Ooo
 return ( iI1Ii11111iIi , iI111I11I1I1 , eid , len ( eid ) * 8 )
 if 94 - 94: OOooOOo . i1IIi - o0oOOo0O0Ooo % O0 - OoO0O00
 if 72 - 72: Oo0ooO0oo0oO
 if 1 - 1: OoO0O00 * o00ooo0 * OoooooooOO + Oo0oO0ooo
 if 33 - 33: O0 * o0oOOo0O0Ooo - o00 % o00
 if 18 - 18: o00 / Oo0Ooo * o00 + o00 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: Oo0oO0ooo / OoOoOO00 - o00ooo0 * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Oo0ooO0oo0oO % I1ii11iIi11i
def iI ( rloc ) :
 if 76 - 76: o00ooo0 * I1i1iI1i
 if 52 - 52: ii11ii1ii
 if 19 - 19: I1IiiI
 if 25 - 25: Oo0ooO0oo0oO / Oo0oO0ooo
 if ( rloc . count ( "." ) == 3 ) :
  try :
   rloc = socket . inet_pton ( socket . AF_INET , rloc )
  except :
   print ( "Invalid IPv4 RLOC address format" )
   return ( None , None )
   if 31 - 31: ii11ii1ii . O0 % I1IiiI . o0oOOo0O0Ooo + o00ooo0
  rloc = int ( binascii . hexlify ( rloc ) , 16 )
  return ( O00ooOO , rloc )
  if 71 - 71: o00 . II111iiii
  if 62 - 62: OoooooooOO . o0OO0
  if 61 - 61: OoOoOO00 - ii11ii1ii - i1IIi
  if 25 - 25: O0 * o0OO0 + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 58 - 58: I1IiiI
 if ( rloc . find ( ":" ) != - 1 ) :
  try :
   rloc = socket . inet_pton ( socket . AF_INET6 , rloc )
  except :
   print ( "Invalid IPv6 RLOC address format" )
   return ( None , None )
   if 53 - 53: i1IIi
  rloc = int ( binascii . hexlify ( rloc ) , 16 )
  return ( I1iII1iiII , rloc )
  if 59 - 59: o0oOOo0O0Ooo
  if 81 - 81: OoOoOO00 - OoOoOO00 . I1i1iI1i
 return ( None , None )
 if 73 - 73: o0OO0 % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Oo0ooO0oo0oO + Oo0oO0ooo % OoO0O00 - Oo0oO0ooo
 if 39 - 39: Oo0Ooo * ii11ii1ii % ii11ii1ii - OoooooooOO + o0oOOo0O0Ooo - o0OO0
 if 23 - 23: i11iIiiIii
 if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + o0OO0 * iIii1I11I1II1
 if 81 - 81: o00ooo0 % i1IIi . iIii1I11I1II1
 if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / o00ooo0
def II1i1Ii11Ii11 ( ms ) :
 try :
  ms = socket . gethostbyname ( ms )
 except :
  print ( "Could not resolve map-server DNS name" )
  return ( None )
  if 6 - 6: I1i1iI1i / I1IiiI % ii11ii1ii - I1IiiI
 return ( ms )
 if 31 - 31: ii11ii1ii
 if 23 - 23: o00 . o00ooo0
 if 92 - 92: OoOoOO00 + o00 * Oo0ooO0oo0oO % I1IiiI
 if 42 - 42: Oo0Ooo
 if 76 - 76: I1IiiI * I1i1iI1i % o00
 if 57 - 57: iIii1I11I1II1 - i1IIi / o00 - O0 * OoooooooOO % II111iiii
 if 68 - 68: OoooooooOO * o0OO0 % OoOoOO00 - o00ooo0
def o0O0OOO0Ooo ( address ) :
 I1 = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 97 - 97: Oo0oO0ooo
 if 48 - 48: i1IIi - o00
 if 56 - 56: o0oOOo0O0Ooo + II111iiii + OoOoOO00 - Oo0oO0ooo . OoOoOO00
 if 84 - 84: OoO0O00 + i1IIi - II111iiii . I1ii11iIi11i * OoooooooOO + I1IiiI
 if 38 - 38: ii11ii1ii + II111iiii % Oo0oO0ooo % OoOoOO00 - Oo0ooO0oo0oO / OoooooooOO
 if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
 if 85 - 85: Oo0ooO0oo0oO % I1i1iI1i + o0OO0 / o0oOOo0O0Ooo . OOooOOo + ii11ii1ii
 if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
 return ( I1 )
 if 28 - 28: I1i1iI1i . I1i1iI1i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / I1i1iI1i
 if 27 - 27: OoO0O00 + Oo0oO0ooo - i1IIi
 if 69 - 69: o00ooo0 - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
 if 79 - 79: O0 * i11iIiiIii - o00ooo0 / o00ooo0
 if 48 - 48: O0
 if 93 - 93: i11iIiiIii - I1IiiI * I1ii11iIi11i * o0OO0 % O0 + OoooooooOO
 if 25 - 25: o00ooo0 + Oo0ooO0oo0oO / Oo0oO0ooo . o0oOOo0O0Ooo % O0 * OoO0O00
def oo0OooOOo0 ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 84 - 84: Oo0oO0ooo % Oo0ooO0oo0oO + i11iIiiIii
def Ooo0OO0oOO ( string ) :
 return ( oo0OooOOo0 ( "\033[92m" + string + "\033[0m" ) )
 if 28 - 28: Oo0Ooo + OoO0O00 * ii11ii1ii % OOooOOo . o0OO0 % O0
def IIIii1II1II ( string ) :
 return ( oo0OooOOo0 ( "\033[91m" + string + "\033[0m" ) )
 if 16 - 16: o0OO0 - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
 if 19 - 19: OoO0O00 - Oo0Ooo . O0
 if 60 - 60: II111iiii + Oo0Ooo
 if 9 - 9: Oo0oO0ooo * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
if ( __name__ == "__main__" ) :
 o0o0Oo0oooo0 ( )
 exit ( 0 )
 if 49 - 49: II111iiii
 if 25 - 25: OoooooooOO - I1IiiI . I1IiiI * OOooOOo
 if 81 - 81: I1i1iI1i + o00ooo0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
