#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from __future__ import division
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
if 94 - 94: i1IIi % Oo0Ooo
if 68 - 68: Ii1I / O0
if 46 - 46: O0 * II111iiii / IiII * Oo0Ooo * iII111i . I11i
if 62 - 62: i11iIiiIii - II111iiii % I1Ii111 - iIii1I11I1II1 . I1ii11iIi11i . II111iiii
if 61 - 61: oO0o / OoOoOO00 / iII111i * OoO0O00 . II111iiii
if 1 - 1: II111iiii - I1ii11iIi11i % i11iIiiIii + IiII . I1Ii111
if 55 - 55: iIii1I11I1II1 - I1IiiI . Ii1I * IiII * i1IIi / iIii1I11I1II1
from builtins import zip
from builtins import map
from builtins import chr
from builtins import range
from builtins import object
from past . utils import old_div
import binascii
import sys
import warnings
if 79 - 79: oO0o + I1Ii111 . ooOoO0o * IiII % I11i . I1IiiI
PY3K = int ( sys . version [ 0 ] ) >= 3
if 94 - 94: iII111i * Ii1I / IiII . i1IIi * iII111i
try :
 from Crypto . Cipher import AES
except ImportError :
 pycrypto = False
else :
 pycrypto = True
 if 47 - 47: i1IIi % i11iIiiIii
try :
 from cryptography . hazmat . backends import default_backend
 from cryptography . hazmat . primitives . ciphers . algorithms import AES as AES_C
 from cryptography . hazmat . primitives . ciphers . modes import ECB
 from cryptography . hazmat . primitives . ciphers import Cipher
except ImportError :
 crypto = False
else :
 crypto = True
 if 20 - 20: ooOoO0o * II111iiii
try :
 import M2Crypto
except ImportError :
 m2crypto = False
else :
 m2crypto = True
 if 65 - 65: o0oOOo0O0Ooo * iIii1I11I1II1 * ooOoO0o
 if 18 - 18: iIii1I11I1II1 / I11i + oO0o / Oo0Ooo - II111iiii - I11i
if pycrypto :
 def I111IiIi ( key , val ) :
  return AES . new ( key , mode = AES . MODE_ECB ) . encrypt ( val )
  if 32 - 32: I1IiiI % OoO0O00 / II111iiii + OoO0O00 . OOooOOo * I1Ii111
elif crypto :
 def I111IiIi ( key , val ) :
  e = Cipher ( AES_C ( key ) , ECB ( ) , default_backend ( ) ) . encryptor ( )
  if 62 - 62: i11iIiiIii - II111iiii
  return e . update ( val ) + e . finalize ( )
elif m2crypto :
 def I111IiIi ( key , val ) :
  c = M2Crypto . EVP . Cipher ( alg = 'aes_128_ecb' , key = key , op = 1 )
  if 43 - 43: OoOoOO00 - i1IIi + I1Ii111 + Ii1I
  return c . update ( val ) + c . final ( )
else :
 warnings . warn ( "No AES libary found! Most functions won't work!" ,
 ImportWarning )
 def I111IiIi ( * args ) :
  raise NotImplementedError ( "No crypto libary found!" )
  if 17 - 17: o0oOOo0O0Ooo
  if 64 - 64: Ii1I % i1IIi % OoooooooOO
  if 3 - 3: iII111i + O0
import hmac
if hasattr ( hmac , 'compare_digest' ) :
 def constant_time_compare ( a , b ) :
  return hmac . compare_digest ( a , b )
else :
 def constant_time_compare ( a , b ) :
  if len ( a ) != len ( b ) :
   return False
  I1Ii = 0
  if PY3K and isinstance ( a , bytes ) and isinstance ( b , bytes ) :
   for o0oOo0Ooo0O , OO00O0O0O00Oo in zip ( a , b ) :
    I1Ii |= o0oOo0Ooo0O ^ OO00O0O0O00Oo
  else :
   for o0oOo0Ooo0O , OO00O0O0O00Oo in zip ( a , b ) :
    I1Ii |= ord ( o0oOo0Ooo0O ) ^ ord ( OO00O0O0O00Oo )
  return I1Ii == 0
  if 25 - 25: o0oOOo0O0Ooo % II111iiii - II111iiii . II111iiii
constant_time_compare . __doc__ = """
Returns True if the two strings are equal, False otherwise.
    
The time taken is independent of the number of characters that match.
For the sake of simplicity, this function executes in constant time only
when the two strings have the same length. It short-circuits when an error
occurs they have different lengths. Since Poly1305 MAC's have a constant
length, this is acceptable.

:param a: The first parameter
:type a: byte or ascii string
:param b: The second parameter
:type b: byte or ascii string
"""
if 32 - 32: i1IIi . I11i % OoO0O00 . o0oOOo0O0Ooo
def new ( * args , ** kwargs ) :
 if 42 - 42: I1Ii111 + I1ii11iIi11i
 if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
 if 23 - 23: i11iIiiIii + I1IiiI
 if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
 if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
 if 33 - 33: Ii1I + II111iiii % i11iIiiIii . ooOoO0o - I1IiiI
class Poly1305 ( object ) :
 digest_size = 16
 if 66 - 66: Ii1I - OoooooooOO * OoooooooOO . OOooOOo . I1ii11iIi11i
 if 22 - 22: OoooooooOO % I11i - iII111i . iIii1I11I1II1 * i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 if 61 - 61: ooOoO0o
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
 if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo
 if 77 - 77: OoOoOO00 / I11i
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
 if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % oO0o . O0
 if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
 if 53 - 53: IiII + I1IiiI * oO0o
 if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
 if 60 - 60: I11i / I11i
 def __init__ ( self , key_aes , r , nonce , string = b"" , method = I111IiIi ) :
  self . __key_aes = key_aes
  self . __r = r
  self . __nonce = nonce
  self . __string = string
  self . __aes = method
  if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
 def update ( self , msg ) :
  if 83 - 83: OoooooooOO
  if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
  if 4 - 4: II111iiii / ooOoO0o . iII111i
  if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
  if 50 - 50: I1IiiI
  if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
  if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
  if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
  if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
  self . __string += msg
  if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
 def digest ( self ) :
  if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
  if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
  if 58 - 58: i11iIiiIii % I11i
  if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
  if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
  if 16 - 16: I1IiiI * oO0o % IiII
  if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
  i1I11i1iI , I1ii1Ii1 , iii11 , oOOOOo0 = ( self . __key_aes , self . __r ,
 self . __nonce , self . __string )
  iiII1i1 = ( 1 << 130 ) - 5
  o00oOO0o = str2num_littleend ( I1ii1Ii1 )
  OOO00O = old_div ( ( len ( oOOOOo0 ) + 15 ) , 16 )
  OOoOO0oo0ooO = 0
  for O0o0O00Oo0o0 in range ( int ( OOO00O ) ) :
   O00O0oOO00O00 = oOOOOo0 [ O0o0O00Oo0o0 * 16 : O0o0O00Oo0o0 * 16 + 16 ] + b"\x01"
   O00O0oOO00O00 += ( 17 - len ( O00O0oOO00O00 ) ) * b"\x00"
   i1 = str2num_littleend ( O00O0oOO00O00 )
   OOoOO0oo0ooO = ( OOoOO0oo0ooO + i1 ) * o00oOO0o
  OOoOO0oo0ooO = OOoOO0oo0ooO % iiII1i1
  Oo00 = self . __aes ( i1I11i1iI , iii11 )
  Oo00 = str2num_littleend ( Oo00 )
  I1Ii = ( OOoOO0oo0ooO + Oo00 ) % ( 1 << 128 )
  if 31 - 31: I1Ii111 . OoOoOO00 / O0
  I1Ii = '' . join ( [ chr ( 0xff & ( I1Ii >> 8 * O0o0O00Oo0o0 ) ) for O0o0O00Oo0o0 in range ( 16 ) ] )
  if PY3K :
   I1Ii = I1Ii . encode ( "latin-1" )
   if 89 - 89: OoOoOO00
  return I1Ii
  if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
 def hexdigest ( self ) :
  return binascii . hexlify ( self . digest ( ) ) . decode ( )
  if 4 - 4: ooOoO0o + O0 * OOooOOo
  if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
  if 25 - 25: I1ii11iIi11i
  if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
  if 13 - 13: OOooOOo / i11iIiiIii
  if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
 def copy ( self ) :
  return Poly1305 ( self . __key_aes , self . __r ,
  # o0oOOo0O0Ooo . i11iIiiIii * IiII % o0oOOo0O0Ooo
  # O0 * OoO0O00 + OOooOOo
  # O0 * oO0o . O0
  # o0oOOo0O0Ooo - I1IiiI
  # OoOoOO00 - O0 - IiII % Ii1I - i1IIi % OoOoOO00
  # OoOoOO00 + OoO0O00
  # OoO0O00
  # OoooooooOO + O0 * O0 % O0
  # I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
  # ooOoO0o % Oo0Ooo - i1IIi - i1IIi - iII111i . Oo0Ooo
 self . __nonce , self . __string ,
 self . __aes )
  if 77 - 77: iII111i % iII111i * oO0o - i11iIiiIii
  if 93 - 93: OoooooooOO / I1IiiI % i11iIiiIii + I1ii11iIi11i * OoO0O00
def poly1305aes ( k , r , n , m ) :
 return Poly1305 ( k , r , n , m , I111IiIi ) . digest ( )
 if 15 - 15: I11i . OoO0O00 / Oo0Ooo + I11i
 if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
 if 49 - 49: Ii1I / OoO0O00 . II111iiii
 if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
 if 31 - 31: II111iiii . I1IiiI
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
 if 92 - 92: iII111i
 if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iII111i
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % I1Ii111
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
 if 23 - 23: O0
 if 85 - 85: Ii1I
def str2num_littleend ( val ) :
 return int ( binascii . hexlify ( val [ : : - 1 ] ) , 16 )
 if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
 if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
if sys . version [ 0 ] == "3" :
 def hexify ( s ) :
  b = [ ]
  for i in s :
   if type ( i ) == int :
    i = chr ( i ) . encode ( )
   elif type ( i ) == bytes :
    pass
   elif type ( i ) == str :
    i = i . encode ( )
   b . append ( i )
  return b' ' . join ( map ( binascii . hexlify , b ) )
elif sys . version [ 0 ] == "2" :
 def hexify ( s ) :
  return b" " . join ( map ( binascii . hexlify , s ) )
  if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
hexify . __doc__ = ( "Helper function to turn a binary "
 "string into a human readable hex-encoded "
 "form." )
if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
if 77 - 77: iIii1I11I1II1 * OoO0O00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
