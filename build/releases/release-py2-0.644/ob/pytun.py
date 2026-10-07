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
__author__ = "Gawen Arab (py3 port)"
__license__ = "MIT"
__version__ = "1.0.1-py3"
if 68 - 68: Ii1I / O0
import os
import fcntl
import struct
import logging
import functools
if 46 - 46: O0 * II111iiii / IiII * Oo0Ooo * iII111i . I11i
Oo0oO0ooo = "/dev/net/tun"
if 56 - 56: I11i - i1IIi
o00oOoo = logging . getLogger ( "pytun" )
if 78 - 78: I11i / OoO0O00 - O0 . IiII
class OOooo0000ooo ( object ) :
 if 79 - 79: oO0o + I1Ii111 . ooOoO0o * IiII % I11i . I1IiiI
 if 94 - 94: iII111i * Ii1I / IiII . i1IIi * iII111i
 class AlreadyOpened ( Exception ) :
  pass
  if 47 - 47: i1IIi % i11iIiiIii
 class NotPermitted ( Exception ) :
  pass
  if 20 - 20: ooOoO0o * II111iiii
 MODES = {
 "tun" : 0x0001 ,
 "tap" : 0x0002 ,
 }
 if 65 - 65: o0oOOo0O0Ooo * iIii1I11I1II1 * ooOoO0o
 IFF_NO_PI = 0x1000
 if 18 - 18: iIii1I11I1II1 / I11i + oO0o / Oo0Ooo - II111iiii - I11i
 if 1 - 1: I11i - OOooOOo % O0 + I1IiiI - iII111i / I11i
 TUNSETIFF = 0x400454ca
 if 31 - 31: OoO0O00 + II111iiii
 def __init__ ( self , mode = None , pattern = None , auto_open = None , no_pi = False ) :
  mode = mode if mode is not None else "tun"
  pattern = pattern if pattern is not None else ""
  auto_open = auto_open if auto_open is not None else True
  if 13 - 13: OOooOOo * oO0o * I1IiiI
  super ( OOooo0000ooo , self ) . __init__ ( )
  if 55 - 55: II111iiii
  self . pattern = pattern
  self . mode = mode
  self . no_pi = no_pi
  if 43 - 43: OoOoOO00 - i1IIi + I1Ii111 + Ii1I
  self . name = None
  self . fd = None
  if 17 - 17: o0oOOo0O0Ooo
  if isinstance ( self . mode , str ) :
   self . mode = self . MODES . get ( self . mode , None )
   assert self . mode is not None , "%r is not a valid tunnel type." % ( mode , )
   if 64 - 64: Ii1I % i1IIi % OoooooooOO
  if auto_open :
   self . open ( )
   if 3 - 3: iII111i + O0
 def __del__ ( self ) :
  self . close ( )
  if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
 @ property
 def mode_name ( self ) :
  for oo0Ooo0 , I1I11I1I1I in self . MODES . items ( ) :
   if I1I11I1I1I == self . mode :
    return oo0Ooo0
    if 90 - 90: II111iiii + oO0o / o0oOOo0O0Ooo % II111iiii - O0
 def fileno ( self ) :
  return self . fd
  if 29 - 29: o0oOOo0O0Ooo / iIii1I11I1II1
  if 24 - 24: O0 % o0oOOo0O0Ooo + i1IIi + I1Ii111 + I1ii11iIi11i
 def open ( self ) :
  if self . fd is not None :
   raise self . AlreadyOpened ( )
   if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
  self . fd = os . open ( Oo0oO0ooo , os . O_RDWR )
  if 23 - 23: i11iIiiIii + I1IiiI
  oOo = self . mode
  if self . no_pi :
   oOo |= self . IFF_NO_PI
   if 63 - 63: Oo0Ooo
  ooOoOoo0O = self . pattern
  if isinstance ( ooOoOoo0O , str ) :
   ooOoOoo0O = ooOoOoo0O . encode ( )
   if 76 - 76: O0 / o0oOOo0O0Ooo . I1IiiI * Ii1I - OOooOOo
  try :
   Oooo = fcntl . ioctl ( self . fd , self . TUNSETIFF ,
 struct . pack ( "16sH" , ooOoOoo0O , oOo ) )
  except IOError as O00o :
   if O00o . errno == 1 :
    self . close ( )
    raise self . NotPermitted ( )
   self . close ( )
   raise
   if 61 - 61: iII111i . iIii1I11I1II1 * I1IiiI . ooOoO0o % Oo0Ooo
  self . name = Oooo [ : 16 ] . strip ( b"\x00" ) . decode ( )
  o00oOoo . info ( "Tunnel '%s' opened." % ( self . name , ) )
  if 72 - 72: OOooOOo
 def close ( self ) :
  if self . fd is None :
   return
  os . close ( self . fd )
  self . fd = None
  if 63 - 63: Ii1I
 def write ( self , buf ) :
  return os . write ( self . fd , buf )
  if 86 - 86: ooOoO0o . I1IiiI % Oo0Ooo + o0oOOo0O0Ooo
  if 35 - 35: iIii1I11I1II1 % oO0o * I11i % I11i + II111iiii * iII111i
  if 54 - 54: I11i + IiII / iII111i
  if 9 - 9: OoOoOO00 / Oo0Ooo - IiII . i1IIi / I1IiiI % IiII
 send = write
 if 71 - 71: I1Ii111 . O0
 def read ( self , size = 1500 ) :
  return os . read ( self . fd , size )
  if 73 - 73: OOooOOo % OoOoOO00 - Ii1I
 recv = read
 if 10 - 10: I1IiiI % I1ii11iIi11i
 def __repr__ ( self ) :
  return "<%s tunnel '%s'>" % ( self . mode_name . capitalize ( ) , self . name )
  if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
class i1iiI11I ( OOooo0000ooo ) :
 def __init__ ( self , * kargs , ** kwargs ) :
  if 29 - 29: OoooooooOO
  super ( i1iiI11I , self ) . __init__ ( "tun" , * kargs , ** kwargs )
  if 23 - 23: o0oOOo0O0Ooo . II111iiii
class Oo0O0OOOoo ( OOooo0000ooo ) :
 def __init__ ( self , * kargs , ** kwargs ) :
  if 95 - 95: OoO0O00 % oO0o . O0
  super ( Oo0O0OOOoo , self ) . __init__ ( "tap" , * kargs , ** kwargs )
  if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
o00oOO0 = functools . partial ( OOooo0000ooo , auto_open = True )
open = o00oOO0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
