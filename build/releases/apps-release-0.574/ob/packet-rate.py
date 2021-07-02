#!/usr/bin/python
# 
# packet-rate
#
# Usage: python packet-rate.py [<mc-parms>]
#
# Take output from lisp-mc.py and only display EIDs that are currently moving
# packets.
#
#------------------------------------------------------------------------------
from __future__ import print_function
try :
 from commands import getoutput
except :
 from subprocess import getoutput
 if 64 - 64: i11iIiiIii
import sys
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
o0OO00 = ""
if 78 - 78: i11i . oOooOoO0Oo0O
if ( "help" in sys . argv ) :
 print ( "Usage: python packet-rate.py [<mc-parms>]" )
 exit ( 0 )
 if 10 - 10: IIiI1I11i11
 if 54 - 54: i11iIi1 - oOo0O0Ooo
if ( len ( sys . argv ) > 1 ) :
 o0OO00 = " " . join ( sys . argv [ 1 : : ] )
 if 2 - 2: o0 * i1 * ii1IiI1i % OOooOOo / I11i / Ii1I
 if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
i1I1ii1II1iII = getoutput ( "./mc {}" . format ( o0OO00 ) )
i1I1ii1II1iII = i1I1ii1II1iII . split ( "\n" )
if 86 - 86: ooOoO0o
i1ii1iIII = [ ]
for Oo0oO0oo0oO00 in i1I1ii1II1iII :
 if ( Oo0oO0oo0oO00 . find ( "LISP Map-Cache" ) != - 1 ) : print ( "\n{}\n" . format ( Oo0oO0oo0oO00 ) )
 if ( Oo0oO0oo0oO00 . find ( "EID" ) != - 1 ) : i1ii1iIII . append ( Oo0oO0oo0oO00 )
 if ( Oo0oO0oo0oO00 . find ( "RLOC" ) != - 1 ) : i1ii1iIII . append ( Oo0oO0oo0oO00 )
 if ( Oo0oO0oo0oO00 . find ( "packet-count" ) != - 1 ) : i1ii1iIII . append ( Oo0oO0oo0oO00 )
 if 8 - 8: I1Ii111 / IiII
 if 88 - 88: iII111i . ii1IiI1i % ooOoO0o
for Oo0oO0oo0oO00 in i1ii1iIII :
 if ( Oo0oO0oo0oO00 . find ( "EID" ) != - 1 ) :
  ooO0oooOoO0 = Oo0oO0oo0oO00
  continue
  if 21 - 21: oOo0O0Ooo / iII111i * i11iIi1 . i11i
 if ( Oo0oO0oo0oO00 . find ( "RLOC" ) != - 1 ) :
  Ii1IIii11 = Oo0oO0oo0oO00
  continue
  if 55 - 55: iIii1I11I1II1 - oOooOoO0Oo0O . Ii1I * IiII * i1IIi / iIii1I11I1II1
 if ( Oo0oO0oo0oO00 . find ( "packet-count: 0," ) != - 1 ) : continue
 if 79 - 79: ii1IiI1i + I1Ii111 . ooOoO0o * IiII % I11i . oOooOoO0Oo0O
 Ii1IIii11 = Ii1IIii11 . split ( ", " ) [ 0 ]
 O0o0o00o0Oo0 = "{}, {}" . format ( Ii1IIii11 , Oo0oO0oo0oO00 . strip ( ) )
 print ( ooO0oooOoO0 , "\n" , O0o0o00o0Oo0 , "\n" )
 if 23 - 23: OoooooooOO
 if 33 - 33: i11i * IIiI1I11i11 - o0 * iIii1I11I1II1 * OoooooooOO * ooOoO0o
exit ( 0 )
if 27 - 27: i11iIi1
if 73 - 73: o0 - IIiI1I11i11
if 58 - 58: i11iIiiIii % I1Ii111
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
