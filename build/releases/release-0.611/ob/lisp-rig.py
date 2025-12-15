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
# lisp-rig.py
#
# This file supports LISP rig. See draft-ietf-lisp-rig for details.
#
# Command line usage is:
#
#     rig [<iid>]<dest-eid> to <ddt-node> [debug] [follow-all-referrals]
#
#------------------------------------------------------------------------------
from __future__ import print_function
from builtins import str
from builtins import range
import lisp
import os
import sys
import time
import random
import select
from builtins import input
from subprocess import getoutput
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
i1I1ii1II1iII = None
oooO0oo0oOOOO = None
O0oO = [ None , None , None ]
o0oO0 = lisp . lisp_get_ephemeral_port ( )
if 100 - 100: i1IIi
if 27 - 27: IiII * OoooooooOO + I11i * ooOoO0o - i11iIiiIii - iII111i
if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . II111iiii - oO0o
if 72 - 72: II111iiii - OoOoOO00
if 91 - 91: OoO0O00 . i11iIiiIii / oO0o % I11i / OoO0O00 - i11iIiiIii
if 8 - 8: o0oOOo0O0Ooo * I1ii11iIi11i * iIii1I11I1II1 . IiII / IiII % IiII
def i11 ( ) :
 global O0oO
 global oooO0oo0oOOOO
 if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
 for o000o0o00o0Oo in O0oO :
  if ( o000o0o00o0Oo == None ) : continue
  oo = "/tmp/lisp-rig" if ( o000o0o00o0Oo == oooO0oo0oOOOO ) else ""
  lisp . lisp_close_socket ( o000o0o00o0Oo , oo )
  if 33 - 33: II111iiii * Oo0Ooo - o0oOOo0O0Ooo * iIii1I11I1II1 * OoooooooOO * ooOoO0o
 return
 if 27 - 27: OoO0O00
 if 73 - 73: o0oOOo0O0Ooo - Oo0Ooo
 if 58 - 58: i11iIiiIii % I1Ii111
 if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
 if 31 - 31: OoO0O00 + II111iiii
 if 13 - 13: OOooOOo * oO0o * I1IiiI
 if 55 - 55: II111iiii
def IIIiI11ii ( ) :
 if ( os . path . exists ( "./lisp.config" ) == False ) : return ( None , None )
 if 52 - 52: iII111i + OOooOOo % OoooooooOO / i11iIiiIii
 if 25 - 25: O0 * oO0o + OoooooooOO
 if 70 - 70: OOooOOo / Ii1I . Ii1I
 if 11 - 11: ooOoO0o / O0 - i1IIi
 o00O00O0O0O = getoutput ( 'egrep "instance-id = " ./lisp.config' )
 if ( o00O00O0O0O == "" ) : return ( None , None )
 o00O00O0O0O = o00O00O0O0O . split ( "\n" ) [ 0 ]
 o00O00O0O0O = o00O00O0O0O . split ( " = " ) [ - 1 ]
 if 90 - 90: II111iiii + oO0o / o0oOOo0O0Ooo % II111iiii - O0
 if 29 - 29: o0oOOo0O0Ooo / iIii1I11I1II1
 if 24 - 24: O0 % o0oOOo0O0Ooo + i1IIi + I1Ii111 + I1ii11iIi11i
 if 70 - 70: Oo0Ooo % Oo0Ooo . IiII % OoO0O00 * o0oOOo0O0Ooo % oO0o
 iiI1IiI = getoutput ( 'egrep -A1 "lisp map-resolver {" ./lisp.config' )
 if ( iiI1IiI == "" ) : return ( None , None )
 iiI1IiI = iiI1IiI . split ( "\n" ) [ - 1 ]
 if ( iiI1IiI . find ( "dns-name" ) == - 1 and iiI1IiI . find ( "address" ) == - 1 ) :
  return ( None , None )
  if 13 - 13: Oo0Ooo . i11iIiiIii - iIii1I11I1II1 - OoOoOO00
 iiI1IiI = iiI1IiI . split ( " = " ) [ - 1 ]
 if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
 return ( o00O00O0O0O , iiI1IiI )
 if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
 if 100 - 100: Ii1I - Ii1I - I1Ii111
 if 20 - 20: OoooooooOO
 if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
 if 97 - 97: i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 if 61 - 61: ooOoO0o
oOOO00o = len ( sys . argv )
O0O00o0OOO0 = ""
Ii1iIIIi1ii = ""
if 80 - 80: I11i * i11iIiiIii / I1Ii111
if 9 - 9: Ii1I + oO0o % Ii1I + i1IIi . OOooOOo
if 31 - 31: o0oOOo0O0Ooo + I11i + I11i / II111iiii
if 26 - 26: OoooooooOO
if 12 - 12: OoooooooOO % OoOoOO00 / ooOoO0o % o0oOOo0O0Ooo
if ( oOOO00o == 2 ) :
 O0O00o0OOO0 = sys . argv [ 1 ]
 iiii = ( O0O00o0OOO0 . find ( "[" ) != - 1 and O0O00o0OOO0 . find ( "]" ) != - 1 )
 o00O00O0O0O , Ii1iIIIi1ii = IIIiI11ii ( )
 if ( o00O00O0O0O == None ) :
  oOOO00o = 1
 elif ( iiii == False ) :
  O0O00o0OOO0 = "[" + o00O00O0O0O + "]" + O0O00o0OOO0
  if 54 - 54: I1ii11iIi11i * OOooOOo
  if 13 - 13: IiII + OoOoOO00 - OoooooooOO + I1Ii111 . iII111i + OoO0O00
if ( oOOO00o <= 1 ) :
 while ( O0O00o0OOO0 == "" ) :
  O0O00o0OOO0 = input ( "Enter destination EID (or S->G): " )
  if 8 - 8: iIii1I11I1II1 . I1IiiI - iIii1I11I1II1 * Ii1I
 while ( Ii1iIIIi1ii == "" ) :
  Ii1iIIIi1ii = input ( "Enter ddt-node address: " )
  if 61 - 61: o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * oO0o / oO0o
else :
 if ( O0O00o0OOO0 == "" ) : O0O00o0OOO0 = sys . argv [ 1 ]
 if ( "to" in sys . argv ) :
  OoOo = sys . argv . index ( "to" )
  if ( OoOo + 1 < oOOO00o ) : Ii1iIIIi1ii = sys . argv [ OoOo + 1 ]
  if 18 - 18: i11iIiiIii
 if ( Ii1iIIIi1ii == "" ) :
  print ( "Usage: rig [<iid>]<dest-eid> to <ddt-node> [debug]" )
  exit ( 1 )
  if 46 - 46: i1IIi / I11i % OOooOOo + I1Ii111
  if 79 - 79: I1Ii111 - o0oOOo0O0Ooo + I1Ii111 - iII111i
  if 8 - 8: I1IiiI
  if 75 - 75: iIii1I11I1II1 / OOooOOo % o0oOOo0O0Ooo * OoOoOO00
  if 9 - 9: OoO0O00
  if 33 - 33: ooOoO0o . iII111i
O0oo0OO0oOOOo = None
if ( O0O00o0OOO0 . find ( "->" ) != - 1 ) :
 O0oo0OO0oOOOo = O0O00o0OOO0 . split ( "->" )
 O0O00o0OOO0 = O0oo0OO0oOOOo [ 1 ]
 O0oo0OO0oOOOo = O0oo0OO0oOOOo [ 0 ]
 if 35 - 35: IiII % I1IiiI
 if 70 - 70: iII111i * I1ii11iIi11i
 if 46 - 46: ooOoO0o / OoO0O00
 if 52 - 52: o0oOOo0O0Ooo - OoooooooOO + Ii1I + Ii1I - o0oOOo0O0Ooo / I1Ii111
 if 44 - 44: ooOoO0o . i1IIi - I1ii11iIi11i . O0 - ooOoO0o
iiii = ( O0O00o0OOO0 . find ( "[" ) != - 1 and O0O00o0OOO0 . find ( "]" ) != - 1 )
o00O00O0O0O = 0
if ( iiii ) :
 o00O00O0O0O = O0O00o0OOO0 . split ( "]" )
 O0O00o0OOO0 = o00O00O0O0O [ 1 ]
 o00O00O0O0O = o00O00O0O0O [ 0 ]
 o00O00O0O0O = int ( o00O00O0O0O [ 1 : : ] )
 if 92 - 92: iII111i . I11i + o0oOOo0O0Ooo
 if 28 - 28: i1IIi * Oo0Ooo - o0oOOo0O0Ooo * IiII * Ii1I / OoO0O00
 if 94 - 94: II111iiii % I1ii11iIi11i / OoOoOO00 * iIii1I11I1II1
 if 54 - 54: o0oOOo0O0Ooo - I1IiiI + OoooooooOO
 if 70 - 70: Ii1I / I11i . iII111i % Oo0Ooo
OOoOO00OOO0OO = ( O0O00o0OOO0 [ 0 ] == "'" or O0O00o0OOO0 [ - 1 ] == "'" )
iI1I111Ii111i = [ "-N" , "-S" , "-E" , "-W" ]
I11IiI1I11i1i = False
for iI1ii1Ii in iI1I111Ii111i :
 if ( iI1ii1Ii in O0O00o0OOO0 ) : I11IiI1I11i1i = True
 if 92 - 92: OoOoOO00
 if 26 - 26: iII111i . I1Ii111
if ( OOoOO00OOO0OO == False and I11IiI1I11i1i == False and iiii == False ) :
 oOOOOo0 = lisp . lisp_gethostbyname ( O0O00o0OOO0 )
 if ( oOOOOo0 == "" ) :
  print ( "Cannot resolve EID name '{}'" . format ( O0O00o0OOO0 ) )
  exit ( 1 )
  if 20 - 20: i1IIi + I1ii11iIi11i - ooOoO0o
 O0O00o0OOO0 = oOOOOo0
 if 30 - 30: II111iiii - OOooOOo - i11iIiiIii % OoOoOO00 - II111iiii * Ii1I
 if 61 - 61: oO0o - I11i % OOooOOo
OOoOO0oo0ooO = lisp . lisp_gethostbyname ( Ii1iIIIi1ii )
if ( OOoOO0oo0ooO == "" ) :
 print ( "Cannot resolve DDT-node name '{}'" . format ( Ii1iIIIi1ii ) )
 exit ( 1 )
 if 98 - 98: iII111i * iII111i / iII111i + I11i
Ii1iIIIi1ii = OOoOO0oo0ooO
if 34 - 34: ooOoO0o
if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
if 92 - 92: iII111i . I1Ii111
lisp . lisp_debug_logging = True if "debug" in sys . argv else False
i1i = ( "follow" in sys . argv )
if 50 - 50: IiII
lisp . lisp_i_am ( "rig" )
if 14 - 14: I11i % OoO0O00 * I11i
if 16 - 16: OoOoOO00 . ooOoO0o + i11iIiiIii
if 38 - 38: IiII * OOooOOo . o0oOOo0O0Ooo
if 98 - 98: OoooooooOO + iII111i . OoOoOO00
if 67 - 67: i11iIiiIii - i1IIi % I1ii11iIi11i . O0
if 77 - 77: IiII / I1IiiI
O0oO [ 0 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV4 )
O0oO [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
oooO0oo0oOOOO = lisp . lisp_open_listen_socket ( "" , "/tmp/lisp-rig" )
O0oO [ 2 ] = oooO0oo0oOOOO
if 15 - 15: IiII . iIii1I11I1II1 . OoooooooOO / i11iIiiIii - Ii1I . i1IIi
if 33 - 33: I11i . o0oOOo0O0Ooo
if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
if 91 - 91: O0
try :
 oOOo0 = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 i1I1ii1II1iII = lisp . lisp_open_listen_socket ( "0::0" , str ( 4342 ) )
 O0oO . append ( i1I1ii1II1iII )
except :
 pass
 if 54 - 54: O0 - IiII % OOooOOo
 if 77 - 77: OoOoOO00 / I1IiiI / OoO0O00 + OoO0O00 . OOooOOo
 if 38 - 38: I1Ii111
 if 7 - 7: O0 . iII111i % I1ii11iIi11i - I1IiiI - iIii1I11I1II1
 if 36 - 36: IiII % ooOoO0o % Oo0Ooo - I1ii11iIi11i
Ii1IO000OOo00oo = lisp . lisp_map_request ( )
Ii1IO000OOo00oo . record_count = 1
if 71 - 71: i11iIiiIii + IiII
Ii1IO000OOo00oo . nonce = 0
if ( OOoOO00OOO0OO ) :
 oOo = lisp . LISP_AFI_NAME
 oOO00Oo = len ( O0O00o0OOO0 ) * 8
elif ( O0O00o0OOO0 . find ( ":" ) != - 1 ) :
 oOo = lisp . LISP_AFI_IPV6
 oOO00Oo = 128
elif ( O0O00o0OOO0 . find ( "." ) != - 1 ) :
 oOo = lisp . LISP_AFI_IPV4
 oOO00Oo = 32
elif ( I11IiI1I11i1i ) :
 oOo = lisp . LISP_AFI_GEO_COORD
 oOO00Oo = len ( O0O00o0OOO0 ) * 8
elif ( O0O00o0OOO0 . find ( "-" ) != - 1 ) :
 oOo = lisp . LISP_AFI_MAC
 oOO00Oo = 48
else :
 i11 ( )
 print ( "Invalid EID address {}" . format ( O0O00o0OOO0 ) )
 exit ( 1 )
 if 6 - 6: oO0o
 if 68 - 68: OoOoOO00 - OoO0O00
if ( lisp . lisp_valid_address_format ( "address" , O0O00o0OOO0 ) == False ) :
 print ( "Invalid address syntax '{}'" . format ( O0O00o0OOO0 ) )
 exit ( 1 )
 if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
 if 1 - 1: iIii1I11I1II1 / II111iiii
 if 33 - 33: I11i
 if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
 if 87 - 87: i11iIiiIii
Ii1IO000OOo00oo . target_eid = lisp . lisp_address ( oOo , "" , oOO00Oo , o00O00O0O0O )
if ( O0oo0OO0oOOOo ) :
 Ii1IO000OOo00oo . target_eid . store_address ( O0oo0OO0oOOOo )
 Ii1IO000OOo00oo . target_group . store_address ( O0O00o0OOO0 )
 OO0Oooo0 = Ii1IO000OOo00oo . target_eid . print_sg ( Ii1IO000OOo00oo . target_group )
else :
 Ii1IO000OOo00oo . target_eid . store_address ( O0O00o0OOO0 )
 OO0Oooo0 = Ii1IO000OOo00oo . target_eid . print_address ( )
 if 62 - 62: O0 * i1IIi * o0oOOo0O0Ooo - I1IiiI + I1IiiI
 if 34 - 34: iIii1I11I1II1 - o0oOOo0O0Ooo
 if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
Ii1IO000OOo00oo . source_eid . afi = lisp . LISP_AFI_NONE
if 51 - 51: O0 + iII111i
if ( lisp . lisp_get_local_addresses ( ) == False ) :
 print ( "Cannot obtain a local address" )
 exit ( 1 )
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % I1Ii111
ooO00OO0 = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( )
i11111IIIII = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , ooO00OO0 , 32 , 0 )
Ii1IO000OOo00oo . itr_rlocs . append ( i11111IIIII )
Ii1IO000OOo00oo . dont_reply_bit = True
if 19 - 19: OoOoOO00 * i1IIi
if 14 - 14: iII111i
if 11 - 11: IiII * I1IiiI . iIii1I11I1II1 % OoooooooOO + iII111i
if 78 - 78: OoO0O00 . OOooOOo + OoO0O00 / I11i / OoO0O00
oO0O00OoOO0 = Ii1IO000OOo00oo . encode ( None , 0 )
Ii1IO000OOo00oo . print_map_request ( )
if 82 - 82: II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
if 77 - 77: iIii1I11I1II1 * OoO0O00
if 95 - 95: I1IiiI + i11iIiiIii
if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
o00o0 = lisp . lisp_control_header ( )
ii = lisp . lisp_map_referral ( )
if ( Ii1iIIIi1ii . find ( ":" ) != - 1 ) :
 oOo = lisp . LISP_AFI_IPV6
 oOO00Oo = 128
elif ( Ii1iIIIi1ii . find ( "." ) != - 1 ) :
 oOo = lisp . LISP_AFI_IPV4
 oOO00Oo = 32
else :
 i11 ( )
 print ( "Invalid DDT-node address {}" . format ( Ii1iIIIi1ii ) )
 exit ( 1 )
 if 84 - 84: o0oOOo0O0Ooo % II111iiii . i11iIiiIii / OoO0O00
Ii1iIIIi1ii = lisp . lisp_address ( oOo , Ii1iIIIi1ii , oOO00Oo , 0 )
if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
if 25 - 25: OoO0O00
if 62 - 62: OOooOOo + O0
if 98 - 98: o0oOOo0O0Ooo
if ( O0oo0OO0oOOOo ) :
 OOOO0oo0 = Ii1IO000OOo00oo . target_group
 I11iiI1i1 = Ii1IO000OOo00oo . target_eid
else :
 OOOO0oo0 = Ii1IO000OOo00oo . target_eid
 I11iiI1i1 = lisp . lisp_myrlocs [ 1 ] if OOOO0oo0 . is_ipv6 ( ) else i11111IIIII
 if 47 - 47: iII111i - Ii1I . II111iiii + OoooooooOO . i11iIiiIii
 if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
oO0 = oO0O00OoOO0
O0OO0O = True
OO = 4
OoOoO = 8
Ii1I1i = False
if 99 - 99: oO0o . iII111i + ooOoO0o % oO0o . i11iIiiIii % O0
if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
if 57 - 57: OoO0O00 / ooOoO0o
if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
if 13 - 13: Ii1I . i11iIiiIii
oOOoo00O00o = { Ii1iIIIi1ii . print_address_no_iid ( ) : [ None , Ii1iIIIi1ii ] }
if 98 - 98: OOooOOo + IiII + oO0o % OoooooooOO
while ( True ) :
 OO -= 1
 if ( OO == 0 ) : break
 if 97 - 97: O0 * OoooooooOO . OoooooooOO
 if ( OoOoO == 0 ) :
  print ( "Reached depth limit for LISP-DDT traversal" )
  break
  if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
  if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 for Oo in list ( oOOoo00O00o . keys ( ) ) :
  if ( oOOoo00O00o [ Oo ] [ 0 ] != None ) : continue
  Ii1iIIIi1ii = oOOoo00O00o [ Oo ] [ 1 ]
  if 65 - 65: Ii1I - oO0o + oO0o + II111iiii
  print ( "Send rig map-request to {} for EID {} ..." . format ( Ii1iIIIi1ii . print_address_no_iid ( ) , OO0Oooo0 ) )
  if 96 - 96: OOooOOo % O0 / O0
  if 44 - 44: oO0o / I11i / I11i
  if 87 - 87: Oo0Ooo . I1IiiI - II111iiii + O0 / Oo0Ooo / oO0o
  if 25 - 25: I1IiiI . I1IiiI - OoOoOO00 % OoOoOO00 - i11iIiiIii / I1Ii111
  if 51 - 51: Oo0Ooo / OoOoOO00 . OOooOOo * o0oOOo0O0Ooo + OoO0O00 * IiII
  oO0O00OoOO0 = oO0
  lisp . lisp_send_ecm ( O0oO , oO0O00OoOO0 , I11iiI1i1 ,
 o0oO0 , OOOO0oo0 , Ii1iIIIi1ii , to_ms = Ii1I1i , ddt = True )
  OOOoOo = time . time ( )
  oOOoo00O00o [ Oo ] [ 0 ] = OOOoOo
  if 51 - 51: ooOoO0o / iIii1I11I1II1 % Oo0Ooo * I1IiiI % I1Ii111
  if 76 - 76: o0oOOo0O0Ooo - i11iIiiIii
  if 14 - 14: OoOoOO00 + oO0o
  if 52 - 52: OoooooooOO - ooOoO0o
  if 74 - 74: iII111i + o0oOOo0O0Ooo
  if 71 - 71: Oo0Ooo % OOooOOo
 O00oO000O0O = [ ]
 for o000o0o00o0Oo in O0oO :
  if ( o000o0o00o0Oo == None ) : continue
  O00oO000O0O . append ( o000o0o00o0Oo )
  if 18 - 18: iII111i - OOooOOo . I1Ii111 . iIii1I11I1II1
  if 2 - 2: OOooOOo . OoO0O00
  if 78 - 78: I11i * iIii1I11I1II1 . I1IiiI / o0oOOo0O0Ooo - OoooooooOO / I1Ii111
  if 35 - 35: I11i % OOooOOo - oO0o
  if 20 - 20: i1IIi - ooOoO0o
  if 30 - 30: I11i / I1IiiI
 Iii1I1111ii , ooOoO00 , Ii1IIiI1i = select . select ( O00oO000O0O , [ ] , [ ] , 2 )
 if 78 - 78: I1ii11iIi11i
 if ( O0oO [ 0 ] in Iii1I1111ii ) :
  o0Oo0oO0oOO00 , oo00OO0000oO , I1II1 , oO0O00OoOO0 = lisp . lisp_receive ( O0oO [ 0 ] , False )
  if 86 - 86: iIii1I11I1II1 / OoOoOO00 . II111iiii
 elif ( O0oO [ 1 ] in Iii1I1111ii ) :
  o0Oo0oO0oOO00 , oo00OO0000oO , I1II1 , oO0O00OoOO0 = lisp . lisp_receive ( O0oO [ 1 ] , False )
  if 19 - 19: I1ii11iIi11i % OoooooooOO % IiII * o0oOOo0O0Ooo % O0
 elif ( oooO0oo0oOOOO in Iii1I1111ii ) :
  o0Oo0oO0oOO00 , oo00OO0000oO , I1II1 , oO0O00OoOO0 = lisp . lisp_receive ( oooO0oo0oOOOO , True )
  if 67 - 67: I1IiiI . i1IIi
 elif ( i1I1ii1II1iII in Iii1I1111ii ) :
  o0Oo0oO0oOO00 , oo00OO0000oO , I1II1 , oO0O00OoOO0 = lisp . lisp_receive ( i1I1ii1II1iII , False )
  if 27 - 27: ooOoO0o % I1IiiI
 else :
  continue
  if 73 - 73: OOooOOo
  if 70 - 70: iIii1I11I1II1
  if 31 - 31: IiII - I1IiiI % iIii1I11I1II1
  if 92 - 92: i1IIi - iIii1I11I1II1
  if 16 - 16: OoO0O00 - OoOoOO00 - OOooOOo - i1IIi / Ii1I
 if ( oo00OO0000oO == "" ) : continue
 if 88 - 88: OoO0O00
 if 71 - 71: I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i - I1IiiI . iIii1I11I1II1 - i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 if ( o0Oo0oO0oOO00 != "packet" ) :
  print ( "Internal fatal error" )
  continue
  if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
  if 73 - 73: I11i % i11iIiiIii - I1IiiI
  if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
  if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
  if 23 - 23: i11iIiiIii
 if ( o00o0 . decode ( oO0O00OoOO0 ) == None ) :
  print ( "Could not decode header" )
  continue
  if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
  if 81 - 81: IiII % i1IIi . iIii1I11I1II1
  if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
  if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
  if 31 - 31: OOooOOo
  if 23 - 23: I1Ii111 . IiII
  if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
 if ( o00o0 . type != lisp . LISP_MAP_REFERRAL ) :
  if ( i1I1ii1II1iII != None and o00o0 . type == lisp . LISP_ECM ) :
   time . sleep ( 2 )
  else :
   print ( "Map-Referral not returned, packet type {} returned" . format ( o00o0 . type ) )
   if 42 - 42: Oo0Ooo
   if 76 - 76: I1IiiI * iII111i % I1Ii111
  continue
  if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
  if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
  if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
  if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
  if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
 if ( oo00OO0000oO not in oOOoo00O00o ) :
  print ( "Received Map-Referral from {} but no Map-Request was pending" . format ( oo00OO0000oO ) )
  if 42 - 42: I1IiiI
  continue
  if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
  if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
 OOOoOo = oOOoo00O00o [ oo00OO0000oO ] [ 0 ]
 oOOoo00O00o . pop ( oo00OO0000oO )
 if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
 if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
 if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
 if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
 O00oOOooo = round ( time . time ( ) - OOOoOo , 3 )
 print ( "Received map-referral from {} with rtt {} secs:" . format ( oo00OO0000oO , O00oOOooo ) )
 oO0O00OoOO0 = ii . decode ( oO0O00OoOO0 )
 if ( oO0O00OoOO0 == None ) :
  print ( "Could not decode Map-Referral packet" )
  continue
  if 50 - 50: I1ii11iIi11i % O0 * o0oOOo0O0Ooo
 O0OO0O = False
 ii . print_map_referral ( )
 if 5 - 5: IiII * OoOoOO00
 for i1Ii1i1I11Iii in range ( ii . record_count ) :
  I1i1i1 = lisp . lisp_eid_record ( )
  oO0O00OoOO0 = I1i1i1 . decode ( oO0O00OoOO0 )
  if ( oO0O00OoOO0 == None ) : break
  if 73 - 73: O0 * iII111i + Ii1I + ooOoO0o
  Ii = lisp . lisp_map_referral_action_string [ I1i1i1 . action ]
  Ii = lisp . bold ( Ii , False )
  if 100 - 100: I1Ii111 + OOooOOo + OOooOOo
  print ( "EID-prefix: {}, ttl: {}, referral-type: {}" . format ( I1i1i1 . print_prefix ( ) , I1i1i1 . print_ttl ( ) , Ii ) )
  if 9 - 9: I11i % OoooooooOO . oO0o % I11i
  if 32 - 32: i11iIiiIii
  I1i1i1 . print_record ( "" , True )
  if 31 - 31: iIii1I11I1II1 / OoO0O00 / I1ii11iIi11i
  iiIiIi = 0
  if ( I1i1i1 . rloc_count != 0 ) :
   print ( "  Referrals:" , end = " " )
   if ( lisp . lisp_debug_logging ) : print ( "\n" )
   iiIiIi = random . randint ( 0 , 255 ) % I1i1i1 . rloc_count
   if 39 - 39: I1Ii111
   if 91 - 91: OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoOoOO00 + O0
  Ii1I1i = I1i1i1 . action in ( lisp . LISP_DDT_ACTION_MS_REFERRAL ,
 lisp . LISP_DDT_ACTION_MS_ACK )
  if 26 - 26: I1ii11iIi11i - OoooooooOO
  iiI1iI111ii1i = I1i1i1 . action in ( lisp . LISP_DDT_ACTION_MS_NOT_REG ,
 lisp . LISP_DDT_ACTION_DELEGATION_HOLE ,
 lisp . LISP_DDT_ACTION_NOT_AUTH , lisp . LISP_DDT_ACTION_MS_ACK )
  if 32 - 32: II111iiii * OoOoOO00 % i1IIi - iII111i + iIii1I11I1II1 + I1ii11iIi11i
  if 60 - 60: I1ii11iIi11i % OoOoOO00 * OoO0O00 % II111iiii
  if 70 - 70: OoO0O00 % oO0o + OOooOOo / Ii1I % O0
  if 100 - 100: o0oOOo0O0Ooo + OOooOOo * o0oOOo0O0Ooo
  for oOOo0OOOo00O in range ( I1i1i1 . rloc_count ) :
   OooOOOO = lisp . lisp_rloc_record ( )
   oO0O00OoOO0 = OooOOOO . decode ( oO0O00OoOO0 , ii . nonce )
   if ( oO0O00OoOO0 == None ) : break
   OooOOOO . print_record ( "  " )
   if 45 - 45: I1ii11iIi11i % I1IiiI - i11iIiiIii
   if ( lisp . lisp_debug_logging == False ) :
    ii1iiIiIII1ii = OooOOOO . rloc . print_address_no_iid ( )
    if ( oOOo0OOOo00O != I1i1i1 . rloc_count - 1 ) : ii1iiIiIII1ii += ","
    print ( ii1iiIiIII1ii , end = " " )
    if 82 - 82: iII111i
    if 65 - 65: ooOoO0o . OoooooooOO / I1ii11iIi11i . i1IIi * OoO0O00
   if ( i1i ) :
    if ( iiI1iI111ii1i ) : continue
   else :
    if ( iiIiIi != oOOo0OOOo00O ) : continue
    if 19 - 19: i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
    if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
    if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
    if 71 - 71: O0 - iIii1I11I1II1
    if 12 - 12: OOooOOo / o0oOOo0O0Ooo
   oOOoo00O00o [ OooOOOO . rloc . print_address_no_iid ( ) ] = [ None , OooOOOO . rloc ]
   if 42 - 42: Oo0Ooo
   if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
   if 46 - 46: Oo0Ooo
  if ( I1i1i1 . rloc_count != 0 ) : print ( "\n" )
  if 1 - 1: iII111i
  if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
  if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
  if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
  if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 if ( i1i == False and iiI1iI111ii1i ) : break
 if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
 if 17 - 17: i1IIi
 if 21 - 21: Oo0Ooo
 if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 OoOoO -= 1
 OO = 4
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
 if 54 - 54: i1IIi + II111iiii
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 if 5 - 5: Ii1I
 if 46 - 46: IiII
if ( O0OO0O ) : print ( "*** No map-referral received ***" )
if 45 - 45: ooOoO0o
if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
if 17 - 17: OOooOOo / OOooOOo / I11i
if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
i11 ( )
exit ( 1 ) if ( O0OO0O ) else exit ( 0 )
if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
