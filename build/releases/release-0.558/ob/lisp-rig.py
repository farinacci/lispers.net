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
import lisp
import sys
import time
import random
import select
from builtins import input
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
IIIiI11ii = len ( sys . argv )
O000oo = ""
i1iIIi1 = ""
if 50 - 50: i11iIiiIii - Ii1I
if 78 - 78: OoO0O00
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
if ( IIIiI11ii == 2 ) :
 O000oo = sys . argv [ 1 ]
 IIIiI11ii = 1
 if 14 - 14: I11i % O0
if ( IIIiI11ii <= 1 ) :
 while ( O000oo == "" ) :
  O000oo = input ( "Enter destination EID (or S->G): " )
  if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
 while ( i1iIIi1 == "" ) :
  i1iIIi1 = input ( "Enter ddt-node address: " )
  if 77 - 77: Oo0Ooo . IiII % ooOoO0o
else :
 O000oo = sys . argv [ 1 ]
 if ( "to" in sys . argv ) :
  IIiiIiI1 = sys . argv . index ( "to" )
  if ( IIiiIiI1 + 1 < IIIiI11ii ) : i1iIIi1 = sys . argv [ IIiiIiI1 + 1 ]
  if 41 - 41: OoOoOO00
 if ( i1iIIi1 == "" ) :
  print ( "Usage: rig [<iid>]<dest-eid> to <ddt-node> [debug]" )
  exit ( 1 )
  if 13 - 13: Oo0Ooo . i11iIiiIii - iIii1I11I1II1 - OoOoOO00
  if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
  if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
  if 100 - 100: Ii1I - Ii1I - I1Ii111
  if 20 - 20: OoooooooOO
  if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
ooO0o0Oo = None
if ( O000oo . find ( "->" ) != - 1 ) :
 ooO0o0Oo = O000oo . split ( "->" )
 O000oo = ooO0o0Oo [ 1 ]
 ooO0o0Oo = ooO0o0Oo [ 0 ]
 if 78 - 78: iIii1I11I1II1 - Ii1I * OoO0O00 + o0oOOo0O0Ooo + iII111i + iII111i
 if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
III1ii1iII = 0
if ( O000oo . find ( "[" ) != - 1 ) :
 III1ii1iII = O000oo . split ( "]" )
 O000oo = III1ii1iII [ 1 ]
 III1ii1iII = III1ii1iII [ 0 ]
 III1ii1iII = int ( III1ii1iII [ 1 : : ] )
 if 54 - 54: I1IiiI % II111iiii % II111iiii
 if 13 - 13: o0oOOo0O0Ooo . Ii1I
 if 19 - 19: I11i + ooOoO0o
 if 53 - 53: OoooooooOO . i1IIi
 if 18 - 18: o0oOOo0O0Ooo
I1i1I1II = ( O000oo [ 0 ] == "'" or O000oo [ - 1 ] == "'" )
i1 = [ "-N" , "-S" , "-E" , "-W" ]
IiIiiI = False
for I1I in i1 :
 if ( I1I in O000oo ) : IiIiiI = True
 if 80 - 80: OoOoOO00 - OoO0O00
 if 87 - 87: oO0o / I11i - i1IIi * OOooOOo / OoooooooOO . O0
if ( I1i1I1II == False and IiIiiI == False ) :
 iii11I111 = lisp . lisp_gethostbyname ( O000oo )
 if ( iii11I111 == "" ) :
  print ( "Cannot resolve EID name '{}'" . format ( O000oo ) )
  exit ( 1 )
  if 63 - 63: OoO0O00 * oO0o - iII111i * O0
 O000oo = iii11I111
 if 17 - 17: I1ii11iIi11i % II111iiii
 if 13 - 13: I1Ii111 % OoOoOO00 - i11iIiiIii . I1IiiI + II111iiii
II111ii1II1i = lisp . lisp_gethostbyname ( i1iIIi1 )
if ( II111ii1II1i == "" ) :
 print ( "Cannot resolve DDT-node name '{}'" . format ( i1iIIi1 ) )
 exit ( 1 )
 if 59 - 59: O0 + I1IiiI + IiII % I1IiiI
i1iIIi1 = II111ii1II1i
if 70 - 70: iII111i * I1ii11iIi11i
if 46 - 46: ooOoO0o / OoO0O00
if 52 - 52: o0oOOo0O0Ooo - OoooooooOO + Ii1I + Ii1I - o0oOOo0O0Ooo / I1Ii111
if 44 - 44: ooOoO0o . i1IIi - I1ii11iIi11i . O0 - ooOoO0o
lisp . lisp_debug_logging = True if "debug" in sys . argv else False
o0O = ( "follow" in sys . argv )
if 72 - 72: iII111i / i1IIi * Oo0Ooo - I1Ii111
lisp . lisp_i_am ( "rig" )
if 51 - 51: II111iiii * OoO0O00 % o0oOOo0O0Ooo * II111iiii % I1ii11iIi11i / ooOoO0o
if 49 - 49: o0oOOo0O0Ooo
if 35 - 35: OoOoOO00 - OoooooooOO / I1ii11iIi11i % i1IIi
if 78 - 78: I11i
if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
O0oO [ 0 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV4 )
O0oO [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
oooO0oo0oOOOO = lisp . lisp_open_listen_socket ( "" , "/tmp/lisp-rig" )
O0oO [ 2 ] = oooO0oo0oOOOO
if 16 - 16: I1IiiI * oO0o % IiII
if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
if 44 - 44: oO0o
if 88 - 88: I1Ii111 % Ii1I . II111iiii
if 38 - 38: o0oOOo0O0Ooo
try :
 Oo0O = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 i1I1ii1II1iII = lisp . lisp_open_listen_socket ( "0::0" , str ( 4342 ) )
 O0oO . append ( i1I1ii1II1iII )
except :
 pass
 if 25 - 25: OoOoOO00 . II111iiii / iII111i . OOooOOo * OoO0O00 . I1IiiI
 if 59 - 59: II111iiii + OoooooooOO * OoOoOO00 + i1IIi
 if 58 - 58: II111iiii * OOooOOo * I1ii11iIi11i / OOooOOo
 if 75 - 75: oO0o
 if 50 - 50: Ii1I / Oo0Ooo - oO0o - I11i % iII111i - oO0o
OOO0o = lisp . lisp_map_request ( )
OOO0o . record_count = 1
if 30 - 30: iIii1I11I1II1 / ooOoO0o - I1Ii111 - II111iiii % iII111i
OOO0o . nonce = 0
if ( I1i1I1II ) :
 IIi1i11111 = lisp . LISP_AFI_NAME
 ooOO00O00oo = len ( O000oo ) * 8
elif ( O000oo . find ( ":" ) != - 1 ) :
 IIi1i11111 = lisp . LISP_AFI_IPV6
 ooOO00O00oo = 128
elif ( O000oo . find ( "." ) != - 1 ) :
 IIi1i11111 = lisp . LISP_AFI_IPV4
 ooOO00O00oo = 32
elif ( IiIiiI ) :
 IIi1i11111 = lisp . LISP_AFI_GEO_COORD
 ooOO00O00oo = len ( O000oo ) * 8
elif ( O000oo . find ( "-" ) != - 1 ) :
 IIi1i11111 = lisp . LISP_AFI_MAC
 ooOO00O00oo = 48
else :
 i11 ( )
 print ( "Invalid EID address {}" . format ( O000oo ) )
 exit ( 1 )
 if 3 - 3: I1Ii111 - O0 / I1Ii111 % OoO0O00 / I1Ii111 . I1IiiI
 if 50 - 50: IiII
if ( lisp . lisp_valid_address_format ( "address" , O000oo ) == False ) :
 print ( "Invalid address syntax '{}'" . format ( O000oo ) )
 exit ( 1 )
 if 14 - 14: I11i % OoO0O00 * I11i
 if 16 - 16: OoOoOO00 . ooOoO0o + i11iIiiIii
 if 38 - 38: IiII * OOooOOo . o0oOOo0O0Ooo
 if 98 - 98: OoooooooOO + iII111i . OoOoOO00
 if 67 - 67: i11iIiiIii - i1IIi % I1ii11iIi11i . O0
OOO0o . target_eid = lisp . lisp_address ( IIi1i11111 , "" , ooOO00O00oo , III1ii1iII )
if ( ooO0o0Oo ) :
 OOO0o . target_eid . store_address ( ooO0o0Oo )
 OOO0o . target_group . store_address ( O000oo )
 o0oo = OOO0o . target_eid . print_sg ( OOO0o . target_group )
else :
 OOO0o . target_eid . store_address ( O000oo )
 o0oo = OOO0o . target_eid . print_address ( )
 if 91 - 91: IiII
 if 15 - 15: II111iiii
 if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
 if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
 if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
OOO0o . source_eid . afi = lisp . LISP_AFI_NONE
if 91 - 91: O0
if ( lisp . lisp_get_local_addresses ( ) == False ) :
 print ( "Cannot obtain a local address" )
 exit ( 1 )
 if 61 - 61: II111iiii
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
 if 67 - 67: I1Ii111 . iII111i . O0
IIIIiiII111 = lisp . lisp_myrlocs [ 0 ] . print_address_no_iid ( )
OOoOoo = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , IIIIiiII111 , 32 , 0 )
OOO0o . itr_rlocs . append ( OOoOoo )
OOO0o . dont_reply_bit = True
if 85 - 85: I1ii11iIi11i % iII111i % ooOoO0o
if 82 - 82: i11iIiiIii - iII111i * OoooooooOO / I11i
if 31 - 31: IiII . OoO0O00 - iIii1I11I1II1
if 64 - 64: I11i
iI11Ii = OOO0o . encode ( None , 0 )
OOO0o . print_map_request ( )
if 6 - 6: oO0o
if 68 - 68: OoOoOO00 - OoO0O00
if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
if 1 - 1: iIii1I11I1II1 / II111iiii
iiI1I11i1i = lisp . lisp_control_header ( )
III1Iiii1I11 = lisp . lisp_map_referral ( )
if ( i1iIIi1 . find ( ":" ) != - 1 ) :
 IIi1i11111 = lisp . LISP_AFI_IPV6
 ooOO00O00oo = 128
elif ( i1iIIi1 . find ( "." ) != - 1 ) :
 IIi1i11111 = lisp . LISP_AFI_IPV4
 ooOO00O00oo = 32
else :
 i11 ( )
 print ( "Invalid DDT-node address {}" . format ( i1iIIi1 ) )
 exit ( 1 )
 if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
i1iIIi1 = lisp . lisp_address ( IIi1i11111 , i1iIIi1 , ooOO00O00oo , 0 )
if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
if 51 - 51: O0 + iII111i
if ( ooO0o0Oo ) :
 IIIII11I1IiI = OOO0o . target_group
 i1I = OOO0o . target_eid
else :
 IIIII11I1IiI = OOO0o . target_eid
 i1I = lisp . lisp_myrlocs [ 1 ] if IIIII11I1IiI . is_ipv6 ( ) else OOoOoo
 if 72 - 72: i1IIi / OoO0O00 + OoooooooOO - Oo0Ooo
 if 29 - 29: I1ii11iIi11i + oO0o % O0
I1I11 = iI11Ii
II1 = True
o0oO00000 = 4
OOOOoo0Oo = 8
ii111iI1iIi1 = False
if 78 - 78: OoO0O00 . OOooOOo + OoO0O00 / I11i / OoO0O00
if 54 - 54: OoOoOO00 % iII111i
if 37 - 37: OoOoOO00 * Oo0Ooo / ooOoO0o - iII111i % II111iiii . oO0o
if 88 - 88: iII111i . II111iiii * II111iiii % I1Ii111
if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
if 80 - 80: II111iiii
O0O = { i1iIIi1 . print_address_no_iid ( ) : [ None , i1iIIi1 ] }
if 1 - 1: II111iiii
while ( True ) :
 o0oO00000 -= 1
 if ( o0oO00000 == 0 ) : break
 if 84 - 84: o0oOOo0O0Ooo % II111iiii . i11iIiiIii / OoO0O00
 if ( OOOOoo0Oo == 0 ) :
  print ( "Reached depth limit for LISP-DDT traversal" )
  break
  if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
  if 25 - 25: OoO0O00
 for oOo0oO in O0O . keys ( ) :
  if ( O0O [ oOo0oO ] [ 0 ] != None ) : continue
  i1iIIi1 = O0O [ oOo0oO ] [ 1 ]
  if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
  print ( "Send rig map-request to {} for EID {} ..." . format ( i1iIIi1 . print_address_no_iid ( ) , o0oo ) )
  if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
  if 82 - 82: Ii1I
  if 46 - 46: OoooooooOO . i11iIiiIii
  if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
  if 87 - 87: Oo0Ooo . IiII
  iI11Ii = I1I11
  lisp . lisp_send_ecm ( O0oO , iI11Ii , i1I ,
 o0oO0 , IIIII11I1IiI , i1iIIi1 , to_ms = ii111iI1iIi1 , ddt = True )
  O0OO0O = time . time ( )
  O0O [ oOo0oO ] [ 0 ] = O0OO0O
  if 81 - 81: oO0o . o0oOOo0O0Ooo % O0 / I1IiiI - oO0o
  if 43 - 43: i11iIiiIii + Oo0Ooo * II111iiii * I1Ii111 * O0
  if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
  if 79 - 79: O0
  if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
  if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 oO0o0 = [ ]
 for o000o0o00o0Oo in O0oO :
  if ( o000o0o00o0Oo == None ) : continue
  oO0o0 . append ( o000o0o00o0Oo )
  if 50 - 50: IiII
  if 46 - 46: O0 + iII111i % I1IiiI / o0oOOo0O0Ooo . IiII * I11i
  if 93 - 93: o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
  if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
  if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
  if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 I111iI , oOOo0 , II1I1iiIII = select . select ( oO0o0 , [ ] , [ ] , 2 )
 if 77 - 77: OoOoOO00 - II111iiii - ooOoO0o
 if ( O0oO [ 0 ] in I111iI ) :
  IiiiIIiIi1 , OoOOoOooooOOo , oOo0O , iI11Ii = lisp . lisp_receive ( O0oO [ 0 ] , False )
  if 52 - 52: i11iIiiIii / o0oOOo0O0Ooo * ooOoO0o
 elif ( O0oO [ 1 ] in I111iI ) :
  IiiiIIiIi1 , OoOOoOooooOOo , oOo0O , iI11Ii = lisp . lisp_receive ( O0oO [ 1 ] , False )
  if 22 - 22: OoOoOO00 . OOooOOo * OoOoOO00
 elif ( oooO0oo0oOOOO in I111iI ) :
  IiiiIIiIi1 , OoOOoOooooOOo , oOo0O , iI11Ii = lisp . lisp_receive ( oooO0oo0oOOOO , True )
  if 54 - 54: IiII + Ii1I % OoO0O00 + OoooooooOO - O0 - o0oOOo0O0Ooo
 elif ( i1I1ii1II1iII in I111iI ) :
  IiiiIIiIi1 , OoOOoOooooOOo , oOo0O , iI11Ii = lisp . lisp_receive ( i1I1ii1II1iII , False )
  if 77 - 77: OOooOOo * iIii1I11I1II1
 else :
  continue
  if 98 - 98: I1IiiI % Ii1I * OoooooooOO
  if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
  if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
  if 71 - 71: Oo0Ooo % OOooOOo
  if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if ( OoOOoOooooOOo == "" ) : continue
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
 if ( IiiiIIiIi1 != "packet" ) :
  print ( "Internal fatal error" )
  continue
  if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
  if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
  if 71 - 71: I1Ii111 + Ii1I
  if 28 - 28: OOooOOo
  if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
 if ( iiI1I11i1i . decode ( iI11Ii ) == None ) :
  print ( "Could not decode header" )
  continue
  if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
  if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
  if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
  if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
  if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
  if 26 - 26: Ii1I % I1ii11iIi11i
  if 76 - 76: IiII * iII111i
 if ( iiI1I11i1i . type != lisp . LISP_MAP_REFERRAL ) :
  if ( i1I1ii1II1iII != None and iiI1I11i1i . type == lisp . LISP_ECM ) :
   time . sleep ( 2 )
  else :
   print ( "Map-Referral not returned, packet type {} returned" . format ( iiI1I11i1i . type ) )
   if 52 - 52: OOooOOo
   if 19 - 19: I1IiiI
  continue
  if 25 - 25: Ii1I / ooOoO0o
  if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
  if 71 - 71: I1Ii111 . II111iiii
  if 62 - 62: OoooooooOO . I11i
  if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
 if ( O0O . has_key ( OoOOoOooooOOo ) == False ) :
  print ( "Received Map-Referral from {} but no Map-Request was pending" . format ( OoOOoOooooOOo ) )
  if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  continue
  if 58 - 58: I1IiiI
  if 53 - 53: i1IIi
 O0OO0O = O0O [ OoOOoOooooOOo ] [ 0 ]
 O0O . pop ( OoOOoOooooOOo )
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
 II1IIIIiII1i = round ( time . time ( ) - O0OO0O , 3 )
 print ( "Received map-referral from {} with rtt {} secs:" . format ( OoOOoOooooOOo , II1IIIIiII1i ) )
 iI11Ii = III1Iiii1I11 . decode ( iI11Ii )
 if ( iI11Ii == None ) :
  print ( "Could not decode Map-Referral packet" )
  continue
  if 1 - 1: II111iiii
 II1 = False
 III1Iiii1I11 . print_map_referral ( )
 if 68 - 68: iII111i - I1IiiI / I1Ii111 / I11i
 for I11iiii in range ( III1Iiii1I11 . record_count ) :
  O0i1iI = lisp . lisp_eid_record ( )
  iI11Ii = O0i1iI . decode ( iI11Ii )
  if ( iI11Ii == None ) : break
  if 29 - 29: I1IiiI % OOooOOo - I1IiiI / OOooOOo . i1IIi
  i11III1111iIi = lisp . lisp_map_referral_action_string [ O0i1iI . action ]
  i11III1111iIi = lisp . bold ( i11III1111iIi , False )
  if 38 - 38: iII111i + I11i / I1Ii111 % ooOoO0o - I1ii11iIi11i
  print ( "EID-prefix: {}, ttl: {}, referral-type: {}" . format ( O0i1iI . print_prefix ( ) , O0i1iI . print_ttl ( ) , i11III1111iIi ) )
  if 14 - 14: oO0o / I1Ii111
  if 85 - 85: I11i
  O0i1iI . print_record ( "" , True )
  if 20 - 20: oO0o % IiII
  III1i1i11i = 0
  if ( O0i1iI . rloc_count != 0 ) :
   print ( "  Referrals:" , end = " " )
   if ( lisp . lisp_debug_logging ) : print ( "\n" )
   III1i1i11i = random . randint ( 0 , 255 ) % O0i1iI . rloc_count
   if 100 - 100: oO0o / I1Ii111 / I1ii11iIi11i
   if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
  ii111iI1iIi1 = O0i1iI . action in ( lisp . LISP_DDT_ACTION_MS_REFERRAL ,
 lisp . LISP_DDT_ACTION_MS_ACK )
  if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
  iI1II = O0i1iI . action in ( lisp . LISP_DDT_ACTION_MS_NOT_REG ,
 lisp . LISP_DDT_ACTION_DELEGATION_HOLE ,
 lisp . LISP_DDT_ACTION_NOT_AUTH , lisp . LISP_DDT_ACTION_MS_ACK )
  if 69 - 69: ooOoO0o % oO0o
  if 50 - 50: OoooooooOO % I11i
  if 49 - 49: oO0o - i11iIiiIii . I1Ii111 * Ii1I % iII111i + i1IIi
  if 71 - 71: o0oOOo0O0Ooo
  for IIIIiIiIi1 in range ( O0i1iI . rloc_count ) :
   I11iiiiI1i = lisp . lisp_rloc_record ( )
   iI11Ii = I11iiiiI1i . decode ( iI11Ii , III1Iiii1I11 . nonce )
   if ( iI11Ii == None ) : break
   I11iiiiI1i . print_record ( "  " )
   if 40 - 40: I1ii11iIi11i + i1IIi * OOooOOo
   if ( lisp . lisp_debug_logging == False ) :
    O0oOOoooOO0O = I11iiiiI1i . rloc . print_address_no_iid ( )
    if ( IIIIiIiIi1 != O0i1iI . rloc_count - 1 ) : O0oOOoooOO0O += ","
    print ( O0oOOoooOO0O , end = " " )
    if 86 - 86: o0oOOo0O0Ooo
    if 5 - 5: IiII * OoOoOO00
   if ( o0O ) :
    if ( iI1II ) : continue
   else :
    if ( III1i1i11i != IIIIiIiIi1 ) : continue
    if 5 - 5: I1Ii111
    if 90 - 90: I1Ii111 . ooOoO0o / Ii1I - I11i
    if 40 - 40: OoooooooOO
    if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
    if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
   O0O [ I11iiiiI1i . rloc . print_address_no_iid ( ) ] = [ None , I11iiiiI1i . rloc ]
   if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
   if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
   if 19 - 19: OoO0O00 - Oo0Ooo . O0
  if ( O0i1iI . rloc_count != 0 ) : print ( "\n" )
  if 60 - 60: II111iiii + Oo0Ooo
  if 9 - 9: ooOoO0o * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
  if 49 - 49: II111iiii
  if 25 - 25: OoooooooOO - I1IiiI . I1IiiI * oO0o
  if 81 - 81: iII111i + IiII
 if ( o0O == False and iI1II ) : break
 if 98 - 98: I1IiiI
 if 95 - 95: ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 if 41 - 41: i1IIi - I11i - Ii1I
 OOOOoo0Oo -= 1
 o0oO00000 = 4
 if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
 if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
 if 44 - 44: II111iiii
 if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
 if 35 - 35: iIii1I11I1II1
 if 42 - 42: I1Ii111 . I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI
if ( II1 ) : print ( "*** No map-referral received ***" )
if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
i11 ( )
exit ( 1 ) if ( II1 ) else exit ( 0 )
if 71 - 71: O0 - iIii1I11I1II1
if 12 - 12: OOooOOo / o0oOOo0O0Ooo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
