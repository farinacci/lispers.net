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
# lisp-lig.py
#
# This file supports LISP lig. See RFC 6835 for details.
#
# Command line usage is:
#
#     lig [<iid>]<dest-eid> to <mr-rloc> [source <source-eid>] [count <1-5>]
#                                        [debug] [no-info] [pubsub]
#
# Parameters are position independent other than <dest-eid>, and when it
# is not supplied, interactive input is requested.
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
if 22 - 22: Ii1I . IiII
if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
def o000o0o00o0Oo ( ) :
 if ( os . path . exists ( "./lisp.config" ) == False ) : return ( None , None )
 if 80 - 80: OoooooooOO . I1IiiI
 if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
 if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
 if 58 - 58: i11iIiiIii % I1Ii111
 O0OoOoo00o = getoutput ( 'egrep "instance-id = " ./lisp.config' )
 if ( O0OoOoo00o == "" ) : return ( None , None )
 O0OoOoo00o = O0OoOoo00o . split ( "\n" ) [ 0 ]
 O0OoOoo00o = O0OoOoo00o . split ( " = " ) [ - 1 ]
 if 31 - 31: II111iiii + OoO0O00 . I1Ii111
 if 68 - 68: I1IiiI - i11iIiiIii - OoO0O00 / OOooOOo - OoO0O00 + i1IIi
 if 48 - 48: OoooooooOO % o0oOOo0O0Ooo . I1IiiI - Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 I1Ii = getoutput ( 'egrep -A1 "lisp map-resolver {" ./lisp.config' )
 if ( I1Ii == "" ) : return ( None , None )
 I1Ii = I1Ii . split ( "\n" ) [ - 1 ]
 if ( I1Ii . find ( "dns-name" ) == - 1 and I1Ii . find ( "address" ) == - 1 ) :
  return ( None , None )
  if 66 - 66: Ii1I
 I1Ii = I1Ii . split ( " = " ) [ - 1 ]
 if 78 - 78: OoO0O00
 return ( O0OoOoo00o , I1Ii )
 if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
 if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
 if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
 if 14 - 14: I11i % O0
 if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
 if 77 - 77: Oo0Ooo . IiII % ooOoO0o
 if 42 - 42: oO0o - i1IIi / i11iIiiIii + OOooOOo + OoO0O00
def iIi ( socket_list , lisp_ephem_listen_socket , lisp_listen_socket ,
 lisp_ipc_socket ) :
 if 40 - 40: oO0o . OoOoOO00 . Oo0Ooo . i1IIi
 I11iii , OO0O00 , ii1 = select . select ( socket_list , [ ] , [ ] , 2 )
 if 57 - 57: Ii1I % OoooooooOO
 if ( lisp_ephem_listen_socket in I11iii ) :
  O00 , i11I1 , Ii11Ii11I , iI11i1I1 = lisp . lisp_receive ( lisp_ephem_listen_socket , False )
  if 71 - 71: ooOoO0o % iII111i / o0oOOo0O0Ooo
 elif ( lisp_listen_socket in I11iii ) :
  O00 , i11I1 , Ii11Ii11I , iI11i1I1 = lisp . lisp_receive ( lisp_listen_socket ,
 False )
 elif ( lisp_ipc_socket in I11iii ) :
  O00 , i11I1 , Ii11Ii11I , iI11i1I1 = lisp . lisp_receive ( lisp_ipc_socket ,
 True )
 else :
  return ( "" , "" , 0 , None )
  if 49 - 49: II111iiii % iII111i * O0
 return ( O00 , i11I1 , Ii11Ii11I , iI11i1I1 )
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
 if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo
 if 77 - 77: OoOoOO00 / I11i
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
def I1i1I1II ( record_count , nonce , packet ) :
 if 45 - 45: I1Ii111 . OoOoOO00
 for oO in range ( record_count ) :
  ii1i1I1i = lisp . lisp_eid_record ( )
  packet = ii1i1I1i . decode ( packet )
  if ( packet == None ) : break
  print ( "EID-prefix: {}, ttl: {}, rloc-set:" . format ( ii1i1I1i . print_prefix ( ) , ii1i1I1i . print_ttl ( ) ) )
  if 53 - 53: IiII + I1IiiI * oO0o
  if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
  if ( ii1i1I1i . rloc_count == 0 ) :
   o00O = lisp . lisp_map_reply_action_string [ ii1i1I1i . action ]
   o00O = lisp . bold ( o00O , False )
   print ( "  Empty, map-reply action: {}" . format ( o00O ) )
   if 69 - 69: oO0o % I1Ii111 - o0oOOo0O0Ooo + I1Ii111 - O0 % OoooooooOO
   if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
  ii1i1I1i . print_record ( "" , False )
  for iii11 in range ( ii1i1I1i . rloc_count ) :
   O0oo0OO0oOOOo = lisp . lisp_rloc_record ( )
   packet = O0oo0OO0oOOOo . decode ( packet , nonce )
   if ( packet == None ) : break
   i1i1i11IIi = O0oo0OO0oOOOo . priority
   II1III = O0oo0OO0oOOOo . mpriority
   print ( "  RLOC: {}, up/uw/mp/mw: {}/{}/{}/{}, flags: {}{}{}" . format ( O0oo0OO0oOOOo . rloc . print_address_no_iid ( ) , i1i1i11IIi , O0oo0OO0oOOOo .
   # Ii1I + oO0o
 weight , II1III , O0oo0OO0oOOOo . mweight , O0oo0OO0oOOOo . print_flags ( ) ,
 "" if O0oo0OO0oOOOo . rloc_name == None else ", " + O0oo0OO0oOOOo . print_rloc_name ( ) ,
   # o0oOOo0O0Ooo / OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
 ", RTR" if i1i1i11IIi == 254 and II1III == 255 else "" ) )
   if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
   if ( O0oo0OO0oOOOo . geo ) :
    print ( "        geo: {}" . format ( O0oo0OO0oOOOo . geo . print_geo ( ) ) )
    if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
   if ( O0oo0OO0oOOOo . elp ) :
    O0O0O = O0oo0OO0oOOOo . elp . print_elp ( False )
    print ( "        elp: {}" . format ( O0O0O ) )
    if 83 - 83: I1ii11iIi11i / ooOoO0o
   if ( O0oo0OO0oOOOo . rle ) :
    iIIIIii1 = O0oo0OO0oOOOo . rle . print_rle ( False , True )
    print ( "        rle: {}" . format ( iIIIIii1 ) )
    if 58 - 58: i11iIiiIii % I11i
   if ( O0oo0OO0oOOOo . json ) :
    OO00Oo = O0oo0OO0oOOOo . json . print_json ( False )
    print ( "        json: {}" . format ( OO00Oo ) )
    if 51 - 51: IiII * o0oOOo0O0Ooo + I11i + OoO0O00
   O0oo0OO0oOOOo . print_record ( "  " )
   if 66 - 66: OoOoOO00
  print ( "" )
  if 97 - 97: oO0o % IiII * IiII
 return
 if 39 - 39: Ii1I % IiII
 if 4 - 4: oO0o
 if 93 - 93: OoO0O00 % oO0o . OoO0O00 * I1Ii111 % Ii1I . II111iiii
 if 38 - 38: o0oOOo0O0Ooo
 if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
def i11iIIIIIi1 ( lisp_sockets ) :
 for iiII1i1 in lisp_sockets :
  if ( iiII1i1 == None ) : continue
  o00oOO0o = "/tmp/lisp-lig" if ( iiII1i1 == OOO00O ) else ""
  lisp . lisp_close_socket ( iiII1i1 , o00oOO0o )
  if 84 - 84: oO0o * OoO0O00 / I11i - O0
 return
 if 30 - 30: iIii1I11I1II1 / ooOoO0o - I1Ii111 - II111iiii % iII111i
 if 49 - 49: I1IiiI % ooOoO0o . ooOoO0o . I11i * ooOoO0o
 if 97 - 97: Ii1I + o0oOOo0O0Ooo . OOooOOo + I1ii11iIi11i % iII111i
 if 95 - 95: i1IIi
 if 3 - 3: I1Ii111 - O0 / I1Ii111 % OoO0O00 / I1Ii111 . I1IiiI
 if 50 - 50: IiII
 if 14 - 14: I11i % OoO0O00 * I11i
iII = len ( sys . argv )
oO00o0 = ""
I1Ii = ""
OOoo0O = ""
Oo0ooOo0o = ""
Ii1i1 = ( "pubsub" in sys . argv )
if 15 - 15: II111iiii
if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
if 91 - 91: O0
if 61 - 61: II111iiii
if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
if ( iII == 2 ) :
 oO00o0 = sys . argv [ 1 ]
 O0oOoOOOoOO = ( oO00o0 . find ( "[" ) != - 1 and oO00o0 . find ( "]" ) != - 1 )
 O0OoOoo00o , I1Ii = o000o0o00o0Oo ( )
 if ( O0OoOoo00o == None ) :
  iII = 1
 elif ( O0oOoOOOoOO == False ) :
  oO00o0 = "[" + O0OoOoo00o + "]" + oO00o0
  if 38 - 38: I1Ii111
  if 7 - 7: O0 . iII111i % I1ii11iIi11i - I1IiiI - iIii1I11I1II1
if ( iII <= 1 ) :
 while ( oO00o0 == "" ) :
  oO00o0 = input ( "Enter destination EID (or S->G): " )
  if 36 - 36: IiII % ooOoO0o % Oo0Ooo - I1ii11iIi11i
 while ( I1Ii == "" ) :
  I1Ii = input ( "Enter map-resolver address: " )
  if 22 - 22: iIii1I11I1II1 / Oo0Ooo * I1ii11iIi11i % iII111i
 while ( Oo0ooOo0o == "" ) :
  Oo0ooOo0o = input ( "Enter map-request tries (1-5): " )
  if ( Oo0ooOo0o < 1 and Oo0ooOo0o > 5 ) : Oo0ooOo0o = ""
  if 85 - 85: oO0o % i11iIiiIii - iII111i * OoooooooOO / I1IiiI % I1IiiI
 OOoo0O = input ( "Enter optional source EID: " )
else :
 if ( oO00o0 == "" ) : oO00o0 = sys . argv [ 1 ]
 if ( "source" in sys . argv ) :
  IIiIi1iI = sys . argv . index ( "source" )
  if ( IIiIi1iI + 1 < iII ) : OOoo0O = sys . argv [ IIiIi1iI + 1 ]
  if 35 - 35: Ii1I % O0 - O0
 if ( "to" in sys . argv ) :
  IIiIi1iI = sys . argv . index ( "to" )
  if ( IIiIi1iI + 1 < iII ) : I1Ii = sys . argv [ IIiIi1iI + 1 ]
  if 16 - 16: II111iiii % OoOoOO00 - II111iiii + Ii1I
 if ( "count" in sys . argv ) :
  IIiIi1iI = sys . argv . index ( "count" )
  if ( IIiIi1iI + 1 < iII ) :
   Oo0ooOo0o = sys . argv [ IIiIi1iI + 1 ]
   if ( Oo0ooOo0o . isdigit ( ) == False ) : I1Ii = ""
   if 12 - 12: OOooOOo / OOooOOo + i11iIiiIii
   if 40 - 40: I1IiiI . iIii1I11I1II1 / I1IiiI / i11iIiiIii
 if ( I1Ii == "" ) :
  print ( "Usage: lig [<iid>]<dest-eid> to <mr-rloc> " + "[source <source-eid>] [count <1-5>] [debug] [no-info]" )
  if 75 - 75: I11i + o0oOOo0O0Ooo
  exit ( 1 )
  if 84 - 84: IiII . i11iIiiIii . IiII * I1ii11iIi11i - I11i
  if 42 - 42: i11iIiiIii
  if 33 - 33: iII111i - O0 * i1IIi * o0oOOo0O0Ooo - Oo0Ooo
  if 32 - 32: OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
  if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
  if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
III1IiiI = None
if ( oO00o0 . find ( "->" ) != - 1 ) :
 III1IiiI = oO00o0 . split ( "->" )
 oO00o0 = III1IiiI [ 1 ]
 III1IiiI = III1IiiI [ 0 ]
 if 31 - 31: o0oOOo0O0Ooo . I1IiiI
 if 46 - 46: iII111i
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
O0oOoOOOoOO = ( oO00o0 . find ( "[" ) != - 1 and oO00o0 . find ( "]" ) != - 1 )
O0OoOoo00o = 0
if ( O0oOoOOOoOO ) :
 O0OoOoo00o = oO00o0 . split ( "]" )
 oO00o0 = O0OoOoo00o [ 1 ]
 if ( oO00o0 == "" ) :
  print ( "No destination EID specified" )
  exit ( 1 )
  if 41 - 41: Ii1I - O0 - O0
 O0OoOoo00o = O0OoOoo00o [ 0 ]
 O0OoOoo00o = int ( O0OoOoo00o [ 1 : : ] )
 if 68 - 68: OOooOOo % I1Ii111
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
 if 23 - 23: O0
o00oO0oOo00 = ( oO00o0 [ 0 ] == "'" or oO00o0 [ - 1 ] == "'" )
oO0oOo0 = [ "-N" , "-S" , "-E" , "-W" ]
I1I1I = False
for OoOO000 in oO0oOo0 :
 if ( OoOO000 in oO00o0 ) : I1I1I = True
 if 14 - 14: IiII - I1ii11iIi11i
 if 11 - 11: II111iiii * II111iiii % iIii1I11I1II1 * I1Ii111 + OoOoOO00 / I1IiiI
if ( o00oO0oOo00 == False and I1I1I == False and O0oOoOOOoOO == False ) :
 ii1Ii11I = lisp . lisp_gethostbyname ( oO00o0 )
 if ( ii1Ii11I == "" ) :
  print ( "Cannot resolve EID name '{}'" . format ( oO00o0 ) )
  exit ( 1 )
  if 80 - 80: II111iiii
 oO00o0 = ii1Ii11I
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 if 53 - 53: II111iiii
i1Ii1Ii = lisp . lisp_gethostbyname ( I1Ii )
if ( i1Ii1Ii == "" ) :
 print ( "Cannot resolve Map-Resolver name '{}'" . format ( I1Ii ) )
 exit ( 1 )
 if 52 - 52: OoO0O00 . oO0o
I1Ii = i1Ii1Ii
if 25 - 25: O0 - O0 * o0oOOo0O0Ooo
if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
if 82 - 82: Ii1I
lisp . lisp_debug_logging = True if "debug" in sys . argv else False
if 46 - 46: OoooooooOO . i11iIiiIii
if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
if 87 - 87: Oo0Ooo . IiII
if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
if ( Oo0ooOo0o == "" ) : Oo0ooOo0o = "1"
if 55 - 55: OOooOOo . I1IiiI
lisp . lisp_i_am ( "lig" )
if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
if 100 - 100: I1Ii111 * O0
if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
if 79 - 79: O0
Ii11Ii11I = str ( o0oO0 )
if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
if 57 - 57: OoO0O00 / ooOoO0o
if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
if 13 - 13: Ii1I . i11iIiiIii
if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
OOO00O = lisp . lisp_open_listen_socket ( "" , "/tmp/lisp-lig" )
if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
Oo0O0oooo = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
oooO0oo0oOOOO = lisp . lisp_open_listen_socket ( Oo0O0oooo , Ii11Ii11I )
oooO0oo0oOOOO . settimeout ( 2 )
try :
 i1I1ii1II1iII = lisp . lisp_open_listen_socket ( Oo0O0oooo ,
 str ( lisp . LISP_CTRL_PORT ) )
 I111iI = [ oooO0oo0oOOOO , i1I1ii1II1iII ,
 OOO00O ]
except :
 I111iI = [ oooO0oo0oOOOO , OOO00O ]
 if 56 - 56: I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
O0oO [ 0 ] = oooO0oo0oOOOO
O0oO [ 1 ] = oooO0oo0oOOOO
O0oO [ 2 ] = OOO00O
if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
if 63 - 63: OoOoOO00 * iII111i
if 69 - 69: O0 . OoO0O00
if 49 - 49: I1IiiI - I11i
OoOOoOooooOOo = lisp . lisp_map_request ( )
OoOOoOooooOOo . record_count = 1
OoOOoOooooOOo . subscribe_bit = Ii1i1
OoOOoOooooOOo . xtr_id_present = Ii1i1
OoOOoOooooOOo . nonce = 0xdfdf0e1d10c10000 + random . randint ( 0 , 65535 )
if ( o00oO0oOo00 ) :
 oOo0O = lisp . LISP_AFI_NAME
 oo0O0 = len ( oO00o0 ) * 8
elif ( oO00o0 . find ( ":" ) != - 1 ) :
 oOo0O = lisp . LISP_AFI_IPV6
 oo0O0 = 128
elif ( oO00o0 . find ( "." ) != - 1 ) :
 oOo0O = lisp . LISP_AFI_IPV4
 oo0O0 = 32
elif ( I1I1I ) :
 oOo0O = lisp . LISP_AFI_GEO_COORD
 oo0O0 = len ( oO00o0 ) * 8
elif ( oO00o0 . find ( "-" ) != - 1 ) :
 oOo0O = lisp . LISP_AFI_MAC
 oo0O0 = 48
else :
 print ( "Invalid EID address {}" . format ( oO00o0 ) )
 i11iIIIIIi1 ( O0oO )
 exit ( 1 )
 if 22 - 22: OoOoOO00 . OOooOOo * OoOoOO00
 if 54 - 54: IiII + Ii1I % OoO0O00 + OoooooooOO - O0 - o0oOOo0O0Ooo
if ( lisp . lisp_valid_address_format ( "address" , oO00o0 ) == False ) :
 print ( "Invalid address syntax '{}'" . format ( oO00o0 ) )
 i11iIIIIIi1 ( O0oO )
 exit ( 1 )
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
 if 71 - 71: Oo0Ooo % OOooOOo
OoOOoOooooOOo . target_eid = lisp . lisp_address ( oOo0O , "" , oo0O0 , O0OoOoo00o )
if ( III1IiiI ) :
 OoOOoOooooOOo . target_eid . store_address ( III1IiiI )
 OoOOoOooooOOo . target_group . store_address ( oO00o0 )
 O00oO000O0O = OoOOoOooooOOo . target_eid . print_sg ( OoOOoOooooOOo . target_group )
else :
 OoOOoOooooOOo . target_eid . store_address ( oO00o0 )
 O00oO000O0O = OoOOoOooooOOo . target_eid . print_address ( )
 if 18 - 18: iII111i - OOooOOo . I1Ii111 . iIii1I11I1II1
 if 2 - 2: OOooOOo . OoO0O00
 if 78 - 78: I11i * iIii1I11I1II1 . I1IiiI / o0oOOo0O0Ooo - OoooooooOO / I1Ii111
 if 35 - 35: I11i % OOooOOo - oO0o
 if 20 - 20: i1IIi - ooOoO0o
if ( OOoo0O == "" ) :
 OoOOoOooooOOo . source_eid . afi = lisp . LISP_AFI_NONE
else :
 i1iI = lisp . lisp_gethostbyname ( OOoo0O )
 if ( i1iI == "" ) :
  print ( "Cannot resolve source EID name '{}'" . format ( OOoo0O ) )
  exit ( 1 )
  if 94 - 94: iIii1I11I1II1 / Oo0Ooo % iII111i * iII111i * II111iiii
 OOoo0O = i1iI
 OoOOoOooooOOo . source_eid . afi = lisp . LISP_AFI_IPV6 if OOoo0O . count ( ":" ) == 7 else lisp . LISP_AFI_IPV4
 if 29 - 29: OoO0O00 + OoOoOO00 / o0oOOo0O0Ooo / OOooOOo * iIii1I11I1II1
 OoOOoOooooOOo . source_eid . store_address ( OOoo0O )
 OoOOoOooooOOo . source_eid . instance_id = OoOOoOooooOOo . target_eid . instance_id
 if 62 - 62: OOooOOo / oO0o - OoO0O00 . I11i
 if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
 if 76 - 76: IiII * iII111i
if ( OoOOoOooooOOo . source_eid . is_ipv6 ( ) and OOoo0O != "" ) :
 OoOOoOooooOOo . signature_eid = OoOOoOooooOOo . source_eid
 OoOOoOooooOOo . privkey_filename = "./lisp-lig.pem"
 if 52 - 52: OOooOOo
 if 19 - 19: I1IiiI
 if 25 - 25: Ii1I / ooOoO0o
 if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 if 71 - 71: I1Ii111 . II111iiii
oo0 = lisp . lisp_control_header ( )
oOOOoo00 = lisp . lisp_map_reply ( )
iiIiIIIiiI = lisp . lisp_map_notify ( None )
if ( I1Ii . find ( ":" ) != - 1 ) :
 oOo0O = lisp . LISP_AFI_IPV6
 oo0O0 = 128
elif ( I1Ii . find ( "." ) != - 1 ) :
 oOo0O = lisp . LISP_AFI_IPV4
 oo0O0 = 32
else :
 print ( "Invalid Map-Resolver address {}" . format ( I1Ii ) )
 i11iIIIIIi1 ( O0oO )
 exit ( 1 )
 if 12 - 12: O0 - o0oOOo0O0Ooo
I1Ii = lisp . lisp_address ( oOo0O , I1Ii , oo0O0 , 0 )
if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
if 73 - 73: I11i % i11iIiiIii - I1IiiI
if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
if 23 - 23: i11iIiiIii
II1iIi11 = None
I11iiii = lisp . lisp_get_local_rloc ( )
if 60 - 60: I11i . i1IIi + IiII / o0oOOo0O0Ooo . II111iiii
if ( I11iiii == None ) :
 print ( "Cannot obtain a local address" )
 i11iIIIIIi1 ( O0oO )
 exit ( 1 )
 if 82 - 82: I1ii11iIi11i / I1IiiI % iIii1I11I1II1 / i1IIi - I1IiiI
I1III1111iIi = lisp . LISP_CTRL_PORT
if 38 - 38: iII111i + I11i / I1Ii111 % ooOoO0o - I1ii11iIi11i
if ( I11iiii != None and I11iiii . is_private_address ( ) and
 "no-info" not in sys . argv ) :
 print ( "Possible NAT in path, sending Info-Request ... " )
 if 14 - 14: oO0o / I1Ii111
 ooo0O0o00O = lisp . lisp_convert_4to6 ( I1Ii . print_address_no_iid ( ) )
 lisp . lisp_send_info_request ( O0oO , ooo0O0o00O , lisp . LISP_CTRL_PORT , None )
 if 48 - 48: ooOoO0o / I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / i1IIi
 if 92 - 92: Oo0Ooo % Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
 if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
 if 42 - 42: I1IiiI
 O00 , i11I1 , Ii11Ii11I , iI11i1I1 = lisp . lisp_receive ( oooO0oo0oOOOO ,
 False )
 if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
 if ( i11I1 != "" ) :
  oo0 = lisp . lisp_control_header ( )
  if ( oo0 . decode ( iI11i1I1 ) == None or oo0 . info_reply == False ) :
   i11I1 = ""
   if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
   if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
   if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
   if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
   if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
   if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
 if ( i11I1 == "" ) :
  print ( "No Info-Reply received" )
  i11iIIIIIi1 ( O0oO )
  exit ( 1 )
  if 79 - 79: O0 * i11iIiiIii - IiII / IiII
  if 48 - 48: O0
 II1iIi11 , Oo0o0O00 , ii1I1i11 = lisp . lisp_process_info_reply ( None , iI11i1I1 , False )
 if 51 - 51: OoO0O00 . I1IiiI * ooOoO0o % Ii1I + II111iiii . ooOoO0o
 if 50 - 50: OoO0O00 * OOooOOo % O0
 if ( II1iIi11 == None ) :
  Ooo0O0oooo = iiI = "?"
 else :
  Ooo0O0oooo = II1iIi11 . print_address_no_iid ( )
  iiI = str ( Oo0o0O00 )
  if 56 - 56: Oo0Ooo . I1ii11iIi11i . I1IiiI
 print ( "Info-Reply received, public address {}, translated port {}\n" . format ( Ooo0O0oooo , iiI ) )
 if 39 - 39: O0 + I1Ii111
 if 91 - 91: OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoOoOO00 + O0
 I1III1111iIi = o0oO0
 if 26 - 26: I1ii11iIi11i - OoooooooOO
elif ( i1I1ii1II1iII != None ) :
 if 11 - 11: I1IiiI * oO0o
 if 81 - 81: iII111i + IiII
 if 98 - 98: I1IiiI
 if 95 - 95: ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 if 41 - 41: i1IIi - I11i - Ii1I
 if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
 if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
 if 44 - 44: II111iiii
 if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
 if 35 - 35: iIii1I11I1II1
 if 42 - 42: I1Ii111 . I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI
 O0oO [ 0 ] = i1I1ii1II1iII
 O0oO [ 1 ] = i1I1ii1II1iII
 if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
 if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
 if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
 if 71 - 71: O0 - iIii1I11I1II1
 if 12 - 12: OOooOOo / o0oOOo0O0Ooo
if ( II1iIi11 == None ) :
 iiI1I1 = I11iiii . print_address_no_iid ( )
 ooO = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , iiI1I1 , 32 , 0 )
else :
 ooO = II1iIi11
 o0oO0 = Oo0o0O00
 if 6 - 6: iIii1I11I1II1 . ooOoO0o % o0oOOo0O0Ooo
OoOOoOooooOOo . itr_rlocs . append ( ooO )
if 50 - 50: iII111i + O0 + Ii1I . II111iiii / o0oOOo0O0Ooo
if 17 - 17: Ii1I % iIii1I11I1II1 - iIii1I11I1II1
if 78 - 78: iII111i + I11i . ooOoO0o - iII111i . Ii1I
if 30 - 30: I1IiiI + OoO0O00 % Ii1I * iII111i / Oo0Ooo - I11i
iI11i1I1 = OoOOoOooooOOo . encode ( None , 0 )
if ( iI11i1I1 == None ) :
 print ( "Could not sign Map-Request" )
 i11iIIIIIi1 ( O0oO )
 exit ( 1 )
 if 64 - 64: iIii1I11I1II1
OoOOoOooooOOo . print_map_request ( )
if 21 - 21: Oo0Ooo . II111iiii
if 54 - 54: II111iiii % II111iiii
if 86 - 86: O0 % Ii1I * ooOoO0o * iIii1I11I1II1 * i1IIi * I11i
if 83 - 83: OoOoOO00 % II111iiii - OoOoOO00 + IiII - O0
if ( III1IiiI ) :
 oO0oo000OOOoO = OoOOoOooooOOo . target_group
 ii1I = OoOOoOooooOOo . target_eid
else :
 oO0oo000OOOoO = OoOOoOooooOOo . target_eid
 ii1I = lisp . lisp_myrlocs [ 1 ] if oO0oo000OOOoO . is_ipv6 ( ) else ooO
 if 58 - 58: I1IiiI + i11iIiiIii % Ii1I . OoOoOO00
 if 13 - 13: i11iIiiIii + i1IIi * iIii1I11I1II1 % OoooooooOO - II111iiii * OOooOOo
iiIi1iI1iIii = iI11i1I1
o00OooO0oo = True
Oo0ooOo0o = int ( Oo0ooOo0o )
if 89 - 89: Ii1I
for oO in range ( Oo0ooOo0o ) :
 iI11i1I1 = iiIi1iI1iIii
 ooOoOO0OoO00o = "subscribe " if Ii1i1 else ""
 print ( "Send lig {}map-request to {} for EID {} ..." . format ( ooOoOO0OoO00o ,
 I1Ii . print_address_no_iid ( ) , O00oO000O0O ) )
 if 11 - 11: Oo0Ooo - I1IiiI * II111iiii . I1ii11iIi11i . oO0o
 if 61 - 61: iII111i % I1IiiI - o0oOOo0O0Ooo - II111iiii % O0
 if 90 - 90: iIii1I11I1II1 + I1ii11iIi11i + ooOoO0o - I1Ii111 * IiII . I1ii11iIi11i
 if 37 - 37: ooOoO0o % i11iIiiIii % II111iiii . O0 . Ii1I
 iI11i1I1 = iiIi1iI1iIii
 lisp . lisp_send_ecm ( O0oO , iI11i1I1 , ii1I , I1III1111iIi ,
 oO0oo000OOOoO , I1Ii )
 if 51 - 51: OoO0O00 - O0 % oO0o - II111iiii
 if 31 - 31: iII111i / Oo0Ooo - iII111i - OOooOOo
 if 7 - 7: iII111i % O0 . OoOoOO00 + I1IiiI - I11i
 if 75 - 75: I11i
 if 71 - 71: ooOoO0o
 Ooo0o00o0o = time . time ( )
 if 7 - 7: O0 - Oo0Ooo + I1ii11iIi11i + II111iiii + iIii1I11I1II1
 if 58 - 58: o0oOOo0O0Ooo / IiII . OoOoOO00 / OoooooooOO + I1Ii111
 if 86 - 86: I11i * I1IiiI + I11i + II111iiii
 if 8 - 8: I1Ii111 - iII111i / ooOoO0o
 if 96 - 96: OoOoOO00
 O00 , i11I1 , Ii11Ii11I , iI11i1I1 = iIi ( I111iI ,
 oooO0oo0oOOOO , i1I1ii1II1iII , OOO00O )
 if 29 - 29: I1ii11iIi11i / i1IIi . I1IiiI - OoOoOO00 - OoOoOO00 - Ii1I
 if 20 - 20: i1IIi % OoO0O00 . I1IiiI / IiII * i11iIiiIii * OOooOOo
 if 85 - 85: o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . O0 % I1Ii111
 if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
 if ( i11I1 == "" ) : continue
 if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
 if 74 - 74: O0 / i1IIi
 if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
 if 31 - 31: OoooooooOO . OOooOOo
 if ( O00 != "packet" ) :
  print ( "Internal fatal error" )
  continue
  if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
  if 100 - 100: OoO0O00
  if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
  if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
  if 45 - 45: I1Ii111
 if ( oo0 . decode ( iI11i1I1 ) == None ) :
  print ( "Could not decode header" )
  continue
  if 83 - 83: OoOoOO00 . OoooooooOO
  if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if ( oo0 . type not in [ lisp . LISP_MAP_REPLY , lisp . LISP_MAP_NOTIFY ] ) :
  print ( "Expecting Map-Reply/Notify, packet type {} returned" . format ( oo0 . type ) )
  if 62 - 62: OoO0O00 / I1ii11iIi11i
  continue
  if 7 - 7: OoooooooOO . IiII
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 Oooo00 = "map-reply" if oo0 . type == lisp . LISP_MAP_REPLY else "map-notify"
 if 6 - 6: Ii1I - ooOoO0o * OOooOOo . iII111i / O0 * ooOoO0o
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if 92 - 92: I11i . I1Ii111
 oOO00O0Ooooo00 = round ( time . time ( ) - Ooo0o00o0o , 3 )
 print ( "Received {} from {} with rtt {} secs:" . format ( Oooo00 , i11I1 , oOO00O0Ooooo00 ) )
 if ( Oooo00 == "map-reply" ) :
  iI11i1I1 = oOOOoo00 . decode ( iI11i1I1 )
  if ( iI11i1I1 == None ) :
   print ( "Could not decode Map-Reply packet" )
   continue
   if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
  o00OooO0oo = False
  oOOOoo00 . print_map_reply ( )
  I1i1I1II ( oOOOoo00 . record_count , oOOOoo00 . nonce , iI11i1I1 )
 else :
  iI11i1I1 = iiIiIIIiiI . decode ( iI11i1I1 )
  if ( iI11i1I1 == None ) :
   print ( "Could not decode Map-Notify packet" )
   continue
   if 18 - 18: iIii1I11I1II1 % I11i
  o00OooO0oo = False
  iiIiIIIiiI . print_notify ( )
  I1i1I1II ( iiIiIIIiiI . record_count , iiIiIIIiiI . nonce , iI11i1I1 )
  if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
  if 75 - 75: OoooooooOO * IiII
  if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
  if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
  if 69 - 69: O0
  if 85 - 85: ooOoO0o / O0
if ( o00OooO0oo ) : print ( "*** No reply received ***" )
if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
if 62 - 62: I1Ii111 . IiII . OoooooooOO
if 11 - 11: OOooOOo / I11i
if 73 - 73: i1IIi / i11iIiiIii
if ( Ii1i1 ) :
 iiIiIIIiiI = lisp . lisp_map_notify ( None )
 while ( True ) :
  print ( "Waiting for map-notify EID {} RLOC-set changes ..." . format ( O00oO000O0O ) )
  if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
  if 85 - 85: OoOoOO00 + OOooOOo
  try :
   while ( True ) :
    O00 , i11I1 , Ii11Ii11I , iI11i1I1 = iIi ( I111iI ,
 oooO0oo0oOOOO , i1I1ii1II1iII ,
 OOO00O )
    if ( i11I1 != "" ) : break
    if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
  except :
   break
   if 27 - 27: Ii1I
   if 67 - 67: I1IiiI
  print ( "Received map-notify from map-server {}" . format ( i11I1 ) )
  if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
  iI11i1I1 = iiIiIIIiiI . decode ( iI11i1I1 )
  if ( iI11i1I1 == None ) :
   print ( "Could not decode Map-Reply packet" )
   continue
   if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
   if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
  iiIiIIIiiI . print_notify ( )
  if 92 - 92: Oo0Ooo
  if 40 - 40: OoOoOO00 / IiII
  if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
  if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
  I1i1I1II ( iiIiIIIiiI . record_count , iiIiIIIiiI . nonce , iI11i1I1 )
  if 61 - 61: II111iiii
  if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
  if 90 - 90: iII111i
  if 31 - 31: OOooOOo + O0
  iiIiIIIiiI . map_notify_ack = True
  iiIiIIIiiI . print_notify ( )
  iI11i1I1 = iiIiIIIiiI . encode ( iiIiIIIiiI . eid_records , None )
  ooo0O0o00O = lisp . lisp_convert_4to6 ( i11I1 )
  lisp . lisp_send ( O0oO , ooo0O0o00O , lisp . LISP_CTRL_PORT , iI11i1I1 )
  if 87 - 87: ooOoO0o
  if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
  if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
  if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
  if 13 - 13: Oo0Ooo
  if 60 - 60: I1ii11iIi11i * I1IiiI
i11iIIIIIi1 ( O0oO )
if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
exit ( 1 ) if ( o00OooO0oo ) else exit ( 0 )
if 41 - 41: Ii1I
if 77 - 77: I1Ii111
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
