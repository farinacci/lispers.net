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
lisp . lisp_debug_logging = True if "debug" in sys . argv else False
if 100 - 100: i1IIi
if 27 - 27: IiII * OoooooooOO + I11i * ooOoO0o - i11iIiiIii - iII111i
if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . II111iiii - oO0o
if 72 - 72: II111iiii - OoOoOO00
if 91 - 91: OoO0O00 . i11iIiiIii / oO0o % I11i / OoO0O00 - i11iIiiIii
if 8 - 8: o0oOOo0O0Ooo * I1ii11iIi11i * iIii1I11I1II1 . IiII / IiII % IiII
if 22 - 22: Ii1I . IiII
if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
if 74 - 74: iII111i * IiII
if 82 - 82: iIii1I11I1II1 % IiII
def oOo0oooo00o ( ) :
 oO0o0o0ooO0oO = getoutput ( 'egrep "decentralized-pull-xtr-modulus = " ./lisp.config' )
 oO0o0o0ooO0oO = oO0o0o0ooO0oO . split ( ) if oO0o0o0ooO0oO != "" else [ ]
 if ( oO0o0o0ooO0oO == [ ] ) : return ( False )
 if 52 - 52: II111iiii - i11iIiiIii % I1Ii111
 O0OoOoo00o = int ( oO0o0o0ooO0oO [ - 1 ] )
 if ( O0OoOoo00o == 0 ) : return ( False )
 if 31 - 31: II111iiii + OoO0O00 . I1Ii111
 OoOooOOOO = getoutput ( 'egrep "decentralized-pull-xtr-dns-suffix = " ./lisp.config' )
 OoOooOOOO = OoOooOOOO . split ( ) if OoOooOOOO != "" else [ ]
 if ( OoOooOOOO == [ ] ) : return ( False )
 if 45 - 45: I1Ii111 + Ii1I
 lisp . lisp_decent_modulus = O0OoOoo00o
 lisp . lisp_decent_dns_suffix = OoOooOOOO [ - 1 ]
 if 17 - 17: o0oOOo0O0Ooo
 if 64 - 64: Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
 if 78 - 78: OoO0O00
 Iii1I111 = open ( "./lisp.config" , "r" ) ; OO0O0O00OooO = Iii1I111 . read ( ) ; Iii1I111 . close ( )
 OoooooOoo = OO0O0O00OooO . split ( "\n" )
 OO = 0
 if 55 - 55: OoO0O00 / I1ii11iIi11i * OOooOOo
 while OO < len ( OoooooOoo ) :
  OoO000 = OoooooOoo [ OO ]
  if ( OoO000 . find ( "lisp decent-prefix {" ) == - 1 ) :
   OO += 1
   continue
   if 42 - 42: oO0o - i1IIi / i11iIiiIii + OOooOOo + OoO0O00
   if 17 - 17: oO0o . Oo0Ooo . I1ii11iIi11i
  while ( OoO000 . find ( "}" ) == - 1 ) :
   IIi = 0
   if ( OoO000 . find ( "instance-id" ) != - 1 ) :
    IIi = int ( OoO000 . split ( ) [ - 1 ] )
    if 38 - 38: Ii1I / Oo0Ooo
   if ( OoO000 . find ( "eid-prefix" ) != - 1 ) :
    OooO0 = OoO000 . split ( " = " ) [ - 1 ]
    if 35 - 35: OOooOOo % I1Ii111 % i11iIiiIii / OoooooooOO
   if ( OoO000 . find ( "lookup-length" ) != - 1 ) :
    Ii11iI1i = OoO000 . split ( " = " ) [ - 1 ]
    if 82 - 82: i11iIiiIii . OOooOOo / Oo0Ooo * O0 % oO0o % iIii1I11I1II1
   OO += 1
   OoO000 = OoooooOoo [ OO ]
   if 78 - 78: iIii1I11I1II1 - Ii1I * OoO0O00 + o0oOOo0O0Ooo + iII111i + iII111i
   if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
  o0o0oOOOo0oo = lisp . lisp_address ( lisp . LISP_AFI_NONE , "" , 0 , 0 )
  o0o0oOOOo0oo . store_prefix ( OooO0 )
  o0o0oOOOo0oo . instance_id = IIi
  lisp . lisp_decent_lookup_prefixes [ o0o0oOOOo0oo ] = int ( Ii11iI1i )
  if 80 - 80: I11i * i11iIiiIii / I1Ii111
 return ( True )
 if 9 - 9: Ii1I + oO0o % Ii1I + i1IIi . OOooOOo
 if 31 - 31: o0oOOo0O0Ooo + I11i + I11i / II111iiii
 if 26 - 26: OoooooooOO
 if 12 - 12: OoooooooOO % OoOoOO00 / ooOoO0o % o0oOOo0O0Ooo
 if 29 - 29: OoooooooOO
 if 23 - 23: o0oOOo0O0Ooo . II111iiii
 if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
 if 45 - 45: I1Ii111 . OoOoOO00
def oO ( iid , eid_str ) :
 o0o0oOOOo0oo = lisp . lisp_address ( lisp . LISP_AFI_NONE , eid_str , 0 , iid )
 if 6 - 6: I1ii11iIi11i
 I1I = lisp . lisp_get_decent_eid_string ( o0o0oOOOo0oo )
 oOO00oOO = lisp . lisp_get_decent_dns_name ( o0o0oOOOo0oo )
 return ( oOO00oOO , I1I )
 if 75 - 75: i1IIi / OoooooooOO - O0 / OoOoOO00 . II111iiii - i1IIi
 if 71 - 71: OOooOOo + Ii1I * OOooOOo - OoO0O00 * o0oOOo0O0Ooo
 if 65 - 65: O0 % I1IiiI . I1ii11iIi11i % iIii1I11I1II1 / OOooOOo % I1Ii111
 if 51 - 51: i11iIiiIii . I1IiiI + II111iiii
 if 10 - 10: I1ii11iIi11i * ooOoO0o * II111iiii % Ii1I . OOooOOo + I1Ii111
 if 19 - 19: OoOoOO00 - I1IiiI . OOooOOo / IiII
 if 33 - 33: I1Ii111 / I1ii11iIi11i % I1IiiI + ooOoO0o / OoO0O00
 if 52 - 52: o0oOOo0O0Ooo - OoooooooOO + Ii1I + Ii1I - o0oOOo0O0Ooo / I1Ii111
def I1IiIi11Ii1 ( ) :
 if ( os . path . exists ( "./lisp.config" ) == False ) : return ( None , None , None )
 if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
 if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
 if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 if 58 - 58: i11iIiiIii % I11i
 IIi = getoutput ( 'egrep "instance-id = " ./lisp.config' )
 if ( IIi == "" ) : return ( None , None )
 IIi = IIi . split ( "\n" ) [ 0 ]
 IIi = IIi . split ( " = " ) [ - 1 ]
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
 if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
 if 16 - 16: I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
 i1I11i1iI = getoutput ( 'egrep -A1 "lisp map-resolver {" ./lisp.config' )
 if ( i1I11i1iI == "" ) : return ( None , None )
 i1I11i1iI = i1I11i1iI . split ( "\n" ) [ - 1 ]
 if ( i1I11i1iI . find ( "dns-name" ) == - 1 and i1I11i1iI . find ( "address" ) == - 1 ) :
  return ( None , None )
  if 15 - 15: Ii1I - O0 / oO0o * i1IIi
 i1I11i1iI = i1I11i1iI . split ( " = " ) [ - 1 ]
 if 92 - 92: OoOoOO00
 return ( IIi , i1I11i1iI )
 if 26 - 26: iII111i . I1Ii111
 if 68 - 68: OoO0O00
 if 35 - 35: OoO0O00 - iII111i / Oo0Ooo / OoOoOO00
 if 24 - 24: ooOoO0o - ooOoO0o / II111iiii - I1ii11iIi11i
 if 69 - 69: oO0o . I1Ii111 + Ii1I / Oo0Ooo - oO0o
 if 63 - 63: OOooOOo % oO0o * oO0o * OoO0O00 / I1ii11iIi11i
 if 74 - 74: II111iiii
def oO0 ( socket_list , lisp_ephem_listen_socket , lisp_listen_socket ,
 lisp_ipc_socket ) :
 if 54 - 54: II111iiii % OoOoOO00 % I11i % iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
 O00O0oOO00O00 , i1 , Oo00 = select . select ( socket_list , [ ] , [ ] , 2 )
 if 31 - 31: I1Ii111 . OoOoOO00 / O0
 if ( lisp_ephem_listen_socket in O00O0oOO00O00 ) :
  o000O0o , iI1iII1 , oO0OOoo0OO , O0ii1ii1ii = lisp . lisp_receive ( lisp_ephem_listen_socket , False )
  if 91 - 91: IiII
 elif ( lisp_listen_socket in O00O0oOO00O00 ) :
  o000O0o , iI1iII1 , oO0OOoo0OO , O0ii1ii1ii = lisp . lisp_receive ( lisp_listen_socket ,
 False )
 elif ( lisp_ipc_socket in O00O0oOO00O00 ) :
  o000O0o , iI1iII1 , oO0OOoo0OO , O0ii1ii1ii = lisp . lisp_receive ( lisp_ipc_socket ,
 True )
 else :
  return ( "" , "" , 0 , None )
  if 15 - 15: II111iiii
 return ( o000O0o , iI1iII1 , oO0OOoo0OO , O0ii1ii1ii )
 if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
 if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
 if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
 if 61 - 61: II111iiii
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
def iIIi1i1 ( record_count , nonce , packet ) :
 if 10 - 10: I11i
 for OOooOO000 in range ( record_count ) :
  OOoOoo = lisp . lisp_eid_record ( )
  packet = OOoOoo . decode ( packet )
  if ( packet == None ) : break
  print ( "EID-prefix: {}, ttl: {}, rloc-set:" . format ( OOoOoo . print_prefix ( ) , OOoOoo . print_ttl ( ) ) )
  if 85 - 85: I1ii11iIi11i % iII111i % ooOoO0o
  if 82 - 82: i11iIiiIii - iII111i * OoooooooOO / I11i
  if ( OOoOoo . rloc_count == 0 ) :
   i1oOo = lisp . lisp_map_reply_action_string [ OOoOoo . action ]
   i1oOo = lisp . bold ( i1oOo , False )
   print ( "  Empty, map-reply action: {}" . format ( i1oOo ) )
   if 75 - 75: I1IiiI + Oo0Ooo
   if 73 - 73: O0 - OoooooooOO . OOooOOo - OOooOOo / OoOoOO00
  OOoOoo . print_record ( "" , False )
  for iiIi1I1iIIi in range ( OOoOoo . rloc_count ) :
   iii = lisp . lisp_rloc_record ( )
   packet = iii . decode ( packet , nonce )
   if ( packet == None ) : break
   II1I = iii . priority
   O0i1II1Iiii1I11 = iii . mpriority
   IIII = lisp . red ( iii . rloc . print_address_no_iid ( ) , False )
   print ( "  RLOC: {}, up/uw/mp/mw: {}/{}/{}/{}, flags: {}{}{}" . format ( IIII , II1I , iii .
   # I1IiiI + OoooooooOO
 weight , O0i1II1Iiii1I11 , iii . mweight , iii . print_flags ( ) ,
 "" if iii . rloc_name == None else ", " + iii . print_rloc_name ( ) ,
   # o0oOOo0O0Ooo . I1IiiI * iII111i % iII111i
 ", RTR" if II1I == 254 and O0i1II1Iiii1I11 == 255 else "" ) )
   if 24 - 24: OoooooooOO
   if ( iii . geo ) :
    print ( "        geo: {}" . format ( iii . geo . print_geo ( ) ) )
    if 61 - 61: OoooooooOO - OoOoOO00 % Ii1I % I1Ii111 + I1ii11iIi11i
   if ( iii . elp ) :
    OOooOoooOoOo = iii . elp . print_elp ( False )
    print ( "        elp: {}" . format ( OOooOoooOoOo ) )
    if 84 - 84: IiII
   if ( iii . rle ) :
    OOO00O0O = iii . rle . print_rle ( False , True )
    print ( "        rle: {}" . format ( OOO00O0O ) )
    if 33 - 33: O0 . IiII . I1IiiI
   if ( iii . json ) :
    OoOO = iii . json . print_json ( False )
    print ( "        json: {}" . format ( OoOO ) )
    if 53 - 53: Oo0Ooo
   iii . print_record ( "  " )
   if 29 - 29: I1ii11iIi11i + oO0o % O0
  print ( "" )
  if 10 - 10: I11i / I1Ii111 - I1IiiI * iIii1I11I1II1 - I1IiiI
 return
 if 97 - 97: I1ii11iIi11i + I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
 if 23 - 23: O0
 if 85 - 85: Ii1I
 if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
def IIi1 ( lisp_sockets ) :
 for I1I1I in lisp_sockets :
  if ( I1I1I == None ) : continue
  OoOO000 = "/tmp/lisp-lig" if ( I1I1I == i1Ii11i1i ) else ""
  lisp . lisp_close_socket ( I1I1I , OoOO000 )
  if 91 - 91: OoO0O00
 return
 if 95 - 95: I1IiiI + i11iIiiIii
 if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
 if 80 - 80: II111iiii
 if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
 if 53 - 53: II111iiii
 if 31 - 31: OoO0O00
 if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
iIiIIi1 = len ( sys . argv )
I1IIII1i = ""
i1I11i1iI = ""
I1I11i = False
Ii1I1I1i1Ii = ""
i1Oo0oO00o = ""
i11I1II1I11i = ( "pubsub" in sys . argv )
if 61 - 61: I1IiiI - OOooOOo . oO0o / OOooOOo + Oo0Ooo
if 5 - 5: ooOoO0o + ooOoO0o / O0 * Oo0Ooo - OOooOOo % ooOoO0o
if 15 - 15: i11iIiiIii % Ii1I . Oo0Ooo + I1ii11iIi11i
if 61 - 61: Oo0Ooo * I1ii11iIi11i % Oo0Ooo - i1IIi - iIii1I11I1II1
if 74 - 74: I1ii11iIi11i + II111iiii / OoO0O00
if 100 - 100: OoOoOO00 * iIii1I11I1II1
if 86 - 86: OoO0O00 * OOooOOo . iII111i
if ( iIiIIi1 == 2 ) :
 I1IIII1i = sys . argv [ 1 ]
 iI = ( I1IIII1i . find ( "[" ) != - 1 and I1IIII1i . find ( "]" ) != - 1 )
 IIi , i1I11i1iI = I1IiIi11Ii1 ( )
 if ( IIi == None ) :
  iIiIIi1 = 1
 elif ( iI == False ) :
  I1IIII1i = lisp . lisp_gethostbyname ( I1IIII1i )
  I1IIII1i = "[" + IIi + "]" + I1IIII1i
  if 90 - 90: I1Ii111 % Ii1I - iIii1I11I1II1 - iIii1I11I1II1 / i11iIiiIii % I1ii11iIi11i
  if 37 - 37: oO0o - I1IiiI . I11i * Ii1I - iII111i
  if 8 - 8: OoO0O00 - I1IiiI % Ii1I * OoooooooOO - OoO0O00 * I1Ii111
if ( iIiIIi1 <= 1 ) :
 while ( I1IIII1i == "" ) :
  I1IIII1i = input ( "Enter destination EID (or S->G): " )
  if 6 - 6: OoooooooOO
 while ( i1I11i1iI == "" ) :
  i1I11i1iI = input ( "Enter map-resolver address: " )
  I1I11i = True
  if 17 - 17: I1IiiI % I1Ii111
 while ( i1Oo0oO00o == "" ) :
  i1Oo0oO00o = input ( "Enter map-request tries (1-5): " )
  if ( i1Oo0oO00o < 1 and i1Oo0oO00o > 5 ) : i1Oo0oO00o = ""
  if 90 - 90: oO0o / iIii1I11I1II1 - o0oOOo0O0Ooo / OoooooooOO - OoooooooOO * OOooOOo
 Ii1I1I1i1Ii = input ( "Enter optional source EID: " )
else :
 if ( I1IIII1i == "" ) : I1IIII1i = sys . argv [ 1 ]
 if ( "source" in sys . argv ) :
  OO = sys . argv . index ( "source" )
  if ( OO + 1 < iIiIIi1 ) : Ii1I1I1i1Ii = sys . argv [ OO + 1 ]
  if 73 - 73: I1ii11iIi11i * i11iIiiIii % oO0o . I1ii11iIi11i
 if ( "to" in sys . argv ) :
  OO = sys . argv . index ( "to" )
  if ( OO + 1 < iIiIIi1 ) :
   i1I11i1iI = sys . argv [ OO + 1 ]
   I1I11i = True
   if 66 - 66: oO0o + oO0o + ooOoO0o / iII111i + OOooOOo
   if 30 - 30: O0
 if ( "count" in sys . argv ) :
  OO = sys . argv . index ( "count" )
  if ( OO + 1 < iIiIIi1 ) :
   i1Oo0oO00o = sys . argv [ OO + 1 ]
   if ( i1Oo0oO00o . isdigit ( ) == False ) :
    i1I11i1iI = ""
    I1I11i = False
    if 44 - 44: oO0o / I11i / I11i
    if 87 - 87: Oo0Ooo . I1IiiI - II111iiii + O0 / Oo0Ooo / oO0o
    if 25 - 25: I1IiiI . I1IiiI - OoOoOO00 % OoOoOO00 - i11iIiiIii / I1Ii111
 if ( i1I11i1iI == "" ) :
  print ( "Usage: lig [<iid>]<dest-eid> to <mr-rloc> " + "[source <source-eid>] [count <1-5>] [debug] [no-info]" )
  if 51 - 51: Oo0Ooo / OoOoOO00 . OOooOOo * o0oOOo0O0Ooo + OoO0O00 * IiII
  exit ( 1 )
  if 73 - 73: OoO0O00 + OoooooooOO - O0 - Ii1I - II111iiii
  if 99 - 99: ooOoO0o . Ii1I + I1Ii111 + OoooooooOO % o0oOOo0O0Ooo
  if 51 - 51: iIii1I11I1II1
  if 34 - 34: oO0o + I1IiiI - oO0o
  if 17 - 17: II111iiii % iII111i + I11i - iII111i / OOooOOo + ooOoO0o
  if 59 - 59: OOooOOo % OoOoOO00 . Ii1I * I1ii11iIi11i % I11i
oO0o0o0oo = None
if ( I1IIII1i . find ( "->" ) != - 1 ) :
 oO0o0o0oo = I1IIII1i . split ( "->" )
 I1IIII1i = oO0o0o0oo [ 1 ]
 oO0o0o0oo = oO0o0o0oo [ 0 ]
 if 32 - 32: OOooOOo
 if 42 - 42: IiII * O0 % i1IIi . OOooOOo / o0oOOo0O0Ooo
 if 32 - 32: I1IiiI * Oo0Ooo
 if 78 - 78: OOooOOo - OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii
 if 29 - 29: I1IiiI % I1IiiI
iI = ( I1IIII1i . find ( "[" ) != - 1 and I1IIII1i . find ( "]" ) != - 1 )
IIi = 0
if ( iI ) :
 IIi = I1IIII1i . split ( "]" )
 I1IIII1i = IIi [ 1 ]
 if ( I1IIII1i == "" ) :
  print ( "No destination EID specified" )
  exit ( 1 )
  if 94 - 94: iIii1I11I1II1 / Oo0Ooo % iII111i * iII111i * II111iiii
 IIi = IIi [ 0 ]
 IIi = int ( IIi [ 1 : : ] )
 if 29 - 29: OoO0O00 + OoOoOO00 / o0oOOo0O0Ooo / OOooOOo * iIii1I11I1II1
 if 62 - 62: OOooOOo / oO0o - OoO0O00 . I11i
 if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
I1II1 = ( I1IIII1i [ 0 ] == "'" or I1IIII1i [ - 1 ] == "'" )
oooO = [ "-N" , "-S" , "-E" , "-W" ]
i1I1i111Ii = False
for ooo in oooO :
 if ( ooo in I1IIII1i ) : i1I1i111Ii = True
 if 27 - 27: ooOoO0o % I1IiiI
 if 73 - 73: OOooOOo
if ( I1II1 == False and i1I1i111Ii == False and iI == False ) :
 ooO = lisp . lisp_gethostbyname ( I1IIII1i )
 if ( ooO == "" ) :
  print ( "Cannot resolve EID name '{}'" . format ( I1IIII1i ) )
  exit ( 1 )
  if 51 - 51: I1IiiI % I1Ii111 . oO0o / iIii1I11I1II1 / I11i . oO0o
 I1IIII1i = ooO
 if 42 - 42: o0oOOo0O0Ooo + i1IIi - Ii1I / IiII
 if 9 - 9: O0 % O0 - o0oOOo0O0Ooo
 if 51 - 51: I1IiiI . iIii1I11I1II1 - I1ii11iIi11i / O0
 if 52 - 52: o0oOOo0O0Ooo + O0 + iII111i + Oo0Ooo % iII111i
 if 75 - 75: I1IiiI . ooOoO0o . O0 * I1Ii111
i11II1I11I1 = None
oOO00oOO = None
if ( I1I11i == False ) :
 oO0o0o0ooO0oO = oOo0oooo00o ( )
 if ( oO0o0o0ooO0oO ) :
  oOO00oOO , i11II1I11I1 = oO ( IIi , I1IIII1i )
  i1I11i1iI = oOO00oOO
  if 67 - 67: I1IiiI - o0oOOo0O0Ooo / I11i - i1IIi
  if 1 - 1: II111iiii
  if 68 - 68: iII111i - I1IiiI / I1Ii111 / I11i
I11iiii = lisp . lisp_gethostbyname ( i1I11i1iI )
if ( I11iiii == "" ) :
 print ( "Cannot resolve Map-Resolver name '{}'" . format ( i1I11i1iI ) )
 exit ( 1 )
 if 60 - 60: I11i . i1IIi + IiII / o0oOOo0O0Ooo . II111iiii
i1I11i1iI = I11iiii
if 82 - 82: I1ii11iIi11i / I1IiiI % iIii1I11I1II1 / i1IIi - I1IiiI
if 7 - 7: I1Ii111 * OoO0O00 - ooOoO0o + OOooOOo * I1IiiI % OoO0O00
if 15 - 15: OoOoOO00 % I1IiiI * I11i
if 81 - 81: ooOoO0o - iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * I11i
if ( i1Oo0oO00o == "" ) : i1Oo0oO00o = "1"
if 20 - 20: oO0o % IiII
lisp . lisp_i_am ( "lig" )
if 19 - 19: I1ii11iIi11i % IiII + ooOoO0o / I1Ii111 . ooOoO0o
if 12 - 12: i1IIi + i1IIi - I1ii11iIi11i * Oo0Ooo % Oo0Ooo - II111iiii
if 52 - 52: ooOoO0o . iII111i + I1Ii111
if 38 - 38: i1IIi - II111iiii . I1Ii111
oO0OOoo0OO = str ( o0oO0 )
if 58 - 58: I1IiiI . iII111i + OoOoOO00
if 66 - 66: iII111i / oO0o * OoooooooOO + OoooooooOO % I11i
if 49 - 49: oO0o - i11iIiiIii . I1Ii111 * Ii1I % iII111i + i1IIi
if 71 - 71: o0oOOo0O0Ooo
if 38 - 38: oO0o % OoOoOO00 + I1ii11iIi11i . i11iIiiIii
if 53 - 53: i11iIiiIii * iII111i
if 68 - 68: iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
i1Ii11i1i = lisp . lisp_open_listen_socket ( "" , "/tmp/lisp-lig" )
if 38 - 38: ooOoO0o - OOooOOo / iII111i
OoOOoooOO0O = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
oooO0oo0oOOOO = lisp . lisp_open_listen_socket ( OoOOoooOO0O , oO0OOoo0OO )
oooO0oo0oOOOO . settimeout ( 2 )
try :
 i1I1ii1II1iII = lisp . lisp_open_listen_socket ( OoOOoooOO0O ,
 str ( lisp . LISP_CTRL_PORT ) )
 ooo00Ooo = [ oooO0oo0oOOOO , i1I1ii1II1iII ,
 i1Ii11i1i ]
except :
 ooo00Ooo = [ oooO0oo0oOOOO , i1Ii11i1i ]
 if 93 - 93: i11iIiiIii - I1IiiI * I1ii11iIi11i * I11i % O0 + OoooooooOO
 if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
O0oO [ 0 ] = oooO0oo0oOOOO
O0oO [ 1 ] = oooO0oo0oOOOO
O0oO [ 2 ] = i1Ii11i1i
if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
if 19 - 19: OoO0O00 - Oo0Ooo . O0
ooOo00 = lisp . lisp_map_request ( )
ooOo00 . record_count = 1
ooOo00 . subscribe_bit = i11I1II1I11i
ooOo00 . xtr_id_present = i11I1II1I11i
ooOo00 . nonce = 0xdfdf0e1d10c10000 + random . randint ( 0 , 65535 )
ooOo00 . decent_nat_xtr = True
if ( I1II1 ) :
 OOoo = lisp . LISP_AFI_NAME
 iIIiiiI = len ( I1IIII1i ) * 8
elif ( I1IIII1i . find ( ":" ) != - 1 ) :
 OOoo = lisp . LISP_AFI_IPV6
 iIIiiiI = 128
elif ( I1IIII1i . find ( "." ) != - 1 ) :
 OOoo = lisp . LISP_AFI_IPV4
 iIIiiiI = 32
elif ( i1I1i111Ii ) :
 OOoo = lisp . LISP_AFI_GEO_COORD
 iIIiiiI = len ( I1IIII1i ) * 8
elif ( I1IIII1i . find ( "-" ) != - 1 ) :
 OOoo = lisp . LISP_AFI_MAC
 iIIiiiI = 48
else :
 print ( "Invalid EID address {}" . format ( I1IIII1i ) )
 IIi1 ( O0oO )
 exit ( 1 )
 if 60 - 60: I1IiiI . I1Ii111
 if 34 - 34: I1IiiI % iII111i + ooOoO0o * iIii1I11I1II1
if ( lisp . lisp_valid_address_format ( "address" , I1IIII1i ) == False ) :
 print ( "Invalid address syntax '{}'" . format ( I1IIII1i ) )
 IIi1 ( O0oO )
 exit ( 1 )
 if 33 - 33: I1IiiI / ooOoO0o * OOooOOo / I1ii11iIi11i + Oo0Ooo / iII111i
 if 40 - 40: I1ii11iIi11i
 if 60 - 60: I1ii11iIi11i % OoOoOO00 * OoO0O00 % II111iiii
 if 70 - 70: OoO0O00 % oO0o + OOooOOo / Ii1I % O0
 if 100 - 100: o0oOOo0O0Ooo + OOooOOo * o0oOOo0O0Ooo
ooOo00 . target_eid = lisp . lisp_address ( OOoo , "" , iIIiiiI , IIi )
if ( oO0o0o0oo ) :
 ooOo00 . target_eid . store_address ( oO0o0o0oo )
 ooOo00 . target_group . store_address ( I1IIII1i )
 oOOo0OOOo00O = ooOo00 . target_eid . print_sg ( ooOo00 . target_group )
else :
 ooOo00 . target_eid . store_address ( I1IIII1i )
 oOOo0OOOo00O = ooOo00 . target_eid . print_address ( )
 if 76 - 76: i11iIiiIii + o0oOOo0O0Ooo / I1ii11iIi11i - OoO0O00 - Ii1I + I1ii11iIi11i
 if 51 - 51: iIii1I11I1II1 . ooOoO0o + iIii1I11I1II1
 if 95 - 95: I1IiiI
 if 46 - 46: OoOoOO00 + OoO0O00
 if 70 - 70: iII111i / iIii1I11I1II1
if ( Ii1I1I1i1Ii == "" ) :
 ooOo00 . source_eid . afi = lisp . LISP_AFI_NONE
else :
 Oo0oooO0oO = lisp . lisp_gethostbyname ( Ii1I1I1i1Ii )
 if ( Oo0oooO0oO == "" ) :
  print ( "Cannot resolve source EID name '{}'" . format ( Ii1I1I1i1Ii ) )
  exit ( 1 )
  if 19 - 19: i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 Ii1I1I1i1Ii = Oo0oooO0oO
 ooOo00 . source_eid . afi = lisp . LISP_AFI_IPV6 if Ii1I1I1i1Ii . count ( ":" ) == 7 else lisp . LISP_AFI_IPV4
 if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
 ooOo00 . source_eid . store_address ( Ii1I1I1i1Ii )
 ooOo00 . source_eid . instance_id = ooOo00 . target_eid . instance_id
 if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
 if 71 - 71: O0 - iIii1I11I1II1
 if 12 - 12: OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 if 46 - 46: Oo0Ooo
 if 1 - 1: iII111i
if ( ooOo00 . source_eid . is_ipv6 ( ) and Ii1I1I1i1Ii != "" ) :
 ooOo00 . signature_eid = ooOo00 . source_eid
 ooOo00 . privkey_filename = "./lisp-lig.pem"
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
 if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
 if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
iiiI = lisp . lisp_control_header ( )
I1ii1 = lisp . lisp_map_reply ( )
O00 = lisp . lisp_map_notify ( None )
if ( i1I11i1iI . find ( ":" ) != - 1 ) :
 OOoo = lisp . LISP_AFI_IPV6
 iIIiiiI = 128
elif ( i1I11i1iI . find ( "." ) != - 1 ) :
 OOoo = lisp . LISP_AFI_IPV4
 iIIiiiI = 32
else :
 print ( "Invalid Map-Resolver address {}" . format ( i1I11i1iI ) )
 IIi1 ( O0oO )
 exit ( 1 )
 if 92 - 92: iIii1I11I1II1 * i1IIi * iII111i % OOooOOo % I1ii11iIi11i + II111iiii
i1I11i1iI = lisp . lisp_address ( OOoo , i1I11i1iI , iIIiiiI , 0 )
if 42 - 42: IiII - o0oOOo0O0Ooo . II111iiii
if 94 - 94: I1IiiI * Ii1I . I11i
if 74 - 74: Oo0Ooo - o0oOOo0O0Ooo . i1IIi
if 43 - 43: iII111i / I1IiiI
if 58 - 58: I1IiiI + i11iIiiIii % Ii1I . OoOoOO00
Ii1i1iI = None
IIiI1 = lisp . lisp_get_local_rloc ( )
if 17 - 17: OOooOOo / OOooOOo / I11i
if ( IIiI1 == None ) :
 print ( "Cannot obtain a local address" )
 IIi1 ( O0oO )
 exit ( 1 )
 if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
OooO0oo = lisp . LISP_CTRL_PORT
if 89 - 89: Ii1I
if ( IIiI1 != None and IIiI1 . is_private_address ( ) and
 "no-info" not in sys . argv ) :
 print ( "Possible NAT in path, sending Info-Request ... " )
 if 76 - 76: ooOoO0o
 II = lisp . lisp_convert_4to6 ( i1I11i1iI . print_address_no_iid ( ) )
 lisp . lisp_send_info_request ( O0oO , II , lisp . LISP_CTRL_PORT , None )
 if 45 - 45: OoooooooOO - OOooOOo + O0 * Ii1I . I1ii11iIi11i
 if 39 - 39: iIii1I11I1II1 / O0 / oO0o - Ii1I - iII111i % OOooOOo
 if 31 - 31: I11i - O0 / ooOoO0o * OoOoOO00
 if 12 - 12: o0oOOo0O0Ooo - ooOoO0o * I1Ii111
 o000O0o , iI1iII1 , oO0OOoo0OO , O0ii1ii1ii = lisp . lisp_receive ( oooO0oo0oOOOO ,
 False )
 if 14 - 14: Oo0Ooo - Ii1I % Ii1I * O0 . i11iIiiIii / O0
 if ( iI1iII1 != "" ) :
  iiiI = lisp . lisp_control_header ( )
  if ( iiiI . decode ( O0ii1ii1ii ) == None or iiiI . info_reply == False ) :
   iI1iII1 = ""
   if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
   if 28 - 28: i1IIi - iII111i
   if 54 - 54: iII111i - O0 % OOooOOo
   if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
   if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
   if 28 - 28: I11i
 if ( iI1iII1 == "" ) :
  print ( "No Info-Reply received" )
  IIi1 ( O0oO )
  exit ( 1 )
  if 58 - 58: OoOoOO00
  if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 Ii1i1iI , oo0oOOo0 , O0OoO0ooOO0o = lisp . lisp_process_info_reply ( None , O0ii1ii1ii , False )
 if 81 - 81: O0 * II111iiii + I1IiiI * i11iIiiIii - I1ii11iIi11i / I1IiiI
 if 63 - 63: OoOoOO00 - OoooooooOO % I1Ii111
 if ( Ii1i1iI == None ) :
  oOi11iI11iIiIi = O00O0ooo0 = "?"
 else :
  oOi11iI11iIiIi = Ii1i1iI . print_address_no_iid ( )
  O00O0ooo0 = str ( oo0oOOo0 )
  if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
 print ( "Info-Reply received, public address {}, translated port {}\n" . format ( oOi11iI11iIiIi , O00O0ooo0 ) )
 if 74 - 74: O0 / i1IIi
 if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
 OooO0oo = o0oO0
 if 31 - 31: OoooooooOO . OOooOOo
elif ( i1I1ii1II1iII != None ) :
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
 if 7 - 7: OoooooooOO . IiII
 if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
 if 92 - 92: ooOoO0o
 O0oO [ 0 ] = i1I1ii1II1iII
 O0oO [ 1 ] = i1I1ii1II1iII
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if 92 - 92: I11i . I1Ii111
 if 85 - 85: I1ii11iIi11i . I1Ii111
 if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
if ( Ii1i1iI == None ) :
 O000 = IIiI1 . print_address_no_iid ( )
 ooo0o000O = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , O000 , 32 , 0 )
else :
 ooo0o000O = Ii1i1iI
 o0oO0 = oo0oOOo0
 if 100 - 100: oO0o . ooOoO0o * I1ii11iIi11i / iIii1I11I1II1 * i1IIi % ooOoO0o
ooOo00 . itr_rlocs . append ( ooo0o000O )
if 17 - 17: I11i . IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
if 69 - 69: O0
if 85 - 85: ooOoO0o / O0
O0ii1ii1ii = ooOo00 . encode ( None , 0 )
if ( O0ii1ii1ii == None ) :
 print ( "Could not sign Map-Request" )
 IIi1 ( O0oO )
 exit ( 1 )
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
ooOo00 . print_map_request ( )
if 62 - 62: I1Ii111 . IiII . OoooooooOO
if 11 - 11: OOooOOo / I11i
if 73 - 73: i1IIi / i11iIiiIii
if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
if ( oO0o0o0oo ) :
 oOOoOo = ooOo00 . target_group
 ooOooo0 = ooOo00 . target_eid
else :
 oOOoOo = ooOo00 . target_eid
 ooOooo0 = lisp . lisp_myrlocs [ 1 ] if oOOoOo . is_ipv6 ( ) else ooo0o000O
 if 67 - 67: I1IiiI
 if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
O000Oo0o = O0ii1ii1ii
OoO0O0O0o00 = True
i1Oo0oO00o = int ( i1Oo0oO00o )
if 7 - 7: I1IiiI + OoOoOO00 / IiII
oO0o0o0ooO0oO = lisp . bold ( " ({} for {})" . format ( oOO00oOO , i11II1I11I1 ) , False ) if oOO00oOO != None else ""
if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
for OOooOO000 in range ( i1Oo0oO00o ) :
 O0ii1ii1ii = O000Oo0o
 OoO = "subscribe " if i11I1II1I11i else ""
 print ( "Send lig {}map-request to {}{} for EID {} ..." . format ( OoO ,
 i1I11i1iI . print_address_no_iid ( ) , oO0o0o0ooO0oO , oOOo0OOOo00O ) )
 if 35 - 35: OoOoOO00 + i11iIiiIii - II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 if 31 - 31: OOooOOo + O0
 O0ii1ii1ii = O000Oo0o
 lisp . lisp_send_ecm ( O0oO , O0ii1ii1ii , ooOooo0 , OooO0oo ,
 oOOoOo , i1I11i1iI )
 if 87 - 87: ooOoO0o
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
 if 13 - 13: Oo0Ooo
 oOOo000oOoO0 = time . time ( )
 if 86 - 86: II111iiii % i11iIiiIii + Ii1I % i11iIiiIii
 if 92 - 92: i11iIiiIii - iII111i / ooOoO0o / oO0o
 if 43 - 43: II111iiii + OOooOOo + iII111i
 if 40 - 40: o0oOOo0O0Ooo
 if 67 - 67: oO0o + II111iiii - O0 . oO0o * II111iiii * I11i
 o000O0o , iI1iII1 , oO0OOoo0OO , O0ii1ii1ii = oO0 ( ooo00Ooo ,
 oooO0oo0oOOOO , i1I1ii1II1iII , i1Ii11i1i )
 if 90 - 90: Ii1I . IiII
 if 81 - 81: OOooOOo - I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if ( iI1iII1 == "" ) : continue
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
 if 95 - 95: IiII
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
 if ( o000O0o != "packet" ) :
  print ( "Internal fatal error" )
  continue
  if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
  if 2 - 2: OoooooooOO % OOooOOo
  if 63 - 63: I1IiiI % iIii1I11I1II1
  if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
  if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 if ( iiiI . decode ( O0ii1ii1ii ) == None ) :
  print ( "Could not decode header" )
  continue
  if 59 - 59: OOooOOo + i11iIiiIii
  if 88 - 88: i11iIiiIii - ooOoO0o
 if ( iiiI . type not in [ lisp . LISP_MAP_REPLY , lisp . LISP_MAP_NOTIFY ] ) :
  print ( "Expecting Map-Reply/Notify, packet type {} returned" . format ( iiiI . type ) )
  if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
  continue
  if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
  if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 ii1ii11 = "map-reply" if iiiI . type == lisp . LISP_MAP_REPLY else "map-notify"
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 if 47 - 47: OoooooooOO
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 if 82 - 82: ooOoO0o + II111iiii
 II1i1i1iII1 = round ( time . time ( ) - oOOo000oOoO0 , 3 )
 print ( "Received {} from {} with rtt {} secs:" . format ( ii1ii11 , iI1iII1 , II1i1i1iII1 ) )
 if ( ii1ii11 == "map-reply" ) :
  O0ii1ii1ii = I1ii1 . decode ( O0ii1ii1ii )
  if ( O0ii1ii1ii == None ) :
   print ( "Could not decode Map-Reply packet" )
   continue
   if 68 - 68: Oo0Ooo + i11iIiiIii
  OoO0O0O0o00 = False
  I1ii1 . print_map_reply ( )
  iIIi1i1 ( I1ii1 . record_count , I1ii1 . nonce , O0ii1ii1ii )
 else :
  O0ii1ii1ii = O00 . decode ( O0ii1ii1ii )
  if ( O0ii1ii1ii == None ) :
   print ( "Could not decode Map-Notify packet" )
   continue
   if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
  OoO0O0O0o00 = False
  O00 . print_notify ( )
  iIIi1i1 ( O00 . record_count , O00 . nonce , O0ii1ii1ii )
  if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
  if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
  if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
  if 98 - 98: i1IIi
  if 65 - 65: OoOoOO00 / OoO0O00 % IiII
  if 45 - 45: OoOoOO00
if ( OoO0O0O0o00 ) : print ( "*** No reply received ***" )
if 66 - 66: OoO0O00
if 56 - 56: O0
if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
if 23 - 23: oO0o - OOooOOo + I11i
if ( i11I1II1I11i ) :
 O00 = lisp . lisp_map_notify ( None )
 while ( True ) :
  print ( "Waiting for map-notify EID {} RLOC-set changes ..." . format ( oOOo0OOOo00O ) )
  if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
  if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
  try :
   while ( True ) :
    o000O0o , iI1iII1 , oO0OOoo0OO , O0ii1ii1ii = oO0 ( ooo00Ooo ,
 oooO0oo0oOOOO , i1I1ii1II1iII ,
 i1Ii11i1i )
    if ( iI1iII1 != "" ) : break
    if 11 - 11: iII111i * Ii1I - OoOoOO00
  except :
   break
   if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
   if 74 - 74: Oo0Ooo
  print ( "Received map-notify from map-server {}" . format ( iI1iII1 ) )
  if 61 - 61: Oo0Ooo - I1Ii111 * II111iiii % ooOoO0o * iIii1I11I1II1 + OoO0O00
  O0ii1ii1ii = O00 . decode ( O0ii1ii1ii )
  if ( O0ii1ii1ii == None ) :
   print ( "Could not decode Map-Reply packet" )
   continue
   if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
   if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
  O00 . print_notify ( )
  if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
  if 68 - 68: OoooooooOO % II111iiii
  if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
  if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
  iIIi1i1 ( O00 . record_count , O00 . nonce , O0ii1ii1ii )
  if 2 - 2: Ii1I - IiII
  if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
  if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
  if 71 - 71: OoooooooOO
  O00 . map_notify_ack = True
  O00 . print_notify ( )
  O0ii1ii1ii = O00 . encode ( O00 . eid_records , None )
  II = lisp . lisp_convert_4to6 ( iI1iII1 )
  lisp . lisp_send ( O0oO , II , lisp . LISP_CTRL_PORT , O0ii1ii1ii )
  if 33 - 33: I1Ii111
  if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
  if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
  if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
  if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
  if 45 - 45: IiII
IIi1 ( O0oO )
if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
exit ( 1 ) if ( OoO0O0O0o00 ) else exit ( 0 )
if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
if 34 - 34: O0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
