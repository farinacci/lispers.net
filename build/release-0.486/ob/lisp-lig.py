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
if 64 - 64: i11iIiiIii
import lisp
import sys
import time
import random
import select
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
II1iII1i = None
oO0oIIII = None
Oo0oO0oo0oO00 = [ None , None , None ]
i111I = lisp . lisp_get_ephemeral_port ( )
if 16 - 16: oO0o % OOooOOo * iII111i . OOooOOo / iIii1I11I1II1 * iIii1I11I1II1
if 11 - 11: oO0o / i1IIi % II111iiii - OoOoOO00
if 91 - 91: OoO0O00 . i11iIiiIii / oO0o % I11i / OoO0O00 - i11iIiiIii
if 8 - 8: o0oOOo0O0Ooo * I1ii11iIi11i * iIii1I11I1II1 . IiII / IiII % IiII
if 22 - 22: Ii1I . IiII
if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
if 74 - 74: iII111i * IiII
if 82 - 82: iIii1I11I1II1 % IiII
def oOo0oooo00o ( socket_list , lisp_ephem_listen_socket , lisp_listen_socket ,
 lisp_ipc_socket ) :
 if 65 - 65: o0oOOo0O0Ooo * iIii1I11I1II1 * ooOoO0o
 IiI1i , OOo0o0 , O0OoOoo00o = select . select ( socket_list , [ ] , [ ] , 2 )
 if 31 - 31: II111iiii + OoO0O00 . I1Ii111
 if ( lisp_ephem_listen_socket in IiI1i ) :
  OoOooOOOO , i11iiII , I1iiiiI1iII , IiIi11i = lisp . lisp_receive ( lisp_ephem_listen_socket , False )
  if 43 - 43: o0oOOo0O0Ooo * O0
 elif ( lisp_listen_socket in IiI1i ) :
  OoOooOOOO , i11iiII , I1iiiiI1iII , IiIi11i = lisp . lisp_receive ( lisp_listen_socket ,
 False )
 elif ( lisp_ipc_socket in IiI1i ) :
  OoOooOOOO , i11iiII , I1iiiiI1iII , IiIi11i = lisp . lisp_receive ( lisp_ipc_socket ,
 True )
 else :
  return ( "" , "" , 0 , None )
  if 25 - 25: iII111i + ooOoO0o % ooOoO0o - oO0o * o0oOOo0O0Ooo % iII111i
 return ( OoOooOOOO , i11iiII , I1iiiiI1iII , IiIi11i )
 if 55 - 55: OoOoOO00 % i1IIi / Ii1I - oO0o - O0 / II111iiii
 if 28 - 28: iIii1I11I1II1 - i1IIi
 if 70 - 70: OoO0O00 . OoO0O00 - OoO0O00 / I1ii11iIi11i * OOooOOo
 if 86 - 86: i11iIiiIii + Ii1I + ooOoO0o * I11i + o0oOOo0O0Ooo
 if 61 - 61: OoO0O00 / i11iIiiIii
 if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - I1ii11iIi11i + i11iIiiIii
 if 65 - 65: OoOoOO00
def ii1I ( record_count , nonce , packet ) :
 if 76 - 76: O0 / o0oOOo0O0Ooo . I1IiiI * Ii1I - OOooOOo
 for Oooo in range ( record_count ) :
  O00o = lisp . lisp_eid_record ( )
  packet = O00o . decode ( packet )
  if ( packet == None ) : break
  print "EID-prefix: {}, ttl: {}, rloc-set:" . format ( O00o . print_prefix ( ) , O00o . print_ttl ( ) )
  if 61 - 61: iII111i . iIii1I11I1II1 * I1IiiI . ooOoO0o % Oo0Ooo
  if 72 - 72: OOooOOo
  if ( O00o . rloc_count == 0 ) :
   o0Oo00OOOOO = lisp . lisp_map_reply_action_string [ O00o . action ]
   o0Oo00OOOOO = lisp . bold ( o0Oo00OOOOO , False )
   print "  Empty, map-reply action: {}" . format ( o0Oo00OOOOO )
   if 85 - 85: ooOoO0o . iII111i - OoO0O00 % ooOoO0o % II111iiii
   if 81 - 81: OoO0O00 + II111iiii % iII111i * O0
  O00o . print_record ( "" , False )
  for oOOo0oo in range ( O00o . rloc_count ) :
   o0oo0o0O00OO = lisp . lisp_rloc_record ( )
   packet = o0oo0o0O00OO . decode ( packet , nonce )
   if ( packet == None ) : break
   o0oO = o0oo0o0O00OO . priority
   I1i1iii = o0oo0o0O00OO . mpriority
   print "  RLOC: {}, up/uw/mp/mw: {}/{}/{}/{}, flags: {}{}{}" . format ( o0oo0o0O00OO . rloc . print_address_no_iid ( ) , o0oO , o0oo0o0O00OO .
   # o0oOOo0O0Ooo . Ii1I
 weight , I1i1iii , o0oo0o0O00OO . mweight , o0oo0o0O00OO . print_flags ( ) ,
 "" if o0oo0o0O00OO . rloc_name == None else ", " + o0oo0o0O00OO . print_rloc_name ( ) ,
   # OoOoOO00 / I11i
 ", RTR" if o0oO == 254 and I1i1iii == 255 else "" )
   if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
   if ( o0oo0o0O00OO . geo ) :
    print "        geo: {}" . format ( o0oo0o0O00OO . geo . print_geo ( ) )
    if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
   if ( o0oo0o0O00OO . elp ) :
    oOoOooOo0o0 = o0oo0o0O00OO . elp . print_elp ( False )
    print "        elp: {}" . format ( oOoOooOo0o0 )
    if 61 - 61: o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * oO0o / oO0o
   if ( o0oo0o0O00OO . rle ) :
    OoOo = o0oo0o0O00OO . rle . print_rle ( False )
    print "        rle: {}" . format ( OoOo )
    if 18 - 18: i11iIiiIii
   if ( o0oo0o0O00OO . json ) :
    Ii11I = o0oo0o0O00OO . json . print_json ( False )
    print "        json: {}" . format ( Ii11I )
    if 69 - 69: oO0o % I1Ii111 - o0oOOo0O0Ooo + I1Ii111 - O0 % OoooooooOO
   o0oo0o0O00OO . print_record ( "  " )
   if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
  print ""
  if 4 - 4: II111iiii / ooOoO0o . iII111i
 return
 if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 if 50 - 50: I1IiiI
 if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
 if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
def Ii11Ii1I ( lisp_sockets ) :
 for O00oO in lisp_sockets :
  if ( O00oO == None ) : continue
  I11i1I1I = "/tmp/lisp-lig" if ( O00oO == oO0Oo ) else ""
  lisp . lisp_close_socket ( O00oO , I11i1I1I )
  if 54 - 54: o0oOOo0O0Ooo - I1IiiI + OoooooooOO
 return
 if 70 - 70: Ii1I / I11i . iII111i % Oo0Ooo
 if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . IiII - OoO0O00 * o0oOOo0O0Ooo
 if 46 - 46: OOooOOo + OoOoOO00 . I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
 if 44 - 44: oO0o
 if 88 - 88: I1Ii111 % Ii1I . II111iiii
 if 38 - 38: o0oOOo0O0Ooo
Oo0O = len ( sys . argv )
IIi = ""
i11iIIIIIi1 = ""
iiII1i1 = ""
o00oOO0o = ""
OOO00O = ( "pubsub" in sys . argv )
if 84 - 84: oO0o * OoO0O00 / I11i - O0
if 30 - 30: iIii1I11I1II1 / ooOoO0o - I1Ii111 - II111iiii % iII111i
if 49 - 49: I1IiiI % ooOoO0o . ooOoO0o . I11i * ooOoO0o
if 97 - 97: Ii1I + o0oOOo0O0Ooo . OOooOOo + I1ii11iIi11i % iII111i
if 95 - 95: i1IIi
if ( Oo0O == 2 ) :
 IIi = sys . argv [ 1 ]
 Oo0O = 1
 if 3 - 3: I1Ii111 - O0 / I1Ii111 % OoO0O00 / I1Ii111 . I1IiiI
if ( Oo0O <= 1 ) :
 while ( IIi == "" ) :
  IIi = raw_input ( "Enter destination EID (or S->G): " )
  if 50 - 50: IiII
 while ( i11iIIIIIi1 == "" ) :
  i11iIIIIIi1 = raw_input ( "Enter map-resolver address: " )
  if 14 - 14: I11i % OoO0O00 * I11i
 while ( o00oOO0o == "" ) :
  o00oOO0o = raw_input ( "Enter map-request tries (1-5): " )
  if ( o00oOO0o < 1 and o00oOO0o > 5 ) : o00oOO0o = ""
  if 16 - 16: OoOoOO00 . ooOoO0o + i11iIiiIii
 iiII1i1 = raw_input ( "Enter optional source EID: " )
else :
 IIi = sys . argv [ 1 ]
 if ( "source" in sys . argv ) :
  i1i1I1IIii1II = sys . argv . index ( "source" )
  if ( i1i1I1IIii1II + 1 < Oo0O ) : iiII1i1 = sys . argv [ i1i1I1IIii1II + 1 ]
  if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
 if ( "to" in sys . argv ) :
  i1i1I1IIii1II = sys . argv . index ( "to" )
  if ( i1i1I1IIii1II + 1 < Oo0O ) : i11iIIIIIi1 = sys . argv [ i1i1I1IIii1II + 1 ]
  if 21 - 21: I1IiiI * iIii1I11I1II1
 if ( "count" in sys . argv ) :
  i1i1I1IIii1II = sys . argv . index ( "count" )
  if ( i1i1I1IIii1II + 1 < Oo0O ) :
   o00oOO0o = sys . argv [ i1i1I1IIii1II + 1 ]
   if ( o00oOO0o . isdigit ( ) == False ) : i11iIIIIIi1 = ""
   if 91 - 91: IiII
   if 15 - 15: II111iiii
 if ( i11iIIIIIi1 == "" ) :
  print "Usage: lig [<iid>]<dest-eid> to <mr-rloc> " + "[source <source-eid>] [count <1-5>] [debug] [no-info]"
  if 18 - 18: i11iIiiIii . i1IIi % OoooooooOO / O0
  exit ( 1 )
  if 75 - 75: OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1Ii111
  if 5 - 5: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
  if 91 - 91: O0
  if 61 - 61: II111iiii
  if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
  if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
iIIi1i1 = None
if ( IIi . find ( "->" ) != - 1 ) :
 iIIi1i1 = IIi . split ( "->" )
 IIi = iIIi1i1 [ 1 ]
 iIIi1i1 = iIIi1i1 [ 0 ]
 if 10 - 10: I11i
 if 82 - 82: I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
 if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 if 83 - 83: I11i / I1IiiI
iIIiIi1iIII1 = 0
if ( IIi . find ( "[" ) != - 1 ) :
 iIIiIi1iIII1 = IIi . split ( "]" )
 IIi = iIIiIi1iIII1 [ 1 ]
 if ( IIi == "" ) :
  print "No destination EID specified"
  exit ( 1 )
  if 78 - 78: O0 . oO0o . II111iiii % OOooOOo
 iIIiIi1iIII1 = iIIiIi1iIII1 [ 0 ]
 iIIiIi1iIII1 = int ( iIIiIi1iIII1 [ 1 : : ] )
 if 49 - 49: Ii1I / OoO0O00 . II111iiii
 if 68 - 68: i11iIiiIii % I1ii11iIi11i + i11iIiiIii
 if 31 - 31: II111iiii . I1IiiI
 if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
 if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
ooOOOoOooOoO = ( IIi [ 0 ] == "'" or IIi [ - 1 ] == "'" )
o00oooO0Oo = [ "-N" , "-S" , "-E" , "-W" ]
o0O0OOO0Ooo = False
for iiIiI in o00oooO0Oo :
 if ( iiIiI in IIi ) : o0O0OOO0Ooo = True
 if 6 - 6: IiII . oO0o * OoOoOO00 - Ii1I - IiII
 if 45 - 45: I1IiiI - OoooooooOO + iIii1I11I1II1 . I1IiiI * I11i
if ( ooOOOoOooOoO == False and o0O0OOO0Ooo == False ) :
 oOOO = lisp . lisp_gethostbyname ( IIi )
 if ( oOOO == "" ) :
  print "Cannot resolve EID name '{}'" . format ( IIi )
  exit ( 1 )
  if 16 - 16: OoO0O00 / I1ii11iIi11i + Ii1I
 IIi = oOOO
 if 65 - 65: O0
 if 68 - 68: OOooOOo % I1Ii111
ooO00OO0 = lisp . lisp_gethostbyname ( i11iIIIIIi1 )
if ( ooO00OO0 == "" ) :
 print "Cannot resolve Map-Resolver name '{}'" . format ( i11iIIIIIi1 )
 exit ( 1 )
 if 31 - 31: iII111i % iII111i % I11i
i11iIIIIIi1 = ooO00OO0
if 69 - 69: OoO0O00 - Oo0Ooo + i1IIi / I1Ii111
if 49 - 49: O0 . iII111i
if 11 - 11: IiII * I1IiiI . iIii1I11I1II1 % OoooooooOO + iII111i
if 78 - 78: OoO0O00 . OOooOOo + OoO0O00 / I11i / OoO0O00
lisp . lisp_debug_logging = True if "debug" in sys . argv else False
if 54 - 54: OoOoOO00 % iII111i
if 37 - 37: OoOoOO00 * Oo0Ooo / ooOoO0o - iII111i % II111iiii . oO0o
if 88 - 88: iII111i . II111iiii * II111iiii % I1Ii111
if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
if ( o00oOO0o == "" ) : o00oOO0o = "1"
if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
lisp . lisp_i_am ( "lig" )
if 80 - 80: II111iiii
if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
if 53 - 53: II111iiii
if 31 - 31: OoO0O00
I1iiiiI1iII = str ( i111I )
if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
if 25 - 25: OoO0O00
if 62 - 62: OOooOOo + O0
if 98 - 98: o0oOOo0O0Ooo
if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
if 82 - 82: Ii1I
oO0Oo = lisp . lisp_open_listen_socket ( "" , "/tmp/lisp-lig" )
if 46 - 46: OoooooooOO . i11iIiiIii
OOo0oO00ooO00 = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
oO0oIIII = lisp . lisp_open_listen_socket ( OOo0oO00ooO00 , I1iiiiI1iII )
oO0oIIII . settimeout ( 2 )
try :
 II1iII1i = lisp . lisp_open_listen_socket ( OOo0oO00ooO00 ,
 str ( lisp . LISP_CTRL_PORT ) )
 oOO0O00oO0Ooo = [ oO0oIIII , II1iII1i ,
 oO0Oo ]
except :
 oOO0O00oO0Ooo = [ oO0oIIII , oO0Oo ]
 if 67 - 67: OoO0O00 - OOooOOo
 if 36 - 36: IiII
Oo0oO0oo0oO00 [ 0 ] = oO0oIIII
Oo0oO0oo0oO00 [ 1 ] = oO0oIIII
Oo0oO0oo0oO00 [ 2 ] = oO0Oo
if 36 - 36: ooOoO0o / O0 * Oo0Ooo - OOooOOo % iIii1I11I1II1 * oO0o
if 79 - 79: O0
if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
oO0o0 = lisp . lisp_map_request ( )
oO0o0 . record_count = 1
oO0o0 . subscribe_bit = OOO00O
oO0o0 . xtr_id_present = OOO00O
oO0o0 . nonce = 0xdfdf0e1d10c10000 + random . randint ( 0 , 65535 )
if ( ooOOOoOooOoO ) :
 iI1Ii11iIiI1 = lisp . LISP_AFI_NAME
 OO0Oooo0oOO0O = len ( IIi ) * 8
elif ( IIi . find ( ":" ) != - 1 ) :
 iI1Ii11iIiI1 = lisp . LISP_AFI_IPV6
 OO0Oooo0oOO0O = 128
elif ( IIi . find ( "." ) != - 1 ) :
 iI1Ii11iIiI1 = lisp . LISP_AFI_IPV4
 OO0Oooo0oOO0O = 32
elif ( o0O0OOO0Ooo ) :
 iI1Ii11iIiI1 = lisp . LISP_AFI_GEO_COORD
 OO0Oooo0oOO0O = len ( IIi ) * 8
elif ( IIi . find ( "-" ) != - 1 ) :
 iI1Ii11iIiI1 = lisp . LISP_AFI_MAC
 OO0Oooo0oOO0O = 48
else :
 print ( "Invalid EID address {}" . format ( IIi ) )
 Ii11Ii1I ( Oo0oO0oo0oO00 )
 exit ( 1 )
 if 62 - 62: I1IiiI
 if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
if ( lisp . lisp_valid_address_format ( "address" , IIi ) == False ) :
 print ( "Invalid address syntax '{}'" . format ( IIi ) )
 Ii11Ii1I ( Oo0oO0oo0oO00 )
 exit ( 1 )
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
oO0o0 . target_eid = lisp . lisp_address ( iI1Ii11iIiI1 , "" , OO0Oooo0oOO0O , iIIiIi1iIII1 )
if ( iIIi1i1 ) :
 oO0o0 . target_eid . store_address ( iIIi1i1 )
 oO0o0 . target_group . store_address ( IIi )
 oo = oO0o0 . target_eid . print_sg ( oO0o0 . target_group )
else :
 oO0o0 . target_eid . store_address ( IIi )
 oo = oO0o0 . target_eid . print_address ( )
 if 44 - 44: oO0o / I11i / I11i
 if 87 - 87: Oo0Ooo . I1IiiI - II111iiii + O0 / Oo0Ooo / oO0o
 if 25 - 25: I1IiiI . I1IiiI - OoOoOO00 % OoOoOO00 - i11iIiiIii / I1Ii111
 if 51 - 51: Oo0Ooo / OoOoOO00 . OOooOOo * o0oOOo0O0Ooo + OoO0O00 * IiII
 if 73 - 73: OoO0O00 + OoooooooOO - O0 - Ii1I - II111iiii
if ( iiII1i1 == "" ) :
 oO0o0 . source_eid . afi = lisp . LISP_AFI_NONE
else :
 O0O = lisp . lisp_gethostbyname ( iiII1i1 )
 if ( O0O == "" ) :
  print "Cannot resolve source EID name '{}'" . format ( iiII1i1 )
  exit ( 1 )
  if 80 - 80: Ii1I * o0oOOo0O0Ooo / o0oOOo0O0Ooo
 iiII1i1 = O0O
 oO0o0 . source_eid . afi = lisp . LISP_AFI_IPV6 if iiII1i1 . count ( ":" ) == 7 else lisp . LISP_AFI_IPV4
 if 5 - 5: I1IiiI
 oO0o0 . source_eid . store_address ( iiII1i1 )
 oO0o0 . source_eid . instance_id = oO0o0 . target_eid . instance_id
 if 48 - 48: o0oOOo0O0Ooo - oO0o / OoooooooOO
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo % II111iiii % Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
 if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
 if 69 - 69: I1Ii111
 if 11 - 11: I1IiiI
 if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
if ( oO0o0 . source_eid . is_ipv6 ( ) and iiII1i1 != "" ) :
 oO0o0 . signature_eid = oO0o0 . source_eid
 oO0o0 . privkey_filename = "./lisp-lig.pem"
 if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
 if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
 if 71 - 71: I1Ii111 + Ii1I
 if 28 - 28: OOooOOo
 if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
OoOOo0OOoO = lisp . lisp_control_header ( )
ooO0O00Oo0o = lisp . lisp_map_reply ( )
OOO = lisp . lisp_map_notify ( None )
if ( i11iIIIIIi1 . find ( ":" ) != - 1 ) :
 iI1Ii11iIiI1 = lisp . LISP_AFI_IPV6
 OO0Oooo0oOO0O = 128
elif ( i11iIIIIIi1 . find ( "." ) != - 1 ) :
 iI1Ii11iIiI1 = lisp . LISP_AFI_IPV4
 OO0Oooo0oOO0O = 32
else :
 print ( "Invalid Map-Resolver address {}" . format ( i11iIIIIIi1 ) )
 Ii11Ii1I ( Oo0oO0oo0oO00 )
 exit ( 1 )
 if 73 - 73: OoooooooOO * OoooooooOO * ooOoO0o * OoOoOO00 + ooOoO0o * I1Ii111
i11iIIIIIi1 = lisp . lisp_address ( iI1Ii11iIiI1 , i11iIIIIIi1 , OO0Oooo0oOO0O , 0 )
if 88 - 88: I1ii11iIi11i
if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
if 26 - 26: Ii1I % I1ii11iIi11i
if 76 - 76: IiII * iII111i
if 52 - 52: OOooOOo
iiii1 = None
ooO0oooOO0 = lisp . lisp_get_local_rloc ( )
if 71 - 71: I1Ii111 . II111iiii
if ( ooO0oooOO0 == None ) :
 print ( "Cannot obtain a local address" )
 Ii11Ii1I ( Oo0oO0oo0oO00 )
 exit ( 1 )
 if 62 - 62: OoooooooOO . I11i
oOOOoo00 = lisp . LISP_CTRL_PORT
if 9 - 9: O0 % O0 - o0oOOo0O0Ooo
if ( ooO0oooOO0 != None and ooO0oooOO0 . is_private_address ( ) and
 "no-info" not in sys . argv ) :
 print "Possible NAT in path, sending Info-Request ... "
 if 51 - 51: I1IiiI . iIii1I11I1II1 - I1ii11iIi11i / O0
 OOOoO00 = lisp . lisp_convert_4to6 ( i11iIIIIIi1 . print_address_no_iid ( ) )
 lisp . lisp_send_info_request ( Oo0oO0oo0oO00 , OOOoO00 , lisp . LISP_CTRL_PORT , None )
 if 40 - 40: I1ii11iIi11i % I1IiiI . ooOoO0o . O0 * I1Ii111
 if 4 - 4: Ii1I % oO0o * OoO0O00
 if 100 - 100: I1Ii111 * OOooOOo + OOooOOo
 if 54 - 54: OoooooooOO + o0oOOo0O0Ooo - i1IIi % i11iIiiIii
 OoOooOOOO , i11iiII , I1iiiiI1iII , IiIi11i = lisp . lisp_receive ( oO0oIIII ,
 False )
 if 3 - 3: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if ( i11iiII != "" ) :
  OoOOo0OOoO = lisp . lisp_control_header ( )
  if ( OoOOo0OOoO . decode ( IiIi11i ) == None or OoOOo0OOoO . info_reply == False ) :
   i11iiII = ""
   if 83 - 83: II111iiii + I1Ii111
   if 73 - 73: iII111i
   if 42 - 42: i11iIiiIii * iIii1I11I1II1 / I1ii11iIi11i . i11iIiiIii % I11i
   if 41 - 41: IiII / O0
   if 51 - 51: I11i % I1IiiI
   if 60 - 60: I1IiiI / OOooOOo . I1IiiI / I1Ii111 . IiII
 if ( i11iiII == "" ) :
  print "No Info-Reply received"
  Ii11Ii1I ( Oo0oO0oo0oO00 )
  exit ( 1 )
  if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
  if 42 - 42: Oo0Ooo
 iiii1 , oo000O0OoooO , O0o = lisp . lisp_process_info_reply ( None , IiIi11i , False )
 if 27 - 27: IiII - Ii1I / I1ii11iIi11i % IiII + I1IiiI
 if 96 - 96: I1Ii111
 if ( iiii1 == None ) :
  oOoOo0O0OOOoO = iI11IIIiii1II = "?"
 else :
  oOoOo0O0OOOoO = iiii1 . print_address_no_iid ( )
  iI11IIIiii1II = str ( oo000O0OoooO )
  if 16 - 16: iII111i + OoOoOO00
 print "Info-Reply received, public address {}, translated port {}\n" . format ( oOoOo0O0OOOoO , iI11IIIiii1II )
 if 66 - 66: iII111i / oO0o * OoooooooOO + OoooooooOO % I11i
 if 49 - 49: oO0o - i11iIiiIii . I1Ii111 * Ii1I % iII111i + i1IIi
 oOOOoo00 = i111I
 if 71 - 71: o0oOOo0O0Ooo
elif ( II1iII1i != None ) :
 if 38 - 38: oO0o % OoOoOO00 + I1ii11iIi11i . i11iIiiIii
 if 53 - 53: i11iIiiIii * iII111i
 if 68 - 68: iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
 if 38 - 38: ooOoO0o - OOooOOo / iII111i
 if 66 - 66: O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / Ii1I + I1ii11iIi11i
 if 86 - 86: o0oOOo0O0Ooo
 if 5 - 5: IiII * OoOoOO00
 if 5 - 5: I1Ii111
 if 90 - 90: I1Ii111 . ooOoO0o / Ii1I - I11i
 if 40 - 40: OoooooooOO
 if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
 if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
 if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
 Oo0oO0oo0oO00 [ 0 ] = II1iII1i
 Oo0oO0oo0oO00 [ 1 ] = II1iII1i
 if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
 if 19 - 19: OoO0O00 - Oo0Ooo . O0
 if 60 - 60: II111iiii + Oo0Ooo
 if 9 - 9: ooOoO0o * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
 if 49 - 49: II111iiii
 if 25 - 25: OoooooooOO - I1IiiI . I1IiiI * oO0o
if ( iiii1 == None ) :
 o000oo = ooO0oooOO0 . print_address_no_iid ( )
 o00o0 = lisp . lisp_address ( lisp . LISP_AFI_IPV4 , o000oo , 32 , 0 )
else :
 o00o0 = iiii1
 i111I = oo000O0OoooO
 if 50 - 50: Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
oO0o0 . itr_rlocs . append ( o00o0 )
if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
if 41 - 41: i1IIi - I11i - Ii1I
if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
IiIi11i = oO0o0 . encode ( None , 0 )
if ( IiIi11i == None ) :
 print "Could not sign Map-Request"
 Ii11Ii1I ( Oo0oO0oo0oO00 )
 exit ( 1 )
 if 44 - 44: II111iiii
oO0o0 . print_map_request ( )
if 52 - 52: I1ii11iIi11i - Oo0Ooo + I1ii11iIi11i % o0oOOo0O0Ooo
if 35 - 35: iIii1I11I1II1
if 42 - 42: I1Ii111 . I1IiiI . i1IIi + OoOoOO00 + OOooOOo + I1IiiI
if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
if ( iIIi1i1 ) :
 OOoO = oO0o0 . target_group
 iiII1i11i = oO0o0 . target_eid
else :
 OOoO = oO0o0 . target_eid
 iiII1i11i = lisp . lisp_myrlocs [ 1 ] if OOoO . is_ipv6 ( ) else o00o0
 if 11 - 11: I1IiiI / II111iiii + o0oOOo0O0Ooo * I1ii11iIi11i - I1ii11iIi11i - I1IiiI
 if 85 - 85: I11i % oO0o / iIii1I11I1II1 . iIii1I11I1II1
iIIiIiI1I1 = IiIi11i
ooO = True
o00oOO0o = int ( o00oOO0o )
if 6 - 6: iIii1I11I1II1 . ooOoO0o % o0oOOo0O0Ooo
for Oooo in range ( o00oOO0o ) :
 IiIi11i = iIIiIiI1I1
 I1Iii1 = "subscribe " if OOO00O else ""
 print "Send lig {}map-request to {} for EID {} ..." . format ( I1Iii1 ,
 i11iIIIIIi1 . print_address_no_iid ( ) , oo )
 if 30 - 30: OoooooooOO - OoOoOO00
 if 75 - 75: iIii1I11I1II1 - Ii1I . Oo0Ooo % i11iIiiIii % I11i
 if 55 - 55: iII111i . II111iiii % OoO0O00 * iII111i + ooOoO0o + Ii1I
 if 24 - 24: Oo0Ooo - oO0o % iIii1I11I1II1 . i1IIi / O0
 IiIi11i = iIIiIiI1I1
 lisp . lisp_send_ecm ( Oo0oO0oo0oO00 , IiIi11i , iiII1i11i , oOOOoo00 ,
 OOoO , i11iIIIIIi1 )
 if 36 - 36: I1IiiI - I11i
 if 29 - 29: ooOoO0o * OOooOOo
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
 ooo0OOO = time . time ( )
 if 49 - 49: i11iIiiIii % Ii1I . OoOoOO00
 if 13 - 13: i11iIiiIii + i1IIi * iIii1I11I1II1 % OoooooooOO - II111iiii * OOooOOo
 if 26 - 26: OoooooooOO * I1IiiI + OOooOOo
 if 24 - 24: i11iIiiIii % iIii1I11I1II1 + OOooOOo / i11iIiiIii
 if 70 - 70: OoO0O00 * O0 . I11i + I1IiiI . IiII
 OoOooOOOO , i11iiII , I1iiiiI1iII , IiIi11i = oOo0oooo00o ( oOO0O00oO0Ooo ,
 oO0oIIII , II1iII1i , oO0Oo )
 if 14 - 14: iIii1I11I1II1 % iIii1I11I1II1 * i11iIiiIii - OoO0O00 - I11i
 if 63 - 63: OoO0O00
 if 69 - 69: iIii1I11I1II1 . I1ii11iIi11i % ooOoO0o + iIii1I11I1II1 / O0 / I1ii11iIi11i
 if 61 - 61: OOooOOo % OOooOOo * o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if ( i11iiII == "" ) : continue
 if 75 - 75: IiII . ooOoO0o
 if 50 - 50: OoOoOO00
 if 60 - 60: ooOoO0o * iIii1I11I1II1 * I1ii11iIi11i * Oo0Ooo
 if 69 - 69: Ii1I * O0 . i11iIiiIii / Ii1I . o0oOOo0O0Ooo
 if ( OoOooOOOO != "packet" ) :
  print "Internal fatal error"
  continue
  if 63 - 63: I11i + o0oOOo0O0Ooo . II111iiii - I1IiiI
  if 52 - 52: o0oOOo0O0Ooo % Oo0Ooo
  if 64 - 64: O0 % I11i % O0 * OoO0O00 . oO0o + I1IiiI
  if 75 - 75: I11i . OoooooooOO % o0oOOo0O0Ooo * I11i % OoooooooOO
  if 13 - 13: IiII / i11iIiiIii % II111iiii % I11i . I1ii11iIi11i
 if ( OoOOo0OOoO . decode ( IiIi11i ) == None ) :
  print "Could not decode header"
  continue
  if 8 - 8: OoOoOO00 + Oo0Ooo - II111iiii
  if 11 - 11: i1IIi % i11iIiiIii - i1IIi * OoOoOO00
 if ( OoOOo0OOoO . type not in [ lisp . LISP_MAP_REPLY , lisp . LISP_MAP_NOTIFY ] ) :
  print "Expecting Map-Reply/Notify, packet type {} returned" . format ( OoOOo0OOoO . type )
  if 39 - 39: I1Ii111
  continue
  if 86 - 86: I11i * I1IiiI + I11i + II111iiii
  if 8 - 8: I1Ii111 - iII111i / ooOoO0o
 oo0oOoo = "map-reply" if OoOOo0OOoO . type == lisp . LISP_MAP_REPLY else "map-notify"
 if 57 - 57: OoOoOO00 - I1ii11iIi11i
 if 50 - 50: I1Ii111 / i1IIi % OoO0O00 . I1IiiI / iII111i
 if 88 - 88: OOooOOo . I11i * o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . I11i
 if 10 - 10: o0oOOo0O0Ooo * Oo0Ooo % O0 * iIii1I11I1II1 . O0 % I1ii11iIi11i
 if 44 - 44: II111iiii / iII111i / I11i % II111iiii / i1IIi . Ii1I
 oOO = round ( time . time ( ) - ooo0OOO , 3 )
 print "Received {} from {} with rtt {} secs:" . format ( i11iIIIIIi1 , i11iiII , oOO )
 if ( oo0oOoo == "map-reply" ) :
  IiIi11i = ooO0O00Oo0o . decode ( IiIi11i )
  if ( IiIi11i == None ) :
   print "Could not decode Map-Reply packet"
   continue
   if 54 - 54: I1IiiI / iIii1I11I1II1 / OOooOOo . OOooOOo % iII111i . I1IiiI
  ooO = False
  ooO0O00Oo0o . print_map_reply ( )
  ii1I ( ooO0O00Oo0o . record_count , ooO0O00Oo0o . nonce , IiIi11i )
 else :
  IiIi11i = OOO . decode ( IiIi11i )
  if ( IiIi11i == None ) :
   print "Could not decode Map-Notify packet"
   continue
   if 10 - 10: o0oOOo0O0Ooo + OOooOOo
  ooO = False
  OOO . print_notify ( )
  ii1I ( OOO . record_count , OOO . nonce , IiIi11i )
  if 27 - 27: OoO0O00 . I11i + OoOoOO00 / iIii1I11I1II1 % iII111i . ooOoO0o
  if 14 - 14: oO0o + I1ii11iIi11i - iII111i / O0 . I1Ii111
  if 45 - 45: I1Ii111
  if 83 - 83: OoOoOO00 . OoooooooOO
  if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
  if 62 - 62: OoO0O00 / I1ii11iIi11i
if ( ooO ) : print "*** No reply received ***"
if 7 - 7: OoooooooOO . IiII
if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
if ( OOO00O ) :
 OOO = lisp . lisp_map_notify ( None )
 while ( True ) :
  print "Waiting for map-notify EID {} RLOC-set changes ..." . format ( oo )
  if 92 - 92: ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  try :
   while ( True ) :
    OoOooOOOO , i11iiII , I1iiiiI1iII , IiIi11i = oOo0oooo00o ( oOO0O00oO0Ooo ,
 oO0oIIII , II1iII1i ,
 oO0Oo )
    if ( i11iiII != "" ) : break
    if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  except :
   break
   if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
   if 92 - 92: I11i . I1Ii111
  print "Received map-notify from map-server {}" . format ( i11iiII )
  if 85 - 85: I1ii11iIi11i . I1Ii111
  IiIi11i = OOO . decode ( IiIi11i )
  if ( IiIi11i == None ) :
   print "Could not decode Map-Reply packet"
   continue
   if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
   if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
  OOO . print_notify ( )
  if 18 - 18: iIii1I11I1II1 % I11i
  if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
  if 75 - 75: OoooooooOO * IiII
  if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
  ii1I ( OOO . record_count , OOO . nonce , IiIi11i )
  if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
  if 69 - 69: O0
  if 85 - 85: ooOoO0o / O0
  if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
  OOO . map_notify_ack = True
  OOO . print_notify ( )
  IiIi11i = OOO . encode ( OOO . eid_records , None )
  OOOoO00 = lisp . lisp_convert_4to6 ( i11iiII )
  lisp . lisp_send ( Oo0oO0oo0oO00 , OOOoO00 , lisp . LISP_CTRL_PORT , IiIi11i )
  if 62 - 62: I1Ii111 . IiII . OoooooooOO
  if 11 - 11: OOooOOo / I11i
  if 73 - 73: i1IIi / i11iIiiIii
  if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
  if 85 - 85: OoOoOO00 + OOooOOo
  if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
Ii11Ii1I ( Oo0oO0oo0oO00 )
if 27 - 27: Ii1I
exit ( 1 ) if ( ooO ) else exit ( 0 )
if 67 - 67: I1IiiI
if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
