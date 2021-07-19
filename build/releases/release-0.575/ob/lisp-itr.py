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
# lisp-itr.py
#
# This file performs LISP Ingress Tunnel Router (ITR) functionality.
#
# -----------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
from future import standard_library
standard_library . install_aliases ( )
from builtins import str
from builtins import range
import lisp
import lispconfig
import socket
import select
import threading
import time
import os
from subprocess import getoutput
import struct
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
II1iII1i = [ None , None , None ]
oO0oIIII = None
Oo0oO0oo0oO00 = None
i111I = None
II1Ii1iI1i = None
iiI1iIiI = lisp . lisp_get_ephemeral_port ( )
OOo = lisp . lisp_get_ephemeral_port ( )
Ii1IIii11 = None
Oooo0000 = None
i11 = None
I11 = None
if 98 - 98: i11iIiiIii * I1IiiI % iII111i * iII111i * II111iiii
if 79 - 79: IiII
if 86 - 86: OoOoOO00 % I1IiiI
if 80 - 80: OoooooooOO . I1IiiI
if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
if 11 - 11: I1IiiI % o0oOOo0O0Ooo - Oo0Ooo
oo0O000OoO = False
if 34 - 34: I11i * I1IiiI
if 31 - 31: II111iiii + OoO0O00 . I1Ii111
if 68 - 68: I1IiiI - i11iIiiIii - OoO0O00 / OOooOOo - OoO0O00 + i1IIi
if 48 - 48: OoooooooOO % o0oOOo0O0Ooo . I1IiiI - Ii1I % i1IIi % OoooooooOO
i1iIIi1 = threading . Lock ( )
if 50 - 50: i11iIiiIii - Ii1I
if 78 - 78: OoO0O00
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
if 14 - 14: I11i % O0
if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
if 77 - 77: Oo0Ooo . IiII % ooOoO0o
def IIiiIiI1 ( parameter ) :
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "ITR" , [ ] ) )
 if 41 - 41: OoOoOO00
 if 13 - 13: Oo0Ooo . i11iIiiIii - iIii1I11I1II1 - OoOoOO00
 if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
 if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
 if 100 - 100: Ii1I - Ii1I - I1Ii111
 if 20 - 20: OoooooooOO
 if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
def oo ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "ITR" ) )
 if 68 - 68: I11i + OOooOOo . iIii1I11I1II1 - IiII % iIii1I11I1II1 - ooOoO0o
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
def I1i1iii ( parameter ) :
 return ( lispconfig . lisp_itr_rtr_show_rloc_probe_command ( "ITR" ) )
 if 20 - 20: o0oOOo0O0Ooo
 if 77 - 77: OoOoOO00 / I11i
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
 if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % oO0o . O0
 if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
 if 53 - 53: IiII + I1IiiI * oO0o
 if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
 if 60 - 60: I11i / I11i
 if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
def oo0 ( lisp_sockets , lisp_ephem_port ) :
 lisp . lisp_set_exception ( )
 if 57 - 57: OOooOOo . OOooOOo
 if 95 - 95: O0 + OoO0O00 . II111iiii / O0
 if 97 - 97: ooOoO0o - OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - OoooooooOO
 if 59 - 59: O0 + I1IiiI + IiII % I1IiiI
 for o0OOoo0OO0OOO in list ( lisp . lisp_crypto_keys_by_nonce . values ( ) ) :
  for iI1iI1I1i1I in o0OOoo0OO0OOO : del ( iI1iI1I1i1I )
  if 24 - 24: I1ii11iIi11i
 lisp . lisp_crypto_keys_by_nonce = { }
 if 56 - 56: ooOoO0o
 if 92 - 92: iII111i . I11i + o0oOOo0O0Ooo
 if 28 - 28: i1IIi * Oo0Ooo - o0oOOo0O0Ooo * IiII * Ii1I / OoO0O00
 if 94 - 94: II111iiii % I1ii11iIi11i / OoOoOO00 * iIii1I11I1II1
 if 54 - 54: o0oOOo0O0Ooo - I1IiiI + OoooooooOO
 if ( lisp . lisp_l2_overlay ) :
  O0o0 = lisp . LISP_AFI_MAC
  OO00Oo = lisp . lisp_default_iid
  O0OOO0OOoO0O = lisp . lisp_address ( O0o0 , "0000-0000-0000" , 0 , OO00Oo )
  O0OOO0OOoO0O . mask_len = 0
  O00Oo000ooO0 = lisp . lisp_address ( O0o0 , "ffff-ffff-ffff" , 48 , OO00Oo )
  lisp . lisp_send_map_request ( lisp_sockets , lisp_ephem_port , O0OOO0OOoO0O , O00Oo000ooO0 , None )
  if 100 - 100: O0 + IiII - OOooOOo + i11iIiiIii * Ii1I
  if 30 - 30: o0oOOo0O0Ooo . Ii1I - OoooooooOO
  if 8 - 8: i1IIi - iIii1I11I1II1 * II111iiii + i11iIiiIii / I1Ii111 % OOooOOo
  if 16 - 16: I1ii11iIi11i + OoO0O00 - II111iiii
  if 85 - 85: OoOoOO00 + i1IIi
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 58 - 58: II111iiii * OOooOOo * I1ii11iIi11i / OOooOOo
 if 75 - 75: oO0o
 if 50 - 50: Ii1I / Oo0Ooo - oO0o - I11i % iII111i - oO0o
 if 91 - 91: OoO0O00 / I11i - II111iiii . I11i
 i11 = threading . Timer ( 60 , oo0 ,
 [ lisp_sockets , lisp_ephem_port ] )
 i11 . start ( )
 return
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 if 92 - 92: iII111i . I1Ii111
 if 31 - 31: I1Ii111 . OoOoOO00 / O0
 if 89 - 89: OoOoOO00
def OO0oOoOO0oOO0 ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 if 86 - 86: OOooOOo
 OOoo0O = lisp . lisp_get_timestamp ( )
 for Oo0ooOo0o in lisp . lisp_db_list :
  if ( Oo0ooOo0o . dynamic_eid_configured ( ) == False ) : continue
  if 22 - 22: iIii1I11I1II1 / i11iIiiIii * iIii1I11I1II1 * II111iiii . OOooOOo / i11iIiiIii
  Iiii = [ ]
  for OO0OoO0o00 in list ( Oo0ooOo0o . dynamic_eids . values ( ) ) :
   ooOO0O0ooOooO = OO0OoO0o00 . last_packet
   if ( ooOO0O0ooOooO == None ) : continue
   if ( ooOO0O0ooOooO + OO0OoO0o00 . timeout > OOoo0O ) : continue
   if 55 - 55: o0oOOo0O0Ooo * OoOoOO00
   if 61 - 61: I11i
   if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
   if 42 - 42: OoO0O00
   if 67 - 67: I1Ii111 . iII111i . O0
   if ( lisp . lisp_program_hardware ) :
    IIIIiiII111 = OO0OoO0o00 . dynamic_eid . print_prefix_no_iid ( )
    if ( lisp . lisp_arista_is_alive ( IIIIiiII111 ) ) :
     lisp . lprint ( ( "Hardware indicates dynamic-EID {} " + "still active" ) . format ( lisp . green ( IIIIiiII111 , False ) ) )
     if 97 - 97: I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
     continue
     if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
     if 83 - 83: I11i / I1IiiI
     if 34 - 34: IiII
     if 57 - 57: oO0o . I11i . i1IIi
     if 42 - 42: I11i + I1ii11iIi11i % O0
     if 6 - 6: oO0o
   oOOo0oOo0 = OO0OoO0o00 . dynamic_eid . print_address ( )
   II = "learn%{}%None" . format ( oOOo0oOo0 )
   II = lisp . lisp_command_ipc ( II , "lisp-itr" )
   lisp . lisp_ipc ( II , lisp_socket , "lisp-etr" )
   if 60 - 60: I1IiiI
   lisp . lprint ( "Dynamic-EID {}" . format ( lisp . bold ( lisp . green ( oOOo0oOo0 , False ) + " activity timeout" ,
   # II111iiii . I1IiiI
 False ) ) )
   Iiii . append ( oOOo0oOo0 )
   if 1 - 1: Oo0Ooo / o0oOOo0O0Ooo % iII111i * IiII . i11iIiiIii
   if 2 - 2: I1ii11iIi11i * I11i - iIii1I11I1II1 + I1IiiI . oO0o % iII111i
   if 92 - 92: iII111i
   if 25 - 25: Oo0Ooo - I1IiiI / OoooooooOO / o0oOOo0O0Ooo
   if 12 - 12: I1IiiI * iII111i % i1IIi % iIii1I11I1II1
  for oOOo0oOo0 in Iiii : Oo0ooOo0o . dynamic_eids . pop ( oOOo0oOo0 )
  if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
  if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
  if 51 - 51: O0 + iII111i
  if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
  if 48 - 48: O0
 threading . Timer ( lisp . LISP_DEFAULT_DYN_EID_TIMEOUT ,
 OO0oOoOO0oOO0 , [ lisp_socket ] ) . start ( )
 return
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % I1Ii111
 if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
 if 23 - 23: O0
 if 85 - 85: Ii1I
 if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
 if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
 if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
 if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
 if 77 - 77: iIii1I11I1II1 * OoO0O00
def oOooOo0 ( ) :
 if 38 - 38: I1Ii111
 if 84 - 84: iIii1I11I1II1 % iII111i / iIii1I11I1II1 % I11i
 if 45 - 45: O0
 if 26 - 26: I11i - iIii1I11I1II1 - I1IiiI / OoO0O00 . OoOoOO00 % iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo . iIii1I11I1II1 / oO0o + i1IIi
 if 42 - 42: ooOoO0o . o0oOOo0O0Ooo . ooOoO0o - I1ii11iIi11i
 if 40 - 40: ooOoO0o - i11iIiiIii / Ii1I
 if ( lisp . lisp_is_macos ( ) ) :
  I11iiI1i1 = getoutput ( "netstat -rn | egrep default | egrep UGS" )
  I1i1Iiiii = [ "lo0" ]
  for OOo0oO00ooO00 in I11iiI1i1 . split ( "\n" ) :
   oOO0O00oO0Ooo = OOo0oO00ooO00 . split ( ) [ - 1 ]
   I1i1Iiiii . append ( oOO0O00oO0Ooo )
   if 67 - 67: OoO0O00 - OOooOOo
  return ( I1i1Iiiii )
  if 36 - 36: IiII
  if 36 - 36: ooOoO0o / O0 * Oo0Ooo - OOooOOo % iIii1I11I1II1 * oO0o
  if 79 - 79: O0
  if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
  if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 oO0o0 = "Link encap"
 I1i1Iiiii = getoutput ( "ifconfig | egrep '{}'" . format ( oO0o0 ) )
 if ( I1i1Iiiii == "" ) :
  oO0o0 = ": flags="
  I1i1Iiiii = getoutput ( "ifconfig | egrep '{}'" . format ( oO0o0 ) )
  if 50 - 50: IiII
  if 46 - 46: O0 + iII111i % I1IiiI / o0oOOo0O0Ooo . IiII * I11i
 I1i1Iiiii = I1i1Iiiii . split ( "\n" )
 if 93 - 93: o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
 oOOoo00O00o = [ ]
 for O0O00Oo in I1i1Iiiii :
  oooooo0O000o = O0O00Oo . split ( oO0o0 ) [ 0 ] . replace ( " " , "" )
  oOOoo00O00o . append ( oooooo0O000o )
  if 64 - 64: I1IiiI . o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
 return ( oOOoo00O00o )
 if 66 - 66: iII111i - iII111i - i11iIiiIii . I1ii11iIi11i - OOooOOo
 if 77 - 77: OoOoOO00 - II111iiii - ooOoO0o
 if 49 - 49: II111iiii % O0 . OoOoOO00 + oO0o / I1IiiI
 if 72 - 72: ooOoO0o * Oo0Ooo . I1IiiI - II111iiii + i1IIi
 if 10 - 10: oO0o + i1IIi
 if 87 - 87: I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
def i1 ( ) :
 global II1iII1i
 global oO0oIIII
 global Oo0oO0oo0oO00
 global i111I
 global II1Ii1iI1i
 global Ii1IIii11 , Oooo0000
 if 51 - 51: Oo0Ooo / OoOoOO00 . OOooOOo * o0oOOo0O0Ooo + OoO0O00 * IiII
 lisp . lisp_i_am ( "itr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "ITR starting up" )
 if 73 - 73: OoO0O00 + OoooooooOO - O0 - Ii1I - II111iiii
 if 99 - 99: ooOoO0o . Ii1I + I1Ii111 + OoooooooOO % o0oOOo0O0Ooo
 if 51 - 51: iIii1I11I1II1
 if 34 - 34: oO0o + I1IiiI - oO0o
 lisp . lisp_get_local_interfaces ( )
 lisp . lisp_get_local_macs ( )
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 17 - 17: II111iiii % iII111i + I11i - iII111i / OOooOOo + ooOoO0o
 if 59 - 59: OOooOOo % OoOoOO00 . Ii1I * I1ii11iIi11i % I11i
 if 59 - 59: oO0o - iII111i
 if 15 - 15: I1Ii111 . i11iIiiIii . OoooooooOO / OoO0O00 % Ii1I
 II1iII1i [ 0 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV4 )
 II1iII1i [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 oO0oIIII = lisp . lisp_open_listen_socket ( "" , "lisp-itr" )
 Oo0oO0oo0oO00 = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 II1iII1i [ 2 ] = oO0oIIII
 OooooOOoo0 = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 i111I = lisp . lisp_open_listen_socket ( OooooOOoo0 ,
 str ( iiI1iIiI ) )
 if 35 - 35: I11i % OOooOOo - oO0o
 if 20 - 20: i1IIi - ooOoO0o
 if 30 - 30: I11i / I1IiiI
 if 35 - 35: II111iiii % OOooOOo . ooOoO0o + ooOoO0o % II111iiii % II111iiii
 II1Ii1iI1i = lisp . lisp_open_listen_socket ( "0.0.0.0" ,
 str ( OOo ) )
 if 72 - 72: II111iiii + i1IIi + o0oOOo0O0Ooo
 if 94 - 94: oO0o . i1IIi - o0oOOo0O0Ooo % O0 - OoO0O00
 if 72 - 72: Ii1I
 if 1 - 1: OoO0O00 * IiII * OoooooooOO + ooOoO0o
 Ii1IIii11 = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 Ii1IIii11 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  Oooo0000 = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
  if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
  if 26 - 26: Ii1I % I1ii11iIi11i
  if 76 - 76: IiII * iII111i
  if 52 - 52: OOooOOo
  if 19 - 19: I1IiiI
  if 25 - 25: Ii1I / ooOoO0o
  if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 lisp . lisp_ipc_socket = oO0oIIII
 if 71 - 71: I1Ii111 . II111iiii
 if 62 - 62: OoooooooOO . I11i
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
 if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 threading . Thread ( target = oOooO ) . start ( )
 if 10 - 10: OoOoOO00 % OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
 if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 lisp . lisp_load_checkpoint ( )
 if 23 - 23: i11iIiiIii
 if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
 if 81 - 81: IiII % i1IIi . iIii1I11I1II1
 if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
 if 31 - 31: OOooOOo
 if 23 - 23: I1Ii111 . IiII
 if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
 i11 = threading . Timer ( 60 , oo0 ,
 [ II1iII1i , iiI1iIiI ] )
 i11 . start ( )
 if 42 - 42: Oo0Ooo
 if 76 - 76: I1IiiI * iII111i % I1Ii111
 if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
 if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
 threading . Timer ( lisp . LISP_DEFAULT_DYN_EID_TIMEOUT ,
 OO0oOoOO0oOO0 , [ oO0oIIII ] ) . start ( )
 return ( True )
 if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
 if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
 if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
 if 42 - 42: I1IiiI
 if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
 if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
 if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
 if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
def I1 ( ) :
 OooooO0oOOOO = open ( "./lisp.config" , "r" )
 if 100 - 100: iII111i % OOooOOo
 OOO = False
 iII1 = 0
 for OOo0oO00ooO00 in OooooO0oOOOO :
  if ( OOo0oO00ooO00 == "lisp database-mapping {\n" ) : OOO = True
  if ( OOo0oO00ooO00 == "}\n" ) : OOO = False
  if ( OOO == False ) : continue
  if ( OOo0oO00ooO00 [ 0 ] == " " and OOo0oO00ooO00 . find ( "prefix {" ) != - 1 ) : iII1 += 1
  if 57 - 57: o0oOOo0O0Ooo . i1IIi . IiII * i11iIiiIii + I1Ii111 . IiII
 OooooO0oOOOO . close ( )
 return ( iII1 )
 if 57 - 57: I1Ii111
 if 32 - 32: Ii1I - Oo0Ooo % OoooooooOO . iII111i / IiII + I1IiiI
 if 76 - 76: ooOoO0o
 if 73 - 73: O0 * iII111i + Ii1I + ooOoO0o
 if 40 - 40: II111iiii . OoOoOO00 * I1Ii111 + OOooOOo + OOooOOo
 if 9 - 9: I11i % OoooooooOO . oO0o % I11i
 if 32 - 32: i11iIiiIii
 if 31 - 31: iIii1I11I1II1 / OoO0O00 / I1ii11iIi11i
 if 41 - 41: Oo0Ooo
 if 10 - 10: Oo0Ooo / Oo0Ooo / I1Ii111 . I1Ii111
def OOoo ( ) :
 if 50 - 50: OoO0O00
 if 43 - 43: II111iiii . oO0o / I1ii11iIi11i
 if 20 - 20: I1IiiI
 if 95 - 95: iII111i - I1IiiI
 if 34 - 34: ooOoO0o * I1IiiI . i1IIi * ooOoO0o / ooOoO0o
 iII1 = I1 ( )
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 if 41 - 41: i1IIi - I11i - Ii1I
 if 8 - 8: OoO0O00 + I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo % o0oOOo0O0Ooo * oO0o
 if 9 - 9: Oo0Ooo - i11iIiiIii - OOooOOo * Ii1I + ooOoO0o
 if 44 - 44: II111iiii
 OOOO0OOO = os . getenv ( "LISP_ITR_WAIT_TIME" )
 OOOO0OOO = 1 if ( OOOO0OOO == None ) else int ( OOOO0OOO )
 if 3 - 3: OoO0O00
 if 97 - 97: I1Ii111
 if 15 - 15: i1IIi + OoOoOO00
 if 48 - 48: I1IiiI % iII111i / iIii1I11I1II1
 if 85 - 85: OoooooooOO % i1IIi * OoooooooOO / I1ii11iIi11i
 while ( iII1 != len ( lisp . lisp_db_list ) ) :
  lisp . lprint ( ( "Waiting {} second(s) for {} database-mapping EID-" + "prefixes, {} processed so far ..." ) . format ( OOOO0OOO , iII1 ,
  # OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 len ( lisp . lisp_db_list ) ) )
  time . sleep ( OOOO0OOO )
  if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
  if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
  if 71 - 71: O0 - iIii1I11I1II1
  if 12 - 12: OOooOOo / o0oOOo0O0Ooo
  if 42 - 42: Oo0Ooo
  if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 iii11I = [ ]
 I1Iii1 = [ ]
 for Oo0ooOo0o in lisp . lisp_db_list :
  if ( Oo0ooOo0o . eid . is_ipv4 ( ) or Oo0ooOo0o . eid . is_ipv6 ( ) or Oo0ooOo0o . eid . is_mac ( ) ) :
   oOOo0oOo0 = Oo0ooOo0o . eid . print_prefix_no_iid ( )
   if ( Oo0ooOo0o . dynamic_eid_configured ( ) ) : I1Iii1 . append ( oOOo0oOo0 )
   iii11I . append ( oOOo0oOo0 )
   if 30 - 30: OoooooooOO - OoOoOO00
   if 75 - 75: iIii1I11I1II1 - Ii1I . Oo0Ooo % i11iIiiIii % I11i
 return ( iii11I , I1Iii1 )
 if 55 - 55: iII111i . II111iiii % OoO0O00 * iII111i + ooOoO0o + Ii1I
 if 24 - 24: Oo0Ooo - oO0o % iIii1I11I1II1 . i1IIi / O0
 if 36 - 36: I1IiiI - I11i
 if 29 - 29: ooOoO0o * OOooOOo
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
 if 54 - 54: i1IIi + II111iiii
def oOooO ( ) :
 global i1iIIi1
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 lisp . lisp_set_exception ( )
 if 5 - 5: Ii1I
 if 46 - 46: IiII
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if 17 - 17: OOooOOo / OOooOOo / I11i
 iii11I , I1Iii1 = OOoo ( )
 if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
 if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
 if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 if 9 - 9: Ii1I
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
 if 27 - 27: O0
 OOO0oOOoo = None
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . lprint ( lisp . bold ( "Data-plane packet capture disabled" , False ) )
  OOO0oOOoo = "(udp src port 4342 and ip[28] == 0x28)" + " or (ip[16] >= 224 and ip[16] < 240 and (ip[28] & 0xf0) == 0x30)"
  if 52 - 52: o0oOOo0O0Ooo % Oo0Ooo
  if 64 - 64: O0 % I11i % O0 * OoO0O00 . oO0o + I1IiiI
  lisp . lprint ( "Control-plane capture: '{}'" . format ( OOO0oOOoo ) )
 else :
  lisp . lprint ( "Capturing packets for source-EIDs {}" . format ( lisp . green ( str ( iii11I ) , False ) ) )
  if 75 - 75: I11i . OoooooooOO % o0oOOo0O0Ooo * I11i % OoooooooOO
  if 13 - 13: IiII / i11iIiiIii % II111iiii % I11i . I1ii11iIi11i
 if ( lisp . lisp_pitr ) : lisp . lprint ( "Configured for PITR functionality" )
 if 8 - 8: OoOoOO00 + Oo0Ooo - II111iiii
 if 11 - 11: i1IIi % i11iIiiIii - i1IIi * OoOoOO00
 if 39 - 39: I1Ii111
 if 86 - 86: I11i * I1IiiI + I11i + II111iiii
 if 8 - 8: I1Ii111 - iII111i / ooOoO0o
 if 96 - 96: OoOoOO00
 IIiiI = lisp . lisp_l2_overlay
 if ( IIiiI == False ) :
  if ( lisp . lisp_is_linux ( ) ) : III1i11 ( iii11I , I1Iii1 )
  if 25 - 25: OoO0O00
  if 24 - 24: IiII * i11iIiiIii * OOooOOo
  if 85 - 85: o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . O0 % I1Ii111
  if 90 - 90: Oo0Ooo % O0 * iIii1I11I1II1 . iII111i
  if 8 - 8: ooOoO0o + II111iiii / iII111i / I11i
  if 74 - 74: O0 / i1IIi
 if ( OOO0oOOoo == None ) :
  if ( lisp . lisp_pitr ) :
   OoO = Iiiiii111i1ii ( iii11I , [ ] , False , True )
  else :
   OoO = Iiiiii111i1ii ( iii11I , I1Iii1 , IIiiI ,
 False )
   if 25 - 25: OOooOOo - ooOoO0o / i11iIiiIii
 else :
  OoO = OOO0oOOoo
  if 41 - 41: i1IIi % iII111i + iIii1I11I1II1
  if 2 - 2: iIii1I11I1II1 * Oo0Ooo % oO0o - II111iiii - iII111i
  if 3 - 3: I1Ii111
  if 45 - 45: I1Ii111
  if 83 - 83: OoOoOO00 . OoooooooOO
 I1i1Iiiii = oOooOo0 ( )
 Oo0ooo = os . getenv ( "LISP_PCAP_LIST" )
 lisp . lprint ( "User pcap-list: {}, active-interfaces: {}" . format ( Oo0ooo ,
 I1i1Iiiii ) )
 if ( Oo0ooo == None ) :
  IIiIiiii = ""
  O0000OOO0 = [ ]
 else :
  ooo0 = list ( set ( Oo0ooo . split ( ) ) & set ( I1i1Iiiii ) )
  O0000OOO0 = list ( set ( Oo0ooo . split ( ) ) ^ set ( I1i1Iiiii ) )
  IIiIiiii = "user-selected "
  I1i1Iiiii = ooo0
  if 78 - 78: ooOoO0o
  if 53 - 53: ooOoO0o * OOooOOo . iII111i / O0 * ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  if 92 - 92: I11i . I1Ii111
  if 85 - 85: I1ii11iIi11i . I1Ii111
 O0O0Ooooo000 = ( OoO . find ( "ether host" ) != - 1 )
 for o000oOoo0o000 in I1i1Iiiii :
  if ( o000oOoo0o000 in [ "lo" , "lispers.net" ] and O0O0Ooooo000 ) :
   lisp . lprint ( ( "Capturing suppressed on interface {}, " + "MAC filters configured" ) . format ( o000oOoo0o000 ) )
   if 40 - 40: i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - I11i . i1IIi
   continue
   if 99 - 99: O0 * I11i
   if 64 - 64: II111iiii + O0 / iIii1I11I1II1 / Oo0Ooo . ooOoO0o % IiII
  iiI1I1ii = [ o000oOoo0o000 , OoO , i1iIIi1 ]
  lisp . lprint ( "Capturing packets on {}interface {}" . format ( IIiIiiii , o000oOoo0o000 ) )
  threading . Thread ( target = o0ooO , args = iiI1I1ii ) . start ( )
  if 74 - 74: O0 * oO0o - i11iIiiIii + I1Ii111
 if ( OOO0oOOoo ) : return
 if 17 - 17: iIii1I11I1II1 . OoooooooOO / I11i % II111iiii % i1IIi / i11iIiiIii
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 if 85 - 85: OoOoOO00 + OOooOOo
 if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
 if 27 - 27: Ii1I
 oO0OO0 = "(udp src port 4342 and ip[28] == 0x28)"
 for o000oOoo0o000 in O0000OOO0 :
  iiI1I1ii = [ o000oOoo0o000 , oO0OO0 , i1iIIi1 ]
  lisp . lprint ( "Capture RLOC-probe replies on RLOC interface {}" . format ( o000oOoo0o000 ) )
  if 82 - 82: IiII - IiII + OoOoOO00
  threading . Thread ( target = o0ooO , args = iiI1I1ii ) . start ( )
  if 8 - 8: o0oOOo0O0Ooo % iII111i * oO0o % Ii1I . ooOoO0o / ooOoO0o
 return
 if 81 - 81: OoO0O00
 if 99 - 99: oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
def Ii1ii111i1 ( ) :
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
 if ( I11 ) : I11 . cancel ( )
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
 if 13 - 13: Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( i111I , "" )
 lisp . lisp_close_socket ( II1Ii1iI1i , "" )
 lisp . lisp_close_socket ( oO0oIIII , "lisp-itr" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lispers.net-itr" )
 return
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
def Ii1iI111 ( packet , device , input_interface , macs , my_sa ) :
 global II1iII1i
 global iiI1iIiI
 global Ii1IIii11 , Oooo0000
 global oO0oIIII
 if 51 - 51: IiII * O0 / II111iiii . Ii1I % OOooOOo / I1IiiI
 if 9 - 9: I1IiiI % I1IiiI % II111iiii
 if 30 - 30: IiII + I1Ii111 - IiII . IiII - II111iiii + O0
 if 86 - 86: i1IIi
 IIi11IIiIii1 = packet
 packet , I1iIII1 , iIii , oOo0OoOOo0 = lisp . lisp_is_rloc_probe ( packet , 1 )
 if ( IIi11IIiIii1 != packet ) :
  if ( I1iIII1 == None ) : return
  lisp . lisp_parse_packet ( II1iII1i , packet , I1iIII1 , iIii , oOo0OoOOo0 )
  return
  if 30 - 30: I1ii11iIi11i % I1IiiI
  if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 packet = lisp . lisp_packet ( packet )
 if ( packet . decode ( False , None , None ) == None ) : return
 if 59 - 59: OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
 if ( my_sa ) : input_interface = device
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if 10 - 10: II111iiii . iII111i
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 ooO0oO00O0o = packet . inner_source
 OO00Oo = lisp . lisp_get_interface_instance_id ( input_interface , ooO0oO00O0o )
 packet . inner_dest . instance_id = OO00Oo
 packet . inner_source . instance_id = OO00Oo
 if 70 - 70: I1Ii111
 if 16 - 16: iII111i - OoooooooOO % Oo0Ooo
 if 36 - 36: OOooOOo
 if 84 - 84: I1Ii111 . OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i
 if ( macs != "" ) : macs = ", MACs: " + macs + ","
 packet . print_packet ( "Receive {}{}" . format ( device , macs ) , False )
 if 57 - 57: I1IiiI % I11i - OOooOOo . I1IiiI / Oo0Ooo % iII111i
 if 56 - 56: oO0o . iII111i . IiII * OoOoOO00 . ooOoO0o / O0
 if 23 - 23: i1IIi + iII111i + IiII + OoO0O00
 if 12 - 12: iIii1I11I1II1 - I1ii11iIi11i + i11iIiiIii
 if ( device != input_interface and device != "lispers.net" ) :
  lisp . dprint ( "Not our MAC address on interface {}, pcap interface {}" . format ( input_interface , device ) )
  if 10 - 10: I1IiiI - i1IIi - ooOoO0o % Oo0Ooo
  return
  if 6 - 6: I1ii11iIi11i + oO0o
  if 48 - 48: iIii1I11I1II1 % i1IIi % iII111i + ooOoO0o
 Iiii11iIi1 = lisp . lisp_decent_push_configured
 if ( Iiii11iIi1 ) :
  i1iI11I1II1 = packet . inner_dest . is_multicast_address ( )
  ii11II1i = packet . inner_source . is_local ( )
  Iiii11iIi1 = ( ii11II1i and i1iI11I1II1 )
  if 58 - 58: Oo0Ooo . IiII - Oo0Ooo - I1Ii111 * Ii1I
  if 28 - 28: OoOoOO00 * OoO0O00 . I11i % I11i / I11i * I1Ii111
 if ( Iiii11iIi1 == False ) :
  if 64 - 64: II111iiii - I1IiiI
  if 68 - 68: ooOoO0o - OOooOOo - iIii1I11I1II1 / OoOoOO00 + OOooOOo - OoO0O00
  if 75 - 75: iII111i / o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii
  if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
  Oo0ooOo0o = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False )
  if ( Oo0ooOo0o == None ) :
   lisp . dprint ( "Packet received from non-EID source" )
   return
   if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
   if 2 - 2: Ii1I - IiII
   if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
   if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
   if 71 - 71: OoooooooOO
  if ( Oo0ooOo0o . dynamic_eid_configured ( ) ) :
   iIIIII1iiiiII = lisp . lisp_allow_dynamic_eid ( input_interface ,
 packet . inner_source )
   if ( iIIIII1iiiiII ) :
    lisp . lisp_itr_discover_eid ( Oo0ooOo0o , packet . inner_source ,
 input_interface , iIIIII1iiiiII , oO0oIIII )
   else :
    oooO = lisp . green ( packet . inner_source . print_address ( ) , False )
    lisp . dprint ( "Disallow dynamic-EID {} on interface {}" . format ( oooO ,
 input_interface ) )
    return
    if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
    if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
    if 45 - 45: IiII
  if ( packet . inner_source . is_local ( ) and
 packet . udp_dport == lisp . LISP_CTRL_PORT ) : return
  if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
  if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
  if 34 - 34: O0
  if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
  if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 Ii1II = False
 if ( packet . inner_version == 4 ) :
  Ii1II , packet . packet = lisp . lisp_ipv4_input ( packet . packet )
  if ( packet . packet == None ) : return
  packet . inner_ttl -= 1
 elif ( packet . inner_version == 6 ) :
  packet . packet = lisp . lisp_ipv6_input ( packet )
  if ( packet . packet == None ) : return
  packet . inner_ttl -= 1
 else :
  packet . packet = lisp . lisp_mac_input ( packet . packet )
  if ( packet . packet == None ) : return
  packet . encap_port = lisp . LISP_L2_DATA_PORT
  if 67 - 67: iIii1I11I1II1 - Ii1I + o0oOOo0O0Ooo
  if 97 - 97: OOooOOo
  if 92 - 92: Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - I1ii11iIi11i . o0oOOo0O0Ooo
  if 95 - 95: I1Ii111 % I1IiiI
  if 42 - 42: OoooooooOO - iII111i / OoooooooOO / Ii1I
  if 86 - 86: ooOoO0o * o0oOOo0O0Ooo + O0 / I11i . I1IiiI + iIii1I11I1II1
 if ( oo0O000OoO == False ) :
  Oo0ooOo0o = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( Oo0ooOo0o and Oo0ooOo0o . dynamic_eid_configured == False ) :
   lisp . dprint ( ( "Packet destined to local EID-prefix {}, " + "natively forwarding" ) . format ( Oo0ooOo0o . print_eid_tuple ( ) ) )
   if 66 - 66: oO0o
   packet . send_packet ( Ii1IIii11 , packet . inner_dest )
   return
   if 91 - 91: oO0o + I1IiiI
   if 59 - 59: I1IiiI + i11iIiiIii + i1IIi / I11i
   if 44 - 44: I11i . OoOoOO00 * I1IiiI + OoooooooOO - iII111i - IiII
   if 15 - 15: IiII / O0 . o0oOOo0O0Ooo . i11iIiiIii
   if 59 - 59: I1Ii111 - o0oOOo0O0Ooo - ooOoO0o
   if 48 - 48: i1IIi + I11i % OoOoOO00 / Oo0Ooo - o0oOOo0O0Ooo
 OOoOOo0O00O = lisp . lisp_map_cache_lookup ( packet . inner_source , packet . inner_dest )
 if ( OOoOOo0O00O ) : OOoOOo0O00O . add_recent_source ( packet . inner_source )
 if 36 - 36: O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 OOoo0oo = Oo0ooOo0o . secondary_iid if ( Oo0ooOo0o != None ) else None
 if ( OOoo0oo and OOoOOo0O00O and OOoOOo0O00O . action == lisp . LISP_NATIVE_FORWARD_ACTION ) :
  ooOooo0OO = packet . inner_dest
  ooOooo0OO . instance_id = OOoo0oo
  OOoOOo0O00O = lisp . lisp_map_cache_lookup ( packet . inner_source , ooOooo0OO )
  if ( OOoOOo0O00O ) : OOoOOo0O00O . add_recent_source ( packet . inner_source )
  if 2 - 2: II111iiii - OoO0O00 . IiII * iII111i / oO0o
  if 80 - 80: OOooOOo / I11i / OoOoOO00 + i1IIi - Oo0Ooo
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00
  if 15 - 15: OoOoOO00
  if 62 - 62: Ii1I
 if ( OOoOOo0O00O == None or lisp . lisp_mr_or_pubsub ( OOoOOo0O00O . action ) ) :
  if ( lisp . lisp_rate_limit_map_request ( packet . inner_dest ) ) : return
  if 51 - 51: OoOoOO00
  I11IIIiIi11 = ( OOoOOo0O00O and OOoOOo0O00O . action == lisp . LISP_SEND_PUBSUB_ACTION )
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 packet . inner_source , packet . inner_dest , None , I11IIIiIi11 )
  if 39 - 39: Ii1I % O0 % OoOoOO00 . i1IIi
  if ( packet . is_trace ( ) ) :
   lisp . lisp_trace_append ( packet , reason = "map-cache miss" )
   if 86 - 86: OoO0O00 * OoooooooOO
  return
  if 71 - 71: iIii1I11I1II1 - OOooOOo . I1IiiI % OoooooooOO + OOooOOo
  if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
  if 31 - 31: I11i % OOooOOo * I11i
  if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
  if 1 - 1: iIii1I11I1II1
  if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 if ( OOoOOo0O00O and OOoOOo0O00O . is_active ( ) and OOoOOo0O00O . has_ttl_elapsed ( ) ) :
  if ( lisp . lisp_rate_limit_map_request ( packet . inner_dest ) == False ) :
   lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( OOoOOo0O00O . print_eid_tuple ( ) , False ) ) )
   if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
   lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 packet . inner_source , packet . inner_dest , None )
   if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
   if 4 - 4: OoooooooOO . ooOoO0o
   if 78 - 78: I1ii11iIi11i + I11i - O0
   if 10 - 10: I1Ii111 % I1IiiI
   if 97 - 97: OoooooooOO - I1Ii111
   if 58 - 58: iIii1I11I1II1 + O0
   if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 OOoOOo0O00O . last_refresh_time = time . time ( )
 OOoOOo0O00O . stats . increment ( len ( packet . packet ) )
 if 46 - 46: i11iIiiIii - O0 . oO0o
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 i1iiiIii11 , OOoOOO000O0 , oOo0 , II1i11I1 , iiIiIiII , i1I1 = OOoOOo0O00O . select_rloc ( packet , oO0oIIII )
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
 if ( i1iiiIii11 == None and iiIiIiII == None ) :
  if ( II1i11I1 == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   packet . send_packet ( Ii1IIii11 , packet . inner_dest )
   if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
   if ( packet . is_trace ( ) ) :
    lisp . lisp_trace_append ( packet , reason = "not an EID" )
    if 57 - 57: O0 % OoOoOO00 % oO0o
   return
   if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  IiIIi1I1I11Ii = "No reachable RLOCs found"
  lisp . dprint ( IiIIi1I1I11Ii )
  if ( packet . is_trace ( ) ) : lisp . lisp_trace_append ( packet , reason = IiIIi1I1I11Ii )
  return
  if 64 - 64: OoooooooOO
 if ( i1iiiIii11 and i1iiiIii11 . is_null ( ) ) :
  IiIIi1I1I11Ii = "Drop action RLOC found"
  lisp . dprint ( IiIIi1I1I11Ii )
  if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
  if ( packet . is_trace ( ) ) : lisp . lisp_trace_append ( packet , reason = IiIIi1I1I11Ii )
  return
  if 23 - 23: II111iiii / oO0o
  if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
  if 19 - 19: I11i
  if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
  if 27 - 27: OOooOOo
 packet . outer_tos = packet . inner_tos
 packet . outer_ttl = 32 if ( Ii1II ) else packet . inner_ttl
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if ( i1iiiIii11 ) :
  packet . outer_dest . copy_address ( i1iiiIii11 )
  IIiIiiiIIIIi1 = packet . outer_dest . afi_to_version ( )
  packet . outer_version = IIiIiiiIIIIi1
  iIi11 = lisp . lisp_myrlocs [ 0 ] if ( IIiIiiiIIIIi1 == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 81 - 81: I11i / OoO0O00 % OoooooooOO * oO0o / oO0o
  packet . outer_source . copy_address ( iIi11 )
  if 28 - 28: i11iIiiIii / o0oOOo0O0Ooo . iIii1I11I1II1 / II111iiii
  if ( packet . is_trace ( ) ) :
   if ( lisp . lisp_trace_append ( packet , rloc_entry = i1I1 ) == False ) : return
   if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
   if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
   if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
   if 32 - 32: i11iIiiIii - I1Ii111
   if 53 - 53: OoooooooOO - IiII
   if 87 - 87: oO0o . I1IiiI
  if ( packet . encode ( oOo0 ) == None ) : return
  if ( len ( packet . packet ) <= 1500 ) : packet . print_packet ( "Send" , True )
  if 17 - 17: Ii1I . i11iIiiIii
  if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
  if 63 - 63: oO0o
  if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
  iIIi1iiI1i11 = Oooo0000 if IIiIiiiIIIIi1 == 6 else Ii1IIii11
  packet . send_packet ( iIIi1iiI1i11 , packet . outer_dest )
  if 56 - 56: OoooooooOO
 elif ( iiIiIiII ) :
  if 30 - 30: i11iIiiIii + oO0o
  if 38 - 38: IiII . Ii1I
  if 24 - 24: o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
  if 12 - 12: iII111i . IiII . OoOoOO00 / O0
  if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
  IIo00ooo = iiIiIiII . rle_nodes [ 0 ] . level
  Ii1IiIiIi1IiI = len ( packet . packet )
  for i1iiIIi1I in iiIiIiII . rle_forwarding_list :
   if ( i1iiIIi1I . level != IIo00ooo ) : return
   if 36 - 36: I1IiiI * Oo0Ooo
   packet . outer_dest . copy_address ( i1iiIIi1I . address )
   if ( Iiii11iIi1 ) : packet . inner_dest . instance_id = 0xffffff
   IIiIiiiIIIIi1 = packet . outer_dest . afi_to_version ( )
   packet . outer_version = IIiIiiiIIIIi1
   iIi11 = lisp . lisp_myrlocs [ 0 ] if ( IIiIiiiIIIIi1 == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 77 - 77: oO0o % i1IIi - Ii1I
   packet . outer_source . copy_address ( iIi11 )
   if 93 - 93: OoO0O00 * Oo0Ooo
   if ( packet . is_trace ( ) ) :
    if ( lisp . lisp_trace_append ( packet ) == False ) : return
    if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
    if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
   if ( packet . encode ( None ) == None ) : return
   if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
   if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
   if 87 - 87: oO0o - i11iIiiIii
   if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
   packet . print_packet ( "Replicate-to-L{}" . format ( i1iiIIi1I . level ) , True )
   packet . send_packet ( Ii1IIii11 , packet . outer_dest )
   if 23 - 23: I11i
   if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
   if 14 - 14: I1ii11iIi11i
   if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
   if 56 - 56: OoooooooOO - I11i - i1IIi
   I1i1I = len ( packet . packet ) - Ii1IiIiIi1IiI
   packet . packet = packet . packet [ I1i1I : : ]
   if 35 - 35: i11iIiiIii - I1IiiI
   if 99 - 99: OoO0O00 * i11iIiiIii . OoooooooOO % Oo0Ooo
   if 76 - 76: O0 . I1Ii111 * iII111i * OOooOOo . OoOoOO00 . i11iIiiIii
   if 21 - 21: o0oOOo0O0Ooo / OoOoOO00 / iIii1I11I1II1 % OOooOOo
   if 2 - 2: i11iIiiIii - II111iiii / oO0o % O0
   if 66 - 66: Oo0Ooo
 del ( packet )
 return
 if 28 - 28: IiII - IiII . i1IIi - ooOoO0o + I1IiiI . IiII
 if 54 - 54: OoOoOO00 - I1Ii111
 if 3 - 3: I1IiiI - Oo0Ooo
 if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
 if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
 if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
 if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
def Ii11iI1ii1111 ( device , not_used , packet ) :
 i111i1i = 4 if device == "lo0" else 0 if device == "lispers.net" else 14
 if 19 - 19: II111iiii - i1IIi - OOooOOo / OOooOOo + OoOoOO00
 if ( lisp . lisp_frame_logging ) :
  OO0Oooo0oo = lisp . bold ( "Received frame on interface '{}'" . format ( device ) ,
 False )
  I1i111IiIiIi1 = lisp . lisp_format_packet ( packet [ 0 : 64 ] )
  lisp . lprint ( "{}: {}" . format ( OO0Oooo0oo , I1i111IiIiIi1 ) )
  if 39 - 39: I11i - I1ii11iIi11i
  if 53 - 53: o0oOOo0O0Ooo % iII111i + ooOoO0o . Oo0Ooo - I1ii11iIi11i % o0oOOo0O0Ooo
  if 64 - 64: II111iiii
  if 40 - 40: OoOoOO00 % OoO0O00
  if 62 - 62: o0oOOo0O0Ooo
 I1i111i = ""
 iI1i = False
 O0O00Oo = device
 if ( i111i1i == 14 ) :
  I1i1Iiiii , i111iiIIII , OOO00OOo0o0Oo , iI1i = lisp . lisp_get_input_interface ( packet )
  O0O00Oo = device if ( device in I1i1Iiiii ) else I1i1Iiiii [ 0 ]
  I1i111i = lisp . lisp_format_macs ( i111iiIIII , OOO00OOo0o0Oo )
  if ( O0O00Oo . find ( "vlan" ) != - 1 ) : i111i1i += 4
  if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
  if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
  if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
  if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
  if 84 - 84: i11iIiiIii * OoO0O00
  if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
  if ( int ( OOO00OOo0o0Oo [ 1 ] , 16 ) & 1 ) : iI1i = True
  if 30 - 30: O0 + I1ii11iIi11i + II111iiii
  if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
  if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
  if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if ( i111i1i != 0 ) :
  oo0o = struct . unpack ( "H" , packet [ i111i1i - 2 : i111i1i ] ) [ 0 ]
  oo0o = socket . ntohs ( oo0o )
  if ( oo0o == 0x8100 ) :
   o0 = struct . unpack ( "I" , packet [ i111i1i : i111i1i + 4 ] ) [ 0 ]
   o0 = socket . ntohl ( o0 )
   O0O00Oo = "vlan" + str ( o0 >> 16 )
   i111i1i += 4
  elif ( oo0o == 0x806 ) :
   lisp . dprint ( "Dropping ARP packets, host should have default route" )
   return
   if 35 - 35: i11iIiiIii - I1IiiI / OOooOOo + Ii1I * oO0o
   if 49 - 49: o0oOOo0O0Ooo * Ii1I + I11i + iII111i
   if 30 - 30: o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if ( lisp . lisp_l2_overlay ) : i111i1i = 0
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 Ii1iI111 ( packet [ i111i1i : : ] , device , O0O00Oo , I1i111i , iI1i )
 return
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if 47 - 47: oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if 38 - 38: O0 - IiII % I1Ii111
 if 64 - 64: iIii1I11I1II1
 if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
 if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
 if 6 - 6: Oo0Ooo % IiII * I11i / I1IiiI + Oo0Ooo
 if 39 - 39: OoOoOO00 - Oo0Ooo / iII111i * OoooooooOO
 if 100 - 100: O0 . I11i . OoO0O00 + O0 * oO0o
 if 42 - 42: oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
 if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
 if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
 if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
def III1i11 ( sources , dyn_eids ) :
 if ( os . getenv ( "LISP_NO_IPTABLES" ) != None ) :
  lisp . lprint ( "User selected to suppress installing iptables rules" )
  return
  if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
  if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 os . system ( "sudo iptables -t raw -N lisp" )
 os . system ( "sudo iptables -t raw -A PREROUTING -j lisp" )
 os . system ( "sudo ip6tables -t raw -N lisp" )
 os . system ( "sudo ip6tables -t raw -A PREROUTING -j lisp" )
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
 o00ooo0 = "sudo ip{}tables -t raw -A lisp -j ACCEPT -d {}"
 i1i1IiIi1 = [ "127.0.0.1" , "::1" , "224.0.0.0/4 -p igmp" , "ff00::/8" ,
 "fe80::/16" ]
 i1i1IiIi1 += sources + lisp . lisp_get_all_addresses ( )
 for I1iiIiI1iI1I in i1i1IiIi1 :
  if ( lisp . lisp_is_mac_string ( I1iiIiI1iI1I ) ) : continue
  III1II111Ii1 = "" if I1iiIiI1iI1I . find ( ":" ) == - 1 else "6"
  os . system ( o00ooo0 . format ( III1II111Ii1 , I1iiIiI1iI1I ) )
  if 82 - 82: I1Ii111 - OOooOOo + OoO0O00
  if 64 - 64: o0oOOo0O0Ooo . O0 * Ii1I + OoooooooOO - Oo0Ooo . OoooooooOO
  if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
  if 55 - 55: iII111i - OoO0O00
  if 100 - 100: O0
  if 79 - 79: iIii1I11I1II1
  if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
  if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 if ( lisp . lisp_pitr == False ) :
  o00ooo0 = "sudo ip{}tables -t raw -A lisp -j ACCEPT -s {} -d {}"
  ii1I111i1Ii = "sudo ip{}tables -t raw -C lisp -j ACCEPT -s {} -d {}"
  for I1iIII1 in sources :
   if ( lisp . lisp_is_mac_string ( I1iIII1 ) ) : continue
   if ( I1iIII1 in dyn_eids ) : continue
   III1II111Ii1 = "" if I1iIII1 . find ( ":" ) == - 1 else "6"
   for O0OOO0OOoO0O in sources :
    if ( lisp . lisp_is_mac_string ( O0OOO0OOoO0O ) ) : continue
    if ( O0OOO0OOoO0O in dyn_eids ) : continue
    if ( O0OOO0OOoO0O . find ( "." ) != - 1 and I1iIII1 . find ( "." ) == - 1 ) : continue
    if ( O0OOO0OOoO0O . find ( ":" ) != - 1 and I1iIII1 . find ( ":" ) == - 1 ) : continue
    if ( getoutput ( ii1I111i1Ii . format ( III1II111Ii1 , I1iIII1 , O0OOO0OOoO0O ) ) == "" ) :
     continue
     if 84 - 84: I1ii11iIi11i % iIii1I11I1II1 + OoO0O00 . I1ii11iIi11i % OoO0O00
    os . system ( o00ooo0 . format ( III1II111Ii1 , I1iIII1 , O0OOO0OOoO0O ) )
    if 93 - 93: O0
    if 85 - 85: i11iIiiIii % i11iIiiIii + O0 / OOooOOo
    if 89 - 89: Ii1I % i1IIi % oO0o
    if 53 - 53: oO0o * OoooooooOO . OoOoOO00
    if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
    if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
    if 48 - 48: i11iIiiIii % oO0o
 i11i11 = "sudo ip{}tables -t raw -A lisp -j DROP -s {}"
 for I1iIII1 in sources :
  if ( lisp . lisp_is_mac_string ( I1iIII1 ) ) : continue
  III1II111Ii1 = "" if I1iIII1 . find ( ":" ) == - 1 else "6"
  os . system ( i11i11 . format ( III1II111Ii1 , I1iIII1 ) )
  if 18 - 18: iIii1I11I1II1 + I11i * I1IiiI - OOooOOo / I1IiiI
  if 78 - 78: I11i . IiII
  if 38 - 38: OoOoOO00 + IiII
  if 15 - 15: Oo0Ooo + I11i . ooOoO0o - iIii1I11I1II1 / O0 % iIii1I11I1II1
  if 86 - 86: I1IiiI / oO0o * Ii1I
 O00o = getoutput ( "sudo iptables -t raw -S lisp" ) . split ( "\n" )
 O00o += getoutput ( "sudo ip6tables -t raw -S lisp" ) . split ( "\n" )
 lisp . lprint ( "Using kernel filters: {}" . format ( O00o ) )
 if 86 - 86: I1ii11iIi11i * II111iiii * I11i
 if 74 - 74: I1ii11iIi11i / IiII
 if 60 - 60: I1ii11iIi11i
 if 1 - 1: OoOoOO00 . i11iIiiIii % OoOoOO00 - iII111i % i1IIi + I1ii11iIi11i
 if 2 - 2: iIii1I11I1II1 * oO0o / OoOoOO00 . I11i / IiII
 if 75 - 75: OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 if 24 - 24: OoOoOO00
 if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 if ( os . getenv ( "LISP_VIRTIO_BUG" ) != None ) :
  iIIi11 = ( "sudo iptables -A POSTROUTING -t mangle -p tcp -j " + "CHECKSUM --checksum-fill; " )
  if 54 - 54: Ii1I - I1Ii111
  iIIi11 += ( "sudo iptables -A POSTROUTING -t mangle -p udp -j " + "CHECKSUM --checksum-fill; " )
  if 81 - 81: IiII . O0 + II111iiii * iIii1I11I1II1 * OOooOOo / OoOoOO00
  iIIi11 += ( "sudo ip6tables -A POSTROUTING -t mangle -p tcp -j " + "CHECKSUM --checksum-fill; " )
  if 88 - 88: II111iiii - o0oOOo0O0Ooo * I1IiiI . OoO0O00
  iIIi11 += ( "sudo ip6tables -A POSTROUTING -t mangle -p udp -j " + "CHECKSUM --checksum-fill" )
  if 65 - 65: IiII . i1IIi
  os . system ( iIIi11 )
  OOOoO0 = lisp . bold ( "virtio" , False )
  lisp . lprint ( "{} bug workaround, configure '{}'" . format ( OOOoO0 , iIIi11 ) )
  if 85 - 85: iIii1I11I1II1 / OoooooooOO % II111iiii
 return
 if 49 - 49: i11iIiiIii % OoOoOO00 + I1Ii111 . II111iiii % iII111i * OOooOOo
 if 67 - 67: i1IIi
 if 5 - 5: II111iiii . OoooooooOO
 if 57 - 57: I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if 50 - 50: OoOoOO00
 if 33 - 33: I11i
def Iiiiii111i1ii ( sources , dyn_eids , l2_overlay , pitr ) :
 if ( l2_overlay ) :
  OoO = "ether[6:4] >= 0 and ether[10:2] >= 0"
  lisp . lprint ( "Using pcap filter: '{}'" . format ( OoO ) )
  return ( OoO )
  if 98 - 98: OoOoOO00 % II111iiii
  if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
 IiiIIi1 = "(not ether proto 0x806)"
 oO0OO0 = " or (udp src port 4342 and ip[28] == 0x28)"
 iI1iIiiI = " or (ip[16] >= 224 and ip[16] < 240 and (ip[28] & 0xf0) == 0x30)"
 if 95 - 95: iIii1I11I1II1 + Oo0Ooo * II111iiii + ooOoO0o + O0 * I11i
 if 45 - 45: II111iiii % ooOoO0o % IiII + I1ii11iIi11i . i1IIi . OoOoOO00
 O0o0OO00 = ""
 iIi11i = ""
 for I1iIII1 in sources :
  ooIII1II1iii1i = I1iIII1
  if ( lisp . lisp_is_mac_string ( I1iIII1 ) ) :
   ooIII1II1iii1i = I1iIII1 . split ( "/" ) [ 0 ]
   ooIII1II1iii1i = ooIII1II1iii1i . replace ( "-" , "" )
   O0OO0oOO = [ ]
   for iIIIII1iiiiII in range ( 0 , 12 , 2 ) : O0OO0oOO . append ( ooIII1II1iii1i [ iIIIII1iiiiII : iIIIII1iiiiII + 2 ] )
   ooIII1II1iii1i = "ether host " + ":" . join ( O0OO0oOO )
   if 85 - 85: O0
   if 32 - 32: OoooooooOO . OoO0O00 / Oo0Ooo * o0oOOo0O0Ooo / o0oOOo0O0Ooo * Ii1I
  O0o0OO00 += "{}" . format ( ooIII1II1iii1i )
  if ( I1iIII1 not in dyn_eids ) : iIi11i += "{}" . format ( ooIII1II1iii1i )
  if ( sources [ - 1 ] == I1iIII1 ) : break
  O0o0OO00 += " or "
  if ( I1iIII1 not in dyn_eids ) : iIi11i += " or "
  if 19 - 19: Ii1I
 if ( iIi11i [ - 4 : : ] == " or " ) : iIi11i = iIi11i [ 0 : - 4 ]
 if 55 - 55: OOooOOo % OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
 if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
 if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
 if 71 - 71: iII111i
 if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 Iiiii111 = getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 Iiiii111 = ( Iiiii111 != "" and Iiiii111 [ 0 ] == " " )
 ooOo000OoO0o = lisp . lisp_get_loopback_address ( ) if ( Iiiii111 ) else None
 if 58 - 58: I1ii11iIi11i
 ii1I = ""
 oO0O = lisp . lisp_get_all_addresses ( )
 for I1iiIiI1iI1I in oO0O :
  if ( I1iiIiI1iI1I == ooOo000OoO0o ) : continue
  ii1I += "{}" . format ( I1iiIiI1iI1I )
  if ( oO0O [ - 1 ] == I1iiIiI1iI1I ) : break
  ii1I += " or "
  if 59 - 59: OoooooooOO * Oo0Ooo + i1IIi
  if 23 - 23: ooOoO0o
 if ( O0o0OO00 != "" ) :
  O0o0OO00 = " and (src net {})" . format ( O0o0OO00 )
  if 13 - 13: iIii1I11I1II1
 if ( iIi11i != "" ) :
  iIi11i = " and not (dst net {})" . format ( iIi11i )
  if 77 - 77: i11iIiiIii - iIii1I11I1II1 / oO0o / ooOoO0o / OoO0O00
 if ( ii1I != "" ) :
  ii1I = " and not (dst host {})" . format ( ii1I )
  if 56 - 56: OoooooooOO * O0
  if 85 - 85: OoooooooOO % OoOoOO00 * iIii1I11I1II1
  if 44 - 44: iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
  if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
  if 65 - 65: oO0o + OoOoOO00 + II111iiii
  if 77 - 77: II111iiii
  if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 if ( pitr ) :
  iIi11i = ""
  ii1I = ii1I . replace ( "dst " , "" )
  if 68 - 68: oO0o
  if 10 - 10: Ii1I
  if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
  if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
  if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 OoO = IiiIIi1 + O0o0OO00 + iIi11i + ii1I
 OoO += oO0OO0
 OoO += iI1iIiiI
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 lisp . lprint ( "Using pcap filter: '{}'" . format ( OoO ) )
 return ( OoO )
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
def o0ooO ( device , pfilter , pcap_lock ) :
 lisp . lisp_set_exception ( )
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if ( lisp . lisp_is_python2 ( ) ) :
  import pcappy
  pcap_lock . acquire ( )
  Oo00O0OO = pcappy . open_live ( device , 9000 , 0 , 100 )
  pcap_lock . release ( )
  Oo00O0OO . filter = pfilter
  Oo00O0OO . loop ( - 1 , Ii11iI1ii1111 , device )
  if 77 - 77: oO0o - Oo0Ooo - iIii1I11I1II1
 if ( lisp . lisp_is_python3 ( ) ) :
  import pcapy
  pcap_lock . acquire ( )
  Oo00O0OO = pcapy . open_live ( device , 9000 , 0 , 100 )
  pcap_lock . release ( )
  Oo00O0OO . setfilter ( pfilter )
  while ( True ) :
   IIi1i , iIiIIiii1II = Oo00O0OO . next ( )
   if ( len ( iIiIIiii1II ) == 0 ) : continue
   Ii11iI1ii1111 ( device , None , iIiIIiii1II )
   if 44 - 44: OoooooooOO . II111iiii . OOooOOo % OoooooooOO
   if 86 - 86: i11iIiiIii + O0 * IiII - OoO0O00 * OOooOOo + O0
 return
 if 95 - 95: iIii1I11I1II1 . I1Ii111 % iII111i - I1Ii111 * II111iiii
 if 89 - 89: iII111i . I1IiiI
 if 59 - 59: i1IIi % iIii1I11I1II1 + OoooooooOO
 if 97 - 97: I1ii11iIi11i / Oo0Ooo + I1Ii111
 if 32 - 32: ooOoO0o % I1Ii111 * Oo0Ooo
 if 72 - 72: ooOoO0o . iII111i - I1Ii111 - Ii1I % i1IIi
 if 56 - 56: Oo0Ooo * iII111i
 if 13 - 13: Oo0Ooo * Oo0Ooo * II111iiii * iII111i . i1IIi / IiII
 if 92 - 92: Ii1I * i11iIiiIii + iII111i * I1Ii111
def i11111III11I ( ) :
 global I11
 global II1Ii1iI1i
 global II1iII1i
 if 3 - 3: oO0o
 lisp . lisp_set_exception ( )
 if 64 - 64: OoO0O00 . I1IiiI - OoooooooOO . ooOoO0o - iII111i
 if 77 - 77: Ii1I % OoOoOO00 / II111iiii % iII111i % OoooooooOO % OoO0O00
 if 19 - 19: IiII * I1Ii111 / oO0o * I1Ii111 - OoooooooOO * I11i
 if 17 - 17: II111iiii + Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 i1I = [ II1Ii1iI1i , II1Ii1iI1i ,
 oO0oIIII ]
 lisp . lisp_build_info_requests ( i1I , None , lisp . LISP_CTRL_PORT )
 if 100 - 100: OoO0O00 % OoO0O00
 if 15 - 15: oO0o / I1Ii111
 if 37 - 37: i11iIiiIii + I1IiiI . OOooOOo % I11i % I11i
 if 26 - 26: O0
 I11 . cancel ( )
 I11 = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 i11111III11I , [ ] )
 I11 . start ( )
 return
 if 34 - 34: ooOoO0o * I1Ii111
 if 97 - 97: i11iIiiIii % oO0o / Oo0Ooo / Oo0Ooo
 if 97 - 97: II111iiii - I1Ii111 - iIii1I11I1II1 * I1IiiI
 if 54 - 54: iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
def o0oO0OO00oo0o ( kv_pair ) :
 global II1iII1i
 global iiI1iIiI
 global I11
 if 17 - 17: IiII / I1ii11iIi11i - o0oOOo0O0Ooo * I1ii11iIi11i
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 42 - 42: Ii1I
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , iiI1iIiI ] )
  lisp . lisp_test_mr_timer . start ( )
  if 68 - 68: OOooOOo . Oo0Ooo % ooOoO0o - OoooooooOO * iII111i . OOooOOo
  if 46 - 46: i11iIiiIii - OOooOOo * I1IiiI * I11i % I1ii11iIi11i * i1IIi
  if 5 - 5: O0 / ooOoO0o . Oo0Ooo + OoooooooOO
  if 97 - 97: IiII . Ii1I . Ii1I / iIii1I11I1II1 - OoO0O00 + iII111i
  if 32 - 32: OOooOOo . o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
 I11 = threading . Timer ( 0 , i11111III11I , [ ] )
 I11 . start ( )
 return
 if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
 if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
 if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
 if 26 - 26: o0oOOo0O0Ooo
 if 12 - 12: OoooooooOO / O0 + II111iiii * I1ii11iIi11i
 if 46 - 46: II111iiii - IiII * OoooooooOO / oO0o % IiII
 if 11 - 11: iIii1I11I1II1 . OoOoOO00 / IiII % ooOoO0o
 if 61 - 61: ooOoO0o - OOooOOo + OOooOOo
def iii ( kv_pair ) :
 lispconfig . lisp_database_mapping_command ( kv_pair )
 return
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
def Iiii1 ( kv_pair ) :
 global i111I
 if 36 - 36: iII111i
 if 90 - 90: O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 Oo = lisp . lisp_nat_traversal
 OooOO0oOOo0O = lisp . lisp_rloc_probing
 if 42 - 42: iII111i / o0oOOo0O0Ooo + Oo0Ooo . Oo0Ooo % OOooOOo
 if 16 - 16: i1IIi + OoO0O00 % OoOoOO00 + Ii1I * Oo0Ooo
 if 3 - 3: i11iIiiIii
 if 81 - 81: I1IiiI . OoooooooOO * Ii1I . oO0o - O0 * oO0o
 lispconfig . lisp_xtr_command ( kv_pair )
 if 72 - 72: II111iiii - OOooOOo + I1IiiI - I11i
 if 91 - 91: II111iiii
 if 53 - 53: OoO0O00 % o0oOOo0O0Ooo / OOooOOo % IiII % OoO0O00 % OoooooooOO
 if 31 - 31: I1IiiI
 O0o = ( Oo == False and lisp . lisp_nat_traversal and lisp . lisp_rloc_probing )
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 OooOOOoOoo0O0 = ( OooOO0oOOo0O == False and lisp . lisp_rloc_probing )
 if 81 - 81: IiII - o0oOOo0O0Ooo - Oo0Ooo - Ii1I / OOooOOo % I11i
 oO0Oo = 0
 if ( OooOOOoOoo0O0 ) : oO0Oo = 1
 if ( O0o ) : oO0Oo = 5
 if 72 - 72: O0 . OoOoOO00 * Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if ( oO0Oo != 0 ) :
  iII1I11 = [ i111I , i111I ]
  lisp . lisp_start_rloc_probe_timer ( oO0Oo , iII1I11 )
  if 15 - 15: I11i
  if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
  if 41 - 41: I1ii11iIi11i
  if 5 - 5: Oo0Ooo
  if 100 - 100: Ii1I + iIii1I11I1II1
  if 59 - 59: IiII
  if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if ( lisp . lisp_crypto_ephem_port == None and lisp . lisp_data_plane_security ) :
  iIii = i111I . getsockname ( ) [ 1 ]
  lisp . lisp_crypto_ephem_port = iIii
  lisp . lprint ( "Use port {} for lisp-crypto packets" . format ( iIii ) )
  III11I1 = { "type" : "itr-crypto-port" , "port" : iIii }
  lisp . lisp_write_to_dp_socket ( III11I1 )
  if 61 - 61: OoOoOO00 - OoO0O00 + I1IiiI * OOooOOo % OoO0O00
  if 24 - 24: ooOoO0o - I11i * oO0o
  if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
  if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
  if 79 - 79: IiII % OoO0O00
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
def Ii1Ii1 ( ipc ) :
 ii1IiI11I , OO0Ooo000O0 , o00o , oOo0 = ipc . split ( "%" )
 oOo0 = int ( oOo0 , 16 )
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 i11ii = lisp . lisp_get_echo_nonce ( None , o00o )
 if ( i11ii == None ) : i11ii = lisp . lisp_echo_nonce ( o00o )
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if ( OO0Ooo000O0 == "R" ) :
  i11ii . request_nonce_rcvd = oOo0
  i11ii . last_request_nonce_rcvd = lisp . lisp_get_timestamp ( )
  i11ii . echo_nonce_sent = oOo0
  i11ii . last_new_echo_nonce_sent = lisp . lisp_get_timestamp ( )
  lisp . lprint ( "Start echo-nonce mode for {}, nonce 0x{}" . format ( lisp . red ( i11ii . rloc_str , False ) , lisp . lisp_hex_string ( oOo0 ) ) )
  if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
  if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
  if 11 - 11: O0 + I1IiiI
 if ( OO0Ooo000O0 == "E" ) :
  i11ii . echo_nonce_rcvd = oOo0
  i11ii . last_echo_nonce_rcvd = lisp . lisp_get_timestamp ( )
  if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
  if ( i11ii . request_nonce_sent == oOo0 ) :
   IiIi1Ii = lisp . bold ( "echoed nonce" , False )
   lisp . lprint ( "Received {} {} from {}" . format ( IiIi1Ii ,
 lisp . lisp_hex_string ( oOo0 ) ,
 lisp . red ( i11ii . rloc_str , False ) ) )
   if 39 - 39: Ii1I
   i11ii . request_nonce_sent = None
   lisp . lprint ( "Stop request-nonce mode for {}" . format ( lisp . red ( i11ii . rloc_str , False ) ) )
   if 24 - 24: i11iIiiIii - Ii1I + oO0o * I1IiiI
   i11ii . last_good_echo_nonce_rcvd = lisp . lisp_get_timestamp ( )
  else :
   OoooOo0 = "none"
   if ( i11ii . request_nonce_sent ) :
    OoooOo0 = lisp . lisp_hex_string ( i11ii . request_nonce_sent )
    if 20 - 20: II111iiii - I11i + i1IIi + Ii1I
   lisp . lprint ( ( "Received echo-nonce 0x{} from {}, but request-" + "nonce is {}" ) . format ( lisp . lisp_hex_string ( oOo0 ) ,
   # I1IiiI
 lisp . red ( i11ii . rloc_str , False ) , OoooOo0 ) )
   if 44 - 44: I1IiiI % Ii1I * I1IiiI . Oo0Ooo + I1ii11iIi11i . OOooOOo
   if 6 - 6: IiII * OoooooooOO + I1Ii111 / Ii1I
 return
 if 35 - 35: ooOoO0o % I1IiiI - ooOoO0o - OoO0O00 - OoooooooOO
 if 46 - 46: i1IIi . i1IIi . oO0o / I11i / ooOoO0o
 if 34 - 34: OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
 if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
O00oo00oOOO0o = {
 "lisp xtr-parameters" : [ Iiii1 , {
 "rloc-probing" : [ True , "yes" , "no" ] ,
 "nonce-echoing" : [ True , "yes" , "no" ] ,
 "data-plane-security" : [ True , "yes" , "no" ] ,
 "data-plane-logging" : [ True , "yes" , "no" ] ,
 "frame-logging" : [ True , "yes" , "no" ] ,
 "flow-logging" : [ True , "yes" , "no" ] ,
 "nat-traversal" : [ True , "yes" , "no" ] ,
 "checkpoint-map-cache" : [ True , "yes" , "no" ] ,
 "ipc-data-plane" : [ True , "yes" , "no" ] ,
 "decentralized-push-xtr" : [ True , "yes" , "no" ] ,
 "decentralized-pull-xtr-modulus" : [ True , 1 , 0xff ] ,
 "decentralized-pull-xtr-dns-suffix" : [ True ] ,
 "register-reachable-rtrs" : [ True , "yes" , "no" ] ,
 "program-hardware" : [ True , "yes" , "no" ] } ] ,

 "lisp interface" : [ lispconfig . lisp_interface_command , {
 "interface-name" : [ True ] ,
 "device" : [ True ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "dynamic-eid" : [ True ] ,
 "multi-tenant-eid" : [ True ] ,
 "lisp-nat" : [ True , "yes" , "no" ] ,
 "dynamic-eid-device" : [ True ] ,
 "dynamic-eid-timeout" : [ True , 0 , 0xff ] } ] ,

 "lisp map-resolver" : [ o0oO0OO00oo0o , {
 "mr-name" : [ True ] ,
 "ms-name" : [ True ] ,
 "dns-name" : [ True ] ,
 "address" : [ True ] } ] ,

 "lisp map-server" : [ lispconfig . lisp_map_server_command , {
 "ms-name" : [ True ] ,
 "address" : [ True ] ,
 "dns-name" : [ True ] ,
 "authentication-type" : [ False , "sha1" , "sha2" ] ,
 "authentication-key" : [ False ] ,
 "encryption-key" : [ False ] ,
 "proxy-reply" : [ False , "yes" , "no" ] ,
 "want-map-notify" : [ False , "yes" , "no" ] ,
 "merge-registrations" : [ False , "yes" , "no" ] ,
 "refresh-registrations" : [ False , "yes" , "no" ] ,
 "site-id" : [ False , 1 , 0xffffffffffffffff ] } ] ,

 "lisp database-mapping" : [ iii , {
 "prefix" : [ ] ,
 "mr-name" : [ True ] ,
 "ms-name" : [ True ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "secondary-instance-id" : [ True , 0 , 0xffffffff ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] ,
 "dynamic-eid" : [ True , "yes" , "no" ] ,
 "signature-eid" : [ True , "yes" , "no" ] ,
 "register-ttl" : [ True , 1 , 0xffffffff ] ,
 "rloc" : [ ] ,
 "rloc-record-name" : [ True ] ,
 "elp-name" : [ True ] ,
 "geo-name" : [ True ] ,
 "rle-name" : [ True ] ,
 "json-name" : [ True ] ,
 "address" : [ True ] ,
 "interface" : [ True ] ,
 "priority" : [ True , 0 , 255 ] ,
 "weight" : [ True , 0 , 100 ] } ] ,

 "lisp map-cache" : [ lispconfig . lisp_map_cache_command , {
 "prefix" : [ ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] ,
 "send-map-request" : [ True , "yes" , "no" ] ,
 "subscribe-request" : [ True , "yes" , "no" ] ,
 "rloc" : [ ] ,
 "rloc-record-name" : [ True ] ,
 "rle-name" : [ True ] ,
 "elp-name" : [ True ] ,
 "address" : [ True ] ,
 "priority" : [ True , 0 , 255 ] ,
 "weight" : [ True , 0 , 100 ] } ] ,

 "lisp itr-map-cache" : [ lispconfig . lisp_map_cache_command , {
 "prefix" : [ ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] ,
 "rloc" : [ ] ,
 "rloc-record-name" : [ True ] ,
 "rle-name" : [ True ] ,
 "elp-name" : [ True ] ,
 "address" : [ True ] ,
 "priority" : [ True , 0 , 255 ] ,
 "weight" : [ True , 0 , 100 ] } ] ,

 "lisp explicit-locator-path" : [ lispconfig . lisp_elp_command , {
 "elp-name" : [ False ] ,
 "elp-node" : [ ] ,
 "address" : [ True ] ,
 "probe" : [ True , "yes" , "no" ] ,
 "strict" : [ True , "yes" , "no" ] ,
 "eid" : [ True , "yes" , "no" ] } ] ,

 "lisp replication-list-entry" : [ lispconfig . lisp_rle_command , {
 "rle-name" : [ False ] ,
 "rle-node" : [ ] ,
 "address" : [ True ] ,
 "level" : [ True , 0 , 255 ] } ] ,

 "lisp geo-coordinates" : [ lispconfig . lisp_geo_command , {
 "geo-name" : [ False ] ,
 "geo-tag" : [ False ] } ] ,

 "lisp json" : [ lispconfig . lisp_json_command , {
 "json-name" : [ False ] ,
 "json-string" : [ False ] } ] ,

 "show itr-map-cache" : [ IIiiIiI1 , { } ] ,
 "show itr-rloc-probing" : [ I1i1iii , { } ] ,
 "show itr-keys" : [ oo , { } ] ,
 "show itr-dynamic-eid" : [ lispconfig . lisp_show_dynamic_eid_command , { } ]
 }
if 5 - 5: o0oOOo0O0Ooo / I1IiiI % Ii1I . IiII
if 86 - 86: i1IIi * OoOoOO00 . O0 - Ii1I - o0oOOo0O0Ooo - OoOoOO00
if 47 - 47: OOooOOo + I11i
if 50 - 50: I1Ii111 + I1ii11iIi11i
if 4 - 4: IiII / Oo0Ooo
if 31 - 31: I1Ii111 - I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - oO0o
if ( i1 ( ) == False ) :
 lisp . lprint ( "lisp_itr_startup() failed" )
 lisp . lisp_print_banner ( "ITR abnormal exit" )
 exit ( 1 )
 if 43 - 43: iII111i + Oo0Ooo / OoooooooOO
 if 24 - 24: O0 + o0oOOo0O0Ooo * Ii1I - I1Ii111
ii = [ i111I , oO0oIIII ,
 II1Ii1iI1i , Oo0oO0oo0oO00 ]
if 20 - 20: iII111i / OOooOOo
if 28 - 28: ooOoO0o * I11i % i11iIiiIii * iII111i / Ii1I
if 41 - 41: OOooOOo - o0oOOo0O0Ooo + Ii1I
if 15 - 15: I11i / o0oOOo0O0Ooo + Ii1I
O0oo00o = True
IIi1i1 = [ i111I ] * 3
o0O0Ooo = [ II1Ii1iI1i ] * 3
if 79 - 79: ooOoO0o . oO0o / oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
while ( True ) :
 try : iI1iiIi1 , i1iiiIi1Iii , ii1IiI11I = select . select ( ii , [ ] , [ ] )
 except : break
 if 54 - 54: ooOoO0o . iIii1I11I1II1 * i1IIi
 if 44 - 44: oO0o + I1ii11iIi11i * OOooOOo - i11iIiiIii / iIii1I11I1II1
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if ( lisp . lisp_ipc_data_plane and Oo0oO0oo0oO00 in iI1iiIi1 ) :
  lisp . lisp_process_punt ( Oo0oO0oo0oO00 , II1iII1i ,
 iiI1iIiI )
  if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
  if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
  if 46 - 46: OoOoOO00 - O0
  if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
  if 49 - 49: o0oOOo0O0Ooo
 if ( i111I in iI1iiIi1 ) :
  OO0Ooo000O0 , I1iIII1 , iIii , iIiIIiii1II = lisp . lisp_receive ( IIi1i1 [ 0 ] ,
 False )
  if ( I1iIII1 == "" ) : break
  if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
  if ( lisp . lisp_is_rloc_probe_reply ( iIiIIiii1II [ 0 : 1 ] ) ) :
   lisp . lprint ( "ITR ignoring RLOC-probe reply, using pcap" )
   continue
   if 68 - 68: Oo0Ooo
  lisp . lisp_parse_packet ( IIi1i1 , iIiIIiii1II , I1iIII1 , iIii )
  if 22 - 22: OOooOOo
  if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
  if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
  if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
  if 94 - 94: i1IIi
 if ( II1Ii1iI1i in iI1iiIi1 ) :
  OO0Ooo000O0 , I1iIII1 , iIii , iIiIIiii1II = lisp . lisp_receive ( o0O0Ooo [ 0 ] ,
 False )
  if ( I1iIII1 == "" ) : break
  if 36 - 36: I1IiiI + Oo0Ooo
  if ( lisp . lisp_is_rloc_probe_reply ( iIiIIiii1II [ 0 : 1 ] ) ) :
   lisp . lprint ( "ITR ignoring RLOC-probe reply, using pcap" )
   continue
   if 46 - 46: iII111i
  ooIiI11i1I11111 = lisp . lisp_parse_packet ( o0O0Ooo , iIiIIiii1II , I1iIII1 , iIii )
  if 34 - 34: I1IiiI * OoOoOO00 * oO0o + I1ii11iIi11i
  if 39 - 39: I1ii11iIi11i / i1IIi * IiII - I1IiiI
  if 74 - 74: O0 - II111iiii + i1IIi . I1Ii111 . I1ii11iIi11i
  if 95 - 95: II111iiii / Ii1I - ooOoO0o - II111iiii - i11iIiiIii
  if 85 - 85: o0oOOo0O0Ooo / I1Ii111
  if ( ooIiI11i1I11111 ) :
   iII1I11 = [ i111I , i111I ]
   lisp . lisp_start_rloc_probe_timer ( 0 , iII1I11 )
   if 67 - 67: I11i % oO0o
   if 39 - 39: i11iIiiIii + IiII
   if 7 - 7: iIii1I11I1II1 - i1IIi
   if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
   if 25 - 25: II111iiii / OoO0O00
   if 64 - 64: O0 % ooOoO0o
   if 40 - 40: o0oOOo0O0Ooo + I11i
 if ( oO0oIIII in iI1iiIi1 ) :
  OO0Ooo000O0 , I1iIII1 , iIii , iIiIIiii1II = lisp . lisp_receive ( oO0oIIII , True )
  if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
  if ( I1iIII1 == "" ) : break
  if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
  if ( OO0Ooo000O0 == "command" ) :
   iIiIIiii1II = iIiIIiii1II . decode ( )
   if ( iIiIIiii1II == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 47 - 47: OoooooooOO
   if ( iIiIIiii1II . find ( "nonce%" ) != - 1 ) :
    Ii1Ii1 ( iIiIIiii1II )
    continue
    if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
   lispconfig . lisp_process_command ( oO0oIIII , OO0Ooo000O0 ,
 iIiIIiii1II , "lisp-itr" , [ O00oo00oOOO0o ] )
  elif ( OO0Ooo000O0 == "api" ) :
   iIiIIiii1II = iIiIIiii1II . decode ( )
   lisp . lisp_process_api ( "lisp-itr" , oO0oIIII , iIiIIiii1II )
  elif ( OO0Ooo000O0 == "data-packet" ) :
   Ii1iI111 ( iIiIIiii1II , "ipc" )
  else :
   if ( lisp . lisp_is_rloc_probe_reply ( iIiIIiii1II [ 0 : 1 ] ) ) :
    lisp . lprint ( "ITR ignoring RLOC-probe request, using pcap" )
    continue
    if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
   lisp . lisp_parse_packet ( II1iII1i , iIiIIiii1II , I1iIII1 , iIii )
   if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
   if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
   if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
   if 26 - 26: OOooOOo * Oo0Ooo
   if 31 - 31: I11i * oO0o . Ii1I
Ii1ii111i1 ( )
lisp . lisp_print_banner ( "ITR normal exit" )
exit ( 0 )
if 35 - 35: I11i
if 94 - 94: ooOoO0o / i11iIiiIii % O0
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
