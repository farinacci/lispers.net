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
import lisp
import lispconfig
import socket
import select
import threading
import pcappy
import time
import os
import commands
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
 for o0OOoo0OO0OOO in lisp . lisp_crypto_keys_by_nonce . values ( ) :
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
  for OO0OoO0o00 in Oo0ooOo0o . dynamic_eids . values ( ) :
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
 if ( lisp . lisp_is_macos ( ) ) : return ( [ "en0" , "en1" , "lo0" ] )
 if 38 - 38: I1Ii111
 if 84 - 84: iIii1I11I1II1 % iII111i / iIii1I11I1II1 % I11i
 if 45 - 45: O0
 if 26 - 26: I11i - iIii1I11I1II1 - I1IiiI / OoO0O00 . OoOoOO00 % iIii1I11I1II1
 OO = "Link encap"
 iIiIIi1 = commands . getoutput ( "ifconfig | egrep '{}'" . format ( OO ) )
 if ( iIiIIi1 == "" ) :
  OO = ": flags="
  iIiIIi1 = commands . getoutput ( "ifconfig | egrep '{}'" . format ( OO ) )
  if 7 - 7: ooOoO0o - Oo0Ooo - oO0o + ooOoO0o
  if 26 - 26: Ii1I
 iIiIIi1 = iIiIIi1 . split ( "\n" )
 if 35 - 35: Ii1I - I1IiiI % o0oOOo0O0Ooo . OoooooooOO % Ii1I
 I1i1Iiiii = [ ]
 for OOo0oO00ooO00 in iIiIIi1 :
  oOO0O00oO0Ooo = OOo0oO00ooO00 . split ( OO ) [ 0 ] . replace ( " " , "" )
  I1i1Iiiii . append ( oOO0O00oO0Ooo )
  if 67 - 67: OoO0O00 - OOooOOo
 return ( I1i1Iiiii )
 if 36 - 36: IiII
 if 36 - 36: ooOoO0o / O0 * Oo0Ooo - OOooOOo % iIii1I11I1II1 * oO0o
 if 79 - 79: O0
 if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
 if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
 if 57 - 57: OoO0O00 / ooOoO0o
 if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
def I111I1Iiii1i ( ) :
 global II1iII1i
 global oO0oIIII
 global Oo0oO0oo0oO00
 global i111I
 global II1Ii1iI1i
 global Ii1IIii11 , Oooo0000
 if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 lisp . lisp_i_am ( "itr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "ITR starting up" )
 if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 lisp . lisp_get_local_interfaces ( )
 lisp . lisp_get_local_macs ( )
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 if 49 - 49: I1IiiI - I11i
 II1iII1i [ 0 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV4 )
 II1iII1i [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 oO0oIIII = lisp . lisp_open_listen_socket ( "" , "lisp-itr" )
 Oo0oO0oo0oO00 = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 II1iII1i [ 2 ] = oO0oIIII
 OoOOoOooooOOo = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 i111I = lisp . lisp_open_listen_socket ( OoOOoOooooOOo ,
 str ( iiI1iIiI ) )
 if 87 - 87: I1IiiI
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
 if 97 - 97: O0 + OoOoOO00
 II1Ii1iI1i = lisp . lisp_open_listen_socket ( "0.0.0.0" ,
 str ( OOo ) )
 if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
 if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
 if 77 - 77: OOooOOo * iIii1I11I1II1
 if 98 - 98: I1IiiI % Ii1I * OoooooooOO
 Ii1IIii11 = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 Ii1IIii11 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  Oooo0000 = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
  if 71 - 71: Oo0Ooo % OOooOOo
  if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
  if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
  if 69 - 69: I1Ii111
  if 11 - 11: I1IiiI
  if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
  if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
 lisp . lisp_ipc_socket = oO0oIIII
 if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
 if 71 - 71: I1Ii111 + Ii1I
 if 28 - 28: OOooOOo
 if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
 threading . Thread ( target = OoOOo0OOoO ) . start ( )
 if 72 - 72: Ii1I
 if 1 - 1: OoO0O00 * IiII * OoooooooOO + ooOoO0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 lisp . lisp_load_checkpoint ( )
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
 if 76 - 76: IiII * iII111i
 if 52 - 52: OOooOOo
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 19 - 19: I1IiiI
 if 25 - 25: Ii1I / ooOoO0o
 if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 if 71 - 71: I1Ii111 . II111iiii
 i11 = threading . Timer ( 60 , oo0 ,
 [ II1iII1i , iiI1iIiI ] )
 i11 . start ( )
 if 62 - 62: OoooooooOO . I11i
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
 if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 58 - 58: I1IiiI
 threading . Timer ( lisp . LISP_DEFAULT_DYN_EID_TIMEOUT ,
 OO0oOoOO0oOO0 , [ oO0oIIII ] ) . start ( )
 return ( True )
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
 if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 if 23 - 23: i11iIiiIii
 if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
def o0ooooO0o0O ( ) :
 iiIi11iI1iii = open ( "./lisp.config" , "r" )
 if 67 - 67: O0 / I1Ii111
 OOO0000oO = False
 iI1i111I1Ii = 0
 for i11i1ii1I in iiIi11iI1iii :
  if ( i11i1ii1I == "lisp database-mapping {\n" ) : OOO0000oO = True
  if ( i11i1ii1I == "}\n" ) : OOO0000oO = False
  if ( OOO0000oO == False ) : continue
  if ( i11i1ii1I [ 0 ] == " " and i11i1ii1I . find ( "prefix {" ) != - 1 ) : iI1i111I1Ii += 1
  if 88 - 88: I11i % I1ii11iIi11i
 iiIi11iI1iii . close ( )
 return ( iI1i111I1Ii )
 if 48 - 48: ooOoO0o / I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / i1IIi
 if 92 - 92: Oo0Ooo % Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
 if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
 if 42 - 42: I1IiiI
 if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
 if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
 if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
 if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
 if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
 if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
def O00oOOooo ( ) :
 if 50 - 50: I1ii11iIi11i % O0 * o0oOOo0O0Ooo
 if 5 - 5: IiII * OoOoOO00
 if 5 - 5: I1Ii111
 if 90 - 90: I1Ii111 . ooOoO0o / Ii1I - I11i
 if 40 - 40: OoooooooOO
 iI1i111I1Ii = o0ooooO0o0O ( )
 if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
 if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
 if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
 if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
 if 19 - 19: OoO0O00 - Oo0Ooo . O0
 if 60 - 60: II111iiii + Oo0Ooo
 I1IiIiiIiIII = os . getenv ( "LISP_ITR_WAIT_TIME" )
 I1IiIiiIiIII = 1 if ( I1IiIiiIiIII == None ) else int ( I1IiIiiIiIII )
 if 8 - 8: oO0o / I1ii11iIi11i
 if 20 - 20: I1IiiI
 if 95 - 95: iII111i - I1IiiI
 if 34 - 34: ooOoO0o * I1IiiI . i1IIi * ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 while ( iI1i111I1Ii != len ( lisp . lisp_db_list ) ) :
  lisp . lprint ( ( "Waiting {} second(s) for {} database-mapping EID-" + "prefixes, {} processed so far ..." ) . format ( I1IiIiiIiIII , iI1i111I1Ii ,
  # I1ii11iIi11i % OoOoOO00 * OoO0O00 % II111iiii
 len ( lisp . lisp_db_list ) ) )
  time . sleep ( I1IiIiiIiIII )
  if 70 - 70: OoO0O00 % oO0o + OOooOOo / Ii1I % O0
  if 100 - 100: o0oOOo0O0Ooo + OOooOOo * o0oOOo0O0Ooo
  if 80 - 80: o0oOOo0O0Ooo * O0 - Ii1I
  if 66 - 66: i11iIiiIii - OOooOOo * Oo0Ooo
  if 76 - 76: i11iIiiIii + o0oOOo0O0Ooo / I1ii11iIi11i - OoO0O00 - Ii1I + I1ii11iIi11i
  if 51 - 51: iIii1I11I1II1 . ooOoO0o + iIii1I11I1II1
 oOoOO = [ ]
 Ii1i1 = [ ]
 for Oo0ooOo0o in lisp . lisp_db_list :
  if ( Oo0ooOo0o . eid . is_ipv4 ( ) or Oo0ooOo0o . eid . is_ipv6 ( ) or Oo0ooOo0o . eid . is_mac ( ) ) :
   oOOo0oOo0 = Oo0ooOo0o . eid . print_prefix_no_iid ( )
   if ( Oo0ooOo0o . dynamic_eid_configured ( ) ) : Ii1i1 . append ( oOOo0oOo0 )
   oOoOO . append ( oOOo0oOo0 )
   if 65 - 65: ooOoO0o . OoooooooOO / I1ii11iIi11i . i1IIi * OoO0O00
   if 19 - 19: i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
 return ( oOoOO , Ii1i1 )
 if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
 if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
 if 71 - 71: O0 - iIii1I11I1II1
 if 12 - 12: OOooOOo / o0oOOo0O0Ooo
 if 42 - 42: Oo0Ooo
 if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
 if 46 - 46: Oo0Ooo
 if 1 - 1: iII111i
def OoOOo0OOoO ( ) :
 global i1iIIi1
 if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
 lisp . lisp_set_exception ( )
 if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
 if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
 if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
 if 35 - 35: ooOoO0o + i1IIi % I1ii11iIi11i % I11i + oO0o
 if 17 - 17: i1IIi
 oOoOO , Ii1i1 = O00oOOooo ( )
 if 21 - 21: Oo0Ooo
 if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
 if 54 - 54: i1IIi + II111iiii
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 if 5 - 5: Ii1I
 if 46 - 46: IiII
 ii1iIi1iIiI1i = None
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . lprint ( lisp . bold ( "Data-plane packet capture disabled" , False ) )
  ii1iIi1iIiI1i = "(udp src port 4342 and ip[28] == 0x28)" + " or (ip[16] >= 224 and ip[16] < 240 and (ip[28] & 0xf0) == 0x30)"
  if 40 - 40: i1IIi % OOooOOo
  if 71 - 71: OoOoOO00
  lisp . lprint ( "Control-plane capture: '{}'" . format ( ii1iIi1iIiI1i ) )
 else :
  lisp . lprint ( "Capturing packets for source-EIDs {}" . format ( lisp . green ( str ( oOoOO ) , False ) ) )
  if 14 - 14: i11iIiiIii % OOooOOo
  if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
 if ( lisp . lisp_pitr ) : lisp . lprint ( "Configured for PITR functionality" )
 if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 if 9 - 9: Ii1I
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
 i1 = lisp . lisp_l2_overlay
 if ( i1 == False ) :
  if ( lisp . lisp_is_linux ( ) ) : OO0oOOoo ( oOoOO , Ii1i1 )
  if 52 - 52: o0oOOo0O0Ooo % Oo0Ooo
  if 64 - 64: O0 % I11i % O0 * OoO0O00 . oO0o + I1IiiI
  if 75 - 75: I11i . OoooooooOO % o0oOOo0O0Ooo * I11i % OoooooooOO
  if 13 - 13: IiII / i11iIiiIii % II111iiii % I11i . I1ii11iIi11i
  if 8 - 8: OoOoOO00 + Oo0Ooo - II111iiii
  if 11 - 11: i1IIi % i11iIiiIii - i1IIi * OoOoOO00
 if ( ii1iIi1iIiI1i == None ) :
  if ( lisp . lisp_pitr ) :
   i1I11IiI1iiII = o00oOo0oOoo ( oOoOO , [ ] , False , True )
  else :
   i1I11IiI1iiII = o00oOo0oOoo ( oOoOO , Ii1i1 , i1 ,
 False )
   if 57 - 57: OoOoOO00 - I1ii11iIi11i
 else :
  i1I11IiI1iiII = ii1iIi1iIiI1i
  if 50 - 50: I1Ii111 / i1IIi % OoO0O00 . I1IiiI / iII111i
  if 88 - 88: OOooOOo . I11i * o0oOOo0O0Ooo . OoOoOO00 / ooOoO0o . I11i
  if 10 - 10: o0oOOo0O0Ooo * Oo0Ooo % O0 * iIii1I11I1II1 . O0 % I1ii11iIi11i
  if 44 - 44: II111iiii / iII111i / I11i % II111iiii / i1IIi . Ii1I
  if 59 - 59: OoooooooOO
 iIiIIi1 = oOooOo0 ( )
 i1iiiii1 = os . getenv ( "LISP_PCAP_LIST" )
 if ( i1iiiii1 == None ) :
  O0iII1 = ""
  IIII1i = [ ]
 else :
  Ii1IIIIi1ii1I = list ( set ( i1iiiii1 . split ( ) ) & set ( iIiIIi1 ) )
  IIII1i = list ( set ( i1iiiii1 . split ( ) ) ^ set ( iIiIIi1 ) )
  O0iII1 = "user-selected "
  lisp . lprint ( "User pcap-list: {}, active-interfaces: {}" . format ( i1iiiii1 , iIiIIi1 ) )
  if 13 - 13: I1IiiI % OoOoOO00 . I1ii11iIi11i / Oo0Ooo % OOooOOo . OoooooooOO
  iIiIIi1 = Ii1IIIIi1ii1I
  if 22 - 22: IiII / i11iIiiIii
  if 62 - 62: OoO0O00 / I1ii11iIi11i
  if 7 - 7: OoooooooOO . IiII
  if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
  if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
  if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
 for oo00O00oO000o in iIiIIi1 :
  OOo00OoO = [ oo00O00oO000o , i1I11IiI1iiII , i1iIIi1 ]
  lisp . lprint ( "Capturing packets on {}interface {}" . format ( O0iII1 , oo00O00oO000o ) )
  threading . Thread ( target = iIi1 , args = OOo00OoO ) . start ( )
  if 21 - 21: I11i
 if ( ii1iIi1iIiI1i ) : return
 if 92 - 92: i11iIiiIii / I1Ii111 - iII111i % ooOoO0o * I1Ii111 + Oo0Ooo
 if 11 - 11: OoooooooOO . I1Ii111
 if 80 - 80: OoooooooOO - OOooOOo * Ii1I * I1ii11iIi11i / I1IiiI / OOooOOo
 if 13 - 13: I1Ii111 * ooOoO0o + i11iIiiIii * I1Ii111 - ooOoO0o
 if 23 - 23: iIii1I11I1II1 * i1IIi % OoooooooOO * IiII
 I1Iiiiiii = "(udp src port 4342 and ip[28] == 0x28)"
 for oo00O00oO000o in IIII1i :
  OOo00OoO = [ oo00O00oO000o , I1Iiiiiii , i1iIIi1 ]
  lisp . lprint ( "Capture RLOC-probe replies on RLOC interface {}" . format ( oo00O00oO000o ) )
  if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
  threading . Thread ( target = iIi1 , args = OOo00OoO ) . start ( )
  if 69 - 69: O0
 return
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 if 73 - 73: i1IIi / i11iIiiIii
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 if 85 - 85: OoOoOO00 + OOooOOo
def I1II ( ) :
 if 27 - 27: II111iiii / Ii1I . OOooOOo
 if 9 - 9: ooOoO0o - I1ii11iIi11i - iII111i
 if 82 - 82: IiII - IiII + OoOoOO00
 if 8 - 8: o0oOOo0O0Ooo % iII111i * oO0o % Ii1I . ooOoO0o / ooOoO0o
 if ( I11 ) : I11 . cancel ( )
 if 81 - 81: OoO0O00
 if 99 - 99: oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( i111I , "" )
 lisp . lisp_close_socket ( II1Ii1iI1i , "" )
 lisp . lisp_close_socket ( oO0oIIII , "lisp-itr" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lispers.net-itr" )
 return
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
def IIIii ( packet , device , input_interface , macs , my_sa ) :
 global II1iII1i
 global iiI1iIiI
 global Ii1IIii11 , Oooo0000
 global oO0oIIII
 if 83 - 83: IiII % o0oOOo0O0Ooo % I1IiiI . iIii1I11I1II1 - IiII
 if 88 - 88: OoooooooOO
 if 84 - 84: OoOoOO00 / I11i * iII111i / oO0o - i11iIiiIii . Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 I1iIiI11I1 = packet
 packet , i1oOOoo0o0OOOO , i1IiII1III , i1O00oo = lisp . lisp_is_rloc_probe ( packet , 1 )
 if ( I1iIiI11I1 != packet ) :
  if ( i1oOOoo0o0OOOO == None ) : return
  lisp . lisp_parse_packet ( II1iII1i , packet , i1oOOoo0o0OOOO , i1IiII1III , i1O00oo )
  return
  if 77 - 77: iII111i % OOooOOo - I11i % ooOoO0o - OoO0O00 / Oo0Ooo
  if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 packet = lisp . lisp_packet ( packet )
 if ( packet . decode ( False , None , None ) == None ) : return
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
 if 95 - 95: IiII
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
 if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if ( my_sa ) : input_interface = device
 if 2 - 2: OoooooooOO % OOooOOo
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 oOo0oO = packet . inner_source
 OO00Oo = lisp . lisp_get_interface_instance_id ( input_interface , oOo0oO )
 packet . inner_dest . instance_id = OO00Oo
 packet . inner_source . instance_id = OO00Oo
 if 5 - 5: OOooOOo - OOooOOo . Oo0Ooo + OoOoOO00 - OOooOOo . oO0o
 if 31 - 31: II111iiii - iIii1I11I1II1 - iIii1I11I1II1 % I11i
 if 12 - 12: iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo / i1IIi
 if ( macs != "" ) : macs = ", MACs: " + macs + ","
 packet . print_packet ( "Receive {}{}" . format ( device , macs ) , False )
 if 71 - 71: OoOoOO00 . i1IIi
 if 94 - 94: OOooOOo . I1Ii111
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 if 47 - 47: OoooooooOO
 if ( device != input_interface ) :
  lisp . dprint ( "Not our MAC address on interface {}, pcap interface {}" . format ( input_interface , device ) )
  if 4 - 4: I1IiiI % I11i
  return
  if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
  if 82 - 82: ooOoO0o + II111iiii
 II1i1i1iII1 = lisp . lisp_decent_push_configured
 if ( II1i1i1iII1 ) :
  oOo000 = packet . inner_dest . is_multicast_address ( )
  IIi = packet . inner_source . is_local ( )
  II1i1i1iII1 = ( IIi and oOo000 )
  if 27 - 27: OOooOOo % Ii1I
  if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
 if ( II1i1i1iII1 == False ) :
  if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
  if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
  if 98 - 98: i1IIi
  if 65 - 65: OoOoOO00 / OoO0O00 % IiII
  Oo0ooOo0o = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False )
  if ( Oo0ooOo0o == None ) :
   lisp . dprint ( "Packet received from non-EID source" )
   return
   if 45 - 45: OoOoOO00
   if 66 - 66: OoO0O00
   if 56 - 56: O0
   if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
   if 23 - 23: oO0o - OOooOOo + I11i
  if ( Oo0ooOo0o . dynamic_eid_configured ( ) ) :
   II11 = lisp . lisp_allow_dynamic_eid ( input_interface ,
 packet . inner_source )
   if ( II11 ) :
    lisp . lisp_itr_discover_eid ( Oo0ooOo0o , packet . inner_source ,
 input_interface , II11 , oO0oIIII )
   else :
    Iiii11iIi1 = lisp . green ( packet . inner_source . print_address ( ) , False )
    lisp . dprint ( "Disallow dynamic-EID {} on interface {}" . format ( Iiii11iIi1 ,
 input_interface ) )
    return
    if 40 - 40: I11i % OoO0O00 . I1Ii111
    if 84 - 84: OoOoOO00 % ooOoO0o - OoOoOO00 . o0oOOo0O0Ooo
    if 5 - 5: OoOoOO00 * I1Ii111 - I1ii11iIi11i / iIii1I11I1II1 % oO0o + IiII
  if ( packet . inner_source . is_local ( ) and
 packet . udp_dport == lisp . LISP_CTRL_PORT ) : return
  if 51 - 51: I1Ii111 * II111iiii % ooOoO0o
  if 98 - 98: OoO0O00 . I11i % II111iiii
  if 71 - 71: I1Ii111 % i1IIi - II111iiii - OOooOOo + OOooOOo * ooOoO0o
  if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
  if 29 - 29: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / iII111i
 if ( packet . inner_version == 4 ) :
  packet . packet = lisp . lisp_ipv4_input ( packet . packet )
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
  if 70 - 70: i11iIiiIii % iII111i
  if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
  if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
  if 76 - 76: Ii1I - II111iiii * OOooOOo / OoooooooOO
  if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
  if 71 - 71: OoooooooOO
 if ( oo0O000OoO == False ) :
  Oo0ooOo0o = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( Oo0ooOo0o and Oo0ooOo0o . dynamic_eid_configured == False ) :
   lisp . dprint ( ( "Packet destined to local EID-prefix {}, " + "natively forwarding" ) . format ( Oo0ooOo0o . print_eid_tuple ( ) ) )
   if 33 - 33: I1Ii111
   packet . send_packet ( Ii1IIii11 , packet . inner_dest )
   return
   if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
   if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
   if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
   if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
   if 45 - 45: IiII
   if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 OoO000O = lisp . lisp_map_cache_lookup ( packet . inner_source , packet . inner_dest )
 if 94 - 94: OoOoOO00 . O0 / Ii1I . I1ii11iIi11i - i1IIi
 if 26 - 26: OoO0O00 - OOooOOo . o0oOOo0O0Ooo
 if 65 - 65: I1ii11iIi11i % O0 % iIii1I11I1II1 * Ii1I
 if 31 - 31: Ii1I
 if 44 - 44: OoOoOO00 - iIii1I11I1II1 - Oo0Ooo
 if 80 - 80: iIii1I11I1II1 * I1Ii111 % I11i % Oo0Ooo
 if 95 - 95: iIii1I11I1II1 - I1ii11iIi11i . I1Ii111 - I1IiiI
 OOOOoo = Oo0ooOo0o . secondary_iid if ( Oo0ooOo0o != None ) else None
 if ( OOOOoo and OoO000O and OoO000O . action == lisp . LISP_NATIVE_FORWARD_ACTION ) :
  o000 = packet . inner_dest
  o000 . instance_id = OOOOoo
  OoO000O = lisp . lisp_map_cache_lookup ( packet . inner_source , o000 )
  if 94 - 94: o0oOOo0O0Ooo + O0 / I11i . I1IiiI + OOooOOo . iIii1I11I1II1
  if 62 - 62: OoOoOO00 / I1IiiI - I1ii11iIi11i - I1IiiI + i11iIiiIii + i1IIi
  if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
  if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
  if 8 - 8: o0oOOo0O0Ooo
 if ( OoO000O == None or OoO000O . action == lisp . LISP_SEND_MAP_REQUEST_ACTION ) :
  if ( lisp . lisp_rate_limit_map_request ( packet . inner_source ,
 packet . inner_dest ) ) : return
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 packet . inner_source , packet . inner_dest , None )
  if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
  if ( packet . is_trace ( ) ) :
   lisp . lisp_trace_append ( packet , reason = "map-cache miss" )
   if 78 - 78: Ii1I / II111iiii % OoOoOO00
  return
  if 52 - 52: OOooOOo - iII111i * oO0o
  if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
  if 36 - 36: O0 + Oo0Ooo
  if 5 - 5: Oo0Ooo * OoOoOO00
  if 46 - 46: ooOoO0o
  if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if ( OoO000O and OoO000O . is_active ( ) and OoO000O . has_ttl_elapsed ( ) ) :
  lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( OoO000O . print_eid_tuple ( ) , False ) ) )
  if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 packet . inner_source , packet . inner_dest , None )
  if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
  if 72 - 72: i1IIi
  if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
  if 63 - 63: I1ii11iIi11i
  if 6 - 6: ooOoO0o / I1ii11iIi11i
  if 57 - 57: I11i
 OoO000O . stats . increment ( len ( packet . packet ) )
 if 67 - 67: OoO0O00 . ooOoO0o
 if 87 - 87: oO0o % Ii1I
 if 83 - 83: II111iiii - I11i
 if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
 OooOOo0 , ooO000O , oO , III111iiIi1 , Ii11Ii = OoO000O . select_rloc ( packet , oO0oIIII )
 if 1 - 1: I1IiiI % OoooooooOO + II111iiii - IiII
 if 43 - 43: OOooOOo / OoO0O00 % Ii1I
 if ( OooOOo0 == None and Ii11Ii == None ) :
  if ( III111iiIi1 == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   packet . send_packet ( Ii1IIii11 , packet . inner_dest )
   if 49 - 49: II111iiii - I1IiiI / I11i
   if ( packet . is_trace ( ) ) :
    lisp . lisp_trace_append ( packet , reason = "not an EID" )
    if 74 - 74: I11i - OOooOOo + i1IIi . I1IiiI + OOooOOo - I11i
   return
   if 17 - 17: O0 . I1Ii111 . O0 + O0 / Oo0Ooo . ooOoO0o
  OO00OOoO0o = "No reachable RLOCs found"
  lisp . dprint ( OO00OOoO0o )
  if ( packet . is_trace ( ) ) : lisp . lisp_trace_append ( packet , reason = OO00OOoO0o )
  return
  if 4 - 4: i1IIi - i11iIiiIii / i11iIiiIii / OoooooooOO
 if ( OooOOo0 and OooOOo0 . is_null ( ) ) :
  OO00OOoO0o = "Drop action RLOC found"
  lisp . dprint ( OO00OOoO0o )
  if 100 - 100: Oo0Ooo + o0oOOo0O0Ooo - O0 % II111iiii . iII111i
  if ( packet . is_trace ( ) ) : lisp . lisp_trace_append ( packet , reason = OO00OOoO0o )
  return
  if 92 - 92: II111iiii * OoooooooOO - I1Ii111
  if 58 - 58: iIii1I11I1II1 + O0
  if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
  if 46 - 46: i11iIiiIii - O0 . oO0o
  if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 packet . outer_tos = packet . inner_tos
 packet . outer_ttl = packet . inner_ttl
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if ( OooOOo0 ) :
  packet . outer_dest . copy_address ( OooOOo0 )
  OO0OoOOO0 = packet . outer_dest . afi_to_version ( )
  packet . outer_version = OO0OoOOO0
  O00ooOo = lisp . lisp_myrlocs [ 0 ] if ( OO0OoOOO0 == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 80 - 80: o0oOOo0O0Ooo - OOooOOo + OoooooooOO
  packet . outer_source . copy_address ( O00ooOo )
  if 98 - 98: OOooOOo + i1IIi . I1IiiI - II111iiii - o0oOOo0O0Ooo
  if ( packet . is_trace ( ) ) :
   if ( lisp . lisp_trace_append ( packet ) == False ) : return
   if 24 - 24: Oo0Ooo - i1IIi + I11i
   if 38 - 38: OoooooooOO / I1ii11iIi11i . O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
   if 96 - 96: iII111i
   if 18 - 18: iII111i * I11i - Ii1I
   if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
  if ( packet . encode ( oO ) == None ) : return
  if ( len ( packet . packet ) <= 1500 ) : packet . print_packet ( "Send" , True )
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
  if 39 - 39: iIii1I11I1II1 - OoooooooOO
  if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
  iiIiI = Oooo0000 if OO0OoOOO0 == 6 else Ii1IIii11
  packet . send_packet ( iiIiI , packet . outer_dest )
  if 87 - 87: ooOoO0o - OoooooooOO + i11iIiiIii
 elif ( Ii11Ii ) :
  if 73 - 73: I11i * OoooooooOO . O0 . IiII
  if 55 - 55: Oo0Ooo
  if 77 - 77: II111iiii
  if 16 - 16: I1IiiI * II111iiii / iIii1I11I1II1 - iII111i
  if 3 - 3: I1IiiI * ooOoO0o + II111iiii - OoO0O00
  OOOO = Ii11Ii . rle_nodes [ 0 ] . level
  OoOO0OOoo = len ( packet . packet )
  for IIIi11IiIiii in Ii11Ii . rle_forwarding_list :
   if ( IIIi11IiIiii . level != OOOO ) : return
   if 38 - 38: Oo0Ooo - I11i . Oo0Ooo
   packet . outer_dest . copy_address ( IIIi11IiIiii . address )
   if ( II1i1i1iII1 ) : packet . inner_dest . instance_id = 0xffffff
   OO0OoOOO0 = packet . outer_dest . afi_to_version ( )
   packet . outer_version = OO0OoOOO0
   O00ooOo = lisp . lisp_myrlocs [ 0 ] if ( OO0OoOOO0 == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 38 - 38: i1IIi + Ii1I
   packet . outer_source . copy_address ( O00ooOo )
   if 91 - 91: II111iiii % iII111i % IiII + II111iiii / oO0o
   if ( packet . is_trace ( ) ) :
    if ( lisp . lisp_trace_append ( packet ) == False ) : return
    if 62 - 62: OoooooooOO - i11iIiiIii
    if 5 - 5: iIii1I11I1II1 / I11i / i1IIi % OoooooooOO
   if ( packet . encode ( None ) == None ) : return
   if 50 - 50: Ii1I / OoOoOO00 * Ii1I
   if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
   if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
   if 32 - 32: i11iIiiIii - I1Ii111
   packet . print_packet ( "Replicate-to-L{}" . format ( IIIi11IiIiii . level ) , True )
   packet . send_packet ( Ii1IIii11 , packet . outer_dest )
   if 53 - 53: OoooooooOO - IiII
   if 87 - 87: oO0o . I1IiiI
   if 17 - 17: Ii1I . i11iIiiIii
   if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
   if 63 - 63: oO0o
   Oo0 = len ( packet . packet ) - OoOO0OOoo
   packet . packet = packet . packet [ Oo0 : : ]
   if 79 - 79: OoO0O00 % OOooOOo / iIii1I11I1II1 + OoOoOO00 * OoO0O00
   if 30 - 30: OoooooooOO / I11i + iII111i / I1ii11iIi11i * O0
   if 16 - 16: Oo0Ooo / i11iIiiIii
   if 64 - 64: i11iIiiIii / Ii1I * i1IIi
   if 73 - 73: Oo0Ooo - OoOoOO00 - oO0o - I1IiiI
   if 65 - 65: o0oOOo0O0Ooo
 del ( packet )
 return
 if 7 - 7: IiII . OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - II111iiii
 if 37 - 37: I1Ii111 . OoOoOO00 / O0 * iII111i
 if 7 - 7: OoO0O00 * I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
def i1iI1 ( device , not_used , packet ) :
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 OO0ooo0o0 = 4 if device == "lo0" else 14
 if 69 - 69: I1ii11iIi11i - I1Ii111
 if ( lisp . lisp_frame_logging ) :
  iiIIi1 = lisp . bold ( "Received frame on interface '{}'" . format ( device ) ,
 False )
  i111i11I1Ii1I = lisp . lisp_format_packet ( packet [ 0 : 64 ] )
  lisp . lprint ( "{}: {}" . format ( iiIIi1 , i111i11I1Ii1I ) )
  if 8 - 8: Ii1I
  if 35 - 35: IiII + i1IIi * oO0o - Ii1I . Oo0Ooo
  if 31 - 31: o0oOOo0O0Ooo
  if 15 - 15: O0 / Oo0Ooo % I1ii11iIi11i + o0oOOo0O0Ooo
  if 23 - 23: iIii1I11I1II1 + O0
 ooO0oo = ""
 ooO0oo0o0 = False
 OOo0oO00ooO00 = device
 if ( OO0ooo0o0 == 14 ) :
  iIiIIi1 , IIiIii1 , Ooo0oO0 , ooO0oo0o0 = lisp . lisp_get_input_interface ( packet )
  OOo0oO00ooO00 = device if ( device in iIiIIi1 ) else iIiIIi1 [ 0 ]
  ooO0oo = lisp . lisp_format_macs ( IIiIii1 , Ooo0oO0 )
  if ( OOo0oO00ooO00 . find ( "vlan" ) != - 1 ) : OO0ooo0o0 += 4
  if 86 - 86: O0
  if 95 - 95: iII111i * OOooOOo . OoOoOO00 . i1IIi . i1IIi - o0oOOo0O0Ooo
  if 26 - 26: iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
  if 67 - 67: OoooooooOO
  if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
  if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
  if ( int ( Ooo0oO0 [ 1 ] , 16 ) & 1 ) : ooO0oo0o0 = True
  if 93 - 93: i1IIi
  if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
  if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
  if 66 - 66: Oo0Ooo
  if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 oO0 = struct . unpack ( "H" , packet [ OO0ooo0o0 - 2 : OO0ooo0o0 ] ) [ 0 ]
 oO0 = socket . ntohs ( oO0 )
 if ( oO0 == 0x8100 ) :
  oOo00o00oO = struct . unpack ( "I" , packet [ OO0ooo0o0 : OO0ooo0o0 + 4 ] ) [ 0 ]
  oOo00o00oO = socket . ntohl ( oOo00o00oO )
  OOo0oO00ooO00 = "vlan" + str ( oOo00o00oO >> 16 )
  OO0ooo0o0 += 4
 elif ( oO0 == 0x806 ) :
  lisp . dprint ( "Dropping ARP packets, host should have default route" )
  return
  if 95 - 95: I1IiiI
  if 88 - 88: IiII % OoO0O00 + I1Ii111 + I1Ii111 * II111iiii
 if ( lisp . lisp_l2_overlay ) : OO0ooo0o0 = 0
 if 78 - 78: OoooooooOO
 IIIii ( packet [ OO0ooo0o0 : : ] , device , OOo0oO00ooO00 , ooO0oo , ooO0oo0o0 )
 return
 if 77 - 77: I1ii11iIi11i / i1IIi / Oo0Ooo % OOooOOo
 if 48 - 48: I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
 if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
 if 62 - 62: o0oOOo0O0Ooo
 if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
 if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 if 84 - 84: i11iIiiIii * OoO0O00
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
def OO0oOOoo ( sources , dyn_eids ) :
 if ( os . getenv ( "LISP_NO_IPTABLES" ) != None ) :
  lisp . lprint ( "User selected to suppress installing iptables rules" )
  return
  if 33 - 33: I1IiiI / OoO0O00
  if 12 - 12: II111iiii
 os . system ( "sudo iptables -t raw -N lisp" )
 os . system ( "sudo iptables -t raw -A PREROUTING -j lisp" )
 os . system ( "sudo ip6tables -t raw -N lisp" )
 os . system ( "sudo ip6tables -t raw -A PREROUTING -j lisp" )
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 iIii11iI1II = "sudo ip{}tables -t raw -A lisp -j ACCEPT -d {}"
 I1II1I1I = [ "127.0.0.1" , "::1" , "224.0.0.0/4 -p igmp" , "ff00::/8" ,
 "fe80::/16" ]
 I1II1I1I += sources + lisp . lisp_get_all_addresses ( )
 for OOo0 in I1II1I1I :
  oOO0o0oo0 = "" if OOo0 . find ( ":" ) == - 1 else "6"
  os . system ( iIii11iI1II . format ( oOO0o0oo0 , OOo0 ) )
  if 78 - 78: OOooOOo + iII111i . IiII
  if 91 - 91: iIii1I11I1II1 . o0oOOo0O0Ooo . I1ii11iIi11i + OoooooooOO
  if 69 - 69: I1Ii111 - I1IiiI
  if 95 - 95: I1IiiI * i11iIiiIii . ooOoO0o
  if 41 - 41: II111iiii
  if 37 - 37: I11i . Oo0Ooo % IiII * i1IIi
  if 71 - 71: Oo0Ooo / o0oOOo0O0Ooo + OOooOOo
  if 48 - 48: I1Ii111 + iII111i
 if ( lisp . lisp_pitr == False ) :
  iIii11iI1II = "sudo ip{}tables -t raw -A lisp -j ACCEPT -s {} -d {}"
  Iiii1II1iI = "sudo ip{}tables -t raw -C lisp -j ACCEPT -s {} -d {}"
  for i1oOOoo0o0OOOO in sources :
   if ( i1oOOoo0o0OOOO in dyn_eids ) : continue
   oOO0o0oo0 = "" if i1oOOoo0o0OOOO . find ( ":" ) == - 1 else "6"
   for O0OOO0OOoO0O in sources :
    if ( O0OOO0OOoO0O in dyn_eids ) : continue
    if ( O0OOO0OOoO0O . find ( "." ) != - 1 and i1oOOoo0o0OOOO . find ( "." ) == - 1 ) : continue
    if ( O0OOO0OOoO0O . find ( ":" ) != - 1 and i1oOOoo0o0OOOO . find ( ":" ) == - 1 ) : continue
    if ( commands . getoutput ( Iiii1II1iI . format ( oOO0o0oo0 , i1oOOoo0o0OOOO , O0OOO0OOoO0O ) ) == "" ) :
     continue
     if 42 - 42: oO0o % OoooooooOO + o0oOOo0O0Ooo
    os . system ( iIii11iI1II . format ( oOO0o0oo0 , i1oOOoo0o0OOOO , O0OOO0OOoO0O ) )
    if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
    if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
    if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
    if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
    if 52 - 52: OoO0O00 % Ii1I * II111iiii
    if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
    if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
 II1 = "sudo ip{}tables -t raw -A lisp -j DROP -s {}"
 for i1oOOoo0o0OOOO in sources :
  oOO0o0oo0 = "" if i1oOOoo0o0OOOO . find ( ":" ) == - 1 else "6"
  os . system ( II1 . format ( oOO0o0oo0 , i1oOOoo0o0OOOO ) )
  if 27 - 27: Ii1I + I1IiiI * iIii1I11I1II1 . OoooooooOO * OoOoOO00
  if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
  if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
  if 71 - 71: IiII . I1Ii111 . OoO0O00
  if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 o00OoO0oO00 = commands . getoutput ( "sudo iptables -t raw -S lisp" ) . split ( "\n" )
 o00OoO0oO00 += commands . getoutput ( "sudo ip6tables -t raw -S lisp" ) . split ( "\n" )
 lisp . lprint ( "Using kernel filters: {}" . format ( o00OoO0oO00 ) )
 if 2 - 2: iIii1I11I1II1
 if 45 - 45: OoooooooOO / i11iIiiIii
 if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
 if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
 if 17 - 17: Ii1I
 if 39 - 39: ooOoO0o . II111iiii
 if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
 if 77 - 77: I1Ii111 - I11i
 if 11 - 11: I1ii11iIi11i
 if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
 if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
 if ( os . getenv ( "LISP_VIRTIO_BUG" ) != None ) :
  o0OO0O0OO0oO0 = ( "sudo iptables -A POSTROUTING -t mangle -p tcp -j " + "CHECKSUM --checksum-fill; " )
  if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
  o0OO0O0OO0oO0 += ( "sudo iptables -A POSTROUTING -t mangle -p udp -j " + "CHECKSUM --checksum-fill; " )
  if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
  o0OO0O0OO0oO0 += ( "sudo ip6tables -A POSTROUTING -t mangle -p tcp -j " + "CHECKSUM --checksum-fill; " )
  if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
  o0OO0O0OO0oO0 += ( "sudo ip6tables -A POSTROUTING -t mangle -p udp -j " + "CHECKSUM --checksum-fill" )
  if 45 - 45: O0 . i11iIiiIii % iII111i . OoOoOO00 % IiII % iIii1I11I1II1
  os . system ( o0OO0O0OO0oO0 )
  Oo = lisp . bold ( "virtio" , False )
  lisp . lprint ( "{} bug workaround, configure '{}'" . format ( Oo , o0OO0O0OO0oO0 ) )
  if 66 - 66: i11iIiiIii * iIii1I11I1II1 % OoooooooOO
 return
 if 5 - 5: OoOoOO00 % OoooooooOO
 if 60 - 60: OoOoOO00 . i1IIi % OoO0O00 % ooOoO0o % OOooOOo
 if 33 - 33: iIii1I11I1II1 - Ii1I * I1ii11iIi11i % iIii1I11I1II1 + OoO0O00 . OOooOOo
 if 56 - 56: i11iIiiIii * iII111i . oO0o
 if 78 - 78: OoOoOO00
 if 1 - 1: OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
def o00oOo0oOoo ( sources , dyn_eids , l2_overlay , pitr ) :
 if ( l2_overlay ) :
  i1I11IiI1iiII = "ether[6:4] >= 0 and ether[10:2] >= 0"
  lisp . lprint ( "Using pcap filter: '{}'" . format ( i1I11IiI1iiII ) )
  return ( i1I11IiI1iiII )
  if 19 - 19: oO0o * I1IiiI % i11iIiiIii
  if 24 - 24: o0oOOo0O0Ooo
 iIi1Iii111I = "(not ether proto 0x806)"
 I1Iiiiiii = " or (udp src port 4342 and ip[28] == 0x28)"
 IIi11i11 = " or (ip[16] >= 224 and ip[16] < 240 and (ip[28] & 0xf0) == 0x30)"
 if 18 - 18: iIii1I11I1II1 + I11i * I1IiiI - OOooOOo / I1IiiI
 if 78 - 78: I11i . IiII
 iI1i1II = ""
 I1ii1ii1I = ""
 for i1oOOoo0o0OOOO in sources :
  iI1i1II += "{}" . format ( i1oOOoo0o0OOOO )
  if ( i1oOOoo0o0OOOO not in dyn_eids ) : I1ii1ii1I += "{}" . format ( i1oOOoo0o0OOOO )
  if ( sources [ - 1 ] == i1oOOoo0o0OOOO ) : break
  iI1i1II += " or "
  if ( i1oOOoo0o0OOOO not in dyn_eids ) : I1ii1ii1I += " or "
  if 18 - 18: oO0o * oO0o % oO0o
 if ( I1ii1ii1I [ - 4 : : ] == " or " ) : I1ii1ii1I = I1ii1ii1I [ 0 : - 4 ]
 if 17 - 17: O0 * OoOoOO00 * I1ii11iIi11i * II111iiii * I11i % i1IIi
 if 33 - 33: I1ii11iIi11i * I1ii11iIi11i . ooOoO0o . i11iIiiIii
 if 48 - 48: o0oOOo0O0Ooo . Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 IiIi1i = commands . getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 IiIi1i = ( IiIi1i != "" and IiIi1i [ 0 ] == " " )
 oO0O0oO = lisp . lisp_get_loopback_address ( ) if ( IiIi1i ) else None
 if 27 - 27: O0 / OoOoOO00 + iIii1I11I1II1 - OOooOOo % o0oOOo0O0Ooo
 I111i1Ii1i1 = ""
 iI1IIi1IiI = lisp . lisp_get_all_addresses ( )
 for OOo0 in iI1IIi1IiI :
  if ( OOo0 == oO0O0oO ) : continue
  I111i1Ii1i1 += "{}" . format ( OOo0 )
  if ( iI1IIi1IiI [ - 1 ] == OOo0 ) : break
  I111i1Ii1i1 += " or "
  if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
  if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if ( iI1i1II != "" ) :
  iI1i1II = " and (src net {})" . format ( iI1i1II )
  if 79 - 79: OoOoOO00 / ooOoO0o
 if ( I1ii1ii1I != "" ) :
  I1ii1ii1I = " and not (dst net {})" . format ( I1ii1ii1I )
  if 77 - 77: Oo0Ooo
 if ( I111i1Ii1i1 != "" ) :
  I111i1Ii1i1 = " and not (dst host {})" . format ( I111i1Ii1i1 )
  if 46 - 46: I1Ii111
  if 72 - 72: iII111i * OOooOOo
  if 67 - 67: i1IIi
  if 5 - 5: II111iiii . OoooooooOO
  if 57 - 57: I1IiiI
  if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
  if 50 - 50: OoOoOO00
 if ( pitr ) :
  I1ii1ii1I = ""
  I111i1Ii1i1 = I111i1Ii1i1 . replace ( "dst " , "" )
  if 33 - 33: I11i
  if 98 - 98: OoOoOO00 % II111iiii
  if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
  if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
  if 68 - 68: o0oOOo0O0Ooo
 i1I11IiI1iiII = iIi1Iii111I + iI1i1II + I1ii1ii1I + I111i1Ii1i1
 i1I11IiI1iiII += I1Iiiiiii
 i1I11IiI1iiII += IIi11i11
 if 20 - 20: I1Ii111 - I1Ii111
 lisp . lprint ( "Using pcap filter: '{}'" . format ( i1I11IiI1iiII ) )
 return ( i1I11IiI1iiII )
 if 37 - 37: IiII
 if 37 - 37: Oo0Ooo / IiII * O0
 if 73 - 73: iII111i * iII111i / ooOoO0o
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
def iIi1 ( device , pfilter , pcap_lock ) :
 lisp . lisp_set_exception ( )
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 pcap_lock . acquire ( )
 iiiiI1IiI1I1 = pcappy . open_live ( device , 9000 , 0 , 100 )
 pcap_lock . release ( )
 if 19 - 19: Ii1I
 iiiiI1IiI1I1 . filter = pfilter
 iiiiI1IiI1I1 . loop ( - 1 , i1iI1 , device )
 return
 if 55 - 55: OOooOOo % OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
 if 49 - 49: iIii1I11I1II1 * i1IIi . OoooooooOO
 if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 if 8 - 8: OoOoOO00 * Oo0Ooo / IiII % Ii1I - I1IiiI
 if 71 - 71: iII111i
 if 23 - 23: i1IIi . iIii1I11I1II1 . OOooOOo . O0 % Ii1I % i11iIiiIii
 if 11 - 11: O0 - II111iiii . OOooOOo . Ii1I % I1Ii111
 if 21 - 21: Oo0Ooo / iII111i . I1Ii111 * OoooooooOO + I11i - i1IIi
 if 58 - 58: I1ii11iIi11i
def ii1I ( ) :
 global I11
 global II1Ii1iI1i
 global II1iII1i
 if 98 - 98: i1IIi
 lisp . lisp_set_exception ( )
 if 51 - 51: I1ii11iIi11i + ooOoO0o + Oo0Ooo / i1IIi + i1IIi
 if 12 - 12: iIii1I11I1II1 . Ii1I . I1ii11iIi11i % I1IiiI . II111iiii . oO0o
 if 32 - 32: I1ii11iIi11i + IiII / O0 / OoOoOO00 * OoooooooOO % ooOoO0o
 if 50 - 50: OoO0O00
 if 66 - 66: iIii1I11I1II1
 I11II1i11 = [ II1Ii1iI1i , II1Ii1iI1i ,
 oO0oIIII ]
 lisp . lisp_build_info_requests ( I11II1i11 , None , lisp . LISP_CTRL_PORT )
 if 28 - 28: II111iiii - oO0o % OoOoOO00 + OoO0O00 - OoOoOO00
 if 28 - 28: II111iiii . oO0o + O0 . O0 . OOooOOo
 if 98 - 98: OoooooooOO % O0 - O0
 if 76 - 76: i1IIi % OoOoOO00 - I1IiiI / o0oOOo0O0Ooo * ooOoO0o
 I11 . cancel ( )
 I11 = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 ii1I , [ ] )
 I11 . start ( )
 return
 if 4 - 4: Oo0Ooo * Oo0Ooo / OoOoOO00
 if 4 - 4: I1IiiI * OoOoOO00 % I11i . OoOoOO00
 if 11 - 11: OOooOOo - OoOoOO00 - o0oOOo0O0Ooo * OoOoOO00 + ooOoO0o
 if 62 - 62: I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
def O0O ( kv_pair ) :
 global II1iII1i
 global iiI1iIiI
 global I11
 if 51 - 51: oO0o + OoO0O00 + iII111i + iII111i % o0oOOo0O0Ooo
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 29 - 29: ooOoO0o
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , iiI1iIiI ] )
  lisp . lisp_test_mr_timer . start ( )
  if 41 - 41: O0 % iII111i
  if 10 - 10: iII111i . i1IIi + Ii1I
  if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
  if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
  if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 I11 = threading . Timer ( 0 , ii1I , [ ] )
 I11 . start ( )
 return
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if 81 - 81: IiII / OoOoOO00 * IiII . O0
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
 if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
def II111 ( kv_pair ) :
 lispconfig . lisp_database_mapping_command ( kv_pair )
 return
 if 94 - 94: iII111i % ooOoO0o . oO0o
 if 85 - 85: OOooOOo * i1IIi % I1IiiI - ooOoO0o
 if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 if 83 - 83: IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
def oo000o ( kv_pair ) :
 global i111I
 if 95 - 95: oO0o - ooOoO0o * I11i / OoO0O00 / II111iiii + O0
 if 37 - 37: I11i . I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 O00ooooo00 = lisp . lisp_nat_traversal
 O0ooOoOO0 = lisp . lisp_rloc_probing
 if 56 - 56: o0oOOo0O0Ooo / IiII * I1IiiI . o0oOOo0O0Ooo
 if 15 - 15: i11iIiiIii
 if 13 - 13: I11i * II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 lispconfig . lisp_xtr_command ( kv_pair )
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 o0OO00oo0O = ( O00ooooo00 == False and lisp . lisp_nat_traversal and lisp . lisp_rloc_probing )
 if 46 - 46: i11iIiiIii - OOooOOo * I1IiiI * I11i % I1ii11iIi11i * i1IIi
 Iii1I = ( O0ooOoOO0 == False and lisp . lisp_rloc_probing )
 if 40 - 40: IiII * O0
 oo0OoOO0o0o = 0
 if ( Iii1I ) : oo0OoOO0o0o = 1
 if ( o0OO00oo0O ) : oo0OoOO0o0o = 5
 if 67 - 67: OoOoOO00 - OoOoOO00 * OoO0O00 - iII111i % oO0o
 if ( oo0OoOO0o0o != 0 ) :
  iI = [ i111I , i111I ]
  lisp . lisp_start_rloc_probe_timer ( oo0OoOO0o0o , iI )
  if 47 - 47: OoooooooOO % OoOoOO00
  if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
  if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
  if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
  if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
  if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
  if 88 - 88: o0oOOo0O0Ooo
 if ( lisp . lisp_crypto_ephem_port == None and lisp . lisp_data_plane_security ) :
  i1IiII1III = i111I . getsockname ( ) [ 1 ]
  lisp . lisp_crypto_ephem_port = i1IiII1III
  lisp . lprint ( "Use port {} for lisp-crypto packets" . format ( i1IiII1III ) )
  iI11 = { "type" : "itr-crypto-port" , "port" : i1IiII1III }
  lisp . lisp_write_to_dp_socket ( iI11 )
  if 97 - 97: oO0o + Oo0Ooo * OOooOOo % Oo0Ooo
  if 31 - 31: i11iIiiIii
  if 12 - 12: ooOoO0o
  if 86 - 86: oO0o - OoO0O00
  if 63 - 63: I1IiiI / OoOoOO00 + OoooooooOO . I11i . ooOoO0o
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 48 - 48: i1IIi - iII111i - i11iIiiIii . I11i - iII111i * I11i
 if 60 - 60: OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
def O0OO0ooO00 ( ipc ) :
 oO0oOO0o , o0O , I1IIiIIi1Ii1III , oO = ipc . split ( "%" )
 oO = int ( oO , 16 )
 if 86 - 86: i11iIiiIii + i11iIiiIii . I1Ii111 % I1IiiI . ooOoO0o
 iII1iI1IIiI = lisp . lisp_get_echo_nonce ( None , I1IIiIIi1Ii1III )
 if ( iII1iI1IIiI == None ) : iII1iI1IIiI = lisp . lisp_echo_nonce ( I1IIiIIi1Ii1III )
 if 69 - 69: I11i / i11iIiiIii * o0oOOo0O0Ooo / I1Ii111
 if 71 - 71: o0oOOo0O0Ooo / OOooOOo % OOooOOo
 if 89 - 89: OoooooooOO + i11iIiiIii / I11i + iIii1I11I1II1 % ooOoO0o
 if 29 - 29: I1ii11iIi11i
 if 53 - 53: i11iIiiIii . I1ii11iIi11i % Ii1I / ooOoO0o % iIii1I11I1II1
 if ( o0O == "R" ) :
  iII1iI1IIiI . request_nonce_rcvd = oO
  iII1iI1IIiI . last_request_nonce_rcvd = lisp . lisp_get_timestamp ( )
  iII1iI1IIiI . echo_nonce_sent = oO
  iII1iI1IIiI . last_new_echo_nonce_sent = lisp . lisp_get_timestamp ( )
  lisp . lprint ( "Start echo-nonce mode for {}, nonce 0x{}" . format ( lisp . red ( iII1iI1IIiI . rloc_str , False ) , lisp . lisp_hex_string ( oO ) ) )
  if 6 - 6: Oo0Ooo - OOooOOo . iIii1I11I1II1
  if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
  if 36 - 36: I11i % OOooOOo
 if ( o0O == "E" ) :
  iII1iI1IIiI . echo_nonce_rcvd = oO
  iII1iI1IIiI . last_echo_nonce_rcvd = lisp . lisp_get_timestamp ( )
  if 72 - 72: I1IiiI / iII111i - O0 + I11i
  if ( iII1iI1IIiI . request_nonce_sent == oO ) :
   o0 = lisp . bold ( "echoed nonce" , False )
   lisp . lprint ( "Received {} {} from {}" . format ( o0 ,
 lisp . lisp_hex_string ( oO ) ,
 lisp . red ( iII1iI1IIiI . rloc_str , False ) ) )
   if 48 - 48: o0oOOo0O0Ooo + o0oOOo0O0Ooo - Oo0Ooo
   iII1iI1IIiI . request_nonce_sent = None
   lisp . lprint ( "Stop request-nonce mode for {}" . format ( lisp . red ( iII1iI1IIiI . rloc_str , False ) ) )
   if 27 - 27: OoO0O00 + OoOoOO00 * ooOoO0o
   iII1iI1IIiI . last_good_echo_nonce_rcvd = lisp . lisp_get_timestamp ( )
  else :
   o0o = "none"
   if ( iII1iI1IIiI . request_nonce_sent ) :
    o0o = lisp . lisp_hex_string ( iII1iI1IIiI . request_nonce_sent )
    if 71 - 71: i1IIi . I11i + Oo0Ooo * oO0o * iIii1I11I1II1 + I1ii11iIi11i
   lisp . lprint ( ( "Received echo-nonce 0x{} from {}, but request-" + "nonce is {}" ) . format ( lisp . lisp_hex_string ( oO ) ,
   # OoooooooOO
 lisp . red ( iII1iI1IIiI . rloc_str , False ) , o0o ) )
   if 38 - 38: OoOoOO00 / iIii1I11I1II1 % i11iIiiIii - IiII * iII111i / OoOoOO00
   if 13 - 13: OoO0O00 * I1ii11iIi11i - I1Ii111
 return
 if 79 - 79: oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 if 24 - 24: ooOoO0o - I11i * oO0o
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
o0O0OOo0oO = {
 "lisp xtr-parameters" : [ oo000o , {
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

 "lisp map-resolver" : [ O0O , {
 "mr-name" : [ True ] ,
 "ms-name" : [ True ] ,
 "dns-name" : [ True ] ,
 "address" : [ True ] } ] ,

 "lisp database-mapping" : [ II111 , {
 "prefix" : [ ] ,
 "mr-name" : [ True ] ,
 "ms-name" : [ True ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "secondary-instance-id" : [ True , 0 , 0xffffffff ] ,
 "eid-prefix" : [ True ] ,
 "group-prefix" : [ True ] ,
 "dynamic-eid" : [ True , "yes" , "no" ] ,
 "signature-eid" : [ True , "yes" , "no" ] ,
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

 "show itr-map-cache" : [ IIiiIiI1 , { } ] ,
 "show itr-rloc-probing" : [ I1i1iii , { } ] ,
 "show itr-keys" : [ oo , { } ] ,
 "show itr-dynamic-eid" : [ lispconfig . lisp_show_dynamic_eid_command , { } ]
 }
if 42 - 42: II111iiii / O0 . iIii1I11I1II1 / O0 / OoO0O00 / OoooooooOO
if 62 - 62: O0 . Oo0Ooo
if 33 - 33: Oo0Ooo / iIii1I11I1II1 % i1IIi
if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
if 49 - 49: IiII / ooOoO0o / OOooOOo
if 25 - 25: I1IiiI % O0 + i1IIi - ooOoO0o
if ( I111I1Iiii1i ( ) == False ) :
 lisp . lprint ( "lisp_itr_startup() failed" )
 lisp . lisp_print_banner ( "ITR abnormal exit" )
 exit ( 1 )
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
O0oooOoO = [ i111I , oO0oIIII ,
 II1Ii1iI1i , Oo0oO0oo0oO00 ]
if 62 - 62: OOooOOo / II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
if 36 - 36: OOooOOo % i11iIiiIii
Iiii1Ii = True
ooOOo00oo0 = [ i111I ] * 3
IIIII1Ii = [ II1Ii1iI1i ] * 3
if 13 - 13: II111iiii
while ( True ) :
 try : o0o000Oo , oO0o0O0o0OO00 , oO0oOO0o = select . select ( O0oooOoO , [ ] , [ ] )
 except : break
 if 23 - 23: OoO0O00 + i11iIiiIii
 if 20 - 20: I1ii11iIi11i
 if 3 - 3: OoO0O00 * i1IIi . I1IiiI . O0 - OoOoOO00
 if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
 if ( lisp . lisp_ipc_data_plane and Oo0oO0oo0oO00 in o0o000Oo ) :
  lisp . lisp_process_punt ( Oo0oO0oo0oO00 , II1iII1i ,
 iiI1iIiI )
  if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
  if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
  if 10 - 10: I1ii11iIi11i / i11iIiiIii - Ii1I + oO0o * I1IiiI
  if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
  if 64 - 64: I11i + OoO0O00
 if ( i111I in o0o000Oo ) :
  o0O , i1oOOoo0o0OOOO , i1IiII1III , Ii = lisp . lisp_receive ( ooOOo00oo0 [ 0 ] ,
 False )
  if ( i1oOOoo0o0OOOO == "" ) : break
  if 44 - 44: I1IiiI % Ii1I * I1IiiI . Oo0Ooo + I1ii11iIi11i . OOooOOo
  if ( lisp . lisp_is_rloc_probe_reply ( Ii [ 0 ] ) ) :
   lisp . lprint ( "ITR ignoring RLOC-probe reply, using pcap" )
   continue
   if 6 - 6: IiII * OoooooooOO + I1Ii111 / Ii1I
  lisp . lisp_parse_packet ( ooOOo00oo0 , Ii , i1oOOoo0o0OOOO , i1IiII1III )
  if 35 - 35: ooOoO0o % I1IiiI - ooOoO0o - OoO0O00 - OoooooooOO
  if 46 - 46: i1IIi . i1IIi . oO0o / I11i / ooOoO0o
  if 34 - 34: OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
  if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
  if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
 if ( II1Ii1iI1i in o0o000Oo ) :
  o0O , i1oOOoo0o0OOOO , i1IiII1III , Ii = lisp . lisp_receive ( IIIII1Ii [ 0 ] ,
 False )
  if ( i1oOOoo0o0OOOO == "" ) : break
  if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
  if ( lisp . lisp_is_rloc_probe_reply ( Ii [ 0 ] ) ) :
   lisp . lprint ( "ITR ignoring RLOC-probe reply, using pcap" )
   continue
   if 98 - 98: oO0o . OoooooooOO
  Oo000 = lisp . lisp_parse_packet ( IIIII1Ii , Ii , i1oOOoo0o0OOOO , i1IiII1III )
  if 97 - 97: O0 / OOooOOo + o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
  if 33 - 33: I11i % II111iiii + OoO0O00
  if 93 - 93: i1IIi . IiII / I1IiiI + IiII
  if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
  if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
  if ( Oo000 ) :
   iI = [ i111I , i111I ]
   lisp . lisp_start_rloc_probe_timer ( 0 , iI )
   if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
   if 69 - 69: ooOoO0o % ooOoO0o
   if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
   if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
   if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
   if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
   if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
 if ( oO0oIIII in o0o000Oo ) :
  o0O , i1oOOoo0o0OOOO , i1IiII1III , Ii = lisp . lisp_receive ( oO0oIIII , True )
  if 33 - 33: Ii1I
  if ( i1oOOoo0o0OOOO == "" ) : break
  if 93 - 93: ooOoO0o
  if ( o0O == "command" ) :
   if ( Ii == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
   if ( Ii . find ( "nonce%" ) != - 1 ) :
    O0OO0ooO00 ( Ii )
    continue
    if 19 - 19: I1ii11iIi11i
   lispconfig . lisp_process_command ( oO0oIIII , o0O ,
 Ii , "lisp-itr" , [ o0O0OOo0oO ] )
  elif ( o0O == "api" ) :
   lisp . lisp_process_api ( "lisp-itr" , oO0oIIII , Ii )
  elif ( o0O == "data-packet" ) :
   IIIii ( Ii , "ipc" )
  else :
   if ( lisp . lisp_is_rloc_probe_reply ( Ii [ 0 ] ) ) :
    lisp . lprint ( "ITR ignoring RLOC-probe request, using pcap" )
    continue
    if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
   lisp . lisp_parse_packet ( II1iII1i , Ii , i1oOOoo0o0OOOO , i1IiII1III )
   if 66 - 66: O0
   if 52 - 52: OoO0O00 * OoooooooOO
   if 12 - 12: O0 + IiII * i1IIi . OoO0O00
   if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
   if 28 - 28: iIii1I11I1II1
I1II ( )
lisp . lisp_print_banner ( "ITR normal exit" )
exit ( 0 )
if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
