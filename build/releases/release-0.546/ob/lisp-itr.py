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
  if 92 - 92: ooOoO0o
 II11iI111i1 = ( i1I11IiI1iiII . find ( "ether host" ) != - 1 )
 for Oo00OoOo in iIiIIi1 :
  if ( Oo00OoOo in [ "lo" , "lispers.net" ] and II11iI111i1 ) :
   lisp . lprint ( ( "Capturing suppressed on interface {}, " + "MAC filters configured" ) . format ( Oo00OoOo ) )
   if 24 - 24: i11iIiiIii - I1Ii111
   continue
   if 21 - 21: I11i
   if 92 - 92: i11iIiiIii / I1Ii111 - iII111i % ooOoO0o * I1Ii111 + Oo0Ooo
  ii1 = [ Oo00OoOo , i1I11IiI1iiII , i1iIIi1 ]
  lisp . lprint ( "Capturing packets on {}interface {}" . format ( O0iII1 , Oo00OoOo ) )
  threading . Thread ( target = Oo0000oOo , args = ii1 ) . start ( )
  if 31 - 31: I11i . I1Ii111 * ooOoO0o + i11iIiiIii * oO0o
 if ( ii1iIi1iIiI1i ) : return
 if 93 - 93: I1ii11iIi11i / iIii1I11I1II1 * i1IIi % OoooooooOO * O0 * I11i
 if 64 - 64: II111iiii + O0 / iIii1I11I1II1 / Oo0Ooo . ooOoO0o % IiII
 if 50 - 50: iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
 iI1iIIIi1i = "(udp src port 4342 and ip[28] == 0x28)"
 for Oo00OoOo in IIII1i :
  ii1 = [ Oo00OoOo , iI1iIIIi1i , i1iIIi1 ]
  lisp . lprint ( "Capture RLOC-probe replies on RLOC interface {}" . format ( Oo00OoOo ) )
  if 89 - 89: iIii1I11I1II1
  threading . Thread ( target = Oo0000oOo , args = ii1 ) . start ( )
  if 21 - 21: I11i % I11i
 return
 if 27 - 27: i11iIiiIii / I1ii11iIi11i
 if 84 - 84: Oo0Ooo
 if 43 - 43: oO0o - OoooooooOO
 if 3 - 3: O0 / iII111i
 if 31 - 31: OOooOOo + o0oOOo0O0Ooo . OoooooooOO
 if 89 - 89: II111iiii + i1IIi + II111iiii
 if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
def II1Ii11I111I ( ) :
 if 13 - 13: ooOoO0o / iII111i * OoO0O00 . OoO0O00 * ooOoO0o
 if 63 - 63: I1Ii111 / O0 * Oo0Ooo + II111iiii / IiII + Ii1I
 if 63 - 63: OoO0O00 + I1ii11iIi11i . I1Ii111 % I1Ii111
 if 57 - 57: II111iiii
 if ( I11 ) : I11 . cancel ( )
 if 54 - 54: Oo0Ooo + oO0o + i11iIiiIii
 if 28 - 28: oO0o
 if 70 - 70: IiII
 if 34 - 34: I1Ii111 % IiII
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( i111I , "" )
 lisp . lisp_close_socket ( II1Ii1iI1i , "" )
 lisp . lisp_close_socket ( oO0oIIII , "lisp-itr" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lispers.net-itr" )
 return
 if 3 - 3: II111iiii / OOooOOo + IiII . ooOoO0o . OoO0O00
 if 83 - 83: oO0o + OoooooooOO
 if 22 - 22: Ii1I % iII111i * OoooooooOO - o0oOOo0O0Ooo / iIii1I11I1II1
 if 86 - 86: OoooooooOO . iII111i % OoOoOO00 / I11i * iII111i / o0oOOo0O0Ooo
 if 64 - 64: i11iIiiIii
 if 38 - 38: IiII / I1IiiI - IiII . I11i
 if 69 - 69: OoooooooOO + I1ii11iIi11i
def O0oOo00o0 ( packet , device , input_interface , macs , my_sa ) :
 global II1iII1i
 global iiI1iIiI
 global Ii1IIii11 , Oooo0000
 global oO0oIIII
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 O0O0oOOo0O = packet
 packet , II11 , O00oooo00o0O , ii1iii1I1I = lisp . lisp_is_rloc_probe ( packet , 1 )
 if ( O0O0oOOo0O != packet ) :
  if ( II11 == None ) : return
  lisp . lisp_parse_packet ( II1iII1i , packet , II11 , O00oooo00o0O , ii1iii1I1I )
  return
  if 95 - 95: IiII
  if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 packet = lisp . lisp_packet ( packet )
 if ( packet . decode ( False , None , None ) == None ) : return
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
 if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 if ( my_sa ) : input_interface = device
 if 59 - 59: OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 Iii = packet . inner_source
 OO00Oo = lisp . lisp_get_interface_instance_id ( input_interface , Iii )
 packet . inner_dest . instance_id = OO00Oo
 packet . inner_source . instance_id = OO00Oo
 if 20 - 20: o0oOOo0O0Ooo / i1IIi
 if 71 - 71: OoOoOO00 . i1IIi
 if 94 - 94: OOooOOo . I1Ii111
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 if ( macs != "" ) : macs = ", MACs: " + macs + ","
 packet . print_packet ( "Receive {}{}" . format ( device , macs ) , False )
 if 47 - 47: OoooooooOO
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 if 82 - 82: ooOoO0o + II111iiii
 if ( device != input_interface and device != "lispers.net" ) :
  lisp . dprint ( "Not our MAC address on interface {}, pcap interface {}" . format ( input_interface , device ) )
  if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
  return
  if 68 - 68: Oo0Ooo + i11iIiiIii
  if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
 O0OO0oOoO0O0O = lisp . lisp_decent_push_configured
 if ( O0OO0oOoO0O0O ) :
  oo000oOo0 = packet . inner_dest . is_multicast_address ( )
  iIiI1I1Ii = packet . inner_source . is_local ( )
  O0OO0oOoO0O0O = ( iIiI1I1Ii and oo000oOo0 )
  if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
  if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
 if ( O0OO0oOoO0O0O == False ) :
  if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
  if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
  if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
  if 93 - 93: Ii1I - OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
  Oo0ooOo0o = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False )
  if ( Oo0ooOo0o == None ) :
   lisp . dprint ( "Packet received from non-EID source" )
   return
   if 49 - 49: OoooooooOO * I11i - Oo0Ooo . oO0o
   if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
   if 46 - 46: OoO0O00
   if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
   if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
  if ( Oo0ooOo0o . dynamic_eid_configured ( ) ) :
   O00o00O = lisp . lisp_allow_dynamic_eid ( input_interface ,
 packet . inner_source )
   if ( O00o00O ) :
    lisp . lisp_itr_discover_eid ( Oo0ooOo0o , packet . inner_source ,
 input_interface , O00o00O , oO0oIIII )
   else :
    ii1iii11i1 = lisp . green ( packet . inner_source . print_address ( ) , False )
    lisp . dprint ( "Disallow dynamic-EID {} on interface {}" . format ( ii1iii11i1 ,
 input_interface ) )
    return
    if 4 - 4: IiII . IiII % I1ii11iIi11i % Ii1I / Ii1I
    if 29 - 29: Oo0Ooo * ooOoO0o * I1ii11iIi11i / i11iIiiIii
    if 26 - 26: IiII % I1Ii111 % oO0o % Ii1I
  if ( packet . inner_source . is_local ( ) and
 packet . udp_dport == lisp . LISP_CTRL_PORT ) : return
  if 55 - 55: ooOoO0o % OoooooooOO / OoooooooOO % OoooooooOO
  if 52 - 52: I1ii11iIi11i + I1ii11iIi11i . II111iiii
  if 34 - 34: OoooooooOO . O0 / oO0o * OoOoOO00 - I1ii11iIi11i
  if 36 - 36: i1IIi / O0 / OoO0O00 - O0 - i1IIi
  if 22 - 22: i1IIi + Ii1I
 if ( packet . inner_version == 4 ) :
  O0o0O0OO00o , packet . packet = lisp . lisp_ipv4_input ( packet . packet )
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
  if 92 - 92: o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % OoO0O00 % IiII . OoooooooOO
  if 52 - 52: ooOoO0o / i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + o0oOOo0O0Ooo
  if 71 - 71: oO0o % I11i * OoOoOO00 . O0 / Ii1I . I1ii11iIi11i
  if 58 - 58: Oo0Ooo / oO0o
  if 44 - 44: OOooOOo
  if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
 if ( oo0O000OoO == False ) :
  Oo0ooOo0o = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( Oo0ooOo0o and Oo0ooOo0o . dynamic_eid_configured == False ) :
   lisp . dprint ( ( "Packet destined to local EID-prefix {}, " + "natively forwarding" ) . format ( Oo0ooOo0o . print_eid_tuple ( ) ) )
   if 79 - 79: Ii1I . OoO0O00
   packet . send_packet ( Ii1IIii11 , packet . inner_dest )
   return
   if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
   if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
   if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
   if 52 - 52: i1IIi
   if 84 - 84: Ii1I / IiII
   if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 IiIIiIIIiIii = lisp . lisp_map_cache_lookup ( packet . inner_source , packet . inner_dest )
 if ( IiIIiIIIiIii ) : IiIIiIIIiIii . add_recent_source ( packet . inner_source )
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 if 8 - 8: o0oOOo0O0Ooo
 if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
 if 78 - 78: Ii1I / II111iiii % OoOoOO00
 if 52 - 52: OOooOOo - iII111i * oO0o
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
 iiIii1I = Oo0ooOo0o . secondary_iid if ( Oo0ooOo0o != None ) else None
 if ( iiIii1I and IiIIiIIIiIii and IiIIiIIIiIii . action == lisp . LISP_NATIVE_FORWARD_ACTION ) :
  i1I11iIiII = packet . inner_dest
  i1I11iIiII . instance_id = iiIii1I
  IiIIiIIIiIii = lisp . lisp_map_cache_lookup ( packet . inner_source , i1I11iIiII )
  if ( IiIIiIIIiIii ) : IiIIiIIIiIii . add_recent_source ( packet . inner_source )
  if 66 - 66: Oo0Ooo - o0oOOo0O0Ooo * IiII + OoOoOO00 + o0oOOo0O0Ooo - iIii1I11I1II1
  if 17 - 17: oO0o
  if 22 - 22: I11i + iIii1I11I1II1
  if 24 - 24: OoOoOO00 % i1IIi + iII111i . i11iIiiIii . I1ii11iIi11i
  if 17 - 17: I1ii11iIi11i . II111iiii . ooOoO0o / I1ii11iIi11i
 if ( IiIIiIIIiIii == None or lisp . lisp_mr_or_pubsub ( IiIIiIIIiIii . action ) ) :
  if ( lisp . lisp_rate_limit_map_request ( packet . inner_dest ) ) : return
  if 57 - 57: I11i
  oO0 = ( IiIIiIIIiIii . action == lisp . LISP_SEND_PUBSUB_ACTION )
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 packet . inner_source , packet . inner_dest , None , oO0 )
  if 87 - 87: oO0o % Ii1I
  if ( packet . is_trace ( ) ) :
   lisp . lisp_trace_append ( packet , reason = "map-cache miss" )
   if 83 - 83: II111iiii - I11i
  return
  if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
  if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
  if 51 - 51: OoOoOO00
  if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
  if 53 - 53: Ii1I % Oo0Ooo
  if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if ( IiIIiIIIiIii and IiIIiIIIiIii . is_active ( ) and IiIIiIIIiIii . has_ttl_elapsed ( ) ) :
  if ( lisp . lisp_rate_limit_map_request ( packet . inner_dest ) == False ) :
   lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( IiIIiIIIiIii . print_eid_tuple ( ) , False ) ) )
   if 41 - 41: Ii1I % I1ii11iIi11i
   lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 packet . inner_source , packet . inner_dest , None )
   if 12 - 12: OOooOOo
   if 69 - 69: OoooooooOO + OOooOOo
   if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
   if 31 - 31: I11i % OOooOOo * I11i
   if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
   if 1 - 1: iIii1I11I1II1
   if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 IiIIiIIIiIii . last_refresh_time = time . time ( )
 IiIIiIIIiIii . stats . increment ( len ( packet . packet ) )
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 i1I1iIi1IiI , i1111 , O0O000OOOo , i11ii1Ii1 , i1i1II1i11 , o00o = IiIIiIIIiIii . select_rloc ( packet , oO0oIIII )
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if ( i1I1iIi1IiI == None and i1i1II1i11 == None ) :
  if ( i11ii1Ii1 == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   packet . send_packet ( Ii1IIii11 , packet . inner_dest )
   if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
   if ( packet . is_trace ( ) ) :
    lisp . lisp_trace_append ( packet , reason = "not an EID" )
    if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
   return
   if 62 - 62: i1IIi - OoOoOO00
  oo0O0oo = "No reachable RLOCs found"
  lisp . dprint ( oo0O0oo )
  if ( packet . is_trace ( ) ) : lisp . lisp_trace_append ( packet , reason = oo0O0oo )
  return
  if 14 - 14: O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
 if ( i1I1iIi1IiI and i1I1iIi1IiI . is_null ( ) ) :
  oo0O0oo = "Drop action RLOC found"
  lisp . dprint ( oo0O0oo )
  if 96 - 96: iII111i
  if ( packet . is_trace ( ) ) : lisp . lisp_trace_append ( packet , reason = oo0O0oo )
  return
  if 18 - 18: iII111i * I11i - Ii1I
  if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
  if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
  if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
  if 39 - 39: iIii1I11I1II1 - OoooooooOO
 packet . outer_tos = packet . inner_tos
 packet . outer_ttl = 32 if ( O0o0O0OO00o ) else packet . inner_ttl
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if ( i1I1iIi1IiI ) :
  packet . outer_dest . copy_address ( i1I1iIi1IiI )
  Ooooo0OoO0 = packet . outer_dest . afi_to_version ( )
  packet . outer_version = Ooooo0OoO0
  iI1 = lisp . lisp_myrlocs [ 0 ] if ( Ooooo0OoO0 == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 31 - 31: oO0o / iIii1I11I1II1
  packet . outer_source . copy_address ( iI1 )
  if 84 - 84: OOooOOo
  if ( packet . is_trace ( ) ) :
   if ( lisp . lisp_trace_append ( packet , rloc_entry = o00o ) == False ) : return
   if 87 - 87: ooOoO0o + o0oOOo0O0Ooo
   if 28 - 28: OOooOOo * I1ii11iIi11i / oO0o
   if 64 - 64: oO0o - I1IiiI / iII111i - OoO0O00
   if 37 - 37: i11iIiiIii / iII111i
   if 85 - 85: i11iIiiIii + I1Ii111 * OoOoOO00
   if 1 - 1: i1IIi / Oo0Ooo . OoO0O00
  if ( packet . encode ( O0O000OOOo ) == None ) : return
  if ( len ( packet . packet ) <= 1500 ) : packet . print_packet ( "Send" , True )
  if 57 - 57: I11i . Oo0Ooo + II111iiii
  if 43 - 43: I1Ii111 % iII111i
  if 69 - 69: iII111i % OoO0O00
  if 86 - 86: oO0o / oO0o
  IiiI = Oooo0000 if Ooooo0OoO0 == 6 else Ii1IIii11
  packet . send_packet ( IiiI , packet . outer_dest )
  if 19 - 19: II111iiii
 elif ( i1i1II1i11 ) :
  if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
  if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
  if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
  if 32 - 32: i11iIiiIii - I1Ii111
  if 53 - 53: OoooooooOO - IiII
  oOo = i1i1II1i11 . rle_nodes [ 0 ] . level
  i1i = len ( packet . packet )
  for IIIiiiI in i1i1II1i11 . rle_forwarding_list :
   if ( IIIiiiI . level != oOo ) : return
   if 94 - 94: O0 - I11i - iIii1I11I1II1 % ooOoO0o / Ii1I % iII111i
   packet . outer_dest . copy_address ( IIIiiiI . address )
   if ( O0OO0oOoO0O0O ) : packet . inner_dest . instance_id = 0xffffff
   Ooooo0OoO0 = packet . outer_dest . afi_to_version ( )
   packet . outer_version = Ooooo0OoO0
   iI1 = lisp . lisp_myrlocs [ 0 ] if ( Ooooo0OoO0 == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 44 - 44: Oo0Ooo % iIii1I11I1II1
   packet . outer_source . copy_address ( iI1 )
   if 90 - 90: II111iiii + OoooooooOO % OoooooooOO
   if ( packet . is_trace ( ) ) :
    if ( lisp . lisp_trace_append ( packet ) == False ) : return
    if 35 - 35: iII111i / I1ii11iIi11i * OoooooooOO . II111iiii / Oo0Ooo
    if 1 - 1: OoooooooOO + IiII . i1IIi % I11i
   if ( packet . encode ( None ) == None ) : return
   if 66 - 66: o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
   if 12 - 12: iII111i . IiII . OoOoOO00 / O0
   if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
   if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
   packet . print_packet ( "Replicate-to-L{}" . format ( IIIiiiI . level ) , True )
   packet . send_packet ( Ii1IIii11 , packet . outer_dest )
   if 8 - 8: ooOoO0o * O0
   if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
   if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
   if 34 - 34: ooOoO0o
   if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
   IIi11i1II = len ( packet . packet ) - i1i
   packet . packet = packet . packet [ IIi11i1II : : ]
   if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
   if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
   if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
   if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
   if 87 - 87: oO0o - i11iIiiIii
   if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 del ( packet )
 return
 if 23 - 23: I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
def I11i1iIiiIiIi ( device , not_used , packet ) :
 I1i = 4 if device == "lo0" else 0 if device == "lispers.net" else 14
 if 59 - 59: OoooooooOO . Ii1I / O0 - OOooOOo
 if ( lisp . lisp_frame_logging ) :
  i1I1i = lisp . bold ( "Received frame on interface '{}'" . format ( device ) ,
 False )
  OO0o = lisp . lisp_format_packet ( packet [ 0 : 64 ] )
  lisp . lprint ( "{}: {}" . format ( i1I1i , OO0o ) )
  if 32 - 32: OoooooooOO - OoOoOO00 - i11iIiiIii * o0oOOo0O0Ooo / Oo0Ooo + OoooooooOO
  if 35 - 35: i1IIi - o0oOOo0O0Ooo * iII111i
  if 63 - 63: iII111i * I1ii11iIi11i . OoooooooOO / OOooOOo * Oo0Ooo . ooOoO0o
  if 62 - 62: i1IIi / ooOoO0o . I1IiiI * o0oOOo0O0Ooo
  if 21 - 21: o0oOOo0O0Ooo
 O0Oo0 = ""
 o0oO0oo0000OO = False
 OOo0oO00ooO00 = device
 if ( I1i == 14 ) :
  iIiIIi1 , I1i1ii1IiIii , oOOO0O0Ooo , o0oO0oo0000OO = lisp . lisp_get_input_interface ( packet )
  OOo0oO00ooO00 = device if ( device in iIiIIi1 ) else iIiIIi1 [ 0 ]
  O0Oo0 = lisp . lisp_format_macs ( I1i1ii1IiIii , oOOO0O0Ooo )
  if ( OOo0oO00ooO00 . find ( "vlan" ) != - 1 ) : I1i += 4
  if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
  if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
  if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
  if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
  if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
  if 62 - 62: o0oOOo0O0Ooo
  if ( int ( oOOO0O0Ooo [ 1 ] , 16 ) & 1 ) : o0oO0oo0000OO = True
  if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
  if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
  if 72 - 72: iIii1I11I1II1
  if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if ( I1i != 0 ) :
  oOo0OOoooO = struct . unpack ( "H" , packet [ I1i - 2 : I1i ] ) [ 0 ]
  oOo0OOoooO = socket . ntohs ( oOo0OOoooO )
  if ( oOo0OOoooO == 0x8100 ) :
   iIi1iIIIiIiI = struct . unpack ( "I" , packet [ I1i : I1i + 4 ] ) [ 0 ]
   iIi1iIIIiIiI = socket . ntohl ( iIi1iIIIiIiI )
   OOo0oO00ooO00 = "vlan" + str ( iIi1iIIIiIiI >> 16 )
   I1i += 4
  elif ( oOo0OOoooO == 0x806 ) :
   lisp . dprint ( "Dropping ARP packets, host should have default route" )
   return
   if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
   if 84 - 84: i11iIiiIii * OoO0O00
   if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 if ( lisp . lisp_l2_overlay ) : I1i = 0
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 O0oOo00o0 ( packet [ I1i : : ] , device , OOo0oO00ooO00 , O0Oo0 , o0oO0oo0000OO )
 return
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
def OO0oOOoo ( sources , dyn_eids ) :
 if ( os . getenv ( "LISP_NO_IPTABLES" ) != None ) :
  lisp . lprint ( "User selected to suppress installing iptables rules" )
  return
  if 100 - 100: O0 . I11i . OoO0O00 + O0 * oO0o
  if 42 - 42: oO0o % OoooooooOO + o0oOOo0O0Ooo
 os . system ( "sudo iptables -t raw -N lisp" )
 os . system ( "sudo iptables -t raw -A PREROUTING -j lisp" )
 os . system ( "sudo ip6tables -t raw -N lisp" )
 os . system ( "sudo ip6tables -t raw -A PREROUTING -j lisp" )
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
 if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
 if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
 if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
 oo0i1iIIi1II1iiI = "sudo ip{}tables -t raw -A lisp -j ACCEPT -d {}"
 III1Ii1i1I1 = [ "127.0.0.1" , "::1" , "224.0.0.0/4 -p igmp" , "ff00::/8" ,
 "fe80::/16" ]
 III1Ii1i1I1 += sources + lisp . lisp_get_all_addresses ( )
 for O0O00OooO in III1Ii1i1I1 :
  if ( lisp . lisp_is_mac_string ( O0O00OooO ) ) : continue
  I1IiI1iI11 = "" if O0O00OooO . find ( ":" ) == - 1 else "6"
  os . system ( oo0i1iIIi1II1iiI . format ( I1IiI1iI11 , O0O00OooO ) )
  if 2 - 2: iIii1I11I1II1
  if 45 - 45: OoooooooOO / i11iIiiIii
  if 10 - 10: iII111i - oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - I1ii11iIi11i
  if 97 - 97: II111iiii % I1Ii111 + I1Ii111 - OoO0O00 / Ii1I * I1IiiI
  if 17 - 17: Ii1I
  if 39 - 39: ooOoO0o . II111iiii
  if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
  if 77 - 77: I1Ii111 - I11i
 if ( lisp . lisp_pitr == False ) :
  oo0i1iIIi1II1iiI = "sudo ip{}tables -t raw -A lisp -j ACCEPT -s {} -d {}"
  iiI1iI1I = "sudo ip{}tables -t raw -C lisp -j ACCEPT -s {} -d {}"
  for II11 in sources :
   if ( lisp . lisp_is_mac_string ( II11 ) ) : continue
   if ( II11 in dyn_eids ) : continue
   I1IiI1iI11 = "" if II11 . find ( ":" ) == - 1 else "6"
   for O0OOO0OOoO0O in sources :
    if ( lisp . lisp_is_mac_string ( O0OOO0OOoO0O ) ) : continue
    if ( O0OOO0OOoO0O in dyn_eids ) : continue
    if ( O0OOO0OOoO0O . find ( "." ) != - 1 and II11 . find ( "." ) == - 1 ) : continue
    if ( O0OOO0OOoO0O . find ( ":" ) != - 1 and II11 . find ( ":" ) == - 1 ) : continue
    if ( commands . getoutput ( iiI1iI1I . format ( I1IiI1iI11 , II11 , O0OOO0OOoO0O ) ) == "" ) :
     continue
     if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
    os . system ( oo0i1iIIi1II1iiI . format ( I1IiI1iI11 , II11 , O0OOO0OOoO0O ) )
    if 55 - 55: ooOoO0o
    if 82 - 82: I1Ii111 - OOooOOo + OoO0O00
    if 64 - 64: o0oOOo0O0Ooo . O0 * Ii1I + OoooooooOO - Oo0Ooo . OoooooooOO
    if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
    if 55 - 55: iII111i - OoO0O00
    if 100 - 100: O0
    if 79 - 79: iIii1I11I1II1
 O00oO0o = "sudo ip{}tables -t raw -A lisp -j DROP -s {}"
 for II11 in sources :
  if ( lisp . lisp_is_mac_string ( II11 ) ) : continue
  I1IiI1iI11 = "" if II11 . find ( ":" ) == - 1 else "6"
  os . system ( O00oO0o . format ( I1IiI1iI11 , II11 ) )
  if 15 - 15: I1Ii111 + I11i . OoooooooOO . i11iIiiIii
  if 31 - 31: OoooooooOO + iII111i - OoOoOO00 . i1IIi % iII111i
  if 43 - 43: OOooOOo * ooOoO0o / iIii1I11I1II1 - Ii1I * Ii1I
  if 60 - 60: iIii1I11I1II1 . OOooOOo + I1ii11iIi11i
  if 44 - 44: O0 . oO0o * i11iIiiIii % i11iIiiIii + O0 / OOooOOo
 o00oOOO0Ooo = commands . getoutput ( "sudo iptables -t raw -S lisp" ) . split ( "\n" )
 o00oOOO0Ooo += commands . getoutput ( "sudo ip6tables -t raw -S lisp" ) . split ( "\n" )
 lisp . lprint ( "Using kernel filters: {}" . format ( o00oOOO0Ooo ) )
 if 50 - 50: Ii1I - i11iIiiIii + iIii1I11I1II1 / O0 - Ii1I + o0oOOo0O0Ooo
 if 22 - 22: II111iiii - Ii1I / ooOoO0o % OoooooooOO + OOooOOo
 if 5 - 5: OoO0O00 / iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if ( os . getenv ( "LISP_VIRTIO_BUG" ) != None ) :
  Oo00ooO0OoOo = ( "sudo iptables -A POSTROUTING -t mangle -p tcp -j " + "CHECKSUM --checksum-fill; " )
  if 99 - 99: OoOoOO00
  Oo00ooO0OoOo += ( "sudo iptables -A POSTROUTING -t mangle -p udp -j " + "CHECKSUM --checksum-fill; " )
  if 77 - 77: o0oOOo0O0Ooo
  Oo00ooO0OoOo += ( "sudo ip6tables -A POSTROUTING -t mangle -p tcp -j " + "CHECKSUM --checksum-fill; " )
  if 48 - 48: OoOoOO00 % I1ii11iIi11i / I11i . iIii1I11I1II1 * II111iiii
  Oo00ooO0OoOo += ( "sudo ip6tables -A POSTROUTING -t mangle -p udp -j " + "CHECKSUM --checksum-fill" )
  if 65 - 65: OoOoOO00
  os . system ( Oo00ooO0OoOo )
  I1iI11I1III1 = lisp . bold ( "virtio" , False )
  lisp . lprint ( "{} bug workaround, configure '{}'" . format ( I1iI11I1III1 , Oo00ooO0OoOo ) )
  if 8 - 8: i11iIiiIii / II111iiii + o0oOOo0O0Ooo * Ii1I % IiII . I11i
 return
 if 6 - 6: IiII % Oo0Ooo . Oo0Ooo - I1ii11iIi11i / I11i . i1IIi
 if 99 - 99: OoOoOO00 . I1Ii111
 if 59 - 59: I11i / Oo0Ooo / OOooOOo / O0 / OoOoOO00 + o0oOOo0O0Ooo
 if 13 - 13: o0oOOo0O0Ooo % oO0o / I1Ii111 % I1Ii111 % O0
 if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
def o00oOo0oOoo ( sources , dyn_eids , l2_overlay , pitr ) :
 if ( l2_overlay ) :
  i1I11IiI1iiII = "ether[6:4] >= 0 and ether[10:2] >= 0"
  lisp . lprint ( "Using pcap filter: '{}'" . format ( i1I11IiI1iiII ) )
  return ( i1I11IiI1iiII )
  if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
  if 79 - 79: OoOoOO00 / ooOoO0o
 oOo00o = "(not ether proto 0x806)"
 iI1iIIIi1i = " or (udp src port 4342 and ip[28] == 0x28)"
 OOoooooooO = " or (ip[16] >= 224 and ip[16] < 240 and (ip[28] & 0xf0) == 0x30)"
 if 4 - 4: Oo0Ooo + o0oOOo0O0Ooo
 if 17 - 17: OoO0O00 * OoOoOO00
 ii11i = ""
 o00Oo = ""
 for II11 in sources :
  O000oOo = II11
  if ( lisp . lisp_is_mac_string ( II11 ) ) :
   O000oOo = II11 . split ( "/" ) [ 0 ]
   O000oOo = O000oOo . replace ( "-" , "" )
   IiiIIi1 = [ ]
   for O00o00O in range ( 0 , 12 , 2 ) : IiiIIi1 . append ( O000oOo [ O00o00O : O00o00O + 2 ] )
   O000oOo = "ether host " + ":" . join ( IiiIIi1 )
   if 28 - 28: o0oOOo0O0Ooo
   if 45 - 45: o0oOOo0O0Ooo . I1IiiI / I1Ii111 - Oo0Ooo * iIii1I11I1II1
  ii11i += "{}" . format ( O000oOo )
  if ( II11 not in dyn_eids ) : o00Oo += "{}" . format ( O000oOo )
  if ( sources [ - 1 ] == II11 ) : break
  ii11i += " or "
  if ( II11 not in dyn_eids ) : o00Oo += " or "
  if 86 - 86: II111iiii + ooOoO0o + IiII
 if ( o00Oo [ - 4 : : ] == " or " ) : o00Oo = o00Oo [ 0 : - 4 ]
 if 9 - 9: ooOoO0o + II111iiii % ooOoO0o % IiII + iIii1I11I1II1
 if 59 - 59: i1IIi
 if 48 - 48: O0 * Ii1I * OoO0O00 . OoO0O00 * I11i - Ii1I
 if 14 - 14: I1ii11iIi11i + i11iIiiIii
 if 83 - 83: I1ii11iIi11i / i11iIiiIii + II111iiii . iII111i * OOooOOo + IiII
 if 42 - 42: i1IIi % II111iiii . ooOoO0o
 II1II1iI = commands . getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 II1II1iI = ( II1II1iI != "" and II1II1iI [ 0 ] == " " )
 Ooo = lisp . lisp_get_loopback_address ( ) if ( II1II1iI ) else None
 if 88 - 88: OoooooooOO
 iIiI1I1ii1I1 = ""
 O00oO = lisp . lisp_get_all_addresses ( )
 for O0O00OooO in O00oO :
  if ( O0O00OooO == Ooo ) : continue
  iIiI1I1ii1I1 += "{}" . format ( O0O00OooO )
  if ( O00oO [ - 1 ] == O0O00OooO ) : break
  iIiI1I1ii1I1 += " or "
  if 83 - 83: o0oOOo0O0Ooo
  if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if ( ii11i != "" ) :
  ii11i = " and (src net {})" . format ( ii11i )
  if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if ( o00Oo != "" ) :
  o00Oo = " and not (dst net {})" . format ( o00Oo )
  if 48 - 48: iII111i + IiII
 if ( iIiI1I1ii1I1 != "" ) :
  iIiI1I1ii1I1 = " and not (dst host {})" . format ( iIiI1I1ii1I1 )
  if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
  if 14 - 14: OOooOOo
  if 79 - 79: Ii1I
  if 76 - 76: iIii1I11I1II1
  if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
  if 93 - 93: OoooooooOO * Oo0Ooo
  if 10 - 10: I1Ii111 * OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i11iIiiIii
 if ( pitr ) :
  o00Oo = ""
  iIiI1I1ii1I1 = iIiI1I1ii1I1 . replace ( "dst " , "" )
  if 22 - 22: I1Ii111 / o0oOOo0O0Ooo
  if 98 - 98: i1IIi
  if 51 - 51: I1ii11iIi11i + ooOoO0o + Oo0Ooo / i1IIi + i1IIi
  if 12 - 12: iIii1I11I1II1 . Ii1I . I1ii11iIi11i % I1IiiI . II111iiii . oO0o
  if 32 - 32: I1ii11iIi11i + IiII / O0 / OoOoOO00 * OoooooooOO % ooOoO0o
 i1I11IiI1iiII = oOo00o + ii11i + o00Oo + iIiI1I1ii1I1
 i1I11IiI1iiII += iI1iIIIi1i
 i1I11IiI1iiII += OOoooooooO
 if 50 - 50: OoO0O00
 lisp . lprint ( "Using pcap filter: '{}'" . format ( i1I11IiI1iiII ) )
 return ( i1I11IiI1iiII )
 if 66 - 66: iIii1I11I1II1
 if 41 - 41: I1Ii111 . O0 * I1IiiI * I1ii11iIi11i
 if 100 - 100: iII111i
 if 73 - 73: I1ii11iIi11i % II111iiii
 if 79 - 79: OoOoOO00 + OoO0O00 - II111iiii + Ii1I
 if 11 - 11: oO0o + iIii1I11I1II1
 if 10 - 10: O0
def Oo0000oOo ( device , pfilter , pcap_lock ) :
 lisp . lisp_set_exception ( )
 if 68 - 68: OOooOOo + oO0o . O0 . Ii1I % i1IIi % OOooOOo
 pcap_lock . acquire ( )
 i1I1iI = pcappy . open_live ( device , 9000 , 0 , 100 )
 pcap_lock . release ( )
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 i1I1iI . filter = pfilter
 i1I1iI . loop ( - 1 , I11i1iIiiIiIi , device )
 return
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
def oOOoOOO0oo0 ( ) :
 global I11
 global II1Ii1iI1i
 global II1iII1i
 if 87 - 87: ooOoO0o / OoOoOO00 % o0oOOo0O0Ooo * oO0o
 lisp . lisp_set_exception ( )
 if 77 - 77: oO0o - Oo0Ooo - iIii1I11I1II1
 if 16 - 16: OoO0O00 / iII111i / i1IIi . iII111i + oO0o
 if 26 - 26: iIii1I11I1II1 + i1IIi / OoOoOO00 % I1ii11iIi11i
 if 44 - 44: OoooooooOO . II111iiii . OOooOOo % OoooooooOO
 if 86 - 86: i11iIiiIii + O0 * IiII - OoO0O00 * OOooOOo + O0
 Oo0 = [ II1Ii1iI1i , II1Ii1iI1i ,
 oO0oIIII ]
 lisp . lisp_build_info_requests ( Oo0 , None , lisp . LISP_CTRL_PORT )
 if 94 - 94: I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
 if 81 - 81: Oo0Ooo - I11i
 if 24 - 24: OoooooooOO . OoO0O00 * II111iiii
 if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
 I11 . cancel ( )
 I11 = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 oOOoOOO0oo0 , [ ] )
 I11 . start ( )
 return
 if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
 if 79 - 79: I1IiiI - ooOoO0o
 if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 if 83 - 83: IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
def O0000oO0o00 ( kv_pair ) :
 global II1iII1i
 global iiI1iIiI
 global I11
 if 80 - 80: OoooooooOO + IiII
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , iiI1iIiI ] )
  lisp . lisp_test_mr_timer . start ( )
  if 43 - 43: Oo0Ooo . I1Ii111
  if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
  if 29 - 29: IiII . ooOoO0o - II111iiii
  if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
  if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 I11 = threading . Timer ( 0 , oOOoOOO0oo0 , [ ] )
 I11 . start ( )
 return
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
def i1ii1iiIi1II ( kv_pair ) :
 lispconfig . lisp_database_mapping_command ( kv_pair )
 return
 if 98 - 98: OoO0O00 - Ii1I . IiII % i11iIiiIii
 if 69 - 69: I1ii11iIi11i + iII111i * O0 . OOooOOo % OoOoOO00
 if 96 - 96: ooOoO0o . ooOoO0o - I11i / I11i
 if 96 - 96: i11iIiiIii / I1IiiI - O0 . ooOoO0o
 if 39 - 39: ooOoO0o / O0 * IiII
 if 17 - 17: Ii1I / iIii1I11I1II1 - OoO0O00 + I1IiiI % OOooOOo
 if 14 - 14: o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
 if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
def IiI1Iii1 ( kv_pair ) :
 global i111I
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
 if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
 if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 if 88 - 88: o0oOOo0O0Ooo
 iI11 = lisp . lisp_nat_traversal
 OO0O00O = lisp . lisp_rloc_probing
 if 31 - 31: i11iIiiIii
 if 12 - 12: ooOoO0o
 if 86 - 86: oO0o - OoO0O00
 if 63 - 63: I1IiiI / OoOoOO00 + OoooooooOO . I11i . ooOoO0o
 lispconfig . lisp_xtr_command ( kv_pair )
 if 48 - 48: i1IIi - iII111i - i11iIiiIii . I11i - iII111i * I11i
 if 60 - 60: OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 Oo0O0000Oo00o = ( iI11 == False and lisp . lisp_nat_traversal and lisp . lisp_rloc_probing )
 if 20 - 20: OoO0O00 . I1IiiI * i11iIiiIii / i11iIiiIii
 o00 = ( OO0O00O == False and lisp . lisp_rloc_probing )
 if 4 - 4: OoO0O00
 ooOO = 0
 if ( o00 ) : ooOO = 1
 if ( Oo0O0000Oo00o ) : ooOO = 5
 if 5 - 5: OoooooooOO / o0oOOo0O0Ooo % I11i % OoO0O00 * iII111i + iIii1I11I1II1
 if ( ooOO != 0 ) :
  I11iiI11iiI = [ i111I , i111I ]
  lisp . lisp_start_rloc_probe_timer ( ooOO , I11iiI11iiI )
  if 51 - 51: oO0o . iIii1I11I1II1 + OoO0O00 * Ii1I + i1IIi
  if 81 - 81: O0 - Ii1I + Oo0Ooo
  if 67 - 67: Ii1I
  if 43 - 43: OoO0O00 % OoO0O00
  if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
  if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if ( lisp . lisp_crypto_ephem_port == None and lisp . lisp_data_plane_security ) :
  O00oooo00o0O = i111I . getsockname ( ) [ 1 ]
  lisp . lisp_crypto_ephem_port = O00oooo00o0O
  lisp . lprint ( "Use port {} for lisp-crypto packets" . format ( O00oooo00o0O ) )
  i1I111Ii = { "type" : "itr-crypto-port" , "port" : O00oooo00o0O }
  lisp . lisp_write_to_dp_socket ( i1I111Ii )
  if 31 - 31: I1IiiI
  if 73 - 73: ooOoO0o . O0 / o0oOOo0O0Ooo - OoooooooOO % i11iIiiIii
  if 80 - 80: Ii1I / ooOoO0o % O0 . Oo0Ooo
  if 63 - 63: OOooOOo . II111iiii . I11i
  if 46 - 46: ooOoO0o % IiII - o0oOOo0O0Ooo - Oo0Ooo - Ii1I / I11i
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 68 - 68: i1IIi - I1ii11iIi11i / Oo0Ooo % I11i . iII111i
 if 9 - 9: IiII
 if 48 - 48: o0oOOo0O0Ooo + o0oOOo0O0Ooo - Oo0Ooo
 if 27 - 27: OoO0O00 + OoOoOO00 * ooOoO0o
 if 83 - 83: iIii1I11I1II1
 if 72 - 72: I11i
 if 87 - 87: i1IIi
 if 48 - 48: Oo0Ooo * oO0o * iIii1I11I1II1 + i11iIiiIii - OoooooooOO
 if 38 - 38: OoOoOO00 / iIii1I11I1II1 % i11iIiiIii - IiII * iII111i / OoOoOO00
def iIII11I1I1II ( ipc ) :
 ii1IIiII111I , O00OoOoO , ooO0o0oo , O0O000OOOo = ipc . split ( "%" )
 O0O000OOOo = int ( O0O000OOOo , 16 )
 if 79 - 79: IiII % OoO0O00
 Oo0oOO = lisp . lisp_get_echo_nonce ( None , ooO0o0oo )
 if ( Oo0oOO == None ) : Oo0oOO = lisp . lisp_echo_nonce ( ooO0o0oo )
 if 86 - 86: iIii1I11I1II1 / O0
 if 17 - 17: II111iiii
 if 9 - 9: OoooooooOO + oO0o
 if 33 - 33: O0
 if 39 - 39: I1IiiI + Oo0Ooo
 if ( O00OoOoO == "R" ) :
  Oo0oOO . request_nonce_rcvd = O0O000OOOo
  Oo0oOO . last_request_nonce_rcvd = lisp . lisp_get_timestamp ( )
  Oo0oOO . echo_nonce_sent = O0O000OOOo
  Oo0oOO . last_new_echo_nonce_sent = lisp . lisp_get_timestamp ( )
  lisp . lprint ( "Start echo-nonce mode for {}, nonce 0x{}" . format ( lisp . red ( Oo0oOO . rloc_str , False ) , lisp . lisp_hex_string ( O0O000OOOo ) ) )
  if 83 - 83: i1IIi
  if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
  if 49 - 49: IiII / ooOoO0o / OOooOOo
 if ( O00OoOoO == "E" ) :
  Oo0oOO . echo_nonce_rcvd = O0O000OOOo
  Oo0oOO . last_echo_nonce_rcvd = lisp . lisp_get_timestamp ( )
  if 25 - 25: I1IiiI % O0 + i1IIi - ooOoO0o
  if ( Oo0oOO . request_nonce_sent == O0O000OOOo ) :
   III1IiI1i1i = lisp . bold ( "echoed nonce" , False )
   lisp . lprint ( "Received {} {} from {}" . format ( III1IiI1i1i ,
 lisp . lisp_hex_string ( O0O000OOOo ) ,
 lisp . red ( Oo0oOO . rloc_str , False ) ) )
   if 94 - 94: iII111i - Oo0Ooo + oO0o
   Oo0oOO . request_nonce_sent = None
   lisp . lprint ( "Stop request-nonce mode for {}" . format ( lisp . red ( Oo0oOO . rloc_str , False ) ) )
   if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
   Oo0oOO . last_good_echo_nonce_rcvd = lisp . lisp_get_timestamp ( )
  else :
   oO0o0Oo = "none"
   if ( Oo0oOO . request_nonce_sent ) :
    oO0o0Oo = lisp . lisp_hex_string ( Oo0oOO . request_nonce_sent )
    if 76 - 76: ooOoO0o / OoOoOO00 + I1ii11iIi11i
   lisp . lprint ( ( "Received echo-nonce 0x{} from {}, but request-" + "nonce is {}" ) . format ( lisp . lisp_hex_string ( O0O000OOOo ) ,
   # OOooOOo
 lisp . red ( Oo0oOO . rloc_str , False ) , oO0o0Oo ) )
   if 65 - 65: OoOoOO00
   if 91 - 91: IiII + Ii1I % Ii1I - O0 - i11iIiiIii
 return
 if 84 - 84: Oo0Ooo % iII111i % OoooooooOO + OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
I1IiII1I1i1I1 = {
 "lisp xtr-parameters" : [ IiI1Iii1 , {
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

 "lisp map-resolver" : [ O0000oO0o00 , {
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

 "lisp database-mapping" : [ i1ii1iiIi1II , {
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
if 28 - 28: Oo0Ooo + IiII % II111iiii / OoO0O00 + i11iIiiIii
if 20 - 20: I1ii11iIi11i
if 3 - 3: OoO0O00 * i1IIi . I1IiiI . O0 - OoOoOO00
if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
if ( I111I1Iiii1i ( ) == False ) :
 lisp . lprint ( "lisp_itr_startup() failed" )
 lisp . lisp_print_banner ( "ITR abnormal exit" )
 exit ( 1 )
 if 10 - 10: I1ii11iIi11i / i11iIiiIii - Ii1I + oO0o * I1IiiI
 if 94 - 94: I1IiiI + iIii1I11I1II1 / O0 - OoooooooOO % I1ii11iIi11i
o0Oo0oo = [ i111I , oO0oIIII ,
 II1Ii1iI1i , Oo0oO0oo0oO00 ]
if 44 - 44: I1IiiI % Ii1I * I1IiiI . Oo0Ooo + I1ii11iIi11i . OOooOOo
if 6 - 6: IiII * OoooooooOO + I1Ii111 / Ii1I
if 35 - 35: ooOoO0o % I1IiiI - ooOoO0o - OoO0O00 - OoooooooOO
if 46 - 46: i1IIi . i1IIi . oO0o / I11i / ooOoO0o
Ii1Iiii = True
Oo = [ i111I ] * 3
i1IIii11i1I1 = [ II1Ii1iI1i ] * 3
if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
while ( True ) :
 try : OOOO , oO , ii1IIiII111I = select . select ( o0Oo0oo , [ ] , [ ] )
 except : break
 if 19 - 19: I1IiiI % Ii1I . IiII * ooOoO0o
 if 89 - 89: OoOoOO00 . OOooOOo
 if 7 - 7: oO0o % OoOoOO00 - I1IiiI + Oo0Ooo
 if 70 - 70: II111iiii + I1Ii111 + i11iIiiIii - i1IIi / IiII
 if ( lisp . lisp_ipc_data_plane and Oo0oO0oo0oO00 in OOOO ) :
  lisp . lisp_process_punt ( Oo0oO0oo0oO00 , II1iII1i ,
 iiI1iIiI )
  if 40 - 40: I1ii11iIi11i * I1Ii111
  if 38 - 38: O0 . Oo0Ooo + OoOoOO00 - oO0o
  if 43 - 43: iII111i + Oo0Ooo / OoooooooOO
  if 24 - 24: O0 + o0oOOo0O0Ooo * Ii1I - I1Ii111
  if 10 - 10: i11iIiiIii
 if ( i111I in OOOO ) :
  O00OoOoO , II11 , O00oooo00o0O , ii11iO000oo00OOOOO = lisp . lisp_receive ( Oo [ 0 ] ,
 False )
  if ( II11 == "" ) : break
  if 52 - 52: Oo0Ooo . I11i / o0oOOo0O0Ooo + Ii1I % I11i
  if ( lisp . lisp_is_rloc_probe_reply ( ii11iO000oo00OOOOO [ 0 ] ) ) :
   lisp . lprint ( "ITR ignoring RLOC-probe reply, using pcap" )
   continue
   if 47 - 47: OoooooooOO / OOooOOo % OoO0O00 / Oo0Ooo - I1ii11iIi11i
  lisp . lisp_parse_packet ( Oo , ii11iO000oo00OOOOO , II11 , O00oooo00o0O )
  if 13 - 13: iII111i . I1IiiI * OOooOOo + Ii1I + I1IiiI - i11iIiiIii
  if 79 - 79: ooOoO0o . oO0o / oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
  if 19 - 19: I1ii11iIi11i
  if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
  if 66 - 66: O0
 if ( II1Ii1iI1i in OOOO ) :
  O00OoOoO , II11 , O00oooo00o0O , ii11iO000oo00OOOOO = lisp . lisp_receive ( i1IIii11i1I1 [ 0 ] ,
 False )
  if ( II11 == "" ) : break
  if 52 - 52: OoO0O00 * OoooooooOO
  if ( lisp . lisp_is_rloc_probe_reply ( ii11iO000oo00OOOOO [ 0 ] ) ) :
   lisp . lprint ( "ITR ignoring RLOC-probe reply, using pcap" )
   continue
   if 12 - 12: O0 + IiII * i1IIi . OoO0O00
  o0OO0oooo = lisp . lisp_parse_packet ( i1IIii11i1I1 , ii11iO000oo00OOOOO , II11 , O00oooo00o0O )
  if 40 - 40: I1Ii111 - OoOoOO00 * I11i - IiII / OoOoOO00
  if 71 - 71: oO0o / OoooooooOO % IiII / OoOoOO00 % I1Ii111
  if 19 - 19: I1Ii111 + IiII / oO0o / II111iiii
  if 92 - 92: i1IIi % ooOoO0o + ooOoO0o - iIii1I11I1II1 . Ii1I
  if 33 - 33: o0oOOo0O0Ooo / O0 + OOooOOo
  if ( o0OO0oooo ) :
   I11iiI11iiI = [ i111I , i111I ]
   lisp . lisp_start_rloc_probe_timer ( 0 , I11iiI11iiI )
   if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
   if 92 - 92: OoOoOO00 % O0
   if 55 - 55: iIii1I11I1II1 * iII111i
   if 85 - 85: iIii1I11I1II1 . II111iiii
   if 54 - 54: Ii1I . OoooooooOO % Oo0Ooo
   if 22 - 22: OOooOOo
   if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if ( oO0oIIII in OOOO ) :
  O00OoOoO , II11 , O00oooo00o0O , ii11iO000oo00OOOOO = lisp . lisp_receive ( oO0oIIII , True )
  if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
  if ( II11 == "" ) : break
  if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
  if ( O00OoOoO == "command" ) :
   if ( ii11iO000oo00OOOOO == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 94 - 94: i1IIi
   if ( ii11iO000oo00OOOOO . find ( "nonce%" ) != - 1 ) :
    iIII11I1I1II ( ii11iO000oo00OOOOO )
    continue
    if 36 - 36: I1IiiI + Oo0Ooo
   lispconfig . lisp_process_command ( oO0oIIII , O00OoOoO ,
 ii11iO000oo00OOOOO , "lisp-itr" , [ I1IiII1I1i1I1 ] )
  elif ( O00OoOoO == "api" ) :
   lisp . lisp_process_api ( "lisp-itr" , oO0oIIII , ii11iO000oo00OOOOO )
  elif ( O00OoOoO == "data-packet" ) :
   O0oOo00o0 ( ii11iO000oo00OOOOO , "ipc" )
  else :
   if ( lisp . lisp_is_rloc_probe_reply ( ii11iO000oo00OOOOO [ 0 ] ) ) :
    lisp . lprint ( "ITR ignoring RLOC-probe request, using pcap" )
    continue
    if 46 - 46: iII111i
   lisp . lisp_parse_packet ( II1iII1i , ii11iO000oo00OOOOO , II11 , O00oooo00o0O )
   if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
   if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
   if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
   if 65 - 65: ooOoO0o - i1IIi
   if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
II1Ii11I111I ( )
lisp . lisp_print_banner ( "ITR normal exit" )
exit ( 0 )
if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
if 34 - 34: I1Ii111 - OOooOOo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
