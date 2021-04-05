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
   if 11 - 11: OoooooooOO . I1Ii111
   if 80 - 80: OoooooooOO - OOooOOo * Ii1I * I1ii11iIi11i / I1IiiI / OOooOOo
   if 13 - 13: I1Ii111 * ooOoO0o + i11iIiiIii * I1Ii111 - ooOoO0o
   if 23 - 23: iIii1I11I1II1 * i1IIi % OoooooooOO * IiII
  if ( lisp . lisp_is_macos ( ) and Oo00OoOo != "en0" ) : continue
  if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
  I1IIIiI1I1ii1 = [ Oo00OoOo , i1I11IiI1iiII , i1iIIi1 ]
  lisp . lprint ( "Capturing packets on {}interface {}" . format ( O0iII1 , Oo00OoOo ) )
  threading . Thread ( target = iiiI1I1iIIIi1 , args = I1IIIiI1I1ii1 ) . start ( )
  if 17 - 17: iIii1I11I1II1 . OoooooooOO / I11i % II111iiii % i1IIi / i11iIiiIii
 if ( ii1iIi1iIiI1i ) : return
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 if 85 - 85: OoOoOO00 + OOooOOo
 if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
 if 27 - 27: Ii1I
 if 67 - 67: I1IiiI
 OO00OO0O0 = "(udp src port 4342 and ip[28] == 0x28)"
 for Oo00OoOo in IIII1i :
  I1IIIiI1I1ii1 = [ Oo00OoOo , OO00OO0O0 , i1iIIi1 ]
  lisp . lprint ( "Capture RLOC-probe replies on RLOC interface {}" . format ( Oo00OoOo ) )
  if 48 - 48: I1Ii111
  threading . Thread ( target = iiiI1I1iIIIi1 , args = I1IIIiI1I1ii1 ) . start ( )
  if 72 - 72: iII111i * oO0o % Ii1I . OoooooooOO
 return
 if 99 - 99: iIii1I11I1II1 % ooOoO0o + ooOoO0o + iII111i - I1Ii111 / I1Ii111
 if 7 - 7: I1IiiI + OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
def i1i1i1I ( ) :
 if 83 - 83: oO0o + OoooooooOO
 if 22 - 22: Ii1I % iII111i * OoooooooOO - o0oOOo0O0Ooo / iIii1I11I1II1
 if 86 - 86: OoooooooOO . iII111i % OoOoOO00 / I11i * iII111i / o0oOOo0O0Ooo
 if 64 - 64: i11iIiiIii
 if ( I11 ) : I11 . cancel ( )
 if 38 - 38: IiII / I1IiiI - IiII . I11i
 if 69 - 69: OoooooooOO + I1ii11iIi11i
 if 97 - 97: OOooOOo - OoO0O00 / Ii1I . i11iIiiIii % oO0o * oO0o
 if 1 - 1: I1IiiI % ooOoO0o
 lisp . lisp_close_socket ( II1iII1i [ 0 ] , "" )
 lisp . lisp_close_socket ( II1iII1i [ 1 ] , "" )
 lisp . lisp_close_socket ( i111I , "" )
 lisp . lisp_close_socket ( II1Ii1iI1i , "" )
 lisp . lisp_close_socket ( oO0oIIII , "lisp-itr" )
 lisp . lisp_close_socket ( Oo0oO0oo0oO00 , "lispers.net-itr" )
 return
 if 65 - 65: I1IiiI + OoOoOO00 / OOooOOo
 if 83 - 83: o0oOOo0O0Ooo . iII111i - Oo0Ooo
 if 65 - 65: iIii1I11I1II1 / ooOoO0o . IiII - II111iiii
 if 72 - 72: iIii1I11I1II1 / IiII % iII111i % OOooOOo - I11i % OOooOOo
 if 100 - 100: Oo0Ooo + i11iIiiIii
 if 71 - 71: I11i / o0oOOo0O0Ooo / I1Ii111 % OOooOOo
 if 51 - 51: IiII * O0 / II111iiii . Ii1I % OOooOOo / I1IiiI
def ii1iii1I1I ( packet , device , input_interface , macs , my_sa ) :
 global II1iII1i
 global iiI1iIiI
 global Ii1IIii11 , Oooo0000
 global oO0oIIII
 if 95 - 95: IiII
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
 if 49 - 49: oO0o . OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 ii1Ii1IiIIi = packet
 packet , o0OO0 , oOo00Oo0o0Oo , I1 = lisp . lisp_is_rloc_probe ( packet , 1 )
 if ( ii1Ii1IiIIi != packet ) :
  if ( o0OO0 == None ) : return
  lisp . lisp_parse_packet ( II1iII1i , packet , o0OO0 , oOo00Oo0o0Oo , I1 )
  return
  if 26 - 26: ooOoO0o . OOooOOo - OOooOOo . OoO0O00
  if 39 - 39: OoooooooOO + oO0o % OOooOOo / OOooOOo
 packet = lisp . lisp_packet ( packet )
 if ( packet . decode ( False , None , None ) == None ) : return
 if 27 - 27: iII111i . I11i . iIii1I11I1II1 . iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo / i1IIi
 if 71 - 71: OoOoOO00 . i1IIi
 if 94 - 94: OOooOOo . I1Ii111
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 if 47 - 47: OoooooooOO
 if ( my_sa ) : input_interface = device
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 if 82 - 82: ooOoO0o + II111iiii
 if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
 oOo000 = packet . inner_source
 OO00Oo = lisp . lisp_get_interface_instance_id ( input_interface , oOo000 )
 packet . inner_dest . instance_id = OO00Oo
 packet . inner_source . instance_id = OO00Oo
 if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
 if 67 - 67: I11i - OOooOOo . i1IIi
 if 35 - 35: iII111i + ooOoO0o - oO0o . iII111i . IiII
 if 87 - 87: OoOoOO00
 if ( macs != "" ) : macs = ", MACs: " + macs + ","
 packet . print_packet ( "Receive {}{}" . format ( device , macs ) , False )
 if 25 - 25: i1IIi . OoO0O00 - OoOoOO00 / OoO0O00 % OoO0O00 * iIii1I11I1II1
 if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
 if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
 if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
 if ( device != input_interface and device != "lispers.net" ) :
  lisp . dprint ( "Not our MAC address on interface {}, pcap interface {}" . format ( input_interface , device ) )
  if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
  return
  if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
  if 93 - 93: Ii1I - OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
 IiI1iII1II111 = lisp . lisp_decent_push_configured
 if ( IiI1iII1II111 ) :
  IIiI11i1111Ii = packet . inner_dest . is_multicast_address ( )
  o00O0O = packet . inner_source . is_local ( )
  IiI1iII1II111 = ( o00O0O and IIiI11i1111Ii )
  if 70 - 70: Oo0Ooo . OoOoOO00
  if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if ( IiI1iII1II111 == False ) :
  if 68 - 68: OoooooooOO % II111iiii
  if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
  if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
  if 2 - 2: Ii1I - IiII
  Oo0ooOo0o = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False )
  if ( Oo0ooOo0o == None ) :
   lisp . dprint ( "Packet received from non-EID source" )
   return
   if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
   if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
   if 71 - 71: OoooooooOO
   if 33 - 33: I1Ii111
   if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
  if ( Oo0ooOo0o . dynamic_eid_configured ( ) ) :
   IIiiii = lisp . lisp_allow_dynamic_eid ( input_interface ,
 packet . inner_source )
   if ( IIiiii ) :
    lisp . lisp_itr_discover_eid ( Oo0ooOo0o , packet . inner_source ,
 input_interface , IIiiii , oO0oIIII )
   else :
    iI111i1I1II = lisp . green ( packet . inner_source . print_address ( ) , False )
    lisp . dprint ( "Disallow dynamic-EID {} on interface {}" . format ( iI111i1I1II ,
 input_interface ) )
    return
    if 96 - 96: I1Ii111 / Oo0Ooo * II111iiii - iII111i * Oo0Ooo
    if 81 - 81: IiII . o0oOOo0O0Ooo / I1Ii111
    if 17 - 17: i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + I11i - ooOoO0o
  if ( packet . inner_source . is_local ( ) and
 packet . udp_dport == lisp . LISP_CTRL_PORT ) : return
  if 78 - 78: I11i * OoOoOO00 . O0 / O0
  if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
  if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
  if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
  if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 OoO = False
 if ( packet . inner_version == 4 ) :
  OoO , packet . packet = lisp . lisp_ipv4_input ( packet . packet )
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
  if 54 - 54: I11i / I1IiiI * oO0o + OoooooooOO - iII111i / OoooooooOO
  if 19 - 19: IiII * ooOoO0o * o0oOOo0O0Ooo + O0 / O0
  if 73 - 73: iIii1I11I1II1 / iIii1I11I1II1 - oO0o
  if 91 - 91: oO0o + I1IiiI
  if 59 - 59: I1IiiI + i11iIiiIii + i1IIi / I11i
  if 44 - 44: I11i . OoOoOO00 * I1IiiI + OoooooooOO - iII111i - IiII
 if ( oo0O000OoO == False ) :
  Oo0ooOo0o = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( Oo0ooOo0o and Oo0ooOo0o . dynamic_eid_configured == False ) :
   lisp . dprint ( ( "Packet destined to local EID-prefix {}, " + "natively forwarding" ) . format ( Oo0ooOo0o . print_eid_tuple ( ) ) )
   if 15 - 15: IiII / O0 . o0oOOo0O0Ooo . i11iIiiIii
   packet . send_packet ( Ii1IIii11 , packet . inner_dest )
   return
   if 59 - 59: I1Ii111 - o0oOOo0O0Ooo - ooOoO0o
   if 48 - 48: i1IIi + I11i % OoOoOO00 / Oo0Ooo - o0oOOo0O0Ooo
   if 67 - 67: oO0o % o0oOOo0O0Ooo . OoooooooOO + OOooOOo * I11i * OoOoOO00
   if 36 - 36: O0 + Oo0Ooo
   if 5 - 5: Oo0Ooo * OoOoOO00
   if 46 - 46: ooOoO0o
 I11iIiII = lisp . lisp_map_cache_lookup ( packet . inner_source , packet . inner_dest )
 if ( I11iIiII ) : I11iIiII . add_recent_source ( packet . inner_source )
 if 66 - 66: Oo0Ooo - o0oOOo0O0Ooo * IiII + OoOoOO00 + o0oOOo0O0Ooo - iIii1I11I1II1
 if 17 - 17: oO0o
 if 22 - 22: I11i + iIii1I11I1II1
 if 24 - 24: OoOoOO00 % i1IIi + iII111i . i11iIiiIii . I1ii11iIi11i
 if 17 - 17: I1ii11iIi11i . II111iiii . ooOoO0o / I1ii11iIi11i
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
 oO00oOo0OOO = Oo0ooOo0o . secondary_iid if ( Oo0ooOo0o != None ) else None
 if ( oO00oOo0OOO and I11iIiII and I11iIiII . action == lisp . LISP_NATIVE_FORWARD_ACTION ) :
  ii1 = packet . inner_dest
  ii1 . instance_id = oO00oOo0OOO
  I11iIiII = lisp . lisp_map_cache_lookup ( packet . inner_source , ii1 )
  if ( I11iIiII ) : I11iIiII . add_recent_source ( packet . inner_source )
  if 51 - 51: O0 . oO0o + i11iIiiIii
  if 79 - 79: OoOoOO00 . oO0o . IiII % Ii1I
  if 65 - 65: i11iIiiIii + i1IIi - Ii1I % Oo0Ooo
  if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
  if 41 - 41: Ii1I % I1ii11iIi11i
 if ( I11iIiII == None or lisp . lisp_mr_or_pubsub ( I11iIiII . action ) ) :
  if ( lisp . lisp_rate_limit_map_request ( packet . inner_dest ) ) : return
  if 12 - 12: OOooOOo
  ooOo0O = ( I11iIiII and I11iIiII . action == lisp . LISP_SEND_PUBSUB_ACTION )
  lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 packet . inner_source , packet . inner_dest , None , ooOo0O )
  if 37 - 37: Ii1I % OoO0O00
  if ( packet . is_trace ( ) ) :
   lisp . lisp_trace_append ( packet , reason = "map-cache miss" )
   if 79 - 79: I1ii11iIi11i + I1IiiI / I1IiiI
  return
  if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
  if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
  if 23 - 23: i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo - I1ii11iIi11i % iII111i * OoO0O00 - OOooOOo / iII111i
  if 29 - 29: I1ii11iIi11i
  if 52 - 52: i11iIiiIii / i1IIi
 if ( I11iIiII and I11iIiII . is_active ( ) and I11iIiII . has_ttl_elapsed ( ) ) :
  if ( lisp . lisp_rate_limit_map_request ( packet . inner_dest ) == False ) :
   lisp . lprint ( "Refresh map-cache entry {}" . format ( lisp . green ( I11iIiII . print_eid_tuple ( ) , False ) ) )
   if 1 - 1: ooOoO0o
   lisp . lisp_send_map_request ( II1iII1i , iiI1iIiI ,
 packet . inner_source , packet . inner_dest , None )
   if 78 - 78: I1ii11iIi11i + I11i - O0
   if 10 - 10: I1Ii111 % I1IiiI
   if 97 - 97: OoooooooOO - I1Ii111
   if 58 - 58: iIii1I11I1II1 + O0
   if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
   if 46 - 46: i11iIiiIii - O0 . oO0o
   if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 I11iIiII . last_refresh_time = time . time ( )
 I11iIiII . stats . increment ( len ( packet . packet ) )
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 OO0OoOOO0 , O00ooOo , oOO0o00O , oOoO , IIII , iI1iiiIiii = I11iIiII . select_rloc ( packet , oO0oIIII )
 if 24 - 24: iIii1I11I1II1 + iIii1I11I1II1 * iII111i
 if 18 - 18: iII111i * I11i - Ii1I
 if ( OO0OoOOO0 == None and IIII == None ) :
  if ( oOoO == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   packet . send_packet ( Ii1IIii11 , packet . inner_dest )
   if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
   if ( packet . is_trace ( ) ) :
    lisp . lisp_trace_append ( packet , reason = "not an EID" )
    if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
   return
   if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
  iii1III1i = "No reachable RLOCs found"
  lisp . dprint ( iii1III1i )
  if ( packet . is_trace ( ) ) : lisp . lisp_trace_append ( packet , reason = iii1III1i )
  return
  if 17 - 17: II111iiii / II111iiii
 if ( OO0OoOOO0 and OO0OoOOO0 . is_null ( ) ) :
  iii1III1i = "Drop action RLOC found"
  lisp . dprint ( iii1III1i )
  if 65 - 65: IiII + Oo0Ooo
  if ( packet . is_trace ( ) ) : lisp . lisp_trace_append ( packet , reason = iii1III1i )
  return
  if 59 - 59: OoooooooOO + I11i . I1Ii111 - O0 % iIii1I11I1II1 / O0
  if 88 - 88: Oo0Ooo . O0 % OoooooooOO / OOooOOo
  if 89 - 89: II111iiii / oO0o
  if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
  if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 packet . outer_tos = packet . inner_tos
 packet . outer_ttl = 32 if ( OoO ) else packet . inner_ttl
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if ( OO0OoOOO0 ) :
  packet . outer_dest . copy_address ( OO0OoOOO0 )
  iI = packet . outer_dest . afi_to_version ( )
  packet . outer_version = iI
  i11ii = lisp . lisp_myrlocs [ 0 ] if ( iI == 4 ) else lisp . lisp_myrlocs [ 1 ]
  if 50 - 50: Ii1I / OoOoOO00 * Ii1I
  packet . outer_source . copy_address ( i11ii )
  if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
  if ( packet . is_trace ( ) ) :
   if ( lisp . lisp_trace_append ( packet , rloc_entry = iI1iiiIiii ) == False ) : return
   if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
   if 32 - 32: i11iIiiIii - I1Ii111
   if 53 - 53: OoooooooOO - IiII
   if 87 - 87: oO0o . I1IiiI
   if 17 - 17: Ii1I . i11iIiiIii
   if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
  if ( packet . encode ( oOO0o00O ) == None ) : return
  if ( len ( packet . packet ) <= 1500 ) : packet . print_packet ( "Send" , True )
  if 63 - 63: oO0o
  if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
  if 36 - 36: IiII
  if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
  o0OooooOoOO = Oooo0000 if iI == 6 else Ii1IIii11
  packet . send_packet ( o0OooooOoOO , packet . outer_dest )
  if 19 - 19: IiII
 elif ( IIII ) :
  if 78 - 78: OOooOOo % o0oOOo0O0Ooo
  if 39 - 39: I1ii11iIi11i + I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo
  if 7 - 7: IiII . OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - II111iiii
  if 37 - 37: I1Ii111 . OoOoOO00 / O0 * iII111i
  if 7 - 7: OoO0O00 * I11i + II111iiii % i11iIiiIii
  i1i1IiIiIi1Ii = IIII . rle_nodes [ 0 ] . level
  oO0ooOO = len ( packet . packet )
  for IIi1iI1 in IIII . rle_forwarding_list :
   if ( IIi1iI1 . level != i1i1IiIiIi1Ii ) : return
   if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
   packet . outer_dest . copy_address ( IIi1iI1 . address )
   if ( IiI1iII1II111 ) : packet . inner_dest . instance_id = 0xffffff
   iI = packet . outer_dest . afi_to_version ( )
   packet . outer_version = iI
   i11ii = lisp . lisp_myrlocs [ 0 ] if ( iI == 4 ) else lisp . lisp_myrlocs [ 1 ]
   if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
   packet . outer_source . copy_address ( i11ii )
   if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
   if ( packet . is_trace ( ) ) :
    if ( lisp . lisp_trace_append ( packet ) == False ) : return
    if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
    if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
   if ( packet . encode ( None ) == None ) : return
   if 87 - 87: oO0o - i11iIiiIii
   if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
   if 23 - 23: I11i
   if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
   packet . print_packet ( "Replicate-to-L{}" . format ( IIi1iI1 . level ) , True )
   packet . send_packet ( Ii1IIii11 , packet . outer_dest )
   if 14 - 14: I1ii11iIi11i
   if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
   if 56 - 56: OoooooooOO - I11i - i1IIi
   if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
   if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
   I11i1iIiiIiIi = len ( packet . packet ) - oO0ooOO
   packet . packet = packet . packet [ I11i1iIiiIiIi : : ]
   if 49 - 49: OOooOOo . I1ii11iIi11i . i11iIiiIii - II111iiii / Ii1I
   if 62 - 62: OOooOOo
   if 1 - 1: IiII / IiII - i11iIiiIii
   if 87 - 87: Oo0Ooo / O0 * IiII / o0oOOo0O0Ooo
   if 19 - 19: I1Ii111 + i1IIi . I1IiiI - Oo0Ooo
   if 16 - 16: oO0o + ooOoO0o / o0oOOo0O0Ooo
 del ( packet )
 return
 if 82 - 82: IiII * i11iIiiIii % II111iiii - OoooooooOO
 if 90 - 90: Oo0Ooo . oO0o * i1IIi - i1IIi
 if 16 - 16: I1IiiI * i1IIi - o0oOOo0O0Ooo . IiII % I11i / o0oOOo0O0Ooo
 if 14 - 14: iIii1I11I1II1 * I1Ii111 * I1ii11iIi11i / iIii1I11I1II1 * IiII / I11i
 if 77 - 77: OoO0O00 + I1Ii111 + I1Ii111 * Ii1I / OoooooooOO . Ii1I
 if 62 - 62: i1IIi - i1IIi
 if 69 - 69: OoOoOO00 % oO0o - I11i
def Iiii1ii ( device , not_used , packet ) :
 I1i111IiIiIi1 = 4 if device == "lo0" else 0 if device == "lispers.net" else 14
 if 39 - 39: I11i - I1ii11iIi11i
 if ( lisp . lisp_frame_logging ) :
  OOO0o0OO0OO = lisp . bold ( "Received frame on interface '{}'" . format ( device ) ,
 False )
  oOo0O = lisp . lisp_format_packet ( packet [ 0 : 64 ] )
  lisp . lprint ( "{}: {}" . format ( OOO0o0OO0OO , oOo0O ) )
  if 43 - 43: o0oOOo0O0Ooo . iII111i . I11i + iIii1I11I1II1
  if 78 - 78: iIii1I11I1II1 % OoOoOO00 + I1ii11iIi11i / i1IIi % II111iiii + OOooOOo
  if 91 - 91: iIii1I11I1II1 % OoO0O00 . o0oOOo0O0Ooo + Ii1I + o0oOOo0O0Ooo
  if 95 - 95: Ii1I + I1ii11iIi11i * OOooOOo
  if 16 - 16: I11i / I1IiiI + OoO0O00 % iIii1I11I1II1 - i1IIi . oO0o
 iIi1iIIIiIiI = ""
 OooOo000o0o = False
 OOo0oO00ooO00 = device
 if ( I1i111IiIiIi1 == 14 ) :
  iIiIIi1 , iI1I1iII1i , iiIIii , OooOo000o0o = lisp . lisp_get_input_interface ( packet )
  OOo0oO00ooO00 = device if ( device in iIiIIi1 ) else iIiIIi1 [ 0 ]
  iIi1iIIIiIiI = lisp . lisp_format_macs ( iI1I1iII1i , iiIIii )
  if ( OOo0oO00ooO00 . find ( "vlan" ) != - 1 ) : I1i111IiIiIi1 += 4
  if 70 - 70: o0oOOo0O0Ooo - OOooOOo
  if 62 - 62: I11i
  if 63 - 63: OOooOOo + ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
  if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
  if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
  if 64 - 64: i1IIi
  if ( int ( iiIIii [ 1 ] , 16 ) & 1 ) : OooOo000o0o = True
  if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
  if 18 - 18: OOooOOo + I1Ii111
  if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
  if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
  if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if ( I1i111IiIiIi1 != 0 ) :
  i1iii11 = struct . unpack ( "H" , packet [ I1i111IiIiIi1 - 2 : I1i111IiIiIi1 ] ) [ 0 ]
  i1iii11 = socket . ntohs ( i1iii11 )
  if ( i1iii11 == 0x8100 ) :
   oO = struct . unpack ( "I" , packet [ I1i111IiIiIi1 : I1i111IiIiIi1 + 4 ] ) [ 0 ]
   oO = socket . ntohl ( oO )
   OOo0oO00ooO00 = "vlan" + str ( oO >> 16 )
   I1i111IiIiIi1 += 4
  elif ( i1iii11 == 0x806 ) :
   lisp . dprint ( "Dropping ARP packets, host should have default route" )
   return
   if 51 - 51: I11i * o0oOOo0O0Ooo
   if 78 - 78: IiII
   if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if ( lisp . lisp_l2_overlay ) : I1i111IiIiIi1 = 0
 if 47 - 47: o0oOOo0O0Ooo
 ii1iii1I1I ( packet [ I1i111IiIiIi1 : : ] , device , OOo0oO00ooO00 , iIi1iIIIiIiI , OooOo000o0o )
 return
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
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
def OO0oOOoo ( sources , dyn_eids ) :
 if ( os . getenv ( "LISP_NO_IPTABLES" ) != None ) :
  lisp . lprint ( "User selected to suppress installing iptables rules" )
  return
  if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
  if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 os . system ( "sudo iptables -t raw -N lisp" )
 os . system ( "sudo iptables -t raw -A PREROUTING -j lisp" )
 os . system ( "sudo ip6tables -t raw -N lisp" )
 os . system ( "sudo ip6tables -t raw -A PREROUTING -j lisp" )
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
 if 93 - 93: I1Ii111 + Ii1I
 if 33 - 33: O0
 if 78 - 78: O0 / II111iiii * OoO0O00
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
 if 58 - 58: IiII + iIii1I11I1II1
 Oo00OO0OO = "sudo ip{}tables -t raw -A lisp -j ACCEPT -d {}"
 OOo00OO0O0O = [ "127.0.0.1" , "::1" , "224.0.0.0/4 -p igmp" , "ff00::/8" ,
 "fe80::/16" ]
 OOo00OO0O0O += sources + lisp . lisp_get_all_addresses ( )
 for OO0 in OOo00OO0O0O :
  if ( lisp . lisp_is_mac_string ( OO0 ) ) : continue
  iIiiIi11IIi = "" if OO0 . find ( ":" ) == - 1 else "6"
  os . system ( Oo00OO0OO . format ( iIiiIi11IIi , OO0 ) )
  if 64 - 64: OoooooooOO . I1ii11iIi11i % O0 + I1IiiI - o0oOOo0O0Ooo
  if 84 - 84: i11iIiiIii * Ii1I . i11iIiiIii
  if 12 - 12: OoOoOO00 % IiII % I1ii11iIi11i . i11iIiiIii * iIii1I11I1II1
  if 66 - 66: i11iIiiIii * iIii1I11I1II1 % OoooooooOO
  if 5 - 5: OoOoOO00 % OoooooooOO
  if 60 - 60: OoOoOO00 . i1IIi % OoO0O00 % ooOoO0o % OOooOOo
  if 33 - 33: iIii1I11I1II1 - Ii1I * I1ii11iIi11i % iIii1I11I1II1 + OoO0O00 . OOooOOo
  if 56 - 56: i11iIiiIii * iII111i . oO0o
 if ( lisp . lisp_pitr == False ) :
  Oo00OO0OO = "sudo ip{}tables -t raw -A lisp -j ACCEPT -s {} -d {}"
  ooooO0O = "sudo ip{}tables -t raw -C lisp -j ACCEPT -s {} -d {}"
  for o0OO0 in sources :
   if ( lisp . lisp_is_mac_string ( o0OO0 ) ) : continue
   if ( o0OO0 in dyn_eids ) : continue
   iIiiIi11IIi = "" if o0OO0 . find ( ":" ) == - 1 else "6"
   for O0OOO0OOoO0O in sources :
    if ( lisp . lisp_is_mac_string ( O0OOO0OOoO0O ) ) : continue
    if ( O0OOO0OOoO0O in dyn_eids ) : continue
    if ( O0OOO0OOoO0O . find ( "." ) != - 1 and o0OO0 . find ( "." ) == - 1 ) : continue
    if ( O0OOO0OOoO0O . find ( ":" ) != - 1 and o0OO0 . find ( ":" ) == - 1 ) : continue
    if ( commands . getoutput ( ooooO0O . format ( iIiiIi11IIi , o0OO0 , O0OOO0OOoO0O ) ) == "" ) :
     continue
     if 81 - 81: i1IIi % o0oOOo0O0Ooo - I1Ii111 + i11iIiiIii - OoooooooOO
    os . system ( Oo00OO0OO . format ( iIiiIi11IIi , o0OO0 , O0OOO0OOoO0O ) )
    if 50 - 50: Ii1I - i11iIiiIii + iIii1I11I1II1 / O0 - Ii1I + o0oOOo0O0Ooo
    if 22 - 22: II111iiii - Ii1I / ooOoO0o % OoooooooOO + OOooOOo
    if 5 - 5: OoO0O00 / iII111i + i11iIiiIii % I11i
    if 93 - 93: OoOoOO00 % iIii1I11I1II1
    if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
    if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
    if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 iii1IiI1I1 = "sudo ip{}tables -t raw -A lisp -j DROP -s {}"
 for o0OO0 in sources :
  if ( lisp . lisp_is_mac_string ( o0OO0 ) ) : continue
  iIiiIi11IIi = "" if o0OO0 . find ( ":" ) == - 1 else "6"
  os . system ( iii1IiI1I1 . format ( iIiiIi11IIi , o0OO0 ) )
  if 64 - 64: ooOoO0o / O0 * OoOoOO00 * ooOoO0o
  if 60 - 60: I11i / i1IIi % I1ii11iIi11i / I1ii11iIi11i * I1ii11iIi11i . i11iIiiIii
  if 99 - 99: OoOoOO00
  if 77 - 77: o0oOOo0O0Ooo
  if 48 - 48: OoOoOO00 % I1ii11iIi11i / I11i . iIii1I11I1II1 * II111iiii
 oo000oO = commands . getoutput ( "sudo iptables -t raw -S lisp" ) . split ( "\n" )
 oo000oO += commands . getoutput ( "sudo ip6tables -t raw -S lisp" ) . split ( "\n" )
 lisp . lprint ( "Using kernel filters: {}" . format ( oo000oO ) )
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 if 24 - 24: OoOoOO00
 if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 if 28 - 28: I1IiiI
 if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if ( os . getenv ( "LISP_VIRTIO_BUG" ) != None ) :
  oO00o = ( "sudo iptables -A POSTROUTING -t mangle -p tcp -j " + "CHECKSUM --checksum-fill; " )
  if 36 - 36: I1Ii111 . II111iiii % ooOoO0o
  oO00o += ( "sudo iptables -A POSTROUTING -t mangle -p udp -j " + "CHECKSUM --checksum-fill; " )
  if 84 - 84: OoooooooOO - i11iIiiIii / iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i
  oO00o += ( "sudo ip6tables -A POSTROUTING -t mangle -p tcp -j " + "CHECKSUM --checksum-fill; " )
  if 4 - 4: Oo0Ooo + o0oOOo0O0Ooo
  oO00o += ( "sudo ip6tables -A POSTROUTING -t mangle -p udp -j " + "CHECKSUM --checksum-fill" )
  if 17 - 17: OoO0O00 * OoOoOO00
  os . system ( oO00o )
  ii11i = lisp . bold ( "virtio" , False )
  lisp . lprint ( "{} bug workaround, configure '{}'" . format ( ii11i , oO00o ) )
  if 71 - 71: I1Ii111 / I1ii11iIi11i * iIii1I11I1II1
 return
 if 57 - 57: OOooOOo + I1Ii111 % I1ii11iIi11i . OoO0O00 / OoO0O00 * O0
 if 6 - 6: i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 if 68 - 68: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 - I1Ii111
 if 37 - 37: IiII
 if 37 - 37: Oo0Ooo / IiII * O0
 if 73 - 73: iII111i * iII111i / ooOoO0o
def o00oOo0oOoo ( sources , dyn_eids , l2_overlay , pitr ) :
 if ( l2_overlay ) :
  i1I11IiI1iiII = "ether[6:4] >= 0 and ether[10:2] >= 0"
  lisp . lprint ( "Using pcap filter: '{}'" . format ( i1I11IiI1iiII ) )
  return ( i1I11IiI1iiII )
  if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
  if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 Iiii11I = "(not ether proto 0x806)"
 OO00OO0O0 = " or (udp src port 4342 and ip[28] == 0x28)"
 OO0ooo0 = " or (ip[16] >= 224 and ip[16] < 240 and (ip[28] & 0xf0) == 0x30)"
 if 7 - 7: I1ii11iIi11i - oO0o * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i
 if 85 - 85: O0
 Iii = ""
 IiI1I1 = ""
 for o0OO0 in sources :
  iI111i11iI1 = o0OO0
  if ( lisp . lisp_is_mac_string ( o0OO0 ) ) :
   iI111i11iI1 = o0OO0 . split ( "/" ) [ 0 ]
   iI111i11iI1 = iI111i11iI1 . replace ( "-" , "" )
   III1ii = [ ]
   for IIiiii in range ( 0 , 12 , 2 ) : III1ii . append ( iI111i11iI1 [ IIiiii : IIiiii + 2 ] )
   iI111i11iI1 = "ether host " + ":" . join ( III1ii )
   if 23 - 23: oO0o * iII111i
   if 53 - 53: Ii1I - OoOoOO00 . iII111i . I1Ii111
  Iii += "{}" . format ( iI111i11iI1 )
  if ( o0OO0 not in dyn_eids ) : IiI1I1 += "{}" . format ( iI111i11iI1 )
  if ( sources [ - 1 ] == o0OO0 ) : break
  Iii += " or "
  if ( o0OO0 not in dyn_eids ) : IiI1I1 += " or "
  if 48 - 48: iII111i + IiII
 if ( IiI1I1 [ - 4 : : ] == " or " ) : IiI1I1 = IiI1I1 [ 0 : - 4 ]
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 if 14 - 14: OOooOOo
 if 79 - 79: Ii1I
 if 76 - 76: iIii1I11I1II1
 if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
 if 93 - 93: OoooooooOO * Oo0Ooo
 I1IiI1iIiIiii = commands . getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 I1IiI1iIiIiii = ( I1IiI1iIiIiii != "" and I1IiI1iIiIiii [ 0 ] == " " )
 I1iiI1II = lisp . lisp_get_loopback_address ( ) if ( I1IiI1iIiIiii ) else None
 if 44 - 44: Oo0Ooo / i1IIi + iIii1I11I1II1 / iIii1I11I1II1 * iIii1I11I1II1 . Ii1I
 Oo = ""
 ii1IIi1ii = lisp . lisp_get_all_addresses ( )
 for OO0 in ii1IIi1ii :
  if ( OO0 == I1iiI1II ) : continue
  Oo += "{}" . format ( OO0 )
  if ( ii1IIi1ii [ - 1 ] == OO0 ) : break
  Oo += " or "
  if 85 - 85: OoooooooOO % OoOoOO00 * iIii1I11I1II1
  if 44 - 44: iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if ( Iii != "" ) :
  Iii = " and (src net {})" . format ( Iii )
  if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if ( IiI1I1 != "" ) :
  IiI1I1 = " and not (dst net {})" . format ( IiI1I1 )
  if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if ( Oo != "" ) :
  Oo = " and not (dst host {})" . format ( Oo )
  if 77 - 77: II111iiii
  if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
  if 68 - 68: oO0o
  if 10 - 10: Ii1I
  if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
  if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
  if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if ( pitr ) :
  IiI1I1 = ""
  Oo = Oo . replace ( "dst " , "" )
  if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
  if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
  if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
  if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
  if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 i1I11IiI1iiII = Iiii11I + Iii + IiI1I1 + Oo
 i1I11IiI1iiII += OO00OO0O0
 i1I11IiI1iiII += OO0ooo0
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 lisp . lprint ( "Using pcap filter: '{}'" . format ( i1I11IiI1iiII ) )
 return ( i1I11IiI1iiII )
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
def iiiI1I1iIIIi1 ( device , pfilter , pcap_lock ) :
 lisp . lisp_set_exception ( )
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 pcap_lock . acquire ( )
 O00O = pcappy . open_live ( device , 9000 , 0 , 100 )
 pcap_lock . release ( )
 if 2 - 2: oO0o . I1Ii111 * Oo0Ooo + O0 - I11i * iIii1I11I1II1
 O00O . filter = pfilter
 O00O . loop ( - 1 , Iiii1ii , device )
 return
 if 12 - 12: o0oOOo0O0Ooo * I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
 if 81 - 81: Oo0Ooo - I11i
 if 24 - 24: OoooooooOO . OoO0O00 * II111iiii
 if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
 if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
 if 79 - 79: I1IiiI - ooOoO0o
 if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 if 83 - 83: IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
def OOOO00OooO ( ) :
 global I11
 global II1Ii1iI1i
 global II1iII1i
 if 64 - 64: OoO0O00 . I1IiiI - OoooooooOO . ooOoO0o - iII111i
 lisp . lisp_set_exception ( )
 if 77 - 77: Ii1I % OoOoOO00 / II111iiii % iII111i % OoooooooOO % OoO0O00
 if 19 - 19: IiII * I1Ii111 / oO0o * I1Ii111 - OoooooooOO * I11i
 if 17 - 17: II111iiii + Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 ooooO0 = [ II1Ii1iI1i , II1Ii1iI1i ,
 oO0oIIII ]
 lisp . lisp_build_info_requests ( ooooO0 , None , lisp . LISP_CTRL_PORT )
 if 37 - 37: i11iIiiIii + I1IiiI . OOooOOo % I11i % I11i
 if 26 - 26: O0
 if 34 - 34: ooOoO0o * I1Ii111
 if 97 - 97: i11iIiiIii % oO0o / Oo0Ooo / Oo0Ooo
 I11 . cancel ( )
 I11 = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 OOOO00OooO , [ ] )
 I11 . start ( )
 return
 if 97 - 97: II111iiii - I1Ii111 - iIii1I11I1II1 * I1IiiI
 if 54 - 54: iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
def ii1II1II ( kv_pair ) :
 global II1iII1i
 global iiI1iIiI
 global I11
 if 42 - 42: Ii1I
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 68 - 68: OOooOOo . Oo0Ooo % ooOoO0o - OoooooooOO * iII111i . OOooOOo
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ II1iII1i , iiI1iIiI ] )
  lisp . lisp_test_mr_timer . start ( )
  if 46 - 46: i11iIiiIii - OOooOOo * I1IiiI * I11i % I1ii11iIi11i * i1IIi
  if 5 - 5: O0 / ooOoO0o . Oo0Ooo + OoooooooOO
  if 97 - 97: IiII . Ii1I . Ii1I / iIii1I11I1II1 - OoO0O00 + iII111i
  if 32 - 32: OOooOOo . o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
  if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
 I11 = threading . Timer ( 0 , OOOO00OooO , [ ] )
 I11 . start ( )
 return
 if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
 if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
 if 26 - 26: o0oOOo0O0Ooo
 if 12 - 12: OoooooooOO / O0 + II111iiii * I1ii11iIi11i
 if 46 - 46: II111iiii - IiII * OoooooooOO / oO0o % IiII
 if 11 - 11: iIii1I11I1II1 . OoOoOO00 / IiII % ooOoO0o
 if 61 - 61: ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
def IiIIII1iiIIi ( kv_pair ) :
 lispconfig . lisp_database_mapping_command ( kv_pair )
 return
 if 17 - 17: I11i
 if 97 - 97: I1ii11iIi11i * I1ii11iIi11i / iII111i
 if 6 - 6: oO0o
 if 72 - 72: I11i * I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
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
 OoOooOO0oOOo0O = lisp . lisp_nat_traversal
 I1II = lisp . lisp_rloc_probing
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 lispconfig . lisp_xtr_command ( kv_pair )
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 OooOOOoOoo0O0 = ( OoOooOO0oOOo0O == False and lisp . lisp_nat_traversal and lisp . lisp_rloc_probing )
 if 81 - 81: IiII - o0oOOo0O0Ooo - Oo0Ooo - Ii1I / OOooOOo % I11i
 oO0Oo = ( I1II == False and lisp . lisp_rloc_probing )
 if 72 - 72: O0 . OoOoOO00 * Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 iII1I11 = 0
 if ( oO0Oo ) : iII1I11 = 1
 if ( OooOOOoOoo0O0 ) : iII1I11 = 5
 if 15 - 15: I11i
 if ( iII1I11 != 0 ) :
  IiiI11I1IIiI = [ i111I , i111I ]
  lisp . lisp_start_rloc_probe_timer ( iII1I11 , IiiI11I1IIiI )
  if 5 - 5: Oo0Ooo
  if 100 - 100: Ii1I + iIii1I11I1II1
  if 59 - 59: IiII
  if 89 - 89: OoOoOO00 % iIii1I11I1II1
  if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
  if 45 - 45: I1IiiI * OOooOOo % OoO0O00
  if 24 - 24: ooOoO0o - I11i * oO0o
 if ( lisp . lisp_crypto_ephem_port == None and lisp . lisp_data_plane_security ) :
  oOo00Oo0o0Oo = i111I . getsockname ( ) [ 1 ]
  lisp . lisp_crypto_ephem_port = oOo00Oo0o0Oo
  lisp . lprint ( "Use port {} for lisp-crypto packets" . format ( oOo00Oo0o0Oo ) )
  O00OoOoO = { "type" : "itr-crypto-port" , "port" : oOo00Oo0o0Oo }
  lisp . lisp_write_to_dp_socket ( O00OoOoO )
  if 58 - 58: I1ii11iIi11i
  if 19 - 19: iIii1I11I1II1 * OoooooooOO * i11iIiiIii
  if 79 - 79: IiII % OoO0O00
  if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
  if 32 - 32: O0 . OoooooooOO
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
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
 ii1IiI11I , OO0Ooo000O0 , o00o , oOO0o00O = ipc . split ( "%" )
 oOO0o00O = int ( oOO0o00O , 16 )
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 i11iioOOOOO0Ooooo = lisp . lisp_get_echo_nonce ( None , o00o )
 if ( i11iioOOOOO0Ooooo == None ) : i11iioOOOOO0Ooooo = lisp . lisp_echo_nonce ( o00o )
 if 57 - 57: Ii1I - OoooooooOO
 if 68 - 68: o0oOOo0O0Ooo % I1ii11iIi11i / I1Ii111 + I1Ii111 - I1Ii111 . OoO0O00
 if 100 - 100: OoOoOO00 % Oo0Ooo
 if 76 - 76: II111iiii / OoO0O00 + OoooooooOO . I1ii11iIi11i . I11i . ooOoO0o
 if 43 - 43: i1IIi
 if ( OO0Ooo000O0 == "R" ) :
  i11iioOOOOO0Ooooo . request_nonce_rcvd = oOO0o00O
  i11iioOOOOO0Ooooo . last_request_nonce_rcvd = lisp . lisp_get_timestamp ( )
  i11iioOOOOO0Ooooo . echo_nonce_sent = oOO0o00O
  i11iioOOOOO0Ooooo . last_new_echo_nonce_sent = lisp . lisp_get_timestamp ( )
  lisp . lprint ( "Start echo-nonce mode for {}, nonce 0x{}" . format ( lisp . red ( i11iioOOOOO0Ooooo . rloc_str , False ) , lisp . lisp_hex_string ( oOO0o00O ) ) )
  if 17 - 17: O0 - OoOoOO00
  if 81 - 81: I1IiiI - iIii1I11I1II1 / I1IiiI / O0
  if 34 - 34: Ii1I * Ii1I - I1ii11iIi11i - O0 . i11iIiiIii
 if ( OO0Ooo000O0 == "E" ) :
  i11iioOOOOO0Ooooo . echo_nonce_rcvd = oOO0o00O
  i11iioOOOOO0Ooooo . last_echo_nonce_rcvd = lisp . lisp_get_timestamp ( )
  if 32 - 32: iIii1I11I1II1 . OoO0O00 * oO0o / OOooOOo . II111iiii - Oo0Ooo
  if ( i11iioOOOOO0Ooooo . request_nonce_sent == oOO0o00O ) :
   IIIi = lisp . bold ( "echoed nonce" , False )
   lisp . lprint ( "Received {} {} from {}" . format ( IIIi ,
 lisp . lisp_hex_string ( oOO0o00O ) ,
 lisp . red ( i11iioOOOOO0Ooooo . rloc_str , False ) ) )
   if 39 - 39: oO0o * I1Ii111 + OoOoOO00 % OoooooooOO / iIii1I11I1II1
   i11iioOOOOO0Ooooo . request_nonce_sent = None
   lisp . lprint ( "Stop request-nonce mode for {}" . format ( lisp . red ( i11iioOOOOO0Ooooo . rloc_str , False ) ) )
   if 60 - 60: Ii1I
   i11iioOOOOO0Ooooo . last_good_echo_nonce_rcvd = lisp . lisp_get_timestamp ( )
  else :
   IiI1Ii1ii = "none"
   if ( i11iioOOOOO0Ooooo . request_nonce_sent ) :
    IiI1Ii1ii = lisp . lisp_hex_string ( i11iioOOOOO0Ooooo . request_nonce_sent )
    if 44 - 44: I1IiiI % Ii1I * I1IiiI . Oo0Ooo + I1ii11iIi11i . OOooOOo
   lisp . lprint ( ( "Received echo-nonce 0x{} from {}, but request-" + "nonce is {}" ) . format ( lisp . lisp_hex_string ( oOO0o00O ) ,
   # o0oOOo0O0Ooo
 lisp . red ( i11iioOOOOO0Ooooo . rloc_str , False ) , IiI1Ii1ii ) )
   if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
   if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 return
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
 if 12 - 12: I1ii11iIi11i / Ii1I
 if 5 - 5: OoooooooOO
 if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
 if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
OOOO = {
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

 "lisp map-resolver" : [ ii1II1II , {
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

 "lisp database-mapping" : [ IiIIII1iiIIi , {
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
if 98 - 98: oO0o . OoooooooOO
if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
if 33 - 33: I11i % II111iiii + OoO0O00
if 93 - 93: i1IIi . IiII / I1IiiI + IiII
if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
if ( I111I1Iiii1i ( ) == False ) :
 lisp . lprint ( "lisp_itr_startup() failed" )
 lisp . lisp_print_banner ( "ITR abnormal exit" )
 exit ( 1 )
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
o00000oo00 = [ i111I , oO0oIIII ,
 II1Ii1iI1i , Oo0oO0oo0oO00 ]
if 41 - 41: OOooOOo - o0oOOo0O0Ooo + Ii1I
if 15 - 15: I11i / o0oOOo0O0Ooo + Ii1I
if 76 - 76: Ii1I + OoooooooOO / OOooOOo % OoO0O00 / I1ii11iIi11i
if 38 - 38: I1Ii111 . iII111i . I1IiiI * OoO0O00
oOoo00o0oOO = True
OoOOooOO0ooOo = [ i111I ] * 3
oo0o = [ II1Ii1iI1i ] * 3
if 24 - 24: O0 . OoooooooOO - OoO0O00 * OoooooooOO
while ( True ) :
 try : Ii11iiI , o0OO0oooo , ii1IiI11I = select . select ( o00000oo00 , [ ] , [ ] )
 except : break
 if 40 - 40: I1Ii111 - OoOoOO00 * I11i - IiII / OoOoOO00
 if 71 - 71: oO0o / OoooooooOO % IiII / OoOoOO00 % I1Ii111
 if 19 - 19: I1Ii111 + IiII / oO0o / II111iiii
 if 92 - 92: i1IIi % ooOoO0o + ooOoO0o - iIii1I11I1II1 . Ii1I
 if ( lisp . lisp_ipc_data_plane and Oo0oO0oo0oO00 in Ii11iiI ) :
  lisp . lisp_process_punt ( Oo0oO0oo0oO00 , II1iII1i ,
 iiI1iIiI )
  if 33 - 33: o0oOOo0O0Ooo / O0 + OOooOOo
  if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
  if 92 - 92: OoOoOO00 % O0
  if 55 - 55: iIii1I11I1II1 * iII111i
  if 85 - 85: iIii1I11I1II1 . II111iiii
 if ( i111I in Ii11iiI ) :
  OO0Ooo000O0 , o0OO0 , oOo00Oo0o0Oo , o0 = lisp . lisp_receive ( OoOOooOO0ooOo [ 0 ] ,
 False )
  if ( o0OO0 == "" ) : break
  if 68 - 68: Oo0Ooo
  if ( lisp . lisp_is_rloc_probe_reply ( o0 [ 0 ] ) ) :
   lisp . lprint ( "ITR ignoring RLOC-probe reply, using pcap" )
   continue
   if 22 - 22: OOooOOo
  lisp . lisp_parse_packet ( OoOOooOO0ooOo , o0 , o0OO0 , oOo00Oo0o0Oo )
  if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
  if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
  if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
  if 94 - 94: i1IIi
  if 36 - 36: I1IiiI + Oo0Ooo
 if ( II1Ii1iI1i in Ii11iiI ) :
  OO0Ooo000O0 , o0OO0 , oOo00Oo0o0Oo , o0 = lisp . lisp_receive ( oo0o [ 0 ] ,
 False )
  if ( o0OO0 == "" ) : break
  if 46 - 46: iII111i
  if ( lisp . lisp_is_rloc_probe_reply ( o0 [ 0 ] ) ) :
   lisp . lprint ( "ITR ignoring RLOC-probe reply, using pcap" )
   continue
   if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
  I1i1I11111iI1 = lisp . lisp_parse_packet ( oo0o , o0 , o0OO0 , oOo00Oo0o0Oo )
  if 32 - 32: I1IiiI + I1ii11iIi11i - oO0o + I1ii11iIi11i / i1IIi * oO0o
  if 90 - 90: Ii1I % oO0o
  if 6 - 6: OoooooooOO / i11iIiiIii / I1Ii111
  if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  if 34 - 34: I1Ii111 - OOooOOo
  if ( I1i1I11111iI1 ) :
   IiiI11I1IIiI = [ i111I , i111I ]
   lisp . lisp_start_rloc_probe_timer ( 0 , IiiI11I1IIiI )
   if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
   if 64 - 64: i1IIi
   if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
   if 25 - 25: II111iiii / OoO0O00
   if 64 - 64: O0 % ooOoO0o
   if 40 - 40: o0oOOo0O0Ooo + I11i
   if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
 if ( oO0oIIII in Ii11iiI ) :
  OO0Ooo000O0 , o0OO0 , oOo00Oo0o0Oo , o0 = lisp . lisp_receive ( oO0oIIII , True )
  if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
  if ( o0OO0 == "" ) : break
  if 47 - 47: OoooooooOO
  if ( OO0Ooo000O0 == "command" ) :
   if ( o0 == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
   if ( o0 . find ( "nonce%" ) != - 1 ) :
    Ii1Ii1 ( o0 )
    continue
    if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
   lispconfig . lisp_process_command ( oO0oIIII , OO0Ooo000O0 ,
 o0 , "lisp-itr" , [ OOOO ] )
  elif ( OO0Ooo000O0 == "api" ) :
   lisp . lisp_process_api ( "lisp-itr" , oO0oIIII , o0 )
  elif ( OO0Ooo000O0 == "data-packet" ) :
   ii1iii1I1I ( o0 , "ipc" )
  else :
   if ( lisp . lisp_is_rloc_probe_reply ( o0 [ 0 ] ) ) :
    lisp . lprint ( "ITR ignoring RLOC-probe request, using pcap" )
    continue
    if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
   lisp . lisp_parse_packet ( II1iII1i , o0 , o0OO0 , oOo00Oo0o0Oo )
   if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
   if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
   if 26 - 26: OOooOOo * Oo0Ooo
   if 31 - 31: I11i * oO0o . Ii1I
   if 35 - 35: I11i
i1i1i1I ( )
lisp . lisp_print_banner ( "ITR normal exit" )
exit ( 0 )
if 94 - 94: ooOoO0o / i11iIiiIii % O0
if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
