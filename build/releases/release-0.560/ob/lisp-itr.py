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
try :
 from commands import getoutput
except :
 from subprocess import getoutput
 if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
import struct
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
Oo0o = [ None , None , None ]
OOO0o0o = None
Ii1iI = None
Oo = None
I1Ii11I1Ii1i = None
Ooo = lisp . lisp_get_ephemeral_port ( )
o0oOoO00o = lisp . lisp_get_ephemeral_port ( )
i1 = None
oOOoo00O0O = None
i1111 = None
i11 = None
if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
if 74 - 74: iII111i * IiII
if 82 - 82: iIii1I11I1II1 % IiII
if 86 - 86: OoOoOO00 % I1IiiI
if 80 - 80: OoooooooOO . I1IiiI
if 87 - 87: oO0o / ooOoO0o + I1Ii111 - ooOoO0o . ooOoO0o / II111iiii
iiIIIIi1i1 = False
if 54 - 54: OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
if 13 - 13: OOooOOo * oO0o * I1IiiI
if 55 - 55: II111iiii
IIIiI11ii = threading . Lock ( )
if 52 - 52: iII111i + OOooOOo % OoooooooOO / i11iIiiIii
if 25 - 25: O0 * oO0o + OoooooooOO
if 70 - 70: OOooOOo / Ii1I . Ii1I
if 11 - 11: ooOoO0o / O0 - i1IIi
if 85 - 85: OOooOOo % I1ii11iIi11i * ooOoO0o
if 90 - 90: o0oOOo0O0Ooo % o0oOOo0O0Ooo % I11i * OoOoOO00
if 26 - 26: Ii1I - o0oOOo0O0Ooo
if 63 - 63: II111iiii . II111iiii
def Ii1 ( parameter ) :
 return ( lispconfig . lisp_itr_rtr_show_command ( parameter , "ITR" , [ ] ) )
 if 71 - 71: OoO0O00
 if 55 - 55: OoO0O00 / I1ii11iIi11i * OOooOOo
 if 86 - 86: i11iIiiIii + Ii1I + ooOoO0o * I11i + o0oOOo0O0Ooo
 if 61 - 61: OoO0O00 / i11iIiiIii
 if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - I1ii11iIi11i + i11iIiiIii
 if 65 - 65: OoOoOO00
 if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
def oo ( parameter ) :
 return ( lispconfig . lisp_show_crypto_list ( "ITR" ) )
 if 54 - 54: OOooOOo + OOooOOo % I1Ii111 % i11iIiiIii / iIii1I11I1II1 . OOooOOo
 if 57 - 57: Ii1I % OoooooooOO
 if 61 - 61: iII111i . iIii1I11I1II1 * I1IiiI . ooOoO0o % Oo0Ooo
 if 72 - 72: OOooOOo
 if 63 - 63: Ii1I
 if 86 - 86: ooOoO0o . I1IiiI % Oo0Ooo + o0oOOo0O0Ooo
 if 35 - 35: iIii1I11I1II1 % oO0o * I11i % I11i + II111iiii * iII111i
 if 54 - 54: I11i + IiII / iII111i
def IIII ( parameter ) :
 return ( lispconfig . lisp_itr_rtr_show_rloc_probe_command ( "ITR" ) )
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
 if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
 if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo
 if 77 - 77: OoOoOO00 / I11i
 if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
 if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 if 95 - 95: OoO0O00 % oO0o . O0
 if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
 if 53 - 53: IiII + I1IiiI * oO0o
def OooOooooOOoo0 ( lisp_sockets , lisp_ephem_port ) :
 lisp . lisp_set_exception ( )
 if 71 - 71: I1Ii111 % oO0o % OOooOOo
 if 94 - 94: oO0o - iII111i * O0
 if 17 - 17: I1ii11iIi11i % II111iiii
 if 13 - 13: I1Ii111 % OoOoOO00 - i11iIiiIii . I1IiiI + II111iiii
 for II111ii1II1i in lisp . lisp_crypto_keys_by_nonce . values ( ) :
  for OoOo00o in II111ii1II1i : del ( OoOo00o )
  if 70 - 70: iII111i * I1ii11iIi11i
 lisp . lisp_crypto_keys_by_nonce = { }
 if 46 - 46: ooOoO0o / OoO0O00
 if 52 - 52: o0oOOo0O0Ooo - OoooooooOO + Ii1I + Ii1I - o0oOOo0O0Ooo / I1Ii111
 if 44 - 44: ooOoO0o . i1IIi - I1ii11iIi11i . O0 - ooOoO0o
 if 92 - 92: iII111i . I11i + o0oOOo0O0Ooo
 if 28 - 28: i1IIi * Oo0Ooo - o0oOOo0O0Ooo * IiII * Ii1I / OoO0O00
 if ( lisp . lisp_l2_overlay ) :
  OooO0OoOOOO = lisp . LISP_AFI_MAC
  i1Ii = lisp . lisp_default_iid
  o00OO00OoO = lisp . lisp_address ( OooO0OoOOOO , "0000-0000-0000" , 0 , i1Ii )
  o00OO00OoO . mask_len = 0
  OOOO0OOoO0O0 = lisp . lisp_address ( OooO0OoOOOO , "ffff-ffff-ffff" , 48 , i1Ii )
  lisp . lisp_send_map_request ( lisp_sockets , lisp_ephem_port , o00OO00OoO , OOOO0OOoO0O0 , None )
  if 65 - 65: IiII * I1IiiI + Ii1I % i11iIiiIii * oO0o . I1Ii111
  if 100 - 100: O0 + IiII - OOooOOo + i11iIiiIii * Ii1I
  if 30 - 30: o0oOOo0O0Ooo . Ii1I - OoooooooOO
  if 8 - 8: i1IIi - iIii1I11I1II1 * II111iiii + i11iIiiIii / I1Ii111 % OOooOOo
  if 16 - 16: I1ii11iIi11i + OoO0O00 - II111iiii
 lisp . lisp_timeout_map_cache ( lisp . lisp_map_cache )
 if 85 - 85: OoOoOO00 + i1IIi
 if 58 - 58: II111iiii * OOooOOo * I1ii11iIi11i / OOooOOo
 if 75 - 75: oO0o
 if 50 - 50: Ii1I / Oo0Ooo - oO0o - I11i % iII111i - oO0o
 i1111 = threading . Timer ( 60 , OooOooooOOoo0 ,
 [ lisp_sockets , lisp_ephem_port ] )
 i1111 . start ( )
 return
 if 91 - 91: OoO0O00 / I11i - II111iiii . I11i
 if 18 - 18: o0oOOo0O0Ooo
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 if 92 - 92: iII111i . I1Ii111
 if 31 - 31: I1Ii111 . OoOoOO00 / O0
def o000O0o ( lisp_socket ) :
 lisp . lisp_set_exception ( )
 if 42 - 42: OoOoOO00
 II = lisp . lisp_get_timestamp ( )
 for Ii1I1IIii1II in lisp . lisp_db_list :
  if ( Ii1I1IIii1II . dynamic_eid_configured ( ) == False ) : continue
  if 65 - 65: Ii1I . iIii1I11I1II1 / O0 - Ii1I
  iii1i1iiiiIi = [ ]
  for Iiii in Ii1I1IIii1II . dynamic_eids . values ( ) :
   OO0OoO0o00 = Iiii . last_packet
   if ( OO0OoO0o00 == None ) : continue
   if ( OO0OoO0o00 + Iiii . timeout > II ) : continue
   if 53 - 53: O0 * OoO0O00 + OOooOOo
   if 50 - 50: O0 . O0 - oO0o / I1IiiI - o0oOOo0O0Ooo * OoOoOO00
   if 61 - 61: I11i
   if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
   if 42 - 42: OoO0O00
   if ( lisp . lisp_program_hardware ) :
    o0o = Iiii . dynamic_eid . print_prefix_no_iid ( )
    if ( lisp . lisp_arista_is_alive ( o0o ) ) :
     lisp . lprint ( ( "Hardware indicates dynamic-EID {} " + "still active" ) . format ( lisp . green ( o0o , False ) ) )
     if 84 - 84: O0
     continue
     if 74 - 74: I1ii11iIi11i - I1IiiI - Oo0Ooo . Ii1I - IiII
     if 73 - 73: Oo0Ooo - i1IIi - i1IIi - iII111i . Ii1I + I1ii11iIi11i
     if 81 - 81: iII111i * oO0o - I1Ii111 . II111iiii % I11i / I1IiiI
     if 34 - 34: IiII
     if 57 - 57: oO0o . I11i . i1IIi
     if 42 - 42: I11i + I1ii11iIi11i % O0
   i1iIIIi1i = Iiii . dynamic_eid . print_address ( )
   iI1iIIiiii = "learn%{}%None" . format ( i1iIIIi1i )
   iI1iIIiiii = lisp . lisp_command_ipc ( iI1iIIiiii , "lisp-itr" )
   lisp . lisp_ipc ( iI1iIIiiii , lisp_socket , "lisp-etr" )
   if 26 - 26: I11i . OoooooooOO
   lisp . lprint ( "Dynamic-EID {}" . format ( lisp . bold ( lisp . green ( i1iIIIi1i , False ) + " activity timeout" ,
   # o0oOOo0O0Ooo % iII111i * O0
 False ) ) )
   iii1i1iiiiIi . append ( i1iIIIi1i )
   if 87 - 87: i11iIiiIii
   if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
   if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
   if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
   if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
  for i1iIIIi1i in iii1i1iiiiIi : Ii1I1IIii1II . dynamic_eids . pop ( i1iIIIi1i )
  if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
  if 51 - 51: O0 + iII111i
  if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
  if 48 - 48: O0
  if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 threading . Timer ( lisp . LISP_DEFAULT_DYN_EID_TIMEOUT ,
 o000O0o , [ lisp_socket ] ) . start ( )
 return
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
 if 95 - 95: I1IiiI + i11iIiiIii
def I1Ii ( ) :
 if ( lisp . lisp_is_macos ( ) ) : return ( [ "en0" , "en1" , "lo0" ] )
 if 94 - 94: Ii1I - II111iiii . OOooOOo % I11i . i11iIiiIii + O0
 if 26 - 26: I11i - iIii1I11I1II1 - I1IiiI / OoO0O00 . OoOoOO00 % iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo . iIii1I11I1II1 / oO0o + i1IIi
 if 42 - 42: ooOoO0o . o0oOOo0O0Ooo . ooOoO0o - I1ii11iIi11i
 i1ii1I1I1 = "Link encap"
 oO = getoutput ( "ifconfig | egrep '{}'" . format ( i1ii1I1I1 ) )
 if ( oO == "" ) :
  i1ii1I1I1 = ": flags="
  oO = getoutput ( "ifconfig | egrep '{}'" . format ( i1ii1I1I1 ) )
  if 82 - 82: OoOoOO00 % OOooOOo
  if 64 - 64: Ii1I . II111iiii + OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 oO = oO . split ( "\n" )
 if 99 - 99: Ii1I / Oo0Ooo / IiII % I1IiiI
 i11I1II1I11i = [ ]
 for OooOoOO0 in oO :
  iI1i11iII111 = OooOoOO0 . split ( i1ii1I1I1 ) [ 0 ] . replace ( " " , "" )
  i11I1II1I11i . append ( iI1i11iII111 )
  if 15 - 15: i11iIiiIii % Ii1I . Oo0Ooo + I1ii11iIi11i
 return ( i11I1II1I11i )
 if 61 - 61: Oo0Ooo * I1ii11iIi11i % Oo0Ooo - i1IIi - iIii1I11I1II1
 if 74 - 74: I1ii11iIi11i + II111iiii / OoO0O00
 if 100 - 100: OoOoOO00 * iIii1I11I1II1
 if 86 - 86: OoO0O00 * OOooOOo . iII111i
 if 32 - 32: o0oOOo0O0Ooo . IiII * I11i
 if 93 - 93: o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
 if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
def O00o0OO0 ( ) :
 global Oo0o
 global OOO0o0o
 global Ii1iI
 global Oo
 global I1Ii11I1Ii1i
 global i1 , oOOoo00O0O
 if 35 - 35: oO0o % ooOoO0o / I1Ii111 + iIii1I11I1II1 . OoooooooOO . I1IiiI
 lisp . lisp_i_am ( "itr" )
 lisp . lisp_set_exception ( )
 lisp . lisp_print_banner ( "ITR starting up" )
 if 71 - 71: IiII * II111iiii * oO0o
 if 56 - 56: I1IiiI
 if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 lisp . lisp_get_local_interfaces ( )
 lisp . lisp_get_local_macs ( )
 if ( lisp . lisp_get_local_addresses ( ) == False ) : return ( False )
 if 63 - 63: OoOoOO00 * iII111i
 if 69 - 69: O0 . OoO0O00
 if 49 - 49: I1IiiI - I11i
 if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
 Oo0o [ 0 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV4 )
 Oo0o [ 1 ] = lisp . lisp_open_send_socket ( "" , lisp . LISP_AFI_IPV6 )
 OOO0o0o = lisp . lisp_open_listen_socket ( "" , "lisp-itr" )
 Ii1iI = lisp . lisp_open_listen_socket ( "" , "lispers.net-itr" )
 Oo0o [ 2 ] = OOO0o0o
 oooOo0OOOoo0 = "0.0.0.0" if lisp . lisp_is_raspbian ( ) else "0::0"
 Oo = lisp . lisp_open_listen_socket ( oooOo0OOOoo0 ,
 str ( Ooo ) )
 if 51 - 51: Oo0Ooo / OoOoOO00 . OOooOOo * o0oOOo0O0Ooo + OoO0O00 * IiII
 if 73 - 73: OoO0O00 + OoooooooOO - O0 - Ii1I - II111iiii
 if 99 - 99: ooOoO0o . Ii1I + I1Ii111 + OoooooooOO % o0oOOo0O0Ooo
 if 51 - 51: iIii1I11I1II1
 I1Ii11I1Ii1i = lisp . lisp_open_listen_socket ( "0.0.0.0" ,
 str ( o0oOoO00o ) )
 if 34 - 34: oO0o + I1IiiI - oO0o
 if 17 - 17: II111iiii % iII111i + I11i - iII111i / OOooOOo + ooOoO0o
 if 59 - 59: OOooOOo % OoOoOO00 . Ii1I * I1ii11iIi11i % I11i
 if 59 - 59: oO0o - iII111i
 i1 = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_RAW )
 i1 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 if 15 - 15: I1Ii111 . i11iIiiIii . OoooooooOO / OoO0O00 % Ii1I
 if ( lisp . lisp_is_raspbian ( ) == False ) :
  oOOoo00O0O = socket . socket ( socket . AF_INET6 , socket . SOCK_RAW ,
 socket . IPPROTO_UDP )
  if 93 - 93: O0 % i1IIi . OOooOOo / I1IiiI - I1Ii111 / I1IiiI
  if 36 - 36: oO0o % oO0o % i1IIi / i1IIi - ooOoO0o
  if 30 - 30: I11i / I1IiiI
  if 35 - 35: II111iiii % OOooOOo . ooOoO0o + ooOoO0o % II111iiii % II111iiii
  if 72 - 72: II111iiii + i1IIi + o0oOOo0O0Ooo
  if 94 - 94: oO0o . i1IIi - o0oOOo0O0Ooo % O0 - OoO0O00
  if 72 - 72: Ii1I
  if 1 - 1: OoO0O00 * IiII * OoooooooOO + ooOoO0o
 lisp . lisp_ipc_socket = OOO0o0o
 if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
 if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
 if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
 threading . Thread ( target = o00Oo0oooooo ) . start ( )
 if 76 - 76: I11i / OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 if 71 - 71: I1Ii111 . II111iiii
 if 62 - 62: OoooooooOO . I11i
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
 lisp . lisp_load_checkpoint ( )
 if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 58 - 58: I1IiiI
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo
 lisp . lisp_load_split_pings = ( os . getenv ( "LISP_LOAD_SPLIT_PINGS" ) != None )
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
 if 73 - 73: I11i % i11iIiiIii - I1IiiI
 if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
 if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
 i1111 = threading . Timer ( 60 , OooOooooOOoo0 ,
 [ Oo0o , Ooo ] )
 i1111 . start ( )
 if 23 - 23: i11iIiiIii
 if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
 if 81 - 81: IiII % i1IIi . iIii1I11I1II1
 if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
 threading . Timer ( lisp . LISP_DEFAULT_DYN_EID_TIMEOUT ,
 o000O0o , [ OOO0o0o ] ) . start ( )
 return ( True )
 if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
 if 31 - 31: OOooOOo
 if 23 - 23: I1Ii111 . IiII
 if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
 if 42 - 42: Oo0Ooo
 if 76 - 76: I1IiiI * iII111i % I1Ii111
 if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
 if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
def I1 ( ) :
 oOoOo0O0OOOoO = open ( "./lisp.config" , "r" )
 if 50 - 50: ooOoO0o
 IIIIiii1IIii = False
 II1i11I = 0
 for ii1I1IIii11 in oOoOo0O0OOOoO :
  if ( ii1I1IIii11 == "lisp database-mapping {\n" ) : IIIIiii1IIii = True
  if ( ii1I1IIii11 == "}\n" ) : IIIIiii1IIii = False
  if ( IIIIiii1IIii == False ) : continue
  if ( ii1I1IIii11 [ 0 ] == " " and ii1I1IIii11 . find ( "prefix {" ) != - 1 ) : II1i11I += 1
  if 67 - 67: iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
 oOoOo0O0OOOoO . close ( )
 return ( II1i11I )
 if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
 if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
 if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
 if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
 if 79 - 79: O0 * i11iIiiIii - IiII / IiII
 if 48 - 48: O0
 if 93 - 93: i11iIiiIii - I1IiiI * I1ii11iIi11i * I11i % O0 + OoooooooOO
 if 25 - 25: IiII + Ii1I / ooOoO0o . o0oOOo0O0Ooo % O0 * OoO0O00
 if 84 - 84: ooOoO0o % Ii1I + i11iIiiIii
 if 28 - 28: Oo0Ooo + OoO0O00 * OOooOOo % oO0o . I11i % O0
def I1iiiiIii ( ) :
 if 19 - 19: OoO0O00 - Oo0Ooo . O0
 if 60 - 60: II111iiii + Oo0Ooo
 if 9 - 9: ooOoO0o * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
 if 49 - 49: II111iiii
 if 25 - 25: OoooooooOO - I1IiiI . I1IiiI * oO0o
 II1i11I = I1 ( )
 if 81 - 81: iII111i + IiII
 if 98 - 98: I1IiiI
 if 95 - 95: ooOoO0o / ooOoO0o
 if 30 - 30: I1ii11iIi11i + Oo0Ooo / Oo0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 55 - 55: ooOoO0o - I11i + II111iiii + iII111i % Ii1I
 if 41 - 41: i1IIi - I11i - Ii1I
 III11I1 = os . getenv ( "LISP_ITR_WAIT_TIME" )
 III11I1 = 1 if ( III11I1 == None ) else int ( III11I1 )
 if 36 - 36: oO0o - Ii1I . Oo0Ooo - i11iIiiIii - OOooOOo * Oo0Ooo
 if 76 - 76: i11iIiiIii + o0oOOo0O0Ooo / I1ii11iIi11i - OoO0O00 - Ii1I + I1ii11iIi11i
 if 51 - 51: iIii1I11I1II1 . ooOoO0o + iIii1I11I1II1
 if 95 - 95: I1IiiI
 if 46 - 46: OoOoOO00 + OoO0O00
 while ( II1i11I != len ( lisp . lisp_db_list ) ) :
  lisp . lprint ( ( "Waiting {} second(s) for {} database-mapping EID-" + "prefixes, {} processed so far ..." ) . format ( III11I1 , II1i11I ,
  # I1IiiI / iIii1I11I1II1 % oO0o * OoooooooOO % ooOoO0o
 len ( lisp . lisp_db_list ) ) )
  time . sleep ( III11I1 )
  if 25 - 25: I1ii11iIi11i . ooOoO0o
  if 24 - 24: oO0o / i11iIiiIii + oO0o
  if 20 - 20: I11i + Ii1I / O0 % iIii1I11I1II1
  if 88 - 88: OoOoOO00 / II111iiii
  if 87 - 87: I1ii11iIi11i - I1ii11iIi11i - iII111i + oO0o
  if 82 - 82: oO0o / iIii1I11I1II1 . I1IiiI . OOooOOo / o0oOOo0O0Ooo
 iiI1I1 = [ ]
 ooO = [ ]
 for Ii1I1IIii1II in lisp . lisp_db_list :
  if ( Ii1I1IIii1II . eid . is_ipv4 ( ) or Ii1I1IIii1II . eid . is_ipv6 ( ) or Ii1I1IIii1II . eid . is_mac ( ) ) :
   i1iIIIi1i = Ii1I1IIii1II . eid . print_prefix_no_iid ( )
   if ( Ii1I1IIii1II . dynamic_eid_configured ( ) ) : ooO . append ( i1iIIIi1i )
   iiI1I1 . append ( i1iIIIi1i )
   if 6 - 6: iIii1I11I1II1 . ooOoO0o % o0oOOo0O0Ooo
   if 50 - 50: iII111i + O0 + Ii1I . II111iiii / o0oOOo0O0Ooo
 return ( iiI1I1 , ooO )
 if 17 - 17: Ii1I % iIii1I11I1II1 - iIii1I11I1II1
 if 78 - 78: iII111i + I11i . ooOoO0o - iII111i . Ii1I
 if 30 - 30: I1IiiI + OoO0O00 % Ii1I * iII111i / Oo0Ooo - I11i
 if 64 - 64: iIii1I11I1II1
 if 21 - 21: Oo0Ooo . II111iiii
 if 54 - 54: II111iiii % II111iiii
 if 86 - 86: O0 % Ii1I * ooOoO0o * iIii1I11I1II1 * i1IIi * I11i
 if 83 - 83: OoOoOO00 % II111iiii - OoOoOO00 + IiII - O0
def o00Oo0oooooo ( ) :
 global IIIiI11ii
 if 52 - 52: Oo0Ooo * ooOoO0o
 lisp . lisp_set_exception ( )
 if 33 - 33: Ii1I
 if 74 - 74: OOooOOo + O0 + i1IIi - i1IIi + II111iiii
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 if 5 - 5: Ii1I
 if 46 - 46: IiII
 iiI1I1 , ooO = I1iiiiIii ( )
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if 17 - 17: OOooOOo / OOooOOo / I11i
 if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
 if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
 if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 if 9 - 9: Ii1I
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
 Oo00O = None
 if ( lisp . lisp_ipc_data_plane ) :
  lisp . lprint ( lisp . bold ( "Data-plane packet capture disabled" , False ) )
  Oo00O = "(udp src port 4342 and ip[28] == 0x28)" + " or (ip[16] >= 224 and ip[16] < 240 and (ip[28] & 0xf0) == 0x30)"
  if 12 - 12: o0oOOo0O0Ooo - ooOoO0o * I1Ii111
  if 14 - 14: Oo0Ooo - Ii1I % Ii1I * O0 . i11iIiiIii / O0
  lisp . lprint ( "Control-plane capture: '{}'" . format ( Oo00O ) )
 else :
  lisp . lprint ( "Capturing packets for source-EIDs {}" . format ( lisp . green ( str ( iiI1I1 ) , False ) ) )
  if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
  if 28 - 28: i1IIi - iII111i
 if ( lisp . lisp_pitr ) : lisp . lprint ( "Configured for PITR functionality" )
 if 54 - 54: iII111i - O0 % OOooOOo
 if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
 if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if 28 - 28: I11i
 if 58 - 58: OoOoOO00
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 oo0oOOo0 = lisp . lisp_l2_overlay
 if ( oo0oOOo0 == False ) :
  if ( lisp . lisp_is_linux ( ) ) : O0OoO0ooOO0o ( iiI1I1 , ooO )
  if 81 - 81: O0 * II111iiii + I1IiiI * i11iIiiIii - I1ii11iIi11i / I1IiiI
  if 63 - 63: OoOoOO00 - OoooooooOO % I1Ii111
  if 77 - 77: OoO0O00 . i1IIi
  if 35 - 35: ooOoO0o * OOooOOo . I11i * o0oOOo0O0Ooo . OoOoOO00 / O0
  if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo % O0 * O0
  if 14 - 14: I1ii11iIi11i . ooOoO0o + II111iiii / iII111i / I11i
 if ( Oo00O == None ) :
  if ( lisp . lisp_pitr ) :
   ooo0O = iII1iii ( iiI1I1 , [ ] , False , True )
  else :
   ooo0O = iII1iii ( iiI1I1 , ooO , oo0oOOo0 ,
 False )
   if 12 - 12: OOooOOo
 else :
  ooo0O = Oo00O
  if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
  if 100 - 100: OoO0O00
  if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
  if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
  if 45 - 45: I1Ii111
 oO = I1Ii ( )
 oOIIi1iiii1iI = os . getenv ( "LISP_PCAP_LIST" )
 if ( oOIIi1iiii1iI == None ) :
  iIiiii = ""
  O0000OOO0 = [ ]
 else :
  ooo0 = list ( set ( oOIIi1iiii1iI . split ( ) ) & set ( oO ) )
  O0000OOO0 = list ( set ( oOIIi1iiii1iI . split ( ) ) ^ set ( oO ) )
  iIiiii = "user-selected "
  lisp . lprint ( "User pcap-list: {}, active-interfaces: {}" . format ( oOIIi1iiii1iI , oO ) )
  if 78 - 78: ooOoO0o
  oO = ooo0
  if 53 - 53: ooOoO0o * OOooOOo . iII111i / O0 * ooOoO0o
  if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
  if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
  if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
  if 92 - 92: I11i . I1Ii111
  if 85 - 85: I1ii11iIi11i . I1Ii111
  if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
 O000 = ( ooo0O . find ( "ether host" ) != - 1 )
 for ooo0o000O in oO :
  if ( ooo0o000O in [ "lo" , "lispers.net" ] and O000 ) :
   lisp . lprint ( ( "Capturing suppressed on interface {}, " + "MAC filters configured" ) . format ( ooo0o000O ) )
   if 100 - 100: oO0o . ooOoO0o * I1ii11iIi11i / iIii1I11I1II1 * i1IIi % ooOoO0o
   continue
   if 17 - 17: I11i . IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
   if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
   if 69 - 69: O0
   if 85 - 85: ooOoO0o / O0
   if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
   if 62 - 62: I1Ii111 . IiII . OoooooooOO
  if ( lisp . lisp_is_macos ( ) ) :
   if ( ooo0o000O not in [ "en0" , "lo0" ] ) : continue
   if 11 - 11: OOooOOo / I11i
   if 73 - 73: i1IIi / i11iIiiIii
  OOO = [ ooo0o000O , ooo0O , IIIiI11ii ]
  lisp . lprint ( "Capturing packets on {}interface {}" . format ( iIiiii , ooo0o000O ) )
  threading . Thread ( target = Iiiiii1iI , args = OOO ) . start ( )
  if 49 - 49: o0oOOo0O0Ooo . IiII / OoO0O00 + II111iiii
 if ( Oo00O ) : return
 if 47 - 47: O0 / Ii1I
 if 67 - 67: I1IiiI
 if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
 if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
 if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
 oOooO0 = "(udp src port 4342 and ip[28] == 0x28)"
 for ooo0o000O in O0000OOO0 :
  OOO = [ ooo0o000O , oOooO0 , IIIiI11ii ]
  lisp . lprint ( "Capture RLOC-probe replies on RLOC interface {}" . format ( ooo0o000O ) )
  if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
  threading . Thread ( target = Iiiiii1iI , args = OOO ) . start ( )
  if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 return
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
def IiI11i1IIiiI ( ) :
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if ( i11 ) : i11 . cancel ( )
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 lisp . lisp_close_socket ( Oo0o [ 0 ] , "" )
 lisp . lisp_close_socket ( Oo0o [ 1 ] , "" )
 lisp . lisp_close_socket ( Oo , "" )
 lisp . lisp_close_socket ( I1Ii11I1Ii1i , "" )
 lisp . lisp_close_socket ( OOO0o0o , "lisp-itr" )
 lisp . lisp_close_socket ( Ii1iI , "lispers.net-itr" )
 return
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
 if 95 - 95: IiII
 if 51 - 51: II111iiii + IiII . i1IIi . I1ii11iIi11i + OoOoOO00 * I1IiiI
 if 72 - 72: oO0o + oO0o / II111iiii . OoooooooOO % Ii1I
def III ( packet , device , input_interface , macs , my_sa ) :
 global Oo0o
 global Ooo
 global i1 , oOOoo00O0O
 global OOO0o0o
 if 41 - 41: i11iIiiIii + Oo0Ooo / I1IiiI . OoooooooOO % oO0o % i1IIi
 if 70 - 70: Oo0Ooo . OoooooooOO - iII111i
 if 30 - 30: I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 oOo0oO = packet
 packet , IIi1IIIIi , OOOoO , I1i = lisp . lisp_is_rloc_probe ( packet , 1 )
 if ( oOo0oO != packet ) :
  if ( IIi1IIIIi == None ) : return
  lisp . lisp_parse_packet ( Oo0o , packet , IIi1IIIIi , OOOoO , I1i )
  return
  if 12 - 12: OoooooooOO
  if 20 - 20: i1IIi - I11i
 packet = lisp . lisp_packet ( packet )
 if ( packet . decode ( False , None , None ) == None ) : return
 if 30 - 30: OoOoOO00
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if 10 - 10: II111iiii . iII111i
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 if 88 - 88: iII111i
 if ( my_sa ) : input_interface = device
 if 19 - 19: II111iiii * IiII + Ii1I
 if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
 if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
 if 14 - 14: OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i - ooOoO0o
 o0oOoO0O = packet . inner_source
 i1Ii = lisp . lisp_get_interface_instance_id ( input_interface , o0oOoO0O )
 packet . inner_dest . instance_id = i1Ii
 packet . inner_source . instance_id = i1Ii
 if 84 - 84: O0 * OoooooooOO - IiII * IiII
 if 8 - 8: ooOoO0o / i1IIi . oO0o
 if 41 - 41: iII111i + OoO0O00
 if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
 if ( macs != "" ) : macs = ", MACs: " + macs + ","
 packet . print_packet ( "Receive {}{}" . format ( device , macs ) , False )
 if 56 - 56: O0
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
 if 23 - 23: oO0o - OOooOOo + I11i
 if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
 if ( device != input_interface and device != "lispers.net" ) :
  lisp . dprint ( "Not our MAC address on interface {}, pcap interface {}" . format ( input_interface , device ) )
  if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
  return
  if 11 - 11: iII111i * Ii1I - OoOoOO00
  if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
 oO0OO0 = lisp . lisp_decent_push_configured
 if ( oO0OO0 ) :
  O00Oo = packet . inner_dest . is_multicast_address ( )
  Ii1111IiIi = packet . inner_source . is_local ( )
  oO0OO0 = ( Ii1111IiIi and O00Oo )
  if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
  if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if ( oO0OO0 == False ) :
  if 68 - 68: OoooooooOO % II111iiii
  if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
  if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
  if 2 - 2: Ii1I - IiII
  Ii1I1IIii1II = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_source , False )
  if ( Ii1I1IIii1II == None ) :
   lisp . dprint ( "Packet received from non-EID source" )
   return
   if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
   if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
   if 71 - 71: OoooooooOO
   if 33 - 33: I1Ii111
   if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
  if ( Ii1I1IIii1II . dynamic_eid_configured ( ) ) :
   IIiiii = lisp . lisp_allow_dynamic_eid ( input_interface ,
 packet . inner_source )
   if ( IIiiii ) :
    lisp . lisp_itr_discover_eid ( Ii1I1IIii1II , packet . inner_source ,
 input_interface , IIiiii , OOO0o0o )
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
 if ( iiIIIIi1i1 == False ) :
  Ii1I1IIii1II = lisp . lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( Ii1I1IIii1II and Ii1I1IIii1II . dynamic_eid_configured == False ) :
   lisp . dprint ( ( "Packet destined to local EID-prefix {}, " + "natively forwarding" ) . format ( Ii1I1IIii1II . print_eid_tuple ( ) ) )
   if 15 - 15: IiII / O0 . o0oOOo0O0Ooo . i11iIiiIii
   packet . send_packet ( i1 , packet . inner_dest )
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
 oO00oOo0OOO = Ii1I1IIii1II . secondary_iid if ( Ii1I1IIii1II != None ) else None
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
  lisp . lisp_send_map_request ( Oo0o , Ooo ,
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
   lisp . lisp_send_map_request ( Oo0o , Ooo ,
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
 OO0OoOOO0 , O00ooOo , oOO0o00O , oOoO , IIIIiI1iiiIiii , ii1i1i = I11iIiII . select_rloc ( packet , OOO0o0o )
 if 50 - 50: o0oOOo0O0Ooo * Ii1I % I1ii11iIi11i / Oo0Ooo - O0 % iII111i
 if 48 - 48: I1IiiI + I1ii11iIi11i + II111iiii * i11iIiiIii
 if ( OO0OoOOO0 == None and IIIIiI1iiiIiii == None ) :
  if ( oOoO == lisp . LISP_NATIVE_FORWARD_ACTION ) :
   lisp . dprint ( "Natively forwarding" )
   packet . send_packet ( i1 , packet . inner_dest )
   if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
   if ( packet . is_trace ( ) ) :
    lisp . lisp_trace_append ( packet , reason = "not an EID" )
    if 39 - 39: iIii1I11I1II1 - OoooooooOO
   return
   if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
  iiIiI = "No reachable RLOCs found"
  lisp . dprint ( iiIiI )
  if ( packet . is_trace ( ) ) : lisp . lisp_trace_append ( packet , reason = iiIiI )
  return
  if 87 - 87: ooOoO0o - OoooooooOO + i11iIiiIii
 if ( OO0OoOOO0 and OO0OoOOO0 . is_null ( ) ) :
  iiIiI = "Drop action RLOC found"
  lisp . dprint ( iiIiI )
  if 73 - 73: I11i * OoooooooOO . O0 . IiII
  if ( packet . is_trace ( ) ) : lisp . lisp_trace_append ( packet , reason = iiIiI )
  return
  if 55 - 55: Oo0Ooo
  if 77 - 77: II111iiii
  if 16 - 16: I1IiiI * II111iiii / iIii1I11I1II1 - iII111i
  if 3 - 3: I1IiiI * ooOoO0o + II111iiii - OoO0O00
  if 97 - 97: I1ii11iIi11i / oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
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
   if ( lisp . lisp_trace_append ( packet , rloc_entry = ii1i1i ) == False ) : return
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
  o0OooooOoOO = oOOoo00O0O if iI == 6 else i1
  packet . send_packet ( o0OooooOoOO , packet . outer_dest )
  if 19 - 19: IiII
 elif ( IIIIiI1iiiIiii ) :
  if 78 - 78: OOooOOo % o0oOOo0O0Ooo
  if 39 - 39: I1ii11iIi11i + I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo
  if 7 - 7: IiII . OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - II111iiii
  if 37 - 37: I1Ii111 . OoOoOO00 / O0 * iII111i
  if 7 - 7: OoO0O00 * I11i + II111iiii % i11iIiiIii
  i1i1IiIiIi1Ii = IIIIiI1iiiIiii . rle_nodes [ 0 ] . level
  oO0ooOO = len ( packet . packet )
  for IIi1iI1 in IIIIiI1iiiIiii . rle_forwarding_list :
   if ( IIi1iI1 . level != i1i1IiIiIi1Ii ) : return
   if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
   packet . outer_dest . copy_address ( IIi1iI1 . address )
   if ( oO0OO0 ) : packet . inner_dest . instance_id = 0xffffff
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
   packet . send_packet ( i1 , packet . outer_dest )
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
 OooOoOO0 = device
 if ( I1i111IiIiIi1 == 14 ) :
  oO , iI1I1iII1i , iiIIii , OooOo000o0o = lisp . lisp_get_input_interface ( packet )
  OooOoOO0 = device if ( device in oO ) else oO [ 0 ]
  iIi1iIIIiIiI = lisp . lisp_format_macs ( iI1I1iII1i , iiIIii )
  if ( OooOoOO0 . find ( "vlan" ) != - 1 ) : I1i111IiIiIi1 += 4
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
   oOo0O0o0000o0O0 = struct . unpack ( "I" , packet [ I1i111IiIiIi1 : I1i111IiIiIi1 + 4 ] ) [ 0 ]
   oOo0O0o0000o0O0 = socket . ntohl ( oOo0O0o0000o0O0 )
   OooOoOO0 = "vlan" + str ( oOo0O0o0000o0O0 >> 16 )
   I1i111IiIiIi1 += 4
  elif ( i1iii11 == 0x806 ) :
   lisp . dprint ( "Dropping ARP packets, host should have default route" )
   return
   if 53 - 53: I1Ii111
   if 69 - 69: OoOoOO00 . o0oOOo0O0Ooo . I1IiiI - I1ii11iIi11i
   if 32 - 32: OoooooooOO / I1IiiI / iIii1I11I1II1 + II111iiii . oO0o . o0oOOo0O0Ooo
 if ( lisp . lisp_l2_overlay ) : I1i111IiIiIi1 = 0
 if 21 - 21: iIii1I11I1II1 / II111iiii % i1IIi
 III ( packet [ I1i111IiIiIi1 : : ] , device , OooOoOO0 , iIi1iIIIiIiI , OooOo000o0o )
 return
 if 8 - 8: OoO0O00 + OoOoOO00 . iIii1I11I1II1 % O0
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
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
def O0OoO0ooOO0o ( sources , dyn_eids ) :
 if ( os . getenv ( "LISP_NO_IPTABLES" ) != None ) :
  lisp . lprint ( "User selected to suppress installing iptables rules" )
  return
  if 93 - 93: I1Ii111 + Ii1I
  if 33 - 33: O0
 os . system ( "sudo iptables -t raw -N lisp" )
 os . system ( "sudo iptables -t raw -A PREROUTING -j lisp" )
 os . system ( "sudo ip6tables -t raw -N lisp" )
 os . system ( "sudo ip6tables -t raw -A PREROUTING -j lisp" )
 if 78 - 78: O0 / II111iiii * OoO0O00
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
 if 58 - 58: IiII + iIii1I11I1II1
 if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
 if 79 - 79: ooOoO0o . OoOoOO00 % I1Ii111 - Oo0Ooo
 if 69 - 69: ooOoO0o - o0oOOo0O0Ooo . ooOoO0o
 if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
 if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 oOII1ii1ii11I1 = "sudo ip{}tables -t raw -A lisp -j ACCEPT -d {}"
 o0ooOO0o = [ "127.0.0.1" , "::1" , "224.0.0.0/4 -p igmp" , "ff00::/8" ,
 "fe80::/16" ]
 o0ooOO0o += sources + lisp . lisp_get_all_addresses ( )
 for ooo0i1iI1i1I1 in o0ooOO0o :
  if ( lisp . lisp_is_mac_string ( ooo0i1iI1i1I1 ) ) : continue
  O0Oo0 = "" if ooo0i1iI1i1I1 . find ( ":" ) == - 1 else "6"
  os . system ( oOII1ii1ii11I1 . format ( O0Oo0 , ooo0i1iI1i1I1 ) )
  if 80 - 80: I1IiiI - iIii1I11I1II1 . OOooOOo + OoO0O00 - I1Ii111
  if 5 - 5: iII111i
  if 62 - 62: OoOoOO00 . OoooooooOO . OOooOOo . OoO0O00 * iII111i
  if 78 - 78: oO0o / OoO0O00 - oO0o * OoooooooOO . OoOoOO00
  if 96 - 96: I1IiiI % i1IIi . o0oOOo0O0Ooo . O0
  if 37 - 37: i1IIi - OOooOOo % OoooooooOO / OOooOOo % ooOoO0o
  if 48 - 48: i11iIiiIii % oO0o
  if 29 - 29: iII111i + i11iIiiIii % I11i
 if ( lisp . lisp_pitr == False ) :
  oOII1ii1ii11I1 = "sudo ip{}tables -t raw -A lisp -j ACCEPT -s {} -d {}"
  oOo00Ooo0o0 = "sudo ip{}tables -t raw -C lisp -j ACCEPT -s {} -d {}"
  for IIi1IIIIi in sources :
   if ( lisp . lisp_is_mac_string ( IIi1IIIIi ) ) : continue
   if ( IIi1IIIIi in dyn_eids ) : continue
   O0Oo0 = "" if IIi1IIIIi . find ( ":" ) == - 1 else "6"
   for o00OO00OoO in sources :
    if ( lisp . lisp_is_mac_string ( o00OO00OoO ) ) : continue
    if ( o00OO00OoO in dyn_eids ) : continue
    if ( o00OO00OoO . find ( "." ) != - 1 and IIi1IIIIi . find ( "." ) == - 1 ) : continue
    if ( o00OO00OoO . find ( ":" ) != - 1 and IIi1IIIIi . find ( ":" ) == - 1 ) : continue
    if ( getoutput ( oOo00Ooo0o0 . format ( O0Oo0 , IIi1IIIIi , o00OO00OoO ) ) == "" ) :
     continue
     if 33 - 33: I11i
    os . system ( oOII1ii1ii11I1 . format ( O0Oo0 , IIi1IIIIi , o00OO00OoO ) )
    if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
    if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
    if 21 - 21: OOooOOo
    if 6 - 6: IiII
    if 46 - 46: IiII + oO0o
    if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
    if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 OOo = "sudo ip{}tables -t raw -A lisp -j DROP -s {}"
 for IIi1IIIIi in sources :
  if ( lisp . lisp_is_mac_string ( IIi1IIIIi ) ) : continue
  O0Oo0 = "" if IIi1IIIIi . find ( ":" ) == - 1 else "6"
  os . system ( OOo . format ( O0Oo0 , IIi1IIIIi ) )
  if 99 - 99: OoOoOO00
  if 77 - 77: o0oOOo0O0Ooo
  if 48 - 48: OoOoOO00 % I1ii11iIi11i / I11i . iIii1I11I1II1 * II111iiii
  if 65 - 65: OoOoOO00
  if 31 - 31: I11i * OoOoOO00 . IiII % Ii1I + Oo0Ooo
 Ii1iiIi1I11i = getoutput ( "sudo iptables -t raw -S lisp" ) . split ( "\n" )
 Ii1iiIi1I11i += getoutput ( "sudo ip6tables -t raw -S lisp" ) . split ( "\n" )
 lisp . lprint ( "Using kernel filters: {}" . format ( Ii1iiIi1I11i ) )
 if 89 - 89: I1Ii111 . IiII % Oo0Ooo . Oo0Ooo - OoooooooOO
 if 56 - 56: I11i
 if 21 - 21: iIii1I11I1II1 / I1Ii111 + ooOoO0o - I11i / Oo0Ooo / II111iiii
 if 69 - 69: I1IiiI . OoOoOO00
 if 53 - 53: I11i
 if 68 - 68: oO0o / I1Ii111 % I1Ii111 % O0
 if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 if ( os . getenv ( "LISP_VIRTIO_BUG" ) != None ) :
  oOo00o = ( "sudo iptables -A POSTROUTING -t mangle -p tcp -j " + "CHECKSUM --checksum-fill; " )
  if 98 - 98: OOooOOo % i1IIi . I1IiiI . II111iiii . I1ii11iIi11i / i11iIiiIii
  oOo00o += ( "sudo iptables -A POSTROUTING -t mangle -p udp -j " + "CHECKSUM --checksum-fill; " )
  if 32 - 32: o0oOOo0O0Ooo + I1IiiI . I1Ii111
  oOo00o += ( "sudo ip6tables -A POSTROUTING -t mangle -p tcp -j " + "CHECKSUM --checksum-fill; " )
  if 41 - 41: OoOoOO00 . i11iIiiIii / I11i
  oOo00o += ( "sudo ip6tables -A POSTROUTING -t mangle -p udp -j " + "CHECKSUM --checksum-fill" )
  if 98 - 98: OoOoOO00 % II111iiii
  os . system ( oOo00o )
  OoO0O000 = lisp . bold ( "virtio" , False )
  lisp . lprint ( "{} bug workaround, configure '{}'" . format ( OoO0O000 , oOo00o ) )
  if 14 - 14: OoO0O00 / OoO0O00 * O0 . oO0o
 return
 if 59 - 59: II111iiii * i11iIiiIii
 if 54 - 54: O0 % OoooooooOO - I1IiiI
 if 61 - 61: Oo0Ooo * IiII . Oo0Ooo + Oo0Ooo / IiII * O0
 if 73 - 73: iII111i * iII111i / ooOoO0o
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
def iII1iii ( sources , dyn_eids , l2_overlay , pitr ) :
 if ( l2_overlay ) :
  ooo0O = "ether[6:4] >= 0 and ether[10:2] >= 0"
  lisp . lprint ( "Using pcap filter: '{}'" . format ( ooo0O ) )
  return ( ooo0O )
  if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
  if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 iiiiI1IiI1I1 = "(not ether proto 0x806)"
 oOooO0 = " or (udp src port 4342 and ip[28] == 0x28)"
 iI111i11iI1 = " or (ip[16] >= 224 and ip[16] < 240 and (ip[28] & 0xf0) == 0x30)"
 if 2 - 2: OoOoOO00 + I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 i11I1I = ""
 oo0ooooo00o = ""
 for IIi1IIIIi in sources :
  OoOo = IIi1IIIIi
  if ( lisp . lisp_is_mac_string ( IIi1IIIIi ) ) :
   OoOo = IIi1IIIIi . split ( "/" ) [ 0 ]
   OoOo = OoOo . replace ( "-" , "" )
   i111i1iIi1 = [ ]
   for IIiiii in range ( 0 , 12 , 2 ) : i111i1iIi1 . append ( OoOo [ IIiiii : IIiiii + 2 ] )
   OoOo = "ether host " + ":" . join ( i111i1iIi1 )
   if 95 - 95: OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i1IIi . OoooooooOO
   if 29 - 29: ooOoO0o - i1IIi . I11i - I1ii11iIi11i + ooOoO0o + OoooooooOO
  i11I1I += "{}" . format ( OoOo )
  if ( IIi1IIIIi not in dyn_eids ) : oo0ooooo00o += "{}" . format ( OoOo )
  if ( sources [ - 1 ] == IIi1IIIIi ) : break
  i11I1I += " or "
  if ( IIi1IIIIi not in dyn_eids ) : oo0ooooo00o += " or "
  if 36 - 36: i1IIi / ooOoO0o . iIii1I11I1II1
 if ( oo0ooooo00o [ - 4 : : ] == " or " ) : oo0ooooo00o = oo0ooooo00o [ 0 : - 4 ]
 if 12 - 12: Ii1I
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 oOOoo = getoutput ( "egrep 'lisp-nat = yes' ./lisp.config" )
 oOOoo = ( oOOoo != "" and oOOoo [ 0 ] == " " )
 i1I1iIii11 = lisp . lisp_get_loopback_address ( ) if ( oOOoo ) else None
 if 80 - 80: OoOoOO00 - II111iiii
 I1iI1IiI = ""
 i1i1Ii1I = lisp . lisp_get_all_addresses ( )
 for ooo0i1iI1i1I1 in i1i1Ii1I :
  if ( ooo0i1iI1i1I1 == i1I1iIii11 ) : continue
  I1iI1IiI += "{}" . format ( ooo0i1iI1i1I1 )
  if ( i1i1Ii1I [ - 1 ] == ooo0i1iI1i1I1 ) : break
  I1iI1IiI += " or "
  if 11 - 11: OOooOOo - OoOoOO00 - o0oOOo0O0Ooo * OoOoOO00 + ooOoO0o
  if 62 - 62: I1IiiI * i11iIiiIii . iII111i
 if ( i11I1I != "" ) :
  i11I1I = " and (src net {})" . format ( i11I1I )
  if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if ( oo0ooooo00o != "" ) :
  oo0ooooo00o = " and not (dst net {})" . format ( oo0ooooo00o )
  if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if ( I1iI1IiI != "" ) :
  I1iI1IiI = " and not (dst host {})" . format ( I1iI1IiI )
  if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
  if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
  if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
  if 10 - 10: iII111i . i1IIi + Ii1I
  if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
  if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
  if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if ( pitr ) :
  oo0ooooo00o = ""
  I1iI1IiI = I1iI1IiI . replace ( "dst " , "" )
  if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
  if 84 - 84: i1IIi
  if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
  if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
  if 81 - 81: IiII / OoOoOO00 * IiII . O0
 ooo0O = iiiiI1IiI1I1 + i11I1I + oo0ooooo00o + I1iI1IiI
 ooo0O += oOooO0
 ooo0O += iI111i11iI1
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 lisp . lprint ( "Using pcap filter: '{}'" . format ( ooo0O ) )
 return ( ooo0O )
 if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
 if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
 if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
 if 61 - 61: I1Ii111 - Ii1I % I1ii11iIi11i / ooOoO0o / iII111i + iIii1I11I1II1
 if 87 - 87: I1Ii111 + ooOoO0o + O0 / i1IIi % IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
def Iiiiii1iI ( device , pfilter , pcap_lock ) :
 lisp . lisp_set_exception ( )
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 pcap_lock . acquire ( )
 O0000oO0o00 = pcappy . open_live ( device , 9000 , 0 , 100 )
 pcap_lock . release ( )
 if 80 - 80: OoooooooOO + IiII
 O0000oO0o00 . filter = pfilter
 O0000oO0o00 . loop ( - 1 , Iiii1ii , device )
 return
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if 43 - 43: Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
def iiiii111 ( ) :
 global i11
 global I1Ii11I1Ii1i
 global Oo0o
 if 93 - 93: oO0o * Ii1I
 lisp . lisp_set_exception ( )
 if 27 - 27: I1IiiI * ooOoO0o
 if 77 - 77: IiII
 if 66 - 66: iIii1I11I1II1 . i11iIiiIii / I11i / ooOoO0o + I1Ii111
 if 5 - 5: OoOoOO00 % iII111i + IiII
 if 13 - 13: IiII
 ii1II1II = [ I1Ii11I1Ii1i , I1Ii11I1Ii1i ,
 OOO0o0o ]
 lisp . lisp_build_info_requests ( ii1II1II , None , lisp . LISP_CTRL_PORT )
 if 42 - 42: Ii1I
 if 68 - 68: OOooOOo . Oo0Ooo % ooOoO0o - OoooooooOO * iII111i . OOooOOo
 if 46 - 46: i11iIiiIii - OOooOOo * I1IiiI * I11i % I1ii11iIi11i * i1IIi
 if 5 - 5: O0 / ooOoO0o . Oo0Ooo + OoooooooOO
 i11 . cancel ( )
 i11 = threading . Timer ( lisp . LISP_INFO_INTERVAL ,
 iiiii111 , [ ] )
 i11 . start ( )
 return
 if 97 - 97: IiII . Ii1I . Ii1I / iIii1I11I1II1 - OoO0O00 + iII111i
 if 32 - 32: OOooOOo . o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
 if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
 if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
 if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
 if 26 - 26: o0oOOo0O0Ooo
 if 12 - 12: OoooooooOO / O0 + II111iiii * I1ii11iIi11i
def Ii11ii1I1 ( kv_pair ) :
 global Oo0o
 global Ooo
 global i11
 if 11 - 11: iIii1I11I1II1 . OoOoOO00 / IiII % ooOoO0o
 lispconfig . lisp_map_resolver_command ( kv_pair )
 if 61 - 61: ooOoO0o - OOooOOo + OOooOOo
 if ( lisp . lisp_test_mr_timer == None or
 lisp . lisp_test_mr_timer . is_alive ( ) == False ) :
  lisp . lisp_test_mr_timer = threading . Timer ( 2 , lisp . lisp_test_mr ,
 [ Oo0o , Ooo ] )
  lisp . lisp_test_mr_timer . start ( )
  if 40 - 40: i11iIiiIii . iIii1I11I1II1
  if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
  if 3 - 3: OoooooooOO
  if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
  if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 i11 = threading . Timer ( 0 , iiiii111 , [ ] )
 i11 . start ( )
 return
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
def OoOooOO0oOOo0O ( kv_pair ) :
 lispconfig . lisp_database_mapping_command ( kv_pair )
 return
 if 42 - 42: iII111i / o0oOOo0O0Ooo + Oo0Ooo . Oo0Ooo % OOooOOo
 if 16 - 16: i1IIi + OoO0O00 % OoOoOO00 + Ii1I * Oo0Ooo
 if 3 - 3: i11iIiiIii
 if 81 - 81: I1IiiI . OoooooooOO * Ii1I . oO0o - O0 * oO0o
 if 72 - 72: II111iiii - OOooOOo + I1IiiI - I11i
 if 91 - 91: II111iiii
 if 53 - 53: OoO0O00 % o0oOOo0O0Ooo / OOooOOo % IiII % OoO0O00 % OoooooooOO
 if 31 - 31: I1IiiI
def O0o ( kv_pair ) :
 global Oo
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 o0 = lisp . lisp_nat_traversal
 iIIIIi = lisp . lisp_rloc_probing
 if 50 - 50: I1Ii111 + ooOoO0o + iII111i
 if 15 - 15: I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 lispconfig . lisp_xtr_command ( kv_pair )
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 III11I1OOOO0o0O = ( o0 == False and lisp . lisp_nat_traversal and lisp . lisp_rloc_probing )
 if 41 - 41: o0oOOo0O0Ooo + ooOoO0o
 O00O00OoO = ( iIIIIi == False and lisp . lisp_rloc_probing )
 if 20 - 20: O0 - OoooooooOO - IiII + iIii1I11I1II1
 o0II1IIi1iII1i = 0
 if ( O00O00OoO ) : o0II1IIi1iII1i = 1
 if ( III11I1OOOO0o0O ) : o0II1IIi1iII1i = 5
 if 26 - 26: O0
 if ( o0II1IIi1iII1i != 0 ) :
  iiiIi = [ Oo , Oo ]
  lisp . lisp_start_rloc_probe_timer ( o0II1IIi1iII1i , iiiIi )
  if 62 - 62: O0 . Oo0Ooo
  if 33 - 33: Oo0Ooo / iIii1I11I1II1 % i1IIi
  if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
  if 49 - 49: IiII / ooOoO0o / OOooOOo
  if 25 - 25: I1IiiI % O0 + i1IIi - ooOoO0o
  if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
  if 94 - 94: iII111i - Oo0Ooo + oO0o
 if ( lisp . lisp_crypto_ephem_port == None and lisp . lisp_data_plane_security ) :
  OOOoO = Oo . getsockname ( ) [ 1 ]
  lisp . lisp_crypto_ephem_port = OOOoO
  lisp . lprint ( "Use port {} for lisp-crypto packets" . format ( OOOoO ) )
  O0oooOoO = { "type" : "itr-crypto-port" , "port" : OOOoO }
  lisp . lisp_write_to_dp_socket ( O0oooOoO )
  if 62 - 62: OOooOOo / II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
  if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
  if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
  if 36 - 36: OOooOOo % i11iIiiIii
  if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 lisp . lisp_ipc_write_xtr_parameters ( lisp . lisp_debug_logging ,
 lisp . lisp_data_plane_logging )
 return
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
def OO0OOoooo0o ( ipc ) :
 IiIi1Ii , iiIIiI11II1 , oooOo , oOO0o00O = ipc . split ( "%" )
 oOO0o00O = int ( oOO0o00O , 16 )
 if 79 - 79: oO0o - II111iiii
 Ii1iiI1 = lisp . lisp_get_echo_nonce ( None , oooOo )
 if ( Ii1iiI1 == None ) : Ii1iiI1 = lisp . lisp_echo_nonce ( oooOo )
 if 76 - 76: Ii1I * iIii1I11I1II1
 if 31 - 31: i11iIiiIii + OOooOOo - O0
 if 51 - 51: OoO0O00 * i1IIi / Ii1I * OOooOOo + ooOoO0o % I1ii11iIi11i
 if 34 - 34: oO0o * OoooooooOO + Ii1I + i11iIiiIii
 if 22 - 22: i1IIi
 if ( iiIIiI11II1 == "R" ) :
  Ii1iiI1 . request_nonce_rcvd = oOO0o00O
  Ii1iiI1 . last_request_nonce_rcvd = lisp . lisp_get_timestamp ( )
  Ii1iiI1 . echo_nonce_sent = oOO0o00O
  Ii1iiI1 . last_new_echo_nonce_sent = lisp . lisp_get_timestamp ( )
  lisp . lprint ( "Start echo-nonce mode for {}, nonce 0x{}" . format ( lisp . red ( Ii1iiI1 . rloc_str , False ) , lisp . lisp_hex_string ( oOO0o00O ) ) )
  if 24 - 24: I11i / I1IiiI * i1IIi % OoooooooOO
  if 99 - 99: i11iIiiIii . II111iiii . OoooooooOO
  if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
 if ( iiIIiI11II1 == "E" ) :
  Ii1iiI1 . echo_nonce_rcvd = oOO0o00O
  Ii1iiI1 . last_echo_nonce_rcvd = lisp . lisp_get_timestamp ( )
  if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
  if ( Ii1iiI1 . request_nonce_sent == oOO0o00O ) :
   O00oo00oOOO0o = lisp . bold ( "echoed nonce" , False )
   lisp . lprint ( "Received {} {} from {}" . format ( O00oo00oOOO0o ,
 lisp . lisp_hex_string ( oOO0o00O ) ,
 lisp . red ( Ii1iiI1 . rloc_str , False ) ) )
   if 5 - 5: o0oOOo0O0Ooo / I1IiiI % Ii1I . IiII
   Ii1iiI1 . request_nonce_sent = None
   lisp . lprint ( "Stop request-nonce mode for {}" . format ( lisp . red ( Ii1iiI1 . rloc_str , False ) ) )
   if 86 - 86: i1IIi * OoOoOO00 . O0 - Ii1I - o0oOOo0O0Ooo - OoOoOO00
   Ii1iiI1 . last_good_echo_nonce_rcvd = lisp . lisp_get_timestamp ( )
  else :
   i11IiI = "none"
   if ( Ii1iiI1 . request_nonce_sent ) :
    i11IiI = lisp . lisp_hex_string ( Ii1iiI1 . request_nonce_sent )
    if 93 - 93: i1IIi . IiII / I1IiiI + IiII
   lisp . lprint ( ( "Received echo-nonce 0x{} from {}, but request-" + "nonce is {}" ) . format ( lisp . lisp_hex_string ( oOO0o00O ) ,
   # Oo0Ooo * iIii1I11I1II1 - OoO0O00 . Oo0Ooo
 lisp . red ( Ii1iiI1 . rloc_str , False ) , i11IiI ) )
   if 59 - 59: OoO0O00 - OoO0O00 + iII111i
   if 32 - 32: i1IIi / Oo0Ooo - O0
 return
 if 85 - 85: Ii1I - O0 * i11iIiiIii . i1IIi
 if 20 - 20: iII111i / OOooOOo
 if 28 - 28: ooOoO0o * I11i % i11iIiiIii * iII111i / Ii1I
 if 41 - 41: OOooOOo - o0oOOo0O0Ooo + Ii1I
 if 15 - 15: I11i / o0oOOo0O0Ooo + Ii1I
O0oo00o = {
 "lisp xtr-parameters" : [ O0o , {
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

 "lisp map-resolver" : [ Ii11ii1I1 , {
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

 "lisp database-mapping" : [ OoOooOO0oOOo0O , {
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

 "show itr-map-cache" : [ Ii1 , { } ] ,
 "show itr-rloc-probing" : [ IIII , { } ] ,
 "show itr-keys" : [ oo , { } ] ,
 "show itr-dynamic-eid" : [ lispconfig . lisp_show_dynamic_eid_command , { } ]
 }
if 45 - 45: I1ii11iIi11i + I1Ii111 . iII111i . iII111i
if 34 - 34: OoO0O00 % o0oOOo0O0Ooo % I1IiiI
if 3 - 3: OoooooooOO * I1IiiI * oO0o - IiII - ooOoO0o
if 21 - 21: OoooooooOO - I1ii11iIi11i . OoOoOO00
if 90 - 90: iIii1I11I1II1
if 56 - 56: OOooOOo
if ( O00o0OO0 ( ) == False ) :
 lisp . lprint ( "lisp_itr_startup() failed" )
 lisp . lisp_print_banner ( "ITR abnormal exit" )
 exit ( 1 )
 if 49 - 49: ooOoO0o . II111iiii
 if 24 - 24: O0 . OoooooooOO - OoO0O00 * OoooooooOO
Ii11iiI = [ Oo , OOO0o0o ,
 I1Ii11I1Ii1i , Ii1iI ]
if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
if 28 - 28: iIii1I11I1II1
if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
II1iII1i1i = True
o00oO0O0oo0o = [ Oo ] * 3
iIi11I11 = [ I1Ii11I1Ii1i ] * 3
if 40 - 40: iIii1I11I1II1
while ( True ) :
 try : oOoOo0o00o , iIIi1 , IiIi1Ii = select . select ( Ii11iiI , [ ] , [ ] )
 except : break
 if 68 - 68: Oo0Ooo
 if 22 - 22: OOooOOo
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
 if ( lisp . lisp_ipc_data_plane and Ii1iI in oOoOo0o00o ) :
  lisp . lisp_process_punt ( Ii1iI , Oo0o ,
 Ooo )
  if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
  if 94 - 94: i1IIi
  if 36 - 36: I1IiiI + Oo0Ooo
  if 46 - 46: iII111i
  if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 if ( Oo in oOoOo0o00o ) :
  iiIIiI11II1 , IIi1IIIIi , OOOoO , I1i1I11111iI1 = lisp . lisp_receive ( o00oO0O0oo0o [ 0 ] ,
 False )
  if ( IIi1IIIIi == "" ) : break
  if 32 - 32: I1IiiI + I1ii11iIi11i - oO0o + I1ii11iIi11i / i1IIi * oO0o
  if ( lisp . lisp_is_rloc_probe_reply ( I1i1I11111iI1 [ 0 ] ) ) :
   lisp . lprint ( "ITR ignoring RLOC-probe reply, using pcap" )
   continue
   if 90 - 90: Ii1I % oO0o
  lisp . lisp_parse_packet ( o00oO0O0oo0o , I1i1I11111iI1 , IIi1IIIIi , OOOoO )
  if 6 - 6: OoooooooOO / i11iIiiIii / I1Ii111
  if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  if 34 - 34: I1Ii111 - OOooOOo
  if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
  if 64 - 64: i1IIi
 if ( I1Ii11I1Ii1i in oOoOo0o00o ) :
  iiIIiI11II1 , IIi1IIIIi , OOOoO , I1i1I11111iI1 = lisp . lisp_receive ( iIi11I11 [ 0 ] ,
 False )
  if ( IIi1IIIIi == "" ) : break
  if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
  if ( lisp . lisp_is_rloc_probe_reply ( I1i1I11111iI1 [ 0 ] ) ) :
   lisp . lprint ( "ITR ignoring RLOC-probe reply, using pcap" )
   continue
   if 25 - 25: II111iiii / OoO0O00
  oo0OoOO0000 = lisp . lisp_parse_packet ( iIi11I11 , I1i1I11111iI1 , IIi1IIIIi , OOOoO )
  if 2 - 2: Ii1I * I1ii11iIi11i * OoooooooOO
  if 73 - 73: OoOoOO00 + Oo0Ooo
  if 61 - 61: iIii1I11I1II1
  if 47 - 47: OoooooooOO
  if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
  if ( oo0OoOO0000 ) :
   iiiIi = [ Oo , Oo ]
   lisp . lisp_start_rloc_probe_timer ( 0 , iiiIi )
   if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
   if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
   if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
   if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
   if 26 - 26: OOooOOo * Oo0Ooo
   if 31 - 31: I11i * oO0o . Ii1I
   if 35 - 35: I11i
 if ( OOO0o0o in oOoOo0o00o ) :
  iiIIiI11II1 , IIi1IIIIi , OOOoO , I1i1I11111iI1 = lisp . lisp_receive ( OOO0o0o , True )
  if 94 - 94: ooOoO0o / i11iIiiIii % O0
  if ( IIi1IIIIi == "" ) : break
  if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
  if ( iiIIiI11II1 == "command" ) :
   if ( I1i1I11111iI1 == "clear" ) :
    lisp . lisp_clear_map_cache ( )
    continue
    if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
   if ( I1i1I11111iI1 . find ( "nonce%" ) != - 1 ) :
    OO0OOoooo0o ( I1i1I11111iI1 )
    continue
    if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
   lispconfig . lisp_process_command ( OOO0o0o , iiIIiI11II1 ,
 I1i1I11111iI1 , "lisp-itr" , [ O0oo00o ] )
  elif ( iiIIiI11II1 == "api" ) :
   lisp . lisp_process_api ( "lisp-itr" , OOO0o0o , I1i1I11111iI1 )
  elif ( iiIIiI11II1 == "data-packet" ) :
   III ( I1i1I11111iI1 , "ipc" )
  else :
   if ( lisp . lisp_is_rloc_probe_reply ( I1i1I11111iI1 [ 0 ] ) ) :
    lisp . lprint ( "ITR ignoring RLOC-probe request, using pcap" )
    continue
    if 68 - 68: O0
   lisp . lisp_parse_packet ( Oo0o , I1i1I11111iI1 , IIi1IIIIi , OOOoO )
   if 76 - 76: I1ii11iIi11i
   if 99 - 99: o0oOOo0O0Ooo
   if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
   if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
   if 89 - 89: oO0o
IiI11i1IIiiI ( )
lisp . lisp_print_banner ( "ITR normal exit" )
exit ( 0 )
if 87 - 87: iII111i % Oo0Ooo
if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
