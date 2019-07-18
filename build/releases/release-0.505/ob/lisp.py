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
# lisp.py
#
# This file contains all constants, definitions, data structures, packet
# send and receive functions for the LISP protocol according to RFC 6830.
#
#------------------------------------------------------------------------------
if 64 - 64: i11iIiiIii
import socket
import time
import struct
import binascii
import hmac
import hashlib
import datetime
import os
import sys
import random
import threading
import operator
import netifaces
import platform
import Queue
import traceback
from Crypto . Cipher import AES
import ecdsa
import json
import commands
import copy
import chacha
import poly1305
from geopy . distance import vincenty
import curve25519
use_chacha = ( os . getenv ( "LISP_USE_CHACHA" ) != None )
use_poly = ( os . getenv ( "LISP_USE_POLY" ) != None )
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
lisp_print_rloc_probe_list = False
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
if 94 - 94: i1IIi % Oo0Ooo
if 68 - 68: Ii1I / O0
lisp_hostname = ""
lisp_version = ""
lisp_uptime = ""
lisp_i_am_core = False
lisp_i_am_itr = False
lisp_i_am_etr = False
lisp_i_am_rtr = False
lisp_i_am_mr = False
lisp_i_am_ms = False
lisp_i_am_ddt = False
lisp_log_id = ""
lisp_debug_logging = True
if 46 - 46: O0 * II111iiii / IiII * Oo0Ooo * iII111i . I11i
lisp_map_notify_queue = { }
lisp_map_servers_list = { }
lisp_ddt_map_requestQ = { }
lisp_db_list = [ ]
lisp_group_mapping_list = { }
lisp_map_resolvers_list = { }
lisp_rtr_list = { }
lisp_elp_list = { }
lisp_rle_list = { }
lisp_geo_list = { }
lisp_json_list = { }
lisp_myrlocs = [ None , None , None ]
lisp_mymacs = { }
if 62 - 62: i11iIiiIii - II111iiii % I1Ii111 - iIii1I11I1II1 . I1ii11iIi11i . II111iiii
if 61 - 61: oO0o / OoOoOO00 / iII111i * OoO0O00 . II111iiii
if 1 - 1: II111iiii - I1ii11iIi11i % i11iIiiIii + IiII . I1Ii111
if 55 - 55: iIii1I11I1II1 - I1IiiI . Ii1I * IiII * i1IIi / iIii1I11I1II1
if 79 - 79: oO0o + I1Ii111 . ooOoO0o * IiII % I11i . I1IiiI
lisp_myinterfaces = { }
lisp_iid_to_interface = { }
lisp_multi_tenant_interfaces = [ ]
if 94 - 94: iII111i * Ii1I / IiII . i1IIi * iII111i
lisp_test_mr_timer = None
lisp_rloc_probe_timer = None
if 47 - 47: i1IIi % i11iIiiIii
if 20 - 20: ooOoO0o * II111iiii
if 65 - 65: o0oOOo0O0Ooo * iIii1I11I1II1 * ooOoO0o
if 18 - 18: iIii1I11I1II1 / I11i + oO0o / Oo0Ooo - II111iiii - I11i
lisp_registered_count = 0
if 1 - 1: I11i - OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
if 13 - 13: OOooOOo * oO0o * I1IiiI
if 55 - 55: II111iiii
lisp_info_sources_by_address = { }
lisp_info_sources_by_nonce = { }
if 43 - 43: OoOoOO00 - i1IIi + I1Ii111 + Ii1I
if 17 - 17: o0oOOo0O0Ooo
if 64 - 64: Ii1I % i1IIi % OoooooooOO
if 3 - 3: iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
if 78 - 78: OoO0O00
lisp_crypto_keys_by_nonce = { }
lisp_crypto_keys_by_rloc_encap = { }
lisp_crypto_keys_by_rloc_decap = { }
lisp_data_plane_security = False
lisp_search_decap_keys = True
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
lisp_data_plane_logging = False
lisp_frame_logging = False
lisp_flow_logging = False
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
if 14 - 14: I11i % O0
if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
if 77 - 77: Oo0Ooo . IiII % ooOoO0o
if 42 - 42: oO0o - i1IIi / i11iIiiIii + OOooOOo + OoO0O00
if 17 - 17: oO0o . Oo0Ooo . I1ii11iIi11i
lisp_crypto_ephem_port = None
if 3 - 3: OoOoOO00 . Oo0Ooo . I1IiiI / Ii1I
if 38 - 38: II111iiii % i11iIiiIii . ooOoO0o - OOooOOo + Ii1I
if 66 - 66: OoooooooOO * OoooooooOO . OOooOOo . i1IIi - OOooOOo
if 77 - 77: I11i - iIii1I11I1II1
lisp_pitr = False
if 82 - 82: i11iIiiIii . OOooOOo / Oo0Ooo * O0 % oO0o % iIii1I11I1II1
if 78 - 78: iIii1I11I1II1 - Ii1I * OoO0O00 + o0oOOo0O0Ooo + iII111i + iII111i
if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
if 74 - 74: iII111i * O0
lisp_l2_overlay = False
if 89 - 89: oO0o + Oo0Ooo
if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
if 20 - 20: o0oOOo0O0Ooo
lisp_rloc_probing = False
lisp_rloc_probe_list = { }
if 77 - 77: OoOoOO00 / I11i
if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
if 95 - 95: OoO0O00 % oO0o . O0
if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
if 53 - 53: IiII + I1IiiI * oO0o
lisp_register_all_rtrs = True
if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
if 60 - 60: I11i / I11i
if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
if 83 - 83: OoooooooOO
lisp_nonce_echoing = False
lisp_nonce_echo_list = { }
if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
if 4 - 4: II111iiii / ooOoO0o . iII111i
if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
if 50 - 50: I1IiiI
lisp_nat_traversal = False
if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
if 58 - 58: i11iIiiIii % I11i
lisp_program_hardware = False
if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
if 16 - 16: I1IiiI * oO0o % IiII
if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
lisp_checkpoint_map_cache = False
lisp_checkpoint_filename = "./lisp.checkpoint"
if 44 - 44: oO0o
if 88 - 88: I1Ii111 % Ii1I . II111iiii
if 38 - 38: o0oOOo0O0Ooo
if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
lisp_ipc_data_plane = False
lisp_ipc_dp_socket = None
lisp_ipc_dp_socket_name = "lisp-ipc-data-plane"
if 26 - 26: iII111i
if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
if 91 - 91: oO0o % Oo0Ooo
lisp_ipc_lock = None
if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
if 31 - 31: I11i - II111iiii . I11i
if 18 - 18: o0oOOo0O0Ooo
if 98 - 98: iII111i * iII111i / iII111i + I11i
if 34 - 34: ooOoO0o
if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
lisp_default_iid = 0
if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
if 92 - 92: iII111i . I1Ii111
if 31 - 31: I1Ii111 . OoOoOO00 / O0
if 89 - 89: OoOoOO00
if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
lisp_ms_rtr_list = [ ]
if 4 - 4: ooOoO0o + O0 * OOooOOo
if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
if 25 - 25: I1ii11iIi11i
if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
if 13 - 13: OOooOOo / i11iIiiIii
if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
lisp_nat_state_info = { }
if 52 - 52: o0oOOo0O0Ooo
if 95 - 95: Ii1I
if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
if 91 - 91: O0
lisp_last_map_request_sent = None
if 61 - 61: II111iiii
if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
if 42 - 42: OoO0O00
lisp_last_icmp_too_big_sent = 0
if 67 - 67: I1Ii111 . iII111i . O0
if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
LISP_FLOW_LOG_SIZE = 100
lisp_flow_log = [ ]
if 83 - 83: I11i / I1IiiI
if 34 - 34: IiII
if 57 - 57: oO0o . I11i . i1IIi
if 42 - 42: I11i + I1ii11iIi11i % O0
lisp_policies = { }
if 6 - 6: oO0o
if 68 - 68: OoOoOO00 - OoO0O00
if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
if 1 - 1: iIii1I11I1II1 / II111iiii
if 33 - 33: I11i
lisp_load_split_pings = False
if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
if 87 - 87: i11iIiiIii
if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
lisp_eid_hashes = [ ]
if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
if 51 - 51: O0 + iII111i
if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
if 48 - 48: O0
if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
if 41 - 41: Ii1I - O0 - O0
if 68 - 68: OOooOOo % I1Ii111
if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
lisp_reassembly_queue = { }
if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
if 23 - 23: O0
if 85 - 85: Ii1I
if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
lisp_pubsub_cache = { }
if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
if 77 - 77: iIii1I11I1II1 * OoO0O00
if 95 - 95: I1IiiI + i11iIiiIii
if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
if 80 - 80: II111iiii
if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
lisp_decent_push_configured = False
if 53 - 53: II111iiii
if 31 - 31: OoO0O00
if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
if 25 - 25: OoO0O00
if 62 - 62: OOooOOo + O0
if 98 - 98: o0oOOo0O0Ooo
lisp_decent_modulus = 0
lisp_decent_dns_suffix = None
if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
if 82 - 82: Ii1I
if 46 - 46: OoooooooOO . i11iIiiIii
if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
if 87 - 87: Oo0Ooo . IiII
lisp_ipc_socket = None
if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
if 55 - 55: OOooOOo . I1IiiI
if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
if 100 - 100: I1Ii111 * O0
lisp_ms_encryption_keys = { }
if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
if 79 - 79: O0
if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
if 57 - 57: OoO0O00 / ooOoO0o
if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
if 13 - 13: Ii1I . i11iIiiIii
if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
lisp_rtr_nat_trace_cache = { }
if 63 - 63: OoOoOO00 * iII111i
if 69 - 69: O0 . OoO0O00
if 49 - 49: I1IiiI - I11i
if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
if 62 - 62: OoooooooOO * I1IiiI
if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
if 97 - 97: O0 + OoOoOO00
if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
lisp_glean_mappings = [ ]
if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
if 77 - 77: OOooOOo * iIii1I11I1II1
if 98 - 98: I1IiiI % Ii1I * OoooooooOO
if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
lisp_icmp_raw_socket = None
if ( os . getenv ( "LISP_SEND_ICMP_TOO_BIG" ) != None ) :
 lisp_icmp_raw_socket = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_ICMP )
 lisp_icmp_raw_socket . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 if 71 - 71: Oo0Ooo % OOooOOo
 if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
lisp_ignore_df_bit = ( os . getenv ( "LISP_IGNORE_DF_BIT" ) != None )
if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
if 69 - 69: I1Ii111
if 11 - 11: I1IiiI
if 16 - 16: Ii1I + IiII * O0 % i1IIi . I1IiiI
if 67 - 67: OoooooooOO / I1IiiI * Ii1I + I11i
if 65 - 65: OoooooooOO - I1ii11iIi11i / ooOoO0o / II111iiii / i1IIi
LISP_DATA_PORT = 4341
LISP_CTRL_PORT = 4342
LISP_L2_DATA_PORT = 8472
LISP_VXLAN_DATA_PORT = 4789
LISP_VXLAN_GPE_PORT = 4790
LISP_TRACE_PORT = 2434
if 71 - 71: I1Ii111 + Ii1I
if 28 - 28: OOooOOo
if 38 - 38: ooOoO0o % II111iiii % I11i / OoO0O00 + OoOoOO00 / i1IIi
if 54 - 54: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo / oO0o - OoO0O00 . I11i
LISP_MAP_REQUEST = 1
LISP_MAP_REPLY = 2
LISP_MAP_REGISTER = 3
LISP_MAP_NOTIFY = 4
LISP_MAP_NOTIFY_ACK = 5
LISP_MAP_REFERRAL = 6
LISP_NAT_INFO = 7
LISP_ECM = 8
LISP_TRACE = 9
if 11 - 11: I1ii11iIi11i . OoO0O00 * IiII * OoooooooOO + ooOoO0o
if 33 - 33: O0 * o0oOOo0O0Ooo - I1Ii111 % I1Ii111
if 18 - 18: I1Ii111 / Oo0Ooo * I1Ii111 + I1Ii111 * i11iIiiIii * I1ii11iIi11i
if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
LISP_NO_ACTION = 0
LISP_NATIVE_FORWARD_ACTION = 1
LISP_SEND_MAP_REQUEST_ACTION = 2
LISP_DROP_ACTION = 3
LISP_POLICY_DENIED_ACTION = 4
LISP_AUTH_FAILURE_ACTION = 5
if 26 - 26: Ii1I % I1ii11iIi11i
lisp_map_reply_action_string = [ "no-action" , "native-forward" ,
 "send-map-request" , "drop-action" , "policy-denied" , "auth-failure" ]
if 76 - 76: IiII * iII111i
if 52 - 52: OOooOOo
if 19 - 19: I1IiiI
if 25 - 25: Ii1I / ooOoO0o
LISP_NONE_ALG_ID = 0
LISP_SHA_1_96_ALG_ID = 1
LISP_SHA_256_128_ALG_ID = 2
LISP_MD5_AUTH_DATA_LEN = 16
LISP_SHA1_160_AUTH_DATA_LEN = 20
LISP_SHA2_256_AUTH_DATA_LEN = 32
if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
if 71 - 71: I1Ii111 . II111iiii
if 62 - 62: OoooooooOO . I11i
if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
LISP_LCAF_NULL_TYPE = 0
LISP_LCAF_AFI_LIST_TYPE = 1
LISP_LCAF_INSTANCE_ID_TYPE = 2
LISP_LCAF_ASN_TYPE = 3
LISP_LCAF_APP_DATA_TYPE = 4
LISP_LCAF_GEO_COORD_TYPE = 5
LISP_LCAF_OPAQUE_TYPE = 6
LISP_LCAF_NAT_TYPE = 7
LISP_LCAF_NONCE_LOC_TYPE = 8
LISP_LCAF_MCAST_INFO_TYPE = 9
LISP_LCAF_ELP_TYPE = 10
LISP_LCAF_SECURITY_TYPE = 11
LISP_LCAF_SOURCE_DEST_TYPE = 12
LISP_LCAF_RLE_TYPE = 13
LISP_LCAF_JSON_TYPE = 14
LISP_LCAF_KV_TYPE = 15
LISP_LCAF_ENCAP_TYPE = 16
if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
if 58 - 58: I1IiiI
if 53 - 53: i1IIi
if 59 - 59: o0oOOo0O0Ooo
LISP_MR_TTL = ( 24 * 60 )
LISP_REGISTER_TTL = 3
LISP_SHORT_TTL = 1
LISP_NMR_TTL = 15
LISP_GLEAN_TTL = 15
if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
LISP_SITE_TIMEOUT_CHECK_INTERVAL = 60
LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL = 60
LISP_REFERRAL_TIMEOUT_CHECK_INTERVAL = 60
LISP_TEST_MR_INTERVAL = 60
LISP_MAP_NOTIFY_INTERVAL = 2
LISP_DDT_MAP_REQUEST_INTERVAL = 2
LISP_MAX_MAP_NOTIFY_RETRIES = 3
LISP_INFO_INTERVAL = 15
LISP_MAP_REQUEST_RATE_LIMIT = 5
LISP_ICMP_TOO_BIG_RATE_LIMIT = 1
if 73 - 73: I11i % i11iIiiIii - I1IiiI
LISP_RLOC_PROBE_TTL = 64
LISP_RLOC_PROBE_INTERVAL = 10
LISP_RLOC_PROBE_REPLY_WAIT = 15
if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
LISP_DEFAULT_DYN_EID_TIMEOUT = 15
LISP_NONCE_ECHO_INTERVAL = 10
if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
if 23 - 23: i11iIiiIii
if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
if 81 - 81: IiII % i1IIi . iIii1I11I1II1
if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
if 31 - 31: OOooOOo
if 23 - 23: I1Ii111 . IiII
if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
if 42 - 42: Oo0Ooo
if 76 - 76: I1IiiI * iII111i % I1Ii111
if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
if 42 - 42: I1IiiI
if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
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
if 16 - 16: I11i - iIii1I11I1II1 / I1IiiI . II111iiii + iIii1I11I1II1
if 19 - 19: OoO0O00 - Oo0Ooo . O0
if 60 - 60: II111iiii + Oo0Ooo
if 9 - 9: ooOoO0o * OoooooooOO - iIii1I11I1II1 + OoOoOO00 / OoO0O00 . OoO0O00
if 49 - 49: II111iiii
if 25 - 25: OoooooooOO - I1IiiI . I1IiiI * oO0o
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
if 31 - 31: iII111i . OOooOOo - ooOoO0o . OoooooooOO / OoooooooOO
LISP_CS_1024 = 0
LISP_CS_1024_G = 2
LISP_CS_1024_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 56 - 56: OoO0O00 / oO0o / i11iIiiIii + OoooooooOO - Oo0Ooo - I11i
LISP_CS_2048_CBC = 1
LISP_CS_2048_CBC_G = 2
LISP_CS_2048_CBC_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 21 - 21: O0 % IiII . I1IiiI / II111iiii + IiII
LISP_CS_25519_CBC = 2
LISP_CS_2048_GCM = 3
if 53 - 53: oO0o - I1IiiI - oO0o * iII111i
LISP_CS_3072 = 4
LISP_CS_3072_G = 2
LISP_CS_3072_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
if 71 - 71: O0 - iIii1I11I1II1
LISP_CS_25519_GCM = 5
LISP_CS_25519_CHACHA = 6
if 12 - 12: OOooOOo / o0oOOo0O0Ooo
LISP_4_32_MASK = 0xFFFFFFFF
LISP_8_64_MASK = 0xFFFFFFFFFFFFFFFF
LISP_16_128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
if 42 - 42: Oo0Ooo
if 19 - 19: oO0o % I1ii11iIi11i * iIii1I11I1II1 + I1IiiI
if 46 - 46: Oo0Ooo
if 1 - 1: iII111i
if 97 - 97: OOooOOo + iII111i + O0 + i11iIiiIii
if 77 - 77: o0oOOo0O0Ooo / OoooooooOO
if 46 - 46: o0oOOo0O0Ooo % iIii1I11I1II1 . iII111i % iII111i + i11iIiiIii
if 72 - 72: iIii1I11I1II1 * Ii1I % ooOoO0o / OoO0O00
def lisp_record_traceback ( * args ) :
 I11i1II = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
 Ooo = open ( "./logs/lisp-traceback.log" , "a" )
 Ooo . write ( "---------- Exception occurred: {} ----------\n" . format ( I11i1II ) )
 try :
  traceback . print_last ( file = Ooo )
 except :
  Ooo . write ( "traceback.print_last(file=fd) failed" )
  if 21 - 21: Oo0Ooo
 try :
  traceback . print_last ( )
 except :
  print ( "traceback.print_last() failed" )
  if 29 - 29: I11i / II111iiii / ooOoO0o * OOooOOo
 Ooo . close ( )
 return
 if 10 - 10: I1Ii111 % IiII * IiII . I11i / Ii1I % OOooOOo
 if 49 - 49: OoO0O00 / oO0o + O0 * o0oOOo0O0Ooo
 if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
 if 54 - 54: i1IIi + II111iiii
 if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
 if 5 - 5: Ii1I
 if 46 - 46: IiII
def lisp_set_exception ( ) :
 sys . excepthook = lisp_record_traceback
 return
 if 45 - 45: ooOoO0o
 if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
 if 17 - 17: OOooOOo / OOooOOo / I11i
 if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
 if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
 if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
 if 9 - 9: Ii1I
def lisp_is_raspbian ( ) :
 if ( platform . dist ( ) [ 0 ] != "debian" ) : return ( False )
 return ( platform . machine ( ) in [ "armv6l" , "armv7l" ] )
 if 59 - 59: I1IiiI * II111iiii . O0
 if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
 if 27 - 27: O0
 if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
 if 28 - 28: i1IIi - iII111i
def lisp_is_ubuntu ( ) :
 return ( platform . dist ( ) [ 0 ] == "Ubuntu" )
 if 54 - 54: iII111i - O0 % OOooOOo
 if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
 if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if 28 - 28: I11i
 if 58 - 58: OoOoOO00
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 if 73 - 73: i11iIiiIii - IiII
def lisp_is_fedora ( ) :
 return ( platform . dist ( ) [ 0 ] == "fedora" )
 if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
 if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
 if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
 if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
def lisp_is_centos ( ) :
 return ( platform . dist ( ) [ 0 ] == "centos" )
 if 97 - 97: I1IiiI / iII111i
 if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
def lisp_is_debian ( ) :
 return ( platform . dist ( ) [ 0 ] == "debian" )
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
 if 7 - 7: OoooooooOO . IiII
 if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
def lisp_is_debian_kali ( ) :
 return ( platform . dist ( ) [ 0 ] == "Kali" )
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
 if 92 - 92: ooOoO0o
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if 92 - 92: I11i . I1Ii111
 if 85 - 85: I1ii11iIi11i . I1Ii111
def lisp_is_macos ( ) :
 return ( platform . uname ( ) [ 0 ] == "Darwin" )
 if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
 if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
 if 18 - 18: iIii1I11I1II1 % I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
def lisp_is_alpine ( ) :
 return ( os . path . exists ( "/etc/alpine-release" ) )
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 if 73 - 73: i1IIi / i11iIiiIii
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
def lisp_is_x86 ( ) :
 oOOoOo = platform . machine ( )
 return ( oOOoOo in ( "x86" , "i686" , "x86_64" ) )
 if 89 - 89: II111iiii + i1IIi + II111iiii
 if 7 - 7: O0 % o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - iII111i
 if 42 - 42: OoOoOO00 * OoOoOO00 * I1Ii111 . I11i
 if 51 - 51: OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o * iIii1I11I1II1 % OoO0O00
 if 99 - 99: oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
def lisp_is_linux ( ) :
 return ( platform . uname ( ) [ 0 ] == "Linux" )
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
def lisp_on_aws ( ) :
 IIIii = commands . getoutput ( "sudo dmidecode -s bios-version" )
 return ( IIIii . lower ( ) . find ( "amazon" ) != - 1 )
 if 83 - 83: IiII % o0oOOo0O0Ooo % I1IiiI . iIii1I11I1II1 - IiII
 if 88 - 88: OoooooooOO
 if 84 - 84: OoOoOO00 / I11i * iII111i / oO0o - i11iIiiIii . Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
def lisp_on_gcp ( ) :
 IIIii = commands . getoutput ( "sudo dmidecode -s bios-version" )
 return ( IIIii . lower ( ) . find ( "google" ) != - 1 )
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
 if 85 - 85: OoooooooOO * iIii1I11I1II1 . iII111i / OoooooooOO % I1IiiI % O0
 if 36 - 36: Ii1I / II111iiii / IiII / IiII + I1ii11iIi11i
def lisp_process_logfile ( ) :
 oO0Ooo0ooOO0 = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( oO0Ooo0ooOO0 ) ) : return
 if 46 - 46: Ii1I % OoOoOO00
 sys . stdout . close ( )
 sys . stdout = open ( oO0Ooo0ooOO0 , "a" )
 if 64 - 64: i11iIiiIii - II111iiii
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 77 - 77: OoOoOO00 % Ii1I
 if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 if 59 - 59: OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 lisp_hostname = socket . gethostname ( )
 ii = lisp_hostname . find ( "." )
 if ( ii != - 1 ) : lisp_hostname = lisp_hostname [ 0 : ii ]
 return
 if 81 - 81: O0 % Ii1I
 if 5 - 5: OoooooooOO - OoO0O00 + IiII - iII111i . OoO0O00 / ooOoO0o
 if 28 - 28: Ii1I * Ii1I - iIii1I11I1II1
 if 70 - 70: I1Ii111
 if 16 - 16: iII111i - OoooooooOO % Oo0Ooo
 if 36 - 36: OOooOOo
 if 84 - 84: I1Ii111 . OoO0O00 . II111iiii . I11i / Ii1I % I1ii11iIi11i
def lprint ( * args ) :
 if ( lisp_debug_logging == False ) : return
 if 57 - 57: I1IiiI % I11i - OOooOOo . I1IiiI / Oo0Ooo % iII111i
 lisp_process_logfile ( )
 I11i1II = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 I11i1II = I11i1II [ : - 3 ]
 print "{}: {}:" . format ( I11i1II , lisp_log_id ) ,
 for OO in args : print OO ,
 print ""
 try : sys . stdout . flush ( )
 except : pass
 return
 if 16 - 16: IiII * OoOoOO00 . ooOoO0o / i1IIi . OoO0O00 - i1IIi
 if 46 - 46: IiII + iIii1I11I1II1 + OOooOOo + OoO0O00 . I1ii11iIi11i
 if 1 - 1: oO0o
 if 62 - 62: i1IIi - OOooOOo
 if 96 - 96: i1IIi . I1ii11iIi11i + oO0o
 if 48 - 48: iIii1I11I1II1 % i1IIi % iII111i + ooOoO0o
 if 30 - 30: i11iIiiIii % iIii1I11I1II1 . I11i % iIii1I11I1II1
 if 62 - 62: Oo0Ooo * OoOoOO00
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 79 - 79: OoO0O00 . iII111i * Ii1I - OOooOOo + ooOoO0o
 if 14 - 14: i11iIiiIii - iII111i * OoOoOO00
 if 51 - 51: I1ii11iIi11i / iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo * ooOoO0o + I1Ii111
 if 77 - 77: ooOoO0o * OoOoOO00
 if 14 - 14: I11i % I11i / IiII
 if 72 - 72: i1IIi - II111iiii - OOooOOo + OOooOOo * o0oOOo0O0Ooo * OOooOOo
 if 33 - 33: Oo0Ooo
 if 49 - 49: OoO0O00 % iII111i % iII111i / iII111i
def debug ( * args ) :
 lisp_process_logfile ( )
 if 53 - 53: iIii1I11I1II1
 I11i1II = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 I11i1II = I11i1II [ : - 3 ]
 if 68 - 68: OoooooooOO % II111iiii
 print red ( ">>>" , False ) ,
 print "{}:" . format ( I11i1II ) ,
 for OO in args : print OO ,
 print red ( "<<<\n" , False )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if ( lisp_version == "" ) :
  lisp_version = commands . getoutput ( "cat lisp-version.txt" )
  if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 I111i1I1 = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , I111i1I1 ) )
 return
 if 62 - 62: OOooOOo * I1Ii111 / Oo0Ooo * o0oOOo0O0Ooo
 if 29 - 29: Oo0Ooo % OoO0O00 % IiII . o0oOOo0O0Ooo / OoooooooOO * ooOoO0o
 if 54 - 54: O0
 if 68 - 68: OoO0O00 * o0oOOo0O0Ooo . ooOoO0o % oO0o % I1Ii111
 if 75 - 75: OoOoOO00
 if 34 - 34: O0
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
 if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
 if 91 - 91: oO0o + OoooooooOO - i1IIi
 if 84 - 84: Ii1I / IiII
 if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if 37 - 37: i11iIiiIii + i1IIi
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 if 8 - 8: o0oOOo0O0Ooo
 if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
 if 78 - 78: Ii1I / II111iiii % OoOoOO00
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 52 - 52: OOooOOo - iII111i * oO0o
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
 if 36 - 36: O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
 if 63 - 63: I1ii11iIi11i
 if 6 - 6: ooOoO0o / I1ii11iIi11i
 if 57 - 57: I11i
 if 67 - 67: OoO0O00 . ooOoO0o
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 87 - 87: oO0o % Ii1I
 if 83 - 83: II111iiii - I11i
 if 35 - 35: i1IIi - iIii1I11I1II1 + i1IIi
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
def convert_font ( string ) :
 i1I = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 iiII1I11IIi = "[0m"
 if 66 - 66: i11iIiiIii / o0oOOo0O0Ooo - OoooooooOO / i1IIi . i11iIiiIii
 for IIIII1iii11 in i1I :
  IIi1I = IIIII1iii11 [ 0 ]
  iii = IIIII1iii11 [ 1 ]
  O00O00O000OOO = len ( IIi1I )
  ii = string . find ( IIi1I )
  if ( ii != - 1 ) : break
  if 3 - 3: O0
  if 64 - 64: i1IIi % ooOoO0o / i11iIiiIii - i1IIi % OOooOOo . iII111i
 while ( ii != - 1 ) :
  II1i111 = string [ ii : : ] . find ( iiII1I11IIi )
  i1iiiIii11 = string [ ii + O00O00O000OOO : ii + II1i111 ]
  string = string [ : ii ] + iii ( i1iiiIii11 , True ) + string [ ii + II1i111 + O00O00O000OOO : : ]
  if 67 - 67: o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
  ii = string . find ( IIi1I )
  if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
  if 62 - 62: i1IIi - OoOoOO00
  if 62 - 62: i1IIi + Oo0Ooo % IiII
  if 28 - 28: I1ii11iIi11i . i1IIi
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 10 - 10: OoO0O00 / Oo0Ooo
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
 if 57 - 57: O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
def lisp_space ( num ) :
 iiIiI = ""
 for o0Ooo0O00 in range ( num ) : iiIiI += "&#160;"
 return ( iiIiI )
 if 9 - 9: O0 . IiII
 if 55 - 55: Oo0Ooo
 if 77 - 77: II111iiii
 if 16 - 16: I1IiiI * II111iiii / iIii1I11I1II1 - iII111i
 if 3 - 3: I1IiiI * ooOoO0o + II111iiii - OoO0O00
 if 97 - 97: I1ii11iIi11i / oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
def lisp_button ( string , url ) :
 IIiIiiiIIIIi1 = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 39 - 39: OoO0O00 / Ii1I / I1Ii111
 if 81 - 81: I11i / OoO0O00 % OoooooooOO * oO0o / oO0o
 if ( url == None ) :
  IiiI = IIiIiiiIIIIi1 + string + "</button>"
 else :
  i11ii = '<a href="{}">' . format ( url )
  i11I1 = lisp_space ( 2 )
  IiiI = i11I1 + i11ii + IIiIiiiIIIIi1 + string + "</button></a>" + i11I1
  if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 return ( IiiI )
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
def lisp_print_cour ( string ) :
 iiIiI = '<font face="Courier New">{}</font>' . format ( string )
 return ( iiIiI )
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if 7 - 7: II111iiii
 if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
 if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
def lisp_print_sans ( string ) :
 iiIiI = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( iiIiI )
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
 if 94 - 94: I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
def lisp_span ( string , hover_string ) :
 iiIiI = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( iiIiI )
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
def lisp_eid_help_hover ( output ) :
 Oo0Ooo0O0 = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 42 - 42: i1IIi * oO0o - Ii1I . I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1
 if 51 - 51: I11i . Oo0Ooo
 IiiIiiIi = lisp_span ( output , Oo0Ooo0O0 )
 return ( IiiIiiIi )
 if 40 - 40: o0oOOo0O0Ooo
 if 78 - 78: iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
def lisp_geo_help_hover ( output ) :
 Oo0Ooo0O0 = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 IiiIiiIi = lisp_span ( output , Oo0Ooo0O0 )
 return ( IiiIiiIi )
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 if 66 - 66: Oo0Ooo
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
def space ( num ) :
 iiIiI = ""
 for o0Ooo0O00 in range ( num ) : iiIiI += "&#160;"
 return ( iiIiI )
 if 55 - 55: o0oOOo0O0Ooo . iII111i
 if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
 if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
 if 89 - 89: OoO0O00 + IiII * I1Ii111
 if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
 if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
 if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
 if 62 - 62: o0oOOo0O0Ooo
 if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
 if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 84 - 84: i11iIiiIii * OoO0O00
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
def lisp_hex_string ( integer_value ) :
 i111II = hex ( integer_value ) [ 2 : : ]
 if ( i111II [ - 1 ] == "L" ) : i111II = i111II [ 0 : - 1 ]
 return ( i111II )
 if 63 - 63: I1IiiI - OoO0O00 % iII111i % I11i / o0oOOo0O0Ooo / i1IIi
 if 69 - 69: Oo0Ooo * II111iiii * ooOoO0o . iII111i - I1ii11iIi11i
 if 39 - 39: Ii1I * I1IiiI % OoO0O00 . OoOoOO00
 if 24 - 24: i1IIi * iIii1I11I1II1 / Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if 47 - 47: oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 OOo0 = time . time ( ) - ts
 OOo0 = round ( OOo0 , 0 )
 return ( str ( datetime . timedelta ( seconds = OOo0 ) ) )
 if 58 - 58: OoOoOO00 - iII111i - OoooooooOO
 if 96 - 96: iIii1I11I1II1
 if 82 - 82: OoOoOO00 + O0 - IiII % oO0o * i11iIiiIii
 if 15 - 15: o0oOOo0O0Ooo
 if 39 - 39: OOooOOo / I1ii11iIi11i / I1IiiI * I1Ii111
 if 44 - 44: O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / O0 - I11i
 if 83 - 83: IiII * I11i / Oo0Ooo
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 iIIIiI = ts - time . time ( )
 if ( iIIIiI < 0 ) : return ( "expired" )
 iIIIiI = round ( iIIIiI , 0 )
 return ( str ( datetime . timedelta ( seconds = iIIIiI ) ) )
 if 93 - 93: ooOoO0o . iIii1I11I1II1 % i11iIiiIii . OoOoOO00 % ooOoO0o + O0
 if 65 - 65: Ii1I + OoO0O00 - OoooooooOO
 if 51 - 51: Oo0Ooo + oO0o / iII111i - i1IIi
 if 51 - 51: Oo0Ooo - I1ii11iIi11i * I11i
 if 12 - 12: iIii1I11I1II1 % ooOoO0o % ooOoO0o
 if 78 - 78: IiII . OoOoOO00 . I11i
 if 97 - 97: oO0o
 if 80 - 80: I1IiiI . Ii1I
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
def lisp_print_eid_tuple ( eid , group ) :
 o0o0O00 = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( o0o0O00 )
 if 35 - 35: iIii1I11I1II1
 o00oOOo = group . print_prefix ( )
 o0ooOo00O = group . instance_id
 if 38 - 38: iIii1I11I1II1 + i11iIiiIii * OoO0O00 * ooOoO0o % OOooOOo
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  ii = o00oOOo . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( o0ooOo00O , o00oOOo [ ii : : ] ) )
  if 5 - 5: ooOoO0o - I1Ii111 + I1IiiI * O0 / Oo0Ooo - Ii1I
  if 75 - 75: OoooooooOO - OOooOOo + o0oOOo0O0Ooo / iII111i % i11iIiiIii
 iiiiii1 = eid . print_sg ( group )
 return ( iiiiii1 )
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
 if 93 - 93: I1Ii111 + Ii1I
 if 33 - 33: O0
 if 78 - 78: O0 / II111iiii * OoO0O00
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
 if 58 - 58: IiII + iIii1I11I1II1
 if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 O0o0O0OO0o = addr_str . split ( ":" )
 return ( O0o0O0OO0o [ - 1 ] )
 if 54 - 54: OoOoOO00 . oO0o % i11iIiiIii / OoooooooOO + IiII % oO0o
 if 36 - 36: oO0o
 if 74 - 74: OoooooooOO
 if 72 - 72: O0 + I1IiiI - iII111i - OoO0O00
 if 100 - 100: O0
 if 79 - 79: iIii1I11I1II1
 if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
 if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 if 11 - 11: i1IIi % OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
def lisp_convert_4to6 ( addr_str ) :
 O0o0O0OO0o = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( O0o0O0OO0o . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 O0o0O0OO0o . store_address ( addr_str )
 return ( O0o0O0OO0o )
 if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
 if 2 - 2: OoooooooOO . OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
def lisp_gethostbyname ( string ) :
 oOo00Ooo0o0 = string . split ( "." )
 i1IiII1i1I = string . split ( ":" )
 iI1ii1ii1I = string . split ( "-" )
 if 18 - 18: oO0o * oO0o % oO0o
 if ( len ( oOo00Ooo0o0 ) > 1 ) :
  if ( oOo00Ooo0o0 [ 0 ] . isdigit ( ) ) : return ( string )
  if 17 - 17: O0 * OoOoOO00 * I1ii11iIi11i * II111iiii * I11i % i1IIi
 if ( len ( i1IiII1i1I ) > 1 ) :
  try :
   int ( i1IiII1i1I [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 33 - 33: I1ii11iIi11i * I1ii11iIi11i . ooOoO0o . i11iIiiIii
   if 48 - 48: o0oOOo0O0Ooo . Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
   if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
   if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
   if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
   if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
   if 24 - 24: OoOoOO00
 if ( len ( iI1ii1ii1I ) == 3 ) :
  for o0Ooo0O00 in range ( 3 ) :
   try : int ( iI1ii1ii1I [ o0Ooo0O00 ] , 16 )
   except : break
   if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
   if 28 - 28: I1IiiI
   if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 try :
  O0o0O0OO0o = socket . gethostbyname ( string )
  return ( O0o0O0OO0o )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
  if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
  if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
  if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
  if 79 - 79: OoOoOO00 / ooOoO0o
 try :
  O0o0O0OO0o = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( O0o0O0OO0o [ 3 ] != string ) : return ( "" )
  O0o0O0OO0o = O0o0O0OO0o [ 4 ] [ 0 ]
 except :
  O0o0O0OO0o = ""
  if 77 - 77: Oo0Ooo
 return ( O0o0O0OO0o )
 if 46 - 46: I1Ii111
 if 72 - 72: iII111i * OOooOOo
 if 67 - 67: i1IIi
 if 5 - 5: II111iiii . OoooooooOO
 if 57 - 57: I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if 50 - 50: OoOoOO00
 if 33 - 33: I11i
def lisp_ip_checksum ( data ) :
 if ( len ( data ) < 20 ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 98 - 98: OoOoOO00 % II111iiii
  if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
 IiiIIi1 = binascii . hexlify ( data )
 if 28 - 28: o0oOOo0O0Ooo
 if 45 - 45: o0oOOo0O0Ooo . I1IiiI / I1Ii111 - Oo0Ooo * iIii1I11I1II1
 if 86 - 86: II111iiii + ooOoO0o + IiII
 if 9 - 9: ooOoO0o + II111iiii % ooOoO0o % IiII + iIii1I11I1II1
 oO00 = 0
 for o0Ooo0O00 in range ( 0 , 40 , 4 ) :
  oO00 += int ( IiiIIi1 [ o0Ooo0O00 : o0Ooo0O00 + 4 ] , 16 )
  if 7 - 7: O0 % I1Ii111 + I1ii11iIi11i + Ii1I % OoooooooOO . Oo0Ooo
  if 56 - 56: iII111i
  if 84 - 84: OoOoOO00 - i11iIiiIii
  if 1 - 1: iII111i * OoOoOO00
  if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 oO00 = ( oO00 >> 16 ) + ( oO00 & 0xffff )
 oO00 += oO00 >> 16
 oO00 = socket . htons ( ~ oO00 & 0xffff )
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 oO00 = struct . pack ( "H" , oO00 )
 IiiIIi1 = data [ 0 : 10 ] + oO00 + data [ 12 : : ]
 return ( IiiIIi1 )
 if 69 - 69: I1ii11iIi11i
 if 83 - 83: o0oOOo0O0Ooo
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if 48 - 48: iII111i + IiII
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 if 14 - 14: OOooOOo
 if 79 - 79: Ii1I
def lisp_icmp_checksum ( data ) :
 if ( len ( data ) < 36 ) :
  lprint ( "ICMP packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 76 - 76: iIii1I11I1II1
  if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
 ooOo000OoO0o = binascii . hexlify ( data )
 if 58 - 58: I1ii11iIi11i
 if 2 - 2: II111iiii / I1Ii111
 if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 if 22 - 22: ooOoO0o . iIii1I11I1II1
 oO00 = 0
 for o0Ooo0O00 in range ( 0 , 36 , 4 ) :
  oO00 += int ( ooOo000OoO0o [ o0Ooo0O00 : o0Ooo0O00 + 4 ] , 16 )
  if 12 - 12: Ii1I
  if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
  if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
  if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
  if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 oO00 = ( oO00 >> 16 ) + ( oO00 & 0xffff )
 oO00 += oO00 >> 16
 oO00 = socket . htons ( ~ oO00 & 0xffff )
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 if 68 - 68: oO0o
 oO00 = struct . pack ( "H" , oO00 )
 ooOo000OoO0o = data [ 0 : 2 ] + oO00 + data [ 4 : : ]
 return ( ooOo000OoO0o )
 if 10 - 10: Ii1I
 if 77 - 77: OOooOOo / II111iiii + IiII + ooOoO0o - i11iIiiIii
 if 44 - 44: I1IiiI + OoOoOO00 + I1ii11iIi11i . I1IiiI * OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if 81 - 81: IiII / OoOoOO00 * IiII . O0
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
 if 39 - 39: OoO0O00 / OoooooooOO . OoO0O00 * I1ii11iIi11i / OoOoOO00
 if 38 - 38: OoO0O00 / ooOoO0o % I1Ii111 * I11i + i11iIiiIii % ooOoO0o
 if 61 - 61: I1Ii111 - Ii1I % I1ii11iIi11i / ooOoO0o / iII111i + iIii1I11I1II1
 if 87 - 87: I1Ii111 + ooOoO0o + O0 / i1IIi % IiII / I1Ii111
 if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if 80 - 80: OoooooooOO + IiII
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if 43 - 43: Oo0Ooo . I1Ii111
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
def lisp_udp_checksum ( source , dest , data ) :
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 i11I1 = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 iiiii111 = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 oO0oo0o00o0O = socket . htonl ( len ( data ) )
 ooo = socket . htonl ( LISP_UDP_PROTOCOL )
 I11iI1I = i11I1 . pack_address ( )
 I11iI1I += iiiii111 . pack_address ( )
 I11iI1I += struct . pack ( "II" , oO0oo0o00o0O , ooo )
 if 50 - 50: iIii1I11I1II1 * IiII . OoooooooOO / II111iiii - I1ii11iIi11i * I1ii11iIi11i
 if 98 - 98: OoO0O00 - Ii1I . IiII % i11iIiiIii
 if 69 - 69: I1ii11iIi11i + iII111i * O0 . OOooOOo % OoOoOO00
 if 96 - 96: ooOoO0o . ooOoO0o - I11i / I11i
 OoOo = binascii . hexlify ( I11iI1I + data )
 iIIi11i1i1i1I = len ( OoOo ) % 4
 for o0Ooo0O00 in range ( 0 , iIIi11i1i1i1I ) : OoOo += "0"
 if 13 - 13: iII111i + OOooOOo / iIii1I11I1II1
 if 67 - 67: OoOoOO00 - OoOoOO00 * OoO0O00 - iII111i % oO0o
 if 44 - 44: I1IiiI . i1IIi + OOooOOo
 if 16 - 16: o0oOOo0O0Ooo - OoO0O00 / I1Ii111
 oO00 = 0
 for o0Ooo0O00 in range ( 0 , len ( OoOo ) , 4 ) :
  oO00 += int ( OoOo [ o0Ooo0O00 : o0Ooo0O00 + 4 ] , 16 )
  if 48 - 48: iIii1I11I1II1
  if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
  if 26 - 26: o0oOOo0O0Ooo
  if 12 - 12: OoooooooOO / O0 + II111iiii * I1ii11iIi11i
  if 46 - 46: II111iiii - IiII * OoooooooOO / oO0o % IiII
 oO00 = ( oO00 >> 16 ) + ( oO00 & 0xffff )
 oO00 += oO00 >> 16
 oO00 = socket . htons ( ~ oO00 & 0xffff )
 if 11 - 11: iIii1I11I1II1 . OoOoOO00 / IiII % ooOoO0o
 if 61 - 61: ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 oO00 = struct . pack ( "H" , oO00 )
 OoOo = data [ 0 : 6 ] + oO00 + data [ 8 : : ]
 return ( OoOo )
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
def lisp_get_interface_address ( device ) :
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 iIIi1Ii1III = netifaces . ifaddresses ( device )
 if ( iIIi1Ii1III . has_key ( netifaces . AF_INET ) == False ) : return ( None )
 if 86 - 86: i11iIiiIii + i11iIiiIii . I1Ii111 % I1IiiI . ooOoO0o
 if 17 - 17: Ii1I
 if 67 - 67: O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 i1I111Ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 31 - 31: I1IiiI
 for O0o0O0OO0o in iIIi1Ii1III [ netifaces . AF_INET ] :
  O0o = O0o0O0OO0o [ "addr" ]
  i1I111Ii . store_address ( O0o )
  return ( i1I111Ii )
  if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 return ( None )
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
def lisp_get_input_interface ( packet ) :
 o0o0OoO0OOO0 = lisp_format_packet ( packet [ 0 : 12 ] ) . replace ( " " , "" )
 oO0OOOO0o0 = o0o0OoO0OOO0 [ 0 : 12 ]
 oOO0 = o0o0OoO0OOO0 [ 12 : : ]
 if 90 - 90: IiII - I1ii11iIi11i % I11i % iIii1I11I1II1 - I1ii11iIi11i
 try : IiIiI1i1 = lisp_mymacs . has_key ( oOO0 )
 except : IiIiI1i1 = False
 if 18 - 18: Ii1I
 if ( lisp_mymacs . has_key ( oO0OOOO0o0 ) ) : return ( lisp_mymacs [ oO0OOOO0o0 ] , oOO0 , oO0OOOO0o0 , IiIiI1i1 )
 if ( IiIiI1i1 ) : return ( lisp_mymacs [ oOO0 ] , oOO0 , oO0OOOO0o0 , IiIiI1i1 )
 return ( [ "?" ] , oOO0 , oO0OOOO0o0 , IiIiI1i1 )
 if 25 - 25: OoO0O00 * oO0o % i11iIiiIii + i11iIiiIii * OoO0O00
 if 42 - 42: II111iiii / O0 . iIii1I11I1II1 / O0 / OoO0O00 / OoooooooOO
 if 62 - 62: O0 . Oo0Ooo
 if 33 - 33: Oo0Ooo / iIii1I11I1II1 % i1IIi
 if 76 - 76: Ii1I + iIii1I11I1II1 + OoOoOO00 . OoO0O00
 if 49 - 49: IiII / ooOoO0o / OOooOOo
 if 25 - 25: I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
def lisp_get_local_interfaces ( ) :
 for o0OOOOOo0 in netifaces . interfaces ( ) :
  oooOoO = lisp_interface ( o0OOOOOo0 )
  oooOoO . add_interface ( )
  if 62 - 62: OOooOOo / II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 return
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
def lisp_get_loopback_address ( ) :
 for O0o0O0OO0o in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( O0o0O0OO0o [ "peer" ] == "127.0.0.1" ) : continue
  return ( O0o0O0OO0o [ "peer" ] )
  if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 return ( None )
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
def lisp_is_mac_string ( mac_str ) :
 iI1ii1ii1I = mac_str . split ( "/" )
 if ( len ( iI1ii1ii1I ) == 2 ) : mac_str = iI1ii1ii1I [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
 if 12 - 12: I1ii11iIi11i / Ii1I
def lisp_get_local_macs ( ) :
 for o0OOOOOo0 in netifaces . interfaces ( ) :
  if 5 - 5: OoooooooOO
  if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
  if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
  if 93 - 93: Oo0Ooo / I1ii11iIi11i + i1IIi * oO0o . OoooooooOO
  if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
  iiiii111 = o0OOOOOo0 . replace ( ":" , "" )
  iiiii111 = o0OOOOOo0 . replace ( "-" , "" )
  if ( iiiii111 . isalnum ( ) == False ) : continue
  if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
  if 33 - 33: I11i % II111iiii + OoO0O00
  if 93 - 93: i1IIi . IiII / I1IiiI + IiII
  if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
  if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
  try :
   Oooooooo00o00 = netifaces . ifaddresses ( o0OOOOOo0 )
  except :
   continue
   if 100 - 100: I1Ii111 % II111iiii . Ii1I % OoO0O00 + I1ii11iIi11i
  if ( Oooooooo00o00 . has_key ( netifaces . AF_LINK ) == False ) : continue
  iI1ii1ii1I = Oooooooo00o00 [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  iI1ii1ii1I = iI1ii1ii1I . replace ( ":" , "" )
  if 66 - 66: Ii1I - Oo0Ooo . i1IIi
  if 75 - 75: Ii1I - I11i % OoOoOO00
  if 80 - 80: Ii1I / OOooOOo
  if 21 - 21: Oo0Ooo - iIii1I11I1II1 - I1Ii111
  if 1 - 1: I1IiiI * OOooOOo + Ii1I + I1IiiI - i11iIiiIii
  if ( len ( iI1ii1ii1I ) < 12 ) : continue
  if 79 - 79: ooOoO0o . oO0o / oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
  if ( lisp_mymacs . has_key ( iI1ii1ii1I ) == False ) : lisp_mymacs [ iI1ii1ii1I ] = [ ]
  lisp_mymacs [ iI1ii1ii1I ] . append ( o0OOOOOo0 )
  if 19 - 19: I1ii11iIi11i
  if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 66 - 66: O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
 if 28 - 28: iIii1I11I1II1
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
def lisp_get_local_rloc ( ) :
 I1iI1I1ii1 = commands . getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( I1iI1I1ii1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 33 - 33: o0oOOo0O0Ooo / O0 + OOooOOo
 if 75 - 75: IiII % i11iIiiIii + iIii1I11I1II1
 if 92 - 92: OoOoOO00 % O0
 if 55 - 55: iIii1I11I1II1 * iII111i
 I1iI1I1ii1 = I1iI1I1ii1 . split ( "\n" ) [ 0 ]
 o0OOOOOo0 = I1iI1I1ii1 . split ( ) [ - 1 ]
 if 85 - 85: iIii1I11I1II1 . II111iiii
 O0o0O0OO0o = ""
 o0 = lisp_is_macos ( )
 if ( o0 ) :
  I1iI1I1ii1 = commands . getoutput ( "ifconfig {} | egrep 'inet '" . format ( o0OOOOOo0 ) )
  if ( I1iI1I1ii1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  ooo0o0 = 'ip addr show | egrep "inet " | egrep "{}"' . format ( o0OOOOOo0 )
  I1iI1I1ii1 = commands . getoutput ( ooo0o0 )
  if ( I1iI1I1ii1 == "" ) :
   ooo0o0 = 'ip addr show | egrep "inet " | egrep "global lo"'
   I1iI1I1ii1 = commands . getoutput ( ooo0o0 )
   if 84 - 84: I11i - Oo0Ooo * O0 / Ii1I . Ii1I
  if ( I1iI1I1ii1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 93 - 93: O0 / ooOoO0o + I1IiiI
  if 20 - 20: IiII / iII111i % OoooooooOO / iIii1I11I1II1 + I1IiiI
  if 57 - 57: o0oOOo0O0Ooo / I1Ii111
  if 13 - 13: OoooooooOO + OoO0O00
  if 32 - 32: O0 + oO0o % Oo0Ooo
  if 7 - 7: I1ii11iIi11i / ooOoO0o
 O0o0O0OO0o = ""
 I1iI1I1ii1 = I1iI1I1ii1 . split ( "\n" )
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 for OoO0o0OOOO in I1iI1I1ii1 :
  i11ii = OoO0o0OOOO . split ( ) [ 1 ]
  if ( o0 == False ) : i11ii = i11ii . split ( "/" ) [ 0 ]
  II1i = lisp_address ( LISP_AFI_IPV4 , i11ii , 32 , 0 )
  return ( II1i )
  if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 return ( lisp_address ( LISP_AFI_IPV4 , O0o0O0OO0o , 32 , 0 ) )
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if 64 - 64: i1IIi
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 if 25 - 25: II111iiii / OoO0O00
 if 64 - 64: O0 % ooOoO0o
 if 40 - 40: o0oOOo0O0Ooo + I11i
 if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
 if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
 if 47 - 47: OoooooooOO
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
 if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 oooo0o0OOO0 = None
 ii = 1
 iiIII1 = os . getenv ( "LISP_ADDR_SELECT" )
 if ( iiIII1 != None and iiIII1 != "" ) :
  iiIII1 = iiIII1 . split ( ":" )
  if ( len ( iiIII1 ) == 2 ) :
   oooo0o0OOO0 = iiIII1 [ 0 ]
   ii = iiIII1 [ 1 ]
  else :
   if ( iiIII1 [ 0 ] . isdigit ( ) ) :
    ii = iiIII1 [ 0 ]
   else :
    oooo0o0OOO0 = iiIII1 [ 0 ]
    if 11 - 11: Ii1I
    if 1 - 1: O0 * i11iIiiIii - ooOoO0o - Ii1I
  ii = 1 if ( ii == "" ) else int ( ii )
  if 94 - 94: OoO0O00 + IiII + ooOoO0o
  if 82 - 82: Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + IiII % iIii1I11I1II1
 O00OO = [ None , None , None ]
 oo000o = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iiIIIIiI111 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 OoooOO0Oo0 = None
 if 31 - 31: IiII - OoO0O00 / OOooOOo . i1IIi / Ii1I
 for o0OOOOOo0 in netifaces . interfaces ( ) :
  if ( oooo0o0OOO0 != None and oooo0o0OOO0 != o0OOOOOo0 ) : continue
  iIIi1Ii1III = netifaces . ifaddresses ( o0OOOOOo0 )
  if ( iIIi1Ii1III == { } ) : continue
  if 66 - 66: OoO0O00
  if 72 - 72: I1Ii111
  if 91 - 91: II111iiii / IiII + iIii1I11I1II1 . I11i - O0
  if 70 - 70: Ii1I * oO0o - I11i + Oo0Ooo % I1ii11iIi11i - IiII
  OoooOO0Oo0 = lisp_get_interface_instance_id ( o0OOOOOo0 , None )
  if 81 - 81: O0 . O0
  if 75 - 75: iIii1I11I1II1 % IiII + I1ii11iIi11i * O0 . iII111i - ooOoO0o
  if 32 - 32: Ii1I % oO0o - i1IIi
  if 40 - 40: iIii1I11I1II1 + iII111i * OoOoOO00 + oO0o
  if ( iIIi1Ii1III . has_key ( netifaces . AF_INET ) ) :
   oOo00Ooo0o0 = iIIi1Ii1III [ netifaces . AF_INET ]
   I1Ii1i11I1I = 0
   for O0o0O0OO0o in oOo00Ooo0o0 :
    oo000o . store_address ( O0o0O0OO0o [ "addr" ] )
    if ( oo000o . is_ipv4_loopback ( ) ) : continue
    if ( oo000o . is_ipv4_link_local ( ) ) : continue
    if ( oo000o . address == 0 ) : continue
    I1Ii1i11I1I += 1
    oo000o . instance_id = OoooOO0Oo0
    if ( oooo0o0OOO0 == None and
 lisp_db_for_lookups . lookup_cache ( oo000o , False ) ) : continue
    O00OO [ 0 ] = oo000o
    if ( I1Ii1i11I1I == ii ) : break
    if 71 - 71: I1IiiI * i1IIi % I11i
    if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
  if ( iIIi1Ii1III . has_key ( netifaces . AF_INET6 ) ) :
   i1IiII1i1I = iIIi1Ii1III [ netifaces . AF_INET6 ]
   I1Ii1i11I1I = 0
   for O0o0O0OO0o in i1IiII1i1I :
    O0o = O0o0O0OO0o [ "addr" ]
    iiIIIIiI111 . store_address ( O0o )
    if ( iiIIIIiI111 . is_ipv6_string_link_local ( O0o ) ) : continue
    if ( iiIIIIiI111 . is_ipv6_loopback ( ) ) : continue
    I1Ii1i11I1I += 1
    iiIIIIiI111 . instance_id = OoooOO0Oo0
    if ( oooo0o0OOO0 == None and
 lisp_db_for_lookups . lookup_cache ( iiIIIIiI111 , False ) ) : continue
    O00OO [ 1 ] = iiIIIIiI111
    if ( I1Ii1i11I1I == ii ) : break
    if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
    if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
    if 46 - 46: iIii1I11I1II1
    if 70 - 70: i1IIi . I11i
    if 74 - 74: I11i
    if 58 - 58: iIii1I11I1II1 * OoO0O00 * I1Ii111 * ooOoO0o . OoooooooOO
  if ( O00OO [ 0 ] == None ) : continue
  if 6 - 6: I1ii11iIi11i - oO0o * i11iIiiIii + OoOoOO00 / ooOoO0o % OOooOOo
  O00OO [ 2 ] = o0OOOOOo0
  break
  if 38 - 38: OOooOOo % IiII % II111iiii - Oo0Ooo - iIii1I11I1II1
  if 9 - 9: o0oOOo0O0Ooo % I1ii11iIi11i . I1ii11iIi11i
 IiIIIIii11i = O00OO [ 0 ] . print_address_no_iid ( ) if O00OO [ 0 ] else "none"
 oO0OOO00 = O00OO [ 1 ] . print_address_no_iid ( ) if O00OO [ 1 ] else "none"
 o0OOOOOo0 = O00OO [ 2 ] if O00OO [ 2 ] else "none"
 if 13 - 13: IiII * I1ii11iIi11i / I1ii11iIi11i / iIii1I11I1II1 % iIii1I11I1II1
 oooo0o0OOO0 = " (user selected)" if oooo0o0OOO0 != None else ""
 if 21 - 21: I1ii11iIi11i
 IiIIIIii11i = red ( IiIIIIii11i , False )
 oO0OOO00 = red ( oO0OOO00 , False )
 o0OOOOOo0 = bold ( o0OOOOOo0 , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( IiIIIIii11i , oO0OOO00 , o0OOOOOo0 , oooo0o0OOO0 , OoooOO0Oo0 ) )
 if 86 - 86: ooOoO0o
 if 51 - 51: OoO0O00 - i11iIiiIii * I1IiiI
 lisp_myrlocs = O00OO
 return ( ( O00OO [ 0 ] != None ) )
 if 95 - 95: OOooOOo % I1ii11iIi11i + o0oOOo0O0Ooo % ooOoO0o
 if 36 - 36: O0 / i1IIi % II111iiii / iII111i
 if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
 if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: oO0o
 if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
 if 97 - 97: I1Ii111 . I11i / I1IiiI
def lisp_get_all_addresses ( ) :
 o00OO0o0 = [ ]
 for oooOoO in netifaces . interfaces ( ) :
  try : i1II1IiiIi = netifaces . ifaddresses ( oooOoO )
  except : continue
  if 13 - 13: O0 % ooOoO0o % I11i
  if ( i1II1IiiIi . has_key ( netifaces . AF_INET ) ) :
   for O0o0O0OO0o in i1II1IiiIi [ netifaces . AF_INET ] :
    i11ii = O0o0O0OO0o [ "addr" ]
    if ( i11ii . find ( "127.0.0.1" ) != - 1 ) : continue
    o00OO0o0 . append ( i11ii )
    if 25 - 25: OoooooooOO % Ii1I * II111iiii - OoO0O00
    if 95 - 95: I1IiiI % I1Ii111 * I1IiiI + O0 . I1Ii111 % OoooooooOO
  if ( i1II1IiiIi . has_key ( netifaces . AF_INET6 ) ) :
   for O0o0O0OO0o in i1II1IiiIi [ netifaces . AF_INET6 ] :
    i11ii = O0o0O0OO0o [ "addr" ]
    if ( i11ii == "::1" ) : continue
    if ( i11ii [ 0 : 5 ] == "fe80:" ) : continue
    o00OO0o0 . append ( i11ii )
    if 6 - 6: OoOoOO00 - ooOoO0o * o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo
    if 100 - 100: OoO0O00 % I1Ii111 - I11i % I11i % I11i / ooOoO0o
    if 83 - 83: oO0o - ooOoO0o - IiII % i1IIi - iII111i . o0oOOo0O0Ooo
 return ( o00OO0o0 )
 if 96 - 96: Oo0Ooo + I1Ii111 . i1IIi
 if 54 - 54: II111iiii . i1IIi / I1ii11iIi11i % I1IiiI / I1Ii111
 if 65 - 65: OoOoOO00 . OoOoOO00 - oO0o + Oo0Ooo / i11iIiiIii
 if 90 - 90: iIii1I11I1II1 + OoOoOO00
 if 9 - 9: iIii1I11I1II1 . OoooooooOO + i1IIi - Oo0Ooo
 if 30 - 30: iII111i / OoO0O00 . iII111i
 if 17 - 17: Oo0Ooo + OoooooooOO * OoooooooOO
 if 5 - 5: I1Ii111 % OoooooooOO . OoOoOO00
def lisp_get_all_multicast_rles ( ) :
 oO00o00 = [ ]
 I1iI1I1ii1 = commands . getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( I1iI1I1ii1 == "" ) : return ( oO00o00 )
 if 51 - 51: Oo0Ooo * iIii1I11I1II1 . OoooooooOO . Ii1I - OOooOOo / I1IiiI
 OoO0ooO = I1iI1I1ii1 . split ( "\n" )
 for OoO0o0OOOO in OoO0ooO :
  if ( OoO0o0OOOO [ 0 ] == "#" ) : continue
  I1i1i111Ii1I = OoO0o0OOOO . split ( "rle-address = " ) [ 1 ]
  oo0 = int ( I1i1i111Ii1I . split ( "." ) [ 0 ] )
  if ( oo0 >= 224 and oo0 < 240 ) : oO00o00 . append ( I1i1i111Ii1I )
  if 93 - 93: O0 - OoO0O00 . I1IiiI
 return ( oO00o00 )
 if 64 - 64: OoOoOO00 + o0oOOo0O0Ooo
 if 65 - 65: II111iiii / Oo0Ooo
 if 42 - 42: i11iIiiIii . O0
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
 if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
 if 92 - 92: I11i / O0 * I1IiiI - I11i
 if 99 - 99: i11iIiiIii % OoooooooOO
class lisp_packet ( ) :
 def __init__ ( self , packet ) :
  self . outer_source = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . outer_dest = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . outer_tos = 0
  self . outer_ttl = 0
  self . udp_sport = 0
  self . udp_dport = 0
  self . udp_length = 0
  self . udp_checksum = 0
  self . inner_source = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . inner_dest = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . inner_tos = 0
  self . inner_ttl = 0
  self . inner_protocol = 0
  self . inner_sport = 0
  self . inner_dport = 0
  self . lisp_header = lisp_data_header ( )
  self . packet = packet
  self . inner_version = 0
  self . outer_version = 0
  self . encap_port = LISP_DATA_PORT
  self . inner_is_fragment = False
  self . packet_error = ""
  self . gleaned_dest = False
  if 56 - 56: IiII * I1Ii111
  if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
 def encode ( self , nonce ) :
  if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
  if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
  if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
  if 56 - 56: i1IIi . i11iIiiIii
  if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
  if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
  if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
  if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
  if 10 - 10: IiII / OoooooooOO
  if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 25 - 25: iIii1I11I1II1
  if 63 - 63: ooOoO0o
  if 96 - 96: I11i
  if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
  if 63 - 63: iII111i
  if 11 - 11: iII111i - iIii1I11I1II1
  self . lisp_header . key_id ( 0 )
  ooOo0O0 = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and ooOo0O0 == False ) :
   O0o = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 83 - 83: OoooooooOO
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( O0o ) ) :
    iIIi111IiII1i = lisp_crypto_keys_by_rloc_encap [ O0o ]
    if ( iIIi111IiII1i [ 1 ] ) :
     iIIi111IiII1i [ 1 ] . use_count += 1
     oOo0O000oo0 , II11I = self . encrypt ( iIIi111IiII1i [ 1 ] , O0o )
     if ( II11I ) : self . packet = oOo0O000oo0
     if 7 - 7: II111iiii * ooOoO0o . Oo0Ooo / I1IiiI
     if 43 - 43: Ii1I + iII111i + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
     if 54 - 54: I1ii11iIi11i + I1ii11iIi11i + I11i % i1IIi % i11iIiiIii
     if 100 - 100: I1ii11iIi11i
     if 96 - 96: I1IiiI . IiII * II111iiii % IiII . I1Ii111 * i1IIi
     if 83 - 83: iIii1I11I1II1
     if 97 - 97: i11iIiiIii + Oo0Ooo * OOooOOo % iII111i . IiII
     if 4 - 4: O0 . iII111i - iIii1I11I1II1
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 89 - 89: Ii1I
  else :
   self . udp_sport = LISP_DATA_PORT
   if 51 - 51: iII111i
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
  if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
  if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
  if ( self . outer_version == 4 ) :
   O0oo0oOo = socket . htons ( self . udp_sport )
   i111iI1i1iI = socket . htons ( self . udp_dport )
  else :
   O0oo0oOo = self . udp_sport
   i111iI1i1iI = self . udp_dport
   if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
   if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  i111iI1i1iI = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 79 - 79: IiII + IiII + Ii1I
  if 39 - 39: O0 - OoooooooOO
  OoOo = struct . pack ( "HHHH" , O0oo0oOo , i111iI1i1iI , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  if 79 - 79: O0
  if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
  if 15 - 15: I1ii11iIi11i
  I11iI1 = self . lisp_header . encode ( )
  if 96 - 96: o0oOOo0O0Ooo % IiII / OOooOOo
  if 63 - 63: i1IIi % i11iIiiIii % II111iiii * OoooooooOO
  if 40 - 40: Oo0Ooo
  if 47 - 47: OoOoOO00
  if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
  if ( self . outer_version == 4 ) :
   oooOO = socket . htons ( self . udp_length + 20 )
   iI1IIIi11 = socket . htons ( 0x4000 )
   oooOo00O0 = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , oooOO , 0xdfdf ,
 iI1IIIi11 , self . outer_ttl , 17 , 0 )
   oooOo00O0 += self . outer_source . pack_address ( )
   oooOo00O0 += self . outer_dest . pack_address ( )
   oooOo00O0 = lisp_ip_checksum ( oooOo00O0 )
  elif ( self . outer_version == 6 ) :
   oooOo00O0 = ""
   if 26 - 26: I1Ii111 . Ii1I + I1IiiI . OoOoOO00 + OOooOOo
   if 17 - 17: OOooOOo + i11iIiiIii + I1ii11iIi11i % OOooOOo . oO0o
   if 33 - 33: I11i * I1IiiI % OoOoOO00 . IiII . ooOoO0o . OoO0O00
   if 53 - 53: OoOoOO00
   if 84 - 84: OoO0O00
   if 97 - 97: i1IIi
   if 98 - 98: OoooooooOO - I1IiiI + ooOoO0o
  else :
   return ( None )
   if 98 - 98: iII111i . IiII . IiII - OOooOOo
   if 65 - 65: Oo0Ooo + o0oOOo0O0Ooo - Ii1I
  self . packet = oooOo00O0 + OoOo + I11iI1 + self . packet
  return ( self )
  if 12 - 12: OoooooooOO + I1ii11iIi11i
  if 55 - 55: OOooOOo * II111iiii + oO0o
 def cipher_pad ( self , packet ) :
  O0oOOOO00oOOo = len ( packet )
  if ( ( O0oOOOO00oOOo % 16 ) != 0 ) :
   iIIi = ( ( O0oOOOO00oOOo / 16 ) + 1 ) * 16
   packet = packet . ljust ( iIIi )
   if 47 - 47: ooOoO0o
  return ( packet )
  if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
  if 23 - 23: II111iiii * iII111i
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
   if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
   if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
   if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
   if 21 - 21: OoO0O00
  oOo0O000oo0 = self . cipher_pad ( self . packet )
  O0o0oOOO = key . get_iv ( )
  if 24 - 24: o0oOOo0O0Ooo / Ii1I / Ii1I % II111iiii - oO0o * oO0o
  I11i1II = lisp_get_timestamp ( )
  oOoo0oO = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   IIii1i = chacha . ChaCha ( key . encrypt_key , O0o0oOOO ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o00oo = binascii . unhexlify ( key . encrypt_key )
   try :
    Ii11IIIi1 = AES . new ( o00oo , AES . MODE_GCM , O0o0oOOO )
    IIii1i = Ii11IIIi1 . encrypt
    oOoo0oO = Ii11IIIi1 . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 93 - 93: i11iIiiIii . o0oOOo0O0Ooo
  else :
   o00oo = binascii . unhexlify ( key . encrypt_key )
   IIii1i = AES . new ( o00oo , AES . MODE_CBC , O0o0oOOO ) . encrypt
   if 16 - 16: i1IIi . i1IIi / I1Ii111 % OoOoOO00 / I1IiiI * I1ii11iIi11i
   if 30 - 30: o0oOOo0O0Ooo + OoooooooOO + OOooOOo / II111iiii * Oo0Ooo
  O00O0 = IIii1i ( oOo0O000oo0 )
  if 43 - 43: oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
  if ( O00O0 == None ) : return ( [ self . packet , False ] )
  I11i1II = int ( str ( time . time ( ) - I11i1II ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
  if 18 - 18: Oo0Ooo % O0
  if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
  if 86 - 86: IiII
  if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
  if ( oOoo0oO != None ) : O00O0 += oOoo0oO ( )
  if 33 - 33: II111iiii - IiII - ooOoO0o
  if 92 - 92: OoO0O00 * IiII
  if 92 - 92: oO0o
  if 7 - 7: iII111i
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  self . lisp_header . key_id ( key . key_id )
  I11iI1 = self . lisp_header . encode ( )
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  oo = key . do_icv ( I11iI1 + O0o0oOOO + O00O0 , O0o0oOOO )
  if 11 - 11: OoO0O00 % OoooooooOO
  I1111i = 4 if ( key . do_poly ) else 8
  if 79 - 79: I1Ii111
  i1iiiIi11 = bold ( "Encrypt" , False )
  OOoOOO = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  oooooO0O0o = "poly" if key . do_poly else "sha256"
  oooooO0O0o = bold ( oooooO0O0o , False )
  Ii = "ICV({}): 0x{}...{}" . format ( oooooO0O0o , oo [ 0 : I1111i ] , oo [ - I1111i : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( i1iiiIi11 , key . key_id , addr_str , Ii , OOoOOO , I11i1II ) )
  if 22 - 22: iIii1I11I1II1 / I1ii11iIi11i / IiII - I1IiiI % OoOoOO00
  if 16 - 16: i1IIi * ooOoO0o + o0oOOo0O0Ooo * Ii1I
  oo = int ( oo , 16 )
  if ( key . do_poly ) :
   ii1 = byte_swap_64 ( ( oo >> 64 ) & LISP_8_64_MASK )
   o0o0ooOOo0oO = byte_swap_64 ( oo & LISP_8_64_MASK )
   oo = struct . pack ( "QQ" , ii1 , o0o0ooOOo0oO )
  else :
   ii1 = byte_swap_64 ( ( oo >> 96 ) & LISP_8_64_MASK )
   o0o0ooOOo0oO = byte_swap_64 ( ( oo >> 32 ) & LISP_8_64_MASK )
   IiiiI1Ii = socket . htonl ( oo & 0xffffffff )
   oo = struct . pack ( "QQI" , ii1 , o0o0ooOOo0oO , IiiiI1Ii )
   if 41 - 41: OoOoOO00 - OOooOOo + ooOoO0o - i1IIi
   if 6 - 6: II111iiii
  return ( [ O0o0oOOO + O00O0 + oo , True ] )
  if 7 - 7: i1IIi
  if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
  if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
  if 59 - 59: iIii1I11I1II1 / I1ii11iIi11i % ooOoO0o
  if 84 - 84: iIii1I11I1II1 / I1IiiI . OoOoOO00 % I11i
  if 99 - 99: Oo0Ooo + i11iIiiIii
  if 36 - 36: Ii1I * I1Ii111 * iIii1I11I1II1 - I11i % i11iIiiIii
  if ( key . do_poly ) :
   ii1 , o0o0ooOOo0oO = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   OoOo00O0o = byte_swap_64 ( ii1 ) << 64
   OoOo00O0o |= byte_swap_64 ( o0o0ooOOo0oO )
   OoOo00O0o = lisp_hex_string ( OoOo00O0o ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   I1111i = 4
   O000O0Oo00OO0 = bold ( "poly" , False )
  else :
   ii1 , o0o0ooOOo0oO , IiiiI1Ii = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   OoOo00O0o = byte_swap_64 ( ii1 ) << 96
   OoOo00O0o |= byte_swap_64 ( o0o0ooOOo0oO ) << 32
   OoOo00O0o |= socket . htonl ( IiiiI1Ii )
   OoOo00O0o = lisp_hex_string ( OoOo00O0o ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   I1111i = 8
   O000O0Oo00OO0 = bold ( "sha" , False )
   if 31 - 31: o0oOOo0O0Ooo
  I11iI1 = self . lisp_header . encode ( )
  if 35 - 35: OoOoOO00 + Ii1I * ooOoO0o / OoOoOO00
  if 69 - 69: ooOoO0o . OOooOOo - I1IiiI
  if 29 - 29: i11iIiiIii . I1ii11iIi11i / I1IiiI . OOooOOo + i11iIiiIii
  if 26 - 26: IiII / Ii1I - OoooooooOO
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   iiIiiII1II1ii = 8
   OOoOOO = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   iiIiiII1II1ii = 12
   OOoOOO = bold ( "aes-gcm" , False )
  else :
   iiIiiII1II1ii = 16
   OOoOOO = bold ( "aes-cbc" , False )
   if 31 - 31: OOooOOo - I1IiiI
  O0o0oOOO = packet [ 0 : iiIiiII1II1ii ]
  if 58 - 58: iIii1I11I1II1 / I1IiiI - I1ii11iIi11i . o0oOOo0O0Ooo - Oo0Ooo
  if 88 - 88: OoO0O00 . I1Ii111 / I11i
  if 47 - 47: OoO0O00 + I1ii11iIi11i . ooOoO0o
  if 43 - 43: I1IiiI - o0oOOo0O0Ooo / o0oOOo0O0Ooo . II111iiii - Ii1I
  i1 = key . do_icv ( I11iI1 + packet , O0o0oOOO )
  if 88 - 88: O0 . oO0o % I1IiiI
  iii111i = "0x{}...{}" . format ( OoOo00O0o [ 0 : I1111i ] , OoOo00O0o [ - I1111i : : ] )
  iIi11ii1iI = "0x{}...{}" . format ( i1 [ 0 : I1111i ] , i1 [ - I1111i : : ] )
  if 69 - 69: i11iIiiIii
  if ( i1 != OoOo00O0o ) :
   self . packet_error = "ICV-error"
   ooO = OOoOOO + "/" + O000O0Oo00OO0
   ooI1I111IIIi1 = bold ( "ICV failed ({})" . format ( ooO ) , False )
   Ii = "packet-ICV {} != computed-ICV {}" . format ( iii111i , iIi11ii1iI )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( ooI1I111IIIi1 , red ( addr_str , False ) ,
   # I11i / OoOoOO00 - OOooOOo / ooOoO0o
 self . udp_sport , key . key_id , Ii ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 50 - 50: OOooOOo + OoO0O00 . i11iIiiIii + I1ii11iIi11i + i11iIiiIii
   if 31 - 31: oO0o * I1Ii111 . OoOoOO00 * I11i
   if 28 - 28: IiII + I1IiiI - Oo0Ooo % OOooOOo . I11i + I1IiiI
   if 72 - 72: Ii1I / Oo0Ooo / oO0o * OoOoOO00 + OOooOOo
   if 58 - 58: o0oOOo0O0Ooo % I1IiiI . I1IiiI * OoO0O00 - IiII . OoooooooOO
   if 10 - 10: I1Ii111
   lisp_retry_decap_keys ( addr_str , I11iI1 + packet , O0o0oOOO , OoOo00O0o )
   return ( [ None , False ] )
   if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
   if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
   if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
   if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
   if 55 - 55: OoooooooOO
  packet = packet [ iiIiiII1II1ii : : ]
  if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
  if 38 - 38: O0
  if 79 - 79: i1IIi . oO0o
  if 34 - 34: I1Ii111 * II111iiii
  I11i1II = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   o0oO00OOo0oO = chacha . ChaCha ( key . encrypt_key , O0o0oOOO ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o00oo = binascii . unhexlify ( key . encrypt_key )
   try :
    o0oO00OOo0oO = AES . new ( o00oo , AES . MODE_GCM , O0o0oOOO ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 92 - 92: I1IiiI . II111iiii
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
   o00oo = binascii . unhexlify ( key . encrypt_key )
   o0oO00OOo0oO = AES . new ( o00oo , AES . MODE_CBC , O0o0oOOO ) . decrypt
   if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
   if 28 - 28: i11iIiiIii
  Oo00oo0 = o0oO00OOo0oO ( packet )
  I11i1II = int ( str ( time . time ( ) - I11i1II ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 82 - 82: OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
  if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
  if 20 - 20: i1IIi . i1IIi - I11i
  if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
  i1iiiIi11 = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  oooooO0O0o = "poly" if key . do_poly else "sha256"
  oooooO0O0o = bold ( oooooO0O0o , False )
  Ii = "ICV({}): {}" . format ( oooooO0O0o , iii111i )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( i1iiiIi11 , key . key_id , addr_str , Ii , OOoOOO , I11i1II ) )
  if 35 - 35: II111iiii / OoOoOO00 - O0 . II111iiii
  if 55 - 55: Oo0Ooo % i1IIi * I11i
  if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
  if 63 - 63: iIii1I11I1II1 / ooOoO0o
  if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
  if 50 - 50: II111iiii
  if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
  self . packet = self . packet [ 0 : header_length ]
  return ( [ Oo00oo0 , True ] )
  if 44 - 44: I1IiiI
  if 55 - 55: oO0o . I1Ii111 * I1Ii111
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  OO0OO00ooO0 = 1000
  if 68 - 68: OoOoOO00 * I1ii11iIi11i - OoooooooOO - I11i + iIii1I11I1II1 * i11iIiiIii
  if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
  if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
  if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
  if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
  oo0oo00O0O = [ ]
  O00O00O000OOO = 0
  O0oOOOO00oOOo = len ( inner_packet )
  while ( O00O00O000OOO < O0oOOOO00oOOo ) :
   iI1IIIi11 = inner_packet [ O00O00O000OOO : : ]
   if ( len ( iI1IIIi11 ) > OO0OO00ooO0 ) : iI1IIIi11 = iI1IIIi11 [ 0 : OO0OO00ooO0 ]
   oo0oo00O0O . append ( iI1IIIi11 )
   O00O00O000OOO += len ( iI1IIIi11 )
   if 35 - 35: OoO0O00
   if 52 - 52: Oo0Ooo / iII111i
   if 42 - 42: iIii1I11I1II1 * Ii1I / OoO0O00 + OOooOOo
   if 48 - 48: OoooooooOO - I1Ii111 . i11iIiiIii * iII111i - Ii1I - o0oOOo0O0Ooo
   if 59 - 59: iII111i / I11i . Oo0Ooo
   if 100 - 100: O0
  oOOO00Oo = [ ]
  O00O00O000OOO = 0
  for iI1IIIi11 in oo0oo00O0O :
   if 48 - 48: II111iiii + II111iiii * i1IIi / Ii1I
   if 37 - 37: iIii1I11I1II1 % I11i / IiII
   if 37 - 37: I1Ii111 - oO0o - OoO0O00
   if 42 - 42: iIii1I11I1II1 % Ii1I - I1ii11iIi11i + iIii1I11I1II1
   iiI1I = O00O00O000OOO if ( iI1IIIi11 == oo0oo00O0O [ - 1 ] ) else 0x2000 + O00O00O000OOO
   iiI1I = socket . htons ( iiI1I )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , iiI1I ) + outer_hdr [ 8 : : ]
   if 64 - 64: IiII * iIii1I11I1II1 . I1ii11iIi11i / I11i * iIii1I11I1II1
   if 4 - 4: ooOoO0o % IiII . I1Ii111
   if 91 - 91: I1ii11iIi11i + iIii1I11I1II1 % IiII
   if 90 - 90: ooOoO0o - I11i . OoO0O00 + OoO0O00
   IIii1 = socket . htons ( len ( iI1IIIi11 ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , IIii1 ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   oOOO00Oo . append ( outer_hdr + iI1IIIi11 )
   O00O00O000OOO += len ( iI1IIIi11 ) / 8
   if 92 - 92: IiII . Oo0Ooo - Oo0Ooo - o0oOOo0O0Ooo + I1Ii111 - O0
  return ( oOOO00Oo )
  if 30 - 30: IiII - iII111i - OoO0O00
  if 33 - 33: iIii1I11I1II1 / iII111i
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 74 - 74: o0oOOo0O0Ooo / oO0o - II111iiii . II111iiii . IiII + II111iiii
  OOo0 = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( OOo0 < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
   return ( False )
   if 80 - 80: iII111i
   if 3 - 3: I1ii11iIi11i * I11i
   if 53 - 53: iIii1I11I1II1 / iII111i % OoO0O00 + IiII / ooOoO0o
   if 74 - 74: Oo0Ooo
   if 8 - 8: I1IiiI % II111iiii - o0oOOo0O0Ooo - I11i % I1IiiI
   if 93 - 93: Ii1I * iII111i / OOooOOo
   if 88 - 88: oO0o
   if 1 - 1: Oo0Ooo
   if 95 - 95: OoooooooOO / I11i % OoooooooOO / ooOoO0o * IiII
   if 75 - 75: O0
   if 56 - 56: OoO0O00 / II111iiii
   if 39 - 39: OoOoOO00 - OoooooooOO - i1IIi / II111iiii
   if 49 - 49: Oo0Ooo + O0 + IiII . II111iiii % ooOoO0o
   if 33 - 33: OoOoOO00 . iIii1I11I1II1 / I11i % Ii1I
   if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
  iII1i1 = socket . htons ( 1400 )
  ooOo000OoO0o = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , iII1i1 )
  ooOo000OoO0o += inner_packet [ 0 : 20 + 8 ]
  ooOo000OoO0o = lisp_icmp_checksum ( ooOo000OoO0o )
  if 34 - 34: OoO0O00 / OoooooooOO - oO0o / oO0o * I1IiiI
  if 61 - 61: I11i
  if 81 - 81: I11i
  if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
  if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
  if 31 - 31: i1IIi % II111iiii
  if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
  Ii11iIiiI = inner_packet [ 12 : 16 ]
  iiII = self . inner_source . print_address_no_iid ( )
  iII1IiiIIIIii = self . outer_source . pack_address ( )
  if 98 - 98: Oo0Ooo / oO0o - I1IiiI
  if 81 - 81: OoooooooOO . OoOoOO00 * iIii1I11I1II1 / OoOoOO00 - I1ii11iIi11i % i1IIi
  if 77 - 77: I1IiiI / OoooooooOO
  if 33 - 33: i11iIiiIii + Ii1I % o0oOOo0O0Ooo % I1IiiI
  if 66 - 66: o0oOOo0O0Ooo % IiII
  if 100 - 100: iIii1I11I1II1
  if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
  if 98 - 98: OoO0O00
  oooOO = socket . htons ( 20 + 36 )
  IiiIIi1 = struct . pack ( "BBHHHBBH" , 0x45 , 0 , oooOO , 0 , 0 , 32 , 1 , 0 ) + iII1IiiIIIIii + Ii11iIiiI
  IiiIIi1 = lisp_ip_checksum ( IiiIIi1 )
  IiiIIi1 = self . fix_outer_header ( IiiIIi1 )
  IiiIIi1 += ooOo000OoO0o
  I1IIiIi = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( I1IIiIi , iiII ,
 lisp_format_packet ( IiiIIi1 ) ) )
  if 93 - 93: oO0o - OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  try :
   lisp_icmp_raw_socket . sendto ( IiiIIi1 , ( iiII , 0 ) )
  except socket . error , IIIII1iii11 :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( IIIII1iii11 ) )
   return ( False )
   if 52 - 52: I1Ii111 + I1Ii111
   if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
   if 54 - 54: OoOoOO00 . OoooooooOO
   if 36 - 36: oO0o / II111iiii * IiII % I1ii11iIi11i
   if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
   if 28 - 28: Ii1I . I1ii11iIi11i
  lisp_last_icmp_too_big_sent = lisp_get_timestamp ( )
  return ( True )
  if 77 - 77: I1ii11iIi11i % II111iiii
 def fragment ( self ) :
  global lisp_icmp_raw_socket
  global lisp_ignore_df_bit
  if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
  oOo0O000oo0 = self . fix_outer_header ( self . packet )
  if 90 - 90: o0oOOo0O0Ooo
  if 44 - 44: o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo + OoOoOO00
  if 32 - 32: IiII - ooOoO0o * iII111i * I11i
  if 84 - 84: Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
  if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
  if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
  O0oOOOO00oOOo = len ( oOo0O000oo0 )
  if ( O0oOOOO00oOOo <= 1500 ) : return ( [ oOo0O000oo0 ] , "Fragment-None" )
  if 1 - 1: Oo0Ooo . II111iiii
  oOo0O000oo0 = self . packet
  if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
  if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
  if 4 - 4: IiII
  if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
  if 99 - 99: i11iIiiIii - iII111i
  if ( self . inner_version != 4 ) :
   o0O0O0O00o = random . randint ( 0 , 0xffff )
   OoOooOo00o = oOo0O000oo0 [ 0 : 4 ] + struct . pack ( "H" , o0O0O0O00o ) + oOo0O000oo0 [ 6 : 20 ]
   iI1IIi = oOo0O000oo0 [ 20 : : ]
   oOOO00Oo = self . fragment_outer ( OoOooOo00o , iI1IIi )
   return ( oOOO00Oo , "Fragment-Outer" )
   if 10 - 10: I1ii11iIi11i / Ii1I * i1IIi % O0 + I11i
   if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
   if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
   if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
   if 80 - 80: Ii1I
  iioOO = 56 if ( self . outer_version == 6 ) else 36
  OoOooOo00o = oOo0O000oo0 [ 0 : iioOO ]
  I1 = oOo0O000oo0 [ iioOO : iioOO + 20 ]
  iI1IIi = oOo0O000oo0 [ iioOO + 20 : : ]
  if 63 - 63: OoO0O00 . oO0o + I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
  if 46 - 46: i11iIiiIii
  Iiiii = struct . unpack ( "H" , I1 [ 6 : 8 ] ) [ 0 ]
  Iiiii = socket . ntohs ( Iiiii )
  if ( Iiiii & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    IIIII1111111 = oOo0O000oo0 [ iioOO : : ]
    if ( self . send_icmp_too_big ( IIIII1111111 ) ) : return ( [ ] , None )
    if 10 - 10: Ii1I
   if ( lisp_ignore_df_bit ) :
    Iiiii &= ~ 0x4000
   else :
    I11IIiI1IiI1 = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( I11IIiI1IiI1 ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 37 - 37: oO0o % I1Ii111 % oO0o
    if 14 - 14: OoO0O00 / I1IiiI
    if 66 - 66: Oo0Ooo / i11iIiiIii % ooOoO0o
  O00O00O000OOO = 0
  O0oOOOO00oOOo = len ( iI1IIi )
  oOOO00Oo = [ ]
  while ( O00O00O000OOO < O0oOOOO00oOOo ) :
   oOOO00Oo . append ( iI1IIi [ O00O00O000OOO : O00O00O000OOO + 1400 ] )
   O00O00O000OOO += 1400
   if 43 - 43: OOooOOo
   if 84 - 84: OOooOOo . IiII . iII111i
   if 2 - 2: Oo0Ooo - OoOoOO00
   if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
   if 54 - 54: ooOoO0o % Oo0Ooo - OOooOOo
  oo0oo00O0O = oOOO00Oo
  oOOO00Oo = [ ]
  iIi11IiiiII11 = True if Iiiii & 0x2000 else False
  Iiiii = ( Iiiii & 0x1fff ) * 8
  for iI1IIIi11 in oo0oo00O0O :
   if 26 - 26: iII111i / OoooooooOO - Oo0Ooo
   if 2 - 2: I1ii11iIi11i - Oo0Ooo
   if 4 - 4: O0 / I11i . OoO0O00 - ooOoO0o / OOooOOo
   if 25 - 25: I11i * OoOoOO00 - Oo0Ooo . ooOoO0o . oO0o
   oo00Oo0oO00Oo = Iiiii / 8
   if ( iIi11IiiiII11 ) :
    oo00Oo0oO00Oo |= 0x2000
   elif ( iI1IIIi11 != oo0oo00O0O [ - 1 ] ) :
    oo00Oo0oO00Oo |= 0x2000
    if 20 - 20: o0oOOo0O0Ooo / IiII
   oo00Oo0oO00Oo = socket . htons ( oo00Oo0oO00Oo )
   I1 = I1 [ 0 : 6 ] + struct . pack ( "H" , oo00Oo0oO00Oo ) + I1 [ 8 : : ]
   if 25 - 25: OoOoOO00 + OoO0O00 % Ii1I % OOooOOo / oO0o
   if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
   if 23 - 23: I1IiiI
   if 7 - 7: iII111i % I1ii11iIi11i
   if 64 - 64: I1Ii111 + i11iIiiIii
   if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
   O0oOOOO00oOOo = len ( iI1IIIi11 )
   Iiiii += O0oOOOO00oOOo
   IIii1 = socket . htons ( O0oOOOO00oOOo + 20 )
   I1 = I1 [ 0 : 2 ] + struct . pack ( "H" , IIii1 ) + I1 [ 4 : 10 ] + struct . pack ( "H" , 0 ) + I1 [ 12 : : ]
   if 68 - 68: IiII . ooOoO0o
   I1 = lisp_ip_checksum ( I1 )
   Oo0OooooOO0o0OO = I1 + iI1IIIi11
   if 24 - 24: oO0o . O0 * ooOoO0o / OoooooooOO - Ii1I . I11i
   if 41 - 41: OoO0O00 % I1IiiI - Oo0Ooo
   if 11 - 11: Ii1I * o0oOOo0O0Ooo / IiII + OoOoOO00 + OoO0O00 % I1Ii111
   if 18 - 18: I1IiiI - OoOoOO00
   if 18 - 18: OOooOOo + OoO0O00 * oO0o - oO0o . I1ii11iIi11i * I11i
   O0oOOOO00oOOo = len ( Oo0OooooOO0o0OO )
   if ( self . outer_version == 4 ) :
    IIii1 = O0oOOOO00oOOo + iioOO
    O0oOOOO00oOOo += 16
    OoOooOo00o = OoOooOo00o [ 0 : 2 ] + struct . pack ( "H" , IIii1 ) + OoOooOo00o [ 4 : : ]
    if 95 - 95: I1ii11iIi11i / OoOoOO00
    OoOooOo00o = lisp_ip_checksum ( OoOooOo00o )
    Oo0OooooOO0o0OO = OoOooOo00o + Oo0OooooOO0o0OO
    Oo0OooooOO0o0OO = self . fix_outer_header ( Oo0OooooOO0o0OO )
    if 10 - 10: IiII % I1ii11iIi11i - IiII
    if 86 - 86: Oo0Ooo
    if 88 - 88: I1Ii111 * I1IiiI
    if 30 - 30: OoOoOO00 / oO0o / Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
    if 93 - 93: OoOoOO00
   o0OoOo0o0OOoO0 = iioOO - 12
   IIii1 = socket . htons ( O0oOOOO00oOOo )
   Oo0OooooOO0o0OO = Oo0OooooOO0o0OO [ 0 : o0OoOo0o0OOoO0 ] + struct . pack ( "H" , IIii1 ) + Oo0OooooOO0o0OO [ o0OoOo0o0OOoO0 + 2 : : ]
   if 30 - 30: Ii1I % I11i + o0oOOo0O0Ooo
   oOOO00Oo . append ( Oo0OooooOO0o0OO )
   if 65 - 65: iIii1I11I1II1 . iII111i / Ii1I
  return ( oOOO00Oo , "Fragment-Inner" )
  if 12 - 12: I1IiiI + I1Ii111
  if 80 - 80: oO0o . O0
 def fix_outer_header ( self , packet ) :
  if 90 - 90: II111iiii / OoO0O00 / Ii1I
  if 70 - 70: Ii1I - II111iiii . Oo0Ooo / Oo0Ooo
  if 30 - 30: oO0o . OoO0O00 + I11i / iIii1I11I1II1 % Oo0Ooo / oO0o
  if 3 - 3: I1ii11iIi11i / II111iiii
  if 73 - 73: OoO0O00 * OoooooooOO - OoooooooOO + I1IiiI * Oo0Ooo
  if 87 - 87: o0oOOo0O0Ooo / IiII / i11iIiiIii
  if 95 - 95: i1IIi / Ii1I / Ii1I
  if 65 - 65: I1Ii111 + iII111i * iII111i
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 79 - 79: i1IIi / Oo0Ooo - I1IiiI . O0
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 56 - 56: IiII % O0 * i1IIi - II111iiii
    if 74 - 74: i1IIi - OoOoOO00 % oO0o . O0 - OoooooooOO
  return ( packet )
  if 84 - 84: I1Ii111
  if 53 - 53: i1IIi
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
  dest = dest . print_address_no_iid ( )
  oOOO00Oo , iiIII1i1 = self . fragment ( )
  if 78 - 78: oO0o % OoOoOO00
  for Oo0OooooOO0o0OO in oOOO00Oo :
   if ( len ( oOOO00Oo ) != 1 ) :
    self . packet = Oo0OooooOO0o0OO
    self . print_packet ( iiIII1i1 , True )
    if 1 - 1: OoOoOO00 - o0oOOo0O0Ooo / ooOoO0o - IiII / i1IIi
    if 28 - 28: OoO0O00 / I1Ii111 * I1IiiI + ooOoO0o
   try : lisp_raw_socket . sendto ( Oo0OooooOO0o0OO , ( dest , 0 ) )
   except socket . error , IIIII1iii11 :
    lprint ( "socket.sendto() failed: {}" . format ( IIIII1iii11 ) )
    if 48 - 48: O0
    if 44 - 44: OoO0O00 * oO0o
    if 54 - 54: Ii1I % i1IIi
    if 51 - 51: iIii1I11I1II1 - I1IiiI
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 61 - 61: OoooooooOO . Ii1I % oO0o * OoooooooOO
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 96 - 96: Ii1I - II111iiii % OoOoOO00 * I1IiiI * I1IiiI . Oo0Ooo
   if 75 - 75: Oo0Ooo + Ii1I + OoO0O00
  oOo0O000oo0 = mac_header + self . packet
  if 97 - 97: ooOoO0o % i11iIiiIii % I11i
  if 21 - 21: Oo0Ooo / Ii1I / I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
  if 86 - 86: i1IIi
  if 33 - 33: OoOoOO00 % i11iIiiIii * OOooOOo
  if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
  if 75 - 75: OoO0O00 % OoooooooOO
  if 16 - 16: O0 / i1IIi
  if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
  if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
  if 12 - 12: OoOoOO00 + o0oOOo0O0Ooo . I1Ii111
  if 52 - 52: OoO0O00
  l2_socket . write ( oOo0O000oo0 )
  return
  if 4 - 4: Ii1I % I1ii11iIi11i + I11i - I1ii11iIi11i
  if 98 - 98: Ii1I - O0 * oO0o * Ii1I * Ii1I
 def bridge_l2_packet ( self , eid , db ) :
  try : i11IiII = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : oooOoO = lisp_myinterfaces [ i11IiII . interface ]
  except : return
  try :
   socket = oooOoO . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 53 - 53: OoO0O00 % I1ii11iIi11i . iII111i . i1IIi . OoO0O00
  try : socket . send ( self . packet )
  except socket . error , IIIII1iii11 :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( IIIII1iii11 ) )
   if 26 - 26: I1IiiI % OoOoOO00
   if 67 - 67: Oo0Ooo - IiII * Ii1I . OoooooooOO / i11iIiiIii
   if 61 - 61: o0oOOo0O0Ooo % I1IiiI * i1IIi / I1IiiI / II111iiii + I1Ii111
 def is_lisp_packet ( self , packet ) :
  OoOo = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( OoOo == False ) : return ( False )
  if 22 - 22: IiII . iII111i + Oo0Ooo
  IIIIiI1ii1 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( IIIIiI1ii1 ) == LISP_DATA_PORT ) : return ( True )
  IIIIiI1ii1 = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( IIIIiI1ii1 ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 73 - 73: Ii1I
  if 13 - 13: I11i - OoooooooOO / ooOoO0o
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  oOo0O000oo0 = self . packet
  ooOo0 = len ( oOo0O000oo0 )
  I11I1i = oOO0oOooo = True
  if 57 - 57: OoooooooOO
  if 70 - 70: iII111i . OOooOOo * OoO0O00 + OoooooooOO . I1Ii111
  if 97 - 97: OoooooooOO % iIii1I11I1II1 * OoOoOO00 . oO0o / I1Ii111
  if 27 - 27: I1IiiI % IiII
  IiIIIii1i1iI = 0
  o0ooOo00O = 0
  if ( is_lisp_packet ) :
   o0ooOo00O = self . lisp_header . get_instance_id ( )
   OoOOoO0o = struct . unpack ( "B" , oOo0O000oo0 [ 0 : 1 ] ) [ 0 ]
   self . outer_version = OoOOoO0o >> 4
   if ( self . outer_version == 4 ) :
    if 66 - 66: I11i - I11i + IiII
    if 20 - 20: I1Ii111 . i1IIi
    if 9 - 9: OoO0O00
    if 89 - 89: i1IIi
    if 19 - 19: ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
    iI1i1Iiii = struct . unpack ( "H" , oOo0O000oo0 [ 10 : 12 ] ) [ 0 ]
    oOo0O000oo0 = lisp_ip_checksum ( oOo0O000oo0 )
    oO00 = struct . unpack ( "H" , oOo0O000oo0 [ 10 : 12 ] ) [ 0 ]
    if ( oO00 != 0 ) :
     if ( iI1i1Iiii != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( ooOo0 )
       if 15 - 15: Ii1I
       if 17 - 17: OoOoOO00 - I1IiiI
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 63 - 63: OoOoOO00 - oO0o / iIii1I11I1II1 - Ii1I / I1Ii111
      if 34 - 34: iII111i / o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
      if 97 - 97: i1IIi
    ii1iI1i1 = LISP_AFI_IPV4
    O00O00O000OOO = 12
    self . outer_tos = struct . unpack ( "B" , oOo0O000oo0 [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , oOo0O000oo0 [ 8 : 9 ] ) [ 0 ]
    IiIIIii1i1iI = 20
   elif ( self . outer_version == 6 ) :
    ii1iI1i1 = LISP_AFI_IPV6
    O00O00O000OOO = 8
    o0o0oo0OOo0O0 = struct . unpack ( "H" , oOo0O000oo0 [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( o0o0oo0OOo0O0 ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , oOo0O000oo0 [ 7 : 8 ] ) [ 0 ]
    IiIIIii1i1iI = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( ooOo0 )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 37 - 37: o0oOOo0O0Ooo * Oo0Ooo
    if 11 - 11: oO0o
   self . outer_source . afi = ii1iI1i1
   self . outer_dest . afi = ii1iI1i1
   Oo0O0o00o00 = self . outer_source . addr_length ( )
   if 90 - 90: I1Ii111 . II111iiii . I1ii11iIi11i
   self . outer_source . unpack_address ( oOo0O000oo0 [ O00O00O000OOO : O00O00O000OOO + Oo0O0o00o00 ] )
   O00O00O000OOO += Oo0O0o00o00
   self . outer_dest . unpack_address ( oOo0O000oo0 [ O00O00O000OOO : O00O00O000OOO + Oo0O0o00o00 ] )
   oOo0O000oo0 = oOo0O000oo0 [ IiIIIii1i1iI : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 32 - 32: ooOoO0o - OoO0O00 . iII111i . iII111i % i1IIi * Ii1I
   if 65 - 65: iII111i / ooOoO0o . II111iiii
   if 90 - 90: I11i
   if 95 - 95: OoO0O00
   Oo = struct . unpack ( "H" , oOo0O000oo0 [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( Oo )
   Oo = struct . unpack ( "H" , oOo0O000oo0 [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( Oo )
   Oo = struct . unpack ( "H" , oOo0O000oo0 [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( Oo )
   Oo = struct . unpack ( "H" , oOo0O000oo0 [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( Oo )
   oOo0O000oo0 = oOo0O000oo0 [ 8 : : ]
   if 32 - 32: oO0o
   if 48 - 48: iIii1I11I1II1 / OoOoOO00 % ooOoO0o . I1Ii111
   if 35 - 35: Oo0Ooo * IiII
   if 12 - 12: IiII - Ii1I % Ii1I
   I11I1i = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   oOO0oOooo = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 23 - 23: ooOoO0o
   if 61 - 61: IiII + iII111i - OoO0O00 * oO0o
   if 87 - 87: II111iiii % II111iiii
   if 51 - 51: ooOoO0o * iIii1I11I1II1 . iII111i
   if ( self . lisp_header . decode ( oOo0O000oo0 ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( ooOo0 )
    if 25 - 25: OOooOOo - Ii1I . I11i
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
   oOo0O000oo0 = oOo0O000oo0 [ 8 : : ]
   o0ooOo00O = self . lisp_header . get_instance_id ( )
   IiIIIii1i1iI += 16
   if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
  if ( o0ooOo00O == 0xffffff ) : o0ooOo00O = 0
  if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
  if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
  if 100 - 100: i1IIi % Ii1I
  if 55 - 55: I1IiiI + iII111i
  OO00o0 = False
  IiIiIi1I1 = self . lisp_header . k_bits
  if ( IiIiIi1I1 ) :
   O0o = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( O0o == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( ooOo0 )
    if 90 - 90: I1IiiI * I1ii11iIi11i . I11i * Ii1I - o0oOOo0O0Ooo
    self . print_packet ( "Receive" , is_lisp_packet )
    IiI1 = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( IiI1 , IiIiIi1I1 ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 41 - 41: o0oOOo0O0Ooo % Oo0Ooo
    if 93 - 93: ooOoO0o
   OOo0O = lisp_crypto_keys_by_rloc_decap [ O0o ] [ IiIiIi1I1 ]
   if ( OOo0O == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( ooOo0 )
    if 5 - 5: II111iiii % iII111i + i1IIi * i1IIi
    self . print_packet ( "Receive" , is_lisp_packet )
    IiI1 = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( IiI1 ,
 red ( O0o , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 65 - 65: i1IIi . i11iIiiIii
    if 62 - 62: I1ii11iIi11i + OoO0O00 - I1ii11iIi11i * IiII - I11i * I11i
    if 99 - 99: Oo0Ooo / I1Ii111 * Oo0Ooo / iIii1I11I1II1 * IiII
    if 99 - 99: iIii1I11I1II1 - ooOoO0o
    if 79 - 79: I1IiiI + oO0o % I11i % oO0o
   OOo0O . use_count += 1
   oOo0O000oo0 , OO00o0 = self . decrypt ( oOo0O000oo0 , IiIIIii1i1iI , OOo0O ,
 O0o )
   if ( OO00o0 == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( ooOo0 )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
    if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
    if 99 - 99: o0oOOo0O0Ooo + OOooOOo
    if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
    if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
    if 76 - 76: oO0o / OoOoOO00
  OoOOoO0o = struct . unpack ( "B" , oOo0O000oo0 [ 0 : 1 ] ) [ 0 ]
  self . inner_version = OoOOoO0o >> 4
  if ( I11I1i and self . inner_version == 4 and OoOOoO0o >= 0x45 ) :
   iI1II1iIiI11I = socket . ntohs ( struct . unpack ( "H" , oOo0O000oo0 [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , oOo0O000oo0 [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , oOo0O000oo0 [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , oOo0O000oo0 [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( oOo0O000oo0 [ 12 : 16 ] )
   self . inner_dest . unpack_address ( oOo0O000oo0 [ 16 : 20 ] )
   Iiiii = socket . ntohs ( struct . unpack ( "H" , oOo0O000oo0 [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( Iiiii & 0x2000 or Iiiii != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , oOo0O000oo0 [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , oOo0O000oo0 [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 19 - 19: ooOoO0o / I1IiiI - Ii1I
  elif ( I11I1i and self . inner_version == 6 and OoOOoO0o >= 0x60 ) :
   iI1II1iIiI11I = socket . ntohs ( struct . unpack ( "H" , oOo0O000oo0 [ 4 : 6 ] ) [ 0 ] ) + 40
   o0o0oo0OOo0O0 = struct . unpack ( "H" , oOo0O000oo0 [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( o0o0oo0OOo0O0 ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , oOo0O000oo0 [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , oOo0O000oo0 [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( oOo0O000oo0 [ 8 : 24 ] )
   self . inner_dest . unpack_address ( oOo0O000oo0 [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , oOo0O000oo0 [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , oOo0O000oo0 [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 53 - 53: oO0o
  elif ( oOO0oOooo ) :
   iI1II1iIiI11I = len ( oOo0O000oo0 )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( oOo0O000oo0 [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( oOo0O000oo0 [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( ooOo0 )
   if 99 - 99: Oo0Ooo
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( OoOOoO0o ) ) )
   if 17 - 17: i11iIiiIii - i11iIiiIii + I1ii11iIi11i * ooOoO0o * oO0o / OoooooooOO
   oOo0O000oo0 = lisp_format_packet ( oOo0O000oo0 [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( oOo0O000oo0 ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 22 - 22: I1Ii111 * I1ii11iIi11i - IiII
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = o0ooOo00O
  self . inner_dest . instance_id = o0ooOo00O
  if 71 - 71: iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * I1IiiI % II111iiii
  if 35 - 35: I1Ii111 - OoOoOO00
  if 61 - 61: I1Ii111 * o0oOOo0O0Ooo * OoO0O00 + I1ii11iIi11i . Oo0Ooo + i1IIi
  if 82 - 82: Oo0Ooo + I1Ii111
  if 93 - 93: I11i * O0 * OOooOOo - o0oOOo0O0Ooo / I1ii11iIi11i
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   oooOo0OO = lisp_get_echo_nonce ( self . outer_source , None )
   if ( oooOo0OO == None ) :
    iII = self . outer_source . print_address_no_iid ( )
    oooOo0OO = lisp_echo_nonce ( iII )
    if 31 - 31: Ii1I % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
   OoI1 = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    oooOo0OO . receive_request ( lisp_ipc_socket , OoI1 )
   elif ( oooOo0OO . request_nonce_sent ) :
    oooOo0OO . receive_echo ( lisp_ipc_socket , OoI1 )
    if 88 - 88: OoooooooOO - OOooOOo + O0 * IiII * I11i
    if 8 - 8: oO0o / i11iIiiIii
    if 93 - 93: I1Ii111 % i11iIiiIii
    if 25 - 25: ooOoO0o % iII111i * iII111i + iIii1I11I1II1 . i1IIi
    if 67 - 67: I1ii11iIi11i + oO0o * IiII / II111iiii % OoO0O00 % OoO0O00
    if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
    if 91 - 91: I1IiiI / II111iiii * OOooOOo
  if ( OO00o0 ) : self . packet += oOo0O000oo0 [ : iI1II1iIiI11I ]
  if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
  if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
  if 81 - 81: OoO0O00 - iIii1I11I1II1
  if 60 - 60: I1Ii111
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 77 - 77: I1IiiI / I1ii11iIi11i
  if 95 - 95: I1Ii111 * i1IIi + oO0o
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 40 - 40: II111iiii
  if 7 - 7: OOooOOo / OoO0O00
 def strip_outer_headers ( self ) :
  O00O00O000OOO = 16
  O00O00O000OOO += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ O00O00O000OOO : : ]
  return ( self )
  if 88 - 88: i1IIi
  if 53 - 53: ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
 def hash_ports ( self ) :
  oOo0O000oo0 = self . packet
  OoOOoO0o = self . inner_version
  IiiiII = 0
  if ( OoOOoO0o == 4 ) :
   OoO = struct . unpack ( "B" , oOo0O000oo0 [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( OoO )
   if ( OoO in [ 6 , 17 ] ) :
    IiiiII = OoO
    IiiiII += struct . unpack ( "I" , oOo0O000oo0 [ 20 : 24 ] ) [ 0 ]
    IiiiII = ( IiiiII >> 16 ) ^ ( IiiiII & 0xffff )
    if 57 - 57: oO0o
    if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
  if ( OoOOoO0o == 6 ) :
   OoO = struct . unpack ( "B" , oOo0O000oo0 [ 6 ] ) [ 0 ]
   if ( OoO in [ 6 , 17 ] ) :
    IiiiII = OoO
    IiiiII += struct . unpack ( "I" , oOo0O000oo0 [ 40 : 44 ] ) [ 0 ]
    IiiiII = ( IiiiII >> 16 ) ^ ( IiiiII & 0xffff )
    if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
    if 37 - 37: iII111i
  return ( IiiiII )
  if 15 - 15: o0oOOo0O0Ooo % OoO0O00 / iII111i
  if 36 - 36: OoO0O00 + OoO0O00 % Oo0Ooo + Oo0Ooo / i1IIi % i1IIi
 def hash_packet ( self ) :
  IiiiII = self . inner_source . address ^ self . inner_dest . address
  IiiiII += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   IiiiII = ( IiiiII >> 16 ) ^ ( IiiiII & 0xffff )
  elif ( self . inner_version == 6 ) :
   IiiiII = ( IiiiII >> 64 ) ^ ( IiiiII & 0xffffffffffffffff )
   IiiiII = ( IiiiII >> 32 ) ^ ( IiiiII & 0xffffffff )
   IiiiII = ( IiiiII >> 16 ) ^ ( IiiiII & 0xffff )
   if 20 - 20: OOooOOo * oO0o
  self . udp_sport = 0xf000 | ( IiiiII & 0xfff )
  if 91 - 91: OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
  if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   I1i1Ii = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # OoooooooOO % OoOoOO00 + IiII
 green ( I1i1Ii , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 14 - 14: I1Ii111 / I11i - OOooOOo * O0 % IiII . O0
   if 86 - 86: i1IIi * OoooooooOO
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   I1I1I1 = "decap"
   I1I1I1 += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   I1I1I1 = s_or_r
   if ( I1I1I1 in [ "Send" , "Replicate" ] or I1I1I1 . find ( "Fragment" ) != - 1 ) :
    I1I1I1 = "encap"
    if 29 - 29: I1ii11iIi11i
    if 91 - 91: OoO0O00
  OOO = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 99 - 99: ooOoO0o * iIii1I11I1II1 - Ii1I + Oo0Ooo . Oo0Ooo
  if 18 - 18: OOooOOo
  if 82 - 82: OoooooooOO - ooOoO0o * I1ii11iIi11i * ooOoO0o * O0 * iIii1I11I1II1
  if 31 - 31: ooOoO0o . OOooOOo % ooOoO0o
  if 33 - 33: O0 * Ii1I - IiII . OoooooooOO + IiII
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   OoO0o0OOOO = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 20 - 20: I1Ii111 - OoOoOO00
   OoO0o0OOOO += bold ( "control-packet" , False ) + ": {} ..."
   if 91 - 91: i1IIi
   dprint ( OoO0o0OOOO . format ( bold ( s_or_r , False ) , red ( OOO , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   OoO0o0OOOO = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 31 - 31: i11iIiiIii + Ii1I % OoOoOO00
   if 9 - 9: ooOoO0o . I11i - Oo0Ooo . I1Ii111
   if 39 - 39: OOooOOo
   if 70 - 70: IiII % OoO0O00 % I1IiiI
  if ( self . lisp_header . k_bits ) :
   if ( I1I1I1 == "encap" ) : I1I1I1 = "encrypt/encap"
   if ( I1I1I1 == "decap" ) : I1I1I1 = "decap/decrypt"
   if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
   if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
  I1i1Ii = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 2 - 2: oO0o * oO0o . OoOoOO00 * Ii1I * iIii1I11I1II1
  dprint ( OoO0o0OOOO . format ( bold ( s_or_r , False ) , red ( OOO , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( I1i1Ii , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( I1I1I1 ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 13 - 13: I11i / O0 . i11iIiiIii * i1IIi % i11iIiiIii
  if 8 - 8: OoOoOO00 - OoooooooOO
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 99 - 99: II111iiii / IiII % OoooooooOO . i11iIiiIii
  if 18 - 18: o0oOOo0O0Ooo . ooOoO0o
 def get_raw_socket ( self ) :
  o0ooOo00O = str ( self . lisp_header . get_instance_id ( ) )
  if ( o0ooOo00O == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( o0ooOo00O ) == False ) : return ( None )
  if 70 - 70: OoooooooOO . ooOoO0o / oO0o . oO0o - o0oOOo0O0Ooo
  oooOoO = lisp_iid_to_interface [ o0ooOo00O ]
  i11I1 = oooOoO . get_socket ( )
  if ( i11I1 == None ) :
   i1iiiIi11 = bold ( "SO_BINDTODEVICE" , False )
   i1II1i1iiI1 = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( i1iiiIi11 , "drop" if i1II1i1iiI1 else "forward" ) )
   if 62 - 62: Ii1I . i11iIiiIii % O0 % I1Ii111 - Oo0Ooo
   if ( i1II1i1iiI1 ) : return ( None )
   if 69 - 69: II111iiii . OoOoOO00 * OoOoOO00 % Ii1I + I1IiiI
   if 100 - 100: i11iIiiIii - Oo0Ooo
  o0ooOo00O = bold ( o0ooOo00O , False )
  iiiii111 = bold ( oooOoO . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( o0ooOo00O , iiiii111 ) )
  return ( i11I1 )
  if 47 - 47: iII111i * OoOoOO00 * IiII
  if 46 - 46: Ii1I
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 42 - 42: iIii1I11I1II1
  IIi1IiIii = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or IIi1IiIii ) :
   iiIi1I = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = iiIi1I ) . start ( )
   if ( IIi1IiIii ) : os . system ( "rm ./log-flows" )
   return
   if 23 - 23: OoO0O00 % OoooooooOO * ooOoO0o
   if 6 - 6: I1IiiI . II111iiii + I1Ii111 / OoO0O00 % I1IiiI . OoooooooOO
  I11i1II = datetime . datetime . now ( )
  lisp_flow_log . append ( [ I11i1II , encap , self . packet , self ] )
  if 64 - 64: iIii1I11I1II1 + II111iiii . iII111i % Oo0Ooo * ooOoO0o
  if 7 - 7: i1IIi + i1IIi / IiII
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  I1IIiiiiI1iIi = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 82 - 82: i11iIiiIii + O0 - Ii1I
  oO00oO0 = red ( self . outer_source . print_address_no_iid ( ) , False )
  o0o = red ( self . outer_dest . print_address_no_iid ( ) , False )
  I1Iii = green ( self . inner_source . print_address ( ) , False )
  II1I1Ii11 = green ( self . inner_dest . print_address ( ) , False )
  if 20 - 20: Ii1I / iII111i + II111iiii . i11iIiiIii . OOooOOo
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   I1IIiiiiI1iIi += " {}:{} -> {}:{}, LISP control message type {}\n"
   I1IIiiiiI1iIi = I1IIiiiiI1iIi . format ( oO00oO0 , self . udp_sport , o0o , self . udp_dport ,
 self . inner_version )
   return ( I1IIiiiiI1iIi )
   if 77 - 77: OoOoOO00
   if 91 - 91: oO0o
  if ( self . outer_dest . is_null ( ) == False ) :
   I1IIiiiiI1iIi += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   I1IIiiiiI1iIi = I1IIiiiiI1iIi . format ( oO00oO0 , self . udp_sport , o0o , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 56 - 56: iIii1I11I1II1 % II111iiii / OoOoOO00 % OoooooooOO
   if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
   if 84 - 84: II111iiii
   if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
   if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
  if ( self . lisp_header . k_bits != 0 ) :
   IIi1iiIIi1i = "\n"
   if ( self . packet_error != "" ) :
    IIi1iiIIi1i = " ({})" . format ( self . packet_error ) + IIi1iiIIi1i
    if 5 - 5: OoooooooOO / IiII
   I1IIiiiiI1iIi += ", encrypted" + IIi1iiIIi1i
   return ( I1IIiiiiI1iIi )
   if 51 - 51: OOooOOo % i11iIiiIii
   if 77 - 77: OOooOOo % i11iIiiIii - I1ii11iIi11i
   if 21 - 21: I11i . Oo0Ooo - OoooooooOO * i1IIi
   if 54 - 54: II111iiii % o0oOOo0O0Ooo - i1IIi . I1IiiI - II111iiii / iIii1I11I1II1
   if 29 - 29: oO0o
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 66 - 66: OoooooooOO + iII111i . IiII % i1IIi
   if 58 - 58: OOooOOo % iII111i * O0 + I1ii11iIi11i - IiII
  OoO = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  OoO = struct . unpack ( "B" , OoO ) [ 0 ]
  if 26 - 26: i1IIi / I1IiiI / I11i + I11i
  I1IIiiiiI1iIi += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  I1IIiiiiI1iIi = I1IIiiiiI1iIi . format ( I1Iii , II1I1Ii11 , len ( packet ) , self . inner_tos ,
 self . inner_ttl , OoO )
  if 46 - 46: I1Ii111 % I1ii11iIi11i + Ii1I
  if 67 - 67: iIii1I11I1II1 . i11iIiiIii . i11iIiiIii . i11iIiiIii / I11i + ooOoO0o
  if 10 - 10: ooOoO0o - Oo0Ooo % II111iiii
  if 66 - 66: iIii1I11I1II1 . iIii1I11I1II1
  if ( OoO in [ 6 , 17 ] ) :
   I1iI1111ii1I1 = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( I1iI1111ii1I1 ) == 4 ) :
    I1iI1111ii1I1 = socket . ntohl ( struct . unpack ( "I" , I1iI1111ii1I1 ) [ 0 ] )
    I1IIiiiiI1iIi += ", ports {} -> {}" . format ( I1iI1111ii1I1 >> 16 , I1iI1111ii1I1 & 0xffff )
    if 70 - 70: I1ii11iIi11i . O0
  elif ( OoO == 1 ) :
   oOoOOo = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( oOoOOo ) == 2 ) :
    oOoOOo = socket . ntohs ( struct . unpack ( "H" , oOoOOo ) [ 0 ] )
    I1IIiiiiI1iIi += ", icmp-seq {}" . format ( oOoOOo )
    if 2 - 2: ooOoO0o - I11i * i1IIi % OOooOOo / OoooooooOO * OOooOOo
    if 82 - 82: I1ii11iIi11i . I1ii11iIi11i * Ii1I % I11i % O0 / Oo0Ooo
  if ( self . packet_error != "" ) :
   I1IIiiiiI1iIi += " ({})" . format ( self . packet_error )
   if 83 - 83: I1Ii111 + o0oOOo0O0Ooo % oO0o / OoO0O00
  I1IIiiiiI1iIi += "\n"
  return ( I1IIiiiiI1iIi )
  if 59 - 59: Ii1I * OOooOOo . IiII
  if 68 - 68: O0 * iIii1I11I1II1 / I1Ii111
 def is_trace ( self ) :
  I1iI1111ii1I1 = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in I1iI1111ii1I1 )
  if 65 - 65: OOooOOo - I1IiiI * I1Ii111
  if 99 - 99: I1IiiI
  if 64 - 64: I1ii11iIi11i * Ii1I * Oo0Ooo % IiII % ooOoO0o
  if 55 - 55: II111iiii - I1Ii111 - OOooOOo % Ii1I
  if 49 - 49: Oo0Ooo * I1Ii111
  if 53 - 53: Oo0Ooo / Ii1I + oO0o . iII111i + IiII
  if 19 - 19: Ii1I
  if 51 - 51: iIii1I11I1II1
  if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
  if 8 - 8: OoO0O00 * Oo0Ooo
  if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
  if 4 - 4: I11i . IiII
  if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
  if 4 - 4: OoOoOO00 * O0 - I11i
  if 72 - 72: I11i + ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
  if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 70 - 70: II111iiii * II111iiii . I1IiiI
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 11 - 11: iII111i
  if 20 - 20: Ii1I . I1Ii111 % Ii1I
 def print_header ( self , e_or_d ) :
  i11iI1 = lisp_hex_string ( self . first_long & 0xffffff )
  o00 = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 57 - 57: OOooOOo + o0oOOo0O0Ooo . OOooOOo
  OoO0o0OOOO = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 64 - 64: OoOoOO00
  return ( OoO0o0OOOO . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 i11iI1 , o00 ) )
  if 28 - 28: O0 + I1Ii111 / OoO0O00 + I1Ii111
  if 91 - 91: OoooooooOO . OOooOOo - ooOoO0o + II111iiii + Ii1I . OoooooooOO
 def encode ( self ) :
  Iii1 = "II"
  i11iI1 = socket . htonl ( self . first_long )
  o00 = socket . htonl ( self . second_long )
  if 2 - 2: Ii1I
  Ii1i111iI = struct . pack ( Iii1 , i11iI1 , o00 )
  return ( Ii1i111iI )
  if 48 - 48: Oo0Ooo
  if 64 - 64: iIii1I11I1II1 % o0oOOo0O0Ooo . O0 * o0oOOo0O0Ooo
 def decode ( self , packet ) :
  Iii1 = "II"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( False )
  if 23 - 23: OoO0O00 . IiII
  i11iI1 , o00 = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 79 - 79: OOooOOo
  if 94 - 94: IiII - iIii1I11I1II1 % oO0o
  self . first_long = socket . ntohl ( i11iI1 )
  self . second_long = socket . ntohl ( o00 )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 80 - 80: Ii1I - I1ii11iIi11i . Ii1I / i11iIiiIii + O0 . IiII
  if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
  if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
  if 91 - 91: I1IiiI + o0oOOo0O0Ooo % II111iiii + OoO0O00
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 66 - 66: iIii1I11I1II1 * II111iiii % Oo0Ooo % I1IiiI - Ii1I
  if 59 - 59: IiII % oO0o
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
  if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 93 - 93: I1ii11iIi11i * I1ii11iIi11i / OoooooooOO
  if 6 - 6: I1ii11iIi11i * Oo0Ooo + iIii1I11I1II1
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 19 - 19: O0 % II111iiii * o0oOOo0O0Ooo
  if 27 - 27: OOooOOo * IiII / i11iIiiIii - oO0o + II111iiii
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 43 - 43: I1ii11iIi11i - II111iiii
  if 56 - 56: I1ii11iIi11i . i1IIi / iII111i % oO0o / O0 * I11i
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 98 - 98: O0 + iII111i
  if 23 - 23: OoooooooOO . iIii1I11I1II1 / i1IIi
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
  if 74 - 74: Oo0Ooo - II111iiii - IiII
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
  if 70 - 70: i1IIi % OoO0O00 / i1IIi
  if 30 - 30: OoOoOO00 - i11iIiiIii
class lisp_echo_nonce ( ) :
 def __init__ ( self , rloc_str ) :
  self . rloc_str = rloc_str
  self . rloc = lisp_address ( LISP_AFI_NONE , rloc_str , 0 , 0 )
  self . request_nonce_sent = None
  self . echo_nonce_sent = None
  self . last_request_nonce_sent = None
  self . last_new_request_nonce_sent = None
  self . last_echo_nonce_sent = None
  self . last_new_echo_nonce_sent = None
  self . request_nonce_rcvd = None
  self . echo_nonce_rcvd = None
  self . last_request_nonce_rcvd = None
  self . last_echo_nonce_rcvd = None
  self . last_good_echo_nonce_rcvd = None
  lisp_nonce_echo_list [ rloc_str ] = self
  if 94 - 94: OoOoOO00 % iII111i
  if 39 - 39: OoOoOO00 + I1Ii111 % O0
 def send_ipc ( self , ipc_socket , ipc ) :
  i1Ii1I = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  iiII = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , i1Ii1I )
  lisp_ipc ( ipc , ipc_socket , iiII )
  if 60 - 60: ooOoO0o * Ii1I + I1Ii111 . OOooOOo . O0
  if 8 - 8: II111iiii + II111iiii * i1IIi * o0oOOo0O0Ooo / O0 / O0
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  O0oO00o0o0oo0 = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , O0oO00o0o0oo0 )
  if 18 - 18: OoOoOO00
  if 77 - 77: I1Ii111 . i11iIiiIii / Ii1I * i11iIiiIii - o0oOOo0O0Ooo
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  O0oO00o0o0oo0 = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , O0oO00o0o0oo0 )
  if 6 - 6: i11iIiiIii
  if 16 - 16: IiII
 def receive_request ( self , ipc_socket , nonce ) :
  Ooooo = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( Ooooo != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 65 - 65: Oo0Ooo . OoOoOO00 . OOooOOo % o0oOOo0O0Ooo + OoO0O00
  if 53 - 53: Oo0Ooo * I11i - Ii1I % OoO0O00 - OoOoOO00 - iII111i
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 21 - 21: II111iiii + OoO0O00 - Oo0Ooo + I1IiiI
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 20 - 20: OoO0O00
  if 64 - 64: IiII
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
  if 89 - 89: O0 + IiII * I1Ii111
  if 30 - 30: OoOoOO00
  if 39 - 39: I1ii11iIi11i + o0oOOo0O0Ooo + I1Ii111 + IiII
  if 48 - 48: I1Ii111 / ooOoO0o . iIii1I11I1II1
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   ooo0OOoo = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 52 - 52: OoO0O00
   if 49 - 49: Ii1I . I1ii11iIi11i % ooOoO0o . Oo0Ooo * OOooOOo
   if ( remote_rloc . address > ooo0OOoo . address ) :
    i11ii = "exit"
    self . request_nonce_sent = None
   else :
    i11ii = "stay in"
    self . echo_nonce_sent = None
    if 44 - 44: iIii1I11I1II1 / O0 * Oo0Ooo + I1IiiI . ooOoO0o
    if 20 - 20: iII111i + o0oOOo0O0Ooo . I1Ii111 / i11iIiiIii
   IIiI1 = bold ( "collision" , False )
   IIii1 = red ( ooo0OOoo . print_address_no_iid ( ) , False )
   oO = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( IIiI1 ,
 IIii1 , oO , i11ii ) )
   if 90 - 90: IiII * II111iiii * IiII - iII111i
   if 34 - 34: OOooOOo - I1ii11iIi11i * iII111i % Ii1I
   if 25 - 25: II111iiii + I1IiiI * ooOoO0o * I1ii11iIi11i . iII111i
   if 26 - 26: iII111i - ooOoO0o / OoooooooOO + o0oOOo0O0Ooo . Oo0Ooo
   if 75 - 75: O0 / OoOoOO00 . I1Ii111
  if ( self . echo_nonce_sent != None ) :
   OoI1 = self . echo_nonce_sent
   IIIII1iii11 = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( IIIII1iii11 ,
 lisp_hex_string ( OoI1 ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( OoI1 )
   if 7 - 7: OoO0O00 * iII111i
   if 16 - 16: I1Ii111 . i1IIi . IiII
   if 50 - 50: OoO0O00 - II111iiii * OoooooooOO - I1IiiI . O0 + O0
   if 80 - 80: o0oOOo0O0Ooo
   if 50 - 50: ooOoO0o
   if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
   if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
  OoI1 = self . request_nonce_sent
  O0ooO0oOO = self . last_request_nonce_sent
  if ( OoI1 and O0ooO0oOO != None ) :
   if ( time . time ( ) - O0ooO0oOO >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OoI1 ) ) )
    if 53 - 53: O0 / II111iiii - OOooOOo - oO0o . OOooOOo
    return ( None )
    if 4 - 4: OOooOOo - Oo0Ooo % II111iiii - OoO0O00 % i1IIi % ooOoO0o
    if 31 - 31: iIii1I11I1II1 / OoooooooOO
    if 8 - 8: iIii1I11I1II1 . iIii1I11I1II1 + Ii1I . OOooOOo
    if 58 - 58: iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - i1IIi * OoOoOO00
    if 4 - 4: OoooooooOO
    if 7 - 7: IiII
    if 26 - 26: OOooOOo + Oo0Ooo
    if 71 - 71: I1IiiI . ooOoO0o
    if 43 - 43: I1ii11iIi11i * OOooOOo
  if ( OoI1 == None ) :
   OoI1 = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( OoI1 )
   if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
   self . request_nonce_sent = OoI1
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OoI1 ) ) )
   if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 51 - 51: OOooOOo / I11i
   if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
   if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
   if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
   if 26 - 26: i11iIiiIii - ooOoO0o
   if ( lisp_i_am_itr == False ) : return ( OoI1 | 0x80000000 )
   self . send_request_ipc ( ipc_socket , OoI1 )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OoI1 ) ) )
   if 45 - 45: ooOoO0o + II111iiii % iII111i
   if 55 - 55: ooOoO0o - oO0o % I1IiiI
   if 61 - 61: ooOoO0o
   if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
   if 21 - 21: oO0o . i11iIiiIii * I11i . OOooOOo / OOooOOo
   if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
   if 1 - 1: Ii1I % I1Ii111
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( OoI1 | 0x80000000 )
  if 97 - 97: OoOoOO00
  if 13 - 13: OoOoOO00 % OOooOOo . O0 / Oo0Ooo % Oo0Ooo
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 19 - 19: I1Ii111 % ooOoO0o - ooOoO0o % I1IiiI . OOooOOo - OoooooooOO
  OOo0 = time . time ( ) - self . last_request_nonce_sent
  OOO0oO = self . last_echo_nonce_rcvd
  return ( OOo0 >= LISP_NONCE_ECHO_INTERVAL and OOO0oO == None )
  if 82 - 82: oO0o / Ii1I
  if 75 - 75: ooOoO0o
 def recently_requested ( self ) :
  OOO0oO = self . last_request_nonce_sent
  if ( OOO0oO == None ) : return ( False )
  if 23 - 23: OoOoOO00 * Oo0Ooo % OoooooooOO - i11iIiiIii
  OOo0 = time . time ( ) - OOO0oO
  return ( OOo0 <= LISP_NONCE_ECHO_INTERVAL )
  if 46 - 46: Oo0Ooo
  if 99 - 99: OoO0O00 - ooOoO0o * O0 * I1ii11iIi11i * iIii1I11I1II1 - iIii1I11I1II1
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 50 - 50: I1IiiI % i11iIiiIii - I1IiiI * iII111i / IiII / O0
  if 31 - 31: II111iiii . OoooooooOO + OoO0O00 + o0oOOo0O0Ooo . I1IiiI . II111iiii
  if 3 - 3: I11i / I1Ii111 * IiII - O0 + I1IiiI / IiII
  if 19 - 19: i1IIi % II111iiii
  OOO0oO = self . last_good_echo_nonce_rcvd
  if ( OOO0oO == None ) : OOO0oO = 0
  OOo0 = time . time ( ) - OOO0oO
  if ( OOo0 <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
  if 56 - 56: Ii1I * i11iIiiIii
  if 92 - 92: II111iiii - O0 . I1Ii111
  if 59 - 59: OoOoOO00
  if 47 - 47: II111iiii - I1ii11iIi11i - Ii1I
  if 9 - 9: I1ii11iIi11i - IiII
  OOO0oO = self . last_new_request_nonce_sent
  if ( OOO0oO == None ) : OOO0oO = 0
  OOo0 = time . time ( ) - OOO0oO
  return ( OOo0 <= LISP_NONCE_ECHO_INTERVAL )
  if 64 - 64: i1IIi
  if 71 - 71: IiII * o0oOOo0O0Ooo
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   oo00oOoo = bold ( "down" , False )
   oOOO0oo0 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , oo00oOoo , oOOO0oo0 ) )
   if 13 - 13: OoOoOO00 - OoO0O00 * OoooooooOO
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 26 - 26: OoooooooOO
   if 65 - 65: OOooOOo
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 14 - 14: ooOoO0o
  if ( self . recently_requested ( ) == False ) :
   Ooo0OO00oo = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , Ooo0OO00oo ) )
   if 21 - 21: I11i
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 79 - 79: OoO0O00 / OOooOOo - i1IIi + i1IIi - IiII + IiII
   if 67 - 67: OoO0O00 * OoO0O00 / OoooooooOO
   if 79 - 79: o0oOOo0O0Ooo % iIii1I11I1II1 / II111iiii / Ii1I / Ii1I + O0
 def print_echo_nonce ( self ) :
  ii11 = lisp_print_elapsed ( self . last_request_nonce_sent )
  oOo0OO0 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 56 - 56: II111iiii . II111iiii + IiII . o0oOOo0O0Ooo
  i1Ii111 = lisp_print_elapsed ( self . last_echo_nonce_sent )
  OO0o0o0OOoooo = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  i11I1 = space ( 4 )
  if 77 - 77: I1ii11iIi11i % oO0o
  iiIiI = "Nonce-Echoing:\n"
  iiIiI += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( i11I1 , ii11 , i11I1 , oOo0OO0 )
  if 67 - 67: Oo0Ooo - oO0o + I1IiiI * Oo0Ooo * o0oOOo0O0Ooo % OoOoOO00
  iiIiI += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( i11I1 , OO0o0o0OOoooo , i11I1 , i1Ii111 )
  if 44 - 44: iIii1I11I1II1 % i1IIi * i1IIi * OoO0O00
  if 100 - 100: OOooOOo
  return ( iiIiI )
  if 98 - 98: I11i . O0 / II111iiii
  if 92 - 92: oO0o * IiII * O0
  if 93 - 93: II111iiii . I11i - i1IIi * OoOoOO00
  if 28 - 28: I11i % I1Ii111
  if 49 - 49: IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . Ii1I * I1ii11iIi11i
  if 17 - 17: I1ii11iIi11i * OoooooooOO % i1IIi % OoooooooOO . iII111i
  if 20 - 20: OoO0O00 . oO0o
  if 4 - 4: Oo0Ooo % Ii1I % OoO0O00 * iII111i % OoooooooOO
  if 38 - 38: OoooooooOO . iII111i
class lisp_keys ( ) :
 def __init__ ( self , key_id , do_curve = True , do_chacha = use_chacha ,
 do_poly = use_poly ) :
  self . uptime = lisp_get_timestamp ( )
  self . last_rekey = None
  self . rekey_count = 0
  self . use_count = 0
  self . key_id = key_id
  self . cipher_suite = LISP_CS_1024
  self . dh_g_value = LISP_CS_1024_G
  self . dh_p_value = LISP_CS_1024_P
  self . curve25519 = None
  self . cipher_suite_string = ""
  if ( do_curve ) :
   if ( do_chacha ) :
    self . cipher_suite = LISP_CS_25519_CHACHA
    self . cipher_suite_string = "chacha"
   elif ( os . getenv ( "LISP_USE_AES_GCM" ) != None ) :
    self . cipher_suite = LISP_CS_25519_GCM
    self . cipher_suite_string = "aes-gcm"
   else :
    self . cipher_suite = LISP_CS_25519_CBC
    self . cipher_suite_string = "aes-cbc"
    if 43 - 43: OoooooooOO
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   OOo0O = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( OOo0O )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 8 - 8: OOooOOo + I11i . I11i
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 89 - 89: I1ii11iIi11i * I1ii11iIi11i * OoOoOO00 / iII111i
  if 60 - 60: OoO0O00 / iII111i / I1IiiI + oO0o
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 93 - 93: OoooooooOO * Ii1I / O0 + Ii1I - iIii1I11I1II1
  if 6 - 6: IiII - Oo0Ooo - I11i - O0 % OoooooooOO
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 88 - 88: O0 / o0oOOo0O0Ooo * o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0
  O0o0oOOO = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   O0o0oOOO = struct . pack ( "Q" , O0o0oOOO & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   IiI1i11iiII = struct . pack ( "I" , ( O0o0oOOO >> 64 ) & LISP_4_32_MASK )
   oO00OoooOo0 = struct . pack ( "Q" , O0o0oOOO & LISP_8_64_MASK )
   O0o0oOOO = IiI1i11iiII + oO00OoooOo0
  else :
   O0o0oOOO = struct . pack ( "QQ" , O0o0oOOO >> 64 , O0o0oOOO & LISP_8_64_MASK )
  return ( O0o0oOOO )
  if 4 - 4: iII111i % I1ii11iIi11i
  if 9 - 9: O0 * Ii1I
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 54 - 54: I11i % I11i - ooOoO0o
  if 32 - 32: o0oOOo0O0Ooo % II111iiii / o0oOOo0O0Ooo . OOooOOo . o0oOOo0O0Ooo
 def print_key ( self , key ) :
  o00oo = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( o00oo [ 0 : 4 ] , o00oo [ - 4 : : ] , self . key_length ( o00oo ) ) )
  if 29 - 29: OoooooooOO % II111iiii % i11iIiiIii - Oo0Ooo
  if 5 - 5: I1ii11iIi11i . II111iiii . i1IIi
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 35 - 35: o0oOOo0O0Ooo + OoO0O00 - I1ii11iIi11i
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 24 - 24: II111iiii
  if 23 - 23: Oo0Ooo - iII111i
 def print_keys ( self , do_bold = True ) :
  IIii1 = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   IIii1 += "none"
  else :
   IIii1 += self . print_key ( self . local_public_key )
   if 79 - 79: I11i . O0 - i1IIi
  oO = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   oO += "none"
  else :
   oO += self . print_key ( self . remote_public_key )
   if 42 - 42: oO0o - i11iIiiIii % oO0o - I1Ii111 * O0 / II111iiii
  i1iIIi = "ECDH" if ( self . curve25519 ) else "DH"
  oo0O0OO0Oooo = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( i1iIIi , oo0O0OO0Oooo , IIii1 , oO ) )
  if 7 - 7: II111iiii - I1ii11iIi11i / I11i % OoooooooOO + i1IIi
  if 42 - 42: I11i + i1IIi - Ii1I / IiII . iII111i
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 30 - 30: Oo0Ooo + Ii1I % i11iIiiIii * i1IIi + I1IiiI % OOooOOo
  if 30 - 30: i11iIiiIii * Oo0Ooo . II111iiii + I1ii11iIi11i / o0oOOo0O0Ooo % I1Ii111
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 78 - 78: I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
  OOo0O = self . local_private_key
  I1I1i1 = self . dh_g_value
  Ii1Ii = self . dh_p_value
  return ( int ( ( I1I1i1 ** OOo0O ) % Ii1Ii ) )
  if 15 - 15: O0
  if 60 - 60: Ii1I % oO0o - I1ii11iIi11i / oO0o
 def compute_shared_key ( self , ed , print_shared = False ) :
  OOo0O = self . local_private_key
  iii111 = self . remote_public_key
  if 96 - 96: o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + OoO0O00 - IiII - IiII
  i1ii1iiI1iI = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( i1ii1iiI1iI , self . print_keys ( ) ) )
  if 48 - 48: II111iiii / iIii1I11I1II1 * OoO0O00 % oO0o . i1IIi
  if ( self . curve25519 ) :
   Iii = curve25519 . Public ( iii111 )
   self . shared_key = self . curve25519 . get_shared_key ( Iii )
  else :
   Ii1Ii = self . dh_p_value
   self . shared_key = ( iii111 ** OOo0O ) % Ii1Ii
   if 8 - 8: o0oOOo0O0Ooo
   if 78 - 78: i1IIi - Oo0Ooo
   if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
   if 42 - 42: I1Ii111
   if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
   if 80 - 80: OOooOOo
   if 12 - 12: Ii1I
  if ( print_shared ) :
   o00oo = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( o00oo ) )
   if 2 - 2: OoooooooOO
   if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
   if 46 - 46: O0 % OoooooooOO
   if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
   if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
  self . compute_encrypt_icv_keys ( )
  if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
  if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
  if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
  if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
  if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
 def compute_encrypt_icv_keys ( self ) :
  II = hashlib . sha256
  if ( self . curve25519 ) :
   II1IiiI = self . shared_key
  else :
   II1IiiI = lisp_hex_string ( self . shared_key )
   if 100 - 100: I1IiiI - OOooOOo
   if 91 - 91: o0oOOo0O0Ooo * I1ii11iIi11i - iII111i . II111iiii
   if 1 - 1: OOooOOo + I1Ii111 * I1ii11iIi11i
   if 44 - 44: iII111i
   if 79 - 79: o0oOOo0O0Ooo % OOooOOo . O0
  IIii1 = self . local_public_key
  if ( type ( IIii1 ) != long ) : IIii1 = int ( binascii . hexlify ( IIii1 ) , 16 )
  oO = self . remote_public_key
  if ( type ( oO ) != long ) : oO = int ( binascii . hexlify ( oO ) , 16 )
  OO0oO0 = "0001" + "lisp-crypto" + lisp_hex_string ( IIii1 ^ oO ) + "0100"
  if 10 - 10: Ii1I * I1IiiI % I1Ii111 + iII111i . Ii1I
  i11i111i1 = hmac . new ( OO0oO0 , II1IiiI , II ) . hexdigest ( )
  i11i111i1 = int ( i11i111i1 , 16 )
  if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
  if 9 - 9: iII111i - iII111i
  if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
  if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
  ii1Ii = ( i11i111i1 >> 128 ) & LISP_16_128_MASK
  IIIIi11111 = i11i111i1 & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( ii1Ii ) . zfill ( 32 )
  Oo0o00o0oOoo0 = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( IIIIi11111 ) . zfill ( Oo0o00o0oOoo0 )
  if 36 - 36: I1Ii111 / OoOoOO00 + OoOoOO00 * ooOoO0o / OOooOOo * O0
  if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   IIiI1IiI1iIi1 = self . icv . poly1305aes
   iIiiI11II11 = self . icv . binascii . hexlify
   nonce = iIiiI11II11 ( nonce )
   o0o0O00O = IIiI1IiI1iIi1 ( self . encrypt_key , self . icv_key , nonce , packet )
   o0o0O00O = iIiiI11II11 ( o0o0O00O )
  else :
   OOo0O = binascii . unhexlify ( self . icv_key )
   o0o0O00O = hmac . new ( OOo0O , packet , self . icv ) . hexdigest ( )
   o0o0O00O = o0o0O00O [ 0 : 40 ]
   if 83 - 83: OoooooooOO
  return ( o0o0O00O )
  if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
  if 88 - 88: OOooOOo / i11iIiiIii / Ii1I / i11iIiiIii * I1ii11iIi11i % I11i
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 43 - 43: OoOoOO00 * OoO0O00 % i1IIi * Ii1I + iIii1I11I1II1
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
  if 63 - 63: ooOoO0o . OOooOOo
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 66 - 66: I1IiiI
  if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
 def add_key_by_rloc ( self , addr_str , encap ) :
  o0oOOoOoo = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 90 - 90: I1IiiI
  if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
  if ( o0oOOoOoo . has_key ( addr_str ) == False ) :
   o0oOOoOoo [ addr_str ] = [ None , None , None , None ]
   if 30 - 30: IiII
  o0oOOoOoo [ addr_str ] [ self . key_id ] = self
  if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
  if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
  if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
  if 84 - 84: OoOoOO00 - I11i
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , o0oOOoOoo [ addr_str ] )
   if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
   if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
   if 68 - 68: OoooooooOO * I11i
 def encode_lcaf ( self , rloc_addr ) :
  oOOO = self . normalize_pub_key ( self . local_public_key )
  Iii111111 = self . key_length ( oOOO )
  I1IiIi11 = ( 6 + Iii111111 + 2 )
  if ( rloc_addr != None ) : I1IiIi11 += rloc_addr . addr_length ( )
  if 19 - 19: I1Ii111 % I1Ii111 / ooOoO0o + I1Ii111 / i1IIi
  oOo0O000oo0 = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( I1IiIi11 ) , 1 , 0 )
  if 70 - 70: OOooOOo - IiII . I1Ii111
  if 11 - 11: i11iIiiIii + o0oOOo0O0Ooo - I1Ii111 * i11iIiiIii - I1IiiI
  if 49 - 49: i1IIi % oO0o / OOooOOo . I1ii11iIi11i - I1Ii111
  if 12 - 12: i11iIiiIii + I11i - I1ii11iIi11i
  if 27 - 27: iII111i
  if 22 - 22: OoOoOO00 / I1IiiI
  oo0O0OO0Oooo = self . cipher_suite
  oOo0O000oo0 += struct . pack ( "BBH" , oo0O0OO0Oooo , 0 , socket . htons ( Iii111111 ) )
  if 33 - 33: I11i
  if 37 - 37: OoOoOO00 % o0oOOo0O0Ooo * OoO0O00 / i11iIiiIii * II111iiii * iII111i
  if 70 - 70: ooOoO0o . i11iIiiIii % OoOoOO00 + oO0o
  if 95 - 95: I1ii11iIi11i
  for o0Ooo0O00 in range ( 0 , Iii111111 * 2 , 16 ) :
   OOo0O = int ( oOOO [ o0Ooo0O00 : o0Ooo0O00 + 16 ] , 16 )
   oOo0O000oo0 += struct . pack ( "Q" , byte_swap_64 ( OOo0O ) )
   if 48 - 48: I11i
   if 14 - 14: iIii1I11I1II1 / o0oOOo0O0Ooo * IiII
   if 35 - 35: iIii1I11I1II1
   if 34 - 34: OoO0O00 % I1IiiI . o0oOOo0O0Ooo % OoO0O00 % OoO0O00
   if 30 - 30: I1IiiI + I1IiiI
  if ( rloc_addr ) :
   oOo0O000oo0 += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   oOo0O000oo0 += rloc_addr . pack_address ( )
   if 75 - 75: I1IiiI - ooOoO0o - I1IiiI % oO0o % OoooooooOO
  return ( oOo0O000oo0 )
  if 13 - 13: ooOoO0o * OoO0O00 % iIii1I11I1II1 / IiII * iII111i . Oo0Ooo
  if 23 - 23: ooOoO0o / IiII . iII111i * Ii1I
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 87 - 87: i11iIiiIii
  if 34 - 34: i1IIi
  if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
  if 100 - 100: IiII + i1IIi * OoO0O00
  if ( lcaf_len == 0 ) :
   Iii1 = "HHBBH"
   O00O = struct . calcsize ( Iii1 )
   if ( len ( packet ) < O00O ) : return ( None )
   if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
   ii1iI1i1 , OOo0OO00 , ii1i , OOo0OO00 , lcaf_len = struct . unpack ( Iii1 , packet [ : O00O ] )
   if 31 - 31: Oo0Ooo
   if 1 - 1: i1IIi
   if ( ii1i != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 27 - 27: I11i
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ O00O : : ]
   if 47 - 47: OoooooooOO
   if 48 - 48: OoOoOO00 . IiII % I1IiiI + I11i
   if 37 - 37: Oo0Ooo + I1Ii111 * oO0o / o0oOOo0O0Ooo
   if 78 - 78: IiII + I11i - o0oOOo0O0Ooo + OoO0O00 / iIii1I11I1II1
   if 47 - 47: OOooOOo
   if 20 - 20: I1Ii111 % ooOoO0o - I1Ii111 * OoooooooOO / I1ii11iIi11i
  ii1i = LISP_LCAF_SECURITY_TYPE
  Iii1 = "BBBBH"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 57 - 57: IiII % I11i * OOooOOo % I1ii11iIi11i
  oooO0oO0 , OOo0OO00 , oo0O0OO0Oooo , OOo0OO00 , Iii111111 = struct . unpack ( Iii1 ,
 packet [ : O00O ] )
  if 21 - 21: OoO0O00 / oO0o + IiII % i1IIi
  if 81 - 81: I1ii11iIi11i * II111iiii
  if 26 - 26: oO0o % OoooooooOO % iII111i + OoO0O00 * OoooooooOO
  if 18 - 18: O0
  if 25 - 25: o0oOOo0O0Ooo + iIii1I11I1II1 + IiII + I1ii11iIi11i / I1Ii111 - i1IIi
  if 15 - 15: O0 % Oo0Ooo % IiII % OoooooooOO - IiII
  packet = packet [ O00O : : ]
  Iii111111 = socket . ntohs ( Iii111111 )
  if ( len ( packet ) < Iii111111 ) : return ( None )
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
  if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
  if 100 - 100: II111iiii / I1Ii111 / iII111i - I1ii11iIi11i * iIii1I11I1II1
  if 7 - 7: i1IIi . IiII % i11iIiiIii * I1ii11iIi11i . I11i % I1ii11iIi11i
  iII1i = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( oo0O0OO0Oooo not in iII1i ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( iII1i ,
 oo0O0OO0Oooo ) )
   packet = packet [ Iii111111 : : ]
   return ( packet )
   if 62 - 62: OoO0O00 . OoOoOO00
   if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
  self . cipher_suite = oo0O0OO0Oooo
  if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  if 41 - 41: OoooooooOO
  if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
  if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
  if 78 - 78: Ii1I
  oOOO = 0
  for o0Ooo0O00 in range ( 0 , Iii111111 , 8 ) :
   OOo0O = byte_swap_64 ( struct . unpack ( "Q" , packet [ o0Ooo0O00 : o0Ooo0O00 + 8 ] ) [ 0 ] )
   oOOO <<= 64
   oOOO |= OOo0O
   if 29 - 29: II111iiii
  self . remote_public_key = oOOO
  if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
  if 84 - 84: Oo0Ooo % I11i * O0 * I11i
  if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
  if 12 - 12: Oo0Ooo + I1IiiI
  if 37 - 37: i1IIi * i11iIiiIii
  if ( self . curve25519 ) :
   OOo0O = lisp_hex_string ( self . remote_public_key )
   OOo0O = OOo0O . zfill ( 64 )
   Oo00OOooOoO = ""
   for o0Ooo0O00 in range ( 0 , len ( OOo0O ) , 2 ) :
    Oo00OOooOoO += chr ( int ( OOo0O [ o0Ooo0O00 : o0Ooo0O00 + 2 ] , 16 ) )
    if 7 - 7: OoO0O00 * i11iIiiIii * iIii1I11I1II1 / OOooOOo / I1Ii111
   self . remote_public_key = Oo00OOooOoO
   if 35 - 35: iII111i * OOooOOo
   if 65 - 65: II111iiii % i1IIi
  packet = packet [ Iii111111 : : ]
  return ( packet )
  if 13 - 13: OoO0O00 * I1Ii111 + Oo0Ooo - IiII
  if 31 - 31: OoO0O00
  if 68 - 68: OoO0O00 + i1IIi / iIii1I11I1II1 + II111iiii * iIii1I11I1II1 + I1ii11iIi11i
  if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
  if 9 - 9: o0oOOo0O0Ooo
  if 55 - 55: OOooOOo % iIii1I11I1II1 + I11i . ooOoO0o
  if 71 - 71: i11iIiiIii / i1IIi + OoOoOO00
  if 23 - 23: i11iIiiIii
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 88 - 88: II111iiii - iII111i / OoooooooOO
  if 71 - 71: I1ii11iIi11i
  if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
  if 1 - 1: IiII % i1IIi
  if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
  if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
  if 80 - 80: I1ii11iIi11i
  if 67 - 67: II111iiii
  if 2 - 2: o0oOOo0O0Ooo - O0 * Ii1I % IiII
  if 64 - 64: i1IIi . ooOoO0o
  if 7 - 7: oO0o . iII111i - iII111i / I1Ii111 % Oo0Ooo
  if 61 - 61: oO0o - I1ii11iIi11i / iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
  if 10 - 10: i11iIiiIii / OoOoOO00
  if 27 - 27: I1IiiI / OoooooooOO
  if 74 - 74: I1ii11iIi11i % I1Ii111 - OoO0O00 * I11i . OoooooooOO * OoO0O00
  if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
  if 6 - 6: OOooOOo
  if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
class lisp_control_header ( ) :
 def __init__ ( self ) :
  self . type = 0
  self . record_count = 0
  self . nonce = 0
  self . rloc_probe = False
  self . smr_bit = False
  self . smr_invoked_bit = False
  self . ddt_bit = False
  self . to_etr = False
  self . to_ms = False
  self . info_reply = False
  if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
  if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
 def decode ( self , packet ) :
  Iii1 = "BBBBQ"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( False )
  if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
  i1ii , i11 , iiIii11I1 , self . record_count , self . nonce = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 60 - 60: OoooooooOO * Oo0Ooo % I1Ii111
  if 68 - 68: O0 - Oo0Ooo . II111iiii % Ii1I % Oo0Ooo + i11iIiiIii
  self . type = i1ii >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( i1ii & 0x01 ) else False
   self . rloc_probe = True if ( i1ii & 0x02 ) else False
   self . smr_invoked_bit = True if ( i11 & 0x40 ) else False
   if 90 - 90: II111iiii / OOooOOo * I1IiiI - Oo0Ooo
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( i1ii & 0x04 ) else False
   self . to_etr = True if ( i1ii & 0x02 ) else False
   self . to_ms = True if ( i1ii & 0x01 ) else False
   if 11 - 11: IiII - oO0o - oO0o / I1Ii111 * II111iiii % oO0o
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( i1ii & 0x08 ) else False
   if 39 - 39: oO0o / i11iIiiIii
  return ( True )
  if 46 - 46: i11iIiiIii . I1ii11iIi11i
  if 11 - 11: ooOoO0o
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 36 - 36: OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
  if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
  if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
  if 28 - 28: iIii1I11I1II1 . O0
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 32 - 32: OoooooooOO
  if 29 - 29: I1ii11iIi11i
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 41 - 41: Ii1I
  if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
  if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 94 - 94: IiII / I1IiiI . II111iiii
  if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
  if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
  if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
  if 49 - 49: I1ii11iIi11i
  if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
  if 18 - 18: Oo0Ooo + IiII
  if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
  if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
  if 31 - 31: Ii1I / iII111i
  if 3 - 3: IiII
  if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
  if 61 - 61: OOooOOo . OOooOOo
  if 17 - 17: II111iiii / ooOoO0o
  if 80 - 80: OOooOOo * OoO0O00 + Ii1I
  if 62 - 62: OoooooooOO . O0 % Oo0Ooo
  if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
  if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
  if 88 - 88: I1Ii111 - OoO0O00
  if 79 - 79: iII111i
  if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
  if 48 - 48: I1ii11iIi11i + Oo0Ooo
  if 76 - 76: I1ii11iIi11i
  if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
  if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
  if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
  if 82 - 82: OoO0O00
  if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
  if 17 - 17: OoOoOO00
  if 72 - 72: iII111i . Oo0Ooo - i11iIiiIii / I1IiiI
  if 64 - 64: oO0o
  if 80 - 80: o0oOOo0O0Ooo % iIii1I11I1II1
  if 63 - 63: IiII * i11iIiiIii
  if 86 - 86: I11i % I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
  if 26 - 26: II111iiii * iII111i + o0oOOo0O0Ooo / O0 + i1IIi - I11i
  if 56 - 56: OOooOOo
  if 76 - 76: i1IIi % iIii1I11I1II1 - o0oOOo0O0Ooo + IiII - I11i
  if 81 - 81: I1ii11iIi11i + OoooooooOO - OOooOOo * O0
  if 100 - 100: iIii1I11I1II1 - OoOoOO00
  if 28 - 28: Oo0Ooo . O0 . I11i
  if 60 - 60: II111iiii + I1Ii111 / oO0o % OoooooooOO - i1IIi
  if 57 - 57: ooOoO0o
  if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if 52 - 52: I1ii11iIi11i
  if 93 - 93: iII111i . i11iIiiIii
  if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
  if 49 - 49: O0 . Oo0Ooo / Ii1I
  if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
  if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
  if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  if 44 - 44: i11iIiiIii
class lisp_map_register ( ) :
 def __init__ ( self ) :
  self . proxy_reply_requested = False
  self . lisp_sec_present = False
  self . xtr_id_present = False
  self . map_notify_requested = False
  self . mobile_node = False
  self . merge_register_requested = False
  self . use_ttl_for_timeout = False
  self . map_register_refresh = False
  self . record_count = 0
  self . nonce = 0
  self . alg_id = 0
  self . key_id = 0
  self . auth_len = 0
  self . auth_data = 0
  self . xtr_id = 0
  self . site_id = 0
  self . record_count = 0
  self . sport = 0
  self . encrypt_bit = 0
  self . encryption_key_id = None
  if 69 - 69: OOooOOo * O0 + i11iIiiIii
  if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
 def print_map_register ( self ) :
  OOOo00OOooO = lisp_hex_string ( self . xtr_id )
  if 57 - 57: oO0o . o0oOOo0O0Ooo % I1ii11iIi11i - o0oOOo0O0Ooo
  OoO0o0OOOO = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 64 - 64: o0oOOo0O0Ooo
  lprint ( OoO0o0OOOO . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # Ii1I - i11iIiiIii . OoO0O00 % iII111i + I1ii11iIi11i
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , OOOo00OOooO , self . site_id ) )
  if 90 - 90: I1ii11iIi11i
  if 13 - 13: IiII . Oo0Ooo % oO0o * iII111i - i11iIiiIii / ooOoO0o
  if 56 - 56: I1Ii111
  if 90 - 90: O0 . I1IiiI + I1IiiI
 def encode ( self ) :
  i11iI1 = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : i11iI1 |= 0x08000000
  if ( self . lisp_sec_present ) : i11iI1 |= 0x04000000
  if ( self . xtr_id_present ) : i11iI1 |= 0x02000000
  if ( self . map_register_refresh ) : i11iI1 |= 0x1000
  if ( self . use_ttl_for_timeout ) : i11iI1 |= 0x800
  if ( self . merge_register_requested ) : i11iI1 |= 0x400
  if ( self . mobile_node ) : i11iI1 |= 0x200
  if ( self . map_notify_requested ) : i11iI1 |= 0x100
  if ( self . encryption_key_id != None ) :
   i11iI1 |= 0x2000
   i11iI1 |= self . encryption_key_id << 14
   if 96 - 96: I11i + iIii1I11I1II1 % II111iiii
   if 61 - 61: OOooOOo . I1ii11iIi11i * oO0o / I1Ii111 - OoO0O00
   if 18 - 18: I1Ii111
   if 34 - 34: iII111i + I1Ii111 * I11i / II111iiii
   if 14 - 14: II111iiii + iII111i + Ii1I / iII111i . iIii1I11I1II1
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 85 - 85: I11i % I11i . O0
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 40 - 40: OoO0O00 * OoOoOO00 * iIii1I11I1II1 / OoOoOO00 * OoooooooOO / I1ii11iIi11i
    if 33 - 33: i11iIiiIii % o0oOOo0O0Ooo . iII111i * OOooOOo / I11i
    if 25 - 25: OoO0O00
  oOo0O000oo0 = struct . pack ( "I" , socket . htonl ( i11iI1 ) )
  oOo0O000oo0 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 39 - 39: Ii1I * OoOoOO00 + Oo0Ooo . OOooOOo - O0 * I1ii11iIi11i
  oOo0O000oo0 = self . zero_auth ( oOo0O000oo0 )
  return ( oOo0O000oo0 )
  if 98 - 98: IiII * iII111i . OoooooooOO . O0
  if 89 - 89: iII111i / O0 % OoooooooOO - O0 . OoO0O00
 def zero_auth ( self , packet ) :
  O00O00O000OOO = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  ii11iI1Iii1iI = ""
  I1Iii11I = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   ii11iI1Iii1iI = struct . pack ( "QQI" , 0 , 0 , 0 )
   I1Iii11I = struct . calcsize ( "QQI" )
   if 74 - 74: o0oOOo0O0Ooo % OoOoOO00 . iII111i % I1Ii111 . O0 % II111iiii
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   ii11iI1Iii1iI = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   I1Iii11I = struct . calcsize ( "QQQQ" )
   if 5 - 5: oO0o - OoooooooOO / OoOoOO00
  packet = packet [ 0 : O00O00O000OOO ] + ii11iI1Iii1iI + packet [ O00O00O000OOO + I1Iii11I : : ]
  return ( packet )
  if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
  if 55 - 55: OoO0O00
 def encode_auth ( self , packet ) :
  O00O00O000OOO = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  I1Iii11I = self . auth_len
  ii11iI1Iii1iI = self . auth_data
  packet = packet [ 0 : O00O00O000OOO ] + ii11iI1Iii1iI + packet [ O00O00O000OOO + I1Iii11I : : ]
  return ( packet )
  if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
  if 32 - 32: Ii1I * oO0o
 def decode ( self , packet ) :
  ooOiiIII = packet
  Iii1 = "I"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( [ None , None ] )
  if 37 - 37: OoooooooOO / I1ii11iIi11i % o0oOOo0O0Ooo
  i11iI1 = struct . unpack ( Iii1 , packet [ : O00O ] )
  i11iI1 = socket . ntohl ( i11iI1 [ 0 ] )
  packet = packet [ O00O : : ]
  if 34 - 34: OoOoOO00 . I11i % oO0o - O0 * O0
  Iii1 = "QBBH"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( [ None , None ] )
  if 11 - 11: O0 * i11iIiiIii * II111iiii / OOooOOo * O0
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 71 - 71: I11i . Oo0Ooo
  if 24 - 24: OOooOOo * OoooooooOO . O0 . OoO0O00 . I1IiiI
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( i11iI1 & 0x08000000 ) else False
  if 80 - 80: O0 * OoO0O00 . I1Ii111 % O0
  self . lisp_sec_present = True if ( i11iI1 & 0x04000000 ) else False
  self . xtr_id_present = True if ( i11iI1 & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( i11iI1 & 0x800 ) else False
  self . map_register_refresh = True if ( i11iI1 & 0x1000 ) else False
  self . merge_register_requested = True if ( i11iI1 & 0x400 ) else False
  self . mobile_node = True if ( i11iI1 & 0x200 ) else False
  self . map_notify_requested = True if ( i11iI1 & 0x100 ) else False
  self . record_count = i11iI1 & 0xff
  if 12 - 12: OoooooooOO % IiII
  if 97 - 97: II111iiii % oO0o - II111iiii . ooOoO0o
  if 50 - 50: iII111i % I1ii11iIi11i + I11i * Oo0Ooo - i11iIiiIii
  if 24 - 24: i11iIiiIii . ooOoO0o + ooOoO0o - i11iIiiIii % OOooOOo
  self . encrypt_bit = True if i11iI1 & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( i11iI1 >> 14 ) & 0x7
   if 58 - 58: I1IiiI
   if 94 - 94: o0oOOo0O0Ooo + Ii1I % o0oOOo0O0Ooo . I1Ii111 - ooOoO0o * I1IiiI
   if 62 - 62: Oo0Ooo * i1IIi % I1ii11iIi11i + Oo0Ooo . O0 . ooOoO0o
   if 57 - 57: Oo0Ooo - I1Ii111 + O0 % o0oOOo0O0Ooo
   if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( ooOiiIII ) == False ) : return ( [ None , None ] )
   if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
   if 50 - 50: OoooooooOO * i1IIi / oO0o
  packet = packet [ O00O : : ]
  if 83 - 83: i1IIi
  if 38 - 38: OoooooooOO * iIii1I11I1II1
  if 54 - 54: OoooooooOO . I1Ii111
  if 71 - 71: Ii1I
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
    if 93 - 93: ooOoO0o % I1Ii111
   I1Iii11I = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    O00O = struct . calcsize ( "QQI" )
    if ( I1Iii11I < O00O ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
    i1I11iIIiIIiIi , ii1IiI , o0oO00O000O = struct . unpack ( "QQI" , packet [ : I1Iii11I ] )
    IiIIiIi1 = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    O00O = struct . calcsize ( "QQQQ" )
    if ( I1Iii11I < O00O ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 70 - 70: O0 % i11iIiiIii - O0
    i1I11iIIiIIiIi , ii1IiI , o0oO00O000O , IiIIiIi1 = struct . unpack ( "QQQQ" ,
 packet [ : I1Iii11I ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 100 - 100: o0oOOo0O0Ooo / oO0o % i1IIi
    return ( [ None , None ] )
    if 55 - 55: o0oOOo0O0Ooo * IiII - iII111i
   self . auth_data = lisp_concat_auth_data ( self . alg_id , i1I11iIIiIIiIi , ii1IiI ,
 o0oO00O000O , IiIIiIi1 )
   ooOiiIII = self . zero_auth ( ooOiiIII )
   packet = packet [ self . auth_len : : ]
   if 28 - 28: O0 / o0oOOo0O0Ooo . Ii1I / O0 . oO0o - o0oOOo0O0Ooo
  return ( [ ooOiiIII , packet ] )
  if 63 - 63: OOooOOo / II111iiii . OoOoOO00 / i1IIi / I11i . o0oOOo0O0Ooo
  if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
 def encode_xtr_id ( self , packet ) :
  Iii1ii1I1i1i1i1 = self . xtr_id >> 64
  iiii11 = self . xtr_id & 0xffffffffffffffff
  Iii1ii1I1i1i1i1 = byte_swap_64 ( Iii1ii1I1i1i1i1 )
  iiii11 = byte_swap_64 ( iiii11 )
  I1II = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , Iii1ii1I1i1i1i1 , iiii11 , I1II )
  return ( packet )
  if 91 - 91: o0oOOo0O0Ooo
  if 14 - 14: i11iIiiIii
 def decode_xtr_id ( self , packet ) :
  O00O = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < O00O ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - O00O : : ]
  Iii1ii1I1i1i1i1 , iiii11 , I1II = struct . unpack ( "QQQ" ,
 packet [ : O00O ] )
  Iii1ii1I1i1i1i1 = byte_swap_64 ( Iii1ii1I1i1i1i1 )
  iiii11 = byte_swap_64 ( iiii11 )
  self . xtr_id = ( Iii1ii1I1i1i1i1 << 64 ) | iiii11
  self . site_id = byte_swap_64 ( I1II )
  return ( True )
  if 17 - 17: IiII + I11i % Oo0Ooo + oO0o
  if 87 - 87: I11i
  if 54 - 54: Ii1I
  if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
  if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
  if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
  if 66 - 66: ooOoO0o + oO0o % OoooooooOO
  if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
  if 17 - 17: IiII
  if 12 - 12: i1IIi . OoO0O00
  if 14 - 14: OOooOOo + II111iiii % OOooOOo . oO0o * ooOoO0o
  if 54 - 54: ooOoO0o * I11i - I1Ii111
  if 15 - 15: iII111i / O0
  if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
  if 19 - 19: o0oOOo0O0Ooo . II111iiii / i1IIi
  if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
  if 47 - 47: I1ii11iIi11i * I1IiiI / I1ii11iIi11i + Ii1I * II111iiii
  if 78 - 78: I1Ii111 - i1IIi + OoOoOO00 + Oo0Ooo * I1ii11iIi11i * o0oOOo0O0Ooo
  if 97 - 97: i1IIi
  if 29 - 29: I1IiiI
  if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
  if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
  if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
  if 59 - 59: I1Ii111 * iII111i
  if 31 - 31: I11i / O0
  if 57 - 57: i1IIi % ooOoO0o
  if 69 - 69: o0oOOo0O0Ooo
  if 69 - 69: I1Ii111
  if 83 - 83: iIii1I11I1II1 . o0oOOo0O0Ooo + I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
  if 90 - 90: Ii1I * iII111i / OOooOOo
  if 68 - 68: OoOoOO00
  if 65 - 65: oO0o
  if 82 - 82: o0oOOo0O0Ooo
class lisp_map_notify ( ) :
 def __init__ ( self , lisp_sockets ) :
  self . etr = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . etr_port = 0
  self . retransmit_timer = None
  self . lisp_sockets = lisp_sockets
  self . retry_count = 0
  self . record_count = 0
  self . alg_id = LISP_NONE_ALG_ID
  self . key_id = 0
  self . auth_len = 0
  self . auth_data = ""
  self . nonce = 0
  self . nonce_key = ""
  self . packet = None
  self . site = ""
  self . map_notify_ack = False
  self . eid_records = ""
  self . eid_list = [ ]
  if 80 - 80: i1IIi % OoOoOO00 + OoO0O00 - OoooooooOO / iIii1I11I1II1 + I1Ii111
  if 65 - 65: Ii1I
 def print_notify ( self ) :
  ii11iI1Iii1iI = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( ii11iI1Iii1iI ) != 40 ) :
   ii11iI1Iii1iI = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( ii11iI1Iii1iI ) != 64 ) :
   ii11iI1Iii1iI = self . auth_data
   if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
  OoO0o0OOOO = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( OoO0o0OOOO . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # IiII
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , ii11iI1Iii1iI ) )
  if 18 - 18: I1IiiI
  if 32 - 32: iIii1I11I1II1 * I1IiiI . OOooOOo * iIii1I11I1II1
  if 92 - 92: oO0o - ooOoO0o . OoooooooOO * oO0o / Oo0Ooo
  if 16 - 16: I11i / OoooooooOO - IiII % I1IiiI % I11i
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   ii11iI1Iii1iI = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 97 - 97: OOooOOo * i1IIi / OoooooooOO
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   ii11iI1Iii1iI = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 64 - 64: OOooOOo + o0oOOo0O0Ooo / i11iIiiIii - OoOoOO00 + OOooOOo
  packet += ii11iI1Iii1iI
  return ( packet )
  if 90 - 90: i1IIi % OoO0O00 / ooOoO0o - O0 + i11iIiiIii
  if 98 - 98: OoooooooOO
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   i11iI1 = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   i11iI1 = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
  oOo0O000oo0 = struct . pack ( "I" , socket . htonl ( i11iI1 ) )
  oOo0O000oo0 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = oOo0O000oo0 + eid_records
   return ( self . packet )
   if 71 - 71: Ii1I * OoOoOO00
   if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
   if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
   if 87 - 87: OoO0O00 * Oo0Ooo
   if 83 - 83: i1IIi * I1Ii111 - IiII / Ii1I
  oOo0O000oo0 = self . zero_auth ( oOo0O000oo0 )
  oOo0O000oo0 += eid_records
  if 48 - 48: oO0o . II111iiii - OoOoOO00 % i1IIi . OoOoOO00
  IiiiII = lisp_hash_me ( oOo0O000oo0 , self . alg_id , password , False )
  if 32 - 32: Ii1I * I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
  O00O00O000OOO = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  I1Iii11I = self . auth_len
  self . auth_data = IiiiII
  oOo0O000oo0 = oOo0O000oo0 [ 0 : O00O00O000OOO ] + IiiiII + oOo0O000oo0 [ O00O00O000OOO + I1Iii11I : : ]
  self . packet = oOo0O000oo0
  return ( oOo0O000oo0 )
  if 67 - 67: OoOoOO00 % Oo0Ooo
  if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
 def decode ( self , packet ) :
  ooOiiIII = packet
  Iii1 = "I"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 73 - 73: I1ii11iIi11i
  i11iI1 = struct . unpack ( Iii1 , packet [ : O00O ] )
  i11iI1 = socket . ntohl ( i11iI1 [ 0 ] )
  self . map_notify_ack = ( ( i11iI1 >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = i11iI1 & 0xff
  packet = packet [ O00O : : ]
  if 92 - 92: i11iIiiIii + O0 * I11i
  Iii1 = "QBBH"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 60 - 60: o0oOOo0O0Ooo / Oo0Ooo
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ O00O : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 76 - 76: OoO0O00 * oO0o - OoO0O00
  if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
  if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
  if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 70 - 70: O0 . Ii1I
  I1Iii11I = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   i1I11iIIiIIiIi , ii1IiI , o0oO00O000O = struct . unpack ( "QQI" , packet [ : I1Iii11I ] )
   IiIIiIi1 = ""
   if 33 - 33: OOooOOo * Ii1I
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   i1I11iIIiIIiIi , ii1IiI , o0oO00O000O , IiIIiIi1 = struct . unpack ( "QQQQ" ,
 packet [ : I1Iii11I ] )
   if 64 - 64: i11iIiiIii . iIii1I11I1II1
  self . auth_data = lisp_concat_auth_data ( self . alg_id , i1I11iIIiIIiIi , ii1IiI ,
 o0oO00O000O , IiIIiIi1 )
  if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
  O00O = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( ooOiiIII [ : O00O ] )
  O00O += I1Iii11I
  packet += ooOiiIII [ O00O : : ]
  return ( packet )
  if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
  if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
  if 70 - 70: I11i . I1ii11iIi11i * oO0o
  if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
  if 23 - 23: I1ii11iIi11i % I11i
  if 18 - 18: OoooooooOO . i1IIi + II111iiii
  if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
  if 34 - 34: I1Ii111 * I11i
  if 31 - 31: IiII . oO0o
  if 40 - 40: Ii1I - I11i / II111iiii * i1IIi + IiII * II111iiii
  if 53 - 53: I1ii11iIi11i - i11iIiiIii . OoO0O00 / OoOoOO00 - I1Ii111
  if 99 - 99: Ii1I - IiII - i1IIi / i11iIiiIii . IiII
  if 58 - 58: OOooOOo
  if 12 - 12: I1IiiI . o0oOOo0O0Ooo * OoooooooOO
  if 64 - 64: OoOoOO00 + IiII - i1IIi . II111iiii . OoO0O00
  if 31 - 31: oO0o . iII111i - I11i . iIii1I11I1II1 + I11i . OoOoOO00
  if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
  if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
  if 30 - 30: OoooooooOO % OOooOOo
  if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
  if 81 - 81: iII111i % Ii1I . ooOoO0o
  if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
  if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
  if 20 - 20: ooOoO0o
  if 63 - 63: iIii1I11I1II1 . OoO0O00
  if 100 - 100: i1IIi * i1IIi
  if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
  if 94 - 94: IiII
  if 15 - 15: Ii1I - IiII / O0
  if 28 - 28: I1Ii111 . i1IIi / I1ii11iIi11i
  if 77 - 77: i11iIiiIii / I1Ii111 / i11iIiiIii % OoOoOO00 - I1Ii111
  if 80 - 80: I1Ii111 % OoOoOO00 . OoooooooOO . II111iiii % IiII
  if 6 - 6: I1Ii111 % IiII / Ii1I + I1Ii111 . oO0o
  if 70 - 70: iIii1I11I1II1 / Ii1I
  if 61 - 61: O0 * o0oOOo0O0Ooo + I1Ii111 - OOooOOo . I1IiiI - IiII
  if 7 - 7: I1ii11iIi11i
  if 81 - 81: Oo0Ooo % II111iiii % o0oOOo0O0Ooo / I11i
  if 95 - 95: OoOoOO00 - O0 % OoooooooOO
  if 13 - 13: i11iIiiIii
  if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
  if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
  if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
  if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
  if 69 - 69: Oo0Ooo * ooOoO0o
  if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
  if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
  if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
  if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
  if 24 - 24: OoOoOO00 * Ii1I
class lisp_map_request ( ) :
 def __init__ ( self ) :
  self . auth_bit = False
  self . map_data_present = False
  self . rloc_probe = False
  self . smr_bit = False
  self . pitr_bit = False
  self . smr_invoked_bit = False
  self . mobile_node = False
  self . xtr_id_present = False
  self . local_xtr = False
  self . dont_reply_bit = False
  self . itr_rloc_count = 0
  self . record_count = 0
  self . nonce = 0
  self . signature_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . target_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . target_group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . itr_rlocs = [ ]
  self . keys = None
  self . privkey_filename = None
  self . map_request_signature = None
  self . subscribe_bit = False
  self . xtr_id = None
  if 17 - 17: OoO0O00 . I1IiiI * O0
  if 81 - 81: OOooOOo
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 41 - 41: I11i + OoO0O00 . iII111i
  if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
 def print_map_request ( self ) :
  OOOo00OOooO = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   OOOo00OOooO = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 56 - 56: i1IIi
   if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
   if 82 - 82: IiII
  OoO0o0OOOO = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 10 - 10: Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
  lprint ( OoO0o0OOOO . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # II111iiii * Ii1I . I1IiiI . I1ii11iIi11i
 "D" if self . map_data_present else "d" ,
 "R" if self . rloc_probe else "r" ,
 "S" if self . smr_bit else "s" ,
 "P" if self . pitr_bit else "p" ,
 "I" if self . smr_invoked_bit else "i" ,
 "M" if self . mobile_node else "m" ,
 "X" if self . xtr_id_present else "x" ,
 "L" if self . local_xtr else "l" ,
 "D" if self . dont_reply_bit else "d" , self . itr_rloc_count ,
 self . record_count , lisp_hex_string ( self . nonce ) ,
 self . source_eid . afi , green ( self . source_eid . print_address ( ) , False ) ,
 " (with sig)" if self . map_request_signature != None else "" ,
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , OOOo00OOooO ) )
  if 6 - 6: iIii1I11I1II1 / iII111i
  iIIi111IiII1i = self . keys
  for I11I in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( I11I . afi ,
 red ( I11I . print_address_no_iid ( ) , False ) ,
 "" if ( iIIi111IiII1i == None ) else ", " + iIIi111IiII1i [ 1 ] . print_keys ( ) ) )
   iIIi111IiII1i = None
   if 64 - 64: o0oOOo0O0Ooo % ooOoO0o % oO0o
   if 29 - 29: Ii1I % OoO0O00 . II111iiii . oO0o / OoO0O00 % iIii1I11I1II1
   if 8 - 8: O0 / II111iiii
 def sign_map_request ( self , privkey ) :
  Oo000O00o0O = self . signature_eid . print_address ( )
  o0o0oo0oO = self . source_eid . print_address ( )
  Ii1iii1 = self . target_eid . print_address ( )
  OO0o = lisp_hex_string ( self . nonce ) + o0o0oo0oO + Ii1iii1
  self . map_request_signature = privkey . sign ( OO0o )
  ooOo = binascii . b2a_base64 ( self . map_request_signature )
  ooOo = { "source-eid" : o0o0oo0oO , "signature-eid" : Oo000O00o0O ,
 "signature" : ooOo }
  return ( json . dumps ( ooOo ) )
  if 71 - 71: OoooooooOO - iII111i + Ii1I / O0 % o0oOOo0O0Ooo + OoO0O00
  if 83 - 83: IiII * I1ii11iIi11i / IiII * IiII - OOooOOo
 def verify_map_request_sig ( self , pubkey ) :
  oO0OO00000o = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( oO0OO00000o ) )
   return ( False )
   if 46 - 46: ooOoO0o - iIii1I11I1II1
   if 98 - 98: Ii1I - i1IIi
  o0o0oo0oO = self . source_eid . print_address ( )
  Ii1iii1 = self . target_eid . print_address ( )
  OO0o = lisp_hex_string ( self . nonce ) + o0o0oo0oO + Ii1iii1
  pubkey = binascii . a2b_base64 ( pubkey )
  if 23 - 23: o0oOOo0O0Ooo . ooOoO0o - OoooooooOO + I11i
  o000o0O = True
  try :
   OOo0O = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 39 - 39: oO0o + I1ii11iIi11i + IiII . o0oOOo0O0Ooo
   o000o0O = False
   if 11 - 11: Ii1I / OoOoOO00 - OoO0O00 + OoOoOO00
   if 51 - 51: ooOoO0o
  if ( o000o0O ) :
   try :
    o000o0O = OOo0O . verify ( self . map_request_signature , OO0o )
   except :
    o000o0O = False
    if 42 - 42: o0oOOo0O0Ooo - OOooOOo / OOooOOo / iII111i * Oo0Ooo . Oo0Ooo
    if 96 - 96: OoooooooOO + I1ii11iIi11i * O0
    if 33 - 33: I1ii11iIi11i - IiII
  i1IiIii1i = bold ( "passed" if o000o0O else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( i1IiIii1i , oO0OO00000o ) )
  return ( o000o0O )
  if 27 - 27: OoO0O00 % ooOoO0o - O0
  if 44 - 44: I1ii11iIi11i + I1ii11iIi11i - OOooOOo / II111iiii
 def encode ( self , probe_dest , probe_port ) :
  i11iI1 = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  i11iI1 = i11iI1 | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : i11iI1 |= 0x08000000
  if ( self . map_data_present ) : i11iI1 |= 0x04000000
  if ( self . rloc_probe ) : i11iI1 |= 0x02000000
  if ( self . smr_bit ) : i11iI1 |= 0x01000000
  if ( self . pitr_bit ) : i11iI1 |= 0x00800000
  if ( self . smr_invoked_bit ) : i11iI1 |= 0x00400000
  if ( self . mobile_node ) : i11iI1 |= 0x00200000
  if ( self . xtr_id_present ) : i11iI1 |= 0x00100000
  if ( self . local_xtr ) : i11iI1 |= 0x00004000
  if ( self . dont_reply_bit ) : i11iI1 |= 0x00002000
  if 36 - 36: OoO0O00 - o0oOOo0O0Ooo . iII111i % iII111i
  oOo0O000oo0 = struct . pack ( "I" , socket . htonl ( i11iI1 ) )
  oOo0O000oo0 += struct . pack ( "Q" , self . nonce )
  if 12 - 12: OoOoOO00 / I1IiiI * Oo0Ooo
  if 59 - 59: Oo0Ooo . o0oOOo0O0Ooo % I1IiiI / OoooooooOO % oO0o
  if 81 - 81: OoooooooOO / ooOoO0o * iIii1I11I1II1 . Oo0Ooo + oO0o / O0
  if 84 - 84: II111iiii - o0oOOo0O0Ooo
  if 78 - 78: IiII
  if 58 - 58: i11iIiiIii - OoOoOO00
  OOO0 = False
  o0oo00 = self . privkey_filename
  if ( o0oo00 != None and os . path . exists ( o0oo00 ) ) :
   o000 = open ( o0oo00 , "r" ) ; OOo0O = o000 . read ( ) ; o000 . close ( )
   try :
    OOo0O = ecdsa . SigningKey . from_pem ( OOo0O )
   except :
    return ( None )
    if 41 - 41: I1ii11iIi11i * i11iIiiIii - Oo0Ooo * II111iiii
   OOO0oOO0ooOO = self . sign_map_request ( OOo0O )
   OOO0 = True
  elif ( self . map_request_signature != None ) :
   ooOo = binascii . b2a_base64 ( self . map_request_signature )
   OOO0oOO0ooOO = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : ooOo }
   OOO0oOO0ooOO = json . dumps ( OOO0oOO0ooOO )
   OOO0 = True
   if 65 - 65: iIii1I11I1II1
  if ( OOO0 ) :
   ii1i = LISP_LCAF_JSON_TYPE
   ooo0o0oOoOO0 = socket . htons ( LISP_AFI_LCAF )
   OOooo0o0OOO = socket . htons ( len ( OOO0oOO0ooOO ) + 2 )
   i1iI = socket . htons ( len ( OOO0oOO0ooOO ) )
   oOo0O000oo0 += struct . pack ( "HBBBBHH" , ooo0o0oOoOO0 , 0 , 0 , ii1i , 0 ,
 OOooo0o0OOO , i1iI )
   oOo0O000oo0 += OOO0oOO0ooOO
   oOo0O000oo0 += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    oOo0O000oo0 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    oOo0O000oo0 += self . source_eid . lcaf_encode_iid ( )
   else :
    oOo0O000oo0 += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    oOo0O000oo0 += self . source_eid . pack_address ( )
    if 34 - 34: OOooOOo - OoO0O00
    if 3 - 3: Oo0Ooo + OOooOOo - I1IiiI
    if 60 - 60: O0 / i1IIi % i11iIiiIii / iII111i
    if 97 - 97: i1IIi % OoooooooOO
    if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
    if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
    if 35 - 35: I1ii11iIi11i % OoooooooOO
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   O0o = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 59 - 59: I1IiiI % I11i
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( O0o ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ O0o ]
    if 32 - 32: I1IiiI * O0 + O0
    if 34 - 34: IiII
    if 5 - 5: OoO0O00 . I1IiiI
    if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
    if 47 - 47: iII111i / OoooooooOO - II111iiii
    if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
    if 23 - 23: i1IIi
  for I11I in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( I11I ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     iIIi111IiII1i = lisp_keys ( 1 )
     self . keys = [ None , iIIi111IiII1i , None , None ]
     if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
    iIIi111IiII1i = self . keys [ 1 ]
    iIIi111IiII1i . add_key_by_nonce ( self . nonce )
    oOo0O000oo0 += iIIi111IiII1i . encode_lcaf ( I11I )
   else :
    oOo0O000oo0 += struct . pack ( "H" , socket . htons ( I11I . afi ) )
    oOo0O000oo0 += I11I . pack_address ( )
    if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
    if 31 - 31: I1Ii111 - I11i
    if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
  oo0Ooo = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 21 - 21: I1ii11iIi11i - oO0o * OoO0O00
  if 98 - 98: I1ii11iIi11i - OOooOOo % iIii1I11I1II1
  OOOo00o = 0
  if ( self . subscribe_bit ) :
   OOOo00o = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 71 - 71: o0oOOo0O0Ooo + OoooooooOO * II111iiii / I1Ii111
    if 78 - 78: I1Ii111 % OOooOOo
    if 73 - 73: I1ii11iIi11i + iII111i * I1IiiI * I11i
  Iii1 = "BB"
  oOo0O000oo0 += struct . pack ( Iii1 , OOOo00o , oo0Ooo )
  if 35 - 35: I11i * O0 * OoO0O00 . I1ii11iIi11i
  if ( self . target_group . is_null ( ) == False ) :
   oOo0O000oo0 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   oOo0O000oo0 += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   oOo0O000oo0 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   oOo0O000oo0 += self . target_eid . lcaf_encode_iid ( )
  else :
   oOo0O000oo0 += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   oOo0O000oo0 += self . target_eid . pack_address ( )
   if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
   if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
   if 97 - 97: Ii1I % i1IIi % IiII + Oo0Ooo - O0 - I11i
   if 64 - 64: Ii1I - iII111i
   if 12 - 12: i1IIi
  if ( self . subscribe_bit ) : oOo0O000oo0 = self . encode_xtr_id ( oOo0O000oo0 )
  return ( oOo0O000oo0 )
  if 99 - 99: II111iiii - I1ii11iIi11i * IiII
  if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
 def lcaf_decode_json ( self , packet ) :
  Iii1 = "BBBBHH"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 15 - 15: I1ii11iIi11i * Ii1I / iII111i . o0oOOo0O0Ooo / Ii1I % OoOoOO00
  Oo0o0ooOo0 , OoOoo0ooO0000 , ii1i , ii1iiI11III1 , OOooo0o0OOO , i1iI = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 8 - 8: I1ii11iIi11i - i1IIi - oO0o / oO0o % o0oOOo0O0Ooo
  if 98 - 98: OoO0O00 * ooOoO0o + i1IIi + IiII - i1IIi % OoOoOO00
  if ( ii1i != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 19 - 19: iIii1I11I1II1 * Oo0Ooo / OOooOOo
  if 5 - 5: o0oOOo0O0Ooo
  if 24 - 24: IiII + OoO0O00 - Ii1I
  if 38 - 38: I1Ii111
  OOooo0o0OOO = socket . ntohs ( OOooo0o0OOO )
  i1iI = socket . ntohs ( i1iI )
  packet = packet [ O00O : : ]
  if ( len ( packet ) < OOooo0o0OOO ) : return ( None )
  if ( OOooo0o0OOO != i1iI + 2 ) : return ( None )
  if 30 - 30: II111iiii + I11i . i11iIiiIii + iIii1I11I1II1
  if 100 - 100: oO0o * o0oOOo0O0Ooo / iII111i
  if 92 - 92: ooOoO0o / i11iIiiIii * OOooOOo
  if 55 - 55: ooOoO0o
  try :
   OOO0oOO0ooOO = json . loads ( packet [ 0 : i1iI ] )
  except :
   return ( None )
   if 1 - 1: OoO0O00
  packet = packet [ i1iI : : ]
  if 43 - 43: iIii1I11I1II1 - OOooOOo - o0oOOo0O0Ooo + I1ii11iIi11i - I1Ii111 % I1ii11iIi11i
  if 58 - 58: OoOoOO00
  if 27 - 27: IiII * OOooOOo - OoooooooOO . Ii1I - II111iiii
  if 62 - 62: I1IiiI / iIii1I11I1II1 * I11i
  Iii1 = "H"
  O00O = struct . calcsize ( Iii1 )
  ii1iI1i1 = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
  packet = packet [ O00O : : ]
  if ( ii1iI1i1 != 0 ) : return ( packet )
  if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
  if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
  if 24 - 24: OoO0O00 % O0 % I11i
  if ( OOO0oOO0ooOO . has_key ( "source-eid" ) == False ) : return ( packet )
  O0oOoooooooOo00O = OOO0oOO0ooOO [ "source-eid" ]
  ii1iI1i1 = LISP_AFI_IPV4 if O0oOoooooooOo00O . count ( "." ) == 3 else LISP_AFI_IPV6 if O0oOoooooooOo00O . count ( ":" ) == 7 else None
  if 73 - 73: i11iIiiIii + O0 % O0
  if ( ii1iI1i1 == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( O0oOoooooooOo00O ) )
   return ( None )
   if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
   if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  self . source_eid . afi = ii1iI1i1
  self . source_eid . store_address ( O0oOoooooooOo00O )
  if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
  if ( OOO0oOO0ooOO . has_key ( "signature-eid" ) == False ) : return ( packet )
  O0oOoooooooOo00O = OOO0oOO0ooOO [ "signature-eid" ]
  if ( O0oOoooooooOo00O . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( O0oOoooooooOo00O ) )
   return ( None )
   if 18 - 18: OoOoOO00
   if 30 - 30: II111iiii
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( O0oOoooooooOo00O )
  if 27 - 27: i1IIi - iIii1I11I1II1 + O0 % Oo0Ooo / OOooOOo + i1IIi
  if ( OOO0oOO0ooOO . has_key ( "signature" ) == False ) : return ( packet )
  ooOo = binascii . a2b_base64 ( OOO0oOO0ooOO [ "signature" ] )
  self . map_request_signature = ooOo
  return ( packet )
  if 48 - 48: Oo0Ooo
  if 70 - 70: OoooooooOO * i11iIiiIii
 def decode ( self , packet , source , port ) :
  Iii1 = "I"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 60 - 60: IiII / iIii1I11I1II1 + OoooooooOO - I1ii11iIi11i * i11iIiiIii
  i11iI1 = struct . unpack ( Iii1 , packet [ : O00O ] )
  i11iI1 = i11iI1 [ 0 ]
  packet = packet [ O00O : : ]
  if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
  Iii1 = "Q"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 47 - 47: Ii1I . OoOoOO00 . iIii1I11I1II1 . o0oOOo0O0Ooo
  OoI1 = struct . unpack ( Iii1 , packet [ : O00O ] )
  packet = packet [ O00O : : ]
  if 39 - 39: o0oOOo0O0Ooo
  i11iI1 = socket . ntohl ( i11iI1 )
  self . auth_bit = True if ( i11iI1 & 0x08000000 ) else False
  self . map_data_present = True if ( i11iI1 & 0x04000000 ) else False
  self . rloc_probe = True if ( i11iI1 & 0x02000000 ) else False
  self . smr_bit = True if ( i11iI1 & 0x01000000 ) else False
  self . pitr_bit = True if ( i11iI1 & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( i11iI1 & 0x00400000 ) else False
  self . mobile_node = True if ( i11iI1 & 0x00200000 ) else False
  self . xtr_id_present = True if ( i11iI1 & 0x00100000 ) else False
  self . local_xtr = True if ( i11iI1 & 0x00004000 ) else False
  self . dont_reply_bit = True if ( i11iI1 & 0x00002000 ) else False
  self . itr_rloc_count = ( ( i11iI1 >> 8 ) & 0x1f ) + 1
  self . record_count = i11iI1 & 0xff
  self . nonce = OoI1 [ 0 ]
  if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
  if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
  if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
  if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
   if 8 - 8: I11i % ooOoO0o . iIii1I11I1II1
  O00O = struct . calcsize ( "H" )
  if ( len ( packet ) < O00O ) : return ( None )
  if 95 - 95: o0oOOo0O0Ooo + i11iIiiIii . I1ii11iIi11i . ooOoO0o . o0oOOo0O0Ooo
  ii1iI1i1 = struct . unpack ( "H" , packet [ : O00O ] )
  self . source_eid . afi = socket . ntohs ( ii1iI1i1 [ 0 ] )
  packet = packet [ O00O : : ]
  if 93 - 93: iII111i
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   ooOOOOO000o = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( ooOOOOO000o )
    if ( packet == None ) : return ( None )
    if 47 - 47: o0oOOo0O0Ooo * OoOoOO00 / I11i . OOooOOo + ooOoO0o * iIii1I11I1II1
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 4 - 4: iIii1I11I1II1 * OoO0O00
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 5 - 5: Ii1I % Ii1I * I1Ii111
  IiiiiIIi1i = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  while ( self . itr_rloc_count != 0 ) :
   O00O = struct . calcsize ( "H" )
   if ( len ( packet ) < O00O ) : return ( None )
   if 16 - 16: OoO0O00 * II111iiii
   ii1iI1i1 = struct . unpack ( "H" , packet [ : O00O ] ) [ 0 ]
   if 19 - 19: O0 . I11i . I1Ii111 + i11iIiiIii . I1Ii111
   I11I = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   I11I . afi = socket . ntohs ( ii1iI1i1 )
   if 1 - 1: O0 / i11iIiiIii
   if 52 - 52: I11i / OoO0O00
   if 24 - 24: i11iIiiIii
   if 52 - 52: ooOoO0o % iIii1I11I1II1 . i11iIiiIii % ooOoO0o
   if 86 - 86: oO0o % iIii1I11I1II1 % OoOoOO00
   if ( I11I . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < I11I . addr_length ( ) ) : return ( None )
    packet = I11I . unpack_address ( packet [ O00O : : ] )
    if ( packet == None ) : return ( None )
    if 94 - 94: o0oOOo0O0Ooo - I11i % oO0o % o0oOOo0O0Ooo + I11i
    if ( IiiiiIIi1i ) :
     self . itr_rlocs . append ( I11I )
     self . itr_rloc_count -= 1
     continue
     if 31 - 31: I1Ii111 * o0oOOo0O0Ooo * II111iiii + O0 / iII111i * ooOoO0o
     if 52 - 52: iIii1I11I1II1 / iII111i . O0 * IiII . I1IiiI
    O0o = lisp_build_crypto_decap_lookup_key ( I11I , port )
    if 67 - 67: II111iiii + Ii1I - I1IiiI * ooOoO0o
    if 19 - 19: i11iIiiIii * Oo0Ooo
    if 33 - 33: i11iIiiIii + I1IiiI
    if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
    if 6 - 6: IiII
    if ( lisp_nat_traversal and I11I . is_private_address ( ) and source ) : I11I = source
    if 73 - 73: o0oOOo0O0Ooo % o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i - Ii1I
    ooOOooooo0Oo = lisp_crypto_keys_by_rloc_decap
    if ( ooOOooooo0Oo . has_key ( O0o ) ) : ooOOooooo0Oo . pop ( O0o )
    if 32 - 32: ooOoO0o / II111iiii . O0 . ooOoO0o % I1IiiI - o0oOOo0O0Ooo
    if 69 - 69: Ii1I - I1IiiI * OOooOOo . iIii1I11I1II1 * OoOoOO00 . OoooooooOO
    if 6 - 6: O0 . o0oOOo0O0Ooo - OoOoOO00
    if 3 - 3: OoooooooOO % iIii1I11I1II1 * I1Ii111 % Oo0Ooo + iIii1I11I1II1
    if 66 - 66: Oo0Ooo - OoOoOO00
    if 43 - 43: iII111i / I1Ii111 * I1IiiI % ooOoO0o % I1IiiI
    lisp_write_ipc_decap_key ( O0o , None )
   else :
    ooOiiIII = packet
    i11i1iI = lisp_keys ( 1 )
    packet = i11i1iI . decode_lcaf ( ooOiiIII , 0 )
    if ( packet == None ) : return ( None )
    if 34 - 34: OoOoOO00
    if 75 - 75: I11i / iIii1I11I1II1 + I1ii11iIi11i / OoO0O00
    if 50 - 50: I1Ii111 / I11i % iIii1I11I1II1
    if 46 - 46: ooOoO0o + iII111i - Oo0Ooo % OOooOOo + OoooooooOO + iIii1I11I1II1
    iII1i = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( i11i1iI . cipher_suite in iII1i ) :
     if ( i11i1iI . cipher_suite == LISP_CS_25519_CBC or
 i11i1iI . cipher_suite == LISP_CS_25519_GCM ) :
      OOo0O = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 99 - 99: OoO0O00 - IiII * IiII + oO0o / iII111i + OOooOOo
     if ( i11i1iI . cipher_suite == LISP_CS_25519_CHACHA ) :
      OOo0O = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 58 - 58: i11iIiiIii + iIii1I11I1II1 * o0oOOo0O0Ooo - OoOoOO00
    else :
     OOo0O = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 31 - 31: i1IIi
    packet = OOo0O . decode_lcaf ( ooOiiIII , 0 )
    if ( packet == None ) : return ( None )
    if 87 - 87: I1IiiI / I11i + OoooooooOO + O0 . Ii1I
    if ( len ( packet ) < O00O ) : return ( None )
    ii1iI1i1 = struct . unpack ( "H" , packet [ : O00O ] ) [ 0 ]
    I11I . afi = socket . ntohs ( ii1iI1i1 )
    if ( len ( packet ) < I11I . addr_length ( ) ) : return ( None )
    if 44 - 44: Oo0Ooo % Oo0Ooo
    packet = I11I . unpack_address ( packet [ O00O : : ] )
    if ( packet == None ) : return ( None )
    if 58 - 58: OOooOOo * II111iiii
    if ( IiiiiIIi1i ) :
     self . itr_rlocs . append ( I11I )
     self . itr_rloc_count -= 1
     continue
     if 29 - 29: iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / OoOoOO00 - i11iIiiIii
     if 67 - 67: OOooOOo / Ii1I
    O0o = lisp_build_crypto_decap_lookup_key ( I11I , port )
    if 51 - 51: I11i % II111iiii - o0oOOo0O0Ooo % OoO0O00 * i11iIiiIii * iII111i
    Oo0o = None
    if ( lisp_nat_traversal and I11I . is_private_address ( ) and source ) : I11I = source
    if 66 - 66: OoooooooOO % IiII
    if 12 - 12: I11i / i11iIiiIii - I1Ii111
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( O0o ) ) :
     iIIi111IiII1i = lisp_crypto_keys_by_rloc_decap [ O0o ]
     Oo0o = iIIi111IiII1i [ 1 ] if iIIi111IiII1i and iIIi111IiII1i [ 1 ] else None
     if 50 - 50: I11i
     if 88 - 88: i1IIi * OOooOOo . iIii1I11I1II1
    I1iii1i1I = True
    if ( Oo0o ) :
     if ( Oo0o . compare_keys ( OOo0O ) ) :
      self . keys = [ None , Oo0o , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( O0o , False ) ) )
      if 12 - 12: OOooOOo
     else :
      I1iii1i1I = False
      OOO0oOO = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( OOO0oOO , red ( O0o ,
 False ) ) )
      OOo0O . copy_keypair ( Oo0o )
      OOo0O . uptime = Oo0o . uptime
      Oo0o = None
      if 93 - 93: OOooOOo * Ii1I - o0oOOo0O0Ooo . oO0o . iII111i
      if 64 - 64: Oo0Ooo / iIii1I11I1II1 . OoO0O00 / o0oOOo0O0Ooo / I11i
      if 3 - 3: OOooOOo - o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
    if ( Oo0o == None ) :
     self . keys = [ None , OOo0O , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      OOo0O . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( O0o , False ) ) )
     elif ( OOo0O . remote_public_key != None ) :
      if ( I1iii1i1I ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # i11iIiiIii
 red ( O0o , False ) ) )
       if 70 - 70: oO0o
      OOo0O . compute_shared_key ( "decap" )
      OOo0O . add_key_by_rloc ( O0o , False )
      if 98 - 98: IiII
      if 68 - 68: ooOoO0o - OoOoOO00 / OoooooooOO . i1IIi + OoO0O00 + IiII
      if 90 - 90: Ii1I
      if 55 - 55: Oo0Ooo % IiII + i11iIiiIii - OOooOOo - II111iiii
   self . itr_rlocs . append ( I11I )
   self . itr_rloc_count -= 1
   if 80 - 80: IiII
   if 97 - 97: iII111i
  O00O = struct . calcsize ( "BBH" )
  if ( len ( packet ) < O00O ) : return ( None )
  if 40 - 40: ooOoO0o
  OOOo00o , oo0Ooo , ii1iI1i1 = struct . unpack ( "BBH" , packet [ : O00O ] )
  self . subscribe_bit = ( OOOo00o & 0x80 )
  self . target_eid . afi = socket . ntohs ( ii1iI1i1 )
  packet = packet [ O00O : : ]
  if 61 - 61: iII111i - OOooOOo / iII111i . Oo0Ooo % OoO0O00
  self . target_eid . mask_len = oo0Ooo
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , o0O00oo0000O = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( o0O00oo0000O ) : self . target_group = o0O00oo0000O
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ O00O : : ]
   if 1 - 1: Oo0Ooo / ooOoO0o * Ii1I - OoooooooOO * I11i * OOooOOo
  return ( packet )
  if 63 - 63: II111iiii - o0oOOo0O0Ooo * i11iIiiIii / I11i * iII111i - iII111i
  if 32 - 32: Oo0Ooo . O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 48 - 48: I1ii11iIi11i % II111iiii + I11i
  if 25 - 25: IiII * o0oOOo0O0Ooo / I1IiiI . IiII % II111iiii
 def encode_xtr_id ( self , packet ) :
  Iii1ii1I1i1i1i1 = self . xtr_id >> 64
  iiii11 = self . xtr_id & 0xffffffffffffffff
  Iii1ii1I1i1i1i1 = byte_swap_64 ( Iii1ii1I1i1i1i1 )
  iiii11 = byte_swap_64 ( iiii11 )
  packet += struct . pack ( "QQ" , Iii1ii1I1i1i1i1 , iiii11 )
  return ( packet )
  if 50 - 50: OoOoOO00 * iII111i
  if 59 - 59: I1IiiI * I1IiiI / I11i
 def decode_xtr_id ( self , packet ) :
  O00O = struct . calcsize ( "QQ" )
  if ( len ( packet ) < O00O ) : return ( None )
  packet = packet [ len ( packet ) - O00O : : ]
  Iii1ii1I1i1i1i1 , iiii11 = struct . unpack ( "QQ" , packet [ : O00O ] )
  Iii1ii1I1i1i1i1 = byte_swap_64 ( Iii1ii1I1i1i1i1 )
  iiii11 = byte_swap_64 ( iiii11 )
  self . xtr_id = ( Iii1ii1I1i1i1i1 << 64 ) | iiii11
  return ( True )
  if 92 - 92: o0oOOo0O0Ooo
  if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
  if 50 - 50: Oo0Ooo
  if 16 - 16: Ii1I - OoOoOO00 % Oo0Ooo / Ii1I . I11i + ooOoO0o
  if 78 - 78: iIii1I11I1II1 + OoO0O00 + i11iIiiIii
  if 21 - 21: Oo0Ooo + Ii1I % ooOoO0o + OoOoOO00 % I11i
  if 22 - 22: i1IIi / OoooooooOO . OoO0O00
  if 83 - 83: I1IiiI - OoooooooOO + I1ii11iIi11i . Ii1I / o0oOOo0O0Ooo + ooOoO0o
  if 90 - 90: I1IiiI - i11iIiiIii
  if 42 - 42: OOooOOo . Oo0Ooo
  if 21 - 21: iII111i . I1IiiI / I11i
  if 97 - 97: iIii1I11I1II1 + i1IIi - o0oOOo0O0Ooo
  if 73 - 73: OoO0O00 - i11iIiiIii % I1Ii111 / Oo0Ooo - OoooooooOO % OOooOOo
  if 79 - 79: I1IiiI / o0oOOo0O0Ooo . Ii1I * I1ii11iIi11i + I11i
  if 96 - 96: OoO0O00 * II111iiii
  if 1 - 1: I1IiiI - OoOoOO00
  if 74 - 74: OoOoOO00 * II111iiii + O0 + I11i
  if 3 - 3: iIii1I11I1II1 - i1IIi / iII111i + i1IIi + O0
  if 18 - 18: iIii1I11I1II1 . iII111i % OOooOOo % oO0o + iIii1I11I1II1 * OoooooooOO
  if 78 - 78: IiII
  if 38 - 38: OoO0O00 * I1ii11iIi11i
  if 4 - 4: OoO0O00 . I1ii11iIi11i
  if 21 - 21: i11iIiiIii / OoO0O00 / I1ii11iIi11i * O0 - II111iiii * OOooOOo
  if 27 - 27: o0oOOo0O0Ooo . OoOoOO00 * Ii1I * iII111i * O0
  if 93 - 93: IiII % I1Ii111 % II111iiii
  if 20 - 20: OoooooooOO * I1Ii111
  if 38 - 38: iII111i . OoooooooOO
  if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
  if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
  if 61 - 61: I11i
  if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
  if 35 - 35: ooOoO0o
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  if 18 - 18: I1IiiI - I1ii11iIi11i * I11i / i11iIiiIii - o0oOOo0O0Ooo % o0oOOo0O0Ooo
 def print_map_reply ( self ) :
  OoO0o0OOOO = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 31 - 31: I11i
  lprint ( OoO0o0OOOO . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # iII111i % i11iIiiIii . I11i . ooOoO0o . I1ii11iIi11i * OoooooooOO
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 78 - 78: I1Ii111 % i1IIi * II111iiii . i11iIiiIii - IiII / I1IiiI
  if 20 - 20: OoooooooOO . Oo0Ooo
 def encode ( self ) :
  i11iI1 = ( LISP_MAP_REPLY << 28 ) | self . record_count
  i11iI1 |= self . hop_count << 8
  if ( self . rloc_probe ) : i11iI1 |= 0x08000000
  if ( self . echo_nonce_capable ) : i11iI1 |= 0x04000000
  if ( self . security ) : i11iI1 |= 0x02000000
  if 5 - 5: iII111i * ooOoO0o + IiII . I1IiiI / I1IiiI
  oOo0O000oo0 = struct . pack ( "I" , socket . htonl ( i11iI1 ) )
  oOo0O000oo0 += struct . pack ( "Q" , self . nonce )
  return ( oOo0O000oo0 )
  if 72 - 72: OoO0O00 / I1ii11iIi11i - OOooOOo - OoooooooOO / OoooooooOO % OoooooooOO
  if 85 - 85: OoO0O00 . o0oOOo0O0Ooo . I1IiiI
 def decode ( self , packet ) :
  Iii1 = "I"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
  i11iI1 = struct . unpack ( Iii1 , packet [ : O00O ] )
  i11iI1 = i11iI1 [ 0 ]
  packet = packet [ O00O : : ]
  if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
  Iii1 = "Q"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
  OoI1 = struct . unpack ( Iii1 , packet [ : O00O ] )
  packet = packet [ O00O : : ]
  if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
  i11iI1 = socket . ntohl ( i11iI1 )
  self . rloc_probe = True if ( i11iI1 & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( i11iI1 & 0x04000000 ) else False
  self . security = True if ( i11iI1 & 0x02000000 ) else False
  self . hop_count = ( i11iI1 >> 8 ) & 0xff
  self . record_count = i11iI1 & 0xff
  self . nonce = OoI1 [ 0 ]
  if 24 - 24: IiII * I1IiiI / OOooOOo
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 51 - 51: iIii1I11I1II1 / I11i * OoO0O00 * Ii1I + I1ii11iIi11i . OoooooooOO
  return ( packet )
  if 75 - 75: IiII / OoooooooOO / O0 % OOooOOo
  if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00
  if 92 - 92: OoOoOO00 . Oo0Ooo * I11i
  if 86 - 86: O0
  if 55 - 55: Ii1I / I1Ii111 / I1ii11iIi11i % ooOoO0o % I1IiiI
  if 55 - 55: oO0o + OoooooooOO % i1IIi
  if 24 - 24: I1ii11iIi11i - Oo0Ooo
  if 36 - 36: I1IiiI . OOooOOo % II111iiii * IiII
  if 34 - 34: I11i % iII111i - ooOoO0o - I1IiiI
  if 44 - 44: Ii1I . o0oOOo0O0Ooo . iIii1I11I1II1 + OoooooooOO - I1IiiI
  if 22 - 22: I11i * I1ii11iIi11i . OoooooooOO / Oo0Ooo / Ii1I
  if 54 - 54: I1Ii111 % Ii1I + ooOoO0o
  if 45 - 45: Ii1I / oO0o * I1Ii111 . Ii1I
  if 25 - 25: I1ii11iIi11i / I1ii11iIi11i
  if 79 - 79: Oo0Ooo - OoO0O00 % Oo0Ooo . II111iiii
  if 84 - 84: ooOoO0o * OoooooooOO + O0
  if 84 - 84: i1IIi . I11i . i1IIi . Oo0Ooo
  if 21 - 21: II111iiii . O0 + Oo0Ooo - i11iIiiIii
  if 5 - 5: iIii1I11I1II1 * i11iIiiIii + OoO0O00 + I11i * O0 % ooOoO0o
  if 88 - 88: o0oOOo0O0Ooo / i11iIiiIii * I1ii11iIi11i
  if 23 - 23: O0 / iII111i
  if 66 - 66: i1IIi % OoooooooOO * i11iIiiIii + oO0o * O0 / OoO0O00
  if 14 - 14: I1IiiI . IiII
  if 29 - 29: OoooooooOO / IiII + OoOoOO00 - I1Ii111 + IiII . i1IIi
  if 26 - 26: i11iIiiIii - II111iiii
  if 43 - 43: I1IiiI
  if 35 - 35: ooOoO0o + OoOoOO00 * OoooooooOO - II111iiii
  if 19 - 19: i1IIi / Ii1I / OoOoOO00 . I1IiiI / Ii1I % o0oOOo0O0Ooo
  if 39 - 39: ooOoO0o - OoooooooOO
  if 88 - 88: i1IIi + iIii1I11I1II1 * i11iIiiIii - OoooooooOO % o0oOOo0O0Ooo
  if 74 - 74: ooOoO0o - i11iIiiIii
class lisp_eid_record ( ) :
 def __init__ ( self ) :
  self . record_ttl = 0
  self . rloc_count = 0
  self . action = 0
  self . authoritative = False
  self . ddt_incomplete = False
  self . signature_count = 0
  self . map_version = 0
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . record_ttl = 0
  if 34 - 34: IiII + I1Ii111 + Oo0Ooo / II111iiii
  if 33 - 33: Ii1I . i1IIi - II111iiii - OoO0O00
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
  if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
 def print_ttl ( self ) :
  OoI1iI = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   OoI1iI = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( OoI1iI % 60 ) == 0 ) :
   OoI1iI = str ( OoI1iI / 60 ) + " hours"
  else :
   OoI1iI = str ( OoI1iI ) + " mins"
   if 34 - 34: iII111i - II111iiii + OoO0O00 / i11iIiiIii * IiII
  return ( OoI1iI )
  if 23 - 23: OoO0O00 / o0oOOo0O0Ooo
  if 22 - 22: OOooOOo - OoO0O00 . I11i
 def store_ttl ( self ) :
  OoI1iI = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : OoI1iI = self . record_ttl & 0x7fffffff
  return ( OoI1iI )
  if 89 - 89: I1Ii111
  if 19 - 19: IiII + I1Ii111
 def print_record ( self , indent , ddt ) :
  O0OOOo000 = ""
  iIi1 = ""
  OOOO0o0oo0oo = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    OOOO0o0oo0oo = lisp_map_referral_action_string [ self . action ]
    OOOO0o0oo0oo = bold ( OOOO0o0oo0oo , False )
    O0OOOo000 = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 83 - 83: oO0o . Ii1I - o0oOOo0O0Ooo % I11i + i11iIiiIii
    iIi1 = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 40 - 40: O0 . Ii1I
    if 58 - 58: i11iIiiIii * iII111i / Ii1I - oO0o - I1ii11iIi11i % o0oOOo0O0Ooo
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    OOOO0o0oo0oo = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     OOOO0o0oo0oo = bold ( OOOO0o0oo0oo , False )
     if 16 - 16: OoooooooOO
     if 71 - 71: Ii1I % O0 / I1Ii111 % iII111i - II111iiii / OoO0O00
     if 30 - 30: I11i
     if 60 - 60: ooOoO0o - Ii1I . I1IiiI * oO0o * i11iIiiIii
  ii1iI1i1 = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  OoO0o0OOOO = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
  lprint ( OoO0o0OOOO . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 OOOO0o0oo0oo , "auth" if ( self . authoritative is True ) else "non-auth" ,
 O0OOOo000 , iIi1 , self . map_version , ii1iI1i1 ,
 green ( self . print_prefix ( ) , False ) ) )
  if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
  if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
 def encode ( self ) :
  Ooo0O = self . action << 13
  if ( self . authoritative ) : Ooo0O |= 0x1000
  if ( self . ddt_incomplete ) : Ooo0O |= 0x800
  if 87 - 87: iIii1I11I1II1 * II111iiii - I1Ii111 % I1Ii111 - OOooOOo
  if 10 - 10: I1Ii111
  if 78 - 78: O0
  if 60 - 60: oO0o
  ii1iI1i1 = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( ii1iI1i1 < 0 ) : ii1iI1i1 = LISP_AFI_LCAF
  IIII = ( self . group . is_null ( ) == False )
  if ( IIII ) : ii1iI1i1 = LISP_AFI_LCAF
  if 90 - 90: OoooooooOO . OoooooooOO . I1ii11iIi11i * Ii1I - iII111i % I1IiiI
  OoOOOOoo = ( self . signature_count << 12 ) | self . map_version
  oo0Ooo = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 54 - 54: iIii1I11I1II1 - IiII - IiII
  oOo0O000oo0 = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , oo0Ooo , socket . htons ( Ooo0O ) ,
 socket . htons ( OoOOOOoo ) , socket . htons ( ii1iI1i1 ) )
  if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
  if 63 - 63: iII111i - OoO0O00 * OOooOOo
  if 89 - 89: iII111i / Oo0Ooo
  if 66 - 66: o0oOOo0O0Ooo + OoOoOO00 % OoooooooOO . I11i
  if ( IIII ) :
   oOo0O000oo0 += self . eid . lcaf_encode_sg ( self . group )
   return ( oOo0O000oo0 )
   if 30 - 30: II111iiii - Oo0Ooo - i11iIiiIii + O0
   if 93 - 93: i1IIi + I1Ii111 / OoO0O00 - I11i % Oo0Ooo / Ii1I
   if 1 - 1: Oo0Ooo / Ii1I . i11iIiiIii % OOooOOo + o0oOOo0O0Ooo + O0
   if 54 - 54: I1Ii111 + ooOoO0o % IiII
   if 83 - 83: o0oOOo0O0Ooo * iIii1I11I1II1
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   oOo0O000oo0 = oOo0O000oo0 [ 0 : - 2 ]
   oOo0O000oo0 += self . eid . address . encode_geo ( )
   return ( oOo0O000oo0 )
   if 36 - 36: OoOoOO00 + II111iiii - OoO0O00 % ooOoO0o * i1IIi
   if 4 - 4: Ii1I + OoO0O00 * I1ii11iIi11i
   if 13 - 13: OoOoOO00 - IiII * iIii1I11I1II1 * O0
   if 26 - 26: OoooooooOO + oO0o + OoO0O00 . O0
   if 46 - 46: OoooooooOO - Oo0Ooo * I1Ii111 * OOooOOo * I1Ii111 . oO0o
  if ( ii1iI1i1 == LISP_AFI_LCAF ) :
   oOo0O000oo0 += self . eid . lcaf_encode_iid ( )
   return ( oOo0O000oo0 )
   if 96 - 96: Ii1I / IiII % o0oOOo0O0Ooo + I11i
   if 46 - 46: OoO0O00 * I1IiiI
   if 25 - 25: I1Ii111 . IiII % O0 % i1IIi
   if 53 - 53: O0 % ooOoO0o
   if 41 - 41: IiII
  oOo0O000oo0 += self . eid . pack_address ( )
  return ( oOo0O000oo0 )
  if 29 - 29: ooOoO0o
  if 70 - 70: oO0o . O0 % I11i % IiII - I11i * I1ii11iIi11i
 def decode ( self , packet ) :
  Iii1 = "IBBHHH"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 22 - 22: i1IIi
  self . record_ttl , self . rloc_count , self . eid . mask_len , Ooo0O , self . map_version , self . eid . afi = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 82 - 82: oO0o . iIii1I11I1II1 - I1ii11iIi11i
  if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
  if 33 - 33: O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + iII111i - oO0o
  self . record_ttl = socket . ntohl ( self . record_ttl )
  Ooo0O = socket . ntohs ( Ooo0O )
  self . action = ( Ooo0O >> 13 ) & 0x7
  self . authoritative = True if ( ( Ooo0O >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( Ooo0O >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ O00O : : ]
  if 27 - 27: I1Ii111 + ooOoO0o - I1Ii111 % i11iIiiIii * Oo0Ooo * o0oOOo0O0Ooo
  if 88 - 88: OOooOOo
  if 25 - 25: OoO0O00 + o0oOOo0O0Ooo . ooOoO0o - Ii1I . oO0o * Ii1I
  if 85 - 85: i1IIi
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , oooiiIiIIIi1 = self . eid . lcaf_decode_eid ( packet )
   if ( oooiiIiIIIi1 ) : self . group = oooiiIiIIIi1
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 35 - 35: I1ii11iIi11i . OOooOOo
   if 97 - 97: I1IiiI
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 63 - 63: O0 - OoOoOO00 / i11iIiiIii / OoooooooOO / ooOoO0o / II111iiii
  if 45 - 45: II111iiii . OoO0O00 + OoO0O00 * iIii1I11I1II1
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 23 - 23: IiII * OoOoOO00 % Ii1I / Ii1I - ooOoO0o - OOooOOo
  if 86 - 86: OOooOOo . OoooooooOO * I1IiiI - Oo0Ooo / i11iIiiIii * iII111i
  if 56 - 56: I1IiiI . I11i % iII111i
  if 33 - 33: I11i / OOooOOo - OOooOOo / i11iIiiIii * OoOoOO00 + O0
  if 2 - 2: i11iIiiIii % I1IiiI
  if 90 - 90: II111iiii
  if 2 - 2: Ii1I - OoooooooOO - i11iIiiIii % Oo0Ooo / Ii1I
  if 77 - 77: o0oOOo0O0Ooo . o0oOOo0O0Ooo * I1Ii111 + OOooOOo - i11iIiiIii
  if 45 - 45: I1IiiI . I1IiiI - Oo0Ooo * OOooOOo
  if 71 - 71: i1IIi / I11i
  if 14 - 14: OoooooooOO
  if 99 - 99: o0oOOo0O0Ooo * o0oOOo0O0Ooo
  if 6 - 6: i11iIiiIii + oO0o % ooOoO0o + i11iIiiIii - OOooOOo
  if 12 - 12: iII111i . oO0o % IiII * OoooooooOO . IiII
  if 15 - 15: I1IiiI . I1IiiI / i11iIiiIii
  if 17 - 17: iIii1I11I1II1 / OoO0O00 - II111iiii
  if 46 - 46: iIii1I11I1II1 * oO0o / i11iIiiIii + II111iiii + I11i
  if 30 - 30: O0 * IiII - I1Ii111 % O0 * Ii1I
  if 29 - 29: I1ii11iIi11i % I1ii11iIi11i % Ii1I + ooOoO0o % iIii1I11I1II1
  if 41 - 41: I1ii11iIi11i % I1Ii111
  if 37 - 37: Oo0Ooo . I1IiiI % OoOoOO00 . OoO0O00 - Oo0Ooo / OoO0O00
  if 34 - 34: i11iIiiIii + OoO0O00 + i11iIiiIii . IiII % O0
  if 64 - 64: o0oOOo0O0Ooo . iIii1I11I1II1
  if 86 - 86: ooOoO0o - I11i . iIii1I11I1II1 - iIii1I11I1II1
  if 61 - 61: Ii1I % Oo0Ooo + OoOoOO00
  if 60 - 60: oO0o . OoooooooOO
  if 40 - 40: I11i
  if 44 - 44: ooOoO0o
  if 35 - 35: II111iiii + iII111i / I1ii11iIi11i * I1IiiI . I11i
  if 97 - 97: I1IiiI / o0oOOo0O0Ooo
  if 13 - 13: I1ii11iIi11i
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 72 - 72: Oo0Ooo + IiII / Ii1I * Oo0Ooo
class lisp_ecm ( ) :
 def __init__ ( self , sport ) :
  self . security = False
  self . ddt = False
  self . to_etr = False
  self . to_ms = False
  self . length = 0
  self . ttl = LISP_DEFAULT_ECM_TTL
  self . protocol = LISP_UDP_PROTOCOL
  self . ip_checksum = 0
  self . source = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . dest = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . udp_sport = sport
  self . udp_dport = LISP_CTRL_PORT
  self . udp_checksum = 0
  self . udp_length = 0
  self . afi = LISP_AFI_NONE
  if 41 - 41: OOooOOo - OoOoOO00 . I1IiiI + i11iIiiIii + OoO0O00 * iII111i
  if 85 - 85: OoO0O00 + II111iiii
 def print_ecm ( self ) :
  OoO0o0OOOO = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 87 - 87: OoO0O00
  lprint ( OoO0o0OOOO . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 93 - 93: OoooooooOO
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 80 - 80: o0oOOo0O0Ooo
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 3 - 3: i11iIiiIii / OOooOOo + oO0o
   if 10 - 10: OoO0O00 . OoO0O00 + O0
   if 13 - 13: i1IIi . I1IiiI
   if 45 - 45: ooOoO0o % I11i
   if 37 - 37: iII111i
   if 70 - 70: O0 + iIii1I11I1II1 % O0 * o0oOOo0O0Ooo - Oo0Ooo - ooOoO0o
  i11iI1 = ( LISP_ECM << 28 )
  if ( self . security ) : i11iI1 |= 0x08000000
  if ( self . ddt ) : i11iI1 |= 0x04000000
  if ( self . to_etr ) : i11iI1 |= 0x02000000
  if ( self . to_ms ) : i11iI1 |= 0x01000000
  if 94 - 94: i1IIi + IiII / OoooooooOO - oO0o / OOooOOo / OoOoOO00
  oooo0OO0Oo = struct . pack ( "I" , socket . htonl ( i11iI1 ) )
  if 1 - 1: OoooooooOO - OoO0O00 - OoooooooOO / iII111i
  IiiIIi1 = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   IiiIIi1 = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   IiiIIi1 += self . source . pack_address ( )
   IiiIIi1 += self . dest . pack_address ( )
   IiiIIi1 = lisp_ip_checksum ( IiiIIi1 )
   if 70 - 70: Ii1I + I1ii11iIi11i . II111iiii * i11iIiiIii
  if ( self . afi == LISP_AFI_IPV6 ) :
   IiiIIi1 = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   IiiIIi1 += self . source . pack_address ( )
   IiiIIi1 += self . dest . pack_address ( )
   if 87 - 87: Ii1I / I1Ii111 % OoOoOO00 * I1ii11iIi11i - OoooooooOO / OoOoOO00
   if 24 - 24: I11i . OOooOOo * i1IIi . I1ii11iIi11i / ooOoO0o / O0
  i11I1 = socket . htons ( self . udp_sport )
  iiiii111 = socket . htons ( self . udp_dport )
  IIii1 = socket . htons ( self . udp_length )
  IIiI1 = socket . htons ( self . udp_checksum )
  OoOo = struct . pack ( "HHHH" , i11I1 , iiiii111 , IIii1 , IIiI1 )
  return ( oooo0OO0Oo + IiiIIi1 + OoOo )
  if 62 - 62: o0oOOo0O0Ooo % II111iiii
  if 22 - 22: oO0o - o0oOOo0O0Ooo
 def decode ( self , packet ) :
  if 89 - 89: OOooOOo
  if 34 - 34: iII111i . OOooOOo
  if 13 - 13: OoO0O00 * OOooOOo + oO0o
  if 21 - 21: i11iIiiIii . Ii1I % i1IIi * Ii1I . oO0o + Ii1I
  Iii1 = "I"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 92 - 92: i1IIi + OoO0O00 * I11i
  i11iI1 = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 70 - 70: Oo0Ooo
  i11iI1 = socket . ntohl ( i11iI1 [ 0 ] )
  self . security = True if ( i11iI1 & 0x08000000 ) else False
  self . ddt = True if ( i11iI1 & 0x04000000 ) else False
  self . to_etr = True if ( i11iI1 & 0x02000000 ) else False
  self . to_ms = True if ( i11iI1 & 0x01000000 ) else False
  packet = packet [ O00O : : ]
  if 93 - 93: iII111i . I1ii11iIi11i . Oo0Ooo . oO0o . OoooooooOO
  if 51 - 51: O0 - iII111i
  if 65 - 65: O0 / II111iiii * IiII % Ii1I + o0oOOo0O0Ooo
  if 43 - 43: I1Ii111 + OoO0O00 * OoooooooOO
  if ( len ( packet ) < 1 ) : return ( None )
  OoOOoO0o = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  OoOOoO0o = OoOOoO0o >> 4
  if 85 - 85: iII111i + OOooOOo
  if ( OoOOoO0o == 4 ) :
   O00O = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < O00O ) : return ( None )
   if 36 - 36: OoO0O00 % II111iiii * O0 + II111iiii - oO0o - i1IIi
   o000000Oo , IIii1 , o000000Oo , OOOoo0O , Ii1Ii , IIiI1 = struct . unpack ( "HHIBBH" , packet [ : O00O ] )
   self . length = socket . ntohs ( IIii1 )
   self . ttl = OOOoo0O
   self . protocol = Ii1Ii
   self . ip_checksum = socket . ntohs ( IIiI1 )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 81 - 81: Ii1I % OoO0O00
   if 22 - 22: i1IIi
   if 60 - 60: iIii1I11I1II1 . I1ii11iIi11i % o0oOOo0O0Ooo * OOooOOo - I1IiiI * II111iiii
   if 94 - 94: OOooOOo . OoooooooOO
   Ii1Ii = struct . pack ( "H" , 0 )
   I1iiII11i11iI = struct . calcsize ( "HHIBB" )
   I11I1iI = struct . calcsize ( "H" )
   packet = packet [ : I1iiII11i11iI ] + Ii1Ii + packet [ I1iiII11i11iI + I11I1iI : ]
   if 65 - 65: OOooOOo . II111iiii * i11iIiiIii + OOooOOo
   packet = packet [ O00O : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 99 - 99: I1ii11iIi11i % Oo0Ooo
   if 31 - 31: o0oOOo0O0Ooo - II111iiii * OOooOOo . OOooOOo - oO0o
  if ( OoOOoO0o == 6 ) :
   O00O = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < O00O ) : return ( None )
   if 57 - 57: OOooOOo / i11iIiiIii / I1Ii111 - Oo0Ooo . iIii1I11I1II1
   o000000Oo , IIii1 , Ii1Ii , OOOoo0O = struct . unpack ( "IHBB" , packet [ : O00O ] )
   self . length = socket . ntohs ( IIii1 )
   self . protocol = Ii1Ii
   self . ttl = OOOoo0O
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 84 - 84: IiII
   packet = packet [ O00O : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 42 - 42: O0 . I1Ii111 / I11i
   if 69 - 69: OoOoOO00 / I1Ii111 * I1IiiI
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 76 - 76: O0 + II111iiii * OoO0O00
  O00O = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < O00O ) : return ( None )
  if 1 - 1: o0oOOo0O0Ooo
  i11I1 , iiiii111 , IIii1 , IIiI1 = struct . unpack ( "HHHH" , packet [ : O00O ] )
  self . udp_sport = socket . ntohs ( i11I1 )
  self . udp_dport = socket . ntohs ( iiiii111 )
  self . udp_length = socket . ntohs ( IIii1 )
  self . udp_checksum = socket . ntohs ( IIiI1 )
  packet = packet [ O00O : : ]
  return ( packet )
  if 34 - 34: o0oOOo0O0Ooo + OOooOOo . OoO0O00 + I1IiiI + OoooooooOO
  if 90 - 90: Ii1I / OoOoOO00 - iIii1I11I1II1 / i1IIi * I1Ii111 - ooOoO0o
  if 2 - 2: iII111i * I11i * ooOoO0o + i11iIiiIii + oO0o
  if 81 - 81: o0oOOo0O0Ooo * OoO0O00
  if 18 - 18: i11iIiiIii / o0oOOo0O0Ooo - oO0o . I11i * i1IIi
  if 67 - 67: Ii1I
  if 64 - 64: OoOoOO00 + iII111i * OoOoOO00 - I1IiiI * OoooooooOO
  if 27 - 27: II111iiii + i11iIiiIii
  if 32 - 32: i1IIi
  if 76 - 76: II111iiii % ooOoO0o - I1ii11iIi11i
  if 50 - 50: II111iiii / I1IiiI . Ii1I % i11iIiiIii
  if 66 - 66: oO0o / OOooOOo / iII111i
  if 5 - 5: I1Ii111 . oO0o
  if 77 - 77: iII111i / i11iIiiIii
  if 20 - 20: O0 . I11i
  if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
  if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
  if 73 - 73: oO0o / OOooOOo * II111iiii % OoooooooOO - i1IIi - ooOoO0o
  if 43 - 43: o0oOOo0O0Ooo + Ii1I % OoO0O00 . I1Ii111 + i1IIi
  if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
  if 65 - 65: ooOoO0o + IiII - OoOoOO00 % II111iiii - iIii1I11I1II1
  if 39 - 39: I1IiiI + I1ii11iIi11i - i11iIiiIii
  if 43 - 43: iIii1I11I1II1
  if 73 - 73: OoOoOO00 + o0oOOo0O0Ooo
  if 58 - 58: i1IIi * I1ii11iIi11i % iII111i . OoO0O00 % IiII % I11i
  if 63 - 63: I1ii11iIi11i % ooOoO0o % I1ii11iIi11i
  if 71 - 71: Ii1I
  if 43 - 43: o0oOOo0O0Ooo / ooOoO0o
  if 88 - 88: i11iIiiIii - i1IIi + Oo0Ooo - O0
  if 50 - 50: I1ii11iIi11i
  if 37 - 37: oO0o % iII111i / II111iiii / OoO0O00 - IiII - ooOoO0o
  if 69 - 69: I1ii11iIi11i . OoooooooOO % I1Ii111
  if 79 - 79: I1IiiI - IiII . OoooooooOO - I1ii11iIi11i
  if 79 - 79: OOooOOo + o0oOOo0O0Ooo % iII111i . oO0o
  if 49 - 49: Ii1I + i11iIiiIii * OoOoOO00 . OoOoOO00 . I1ii11iIi11i . Oo0Ooo
  if 61 - 61: I11i / OOooOOo
  if 85 - 85: OoOoOO00 - I11i . OoOoOO00 . OoOoOO00
  if 62 - 62: IiII % OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % iII111i
  if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
  if 68 - 68: I11i - i11iIiiIii / o0oOOo0O0Ooo + ooOoO0o / I1IiiI
  if 31 - 31: I1Ii111 . OoooooooOO . i1IIi
  if 65 - 65: OoO0O00 . ooOoO0o
  if 12 - 12: I1Ii111 + O0 - oO0o . IiII
  if 46 - 46: IiII . ooOoO0o / iII111i
  if 63 - 63: II111iiii - I1ii11iIi11i * II111iiii
  if 92 - 92: OoO0O00 % ooOoO0o * O0 % iIii1I11I1II1 / i1IIi / OoOoOO00
  if 67 - 67: I1Ii111 + I11i + I1Ii111 . OOooOOo % o0oOOo0O0Ooo / ooOoO0o
  if 78 - 78: I1ii11iIi11i . O0
  if 56 - 56: oO0o - i1IIi * O0 / I11i * I1IiiI . I11i
  if 54 - 54: i11iIiiIii % i1IIi + Oo0Ooo / OoOoOO00
  if 26 - 26: I11i . I1ii11iIi11i
  if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
  if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
  if 28 - 28: O0 % iII111i - i1IIi
  if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
  if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
  if 97 - 97: oO0o - iII111i + IiII . OoOoOO00 + iIii1I11I1II1
  if 75 - 75: ooOoO0o + ooOoO0o . I1Ii111 % iII111i / iIii1I11I1II1 * iII111i
  if 13 - 13: II111iiii * i11iIiiIii - i1IIi * OoO0O00 + i1IIi
  if 43 - 43: O0 % oO0o * I1IiiI
  if 64 - 64: II111iiii + i11iIiiIii
  if 17 - 17: O0 * I1IiiI
  if 40 - 40: iIii1I11I1II1 * iII111i % iIii1I11I1II1
  if 39 - 39: i1IIi . Ii1I - Oo0Ooo
  if 91 - 91: I1IiiI - OoooooooOO - OoooooooOO
  if 69 - 69: iII111i * i11iIiiIii / i1IIi
  if 86 - 86: I1IiiI % I11i * O0 + i1IIi % I1Ii111
  if 97 - 97: II111iiii * OoOoOO00 - I1Ii111 / i11iIiiIii / OoOoOO00
  if 25 - 25: Oo0Ooo / Oo0Ooo
  if 74 - 74: OOooOOo
  if 30 - 30: O0 . Ii1I / o0oOOo0O0Ooo + I1IiiI - O0
  if 88 - 88: i11iIiiIii
  if 33 - 33: OoO0O00 + O0
  if 20 - 20: o0oOOo0O0Ooo % I11i . ooOoO0o - i1IIi . O0
  if 10 - 10: i1IIi
  if 49 - 49: I1Ii111 - Ii1I . O0
  if 46 - 46: OOooOOo
  if 64 - 64: I1IiiI / OoOoOO00
  if 6 - 6: i11iIiiIii - iII111i * i1IIi - iII111i
  if 8 - 8: I11i / i11iIiiIii . O0 / OoO0O00 * oO0o + I1Ii111
  if 91 - 91: I1IiiI
  if 84 - 84: O0 % Ii1I
  if 3 - 3: I1IiiI . I11i / I1ii11iIi11i
  if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
  if 14 - 14: Oo0Ooo . O0 - oO0o - i11iIiiIii
  if 8 - 8: I1IiiI / iIii1I11I1II1 / OoooooooOO / Oo0Ooo / ooOoO0o
  if 80 - 80: I11i
  if 26 - 26: II111iiii + I1IiiI . II111iiii - oO0o % OoO0O00
  if 1 - 1: OoO0O00 - II111iiii
  if 75 - 75: Oo0Ooo - OoOoOO00 + oO0o % i1IIi * OOooOOo
  if 56 - 56: OoOoOO00 / OoO0O00 / I1IiiI % OoooooooOO
  if 39 - 39: I1IiiI + II111iiii * Oo0Ooo % Ii1I . o0oOOo0O0Ooo * oO0o
  if 42 - 42: Ii1I / Oo0Ooo
  if 25 - 25: OoooooooOO % Ii1I * I1Ii111 * I11i + I1IiiI % I1ii11iIi11i
  if 70 - 70: Ii1I + I1ii11iIi11i * I11i * i1IIi . I1Ii111
  if 76 - 76: OoooooooOO * OoOoOO00 . OoooooooOO
  if 46 - 46: ooOoO0o * o0oOOo0O0Ooo % II111iiii / I1Ii111
  if 29 - 29: OoO0O00 - i11iIiiIii % Oo0Ooo % o0oOOo0O0Ooo
  if 30 - 30: oO0o - Ii1I % Ii1I
  if 8 - 8: IiII
  if 68 - 68: IiII . OoooooooOO - i11iIiiIii + i11iIiiIii
  if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
  if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
  if 58 - 58: ooOoO0o
  if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
  if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
  if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
  if 39 - 39: oO0o + OoOoOO00
  if 68 - 68: i1IIi * oO0o / i11iIiiIii
  if 96 - 96: I1IiiI
  if 78 - 78: OoO0O00
  if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
  if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
  if 57 - 57: I11i / IiII * i1IIi + II111iiii . o0oOOo0O0Ooo
  if 11 - 11: II111iiii
  if 66 - 66: Ii1I - I1IiiI . OoooooooOO * I1Ii111
  if 16 - 16: IiII * OoO0O00 * i11iIiiIii - ooOoO0o
class lisp_rloc_record ( ) :
 def __init__ ( self ) :
  self . priority = 0
  self . weight = 0
  self . mpriority = 0
  self . mweight = 0
  self . local_bit = False
  self . probe_bit = False
  self . reach_bit = False
  self . rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . geo = None
  self . elp = None
  self . rle = None
  self . json = None
  self . rloc_name = None
  self . keys = None
  if 88 - 88: iIii1I11I1II1 / Ii1I * IiII / I1Ii111
  if 31 - 31: O0 . I1IiiI
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  i1i11i1 = self . rloc_name
  if ( cour ) : i1i11i1 = lisp_print_cour ( i1i11i1 )
  return ( 'rloc-name: {}' . format ( blue ( i1i11i1 , cour ) ) )
  if 39 - 39: Ii1I
  if 10 - 10: OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i % iII111i / i11iIiiIii
 def print_record ( self , indent ) :
  iII = self . print_rloc_name ( )
  if ( iII != "" ) : iII = ", " + iII
  Ii1I1iiiI1 = ""
  if ( self . geo ) :
   i11I1II = ""
   if ( self . geo . geo_name ) : i11I1II = "'{}' " . format ( self . geo . geo_name )
   Ii1I1iiiI1 = ", geo: {}{}" . format ( i11I1II , self . geo . print_geo ( ) )
   if 50 - 50: oO0o + i1IIi
  oOOo0oOoooO0o = ""
  if ( self . elp ) :
   i11I1II = ""
   if ( self . elp . elp_name ) : i11I1II = "'{}' " . format ( self . elp . elp_name )
   oOOo0oOoooO0o = ", elp: {}{}" . format ( i11I1II , self . elp . print_elp ( True ) )
   if 24 - 24: O0 / OoO0O00 - Oo0Ooo - II111iiii + OoooooooOO + I1IiiI
  oooOOOO0oO0O = ""
  if ( self . rle ) :
   i11I1II = ""
   if ( self . rle . rle_name ) : i11I1II = "'{}' " . format ( self . rle . rle_name )
   oooOOOO0oO0O = ", rle: {}{}" . format ( i11I1II , self . rle . print_rle ( False ) )
   if 61 - 61: I1ii11iIi11i * i11iIiiIii * ooOoO0o . I11i
  i1iII11iIiiI1 = ""
  if ( self . json ) :
   i11I1II = ""
   if ( self . json . json_name ) :
    i11I1II = "'{}' " . format ( self . json . json_name )
    if 37 - 37: IiII / OOooOOo + O0
   i1iII11iIiiI1 = ", json: {}" . format ( self . json . print_json ( False ) )
   if 86 - 86: iII111i / iII111i . ooOoO0o - OoO0O00
   if 19 - 19: I11i
  IiI1II111iii = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   IiI1II111iii = ", " + self . keys [ 1 ] . print_keys ( )
   if 48 - 48: iIii1I11I1II1 - Oo0Ooo
   if 80 - 80: i1IIi
  OoO0o0OOOO = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( OoO0o0OOOO . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , iII , Ii1I1iiiI1 ,
 oOOo0oOoooO0o , oooOOOO0oO0O , i1iII11iIiiI1 , IiI1II111iii ) )
  if 56 - 56: II111iiii - o0oOOo0O0Ooo
  if 48 - 48: Oo0Ooo - I1ii11iIi11i - II111iiii . Ii1I . oO0o / iIii1I11I1II1
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 38 - 38: I1Ii111 % i11iIiiIii + Ii1I * ooOoO0o / I1Ii111
  if 93 - 93: oO0o
  if 60 - 60: I1Ii111 . oO0o / Oo0Ooo * ooOoO0o + OoOoOO00 - i1IIi
 def store_rloc_entry ( self , rloc_entry ) :
  IiiI11iiI1i1 = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 77 - 77: OOooOOo
  self . rloc . copy_address ( IiiI11iiI1i1 )
  if 29 - 29: II111iiii % iIii1I11I1II1 * O0 . o0oOOo0O0Ooo
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 56 - 56: i1IIi . ooOoO0o + I11i - i11iIiiIii
   if 100 - 100: iIii1I11I1II1 - i1IIi . OOooOOo
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   i11I1II = rloc_entry . geo_name
   if ( i11I1II and lisp_geo_list . has_key ( i11I1II ) ) :
    self . geo = lisp_geo_list [ i11I1II ]
    if 73 - 73: I1Ii111 / I11i / i11iIiiIii - I1ii11iIi11i % ooOoO0o
    if 92 - 92: I1IiiI - o0oOOo0O0Ooo % I1ii11iIi11i / iII111i % oO0o
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   i11I1II = rloc_entry . elp_name
   if ( i11I1II and lisp_elp_list . has_key ( i11I1II ) ) :
    self . elp = lisp_elp_list [ i11I1II ]
    if 43 - 43: Oo0Ooo % oO0o . i11iIiiIii - O0
    if 5 - 5: i1IIi + Ii1I
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   i11I1II = rloc_entry . rle_name
   if ( i11I1II and lisp_rle_list . has_key ( i11I1II ) ) :
    self . rle = lisp_rle_list [ i11I1II ]
    if 38 - 38: I1IiiI . O0 + OOooOOo / I1ii11iIi11i . iIii1I11I1II1 - i1IIi
    if 3 - 3: Oo0Ooo + oO0o
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   i11I1II = rloc_entry . json_name
   if ( i11I1II and lisp_json_list . has_key ( i11I1II ) ) :
    self . json = lisp_json_list [ i11I1II ]
    if 65 - 65: I1IiiI / OoOoOO00 % I1IiiI * i11iIiiIii * OoooooooOO / I11i
    if 91 - 91: i11iIiiIii / i11iIiiIii
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 9 - 9: I11i / I1Ii111 + iIii1I11I1II1 + I1IiiI - II111iiii
  if 96 - 96: iII111i + Oo0Ooo - OoooooooOO . i1IIi + i1IIi % iIii1I11I1II1
 def encode_lcaf ( self ) :
  ooo0o0oOoOO0 = socket . htons ( LISP_AFI_LCAF )
  OoooO = ""
  if ( self . geo ) :
   OoooO = self . geo . encode_geo ( )
   if 93 - 93: Oo0Ooo
   if 5 - 5: iII111i
  o0OOooooooOO = ""
  if ( self . elp ) :
   OooOOO = ""
   for ooOoIIi11iiI1 in self . elp . elp_nodes :
    ii1iI1i1 = socket . htons ( ooOoIIi11iiI1 . address . afi )
    OoOoo0ooO0000 = 0
    if ( ooOoIIi11iiI1 . eid ) : OoOoo0ooO0000 |= 0x4
    if ( ooOoIIi11iiI1 . probe ) : OoOoo0ooO0000 |= 0x2
    if ( ooOoIIi11iiI1 . strict ) : OoOoo0ooO0000 |= 0x1
    OoOoo0ooO0000 = socket . htons ( OoOoo0ooO0000 )
    OooOOO += struct . pack ( "HH" , OoOoo0ooO0000 , ii1iI1i1 )
    OooOOO += ooOoIIi11iiI1 . address . pack_address ( )
    if 5 - 5: i1IIi - OoOoOO00 - oO0o + i11iIiiIii
    if 65 - 65: I1IiiI - O0
   I1iIII = socket . htons ( len ( OooOOO ) )
   o0OOooooooOO = struct . pack ( "HBBBBH" , ooo0o0oOoOO0 , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , I1iIII )
   o0OOooooooOO += OooOOO
   if 97 - 97: I1ii11iIi11i % oO0o
   if 90 - 90: Ii1I / I11i
  o0OO = ""
  if ( self . rle ) :
   OoII1ii1iI1111 = ""
   for iiiI1Ii in self . rle . rle_nodes :
    ii1iI1i1 = socket . htons ( iiiI1Ii . address . afi )
    OoII1ii1iI1111 += struct . pack ( "HBBH" , 0 , 0 , iiiI1Ii . level , ii1iI1i1 )
    OoII1ii1iI1111 += iiiI1Ii . address . pack_address ( )
    if ( iiiI1Ii . rloc_name ) :
     OoII1ii1iI1111 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     OoII1ii1iI1111 += iiiI1Ii . rloc_name + "\0"
     if 79 - 79: O0
     if 71 - 71: OoO0O00 - O0
     if 73 - 73: iIii1I11I1II1
   iI1iIII = socket . htons ( len ( OoII1ii1iI1111 ) )
   o0OO = struct . pack ( "HBBBBH" , ooo0o0oOoOO0 , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , iI1iIII )
   o0OO += OoII1ii1iI1111
   if 34 - 34: OoooooooOO
   if 49 - 49: O0 - iII111i . II111iiii - o0oOOo0O0Ooo
  Iiii1 = ""
  if ( self . json ) :
   OOooo0o0OOO = socket . htons ( len ( self . json . json_string ) + 2 )
   i1iI = socket . htons ( len ( self . json . json_string ) )
   Iiii1 = struct . pack ( "HBBBBHH" , ooo0o0oOoOO0 , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , OOooo0o0OOO , i1iI )
   Iiii1 += self . json . json_string
   Iiii1 += struct . pack ( "H" , 0 )
   if 46 - 46: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1
   if 25 - 25: II111iiii / OOooOOo + Oo0Ooo - iIii1I11I1II1 - OoOoOO00
  OOo = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   OOo = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 69 - 69: IiII - i1IIi + o0oOOo0O0Ooo
   if 5 - 5: II111iiii
  OoOoO000O0O = ""
  if ( self . rloc_name ) :
   OoOoO000O0O += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   OoOoO000O0O += self . rloc_name + "\0"
   if 100 - 100: ooOoO0o + I1Ii111
   if 49 - 49: I1IiiI % oO0o % II111iiii * II111iiii + OoooooooOO + iII111i
  OoOooOoOoOO = len ( OoooO ) + len ( o0OOooooooOO ) + len ( o0OO ) + len ( OOo ) + 2 + len ( Iiii1 ) + self . rloc . addr_length ( ) + len ( OoOoO000O0O )
  if 11 - 11: OoO0O00 . OoO0O00 . OoOoOO00 + i1IIi - I1IiiI
  OoOooOoOoOO = socket . htons ( OoOooOoOoOO )
  ii11iIi1I1i = struct . pack ( "HBBBBHH" , ooo0o0oOoOO0 , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , OoOooOoOoOO , socket . htons ( self . rloc . afi ) )
  ii11iIi1I1i += self . rloc . pack_address ( )
  return ( ii11iIi1I1i + OoOoO000O0O + OoooO + o0OOooooooOO + o0OO + OOo + Iiii1 )
  if 79 - 79: I1ii11iIi11i + IiII
  if 94 - 94: i11iIiiIii % ooOoO0o * OoOoOO00 % Oo0Ooo * IiII
 def encode ( self ) :
  OoOoo0ooO0000 = 0
  if ( self . local_bit ) : OoOoo0ooO0000 |= 0x0004
  if ( self . probe_bit ) : OoOoo0ooO0000 |= 0x0002
  if ( self . reach_bit ) : OoOoo0ooO0000 |= 0x0001
  if 30 - 30: i1IIi + o0oOOo0O0Ooo - OoOoOO00 . OOooOOo
  oOo0O000oo0 = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( OoOoo0ooO0000 ) ,
 socket . htons ( self . rloc . afi ) )
  if 95 - 95: i1IIi . I11i + O0 . I11i - I11i / Oo0Ooo
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 41 - 41: OoooooooOO . OOooOOo - Ii1I * OoO0O00 % i11iIiiIii
   oOo0O000oo0 = oOo0O000oo0 [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   oOo0O000oo0 += self . rloc . pack_address ( )
   if 7 - 7: Ii1I
  return ( oOo0O000oo0 )
  if 16 - 16: IiII * o0oOOo0O0Ooo % II111iiii - II111iiii + ooOoO0o
  if 55 - 55: OoO0O00 % OoOoOO00
 def decode_lcaf ( self , packet , nonce ) :
  Iii1 = "HBBBBH"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 58 - 58: Ii1I
  ii1iI1i1 , Oo0o0ooOo0 , OoOoo0ooO0000 , ii1i , ii1iiI11III1 , OOooo0o0OOO = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 17 - 17: OoO0O00 - oO0o % Oo0Ooo % oO0o * I1Ii111 / IiII
  if 88 - 88: ooOoO0o . II111iiii * O0 % IiII
  OOooo0o0OOO = socket . ntohs ( OOooo0o0OOO )
  packet = packet [ O00O : : ]
  if ( OOooo0o0OOO > len ( packet ) ) : return ( None )
  if 15 - 15: O0 % i1IIi - OOooOOo . IiII
  if 1 - 1: I1IiiI
  if 40 - 40: o0oOOo0O0Ooo % I11i % O0
  if 88 - 88: o0oOOo0O0Ooo - oO0o
  if ( ii1i == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( OOooo0o0OOO > 0 ) :
    Iii1 = "H"
    O00O = struct . calcsize ( Iii1 )
    if ( OOooo0o0OOO < O00O ) : return ( None )
    if 73 - 73: II111iiii
    iI1II1iIiI11I = len ( packet )
    ii1iI1i1 = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
    ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
    if 7 - 7: O0 / OoO0O00
    if ( ii1iI1i1 == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ O00O : : ]
     self . rloc_name = None
     if ( ii1iI1i1 == LISP_AFI_NAME ) :
      packet , i1i11i1 = lisp_decode_dist_name ( packet )
      self . rloc_name = i1i11i1
     else :
      self . rloc . afi = ii1iI1i1
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 90 - 90: iII111i % oO0o / iIii1I11I1II1
      if 52 - 52: I1IiiI / o0oOOo0O0Ooo
      if 20 - 20: I1Ii111 . I1IiiI - iIii1I11I1II1 / iII111i
    OOooo0o0OOO -= iI1II1iIiI11I - len ( packet )
    if 46 - 46: I1Ii111 . i11iIiiIii
    if 89 - 89: OoO0O00 - OOooOOo - i1IIi - OoO0O00 % iIii1I11I1II1
  elif ( ii1i == LISP_LCAF_GEO_COORD_TYPE ) :
   if 52 - 52: o0oOOo0O0Ooo * O0 + I1ii11iIi11i
   if 83 - 83: I11i + OOooOOo - OoooooooOO
   if 7 - 7: IiII % ooOoO0o / OoooooooOO / o0oOOo0O0Ooo + OoO0O00 - OoO0O00
   if 15 - 15: i1IIi + OOooOOo / Ii1I
   oOo00O = lisp_geo ( "" )
   packet = oOo00O . decode_geo ( packet , OOooo0o0OOO , ii1iiI11III1 )
   if ( packet == None ) : return ( None )
   self . geo = oOo00O
   if 5 - 5: II111iiii - o0oOOo0O0Ooo + i1IIi - Ii1I % i11iIiiIii
  elif ( ii1i == LISP_LCAF_JSON_TYPE ) :
   if 79 - 79: iII111i . Ii1I / OoO0O00
   if 57 - 57: O0 / I11i + I1IiiI . IiII
   if 38 - 38: i1IIi . iII111i
   if 47 - 47: o0oOOo0O0Ooo * I1ii11iIi11i
   Iii1 = "H"
   O00O = struct . calcsize ( Iii1 )
   if ( OOooo0o0OOO < O00O ) : return ( None )
   if 48 - 48: oO0o * i1IIi % iII111i * Ii1I * I1Ii111 + ooOoO0o
   i1iI = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
   i1iI = socket . ntohs ( i1iI )
   if ( OOooo0o0OOO < O00O + i1iI ) : return ( None )
   if 12 - 12: iIii1I11I1II1 - I11i . I1Ii111 - Ii1I / OoO0O00 . O0
   packet = packet [ O00O : : ]
   self . json = lisp_json ( "" , packet [ 0 : i1iI ] )
   packet = packet [ i1iI : : ]
   if 8 - 8: II111iiii % OOooOOo / IiII + I1IiiI * OOooOOo
  elif ( ii1i == LISP_LCAF_ELP_TYPE ) :
   if 85 - 85: OoOoOO00 + iII111i % I1Ii111 % OOooOOo * I1ii11iIi11i
   if 48 - 48: OoO0O00 % OoO0O00 % OoOoOO00
   if 30 - 30: Oo0Ooo % OoooooooOO * i11iIiiIii % oO0o
   if 37 - 37: iII111i
   i1I1I1i1I1 = lisp_elp ( None )
   i1I1I1i1I1 . elp_nodes = [ ]
   while ( OOooo0o0OOO > 0 ) :
    OoOoo0ooO0000 , ii1iI1i1 = struct . unpack ( "HH" , packet [ : 4 ] )
    if 25 - 25: i11iIiiIii . OoOoOO00 % O0 / iIii1I11I1II1
    ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
    if ( ii1iI1i1 == LISP_AFI_LCAF ) : return ( None )
    if 50 - 50: I1Ii111 . I11i / O0 . I11i
    ooOoIIi11iiI1 = lisp_elp_node ( )
    i1I1I1i1I1 . elp_nodes . append ( ooOoIIi11iiI1 )
    if 91 - 91: i11iIiiIii . I1ii11iIi11i + I11i
    OoOoo0ooO0000 = socket . ntohs ( OoOoo0ooO0000 )
    ooOoIIi11iiI1 . eid = ( OoOoo0ooO0000 & 0x4 )
    ooOoIIi11iiI1 . probe = ( OoOoo0ooO0000 & 0x2 )
    ooOoIIi11iiI1 . strict = ( OoOoo0ooO0000 & 0x1 )
    ooOoIIi11iiI1 . address . afi = ii1iI1i1
    ooOoIIi11iiI1 . address . mask_len = ooOoIIi11iiI1 . address . host_mask_len ( )
    packet = ooOoIIi11iiI1 . address . unpack_address ( packet [ 4 : : ] )
    OOooo0o0OOO -= ooOoIIi11iiI1 . address . addr_length ( ) + 4
    if 67 - 67: I1ii11iIi11i * I1Ii111 * I1IiiI / I11i - IiII + oO0o
   i1I1I1i1I1 . select_elp_node ( )
   self . elp = i1I1I1i1I1
   if 11 - 11: O0 + i1IIi / o0oOOo0O0Ooo * OoO0O00
  elif ( ii1i == LISP_LCAF_RLE_TYPE ) :
   if 64 - 64: i1IIi % IiII . ooOoO0o . iIii1I11I1II1 + OoO0O00 - iIii1I11I1II1
   if 52 - 52: II111iiii - IiII
   if 91 - 91: iIii1I11I1II1 + iII111i . I11i % i11iIiiIii - i11iIiiIii + I1IiiI
   if 75 - 75: I1ii11iIi11i / I1IiiI - iIii1I11I1II1 / OoO0O00 * OOooOOo
   I1i1i111Ii1I = lisp_rle ( None )
   I1i1i111Ii1I . rle_nodes = [ ]
   while ( OOooo0o0OOO > 0 ) :
    o000000Oo , Ooo000O00o , IiIiIii11Ii , ii1iI1i1 = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 53 - 53: OOooOOo / I1IiiI / oO0o * OOooOOo / i1IIi - I1Ii111
    ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
    if ( ii1iI1i1 == LISP_AFI_LCAF ) : return ( None )
    if 71 - 71: O0 + Oo0Ooo % oO0o - o0oOOo0O0Ooo
    iiiI1Ii = lisp_rle_node ( )
    I1i1i111Ii1I . rle_nodes . append ( iiiI1Ii )
    if 82 - 82: iIii1I11I1II1
    iiiI1Ii . level = IiIiIii11Ii
    iiiI1Ii . address . afi = ii1iI1i1
    iiiI1Ii . address . mask_len = iiiI1Ii . address . host_mask_len ( )
    packet = iiiI1Ii . address . unpack_address ( packet [ 6 : : ] )
    if 64 - 64: ooOoO0o + I1IiiI % OOooOOo + II111iiii
    OOooo0o0OOO -= iiiI1Ii . address . addr_length ( ) + 6
    if ( OOooo0o0OOO >= 2 ) :
     ii1iI1i1 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( ii1iI1i1 ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , iiiI1Ii . rloc_name = lisp_decode_dist_name ( packet )
      if 46 - 46: I1IiiI
      if ( packet == None ) : return ( None )
      OOooo0o0OOO -= len ( iiiI1Ii . rloc_name ) + 1 + 2
      if 72 - 72: iII111i
      if 100 - 100: I1IiiI
      if 55 - 55: i1IIi % IiII
   self . rle = I1i1i111Ii1I
   self . rle . build_forwarding_list ( )
   if 44 - 44: oO0o - iIii1I11I1II1 / ooOoO0o - iIii1I11I1II1 % i1IIi + ooOoO0o
  elif ( ii1i == LISP_LCAF_SECURITY_TYPE ) :
   if 74 - 74: I11i . OoOoOO00 + OoOoOO00
   if 87 - 87: IiII + o0oOOo0O0Ooo . i1IIi % I1Ii111
   if 44 - 44: Oo0Ooo - OOooOOo . Ii1I * OoooooooOO
   if 93 - 93: OoO0O00 . OoO0O00
   if 52 - 52: OOooOOo . oO0o / Oo0Ooo . OoooooooOO % I1ii11iIi11i
   ooOiiIII = packet
   i11i1iI = lisp_keys ( 1 )
   packet = i11i1iI . decode_lcaf ( ooOiiIII , OOooo0o0OOO )
   if ( packet == None ) : return ( None )
   if 65 - 65: ooOoO0o % II111iiii . iII111i - iIii1I11I1II1 - I1IiiI
   if 63 - 63: I1IiiI . OoOoOO00 - II111iiii
   if 55 - 55: ooOoO0o - o0oOOo0O0Ooo
   if 32 - 32: I1Ii111 * Ii1I / I1Ii111 . OoOoOO00 + I1ii11iIi11i - ooOoO0o
   iII1i = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( i11i1iI . cipher_suite in iII1i ) :
    if ( i11i1iI . cipher_suite == LISP_CS_25519_CBC ) :
     OOo0O = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 14 - 14: IiII * O0 + O0 - ooOoO0o . i11iIiiIii - IiII
    if ( i11i1iI . cipher_suite == LISP_CS_25519_CHACHA ) :
     OOo0O = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 37 - 37: I11i
   else :
    OOo0O = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 19 - 19: OoooooooOO % I1Ii111
   packet = OOo0O . decode_lcaf ( ooOiiIII , OOooo0o0OOO )
   if ( packet == None ) : return ( None )
   if 57 - 57: OoOoOO00 + i1IIi . iIii1I11I1II1 . iIii1I11I1II1 / iIii1I11I1II1 % oO0o
   if ( len ( packet ) < 2 ) : return ( None )
   ii1iI1i1 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( ii1iI1i1 )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 7 - 7: i11iIiiIii * I1ii11iIi11i / OoO0O00 * oO0o
   if 35 - 35: IiII . i1IIi + I1ii11iIi11i . IiII + ooOoO0o . oO0o
   if 2 - 2: II111iiii
   if 18 - 18: iIii1I11I1II1 % I1ii11iIi11i % Oo0Ooo
   if 47 - 47: ooOoO0o - I1IiiI % OOooOOo * Ii1I % I1IiiI
   if 95 - 95: OoO0O00 + OoOoOO00 % Oo0Ooo . Ii1I * I1IiiI + I1Ii111
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 22 - 22: Oo0Ooo . OoO0O00
   OO0o0ooo0o0 = self . rloc_name
   if ( OO0o0ooo0o0 ) : OO0o0ooo0o0 = blue ( self . rloc_name , False )
   if 36 - 36: OoooooooOO + OoOoOO00 + Oo0Ooo + II111iiii
   if 32 - 32: IiII
   if 82 - 82: i11iIiiIii - oO0o - i1IIi
   if 78 - 78: oO0o % iII111i / i1IIi / ooOoO0o
   if 44 - 44: o0oOOo0O0Ooo + Ii1I + I1IiiI % O0
   if 100 - 100: OoooooooOO
   Oo0o = self . keys [ 1 ] if self . keys else None
   if ( Oo0o == None ) :
    if ( OOo0O . remote_public_key == None ) :
     i1iiiIi11 = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( i1iiiIi11 , OO0o0ooo0o0 ) )
     OOo0O = None
    else :
     i1iiiIi11 = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( i1iiiIi11 , OO0o0ooo0o0 ) )
     OOo0O . compute_shared_key ( "encap" )
     if 27 - 27: i11iIiiIii % II111iiii + I1Ii111
     if 76 - 76: OOooOOo - I1Ii111 + iIii1I11I1II1 + I1IiiI * oO0o
     if 93 - 93: i11iIiiIii * i11iIiiIii - I1IiiI + iIii1I11I1II1 * i11iIiiIii
     if 14 - 14: ooOoO0o . OoooooooOO . I1IiiI - IiII + iIii1I11I1II1
     if 47 - 47: OOooOOo % i1IIi
     if 23 - 23: Ii1I * Ii1I / I11i
     if 11 - 11: OOooOOo
     if 58 - 58: OoO0O00 * OoooooooOO
     if 47 - 47: iII111i - Oo0Ooo
     if 19 - 19: O0 . i1IIi + I11i / II111iiii + ooOoO0o
   if ( Oo0o ) :
    if ( OOo0O . remote_public_key == None ) :
     OOo0O = None
     OOO0oOO = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( OOO0oOO , OO0o0ooo0o0 ) )
    elif ( Oo0o . compare_keys ( OOo0O ) ) :
     OOo0O = Oo0o
     lprint ( "    Maintain stored encap-keys for {}" . format ( OO0o0ooo0o0 ) )
     if 26 - 26: Ii1I * oO0o % I1IiiI - OOooOOo . I1Ii111
    else :
     if ( Oo0o . remote_public_key == None ) :
      i1iiiIi11 = "New encap-keying for existing state"
     else :
      i1iiiIi11 = "Remote encap-rekeying"
      if 35 - 35: i1IIi % i11iIiiIii + Ii1I
     lprint ( "    {} for {}" . format ( bold ( i1iiiIi11 , False ) ,
 OO0o0ooo0o0 ) )
     Oo0o . remote_public_key = OOo0O . remote_public_key
     Oo0o . compute_shared_key ( "encap" )
     OOo0O = Oo0o
     if 14 - 14: OoO0O00 * OoooooooOO
     if 45 - 45: iIii1I11I1II1 * I1IiiI . OoOoOO00
   self . keys = [ None , OOo0O , None , None ]
   if 97 - 97: I11i % II111iiii % Ii1I . II111iiii . iIii1I11I1II1
  else :
   if 98 - 98: i11iIiiIii + O0 - O0 - iII111i
   if 25 - 25: oO0o / O0 + I1Ii111 % i11iIiiIii / I1IiiI
   if 62 - 62: iII111i . I11i * i1IIi + iII111i
   if 95 - 95: Ii1I / o0oOOo0O0Ooo % ooOoO0o - I1IiiI / OOooOOo * OOooOOo
   packet = packet [ OOooo0o0OOO : : ]
   if 6 - 6: OoO0O00 % IiII + iIii1I11I1II1
  return ( packet )
  if 18 - 18: II111iiii . Ii1I + OoOoOO00 + O0 - I11i
  if 30 - 30: II111iiii
 def decode ( self , packet , nonce ) :
  Iii1 = "BBBBHH"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 26 - 26: I11i - i1IIi - Oo0Ooo * O0 * OOooOOo . OoooooooOO
  self . priority , self . weight , self . mpriority , self . mweight , OoOoo0ooO0000 , ii1iI1i1 = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 99 - 99: oO0o . OoO0O00 / OOooOOo
  if 12 - 12: iIii1I11I1II1 + ooOoO0o * I1Ii111 % OoooooooOO / iIii1I11I1II1
  OoOoo0ooO0000 = socket . ntohs ( OoOoo0ooO0000 )
  ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
  self . local_bit = True if ( OoOoo0ooO0000 & 0x0004 ) else False
  self . probe_bit = True if ( OoOoo0ooO0000 & 0x0002 ) else False
  self . reach_bit = True if ( OoOoo0ooO0000 & 0x0001 ) else False
  if 43 - 43: O0 . i1IIi - OoooooooOO - i1IIi - I1ii11iIi11i
  if ( ii1iI1i1 == LISP_AFI_LCAF ) :
   packet = packet [ O00O - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = ii1iI1i1
   packet = packet [ O00O : : ]
   packet = self . rloc . unpack_address ( packet )
   if 8 - 8: OoOoOO00 / Ii1I
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 12 - 12: iIii1I11I1II1
  if 52 - 52: oO0o . I1ii11iIi11i + oO0o
 def end_of_rlocs ( self , packet , rloc_count ) :
  for o0Ooo0O00 in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 73 - 73: II111iiii / i11iIiiIii / ooOoO0o
  return ( packet )
  if 1 - 1: iII111i + OoOoOO00 / IiII - I1IiiI % I1IiiI
  if 6 - 6: OoOoOO00 - i1IIi + II111iiii % oO0o
  if 72 - 72: OOooOOo + OOooOOo
  if 30 - 30: I11i
  if 15 - 15: O0 - i1IIi . iIii1I11I1II1 - i11iIiiIii / Ii1I
  if 11 - 11: iIii1I11I1II1 + I1IiiI
  if 15 - 15: o0oOOo0O0Ooo
  if 55 - 55: i11iIiiIii / OoooooooOO - I11i
  if 89 - 89: I11i - i1IIi - i1IIi * OOooOOo - O0
  if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
  if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
  if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
  if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
  if 9 - 9: Ii1I
  if 76 - 76: I1IiiI % Oo0Ooo / iIii1I11I1II1 - Oo0Ooo
  if 34 - 34: OoOoOO00 - i1IIi + OOooOOo + Ii1I . o0oOOo0O0Ooo
  if 42 - 42: OoO0O00
  if 59 - 59: OoO0O00 . I1Ii111 % OoO0O00
  if 22 - 22: Oo0Ooo
  if 21 - 21: o0oOOo0O0Ooo
  if 86 - 86: ooOoO0o / iIii1I11I1II1 . OOooOOo
  if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
  if 30 - 30: OoOoOO00 . OOooOOo % OOooOOo / II111iiii + i1IIi
  if 61 - 61: i1IIi % II111iiii * II111iiii . o0oOOo0O0Ooo / I1ii11iIi11i - I1Ii111
  if 93 - 93: Ii1I - i1IIi
  if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
  if 58 - 58: Ii1I * I11i
  if 95 - 95: oO0o
  if 49 - 49: I1IiiI
  if 23 - 23: I1Ii111
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
  if 54 - 54: ooOoO0o - O0 + iII111i
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # oO0o + I11i % OOooOOo
 lisp_hex_string ( self . nonce ) ) )
  if 84 - 84: oO0o / O0 - OoooooooOO
  if 87 - 87: iIii1I11I1II1
 def encode ( self ) :
  i11iI1 = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  oOo0O000oo0 = struct . pack ( "I" , socket . htonl ( i11iI1 ) )
  oOo0O000oo0 += struct . pack ( "Q" , self . nonce )
  return ( oOo0O000oo0 )
  if 28 - 28: ooOoO0o % I11i + o0oOOo0O0Ooo - I1Ii111 . OoO0O00 * OoOoOO00
  if 64 - 64: I11i * i1IIi + i1IIi * I1ii11iIi11i . ooOoO0o
 def decode ( self , packet ) :
  Iii1 = "I"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 37 - 37: I11i % iIii1I11I1II1 % I1ii11iIi11i
  i11iI1 = struct . unpack ( Iii1 , packet [ : O00O ] )
  i11iI1 = socket . ntohl ( i11iI1 [ 0 ] )
  self . record_count = i11iI1 & 0xff
  packet = packet [ O00O : : ]
  if 61 - 61: o0oOOo0O0Ooo * O0
  Iii1 = "Q"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 84 - 84: I11i * oO0o
  self . nonce = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
  packet = packet [ O00O : : ]
  return ( packet )
  if 89 - 89: o0oOOo0O0Ooo
  if 95 - 95: i1IIi . OoOoOO00 % OoOoOO00 + OOooOOo / OoooooooOO
  if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
  if 85 - 85: O0 - OoOoOO00
  if 17 - 17: o0oOOo0O0Ooo / i1IIi / OOooOOo
  if 91 - 91: I1ii11iIi11i / Ii1I - OoOoOO00 . I11i / oO0o
  if 16 - 16: IiII % iII111i . oO0o . I1IiiI % O0 * I11i
  if 99 - 99: OoOoOO00 / OoooooooOO + iII111i * I11i * i11iIiiIii + OOooOOo
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 40 - 40: II111iiii / I11i % I1IiiI - O0
  if 39 - 39: i11iIiiIii - OoOoOO00 % OOooOOo + ooOoO0o + i11iIiiIii
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 59 - 59: IiII / OoOoOO00 - I1Ii111 - ooOoO0o . oO0o
  if 87 - 87: oO0o + I1IiiI * I1Ii111 * o0oOOo0O0Ooo + O0
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 21 - 21: I1Ii111 + OoOoOO00 + OoOoOO00 . II111iiii / I1Ii111 . I1IiiI
  if 66 - 66: I1Ii111 % oO0o . iII111i * i1IIi
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  oooo0oOOooo0 = self . delegation_set [ 0 ]
  return ( oooo0oOOooo0 . print_node_type ( ) )
  if 88 - 88: OOooOOo % OoooooooOO
  if 28 - 28: i11iIiiIii % OoO0O00 - IiII + OOooOOo . o0oOOo0O0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 66 - 66: II111iiii + I1ii11iIi11i - OoOoOO00 . o0oOOo0O0Ooo / IiII % OoOoOO00
  if 32 - 32: iII111i . OOooOOo * o0oOOo0O0Ooo - Oo0Ooo % O0
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   OoII1i = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( OoII1i == None ) :
    OoII1i = lisp_ddt_entry ( )
    OoII1i . eid . copy_address ( self . group )
    OoII1i . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , OoII1i )
    if 96 - 96: Oo0Ooo + I1ii11iIi11i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OoII1i . group )
   OoII1i . add_source_entry ( self )
   if 94 - 94: OoooooooOO / i1IIi + Oo0Ooo
   if 57 - 57: O0
   if 83 - 83: OOooOOo / Ii1I * I1IiiI % oO0o / iIii1I11I1II1
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 1 - 1: I11i / OoooooooOO / iII111i
  if 68 - 68: i1IIi / Oo0Ooo / I11i * Oo0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 91 - 91: OoO0O00 . iII111i
  if 82 - 82: I1ii11iIi11i / Oo0Ooo
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 63 - 63: I1IiiI
  if 3 - 3: iII111i + I1ii11iIi11i
  if 35 - 35: oO0o * iII111i * oO0o * I1Ii111 * IiII * i1IIi
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 43 - 43: OoO0O00 * I1IiiI / IiII . i11iIiiIii + iII111i + o0oOOo0O0Ooo
  if 1 - 1: I1IiiI % o0oOOo0O0Ooo . I1Ii111 + I11i * oO0o
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 41 - 41: OoO0O00 * oO0o - II111iiii
  if 2 - 2: IiII + IiII - OoO0O00 * iII111i . oO0o
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 91 - 91: ooOoO0o
  if 22 - 22: ooOoO0o % OoO0O00 * OoOoOO00 + Oo0Ooo
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 44 - 44: O0 - I11i
  if 43 - 43: O0
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 50 - 50: I11i - OoooooooOO
  if 29 - 29: oO0o * oO0o
  if 44 - 44: ooOoO0o . I1IiiI * oO0o * Ii1I
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
  if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
  if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
  if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
class lisp_ddt_map_request ( ) :
 def __init__ ( self , lisp_sockets , packet , eid , group , nonce ) :
  self . uptime = lisp_get_timestamp ( )
  self . lisp_sockets = lisp_sockets
  self . packet = packet
  self . eid = eid
  self . group = group
  self . nonce = nonce
  self . mr_source = None
  self . sport = 0
  self . itr = None
  self . retry_count = 0
  self . send_count = 0
  self . retransmit_timer = None
  self . last_request_sent_to = None
  self . from_pitr = False
  self . tried_root = False
  self . last_cached_prefix = [ None , None ]
  if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
  if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # IiII . OoOoOO00 % Ii1I - i1IIi . iIii1I11I1II1 / I1Ii111
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 75 - 75: II111iiii / oO0o
  if 26 - 26: I11i - i1IIi % OOooOOo - OoooooooOO
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 23 - 23: OoOoOO00 + I1Ii111 * OoO0O00
  if 22 - 22: OoO0O00
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 28 - 28: OoO0O00 + IiII % Oo0Ooo
   if 95 - 95: i11iIiiIii / I1Ii111 - I1Ii111
   if 61 - 61: OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
  if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
  if 87 - 87: I1IiiI + OoooooooOO + O0
  if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
  if 65 - 65: IiII
  if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
  if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
  if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
  if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
  if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
  if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
  if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
  if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
  if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
  if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
  if 38 - 38: IiII / i1IIi
  if 60 - 60: OoOoOO00
  if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
  if 61 - 61: IiII . IiII
  if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
if 95 - 95: iII111i / ooOoO0o + I1Ii111
if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
if 81 - 81: I1ii11iIi11i
if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
if 76 - 76: I1Ii111 - O0
if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
if 7 - 7: II111iiii + I11i
if 99 - 99: iIii1I11I1II1 * oO0o
if 37 - 37: ooOoO0o * iII111i * I11i
if 11 - 11: I1IiiI
if 48 - 48: O0 . I11i
if 9 - 9: oO0o / Oo0Ooo
if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
if 31 - 31: oO0o
if 74 - 74: OoO0O00
if 11 - 11: oO0o + O0 % Ii1I . I11i * o0oOOo0O0Ooo
if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
if 30 - 30: i11iIiiIii % OOooOOo
if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
if 27 - 27: I1IiiI + OoOoOO00 + iII111i
if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
if 34 - 34: i1IIi % Oo0Ooo . oO0o
if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
if 62 - 62: Oo0Ooo . OoO0O00 * I1Ii111 . i11iIiiIii * O0
if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
if 62 - 62: I1IiiI . Ii1I
if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
if 52 - 52: Ii1I - I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo
if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
if 40 - 40: OoOoOO00 - II111iiii
if 29 - 29: I1IiiI - O0
if 36 - 36: I1IiiI * I1IiiI
if 79 - 79: I1Ii111 - I11i
if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
if 18 - 18: II111iiii . o0oOOo0O0Ooo
if 75 - 75: OoooooooOO - Oo0Ooo
if 56 - 56: II111iiii - i11iIiiIii - oO0o . o0oOOo0O0Ooo
if 4 - 4: i1IIi
if 91 - 91: IiII . OoO0O00 * Ii1I / o0oOOo0O0Ooo
if 41 - 41: I1IiiI . OoO0O00 / i1IIi . Oo0Ooo . oO0o
class lisp_info ( ) :
 def __init__ ( self ) :
  self . info_reply = False
  self . nonce = 0
  self . private_etr_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . global_etr_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . global_ms_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . ms_port = 0
  self . etr_port = 0
  self . rtr_list = [ ]
  self . hostname = lisp_hostname
  if 44 - 44: iII111i * I11i + i11iIiiIii + i1IIi / IiII * II111iiii
  if 58 - 58: OOooOOo
 def print_info ( self ) :
  if ( self . info_reply ) :
   OOO00O = "Info-Reply"
   IiiI11iiI1i1 = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # ooOoO0o
   # ooOoO0o * iII111i % OOooOOo - IiII - OoOoOO00 % IiII
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : IiiI11iiI1i1 += "empty, "
   for ooooOoOOO0 in self . rtr_list :
    IiiI11iiI1i1 += red ( ooooOoOOO0 . print_address_no_iid ( ) , False ) + ", "
    if 84 - 84: Ii1I . I1ii11iIi11i - o0oOOo0O0Ooo . Oo0Ooo + O0
   IiiI11iiI1i1 = IiiI11iiI1i1 [ 0 : - 2 ]
  else :
   OOO00O = "Info-Request"
   O0Ooo = "<none>" if self . hostname == None else self . hostname
   IiiI11iiI1i1 = ", hostname: {}" . format ( blue ( O0Ooo , False ) )
   if 11 - 11: OoooooooOO - Ii1I % oO0o - OoOoOO00 - OoO0O00 + Oo0Ooo
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( OOO00O , False ) ,
 lisp_hex_string ( self . nonce ) , IiiI11iiI1i1 ) )
  if 32 - 32: Oo0Ooo + oO0o / I11i - I1IiiI - OoO0O00 * OoOoOO00
  if 50 - 50: I1ii11iIi11i + I11i * iII111i
 def encode ( self ) :
  i11iI1 = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : i11iI1 |= ( 1 << 27 )
  if 27 - 27: OoOoOO00 * OOooOOo * iIii1I11I1II1 / i1IIi
  if 60 - 60: OOooOOo * I1Ii111 . oO0o
  if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
  if 51 - 51: I1IiiI . I11i - OoOoOO00
  if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
  oOo0O000oo0 = struct . pack ( "I" , socket . htonl ( i11iI1 ) )
  oOo0O000oo0 += struct . pack ( "Q" , self . nonce )
  oOo0O000oo0 += struct . pack ( "III" , 0 , 0 , 0 )
  if 97 - 97: Ii1I . Ii1I % iII111i
  if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
  if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
  if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    oOo0O000oo0 += struct . pack ( "H" , 0 )
   else :
    oOo0O000oo0 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    oOo0O000oo0 += self . hostname + "\0"
    if 25 - 25: I11i - I1ii11iIi11i
   return ( oOo0O000oo0 )
   if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
   if 83 - 83: O0
   if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
   if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
   if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
  ii1iI1i1 = socket . htons ( LISP_AFI_LCAF )
  ii1i = LISP_LCAF_NAT_TYPE
  OOooo0o0OOO = socket . htons ( 16 )
  oOOOOOoOoo = socket . htons ( self . ms_port )
  I1IiiI1iIiI = socket . htons ( self . etr_port )
  oOo0O000oo0 += struct . pack ( "HHBBHHHH" , ii1iI1i1 , 0 , ii1i , 0 , OOooo0o0OOO ,
 oOOOOOoOoo , I1IiiI1iIiI , socket . htons ( self . global_etr_rloc . afi ) )
  oOo0O000oo0 += self . global_etr_rloc . pack_address ( )
  oOo0O000oo0 += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  oOo0O000oo0 += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : oOo0O000oo0 += struct . pack ( "H" , 0 )
  if 44 - 44: I1IiiI * I11i % Ii1I + ooOoO0o * ooOoO0o / OoooooooOO
  if 77 - 77: OOooOOo % OOooOOo * Oo0Ooo / iII111i - OoooooooOO - iII111i
  if 52 - 52: I1Ii111 + i1IIi % iII111i % I11i * iIii1I11I1II1 % o0oOOo0O0Ooo
  if 77 - 77: iIii1I11I1II1 * OOooOOo % ooOoO0o
  for ooooOoOOO0 in self . rtr_list :
   oOo0O000oo0 += struct . pack ( "H" , socket . htons ( ooooOoOOO0 . afi ) )
   oOo0O000oo0 += ooooOoOOO0 . pack_address ( )
   if 80 - 80: II111iiii
  return ( oOo0O000oo0 )
  if 66 - 66: Oo0Ooo . I1Ii111
  if 59 - 59: iII111i - I1IiiI . I1IiiI - Ii1I * OoOoOO00
 def decode ( self , packet ) :
  ooOiiIII = packet
  Iii1 = "I"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
  i11iI1 = struct . unpack ( Iii1 , packet [ : O00O ] )
  i11iI1 = i11iI1 [ 0 ]
  packet = packet [ O00O : : ]
  if 11 - 11: Ii1I
  Iii1 = "Q"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
  OoI1 = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
  i11iI1 = socket . ntohl ( i11iI1 )
  self . nonce = OoI1 [ 0 ]
  self . info_reply = i11iI1 & 0x08000000
  self . hostname = None
  packet = packet [ O00O : : ]
  if 50 - 50: Oo0Ooo
  if 14 - 14: O0
  if 67 - 67: II111iiii / O0
  if 10 - 10: i1IIi / Oo0Ooo
  if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
  Iii1 = "HH"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
  if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
  if 50 - 50: o0oOOo0O0Ooo
  if 85 - 85: II111iiii . iII111i - i1IIi
  if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
  IiIiIi1I1 , I1Iii11I = struct . unpack ( Iii1 , packet [ : O00O ] )
  if ( I1Iii11I != 0 ) : return ( None )
  if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
  packet = packet [ O00O : : ]
  Iii1 = "IBBH"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
  OoI1iI , OOo0OO00 , iIiIIIIiiiii , Oo00Oo = struct . unpack ( Iii1 ,
 packet [ : O00O ] )
  if 18 - 18: Ii1I % o0oOOo0O0Ooo - Oo0Ooo
  if ( Oo00Oo != 0 ) : return ( None )
  packet = packet [ O00O : : ]
  if 28 - 28: IiII
  if 93 - 93: Oo0Ooo % i1IIi
  if 51 - 51: oO0o % O0
  if 41 - 41: I1IiiI * I1IiiI . I1Ii111
  if ( self . info_reply == False ) :
   Iii1 = "H"
   O00O = struct . calcsize ( Iii1 )
   if ( len ( packet ) >= O00O ) :
    ii1iI1i1 = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
    if ( socket . ntohs ( ii1iI1i1 ) == LISP_AFI_NAME ) :
     packet = packet [ O00O : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 38 - 38: I1IiiI % i11iIiiIii
     if 17 - 17: i11iIiiIii
   return ( ooOiiIII )
   if 81 - 81: I1Ii111
   if 25 - 25: I1IiiI
   if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
   if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
   if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
  Iii1 = "HHBBHHH"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 33 - 33: II111iiii + Ii1I
  ii1iI1i1 , o000000Oo , ii1i , OOo0OO00 , OOooo0o0OOO , oOOOOOoOoo , I1IiiI1iIiI = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
  if ( socket . ntohs ( ii1iI1i1 ) != LISP_AFI_LCAF ) : return ( None )
  if 59 - 59: I11i % Ii1I / OoOoOO00
  self . ms_port = socket . ntohs ( oOOOOOoOoo )
  self . etr_port = socket . ntohs ( I1IiiI1iIiI )
  packet = packet [ O00O : : ]
  if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
  if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
  if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
  if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
  Iii1 = "H"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 80 - 80: Oo0Ooo
  if 58 - 58: I1Ii111 + OOooOOo
  if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
  if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
  ii1iI1i1 = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
  packet = packet [ O00O : : ]
  if ( ii1iI1i1 != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( ii1iI1i1 )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
   if 76 - 76: iII111i - iIii1I11I1II1
   if 23 - 23: I11i / OoO0O00 % OOooOOo
   if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
   if 21 - 21: Ii1I % O0
   if 15 - 15: II111iiii * Ii1I + IiII % iII111i
  if ( len ( packet ) < O00O ) : return ( ooOiiIII )
  if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
  ii1iI1i1 = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
  packet = packet [ O00O : : ]
  if ( ii1iI1i1 != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( ii1iI1i1 )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( ooOiiIII )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 35 - 35: I1IiiI
   if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
   if 72 - 72: Ii1I
   if 87 - 87: iII111i - I1IiiI
   if 54 - 54: iIii1I11I1II1 + oO0o * o0oOOo0O0Ooo % OoooooooOO . Oo0Ooo
  if ( len ( packet ) < O00O ) : return ( ooOiiIII )
  if 32 - 32: iII111i
  ii1iI1i1 = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
  packet = packet [ O00O : : ]
  if ( ii1iI1i1 != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( ii1iI1i1 )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( ooOiiIII )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 33 - 33: ooOoO0o + Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - OoO0O00
   if 40 - 40: I11i . OoooooooOO * O0 / I1Ii111 + O0
   if 97 - 97: ooOoO0o - ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - I1Ii111
   if 52 - 52: O0 % iII111i
   if 81 - 81: OoooooooOO % OoOoOO00 % Oo0Ooo - I1IiiI
   if 43 - 43: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  while ( len ( packet ) >= O00O ) :
   ii1iI1i1 = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
   packet = packet [ O00O : : ]
   if ( ii1iI1i1 == 0 ) : continue
   ooooOoOOO0 = lisp_address ( socket . ntohs ( ii1iI1i1 ) , "" , 0 , 0 )
   packet = ooooOoOOO0 . unpack_address ( packet )
   if ( packet == None ) : return ( ooOiiIII )
   ooooOoOOO0 . mask_len = ooooOoOOO0 . host_mask_len ( )
   self . rtr_list . append ( ooooOoOOO0 )
   if 48 - 48: O0
  return ( ooOiiIII )
  if 5 - 5: OOooOOo / i11iIiiIii . I11i % OOooOOo
  if 1 - 1: II111iiii + O0 * OoOoOO00 / IiII . O0
  if 87 - 87: IiII + I1IiiI
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 74 - 74: OoO0O00 + OoO0O00 % iII111i / I11i / O0
  if 54 - 54: o0oOOo0O0Ooo / OoooooooOO * ooOoO0o . OoOoOO00 - I1Ii111
 def timed_out ( self ) :
  OOo0 = time . time ( ) - self . uptime
  return ( OOo0 >= ( LISP_INFO_INTERVAL * 2 ) )
  if 69 - 69: oO0o - OoO0O00
  if 80 - 80: ooOoO0o + iIii1I11I1II1 . II111iiii + I1IiiI - oO0o % OoOoOO00
  if 10 - 10: iIii1I11I1II1
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 44 - 44: OoOoOO00 * oO0o . I1ii11iIi11i + i11iIiiIii
  if 85 - 85: I11i
 def cache_address_for_info_source ( self ) :
  OOo0O = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ OOo0O ] = self
  if 36 - 36: ooOoO0o % OoO0O00
  if 1 - 1: OoooooooOO - OoOoOO00
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 35 - 35: I1Ii111
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
  if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
  if 92 - 92: iII111i % I1ii11iIi11i
  if 16 - 16: oO0o
  if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
  if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
  if 52 - 52: ooOoO0o
  if 38 - 38: OoO0O00 + I1IiiI % IiII
  if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
  if 65 - 65: OoOoOO00
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
  if 97 - 97: Ii1I - IiII
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  ii11iI1Iii1iI = auth1 + auth2 + auth3
  if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  ii11iI1Iii1iI = auth1 + auth2 + auth3 + auth4
  if 81 - 81: I1ii11iIi11i
 return ( ii11iI1Iii1iI )
 if 64 - 64: oO0o * OoO0O00 / OOooOOo + Ii1I % Oo0Ooo . IiII
 if 2 - 2: I1Ii111 + I11i
 if 47 - 47: i11iIiiIii + iIii1I11I1II1 % I1ii11iIi11i - oO0o % OoO0O00
 if 85 - 85: oO0o * OoOoOO00 / OoOoOO00
 if 85 - 85: OOooOOo / I1Ii111 . i1IIi / OoOoOO00 + iIii1I11I1II1
 if 71 - 71: OoO0O00
 if 96 - 96: I1ii11iIi11i / I1IiiI - I1ii11iIi11i / II111iiii - IiII
 if 74 - 74: Ii1I * OoooooooOO % OOooOOo + OoooooooOO + iII111i
 if 83 - 83: i1IIi
 if 2 - 2: i1IIi / OOooOOo * O0
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   oooiIi1iiIii = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 5 - 5: O0 . i11iIiiIii
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   oooiIi1iiIii = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
  oooiIi1iiIii . bind ( ( local_addr , int ( port ) ) )
 else :
  i11I1II = port
  if ( os . path . exists ( i11I1II ) ) :
   os . system ( "rm " + i11I1II )
   time . sleep ( 1 )
   if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
  oooiIi1iiIii = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  oooiIi1iiIii . bind ( i11I1II )
  if 86 - 86: i1IIi
 return ( oooiIi1iiIii )
 if 81 - 81: OoOoOO00
 if 52 - 52: iII111i * IiII % I1IiiI * I11i
 if 73 - 73: I1Ii111 * ooOoO0o
 if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
 if 14 - 14: iII111i / OoO0O00
 if 75 - 75: IiII
 if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   oooiIi1iiIii = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   oooiIi1iiIii = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  oooiIi1iiIii = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  oooiIi1iiIii . bind ( internal_name )
  if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
 return ( oooiIi1iiIii )
 if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
 if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
 if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
 if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
 if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
 if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
 if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 38 - 38: OoOoOO00 + OoO0O00 . i11iIiiIii + Ii1I % i1IIi % I1IiiI
 if 93 - 93: i11iIiiIii
 if 63 - 63: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo
 if 97 - 97: i1IIi % I11i % OoOoOO00
 if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
 if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
 if 100 - 100: I1ii11iIi11i - i1IIi - OoO0O00 * o0oOOo0O0Ooo + OoOoOO00
 if 31 - 31: i1IIi
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 21 - 21: o0oOOo0O0Ooo / O0 % O0 . OoooooooOO / I1IiiI
 if 94 - 94: ooOoO0o + OoO0O00 / ooOoO0o - ooOoO0o + Oo0Ooo + o0oOOo0O0Ooo
 if 50 - 50: oO0o . Oo0Ooo
 if 15 - 15: Ii1I
 if 64 - 64: OoooooooOO
 if 25 - 25: IiII
 if 29 - 29: OoOoOO00 % ooOoO0o * OoooooooOO
 if 8 - 8: i11iIiiIii - I1Ii111 / IiII
 if 17 - 17: i11iIiiIii * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO . OoOoOO00 - I1ii11iIi11i
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 78 - 78: I1ii11iIi11i - OoooooooOO + O0
 if 15 - 15: I1ii11iIi11i / IiII % I1IiiI
 if 16 - 16: Ii1I
 if 26 - 26: o0oOOo0O0Ooo / I11i + OoOoOO00 / OoOoOO00
 if 31 - 31: I1Ii111
 if 84 - 84: i11iIiiIii * OOooOOo . iII111i - Ii1I * i1IIi - I1ii11iIi11i
 if 1 - 1: II111iiii
 if 94 - 94: I1ii11iIi11i * iII111i % iII111i % I11i - iII111i
 if 38 - 38: IiII - OoO0O00 % Ii1I - II111iiii
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 97 - 97: O0 . Ii1I
 if 52 - 52: IiII
 if 86 - 86: I1Ii111 / O0 + OoooooooOO % oO0o
 if 45 - 45: I1IiiI . Oo0Ooo . I11i . Ii1I
 if 81 - 81: II111iiii + OoOoOO00 % i11iIiiIii / iII111i . I1Ii111 + II111iiii
 if 48 - 48: I1IiiI . I1ii11iIi11i * OoOoOO00 % i1IIi / I1Ii111 * II111iiii
 if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 75 - 75: OoooooooOO / ooOoO0o - iII111i . OoooooooOO . OoOoOO00 % i1IIi
 if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
 if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
 if 39 - 39: OoO0O00 . ooOoO0o
 if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
 if 7 - 7: oO0o
 if 41 - 41: ooOoO0o
 if 93 - 93: Ii1I + I1Ii111 + Ii1I
 if 23 - 23: I1IiiI - i1IIi / ooOoO0o
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 4 - 4: IiII . I1ii11iIi11i + iII111i % ooOoO0o
 if 28 - 28: I1Ii111
 if 27 - 27: iII111i * I1IiiI
 if 60 - 60: i1IIi / I1IiiI - I1ii11iIi11i
 if 41 - 41: I1Ii111 + ooOoO0o / OOooOOo + I11i % Oo0Ooo
 if 91 - 91: I1IiiI % I1ii11iIi11i % oO0o / i1IIi * iIii1I11I1II1 + I11i
 if 48 - 48: ooOoO0o / I1ii11iIi11i / OoO0O00 / II111iiii * OoOoOO00
 if 73 - 73: I11i / I1IiiI - IiII - i1IIi * IiII - OOooOOo
 if 39 - 39: I11i . ooOoO0o * II111iiii
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 21 - 21: Ii1I
 if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
 if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
 if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
 if 45 - 45: II111iiii
 if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
 if 84 - 84: o0oOOo0O0Ooo
 if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
 if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
def lisp_ipc ( packet , send_socket , node ) :
 if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
 if 66 - 66: OOooOOo * Oo0Ooo
 if 58 - 58: OOooOOo
 if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
  if 13 - 13: ooOoO0o
 OoIiIiI1 = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 23 - 23: OoooooooOO
 O00O00O000OOO = 0
 O0oOOOO00oOOo = len ( packet )
 iIIi1Ii1I = 0
 iIiI = .001
 while ( O0oOOOO00oOOo > 0 ) :
  i1I1II = min ( O0oOOOO00oOOo , OoIiIiI1 )
  iIIi1I = packet [ O00O00O000OOO : i1I1II + O00O00O000OOO ]
  if 85 - 85: OoooooooOO
  try :
   send_socket . sendto ( iIIi1I , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( iIIi1I ) , len ( packet ) , node ) )
   if 19 - 19: II111iiii % II111iiii % iII111i * I11i
   iIIi1Ii1I = 0
   iIiI = .001
   if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
  except socket . error , IIIII1iii11 :
   if ( iIIi1Ii1I == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
    if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( iIIi1I ) , len ( packet ) , node , IIIII1iii11 ) )
   if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
   if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
   iIIi1Ii1I += 1
   time . sleep ( iIiI )
   if 63 - 63: I1ii11iIi11i - Ii1I + I11i
   lprint ( "Retrying after {} ms ..." . format ( iIiI * 1000 ) )
   iIiI *= 2
   continue
   if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
   if 72 - 72: O0 . OOooOOo
  O00O00O000OOO += i1I1II
  O0oOOOO00oOOo -= i1I1II
  if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
 return
 if 74 - 74: i1IIi
 if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
 if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
 if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
 if 35 - 35: i11iIiiIii + oO0o
 if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
 if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 O00O00O000OOO = 0
 I1iii1i1I = ""
 O0oOOOO00oOOo = len ( packet ) * 2
 while ( O00O00O000OOO < O0oOOOO00oOOo ) :
  I1iii1i1I += packet [ O00O00O000OOO : O00O00O000OOO + 8 ] + " "
  O00O00O000OOO += 8
  O0oOOOO00oOOo -= 4
  if 12 - 12: II111iiii - iIii1I11I1II1
 return ( I1iii1i1I )
 if 43 - 43: i11iIiiIii % OoO0O00
 if 100 - 100: i1IIi
 if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
 if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
 if 71 - 71: IiII + OoO0O00
 if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
 if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
def lisp_send ( lisp_sockets , dest , port , packet ) :
 Ii1iIi11 = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 17 - 17: iIii1I11I1II1
 if 10 - 10: i11iIiiIii / iII111i - oO0o
 if 98 - 98: Ii1I % iII111i . I11i
 if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i % o0oOOo0O0Ooo . ooOoO0o - oO0o
 if 64 - 64: I11i * ooOoO0o
 if 86 - 86: OoooooooOO * I1IiiI
 if 88 - 88: Ii1I + O0
 if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
 if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
 if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
 if 85 - 85: OoooooooOO * ooOoO0o
 if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
 II1i = dest . print_address_no_iid ( )
 if ( II1i . find ( "::ffff:" ) != - 1 and II1i . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : Ii1iIi11 = lisp_sockets [ 0 ]
  if ( Ii1iIi11 == None ) :
   Ii1iIi11 = lisp_sockets [ 0 ]
   II1i = II1i . split ( "::ffff:" ) [ - 1 ]
   if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
   if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
   if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + II1i , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
 if 62 - 62: I1Ii111 % II111iiii
 if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
 if 91 - 91: i11iIiiIii + Ii1I
 o0000oOO00 = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( o0000oOO00 ) :
  O0oIi11ii = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  o0000oOO00 = ( O0oIi11ii in [ 0x12 , 0x28 ] )
  if ( o0000oOO00 ) : lisp_set_ttl ( Ii1iIi11 , LISP_RLOC_PROBE_TTL )
  if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
  if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
 try : Ii1iIi11 . sendto ( packet , ( II1i , port ) )
 except socket . error , IIIII1iii11 :
  lprint ( "socket.sendto() failed: {}" . format ( IIIII1iii11 ) )
  if 93 - 93: Ii1I / iII111i
  if 100 - 100: Oo0Ooo
  if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
  if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
  if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
 if ( o0000oOO00 ) : lisp_set_ttl ( Ii1iIi11 , 64 )
 return
 if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
 if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
 if 72 - 72: I1Ii111 . OoO0O00
 if 59 - 59: I1IiiI * I11i % i1IIi
 if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
 if 60 - 60: iIii1I11I1II1
 if 13 - 13: II111iiii + Ii1I
 if 33 - 33: i1IIi
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
 if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
 if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
 if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
 if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
 i1I1II = total_length - len ( packet )
 if ( i1I1II == 0 ) : return ( [ True , packet ] )
 if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 81 - 81: i1IIi % iIii1I11I1II1
 if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
 if 82 - 82: ooOoO0o
 if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
 if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
 O0oOOOO00oOOo = i1I1II
 while ( O0oOOOO00oOOo > 0 ) :
  try : iIIi1I = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 59 - 59: i11iIiiIii / OoO0O00
  iIIi1I = iIIi1I [ 0 ]
  if 48 - 48: iIii1I11I1II1
  if 19 - 19: oO0o
  if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
  if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
  if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
  if ( iIIi1I . find ( "packet@" ) == 0 ) :
   O0oooO00oo0O = iIIi1I . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( iIIi1I ) ,
   # II111iiii . OoO0O00 + I1IiiI - I11i
 O0oooO00oo0O [ 1 ] if len ( O0oooO00oo0O ) > 2 else "?" )
   return ( [ False , iIIi1I ] )
   if 28 - 28: OoO0O00 * i11iIiiIii % OoO0O00
   if 84 - 84: oO0o . I1Ii111
  O0oOOOO00oOOo -= len ( iIIi1I )
  packet += iIIi1I
  if 100 - 100: OoOoOO00 + OoOoOO00
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( iIIi1I ) , total_length , source ) )
  if 26 - 26: II111iiii * iII111i + OOooOOo
  if 28 - 28: Ii1I + O0
 return ( [ True , packet ] )
 if 44 - 44: oO0o
 if 51 - 51: o0oOOo0O0Ooo * o0oOOo0O0Ooo . Ii1I
 if 14 - 14: OoO0O00 . I11i % II111iiii % i11iIiiIii + OoooooooOO
 if 50 - 50: i11iIiiIii * I11i + i11iIiiIii - i1IIi
 if 69 - 69: I1IiiI + IiII + oO0o * I1ii11iIi11i . iIii1I11I1II1 / OoooooooOO
 if 77 - 77: Oo0Ooo - ooOoO0o
 if 68 - 68: Ii1I * O0
 if 61 - 61: II111iiii - OoO0O00 . iIii1I11I1II1 * o0oOOo0O0Ooo . OoO0O00 % IiII
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 oOo0O000oo0 = ""
 for iIIi1I in payload : oOo0O000oo0 += iIIi1I + "\x40"
 return ( oOo0O000oo0 [ : - 1 ] )
 if 11 - 11: oO0o + I11i
 if 6 - 6: i1IIi . o0oOOo0O0Ooo + OoO0O00 + OOooOOo + oO0o
 if 30 - 30: O0
 if 98 - 98: I1Ii111
 if 58 - 58: OOooOOo
 if 6 - 6: I1ii11iIi11i
 if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
 if 18 - 18: ooOoO0o
 if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
 if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
 if 29 - 29: Ii1I . II111iiii / I1Ii111
 if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
 if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
 if 81 - 81: i11iIiiIii - II111iiii + I11i
 if 52 - 52: II111iiii
 if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
 if 26 - 26: I1ii11iIi11i - OoO0O00
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
 if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
 if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
  if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
  if 15 - 15: Ii1I
  if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
  try : OoOOOO0Oo0oO = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 95 - 95: o0oOOo0O0Ooo * I1ii11iIi11i - o0oOOo0O0Ooo
  if 47 - 47: I1IiiI / OoOoOO00 / II111iiii
  if 7 - 7: oO0o . ooOoO0o
  if 73 - 73: i1IIi % I1Ii111 * ooOoO0o % OoO0O00
  if 70 - 70: ooOoO0o * I1ii11iIi11i
  if 26 - 26: i11iIiiIii - II111iiii . II111iiii * oO0o / Ii1I + I1IiiI
  if ( internal == False ) :
   oOo0O000oo0 = OoOOOO0Oo0oO [ 0 ]
   i1Ii1I = lisp_convert_6to4 ( OoOOOO0Oo0oO [ 1 ] [ 0 ] )
   IIIIiI1ii1 = OoOOOO0Oo0oO [ 1 ] [ 1 ]
   if 12 - 12: OoO0O00 * iIii1I11I1II1 % I1Ii111 . O0 * OoOoOO00 * OOooOOo
   if ( IIIIiI1ii1 == LISP_DATA_PORT ) :
    iiiiI = lisp_data_plane_logging
    iI11 = lisp_format_packet ( oOo0O000oo0 [ 0 : 60 ] ) + " ..."
   else :
    iiiiI = True
    iI11 = lisp_format_packet ( oOo0O000oo0 )
    if 92 - 92: O0 * oO0o + OoOoOO00 / OoO0O00 * IiII
    if 80 - 80: oO0o
   if ( iiiiI ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( oOo0O000oo0 ) , bold ( "from " + i1Ii1I , False ) , IIIIiI1ii1 ,
 iI11 ) )
    if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
   return ( [ "packet" , i1Ii1I , IIIIiI1ii1 , oOo0O000oo0 ] )
   if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
   if 94 - 94: IiII
   if 69 - 69: I1Ii111 . I1Ii111
   if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
   if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
   if 8 - 8: iII111i % o0oOOo0O0Ooo
  o0o00oOOOo0 = False
  II1IiiI = OoOOOO0Oo0oO [ 0 ]
  Oo000ooO = False
  if 38 - 38: i1IIi
  while ( o0o00oOOOo0 == False ) :
   II1IiiI = II1IiiI . split ( "@" )
   if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
   if ( len ( II1IiiI ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( II1IiiI [ 0 ] ) )
    if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
    Oo000ooO = True
    break
    if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
    if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
   o0O00o = II1IiiI [ 0 ]
   try :
    oOooO0O0OOO0 = int ( II1IiiI [ 1 ] )
   except :
    II11 = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( II11 , OoOOOO0Oo0oO ) )
    Oo000ooO = True
    break
    if 39 - 39: ooOoO0o
   i1Ii1I = II1IiiI [ 2 ]
   IIIIiI1ii1 = II1IiiI [ 3 ]
   if 28 - 28: I11i * I11i + I11i / O0 - OOooOOo
   if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
   if 68 - 68: iII111i / OOooOOo
   if 28 - 28: II111iiii
   if 49 - 49: I1ii11iIi11i
   if 33 - 33: iIii1I11I1II1
   if 72 - 72: I1ii11iIi11i * i11iIiiIii
   if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
   if ( len ( II1IiiI ) > 5 ) :
    oOo0O000oo0 = lisp_bit_stuff ( II1IiiI [ 4 : : ] )
   else :
    oOo0O000oo0 = II1IiiI [ 4 ]
    if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
    if 45 - 45: Ii1I
    if 8 - 8: oO0o + OOooOOo
    if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
    if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
    if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
   o0o00oOOOo0 , oOo0O000oo0 = lisp_receive_segments ( lisp_socket , oOo0O000oo0 ,
 i1Ii1I , oOooO0O0OOO0 )
   if ( oOo0O000oo0 == None ) : return ( [ "" , "" , "" , "" ] )
   if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
   if 30 - 30: I11i + O0 / Ii1I / OoOoOO00 - oO0o + II111iiii
   if 21 - 21: iIii1I11I1II1 % OoooooooOO * OOooOOo % i1IIi
   if 73 - 73: OoooooooOO
   if 100 - 100: I11i / i1IIi / i1IIi % Ii1I - II111iiii . OoooooooOO
   if ( o0o00oOOOo0 == False ) :
    II1IiiI = oOo0O000oo0
    continue
    if 72 - 72: Oo0Ooo * OoooooooOO % I1IiiI + I11i - II111iiii
    if 82 - 82: iIii1I11I1II1 / i1IIi * I1IiiI . i11iIiiIii
   if ( IIIIiI1ii1 == "" ) : IIIIiI1ii1 = "no-port"
   if ( o0O00o == "command" and lisp_i_am_core == False ) :
    ii = oOo0O000oo0 . find ( " {" )
    O0oo00oOOoo0O = oOo0O000oo0 if ii == - 1 else oOo0O000oo0 [ : ii ]
    O0oo00oOOoo0O = ": '" + O0oo00oOOoo0O + "'"
   else :
    O0oo00oOOoo0O = ""
    if 70 - 70: OoO0O00 + i1IIi / iIii1I11I1II1 % i11iIiiIii . O0 . OOooOOo
    if 21 - 21: i1IIi
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( oOo0O000oo0 ) , bold ( "from " + i1Ii1I , False ) , IIIIiI1ii1 , o0O00o ,
 O0oo00oOOoo0O if ( o0O00o in [ "command" , "api" ] ) else ": ... " if ( o0O00o == "data-packet" ) else ": " + lisp_format_packet ( oOo0O000oo0 ) ) )
   if 10 - 10: i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo . o0oOOo0O0Ooo
   if 8 - 8: iII111i + iIii1I11I1II1 . I1ii11iIi11i
   if 68 - 68: OoooooooOO . OoooooooOO % I1ii11iIi11i + i1IIi % OoooooooOO + Ii1I
   if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
   if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
  if ( Oo000ooO ) : continue
  return ( [ o0O00o , i1Ii1I , IIIIiI1ii1 , oOo0O000oo0 ] )
  if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
  if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
  if 86 - 86: iII111i / i1IIi % Oo0Ooo
  if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
  if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
  if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
  if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
  if 92 - 92: OoO0O00 . i1IIi
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 i1Ii11III = False
 if 25 - 25: iII111i % iIii1I11I1II1 + IiII
 Ii1i111iI = lisp_control_header ( )
 if ( Ii1i111iI . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( i1Ii11III )
  if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
  if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
  if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
  if 37 - 37: Ii1I + o0oOOo0O0Ooo
  if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 iIi1i = source
 if ( source . find ( "lisp" ) == - 1 ) :
  i11I1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  i11I1 . string_to_afi ( source )
  i11I1 . store_address ( source )
  source = i11I1
  if 8 - 8: I11i - I11i % IiII
  if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 if ( Ii1i111iI . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 elif ( Ii1i111iI . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 elif ( Ii1i111iI . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 81 - 81: OOooOOo * oO0o
 elif ( Ii1i111iI . type == LISP_MAP_NOTIFY ) :
  if ( iIi1i == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 50 - 50: i1IIi
   if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
 elif ( Ii1i111iI . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 80 - 80: Ii1I + O0
 elif ( Ii1i111iI . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 59 - 59: i11iIiiIii - OoooooooOO % I11i . OoO0O00 - Oo0Ooo * o0oOOo0O0Ooo
 elif ( Ii1i111iI . type == LISP_NAT_INFO and Ii1i111iI . is_info_reply ( ) ) :
  o000000Oo , Ooo000O00o , i1Ii11III = lisp_process_info_reply ( source , packet , True )
  if 7 - 7: II111iiii % Ii1I * i11iIiiIii
 elif ( Ii1i111iI . type == LISP_NAT_INFO and Ii1i111iI . is_info_reply ( ) == False ) :
  O0o = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , O0o , udp_sport ,
 None )
  if 28 - 28: II111iiii / ooOoO0o * i11iIiiIii % OOooOOo
 elif ( Ii1i111iI . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 18 - 18: I11i - IiII - iIii1I11I1II1
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( Ii1i111iI . type ) )
  if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
 return ( i1Ii11III )
 if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
 if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
 if 32 - 32: OoO0O00
 if 22 - 22: II111iiii . I11i
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
 if 94 - 94: OOooOOo / IiII
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 Ii1Ii = bold ( "RLOC-probe" , False )
 if 22 - 22: OoOoOO00 - Oo0Ooo
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( Ii1Ii ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
  if 33 - 33: I11i + O0
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( Ii1Ii ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
  if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( Ii1Ii ) )
 return
 if 12 - 12: II111iiii + I11i
 if 9 - 9: I1ii11iIi11i
 if 51 - 51: I1ii11iIi11i
 if 37 - 37: I1IiiI % I1Ii111
 if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 98 - 98: I11i * O0 + IiII - oO0o
 if 35 - 35: OoooooooOO * Ii1I
 if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
 if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
 if 100 - 100: Oo0Ooo - I1IiiI . OOooOOo % iIii1I11I1II1 . I11i
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 83 - 83: OoOoOO00 * iII111i
 if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
 if 94 - 94: iII111i . Ii1I
 if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
 if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
 if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
 if 100 - 100: Oo0Ooo + IiII
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 oooo0O = lisp_map_reply ( )
 oooo0O . rloc_probe = rloc_probe
 oooo0O . echo_nonce_capable = enc
 oooo0O . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 oooo0O . record_count = 1
 oooo0O . nonce = nonce
 oOo0O000oo0 = oooo0O . encode ( )
 oooo0O . print_map_reply ( )
 if 100 - 100: iII111i / Oo0Ooo
 o00o = lisp_eid_record ( )
 o00o . rloc_count = len ( rloc_set )
 o00o . authoritative = auth
 o00o . record_ttl = ttl
 o00o . action = action
 o00o . eid = eid
 o00o . group = group
 if 2 - 2: ooOoO0o % Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1
 oOo0O000oo0 += o00o . encode ( )
 o00o . print_record ( "  " , False )
 if 15 - 15: Oo0Ooo % I11i . i1IIi
 Oo000O0O0oOo0 = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 13 - 13: OoO0O00 + Ii1I % iIii1I11I1II1 / Ii1I
 for oo0oo00000 in rloc_set :
  Iii1i1iii = lisp_rloc_record ( )
  O0o = oo0oo00000 . rloc . print_address_no_iid ( )
  if ( O0o in Oo000O0O0oOo0 ) :
   Iii1i1iii . local_bit = True
   Iii1i1iii . probe_bit = rloc_probe
   Iii1i1iii . keys = keys
   if ( oo0oo00000 . priority == 254 and lisp_i_am_rtr ) :
    Iii1i1iii . rloc_name = "RTR"
    if 77 - 77: o0oOOo0O0Ooo - i1IIi % Oo0Ooo / O0 % Oo0Ooo
    if 49 - 49: II111iiii * iIii1I11I1II1 / I11i - oO0o
  Iii1i1iii . store_rloc_entry ( oo0oo00000 )
  Iii1i1iii . reach_bit = True
  Iii1i1iii . print_record ( "    " )
  oOo0O000oo0 += Iii1i1iii . encode ( )
  if 76 - 76: I1Ii111 . Oo0Ooo - ooOoO0o . II111iiii - iII111i
 return ( oOo0O000oo0 )
 if 36 - 36: iIii1I11I1II1 % Oo0Ooo
 if 67 - 67: oO0o / II111iiii . I11i / oO0o
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 if 100 - 100: i11iIiiIii % oO0o
 if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
 if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
 if 73 - 73: i11iIiiIii
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 III1II1II1 = lisp_map_referral ( )
 III1II1II1 . record_count = 1
 III1II1II1 . nonce = nonce
 oOo0O000oo0 = III1II1II1 . encode ( )
 III1II1II1 . print_map_referral ( )
 if 83 - 83: i1IIi - Oo0Ooo - IiII - i11iIiiIii
 o00o = lisp_eid_record ( )
 if 53 - 53: OoOoOO00 . OoooooooOO
 ii1iI1iII1i = 0
 if ( ddt_entry == None ) :
  o00o . eid = eid
  o00o . group = group
 else :
  ii1iI1iII1i = len ( ddt_entry . delegation_set )
  o00o . eid = ddt_entry . eid
  o00o . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 21 - 21: I11i / OoO0O00 + Oo0Ooo - O0
 o00o . rloc_count = ii1iI1iII1i
 o00o . authoritative = True
 if 6 - 6: iIii1I11I1II1 . i11iIiiIii * iIii1I11I1II1
 if 81 - 81: OOooOOo / I11i / OoooooooOO
 if 74 - 74: I11i + OoooooooOO % II111iiii % o0oOOo0O0Ooo
 if 27 - 27: OoO0O00 * Oo0Ooo
 if 80 - 80: i11iIiiIii . OoO0O00 - I11i % I11i
 O0OOOo000 = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( ii1iI1iII1i == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   oooo0oOOooo0 = ddt_entry . delegation_set [ 0 ]
   if ( oooo0oOOooo0 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
   if ( oooo0oOOooo0 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 94 - 94: ooOoO0o
    if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
    if 95 - 95: II111iiii
    if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
    if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
    if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
    if 75 - 75: I1Ii111 - i1IIi - OoO0O00
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0OOOo000 = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0OOOo000 = ( lisp_i_am_ms and oooo0oOOooo0 . is_ms_peer ( ) == False )
  if 25 - 25: iII111i . o0oOOo0O0Ooo
  if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
 o00o . action = action
 o00o . ddt_incomplete = O0OOOo000
 o00o . record_ttl = ttl
 if 68 - 68: ooOoO0o % OoooooooOO
 oOo0O000oo0 += o00o . encode ( )
 o00o . print_record ( "  " , True )
 if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
 if ( ii1iI1iII1i == 0 ) : return ( oOo0O000oo0 )
 if 60 - 60: iII111i . OOooOOo
 for oooo0oOOooo0 in ddt_entry . delegation_set :
  Iii1i1iii = lisp_rloc_record ( )
  Iii1i1iii . rloc = oooo0oOOooo0 . delegate_address
  Iii1i1iii . priority = oooo0oOOooo0 . priority
  Iii1i1iii . weight = oooo0oOOooo0 . weight
  Iii1i1iii . mpriority = 255
  Iii1i1iii . mweight = 0
  Iii1i1iii . reach_bit = True
  oOo0O000oo0 += Iii1i1iii . encode ( )
  Iii1i1iii . print_record ( "    " )
  if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 return ( oOo0O000oo0 )
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
 if 99 - 99: OOooOOo - OOooOOo
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo . I11i
 if 67 - 67: iII111i
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 52 - 52: IiII . OoooooooOO
 if ( map_request . target_group . is_null ( ) ) :
  IIi1 = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  IIi1 = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( IIi1 ) : IIi1 = IIi1 . lookup_source_cache ( map_request . target_eid , False )
  if 4 - 4: Oo0Ooo / OoOoOO00
 o0o0O00 = map_request . print_prefix ( )
 if 97 - 97: Oo0Ooo
 if ( IIi1 == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( o0o0O00 , False ) ) )
  if 6 - 6: O0 - I1ii11iIi11i / OoooooooOO - Ii1I + Oo0Ooo
  return
  if 88 - 88: OOooOOo - I1ii11iIi11i % iII111i
  if 58 - 58: OoO0O00 . O0 - i11iIiiIii . I1IiiI
 Oo00 = IIi1 . print_eid_tuple ( )
 if 56 - 56: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * OoooooooOO + I1ii11iIi11i
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( Oo00 , False ) , green ( o0o0O00 , False ) ) )
 if 21 - 21: Ii1I
 if 28 - 28: i11iIiiIii * IiII * iII111i
 if 5 - 5: ooOoO0o
 if 22 - 22: I1Ii111 . o0oOOo0O0Ooo + OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
 if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
 iIi = map_request . itr_rlocs [ 0 ]
 if ( iIi . is_private_address ( ) and lisp_nat_traversal ) :
  iIi = source
  if 65 - 65: OOooOOo * OOooOOo . i1IIi - OOooOOo
  if 85 - 85: OoooooooOO / IiII + OoOoOO00 - iIii1I11I1II1 % OoooooooOO + iIii1I11I1II1
 OoI1 = map_request . nonce
 II1111111 = lisp_nonce_echoing
 iIIi111IiII1i = map_request . keys
 if 64 - 64: o0oOOo0O0Ooo + Oo0Ooo * O0 + iIii1I11I1II1
 IIi1 . map_replies_sent += 1
 if 5 - 5: o0oOOo0O0Ooo + OoO0O00
 oOo0O000oo0 = lisp_build_map_reply ( IIi1 . eid , IIi1 . group , IIi1 . rloc_set , OoI1 ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , iIIi111IiII1i , II1111111 , True , ttl )
 if 28 - 28: OOooOOo
 if 56 - 56: II111iiii
 if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
 if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
 if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
 if 15 - 15: oO0o . IiII + I1Ii111 - OoooooooOO
 if 85 - 85: II111iiii - Oo0Ooo + oO0o . i11iIiiIii + Oo0Ooo
 if 86 - 86: ooOoO0o . OoO0O00
 if 47 - 47: IiII % I1IiiI
 if 91 - 91: Ii1I
 if 69 - 69: iII111i
 if 96 - 96: Ii1I
 if 39 - 39: OoO0O00 - I1IiiI % II111iiii - IiII * I1ii11iIi11i
 if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
 if 7 - 7: ooOoO0o * I11i / iIii1I11I1II1
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  Iii = ( iIi . is_private_address ( ) == False )
  ooooOoOOO0 = iIi . print_address_no_iid ( )
  if ( ( Iii and lisp_rtr_list . has_key ( ooooOoOOO0 ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , iIi , None , oOo0O000oo0 )
   return
   if 15 - 15: OoooooooOO / iII111i
   if 40 - 40: o0oOOo0O0Ooo
   if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
   if 78 - 78: Oo0Ooo
   if 74 - 74: O0 / I11i
   if 52 - 52: I1IiiI + oO0o * II111iiii
 lisp_send_map_reply ( lisp_sockets , oOo0O000oo0 , iIi , sport )
 return
 if 15 - 15: I11i
 if 72 - 72: O0
 if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
 if 93 - 93: OOooOOo / OoooooooOO % iII111i
 if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
 if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
 if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
 if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
 if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
 if 74 - 74: OoooooooOO * ooOoO0o
 iIi = map_request . itr_rlocs [ 0 ]
 if ( iIi . is_private_address ( ) ) : iIi = source
 OoI1 = map_request . nonce
 if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
 O0oOoooooooOo00O = map_request . target_eid
 oooiiIiIIIi1 = map_request . target_group
 if 50 - 50: o0oOOo0O0Ooo % O0
 oo000OO = [ ]
 for iiiIi111i1i in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( iiiIi111i1i == None ) : continue
  IiiI11iiI1i1 = lisp_rloc ( )
  IiiI11iiI1i1 . rloc . copy_address ( iiiIi111i1i )
  IiiI11iiI1i1 . priority = 254
  oo000OO . append ( IiiI11iiI1i1 )
  if 64 - 64: iII111i
  if 9 - 9: I1ii11iIi11i + Oo0Ooo * I11i / I1Ii111 / I1ii11iIi11i / oO0o
 II1111111 = lisp_nonce_echoing
 iIIi111IiII1i = map_request . keys
 if 48 - 48: Oo0Ooo % i1IIi / I1ii11iIi11i / oO0o + iII111i
 oOo0O000oo0 = lisp_build_map_reply ( O0oOoooooooOo00O , oooiiIiIIIi1 , oo000OO , OoI1 , LISP_NO_ACTION ,
 1440 , True , iIIi111IiII1i , II1111111 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , oOo0O000oo0 , iIi , sport )
 return
 if 47 - 47: Ii1I
 if 75 - 75: II111iiii / OoOoOO00 - o0oOOo0O0Ooo % I1ii11iIi11i + OoO0O00
 if 7 - 7: iII111i - OoO0O00 + ooOoO0o * iII111i
 if 14 - 14: OoOoOO00 - OoOoOO00 / ooOoO0o
 if 22 - 22: I1Ii111
 if 59 - 59: I1Ii111
 if 22 - 22: OoooooooOO
 if 88 - 88: I1Ii111 - OoO0O00
 if 29 - 29: I1IiiI . I1Ii111
 if 74 - 74: Oo0Ooo / OoOoOO00 + OoOoOO00 % i11iIiiIii . OoO0O00 + ooOoO0o
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 oo000OO = target_site_eid . registered_rlocs
 if 77 - 77: ooOoO0o . I11i + OoooooooOO
 O00 = lisp_site_eid_lookup ( seid , group , False )
 if ( O00 == None ) : return ( oo000OO )
 if 65 - 65: I1ii11iIi11i
 if 93 - 93: IiII - OoOoOO00 - Ii1I % II111iiii . I1ii11iIi11i % OoooooooOO
 if 2 - 2: oO0o % ooOoO0o
 if 44 - 44: Ii1I
 oooOooo0oO0o0 = None
 oo0Oo0oo = [ ]
 for oo0oo00000 in oo000OO :
  if ( oo0oo00000 . is_rtr ( ) ) : continue
  if ( oo0oo00000 . rloc . is_private_address ( ) ) :
   ii1iI1iI = copy . deepcopy ( oo0oo00000 )
   oo0Oo0oo . append ( ii1iI1iI )
   continue
   if 63 - 63: OoO0O00 . I1IiiI + ooOoO0o + I1ii11iIi11i
  oooOooo0oO0o0 = oo0oo00000
  break
  if 63 - 63: OoooooooOO * OoOoOO00 - Ii1I
 if ( oooOooo0oO0o0 == None ) : return ( oo000OO )
 oooOooo0oO0o0 = oooOooo0oO0o0 . rloc . print_address_no_iid ( )
 if 93 - 93: OoooooooOO * OOooOOo
 if 34 - 34: OoOoOO00 + OoOoOO00 - Oo0Ooo
 if 21 - 21: i1IIi + O0 % I1ii11iIi11i / i1IIi - iII111i
 if 56 - 56: Ii1I - Ii1I / OoooooooOO * i11iIiiIii - iII111i % iIii1I11I1II1
 ooiiii1Iii1Ii1I = None
 for oo0oo00000 in O00 . registered_rlocs :
  if ( oo0oo00000 . is_rtr ( ) ) : continue
  if ( oo0oo00000 . rloc . is_private_address ( ) ) : continue
  ooiiii1Iii1Ii1I = oo0oo00000
  break
  if 40 - 40: iII111i + iII111i % i11iIiiIii % ooOoO0o * OOooOOo
 if ( ooiiii1Iii1Ii1I == None ) : return ( oo000OO )
 ooiiii1Iii1Ii1I = ooiiii1Iii1Ii1I . rloc . print_address_no_iid ( )
 if 58 - 58: ooOoO0o
 if 49 - 49: Oo0Ooo * I1ii11iIi11i - i1IIi + OoOoOO00
 if 98 - 98: i11iIiiIii + OoooooooOO / I1IiiI / OOooOOo
 if 6 - 6: I1ii11iIi11i + IiII * oO0o * OoOoOO00
 I1II = target_site_eid . site_id
 if ( I1II == 0 ) :
  if ( ooiiii1Iii1Ii1I == oooOooo0oO0o0 ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( oooOooo0oO0o0 ) )
   if 67 - 67: I1Ii111 + OoooooooOO + OoOoOO00 % iIii1I11I1II1 . I1IiiI
   return ( oo0Oo0oo )
   if 68 - 68: ooOoO0o
  return ( oo000OO )
  if 68 - 68: I11i % IiII
  if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
  if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
  if 28 - 28: i1IIi / iII111i + OOooOOo
  if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
  if 59 - 59: O0 + Oo0Ooo
  if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
 if ( I1II == O00 . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( I1II ) )
  return ( oo0Oo0oo )
  if 50 - 50: I11i . I11i % I1IiiI - i1IIi
 return ( oo000OO )
 if 63 - 63: OoO0O00 . iII111i
 if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
 if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
 if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
 if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
 if 30 - 30: OoO0O00 / ooOoO0o % ooOoO0o
 if 40 - 40: i1IIi . iIii1I11I1II1 * OoOoOO00
 if 83 - 83: iIii1I11I1II1 + Ii1I - Ii1I % II111iiii
 if 82 - 82: O0
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 i1II1i1 = [ ]
 oo000OO = [ ]
 if 48 - 48: OoooooooOO / iII111i / II111iiii + i1IIi
 if 33 - 33: I11i + I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
 if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 if 69 - 69: OoooooooOO
 if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
 if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 oooOooOoO = False
 oOooo0Oo0o = False
 for oo0oo00000 in registered_rloc_set :
  if ( oo0oo00000 . priority != 254 ) : continue
  oOooo0Oo0o |= True
  if ( oo0oo00000 . rloc . is_exact_match ( mr_source ) == False ) : continue
  oooOooOoO = True
  break
  if 29 - 29: IiII * OoOoOO00 - oO0o - IiII / I1ii11iIi11i
  if 82 - 82: Oo0Ooo - ooOoO0o
  if 25 - 25: I11i + oO0o / I1Ii111 % IiII * OOooOOo - I1Ii111
  if 100 - 100: ooOoO0o . i11iIiiIii * Oo0Ooo - i11iIiiIii
  if 72 - 72: oO0o + I11i . OoooooooOO
  if 84 - 84: oO0o * oO0o - i1IIi + ooOoO0o
  if 83 - 83: i1IIi
 if ( oOooo0Oo0o == False ) : return ( registered_rloc_set )
 if 85 - 85: i11iIiiIii / OoO0O00 / oO0o
 if 12 - 12: iII111i % OOooOOo % i1IIi
 if 17 - 17: IiII
 if 63 - 63: ooOoO0o . i11iIiiIii / iIii1I11I1II1
 if 8 - 8: i11iIiiIii . IiII * iIii1I11I1II1 * I1IiiI * Ii1I * i11iIiiIii
 if 24 - 24: I1IiiI * I11i - o0oOOo0O0Ooo / iII111i + IiII - I1ii11iIi11i
 if 53 - 53: I11i / I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * OoOoOO00
 if 86 - 86: iIii1I11I1II1 - I1Ii111
 if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
 if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
 O0oOO0O00 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 52 - 52: IiII % iII111i
 if 74 - 74: II111iiii . II111iiii + I1IiiI / OoO0O00
 if 86 - 86: Ii1I + Ii1I - Oo0Ooo * I1IiiI
 if 52 - 52: I11i - OoO0O00 - I1IiiI % OoOoOO00 % OoOoOO00 + Oo0Ooo
 if 88 - 88: iIii1I11I1II1 * OoO0O00 / IiII
 for oo0oo00000 in registered_rloc_set :
  if ( O0oOO0O00 and oo0oo00000 . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and oo0oo00000 . priority == 255 ) : continue
  if ( multicast and oo0oo00000 . mpriority == 255 ) : continue
  if ( oo0oo00000 . priority == 254 ) :
   i1II1i1 . append ( oo0oo00000 )
  else :
   oo000OO . append ( oo0oo00000 )
   if 74 - 74: I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
   if 55 - 55: OoO0O00 % IiII
   if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
   if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
   if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
   if 63 - 63: I1Ii111 + iII111i
 if ( oooOooOoO ) : return ( oo000OO )
 if 6 - 6: I1ii11iIi11i + Ii1I
 if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
 if 97 - 97: ooOoO0o + OOooOOo
 if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
 if 6 - 6: Oo0Ooo + I1IiiI
 if 48 - 48: oO0o . I1ii11iIi11i
 if 59 - 59: IiII - Ii1I
 if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
 if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
 if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
 oo000OO = [ ]
 for oo0oo00000 in registered_rloc_set :
  if ( oo0oo00000 . rloc . is_private_address ( ) ) : oo000OO . append ( oo0oo00000 )
  if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
 oo000OO += i1II1i1
 return ( oo000OO )
 if 53 - 53: o0oOOo0O0Ooo * Ii1I
 if 42 - 42: I11i + iII111i / iIii1I11I1II1
 if 1 - 1: O0 - II111iiii
 if 75 - 75: II111iiii / OoO0O00 % II111iiii
 if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
 if 44 - 44: OOooOOo - o0oOOo0O0Ooo
 if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
 if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
 if 62 - 62: OoooooooOO
 if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 O0oIII = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 O0oIII . add ( reply_eid )
 return
 if 98 - 98: I1ii11iIi11i / I1Ii111 . i1IIi / OoOoOO00
 if 56 - 56: OOooOOo * O0
 if 52 - 52: IiII / I1IiiI - o0oOOo0O0Ooo
 if 6 - 6: I1ii11iIi11i / OOooOOo
 if 92 - 92: OOooOOo % OOooOOo
 if 67 - 67: iII111i + I1ii11iIi11i - IiII . iII111i + iIii1I11I1II1
 if 40 - 40: II111iiii - oO0o / OoO0O00 / OoOoOO00 / Oo0Ooo
 if 11 - 11: IiII + OoooooooOO % OoooooooOO . o0oOOo0O0Ooo * OoOoOO00 + O0
 if 37 - 37: I1IiiI
 if 64 - 64: ooOoO0o
 if 35 - 35: I1IiiI . iIii1I11I1II1 + IiII / i11iIiiIii - II111iiii . OoooooooOO
 if 19 - 19: IiII - OoOoOO00
 if 43 - 43: IiII / OOooOOo % II111iiii . o0oOOo0O0Ooo / i11iIiiIii
 if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
 if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
def lisp_convert_reply_to_notify ( packet ) :
 if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
 if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
 if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
 if 16 - 16: iIii1I11I1II1 . II111iiii
 oO0oooO = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 oO0oooO = socket . ntohl ( oO0oooO ) & 0xff
 OoI1 = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 36 - 36: iIii1I11I1II1 + I1IiiI + OoOoOO00 . iIii1I11I1II1
 if 6 - 6: OoOoOO00 - O0
 if 46 - 46: IiII . Oo0Ooo
 if 75 - 75: OoO0O00 % OoO0O00 + OoOoOO00 . O0 . OOooOOo / O0
 i11iI1 = ( LISP_MAP_NOTIFY << 28 ) | oO0oooO
 Ii1i111iI = struct . pack ( "I" , socket . htonl ( i11iI1 ) )
 oooooO0O0o = struct . pack ( "I" , 0 )
 if 39 - 39: iII111i - Oo0Ooo * I1ii11iIi11i % OOooOOo / oO0o / Oo0Ooo
 if 53 - 53: ooOoO0o % OoO0O00 * O0 + II111iiii + iIii1I11I1II1
 if 11 - 11: II111iiii . II111iiii + Ii1I % oO0o
 if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 packet = Ii1i111iI + OoI1 + oooooO0O0o + packet
 return ( packet )
 if 78 - 78: oO0o
 if 20 - 20: i1IIi + i1IIi * i1IIi
 if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
 if 27 - 27: oO0o + Ii1I . i11iIiiIii
 if 97 - 97: iII111i . I1IiiI
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
 if 45 - 45: oO0o
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 o0o0O00 = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( o0o0O00 ) == False ) : return
 if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
 for O0oIII in lisp_pubsub_cache [ o0o0O00 ] . values ( ) :
  I11I = O0oIII . itr
  IIIIiI1ii1 = O0oIII . port
  ii1iI1IIiI1 = red ( I11I . print_address_no_iid ( ) , False )
  o0O000 = bold ( "subscriber" , False )
  OOOo00OOooO = "0x" + lisp_hex_string ( O0oIII . xtr_id )
  OoI1 = "0x" + lisp_hex_string ( O0oIII . nonce )
  if 98 - 98: iII111i / OOooOOo + IiII
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( o0O000 , ii1iI1IIiI1 , IIIIiI1ii1 , OOOo00OOooO , green ( o0o0O00 , False ) , OoI1 ) )
  if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
  if 82 - 82: ooOoO0o % OOooOOo % Ii1I
  lisp_build_map_notify ( lisp_sockets , eid_record , [ o0o0O00 ] , 1 , I11I ,
 IIIIiI1ii1 , O0oIII . nonce , 0 , 0 , 0 , site , False )
  O0oIII . map_notify_count += 1
  if 82 - 82: I1ii11iIi11i
 return
 if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
 if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
 if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 73 - 73: Oo0Ooo + iIii1I11I1II1 . iIii1I11I1II1
 if 73 - 73: ooOoO0o + OoOoOO00
 if 61 - 61: I1Ii111 * I1Ii111 % OOooOOo
 if 31 - 31: oO0o + Ii1I - iIii1I11I1II1 / i11iIiiIii
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 9 - 9: IiII % OoO0O00
 O0oOoooooooOo00O = green ( reply_eid . print_prefix ( ) , False )
 I11I = red ( itr_rloc . print_address_no_iid ( ) , False )
 oooOOoO0oo0 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( oooOOoO0oo0 ,
 O0oOoooooooOo00O , I11I , xtr_id ) )
 if 48 - 48: Oo0Ooo / iIii1I11I1II1
 if 80 - 80: i1IIi + I1IiiI / OoooooooOO + OOooOOo . Ii1I
 if 96 - 96: iIii1I11I1II1 - I1ii11iIi11i
 if 41 - 41: II111iiii - OoOoOO00 + OoooooooOO - I1ii11iIi11i . oO0o . o0oOOo0O0Ooo
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 34 - 34: I1ii11iIi11i % I11i / Oo0Ooo * oO0o % ooOoO0o / OOooOOo
 if 50 - 50: O0 * O0 / iIii1I11I1II1
 if 31 - 31: I1IiiI / o0oOOo0O0Ooo
 if 70 - 70: I1IiiI
 if 36 - 36: ooOoO0o . oO0o . I11i - I1ii11iIi11i / OoOoOO00 * Oo0Ooo
 if 42 - 42: OoooooooOO / o0oOOo0O0Ooo . Ii1I * iII111i * I1IiiI - Oo0Ooo
 if 76 - 76: oO0o * II111iiii
 if 81 - 81: I11i
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 2 - 2: OoOoOO00
 if 75 - 75: I1IiiI - OoooooooOO * I1Ii111
 if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
 if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
 if 11 - 11: IiII + II111iiii
 if 37 - 37: O0
 O0oOoooooooOo00O = map_request . target_eid
 oooiiIiIIIi1 = map_request . target_group
 o0o0O00 = lisp_print_eid_tuple ( O0oOoooooooOo00O , oooiiIiIIIi1 )
 iIi = map_request . itr_rlocs [ 0 ]
 OOOo00OOooO = map_request . xtr_id
 OoI1 = map_request . nonce
 Ooo0O = LISP_NO_ACTION
 O0oIII = map_request . subscribe_bit
 if 98 - 98: IiII * OoooooooOO . iII111i
 if 34 - 34: OoooooooOO + I1Ii111
 if 97 - 97: II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
 if 9 - 9: i1IIi - I1Ii111 + I1Ii111
 if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
 OooIi1 = True
 IIIiIII = ( lisp_get_eid_hash ( O0oOoooooooOo00O ) != None )
 if ( IIIiIII ) :
  ooOo = map_request . map_request_signature
  if ( ooOo == None ) :
   OooIi1 = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 9 - 9: II111iiii * OOooOOo / Oo0Ooo + iIii1I11I1II1 % I1IiiI
  else :
   Oo000O00o0O = map_request . signature_eid
   O0OOO00OO0 , Ii11IiiI1 , OooIi1 = lisp_lookup_public_key ( Oo000O00o0O )
   if ( OooIi1 ) :
    OooIi1 = map_request . verify_map_request_sig ( Ii11IiiI1 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Oo000O00o0O . print_address ( ) , O0OOO00OO0 . print_address ( ) ) )
    if 28 - 28: iIii1I11I1II1
    if 1 - 1: iII111i
   OOoo0O = bold ( "passed" , False ) if OooIi1 else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( OOoo0O ) )
   if 16 - 16: iII111i % OoOoOO00 . OoooooooOO * o0oOOo0O0Ooo - I1IiiI / oO0o
   if 51 - 51: Oo0Ooo + O0 / OoOoOO00 - I1ii11iIi11i * Oo0Ooo / IiII
   if 33 - 33: OoO0O00 . OOooOOo * ooOoO0o - ooOoO0o
 if ( O0oIII and OooIi1 == False ) :
  O0oIII = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 20 - 20: iIii1I11I1II1
  if 66 - 66: O0 . iIii1I11I1II1 / OoO0O00 . Ii1I * i1IIi * OoooooooOO
  if 26 - 26: iIii1I11I1II1 . IiII * Oo0Ooo * OoOoOO00 * O0
  if 25 - 25: iIii1I11I1II1 . iII111i / II111iiii % OoO0O00 / Ii1I
  if 82 - 82: Ii1I . I11i - OOooOOo
  if 64 - 64: o0oOOo0O0Ooo - I1Ii111 - Oo0Ooo + OoOoOO00
  if 6 - 6: IiII * iIii1I11I1II1 + OOooOOo . OoooooooOO
  if 30 - 30: iII111i . IiII % O0 + iII111i % Ii1I
  if 72 - 72: II111iiii * ooOoO0o + I1IiiI
  if 19 - 19: OoO0O00 * ooOoO0o % I1ii11iIi11i
  if 21 - 21: OoO0O00 * I11i
  if 76 - 76: I1IiiI - I1ii11iIi11i / I1ii11iIi11i . o0oOOo0O0Ooo % OoooooooOO
  if 39 - 39: OoooooooOO % iII111i
  if 55 - 55: IiII . i11iIiiIii % OoooooooOO
 o0oOOOooOOoo = iIi if ( iIi . afi == ecm_source . afi ) else ecm_source
 if 20 - 20: I11i % I1IiiI
 OoOoO00OOO0O0 = lisp_site_eid_lookup ( O0oOoooooooOo00O , oooiiIiIIIi1 , False )
 if 46 - 46: OoO0O00 % i1IIi % iII111i * I1Ii111
 if ( OoOoO00OOO0O0 == None or OoOoO00OOO0O0 . is_star_g ( ) ) :
  II1ii1IIi1i = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( II1ii1IIi1i ,
 green ( o0o0O00 , False ) ) )
  if 4 - 4: II111iiii . I1ii11iIi11i
  if 21 - 21: I11i . O0 * OoOoOO00 - OOooOOo + ooOoO0o
  if 81 - 81: Oo0Ooo + I1Ii111 - I1IiiI
  if 4 - 4: i1IIi
  lisp_send_negative_map_reply ( lisp_sockets , O0oOoooooooOo00O , oooiiIiIIIi1 , OoI1 , iIi ,
 mr_sport , 15 , OOOo00OOooO , O0oIII )
  if 89 - 89: II111iiii . I11i + Ii1I * ooOoO0o + I11i . IiII
  return ( [ O0oOoooooooOo00O , oooiiIiIIIi1 , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 83 - 83: o0oOOo0O0Ooo - iIii1I11I1II1
  if 9 - 9: Ii1I
 Oo00 = OoOoO00OOO0O0 . print_eid_tuple ( )
 O0O0000oo0 = OoOoO00OOO0O0 . site . site_name
 if 8 - 8: I11i
 if 95 - 95: OoOoOO00 % O0 % I1IiiI
 if 85 - 85: iIii1I11I1II1 * i11iIiiIii
 if 54 - 54: O0 * Ii1I + Ii1I
 if 59 - 59: i11iIiiIii % iII111i
 if ( IIIiIII == False and OoOoO00OOO0O0 . require_signature ) :
  ooOo = map_request . map_request_signature
  Oo000O00o0O = map_request . signature_eid
  if ( ooOo == None or Oo000O00o0O . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( O0O0000oo0 ) )
   OooIi1 = False
  else :
   Oo000O00o0O = map_request . signature_eid
   O0OOO00OO0 , Ii11IiiI1 , OooIi1 = lisp_lookup_public_key ( Oo000O00o0O )
   if ( OooIi1 ) :
    OooIi1 = map_request . verify_map_request_sig ( Ii11IiiI1 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Oo000O00o0O . print_address ( ) , O0OOO00OO0 . print_address ( ) ) )
    if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
    if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
   OOoo0O = bold ( "passed" , False ) if OooIi1 else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( OOoo0O ) )
   if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
   if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
   if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
   if 14 - 14: ooOoO0o % iIii1I11I1II1 % ooOoO0o / IiII + OOooOOo
   if 14 - 14: Oo0Ooo
   if 79 - 79: I1ii11iIi11i % I1Ii111 % I11i - iII111i * OoOoOO00
 if ( OooIi1 and OoOoO00OOO0O0 . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( O0O0000oo0 , green ( Oo00 , False ) , green ( o0o0O00 , False ) ) )
  if 48 - 48: O0 + OoOoOO00 - O0
  if 79 - 79: ooOoO0o . OoOoOO00 / OoooooooOO - II111iiii
  if 48 - 48: Oo0Ooo
  if 59 - 59: OoO0O00 % o0oOOo0O0Ooo
  if 83 - 83: iII111i % iIii1I11I1II1 / OOooOOo - OoOoOO00
  if 98 - 98: I11i % oO0o . I1IiiI % OoOoOO00
  if ( OoOoO00OOO0O0 . accept_more_specifics == False ) :
   O0oOoooooooOo00O = OoOoO00OOO0O0 . eid
   oooiiIiIIIi1 = OoOoO00OOO0O0 . group
   if 32 - 32: I1ii11iIi11i / Ii1I
   if 54 - 54: I11i - i11iIiiIii
   if 91 - 91: Ii1I - OoO0O00 - I1IiiI % OoO0O00 . o0oOOo0O0Ooo
   if 85 - 85: ooOoO0o . ooOoO0o % Oo0Ooo . OOooOOo + OOooOOo / I1IiiI
   if 69 - 69: i1IIi + II111iiii / Ii1I
  OoI1iI = 1
  if ( OoOoO00OOO0O0 . force_ttl != None ) :
   OoI1iI = OoOoO00OOO0O0 . force_ttl | 0x80000000
   if 4 - 4: I11i * OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - I1ii11iIi11i
   if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 * I11i * OoOoOO00
   if 14 - 14: i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
   if 18 - 18: Oo0Ooo % OOooOOo + IiII
   if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
  lisp_send_negative_map_reply ( lisp_sockets , O0oOoooooooOo00O , oooiiIiIIIi1 , OoI1 , iIi ,
 mr_sport , OoI1iI , OOOo00OOooO , O0oIII )
  if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
  return ( [ O0oOoooooooOo00O , oooiiIiIIIi1 , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 47 - 47: II111iiii
  if 30 - 30: i1IIi . Oo0Ooo / o0oOOo0O0Ooo + IiII * OOooOOo
  if 26 - 26: Ii1I % O0 - i1IIi % iII111i * OoO0O00
  if 60 - 60: I1ii11iIi11i * iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
  if 94 - 94: OoO0O00 . ooOoO0o
 i111i1iIi1i = False
 ii1i11Ii111 = ""
 iIiIIi11 = False
 if ( OoOoO00OOO0O0 . force_nat_proxy_reply ) :
  ii1i11Ii111 = ", nat-forced"
  i111i1iIi1i = True
  iIiIIi11 = True
 elif ( OoOoO00OOO0O0 . force_proxy_reply ) :
  ii1i11Ii111 = ", forced"
  iIiIIi11 = True
 elif ( OoOoO00OOO0O0 . proxy_reply_requested ) :
  ii1i11Ii111 = ", requested"
  iIiIIi11 = True
 elif ( map_request . pitr_bit and OoOoO00OOO0O0 . pitr_proxy_reply_drop ) :
  ii1i11Ii111 = ", drop-to-pitr"
  Ooo0O = LISP_DROP_ACTION
 elif ( OoOoO00OOO0O0 . proxy_reply_action != "" ) :
  Ooo0O = OoOoO00OOO0O0 . proxy_reply_action
  ii1i11Ii111 = ", forced, action {}" . format ( Ooo0O )
  Ooo0O = LISP_DROP_ACTION if ( Ooo0O == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 65 - 65: i11iIiiIii
  if 11 - 11: i1IIi - Oo0Ooo % O0 . II111iiii % oO0o
  if 43 - 43: I1Ii111 - Oo0Ooo % II111iiii / Ii1I . iII111i . iIii1I11I1II1
  if 69 - 69: I11i - I11i / I11i + IiII - I1IiiI
  if 21 - 21: I1IiiI * OoO0O00 * oO0o . o0oOOo0O0Ooo + II111iiii
  if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
  if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
 I11I111Ii1II = False
 IiIiI1ii = None
 if ( iIiIIi11 and lisp_policies . has_key ( OoOoO00OOO0O0 . policy ) ) :
  Ii1Ii = lisp_policies [ OoOoO00OOO0O0 . policy ]
  if ( Ii1Ii . match_policy_map_request ( map_request , mr_source ) ) : IiIiI1ii = Ii1Ii
  if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
  if ( IiIiI1ii ) :
   I1111i = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( I1111i ,
 Ii1Ii . policy_name , Ii1Ii . set_action ) )
  else :
   I1111i = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( I1111i ,
 Ii1Ii . policy_name ) )
   I11I111Ii1II = True
   if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
   if 85 - 85: OoooooooOO
   if 37 - 37: OoooooooOO + O0 + I1ii11iIi11i + IiII * iII111i
 if ( ii1i11Ii111 != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( o0o0O00 , False ) , O0O0000oo0 , green ( Oo00 , False ) ,
  # oO0o
 ii1i11Ii111 ) )
  if 26 - 26: I1ii11iIi11i
  oo000OO = OoOoO00OOO0O0 . registered_rlocs
  OoI1iI = 1440
  if ( i111i1iIi1i ) :
   if ( OoOoO00OOO0O0 . site_id != 0 ) :
    i1iIi11iII = map_request . source_eid
    oo000OO = lisp_get_private_rloc_set ( OoOoO00OOO0O0 , i1iIi11iII , oooiiIiIIIi1 )
    if 24 - 24: I1ii11iIi11i % oO0o / o0oOOo0O0Ooo - I1Ii111 * OoOoOO00
   if ( oo000OO == OoOoO00OOO0O0 . registered_rlocs ) :
    oO0O0O0O0O0OO = ( OoOoO00OOO0O0 . group . is_null ( ) == False )
    oo0Oo0oo = lisp_get_partial_rloc_set ( oo000OO , o0oOOOooOOoo , oO0O0O0O0O0OO )
    if ( oo0Oo0oo != oo000OO ) :
     OoI1iI = 15
     oo000OO = oo0Oo0oo
     if 85 - 85: OoooooooOO * I11i % IiII + IiII % iII111i
     if 44 - 44: i1IIi
     if 86 - 86: i11iIiiIii / ooOoO0o / OOooOOo + Oo0Ooo . I1Ii111 + II111iiii
     if 4 - 4: II111iiii * I1IiiI * O0 + I1ii11iIi11i
     if 24 - 24: iIii1I11I1II1
     if 2 - 2: iIii1I11I1II1
     if 87 - 87: I11i
     if 17 - 17: OOooOOo - Oo0Ooo + Ii1I
  if ( OoOoO00OOO0O0 . force_ttl != None ) :
   OoI1iI = OoOoO00OOO0O0 . force_ttl | 0x80000000
   if 94 - 94: OoO0O00 * OoO0O00 * II111iiii + i1IIi / i1IIi % Ii1I
   if 82 - 82: I11i + OoO0O00 . oO0o * I1ii11iIi11i % ooOoO0o . iIii1I11I1II1
   if 2 - 2: Ii1I + OoooooooOO . oO0o
   if 26 - 26: ooOoO0o - Ii1I - I1Ii111 * IiII + I1Ii111 . OoOoOO00
   if 12 - 12: OoooooooOO
   if 57 - 57: OoOoOO00 . iII111i . O0 * oO0o
  if ( IiIiI1ii ) :
   if ( IiIiI1ii . set_record_ttl ) :
    OoI1iI = IiIiI1ii . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( OoI1iI ) )
    if 85 - 85: I1Ii111 * iIii1I11I1II1 . OoOoOO00
   if ( IiIiI1ii . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    Ooo0O = LISP_POLICY_DENIED_ACTION
    oo000OO = [ ]
   else :
    IiiI11iiI1i1 = IiIiI1ii . set_policy_map_reply ( )
    if ( IiiI11iiI1i1 ) : oo000OO = [ IiiI11iiI1i1 ]
    if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
    if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
    if 48 - 48: iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
  if ( I11I111Ii1II ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   Ooo0O = LISP_POLICY_DENIED_ACTION
   oo000OO = [ ]
   if 24 - 24: I1IiiI
   if 63 - 63: I11i - iIii1I11I1II1 * Ii1I + OoooooooOO . i11iIiiIii
  II1111111 = OoOoO00OOO0O0 . echo_nonce_capable
  if 94 - 94: OoO0O00 . oO0o . OoOoOO00 * i11iIiiIii
  if 96 - 96: i1IIi . OoO0O00 . OoO0O00 - o0oOOo0O0Ooo - Ii1I
  if 33 - 33: ooOoO0o + I1ii11iIi11i - I1IiiI . iII111i / OoO0O00
  if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
  if ( OooIi1 ) :
   I1i = OoOoO00OOO0O0 . eid
   II1iIIi1i = OoOoO00OOO0O0 . group
  else :
   I1i = O0oOoooooooOo00O
   II1iIIi1i = oooiiIiIIIi1
   Ooo0O = LISP_AUTH_FAILURE_ACTION
   oo000OO = [ ]
   if 20 - 20: IiII * I1Ii111
   if 11 - 11: I11i * OoO0O00 * OoO0O00 * I1ii11iIi11i * IiII
   if 42 - 42: I1Ii111 * I1Ii111 * OoO0O00 - oO0o
   if 96 - 96: Oo0Ooo
   if 82 - 82: ooOoO0o - O0 / OoO0O00
   if 24 - 24: IiII - OoOoOO00 / OoooooooOO . I1ii11iIi11i
  packet = lisp_build_map_reply ( I1i , II1iIIi1i , oo000OO ,
 OoI1 , Ooo0O , OoI1iI , False , None , II1111111 , False )
  if 88 - 88: I11i
  if ( O0oIII ) :
   lisp_process_pubsub ( lisp_sockets , packet , I1i , iIi ,
 mr_sport , OoI1 , OoI1iI , OOOo00OOooO )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , iIi , mr_sport )
   if 36 - 36: iIii1I11I1II1 - ooOoO0o * OoO0O00 * OoO0O00 . II111iiii
   if 49 - 49: O0 + OoO0O00 - I1ii11iIi11i + ooOoO0o
  return ( [ OoOoO00OOO0O0 . eid , OoOoO00OOO0O0 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 90 - 90: O0 . Ii1I * OOooOOo * OoooooooOO * ooOoO0o * Ii1I
  if 12 - 12: ooOoO0o * OoooooooOO * i1IIi
  if 3 - 3: o0oOOo0O0Ooo + Ii1I - i1IIi . OoooooooOO % Ii1I
  if 39 - 39: o0oOOo0O0Ooo
  if 73 - 73: IiII
 ii1iI1iII1i = len ( OoOoO00OOO0O0 . registered_rlocs )
 if ( ii1iI1iII1i == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( o0o0O00 , False ) , O0O0000oo0 ,
  # i1IIi % i11iIiiIii - i11iIiiIii * II111iiii * ooOoO0o % iII111i
 green ( Oo00 , False ) ) )
  return ( [ OoOoO00OOO0O0 . eid , OoOoO00OOO0O0 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 41 - 41: o0oOOo0O0Ooo . I1Ii111 + IiII / oO0o
  if 86 - 86: iII111i % OoOoOO00 . i11iIiiIii . I1Ii111 + II111iiii . i1IIi
  if 88 - 88: O0
  if 28 - 28: OOooOOo % IiII * Oo0Ooo / OoO0O00
  if 67 - 67: Oo0Ooo * I11i - IiII + I1Ii111
 O00oOOOOoOO = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 7 - 7: IiII - oO0o
 IiiiII = map_request . target_eid . hash_address ( O00oOOOOoOO )
 IiiiII %= ii1iI1iII1i
 IIiiiIiii = OoOoO00OOO0O0 . registered_rlocs [ IiiiII ]
 if 22 - 22: o0oOOo0O0Ooo * I1Ii111 * I1ii11iIi11i . OoOoOO00 . i1IIi % ooOoO0o
 if ( IIiiiIiii . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( o0o0O00 , False ) ,
  # I11i . II111iiii * OoO0O00 % I1Ii111
 O0O0000oo0 , green ( Oo00 , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( o0o0O00 , False ) ,
  # iII111i + I11i / OoOoOO00
 red ( IIiiiIiii . rloc . print_address ( ) , False ) , O0O0000oo0 ,
 green ( Oo00 , False ) ) )
  if 70 - 70: OoO0O00 / i1IIi - O0
  if 10 - 10: Oo0Ooo % OoOoOO00 - OOooOOo % iII111i + I1Ii111
  if 82 - 82: IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
  if 65 - 65: IiII / O0 * II111iiii + oO0o
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , IIiiiIiii . rloc , to_etr = True )
  if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
 return ( [ OoOoO00OOO0O0 . eid , OoOoO00OOO0O0 . group , LISP_DDT_ACTION_MS_ACK ] )
 if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
 if 79 - 79: iII111i . iIii1I11I1II1
 if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
 if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
 if 29 - 29: Oo0Ooo
 if 35 - 35: OoOoOO00 + II111iiii
 if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
 if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
 if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
 if 81 - 81: iIii1I11I1II1 - Oo0Ooo - ooOoO0o . OoO0O00 + I1ii11iIi11i
 O0oOoooooooOo00O = map_request . target_eid
 oooiiIiIIIi1 = map_request . target_group
 o0o0O00 = lisp_print_eid_tuple ( O0oOoooooooOo00O , oooiiIiIIIi1 )
 OoI1 = map_request . nonce
 Ooo0O = LISP_DDT_ACTION_NULL
 if 84 - 84: iII111i . OOooOOo . iII111i * oO0o % Ii1I . oO0o
 if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
 if 64 - 64: IiII - Oo0Ooo % iII111i % I11i
 if 42 - 42: Oo0Ooo . OoO0O00
 if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
 iIi1O00o0 = None
 if ( lisp_i_am_ms ) :
  OoOoO00OOO0O0 = lisp_site_eid_lookup ( O0oOoooooooOo00O , oooiiIiIIIi1 , False )
  if ( OoOoO00OOO0O0 == None ) : return
  if 53 - 53: i11iIiiIii * II111iiii
  if ( OoOoO00OOO0O0 . registered ) :
   Ooo0O = LISP_DDT_ACTION_MS_ACK
   OoI1iI = 1440
  else :
   O0oOoooooooOo00O , oooiiIiIIIi1 , Ooo0O = lisp_ms_compute_neg_prefix ( O0oOoooooooOo00O , oooiiIiIIIi1 )
   Ooo0O = LISP_DDT_ACTION_MS_NOT_REG
   OoI1iI = 1
   if 2 - 2: I11i - OoooooooOO / I1ii11iIi11i . I1ii11iIi11i * i11iIiiIii % II111iiii
 else :
  iIi1O00o0 = lisp_ddt_cache_lookup ( O0oOoooooooOo00O , oooiiIiIIIi1 , False )
  if ( iIi1O00o0 == None ) :
   Ooo0O = LISP_DDT_ACTION_NOT_AUTH
   OoI1iI = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( o0o0O00 , False ) ) )
   if 1 - 1: i11iIiiIii / OoOoOO00 - I1ii11iIi11i . I1IiiI / I1Ii111 % iIii1I11I1II1
  elif ( iIi1O00o0 . is_auth_prefix ( ) ) :
   if 87 - 87: OoOoOO00 - II111iiii + Oo0Ooo
   if 44 - 44: i1IIi + I1ii11iIi11i / iIii1I11I1II1
   if 47 - 47: I1Ii111
   if 41 - 41: IiII
   Ooo0O = LISP_DDT_ACTION_DELEGATION_HOLE
   OoI1iI = 15
   i1iiIiiiiIi = iIi1O00o0 . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( i1iiIiiiiIi ,
   # oO0o * I1ii11iIi11i
 green ( o0o0O00 , False ) ) )
   if 44 - 44: o0oOOo0O0Ooo * IiII - o0oOOo0O0Ooo
   if ( oooiiIiIIIi1 . is_null ( ) ) :
    O0oOoooooooOo00O = lisp_ddt_compute_neg_prefix ( O0oOoooooooOo00O , iIi1O00o0 ,
 lisp_ddt_cache )
   else :
    oooiiIiIIIi1 = lisp_ddt_compute_neg_prefix ( oooiiIiIIIi1 , iIi1O00o0 ,
 lisp_ddt_cache )
    O0oOoooooooOo00O = lisp_ddt_compute_neg_prefix ( O0oOoooooooOo00O , iIi1O00o0 ,
 iIi1O00o0 . source_cache )
    if 90 - 90: i1IIi + I1ii11iIi11i * oO0o % i11iIiiIii - OoO0O00
   iIi1O00o0 = None
  else :
   i1iiIiiiiIi = iIi1O00o0 . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( i1iiIiiiiIi , green ( o0o0O00 , False ) ) )
   if 12 - 12: OoO0O00 . I1ii11iIi11i - I1IiiI % OOooOOo
   OoI1iI = 1440
   if 9 - 9: Ii1I / O0
   if 95 - 95: iII111i / I11i
   if 86 - 86: O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
   if 22 - 22: Ii1I
   if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
   if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
 oOo0O000oo0 = lisp_build_map_referral ( O0oOoooooooOo00O , oooiiIiIIIi1 , iIi1O00o0 , Ooo0O , OoI1iI , OoI1 )
 OoI1 = map_request . nonce >> 32
 if ( map_request . nonce != 0 and OoI1 != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , oOo0O000oo0 , ecm_source , port )
 return
 if 32 - 32: oO0o . I1Ii111 * I1Ii111
 if 32 - 32: I1Ii111 . Ii1I / i1IIi
 if 2 - 2: OOooOOo * ooOoO0o / I11i + OoO0O00
 if 96 - 96: II111iiii * OoO0O00 + I1ii11iIi11i + OoOoOO00 / II111iiii . iII111i
 if 64 - 64: iII111i % Oo0Ooo
 if 79 - 79: IiII + iII111i / II111iiii . i1IIi + iIii1I11I1II1
 if 32 - 32: Ii1I * iII111i
 if 52 - 52: I11i
 if 100 - 100: Oo0Ooo % Oo0Ooo % I1ii11iIi11i
 if 33 - 33: I1Ii111 . I1Ii111 * i1IIi
 if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
 if 13 - 13: II111iiii
 if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 Iiooo0O0o0o = eid . hash_address ( entry_prefix )
 Ii111I = eid . addr_length ( ) * 8
 oo0Ooo = 0
 if 90 - 90: iII111i . OOooOOo % OoooooooOO % O0
 if 55 - 55: ooOoO0o / OoOoOO00 / oO0o + O0
 if 98 - 98: Oo0Ooo / Oo0Ooo * I1ii11iIi11i / OoO0O00
 if 69 - 69: ooOoO0o
 for oo0Ooo in range ( Ii111I ) :
  oo0O0O = 1 << ( Ii111I - oo0Ooo - 1 )
  if ( Iiooo0O0o0o & oo0O0O ) : break
  if 34 - 34: OoO0O00 % I1ii11iIi11i
  if 80 - 80: IiII - I1Ii111 / iIii1I11I1II1
 if ( oo0Ooo > neg_prefix . mask_len ) : neg_prefix . mask_len = oo0Ooo
 return
 if 45 - 45: oO0o + iII111i / o0oOOo0O0Ooo + I11i % OoOoOO00
 if 6 - 6: OoooooooOO + i1IIi % IiII - OoO0O00 * iIii1I11I1II1
 if 36 - 36: I11i / o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo + Ii1I - I11i
 if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
 if 91 - 91: OoO0O00 - OoO0O00 % O0
 if 67 - 67: ooOoO0o * i1IIi
 if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
 if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
 if 94 - 94: Oo0Ooo
 if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
def lisp_neg_prefix_walk ( entry , parms ) :
 O0oOoooooooOo00O , OooOoOooOO , IIi1IIII1ii = parms
 if 11 - 11: I11i * Oo0Ooo * ooOoO0o + i1IIi
 if ( OooOoOooOO == None ) :
  if ( entry . eid . instance_id != O0oOoooooooOo00O . instance_id ) :
   return ( [ True , parms ] )
   if 76 - 76: o0oOOo0O0Ooo * i1IIi / I1Ii111 * Oo0Ooo + II111iiii . OoOoOO00
  if ( entry . eid . afi != O0oOoooooooOo00O . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( OooOoOooOO ) == False ) :
   return ( [ True , parms ] )
   if 44 - 44: OoOoOO00
   if 63 - 63: OoOoOO00 % iIii1I11I1II1 . I1Ii111 * O0 * OOooOOo - I11i
   if 52 - 52: I11i - I11i / OoooooooOO - iIii1I11I1II1 / i11iIiiIii - Oo0Ooo
   if 61 - 61: OOooOOo / iIii1I11I1II1 - Oo0Ooo % Oo0Ooo % Oo0Ooo
   if 66 - 66: OoooooooOO
   if 23 - 23: OoOoOO00
 lisp_find_negative_mask_len ( O0oOoooooooOo00O , entry . eid , IIi1IIII1ii )
 return ( [ True , parms ] )
 if 35 - 35: I1Ii111 - i1IIi
 if 90 - 90: I11i . OoO0O00 . iIii1I11I1II1
 if 81 - 81: iII111i + I11i - i11iIiiIii * I1IiiI / IiII - Ii1I
 if 44 - 44: OoooooooOO . oO0o
 if 30 - 30: I1Ii111 % IiII / II111iiii
 if 68 - 68: oO0o / O0 / OOooOOo
 if 3 - 3: o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 17 - 17: OoO0O00 * i1IIi
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 50 - 50: OoOoOO00 + I11i
 if 56 - 56: OOooOOo * OOooOOo + I1IiiI % I1IiiI - I11i
 if 1 - 1: OoooooooOO . ooOoO0o - i1IIi
 if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
 IIi1IIII1ii = lisp_address ( eid . afi , "" , 0 , 0 )
 IIi1IIII1ii . copy_address ( eid )
 IIi1IIII1ii . mask_len = 0
 if 5 - 5: OoOoOO00 . I11i
 I1I1iI1IIII = ddt_entry . print_eid_tuple ( )
 OooOoOooOO = ddt_entry . eid
 if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
 if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
 if 3 - 3: Ii1I - I1IiiI + O0
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 eid , OooOoOooOO , IIi1IIII1ii = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , OooOoOooOO , IIi1IIII1ii ) )
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
 if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
 if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
 if 67 - 67: o0oOOo0O0Ooo - Ii1I
 IIi1IIII1ii . mask_address ( IIi1IIII1ii . mask_len )
 if 29 - 29: OoOoOO00 . I1ii11iIi11i
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # Oo0Ooo % OOooOOo
 I1I1iI1IIII , IIi1IIII1ii . print_prefix ( ) ) )
 return ( IIi1IIII1ii )
 if 14 - 14: I11i . OoO0O00
 if 46 - 46: ooOoO0o
 if 48 - 48: i1IIi * I1IiiI / i11iIiiIii
 if 40 - 40: IiII
 if 42 - 42: O0 / II111iiii
 if 88 - 88: Oo0Ooo
 if 20 - 20: OoooooooOO * i1IIi * IiII / OoooooooOO - Oo0Ooo / i11iIiiIii
 if 28 - 28: iIii1I11I1II1 % OOooOOo * I1IiiI
def lisp_ms_compute_neg_prefix ( eid , group ) :
 IIi1IIII1ii = lisp_address ( eid . afi , "" , 0 , 0 )
 IIi1IIII1ii . copy_address ( eid )
 IIi1IIII1ii . mask_len = 0
 iiI = lisp_address ( group . afi , "" , 0 , 0 )
 iiI . copy_address ( group )
 iiI . mask_len = 0
 OooOoOooOO = None
 if 27 - 27: I1ii11iIi11i / II111iiii + O0 % I1ii11iIi11i
 if 72 - 72: I1IiiI - i1IIi
 if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
 if 65 - 65: Oo0Ooo / OoooooooOO
 if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
 if ( group . is_null ( ) ) :
  iIi1O00o0 = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( iIi1O00o0 == None ) :
   IIi1IIII1ii . mask_len = IIi1IIII1ii . host_mask_len ( )
   iiI . mask_len = iiI . host_mask_len ( )
   return ( [ IIi1IIII1ii , iiI , LISP_DDT_ACTION_NOT_AUTH ] )
   if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
  o0o0o = lisp_sites_by_eid
  if ( iIi1O00o0 . is_auth_prefix ( ) ) : OooOoOooOO = iIi1O00o0 . eid
 else :
  iIi1O00o0 = lisp_ddt_cache . lookup_cache ( group , False )
  if ( iIi1O00o0 == None ) :
   IIi1IIII1ii . mask_len = IIi1IIII1ii . host_mask_len ( )
   iiI . mask_len = iiI . host_mask_len ( )
   return ( [ IIi1IIII1ii , iiI , LISP_DDT_ACTION_NOT_AUTH ] )
   if 34 - 34: OoooooooOO * OoooooooOO / O0
  if ( iIi1O00o0 . is_auth_prefix ( ) ) : OooOoOooOO = iIi1O00o0 . group
  if 73 - 73: II111iiii
  group , OooOoOooOO , iiI = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , OooOoOooOO , iiI ) )
  if 98 - 98: OoOoOO00 / iII111i - OoooooooOO + i11iIiiIii / O0 % II111iiii
  if 42 - 42: I1ii11iIi11i % i11iIiiIii . iII111i
  iiI . mask_address ( iiI . mask_len )
  if 60 - 60: I1Ii111 % IiII - iIii1I11I1II1
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , OooOoOooOO . print_prefix ( ) if ( OooOoOooOO != None ) else "'not found'" ,
  # I1Ii111 . I11i - I1IiiI . iII111i + O0 / I1ii11iIi11i
  # I1Ii111
  # ooOoO0o . O0
 iiI . print_prefix ( ) ) )
  if 5 - 5: OoooooooOO % OoooooooOO * oO0o * ooOoO0o + ooOoO0o * oO0o
  o0o0o = iIi1O00o0 . source_cache
  if 12 - 12: IiII - II111iiii
  if 71 - 71: i11iIiiIii . Oo0Ooo + oO0o + oO0o
  if 97 - 97: i11iIiiIii / O0 . iII111i . iIii1I11I1II1
  if 40 - 40: OoOoOO00 / iII111i / O0 * ooOoO0o
  if 58 - 58: iII111i % I11i
 Ooo0O = LISP_DDT_ACTION_DELEGATION_HOLE if ( OooOoOooOO != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 71 - 71: I1IiiI + OoO0O00 + IiII * I11i
 if 61 - 61: I1IiiI / OoOoOO00
 if 58 - 58: o0oOOo0O0Ooo - Oo0Ooo % OoOoOO00 + I11i
 if 10 - 10: II111iiii / iIii1I11I1II1 % i11iIiiIii
 if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
 if 43 - 43: oO0o
 eid , OooOoOooOO , IIi1IIII1ii = o0o0o . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , OooOoOooOO , IIi1IIII1ii ) )
 if 22 - 22: I1Ii111 + i11iIiiIii
 if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
 if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
 if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
 IIi1IIII1ii . mask_address ( IIi1IIII1ii . mask_len )
 if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # I1ii11iIi11i + oO0o
 # OoOoOO00
 OooOoOooOO . print_prefix ( ) if ( OooOoOooOO != None ) else "'not found'" , IIi1IIII1ii . print_prefix ( ) ) )
 if 33 - 33: OoOoOO00 . Ii1I
 if 91 - 91: Ii1I - I1IiiI * Ii1I . Oo0Ooo
 return ( [ IIi1IIII1ii , iiI , Ooo0O ] )
 if 26 - 26: I1ii11iIi11i * O0 . o0oOOo0O0Ooo / OoO0O00 / II111iiii . O0
 if 58 - 58: iIii1I11I1II1
 if 15 - 15: IiII / OOooOOo / I11i + i1IIi
 if 95 - 95: i1IIi + II111iiii . iIii1I11I1II1 . OoooooooOO + o0oOOo0O0Ooo / iIii1I11I1II1
 if 40 - 40: OoO0O00 / O0
 if 60 - 60: iIii1I11I1II1 / Oo0Ooo / oO0o + iII111i
 if 66 - 66: iIii1I11I1II1 . O0 * IiII . ooOoO0o + i1IIi
 if 83 - 83: o0oOOo0O0Ooo / II111iiii + I1IiiI - iII111i + OoO0O00
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 67 - 67: I1Ii111 - OoOoOO00 . i11iIiiIii - I1Ii111 . i11iIiiIii
 O0oOoooooooOo00O = map_request . target_eid
 oooiiIiIIIi1 = map_request . target_group
 OoI1 = map_request . nonce
 if 25 - 25: I11i % I1Ii111 + Ii1I
 if ( action == LISP_DDT_ACTION_MS_ACK ) : OoI1iI = 1440
 if 46 - 46: ooOoO0o + Oo0Ooo + oO0o / II111iiii . iIii1I11I1II1 * I1IiiI
 if 87 - 87: I11i + iIii1I11I1II1
 if 91 - 91: oO0o
 if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
 III1II1II1 = lisp_map_referral ( )
 III1II1II1 . record_count = 1
 III1II1II1 . nonce = OoI1
 oOo0O000oo0 = III1II1II1 . encode ( )
 III1II1II1 . print_map_referral ( )
 if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
 O0OOOo000 = False
 if 75 - 75: i11iIiiIii
 if 38 - 38: iIii1I11I1II1
 if 80 - 80: OoO0O00
 if 72 - 72: I11i * II111iiii
 if 82 - 82: I1Ii111 . OoO0O00 * II111iiii
 if 99 - 99: iIii1I11I1II1 / iII111i % i1IIi - II111iiii / OoO0O00
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( O0oOoooooooOo00O ,
 oooiiIiIIIi1 )
  OoI1iI = 15
  if 33 - 33: OoooooooOO / i1IIi . Ii1I
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : OoI1iI = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : OoI1iI = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : OoI1iI = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : OoI1iI = 0
 if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
 O000oO0O0 = False
 ii1iI1iII1i = 0
 iIi1O00o0 = lisp_ddt_cache_lookup ( O0oOoooooooOo00O , oooiiIiIIIi1 , False )
 if ( iIi1O00o0 != None ) :
  ii1iI1iII1i = len ( iIi1O00o0 . delegation_set )
  O000oO0O0 = iIi1O00o0 . is_ms_peer_entry ( )
  iIi1O00o0 . map_referrals_sent += 1
  if 63 - 63: I11i
  if 59 - 59: OOooOOo % II111iiii
  if 30 - 30: i1IIi / I1ii11iIi11i
  if 4 - 4: Oo0Ooo
  if 31 - 31: IiII
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0OOOo000 = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0OOOo000 = ( O000oO0O0 == False )
  if 86 - 86: Oo0Ooo + IiII / o0oOOo0O0Ooo % OoOoOO00
  if 49 - 49: iIii1I11I1II1 % Oo0Ooo % I11i * Ii1I - OoO0O00
  if 15 - 15: i11iIiiIii + o0oOOo0O0Ooo . Ii1I . I1IiiI
  if 8 - 8: iII111i % II111iiii + IiII
  if 5 - 5: i1IIi + II111iiii
 o00o = lisp_eid_record ( )
 o00o . rloc_count = ii1iI1iII1i
 o00o . authoritative = True
 o00o . action = action
 o00o . ddt_incomplete = O0OOOo000
 o00o . eid = eid_prefix
 o00o . group = group_prefix
 o00o . record_ttl = OoI1iI
 if 75 - 75: OOooOOo . IiII . I1IiiI + OoooooooOO
 oOo0O000oo0 += o00o . encode ( )
 o00o . print_record ( "  " , True )
 if 35 - 35: I11i % i1IIi - I1ii11iIi11i . Oo0Ooo
 if 69 - 69: ooOoO0o * OoO0O00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 if 35 - 35: I1IiiI . OOooOOo * OoO0O00 . I1ii11iIi11i - I1IiiI
 if 5 - 5: i1IIi * II111iiii
 if ( ii1iI1iII1i != 0 ) :
  for oooo0oOOooo0 in iIi1O00o0 . delegation_set :
   Iii1i1iii = lisp_rloc_record ( )
   Iii1i1iii . rloc = oooo0oOOooo0 . delegate_address
   Iii1i1iii . priority = oooo0oOOooo0 . priority
   Iii1i1iii . weight = oooo0oOOooo0 . weight
   Iii1i1iii . mpriority = 255
   Iii1i1iii . mweight = 0
   Iii1i1iii . reach_bit = True
   oOo0O000oo0 += Iii1i1iii . encode ( )
   Iii1i1iii . print_record ( "    " )
   if 64 - 64: I1IiiI * iIii1I11I1II1 % I1Ii111
   if 22 - 22: OoooooooOO + I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo
   if 61 - 61: iIii1I11I1II1
   if 95 - 95: I1ii11iIi11i + IiII * Ii1I - IiII
   if 58 - 58: I1ii11iIi11i - oO0o % I11i * O0
   if 43 - 43: OoOoOO00 + O0
   if 71 - 71: ooOoO0o * I1IiiI / I1ii11iIi11i
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , oOo0O000oo0 , ecm_source , port )
 return
 if 8 - 8: I1Ii111 / iIii1I11I1II1
 if 29 - 29: i11iIiiIii % i1IIi + oO0o . I1ii11iIi11i
 if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
 if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
 if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
 if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
 if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
 if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # I1Ii111 . O0 - oO0o + i1IIi % Oo0Ooo
 red ( dest . print_address ( ) , False ) ) )
 if 39 - 39: I1Ii111 - I1IiiI
 Ooo0O = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 18 - 18: i1IIi
 if 42 - 42: II111iiii - i1IIi . oO0o % OOooOOo % ooOoO0o - i11iIiiIii
 if 23 - 23: OOooOOo + iIii1I11I1II1 - i1IIi
 if 72 - 72: OOooOOo . I1IiiI * O0 + i11iIiiIii - iII111i
 if 79 - 79: o0oOOo0O0Ooo + I1ii11iIi11i
 if ( lisp_get_eid_hash ( eid ) != None ) :
  Ooo0O = LISP_SEND_MAP_REQUEST_ACTION
  if 46 - 46: I11i
  if 78 - 78: IiII / II111iiii
 oOo0O000oo0 = lisp_build_map_reply ( eid , group , [ ] , nonce , Ooo0O , ttl , False ,
 None , False , False )
 if 55 - 55: Oo0Ooo
 if 80 - 80: o0oOOo0O0Ooo - I1Ii111 * O0 * iIii1I11I1II1
 if 59 - 59: I1ii11iIi11i + I11i / OoO0O00
 if 36 - 36: o0oOOo0O0Ooo + ooOoO0o * I11i
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , oOo0O000oo0 , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , oOo0O000oo0 , dest , port )
  if 81 - 81: OOooOOo * I11i - I1ii11iIi11i
 return
 if 82 - 82: I1ii11iIi11i * II111iiii - OoooooooOO % iII111i * I1IiiI % OoOoOO00
 if 81 - 81: I11i + o0oOOo0O0Ooo / iII111i
 if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
 if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
 if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
 if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
 if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
def lisp_retransmit_ddt_map_request ( mr ) :
 O0OoooO = mr . mr_source . print_address ( )
 I1IIiII1 = mr . print_eid_tuple ( )
 OoI1 = mr . nonce
 if 35 - 35: iII111i / iII111i * OoOoOO00 - i11iIiiIii
 if 27 - 27: i1IIi / I11i + I1Ii111 . II111iiii * OoO0O00
 if 55 - 55: i1IIi % Ii1I - o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 6 - 6: i1IIi
 if 10 - 10: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / i11iIiiIii - I1IiiI . O0
 if ( mr . last_request_sent_to ) :
  iii11 = mr . last_request_sent_to . print_address ( )
  i111II1iI1ii = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( i111II1iI1ii and i111II1iI1ii . referral_set . has_key ( iii11 ) ) :
   i111II1iI1ii . referral_set [ iii11 ] . no_responses += 1
   if 50 - 50: I1ii11iIi11i + iII111i
   if 64 - 64: oO0o
   if 11 - 11: o0oOOo0O0Ooo
   if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
   if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
   if 66 - 66: I1IiiI + I11i
   if 58 - 58: I1ii11iIi11i
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( I1IIiII1 , False ) , lisp_hex_string ( OoI1 ) ) )
  if 7 - 7: oO0o - I11i
  mr . dequeue_map_request ( )
  return
  if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
  if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 mr . retry_count += 1
 if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
 i11I1 = green ( O0OoooO , False )
 iiiii111 = green ( I1IIiII1 , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # OoooooooOO
 red ( mr . itr . print_address ( ) , False ) , i11I1 , iiiii111 ,
 lisp_hex_string ( OoI1 ) ) )
 if 24 - 24: i1IIi - OOooOOo - i11iIiiIii + Oo0Ooo + o0oOOo0O0Ooo
 if 88 - 88: I1IiiI + I1IiiI . i1IIi
 if 83 - 83: iII111i
 if 51 - 51: OoO0O00
 lisp_send_ddt_map_request ( mr , False )
 if 45 - 45: I1ii11iIi11i + Ii1I * I1ii11iIi11i % Ii1I - O0 * OoooooooOO
 if 98 - 98: OoO0O00 / o0oOOo0O0Ooo . OoooooooOO % i11iIiiIii % Oo0Ooo + OoOoOO00
 if 49 - 49: II111iiii - OOooOOo - I1IiiI / Ii1I
 if 47 - 47: I1ii11iIi11i + OoO0O00
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 95 - 95: I11i . OoOoOO00 / Oo0Ooo % ooOoO0o % II111iiii
 if 82 - 82: ooOoO0o - I11i / I1Ii111 - i11iIiiIii - iIii1I11I1II1
 if 53 - 53: iIii1I11I1II1 % I11i . i1IIi + IiII / OoOoOO00 . II111iiii
 if 43 - 43: O0 - IiII + i11iIiiIii * i1IIi - ooOoO0o % IiII
 if 23 - 23: OoooooooOO % o0oOOo0O0Ooo + OoO0O00
 if 25 - 25: IiII % OOooOOo + Ii1I * I1ii11iIi11i
 if 25 - 25: iIii1I11I1II1 * OoOoOO00 % I1IiiI + IiII
 if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 83 - 83: II111iiii . OOooOOo
 if 88 - 88: O0
 if 12 - 12: Ii1I % OOooOOo % Oo0Ooo * I1Ii111
 if 96 - 96: iII111i + ooOoO0o
 O0I111Ii1 = [ ]
 for iiIi11i1i in referral . referral_set . values ( ) :
  if ( iiIi11i1i . updown == False ) : continue
  if ( len ( O0I111Ii1 ) == 0 or O0I111Ii1 [ 0 ] . priority == iiIi11i1i . priority ) :
   O0I111Ii1 . append ( iiIi11i1i )
  elif ( O0I111Ii1 [ 0 ] . priority > iiIi11i1i . priority ) :
   O0I111Ii1 = [ ]
   O0I111Ii1 . append ( iiIi11i1i )
   if 52 - 52: Ii1I * OoooooooOO * I1ii11iIi11i / O0 * o0oOOo0O0Ooo
   if 28 - 28: o0oOOo0O0Ooo . o0oOOo0O0Ooo . o0oOOo0O0Ooo
   if 93 - 93: i11iIiiIii / IiII
 i1II = len ( O0I111Ii1 )
 if ( i1II == 0 ) : return ( None )
 if 20 - 20: i11iIiiIii * I1ii11iIi11i * ooOoO0o % iIii1I11I1II1 + iII111i
 IiiiII = dest_eid . hash_address ( source_eid )
 IiiiII = IiiiII % i1II
 return ( O0I111Ii1 [ IiiiII ] )
 if 51 - 51: O0 - I11i . o0oOOo0O0Ooo + o0oOOo0O0Ooo / I1Ii111
 if 32 - 32: II111iiii - Oo0Ooo
 if 69 - 69: o0oOOo0O0Ooo * I1ii11iIi11i / o0oOOo0O0Ooo * OoooooooOO
 if 60 - 60: OoOoOO00 / i1IIi * Oo0Ooo / i1IIi
 if 86 - 86: OoOoOO00 . I11i
 if 97 - 97: Ii1I
 if 24 - 24: I1IiiI * i11iIiiIii
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 oOOOO0oOo0o0 = mr . lisp_sockets
 OoI1 = mr . nonce
 I11I = mr . itr
 II1 = mr . mr_source
 o0o0O00 = mr . print_eid_tuple ( )
 if 44 - 44: o0oOOo0O0Ooo * I1IiiI + Ii1I . I1IiiI - I1Ii111 - ooOoO0o
 if 16 - 16: Ii1I + i11iIiiIii . OoO0O00 / I11i . I11i % I11i
 if 80 - 80: i11iIiiIii + OoO0O00
 if 2 - 2: II111iiii
 if 67 - 67: oO0o % I1Ii111
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( o0o0O00 , False ) , lisp_hex_string ( OoI1 ) ) )
  if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
  mr . dequeue_map_request ( )
  return
  if 15 - 15: I1IiiI
  if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
  if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
  if 45 - 45: I1Ii111 + OOooOOo
  if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
  if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
 if ( send_to_root ) :
  Ii1iI11i11Ii = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  oOooo00 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( o0o0O00 , False ) ) )
 else :
  Ii1iI11i11Ii = mr . eid
  oOooo00 = mr . group
  if 14 - 14: i1IIi - i1IIi - ooOoO0o / Oo0Ooo % I11i
  if 17 - 17: OoooooooOO + ooOoO0o
  if 57 - 57: i11iIiiIii / I1Ii111 * iII111i * OoOoOO00
  if 40 - 40: I1ii11iIi11i - OoooooooOO
  if 74 - 74: i11iIiiIii % i11iIiiIii / II111iiii + I1ii11iIi11i . OOooOOo
 OoIi11IIiiI1I = lisp_referral_cache_lookup ( Ii1iI11i11Ii , oOooo00 , False )
 if ( OoIi11IIiiI1I == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( oOOOO0oOo0o0 , Ii1iI11i11Ii , oOooo00 ,
 OoI1 , I11I , mr . sport , 15 , None , False )
  return
  if 18 - 18: O0
  if 26 - 26: i1IIi - iIii1I11I1II1
 i1iiiI1Ii1I1I = OoIi11IIiiI1I . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( i1iiiI1Ii1I1I ,
 OoIi11IIiiI1I . print_referral_type ( ) ) )
 if 21 - 21: Oo0Ooo / Oo0Ooo
 iiIi11i1i = lisp_get_referral_node ( OoIi11IIiiI1I , II1 , mr . eid )
 if ( iiIi11i1i == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( oOOOO0oOo0o0 , OoIi11IIiiI1I . eid ,
 OoIi11IIiiI1I . group , OoI1 , I11I , mr . sport , 1 , None , False )
  return
  if 1 - 1: Oo0Ooo
  if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( iiIi11i1i . referral_address . print_address ( ) ,
 # IiII + OOooOOo % II111iiii - I1IiiI
 OoIi11IIiiI1I . print_referral_type ( ) , green ( o0o0O00 , False ) ,
 lisp_hex_string ( OoI1 ) ) )
 if 59 - 59: i11iIiiIii . Ii1I + ooOoO0o / OOooOOo + OoO0O00
 if 57 - 57: i1IIi * OoO0O00 % o0oOOo0O0Ooo + iIii1I11I1II1 + I1ii11iIi11i * i1IIi
 if 25 - 25: oO0o / o0oOOo0O0Ooo * Ii1I
 if 23 - 23: ooOoO0o - i1IIi
 IIIIIi111i1i = ( OoIi11IIiiI1I . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 OoIi11IIiiI1I . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( oOOOO0oOo0o0 , mr . packet , II1 , mr . sport , mr . eid ,
 iiIi11i1i . referral_address , to_ms = IIIIIi111i1i , ddt = True )
 if 26 - 26: I11i + I1IiiI + i1IIi % OoO0O00 * OoOoOO00
 if 28 - 28: I1ii11iIi11i - o0oOOo0O0Ooo + Oo0Ooo - Ii1I
 if 98 - 98: OoOoOO00 + O0 - I1Ii111
 if 67 - 67: I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
 mr . last_request_sent_to = iiIi11i1i . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 iiIi11i1i . map_requests_sent += 1
 return
 if 75 - 75: OOooOOo . ooOoO0o
 if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
 if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
 if 51 - 51: I1IiiI + O0
 if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
 if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
 if 85 - 85: OoOoOO00
 if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
 O0oOoooooooOo00O = map_request . target_eid
 oooiiIiIIIi1 = map_request . target_group
 I1IIiII1 = map_request . print_eid_tuple ( )
 O0OoooO = mr_source . print_address ( )
 OoI1 = map_request . nonce
 if 72 - 72: Ii1I
 i11I1 = green ( O0OoooO , False )
 iiiii111 = green ( I1IIiII1 , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # i1IIi * o0oOOo0O0Ooo
 red ( ecm_source . print_address ( ) , False ) , i11I1 , iiiii111 ,
 lisp_hex_string ( OoI1 ) ) )
 if 37 - 37: OoOoOO00 + Ii1I . iII111i
 if 26 - 26: II111iiii * i11iIiiIii / II111iiii % Oo0Ooo % i11iIiiIii
 if 24 - 24: I11i . Ii1I / ooOoO0o + I1ii11iIi11i + OoooooooOO - I11i
 if 51 - 51: I1IiiI % i1IIi + ooOoO0o / I1ii11iIi11i % iIii1I11I1II1 % IiII
 IIiII11I1I111 = lisp_ddt_map_request ( lisp_sockets , packet , O0oOoooooooOo00O , oooiiIiIIIi1 , OoI1 )
 IIiII11I1I111 . packet = packet
 IIiII11I1I111 . itr = ecm_source
 IIiII11I1I111 . mr_source = mr_source
 IIiII11I1I111 . sport = sport
 IIiII11I1I111 . from_pitr = map_request . pitr_bit
 IIiII11I1I111 . queue_map_request ( )
 if 95 - 95: OOooOOo / I1Ii111 * I1IiiI * I11i * oO0o . I1ii11iIi11i
 lisp_send_ddt_map_request ( IIiII11I1I111 , False )
 return
 if 80 - 80: iIii1I11I1II1 + I11i / oO0o . I1Ii111 + I11i
 if 26 - 26: Oo0Ooo . i11iIiiIii % I1Ii111 . Oo0Ooo + Oo0Ooo + OoOoOO00
 if 100 - 100: IiII * I11i - OOooOOo
 if 11 - 11: I1IiiI % Ii1I + II111iiii
 if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 if 63 - 63: OoOoOO00 % IiII . iII111i
 if 44 - 44: I1IiiI
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl ) :
 if 25 - 25: oO0o
 ooOiiIII = packet
 OoO0o = lisp_map_request ( )
 packet = OoO0o . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 42 - 42: OoOoOO00 + OoooooooOO * OOooOOo - i11iIiiIii + OOooOOo
  if 11 - 11: i11iIiiIii % Oo0Ooo % II111iiii . IiII % OoOoOO00
 OoO0o . print_map_request ( )
 if 10 - 10: Ii1I
 if 68 - 68: Oo0Ooo % ooOoO0o + i11iIiiIii / oO0o / II111iiii
 if 63 - 63: OoO0O00 % i1IIi - OoooooooOO / ooOoO0o
 if 75 - 75: OOooOOo + IiII + ooOoO0o / I1IiiI . iIii1I11I1II1 / Oo0Ooo
 if ( OoO0o . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , OoO0o ,
 mr_source , mr_port , ttl )
  return
  if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
  if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
  if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
  if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
  if 70 - 70: i1IIi * II111iiii * I1IiiI
 if ( OoO0o . smr_bit ) :
  lisp_process_smr ( OoO0o )
  if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
  if 20 - 20: Oo0Ooo % OOooOOo
  if 8 - 8: OOooOOo
  if 92 - 92: iII111i / OOooOOo . IiII / I11i + o0oOOo0O0Ooo
  if 99 - 99: II111iiii
 if ( OoO0o . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( OoO0o )
  if 70 - 70: O0 % I1ii11iIi11i
  if 28 - 28: IiII - i1IIi - I1Ii111 % Ii1I - IiII
  if 73 - 73: iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
  if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
  if 2 - 2: i11iIiiIii % ooOoO0o
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , OoO0o , mr_source ,
 mr_port , ttl )
  if 56 - 56: IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
  if 82 - 82: OoooooooOO . i1IIi . OoO0O00 . OoO0O00
  if 31 - 31: iIii1I11I1II1
  if 64 - 64: ooOoO0o
  if 30 - 30: OoO0O00 + o0oOOo0O0Ooo / iIii1I11I1II1
 if ( lisp_i_am_ms ) :
  packet = ooOiiIII
  O0oOoooooooOo00O , oooiiIiIIIi1 , O0OoO0O0 = lisp_ms_process_map_request ( lisp_sockets ,
 ooOiiIII , OoO0o , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , OoO0o , ecm_source ,
 ecm_port , O0OoO0O0 , O0oOoooooooOo00O , oooiiIiIIIi1 )
   if 79 - 79: I11i * I1ii11iIi11i
  return
  if 85 - 85: iIii1I11I1II1 * O0 / iII111i
  if 75 - 75: Oo0Ooo * IiII % Ii1I
  if 40 - 40: o0oOOo0O0Ooo * i11iIiiIii . ooOoO0o
  if 63 - 63: I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / IiII + I11i
  if 57 - 57: iIii1I11I1II1 % iIii1I11I1II1
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , ooOiiIII , OoO0o ,
 ecm_source , mr_port , mr_source )
  if 23 - 23: II111iiii . ooOoO0o % I1Ii111
  if 39 - 39: OoooooooOO
  if 10 - 10: Oo0Ooo * iII111i
  if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
  if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = ooOiiIII
  lisp_ddt_process_map_request ( lisp_sockets , OoO0o , ecm_source ,
 ecm_port )
  if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
 return
 if 44 - 44: OoooooooOO + I1Ii111 + OoO0O00
 if 15 - 15: iIii1I11I1II1 % i1IIi + iII111i
 if 48 - 48: o0oOOo0O0Ooo / oO0o
 if 61 - 61: I1IiiI + iII111i * Ii1I % I1Ii111 . Ii1I
 if 83 - 83: i11iIiiIii * OoOoOO00 * i11iIiiIii % II111iiii . i11iIiiIii * I11i
 if 67 - 67: i1IIi / i1IIi + IiII . oO0o
 if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
 if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
def lisp_store_mr_stats ( source , nonce ) :
 IIiII11I1I111 = lisp_get_map_resolver ( source , None )
 if ( IIiII11I1I111 == None ) : return
 if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
 if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
 if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
 if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
 IIiII11I1I111 . neg_map_replies_received += 1
 IIiII11I1I111 . last_reply = lisp_get_timestamp ( )
 if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
 if 88 - 88: Ii1I % Ii1I
 if 29 - 29: OOooOOo % I1ii11iIi11i
 if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
 if ( ( IIiII11I1I111 . neg_map_replies_received % 100 ) == 0 ) : IIiII11I1I111 . total_rtt = 0
 if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
 if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
 if 52 - 52: I11i % i1IIi . I1ii11iIi11i
 if 62 - 62: ooOoO0o - I1ii11iIi11i
 if ( IIiII11I1I111 . last_nonce == nonce ) :
  IIiII11I1I111 . total_rtt += ( time . time ( ) - IIiII11I1I111 . last_used )
  IIiII11I1I111 . last_nonce = 0
  if 71 - 71: I11i
 if ( ( IIiII11I1I111 . neg_map_replies_received % 10 ) == 0 ) : IIiII11I1I111 . last_nonce = 0
 return
 if 34 - 34: oO0o / O0 * oO0o
 if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
 if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
 if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
 if 60 - 60: I1IiiI / I1IiiI / II111iiii
 if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
 if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl ) :
 global lisp_map_cache
 if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
 oooo0O = lisp_map_reply ( )
 packet = oooo0O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 34 - 34: I1Ii111 / i1IIi
 oooo0O . print_map_reply ( )
 if 95 - 95: OoOoOO00 * OOooOOo
 if 68 - 68: I1Ii111 / iIii1I11I1II1 % Ii1I
 if 77 - 77: i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
 if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
 o0OOoO00OO0O0 = None
 for o0Ooo0O00 in range ( oooo0O . record_count ) :
  o00o = lisp_eid_record ( )
  packet = o00o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 90 - 90: Ii1I + Ii1I / OoO0O00 + i1IIi - ooOoO0o
  o00o . print_record ( "  " , False )
  if 6 - 6: Ii1I
  if 39 - 39: Oo0Ooo * Oo0Ooo . I11i - OoOoOO00 * i11iIiiIii / ooOoO0o
  if 76 - 76: OoooooooOO - OOooOOo % OoOoOO00 / I1Ii111 + OoO0O00
  if 68 - 68: Oo0Ooo / OOooOOo / i1IIi % I1Ii111 + I1ii11iIi11i . OoooooooOO
  if 97 - 97: II111iiii + IiII / i11iIiiIii
  if ( o00o . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , oooo0O . nonce )
   if 32 - 32: Oo0Ooo * i1IIi * OOooOOo . i1IIi
   if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
  IiI = ( o00o . group . is_null ( ) == False )
  if 77 - 77: I1Ii111 / I11i % oO0o * Oo0Ooo - I1Ii111 . IiII
  if 77 - 77: o0oOOo0O0Ooo - OoOoOO00 + Oo0Ooo . o0oOOo0O0Ooo
  if 59 - 59: ooOoO0o + I1Ii111 % Ii1I + I1IiiI * I11i
  if 19 - 19: i11iIiiIii + i1IIi . iII111i % iIii1I11I1II1 / o0oOOo0O0Ooo
  if 20 - 20: OoooooooOO + Ii1I / II111iiii * OoOoOO00 + OOooOOo
  if ( lisp_decent_push_configured ) :
   Ooo0O = o00o . action
   if ( IiI and Ooo0O == LISP_DROP_ACTION ) :
    if ( o00o . eid . is_local ( ) ) : continue
    if 75 - 75: OoooooooOO - Oo0Ooo - Oo0Ooo % O0 + ooOoO0o + Oo0Ooo
    if 56 - 56: i1IIi
    if 37 - 37: I1IiiI % i11iIiiIii + OoO0O00 * OOooOOo . o0oOOo0O0Ooo % IiII
    if 18 - 18: Oo0Ooo % IiII . OoOoOO00 - IiII + I1Ii111 + oO0o
    if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
    if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
    if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
  if ( o00o . eid . is_null ( ) ) : continue
  if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
  if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
  if 41 - 41: I1ii11iIi11i * IiII
  if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
  if 29 - 29: OoooooooOO / oO0o
  if ( IiI ) :
   IIo0OooOO = lisp_map_cache_lookup ( o00o . eid , o00o . group )
  else :
   IIo0OooOO = lisp_map_cache . lookup_cache ( o00o . eid , True )
   if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
  iIIIi11 = ( IIo0OooOO == None )
  if 35 - 35: iIii1I11I1II1 + oO0o . ooOoO0o - II111iiii
  if 80 - 80: I1Ii111 + I1ii11iIi11i / OoOoOO00 / OoOoOO00
  if 49 - 49: O0 - i1IIi
  if 28 - 28: I1Ii111 + IiII . oO0o
  oo000OO = [ ]
  for OOOO00o00o0 in range ( o00o . rloc_count ) :
   Iii1i1iii = lisp_rloc_record ( )
   Iii1i1iii . keys = oooo0O . keys
   packet = Iii1i1iii . decode ( packet , oooo0O . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 92 - 92: II111iiii . I11i
   Iii1i1iii . print_record ( "    " )
   if 44 - 44: II111iiii - I1ii11iIi11i / I1ii11iIi11i
   IiI1i = None
   if ( IIo0OooOO ) : IiI1i = IIo0OooOO . get_rloc ( Iii1i1iii . rloc )
   if ( IiI1i ) :
    IiiI11iiI1i1 = IiI1i
   else :
    IiiI11iiI1i1 = lisp_rloc ( )
    if 14 - 14: IiII / ooOoO0o . i1IIi + Oo0Ooo
    if 80 - 80: I1Ii111 + I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I11i
    if 60 - 60: I1ii11iIi11i - I1IiiI % OOooOOo + Ii1I - ooOoO0o % OoOoOO00
    if 94 - 94: OoOoOO00 - i1IIi
    if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
    if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
    if 90 - 90: I11i * i11iIiiIii % i1IIi + I1Ii111 / OoO0O00
   IIIIiI1ii1 = IiiI11iiI1i1 . store_rloc_from_record ( Iii1i1iii , oooo0O . nonce ,
 source )
   IiiI11iiI1i1 . echo_nonce_capable = oooo0O . echo_nonce_capable
   if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
   if ( IiiI11iiI1i1 . echo_nonce_capable ) :
    O0o = IiiI11iiI1i1 . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , O0o ) == None ) :
     lisp_echo_nonce ( O0o )
     if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
     if 45 - 45: I1ii11iIi11i - I11i
     if 60 - 60: OOooOOo - OOooOOo * OoOoOO00 / Ii1I % iII111i % Oo0Ooo
     if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
     if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
     if 61 - 61: iIii1I11I1II1 . Oo0Ooo . i1IIi
     if 45 - 45: I1Ii111
   if ( IIo0OooOO and IIo0OooOO . gleaned ) :
    IiiI11iiI1i1 = IIo0OooOO . rloc_set [ 0 ]
    IIIIiI1ii1 = IiiI11iiI1i1 . translated_port
    if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
    if 48 - 48: IiII
    if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
    if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
    if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
    if 57 - 57: I1Ii111 / II111iiii % iII111i
    if 32 - 32: IiII - OOooOOo + i11iIiiIii + I1IiiI . iII111i
    if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1IiiI / OoO0O00
    if 22 - 22: Oo0Ooo / iIii1I11I1II1 + o0oOOo0O0Ooo
   if ( oooo0O . rloc_probe and Iii1i1iii . probe_bit ) :
    if ( IiiI11iiI1i1 . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( IiiI11iiI1i1 . rloc , source , IIIIiI1ii1 ,
 oooo0O . nonce , oooo0O . hop_count , ttl )
     if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
     if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
     if 66 - 66: i11iIiiIii
     if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
     if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
     if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
   oo000OO . append ( IiiI11iiI1i1 )
   if 10 - 10: I11i
   if 24 - 24: Ii1I
   if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
   if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
   if ( lisp_data_plane_security and IiiI11iiI1i1 . rloc_recent_rekey ( ) ) :
    o0OOoO00OO0O0 = IiiI11iiI1i1
    if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
    if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
    if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
    if 26 - 26: ooOoO0o + Oo0Ooo
    if 24 - 24: I1IiiI
    if 43 - 43: OoO0O00
    if 51 - 51: OoooooooOO % IiII % Oo0Ooo
    if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
    if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
    if 95 - 95: iII111i
    if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
  if ( oooo0O . rloc_probe == False and lisp_nat_traversal ) :
   oo0Oo0oo = [ ]
   i1III11i1iI11 = [ ]
   for IiiI11iiI1i1 in oo000OO :
    if 12 - 12: OoOoOO00 % i11iIiiIii
    if 60 - 60: i11iIiiIii + o0oOOo0O0Ooo / OoooooooOO
    if 25 - 25: OoooooooOO / iII111i * OOooOOo
    if 1 - 1: OOooOOo / II111iiii / II111iiii % OoO0O00 % iIii1I11I1II1
    if 36 - 36: I1IiiI / O0
    if ( IiiI11iiI1i1 . rloc . is_private_address ( ) ) :
     IiiI11iiI1i1 . priority = 1
     IiiI11iiI1i1 . state = LISP_RLOC_UNREACH_STATE
     oo0Oo0oo . append ( IiiI11iiI1i1 )
     i1III11i1iI11 . append ( IiiI11iiI1i1 . rloc . print_address_no_iid ( ) )
     continue
     if 20 - 20: OoooooooOO + o0oOOo0O0Ooo . IiII * O0 + i11iIiiIii
     if 67 - 67: ooOoO0o . Oo0Ooo
     if 15 - 15: OoO0O00 . oO0o - o0oOOo0O0Ooo
     if 28 - 28: OOooOOo * OoOoOO00 + OoooooooOO . OOooOOo / oO0o / OoOoOO00
     if 94 - 94: OoO0O00 / i1IIi . OoO0O00 . I1Ii111 + OoO0O00
     if 30 - 30: o0oOOo0O0Ooo + iIii1I11I1II1 - II111iiii - ooOoO0o + OoOoOO00 - II111iiii
    if ( IiiI11iiI1i1 . priority == 254 and lisp_i_am_rtr == False ) :
     oo0Oo0oo . append ( IiiI11iiI1i1 )
     i1III11i1iI11 . append ( IiiI11iiI1i1 . rloc . print_address_no_iid ( ) )
     if 69 - 69: oO0o / O0 / I1IiiI + OoooooooOO * I11i * IiII
    if ( IiiI11iiI1i1 . priority != 254 and lisp_i_am_rtr ) :
     oo0Oo0oo . append ( IiiI11iiI1i1 )
     i1III11i1iI11 . append ( IiiI11iiI1i1 . rloc . print_address_no_iid ( ) )
     if 41 - 41: ooOoO0o % i11iIiiIii
     if 69 - 69: IiII - oO0o
     if 21 - 21: Oo0Ooo / I1Ii111
   if ( i1III11i1iI11 != [ ] ) :
    oo000OO = oo0Oo0oo
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( i1III11i1iI11 ) )
    if 72 - 72: OoOoOO00 . i11iIiiIii
    if 25 - 25: i1IIi
    if 69 - 69: OOooOOo / Ii1I
    if 67 - 67: i11iIiiIii . II111iiii + OoooooooOO % o0oOOo0O0Ooo + IiII * i1IIi
    if 53 - 53: oO0o * OoooooooOO + II111iiii . IiII * I1ii11iIi11i
    if 55 - 55: OoOoOO00
    if 27 - 27: I1IiiI
  oo0Oo0oo = [ ]
  for IiiI11iiI1i1 in oo000OO :
   if ( IiiI11iiI1i1 . json != None ) : continue
   oo0Oo0oo . append ( IiiI11iiI1i1 )
   if 81 - 81: Oo0Ooo
  if ( oo0Oo0oo != [ ] ) :
   I1Ii1i11I1I = len ( oo000OO ) - len ( oo0Oo0oo )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( I1Ii1i11I1I ) )
   if 43 - 43: i1IIi * O0 + ooOoO0o + OoO0O00
   oo000OO = oo0Oo0oo
   if 99 - 99: IiII . OoOoOO00
   if 64 - 64: I1Ii111
   if 96 - 96: Ii1I
   if 100 - 100: ooOoO0o
   if 43 - 43: Ii1I * ooOoO0o + O0 . II111iiii
   if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
   if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
   if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
  if ( oooo0O . rloc_probe and IIo0OooOO != None ) : oo000OO = IIo0OooOO . rloc_set
  if 3 - 3: iII111i
  if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
  if 29 - 29: IiII % OoO0O00
  if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
  if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
  O0O0oOOOoOOoO = iIIIi11
  if ( IIo0OooOO and oo000OO != IIo0OooOO . rloc_set ) :
   IIo0OooOO . delete_rlocs_from_rloc_probe_list ( )
   O0O0oOOOoOOoO = True
   if 63 - 63: ooOoO0o / i1IIi % I1ii11iIi11i + OoOoOO00 - Oo0Ooo
   if 98 - 98: II111iiii - o0oOOo0O0Ooo * Oo0Ooo - i11iIiiIii
   if 75 - 75: oO0o * OoooooooOO . iIii1I11I1II1 + O0 - i1IIi
   if 37 - 37: II111iiii - iIii1I11I1II1 / OOooOOo % I1ii11iIi11i
   if 27 - 27: O0
  ii1ii1I11 = IIo0OooOO . uptime if ( IIo0OooOO ) else None
  if ( IIo0OooOO == None or IIo0OooOO . gleaned == False ) :
   IIo0OooOO = lisp_mapping ( o00o . eid , o00o . group , oo000OO )
   IIo0OooOO . mapping_source = source
   IIo0OooOO . map_cache_ttl = o00o . store_ttl ( )
   IIo0OooOO . action = o00o . action
   IIo0OooOO . add_cache ( O0O0oOOOoOOoO )
   if 39 - 39: ooOoO0o / iIii1I11I1II1 % iII111i + iIii1I11I1II1 / O0
   if 6 - 6: iIii1I11I1II1 . O0 . oO0o + I1ii11iIi11i
  IIiII = "Add"
  if ( ii1ii1I11 ) :
   IIo0OooOO . uptime = ii1ii1I11
   IIo0OooOO . refresh_time = lisp_get_timestamp ( )
   IIiII = "Replace"
   if 3 - 3: IiII
   if 2 - 2: I1IiiI % Ii1I % Oo0Ooo / ooOoO0o % Oo0Ooo + OoOoOO00
  lprint ( "{} {} map-cache with {} RLOCs" . format ( IIiII ,
 green ( IIo0OooOO . print_eid_tuple ( ) , False ) , len ( oo000OO ) ) )
  if 44 - 44: i1IIi / OoooooooOO * OoooooooOO
  if 93 - 93: OoOoOO00 % Oo0Ooo . OoO0O00 / OoooooooOO
  if 59 - 59: OoO0O00 + O0 + i11iIiiIii / OoOoOO00 + iIii1I11I1II1 / OoOoOO00
  if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
  if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
  if ( lisp_ipc_dp_socket and o0OOoO00OO0O0 != None ) :
   lisp_write_ipc_keys ( o0OOoO00OO0O0 )
   if 96 - 96: II111iiii
   if 73 - 73: II111iiii
   if 81 - 81: I1IiiI + OoO0O00
   if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
   if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
   if 9 - 9: iIii1I11I1II1
   if 66 - 66: iIii1I11I1II1
  if ( iIIIi11 ) :
   ii1I = bold ( "RLOC-probe" , False )
   for IiiI11iiI1i1 in IIo0OooOO . best_rloc_set :
    O0o = red ( IiiI11iiI1i1 . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( ii1I , O0o ) )
    lisp_send_map_request ( lisp_sockets , 0 , IIo0OooOO . eid , IIo0OooOO . group , IiiI11iiI1i1 )
    if 65 - 65: i1IIi . I1ii11iIi11i / Oo0Ooo
    if 84 - 84: I1ii11iIi11i . OOooOOo
    if 86 - 86: II111iiii * Oo0Ooo . IiII . iII111i + II111iiii . iIii1I11I1II1
 return
 if 88 - 88: OoooooooOO % ooOoO0o
 if 71 - 71: II111iiii * I1IiiI * Oo0Ooo / II111iiii + iIii1I11I1II1 % i1IIi
 if 85 - 85: IiII * O0 . I1Ii111 . II111iiii
 if 6 - 6: I1ii11iIi11i * oO0o + iIii1I11I1II1 + II111iiii
 if 69 - 69: iII111i . OoO0O00 + I1IiiI
 if 77 - 77: Ii1I * II111iiii
 if 80 - 80: i11iIiiIii
 if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
 packet = map_register . zero_auth ( packet )
 IiiiII = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 69 - 69: O0 % I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 . OOooOOo
 if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 if 61 - 61: OOooOOo
 map_register . auth_data = IiiiII
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 51 - 51: Oo0Ooo * OOooOOo / iII111i
 if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
 if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
 if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
 if 40 - 40: oO0o * IiII
 if 29 - 29: O0 - II111iiii + iII111i
 if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  oooO = hashlib . sha1
  if 14 - 14: OOooOOo
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  oooO = hashlib . sha256
  if 84 - 84: Ii1I + OoO0O00 + OOooOOo % ooOoO0o
  if 27 - 27: OoOoOO00 % I11i
 if ( do_hex ) :
  IiiiII = hmac . new ( password , packet , oooO ) . hexdigest ( )
 else :
  IiiiII = hmac . new ( password , packet , oooO ) . digest ( )
  if 19 - 19: i1IIi - OoOoOO00
 return ( IiiiII )
 if 26 - 26: IiII . i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / o0oOOo0O0Ooo
 if 7 - 7: I1IiiI / OOooOOo * iIii1I11I1II1 * Ii1I * i1IIi
 if 87 - 87: IiII * Oo0Ooo - OOooOOo * OoOoOO00
 if 61 - 61: Oo0Ooo - OoooooooOO % I1ii11iIi11i / i1IIi + O0 % ooOoO0o
 if 79 - 79: I1ii11iIi11i
 if 9 - 9: IiII . O0
 if 66 - 66: i11iIiiIii
 if 33 - 33: i11iIiiIii % OoO0O00 * I1ii11iIi11i
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 96 - 96: I11i % OoooooooOO * I11i . IiII / I1Ii111
 IiiiII = lisp_hash_me ( packet , alg_id , password , True )
 Oo00o00O = ( IiiiII == auth_data )
 if 21 - 21: OoOoOO00 . ooOoO0o * OoO0O00 - OoOoOO00 - OoooooooOO
 if 23 - 23: I1Ii111 + iIii1I11I1II1 - o0oOOo0O0Ooo - iII111i - O0 / iIii1I11I1II1
 if 24 - 24: I1IiiI * o0oOOo0O0Ooo % iII111i % OoooooooOO - ooOoO0o - OoO0O00
 if 75 - 75: i1IIi . i1IIi
 if ( Oo00o00O == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( IiiiII , auth_data ) )
  if 7 - 7: OoooooooOO / iII111i
  if 32 - 32: IiII
 return ( Oo00o00O )
 if 89 - 89: I1IiiI
 if 24 - 24: o0oOOo0O0Ooo - i1IIi . II111iiii
 if 73 - 73: i11iIiiIii % OoooooooOO - i1IIi - O0 * I1Ii111
 if 73 - 73: I1ii11iIi11i + OoooooooOO - OoOoOO00 + Oo0Ooo
 if 47 - 47: II111iiii + iII111i / i1IIi * Ii1I . OoO0O00 + IiII
 if 7 - 7: i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o * I1ii11iIi11i
 if 34 - 34: OoOoOO00 - I11i
def lisp_retransmit_map_notify ( map_notify ) :
 iiII = map_notify . etr
 IIIIiI1ii1 = map_notify . etr_port
 if 85 - 85: OoOoOO00 . oO0o
 if 98 - 98: I1Ii111
 if 49 - 49: OoO0O00 / I1ii11iIi11i % IiII * II111iiii
 if 92 - 92: iIii1I11I1II1 . OoooooooOO . ooOoO0o / II111iiii
 if 30 - 30: i1IIi * Ii1I + Ii1I / I1Ii111
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( iiII . print_address ( ) , False ) ) )
  if 84 - 84: I1IiiI - Oo0Ooo * OoO0O00 * oO0o
  if 13 - 13: I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + oO0o - iII111i
  OOo0O = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( OOo0O ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( OOo0O ) )
   if 32 - 32: I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
   try :
    lisp_map_notify_queue . pop ( OOo0O )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 33 - 33: ooOoO0o % I11i
    if 72 - 72: OoO0O00 % OoooooooOO / II111iiii * oO0o * I1Ii111
  return
  if 98 - 98: OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / OoOoOO00 + I1IiiI
  if 74 - 74: ooOoO0o . IiII . O0 * I1IiiI * oO0o
 oOOOO0oOo0o0 = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 6 - 6: O0 . Ii1I / Oo0Ooo * o0oOOo0O0Ooo
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # i11iIiiIii
 red ( iiII . print_address ( ) , False ) , map_notify . retry_count ) )
 if 5 - 5: I11i . II111iiii
 lisp_send_map_notify ( oOOOO0oOo0o0 , map_notify . packet , iiII , IIIIiI1ii1 )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 36 - 36: Ii1I + ooOoO0o / Oo0Ooo % Oo0Ooo
 if 2 - 2: oO0o - Oo0Ooo * OoO0O00 . ooOoO0o . OOooOOo - oO0o
 if 74 - 74: o0oOOo0O0Ooo
 if 18 - 18: Oo0Ooo % OOooOOo / OOooOOo . I1IiiI + i1IIi . I1IiiI
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
 if 6 - 6: O0 * I1Ii111 - II111iiii
 if 60 - 60: oO0o % oO0o
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
 if 82 - 82: I1ii11iIi11i
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 75 - 75: I11i - II111iiii
 if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
 if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
 if 76 - 76: OOooOOo - iII111i + IiII
 eid_record . rloc_count = len ( parent . registered_rlocs )
 iiiiiiIi = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 13 - 13: OoO0O00 + OoO0O00 % OoO0O00 % O0
 if 62 - 62: IiII - iII111i . I1ii11iIi11i . oO0o
 if 22 - 22: OoOoOO00 * i11iIiiIii * Ii1I
 if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
 for iI111 in parent . registered_rlocs :
  Iii1i1iii = lisp_rloc_record ( )
  Iii1i1iii . store_rloc_entry ( iI111 )
  iiiiiiIi += Iii1i1iii . encode ( )
  Iii1i1iii . print_record ( "  " )
  del ( Iii1i1iii )
  if 28 - 28: iII111i + O0 * ooOoO0o
  if 100 - 100: Oo0Ooo % II111iiii * oO0o / OOooOOo % IiII
  if 33 - 33: Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
  if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
  if 91 - 91: IiII * Ii1I * OOooOOo
 for iI111 in parent . registered_rlocs :
  iiII = iI111 . rloc
  II11II1 = lisp_map_notify ( lisp_sockets )
  II11II1 . record_count = 1
  IiIiIi1I1 = map_register . key_id
  II11II1 . key_id = IiIiIi1I1
  II11II1 . alg_id = map_register . alg_id
  II11II1 . auth_len = map_register . auth_len
  II11II1 . nonce = map_register . nonce
  II11II1 . nonce_key = lisp_hex_string ( II11II1 . nonce )
  II11II1 . etr . copy_address ( iiII )
  II11II1 . etr_port = map_register . sport
  II11II1 . site = parent . site
  oOo0O000oo0 = II11II1 . encode ( iiiiiiIi , parent . site . auth_key [ IiIiIi1I1 ] )
  II11II1 . print_notify ( )
  if 89 - 89: I1ii11iIi11i * iII111i * IiII
  if 74 - 74: OoO0O00 + I1Ii111 / o0oOOo0O0Ooo % Ii1I
  if 19 - 19: I1IiiI % oO0o - Ii1I
  if 97 - 97: OOooOOo / ooOoO0o . Oo0Ooo - Oo0Ooo . OoOoOO00
  OOo0O = II11II1 . nonce_key
  if ( lisp_map_notify_queue . has_key ( OOo0O ) ) :
   ooOOo0OO = lisp_map_notify_queue [ OOo0O ]
   ooOOo0OO . retransmit_timer . cancel ( )
   del ( ooOOo0OO )
   if 95 - 95: IiII + iII111i % I1IiiI
  lisp_map_notify_queue [ OOo0O ] = II11II1
  if 18 - 18: Oo0Ooo
  if 8 - 8: O0 + iIii1I11I1II1 - O0
  if 67 - 67: O0
  if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( iiII . print_address ( ) , False ) ) )
  if 28 - 28: O0 - Oo0Ooo
  lisp_send ( lisp_sockets , iiII , LISP_CTRL_PORT , oOo0O000oo0 )
  if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
  parent . site . map_notifies_sent += 1
  if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
  if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
  if 99 - 99: Oo0Ooo - OoO0O00 + OoooooooOO - I1Ii111 - I1ii11iIi11i % i1IIi
  if 49 - 49: IiII % OoooooooOO / Oo0Ooo - OoOoOO00 + o0oOOo0O0Ooo / Ii1I
  II11II1 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ II11II1 ] )
  II11II1 . retransmit_timer . start ( )
  if 6 - 6: I11i % IiII
 return
 if 48 - 48: Ii1I
 if 100 - 100: OoO0O00 % I1Ii111 + OoooooooOO / OoO0O00
 if 62 - 62: IiII
 if 66 - 66: o0oOOo0O0Ooo % OOooOOo
 if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
 if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
 if 62 - 62: i11iIiiIii
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
 OOo0O = lisp_hex_string ( nonce ) + source . print_address ( )
 if 6 - 6: i11iIiiIii
 if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
 if 53 - 53: oO0o
 if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
 if 4 - 4: I1IiiI
 if 31 - 31: ooOoO0o * i1IIi . O0
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( OOo0O ) ) :
  II11II1 = lisp_map_notify_queue [ OOo0O ]
  i11I1 = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( II11II1 . nonce ) , i11I1 ) )
  if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
  return
  if 100 - 100: I1Ii111
  if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
 II11II1 = lisp_map_notify ( lisp_sockets )
 II11II1 . record_count = record_count
 key_id = key_id
 II11II1 . key_id = key_id
 II11II1 . alg_id = alg_id
 II11II1 . auth_len = auth_len
 II11II1 . nonce = nonce
 II11II1 . nonce_key = lisp_hex_string ( nonce )
 II11II1 . etr . copy_address ( source )
 II11II1 . etr_port = port
 II11II1 . site = site
 II11II1 . eid_list = eid_list
 if 88 - 88: IiII
 if 29 - 29: iII111i . ooOoO0o
 if 62 - 62: IiII
 if 95 - 95: ooOoO0o / i1IIi + II111iiii + OoO0O00 % OoO0O00
 if ( map_register_ack == False ) :
  OOo0O = II11II1 . nonce_key
  lisp_map_notify_queue [ OOo0O ] = II11II1
  if 18 - 18: ooOoO0o * I1IiiI / iII111i % iII111i
  if 9 - 9: i11iIiiIii % ooOoO0o % O0 + i1IIi / O0
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 12 - 12: I1Ii111 - iII111i * iII111i + OoO0O00 . Ii1I % I11i
  if 28 - 28: ooOoO0o % OoO0O00 - II111iiii * IiII - I1IiiI + I1IiiI
  if 84 - 84: IiII / Ii1I
  if 39 - 39: OOooOOo - iIii1I11I1II1 + OoOoOO00 % IiII * OoooooooOO % Ii1I
  if 11 - 11: I1ii11iIi11i
 oOo0O000oo0 = II11II1 . encode ( eid_records , site . auth_key [ key_id ] )
 II11II1 . print_notify ( )
 if 83 - 83: O0
 if ( map_register_ack == False ) :
  o00o = lisp_eid_record ( )
  o00o . decode ( eid_records )
  o00o . print_record ( "  " , False )
  if 97 - 97: O0
  if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
  if 28 - 28: I1Ii111 * II111iiii
  if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
  if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
 lisp_send_map_notify ( lisp_sockets , oOo0O000oo0 , II11II1 . etr , port )
 site . map_notifies_sent += 1
 if 15 - 15: I11i
 if ( map_register_ack ) : return
 if 67 - 67: iIii1I11I1II1
 if 91 - 91: ooOoO0o
 if 66 - 66: OOooOOo
 if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
 if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
 if 9 - 9: Ii1I
 II11II1 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ II11II1 ] )
 II11II1 . retransmit_timer . start ( )
 return
 if 44 - 44: iII111i
 if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
 if 37 - 37: OoO0O00 - Ii1I + OoO0O00
 if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
 if 60 - 60: Oo0Ooo
 if 46 - 46: OoOoOO00 + i1IIi
 if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
 if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
 if 4 - 4: OoO0O00
 if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
 if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
 oOo0O000oo0 = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
 if 38 - 38: iII111i * OoooooooOO - IiII
 if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
 if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
 iiII = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( iiII . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , iiII , LISP_CTRL_PORT , oOo0O000oo0 )
 return
 if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
 if 76 - 76: I11i . I1IiiI
 if 66 - 66: oO0o % oO0o * IiII
 if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
 if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
 if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
 if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 23 - 23: OOooOOo
 II11II1 = lisp_map_notify ( lisp_sockets )
 II11II1 . record_count = 1
 II11II1 . nonce = lisp_get_control_nonce ( )
 II11II1 . nonce_key = lisp_hex_string ( II11II1 . nonce )
 II11II1 . etr . copy_address ( xtr )
 II11II1 . etr_port = LISP_CTRL_PORT
 II11II1 . eid_list = eid_list
 OOo0O = II11II1 . nonce_key
 if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
 if 47 - 47: OoO0O00
 if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
 if 9 - 9: I11i
 if 83 - 83: i11iIiiIii
 if 72 - 72: oO0o + II111iiii . O0 * oO0o + iII111i
 lisp_remove_eid_from_map_notify_queue ( II11II1 . eid_list )
 if ( lisp_map_notify_queue . has_key ( OOo0O ) ) :
  II11II1 = lisp_map_notify_queue [ OOo0O ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( II11II1 . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 22 - 22: I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
  return
  if 84 - 84: OoooooooOO - Oo0Ooo
  if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
  if 82 - 82: OoOoOO00
  if 61 - 61: oO0o . o0oOOo0O0Ooo
  if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
 lisp_map_notify_queue [ OOo0O ] = II11II1
 if 70 - 70: I1IiiI
 if 74 - 74: ooOoO0o * II111iiii
 if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
 if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
 oOOo = site_eid . rtrs_in_rloc_set ( )
 if ( oOOo ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : oOOo = False
  if 67 - 67: I1IiiI % I11i - OoooooooOO
  if 2 - 2: Ii1I
  if 25 - 25: I1Ii111 * I1IiiI + OoOoOO00 . i11iIiiIii . I1IiiI . I11i
  if 61 - 61: o0oOOo0O0Ooo / ooOoO0o + o0oOOo0O0Ooo + Ii1I * iIii1I11I1II1 * OoooooooOO
  if 86 - 86: oO0o . o0oOOo0O0Ooo * OoOoOO00 / oO0o
 o00o = lisp_eid_record ( )
 o00o . record_ttl = 1440
 o00o . eid . copy_address ( site_eid . eid )
 o00o . group . copy_address ( site_eid . group )
 o00o . rloc_count = 0
 for oo0oo00000 in site_eid . registered_rlocs :
  if ( oOOo ^ oo0oo00000 . is_rtr ( ) ) : continue
  o00o . rloc_count += 1
  if 47 - 47: OOooOOo
 oOo0O000oo0 = o00o . encode ( )
 if 40 - 40: I1ii11iIi11i
 if 67 - 67: I1Ii111 - OoO0O00 * ooOoO0o - oO0o / OoO0O00 . I1Ii111
 if 39 - 39: Ii1I
 if 90 - 90: I1Ii111 - I1Ii111 . i11iIiiIii + OoooooooOO % OOooOOo / Oo0Ooo
 II11II1 . print_notify ( )
 o00o . print_record ( "  " , False )
 if 51 - 51: o0oOOo0O0Ooo
 if 8 - 8: oO0o . oO0o . Ii1I
 if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
 if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
 for oo0oo00000 in site_eid . registered_rlocs :
  if ( oOOo ^ oo0oo00000 . is_rtr ( ) ) : continue
  Iii1i1iii = lisp_rloc_record ( )
  Iii1i1iii . store_rloc_entry ( oo0oo00000 )
  oOo0O000oo0 += Iii1i1iii . encode ( )
  Iii1i1iii . print_record ( "    " )
  if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
  if 10 - 10: ooOoO0o
  if 69 - 69: I11i + I1IiiI / oO0o
  if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
  if 85 - 85: I1Ii111 - oO0o
 oOo0O000oo0 = II11II1 . encode ( oOo0O000oo0 , "" )
 if ( oOo0O000oo0 == None ) : return
 if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
 if 96 - 96: oO0o
 if 44 - 44: OoooooooOO / iII111i * Oo0Ooo % OoOoOO00 . oO0o
 if 97 - 97: iIii1I11I1II1 / ooOoO0o
 lisp_send_map_notify ( lisp_sockets , oOo0O000oo0 , xtr , LISP_CTRL_PORT )
 if 16 - 16: Oo0Ooo % IiII
 if 48 - 48: I1IiiI . I1Ii111 . o0oOOo0O0Ooo
 if 72 - 72: Ii1I * OoO0O00 / OoO0O00
 if 39 - 39: oO0o
 II11II1 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ II11II1 ] )
 II11II1 . retransmit_timer . start ( )
 return
 if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
 if 57 - 57: oO0o + O0 - OoOoOO00
 if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
 if 93 - 93: o0oOOo0O0Ooo + i1IIi
 if 24 - 24: i1IIi
 if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
 if 99 - 99: Oo0Ooo
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 iIiI111I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 42 - 42: i11iIiiIii - O0 + O0
 for IIII in rle_list :
  oO0OO = lisp_site_eid_lookup ( IIII [ 0 ] , IIII [ 1 ] , True )
  if ( oO0OO == None ) : continue
  if 29 - 29: IiII - I1ii11iIi11i . Oo0Ooo + IiII - I1IiiI
  if 95 - 95: O0 / o0oOOo0O0Ooo + OoO0O00 / IiII - IiII % OOooOOo
  if 16 - 16: I1IiiI * iIii1I11I1II1 % o0oOOo0O0Ooo - IiII - OOooOOo
  if 83 - 83: Ii1I
  if 20 - 20: ooOoO0o
  if 38 - 38: IiII + OoO0O00 . OOooOOo - I1Ii111 + IiII
  if 82 - 82: OOooOOo
  I1Ii11 = oO0OO . registered_rlocs
  if ( len ( I1Ii11 ) == 0 ) :
   oOo0O = { }
   for OoooOO0o0oO0 in oO0OO . individual_registrations . values ( ) :
    for oo0oo00000 in OoooOO0o0oO0 . registered_rlocs :
     if ( oo0oo00000 . is_rtr ( ) == False ) : continue
     oOo0O [ oo0oo00000 . rloc . print_address ( ) ] = oo0oo00000
     if 88 - 88: I1Ii111 * o0oOOo0O0Ooo
     if 73 - 73: I1Ii111 - I1IiiI + I1Ii111
   I1Ii11 = oOo0O . values ( )
   if 19 - 19: I1IiiI . I1IiiI
   if 97 - 97: iII111i % i1IIi . O0 % II111iiii * I1Ii111 / i1IIi
   if 97 - 97: ooOoO0o
   if 46 - 46: II111iiii - i1IIi
   if 72 - 72: I11i
   if 35 - 35: I1Ii111 + oO0o + II111iiii
  oOOoOOoOo00O = [ ]
  ooO0OooO = False
  if ( oO0OO . eid . address == 0 and oO0OO . eid . mask_len == 0 ) :
   oOOoiII = [ ]
   O000oOo = [ ] if len ( I1Ii11 ) == 0 else I1Ii11 [ 0 ] . rle . rle_nodes
   if 35 - 35: I1ii11iIi11i - iII111i + o0oOOo0O0Ooo
   for iiiI1Ii in O000oOo :
    oOOoOOoOo00O . append ( iiiI1Ii . address )
    oOOoiII . append ( iiiI1Ii . address . print_address_no_iid ( ) )
    if 27 - 27: IiII * Oo0Ooo
   lprint ( "Notify existing RLE-nodes {}" . format ( oOOoiII ) )
  else :
   if 12 - 12: Ii1I
   if 29 - 29: I11i / i11iIiiIii + OoO0O00 % O0 - I1ii11iIi11i % oO0o
   if 30 - 30: I11i + OOooOOo
   if 27 - 27: OoOoOO00 . ooOoO0o
   if 73 - 73: o0oOOo0O0Ooo
   for oo0oo00000 in I1Ii11 :
    if ( oo0oo00000 . is_rtr ( ) ) : oOOoOOoOo00O . append ( oo0oo00000 . rloc )
    if 8 - 8: O0
    if 40 - 40: OOooOOo . II111iiii . ooOoO0o % o0oOOo0O0Ooo
    if 22 - 22: O0 * IiII . OoO0O00
    if 63 - 63: oO0o % Oo0Ooo * OoO0O00 / II111iiii / Ii1I - ooOoO0o
    if 14 - 14: ooOoO0o . o0oOOo0O0Ooo + II111iiii
   ooO0OooO = ( len ( oOOoOOoOo00O ) != 0 )
   if ( ooO0OooO == False ) :
    OoOoO00OOO0O0 = lisp_site_eid_lookup ( IIII [ 0 ] , iIiI111I , False )
    if ( OoOoO00OOO0O0 == None ) : continue
    if 50 - 50: Ii1I - i1IIi * oO0o
    for oo0oo00000 in OoOoO00OOO0O0 . registered_rlocs :
     if ( oo0oo00000 . rloc . is_null ( ) ) : continue
     oOOoOOoOo00O . append ( oo0oo00000 . rloc )
     if 52 - 52: I11i / oO0o - oO0o
     if 84 - 84: iIii1I11I1II1 - o0oOOo0O0Ooo
     if 37 - 37: iII111i * o0oOOo0O0Ooo
     if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
     if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
     if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
   if ( len ( oOOoOOoOo00O ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( oO0OO . print_eid_tuple ( ) , False ) ) )
    if 34 - 34: O0 * oO0o
    continue
    if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
    if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
    if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
    if 88 - 88: i11iIiiIii
    if 13 - 13: I1IiiI
    if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
  for iI111 in oOOoOOoOo00O :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if ooO0OooO else "x" , red ( iI111 . print_address_no_iid ( ) , False ) ,
   # I1ii11iIi11i + I1ii11iIi11i / I1Ii111 - I11i % OoOoOO00 * OOooOOo
 green ( oO0OO . print_eid_tuple ( ) , False ) ) )
   if 80 - 80: I1Ii111 / OoOoOO00 % O0 / OoooooooOO * II111iiii
   OOOi1i = [ oO0OO . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , oO0OO , OOOi1i , iI111 )
   time . sleep ( .001 )
   if 66 - 66: iIii1I11I1II1 % I11i
   if 38 - 38: I1ii11iIi11i * ooOoO0o
 return
 if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
 if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
 if 65 - 65: OOooOOo
 if 90 - 90: O0
 if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
 if 38 - 38: oO0o * I11i % OOooOOo
 if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
 if 47 - 47: Ii1I - Oo0Ooo * OoOoOO00
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for o0Ooo0O00 in range ( rloc_count ) :
  Iii1i1iii = lisp_rloc_record ( )
  packet = Iii1i1iii . decode ( packet , None )
  iIi1IIii1 = Iii1i1iii . json
  if ( iIi1IIii1 == None ) : continue
  if 73 - 73: Ii1I . IiII
  try :
   iIi1IIii1 = json . loads ( iIi1IIii1 . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
   if 90 - 90: i11iIiiIii * i1IIi
  if ( iIi1IIii1 . has_key ( "signature" ) == False ) : continue
  return ( Iii1i1iii )
  if 88 - 88: i11iIiiIii - OoOoOO00
 return ( None )
 if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
 if 6 - 6: iII111i
 if 44 - 44: oO0o
 if 23 - 23: I1IiiI + iIii1I11I1II1 . iII111i + OOooOOo - OoO0O00 + i1IIi
 if 60 - 60: i11iIiiIii + Oo0Ooo * OoOoOO00 . iII111i - iIii1I11I1II1 * IiII
 if 52 - 52: OOooOOo
 if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
 if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
 if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
 if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
 if 66 - 66: I1IiiI
 if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
 if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
 if 22 - 22: I1Ii111
 if 41 - 41: O0 * i1IIi
 if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
 if 5 - 5: I1ii11iIi11i / I1IiiI . iII111i
 if 7 - 7: Ii1I
 if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
def lisp_get_eid_hash ( eid ) :
 O0O0O00 = None
 for iI1iIIiIii1I in lisp_eid_hashes :
  if 56 - 56: I11i
  if 75 - 75: ooOoO0o . oO0o . OoOoOO00
  if 72 - 72: I11i % ooOoO0o / O0 . O0
  if 7 - 7: O0 * I1ii11iIi11i + Ii1I + oO0o % oO0o
  o0ooOo00O = iI1iIIiIii1I . instance_id
  if ( o0ooOo00O == - 1 ) : iI1iIIiIii1I . instance_id = eid . instance_id
  if 47 - 47: oO0o * I1ii11iIi11i
  OoOOoo00ooOoo = eid . is_more_specific ( iI1iIIiIii1I )
  iI1iIIiIii1I . instance_id = o0ooOo00O
  if ( OoOOoo00ooOoo ) :
   O0O0O00 = 128 - iI1iIIiIii1I . mask_len
   break
   if 92 - 92: O0 % I1IiiI / OOooOOo
   if 43 - 43: I11i - I11i
 if ( O0O0O00 == None ) : return ( None )
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 II1i = eid . address
 i1iI1II1i1Ii1 = ""
 for o0Ooo0O00 in range ( 0 , O0O0O00 / 16 ) :
  O0o0O0OO0o = II1i & 0xffff
  O0o0O0OO0o = hex ( O0o0O0OO0o ) [ 2 : - 1 ]
  i1iI1II1i1Ii1 = O0o0O0OO0o . zfill ( 4 ) + ":" + i1iI1II1i1Ii1
  II1i >>= 16
  if 61 - 61: IiII + iII111i
 if ( O0O0O00 % 16 != 0 ) :
  O0o0O0OO0o = II1i & 0xff
  O0o0O0OO0o = hex ( O0o0O0OO0o ) [ 2 : - 1 ]
  i1iI1II1i1Ii1 = O0o0O0OO0o . zfill ( 2 ) + ":" + i1iI1II1i1Ii1
  if 15 - 15: II111iiii / iIii1I11I1II1 / I1ii11iIi11i % OoOoOO00 % OoO0O00 - I1Ii111
 return ( i1iI1II1i1Ii1 [ 0 : - 1 ] )
 if 17 - 17: OoooooooOO
 if 23 - 23: OoO0O00
 if 26 - 26: I11i % IiII . OoooooooOO % i11iIiiIii * IiII
 if 55 - 55: I11i / I11i - IiII - I11i
 if 3 - 3: oO0o % o0oOOo0O0Ooo + OoOoOO00
 if 22 - 22: O0
 if 36 - 36: OOooOOo
 if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
 if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
 if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
 if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
def lisp_lookup_public_key ( eid ) :
 o0ooOo00O = eid . instance_id
 if 79 - 79: oO0o - iII111i
 if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
 if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
 if 39 - 39: O0 . OOooOOo
 if 95 - 95: I11i
 OOOo = lisp_get_eid_hash ( eid )
 if ( OOOo == None ) : return ( [ None , None , False ] )
 if 39 - 39: I11i / O0 - I1ii11iIi11i . Oo0Ooo * OoooooooOO / o0oOOo0O0Ooo
 OOOo = "hash-" + OOOo
 O0OOO00OO0 = lisp_address ( LISP_AFI_NAME , OOOo , len ( OOOo ) , o0ooOo00O )
 oooiiIiIIIi1 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0ooOo00O )
 if 71 - 71: O0 . OoooooooOO + Oo0Ooo . ooOoO0o / Ii1I
 if 92 - 92: I1ii11iIi11i . oO0o
 if 8 - 8: o0oOOo0O0Ooo / oO0o
 if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 OoOoO00OOO0O0 = lisp_site_eid_lookup ( O0OOO00OO0 , oooiiIiIIIi1 , True )
 if ( OoOoO00OOO0O0 == None ) : return ( [ O0OOO00OO0 , None , False ] )
 if 1 - 1: I1ii11iIi11i
 if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
 if 81 - 81: iII111i % IiII / I11i
 if 50 - 50: IiII + i1IIi % I1Ii111
 Ii11IiiI1 = None
 for IiiI11iiI1i1 in OoOoO00OOO0O0 . registered_rlocs :
  oooOoo00OO0O0 = IiiI11iiI1i1 . json
  if ( oooOoo00OO0O0 == None ) : continue
  try :
   oooOoo00OO0O0 = json . loads ( oooOoo00OO0O0 . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( OOOo ) )
   if 27 - 27: iIii1I11I1II1
   return ( [ O0OOO00OO0 , None , False ] )
   if 76 - 76: iII111i
  if ( oooOoo00OO0O0 . has_key ( "public-key" ) == False ) : continue
  Ii11IiiI1 = oooOoo00OO0O0 [ "public-key" ]
  break
  if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
 return ( [ O0OOO00OO0 , Ii11IiiI1 , True ] )
 if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
 if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
 if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
 if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
 if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
 if 32 - 32: I1Ii111
 if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
 if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
 if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
 if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
 if 24 - 24: Ii1I
 if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
 ooOo = json . loads ( rloc_record . json . json_string )
 if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
 if ( lisp_get_eid_hash ( eid ) ) :
  Oo000O00o0O = eid
 elif ( ooOo . has_key ( "signature-eid" ) ) :
  i1iiI11I111I1 = ooOo [ "signature-eid" ]
  Oo000O00o0O = lisp_address ( LISP_AFI_IPV6 , i1iiI11I111I1 , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 65 - 65: o0oOOo0O0Ooo
  if 77 - 77: i1IIi . Oo0Ooo . oO0o + oO0o - i11iIiiIii + I1ii11iIi11i
  if 86 - 86: ooOoO0o . ooOoO0o . OoooooooOO - OoOoOO00 % oO0o
  if 81 - 81: Oo0Ooo . OoooooooOO
  if 15 - 15: I1Ii111 - I11i * I1IiiI % o0oOOo0O0Ooo
 O0OOO00OO0 , Ii11IiiI1 , OO0ooo000oo = lisp_lookup_public_key ( Oo000O00o0O )
 if ( O0OOO00OO0 == None ) :
  o0o0O00 = green ( Oo000O00o0O . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( o0o0O00 ) )
  return ( False )
  if 23 - 23: II111iiii + II111iiii + Ii1I / I11i % I11i
  if 12 - 12: I1Ii111 * O0 + I1ii11iIi11i / ooOoO0o + i11iIiiIii * oO0o
 OOO0O0oOoo = "found" if OO0ooo000oo else bold ( "not found" , False )
 o0o0O00 = green ( O0OOO00OO0 . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( o0o0O00 , OOO0O0oOoo ) )
 if ( OO0ooo000oo == False ) : return ( False )
 if 42 - 42: ooOoO0o
 if ( Ii11IiiI1 == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
  if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
 IiiiIii = Ii11IiiI1 [ 0 : 8 ] + "..." + Ii11IiiI1 [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( IiiiIii ) )
 if 37 - 37: i1IIi . oO0o * o0oOOo0O0Ooo + I1ii11iIi11i - OoO0O00
 if 62 - 62: I11i * oO0o
 if 91 - 91: I1Ii111
 if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
 if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
 O00OiI = ooOo [ "signature" ]
 if 89 - 89: iIii1I11I1II1 . I1IiiI + II111iiii % o0oOOo0O0Ooo
 try :
  ooOo = binascii . a2b_base64 ( O00OiI )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 86 - 86: i11iIiiIii + OoooooooOO
  if 93 - 93: OoO0O00 - iIii1I11I1II1 % iIii1I11I1II1 % Ii1I * Ii1I - OoooooooOO
 O00OoOoo0oo = len ( ooOo )
 if ( O00OoOoo0oo & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( O00OoOoo0oo ) )
  return ( False )
  if 57 - 57: I11i . OoOoOO00 - iIii1I11I1II1 + OOooOOo
  if 7 - 7: i11iIiiIii . OoOoOO00 . OoOoOO00 . ooOoO0o - I1Ii111 / I1IiiI
  if 94 - 94: I1ii11iIi11i * ooOoO0o
  if 12 - 12: Ii1I - OoOoOO00
  if 56 - 56: OOooOOo . oO0o
 OO0o = Oo000O00o0O . print_address ( )
 if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
 if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
 if 8 - 8: OoO0O00 . OOooOOo % I1Ii111 * OOooOOo / I1IiiI
 if 3 - 3: IiII - I1ii11iIi11i . o0oOOo0O0Ooo
 Ii11IiiI1 = binascii . a2b_base64 ( Ii11IiiI1 )
 try :
  OOo0O = ecdsa . VerifyingKey . from_pem ( Ii11IiiI1 )
 except :
  III = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( III ) )
  return ( False )
  if 94 - 94: I1ii11iIi11i - i11iIiiIii + OoooooooOO % I11i / OoO0O00
  if 73 - 73: i11iIiiIii / i1IIi
  if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
  if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
  if 80 - 80: I1Ii111 / O0 * O0
  if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
  if 89 - 89: i11iIiiIii - II111iiii
  if 67 - 67: IiII % I1Ii111 + i11iIiiIii
  if 53 - 53: OOooOOo
  if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
  if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
 try :
  o000o0O = OOo0O . verify ( ooOo , OO0o , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( OO0o ) )
  if 52 - 52: Ii1I * I1ii11iIi11i
  lprint ( "  Signature used '{}'" . format ( O00OiI ) )
  return ( False )
  if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
 return ( o000o0O )
 if 9 - 9: I1ii11iIi11i + I11i
 if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
 if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
 if 4 - 4: OoOoOO00 / OoO0O00
 if 66 - 66: I1Ii111 / OoOoOO00
 if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
 if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
 if 25 - 25: oO0o / oO0o / Ii1I / O0
 if 56 - 56: ooOoO0o
 if 19 - 19: O0 * I1IiiI + I1ii11iIi11i
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 25 - 25: I11i - ooOoO0o / OoO0O00 / iII111i - OoO0O00
 if 86 - 86: OoO0O00
 if 89 - 89: OoooooooOO % iII111i * I1ii11iIi11i + I1ii11iIi11i . Oo0Ooo
 if 4 - 4: I11i
 if 8 - 8: IiII
 i11IiIiii1I1Ii = [ ]
 for OO0 in eid_list :
  for iIIiiiI1iII in lisp_map_notify_queue :
   II11II1 = lisp_map_notify_queue [ iIIiiiI1iII ]
   if ( OO0 not in II11II1 . eid_list ) : continue
   if 8 - 8: oO0o - OoO0O00 * I1Ii111
   i11IiIiii1I1Ii . append ( iIIiiiI1iII )
   i1Ii1iiIII = II11II1 . retransmit_timer
   if ( i1Ii1iiIII ) : i1Ii1iiIII . cancel ( )
   if 53 - 53: II111iiii % i1IIi + ooOoO0o . I1Ii111
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( II11II1 . nonce_key , green ( OO0 , False ) ) )
   if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
   if 27 - 27: Oo0Ooo
   if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
   if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
   if 21 - 21: II111iiii
   if 23 - 23: I11i * i1IIi . oO0o / IiII + o0oOOo0O0Ooo
   if 1 - 1: IiII / OoO0O00 . oO0o * I1Ii111 - i11iIiiIii
 for iIIiiiI1iII in i11IiIiii1I1Ii : lisp_map_notify_queue . pop ( iIIiiiI1iII )
 return
 if 50 - 50: oO0o - O0 / I1IiiI . OoOoOO00 . Oo0Ooo
 if 30 - 30: IiII . OoO0O00 + Oo0Ooo
 if 48 - 48: iIii1I11I1II1 / i11iIiiIii . OoOoOO00 * I11i
 if 1 - 1: IiII . OoOoOO00 * o0oOOo0O0Ooo
 if 63 - 63: O0 / Ii1I + I1Ii111 % OoO0O00 % OOooOOo * O0
 if 35 - 35: OoO0O00 + OoooooooOO % Oo0Ooo / I11i - O0 . i1IIi
 if 76 - 76: IiII % I1IiiI * Ii1I / Ii1I / OoooooooOO + Ii1I
 if 19 - 19: OoooooooOO
def lisp_decrypt_map_register ( packet ) :
 if 88 - 88: I1IiiI % ooOoO0o % Oo0Ooo - O0
 if 71 - 71: OOooOOo % Ii1I - i11iIiiIii - oO0o . ooOoO0o / I1Ii111
 if 53 - 53: iII111i . Oo0Ooo
 if 91 - 91: oO0o * OoooooooOO * oO0o % oO0o * II111iiii % I1Ii111
 if 8 - 8: Ii1I
 Ii1i111iI = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 I1II1 = ( Ii1i111iI >> 13 ) & 0x1
 if ( I1II1 == 0 ) : return ( packet )
 if 48 - 48: IiII + OoOoOO00 % I1Ii111
 II11Ii1i1iiII = ( Ii1i111iI >> 14 ) & 0x7
 if 38 - 38: I1ii11iIi11i + i1IIi % iIii1I11I1II1
 if 96 - 96: OoOoOO00 - OoOoOO00
 if 59 - 59: OoOoOO00 / iII111i * i11iIiiIii
 if 61 - 61: I1Ii111 % oO0o - OOooOOo
 try :
  oOOOOoo0OoOOO = lisp_ms_encryption_keys [ II11Ii1i1iiII ]
  oOOOOoo0OoOOO = oOOOOoo0OoOOO . zfill ( 32 )
  O0o0oOOO = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( II11Ii1i1iiII ) )
  return ( None )
  if 100 - 100: o0oOOo0O0Ooo * OoO0O00 + I1ii11iIi11i
  if 8 - 8: OOooOOo . i11iIiiIii / oO0o % OOooOOo - II111iiii % II111iiii
 iiiii111 = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( iiiii111 , II11Ii1i1iiII ) )
 if 46 - 46: II111iiii + OoOoOO00 % OoO0O00
 Oo00oo0 = chacha . ChaCha ( oOOOOoo0OoOOO , O0o0oOOO ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + Oo00oo0 )
 if 7 - 7: oO0o + II111iiii - O0
 if 32 - 32: oO0o
 if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
 if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
 if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
 if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 94 - 94: Ii1I
 if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
 if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
 if 34 - 34: iIii1I11I1II1
 if 47 - 47: OOooOOo * iII111i
 if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
 I1ii1 = lisp_map_register ( )
 ooOiiIII , packet = I1ii1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 93 - 93: OOooOOo / iIii1I11I1II1 % OoO0O00 + iII111i
 I1ii1 . sport = sport
 if 66 - 66: I1Ii111 + ooOoO0o
 I1ii1 . print_map_register ( )
 if 58 - 58: i1IIi % OoO0O00 % I1IiiI * O0 . Ii1I / OoO0O00
 if 97 - 97: IiII
 if 72 - 72: iII111i * Ii1I * OoO0O00 . i1IIi . O0 - OOooOOo
 if 88 - 88: OoooooooOO / iII111i + i1IIi
 o0o0oOo0O0 = True
 if ( I1ii1 . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  o0o0oOo0O0 = True
  if 42 - 42: I1IiiI + IiII . Ii1I * I11i - o0oOOo0O0Ooo
 if ( I1ii1 . alg_id == LISP_SHA_256_128_ALG_ID ) :
  o0o0oOo0O0 = False
  if 61 - 61: iII111i % I1IiiI * II111iiii % oO0o / OoO0O00 * iII111i
  if 54 - 54: oO0o % ooOoO0o + Ii1I . ooOoO0o % I11i / Ii1I
  if 85 - 85: Ii1I % OoOoOO00
  if 28 - 28: IiII
  if 32 - 32: IiII * II111iiii . Ii1I
 o0ooO = [ ]
 if 67 - 67: oO0o . I1IiiI % i1IIi - OoO0O00
 if 33 - 33: I1IiiI / I1IiiI / I1ii11iIi11i * IiII / Ii1I
 if 55 - 55: i11iIiiIii / OoooooooOO - Ii1I * Oo0Ooo . I1Ii111
 if 96 - 96: IiII / OoooooooOO + i11iIiiIii . Ii1I
 OoO0 = None
 I1II1111iI = packet
 iIi1iiIiiII1I = [ ]
 oO0oooO = I1ii1 . record_count
 for o0Ooo0O00 in range ( oO0oooO ) :
  o00o = lisp_eid_record ( )
  Iii1i1iii = lisp_rloc_record ( )
  packet = o00o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 36 - 36: I1Ii111 + o0oOOo0O0Ooo % IiII
  o00o . print_record ( "  " , False )
  if 68 - 68: I11i + i1IIi % OoooooooOO + OOooOOo
  if 8 - 8: Oo0Ooo + IiII - II111iiii % Ii1I
  if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
  if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
  OoOoO00OOO0O0 = lisp_site_eid_lookup ( o00o . eid , o00o . group ,
 False )
  if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
  ooOO00o = OoOoO00OOO0O0 . print_eid_tuple ( ) if OoOoO00OOO0O0 else None
  if 100 - 100: iIii1I11I1II1 / oO0o
  if 26 - 26: OOooOOo / iIii1I11I1II1 / I1Ii111 + I11i - O0 . O0
  if 20 - 20: oO0o * O0 * Oo0Ooo
  if 81 - 81: OoO0O00 . ooOoO0o
  if 78 - 78: II111iiii - i11iIiiIii . OOooOOo
  if 22 - 22: Oo0Ooo + ooOoO0o
  if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
  if ( OoOoO00OOO0O0 and OoOoO00OOO0O0 . accept_more_specifics == False ) :
   if ( OoOoO00OOO0O0 . eid_record_matches ( o00o ) == False ) :
    IiiIIi111i1 = OoOoO00OOO0O0 . parent_for_more_specifics
    if ( IiiIIi111i1 ) : OoOoO00OOO0O0 = IiiIIi111i1
    if 55 - 55: II111iiii
    if 56 - 56: OoOoOO00 . IiII / iII111i / II111iiii
    if 29 - 29: Oo0Ooo
    if 80 - 80: OoOoOO00
    if 65 - 65: o0oOOo0O0Ooo + O0 - iIii1I11I1II1
    if 12 - 12: OoooooooOO
    if 61 - 61: oO0o / o0oOOo0O0Ooo * iIii1I11I1II1 . O0
    if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
  oO00oO = ( OoOoO00OOO0O0 and OoOoO00OOO0O0 . accept_more_specifics )
  if ( oO00oO ) :
   o0oOOo000 = lisp_site_eid ( OoOoO00OOO0O0 . site )
   o0oOOo000 . dynamic = True
   o0oOOo000 . eid . copy_address ( o00o . eid )
   o0oOOo000 . group . copy_address ( o00o . group )
   o0oOOo000 . parent_for_more_specifics = OoOoO00OOO0O0
   o0oOOo000 . add_cache ( )
   o0oOOo000 . inherit_from_ams_parent ( )
   OoOoO00OOO0O0 . more_specific_registrations . append ( o0oOOo000 )
   OoOoO00OOO0O0 = o0oOOo000
  else :
   OoOoO00OOO0O0 = lisp_site_eid_lookup ( o00o . eid , o00o . group ,
 True )
   if 72 - 72: I11i - o0oOOo0O0Ooo * IiII - I1IiiI
   if 22 - 22: i11iIiiIii
  o0o0O00 = o00o . print_eid_tuple ( )
  if 32 - 32: i1IIi / II111iiii
  if ( OoOoO00OOO0O0 == None ) :
   II1ii1IIi1i = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( II1ii1IIi1i , green ( o0o0O00 , False ) ,
 ", matched non-ams {}" . format ( green ( ooOO00o , False ) if ooOO00o else "" ) ) )
   if 82 - 82: iII111i % i11iIiiIii
   if 16 - 16: I1IiiI + i1IIi + oO0o % Ii1I % OoO0O00 . o0oOOo0O0Ooo
   if 35 - 35: IiII
   if 15 - 15: OoooooooOO / o0oOOo0O0Ooo % iII111i . Oo0Ooo / i1IIi / i11iIiiIii
   if 77 - 77: I1Ii111
   packet = Iii1i1iii . end_of_rlocs ( packet , o00o . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 92 - 92: iII111i * i11iIiiIii * o0oOOo0O0Ooo * OoO0O00
   continue
   if 70 - 70: Ii1I
   if 51 - 51: i1IIi % Oo0Ooo
  OoO0 = OoOoO00OOO0O0 . site
  if 32 - 32: OoOoOO00 + iIii1I11I1II1 . OoO0O00 . I1ii11iIi11i . IiII
  if ( oO00oO ) :
   IIIII1iii11 = OoOoO00OOO0O0 . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( IIIII1iii11 , False ) , OoO0 . site_name , green ( o0o0O00 , False ) ) )
   if 97 - 97: ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + iII111i + OoOoOO00
  else :
   IIIII1iii11 = green ( OoOoO00OOO0O0 . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( IIIII1iii11 , OoO0 . site_name , green ( o0o0O00 , False ) ) )
   if 8 - 8: Oo0Ooo . oO0o + II111iiii
   if 100 - 100: OoOoOO00 . IiII / OoO0O00 * OoooooooOO - OoOoOO00
   if 98 - 98: OoO0O00 / I1ii11iIi11i + I1ii11iIi11i
   if 70 - 70: i1IIi % Oo0Ooo % I1Ii111 + I11i . ooOoO0o
   if 66 - 66: i11iIiiIii % I11i / Oo0Ooo * oO0o
   if 7 - 7: O0 - Ii1I - oO0o
  if ( OoO0 . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( OoO0 . site_name ) )
   packet = Iii1i1iii . end_of_rlocs ( packet , o00o . rloc_count )
   continue
   if 95 - 95: i1IIi - OOooOOo / OoOoOO00 + I1ii11iIi11i + O0
   if 10 - 10: ooOoO0o - OOooOOo + i1IIi * Ii1I
   if 78 - 78: iIii1I11I1II1
   if 76 - 76: ooOoO0o - i11iIiiIii * I11i / I1IiiI - OOooOOo
   if 41 - 41: iII111i
   if 91 - 91: I1Ii111
   if 54 - 54: o0oOOo0O0Ooo . i1IIi / iII111i
   if 21 - 21: O0 + ooOoO0o
  IiIiIi1I1 = I1ii1 . key_id
  if ( OoO0 . auth_key . has_key ( IiIiIi1I1 ) == False ) : IiIiIi1I1 = 0
  o00oo0o0O = OoO0 . auth_key [ IiIiIi1I1 ]
  if 15 - 15: II111iiii + OoO0O00 . iIii1I11I1II1 + iIii1I11I1II1 - o0oOOo0O0Ooo
  O0OOo0oo = lisp_verify_auth ( ooOiiIII , I1ii1 . alg_id ,
 I1ii1 . auth_data , o00oo0o0O )
  II1i1i = "dynamic " if OoOoO00OOO0O0 . dynamic else ""
  if 53 - 53: Ii1I
  i1IiIii1i = bold ( "passed" if O0OOo0oo else "failed" , False )
  IiIiIi1I1 = "key-id {}" . format ( IiIiIi1I1 ) if IiIiIi1I1 == I1ii1 . key_id else "bad key-id {}" . format ( I1ii1 . key_id )
  if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( i1IiIii1i , II1i1i , green ( o0o0O00 , False ) , IiIiIi1I1 ) )
  if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
  if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
  if 33 - 33: oO0o . oO0o / IiII + II111iiii
  if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
  if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
  if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
  i1iiii1 = True
  o0O = ( lisp_get_eid_hash ( o00o . eid ) != None )
  if ( o0O or OoOoO00OOO0O0 . require_signature ) :
   IiiI1i1Ii1 = "Required " if OoOoO00OOO0O0 . require_signature else ""
   o0o0O00 = green ( o0o0O00 , False )
   IiiI11iiI1i1 = lisp_find_sig_in_rloc_set ( packet , o00o . rloc_count )
   if ( IiiI11iiI1i1 == None ) :
    i1iiii1 = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( IiiI1i1Ii1 ,
    # iIii1I11I1II1 % iIii1I11I1II1 + OoOoOO00 + I1IiiI . oO0o
 bold ( "failed" , False ) , o0o0O00 ) )
   else :
    i1iiii1 = lisp_verify_cga_sig ( o00o . eid , IiiI11iiI1i1 )
    i1IiIii1i = bold ( "passed" if i1iiii1 else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( IiiI1i1Ii1 , i1IiIii1i , o0o0O00 ) )
    if 100 - 100: i11iIiiIii * I1ii11iIi11i
    if 69 - 69: I1Ii111 + II111iiii
    if 92 - 92: OoooooooOO
    if 80 - 80: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . oO0o % I1IiiI % I11i
  if ( O0OOo0oo == False or i1iiii1 == False ) :
   packet = Iii1i1iii . end_of_rlocs ( packet , o00o . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 4 - 4: OoO0O00 / iII111i / I1ii11iIi11i - o0oOOo0O0Ooo * I1Ii111
   continue
   if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
   if 2 - 2: I1IiiI . o0oOOo0O0Ooo / Oo0Ooo - OoOoOO00 - OoooooooOO
   if 73 - 73: I1Ii111 . i11iIiiIii * ooOoO0o . IiII - I11i + I1Ii111
   if 21 - 21: I1Ii111 + iIii1I11I1II1 + I1IiiI / O0 * I1ii11iIi11i
   if 57 - 57: OOooOOo * I11i . oO0o
   if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
  if ( I1ii1 . merge_register_requested ) :
   IiiIIi111i1 = OoOoO00OOO0O0
   IiiIIi111i1 . inconsistent_registration = False
   if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
   if 27 - 27: O0 - iIii1I11I1II1
   if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
   if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
   if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
   if ( OoOoO00OOO0O0 . group . is_null ( ) ) :
    if ( IiiIIi111i1 . site_id != I1ii1 . site_id ) :
     IiiIIi111i1 . site_id = I1ii1 . site_id
     IiiIIi111i1 . registered = False
     IiiIIi111i1 . individual_registrations = { }
     IiiIIi111i1 . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
     if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
     if 17 - 17: I1IiiI % I11i
   OOo0O = source . address + I1ii1 . xtr_id
   if ( OoOoO00OOO0O0 . individual_registrations . has_key ( OOo0O ) ) :
    OoOoO00OOO0O0 = OoOoO00OOO0O0 . individual_registrations [ OOo0O ]
   else :
    OoOoO00OOO0O0 = lisp_site_eid ( OoO0 )
    OoOoO00OOO0O0 . eid . copy_address ( IiiIIi111i1 . eid )
    OoOoO00OOO0O0 . group . copy_address ( IiiIIi111i1 . group )
    IiiIIi111i1 . individual_registrations [ OOo0O ] = OoOoO00OOO0O0
    if 28 - 28: I1ii11iIi11i * OoooooooOO
  else :
   OoOoO00OOO0O0 . inconsistent_registration = OoOoO00OOO0O0 . merge_register_requested
   if 19 - 19: Oo0Ooo - iII111i % OoOoOO00 * i11iIiiIii / oO0o . i11iIiiIii
   if 46 - 46: I1ii11iIi11i
   if 50 - 50: OOooOOo * OoO0O00 * OOooOOo % I1IiiI - I1Ii111 * Ii1I
  OoOoO00OOO0O0 . map_registers_received += 1
  if 88 - 88: OOooOOo . iII111i / I11i
  if 1 - 1: iIii1I11I1II1 - Oo0Ooo % OoooooooOO
  if 71 - 71: OOooOOo - Ii1I
  if 68 - 68: ooOoO0o
  if 35 - 35: IiII . iIii1I11I1II1 + Ii1I % O0
  III = ( OoOoO00OOO0O0 . is_rloc_in_rloc_set ( source ) == False )
  if ( o00o . record_ttl == 0 and III ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 94 - 94: OoOoOO00 + II111iiii . II111iiii + ooOoO0o + ooOoO0o
   continue
   if 95 - 95: iIii1I11I1II1 / i11iIiiIii - IiII - OOooOOo
   if 4 - 4: II111iiii + oO0o + o0oOOo0O0Ooo % IiII % iIii1I11I1II1
   if 68 - 68: i11iIiiIii
   if 79 - 79: OoOoOO00 * Ii1I / I1ii11iIi11i + OOooOOo
   if 19 - 19: I1IiiI + I11i + I1IiiI + OoO0O00
   if 33 - 33: i11iIiiIii - Ii1I * II111iiii
  oO0O = OoOoO00OOO0O0 . registered_rlocs
  OoOoO00OOO0O0 . registered_rlocs = [ ]
  if 12 - 12: O0
  if 35 - 35: I1IiiI - i1IIi
  if 29 - 29: I1ii11iIi11i + ooOoO0o - OoOoOO00 / II111iiii
  if 12 - 12: I1IiiI + i1IIi % i11iIiiIii / I1IiiI - iIii1I11I1II1
  iiII1I = packet
  for OOOO00o00o0 in range ( o00o . rloc_count ) :
   Iii1i1iii = lisp_rloc_record ( )
   packet = Iii1i1iii . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 35 - 35: I1ii11iIi11i . OOooOOo * I1Ii111 / OoooooooOO
   Iii1i1iii . print_record ( "    " )
   if 8 - 8: ooOoO0o + O0 + IiII - Oo0Ooo % OOooOOo
   if 47 - 47: O0 / oO0o / I1ii11iIi11i . OoooooooOO / II111iiii . OOooOOo
   if 58 - 58: oO0o / ooOoO0o
   if 31 - 31: o0oOOo0O0Ooo % I11i - OoO0O00
   if ( len ( OoO0 . allowed_rlocs ) > 0 ) :
    O0o = Iii1i1iii . rloc . print_address ( )
    if ( OoO0 . allowed_rlocs . has_key ( O0o ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( O0o , False ) ) )
     if 40 - 40: o0oOOo0O0Ooo % OoOoOO00 + I11i / O0 - II111iiii
     if 9 - 9: OoooooooOO - OOooOOo . I11i * oO0o
     OoOoO00OOO0O0 . registered = False
     packet = Iii1i1iii . end_of_rlocs ( packet ,
 o00o . rloc_count - OOOO00o00o0 - 1 )
     break
     if 3 - 3: iIii1I11I1II1 - OoO0O00
     if 38 - 38: O0 + ooOoO0o * I1Ii111 - oO0o * o0oOOo0O0Ooo
     if 97 - 97: Oo0Ooo - O0 * OoooooooOO
     if 52 - 52: i1IIi + IiII
     if 11 - 11: I1IiiI % iIii1I11I1II1 * Ii1I % ooOoO0o
     if 33 - 33: iII111i / O0 % II111iiii % OoOoOO00 / I1Ii111
   IiiI11iiI1i1 = lisp_rloc ( )
   IiiI11iiI1i1 . store_rloc_from_record ( Iii1i1iii , None , source )
   if 77 - 77: OoOoOO00 % I1IiiI % II111iiii * iII111i . OoOoOO00 / O0
   if 21 - 21: ooOoO0o - I11i . i11iIiiIii
   if 39 - 39: Oo0Ooo * II111iiii % OOooOOo / oO0o . ooOoO0o
   if 75 - 75: I11i / O0 + OoooooooOO + OOooOOo % iII111i + I1IiiI
   if 10 - 10: II111iiii * I11i - IiII * iIii1I11I1II1 . OoooooooOO
   if 39 - 39: I11i . I1IiiI % Oo0Ooo + oO0o
   if ( source . is_exact_match ( IiiI11iiI1i1 . rloc ) ) :
    IiiI11iiI1i1 . map_notify_requested = I1ii1 . map_notify_requested
    if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
    if 82 - 82: IiII % ooOoO0o
    if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
    if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
    if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
   OoOoO00OOO0O0 . registered_rlocs . append ( IiiI11iiI1i1 )
   if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
   if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
  Ii1iI1 = ( OoOoO00OOO0O0 . do_rloc_sets_match ( oO0O ) == False )
  if 35 - 35: oO0o - ooOoO0o
  if 4 - 4: Oo0Ooo - IiII - I11i
  if 72 - 72: OoooooooOO
  if 19 - 19: Oo0Ooo . OOooOOo
  if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
  if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
  if ( I1ii1 . map_register_refresh and Ii1iI1 and
 OoOoO00OOO0O0 . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   OoOoO00OOO0O0 . registered_rlocs = oO0O
   continue
   if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
   if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
   if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
   if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
   if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
   if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
  if ( OoOoO00OOO0O0 . registered == False ) :
   OoOoO00OOO0O0 . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 24 - 24: OoOoOO00
  OoOoO00OOO0O0 . last_registered = lisp_get_timestamp ( )
  OoOoO00OOO0O0 . registered = ( o00o . record_ttl != 0 )
  OoOoO00OOO0O0 . last_registerer = source
  if 19 - 19: ooOoO0o
  if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
  if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
  if 7 - 7: OoooooooOO - I1Ii111 * IiII
  OoOoO00OOO0O0 . auth_sha1_or_sha2 = o0o0oOo0O0
  OoOoO00OOO0O0 . proxy_reply_requested = I1ii1 . proxy_reply_requested
  OoOoO00OOO0O0 . lisp_sec_present = I1ii1 . lisp_sec_present
  OoOoO00OOO0O0 . map_notify_requested = I1ii1 . map_notify_requested
  OoOoO00OOO0O0 . mobile_node_requested = I1ii1 . mobile_node
  OoOoO00OOO0O0 . merge_register_requested = I1ii1 . merge_register_requested
  if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
  OoOoO00OOO0O0 . use_register_ttl_requested = I1ii1 . use_ttl_for_timeout
  if ( OoOoO00OOO0O0 . use_register_ttl_requested ) :
   OoOoO00OOO0O0 . register_ttl = o00o . store_ttl ( )
  else :
   OoOoO00OOO0O0 . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
  OoOoO00OOO0O0 . xtr_id_present = I1ii1 . xtr_id_present
  if ( OoOoO00OOO0O0 . xtr_id_present ) :
   OoOoO00OOO0O0 . xtr_id = I1ii1 . xtr_id
   OoOoO00OOO0O0 . site_id = I1ii1 . site_id
   if 8 - 8: OoooooooOO * ooOoO0o
   if 26 - 26: i11iIiiIii + oO0o - i1IIi
   if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
   if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
   if 37 - 37: iII111i % I1IiiI - I1ii11iIi11i % I11i
  if ( I1ii1 . merge_register_requested ) :
   if ( IiiIIi111i1 . merge_in_site_eid ( OoOoO00OOO0O0 ) ) :
    o0ooO . append ( [ o00o . eid , o00o . group ] )
    if 35 - 35: O0 - OoooooooOO % iII111i
   if ( I1ii1 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , IiiIIi111i1 , I1ii1 ,
 o00o )
    if 48 - 48: OOooOOo % i11iIiiIii
    if 49 - 49: O0 * iII111i + II111iiii - OOooOOo
    if 29 - 29: OoooooooOO % II111iiii - Oo0Ooo / IiII - i11iIiiIii
  if ( Ii1iI1 == False ) : continue
  if ( len ( o0ooO ) != 0 ) : continue
  if 64 - 64: iII111i . I1Ii111 + I1Ii111
  iIi1iiIiiII1I . append ( OoOoO00OOO0O0 . print_eid_tuple ( ) )
  if 1 - 1: OOooOOo % Oo0Ooo
  if 81 - 81: oO0o / I11i % Ii1I . I11i + OoooooooOO
  if 31 - 31: OoO0O00
  if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
  if 5 - 5: OoOoOO00 + i1IIi
  if 43 - 43: iII111i * I1IiiI
  if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
  o00o = o00o . encode ( )
  o00o += iiII1I
  OOOi1i = [ OoOoO00OOO0O0 . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
  for IiiI11iiI1i1 in oO0O :
   if ( IiiI11iiI1i1 . map_notify_requested == False ) : continue
   if ( IiiI11iiI1i1 . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , o00o , OOOi1i , 1 , IiiI11iiI1i1 . rloc ,
 LISP_CTRL_PORT , I1ii1 . nonce , I1ii1 . key_id ,
 I1ii1 . alg_id , I1ii1 . auth_len , OoO0 , False )
   if 20 - 20: oO0o
   if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
   if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
   if 87 - 87: ooOoO0o
   if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
  lisp_notify_subscribers ( lisp_sockets , o00o , OoOoO00OOO0O0 . eid , OoO0 )
  if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
  if 26 - 26: O0
  if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
  if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
  if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
 if ( len ( o0ooO ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , o0ooO )
  if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
  if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
  if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
  if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
  if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
  if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
 if ( I1ii1 . merge_register_requested ) : return
 if 77 - 77: i11iIiiIii / OOooOOo
 if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
 if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
 if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
 if ( I1ii1 . map_notify_requested and OoO0 != None ) :
  lisp_build_map_notify ( lisp_sockets , I1II1111iI , iIi1iiIiiII1I ,
 I1ii1 . record_count , source , sport , I1ii1 . nonce ,
 I1ii1 . key_id , I1ii1 . alg_id , I1ii1 . auth_len ,
 OoO0 , True )
  if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
 return
 if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
 if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
 if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
 if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
 if 83 - 83: O0 . I1Ii111 % I1ii11iIi11i
 if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
 if 12 - 12: ooOoO0o
 if 56 - 56: i1IIi
 if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
 if 53 - 53: i1IIi % I1ii11iIi11i
def lisp_process_multicast_map_notify ( packet , source ) :
 II11II1 = lisp_map_notify ( "" )
 packet = II11II1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
  if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
 II11II1 . print_notify ( )
 if ( II11II1 . record_count == 0 ) : return
 if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
 IIi1I1 = II11II1 . eid_records
 if 78 - 78: OoO0O00 / Oo0Ooo + I1ii11iIi11i % I1ii11iIi11i % OoO0O00 * O0
 for o0Ooo0O00 in range ( II11II1 . record_count ) :
  o00o = lisp_eid_record ( )
  IIi1I1 = o00o . decode ( IIi1I1 )
  if ( packet == None ) : return
  o00o . print_record ( "  " , False )
  if 12 - 12: IiII . IiII / OoOoOO00 / II111iiii
  if 2 - 2: I1Ii111
  if 45 - 45: OOooOOo * ooOoO0o
  if 77 - 77: i11iIiiIii / OOooOOo % i11iIiiIii
  IIo0OooOO = lisp_map_cache_lookup ( o00o . eid , o00o . group )
  if ( IIo0OooOO == None ) :
   IIo0OooOO = lisp_mapping ( o00o . eid , o00o . group , [ ] )
   IIo0OooOO . add_cache ( )
   if 19 - 19: OoooooooOO - I1IiiI * OoO0O00
   if 65 - 65: OoooooooOO . I11i / I1ii11iIi11i / i11iIiiIii
  IIo0OooOO . mapping_source = None if source == "lisp-etr" else source
  IIo0OooOO . map_cache_ttl = o00o . store_ttl ( )
  if 20 - 20: OoOoOO00 / OoO0O00 - Oo0Ooo + ooOoO0o
  if 86 - 86: O0 / II111iiii / ooOoO0o % I1ii11iIi11i / iIii1I11I1II1
  if 1 - 1: O0
  if 55 - 55: i1IIi % IiII - i1IIi . IiII . o0oOOo0O0Ooo
  if 85 - 85: Ii1I . i11iIiiIii
  if ( len ( IIo0OooOO . rloc_set ) != 0 and o00o . rloc_count == 0 ) :
   IIo0OooOO . rloc_set = [ ]
   IIo0OooOO . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , IIo0OooOO )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( IIo0OooOO . print_eid_tuple ( ) , False ) ) )
   if 69 - 69: OoOoOO00
   continue
   if 49 - 49: Oo0Ooo % Oo0Ooo * OoOoOO00 - Oo0Ooo
   if 32 - 32: i1IIi . I11i - IiII % OoO0O00 % iIii1I11I1II1 - OoooooooOO
  IIiiI1i = IIo0OooOO . rtrs_in_rloc_set ( )
  if 73 - 73: iII111i
  if 53 - 53: Oo0Ooo % I1IiiI
  if 15 - 15: o0oOOo0O0Ooo
  if 32 - 32: I1Ii111 % oO0o * iII111i * OOooOOo
  if 45 - 45: oO0o / O0
  for OOOO00o00o0 in range ( o00o . rloc_count ) :
   Iii1i1iii = lisp_rloc_record ( )
   IIi1I1 = Iii1i1iii . decode ( IIi1I1 , None )
   Iii1i1iii . print_record ( "    " )
   if ( o00o . group . is_null ( ) ) : continue
   if ( Iii1i1iii . rle == None ) : continue
   if 5 - 5: OoO0O00 / O0
   if 64 - 64: I11i / i1IIi
   if 68 - 68: Ii1I / oO0o - iII111i
   if 52 - 52: I11i / OoO0O00 - Ii1I
   if 11 - 11: OoooooooOO - i11iIiiIii - I1ii11iIi11i / o0oOOo0O0Ooo - Ii1I
   i1ii11 = IIo0OooOO . rloc_set [ 0 ] . stats if len ( IIo0OooOO . rloc_set ) != 0 else None
   if 12 - 12: I11i + I1Ii111 % O0 + IiII + IiII
   if 51 - 51: OoooooooOO - I11i / Oo0Ooo * iIii1I11I1II1
   if 58 - 58: I11i / oO0o * II111iiii / I1IiiI
   if 69 - 69: OoooooooOO - OoooooooOO * ooOoO0o / oO0o * iIii1I11I1II1 . II111iiii
   IiiI11iiI1i1 = lisp_rloc ( )
   IiiI11iiI1i1 . store_rloc_from_record ( Iii1i1iii , None , IIo0OooOO . mapping_source )
   if ( i1ii11 != None ) : IiiI11iiI1i1 . stats = copy . deepcopy ( i1ii11 )
   if 61 - 61: oO0o . I1IiiI + i1IIi
   if ( IIiiI1i and IiiI11iiI1i1 . is_rtr ( ) == False ) : continue
   if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
   IIo0OooOO . rloc_set = [ IiiI11iiI1i1 ]
   IIo0OooOO . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , IIo0OooOO )
   if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( IIo0OooOO . print_eid_tuple ( ) , False ) , IiiI11iiI1i1 . rle . print_rle ( False ) ) )
   if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
   if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
   if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
 return
 if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
 if 75 - 75: oO0o * Oo0Ooo * O0
 if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
 if 62 - 62: oO0o % Ii1I - Ii1I
 if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
 if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
 if 9 - 9: I11i . I11i . OoooooooOO
 if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 II11II1 = lisp_map_notify ( "" )
 oOo0O000oo0 = II11II1 . decode ( orig_packet )
 if ( oOo0O000oo0 == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
  if 12 - 12: IiII / Ii1I
 II11II1 . print_notify ( )
 if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
 if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
 if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
 if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
 if 71 - 71: Ii1I - IiII
 i11I1 = source . print_address ( )
 if ( II11II1 . alg_id != 0 or II11II1 . auth_len != 0 ) :
  OoOOoo00ooOoo = None
  for OOo0O in lisp_map_servers_list :
   if ( OOo0O . find ( i11I1 ) == - 1 ) : continue
   OoOOoo00ooOoo = lisp_map_servers_list [ OOo0O ]
   if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
  if ( OoOOoo00ooOoo == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( i11I1 ) )
   if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
   return
   if 65 - 65: iII111i . oO0o
   if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
  OoOOoo00ooOoo . map_notifies_received += 1
  if 31 - 31: I11i - oO0o * ooOoO0o
  O0OOo0oo = lisp_verify_auth ( oOo0O000oo0 , II11II1 . alg_id ,
 II11II1 . auth_data , OoOOoo00ooOoo . password )
  if 64 - 64: I11i
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if O0OOo0oo else "failed" ) )
  if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
  if ( O0OOo0oo == False ) : return
 else :
  OoOOoo00ooOoo = lisp_ms ( i11I1 , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
  if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
  if 43 - 43: Oo0Ooo % I11i
  if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
  if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
  if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
 IIi1I1 = II11II1 . eid_records
 if ( II11II1 . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , IIi1I1 , II11II1 , OoOOoo00ooOoo )
  return
  if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
  if 26 - 26: OoOoOO00 * IiII
  if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
  if 46 - 46: OoOoOO00
  if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
  if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
  if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
  if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
 o00o = lisp_eid_record ( )
 oOo0O000oo0 = o00o . decode ( IIi1I1 )
 if ( oOo0O000oo0 == None ) : return
 if 20 - 20: IiII
 o00o . print_record ( "  " , False )
 if 81 - 81: Oo0Ooo / I1Ii111
 for OOOO00o00o0 in range ( o00o . rloc_count ) :
  Iii1i1iii = lisp_rloc_record ( )
  oOo0O000oo0 = Iii1i1iii . decode ( oOo0O000oo0 , None )
  if ( oOo0O000oo0 == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
  Iii1i1iii . print_record ( "    " )
  if 51 - 51: iII111i - ooOoO0o
  if 32 - 32: IiII - i11iIiiIii
  if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
  if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
  if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
 if ( o00o . group . is_null ( ) == False ) :
  if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
  if 37 - 37: OOooOOo
  if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
  if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
  if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( o00o . print_eid_tuple ( ) , False ) ) )
  if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
  if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
  O0oO00o0o0oo0 = lisp_control_packet_ipc ( orig_packet , i11I1 , "lisp-itr" , 0 )
  lisp_ipc ( O0oO00o0o0oo0 , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
  if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
  if 22 - 22: ooOoO0o - OOooOOo
  if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
  if 20 - 20: ooOoO0o - i11iIiiIii
 lisp_send_map_notify_ack ( lisp_sockets , IIi1I1 , II11II1 , OoOOoo00ooOoo )
 return
 if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
 if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
 if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
 if 29 - 29: oO0o
 if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
 if 78 - 78: Oo0Ooo
 if 77 - 77: oO0o % Oo0Ooo % O0
 if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
def lisp_process_map_notify_ack ( packet , source ) :
 II11II1 = lisp_map_notify ( "" )
 packet = II11II1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
  if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
 II11II1 . print_notify ( )
 if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
 if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
 if 88 - 88: ooOoO0o
 if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
 if 20 - 20: i11iIiiIii * I11i
 if ( II11II1 . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 29 - 29: IiII / OOooOOo
  if 39 - 39: O0 + II111iiii
 o00o = lisp_eid_record ( )
 if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
 if ( o00o . decode ( II11II1 . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
 o00o . print_record ( "  " , False )
 if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
 o0o0O00 = o00o . print_eid_tuple ( )
 if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
 if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
 if 91 - 91: oO0o - ooOoO0o
 if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
 if ( II11II1 . alg_id != LISP_NONE_ALG_ID and II11II1 . auth_len != 0 ) :
  OoOoO00OOO0O0 = lisp_sites_by_eid . lookup_cache ( o00o . eid , True )
  if ( OoOoO00OOO0O0 == None ) :
   II1ii1IIi1i = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( II1ii1IIi1i , green ( o0o0O00 , False ) ) )
   if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
   return
   if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
  OoO0 = OoOoO00OOO0O0 . site
  if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
  if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
  if 38 - 38: I1ii11iIi11i - Ii1I % OoooooooOO
  if 43 - 43: iIii1I11I1II1 / OoOoOO00
  OoO0 . map_notify_acks_received += 1
  if 13 - 13: o0oOOo0O0Ooo / I1Ii111
  IiIiIi1I1 = II11II1 . key_id
  if ( OoO0 . auth_key . has_key ( IiIiIi1I1 ) == False ) : IiIiIi1I1 = 0
  o00oo0o0O = OoO0 . auth_key [ IiIiIi1I1 ]
  if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
  O0OOo0oo = lisp_verify_auth ( packet , II11II1 . alg_id ,
 II11II1 . auth_data , o00oo0o0O )
  if 32 - 32: oO0o
  IiIiIi1I1 = "key-id {}" . format ( IiIiIi1I1 ) if IiIiIi1I1 == II11II1 . key_id else "bad key-id {}" . format ( II11II1 . key_id )
  if 72 - 72: I1IiiI
  if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if O0OOo0oo else "failed" , IiIiIi1I1 ) )
  if 87 - 87: Oo0Ooo
  if ( O0OOo0oo == False ) : return
  if 7 - 7: iIii1I11I1II1
  if 85 - 85: iIii1I11I1II1 . O0
  if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
  if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
  if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
 if ( II11II1 . retransmit_timer ) : II11II1 . retransmit_timer . cancel ( )
 if 8 - 8: OoO0O00 . OoO0O00
 IIiiiIiii = source . print_address ( )
 OOo0O = II11II1 . nonce_key
 if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
 if ( lisp_map_notify_queue . has_key ( OOo0O ) ) :
  II11II1 = lisp_map_notify_queue . pop ( OOo0O )
  if ( II11II1 . retransmit_timer ) : II11II1 . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( OOo0O ) )
  if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( II11II1 . nonce_key , red ( IIiiiIiii , False ) ) )
  if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
  if 24 - 24: IiII
 return
 if 95 - 95: IiII + OoOoOO00 * OOooOOo
 if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
 if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
 if 41 - 41: i1IIi / IiII
 if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
 if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
 if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
 if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
 if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
 if 13 - 13: oO0o + IiII
 if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
 Oo000ooO = False
 if ( group . is_null ( ) == False ) :
  Oo000ooO = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
 if ( Oo000ooO == False ) :
  Oo000ooO = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
 if ( Oo000ooO ) :
  Oo00 = lisp_print_eid_tuple ( eid , group )
  Iiii1IIIii = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 83 - 83: o0oOOo0O0Ooo % oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( Oo00 , False ) , s ,
  # I11i * I11i + OoooooooOO * Oo0Ooo / I11i . i11iIiiIii
 Iiii1IIIii ) )
  if 90 - 90: OOooOOo - I1IiiI % o0oOOo0O0Ooo
 return ( Oo000ooO )
 if 26 - 26: Oo0Ooo . II111iiii - I11i . Ii1I % OOooOOo
 if 4 - 4: I11i + I1Ii111 / i1IIi + OoooooooOO
 if 84 - 84: ooOoO0o
 if 47 - 47: Oo0Ooo
 if 60 - 60: i11iIiiIii - o0oOOo0O0Ooo
 if 36 - 36: II111iiii
 if 80 - 80: i11iIiiIii / iII111i
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 91 - 91: i11iIiiIii % OoOoOO00
 III1II1II1 = lisp_map_referral ( )
 packet = III1II1II1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 17 - 17: OoOoOO00
 III1II1II1 . print_map_referral ( )
 if 62 - 62: I1Ii111 * I11i - II111iiii + Oo0Ooo - Ii1I . ooOoO0o
 i11I1 = source . print_address ( )
 OoI1 = III1II1II1 . nonce
 if 70 - 70: OoOoOO00 * o0oOOo0O0Ooo / IiII
 if 6 - 6: iII111i
 if 4 - 4: I1ii11iIi11i % o0oOOo0O0Ooo * Oo0Ooo
 if 97 - 97: OoOoOO00
 for o0Ooo0O00 in range ( III1II1II1 . record_count ) :
  o00o = lisp_eid_record ( )
  packet = o00o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 34 - 34: iII111i % Oo0Ooo
  o00o . print_record ( "  " , True )
  if 25 - 25: OOooOOo / Oo0Ooo
  if 26 - 26: iII111i
  if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
  if 6 - 6: IiII
  OOo0O = str ( OoI1 )
  if ( OOo0O not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( OoI1 ) , i11I1 ) )
   if 68 - 68: Oo0Ooo
   if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
   continue
   if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
  IIiII11I1I111 = lisp_ddt_map_requestQ [ OOo0O ]
  if ( IIiII11I1I111 == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( OoI1 ) , i11I1 ) )
   if 93 - 93: i11iIiiIii
   continue
   if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
   if 40 - 40: IiII % IiII
   if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
   if 8 - 8: iII111i
   if 51 - 51: I1IiiI
   if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
  if ( lisp_map_referral_loop ( IIiII11I1I111 , o00o . eid , o00o . group ,
 o00o . action , i11I1 ) ) :
   IIiII11I1I111 . dequeue_map_request ( )
   continue
   if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
   if 68 - 68: OOooOOo
  IIiII11I1I111 . last_cached_prefix [ 0 ] = o00o . eid
  IIiII11I1I111 . last_cached_prefix [ 1 ] = o00o . group
  if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
  if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
  if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
  if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
  IIiII = False
  OoIi11IIiiI1I = lisp_referral_cache_lookup ( o00o . eid , o00o . group ,
 True )
  if ( OoIi11IIiiI1I == None ) :
   IIiII = True
   OoIi11IIiiI1I = lisp_referral ( )
   OoIi11IIiiI1I . eid = o00o . eid
   OoIi11IIiiI1I . group = o00o . group
   if ( o00o . ddt_incomplete == False ) : OoIi11IIiiI1I . add_cache ( )
  elif ( OoIi11IIiiI1I . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( OoIi11IIiiI1I . print_eid_tuple ( ) , False ) ) )
   if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
   IIiII11I1I111 . dequeue_map_request ( )
   continue
   if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
   if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
  Ooo0O = o00o . action
  OoIi11IIiiI1I . referral_source = source
  OoIi11IIiiI1I . referral_type = Ooo0O
  OoI1iI = o00o . store_ttl ( )
  OoIi11IIiiI1I . referral_ttl = OoI1iI
  OoIi11IIiiI1I . expires = lisp_set_timestamp ( OoI1iI )
  if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
  if 57 - 57: i11iIiiIii
  if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
  if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
  oooOoooOO0o0 = OoIi11IIiiI1I . is_referral_negative ( )
  if ( OoIi11IIiiI1I . referral_set . has_key ( i11I1 ) ) :
   iiIi11i1i = OoIi11IIiiI1I . referral_set [ i11I1 ]
   if 45 - 45: OOooOOo . I11i + Ii1I
   if ( iiIi11i1i . updown == False and oooOoooOO0o0 == False ) :
    iiIi11i1i . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( i11I1 ) )
    if 7 - 7: Oo0Ooo
   elif ( iiIi11i1i . updown == True and oooOoooOO0o0 == True ) :
    iiIi11i1i . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( i11I1 ) )
    if 78 - 78: I1IiiI - iIii1I11I1II1
    if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
    if 85 - 85: I11i + OoOoOO00 * O0 * O0
    if 92 - 92: i11iIiiIii
    if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
    if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
    if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
    if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
  OoO0o00ooOOo = { }
  for OOo0O in OoIi11IIiiI1I . referral_set : OoO0o00ooOOo [ OOo0O ] = None
  if 47 - 47: II111iiii % O0 / I1IiiI / iIii1I11I1II1 * I11i
  if 60 - 60: O0 * iII111i % I1ii11iIi11i
  if 92 - 92: OoOoOO00 / iIii1I11I1II1
  if 67 - 67: i1IIi + i11iIiiIii - i1IIi % OoOoOO00
  for o0Ooo0O00 in range ( o00o . rloc_count ) :
   Iii1i1iii = lisp_rloc_record ( )
   packet = Iii1i1iii . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 3 - 3: I1IiiI % ooOoO0o
   Iii1i1iii . print_record ( "    " )
   if 32 - 32: OOooOOo / i1IIi / OOooOOo
   if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
   if 45 - 45: Oo0Ooo
   if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
   O0o = Iii1i1iii . rloc . print_address ( )
   if ( OoIi11IIiiI1I . referral_set . has_key ( O0o ) == False ) :
    iiIi11i1i = lisp_referral_node ( )
    iiIi11i1i . referral_address . copy_address ( Iii1i1iii . rloc )
    OoIi11IIiiI1I . referral_set [ O0o ] = iiIi11i1i
    if ( i11I1 == O0o and oooOoooOO0o0 ) : iiIi11i1i . updown = False
   else :
    iiIi11i1i = OoIi11IIiiI1I . referral_set [ O0o ]
    if ( OoO0o00ooOOo . has_key ( O0o ) ) : OoO0o00ooOOo . pop ( O0o )
    if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
   iiIi11i1i . priority = Iii1i1iii . priority
   iiIi11i1i . weight = Iii1i1iii . weight
   if 52 - 52: OOooOOo + OoO0O00
   if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
   if 42 - 42: i1IIi
   if 52 - 52: OoO0O00 % iII111i % O0
   if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
  for OOo0O in OoO0o00ooOOo : OoIi11IIiiI1I . referral_set . pop ( OOo0O )
  if 50 - 50: oO0o . I1Ii111
  o0o0O00 = OoIi11IIiiI1I . print_eid_tuple ( )
  if 38 - 38: iIii1I11I1II1 . Ii1I
  if ( IIiII ) :
   if ( o00o . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( o0o0O00 , False ) ) )
    if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( o0o0O00 , False ) , o00o . rloc_count ) )
    if 15 - 15: O0
    if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( o0o0O00 , False ) , o00o . rloc_count ) )
   if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
   if 25 - 25: ooOoO0o
   if 33 - 33: Oo0Ooo
   if 11 - 11: I11i
   if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
   if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
  if ( Ooo0O == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( IIiII11I1I111 . lisp_sockets , OoIi11IIiiI1I . eid ,
 OoIi11IIiiI1I . group , IIiII11I1I111 . nonce , IIiII11I1I111 . itr , IIiII11I1I111 . sport , 15 , None , False )
   IIiII11I1I111 . dequeue_map_request ( )
   if 74 - 74: I1IiiI / o0oOOo0O0Ooo
   if 53 - 53: iIii1I11I1II1 * oO0o
  if ( Ooo0O == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( IIiII11I1I111 . tried_root ) :
    lisp_send_negative_map_reply ( IIiII11I1I111 . lisp_sockets , OoIi11IIiiI1I . eid ,
 OoIi11IIiiI1I . group , IIiII11I1I111 . nonce , IIiII11I1I111 . itr , IIiII11I1I111 . sport , 0 , None , False )
    IIiII11I1I111 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( IIiII11I1I111 , True )
    if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
    if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
    if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
  if ( Ooo0O == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( OoIi11IIiiI1I . referral_set . has_key ( i11I1 ) ) :
    iiIi11i1i = OoIi11IIiiI1I . referral_set [ i11I1 ]
    iiIi11i1i . updown = False
    if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
   if ( len ( OoIi11IIiiI1I . referral_set ) == 0 ) :
    IIiII11I1I111 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( IIiII11I1I111 , False )
    if 60 - 60: oO0o * I1Ii111
    if 81 - 81: oO0o - OOooOOo - oO0o
    if 54 - 54: oO0o % I11i
  if ( Ooo0O in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( IIiII11I1I111 . eid . is_exact_match ( o00o . eid ) ) :
    if ( not IIiII11I1I111 . tried_root ) :
     lisp_send_ddt_map_request ( IIiII11I1I111 , True )
    else :
     lisp_send_negative_map_reply ( IIiII11I1I111 . lisp_sockets ,
 OoIi11IIiiI1I . eid , OoIi11IIiiI1I . group , IIiII11I1I111 . nonce , IIiII11I1I111 . itr ,
 IIiII11I1I111 . sport , 15 , None , False )
     IIiII11I1I111 . dequeue_map_request ( )
     if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
   else :
    lisp_send_ddt_map_request ( IIiII11I1I111 , False )
    if 22 - 22: iIii1I11I1II1 - OoooooooOO
    if 8 - 8: ooOoO0o % i11iIiiIii
    if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
  if ( Ooo0O == LISP_DDT_ACTION_MS_ACK ) : IIiII11I1I111 . dequeue_map_request ( )
  if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
 return
 if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
 if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
 if 73 - 73: O0 % i11iIiiIii
 if 16 - 16: O0
 if 15 - 15: i1IIi % i11iIiiIii
 if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
 if 35 - 35: OoOoOO00 . oO0o / II111iiii
 if 97 - 97: Ii1I + I1Ii111 / II111iiii
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 oooo0OO0Oo = lisp_ecm ( 0 )
 packet = oooo0OO0Oo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 14 - 14: iII111i / IiII / oO0o
  if 55 - 55: OoO0O00 % O0
 oooo0OO0Oo . print_ecm ( )
 if 92 - 92: OoooooooOO / O0
 Ii1i111iI = lisp_control_header ( )
 if ( Ii1i111iI . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 14 - 14: i11iIiiIii
  if 43 - 43: OOooOOo
 O0oO0o00oO = Ii1i111iI . type
 del ( Ii1i111iI )
 if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
 if ( O0oO0o00oO != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 72 - 72: ooOoO0o
  if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
  if 53 - 53: OOooOOo * O0 . iII111i
  if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
  if 78 - 78: iII111i
 ooOoO0O0O0Oo = oooo0OO0Oo . udp_sport
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 oooo0OO0Oo . source , ooOoO0O0O0Oo , oooo0OO0Oo . ddt , - 1 )
 return
 if 40 - 40: Oo0Ooo - i11iIiiIii / o0oOOo0O0Ooo . II111iiii
 if 63 - 63: O0
 if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
 if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
 if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
 if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
 if 74 - 74: i11iIiiIii
 if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
 if 6 - 6: I11i
 if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
 if 6 - 6: Ii1I
 if 60 - 60: iII111i + I1IiiI
 if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
 if 16 - 16: Oo0Ooo
 if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
 if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
 iiII = ms . map_server
 if ( lisp_decent_push_configured and iiII . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  iiII = copy . deepcopy ( iiII )
  iiII . address = 0x7f000001
  IIiIiiiIIIIi1 = bold ( "Bootstrap" , False )
  I1I1i1 = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( IIiIiiiIIIIi1 , I1I1i1 ) )
  if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
  if 43 - 43: I1ii11iIi11i + I11i
  if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
  if 100 - 100: IiII - OoOoOO00 / I11i
  if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
  if 87 - 87: Oo0Ooo
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 65 - 65: ooOoO0o . I1IiiI
 if 51 - 51: IiII
 if 43 - 43: oO0o - I11i . i11iIiiIii
 if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
 if 30 - 30: I1IiiI % oO0o * OoooooooOO
 if ( ms . ekey != None ) :
  oOOOOoo0OoOOO = ms . ekey . zfill ( 32 )
  O0o0oOOO = "0" * 8
  O00O0 = chacha . ChaCha ( oOOOOoo0OoOOO , O0o0oOOO ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + O00O0
  IIIII1iii11 = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( IIIII1iii11 , ms . ekey_id ) )
  if 64 - 64: I1IiiI
  if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
 i1i1 = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  i1i1 = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 52 - 52: oO0o * I1IiiI
  if 10 - 10: II111iiii * I1ii11iIi11i % ooOoO0o / IiII / ooOoO0o
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( iiII . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , i1i1 ) )
 if 23 - 23: I1ii11iIi11i - oO0o - Ii1I - OoO0O00
 lisp_send ( lisp_sockets , iiII , LISP_CTRL_PORT , packet )
 return
 if 35 - 35: oO0o * I1IiiI - I11i . I1IiiI - i11iIiiIii . OOooOOo
 if 7 - 7: OOooOOo
 if 76 - 76: iIii1I11I1II1 % oO0o / i1IIi
 if 43 - 43: o0oOOo0O0Ooo
 if 72 - 72: OOooOOo . ooOoO0o / Ii1I / iIii1I11I1II1 - IiII - ooOoO0o
 if 7 - 7: OoOoOO00 + i1IIi % ooOoO0o * I11i + i11iIiiIii / II111iiii
 if 2 - 2: O0 / o0oOOo0O0Ooo - OoO0O00 * II111iiii
 if 4 - 4: I1IiiI + Oo0Ooo . iIii1I11I1II1
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 i1Ii1I = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 100 - 100: i11iIiiIii
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 21 - 21: OoOoOO00 + iII111i . OoO0O00
 if 79 - 79: i11iIiiIii - OoO0O00 * OoO0O00 * i1IIi / iIii1I11I1II1 + iII111i
 packet = lisp_control_packet_ipc ( packet , i1Ii1I , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
 if 62 - 62: iIii1I11I1II1
 if 60 - 60: Oo0Ooo % IiII % OoO0O00 - i11iIiiIii
 if 53 - 53: i11iIiiIii + OoooooooOO
 if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
 if 79 - 79: II111iiii / OoooooooOO
 if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
 if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
 if 17 - 17: I1Ii111
 if 2 - 2: O0 % OoOoOO00 + oO0o
 if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
 if 51 - 51: IiII
 if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
 if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 95 - 95: O0 - OoOoOO00
 if 68 - 68: ooOoO0o . I1Ii111
 if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
 if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
 if 41 - 41: Oo0Ooo
 if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
 if 66 - 66: oO0o % i1IIi % OoooooooOO
 if 58 - 58: OOooOOo
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 89 - 89: iIii1I11I1II1 - i1IIi
 if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
 if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
 if 36 - 36: IiII . OoOoOO00 . Ii1I
 if 31 - 31: iIii1I11I1II1
 if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
 if 88 - 88: OOooOOo / Oo0Ooo
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 31 - 31: II111iiii
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 67 - 67: IiII + oO0o * IiII
  if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
  if 62 - 62: ooOoO0o + ooOoO0o % I11i
  if 100 - 100: II111iiii . OoooooooOO
  if 32 - 32: I11i % OOooOOo * O0 / iIii1I11I1II1 / i1IIi
 if ( lisp_nat_traversal ) :
  O0oo0oOo = lisp_get_any_translated_port ( )
  if ( O0oo0oOo != None ) : inner_sport = O0oo0oOo
  if 87 - 87: OoO0O00 . I1ii11iIi11i * I1IiiI
 oooo0OO0Oo = lisp_ecm ( inner_sport )
 if 83 - 83: OOooOOo
 oooo0OO0Oo . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 oooo0OO0Oo . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 oooo0OO0Oo . ddt = ddt
 o0OOooOooOO = oooo0OO0Oo . encode ( packet , inner_source , inner_dest )
 if ( o0OOooOooOO == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 97 - 97: I1Ii111 + Ii1I * ooOoO0o
 oooo0OO0Oo . print_ecm ( )
 if 95 - 95: O0
 packet = o0OOooOooOO + packet
 if 61 - 61: Oo0Ooo % O0 . Ii1I - OOooOOo - o0oOOo0O0Ooo
 O0o = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( O0o ) )
 iiII = lisp_convert_4to6 ( O0o )
 lisp_send ( lisp_sockets , iiII , LISP_CTRL_PORT , packet )
 return
 if 71 - 71: iIii1I11I1II1
 if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
 if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
 if 77 - 77: II111iiii - IiII % OOooOOo
 if 22 - 22: OoooooooOO / oO0o
 if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
 if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
LISP_AFI_GEO_COORD = - 3
LISP_AFI_IID_RANGE = - 2
LISP_AFI_ULTIMATE_ROOT = - 1
LISP_AFI_NONE = 0
LISP_AFI_IPV4 = 1
LISP_AFI_IPV6 = 2
LISP_AFI_MAC = 6
LISP_AFI_E164 = 8
LISP_AFI_NAME = 17
LISP_AFI_LCAF = 16387
if 12 - 12: I1Ii111
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 17 - 17: I1Ii111 % oO0o + O0
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
if 81 - 81: Oo0Ooo . I1Ii111 * iIii1I11I1II1
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 60 - 60: OoooooooOO
if 41 - 41: iIii1I11I1II1 + O0 % o0oOOo0O0Ooo - IiII . I11i * O0
if 39 - 39: i11iIiiIii . Ii1I
if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
if 81 - 81: I11i % Oo0Ooo / iII111i
if 44 - 44: Oo0Ooo
def byte_swap_64 ( address ) :
 O0o0O0OO0o = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
 if 43 - 43: iIii1I11I1II1 % OOooOOo + OoOoOO00 + I1ii11iIi11i - Oo0Ooo / Ii1I
 if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
 if 54 - 54: O0 / ooOoO0o * I1Ii111
 if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
 if 13 - 13: IiII + Oo0Ooo - I1Ii111
 if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
 if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
 return ( O0o0O0OO0o )
 if 95 - 95: oO0o / Ii1I + OoO0O00
 if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
 if 39 - 39: OoO0O00 + II111iiii
 if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
 if 76 - 76: o0oOOo0O0Ooo
 if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
 if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
 if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
 if 49 - 49: iII111i + I11i . Oo0Ooo
 if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
 if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
 if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
 if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
 if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
 if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
  if 1 - 1: i11iIiiIii
  if 1 - 1: iIii1I11I1II1
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 73 - 73: iII111i + IiII
  if 95 - 95: O0
 def cache_size ( self ) :
  return ( self . cache_count )
  if 75 - 75: ooOoO0o
  if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   iIiIIIIiiiii = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   iIiIIIIiiiii = prefix . mask_len
  else :
   iIiIIIIiiiii = prefix . mask_len + 48
   if 85 - 85: ooOoO0o
   if 29 - 29: iII111i . Ii1I
  o0ooOo00O = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  ii1iI1i1 = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    O0oOOOO00oOOo = prefix . addr_length ( ) * 2
    O0o0O0OO0o = lisp_hex_string ( prefix . address ) . zfill ( O0oOOOO00oOOo )
   else :
    O0o0O0OO0o = prefix . address
    if 45 - 45: IiII
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   ii1iI1i1 = "8003"
   O0o0O0OO0o = prefix . address . print_geo ( )
  else :
   ii1iI1i1 = ""
   O0o0O0OO0o = ""
   if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
   if 9 - 9: iIii1I11I1II1 * Ii1I / O0 - OOooOOo
  OOo0O = o0ooOo00O + ii1iI1i1 + O0o0O0OO0o
  return ( [ iIiIIIIiiiii , OOo0O ] )
  if 95 - 95: i11iIiiIii * II111iiii * OOooOOo * iIii1I11I1II1
  if 22 - 22: iIii1I11I1II1 / I1IiiI + OoOoOO00 - OOooOOo . i11iIiiIii / i11iIiiIii
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  iIiIIIIiiiii , OOo0O = self . build_key ( prefix )
  if ( self . cache . has_key ( iIiIIIIiiiii ) == False ) :
   self . cache [ iIiIIIIiiiii ] = lisp_cache_entries ( )
   self . cache [ iIiIIIIiiiii ] . entries = { }
   self . cache [ iIiIIIIiiiii ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 10 - 10: iIii1I11I1II1 % i1IIi
  if ( self . cache [ iIiIIIIiiiii ] . entries . has_key ( OOo0O ) == False ) :
   self . cache_count += 1
   if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
  self . cache [ iIiIIIIiiiii ] . entries [ OOo0O ] = entry
  self . cache [ iIiIIIIiiiii ] . entries_sorted = sorted ( self . cache [ iIiIIIIiiiii ] . entries )
  if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
  if 44 - 44: I1ii11iIi11i
 def lookup_cache ( self , prefix , exact ) :
  i1iII11 , OOo0O = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( i1iII11 ) == False ) : return ( None )
   if ( self . cache [ i1iII11 ] . entries . has_key ( OOo0O ) == False ) : return ( None )
   return ( self . cache [ i1iII11 ] . entries [ OOo0O ] )
   if 85 - 85: oO0o / ooOoO0o . Ii1I . ooOoO0o + ooOoO0o / I1IiiI
   if 26 - 26: o0oOOo0O0Ooo / I1IiiI / OoOoOO00 + iIii1I11I1II1 % OOooOOo
  OOO0O0oOoo = None
  for iIiIIIIiiiii in self . cache_sorted :
   if ( i1iII11 < iIiIIIIiiiii ) : return ( OOO0O0oOoo )
   for ooO0o0 in self . cache [ iIiIIIIiiiii ] . entries_sorted :
    Oo0oOO0o0Oo = self . cache [ iIiIIIIiiiii ] . entries
    if ( ooO0o0 in Oo0oOO0o0Oo ) :
     i1II1IiiIi = Oo0oOO0o0Oo [ ooO0o0 ]
     if ( i1II1IiiIi == None ) : continue
     if ( prefix . is_more_specific ( i1II1IiiIi . eid ) ) : OOO0O0oOoo = i1II1IiiIi
     if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
     if 16 - 16: I1IiiI
     if 39 - 39: ooOoO0o * II111iiii
  return ( OOO0O0oOoo )
  if 90 - 90: OoooooooOO * ooOoO0o
  if 14 - 14: I1IiiI % i1IIi
 def delete_cache ( self , prefix ) :
  iIiIIIIiiiii , OOo0O = self . build_key ( prefix )
  if ( self . cache . has_key ( iIiIIIIiiiii ) == False ) : return
  if ( self . cache [ iIiIIIIiiiii ] . entries . has_key ( OOo0O ) == False ) : return
  self . cache [ iIiIIIIiiiii ] . entries . pop ( OOo0O )
  self . cache [ iIiIIIIiiiii ] . entries_sorted . remove ( OOo0O )
  self . cache_count -= 1
  if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
  if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
 def walk_cache ( self , function , parms ) :
  for iIiIIIIiiiii in self . cache_sorted :
   for OOo0O in self . cache [ iIiIIIIiiiii ] . entries_sorted :
    i1II1IiiIi = self . cache [ iIiIIIIiiiii ] . entries [ OOo0O ]
    oOOoOOo00oo0OO , parms = function ( i1II1IiiIi , parms )
    if ( oOOoOOo00oo0OO == False ) : return ( parms )
    if 84 - 84: oO0o + OoooooooOO
    if 8 - 8: I11i + i11iIiiIii + Ii1I
  return ( parms )
  if 38 - 38: oO0o + IiII . oO0o % iIii1I11I1II1 % Oo0Ooo * i11iIiiIii
  if 94 - 94: i11iIiiIii . II111iiii - i11iIiiIii / OoOoOO00
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  for iIiIIIIiiiii in self . cache_sorted :
   for OOo0O in self . cache [ iIiIIIIiiiii ] . entries_sorted :
    i1II1IiiIi = self . cache [ iIiIIIIiiiii ] . entries [ OOo0O ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( iIiIIIIiiiii , OOo0O ,
 i1II1IiiIi ) )
    if 39 - 39: Oo0Ooo . OoO0O00
    if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
    if 100 - 100: ooOoO0o / OoooooooOO
    if 73 - 73: i11iIiiIii - Oo0Ooo
    if 100 - 100: iIii1I11I1II1 + I1Ii111
    if 51 - 51: o0oOOo0O0Ooo * I11i
    if 42 - 42: OOooOOo % I11i
    if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 81 - 81: I1IiiI
if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
if 83 - 83: iII111i - I1ii11iIi11i + iII111i
if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
if 20 - 20: IiII - OOooOOo + OoOoOO00
def lisp_map_cache_lookup ( source , dest ) :
 if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
 IiI = dest . is_multicast_address ( )
 if 74 - 74: OoO0O00
 if 13 - 13: I1ii11iIi11i / OoO0O00
 if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
 if 94 - 94: IiII * i1IIi
 IIo0OooOO = lisp_map_cache . lookup_cache ( dest , False )
 if ( IIo0OooOO == None ) :
  o0o0O00 = source . print_sg ( dest ) if IiI else dest . print_address ( )
  o0o0O00 = green ( o0o0O00 , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( o0o0O00 ) )
  return ( None )
  if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
  if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
  if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
  if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
 if ( IiI == False ) :
  oO0O0O0O0O0OO = green ( IIo0OooOO . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , oO0O0O0O0O0OO ) )
  if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
  return ( IIo0OooOO )
  if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
  if 66 - 66: i1IIi
  if 98 - 98: Oo0Ooo / iIii1I11I1II1
  if 33 - 33: O0 - iII111i
  if 40 - 40: iII111i * I11i
 IIo0OooOO = IIo0OooOO . lookup_source_cache ( source , False )
 if ( IIo0OooOO == None ) :
  o0o0O00 = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( o0o0O00 ) )
  return ( None )
  if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if 87 - 87: OoOoOO00
  if 30 - 30: IiII % OoOoOO00 + I1Ii111
  if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
  if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
 oO0O0O0O0O0OO = green ( IIo0OooOO . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , oO0O0O0O0O0OO ) )
 if 87 - 87: I11i
 return ( IIo0OooOO )
 if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
 if 72 - 72: OoO0O00 * Oo0Ooo - IiII
 if 74 - 74: Ii1I
 if 26 - 26: I11i . O0
 if 68 - 68: Ii1I
 if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
 if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  i111II1iI1ii = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( i111II1iI1ii )
  if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
  if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
  if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
  if 9 - 9: o0oOOo0O0Ooo
  if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 21 - 21: Ii1I * OoOoOO00
 if 29 - 29: iIii1I11I1II1 / ooOoO0o
 if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
 if 88 - 88: OoO0O00 % Ii1I
 if 12 - 12: OoooooooOO . O0
 if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
 i111II1iI1ii = lisp_referral_cache . lookup_cache ( group , exact )
 if ( i111II1iI1ii == None ) : return ( None )
 if 34 - 34: i11iIiiIii / OoOoOO00
 oOoo0Oo0O = i111II1iI1ii . lookup_source_cache ( eid , exact )
 if ( oOoo0Oo0O ) : return ( oOoo0Oo0O )
 if 12 - 12: OoOoOO00 * I1ii11iIi11i - Ii1I / I1Ii111 * I1Ii111 - ooOoO0o
 if ( exact ) : i111II1iI1ii = None
 return ( i111II1iI1ii )
 if 28 - 28: Ii1I
 if 6 - 6: i1IIi + Oo0Ooo % I11i . OOooOOo + oO0o
 if 92 - 92: OoOoOO00 / OoOoOO00 / i1IIi + I1IiiI . i1IIi
 if 81 - 81: Ii1I * IiII / OoO0O00 . iII111i % I11i . ooOoO0o
 if 63 - 63: Oo0Ooo * I1Ii111 % Ii1I
 if 88 - 88: IiII - i1IIi * OoO0O00 * OoOoOO00 % I1IiiI
 if 10 - 10: OOooOOo * I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  OoII1i = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( OoII1i )
  if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
  if 96 - 96: O0
  if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
  if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
  if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
 if ( eid . is_null ( ) ) : return ( None )
 if 61 - 61: IiII . O0
 if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
 if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
 if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
 if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
 OoII1i = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( OoII1i == None ) : return ( None )
 if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
 IIi1III = OoII1i . lookup_source_cache ( eid , exact )
 if ( IIi1III ) : return ( IIi1III )
 if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
 if ( exact ) : OoII1i = None
 return ( OoII1i )
 if 86 - 86: OOooOOo / OoooooooOO - IiII
 if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
 if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
 if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
 if 8 - 8: oO0o * iII111i * I11i
 if 30 - 30: I1Ii111
 if 61 - 61: iII111i
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 50 - 50: Ii1I / I1IiiI . O0
 if ( group . is_null ( ) ) :
  OoOoO00OOO0O0 = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( OoOoO00OOO0O0 )
  if 49 - 49: I1Ii111 . OoO0O00 % O0
  if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
  if 62 - 62: II111iiii + ooOoO0o + I1IiiI
  if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
  if 13 - 13: I1ii11iIi11i
 if ( eid . is_null ( ) ) : return ( None )
 if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
 if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
 if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
 if 18 - 18: OoooooooOO - I1ii11iIi11i
 if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
 OoOoO00OOO0O0 = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( OoOoO00OOO0O0 == None ) : return ( None )
 if 79 - 79: OOooOOo + Oo0Ooo
 if 33 - 33: iIii1I11I1II1
 if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
 if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
 if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
 if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
 if 99 - 99: OOooOOo
 if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
 if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
 if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
 if 56 - 56: Oo0Ooo % I1ii11iIi11i
 if 53 - 53: OoO0O00 . I11i - ooOoO0o
 if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
 if 74 - 74: oO0o . I1Ii111 . II111iiii
 if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
 if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
 if 41 - 41: iII111i * OoO0O00 - OoO0O00
 if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
 i1iIi11iII = OoOoO00OOO0O0 . lookup_source_cache ( eid , exact )
 if ( i1iIi11iII ) : return ( i1iIi11iII )
 if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
 if ( exact ) :
  OoOoO00OOO0O0 = None
 else :
  IiiIIi111i1 = OoOoO00OOO0O0 . parent_for_more_specifics
  if ( IiiIIi111i1 and IiiIIi111i1 . accept_more_specifics ) :
   if ( group . is_more_specific ( IiiIIi111i1 . group ) ) : OoOoO00OOO0O0 = IiiIIi111i1
   if 39 - 39: i1IIi
   if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
 return ( OoOoO00OOO0O0 )
 if 59 - 59: i1IIi
 if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
 if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
 if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
 if 71 - 71: OOooOOo
 if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
 if 73 - 73: iII111i / I1IiiI * ooOoO0o
 if 85 - 85: I11i + I11i + oO0o - OoOoOO00
 if 15 - 15: OoO0O00
 if 88 - 88: Ii1I % i1IIi / I1Ii111
 if 2 - 2: Ii1I . IiII % OoOoOO00
 if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
 if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
 if 35 - 35: i11iIiiIii
 if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
 if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
 if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
 if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
 if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
 if 12 - 12: i11iIiiIii / Ii1I + i1IIi
 if 54 - 54: I1IiiI
 if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
 if 37 - 37: Oo0Ooo
 if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
 if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
 if 19 - 19: O0 * II111iiii * OoOoOO00
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 53 - 53: Oo0Ooo
  if 16 - 16: Ii1I
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
  if 78 - 78: OoO0O00 + oO0o
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 86 - 86: ooOoO0o . ooOoO0o + oO0o
  if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 31 - 31: IiII + iII111i
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 5 - 5: O0 * Ii1I
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
   if 77 - 77: OOooOOo / OoooooooOO
   if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
  if 31 - 31: IiII / o0oOOo0O0Ooo
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  O0o0O0OO0o = self . address
  if ( ( ( O0o0O0OO0o & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( O0o0O0OO0o & 0xff000000 ) >> 24 ) == 172 ) :
   ii11I1 = ( O0o0O0OO0o & 0x00ff0000 ) >> 16
   if ( ii11I1 >= 16 and ii11I1 <= 31 ) : return ( True )
   if 4 - 4: I1ii11iIi11i + I11i . I1ii11iIi11i * I1IiiI
  if ( ( ( O0o0O0OO0o & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 89 - 89: I1IiiI - IiII % O0 . i1IIi / o0oOOo0O0Ooo
  if 69 - 69: o0oOOo0O0Ooo / i11iIiiIii - oO0o + iII111i * oO0o
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 73 - 73: II111iiii
  if 54 - 54: I1IiiI % oO0o % iIii1I11I1II1 % II111iiii
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 43 - 43: I1ii11iIi11i
  return ( 0 )
  if 60 - 60: i11iIiiIii + IiII
  if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  O0o0O0OO0o = self . address >> 96
  return ( O0o0O0OO0o == 0x20010005 )
  if 86 - 86: Ii1I / oO0o
  if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
 def addr_length ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 16 )
  if ( self . afi == LISP_AFI_MAC ) : return ( 6 )
  if ( self . afi == LISP_AFI_E164 ) : return ( 8 )
  if ( self . afi == LISP_AFI_LCAF ) : return ( 0 )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) + 1 )
  if ( self . afi == LISP_AFI_IID_RANGE ) : return ( 4 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) )
   if 60 - 60: II111iiii / Ii1I
  return ( 0 )
  if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
  if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 66 - 66: OoooooooOO
  if 68 - 68: iII111i + I1Ii111
 def packet_format ( self ) :
  if 90 - 90: o0oOOo0O0Ooo
  if 48 - 48: iII111i + Ii1I
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
  if 67 - 67: oO0o
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
  if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
 def pack_address ( self ) :
  Iii1 = self . packet_format ( )
  oOo0O000oo0 = ""
  if ( self . is_ipv4 ( ) ) :
   oOo0O000oo0 = struct . pack ( Iii1 , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   IiIIIIii11i = byte_swap_64 ( self . address >> 64 )
   oO0OOO00 = byte_swap_64 ( self . address & 0xffffffffffffffff )
   oOo0O000oo0 = struct . pack ( Iii1 , IiIIIIii11i , oO0OOO00 )
  elif ( self . is_mac ( ) ) :
   O0o0O0OO0o = self . address
   IiIIIIii11i = ( O0o0O0OO0o >> 32 ) & 0xffff
   oO0OOO00 = ( O0o0O0OO0o >> 16 ) & 0xffff
   iIiiI1ii = O0o0O0OO0o & 0xffff
   oOo0O000oo0 = struct . pack ( Iii1 , IiIIIIii11i , oO0OOO00 , iIiiI1ii )
  elif ( self . is_e164 ( ) ) :
   O0o0O0OO0o = self . address
   IiIIIIii11i = ( O0o0O0OO0o >> 32 ) & 0xffffffff
   oO0OOO00 = ( O0o0O0OO0o & 0xffffffff )
   oOo0O000oo0 = struct . pack ( Iii1 , IiIIIIii11i , oO0OOO00 )
  elif ( self . is_dist_name ( ) ) :
   oOo0O000oo0 += self . address + "\0"
   if 93 - 93: I1IiiI + O0 / Ii1I + OOooOOo
  return ( oOo0O000oo0 )
  if 5 - 5: II111iiii % I1IiiI * ooOoO0o / ooOoO0o + iII111i
  if 3 - 3: O0 + OOooOOo + I1Ii111 + Oo0Ooo * OoOoOO00
 def unpack_address ( self , packet ) :
  Iii1 = self . packet_format ( )
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 19 - 19: II111iiii * O0 % II111iiii
  O0o0O0OO0o = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( O0o0O0OO0o [ 0 ] )
   if 35 - 35: II111iiii + IiII
  elif ( self . is_ipv6 ( ) ) :
   if 66 - 66: o0oOOo0O0Ooo % IiII
   if 39 - 39: IiII
   if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
   if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
   if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
   if 62 - 62: O0
   if 52 - 52: OoooooooOO . oO0o
   if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
   if ( O0o0O0OO0o [ 0 ] <= 0xffff and ( O0o0O0OO0o [ 0 ] & 0xff ) == 0 ) :
    IiIiii = ( O0o0O0OO0o [ 0 ] << 48 ) << 64
   else :
    IiIiii = byte_swap_64 ( O0o0O0OO0o [ 0 ] ) << 64
    if 85 - 85: Ii1I
   oo0000O00 = byte_swap_64 ( O0o0O0OO0o [ 1 ] )
   self . address = IiIiii | oo0000O00
   if 85 - 85: OOooOOo
  elif ( self . is_mac ( ) ) :
   IiiIiiI = O0o0O0OO0o [ 0 ]
   oooo0 = O0o0O0OO0o [ 1 ]
   I1I11 = O0o0O0OO0o [ 2 ]
   self . address = ( IiiIiiI << 32 ) + ( oooo0 << 16 ) + I1I11
   if 44 - 44: ooOoO0o % OoooooooOO * Oo0Ooo
  elif ( self . is_e164 ( ) ) :
   self . address = ( O0o0O0OO0o [ 0 ] << 32 ) + O0o0O0OO0o [ 1 ]
   if 29 - 29: i11iIiiIii + Ii1I . OoooooooOO - II111iiii / Oo0Ooo
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   O00O = 0
   if 47 - 47: oO0o / I1ii11iIi11i / I1Ii111 + OoooooooOO - OoOoOO00 . IiII
  packet = packet [ O00O : : ]
  return ( packet )
  if 33 - 33: OoOoOO00 - I1IiiI + iII111i . iII111i
  if 68 - 68: OoO0O00 / OoO0O00 - I1IiiI + OoOoOO00
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
  if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
  if 38 - 38: IiII . I1Ii111
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
  if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
  if 11 - 11: iII111i
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 60 - 60: I1ii11iIi11i / I1Ii111
  if 10 - 10: OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . OoOoOO00 / I1IiiI
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
  if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
  if 69 - 69: iII111i % I1ii11iIi11i
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 19 - 19: IiII
  if 35 - 35: OoOoOO00
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
  if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 73 - 73: OOooOOo
  if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
  if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
  if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
  if 8 - 8: O0 + i1IIi . O0
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 67 - 67: I1IiiI
  if 42 - 42: ooOoO0o - o0oOOo0O0Ooo % oO0o - ooOoO0o
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 87 - 87: OoooooooOO / O0
  if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 75 - 75: O0 + I1IiiI
  return ( False )
  if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
  if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 73 - 73: II111iiii
  if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
  if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
  if 44 - 44: iIii1I11I1II1 * iII111i
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 32 - 32: OoOoOO00
  if 65 - 65: iIii1I11I1II1 + iII111i
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 90 - 90: i11iIiiIii - Oo0Ooo
  if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
  if 45 - 45: OoooooooOO * I1Ii111
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 7 - 7: O0
  if 42 - 42: o0oOOo0O0Ooo / Ii1I
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 31 - 31: OOooOOo
  if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
  if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
  if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
  o0Ooo0O00 = addr_str . find ( "[" )
  OOOO00o00o0 = addr_str . find ( "]" )
  if ( o0Ooo0O00 != - 1 and OOOO00o00o0 != - 1 ) :
   self . instance_id = int ( addr_str [ o0Ooo0O00 + 1 : OOOO00o00o0 ] )
   addr_str = addr_str [ OOOO00o00o0 + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
    if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
    if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
    if 65 - 65: I1IiiI . ooOoO0o
    if 51 - 51: I1Ii111
    if 89 - 89: Oo0Ooo
  if ( self . is_ipv4 ( ) ) :
   IIIi11i1Ii11i = addr_str . split ( "." )
   i111II = int ( IIIi11i1Ii11i [ 0 ] ) << 24
   i111II += int ( IIIi11i1Ii11i [ 1 ] ) << 16
   i111II += int ( IIIi11i1Ii11i [ 2 ] ) << 8
   i111II += int ( IIIi11i1Ii11i [ 3 ] )
   self . address = i111II
  elif ( self . is_ipv6 ( ) ) :
   if 94 - 94: IiII / II111iiii * II111iiii / OoO0O00 + oO0o
   if 77 - 77: OOooOOo + oO0o + Oo0Ooo * o0oOOo0O0Ooo
   if 71 - 71: Ii1I
   if 70 - 70: oO0o . I1ii11iIi11i
   if 81 - 81: iII111i * i11iIiiIii % OoO0O00 - iIii1I11I1II1 * I1ii11iIi11i
   if 8 - 8: O0 / iIii1I11I1II1 - Oo0Ooo % ooOoO0o * Ii1I % o0oOOo0O0Ooo
   if 59 - 59: Oo0Ooo % iII111i
   if 52 - 52: o0oOOo0O0Ooo . I1ii11iIi11i
   if 72 - 72: Ii1I
   if 76 - 76: O0 + oO0o * OoooooooOO - I11i
   if 96 - 96: I1Ii111 - Ii1I - i11iIiiIii
   if 57 - 57: IiII % i1IIi
   if 74 - 74: iII111i % I11i * i11iIiiIii . i11iIiiIii + iIii1I11I1II1 * i1IIi
   if 53 - 53: I1ii11iIi11i + IiII / OOooOOo . OoooooooOO - ooOoO0o
   if 47 - 47: i11iIiiIii
   if 21 - 21: i1IIi - oO0o - Oo0Ooo
   if 11 - 11: i1IIi
   O00o0Oo = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
   addr_str = binascii . hexlify ( addr_str )
   if 56 - 56: Ii1I . iII111i
   if ( O00o0Oo ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
   self . address = int ( addr_str , 16 )
   if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
  elif ( self . is_geo_prefix ( ) ) :
   oOo00O = lisp_geo ( None )
   oOo00O . name = "geo-prefix-{}" . format ( oOo00O )
   oOo00O . parse_geo_string ( addr_str )
   self . address = oOo00O
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   i111II = int ( addr_str , 16 )
   self . address = i111II
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   i111II = int ( addr_str , 16 )
   self . address = i111II << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 52 - 52: i11iIiiIii
  self . mask_len = self . host_mask_len ( )
  if 1 - 1: i1IIi * iIii1I11I1II1
  if 29 - 29: I11i
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   ii = prefix_str . find ( "]" )
   oo0Ooo = len ( prefix_str [ ii + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , oo0Ooo = prefix_str . split ( "/" )
  else :
   IIi1I = prefix_str . find ( "'" )
   if ( IIi1I == - 1 ) : return
   iiII1I11IIi = prefix_str . find ( "'" , IIi1I + 1 )
   if ( iiII1I11IIi == - 1 ) : return
   oo0Ooo = len ( prefix_str [ IIi1I + 1 : iiII1I11IIi ] ) * 8
   if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
   if 6 - 6: IiII / OoO0O00
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( oo0Ooo )
  if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
  if 77 - 77: Ii1I
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  i1Ii = ( 2 ** self . mask_len ) - 1
  Oo00OOoO = self . addr_length ( ) * 8 - self . mask_len
  i1Ii <<= Oo00OOoO
  self . address &= i1Ii
  if 20 - 20: I1Ii111
  if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 def is_geo_string ( self , addr_str ) :
  ii = addr_str . find ( "]" )
  if ( ii != - 1 ) : addr_str = addr_str [ ii + 1 : : ]
  if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
  oOo00O = addr_str . split ( "/" )
  if ( len ( oOo00O ) == 2 ) :
   if ( oOo00O [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
  oOo00O = oOo00O [ 0 ]
  oOo00O = oOo00O . split ( "-" )
  OO00000OO00oo = len ( oOo00O )
  if ( OO00000OO00oo < 8 or OO00000OO00oo > 9 ) : return ( False )
  if 5 - 5: i1IIi % I1IiiI
  for OOo00O00 in range ( 0 , OO00000OO00oo ) :
   if ( OOo00O00 == 3 ) :
    if ( oOo00O [ OOo00O00 ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 34 - 34: OoOoOO00 . Oo0Ooo
   if ( OOo00O00 == 7 ) :
    if ( oOo00O [ OOo00O00 ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 5 - 5: I1ii11iIi11i + IiII + I1ii11iIi11i
   if ( oOo00O [ OOo00O00 ] . isdigit ( ) == False ) : return ( False )
   if 28 - 28: Ii1I % o0oOOo0O0Ooo * IiII
  return ( True )
  if 20 - 20: OoOoOO00 / I11i * O0 + Ii1I - OoOoOO00 % ooOoO0o
  if 99 - 99: o0oOOo0O0Ooo / i1IIi * OOooOOo % iII111i
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 18 - 18: iII111i * i1IIi / II111iiii / Oo0Ooo
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 47 - 47: Ii1I / i1IIi - iII111i - i11iIiiIii
  if 3 - 3: OoOoOO00
 def print_address ( self ) :
  O0o0O0OO0o = self . print_address_no_iid ( )
  o0ooOo00O = "[" + str ( self . instance_id )
  for o0Ooo0O00 in self . iid_list : o0ooOo00O += "," + str ( o0Ooo0O00 )
  o0ooOo00O += "]"
  O0o0O0OO0o = "{}{}" . format ( o0ooOo00O , O0o0O0OO0o )
  return ( O0o0O0OO0o )
  if 53 - 53: II111iiii / II111iiii . O0 - oO0o . i1IIi
  if 45 - 45: OoOoOO00 + I1Ii111 + Oo0Ooo
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   O0o0O0OO0o = self . address
   OO0O0 = O0o0O0OO0o >> 24
   OOooO0ooOOo0o = ( O0o0O0OO0o >> 16 ) & 0xff
   i1i1i11 = ( O0o0O0OO0o >> 8 ) & 0xff
   ii1II11I11I11 = O0o0O0OO0o & 0xff
   return ( "{}.{}.{}.{}" . format ( OO0O0 , OOooO0ooOOo0o , i1i1i11 , ii1II11I11I11 ) )
  elif ( self . is_ipv6 ( ) ) :
   O0o = lisp_hex_string ( self . address ) . zfill ( 32 )
   O0o = binascii . unhexlify ( O0o )
   O0o = socket . inet_ntop ( socket . AF_INET6 , O0o )
   return ( "{}" . format ( O0o ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   O0o = lisp_hex_string ( self . address ) . zfill ( 12 )
   O0o = "{}-{}-{}" . format ( O0o [ 0 : 4 ] , O0o [ 4 : 8 ] ,
 O0o [ 8 : 12 ] )
   return ( "{}" . format ( O0o ) )
  elif ( self . is_e164 ( ) ) :
   O0o = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( O0o ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 7 - 7: O0 . OoO0O00 % I1Ii111 % i1IIi
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 44 - 44: o0oOOo0O0Ooo
  if 37 - 37: I1IiiI / I11i * OOooOOo * iII111i
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   iII111i1I1i1 = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , iII111i1I1i1 ) )
   if 32 - 32: I1IiiI + I1Ii111 % ooOoO0o
  O0o0O0OO0o = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( O0o0O0OO0o )
  if ( self . is_geo_prefix ( ) ) : return ( O0o0O0OO0o )
  if 83 - 83: I1Ii111
  ii = O0o0O0OO0o . find ( "no-address" )
  if ( ii == - 1 ) :
   O0o0O0OO0o = "{}/{}" . format ( O0o0O0OO0o , str ( self . mask_len ) )
  else :
   O0o0O0OO0o = O0o0O0OO0o [ 0 : ii ]
   if 2 - 2: OOooOOo - Ii1I - Oo0Ooo / OoO0O00
  return ( O0o0O0OO0o )
  if 64 - 64: IiII % I11i / I1IiiI + I1IiiI + I11i
  if 92 - 92: I1IiiI / Ii1I % II111iiii - o0oOOo0O0Ooo . OoO0O00 . Ii1I
 def print_prefix_no_iid ( self ) :
  O0o0O0OO0o = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( O0o0O0OO0o )
  if ( self . is_geo_prefix ( ) ) : return ( O0o0O0OO0o )
  return ( "{}/{}" . format ( O0o0O0OO0o , str ( self . mask_len ) ) )
  if 70 - 70: Ii1I * i1IIi % OoooooooOO * oO0o
  if 67 - 67: iIii1I11I1II1 + OOooOOo * i11iIiiIii
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  O0o0O0OO0o = self . print_address ( )
  ii = O0o0O0OO0o . find ( "]" )
  if ( ii != - 1 ) : O0o0O0OO0o = O0o0O0OO0o [ ii + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   O0o0O0OO0o = O0o0O0OO0o . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , O0o0O0OO0o ) )
   if 72 - 72: I1ii11iIi11i - i1IIi
  return ( "{}-{}-{}" . format ( self . instance_id , O0o0O0OO0o , self . mask_len ) )
  if 57 - 57: OoOoOO00 . iII111i
  if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
 def print_sg ( self , g ) :
  i11I1 = self . print_prefix ( )
  i1i1IIIi11Ii = i11I1 . find ( "]" ) + 1
  g = g . print_prefix ( )
  IIo0Oo0ooO0o0 = g . find ( "]" ) + 1
  iiiiii1 = "[{}]({}, {})" . format ( self . instance_id , i11I1 [ i1i1IIIi11Ii : : ] , g [ IIo0Oo0ooO0o0 : : ] )
  return ( iiiiii1 )
  if 39 - 39: IiII * I11i + I1IiiI
  if 60 - 60: I11i % Ii1I * oO0o % II111iiii + o0oOOo0O0Ooo
 def hash_address ( self , addr ) :
  IiIIIIii11i = self . address
  oO0OOO00 = addr . address
  if 62 - 62: O0 - O0 - I1IiiI . OoO0O00 . i11iIiiIii % i11iIiiIii
  if ( self . is_geo_prefix ( ) ) : IiIIIIii11i = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : oO0OOO00 = addr . address . print_geo ( )
  if 54 - 54: I1IiiI + OoooooooOO / iII111i / I11i . I11i % I11i
  if ( type ( IiIIIIii11i ) == str ) :
   IiIIIIii11i = int ( binascii . hexlify ( IiIIIIii11i [ 0 : 1 ] ) )
   if 54 - 54: OoO0O00 * I11i * iIii1I11I1II1 * IiII
  if ( type ( oO0OOO00 ) == str ) :
   oO0OOO00 = int ( binascii . hexlify ( oO0OOO00 [ 0 : 1 ] ) )
   if 12 - 12: O0 - iII111i * IiII . i11iIiiIii
  return ( IiIIIIii11i ^ oO0OOO00 )
  if 25 - 25: Ii1I % i1IIi * I11i * Ii1I - IiII . i11iIiiIii
  if 40 - 40: OOooOOo - OoooooooOO
  if 36 - 36: i1IIi % OoOoOO00 - i1IIi
  if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
  if 97 - 97: I11i . ooOoO0o
  if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
  oo0Ooo = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   O0O00oOoo = 2 ** ( 32 - oo0Ooo )
   oo0O0o0oo0O = prefix . instance_id
   iII111i1I1i1 = oo0O0o0oo0O + O0O00oOoo
   return ( self . instance_id in range ( oo0O0o0oo0O , iII111i1I1i1 ) )
   if 4 - 4: Ii1I + ooOoO0o * i11iIiiIii + iII111i
   if 77 - 77: OoO0O00 . iII111i
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 77 - 77: I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
   if 17 - 17: OoooooooOO - i1IIi * I11i
   if 33 - 33: i1IIi . Oo0Ooo + I11i
   if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
   if 78 - 78: I1Ii111 + I1Ii111
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   O0o0O0OO0o = self . address
   i1IIiii1IiIII = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    O0o0O0OO0o = self . address . print_geo ( )
    i1IIiii1IiIII = prefix . address . print_geo ( )
    if 56 - 56: OoOoOO00
   if ( len ( O0o0O0OO0o ) < len ( i1IIiii1IiIII ) ) : return ( False )
   return ( O0o0O0OO0o . find ( i1IIiii1IiIII ) == 0 )
   if 36 - 36: OoO0O00 * I1IiiI + o0oOOo0O0Ooo % II111iiii + OOooOOo . OoooooooOO
   if 14 - 14: o0oOOo0O0Ooo / OOooOOo . ooOoO0o % O0
   if 35 - 35: ooOoO0o - i1IIi
   if 11 - 11: Oo0Ooo + oO0o / I1ii11iIi11i / OoOoOO00
   if 49 - 49: Ii1I * I1ii11iIi11i
  if ( self . mask_len < oo0Ooo ) : return ( False )
  if 66 - 66: ooOoO0o
  Oo00OOoO = ( prefix . addr_length ( ) * 8 ) - oo0Ooo
  i1Ii = ( 2 ** oo0Ooo - 1 ) << Oo00OOoO
  return ( ( self . address & i1Ii ) == prefix . address )
  if 2 - 2: o0oOOo0O0Ooo
  if 86 - 86: OoooooooOO * I1ii11iIi11i + O0 + o0oOOo0O0Ooo + OOooOOo % OoO0O00
 def mask_address ( self , mask_len ) :
  Oo00OOoO = ( self . addr_length ( ) * 8 ) - mask_len
  i1Ii = ( 2 ** mask_len - 1 ) << Oo00OOoO
  self . address &= i1Ii
  if 72 - 72: ooOoO0o * I1IiiI
  if 71 - 71: OoOoOO00 * OoO0O00 * O0 . i1IIi
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  oOoooooo = self . print_prefix ( )
  OOOi1II11i111 = prefix . print_prefix ( ) if prefix else ""
  return ( oOoooooo == OOOi1II11i111 )
  if 11 - 11: Ii1I
  if 35 - 35: i11iIiiIii + ooOoO0o
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   ooOoo00OoO = lisp_myrlocs [ 0 ]
   if ( ooOoo00OoO == None ) : return ( False )
   ooOoo00OoO = ooOoo00OoO . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == ooOoo00OoO )
   if 74 - 74: OoOoOO00 + I1Ii111 % I1Ii111
  if ( self . is_ipv6 ( ) ) :
   ooOoo00OoO = lisp_myrlocs [ 1 ]
   if ( ooOoo00OoO == None ) : return ( False )
   ooOoo00OoO = ooOoo00OoO . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == ooOoo00OoO )
   if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
  return ( False )
  if 9 - 9: iIii1I11I1II1
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid is 0 and mask_len is 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  self . instance_id = iid
  self . mask_len = mask_len
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
 def lcaf_length ( self , lcaf_type ) :
  O0oOOOO00oOOo = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : O0oOOOO00oOOo += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : O0oOOOO00oOOo += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : O0oOOOO00oOOo += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : O0oOOOO00oOOo += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : O0oOOOO00oOOo += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : O0oOOOO00oOOo += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : O0oOOOO00oOOo += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : O0oOOOO00oOOo += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : O0oOOOO00oOOo = O0oOOOO00oOOo * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : O0oOOOO00oOOo += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : O0oOOOO00oOOo += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : O0oOOOO00oOOo += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : O0oOOOO00oOOo += 4
  return ( O0oOOOO00oOOo )
  if 34 - 34: iIii1I11I1II1
  if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
  if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
  if 20 - 20: OoO0O00
  if 93 - 93: ooOoO0o + o0oOOo0O0Ooo - I1ii11iIi11i
  if 56 - 56: Ii1I / Oo0Ooo
  if 96 - 96: o0oOOo0O0Ooo . II111iiii
  if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
  if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
  if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
  if 6 - 6: OoooooooOO
  if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
  if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
  if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
  if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
  if 14 - 14: OOooOOo * IiII
 def lcaf_encode_iid ( self ) :
  ii1i = LISP_LCAF_INSTANCE_ID_TYPE
  Oo0O0o00o00 = socket . htons ( self . lcaf_length ( ii1i ) )
  o0ooOo00O = self . instance_id
  ii1iI1i1 = self . afi
  iIiIIIIiiiii = 0
  if ( ii1iI1i1 < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    ii1iI1i1 = LISP_AFI_LCAF
    iIiIIIIiiiii = 0
   else :
    ii1iI1i1 = 0
    iIiIIIIiiiii = self . mask_len
    if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
    if 33 - 33: OoO0O00
    if 91 - 91: I11i % I11i % iII111i
  I1I11Ii1I111 = struct . pack ( "BBBBH" , 0 , 0 , ii1i , iIiIIIIiiiii , Oo0O0o00o00 )
  I1I11Ii1I111 += struct . pack ( "IH" , socket . htonl ( o0ooOo00O ) , socket . htons ( ii1iI1i1 ) )
  if ( ii1iI1i1 == 0 ) : return ( I1I11Ii1I111 )
  if 84 - 84: iIii1I11I1II1 % OoooooooOO
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   I1I11Ii1I111 = I1I11Ii1I111 [ 0 : - 2 ]
   I1I11Ii1I111 += self . address . encode_geo ( )
   return ( I1I11Ii1I111 )
   if 81 - 81: OoO0O00 % i1IIi
   if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
  I1I11Ii1I111 += self . pack_address ( )
  return ( I1I11Ii1I111 )
  if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
  if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
 def lcaf_decode_iid ( self , packet ) :
  Iii1 = "BBBBH"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
  o000000Oo , Ooo000O00o , ii1i , OOOo00oO , O0oOOOO00oOOo = struct . unpack ( Iii1 ,
 packet [ : O00O ] )
  packet = packet [ O00O : : ]
  if 19 - 19: O0 . O0
  if ( ii1i != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 13 - 13: i11iIiiIii - i11iIiiIii . iIii1I11I1II1 - O0 . I11i / i11iIiiIii
  Iii1 = "IH"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( None )
  if 59 - 59: ooOoO0o + I1ii11iIi11i . OoO0O00 . O0
  o0ooOo00O , ii1iI1i1 = struct . unpack ( Iii1 , packet [ : O00O ] )
  packet = packet [ O00O : : ]
  if 45 - 45: O0 . o0oOOo0O0Ooo + OoOoOO00 / I1ii11iIi11i + Ii1I % I1Ii111
  O0oOOOO00oOOo = socket . ntohs ( O0oOOOO00oOOo )
  self . instance_id = socket . ntohl ( o0ooOo00O )
  ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
  self . afi = ii1iI1i1
  if ( OOOo00oO != 0 and ii1iI1i1 == 0 ) : self . mask_len = OOOo00oO
  if ( ii1iI1i1 == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if OOOo00oO else LISP_AFI_ULTIMATE_ROOT
   if 20 - 20: Oo0Ooo
   if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
   if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
   if 84 - 84: OOooOOo
   if 68 - 68: I1Ii111
  if ( ii1iI1i1 == 0 ) : return ( packet )
  if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
  if 54 - 54: oO0o + I11i - OoO0O00
  if 86 - 86: OoooooooOO
  if 51 - 51: i11iIiiIii
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 91 - 91: OOooOOo
   if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
   if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
   if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
   if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
  if ( ii1iI1i1 == LISP_AFI_LCAF ) :
   Iii1 = "BBBBH"
   O00O = struct . calcsize ( Iii1 )
   if ( len ( packet ) < O00O ) : return ( None )
   if 61 - 61: ooOoO0o / ooOoO0o
   Oo0o0ooOo0 , OoOoo0ooO0000 , ii1i , ii1iiI11III1 , OOooo0o0OOO = struct . unpack ( Iii1 , packet [ : O00O ] )
   if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
   if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
   if ( ii1i != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 93 - 93: iIii1I11I1II1 % OoooooooOO
   OOooo0o0OOO = socket . ntohs ( OOooo0o0OOO )
   packet = packet [ O00O : : ]
   if ( OOooo0o0OOO > len ( packet ) ) : return ( None )
   if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
   oOo00O = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = oOo00O
   packet = oOo00O . decode_geo ( packet , OOooo0o0OOO , ii1iiI11III1 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
   if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
  Oo0O0o00o00 = self . addr_length ( )
  if ( len ( packet ) < Oo0O0o00o00 ) : return ( None )
  if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
  packet = self . unpack_address ( packet )
  return ( packet )
  if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
  if 87 - 87: iII111i
  if 86 - 86: IiII - I11i
  if 99 - 99: i1IIi + I1ii11iIi11i
  if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
  if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
  if 44 - 44: II111iiii / I1ii11iIi11i
  if 39 - 39: OoooooooOO % OoO0O00
  if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
  if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
  if 29 - 29: IiII
  if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
  if 91 - 91: I1Ii111 * iII111i * OoO0O00
  if 79 - 79: iII111i + oO0o
  if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
  if 97 - 97: O0 / OoOoOO00 / ooOoO0o
  if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
  if 10 - 10: OOooOOo * OoooooooOO
  if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
  if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
  if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
 def lcaf_encode_sg ( self , group ) :
  ii1i = LISP_LCAF_MCAST_INFO_TYPE
  o0ooOo00O = socket . htonl ( self . instance_id )
  Oo0O0o00o00 = socket . htons ( self . lcaf_length ( ii1i ) )
  I1I11Ii1I111 = struct . pack ( "BBBBHIHBB" , 0 , 0 , ii1i , 0 , Oo0O0o00o00 , o0ooOo00O ,
 0 , self . mask_len , group . mask_len )
  if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
  I1I11Ii1I111 += struct . pack ( "H" , socket . htons ( self . afi ) )
  I1I11Ii1I111 += self . pack_address ( )
  I1I11Ii1I111 += struct . pack ( "H" , socket . htons ( group . afi ) )
  I1I11Ii1I111 += group . pack_address ( )
  return ( I1I11Ii1I111 )
  if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
  if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
 def lcaf_decode_sg ( self , packet ) :
  Iii1 = "BBBBHIHBB"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( [ None , None ] )
  if 62 - 62: I11i
  o000000Oo , Ooo000O00o , ii1i , OOo0OO00 , O0oOOOO00oOOo , o0ooOo00O , O0O , i1I1I1111III , OOO00Oo0o0Oo = struct . unpack ( Iii1 , packet [ : O00O ] )
  if 66 - 66: iII111i + i1IIi
  packet = packet [ O00O : : ]
  if 24 - 24: O0 / OoooooooOO - OoOoOO00
  if ( ii1i != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
  self . instance_id = socket . ntohl ( o0ooOo00O )
  O0oOOOO00oOOo = socket . ntohs ( O0oOOOO00oOOo ) - 8
  if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
  if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
  if 53 - 53: i11iIiiIii % I1ii11iIi11i
  if 59 - 59: OOooOOo
  if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
  Iii1 = "H"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( [ None , None ] )
  if ( O0oOOOO00oOOo < O00O ) : return ( [ None , None ] )
  if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
  ii1iI1i1 = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
  packet = packet [ O00O : : ]
  O0oOOOO00oOOo -= O00O
  self . afi = socket . ntohs ( ii1iI1i1 )
  self . mask_len = i1I1I1111III
  Oo0O0o00o00 = self . addr_length ( )
  if ( O0oOOOO00oOOo < Oo0O0o00o00 ) : return ( [ None , None ] )
  if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 11 - 11: Ii1I - ooOoO0o % i11iIiiIii / OoooooooOO - O0 - IiII
  O0oOOOO00oOOo -= Oo0O0o00o00
  if 25 - 25: IiII + O0 + oO0o % iIii1I11I1II1 - II111iiii . I1IiiI
  if 62 - 62: IiII . O0 + oO0o - ooOoO0o * iIii1I11I1II1
  if 8 - 8: I1ii11iIi11i
  if 65 - 65: i11iIiiIii
  if 92 - 92: oO0o * II111iiii + I1Ii111
  Iii1 = "H"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( [ None , None ] )
  if ( O0oOOOO00oOOo < O00O ) : return ( [ None , None ] )
  if 49 - 49: II111iiii * I1IiiI * O0 / ooOoO0o * IiII
  ii1iI1i1 = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
  packet = packet [ O00O : : ]
  O0oOOOO00oOOo -= O00O
  oooiiIiIIIi1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  oooiiIiIIIi1 . afi = socket . ntohs ( ii1iI1i1 )
  oooiiIiIIIi1 . mask_len = OOO00Oo0o0Oo
  oooiiIiIIIi1 . instance_id = self . instance_id
  Oo0O0o00o00 = self . addr_length ( )
  if ( O0oOOOO00oOOo < Oo0O0o00o00 ) : return ( [ None , None ] )
  if 94 - 94: OoO0O00 - I1IiiI * oO0o
  packet = oooiiIiIIIi1 . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 35 - 35: OOooOOo / i1IIi + OoO0O00
  return ( [ packet , oooiiIiIIIi1 ] )
  if 31 - 31: OoO0O00 . i1IIi / OoooooooOO
  if 81 - 81: ooOoO0o . Oo0Ooo . OoOoOO00 + OOooOOo % iII111i - oO0o
 def lcaf_decode_eid ( self , packet ) :
  Iii1 = "BBB"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( [ None , None ] )
  if 68 - 68: iII111i - O0 / Ii1I
  if 15 - 15: I1Ii111 / I1ii11iIi11i / I1IiiI % i11iIiiIii + II111iiii . ooOoO0o
  if 74 - 74: o0oOOo0O0Ooo
  if 4 - 4: I1ii11iIi11i * II111iiii - Oo0Ooo % i1IIi % O0 * i11iIiiIii
  if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
  OOo0OO00 , OoOoo0ooO0000 , ii1i = struct . unpack ( Iii1 ,
 packet [ : O00O ] )
  if 27 - 27: oO0o . iII111i . oO0o
  if ( ii1i == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( ii1i == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , oooiiIiIIIi1 = self . lcaf_decode_sg ( packet )
   return ( [ packet , oooiiIiIIIi1 ] )
  elif ( ii1i == LISP_LCAF_GEO_COORD_TYPE ) :
   Iii1 = "BBBBH"
   O00O = struct . calcsize ( Iii1 )
   if ( len ( packet ) < O00O ) : return ( None )
   if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
   Oo0o0ooOo0 , OoOoo0ooO0000 , ii1i , ii1iiI11III1 , OOooo0o0OOO = struct . unpack ( Iii1 , packet [ : O00O ] )
   if 14 - 14: I11i + ooOoO0o . oO0o * I11i
   if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
   if ( ii1i != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
   OOooo0o0OOO = socket . ntohs ( OOooo0o0OOO )
   packet = packet [ O00O : : ]
   if ( OOooo0o0OOO > len ( packet ) ) : return ( None )
   if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
   oOo00O = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = oOo00O
   packet = oOo00O . decode_geo ( packet , OOooo0o0OOO , ii1iiI11III1 )
   self . mask_len = self . host_mask_len ( )
   if 33 - 33: I11i
  return ( [ packet , None ] )
  if 37 - 37: Oo0Ooo
  if 36 - 36: IiII % I11i
  if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
  if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
  if 82 - 82: OoooooooOO
  if 14 - 14: OoO0O00 / oO0o - OOooOOo
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
  if 16 - 16: IiII + Oo0Ooo % I11i
 def copy_elp_node ( self ) :
  ooOoIIi11iiI1 = lisp_elp_node ( )
  ooOoIIi11iiI1 . copy_address ( self . address )
  ooOoIIi11iiI1 . probe = self . probe
  ooOoIIi11iiI1 . strict = self . strict
  ooOoIIi11iiI1 . eid = self . eid
  ooOoIIi11iiI1 . we_are_last = self . we_are_last
  return ( ooOoIIi11iiI1 )
  if 16 - 16: ooOoO0o / I1Ii111
  if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
  if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 54 - 54: iIii1I11I1II1 % ooOoO0o
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
 def copy_elp ( self ) :
  i1I1I1i1I1 = lisp_elp ( self . elp_name )
  i1I1I1i1I1 . use_elp_node = self . use_elp_node
  i1I1I1i1I1 . we_are_last = self . we_are_last
  for ooOoIIi11iiI1 in self . elp_nodes :
   i1I1I1i1I1 . elp_nodes . append ( ooOoIIi11iiI1 . copy_elp_node ( ) )
   if 92 - 92: I11i + OoO0O00 . OoooooooOO
  return ( i1I1I1i1I1 )
  if 3 - 3: OoO0O00 % iIii1I11I1II1
  if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
 def print_elp ( self , want_marker ) :
  oOOo0oOoooO0o = ""
  for ooOoIIi11iiI1 in self . elp_nodes :
   ooOOoOo = ""
   if ( want_marker ) :
    if ( ooOoIIi11iiI1 == self . use_elp_node ) :
     ooOOoOo = "*"
    elif ( ooOoIIi11iiI1 . we_are_last ) :
     ooOOoOo = "x"
     if 6 - 6: o0oOOo0O0Ooo * OoOoOO00 . i11iIiiIii - IiII - i11iIiiIii / iII111i
     if 36 - 36: I11i . Ii1I - I1IiiI / II111iiii
   oOOo0oOoooO0o += "{}{}({}{}{}), " . format ( ooOOoOo ,
 ooOoIIi11iiI1 . address . print_address_no_iid ( ) ,
 "r" if ooOoIIi11iiI1 . eid else "R" , "P" if ooOoIIi11iiI1 . probe else "p" ,
 "S" if ooOoIIi11iiI1 . strict else "s" )
   if 57 - 57: OoOoOO00 % Ii1I
  return ( oOOo0oOoooO0o [ 0 : - 2 ] if oOOo0oOoooO0o != "" else "" )
  if 14 - 14: OoooooooOO - i11iIiiIii . OoooooooOO % I1ii11iIi11i + iII111i % iII111i
  if 58 - 58: I1Ii111 % Ii1I / I11i % i1IIi / OoO0O00
 def select_elp_node ( self ) :
  iiiI , i1iiIiII1II1 , o0OOOOOo0 = lisp_myrlocs
  ii = None
  if 17 - 17: iIii1I11I1II1 - Ii1I + IiII . Oo0Ooo + i11iIiiIii
  for ooOoIIi11iiI1 in self . elp_nodes :
   if ( iiiI and ooOoIIi11iiI1 . address . is_exact_match ( iiiI ) ) :
    ii = self . elp_nodes . index ( ooOoIIi11iiI1 )
    break
    if 97 - 97: ooOoO0o % II111iiii / Ii1I . iIii1I11I1II1
   if ( i1iiIiII1II1 and ooOoIIi11iiI1 . address . is_exact_match ( i1iiIiII1II1 ) ) :
    ii = self . elp_nodes . index ( ooOoIIi11iiI1 )
    break
    if 100 - 100: II111iiii / I11i * iIii1I11I1II1 / OOooOOo + i11iIiiIii - iIii1I11I1II1
    if 32 - 32: o0oOOo0O0Ooo - Ii1I / ooOoO0o % I1Ii111
    if 69 - 69: oO0o - I1IiiI . OOooOOo * OoooooooOO
    if 83 - 83: IiII % I1Ii111 % IiII - O0 % I1ii11iIi11i
    if 44 - 44: i11iIiiIii + oO0o * oO0o . i11iIiiIii % i1IIi + iII111i
    if 91 - 91: I1Ii111 . II111iiii / Ii1I * O0
    if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
  if ( ii == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   ooOoIIi11iiI1 . we_are_last = False
   return
   if 35 - 35: I1Ii111
   if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
   if 12 - 12: Oo0Ooo + I1IiiI
   if 12 - 12: OoOoOO00 / II111iiii
   if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
   if 28 - 28: I1IiiI
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ ii ] ) :
   self . use_elp_node = None
   ooOoIIi11iiI1 . we_are_last = True
   return
   if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
   if 46 - 46: II111iiii
   if 24 - 24: i11iIiiIii * i1IIi - I11i + o0oOOo0O0Ooo
   if 60 - 60: ooOoO0o
   if 62 - 62: i11iIiiIii
  self . use_elp_node = self . elp_nodes [ ii + 1 ]
  return
  if 88 - 88: i11iIiiIii
  if 59 - 59: oO0o - OoooooooOO % ooOoO0o
  if 90 - 90: OoOoOO00
class lisp_geo ( ) :
 def __init__ ( self , name ) :
  self . geo_name = name
  self . latitude = 0xffffffff
  self . lat_mins = 0
  self . lat_secs = 0
  self . longitude = 0xffffffff
  self . long_mins = 0
  self . long_secs = 0
  self . altitude = - 1
  self . radius = 0
  if 96 - 96: II111iiii % Ii1I
  if 84 - 84: I1IiiI . I1IiiI
 def copy_geo ( self ) :
  oOo00O = lisp_geo ( self . geo_name )
  oOo00O . latitude = self . latitude
  oOo00O . lat_mins = self . lat_mins
  oOo00O . lat_secs = self . lat_secs
  oOo00O . longitude = self . longitude
  oOo00O . long_mins = self . long_mins
  oOo00O . long_secs = self . long_secs
  oOo00O . altitude = self . altitude
  oOo00O . radius = self . radius
  return ( oOo00O )
  if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
  if 45 - 45: iII111i . oO0o * iII111i
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 3 - 3: OoOoOO00 / Oo0Ooo - Oo0Ooo
  if 54 - 54: Oo0Ooo . OoO0O00 * I1IiiI % IiII
 def parse_geo_string ( self , geo_str ) :
  ii = geo_str . find ( "]" )
  if ( ii != - 1 ) : geo_str = geo_str [ ii + 1 : : ]
  if 97 - 97: o0oOOo0O0Ooo + Ii1I
  if 77 - 77: I11i - oO0o . Ii1I
  if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
  if 74 - 74: ooOoO0o
  if 18 - 18: iIii1I11I1II1 - I11i - oO0o
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , IiIii11 = geo_str . split ( "/" )
   self . radius = int ( IiIii11 )
   if 32 - 32: Ii1I + Ii1I
   if 2 - 2: iIii1I11I1II1 - ooOoO0o
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 61 - 61: O0 / II111iiii + I1IiiI + I1ii11iIi11i * Oo0Ooo * I1ii11iIi11i
  Ii11Ii1IiiIi = geo_str [ 0 : 4 ]
  oO0Oo0O000 = geo_str [ 4 : 8 ]
  if 80 - 80: OOooOOo % OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
  if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
  if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
  if 14 - 14: iIii1I11I1II1
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
  if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
  if 84 - 84: OoO0O00 % OoooooooOO
  if 66 - 66: OoOoOO00 . iII111i
  self . latitude = int ( Ii11Ii1IiiIi [ 0 ] )
  self . lat_mins = int ( Ii11Ii1IiiIi [ 1 ] )
  self . lat_secs = int ( Ii11Ii1IiiIi [ 2 ] )
  if ( Ii11Ii1IiiIi [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 1 - 1: iII111i * i1IIi . iIii1I11I1II1 % O0 - OoooooooOO
  if 87 - 87: iII111i . Oo0Ooo * i11iIiiIii % o0oOOo0O0Ooo + Ii1I
  if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
  self . longitude = int ( oO0Oo0O000 [ 0 ] )
  self . long_mins = int ( oO0Oo0O000 [ 1 ] )
  self . long_secs = int ( oO0Oo0O000 [ 2 ] )
  if ( oO0Oo0O000 [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
 def print_geo ( self ) :
  OooO0o000Oo = "N" if self . latitude < 0 else "S"
  O00ooO00o0oO = "E" if self . longitude < 0 else "W"
  if 8 - 8: OOooOOo / Oo0Ooo + OoO0O00 + I1ii11iIi11i + OoooooooOO % i1IIi
  Ii1I1iiiI1 = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , OooO0o000Oo , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , O00ooO00o0oO )
  if 46 - 46: OoOoOO00
  if ( self . no_geo_altitude ( ) == False ) :
   Ii1I1iiiI1 += "-" + str ( self . altitude )
   if 75 - 75: I1IiiI
   if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
   if 14 - 14: i1IIi / ooOoO0o
   if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
   if 16 - 16: O0
  if ( self . radius != 0 ) : Ii1I1iiiI1 += "/{}" . format ( self . radius )
  return ( Ii1I1iiiI1 )
  if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
  if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
 def geo_url ( self ) :
  OooOoO = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  OooOoO = "10" if ( OooOoO == "" or OooOoO . isdigit ( ) == False ) else OooOoO
  OOOoOOo0 , iI111iIiiI = self . dms_to_decimal ( )
  O0O0OO0 = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( OOOoOOo0 , iI111iIiiI , OOOoOOo0 , iI111iIiiI ,
  # Oo0Ooo / I1ii11iIi11i
  # I1ii11iIi11i
 OooOoO )
  return ( O0O0OO0 )
  if 26 - 26: IiII . Ii1I
  if 35 - 35: I1ii11iIi11i + OOooOOo
 def print_geo_url ( self ) :
  oOo00O = self . print_geo ( )
  if ( self . radius == 0 ) :
   O0O0OO0 = self . geo_url ( )
   i1iiiIi11 = "<a href='{}'>{}</a>" . format ( O0O0OO0 , oOo00O )
  else :
   O0O0OO0 = oOo00O . replace ( "/" , "-" )
   i1iiiIi11 = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( O0O0OO0 , oOo00O )
   if 88 - 88: O0
  return ( i1iiiIi11 )
  if 4 - 4: OoOoOO00 % iIii1I11I1II1 % OoooooooOO . oO0o
  if 27 - 27: II111iiii - OoOoOO00
 def dms_to_decimal ( self ) :
  OO0OO0o0 , iIio0O , IiIIi1iIiI1I = self . latitude , self . lat_mins , self . lat_secs
  iiii111I = float ( abs ( OO0OO0o0 ) )
  iiii111I += float ( iIio0O * 60 + IiIIi1iIiI1I ) / 3600
  if ( OO0OO0o0 > 0 ) : iiii111I = - iiii111I
  o0Oo0OoOOoO00 = iiii111I
  if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
  OO0OO0o0 , iIio0O , IiIIi1iIiI1I = self . longitude , self . long_mins , self . long_secs
  iiii111I = float ( abs ( OO0OO0o0 ) )
  iiii111I += float ( iIio0O * 60 + IiIIi1iIiI1I ) / 3600
  if ( OO0OO0o0 > 0 ) : iiii111I = - iiii111I
  ooOOoOoooOO0o = iiii111I
  return ( ( o0Oo0OoOOoO00 , ooOOoOoooOO0o ) )
  if 14 - 14: Ii1I + OoooooooOO - I1Ii111 + I1Ii111 % IiII % OoooooooOO
  if 24 - 24: I1Ii111 . Oo0Ooo / ooOoO0o * O0
 def get_distance ( self , geo_point ) :
  oOOoo0ooo = self . dms_to_decimal ( )
  iiiO0ooo000 = geo_point . dms_to_decimal ( )
  I1iIi1ii = vincenty ( oOOoo0ooo , iiiO0ooo000 )
  return ( I1iIi1ii . km )
  if 72 - 72: iII111i * I1Ii111 + i11iIiiIii - iII111i % o0oOOo0O0Ooo + OOooOOo
  if 16 - 16: I11i
 def point_in_circle ( self , geo_point ) :
  iII1Ii1iIiIII = self . get_distance ( geo_point )
  return ( iII1Ii1iIiIII <= self . radius )
  if 74 - 74: i1IIi
  if 34 - 34: I1IiiI . II111iiii
 def encode_geo ( self ) :
  ooo0o0oOoOO0 = socket . htons ( LISP_AFI_LCAF )
  OO00000OO00oo = socket . htons ( 20 + 2 )
  OoOoo0ooO0000 = 0
  if 100 - 100: OoO0O00 / O0 / OoOoOO00
  OOOoOOo0 = abs ( self . latitude )
  iiiIi = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : OoOoo0ooO0000 |= 0x40
  if 8 - 8: I1IiiI * OOooOOo * IiII / I1IiiI + i1IIi
  iI111iIiiI = abs ( self . longitude )
  I111Ii1ii1I1i = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : OoOoo0ooO0000 |= 0x20
  if 97 - 97: O0 % ooOoO0o . Ii1I - ooOoO0o - I1ii11iIi11i
  OO0OOOooO = 0
  if ( self . no_geo_altitude ( ) == False ) :
   OO0OOOooO = socket . htonl ( self . altitude )
   OoOoo0ooO0000 |= 0x10
   if 35 - 35: OoooooooOO * ooOoO0o + i11iIiiIii % i1IIi / ooOoO0o
  IiIii11 = socket . htons ( self . radius )
  if ( IiIii11 != 0 ) : OoOoo0ooO0000 |= 0x06
  if 11 - 11: O0 * iII111i
  oOo000o = struct . pack ( "HBBBBH" , ooo0o0oOoOO0 , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , OO00000OO00oo )
  oOo000o += struct . pack ( "BBHBBHBBHIHHH" , OoOoo0ooO0000 , 0 , 0 , OOOoOOo0 , iiiIi >> 16 ,
 socket . htons ( iiiIi & 0x0ffff ) , iI111iIiiI , I111Ii1ii1I1i >> 16 ,
 socket . htons ( I111Ii1ii1I1i & 0xffff ) , OO0OOOooO , IiIii11 , 0 , 0 )
  if 98 - 98: I1IiiI - oO0o / i11iIiiIii % I1ii11iIi11i * oO0o * OoO0O00
  return ( oOo000o )
  if 74 - 74: I1Ii111 . I1ii11iIi11i - Ii1I * i11iIiiIii
  if 36 - 36: II111iiii * Ii1I
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  Iii1 = "BBHBBHBBHIHHH"
  O00O = struct . calcsize ( Iii1 )
  if ( lcaf_len < O00O ) : return ( None )
  if 53 - 53: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I
  OoOoo0ooO0000 , o00o0OOoO0o , OOO0oOOoo , OOOoOOo0 , OOOooo0O , iiiIi , iI111iIiiI , OO0O0i1iII1 , I111Ii1ii1I1i , OO0OOOooO , IiIii11 , OOOoI11 , ii1iI1i1 = struct . unpack ( Iii1 ,
  # ooOoO0o % O0 . OoOoOO00
 packet [ : O00O ] )
  if 44 - 44: OoooooooOO + i1IIi + I11i
  if 21 - 21: IiII . i11iIiiIii
  if 66 - 66: i1IIi - II111iiii . O0 % O0 . I11i
  if 5 - 5: OoOoOO00
  ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
  if ( ii1iI1i1 == LISP_AFI_LCAF ) : return ( None )
  if 31 - 31: ooOoO0o - OOooOOo
  if ( OoOoo0ooO0000 & 0x40 ) : OOOoOOo0 = - OOOoOOo0
  self . latitude = OOOoOOo0
  o00oOooo0 = ( ( OOOooo0O << 16 ) | socket . ntohs ( iiiIi ) ) / 1000
  self . lat_mins = o00oOooo0 / 60
  self . lat_secs = o00oOooo0 % 60
  if 54 - 54: I11i % o0oOOo0O0Ooo
  if ( OoOoo0ooO0000 & 0x20 ) : iI111iIiiI = - iI111iIiiI
  self . longitude = iI111iIiiI
  iIIIii1ii = ( ( OO0O0i1iII1 << 16 ) | socket . ntohs ( I111Ii1ii1I1i ) ) / 1000
  self . long_mins = iIIIii1ii / 60
  self . long_secs = iIIIii1ii % 60
  if 68 - 68: OoooooooOO . iIii1I11I1II1 - Ii1I / OoO0O00 / oO0o
  self . altitude = socket . ntohl ( OO0OOOooO ) if ( OoOoo0ooO0000 & 0x10 ) else - 1
  IiIii11 = socket . ntohs ( IiIii11 )
  self . radius = IiIii11 if ( OoOoo0ooO0000 & 0x02 ) else IiIii11 * 1000
  if 14 - 14: OOooOOo + iIii1I11I1II1 - Ii1I % I11i % OoO0O00 - i11iIiiIii
  self . geo_name = None
  packet = packet [ O00O : : ]
  if 88 - 88: iII111i / I11i / I1ii11iIi11i + IiII * OoooooooOO . IiII
  if ( ii1iI1i1 != 0 ) :
   self . rloc . afi = ii1iI1i1
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 3 - 3: ooOoO0o - Oo0Ooo
  return ( packet )
  if 86 - 86: I1ii11iIi11i * I1Ii111 / o0oOOo0O0Ooo . OoO0O00
  if 14 - 14: I11i * IiII / iIii1I11I1II1
  if 88 - 88: OoOoOO00 % II111iiii . I1IiiI / oO0o * IiII / i11iIiiIii
  if 76 - 76: o0oOOo0O0Ooo
  if 80 - 80: OOooOOo
  if 15 - 15: OOooOOo . OoOoOO00 / oO0o . I1ii11iIi11i % OoO0O00 - oO0o
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 21 - 21: ooOoO0o . o0oOOo0O0Ooo . oO0o . i1IIi
  if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
 def copy_rle_node ( self ) :
  iiiI1Ii = lisp_rle_node ( )
  iiiI1Ii . address . copy_address ( self . address )
  iiiI1Ii . level = self . level
  iiiI1Ii . translated_port = self . translated_port
  iiiI1Ii . rloc_name = self . rloc_name
  return ( iiiI1Ii )
  if 8 - 8: O0 + o0oOOo0O0Ooo / O0 - I1ii11iIi11i % I1ii11iIi11i
  if 55 - 55: OoooooooOO * OoooooooOO % I1Ii111 / Ii1I / ooOoO0o
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 12 - 12: i11iIiiIii + Ii1I % iIii1I11I1II1 + I1Ii111
  if 12 - 12: Ii1I + I1Ii111 / O0 * II111iiii
 def get_encap_keys ( self ) :
  IIIIiI1ii1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 67 - 67: iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111 * oO0o
  O0o = self . address . print_address_no_iid ( ) + ":" + IIIIiI1ii1
  if 100 - 100: OoooooooOO % I1IiiI / OoOoOO00 % OoOoOO00 . o0oOOo0O0Ooo
  try :
   iIIi111IiII1i = lisp_crypto_keys_by_rloc_encap [ O0o ]
   if ( iIIi111IiII1i [ 1 ] ) : return ( iIIi111IiII1i [ 1 ] . encrypt_key , iIIi111IiII1i [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 81 - 81: Ii1I - II111iiii + I11i / Ii1I
   if 89 - 89: i11iIiiIii + I1ii11iIi11i - ooOoO0o . ooOoO0o + Oo0Ooo % Ii1I
   if 96 - 96: I1Ii111 - I11i * I1Ii111
   if 32 - 32: I1IiiI / i1IIi / I1ii11iIi11i % i1IIi . ooOoO0o % I1ii11iIi11i
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 97 - 97: OoO0O00 . OOooOOo % Ii1I + OoooooooOO * I1Ii111
  if 89 - 89: I11i
 def copy_rle ( self ) :
  I1i1i111Ii1I = lisp_rle ( self . rle_name )
  for iiiI1Ii in self . rle_nodes :
   I1i1i111Ii1I . rle_nodes . append ( iiiI1Ii . copy_rle_node ( ) )
   if 91 - 91: OoooooooOO - IiII - Ii1I
  I1i1i111Ii1I . build_forwarding_list ( )
  return ( I1i1i111Ii1I )
  if 36 - 36: OOooOOo
  if 76 - 76: OoO0O00 . i1IIi
 def print_rle ( self , html ) :
  oooOOOO0oO0O = ""
  for iiiI1Ii in self . rle_nodes :
   IIIIiI1ii1 = iiiI1Ii . translated_port
   o0OOoOooo0 = blue ( iiiI1Ii . rloc_name , html ) if iiiI1Ii . rloc_name != None else ""
   if 46 - 46: OOooOOo / Ii1I
   O0o = iiiI1Ii . address . print_address_no_iid ( )
   if ( iiiI1Ii . address . is_local ( ) ) : O0o = red ( O0o , html )
   oooOOOO0oO0O += "{}{}(L{}){}, " . format ( O0o , "" if IIIIiI1ii1 == 0 else "-" + str ( IIIIiI1ii1 ) , iiiI1Ii . level ,
   # i11iIiiIii - I1Ii111 % OoOoOO00 % IiII + I11i
 "" if iiiI1Ii . rloc_name == None else o0OOoOooo0 )
   if 52 - 52: ooOoO0o % ooOoO0o
  return ( oooOOOO0oO0O [ 0 : - 2 ] if oooOOOO0oO0O != "" else "" )
  if 58 - 58: OOooOOo
  if 74 - 74: i1IIi . IiII / ooOoO0o + I11i % i11iIiiIii % iII111i
 def build_forwarding_list ( self ) :
  IiIiIii11Ii = - 1
  for iiiI1Ii in self . rle_nodes :
   if ( IiIiIii11Ii == - 1 ) :
    if ( iiiI1Ii . address . is_local ( ) ) : IiIiIii11Ii = iiiI1Ii . level
   else :
    if ( iiiI1Ii . level > IiIiIii11Ii ) : break
    if 62 - 62: i1IIi % I1Ii111
    if 94 - 94: i1IIi + iII111i
  IiIiIii11Ii = 0 if IiIiIii11Ii == - 1 else iiiI1Ii . level
  if 25 - 25: I1Ii111 . Ii1I - Ii1I . o0oOOo0O0Ooo - IiII
  self . rle_forwarding_list = [ ]
  for iiiI1Ii in self . rle_nodes :
   if ( iiiI1Ii . level == IiIiIii11Ii or ( IiIiIii11Ii == 0 and
 iiiI1Ii . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and iiiI1Ii . address . is_local ( ) ) :
     O0o = iiiI1Ii . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( O0o ) )
     continue
     if 91 - 91: o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * iIii1I11I1II1
    self . rle_forwarding_list . append ( iiiI1Ii )
    if 18 - 18: OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
    if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
    if 23 - 23: Oo0Ooo
    if 7 - 7: Oo0Ooo / oO0o . I1Ii111 % I11i
    if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
  if 50 - 50: IiII / OoooooooOO . I11i
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
  if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
   if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
   if 79 - 79: OoO0O00 + ooOoO0o / oO0o % I1ii11iIi11i
 def print_json ( self , html ) :
  o0o0 = self . json_string
  III = "***"
  if ( html ) : III = red ( III , html )
  O0ooo0Oo00O00 = III + self . json_string + III
  if ( self . valid_json ( ) ) : return ( o0o0 )
  return ( O0ooo0Oo00O00 )
  if 21 - 21: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO * O0
  if 52 - 52: OOooOOo / ooOoO0o . II111iiii / Oo0Ooo
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 66 - 66: Ii1I * I1Ii111 * OoO0O00
  return ( True )
  if 92 - 92: II111iiii * iII111i % OoOoOO00 % OoOoOO00 % i11iIiiIii
  if 93 - 93: Ii1I + iIii1I11I1II1 % Ii1I . iIii1I11I1II1
  if 48 - 48: OoooooooOO - O0 + I1IiiI - I11i
  if 86 - 86: i11iIiiIii / IiII + i11iIiiIii + o0oOOo0O0Ooo . I1Ii111 . I1Ii111
  if 90 - 90: ooOoO0o % Ii1I
  if 12 - 12: OoooooooOO . OoooooooOO * I11i
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
  if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
  if 98 - 98: II111iiii - i1IIi - ooOoO0o
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  OOo0 = time . time ( ) - self . last_increment
  return ( OOo0 <= 1 )
  if 36 - 36: IiII + o0oOOo0O0Ooo
  if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  OOo0 = time . time ( ) - self . last_increment
  return ( OOo0 <= 60 )
  if 10 - 10: oO0o / i11iIiiIii
  if 73 - 73: OoO0O00 - i1IIi
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 52 - 52: I1ii11iIi11i
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
  return ( c1 , c2 )
  if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
 def normalize ( self , count ) :
  count = str ( count )
  i11IIi = len ( count )
  if ( i11IIi > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 2 - 2: I1IiiI + II111iiii . ooOoO0o + oO0o . OoO0O00
  if ( i11IIi > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 49 - 49: OoO0O00 . IiII
  if ( i11IIi > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 41 - 41: OoooooooOO + oO0o % oO0o / I1ii11iIi11i
  return ( count )
  if 86 - 86: i1IIi
  if 73 - 73: iIii1I11I1II1 * Oo0Ooo
 def get_stats ( self , summary , html ) :
  oOo0 = self . last_rate_check
  OOo00oo0o = self . last_packet_count
  iiI1 = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 14 - 14: I1Ii111 * OoOoOO00 . I1Ii111 / o0oOOo0O0Ooo
  iIiIi1 = self . last_rate_check - oOo0
  if ( iIiIi1 == 0 ) :
   ooOoOO00o0 = 0
   ii1III1IiIII1 = 0
  else :
   ooOoOO00o0 = int ( ( self . packet_count - OOo00oo0o ) / iIiIi1 )
   ii1III1IiIII1 = ( self . byte_count - iiI1 ) / iIiIi1
   ii1III1IiIII1 = ( ii1III1IiIII1 * 8 ) / 1000000
   ii1III1IiIII1 = round ( ii1III1IiIII1 , 2 )
   if 51 - 51: I1ii11iIi11i * OOooOOo
   if 100 - 100: OoO0O00 * oO0o + I1IiiI - o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoO0O00
   if 65 - 65: OoooooooOO / OoOoOO00 + I1IiiI - II111iiii / OoOoOO00
   if 69 - 69: i11iIiiIii
   if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
  Oo0o0OoO00 = self . normalize ( self . packet_count )
  II1III = self . normalize ( self . byte_count )
  if 83 - 83: ooOoO0o
  if 59 - 59: I1ii11iIi11i
  if 26 - 26: I11i . Ii1I
  if 94 - 94: ooOoO0o . I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 21 - 21: O0 / OOooOOo - II111iiii + I1ii11iIi11i / OoooooooOO
  if ( summary ) :
   Oo0O = "<br>" if html else ""
   Oo0o0OoO00 , II1III = self . stat_colors ( Oo0o0OoO00 , II1III , html )
   iI1iIi1 = "packet-count: {}{}byte-count: {}" . format ( Oo0o0OoO00 , Oo0O , II1III )
   i1ii11 = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( ooOoOO00o0 , ii1III1IiIII1 )
   if 94 - 94: i11iIiiIii
   if ( html != "" ) : i1ii11 = lisp_span ( iI1iIi1 , i1ii11 )
  else :
   O0Oo00 = str ( ooOoOO00o0 )
   o00O0000O = str ( ii1III1IiIII1 )
   if ( html ) :
    Oo0o0OoO00 = lisp_print_cour ( Oo0o0OoO00 )
    O0Oo00 = lisp_print_cour ( O0Oo00 )
    II1III = lisp_print_cour ( II1III )
    o00O0000O = lisp_print_cour ( o00O0000O )
    if 15 - 15: I1Ii111 % O0 . iIii1I11I1II1 . iIii1I11I1II1 * ooOoO0o
   Oo0O = "<br>" if html else ", "
   if 37 - 37: ooOoO0o * OoOoOO00 . ooOoO0o
   i1ii11 = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( Oo0o0OoO00 , Oo0O , O0Oo00 , Oo0O , II1III , Oo0O ,
   # Oo0Ooo + OoooooooOO . iIii1I11I1II1
 o00O0000O )
   if 76 - 76: iIii1I11I1II1 - OOooOOo
  return ( i1ii11 )
  if 77 - 77: iIii1I11I1II1 % I1Ii111 + II111iiii
  if 40 - 40: I1ii11iIi11i / I1ii11iIi11i + I1IiiI + OoOoOO00
  if 76 - 76: iIii1I11I1II1 . iIii1I11I1II1 / OOooOOo / OoOoOO00 / iII111i / II111iiii
  if 64 - 64: i1IIi * II111iiii + I1ii11iIi11i + OOooOOo % I1ii11iIi11i - OoooooooOO
  if 96 - 96: IiII + oO0o / Oo0Ooo + OoooooooOO
  if 53 - 53: Ii1I * IiII + Oo0Ooo + i11iIiiIii - iIii1I11I1II1
  if 66 - 66: O0 - I1ii11iIi11i * iIii1I11I1II1 - I1Ii111 / I1ii11iIi11i
  if 24 - 24: Ii1I
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 39 - 39: O0 % Ii1I
if 63 - 63: OOooOOo / I1ii11iIi11i
if 11 - 11: O0 % iIii1I11I1II1
if 64 - 64: OoOoOO00 - oO0o
class lisp_rloc ( ) :
 def __init__ ( self , recurse = True ) :
  self . rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . rloc_name = None
  self . interface = None
  self . translated_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . translated_port = 0
  self . priority = 255
  self . weight = 0
  self . mpriority = 255
  self . mweight = 0
  self . uptime = 0
  self . state = LISP_RLOC_UP_STATE
  self . last_state_change = None
  self . rle_name = None
  self . elp_name = None
  self . geo_name = None
  self . json_name = None
  self . geo = None
  self . elp = None
  self . rle = None
  self . json = None
  self . stats = lisp_stats ( )
  self . last_rloc_probe = None
  self . last_rloc_probe_reply = None
  self . rloc_probe_rtt = - 1
  self . recent_rloc_probe_rtts = [ - 1 , - 1 , - 1 ]
  self . rloc_probe_hops = "?/?"
  self . recent_rloc_probe_hops = [ "?/?" , "?/?" , "?/?" ]
  self . last_rloc_probe_nonce = 0
  self . echo_nonce_capable = False
  self . map_notify_requested = False
  self . rloc_next_hop = None
  self . next_rloc = None
  if 8 - 8: i11iIiiIii - iIii1I11I1II1 / I1Ii111 . i11iIiiIii % o0oOOo0O0Ooo / oO0o
  if ( recurse == False ) : return
  if 36 - 36: IiII
  if 53 - 53: OoooooooOO / I1IiiI % I11i + Oo0Ooo
  if 15 - 15: O0
  if 75 - 75: iII111i / OoOoOO00
  if 2 - 2: i1IIi + oO0o % iII111i % I1ii11iIi11i + ooOoO0o . iII111i
  if 26 - 26: I11i + o0oOOo0O0Ooo + Ii1I % I11i
  O00o0OoO = lisp_get_default_route_next_hops ( )
  if ( O00o0OoO == [ ] or len ( O00o0OoO ) == 1 ) : return
  if 3 - 3: i11iIiiIii / I1Ii111
  self . rloc_next_hop = O00o0OoO [ 0 ]
  O0ooO0oOO = self
  for iiIIIi1I in O00o0OoO [ 1 : : ] :
   OO0ooo = lisp_rloc ( False )
   OO0ooo = copy . deepcopy ( self )
   OO0ooo . rloc_next_hop = iiIIIi1I
   O0ooO0oOO . next_rloc = OO0ooo
   O0ooO0oOO = OO0ooo
   if 75 - 75: i1IIi * II111iiii . II111iiii * I1Ii111 + I1Ii111
   if 25 - 25: oO0o
   if 33 - 33: o0oOOo0O0Ooo * OOooOOo
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 7 - 7: i11iIiiIii . OOooOOo * Ii1I . i1IIi
  if 4 - 4: O0 - IiII - II111iiii / iII111i - OOooOOo
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 6 - 6: ooOoO0o + OOooOOo - I1IiiI + OOooOOo
  if 16 - 16: OoO0O00 * OoOoOO00 - Oo0Ooo
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 44 - 44: ooOoO0o / OoOoOO00 - O0 + iII111i / iIii1I11I1II1
  if 41 - 41: iIii1I11I1II1 - iII111i / O0
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 39 - 39: OoooooooOO * iIii1I11I1II1 - o0oOOo0O0Ooo / O0
  if 29 - 29: I11i % OoOoOO00 - oO0o + II111iiii . II111iiii
  if 25 - 25: Oo0Ooo * ooOoO0o % I1Ii111
 def print_state ( self ) :
  if ( self . state is LISP_RLOC_UNKNOWN_STATE ) :
   return ( "unknown-state" )
  if ( self . state is LISP_RLOC_UP_STATE ) :
   return ( "up-state" )
  if ( self . state is LISP_RLOC_DOWN_STATE ) :
   return ( "down-state" )
  if ( self . state is LISP_RLOC_ADMIN_DOWN_STATE ) :
   return ( "admin-down-state" )
  if ( self . state is LISP_RLOC_UNREACH_STATE ) :
   return ( "unreach-state" )
  if ( self . state is LISP_RLOC_NO_ECHOED_NONCE_STATE ) :
   return ( "no-echoed-nonce-state" )
  return ( "invalid-state" )
  if 34 - 34: OoOoOO00 / I1Ii111 - ooOoO0o
  if 66 - 66: I11i * OoO0O00
 def print_rloc ( self , indent ) :
  I11i1II = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , I11i1II , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 98 - 98: IiII . Oo0Ooo + I1Ii111
  if 63 - 63: oO0o * I1IiiI * oO0o
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  i1i11i1 = self . rloc_name
  if ( cour ) : i1i11i1 = lisp_print_cour ( i1i11i1 )
  return ( 'rloc-name: {}' . format ( blue ( i1i11i1 , cour ) ) )
  if 56 - 56: oO0o - Ii1I % I1Ii111
  if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  IIIIiI1ii1 = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 12 - 12: I1IiiI
  if 32 - 32: I1Ii111
  if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
  if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
  IiiI11iiI1i1 = self . rloc
  if ( IiiI11iiI1i1 . is_null ( ) == False ) :
   OOOOoooO0 = lisp_get_nat_info ( IiiI11iiI1i1 , self . rloc_name )
   if ( OOOOoooO0 ) :
    IIIIiI1ii1 = OOOOoooO0 . port
    oOOOo000000 = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    O0o = IiiI11iiI1i1 . print_address_no_iid ( )
    iII = red ( O0o , False )
    Oo00Oo0o0O = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 25 - 25: oO0o + I1Ii111 . i1IIi
    if 4 - 4: o0oOOo0O0Ooo * iII111i - OoO0O00 . Ii1I / IiII * OoO0O00
    if 78 - 78: O0
    if 66 - 66: Ii1I + O0 . Ii1I % IiII % I1ii11iIi11i - OoOoOO00
    if 94 - 94: I1IiiI . I1Ii111
    if 37 - 37: i1IIi - O0
    if ( OOOOoooO0 . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( iII , IIIIiI1ii1 , Oo00Oo0o0O ) )
     if 36 - 36: I1Ii111 . OoooooooOO - i1IIi % iII111i - II111iiii * i11iIiiIii
     if 90 - 90: OoOoOO00 % iII111i - Oo0Ooo
     OOOOoooO0 = None if ( OOOOoooO0 == oOOOo000000 ) else oOOOo000000
     if ( OOOOoooO0 and OOOOoooO0 . timed_out ( ) ) :
      IIIIiI1ii1 = OOOOoooO0 . port
      iII = red ( OOOOoooO0 . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( iII , IIIIiI1ii1 ,
      # I1ii11iIi11i
 Oo00Oo0o0O ) )
      OOOOoooO0 = None
      if 20 - 20: O0 . I1Ii111 * Ii1I * II111iiii
      if 66 - 66: Ii1I % OoO0O00 % II111iiii - OOooOOo * o0oOOo0O0Ooo
      if 33 - 33: OoooooooOO / I11i
      if 98 - 98: I1ii11iIi11i . Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
      if 74 - 74: Oo0Ooo * I1Ii111
      if 72 - 72: OoOoOO00 + O0 - IiII * ooOoO0o
      if 20 - 20: II111iiii % OoOoOO00 * i11iIiiIii
    if ( OOOOoooO0 ) :
     if ( OOOOoooO0 . address != O0o ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( iII , red ( OOOOoooO0 . address , False ) ) )
      if 68 - 68: IiII / ooOoO0o
      self . rloc . store_address ( OOOOoooO0 . address )
      if 100 - 100: ooOoO0o / I1IiiI
     iII = red ( OOOOoooO0 . address , False )
     IIIIiI1ii1 = OOOOoooO0 . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( iII , IIIIiI1ii1 , Oo00Oo0o0O ) )
     if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
     self . store_translated_rloc ( IiiI11iiI1i1 , IIIIiI1ii1 )
     if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
     if 64 - 64: i1IIi
     if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
     if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 5 - 5: OoOoOO00 % i1IIi
  if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
  if 76 - 76: Oo0Ooo + I1IiiI - O0
  if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for iiiI1Ii in self . rle . rle_nodes :
    i1i11i1 = iiiI1Ii . rloc_name
    OOOOoooO0 = lisp_get_nat_info ( iiiI1Ii . address , i1i11i1 )
    if ( OOOOoooO0 == None ) : continue
    if 73 - 73: Oo0Ooo . OoOoOO00
    IIIIiI1ii1 = OOOOoooO0 . port
    OO0o0ooo0o0 = i1i11i1
    if ( OO0o0ooo0o0 ) : OO0o0ooo0o0 = blue ( i1i11i1 , False )
    if 50 - 50: IiII / o0oOOo0O0Ooo
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( IIIIiI1ii1 ,
    # oO0o
 iiiI1Ii . address . print_address_no_iid ( ) , OO0o0ooo0o0 ) )
    iiiI1Ii . translated_port = IIIIiI1ii1
    if 53 - 53: OoO0O00 + iII111i / OoooooooOO
    if 52 - 52: O0
    if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
  if 83 - 83: oO0o / OoO0O00
  if 34 - 34: OoooooooOO - i1IIi * O0
  oOOO0O = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 77 - 77: II111iiii
  if ( rloc_record . keys != None and oOOO0O ) :
   OOo0O = rloc_record . keys [ 1 ]
   if ( OOo0O != None ) :
    O0o = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( IIIIiI1ii1 )
    if 92 - 92: I1Ii111 / I1IiiI / I1ii11iIi11i + I11i + Ii1I
    OOo0O . add_key_by_rloc ( O0o , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( O0o , False ) ) )
    if 51 - 51: OOooOOo
    if 85 - 85: II111iiii
    if 60 - 60: Ii1I * OOooOOo - o0oOOo0O0Ooo - Ii1I / Oo0Ooo . OOooOOo
  return ( IIIIiI1ii1 )
  if 43 - 43: II111iiii * o0oOOo0O0Ooo % o0oOOo0O0Ooo + iIii1I11I1II1 + OoOoOO00
  if 54 - 54: II111iiii + OOooOOo * Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
  if 81 - 81: I11i - o0oOOo0O0Ooo % Ii1I / I1Ii111 * II111iiii
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 40 - 40: OoO0O00 . i11iIiiIii
  if 36 - 36: o0oOOo0O0Ooo * iII111i / I1ii11iIi11i % i1IIi % I1ii11iIi11i + i11iIiiIii
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 24 - 24: I1Ii111 / ooOoO0o - i11iIiiIii
  return ( True )
  if 32 - 32: II111iiii * Ii1I . ooOoO0o * Oo0Ooo - I1ii11iIi11i % I11i
  if 96 - 96: Ii1I / OOooOOo / O0
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 8 - 8: iII111i + OOooOOo / I1ii11iIi11i . iII111i
  if 45 - 45: i1IIi
  if 28 - 28: iII111i
 def print_state_change ( self , new_state ) :
  IiI1iI1I = self . print_state ( )
  i1iiiIi11 = "{} -> {}" . format ( IiI1iI1I , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   i1iiiIi11 = bold ( i1iiiIi11 , False )
   if 63 - 63: I11i
  return ( i1iiiIi11 )
  if 42 - 42: OOooOOo * ooOoO0o / i1IIi . i11iIiiIii - oO0o - Ii1I
  if 5 - 5: i1IIi + II111iiii . ooOoO0o
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 21 - 21: i1IIi
  if 96 - 96: OoOoOO00 * OoOoOO00 % OoO0O00 * iII111i
 def print_recent_rloc_probe_rtts ( self ) :
  ooOo0O = str ( self . recent_rloc_probe_rtts )
  ooOo0O = ooOo0O . replace ( "-1" , "?" )
  return ( ooOo0O )
  if 26 - 26: Oo0Ooo
  if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
 def compute_rloc_probe_rtt ( self ) :
  O0ooO0oOO = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  iI1IIiiI11IiI = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ O0ooO0oOO ] + iI1IIiiI11IiI [ 0 : - 1 ]
  if 94 - 94: i1IIi - i11iIiiIii + I1Ii111 % Oo0Ooo % Oo0Ooo . OoO0O00
  if 65 - 65: IiII * I11i * o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoOoOO00 % OoOoOO00
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 55 - 55: i11iIiiIii * II111iiii
  if 41 - 41: iIii1I11I1II1
 def print_recent_rloc_probe_hops ( self ) :
  iIIiI = str ( self . recent_rloc_probe_hops )
  return ( iIIiI )
  if 76 - 76: I1ii11iIi11i * i1IIi % oO0o
  if 80 - 80: i1IIi * II111iiii . O0 % I1ii11iIi11i / ooOoO0o
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 58 - 58: I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   i1111I1 = "!"
  else :
   i1111I1 = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 35 - 35: OoooooooOO
   if 13 - 13: oO0o - O0 * i11iIiiIii / IiII / IiII
  O0ooO0oOO = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + i1111I1
  iI1IIiiI11IiI = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ O0ooO0oOO ] + iI1IIiiI11IiI [ 0 : - 1 ]
  if 72 - 72: i11iIiiIii * OoOoOO00 % oO0o / I1Ii111
  if 9 - 9: iIii1I11I1II1 . IiII
 def process_rloc_probe_reply ( self , nonce , eid , group , hop_count , ttl ) :
  IiiI11iiI1i1 = self
  while ( True ) :
   if ( IiiI11iiI1i1 . last_rloc_probe_nonce == nonce ) : break
   IiiI11iiI1i1 = IiiI11iiI1i1 . next_rloc
   if ( IiiI11iiI1i1 == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
    return
    if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
    if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
    if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
  IiiI11iiI1i1 . last_rloc_probe_reply = lisp_get_timestamp ( )
  IiiI11iiI1i1 . compute_rloc_probe_rtt ( )
  O0oO = IiiI11iiI1i1 . print_state_change ( "up" )
  if ( IiiI11iiI1i1 . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( IiiI11iiI1i1 . rloc , True )
   IiiI11iiI1i1 . state = LISP_RLOC_UP_STATE
   IiiI11iiI1i1 . last_state_change = lisp_get_timestamp ( )
   IIo0OooOO = lisp_map_cache . lookup_cache ( eid , True )
   if ( IIo0OooOO ) : lisp_write_ipc_map_cache ( True , IIo0OooOO )
   if 75 - 75: I1IiiI * ooOoO0o % oO0o / i11iIiiIii
   if 91 - 91: OOooOOo
  IiiI11iiI1i1 . store_rloc_probe_hops ( hop_count , ttl )
  if 60 - 60: i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  ii1I = bold ( "RLOC-probe reply" , False )
  O0o = IiiI11iiI1i1 . rloc . print_address_no_iid ( )
  O0O0o = bold ( str ( IiiI11iiI1i1 . print_rloc_probe_rtt ( ) ) , False )
  Ii1Ii = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 90 - 90: o0oOOo0O0Ooo . o0oOOo0O0Ooo
  iiIIIi1I = ""
  if ( IiiI11iiI1i1 . rloc_next_hop != None ) :
   iiiii111 , IIIiI = IiiI11iiI1i1 . rloc_next_hop
   iiIIIi1I = ", nh {}({})" . format ( IIIiI , iiiii111 )
   if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
   if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  IIIII1iii11 = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( ii1I , red ( O0o , False ) , Ii1Ii , IIIII1iii11 ,
  # I11i % ooOoO0o / I1Ii111 * i11iIiiIii
 O0oO , O0O0o , iiIIIi1I , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 75 - 75: IiII
  if ( IiiI11iiI1i1 . rloc_next_hop == None ) : return
  if 15 - 15: oO0o
  if 40 - 40: I1Ii111
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
  if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
  IiiI11iiI1i1 = None
  o0o0I1Ii111 = None
  while ( True ) :
   IiiI11iiI1i1 = self if IiiI11iiI1i1 == None else IiiI11iiI1i1 . next_rloc
   if ( IiiI11iiI1i1 == None ) : break
   if ( IiiI11iiI1i1 . up_state ( ) == False ) : continue
   if ( IiiI11iiI1i1 . rloc_probe_rtt == - 1 ) : continue
   if 7 - 7: I1Ii111 - I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoO0O00
   if ( o0o0I1Ii111 == None ) : o0o0I1Ii111 = IiiI11iiI1i1
   if ( IiiI11iiI1i1 . rloc_probe_rtt < o0o0I1Ii111 . rloc_probe_rtt ) : o0o0I1Ii111 = IiiI11iiI1i1
   if 17 - 17: I1IiiI * Ii1I . i11iIiiIii - oO0o . i11iIiiIii + Oo0Ooo
   if 42 - 42: iII111i
  if ( o0o0I1Ii111 != None ) :
   iiiii111 , IIIiI = o0o0I1Ii111 . rloc_next_hop
   iiIIIi1I = bold ( "nh {}({})" . format ( IIIiI , iiiii111 ) , False )
   lprint ( "    Install host-route via best {}" . format ( iiIIIi1I ) )
   lisp_install_host_route ( O0o , None , False )
   lisp_install_host_route ( O0o , IIIiI , True )
   if 51 - 51: I1IiiI - OoOoOO00 * I1Ii111 * iIii1I11I1II1
   if 5 - 5: i11iIiiIii / o0oOOo0O0Ooo
   if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
 def add_to_rloc_probe_list ( self , eid , group ) :
  O0o = self . rloc . print_address_no_iid ( )
  IIIIiI1ii1 = self . translated_port
  if ( IIIIiI1ii1 != 0 ) : O0o += ":" + str ( IIIIiI1ii1 )
  if 12 - 12: I1ii11iIi11i / O0
  if ( lisp_rloc_probe_list . has_key ( O0o ) == False ) :
   lisp_rloc_probe_list [ O0o ] = [ ]
   if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
   if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
  if ( group . is_null ( ) ) : group . instance_id = 0
  for oO , IIIII1iii11 , I1I1i1 in lisp_rloc_probe_list [ O0o ] :
   if ( IIIII1iii11 . is_exact_match ( eid ) and I1I1i1 . is_exact_match ( group ) ) :
    if ( oO == self ) :
     if ( lisp_rloc_probe_list [ O0o ] == [ ] ) :
      lisp_rloc_probe_list . pop ( O0o )
      if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
     return
     if 16 - 16: I1IiiI + I11i
    lisp_rloc_probe_list [ O0o ] . remove ( [ oO , IIIII1iii11 , I1I1i1 ] )
    break
    if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
    if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
  lisp_rloc_probe_list [ O0o ] . append ( [ self , eid , group ] )
  if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
  if 78 - 78: i1IIi / ooOoO0o / oO0o
  if 21 - 21: IiII % Ii1I + OOooOOo + IiII
  if 90 - 90: o0oOOo0O0Ooo
  if 38 - 38: OoOoOO00 / OOooOOo % OoooooooOO * I1ii11iIi11i
  IiiI11iiI1i1 = lisp_rloc_probe_list [ O0o ] [ 0 ] [ 0 ]
  if ( IiiI11iiI1i1 . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 7 - 7: I11i * O0 + Oo0Ooo / O0 * oO0o + i11iIiiIii
   if 74 - 74: OoOoOO00
   if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
 def delete_from_rloc_probe_list ( self , eid , group ) :
  O0o = self . rloc . print_address_no_iid ( )
  IIIIiI1ii1 = self . translated_port
  if ( IIIIiI1ii1 != 0 ) : O0o += ":" + str ( IIIIiI1ii1 )
  if ( lisp_rloc_probe_list . has_key ( O0o ) == False ) : return
  if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
  o0oO00o00 = [ ]
  for i1II1IiiIi in lisp_rloc_probe_list [ O0o ] :
   if ( i1II1IiiIi [ 0 ] != self ) : continue
   if ( i1II1IiiIi [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( i1II1IiiIi [ 2 ] . is_exact_match ( group ) == False ) : continue
   o0oO00o00 = i1II1IiiIi
   break
   if 65 - 65: iIii1I11I1II1
  if ( o0oO00o00 == [ ] ) : return
  if 58 - 58: IiII % i1IIi . i11iIiiIii
  try :
   lisp_rloc_probe_list [ O0o ] . remove ( o0oO00o00 )
   if ( lisp_rloc_probe_list [ O0o ] == [ ] ) :
    lisp_rloc_probe_list . pop ( O0o )
    if 5 - 5: OoOoOO00
  except :
   return
   if 75 - 75: OOooOOo
   if 60 - 60: ooOoO0o - II111iiii - iIii1I11I1II1
   if 23 - 23: I1ii11iIi11i
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  iiIiI = ""
  IiiI11iiI1i1 = self
  while ( True ) :
   OOoO0oOo0ooOOoO = IiiI11iiI1i1 . last_rloc_probe
   if ( OOoO0oOo0ooOOoO == None ) : OOoO0oOo0ooOOoO = 0
   I1I1iI1111I = IiiI11iiI1i1 . last_rloc_probe_reply
   if ( I1I1iI1111I == None ) : I1I1iI1111I = 0
   O0O0o = IiiI11iiI1i1 . print_rloc_probe_rtt ( )
   i11I1 = space ( 4 )
   if 80 - 80: OoooooooOO * i11iIiiIii % oO0o / Oo0Ooo - I1ii11iIi11i
   if ( IiiI11iiI1i1 . rloc_next_hop == None ) :
    iiIiI += "RLOC-Probing:\n"
   else :
    iiiii111 , IIIiI = IiiI11iiI1i1 . rloc_next_hop
    iiIiI += "RLOC-Probing for nh {}({}):\n" . format ( IIIiI , iiiii111 )
    if 92 - 92: o0oOOo0O0Ooo % i1IIi / I1Ii111 % ooOoO0o / oO0o
    if 2 - 2: i11iIiiIii / Ii1I - i1IIi % O0
   iiIiI += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( i11I1 , lisp_print_elapsed ( OOoO0oOo0ooOOoO ) ,
   # II111iiii
 i11I1 , lisp_print_elapsed ( I1I1iI1111I ) , O0O0o )
   if 50 - 50: o0oOOo0O0Ooo - O0 + OoO0O00
   if ( trailing_linefeed ) : iiIiI += "\n"
   if 22 - 22: I1Ii111 % O0 / I1Ii111 / I1Ii111
   IiiI11iiI1i1 = IiiI11iiI1i1 . next_rloc
   if ( IiiI11iiI1i1 == None ) : break
   iiIiI += "\n"
   if 64 - 64: Oo0Ooo + iIii1I11I1II1 % i1IIi
  return ( iiIiI )
  if 15 - 15: I1Ii111 - I1Ii111 . I1ii11iIi11i - I1IiiI
  if 52 - 52: i1IIi . iIii1I11I1II1 % I1IiiI + I1IiiI / I1IiiI . iII111i
 def get_encap_keys ( self ) :
  IIIIiI1ii1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 82 - 82: I11i * Ii1I
  O0o = self . rloc . print_address_no_iid ( ) + ":" + IIIIiI1ii1
  if 55 - 55: IiII / OoooooooOO
  try :
   iIIi111IiII1i = lisp_crypto_keys_by_rloc_encap [ O0o ]
   if ( iIIi111IiII1i [ 1 ] ) : return ( iIIi111IiII1i [ 1 ] . encrypt_key , iIIi111IiII1i [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 23 - 23: iIii1I11I1II1
   if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
   if 33 - 33: I1Ii111 + OoooooooOO
 def rloc_recent_rekey ( self ) :
  IIIIiI1ii1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 73 - 73: O0 . Oo0Ooo
  O0o = self . rloc . print_address_no_iid ( ) + ":" + IIIIiI1ii1
  if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
  try :
   OOo0O = lisp_crypto_keys_by_rloc_encap [ O0o ] [ 1 ]
   if ( OOo0O == None ) : return ( False )
   if ( OOo0O . last_rekey == None ) : return ( True )
   return ( time . time ( ) - OOo0O . last_rekey < 1 )
  except :
   return ( False )
   if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
   if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
   if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
   if 40 - 40: I1Ii111 - iIii1I11I1II1
class lisp_mapping ( ) :
 def __init__ ( self , eid , group , rloc_set ) :
  self . eid = eid
  if ( eid == "" ) : self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = group
  if ( group == "" ) : self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . rloc_set = rloc_set
  self . best_rloc_set = [ ]
  self . build_best_rloc_set ( )
  self . uptime = lisp_get_timestamp ( )
  self . action = LISP_NO_ACTION
  self . expires = None
  self . map_cache_ttl = None
  self . last_refresh_time = self . uptime
  self . source_cache = None
  self . map_replies_sent = 0
  self . mapping_source = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . use_mr_name = "all"
  self . use_ms_name = "all"
  self . stats = lisp_stats ( )
  self . dynamic_eids = None
  self . checkpoint_entry = False
  self . secondary_iid = None
  self . signature_eid = False
  self . gleaned = False
  if 88 - 88: OOooOOo * O0 * OoOoOO00
  if 26 - 26: Ii1I
 def print_mapping ( self , eid_indent , rloc_indent ) :
  I11i1II = lisp_print_elapsed ( self . uptime )
  oooiiIiIIIi1 = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , oooiiIiIIIi1 , I11i1II ,
 len ( self . rloc_set ) ) )
  for IiiI11iiI1i1 in self . rloc_set : IiiI11iiI1i1 . print_rloc ( rloc_indent )
  if 77 - 77: OoOoOO00 / I1IiiI + IiII
  if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
  if 21 - 21: OoooooooOO
 def print_ttl ( self ) :
  OoI1iI = self . map_cache_ttl
  if ( OoI1iI == None ) : return ( "forever" )
  if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
  if ( OoI1iI >= 3600 ) :
   if ( ( OoI1iI % 3600 ) == 0 ) :
    OoI1iI = str ( OoI1iI / 3600 ) + " hours"
   else :
    OoI1iI = str ( OoI1iI * 60 ) + " mins"
    if 50 - 50: oO0o % OoOoOO00 + I1IiiI
  elif ( OoI1iI >= 60 ) :
   if ( ( OoI1iI % 60 ) == 0 ) :
    OoI1iI = str ( OoI1iI / 60 ) + " mins"
   else :
    OoI1iI = str ( OoI1iI ) + " secs"
    if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
  else :
   OoI1iI = str ( OoI1iI ) + " secs"
   if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
  return ( OoI1iI )
  if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
  if 46 - 46: o0oOOo0O0Ooo
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  OOo0 = time . time ( ) - self . last_refresh_time
  if ( OOo0 >= self . map_cache_ttl ) : return ( True )
  if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
  if 44 - 44: I11i . oO0o
  if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
  i1IiI1IIIIi = self . map_cache_ttl - ( self . map_cache_ttl / 10 )
  if ( OOo0 >= i1IiI1IIIIi ) : return ( True )
  return ( False )
  if 51 - 51: iIii1I11I1II1 * Oo0Ooo + ooOoO0o
  if 58 - 58: I11i / i11iIiiIii . iII111i
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  OOo0 = time . time ( ) - self . stats . last_increment
  return ( OOo0 <= 60 )
  if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
  if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
  if 100 - 100: IiII - OoOoOO00 % iII111i
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
  if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for IiiI11iiI1i1 in self . best_rloc_set :
   IiiI11iiI1i1 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
   if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
   if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
 def build_best_rloc_set ( self ) :
  iIIIiI11ii = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 82 - 82: OoooooooOO % ooOoO0o
  if 68 - 68: I1ii11iIi11i . Ii1I . O0 * OoO0O00
  if 26 - 26: ooOoO0o + OoO0O00 / I1ii11iIi11i * ooOoO0o
  if 96 - 96: IiII % iII111i . OoOoOO00 / oO0o . OoO0O00
  oo0OO = 256
  for IiiI11iiI1i1 in self . rloc_set :
   if ( IiiI11iiI1i1 . up_state ( ) ) : oo0OO = min ( IiiI11iiI1i1 . priority , oo0OO )
   if 26 - 26: iII111i - OoO0O00 . o0oOOo0O0Ooo
   if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
   if 65 - 65: I1IiiI % iIii1I11I1II1
   if 52 - 52: I1IiiI
   if 19 - 19: I1IiiI
   if 17 - 17: I11i + OoooooooOO
   if 63 - 63: IiII
   if 3 - 3: oO0o * II111iiii . O0
   if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
   if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
  for IiiI11iiI1i1 in self . rloc_set :
   if ( IiiI11iiI1i1 . priority <= oo0OO ) :
    if ( IiiI11iiI1i1 . unreach_state ( ) and IiiI11iiI1i1 . last_rloc_probe == None ) :
     IiiI11iiI1i1 . last_rloc_probe = lisp_get_timestamp ( )
     if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
    self . best_rloc_set . append ( IiiI11iiI1i1 )
    if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
    if 100 - 100: I11i - I1ii11iIi11i . i1IIi
    if 85 - 85: II111iiii
    if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
    if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
    if 4 - 4: I11i % I1IiiI
    if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
    if 96 - 96: OoOoOO00 % Ii1I
  for IiiI11iiI1i1 in iIIIiI11ii :
   if ( IiiI11iiI1i1 . priority < oo0OO ) : continue
   IiiI11iiI1i1 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 50 - 50: IiII - II111iiii
  for IiiI11iiI1i1 in self . best_rloc_set :
   if ( IiiI11iiI1i1 . rloc . is_null ( ) ) : continue
   IiiI11iiI1i1 . add_to_rloc_probe_list ( self . eid , self . group )
   if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
   if 13 - 13: II111iiii
   if 14 - 14: i11iIiiIii . IiII
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  oOo0O000oo0 = lisp_packet . packet
  OOO000oOoo00o = lisp_packet . inner_version
  O0oOOOO00oOOo = len ( self . best_rloc_set )
  if ( O0oOOOO00oOOo is 0 ) :
   self . stats . increment ( len ( oOo0O000oo0 ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 29 - 29: I1IiiI + i1IIi * O0 % oO0o
   if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
  Ooo00oo = 4 if lisp_load_split_pings else 0
  IiiiII = lisp_packet . hash_ports ( )
  if ( OOO000oOoo00o == 4 ) :
   for o0Ooo0O00 in range ( 8 + Ooo00oo ) :
    IiiiII = IiiiII ^ struct . unpack ( "B" , oOo0O000oo0 [ o0Ooo0O00 + 12 ] ) [ 0 ]
    if 39 - 39: OoO0O00 . II111iiii + iII111i + I1IiiI + ooOoO0o . OoooooooOO
  elif ( OOO000oOoo00o == 6 ) :
   for o0Ooo0O00 in range ( 0 , 32 + Ooo00oo , 4 ) :
    IiiiII = IiiiII ^ struct . unpack ( "I" , oOo0O000oo0 [ o0Ooo0O00 + 8 : o0Ooo0O00 + 12 ] ) [ 0 ]
    if 20 - 20: IiII * iII111i * I1Ii111 * I1ii11iIi11i * oO0o
   IiiiII = ( IiiiII >> 16 ) + ( IiiiII & 0xffff )
   IiiiII = ( IiiiII >> 8 ) + ( IiiiII & 0xff )
  else :
   for o0Ooo0O00 in range ( 0 , 12 + Ooo00oo , 4 ) :
    IiiiII = IiiiII ^ struct . unpack ( "I" , oOo0O000oo0 [ o0Ooo0O00 : o0Ooo0O00 + 4 ] ) [ 0 ]
    if 58 - 58: o0oOOo0O0Ooo
    if 5 - 5: O0
    if 23 - 23: OOooOOo . i11iIiiIii % o0oOOo0O0Ooo - OoOoOO00 * OoooooooOO - OoO0O00
  if ( lisp_data_plane_logging ) :
   ooO0O = [ ]
   for oO in self . best_rloc_set :
    if ( oO . rloc . is_null ( ) ) : continue
    ooO0O . append ( [ oO . rloc . print_address_no_iid ( ) , oO . print_state ( ) ] )
    if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( IiiiII ) , IiiiII % O0oOOOO00oOOo , red ( str ( ooO0O ) , False ) ) )
   if 97 - 97: OoO0O00 - IiII + ooOoO0o % iIii1I11I1II1 % iII111i
   if 100 - 100: IiII - Ii1I * iIii1I11I1II1 . iII111i . i1IIi % Oo0Ooo
   if 11 - 11: I11i + oO0o % Ii1I
   if 22 - 22: ooOoO0o
   if 83 - 83: OOooOOo - i11iIiiIii - i1IIi / oO0o
   if 33 - 33: OoO0O00 + OOooOOo
  IiiI11iiI1i1 = self . best_rloc_set [ IiiiII % O0oOOOO00oOOo ]
  if 36 - 36: o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * ooOoO0o * Ii1I * IiII
  if 39 - 39: i1IIi
  if 79 - 79: ooOoO0o - II111iiii - oO0o
  if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
  if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
  oooOo0OO = lisp_get_echo_nonce ( IiiI11iiI1i1 . rloc , None )
  if ( oooOo0OO ) :
   oooOo0OO . change_state ( IiiI11iiI1i1 )
   if ( IiiI11iiI1i1 . no_echoed_nonce_state ( ) ) :
    oooOo0OO . request_nonce_sent = None
    if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
    if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
    if 65 - 65: Ii1I . OoOoOO00 + O0 / iIii1I11I1II1 % Ii1I % I1Ii111
    if 31 - 31: o0oOOo0O0Ooo - Oo0Ooo
    if 15 - 15: O0 + OOooOOo
    if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
  if ( IiiI11iiI1i1 . up_state ( ) == False ) :
   oo0iiiii1ii1iiI = IiiiII % O0oOOOO00oOOo
   ii = ( oo0iiiii1ii1iiI + 1 ) % O0oOOOO00oOOo
   while ( ii != oo0iiiii1ii1iiI ) :
    IiiI11iiI1i1 = self . best_rloc_set [ ii ]
    if ( IiiI11iiI1i1 . up_state ( ) ) : break
    ii = ( ii + 1 ) % O0oOOOO00oOOo
    if 96 - 96: IiII * OOooOOo / Oo0Ooo / Oo0Ooo / OoooooooOO . i11iIiiIii
   if ( ii == oo0iiiii1ii1iiI ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 24 - 24: OoO0O00 - OoO0O00 * Oo0Ooo + oO0o + o0oOOo0O0Ooo % OOooOOo
    if 39 - 39: i11iIiiIii * II111iiii
    if 75 - 75: OoooooooOO * IiII * OOooOOo
    if 1 - 1: iII111i * I1IiiI . o0oOOo0O0Ooo . IiII
    if 6 - 6: OOooOOo . oO0o / Oo0Ooo / o0oOOo0O0Ooo
    if 24 - 24: Oo0Ooo % OoooooooOO
  IiiI11iiI1i1 . stats . increment ( len ( oOo0O000oo0 ) )
  if 78 - 78: OoooooooOO - II111iiii . OoO0O00 / I1ii11iIi11i
  if 86 - 86: OOooOOo * OoOoOO00 % i1IIi * IiII . I1ii11iIi11i
  if 72 - 72: i1IIi - I1Ii111 . O0 * OoO0O00
  if 62 - 62: Oo0Ooo . iII111i
  if ( IiiI11iiI1i1 . rle_name and IiiI11iiI1i1 . rle == None ) :
   if ( lisp_rle_list . has_key ( IiiI11iiI1i1 . rle_name ) ) :
    IiiI11iiI1i1 . rle = lisp_rle_list [ IiiI11iiI1i1 . rle_name ]
    if 15 - 15: i11iIiiIii * I11i + oO0o
    if 67 - 67: IiII . OoO0O00
  if ( IiiI11iiI1i1 . rle ) : return ( [ None , None , None , None , IiiI11iiI1i1 . rle , None ] )
  if 59 - 59: oO0o * o0oOOo0O0Ooo
  if 76 - 76: I1IiiI
  if 94 - 94: OoooooooOO * I1ii11iIi11i
  if 28 - 28: II111iiii / II111iiii / II111iiii
  if ( IiiI11iiI1i1 . elp and IiiI11iiI1i1 . elp . use_elp_node ) :
   return ( [ IiiI11iiI1i1 . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 70 - 70: OoO0O00 + O0 * OoO0O00
   if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
   if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
   if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
   if 97 - 97: Ii1I
  oo0OOOo00o = None if ( IiiI11iiI1i1 . rloc . is_null ( ) ) else IiiI11iiI1i1 . rloc
  IIIIiI1ii1 = IiiI11iiI1i1 . translated_port
  Ooo0O = self . action if ( oo0OOOo00o == None ) else None
  if 32 - 32: I1ii11iIi11i + OoOoOO00 / O0 + I1Ii111 . OoOoOO00 - ooOoO0o
  if 15 - 15: o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
  if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
  if 3 - 3: iIii1I11I1II1 + i11iIiiIii
  if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
  OoI1 = None
  if ( oooOo0OO and oooOo0OO . request_nonce_timeout ( ) == False ) :
   OoI1 = oooOo0OO . get_request_or_echo_nonce ( ipc_socket , oo0OOOo00o )
   if 38 - 38: i11iIiiIii
   if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
   if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
   if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
   if 93 - 93: iII111i
  return ( [ oo0OOOo00o , IIIIiI1ii1 , OoI1 , Ooo0O , None , IiiI11iiI1i1 ] )
  if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
  if 32 - 32: II111iiii
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
  if 41 - 41: iII111i . I1Ii111 - IiII / O0
  if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
  if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
  if 25 - 25: Oo0Ooo * oO0o
  for oo0oo00000 in self . rloc_set :
   for IiiI11iiI1i1 in rloc_address_set :
    if ( IiiI11iiI1i1 . is_exact_match ( oo0oo00000 . rloc ) == False ) : continue
    IiiI11iiI1i1 = None
    break
    if 78 - 78: OoOoOO00 / II111iiii
   if ( IiiI11iiI1i1 == rloc_address_set [ - 1 ] ) : return ( False )
   if 6 - 6: I1Ii111 . OoOoOO00
  return ( True )
  if 75 - 75: Oo0Ooo + I11i
  if 87 - 87: I1IiiI
 def get_rloc ( self , rloc ) :
  for oo0oo00000 in self . rloc_set :
   oO = oo0oo00000 . rloc
   if ( rloc . is_exact_match ( oO ) ) : return ( oo0oo00000 )
   if 36 - 36: OoO0O00 . ooOoO0o . O0 / OoO0O00
  return ( None )
  if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
  if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
 def get_rloc_by_interface ( self , interface ) :
  for oo0oo00000 in self . rloc_set :
   if ( oo0oo00000 . interface == interface ) : return ( oo0oo00000 )
   if 72 - 72: I1ii11iIi11i
  return ( None )
  if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
  if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   IIi1 = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( IIi1 == None ) :
    IIi1 = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , IIi1 )
    if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
   IIi1 . add_source_entry ( self )
   if 89 - 89: Oo0Ooo % IiII
   if 36 - 36: IiII % OoOoOO00 % I1ii11iIi11i
   if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   IIo0OooOO = lisp_map_cache . lookup_cache ( self . group , True )
   if ( IIo0OooOO == None ) :
    IIo0OooOO = lisp_mapping ( self . group , self . group , [ ] )
    IIo0OooOO . eid . copy_address ( self . group )
    IIo0OooOO . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , IIo0OooOO )
    if 9 - 9: Ii1I . OoooooooOO / ooOoO0o + i1IIi
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IIo0OooOO . group )
   IIo0OooOO . add_source_entry ( self )
   if 90 - 90: oO0o - OoOoOO00 % ooOoO0o
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 83 - 83: OOooOOo - I1ii11iIi11i + OoO0O00
  if 99 - 99: iII111i - OoOoOO00 % ooOoO0o
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 27 - 27: oO0o . oO0o * iII111i % iIii1I11I1II1
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    o0ooOoooO0oOO = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( o0ooOoooO0oOO ) )
    if 42 - 42: OoOoOO00 % OOooOOo * iII111i
  else :
   IIo0OooOO = lisp_map_cache . lookup_cache ( self . group , True )
   if ( IIo0OooOO == None ) : return
   if 24 - 24: Oo0Ooo % i1IIi
   iIiIIi = IIo0OooOO . lookup_source_cache ( self . eid , True )
   if ( iIiIIi == None ) : return
   if 13 - 13: OoO0O00
   IIo0OooOO . source_cache . delete_cache ( self . eid )
   if ( IIo0OooOO . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 56 - 56: OoOoOO00 . ooOoO0o * oO0o - I11i
    if 47 - 47: oO0o . i1IIi * I1ii11iIi11i % OOooOOo % IiII / Oo0Ooo
    if 39 - 39: i11iIiiIii . OOooOOo + Oo0Ooo
    if 92 - 92: O0 * Oo0Ooo / o0oOOo0O0Ooo % OoO0O00
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 87 - 87: OoooooooOO / I11i . O0
  if 77 - 77: OOooOOo + oO0o * iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 92 - 92: Oo0Ooo . o0oOOo0O0Ooo % OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
  if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 11 - 11: OOooOOo / o0oOOo0O0Ooo
  if 98 - 98: oO0o + I11i . oO0o
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  o0ooOo00O = "," + str ( self . secondary_iid )
  return ( prefix . replace ( o0ooOo00O , o0ooOo00O + "*" ) )
  if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
  if 86 - 86: Oo0Ooo
 def increment_decap_stats ( self , packet ) :
  IIIIiI1ii1 = packet . udp_dport
  if ( IIIIiI1ii1 == LISP_DATA_PORT ) :
   IiiI11iiI1i1 = self . get_rloc ( packet . outer_dest )
  else :
   if 7 - 7: iIii1I11I1II1
   if 86 - 86: IiII + iII111i * II111iiii - IiII - o0oOOo0O0Ooo
   if 8 - 8: OOooOOo . Ii1I
   if 15 - 15: ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
   for IiiI11iiI1i1 in self . rloc_set :
    if ( IiiI11iiI1i1 . translated_port != 0 ) : break
    if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
    if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
  if ( IiiI11iiI1i1 != None ) : IiiI11iiI1i1 . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
  if 48 - 48: OOooOOo
 def rtrs_in_rloc_set ( self ) :
  for IiiI11iiI1i1 in self . rloc_set :
   if ( IiiI11iiI1i1 . is_rtr ( ) ) : return ( True )
   if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
  return ( False )
  if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
  if 23 - 23: o0oOOo0O0Ooo
  if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
  if 63 - 63: I1ii11iIi11i / OOooOOo
 def get_timeout ( self , interface ) :
  try :
   I1I11OooO = lisp_myinterfaces [ interface ]
   self . timeout = I1I11OooO . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 83 - 83: o0oOOo0O0Ooo / OoooooooOO . OoooooooOO * I1IiiI % I1ii11iIi11i
   if 30 - 30: iIii1I11I1II1 . OoOoOO00
   if 28 - 28: I1IiiI . O0 - oO0o
   if 56 - 56: ooOoO0o
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 94 - 94: OoOoOO00
  if 12 - 12: I11i * OoooooooOO + ooOoO0o
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 16 - 16: IiII
  if 100 - 100: OoO0O00 % Oo0Ooo - OoooooooOO
  if 48 - 48: IiII / I11i * OoooooooOO
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 1 - 1: I1ii11iIi11i + I11i
class lisp_site ( ) :
 def __init__ ( self ) :
  self . site_name = ""
  self . description = ""
  self . shutdown = False
  self . auth_sha1_or_sha2 = False
  self . auth_key = { }
  self . encryption_key = None
  self . allowed_prefixes = { }
  self . allowed_prefixes_sorted = [ ]
  self . allowed_rlocs = { }
  self . map_notifies_sent = 0
  self . map_notify_acks_received = 0
  if 54 - 54: IiII * O0 * I1Ii111 + i1IIi - I11i . I11i
  if 39 - 39: I1Ii111
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
class lisp_site_eid ( ) :
 def __init__ ( self , site ) :
  self . site = site
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . first_registered = 0
  self . last_registered = 0
  self . last_registerer = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
  self . registered = False
  self . registered_rlocs = [ ]
  self . auth_sha1_or_sha2 = False
  self . individual_registrations = { }
  self . map_registers_received = 0
  self . proxy_reply_requested = False
  self . force_proxy_reply = False
  self . force_nat_proxy_reply = False
  self . force_ttl = None
  self . pitr_proxy_reply_drop = False
  self . proxy_reply_action = ""
  self . lisp_sec_present = False
  self . map_notify_requested = False
  self . mobile_node_requested = False
  self . echo_nonce_capable = False
  self . use_register_ttl_requested = False
  self . merge_register_requested = False
  self . xtr_id_present = False
  self . xtr_id = 0
  self . site_id = 0
  self . accept_more_specifics = False
  self . parent_for_more_specifics = None
  self . dynamic = False
  self . more_specific_registrations = [ ]
  self . source_cache = None
  self . inconsistent_registration = False
  self . policy = None
  self . require_signature = False
  if 84 - 84: Ii1I
  if 92 - 92: I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
  if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 def print_flags ( self , html ) :
  if ( html == False ) :
   iiIiI = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # I1Ii111 - I1Ii111 . i11iIiiIii * i1IIi . OoOoOO00
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   i11 = self . print_flags ( False )
   i11 = i11 . split ( "-" )
   iiIiI = ""
   for Ii1I1IIiII in i11 :
    III11Ii1 = lisp_site_flags [ Ii1I1IIiII . upper ( ) ]
    III11Ii1 = III11Ii1 . format ( "" if Ii1I1IIiII . isupper ( ) else "not " )
    iiIiI += lisp_span ( Ii1I1IIiII , III11Ii1 )
    if ( Ii1I1IIiII . lower ( ) != "n" ) : iiIiI += "-"
    if 33 - 33: iIii1I11I1II1 . I11i
    if 63 - 63: oO0o - iII111i
  return ( iiIiI )
  if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
  if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 33 - 33: oO0o
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
  if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
 def build_sort_key ( self ) :
  iiiIO0 = lisp_cache ( )
  iIiIIIIiiiii , OOo0O = iiiIO0 . build_key ( self . eid )
  O0OooO0oOo0000 = ""
  if ( self . group . is_null ( ) == False ) :
   OOO00Oo0o0Oo , O0OooO0oOo0000 = iiiIO0 . build_key ( self . group )
   O0OooO0oOo0000 = "-" + O0OooO0oOo0000 [ 0 : 12 ] + "-" + str ( OOO00Oo0o0Oo ) + "-" + O0OooO0oOo0000 [ 12 : : ]
   if 8 - 8: oO0o . OoOoOO00
  OOo0O = OOo0O [ 0 : 12 ] + "-" + str ( iIiIIIIiiiii ) + "-" + OOo0O [ 12 : : ] + O0OooO0oOo0000
  del ( iiiIO0 )
  return ( OOo0O )
  if 64 - 64: I1ii11iIi11i + iII111i + i1IIi * OOooOOo . IiII + I1Ii111
  if 2 - 2: o0oOOo0O0Ooo / ooOoO0o * OoooooooOO
 def merge_in_site_eid ( self , child ) :
  i1IIi1 = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   i1IIi1 = self . merge_rles_in_site_eid ( )
   if 98 - 98: OoOoOO00 % I1ii11iIi11i / OoOoOO00 % o0oOOo0O0Ooo / I1ii11iIi11i
   if 21 - 21: I1IiiI * IiII - Oo0Ooo % ooOoO0o * i1IIi
   if 23 - 23: I11i * II111iiii + OoooooooOO . i1IIi + OoO0O00 + OoOoOO00
   if 52 - 52: iII111i * OoOoOO00
   if 80 - 80: I1Ii111 / IiII * o0oOOo0O0Ooo - OoOoOO00 / iIii1I11I1II1
   if 38 - 38: II111iiii / I11i + IiII % OoooooooOO
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 27 - 27: OoOoOO00 * OoO0O00 * OOooOOo % I1IiiI * o0oOOo0O0Ooo + I1ii11iIi11i
  return ( i1IIi1 )
  if 73 - 73: i1IIi
  if 52 - 52: IiII / i11iIiiIii * O0
 def copy_rloc_records ( self ) :
  OOO0Oo = [ ]
  for oo0oo00000 in self . registered_rlocs :
   OOO0Oo . append ( copy . deepcopy ( oo0oo00000 ) )
   if 36 - 36: OoO0O00 - OOooOOo % o0oOOo0O0Ooo
  return ( OOO0Oo )
  if 67 - 67: o0oOOo0O0Ooo . I1ii11iIi11i + IiII
  if 25 - 25: iII111i % iII111i * ooOoO0o % I1ii11iIi11i % I1Ii111
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for OoOoO00OOO0O0 in self . individual_registrations . values ( ) :
   if ( self . site_id != OoOoO00OOO0O0 . site_id ) : continue
   if ( OoOoO00OOO0O0 . registered == False ) : continue
   self . registered_rlocs += OoOoO00OOO0O0 . copy_rloc_records ( )
   if 4 - 4: O0 % i11iIiiIii % I1Ii111 - i11iIiiIii / o0oOOo0O0Ooo % o0oOOo0O0Ooo
   if 59 - 59: i1IIi . o0oOOo0O0Ooo . IiII + iII111i * i1IIi
   if 41 - 41: ooOoO0o - i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - IiII
   if 12 - 12: I1ii11iIi11i * iII111i / i11iIiiIii / OoOoOO00
   if 62 - 62: O0 - IiII + I1ii11iIi11i
   if 67 - 67: i1IIi + i11iIiiIii * I1ii11iIi11i / ooOoO0o * OoO0O00
  OOO0Oo = [ ]
  for oo0oo00000 in self . registered_rlocs :
   if ( oo0oo00000 . rloc . is_null ( ) or len ( OOO0Oo ) == 0 ) :
    OOO0Oo . append ( oo0oo00000 )
    continue
    if 52 - 52: II111iiii / Ii1I - iII111i
   for iIi1I in OOO0Oo :
    if ( iIi1I . rloc . is_null ( ) ) : continue
    if ( oo0oo00000 . rloc . is_exact_match ( iIi1I . rloc ) ) : break
    if 25 - 25: I11i . O0 / iII111i % II111iiii . Oo0Ooo - I11i
   if ( iIi1I == OOO0Oo [ - 1 ] ) : OOO0Oo . append ( oo0oo00000 )
   if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
  self . registered_rlocs = OOO0Oo
  if 73 - 73: OoOoOO00
  if 66 - 66: Oo0Ooo
  if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
  if 65 - 65: OoOoOO00 % II111iiii + Oo0Ooo
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 24 - 24: OoO0O00 % OoooooooOO
  if 16 - 16: OoOoOO00 % Oo0Ooo * OoOoOO00 . Ii1I
 def merge_rles_in_site_eid ( self ) :
  if 91 - 91: I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
  if 37 - 37: IiII - oO0o
  if 92 - 92: I1IiiI
  if 51 - 51: OoO0O00 + Oo0Ooo - OOooOOo + I1ii11iIi11i
  iIIII11iii = { }
  for oo0oo00000 in self . registered_rlocs :
   if ( oo0oo00000 . rle == None ) : continue
   for iiiI1Ii in oo0oo00000 . rle . rle_nodes :
    O0o0O0OO0o = iiiI1Ii . address . print_address_no_iid ( )
    iIIII11iii [ O0o0O0OO0o ] = iiiI1Ii . address
    if 9 - 9: oO0o . i11iIiiIii * i11iIiiIii . I1ii11iIi11i + iII111i
   break
   if 18 - 18: I11i
   if 46 - 46: I1IiiI . OoooooooOO / iIii1I11I1II1 - ooOoO0o * OOooOOo
   if 55 - 55: o0oOOo0O0Ooo + iIii1I11I1II1 / I11i
   if 97 - 97: i11iIiiIii
   if 71 - 71: oO0o + Oo0Ooo
  self . merge_rlocs_in_site_eid ( )
  if 7 - 7: OoOoOO00 / I1ii11iIi11i * i1IIi
  if 87 - 87: OoooooooOO * IiII - I1IiiI % I1ii11iIi11i % iIii1I11I1II1
  if 28 - 28: I1Ii111 / o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo . Ii1I / I11i
  if 43 - 43: I1Ii111 . I1IiiI
  if 16 - 16: i11iIiiIii * Oo0Ooo * Ii1I / OoOoOO00 / OOooOOo
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
  if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
  if 24 - 24: iII111i + i1IIi
  iII1ii1 = [ ]
  for oo0oo00000 in self . registered_rlocs :
   if ( self . registered_rlocs . index ( oo0oo00000 ) == 0 ) :
    iII1ii1 . append ( oo0oo00000 )
    continue
    if 59 - 59: oO0o
   if ( oo0oo00000 . rle == None ) : iII1ii1 . append ( oo0oo00000 )
   if 43 - 43: II111iiii - OoooooooOO
  self . registered_rlocs = iII1ii1
  if 11 - 11: I1IiiI
  if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
  if 64 - 64: OoO0O00 - OoO0O00
  if 93 - 93: Oo0Ooo . O0
  if 75 - 75: iII111i * II111iiii - I1IiiI
  if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
  if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
  I1i1i111Ii1I = lisp_rle ( "" )
  OoiI1iII1Ii111I = { }
  i1i11i1 = None
  for OoOoO00OOO0O0 in self . individual_registrations . values ( ) :
   if ( OoOoO00OOO0O0 . registered == False ) : continue
   O0OoOoOOO0O = OoOoO00OOO0O0 . registered_rlocs [ 0 ] . rle
   if ( O0OoOoOOO0O == None ) : continue
   if 5 - 5: Oo0Ooo / I1ii11iIi11i / ooOoO0o / o0oOOo0O0Ooo - i1IIi + IiII
   i1i11i1 = OoOoO00OOO0O0 . registered_rlocs [ 0 ] . rloc_name
   for iI11Ii1IIi in O0OoOoOOO0O . rle_nodes :
    O0o0O0OO0o = iI11Ii1IIi . address . print_address_no_iid ( )
    if ( OoiI1iII1Ii111I . has_key ( O0o0O0OO0o ) ) : break
    if 2 - 2: i11iIiiIii * i11iIiiIii
    iiiI1Ii = lisp_rle_node ( )
    iiiI1Ii . address . copy_address ( iI11Ii1IIi . address )
    iiiI1Ii . level = iI11Ii1IIi . level
    iiiI1Ii . rloc_name = i1i11i1
    I1i1i111Ii1I . rle_nodes . append ( iiiI1Ii )
    OoiI1iII1Ii111I [ O0o0O0OO0o ] = iI11Ii1IIi . address
    if 92 - 92: o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
    if 33 - 33: I1IiiI + O0 - I11i
    if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
    if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
    if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
    if 38 - 38: O0 % I1ii11iIi11i + O0
  if ( len ( I1i1i111Ii1I . rle_nodes ) == 0 ) : I1i1i111Ii1I = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = I1i1i111Ii1I
   if ( i1i11i1 ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 37 - 37: Oo0Ooo / I1IiiI
   if 23 - 23: II111iiii / iII111i
   if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
   if 92 - 92: iIii1I11I1II1
   if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
  if ( iIIII11iii . keys ( ) == OoiI1iII1Ii111I . keys ( ) ) : return ( False )
  if 10 - 10: II111iiii / ooOoO0o . Ii1I / I1Ii111 / oO0o
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # I11i
 iIIII11iii . keys ( ) , OoiI1iII1Ii111I . keys ( ) ) )
  if 26 - 26: ooOoO0o * I11i + OOooOOo * i1IIi
  return ( True )
  if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
  if 63 - 63: O0 - IiII . OOooOOo % IiII . I1IiiI / oO0o
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   OoooOO0o0oO0 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( OoooOO0o0oO0 == None ) :
    OoooOO0o0oO0 = lisp_site_eid ( self . site )
    OoooOO0o0oO0 . eid . copy_address ( self . group )
    OoooOO0o0oO0 . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , OoooOO0o0oO0 )
    if 79 - 79: OoOoOO00
    if 88 - 88: oO0o * o0oOOo0O0Ooo
    if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
    if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
    if 78 - 78: OoooooooOO
    OoooOO0o0oO0 . parent_for_more_specifics = self . parent_for_more_specifics
    if 8 - 8: Oo0Ooo - Oo0Ooo % O0 - Ii1I / o0oOOo0O0Ooo % Oo0Ooo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OoooOO0o0oO0 . group )
   OoooOO0o0oO0 . add_source_entry ( self )
   if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1 * I1ii11iIi11i / I11i
   if 18 - 18: Ii1I - i11iIiiIii + OoO0O00 . O0 - iII111i
   if 9 - 9: OoooooooOO / iII111i + o0oOOo0O0Ooo / II111iiii / I1Ii111
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   OoooOO0o0oO0 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( OoooOO0o0oO0 == None ) : return
   if 44 - 44: I1IiiI / iII111i / Oo0Ooo
   OoOoO00OOO0O0 = OoooOO0o0oO0 . lookup_source_cache ( self . eid , True )
   if ( OoOoO00OOO0O0 == None ) : return
   if 66 - 66: I1Ii111 + OoooooooOO % I1IiiI . iII111i * Oo0Ooo + o0oOOo0O0Ooo
   if ( OoooOO0o0oO0 . source_cache == None ) : return
   if 96 - 96: OoO0O00 - ooOoO0o * Ii1I
   OoooOO0o0oO0 . source_cache . delete_cache ( self . eid )
   if ( OoooOO0o0oO0 . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 34 - 34: OoO0O00 . Oo0Ooo % Ii1I . IiII + OoOoOO00
    if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
    if 71 - 71: Ii1I + IiII
    if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 2 - 2: OoooooooOO / IiII % Oo0Ooo % iIii1I11I1II1
  if 62 - 62: oO0o
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 47 - 47: I1IiiI - O0 - I1ii11iIi11i . OoOoOO00
  if 98 - 98: o0oOOo0O0Ooo - OoO0O00 . I1ii11iIi11i / OOooOOo
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 43 - 43: I1IiiI + OOooOOo + o0oOOo0O0Ooo
  if 44 - 44: o0oOOo0O0Ooo % OoO0O00 . OoooooooOO
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 21 - 21: Oo0Ooo * Oo0Ooo - iII111i - O0
  if 87 - 87: OOooOOo / I1Ii111 - Ii1I + O0 - oO0o - O0
 def inherit_from_ams_parent ( self ) :
  IiiIIi111i1 = self . parent_for_more_specifics
  if ( IiiIIi111i1 == None ) : return
  self . force_proxy_reply = IiiIIi111i1 . force_proxy_reply
  self . force_nat_proxy_reply = IiiIIi111i1 . force_nat_proxy_reply
  self . force_ttl = IiiIIi111i1 . force_ttl
  self . pitr_proxy_reply_drop = IiiIIi111i1 . pitr_proxy_reply_drop
  self . proxy_reply_action = IiiIIi111i1 . proxy_reply_action
  self . echo_nonce_capable = IiiIIi111i1 . echo_nonce_capable
  self . policy = IiiIIi111i1 . policy
  self . require_signature = IiiIIi111i1 . require_signature
  if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
  if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
 def rtrs_in_rloc_set ( self ) :
  for oo0oo00000 in self . registered_rlocs :
   if ( oo0oo00000 . is_rtr ( ) ) : return ( True )
   if 3 - 3: ooOoO0o * Ii1I
  return ( False )
  if 29 - 29: OoooooooOO + OOooOOo
  if 68 - 68: O0 + IiII / iII111i - OoOoOO00
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for oo0oo00000 in self . registered_rlocs :
   if ( oo0oo00000 . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( oo0oo00000 . is_rtr ( ) ) : return ( True )
   if 5 - 5: I1IiiI * OoooooooOO - II111iiii
  return ( False )
  if 64 - 64: i1IIi
  if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
 def is_rloc_in_rloc_set ( self , rloc ) :
  for oo0oo00000 in self . registered_rlocs :
   if ( oo0oo00000 . rle ) :
    for I1i1i111Ii1I in oo0oo00000 . rle . rle_nodes :
     if ( I1i1i111Ii1I . address . is_exact_match ( rloc ) ) : return ( True )
     if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
     if 17 - 17: Ii1I * i1IIi % OoO0O00
   if ( oo0oo00000 . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 12 - 12: I1ii11iIi11i
  return ( False )
  if 86 - 86: iIii1I11I1II1 % iII111i
  if 80 - 80: Oo0Ooo
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 37 - 37: i11iIiiIii - I1Ii111
  for oo0oo00000 in prev_rloc_set :
   IiI1i = oo0oo00000 . rloc
   if ( self . is_rloc_in_rloc_set ( IiI1i ) == False ) : return ( False )
   if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
  return ( True )
  if 72 - 72: II111iiii . OoO0O00 . II111iiii * I1ii11iIi11i
  if 42 - 42: II111iiii
  if 45 - 45: I1ii11iIi11i . I1Ii111 . i1IIi * OOooOOo
class lisp_mr ( ) :
 def __init__ ( self , addr_str , dns_name , mr_name ) :
  self . mr_name = mr_name if ( mr_name != None ) else "all"
  self . dns_name = dns_name
  self . map_resolver = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . last_dns_resolve = None
  self . a_record_index = 0
  if ( addr_str ) :
   self . map_resolver . store_address ( addr_str )
   self . insert_mr ( )
  else :
   self . resolve_dns_name ( )
   if 53 - 53: Ii1I . i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 87 - 87: I1Ii111 % i11iIiiIii + O0
  if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
  try :
   iIIi1Ii1III = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   ii1IiIiii = iIIi1Ii1III [ 2 ]
  except :
   return
   if 46 - 46: I1ii11iIi11i - i1IIi
   if 5 - 5: I1IiiI * Ii1I
   if 80 - 80: OoOoOO00
   if 36 - 36: I11i - ooOoO0o - ooOoO0o . I1ii11iIi11i / II111iiii % OOooOOo
   if 26 - 26: OoooooooOO / ooOoO0o - iII111i / OoO0O00 . O0 * OOooOOo
   if 85 - 85: iIii1I11I1II1 + iII111i + iII111i - ooOoO0o * OoO0O00
  if ( len ( ii1IiIiii ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 80 - 80: i11iIiiIii / OOooOOo . OoooooooOO % I11i - iII111i * iIii1I11I1II1
   if 70 - 70: Oo0Ooo
  O0o0O0OO0o = ii1IiIiii [ self . a_record_index ]
  if ( O0o0O0OO0o != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( O0o0O0OO0o )
   self . insert_mr ( )
   if 75 - 75: I1Ii111
   if 40 - 40: OoO0O00 % Oo0Ooo / OoooooooOO / i11iIiiIii
   if 5 - 5: O0 % i11iIiiIii
   if 60 - 60: I1ii11iIi11i / I11i
   if 100 - 100: I1IiiI
   if 44 - 44: iIii1I11I1II1 + Oo0Ooo - I1Ii111 . OoooooooOO
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
  for O0o0O0OO0o in ii1IiIiii [ 1 : : ] :
   i11ii = lisp_address ( LISP_AFI_NONE , O0o0O0OO0o , 0 , 0 )
   IIiII11I1I111 = lisp_get_map_resolver ( i11ii , None )
   if ( IIiII11I1I111 != None and IIiII11I1I111 . a_record_index == ii1IiIiii . index ( O0o0O0OO0o ) ) :
    continue
    if 2 - 2: I11i * I1ii11iIi11i + O0
   IIiII11I1I111 = lisp_mr ( O0o0O0OO0o , None , None )
   IIiII11I1I111 . a_record_index = ii1IiIiii . index ( O0o0O0OO0o )
   IIiII11I1I111 . dns_name = self . dns_name
   IIiII11I1I111 . last_dns_resolve = lisp_get_timestamp ( )
   if 44 - 44: iIii1I11I1II1 / II111iiii - ooOoO0o
   if 10 - 10: OOooOOo
   if 78 - 78: OOooOOo * I1ii11iIi11i % i11iIiiIii % o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO
   if 12 - 12: iIii1I11I1II1 % OoO0O00 + OOooOOo * iIii1I11I1II1 - iIii1I11I1II1
   if 70 - 70: OoO0O00 % i11iIiiIii * IiII . I11i * Oo0Ooo
  ii11oOOoO0 = [ ]
  for IIiII11I1I111 in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != IIiII11I1I111 . dns_name ) : continue
   i11ii = IIiII11I1I111 . map_resolver . print_address_no_iid ( )
   if ( i11ii in ii1IiIiii ) : continue
   ii11oOOoO0 . append ( IIiII11I1I111 )
   if 14 - 14: i1IIi + OoOoOO00 * oO0o - II111iiii + IiII + OoOoOO00
  for IIiII11I1I111 in ii11oOOoO0 : IIiII11I1I111 . delete_mr ( )
  if 42 - 42: Oo0Ooo + iII111i * ooOoO0o
  if 72 - 72: iIii1I11I1II1 % I1Ii111
 def insert_mr ( self ) :
  OOo0O = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ OOo0O ] = self
  if 77 - 77: I1Ii111 * I1IiiI / iIii1I11I1II1 . II111iiii * Oo0Ooo
  if 71 - 71: ooOoO0o / iIii1I11I1II1 % O0 / I1ii11iIi11i . I1Ii111 / i11iIiiIii
 def delete_mr ( self ) :
  OOo0O = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( OOo0O ) == False ) : return
  lisp_map_resolvers_list . pop ( OOo0O )
  if 6 - 6: oO0o . OoO0O00 - II111iiii . I1IiiI - o0oOOo0O0Ooo - i1IIi
  if 42 - 42: Ii1I + i11iIiiIii
  if 46 - 46: O0 % OoOoOO00 - I1Ii111 . I1IiiI
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 66 - 66: II111iiii * iIii1I11I1II1 * ooOoO0o * I11i . II111iiii - ooOoO0o
  if 15 - 15: I1ii11iIi11i - i11iIiiIii - Ii1I / Ii1I . iII111i
  if 36 - 36: oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
class lisp_referral ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . referral_set = { }
  self . referral_type = LISP_DDT_ACTION_NULL
  self . referral_source = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . referral_ttl = 0
  self . uptime = lisp_get_timestamp ( )
  self . expires = 0
  self . source_cache = None
  if 81 - 81: o0oOOo0O0Ooo . OoOoOO00 . i11iIiiIii
  if 13 - 13: i1IIi
 def print_referral ( self , eid_indent , referral_indent ) :
  ooo0 = lisp_print_elapsed ( self . uptime )
  OooOo00 = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , ooo0 ,
  # O0
 OooOo00 , len ( self . referral_set ) ) )
  if 87 - 87: OoO0O00 * OoooooooOO + OoOoOO00 . OoooooooOO + o0oOOo0O0Ooo + Ii1I
  for iiIi11i1i in self . referral_set . values ( ) :
   iiIi11i1i . print_ref_node ( referral_indent )
   if 26 - 26: i1IIi
   if 33 - 33: OoOoOO00 + OOooOOo . i1IIi . IiII
   if 78 - 78: OoooooooOO * I11i / OOooOOo + oO0o . I1Ii111 * iII111i
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 98 - 98: i1IIi
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 28 - 28: Oo0Ooo . I1Ii111 . iIii1I11I1II1 + I1IiiI . II111iiii * I1ii11iIi11i
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 26 - 26: i1IIi / i11iIiiIii * II111iiii
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 11 - 11: Oo0Ooo % i1IIi
  if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
  if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
 def print_ttl ( self ) :
  OoI1iI = self . referral_ttl
  if ( OoI1iI < 60 ) : return ( str ( OoI1iI ) + " secs" )
  if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
  if ( ( OoI1iI % 60 ) == 0 ) :
   OoI1iI = str ( OoI1iI / 60 ) + " mins"
  else :
   OoI1iI = str ( OoI1iI ) + " secs"
   if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
  return ( OoI1iI )
  if 8 - 8: OoooooooOO
  if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # I1Ii111 % o0oOOo0O0Ooo - IiII % oO0o + iII111i
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 2 - 2: I1ii11iIi11i
  if 47 - 47: i11iIiiIii + II111iiii
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   i111II1iI1ii = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( i111II1iI1ii == None ) :
    i111II1iI1ii = lisp_referral ( )
    i111II1iI1ii . eid . copy_address ( self . group )
    i111II1iI1ii . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , i111II1iI1ii )
    if 8 - 8: ooOoO0o + OoooooooOO
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( i111II1iI1ii . group )
   i111II1iI1ii . add_source_entry ( self )
   if 85 - 85: I11i / i1IIi * i11iIiiIii / I1IiiI - Ii1I
   if 25 - 25: iII111i - Oo0Ooo % iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
   if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   i111II1iI1ii = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( i111II1iI1ii == None ) : return
   if 81 - 81: iII111i % OOooOOo * oO0o
   oOoo0Oo0O = i111II1iI1ii . lookup_source_cache ( self . eid , True )
   if ( oOoo0Oo0O == None ) : return
   if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
   i111II1iI1ii . source_cache . delete_cache ( self . eid )
   if ( i111II1iI1ii . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
    if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
    if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
    if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 15 - 15: OOooOOo - OOooOOo - OoooooooOO * OoO0O00
  if 12 - 12: II111iiii * I1Ii111 / I1Ii111 * oO0o * Oo0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 17 - 17: OoOoOO00 % I1Ii111 / iII111i * I1Ii111
  if 96 - 96: Oo0Ooo % o0oOOo0O0Ooo . OoOoOO00 % i11iIiiIii / OoooooooOO
  if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 86 - 86: i1IIi . oO0o % OOooOOo
  if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
 def print_ref_node ( self , indent ) :
  I11i1II = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , I11i1II ,
  # Oo0Ooo / OoOoOO00 - i1IIi
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 77 - 77: I1ii11iIi11i % o0oOOo0O0Ooo - I1IiiI - I1Ii111
  if 16 - 16: OoO0O00 . Ii1I
  if 19 - 19: II111iiii % I1IiiI - II111iiii / OoooooooOO
class lisp_ms ( ) :
 def __init__ ( self , addr_str , dns_name , ms_name , alg_id , key_id , pw , pr ,
 mr , rr , wmn , site_id , ekey_id , ekey ) :
  self . ms_name = ms_name if ( ms_name != None ) else "all"
  self . dns_name = dns_name
  self . map_server = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . last_dns_resolve = None
  self . a_record_index = 0
  if ( lisp_map_servers_list == { } ) :
   self . xtr_id = lisp_get_control_nonce ( )
  else :
   self . xtr_id = lisp_map_servers_list . values ( ) [ 0 ] . xtr_id
   if 4 - 4: I11i * OoOoOO00
  self . alg_id = alg_id
  self . key_id = key_id
  self . password = pw
  self . proxy_reply = pr
  self . merge_registrations = mr
  self . refresh_registrations = rr
  self . want_map_notify = wmn
  self . site_id = site_id
  self . map_registers_sent = 0
  self . map_registers_multicast_sent = 0
  self . map_notifies_received = 0
  self . map_notify_acks_sent = 0
  self . ekey_id = ekey_id
  self . ekey = ekey
  if ( addr_str ) :
   self . map_server . store_address ( addr_str )
   self . insert_ms ( )
  else :
   self . resolve_dns_name ( )
   if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
   if 87 - 87: oO0o . I11i
   if 15 - 15: oO0o
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
  try :
   iIIi1Ii1III = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   ii1IiIiii = iIIi1Ii1III [ 2 ]
  except :
   return
   if 89 - 89: IiII . IiII . oO0o % iII111i
   if 27 - 27: OoOoOO00 + O0 % i1IIi - Oo0Ooo
   if 96 - 96: O0 % o0oOOo0O0Ooo + OOooOOo % I1IiiI
   if 51 - 51: i1IIi . o0oOOo0O0Ooo % I1IiiI - OoooooooOO / OoOoOO00 - I11i
   if 45 - 45: O0 * II111iiii / i11iIiiIii
   if 38 - 38: OoooooooOO % i11iIiiIii - O0 / O0
  if ( len ( ii1IiIiii ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
   if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
  O0o0O0OO0o = ii1IiIiii [ self . a_record_index ]
  if ( O0o0O0OO0o != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( O0o0O0OO0o )
   self . insert_ms ( )
   if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
   if 19 - 19: I1ii11iIi11i
   if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
   if 81 - 81: Ii1I
   if 87 - 87: O0 % iII111i
   if 57 - 57: Ii1I
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 49 - 49: I11i
  for O0o0O0OO0o in ii1IiIiii [ 1 : : ] :
   i11ii = lisp_address ( LISP_AFI_NONE , O0o0O0OO0o , 0 , 0 )
   OoOOoo00ooOoo = lisp_get_map_server ( i11ii )
   if ( OoOOoo00ooOoo != None and OoOOoo00ooOoo . a_record_index == ii1IiIiii . index ( O0o0O0OO0o ) ) :
    continue
    if 22 - 22: Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
   OoOOoo00ooOoo = copy . deepcopy ( self )
   OoOOoo00ooOoo . map_server . store_address ( O0o0O0OO0o )
   OoOOoo00ooOoo . a_record_index = ii1IiIiii . index ( O0o0O0OO0o )
   OoOOoo00ooOoo . last_dns_resolve = lisp_get_timestamp ( )
   OoOOoo00ooOoo . insert_ms ( )
   if 42 - 42: O0
   if 55 - 55: i11iIiiIii % OOooOOo
   if 10 - 10: OoOoOO00 / i11iIiiIii
   if 21 - 21: Ii1I - i1IIi / I11i + IiII
   if 44 - 44: OoooooooOO % I11i / O0
  ii11oOOoO0 = [ ]
  for OoOOoo00ooOoo in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != OoOOoo00ooOoo . dns_name ) : continue
   i11ii = OoOOoo00ooOoo . map_server . print_address_no_iid ( )
   if ( i11ii in ii1IiIiii ) : continue
   ii11oOOoO0 . append ( OoOOoo00ooOoo )
   if 94 - 94: IiII
  for OoOOoo00ooOoo in ii11oOOoO0 : OoOOoo00ooOoo . delete_ms ( )
  if 83 - 83: OoO0O00
  if 55 - 55: iII111i
 def insert_ms ( self ) :
  OOo0O = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ OOo0O ] = self
  if 37 - 37: oO0o / o0oOOo0O0Ooo + I11i * OoO0O00 * o0oOOo0O0Ooo
  if 33 - 33: I1Ii111
 def delete_ms ( self ) :
  OOo0O = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( OOo0O ) == False ) : return
  lisp_map_servers_list . pop ( OOo0O )
  if 97 - 97: Ii1I / iII111i - ooOoO0o + IiII * OoOoOO00 - OOooOOo
  if 43 - 43: oO0o / II111iiii - iII111i / oO0o
  if 98 - 98: OoOoOO00 / OOooOOo
class lisp_interface ( ) :
 def __init__ ( self , device ) :
  self . interface_name = ""
  self . device = device
  self . instance_id = None
  self . bridge_socket = None
  self . raw_socket = None
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . dynamic_eid_device = None
  self . dynamic_eid_timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  self . multi_tenant_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  if 31 - 31: II111iiii % I11i - I11i
  if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 100 - 100: i11iIiiIii - O0 . OoO0O00 / O0 - Ii1I - IiII
  if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 66 - 66: II111iiii % I1IiiI
  if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 96 - 96: I1ii11iIi11i
  if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
  if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
  if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
 def set_socket ( self , device ) :
  i11I1 = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  i11I1 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   i11I1 . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   i11I1 . close ( )
   i11I1 = None
   if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
  self . raw_socket = i11I1
  if 35 - 35: II111iiii
  if 28 - 28: I1Ii111 + IiII + I1ii11iIi11i . Ii1I
 def set_bridge_socket ( self , device ) :
  i11I1 = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   i11I1 = i11I1 . bind ( ( device , 0 ) )
   self . bridge_socket = i11I1
  except :
   return
   if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
   if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
   if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
   if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 98 - 98: IiII
  if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
 def valid_datetime ( self ) :
  ooO0oOoO0O0 = self . datetime_name
  if ( ooO0oOoO0O0 . find ( ":" ) == - 1 ) : return ( False )
  if ( ooO0oOoO0O0 . find ( "-" ) == - 1 ) : return ( False )
  oO0ooO00 , IiiI1i11I11iI , I11i1 , time = ooO0oOoO0O0 [ 0 : 4 ] , ooO0oOoO0O0 [ 5 : 7 ] , ooO0oOoO0O0 [ 8 : 10 ] , ooO0oOoO0O0 [ 11 : : ]
  if 41 - 41: OOooOOo + I11i
  if ( ( oO0ooO00 + IiiI1i11I11iI + I11i1 ) . isdigit ( ) == False ) : return ( False )
  if ( IiiI1i11I11iI < "01" and IiiI1i11I11iI > "12" ) : return ( False )
  if ( I11i1 < "01" and I11i1 > "31" ) : return ( False )
  if 39 - 39: OoOoOO00 * i1IIi . i11iIiiIii + IiII * II111iiii
  iI1II1I1IiIi , IIi1IIii , i1oo0O0OO = time . split ( ":" )
  if 28 - 28: OOooOOo * Ii1I
  if ( ( iI1II1I1IiIi + IIi1IIii + i1oo0O0OO ) . isdigit ( ) == False ) : return ( False )
  if ( iI1II1I1IiIi < "00" and iI1II1I1IiIi > "23" ) : return ( False )
  if ( IIi1IIii < "00" and IIi1IIii > "59" ) : return ( False )
  if ( i1oo0O0OO < "00" and i1oo0O0OO > "59" ) : return ( False )
  return ( True )
  if 98 - 98: I1IiiI
  if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
 def parse_datetime ( self ) :
  O0ooO0ooo = self . datetime_name
  O0ooO0ooo = O0ooO0ooo . replace ( "-" , "" )
  O0ooO0ooo = O0ooO0ooo . replace ( ":" , "" )
  self . datetime = int ( O0ooO0ooo )
  if 42 - 42: I1ii11iIi11i
  if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
 def now ( self ) :
  I11i1II = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  I11i1II = lisp_datetime ( I11i1II )
  return ( I11i1II )
  if 14 - 14: I1ii11iIi11i . OoO0O00
  if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
  if 29 - 29: O0 + iII111i
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
  if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
 def past ( self ) :
  return ( self . future ( ) == False )
  if 76 - 76: OoooooooOO - O0
  if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 32 - 32: O0 % O0
  if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
 def this_year ( self ) :
  OOO0OOO0O00 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  I11i1II = str ( self . datetime ) [ 0 : 4 ]
  return ( I11i1II == OOO0OOO0O00 )
  if 94 - 94: i11iIiiIii - I1IiiI - OoOoOO00 . I1IiiI * I11i * OoooooooOO
  if 39 - 39: OoooooooOO % i11iIiiIii / IiII - ooOoO0o
 def this_month ( self ) :
  OOO0OOO0O00 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  I11i1II = str ( self . datetime ) [ 0 : 6 ]
  return ( I11i1II == OOO0OOO0O00 )
  if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
  if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
 def today ( self ) :
  OOO0OOO0O00 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  I11i1II = str ( self . datetime ) [ 0 : 8 ]
  return ( I11i1II == OOO0OOO0O00 )
  if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
  if 11 - 11: OOooOOo
  if 25 - 25: i1IIi
  if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
  if 75 - 75: iII111i
  if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
class lisp_policy_match ( ) :
 def __init__ ( self ) :
  self . source_eid = None
  self . dest_eid = None
  self . source_rloc = None
  self . dest_rloc = None
  self . rloc_record_name = None
  self . geo_name = None
  self . elp_name = None
  self . rle_name = None
  self . json_name = None
  self . datetime_lower = None
  self . datetime_upper = None
  if 22 - 22: OOooOOo
  if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
class lisp_policy ( ) :
 def __init__ ( self , policy_name ) :
  self . policy_name = policy_name
  self . match_clauses = [ ]
  self . set_action = None
  self . set_record_ttl = None
  self . set_source_eid = None
  self . set_dest_eid = None
  self . set_rloc_address = None
  self . set_rloc_record_name = None
  self . set_geo_name = None
  self . set_elp_name = None
  self . set_rle_name = None
  self . set_json_name = None
  if 17 - 17: o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - i1IIi / I1IiiI
  if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
 def match_policy_map_request ( self , mr , srloc ) :
  for oO0O0O0O0O0OO in self . match_clauses :
   Ii1Ii = oO0O0O0O0O0OO . source_eid
   OOOoo0O = mr . source_eid
   if ( Ii1Ii and OOOoo0O and OOOoo0O . is_more_specific ( Ii1Ii ) == False ) : continue
   if 100 - 100: iII111i - i11iIiiIii + OoO0O00
   Ii1Ii = oO0O0O0O0O0OO . dest_eid
   OOOoo0O = mr . target_eid
   if ( Ii1Ii and OOOoo0O and OOOoo0O . is_more_specific ( Ii1Ii ) == False ) : continue
   if 50 - 50: II111iiii
   Ii1Ii = oO0O0O0O0O0OO . source_rloc
   OOOoo0O = srloc
   if ( Ii1Ii and OOOoo0O and OOOoo0O . is_more_specific ( Ii1Ii ) == False ) : continue
   IIii1 = oO0O0O0O0O0OO . datetime_lower
   iI1I11ii11I1I = oO0O0O0O0O0OO . datetime_upper
   if ( IIii1 and iI1I11ii11I1I and IIii1 . now_in_range ( iI1I11ii11I1I ) == False ) : continue
   return ( True )
   if 89 - 89: I1Ii111 % iIii1I11I1II1 / OoooooooOO % IiII
  return ( False )
  if 27 - 27: I1IiiI . I1ii11iIi11i + iII111i % iII111i
  if 20 - 20: I1IiiI % Oo0Ooo - OoO0O00 - I1Ii111 - II111iiii
 def set_policy_map_reply ( self ) :
  OoOooO00 = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( OoOooO00 ) : return ( None )
  if 66 - 66: i1IIi + I1IiiI
  IiiI11iiI1i1 = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   IiiI11iiI1i1 . rloc . copy_address ( self . set_rloc_address )
   O0o0O0OO0o = IiiI11iiI1i1 . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( O0o0O0OO0o ) )
   if 45 - 45: I1Ii111 . iII111i + OoO0O00 - O0
  if ( self . set_rloc_record_name ) :
   IiiI11iiI1i1 . rloc_name = self . set_rloc_record_name
   i11I1II = blue ( IiiI11iiI1i1 . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( i11I1II ) )
   if 71 - 71: Oo0Ooo + OOooOOo
  if ( self . set_geo_name ) :
   IiiI11iiI1i1 . geo_name = self . set_geo_name
   i11I1II = IiiI11iiI1i1 . geo_name
   o00Ooooooo = "" if lisp_geo_list . has_key ( i11I1II ) else "(not configured)"
   if 66 - 66: iII111i + i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * IiII
   lprint ( "Policy set-geo-name '{}' {}" . format ( i11I1II , o00Ooooooo ) )
   if 59 - 59: I1ii11iIi11i + i1IIi / I11i . iII111i - II111iiii
  if ( self . set_elp_name ) :
   IiiI11iiI1i1 . elp_name = self . set_elp_name
   i11I1II = IiiI11iiI1i1 . elp_name
   o00Ooooooo = "" if lisp_elp_list . has_key ( i11I1II ) else "(not configured)"
   if 66 - 66: Ii1I + OoOoOO00 - I11i / o0oOOo0O0Ooo + iIii1I11I1II1
   lprint ( "Policy set-elp-name '{}' {}" . format ( i11I1II , o00Ooooooo ) )
   if 66 - 66: OOooOOo - I1Ii111 - OoOoOO00 - i1IIi * Ii1I
  if ( self . set_rle_name ) :
   IiiI11iiI1i1 . rle_name = self . set_rle_name
   i11I1II = IiiI11iiI1i1 . rle_name
   o00Ooooooo = "" if lisp_rle_list . has_key ( i11I1II ) else "(not configured)"
   if 23 - 23: IiII - OoOoOO00 . OoO0O00
   lprint ( "Policy set-rle-name '{}' {}" . format ( i11I1II , o00Ooooooo ) )
   if 81 - 81: I1Ii111 / I1ii11iIi11i
  if ( self . set_json_name ) :
   IiiI11iiI1i1 . json_name = self . set_json_name
   i11I1II = IiiI11iiI1i1 . json_name
   o00Ooooooo = "" if lisp_json_list . has_key ( i11I1II ) else "(not configured)"
   if 69 - 69: I1IiiI
   lprint ( "Policy set-json-name '{}' {}" . format ( i11I1II , o00Ooooooo ) )
   if 79 - 79: ooOoO0o
  return ( IiiI11iiI1i1 )
  if 83 - 83: I1Ii111 % II111iiii
  if 89 - 89: Ii1I . I11i
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 98 - 98: I1Ii111 / O0 % ooOoO0o
  if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
  if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 97 - 97: i11iIiiIii / O0 % OoO0O00
  if 88 - 88: i1IIi . I1IiiI
 def add ( self , eid_prefix ) :
  OoI1iI = self . ttl
  O0oOoooooooOo00O = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( O0oOoooooooOo00O ) == False ) :
   lisp_pubsub_cache [ O0oOoooooooOo00O ] = { }
   if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
  O0oIII = lisp_pubsub_cache [ O0oOoooooooOo00O ]
  if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
  iiIII1II1ii1 = "Add"
  if ( O0oIII . has_key ( self . xtr_id ) ) :
   iiIII1II1ii1 = "Replace"
   del ( O0oIII [ self . xtr_id ] )
   if 84 - 84: I1IiiI + OOooOOo
  O0oIII [ self . xtr_id ] = self
  if 80 - 80: OOooOOo / OoOoOO00
  O0oOoooooooOo00O = green ( O0oOoooooooOo00O , False )
  I11I = red ( self . itr . print_address_no_iid ( ) , False )
  OOOo00OOooO = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( iiIII1II1ii1 , O0oOoooooooOo00O ,
 I11I , OOOo00OOooO , OoI1iI ) )
  if 93 - 93: OOooOOo
  if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
 def delete ( self , eid_prefix ) :
  O0oOoooooooOo00O = eid_prefix . print_prefix ( )
  I11I = red ( self . itr . print_address_no_iid ( ) , False )
  OOOo00OOooO = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( O0oOoooooooOo00O ) ) :
   O0oIII = lisp_pubsub_cache [ O0oOoooooooOo00O ]
   if ( O0oIII . has_key ( self . xtr_id ) ) :
    O0oIII . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( O0oOoooooooOo00O ,
 I11I , OOOo00OOooO ) )
    if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
    if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
    if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
    if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
    if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
    if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
    if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
    if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
    if 91 - 91: II111iiii * o0oOOo0O0Ooo
    if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
    if 93 - 93: I11i * iIii1I11I1II1 * oO0o
    if 74 - 74: I1IiiI
    if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
    if 27 - 27: iIii1I11I1II1 . ooOoO0o
    if 74 - 74: i1IIi % OoOoOO00
    if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
    if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
    if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
    if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
    if 100 - 100: Ii1I
    if 73 - 73: IiII - O0
    if 54 - 54: OOooOOo
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 28 - 28: i1IIi - Oo0Ooo * OoO0O00 + OoooooooOO - Ii1I * i11iIiiIii
  if 71 - 71: iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
 def print_trace ( self ) :
  ii1iiii1 = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( ii1iiii1 ) )
  if 89 - 89: iII111i . ooOoO0o
  if 13 - 13: OoooooooOO
 def encode ( self ) :
  i11iI1 = socket . htonl ( 0x90000000 )
  oOo0O000oo0 = struct . pack ( "II" , i11iI1 , 0 )
  oOo0O000oo0 += struct . pack ( "Q" , self . nonce )
  oOo0O000oo0 += json . dumps ( self . packet_json )
  return ( oOo0O000oo0 )
  if 12 - 12: I11i * O0 - i1IIi . I11i / I11i
  if 76 - 76: I1ii11iIi11i
 def decode ( self , packet ) :
  Iii1 = "I"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( False )
  i11iI1 = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
  packet = packet [ O00O : : ]
  i11iI1 = socket . ntohl ( i11iI1 )
  if ( ( i11iI1 & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 64 - 64: I11i
  if ( len ( packet ) < O00O ) : return ( False )
  O0o0O0OO0o = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
  packet = packet [ O00O : : ]
  if 32 - 32: iIii1I11I1II1 - OoOoOO00 * OoooooooOO / II111iiii . oO0o * Oo0Ooo
  O0o0O0OO0o = socket . ntohl ( O0o0O0OO0o )
  I1I = O0o0O0OO0o >> 24
  iiIO00OooOoooO = ( O0o0O0OO0o >> 16 ) & 0xff
  O0OOOo = ( O0o0O0OO0o >> 8 ) & 0xff
  iiiI = O0o0O0OO0o & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( I1I , iiIO00OooOoooO , O0OOOo , iiiI )
  self . local_port = str ( i11iI1 & 0xffff )
  if 11 - 11: iII111i % I1IiiI . i1IIi % OoO0O00 . OoO0O00
  Iii1 = "Q"
  O00O = struct . calcsize ( Iii1 )
  if ( len ( packet ) < O00O ) : return ( False )
  self . nonce = struct . unpack ( Iii1 , packet [ : O00O ] ) [ 0 ]
  packet = packet [ O00O : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 6 - 6: I1Ii111 . ooOoO0o * I1Ii111 % iIii1I11I1II1 - i11iIiiIii
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 27 - 27: oO0o * i11iIiiIii . o0oOOo0O0Ooo
  return ( True )
  if 64 - 64: Ii1I / OOooOOo . i1IIi - Oo0Ooo + oO0o
  if 71 - 71: ooOoO0o
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 32 - 32: OoOoOO00 % IiII % OoO0O00
  if 95 - 95: ooOoO0o
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  IiiI11iiI1i1 , IIIIiI1ii1 = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( IiiI11iiI1i1 == None ) :
   IiiI11iiI1i1 , IIIIiI1ii1 = rts_rloc . split ( ":" )
   IIIIiI1ii1 = int ( IIIIiI1ii1 )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( IiiI11iiI1i1 , IIIIiI1ii1 ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( IiiI11iiI1i1 ,
 IIIIiI1ii1 ) )
   if 47 - 47: I1IiiI * i11iIiiIii / I1IiiI / iIii1I11I1II1 - Ii1I
   if 25 - 25: oO0o / i11iIiiIii + i11iIiiIii % IiII - o0oOOo0O0Ooo
  if ( lisp_socket == None ) :
   i11I1 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   i11I1 . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   i11I1 . sendto ( packet , ( IiiI11iiI1i1 , IIIIiI1ii1 ) )
   i11I1 . close ( )
  else :
   lisp_socket . sendto ( packet , ( IiiI11iiI1i1 , IIIIiI1ii1 ) )
   if 97 - 97: I1ii11iIi11i % iII111i * ooOoO0o % OOooOOo . I1IiiI - i11iIiiIii
   if 2 - 2: IiII . o0oOOo0O0Ooo % II111iiii
   if 69 - 69: Ii1I
 def packet_length ( self ) :
  OoOo = 8 ; oOOOoo = 4 + 4 + 8
  return ( OoOo + oOOOoo + len ( json . dumps ( self . packet_json ) ) )
  if 34 - 34: OoooooooOO - O0 + ooOoO0o * I1IiiI
  if 75 - 75: OOooOOo % iII111i
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  OOo0O = self . local_rloc + ":" + self . local_port
  i111II = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ OOo0O ] = i111II
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( OOo0O , i111II ) )
  if 15 - 15: OoO0O00
  if 52 - 52: II111iiii / ooOoO0o
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  OOo0O = local_rloc_and_port
  try : i111II = lisp_rtr_nat_trace_cache [ OOo0O ]
  except : i111II = ( None , None )
  return ( i111II )
  if 23 - 23: i11iIiiIii % OoO0O00 - o0oOOo0O0Ooo + OoooooooOO
  if 12 - 12: Ii1I / I1IiiI . oO0o . I1IiiI + ooOoO0o - II111iiii
  if 6 - 6: Oo0Ooo + Oo0Ooo - OoOoOO00 - II111iiii
  if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
  if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
  if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
  if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
  if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
  if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
  if 92 - 92: I11i
  if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
def lisp_get_map_server ( address ) :
 for OoOOoo00ooOoo in lisp_map_servers_list . values ( ) :
  if ( OoOOoo00ooOoo . map_server . is_exact_match ( address ) ) : return ( OoOOoo00ooOoo )
  if 98 - 98: iII111i % IiII + OoO0O00
 return ( None )
 if 23 - 23: OOooOOo
 if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
 if 99 - 99: II111iiii + O0
 if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
 if 88 - 88: Oo0Ooo . iII111i
 if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
 if 9 - 9: OoOoOO00 % i1IIi + IiII
def lisp_get_any_map_server ( ) :
 for OoOOoo00ooOoo in lisp_map_servers_list . values ( ) : return ( OoOOoo00ooOoo )
 return ( None )
 if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
 if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
 if 95 - 95: ooOoO0o
 if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
 if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 if 32 - 32: OoOoOO00 % i11iIiiIii
 if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 if 44 - 44: I1Ii111 + ooOoO0o
 if 15 - 15: I11i + OoO0O00 + OoOoOO00
 if 100 - 100: I1Ii111
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  O0o0O0OO0o = address . print_address ( )
  IIiII11I1I111 = None
  for OOo0O in lisp_map_resolvers_list :
   if ( OOo0O . find ( O0o0O0OO0o ) == - 1 ) : continue
   IIiII11I1I111 = lisp_map_resolvers_list [ OOo0O ]
   if 78 - 78: OoOoOO00
  return ( IIiII11I1I111 )
  if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
  if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
  if 13 - 13: I1ii11iIi11i * II111iiii
  if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
  if 53 - 53: I1ii11iIi11i
  if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
  if 64 - 64: ooOoO0o
 if ( eid == "" ) :
  iIIiI1i1iIIIII = ""
 elif ( eid == None ) :
  iIIiI1i1iIIIII = "all"
 else :
  IIi1 = lisp_db_for_lookups . lookup_cache ( eid , False )
  iIIiI1i1iIIIII = "all" if IIi1 == None else IIi1 . use_mr_name
  if 19 - 19: oO0o - I1ii11iIi11i + iII111i . o0oOOo0O0Ooo . OoO0O00 * Oo0Ooo
  if 39 - 39: i11iIiiIii - iII111i / O0 % Oo0Ooo
 Ii1IiIi1i111i = None
 for IIiII11I1I111 in lisp_map_resolvers_list . values ( ) :
  if ( iIIiI1i1iIIIII == "" ) : return ( IIiII11I1I111 )
  if ( IIiII11I1I111 . mr_name != iIIiI1i1iIIIII ) : continue
  if ( Ii1IiIi1i111i == None or IIiII11I1I111 . last_used < Ii1IiIi1i111i . last_used ) : Ii1IiIi1i111i = IIiII11I1I111
  if 52 - 52: I1ii11iIi11i
 return ( Ii1IiIi1i111i )
 if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
 if 77 - 77: iII111i + o0oOOo0O0Ooo
 if 60 - 60: I1ii11iIi11i
 if 23 - 23: iII111i % I1IiiI % I1Ii111 * oO0o * I1IiiI
 if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
 if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
 if 52 - 52: OoooooooOO
 if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
def lisp_get_decent_map_resolver ( eid ) :
 ii = lisp_get_decent_index ( eid )
 IIIIOo = str ( ii ) + "." + lisp_decent_dns_suffix
 if 68 - 68: i1IIi / OoO0O00 * i1IIi - OoooooooOO / II111iiii * OoooooooOO
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( IIIIOo , False ) , eid . print_prefix ( ) ) )
 if 37 - 37: OoooooooOO % I1IiiI * I1IiiI
 if 13 - 13: oO0o
 Ii1IiIi1i111i = None
 for IIiII11I1I111 in lisp_map_resolvers_list . values ( ) :
  if ( IIIIOo != IIiII11I1I111 . dns_name ) : continue
  if ( Ii1IiIi1i111i == None or IIiII11I1I111 . last_used < Ii1IiIi1i111i . last_used ) : Ii1IiIi1i111i = IIiII11I1I111
  if 43 - 43: oO0o / Ii1I % OOooOOo
 return ( Ii1IiIi1i111i )
 if 45 - 45: II111iiii
 if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
 if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
 if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
 if 43 - 43: OOooOOo . O0
 if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
 if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
def lisp_ipv4_input ( packet ) :
 if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
 if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
 if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
 oO00 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( oO00 == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  oO00 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( oO00 != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( None )
   if 85 - 85: I1IiiI - o0oOOo0O0Ooo
   if 86 - 86: II111iiii + Ii1I * Ii1I
   if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
   if 86 - 86: Ii1I
   if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
   if 1 - 1: Ii1I
   if 43 - 43: o0oOOo0O0Ooo
 OoI1iI = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( OoI1iI == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( None )
 elif ( OoI1iI == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 78 - 78: I1Ii111 % i1IIi * I11i
  return ( None )
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
 OoI1iI -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , OoI1iI ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( packet )
 if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
 if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
 if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
 if 29 - 29: OoO0O00
 if 33 - 33: I1ii11iIi11i - O0
 if 72 - 72: Oo0Ooo * iII111i - I11i
 if 81 - 81: I1Ii111
def lisp_ipv6_input ( packet ) :
 iiII = packet . inner_dest
 packet = packet . packet
 if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
 if 46 - 46: OOooOOo * iIii1I11I1II1
 if 33 - 33: OoO0O00 * II111iiii / i1IIi
 if 93 - 93: I1Ii111 % I11i
 if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
 OoI1iI = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( OoI1iI == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( OoI1iI == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
  return ( None )
  if 49 - 49: IiII - OOooOOo * OOooOOo . O0
  if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
  if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
  if 61 - 61: OoO0O00
  if 100 - 100: OoOoOO00
 if ( iiII . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 97 - 97: OoooooooOO
  if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
 OoI1iI -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , OoI1iI ) + packet [ 8 : : ]
 return ( packet )
 if 35 - 35: iII111i % OoO0O00 * O0
 if 37 - 37: OOooOOo
 if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
 if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
 if 75 - 75: OoooooooOO
 if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
 if 23 - 23: o0oOOo0O0Ooo * II111iiii - Oo0Ooo - I1IiiI
 if 86 - 86: I1IiiI - II111iiii * II111iiii * oO0o % OoooooooOO * OoOoOO00
def lisp_mac_input ( packet ) :
 return ( packet )
 if 93 - 93: I1IiiI + OoO0O00 % O0 - ooOoO0o * i1IIi
 if 60 - 60: I1IiiI
 if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
 if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
 if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
 if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
 if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
 if 100 - 100: OoO0O00
 if 36 - 36: oO0o + Ii1I - O0
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 OOO0OOO0O00 = lisp_get_timestamp ( )
 OOo0 = OOO0OOO0O00 - lisp_last_map_request_sent
 Iii1111 = ( OOo0 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 88 - 88: i1IIi * o0oOOo0O0Ooo - I11i
 if ( Iii1111 ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 99 - 99: II111iiii + O0 / oO0o . OOooOOo . IiII
 return ( Iii1111 )
 if 56 - 56: OoO0O00 % O0 . iII111i % o0oOOo0O0Ooo - I1IiiI + Ii1I
 if 77 - 77: iIii1I11I1II1 - OoO0O00 - i1IIi
 if 21 - 21: oO0o . Oo0Ooo . IiII . ooOoO0o
 if 88 - 88: i11iIiiIii . I1Ii111 . O0 % II111iiii - OoO0O00
 if 33 - 33: I1ii11iIi11i + OoooooooOO % OoO0O00
 if 1 - 1: I1Ii111 + ooOoO0o . i1IIi + O0
 if 15 - 15: OoooooooOO - ooOoO0o + ooOoO0o / I1Ii111 + IiII . II111iiii
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 1 - 1: iIii1I11I1II1
 if 69 - 69: I1Ii111 * ooOoO0o % iIii1I11I1II1 * OoooooooOO + i1IIi
 if 14 - 14: i1IIi * iIii1I11I1II1 . iII111i % i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o
 if 100 - 100: I1ii11iIi11i
 if 21 - 21: o0oOOo0O0Ooo % I1ii11iIi11i / I1IiiI / o0oOOo0O0Ooo
 if 68 - 68: I11i * OoO0O00
 OooOoOO0 = iiiIIii = None
 if ( rloc ) :
  OooOoOO0 = rloc . rloc
  iiiIIii = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
  if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
  if 84 - 84: OoOoOO00
  if 80 - 80: oO0o
  if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
 o00oOoOOOOoO , OOoo00 , o0OOOOOo0 = lisp_myrlocs
 if ( o00oOoOOOOoO == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 13 - 13: I1ii11iIi11i + II111iiii * IiII * OoooooooOO + O0 * O0
 if ( OOoo00 == None and OooOoOO0 != None and OooOoOO0 . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 15 - 15: Oo0Ooo % I11i * O0
  if 61 - 61: I1ii11iIi11i - ooOoO0o / OoOoOO00 % OOooOOo * i1IIi . IiII
 OoO0o = lisp_map_request ( )
 OoO0o . record_count = 1
 OoO0o . nonce = lisp_get_control_nonce ( )
 OoO0o . rloc_probe = ( OooOoOO0 != None )
 if 27 - 27: I1ii11iIi11i % iII111i . Oo0Ooo * iIii1I11I1II1
 if 40 - 40: I11i
 if 58 - 58: o0oOOo0O0Ooo / OOooOOo . oO0o % ooOoO0o
 if 33 - 33: I1IiiI * I1ii11iIi11i . OoO0O00 - I1Ii111 . OoO0O00
 if 79 - 79: ooOoO0o
 if 90 - 90: OOooOOo
 if 4 - 4: OoOoOO00 - I1Ii111 . i1IIi - IiII . ooOoO0o + II111iiii
 if ( rloc ) : rloc . last_rloc_probe_nonce = OoO0o . nonce
 if 56 - 56: I1ii11iIi11i / i1IIi + I11i % Oo0Ooo
 IIII = deid . is_multicast_address ( )
 if ( IIII ) :
  OoO0o . target_eid = seid
  OoO0o . target_group = deid
 else :
  OoO0o . target_eid = deid
  if 86 - 86: O0 * II111iiii
  if 75 - 75: iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % I1ii11iIi11i . II111iiii
  if 11 - 11: I1ii11iIi11i - I1ii11iIi11i . ooOoO0o * Oo0Ooo + I1Ii111
  if 59 - 59: iII111i - OOooOOo - OoO0O00 . I1IiiI % o0oOOo0O0Ooo + iII111i
  if 10 - 10: iIii1I11I1II1 - Ii1I
  if 84 - 84: iII111i
  if 21 - 21: i11iIiiIii
  if 30 - 30: OoO0O00 + OoooooooOO
  if 98 - 98: I1ii11iIi11i % I1IiiI
 if ( OoO0o . rloc_probe == False ) :
  IIi1 = lisp_get_signature_eid ( )
  if ( IIi1 ) :
   OoO0o . signature_eid . copy_address ( IIi1 . eid )
   OoO0o . privkey_filename = "./lisp-sig.pem"
   if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
   if 66 - 66: IiII
   if 56 - 56: oO0o + OoooooooOO
   if 75 - 75: O0 % Ii1I
   if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
   if 23 - 23: iII111i / iIii1I11I1II1
 if ( seid == None or IIII ) :
  OoO0o . source_eid . afi = LISP_AFI_NONE
 else :
  OoO0o . source_eid = seid
  if 5 - 5: O0
  if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
  if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
  if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
  if 6 - 6: O0 - OoOoOO00 - i11iIiiIii / iII111i
  if 63 - 63: OOooOOo
  if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
  if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
  if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
  if 13 - 13: Ii1I - OoOoOO00 . Ii1I
  if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
  if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
 if ( OooOoOO0 != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( OooOoOO0 . is_private_address ( ) == False ) :
   o00oOoOOOOoO = lisp_get_any_translated_rloc ( )
   if 73 - 73: Ii1I . IiII % IiII
  if ( o00oOoOOOOoO == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 56 - 56: I1Ii111 + iII111i + iII111i
   if 99 - 99: o0oOOo0O0Ooo % I1ii11iIi11i / Oo0Ooo . O0 + OoO0O00 * OoOoOO00
   if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
   if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
   if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
   if 47 - 47: II111iiii % o0oOOo0O0Ooo
   if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
   if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
 if ( OooOoOO0 == None or OooOoOO0 . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and OooOoOO0 == None ) :
   OOOO0oOO0Oo0 = lisp_get_any_translated_rloc ( )
   if ( OOOO0oOO0Oo0 != None ) : o00oOoOOOOoO = OOOO0oOO0Oo0
   if 3 - 3: iIii1I11I1II1
  OoO0o . itr_rlocs . append ( o00oOoOOOOoO )
  if 25 - 25: OOooOOo * OoO0O00 + o0oOOo0O0Ooo % Ii1I - o0oOOo0O0Ooo - iII111i
 if ( OooOoOO0 == None or OooOoOO0 . is_ipv6 ( ) ) :
  if ( OOoo00 == None or OOoo00 . is_ipv6_link_local ( ) ) :
   OOoo00 = None
  else :
   OoO0o . itr_rloc_count = 1 if ( OooOoOO0 == None ) else 0
   OoO0o . itr_rlocs . append ( OOoo00 )
   if 17 - 17: O0 . ooOoO0o % I1IiiI . iII111i / oO0o . IiII
   if 95 - 95: ooOoO0o . I11i / i11iIiiIii - IiII
   if 87 - 87: I1Ii111 - iII111i * I11i
   if 74 - 74: Ii1I - OoOoOO00 + i11iIiiIii - II111iiii - i11iIiiIii . ooOoO0o
   if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
   if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
   if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
   if 78 - 78: i1IIi
   if 25 - 25: Ii1I * II111iiii / OoOoOO00
 if ( OooOoOO0 != None and OoO0o . itr_rlocs != [ ] ) :
  iIi = OoO0o . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   iIi = o00oOoOOOOoO
  elif ( deid . is_ipv6 ( ) ) :
   iIi = OOoo00
  else :
   iIi = o00oOoOOOOoO
   if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
   if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
   if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
   if 15 - 15: i11iIiiIii
   if 85 - 85: I1Ii111 + iII111i - oO0o
   if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
 oOo0O000oo0 = OoO0o . encode ( OooOoOO0 , iiiIIii )
 OoO0o . print_map_request ( )
 if 64 - 64: OoOoOO00
 if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
 if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
 if 71 - 71: ooOoO0o
 if 35 - 35: OoOoOO00
 if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
 if ( OooOoOO0 != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   OOOOoooO0 = lisp_get_nat_info ( OooOoOO0 , rloc . rloc_name )
   if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
   if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
   if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
   if 89 - 89: iIii1I11I1II1 . ooOoO0o
   if ( OOOOoooO0 == None ) :
    oO = rloc . rloc . print_address_no_iid ( )
    I1I1i1 = "gleaned-{}" . format ( oO )
    Ii1Ii = rloc . translated_port
    OOOOoooO0 = lisp_nat_info ( oO , I1I1i1 , Ii1Ii )
    if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
   lisp_encapsulate_rloc_probe ( lisp_sockets , OooOoOO0 , OOOOoooO0 ,
 oOo0O000oo0 )
   return
   if 78 - 78: OoOoOO00 % oO0o
   if 39 - 39: iIii1I11I1II1
  O0o = OooOoOO0 . print_address_no_iid ( )
  iiII = lisp_convert_4to6 ( O0o )
  lisp_send ( lisp_sockets , iiII , LISP_CTRL_PORT , oOo0O000oo0 )
  return
  if 72 - 72: II111iiii + I1Ii111 / Ii1I * iIii1I11I1II1
  if 95 - 95: OoooooooOO + OOooOOo + II111iiii + IiII + OoO0O00
  if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
  if 65 - 65: I1ii11iIi11i + OoOoOO00
  if 43 - 43: O0 + I11i % II111iiii
  if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
 O0Oo = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  IIiII11I1I111 = lisp_get_decent_map_resolver ( deid )
 else :
  IIiII11I1I111 = lisp_get_map_resolver ( None , O0Oo )
  if 60 - 60: Ii1I . I1ii11iIi11i - I11i + i11iIiiIii / iII111i
 if ( IIiII11I1I111 == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 9 - 9: I1Ii111 . oO0o . OoO0O00 / IiII - oO0o / oO0o
  return
  if 50 - 50: II111iiii + OoOoOO00
 IIiII11I1I111 . last_used = lisp_get_timestamp ( )
 IIiII11I1I111 . map_requests_sent += 1
 if ( IIiII11I1I111 . last_nonce == 0 ) : IIiII11I1I111 . last_nonce = OoO0o . nonce
 if 17 - 17: ooOoO0o + I1ii11iIi11i
 if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
 if 48 - 48: O0
 if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
 if ( seid == None ) : seid = iIi
 lisp_send_ecm ( lisp_sockets , oOo0O000oo0 , seid , lisp_ephem_port , deid ,
 IIiII11I1I111 . map_resolver )
 if 84 - 84: i11iIiiIii . OoooooooOO
 if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
 if 5 - 5: Ii1I
 if 19 - 19: oO0o
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
 if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
 if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
 if 1 - 1: OoOoOO00 / I11i
 IIiII11I1I111 . resolve_dns_name ( )
 return
 if 43 - 43: o0oOOo0O0Ooo - i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
 if 69 - 69: i11iIiiIii - iIii1I11I1II1
 if 40 - 40: I1IiiI / oO0o + ooOoO0o
 if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
 if 37 - 37: I1ii11iIi11i
 if 24 - 24: O0 . I1Ii111 * i11iIiiIii
 if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
 if 16 - 16: I11i % O0
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 56 - 56: Ii1I * OoOoOO00 . i1IIi
 if 15 - 15: I1Ii111
 if 64 - 64: OOooOOo * Oo0Ooo
 if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
 iiIIiiiiIi11 = lisp_info ( )
 iiIIiiiiIi11 . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : iiIIiiiiIi11 . hostname += "-" + device_name
 if 22 - 22: OOooOOo
 O0o = dest . print_address_no_iid ( )
 if 34 - 34: OOooOOo
 if 93 - 93: I1IiiI - I1Ii111 / i1IIi % iII111i - OOooOOo % I11i
 if 52 - 52: I11i
 if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
 if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
 if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
 if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
 if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
 if 97 - 97: iIii1I11I1II1 * I1Ii111
 if 39 - 39: I1Ii111 . II111iiii
 if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
 if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 if 34 - 34: I1IiiI
 if 56 - 56: Ii1I
 if 71 - 71: O0 / i1IIi
 IIo0 = False
 if ( device_name ) :
  I1I1i1II1I1Ii = lisp_get_host_route_next_hop ( O0o )
  if 76 - 76: oO0o
  if 42 - 42: OoO0O00 * i1IIi
  if 60 - 60: I1IiiI * I1Ii111 + oO0o - Ii1I
  if 58 - 58: i11iIiiIii . o0oOOo0O0Ooo - i1IIi - I1IiiI * i1IIi % I1Ii111
  if 37 - 37: I11i
  if 61 - 61: OoooooooOO % iIii1I11I1II1 % O0 % I1Ii111 / Oo0Ooo . I1IiiI
  if 20 - 20: ooOoO0o - I1Ii111
  if 97 - 97: O0
  if 56 - 56: Ii1I * I1IiiI * ooOoO0o
  if ( port == LISP_CTRL_PORT and I1I1i1II1I1Ii != None ) :
   while ( True ) :
    time . sleep ( .01 )
    I1I1i1II1I1Ii = lisp_get_host_route_next_hop ( O0o )
    if ( I1I1i1II1I1Ii == None ) : break
    if 39 - 39: iII111i % Ii1I * iIii1I11I1II1 - Ii1I - I1Ii111
    if 60 - 60: i11iIiiIii + i11iIiiIii - OoooooooOO + OoooooooOO
    if 5 - 5: o0oOOo0O0Ooo
  OO0o0oOo0oOO = lisp_get_default_route_next_hops ( )
  for o0OOOOOo0 , iiIIIi1I in OO0o0oOo0oOO :
   if ( o0OOOOOo0 != device_name ) : continue
   if 53 - 53: Ii1I / i11iIiiIii - I11i * OoooooooOO
   if 88 - 88: OoO0O00 / Ii1I + ooOoO0o . iIii1I11I1II1 * ooOoO0o
   if 56 - 56: o0oOOo0O0Ooo / iII111i . O0 % O0
   if 37 - 37: I1Ii111
   if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
   if 84 - 84: OOooOOo * ooOoO0o / O0
   if ( I1I1i1II1I1Ii != iiIIIi1I ) :
    if ( I1I1i1II1I1Ii != None ) :
     lisp_install_host_route ( O0o , I1I1i1II1I1Ii , False )
     if 96 - 96: I11i . I11i % II111iiii
    lisp_install_host_route ( O0o , iiIIIi1I , True )
    IIo0 = True
    if 14 - 14: iII111i / OoooooooOO
   break
   if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
   if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
   if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
   if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
   if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
   if 11 - 11: I1IiiI
 oOo0O000oo0 = iiIIiiiiIi11 . encode ( )
 iiIIiiiiIi11 . print_info ( )
 if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
 if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
 if 91 - 91: OoO0O00
 if 8 - 8: oO0o
 oO000Oo0oOOo = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 oO000Oo0oOOo = bold ( oO000Oo0oOOo , False )
 Ii1Ii = bold ( "{}" . format ( port ) , False )
 i11ii = red ( O0o , False )
 ooooOoOOO0 = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( ooooOoOOO0 , i11ii , Ii1Ii , oO000Oo0oOOo ) )
 if 26 - 26: o0oOOo0O0Ooo . i1IIi
 if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , oOo0O000oo0 )
 else :
  Ii1i111iI = lisp_data_header ( )
  Ii1i111iI . instance_id ( 0xffffff )
  Ii1i111iI = Ii1i111iI . encode ( )
  if ( Ii1i111iI ) :
   oOo0O000oo0 = Ii1i111iI + oOo0O000oo0
   if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
   if 100 - 100: iIii1I11I1II1
   if 50 - 50: I1Ii111 / ooOoO0o * I11i
   if 53 - 53: II111iiii . IiII
   if 5 - 5: i1IIi % IiII
   if 16 - 16: ooOoO0o - iII111i % Ii1I . OoOoOO00
   if 56 - 56: i11iIiiIii % i11iIiiIii % OoooooooOO . Ii1I . iII111i + I11i
   if 64 - 64: O0
   if 37 - 37: o0oOOo0O0Ooo / O0
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , oOo0O000oo0 )
   if 58 - 58: I1Ii111 + OoooooooOO + iIii1I11I1II1
   if 13 - 13: o0oOOo0O0Ooo . I11i / O0
   if 39 - 39: I11i + oO0o + ooOoO0o % ooOoO0o - I1IiiI % Oo0Ooo
   if 9 - 9: IiII / iII111i * II111iiii + O0 % Oo0Ooo / i1IIi
   if 45 - 45: OoOoOO00 % i11iIiiIii . I1IiiI - O0 * i1IIi - I1IiiI
   if 48 - 48: IiII / iIii1I11I1II1
   if 20 - 20: oO0o / OoooooooOO
 if ( IIo0 ) :
  lisp_install_host_route ( O0o , None , False )
  if ( I1I1i1II1I1Ii != None ) : lisp_install_host_route ( O0o , I1I1i1II1I1Ii , True )
  if 95 - 95: Oo0Ooo . i11iIiiIii
 return
 if 50 - 50: iII111i . i11iIiiIii - i1IIi
 if 24 - 24: i11iIiiIii % iII111i . oO0o
 if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
 if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
 if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
 if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
 if 39 - 39: i11iIiiIii / oO0o
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
 if 87 - 87: I1IiiI / Ii1I
 if 54 - 54: OoooooooOO / Ii1I
 if 26 - 26: o0oOOo0O0Ooo + OoO0O00
 iiIIiiiiIi11 = lisp_info ( )
 packet = iiIIiiiiIi11 . decode ( packet )
 if ( packet == None ) : return
 iiIIiiiiIi11 . print_info ( )
 if 59 - 59: Ii1I * IiII
 if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
 if 66 - 66: OoOoOO00
 if 83 - 83: OOooOOo . IiII
 if 98 - 98: i11iIiiIii
 iiIIiiiiIi11 . info_reply = True
 iiIIiiiiIi11 . global_etr_rloc . store_address ( addr_str )
 iiIIiiiiIi11 . etr_port = sport
 if 74 - 74: iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
 if 17 - 17: I1Ii111
 if 59 - 59: OoOoOO00 . OoOoOO00 * iII111i - Ii1I . i11iIiiIii
 if 68 - 68: iII111i
 if 68 - 68: I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
 if ( iiIIiiiiIi11 . hostname != None ) :
  iiIIiiiiIi11 . private_etr_rloc . afi = LISP_AFI_NAME
  iiIIiiiiIi11 . private_etr_rloc . store_address ( iiIIiiiiIi11 . hostname )
  if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
  if 59 - 59: iII111i
 if ( rtr_list != None ) : iiIIiiiiIi11 . rtr_list = rtr_list
 packet = iiIIiiiiIi11 . encode ( )
 iiIIiiiiIi11 . print_info ( )
 if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + OOooOOo
 if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
 if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 iiII = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , iiII , sport , packet )
 if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 if 77 - 77: ooOoO0o % I1IiiI
 if 26 - 26: o0oOOo0O0Ooo
 if 72 - 72: I1IiiI
 if 90 - 90: ooOoO0o
 Oo0o0o = lisp_info_source ( iiIIiiiiIi11 . hostname , addr_str , sport )
 Oo0o0o . cache_address_for_info_source ( )
 return
 if 19 - 19: IiII . I1IiiI
 if 82 - 82: I11i + II111iiii % oO0o - I1ii11iIi11i
 if 54 - 54: i1IIi - I11i % Oo0Ooo / i11iIiiIii
 if 83 - 83: I1IiiI * OoooooooOO % I1IiiI - oO0o
 if 93 - 93: I1ii11iIi11i - OOooOOo - II111iiii * OoO0O00 . O0 - ooOoO0o
 if 53 - 53: OoO0O00 / i11iIiiIii . OoooooooOO
 if 84 - 84: I1ii11iIi11i
 if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
def lisp_get_signature_eid ( ) :
 for IIi1 in lisp_db_list :
  if ( IIi1 . signature_eid ) : return ( IIi1 )
  if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
 return ( None )
 if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
 if 67 - 67: i1IIi * I1Ii111 * O0
 if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
 if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
 if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
 if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
 if 75 - 75: i11iIiiIii
 if 58 - 58: iII111i
def lisp_get_any_translated_port ( ) :
 for IIi1 in lisp_db_list :
  for oo0oo00000 in IIi1 . rloc_set :
   if ( oo0oo00000 . translated_rloc . is_null ( ) ) : continue
   return ( oo0oo00000 . translated_port )
   if 48 - 48: OoO0O00 * OOooOOo / iII111i
   if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
 return ( None )
 if 82 - 82: Oo0Ooo
 if 50 - 50: I1Ii111 * OOooOOo * OoOoOO00 / OoooooooOO % iII111i
 if 80 - 80: I1Ii111
 if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
 if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
 if 20 - 20: OoOoOO00 - IiII
 if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
 if 66 - 66: II111iiii / Oo0Ooo
 if 93 - 93: iII111i + I11i * OoooooooOO . OoO0O00
def lisp_get_any_translated_rloc ( ) :
 for IIi1 in lisp_db_list :
  for oo0oo00000 in IIi1 . rloc_set :
   if ( oo0oo00000 . translated_rloc . is_null ( ) ) : continue
   return ( oo0oo00000 . translated_rloc )
   if 40 - 40: ooOoO0o * I1Ii111 + iII111i
   if 52 - 52: iII111i % I11i
 return ( None )
 if 95 - 95: IiII + Ii1I / OoO0O00 - iII111i / I1IiiI
 if 27 - 27: Oo0Ooo + i1IIi + i11iIiiIii . OoO0O00 . OoO0O00
 if 56 - 56: I1Ii111 / OoO0O00 + o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
 if 14 - 14: OoO0O00
 if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
 if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
 if 88 - 88: IiII % iIii1I11I1II1
def lisp_get_all_translated_rlocs ( ) :
 I111 = [ ]
 for IIi1 in lisp_db_list :
  for oo0oo00000 in IIi1 . rloc_set :
   if ( oo0oo00000 . is_rloc_translated ( ) == False ) : continue
   O0o0O0OO0o = oo0oo00000 . translated_rloc . print_address_no_iid ( )
   I111 . append ( O0o0O0OO0o )
   if 73 - 73: IiII
   if 75 - 75: iIii1I11I1II1 - I11i
 return ( I111 )
 if 32 - 32: i11iIiiIii
 if 84 - 84: iIii1I11I1II1 - OOooOOo - O0 - i11iIiiIii - OoO0O00
 if 49 - 49: I1Ii111 - I1Ii111 - II111iiii / O0 + i11iIiiIii
 if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
 if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
 if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
 if 52 - 52: II111iiii * o0oOOo0O0Ooo
 if 95 - 95: I1Ii111 - OoooooooOO
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 O0oOO0O00 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
 o00ooI11 = { }
 for IiiI11iiI1i1 in rtr_list :
  if ( IiiI11iiI1i1 == None ) : continue
  O0o0O0OO0o = rtr_list [ IiiI11iiI1i1 ]
  if ( O0oOO0O00 and O0o0O0OO0o . is_private_address ( ) ) : continue
  o00ooI11 [ IiiI11iiI1i1 ] = O0o0O0OO0o
  if 8 - 8: IiII / I11i * oO0o
 rtr_list = o00ooI11
 if 4 - 4: IiII + ooOoO0o
 IiIi111 = [ ]
 for ii1iI1i1 in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( ii1iI1i1 == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 76 - 76: OoOoOO00
  if 63 - 63: OoOoOO00 % i11iIiiIii - Ii1I
  if 56 - 56: OoooooooOO % OoOoOO00
  if 11 - 11: OoOoOO00 * OoOoOO00 % I11i
  if 21 - 21: ooOoO0o . i11iIiiIii / IiII . i1IIi + OoooooooOO
  o0ooOoooO0oOO = lisp_address ( ii1iI1i1 , "" , 0 , iid )
  o0ooOoooO0oOO . make_default_route ( o0ooOoooO0oOO )
  IIo0OooOO = lisp_map_cache . lookup_cache ( o0ooOoooO0oOO , True )
  if ( IIo0OooOO ) :
   if ( IIo0OooOO . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( IIo0OooOO . print_eid_tuple ( ) , False ) ) )
    if 18 - 18: ooOoO0o - I11i - I1Ii111
   elif ( IIo0OooOO . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 81 - 81: IiII - Ii1I % i1IIi
   IIo0OooOO . delete_cache ( )
   if 48 - 48: Ii1I + I11i % iIii1I11I1II1 + ooOoO0o + ooOoO0o + OoO0O00
   if 7 - 7: O0 + II111iiii
  IiIi111 . append ( [ o0ooOoooO0oOO , "" ] )
  if 44 - 44: OOooOOo + i11iIiiIii - I1Ii111 + ooOoO0o
  if 92 - 92: O0 . iIii1I11I1II1 % iIii1I11I1II1 % OoO0O00 - i11iIiiIii - iII111i
  if 76 - 76: OoO0O00 . II111iiii / I1ii11iIi11i
  if 15 - 15: OoOoOO00 . O0 + iII111i + I1IiiI . ooOoO0o + iIii1I11I1II1
  oooiiIiIIIi1 = lisp_address ( ii1iI1i1 , "" , 0 , iid )
  oooiiIiIIIi1 . make_default_multicast_route ( oooiiIiIIIi1 )
  iIIiiiI11I = lisp_map_cache . lookup_cache ( oooiiIiIIIi1 , True )
  if ( iIIiiiI11I ) : iIIiiiI11I = iIIiiiI11I . source_cache . lookup_cache ( o0ooOoooO0oOO , True )
  if ( iIIiiiI11I ) : iIIiiiI11I . delete_cache ( )
  if 11 - 11: oO0o + I11i * I1Ii111 . OoOoOO00 * Ii1I
  IiIi111 . append ( [ o0ooOoooO0oOO , oooiiIiIIIi1 ] )
  if 98 - 98: Oo0Ooo
 if ( len ( IiIi111 ) == 0 ) : return
 if 51 - 51: OOooOOo * O0
 if 50 - 50: OoO0O00 - iII111i + I1IiiI . I11i . I11i
 if 40 - 40: O0 - I11i . I1IiiI + Oo0Ooo - Ii1I - I11i
 if 98 - 98: OoOoOO00 - OoooooooOO * Ii1I
 oo000OO = [ ]
 for ooooOoOOO0 in rtr_list :
  OO0iiiII = rtr_list [ ooooOoOOO0 ]
  oo0oo00000 = lisp_rloc ( )
  oo0oo00000 . rloc . copy_address ( OO0iiiII )
  oo0oo00000 . priority = 254
  oo0oo00000 . mpriority = 255
  oo0oo00000 . rloc_name = "RTR"
  oo000OO . append ( oo0oo00000 )
  if 62 - 62: ooOoO0o / OoOoOO00
  if 71 - 71: Ii1I + OoO0O00 + I11i + o0oOOo0O0Ooo % I1IiiI . II111iiii
 for o0ooOoooO0oOO in IiIi111 :
  IIo0OooOO = lisp_mapping ( o0ooOoooO0oOO [ 0 ] , o0ooOoooO0oOO [ 1 ] , oo000OO )
  IIo0OooOO . mapping_source = map_resolver
  IIo0OooOO . map_cache_ttl = LISP_MR_TTL * 60
  IIo0OooOO . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( IIo0OooOO . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 98 - 98: OoO0O00 % Oo0Ooo
  oo000OO = copy . deepcopy ( oo000OO )
  if 78 - 78: IiII - I1IiiI . ooOoO0o . OoO0O00 + oO0o
 return
 if 6 - 6: i11iIiiIii % O0 - I1IiiI + I1ii11iIi11i
 if 75 - 75: oO0o * OOooOOo * OoooooooOO . I1IiiI / I1IiiI
 if 74 - 74: ooOoO0o / i11iIiiIii % I1ii11iIi11i . IiII
 if 95 - 95: O0 / o0oOOo0O0Ooo * iII111i * ooOoO0o - o0oOOo0O0Ooo % iII111i
 if 6 - 6: Ii1I
 if 48 - 48: I1IiiI . I11i / I1Ii111 + o0oOOo0O0Ooo . OoOoOO00
 if 32 - 32: I11i
 if 64 - 64: O0 / OOooOOo % iII111i
 if 37 - 37: OoOoOO00 + I1IiiI + i1IIi + OoooooooOO % Ii1I / I1ii11iIi11i
 if 32 - 32: O0 % OoooooooOO / I11i + ooOoO0o . iII111i % O0
def lisp_process_info_reply ( source , packet , store ) :
 if 65 - 65: OOooOOo . I1Ii111 * IiII + OoO0O00 - iIii1I11I1II1
 if 23 - 23: I11i % IiII
 if 79 - 79: I1IiiI . i11iIiiIii % I1Ii111 - I11i + Oo0Ooo * II111iiii
 if 62 - 62: I1Ii111 * iII111i % OOooOOo / o0oOOo0O0Ooo
 iiIIiiiiIi11 = lisp_info ( )
 packet = iiIIiiiiIi11 . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 76 - 76: OoooooooOO * o0oOOo0O0Ooo / OoO0O00
 iiIIiiiiIi11 . print_info ( )
 if 2 - 2: OoOoOO00 / O0
 if 39 - 39: IiII . O0
 if 4 - 4: I1Ii111
 if 15 - 15: I11i % I11i / iIii1I11I1II1 - i11iIiiIii / i1IIi
 i1i1ooo0o0O00oOoO = False
 for ooooOoOOO0 in iiIIiiiiIi11 . rtr_list :
  O0o = ooooOoOOO0 . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( O0o ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ O0o ] != None ) : continue
   if 76 - 76: Ii1I * OoooooooOO . Ii1I - iII111i . I11i
  i1i1ooo0o0O00oOoO = True
  lisp_rtr_list [ O0o ] = ooooOoOOO0
  if 64 - 64: Oo0Ooo
  if 16 - 16: IiII . Ii1I + I11i
  if 47 - 47: IiII + O0 - I1Ii111 . o0oOOo0O0Ooo . II111iiii + OoO0O00
  if 95 - 95: I1Ii111
  if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
 if ( lisp_i_am_itr and i1i1ooo0o0O00oOoO ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for o0ooOo00O in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( o0ooOo00O ) , lisp_rtr_list )
    if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
    if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
    if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
    if 83 - 83: OOooOOo . ooOoO0o / IiII
    if 80 - 80: I1Ii111 . I11i - I11i + I1ii11iIi11i
    if 42 - 42: I11i / IiII % O0 - Oo0Ooo
    if 33 - 33: I1Ii111
 if ( store == False ) :
  return ( [ iiIIiiiiIi11 . global_etr_rloc , iiIIiiiiIi11 . etr_port , i1i1ooo0o0O00oOoO ] )
  if 1 - 1: IiII - iIii1I11I1II1 % OoooooooOO
  if 1 - 1: o0oOOo0O0Ooo - i11iIiiIii + I11i
  if 47 - 47: O0 + IiII + ooOoO0o + OOooOOo / OoOoOO00
  if 31 - 31: oO0o * iII111i % OoOoOO00
  if 80 - 80: ooOoO0o % I1ii11iIi11i % I11i . I1Ii111
  if 3 - 3: ooOoO0o - Oo0Ooo
 for IIi1 in lisp_db_list :
  for oo0oo00000 in IIi1 . rloc_set :
   IiiI11iiI1i1 = oo0oo00000 . rloc
   oooOoO = oo0oo00000 . interface
   if ( oooOoO == None ) :
    if ( IiiI11iiI1i1 . is_null ( ) ) : continue
    if ( IiiI11iiI1i1 . is_local ( ) == False ) : continue
    if ( iiIIiiiiIi11 . private_etr_rloc . is_null ( ) == False and
 IiiI11iiI1i1 . is_exact_match ( iiIIiiiiIi11 . private_etr_rloc ) == False ) :
     continue
     if 2 - 2: iII111i . iII111i
   elif ( iiIIiiiiIi11 . private_etr_rloc . is_dist_name ( ) ) :
    i1i11i1 = iiIIiiiiIi11 . private_etr_rloc . address
    if ( i1i11i1 != oo0oo00000 . rloc_name ) : continue
    if 77 - 77: OOooOOo
    if 74 - 74: O0
   o0o0O00 = green ( IIi1 . eid . print_prefix ( ) , False )
   iII = red ( IiiI11iiI1i1 . print_address_no_iid ( ) , False )
   if 86 - 86: OoOoOO00
   iiI1IIII1Ii1 = iiIIiiiiIi11 . global_etr_rloc . is_exact_match ( IiiI11iiI1i1 )
   if ( oo0oo00000 . translated_port == 0 and iiI1IIII1Ii1 ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( iII ,
 oooOoO , o0o0O00 ) )
    continue
    if 9 - 9: oO0o * i11iIiiIii * IiII - oO0o
    if 44 - 44: ooOoO0o / I1IiiI
    if 12 - 12: I1Ii111 + ooOoO0o / O0 % O0 % i1IIi . oO0o
    if 35 - 35: I1IiiI - OOooOOo - ooOoO0o
    if 65 - 65: II111iiii - oO0o
   iIIII11 = iiIIiiiiIi11 . global_etr_rloc
   i1I1 = oo0oo00000 . translated_rloc
   if ( i1I1 . is_exact_match ( iIIII11 ) and
 iiIIiiiiIi11 . etr_port == oo0oo00000 . translated_port ) : continue
   if 24 - 24: O0 . Oo0Ooo + iIii1I11I1II1 / I1Ii111 + iII111i + i1IIi
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( iiIIiiiiIi11 . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # I1IiiI * O0
 iiIIiiiiIi11 . etr_port , iII , oooOoO , o0o0O00 ) )
   if 73 - 73: II111iiii + IiII . OoOoOO00 - I1IiiI
   oo0oo00000 . store_translated_rloc ( iiIIiiiiIi11 . global_etr_rloc ,
 iiIIiiiiIi11 . etr_port )
   if 77 - 77: oO0o / I1ii11iIi11i . IiII - IiII . OoOoOO00 . iIii1I11I1II1
   if 36 - 36: i1IIi * I11i
 return ( [ iiIIiiiiIi11 . global_etr_rloc , iiIIiiiiIi11 . etr_port , i1i1ooo0o0O00oOoO ] )
 if 80 - 80: iIii1I11I1II1 % Ii1I . I1ii11iIi11i % iII111i - IiII % OoO0O00
 if 58 - 58: IiII + Oo0Ooo - i1IIi
 if 3 - 3: o0oOOo0O0Ooo * Ii1I
 if 53 - 53: I1ii11iIi11i / i1IIi . OoOoOO00 % Ii1I + I1IiiI
 if 25 - 25: oO0o + OoooooooOO / i1IIi + O0 % OoooooooOO . OoooooooOO
 if 78 - 78: iIii1I11I1II1 / I1Ii111 / iII111i / iIii1I11I1II1 . iIii1I11I1II1 % II111iiii
 if 26 - 26: Oo0Ooo
 if 14 - 14: O0
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 O0oOoooooooOo00O = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 OO000 = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 91 - 91: IiII % IiII % IiII
 if 81 - 81: I1ii11iIi11i
 if 59 - 59: I11i + i11iIiiIii
 if 48 - 48: Oo0Ooo
 O0oOoooooooOo00O . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , O0oOoooooooOo00O , None )
 O0oOoooooooOo00O . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , O0oOoooooooOo00O , None )
 if 9 - 9: IiII - ooOoO0o * Ii1I / I1IiiI . i1IIi % O0
 if 96 - 96: OoooooooOO
 if 83 - 83: i1IIi * OoO0O00
 if 30 - 30: OOooOOo % IiII
 OO000 . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , OO000 , None )
 OO000 . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , OO000 , None )
 if 88 - 88: i1IIi - OoOoOO00
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if 7 - 7: Ii1I / iIii1I11I1II1
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 IIIIIi = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 IIIIIi . start ( )
 return
 if 91 - 91: I1Ii111 - II111iiii / I1Ii111 + II111iiii
 if 62 - 62: I1ii11iIi11i * oO0o / Ii1I
 if 11 - 11: O0 % iII111i * iIii1I11I1II1 % O0 * OoooooooOO
 if 86 - 86: I1Ii111 . ooOoO0o % OoO0O00 * O0 + Ii1I
 if 46 - 46: i11iIiiIii . OOooOOo % iII111i - O0 / I1Ii111 + iIii1I11I1II1
 if 51 - 51: O0
 if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
 if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
 if 38 - 38: IiII
 if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
 if 2 - 2: Oo0Ooo - OoOoOO00
 if 22 - 22: OoO0O00 - oO0o - O0
 if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
 O0o0O0OO0o = lisp_get_interface_address ( rloc . interface )
 if ( O0o0O0OO0o == None ) : return
 if 2 - 2: i11iIiiIii
 o0Ooooo = rloc . rloc . print_address_no_iid ( )
 I1iii1i1I = O0o0O0OO0o . print_address_no_iid ( )
 if 33 - 33: OoOoOO00 * o0oOOo0O0Ooo * OOooOOo - OoOoOO00
 if ( o0Ooooo == I1iii1i1I ) : return
 if 28 - 28: Oo0Ooo / OOooOOo + I1Ii111 + IiII % iII111i * OoO0O00
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , o0Ooooo , I1iii1i1I ) )
 if 82 - 82: I1ii11iIi11i % OoO0O00 . I11i * I1ii11iIi11i - OoO0O00 / Oo0Ooo
 if 4 - 4: OoOoOO00 * iIii1I11I1II1
 rloc . rloc . copy_address ( O0o0O0OO0o )
 lisp_myrlocs [ 0 ] = O0o0O0OO0o
 return
 if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
 if 16 - 16: Oo0Ooo
 if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 if 96 - 96: I1IiiI . oO0o % O0
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 if 87 - 87: OoooooooOO
def lisp_update_encap_port ( mc ) :
 for IiiI11iiI1i1 in mc . rloc_set :
  OOOOoooO0 = lisp_get_nat_info ( IiiI11iiI1i1 . rloc , IiiI11iiI1i1 . rloc_name )
  if ( OOOOoooO0 == None ) : continue
  if ( IiiI11iiI1i1 . translated_port == OOOOoooO0 . port ) : continue
  if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( IiiI11iiI1i1 . translated_port , OOOOoooO0 . port ,
  # o0oOOo0O0Ooo * OoO0O00 / I11i . oO0o
 red ( IiiI11iiI1i1 . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 52 - 52: OoO0O00 % i1IIi * oO0o
  IiiI11iiI1i1 . store_translated_rloc ( IiiI11iiI1i1 . rloc , OOOOoooO0 . port )
  if 3 - 3: o0oOOo0O0Ooo - iIii1I11I1II1 / oO0o - I1Ii111
 return
 if 44 - 44: I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * i11iIiiIii - OOooOOo
 if 68 - 68: iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
 if 45 - 45: II111iiii . iII111i
 if 55 - 55: ooOoO0o / iII111i / O0
 if 98 - 98: O0 % iII111i + II111iiii
 if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
 if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
 if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
 if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
 if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 if 36 - 36: O0
 if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
  if 21 - 21: i1IIi * iII111i + OoO0O00
 OOO0OOO0O00 = lisp_get_timestamp ( )
 if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if 85 - 85: OoooooooOO
 if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
 if 8 - 8: I1Ii111
 if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
 if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
 if ( mc . last_refresh_time + mc . map_cache_ttl > OOO0OOO0O00 ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
  if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
  if 7 - 7: i1IIi . I1IiiI
  if 68 - 68: OoooooooOO
  if 91 - 91: IiII . ooOoO0o * I11i
 OOo0 = lisp_print_elapsed ( mc . last_refresh_time )
 Oo00 = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( Oo00 , False ) , bold ( "timed out" , False ) , OOo0 ) )
 if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 if 7 - 7: OoooooooOO
 if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
 if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
 if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
 if 52 - 52: OoooooooOO - OoO0O00
 if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
def lisp_timeout_map_cache_walk ( mc , parms ) :
 ii11oOOoO0 = parms [ 0 ]
 IIiIiII = parms [ 1 ]
 if 24 - 24: II111iiii
 if 40 - 40: o0oOOo0O0Ooo . I1IiiI - o0oOOo0O0Ooo
 if 62 - 62: oO0o
 if 71 - 71: i1IIi . I1ii11iIi11i / i11iIiiIii + II111iiii
 if ( mc . group . is_null ( ) ) :
  oOOoOOo00oo0OO , ii11oOOoO0 = lisp_timeout_map_cache_entry ( mc , ii11oOOoO0 )
  if ( ii11oOOoO0 == [ ] or mc != ii11oOOoO0 [ - 1 ] ) :
   IIiIiII = lisp_write_checkpoint_entry ( IIiIiII , mc )
   if 14 - 14: iII111i
  return ( [ oOOoOOo00oo0OO , parms ] )
  if 35 - 35: Ii1I
  if 54 - 54: OOooOOo
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 83 - 83: i1IIi / II111iiii - I1IiiI + I1ii11iIi11i . IiII * oO0o
 if 92 - 92: OoOoOO00 + oO0o % Ii1I / Ii1I - iII111i
 if 11 - 11: Oo0Ooo % II111iiii * Ii1I + II111iiii
 if 9 - 9: I1Ii111
 if 69 - 69: i1IIi + ooOoO0o + Ii1I
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 if 8 - 8: i1IIi
 if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
 if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
def lisp_timeout_map_cache ( lisp_map_cache ) :
 Oooooooo00o00 = [ [ ] , [ ] ]
 Oooooooo00o00 = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , Oooooooo00o00 )
 if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
 if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
 if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
 if 54 - 54: OOooOOo
 if 86 - 86: oO0o * Oo0Ooo / OOooOOo
 ii11oOOoO0 = Oooooooo00o00 [ 0 ]
 for IIo0OooOO in ii11oOOoO0 : IIo0OooOO . delete_cache ( )
 if 18 - 18: II111iiii - I1Ii111
 if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
 if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
 if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
 IIiIiII = Oooooooo00o00 [ 1 ]
 lisp_checkpoint ( IIiIiII )
 return
 if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
 if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
 if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
 if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
 if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
 if 34 - 34: II111iiii + iII111i / IiII
 if 47 - 47: OoO0O00
 if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
 if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
 if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
 if 100 - 100: II111iiii . IiII . I11i
 if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
 if 3 - 3: OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
def lisp_store_nat_info ( hostname , rloc , port ) :
 O0o = rloc . print_address_no_iid ( )
 IIIII1I1iI = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( O0o , False ) , port )
 if 30 - 30: IiII - iII111i - OOooOOo / O0 . I1ii11iIi11i % Ii1I
 i1IiI1 = lisp_nat_info ( O0o , hostname , port )
 if 39 - 39: iII111i * I11i * iIii1I11I1II1 - I1ii11iIi11i % O0
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ i1IiI1 ]
  lprint ( IIIII1I1iI . format ( "Store initial" ) )
  return ( True )
  if 88 - 88: I1Ii111 - I1IiiI + OoOoOO00 * IiII + iIii1I11I1II1 . OoO0O00
  if 91 - 91: iIii1I11I1II1 * iIii1I11I1II1 * OoooooooOO - iII111i * iIii1I11I1II1 + OoOoOO00
  if 10 - 10: oO0o . OoooooooOO / oO0o + I1IiiI / O0
  if 12 - 12: ooOoO0o / I1IiiI % Oo0Ooo - II111iiii / i11iIiiIii
  if 33 - 33: o0oOOo0O0Ooo + IiII / OoOoOO00 / ooOoO0o
  if 9 - 9: OoOoOO00
 OOOOoooO0 = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( OOOOoooO0 . address == O0o and OOOOoooO0 . port == port ) :
  OOOOoooO0 . uptime = lisp_get_timestamp ( )
  lprint ( IIIII1I1iI . format ( "Refresh existing" ) )
  return ( False )
  if 44 - 44: Oo0Ooo . i11iIiiIii % OOooOOo
  if 87 - 87: o0oOOo0O0Ooo
  if 41 - 41: OoooooooOO . iII111i / oO0o
  if 16 - 16: iII111i + o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
  if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
  if 89 - 89: I1ii11iIi11i . OoooooooOO
  if 61 - 61: i1IIi + i11iIiiIii
 OoOO0oOo00OOO = None
 for OOOOoooO0 in lisp_nat_state_info [ hostname ] :
  if ( OOOOoooO0 . address == O0o and OOOOoooO0 . port == port ) :
   OoOO0oOo00OOO = OOOOoooO0
   break
   if 2 - 2: I1ii11iIi11i / OoooooooOO + OoooooooOO - i11iIiiIii / II111iiii
   if 41 - 41: Oo0Ooo . OoOoOO00 . iII111i / i11iIiiIii
   if 65 - 65: iII111i * o0oOOo0O0Ooo * OoooooooOO + I11i + oO0o % OoO0O00
 if ( OoOO0oOo00OOO == None ) :
  lprint ( IIIII1I1iI . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( OoOO0oOo00OOO )
  lprint ( IIIII1I1iI . format ( "Use previous" ) )
  if 1 - 1: I1ii11iIi11i . ooOoO0o
  if 54 - 54: OoOoOO00 % I1IiiI . ooOoO0o + IiII / i11iIiiIii / o0oOOo0O0Ooo
 OOo0i1I = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ i1IiI1 ] + OOo0i1I
 return ( True )
 if 30 - 30: Ii1I
 if 2 - 2: O0 + OoOoOO00 % I1IiiI * O0 . Ii1I
 if 24 - 24: ooOoO0o * OoOoOO00 * iIii1I11I1II1 * iII111i + I1IiiI - II111iiii
 if 31 - 31: oO0o / I1ii11iIi11i
 if 96 - 96: i1IIi + i1IIi * I1Ii111 . II111iiii % OoooooooOO
 if 58 - 58: IiII
 if 64 - 64: iIii1I11I1II1 / OoOoOO00
 if 14 - 14: Ii1I / OoooooooOO . i1IIi % IiII % i11iIiiIii
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
 O0o = rloc . print_address_no_iid ( )
 for OOOOoooO0 in lisp_nat_state_info [ hostname ] :
  if ( OOOOoooO0 . address == O0o ) : return ( OOOOoooO0 )
  if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
 return ( None )
 if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
 if 19 - 19: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
 if 71 - 71: OoO0O00 - I11i
 if 96 - 96: I1Ii111 / Ii1I
 if 65 - 65: I1ii11iIi11i * O0 . IiII
 if 11 - 11: I11i / Ii1I % oO0o
 if 50 - 50: i11iIiiIii
 if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
 if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
 if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 if 4 - 4: I1IiiI
 if 36 - 36: Ii1I
 if 76 - 76: i11iIiiIii + i1IIi
 if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
 if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
 if 76 - 76: Ii1I * iII111i . OoooooooOO
 if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
 if 44 - 44: I1Ii111 - II111iiii / OOooOOo
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 50 - 50: I11i / I1ii11iIi11i
 if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
 if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
 if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 i1Oo = [ ]
 iIIII1i = [ ]
 if ( dest == None ) :
  for IIiII11I1I111 in lisp_map_resolvers_list . values ( ) :
   iIIII1i . append ( IIiII11I1I111 . map_resolver )
   if 77 - 77: IiII + Oo0Ooo * Oo0Ooo / Oo0Ooo % OOooOOo
  i1Oo = iIIII1i
  if ( i1Oo == [ ] ) :
   for OoOOoo00ooOoo in lisp_map_servers_list . values ( ) :
    i1Oo . append ( OoOOoo00ooOoo . map_server )
    if 45 - 45: OoooooooOO + iII111i * ooOoO0o * Ii1I + I11i + ooOoO0o
    if 26 - 26: iII111i + Oo0Ooo
  if ( i1Oo == [ ] ) : return
 else :
  i1Oo . append ( dest )
  if 95 - 95: iII111i . oO0o % iIii1I11I1II1 - I1IiiI
  if 38 - 38: ooOoO0o % iIii1I11I1II1 - OOooOOo
  if 13 - 13: OOooOOo . i11iIiiIii
  if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
  if 79 - 79: oO0o
 I111 = { }
 for IIi1 in lisp_db_list :
  for oo0oo00000 in IIi1 . rloc_set :
   lisp_update_local_rloc ( oo0oo00000 )
   if ( oo0oo00000 . rloc . is_null ( ) ) : continue
   if ( oo0oo00000 . interface == None ) : continue
   if 47 - 47: OoooooooOO - i1IIi * OOooOOo
   O0o0O0OO0o = oo0oo00000 . rloc . print_address_no_iid ( )
   if ( O0o0O0OO0o in I111 ) : continue
   I111 [ O0o0O0OO0o ] = oo0oo00000 . interface
   if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
   if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 if ( I111 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
  return
  if 8 - 8: iII111i
  if 10 - 10: OoOoOO00 % I11i
  if 49 - 49: oO0o % ooOoO0o + II111iiii
  if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
  if 99 - 99: OoOoOO00
  if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
 for O0o0O0OO0o in I111 :
  oooOoO = I111 [ O0o0O0OO0o ]
  i11ii = red ( O0o0O0OO0o , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( i11ii ,
 oooOoO ) )
  o0OOOOOo0 = oooOoO if len ( I111 ) > 1 else None
  for dest in i1Oo :
   lisp_send_info_request ( lisp_sockets , dest , port , o0OOOOOo0 )
   if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
   if 8 - 8: oO0o
   if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
   if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
   if 1 - 1: OoooooooOO . Ii1I
   if 68 - 68: Ii1I
 if ( iIIII1i != [ ] ) :
  for IIiII11I1I111 in lisp_map_resolvers_list . values ( ) :
   IIiII11I1I111 . resolve_dns_name ( )
   if 98 - 98: iII111i
   if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 return
 if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
 if 67 - 67: o0oOOo0O0Ooo
 if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
 if 33 - 33: II111iiii
 if 61 - 61: I1Ii111
 if 56 - 56: I1ii11iIi11i - OoooooooOO
 if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
 if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
 if 31 - 31: Oo0Ooo * IiII / IiII
 if 3 - 3: I1Ii111
 if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
 if 82 - 82: o0oOOo0O0Ooo
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
 if 92 - 92: iII111i + OoO0O00
 if 70 - 70: iIii1I11I1II1
 if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
 if ( value . find ( "." ) != - 1 ) :
  O0o0O0OO0o = value . split ( "." )
  if ( len ( O0o0O0OO0o ) != 4 ) : return ( False )
  if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
  for i1IIi1i in O0o0O0OO0o :
   if ( i1IIi1i . isdigit ( ) == False ) : return ( False )
   if ( int ( i1IIi1i ) > 255 ) : return ( False )
   if 76 - 76: iIii1I11I1II1 + OoooooooOO . iIii1I11I1II1 * OoooooooOO + ooOoO0o + OoOoOO00
  return ( True )
  if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
  if 91 - 91: I11i
  if 54 - 54: I1ii11iIi11i / i1IIi
  if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
  if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
 if ( value . find ( "-" ) != - 1 ) :
  O0o0O0OO0o = value . split ( "-" )
  for o0Ooo0O00 in [ "N" , "S" , "W" , "E" ] :
   if ( o0Ooo0O00 in O0o0O0OO0o ) :
    if ( len ( O0o0O0OO0o ) < 8 ) : return ( False )
    return ( True )
    if 23 - 23: iII111i - IiII % i11iIiiIii
    if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
    if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
    if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
    if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
    if 11 - 11: II111iiii + i1IIi
    if 1 - 1: OOooOOo
 if ( value . find ( "-" ) != - 1 ) :
  O0o0O0OO0o = value . split ( "-" )
  if ( len ( O0o0O0OO0o ) != 3 ) : return ( False )
  if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
  for oOOOoO0o00 in O0o0O0OO0o :
   try : int ( oOOOoO0o00 , 16 )
   except : return ( False )
   if 77 - 77: I1Ii111 * O0 - IiII
  return ( True )
  if 21 - 21: Oo0Ooo % Oo0Ooo % Oo0Ooo
  if 15 - 15: I1IiiI + OoO0O00 . I1IiiI / OoO0O00 . o0oOOo0O0Ooo
  if 72 - 72: IiII + oO0o * o0oOOo0O0Ooo
  if 39 - 39: O0 + iII111i + ooOoO0o / iIii1I11I1II1
  if 91 - 91: Ii1I
 if ( value . find ( ":" ) != - 1 ) :
  O0o0O0OO0o = value . split ( ":" )
  if ( len ( O0o0O0OO0o ) < 2 ) : return ( False )
  if 62 - 62: I1Ii111 . iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I11i % i1IIi
  ooOO0oO0O = False
  I1Ii1i11I1I = 0
  for oOOOoO0o00 in O0o0O0OO0o :
   I1Ii1i11I1I += 1
   if ( oOOOoO0o00 == "" ) :
    if ( ooOO0oO0O ) :
     if ( len ( O0o0O0OO0o ) == I1Ii1i11I1I ) : break
     if ( I1Ii1i11I1I > 2 ) : return ( False )
     if 32 - 32: oO0o * Ii1I * I11i
    ooOO0oO0O = True
    continue
    if 94 - 94: I1Ii111 - Oo0Ooo % i11iIiiIii
   try : int ( oOOOoO0o00 , 16 )
   except : return ( False )
   if 2 - 2: oO0o + i11iIiiIii
  return ( True )
  if 74 - 74: I1Ii111
  if 10 - 10: i11iIiiIii - Ii1I - OoooooooOO % II111iiii
  if 42 - 42: OoOoOO00 + iII111i % Oo0Ooo
  if 25 - 25: IiII % O0 * I11i * OoOoOO00 / OoooooooOO
  if 80 - 80: I1IiiI . oO0o - I1IiiI - OoOoOO00 * ooOoO0o / O0
 if ( value [ 0 ] == "+" ) :
  O0o0O0OO0o = value [ 1 : : ]
  for oO0oO0oOOOo in O0o0O0OO0o :
   if ( oO0oO0oOOOo . isdigit ( ) == False ) : return ( False )
   if 54 - 54: ooOoO0o - OOooOOo / iIii1I11I1II1 * Ii1I
  return ( True )
  if 70 - 70: iIii1I11I1II1 - i11iIiiIii * OOooOOo
 return ( False )
 if 17 - 17: ooOoO0o / IiII
 if 4 - 4: i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoO0O00 . OOooOOo
 if 5 - 5: I1IiiI / OoOoOO00 / i11iIiiIii
 if 59 - 59: I11i - Ii1I - O0
 if 7 - 7: OoooooooOO
 if 13 - 13: I11i - o0oOOo0O0Ooo - O0 % Oo0Ooo - oO0o * OoOoOO00
 if 76 - 76: IiII
 if 88 - 88: o0oOOo0O0Ooo * II111iiii % Oo0Ooo * I1ii11iIi11i . I1IiiI % I1ii11iIi11i
 if 37 - 37: OOooOOo % OoO0O00 % oO0o . I11i / OOooOOo
 if 8 - 8: iIii1I11I1II1 + O0 + IiII - IiII * I1Ii111 / i1IIi
 if 10 - 10: Oo0Ooo . i11iIiiIii + iIii1I11I1II1 % iII111i + i11iIiiIii
 if 6 - 6: OoOoOO00 + OOooOOo + Oo0Ooo
def lisp_process_api ( process , lisp_socket , data_structure ) :
 I1i1i1iI11iii , Oooooooo00o00 = data_structure . split ( "%" )
 if 81 - 81: OoOoOO00 / oO0o * IiII % oO0o
 lprint ( "Process API request '{}', parameters: '{}'" . format ( I1i1i1iI11iii ,
 Oooooooo00o00 ) )
 if 8 - 8: OoO0O00 * iII111i % OoooooooOO - I11i / I1IiiI % oO0o
 II1IiiI = [ ]
 if ( I1i1i1iI11iii == "map-cache" ) :
  if ( Oooooooo00o00 == "" ) :
   II1IiiI = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , II1IiiI )
  else :
   II1IiiI = lisp_process_api_map_cache_entry ( json . loads ( Oooooooo00o00 ) )
   if 50 - 50: iIii1I11I1II1 + i1IIi * Oo0Ooo * OoooooooOO - II111iiii
   if 79 - 79: o0oOOo0O0Ooo * O0
 if ( I1i1i1iI11iii == "site-cache" ) :
  if ( Oooooooo00o00 == "" ) :
   II1IiiI = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 II1IiiI )
  else :
   II1IiiI = lisp_process_api_site_cache_entry ( json . loads ( Oooooooo00o00 ) )
   if 49 - 49: I11i / OoO0O00 % IiII
   if 62 - 62: oO0o % oO0o / o0oOOo0O0Ooo + I1IiiI + OOooOOo
 if ( I1i1i1iI11iii == "map-server" ) :
  Oooooooo00o00 = { } if ( Oooooooo00o00 == "" ) else json . loads ( Oooooooo00o00 )
  II1IiiI = lisp_process_api_ms_or_mr ( True , Oooooooo00o00 )
  if 45 - 45: O0 . OoO0O00 % OOooOOo + iIii1I11I1II1 * iII111i % OoO0O00
 if ( I1i1i1iI11iii == "map-resolver" ) :
  Oooooooo00o00 = { } if ( Oooooooo00o00 == "" ) else json . loads ( Oooooooo00o00 )
  II1IiiI = lisp_process_api_ms_or_mr ( False , Oooooooo00o00 )
  if 62 - 62: I1Ii111 - ooOoO0o + iIii1I11I1II1 % OOooOOo + Oo0Ooo
 if ( I1i1i1iI11iii == "database-mapping" ) :
  II1IiiI = lisp_process_api_database_mapping ( )
  if 59 - 59: I1IiiI * II111iiii . i1IIi - i1IIi
  if 23 - 23: oO0o * OoO0O00 % O0 . OoOoOO00 * Oo0Ooo
  if 69 - 69: OoOoOO00 % I1ii11iIi11i % II111iiii * oO0o
  if 100 - 100: i11iIiiIii . IiII - I1IiiI + I1Ii111
  if 29 - 29: Oo0Ooo . I1IiiI % ooOoO0o * I1ii11iIi11i . iII111i
 II1IiiI = json . dumps ( II1IiiI )
 O0oO00o0o0oo0 = lisp_api_ipc ( process , II1IiiI )
 lisp_ipc ( O0oO00o0o0oo0 , lisp_socket , "lisp-core" )
 return
 if 14 - 14: OoOoOO00 - O0 % Ii1I
 if 19 - 19: iII111i / i1IIi * O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 if 32 - 32: O0 + IiII
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 17 - 17: OOooOOo
def lisp_process_api_map_cache ( mc , data ) :
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 if 46 - 46: II111iiii * OoO0O00
 if 77 - 77: ooOoO0o * I11i
 if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 76 - 76: iII111i * OoooooooOO
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
 if 51 - 51: i11iIiiIii
 if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
 if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 if 63 - 63: II111iiii - Oo0Ooo
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
 if 78 - 78: IiII - I1IiiI
 if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
 if 71 - 71: OoO0O00
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
def lisp_gather_map_cache_data ( mc , data ) :
 i1II1IiiIi = { }
 i1II1IiiIi [ "instance-id" ] = str ( mc . eid . instance_id )
 i1II1IiiIi [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  i1II1IiiIi [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 54 - 54: Ii1I / I1IiiI
 i1II1IiiIi [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 i1II1IiiIi [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 i1II1IiiIi [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 i1II1IiiIi [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
 if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
 if 18 - 18: oO0o * OOooOOo
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 oo000OO = [ ]
 for IiiI11iiI1i1 in mc . rloc_set :
  oO = { }
  if ( IiiI11iiI1i1 . rloc_exists ( ) ) :
   oO [ "address" ] = IiiI11iiI1i1 . rloc . print_address_no_iid ( )
   if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
   if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
  if ( IiiI11iiI1i1 . translated_port != 0 ) :
   oO [ "encap-port" ] = str ( IiiI11iiI1i1 . translated_port )
   if 63 - 63: I1IiiI
  oO [ "state" ] = IiiI11iiI1i1 . print_state ( )
  if ( IiiI11iiI1i1 . geo ) : oO [ "geo" ] = IiiI11iiI1i1 . geo . print_geo ( )
  if ( IiiI11iiI1i1 . elp ) : oO [ "elp" ] = IiiI11iiI1i1 . elp . print_elp ( False )
  if ( IiiI11iiI1i1 . rle ) : oO [ "rle" ] = IiiI11iiI1i1 . rle . print_rle ( False )
  if ( IiiI11iiI1i1 . json ) : oO [ "json" ] = IiiI11iiI1i1 . json . print_json ( False )
  if ( IiiI11iiI1i1 . rloc_name ) : oO [ "rloc-name" ] = IiiI11iiI1i1 . rloc_name
  i1ii11 = IiiI11iiI1i1 . stats . get_stats ( False , False )
  if ( i1ii11 ) : oO [ "stats" ] = i1ii11
  oO [ "uptime" ] = lisp_print_elapsed ( IiiI11iiI1i1 . uptime )
  oO [ "upriority" ] = str ( IiiI11iiI1i1 . priority )
  oO [ "uweight" ] = str ( IiiI11iiI1i1 . weight )
  oO [ "mpriority" ] = str ( IiiI11iiI1i1 . mpriority )
  oO [ "mweight" ] = str ( IiiI11iiI1i1 . mweight )
  Ii1I1Iii = IiiI11iiI1i1 . last_rloc_probe_reply
  if ( Ii1I1Iii ) :
   oO [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( Ii1I1Iii )
   oO [ "rloc-probe-rtt" ] = str ( IiiI11iiI1i1 . rloc_probe_rtt )
   if 35 - 35: i1IIi % I1IiiI . Ii1I - i11iIiiIii / oO0o
  oO [ "rloc-hop-count" ] = IiiI11iiI1i1 . rloc_probe_hops
  oO [ "recent-rloc-hop-counts" ] = IiiI11iiI1i1 . recent_rloc_probe_hops
  if 98 - 98: OoOoOO00 . oO0o + I1ii11iIi11i
  i1i1IiIii = [ ]
  for O0O0o in IiiI11iiI1i1 . recent_rloc_probe_rtts : i1i1IiIii . append ( str ( O0O0o ) )
  oO [ "recent-rloc-probe-rtts" ] = i1i1IiIii
  if 3 - 3: oO0o % OoO0O00 % OOooOOo
  oo000OO . append ( oO )
  if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
 i1II1IiiIi [ "rloc-set" ] = oo000OO
 if 58 - 58: ooOoO0o
 data . append ( i1II1IiiIi )
 return ( [ True , data ] )
 if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
 if 77 - 77: O0
 if 98 - 98: iII111i - iII111i % i1IIi - I1Ii111 . I1IiiI % o0oOOo0O0Ooo
 if 38 - 38: IiII % OoOoOO00 . OOooOOo . I1ii11iIi11i
 if 34 - 34: iII111i . i11iIiiIii + OoO0O00 + o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
 if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
 if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
def lisp_process_api_map_cache_entry ( parms ) :
 o0ooOo00O = parms [ "instance-id" ]
 o0ooOo00O = 0 if ( o0ooOo00O == "" ) else int ( o0ooOo00O )
 if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
 if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
 if 60 - 60: OoOoOO00 - IiII + OoO0O00
 if 77 - 77: iIii1I11I1II1
 O0oOoooooooOo00O = lisp_address ( LISP_AFI_NONE , "" , 0 , o0ooOo00O )
 O0oOoooooooOo00O . store_prefix ( parms [ "eid-prefix" ] )
 iiII = O0oOoooooooOo00O
 i1Ii1I = O0oOoooooooOo00O
 if 92 - 92: IiII
 if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
 if 74 - 74: iII111i + i11iIiiIii
 if 95 - 95: Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 oooiiIiIIIi1 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0ooOo00O )
 if ( parms . has_key ( "group-prefix" ) ) :
  oooiiIiIIIi1 . store_prefix ( parms [ "group-prefix" ] )
  iiII = oooiiIiIIIi1
  if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
  if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 II1IiiI = [ ]
 IIo0OooOO = lisp_map_cache_lookup ( i1Ii1I , iiII )
 if ( IIo0OooOO ) : oOOoOOo00oo0OO , II1IiiI = lisp_process_api_map_cache ( IIo0OooOO , II1IiiI )
 return ( II1IiiI )
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 if 49 - 49: iII111i / iII111i - OoOoOO00
 if 89 - 89: ooOoO0o
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
def lisp_process_api_site_cache ( se , data ) :
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 if 89 - 89: I11i % II111iiii
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 35 - 35: oO0o
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 65 - 65: II111iiii
 if 87 - 87: oO0o / OoO0O00 - oO0o
 if 69 - 69: i11iIiiIii
 if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
 if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
 if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
 if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
 if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
 if 82 - 82: OOooOOo . oO0o
 if 12 - 12: i11iIiiIii + II111iiii
 if 49 - 49: OoooooooOO
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 II1i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 IIIIOo = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  II1i . store_address ( data [ "address" ] )
  if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
  if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
 i111II = { }
 if ( ms_or_mr ) :
  for OoOOoo00ooOoo in lisp_map_servers_list . values ( ) :
   if ( IIIIOo ) :
    if ( IIIIOo != OoOOoo00ooOoo . dns_name ) : continue
   else :
    if ( II1i . is_exact_match ( OoOOoo00ooOoo . map_server ) == False ) : continue
    if 6 - 6: oO0o / II111iiii
    if 23 - 23: IiII - OoooooooOO / oO0o
   i111II [ "dns-name" ] = OoOOoo00ooOoo . dns_name
   i111II [ "address" ] = OoOOoo00ooOoo . map_server . print_address_no_iid ( )
   i111II [ "ms-name" ] = "" if OoOOoo00ooOoo . ms_name == None else OoOOoo00ooOoo . ms_name
   return ( [ i111II ] )
   if 69 - 69: O0 - OoooooooOO
 else :
  for IIiII11I1I111 in lisp_map_resolvers_list . values ( ) :
   if ( IIIIOo ) :
    if ( IIIIOo != IIiII11I1I111 . dns_name ) : continue
   else :
    if ( II1i . is_exact_match ( IIiII11I1I111 . map_resolver ) == False ) : continue
    if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
    if 50 - 50: IiII - OOooOOo % OoOoOO00
   i111II [ "dns-name" ] = IIiII11I1I111 . dns_name
   i111II [ "address" ] = IIiII11I1I111 . map_resolver . print_address_no_iid ( )
   i111II [ "mr-name" ] = "" if IIiII11I1I111 . mr_name == None else IIiII11I1I111 . mr_name
   return ( [ i111II ] )
   if 66 - 66: IiII * i11iIiiIii
   if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 return ( [ ] )
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
def lisp_process_api_database_mapping ( ) :
 II1IiiI = [ ]
 if 1 - 1: oO0o / I11i
 for IIi1 in lisp_db_list :
  i1II1IiiIi = { }
  i1II1IiiIi [ "eid-prefix" ] = IIi1 . eid . print_prefix ( )
  if ( IIi1 . group . is_null ( ) == False ) :
   i1II1IiiIi [ "group-prefix" ] = IIi1 . group . print_prefix ( )
   if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
   if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
  O00OO = [ ]
  for oO in IIi1 . rloc_set :
   IiiI11iiI1i1 = { }
   if ( oO . rloc . is_null ( ) == False ) :
    IiiI11iiI1i1 [ "rloc" ] = oO . rloc . print_address_no_iid ( )
    if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
   if ( oO . rloc_name != None ) : IiiI11iiI1i1 [ "rloc-name" ] = oO . rloc_name
   if ( oO . interface != None ) : IiiI11iiI1i1 [ "interface" ] = oO . interface
   iiooooo = oO . translated_rloc
   if ( iiooooo . is_null ( ) == False ) :
    IiiI11iiI1i1 [ "translated-rloc" ] = iiooooo . print_address_no_iid ( )
    if 1 - 1: oO0o - i11iIiiIii . OoOoOO00
   if ( IiiI11iiI1i1 != { } ) : O00OO . append ( IiiI11iiI1i1 )
   if 16 - 16: OOooOOo
   if 33 - 33: o0oOOo0O0Ooo / OoO0O00 + OoooooooOO
   if 82 - 82: o0oOOo0O0Ooo / i1IIi / i11iIiiIii * Oo0Ooo / OoO0O00
   if 95 - 95: I11i . OoOoOO00 * Ii1I
   if 94 - 94: OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
  i1II1IiiIi [ "rlocs" ] = O00OO
  if 55 - 55: II111iiii - IiII
  if 24 - 24: oO0o % Ii1I / i1IIi
  if 84 - 84: i1IIi
  if 53 - 53: OoooooooOO - i1IIi - Ii1I
  II1IiiI . append ( i1II1IiiIi )
  if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 return ( II1IiiI )
 if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
 if 34 - 34: Ii1I
 if 5 - 5: II111iiii . I1ii11iIi11i
 if 85 - 85: I1Ii111 . IiII + II111iiii
 if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
 if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
def lisp_gather_site_cache_data ( se , data ) :
 i1II1IiiIi = { }
 i1II1IiiIi [ "site-name" ] = se . site . site_name
 i1II1IiiIi [ "instance-id" ] = str ( se . eid . instance_id )
 i1II1IiiIi [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  i1II1IiiIi [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 87 - 87: OOooOOo
 i1II1IiiIi [ "registered" ] = "yes" if se . registered else "no"
 i1II1IiiIi [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 i1II1IiiIi [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 44 - 44: Oo0Ooo + iIii1I11I1II1
 O0o0O0OO0o = se . last_registerer
 O0o0O0OO0o = "none" if O0o0O0OO0o . is_null ( ) else O0o0O0OO0o . print_address ( )
 i1II1IiiIi [ "last-registerer" ] = O0o0O0OO0o
 i1II1IiiIi [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 i1II1IiiIi [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 i1II1IiiIi [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  i1II1IiiIi [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
  if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
  if 10 - 10: O0 / I11i
  if 29 - 29: i11iIiiIii % I11i
  if 49 - 49: I11i
 oo000OO = [ ]
 for IiiI11iiI1i1 in se . registered_rlocs :
  oO = { }
  oO [ "address" ] = IiiI11iiI1i1 . rloc . print_address_no_iid ( ) if IiiI11iiI1i1 . rloc_exists ( ) else "none"
  if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
  if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
  if ( IiiI11iiI1i1 . geo ) : oO [ "geo" ] = IiiI11iiI1i1 . geo . print_geo ( )
  if ( IiiI11iiI1i1 . elp ) : oO [ "elp" ] = IiiI11iiI1i1 . elp . print_elp ( False )
  if ( IiiI11iiI1i1 . rle ) : oO [ "rle" ] = IiiI11iiI1i1 . rle . print_rle ( False )
  if ( IiiI11iiI1i1 . json ) : oO [ "json" ] = IiiI11iiI1i1 . json . print_json ( False )
  if ( IiiI11iiI1i1 . rloc_name ) : oO [ "rloc-name" ] = IiiI11iiI1i1 . rloc_name
  oO [ "uptime" ] = lisp_print_elapsed ( IiiI11iiI1i1 . uptime )
  oO [ "upriority" ] = str ( IiiI11iiI1i1 . priority )
  oO [ "uweight" ] = str ( IiiI11iiI1i1 . weight )
  oO [ "mpriority" ] = str ( IiiI11iiI1i1 . mpriority )
  oO [ "mweight" ] = str ( IiiI11iiI1i1 . mweight )
  if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
  oo000OO . append ( oO )
  if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
 i1II1IiiIi [ "registered-rlocs" ] = oo000OO
 if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
 data . append ( i1II1IiiIi )
 return ( [ True , data ] )
 if 32 - 32: O0
 if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
 if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
 if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
 if 70 - 70: iIii1I11I1II1 - I11i
 if 2 - 2: oO0o / II111iiii * OoO0O00
 if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
def lisp_process_api_site_cache_entry ( parms ) :
 o0ooOo00O = parms [ "instance-id" ]
 o0ooOo00O = 0 if ( o0ooOo00O == "" ) else int ( o0ooOo00O )
 if 40 - 40: OOooOOo
 if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
 if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
 if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
 O0oOoooooooOo00O = lisp_address ( LISP_AFI_NONE , "" , 0 , o0ooOo00O )
 O0oOoooooooOo00O . store_prefix ( parms [ "eid-prefix" ] )
 if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
 if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
 if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
 if 98 - 98: OoO0O00 + oO0o - II111iiii
 if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
 oooiiIiIIIi1 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0ooOo00O )
 if ( parms . has_key ( "group-prefix" ) ) :
  oooiiIiIIIi1 . store_prefix ( parms [ "group-prefix" ] )
  if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
  if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
 II1IiiI = [ ]
 OoooOO0o0oO0 = lisp_site_eid_lookup ( O0oOoooooooOo00O , oooiiIiIIIi1 , False )
 if ( OoooOO0o0oO0 ) : lisp_gather_site_cache_data ( OoooOO0o0oO0 , II1IiiI )
 return ( II1IiiI )
 if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
 if 18 - 18: Ii1I
 if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
 if 70 - 70: OoO0O00
 if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
 if 58 - 58: I11i
 if 94 - 94: Oo0Ooo
def lisp_get_interface_instance_id ( device , source_eid ) :
 oooOoO = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  oooOoO = lisp_myinterfaces [ device ]
  if 39 - 39: I11i - oO0o % iII111i - ooOoO0o - OoOoOO00
  if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
  if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
  if 58 - 58: II111iiii * oO0o - i1IIi . I11i
  if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
  if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
 if ( oooOoO == None or oooOoO . instance_id == None ) :
  return ( lisp_default_iid )
  if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
  if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
  if 31 - 31: i1IIi * Ii1I
  if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
  if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
  if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
  if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
  if 15 - 15: oO0o
  if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
 o0ooOo00O = oooOoO . get_instance_id ( )
 if ( source_eid == None ) : return ( o0ooOo00O )
 if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
 oOo = source_eid . instance_id
 ooO0O = None
 for oooOoO in lisp_multi_tenant_interfaces :
  if ( oooOoO . device != device ) : continue
  o0ooOoooO0oOO = oooOoO . multi_tenant_eid
  source_eid . instance_id = o0ooOoooO0oOO . instance_id
  if ( source_eid . is_more_specific ( o0ooOoooO0oOO ) == False ) : continue
  if ( ooO0O == None or ooO0O . multi_tenant_eid . mask_len < o0ooOoooO0oOO . mask_len ) :
   ooO0O = oooOoO
   if 90 - 90: Ii1I . iII111i . I11i - OoooooooOO
   if 38 - 38: OoOoOO00 / OOooOOo . I1IiiI
 source_eid . instance_id = oOo
 if 14 - 14: O0 . I1Ii111 - OoO0O00 * i11iIiiIii
 if ( ooO0O == None ) : return ( o0ooOo00O )
 return ( ooO0O . get_instance_id ( ) )
 if 62 - 62: Ii1I % OoOoOO00 + I11i
 if 89 - 89: OoOoOO00 % i11iIiiIii / iII111i - o0oOOo0O0Ooo
 if 61 - 61: I1Ii111
 if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
 if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
 if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
 if 56 - 56: Oo0Ooo
 if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
 if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
 oooOoO = lisp_myinterfaces [ device ]
 iIi1I11IIi = device if oooOoO . dynamic_eid_device == None else oooOoO . dynamic_eid_device
 if 73 - 73: Ii1I - II111iiii + I1IiiI % i11iIiiIii * I11i
 if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
 if ( oooOoO . does_dynamic_eid_match ( eid ) ) : return ( iIi1I11IIi )
 return ( None )
 if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
 if 64 - 64: OoooooooOO
 if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
 if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
 if 71 - 71: O0 - OoooooooOO
 if 82 - 82: i11iIiiIii * II111iiii % IiII
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 67 - 67: iII111i
 O00O0000 = lisp_process_rloc_probe_timer
 i1Ii1iiIII = threading . Timer ( interval , O00O0000 , [ lisp_sockets ] )
 lisp_rloc_probe_timer = i1Ii1iiIII
 i1Ii1iiIII . start ( )
 return
 if 41 - 41: OoooooooOO + O0 . OoOoOO00 + Ii1I - i1IIi - OoooooooOO
 if 23 - 23: IiII . I1Ii111 / OoOoOO00 * Ii1I % O0
 if 54 - 54: I1ii11iIi11i + i11iIiiIii
 if 16 - 16: iII111i
 if 29 - 29: ooOoO0o . I1IiiI + o0oOOo0O0Ooo - I1IiiI
 if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
 if 65 - 65: Ii1I % i11iIiiIii
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for OOo0O in lisp_rloc_probe_list :
  o00OOo00O0ooO = lisp_rloc_probe_list [ OOo0O ]
  lprint ( "RLOC {}:" . format ( OOo0O ) )
  for oO , IIIII1iii11 , I1I1i1 in o00OOo00O0ooO :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( oO ) ) , IIIII1iii11 . print_prefix ( ) ,
 I1I1i1 . print_prefix ( ) , oO . translated_port ) )
   if 36 - 36: iIii1I11I1II1 . ooOoO0o * iII111i % I1IiiI / iIii1I11I1II1 - iII111i
   if 67 - 67: IiII % i11iIiiIii
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 81 - 81: OoooooooOO . i11iIiiIii / O0 - I1Ii111 + I1ii11iIi11i % i11iIiiIii
 if 97 - 97: i11iIiiIii % OoooooooOO * I1IiiI
 if 84 - 84: I1Ii111
 if 82 - 82: OOooOOo . iII111i
 if 65 - 65: oO0o
 if 18 - 18: i1IIi % I11i * OoOoOO00 - I11i + OoO0O00 - O0
 if 36 - 36: iIii1I11I1II1 * iII111i / IiII % i1IIi
 if 8 - 8: I11i
 if 33 - 33: I1Ii111 . I11i . Ii1I - iIii1I11I1II1
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 96 - 96: II111iiii % oO0o . i1IIi + II111iiii . iII111i
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 if 64 - 64: oO0o / IiII
 if 86 - 86: I11i
 IiiI11iiI1i1 , IIIII1iii11 , I1I1i1 = eid_list [ 0 ]
 iIIi1 = [ lisp_print_eid_tuple ( IIIII1iii11 , I1I1i1 ) ]
 if 80 - 80: I1IiiI + iII111i * OoooooooOO . IiII . I1ii11iIi11i
 for IiiI11iiI1i1 , IIIII1iii11 , I1I1i1 in eid_list [ 1 : : ] :
  IiiI11iiI1i1 . state = LISP_RLOC_UNREACH_STATE
  IiiI11iiI1i1 . last_state_change = lisp_get_timestamp ( )
  iIIi1 . append ( lisp_print_eid_tuple ( IIIII1iii11 , I1I1i1 ) )
  if 20 - 20: Ii1I % O0 . o0oOOo0O0Ooo + i11iIiiIii % iII111i / o0oOOo0O0Ooo
  if 34 - 34: iIii1I11I1II1
 i1111 = bold ( "unreachable" , False )
 iII = red ( IiiI11iiI1i1 . rloc . print_address_no_iid ( ) , False )
 if 91 - 91: Oo0Ooo
 for O0oOoooooooOo00O in iIIi1 :
  IIIII1iii11 = green ( O0oOoooooooOo00O , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( iII , i1111 , IIIII1iii11 ) )
  if 98 - 98: iIii1I11I1II1 . OoO0O00
  if 1 - 1: OOooOOo % Oo0Ooo
  if 86 - 86: i11iIiiIii
  if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
  if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
  if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 for IiiI11iiI1i1 , IIIII1iii11 , I1I1i1 in eid_list :
  IIo0OooOO = lisp_map_cache . lookup_cache ( IIIII1iii11 , True )
  if ( IIo0OooOO ) : lisp_write_ipc_map_cache ( True , IIo0OooOO )
  if 79 - 79: I11i - II111iiii
 return
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 12 - 12: i1IIi . I1Ii111
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
 if 14 - 14: O0 . Oo0Ooo
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
 if 16 - 16: i11iIiiIii * Oo0Ooo
 if 76 - 76: iII111i . oO0o - i1IIi
 oo00o0o00Oo = lisp_get_default_route_next_hops ( )
 if 47 - 47: I1ii11iIi11i
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 69 - 69: oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
 I1Ii1i11I1I = 0
 ii1I = bold ( "RLOC-probe" , False )
 for IIiii1IiiIiii in lisp_rloc_probe_list . values ( ) :
  if 81 - 81: I11i
  if 31 - 31: OoooooooOO - OoO0O00 . iIii1I11I1II1 % I1IiiI
  if 98 - 98: I1IiiI + Ii1I
  if 7 - 7: o0oOOo0O0Ooo . OoooooooOO
  if 32 - 32: I1ii11iIi11i
  I1iIIii111i11i11 = None
  for IIi1I111iii , O0oOoooooooOo00O , oooiiIiIIIi1 in IIiii1IiiIiii :
   O0o = IIi1I111iii . rloc . print_address_no_iid ( )
   if 22 - 22: OOooOOo
   if 22 - 22: i11iIiiIii + IiII / IiII - I11i
   if 87 - 87: iII111i
   if 37 - 37: oO0o + OoO0O00
   OoOo00oOOo0o0 , iII1111II = lisp_allow_gleaning ( O0oOoooooooOo00O , IIi1I111iii )
   if ( OoOo00oOOo0o0 and iII1111II == False ) :
    IIIII1iii11 = green ( O0oOoooooooOo00O . print_address ( ) , False )
    O0o += ":{}" . format ( IIi1I111iii . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( O0o , False ) , IIIII1iii11 ) )
    if 46 - 46: oO0o . O0 % iIii1I11I1II1 - iIii1I11I1II1 . O0
    continue
    if 91 - 91: I1IiiI + IiII / OOooOOo - i1IIi % i11iIiiIii / iIii1I11I1II1
    if 73 - 73: i11iIiiIii . I1ii11iIi11i * OoOoOO00
    if 95 - 95: i1IIi + iIii1I11I1II1 . I1Ii111 / I1Ii111
    if 84 - 84: Oo0Ooo . OoO0O00 * IiII
    if 95 - 95: OoO0O00
    if 100 - 100: II111iiii
    if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
   if ( IIi1I111iii . down_state ( ) ) : continue
   if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
   if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
   if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
   if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
   if 40 - 40: o0oOOo0O0Ooo * I1IiiI
   if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
   if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
   if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
   if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
   if 16 - 16: oO0o
   if 32 - 32: OoooooooOO
   if ( I1iIIii111i11i11 ) :
    IIi1I111iii . last_rloc_probe_nonce = I1iIIii111i11i11 . last_rloc_probe_nonce
    if 77 - 77: Oo0Ooo . i1IIi - I11i
    if ( I1iIIii111i11i11 . translated_port == IIi1I111iii . translated_port and I1iIIii111i11i11 . rloc_name == IIi1I111iii . rloc_name ) :
     if 98 - 98: O0
     IIIII1iii11 = green ( lisp_print_eid_tuple ( O0oOoooooooOo00O , oooiiIiIIIi1 ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( O0o , False ) , IIIII1iii11 ) )
     if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
     continue
     if 54 - 54: i1IIi % iII111i
     if 16 - 16: II111iiii - Oo0Ooo
     if 44 - 44: OOooOOo / Oo0Ooo - I1ii11iIi11i + I11i . oO0o
   iiIIIi1I = None
   IiiI11iiI1i1 = None
   while ( True ) :
    IiiI11iiI1i1 = IIi1I111iii if IiiI11iiI1i1 == None else IiiI11iiI1i1 . next_rloc
    if ( IiiI11iiI1i1 == None ) : break
    if 85 - 85: iIii1I11I1II1 / Ii1I
    if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
    if 97 - 97: I1Ii111 + I1ii11iIi11i
    if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
    if 80 - 80: I11i
    if ( IiiI11iiI1i1 . rloc_next_hop != None ) :
     if ( IiiI11iiI1i1 . rloc_next_hop not in oo00o0o00Oo ) :
      if ( IiiI11iiI1i1 . up_state ( ) ) :
       iiiii111 , IIIiI = IiiI11iiI1i1 . rloc_next_hop
       IiiI11iiI1i1 . state = LISP_RLOC_UNREACH_STATE
       IiiI11iiI1i1 . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( IiiI11iiI1i1 . rloc , False )
       if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
      i1111 = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( IIIiI , iiiii111 ,
 red ( O0o , False ) , i1111 ) )
      continue
      if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
      if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
      if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
      if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
      if 65 - 65: I11i
      if 92 - 92: iII111i . IiII + i1IIi % i1IIi
    O0ooO0oOO = IiiI11iiI1i1 . last_rloc_probe
    IIIi111 = 0 if O0ooO0oOO == None else time . time ( ) - O0ooO0oOO
    if ( IiiI11iiI1i1 . unreach_state ( ) and IIIi111 < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( O0o , False ) ) )
     if 11 - 11: oO0o * Ii1I . I1Ii111
     continue
     if 91 - 91: I1ii11iIi11i % i1IIi / Ii1I
     if 62 - 62: I11i % IiII * I1Ii111 - II111iiii / OoooooooOO
     if 39 - 39: I1IiiI . O0 + I1ii11iIi11i . iIii1I11I1II1 + ooOoO0o
     if 54 - 54: II111iiii / iII111i + OOooOOo - i11iIiiIii % I1Ii111 / OoO0O00
     if 2 - 2: II111iiii + I1Ii111 - Ii1I
     if 44 - 44: II111iiii + OOooOOo % I1IiiI
    oooOo0OO = lisp_get_echo_nonce ( None , O0o )
    if ( oooOo0OO and oooOo0OO . request_nonce_timeout ( ) ) :
     IiiI11iiI1i1 . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     IiiI11iiI1i1 . last_state_change = lisp_get_timestamp ( )
     i1111 = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( O0o , False ) , i1111 ) )
     if 34 - 34: o0oOOo0O0Ooo / I1ii11iIi11i - o0oOOo0O0Ooo / i11iIiiIii
     lisp_update_rtr_updown ( IiiI11iiI1i1 . rloc , False )
     continue
     if 18 - 18: oO0o
     if 43 - 43: I11i / OOooOOo + OOooOOo
     if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
     if 90 - 90: OOooOOo
     if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
     if 65 - 65: oO0o
    if ( oooOo0OO and oooOo0OO . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( O0o , False ) ) )
     if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
     continue
     if 13 - 13: Ii1I
     if 34 - 34: I1IiiI / iIii1I11I1II1
     if 35 - 35: oO0o / oO0o
     if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
     if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
     if 77 - 77: O0
    if ( IiiI11iiI1i1 . last_rloc_probe != None ) :
     O0ooO0oOO = IiiI11iiI1i1 . last_rloc_probe_reply
     if ( O0ooO0oOO == None ) : O0ooO0oOO = 0
     IIIi111 = time . time ( ) - O0ooO0oOO
     if ( IiiI11iiI1i1 . up_state ( ) and IIIi111 >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
      IiiI11iiI1i1 . state = LISP_RLOC_UNREACH_STATE
      IiiI11iiI1i1 . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( IiiI11iiI1i1 . rloc , False )
      i1111 = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( O0o , False ) , i1111 ) )
      if 36 - 36: II111iiii
      if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
      lisp_mark_rlocs_for_other_eids ( IIiii1IiiIiii )
      if 7 - 7: i11iIiiIii
      if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
      if 41 - 41: IiII % II111iiii
    IiiI11iiI1i1 . last_rloc_probe = lisp_get_timestamp ( )
    if 99 - 99: IiII - O0
    O0Oo000oO0 = "" if IiiI11iiI1i1 . unreach_state ( ) == False else " unreachable"
    if 94 - 94: I1IiiI . I1ii11iIi11i / OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
    if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
    if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
    if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
    if 74 - 74: I11i . I11i
    if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
    if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
    Ooo0OO0 = ""
    IIIiI = None
    if ( IiiI11iiI1i1 . rloc_next_hop != None ) :
     iiiii111 , IIIiI = IiiI11iiI1i1 . rloc_next_hop
     lisp_install_host_route ( O0o , IIIiI , True )
     Ooo0OO0 = ", send on nh {}({})" . format ( IIIiI , iiiii111 )
     if 19 - 19: i1IIi
     if 32 - 32: I1IiiI
     if 97 - 97: iII111i
     if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
     if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
    O0O0o = IiiI11iiI1i1 . print_rloc_probe_rtt ( )
    Ooo000OO = O0o
    if ( IiiI11iiI1i1 . translated_port != 0 ) :
     Ooo000OO += ":{}" . format ( IiiI11iiI1i1 . translated_port )
     if 81 - 81: II111iiii
    Ooo000OO = red ( Ooo000OO , False )
    if ( IiiI11iiI1i1 . rloc_name != None ) :
     Ooo000OO += " (" + blue ( IiiI11iiI1i1 . rloc_name , False ) + ")"
     if 47 - 47: I1Ii111 * iII111i
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( ii1I , O0Oo000oO0 ,
 Ooo000OO , O0O0o , Ooo0OO0 ) )
    if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
    if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
    if 51 - 51: I1IiiI
    if 52 - 52: I1Ii111
    if 82 - 82: iII111i + II111iiii
    if 29 - 29: O0 % Ii1I * ooOoO0o % O0
    if 83 - 83: oO0o
    if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
    if ( IiiI11iiI1i1 . rloc_next_hop != None ) :
     iiIIIi1I = lisp_get_host_route_next_hop ( O0o )
     if ( iiIIIi1I ) : lisp_install_host_route ( O0o , iiIIIi1I , False )
     if 85 - 85: iIii1I11I1II1 / I11i
     if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
     if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
     if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
     if 89 - 89: ooOoO0o
     if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
    if ( IiiI11iiI1i1 . rloc . is_null ( ) ) :
     IiiI11iiI1i1 . rloc . copy_address ( IIi1I111iii . rloc )
     if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
     if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
     if 20 - 20: I11i
     if 37 - 37: I1Ii111
     if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
    i1iIi11iII = None if ( oooiiIiIIIi1 . is_null ( ) ) else O0oOoooooooOo00O
    OOi1i111iIIi = O0oOoooooooOo00O if ( oooiiIiIIIi1 . is_null ( ) ) else oooiiIiIIIi1
    lisp_send_map_request ( lisp_sockets , 0 , i1iIi11iII , OOi1i111iIIi , IiiI11iiI1i1 )
    I1iIIii111i11i11 = IIi1I111iii
    if 10 - 10: i1IIi . ooOoO0o . i1IIi - Ii1I
    if 58 - 58: II111iiii * I1IiiI / i11iIiiIii * I1IiiI
    if 65 - 65: o0oOOo0O0Ooo - IiII
    if 3 - 3: OOooOOo * ooOoO0o / i11iIiiIii . OoO0O00 * ooOoO0o
    if ( IIIiI ) : lisp_install_host_route ( O0o , IIIiI , False )
    if 58 - 58: i1IIi - OoO0O00 * II111iiii
    if 92 - 92: ooOoO0o / I1Ii111 . iII111i
    if 59 - 59: Ii1I - OoO0O00 % iII111i + I1ii11iIi11i * iII111i
    if 51 - 51: ooOoO0o - Oo0Ooo / iII111i . I11i - Ii1I / OOooOOo
    if 4 - 4: II111iiii + OoOoOO00 . ooOoO0o - I11i . I1IiiI
   if ( iiIIIi1I ) : lisp_install_host_route ( O0o , iiIIIi1I , True )
   if 46 - 46: II111iiii
   if 38 - 38: OOooOOo % II111iiii
   if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
   if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
   I1Ii1i11I1I += 1
   if ( ( I1Ii1i11I1I % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
   if 89 - 89: I1Ii111
   if 29 - 29: I11i * ooOoO0o - OoooooooOO
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
 if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
 if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
 if 73 - 73: OoooooooOO
 if 25 - 25: i1IIi . II111iiii . I1Ii111
 if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 if 61 - 61: I1ii11iIi11i
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 12 - 12: OoO0O00
 if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if 7 - 7: Oo0Ooo
 if 38 - 38: Oo0Ooo - I1ii11iIi11i
 if ( lisp_i_am_itr == False ) : return
 if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
 if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
 if 3 - 3: Ii1I
 if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
 if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
 if ( lisp_register_all_rtrs ) : return
 if 86 - 86: Oo0Ooo
 o00o0 = rtr . print_address_no_iid ( )
 if 92 - 92: OOooOOo . II111iiii - I11i - I11i
 if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
 if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
 if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
 if 64 - 64: I1IiiI % ooOoO0o
 if ( lisp_rtr_list . has_key ( o00o0 ) == False ) : return
 if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( o00o0 , False ) , bold ( updown , False ) ) )
 if 80 - 80: OOooOOo * I11i / OOooOOo - oO0o
 if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
 if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
 if 28 - 28: II111iiii / iIii1I11I1II1 / iII111i - o0oOOo0O0Ooo . I1IiiI / O0
 O0oO00o0o0oo0 = "rtr%{}%{}" . format ( o00o0 , updown )
 O0oO00o0o0oo0 = lisp_command_ipc ( O0oO00o0o0oo0 , "lisp-itr" )
 lisp_ipc ( O0oO00o0o0oo0 , lisp_ipc_socket , "lisp-etr" )
 return
 if 16 - 16: ooOoO0o * oO0o . OoooooooOO
 if 44 - 44: iIii1I11I1II1 * OOooOOo + OoO0O00 - OoooooooOO
 if 13 - 13: Oo0Ooo . I11i . II111iiii
 if 6 - 6: OOooOOo . IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
 if 85 - 85: i11iIiiIii + OoOoOO00
 if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
 if 60 - 60: OOooOOo . Ii1I
def lisp_process_rloc_probe_reply ( rloc , source , port , nonce , hop_count , ttl ) :
 ii1I = bold ( "RLOC-probe reply" , False )
 Iiio0OO0O0 = rloc . print_address_no_iid ( )
 ooOOo0 = source . print_address_no_iid ( )
 I11iiIiii1I1 = lisp_rloc_probe_list
 if 85 - 85: oO0o
 if 14 - 14: IiII / iIii1I11I1II1 . OoooooooOO
 if 14 - 14: IiII * OoooooooOO - iIii1I11I1II1
 if 11 - 11: I1IiiI + Oo0Ooo % I1Ii111 * Ii1I - iIii1I11I1II1 % I1ii11iIi11i
 if 43 - 43: o0oOOo0O0Ooo * o0oOOo0O0Ooo . iII111i / Oo0Ooo - i11iIiiIii
 if 66 - 66: I1IiiI / i1IIi + o0oOOo0O0Ooo % IiII - OoOoOO00 / Oo0Ooo
 O0o0O0OO0o = Iiio0OO0O0
 if ( I11iiIiii1I1 . has_key ( O0o0O0OO0o ) == False ) :
  O0o0O0OO0o += ":" + str ( port )
  if ( I11iiIiii1I1 . has_key ( O0o0O0OO0o ) == False ) :
   O0o0O0OO0o = ooOOo0
   if ( I11iiIiii1I1 . has_key ( O0o0O0OO0o ) == False ) :
    O0o0O0OO0o += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( ii1I , red ( Iiio0OO0O0 , False ) , red ( ooOOo0 ,
    # OOooOOo - oO0o
 False ) , port ) )
    return
    if 58 - 58: I1Ii111 / i1IIi * OoooooooOO * II111iiii / i1IIi - ooOoO0o
    if 86 - 86: I1ii11iIi11i . o0oOOo0O0Ooo
    if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
    if 33 - 33: OOooOOo % OoooooooOO
    if 98 - 98: Ii1I
    if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
    if 95 - 95: iIii1I11I1II1 / O0 % O0
    if 53 - 53: ooOoO0o . ooOoO0o
 for rloc , O0oOoooooooOo00O , oooiiIiIIIi1 in lisp_rloc_probe_list [ O0o0O0OO0o ] :
  if ( lisp_i_am_rtr and rloc . translated_port != 0 and
 rloc . translated_port != port ) : continue
  if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
  rloc . process_rloc_probe_reply ( nonce , O0oOoooooooOo00O , oooiiIiIIIi1 , hop_count , ttl )
  if 18 - 18: OoO0O00 * ooOoO0o
 return
 if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
 if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
 if 67 - 67: I1IiiI
 if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
 if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
 if 59 - 59: i11iIiiIii
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
def lisp_db_list_length ( ) :
 I1Ii1i11I1I = 0
 for IIi1 in lisp_db_list :
  I1Ii1i11I1I += len ( IIi1 . dynamic_eids ) if IIi1 . dynamic_eid_configured ( ) else 1
  I1Ii1i11I1I += len ( IIi1 . eid . iid_list )
  if 59 - 59: I1ii11iIi11i
 return ( I1Ii1i11I1I )
 if 47 - 47: I1IiiI + Oo0Ooo
 if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
 if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
def lisp_is_myeid ( eid ) :
 for IIi1 in lisp_db_list :
  if ( eid . is_more_specific ( IIi1 . eid ) ) : return ( True )
  if 58 - 58: IiII . Ii1I + II111iiii
 return ( False )
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 if 54 - 54: oO0o * II111iiii
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 if 98 - 98: ooOoO0o
 if 73 - 73: I1Ii111
 if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
 if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
 if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
 if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 oooOo0OO = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  oooOo0OO = lisp_nonce_echo_list [ rloc_str ]
  if 76 - 76: iII111i * OOooOOo
 return ( oooOo0OO )
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if 40 - 40: iII111i
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
 if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
def lisp_decode_dist_name ( packet ) :
 I1Ii1i11I1I = 0
 IIiI1111I = ""
 if 82 - 82: II111iiii . Oo0Ooo . Ii1I * o0oOOo0O0Ooo
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( I1Ii1i11I1I == 255 ) : return ( [ None , None ] )
  IIiI1111I += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  I1Ii1i11I1I += 1
  if 17 - 17: II111iiii
  if 91 - 91: oO0o - oO0o % Ii1I % iIii1I11I1II1 / OoOoOO00
 packet = packet [ 1 : : ]
 return ( packet , IIiI1111I )
 if 60 - 60: I1IiiI / iIii1I11I1II1 - o0oOOo0O0Ooo / OoooooooOO * OoooooooOO
 if 22 - 22: I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo . i1IIi * OoO0O00
 if 7 - 7: O0 / I1IiiI + OoO0O00 . i1IIi - ooOoO0o + ooOoO0o
 if 93 - 93: oO0o - I1IiiI / I1ii11iIi11i % o0oOOo0O0Ooo / OoooooooOO + II111iiii
 if 10 - 10: o0oOOo0O0Ooo - iII111i . O0 + OoO0O00 - Oo0Ooo - i11iIiiIii
 if 37 - 37: iIii1I11I1II1
 if 37 - 37: II111iiii % OoOoOO00 . IiII * ooOoO0o . I1IiiI
 if 25 - 25: OoooooooOO % i1IIi . I1Ii111 / OoOoOO00 - I1ii11iIi11i
def lisp_write_flow_log ( flow_log ) :
 o000 = open ( "./logs/lisp-flow.log" , "a" )
 if 15 - 15: iIii1I11I1II1
 I1Ii1i11I1I = 0
 for I1IIiiiiI1iIi in flow_log :
  oOo0O000oo0 = I1IIiiiiI1iIi [ 3 ]
  OOO0o0OoOO = oOo0O000oo0 . print_flow ( I1IIiiiiI1iIi [ 0 ] , I1IIiiiiI1iIi [ 1 ] , I1IIiiiiI1iIi [ 2 ] )
  o000 . write ( OOO0o0OoOO )
  I1Ii1i11I1I += 1
  if 68 - 68: Ii1I
 o000 . close ( )
 del ( flow_log )
 if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 I1Ii1i11I1I = bold ( str ( I1Ii1i11I1I ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( I1Ii1i11I1I ) )
 return
 if 43 - 43: Oo0Ooo
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
 if 66 - 66: o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
def lisp_policy_command ( kv_pair ) :
 Ii1Ii = lisp_policy ( "" )
 iiIIiI111Ii1I = None
 if 2 - 2: I1ii11iIi11i % O0 . I1ii11iIi11i
 iiiOOO0O = [ ]
 for o0Ooo0O00 in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  iiiOOO0O . append ( lisp_policy_match ( ) )
  if 21 - 21: Ii1I % Oo0Ooo . iII111i . O0 + iIii1I11I1II1
  if 42 - 42: oO0o . OOooOOo * OoO0O00
 for ooOoooO0o in kv_pair . keys ( ) :
  i111II = kv_pair [ ooOoooO0o ]
  if 64 - 64: O0 . Oo0Ooo
  if 59 - 59: Oo0Ooo
  if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
  if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
  if ( ooOoooO0o == "instance-id" ) :
   for o0Ooo0O00 in range ( len ( iiiOOO0O ) ) :
    iI1Iii111iI = i111II [ o0Ooo0O00 ]
    if ( iI1Iii111iI == "" ) : continue
    o0oo = iiiOOO0O [ o0Ooo0O00 ]
    if ( o0oo . source_eid == None ) :
     o0oo . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
    if ( o0oo . dest_eid == None ) :
     o0oo . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 92 - 92: I1IiiI . I11i
    o0oo . source_eid . instance_id = int ( iI1Iii111iI )
    o0oo . dest_eid . instance_id = int ( iI1Iii111iI )
    if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
    if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
  if ( ooOoooO0o == "source-eid" ) :
   for o0Ooo0O00 in range ( len ( iiiOOO0O ) ) :
    iI1Iii111iI = i111II [ o0Ooo0O00 ]
    if ( iI1Iii111iI == "" ) : continue
    o0oo = iiiOOO0O [ o0Ooo0O00 ]
    if ( o0oo . source_eid == None ) :
     o0oo . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 25 - 25: I1ii11iIi11i / I11i + i1IIi . I1IiiI + ooOoO0o
    o0ooOo00O = o0oo . source_eid . instance_id
    o0oo . source_eid . store_prefix ( iI1Iii111iI )
    o0oo . source_eid . instance_id = o0ooOo00O
    if 29 - 29: IiII + I1ii11iIi11i
    if 8 - 8: IiII % I1IiiI
  if ( ooOoooO0o == "destination-eid" ) :
   for o0Ooo0O00 in range ( len ( iiiOOO0O ) ) :
    iI1Iii111iI = i111II [ o0Ooo0O00 ]
    if ( iI1Iii111iI == "" ) : continue
    o0oo = iiiOOO0O [ o0Ooo0O00 ]
    if ( o0oo . dest_eid == None ) :
     o0oo . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 10 - 10: OoooooooOO / OoOoOO00
    o0ooOo00O = o0oo . dest_eid . instance_id
    o0oo . dest_eid . store_prefix ( iI1Iii111iI )
    o0oo . dest_eid . instance_id = o0ooOo00O
    if 77 - 77: OoOoOO00
    if 10 - 10: IiII / i11iIiiIii
  if ( ooOoooO0o == "source-rloc" ) :
   for o0Ooo0O00 in range ( len ( iiiOOO0O ) ) :
    iI1Iii111iI = i111II [ o0Ooo0O00 ]
    if ( iI1Iii111iI == "" ) : continue
    o0oo = iiiOOO0O [ o0Ooo0O00 ]
    o0oo . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    o0oo . source_rloc . store_prefix ( iI1Iii111iI )
    if 19 - 19: OoO0O00
    if 100 - 100: I1ii11iIi11i - I1ii11iIi11i
  if ( ooOoooO0o == "destination-rloc" ) :
   for o0Ooo0O00 in range ( len ( iiiOOO0O ) ) :
    iI1Iii111iI = i111II [ o0Ooo0O00 ]
    if ( iI1Iii111iI == "" ) : continue
    o0oo = iiiOOO0O [ o0Ooo0O00 ]
    o0oo . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    o0oo . dest_rloc . store_prefix ( iI1Iii111iI )
    if 38 - 38: I1Ii111
    if 23 - 23: Ii1I . I1ii11iIi11i + I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
  if ( ooOoooO0o == "rloc-record-name" ) :
   for o0Ooo0O00 in range ( len ( iiiOOO0O ) ) :
    iI1Iii111iI = i111II [ o0Ooo0O00 ]
    if ( iI1Iii111iI == "" ) : continue
    o0oo = iiiOOO0O [ o0Ooo0O00 ]
    o0oo . rloc_record_name = iI1Iii111iI
    if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
    if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
  if ( ooOoooO0o == "geo-name" ) :
   for o0Ooo0O00 in range ( len ( iiiOOO0O ) ) :
    iI1Iii111iI = i111II [ o0Ooo0O00 ]
    if ( iI1Iii111iI == "" ) : continue
    o0oo = iiiOOO0O [ o0Ooo0O00 ]
    o0oo . geo_name = iI1Iii111iI
    if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
    if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
  if ( ooOoooO0o == "elp-name" ) :
   for o0Ooo0O00 in range ( len ( iiiOOO0O ) ) :
    iI1Iii111iI = i111II [ o0Ooo0O00 ]
    if ( iI1Iii111iI == "" ) : continue
    o0oo = iiiOOO0O [ o0Ooo0O00 ]
    o0oo . elp_name = iI1Iii111iI
    if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
    if 40 - 40: iII111i - I1IiiI + OoOoOO00
  if ( ooOoooO0o == "rle-name" ) :
   for o0Ooo0O00 in range ( len ( iiiOOO0O ) ) :
    iI1Iii111iI = i111II [ o0Ooo0O00 ]
    if ( iI1Iii111iI == "" ) : continue
    o0oo = iiiOOO0O [ o0Ooo0O00 ]
    o0oo . rle_name = iI1Iii111iI
    if 2 - 2: I11i - II111iiii / I1Ii111
    if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
  if ( ooOoooO0o == "json-name" ) :
   for o0Ooo0O00 in range ( len ( iiiOOO0O ) ) :
    iI1Iii111iI = i111II [ o0Ooo0O00 ]
    if ( iI1Iii111iI == "" ) : continue
    o0oo = iiiOOO0O [ o0Ooo0O00 ]
    o0oo . json_name = iI1Iii111iI
    if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
    if 76 - 76: ooOoO0o . I11i * OoO0O00
  if ( ooOoooO0o == "datetime-range" ) :
   for o0Ooo0O00 in range ( len ( iiiOOO0O ) ) :
    iI1Iii111iI = i111II [ o0Ooo0O00 ]
    o0oo = iiiOOO0O [ o0Ooo0O00 ]
    if ( iI1Iii111iI == "" ) : continue
    IIii1 = lisp_datetime ( iI1Iii111iI [ 0 : 19 ] )
    iI1I11ii11I1I = lisp_datetime ( iI1Iii111iI [ 19 : : ] )
    if ( IIii1 . valid_datetime ( ) and iI1I11ii11I1I . valid_datetime ( ) ) :
     o0oo . datetime_lower = IIii1
     o0oo . datetime_upper = iI1I11ii11I1I
     if 53 - 53: II111iiii / OoOoOO00 / IiII * oO0o
     if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
     if 93 - 93: iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1 . oO0o % Oo0Ooo
     if 92 - 92: OoO0O00
     if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 % ooOoO0o
     if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
     if 38 - 38: o0oOOo0O0Ooo . O0 - OoO0O00 % I11i
  if ( ooOoooO0o == "set-action" ) :
   Ii1Ii . set_action = i111II
   if 80 - 80: o0oOOo0O0Ooo
  if ( ooOoooO0o == "set-record-ttl" ) :
   Ii1Ii . set_record_ttl = int ( i111II )
   if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
  if ( ooOoooO0o == "set-instance-id" ) :
   if ( Ii1Ii . set_source_eid == None ) :
    Ii1Ii . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
   if ( Ii1Ii . set_dest_eid == None ) :
    Ii1Ii . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 15 - 15: I1Ii111
   iiIIiI111Ii1I = int ( i111II )
   Ii1Ii . set_source_eid . instance_id = iiIIiI111Ii1I
   Ii1Ii . set_dest_eid . instance_id = iiIIiI111Ii1I
   if 38 - 38: O0
  if ( ooOoooO0o == "set-source-eid" ) :
   if ( Ii1Ii . set_source_eid == None ) :
    Ii1Ii . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
   Ii1Ii . set_source_eid . store_prefix ( i111II )
   if ( iiIIiI111Ii1I != None ) : Ii1Ii . set_source_eid . instance_id = iiIIiI111Ii1I
   if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
  if ( ooOoooO0o == "set-destination-eid" ) :
   if ( Ii1Ii . set_dest_eid == None ) :
    Ii1Ii . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
   Ii1Ii . set_dest_eid . store_prefix ( i111II )
   if ( iiIIiI111Ii1I != None ) : Ii1Ii . set_dest_eid . instance_id = iiIIiI111Ii1I
   if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
  if ( ooOoooO0o == "set-rloc-address" ) :
   Ii1Ii . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   Ii1Ii . set_rloc_address . store_address ( i111II )
   if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
  if ( ooOoooO0o == "set-rloc-record-name" ) :
   Ii1Ii . set_rloc_record_name = i111II
   if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
  if ( ooOoooO0o == "set-elp-name" ) :
   Ii1Ii . set_elp_name = i111II
   if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
  if ( ooOoooO0o == "set-geo-name" ) :
   Ii1Ii . set_geo_name = i111II
   if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
  if ( ooOoooO0o == "set-rle-name" ) :
   Ii1Ii . set_rle_name = i111II
   if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
  if ( ooOoooO0o == "set-json-name" ) :
   Ii1Ii . set_json_name = i111II
   if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
  if ( ooOoooO0o == "policy-name" ) :
   Ii1Ii . policy_name = i111II
   if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
   if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
   if 47 - 47: OOooOOo + IiII
   if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
   if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
   if 64 - 64: Ii1I
 Ii1Ii . match_clauses = iiiOOO0O
 Ii1Ii . save_policy ( )
 return
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
lisp_policy_commands = {
 "lisp policy" : [ lisp_policy_command , {
 "policy-name" : [ True ] ,
 "match" : [ ] ,
 "instance-id" : [ True , 0 , 0xffffffff ] ,
 "source-eid" : [ True ] ,
 "destination-eid" : [ True ] ,
 "source-rloc" : [ True ] ,
 "destination-rloc" : [ True ] ,
 "rloc-record-name" : [ True ] ,
 "elp-name" : [ True ] ,
 "geo-name" : [ True ] ,
 "rle-name" : [ True ] ,
 "json-name" : [ True ] ,
 "datetime-range" : [ True ] ,
 "set-action" : [ False , "process" , "drop" ] ,
 "set-record-ttl" : [ True , 0 , 0x7fffffff ] ,
 "set-instance-id" : [ True , 0 , 0xffffffff ] ,
 "set-source-eid" : [ True ] ,
 "set-destination-eid" : [ True ] ,
 "set-rloc-address" : [ True ] ,
 "set-rloc-record-name" : [ True ] ,
 "set-elp-name" : [ True ] ,
 "set-geo-name" : [ True ] ,
 "set-rle-name" : [ True ] ,
 "set-json-name" : [ True ] } ]
 }
if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
if 45 - 45: OOooOOo / Ii1I % O0
if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
if 96 - 96: oO0o
if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 64 - 64: I1IiiI % i11iIiiIii / oO0o
 OooOOoo0O = command
 if ( interface != "" ) : OooOOoo0O = interface + ": " + OooOOoo0O
 lprint ( "Send CLI command '{}' to hardware" . format ( OooOOoo0O ) )
 if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 31 - 31: OoO0O00
 if 89 - 89: II111iiii
 if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
 if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
 if 85 - 85: O0 * OOooOOo % I1Ii111
 if 33 - 33: O0
 if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
def lisp_arista_is_alive ( prefix ) :
 ooo0o0 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 iiIiI = commands . getoutput ( "FastCli -c '{}'" . format ( ooo0o0 ) )
 if 43 - 43: iIii1I11I1II1
 if 88 - 88: I1IiiI - OoO0O00 . O0 . oO0o
 if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
 if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
 iiIiI = iiIiI . split ( "\n" ) [ 1 ]
 oOO0O00O0 = iiIiI . split ( " " )
 oOO0O00O0 = oOO0O00O0 [ - 1 ] . replace ( "\r" , "" )
 if 69 - 69: o0oOOo0O0Ooo * OOooOOo - ooOoO0o
 if 14 - 14: o0oOOo0O0Ooo . OoooooooOO - I1ii11iIi11i * iII111i / ooOoO0o
 if 99 - 99: I1ii11iIi11i + I11i
 if 29 - 29: I1ii11iIi11i / oO0o
 return ( oOO0O00O0 == "Y" )
 if 2 - 2: Oo0Ooo / IiII - OoooooooOO
 if 65 - 65: OoO0O00 - Ii1I
 if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
 if 15 - 15: Oo0Ooo
 if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
 if 84 - 84: o0oOOo0O0Ooo * I11i
 if 22 - 22: i1IIi + OOooOOo % OoooooooOO
 if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
 if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 if 66 - 66: OoooooooOO
 if 90 - 90: IiII - OoOoOO00
 if 98 - 98: Oo0Ooo / oO0o . Ii1I
 if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
 if 37 - 37: iII111i - Ii1I . oO0o
 if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
 if 25 - 25: oO0o
 if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
 if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
 if 39 - 39: iIii1I11I1II1 % ooOoO0o
 if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
 if 36 - 36: IiII / I1IiiI % iII111i / iII111i
 if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
 if 65 - 65: O0 + O0 * I1Ii111
 if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
 if 16 - 16: I11i % iII111i
 if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
 if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
 if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
 if 1 - 1: O0 / iIii1I11I1II1
 if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
 if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
 if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
 if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
 if 16 - 16: o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii . I1ii11iIi11i
 if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
 if 100 - 100: o0oOOo0O0Ooo
 if 95 - 95: iII111i * oO0o * i1IIi
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
def lisp_program_vxlan_hardware ( mc ) :
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 if 92 - 92: OoOoOO00 + oO0o
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
 if 28 - 28: I1IiiI . iIii1I11I1II1
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 12 - 12: I1Ii111 * OOooOOo
 if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
 if 45 - 45: OoooooooOO * oO0o
 if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 16 - 16: Oo0Ooo
 if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
 if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
 iI1iIIiIii1I = mc . eid . print_prefix_no_iid ( )
 IiiI11iiI1i1 = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 if 33 - 33: OOooOOo - OoooooooOO . iII111i
 if 2 - 2: I11i + i1IIi
 O00Oo000 = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( iI1iIIiIii1I ) )
 if 96 - 96: I1IiiI . IiII + I11i / iIii1I11I1II1
 if ( O00Oo000 != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( iI1iIIiIii1I , False ) , O00Oo000 ) )
  if 27 - 27: I11i - Ii1I * OoOoOO00 % iIii1I11I1II1
  return
  if 69 - 69: Ii1I . II111iiii + o0oOOo0O0Ooo * iII111i
  if 95 - 95: II111iiii / iII111i + i1IIi
  if 70 - 70: IiII . I1Ii111
  if 29 - 29: Oo0Ooo . i11iIiiIii + OoOoOO00 - Oo0Ooo
  if 13 - 13: ooOoO0o
  if 56 - 56: I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / OoooooooOO - I1IiiI
  if 3 - 3: ooOoO0o
 oO0oOO00 = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( oO0oOO00 . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 33 - 33: OoO0O00 / OOooOOo % Oo0Ooo . o0oOOo0O0Ooo % II111iiii
 if ( oO0oOO00 . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 62 - 62: iII111i . OoooooooOO - i1IIi
 OO0oooO = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( OO0oooO == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 38 - 38: I1ii11iIi11i / o0oOOo0O0Ooo
 OO0oooO = OO0oooO . split ( "inet " ) [ 1 ]
 OO0oooO = OO0oooO . split ( "/" ) [ 0 ]
 if 95 - 95: iIii1I11I1II1 / OoOoOO00 % I1Ii111
 if 54 - 54: OoooooooOO % Ii1I
 if 100 - 100: OOooOOo - I11i . O0 * i1IIi % OoooooooOO - ooOoO0o
 if 54 - 54: O0 + I11i
 if 71 - 71: OoOoOO00
 if 29 - 29: O0 . i11iIiiIii
 if 51 - 51: IiII
 ooOI1IIiI11IiI = [ ]
 i1i1o0o000O0 = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for OoO0o0OOOO in i1i1o0o000O0 :
  if ( OoO0o0OOOO . find ( "vlan4094" ) == - 1 ) : continue
  if ( OoO0o0OOOO . find ( "(incomplete)" ) == - 1 ) : continue
  iiIIIi1I = OoO0o0OOOO . split ( " " ) [ 0 ]
  ooOI1IIiI11IiI . append ( iiIIIi1I )
  if 57 - 57: I1ii11iIi11i + i1IIi - I1Ii111
  if 7 - 7: Ii1I
 iiIIIi1I = None
 ooOoo00OoO = OO0oooO
 OO0oooO = OO0oooO . split ( "." )
 for o0Ooo0O00 in range ( 1 , 255 ) :
  OO0oooO [ 3 ] = str ( o0Ooo0O00 )
  O0o0O0OO0o = "." . join ( OO0oooO )
  if ( O0o0O0OO0o in ooOI1IIiI11IiI ) : continue
  if ( O0o0O0OO0o == ooOoo00OoO ) : continue
  iiIIIi1I = O0o0O0OO0o
  break
  if 72 - 72: OoO0O00 . Oo0Ooo % ooOoO0o / o0oOOo0O0Ooo . IiII . iII111i
 if ( iiIIIi1I == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 28 - 28: i1IIi % iIii1I11I1II1 . i11iIiiIii - OoO0O00
  return
  if 97 - 97: O0 / i1IIi - Oo0Ooo % i11iIiiIii + OOooOOo % iII111i
  if 59 - 59: I11i
  if 23 - 23: OoOoOO00 * I1Ii111
  if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
  if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
  if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
  if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
 iIIiIIII11iii = IiiI11iiI1i1 . split ( "." )
 I1I1IIIiI = lisp_hex_string ( iIIiIIII11iii [ 1 ] ) . zfill ( 2 )
 OOO000OO = lisp_hex_string ( iIIiIIII11iii [ 2 ] ) . zfill ( 2 )
 IiIii1IIIIi = lisp_hex_string ( iIIiIIII11iii [ 3 ] ) . zfill ( 2 )
 iI1ii1ii1I = "00:00:00:{}:{}:{}" . format ( I1I1IIIiI , OOO000OO , IiIii1IIIIi )
 Ooooooo000O = "0000.00{}.{}{}" . format ( I1I1IIIiI , OOO000OO , IiIii1IIIIi )
 o0000OO0o = "arp -i vlan4094 -s {} {}" . format ( iiIIIi1I , iI1ii1ii1I )
 os . system ( o0000OO0o )
 if 89 - 89: ooOoO0o * O0 / I1Ii111 / Oo0Ooo
 if 77 - 77: iIii1I11I1II1
 if 46 - 46: oO0o . OoO0O00
 if 82 - 82: OoooooooOO * Ii1I + O0 * I1IiiI + ooOoO0o
 OO0oooOOO0 = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( Ooooooo000O , IiiI11iiI1i1 )
 if 60 - 60: o0oOOo0O0Ooo
 lisp_send_to_arista ( OO0oooOOO0 , None )
 if 63 - 63: i11iIiiIii * Oo0Ooo * I1Ii111
 if 56 - 56: I1Ii111 . i11iIiiIii
 if 76 - 76: II111iiii / ooOoO0o * i11iIiiIii . O0 / O0 - i11iIiiIii
 if 89 - 89: o0oOOo0O0Ooo . I1Ii111 * I11i + oO0o - OoooooooOO + OoO0O00
 if 25 - 25: i1IIi * I1Ii111 * iII111i . OoooooooOO
 ooOiiIiI1I = "ip route add {} via {}" . format ( iI1iIIiIii1I , iiIIIi1I )
 os . system ( ooOiiIiI1I )
 if 52 - 52: OOooOOo / oO0o - I1ii11iIi11i * OoooooooOO * OoO0O00
 lprint ( "Hardware programmed with commands:" )
 ooOiiIiI1I = ooOiiIiI1I . replace ( iI1iIIiIii1I , green ( iI1iIIiIii1I , False ) )
 lprint ( "  " + ooOiiIiI1I )
 lprint ( "  " + o0000OO0o )
 OO0oooOOO0 = OO0oooOOO0 . replace ( IiiI11iiI1i1 , red ( IiiI11iiI1i1 , False ) )
 lprint ( "  " + OO0oooOOO0 )
 return
 if 71 - 71: iII111i % i11iIiiIii * OoooooooOO * iII111i
 if 92 - 92: I11i % iIii1I11I1II1 * iII111i - OoooooooOO - I11i
 if 34 - 34: I1Ii111 / i1IIi / O0 / OoooooooOO
 if 55 - 55: I1Ii111 . I1IiiI * iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
def lisp_clear_hardware_walk ( mc , parms ) :
 o0ooOoooO0oOO = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( o0ooOoooO0oOO ) )
 return ( [ True , None ] )
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 if 78 - 78: II111iiii % OOooOOo
 if 6 - 6: OOooOOo
 if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 if 55 - 55: OOooOOo + oO0o - II111iiii
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if 59 - 59: OoOoOO00
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list
 if 96 - 96: I1IiiI
 ii1iOo = bold ( "User cleared" , False )
 I1Ii1i11I1I = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( ii1iOo , I1Ii1i11I1I ) )
 if 4 - 4: iIii1I11I1II1 * O0 - iII111i * IiII
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 12 - 12: IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . I1ii11iIi11i + OoooooooOO
 lisp_map_cache = lisp_cache ( )
 if 37 - 37: IiII % OoooooooOO * iIii1I11I1II1 / OOooOOo + I1Ii111 + o0oOOo0O0Ooo
 if 5 - 5: I1IiiI - ooOoO0o / OoooooooOO
 if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
 if 41 - 41: ooOoO0o * I1Ii111
 if 40 - 40: OoOoOO00
 lisp_rloc_probe_list = { }
 if 60 - 60: IiII . i11iIiiIii * II111iiii . Ii1I
 if 10 - 10: O0
 if 65 - 65: I11i % i11iIiiIii + i11iIiiIii % II111iiii
 if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 96 - 96: iIii1I11I1II1 * iII111i / OOooOOo * iIii1I11I1II1 - O0
 if 28 - 28: I11i / I1IiiI - I1Ii111 + I1ii11iIi11i % iIii1I11I1II1
 if 35 - 35: iIii1I11I1II1 % Oo0Ooo % iII111i / iIii1I11I1II1 - I1ii11iIi11i . Oo0Ooo
 if 81 - 81: II111iiii + oO0o
 if 67 - 67: ooOoO0o + I11i - I1ii11iIi11i - OoooooooOO
 lisp_rtr_list = { }
 if 37 - 37: I11i % I1IiiI
 if 32 - 32: OOooOOo + OoooooooOO . IiII . Oo0Ooo * iII111i
 if 86 - 86: I1ii11iIi11i . iII111i + Ii1I - IiII / i11iIiiIii + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo - IiII + OoOoOO00 - II111iiii
 lisp_process_data_plane_restart ( True )
 return
 if 24 - 24: I1Ii111 - IiII % I1IiiI - OoooooooOO % Ii1I
 if 56 - 56: I1ii11iIi11i
 if 40 - 40: OoooooooOO
 if 100 - 100: IiII - I11i
 if 79 - 79: iII111i % O0
 if 73 - 73: Oo0Ooo
 if 13 - 13: OOooOOo - ooOoO0o
 if 8 - 8: I1Ii111 % oO0o
 if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
 if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
 if 90 - 90: OoO0O00
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 54 - 54: OOooOOo + Oo0Ooo * o0oOOo0O0Ooo - iIii1I11I1II1 * ooOoO0o
 OoOoo00Oo0o0O = lisp_myrlocs [ 0 ]
 if 48 - 48: I1IiiI
 if 54 - 54: oO0o . Ii1I . Ii1I . iIii1I11I1II1 / OOooOOo * O0
 if 7 - 7: OoO0O00 + OoO0O00 * OoooooooOO
 if 71 - 71: O0 - II111iiii + IiII
 if 34 - 34: Oo0Ooo % I1IiiI - ooOoO0o / iII111i - Ii1I / II111iiii
 O0oOOOO00oOOo = len ( packet ) + 28
 IiiIIi1 = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( O0oOOOO00oOOo ) , 0 , 64 ,
 17 , 0 , socket . htonl ( OoOoo00Oo0o0O . address ) , socket . htonl ( rloc . address ) )
 IiiIIi1 = lisp_ip_checksum ( IiiIIi1 )
 if 48 - 48: i11iIiiIii . Oo0Ooo
 OoOo = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( O0oOOOO00oOOo - 20 ) , 0 )
 if 64 - 64: OOooOOo * II111iiii * Ii1I
 if 77 - 77: ooOoO0o / i11iIiiIii * I1IiiI
 if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
 if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
 packet = lisp_packet ( IiiIIi1 + OoOo + packet )
 if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
 if 67 - 67: oO0o
 if 12 - 12: I1IiiI + OoooooooOO
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( OoOoo00Oo0o0O )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( OoOoo00Oo0o0O )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
 iII = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  O0Ooo = " {}" . format ( blue ( nat_info . hostname , False ) )
  ii1I = bold ( "RLOC-probe request" , False )
 else :
  O0Ooo = ""
  ii1I = bold ( "RLOC-probe reply" , False )
  if 19 - 19: OoooooooOO / IiII
  if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( ii1I , iII , O0Ooo , packet . encap_port ) )
 if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
 if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
 if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
 if 51 - 51: OoO0O00 - OoO0O00 * IiII
 if 24 - 24: OoooooooOO . II111iiii
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 97 - 97: II111iiii . O0
 iI1i1iiIiIi = lisp_sockets [ 3 ]
 packet . send_packet ( iI1i1iiIiIi , packet . outer_dest )
 del ( packet )
 return
 if 74 - 74: o0oOOo0O0Ooo
 if 15 - 15: oO0o % Oo0Ooo * i1IIi / OoO0O00 . iIii1I11I1II1 - O0
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
 if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 if 92 - 92: ooOoO0o - iII111i
 if 69 - 69: iII111i
 if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
 if 63 - 63: oO0o * OoO0O00 * oO0o
def lisp_get_default_route_next_hops ( ) :
 if 31 - 31: Oo0Ooo
 if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
 if 67 - 67: I1Ii111 . I1ii11iIi11i
 if 2 - 2: O0 + I1Ii111
 if ( lisp_is_macos ( ) ) :
  ooo0o0 = "route -n get default"
  o00ooIIIIIii1IiI = commands . getoutput ( ooo0o0 ) . split ( "\n" )
  I111IiIIII11 = oooOoO = None
  for o000 in o00ooIIIIIii1IiI :
   if ( o000 . find ( "gateway: " ) != - 1 ) : I111IiIIII11 = o000 . split ( ": " ) [ 1 ]
   if ( o000 . find ( "interface: " ) != - 1 ) : oooOoO = o000 . split ( ": " ) [ 1 ]
   if 37 - 37: i1IIi
  return ( [ [ oooOoO , I111IiIIII11 ] ] )
  if 27 - 27: O0 % OoOoOO00 * Oo0Ooo * Ii1I * iII111i
  if 37 - 37: i11iIiiIii + OoO0O00 . OoOoOO00 / I1ii11iIi11i / I1IiiI + iIii1I11I1II1
  if 3 - 3: I1ii11iIi11i * ooOoO0o - OOooOOo - iII111i
  if 67 - 67: O0 / Oo0Ooo / Oo0Ooo / ooOoO0o
  if 72 - 72: o0oOOo0O0Ooo . i11iIiiIii
 ooo0o0 = "ip route | egrep 'default via'"
 OO0o0oOo0oOO = commands . getoutput ( ooo0o0 ) . split ( "\n" )
 if 59 - 59: OoOoOO00 . Ii1I - ooOoO0o - oO0o
 O00o0OoO = [ ]
 for O00Oo000 in OO0o0oOo0oOO :
  if ( O00Oo000 . find ( " metric " ) != - 1 ) : continue
  oO = O00Oo000 . split ( " " )
  try :
   IIIi1i1Ii1 = oO . index ( "via" ) + 1
   if ( IIIi1i1Ii1 >= len ( oO ) ) : continue
   I1IIIiI11I1i1 = oO . index ( "dev" ) + 1
   if ( I1IIIiI11I1i1 >= len ( oO ) ) : continue
  except :
   continue
   if 64 - 64: Oo0Ooo % o0oOOo0O0Ooo + I1ii11iIi11i * IiII
   if 10 - 10: ooOoO0o . I1IiiI . Oo0Ooo * I1ii11iIi11i
  O00o0OoO . append ( [ oO [ I1IIIiI11I1i1 ] , oO [ IIIi1i1Ii1 ] ] )
  if 11 - 11: OoOoOO00 * OOooOOo % o0oOOo0O0Ooo / I1ii11iIi11i . o0oOOo0O0Ooo
 return ( O00o0OoO )
 if 23 - 23: iIii1I11I1II1 + OOooOOo
 if 74 - 74: oO0o - I11i . i11iIiiIii / iIii1I11I1II1 . I11i
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
def lisp_get_host_route_next_hop ( rloc ) :
 ooo0o0 = "ip route | egrep '{} via'" . format ( rloc )
 O00Oo000 = commands . getoutput ( ooo0o0 ) . split ( " " )
 if 49 - 49: II111iiii
 try : ii = O00Oo000 . index ( "via" ) + 1
 except : return ( None )
 if 99 - 99: Oo0Ooo . OOooOOo
 if ( ii >= len ( O00Oo000 ) ) : return ( None )
 return ( O00Oo000 [ ii ] )
 if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
 if 70 - 70: O0 % I1Ii111
 if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
 if 82 - 82: ooOoO0o % Oo0Ooo
 if 26 - 26: OoO0O00 + i11iIiiIii % I11i . I1ii11iIi11i
 if 76 - 76: i1IIi + ooOoO0o - Oo0Ooo + OoOoOO00 / I1ii11iIi11i . OOooOOo
 if 50 - 50: IiII - Ii1I % iIii1I11I1II1
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 Ooo0OO0 = "none" if nh == None else nh
 if 60 - 60: o0oOOo0O0Ooo - Oo0Ooo
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , Ooo0OO0 ) )
 if 92 - 92: OoOoOO00 + IiII . OoO0O00 % iII111i / II111iiii / I11i
 if ( nh == None ) :
  iiIII1II1ii1 = "ip route {} {}/32" . format ( install , dest )
 else :
  iiIII1II1ii1 = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 62 - 62: I1ii11iIi11i
 os . system ( iiIII1II1ii1 )
 return
 if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
 if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 if 71 - 71: i1IIi
 if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 o000 = open ( lisp_checkpoint_filename , "w" )
 for i1II1IiiIi in checkpoint_list :
  o000 . write ( i1II1IiiIi + "\n" )
  if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
 o000 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
 if 79 - 79: iII111i
 if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
 if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
 if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
 if 47 - 47: oO0o - OoooooooOO + iII111i
 if 69 - 69: I1ii11iIi11i - I1IiiI % oO0o + OOooOOo - I1Ii111
 if 5 - 5: ooOoO0o . OoO0O00
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 40 - 40: iII111i
 o000 = open ( lisp_checkpoint_filename , "r" )
 if 87 - 87: IiII / II111iiii
 I1Ii1i11I1I = 0
 for i1II1IiiIi in o000 :
  I1Ii1i11I1I += 1
  IIIII1iii11 = i1II1IiiIi . split ( " rloc " )
  O00OO = [ ] if ( IIIII1iii11 [ 1 ] in [ "native-forward\n" , "\n" ] ) else IIIII1iii11 [ 1 ] . split ( ", " )
  if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
  if 84 - 84: OOooOOo . OOooOOo . oO0o % iII111i * Oo0Ooo - iIii1I11I1II1
  oo000OO = [ ]
  for IiiI11iiI1i1 in O00OO :
   oo0oo00000 = lisp_rloc ( False )
   oO = IiiI11iiI1i1 . split ( " " )
   oo0oo00000 . rloc . store_address ( oO [ 0 ] )
   oo0oo00000 . priority = int ( oO [ 1 ] )
   oo0oo00000 . weight = int ( oO [ 2 ] )
   oo000OO . append ( oo0oo00000 )
   if 4 - 4: iII111i
   if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
  IIo0OooOO = lisp_mapping ( "" , "" , oo000OO )
  if ( IIo0OooOO != None ) :
   IIo0OooOO . eid . store_prefix ( IIIII1iii11 [ 0 ] )
   IIo0OooOO . checkpoint_entry = True
   IIo0OooOO . map_cache_ttl = LISP_NMR_TTL * 60
   if ( oo000OO == [ ] ) : IIo0OooOO . action = LISP_NATIVE_FORWARD_ACTION
   IIo0OooOO . add_cache ( )
   continue
   if 65 - 65: Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
   if 17 - 17: I1ii11iIi11i * OOooOOo % II111iiii
  I1Ii1i11I1I -= 1
  if 30 - 30: I1Ii111 . Ii1I . Oo0Ooo / OOooOOo * OoooooooOO / I1ii11iIi11i
  if 41 - 41: i1IIi
 o000 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , I1Ii1i11I1I , lisp_checkpoint_filename ) )
 return
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
 if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
 if 100 - 100: OoO0O00 . Oo0Ooo
 if 29 - 29: OoO0O00
 if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
 if 47 - 47: II111iiii * I1ii11iIi11i
 if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
 if 71 - 71: I1ii11iIi11i * i1IIi
 if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
 if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
 if 57 - 57: OOooOOo . I11i % OoOoOO00
 if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 78 - 78: iII111i - OOooOOo / I1Ii111
 i1II1IiiIi = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
 for oo0oo00000 in mc . rloc_set :
  if ( oo0oo00000 . rloc . is_null ( ) ) : continue
  i1II1IiiIi += "{} {} {}, " . format ( oo0oo00000 . rloc . print_address_no_iid ( ) ,
 oo0oo00000 . priority , oo0oo00000 . weight )
  if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
  if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 if ( mc . rloc_set != [ ] ) :
  i1II1IiiIi = i1II1IiiIi [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  i1II1IiiIi += "native-forward"
  if 56 - 56: I11i % OoOoOO00 - OoO0O00
  if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
 checkpoint_list . append ( i1II1IiiIi )
 return
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
 if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
 if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
 if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
 if 66 - 66: OoO0O00 * Ii1I . OoO0O00
 if 90 - 90: II111iiii % Ii1I
def lisp_check_dp_socket ( ) :
 ooO0oOOO0 = lisp_ipc_dp_socket_name
 if ( os . path . exists ( ooO0oOOO0 ) == False ) :
  II1I = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( ooO0oOOO0 , II1I ) )
  return ( False )
  if 87 - 87: ooOoO0o
 return ( True )
 if 47 - 47: i11iIiiIii
 if 84 - 84: Ii1I + ooOoO0o
 if 81 - 81: I1ii11iIi11i - iIii1I11I1II1
 if 31 - 31: I11i * oO0o % I1ii11iIi11i * I1Ii111 % OoOoOO00 + oO0o
 if 33 - 33: I1Ii111
 if 96 - 96: i1IIi
 if 52 - 52: OoO0O00 * Ii1I + OOooOOo + ooOoO0o * OoooooooOO
def lisp_write_to_dp_socket ( entry ) :
 try :
  I1O0O0oO00o0 = json . dumps ( entry )
  IIiI111i = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( IIiI111i , I1O0O0oO00o0 ) )
  lisp_ipc_dp_socket . sendto ( I1O0O0oO00o0 , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( I1O0O0oO00o0 ) )
  if 36 - 36: o0oOOo0O0Ooo % I11i % iII111i % O0
 return
 if 3 - 3: I1ii11iIi11i / O0 * II111iiii . O0
 if 86 - 86: iIii1I11I1II1
 if 39 - 39: I11i
 if 77 - 77: OoO0O00 / OoO0O00 . ooOoO0o . Oo0Ooo * OoooooooOO * I11i
 if 63 - 63: iIii1I11I1II1 + ooOoO0o + o0oOOo0O0Ooo . ooOoO0o / o0oOOo0O0Ooo - IiII
 if 7 - 7: I1ii11iIi11i . iII111i . OOooOOo
 if 81 - 81: o0oOOo0O0Ooo . Oo0Ooo * OoO0O00 - OoOoOO00 + OoO0O00
 if 67 - 67: I1Ii111
 if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
def lisp_write_ipc_keys ( rloc ) :
 O0o = rloc . rloc . print_address_no_iid ( )
 IIIIiI1ii1 = rloc . translated_port
 if ( IIIIiI1ii1 != 0 ) : O0o += ":" + str ( IIIIiI1ii1 )
 if ( lisp_rloc_probe_list . has_key ( O0o ) == False ) : return
 if 77 - 77: ooOoO0o
 for oO , IIIII1iii11 , I1I1i1 in lisp_rloc_probe_list [ O0o ] :
  IIo0OooOO = lisp_map_cache . lookup_cache ( IIIII1iii11 , True )
  if ( IIo0OooOO == None ) : continue
  lisp_write_ipc_map_cache ( True , IIo0OooOO )
  if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
 return
 if 6 - 6: iII111i / iII111i . i11iIiiIii
 if 12 - 12: I11i - OoO0O00
 if 68 - 68: IiII - OoOoOO00
 if 22 - 22: i1IIi . IiII
 if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
 if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
 if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
 if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
 if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
 if 42 - 42: i1IIi . OoO0O00 % iII111i
 iIIi11i1i1i1I = "add" if add_or_delete else "delete"
 i1II1IiiIi = { "type" : "map-cache" , "opcode" : iIIi11i1i1i1I }
 if 57 - 57: I1ii11iIi11i / I1IiiI
 IiI = ( mc . group . is_null ( ) == False )
 if ( IiI ) :
  i1II1IiiIi [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  i1II1IiiIi [ "rles" ] = [ ]
 else :
  i1II1IiiIi [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  i1II1IiiIi [ "rlocs" ] = [ ]
  if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
 i1II1IiiIi [ "instance-id" ] = str ( mc . eid . instance_id )
 if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 if ( IiI ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for iiiI1Ii in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    O0o0O0OO0o = iiiI1Ii . address . print_address_no_iid ( )
    IIIIiI1ii1 = str ( 4341 ) if iiiI1Ii . translated_port == 0 else str ( iiiI1Ii . translated_port )
    if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
    oO = { "rle" : O0o0O0OO0o , "port" : IIIIiI1ii1 }
    oOOOOoo0OoOOO , ooO0o = iiiI1Ii . get_encap_keys ( )
    oO = lisp_build_json_keys ( oO , oOOOOoo0OoOOO , ooO0o , "encrypt-key" )
    i1II1IiiIi [ "rles" ] . append ( oO )
    if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
    if 39 - 39: OoooooooOO
 else :
  for IiiI11iiI1i1 in mc . rloc_set :
   if ( IiiI11iiI1i1 . rloc . is_ipv4 ( ) == False and IiiI11iiI1i1 . rloc . is_ipv6 ( ) == False ) :
    continue
    if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
   if ( IiiI11iiI1i1 . up_state ( ) == False ) : continue
   if 41 - 41: II111iiii . o0oOOo0O0Ooo
   IIIIiI1ii1 = str ( 4341 ) if IiiI11iiI1i1 . translated_port == 0 else str ( IiiI11iiI1i1 . translated_port )
   if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
   oO = { "rloc" : IiiI11iiI1i1 . rloc . print_address_no_iid ( ) , "priority" :
 str ( IiiI11iiI1i1 . priority ) , "weight" : str ( IiiI11iiI1i1 . weight ) , "port" :
 IIIIiI1ii1 }
   oOOOOoo0OoOOO , ooO0o = IiiI11iiI1i1 . get_encap_keys ( )
   oO = lisp_build_json_keys ( oO , oOOOOoo0OoOOO , ooO0o , "encrypt-key" )
   i1II1IiiIi [ "rlocs" ] . append ( oO )
   if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
   if 15 - 15: OoO0O00
   if 37 - 37: OoO0O00 . OoooooooOO - OOooOOo
 if ( dont_send == False ) : lisp_write_to_dp_socket ( i1II1IiiIi )
 return ( i1II1IiiIi )
 if 34 - 34: o0oOOo0O0Ooo + iIii1I11I1II1 / o0oOOo0O0Ooo / ooOoO0o
 if 53 - 53: II111iiii / iIii1I11I1II1
 if 25 - 25: I1Ii111
 if 58 - 58: OoOoOO00 * i1IIi
 if 20 - 20: IiII
 if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 if 30 - 30: i11iIiiIii . I1IiiI
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 oOOOOoo0OoOOO = keys [ 1 ] . encrypt_key
 ooO0o = keys [ 1 ] . icv_key
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 III111 = rloc_addr . split ( ":" )
 if ( len ( III111 ) == 1 ) :
  i1II1IiiIi = { "type" : "decap-keys" , "rloc" : III111 [ 0 ] }
 else :
  i1II1IiiIi = { "type" : "decap-keys" , "rloc" : III111 [ 0 ] , "port" : III111 [ 1 ] }
  if 2 - 2: I1Ii111 - O0 % OoooooooOO + I1Ii111
 i1II1IiiIi = lisp_build_json_keys ( i1II1IiiIi , oOOOOoo0OoOOO , ooO0o , "decrypt-key" )
 if 1 - 1: I1Ii111 % OoooooooOO + OoooooooOO - I1IiiI % I1IiiI
 lisp_write_to_dp_socket ( i1II1IiiIi )
 return
 if 51 - 51: iIii1I11I1II1 / I1IiiI
 if 27 - 27: O0 . o0oOOo0O0Ooo / ooOoO0o / OoooooooOO % Ii1I
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
 if 24 - 24: i11iIiiIii + ooOoO0o
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 80 - 80: IiII % I11i % oO0o
 entry [ "keys" ] = [ ]
 OOo0O = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( OOo0O )
 return ( entry )
 if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 if 70 - 70: iIii1I11I1II1
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 if 64 - 64: iII111i - Oo0Ooo
 if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
 if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
 if 50 - 50: I1IiiI % o0oOOo0O0Ooo
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 1 - 1: II111iiii
 if 22 - 22: I1Ii111 + iII111i
 if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
 i1II1IiiIi = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 for IIi1 in lisp_db_list :
  if ( IIi1 . eid . is_ipv4 ( ) == False and IIi1 . eid . is_ipv6 ( ) == False ) : continue
  i11i1Iii11II = { "instance-id" : str ( IIi1 . eid . instance_id ) ,
 "eid-prefix" : IIi1 . eid . print_prefix_no_iid ( ) }
  i1II1IiiIi [ "database-mappings" ] . append ( i11i1Iii11II )
  if 34 - 34: OOooOOo . oO0o + I11i / I1Ii111 . I11i
 lisp_write_to_dp_socket ( i1II1IiiIi )
 if 59 - 59: Ii1I
 if 47 - 47: iII111i % iII111i
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 if 74 - 74: I11i % OOooOOo
 i1II1IiiIi = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( i1II1IiiIi )
 return
 if 57 - 57: O0 + I1IiiI + i11iIiiIii
 if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
 if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
 if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
 if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
 if 21 - 21: O0
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 14 - 14: IiII / I1ii11iIi11i + Ii1I
 if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
 if 38 - 38: I1IiiI * Ii1I + Oo0Ooo - OoooooooOO
 if 63 - 63: I1ii11iIi11i
 i1II1IiiIi = { "type" : "interfaces" , "interfaces" : [ ] }
 if 99 - 99: I1Ii111 % oO0o - II111iiii . ooOoO0o
 for oooOoO in lisp_myinterfaces . values ( ) :
  if ( oooOoO . instance_id == None ) : continue
  i11i1Iii11II = { "interface" : oooOoO . device ,
 "instance-id" : str ( oooOoO . instance_id ) }
  i1II1IiiIi [ "interfaces" ] . append ( i11i1Iii11II )
  if 26 - 26: I1ii11iIi11i * iII111i . OoooooooOO - Oo0Ooo - IiII
  if 6 - 6: OOooOOo - I1IiiI . IiII
 lisp_write_to_dp_socket ( i1II1IiiIi )
 return
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
def lisp_parse_auth_key ( value ) :
 IIiii1IiiIiii = value . split ( "[" )
 II11oOO0O0oOOOoO0 = { }
 if ( len ( IIiii1IiiIiii ) == 1 ) :
  II11oOO0O0oOOOoO0 [ 0 ] = value
  return ( II11oOO0O0oOOOoO0 )
  if 94 - 94: Ii1I + o0oOOo0O0Ooo / II111iiii
  if 18 - 18: I1IiiI
 for iI1Iii111iI in IIiii1IiiIiii :
  if ( iI1Iii111iI == "" ) : continue
  ii = iI1Iii111iI . find ( "]" )
  IiIiIi1I1 = iI1Iii111iI [ 0 : ii ]
  try : IiIiIi1I1 = int ( IiIiIi1I1 )
  except : return
  if 27 - 27: ooOoO0o
  II11oOO0O0oOOOoO0 [ IiIiIi1I1 ] = iI1Iii111iI [ ii + 1 : : ]
  if 20 - 20: OoooooooOO * OOooOOo
 return ( II11oOO0O0oOOOoO0 )
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
 if 93 - 93: OoooooooOO / I1Ii111
 if 91 - 91: I1Ii111
 if 18 - 18: ooOoO0o * I11i
 if 53 - 53: I11i . i11iIiiIii - iIii1I11I1II1 / I1Ii111
 if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
 if 63 - 63: o0oOOo0O0Ooo . iIii1I11I1II1 % IiII * i11iIiiIii
 if 70 - 70: iIii1I11I1II1
 if 12 - 12: OoOoOO00 / o0oOOo0O0Ooo - I1ii11iIi11i + oO0o + O0
 if 9 - 9: I1ii11iIi11i * OoooooooOO . O0 . ooOoO0o * i11iIiiIii / i1IIi
 if 38 - 38: OoOoOO00 . OoooooooOO % I1ii11iIi11i . oO0o % oO0o
 if 80 - 80: i11iIiiIii / OoOoOO00 . OOooOOo . iIii1I11I1II1
 if 81 - 81: I1ii11iIi11i * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO
 if 64 - 64: Oo0Ooo . I1ii11iIi11i / ooOoO0o % oO0o . iIii1I11I1II1
 if 84 - 84: II111iiii . oO0o * O0 / iII111i + OoooooooOO
 if 99 - 99: I1ii11iIi11i . oO0o + Oo0Ooo + I1ii11iIi11i / I1Ii111 . I1ii11iIi11i
def lisp_reassemble ( packet ) :
 iiI1I = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 95 - 95: OoOoOO00 * iIii1I11I1II1 / OoooooooOO % i1IIi
 if 91 - 91: OOooOOo - OoOoOO00
 if 58 - 58: II111iiii . OOooOOo % II111iiii * oO0o % OoO0O00 % I11i
 if 71 - 71: Ii1I * II111iiii * I1IiiI
 if ( iiI1I == 0 or iiI1I == 0x4000 ) : return ( packet )
 if 22 - 22: oO0o
 if 96 - 96: ooOoO0o * iII111i . IiII
 if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
 if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
 o0O0O0O00o = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 iIIiiiiii = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 34 - 34: I1Ii111 . IiII % iII111i
 oOoo0O0oO0 = ( iiI1I & 0x2000 == 0 and ( iiI1I & 0x1fff ) != 0 )
 i1II1IiiIi = [ ( iiI1I & 0x1fff ) * 8 , iIIiiiiii - 20 , packet , oOoo0O0oO0 ]
 if 49 - 49: o0oOOo0O0Ooo
 if 11 - 11: I1ii11iIi11i - i11iIiiIii - I1ii11iIi11i - I1Ii111 . i1IIi
 if 55 - 55: I11i . IiII / i11iIiiIii / Oo0Ooo
 if 20 - 20: OoO0O00 - OoooooooOO . I1ii11iIi11i
 if 1 - 1: I11i
 if 7 - 7: II111iiii / iII111i / oO0o
 if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
 if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
 if ( iiI1I == 0x2000 ) :
  O0oo0oOo , i111iI1i1iI = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  O0oo0oOo = socket . ntohs ( O0oo0oOo )
  i111iI1i1iI = socket . ntohs ( i111iI1i1iI )
  if ( i111iI1i1iI not in [ 4341 , 8472 , 4789 ] and O0oo0oOo != 4341 ) :
   lisp_reassembly_queue [ o0O0O0O00o ] = [ ]
   i1II1IiiIi [ 2 ] = None
   if 61 - 61: I1IiiI / OOooOOo
   if 67 - 67: OoOoOO00
   if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
   if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
   if 95 - 95: ooOoO0o % OOooOOo
   if 17 - 17: i1IIi + Ii1I
 if ( lisp_reassembly_queue . has_key ( o0O0O0O00o ) == False ) :
  lisp_reassembly_queue [ o0O0O0O00o ] = [ ]
  if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
  if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
  if 26 - 26: oO0o / I1ii11iIi11i - oO0o
  if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
  if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 o0oo00oo00o = lisp_reassembly_queue [ o0O0O0O00o ]
 if 36 - 36: II111iiii * IiII % OoO0O00 . OoOoOO00 % oO0o
 if 93 - 93: o0oOOo0O0Ooo
 if 28 - 28: ooOoO0o . o0oOOo0O0Ooo . OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o
 if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
 if ( len ( o0oo00oo00o ) == 1 and o0oo00oo00o [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( o0O0O0O00o ) . zfill ( 4 ) ) )
  if 9 - 9: O0 + IiII
  return ( None )
  if 69 - 69: I1IiiI
  if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
  if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
  if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
  if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
 o0oo00oo00o . append ( i1II1IiiIi )
 o0oo00oo00o = sorted ( o0oo00oo00o )
 if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
 if 19 - 19: I1ii11iIi11i
 if 42 - 42: OoOoOO00 / IiII
 if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
 O0o0O0OO0o = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O0o0O0OO0o . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 o0o00o0O0O = O0o0O0OO0o . print_address_no_iid ( )
 O0o0O0OO0o . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 oo0oo = O0o0O0OO0o . print_address_no_iid ( )
 O0o0O0OO0o = red ( "{} -> {}" . format ( o0o00o0O0O , oo0oo ) , False )
 if 55 - 55: OoO0O00
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if i1II1IiiIi [ 2 ] == None else "" , O0o0O0OO0o , lisp_hex_string ( o0O0O0O00o ) . zfill ( 4 ) ,
 # ooOoO0o * I1IiiI / II111iiii / OoooooooOO
 # I1Ii111
 lisp_hex_string ( iiI1I ) . zfill ( 4 ) ) )
 if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
 if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
 if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
 if 11 - 11: Ii1I
 if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
 if ( o0oo00oo00o [ 0 ] [ 0 ] != 0 or o0oo00oo00o [ - 1 ] [ 3 ] == False ) : return ( None )
 iI1ii1I11Ii = o0oo00oo00o [ 0 ]
 for iI1IIIi11 in o0oo00oo00o [ 1 : : ] :
  iiI1I = iI1IIIi11 [ 0 ]
  iiIiIi1iiiII1 , O000 = iI1ii1I11Ii [ 0 ] , iI1ii1I11Ii [ 1 ]
  if ( iiIiIi1iiiII1 + O000 != iiI1I ) : return ( None )
  iI1ii1I11Ii = iI1IIIi11
  if 29 - 29: IiII . iII111i * Oo0Ooo
 lisp_reassembly_queue . pop ( o0O0O0O00o )
 if 17 - 17: iIii1I11I1II1 + iIii1I11I1II1 * iIii1I11I1II1 / i11iIiiIii * OoooooooOO
 if 40 - 40: ooOoO0o * oO0o * Ii1I . ooOoO0o + i11iIiiIii
 if 44 - 44: o0oOOo0O0Ooo / iIii1I11I1II1
 if 66 - 66: O0 % I11i . O0 * o0oOOo0O0Ooo / I1Ii111 + o0oOOo0O0Ooo
 if 24 - 24: i11iIiiIii * oO0o * I1IiiI - i1IIi * OoOoOO00
 packet = o0oo00oo00o [ 0 ] [ 2 ]
 for iI1IIIi11 in o0oo00oo00o [ 1 : : ] : packet += iI1IIIi11 [ 2 ] [ 20 : : ]
 if 5 - 5: I1ii11iIi11i % o0oOOo0O0Ooo . iII111i
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( o0O0O0O00o ) . zfill ( 4 ) , len ( packet ) ) )
 if 73 - 73: OoOoOO00 . o0oOOo0O0Ooo * OoOoOO00
 if 94 - 94: OoO0O00 / I1ii11iIi11i
 if 50 - 50: OoOoOO00 % I1IiiI + I1Ii111 . iII111i . iII111i
 if 89 - 89: oO0o / I1ii11iIi11i % I1Ii111
 if 86 - 86: Ii1I * II111iiii % ooOoO0o
 O0oOOOO00oOOo = socket . htons ( len ( packet ) )
 Ii1i111iI = packet [ 0 : 2 ] + struct . pack ( "H" , O0oOOOO00oOOo ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 82 - 82: OOooOOo . Oo0Ooo * ooOoO0o % II111iiii % II111iiii - oO0o
 if 71 - 71: iIii1I11I1II1 % i11iIiiIii . o0oOOo0O0Ooo - oO0o + Oo0Ooo
 Ii1i111iI = lisp_ip_checksum ( Ii1i111iI )
 return ( Ii1i111iI + packet [ 20 : : ] )
 if 69 - 69: I1IiiI - OoOoOO00 . I1ii11iIi11i
 if 88 - 88: ooOoO0o + ooOoO0o + oO0o * o0oOOo0O0Ooo . Ii1I
 if 72 - 72: I11i / I11i
 if 78 - 78: I1IiiI % II111iiii
 if 99 - 99: Oo0Ooo
 if 30 - 30: OoOoOO00 + I1Ii111 . OoOoOO00 - I11i
 if 42 - 42: OoOoOO00
 if 77 - 77: Oo0Ooo * IiII * I1ii11iIi11i + IiII
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 O0o = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( O0o ) ) : return ( O0o )
 if 37 - 37: IiII . OoooooooOO - i11iIiiIii * I1ii11iIi11i - OOooOOo
 O0o = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( O0o ) ) : return ( O0o )
 if 74 - 74: Ii1I + i11iIiiIii * iII111i / o0oOOo0O0Ooo . i11iIiiIii
 if 99 - 99: OOooOOo - OoooooooOO + OoooooooOO . OOooOOo
 if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
 if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
 if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
 for oO0o00o0O in lisp_crypto_keys_by_rloc_decap :
  i11ii = oO0o00o0O . split ( ":" )
  if ( len ( i11ii ) == 1 ) : continue
  i11ii = i11ii [ 0 ] if len ( i11ii ) == 2 else ":" . join ( i11ii [ 0 : - 1 ] )
  if ( i11ii == O0o ) :
   iIIi111IiII1i = lisp_crypto_keys_by_rloc_decap [ oO0o00o0O ]
   lisp_crypto_keys_by_rloc_decap [ O0o ] = iIIi111IiII1i
   return ( O0o )
   if 87 - 87: iII111i
   if 63 - 63: iII111i - I11i - iIii1I11I1II1 - Ii1I / iII111i % I1Ii111
 return ( None )
 if 59 - 59: OoooooooOO
 if 89 - 89: i1IIi / OoooooooOO . I1IiiI
 if 70 - 70: OOooOOo . I1Ii111
 if 20 - 20: i1IIi * IiII % II111iiii + IiII
 if 4 - 4: Ii1I + I1ii11iIi11i
 if 40 - 40: OOooOOo % iII111i
 if 5 - 5: O0 + i11iIiiIii . IiII - OOooOOo
 if 51 - 51: OOooOOo . I1IiiI % OoO0O00 . I1IiiI
 if 88 - 88: O0 . iIii1I11I1II1 . iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1 . Oo0Ooo
 if 8 - 8: iII111i
 if 78 - 78: i11iIiiIii % oO0o % ooOoO0o - I1Ii111
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 OOooOoO = addr + ":" + str ( port )
 if 45 - 45: ooOoO0o / OoooooooOO . Oo0Ooo
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
  if 53 - 53: i1IIi
  if 51 - 51: OoOoOO00 / iIii1I11I1II1 . oO0o - I1ii11iIi11i - OOooOOo
  if 90 - 90: i1IIi / oO0o * I1Ii111 + II111iiii % I11i
  if 41 - 41: o0oOOo0O0Ooo - II111iiii . ooOoO0o . iII111i - ooOoO0o / iII111i
  if 59 - 59: O0 / II111iiii * II111iiii - ooOoO0o
  for OOOOoooO0 in lisp_nat_state_info . values ( ) :
   for i111i1iIi1i in OOOOoooO0 :
    if ( addr == i111i1iIi1i . address ) : return ( OOooOoO )
    if 63 - 63: I1ii11iIi11i * IiII % OoO0O00 . OoOoOO00 - II111iiii % IiII
    if 8 - 8: iIii1I11I1II1
  return ( addr )
  if 71 - 71: oO0o / o0oOOo0O0Ooo % iIii1I11I1II1 * iIii1I11I1II1
 return ( OOooOoO )
 if 29 - 29: ooOoO0o - OoOoOO00 - o0oOOo0O0Ooo
 if 54 - 54: Ii1I + i11iIiiIii + i1IIi - OoooooooOO
 if 100 - 100: oO0o . ooOoO0o
 if 14 - 14: OoooooooOO + iII111i / iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1 - IiII
 if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
 if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
 if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 79 - 79: I1ii11iIi11i % I11i
 return
 if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
 if 66 - 66: I1IiiI - o0oOOo0O0Ooo
 if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
 if 98 - 98: OoOoOO00 * OoO0O00 . Oo0Ooo
 if 6 - 6: I11i % iIii1I11I1II1 + I1Ii111
 if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
 if 90 - 90: OOooOOo
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 43 - 43: IiII + ooOoO0o
 if 4 - 4: i1IIi
 if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
 if 6 - 6: Ii1I / iII111i
 if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
 if 70 - 70: oO0o - I1IiiI + Ii1I
 if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 37 - 37: o0oOOo0O0Ooo
 if 57 - 57: iII111i / i1IIi / i1IIi + IiII
 if 75 - 75: IiII / O0
 if 72 - 72: I11i
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 if 23 - 23: OoOoOO00 . oO0o - iII111i
 if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
 if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
 if 88 - 88: I1Ii111
 if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
 if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
 if 83 - 83: oO0o
 if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
 if 71 - 71: II111iiii + iII111i + O0 % Oo0Ooo / I1IiiI
 if 52 - 52: Oo0Ooo . I1Ii111 * i1IIi / Oo0Ooo / OoO0O00
 if 29 - 29: iII111i
def lisp_is_rloc_probe ( packet , rr ) :
 OoOo = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( OoOo == False ) : return ( [ packet , None , None , None ] )
 if 91 - 91: Oo0Ooo - IiII
 O0oo0oOo = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 i111iI1i1iI = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 i1I1OoOOo = ( socket . htons ( LISP_CTRL_PORT ) in [ O0oo0oOo , i111iI1i1iI ] )
 if ( i1I1OoOOo == False ) : return ( [ packet , None , None , None ] )
 if 21 - 21: I1IiiI % Ii1I + i1IIi . I1Ii111 - ooOoO0o + i1IIi
 if ( rr == 0 ) :
  ii1I = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( ii1I == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  ii1I = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( ii1I == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  ii1I = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( ii1I == False ) :
   ii1I = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( ii1I == False ) : return ( [ packet , None , None , None ] )
   if 72 - 72: I1Ii111 - i1IIi + OoooooooOO % I1IiiI
   if 4 - 4: OoOoOO00 * I1IiiI + Ii1I * Ii1I % I11i
   if 19 - 19: I1Ii111 * OoOoOO00 . O0 % oO0o % O0 * iIii1I11I1II1
   if 12 - 12: ooOoO0o % oO0o % O0 % oO0o
   if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
   if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
 i1Ii1I = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1Ii1I . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 53 - 53: I1IiiI % I1IiiI
 if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
 if 85 - 85: IiII
 if 72 - 72: iII111i * OoOoOO00
 if ( i1Ii1I . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
 if 65 - 65: I11i
 if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
 if 78 - 78: ooOoO0o - II111iiii - i1IIi
 i1Ii1I = i1Ii1I . print_address_no_iid ( )
 IIIIiI1ii1 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 OoI1iI = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 18 - 18: OoooooooOO % OoOoOO00 - IiII / oO0o . OOooOOo . I1IiiI
 oO = bold ( "Receive(pcap)" , False )
 o000 = bold ( "from " + i1Ii1I , False )
 Ii1Ii = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( oO , len ( packet ) , o000 , IIIIiI1ii1 , Ii1Ii ) )
 if 77 - 77: I1ii11iIi11i . OoO0O00 / OoOoOO00 / O0
 return ( [ packet , i1Ii1I , IIIIiI1ii1 , OoI1iI ] )
 if 67 - 67: ooOoO0o % I11i % oO0o
 if 74 - 74: II111iiii
 if 44 - 44: Oo0Ooo + OoO0O00 + OoOoOO00 - I1IiiI
 if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
 if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
 if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
 if 20 - 20: I1IiiI + iII111i + O0 * O0
 if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
 if 31 - 31: ooOoO0o
 if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
 if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
 O0oO00o0o0oo0 = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 lisp_write_to_dp_socket ( O0oO00o0o0oo0 )
 return
 if 97 - 97: O0
 if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
 if 31 - 31: iIii1I11I1II1
 if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
 if 20 - 20: iIii1I11I1II1 % OOooOOo
 if 91 - 91: ooOoO0o
 if 96 - 96: I1IiiI . OOooOOo
 if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
def lisp_external_data_plane ( ) :
 ooo0o0 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( ooo0o0 ) != "" ) : return ( True )
 if 34 - 34: IiII % oO0o
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 54 - 54: I1IiiI
 if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
 if 31 - 31: I11i * o0oOOo0O0Ooo
 if 17 - 17: Ii1I * iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo - IiII
 if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
 if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
 if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
 if 23 - 23: Ii1I % i1IIi - I1Ii111
 if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
 if 11 - 11: IiII / I1IiiI . I1IiiI
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
 O0000o000o = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 21 - 21: o0oOOo0O0Ooo * o0oOOo0O0Ooo - OoOoOO00 % OoOoOO00
 if ( do_clear == False ) :
  Oo0oOO0o0Oo = O0000o000o [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , Oo0oOO0o0Oo )
  if 8 - 8: I1ii11iIi11i
  if 5 - 5: OOooOOo * i11iIiiIii % oO0o * ooOoO0o
 lisp_write_to_dp_socket ( O0000o000o )
 return
 if 37 - 37: oO0o . IiII + I1ii11iIi11i
 if 57 - 57: ooOoO0o * o0oOOo0O0Ooo . i11iIiiIii . I1Ii111 . i1IIi
 if 95 - 95: I1Ii111 % o0oOOo0O0Ooo . I1Ii111
 if 23 - 23: Ii1I - OOooOOo + oO0o
 if 62 - 62: I1IiiI . oO0o - I1IiiI / o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 53 - 53: i1IIi + OoOoOO00 / i1IIi * o0oOOo0O0Ooo
 if 47 - 47: OoooooooOO * Ii1I % i1IIi . oO0o * iIii1I11I1II1 * I1ii11iIi11i
 if 43 - 43: o0oOOo0O0Ooo * OoooooooOO % IiII . Oo0Ooo / OoO0O00
 if 51 - 51: Oo0Ooo / OoOoOO00 - OoooooooOO
 if 57 - 57: Ii1I
 if 52 - 52: oO0o % I1ii11iIi11i % i11iIiiIii
 if 8 - 8: i1IIi * i11iIiiIii - ooOoO0o / IiII - oO0o
 if 29 - 29: OoooooooOO / iII111i + I1IiiI % I11i - Ii1I
 if 75 - 75: i1IIi
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 80 - 80: O0
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 16 - 16: OOooOOo - iII111i
  if 5 - 5: o0oOOo0O0Ooo % ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
  o0o0O00 = msg [ "eid-prefix" ]
  if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
  o0ooOo00O = int ( msg [ "instance-id" ] )
  if 72 - 72: IiII / II111iiii
  if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
  if 21 - 21: I1ii11iIi11i
  if 60 - 60: i1IIi / OoO0O00 . Ii1I
  O0oOoooooooOo00O = lisp_address ( LISP_AFI_NONE , "" , 0 , o0ooOo00O )
  O0oOoooooooOo00O . store_prefix ( o0o0O00 )
  IIo0OooOO = lisp_map_cache_lookup ( None , O0oOoooooooOo00O )
  if ( IIo0OooOO == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( o0o0O00 ) )
   if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
   continue
   if 26 - 26: iII111i
   if 31 - 31: iII111i
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( o0o0O00 ) )
   if 45 - 45: OoO0O00
   continue
   if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 + I11i - ooOoO0o + I1IiiI * O0
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 47 - 47: ooOoO0o + iIii1I11I1II1 * OOooOOo . I1IiiI . o0oOOo0O0Ooo
  iI = msg [ "rlocs" ]
  if 89 - 89: IiII - iII111i + IiII
  if 39 - 39: oO0o % I11i . oO0o * I11i
  if 36 - 36: i1IIi / I1ii11iIi11i * iIii1I11I1II1
  if 44 - 44: Ii1I / I1Ii111
  for Oo0oooOo000OO in iI :
   if ( Oo0oooOo000OO . has_key ( "rloc" ) == False ) : continue
   if 78 - 78: I1ii11iIi11i / OoooooooOO * ooOoO0o
   iII = Oo0oooOo000OO [ "rloc" ]
   if ( iII == "no-address" ) : continue
   if 45 - 45: OoO0O00 + iIii1I11I1II1 + ooOoO0o - OoO0O00
   IiiI11iiI1i1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   IiiI11iiI1i1 . store_address ( iII )
   if 22 - 22: I1IiiI
   oo0oo00000 = IIo0OooOO . get_rloc ( IiiI11iiI1i1 )
   if ( oo0oo00000 == None ) : continue
   if 28 - 28: OoO0O00 / ooOoO0o % OoOoOO00 - Ii1I * i11iIiiIii + I1ii11iIi11i
   if 90 - 90: ooOoO0o * o0oOOo0O0Ooo + Ii1I / I11i % II111iiii
   if 59 - 59: I11i + iII111i + I11i
   if 84 - 84: I1IiiI * Ii1I . I1IiiI % OOooOOo * Ii1I % OoO0O00
   OOOOOo0 = 0 if Oo0oooOo000OO . has_key ( "packet-count" ) == False else Oo0oooOo000OO [ "packet-count" ]
   if 44 - 44: OoOoOO00 + oO0o / i11iIiiIii
   II1III = 0 if Oo0oooOo000OO . has_key ( "byte-count" ) == False else Oo0oooOo000OO [ "byte-count" ]
   if 23 - 23: i1IIi . i11iIiiIii . Ii1I * I1IiiI * Ii1I . iIii1I11I1II1
   I11i1II = 0 if Oo0oooOo000OO . has_key ( "seconds-last-packet" ) == False else Oo0oooOo000OO [ "seconds-last-packet" ]
   if 92 - 92: ooOoO0o / i11iIiiIii . IiII + OoooooooOO / I1IiiI . O0
   if 41 - 41: OOooOOo * oO0o . iIii1I11I1II1 . i1IIi
   oo0oo00000 . stats . packet_count += OOOOOo0
   oo0oo00000 . stats . byte_count += II1III
   oo0oo00000 . stats . last_increment = lisp_get_timestamp ( ) - I11i1II
   if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( OOOOOo0 , II1III ,
 I11i1II , o0o0O00 , iII ) )
   if 34 - 34: iII111i + i11iIiiIii . IiII
   if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
   if 29 - 29: II111iiii % i11iIiiIii % O0
   if 38 - 38: o0oOOo0O0Ooo * IiII
   if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
  if ( IIo0OooOO . group . is_null ( ) and IIo0OooOO . has_ttl_elapsed ( ) ) :
   o0o0O00 = green ( IIo0OooOO . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( o0o0O00 ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , IIo0OooOO . eid , None )
   if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
   if 19 - 19: OoooooooOO
 return
 if 34 - 34: OoOoOO00 . oO0o
 if 53 - 53: oO0o + OoooooooOO * ooOoO0o
 if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 if 80 - 80: II111iiii . i11iIiiIii
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 52 - 52: iIii1I11I1II1 + O0
 if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
 if 29 - 29: iII111i % I1Ii111
 if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
 if 63 - 63: ooOoO0o
 if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
 if 90 - 90: IiII
 if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
 if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
 if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
 if 98 - 98: OOooOOo
 if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
 if 75 - 75: II111iiii . O0 . I1Ii111 * O0 / OoooooooOO
 if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
 if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
 if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i . Ii1I + I1IiiI % i11iIiiIii - i11iIiiIii
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  O0oO00o0o0oo0 = "stats%{}" . format ( json . dumps ( msg ) )
  O0oO00o0o0oo0 = lisp_command_ipc ( O0oO00o0o0oo0 , "lisp-itr" )
  lisp_ipc ( O0oO00o0o0oo0 , lisp_ipc_socket , "lisp-etr" )
  return
  if 62 - 62: I1Ii111 + I1IiiI
  if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
  if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
  if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
  if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
  if 59 - 59: iII111i
  if 14 - 14: oO0o . IiII + iIii1I11I1II1 - i1IIi
  if 46 - 46: i11iIiiIii * II111iiii / i11iIiiIii % i11iIiiIii * II111iiii + i11iIiiIii
 O0oO00o0o0oo0 = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( O0oO00o0o0oo0 , msg ) )
 if 87 - 87: Oo0Ooo + OoO0O00 / II111iiii * OoooooooOO
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 95 - 95: I1Ii111 * o0oOOo0O0Ooo + OoO0O00 % OoOoOO00 - ooOoO0o / OoOoOO00
 IiiII = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 52 - 52: iIii1I11I1II1 % iII111i . I1IiiI
 for iIIOoo0 in IiiII :
  OOOOOo0 = 0 if msg . has_key ( iIIOoo0 ) == False else msg [ iIIOoo0 ] [ "packet-count" ]
  if 82 - 82: OoO0O00 * OOooOOo * I11i * I1Ii111 % iIii1I11I1II1
  lisp_decap_stats [ iIIOoo0 ] . packet_count += OOOOOo0
  if 50 - 50: Ii1I * Ii1I % I11i / iIii1I11I1II1 / ooOoO0o / iII111i
  II1III = 0 if msg . has_key ( iIIOoo0 ) == False else msg [ iIIOoo0 ] [ "byte-count" ]
  if 91 - 91: Ii1I - O0 . I11i - OoooooooOO * IiII . II111iiii
  lisp_decap_stats [ iIIOoo0 ] . byte_count += II1III
  if 38 - 38: I1IiiI + OoO0O00
  I11i1II = 0 if msg . has_key ( iIIOoo0 ) == False else msg [ iIIOoo0 ] [ "seconds-last-packet" ]
  if 11 - 11: iIii1I11I1II1 + i1IIi * IiII - Oo0Ooo
  lisp_decap_stats [ iIIOoo0 ] . last_increment = lisp_get_timestamp ( ) - I11i1II
  if 66 - 66: I1Ii111 . Ii1I / I1ii11iIi11i / iIii1I11I1II1 + O0 / i1IIi
 return
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
 if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
 if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 if 38 - 38: Ii1I
 if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
 if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
 if 59 - 59: i11iIiiIii / I1IiiI * iII111i
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 iiIi111IiIiI , i1Ii1I = punt_socket . recvfrom ( 4000 )
 if 92 - 92: o0oOOo0O0Ooo * Ii1I % I1IiiI * O0 * Oo0Ooo * IiII
 IIIII1I1iI = json . loads ( iiIi111IiIiI )
 if ( type ( IIIII1I1iI ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( i1Ii1I ) )
  if 95 - 95: II111iiii * iII111i + I1IiiI + Oo0Ooo
  return
  if 45 - 45: I1ii11iIi11i / Ii1I - i11iIiiIii . i1IIi
 oO00o000oo0 = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( oO00o000oo0 , i1Ii1I , IIIII1I1iI ) )
 if 81 - 81: I1Ii111 * i1IIi
 if ( IIIII1I1iI . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 94 - 94: II111iiii
  if 98 - 98: Ii1I * Ii1I / IiII
  if 1 - 1: OOooOOo
  if 47 - 47: i11iIiiIii - I11i
  if 38 - 38: Oo0Ooo % OoooooooOO + iII111i
 if ( IIIII1I1iI [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( IIIII1I1iI , lisp_send_sockets , lisp_ephem_port )
  return
  if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
 if ( IIIII1I1iI [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( IIIII1I1iI , punt_socket )
  return
  if 11 - 11: ooOoO0o - OoOoOO00
  if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
  if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
  if 4 - 4: OoO0O00 - OOooOOo
  if 21 - 21: I1Ii111 * i11iIiiIii
 if ( IIIII1I1iI [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 63 - 63: oO0o + OoOoOO00
  if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
  if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
  if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
  if 20 - 20: Ii1I * iII111i / ooOoO0o
 if ( IIIII1I1iI [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
 if ( IIIII1I1iI . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( i1Ii1I ) )
  if 23 - 23: I1IiiI - I1ii11iIi11i . O0 . OoOoOO00 . OoO0O00
  return
  if 81 - 81: IiII * I11i - iIii1I11I1II1
  if 41 - 41: oO0o * I11i + I1IiiI - OoO0O00
  if 63 - 63: Oo0Ooo * Ii1I - Ii1I
  if 76 - 76: OoO0O00 . IiII % iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1IiiI
  if 57 - 57: IiII - i1IIi * ooOoO0o
 o0OOOOOo0 = IIIII1I1iI [ "interface" ]
 if ( o0OOOOOo0 == "" ) :
  o0ooOo00O = int ( IIIII1I1iI [ "instance-id" ] )
  if ( o0ooOo00O == - 1 ) : return
 else :
  o0ooOo00O = lisp_get_interface_instance_id ( o0OOOOOo0 , None )
  if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
  if 75 - 75: OOooOOo * OoOoOO00
  if 82 - 82: Ii1I
  if 83 - 83: I1IiiI
  if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
 i1iIi11iII = None
 if ( IIIII1I1iI . has_key ( "source-eid" ) ) :
  o0o0oo0oO = IIIII1I1iI [ "source-eid" ]
  i1iIi11iII = lisp_address ( LISP_AFI_NONE , o0o0oo0oO , 0 , o0ooOo00O )
  if ( i1iIi11iII . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( o0o0oo0oO ) )
   return
   if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
   if 45 - 45: I11i - iIii1I11I1II1
 OOi1i111iIIi = None
 if ( IIIII1I1iI . has_key ( "dest-eid" ) ) :
  i1iIIIi = IIIII1I1iI [ "dest-eid" ]
  OOi1i111iIIi = lisp_address ( LISP_AFI_NONE , i1iIIIi , 0 , o0ooOo00O )
  if ( OOi1i111iIIi . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( i1iIIIi ) )
   return
   if 76 - 76: i11iIiiIii * oO0o / I1IiiI
   if 10 - 10: iII111i * iIii1I11I1II1 % OoO0O00 * ooOoO0o
   if 10 - 10: OoOoOO00
   if 97 - 97: OOooOOo
   if 86 - 86: i11iIiiIii
   if 45 - 45: OoooooooOO + II111iiii + iIii1I11I1II1 % O0 % OOooOOo + i1IIi
   if 51 - 51: oO0o / ooOoO0o - OOooOOo + oO0o
   if 28 - 28: OoOoOO00 % I11i + o0oOOo0O0Ooo
 if ( i1iIi11iII ) :
  IIIII1iii11 = green ( i1iIi11iII . print_address ( ) , False )
  IIi1 = lisp_db_for_lookups . lookup_cache ( i1iIi11iII , False )
  if ( IIi1 != None ) :
   if 51 - 51: iIii1I11I1II1 + I1ii11iIi11i % OoooooooOO + Ii1I
   if 20 - 20: O0 * I1ii11iIi11i + OoOoOO00 * OOooOOo . i1IIi . o0oOOo0O0Ooo
   if 26 - 26: OOooOOo - OoOoOO00 + I1ii11iIi11i + OoO0O00 - OoOoOO00 / o0oOOo0O0Ooo
   if 76 - 76: I1ii11iIi11i / oO0o + Ii1I - O0
   if 95 - 95: OoOoOO00
   if ( IIi1 . dynamic_eid_configured ( ) ) :
    oooOoO = lisp_allow_dynamic_eid ( o0OOOOOo0 , i1iIi11iII )
    if ( oooOoO != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( IIi1 , i1iIi11iII , o0OOOOOo0 , oooOoO )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( IIIII1iii11 , o0OOOOOo0 ) )
     if 69 - 69: iII111i / Ii1I
     if 83 - 83: oO0o
     if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
  else :
   lprint ( "Punt from non-EID source {}" . format ( IIIII1iii11 ) )
   if 29 - 29: OoooooooOO
   if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
   if 83 - 83: iIii1I11I1II1
   if 92 - 92: OoO0O00 - iII111i
   if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
   if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
 if ( OOi1i111iIIi ) :
  IIo0OooOO = lisp_map_cache_lookup ( i1iIi11iII , OOi1i111iIIi )
  if ( IIo0OooOO == None or IIo0OooOO . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
   if 70 - 70: I1Ii111 % iIii1I11I1II1
   if 74 - 74: i1IIi % i11iIiiIii + oO0o
   if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
   if 34 - 34: Oo0Ooo . i1IIi
   if ( lisp_rate_limit_map_request ( i1iIi11iII , OOi1i111iIIi ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 i1iIi11iII , OOi1i111iIIi , None )
  else :
   IIIII1iii11 = green ( OOi1i111iIIi . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( IIIII1iii11 ) )
   if 97 - 97: I11i
   if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
 return
 if 20 - 20: oO0o % OoOoOO00
 if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
 if 82 - 82: OOooOOo
 if 27 - 27: I1Ii111 / IiII - i1IIi * Ii1I
 if 90 - 90: ooOoO0o
 if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
 if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 i1II1IiiIi = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( i1II1IiiIi )
 return ( [ True , jdata ] )
 if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
 if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
 if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
 if 55 - 55: Oo0Ooo - OOooOOo - O0
 if 40 - 40: OoOoOO00 - OOooOOo
 if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 if 35 - 35: II111iiii
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 96 - 96: O0
 if 15 - 15: i1IIi . iIii1I11I1II1
 if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
 if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 61 - 61: I1Ii111 + I11i + I1IiiI
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 48 - 48: I11i
 if 67 - 67: o0oOOo0O0Ooo
 if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
 if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
 if 89 - 89: ooOoO0o % i11iIiiIii
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 if 75 - 75: Ii1I
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 o0o0O00 = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( o0o0O00 ) ) :
  db . dynamic_eids [ o0o0O00 ] . last_packet = lisp_get_timestamp ( )
  return
  if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
  if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
  if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
  if 74 - 74: OoOoOO00 + I1ii11iIi11i
  if 82 - 82: II111iiii
 i11IiII = lisp_dynamic_eid ( )
 i11IiII . dynamic_eid . copy_address ( eid )
 i11IiII . interface = routed_interface
 i11IiII . last_packet = lisp_get_timestamp ( )
 i11IiII . get_timeout ( routed_interface )
 db . dynamic_eids [ o0o0O00 ] = i11IiII
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 i1iIIio00 = ""
 if ( input_interface != routed_interface ) :
  i1iIIio00 = ", routed-interface " + routed_interface
  if 98 - 98: iII111i
  if 10 - 10: OoooooooOO - oO0o % I11i / OoOoOO00 % OoOoOO00
 oooo00OoO00oO0Oo = green ( o0o0O00 , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( oooo00OoO00oO0Oo , input_interface , i1iIIio00 , i11IiII . timeout ) )
 if 26 - 26: Oo0Ooo % I1ii11iIi11i - II111iiii / i1IIi + OoooooooOO * O0
 if 62 - 62: IiII . O0
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
 if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
 if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
 O0oO00o0o0oo0 = "learn%{}%{}" . format ( o0o0O00 , routed_interface )
 O0oO00o0o0oo0 = lisp_command_ipc ( O0oO00o0o0oo0 , "lisp-itr" )
 lisp_ipc ( O0oO00o0o0oo0 , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
 if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
 if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
 if 24 - 24: OoOoOO00
 if 87 - 87: I1ii11iIi11i / ooOoO0o * i1IIi
 if 71 - 71: OoOoOO00 - I11i
 if 83 - 83: oO0o + oO0o - Oo0Ooo . Oo0Ooo - iII111i . OOooOOo
 if 56 - 56: OoOoOO00 * IiII + i1IIi
 if 40 - 40: I1ii11iIi11i / O0
 if 87 - 87: ooOoO0o
 if 100 - 100: iII111i + II111iiii * Oo0Ooo * OOooOOo
 if 6 - 6: IiII % OOooOOo
 if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 41 - 41: oO0o
 if 12 - 12: I1IiiI + I1Ii111
 if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 79 - 79: Ii1I + IiII
 IiiIIi111i1 = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
 for OOo0O in lisp_crypto_keys_by_rloc_decap :
  if 98 - 98: I1ii11iIi11i
  if 58 - 58: IiII / i11iIiiIii % I11i
  if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
  if 21 - 21: Ii1I
  if ( OOo0O . find ( addr_str ) == - 1 ) : continue
  if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
  if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
  if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
  if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
  if ( OOo0O == addr_str ) : continue
  if 44 - 44: iIii1I11I1II1 . OOooOOo
  if 57 - 57: II111iiii + I1Ii111
  if 42 - 42: OoOoOO00 % O0
  if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
  i1II1IiiIi = lisp_crypto_keys_by_rloc_decap [ OOo0O ]
  if ( i1II1IiiIi == IiiIIi111i1 ) : continue
  if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
  if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
  if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
  if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
  i1i111Ii1IIi = i1II1IiiIi [ 1 ]
  if ( packet_icv != i1i111Ii1IIi . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( OOo0O , False ) ) )
   continue
   if 62 - 62: I11i * I1ii11iIi11i
   if 12 - 12: ooOoO0o . i11iIiiIii - II111iiii - iII111i % II111iiii - OoO0O00
  lprint ( "Changing decap crypto key to {}" . format ( red ( OOo0O , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = i1II1IiiIi
  if 39 - 39: i1IIi
 return
 if 47 - 47: OoooooooOO - OOooOOo
 if 59 - 59: OoO0O00 * IiII
 if 99 - 99: OOooOOo + oO0o
 if 86 - 86: i1IIi . ooOoO0o % I11i
 if 38 - 38: o0oOOo0O0Ooo + OoooooooOO * O0
 if 75 - 75: iII111i
 if 27 - 27: IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
 if 61 - 61: O0 % iII111i
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 41 - 41: I1Ii111 * OoooooooOO
 if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
 if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
 if 19 - 19: iIii1I11I1II1
 if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
 if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 i11I1II = dns_name . split ( "." )
 i11I1II = "." . join ( i11I1II [ 1 : : ] )
 return ( i11I1II == lisp_decent_dns_suffix )
 if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
 if 57 - 57: i1IIi
 if 41 - 41: I11i / Ii1I
 if 1 - 1: II111iiii / iII111i
 if 83 - 83: OoO0O00 / iII111i
 if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
 if 96 - 96: OoO0O00
def lisp_get_decent_index ( eid ) :
 o0o0O00 = eid . print_prefix ( )
 oOOOoO = hashlib . sha256 ( o0o0O00 ) . hexdigest ( )
 ii = int ( oOOOoO , 16 ) % lisp_decent_modulus
 return ( ii )
 if 12 - 12: I11i - iII111i % IiII
 if 36 - 36: OoOoOO00 . II111iiii / I11i
 if 46 - 46: OoOoOO00
 if 56 - 56: iIii1I11I1II1 - iIii1I11I1II1
 if 46 - 46: o0oOOo0O0Ooo
 if 67 - 67: OOooOOo - i11iIiiIii / oO0o * i11iIiiIii
 if 88 - 88: Ii1I - OoO0O00 * OoooooooOO - I1IiiI * I1ii11iIi11i
def lisp_get_decent_dns_name ( eid ) :
 ii = lisp_get_decent_index ( eid )
 return ( str ( ii ) + "." + lisp_decent_dns_suffix )
 if 52 - 52: oO0o % iII111i - I1IiiI - o0oOOo0O0Ooo
 if 66 - 66: o0oOOo0O0Ooo - Oo0Ooo - OoooooooOO * o0oOOo0O0Ooo + I1Ii111
 if 82 - 82: I11i * i1IIi / Ii1I + O0
 if 85 - 85: O0 + oO0o / I1Ii111
 if 65 - 65: o0oOOo0O0Ooo . Oo0Ooo . i1IIi / IiII . I11i . O0
 if 69 - 69: Oo0Ooo - i11iIiiIii
 if 87 - 87: Oo0Ooo % OOooOOo - Ii1I
 if 34 - 34: iII111i / Ii1I / I1IiiI * i11iIiiIii
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 O0oOoooooooOo00O = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 ii = lisp_get_decent_index ( O0oOoooooooOo00O )
 return ( str ( ii ) + "." + lisp_decent_dns_suffix )
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if 4 - 4: iII111i
 if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
 if 32 - 32: iII111i
 if 59 - 59: OoOoOO00 - I1Ii111
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
 O00O00O000OOO = 28 if packet . inner_version == 4 else 48
 IiiIii1IiI1ii = packet . packet [ O00O00O000OOO : : ]
 oOOOoo = lisp_trace ( )
 if ( oOOOoo . decode ( IiiIii1IiI1ii ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 78 - 78: Oo0Ooo / Ii1I
  if 74 - 74: OOooOOo . II111iiii - i11iIiiIii / OoooooooOO + OoOoOO00 * ooOoO0o
 oOoo0Oo = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 83 - 83: OoO0O00 - Oo0Ooo * I1IiiI % Oo0Ooo % oO0o
 if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
 if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
 if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
 if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
 if 21 - 21: IiII
 if ( oOoo0Oo != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : oOoo0Oo += ":{}" . format ( packet . encap_port )
  if 43 - 43: IiII
  if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
  if 8 - 8: IiII * iIii1I11I1II1
  if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
  if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
 i1II1IiiIi = { }
 i1II1IiiIi [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
 o0oO = packet . outer_source
 if ( o0oO . is_null ( ) ) : o0oO = lisp_myrlocs [ 0 ]
 i1II1IiiIi [ "srloc" ] = o0oO . print_address_no_iid ( )
 if 22 - 22: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
 if 41 - 41: oO0o . II111iiii
 if 47 - 47: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
 if ( i1II1IiiIi [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  i1II1IiiIi [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 100 - 100: Oo0Ooo
  if 13 - 13: I1IiiI + ooOoO0o * II111iiii
 i1II1IiiIi [ "hn" ] = lisp_hostname
 OOo0O = ed + "-ts"
 i1II1IiiIi [ OOo0O ] = lisp_get_timestamp ( )
 if 32 - 32: iIii1I11I1II1 + O0 + i1IIi
 if 28 - 28: IiII + I11i
 if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
 if 56 - 56: Ii1I . OoO0O00
 if 43 - 43: iII111i * iII111i
 if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 if ( oOoo0Oo == "?" and i1II1IiiIi [ "node" ] == "ETR" ) :
  IIi1 = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( IIi1 != None and len ( IIi1 . rloc_set ) >= 1 ) :
   oOoo0Oo = IIi1 . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
   if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
 i1II1IiiIi [ "drloc" ] = oOoo0Oo
 if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
 if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
 if 47 - 47: OOooOOo * oO0o
 if 41 - 41: OoooooooOO * I1IiiI
 if ( oOoo0Oo == "?" and reason != None ) :
  i1II1IiiIi [ "drloc" ] += " ({})" . format ( reason )
  if 3 - 3: IiII
  if 96 - 96: I11i - OOooOOo + I11i
  if 71 - 71: Oo0Ooo
  if 48 - 48: o0oOOo0O0Ooo / II111iiii / OoOoOO00 * o0oOOo0O0Ooo + I1IiiI . OoOoOO00
  if 52 - 52: Ii1I / OoOoOO00 . OOooOOo * IiII . OoooooooOO
 if ( rloc_entry != None ) :
  i1II1IiiIi [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  i1II1IiiIi [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
  if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
  if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
  if 75 - 75: IiII
  if 74 - 74: o0oOOo0O0Ooo - iIii1I11I1II1
  if 92 - 92: i11iIiiIii * iIii1I11I1II1 - I1Ii111 . i1IIi
 i1iIi11iII = packet . inner_source . print_address ( )
 OOi1i111iIIi = packet . inner_dest . print_address ( )
 if ( oOOOoo . packet_json == [ ] ) :
  I1O0O0oO00o0 = { }
  I1O0O0oO00o0 [ "seid" ] = i1iIi11iII
  I1O0O0oO00o0 [ "deid" ] = OOi1i111iIIi
  I1O0O0oO00o0 [ "paths" ] = [ ]
  oOOOoo . packet_json . append ( I1O0O0oO00o0 )
  if 23 - 23: O0 - O0 . I1Ii111 . I1IiiI - I1IiiI * i1IIi
  if 8 - 8: I1IiiI . I1ii11iIi11i + oO0o % oO0o * oO0o
  if 70 - 70: II111iiii + IiII + O0 / Ii1I - i11iIiiIii
  if 72 - 72: II111iiii - II111iiii
  if 44 - 44: o0oOOo0O0Ooo + OoooooooOO
  if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
 for I1O0O0oO00o0 in oOOOoo . packet_json :
  if ( I1O0O0oO00o0 [ "deid" ] != OOi1i111iIIi ) : continue
  I1O0O0oO00o0 [ "paths" ] . append ( i1II1IiiIi )
  break
  if 87 - 87: OOooOOo * OoO0O00
  if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
  if 86 - 86: II111iiii
  if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
  if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
  if 91 - 91: Ii1I
  if 45 - 45: I1ii11iIi11i + Oo0Ooo
  if 72 - 72: I1ii11iIi11i
 ii1IooO = False
 if ( len ( oOOOoo . packet_json ) == 1 and i1II1IiiIi [ "node" ] == "ETR" and
 oOOOoo . myeid ( packet . inner_dest ) ) :
  I1O0O0oO00o0 = { }
  I1O0O0oO00o0 [ "seid" ] = OOi1i111iIIi
  I1O0O0oO00o0 [ "deid" ] = i1iIi11iII
  I1O0O0oO00o0 [ "paths" ] = [ ]
  oOOOoo . packet_json . append ( I1O0O0oO00o0 )
  ii1IooO = True
  if 49 - 49: I1ii11iIi11i
  if 93 - 93: o0oOOo0O0Ooo * I1ii11iIi11i % I1IiiI * ooOoO0o
  if 37 - 37: OoO0O00 * OoooooooOO / oO0o * I11i * I1ii11iIi11i
  if 42 - 42: OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
  if 53 - 53: o0oOOo0O0Ooo
  if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
 oOOOoo . print_trace ( )
 IiiIii1IiI1ii = oOOOoo . encode ( )
 if 31 - 31: OoO0O00 % I1Ii111
 if 62 - 62: oO0o / O0 - I1Ii111 . IiII
 if 81 - 81: i11iIiiIii
 if 57 - 57: O0
 if 85 - 85: i11iIiiIii - i11iIiiIii - OoOoOO00 / II111iiii - II111iiii
 if 4 - 4: I1ii11iIi11i * O0 / OoO0O00 * II111iiii . iIii1I11I1II1 / OOooOOo
 if 97 - 97: i1IIi - OoOoOO00 . OoooooooOO
 if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
 O0OOO0o00o0 = oOOOoo . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( oOoo0Oo == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( O0OOO0o00o0 ) )
  oOOOoo . return_to_sender ( lisp_socket , O0OOO0o00o0 , IiiIii1IiI1ii )
  return ( False )
  if 44 - 44: ooOoO0o + o0oOOo0O0Ooo % OoOoOO00 + I1IiiI
  if 96 - 96: O0 % Ii1I / I1ii11iIi11i + I1ii11iIi11i - OoO0O00 / oO0o
  if 41 - 41: Ii1I
  if 78 - 78: OOooOOo
  if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
  if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
 oO0oo0o00o0O = oOOOoo . packet_length ( )
 if 81 - 81: IiII
 if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
 if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
 if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
 if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
 iii1I1iI11I = packet . packet [ 0 : O00O00O000OOO ]
 Ii1Ii = struct . pack ( "HH" , socket . htons ( oO0oo0o00o0O ) , 0 )
 iii1I1iI11I = iii1I1iI11I [ 0 : O00O00O000OOO - 4 ] + Ii1Ii
 if ( packet . inner_version == 6 and i1II1IiiIi [ "node" ] == "ETR" and
 len ( oOOOoo . packet_json ) == 2 ) :
  OoOo = iii1I1iI11I [ O00O00O000OOO - 8 : : ] + IiiIii1IiI1ii
  OoOo = lisp_udp_checksum ( i1iIi11iII , OOi1i111iIIi , OoOo )
  iii1I1iI11I = iii1I1iI11I [ 0 : O00O00O000OOO - 8 ] + OoOo [ 0 : 8 ]
  if 78 - 78: i11iIiiIii * OoooooooOO - I1Ii111 * IiII
  if 1 - 1: o0oOOo0O0Ooo - IiII % OoOoOO00 + II111iiii
  if 11 - 11: Ii1I * OoooooooOO / II111iiii
  if 1 - 1: OOooOOo * I1ii11iIi11i . I11i . iIii1I11I1II1
  if 50 - 50: OoooooooOO / oO0o + O0
  if 88 - 88: Oo0Ooo / ooOoO0o + II111iiii + OoooooooOO * iIii1I11I1II1
 if ( ii1IooO ) :
  if ( packet . inner_version == 4 ) :
   iii1I1iI11I = iii1I1iI11I [ 0 : 12 ] + iii1I1iI11I [ 16 : 20 ] + iii1I1iI11I [ 12 : 16 ] + iii1I1iI11I [ 22 : 24 ] + iii1I1iI11I [ 20 : 22 ] + iii1I1iI11I [ 24 : : ]
   if 82 - 82: i1IIi - I11i % ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo
  else :
   iii1I1iI11I = iii1I1iI11I [ 0 : 8 ] + iii1I1iI11I [ 24 : 40 ] + iii1I1iI11I [ 8 : 24 ] + iii1I1iI11I [ 42 : 44 ] + iii1I1iI11I [ 40 : 42 ] + iii1I1iI11I [ 44 : : ]
   if 20 - 20: i11iIiiIii - O0 / i11iIiiIii
   if 51 - 51: iII111i . ooOoO0o
  iiiii111 = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = iiiii111
  if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
  if 6 - 6: I11i + II111iiii - I1Ii111
  if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
  if 56 - 56: I11i + I1Ii111
  if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
 O00O00O000OOO = 2 if packet . inner_version == 4 else 4
 IIIII1 = 20 + oO0oo0o00o0O if packet . inner_version == 4 else oO0oo0o00o0O
 Oo0O = struct . pack ( "H" , socket . htons ( IIIII1 ) )
 iii1I1iI11I = iii1I1iI11I [ 0 : O00O00O000OOO ] + Oo0O + iii1I1iI11I [ O00O00O000OOO + 2 : : ]
 if 60 - 60: i1IIi / OoooooooOO . OOooOOo / Oo0Ooo
 if 56 - 56: oO0o
 if 69 - 69: iIii1I11I1II1 / O0 * o0oOOo0O0Ooo
 if 11 - 11: I1Ii111
 if ( packet . inner_version == 4 ) :
  IIiI1 = struct . pack ( "H" , 0 )
  iii1I1iI11I = iii1I1iI11I [ 0 : 10 ] + IIiI1 + iii1I1iI11I [ 12 : : ]
  Oo0O = lisp_ip_checksum ( iii1I1iI11I [ 0 : 20 ] )
  iii1I1iI11I = Oo0O + iii1I1iI11I [ 20 : : ]
  if 32 - 32: I1IiiI - I11i + Ii1I
  if 24 - 24: iII111i
  if 19 - 19: OoOoOO00
  if 74 - 74: i1IIi
  if 55 - 55: OoOoOO00
 packet . packet = iii1I1iI11I + IiiIii1IiI1ii
 return ( True )
 if 11 - 11: OoOoOO00 + II111iiii + o0oOOo0O0Ooo
 if 56 - 56: iII111i - OoOoOO00
 if 69 - 69: oO0o - Ii1I % O0 / OoooooooOO
 if 27 - 27: IiII * i11iIiiIii * iII111i
 if 28 - 28: iIii1I11I1II1
 if 31 - 31: Oo0Ooo . Ii1I - OoO0O00 . I1Ii111
 if 9 - 9: I1Ii111 - OOooOOo
 if 12 - 12: I1Ii111 % OoOoOO00
 if 89 - 89: OoooooooOO * OoO0O00 . ooOoO0o * I1Ii111 + IiII / OOooOOo
 if 63 - 63: OoooooooOO
def lisp_allow_gleaning ( eid , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False )
 if 10 - 10: iII111i % I11i % I1Ii111 . I11i
 for i1II1IiiIi in lisp_glean_mappings :
  if ( i1II1IiiIi . has_key ( "instance-id" ) ) :
   o0ooOo00O = eid . instance_id
   oo0000O00 , IiIiii = i1II1IiiIi [ "instance-id" ]
   if ( o0ooOo00O < oo0000O00 or o0ooOo00O > IiIiii ) : continue
   if 86 - 86: o0oOOo0O0Ooo / I11i * iII111i + IiII / ooOoO0o * ooOoO0o
  if ( i1II1IiiIi . has_key ( "eid-prefix" ) ) :
   IIIII1iii11 = copy . deepcopy ( i1II1IiiIi [ "eid-prefix" ] )
   IIIII1iii11 . instance_id = eid . instance_id
   if ( eid . is_more_specific ( IIIII1iii11 ) == False ) : continue
   if 98 - 98: i11iIiiIii * OoOoOO00 * II111iiii - oO0o % I1ii11iIi11i
  if ( i1II1IiiIi . has_key ( "rloc-prefix" ) ) :
   if ( rloc != None and rloc . is_more_specific ( i1II1IiiIi [ "rloc-prefix" ] )
 == False ) : continue
   if 7 - 7: I1ii11iIi11i / I1ii11iIi11i - I11i . OoO0O00 / o0oOOo0O0Ooo
  return ( True , i1II1IiiIi [ "rloc-probe" ] )
  if 87 - 87: iIii1I11I1II1 - OOooOOo - OOooOOo
 return ( False , False )
 if 55 - 55: Oo0Ooo + OoooooooOO . IiII / O0 + I11i
 if 58 - 58: Ii1I
 if 35 - 35: OoO0O00 + OoOoOO00
 if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
 if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
 if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
 if 37 - 37: O0 + IiII + I1IiiI
def lisp_glean_map_cache ( eid , rloc , encap_port ) :
 if 50 - 50: OoooooooOO . I1Ii111
 if 100 - 100: ooOoO0o * ooOoO0o - Ii1I
 if 13 - 13: iII111i . I11i * OoO0O00 . i1IIi . iIii1I11I1II1 - o0oOOo0O0Ooo
 if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
 if 79 - 79: II111iiii / IiII
 if 4 - 4: O0 - i11iIiiIii % ooOoO0o * O0 - ooOoO0o
 IIo0OooOO = lisp_map_cache . lookup_cache ( eid , True )
 if ( IIo0OooOO and len ( IIo0OooOO . rloc_set ) != 0 ) :
  IIo0OooOO . last_refresh_time = lisp_get_timestamp ( )
  if 96 - 96: oO0o % II111iiii . Ii1I % OoO0O00 . iIii1I11I1II1 / IiII
  OOooo = IIo0OooOO . rloc_set [ 0 ]
  if ( OOooo . rloc . is_exact_match ( rloc ) and
 OOooo . translated_port == encap_port ) : return
  if 13 - 13: Ii1I % II111iiii % o0oOOo0O0Ooo . OoooooooOO / OOooOOo
  IIIII1iii11 = green ( eid . print_address ( ) , False )
  oO = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Gleaned EID {} RLOC changed to {}" . format ( IIIII1iii11 , oO ) )
  OOooo . delete_from_rloc_probe_list ( IIo0OooOO . eid , IIo0OooOO . group )
 else :
  IIo0OooOO = lisp_mapping ( "" , "" , [ ] )
  IIo0OooOO . eid . copy_address ( eid )
  IIo0OooOO . mapping_source . copy_address ( rloc )
  IIo0OooOO . map_cache_ttl = LISP_GLEAN_TTL
  IIo0OooOO . gleaned = True
  IIIII1iii11 = green ( eid . print_address ( ) , False )
  oO = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( IIIII1iii11 , oO ) )
  IIo0OooOO . add_cache ( )
  if 95 - 95: I1IiiI * OoooooooOO
  if 94 - 94: OOooOOo / OOooOOo * IiII * o0oOOo0O0Ooo
  if 45 - 45: OoO0O00 - i1IIi . OoO0O00 * I1ii11iIi11i / OoOoOO00
  if 88 - 88: II111iiii * IiII . Oo0Ooo + I1Ii111
  if 75 - 75: Ii1I - OoOoOO00 + OoO0O00 + IiII * iIii1I11I1II1 % I1Ii111
  if 23 - 23: O0 % I1ii11iIi11i % iIii1I11I1II1
 oo0oo00000 = lisp_rloc ( )
 oo0oo00000 . store_translated_rloc ( rloc , encap_port )
 oo0oo00000 . add_to_rloc_probe_list ( IIo0OooOO . eid , IIo0OooOO . group )
 oo0oo00000 . priority = 253
 oo0oo00000 . mpriority = 255
 oo000OO = [ oo0oo00000 ]
 IIo0OooOO . rloc_set = oo000OO
 IIo0OooOO . build_best_rloc_set ( )
 if 49 - 49: iII111i + I1Ii111 % OoOoOO00
 if 67 - 67: Ii1I
 if 27 - 27: Oo0Ooo / i11iIiiIii / II111iiii . Ii1I - II111iiii / OoO0O00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
